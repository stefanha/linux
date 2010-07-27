/*******************************************************************************
 * Filename:  target_core_rd.c
 *
 * This file contains the Storage Engine <-> Ramdisk transport
 * specific functions.
 *
 * Copyright (c) 2003, 2004, 2005 PyX Technologies, Inc.
 * Copyright (c) 2005, 2006, 2007 SBE, Inc.
 * Copyright (c) 2007-2009 Rising Tide Software, Inc.
 * Copyright (c) 2008-2009 Linux-iSCSI.org
 *
 * Nicholas A. Bellinger <nab@kernel.org>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 *
 ******************************************************************************/


#define TARGET_CORE_RD_C

#include <linux/version.h>
#include <linux/string.h>
#include <linux/timer.h>
#include <linux/blkdev.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/smp_lock.h>
#include <scsi/scsi.h>
#include <scsi/scsi_host.h>

#include <target/target_core_base.h>
#include <target/target_core_device.h>
#include <target/target_core_transport.h>
#include <target/target_core_rd.h>

#undef TARGET_CORE_RD_C

/* #define DEBUG_RAMDISK_MCP */
/* #define DEBUG_RAMDISK_DR */

/*	rd_attach_hba(): (Part of se_subsystem_api_t template)
 *
 *
 */
int rd_attach_hba(struct se_hba *hba, u32 host_id)
{
	struct rd_host *rd_host;

	rd_host = kzalloc(sizeof(struct rd_host), GFP_KERNEL);
	if (!(rd_host)) {
		printk(KERN_ERR "Unable to allocate memory for struct rd_host\n");
		return -ENOMEM;
	}

	rd_host->rd_host_id = host_id;

	atomic_set(&hba->left_queue_depth, RD_HBA_QUEUE_DEPTH);
	atomic_set(&hba->max_queue_depth, RD_HBA_QUEUE_DEPTH);
	hba->hba_ptr = (void *) rd_host;
	hba->transport = (hba->type == RAMDISK_DR) ?
			&rd_dr_template : &rd_mcp_template;

	printk(KERN_INFO "CORE_HBA[%d] - TCM Ramdisk HBA Driver %s on"
		" Generic Target Core Stack %s\n", hba->hba_id,
		RD_HBA_VERSION, TARGET_CORE_MOD_VERSION);
	printk(KERN_INFO "CORE_HBA[%d] - Attached Ramdisk HBA: %u to Generic"
		" Target Core TCQ Depth: %d MaxSectors: %u\n", hba->hba_id,
		rd_host->rd_host_id, atomic_read(&hba->max_queue_depth),
		RD_MAX_SECTORS);

	return 0;
}

/*	rd_detach_hba(): (Part of se_subsystem_api_t template)
 *
 *
 */
int rd_detach_hba(struct se_hba *hba)
{
	struct rd_host *rd_host;

	if (!hba->hba_ptr) {
		printk(KERN_ERR "hba->hba_ptr is NULL!\n");
		return -1;
	}

	rd_host = (struct rd_host *) hba->hba_ptr;

	printk(KERN_INFO "CORE_HBA[%d] - Detached Ramdisk HBA: %u from"
		" Generic Target Core\n", hba->hba_id, rd_host->rd_host_id);

	kfree(rd_host);
	hba->hba_ptr = NULL;

	return 0;
}

/*	rd_release_device_space():
 *
 *
 */
void rd_release_device_space(struct rd_dev *rd_dev)
{
	u32 i, j, page_count = 0, sg_per_table;
	struct rd_dev_sg_table *sg_table;
	struct page *pg;
	struct scatterlist *sg;

	if (!rd_dev->sg_table_array || !rd_dev->sg_table_count)
		return;

	sg_table = rd_dev->sg_table_array;

	for (i = 0; i < rd_dev->sg_table_count; i++) {
		sg = sg_table[i].sg_table;
		sg_per_table = sg_table[i].rd_sg_count;

		for (j = 0; j < sg_per_table; j++) {
			pg = sg_page(&sg[j]);
			if ((pg)) {
				__free_page(pg);
				page_count++;
			}
		}

		kfree(sg);
	}

	printk(KERN_INFO "CORE_RD[%u] - Released device space for Ramdisk"
		" Device ID: %u, pages %u in %u tables total bytes %lu\n",
		rd_dev->rd_host->rd_host_id, rd_dev->rd_dev_id, page_count,
		rd_dev->sg_table_count, (unsigned long)page_count * PAGE_SIZE);

	kfree(sg_table);
	rd_dev->sg_table_array = NULL;
	rd_dev->sg_table_count = 0;
}


/*	rd_build_device_space():
 *
 *
 */
static int rd_build_device_space(struct rd_dev *rd_dev)
{
	u32 i = 0, j, page_offset = 0, sg_per_table, sg_tables, total_sg_needed;
	u32 max_sg_per_table = (RD_MAX_ALLOCATION_SIZE /
				sizeof(struct scatterlist));
	struct rd_dev_sg_table *sg_table;
	struct page *pg;
	struct scatterlist *sg;

	if (rd_dev->rd_page_count <= 0) {
		printk(KERN_ERR "Illegal page count: %u for Ramdisk device\n",
			rd_dev->rd_page_count);
		return -1;
	}
	total_sg_needed = rd_dev->rd_page_count;

	sg_tables = (total_sg_needed / max_sg_per_table) + 1;

	sg_table = kzalloc(sg_tables * sizeof(struct rd_dev_sg_table), GFP_KERNEL);
	if (!(sg_table)) {
		printk(KERN_ERR "Unable to allocate memory for Ramdisk"
			" scatterlist tables\n");
		return -1;
	}

	rd_dev->sg_table_array = sg_table;
	rd_dev->sg_table_count = sg_tables;

	while (total_sg_needed) {
		sg_per_table = (total_sg_needed > max_sg_per_table) ?
			max_sg_per_table : total_sg_needed;

		sg = kzalloc(sg_per_table * sizeof(struct scatterlist),
				GFP_KERNEL);
		if (!(sg)) {
			printk(KERN_ERR "Unable to allocate scatterlist array"
				" for struct rd_dev\n");
			return -1;
		}

		sg_init_table((struct scatterlist *)&sg[0], sg_per_table);

		sg_table[i].sg_table = sg;
		sg_table[i].rd_sg_count = sg_per_table;
		sg_table[i].page_start_offset = page_offset;
		sg_table[i++].page_end_offset = (page_offset + sg_per_table)
						- 1;

		for (j = 0; j < sg_per_table; j++) {
			pg = (struct page *) alloc_pages(
					GFP_KERNEL, 0);
			if (!(pg)) {
				printk(KERN_ERR "Unable to allocate scatterlist"
					" pages for struct rd_dev_sg_table\n");
				return -1;
			}
			sg_assign_page(&sg[j], pg);
			sg[j].length = PAGE_SIZE;
		}

		page_offset += sg_per_table;
		total_sg_needed -= sg_per_table;
	}

	printk(KERN_INFO "CORE_RD[%u] - Built Ramdisk Device ID: %u space of"
		" %u pages in %u tables\n", rd_dev->rd_host->rd_host_id,
		rd_dev->rd_dev_id, rd_dev->rd_page_count,
		rd_dev->sg_table_count);

	return 0;
}

static void *rd_allocate_virtdevice(
	struct se_hba *hba,
	const char *name,
	int rd_direct)
{
	struct rd_dev *rd_dev;
	struct rd_host *rd_host = (struct rd_host *) hba->hba_ptr;

	rd_dev = kzalloc(sizeof(struct rd_dev), GFP_KERNEL);
	if (!(rd_dev)) {
		printk(KERN_ERR "Unable to allocate memory for struct rd_dev\n");
		return NULL;
	}

	rd_dev->rd_host = rd_host;
	rd_dev->rd_direct = rd_direct;

	return rd_dev;
}

void *rd_DIRECT_allocate_virtdevice(struct se_hba *hba, const char *name)
{
	return rd_allocate_virtdevice(hba, name, 1);
}

void *rd_MEMCPY_allocate_virtdevice(struct se_hba *hba, const char *name)
{
	return rd_allocate_virtdevice(hba, name, 0);
}

/*	rd_create_virtdevice():
 *
 *
 */
static struct se_device *rd_create_virtdevice(
	struct se_hba *hba,
	struct se_subsystem_dev *se_dev,
	void *p,
	int rd_direct)
{
	struct se_device *dev;
	struct rd_dev *rd_dev = (struct rd_dev *) p;
	struct rd_host *rd_host = (struct rd_host *) hba->hba_ptr;
	int dev_flags = 0;

	if (rd_dev->rd_direct)
		dev_flags |= DF_TRANSPORT_DMA_ALLOC;

	if (rd_build_device_space(rd_dev) < 0)
		goto fail;

	dev = transport_add_device_to_core_hba(hba,
			(rd_dev->rd_direct) ? &rd_dr_template :
			&rd_mcp_template, se_dev, dev_flags, (void *)rd_dev);
	if (!(dev))
		goto fail;

	rd_dev->rd_dev_id = rd_host->rd_host_dev_id_count++;
	rd_dev->rd_queue_depth = dev->queue_depth;

	printk(KERN_INFO "CORE_RD[%u] - Added TCM %s Ramdisk Device ID: %u of"
		" %u pages in %u tables, %lu total bytes\n",
		rd_host->rd_host_id, (!rd_dev->rd_direct) ? "MEMCPY" :
		"DIRECT", rd_dev->rd_dev_id, rd_dev->rd_page_count,
		rd_dev->sg_table_count,
		(unsigned long)(rd_dev->rd_page_count * PAGE_SIZE));

	return dev;

fail:
	rd_release_device_space(rd_dev);
	return NULL;
}

struct se_device *rd_DIRECT_create_virtdevice(
	struct se_hba *hba,
	struct se_subsystem_dev *se_dev,
	void *p)
{
	return rd_create_virtdevice(hba, se_dev, p, 1);
}

struct se_device *rd_MEMCPY_create_virtdevice(
	struct se_hba *hba,
	struct se_subsystem_dev *se_dev,
	void *p)
{
	return rd_create_virtdevice(hba, se_dev, p, 0);
}

/*	rd_activate_device(): (Part of se_subsystem_api_t template)
 *
 *
 */
int rd_activate_device(struct se_device *dev)
{
	struct rd_dev *rd_dev = (struct rd_dev *) dev->dev_ptr;
	struct rd_host *rd_host = rd_dev->rd_host;

	printk(KERN_INFO "CORE_RD[%u] - Activating Device with TCQ: %d at"
		" Ramdisk Device ID: %d\n", rd_host->rd_host_id,
		rd_dev->rd_queue_depth, rd_dev->rd_dev_id);

	return 0;
}

/*	rd_deactivate_device(): (Part of se_subsystem_api_t template)
 *
 *
 */
void rd_deactivate_device(struct se_device *dev)
{
	struct rd_dev *rd_dev = (struct rd_dev *) dev->dev_ptr;
	struct rd_host *rd_host = rd_dev->rd_host;

	printk(KERN_INFO "CORE_RD[%u] - Deactivating Device with TCQ: %d at"
		" Ramdisk Device ID: %d\n", rd_host->rd_host_id,
		rd_dev->rd_queue_depth, rd_dev->rd_dev_id);
}

/*	rd_free_device(): (Part of se_subsystem_api_t template)
 *
 *
 */
void rd_free_device(void *p)
{
	struct rd_dev *rd_dev = (struct rd_dev *) p;

	rd_release_device_space(rd_dev);
	kfree(rd_dev);
}

/*	rd_transport_complete(): (Part of se_subsystem_api_t template)
 *
 *
 */
int rd_transport_complete(struct se_task *task)
{
	return 0;
}

/*	rd_allocate_request(): (Part of se_subsystem_api_t template)
 *
 *
 */
void *rd_allocate_request(
	struct se_task *task,
	struct se_device *dev)
{
	struct rd_request *rd_req;

	rd_req = kzalloc(sizeof(struct rd_request), GFP_KERNEL);
	if (!(rd_req)) {
		printk(KERN_ERR "Unable to allocate struct rd_request\n");
		return NULL;
	}
	rd_req->rd_dev = (struct rd_dev *) dev->dev_ptr;

	return (void *)rd_req;
}

/*	rd_emulate_inquiry():
 *
 *
 */
static int rd_emulate_inquiry(struct se_task *task)
{
	unsigned char prod[64], se_location[128];
	struct rd_dev *rd_dev = (struct rd_dev *) task->se_dev->dev_ptr;
	struct se_cmd *cmd = TASK_CMD(task);
	struct se_hba *hba = task->se_dev->se_hba;

	memset(prod, 0, 64);
	memset(se_location, 0, 128);

	sprintf(prod, "RAMDISK-%s", (rd_dev->rd_direct) ? "DR" : "MCP");
	sprintf(se_location, "%u_%u", hba->hba_id, rd_dev->rd_dev_id);

	return transport_generic_emulate_inquiry(cmd, TYPE_DISK, prod,
			(hba->transport->do_se_mem_map) ? RD_DR_VERSION :
			RD_MCP_VERSION, se_location);
}

/*	rd_emulate_read_cap():
 *
 *
 */
static int rd_emulate_read_cap(struct se_task *task)
{
	struct rd_dev *rd_dev = (struct rd_dev *) task->se_dev->dev_ptr;
	u32 blocks = ((rd_dev->rd_page_count * PAGE_SIZE) /
		       DEV_ATTRIB(task->se_dev)->block_size) - 1;

	if ((((rd_dev->rd_page_count * PAGE_SIZE) /
	       DEV_ATTRIB(task->se_dev)->block_size) - 1) >= 0x00000000ffffffff)
		blocks = 0xffffffff;

	return transport_generic_emulate_readcapacity(TASK_CMD(task), blocks);
}

static int rd_emulate_read_cap16(struct se_task *task)
{
	struct rd_dev *rd_dev = (struct rd_dev *) task->se_dev->dev_ptr;
	unsigned long long blocks_long = ((rd_dev->rd_page_count * PAGE_SIZE) /
				   DEV_ATTRIB(task->se_dev)->block_size) - 1;

	return transport_generic_emulate_readcapacity_16(TASK_CMD(task),
				blocks_long);
}

/*	rd_emulate_scsi_cdb():
 *
 *
 */
static int rd_emulate_scsi_cdb(struct se_task *task)
{
	int ret;
	struct se_cmd *cmd = TASK_CMD(task);
	struct rd_request *rd_req = (struct rd_request *) task->transport_req;

	switch (rd_req->rd_scsi_cdb[0]) {
	case INQUIRY:
		if (rd_emulate_inquiry(task) < 0)
			return PYX_TRANSPORT_INVALID_CDB_FIELD;
		break;
	case READ_CAPACITY:
		ret = rd_emulate_read_cap(task);
		if (ret < 0)
			return ret;
		break;
	case MODE_SENSE:
		ret = transport_generic_emulate_modesense(TASK_CMD(task),
				rd_req->rd_scsi_cdb, rd_req->rd_buf, 0,
				TYPE_DISK);
		if (ret < 0)
			return ret;
		break;
	case MODE_SENSE_10:
		ret = transport_generic_emulate_modesense(TASK_CMD(task),
				rd_req->rd_scsi_cdb, rd_req->rd_buf, 1,
				TYPE_DISK);
		if (ret < 0)
			return ret;
		break;
	case SERVICE_ACTION_IN:
		if ((T_TASK(cmd)->t_task_cdb[1] & 0x1f) !=
		     SAI_READ_CAPACITY_16) {
			printk(KERN_ERR "Unsupported SA: 0x%02x\n",
					T_TASK(cmd)->t_task_cdb[1] & 0x1f);
			return PYX_TRANSPORT_UNKNOWN_SAM_OPCODE;
		}
		ret = rd_emulate_read_cap16(task);
		if (ret < 0)
			return ret;
		break;
	case REQUEST_SENSE:
		ret = transport_generic_emulate_request_sense(cmd,
				T_TASK(cmd)->t_task_cdb);
		if (ret < 0)
			return ret;
		break;
	case ALLOW_MEDIUM_REMOVAL:
	case ERASE:
	case REZERO_UNIT:
	case SEEK_10:
	case SPACE:
	case START_STOP:
	case SYNCHRONIZE_CACHE:
	case TEST_UNIT_READY:
	case VERIFY:
	case WRITE_FILEMARKS:
	case RESERVE:
	case RESERVE_10:
	case RELEASE:
	case RELEASE_10:
		break;
	default:
		printk(KERN_ERR "Unsupported SCSI Opcode: 0x%02x for"
			" RAMDISKs\n", rd_req->rd_scsi_cdb[0]);
		return PYX_TRANSPORT_UNKNOWN_SAM_OPCODE;
	}

	task->task_scsi_status = GOOD;
	transport_complete_task(task, 1);

	return PYX_TRANSPORT_SENT_TO_TRANSPORT;
}

/*	rd_get_sg_table():
 *
 *
 */
static struct rd_dev_sg_table *rd_get_sg_table(struct rd_dev *rd_dev, u32 page)
{
	u32 i;
	struct rd_dev_sg_table *sg_table;

	for (i = 0; i < rd_dev->sg_table_count; i++) {
		sg_table = &rd_dev->sg_table_array[i];
		if ((sg_table->page_start_offset <= page) &&
		    (sg_table->page_end_offset >= page))
			return sg_table;
	}

	printk(KERN_ERR "Unable to locate struct rd_dev_sg_table for page: %u\n",
			page);

	return NULL;
}

/*	rd_MEMCPY_read():
 *
 *
 */
static int rd_MEMCPY_read(struct rd_request *req)
{
	struct rd_dev *dev = req->rd_dev;
	struct rd_dev_sg_table *table;
	struct scatterlist *sg_d, *sg_s;
	void *dst, *src;
	u32 i = 0, j = 0, dst_offset = 0, src_offset = 0;
	u32 length, page_end = 0, table_sg_end;
	u32 rd_offset = req->rd_offset;

	table = rd_get_sg_table(dev, req->rd_page);
	if (!(table))
		return -1;

	table_sg_end = (table->page_end_offset - req->rd_page);
	sg_d = (struct scatterlist *) req->rd_buf;
	sg_s = &table->sg_table[req->rd_page - table->page_start_offset];
#ifdef DEBUG_RAMDISK_MCP
	printk(KERN_INFO "RD[%u]: Read LBA: %llu, Size: %u Page: %u, Offset:"
		" %u\n", dev->rd_dev_id, req->rd_lba, req->rd_size,
		req->rd_page, req->rd_offset);
#endif
	src_offset = rd_offset;

	while (req->rd_size) {
		if ((sg_d[i].length - dst_offset) <
		    (sg_s[j].length - src_offset)) {
			length = (sg_d[i].length - dst_offset);
#ifdef DEBUG_RAMDISK_MCP
			printk(KERN_INFO "Step 1 - sg_d[%d]: %p length: %d"
				" offset: %u sg_s[%d].length: %u\n", i,
				&sg_d[i], sg_d[i].length, sg_d[i].offset, j,
				sg_s[j].length);
			printk(KERN_INFO "Step 1 - length: %u dst_offset: %u"
				" src_offset: %u\n", length, dst_offset,
				src_offset);
#endif
			if (length > req->rd_size)
				length = req->rd_size;

			dst = sg_virt(&sg_d[i++]) + dst_offset;
			if (!dst)
				BUG();

			src = sg_virt(&sg_s[j]) + src_offset;
			if (!src)
				BUG();

			dst_offset = 0;
			src_offset = length;
			page_end = 0;
		} else {
			length = (sg_s[j].length - src_offset);
#ifdef DEBUG_RAMDISK_MCP
			printk(KERN_INFO "Step 2 - sg_d[%d]: %p length: %d"
				" offset: %u sg_s[%d].length: %u\n", i,
				&sg_d[i], sg_d[i].length, sg_d[i].offset,
				j, sg_s[j].length);
			printk(KERN_INFO "Step 2 - length: %u dst_offset: %u"
				" src_offset: %u\n", length, dst_offset,
				src_offset);
#endif
			if (length > req->rd_size)
				length = req->rd_size;

			dst = sg_virt(&sg_d[i]) + dst_offset;
			if (!dst)
				BUG();

			if (sg_d[i].length == length) {
				i++;
				dst_offset = 0;
			} else
				dst_offset = length;

			src = sg_virt(&sg_s[j++]) + src_offset;
			if (!src)
				BUG();

			src_offset = 0;
			page_end = 1;
		}

		memcpy(dst, src, length);

#ifdef DEBUG_RAMDISK_MCP
		printk(KERN_INFO "page: %u, remaining size: %u, length: %u,"
			" i: %u, j: %u\n", req->rd_page,
			(req->rd_size - length), length, i, j);
#endif
		req->rd_size -= length;
		if (!(req->rd_size))
			return 0;

		if (!page_end)
			continue;

		if (++req->rd_page <= table->page_end_offset) {
#ifdef DEBUG_RAMDISK_MCP
			printk(KERN_INFO "page: %u in same page table\n",
				req->rd_page);
#endif
			continue;
		}
#ifdef DEBUG_RAMDISK_MCP
		printk(KERN_INFO "getting new page table for page: %u\n",
				req->rd_page);
#endif
		table = rd_get_sg_table(dev, req->rd_page);
		if (!(table))
			return -1;

		sg_s = &table->sg_table[j = 0];
	}

	return 0;
}

/*	rd_MEMCPY_write():
 *
 *
 */
static int rd_MEMCPY_write(struct rd_request *req)
{
	struct rd_dev *dev = req->rd_dev;
	struct rd_dev_sg_table *table;
	struct scatterlist *sg_d, *sg_s;
	void *dst, *src;
	u32 i = 0, j = 0, dst_offset = 0, src_offset = 0;
	u32 length, page_end = 0, table_sg_end;
	u32 rd_offset = req->rd_offset;

	table = rd_get_sg_table(dev, req->rd_page);
	if (!(table))
		return -1;

	table_sg_end = (table->page_end_offset - req->rd_page);
	sg_d = &table->sg_table[req->rd_page - table->page_start_offset];
	sg_s = (struct scatterlist *) req->rd_buf;
#ifdef DEBUG_RAMDISK_MCP
	printk(KERN_INFO "RD[%d] Write LBA: %llu, Size: %u, Page: %u,"
		" Offset: %u\n", dev->rd_dev_id, req->rd_lba, req->rd_size,
		req->rd_page, req->rd_offset);
#endif
	dst_offset = rd_offset;

	while (req->rd_size) {
		if ((sg_s[i].length - src_offset) <
		    (sg_d[j].length - dst_offset)) {
			length = (sg_s[i].length - src_offset);
#ifdef DEBUG_RAMDISK_MCP
			printk(KERN_INFO "Step 1 - sg_s[%d]: %p length: %d"
				" offset: %d sg_d[%d].length: %u\n", i,
				&sg_s[i], sg_s[i].length, sg_s[i].offset,
				j, sg_d[j].length);
			printk(KERN_INFO "Step 1 - length: %u src_offset: %u"
				" dst_offset: %u\n", length, src_offset,
				dst_offset);
#endif
			if (length > req->rd_size)
				length = req->rd_size;

			src = sg_virt(&sg_s[i++]) + src_offset;
			if (!src)
				BUG();

			dst = sg_virt(&sg_d[j]) + dst_offset;
			if (!dst)
				BUG();

			src_offset = 0;
			dst_offset = length;
			page_end = 0;
		} else {
			length = (sg_d[j].length - dst_offset);
#ifdef DEBUG_RAMDISK_MCP
			printk(KERN_INFO "Step 2 - sg_s[%d]: %p length: %d"
				" offset: %d sg_d[%d].length: %u\n", i,
				&sg_s[i], sg_s[i].length, sg_s[i].offset,
				j, sg_d[j].length);
			printk(KERN_INFO "Step 2 - length: %u src_offset: %u"
				" dst_offset: %u\n", length, src_offset,
				dst_offset);
#endif
			if (length > req->rd_size)
				length = req->rd_size;

			src = sg_virt(&sg_s[i]) + src_offset;
			if (!src)
				BUG();

			if (sg_s[i].length == length) {
				i++;
				src_offset = 0;
			} else
				src_offset = length;

			dst = sg_virt(&sg_d[j++]) + dst_offset;
			if (!dst)
				BUG();

			dst_offset = 0;
			page_end = 1;
		}

		memcpy(dst, src, length);

#ifdef DEBUG_RAMDISK_MCP
		printk(KERN_INFO "page: %u, remaining size: %u, length: %u,"
			" i: %u, j: %u\n", req->rd_page,
			(req->rd_size - length), length, i, j);
#endif
		req->rd_size -= length;
		if (!(req->rd_size))
			return 0;

		if (!page_end)
			continue;

		if (++req->rd_page <= table->page_end_offset) {
#ifdef DEBUG_RAMDISK_MCP
			printk(KERN_INFO "page: %u in same page table\n",
				req->rd_page);
#endif
			continue;
		}
#ifdef DEBUG_RAMDISK_MCP
		printk(KERN_INFO "getting new page table for page: %u\n",
				req->rd_page);
#endif
		table = rd_get_sg_table(dev, req->rd_page);
		if (!(table))
			return -1;

		sg_d = &table->sg_table[j = 0];
	}

	return 0;
}

/*	rd_MEMCPY_do_task(): (Part of se_subsystem_api_t template)
 *
 *
 */
int rd_MEMCPY_do_task(struct se_task *task)
{
	struct se_device *dev = task->se_dev;
	struct rd_request *req = (struct rd_request *) task->transport_req;
	int ret;

	if (!(TASK_CMD(task)->se_cmd_flags & SCF_SCSI_DATA_SG_IO_CDB))
		return rd_emulate_scsi_cdb(task);

	req->rd_lba = task->task_lba;
	req->rd_page = (req->rd_lba * DEV_ATTRIB(dev)->block_size) / PAGE_SIZE;
	req->rd_offset = (do_div(req->rd_lba,
			  (PAGE_SIZE / DEV_ATTRIB(dev)->block_size))) *
			   DEV_ATTRIB(dev)->block_size;
	req->rd_size = task->task_size;

	if (req->rd_data_direction == RD_DATA_READ)
		ret = rd_MEMCPY_read(req);
	else
		ret = rd_MEMCPY_write(req);

	if (ret != 0)
		return ret;

	task->task_scsi_status = GOOD;
	transport_complete_task(task, 1);

	return PYX_TRANSPORT_SENT_TO_TRANSPORT;
}

/*	rd_DIRECT_with_offset():
 *
 *
 */
static int rd_DIRECT_with_offset(
	struct se_task *task,
	struct list_head *se_mem_list,
	u32 *se_mem_cnt,
	u32 *task_offset)
{
	struct rd_request *req = (struct rd_request *)task->transport_req;
	struct rd_dev *dev = req->rd_dev;
	struct rd_dev_sg_table *table;
	struct se_mem *se_mem;
	struct scatterlist *sg_s;
	u32 j = 0, set_offset = 1;
	u32 get_next_table = 0, offset_length, table_sg_end;

	table = rd_get_sg_table(dev, req->rd_page);
	if (!(table))
		return -1;

	table_sg_end = (table->page_end_offset - req->rd_page);
	sg_s = &table->sg_table[req->rd_page - table->page_start_offset];
#ifdef DEBUG_RAMDISK_DR
	printk(KERN_INFO "%s DIRECT LBA: %llu, Size: %u Page: %u, Offset: %u\n",
		(req->rd_data_direction != RD_DATA_READ) ? "Write" : "Read",
		req->rd_lba, req->rd_size, req->rd_page, req->rd_offset);
#endif
	while (req->rd_size) {
		se_mem = kmem_cache_zalloc(se_mem_cache, GFP_KERNEL);
		if (!(se_mem)) {
			printk(KERN_ERR "Unable to allocate struct se_mem\n");
			return -1;
		}
		INIT_LIST_HEAD(&se_mem->se_list);

		if (set_offset) {
			offset_length = sg_s[j].length - req->rd_offset;
			if (offset_length > req->rd_size)
				offset_length = req->rd_size;

			se_mem->se_page = sg_page(&sg_s[j++]);
			se_mem->se_off = req->rd_offset;
			se_mem->se_len = offset_length;

			set_offset = 0;
			get_next_table = (j > table_sg_end);
			goto check_eot;
		}

		offset_length = (req->rd_size < req->rd_offset) ?
			req->rd_size : req->rd_offset;

		se_mem->se_page = sg_page(&sg_s[j]);
		se_mem->se_len = offset_length;

		set_offset = 1;

check_eot:
#ifdef DEBUG_RAMDISK_DR
		printk(KERN_INFO "page: %u, size: %u, offset_length: %u, j: %u"
			" se_mem: %p, se_page: %p se_off: %u se_len: %u\n",
			req->rd_page, req->rd_size, offset_length, j, se_mem,
			se_mem->se_page, se_mem->se_off, se_mem->se_len);
#endif
		list_add_tail(&se_mem->se_list, se_mem_list);
		(*se_mem_cnt)++;

		req->rd_size -= offset_length;
		if (!(req->rd_size))
			goto out;

		if (!set_offset && !get_next_table)
			continue;

		if (++req->rd_page <= table->page_end_offset) {
#ifdef DEBUG_RAMDISK_DR
			printk(KERN_INFO "page: %u in same page table\n",
					req->rd_page);
#endif
			continue;
		}
#ifdef DEBUG_RAMDISK_DR
		printk(KERN_INFO "getting new page table for page: %u\n",
				req->rd_page);
#endif
		table = rd_get_sg_table(dev, req->rd_page);
		if (!(table))
			return -1;

		sg_s = &table->sg_table[j = 0];
	}

out:
	T_TASK(task->task_se_cmd)->t_task_se_num += *se_mem_cnt;
#ifdef DEBUG_RAMDISK_DR
	printk(KERN_INFO "RD_DR - Allocated %u struct se_mem segments for task\n",
			*se_mem_cnt);
#endif
	return 0;
}

/*	rd_DIRECT_without_offset():
 *
 *
 */
static int rd_DIRECT_without_offset(
	struct se_task *task,
	struct list_head *se_mem_list,
	u32 *se_mem_cnt,
	u32 *task_offset)
{
	struct rd_request *req = (struct rd_request *)task->transport_req;
	struct rd_dev *dev = req->rd_dev;
	struct rd_dev_sg_table *table;
	struct se_mem *se_mem;
	struct scatterlist *sg_s;
	u32 length, j = 0;

	table = rd_get_sg_table(dev, req->rd_page);
	if (!(table))
		return -1;

	sg_s = &table->sg_table[req->rd_page - table->page_start_offset];
#ifdef DEBUG_RAMDISK_DR
	printk(KERN_INFO "%s DIRECT LBA: %llu, Size: %u, Page: %u\n",
		(req->rd_data_direction != RD_DATA_READ) ? "Write" : "Read",
		req->rd_lba, req->rd_size, req->rd_page);
#endif
	while (req->rd_size) {
		se_mem = kmem_cache_zalloc(se_mem_cache, GFP_KERNEL);
		if (!(se_mem)) {
			printk(KERN_ERR "Unable to allocate struct se_mem\n");
			return -1;
		}
		INIT_LIST_HEAD(&se_mem->se_list);

		length = (req->rd_size < sg_s[j].length) ?
			req->rd_size : sg_s[j].length;

		se_mem->se_page = sg_page(&sg_s[j++]);
		se_mem->se_len = length;

#ifdef DEBUG_RAMDISK_DR
		printk(KERN_INFO "page: %u, size: %u, j: %u se_mem: %p,"
			" se_page: %p se_off: %u se_len: %u\n", req->rd_page,
			req->rd_size, j, se_mem, se_mem->se_page,
			se_mem->se_off, se_mem->se_len);
#endif
		list_add_tail(&se_mem->se_list, se_mem_list);
		(*se_mem_cnt)++;

		req->rd_size -= length;
		if (!(req->rd_size))
			goto out;

		if (++req->rd_page <= table->page_end_offset) {
#ifdef DEBUG_RAMDISK_DR
			printk("page: %u in same page table\n",
				req->rd_page);
#endif
			continue;
		}
#ifdef DEBUG_RAMDISK_DR
		printk(KERN_INFO "getting new page table for page: %u\n",
				req->rd_page);
#endif
		table = rd_get_sg_table(dev, req->rd_page);
		if (!(table))
			return -1;

		sg_s = &table->sg_table[j = 0];
	}

out:
	T_TASK(task->task_se_cmd)->t_task_se_num += *se_mem_cnt;
#ifdef DEBUG_RAMDISK_DR
	printk(KERN_INFO "RD_DR - Allocated %u struct se_mem segments for task\n",
			*se_mem_cnt);
#endif
	return 0;
}

/*	rd_DIRECT_do_se_mem_map():
 *
 *
 */
int rd_DIRECT_do_se_mem_map(
	struct se_task *task,
	struct list_head *se_mem_list,
	void *in_mem,
	struct se_mem *in_se_mem,
	struct se_mem **out_se_mem,
	u32 *se_mem_cnt,
	u32 *task_offset)
{
	struct rd_request *req = (struct rd_request *) task->transport_req;
	int ret;

	req->rd_lba = task->task_lba;
	req->rd_req_flags = RRF_GOT_LBA;
	req->rd_page = ((req->rd_lba * DEV_ATTRIB(task->se_dev)->block_size) /
			PAGE_SIZE);
	req->rd_offset = (do_div(req->rd_lba,
			  (PAGE_SIZE / DEV_ATTRIB(task->se_dev)->block_size))) *
			   DEV_ATTRIB(task->se_dev)->block_size;
	req->rd_size = task->task_size;

	if (req->rd_offset)
		ret = rd_DIRECT_with_offset(task, se_mem_list, se_mem_cnt,
				task_offset);
	else
		ret = rd_DIRECT_without_offset(task, se_mem_list, se_mem_cnt,
				task_offset);

	return ret;
}

/*	rd_DIRECT_free_DMA():
 *
 *
 */
void rd_DIRECT_free_DMA(struct se_cmd *cmd)
{
	struct se_mem *se_mem, *se_mem_tmp;

	/*
	 * The scatterlists in the RAMDISK DIRECT case are using the pages
	 * from the rd_device_t's scatterlist table. They are referencing
	 * valid memory that is held within the RD transport plugin, so we
	 * only free the struct se_mem elements.
	 */
	list_for_each_entry_safe(se_mem, se_mem_tmp, T_TASK(cmd)->t_mem_list,
				se_list) {
		 list_del(&se_mem->se_list);
		 kmem_cache_free(se_mem_cache, se_mem);
	}
	kfree(T_TASK(cmd)->t_mem_list);
	T_TASK(cmd)->t_mem_list = NULL;
	T_TASK(cmd)->t_task_se_num = 0;
}

/*	rd_DIRECT_allocate_DMA():
 *
 *	Note that rd_DIRECT_do_se_mem_map() actually does the real work.
 */
int rd_DIRECT_allocate_DMA(struct se_cmd *cmd, u32 length, u32 dma_size)
{
	T_TASK(cmd)->t_mem_list = kzalloc(sizeof(struct list_head), GFP_KERNEL);
	if (!(T_TASK(cmd)->t_mem_list)) {
		printk(KERN_ERR "Unable to allocate memory for T_TASK(cmd)"
				"->t_mem_list\n");
		return -1;
	}
	INIT_LIST_HEAD(T_TASK(cmd)->t_mem_list);

	return 0;
}

/*	rd_DIRECT_do_task(): (Part of se_subsystem_api_t template)
 *
 *
 */
int rd_DIRECT_do_task(struct se_task *task)
{
	if (!(TASK_CMD(task)->se_cmd_flags & SCF_SCSI_DATA_SG_IO_CDB))
		return rd_emulate_scsi_cdb(task);

	/*
	 * At this point the locally allocated RD tables have been mapped
	 * to struct se_mem elements in rd_DIRECT_do_se_mem_map().
	 */
	task->task_scsi_status = GOOD;
	transport_complete_task(task, 1);

	return PYX_TRANSPORT_SENT_TO_TRANSPORT;
}

/*	rd_free_task(): (Part of se_subsystem_api_t template)
 *
 *
 */
void rd_free_task(struct se_task *task)
{
	struct rd_request *req;
	req = (struct rd_request *) task->transport_req;

	kfree(req);
}

ssize_t rd_set_configfs_dev_params(
	struct se_hba *hba,
	struct se_subsystem_dev *se_dev,
	const char *page,
	ssize_t count)
{
	struct rd_dev *rd_dev = (struct rd_dev *) se_dev->se_dev_su_ptr;
	char *buf, *cur, *ptr, *ptr2;
	unsigned long rd_pages;
	int params = 0, ret;

	buf = kzalloc(count, GFP_KERNEL);
	if (!(buf)) {
		printk(KERN_ERR "Unable to allocate memory for temporary buffer\n");
		return 0;
	}
	memcpy(buf, page, count);
	cur = buf;

	while (cur) {
		ptr = strstr(cur, "=");
		if (!(ptr))
			goto out;

		*ptr = '\0';
		ptr++;

		ptr2 = strstr(cur, "rd_pages");
		if ((ptr2)) {
			transport_check_dev_params_delim(ptr, &cur);
			ret = strict_strtoul(ptr, 0, &rd_pages);
			if (ret < 0) {
				printk(KERN_ERR "strict_strtoul() failed for"
					" rd_pages=\n");
				break;
			}
			rd_dev->rd_page_count = (u32)rd_pages;
			printk(KERN_INFO "RAMDISK: Referencing Page"
				" Count: %u\n", rd_dev->rd_page_count);
			rd_dev->rd_flags |= RDF_HAS_PAGE_COUNT;
			params++;
		} else
			cur = NULL;
	}

out:
	kfree(buf);
	return (params) ? count : -EINVAL;
}

ssize_t rd_check_configfs_dev_params(struct se_hba *hba, struct se_subsystem_dev *se_dev)
{
	struct rd_dev *rd_dev = (struct rd_dev *) se_dev->se_dev_su_ptr;

	if (!(rd_dev->rd_flags & RDF_HAS_PAGE_COUNT)) {
		printk(KERN_INFO "Missing rd_pages= parameter\n");
		return -1;
	}

	return 0;
}

ssize_t rd_show_configfs_dev_params(
	struct se_hba *hba,
	struct se_subsystem_dev *se_dev,
	char *page)
{
	struct rd_dev *rd_dev = (struct rd_dev *) se_dev->se_dev_su_ptr;
	int bl = 0;

	 __rd_get_dev_info(rd_dev, page, &bl);
	return (ssize_t)bl;
}

void rd_dr_get_plugin_info(void *p, char *b, int *bl)
{
	*bl += sprintf(b + *bl, "TCM RAMDISK_DR Plugin %s\n", RD_DR_VERSION);
}

void rd_mcp_get_plugin_info(void *p, char *b, int *bl)
{
	*bl += sprintf(b + *bl, "TCM RAMDISK_MCP Plugin %s\n", RD_MCP_VERSION);
}

void rd_get_hba_info(struct se_hba *hba, char *b, int *bl)
{
	struct rd_host *rd_host = (struct rd_host *)hba->hba_ptr;

	*bl += sprintf(b + *bl, "SE Host ID: %u  RD Host ID: %u\n",
		hba->hba_id, rd_host->rd_host_id);
	*bl += sprintf(b + *bl, "        TCM RamDisk HBA\n");
}

void rd_get_dev_info(struct se_device *dev, char *b, int *bl)
{
	struct rd_dev *rd_dev = (struct rd_dev *) dev->dev_ptr;

	__rd_get_dev_info(rd_dev, b, bl);
}

void __rd_get_dev_info(struct rd_dev *rd_dev, char *b, int *bl)
{
	*bl += sprintf(b + *bl, "TCM RamDisk ID: %u  RamDisk Makeup: %s\n",
			rd_dev->rd_dev_id, (rd_dev->rd_direct) ?
			"rd_direct" : "rd_mcp");
	*bl += sprintf(b + *bl, "        PAGES/PAGE_SIZE: %u*%lu"
			"  SG_table_count: %u\n", rd_dev->rd_page_count,
			PAGE_SIZE, rd_dev->sg_table_count);

	return;
}

/*	rd_map_task_non_SG():
 *
 *
 */
void rd_map_task_non_SG(struct se_task *task)
{
	struct se_cmd *cmd = TASK_CMD(task);
	struct rd_request *req = (struct rd_request *) task->transport_req;

	req->rd_bufflen		= task->task_size;
	req->rd_buf		= (void *) T_TASK(cmd)->t_task_buf;
	req->rd_sg_count	= 0;
}

/*	rd_map_task_SG():
 *
 *
 */
void rd_map_task_SG(struct se_task *task)
{
	struct rd_request *req = (struct rd_request *) task->transport_req;

	req->rd_bufflen		= task->task_size;
	req->rd_buf		= task->task_sg;
	req->rd_sg_count	= task->task_sg_num;
}

/*      iblock_CDB_inquiry():
 *
 *
 */
int rd_CDB_inquiry(struct se_task *task, u32 size)
{
	struct rd_request *req = (struct rd_request *) task->transport_req;

	req->rd_data_direction  = RD_DATA_READ;

	rd_map_task_non_SG(task);
	return 0;
}

/*      rd_CDB_none():
 *
 *
 */
int rd_CDB_none(struct se_task *task, u32 size)
{
	struct rd_request *req = (struct rd_request *) task->transport_req;

	req->rd_data_direction	= RD_DATA_NONE;
	req->rd_bufflen		= 0;
	req->rd_sg_count	= 0;
	req->rd_buf		= NULL;

	return 0;
}

/*	rd_CDB_read_non_SG():
 *
 *
 */
int rd_CDB_read_non_SG(struct se_task *task, u32 size)
{
	struct rd_request *req = (struct rd_request *) task->transport_req;

	req->rd_data_direction = RD_DATA_READ;
	rd_map_task_non_SG(task);

	return 0;
}

/*	rd_CDB_read_SG):
 *
 *
 */
int rd_CDB_read_SG(struct se_task *task, u32 size)
{
	struct rd_request *req = (struct rd_request *) task->transport_req;

	req->rd_data_direction = RD_DATA_READ;
	rd_map_task_SG(task);

	return req->rd_sg_count;
}

/*	rd_CDB_write_non_SG():
 *
 *
 */
int rd_CDB_write_non_SG(struct se_task *task, u32 size)
{
	struct rd_request *req = (struct rd_request *) task->transport_req;

	req->rd_data_direction = RD_DATA_WRITE;
	rd_map_task_non_SG(task);

	return 0;
}

/*	d_CDB_write_SG():
 *
 *
 */
int rd_CDB_write_SG(struct se_task *task, u32 size)
{
	struct rd_request *req = (struct rd_request *) task->transport_req;

	req->rd_data_direction = RD_DATA_WRITE;
	rd_map_task_SG(task);

	return req->rd_sg_count;
}

/*	rd_DIRECT_check_lba():
 *
 *
 */
int rd_DIRECT_check_lba(unsigned long long lba, struct se_device *dev)
{
	return ((do_div(lba, PAGE_SIZE / DEV_ATTRIB(dev)->block_size)) *
		 DEV_ATTRIB(dev)->block_size) ? 1 : 0;
}

/*	rd_MEMCPY_check_lba():
 *
 *
 */
int rd_MEMCPY_check_lba(unsigned long long lba, struct se_device *dev)
{
	return 0;
}

/*	rd_check_for_SG(): (Part of se_subsystem_api_t template)
 *
 *
 */
int rd_check_for_SG(struct se_task *task)
{
	struct rd_request *req = (struct rd_request *) task->transport_req;

	return req->rd_sg_count;
}

/*	rd_get_cdb(): (Part of se_subsystem_api_t template)
 *
 *
 */
unsigned char *rd_get_cdb(struct se_task *task)
{
	struct rd_request *req = (struct rd_request *) task->transport_req;

	return req->rd_scsi_cdb;
}

/*	rd_get_blocksize(): (Part of se_subsystem_api_t template)
 *
 *
 */
u32 rd_get_blocksize(struct se_device *dev)
{
	return RD_BLOCKSIZE;
}

u32 rd_get_device_rev(struct se_device *dev)
{
	return SCSI_SPC_2; /* Returns SPC-3 in Initiator Data */
}

u32 rd_get_device_type(struct se_device *dev)
{
	return TYPE_DISK;
}

/*	rd_get_dma_length(): (Part of se_subsystem_api_t template)
 *
 *
 */
u32 rd_get_dma_length(u32 task_size, struct se_device *dev)
{
	return PAGE_SIZE;
}

/*	rd_get_max_sectors(): (Part of se_subsystem_api_t template)
 *
 *
 */
u32 rd_get_max_sectors(struct se_device *dev)
{
	return RD_MAX_SECTORS;
}

/*	rd_get_queue_depth(): (Part of se_subsystem_api_t template)
 *
 *
 */
u32 rd_get_queue_depth(struct se_device *dev)
{
	return RD_DEVICE_QUEUE_DEPTH;
}

u32 rd_get_max_queue_depth(struct se_device *dev)
{
	return RD_MAX_DEVICE_QUEUE_DEPTH;
}
