/*********************************************************************************
 * Filename:  iscsi_target_rd.c
 *
 * This file contains the iSCSI <-> Ramdisk transport specific functions.
 *
 * Copyright (c) 2003, 2004, 2005 PyX Technologies, Inc.
 * Copyright (c) 2005, 2006, 2007 SBE, Inc. 
 * Copyright (c) 2007 Rising Tide Software, Inc.
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
 *********************************************************************************/


#define ISCSI_TARGET_RD_C

#include <linux/version.h>
#include <linux/string.h>
#include <linux/timer.h>
#include <linux/blkdev.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/smp_lock.h>
#include <scsi/scsi.h>
#include <scsi/scsi_host.h>

#include <iscsi_linux_os.h> 
#include <iscsi_linux_defs.h>
                                
#include <iscsi_debug.h>
#include <iscsi_protocol.h>
#include <iscsi_target_core.h>
#include <iscsi_target_ioctl.h>
#include <iscsi_target_ioctl_defs.h>
#include <iscsi_target_device.h>
#include <iscsi_target_transport.h>
#include <iscsi_target_util.h>
#include <iscsi_target_rd.h>
#include <iscsi_target_error.h>

extern iscsi_global_t *iscsi_global;

//#define DEBUG_RAMDISK_MCP
//#define DEBUG_RAMDISK_DR

/*	rd_attach_hba(): (Part of iscsi_transport_t template)
 *
 *
 */
extern int rd_attach_hba (
	iscsi_portal_group_t *tpg,
	iscsi_hba_t *hba,
	iscsi_hbainfo_t *hi)
{
	rd_host_t *rd_host;

	if (!(rd_host = kmalloc(sizeof(rd_host_t), GFP_KERNEL))) {
		TRACE_ERROR("Unable to allocate memory for rd_host_t\n");
		return(-1);
	}
	memset(rd_host, 0, sizeof(rd_host_t));

	rd_host->rd_host_id = hi->rd_host_id;
	
	atomic_set(&hba->left_queue_depth, RD_HBA_QUEUE_DEPTH);
	atomic_set(&hba->max_queue_depth, RD_HBA_QUEUE_DEPTH);
	hba->hba_ptr = (void *) rd_host;
	hba->hba_id = hi->hba_id;
	hba->transport = (hi->hba_type == RAMDISK_DR) ? &rd_dr_template : &rd_mcp_template;

	PYXPRINT("iSCSI_HBA[%d] - %s Ramdisk HBA Driver %s for iSCSI"
		" Target Core Stack %s\n", hba->hba_id, PYX_ISCSI_VENDOR, RD_HBA_VERSION, PYX_ISCSI_VERSION);
	
	PYXPRINT("iSCSI_HBA[%d] - Attached Ramdisk HBA: %u to iSCSI Transport with"
		" TCQ Depth: %d MaxSectors: %u\n", hba->hba_id, rd_host->rd_host_id,
		atomic_read(&hba->max_queue_depth), RD_MAX_SECTORS);

	return(0);
}

/*	rd_detach_hba(): (Part of iscsi_transport_t template)
 *
 *
 */
extern int rd_detach_hba (iscsi_hba_t *hba)
{
	rd_host_t *rd_host;

	if (!hba->hba_ptr) {
		TRACE_ERROR("hba->hba_ptr is NULL!\n");
		return(-1);
	}

	rd_host = (rd_host_t *) hba->hba_ptr;

        PYXPRINT("iSCSI_HBA[%d] - Detached Ramdisk HBA: %u from iSCSI Transport\n",
			hba->hba_id, rd_host->rd_host_id);
	
	kfree(rd_host);
	hba->hba_ptr = NULL;
	
	return(0);
}

/*	rd_release_device_space():
 *
 *
 */
extern void rd_release_device_space (rd_dev_t *rd_dev)
{
	u32 i, j, page_count = 0, sg_per_table;
	rd_dev_sg_table_t *sg_table;
	struct page *pg;
	struct scatterlist *sg;

	if (!rd_dev->sg_table_array || !rd_dev->sg_table_count)
		return;

	sg_table = rd_dev->sg_table_array;
	
	for (i = 0; i < rd_dev->sg_table_count; i++) {
		sg = sg_table[i].sg_table;
		sg_per_table = sg_table[i].rd_sg_count;

		for (j = 0; j < sg_per_table; j++) {
			if ((pg = sg_page(&sg[j]))) {
				__free_page(pg);
				page_count++;
			}
		}

		kfree(sg);
	}

	PYXPRINT("iSCSI_RD[%u] - Released device space for Ramdisk Device ID: %u,"
		" pages %u in %u tables total bytes %lu\n", rd_dev->rd_host->rd_host_id,
			rd_dev->rd_dev_id, page_count, rd_dev->sg_table_count,
			(unsigned long)page_count * PAGE_SIZE);
	
	kfree(sg_table);
	
	return;
}
		

/*	rd_build_device_space():
 *
 *
 */
static int rd_build_device_space (rd_dev_t *rd_dev)
{
	u32 i = 0, j, page_offset = 0, sg_per_table, sg_tables, total_sg_needed;
	u32 max_sg_per_table = (RD_MAX_ALLOCATION_SIZE / sizeof(struct scatterlist));
	rd_dev_sg_table_t *sg_table;
	struct page *pg;
	struct scatterlist *sg;
	
	if (rd_dev->rd_page_count <= 0) {
		TRACE_ERROR("Illegal page count: %u for Ramdisk device\n",
			rd_dev->rd_page_count);
		return(-1);
	}
	total_sg_needed = rd_dev->rd_page_count;

	sg_tables = (total_sg_needed / max_sg_per_table) + 1;

	if (!(sg_table = (rd_dev_sg_table_t *) kmalloc(
			sg_tables * sizeof(rd_dev_sg_table_t), GFP_KERNEL))) {
		TRACE_ERROR("Unable to allocate memory for Ramdisk"
			" scatterlist tables\n");
		return(-1);
	}
	memset(sg_table, 0, sg_tables * sizeof(rd_dev_sg_table_t));

	rd_dev->sg_table_array = sg_table;
	rd_dev->sg_table_count = sg_tables;
	
	while (total_sg_needed) {
		sg_per_table = (total_sg_needed > max_sg_per_table) ?
			max_sg_per_table : total_sg_needed;	

		if (!(sg = (struct scatterlist *) kmalloc(
				sg_per_table * sizeof(struct scatterlist),
				GFP_KERNEL))) {
			TRACE_ERROR("Unable to allocate scatterlist array"
				" for rd_dev_t\n");
			return(-1);
		}
		memset(sg, 0, sg_per_table * sizeof(struct scatterlist));

		sg_init_table((struct scatterlist *)&sg[0], sg_per_table);

		sg_table[i].sg_table = sg;
		sg_table[i].rd_sg_count = sg_per_table;
		sg_table[i].page_start_offset = page_offset;
		sg_table[i++].page_end_offset = (page_offset + sg_per_table) - 1;

		for (j = 0; j < sg_per_table; j++) {
			if (!(pg = (struct page *) alloc_pages(
					GFP_KERNEL, 0))) {
				TRACE_ERROR("Unable to allocate scatterlist"
					" pages for rd_dev_sg_table_t\n");
				return(-1);
			}
			sg_assign_page(&sg[j], pg);
			sg[j].length = PAGE_SIZE;
		}

		page_offset += sg_per_table;
		total_sg_needed -= sg_per_table;
	}

	PYXPRINT("iSCSI_RD[%u] - Built Ramdisk Device ID: %u space of %u pages"
		" in %u tables\n", rd_dev->rd_host->rd_host_id, rd_dev->rd_dev_id,
			rd_dev->rd_page_count, rd_dev->sg_table_count);
	
	return(0);
}

/*	rd_create_virtdevice():
 *
 *
 */
static int rd_create_virtdevice (iscsi_hba_t *iscsi_hba, iscsi_devinfo_t *di, int rd_direct)
{
	iscsi_device_t *dev;
	rd_dev_t *rd_dev;
	rd_host_t *rd_host = (rd_host_t *) iscsi_hba->hba_ptr;

	if (!(rd_dev = (rd_dev_t *) kmalloc(sizeof(rd_dev_t), GFP_KERNEL))) {
		TRACE_ERROR("Unable to allocate memory for rd_dev_t\n");
		return(0);
	}
	memset(rd_dev, 0, sizeof(rd_dev_t));

	rd_dev->rd_dev_id = di->rd_device_id;
	rd_dev->rd_page_count = di->rd_pages;
	rd_dev->rd_host = rd_host;
	rd_dev->rd_direct = rd_direct;

	di->dev_flags |= DF_DISABLE_STATUS_THREAD;
	if (rd_dev->rd_direct)
		di->dev_flags |= DF_TRANSPORT_DMA_ALLOC;
	
	if (rd_build_device_space(rd_dev) < 0)
		goto fail;
	
	if (!(dev = rd_add_device_to_list(iscsi_hba, rd_dev, di)))
		goto fail;

	rd_dev->rd_queue_depth = dev->queue_depth;
	
	PYXPRINT("iSCSI_RD[%u] - Added iSBE %s Ramdisk Device ID: %u of %u pages in"
		" %u tables, %lu total bytes\n", rd_host->rd_host_id, (!rd_dev->rd_direct) ?
		"MEMCPY" : "DIRECT", rd_dev->rd_dev_id, rd_dev->rd_page_count,
		rd_dev->sg_table_count, (unsigned long)(rd_dev->rd_page_count * PAGE_SIZE));

	return(1);

fail:
	rd_release_device_space(rd_dev);
	kfree(rd_dev);

	return(0);
}

extern int rd_DIRECT_create_virtdevice (iscsi_hba_t *iscsi_hba, iscsi_devinfo_t *di)
{
	return(rd_create_virtdevice(iscsi_hba, di, 1));	
}

extern int rd_MEMCPY_create_virtdevice (iscsi_hba_t *iscsi_hba, iscsi_devinfo_t *di)
{
	return(rd_create_virtdevice(iscsi_hba, di, 0));
}

/*	rd_add_device_to_list():
 *
 *
 */
extern iscsi_device_t *rd_add_device_to_list (iscsi_hba_t *iscsi_hba, void *rd_dev_p, iscsi_devinfo_t *di)
{
	iscsi_device_t *dev;
	rd_dev_t *rd_dev = (rd_dev_t *) rd_dev_p;
	
	if (!(dev = transport_add_device_to_iscsi_hba(iscsi_hba,
			(rd_dev->rd_direct) ? &rd_dr_template : &rd_mcp_template,
			di->dev_flags, (void *)rd_dev)))
		return(NULL);

	return(dev);
}

/*	rd_activate_device(): (Part of iscsi_transport_t template)
 *
 *
 */
extern int rd_activate_device (iscsi_device_t *dev)
{
	rd_dev_t *rd_dev = (rd_dev_t *) dev->dev_ptr;
	rd_host_t *rd_host = rd_dev->rd_host;
	
	PYXPRINT("iSCSI_RD[%u] - Activating Device with TCQ: %d at Ramdisk"
		" Device ID: %d\n", rd_host->rd_host_id, rd_dev->rd_queue_depth,
		rd_dev->rd_dev_id);

	return(0);
}

/*	rd_deactivate_device(): (Part of iscsi_transport_t template)
 *
 *
 */
extern void rd_deactivate_device (iscsi_device_t *dev)
{
	rd_dev_t *rd_dev = (rd_dev_t *) dev->dev_ptr;
	rd_host_t *rd_host = rd_dev->rd_host;

	PYXPRINT("iSCSI_RD[%u] - Deactivating Device with TCQ: %d at Ramdisk"
		" Device ID: %d\n", rd_host->rd_host_id, rd_dev->rd_queue_depth,
		rd_dev->rd_dev_id);

	return;
}

/*	rd_check_device_location(): (Part of iscsi_transport_t template)
 *
 *
 */
extern int rd_check_device_location (iscsi_device_t *dev, iscsi_dev_transport_info_t *dti)
{
	rd_dev_t *rd_dev = (rd_dev_t *) dev->dev_ptr;

	if (dti->rd_device_id == rd_dev->rd_dev_id)
		return(0);

	return(-1);
}

extern int rd_check_ghost_id (iscsi_hbainfo_t *hi, int type)
{
	int i;          
	iscsi_hba_t *hba;
	rd_host_t *rh;

	spin_lock(&iscsi_global->hba_lock);
	for (i = 0; i < ISCSI_MAX_GLOBAL_HBAS; i++) {
		hba = &iscsi_global->hba_list[i];

		if (!(hba->hba_status & HBA_STATUS_ACTIVE))
			continue;
		if (hba->type != type)
			continue;

		rh = (rd_host_t *) hba->hba_ptr;
		if (rh->rd_host_id == hi->rd_host_id) {
			TRACE_ERROR("RAMDISK HBA with RH_HOST_ID: %u already"
				" assigned to iSCSI HBA: %hu, ignoring request\n",
				hi->rd_host_id, hba->hba_id);
			spin_unlock(&iscsi_global->hba_lock);
			return(-1);
		}
	}
	spin_unlock(&iscsi_global->hba_lock);
		
	return(0);
}

extern int rd_mcp_check_ghost_id (iscsi_hbainfo_t *hi)
{
	return(rd_check_ghost_id(hi, RAMDISK_MCP));
}

extern int rd_dr_check_ghost_id (iscsi_hbainfo_t *hi)
{
	return(rd_check_ghost_id(hi, RAMDISK_DR));
}

/*	rd_free_device(): (Part of iscsi_transport_t template)
 *
 *
 */
extern void rd_free_device (iscsi_device_t *dev)
{
	rd_dev_t *rd_dev = (rd_dev_t *) dev->dev_ptr;

	rd_release_device_space(rd_dev);
	kfree(rd_dev);

	return;
}

/*	rd_transport_complete(): (Part of iscsi_transport_t template)
 *
 *
 */
extern int rd_transport_complete (se_task_t *task)
{
	return(0);
}

/*	rd_allocate_request(): (Part of iscsi_transport_t template)
 *
 *
 */
extern void *rd_allocate_request (
	se_task_t *task,
	iscsi_device_t *dev)
{
	rd_request_t *rd_req;
	
	if (!(rd_req = (rd_request_t *) kmalloc(sizeof(rd_request_t), GFP_KERNEL))) {
		TRACE_ERROR("Unable to allocate rd_request_t\n");
		return(NULL);
	}
	memset(rd_req, 0, sizeof(rd_request_t));

	rd_req->rd_dev = (rd_dev_t *) dev->dev_ptr;

	return((void *)rd_req);
}

extern void rd_get_evpd_prod (unsigned char *buf, u32 size, iscsi_device_t *dev)
{
	rd_dev_t *rd_dev = (rd_dev_t *) dev->dev_ptr;

	snprintf(buf, size, "RAMDISK-%s", (rd_dev->rd_direct) ? "DR" : "MCP");
	return;
}

extern void rd_get_evpd_sn (unsigned char *buf, u32 size, iscsi_device_t *dev)
{
	rd_dev_t *rd_dev = (rd_dev_t *) dev->dev_ptr;
	iscsi_hba_t *hba = dev->iscsi_hba;

	snprintf(buf, size, "%u_%u", hba->hba_id, rd_dev->rd_dev_id);
	return;
}

/*	rd_emulate_inquiry():
 *
 *
 */
static int rd_emulate_inquiry (se_task_t *task)
{
	unsigned char prod[64], se_location[128];
	rd_dev_t *rd_dev = (rd_dev_t *) task->iscsi_dev->dev_ptr;
	iscsi_cmd_t *cmd = task->iscsi_cmd;
	iscsi_hba_t *hba = task->iscsi_dev->iscsi_hba;
	
	memset(prod, 0, 64);
	memset(se_location, 0, 128);

	sprintf(prod, "RAMDISK-%s", (rd_dev->rd_direct) ? "DR" : "MCP");
	sprintf(se_location, "%u_%u", hba->hba_id, rd_dev->rd_dev_id);

	return(transport_generic_emulate_inquiry(cmd, TYPE_DISK, prod,
			(hba->transport->do_se_mem_map) ? RD_DR_VERSION : RD_MCP_VERSION,
			se_location, NULL));
}

/*	rd_emulate_read_cap():
 *
 *
 */
static int rd_emulate_read_cap (se_task_t *task)
{
	rd_dev_t *rd_dev = (rd_dev_t *) task->iscsi_dev->dev_ptr;
	u32 blocks = ((rd_dev->rd_page_count * PAGE_SIZE) / RD_BLOCKSIZE) - 1;

	if ((((rd_dev->rd_page_count * PAGE_SIZE) / RD_BLOCKSIZE) - 1) > 0x00000000ffffffff)
		blocks = 0xffffffff;

	return(transport_generic_emulate_readcapacity(task->iscsi_cmd, blocks, RD_BLOCKSIZE));
}

static int rd_emulate_read_cap16 (se_task_t *task)
{
	rd_dev_t *rd_dev = (rd_dev_t *) task->iscsi_dev->dev_ptr;
	unsigned long long blocks_long = ((rd_dev->rd_page_count * PAGE_SIZE) / RD_BLOCKSIZE) - 1;	

	return(transport_generic_emulate_readcapacity_16(task->iscsi_cmd, blocks_long, RD_BLOCKSIZE));
}

/*	rd_emulate_scsi_cdb():
 *
 *
 */
static int rd_emulate_scsi_cdb (se_task_t *task)
{
	int ret;
	iscsi_cmd_t *cmd = task->iscsi_cmd;
	rd_request_t *rd_req = (rd_request_t *) task->transport_req;

	switch (rd_req->rd_scsi_cdb[0]) {
	case INQUIRY:
		if (rd_emulate_inquiry(task) < 0)
			return(PYX_TRANSPORT_INVALID_CDB_FIELD);
		break;
	case READ_CAPACITY:
		if ((ret = rd_emulate_read_cap(task)) < 0)
			return(ret);
		break;
	case MODE_SENSE:
		if ((ret = transport_generic_emulate_modesense(task->iscsi_cmd,
				rd_req->rd_scsi_cdb, rd_req->rd_buf, 0, TYPE_DISK)) < 0)
			return(ret);
		break;
	case MODE_SENSE_10:
		if ((ret = transport_generic_emulate_modesense(task->iscsi_cmd,
				rd_req->rd_scsi_cdb, rd_req->rd_buf, 1, TYPE_DISK)) < 0)
			return(ret);
		break;
	case SERVICE_ACTION_IN:
		if ((T_TASK(cmd)->t_task_cdb[1] & 0x1f) != SAI_READ_CAPACITY_16) {
			TRACE_ERROR("Unsupported SA: 0x%02x\n", T_TASK(cmd)->t_task_cdb[1] & 0x1f);
			return(PYX_TRANSPORT_UNKNOWN_SAM_OPCODE);
		}
		if ((ret = rd_emulate_read_cap16(task)) < 0)
			return(ret);
		break;
	case ALLOW_MEDIUM_REMOVAL:
	case ERASE:
	case LOAD_UNLOAD_MEDIUM:
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
		TRACE_ERROR("Unsupported SCSI Opcode: 0x%02x for RAMDISKs\n",
				rd_req->rd_scsi_cdb[0]);
		return(PYX_TRANSPORT_UNKNOWN_SAM_OPCODE);
	}

	task->task_scsi_status = GOOD;
	transport_complete_task(task, 1);
	
	return(PYX_TRANSPORT_SENT_TO_TRANSPORT);
}

/*	rd_get_sg_table():
 *
 *
 */
static rd_dev_sg_table_t *rd_get_sg_table (rd_dev_t *rd_dev, u32 page)
{
	u32 i;
	rd_dev_sg_table_t *sg_table;

	for (i = 0; i < rd_dev->sg_table_count; i++) {
		sg_table = &rd_dev->sg_table_array[i];
		if ((sg_table->page_start_offset <= page) &&
		    (sg_table->page_end_offset >= page))
			return(sg_table);
	}

	TRACE_ERROR("Unable to locate rd_dev_sg_table_t for page: %u\n", page);
	
	return(NULL);
}

/*	rd_MEMCPY_read():
 *
 *
 */
static int rd_MEMCPY_read (rd_request_t *req)
{
	rd_dev_t *dev = req->rd_dev; 
	rd_dev_sg_table_t *table;
	struct scatterlist *sg_d, *sg_s;
	void *dst, *src;
	u32 i = 0, j = 0, dst_offset = 0, src_offset = 0;
	u32 length, page_end = 0, table_sg_end;
	u32 rd_offset = req->rd_offset;

	if (!(table = rd_get_sg_table(dev, req->rd_page)))
		return(-1);
	        
	table_sg_end = (table->page_end_offset - req->rd_page);
	sg_d = (struct scatterlist *) req->rd_buf; 
	sg_s = &table->sg_table[req->rd_page - table->page_start_offset];
#ifdef DEBUG_RAMDISK_MCP
	printk("RD[%u]: Read LBA: %llu, Size: %u Page: %u, Offset: %u\n",
		dev->rd_dev_id, req->rd_lba, req->rd_size, req->rd_page, req->rd_offset);
#endif	
	src_offset = rd_offset;

	while (req->rd_size) {
		if ((sg_d[i].length - dst_offset) < (sg_s[j].length - src_offset)) {
			length = (sg_d[i].length - dst_offset);
#ifdef DEBUG_RAMDISK_MCP
			printk("Step 1 - sg_d[%d]: %p length: %d offset: %u sg_s[%d].length: %u\n",
				i, &sg_d[i], sg_d[i].length, sg_d[i].offset, j, sg_s[j].length);
			printk("Step 1 - length: %u dst_offset: %u src_offset: %u\n",
				length, dst_offset, src_offset);
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
			printk("Step 2 - sg_d[%d]: %p length: %d offset: %u sg_s[%d].length: %u\n",
				i, &sg_d[i], sg_d[i].length, sg_d[i].offset, j, sg_s[j].length);
			printk("Step 2 - length: %u dst_offset: %u src_offset: %u\n",
				length, dst_offset, src_offset);
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
		printk("page: %u, remaining size: %u, length: %u, i: %u, j: %u\n",
			req->rd_page, (req->rd_size - length), length, i, j);
#endif
		if (!(req->rd_size -= length))
			return(0);

		if (!page_end)
			continue;

		if (++req->rd_page <= table->page_end_offset) {
#ifdef DEBUG_RAMDISK_MCP
			printk("page: %u in same page table\n",
				req->rd_page);
#endif
			continue;
		}
#ifdef DEBUG_RAMDISK_MCP
		printk("getting new page table for page: %u\n",
				req->rd_page);
#endif
		if (!(table = rd_get_sg_table(dev, req->rd_page)))
			return(-1);

		sg_s = &table->sg_table[j = 0];
	}

	return(0);
}

/*	rd_MEMCPY_write():
 *
 *
 */
static int rd_MEMCPY_write (rd_request_t *req)
{
	rd_dev_t *dev = req->rd_dev;
	rd_dev_sg_table_t *table; 
	struct scatterlist *sg_d, *sg_s;
	void *dst, *src;
	u32 i = 0, j = 0, dst_offset = 0, src_offset = 0;
	u32 length, page_end = 0, table_sg_end;
	u32 rd_offset = req->rd_offset;
	
	if (!(table = rd_get_sg_table(dev, req->rd_page)))
		return(-1);
	
	table_sg_end = (table->page_end_offset - req->rd_page);
	sg_d = &table->sg_table[req->rd_page - table->page_start_offset];
	sg_s = (struct scatterlist *) req->rd_buf;
#ifdef DEBUG_RAMDISK_MCP
	printk("RD[%d] Write LBA: %llu, Size: %u, Page: %u, Offset: %u\n",
		dev->rd_dev_id, req->rd_lba, req->rd_size, req->rd_page, req->rd_offset);
#endif	
	dst_offset = rd_offset;

	while (req->rd_size) {
		if ((sg_s[i].length - src_offset) < (sg_d[j].length - dst_offset)) {
			length = (sg_s[i].length - src_offset);
#ifdef DEBUG_RAMDISK_MCP
			printk("Step 1 - sg_s[%d]: %p length: %d offset: %d sg_d[%d].length: %u\n",
				i, &sg_s[i], sg_s[i].length, sg_s[i].offset, j, sg_d[j].length);
			printk("Step 1 - length: %u src_offset: %u dst_offset: %u\n",
				length, src_offset, dst_offset);
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
			printk("Step 2 - sg_s[%d]: %p length: %d offset: %d sg_d[%d].length: %u\n",
				i, &sg_s[i], sg_s[i].length, sg_s[i].offset, j, sg_d[j].length);
			printk("Step 2 - length: %u src_offset: %u dst_offset: %u\n",
				length, src_offset, dst_offset);
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
		printk("page: %u, remaining size: %u, length: %u, i: %u, j: %u\n",
			req->rd_page, (req->rd_size - length), length, i, j);
#endif
		if (!(req->rd_size -= length))
			return(0);

		if (!page_end)
			continue;
		
		if (++req->rd_page <= table->page_end_offset) {
#ifdef DEBUG_RAMDISK_MCP
			printk("page: %u in same page table\n",
				req->rd_page);
#endif
			continue;
		}
#ifdef DEBUG_RAMDISK_MCP
		printk("getting new page table for page: %u\n",
				req->rd_page);
#endif
		if (!(table = rd_get_sg_table(dev, req->rd_page)))
			return(-1);

		sg_d = &table->sg_table[j = 0];
	}

	return(0);
}

/*	rd_MEMCPY_do_task(): (Part of iscsi_transport_t template)
 *
 *
 */
extern int rd_MEMCPY_do_task (se_task_t *task)
{
	int ret = 0;
	rd_request_t *req = (rd_request_t *) task->transport_req;

	if (!(task->iscsi_cmd->cmd_flags & ICF_SCSI_DATA_SG_IO_CDB))
		return(rd_emulate_scsi_cdb(task));
		
	req->rd_lba = task->task_lba;
	req->rd_page = (req->rd_lba * RD_BLOCKSIZE) / PAGE_SIZE;
	req->rd_offset = (req->rd_lba % (PAGE_SIZE / RD_BLOCKSIZE)) * RD_BLOCKSIZE;
	req->rd_size = task->task_size;

	if (req->rd_data_direction == RD_DATA_READ)
		ret = rd_MEMCPY_read(req);
	else
		ret = rd_MEMCPY_write(req);

	if (ret != 0)       
		return(ret);

	task->task_scsi_status = GOOD;   
	transport_complete_task(task, 1);

	return(PYX_TRANSPORT_SENT_TO_TRANSPORT);
}

/*	rd_DIRECT_with_offset():
 *
 *
 */
static int rd_DIRECT_with_offset (se_task_t *task, struct list_head *se_mem_list, u32 *se_mem_cnt, u32 *task_offset)
{
	rd_request_t *req = (rd_request_t *)task->transport_req;
	rd_dev_t *dev = req->rd_dev;
	rd_dev_sg_table_t *table;
	se_mem_t *se_mem;
	struct scatterlist *sg_s;
	u32 j = 0, set_offset = 1;
	u32 get_next_table = 0, offset_length, table_sg_end;

	if (!(table = rd_get_sg_table(dev, req->rd_page)))
		return(-1);

	table_sg_end = (table->page_end_offset - req->rd_page);
	sg_s = &table->sg_table[req->rd_page - table->page_start_offset];
#ifdef DEBUG_RAMDISK_DR
	printk("%s DIRECT LBA: %llu, Size: %u Page: %u, Offset: %u\n",
		(req->rd_data_direction != RD_DATA_READ) ? "Write" : "Read",
		req->rd_lba, req->rd_size, req->rd_page, req->rd_offset);
#endif
	while (req->rd_size) {
		if (!(se_mem = kmalloc(sizeof(se_mem_t), GFP_KERNEL))) {
			TRACE_ERROR("Unable to allocate se_mem_t\n");
			return(-1);
		}
		memset(se_mem, 0, sizeof(se_mem_t));

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
		printk("page: %u, size: %u, offset_length: %u, j: %u se_mem: %p,"
			" se_page: %p se_off: %u se_len: %u\n", req->rd_page,
			req->rd_size, offset_length, j, se_mem, se_mem->se_page,
			se_mem->se_off, se_mem->se_len);
#endif
		list_add_tail(&se_mem->se_list, se_mem_list);
		(*se_mem_cnt)++;

		if (!(req->rd_size -= offset_length))
			goto out;

		if (!set_offset && !get_next_table)
			continue;

		if (++req->rd_page <= table->page_end_offset) {
#ifdef DEBUG_RAMDISK_DR
			printk("page: %u in same page table\n",
					req->rd_page);
#endif
			continue;
		}
#ifdef DEBUG_RAMDISK_DR
		printk("getting new page table for page: %u\n",
				req->rd_page);
#endif
		if (!(table = rd_get_sg_table(dev, req->rd_page)))
			return(-1);

		sg_s = &table->sg_table[j = 0];
	}

out:
	T_TASK(task->iscsi_cmd)->t_task_se_num += *se_mem_cnt;
#ifdef DEBUG_RAMDISK_DR
	printk("RD_DR - Allocated %u se_mem_t segments for task\n", *se_mem_cnt);
#endif
	return(0);
}

/*	rd_DIRECT_without_offset():
 *
 *
 */
static int rd_DIRECT_without_offset (se_task_t *task, struct list_head *se_mem_list, u32 *se_mem_cnt, u32 *task_offset)
{
	rd_request_t *req = (rd_request_t *)task->transport_req;
	rd_dev_t *dev = req->rd_dev;
	rd_dev_sg_table_t *table;
	se_mem_t *se_mem;
	struct scatterlist *sg_s;
	u32 length, j = 0;

	if (!(table = rd_get_sg_table(dev, req->rd_page)))
		return(-1);

	sg_s = &table->sg_table[req->rd_page - table->page_start_offset];
#ifdef DEBUG_RAMDISK_DR
	printk("%s DIRECT LBA: %llu, Size: %u, Page: %u\n",
		(req->rd_data_direction != RD_DATA_READ) ? "Write" : "Read",
		req->rd_lba, req->rd_size, req->rd_page);
#endif
	while (req->rd_size) {
		if (!(se_mem = kmalloc(sizeof(se_mem_t), GFP_KERNEL))) {
			TRACE_ERROR("Unable to allocate se_mem_t\n");
			return(-1);
		}
		memset(se_mem, 0, sizeof(se_mem_t));

		INIT_LIST_HEAD(&se_mem->se_list);

		length = (req->rd_size < sg_s[j].length) ?
			req->rd_size : sg_s[j].length;
		
		se_mem->se_page = sg_page(&sg_s[j++]);
		se_mem->se_len = length;

#ifdef DEBUG_RAMDISK_DR
		printk("page: %u, size: %u, j: %u se_mem: %p, se_page: %p"
			" se_off: %u se_len: %u\n", req->rd_page, req->rd_size,
			j, se_mem, se_mem->se_page, se_mem->se_off, se_mem->se_len);
#endif          
                list_add_tail(&se_mem->se_list, se_mem_list);
                (*se_mem_cnt)++;
		
		if (!(req->rd_size -= length))
			goto out;

		if (++req->rd_page <= table->page_end_offset) {
#ifdef DEBUG_RAMDISK_DR
			printk("page: %u in same page table\n",
				req->rd_page);
#endif
			continue;
		}
#ifdef DEBUG_RAMDISK_DR
		printk("getting new page table for page: %u\n",
				req->rd_page);
#endif
		if (!(table = rd_get_sg_table(dev, req->rd_page)))
			return(-1);

		sg_s = &table->sg_table[j = 0];
	}

out:
	T_TASK(task->iscsi_cmd)->t_task_se_num += *se_mem_cnt;
#ifdef DEBUG_RAMDISK_DR
	printk("RD_DR - Allocated %u se_mem_t segments for task\n", *se_mem_cnt);
#endif
	return(0);
}

/*	rd_DIRECT_do_se_mem_map():
 *
 *
 */
extern int rd_DIRECT_do_se_mem_map (
	se_task_t *task,
	struct list_head *se_mem_list,
	void *in_mem,
	se_mem_t *in_se_mem,
	se_mem_t **out_se_mem,
	u32 *se_mem_cnt,
	u32 *task_offset)
{
	rd_request_t *req = (rd_request_t *) task->transport_req;
	int ret;

	req->rd_lba = task->task_lba;
	req->rd_req_flags = RRF_GOT_LBA;
	req->rd_page = ((req->rd_lba * RD_BLOCKSIZE) / PAGE_SIZE);
	req->rd_offset = (req->rd_lba % (PAGE_SIZE / RD_BLOCKSIZE)) * RD_BLOCKSIZE;
	req->rd_size = task->task_size;

	if (req->rd_offset)
		ret = rd_DIRECT_with_offset(task, se_mem_list, se_mem_cnt, task_offset);
	else
		ret = rd_DIRECT_without_offset(task, se_mem_list, se_mem_cnt, task_offset);

	return(ret);
}

/*	rd_DIRECT_free_DMA():
 *
 *
 */
extern void rd_DIRECT_free_DMA (iscsi_cmd_t *cmd)
{
	se_mem_t *se_mem, *se_mem_tmp;

	/*
	 * The scatterlists in the RAMDISK DIRECT case are using the pages
	 * from the rd_device_t's scatterlist table. They are referencing valid memory
	 * that is held within the RD transport plugin, so we only free the se_mem_t
	 * elements.
	 */
	list_for_each_entry_safe(se_mem, se_mem_tmp, T_TASK(cmd)->t_mem_list, se_list) {
		 list_del(&se_mem->se_list);
		 kfree(se_mem);
	}
	kfree(T_TASK(cmd)->t_mem_list);
	T_TASK(cmd)->t_mem_list = NULL;
	T_TASK(cmd)->t_task_se_num = 0;
	return;
}

/*	rd_DIRECT_allocate_DMA():
 *
 *	Note that rd_DIRECT_do_se_mem_map() actually does the real work.
 */
extern int rd_DIRECT_allocate_DMA (iscsi_cmd_t *cmd, u32 length, u32 dma_size)
{
	if (!(T_TASK(cmd)->t_mem_list = kmalloc(sizeof(struct list_head), GFP_KERNEL))) {
		TRACE_ERROR("Unable to allocate memory for T_TASK(cmd)->t_mem_list\n");
		return(-1);
	}
	memset(T_TASK(cmd)->t_mem_list, 0, sizeof(struct list_head));

	INIT_LIST_HEAD(T_TASK(cmd)->t_mem_list);

	return(0);
}

/*	rd_DIRECT_do_task(): (Part of iscsi_transport_t template)
 *
 *
 */
extern int rd_DIRECT_do_task (se_task_t *task)
{
	if (!(task->iscsi_cmd->cmd_flags & ICF_SCSI_DATA_SG_IO_CDB))
		return(rd_emulate_scsi_cdb(task));

	/*
	 * At this point the locally allocated RD tables have been mapped
	 * to se_mem_t elements in rd_DIRECT_do_se_mem_map().
	 */
	task->task_scsi_status = GOOD;					
	transport_complete_task(task, 1);				
										
	return(PYX_TRANSPORT_SENT_TO_TRANSPORT);				
}

/*	rd_free_task(): (Part of iscsi_transport_t template)
 *
 *
 */
extern void rd_free_task (se_task_t *task)
{
	rd_request_t *req;
	req = (rd_request_t *) task->transport_req;

	kfree(req);
	
	return;
}

extern int rd_check_hba_params (iscsi_hbainfo_t *hi, struct iscsi_target *t, int virt)
{
	if (!(t->hba_params_set & PARAM_HBA_RD_HOST_ID)) {
		TRACE_ERROR("rd_host_id must be set for"
			" addhbatotarget requests with Ramdisk"
			" Interfaces\n");
		return(ERR_HBA_MISSING_PARAMS);
	}
	hi->rd_host_id = t->rd_host_id;

	return(0);
}

extern int rd_check_dev_params (iscsi_hba_t *hba, struct iscsi_target *t, iscsi_dev_transport_info_t *dti)
{
	if (!(t->hba_params_set & PARAM_HBA_RD_DEVICE_ID)) {
		TRACE_ERROR("Missing Ramdisk createvirtdev parameters\n");
		return(ERR_VIRTDEV_MISSING_PARAMS);
	}
	dti->rd_device_id = t->rd_device_id; 

	return(0);
}

extern int rd_check_virtdev_params (iscsi_devinfo_t *di, struct iscsi_target *t)
{
	if (!(t->hba_params_set & PARAM_HBA_RD_DEVICE_ID) ||
	    !(t->hba_params_set & PARAM_HBA_RD_PAGES)) {
		TRACE_ERROR("Missing Ramdisk createvirtdev parameters\n");
		return(ERR_VIRTDEV_MISSING_PARAMS);
	}

	di->rd_device_id = t->rd_device_id;
	di->rd_direct = t->rd_direct;
	di->rd_pages = t->rd_pages;

	return(0);
}

extern void rd_dr_get_plugin_info (void *p, char *b, int *bl)
{
	*bl += sprintf(b+*bl, "%s RAMDISK_DR Plugin %s\n", PYX_ISCSI_VENDOR, RD_DR_VERSION);

	return;
}

extern void rd_mcp_get_plugin_info (void *p, char *b, int *bl)
{
        *bl += sprintf(b+*bl, "%s RAMDISK_MCP Plugin %s\n", PYX_ISCSI_VENDOR, RD_MCP_VERSION);

	return;
}

extern void rd_get_hba_info (iscsi_hba_t *hba, char *b, int *bl)
{
	*bl += sprintf(b+*bl, "iSCSI Host ID: %u  RD Host ID: %u\n",
		hba->hba_id, hba->hba_info.rd_host_id);
	*bl += sprintf(b+*bl, "        iSBE RamDisk HBA\n");

	return;
}

extern void rd_get_dev_info (iscsi_device_t *dev, char *b, int *bl)
{
	struct rd_dev_s *rd = (struct rd_dev_s *) dev->dev_ptr;

	*bl += sprintf(b+*bl, "iSBE RamDisk ID: %u  RamDisk Makeup: %s\n",
			rd->rd_dev_id, TRANSPORT(dev)->name);
	*bl += sprintf(b+*bl, "        PAGES/PAGE_SIZE: %u*%lu  SG_table_count: %u\n",
			rd->rd_page_count, PAGE_SIZE, rd->sg_table_count);

	return;
}

/*	rd_map_task_non_SG():
 *
 *
 */
extern void rd_map_task_non_SG (se_task_t *task)
{
	iscsi_cmd_t *cmd = task->iscsi_cmd;
	rd_request_t *req = (rd_request_t *) task->transport_req;

	req->rd_bufflen		= task->task_size;
	req->rd_buf		= (void *) T_TASK(cmd)->t_task_buf;
	req->rd_sg_count	= 0;
	
	return;
}

/*	rd_map_task_SG():
 *
 *
 */
extern void rd_map_task_SG (se_task_t *task)
{
	rd_request_t *req = (rd_request_t *) task->transport_req;

	req->rd_bufflen		= task->task_size;
	req->rd_buf		= (void *)task->task_buf;
	req->rd_sg_count	= task->task_sg_num;

	return;
}

/*      iblock_CDB_inquiry():
 *
 *
 */
extern int rd_CDB_inquiry (se_task_t *task, u32 size)
{      
	rd_request_t *req = (rd_request_t *) task->transport_req;
		        
	req->rd_data_direction  = RD_DATA_READ;
			        
	/*
	 * This causes 255 instead of the requested 256 bytes
	 * to be returned.  This can be safely ignored for now,
	 * and take the Initiators word on INQUIRY data lengths.
	 */
#if 0
	cmd->data_length	= req->rd_bufflen;
#endif
	rd_map_task_non_SG(task);

	return(0);
}

/*      rd_CDB_none():
 *
 *
 */
extern int rd_CDB_none (se_task_t *task, u32 size)
{
	rd_request_t *req = (rd_request_t *) task->transport_req;

	req->rd_data_direction	= RD_DATA_NONE;
	req->rd_bufflen		= 0;
	req->rd_sg_count	= 0;
	req->rd_buf		= NULL;

	return(0);
}

/*	rd_CDB_read_non_SG():
 *
 *
 */
extern int rd_CDB_read_non_SG (se_task_t *task, u32 size)
{
	rd_request_t *req = (rd_request_t *) task->transport_req;

	req->rd_data_direction = RD_DATA_READ;
	rd_map_task_non_SG(task);

	return(0);
}

/*	rd_CDB_read_SG):
 *
 *
 */
extern int rd_CDB_read_SG (se_task_t *task, u32 size)
{
	rd_request_t *req = (rd_request_t *) task->transport_req;

	req->rd_data_direction = RD_DATA_READ;
	rd_map_task_SG(task);

	return(req->rd_sg_count);
}

/*	rd_CDB_write_non_SG():
 *
 *
 */
extern int rd_CDB_write_non_SG (se_task_t *task, u32 size)
{
	rd_request_t *req = (rd_request_t *) task->transport_req;
	
	req->rd_data_direction = RD_DATA_WRITE;
	rd_map_task_non_SG(task);
	
	return(0);
}

/*	d_CDB_write_SG():
 *
 *
 */
extern int rd_CDB_write_SG (se_task_t *task, u32 size)
{
	rd_request_t *req = (rd_request_t *) task->transport_req;

	req->rd_data_direction = RD_DATA_WRITE;
	rd_map_task_SG(task);

	return(req->rd_sg_count);
}

/*	rd_DIRECT_check_lba():
 *
 *
 */
extern int rd_DIRECT_check_lba (unsigned long long lba, iscsi_device_t *dev)
{
	return(((lba % (PAGE_SIZE / RD_BLOCKSIZE)) * RD_BLOCKSIZE) ? 1 : 0);
}

/*	rd_MEMCPY_check_lba():
 *
 *
 */
extern int rd_MEMCPY_check_lba (unsigned long long lba, iscsi_device_t *dev)
{
	return(0);
}

/*	rd_check_for_SG(): (Part of iscsi_transport_t template)
 *
 *
 */
extern int rd_check_for_SG (se_task_t *task)
{
	rd_request_t *req = (rd_request_t *) task->transport_req;
	
	return(req->rd_sg_count);
}

/*	rd_get_cdb(): (Part of iscsi_transport_t template)
 *
 *
 */
extern unsigned char *rd_get_cdb (se_task_t *task)
{
	rd_request_t *req = (rd_request_t *) task->transport_req;

	return(req->rd_scsi_cdb);
}

/*	rd_get_blocksize(): (Part of iscsi_transport_t template)
 *
 *
 */
extern u32 rd_get_blocksize (iscsi_device_t *dev)
{
	return(RD_BLOCKSIZE);
}

extern u32 rd_get_device_rev (iscsi_device_t *dev)
{
	return(02);
}

extern u32 rd_get_device_type (iscsi_device_t *dev)
{
	return(0); /* TYPE_DISK */
}

/*	rd_get_dma_length(): (Part of iscsi_transport_t template)
 *
 *
 */
extern u32 rd_get_dma_length (u32 task_size, iscsi_device_t *dev)
{
	return(PAGE_SIZE);
}

/*	rd_get_max_sectors(): (Part of iscsi_transport_t template)
 *
 *
 */
extern u32 rd_get_max_sectors (iscsi_device_t *dev)
{
	return(RD_MAX_SECTORS);
}

/*	rd_get_queue_depth(): (Part of iscsi_transport_t template)
 *
 *
 */
extern u32 rd_get_queue_depth (iscsi_device_t *dev)
{
	return(RD_DEVICE_QUEUE_DEPTH);
}

/*	rd_get_non_SG(): (Part of iscsi_transport_t template)
 *
 *
 */
extern unsigned char *rd_get_non_SG (se_task_t *task)
{
	rd_request_t *req = (rd_request_t *) task->transport_req;

	return((unsigned char *)req->rd_buf);
}

/*	rd_get_SG(): (Part of iscsi_transport_t template)
 *
 *
 */
extern struct scatterlist *rd_get_SG (se_task_t *task)
{
	rd_request_t *req = (rd_request_t *) task->transport_req;

	return((struct scatterlist *)req->rd_buf);
}

/*	rd_get_SG_count(): (Part of iscsi_transport_t template)
 *
 *
 */
extern u32 rd_get_SG_count (se_task_t *task)
{
	return(0);
}

/*	rd_set_non_SG_buf():
 *
 *
 */
extern int rd_set_non_SG_buf (unsigned char *buf, se_task_t *task)
{
	rd_request_t *req = (rd_request_t *) task->transport_req;
	
	req->rd_buf		= (void *) buf;
	req->rd_bufflen         = task->task_size;
	req->rd_sg_count        = 0;

	return(0);
}
