/*******************************************************************************
 * Filename:  target_core_iblock.c
 *
 * This file contains the Storage Engine  <-> Linux BlockIO transport
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

#include <linux/version.h>
#include <linux/string.h>
#include <linux/timer.h>
#include <linux/fs.h>
#include <linux/blkdev.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/smp_lock.h>
#include <linux/bio.h>
#include <linux/genhd.h>
#include <linux/file.h>
#include <scsi/scsi.h>
#include <scsi/scsi_host.h>

#include <target/target_core_base.h>
#include <target/target_core_device.h>
#include <target/target_core_transport.h>

#include "target_core_iblock.h"

#if 0
#define DEBUG_IBLOCK(x...) printk(x)
#else
#define DEBUG_IBLOCK(x...)
#endif

static struct se_subsystem_api iblock_template;

static void __iblock_get_dev_info(struct iblock_dev *, char *, int *);
static void iblock_bio_done(struct bio *, int);

/*	iblock_attach_hba(): (Part of se_subsystem_api_t template)
 *
 *
 */
static int iblock_attach_hba(struct se_hba *hba, u32 host_id)
{
	struct iblock_hba *ib_host;

	ib_host = kzalloc(sizeof(struct iblock_hba), GFP_KERNEL);
	if (!(ib_host)) {
		printk(KERN_ERR "Unable to allocate memory for"
				" struct iblock_hba\n");
		return -ENOMEM;
	}

	ib_host->iblock_host_id = host_id;

	atomic_set(&hba->left_queue_depth, IBLOCK_HBA_QUEUE_DEPTH);
	atomic_set(&hba->max_queue_depth, IBLOCK_HBA_QUEUE_DEPTH);
	hba->hba_ptr = (void *) ib_host;
	try_module_get(THIS_MODULE);

	printk(KERN_INFO "CORE_HBA[%d] - TCM iBlock HBA Driver %s on"
		" Generic Target Core Stack %s\n", hba->hba_id,
		IBLOCK_VERSION, TARGET_CORE_MOD_VERSION);

	printk(KERN_INFO "CORE_HBA[%d] - Attached iBlock HBA: %u to Generic"
		" Target Core TCQ Depth: %d\n", hba->hba_id,
		ib_host->iblock_host_id, atomic_read(&hba->max_queue_depth));

	return 0;
}

/*	iblock_detach_hba(): (Part of se_subsystem_api_t template)
 *
 *
 */
static int iblock_detach_hba(struct se_hba *hba)
{
	struct iblock_hba *ib_host;

	if (!hba->hba_ptr) {
		printk(KERN_ERR "hba->hba_ptr is NULL!\n");
		return -1;
	}
	ib_host = (struct iblock_hba *) hba->hba_ptr;

	printk(KERN_INFO "CORE_HBA[%d] - Detached iBlock HBA: %u from Generic"
		" Target Core\n", hba->hba_id, ib_host->iblock_host_id);

	kfree(ib_host);
	hba->hba_ptr = NULL;
	module_put(THIS_MODULE);

	return 0;
}

static void *iblock_allocate_virtdevice(struct se_hba *hba, const char *name)
{
	struct iblock_dev *ib_dev = NULL;
	struct iblock_hba *ib_host = (struct iblock_hba *) hba->hba_ptr;

	ib_dev = kzalloc(sizeof(struct iblock_dev), GFP_KERNEL);
	if (!(ib_dev)) {
		printk(KERN_ERR "Unable to allocate struct iblock_dev\n");
		return NULL;
	}
	ib_dev->ibd_host = ib_host;

	printk(KERN_INFO  "IBLOCK: Allocated ib_dev for %s\n", name);

	return ib_dev;
}

static struct se_device *iblock_create_virtdevice(
	struct se_hba *hba,
	struct se_subsystem_dev *se_dev,
	void *p)
{
	struct iblock_dev *ib_dev = (struct iblock_dev *) p;
	struct se_device *dev;
	struct block_device *bd = NULL;
	u32 dev_flags = 0;

	if (!(ib_dev)) {
		printk(KERN_ERR "Unable to locate struct iblock_dev parameter\n");
		return 0;
	}
	/*
	 * These settings need to be made tunable..
	 */
	ib_dev->ibd_bio_set = bioset_create(32, 64);
	if (!(ib_dev->ibd_bio_set)) {
		printk(KERN_ERR "IBLOCK: Unable to create bioset()\n");
		return 0;
	}
	printk(KERN_INFO "IBLOCK: Created bio_set()\n");
	/*
	 * Check if we have an open file descritpor passed through configfs
	 * $TARGET/iblock_0/some_bd/fd pointing to an underlying.
	 * struct block_device.  If so, claim it with the pointer from
	 * iblock_create_virtdevice_from_fd()
	 *
	 * Otherwise, assume that parameters through 'control' attribute
	 * have set ib_dev->ibd_[major,minor]
	 */
	if (ib_dev->ibd_bd) {
		printk(KERN_INFO  "IBLOCK: Claiming struct block_device: %p\n",
			 ib_dev->ibd_bd);

		ib_dev->ibd_major = MAJOR(ib_dev->ibd_bd->bd_dev);
		ib_dev->ibd_minor = MINOR(ib_dev->ibd_bd->bd_dev);

		bd = linux_blockdevice_claim(ib_dev->ibd_major,
				ib_dev->ibd_minor, ib_dev);
		if (!(bd)) {
			printk(KERN_INFO "IBLOCK: Unable to claim"
					" struct block_device\n");
			goto failed;
		}
		dev_flags = DF_CLAIMED_BLOCKDEV;
	} else {
		/*
		 * iblock_check_configfs_dev_params() ensures that
		 * ib_dev->ibd_udev_path must already have been set
		 * in order for echo 1 > $HBA/$DEV/enable to run.
		 */
		printk(KERN_INFO  "IBLOCK: Claiming struct block_device: %s\n",
				ib_dev->ibd_udev_path);

		bd = open_bdev_exclusive(ib_dev->ibd_udev_path,
				FMODE_WRITE|FMODE_READ, ib_dev);
		if (!(bd))
			goto failed;

		dev_flags = DF_CLAIMED_BLOCKDEV;
		ib_dev->ibd_major = MAJOR(bd->bd_dev);
		ib_dev->ibd_minor = MINOR(bd->bd_dev);
		ib_dev->ibd_bd = bd;
		ib_dev->ibd_flags |= IBDF_BDEV_EXCLUSIVE;
	}
	/*
	 * Pass dev_flags for linux_blockdevice_claim() or
	 * linux_blockdevice_claim() from the usage above.
	 *
	 * Note that transport_add_device_to_core_hba() will call
	 * linux_blockdevice_release() internally on failure to
	 * call bd_release() on the referenced struct block_device.
	 */
	dev = transport_add_device_to_core_hba(hba,
			&iblock_template, se_dev, dev_flags, (void *)ib_dev);
	if (!(dev))
		goto failed;

	ib_dev->ibd_depth = dev->queue_depth;

	return dev;

failed:
	if (ib_dev->ibd_bio_set) {
		bioset_free(ib_dev->ibd_bio_set);
		ib_dev->ibd_bio_set = NULL;
	}
	ib_dev->ibd_bd = NULL;
	ib_dev->ibd_major = 0;
	ib_dev->ibd_minor = 0;
	return NULL;
}

/*	iblock_activate_device(): (Part of se_subsystem_api_t template)
 *
 *
 */
static int iblock_activate_device(struct se_device *dev)
{
	struct iblock_dev *ib_dev = (struct iblock_dev *) dev->dev_ptr;
	struct iblock_hba *ib_hba = ib_dev->ibd_host;

	printk(KERN_INFO "CORE_iBLOCK[%u] - Activating Device with TCQ: %d at"
		" Major: %d Minor %d\n", ib_hba->iblock_host_id,
		ib_dev->ibd_depth, ib_dev->ibd_major, ib_dev->ibd_minor);

	return 0;
}

/*	iblock_deactivate_device(): (Part of se_subsystem_api_t template)
 *
 *
 */
static void iblock_deactivate_device(struct se_device *dev)
{
	struct iblock_dev *ib_dev = (struct iblock_dev *) dev->dev_ptr;
	struct iblock_hba *ib_hba = ib_dev->ibd_host;

	printk(KERN_INFO "CORE_iBLOCK[%u] - Deactivating Device with TCQ: %d"
		" at Major: %d Minor %d\n", ib_hba->iblock_host_id,
		ib_dev->ibd_depth, ib_dev->ibd_major, ib_dev->ibd_minor);
}

static void iblock_free_device(void *p)
{
	struct iblock_dev *ib_dev = (struct iblock_dev *) p;

	printk(KERN_INFO "IBLOCK: Releasing Major:Minor - %d:%d\n",
		ib_dev->ibd_major, ib_dev->ibd_minor);

	if (ib_dev->ibd_flags & IBDF_BDEV_EXCLUSIVE)
		close_bdev_exclusive(ib_dev->ibd_bd, FMODE_WRITE|FMODE_READ);
	else
		linux_blockdevice_release(ib_dev->ibd_major, ib_dev->ibd_minor,
				ib_dev->ibd_bd);
	ib_dev->ibd_bd = NULL;

	if (ib_dev->ibd_bio_set) {
		DEBUG_IBLOCK("Calling bioset_free ib_dev->ibd_bio_set: %p\n",
				ib_dev->ibd_bio_set);
		bioset_free(ib_dev->ibd_bio_set);
	}

	kfree(ib_dev);
}

static int iblock_transport_complete(struct se_task *task)
{
	return 0;
}

/*	iblock_allocate_request(): (Part of se_subsystem_api_t template)
 *
 *
 */
static void *iblock_allocate_request(
	struct se_task *task,
	struct se_device *dev)
{
	struct iblock_req *ib_req;

	ib_req = kmalloc(sizeof(struct iblock_req), GFP_KERNEL);
	if (!(ib_req)) {
		printk(KERN_ERR "Unable to allocate memory for struct iblock_req\n");
		return NULL;
	}

	ib_req->ib_dev = (struct iblock_dev *) dev->dev_ptr;
	return (void *)ib_req;
}

static int iblock_emulate_inquiry(struct se_task *task)
{
	unsigned char prod[64], se_location[128];
	struct se_cmd *cmd = TASK_CMD(task);
	struct iblock_dev *ibd = (struct iblock_dev *) task->se_dev->dev_ptr;
	struct se_hba *hba = task->se_dev->se_hba;

	memset(prod, 0, 64);
	memset(se_location, 0, 128);

	sprintf(prod, "IBLOCK");
	sprintf(se_location, "%u_%u_%u", hba->hba_id, ibd->ibd_major,
		ibd->ibd_minor);

	return transport_generic_emulate_inquiry(cmd, TYPE_DISK, prod,
		IBLOCK_VERSION, se_location);
}

static unsigned long long iblock_emulate_read_cap_with_block_size(
	struct se_device *dev,
	struct block_device *bd,
	struct request_queue *q)
{
	unsigned long long blocks_long = (div_u64(i_size_read(bd->bd_inode), 
					bdev_logical_block_size(bd)) - 1);
	u32 block_size = bdev_logical_block_size(bd);

	if (block_size == DEV_ATTRIB(dev)->block_size)
		return blocks_long;

	switch (block_size) {
	case 4096:
		switch (DEV_ATTRIB(dev)->block_size) {
		case 2048:
			blocks_long <<= 1;
			break;
		case 1024:
			blocks_long <<= 2;
			break;
		case 512:
			blocks_long <<= 3;
		default:
			break;
		}
		break;
	case 2048:
		switch (DEV_ATTRIB(dev)->block_size) {
		case 4096:
			blocks_long >>= 1;
			break;
		case 1024:
			blocks_long <<= 1;
			break;
		case 512:
			blocks_long <<= 2;
			break;
		default:
			break;
		}
		break;
	case 1024:
		switch (DEV_ATTRIB(dev)->block_size) {
		case 4096:
			blocks_long >>= 2;
			break;
		case 2048:
			blocks_long >>= 1;
			break;
		case 512:
			blocks_long <<= 1;
			break;
		default:
			break;
		}
		break;
	case 512:
		switch (DEV_ATTRIB(dev)->block_size) {
		case 4096:
			blocks_long >>= 3;
			break;
		case 2048:
			blocks_long >>= 2;
			break;
		case 1024:
			blocks_long >>= 1;
			break;
		default:
			break;
		}
		break;
	default:
		break;
	}

	return blocks_long;
}

static int iblock_emulate_read_cap(struct se_task *task)
{
	struct iblock_dev *ibd = (struct iblock_dev *) task->se_dev->dev_ptr;
	struct block_device *bd = ibd->ibd_bd;
	struct request_queue *q = bdev_get_queue(bd);
	unsigned long long blocks_long = 0;
	u32 blocks = 0;

	blocks_long = iblock_emulate_read_cap_with_block_size(
				task->se_dev, bd, q);
	if (blocks_long >= 0x00000000ffffffff)
		blocks = 0xffffffff;
	else
		blocks = (u32)blocks_long;

	return transport_generic_emulate_readcapacity(TASK_CMD(task), blocks);
}

static int iblock_emulate_read_cap16(struct se_task *task)
{
	struct iblock_dev *ibd = (struct iblock_dev *) task->se_dev->dev_ptr;
	struct block_device *bd = ibd->ibd_bd;
	struct request_queue *q = bdev_get_queue(bd);
	unsigned long long blocks_long;

	blocks_long = iblock_emulate_read_cap_with_block_size(
				task->se_dev, bd, q);
	return transport_generic_emulate_readcapacity_16(
				TASK_CMD(task), blocks_long);
}

static int iblock_emulate_scsi_cdb(struct se_task *task)
{
	int ret;
	struct se_cmd *cmd = TASK_CMD(task);

	switch (T_TASK(cmd)->t_task_cdb[0]) {
	case INQUIRY:
		if (iblock_emulate_inquiry(task) < 0)
			return PYX_TRANSPORT_INVALID_CDB_FIELD;
		break;
	case READ_CAPACITY:
		ret = iblock_emulate_read_cap(task);
		if (ret < 0)
			return ret;
		break;
	case MODE_SENSE:
		ret = transport_generic_emulate_modesense(TASK_CMD(task),
				T_TASK(cmd)->t_task_cdb,
				T_TASK(cmd)->t_task_buf, 0, TYPE_DISK);
		if (ret < 0)
			return ret;
		break;
	case MODE_SENSE_10:
		ret = transport_generic_emulate_modesense(TASK_CMD(task),
				T_TASK(cmd)->t_task_cdb,
			T_TASK(cmd)->t_task_buf, 1, TYPE_DISK);
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
		ret = iblock_emulate_read_cap16(task);
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
		printk(KERN_ERR "Unsupported SCSI Opcode: 0x%02x for iBlock\n",
				T_TASK(cmd)->t_task_cdb[0]);
		return PYX_TRANSPORT_UNKNOWN_SAM_OPCODE;
	}

	task->task_scsi_status = GOOD;
	transport_complete_task(task, 1);

	return PYX_TRANSPORT_SENT_TO_TRANSPORT;
}

static int iblock_do_task(struct se_task *task)
{
	struct iblock_req *req = (struct iblock_req *)task->transport_req;
	struct iblock_dev *ibd = (struct iblock_dev *)req->ib_dev;
	struct request_queue *q = bdev_get_queue(ibd->ibd_bd);
	struct bio *bio = req->ib_bio, *nbio = NULL;

	if (!(TASK_CMD(task)->se_cmd_flags & SCF_SCSI_DATA_SG_IO_CDB))
		return iblock_emulate_scsi_cdb(task);

	while (bio) {
		nbio = bio->bi_next;
		bio->bi_next = NULL;
		DEBUG_IBLOCK("Calling submit_bio() task: %p bio: %p"
			" bio->bi_sector: %llu\n", task, bio, bio->bi_sector);

		submit_bio(
			(TASK_CMD(task)->data_direction == SE_DIRECTION_WRITE),
			bio);

		bio = nbio;
	}

	if (q->unplug_fn)
		q->unplug_fn(q);

	return PYX_TRANSPORT_SENT_TO_TRANSPORT;
}

static void iblock_free_task(struct se_task *task)
{
	struct iblock_req *req = (struct iblock_req *) task->transport_req;

	/*
	 * We do not release the bio(s) here associated with this task, as
	 * this is handled by bio_put() and iblock_bio_destructor().
	 */

	kfree(req);
	task->transport_req = NULL;
}

static ssize_t iblock_set_configfs_dev_params(struct se_hba *hba,
					       struct se_subsystem_dev *se_dev,
					       const char *page, ssize_t count)
{
	struct iblock_dev *ib_dev = (struct iblock_dev *) se_dev->se_dev_su_ptr;
	char *buf, *cur, *ptr, *ptr2;
	unsigned long force;
	int params = 0, ret = 0;

	buf = kzalloc(count, GFP_KERNEL);
	if (!(buf)) {
		printk(KERN_ERR "Unable to allocate memory for temporary"
			" buffer\n");
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

		ptr2 = strstr(cur, "udev_path");
		if ((ptr2)) {
			transport_check_dev_params_delim(ptr, &cur);
			ptr = strstrip(ptr);
			if (ib_dev->ibd_bd) {
				printk(KERN_ERR "Unable to set udev_path= while"
					" ib_dev->ibd_bd exists\n");
				params = 0;
				goto out;
			}

			ret = snprintf(ib_dev->ibd_udev_path, SE_UDEV_PATH_LEN,
				"%s", ptr);
			printk(KERN_INFO "IBLOCK: Referencing UDEV path: %s\n",
					ib_dev->ibd_udev_path);
			ib_dev->ibd_flags |= IBDF_HAS_UDEV_PATH;
			params++;
			continue;
		}
		ptr2 = strstr(cur, "force");
		if ((ptr2)) {
			transport_check_dev_params_delim(ptr, &cur);
			ret = strict_strtoul(ptr, 0, &force);
			if (ret < 0) {
				printk(KERN_ERR "strict_strtoul() failed"
					" for force=\n");
				break;
			}
			ib_dev->ibd_force = (int)force;
			printk(KERN_INFO "IBLOCK: Set force=%d\n",
				ib_dev->ibd_force);
			params++;
		} else
			cur = NULL;
	}

out:
	kfree(buf);
	return (params) ? count : -EINVAL;
}

static ssize_t iblock_check_configfs_dev_params(
	struct se_hba *hba,
	struct se_subsystem_dev *se_dev)
{
	struct iblock_dev *ibd = (struct iblock_dev *) se_dev->se_dev_su_ptr;

	if (!(ibd->ibd_flags & IBDF_HAS_UDEV_PATH)) {
		printk(KERN_ERR "Missing udev_path= parameters for IBLOCK\n");
		return -1;
	}

	return 0;
}

static ssize_t iblock_show_configfs_dev_params(
	struct se_hba *hba,
	struct se_subsystem_dev *se_dev,
	char *page)
{
	struct iblock_dev *ibd = (struct iblock_dev *) se_dev->se_dev_su_ptr;
	int bl = 0;

	__iblock_get_dev_info(ibd, page, &bl);
	return (ssize_t)bl;
}

static struct se_device *iblock_create_virtdevice_from_fd(
	struct se_subsystem_dev *se_dev,
	const char *page)
{
	struct iblock_dev *ibd = (struct iblock_dev *) se_dev->se_dev_su_ptr;
	struct se_device *dev = NULL;
	struct file *filp;
	struct inode *inode;
	char *p = (char *)page;
	unsigned long long fd;
	int ret;

	ret = strict_strtoull(p, 0, (unsigned long long *)&fd);
	if (ret < 0) {
		printk(KERN_ERR "strict_strtol() failed for fd\n");
		return ERR_PTR(-EINVAL);
	}
	if ((fd < 3 || fd > 7)) {
		printk(KERN_ERR "IBLOCK: Illegal value of file descriptor:"
				" %llu\n", fd);
		return ERR_PTR(-EINVAL);
	}
	filp = fget(fd);
	if (!(filp)) {
		printk(KERN_ERR "IBLOCK: Unable to fget() fd: %llu\n", fd);
		return ERR_PTR(-EBADF);
	}
	inode = igrab(filp->f_mapping->host);
	if (!(inode)) {
		printk(KERN_ERR "IBLOCK: Unable to locate struct inode for"
			" struct block_device fd\n");
		fput(filp);
		return ERR_PTR(-EINVAL);
	}
	if (!(S_ISBLK(inode->i_mode))) {
		printk(KERN_ERR "IBLOCK: S_ISBLK(inode->i_mode) failed for file"
				" descriptor: %llu\n", fd);
		iput(inode);
		fput(filp);
		return ERR_PTR(-ENODEV);
	}
	ibd->ibd_bd = I_BDEV(filp->f_mapping->host);
	if (!(ibd->ibd_bd)) {
		printk(KERN_ERR "IBLOCK: Unable to locate struct block_device"
				" from I_BDEV()\n");
		iput(inode);
		fput(filp);
		return ERR_PTR(-EINVAL);
	}
	/*
	 * iblock_create_virtdevice() will call linux_blockdevice_claim()
	 * to claim struct block_device.
	 */
	dev = iblock_create_virtdevice(se_dev->se_dev_hba, se_dev, (void *)ibd);

	iput(inode);
	fput(filp);
	return dev;
}

static void iblock_get_plugin_info(void *p, char *b, int *bl)
{
	*bl += sprintf(b + *bl, "TCM iBlock Plugin %s\n", IBLOCK_VERSION);
}

static void iblock_get_hba_info(struct se_hba *hba, char *b, int *bl)
{
	struct iblock_hba *ib_host = (struct iblock_hba *)hba->hba_ptr;

	*bl += sprintf(b + *bl, "SE Host ID: %u  iBlock Host ID: %u\n",
		hba->hba_id, ib_host->iblock_host_id);
	*bl += sprintf(b + *bl, "        TCM iBlock HBA\n");
}

static void iblock_get_dev_info(struct se_device *dev, char *b, int *bl)
{
	struct iblock_dev *ibd = (struct iblock_dev *) dev->dev_ptr;

	__iblock_get_dev_info(ibd, b, bl);
}

static void __iblock_get_dev_info(struct iblock_dev *ibd, char *b, int *bl)
{
	char buf[BDEVNAME_SIZE];
	struct block_device *bd = ibd->ibd_bd;

	if (bd)
		*bl += sprintf(b + *bl, "iBlock device: %s",
				bdevname(bd, buf));
	if (ibd->ibd_flags & IBDF_HAS_UDEV_PATH) {
		*bl += sprintf(b + *bl, "  UDEV PATH: %s\n",
				ibd->ibd_udev_path);
	} else
		*bl += sprintf(b + *bl, "\n");

	*bl += sprintf(b + *bl, "        ");
	if (bd) {
		*bl += sprintf(b + *bl, "Major: %d Minor: %d  %s\n",
			ibd->ibd_major, ibd->ibd_minor, (!bd->bd_contains) ?
			"" : (bd->bd_holder == (struct iblock_dev *)ibd) ?
			"CLAIMED: IBLOCK" : "CLAIMED: OS");
	} else {
		*bl += sprintf(b + *bl, "Major: %d Minor: %d\n",
			ibd->ibd_major, ibd->ibd_minor);
	}
}

static void iblock_bio_destructor(struct bio *bio)
{
	struct se_task *task = (struct se_task *)bio->bi_private;
	struct iblock_dev *ib_dev = (struct iblock_dev *) task->se_dev->dev_ptr;

	bio_free(bio, ib_dev->ibd_bio_set);
}

static struct bio *iblock_get_bio(struct se_task *task,
	struct iblock_req *ib_req,
	struct iblock_dev *ib_dev,
	int *ret,
	u64 lba,
	u32 sg_num)
{
	struct bio *bio;

	bio = bio_alloc_bioset(GFP_NOIO, sg_num, ib_dev->ibd_bio_set);
	if (!(bio)) {
		printk(KERN_ERR "Unable to allocate memory for bio\n");
		*ret = PYX_TRANSPORT_OUT_OF_MEMORY_RESOURCES;
		return NULL;
	}

	DEBUG_IBLOCK("Allocated bio: %p task_sg_num: %u using ibd_bio_set:"
		" %p\n", bio, task->task_sg_num, ib_dev->ibd_bio_set);
	DEBUG_IBLOCK("Allocated bio: %p task_size: %u\n", bio, task->task_size);

	bio->bi_bdev = ib_dev->ibd_bd;
	bio->bi_private = (void *) task;
	bio->bi_destructor = iblock_bio_destructor;
	bio->bi_end_io = &iblock_bio_done;
	bio->bi_sector = lba;
	atomic_inc(&ib_req->ib_bio_cnt);

	DEBUG_IBLOCK("Set bio->bi_sector: %llu\n", bio->bi_sector);
	DEBUG_IBLOCK("Set ib_req->ib_bio_cnt: %d\n",
			atomic_read(&ib_req->ib_bio_cnt));
	return bio;
}

static int iblock_map_task_SG(struct se_task *task)
{
	struct iblock_dev *ib_dev = (struct iblock_dev *) task->se_dev->dev_ptr;
	struct iblock_req *ib_req = (struct iblock_req *) task->transport_req;
	struct bio *bio = NULL, *hbio = NULL, *tbio = NULL;
	struct scatterlist *sg = task->task_sg;
	int ret = 0;
	u32 i, sg_num = task->task_sg_num;
	u64 lba = task->task_lba;

	atomic_set(&ib_req->ib_bio_cnt, 0);

	bio = iblock_get_bio(task, ib_req, ib_dev, &ret,
			task->task_lba, sg_num);
	if (!(bio))
		return ret;

	ib_req->ib_bio = bio;
	hbio = tbio = bio;
	/*
	 * Use fs/bio.c:bio_add_pages() to setup the bio_vec maplist
	 * from TCM struct se_mem -> task->task_sg -> struct scatterlist memory.
	 */
	for (i = 0; i < task->task_sg_num; i++) {
		DEBUG_IBLOCK("task: %p bio: %p Calling bio_add_page(): page:"
			" %p len: %u offset: %u\n", task, bio, sg_page(&sg[i]),
				sg[i].length, sg[i].offset);
again:
		ret = bio_add_page(bio, sg_page(&sg[i]), sg[i].length,
				sg[i].offset);
		if (ret != sg[i].length) {

			DEBUG_IBLOCK("*** Set bio->bi_sector: %llu\n",
					bio->bi_sector);
			DEBUG_IBLOCK("** task->task_size: %u\n",
					task->task_size);
			DEBUG_IBLOCK("*** bio->bi_max_vecs: %u\n",
					bio->bi_max_vecs);
			DEBUG_IBLOCK("*** bio->bi_vcnt: %u\n",
					bio->bi_vcnt);

			bio = iblock_get_bio(task, ib_req, ib_dev, &ret,
					lba, sg_num);
			if (!(bio))
				goto fail;

			tbio = tbio->bi_next = bio;
			DEBUG_IBLOCK("-----------------> Added +1 bio: %p to"
				" list, Going to again\n", bio);
			goto again;
		}

		lba += sg[i].length >> IBLOCK_LBA_SHIFT;
		sg_num--;
		DEBUG_IBLOCK("task: %p bio-add_page() passed!, decremented"
			" sg_num to %u\n", task, sg_num);
		DEBUG_IBLOCK("task: %p bio_add_page() passed!, increased lba"
				" to %llu\n", task, lba);
		DEBUG_IBLOCK("task: %p bio_add_page() passed!, bio->bi_vcnt:"
				" %u\n", task, bio->bi_vcnt);
	}

	return task->task_sg_num;
fail:
	while (hbio) {
		bio = hbio;
		hbio = hbio->bi_next;
		bio->bi_next = NULL;
		bio_put(bio);
	}
	return ret;
}

static int iblock_CDB_inquiry(struct se_task *task, u32 size)
{
	return 0;
}

static int iblock_CDB_none(struct se_task *task, u32 size)
{
	return 0;
}

static int iblock_CDB_read_non_SG(struct se_task *task, u32 size)
{
	return 0;
}

static int iblock_CDB_read_SG(struct se_task *task, u32 size)
{
	return iblock_map_task_SG(task);
}

static int iblock_CDB_write_non_SG(struct se_task *task, u32 size)
{
	return 0;
}

static int iblock_CDB_write_SG(struct se_task *task, u32 size)
{
	return iblock_map_task_SG(task);
}

static int iblock_check_lba(unsigned long long lba, struct se_device *dev)
{
	return 0;
}

static int iblock_check_for_SG(struct se_task *task)
{
	return task->task_sg_num;
}

static unsigned char *iblock_get_cdb(struct se_task *task)
{
	struct iblock_req *req = (struct iblock_req *) task->transport_req;

	return req->ib_scsi_cdb;
}

static u32 iblock_get_blocksize(struct se_device *dev)
{
	struct iblock_dev *ibd = (struct iblock_dev *) dev->dev_ptr;

	return bdev_logical_block_size(ibd->ibd_bd);
}

static u32 iblock_get_device_rev(struct se_device *dev)
{
	return SCSI_SPC_2; /* Returns SPC-3 in Initiator Data */
}

static u32 iblock_get_device_type(struct se_device *dev)
{
	return TYPE_DISK;
}

static u32 iblock_get_dma_length(u32 task_size, struct se_device *dev)
{
	return PAGE_SIZE;
}

static u32 iblock_get_max_sectors(struct se_device *dev)
{
	struct iblock_dev *ibd = (struct iblock_dev *) dev->dev_ptr;
	struct request_queue *q = bdev_get_queue(ibd->ibd_bd);

	return q->limits.max_sectors;
}

static u32 iblock_get_queue_depth(struct se_device *dev)
{
	return IBLOCK_DEVICE_QUEUE_DEPTH;
}

static u32 iblock_get_max_queue_depth(struct se_device *dev)
{
	return IBLOCK_MAX_DEVICE_QUEUE_DEPTH;
}

static void iblock_bio_done(struct bio *bio, int err)
{
	struct se_task *task = (struct se_task *)bio->bi_private;
	struct iblock_req *ibr = (struct iblock_req *)task->transport_req;

	err = test_bit(BIO_UPTODATE, &bio->bi_flags) ? err : -EIO;
	if (err != 0) {
		printk(KERN_ERR "test_bit(BIO_UPTODATE) failed for bio: %p,"
			" err: %d\n", bio, err);
		transport_complete_task(task, 0);
		goto out;
	}
	DEBUG_IBLOCK("done[%p] bio: %p task_lba: %llu bio_lba: %llu err=%d\n",
		task, bio, task->task_lba, bio->bi_sector, err);
	/*
	 * bio_put() will call iblock_bio_destructor() to release the bio back
	 * to ibr->ib_bio_set.
	 */
	bio_put(bio);

	/*
	 * Wait to complete the task until the last bio as completed.
	 */
	if (!(atomic_dec_and_test(&ibr->ib_bio_cnt)))
		goto out;

	ibr->ib_bio = NULL;
	transport_complete_task(task, (!err));
out:
	return;
}

/*
 * We use the generic command sequencer, so we must setup
 * struct se_subsystem_spc.
 */
static struct se_subsystem_spc iblock_template_spc = {
	.inquiry		= iblock_CDB_inquiry,
	.none			= iblock_CDB_none,
	.read_non_SG		= iblock_CDB_read_non_SG,
	.read_SG		= iblock_CDB_read_SG,
	.write_non_SG		= iblock_CDB_write_non_SG,
	.write_SG		= iblock_CDB_write_SG,
};

static struct se_subsystem_api iblock_template = {
	.name			= "iblock",
	.type			= IBLOCK,
	.transport_type		= TRANSPORT_PLUGIN_VHBA_PDEV,
	.attach_hba		= iblock_attach_hba,
	.detach_hba		= iblock_detach_hba,
	.allocate_virtdevice	= iblock_allocate_virtdevice,
	.create_virtdevice	= iblock_create_virtdevice,
	.activate_device	= iblock_activate_device,
	.deactivate_device	= iblock_deactivate_device,
	.free_device		= iblock_free_device,
	.transport_complete	= iblock_transport_complete,
	.allocate_request	= iblock_allocate_request,
	.do_task		= iblock_do_task,
	.free_task		= iblock_free_task,
	.check_configfs_dev_params = iblock_check_configfs_dev_params,
	.set_configfs_dev_params = iblock_set_configfs_dev_params,
	.show_configfs_dev_params = iblock_show_configfs_dev_params,
	.create_virtdevice_from_fd = iblock_create_virtdevice_from_fd,
	.get_plugin_info	= iblock_get_plugin_info,
	.get_hba_info		= iblock_get_hba_info,
	.get_dev_info		= iblock_get_dev_info,
	.check_lba		= iblock_check_lba,
	.check_for_SG		= iblock_check_for_SG,
	.get_cdb		= iblock_get_cdb,
	.get_blocksize		= iblock_get_blocksize,
	.get_device_rev		= iblock_get_device_rev,
	.get_device_type	= iblock_get_device_type,
	.get_dma_length		= iblock_get_dma_length,
	.get_max_sectors	= iblock_get_max_sectors,
	.get_queue_depth	= iblock_get_queue_depth,
	.get_max_queue_depth	= iblock_get_max_queue_depth,
	.write_pending		= NULL,
	.spc			= &iblock_template_spc,
};

int __init iblock_module_init(void)
{
	int ret;

	INIT_LIST_HEAD(&iblock_template.sub_api_list);

	ret = transport_subsystem_register(&iblock_template);
	if (ret < 0)
		return ret;

	return 0;
}

void iblock_module_exit(void)
{
	transport_subsystem_release(&iblock_template);
}

MODULE_DESCRIPTION("TCM IBLOCK subsystem plugin");
MODULE_AUTHOR("nab@Linux-iSCSI.org");
MODULE_LICENSE("GPL");

module_init(iblock_module_init);
module_exit(iblock_module_exit);
