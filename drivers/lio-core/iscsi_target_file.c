/*********************************************************************************
 * Filename:  iscsi_target_file.c
 *
 * This file contains the iSCSI <-> FILEIO transport specific functions.
 *
 * Copyright (c) 2005 PyX Technologies, Inc.
 * Copyright (c) 2005-2006 SBE, Inc.  All Rights Reserved.
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


#define ISCSI_TARGET_FILE_C

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
#include <iscsi_target_file.h>
#include <iscsi_target_error.h>
 
extern iscsi_global_t *iscsi_global;
extern struct block_device *__linux_blockdevice_claim (int, int, void *, int *);
extern struct block_device *linux_blockdevice_claim(int, int, void *);
extern int linux_blockdevice_release(int, int, struct block_device *);
extern int linux_blockdevice_check(int, int);

/*	fd_attach_hba(): (Part of iscsi_transport_t template)
 *
 *
 */
extern int fd_attach_hba (
	iscsi_portal_group_t *tpg,
	iscsi_hba_t *hba,
	iscsi_hbainfo_t *hi)
{
	fd_host_t *fd_host;

	if (!(fd_host = kmalloc(sizeof(fd_host_t), GFP_KERNEL))) {
		TRACE_ERROR("Unable to allocate memory for fd_host_t\n");
		return(-1);
	}
	memset(fd_host, 0, sizeof(fd_host_t));

	fd_host->fd_host_id = hi->fd_host_id;
	
	atomic_set(&hba->left_queue_depth, FD_HBA_QUEUE_DEPTH);
	atomic_set(&hba->max_queue_depth, FD_HBA_QUEUE_DEPTH);
	hba->hba_ptr = (void *) fd_host;
	hba->hba_id = hi->hba_id;
	hba->transport = &fileio_template;

	PYXPRINT("iSCSI_HBA[%d] - %s FILEIO HBA Driver %s for iSCSI"
		" Target Core Stack %s\n", hba->hba_id, PYX_ISCSI_VENDOR, FD_VERSION, PYX_ISCSI_VERSION);
	
	PYXPRINT("iSCSI_HBA[%d] - Attached FILEIO HBA: %u to iSCSI Transport with"
		" TCQ Depth: %d MaxSectors: %u\n", hba->hba_id, fd_host->fd_host_id,
		atomic_read(&hba->max_queue_depth), FD_MAX_SECTORS);

	return(0);
}

/*	fd_detach_hba(): (Part of iscsi_transport_t template)
 *
 *
 */
extern int fd_detach_hba (iscsi_hba_t *hba)
{
	fd_host_t *fd_host;
	
	if (!hba->hba_ptr) {
		TRACE_ERROR("hba->hba_ptr is NULL!\n");
		return(-1);
	}
	fd_host = (fd_host_t *) hba->hba_ptr;

	PYXPRINT("iSCSI_HBA[%d] - Detached FILEIO HBA: %u from iSCSI Transport\n",
			hba->hba_id, fd_host->fd_host_id);

	kfree(fd_host);
	hba->hba_ptr = NULL;
	
	return(0);
}

extern int fd_claim_phydevice (iscsi_hba_t *hba, iscsi_device_t *dev)
{
	fd_dev_t *fd_dev = (fd_dev_t *)dev->dev_ptr;
	struct block_device *bd;

	if (!fd_dev->fd_claim_bd)
		return(0);
	
	if (dev->dev_flags & DF_READ_ONLY) {
		PYXPRINT("FILEIO: Using previously claimed %p Major:Minor - %d:%d\n",
		fd_dev->fd_bd, fd_dev->fd_major, fd_dev->fd_minor);
	} else {
		PYXPRINT("FILEIO: Claiming %p Major:Minor - %d:%d\n", fd_dev,
			fd_dev->fd_major, fd_dev->fd_minor);

		if (!(bd = linux_blockdevice_claim(fd_dev->fd_major, fd_dev->fd_minor,
				(void *)fd_dev)))
			return(-1);

		fd_dev->fd_bd = bd;
		fd_dev->fd_bd->bd_contains = bd;
	}

	return(0);
}

extern int fd_release_phydevice (iscsi_device_t *dev)
{
	fd_dev_t *fd_dev = (fd_dev_t *)dev->dev_ptr;

	if (!fd_dev->fd_claim_bd)
		return(0);

	if (!fd_dev->fd_bd)
		return(0);
	
	if (dev->dev_flags & DF_READ_ONLY) {
		PYXPRINT("FILEIO: Calling blkdev_put() for Major:Minor - %d:%d\n",
			fd_dev->fd_major, fd_dev->fd_minor);
		blkdev_put((struct block_device *)fd_dev->fd_bd);
	} else {	
		PYXPRINT("FILEIO: Releasing Major:Minor - %d:%d\n", fd_dev->fd_major,
			fd_dev->fd_minor);
		linux_blockdevice_release(fd_dev->fd_major, fd_dev->fd_minor,
			(struct block_device *)fd_dev->fd_bd);
	}
	
	fd_dev->fd_bd = NULL;
	
	return(0);
}

/*	fd_create_virtdevice(): (Part of iscsi_transport_t template)
 *
 *
 */
extern int fd_create_virtdevice (iscsi_hba_t *iscsi_hba, iscsi_devinfo_t *di)
{
	char *dev_p = NULL;
	iscsi_device_t *dev;
	fd_dev_t *fd_dev;
	fd_host_t *fd_host = (fd_host_t *) iscsi_hba->hba_ptr;
	mm_segment_t old_fs;
	struct block_device *bd = NULL;
	struct file *file;
	int flags, ret = 0;

	if (strlen(di->fd_dev_name) > FD_MAX_DEV_NAME) {
		TRACE_ERROR("di->fd_dev_name exceeds FD_MAX_DEV_NAME: %d\n",
				FD_MAX_DEV_NAME);
		return(0);
	}

	if (!(fd_dev = (fd_dev_t *) kmalloc(sizeof(fd_dev_t), GFP_KERNEL))) {
		TRACE_ERROR("Unable to allocate memory for fd_dev_t\n");
		return(0);
	}
	memset(fd_dev, 0, sizeof(fd_dev_t));

	fd_dev->fd_dev_id = di->fd_device_id;
	fd_dev->fd_host = fd_host;
	fd_dev->fd_dev_size = di->fd_device_size;
	fd_dev->fd_claim_bd = di->fd_claim_bd;
	sprintf(fd_dev->fd_dev_name, "%s", di->fd_dev_name);
	
	old_fs = get_fs();
	set_fs(get_ds());
	dev_p = getname(fd_dev->fd_dev_name);	
	set_fs(old_fs);

	if (IS_ERR(dev_p)) {
		TRACE_ERROR("getname(%s) failed: %lu\n", fd_dev->fd_dev_name,
				IS_ERR(dev_p));
		goto fail;
	}
	
	if (di->no_create_file)
		flags = O_RDWR | O_LARGEFILE;
	else
		flags = O_RDWR | O_CREAT | O_LARGEFILE;

//	flags |= O_DIRECT;
	
	file = filp_open(dev_p, flags, 0600);

	if (IS_ERR(file) || !file || !file->f_dentry) {
		TRACE_ERROR("filp_open(%s) failed\n", dev_p);
		goto fail;
	}

	fd_dev->fd_file = file;

	/*
	 * If we are claiming a blockend for this struct file, we extract fd_dev->fd_size
	 * from struct block_device.
	 *
	 * Otherwise, we use the passed fd_size= from target-ctl.
	 */
	if (fd_dev->fd_claim_bd) {
		fd_dev->fd_major = di->iblock_major;
		fd_dev->fd_minor = di->iblock_minor;
		
		if ((di->uu_id[0] != 0) && (di->uu_id[1] != 0) && (di->uu_id[2] != 0) &&
		    (di->uu_id[3] != 0)) {
			PYXPRINT("FILEIO: Referencing MD Universal Unit Identifier "
				"<%x %x %x %x>\n", di->uu_id[0], di->uu_id[1], di->uu_id[2],
					 di->uu_id[3]);
			fd_dev->fbd_uu_id[0] = di->uu_id[0];
			fd_dev->fbd_uu_id[1] = di->uu_id[1];
			fd_dev->fbd_uu_id[2] = di->uu_id[2];
			fd_dev->fbd_uu_id[3] = di->uu_id[3];
			fd_dev->fbd_flags |= FBDF_HAS_MD_UUID;
		} else if (strlen(di->lvm_uuid)) {
			snprintf(fd_dev->fbd_lvm_uuid, SE_LVM_UUID_LEN, "%s", di->lvm_uuid);
			PYXPRINT("FILEIO: Referencing LVM Universal Unit Identifier "
				"<%s>\n", fd_dev->fbd_lvm_uuid);
			fd_dev->fbd_flags |= FBDF_HAS_LVM_UUID;
		}	

		PYXPRINT("FILEIO: Claiming %p Major:Minor - %d:%d\n", fd_dev,
			fd_dev->fd_major, fd_dev->fd_minor);

		if ((bd = __linux_blockdevice_claim(fd_dev->fd_major, fd_dev->fd_minor,
				(void *)fd_dev, &ret)))
			if (ret == 1)
				di->dev_flags |= DF_CLAIMED_BLOCKDEV;
			else if (di->force) {
				di->dev_flags |= DF_READ_ONLY;	
				PYXPRINT("FILEIO: DF_READ_ONLY for Major:Minor - %d:%d\n",
					di->iblock_major, di->iblock_minor);
			} else {	
				TRACE_ERROR("WARNING: Unable to claim block device. Only use"
					" force=1 for READ-ONLY access.\n");
				goto fail;
			}
		else
			goto fail;

		fd_dev->fd_bd = bd;
		if (di->dev_flags & DF_CLAIMED_BLOCKDEV)
			fd_dev->fd_bd->bd_contains = bd;

		/*
		 * Determine the number of bytes for this FILEIO device from struct block_device.
		 */
		fd_dev->fd_dev_size = ((unsigned long long)bd->bd_disk->capacity * 512);
#if 0	
		TRACE_ERROR("FILEIO: Using fd_dev_size %llu from struct block_device\n",
				fd_dev->fd_dev_size);
#endif
	}

	di->dev_flags |= DF_DISABLE_STATUS_THREAD;
	
	if (!(dev = fd_add_device_to_list(iscsi_hba, fd_dev, di)))
		goto fail;

	fd_dev->fd_queue_depth = dev->queue_depth;
	
	PYXPRINT("iSCSI_FILE[%u] - Added LIO FILEIO Device ID: %u at %s,"
		" %llu total bytes\n", fd_host->fd_host_id, fd_dev->fd_dev_id,
			fd_dev->fd_dev_name, fd_dev->fd_dev_size);
	
	putname(dev_p);
	
	return(1);

fail:
	if (fd_dev->fd_file) {
		filp_close(fd_dev->fd_file, NULL);
		fd_dev->fd_file = NULL;
	}
	
	putname(dev_p);
	kfree(fd_dev);
	
	return(0);
}

/*	fd_add_device_to_list():
 *
 *
 */
extern iscsi_device_t *fd_add_device_to_list (iscsi_hba_t *iscsi_hba, void *fd_dev_p, iscsi_devinfo_t *di)
{
	iscsi_device_t *dev;
	fd_dev_t *fd_dev = (fd_dev_t *) fd_dev_p;
	
	if (!(dev = transport_add_device_to_iscsi_hba(iscsi_hba, &fileio_template,
				di->dev_flags, (void *)fd_dev)))
		return(NULL);

	return(dev);
}

/*	fd_activate_device(): (Part of iscsi_transport_t template)
 *
 *
 */
extern int fd_activate_device (iscsi_device_t *dev)
{
	fd_dev_t *fd_dev = (fd_dev_t *) dev->dev_ptr;
	fd_host_t *fd_host = fd_dev->fd_host;
	
	PYXPRINT("iSCSI_FILE[%u] - Activating Device with TCQ: %d at FILEIO"
		" Device ID: %d\n", fd_host->fd_host_id, fd_dev->fd_queue_depth,
		fd_dev->fd_dev_id);

	return(0);
}

/*	fd_deactivate_device(): (Part of iscsi_transport_t template)
 *
 *
 */
extern void fd_deactivate_device (iscsi_device_t *dev)
{
	fd_dev_t *fd_dev = (fd_dev_t *) dev->dev_ptr;
	fd_host_t *fd_host = fd_dev->fd_host;

	PYXPRINT("iSCSI_FILE[%u] - Deactivating Device with TCQ: %d at FILEIO"
		" Device ID: %d\n", fd_host->fd_host_id, fd_dev->fd_queue_depth,
		fd_dev->fd_dev_id);

	return;
}

/*	fd_check_device_location(): (Part of iscsi_transport_t template)
 *
 *
 */
extern int fd_check_device_location (iscsi_device_t *dev, iscsi_dev_transport_info_t *dti)
{
	fd_dev_t *fd_dev = (fd_dev_t *) dev->dev_ptr;

	if (dti->fd_device_id == fd_dev->fd_dev_id)
		return(0);

	return(-1);
}

extern int fd_check_ghost_id (iscsi_hbainfo_t *hi)
{
	int i;          
	iscsi_hba_t *hba;
	fd_host_t *fh;

	spin_lock(&iscsi_global->hba_lock);
	for (i = 0; i < ISCSI_MAX_GLOBAL_HBAS; i++) {
		hba = &iscsi_global->hba_list[i];

		if (!(hba->hba_status & HBA_STATUS_ACTIVE))
			continue;
		if (hba->type != FILEIO)
			continue;

		fh = (fd_host_t *) hba->hba_ptr;
		if (fh->fd_host_id == hi->fd_host_id) {
			TRACE_ERROR("FILEIO HBA with FD_HOST_ID: %u already"
				" assigned to iSCSI HBA: %hu, ignoring request\n",
				hi->fd_host_id, hba->hba_id);
			spin_unlock(&iscsi_global->hba_lock);
			return(-1);
		}
	}
	spin_unlock(&iscsi_global->hba_lock);
		
	return(0);
}

/*	fd_free_device(): (Part of iscsi_transport_t template)
 *
 *
 */
extern void fd_free_device (iscsi_device_t *dev)
{
	fd_dev_t *fd_dev = (fd_dev_t *) dev->dev_ptr;

	if (fd_dev->fd_file) {
		filp_close(fd_dev->fd_file, NULL);
		fd_dev->fd_file = NULL;
	}

	transport_generic_release_phydevice(dev, 0);
	kfree(fd_dev);

	return;
}

/*	fd_transport_complete(): (Part of iscsi_transport_t template)
 *
 *
 */
extern int fd_transport_complete (iscsi_task_t *task)
{
	return(0);
}

/*	fd_allocate_request(): (Part of iscsi_transport_t template)
 *
 *
 */
extern void *fd_allocate_request (
	iscsi_task_t *task,
	iscsi_device_t *dev)
{
	fd_request_t *fd_req;
	
	if (!(fd_req = (fd_request_t *) kmalloc(sizeof(fd_request_t), GFP_KERNEL))) {
		TRACE_ERROR("Unable to allocate fd_request_t\n");
		return(NULL);
	}
	memset(fd_req, 0, sizeof(fd_request_t));

	fd_req->fd_dev = (fd_dev_t *) dev->dev_ptr;

	return((void *)fd_req);
}

extern void fd_get_evpd_prod (unsigned char *buf, u32 size, iscsi_device_t *dev)
{
	snprintf(buf, size, "FILEIO");
	return;
}

extern void fd_get_evpd_sn (unsigned char *buf, u32 size, iscsi_device_t *dev)
{
	fd_dev_t *fdev = (fd_dev_t *) dev->dev_ptr;
	iscsi_hba_t *hba = dev->iscsi_hba;

	snprintf(buf, size, "%u_%u", hba->hba_id, fdev->fd_dev_id);	
	return;
}

/*	fd_emulate_inquiry():
 *
 *
 */
extern int fd_emulate_inquiry (iscsi_task_t *task)
{
	unsigned char prod[64], se_location[128];
	unsigned char *sub_sn = NULL;
	iscsi_cmd_t *cmd = task->iscsi_cmd;
	fd_dev_t *fdev = (fd_dev_t *) task->iscsi_dev->dev_ptr;
	iscsi_hba_t *hba = task->iscsi_dev->iscsi_hba;
	
	memset(prod, 0, 64);
	memset(se_location, 0, 128);
	
	sprintf(prod, "FILEIO");

	if (fdev->fbd_flags & FBDF_HAS_MD_UUID) {
		snprintf(se_location, 128, "%x%x%x%x", fdev->fbd_uu_id[0],
			fdev->fbd_uu_id[1], fdev->fbd_uu_id[2], fdev->fbd_uu_id[3]);
		sub_sn = &se_location[0];
	} else if (fdev->fbd_flags & FBDF_HAS_LVM_UUID) {
		snprintf(se_location, 128, "%s", fdev->fbd_lvm_uuid);
		sub_sn = &se_location[0];
	} else 
		sprintf(se_location, "%u_%u", hba->hba_id, fdev->fd_dev_id);
		
	return(transport_generic_emulate_inquiry(cmd, TYPE_DISK, prod, FD_VERSION,
		se_location, sub_sn));
}

/*	fd_emulate_read_cap():
 *
 *
 */
static int fd_emulate_read_cap (iscsi_task_t *task)
{
	fd_dev_t *fd_dev = (fd_dev_t *) task->iscsi_dev->dev_ptr;
	u32 blocks = (fd_dev->fd_dev_size / FD_BLOCKSIZE);
	
	if ((fd_dev->fd_dev_size / FD_BLOCKSIZE) >= 0x00000000ffffffff)
		blocks = 0xffffffff;
	
	return(transport_generic_emulate_readcapacity(task->iscsi_cmd, blocks, FD_BLOCKSIZE));
}

static int fd_emulate_read_cap16 (iscsi_task_t *task)
{
	fd_dev_t *fd_dev = (fd_dev_t *) task->iscsi_dev->dev_ptr;
	unsigned long long blocks_long = (fd_dev->fd_dev_size / FD_BLOCKSIZE);
	
	return(transport_generic_emulate_readcapacity_16(task->iscsi_cmd, blocks_long, FD_BLOCKSIZE));
}

/*	fd_emulate_scsi_cdb():
 *
 *
 */
static int fd_emulate_scsi_cdb (iscsi_task_t *task)
{
	int ret;
	iscsi_cmd_t *cmd = task->iscsi_cmd;
	fd_request_t *fd_req = (fd_request_t *) task->transport_req;

	switch (fd_req->fd_scsi_cdb[0]) {
	case INQUIRY:
		if (fd_emulate_inquiry(task) < 0)
			return(PYX_TRANSPORT_INVALID_CDB_FIELD);
		break;
	case READ_CAPACITY:
		if ((ret = fd_emulate_read_cap(task)) < 0)
			return(ret);
		break;
	case MODE_SENSE:
		if ((ret = transport_generic_emulate_modesense(task->iscsi_cmd,
				fd_req->fd_scsi_cdb, fd_req->fd_buf, 0, TYPE_DISK)) < 0)
			return(ret);
		break;
	case MODE_SENSE_10:
		if ((ret = transport_generic_emulate_modesense(task->iscsi_cmd,
				fd_req->fd_scsi_cdb, fd_req->fd_buf, 1, TYPE_DISK)) < 0)
			return(ret);
		break;
	case SERVICE_ACTION_IN:
		if ((T_TASK(cmd)->t_task_cdb[1] & 0x1f) != SAI_READ_CAPACITY_16) {
			TRACE_ERROR("Unsupported SA: 0x%02x\n", T_TASK(cmd)->t_task_cdb[1] & 0x1f);
			return(PYX_TRANSPORT_UNKNOWN_SAM_OPCODE);
		}
		if ((ret = fd_emulate_read_cap16(task)) < 0)
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
		TRACE_ERROR("Unsupported SCSI Opcode: 0x%02x for FILEIO\n",
				fd_req->fd_scsi_cdb[0]);
		return(PYX_TRANSPORT_UNKNOWN_SAM_OPCODE);
	}

	task->task_scsi_status = GOOD;
	transport_complete_task(task, 1);
	
	return(PYX_TRANSPORT_SENT_TO_TRANSPORT);
}

static inline int fd_iovec_alloc (fd_request_t *req)
{
	if (!(req->fd_iovs = kmalloc(sizeof(struct iovec) * req->fd_sg_count, GFP_KERNEL))) {
		TRACE_ERROR("Unable to allocate req->fd_iovs\n");
		return(-1);
	}
	memset(req->fd_iovs, 0, sizeof(struct iovec) * req->fd_sg_count);

	return(0);
}

static inline int fd_seek (struct file *fd, unsigned long long lba)
{
	mm_segment_t old_fs;
	unsigned long long offset;
	
	old_fs = get_fs();
	set_fs(get_ds());
	if (fd->f_op->llseek)
		offset = fd->f_op->llseek(fd, lba * FD_BLOCKSIZE, 0);
	else
		offset = default_llseek(fd, lba * FD_BLOCKSIZE, 0);
	set_fs(old_fs);
#if 0
	PYXPRINT("lba: %llu : FD_BLOCKSIZE: %d\n", lba, FD_BLOCKSIZE);
	PYXPRINT("offset from llseek: %llu\n", offset);
	PYXPRINT("(lba * FD_BLOCKSIZE): %llu\n", (lba * FD_BLOCKSIZE));
#endif	
	if (offset != (lba * FD_BLOCKSIZE)) {
		TRACE_ERROR("offset: %llu not equal to LBA: %llu\n",
			offset, (lba * FD_BLOCKSIZE));
		return(-1);
	}

	return(0);
}

static int fd_do_readv (fd_request_t *req, iscsi_task_t *task)
{
	int ret = 0;
	u32 i;
	mm_segment_t old_fs;
	struct file *fd = req->fd_dev->fd_file;
	struct scatterlist *sg = (struct scatterlist *) req->fd_buf;
	struct iovec iov[req->fd_sg_count];	

	memset(iov, 0, sizeof(struct iovec) + req->fd_sg_count);

	if (fd_seek(fd, req->fd_lba) < 0)
		return(-1);

	for (i = 0; i < req->fd_sg_count; i++) {
		iov[i].iov_len = sg[i].length;
		iov[i].iov_base = sg_virt(&sg[i]); 
	}

	old_fs = get_fs();
	set_fs(get_ds());
	ret = vfs_readv(fd, &iov[0], req->fd_sg_count, &fd->f_pos);
	set_fs(old_fs);

	if (ret < 0) {
		TRACE_ERROR("vfs_readv() returned %d\n", ret);
		return(-1);
	}

	return(1);
}

#if 0

static void fd_aio_intr (struct kiocb *kcb)
{
	iscsi_task_t *task = (iscsi_task_t *)kcb->private;

	printk("Got AIO_READ Response: task: %p\n", task);

	task->task_scsi_status = GOOD;
	transport_complete_task(task, 1);
	return;
}

static ssize_t fd_aio_retry (struct kiocb *kcb)
{
	TRACE_ERROR("fd_aio_retry() called for %p\n", kcb);
	return(0);
}

static int fd_do_aio_read (fd_request_t *req, iscsi_task_t *task)
{
	int ret = 0;
	u32 i, length = 0;
	unsigned long long offset, lba = req->fd_lba;;
	mm_segment_t old_fs;
	struct file *fd = req->fd_dev->fd_file;
	struct scatterlist *sg = (struct scatterlist *) req->fd_buf;
	struct iovec *iov;
	struct kiocb	*iocb;

	if (fd_iovec_alloc(req) < 0)
		return(-1);

       old_fs = get_fs();
	set_fs(get_ds());
         if (fd->f_op->llseek)
             offset = fd->f_op->llseek(fd, lba * FD_BLOCKSIZE, 0);
              else
         offset = default_llseek(fd, lba * FD_BLOCKSIZE, 0);
        set_fs(old_fs);

        PYXPRINT("lba: %llu : FD_BLOCKSIZE: %d\n", lba, FD_BLOCKSIZE);
        PYXPRINT("offset from llseek: %llu\n", offset);
        PYXPRINT("(lba * FD_BLOCKSIZE): %llu\n", (lba * FD_BLOCKSIZE));

       if (offset != (lba * FD_BLOCKSIZE)) {
                TRACE_ERROR("offset: %llu not equal to LBA: %llu\n",
                        offset, (lba * FD_BLOCKSIZE));
                return(-1);
        }


	TRACE_ERROR("req->fd_lba: %llu\n", req->fd_lba);
	
	for (i = 0; i < req->fd_sg_count; i++) {
		iov = &req->fd_iovs[i];
		TRACE_ERROR("sg->length: %d sg->page: %p\n", sg[i].length, sg[i].page);
		length += sg[i].length;
		iov->iov_len = sg[i].length;
		iov->iov_base = sg_virt(&sg[i]);
		TRACE_ERROR("iov_iov_len: %d iov_iov_base: %p\n", iov->iov_len, iov->iov_base);
	}
	
	init_sync_kiocb(&req->fd_iocb, fd);
	req->fd_iocb.ki_opcode = IOCB_CMD_PREAD;
	req->fd_iocb.ki_nbytes = length;
	req->fd_iocb.private = (void *) task;
	req->fd_iocb.ki_dtor = &fd_aio_intr;
	req->fd_iocb.ki_retry = &fd_aio_retry;
	
	PYXPRINT("Launching AIO_READ: %p iovecs: %p total length: %u\n",
		&req->fd_iocb, &req->fd_iovs[0], length);

	PYXPRINT("fd->f_pos: %d\n", fd->f_pos);
	PYXPRINT("req->fd_iocb.ki_pos: %d\n", req->fd_iocb.ki_pos);

	old_fs = get_fs();
	set_fs(get_ds());
	ret = __generic_file_aio_read(&req->fd_iocb, &req->fd_iovs[0], req->fd_sg_count, &fd->f_pos);
	set_fs(old_fs);

	PYXPRINT("__generic_file_aio_read() returned %d\n", ret);

	if (ret <= 0) 
		return(PYX_TRANSPORT_LOGICAL_UNIT_COMMUNICATION_FAILURE);
	
	if (ret != length) {
		TRACE_ERROR("ret [%d] != LENGTH [%d]\n", ret, length);
	}

	return(1);
}

extern void fd_sendfile_free_DMA (iscsi_cmd_t *cmd)
{
	TRACE_ERROR("Release reference to pages now..\n");
	return;
}

static int fd_sendactor (read_descriptor_t * desc, struct page *page, unsigned long offset, unsigned long size)
{
	unsigned long count = desc->count;
	iscsi_task_t *task = desc->arg.data;
	fd_request_t *req = (fd_request_t *) task->transport_req;	
	struct scatterlist *sg = (struct scatterlist *) req->fd_buf;

//	PYXPRINT("page: %p offset: %lu size: %lu\n", page, offset, size);

	__free_page(sg[req->fd_cur_offset].page);

//	TRACE_ERROR("page_address(page): %p\n", page_address(page));
	sg[req->fd_cur_offset].page = page;
	sg[req->fd_cur_offset].offset = offset;
	sg[req->fd_cur_offset].length = size;

//	PYXPRINT("sg[%d:%p].page %p length: %d\n", req->fd_cur_offset, &sg[req->fd_cur_offset],
//		sg[req->fd_cur_offset].page, sg[req->fd_cur_offset].length);

	req->fd_cur_size += size;
//	TRACE_ERROR("fd_cur_size: %u\n", req->fd_cur_size);
	
	req->fd_cur_offset++;

	desc->count--;
	desc->written += size;
	return(size);
}

static int fd_do_sendfile (fd_request_t *req, iscsi_task_t *task)
{
	int ret = 0;
	struct file *fd = req->fd_dev->fd_file;

	if (fd_seek(fd, req->fd_lba) < 0)
		return(-1);

	task->iscsi_cmd->transport_free_DMA = &fd_sendfile_free_DMA;
	
	ret = fd->f_op->sendfile(fd, &fd->f_pos, req->fd_sg_count, fd_sendactor, (void *)task);	

	if (ret < 0) {
		TRACE_ERROR("fd->f_op->sendfile() returned %d\n", ret);
		return(-1);
	}

	return(1);
}

#endif

static int fd_do_writev (fd_request_t *req, iscsi_task_t *task)
{
	int ret = 0;
	u32 i;
	struct file *fd = req->fd_dev->fd_file;
	struct scatterlist *sg = (struct scatterlist *) req->fd_buf;
	mm_segment_t old_fs;
	struct iovec iov[req->fd_sg_count];

	memset(iov, 0, sizeof(struct iovec) + req->fd_sg_count);
	
	if (fd_seek(fd, req->fd_lba) < 0)
		return(-1);
	
	for (i = 0; i < req->fd_sg_count; i++) {
		iov[i].iov_len = sg[i].length;
		iov[i].iov_base = sg_virt(&sg[i]);
	}

	old_fs = get_fs();
	set_fs(get_ds());
	ret = vfs_writev(fd, &iov[0], req->fd_sg_count, &fd->f_pos);
	set_fs(old_fs);

	if (ret < 0) {
		TRACE_ERROR("vfs_writev() returned %d\n", ret);
		return(-1);
	}

	return(1);
}

#if 0

static int fd_do_aio_write (fd_request_t *req, iscsi_task_t *task)
{
	int ret = 0;
	u32 i, length = 0;
	unsigned long long offset, lba = req->fd_lba;
	mm_segment_t old_fs;
	struct file *fd = req->fd_dev->fd_file;
	struct scatterlist *sg = (struct scatterlist *) req->fd_buf;
	struct iovec *iov;
	struct kiocb    *iocb;

	if (fd_iovec_alloc(req) < 0)
		return(-1);

	old_fs = get_fs();
	set_fs(get_ds());
	if (fd->f_op->llseek)
		offset = fd->f_op->llseek(fd, lba * FD_BLOCKSIZE, 0);
	else
		offset = default_llseek(fd, lba * FD_BLOCKSIZE, 0);
	set_fs(old_fs);

	PYXPRINT("lba: %llu : FD_BLOCKSIZE: %d\n", lba, FD_BLOCKSIZE);
	PYXPRINT("offset from llseek: %llu\n", offset);
	PYXPRINT("(lba * FD_BLOCKSIZE): %llu\n", (lba * FD_BLOCKSIZE));

	if (offset != (lba * FD_BLOCKSIZE)) {
		TRACE_ERROR("offset: %llu not equal to LBA: %llu\n",
			offset, (lba * FD_BLOCKSIZE));
		return(-1);
	}

	for (i = 0; i < req->fd_sg_count; i++) {
		iov = &req->fd_iovs[i];
		TRACE_ERROR("sg->length: %d sg->page: %p\n", sg[i].length, sg[i].page);

		length += sg[i].length;
		iov->iov_len = sg[i].length;
		iov->iov_base = sg_virt(&sg[i]);
		TRACE_ERROR("iov_iov_len: %d iov_iov_base: %p\n", iov->iov_len, iov->iov_base);
	}

	init_sync_kiocb(&req->fd_iocb, fd);
	req->fd_iocb.ki_opcode = IOCB_CMD_PWRITE;
	req->fd_iocb.ki_nbytes = length;
	req->fd_iocb.private = (void *) task;
	req->fd_iocb.ki_dtor = &fd_aio_intr;
	req->fd_iocb.ki_retry = &fd_aio_retry;

	PYXPRINT("Launching AIO_WRITE: %p iovecs: %p total length: %u\n",
		&req->fd_iocb, &req->fd_iovs[0], length);

	PYXPRINT("fd->f_pos: %d\n", fd->f_pos);
	PYXPRINT("req->fd_iocb.ki_pos: %d\n", req->fd_iocb.ki_pos);

	old_fs = get_fs();
	set_fs(get_ds());
	ret = generic_file_aio_write_nolock(&req->fd_iocb, &req->fd_iovs[0], req->fd_sg_count, &fd->f_pos);
	set_fs(old_fs);

	PYXPRINT("generic_file_aio_write_nolock() returned %d\n", ret);

	if (ret <= 0)
		return(PYX_TRANSPORT_LOGICAL_UNIT_COMMUNICATION_FAILURE);

	if (ret != length) {
		TRACE_ERROR("ret [%d] != WRITE LENGTH [%d]\n", ret, length);
	}

	return(1);
}

#endif

extern int fd_do_task (iscsi_task_t *task)
{
	int ret = 0;
	fd_request_t *req = (fd_request_t *) task->transport_req;

	if (!(task->iscsi_cmd->cmd_flags & ICF_SCSI_DATA_SG_IO_CDB))
		return(fd_emulate_scsi_cdb(task));

	req->fd_lba = task->task_lba;
	req->fd_size = task->task_size;

	if (req->fd_data_direction == FD_DATA_READ) {
//		ret = fd_do_aio_read(req, task);
//		ret = fd_do_sendfile(req, task);
		ret = fd_do_readv(req, task);
	} else {
//		ret = fd_do_aio_write(req, task);
		ret = fd_do_writev(req, task);
	}

	if (ret < 0)       
		return(ret);

	if (ret) {
		task->task_scsi_status = GOOD;   
		transport_complete_task(task, 1);
	}	

	return(PYX_TRANSPORT_SENT_TO_TRANSPORT);
}

/*	fd_free_task(): (Part of iscsi_transport_t template)
 *
 *
 */
extern void fd_free_task (iscsi_task_t *task)
{
	fd_request_t *req;

	req = (fd_request_t *) task->transport_req;
	kfree(req->fd_iovs);
	
	kfree(req);
	
	return;
}

extern int fd_check_hba_params (iscsi_hbainfo_t *hi, struct iscsi_target *t, int virt)
{
	if (!(t->hba_params_set & PARAM_HBA_FD_HOST_ID)) {
		TRACE_ERROR("fd_host_id must be set for"
			" addhbatotarget requests with FILEIO"
				" Interfaces\n");
		return(ERR_HBA_MISSING_PARAMS);
	}
	hi->fd_host_id = t->fd_host_id;

	return(0);
}

extern int fd_check_dev_params (iscsi_hba_t *hba, struct iscsi_target *t, iscsi_dev_transport_info_t *dti)
{
	if (!(t->hba_params_set & PARAM_HBA_FD_DEVICE_ID)) {
		TRACE_ERROR("Missing FILEIO createvirtdev parameters\n");
		return(ERR_VIRTDEV_MISSING_PARAMS);
	}
	dti->fd_device_id = t->fd_device_id;

	return(0);
}

extern int fd_check_virtdev_params (iscsi_devinfo_t *di, struct iscsi_target *t)
{
	/*
	 * Special case when we are using FILEIO with a block device that
	 * contains a valid major/minor, currently passed into the stack
	 * with iblock_major= and iblock_minor= target-ctl parameters.
	 *
	 * In this case, we will autodetect the fd_size in fd_create_virtdevice()
	 */
	if ((t->hba_params_set & PARAM_HBA_IBLOCK_MAJOR) &&
	    (t->hba_params_set & PARAM_HBA_IBLOCK_MINOR)) {
		if (!(t->hba_params_set & PARAM_HBA_FD_FILE) ||
		    !(t->hba_params_set & PARAM_HBA_FD_DEVICE_ID)) {
			TRACE_ERROR("Missing FILEIO createvirtdev parameters\n");
			return(ERR_VIRTDEV_MISSING_PARAMS);
		}

		di->fd_claim_bd = 1;
		di->iblock_major = t->iblock_major;
		di->iblock_minor = t->iblock_minor;
	} else {
		if (!(t->hba_params_set & PARAM_HBA_FD_FILE) ||
		    !(t->hba_params_set & PARAM_HBA_FD_SIZE) ||
		    !(t->hba_params_set & PARAM_HBA_FD_DEVICE_ID)) {
			TRACE_ERROR("Missing FILEIO createvirtdev parameters\n");
			return(ERR_VIRTDEV_MISSING_PARAMS);
		}
	}

	if (!(strlen(t->value))) {
		TRACE_ERROR("fd_file= does not contain a valid path/filename!\n");
		return(ERR_VIRTDEV_MISSING_PARAMS);
	}

	di->fd_device_id = t->fd_device_id;
	di->fd_device_size = t->fd_dev_size;
	snprintf(di->fd_dev_name, FD_MAX_DEV_NAME, "%s", t->value);

	return(0);
}

extern void fd_get_plugin_info (void *p, char *b, int *bl)
{
	*bl += sprintf(b+*bl, "%s FILEIO Plugin %s\n", PYX_ISCSI_VENDOR, FD_VERSION);
	
	return;
}

extern void fd_get_hba_info (iscsi_hba_t *hba, char *b, int *bl)
{
	*bl += sprintf(b+*bl, "iSCSI Host ID: %u  FD Host ID: %u\n",
		 hba->hba_id, hba->hba_info.fd_host_id);
	*bl += sprintf(b+*bl, "        LIO FILEIO HBA\n");

	return;
}

extern void fd_get_dev_info (iscsi_device_t *dev, char *b, int *bl)
{
	fd_dev_t *fd = (fd_dev_t *) dev->dev_ptr;

	*bl += sprintf(b+*bl, "LIO FILEIO ID: %u", fd->fd_dev_id);
	if (fd->fbd_flags & FBDF_HAS_MD_UUID) {
		*bl += sprintf(b+*bl, "  MD UUID: %x:%x:%x:%x\n",
			fd->fbd_uu_id[0], fd->fbd_uu_id[1],
			fd->fbd_uu_id[2], fd->fbd_uu_id[3]);
	} else if (fd->fbd_flags & FBDF_HAS_LVM_UUID)
		*bl += sprintf(b+*bl, "  LVM UUID: %s\n", fd->fbd_lvm_uuid);
	else
		*bl += sprintf(b+*bl, "  FILEIO Makeup: %s\n", TRANSPORT(dev)->name);

	if (fd->fd_bd) {
		struct block_device *bd = fd->fd_bd;
		
		*bl += sprintf(b+*bl, "        File: %s  Size: %llu  %s\n",
				fd->fd_dev_name, fd->fd_dev_size,
				(!bd->bd_contains) ? "" :
				(bd->bd_holder == (fd_dev_t *)fd) ?
					"CLAIMED: FILEIO" : "CLAIMED: OS");
	}

	return;
}

/*	fd_map_task_non_SG():
 *
 *
 */
extern void fd_map_task_non_SG (iscsi_task_t *task)
{
	iscsi_cmd_t *cmd = task->iscsi_cmd;
	fd_request_t *req = (fd_request_t *) task->transport_req;

	req->fd_bufflen		= task->task_size;
	req->fd_buf		= (void *) T_TASK(cmd)->t_task_buf;
	req->fd_sg_count	= 0;
	
	return;
}

/*	fd_map_task_SG():
 *
 *
 */
extern void fd_map_task_SG (iscsi_task_t *task)
{
	fd_request_t *req = (fd_request_t *) task->transport_req;

	req->fd_bufflen		= task->task_size;
	req->fd_buf		= (void *)task->task_buf;
	req->fd_sg_count	= task->task_sg_num;

	return;
}

/*      fd_CDB_inquiry():
 *
 *
 */
extern int fd_CDB_inquiry (iscsi_task_t *task, u32 size)
{      
	fd_request_t *req = (fd_request_t *) task->transport_req;
		        
	req->fd_data_direction  = FD_DATA_READ;
			        
	/*
	 * This causes 255 instead of the requested 256 bytes
	 * to be returned.  This can be safely ignored for now,
	 * and take the Initiators word on INQUIRY data lengths.
	 */
#if 0
	cmd->data_length	= req->fd_bufflen;
#endif
	fd_map_task_non_SG(task);

	return(0);
}

/*      fd_CDB_none():
 *
 *
 */
extern int fd_CDB_none (iscsi_task_t *task, u32 size)
{
	fd_request_t *req = (fd_request_t *) task->transport_req;

	req->fd_data_direction	= FD_DATA_NONE;
	req->fd_bufflen		= 0;
	req->fd_sg_count	= 0;
	req->fd_buf		= NULL;

	return(0);
}

/*	fd_CDB_read_non_SG():
 *
 *
 */
extern int fd_CDB_read_non_SG (iscsi_task_t *task, u32 size)
{
	fd_request_t *req = (fd_request_t *) task->transport_req;

	req->fd_data_direction = FD_DATA_READ;
	fd_map_task_non_SG(task);

	return(0);
}

/*	fd_CDB_read_SG):
 *
 *
 */
extern int fd_CDB_read_SG (iscsi_task_t *task, u32 size)
{
	fd_request_t *req = (fd_request_t *) task->transport_req;

	req->fd_data_direction = FD_DATA_READ;
	fd_map_task_SG(task);

	return(req->fd_sg_count);
}

/*	fd_CDB_write_non_SG():
 *
 *
 */
extern int fd_CDB_write_non_SG (iscsi_task_t *task, u32 size)
{
	fd_request_t *req = (fd_request_t *) task->transport_req;
	
	req->fd_data_direction = FD_DATA_WRITE;
	fd_map_task_non_SG(task);
	
	return(0);
}

/*	fd_CDB_write_SG():
 *
 *
 */
extern int fd_CDB_write_SG (iscsi_task_t *task, u32 size)
{
	fd_request_t *req = (fd_request_t *) task->transport_req;

	req->fd_data_direction = FD_DATA_WRITE;
	fd_map_task_SG(task);

	return(req->fd_sg_count);
}

/*	fd_check_lba():
 *
 *
 */
extern int fd_check_lba (unsigned long long lba, iscsi_device_t *dev)
{
	return(0);
}

/*	fd_check_for_SG(): (Part of iscsi_transport_t template)
 *
 *
 */
extern int fd_check_for_SG (iscsi_task_t *task)
{
	fd_request_t *req = (fd_request_t *) task->transport_req;
	
	return(req->fd_sg_count);
}

/*	fd_get_cdb(): (Part of iscsi_transport_t template)
 *
 *
 */
extern unsigned char *fd_get_cdb (iscsi_task_t *task)
{
	fd_request_t *req = (fd_request_t *) task->transport_req;

	return(req->fd_scsi_cdb);
}

/*	fd_get_blocksize(): (Part of iscsi_transport_t template)
 *
 *
 */
extern u32 fd_get_blocksize (iscsi_device_t *dev)
{
	return(FD_BLOCKSIZE);
}

/*	fd_get_device_rev(): (Part of iscsi_transport_t template)
 *
 *
 */
extern u32 fd_get_device_rev (iscsi_device_t *dev)
{
	return(02); 
}

/*	fd_get_device_type(): (Part of iscsi_transport_t template)
 *
 *
 */
extern u32 fd_get_device_type (iscsi_device_t *dev)
{
	return(0); /* TYPE_DISK */
}

/*	fd_get_dma_length(): (Part of iscsi_transport_t template)
 *
 *
 */
extern u32 fd_get_dma_length (u32 task_size, iscsi_device_t *dev)
{
	return(PAGE_SIZE);
}

/*	fd_get_max_sectors(): (Part of iscsi_transport_t template)
 *
 *
 */
extern u32 fd_get_max_sectors (iscsi_device_t *dev)
{
	return(FD_MAX_SECTORS);
}

/*	fd_get_queue_depth(): (Part of iscsi_transport_t template)
 *
 *
 */
extern u32 fd_get_queue_depth (iscsi_device_t *dev)
{
	return(FD_DEVICE_QUEUE_DEPTH);
}

/*	fd_get_non_SG(): (Part of iscsi_transport_t template)
 *
 *
 */
extern unsigned char *fd_get_non_SG (iscsi_task_t *task)
{
	fd_request_t *req = (fd_request_t *) task->transport_req;

	return((unsigned char *)req->fd_buf);
}

/*	fd_get_SG(): (Part of iscsi_transport_t template)
 *
 *
 */
extern struct scatterlist *fd_get_SG (iscsi_task_t *task)
{
	fd_request_t *req = (fd_request_t *) task->transport_req;

	return((struct scatterlist *)req->fd_buf);
}

/*	fd_get_SG_count(): (Part of iscsi_transport_t template)
 *
 *
 */
extern u32 fd_get_SG_count (iscsi_task_t *task)
{
	return(0);
}

/*	fd_set_non_SG_buf():
 *
 *
 */
extern int fd_set_non_SG_buf (unsigned char *buf, iscsi_task_t *task)
{
	fd_request_t *req = (fd_request_t *) task->transport_req;
	
	req->fd_buf		= (void *) buf;
	req->fd_bufflen         = task->task_size;
	req->fd_sg_count        = 0;

	return(0);
}
