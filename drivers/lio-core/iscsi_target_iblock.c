/*********************************************************************************
 * Filename:  iscsi_target_iblock.c
 *
 * This file contains the iSCSI <-> Linux BlockIO transport specific functions.
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
#include <iscsi_target_iblock.h>
#include <iscsi_target_error.h>

extern iscsi_global_t *iscsi_global;
extern struct block_device *__linux_blockdevice_claim (int, int, void *, int *); 
extern struct block_device *linux_blockdevice_claim(int, int, void *);

extern int linux_blockdevice_release(int, int, struct block_device *);

#if 0
#define DEBUG_IBLOCK(x...) PYXPRINT(x)
#else
#define DEBUG_IBLOCK(x...)
#endif

/*	iblock_attach_hba(): (Part of se_subsystem_api_t template)
 *
 *
 */
extern int iblock_attach_hba (
	iscsi_portal_group_t *tpg,
	se_hba_t *hba,
	iscsi_hbainfo_t *hi)
{
	iblock_hba_t *ib_host;

	if (!(ib_host = kmalloc(sizeof(iblock_hba_t), GFP_KERNEL))) {
		TRACE_ERROR("Unable to allocate memory for iblock_hba_t\n");
		return(-1);
	}
	memset(ib_host, 0, sizeof(iblock_hba_t));

	ib_host->iblock_host_id = hi->iblock_host_id;

	atomic_set(&hba->left_queue_depth, IBLOCK_HBA_QUEUE_DEPTH);
	atomic_set(&hba->max_queue_depth, IBLOCK_HBA_QUEUE_DEPTH);
	hba->hba_ptr = (void *) ib_host;
	hba->hba_id = hi->hba_id;
	hba->transport = &iblock_template;

	PYXPRINT("iSCSI_HBA[%d] - %s iBlock HBA Driver %s for iSCSI"
		" Target Core Stack %s\n", hba->hba_id, PYX_ISCSI_VENDOR,
			IBLOCK_VERSION, PYX_ISCSI_VERSION);

	PYXPRINT("iSCSI_HBA[%d] - Attached iBlock HBA: %u to iSCSI Transport with"
		" TCQ Depth: %d\n", hba->hba_id, ib_host->iblock_host_id,
		atomic_read(&hba->max_queue_depth));

	return(0);
}

/*	iblock_detach_hba(): (Part of se_subsystem_api_t template)
 *
 *
 */
extern int iblock_detach_hba (se_hba_t *hba)
{
	iblock_hba_t *ib_host;

	if (!hba->hba_ptr) {
		TRACE_ERROR("hba->hba_ptr is NULL!\n");
		return(-1);
	}
	ib_host = (iblock_hba_t *) hba->hba_ptr;

	PYXPRINT("iSCSI_HBA[%d] - Detached iBlock HBA: %u from iSCSI Transport\n",
			hba->hba_id, ib_host->iblock_host_id);

	kfree(ib_host);
	hba->hba_ptr = NULL;

	return(0);
}

extern int iblock_claim_phydevice (se_hba_t *hba, se_device_t *dev)
{
	iblock_dev_t *ib_dev = (iblock_dev_t *)dev->dev_ptr;
	struct block_device *bd;
	
	if (dev->dev_flags & DF_READ_ONLY) {
		PYXPRINT("IBLOCK: Using previously claimed %p Major:Minor - %d:%d\n",
			ib_dev->ibd_bd, ib_dev->ibd_major, ib_dev->ibd_minor);
	} else {
		PYXPRINT("IBLOCK: Claiming %p Major:Minor - %d:%d\n",
			ib_dev, ib_dev->ibd_major, ib_dev->ibd_minor);

		if (!(bd = linux_blockdevice_claim(ib_dev->ibd_major, ib_dev->ibd_minor,
				(void *)ib_dev)))
			return(-1);
	
		ib_dev->ibd_bd = bd;
		ib_dev->ibd_bd->bd_contains = bd;
	}
	
	return(0);
}

extern int iblock_release_phydevice (se_device_t *dev)
{
	iblock_dev_t *ib_dev = (iblock_dev_t *)dev->dev_ptr;
	
	if (!ib_dev->ibd_bd)
		return(0);

	if (dev->dev_flags & DF_READ_ONLY) {
		PYXPRINT("IBLOCK: Calling blkdev_put() for Major:Minor - %d:%d\n",
			ib_dev->ibd_major, ib_dev->ibd_minor);
		blkdev_put((struct block_device *)ib_dev->ibd_bd);
	} else {
		PYXPRINT("IBLOCK: Releasing Major:Minor - %d:%d\n",
			ib_dev->ibd_major, ib_dev->ibd_minor);
		linux_blockdevice_release(ib_dev->ibd_major, ib_dev->ibd_minor,
			(struct block_device *)ib_dev->ibd_bd);
	}

	ib_dev->ibd_bd = NULL;
	
	return(0);
}

extern int iblock_create_virtdevice (se_hba_t *iscsi_hba, iscsi_devinfo_t *di)
{
	iblock_dev_t *ib_dev = NULL;
	iblock_hba_t *ib_host = (iblock_hba_t *) iscsi_hba->hba_ptr;
	se_device_t *iscsi_dev;
	struct block_device *bd = NULL;
	u32 dev_flags = 0;
	int ret = 0;

	if (!(ib_dev = kmalloc(sizeof(iblock_dev_t), GFP_KERNEL))) {
		TRACE_ERROR("Unable to allocate iblock_dev_t\n");
		return(0);
	}
	memset(ib_dev, 0, sizeof(iblock_dev_t));

	if ((di->uu_id[0] != 0) && (di->uu_id[1] != 0) && (di->uu_id[2] != 0) &&
	    (di->uu_id[3] != 0)) {
		PYXPRINT("IBLOCK: Referencing MD Universal Unit Identifier "
			"<%x %x %x %x>\n", di->uu_id[0], di->uu_id[1], di->uu_id[2],
                               di->uu_id[3]);
		ib_dev->ibd_uu_id[0] = di->uu_id[0];
		ib_dev->ibd_uu_id[1] = di->uu_id[1];
		ib_dev->ibd_uu_id[2] = di->uu_id[2];
		ib_dev->ibd_uu_id[3] = di->uu_id[3];
		ib_dev->ibd_flags |= IBDF_HAS_MD_UUID;
	} else if (strlen(di->lvm_uuid)) {
		snprintf(ib_dev->ibd_lvm_uuid, SE_LVM_UUID_LEN, "%s", di->lvm_uuid);
		PYXPRINT("IBLOCK: Referencing LVM Universal Unit Identifier "
			"<%s>\n", ib_dev->ibd_lvm_uuid);
		ib_dev->ibd_flags |= IBDF_HAS_LVM_UUID;
	}
	
	PYXPRINT("IBLOCK: Claiming %p Major:Minor - %d:%d\n", ib_dev,
                di->iblock_major, di->iblock_minor);

	if ((bd = __linux_blockdevice_claim(di->iblock_major, di->iblock_minor, ib_dev, &ret)))
		if (ret == 1)
			dev_flags = DF_CLAIMED_BLOCKDEV;
		else if (di->force) {
			dev_flags = DF_READ_ONLY;
			PYXPRINT("IBLOCK: DF_READ_ONLY for Major:Minor - %d:%d\n",
				di->iblock_major, di->iblock_minor);
		} else {
			TRACE_ERROR("WARNING: Unable to claim block device. Only use"
				" force=1 for READ-ONLY access.\n");
			goto failed;
		}
	else
		goto failed;	
	
	ib_dev->ibd_host = ib_host;
	ib_dev->ibd_bd = bd;
	if (dev_flags & DF_CLAIMED_BLOCKDEV)
		ib_dev->ibd_bd->bd_contains = bd;

	ib_dev->ibd_major = di->iblock_major;
	ib_dev->ibd_minor = di->iblock_minor;

	if (!(ib_dev->ibd_bio_set = bioset_create(32, 64))) {
		TRACE_ERROR("Unable to create bioset for IBLOCK\n");
		dump_stack();
		goto failed;
	}
	printk("IBLOCK: Created bio_set() for major/minor: %d:%d\n",
		ib_dev->ibd_major, ib_dev->ibd_minor);
	/*
	 * Pass dev_flags for linux_blockdevice_claim() above..
	 */
	if (!(iscsi_dev = transport_add_device_to_iscsi_hba(iscsi_hba,
			&iblock_template, dev_flags, (void *)ib_dev)))
		goto failed;

	ib_dev->ibd_depth = iscsi_dev->queue_depth;

	return(1);

failed:
	if (ib_dev->ibd_bio_set)
		bioset_free(ib_dev->ibd_bio_set);
	kfree(ib_dev);
	return(0);
}

/*	iblock_activate_device(): (Part of se_subsystem_api_t template)
 *
 *
 */
extern int iblock_activate_device (se_device_t *dev)
{
	iblock_dev_t *ib_dev = (iblock_dev_t *) dev->dev_ptr;
	iblock_hba_t *ib_hba = ib_dev->ibd_host;

	PYXPRINT("iSCSI_iBLOCK[%u] - Activating Device with TCQ: %d at Major:"
		" %d Minor %d\n", ib_hba->iblock_host_id, ib_dev->ibd_depth,
			ib_dev->ibd_major, ib_dev->ibd_minor);

	return(0);
}

/*	iblock_deactivate_device(): (Part of se_subsystem_api_t template)
 *
 *
 */
extern void iblock_deactivate_device (se_device_t *dev)
{
	iblock_dev_t *ib_dev = (iblock_dev_t *) dev->dev_ptr;
	iblock_hba_t *ib_hba = ib_dev->ibd_host;

	PYXPRINT("iSCSI_iBLOCK[%u] - Deactivating Device with TCQ: %d at Major:"
		" %d Minor %d\n", ib_hba->iblock_host_id, ib_dev->ibd_depth,
			ib_dev->ibd_major, ib_dev->ibd_minor);

	return;
}

extern int iblock_check_device_location (se_device_t *dev, iscsi_dev_transport_info_t *dti)
{
	iblock_dev_t *ib_dev = (iblock_dev_t *) dev->dev_ptr;

	if ((dti->iblock_major == ib_dev->ibd_major) &&
	    (dti->iblock_minor == ib_dev->ibd_minor))
		return(0);

	return(-1);
}

extern int iblock_check_ghost_id (iscsi_hbainfo_t *hi)
{
	int i;
	se_hba_t *hba;
	iblock_hba_t *ib_hba;

	spin_lock(&iscsi_global->hba_lock);
	for (i = 0; i < ISCSI_MAX_GLOBAL_HBAS; i++) {
		 hba = &iscsi_global->hba_list[i];

		 if (!(hba->hba_status & HBA_STATUS_ACTIVE))
			 continue;
		 if (hba->type != IBLOCK)
			 continue;

		 ib_hba = (iblock_hba_t *) hba->hba_ptr;
		 if (ib_hba->iblock_host_id == hi->iblock_host_id) {
			 TRACE_ERROR("iBlock HBA with iblock_hba_id: %u already"
				" assigned to iSCSI HBA: %hu, ignoring request\n",
				hi->iblock_host_id, hba->hba_id);
			 spin_unlock(&iscsi_global->hba_lock);
			 return(-1);
		}
	}
	spin_unlock(&iscsi_global->hba_lock);

	return(0);
}

extern void iblock_free_device (se_device_t *dev)
{
	iblock_dev_t *ib_dev = (iblock_dev_t *) dev->dev_ptr;

	if (ib_dev->ibd_bio_set) {
		DEBUG_IBLOCK("Calling bioset_free ib_dev->ibd_bio_set: %p\n",
				ib_dev->ibd_bio_set);
		bioset_free(ib_dev->ibd_bio_set);
	}

	transport_generic_release_phydevice(dev, 0);
	kfree(ib_dev);

	return;
}

extern int iblock_transport_complete (se_task_t *task)
{
	return(0);
}

/*	iblock_allocate_request(): (Part of se_subsystem_api_t template)
 *
 *
 */
extern void *iblock_allocate_request (
	se_task_t *task,
        se_device_t *dev)
{
	iblock_req_t *ib_req;

	if (!(ib_req = (iblock_req_t *) kmalloc(sizeof(iblock_req_t), GFP_KERNEL))) {
		TRACE_ERROR("Unable to allocate memory for iblock_req_t\n");
		return(NULL);
	}
	memset(ib_req, 0, sizeof(iblock_req_t));

	ib_req->ib_dev = (iblock_dev_t *) dev->dev_ptr;
	return((void *)ib_req);
}

extern void iblock_get_evpd_prod (unsigned char *buf, u32 size, se_device_t *dev)
{
	snprintf(buf, size, "IBLOCK");
	return;
}

extern void iblock_get_evpd_sn (unsigned char *buf, u32 size, se_device_t *dev)
{
	iblock_dev_t *ibd = (iblock_dev_t *) dev->dev_ptr;
	
	snprintf(buf, size, "%u_%u", ibd->ibd_major, ibd->ibd_minor);
	return;
}

static int iblock_emulate_inquiry (se_task_t *task)
{
	unsigned char prod[64], se_location[128];
	iscsi_cmd_t *cmd = task->iscsi_cmd;
	iblock_dev_t *ibd = (iblock_dev_t *) task->iscsi_dev->dev_ptr;
	se_hba_t *hba = task->iscsi_dev->iscsi_hba;
	unsigned char *sub_sn = NULL;

	memset(prod, 0, 64);
	memset(se_location, 0, 128);

	sprintf(prod, "IBLOCK");

	if (ibd->ibd_flags & IBDF_HAS_MD_UUID) {
		snprintf(se_location, 128, "%x%x%x%x", ibd->ibd_uu_id[0],
			ibd->ibd_uu_id[1], ibd->ibd_uu_id[2], ibd->ibd_uu_id[3]);
		sub_sn = &se_location[0];
	} else if (ibd->ibd_flags & IBDF_HAS_LVM_UUID) {
		snprintf(se_location, 128, "%s", ibd->ibd_lvm_uuid);
		sub_sn = &se_location[0];
	} else
		sprintf(se_location, "%u_%u_%u", hba->hba_id, ibd->ibd_major, ibd->ibd_minor);

	return(transport_generic_emulate_inquiry(cmd, TYPE_DISK, prod, IBLOCK_VERSION,
	       se_location, sub_sn));
}

static int iblock_emulate_read_cap (se_task_t *task)
{
	iblock_dev_t *ibd = (iblock_dev_t *) task->iscsi_dev->dev_ptr;
	struct block_device *bd = ibd->ibd_bd;
	u32 blocks = (bd->bd_disk->capacity - 1);

	if ((bd->bd_disk->capacity - 1) >= 0x00000000ffffffff)
		blocks = 0xffffffff;

	return(transport_generic_emulate_readcapacity(task->iscsi_cmd, blocks, IBLOCK_BLOCKSIZE));
}

static int iblock_emulate_read_cap16 (se_task_t *task)
{
	iblock_dev_t *ibd = (iblock_dev_t *) task->iscsi_dev->dev_ptr;
	struct block_device *bd = ibd->ibd_bd;
	unsigned long long blocks_long = (bd->bd_disk->capacity - 1);

	return(transport_generic_emulate_readcapacity_16(task->iscsi_cmd, blocks_long, IBLOCK_BLOCKSIZE));;
}

static int iblock_emulate_scsi_cdb (se_task_t *task)
{
	int ret;
	iscsi_cmd_t *cmd = task->iscsi_cmd;

	switch (T_TASK(cmd)->t_task_cdb[0]) {
	case INQUIRY:
		if (iblock_emulate_inquiry(task) < 0)
			return(PYX_TRANSPORT_INVALID_CDB_FIELD);
		break;
	case READ_CAPACITY:
		if ((ret = iblock_emulate_read_cap(task)) < 0)
			return(ret);
		break;	
	case MODE_SENSE:
		if ((ret = transport_generic_emulate_modesense(task->iscsi_cmd,
				T_TASK(cmd)->t_task_cdb, T_TASK(cmd)->t_task_buf, 0, TYPE_DISK)) < 0)
			return(ret);
		break;
	case MODE_SENSE_10:
		if ((ret = transport_generic_emulate_modesense(task->iscsi_cmd,
				T_TASK(cmd)->t_task_cdb, T_TASK(cmd)->t_task_buf, 1, TYPE_DISK)) < 0)
			return(ret);
		break;
	case SERVICE_ACTION_IN:
		if ((T_TASK(cmd)->t_task_cdb[1] & 0x1f) != SAI_READ_CAPACITY_16) {
			TRACE_ERROR("Unsupported SA: 0x%02x\n", T_TASK(cmd)->t_task_cdb[1] & 0x1f);
			return(PYX_TRANSPORT_UNKNOWN_SAM_OPCODE);
		}
		if ((ret = iblock_emulate_read_cap16(task)) < 0)
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
		TRACE_ERROR("Unsupported SCSI Opcode: 0x%02x for iBlock\n",
				T_TASK(cmd)->t_task_cdb[0]);
		return(PYX_TRANSPORT_UNKNOWN_SAM_OPCODE);
	}

	task->task_scsi_status = GOOD;
	transport_complete_task(task, 1);

	return(PYX_TRANSPORT_SENT_TO_TRANSPORT);
}

extern int iblock_do_task (se_task_t *task)
{
	iblock_req_t *req = (iblock_req_t *)task->transport_req;
	iblock_dev_t *ibd = (iblock_dev_t *)req->ib_dev;
	request_queue_t *q = bdev_get_queue(ibd->ibd_bd);
	struct bio *bio = req->ib_bio, *nbio = NULL;

	if (!(task->iscsi_cmd->cmd_flags & ICF_SCSI_DATA_SG_IO_CDB))
		return(iblock_emulate_scsi_cdb(task));

	while (bio) {
		nbio = bio->bi_next;
		bio->bi_next = NULL;
		DEBUG_IBLOCK("Calling submit_bio() task: %p bio: %p bio->bi_sector:"
				" %llu\n", task, bio, bio->bi_sector);
		submit_bio((task->iscsi_cmd->data_direction == ISCSI_WRITE), bio);
		bio = nbio;
	}

	if (q->unplug_fn)
		q->unplug_fn(q);
	
	return(PYX_TRANSPORT_SENT_TO_TRANSPORT);
}

extern void iblock_free_task (se_task_t *task)
{
	iblock_req_t *req = (iblock_req_t *) task->transport_req;

	/*
	 * We do not release the bio(s) here associated with this task, as this is
	 * handled by bio_put() and iblock_bio_destructor().
	 */

	kfree(req);
	task->transport_req = NULL;
	
	return;
}

extern int iblock_check_hba_params (iscsi_hbainfo_t *hi, struct iscsi_target *t, int virt)
{
	if (!(t->hba_params_set & PARAM_HBA_IBLOCK_HOST_ID)) {
		TRACE_ERROR("iblock_host_id must be set for"
			" addhbatotarget requests with iBlock interfaces\n");
		return(ERR_HBA_MISSING_PARAMS);
	}
	hi->iblock_host_id = t->iblock_host_id;

	return(0);
}

extern int iblock_check_dev_params (se_hba_t *hba, struct iscsi_target *t, iscsi_dev_transport_info_t *dti)
{
	if (!(t->hba_params_set & PARAM_HBA_IBLOCK_MAJOR) ||
	    !(t->hba_params_set & PARAM_HBA_IBLOCK_MINOR)) {
		TRACE_ERROR("Missing iblock_check_dev_params() parameters\n");
		return(ERR_VIRTDEV_MISSING_PARAMS);
	}
	dti->iblock_major = t->iblock_major;
	dti->iblock_minor = t->iblock_minor;

	return(0);
}

extern int iblock_check_virtdev_params (iscsi_devinfo_t *di, struct iscsi_target *t)
{
	if (!(t->hba_params_set & PARAM_HBA_IBLOCK_MAJOR) ||
	    !(t->hba_params_set & PARAM_HBA_IBLOCK_MINOR)) {
		TRACE_ERROR("Missing iblock_check_virtdev_params() parameters\n");
		return(ERR_VIRTDEV_MISSING_PARAMS);
	}

	di->iblock_major = t->iblock_major;
	di->iblock_minor = t->iblock_minor;
	
	return(0);
}

extern void iblock_get_plugin_info (void *p, char *b, int *bl)
{
	*bl += sprintf(b+*bl, "%s iBlock Plugin %s\n", PYX_ISCSI_VENDOR, IBLOCK_VERSION);

	return;
}

extern void iblock_get_hba_info (se_hba_t *hba, char *b, int *bl)
{
	*bl += sprintf(b+*bl, "iSCSI Host ID: %u  iBlock Host ID: %u\n",
		hba->hba_id, hba->hba_info.iblock_host_id);
	*bl += sprintf(b+*bl, "        LIO iBlock HBA\n");

	return;
}

extern void iblock_get_dev_info (se_device_t *dev, char *b, int *bl)
{
	char buf[BDEVNAME_SIZE];
	iblock_dev_t *ibd = (iblock_dev_t *) dev->dev_ptr;
	struct block_device *bd = ibd->ibd_bd;

	*bl += sprintf(b+*bl, "iBlock device: %s", bdevname(bd, buf));
	if (ibd->ibd_flags & IBDF_HAS_MD_UUID) {
		*bl += sprintf(b+*bl, "  MD UUID: %x:%x:%x:%x\n",
			ibd->ibd_uu_id[0], ibd->ibd_uu_id[1],
			ibd->ibd_uu_id[2], ibd->ibd_uu_id[3]);
	} else if (ibd->ibd_flags & IBDF_HAS_LVM_UUID)
		*bl += sprintf(b+*bl, "  LVM UUID: %s\n", ibd->ibd_lvm_uuid);
	else 
		*bl += sprintf(b+*bl, "\n");

	*bl += sprintf(b+*bl, "        ");
	*bl += sprintf(b+*bl, "Major: %d Minor: %d  %s\n",
		ibd->ibd_major, ibd->ibd_minor, (!bd->bd_contains) ? "" :
		(bd->bd_holder == (iblock_dev_t *)ibd) ?
			"CLAIMED: IBLOCK" : "CLAIMED: OS");
	return;
}

extern void iblock_map_task_non_SG (se_task_t *task)
{
	return;
}

static void iblock_bio_destructor (struct bio *bio)
{
	se_task_t *task = (se_task_t *)bio->bi_private;
	iblock_dev_t *ib_dev = (iblock_dev_t *) task->iscsi_dev->dev_ptr;

	bio_free(bio, ib_dev->ibd_bio_set);
}

static struct bio *iblock_get_bio (se_task_t *task,
	iblock_req_t *ib_req,
	iblock_dev_t *ib_dev,
	int *ret,
	u64 lba,
	u32 sg_num)
{
	struct bio *bio;

	if (!(bio = bio_alloc_bioset(GFP_NOIO, sg_num, ib_dev->ibd_bio_set))) {
		TRACE_ERROR("Unable to allocate memory for bio\n");
		*ret = PYX_TRANSPORT_OUT_OF_MEMORY_RESOURCES;
		return(NULL);
	}

	DEBUG_IBLOCK("Allocated bio: %p task_sg_num: %u using ibd_bio_set: %p\n",
		bio, task->task_sg_num, ib_dev->ibd_bio_set);
	DEBUG_IBLOCK("Allocated bio: %p task_size: %u\n", bio, task->task_size);

	bio->bi_bdev = ib_dev->ibd_bd;
	bio->bi_private = (void *) task;
	bio->bi_destructor = iblock_bio_destructor;
	bio->bi_end_io = &iblock_bio_done;
	bio->bi_sector = lba;
	atomic_inc(&ib_req->ib_bio_cnt);

	DEBUG_IBLOCK("Set bio->bi_sector: %llu\n", bio->bi_sector);
	DEBUG_IBLOCK("Set ib_req->ib_bio_cnt: %d\n", atomic_read(&ib_req->ib_bio_cnt));

	return(bio);
}

extern int iblock_map_task_SG (se_task_t *task)
{
	iblock_dev_t *ib_dev = (iblock_dev_t *) task->iscsi_dev->dev_ptr;
	iblock_req_t *ib_req = (iblock_req_t *) task->transport_req;
	struct bio *bio = NULL, *hbio = NULL, *tbio = NULL;
	struct scatterlist *sg = (struct scatterlist *)task->task_buf;
	int ret = 0;
	u32 i, sg_num = task->task_sg_num;
	u64 lba = task->task_lba;

	atomic_set(&ib_req->ib_bio_cnt, 0);

	if (!(bio = iblock_get_bio(task, ib_req, ib_dev, &ret, task->task_lba, sg_num)))
		return(ret);

	ib_req->ib_bio = bio;
	hbio = tbio = bio;
	/*
	 * Use fs/bio.c:bio_add_pages() to setup the bio_vec maplist
	 * from LIO-SE se_mem_t -> task->task_buf -> struct scatterlist memory.
	 */
	for (i = 0; i < task->task_sg_num; i++) {
		DEBUG_IBLOCK("task: %p bio: %p Calling bio_add_page(): page: %p len:"
			" %u offset: %u\n", task, bio, sg_page(&sg[i]),
				sg[i].length, sg[i].offset);
again:
		if ((ret = bio_add_page(bio, sg_page(&sg[i]), sg[i].length,
				sg[i].offset)) != sg[i].length) {

			DEBUG_IBLOCK("*** Set bio->bi_sector: %llu\n", bio->bi_sector);
			DEBUG_IBLOCK("** task->task_size: %u\n", task->task_size);
			DEBUG_IBLOCK("*** bio->bi_max_vecs: %u\n", bio->bi_max_vecs);
			DEBUG_IBLOCK("*** bio->bi_vcnt: %u\n", bio->bi_vcnt);

			if (!(bio = iblock_get_bio(task, ib_req, ib_dev, &ret, lba, sg_num)))
				goto fail;

			tbio = tbio->bi_next = bio;
			DEBUG_IBLOCK("-----------------> Added +1 bio: %p to list,"
					" Going to again\n", bio);
			goto again;
		}

		lba += sg[i].length >> IBLOCK_LBA_SHIFT;
		sg_num--;
		DEBUG_IBLOCK("task: %p bio-add_page() passed!, decremented sg_num"
				" to %u\n", task, sg_num);
		DEBUG_IBLOCK("task: %p bio_add_page() passed!, increased lba to"
				" %llu\n", task, lba);
		DEBUG_IBLOCK("task: %p bio_add_page() passed!, bio->bi_vcnt: %u\n",
				task, bio->bi_vcnt);
	}

	return(task->task_sg_num);
fail:
	while (hbio) {
		bio = hbio;
		hbio = hbio->bi_next;
		bio->bi_next = NULL;
		bio_put(bio);
	}
	return(ret);
}

extern int iblock_CDB_inquiry (se_task_t *task, __u32 size)
{
	iblock_map_task_non_SG(task);

	return(0);
}

extern int iblock_CDB_none (se_task_t *task, u32 size)
{
	return(0);
}

extern int iblock_CDB_read_non_SG (se_task_t *task, u32 size)
{
	iblock_map_task_non_SG(task);

	return(0);
}

extern int iblock_CDB_read_SG (se_task_t *task, u32 size)
{
	return(iblock_map_task_SG(task));
}

extern int iblock_CDB_write_non_SG (se_task_t *task, u32 size)
{
	iblock_map_task_non_SG(task);

	return(0);
}

extern int iblock_CDB_write_SG (se_task_t *task, u32 size)
{
	return(iblock_map_task_SG(task));
}

extern int iblock_check_lba (unsigned long long lba, se_device_t *dev)
{
	return(0);
}

extern int iblock_check_for_SG (se_task_t *task)
{
	return(task->task_sg_num);
}

extern unsigned char *iblock_get_cdb (se_task_t *task)
{
	iblock_req_t *req = (iblock_req_t *) task->transport_req;
	
	return(req->ib_scsi_cdb);
}

extern u32 iblock_get_blocksize (se_device_t *dev)
{
	return(IBLOCK_BLOCKSIZE);
}

extern u32 iblock_get_device_rev (se_device_t *dev)
{
	return(02);
}

extern u32 iblock_get_device_type (se_device_t *dev)
{
	return(0); /* TYPE_DISK */
}

extern u32 iblock_get_dma_length (u32 task_size, se_device_t *dev)
{
	return(PAGE_SIZE);
}

extern u32 iblock_get_max_sectors (se_device_t *dev)
{
	iblock_dev_t *ibd = (iblock_dev_t *) dev->dev_ptr;
	request_queue_t *q = bdev_get_queue(ibd->ibd_bd);

	return((q->max_sectors < IBLOCK_MAX_SECTORS) ?
		q->max_sectors : IBLOCK_MAX_SECTORS);
}

extern u32 iblock_get_queue_depth (se_device_t *dev)
{
	return(IBLOCK_DEVICE_QUEUE_DEPTH);
}

extern unsigned char *iblock_get_non_SG (se_task_t *task)
{
	return((unsigned char *)task->iscsi_cmd->t_task->t_task_buf);
}

extern struct scatterlist *iblock_get_SG (se_task_t *task)
{
	return((struct scatterlist *)task->task_buf);
}

extern u32 iblock_get_SG_count (se_task_t *task)
{
	return(task->task_sg_num);
}

//#warning FIXME v2.8: Breakage in iblock_set_non_SG_buf()
extern int iblock_set_non_SG_buf (unsigned char *buf, se_task_t *task)
{
	return(0);
}

extern void iblock_bio_done (struct bio *bio, int err)
{
	se_task_t *task = (se_task_t *)bio->bi_private;
	iblock_req_t *ibr = (iblock_req_t *)task->transport_req;
	int ret = 0;

	if ((err = test_bit(BIO_UPTODATE, &bio->bi_flags) ? err : -EIO) != 0) {
		TRACE_ERROR("test_bit(BIO_UPTODATE) failed for bio: %p\n", bio);
		transport_complete_task(task, 0);
		ret = 1;
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
