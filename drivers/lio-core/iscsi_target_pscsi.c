/*********************************************************************************
 * Filename:  iscsi_target_pscsi.c
 *
 * This file contains the iSCSI <-> Parallel SCSI transport specific functions.
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


#define ISCSI_TARGET_PSCSI_C

#ifdef LINUX
#include <linux/version.h>
#include <linux/string.h>
#include <linux/timer.h>
#include <linux/blkdev.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/smp_lock.h>
#include <linux/genhd.h>

#ifdef USE_SCSI_H
#include <scsi.h>
#endif /* USE_SCSI_H */
#ifndef _SCSI_H
#include <scsi/scsi.h>
#include <scsi/scsi_device.h>
# ifndef scsi_execute_async_address
# include <scsi/scsi_request.h>
# endif
#include <scsi/scsi_cmnd.h>
#include <scsi/sd.h>
typedef struct scsi_cmnd Scsi_Cmnd;
typedef struct scsi_request Scsi_Request;
typedef struct scsi_pointer Scsi_Pointer;
#define SCSI_DATA_UNKNOWN	(DMA_BIDIRECTIONAL)
#define SCSI_DATA_WRITE		(DMA_TO_DEVICE)
#define SCSI_DATA_READ		(DMA_FROM_DEVICE)
#define SCSI_DATA_NONE		(DMA_NONE)
#endif /* _SCSI_H */
#include <scsi/scsi_host.h>

#include <iscsi_linux_os.h>
#include <iscsi_linux_defs.h>

#endif /* LINUX */

#include <iscsi_debug.h>
#include <iscsi_protocol.h>
#include <iscsi_target_core.h>
#include <iscsi_target_ioctl.h>
#include <iscsi_target_ioctl_defs.h>
#include <iscsi_target_device.h>
#include <iscsi_target_transport.h>
#include <iscsi_target_util.h>
#include <iscsi_target_pscsi.h>
#include <iscsi_target_error.h>

#include <iscsi_target_plugin.h>
#include <iscsi_target_seobj.h>
#include <iscsi_target_seobj_plugins.h>
#include <iscsi_target_transport_plugin.h>
				
#undef ISCSI_TARGET_PSCSI_C

#define ISPRINT(a)  ((a >=' ')&&(a <= '~'))

#warning FIXME: Obtain via IOCTL for Initiator Drivers
#define INIT_CORE_NAME          "SBE, Inc. iSCSI Initiator Core"

extern iscsi_global_t *iscsi_global;
extern struct block_device *linux_blockdevice_claim(int, int, void *);
extern int linux_blockdevice_release(int, int, struct block_device *);
extern int linux_blockdevice_check(int, int);

/*	pscsi_get_sh():
 *
 *
 */
static struct Scsi_Host *pscsi_get_sh (u32 host_no)
{
	struct Scsi_Host *sh = NULL;
	
	sh = scsi_host_lookup(host_no);
	if (IS_ERR(sh)) {
		TRACE_ERROR("Unable to locate Parallel SCSI HBA with Host ID:"
				" %u\n", host_no);
		return(NULL);
	}

	return(sh);
}

/*	pscsi_check_sd():
 *
 *	Should be called with scsi_device_get(sd) held
 */
extern int pscsi_check_sd (struct scsi_device *sd)
{
	struct gendisk *disk;
	struct scsi_disk *sdisk;

	if (!sd) {
		TRACE_ERROR("struct scsi_device is NULL!\n");
		return(-1);
	}
	
	if (sd->type != TYPE_DISK)
		return(0);

	/*
	 * Some struct scsi_device of Type: Direct-Access, namely the
	 * SGI Univerisal Xport do not have a corrasponding block device.
	 * We skip these for now.
	 */
	if (!(sdisk = dev_get_drvdata(&sd->sdev_gendev)))
		return(-1);

	disk = (struct gendisk *) sdisk->disk;
	if (!(disk->major)) {
		TRACE_ERROR("dev_get_drvdata() failed\n");
		return(-1);
	}

	if (linux_blockdevice_check(disk->major, disk->first_minor) < 0)
		return(-1);

	return(0);
}

/*	pscsi_claim_sd():
 *
 *	Should be called with scsi_device_get(sd) held
 */
extern int pscsi_claim_sd (struct scsi_device *sd)
{
	struct block_device *bdev;
	struct gendisk *disk;
	struct scsi_disk *sdisk;

	if (!sd) {
		TRACE_ERROR("struct scsi_device is NULL!\n");
		return(-1);
	}
	
	if (sd->type != TYPE_DISK)
		return(0);
	
	/*
	 * Some struct scsi_device of Type: Direct-Access, namely the
	 * SGI Univerisal Xport do not have a corrasponding block device.
	 * We skip these for now.
	 */
	if (!(sdisk = dev_get_drvdata(&sd->sdev_gendev)))
		return(-1);

	disk = (struct gendisk *) sdisk->disk;
	if (!(disk->major)) {
		TRACE_ERROR("dev_get_drvdata() failed\n");
		return(-1);
	}

	PYXPRINT("PSCSI: Claiming %p Major:Minor - %d:%d\n", sd, disk->major, disk->first_minor);
	
	if (!(bdev = linux_blockdevice_claim(disk->major, disk->first_minor, (void *)sd)))
		return(-1);

	return(0);
}

/*	pscsi_release_sd()
 *
 * 	Should be called with scsi_device_get(sd) held
 */
extern int pscsi_release_sd (struct scsi_device *sd)
{
	struct gendisk *disk;
	struct scsi_disk *sdisk;
	
	if (!sd) {
		TRACE_ERROR("struct scsi_device is NULL!\n");
		return(-1);
	}

	if (sd->type != TYPE_DISK)
		return(0);
	
	/*
	 * Some struct scsi_device of Type: Direct-Access, namely the
	 * SGI Univerisal Xport do not have a corrasponding block device.
	 * We skip these for now.
	 */
	if (!(sdisk = dev_get_drvdata(&sd->sdev_gendev)))
		return(-1);

	disk = (struct gendisk *) sdisk->disk;
	if (!(disk->major)) {
		TRACE_ERROR("dev_get_drvdata() failed\n");
		return(-1);
	}

	PYXPRINT("PSCSI: Releasing Major:Minor - %d:%d\n", disk->major, disk->first_minor);

	return(linux_blockdevice_release(disk->major, disk->first_minor, NULL));
}

/*	pscsi_attach_hba():
 *
 *	FIXME: Check was locking the midlayer does for accessing scsi_hostlist.	
 */
extern int pscsi_attach_hba (iscsi_portal_group_t *tpg, iscsi_hba_t *hba, iscsi_hbainfo_t *hi)
{
	int hba_depth, max_sectors, pscsi_dev_count;
	struct Scsi_Host *sh;

	if (!(sh = pscsi_get_sh(hi->scsi_host_id)))
		return(-1);

	max_sectors = sh->max_sectors;

	/*
	 * Usually the SCSI LLD will use the hostt->can_queue value to define its
	 * HBA TCQ depth.  Some other drivers (like 2.6 megaraid) don't set this
	 * at all and set sh->can_queue at runtime.
	 */
	hba_depth = (sh->hostt->can_queue > sh->can_queue) ?
		sh->hostt->can_queue : sh->can_queue;
	atomic_set(&hba->left_queue_depth, hba_depth);
	atomic_set(&hba->max_queue_depth, hba_depth);

	hba->hba_ptr = (void *) sh;
	hba->hba_id = hi->hba_id;
	hba->transport = &pscsi_template;
	memcpy((void *)&hba->hba_info, (void *)hi, sizeof(iscsi_hbainfo_t));
	
	PYXPRINT("iSCSI_HBA[%d] - %s Parallel SCSI HBA Driver %s on iSCSI"
		" Target Core Stack %s\n", hba->hba_id, PYX_ISCSI_VENDOR, PSCSI_VERSION, PYX_ISCSI_VERSION);
	PYXPRINT("iSCSI_HBA[%d] - %s\n", hba->hba_id, (sh->hostt->name) ?
			(sh->hostt->name) : "Unknown");
	PYXPRINT("iSCSI_HBA[%d] - Attached Parallel SCSI HBA to iSCSI Transport"
		" with TCQ Depth: %d MaxSectors: %hu\n", hba->hba_id,
		atomic_read(&hba->max_queue_depth), max_sectors);

	/*
	 * For Parallel SCSI we assume the devices are already attached to the
	 * HBA, so go ahead and scan the bus for devices to export as iSCSI LUNs.
	 */
	if ((pscsi_dev_count = pscsi_scan_devices(hba, hi)) < 0) {
		PYXPRINT("No devices present, ignoring request to add"
			" Parallel SCSI HBA %d.\n", sh->host_no);
		goto fail;
	}
		
	return(0);
fail:
	scsi_host_put(sh);
	return(-1);
}

/*	pscsi_detach_hba(): (Part of iscsi_transport_t template)
 *
 *
 */
extern int pscsi_detach_hba (iscsi_hba_t *hba)
{
	struct Scsi_Host *scsi_host = (struct Scsi_Host *) hba->hba_ptr;
	
	scsi_host_put(scsi_host);
	
	PYXPRINT("iSCSI_HBA[%d] - Detached Parallel SCSI HBA: %s from iSCSI Transport\n",
		hba->hba_id, (scsi_host->hostt->name) ? (scsi_host->hostt->name) : "Unknown");	

	hba->hba_ptr = NULL;
	
	return(0);
}

/*	pscsi_scan_devices(): (Part of iscsi_transport_t template)
 *
 * 	FIXME: For <= v2.4, check what locking the midlayer does for accessing Scsi_Host->host_queue (if any?)
 */
extern int pscsi_scan_devices (iscsi_hba_t *iscsi_hba, iscsi_hbainfo_t *hi)
{
	int pscsi_dev_count = 0;
	int dev_flags = 0;
	iscsi_device_t *dev;
	struct scsi_device *sd;
	struct Scsi_Host *sh = (struct Scsi_Host *) iscsi_hba->hba_ptr;

	spin_lock_irq(sh->host_lock);
	list_for_each_entry(sd, &sh->__devices, siblings) {
		if (sd->type == TYPE_DISK) {
			if (scsi_device_get(sd))
			    continue;

			spin_unlock_irq(sh->host_lock);

			if (pscsi_check_sd(sd) < 0) {
				spin_lock_irq(sh->host_lock);
				scsi_device_put(sd);
				continue;
			}

			/*
			 * In some cases (namely the iSCSI Initiator Case) we want to
			 * grab exclusive access to the underlying Linux block device
			 * immediately at this point.  We use parameter that is passed
			 * with addhbatotarget to determine when to claim for this case.
			 */
			if (hi->os_claim_devices) 
				if (!(pscsi_claim_sd(sd))) {
					dev_flags |= DF_CLAIMED_BLOCKDEV;
					dev_flags |= DF_PERSISTENT_CLAIMED_BLOCKDEV;
				}
			
			dev = pscsi_add_device_to_list(iscsi_hba, sd, dev_flags);
			
			if (dev_flags & DF_CLAIMED_BLOCKDEV) {
				dev_flags &= ~DF_CLAIMED_BLOCKDEV;
				dev_flags &= ~DF_PERSISTENT_CLAIMED_BLOCKDEV;
			}
			
			spin_lock_irq(sh->host_lock);

			if (!dev) {
			    scsi_device_put(sd);
			    continue;
			}
			
			pscsi_dev_count++;
			continue;
		}

		/*
		 * We may need to do peripheral-type specific checking of access counts.
		 */
//#warning FIXME v2.8: Check usage of scsi_device_get() for non TYPE_DISK
		if (sd->type == TYPE_ROM || sd->type == TYPE_TAPE || sd->type == TYPE_MEDIUM_CHANGER) {
			spin_unlock_irq(sh->host_lock);
			dev = pscsi_add_device_to_list(iscsi_hba, sd, dev_flags);
			spin_lock_irq(sh->host_lock);

			if (!dev)
				continue;
			
			pscsi_dev_count++;
			continue;
		}

	}
	spin_unlock_irq(sh->host_lock);
		
	if (!pscsi_dev_count)
		return(-1);

	PYXPRINT("iSCSI_PSCSI[%d] - Detected %d Parallel SCSI Devices\n",
			sh->host_no, pscsi_dev_count);

	return(pscsi_dev_count);
}

/*	pscsi_add_device_to_list():
 *
 *	FIXME: We are going to want to increment struct scsi_device->access_count
 *	       either here or in pscsi_activate_device().
 */
extern iscsi_device_t *pscsi_add_device_to_list (iscsi_hba_t *iscsi_hba, struct scsi_device *sd, int dev_flags)
{
	iscsi_device_t *dev;
	
	/*
	 * Some pseudo Parallel SCSI HBAs do not fill in sector_size
	 * correctly. (See ide-scsi.c)  So go ahead and setup sane
	 * values.
	 */
	if (!sd->sector_size) {
		switch (sd->type) {
		case TYPE_DISK:
			sd->sector_size = 512;
			break;
		case TYPE_ROM:
			sd->sector_size = 2048;
			break;
		case TYPE_TAPE: /* The Tape may not be in the drive */
			break;
		case TYPE_MEDIUM_CHANGER: /* Control CDBs only */
			break;
		default:
			TRACE_ERROR("Unable to set sector_size for %d\n",
					sd->type);
			return(NULL);
		}

		if (sd->sector_size) {
			TRACE_ERROR("Set broken Parallel SCSI Device %d:%d:%d"
				" sector_size to %d\n", sd->channel, sd->id,
					sd->lun, sd->sector_size);
		}
	}

	if (!sd->queue_depth) {
		sd->queue_depth = PSCSI_DEFAULT_QUEUEDEPTH;

		TRACE_ERROR("Set broken Parallel SCSI Device %d:%d:%d"
			" queue_depth to %d\n", sd->channel, sd->id,
				sd->lun, sd->queue_depth);
	}
	
	if (!(dev = transport_add_device_to_iscsi_hba(iscsi_hba, &pscsi_template,
			 	dev_flags, (void *)sd)))
		return(NULL);
	
	/*
	 * For TYPE_TAPE, attempt to determine blocksize with MODE_SENSE.
	 */
	if (sd->type == TYPE_TAPE) {
		unsigned char *buf = NULL, cdb[SCSI_CDB_SIZE];
		iscsi_cmd_t *cmd;
		u32 blocksize;

		memset(cdb, 0, SCSI_CDB_SIZE);
		cdb[0] = MODE_SENSE;
		cdb[4] = 0x0c; /* 12 bytes */
		
		if (!(cmd = transport_allocate_passthrough(&cdb[0], ISCSI_READ, 0, NULL, 0,
				12, DEV_OBJ_API(dev), dev))) {
			TRACE_ERROR("Unable to determine blocksize for TYPE_TAPE\n");
			goto out;
		}

		if (transport_generic_passthrough(cmd) < 0) {
			TRACE_ERROR("Unable to determine blocksize for TYPE_TAPE\n");
			goto out;
		}

		buf = (unsigned char *)T_TASK(cmd)->t_task_buf;
		blocksize = (buf[9] << 16) | (buf[10] << 8) | (buf[11]);

		/*
		 * If MODE_SENSE still returns zero, set the default value to 1024.
		 */
		if (!(sd->sector_size = blocksize))
			sd->sector_size = 1024;

		transport_passthrough_release(cmd);
	}
out:
	return(dev);
}

extern int pscsi_claim_phydevice (iscsi_hba_t *hba, iscsi_device_t *dev)
{
	struct scsi_device *sd = (struct scsi_device *)dev->dev_ptr;
	
	return(pscsi_claim_sd(sd));
}

extern int pscsi_release_phydevice (iscsi_device_t *dev)
{
	struct scsi_device *sd = (struct scsi_device *)dev->dev_ptr;
	
	return(pscsi_release_sd(sd));
}

/*	pscsi_activate_device(): (Part of iscsi_transport_t template)
 *
 *
 */
extern int pscsi_activate_device (iscsi_device_t *dev)
{
	struct scsi_device *sd = (struct scsi_device *) dev->dev_ptr;
	struct Scsi_Host *sh = sd->host;
	
	PYXPRINT("iSCSI_PSCSI[%d] - Activating Device with TCQ: %d at Parallel"
		" SCSI Location (Channel/Target/LUN) %d/%d/%d\n", sh->host_no,
		 sd->queue_depth, sd->channel, sd->id, sd->lun);

	return(0);
}

/*	pscsi_deactivate_device(): (Part of iscsi_transport_t template)
 *
 *
 */
extern void pscsi_deactivate_device (iscsi_device_t *dev)
{
	struct scsi_device *sd = (struct scsi_device *) dev->dev_ptr;
	struct Scsi_Host *sh = sd->host;
	
	PYXPRINT("iSCSI_PSCSI[%d] - Deactivating Device with TCQ: %d at Parallel"
		" SCSI Location (Channel/Target/LUN) %d/%d/%d\n", sh->host_no,
		sd->queue_depth, sd->channel, sd->id, sd->lun);
	
	return;
}

/*	pscsi_check_device_location(): (Part of iscsi_transport_t template)
 *
 *
 */
extern int pscsi_check_device_location (iscsi_device_t *dev, iscsi_dev_transport_info_t *dti)
{
	struct scsi_device *sd = (struct scsi_device *) dev->dev_ptr;

	if ((dti->scsi_channel_id == sd->channel) &&
	    (dti->scsi_lun_id == sd->lun) &&
	    (dti->scsi_target_id == sd->id))
		return(0);

	return(-1);	
}

/*	pscsi_check_ghost_id(): (Part of iscsi_transport_t template)
 *
 *	
 */
extern int pscsi_check_ghost_id (iscsi_hbainfo_t *hi)
{
	int i;
	iscsi_hba_t *hba;
	struct Scsi_Host *sh;
	
	spin_lock(&iscsi_global->hba_lock);
	for (i = 0; i < ISCSI_MAX_GLOBAL_HBAS; i++) {
		hba = &iscsi_global->hba_list[i];

		if (!(hba->hba_status & HBA_STATUS_ACTIVE))
			continue;
		if (hba->type != PSCSI)
			continue;
		sh = (struct Scsi_Host *) hba->hba_ptr;
		if (sh->host_no == hi->scsi_host_id) {
			TRACE_ERROR("Parallel SCSI HBA with SCSI Host ID: %d"
				" already assigned to iSCSI HBA: %hu, ignoring"
				" request.\n", hi->scsi_host_id, i);
			spin_unlock(&iscsi_global->hba_lock);
			return(1);
		}
	}
	spin_unlock(&iscsi_global->hba_lock);

	return(0);
}

/*	pscsi_free_device(): (Part of iscsi_transport_t template)
 *
 *
 */
extern void pscsi_free_device (iscsi_device_t *dev)
{
	struct scsi_device *sd = (struct scsi_device *) dev->dev_ptr;

	if (sd->type == TYPE_DISK) {
		transport_generic_release_phydevice(dev, 0);
		scsi_device_put(sd);
	}
	
	dev->dev_ptr = NULL;

	return;
}

/*	pscsi_transport_complete():
 *
 *
 */
extern int pscsi_transport_complete (iscsi_task_t *task)
{
	struct scsi_device *sd = (struct scsi_device *) task->iscsi_dev->dev_ptr;
	void *pscsi_buf;
	int result;
#ifdef scsi_execute_async_address
	pscsi_plugin_task_t *pt = (pscsi_plugin_task_t *) task->transport_req;
	unsigned char *cdb = &pt->pscsi_cdb[0];

	result = pt->pscsi_result;
	pscsi_buf = pt->pscsi_buf;
#else
	Scsi_Request *req = (Scsi_Request *) task->transport_req;
	unsigned char *cdb = &req->sr_cmnd[0];
	
	result = req->sr_result;
	pscsi_buf = req->sr_buffer;
#endif

# ifdef LINUX_EVPD_PAGE_CHECK
	if ((cdb[0] == INQUIRY) && host_byte(result) == DID_OK) {
		u32 len = 0;
		unsigned char *dst = (unsigned char *)pscsi_buf, *iqn = NULL;
		unsigned char buf[EVPD_BUF_LEN];
//#warning FIXME v2.8: se_obj_api usage
		iscsi_hba_t *hba = task->iscsi_dev->iscsi_hba;

		/*
		 * The Initiator port did not request EVPD information.
		 */
		if (!(cdb[1] & 0x1)) {
			task->task_scsi_status = GOOD;
			return(0);
		}
			
		/*
		 * Assume the HBA did the right thing..
		 */
		if (dst[3] != 0x00) {
			task->task_scsi_status = GOOD;
			return(0);
		}

		memset(buf, 0, EVPD_BUF_LEN);
		memset(dst, 0, task->task_size);
		buf[0] = sd->type;

		switch (cdb[2]) {
		case 0x00:
			buf[1] = 0x00;
			buf[3] = 3;
			buf[4] = 0x0;
			buf[5] = 0x80; 
			buf[6] = 0x83;
			len = 3;
			break;
		case 0x80:
			iqn = transport_get_iqn_sn();
			buf[1] = 0x80;
			len += sprintf((unsigned char *)&buf[4], "%s:%u_%u_%u_%u",
				iqn, hba->hba_id, sd->channel, sd->id, sd->lun);
			buf[3] = len;
			break;
		case 0x83:
			iqn = transport_get_iqn_sn();
			buf[1] = 0x83;
			/* Start Identifier Page */
			buf[4] = 0x2; /* ASCII */
			buf[5] = 0x1; 
			buf[6] = 0x0;
			len += sprintf((unsigned char *)&buf[8], "SBEi-INC");
			len += sprintf((unsigned char *)&buf[16], "PSCSI:%s:%u_%u_%u_%u",
					iqn, hba->hba_id, sd->channel, sd->id, sd->lun);
			buf[7] = len; /* Identifer Length */
			len += 4;
			buf[3] = len; /* Page Length */
			break;
		default:
			break;
		}
				
		if ((len + 4) > task->task_size) {
			TRACE_ERROR("Inquiry EVPD Length: %u larger than"
				" req->sr_bufflen: %u\n", (len + 4), task->task_size);
			memcpy(dst, buf, task->task_size);
		} else
			memcpy(dst, buf, (len + 4));
		
		/*
		 * Fake the GOOD SAM status here too.
		 */
		task->task_scsi_status = GOOD;	
		return(0);
	}

# endif /* LINUX_EVPD_PAGE_CHECK */

	/*
	 * Hack to make sure that Write-Protect modepage is set if R/O mode is forced.
	 */
	if (((cdb[0] == MODE_SENSE) || (cdb[0] == MODE_SENSE_10)) &&
	     (status_byte(result) << 1) == SAM_STAT_GOOD) {
		if (!task->iscsi_cmd->iscsi_deve)
			goto after_mode_sense;

		if (task->iscsi_cmd->iscsi_deve->lun_flags & ISCSI_LUNFLAGS_READ_ONLY) {
			unsigned char *buf = (unsigned char *)pscsi_buf;

			if (cdb[0] == MODE_SENSE_10) {
				if (!(buf[3] & 0x80))
					buf[3] |= 0x80;
			} else {
				if (!(buf[2] & 0x80))
					buf[2] |= 0x80;
			}
		}
	}
after_mode_sense:

	if (sd->type != TYPE_TAPE)
		goto after_mode_select;
	
	/*
	 * Hack to correctly obtain the initiator requested blocksize for TYPE_TAPE.
	 * Since this value is dependent upon each tape media, struct scsi_device->sector_size
	 * will not contain the correct value by default, so we go ahead and set it so
	 * TRANSPORT(dev)->get_blockdev() returns the correct value to the storage engine.
	 */
	if (((cdb[0] == MODE_SELECT) || (cdb[0] == MODE_SELECT_10)) &&
	      (status_byte(result) << 1) == SAM_STAT_GOOD) {
		unsigned char *buf;
		struct scatterlist *sg = (struct scatterlist *)pscsi_buf;
		u16 bdl;
		u32 blocksize;
		
		if (!(buf = GET_ADDR_SG(&sg[0]))) {
			TRACE_ERROR("Unable to get buf for scatterlist\n");
			goto after_mode_select;
		}

		if (cdb[0] == MODE_SELECT)
			bdl = (buf[3]);
		else
			bdl = (buf[6] << 8) | (buf[7]);

		if (!bdl)
			goto after_mode_select;

		if (cdb[0] == MODE_SELECT)
			blocksize = (buf[9] << 16) | (buf[10] << 8) | (buf[11]);
		else
			blocksize = (buf[13] << 16) | (buf[14] << 8) | (buf[15]);

		sd->sector_size = blocksize;
	}
after_mode_select:
	
	if (status_byte(result) & CHECK_CONDITION)
		return(1);

	return(0);
}

/*	pscsi_allocate_request(): (Part of iscsi_transport_t template)
 *
 *
 */
extern void *pscsi_allocate_request (
	iscsi_task_t *task,
	iscsi_device_t *dev)
{
#ifdef scsi_execute_async_address
	pscsi_plugin_task_t *pt;
	if (!(pt = kmalloc(sizeof(pscsi_plugin_task_t), GFP_KERNEL))) {
		TRACE_ERROR("Unable to allocate pscsi_plugin_task_t\n");
		return(NULL);
	}
	memset(pt, 0, sizeof(pscsi_plugin_task_t));

	return(pt);

#else
	struct scsi_device *sd = (struct scsi_device *) dev->dev_ptr;
	Scsi_Request *sr;

	if (!(sr = (Scsi_Request *) scsi_allocate_request(sd, GFP_KERNEL))) {
		TRACE_ERROR("scsi_allocate_request() failed\n");
		return(NULL);
	}
	sr->upper_private_data = (void *) task;

	return(sr);
#endif
}

extern void pscsi_get_evpd_prod (unsigned char *buf, u32 size, iscsi_device_t *dev)
{
	snprintf(buf, size, "PSCSI");
	return;
}

extern void pscsi_get_evpd_sn (unsigned char *buf, u32 size, iscsi_device_t *dev)
{
	struct scsi_device *sd = (struct scsi_device *) dev->dev_ptr;
	iscsi_hba_t *hba = dev->iscsi_hba;

	snprintf(buf, size, "%u_%u_%u_%u", hba->hba_id, sd->channel, sd->id, sd->lun);
	return;
}

/*	pscsi_do_task(): (Part of iscsi_transport_t template)
 *
 *
 */
extern int pscsi_do_task (iscsi_task_t *task)
{
#ifdef scsi_execute_async_address
	pscsi_plugin_task_t *pt = (pscsi_plugin_task_t *) task->transport_req;
	int ret;
	
	if ((ret = scsi_execute_async((struct scsi_device *)task->iscsi_dev->dev_ptr,
			   pt->pscsi_cdb, COMMAND_SIZE(pt->pscsi_cdb[0]), pt->pscsi_direction,
			   pt->pscsi_buf, task->task_size, task->task_sg_num,
			   (task->se_obj_api->get_device_type(task->se_obj_ptr) == 0) ?
			   PS_TIMEOUT_DISK : PS_TIMEOUT_OTHER, PS_RETRY,
			   (void *)task, pscsi_req_done, GFP_KERNEL)) != 0) {
		TRACE_ERROR("PSCSI Execute(): returned: %d\n", ret);
		return(PYX_TRANSPORT_LOGICAL_UNIT_COMMUNICATION_FAILURE);
	}	

#else
	Scsi_Request *req = (Scsi_Request *) task->transport_req;

	scsi_do_req(req, req->sr_cmnd, req->sr_buffer, req->sr_bufflen, pscsi_req_done,
			(task->se_obj_api->get_device_type(task->se_obj_ptr) == 0) ?
			PS_TIMEOUT_DISK : PS_TIMEOUT_OTHER, PS_RETRY);
#endif 
	return(PYX_TRANSPORT_SENT_TO_TRANSPORT);
}

/*	pscsi_free_task(): (Part of iscsi_transport_t template)
 *
 *
 */
extern void pscsi_free_task (iscsi_task_t *task)
{
#ifdef scsi_execute_async_address
	kfree(task->transport_req);
#else
	Scsi_Request *req = (Scsi_Request *) task->transport_req;
	if (!req) {
		TRACE_ERROR("REQ is NULL!\n");
		BUG();
	}
	scsi_release_request(req);
#endif 
	return;
}

extern int pscsi_check_hba_params (iscsi_hbainfo_t *hi, struct iscsi_target *t, int virt)
{
	if (virt) {
		TRACE_ERROR("createvirtdev is not required for Physical"
			" Storage Transports, ignoring request\n");
		return(ERR_FREE_VIRTDEV_PHYSICAL_HBA);
	}

	if (!(t->hba_params_set & PARAM_HBA_SCSI_HOST_ID)) {
		TRACE_ERROR("scsi_host_id must be set for"
			" addhbatotarget requests with Parallel"
			" SCSI HBAs.\n");
		return(ERR_HBA_MISSING_PARAMS);
	}
	hi->scsi_host_id = t->scsi_host_id;

	/* PSCSI T/I Repeater Mode */
	if (t->hba_params_set & PARAM_HBA_ISCSI_CHANNEL_ID)
		hi->iscsi_channel_id = t->iscsi_channel_id;

	return(0);
}

extern int pscsi_check_dev_params (iscsi_hba_t *hba, struct iscsi_target *t, iscsi_dev_transport_info_t *dti)
{
	if (!(t->hba_params_set & PARAM_HBA_SCSI_CHANNEL_ID)) {
		TRACE_ERROR("scsi_channel_id must be set for"
			" addluntodev requests with Parallel"
			" SCSI Devices.\n");
		return(-1);
	}

	if (!(t->hba_params_set & PARAM_HBA_SCSI_TARGET_ID)) {
		TRACE_ERROR("scsi_target_id must be set for"
			" addluntodev requests with Parallel"
			" SCSI Devices.\n");
		return(-1);
	}

	if (!(t->hba_params_set & PARAM_HBA_SCSI_LUN_ID)) {
		TRACE_ERROR("scsi_lun_id must be set for"
			" addluntodev requests with Parallel"
			" SCSI Devices.\n");
		return(-1);
	}

	dti->scsi_channel_id = t->scsi_channel_id;
	dti->scsi_lun_id = t->scsi_lun_id;
	dti->scsi_target_id = t->scsi_target_id;

	return(0);
}

extern void pscsi_get_plugin_info (void *p, char *b, int *bl)
{
	*bl += sprintf(b+*bl, "%s Parallel SCSI Plugin %s\n", PYX_ISCSI_VENDOR, PSCSI_VERSION);

	return;
}

extern void pscsi_get_hba_info (iscsi_hba_t *hba, char *b, int *bl)
{
	struct Scsi_Host *sh = (struct Scsi_Host *) hba->hba_ptr;

	*bl += sprintf(b+*bl, "iSCSI Host ID: %u  SCSI Host ID: %u\n",
			 hba->hba_id, sh->host_no);

	if (strcmp(sh->hostt->name, INIT_CORE_NAME))
		*bl += sprintf(b+*bl, "        Parallel SCSI HBA: %s  <local>\n",
			(sh->hostt->name) ? (sh->hostt->name) : "Unknown");
	else
		*bl += sprintf(b+*bl, "        Parallel SCSI HBA: %s "
				" iSCSI Channel No: %d  <remote>\n",
				(sh->hostt->name) ? (sh->hostt->name) : "Unknown",
				hba->hba_info.iscsi_channel_id);
	return;	
}

extern void pscsi_get_dev_info (iscsi_device_t *dev, char *b, int *bl)
{
	int i;
	struct scsi_device *sd = (struct scsi_device *) dev->dev_ptr;

	*bl += sprintf(b+*bl, "Parallel SCSI Device Bus Location:"
		" Target ID: %d Channel ID: %d LUN: %d\n",
		sd->id, sd->channel, sd->lun);

	*bl += sprintf(b+*bl, "        ");

	*bl += sprintf(b+*bl, "Vendor: ");
	for (i = 0; i < 8; i++) {
		if (ISPRINT(sd->vendor[i]))   /* printable character ? */
			*bl += sprintf(b+*bl, "%c", sd->vendor[i]);
		else
			*bl += sprintf(b+*bl, " ");
	}

	*bl += sprintf(b+*bl, " Model: ");
	for (i = 0; i < 16; i++) {
		if (ISPRINT(sd->model[i]))   /* printable character ? */
			*bl += sprintf(b+*bl, "%c", sd->model[i]);
		else
			*bl += sprintf(b+*bl, " ");
	}

	*bl += sprintf(b+*bl, " Rev: ");
	for (i = 0; i < 4; i++) {
		if (ISPRINT(sd->rev[i]))   /* printable character ? */
			*bl += sprintf(b+*bl, "%c", sd->rev[i]);
		else
			*bl += sprintf(b+*bl, " ");
	}

	if (sd->type == TYPE_DISK) {
		struct scsi_disk *sdisk = dev_get_drvdata(&sd->sdev_gendev);
		struct gendisk *disk = (struct gendisk *) sdisk->disk;
		struct block_device *bdev = bdget(MKDEV(disk->major, disk->first_minor));

		bdev->bd_disk = disk;
		*bl += sprintf(b+*bl, "   %s\n", (!bdev->bd_holder) ? "" :
				(bdev->bd_holder == (struct scsi_device *)sd) ?
				"CLAIMED: PSCSI" : "CLAIMED: OS");
	} else
		*bl += sprintf(b+*bl, "\n");

	return;
}

/*	pscsi_map_task_SG(): 
 *
 *
 */
extern void pscsi_map_task_SG (iscsi_task_t *task)
{
#ifdef scsi_execute_async_address
        pscsi_plugin_task_t *pt = (pscsi_plugin_task_t *) task->transport_req;
	pt->pscsi_buf = (void *)task->task_buf;
#else
	Scsi_Request *req = (Scsi_Request *) task->transport_req;
	req->sr_bufflen = task->task_size;
	req->sr_buffer = (void *)task->task_buf;
	req->sr_sglist_len = (task->task_sg_num * sizeof(struct scatterlist));
	req->sr_use_sg = task->task_sg_num;
#endif

	return;
}

/*	pscsi_map_task_non_SG():
 *
 *
 */
extern void pscsi_map_task_non_SG (iscsi_task_t *task)
{
	iscsi_cmd_t *cmd = task->iscsi_cmd;
	unsigned char *buf = (unsigned char *) T_TASK(cmd)->t_task_buf;

#ifdef scsi_execute_async_address
	pscsi_plugin_task_t *pt = (pscsi_plugin_task_t *) task->transport_req;
	pt->pscsi_buf = (void *)buf;
#else
	Scsi_Request *req = (Scsi_Request *) task->transport_req;
	req->sr_bufflen = task->task_size;
	req->sr_buffer = (void *)buf;
	req->sr_sglist_len = 0;
	req->sr_use_sg = 0;
#endif 

	return;
}

/*	pscsi_CDB_inquiry():
 *
 *
 */
extern int pscsi_CDB_inquiry (iscsi_task_t *task, u32 size)
{
#ifdef scsi_execute_async_address
	pscsi_plugin_task_t *pt = (pscsi_plugin_task_t *) task->transport_req;

	pt->pscsi_direction = DMA_FROM_DEVICE;
#else
	Scsi_Request *req = (Scsi_Request *) task->transport_req;

	req->sr_data_direction	= SCSI_DATA_READ;
#endif 

	pscsi_map_task_non_SG(task);
	return(0);
}

extern int pscsi_CDB_none (iscsi_task_t *task, u32 size)
{
#ifdef scsi_execute_async_address
	pscsi_plugin_task_t *pt = (pscsi_plugin_task_t *) task->transport_req;

	pt->pscsi_direction = DMA_NONE;
#else
	Scsi_Request *req = (Scsi_Request *) task->transport_req;

	req->sr_data_direction	= SCSI_DATA_NONE;
	req->sr_bufflen		= 0;
	req->sr_sglist_len	= 0;
	req->sr_use_sg		= 0;
#endif 

	return(0);
}

/*	pscsi_CDB_read_non_SG():
 *
 *
 */
extern int pscsi_CDB_read_non_SG (iscsi_task_t *task, u32 size)
{
#ifdef scsi_execute_async_address
	pscsi_plugin_task_t *pt = (pscsi_plugin_task_t *) task->transport_req;

	pt->pscsi_direction = DMA_FROM_DEVICE;
#else
	Scsi_Request *req = (Scsi_Request *) task->transport_req;

	req->sr_data_direction  = SCSI_DATA_READ;
#endif 

	pscsi_map_task_non_SG(task);

	return(0);
}

/*	pscsi_CDB_read_SG():
 *
 *
 */
extern int pscsi_CDB_read_SG (iscsi_task_t *task, u32 size)
{
#ifdef scsi_execute_async_address
	pscsi_plugin_task_t *pt = (pscsi_plugin_task_t *) task->transport_req;

	pt->pscsi_direction = DMA_FROM_DEVICE;
	pscsi_map_task_SG(task);

	return(task->task_sg_num);
#else
	Scsi_Request *req = (Scsi_Request *) task->transport_req;

	req->sr_data_direction  = SCSI_DATA_READ;
	pscsi_map_task_SG(task);

	return(req->sr_use_sg);
#endif
}

/*	pscsi_CDB_write_non_SG():
 *
 *
 */
extern int pscsi_CDB_write_non_SG (iscsi_task_t *task, u32 size)
{
#ifdef scsi_execute_async_address
	pscsi_plugin_task_t *pt = (pscsi_plugin_task_t *) task->transport_req;

	pt->pscsi_direction = DMA_TO_DEVICE;
#else
	Scsi_Request *req = (Scsi_Request *) task->transport_req;

	req->sr_data_direction  = SCSI_DATA_WRITE;
#endif 

	pscsi_map_task_non_SG(task);
	return(0);
}

/*	pscsi_CDB_write_SG():
 *
 *
 */
extern int pscsi_CDB_write_SG (iscsi_task_t *task, u32 size)
{
#ifdef scsi_execute_async_address
	pscsi_plugin_task_t *pt = (pscsi_plugin_task_t *) task->transport_req;

	pt->pscsi_direction = DMA_TO_DEVICE;
	pscsi_map_task_SG(task);
	
	return(task->task_sg_num);
#else
	Scsi_Request *req = (Scsi_Request *) task->transport_req;

	req->sr_data_direction  = SCSI_DATA_WRITE;
	pscsi_map_task_SG(task);

	return(req->sr_use_sg);
#endif
}

/*	pscsi_check_lba():
 *
 *
 */
extern int pscsi_check_lba (unsigned long long lba, iscsi_device_t *dev)
{
	return(0);
}

/*	pscsi_check_for_SG():
 *
 *
 */
extern int pscsi_check_for_SG (iscsi_task_t *task)
{
	return(task->task_sg_num);
}

/*	pscsi_get_cdb():
 *
 *
 */
extern unsigned char *pscsi_get_cdb (iscsi_task_t *task)
{
#ifdef scsi_execute_async_address
	pscsi_plugin_task_t *pt = (pscsi_plugin_task_t *) task->transport_req;

	return(pt->pscsi_cdb);
#else
	Scsi_Request *req = (Scsi_Request *) task->transport_req;

	return(req->sr_cmnd);
#endif 
}

/*	pscsi_get_sense_buffer():
 *
 *
 */
extern unsigned char *pscsi_get_sense_buffer (iscsi_task_t *task)
{
#ifdef scsi_execute_async_address
	pscsi_plugin_task_t *pt = (pscsi_plugin_task_t *) task->transport_req;

	return((unsigned char *)&pt->pscsi_sense[0]);
#else
	Scsi_Request *req = (Scsi_Request *) task->transport_req;
	
	return((unsigned char *)&req->sr_sense_buffer[0]);
#endif
}

/*	pscsi_get_blocksize():
 *
 *
 */
extern u32 pscsi_get_blocksize (iscsi_device_t *dev)
{
	struct scsi_device *sd = (struct scsi_device *) dev->dev_ptr;

	return(sd->sector_size);
}

/*	pscsi_get_device_rev():
 *
 *
 */
extern u32 pscsi_get_device_rev (iscsi_device_t *dev)
{
	struct scsi_device *sd = (struct scsi_device *) dev->dev_ptr;
	
	return((sd->scsi_level - 1) ? sd->scsi_level - 1 : 1);
}

/*	pscsi_get_device_type():
 *
 *
 */
extern u32 pscsi_get_device_type (iscsi_device_t *dev)
{
	struct scsi_device *sd = (struct scsi_device *) dev->dev_ptr;

	return(sd->type);
}

/*	pscsi_get_dma_length():
 *
 *
 */
extern u32 pscsi_get_dma_length (u32 task_size, iscsi_device_t *dev)
{
	return(PAGE_SIZE);
}

/*	pscsi_get_max_sectors():
 *
 *
 */
extern u32 pscsi_get_max_sectors (iscsi_device_t *dev)
{
	struct scsi_device *sd = (struct scsi_device *) dev->dev_ptr;
	return((sd->host->max_sectors > sd->request_queue->max_sectors) ?
		sd->request_queue->max_sectors : sd->host->max_sectors);
}

/*	pscsi_get_queue_depth():
 *
 *
 */
extern u32 pscsi_get_queue_depth (iscsi_device_t *dev)
{
	struct scsi_device *sd = (struct scsi_device *) dev->dev_ptr;

	return(sd->queue_depth);
}

/*	pscsi_get_non_SG():
 *
 *
 */
extern unsigned char *pscsi_get_non_SG (iscsi_task_t *task)
{
#ifdef scsi_execute_async_address
	pscsi_plugin_task_t *pt = (pscsi_plugin_task_t *) task->transport_req;
	
	return((unsigned char *)pt->pscsi_buf);
#else
	Scsi_Request *req = (Scsi_Request *) task->transport_req;

	return((unsigned char *)req->sr_buffer);
#endif
}

/*	pscsi_get_SG():
 *
 * 
 */
extern struct scatterlist *pscsi_get_SG (iscsi_task_t *task)
{
#ifdef scsi_execute_async_address
	pscsi_plugin_task_t *pt = (pscsi_plugin_task_t *) task->transport_req;

	return((struct scatterlist *)pt->pscsi_buf);
#else
	Scsi_Request *req = (Scsi_Request *) task->transport_req;

	return((struct scatterlist *)req->sr_buffer);
#endif
}

/*	pscsi_get_SG_count():
 *
 *
 */
extern u32 pscsi_get_SG_count (iscsi_task_t *task)
{
	return(task->task_sg_num);
}

/*	pscsi_set_non_SG_buf(): (Part of iscsi_transport_t template)
 *
 *
 */
extern int pscsi_set_non_SG_buf (unsigned char *buf, iscsi_task_t *task)
{
#ifdef scsi_execute_async_address
	pscsi_plugin_task_t *pt = (pscsi_plugin_task_t *) task->transport_req;

	pt->pscsi_buf = (void *) buf;
#else
	Scsi_Request *req = (Scsi_Request *) task->transport_req;	

	req->sr_buffer = (void *) buf;
	req->sr_bufflen = task->task_size;
	req->sr_sglist_len = 0;
	req->sr_use_sg = 0;
#endif

	return(0);
}

extern void pscsi_shutdown_hba (iscsi_hba_t *hba)
{
	struct Scsi_Host *sh = (struct Scsi_Host *)hba->hba_ptr;

	if (strcmp(sh->hostt->name, INIT_CORE_NAME)) {
		/*
		 * Perhaps we could force a host-reset here if outstanding tasks
		 * have not come back..
		 */
		return;
	}
	
	if (!iscsi_global->ti_forcechanoffline)
		return;
	
	/*
	 * Notify the iSCSI Initiator to perform pause/forcechanoffline operations
	 */
	iscsi_global->ti_forcechanoffline(hba->hba_ptr);

	return;
}

/*	pscsi_handle_SAM_STATUS_failures():
 *
 *
 */
//#warning FIXME: We can do some custom handling of HBA fuckups here.
extern inline void pscsi_process_SAM_status (iscsi_task_t *task, unsigned char *cdb, int result)
{
	if ((task->task_scsi_status = status_byte(result))) {
		task->task_scsi_status <<= 1;
		PYXPRINT("Parallel SCSI Status Byte exception - ITT: 0x%08x Task: %p CDB: 0x%02x"
			" Result: 0x%08x\n", task->iscsi_cmd->init_task_tag, task, cdb[0], result);
	}

	switch (host_byte(result)) {
	case DID_OK:
		transport_complete_task(task, (!task->task_scsi_status));
		break;
	default:
		PYXPRINT("Parallel SCSI Host Byte exception - ITT: 0x%08x Task: %p CDB: 0x%02x"
			" Result: 0x%08x\n", task->iscsi_cmd->init_task_tag, task, cdb[0], result);
		task->task_scsi_status = SAM_STAT_CHECK_CONDITION;
		task->task_error_status = PYX_TRANSPORT_UNKNOWN_SAM_OPCODE;
		task->iscsi_cmd->transport_error_status = PYX_TRANSPORT_UNKNOWN_SAM_OPCODE;
		transport_complete_task(task, 0);
		break;
	}

	return;
}

#ifdef scsi_execute_async_address
extern void pscsi_req_done (void *data, char *sense, int result, int data_len)
{
	iscsi_task_t *task = (iscsi_task_t *)data;
	pscsi_plugin_task_t *pt = (pscsi_plugin_task_t *)task->transport_req;
#if 0
	printk("pscsi_req_done(): result: %08x, sense: %p data_len: %d\n",
			result, sense, data_len);
#endif	
	pt->pscsi_result = result;
	pt->pscsi_data_len = data_len;

	if (result != 0)
		memcpy(pt->pscsi_sense, sense, SCSI_SENSE_BUFFERSIZE);
	
	pscsi_process_SAM_status(task, &pt->pscsi_cdb[0], result);
	return;
}

#else

/*	pscsi_req_done():
 *
 *	This function is passed to scsi_do_req() in pscsi_do_task() and is
 *	called once scsi_do_req() completes.
 */
extern void pscsi_req_done (Scsi_Cmnd *sc_cmd)
{
	iscsi_task_t *task = NULL;
	Scsi_Request *req = sc_cmd->sc_request;

	task = (iscsi_task_t *)req->upper_private_data;

	scsi_put_command(sc_cmd);
	req->sr_command = NULL;

	pscsi_process_SAM_status(task, &req->sr_cmnd[0], req->sr_result);
	return;
}
#endif /* scsi_execute_async_address */
