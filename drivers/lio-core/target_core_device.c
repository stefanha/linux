/*********************************************************************************
 * Filename:  target_core_device.c (based on iscsi_target_device.c)
 *
 * This file contains the iSCSI Virtual Device and Disk Transport
 * agnostic related functions.
 *
 * Copyright (c) 2003, 2004, 2005 PyX Technologies, Inc.
 * Copyright (c) 2005-2006 SBE, Inc.  All Rights Reserved.
 * Copyright (c) 2007 Rising Tide Software, Inc.
 * Copyright (c) 2008 Linux-iSCSI.org
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


#define TARGET_CORE_DEVICE_C

#include <linux/net.h>
#include <linux/string.h>
#include <linux/delay.h>
#include <linux/timer.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/smp_lock.h>
#include <linux/in.h>
#include <net/sock.h>
#include <net/tcp.h>

#include <iscsi_linux_os.h>
#include <iscsi_linux_defs.h>

#include <iscsi_lists.h>
#include <iscsi_debug.h>
#include <iscsi_protocol.h>
#include <iscsi_target_core.h>
#include <iscsi_target_error.h>
#include <iscsi_target_ioctl.h> 
#include <iscsi_target_ioctl_defs.h>
#include <target_core_device.h>
#include <iscsi_target_device.h>
#include <target_core_hba.h>
#include <iscsi_target_tpg.h>
#include <target_core_transport.h>
#include <iscsi_target_util.h>

#include <target_core_plugin.h>
#include <target_core_seobj.h>
#include <target_core_feature_obj.h>

#undef TARGET_CORE_DEVICE_C

extern se_global_t *se_global;
extern __u32 iscsi_unpack_lun (unsigned char *);

extern struct block_device *__linux_blockdevice_claim (int major, int minor, void *claim_ptr, int *ret)
{
	dev_t dev;
	struct block_device *bd;

	dev = MKDEV(major, minor);

	if (!(bd = bdget(dev))) {
		*ret = -1;
		return(NULL);
	}

	if (blkdev_get(bd, FMODE_WRITE, O_RDWR) < 0) {
		*ret = -1;
		return(NULL);
	}
	/*
	 * If no claim pointer was passed from claimee, use struct block_device.
	 */
	if (!claim_ptr)
		claim_ptr = (void *)bd;

	if (bd_claim(bd, claim_ptr) < 0) {
#if 0
		PYXPRINT("Using previously claimed Major:Minor - %d:%d\n",
				major, minor);
#endif
		*ret = 0;
		return(bd);
	}

	*ret = 1;
	return(bd);
}

extern struct block_device *linux_blockdevice_claim (int major, int minor, void *claim_ptr)
{
	dev_t dev;
	struct block_device *bd;

	dev = MKDEV(major, minor);

	if (!(bd = bdget(dev)))
		return(NULL);

	if (blkdev_get(bd, FMODE_WRITE, O_RDWR) < 0)
		return(NULL);
	/*
	 * If no claim pointer was passed from claimee, use struct block_device.
	 */
	if (!claim_ptr)
		claim_ptr = (void *)bd;

	if (bd_claim(bd, claim_ptr) < 0) {
		blkdev_put(bd);
		return(NULL);
	}
	
	return(bd);
}

extern int linux_blockdevice_release (int major, int minor, struct block_device *bd_p)
{
	dev_t dev;
	struct block_device *bd;

	if (!bd_p) {
		dev = MKDEV(major, minor);

		if (!(bd = bdget(dev)))
			return(-1);
	} else
		bd = bd_p;

	bd_release(bd);
	blkdev_put(bd);

	return(0);
}

extern int linux_blockdevice_check (int major, int minor)
{
	struct block_device *bd;

	if (!(bd = linux_blockdevice_claim(major, minor, NULL)))
		return(-1);
	/*
	 * Blockdevice was able to be claimed, now unclaim it and return success.
	 */
	linux_blockdevice_release(major, minor, NULL);

	return(0);
}

EXPORT_SYMBOL(linux_blockdevice_check);

extern int iscsi_check_devices_access (se_hba_t *hba)
{
	int ret = 0;
	se_device_t *dev = NULL, *dev_next = NULL;

	spin_lock(&hba->device_lock);
	dev = hba->device_head;
	while (dev) {
		dev_next = dev->next;

		if (DEV_OBJ_API(dev)->check_count(&dev->dev_feature_obj) != 0) {
			TRACE_ERROR("check_count(&dev->dev_feature_obj): %u\n",
				DEV_OBJ_API(dev)->check_count(&dev->dev_feature_obj));
			ret = -1;
		}

		dev = dev_next;
	}
	spin_unlock(&hba->device_lock);

	return(ret);		
}

/*	iscsi_disable_devices_for_hba():
 *
 *
 */
extern void iscsi_disable_devices_for_hba (se_hba_t *hba)
{
	se_device_t *dev, *dev_next;

	spin_lock(&hba->device_lock);
	dev = hba->device_head;
	while (dev) {
		dev_next = dev->next;
		
		spin_lock(&dev->dev_status_lock);
		if ((dev->dev_status & ISCSI_DEVICE_ACTIVATED) ||
		    (dev->dev_status & ISCSI_DEVICE_DEACTIVATED) ||
		    (dev->dev_status & ISCSI_DEVICE_OFFLINE_ACTIVATED) ||
		    (dev->dev_status & ISCSI_DEVICE_OFFLINE_DEACTIVATED)) {
			dev->dev_status |= ISCSI_DEVICE_SHUTDOWN;
			dev->dev_status &= ~ISCSI_DEVICE_ACTIVATED;
			dev->dev_status &= ~ISCSI_DEVICE_DEACTIVATED;
			dev->dev_status &= ~ISCSI_DEVICE_OFFLINE_ACTIVATED;
			dev->dev_status &= ~ISCSI_DEVICE_OFFLINE_DEACTIVATED;

			up(&dev->dev_queue_obj->thread_sem);
		}
		spin_unlock(&dev->dev_status_lock);

		dev = dev_next;
	}
	spin_unlock(&hba->device_lock);

	return;
}

/*	se_release_device_for_hba():
 *
 *
 */
extern void se_release_device_for_hba (se_device_t *dev)
{
	se_hba_t *hba = dev->iscsi_hba;

	if ((dev->dev_status & ISCSI_DEVICE_ACTIVATED) ||
	    (dev->dev_status & ISCSI_DEVICE_DEACTIVATED) ||
	    (dev->dev_status & ISCSI_DEVICE_SHUTDOWN) ||
	    (dev->dev_status & ISCSI_DEVICE_OFFLINE_ACTIVATED) ||
	    (dev->dev_status & ISCSI_DEVICE_OFFLINE_DEACTIVATED))
		se_dev_stop(dev);

	transport_generic_free_device(dev);

	spin_lock(&hba->device_lock);
	REMOVE_ENTRY_FROM_LIST(dev, hba->device_head, hba->device_tail);
	hba->dev_count--;
	spin_unlock(&hba->device_lock);
		
	kfree(dev->dev_status_queue_obj);
	kfree(dev->dev_queue_obj);
	kfree(dev);

	return;
}

/*	core_get_device_from_transport():
 *
 *
 */
extern se_device_t *core_get_device_from_transport (se_hba_t *hba, se_dev_transport_info_t *dti)
{
	se_device_t *dev;
	
	spin_lock(&hba->device_lock);
	for (dev = hba->device_head; dev; dev = dev->next) {
		spin_unlock(&hba->device_lock);
		if (!transport_generic_check_device_location(dev, dti))
			return(dev);
		spin_lock(&hba->device_lock);
	}
	spin_unlock(&hba->device_lock);
		
	return(NULL);
}

/*
 * Called with se_hba_t->device_lock held.
 */
extern void se_clear_dev_ports (se_device_t *dev)
{
	se_hba_t *hba = dev->iscsi_hba;	
	se_lun_t *lun;
	iscsi_portal_group_t *tpg;
	se_port_t *sep, *sep_tmp;

	spin_lock(&dev->se_port_lock);
	list_for_each_entry_safe(sep, sep_tmp, &dev->dev_sep_list, sep_list) {
		spin_unlock(&dev->se_port_lock);
		spin_unlock(&hba->device_lock);

		lun = sep->sep_lun;
		tpg = sep->sep_tpg;
		spin_lock(&lun->lun_sep_lock);
		if (lun->lun_type_ptr == NULL) {
			spin_unlock(&lun->lun_sep_lock);
			continue;
		}
		spin_unlock(&lun->lun_sep_lock);

		LUN_OBJ_API(lun)->del_obj_from_lun(tpg, lun);
		
		spin_lock(&hba->device_lock);
		spin_lock(&dev->se_port_lock);
	}
	spin_unlock(&dev->se_port_lock);

	return;
}

/*	se_free_virtual_device():
 *
 *	Used for IBLOCK, RAMDISK, and FILEIO Transport Drivers.
 */
extern int se_free_virtual_device (se_device_t *dev, se_hba_t *hba)
{
	spin_lock(&hba->device_lock);
	se_clear_dev_ports(dev);
	spin_unlock(&hba->device_lock);

	se_release_device_for_hba(dev);
	
	return(0);
}

EXPORT_SYMBOL(se_free_virtual_device);

extern se_hba_t *core_get_hba_from_hbaid (
	struct iscsi_target *tg,
	se_dev_transport_info_t *dti,
	int add)
{
	int ret = 0;
	se_hba_t *hba;
	se_subsystem_api_t *t;
	
	if (!(tg->params_set & PARAM_HBA_ID)) {
		TRACE_ERROR("PARAM_HBA_ID not passed!\n");
		return(NULL);
	}
	
	if (dti->hba_id > (ISCSI_MAX_GLOBAL_HBAS-1)) {
		 TRACE_ERROR("Passed HBA ID: %d exceeds ISCSI_MAX_GLOBAL_HBAS-1: %d\n",
			dti->hba_id, ISCSI_MAX_GLOBAL_HBAS-1);
		 return(NULL);
	}
	hba = &se_global->hba_list[dti->hba_id];

	if (!(hba->hba_status & HBA_STATUS_ACTIVE)) {
		TRACE_ERROR("iSCSI HBA ID: %d Status: [HBA,TPG_HBA]_NOT_ACTIVE,"
			" ignoring request\n", dti->hba_id);
		return(NULL);
	}
	
	if (!add)
		return(hba);
	
        t = (se_subsystem_api_t *)plugin_get_obj(PLUGIN_TYPE_TRANSPORT, hba->type, &ret);
	if (!t || (ret != 0))
                return(NULL);

	if ((ret = t->check_dev_params(hba, tg, dti)) < 0)
		return(NULL);
	
	return(hba);
}

extern void se_dev_start (se_device_t *dev)
{
	se_hba_t *hba = dev->iscsi_hba;
	
        spin_lock(&hba->device_lock);
	DEV_OBJ_API(dev)->inc_count(&dev->dev_obj);
        if (DEV_OBJ_API(dev)->check_count(&dev->dev_obj) == 1) {
		if (dev->dev_status & ISCSI_DEVICE_DEACTIVATED) {
			dev->dev_status &= ~ISCSI_DEVICE_DEACTIVATED;
			dev->dev_status |= ISCSI_DEVICE_ACTIVATED;
		} else if (dev->dev_status & ISCSI_DEVICE_OFFLINE_DEACTIVATED) {
			dev->dev_status &= ~ISCSI_DEVICE_OFFLINE_DEACTIVATED;
			dev->dev_status |= ISCSI_DEVICE_OFFLINE_ACTIVATED;	
		}
	}
        spin_unlock(&hba->device_lock);

	return;
}

extern void se_dev_stop (se_device_t *dev)
{
	se_hba_t *hba = dev->iscsi_hba;

	spin_lock(&hba->device_lock);
	DEV_OBJ_API(dev)->dec_count(&dev->dev_obj);
        if (DEV_OBJ_API(dev)->check_count(&dev->dev_obj) == 0) {
		if (dev->dev_status & ISCSI_DEVICE_ACTIVATED) {
			dev->dev_status &= ~ISCSI_DEVICE_ACTIVATED;
			dev->dev_status |= ISCSI_DEVICE_DEACTIVATED;
		} else if (dev->dev_status & ISCSI_DEVICE_OFFLINE_ACTIVATED) {
			dev->dev_status &= ~ISCSI_DEVICE_OFFLINE_ACTIVATED;
			dev->dev_status |= ISCSI_DEVICE_OFFLINE_DEACTIVATED;
		}
	}
	spin_unlock(&hba->device_lock);

	while (atomic_read(&hba->dev_mib_access_count)) 
		msleep(10);

	return;
}

extern void se_dev_set_default_attribs (se_device_t *dev)
{
	DEV_ATTRIB(dev)->da_status_thread = DA_STATUS_THREAD;
	DEV_ATTRIB(dev)->da_status_thread_tur = DA_STATUS_THREAD_TUR;
	/*
	 * max_sectors is based on subsystem plugin dependent requirements.
	 */
	DEV_ATTRIB(dev)->da_max_sectors = TRANSPORT(dev)->get_max_sectors(dev);
	/*
	 * queue_depth is based on subsystem plugin dependent requirements.
	 */
	DEV_ATTRIB(dev)->da_queue_depth = TRANSPORT(dev)->get_queue_depth(dev);
	/*
	 * task_timeout is based on device type.
	 */
	DEV_ATTRIB(dev)->da_task_timeout = transport_get_default_task_timeout(dev);

	return;
}

static int se_dev_set_task_timeout (se_device_t *dev, u32 task_timeout)
{
	if (task_timeout > DA_TASK_TIMEOUT_MAX) {
		TRACE_ERROR("dev[%p]: Passed task_timeout: %u larger then"
			" DA_TASK_TIMEOUT_MAX\n", dev, task_timeout);
		return(-1);
	} else {
		DEV_ATTRIB(dev)->da_task_timeout = task_timeout;
		PYXPRINT("dev[%p]: Set SE Device task_timeout: %u\n", dev, task_timeout);
	}

	return(0);
}

static int se_dev_set_status_thread (se_device_t *dev, int flag)
{
	if ((flag != 0) && (flag != 1)) {
	 	TRACE_ERROR("Illegal value %d\n", flag);
		return(-1);		
	}

	if (!flag) {
		if (DEV_ATTRIB(dev)->da_status_thread) {
			if (DEV_OBJ_API(dev)->check_count(&dev->dev_export_obj)) {
				TRACE_ERROR("dev[%p]: Unable to stop SE Device Status"
					" Thread while dev_export_obj: %d count exists\n",
					dev, DEV_OBJ_API(dev)->check_count(&dev->dev_export_obj));
				return(-1);
			}
			if (!(dev->dev_flags & DF_DISABLE_STATUS_THREAD))
	        	        DEV_OBJ_API(dev)->stop_status_thread((void *)dev);
		}
	} else {
		if (!(DEV_ATTRIB(dev)->da_status_thread))
			DEV_OBJ_API(dev)->start_status_thread((void *)dev, 1);
	}

	DEV_ATTRIB(dev)->da_status_thread = flag;
	PYXPRINT("dev[%p]: SE Device Status Thread: %s\n", dev, (flag) ?
			"Enabled" : "Disabled");
	return(0);
}

static int se_dev_set_status_thread_tur (se_device_t *dev, int flag)
{
	int start = 0;

	if ((flag != 0) && (flag != 1)) {
		TRACE_ERROR("Illegal value %d\n", flag);
		return(-1);
	}

	if (flag && !(DEV_ATTRIB(dev)->da_status_thread_tur))
		start = 1;

	DEV_ATTRIB(dev)->da_status_thread_tur = flag;
	if (start)
		transport_start_status_timer(dev);
	PYXPRINT("dev[%p]: SE Device Status Thread TUR: %s\n", dev, (flag) ?
			"Enabled" : "Disabled");
	return(0);
}

/*
 * Note, this can only be called on unexported SE Device Object.
 */
static int se_dev_set_queue_depth (se_device_t *dev, u32 queue_depth)
{
	u32 orig_queue_depth = dev->queue_depth;

	if (DEV_OBJ_API(dev)->check_count(&dev->dev_export_obj)) {
		TRACE_ERROR("dev[%p]: Unable to change SE Device TCQ while"
			" dev_export_obj: %d count exists\n", dev,
			DEV_OBJ_API(dev)->check_count(&dev->dev_export_obj));
		return(-1);
	}
	if (!(queue_depth)) {
		TRACE_ERROR("dev[%p]: Illegal ZERO value for queue_depth\n", dev);
		return(-1);
	}
	if (queue_depth > TRANSPORT(dev)->get_queue_depth(dev)) {
		TRACE_ERROR("dev[%p]: Passed queue_depth: %u exceeds"
			" LIO-Core/SE_Device TCQ: %u\n", dev, queue_depth,
			TRANSPORT(dev)->get_queue_depth(dev));
		return(-1);
	}
		
	DEV_ATTRIB(dev)->da_queue_depth = dev->queue_depth = queue_depth;
	if (queue_depth > orig_queue_depth)
		atomic_add(queue_depth - orig_queue_depth, &dev->depth_left);	
	else if (queue_depth < orig_queue_depth)
		atomic_sub(orig_queue_depth - queue_depth, &dev->depth_left);

	PYXPRINT("dev[%p]: SE Device TCQ Depth changed to: %u\n", dev, queue_depth);
	return(0);
}

static int se_dev_set_max_sectors (se_device_t *dev, u32 max_sectors, int force)
{
	if (DEV_OBJ_API(dev)->check_count(&dev->dev_export_obj)) {
		TRACE_ERROR("dev[%p]: Unable to change SE Device max_sectors"
			" while dev_export_obj: %d count exists\n", dev,
			DEV_OBJ_API(dev)->check_count(&dev->dev_export_obj));
		return(-1);
	}
	if (!(max_sectors)) {
		TRACE_ERROR("dev[%p]: Illegal ZERO value for max_sectors\n", dev);
		return(-1);
	}
	if (max_sectors < DA_STATUS_MAX_SECTORS_MIN) {
		TRACE_ERROR("dev[%p]: Passed max_sectors: %u less than"
			" DA_STATUS_MAX_SECTORS_MIN: %u\n", dev, max_sectors,
				DA_STATUS_MAX_SECTORS_MIN);
		return(-1);
	}
	if (TRANSPORT(dev)->transport_type == TRANSPORT_PLUGIN_PHBA_PDEV) {
		if (max_sectors > TRANSPORT(dev)->get_max_sectors(dev)) {
			 TRACE_ERROR("dev[%p]: Passed max_sectors: %u greater than"
				" LIO-Core/SE_Device max_sectors: %u\n", dev,
				max_sectors, TRANSPORT(dev)->get_max_sectors(dev));
			 return(-1);
		}
	} else {
		if (!(force) && (max_sectors > TRANSPORT(dev)->get_max_sectors(dev))) {
			TRACE_ERROR("dev[%p]: Passed max_sectors: %u greater than"
				" LIO-Core/SE_Device max_sectors: %u, use force=1 to override.\n",
				dev, max_sectors, TRANSPORT(dev)->get_max_sectors(dev));
			return(-1);
		}
		if (max_sectors > DA_STATUS_MAX_SECTORS_MAX) {
			TRACE_ERROR("dev[%p]: Passed max_sectors: %u greater than"
				" DA_STATUS_MAX_SECTORS_MAX: %u\n", dev,
				max_sectors, DA_STATUS_MAX_SECTORS_MAX);
			return(-1);
		}
	}

	DEV_ATTRIB(dev)->da_max_sectors = max_sectors;
	PYXPRINT("dev[%p]: SE Device max_sectors changed to %u\n",
			dev, max_sectors);
	return(0);
}

extern int se_dev_set_attrib (
	se_device_t *dev,
	u32 da_attrib,
	u32 da_attrib_value,
	int force)
{
	switch (da_attrib) {
	case DA_SET_TASK_TIMEOUT:
		return(se_dev_set_task_timeout(dev, da_attrib_value));
	case DA_SET_STATUS_THREAD:
		return(se_dev_set_status_thread(dev, da_attrib_value));
	case DA_SET_STATUS_THREAD_TUR:
		return(se_dev_set_status_thread_tur(dev, da_attrib_value));
	case DA_SET_QUEUE_DEPTH:
		return(se_dev_set_queue_depth(dev, da_attrib_value));
	case DA_SET_MAX_SECTORS:
		return(se_dev_set_max_sectors(dev, da_attrib_value, force));
	default:
		TRACE_ERROR("Unknown SE Device Attribute: %u, ignoring"
			" request\n", da_attrib);
		return(-1);
	}

	return(0);
}

EXPORT_SYMBOL(se_dev_set_attrib);
