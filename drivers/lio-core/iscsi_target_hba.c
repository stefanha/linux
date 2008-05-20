/*********************************************************************************
 * Filename:  iscsi_target_hba.c
 *
 * This file copntains the iSCSI HBA Transport related functions.
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


#define ISCSI_TARGET_HBA_C

#include <linux/net.h>
#include <linux/string.h>
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
#include <iscsi_target_ioctl.h>
#include <iscsi_target_ioctl_defs.h>
#include <iscsi_target_error.h>
#include <iscsi_target_device.h>
#include <iscsi_target_hba.h>
#include <iscsi_target_tpg.h>
#include <iscsi_target_transport.h>
#include <iscsi_target_util.h>

#include <iscsi_target_plugin.h>
#include <iscsi_target_seobj.h>

#undef ISCSI_TARGET_HBA_C

extern iscsi_global_t *iscsi_global;

/*	iscsi_hba_check_online():
 *
 *
 */
extern int iscsi_hba_check_online (
	iscsi_dev_transport_info_t *dti)
{
	int found_hba = 0, ret = 0;
	iscsi_hba_t *hba;
	iscsi_hbainfo_t hi;
	iscsi_transport_t *t;

	if (dti->hba_id < (ISCSI_MAX_GLOBAL_HBAS-1)) {
		TRACE_ERROR("Passed HBA ID: %d exceeds ISCSI_MAX_GLOBAL_HBAS-1: %d\n", 
			dti->hba_id, ISCSI_MAX_GLOBAL_HBAS-1);
		return(-1);
	}
	
	hba = &iscsi_global->hba_list[dti->hba_id];
		
	if (hba->hba_status != HBA_STATUS_ACTIVE)
		goto out;

	memset(&hi, 0, sizeof(iscsi_hbainfo_t));
	
	if (!(t = (iscsi_transport_t *)plugin_get_obj(PLUGIN_TYPE_TRANSPORT, hba->type, &ret)))
		return(ret);

	if (t->check_ghost_id(&hi))
		found_hba = 1;

out:
	return(found_hba);
}

extern iscsi_hba_t *iscsi_get_hba_from_ptr (void *p)
{
	iscsi_hba_t *hba;
	u32 i;
	
	spin_lock(&iscsi_global->hba_lock);	
	for (i = 0; i < ISCSI_MAX_GLOBAL_HBAS; i++) {
		hba = &iscsi_global->hba_list[i];
		
		if (hba->hba_status != HBA_STATUS_ACTIVE)	
			continue;
		
		if (!hba->hba_ptr)
			continue;

		if (hba->hba_ptr == p) {
			spin_unlock(&iscsi_global->hba_lock);

			down_interruptible(&hba->hba_access_sem);
			return((signal_pending(current)) ? NULL : hba);
		}
	}
	spin_unlock(&iscsi_global->hba_lock);

	return(NULL);
}
	
extern iscsi_hba_t *__core_get_hba_from_id (iscsi_hba_t *hba)
{
	down_interruptible(&hba->hba_access_sem);
	return((signal_pending(current)) ? NULL : hba);
}

extern iscsi_hba_t *core_get_hba_from_id (u32 hba_id, int addhba)
{
	iscsi_hba_t *hba;
	
	if (hba_id > (ISCSI_MAX_GLOBAL_HBAS-1)) {
		TRACE_ERROR("iSCSI HBA_ID: %u exceeds ISCSI_MAX_GLOBAL_HBAS-1: %u\n",
			hba_id, ISCSI_MAX_GLOBAL_HBAS-1);
		return(NULL);
	}

	hba = &iscsi_global->hba_list[hba_id];

	if (!addhba && !(hba->hba_status & HBA_STATUS_ACTIVE)) {
		TRACE_ERROR("iSCSI HBA ID: %d Status: !HBA_STATUS_ACTIVE,"
			" ignoring request\n", hba_id);
		return(NULL);
	}

	return(__core_get_hba_from_id(hba));
}

extern void core_put_hba (iscsi_hba_t *hba)
{
	up(&hba->hba_access_sem);
	return;
}

/*	iscsi_hba_check_addhba_params();
 *
 *
 */
extern int iscsi_hba_check_addhba_params (
	struct iscsi_target *tg,
	iscsi_hbainfo_t *hi)
{
	int ret = 0;
	iscsi_transport_t *t;

	if (!(tg->params_set & PARAM_HBA_ID)) {
		TRACE_ERROR("hba_id must be set for addhbatotarget\n");
		return(ERR_HBA_MISSING_PARAMS);
	}
	hi->hba_type = tg->hba_type;
	
	if (!(t = (iscsi_transport_t *)plugin_get_obj(PLUGIN_TYPE_TRANSPORT, tg->hba_type, &ret)))
		return(ret);

	if ((ret = t->check_hba_params(hi, tg, 0)) < 0)
		return(ret);
	
	return(0);
}

/*	iscsi_hba_add_hba():
 *
 *
 */
extern int iscsi_hba_add_hba (
	iscsi_hba_t *hba,
	iscsi_hbainfo_t *hi,
	struct iscsi_target *tg)
{
	int ret = 0;
	iscsi_transport_t *t;
	
	if (hba->hba_status & HBA_STATUS_ACTIVE)
                return(ERR_ADDTHBA_ALREADY_ACTIVE);

	atomic_set(&hba->max_queue_depth, 0);
	atomic_set(&hba->left_queue_depth, 0);
	hba->hba_info.hba_type = hi->hba_type;
	hba->hba_info.hba_id = hi->hba_id;
	
	if (!(t = (iscsi_transport_t *)plugin_get_obj(PLUGIN_TYPE_TRANSPORT, hi->hba_type, &ret)))
		return(ret);
	
	if ((ret = t->check_hba_params(&hba->hba_info, tg, 0)) < 0)
		return(ret);
	
	if (t->check_ghost_id(hi))
		return(-1);

	if (t->attach_hba(NULL, hba, hi) < 0)
		return(-1);
	
	hba->type = hi->hba_type;

	hba->hba_status &= ~HBA_STATUS_FREE;
	hba->hba_status |= HBA_STATUS_ACTIVE;

	PYXPRINT("iSCSI_HBA[%d] - Attached HBA to iSCSI Target Node\n", hba->hba_id);

	return(0);
}

static int iscsi_shutdown_hba (
	iscsi_hba_t *hba)
{
	int ret = 0;
	iscsi_transport_t *t;

	if (!(t = (iscsi_transport_t *)plugin_get_obj(PLUGIN_TYPE_TRANSPORT, hba->type, &ret)))
		return(ret);

	if (t->detach_hba(hba) < 0)
		return(ERR_SHUTDOWN_DETACH_HBA);

	return(0);
}

/*	iscsi_hba_del_hba():
 *
 *
 */
extern int iscsi_hba_del_hba (
	iscsi_hba_t *hba)
{
	iscsi_device_t *dev, *dev_next;
	
	if (!(hba->hba_status & HBA_STATUS_ACTIVE)) {
		TRACE_ERROR("HBA ID: %d Status: INACTIVE, ignoring delhbafromtarget"
			" request\n", hba->hba_id);
		return(ERR_DELHBA_NOT_ACTIVE);
	}

	/*
	 * Do not allow the iscsi_hba_t to be released if references exist to
	 * from iscsi_device_t->iscsi_lun_t or iscsi_device_t->raid_engine_t.
	 */
	if (iscsi_check_devices_access(hba) < 0) {
		TRACE_ERROR("iSCSI_HBA[%u] - **ERROR** - Unable to release HBA"
			" with active LUNs\n", hba->hba_id);
		return(ERR_DELHBA_SHUTDOWN_FAILED);
	}

	spin_lock(&hba->device_lock);
	dev = hba->device_head;
	while (dev) {
		dev_next = dev->next;

		se_clear_dev_ports(dev);
		spin_unlock(&hba->device_lock);
		
		se_release_device_for_hba(dev);

		spin_lock(&hba->device_lock);
		dev = dev_next;
	}
	spin_unlock(&hba->device_lock);

	iscsi_shutdown_hba(hba);
	
	hba->hba_status &= ~HBA_STATUS_ACTIVE;
	hba->hba_status |= HBA_STATUS_FREE;

	PYXPRINT("iSCSI_HBA[%d] - Detached HBA from iSCSI Target Node\n", hba->hba_id);

	return(0);
}

static void iscsi_hba_transport_shutdown (iscsi_hba_t *hba)
{
	if (!(HBA_TRANSPORT(hba)->shutdown_hba))
		return;

	HBA_TRANSPORT(hba)->shutdown_hba(hba);
	return;
}

extern void iscsi_disable_all_hbas (void)
{
	int i;
	iscsi_hba_t *hba;

	spin_lock(&iscsi_global->hba_lock);
	for (i = 0; i < ISCSI_MAX_GLOBAL_HBAS; i++) {
		hba = &iscsi_global->hba_list[i];

		if (!(hba->hba_status & HBA_STATUS_ACTIVE))
			continue;

		spin_unlock(&iscsi_global->hba_lock);
		iscsi_disable_devices_for_hba(hba);
		spin_lock(&iscsi_global->hba_lock);
	}
	spin_unlock(&iscsi_global->hba_lock);

	return;
}

/*	iscsi_hba_del_all_hbas():
 *
 *
 */
extern void iscsi_hba_del_all_hbas (void)
{
	int i;
	iscsi_hba_t *hba;

	spin_lock(&iscsi_global->hba_lock);
	for (i = 0; i < ISCSI_MAX_GLOBAL_HBAS; i++) {
		hba = &iscsi_global->hba_list[i];
	
		if (!(hba->hba_status & HBA_STATUS_ACTIVE))
			continue;
#if 0
		PYXPRINT("Shutting down HBA ID: %d, HBA_TYPE: %d, STATUS: 0x%08x\n",
			hba->hba_id, hba->type, hba->hba_status);
#endif		
		spin_unlock(&iscsi_global->hba_lock);
		iscsi_hba_transport_shutdown(hba);
		iscsi_hba_del_hba(hba);
		spin_lock(&iscsi_global->hba_lock);
	}
	spin_unlock(&iscsi_global->hba_lock);

	return;
}
