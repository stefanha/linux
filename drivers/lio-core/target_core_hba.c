/*******************************************************************************
 * Filename:  target_core_hba.c
 *
 * This file copntains the iSCSI HBA Transport related functions.
 *
 * Copyright (c) 2003, 2004, 2005 PyX Technologies, Inc.
 * Copyright (c) 2005, 2006, 2007 SBE, Inc.
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
 ******************************************************************************/


#define TARGET_CORE_HBA_C

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

#include <target_core_base.h>
#include <iscsi_target_error.h>
#include <target_core_device.h>
#include <target_core_device.h>
#include <target_core_hba.h>
#include <target_core_tpg.h>
#include <target_core_transport.h>

#include <target_core_plugin.h>
#include <target_core_seobj.h>

#undef TARGET_CORE_HBA_C

se_hba_t *__core_get_hba_from_id(se_hba_t *hba)
{
	down_interruptible(&hba->hba_access_sem);
	return (signal_pending(current)) ? NULL : hba;
}

se_hba_t *core_get_hba_from_id(u32 hba_id, int addhba)
{
	se_hba_t *hba;

	if (hba_id > (TRANSPORT_MAX_GLOBAL_HBAS-1)) {
		printk(KERN_ERR "SE HBA_ID: %u exceeds TRANSPORT_MAX_GLOBAL"
			"_HBAS-1: %u\n", hba_id, TRANSPORT_MAX_GLOBAL_HBAS-1);
		return NULL;
	}

	hba = &se_global->hba_list[hba_id];

	if (!addhba && !(hba->hba_status & HBA_STATUS_ACTIVE))
		return NULL;

	return __core_get_hba_from_id(hba);
}
EXPORT_SYMBOL(core_get_hba_from_id);

se_hba_t *core_get_next_free_hba(void)
{
	se_hba_t *hba;
	u32 i;

	spin_lock(&se_global->hba_lock);
	for (i = 0; i < TRANSPORT_MAX_GLOBAL_HBAS; i++) {
		hba = &se_global->hba_list[i];
		if (hba->hba_status != HBA_STATUS_FREE)
			continue;

		spin_unlock(&se_global->hba_lock);
		return __core_get_hba_from_id(hba);
	}
	spin_unlock(&se_global->hba_lock);

	printk(KERN_ERR "Unable to locate next free HBA\n");
	return NULL;
}

void core_put_hba(se_hba_t *hba)
{
	up(&hba->hba_access_sem);
}
EXPORT_SYMBOL(core_put_hba);

/*	se_core_add_hba():
 *
 *
 */
int se_core_add_hba(
	se_hba_t *hba,
	u32 plugin_dep_id)
{
	se_subsystem_api_t *t;
	int ret = 0;

	if (hba->hba_status & HBA_STATUS_ACTIVE)
		return -EEXIST;

	atomic_set(&hba->max_queue_depth, 0);
	atomic_set(&hba->left_queue_depth, 0);

	t = (se_subsystem_api_t *)plugin_get_obj(PLUGIN_TYPE_TRANSPORT,
				hba->type, &ret);
	if (!(t))
		return -EINVAL;

	ret = t->attach_hba(hba, plugin_dep_id);
	if (ret < 0)
		return ret;

	hba->hba_status &= ~HBA_STATUS_FREE;
	hba->hba_status |= HBA_STATUS_ACTIVE;
	printk(KERN_INFO "CORE_HBA[%d] - Attached HBA to Generic Target"
			" Core\n", hba->hba_id);

	return 0;
}
EXPORT_SYMBOL(se_core_add_hba);

static int se_core_shutdown_hba(
	se_hba_t *hba)
{
	int ret = 0;
	se_subsystem_api_t *t;

	t = (se_subsystem_api_t *)plugin_get_obj(PLUGIN_TYPE_TRANSPORT,
				hba->type, &ret);
	if (!(t))
		return ret;

	if (t->detach_hba(hba) < 0)
		return ERR_SHUTDOWN_DETACH_HBA;

	return 0;
}

/*	se_core_del_hba():
 *
 *
 */
int se_core_del_hba(
	se_hba_t *hba)
{
	se_device_t *dev, *dev_next;

	if (!(hba->hba_status & HBA_STATUS_ACTIVE)) {
		printk(KERN_ERR "HBA ID: %d Status: INACTIVE, ignoring"
			" delhbafromtarget request\n", hba->hba_id);
		return -EINVAL;
	}

	/*
	 * Do not allow the se_hba_t to be released if references exist to
	 * from se_device_t->se_lun_t.
	 */
	if (se_check_devices_access(hba) < 0) {
		printk(KERN_ERR "CORE_HBA[%u] - **ERROR** - Unable to release"
			" HBA with active LUNs\n", hba->hba_id);
		return -EINVAL;
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

	se_core_shutdown_hba(hba);

	hba->type = 0;
	hba->transport = NULL;
	hba->hba_status &= ~HBA_STATUS_ACTIVE;
	hba->hba_status |= HBA_STATUS_FREE;

	printk(KERN_INFO "CORE_HBA[%d] - Detached HBA from Generic Target"
			" Core\n", hba->hba_id);
	return 0;
}
EXPORT_SYMBOL(se_core_del_hba);

static void se_hba_transport_shutdown(se_hba_t *hba)
{
	if (!(HBA_TRANSPORT(hba)->shutdown_hba))
		return;

	HBA_TRANSPORT(hba)->shutdown_hba(hba);
}

void iscsi_disable_all_hbas(void)
{
	int i;
	se_hba_t *hba;

	spin_lock(&se_global->hba_lock);
	for (i = 0; i < TRANSPORT_MAX_GLOBAL_HBAS; i++) {
		hba = &se_global->hba_list[i];

		if (!(hba->hba_status & HBA_STATUS_ACTIVE))
			continue;

		spin_unlock(&se_global->hba_lock);
		se_disable_devices_for_hba(hba);
		spin_lock(&se_global->hba_lock);
	}
	spin_unlock(&se_global->hba_lock);
}
EXPORT_SYMBOL(iscsi_disable_all_hbas);

/*	iscsi_hba_del_all_hbas():
 *
 *
 */
void iscsi_hba_del_all_hbas(void)
{
	int i;
	se_hba_t *hba;

	spin_lock(&se_global->hba_lock);
	for (i = 0; i < TRANSPORT_MAX_GLOBAL_HBAS; i++) {
		hba = &se_global->hba_list[i];

		if (!(hba->hba_status & HBA_STATUS_ACTIVE))
			continue;
#if 0
		printk(KERN_INFO "Shutting down HBA ID: %d, HBA_TYPE: %d,"
			" STATUS: 0x%08x\n", hba->hba_id, hba->type,
			hba->hba_status);
#endif
		spin_unlock(&se_global->hba_lock);
		se_hba_transport_shutdown(hba);
		se_core_del_hba(hba);
		spin_lock(&se_global->hba_lock);
	}
	spin_unlock(&se_global->hba_lock);
}
EXPORT_SYMBOL(iscsi_hba_del_all_hbas);
