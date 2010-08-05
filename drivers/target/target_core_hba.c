/*******************************************************************************
 * Filename:  target_core_hba.c
 *
 * This file copntains the iSCSI HBA Transport related functions.
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

#include <linux/net.h>
#include <linux/string.h>
#include <linux/timer.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/smp_lock.h>
#include <linux/in.h>
#include <net/sock.h>
#include <net/tcp.h>

#include <target/target_core_base.h>
#include <target/target_core_device.h>
#include <target/target_core_device.h>
#include <target/target_core_tpg.h>
#include <target/target_core_transport.h>

#include "target_core_hba.h"

int core_get_hba(struct se_hba *hba)
{
	return ((mutex_lock_interruptible(&hba->hba_access_mutex) != 0) ?
		-1 : 0);
}

struct se_hba *core_alloc_hba(void)
{
	struct se_hba *hba;

	hba = kmem_cache_zalloc(se_hba_cache, GFP_KERNEL);
	if (!(hba)) {
		printk(KERN_ERR "Unable to allocate struct se_hba\n");
		return NULL;
	}

	hba->hba_status |= HBA_STATUS_FREE;
	INIT_LIST_HEAD(&hba->hba_dev_list);
	spin_lock_init(&hba->device_lock);
	spin_lock_init(&hba->hba_queue_lock);
	mutex_init(&hba->hba_access_mutex);
	hba->hba_index = scsi_get_new_index(SCSI_INST_INDEX);

	return hba;
}
EXPORT_SYMBOL(core_alloc_hba);

void core_put_hba(struct se_hba *hba)
{
	mutex_unlock(&hba->hba_access_mutex);
}
EXPORT_SYMBOL(core_put_hba);

/*	se_core_add_hba():
 *
 *
 */
int se_core_add_hba(
	struct se_hba *hba,
	const char *plugin_name,
	u32 plugin_dep_id)
{
	struct se_subsystem_api *t;
	int ret = 0;

	if (hba->hba_status & HBA_STATUS_ACTIVE)
		return -EEXIST;

	atomic_set(&hba->max_queue_depth, 0);
	atomic_set(&hba->left_queue_depth, 0);

	t = transport_core_get_sub_by_name(plugin_name);
	if (!(t))
		return -EINVAL;

	hba->transport = t;
	/*
	 * Get TCM subsystem api struct module reference to struct se_hba
	 */
	if (t->external_submod) {
		if (!(t->sub_owner)) {
			printk(KERN_ERR "Pointer to struct module does not"
				" exist for %s\n", t->name);
			hba->transport = NULL;
			transport_core_put_sub(t);
			return -EINVAL;
		}
		/*
		 * Grab a struct module reference count for subsystem plugin
		 */
		if (!(try_module_get(t->sub_owner))) {
			printk(KERN_ERR "try_module_get() failed for"
				" t->sub_owner\n");
			hba->transport = NULL;
			transport_core_put_sub(t);
			return -EINVAL;
		}
	}

	ret = t->attach_hba(hba, plugin_dep_id);
	if (ret < 0) {
		hba->transport = NULL;
		if (t->external_submod)
			module_put(t->sub_owner);
		transport_core_put_sub(t);
		return ret;
	}

	hba->hba_status &= ~HBA_STATUS_FREE;
	hba->hba_status |= HBA_STATUS_ACTIVE;

	spin_lock(&se_global->hba_lock);
	hba->hba_id = se_global->g_hba_id_counter++;
	list_add_tail(&hba->hba_list, &se_global->g_hba_list);
	spin_unlock(&se_global->hba_lock);

	printk(KERN_INFO "CORE_HBA[%d] - Attached HBA to Generic Target"
			" Core\n", hba->hba_id);

	return 0;
}
EXPORT_SYMBOL(se_core_add_hba);

static int se_core_shutdown_hba(
	struct se_hba *hba)
{
	struct se_subsystem_api *t = hba->transport;;

	if (t->detach_hba(hba) < 0)
		return -1;
	/*
	 * Release TCM subsystem api struct module reference from struct se_hba
	 */
	if (t->external_submod)
		module_put(t->sub_owner);

	return 0;
}

/*	se_core_del_hba():
 *
 *
 */
int se_core_del_hba(
	struct se_hba *hba)
{
	struct se_device *dev, *dev_tmp;

	if (!(hba->hba_status & HBA_STATUS_ACTIVE)) {
		printk(KERN_ERR "HBA ID: %d Status: INACTIVE, ignoring"
			" delhbafromtarget request\n", hba->hba_id);
		return -EINVAL;
	}

	spin_lock(&hba->device_lock);
	list_for_each_entry_safe(dev, dev_tmp, &hba->hba_dev_list, dev_list) {

		se_clear_dev_ports(dev);
		spin_unlock(&hba->device_lock);

		se_release_device_for_hba(dev);

		spin_lock(&hba->device_lock);
	}
	spin_unlock(&hba->device_lock);

	se_core_shutdown_hba(hba);
	if (!(hba->hba_flags & HBA_FLAGS_INTERNAL_USE))
		transport_core_put_sub(hba->transport);

	spin_lock(&se_global->hba_lock);
	list_del(&hba->hba_list);
	spin_unlock(&se_global->hba_lock);

	hba->transport = NULL;
	hba->hba_status &= ~HBA_STATUS_ACTIVE;
	hba->hba_status |= HBA_STATUS_FREE;

	printk(KERN_INFO "CORE_HBA[%d] - Detached HBA from Generic Target"
			" Core\n", hba->hba_id);

	kmem_cache_free(se_hba_cache, hba);
	return 0;
}
EXPORT_SYMBOL(se_core_del_hba);
