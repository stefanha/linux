/*******************************************************************************
 * Filename:  target_core_hba.c
 *
 * This file copntains the iSCSI HBA Transport related functions.
 *
 * Copyright (c) 2003, 2004, 2005 PyX Technologies, Inc.
 * Copyright (c) 2005, 2006, 2007 SBE, Inc.
 * Copyright (c) 2007-2010 Rising Tide Systems
 * Copyright (c) 2008-2010 Linux-iSCSI.org
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

struct se_hba *
core_alloc_hba(const char *plugin_name, u32 plugin_dep_id, u32 hba_flags)
{
	struct se_subsystem_api *t;
	struct se_hba *hba;
	int ret = 0;

	hba = kzalloc(sizeof(*hba), GFP_KERNEL);
	if (!hba) {
		printk(KERN_ERR "Unable to allocate struct se_hba\n");
		return ERR_PTR(-ENOMEM);
	}

	INIT_LIST_HEAD(&hba->hba_dev_list);
	spin_lock_init(&hba->device_lock);
	spin_lock_init(&hba->hba_queue_lock);
	mutex_init(&hba->hba_access_mutex);

	hba->hba_index = scsi_get_new_index(SCSI_INST_INDEX);
	hba->hba_flags |= hba_flags;

	atomic_set(&hba->max_queue_depth, 0);
	atomic_set(&hba->left_queue_depth, 0);

	t = transport_core_get_sub_by_name(plugin_name);
	if (!t) {
		ret = -EINVAL;
		goto out_free_hba;
	}

	hba->transport = t;

	/*
	 * Get TCM subsystem api struct module reference to struct se_hba
	 */
	if (t->owner) {
		/*
		 * Grab a struct module reference count for subsystem plugin
		 */
		if (!try_module_get(t->owner)) {
			printk(KERN_ERR "try_module_get() failed for %s\n",
				t->owner->name);
			ret = -EINVAL;
			goto out_put_subsystem;
		}
	}

	ret = t->attach_hba(hba, plugin_dep_id);
	if (ret < 0)
		goto out_module_put;

	spin_lock(&se_global->hba_lock);
	hba->hba_id = se_global->g_hba_id_counter++;
	list_add_tail(&hba->hba_list, &se_global->g_hba_list);
	spin_unlock(&se_global->hba_lock);

	printk(KERN_INFO "CORE_HBA[%d] - Attached HBA to Generic Target"
			" Core\n", hba->hba_id);

	return hba;

out_module_put:
	if (t->owner)
		module_put(t->owner);
out_put_subsystem:
	hba->transport = NULL;
	transport_core_put_sub(t);
out_free_hba:
	kfree(hba);
	return ERR_PTR(ret);
}

int
core_delete_hba(struct se_hba *hba)
{
	struct se_device *dev, *dev_tmp;

	spin_lock(&hba->device_lock);
	list_for_each_entry_safe(dev, dev_tmp, &hba->hba_dev_list, dev_list) {

		se_clear_dev_ports(dev);
		spin_unlock(&hba->device_lock);

		se_release_device_for_hba(dev);

		spin_lock(&hba->device_lock);
	}
	spin_unlock(&hba->device_lock);

	hba->transport->detach_hba(hba);
	if (hba->transport->owner)
		module_put(hba->transport->owner);

	if (!(hba->hba_flags & HBA_FLAGS_INTERNAL_USE))
		transport_core_put_sub(hba->transport);

	spin_lock(&se_global->hba_lock);
	list_del(&hba->hba_list);
	spin_unlock(&se_global->hba_lock);

	hba->transport = NULL;

	printk(KERN_INFO "CORE_HBA[%d] - Detached HBA from Generic Target"
			" Core\n", hba->hba_id);

	kfree(hba);
	return 0;
}
