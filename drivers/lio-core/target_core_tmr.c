/*******************************************************************************
 * Filename:  target_core_tmr.c
 *
 * This file contains SPC-3 task management infrastructure
 *
 * Copyright (c) 2009 Rising Tide, Inc.
 * Copyright (c) 2009 Linux-iSCSI.org
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

#define TARGET_CORE_TMR_C

#include <linux/version.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <scsi/scsi.h>
#include <scsi/scsi_cmnd.h>

#include <target_core_base.h>
#include <target_core_device.h>
#include <target_core_hba.h>
#include <target_core_tmr.h>
#include <target_core_transport.h>
#include <target_core_alua.h>
#include <target_core_transport_plugin.h>
#include <target_core_fabric_ops.h>
#include <target_core_configfs.h>

#undef TARGET_CORE_TMR_C

se_tmr_req_t *core_tmr_alloc_req(
	void *fabric_tmr_ptr,
	u8 function)
{
	se_tmr_req_t *tmr;

	tmr = kmem_cache_zalloc(se_tmr_req_cache, GFP_KERNEL);
	if (!(tmr)) {
		printk(KERN_ERR "Unable to allocate se_tmr_req_t\n");
		return ERR_PTR(-ENOMEM);
	}
	tmr->fabric_tmr_ptr = fabric_tmr_ptr;
	tmr->function = function;
	INIT_LIST_HEAD(&tmr->tmr_list);

	return tmr;
}
EXPORT_SYMBOL(core_tmr_alloc_req);

void core_tmr_release_req(
	se_tmr_req_t *tmr)
{
	se_lun_t *lun = tmr->tmr_lun;
	se_device_t *dev = lun->se_dev;

	spin_lock(&dev->se_tmr_lock);
	list_del(&tmr->tmr_list);
	spin_unlock(&dev->se_tmr_lock);

	kmem_cache_free(se_tmr_req_cache, tmr);
}

int core_tmr_lun_reset(se_device_t *dev, se_tmr_req_t *tmr)
{
	spin_lock(&dev->stats_lock);
	dev->num_resets++;
	spin_unlock(&dev->stats_lock);

	return -1;
}
