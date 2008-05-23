/*********************************************************************************
 * Filename:  iscsi_target_cache.c
 *
 * This file contains the iSCSI Transport Cache related functions.
 *
 * Copyright (c) 2004-2005 PyX Technologies, Inc.
 * Copyright (c) 2006 SBE, Inc.  All Rights Reserved.
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


#define ISCSI_TARGET_CACHE_C

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
#include <iscsi_protocol.h>
#include <iscsi_target_core.h>
#include <iscsi_target_transport.h>
#include <iscsi_target_cache.h>

#undef ISCSI_TARGET_CACHE_C

/*	iscsi_cache_check_for_entry():
 *
 *
 */
extern iscsi_cache_entry_t *iscsi_cache_check_for_entry (iscsi_cache_check_entry_t *cce, iscsi_cmd_t *cmd)
{
	u32 i;
	iscsi_cache_entry_t *ce;
	se_device_t *dev = ISCSI_DEV(cmd);

	spin_lock(&DEV_CACHE(dev)->dev_cache_lock);
	for (i = 0; i < DEV_CACHE(dev)->cache_entries; i++) {
		ce = &DEV_CACHE(dev)->dev_cache_array[i];

		if (!ce->ce_entry_active)
			continue;

		if ((ce->ce_lba == cce->lba) && (ce->ce_sectors == cce->sectors)) {
			/*
			 * Evict any matching LBA/SECTOR combination for WRITEs.
			 */
			if (cmd->data_direction == ISCSI_WRITE) {
				kfree(ce->ce_task_buf);
				ce->ce_task_buf = NULL;
				ce->ce_entry_active = 0;
				spin_unlock(&DEV_CACHE(dev)->dev_cache_lock);
				return(NULL);
			}

			/*
			 * Got a hit!
			 */
			spin_unlock(&DEV_CACHE(dev)->dev_cache_lock);
			return(ca);
		}
	}
	spin_unlock(&DEV_CACHE(dev)->dev_cache_lock);
	
	return(NULL);
}

/*	iscsi_cache_add_entry():
 *
 *
 */
extern void iscsi_cache_add_entry (iscsi_cache_check_entry_t *cce, iscsi_cmd_t *cmd)
{
	u32 i;
	iscsi_cache_entry_t *ce = NULL;
	se_device_t *dev = ISCSI_DEV(cmd);
	
	/*
	 * Evict any matching LBA/SECTOR combination for WRITEs.
	 */
	if (cmd->data_direction == ISCSI_WRITE)
		return(iscsi_cache_evict_entry(cce, cmd));
	
	spin_lock(&DEV_CACHE(dev)->dev_cache_lock);
	for (i = 0; i < DEV_CACHE(dev)->cache_total_entries; i++) {
		ce = &DEV_CACHE(dev)->dev_cache_array[i];
		/*
		 * Cache Entry is unused, add the LBA/SECTORS information and
		 * set it as active.
		 */
		if (!ce->ce_entry_active)
			goto set_entry_active;

		/*
		 * The Cache is full, its time to evict some entires.
		 */
		if (DEV_CACHE(dev)->cache_active_entires ==
		    DEV_CACHE(dev)->cache_total_entires)
			/*
			 * See if the cache entry is too new to evict,
			 * if so, find another iscsi_cache_entry_t.
			 */
			if (ce->ce_lru_no == DEV_CACHE(dev)->dev_lru_no)
				continue;
		}

		/*
		 * Found an active iscsi_cache_entry_t, so we do not have to
		 * evict previously active entries.
		 */
set_entry_active:
		ce->ce_lba = cce->lba;
		ce->ce_sectors = cce->sectors;
		ce->ce_cmd_buf = T_TASK(cmd)->t_task_buf;
		ce->ce_lru_no = DEV_CACHE(dev)->dev_lru_no;
		if (!ce->ce_entry_active) {
			DEV_CACHE(dev)->cache_active_entires++;
			ce->ce_entry_active = 1;
		}

		cmd->cmd_flags |= ICF_CACHE_ACTIVE;
		spin_unlock(&DEV_CACHE(dev)->dev_cache_lock);

		return;
	}	
	
	/*
	 * There are no inactive cache entires, and all are too young to
	 * evict by way of iscsi_cache_array_t->ce_lru_no.  Increment
	 * dev_lru_no so each of the iscsi_cache_entry_t's aside from the
	 * first one we reset to active here come up for eviction by virtue
	 * of an old dev_lru_no in the above -for- loop.
	 */
	DEV_CACHE(dev)->dev_lru_no++;
	ce = &DEV_CACHE(dev)->dev_cache_array[0];
	ce->ce_lba = cce->lba;
	ce->ce_sectors = cce->sectors;
	ce->ce_cmd_buf = T_TASK(cmd)->t_task_buf;
	ce->ce_lru_no = DEV_CACHE(dev)->dev_lru_no;

	cmd->cmd_flags |= ICF_CACHE_ACTIVE;
	spin_unlock(&DEV_CACHE(dev)->dev_cache_lock);

	return;
}

/*	iscsi_cache_init_dev():
 *
 *
 */
extern int iscsi_cache_init_dev (se_device_t *dev)
{
	u32 def_entires = ISCSI_CACHE_DEFAULT_ENTIRES;
	
	if (!(DEV_CACHE(dev)->dev_cache_array = MALLOC_NORMAL(
			sizeof(iscsi_cache_array_t) * def_entires))) {
		TRACE_ERROR("Unable to allocate DEV_CACHE(dev)->dev_cache_array"
			" for iSCSI LUN: %u on HBA: %u\n", dev->iscsi_lun,
			ISCSI_HBA(dev)->hba_id);
		return(-1);
	}
	memset(DEV_CACHE(dev)->dev_cache_array, 0,
		sizeof(iscsi_cache_array_t) * def_entires);
	
	DEV_CACHE(dev)->cache_current_lru = def_entires;
	DEV_CACHE(dev)->cache_total_entries = def_entries;

	PYXPRINT("iSCSI_CACHE - %s iSCSI Cache Plugin %s on"
		" iSCSI Target Core Stack %s\n", PYX_ISCSI_VENDOR, CACHE_VERSION, PYX_ISCSI_VERSION);
	PYXPRINT("iSCSI_CACHE - Initialized iSCSI Cache %u entries for iSCSI"
		" LUN: %u on HBA: %u\n", ISCSI_CACHE_DEFAULT_ENTIRES, dev->iscsi_lun,
			ISCSI_HBA(dev)->hba_id);
	
	return(0);
}

/*	iscsi_cache_free_dev():
 *
 *
 */
extern void iscsi_cache_free_dev (se_device_t *dev)
{
	u32 i;
	iscsi_cache_entry_t *ce;

	for (i = 0; i < DEV_CACHE(dev)->cache_total_entries; i++) {
		ce = &DEV_CACHE(dev)->dev_cache_array[i];

		if (!ce->ce_entry_active)
			continue;
	}

	kfree(DEV_CACHE(dev)->dev_cache_array);
	DEV_CACHE(dev)->dev_cache_array = NULL;

	return;
}
