/*******************************************************************************
 * Filename:  target_core_alua.c
 *
 * This file contains SPC-3 compliant asymmetric logical unit assigntment (ALUA)
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

#define TARGET_CORE_ALUA_C

#include <linux/version.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <scsi/scsi.h>
#include <scsi/scsi_cmnd.h>

#include <target/target_core_base.h>
#include <target/target_core_device.h>
#include <target/target_core_hba.h>
#include <target/target_core_transport.h>
#include <target/target_core_alua.h>
#include <target/target_core_transport_plugin.h>
#include <target/target_core_fabric_ops.h>
#include <target/target_core_configfs.h>

#undef TARGET_CORE_ALUA_C

/*
 * REPORT_TARGET_PORT_GROUPS
 *
 * See spc4r17 6.2.7
 */
int core_scsi3_emulate_report_target_port_groups(se_cmd_t *cmd)
{
	se_port_t *port;
	t10_alua_tg_pt_gp_t *tg_pt_gp;
	t10_alua_tg_pt_gp_member_t *tg_pt_gp_mem;
	unsigned char *buf = (unsigned char *)T_TASK(cmd)->t_task_buf;
	u32 rd_len = 0, off = 4;

	spin_lock(&se_global->tg_pt_gps_lock);
	list_for_each_entry(tg_pt_gp, &se_global->g_tg_pt_gps_list,
			tg_pt_gp_list) {
		/*
		 * PREF: Preferred target port bit
		 */
/*		buf[off] = 0x80; */
		/*
		 * Set the ASYMMETRIC ACCESS State
		 */
		buf[off++] |= (tg_pt_gp->tg_pt_gp_alua_access_state & 0xff);
		/*
		 * Set supported ASYMMETRIC ACCESS State bits
		 */
/*		buf[off] = 0x80; // T_SUP */
/*		buf[off] |= 0x40; // O_SUP */
/*		buf[off] |= 0x8; // U_SUP */
/*		buf[off] |= 0x4; // S_SUP */
		buf[off] |= 0x2; /* AN_SUP */
		buf[off++] |= 0x1; /* AO_SUP */
		/*
		 * TARGET PORT GROUP
		 */
		buf[off++] = ((tg_pt_gp->tg_pt_gp_id >> 8) & 0xff);
		buf[off++] = (tg_pt_gp->tg_pt_gp_id & 0xff);

		off++; /* Skip over Reserved */
		/*
		 * STATUS CODE
		 */
		buf[off++] = ALUA_STATUS_ALTERED_BY_IMPLICT_ALUA;
		/*
		 * Vendor Specific field
		 */
		buf[off++] = 0x00;
		/*
		 * TARGET PORT COUNT
		 */
		buf[off++] = (tg_pt_gp->tg_pt_gp_members & 0xff);
		rd_len += 8;

		spin_lock(&tg_pt_gp->tg_pt_gp_lock);
		list_for_each_entry(tg_pt_gp_mem, &tg_pt_gp->tg_pt_gp_mem_list,
				tg_pt_gp_mem_list) {
			port = tg_pt_gp_mem->tg_pt;
			/*
			 * Start Target Port descriptor format
			 *
			 * See spc4r17 section 6.2.7 Table 247
			 */
			off += 2; /* Skip over Obsolete */
			/*
			 * Set RELATIVE TARGET PORT IDENTIFIER
			 */
			buf[off++] = ((port->sep_rtpi >> 8) & 0xff);
			buf[off++] = (port->sep_rtpi & 0xff);
			rd_len += 4;
		}
		spin_unlock(&tg_pt_gp->tg_pt_gp_lock);
	}
	spin_unlock(&se_global->tg_pt_gps_lock);
	/*
	 * Set the RETURN DATA LENGTH set in the header of the DataIN Payload
	 */
	buf[0] = ((rd_len >> 24) & 0xff);
	buf[1] = ((rd_len >> 16) & 0xff);
	buf[2] = ((rd_len >> 8) & 0xff);
	buf[3] = (rd_len & 0xff);

	return 0;
}

t10_alua_lu_gp_t *core_alua_allocate_lu_gp(const char *name, int def_group)
{
	t10_alua_lu_gp_t *lu_gp;

	lu_gp = kmem_cache_zalloc(t10_alua_lu_gp_cache, GFP_KERNEL);
	if (!(lu_gp)) {
		printk(KERN_ERR "Unable to allocate t10_alua_lu_gp_t\n");
		return NULL;
	}
	INIT_LIST_HEAD(&lu_gp->lu_gp_list);
	INIT_LIST_HEAD(&lu_gp->lu_gp_mem_list);
	spin_lock_init(&lu_gp->lu_gp_lock);
	atomic_set(&lu_gp->lu_gp_ref_cnt, 0);
	lu_gp->lu_gp_alua_access_state = ALUA_ACCESS_STATE_ACTIVE_OPTMIZED;

	if (def_group) {
		lu_gp->lu_gp_id = se_global->alua_lu_gps_counter++;;
		lu_gp->lu_gp_valid_id = 1;
		se_global->alua_lu_gps_count++;
	}

	return lu_gp;
}

int core_alua_set_lu_gp_id(t10_alua_lu_gp_t *lu_gp, u16 lu_gp_id)
{
	t10_alua_lu_gp_t *lu_gp_tmp;
	u16 lu_gp_id_tmp;

	spin_lock(&se_global->lu_gps_lock);
	if (se_global->alua_lu_gps_count == 0x0000ffff) {
		printk(KERN_ERR "Maximum ALUA se_global->alua_lu_gps_count:"
				" 0x0000ffff reached\n");
		spin_unlock(&se_global->lu_gps_lock);
		kmem_cache_free(t10_alua_lu_gp_cache, lu_gp);
		return -1;
	}
again:
	lu_gp_id_tmp = (lu_gp_id != 0) ? lu_gp_id :
				se_global->alua_lu_gps_counter++;

	list_for_each_entry(lu_gp_tmp, &se_global->g_lu_gps_list, lu_gp_list) {
		if (lu_gp_tmp->lu_gp_id == lu_gp_id_tmp) {
			if (!(lu_gp_id))
				goto again;

			printk(KERN_ERR "ALUA Logical Unit Group ID: %hu already"
				" exists, ignoring request\n", lu_gp_id);
			spin_unlock(&se_global->lu_gps_lock);
			return -1;
		}
	}

	lu_gp->lu_gp_id = lu_gp_id_tmp;
	lu_gp->lu_gp_valid_id = 1;
	list_add_tail(&lu_gp->lu_gp_list, &se_global->g_lu_gps_list);
	se_global->alua_lu_gps_count++;
	spin_unlock(&se_global->lu_gps_lock);

	return 0;
}

t10_alua_lu_gp_member_t *core_alua_allocate_lu_gp_mem(
	se_device_t *dev)
{
	t10_alua_lu_gp_member_t *lu_gp_mem;

	lu_gp_mem = kmem_cache_zalloc(t10_alua_lu_gp_mem_cache, GFP_KERNEL);
	if (!(lu_gp_mem)) {
		printk(KERN_ERR "Unable to allocate t10_alua_lu_gp_member_t\n");
		return ERR_PTR(-ENOMEM);
	}
	INIT_LIST_HEAD(&lu_gp_mem->lu_gp_mem_list);
	spin_lock_init(&lu_gp_mem->lu_gp_mem_lock);

	lu_gp_mem->lu_gp_mem_dev = dev;
	dev->dev_alua_lu_gp_mem = lu_gp_mem;

	return lu_gp_mem;
}

void core_alua_free_lu_gp(t10_alua_lu_gp_t *lu_gp)
{
	t10_alua_lu_gp_member_t *lu_gp_mem, *lu_gp_mem_tmp;
	/*
	 * Once we have reached this point, config_item_put() has
	 * already been called from target_core_alua_drop_lu_gp().
	 *
	 * Here, we remove the *lu_gp from the global list so that
	 * no associations can be made while we are releasing
	 * t10_alua_lu_gp_t.
	 */
	spin_lock(&se_global->lu_gps_lock);
	atomic_set(&lu_gp->lu_gp_shutdown, 1);
	list_del(&lu_gp->lu_gp_list);
	se_global->alua_lu_gps_count--;
	spin_unlock(&se_global->lu_gps_lock);
	/*
	 * Allow t10_alua_lu_gp_t * referenced by core_alua_get_lu_gp_by_name()
	 * in target_core_configfs.c:target_core_store_alua_lu_gp() to be
	 * released with core_alua_put_lu_gp_from_name()
	 */
	while (atomic_read(&lu_gp->lu_gp_ref_cnt))
		msleep(10);
	/*
	 * Release reference to t10_alua_lu_gp_t * from all associated
	 * se_device_t.
	 */
	spin_lock(&lu_gp->lu_gp_lock);
	list_for_each_entry_safe(lu_gp_mem, lu_gp_mem_tmp,
				&lu_gp->lu_gp_mem_list, lu_gp_mem_list) {
		if (lu_gp_mem->lu_gp_assoc) {
			list_del(&lu_gp_mem->lu_gp_mem_list);
			lu_gp->lu_gp_members--;
			lu_gp_mem->lu_gp_assoc = 0;
		}
		spin_unlock(&lu_gp->lu_gp_lock);
		/*
		 *
		 * lu_gp_mem is assoicated with a single
		 * se_device_t->dev_alua_lu_gp_mem, and is released when
		 * se_device_t is released via core_alua_free_lu_gp_mem().
		 *
		 * If the passed lu_gp does NOT match the default_lu_gp, assume
		 * we want to re-assocate a given lu_gp_mem with default_lu_gp.
		 */
		spin_lock(&lu_gp_mem->lu_gp_mem_lock);
		if (lu_gp != se_global->default_lu_gp)
			__core_alua_attach_lu_gp_mem(lu_gp_mem,
					se_global->default_lu_gp);
		else
			lu_gp_mem->lu_gp = NULL;
		spin_unlock(&lu_gp_mem->lu_gp_mem_lock);

		spin_lock(&lu_gp->lu_gp_lock);
	}
	spin_unlock(&lu_gp->lu_gp_lock);

	kmem_cache_free(t10_alua_lu_gp_cache, lu_gp);
}

void core_alua_free_lu_gp_mem(se_device_t *dev)
{
	se_subsystem_dev_t *su_dev = dev->se_sub_dev;
	t10_alua_t *alua = T10_ALUA(su_dev);
	t10_alua_lu_gp_t *lu_gp;
	t10_alua_lu_gp_member_t *lu_gp_mem;

	if (alua->alua_type != SPC3_ALUA_EMULATED)
		return;

	lu_gp_mem = dev->dev_alua_lu_gp_mem;
	if (!(lu_gp_mem))
		return;

	spin_lock(&lu_gp_mem->lu_gp_mem_lock);
	lu_gp = lu_gp_mem->lu_gp;
	if ((lu_gp)) {
		spin_lock(&lu_gp->lu_gp_lock);
		if (lu_gp_mem->lu_gp_assoc) {
			list_del(&lu_gp_mem->lu_gp_mem_list);
			lu_gp->lu_gp_members--;
			lu_gp_mem->lu_gp_assoc = 0;
		}
		spin_unlock(&lu_gp->lu_gp_lock);
		lu_gp_mem->lu_gp = NULL;
	}
	spin_unlock(&lu_gp_mem->lu_gp_mem_lock);

	kmem_cache_free(t10_alua_lu_gp_mem_cache, lu_gp_mem);
}

t10_alua_lu_gp_t *core_alua_get_lu_gp_by_name(const char *name)
{
	t10_alua_lu_gp_t *lu_gp;
	struct config_item *ci;

	spin_lock(&se_global->lu_gps_lock);
	list_for_each_entry(lu_gp, &se_global->g_lu_gps_list, lu_gp_list) {
		if (!(lu_gp->lu_gp_valid_id))
			continue;
		ci = &lu_gp->lu_gp_group.cg_item;
		if (!(strcmp(config_item_name(ci), name))) {
			atomic_inc(&lu_gp->lu_gp_ref_cnt);
			spin_unlock(&se_global->lu_gps_lock);
			return lu_gp;
		}
	}
	spin_unlock(&se_global->lu_gps_lock);

	return NULL;
}

void core_alua_put_lu_gp_from_name(t10_alua_lu_gp_t *lu_gp)
{
	spin_lock(&se_global->lu_gps_lock);
	atomic_dec(&lu_gp->lu_gp_ref_cnt);
	spin_unlock(&se_global->lu_gps_lock);
}

/*
 * Called with t10_alua_lu_gp_member_t->lu_gp_mem_lock
 */
void __core_alua_attach_lu_gp_mem(
	t10_alua_lu_gp_member_t *lu_gp_mem,
	t10_alua_lu_gp_t *lu_gp)
{
	spin_lock(&lu_gp->lu_gp_lock);
	lu_gp_mem->lu_gp = lu_gp;
	lu_gp_mem->lu_gp_assoc = 1;
	list_add_tail(&lu_gp_mem->lu_gp_mem_list, &lu_gp->lu_gp_mem_list);
	lu_gp->lu_gp_members++;
	spin_unlock(&lu_gp->lu_gp_lock);
}

/*
 * Called with t10_alua_lu_gp_member_t->lu_gp_mem_lock
 */
void __core_alua_drop_lu_gp_mem(
	t10_alua_lu_gp_member_t *lu_gp_mem,
	t10_alua_lu_gp_t *lu_gp)
{
	spin_lock(&lu_gp->lu_gp_lock);
	list_del(&lu_gp_mem->lu_gp_mem_list);
	lu_gp_mem->lu_gp = NULL;
	lu_gp_mem->lu_gp_assoc = 0;
	lu_gp->lu_gp_members--;
	spin_unlock(&lu_gp->lu_gp_lock);
}

t10_alua_tg_pt_gp_t *core_alua_allocate_tg_pt_gp(const char *name, int def_group)
{
	t10_alua_tg_pt_gp_t *tg_pt_gp;

	tg_pt_gp = kmem_cache_zalloc(t10_alua_tg_pt_gp_cache, GFP_KERNEL);
	if (!(tg_pt_gp)) {
		printk(KERN_ERR "Unable to allocate t10_alua_tg_pt_gp_t\n");
		return NULL;
	}
	INIT_LIST_HEAD(&tg_pt_gp->tg_pt_gp_list);
	INIT_LIST_HEAD(&tg_pt_gp->tg_pt_gp_mem_list);
	spin_lock_init(&tg_pt_gp->tg_pt_gp_lock);
	atomic_set(&tg_pt_gp->tg_pt_gp_ref_cnt, 0);
	tg_pt_gp->tg_pt_gp_alua_access_state =
			ALUA_ACCESS_STATE_ACTIVE_OPTMIZED;

	if (def_group) {
		tg_pt_gp->tg_pt_gp_id = se_global->alua_tg_pt_gps_counter++;
		tg_pt_gp->tg_pt_gp_valid_id = 1;
		se_global->alua_tg_pt_gps_count++;
	}

	return tg_pt_gp;
}

int core_alua_set_tg_pt_gp_id(t10_alua_tg_pt_gp_t *tg_pt_gp, u16 tg_pt_gp_id)
{
	t10_alua_tg_pt_gp_t *tg_pt_gp_tmp;
	u16 tg_pt_gp_id_tmp;

	spin_lock(&se_global->tg_pt_gps_lock);
	if (se_global->alua_tg_pt_gps_count == 0x0000ffff) {
		printk(KERN_ERR "Maximum ALUA se_global->alua_tg_pt_gps_count:"
			" 0x0000ffff reached\n");
		spin_unlock(&se_global->tg_pt_gps_lock);
		kmem_cache_free(t10_alua_tg_pt_gp_cache, tg_pt_gp);
		return -1;
	}
again:
	tg_pt_gp_id_tmp = (tg_pt_gp_id != 0) ? tg_pt_gp_id :
			se_global->alua_tg_pt_gps_counter++;

	list_for_each_entry(tg_pt_gp_tmp, &se_global->g_tg_pt_gps_list,
			tg_pt_gp_list) {
		if (tg_pt_gp_tmp->tg_pt_gp_id == tg_pt_gp_id_tmp) {
			if (!(tg_pt_gp_id))
				goto again;

			printk(KERN_ERR "ALUA Target Port Group ID: %hu already"
				" exists, ignoring request\n", tg_pt_gp_id);
			spin_unlock(&se_global->tg_pt_gps_lock);
			return -1;
		}
	}

	tg_pt_gp->tg_pt_gp_id = tg_pt_gp_id_tmp;
	tg_pt_gp->tg_pt_gp_valid_id = 1;
	list_add_tail(&tg_pt_gp->tg_pt_gp_list, &se_global->g_tg_pt_gps_list);
	se_global->alua_tg_pt_gps_count++;
	spin_unlock(&se_global->tg_pt_gps_lock);

	return 0;
}

t10_alua_tg_pt_gp_member_t *core_alua_allocate_tg_pt_gp_mem(
	se_port_t *port)
{
	t10_alua_tg_pt_gp_member_t *tg_pt_gp_mem;

	tg_pt_gp_mem = kmem_cache_zalloc(t10_alua_tg_pt_gp_mem_cache,
				GFP_KERNEL);
	if (!(tg_pt_gp_mem)) {
		printk(KERN_ERR "Unable to allocate t10_alua_tg_pt_gp_member_t\n");
		return ERR_PTR(-ENOMEM);
	}
	INIT_LIST_HEAD(&tg_pt_gp_mem->tg_pt_gp_mem_list);
	spin_lock_init(&tg_pt_gp_mem->tg_pt_gp_mem_lock);

	tg_pt_gp_mem->tg_pt = port;
	port->sep_alua_tg_pt_gp_mem = tg_pt_gp_mem;

	return tg_pt_gp_mem;
}

void core_alua_free_tg_pt_gp(t10_alua_tg_pt_gp_t *tg_pt_gp)
{
	t10_alua_tg_pt_gp_member_t *tg_pt_gp_mem, *tg_pt_gp_mem_tmp;
	/*
	 * Once we have reached this point, config_item_put() has already
	 * been called from target_core_alua_drop_tg_pt_gp().
	 *
	 * Here we remove *tg_pt_gp from the global list so that
	 * no assications *OR* explict ALUA via SET_TARGET_PORT_GROUPS
	 * can be made while we are releasing t10_alua_tg_pt_gp_t.
	 */
	spin_lock(&se_global->tg_pt_gps_lock);
	list_del(&tg_pt_gp->tg_pt_gp_list);
	se_global->alua_tg_pt_gps_counter--;
	spin_unlock(&se_global->tg_pt_gps_lock);
	/*
	 * Allow a t10_alua_tg_pt_gp_member_t * referenced by
	 * core_alua_get_tg_pt_gp_by_name() in
	 * target_core_configfs.c:target_core_store_alua_tg_pt_gp()
	 * to be released with core_alua_put_tg_pt_gp_from_name().
	 */
	while (atomic_read(&tg_pt_gp->tg_pt_gp_ref_cnt))
		msleep(10);
	/*
	 * Release reference to t10_alua_tg_pt_gp_t from all associated
	 * se_port_t.
	 */
	spin_lock(&tg_pt_gp->tg_pt_gp_lock);
	list_for_each_entry_safe(tg_pt_gp_mem, tg_pt_gp_mem_tmp,
			&tg_pt_gp->tg_pt_gp_mem_list, tg_pt_gp_mem_list) {
		if (tg_pt_gp_mem->tg_pt_gp_assoc) {
			list_del(&tg_pt_gp_mem->tg_pt_gp_mem_list);
			tg_pt_gp->tg_pt_gp_members--;
			tg_pt_gp_mem->tg_pt_gp_assoc = 0;
		}
		spin_unlock(&tg_pt_gp->tg_pt_gp_lock);
		/*
		 * tg_pt_gp_mem is assoicated with a single
		 * se_portt->sep_alua_tg_pt_gp_mem, and is released via
		 * core_alua_free_tg_pt_gp_mem().
		 *
		 * If the passed tg_pt_gp does NOT match the default_tg_pt_gp,
		 * assume we want to re-assocate a given tg_pt_gp_mem with
		 * default_tg_pt_gp.
		 */
		spin_lock(&tg_pt_gp_mem->tg_pt_gp_mem_lock);
		if (tg_pt_gp != se_global->default_tg_pt_gp) {
			__core_alua_attach_tg_pt_gp_mem(tg_pt_gp_mem,
					se_global->default_tg_pt_gp);
		} else
			tg_pt_gp_mem->tg_pt_gp = NULL;
		spin_unlock(&tg_pt_gp_mem->tg_pt_gp_mem_lock);

		spin_lock(&tg_pt_gp->tg_pt_gp_lock);
	}
	spin_unlock(&tg_pt_gp->tg_pt_gp_lock);

	kmem_cache_free(t10_alua_tg_pt_gp_cache, tg_pt_gp);
}

void core_alua_free_tg_pt_gp_mem(se_port_t *port)
{
	se_subsystem_dev_t *su_dev = port->sep_lun->se_dev->se_sub_dev;
	t10_alua_t *alua = T10_ALUA(su_dev);
	t10_alua_tg_pt_gp_t *tg_pt_gp;
	t10_alua_tg_pt_gp_member_t *tg_pt_gp_mem;

	if (alua->alua_type != SPC3_ALUA_EMULATED)
		return;

	tg_pt_gp_mem = port->sep_alua_tg_pt_gp_mem;
	if (!(tg_pt_gp_mem))
		return;

	spin_lock(&tg_pt_gp_mem->tg_pt_gp_mem_lock);
	tg_pt_gp = tg_pt_gp_mem->tg_pt_gp;
	if ((tg_pt_gp)) {
		spin_lock(&tg_pt_gp->tg_pt_gp_lock);
		if (tg_pt_gp_mem->tg_pt_gp_assoc) {
			list_del(&tg_pt_gp_mem->tg_pt_gp_mem_list);
			tg_pt_gp->tg_pt_gp_members--;
			tg_pt_gp_mem->tg_pt_gp_assoc = 0;
		}
		spin_unlock(&tg_pt_gp->tg_pt_gp_lock);
		tg_pt_gp_mem->tg_pt_gp = NULL;
	}
	spin_unlock(&tg_pt_gp_mem->tg_pt_gp_mem_lock);

	kmem_cache_free(t10_alua_tg_pt_gp_mem_cache, tg_pt_gp_mem);
}

t10_alua_tg_pt_gp_t *core_alua_get_tg_pt_gp_by_name(const char *name)
{
	t10_alua_tg_pt_gp_t *tg_pt_gp;
	struct config_item *ci;

	spin_lock(&se_global->tg_pt_gps_lock);
	list_for_each_entry(tg_pt_gp, &se_global->g_tg_pt_gps_list,
			tg_pt_gp_list) {
		if (!(tg_pt_gp->tg_pt_gp_valid_id))
			continue;
		ci = &tg_pt_gp->tg_pt_gp_group.cg_item;
		if (!(strcmp(config_item_name(ci), name))) {
			atomic_inc(&tg_pt_gp->tg_pt_gp_ref_cnt);
			spin_unlock(&se_global->tg_pt_gps_lock);
			return tg_pt_gp;
		}
	}
	spin_unlock(&se_global->tg_pt_gps_lock);

	return NULL;
}

void core_alua_put_tg_pt_gp_from_name(t10_alua_tg_pt_gp_t *tg_pt_gp)
{
	spin_lock(&se_global->tg_pt_gps_lock);
	atomic_dec(&tg_pt_gp->tg_pt_gp_ref_cnt);
	spin_unlock(&se_global->tg_pt_gps_lock);
}

/*
 * Called with t10_alua_tg_pt_gp_member_t->tg_pt_gp_mem_lock held
 */
void __core_alua_attach_tg_pt_gp_mem(
	t10_alua_tg_pt_gp_member_t *tg_pt_gp_mem,
	t10_alua_tg_pt_gp_t *tg_pt_gp)
{
	spin_lock(&tg_pt_gp->tg_pt_gp_lock);
	tg_pt_gp_mem->tg_pt_gp = tg_pt_gp;
	tg_pt_gp_mem->tg_pt_gp_assoc = 1;
	list_add_tail(&tg_pt_gp_mem->tg_pt_gp_mem_list,
			&tg_pt_gp->tg_pt_gp_mem_list);
	tg_pt_gp->tg_pt_gp_members++;
	spin_unlock(&tg_pt_gp->tg_pt_gp_lock);
}

/*
 * Called with t10_alua_tg_pt_gp_member_t->tg_pt_gp_mem_lock held
 */
void __core_alua_drop_tg_pt_gp_mem(
	t10_alua_tg_pt_gp_member_t *tg_pt_gp_mem,
	t10_alua_tg_pt_gp_t *tg_pt_gp)
{
	spin_lock(&tg_pt_gp->tg_pt_gp_lock);
	list_del(&tg_pt_gp_mem->tg_pt_gp_mem_list);
	tg_pt_gp_mem->tg_pt_gp = NULL;
	tg_pt_gp_mem->tg_pt_gp_assoc = 0;
	tg_pt_gp->tg_pt_gp_members--;
	spin_unlock(&tg_pt_gp->tg_pt_gp_lock);
}

ssize_t core_alua_show_tg_pt_gp_info(se_port_t *port, char *page)
{
	se_subsystem_dev_t *su_dev = port->sep_lun->se_dev->se_sub_dev;
	struct config_item *tg_pt_ci;
	t10_alua_t *alua = T10_ALUA(su_dev);
	t10_alua_tg_pt_gp_t *tg_pt_gp;
	t10_alua_tg_pt_gp_member_t *tg_pt_gp_mem;
	ssize_t len = 0;

	if (alua->alua_type != SPC3_ALUA_EMULATED)
		return len;

	tg_pt_gp_mem = port->sep_alua_tg_pt_gp_mem;
	if (!(tg_pt_gp_mem))
		return len;

	spin_lock(&tg_pt_gp_mem->tg_pt_gp_mem_lock);
	tg_pt_gp = tg_pt_gp_mem->tg_pt_gp;
	if ((tg_pt_gp)) {
		tg_pt_ci = &tg_pt_gp->tg_pt_gp_group.cg_item;
		len += sprintf(page, "TG Port Alias: %s\nTG Port Group ID:"
			" %hu\n", config_item_name(tg_pt_ci),
			tg_pt_gp->tg_pt_gp_id);
	}
	spin_unlock(&tg_pt_gp_mem->tg_pt_gp_mem_lock);

	return len;
}
EXPORT_SYMBOL(core_alua_show_tg_pt_gp_info);

ssize_t core_alua_store_tg_pt_gp_info(
	se_port_t *port,
	const char *page,
	size_t count)
{
	se_portal_group_t *tpg;
	se_lun_t *lun;
	se_subsystem_dev_t *su_dev = port->sep_lun->se_dev->se_sub_dev;
	t10_alua_tg_pt_gp_t *tg_pt_gp = NULL, *tg_pt_gp_new = NULL;
	t10_alua_tg_pt_gp_member_t *tg_pt_gp_mem;
	unsigned char buf[TG_PT_GROUP_NAME_BUF];
	int move = 0;

	tpg = port->sep_tpg;
	lun = port->sep_lun;

	if (T10_ALUA(su_dev)->alua_type != SPC3_ALUA_EMULATED) {
		printk(KERN_WARNING "SPC3_ALUA_EMULATED not enabled for"
			" %s/tpgt_%hu/%s\n", TPG_TFO(tpg)->tpg_get_wwn(tpg),
			TPG_TFO(tpg)->tpg_get_tag(tpg),
			config_item_name(&lun->lun_group.cg_item));
		return -EINVAL;
	}
	if (count > TG_PT_GROUP_NAME_BUF) {
		printk(KERN_ERR "ALUA Target Port Group alias too large!\n");
		return -EINVAL;
	}
	memset(buf, 0, TG_PT_GROUP_NAME_BUF);
	memcpy(buf, page, count);
	/*
	 * Any ALUA target port group alias besides "NULL" means we will be
	 * making a new group association.
	 */
	if (strcmp(strstrip(buf), "NULL")) {
		/*
		 * core_alua_get_tg_pt_gp_by_name() will increment reference to
		 * t10_alua_tg_pt_gp_t.  This reference is released with
		 * core_alua_put_tg_pt_gp_from_name() below.
		 */
		tg_pt_gp_new = core_alua_get_tg_pt_gp_by_name(strstrip(buf));
		if (!(tg_pt_gp_new))
			return -ENODEV;
	}
	tg_pt_gp_mem = port->sep_alua_tg_pt_gp_mem;
	if (!(tg_pt_gp_mem)) {
		if (tg_pt_gp_new)
			core_alua_put_tg_pt_gp_from_name(tg_pt_gp_new);
		printk(KERN_ERR "NULL se_port_t->sep_alua_tg_pt_gp_mem pointer\n");
		return -EINVAL;
	}

	spin_lock(&tg_pt_gp_mem->tg_pt_gp_mem_lock);
	tg_pt_gp = tg_pt_gp_mem->tg_pt_gp;
	if ((tg_pt_gp)) {
		/*
		 * Clearing an existing tg_pt_gp association, and replacing
		 * with NULL
		 */
		if (!(tg_pt_gp_new)) {
			printk(KERN_INFO "Target_Core_ConfigFS: Releasing"
				" %s/tpgt_%hu/%s from ALUA Target Port Group:"
				" core/alua/tg_pt_gps/%s, ID: %hu\n",
				TPG_TFO(tpg)->tpg_get_wwn(tpg),
				TPG_TFO(tpg)->tpg_get_tag(tpg),
				config_item_name(&lun->lun_group.cg_item),
				config_item_name(
					&tg_pt_gp->tg_pt_gp_group.cg_item),
				tg_pt_gp->tg_pt_gp_id);

			__core_alua_drop_tg_pt_gp_mem(tg_pt_gp_mem, tg_pt_gp);
			spin_unlock(&tg_pt_gp_mem->tg_pt_gp_mem_lock);

			return count;
		}
		/*
		 * Removing existing association of tg_pt_gp_mem with tg_pt_gp
		 */
		__core_alua_drop_tg_pt_gp_mem(tg_pt_gp_mem, tg_pt_gp);
		move = 1;
	}
	/*
	 * Associate tg_pt_gp_mem with tg_pt_gp_new.
	 */
	__core_alua_attach_tg_pt_gp_mem(tg_pt_gp_mem, tg_pt_gp_new);
	spin_unlock(&tg_pt_gp_mem->tg_pt_gp_mem_lock);

	printk("Target_Core_ConfigFS: %s %s/tpgt_%hu/%s to ALUA Target Port"
		" Group: core/alua/tg_pt_gps/%s, ID: %hu\n", (move) ?
		"Moving" : "Adding", TPG_TFO(tpg)->tpg_get_wwn(tpg),
		TPG_TFO(tpg)->tpg_get_tag(tpg),
		config_item_name(&lun->lun_group.cg_item),
		config_item_name(&tg_pt_gp_new->tg_pt_gp_group.cg_item),
		tg_pt_gp_new->tg_pt_gp_id);

	core_alua_put_tg_pt_gp_from_name(tg_pt_gp_new);
	return count;
}
EXPORT_SYMBOL(core_alua_store_tg_pt_gp_info);

int core_setup_alua(se_device_t *dev)
{
	se_subsystem_dev_t *su_dev = dev->se_sub_dev;
	t10_alua_t *alua = T10_ALUA(su_dev);
	t10_alua_lu_gp_member_t *lu_gp_mem;
	/*
	 * If this device is from Target_Core_Mod/pSCSI, use the ALUA logic
	 * of the Underlying SCSI hardware.  In Linux/SCSI terms, this can
	 * cause a problem because libata and some SATA RAID HBAs appear
	 * under Linux/SCSI, but emulate SCSI logic themselves.
	 */
	if ((TRANSPORT(dev)->transport_type == TRANSPORT_PLUGIN_PHBA_PDEV) &&
	    !(DEV_ATTRIB(dev)->emulate_alua)) {
		alua->alua_type = SPC_ALUA_PASSTHROUGH;
		printk(KERN_INFO "%s: Using SPC_ALUA_PASSTHROUGH, no ALUA"
			" emulation\n", TRANSPORT(dev)->name);
		return 0;
	}
	/*
	 * If SPC-3 or above is reported by real or emulated se_device_t,
	 * use emulated ALUA.
	 */
	if (TRANSPORT(dev)->get_device_rev(dev) >= SCSI_3) {
		printk(KERN_INFO "%s: Enabling ALUA Emulation for SPC-3"
			" device\n", TRANSPORT(dev)->name);
		/*
		 * Assoicate this se_device_t with the default ALUA
		 * LUN Group.
		 */
		lu_gp_mem = core_alua_allocate_lu_gp_mem(dev);
		if (IS_ERR(lu_gp_mem) || !lu_gp_mem)
			return -1;

		alua->alua_type = SPC3_ALUA_EMULATED;
		spin_lock(&lu_gp_mem->lu_gp_mem_lock);
		__core_alua_attach_lu_gp_mem(lu_gp_mem,
				se_global->default_lu_gp);
		spin_unlock(&lu_gp_mem->lu_gp_mem_lock);

		printk(KERN_INFO "%s: Adding to default ALUA LU Group:"
			" core/alua/lu_gps/default_lu_gp\n",
			TRANSPORT(dev)->name);
	} else {
		alua->alua_type = SPC2_ALUA_DISABLED;
		printk("%s: Disabling ALUA Emulation for SPC-2 device\n",
				TRANSPORT(dev)->name);
	}

	return 0;
}
