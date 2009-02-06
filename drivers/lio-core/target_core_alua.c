/*********************************************************************************
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
 *********************************************************************************/

#define TARGET_CORE_ALUA_C

#include <linux/version.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <scsi/scsi.h>
#include <scsi/scsi_cmnd.h>

#include <target_core_base.h>
#include <target_core_device.h>
#include <target_core_hba.h>
#include <target_core_transport.h>
#include <target_core_alua.h>
#include <target_core_transport_plugin.h>
#include <target_core_fabric_ops.h>
#include <target_core_configfs.h>

#undef TARGET_CORE_ALUA_C

extern se_global_t *se_global;

extern struct kmem_cache *t10_alua_lu_gp_cache;
extern struct kmem_cache *t10_alua_tg_pt_gp_cache;

/*
 * REPORT_TARGET_PORT_GROUPS
 *
 * See spc4r17 6.2.7
 */
extern int core_scsi3_emulate_report_target_port_groups (se_cmd_t *cmd)
{
	se_port_t *port;
	t10_alua_tg_pt_gp_t *tg_pt_gp;
	unsigned char *buf = (unsigned char *)T_TASK(cmd)->t_task_buf;
	u32 rd_len = 0, off = 4;
	
	spin_lock(&se_global->tg_pt_gps_lock);
	list_for_each_entry(tg_pt_gp, &se_global->g_tg_pt_gps_list, tg_pt_gp_list) {
		/*
		 * PREF: Preferred target port bit
		 */
//		buf[off] = 0x80;
		/*
		 * Set the ASYMMETRIC ACCESS State
		 */
		buf[off++] |= (tg_pt_gp->tg_pt_gp_alua_access_state & 0xff);
		/*
		 * Set supported ASYMMETRIC ACCESS State bits
		 */
//		buf[off] = 0x80; // T_SUP
//		buf[off] |= 0x40; // O_SUP
//		buf[off] |= 0x8; // U_SUP
//		buf[off] |= 0x4; // S_SUP
		buf[off] |= 0x2; // AN_SUP
		buf[off++] |= 0x1; // AO_SUP
		/*
		 * TARGET PORT GROUP
		 */
		buf[off++] = ((tg_pt_gp->tg_pt_gp_id >> 8) & 0xff);
		buf[off++] = (tg_pt_gp->tg_pt_gp_id & 0xff);
	
		off++; // Skip over Reserved
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
		
		spin_lock(&tg_pt_gp->tg_pt_gp_ref_lock);
		list_for_each_entry(port, &tg_pt_gp->tg_pt_gp_ref_list, sep_tg_pt_gp_list) {
			/*
			 * Start Target Port descriptor format
			 *
			 * See spc4r17 section 6.2.7 Table 247
			 */
			off += 2; // Skip over Obsolete
			/*
			 * Set RELATIVE TARGET PORT IDENTIFIER
			 */
			buf[off++] = ((port->sep_rtpi >> 8) & 0xff);
			buf[off++] = (port->sep_rtpi & 0xff);
			rd_len += 4;
		}
		spin_unlock(&tg_pt_gp->tg_pt_gp_ref_lock);
	}
	spin_unlock(&se_global->tg_pt_gps_lock);
	/*
	 * Set the RETURN DATA LENGTH set in the header of the DataIN Payload
	 */
	buf[0] = ((rd_len >> 24) & 0xff);
	buf[1] = ((rd_len >> 16) & 0xff);
	buf[2] = ((rd_len >> 8) & 0xff);
	buf[3] = (rd_len & 0xff);

	return(0);	
}

extern t10_alua_lu_gp_t *core_alua_allocate_lu_gp (const char *name)
{
	t10_alua_lu_gp_t *lu_gp, *lu_gp_tmp;

	if (!(lu_gp = kmem_cache_zalloc(t10_alua_lu_gp_cache, GFP_KERNEL))) {
		printk("Unable to allocate t10_alua_lu_gp_t\n");
		return(NULL);
	}
	INIT_LIST_HEAD(&lu_gp->lu_gp_list);
	INIT_LIST_HEAD(&lu_gp->lu_gp_ref_list);
	spin_lock_init(&lu_gp->lu_gp_ref_lock);
	lu_gp->lu_gp_alua_access_state = ALUA_ACCESS_STATE_ACTIVE_OPTMIZED;

	spin_lock(&se_global->lu_gps_lock);
	if (se_global->alua_lu_gps_count == 0x0000ffff) {
		spin_unlock(&se_global->lu_gps_lock);
		kmem_cache_free(t10_alua_lu_gp_cache, lu_gp);
		return(NULL);
	}
again:
	lu_gp->lu_gp_id = se_global->alua_lu_gps_counter++;

	list_for_each_entry(lu_gp_tmp, &se_global->g_lu_gps_list, lu_gp_list) {
		if (lu_gp_tmp->lu_gp_id == lu_gp->lu_gp_id)	
			goto again;
	}

	list_add_tail(&lu_gp->lu_gp_list, &se_global->g_lu_gps_list);	
	se_global->alua_lu_gps_count++;
	spin_unlock(&se_global->lu_gps_lock);

	return(lu_gp);
}

extern void core_alua_free_lu_gp (t10_alua_lu_gp_t *lu_gp)
{
	se_device_t *dev, *dev_tmp;

	spin_lock(&lu_gp->lu_gp_ref_lock);
	list_for_each_entry_safe(dev, dev_tmp, &lu_gp->lu_gp_ref_list, dev_lu_gp_list) {
		list_del(&dev->dev_lu_gp_list);	
		spin_lock(&dev->dev_alua_lock);
		dev->dev_alua_lu_gp = NULL;
		spin_unlock(&dev->dev_alua_lock);
	}
	spin_unlock(&lu_gp->lu_gp_ref_lock);

	spin_lock(&se_global->lu_gps_lock);
	list_del(&lu_gp->lu_gp_list);
	se_global->alua_lu_gps_count--;
	spin_unlock(&se_global->lu_gps_lock);

	kmem_cache_free(t10_alua_lu_gp_cache, lu_gp);
	return;
}

extern t10_alua_lu_gp_t *core_alua_get_lu_gp_by_name (se_device_t *dev, const char *name)
{
	t10_alua_lu_gp_t *lu_gp;
	struct config_item *ci;

	spin_lock(&se_global->lu_gps_lock);
	list_for_each_entry(lu_gp, &se_global->g_lu_gps_list, lu_gp_list) {
		ci = &lu_gp->lu_gp_group.cg_item;
		if (!(strcmp(config_item_name(ci), name))) {
			atomic_inc(&lu_gp->lu_gp_ref_cnt);			
			spin_unlock(&se_global->lu_gps_lock);
			return(lu_gp);
		}
	}
	spin_unlock(&se_global->lu_gps_lock);

	return(NULL);
}

extern void core_alua_attach_lu_gp (se_device_t *dev, t10_alua_lu_gp_t *lu_gp)
{
	spin_lock(&lu_gp->lu_gp_ref_lock);
	list_add_tail(&dev->dev_lu_gp_list, &lu_gp->lu_gp_ref_list);
	lu_gp->lu_gp_members++;
	spin_lock(&dev->dev_alua_lock);
	dev->dev_alua_lu_gp = lu_gp;
	spin_unlock(&dev->dev_alua_lock);
	spin_unlock(&lu_gp->lu_gp_ref_lock);

	return;
}

/*
 * Called with se_device_t->dev_alua_lock held.
 */
extern void __core_alua_put_lu_gp (se_device_t *dev, int clear)
{
	t10_alua_lu_gp_t *lu_gp;

	if (!(lu_gp = dev->dev_alua_lu_gp)) 
		return;

	spin_lock(&lu_gp->lu_gp_ref_lock);
	list_del(&dev->dev_lu_gp_list);
	atomic_dec(&lu_gp->lu_gp_ref_cnt);
	lu_gp->lu_gp_members--;
	
	if (!(clear)) {
		spin_unlock(&lu_gp->lu_gp_ref_lock);
		return;
	}
	dev->dev_alua_lu_gp = NULL;
	spin_unlock(&lu_gp->lu_gp_ref_lock);

	return;
}

extern void core_alua_put_lu_gp (se_device_t *dev, int clear)
{
	t10_alua_lu_gp_t *lu_gp;

	spin_lock(&dev->dev_alua_lock);
	if (!(lu_gp = dev->dev_alua_lu_gp)) {
		spin_unlock(&dev->dev_alua_lock);
		return;
	}
	spin_lock(&lu_gp->lu_gp_ref_lock);
	list_del(&dev->dev_lu_gp_list);
	atomic_dec(&lu_gp->lu_gp_ref_cnt);
	lu_gp->lu_gp_members--;

	if (!(clear)) {
		spin_unlock(&lu_gp->lu_gp_ref_lock);
		spin_unlock(&dev->dev_alua_lock);
		return;
	}
	dev->dev_alua_lu_gp = NULL;
	spin_unlock(&lu_gp->lu_gp_ref_lock);
	spin_unlock(&dev->dev_alua_lock);

	return;
}

extern t10_alua_tg_pt_gp_t *core_alua_allocate_tg_pt_gp (const char *name)
{
	t10_alua_tg_pt_gp_t *tg_pt_gp, *tg_pt_gp_tmp;

	if (!(tg_pt_gp = kmem_cache_zalloc(t10_alua_tg_pt_gp_cache, GFP_KERNEL))) {
		printk("Unable to allocate t10_alua_tg_pt_gp_t\n");
		return(NULL);
	}
	INIT_LIST_HEAD(&tg_pt_gp->tg_pt_gp_list);
	INIT_LIST_HEAD(&tg_pt_gp->tg_pt_gp_ref_list);
	spin_lock_init(&tg_pt_gp->tg_pt_gp_ref_lock);
	tg_pt_gp->tg_pt_gp_alua_access_state = ALUA_ACCESS_STATE_ACTIVE_OPTMIZED;

	spin_lock(&se_global->tg_pt_gps_lock);
	if (se_global->alua_tg_pt_gps_count == 0x0000ffff) {
		spin_unlock(&se_global->tg_pt_gps_lock);
		kmem_cache_free(t10_alua_tg_pt_gp_cache, tg_pt_gp);
		return(NULL);
	}
again:
	tg_pt_gp->tg_pt_gp_id = se_global->alua_tg_pt_gps_counter++;

	list_for_each_entry(tg_pt_gp_tmp, &se_global->g_tg_pt_gps_list, tg_pt_gp_list) {
		if (tg_pt_gp_tmp->tg_pt_gp_id == tg_pt_gp->tg_pt_gp_id)
			goto again;
	}

	list_add_tail(&tg_pt_gp->tg_pt_gp_list, &se_global->g_tg_pt_gps_list);	
	se_global->alua_tg_pt_gps_count++;
	spin_unlock(&se_global->tg_pt_gps_lock);

	return(tg_pt_gp);
}

extern void core_alua_free_tg_pt_gp (t10_alua_tg_pt_gp_t *tg_pt_gp)
{
	se_port_t *port, *port_tmp;

	spin_lock(&tg_pt_gp->tg_pt_gp_ref_lock);
	list_for_each_entry_safe(port, port_tmp, &tg_pt_gp->tg_pt_gp_ref_list,
			sep_tg_pt_gp_list) {
		list_del(&port->sep_tg_pt_gp_list);
		spin_lock(&port->sep_alua_lock);
		port->sep_alua_tg_pt_gp = NULL;
		spin_unlock(&port->sep_alua_lock);
	}
	spin_unlock(&tg_pt_gp->tg_pt_gp_ref_lock);

	spin_lock(&se_global->tg_pt_gps_lock);
	list_del(&tg_pt_gp->tg_pt_gp_list);
	se_global->alua_tg_pt_gps_counter--;
	spin_unlock(&se_global->tg_pt_gps_lock);

	kmem_cache_free(t10_alua_tg_pt_gp_cache, tg_pt_gp);
	return;
}

extern t10_alua_tg_pt_gp_t *core_alua_get_tg_pt_gp_by_name (se_port_t *port, const char *name)
{
	t10_alua_tg_pt_gp_t *tg_pt_gp;
	struct config_item *ci;

	spin_lock(&se_global->tg_pt_gps_lock);
	list_for_each_entry(tg_pt_gp, &se_global->g_tg_pt_gps_list, tg_pt_gp_list) {
		ci = &tg_pt_gp->tg_pt_gp_group.cg_item;
		if (!(strcmp(config_item_name(ci), name))) {
			atomic_inc(&tg_pt_gp->tg_pt_gp_ref_cnt);
			spin_unlock(&se_global->tg_pt_gps_lock);
			return(tg_pt_gp);
		}
	}
	spin_unlock(&se_global->tg_pt_gps_lock);

	return(NULL);
}

extern void core_alua_attach_tg_pt_gp (se_port_t *port, t10_alua_tg_pt_gp_t *tg_pt_gp)
{
	spin_lock(&port->sep_alua_lock);
	spin_lock(&tg_pt_gp->tg_pt_gp_ref_lock);
	list_add_tail(&port->sep_tg_pt_gp_list, &tg_pt_gp->tg_pt_gp_ref_list);
	tg_pt_gp->tg_pt_gp_members++;
	spin_unlock(&tg_pt_gp->tg_pt_gp_ref_lock);
	port->sep_alua_tg_pt_gp = tg_pt_gp;
	spin_unlock(&port->sep_alua_lock);

	return;
}

/*
 * Called with se_port_t->sep_alua_lock held.
 */
extern void __core_alua_put_tg_pt_gp (se_port_t *port, int clear)
{
	t10_alua_tg_pt_gp_t *tg_pt_gp;

	if (!(tg_pt_gp = port->sep_alua_tg_pt_gp))
		return;

	spin_lock(&tg_pt_gp->tg_pt_gp_ref_lock);
	list_del(&port->sep_tg_pt_gp_list);
	atomic_dec(&tg_pt_gp->tg_pt_gp_ref_cnt);
	tg_pt_gp->tg_pt_gp_members--;

	if (!(clear)) {
		spin_unlock(&tg_pt_gp->tg_pt_gp_ref_lock);
		return;
	}
	port->sep_alua_tg_pt_gp = NULL;
	spin_unlock(&tg_pt_gp->tg_pt_gp_ref_lock);

	return;
}

extern void core_alua_put_tg_pt_gp (se_port_t *port, int clear)
{
	t10_alua_tg_pt_gp_t *tg_pt_gp;

	spin_lock(&port->sep_alua_lock);
	if (!(tg_pt_gp = port->sep_alua_tg_pt_gp)) {
		spin_unlock(&port->sep_alua_lock);
		return;
	}
	spin_lock(&tg_pt_gp->tg_pt_gp_ref_lock);
	list_del(&port->sep_tg_pt_gp_list);
	atomic_dec(&tg_pt_gp->tg_pt_gp_ref_cnt);
	tg_pt_gp->tg_pt_gp_members--;

	if (!(clear)) {
		spin_unlock(&tg_pt_gp->tg_pt_gp_ref_lock);
		spin_unlock(&port->sep_alua_lock);
		return;
	}
	port->sep_alua_tg_pt_gp = NULL;
	spin_unlock(&tg_pt_gp->tg_pt_gp_ref_lock);
	spin_unlock(&port->sep_alua_lock);
	
	return;
}

extern ssize_t core_alua_show_tg_pt_gp_info (se_port_t *port, char *page)
{
	struct config_item *tg_pt_ci;
	t10_alua_tg_pt_gp_t *tg_pt_gp;
	ssize_t len = 0;

	spin_lock(&port->sep_alua_lock);
	if ((tg_pt_gp = port->sep_alua_tg_pt_gp)) {	
		tg_pt_ci = &tg_pt_gp->tg_pt_gp_group.cg_item;
		len += sprintf(page, "TG Port Alias: %s\nTG Port Group ID: %hu\n",
			config_item_name(tg_pt_ci), tg_pt_gp->tg_pt_gp_id);
	}
	spin_unlock(&port->sep_alua_lock);

	return(len);
}

EXPORT_SYMBOL(core_alua_show_tg_pt_gp_info);

extern ssize_t core_alua_store_tg_pt_gp_info (se_port_t *port, const char *page, size_t count)
{
	se_portal_group_t *tpg;
	se_lun_t *lun;
	t10_alua_tg_pt_gp_t *tg_pt_gp = NULL, *tg_pt_gp_new;
	unsigned char buf[256];
	int move = 0;

	if (count > 256) {
		printk(KERN_ERR "ALUA Target Port Group alias too large!\n");
		return(-EINVAL);
	}
	memset(buf, 0, 256);
	memcpy(buf, page, count);

	tpg = port->sep_tpg;
	lun = port->sep_lun;

	spin_lock(&port->sep_alua_lock);
	if ((tg_pt_gp = port->sep_alua_tg_pt_gp)) {
		if (!(strcmp(strstrip(buf), "NULL"))) {
			printk("Target_Core_ConfigFS: Releasing %s/tpgt_%hu/%s"
				" from ALUA Target Port Group: core/alua/tg_pt"
				"_gps/%s, ID: %hu\n",
				TPG_TFO(tpg)->tpg_get_wwn(tpg),
				TPG_TFO(tpg)->tpg_get_tag(tpg),
				config_item_name(&lun->lun_group.cg_item),
				config_item_name(&tg_pt_gp->tg_pt_gp_group.cg_item),
				tg_pt_gp->tg_pt_gp_id);
			
			__core_alua_put_tg_pt_gp(port, 1);
			spin_unlock(&port->sep_alua_lock);
			
			return(count);
		}
	}
	spin_unlock(&port->sep_alua_lock);

	if (!(tg_pt_gp_new = core_alua_get_tg_pt_gp_by_name(port, strstrip(buf))))
		return(-ENODEV);

	if (tg_pt_gp) {
		core_alua_put_tg_pt_gp(port, 0);
		move = 1;
	}
	core_alua_attach_tg_pt_gp(port, tg_pt_gp_new);

	printk("Target_Core_ConfigFS: %s %s/tpgt_%hu/%s to ALUA Target Port"
		" Group: core/alua/tg_pt_gps/%s, ID: %hu\n", (move) ?
		"Moving" : "Adding", TPG_TFO(tpg)->tpg_get_wwn(tpg),
		TPG_TFO(tpg)->tpg_get_tag(tpg),
		config_item_name(&lun->lun_group.cg_item),
		config_item_name(&tg_pt_gp_new->tg_pt_gp_group.cg_item),
		tg_pt_gp_new->tg_pt_gp_id);
	
	return(count);
}

EXPORT_SYMBOL(core_alua_store_tg_pt_gp_info);

extern int core_setup_alua (se_device_t *dev)
{
	se_subsystem_dev_t *su_dev = dev->se_sub_dev;
	t10_alua_t *alua = T10_ALUA(su_dev);
	/*
	 * If this device is from Target_Core_Mod/pSCSI, use the ALUA logic
	 * of the Underlying SCSI hardware.  In Linux/SCSI terms, this can
	 * cause a problem because libata and some SATA RAID HBAs appear
	 * under Linux/SCSI, but emulate SCSI logic themselves.
	 */ 
	if ((TRANSPORT(dev)->transport_type == TRANSPORT_PLUGIN_PHBA_PDEV) &&
	    !(DEV_ATTRIB(dev)->emulate_alua)) {
		alua->alua_type = SPC_ALUA_PASSTHROUGH;
		printk("%s: Using SPC_ALUA_PASSTHROUGH, no ALUA emulation\n",
				TRANSPORT(dev)->name);
		return(0);
	}
	/*
	 * If SPC-3 or above is reported by real or emulated se_device_t,
	 * use emulated ALUA.
	 */
	if (TRANSPORT(dev)->get_device_rev(dev) >= SCSI_3) {
		alua->alua_type = SPC3_ALUA_EMULATED;
		printk("%s: Enabling ALUA Emulation for SPC-3 device\n",
				TRANSPORT(dev)->name);
		/*
		 * Assoicate this se_device_t with the default ALUA
		 * LUN Group.
		 */
		core_alua_attach_lu_gp(dev, se_global->default_lu_gp);	
		printk("%s: Adding to default ALUA LU Group: core/alua"
			"/lu_gps/default_lu_gp\n", TRANSPORT(dev)->name);
	} else {
		alua->alua_type = SPC2_ALUA_DISABLED;
		printk("%s: Disabling ALUA Emulation for SPC-2 device\n",
				TRANSPORT(dev)->name);
	}

	return(0);
}
