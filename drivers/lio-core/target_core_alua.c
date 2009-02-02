/*********************************************************************************
 * Filename:  target_core_pr.c
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

extern int core_scsi3_emulate_report_target_port_groups (se_cmd_t *cmd)
{
	se_lun_t *lun = SE_LUN(cmd);
	se_port_t *port;
	unsigned char *buf = (unsigned char *)T_TASK(cmd)->t_task_buf;
	u32 rd_len = 0, off = 4;
	u16 tg_pg = 0;
	u8 tg_pg_count = 1; // Assume 1 for now
	
	if (!(lun)) {
		printk(KERN_ERR "SPC-3 ALUA se_lun_t is NULL!\n");
		return(PYX_TRANSPORT_LOGICAL_UNIT_COMMUNICATION_FAILURE);
	}
	if (!(port = lun->lun_sep)) {
		printk(KERN_ERR "SPC-3 ALUA se_port_t is NULL\n");
		return(PYX_TRANSPORT_LOGICAL_UNIT_COMMUNICATION_FAILURE);
	}
	/*
	 * PREF: Preferred target port bit
	 */
//	buf[off] = 0x80;
	/*
	 * Set the ASYMMETRIC ACCESS State
	 */
	buf[off++] |= ALUA_ACCESS_STATE_ACTIVE_OPTMIZED;
	/*
	 * Set supported ASYMMETRIC ACCESS State bits
	 */
//	buf[off] = 0x80; // T_SUP
//	buf[off] |= 0x40; // O_SUP
//	buf[off] |= 0x8; // U_SUP
//	buf[off] |= 0x4; // S_SUP
//	buf[off] |= 0x2; // AN_SUP
	buf[off++] |= 0x1; // AO_SUP
	/*
	 * TARGET PORT GROUP
	 */
	buf[off++] = ((tg_pg >> 8) & 0xff);
	buf[off++] = (tg_pg & 0xff);
	
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
	buf[off++] = tg_pg_count;

	rd_len += 8;
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
	/*
	 * Set the RETURN DATA LENGTH set in the header of the DataIN Payload
	 */
	buf[0] = ((rd_len >> 24) & 0xff);
	buf[1] = ((rd_len >> 16) & 0xff);
	buf[2] = ((rd_len >> 8) & 0xff);
	buf[3] = (rd_len & 0xff);

	return(0);	
}

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
	} else {
		alua->alua_type = SPC2_ALUA_DISABLED;
		printk("%s: Disabling ALUA for SPC-2 device\n",
				TRANSPORT(dev)->name);
	}

	return(0);
}
