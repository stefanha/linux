/*********************************************************************************
 * Filename:  target_core_pr.c
 *
 * This file contains SPC-3 compliant persistent reservations and
 * legacy SPC-2 reservations.
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

#define TARGET_CORE_PR_C

#include <linux/version.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <scsi/scsi.h>
#include <scsi/scsi_cmnd.h>

#include <target_core_base.h>
#include <target_core_device.h>
#include <target_core_hba.h>
#include <target_core_transport.h>
#include <target_core_pr.h>
#include <target_core_transport_plugin.h>
#include <target_core_fabric_ops.h>
#include <target_core_configfs.h>

#undef TARGET_CORE_PR_C

extern int core_scsi2_reservation_seq_non_holder (
	se_cmd_t *cmd,
	unsigned char *cdb)
{
	switch (cdb[0]) {
	case INQUIRY:
	case RELEASE:
	case RELEASE_10:
		return(0);
	default:
		return(1);
	}

	return(1);
}

extern int core_scsi2_reservation_check (se_cmd_t *cmd)
{
	se_device_t *dev = cmd->se_dev;
	se_session_t *sess = cmd->se_sess;
        int ret;

	if (!(sess))
		return(0);

        spin_lock(&dev->dev_reservation_lock);
        if (!dev->dev_reserved_node_acl || !sess) {
                spin_unlock(&dev->dev_reservation_lock);
                return(0);
        }
        ret = (dev->dev_reserved_node_acl != sess->se_node_acl) ? -1 : 0;
        spin_unlock(&dev->dev_reservation_lock);

        return(ret);
}

EXPORT_SYMBOL(core_scsi2_reservation_check);

extern int core_scsi2_reservation_release (se_cmd_t *cmd)
{
	se_device_t *dev = cmd->se_dev;
	se_session_t *sess = cmd->se_sess;
	se_portal_group_t *tpg = sess->se_tpg;

	if (!(sess) || !(tpg))
		return(0);

        spin_lock(&dev->dev_reservation_lock);
        if (!dev->dev_reserved_node_acl || !sess) {
                spin_unlock(&dev->dev_reservation_lock);
                return(0);
        }

        if (dev->dev_reserved_node_acl != sess->se_node_acl) {
                spin_unlock(&dev->dev_reservation_lock);
                return(0);
        }
        dev->dev_reserved_node_acl = NULL;
        printk("SCSI-2 Released reservation for %s LUN: %u -> MAPPED LUN:"
		" %u for %s\n", TPG_TFO(tpg)->get_fabric_name(),
		SE_LUN(cmd)->unpacked_lun, cmd->se_deve->mapped_lun,
		sess->se_node_acl->initiatorname);
        spin_unlock(&dev->dev_reservation_lock);

        return(0);
}

EXPORT_SYMBOL(core_scsi2_reservation_release);

extern int core_scsi2_reservation_reserve (se_cmd_t *cmd)
{
	se_device_t *dev = cmd->se_dev;
	se_session_t *sess = cmd->se_sess;
	se_portal_group_t *tpg = sess->se_tpg;

	if ((T_TASK(cmd)->t_task_cdb[1] & 0x01) &&
	    (T_TASK(cmd)->t_task_cdb[1] & 0x02)) {
		printk(KERN_ERR "LongIO and Obselete Bits set, returning"
				" ILLEGAL_REQUEST\n");
		return(-1);
	}

	/*
	 * This is currently the case for target_core_mod passthrough se_cmd_t ops
	 */
	if (!(sess) || !(tpg))
		return(0);

	spin_lock(&dev->dev_reservation_lock);
	if (dev->dev_reserved_node_acl &&
	   (dev->dev_reserved_node_acl != sess->se_node_acl)) {
		printk(KERN_ERR "SCSI-2 RESERVATION CONFLIFT for %s fabric\n",
			TPG_TFO(tpg)->get_fabric_name());
		printk(KERN_ERR "Original reserver LUN: %u %s\n",
			SE_LUN(cmd)->unpacked_lun,
			dev->dev_reserved_node_acl->initiatorname);
		printk(KERN_ERR "Current attempt - LUN: %u -> MAPPED LUN: %u"
			" from %s \n", SE_LUN(cmd)->unpacked_lun,
			cmd->se_deve->mapped_lun,
			sess->se_node_acl->initiatorname);
		spin_unlock(&dev->dev_reservation_lock);
		return(1);
        }

	dev->dev_reserved_node_acl = sess->se_node_acl;
	printk("SCSI-2 Reserved %s LUN: %u -> MAPPED LUN: %u for %s\n",
		TPG_TFO(tpg)->get_fabric_name(),
		SE_LUN(cmd)->unpacked_lun, cmd->se_deve->mapped_lun,
		sess->se_node_acl->initiatorname);
	spin_unlock(&dev->dev_reservation_lock);

        return(0);
}

EXPORT_SYMBOL(core_scsi2_reservation_reserve);

/*
 * Begin SPC-3/SPC-4 Persistent Reservations emulation support
 */
static int core_scsi3_pr_seq_non_holder (
	se_cmd_t *cmd,
	unsigned char *cdb)
{
	int registered_nexus = 0; // FIXME: Table 46
	int we = 0; // Write Exclusive
	int legacy = 0; // Act like a legacy device and return RESERVATION CONFLICT on some CDBs
	/*
	 * Referenced from spc4r17 table 45 for *NON* PR holder access
	 */
	switch (cdb[0]) {
	case SECURITY_PROTOCOL_IN:
		return((we) ? 0 : 1);
	case MODE_SENSE:
	case MODE_SENSE_10:
	case READ_ATTRIBUTE:
	case READ_BUFFER:
	case RECEIVE_DIAGNOSTIC:
		if (legacy)
			return(1);
		return((we) ? 0 : 1); // Allowed Write Exclusive
	case PERSISTENT_RESERVE_OUT:
		/*
		 * This follows PERSISTENT_RESERVE_OUT service actions that are allows
		 * in the presence of various reservations.  See spc4r17, table 46
		 */
		switch (cdb[1] & 0x1f) {
		case PRO_CLEAR:
		case PRO_PREEMPT:
		case PRO_PREEMPT_AND_ABORT:
			return((registered_nexus) ? 0 : 1);
		case PRO_REGISTER:
		case PRO_REGISTER_AND_IGNORE_EXISTING_KEY:
			return(0);
		case PRO_REGISTER_AND_MOVE:
		case PRO_RESERVE:
			return(1);
		case PRO_RELEASE:
			return((registered_nexus) ? 0 : 1);
		default:
			printk(KERN_ERR "Unknown PERSISTENT_RESERVE_OUT service"
				" action: 0x%02x\n", cdb[1] & 0x1f);
			return(-1);
		}
//FIXME PR + legacy RELEASE + RESERVE
	case RELEASE:
	case RELEASE_10:
		return(1); // Conflict
	case RESERVE:
	case RESERVE_10:
		return(1); // Conflict
	case TEST_UNIT_READY:
		return((legacy) ? 1 : 0); // Conflict for legacy
	case MAINTENANCE_IN:
		switch (cdb[1] & 0x1f) {
		case MI_MANAGEMENT_PROTOCOL_IN:	
			return((we) ? 0 : 1); // Allowed Write Exclusive
		case MI_REPORT_SUPPORTED_OPERATION_CODES:
		case MI_REPORT_SUPPORTED_TASK_MANAGEMENT_FUNCTIONS:
			if (legacy)
				return(1);
			return((we) ? 0 : 1); // Allowed Write Exclusive
		case MI_REPORT_ALIASES:
		case MI_REPORT_IDENTIFYING_INFORMATION:
		case MI_REPORT_PRIORITY:
		case MI_REPORT_TARGET_PGS:
		case MI_REPORT_TIMESTAMP:
			return(0); // Allowed
		default:
			printk(KERN_ERR "Unknown MI Service Action: 0x%02x\n",
				(cdb[1] & 0x1f));
			return(-1);
		}
	case ACCESS_CONTROL_IN:
	case ACCESS_CONTROL_OUT:
	case INQUIRY:
	case LOG_SENSE:
	case READ_MEDIA_SERIAL_NUMBER:
	case REPORT_LUNS:
	case REQUEST_SENSE:
		return(0); // Allowed CDBs
	default:
		return(1); // Conflift by default
        }

	return(1);
}

static int core_scsi3_pr_reservation_check (se_cmd_t *cmd)
{
	return(0);
}

static int core_scsi3_legacy_reserve (se_cmd_t *cmd)
{
	return(0);
}

static int core_scsi3_legacy_release (se_cmd_t *cmd)
{
	return(0);
}

static int core_scsi3_emulate_pro_register (se_cmd_t *cmd)
{
	return(0);
}

static int core_scsi3_emulate_pro_reserve (se_cmd_t *cmd)
{
	return(0);
}

static int core_scsi3_emulate_pro_release (se_cmd_t *cmd)
{
	return(0);
}

static int core_scsi3_emulate_pro_clear (se_cmd_t *cmd)
{
	return(0);
}

static int core_scsi3_emulate_pr_out (se_cmd_t *cmd, unsigned char *cdb)
{
	switch (cdb[1] & 0x1f) {
	case PRO_REGISTER:
		return(core_scsi3_emulate_pro_register(cmd));
	case PRO_RESERVE:
		return(core_scsi3_emulate_pro_reserve(cmd));
	case PRO_RELEASE:
		return(core_scsi3_emulate_pro_release(cmd));
	case PRO_CLEAR:
		return(core_scsi3_emulate_pro_clear(cmd));
	case PRO_PREEMPT:
	case PRO_PREEMPT_AND_ABORT:
	case PRO_REGISTER_AND_IGNORE_EXISTING_KEY:
	case PRO_REGISTER_AND_MOVE:
		printk(KERN_ERR "Unsupported PERSISTENT_RESERVE_OUT service"
			" action: 0x%02x\n", cdb[1] & 0x1f);
		return(-1);
	default:
		printk(KERN_ERR "Unknown PERSISTENT_RESERVE_OUT service"
			" action: 0x%02x\n", cdb[1] & 0x1f);
		return(-1);
	}

}

static int core_scsi3_pri_read_keys (se_cmd_t *cmd)
{
	return(0);
}

static int core_scsi3_pri_read_reservation (se_cmd_t *cmd)
{
	return(0);
}

static int core_scsi3_pri_report_capabilities (se_cmd_t *cmd)
{
	return(0);
}

static int core_scsi3_pri_read_full_status (se_cmd_t *cmd)
{
	return(0);
}

static int core_scsi3_emulate_pr_in (se_cmd_t *cmd, unsigned char *cdb)
{
	switch (cdb[1] & 0x1f) {
	case PRI_READ_KEYS:
		return(core_scsi3_pri_read_keys(cmd));
	case PRI_READ_RESERVATION:
		return(core_scsi3_pri_read_reservation(cmd));
	case PRI_REPORT_CAPABILITIES:
		return(core_scsi3_pri_report_capabilities(cmd));
	case PRI_READ_FULL_STATUS:
		return(core_scsi3_pri_read_full_status(cmd));
	default:
		printk(KERN_ERR "Unknown PERSISTENT_RESERVE_IN service"
			" action: 0x%02x\n", cdb[1] & 0x1f);
		return(-1);
	}

}

extern int core_scsi3_emulate_pr (se_cmd_t *cmd)
{
	unsigned char *cdb = &T_TASK(cmd)->t_task_cdb[0];

	return((cdb[0] == PERSISTENT_RESERVE_OUT) ?
	       core_scsi3_emulate_pr_out(cmd, cdb) :
	       core_scsi3_emulate_pr_in(cmd, cdb));
}

static int core_pt_reservation_check (se_cmd_t *cmd)
{
	return(0);
}

static int core_pt_reserve (se_cmd_t *cmd)
{
	return(0);
}

static int core_pt_release (se_cmd_t *cmd)
{
	return(0);
}

static int core_pt_seq_non_holder (se_cmd_t *cmd, unsigned char *cdb)
{
	return(0);
}

extern int core_setup_reservations (se_device_t *dev)
{
	se_subsystem_dev_t *su_dev = dev->se_sub_dev;
	t10_reservation_template_t *rest = &su_dev->t10_reservation;
	/*
	 * If this device is from Target_Core_Mod/pSCSI, use the reservations
	 * of the Underlying SCSI hardware.  In Linux/SCSI terms, this can
	 * cause a problem because libata and some SATA RAID HBAs appear
	 * under Linux/SCSI, but to emulate reservations themselves.
	 */ 
	if ((TRANSPORT(dev)->transport_type == TRANSPORT_PLUGIN_PHBA_PDEV) &&
	    !(DEV_ATTRIB(dev)->emulate_reservations)) {
		rest->res_type = SPC_PASSTHROUGH;
		rest->t10_reservation_check = &core_pt_reservation_check;
		rest->t10_reserve = &core_pt_reserve;
		rest->t10_release = &core_pt_release;
		rest->t10_seq_non_holder = &core_pt_seq_non_holder;
		printk("%s: Using SPC_PASSTHROUGH, no reservation emulation\n",
			TRANSPORT(dev)->name);
		return(0);
	}
	/*
	 * If SPC-3 or above is reported by real or emulated se_device_t,
	 * use emulated Persistent Reservations.
	 */
	if (TRANSPORT(dev)->get_device_rev(dev) >= SCSI_3) {
		rest->res_type = SPC3_PERSISTENT_RESERVATIONS;
		rest->t10_reservation_check = &core_scsi3_pr_reservation_check;
		rest->t10_reserve = &core_scsi3_legacy_reserve;
		rest->t10_release = &core_scsi3_legacy_release;
		rest->t10_seq_non_holder = &core_scsi3_pr_seq_non_holder;
		printk("%s: Using SPC3_PERSISTENT_RESERVATIONS emulation\n",
			TRANSPORT(dev)->name);
	} else {
		rest->res_type = SPC2_RESERVATIONS;
		rest->t10_reservation_check = &core_scsi2_reservation_check;
		rest->t10_reserve = &core_scsi2_reservation_reserve;
		rest->t10_release = &core_scsi2_reservation_release;
		rest->t10_seq_non_holder = &core_scsi2_reservation_seq_non_holder;
		printk("%s: Using SPC2_RESERVATIONS emulation\n",
			TRANSPORT(dev)->name);
	}

	return(0);
}
