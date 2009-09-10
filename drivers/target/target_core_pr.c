/*******************************************************************************
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
 ******************************************************************************/

#define TARGET_CORE_PR_C

#include <linux/version.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/list.h>
#include <scsi/scsi.h>
#include <scsi/scsi_cmnd.h>

#include <target/target_core_base.h>
#include <target/target_core_device.h>
#include <target/target_core_hba.h>
#include <target/target_core_tmr.h>
#include <target/target_core_tpg.h>
#include <target/target_core_transport.h>
#include <target/target_core_pr.h>
#include <target/target_core_ua.h>
#include <target/target_core_transport_plugin.h>
#include <target/target_core_fabric_ops.h>
#include <target/target_core_configfs.h>

#undef TARGET_CORE_PR_C

/*
 * Used for Specify Initiator Ports Capable Bit (SPEC_I_PT)
 */
struct pr_transport_id_holder {
	int dest_local_nexus;
	struct t10_pr_registration_s *dest_pr_reg;
	struct se_node_acl_s *dest_node_acl;
	struct se_dev_entry_s *dest_se_deve;
	struct list_head dest_list;
};

static void __core_scsi3_complete_pro_release(se_device_t *, se_node_acl_t *,
			t10_pr_registration_t *, int);

int core_scsi2_reservation_seq_non_holder(
	se_cmd_t *cmd,
	unsigned char *cdb,
	u32 pr_reg_type)
{
	switch (cdb[0]) {
	case INQUIRY:
	case RELEASE:
	case RELEASE_10:
		return 0;
	default:
		return 1;
	}

	return 1;
}

int core_scsi2_reservation_check(se_cmd_t *cmd, u32 *pr_reg_type)
{
	se_device_t *dev = cmd->se_dev;
	se_session_t *sess = cmd->se_sess;
	int ret;

	if (!(sess))
		return 0;

	spin_lock(&dev->dev_reservation_lock);
	if (!dev->dev_reserved_node_acl || !sess) {
		spin_unlock(&dev->dev_reservation_lock);
		return 0;
	}
	ret = (dev->dev_reserved_node_acl != sess->se_node_acl) ? -1 : 0;
	spin_unlock(&dev->dev_reservation_lock);

	return ret;
}
EXPORT_SYMBOL(core_scsi2_reservation_check);

int core_scsi2_reservation_release(se_cmd_t *cmd)
{
	se_device_t *dev = cmd->se_dev;
	se_session_t *sess = cmd->se_sess;
	se_portal_group_t *tpg = sess->se_tpg;

	if (!(sess) || !(tpg))
		return 0;

	spin_lock(&dev->dev_reservation_lock);
	if (!dev->dev_reserved_node_acl || !sess) {
		spin_unlock(&dev->dev_reservation_lock);
		return 0;
	}

	if (dev->dev_reserved_node_acl != sess->se_node_acl) {
		spin_unlock(&dev->dev_reservation_lock);
		return 0;
	}
	dev->dev_reserved_node_acl = NULL;
	printk(KERN_INFO "SCSI-2 Released reservation for %s LUN: %u ->"
		" MAPPED LUN: %u for %s\n", TPG_TFO(tpg)->get_fabric_name(),
		SE_LUN(cmd)->unpacked_lun, cmd->se_deve->mapped_lun,
		sess->se_node_acl->initiatorname);
	spin_unlock(&dev->dev_reservation_lock);

	return 0;
}
EXPORT_SYMBOL(core_scsi2_reservation_release);

int core_scsi2_reservation_reserve(se_cmd_t *cmd)
{
	se_device_t *dev = cmd->se_dev;
	se_session_t *sess = cmd->se_sess;
	se_portal_group_t *tpg = sess->se_tpg;

	if ((T_TASK(cmd)->t_task_cdb[1] & 0x01) &&
	    (T_TASK(cmd)->t_task_cdb[1] & 0x02)) {
		printk(KERN_ERR "LongIO and Obselete Bits set, returning"
				" ILLEGAL_REQUEST\n");
		return -1;
	}

	/*
	 * This is currently the case for target_core_mod passthrough se_cmd_t
	 * ops
	 */
	if (!(sess) || !(tpg))
		return 0;

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
		return 1;
	}

	dev->dev_reserved_node_acl = sess->se_node_acl;
	dev->dev_flags |= DF_SPC2_RESERVATIONS;
	printk(KERN_INFO "SCSI-2 Reserved %s LUN: %u -> MAPPED LUN: %u"
		" for %s\n", TPG_TFO(tpg)->get_fabric_name(),
		SE_LUN(cmd)->unpacked_lun, cmd->se_deve->mapped_lun,
		sess->se_node_acl->initiatorname);
	spin_unlock(&dev->dev_reservation_lock);

	return 0;
}
EXPORT_SYMBOL(core_scsi2_reservation_reserve);

/*
 * Begin SPC-3/SPC-4 Persistent Reservations emulation support
 *
 * This function is called by those initiator ports who are *NOT*
 * the active PR reservation holder when a reservation is present.
 */
static int core_scsi3_pr_seq_non_holder(
	se_cmd_t *cmd,
	unsigned char *cdb,
	u32 pr_reg_type)
{
	se_dev_entry_t *se_deve;
	se_session_t *se_sess = SE_SESS(cmd);
	int other_cdb = 0;
	int registered_nexus = 0, ret = 1; /* Conflict by default */
	int all_reg = 0, reg_only = 0; /* ALL_REG, REG_ONLY */
	int we = 0; /* Write Exclusive */
	int legacy = 0; /* Act like a legacy device and return
			 * RESERVATION CONFLICT on some CDBs */

	se_deve = &se_sess->se_node_acl->device_list[cmd->orig_fe_lun];

	switch (pr_reg_type) {
	case PR_TYPE_WRITE_EXCLUSIVE:
		we = 1;
	case PR_TYPE_EXCLUSIVE_ACCESS:
		/*
		 * Some commands are only allowed for the persistent reservation
		 * holder.
		 */
		if (se_deve->deve_flags & DEF_PR_REGISTERED)
			registered_nexus = 1;
		break;
	case PR_TYPE_WRITE_EXCLUSIVE_REGONLY:
		we = 1;
	case PR_TYPE_EXCLUSIVE_ACCESS_REGONLY:
		/*
		 * Some commands are only allowed for registered I_T Nexuses.
		 */
		reg_only = 1;
		if (se_deve->deve_flags & DEF_PR_REGISTERED)
			registered_nexus = 1;
		break;
	case PR_TYPE_WRITE_EXCLUSIVE_ALLREG:
		we = 1;
	case PR_TYPE_EXCLUSIVE_ACCESS_ALLREG:
		/*
		 * Each registered I_T Nexus is a reservation holder.
		 */
		all_reg = 1;
		if (se_deve->deve_flags & DEF_PR_REGISTERED)
			registered_nexus = 1;
		break;
	default:
		return -1;
	}
	/*
	 * Referenced from spc4r17 table 45 for *NON* PR holder access
	 */
	switch (cdb[0]) {
	case SECURITY_PROTOCOL_IN:
		if (registered_nexus)
			return 0;
		ret = (we) ? 0 : 1;
		break;
	case MODE_SENSE:
	case MODE_SENSE_10:
	case READ_ATTRIBUTE:
	case READ_BUFFER:
	case RECEIVE_DIAGNOSTIC:
		if (legacy) {
			ret = 1;
			break;
		}
		if (registered_nexus) {
			ret = 0;
			break;
		}
		ret = (we) ? 0 : 1; /* Allowed Write Exclusive */
		break;
	case PERSISTENT_RESERVE_OUT:
		/*
		 * This follows PERSISTENT_RESERVE_OUT service actions that
		 * are allowed in the presence of various reservations.
		 * See spc4r17, table 46
		 */
		switch (cdb[1] & 0x1f) {
		case PRO_CLEAR:
		case PRO_PREEMPT:
		case PRO_PREEMPT_AND_ABORT:
			ret = (registered_nexus) ? 0 : 1;
			break;
		case PRO_REGISTER:
		case PRO_REGISTER_AND_IGNORE_EXISTING_KEY:
			ret = 0;
			break;
		case PRO_REGISTER_AND_MOVE:
		case PRO_RESERVE:
			ret = 1;
			break;
		case PRO_RELEASE:
			ret = (registered_nexus) ? 0 : 1;
			break;
		default:
			printk(KERN_ERR "Unknown PERSISTENT_RESERVE_OUT service"
				" action: 0x%02x\n", cdb[1] & 0x1f);
			return -1;
		}
		break;
	/* FIXME PR + legacy RELEASE + RESERVE */
	case RELEASE:
	case RELEASE_10:
		ret = 1; /* Conflict */
		break;
	case RESERVE:
	case RESERVE_10:
		ret = 1; /* Conflict */
		break;
	case TEST_UNIT_READY:
		ret = (legacy) ? 1 : 0; /* Conflict for legacy */
		break;
	case MAINTENANCE_IN:
		switch (cdb[1] & 0x1f) {
		case MI_MANAGEMENT_PROTOCOL_IN:
			if (registered_nexus) {
				ret = 0;
				break;
			}
			ret = (we) ? 0 : 1; /* Allowed Write Exclusive */
			break;
		case MI_REPORT_SUPPORTED_OPERATION_CODES:
		case MI_REPORT_SUPPORTED_TASK_MANAGEMENT_FUNCTIONS:
			if (legacy) {
				ret = 1;
				break;
			}
			if (registered_nexus) {
				ret = 0;
				break;
			}
			ret = (we) ? 0 : 1; /* Allowed Write Exclusive */
			break;
		case MI_REPORT_ALIASES:
		case MI_REPORT_IDENTIFYING_INFORMATION:
		case MI_REPORT_PRIORITY:
		case MI_REPORT_TARGET_PGS:
		case MI_REPORT_TIMESTAMP:
			ret = 0; /* Allowed */
			break;
		default:
			printk(KERN_ERR "Unknown MI Service Action: 0x%02x\n",
				(cdb[1] & 0x1f));
			return -1;
		}
		break;
	case ACCESS_CONTROL_IN:
	case ACCESS_CONTROL_OUT:
	case INQUIRY:
	case LOG_SENSE:
	case READ_MEDIA_SERIAL_NUMBER:
	case REPORT_LUNS:
	case REQUEST_SENSE:
		ret = 0; /*/ Allowed CDBs */
		break;
	default:
		other_cdb = 1;
		break;
	}
	/*
	 * Case where the CDB is explictly allowed in the above switch
	 * statement.
	 */
	if (!(ret) && !(other_cdb)) {
#if 0
		printk(KERN_INFO "Allowing explict CDB: 0x%02x for %s"
			" reservation holder\n", cdb[0],
			core_scsi3_pr_dump_type(pr_reg_type));
#endif
		return ret;
	}
	/*
	 * Check if write exclusive initiator ports *NOT* holding the
	 * WRITE_EXCLUSIVE_* reservation.
	 */
	if ((we) && !(registered_nexus)) {
		if ((cmd->data_direction == SE_DIRECTION_WRITE) ||
		    (cmd->data_direction == SE_DIRECTION_BIDI)) {
			/*
			 * Conflict for write exclusive
			 */
			printk(KERN_INFO "%s Conflict for unregistered nexus"
				" %s CDB: 0x%02x to %s reservation\n",
				transport_dump_cmd_direction(cmd),
				se_sess->se_node_acl->initiatorname, cdb[0],
				core_scsi3_pr_dump_type(pr_reg_type));
			return 1;
		} else {
			/*
			 * Allow non WRITE CDBs for all Write Exclusive
			 * PR TYPEs to pass for registered and
			 * non-registered_nexuxes NOT holding the reservation.
			 *
			 * We only make noise for the unregisterd nexuses,
			 * as we expect registered non-reservation holding
			 * nexuses to issue CDBs.
			 */
#if 0
			if (!(registered_nexus)) {
				printk(KERN_INFO "Allowing implict CDB: 0x%02x"
					" for %s reservation on unregistered"
					" nexus\n", cdb[0],
					core_scsi3_pr_dump_type(pr_reg_type));
			}
#endif
			return 0;
		}
	} else if ((reg_only) || (all_reg)) {
		if (registered_nexus) {
			/*
			 * For PR_*_REG_ONLY and PR_*_ALL_REG reservations,
			 * allow commands from registered nexuses.
			 */
#if 0
			printk(KERN_INFO "Allowing implict CDB: 0x%02x for %s"
				" reservation\n", cdb[0],
				core_scsi3_pr_dump_type(pr_reg_type));
#endif
			return 0;
		}
	}
	printk(KERN_INFO "%s Conflict for %sregistered nexus %s CDB: 0x%2x"
		" for %s reservation\n", transport_dump_cmd_direction(cmd),
		(registered_nexus) ? "" : "un",
		se_sess->se_node_acl->initiatorname, cdb[0],
		core_scsi3_pr_dump_type(pr_reg_type));

	return 1; /* Conflict by default */
}

static u32 core_scsi3_pr_generation(se_device_t *dev)
{
	se_subsystem_dev_t *su_dev = SU_DEV(dev);
	u32 prg;
	/*
	 * PRGeneration field shall contain the value of a 32-bit wrapping
	 * counter mainted by the device server.
	 *
	 * Note that this is done regardless of Active Persist across
	 * Target PowerLoss (APTPL)
	 *
	 * See spc4r17 section 6.3.12 READ_KEYS service action
	 */
	spin_lock(&dev->dev_reservation_lock);
	prg = T10_RES(su_dev)->pr_generation++;
	spin_unlock(&dev->dev_reservation_lock);

	return prg;
}

static int core_scsi3_pr_reservation_check(
	se_cmd_t *cmd,
	u32 *pr_reg_type)
{
	se_device_t *dev = cmd->se_dev;
	se_session_t *sess = cmd->se_sess;
	int ret;

	if (!(sess))
		return 0;

	spin_lock(&dev->dev_reservation_lock);
	if (!(dev->dev_pr_res_holder)) {
		spin_unlock(&dev->dev_reservation_lock);
		return 0;
	}
	*pr_reg_type = dev->dev_pr_res_holder->pr_res_type;
	cmd->pr_res_key = dev->dev_pr_res_holder->pr_res_key;
	ret = (dev->dev_pr_res_holder->pr_reg_nacl != sess->se_node_acl) ?
		-1 : 0;
	spin_unlock(&dev->dev_reservation_lock);

	return ret;
}

static int core_scsi3_legacy_reserve(se_cmd_t *cmd)
{
	/*
	 * FIXME: See spc4r17 Section 5.7.3
	 */
	return core_scsi2_reservation_reserve(cmd);
}

static int core_scsi3_legacy_release(se_cmd_t *cmd)
{
	/*
	 * FIXME: See spc4r17 Section 5.7.3
	 */
	return core_scsi2_reservation_release(cmd);
}

static t10_pr_registration_t *__core_scsi3_alloc_registration(
	se_device_t *dev,
	se_node_acl_t *nacl,
	se_dev_entry_t *deve,
	u64 sa_res_key,
	int all_tg_pt,
	int aptpl)
{
	se_subsystem_dev_t *su_dev = SU_DEV(dev);
	t10_pr_registration_t *pr_reg;

	pr_reg = kmem_cache_zalloc(t10_pr_reg_cache, GFP_ATOMIC);
	if (!(pr_reg)) {
		printk(KERN_ERR "Unable to allocate t10_pr_registration_t\n");
		return NULL;
	}

	pr_reg->pr_aptpl_buf = kzalloc(T10_RES(su_dev)->pr_aptpl_buf_len,
					GFP_ATOMIC);
	if (!(pr_reg->pr_aptpl_buf)) {
		printk(KERN_ERR "Unable to allocate pr_reg->pr_aptpl_buf\n");
		kmem_cache_free(t10_pr_reg_cache, pr_reg);
		return NULL;
	}

	INIT_LIST_HEAD(&pr_reg->pr_reg_list);
	INIT_LIST_HEAD(&pr_reg->pr_reg_abort_list);
	INIT_LIST_HEAD(&pr_reg->pr_reg_aptpl_list);
	atomic_set(&pr_reg->pr_res_holders, 0);
	pr_reg->pr_reg_nacl = nacl;
	pr_reg->pr_reg_deve = deve;
	pr_reg->pr_res_mapped_lun = deve->mapped_lun;
	pr_reg->pr_aptpl_target_lun = deve->se_lun->unpacked_lun;
	pr_reg->pr_res_key = sa_res_key;
	pr_reg->pr_reg_all_tg_pt = all_tg_pt;
	pr_reg->pr_reg_aptpl = aptpl;
	pr_reg->pr_reg_tg_pt_lun = deve->se_lun;

	return pr_reg;
}

int core_scsi3_alloc_aptpl_registration(
	t10_reservation_template_t *pr_tmpl,
	u64 sa_res_key,
	unsigned char *i_port,
	u32 mapped_lun,
	unsigned char *t_port,
	u16 tpgt,
	u32 target_lun,
	int res_holder,
	int all_tg_pt,
	u8 type)
{
	t10_pr_registration_t *pr_reg;

	if (!(i_port) || !(t_port) || !(sa_res_key)) {
		printk(KERN_ERR "Illegal parameters for APTPL registration\n");
		return -1;
	}

	pr_reg = kmem_cache_zalloc(t10_pr_reg_cache, GFP_KERNEL);
	if (!(pr_reg)) {
		printk(KERN_ERR "Unable to allocate t10_pr_registration_t\n");
		return -1;
	}
	pr_reg->pr_aptpl_buf = kzalloc(pr_tmpl->pr_aptpl_buf_len, GFP_KERNEL);

	INIT_LIST_HEAD(&pr_reg->pr_reg_list);
	INIT_LIST_HEAD(&pr_reg->pr_reg_abort_list);
	INIT_LIST_HEAD(&pr_reg->pr_reg_aptpl_list);
	atomic_set(&pr_reg->pr_res_holders, 0);
	pr_reg->pr_reg_nacl = NULL;
	pr_reg->pr_reg_deve = NULL;
	pr_reg->pr_res_mapped_lun = mapped_lun;
	pr_reg->pr_aptpl_target_lun = target_lun;
	pr_reg->pr_res_key = sa_res_key;
	pr_reg->pr_reg_all_tg_pt = all_tg_pt;
	pr_reg->pr_reg_aptpl = 1;
	pr_reg->pr_reg_tg_pt_lun = NULL;
	pr_reg->pr_res_scope = 0; /* Always LUN_SCOPE */
	pr_reg->pr_res_type = type;
	/*
	 * Copy the i_port and t_port information from caller.
	 */
	snprintf(pr_reg->pr_iport, PR_APTPL_MAX_IPORT_LEN, "%s", i_port);
	snprintf(pr_reg->pr_tport, PR_APTPL_MAX_TPORT_LEN, "%s", t_port);
	pr_reg->pr_reg_tpgt = tpgt;
	/*
	 * Set pr_res_holder from caller, the pr_reg who is the reservation
	 * holder will get it's pointer set in core_scsi3_aptpl_reserve() once
	 * the Initiator Node LUN ACL from the fabric module is created for
	 * this registration.
	 */
	pr_reg->pr_res_holder = res_holder;

	list_add_tail(&pr_reg->pr_reg_aptpl_list, &pr_tmpl->aptpl_reg_list);
	printk(KERN_INFO "SPC-3 PR APTPL Successfully added registration%s from"
			" metadata\n", (res_holder) ? "+reservation" : "");
	return 0;
}

static void core_scsi3_aptpl_reserve(
	se_device_t *dev,
	se_portal_group_t *tpg,
	se_node_acl_t *node_acl,
	t10_pr_registration_t *pr_reg)
{
	spin_lock(&dev->dev_reservation_lock);
	dev->dev_pr_res_holder = pr_reg;
	spin_unlock(&dev->dev_reservation_lock);

	printk(KERN_INFO "SPC-3 PR [%s] Service Action: APTPL RESERVE created"
		" new reservation holder TYPE: %s ALL_TG_PT: %d\n",
		TPG_TFO(tpg)->get_fabric_name(),
		core_scsi3_pr_dump_type(pr_reg->pr_res_type),
		(pr_reg->pr_reg_all_tg_pt) ? 1 : 0);
	printk(KERN_INFO "SPC-3 PR [%s] RESERVE Node: %s\n",
		TPG_TFO(tpg)->get_fabric_name(), node_acl->initiatorname);
}

static void __core_scsi3_add_registration(se_device_t *, se_node_acl_t *,
				t10_pr_registration_t *, int, int);

static int __core_scsi3_check_aptpl_registration(
	se_device_t *dev,
	se_portal_group_t *tpg,
	se_lun_t *lun,
	u32 target_lun,
	se_node_acl_t *nacl,
	se_dev_entry_t *deve)
{
	t10_pr_registration_t *pr_reg, *pr_reg_tmp;
	t10_reservation_template_t *pr_tmpl = &SU_DEV(dev)->t10_reservation;
	unsigned char i_port[PR_APTPL_MAX_IPORT_LEN];
	unsigned char t_port[PR_APTPL_MAX_TPORT_LEN];
	u16 tpgt;

	memset(i_port, 0, PR_APTPL_MAX_IPORT_LEN);
	memset(t_port, 0, PR_APTPL_MAX_TPORT_LEN);
	/*
	 * Copy Initiator Port information from se_node_acl_t
	 */
	snprintf(i_port, PR_APTPL_MAX_IPORT_LEN, "%s", nacl->initiatorname);
	snprintf(t_port, PR_APTPL_MAX_TPORT_LEN, "%s",
			TPG_TFO(tpg)->tpg_get_wwn(tpg));
	tpgt = TPG_TFO(tpg)->tpg_get_tag(tpg);

	spin_lock(&pr_tmpl->aptpl_reg_lock);
	list_for_each_entry_safe(pr_reg, pr_reg_tmp, &pr_tmpl->aptpl_reg_list,
				pr_reg_aptpl_list) {
		if (!(strcmp(pr_reg->pr_iport, i_port)) &&
		     (pr_reg->pr_res_mapped_lun == deve->mapped_lun) &&
		    !(strcmp(pr_reg->pr_tport, t_port)) &&
		     (pr_reg->pr_reg_tpgt == tpgt) &&
		     (pr_reg->pr_aptpl_target_lun == target_lun)) {

			pr_reg->pr_reg_nacl = nacl;
			pr_reg->pr_reg_deve = deve;
			pr_reg->pr_reg_tg_pt_lun = lun;

			list_del(&pr_reg->pr_reg_aptpl_list);
			spin_unlock(&pr_tmpl->aptpl_reg_lock);
			/*
			 * At this point all of the pointers in *pr_reg will
			 * be setup, so go ahead and add the registration.
			 */

			__core_scsi3_add_registration(dev, nacl, pr_reg, 0, 0);
			/*
			 * If this registration is the reservation holder,
			 * make that happen now..
			 */
			if (pr_reg->pr_res_holder)
				core_scsi3_aptpl_reserve(dev, tpg,
						nacl, pr_reg);
			/*
			 * Reenable pr_aptpl_active to accept new metadata
			 * updates once the SCSI device is active again..
			 */
			pr_tmpl->pr_aptpl_active = 1;

			return 1;
		}
	}
	spin_unlock(&pr_tmpl->aptpl_reg_lock);

	return 0;
}

int core_scsi3_check_aptpl_registration(
	se_device_t *dev,
	se_portal_group_t *tpg,
	se_lun_t *lun,
	se_lun_acl_t *lun_acl)
{
	se_subsystem_dev_t *su_dev = SU_DEV(dev);
	se_node_acl_t *nacl = lun_acl->se_lun_nacl;
	se_dev_entry_t *deve = &nacl->device_list[lun_acl->mapped_lun];

	if (T10_RES(su_dev)->res_type != SPC3_PERSISTENT_RESERVATIONS)
		return 0;

	return __core_scsi3_check_aptpl_registration(dev, tpg, lun,
				lun->unpacked_lun, nacl, deve);
}

/*
 * this function can be called with se_device_t->dev_reservation_lock
 * when register_move = 1
 */
static void __core_scsi3_add_registration(
	se_device_t *dev,
	se_node_acl_t *nacl,
	t10_pr_registration_t *pr_reg,
	int register_type,
	int register_move)
{
	se_subsystem_dev_t *su_dev = SU_DEV(dev);
	struct target_core_fabric_ops *tfo = nacl->se_tpg->se_tpg_tfo;
	t10_reservation_template_t *pr_tmpl = &SU_DEV(dev)->t10_reservation;

	/*
	 * Increment PRgeneration counter for se_device_t upon a successful
	 * REGISTER, see spc4r17 section 6.3.2 READ_KEYS service action
	 *
	 * Also, when register_move = 1 for PROUT REGISTER_AND_MOVE service
	 * action, the se_device_t->dev_reservation_lock will already be held,
	 * so we do not call core_scsi3_pr_generation() which grabs the lock
	 * for the REGISTER.
	 */
	pr_reg->pr_res_generation = (register_move) ?
			T10_RES(su_dev)->pr_generation++ :
			core_scsi3_pr_generation(dev);

	spin_lock(&pr_tmpl->registration_lock);
	list_add_tail(&pr_reg->pr_reg_list, &pr_tmpl->registration_list);
	pr_reg->pr_reg_deve->deve_flags |= DEF_PR_REGISTERED;

	printk(KERN_INFO "SPC-3 PR [%s] Service Action: REGISTER%s Initiator"
		" Node: %s\n", tfo->get_fabric_name(), (register_type == 2) ?
		"_AND_MOVE" : (register_type == 1) ?
		"_AND_IGNORE_EXISTING_KEY" : "", nacl->initiatorname);
	printk(KERN_INFO "SPC-3 PR [%s] for %s TCM Subsystem %s Object Target"
		" Port(s)\n",  tfo->get_fabric_name(),
		(pr_reg->pr_reg_all_tg_pt) ? "ALL" : "SINGLE",
		TRANSPORT(dev)->name);
	printk(KERN_INFO "SPC-3 PR [%s] SA Res Key: 0x%016Lx PRgeneration:"
		" 0x%08x  APTPL: %d\n", tfo->get_fabric_name(),
		pr_reg->pr_res_key, pr_reg->pr_res_generation,
		pr_reg->pr_reg_aptpl);
	spin_unlock(&pr_tmpl->registration_lock);

	return;
}

static int core_scsi3_alloc_registration(
	se_device_t *dev,
	se_node_acl_t *nacl,
	se_dev_entry_t *deve,
	u64 sa_res_key,
	int all_tg_pt,
	int aptpl,
	int register_type,
	int register_move)
{
	t10_pr_registration_t *pr_reg;

	pr_reg = __core_scsi3_alloc_registration(dev, nacl, deve,
			sa_res_key, all_tg_pt, aptpl);
	if (!(pr_reg))
		return -1;

	__core_scsi3_add_registration(dev, nacl, pr_reg,
			register_type, register_move);
	return 0;
}

static t10_pr_registration_t *core_scsi3_locate_pr_reg(
	se_device_t *dev,
	se_node_acl_t *nacl)
{
	t10_reservation_template_t *pr_tmpl = &SU_DEV(dev)->t10_reservation;
	t10_pr_registration_t *pr_reg, *pr_reg_tmp;

	spin_lock(&pr_tmpl->registration_lock);
	list_for_each_entry_safe(pr_reg, pr_reg_tmp,
			&pr_tmpl->registration_list, pr_reg_list) {
		if (pr_reg->pr_reg_nacl == nacl) {
			atomic_inc(&pr_reg->pr_res_holders);
			smp_mb__after_atomic_inc();
			spin_unlock(&pr_tmpl->registration_lock);
			return pr_reg;
		}
	}
	spin_unlock(&pr_tmpl->registration_lock);

	return NULL;
}

static void core_scsi3_put_pr_reg(t10_pr_registration_t *pr_reg)
{
	atomic_dec(&pr_reg->pr_res_holders);
	smp_mb__after_atomic_dec();
}

static int core_scsi3_check_implict_release(
	se_device_t *dev,
	t10_pr_registration_t *pr_reg)
{
	se_node_acl_t *nacl = pr_reg->pr_reg_nacl;
	t10_pr_registration_t *pr_res_holder;
	int ret = 0;

	spin_lock(&dev->dev_reservation_lock);
	pr_res_holder = dev->dev_pr_res_holder;
	if ((pr_res_holder != NULL) && (pr_res_holder == pr_reg)) {
		/*
		 * Perform an implict RELEASE if the registration that
		 * is being released is holding the reservation.
		 *
		 * From spc4r17, section 5.7.11.1:
		 *
		 * e) If the I_T nexus is the persistent reservation holder
		 *    and the persistent reservation is not an all registrants
		 *    type, then a PERSISTENT RESERVE OUT command with REGISTER
		 *    service action or REGISTER AND  IGNORE EXISTING KEY
		 *    service action with the SERVICE ACTION RESERVATION KEY
		 *    field set to zero (see 5.7.11.3).
		 */
		__core_scsi3_complete_pro_release(dev, nacl, pr_reg, 0);
		ret = 1;
/* #warning FIXME: All Registrants, only release reservation when
   last registration is freed. */
	}
	spin_unlock(&dev->dev_reservation_lock);

	return ret;
}

/*
 * Called with t10_reservation_template_t->registration_lock held.
 */
static void __core_scsi3_free_registration(
	se_device_t *dev,
	t10_pr_registration_t *pr_reg,
	struct list_head *preempt_and_abort_list,
	int dec_holders)
{
	struct target_core_fabric_ops *tfo =
			pr_reg->pr_reg_nacl->se_tpg->se_tpg_tfo;
	t10_reservation_template_t *pr_tmpl = &SU_DEV(dev)->t10_reservation;

	pr_reg->pr_reg_deve->deve_flags &= ~DEF_PR_REGISTERED;
	pr_reg->pr_reg_deve->pr_res_key = 0;
	list_del(&pr_reg->pr_reg_list);
	/*
	 * Caller accessing *pr_reg using core_scsi3_locate_pr_reg(),
	 * so call core_scsi3_put_pr_reg() to decrement our reference.
	 */
	if (dec_holders)
		core_scsi3_put_pr_reg(pr_reg);
	/*
	 * Wait until all reference from any other I_T nexuses for this
	 * *pr_reg have been released.  Because list_del() is called above,
	 * the last core_scsi3_put_pr_reg(pr_reg) will release this reference
	 * count back to zero, and we release *pr_reg.
	 */
	while (atomic_read(&pr_reg->pr_res_holders) != 0) {
		spin_unlock(&pr_tmpl->registration_lock);
		printk("SPC-3 PR [%s] waiting for pr_res_holders\n",
				tfo->get_fabric_name());
		msleep(10);
		spin_lock(&pr_tmpl->registration_lock);
	}

	printk(KERN_INFO "SPC-3 PR [%s] Service Action: UNREGISTER Initiator"
		" Node: %s\n", tfo->get_fabric_name(),
		pr_reg->pr_reg_nacl->initiatorname);
	printk(KERN_INFO "SPC-3 PR [%s] for %s TCM Subsystem %s Object Target"
		" Port(s)\n", tfo->get_fabric_name(),
		(pr_reg->pr_reg_all_tg_pt) ? "ALL" : "SINGLE",
		TRANSPORT(dev)->name);
	printk(KERN_INFO "SPC-3 PR [%s] SA Res Key: 0x%016Lx PRgeneration:"
		" 0x%08x\n", tfo->get_fabric_name(), pr_reg->pr_res_key,
		pr_reg->pr_res_generation);

	if (!(preempt_and_abort_list)) {
		pr_reg->pr_reg_deve = NULL;
		pr_reg->pr_reg_nacl = NULL;
		kfree(pr_reg->pr_aptpl_buf);
		kmem_cache_free(t10_pr_reg_cache, pr_reg);
		return;
	}
	/*
	 * For PREEMPT_AND_ABORT, the list of *pr_reg in preempt_and_abort_list
	 * are released once the ABORT_TASK_SET has completed..
	 */
	list_add_tail(&pr_reg->pr_reg_abort_list, preempt_and_abort_list);
}

void core_scsi3_free_pr_reg_from_nacl(
	se_device_t *dev,
	se_node_acl_t *nacl)
{
	t10_reservation_template_t *pr_tmpl = &SU_DEV(dev)->t10_reservation;
	t10_pr_registration_t *pr_reg, *pr_reg_tmp, *pr_res_holder;
	/*
	 * If the passed se_node_acl matches the reservation holder,
	 * release the reservation.
	 */
	spin_lock(&dev->dev_reservation_lock);
	pr_res_holder = dev->dev_pr_res_holder;
	if ((pr_res_holder != NULL) &&
	    (pr_res_holder->pr_reg_nacl == nacl))
		__core_scsi3_complete_pro_release(dev, nacl, pr_res_holder, 0);
	spin_unlock(&dev->dev_reservation_lock);
	/*
	 * Release any registration associated with the se_node_acl_t.
	 */
	spin_lock(&pr_tmpl->registration_lock);
	list_for_each_entry_safe(pr_reg, pr_reg_tmp,
			&pr_tmpl->registration_list, pr_reg_list) {

		if (pr_reg->pr_reg_nacl != nacl)
			continue;

		__core_scsi3_free_registration(dev, pr_reg, NULL, 0);
	}
	spin_unlock(&pr_tmpl->registration_lock);
}

void core_scsi3_free_all_registrations(
	se_device_t *dev)
{
	t10_reservation_template_t *pr_tmpl = &SU_DEV(dev)->t10_reservation;
	t10_pr_registration_t *pr_reg, *pr_reg_tmp, *pr_res_holder;

	spin_lock(&dev->dev_reservation_lock);
	pr_res_holder = dev->dev_pr_res_holder;
	if (pr_res_holder != NULL) {
		se_node_acl_t *pr_res_nacl = pr_res_holder->pr_reg_nacl;
		__core_scsi3_complete_pro_release(dev, pr_res_nacl,
				pr_res_holder, 0);
	}
	spin_unlock(&dev->dev_reservation_lock);

	spin_lock(&pr_tmpl->registration_lock);
	list_for_each_entry_safe(pr_reg, pr_reg_tmp,
			&pr_tmpl->registration_list, pr_reg_list) {

		__core_scsi3_free_registration(dev, pr_reg, NULL, 0);
	}
	spin_unlock(&pr_tmpl->registration_lock);

	spin_lock(&pr_tmpl->aptpl_reg_lock);
	list_for_each_entry_safe(pr_reg, pr_reg_tmp, &pr_tmpl->aptpl_reg_list,
				pr_reg_aptpl_list) {
		list_del(&pr_reg->pr_reg_aptpl_list);
		kfree(pr_reg->pr_aptpl_buf);
		kmem_cache_free(t10_pr_reg_cache, pr_reg);
	}
	spin_unlock(&pr_tmpl->aptpl_reg_lock);
}

static int core_scsi3_decode_spec_i_port(
	se_cmd_t *cmd,
	se_portal_group_t *tpg,
	u64 sa_res_key,
	int all_tg_pt,
	int aptpl)
{
	se_lun_t *lun = SE_LUN(cmd);
	se_port_t *port = lun->lun_sep;
	se_session_t *se_sess = SE_SESS(cmd);
	se_node_acl_t *dest_node_acl;
	se_dev_entry_t *dest_se_deve = NULL, *local_se_deve;
	t10_pr_registration_t *dest_pr_reg, *local_pr_reg;
	struct list_head tid_dest_list;
	struct pr_transport_id_holder *tidh_new, *tidh, *tidh_tmp;
	unsigned char *buf = (unsigned char *)T_TASK(cmd)->t_task_buf;
	unsigned char *ptr, *i_str = NULL;
	char *iport_ptr = NULL, dest_iport[64];
	u32 tpdl, tid_len = 0;
	int ret, dest_local_nexus;

	memset(dest_iport, 0, 64);
	INIT_LIST_HEAD(&tid_dest_list);

	local_se_deve = &se_sess->se_node_acl->device_list[cmd->orig_fe_lun];
	/*
	 * Allocate a struct pr_transport_id_holder and setup the
	 * local_node_acl and local_se_deve pointers and add to
	 * struct list_head tid_dest_list for add registration
	 * processing in the loop of tid_dest_list below.
	 */
	tidh_new = kzalloc(sizeof(struct pr_transport_id_holder), GFP_KERNEL);
	if (!(tidh_new)) {
		printk(KERN_ERR "Unable to allocate tidh_new\n");
		return PYX_TRANSPORT_LU_COMM_FAILURE;
	}
	INIT_LIST_HEAD(&tidh_new->dest_list);
	tidh_new->dest_node_acl = se_sess->se_node_acl;
	tidh_new->dest_se_deve = local_se_deve;

	local_pr_reg = __core_scsi3_alloc_registration(SE_DEV(cmd),
				se_sess->se_node_acl, local_se_deve,
				sa_res_key, all_tg_pt, aptpl);
	if (!(local_pr_reg)) {
		kfree(tidh_new);
		return PYX_TRANSPORT_LU_COMM_FAILURE;
	}
	tidh_new->dest_pr_reg = local_pr_reg;
	/*
	 * The local I_T nexus does not hold any configfs dependances,
	 * so we set tid_h->dest_local_nexus=1 to prevent the
	 * configfs_undepend_item() calls in the tid_dest_list loops below.
	 */
	tidh_new->dest_local_nexus = 1;
	list_add_tail(&tidh_new->dest_list, &tid_dest_list);
	/*
	 * For a PERSISTENT RESERVE OUT specify initiator ports payload,
	 * first extract TransportID Parameter Data Length, and make sure
	 * the value matches up to the SCSI expected data transfer length.
	 */
	tpdl = (buf[24] & 0xff) << 24;
	tpdl |= (buf[25] & 0xff) << 16;
	tpdl |= (buf[26] & 0xff) << 8;
	tpdl |= buf[27] & 0xff;

	if ((tpdl + 28) != cmd->data_length) {
		printk(KERN_ERR "SPC-3 PR: Illegal tpdl: %u + 28 byte header"
			" does not equal CDB data_length: %u\n", tpdl,
			cmd->data_length);
		return PYX_TRANSPORT_INVALID_PARAMETER_LIST;
	}
	/*
	 * struct target_fabric_core_ops->tpg_parse_pr_out_transport_id()
	 * must exist to parse the fabric dependent transport IDs.
	 */
	if (TPG_TFO(tpg)->tpg_parse_pr_out_transport_id == NULL) {
		printk(KERN_ERR "SPC-3 SPEC_I_PT: Fabric does not"
			" containing a valid tpg_parse_pr_out_transport_id"
			" function pointer\n");
		return PYX_TRANSPORT_LU_COMM_FAILURE;
	}
	/*
	 * Start processing the received transport IDs using the
	 * receiving I_T Nexus portal's fabric dependent methods to
	 * obtain the SCSI Initiator Port/Device Identifiers.
	 */
	ptr = &buf[28];

	while (tpdl > 0) {
		i_str = TPG_TFO(tpg)->tpg_parse_pr_out_transport_id(
					(const char *)ptr, &tid_len,
					&iport_ptr);
		if (!(i_str)) {
			printk(KERN_ERR "SPC-3 PR SPEC_I_PT: Unable to locate"
				" i_str from Transport ID\n");
			ret = PYX_TRANSPORT_INVALID_PARAMETER_LIST;
			goto out;
		}
#if 0
		printk("SPC-3 PR SPEC_I_PT: Got %s data_length: %u tpdl: %u"
			" tid_len: %d for %s + %s\n",
			TPG_TFO(tpg)->get_fabric_name(), cmd->data_length,
			tpdl, tid_len, i_str, iport_ptr);
#endif
		if (tid_len > tpdl) {
			printk(KERN_ERR "SPC-3 PR SPEC_I_PT: Illegal tid_len:"
				" %u for Transport ID: %s\n", tid_len, ptr);
			ret = PYX_TRANSPORT_INVALID_PARAMETER_LIST;
			goto out;
		}
		/*
		 * Locate the desination initiator ACL to be registered.
		 */
		dest_node_acl = core_tpg_get_initiator_node_acl(tpg, i_str);
		if (!(dest_node_acl)) {
			printk(KERN_ERR "Unable to locate %s dest_node_acl"
				" for TransportID: %s %s\n",
				TPG_TFO(tpg)->get_fabric_name(),
				i_str, (iport_ptr != NULL) ? iport_ptr : "");
			ret = PYX_TRANSPORT_INVALID_PARAMETER_LIST;
			goto out;
		}

		ret = configfs_depend_item(TPG_TFO(tpg)->tf_subsys,
				&dest_node_acl->acl_group.cg_item);
		if (ret != 0) {
			printk(KERN_ERR "configfs_depend_item() failed for"
				" dest_node_acl->acl_group\n");
			ret = PYX_TRANSPORT_LU_COMM_FAILURE;
			goto out;
		}
		/*
		 * If the a SCSI Initiator Port identifier is presented, then
		 * the SCSI nexus must be present and matching the provided
		 * TransportID.  The active se_session_t pointer is available
		 * from dest_node_acl->nacl_sess;
		 */
		if (iport_ptr != NULL) {
			spin_lock(&dest_node_acl->nacl_sess_lock);
			if (dest_node_acl->nacl_sess == NULL) {
				printk(KERN_ERR "SPC-3 SPEC_I_PT: iport_ptr: %s"
					" presented in Transport ID, but no "
					" active nexus exists for %s Fabric"
					" Node: %s\n", iport_ptr,
					TPG_TFO(tpg)->get_fabric_name(),
					dest_node_acl->initiatorname);
				spin_unlock(&dest_node_acl->nacl_sess_lock);

				configfs_undepend_item(TPG_TFO(tpg)->tf_subsys,
					&dest_node_acl->acl_group.cg_item);

				ret = PYX_TRANSPORT_INVALID_PARAMETER_LIST;
				goto out;
			}
			TPG_TFO(tpg)->sess_get_initiator_wwn(
					dest_node_acl->nacl_sess,
					&dest_iport[0], 64);
			spin_unlock(&dest_node_acl->nacl_sess_lock);

			if (strcmp(dest_iport, iport_ptr)) {
				printk(KERN_ERR "SPC-3 SPEC_I_PT: dest_iport:"
					" %s and iport_ptr: %s do not match!\n",
					dest_iport, iport_ptr);

				configfs_undepend_item(TPG_TFO(tpg)->tf_subsys,
					&dest_node_acl->acl_group.cg_item);

				ret = PYX_TRANSPORT_INVALID_PARAMETER_LIST;
				goto out;
			}
		}
		/*
		 * Locate the desintation se_dev_entry_t pointer for matching
		 * RELATIVE TARGET PORT IDENTIFIER on the receiving I_T Nexus
		 * Target Port.
		 *
		 * Note that core_get_se_deve_from_rtpi() will call
		 * configfs_item_depend() on
		 * deve->se_lun_acl->se_lun_group.cg_item.
		 */
		dest_se_deve = core_get_se_deve_from_rtpi(dest_node_acl,
					port->sep_rtpi);
		if (!(dest_se_deve)) {
			printk(KERN_ERR "Unable to locate %s dest_se_deve"
				" from local RTPI: %hu\n",
				TPG_TFO(tpg)->get_fabric_name(),
				port->sep_rtpi);

			configfs_undepend_item(TPG_TFO(tpg)->tf_subsys,
				&dest_node_acl->acl_group.cg_item);

			ret = PYX_TRANSPORT_INVALID_PARAMETER_LIST;
			goto out;
		}
#if 0
		printk(KERN_INFO "SPC-3 PR SPEC_I_PT: Located %s Node: %s"
			" dest_se_deve mapped_lun: %u\n",
			TPG_TFO(tpg)->get_fabric_name(),
			dest_node_acl->initiatorname, dest_se_deve->mapped_lun);
#endif
		/*
		 * Skip any TransportIDs that already have a registration for
		 * this target port.
		 */
		if (dest_se_deve->deve_flags & DEF_PR_REGISTERED) {
			configfs_undepend_item(TPG_TFO(tpg)->tf_subsys,
			    &dest_se_deve->se_lun_acl->se_lun_group.cg_item);
			configfs_undepend_item(TPG_TFO(tpg)->tf_subsys,
			    &dest_node_acl->acl_group.cg_item);
			ptr += tid_len;
			tpdl -= tid_len;
			tid_len = 0;
		}
		/*
		 * Allocate a struct pr_transport_id_holder and setup
		 * the dest_node_acl and dest_se_deve pointers for the
		 * loop below.
		 */
		tidh_new = kzalloc(sizeof(struct pr_transport_id_holder),
				GFP_KERNEL);
		if (!(tidh_new)) {
			printk(KERN_ERR "Unable to allocate tidh_new\n");
			ret = PYX_TRANSPORT_LU_COMM_FAILURE;
			goto out;
		}
		INIT_LIST_HEAD(&tidh_new->dest_list);
		tidh_new->dest_node_acl = dest_node_acl;
		tidh_new->dest_se_deve = dest_se_deve;

		/*
		 * Allocate, but do NOT add the registration for the
		 * TransportID referenced SCSI Initiator port.  This
		 * done because of the following from spc4r17 in section
		 * 6.14.3 wrt SPEC_I_PT:
		 *
		 * "If a registration fails for any initiator port (e.g., if th
		 * logical unit does not have enough resources available to
		 * hold the registration information), no registrations shall be
		 * made, and the command shall be terminated with
		 * CHECK CONDITION status."
		 *
		 * That means we call __core_scsi3_alloc_registration() here,
		 * and then call __core_scsi3_add_registration() in the
		 * 2nd loop which will never fail.
		 */
		dest_pr_reg = __core_scsi3_alloc_registration(SE_DEV(cmd),
				dest_node_acl, dest_se_deve,
				sa_res_key, all_tg_pt, aptpl);
		if (!(dest_pr_reg)) {
			configfs_undepend_item(TPG_TFO(tpg)->tf_subsys,
			    &dest_se_deve->se_lun_acl->se_lun_group.cg_item);
			configfs_undepend_item(TPG_TFO(tpg)->tf_subsys,
			    &dest_node_acl->acl_group.cg_item);
			ret = PYX_TRANSPORT_INVALID_PARAMETER_LIST;
			goto out;
		}
		tidh_new->dest_pr_reg = dest_pr_reg;
		list_add_tail(&tidh_new->dest_list, &tid_dest_list);

		ptr += tid_len;
		tpdl -= tid_len;
		tid_len = 0;

	}
	/*
	 * Go ahead and create a registrations from tid_dest_list for the
	 * SPEC_I_PT provided TransportID for the *tidh referenced dest_node_acl
	 * and dest_se_deve.
	 *
	 * The SA Reservation Key from the PROUT is set for the
	 * registration, and ALL_TG_PT is also passed.  ALL_TG_PT=1
	 * means that the TransportID Initiator port will be
	 * registered on all of the target ports in the SCSI target device
	 * ALL_TG_PT=0 means the registration will only be for the
	 * SCSI target port the PROUT REGISTER with SPEC_I_PT=1
	 * was received.
	 */
	list_for_each_entry_safe(tidh, tidh_tmp, &tid_dest_list, dest_list) {
		dest_node_acl = tidh->dest_node_acl;
		dest_se_deve = tidh->dest_se_deve;
		dest_pr_reg = tidh->dest_pr_reg;
		dest_local_nexus = tidh->dest_local_nexus;

		list_del(&tidh->dest_list);
		kfree(tidh);

		__core_scsi3_add_registration(SE_DEV(cmd), dest_node_acl,
					dest_pr_reg, 0, 0);

		printk(KERN_INFO "SPC-3 PR [%s] SPEC_I_PT: Successfully"
			" registered Transport ID for Node: %s Mapped LUN:"
			" %u\n", TPG_TFO(tpg)->get_fabric_name(),
				dest_node_acl->initiatorname,
				dest_se_deve->mapped_lun);

		if (dest_local_nexus)
			continue;

		configfs_undepend_item(TPG_TFO(tpg)->tf_subsys,
			&dest_se_deve->se_lun_acl->se_lun_group.cg_item);
		configfs_undepend_item(TPG_TFO(tpg)->tf_subsys,
			&dest_node_acl->acl_group.cg_item);
	}

	return 0;
out:
	/*
	 * For the failure case, release everything from tid_dest_list
	 * including *dest_pr_reg and the configfs dependances..
	 */
	list_for_each_entry_safe(tidh, tidh_tmp, &tid_dest_list, dest_list) {
		dest_node_acl = tidh->dest_node_acl;
		dest_se_deve = tidh->dest_se_deve;
		dest_pr_reg = tidh->dest_pr_reg;
		dest_local_nexus = tidh->dest_local_nexus;

		list_del(&tidh->dest_list);
		kfree(tidh);

		kfree(dest_pr_reg->pr_aptpl_buf);
		kmem_cache_free(t10_pr_reg_cache, dest_pr_reg);

		if (dest_local_nexus)
			continue;

		configfs_undepend_item(TPG_TFO(tpg)->tf_subsys,
			&dest_se_deve->se_lun_acl->se_lun_group.cg_item);
		configfs_undepend_item(TPG_TFO(tpg)->tf_subsys,
			&dest_node_acl->acl_group.cg_item);
	}
	return ret;
}

/*
 * Called with se_device_t->dev_reservation_lock held
 */
static int __core_scsi3_update_aptpl_buf(
	se_device_t *dev,
	unsigned char *buf,
	u32 pr_aptpl_buf_len,
	int clear_aptpl_metadata)
{
	se_lun_t *lun;
	se_portal_group_t *tpg;
	se_subsystem_dev_t *su_dev = SU_DEV(dev);
	t10_pr_registration_t *pr_reg;
	unsigned char tmp[1024];
	ssize_t len = 0;
	int reg_count = 0;

	memset(buf, 0, pr_aptpl_buf_len);
	/*
	 * Called to clear metadata once APTPL has been deactivated.
	 */
	if (clear_aptpl_metadata) {
		snprintf(buf, pr_aptpl_buf_len,
				"No Registrations or Reservations\n");
		return 0;
	}
	/*
	 * Walk the registration list..
	 */
	spin_lock(&T10_RES(su_dev)->registration_lock);
	list_for_each_entry(pr_reg, &T10_RES(su_dev)->registration_list,
			pr_reg_list) {

		memset(tmp, 0, 1024);
		tpg = pr_reg->pr_reg_nacl->se_tpg;
		lun = pr_reg->pr_reg_tg_pt_lun;
		/*
		 * Include special metadata if the pr_reg matches the
		 * reservation holder.
		 */
		if (dev->dev_pr_res_holder == pr_reg) {
			snprintf(tmp, 1024, "PR_REG_START: %d"
				"\ninitiator_fabric=%s\n"
				"initiator_node=%s\n"
				"sa_res_key=%llu\n"
				"res_holder=1\nres_type=%02x\n"
				"res_scope=%02x\nres_all_tg_pt=%d\n"
				"mapped_lun=%u\n", reg_count,
				TPG_TFO(tpg)->get_fabric_name(),
				pr_reg->pr_reg_nacl->initiatorname,
				pr_reg->pr_res_key, pr_reg->pr_res_type,
				pr_reg->pr_res_scope, pr_reg->pr_reg_all_tg_pt,
				pr_reg->pr_res_mapped_lun);
		} else {
			snprintf(tmp, 1024, "PR_REG_START: %d\n"
				"initiator_fabric=%s\ninitiator_node=%s\n"
				"sa_res_key=%llu\nres_holder=0\n"
				"res_all_tg_pt=%d\nmapped_lun=%u\n",
				reg_count, TPG_TFO(tpg)->get_fabric_name(),
				pr_reg->pr_reg_nacl->initiatorname,
				pr_reg->pr_res_key, pr_reg->pr_reg_all_tg_pt,
				pr_reg->pr_res_mapped_lun);
		}

		if ((len + strlen(tmp) > pr_aptpl_buf_len)) {
			printk(KERN_ERR "Unable to update renaming"
				" APTPL metadata\n");
			spin_unlock(&T10_RES(su_dev)->registration_lock);
			return -1;
		}
		len += sprintf(buf+len, "%s", tmp);

		/*
		 * Include information about the associated SCSI target port.
		 */
		snprintf(tmp, 1024, "target_fabric=%s\ntarget_node=%s\n"
			"tpgt=%hu\nport_rtpi=%hu\ntarget_lun=%u\nPR_REG_END:"
			" %d\n", TPG_TFO(tpg)->get_fabric_name(),
			TPG_TFO(tpg)->tpg_get_wwn(tpg),
			TPG_TFO(tpg)->tpg_get_tag(tpg),
			lun->lun_sep->sep_rtpi, lun->unpacked_lun, reg_count);

		if ((len + strlen(tmp) > pr_aptpl_buf_len)) {
			printk(KERN_ERR "Unable to update renaming"
				" APTPL metadata\n");
			spin_unlock(&T10_RES(su_dev)->registration_lock);
			return -1;
		}
		len += sprintf(buf+len, "%s", tmp);
		reg_count++;
	}
	spin_unlock(&T10_RES(su_dev)->registration_lock);

	 if (!(reg_count))
		len += sprintf(buf+len, "No Registrations or Reservations");

	return 0;
}

static int core_scsi3_update_aptpl_buf(
	se_device_t *dev,
	unsigned char *buf,
	u32 pr_aptpl_buf_len,
	int clear_aptpl_metadata)
{
	int ret;

	spin_lock(&dev->dev_reservation_lock);
	ret = __core_scsi3_update_aptpl_buf(dev, buf, pr_aptpl_buf_len,
				clear_aptpl_metadata);
	spin_unlock(&dev->dev_reservation_lock);

	return ret;
}

/*
 * Called with se_device_t->aptpl_file_mutex held
 */
static int __core_scsi3_write_aptpl_to_file(
	se_device_t *dev,
	unsigned char *buf,
	u32 pr_aptpl_buf_len)
{
	t10_wwn_t *wwn = &SU_DEV(dev)->t10_wwn;
	struct file *file;
	struct iovec iov[1];
	mm_segment_t old_fs;
	int flags = O_RDWR | O_CREAT | O_TRUNC;
	char path[512];
	int ret;

	memset(iov, 0, sizeof(struct iovec));
	memset(path, 0, 512);

	if (strlen(&wwn->unit_serial[0]) > 512) {
		printk(KERN_ERR "WWN value for se_device_t does not fit"
			" into path buffer\n");
		return -1;
	}

	snprintf(path, 512, "/var/target/pr/aptpl_%s", &wwn->unit_serial[0]);
	file = filp_open(path, flags, 0600);
	if (IS_ERR(file) || !file || !file->f_dentry) {
		printk(KERN_ERR "filp_open(%s) for APTPL metadata"
			" failed\n", path);
		return -1;
	}

	iov[0].iov_base = &buf[0];
	if (!(pr_aptpl_buf_len))
		iov[0].iov_len = (strlen(&buf[0]) + 1); /* Add extra for NULL */
	else
		iov[0].iov_len = pr_aptpl_buf_len;

	old_fs = get_fs();
	set_fs(get_ds());
	ret = vfs_writev(file, &iov[0], 1, &file->f_pos);
	set_fs(old_fs);

	if (ret < 0) {
		printk("Error writing APTPL metadata file: %s\n", path);
		filp_close(file, NULL);
		return -1;
	}
	filp_close(file, NULL);

	return 0;
}

static int core_scsi3_update_and_write_aptpl(
	se_device_t *dev,
	unsigned char *in_buf,
	u32 in_pr_aptpl_buf_len)
{
	unsigned char null_buf[64], *buf;
	u32 pr_aptpl_buf_len;
	int ret, clear_aptpl_metadata = 0;
	/*
	 * Can be called with a NULL pointer from PROUT service action CLEAR
	 */
	if (!(in_buf)) {
		memset(null_buf, 0, 64);
		buf = &null_buf[0];
		/*
		 * This will clear the APTPL metadata to:
		 * "No Registrations or Reservations" status
		 */
		pr_aptpl_buf_len = 64;
		clear_aptpl_metadata = 1;
	} else {
		buf = in_buf;
		pr_aptpl_buf_len = in_pr_aptpl_buf_len;
	}

	ret = core_scsi3_update_aptpl_buf(dev, buf, pr_aptpl_buf_len,
				clear_aptpl_metadata);
	if (ret != 0)
		return -1;
	/*
	 * __core_scsi3_write_aptpl_to_file() will call strlen()
	 * on the passed buf to determine pr_aptpl_buf_len.
	 */
	ret = __core_scsi3_write_aptpl_to_file(dev, buf, 0);
	if (ret != 0)
		return -1;

	return ret;
}

static int core_scsi3_emulate_pro_register(
	se_cmd_t *cmd,
	u64 res_key,
	u64 sa_res_key,
	int aptpl,
	int all_tg_pt,
	int spec_i_pt,
	int ignore_key)
{
	se_session_t *se_sess = SE_SESS(cmd);
	se_device_t *dev = SE_DEV(cmd);
	se_dev_entry_t *se_deve;
	se_lun_t *se_lun = SE_LUN(cmd);
	se_portal_group_t *se_tpg;
	t10_pr_registration_t *pr_reg, *pr_reg_p;
	t10_reservation_template_t *pr_tmpl = &SU_DEV(dev)->t10_reservation;
	/* Used for APTPL metadata w/ UNREGISTER */
	unsigned char *pr_aptpl_buf = NULL;
	int pr_holder = 0, ret = 0, type;

	if (!(se_sess) || !(se_lun)) {
		printk(KERN_ERR "SPC-3 PR: se_sess || se_lun_t is NULL!\n");
		return PYX_TRANSPORT_LU_COMM_FAILURE;
	}
	se_tpg = se_sess->se_tpg;
	se_deve = &se_sess->se_node_acl->device_list[cmd->orig_fe_lun];
	/*
	 * Follow logic from spc4r17 Section 5.7.7, Register Behaviors Table 47
	 */
	if (!(se_deve->deve_flags & DEF_PR_REGISTERED)) {
		if (res_key) {
			printk(KERN_WARNING "SPC-3 PR: Reservation Key non-zero"
				" for SA REGISTER, returning CONFLICT\n");
			return PYX_TRANSPORT_RESERVATION_CONFLICT;
		}
		/*
		 * Do nothing but return GOOD status.
		 */
		if (!(sa_res_key))
			return PYX_TRANSPORT_SENT_TO_TRANSPORT;

		if (!(spec_i_pt)) {
			/*
			 * Perform the Service Action REGISTER on the Initiator
			 * Port Endpoint that the PRO was received from on the
			 * Logical Unit of the SCSI device server.
			 */
			ret = core_scsi3_alloc_registration(SE_DEV(cmd),
					se_sess->se_node_acl, se_deve,
					sa_res_key, all_tg_pt, aptpl,
					ignore_key, 0);
			if (ret != 0) {
				printk(KERN_ERR "Unable to allocate"
					" t10_pr_registration_t\n");
				return PYX_TRANSPORT_INVALID_PARAMETER_LIST;
			}
		} else {
			/*
			 * Register both the Initiator port that received
			 * PROUT SA REGISTER + SPEC_I_PT=1 and extract SCSI
			 * TransportID from Parameter list and loop through
			 * fabric dependent parameter list while calling
			 * logic from of core_scsi3_alloc_registration() for
			 * each TransportID provided SCSI Initiator Port/Device
			 */
			ret = core_scsi3_decode_spec_i_port(cmd, se_tpg,
						sa_res_key, all_tg_pt, aptpl);
			if (ret != 0)
				return ret;
		}
		/*
		 * Nothing left to do for the APTPL=0 case.
		 */
		if (!(aptpl)) {
			pr_tmpl->pr_aptpl_active = 0;
			core_scsi3_update_and_write_aptpl(SE_DEV(cmd), NULL, 0);
			printk("SPC-3 PR: Set APTPL Bit Deactivated for"
					" REGISTER\n");
			return 0;
		}
		/*
		 * Locate the newly allocated local I_T Nexus *pr_reg, and
		 * update the APTPL metadata information using its
		 * preallocated *pr_reg->pr_aptpl_buf.
		 */
		pr_reg = core_scsi3_locate_pr_reg(SE_DEV(cmd),
				se_sess->se_node_acl);

		ret = core_scsi3_update_and_write_aptpl(SE_DEV(cmd),
				&pr_reg->pr_aptpl_buf[0],
				pr_tmpl->pr_aptpl_buf_len);
		if (!(ret)) {
			pr_tmpl->pr_aptpl_active = 1;
			printk("SPC-3 PR: Set APTPL Bit Activated for REGISTER\n");
		}

		core_scsi3_put_pr_reg(pr_reg);
		return ret;
	} else {
		/*
		 * Locate the existing *pr_reg via se_node_acl_t pointers
		 */
		pr_reg = core_scsi3_locate_pr_reg(SE_DEV(cmd),
				se_sess->se_node_acl);
		if (!(pr_reg)) {
			printk(KERN_ERR "SPC-3 PR: Unable to locate"
				" PR_REGISTERED *pr_reg for REGISTER\n");
			return PYX_TRANSPORT_LU_COMM_FAILURE;
		}
		type = pr_reg->pr_res_type;

		if (!(ignore_key)) {
			if (res_key != pr_reg->pr_res_key) {
				printk(KERN_ERR "SPC-3 PR REGISTER: Received"
					" res_key: 0x%016Lx does not match"
					" existing SA REGISTER res_key:"
					" 0x%016Lx\n", res_key,
					pr_reg->pr_res_key);
				core_scsi3_put_pr_reg(pr_reg);
				return PYX_TRANSPORT_RESERVATION_CONFLICT;
			}
		}
		if (spec_i_pt) {
			printk(KERN_ERR "SPC-3 PR UNREGISTER: SPEC_I_PT"
				" set while sa_res_key=0\n");
			core_scsi3_put_pr_reg(pr_reg);
			return PYX_TRANSPORT_INVALID_PARAMETER_LIST;
		}
		/*
		 * Allocate APTPL metadata buffer used for UNREGISTER ops
		 */
		if (aptpl) {
			pr_aptpl_buf = kzalloc(pr_tmpl->pr_aptpl_buf_len,
						GFP_KERNEL);
			if (!(pr_aptpl_buf)) {
				printk(KERN_ERR "Unable to allocate"
					" pr_aptpl_buf\n");
				core_scsi3_put_pr_reg(pr_reg);
				return PYX_TRANSPORT_LU_COMM_FAILURE;
			}
		}
		/*
		 * sa_res_key=0 Unregister Reservation Key for registered I_T
		 * Nexus sa_res_key=1 Change Reservation Key for registered I_T
		 * Nexus.
		 */
		if (!(sa_res_key)) {
			pr_holder = core_scsi3_check_implict_release(
					SE_DEV(cmd), pr_reg);

			spin_lock(&pr_tmpl->registration_lock);
			/*
			 * Release the calling I_T Nexus registration now..
			 */
			__core_scsi3_free_registration(SE_DEV(cmd), pr_reg,
							NULL, 1);
			/*
			 * From spc4r17, section 5.7.11.3 Unregistering
			 *
			 * If the persistent reservation is a registrants only
			 * type, the device server shall establish a unit
			 * attention condition for the initiator port associated
			 * with every registered I_T nexus except for the I_T
			 * nexus on which the PERSISTENT RESERVE OUT command was
			 * received, with the additional sense code set to
			 * RESERVATIONS RELEASED.
			 */
			if (pr_holder &&
			   ((type == PR_TYPE_WRITE_EXCLUSIVE_REGONLY) ||
			    (type == PR_TYPE_EXCLUSIVE_ACCESS_REGONLY))) {
				list_for_each_entry(pr_reg_p,
						&pr_tmpl->registration_list,
						pr_reg_list) {

					core_scsi3_ua_allocate(
						pr_reg_p->pr_reg_nacl,
						pr_reg_p->pr_res_mapped_lun,
						0x2A,
						ASCQ_2AH_RESERVATIONS_RELEASED);
				}
			}
			spin_unlock(&pr_tmpl->registration_lock);

			if (!(aptpl)) {
				pr_tmpl->pr_aptpl_active = 0;
				core_scsi3_update_and_write_aptpl(dev, NULL, 0);
				printk("SPC-3 PR: Set APTPL Bit Deactivated"
						" for UNREGISTER\n");
				return 0;
			}

			ret = core_scsi3_update_and_write_aptpl(dev,
					&pr_aptpl_buf[0],
					pr_tmpl->pr_aptpl_buf_len);
			if (!(ret)) {
				pr_tmpl->pr_aptpl_active = 1;
				printk("SPC-3 PR: Set APTPL Bit Activated"
						" for UNREGISTER\n");
			}

			kfree(pr_aptpl_buf);
			return ret;
		} else {
			/*
			 * Increment PRgeneration counter for se_device_t"
			 * upon a successful REGISTER, see spc4r17 section 6.3.2
			 * READ_KEYS service action.
			 */
			pr_reg->pr_res_generation = core_scsi3_pr_generation(
							SE_DEV(cmd));
			pr_reg->pr_res_key = sa_res_key;
			printk("SPC-3 PR [%s] REGISTER%s: Changed Reservation"
				" Key for %s to: 0x%016Lx PRgeneration:"
				" 0x%08x\n", CMD_TFO(cmd)->get_fabric_name(),
				(ignore_key) ? "_AND_IGNORE_EXISTING_KEY" : "",
				pr_reg->pr_reg_nacl->initiatorname,
				pr_reg->pr_res_key, pr_reg->pr_res_generation);

			core_scsi3_put_pr_reg(pr_reg);
		}
	}
	return 0;
}

unsigned char *core_scsi3_pr_dump_type(int type)
{
	switch (type) {
	case PR_TYPE_WRITE_EXCLUSIVE:
		return "Write Exclusive Access";
	case PR_TYPE_EXCLUSIVE_ACCESS:
		return "Exclusive Access";
	case PR_TYPE_WRITE_EXCLUSIVE_REGONLY:
		return "Write Exclusive Access, Registrants Only";
	case PR_TYPE_EXCLUSIVE_ACCESS_REGONLY:
		return "Exclusive Access, Registrants Only";
	case PR_TYPE_WRITE_EXCLUSIVE_ALLREG:
		return "Write Exclusive Access, All Registrants";
	case PR_TYPE_EXCLUSIVE_ACCESS_ALLREG:
		return "Exclusive Access, All Registrants";
	default:
		break;
	}

	return "Unknown SPC-3 PR Type";
}

static int core_scsi3_pro_reserve(
	se_cmd_t *cmd,
	se_device_t *dev,
	int type,
	int scope,
	u64 res_key)
{
	se_session_t *se_sess = SE_SESS(cmd);
	se_dev_entry_t *se_deve;
	se_lun_t *se_lun = SE_LUN(cmd);
	se_portal_group_t *se_tpg;
	t10_pr_registration_t *pr_reg, *pr_res_holder;
	t10_reservation_template_t *pr_tmpl = &SU_DEV(dev)->t10_reservation;
	int ret;

	if (!(se_sess) || !(se_lun)) {
		printk(KERN_ERR "SPC-3 PR: se_sess || se_lun_t is NULL!\n");
		return PYX_TRANSPORT_LU_COMM_FAILURE;
	}
	se_tpg = se_sess->se_tpg;
	se_deve = &se_sess->se_node_acl->device_list[cmd->orig_fe_lun];
	/*
	 * Locate the existing *pr_reg via se_node_acl_t pointers
	 */
	pr_reg = core_scsi3_locate_pr_reg(SE_DEV(cmd), se_sess->se_node_acl);
	if (!(pr_reg)) {
		printk(KERN_ERR "SPC-3 PR: Unable to locate"
			" PR_REGISTERED *pr_reg for RESERVE\n");
		return PYX_TRANSPORT_LU_COMM_FAILURE;
	}
	/*
	 * For a given ALL_TG_PT=0 PR registration, a recevied PR reserve must
	 * be on the same matching se_portal_group_t + se_lun_t.
	 */
	if (!(pr_reg->pr_reg_all_tg_pt) &&
	     (pr_reg->pr_reg_tg_pt_lun != se_lun)) {
		printk(KERN_ERR "SPC-3 PR: Unable to handle RESERVE because"
			" ALL_TG_PT=0 and RESERVE was not received on same"
			" target port as REGISTER\n");
		core_scsi3_put_pr_reg(pr_reg);
		return PYX_TRANSPORT_RESERVATION_CONFLICT;
	}
	/*
	 * From spc4r17 Section 5.7.9: Reserving:
	 *
	 * An application client creates a persistent reservation by issuing
	 * a PERSISTENT RESERVE OUT command with RESERVE service action through
	 * a registered I_T nexus with the following parameters:
	 *    a) RESERVATION KEY set to the value of the reservation key that is
	 * 	 registered with the logical unit for the I_T nexus; and
	 */
	if (res_key != pr_reg->pr_res_key) {
		printk(KERN_ERR "SPC-3 PR RESERVE: Received res_key: 0x%016Lx"
			" does not match existing SA REGISTER res_key:"
			" 0x%016Lx\n", res_key, pr_reg->pr_res_key);
		core_scsi3_put_pr_reg(pr_reg);
		return PYX_TRANSPORT_RESERVATION_CONFLICT;
	}
	/*
	 * From spc4r17 Section 5.7.9: Reserving:
	 *
	 * From above:
	 *  b) TYPE field and SCOPE field set to the persistent reservation
	 *     being created.
	 *
	 * Only one persistent reservation is allowed at a time per logical unit
	 * and that persistent reservation has a scope of LU_SCOPE.
	 */
	if (scope != PR_SCOPE_LU_SCOPE) {
		printk(KERN_ERR "SPC-3 PR: Illegal SCOPE: 0x%02x\n", scope);
		core_scsi3_put_pr_reg(pr_reg);
		return PYX_TRANSPORT_INVALID_PARAMETER_LIST;
	}
	/*
	 * See if we have an existing PR reservation holder pointer at
	 * se_device_t->dev_pr_res_holder in the form t10_pr_registration_t
	 * *pr_res_holder.
	 */
	spin_lock(&dev->dev_reservation_lock);
	pr_res_holder = dev->dev_pr_res_holder;
	if ((pr_res_holder)) {
		/*
		 * From spc4r17 Section 5.7.9: Reserving:
		 *
		 * If the device server receives a PERSISTENT RESERVE OUT
		 * command from an I_T nexus other than a persistent reservation
		 * holder (see 5.7.10) that attempts to create a persistent
		 * reservation when a persistent reservation already exists for
		 * the logical unit, then the command shall be completed with
		 * RESERVATION CONFLICT status.
		 */
		if (pr_res_holder != pr_reg) {
			se_node_acl_t *pr_res_nacl = pr_res_holder->pr_reg_nacl;
			printk(KERN_ERR "SPC-3 PR: Attempted RESERVE from"
				" [%s]: %s while reservation already held by"
				" [%s]: %s, returning RESERVATION_CONFLICT\n",
				CMD_TFO(cmd)->get_fabric_name(),
				se_sess->se_node_acl->initiatorname,
				TPG_TFO(pr_res_nacl->se_tpg)->get_fabric_name(),
				pr_res_holder->pr_reg_nacl->initiatorname);

			spin_unlock(&dev->dev_reservation_lock);
			core_scsi3_put_pr_reg(pr_reg);
			return PYX_TRANSPORT_RESERVATION_CONFLICT;
		}
		/*
		 * From spc4r17 Section 5.7.9: Reserving:
		 *
		 * If a persistent reservation holder attempts to modify the
		 * type or scope of an existing persistent reservation, the
		 * command shall be completed with RESERVATION CONFLICT status.
		 */
		if ((pr_res_holder->pr_res_type != type) ||
		    (pr_res_holder->pr_res_scope != scope)) {
			se_node_acl_t *pr_res_nacl = pr_res_holder->pr_reg_nacl;
			printk(KERN_ERR "SPC-3 PR: Attempted RESERVE from"
				" [%s]: %s trying to change TYPE and/or SCOPE,"
				" while reservation already held by [%s]: %s,"
				" returning RESERVATION_CONFLICT\n",
				CMD_TFO(cmd)->get_fabric_name(),
				se_sess->se_node_acl->initiatorname,
				TPG_TFO(pr_res_nacl->se_tpg)->get_fabric_name(),
				pr_res_holder->pr_reg_nacl->initiatorname);

			spin_unlock(&dev->dev_reservation_lock);
			core_scsi3_put_pr_reg(pr_reg);
			return PYX_TRANSPORT_RESERVATION_CONFLICT;
		}
		/*
		 * From spc4r17 Section 5.7.9: Reserving:
		 *
		 * If the device server receives a PERSISTENT RESERVE OUT
		 * command with RESERVE service action where the TYPE field and
		 * the SCOPE field contain the same values as the existing type
		 * and scope from a persistent reservation holder, it shall not
		 * make any change to the existing persistent reservation and
		 * shall completethe command with GOOD status.
		 */
		spin_unlock(&dev->dev_reservation_lock);
		core_scsi3_put_pr_reg(pr_reg);
		return PYX_TRANSPORT_SENT_TO_TRANSPORT;
	}
	/*
	 * Otherwise, our *pr_reg becomes the PR reservation holder for said
	 * TYPE/SCOPE.  Also set the received scope and type in *pr_reg.
	 */
	pr_reg->pr_res_scope = scope;
	pr_reg->pr_res_type = type;
	pr_reg->pr_res_holder = 1;
	dev->dev_pr_res_holder = pr_reg;

	printk(KERN_INFO "SPC-3 PR [%s] Service Action: RESERVE created new"
		" reservation holder TYPE: %s ALL_TG_PT: %d\n",
		CMD_TFO(cmd)->get_fabric_name(), core_scsi3_pr_dump_type(type),
		(pr_reg->pr_reg_all_tg_pt) ? 1 : 0);
	printk(KERN_INFO "SPC-3 PR [%s] RESERVE Node: %s\n",
			CMD_TFO(cmd)->get_fabric_name(),
			se_sess->se_node_acl->initiatorname);
	spin_unlock(&dev->dev_reservation_lock);

	if (pr_tmpl->pr_aptpl_active) {
		ret = core_scsi3_update_and_write_aptpl(SE_DEV(cmd),
				&pr_reg->pr_aptpl_buf[0],
				pr_tmpl->pr_aptpl_buf_len);
		if (!(ret))
			printk(KERN_INFO "SPC-3 PR: Updated APTPL metadata"
					" for RESERVE\n");
	}

	core_scsi3_put_pr_reg(pr_reg);
	return 0;
}

static int core_scsi3_emulate_pro_reserve(
	se_cmd_t *cmd,
	int type,
	int scope,
	u64 res_key)
{
	se_device_t *dev = cmd->se_dev;
	int ret = 0;

	switch (type) {
	case PR_TYPE_WRITE_EXCLUSIVE:
	case PR_TYPE_EXCLUSIVE_ACCESS:
	case PR_TYPE_WRITE_EXCLUSIVE_REGONLY:
	case PR_TYPE_EXCLUSIVE_ACCESS_REGONLY:
	case PR_TYPE_WRITE_EXCLUSIVE_ALLREG:
	case PR_TYPE_EXCLUSIVE_ACCESS_ALLREG:
		ret = core_scsi3_pro_reserve(cmd, dev, type, scope, res_key);
		break;
	default:
		printk(KERN_ERR "SPC-3 PR: Unknown Service Action RESERVE Type:"
			" 0x%02x\n", type);
		return PYX_TRANSPORT_INVALID_CDB_FIELD;
	}

	return ret;
}

/*
 * Called with se_device_t->dev_reservation_lock held.
 */
static void __core_scsi3_complete_pro_release(
	se_device_t *dev,
	se_node_acl_t *se_nacl,
	t10_pr_registration_t *pr_reg,
	int explict)
{
	struct target_core_fabric_ops *tfo = se_nacl->se_tpg->se_tpg_tfo;
	/*
	 * Go ahead and release the current PR reservation holder.
	 */
	dev->dev_pr_res_holder = NULL;

	printk(KERN_INFO "SPC-3 PR [%s] Service Action: %s RELEASE cleared"
		" reservation holder TYPE: %s ALL_TG_PT: %d\n",
		tfo->get_fabric_name(), (explict) ? "explict" : "implict",
		core_scsi3_pr_dump_type(pr_reg->pr_res_type),
		(pr_reg->pr_reg_all_tg_pt) ? 1 : 0);
	printk(KERN_INFO "SPC-3 PR [%s] RELEASE Node: %s\n",
		tfo->get_fabric_name(),
		se_nacl->initiatorname);
	/*
	 * Clear TYPE and SCOPE for the next PROUT Service Action: RESERVE
	 */
	pr_reg->pr_res_holder = pr_reg->pr_res_type = pr_reg->pr_res_scope = 0;
}

static int core_scsi3_emulate_pro_release(
	se_cmd_t *cmd,
	int type,
	int scope,
	u64 res_key)
{
	se_device_t *dev = cmd->se_dev;
	se_session_t *se_sess = SE_SESS(cmd);
	se_lun_t *se_lun = SE_LUN(cmd);
	t10_pr_registration_t *pr_reg, *pr_reg_p, *pr_res_holder;
	t10_reservation_template_t *pr_tmpl = &SU_DEV(dev)->t10_reservation;
	int ret;

	if (!(se_sess) || !(se_lun)) {
		printk(KERN_ERR "SPC-3 PR: se_sess || se_lun_t is NULL!\n");
		return PYX_TRANSPORT_LU_COMM_FAILURE;
	}
	/*
	 * Locate the existing *pr_reg via se_node_acl_t pointers
	 */
	pr_reg = core_scsi3_locate_pr_reg(dev, se_sess->se_node_acl);
	if (!(pr_reg)) {
		printk(KERN_ERR "SPC-3 PR: Unable to locate"
			" PR_REGISTERED *pr_reg for RELEASE\n");
		return PYX_TRANSPORT_LU_COMM_FAILURE;
	}
	/*
	 * From spc4r17 Section 5.7.11.2 Releasing:
	 *
	 * If there is no persistent reservation or in response to a persistent
	 * reservation release request from a registered I_T nexus that is not a
	 * persistent reservation holder (see 5.7.10), the device server shall
	 * do the following:
	 *
	 *     a) Not release the persistent reservation, if any;
	 *     b) Not remove any registrations; and
	 *     c) Complete the command with GOOD status.
	 */
	spin_lock(&dev->dev_reservation_lock);
	pr_res_holder = dev->dev_pr_res_holder;
	if (!(pr_res_holder)) {
		/*
		 * No persistent reservation, return GOOD status.
		 */
		spin_unlock(&dev->dev_reservation_lock);
		core_scsi3_put_pr_reg(pr_reg);
		return PYX_TRANSPORT_SENT_TO_TRANSPORT;
	}
	if (pr_res_holder != pr_reg) {
		/*
		 * Release request from a registered I_T nexus that is not a
		 * persistent reservation holder. return GOOD status.
		 */
		spin_unlock(&dev->dev_reservation_lock);
		core_scsi3_put_pr_reg(pr_reg);
		return PYX_TRANSPORT_SENT_TO_TRANSPORT;
	}
	/*
	 * From spc4r17 Section 5.7.11.2 Releasing:
	 *
	 * Only the persistent reservation holder (see 5.7.10) is allowed to
	 * release a persistent reservation.
	 *
	 * An application client releases the persistent reservation by issuing
	 * a PERSISTENT RESERVE OUT command with RELEASE service action through
	 * an I_T nexus that is a persistent reservation holder with the
	 * following parameters:
	 *
	 *     a) RESERVATION KEY field set to the value of the reservation key
	 *	  that is registered with the logical unit for the I_T nexus;
	 */
	if (res_key != pr_reg->pr_res_key) {
		printk(KERN_ERR "SPC-3 PR RELEASE: Received res_key: 0x%016Lx"
			" does not match existing SA REGISTER res_key:"
			" 0x%016Lx\n", res_key, pr_reg->pr_res_key);
		spin_unlock(&dev->dev_reservation_lock);
		core_scsi3_put_pr_reg(pr_reg);
		return PYX_TRANSPORT_RESERVATION_CONFLICT;
	}
	/*
	 * From spc4r17 Section 5.7.11.2 Releasing and above:
	 *
	 * b) TYPE field and SCOPE field set to match the persistent
	 *    reservation being released.
	 */
	if ((pr_res_holder->pr_res_type != type) ||
	    (pr_res_holder->pr_res_scope != scope)) {
		se_node_acl_t *pr_res_nacl = pr_res_holder->pr_reg_nacl;
		printk(KERN_ERR "SPC-3 PR RELEASE: Attempted to release"
			" reservation from [%s]: %s with different TYPE "
			"and/or SCOPE  while reservation already held by"
			" [%s]: %s, returning RESERVATION_CONFLICT\n",
			CMD_TFO(cmd)->get_fabric_name(),
			se_sess->se_node_acl->initiatorname,
			TPG_TFO(pr_res_nacl->se_tpg)->get_fabric_name(),
			pr_res_holder->pr_reg_nacl->initiatorname);

		spin_unlock(&dev->dev_reservation_lock);
		core_scsi3_put_pr_reg(pr_reg);
		return PYX_TRANSPORT_RESERVATION_CONFLICT;
	}
	/*
	 * In response to a persistent reservation release request from the
	 * persistent reservation holder the device server shall perform a
	 * release by doing the following as an uninterrupted series of actions:
	 * a) Release the persistent reservation;
	 * b) Not remove any registration(s);
	 * c) If the released persistent reservation is a registrants only type
	 * or all registrants type persistent reservation,
	 *    the device server shall establish a unit attention condition for
	 *    the initiator port associated with every regis-
	 *    tered I_T nexus other than I_T nexus on which the PERSISTENT
	 *    RESERVE OUT command with RELEASE service action was received,
	 *    with the additional sense code set to RESERVATIONS RELEASED; and
	 * d) If the persistent reservation is of any other type, the device
	 *    server shall not establish a unit attention condition.
	 */
	__core_scsi3_complete_pro_release(dev, se_sess->se_node_acl,
			pr_reg, 1);

	if ((type != PR_TYPE_WRITE_EXCLUSIVE_REGONLY) &&
	    (type != PR_TYPE_EXCLUSIVE_ACCESS_REGONLY) &&
	    (type != PR_TYPE_WRITE_EXCLUSIVE_ALLREG) &&
	    (type != PR_TYPE_EXCLUSIVE_ACCESS_ALLREG)) {
		spin_unlock(&dev->dev_reservation_lock);
		core_scsi3_put_pr_reg(pr_reg);
		return 0;
	}
	spin_unlock(&dev->dev_reservation_lock);

	spin_lock(&pr_tmpl->registration_lock);
	list_for_each_entry(pr_reg_p, &pr_tmpl->registration_list,
			pr_reg_list) {
		/*
		 * Do not establish a UNIT ATTENTION condition
		 * for the calling I_T Nexus
		 */
		if (pr_reg_p == pr_reg)
			continue;

		core_scsi3_ua_allocate(pr_reg_p->pr_reg_nacl,
				pr_reg_p->pr_res_mapped_lun,
				0x2A, ASCQ_2AH_RESERVATIONS_RELEASED);
	}
	spin_unlock(&pr_tmpl->registration_lock);

	if (pr_tmpl->pr_aptpl_active) {
		ret = core_scsi3_update_and_write_aptpl(SE_DEV(cmd),
				&pr_reg->pr_aptpl_buf[0],
				pr_tmpl->pr_aptpl_buf_len);
		if (!(ret))
			printk("SPC-3 PR: Updated APTPL metadata for RELEASE\n");
	}

	core_scsi3_put_pr_reg(pr_reg);
	return 0;
}

static int core_scsi3_emulate_pro_clear(
	se_cmd_t *cmd,
	u64 res_key)
{
	se_device_t *dev = cmd->se_dev;
	se_node_acl_t *pr_reg_nacl;
	se_session_t *se_sess = SE_SESS(cmd);
	t10_reservation_template_t *pr_tmpl = &SU_DEV(dev)->t10_reservation;
	t10_pr_registration_t *pr_reg, *pr_reg_tmp, *pr_reg_n, *pr_res_holder;
	u32 pr_res_mapped_lun = 0;
	int calling_it_nexus = 0;
	/*
	 * Locate the existing *pr_reg via se_node_acl_t pointers
	 */
	pr_reg_n = core_scsi3_locate_pr_reg(SE_DEV(cmd),
			se_sess->se_node_acl);
	if (!(pr_reg_n)) {
		printk(KERN_ERR "SPC-3 PR: Unable to locate"
			" PR_REGISTERED *pr_reg for CLEAR\n");
			return PYX_TRANSPORT_LU_COMM_FAILURE;
	}
	/*
	 * From spc4r17 section 5.7.11.6, Clearing:
	 *
	 * Any application client may release the persistent reservation and
	 * remove all registrations from a device server by issuing a
	 * PERSISTENT RESERVE OUT command with CLEAR service action through a
	 * registered I_T nexus with the following parameter:
	 *
	 *	a) RESERVATION KEY field set to the value of the reservation key
	 * 	   that is registered with the logical unit for the I_T nexus.
	 */
	if (res_key != pr_reg_n->pr_res_key) {
		printk(KERN_ERR "SPC-3 PR REGISTER: Received"
			" res_key: 0x%016Lx does not match"
			" existing SA REGISTER res_key:"
			" 0x%016Lx\n", res_key, pr_reg_n->pr_res_key);
		core_scsi3_put_pr_reg(pr_reg_n);
		return PYX_TRANSPORT_RESERVATION_CONFLICT;
	}
	/*
	 * a) Release the persistent reservation, if any;
	 */
	spin_lock(&dev->dev_reservation_lock);
	pr_res_holder = dev->dev_pr_res_holder;
	if (pr_res_holder) {
		se_node_acl_t *pr_res_nacl = pr_res_holder->pr_reg_nacl;
		__core_scsi3_complete_pro_release(dev, pr_res_nacl,
			pr_res_holder, 0);
	}
	spin_unlock(&dev->dev_reservation_lock);
	/*
	 * b) Remove all registration(s) (see spc4r17 5.7.7);
	 */
	spin_lock(&pr_tmpl->registration_lock);
	list_for_each_entry_safe(pr_reg, pr_reg_tmp,
			&pr_tmpl->registration_list, pr_reg_list) {

		calling_it_nexus = (pr_reg_n == pr_reg) ? 1 : 0;
		pr_reg_nacl = pr_reg->pr_reg_nacl;
		pr_res_mapped_lun = pr_reg->pr_res_mapped_lun;
		__core_scsi3_free_registration(dev, pr_reg, NULL,
					calling_it_nexus);
		/*
		 * e) Establish a unit attention condition for the initiator
		 *    port associated with every registered I_T nexus other
		 *    than the I_T nexus on which the PERSISTENT RESERVE OUT
		 *    command with CLEAR service action was received, with the
		 *    additional sense code set to RESERVATIONS PREEMPTED.
		 */
		if (!(calling_it_nexus))
			core_scsi3_ua_allocate(pr_reg_nacl, pr_res_mapped_lun,
				0x2A, ASCQ_2AH_RESERVATIONS_PREEMPTED);
	}
	spin_unlock(&pr_tmpl->registration_lock);

	printk(KERN_INFO "SPC-3 PR [%s] Service Action: CLEAR complete\n",
		CMD_TFO(cmd)->get_fabric_name());

	if (pr_tmpl->pr_aptpl_active) {
		core_scsi3_update_and_write_aptpl(SE_DEV(cmd), NULL, 0);
		printk(KERN_INFO "SPC-3 PR: Updated APTPL metadata"
				" for CLEAR\n");
	}

	core_scsi3_pr_generation(dev);
	return 0;
}

/*
 * Called with se_device_t->dev_reservation_lock held.
 */
static void __core_scsi3_complete_pro_preempt(
	se_device_t *dev,
	t10_pr_registration_t *pr_reg,
	struct list_head *preempt_and_abort_list,
	int type,
	int scope,
	int abort)
{
	se_node_acl_t *nacl = pr_reg->pr_reg_nacl;
	struct target_core_fabric_ops *tfo = nacl->se_tpg->se_tpg_tfo;
	/*
	 * Do an implict RELEASE of the existing reservation.
	 */
	if (dev->dev_pr_res_holder)
		__core_scsi3_complete_pro_release(dev, nacl,
				dev->dev_pr_res_holder, 0);

	dev->dev_pr_res_holder = pr_reg;
	pr_reg->pr_res_holder = 1;
	pr_reg->pr_res_type = type;
	pr_reg->pr_res_scope = scope;

	printk(KERN_INFO "SPC-3 PR [%s] Service Action: PREEMPT%s created new"
		" reservation holder TYPE: %s ALL_TG_PT: %d\n",
		tfo->get_fabric_name(), (abort) ? "_AND_ABORT" : "",
		core_scsi3_pr_dump_type(type),
		(pr_reg->pr_reg_all_tg_pt) ? 1 : 0);
	printk(KERN_INFO "SPC-3 PR [%s] PREEMPT%s from Node: %s\n",
		tfo->get_fabric_name(), (abort) ? "_AND_ABORT" : "",
		nacl->initiatorname);
	/*
	 * For PREEMPT_AND_ABORT, add the preempting reservation's
	 * t10_pr_registration_t to the list that will be compared
	 * against received CDBs..
	 */
	if (preempt_and_abort_list)
		list_add_tail(&pr_reg->pr_reg_abort_list,
				preempt_and_abort_list);
}

static void core_scsi3_release_preempt_and_abort(
	struct list_head *preempt_and_abort_list,
	t10_pr_registration_t *pr_reg_holder)
{
	t10_pr_registration_t *pr_reg, *pr_reg_tmp;

	list_for_each_entry_safe(pr_reg, pr_reg_tmp, preempt_and_abort_list,
				pr_reg_abort_list) {

		list_del(&pr_reg->pr_reg_abort_list);
		if (pr_reg_holder == pr_reg)
			continue;
		if (pr_reg->pr_res_holder) {
			printk(KERN_WARNING "pr_reg->pr_res_holder still set\n");
			continue;
		}

		pr_reg->pr_reg_deve = NULL;
		pr_reg->pr_reg_nacl = NULL;
		kfree(pr_reg->pr_aptpl_buf);
		kmem_cache_free(t10_pr_reg_cache, pr_reg);
	}
}

int core_scsi3_check_cdb_abort_and_preempt(
	struct list_head *preempt_and_abort_list,
	se_cmd_t *cmd)
{
	t10_pr_registration_t *pr_reg, *pr_reg_tmp;

	list_for_each_entry_safe(pr_reg, pr_reg_tmp, preempt_and_abort_list,
				pr_reg_abort_list) {
		if (pr_reg->pr_res_key == cmd->pr_res_key)
			return 0;
	}

	return 1;
}

static int core_scsi3_pro_preempt(
	se_cmd_t *cmd,
	int type,
	int scope,
	u64 res_key,
	u64 sa_res_key,
	int abort)
{
	se_device_t *dev = SE_DEV(cmd);
	se_dev_entry_t *se_deve;
	se_node_acl_t *pr_reg_nacl;
	se_session_t *se_sess = SE_SESS(cmd);
	struct list_head preempt_and_abort_list;
	t10_pr_registration_t *pr_reg, *pr_reg_tmp, *pr_reg_n, *pr_res_holder;
	t10_reservation_template_t *pr_tmpl = &SU_DEV(dev)->t10_reservation;
	u32 pr_res_mapped_lun = 0;
	int all_reg = 0, calling_it_nexus = 0, released_regs = 0;
	int prh_type = 0, prh_scope = 0, ret;

	if (!(se_sess))
		return PYX_TRANSPORT_LU_COMM_FAILURE;

	se_deve = &se_sess->se_node_acl->device_list[cmd->orig_fe_lun];
	if (!(se_deve->deve_flags & DEF_PR_REGISTERED))
		return PYX_TRANSPORT_RESERVATION_CONFLICT;

	pr_reg_n = core_scsi3_locate_pr_reg(SE_DEV(cmd), se_sess->se_node_acl);
	if (!(pr_reg_n)) {
		printk(KERN_ERR "SPC-3 PR: Unable to locate"
			" PR_REGISTERED *pr_reg for PREEMPT%s\n",
			(abort) ? "_AND_ABORT" : "");
		return PYX_TRANSPORT_RESERVATION_CONFLICT;
	}
	if (pr_reg_n->pr_res_key != res_key) {
		core_scsi3_put_pr_reg(pr_reg_n);
		return PYX_TRANSPORT_RESERVATION_CONFLICT;
	}
	if (scope != PR_SCOPE_LU_SCOPE) {
		printk(KERN_ERR "SPC-3 PR: Illegal SCOPE: 0x%02x\n", scope);
		core_scsi3_put_pr_reg(pr_reg_n);
		return PYX_TRANSPORT_INVALID_PARAMETER_LIST;
	}
	INIT_LIST_HEAD(&preempt_and_abort_list);

	spin_lock(&dev->dev_reservation_lock);
	pr_res_holder = dev->dev_pr_res_holder;
	if (pr_res_holder &&
	   ((pr_res_holder->pr_res_type == PR_TYPE_WRITE_EXCLUSIVE_ALLREG) ||
	    (pr_res_holder->pr_res_type == PR_TYPE_EXCLUSIVE_ACCESS_ALLREG)))
		all_reg = 1;

	if (!(all_reg) && !(sa_res_key)) {
		spin_unlock(&dev->dev_reservation_lock);
		core_scsi3_put_pr_reg(pr_reg_n);
		return PYX_TRANSPORT_INVALID_PARAMETER_LIST;
	}
	/*
	 * From spc4r17, section 5.7.11.4.4 Removing Registrations:
	 *
	 * If the SERVICE ACTION RESERVATION KEY field does not identify a
	 * persistent reservation holder or there is no persistent reservation
	 * holder (i.e., there is no persistent reservation), then the device
	 * server shall perform a preempt by doing the following in an
	 * uninterrupted series of actions. (See below..)
	 */
	if (!(pr_res_holder) || (pr_res_holder->pr_res_key != sa_res_key)) {
		/*
		 * No existing or SA Reservation Key matching reservations..
		 *
		 * PROUT SA PREEMPT with All Registrant type reservations are
		 * allowed to be processed without a matching SA Reservation Key
		 */
		spin_lock(&pr_tmpl->registration_lock);
		list_for_each_entry_safe(pr_reg, pr_reg_tmp,
				&pr_tmpl->registration_list, pr_reg_list) {
			/*
			 * Removing of registrations in non all registrants
			 * type reservations without a matching SA reservation
			 * key.
			 *
			 * a) Remove the registrations for all I_T nexuses
			 *    specified by the SERVICE ACTION RESERVATION KEY
			 *    field;
			 * b) Ignore the contents of the SCOPE and TYPE fields;
			 * c) Process tasks as defined in 5.7.1; and
			 * d) Establish a unit attention condition for the
			 *    initiator port associated with every I_T nexus
			 *    that lost its registration other than the I_T
			 *    nexus on which the PERSISTENT RESERVE OUT command
			 *    was received, with the additional sense code set
			 *    to REGISTRATIONS PREEMPTED.
			 */
			if (!(all_reg)) {
				if (pr_reg->pr_res_key != sa_res_key)
					continue;

				calling_it_nexus = (pr_reg_n == pr_reg) ? 1 : 0;
				pr_reg_nacl = pr_reg->pr_reg_nacl;
				pr_res_mapped_lun = pr_reg->pr_res_mapped_lun;
				__core_scsi3_free_registration(dev, pr_reg,
					(abort) ? &preempt_and_abort_list :
						NULL, calling_it_nexus);
				released_regs++;
			} else {
				/*
				 * Case for any existing all registrants type
				 * reservation, follow logic in spc4r17 section
				 * 5.7.11.4 Preempting, Table 52 and Figure 7.
				 *
				 * For a ZERO SA Reservation key, release
				 * all other registrations and do an implict
				 * release of active persistent reservation.
				 *
				 * For a non-ZERO SA Reservation key, only
				 * release the matching reservation key from
				 * registrations.
				 */
				if ((sa_res_key) &&
				     (pr_reg->pr_res_key != sa_res_key))
					continue;

				calling_it_nexus = (pr_reg_n == pr_reg) ? 1 : 0;
				if (calling_it_nexus)
					continue;

				pr_reg_nacl = pr_reg->pr_reg_nacl;
				pr_res_mapped_lun = pr_reg->pr_res_mapped_lun;
				__core_scsi3_free_registration(dev, pr_reg,
					(abort) ? &preempt_and_abort_list :
						NULL, 0);
				released_regs++;
			}
			if (!(calling_it_nexus))
				core_scsi3_ua_allocate(pr_reg_nacl,
					pr_res_mapped_lun, 0x2A,
					ASCQ_2AH_RESERVATIONS_PREEMPTED);
		}
		spin_unlock(&pr_tmpl->registration_lock);
		/*
		 * If a PERSISTENT RESERVE OUT with a PREEMPT service action or
		 * a PREEMPT AND ABORT service action sets the SERVICE ACTION
		 * RESERVATION KEY field to a value that does not match any
		 * registered reservation key, then the device server shall
		 * complete the command with RESERVATION CONFLICT status.
		 */
		if (!(released_regs)) {
			spin_unlock(&dev->dev_reservation_lock);
			core_scsi3_put_pr_reg(pr_reg_n);
			return PYX_TRANSPORT_RESERVATION_CONFLICT;
		}
		/*
		 * For an existing all registrants type reservation
		 * with a zero SA rservation key, preempt the existing
		 * reservation with the new PR type and scope.
		 */
		if (pr_res_holder && all_reg && !(sa_res_key)) {
			__core_scsi3_complete_pro_preempt(dev, pr_reg_n,
				(abort) ? &preempt_and_abort_list : NULL,
				type, scope, abort);

			if (abort)
				core_scsi3_release_preempt_and_abort(
					&preempt_and_abort_list, pr_reg_n);
		}
		spin_unlock(&dev->dev_reservation_lock);

		if (pr_tmpl->pr_aptpl_active) {
			ret = core_scsi3_update_and_write_aptpl(SE_DEV(cmd),
					&pr_reg_n->pr_aptpl_buf[0],
					pr_tmpl->pr_aptpl_buf_len);
			if (!(ret))
				printk(KERN_INFO "SPC-3 PR: Updated APTPL"
					" metadata for  PREEMPT%s\n", (abort) ?
					"_AND_ABORT" : "");
		}

		core_scsi3_put_pr_reg(pr_reg_n);
		core_scsi3_pr_generation(SE_DEV(cmd));
		return 0;
	}
	/*
	 * The PREEMPTing SA reservation key matches that of the
	 * existing persistent reservation, first, we check if
	 * we are preempting our own reservation.
	 * From spc4r17, section 5.7.11.4.3 Preempting
	 * persistent reservations and registration handling
	 *
	 * If an all registrants persistent reservation is not
	 * present, it is not an error for the persistent
	 * reservation holder to preempt itself (i.e., a
	 * PERSISTENT RESERVE OUT with a PREEMPT service action
	 * or a PREEMPT AND ABORT service action with the
	 * SERVICE ACTION RESERVATION KEY value equal to the
	 * persistent reservation holder's reservation key that
	 * is received from the persistent reservation holder).
	 * In that case, the device server shall establish the
	 * new persistent reservation and maintain the
	 * registration.
	 */
	prh_type = pr_res_holder->pr_res_type;
	prh_scope = pr_res_holder->pr_res_scope;
	/*
	 * If the SERVICE ACTION RESERVATION KEY field identifies a
	 * persistent reservation holder (see 5.7.10), the device
	 * server shall perform a preempt by doing the following as
	 * an uninterrupted series of actions:
	 *
	 * a) Release the persistent reservation for the holder
	 *    identified by the SERVICE ACTION RESERVATION KEY field;
	 */
	if (pr_reg_n != pr_res_holder)
		__core_scsi3_complete_pro_release(dev,
				pr_res_holder->pr_reg_nacl,
				dev->dev_pr_res_holder, 0);
	/*
	 * b) Remove the registrations for all I_T nexuses identified
	 *    by the SERVICE ACTION RESERVATION KEY field, except the
	 *    I_T nexus that is being used for the PERSISTENT RESERVE
	 *    OUT command. If an all registrants persistent reservation
	 *    is present and the SERVICE ACTION RESERVATION KEY field
	 *    is set to zero, then all registrations shall be removed
	 *    except for that of the I_T nexus that is being used for
	 *    the PERSISTENT RESERVE OUT command;
	 */
	spin_lock(&pr_tmpl->registration_lock);
	list_for_each_entry_safe(pr_reg, pr_reg_tmp,
			&pr_tmpl->registration_list, pr_reg_list) {

		calling_it_nexus = (pr_reg_n == pr_reg) ? 1 : 0;
		if (calling_it_nexus)
			continue;

		if (pr_reg->pr_res_key != sa_res_key)
			continue;

		pr_reg_nacl = pr_reg->pr_reg_nacl;
		pr_res_mapped_lun = pr_reg->pr_res_mapped_lun;
		__core_scsi3_free_registration(dev, pr_reg,
				(abort) ? &preempt_and_abort_list : NULL,
				calling_it_nexus);
		/*
		 * e) Establish a unit attention condition for the initiator
		 *    port associated with every I_T nexus that lost its
		 *    persistent reservation and/or registration, with the
		 *    additional sense code set to REGISTRATIONS PREEMPTED;
		 */
		core_scsi3_ua_allocate(pr_reg_nacl, pr_res_mapped_lun, 0x2A,
				ASCQ_2AH_RESERVATIONS_PREEMPTED);
	}
	spin_unlock(&pr_tmpl->registration_lock);
	/*
	 * c) Establish a persistent reservation for the preempting
	 *    I_T nexus using the contents of the SCOPE and TYPE fields;
	 */
	__core_scsi3_complete_pro_preempt(dev, pr_reg_n,
			(abort) ? &preempt_and_abort_list : NULL,
			type, scope, abort);
	/*
	 * d) Process tasks as defined in 5.7.1;
	 * e) See above..
	 * f) If the type or scope has changed, then for every I_T nexus
	 *    whose reservation key was not removed, except for the I_T
	 *    nexus on which the PERSISTENT RESERVE OUT command was
	 *    received, the device server shall establish a unit
	 *    attention condition for the initiator port associated with
	 *    that I_T nexus, with the additional sense code set to
	 *    RESERVATIONS RELEASED. If the type or scope have not
	 *    changed, then no unit attention condition(s) shall be
	 *    established for this reason.
	 */
	if ((prh_type != type) || (prh_scope != scope)) {
		spin_lock(&pr_tmpl->registration_lock);
		list_for_each_entry_safe(pr_reg, pr_reg_tmp,
				&pr_tmpl->registration_list, pr_reg_list) {

			calling_it_nexus = (pr_reg_n == pr_reg) ? 1 : 0;
			if (calling_it_nexus)
				continue;

			core_scsi3_ua_allocate(pr_reg->pr_reg_nacl,
					pr_reg->pr_res_mapped_lun, 0x2A,
					ASCQ_2AH_RESERVATIONS_RELEASED);
		}
		spin_unlock(&pr_tmpl->registration_lock);
	}
	spin_unlock(&dev->dev_reservation_lock);
	/*
	 * Call LUN_RESET logic upon list of t10_pr_registration_t,
	 * All received CDBs for the matching existing reservation and
	 * registrations undergo ABORT_TASK logic.
	 *
	 * From there, core_scsi3_release_preempt_and_abort() will
	 * release every registration in the list (which have already
	 * been removed from the primary pr_reg list), except the
	 * new persistent reservation holder, the calling Initiator Port.
	 */
	if (abort) {
		core_tmr_lun_reset(dev, NULL, &preempt_and_abort_list, cmd);
		core_scsi3_release_preempt_and_abort(&preempt_and_abort_list,
						pr_reg_n);
	}

	if (pr_tmpl->pr_aptpl_active) {
		ret = core_scsi3_update_and_write_aptpl(SE_DEV(cmd),
				&pr_reg_n->pr_aptpl_buf[0],
				pr_tmpl->pr_aptpl_buf_len);
		if (!(ret))
			printk("SPC-3 PR: Updated APTPL metadata for PREEMPT"
				"%s\n", (abort) ? "_AND_ABORT" : "");
	}

	core_scsi3_put_pr_reg(pr_reg_n);
	core_scsi3_pr_generation(SE_DEV(cmd));
	return 0;
}

static int core_scsi3_emulate_pro_preempt(
	se_cmd_t *cmd,
	int type,
	int scope,
	u64 res_key,
	u64 sa_res_key,
	int abort)
{
	int ret = 0;

	switch (type) {
	case PR_TYPE_WRITE_EXCLUSIVE:
	case PR_TYPE_EXCLUSIVE_ACCESS:
	case PR_TYPE_WRITE_EXCLUSIVE_REGONLY:
	case PR_TYPE_EXCLUSIVE_ACCESS_REGONLY:
	case PR_TYPE_WRITE_EXCLUSIVE_ALLREG:
	case PR_TYPE_EXCLUSIVE_ACCESS_ALLREG:
		ret = core_scsi3_pro_preempt(cmd, type, scope,
				res_key, sa_res_key, abort);
		break;
	default:
		printk(KERN_ERR "SPC-3 PR: Unknown Service Action PREEMPT%s"
			" Type: 0x%02x\n", (abort) ? "_AND_ABORT" : "", type);
		return PYX_TRANSPORT_INVALID_CDB_FIELD;
	}

	return ret;
}


static int core_scsi3_emulate_pro_register_and_move(
	se_cmd_t *cmd,
	u64 res_key,
	u64 sa_res_key,
	int aptpl,
	int unreg)
{
	se_session_t *se_sess = SE_SESS(cmd);
	se_device_t *dev = SE_DEV(cmd);
	se_dev_entry_t *se_deve, *dest_se_deve = NULL;
	se_lun_t *se_lun = SE_LUN(cmd);
	se_node_acl_t *pr_res_nacl, *pr_reg_nacl, *dest_node_acl = NULL;
	se_port_t *se_port;
	se_portal_group_t *se_tpg, *dest_se_tpg = NULL;
	struct target_core_fabric_ops *dest_tf_ops = NULL, *tf_ops;
	t10_pr_registration_t *pr_reg, *pr_res_holder, *dest_pr_reg;
	t10_reservation_template_t *pr_tmpl = &SU_DEV(dev)->t10_reservation;
	unsigned char *buf = (unsigned char *)T_TASK(cmd)->t_task_buf;
	unsigned char *initiator_str;
	char *iport_ptr = NULL, dest_iport[64];
	u32 tid_len;
	int new_reg = 0, type, scope, ret;
	unsigned short rtpi;
	unsigned char proto_ident;

	if (!(se_sess) || !(se_lun)) {
		printk(KERN_ERR "SPC-3 PR: se_sess || se_lun_t is NULL!\n");
		return PYX_TRANSPORT_LU_COMM_FAILURE;
	}
	memset(dest_iport, 0, 64);
	se_tpg = se_sess->se_tpg;
	tf_ops = TPG_TFO(se_tpg);
	se_deve = &se_sess->se_node_acl->device_list[cmd->orig_fe_lun];
	/*
	 * Follow logic from spc4r17 Section 5.7.8, Table 50 --
	 *	Register behaviors for a REGISTER AND MOVE service action
	 */
	if (!(se_deve->deve_flags & DEF_PR_REGISTERED)) {
		printk(KERN_WARNING "SPC-3 PR: Received REGISTER_AND_MOVE SA"
				" from unregistered nexus\n");
		return PYX_TRANSPORT_RESERVATION_CONFLICT;
	}
	/*
	 * Locate the existing *pr_reg via se_node_acl_t pointers
	 */
	pr_reg = core_scsi3_locate_pr_reg(SE_DEV(cmd), se_sess->se_node_acl);
	if (!(pr_reg)) {
		printk(KERN_ERR "SPC-3 PR: Unable to locate PR_REGISTERED"
			" *pr_reg for REGISTER_AND_MOVE\n");
		return PYX_TRANSPORT_LU_COMM_FAILURE;
	}
	/*
	 * The provided reservation key much match the existing reservation key
	 * provided during this initiator's I_T nexus registration.
	 */
	if (res_key != pr_reg->pr_res_key) {
		printk(KERN_WARNING "SPC-3 PR REGISTER_AND_MOVE: Received"
			" res_key: 0x%016Lx does not match existing SA REGISTER"
			" res_key: 0x%016Lx\n", res_key, pr_reg->pr_res_key);
		core_scsi3_put_pr_reg(pr_reg);
		return PYX_TRANSPORT_RESERVATION_CONFLICT;
	}
	/*
	 * The service active reservation key needs to be non zero
	 */
	if (!(sa_res_key)) {
		printk(KERN_WARNING "SPC-3 PR REGISTER_AND_MOVE: Received zero"
			" sa_res_key\n");
		core_scsi3_put_pr_reg(pr_reg);
		return PYX_TRANSPORT_INVALID_PARAMETER_LIST;
	}
	/*
	 * Determine the Relative Target Port Identifier where the reservation
	 * will be moved to for the TransportID containing SCSI initiator WWN
	 * information.
	 */
	rtpi = (buf[18] & 0xff) << 8;
	rtpi |= buf[19] & 0xff;
	tid_len = (buf[20] & 0xff) << 24;
	tid_len |= (buf[21] & 0xff) << 16;
	tid_len |= (buf[22] & 0xff) << 8;
	tid_len |= buf[23] & 0xff;

	if ((tid_len + 24) != cmd->data_length) {
		printk(KERN_ERR "SPC-3 PR: Illegal tid_len: %u + 24 byte header"
			" does not equal CDB data_length: %u\n", tid_len,
			cmd->data_length);
		core_scsi3_put_pr_reg(pr_reg);
		return PYX_TRANSPORT_INVALID_PARAMETER_LIST;
	}

	spin_lock(&dev->se_port_lock);
	list_for_each_entry(se_port, &dev->dev_sep_list, sep_list) {
		if (se_port->sep_rtpi != rtpi)
			continue;
		dest_se_tpg = se_port->sep_tpg;
		if (!(dest_se_tpg))
			continue;
		dest_tf_ops = TPG_TFO(dest_se_tpg);
		if (!(dest_tf_ops))
			continue;
		spin_unlock(&dev->se_port_lock);

		ret = configfs_depend_item(dest_tf_ops->tf_subsys,
				&dest_se_tpg->tpg_group.cg_item);
		if (ret != 0) {
			printk(KERN_ERR "configfs_depend_item() failed for"
				" dest_se_tpg->tpg_group\n");
			core_scsi3_put_pr_reg(pr_reg);
			return PYX_TRANSPORT_LU_COMM_FAILURE;
		}

		spin_lock(&dev->se_port_lock);
		break;
	}
	spin_unlock(&dev->se_port_lock);

	if (!(dest_se_tpg) || (!dest_tf_ops)) {
		printk(KERN_ERR "SPC-3 PR REGISTER_AND_MOVE: Unable to locate"
			" fabric ops from Relative Target Port Identifier:"
			" %hu\n", rtpi);
		core_scsi3_put_pr_reg(pr_reg);
		return PYX_TRANSPORT_INVALID_PARAMETER_LIST;
	}
	proto_ident = (buf[24] & 0x0f);
#if 0
	printk("SPC-3 PR REGISTER_AND_MOVE: Extracted Protocol Identifier:"
			" 0x%02x\n", proto_ident);
#endif
	if (proto_ident != dest_tf_ops->get_fabric_proto_ident()) {
		printk(KERN_ERR "SPC-3 PR REGISTER_AND_MOVE: Received"
			" proto_ident: 0x%02x does not match ident: 0x%02x"
			" from fabric: %s\n", proto_ident,
			dest_tf_ops->get_fabric_proto_ident(),
			dest_tf_ops->get_fabric_name());
		ret = PYX_TRANSPORT_INVALID_PARAMETER_LIST;
		goto out;
	}
	if (dest_tf_ops->tpg_parse_pr_out_transport_id == NULL) {
		printk(KERN_ERR "SPC-3 PR REGISTER_AND_MOVE: Fabric does not"
			" containg a valid tpg_parse_pr_out_transport_id"
			" function pointer\n");
		ret = PYX_TRANSPORT_LU_COMM_FAILURE;
		goto out;
	}
	initiator_str = dest_tf_ops->tpg_parse_pr_out_transport_id(
			(const char *)&buf[24], NULL, &iport_ptr);
	if (!(initiator_str)) {
		printk(KERN_ERR "SPC-3 PR REGISTER_AND_MOVE: Unable to locate"
			" initiator_str from Transport ID\n");
		ret = PYX_TRANSPORT_INVALID_PARAMETER_LIST;
		goto out;
	}

	printk(KERN_INFO "SPC-3 PR [%s] Extracted initiator %s identifier: %s"
		" %s\n", dest_tf_ops->get_fabric_name(), (iport_ptr != NULL) ?
		"port" : "device", initiator_str, (iport_ptr != NULL) ?
		iport_ptr : "");
	/*
	 * If a PERSISTENT RESERVE OUT command with a REGISTER AND MOVE service
	 * action specifies a TransportID that is the same as the initiator port
	 * of the I_T nexus for the command received, then the command shall
	 * be terminated with CHECK CONDITION status, with the sense key set to
	 * ILLEGAL REQUEST, and the additional sense code set to INVALID FIELD
	 * IN PARAMETER LIST.
	 */
	pr_reg_nacl = pr_reg->pr_reg_nacl;
	if (!(strcmp(initiator_str, pr_reg_nacl->initiatorname))) {
		printk(KERN_ERR "SPC-3 PR REGISTER_AND_MOVE: TransportID: %s"
			" matches: %s on received I_T Nexus\n", initiator_str,
			pr_reg_nacl->initiatorname);
		ret = PYX_TRANSPORT_INVALID_PARAMETER_LIST;
		goto out;
	}
	/*
	 * Locate the destination se_node_acl_t from the received Transport ID
	 */
	dest_node_acl = core_tpg_get_initiator_node_acl(dest_se_tpg,
				initiator_str);
	if (!(dest_node_acl)) {
		printk(KERN_ERR "Unable to locate %s dest_node_acl for"
			" TransportID%s\n", dest_tf_ops->get_fabric_name(),
			initiator_str);
		ret = PYX_TRANSPORT_INVALID_PARAMETER_LIST;
		goto out;
	}
	ret = configfs_depend_item(dest_tf_ops->tf_subsys,
				&dest_node_acl->acl_group.cg_item);
	if (ret != 0) {
		printk(KERN_ERR "configfs_depend_item() failed for"
			" dest_node_acl->acl_group\n");
		ret = PYX_TRANSPORT_LU_COMM_FAILURE;
		dest_node_acl = NULL;
		goto out;
	}
#if 0
	printk(KERN_INFO "SPC-3 PR REGISTER_AND_MOVE: Found %s dest_node_acl:"
		" %s from TransportID\n", dest_tf_ops->get_fabric_name(),
		dest_node_acl->initiatorname);
#endif
	/*
	 * If the a SCSI Initiator Port identifier is presented, then
	 * the SCSI nexus must be present and matching the provided
	 * TransportID.  The active se_session_t pointer is available
	 * from dest_node_acl->nacl_sess;
	 */
	if (iport_ptr != NULL) {
		spin_lock(&dest_node_acl->nacl_sess_lock);
		if (dest_node_acl->nacl_sess == NULL) {
			printk(KERN_ERR "SPC-3 PR REGISTER_AND_MOVE: "
				"iport_ptr: %s presented in Transport ID,"
				" but no active nexus exists for %s Fabric"
				" Node: %s\n", iport_ptr,
				dest_tf_ops->get_fabric_name(),
				dest_node_acl->initiatorname);
			spin_unlock(&dest_node_acl->nacl_sess_lock);
			ret = PYX_TRANSPORT_INVALID_PARAMETER_LIST;
			goto out;
		}
		TPG_TFO(se_tpg)->sess_get_initiator_wwn(
					dest_node_acl->nacl_sess,
					&dest_iport[0], 64);
		spin_unlock(&dest_node_acl->nacl_sess_lock);

		if (strcmp(dest_iport, iport_ptr)) {
			printk(KERN_ERR "SPC-3 PR REGISTER_AND_MOVE:"
				" dest_iport: %s and iport_ptr: %s do not"
				" match!\n", dest_iport, iport_ptr);
			ret = PYX_TRANSPORT_INVALID_PARAMETER_LIST;
			goto out;
		}
	}
	/*
	 * Locate the se_dev_entry_t pointer for the matching RELATIVE TARGET
	 * PORT IDENTIFIER.  core_get_se_deve_from_rtpi() will call
	 * configfs_item_depend() on deve->se_lun_acl->se_lun_group.cg_item
	 */
	dest_se_deve = core_get_se_deve_from_rtpi(dest_node_acl, rtpi);
	if (!(dest_se_deve)) {
		printk(KERN_ERR "Unable to locate %s dest_se_deve from RTPI:"
			" %hu\n",  dest_tf_ops->get_fabric_name(), rtpi);
		ret = PYX_TRANSPORT_INVALID_PARAMETER_LIST;
		goto out;
	}
#if 0
	printk(KERN_INFO "SPC-3 PR REGISTER_AND_MOVE: Located %s node %s LUN"
		" ACL for dest_se_deve->mapped_lun: %u\n",
		dest_tf_ops->get_fabric_name(), dest_node_acl->initiatorname,
		dest_se_deve->mapped_lun);
#endif
	/*
	 * A persistent reservation needs to already existing in order to
	 * successfully complete the REGISTER_AND_MOVE service action..
	 */
	spin_lock(&dev->dev_reservation_lock);
	pr_res_holder = dev->dev_pr_res_holder;
	if (!(pr_res_holder)) {
		printk(KERN_WARNING "SPC-3 PR REGISTER_AND_MOVE: No reservation"
			" currently held\n");
		spin_unlock(&dev->dev_reservation_lock);
		ret = PYX_TRANSPORT_INVALID_CDB_FIELD;
		goto out;
	}
	/*
	 * The received on I_T Nexus must be the reservation holder.
	 *
	 * From spc4r17 section 5.7.8  Table 50 --
	 * 	Register behaviors for a REGISTER AND MOVE service action
	 */
	if (pr_res_holder != pr_reg) {
		printk(KERN_WARNING "SPC-3 PR REGISTER_AND_MOVE: Calling I_T"
			" Nexus is not reservation holder\n");
		spin_unlock(&dev->dev_reservation_lock);
		ret = PYX_TRANSPORT_RESERVATION_CONFLICT;
		goto out;
	}
	/*
	 * From spc4r17 section 5.7.8: registering and moving reservation
	 *
	 * If a PERSISTENT RESERVE OUT command with a REGISTER AND MOVE service
	 * action is received and the established persistent reservation is a
	 * Write Exclusive - All Registrants type or Exclusive Access -
	 * All Registrants type reservation, then the command shall be completed
	 * with RESERVATION CONFLICT status.
	 */
	if ((pr_res_holder->pr_res_type == PR_TYPE_WRITE_EXCLUSIVE_ALLREG) ||
	    (pr_res_holder->pr_res_type == PR_TYPE_EXCLUSIVE_ACCESS_ALLREG)) {
		printk(KERN_WARNING "SPC-3 PR REGISTER_AND_MOVE: Unable to move"
			" reservation for type: %s\n",
			core_scsi3_pr_dump_type(pr_res_holder->pr_res_type));
		spin_unlock(&dev->dev_reservation_lock);
		ret = PYX_TRANSPORT_RESERVATION_CONFLICT;
		goto out;
	}
	pr_res_nacl = pr_res_holder->pr_reg_nacl;
	/*
	 * b) Ignore the contents of the (received) SCOPE and TYPE fields;
	 */
	type = pr_res_holder->pr_res_type;
	scope = pr_res_holder->pr_res_type;
	/*
	 * c) Associate the reservation key specified in the SERVICE ACTION
	 *    RESERVATION KEY field with the I_T nexus specified as the
	 *    destination of the register and move, where:
	 *    A) The I_T nexus is specified by the TransportID and the
	 *	 RELATIVE TARGET PORT IDENTIFIER field (see 6.14.4); and
	 *    B) Regardless of the TransportID format used, the association for
	 *       the initiator port is based on either the initiator port name
	 *       (see 3.1.71) on SCSI transport protocols where port names are
	 *       required or the initiator port identifier (see 3.1.70) on SCSI
	 *       transport protocols where port names are not required;
	 * d) Register the reservation key specified in the SERVICE ACTION
	 *    RESERVATION KEY field;
	 * e) Retain the reservation key specified in the SERVICE ACTION
	 *    RESERVATION KEY field and associated information;
	 *
	 * Also, It is not an error for a REGISTER AND MOVE service action to
	 * register an I_T nexus that is already registered with the same
	 * reservation key or a different reservation key.
	 */
	if (!(dest_se_deve->deve_flags & DEF_PR_REGISTERED)) {
		ret = core_scsi3_alloc_registration(SE_DEV(cmd),
				dest_node_acl, dest_se_deve,
				sa_res_key, 0, aptpl, 2, 1);
		if (ret != 0) {
			spin_unlock(&dev->dev_reservation_lock);
			ret = PYX_TRANSPORT_INVALID_PARAMETER_LIST;
			goto out;
		}
		new_reg = 1;
	}
	/*
	 * Locate the Destination registration where the reservation
	 * is being moved.
	 */
	dest_pr_reg = core_scsi3_locate_pr_reg(dev, dest_node_acl);
	if (!(dest_pr_reg)) {
		printk(KERN_ERR "Unable to locate dest_pr_reg for"
			" REGISTERED I_T Nexus for %s\n", initiator_str);
		spin_unlock(&dev->dev_reservation_lock);
		ret = PYX_TRANSPORT_INVALID_PARAMETER_LIST;
		goto out;
	}
	/*
	 * f) Release the persistent reservation for the persistent reservation
	 *    holder (i.e., the I_T nexus on which the
	 */
	__core_scsi3_complete_pro_release(dev, pr_res_nacl,
			dev->dev_pr_res_holder, 0);
	/*
	 * g) Move the persistent reservation to the specified I_T nexus using
	 *    the same scope and type as the persistent reservation released in
	 *    item f); and
	 */
	dev->dev_pr_res_holder = dest_pr_reg;
	dest_pr_reg->pr_res_holder = 1;
	dest_pr_reg->pr_res_type = type;
	pr_reg->pr_res_scope = scope;
	/*
	 * Increment PRGeneration for existing registrations..
	 */
	if (!(new_reg))
		dest_pr_reg->pr_res_generation = pr_tmpl->pr_generation++;
	spin_unlock(&dev->dev_reservation_lock);

	printk(KERN_INFO "SPC-3 PR [%s] Service Action: REGISTER_AND_MOVE"
		" created new reservation holder TYPE: %s on object RTPI:"
		" %hu  PRGeneration: 0x%08x\n", dest_tf_ops->get_fabric_name(),
		core_scsi3_pr_dump_type(type), rtpi,
		dest_pr_reg->pr_res_generation);
	printk(KERN_INFO "SPC-3 PR Successfully moved reservation from"
		" %s Fabric Node: %s -> %s Fabric Node: %s %s\n",
		tf_ops->get_fabric_name(), pr_reg_nacl->initiatorname,
		dest_tf_ops->get_fabric_name(), dest_node_acl->initiatorname,
		(iport_ptr != NULL) ? iport_ptr : "");
	/*
	 * It is now safe to release configfs group dependencies for destination
	 * of Transport ID Initiator Device/Port Identifier
	 */
	configfs_undepend_item(dest_tf_ops->tf_subsys,
			&dest_se_deve->se_lun_acl->se_lun_group.cg_item);
	configfs_undepend_item(dest_tf_ops->tf_subsys,
			&dest_node_acl->acl_group.cg_item);
	configfs_undepend_item(dest_tf_ops->tf_subsys,
			&dest_se_tpg->tpg_group.cg_item);
	/*
	 * h) If the UNREG bit is set to one, unregister (see 5.7.11.3) the I_T
	 * nexus on which PERSISTENT RESERVE OUT command was received.
	 */
	if (unreg) {
		spin_lock(&pr_tmpl->registration_lock);
		__core_scsi3_free_registration(dev, pr_reg, NULL, 1);
		spin_unlock(&pr_tmpl->registration_lock);
	} else
		core_scsi3_put_pr_reg(pr_reg);

	/*
	 * Clear the APTPL metadata if APTPL has been disabled, otherwise
	 * write out the updated metadata to struct file for this SCSI device.
	 */
	if (!(aptpl)) {
		pr_tmpl->pr_aptpl_active = 0;
		core_scsi3_update_and_write_aptpl(SE_DEV(cmd), NULL, 0);
		printk("SPC-3 PR: Set APTPL Bit Deactivated for"
				" REGISTER_AND_MOVE\n");
	} else {
		pr_tmpl->pr_aptpl_active = 1;
		ret = core_scsi3_update_and_write_aptpl(SE_DEV(cmd),
				&dest_pr_reg->pr_aptpl_buf[0],
				pr_tmpl->pr_aptpl_buf_len);
		if (!(ret))
			printk("SPC-3 PR: Set APTPL Bit Activated for"
					" REGISTER_AND_MOVE\n");
	}

	core_scsi3_put_pr_reg(dest_pr_reg);
	return 0;
out:
	if (dest_se_deve)
		configfs_undepend_item(dest_tf_ops->tf_subsys,
			&dest_se_deve->se_lun_acl->se_lun_group.cg_item);
	if (dest_node_acl)
		configfs_undepend_item(dest_tf_ops->tf_subsys,
				&dest_node_acl->acl_group.cg_item);
	configfs_undepend_item(dest_tf_ops->tf_subsys,
			&dest_se_tpg->tpg_group.cg_item);
	core_scsi3_put_pr_reg(pr_reg);
	return ret;
}

static unsigned long long core_scsi3_extract_reservation_key(unsigned char *cdb)
{
	unsigned int __v1, __v2;

	__v1 = (cdb[0] << 24) | (cdb[1] << 16) | (cdb[2] << 8) | cdb[3];
	__v2 = (cdb[4] << 24) | (cdb[5] << 16) | (cdb[6] << 8) | cdb[7];

	return ((unsigned long long)__v2) | (unsigned long long)__v1 << 32;
}

/*
 * See spc4r17 section 6.14 Table 170
 */
static int core_scsi3_emulate_pr_out(se_cmd_t *cmd, unsigned char *cdb)
{
	unsigned char *buf = (unsigned char *)T_TASK(cmd)->t_task_buf;
	u64 res_key, sa_res_key;
	int sa, scope, type, aptpl;
	int spec_i_pt = 0, all_tg_pt = 0, unreg = 0;
	/*
	 * FIXME: A NULL se_session_t pointer means an this is not coming from
	 * a $FABRIC_MOD's nexus, but from internal passthrough ops.
	 */
	if (!(SE_SESS(cmd)))
		return PYX_TRANSPORT_LU_COMM_FAILURE;

	if (cmd->data_length < 24) {
		printk(KERN_WARNING "SPC-PR: Recieved PR OUT parameter list"
			" length too small: %u\n", cmd->data_length);
		return PYX_TRANSPORT_INVALID_PARAMETER_LIST;
	}
	/*
	 * From the PERSISTENT_RESERVE_OUT command descriptor block (CDB)
	 */
	sa = (cdb[1] & 0x1f);
	scope = (cdb[2] & 0xf0);
	type = (cdb[2] & 0x0f);
	/*
	 * From PERSISTENT_RESERVE_OUT parameter list (payload)
	 */
	res_key = core_scsi3_extract_reservation_key(&buf[0]);
	sa_res_key = core_scsi3_extract_reservation_key(&buf[8]);
	/*
	 * REGISTER_AND_MOVE uses a different SA parameter list containing
	 * SCSI TransportIDs.
	 */
	if (sa != PRO_REGISTER_AND_MOVE) {
		spec_i_pt = (buf[20] & 0x08);
		all_tg_pt = (buf[20] & 0x04);
		aptpl = (buf[20] & 0x01);
	} else {
		aptpl = (buf[17] & 0x01);
		unreg = (buf[17] & 0x02);
	}
	/*
	 * SPEC_I_PT=1 is only valid for Service action: REGISTER
	 */
	if (spec_i_pt && ((cdb[1] & 0x1f) != PRO_REGISTER))
		return PYX_TRANSPORT_INVALID_PARAMETER_LIST;
	/*
	 * From spc4r17 section 6.14:
	 *
	 * If the SPEC_I_PT bit is set to zero, the service action is not
	 * REGISTER AND MOVE, and the parameter list length is not 24, then
	 * the command shall be terminated with CHECK CONDITION status, with
	 * the sense key set to ILLEGAL REQUEST, and the additional sense
	 * code set to PARAMETER LIST LENGTH ERROR.
	 */
	if (!(spec_i_pt) && ((cdb[1] & 0x1f) != PRO_REGISTER_AND_MOVE) &&
	    (cmd->data_length != 24)) {
		printk(KERN_WARNING "SPC-PR: Recieved PR OUT illegal parameter"
			" list length: %u\n", cmd->data_length);
		return PYX_TRANSPORT_INVALID_PARAMETER_LIST;
	}
	/*
	 * (core_scsi3_emulate_pro_* function parameters
	 * are defined by spc4r17 Table 174:
	 * PERSISTENT_RESERVE_OUT service actions and valid parameters.
	 */
	switch (sa) {
	case PRO_REGISTER:
		return core_scsi3_emulate_pro_register(cmd,
			res_key, sa_res_key, aptpl, all_tg_pt, spec_i_pt, 0);
	case PRO_RESERVE:
		return core_scsi3_emulate_pro_reserve(cmd,
			type, scope, res_key);
	case PRO_RELEASE:
		return core_scsi3_emulate_pro_release(cmd,
			type, scope, res_key);
	case PRO_CLEAR:
		return core_scsi3_emulate_pro_clear(cmd, res_key);
	case PRO_PREEMPT:
		return core_scsi3_emulate_pro_preempt(cmd, type, scope,
					res_key, sa_res_key, 0);
	case PRO_PREEMPT_AND_ABORT:
		return core_scsi3_emulate_pro_preempt(cmd, type, scope,
					res_key, sa_res_key, 1);
	case PRO_REGISTER_AND_IGNORE_EXISTING_KEY:
		return core_scsi3_emulate_pro_register(cmd,
			0, sa_res_key, aptpl, all_tg_pt, spec_i_pt, 1);
	case PRO_REGISTER_AND_MOVE:
		return core_scsi3_emulate_pro_register_and_move(cmd, res_key,
				sa_res_key, aptpl, unreg);
	default:
		printk(KERN_ERR "Unknown PERSISTENT_RESERVE_OUT service"
			" action: 0x%02x\n", cdb[1] & 0x1f);
		return PYX_TRANSPORT_INVALID_CDB_FIELD;
	}

	return PYX_TRANSPORT_INVALID_CDB_FIELD;
}

/*
 * PERSISTENT_RESERVE_IN Service Action READ_KEYS
 *
 * See spc4r17 section 5.7.6.2 and section 6.13.2, Table 160
 */
static int core_scsi3_pri_read_keys(se_cmd_t *cmd)
{
	se_device_t *se_dev = SE_DEV(cmd);
	se_subsystem_dev_t *su_dev = SU_DEV(se_dev);
	t10_pr_registration_t *pr_reg;
	unsigned char *buf = (unsigned char *)T_TASK(cmd)->t_task_buf;
	u32 add_len = 0, off = 8;

	if (cmd->data_length < 8) {
		printk(KERN_ERR "PRIN SA READ_KEYS SCSI Data Length: %u"
			" too small\n", cmd->data_length);
		return PYX_TRANSPORT_INVALID_CDB_FIELD;
	}

	buf[0] = ((T10_RES(su_dev)->pr_generation >> 24) & 0xff);
	buf[1] = ((T10_RES(su_dev)->pr_generation >> 16) & 0xff);
	buf[2] = ((T10_RES(su_dev)->pr_generation >> 8) & 0xff);
	buf[3] = (T10_RES(su_dev)->pr_generation & 0xff);

	spin_lock(&T10_RES(su_dev)->registration_lock);
	list_for_each_entry(pr_reg, &T10_RES(su_dev)->registration_list,
			pr_reg_list) {
		/*
		 * Check for overflow of 8byte PRI READ_KEYS payload and
		 * next reservation key list descriptor.
		 */
		if ((add_len + 8) > (cmd->data_length - 8))
			break;

		buf[off++] = ((pr_reg->pr_res_key >> 56) & 0xff);
		buf[off++] = ((pr_reg->pr_res_key >> 48) & 0xff);
		buf[off++] = ((pr_reg->pr_res_key >> 40) & 0xff);
		buf[off++] = ((pr_reg->pr_res_key >> 32) & 0xff);
		buf[off++] = ((pr_reg->pr_res_key >> 24) & 0xff);
		buf[off++] = ((pr_reg->pr_res_key >> 16) & 0xff);
		buf[off++] = ((pr_reg->pr_res_key >> 8) & 0xff);
		buf[off++] = (pr_reg->pr_res_key & 0xff);

		add_len += 8;
	}
	spin_unlock(&T10_RES(su_dev)->registration_lock);

	buf[4] = ((add_len >> 24) & 0xff);
	buf[5] = ((add_len >> 16) & 0xff);
	buf[6] = ((add_len >> 8) & 0xff);
	buf[7] = (add_len & 0xff);

	return 0;
}

/*
 * PERSISTENT_RESERVE_IN Service Action READ_RESERVATION
 *
 * See spc4r17 section 5.7.6.3 and section 6.13.3.2 Table 161 and 162
 */
static int core_scsi3_pri_read_reservation(se_cmd_t *cmd)
{
	se_device_t *se_dev = SE_DEV(cmd);
	se_subsystem_dev_t *su_dev = SU_DEV(se_dev);
	t10_pr_registration_t *pr_reg;
	unsigned char *buf = (unsigned char *)T_TASK(cmd)->t_task_buf;
	u64 pr_res_key;
	u32 add_len = 16; /* Hardcoded to 16 when a reservation is held. */

	if (cmd->data_length < 8) {
		printk(KERN_ERR "PRIN SA READ_RESERVATIONS SCSI Data Length: %u"
			" too small\n", cmd->data_length);
		return PYX_TRANSPORT_INVALID_CDB_FIELD;
	}

	buf[0] = ((T10_RES(su_dev)->pr_generation >> 24) & 0xff);
	buf[1] = ((T10_RES(su_dev)->pr_generation >> 16) & 0xff);
	buf[2] = ((T10_RES(su_dev)->pr_generation >> 8) & 0xff);
	buf[3] = (T10_RES(su_dev)->pr_generation & 0xff);

	spin_lock(&se_dev->dev_reservation_lock);
	pr_reg = se_dev->dev_pr_res_holder;
	if ((pr_reg)) {
		/*
		 * Set the hardcoded Additional Length
		 */
		buf[4] = ((add_len >> 24) & 0xff);
		buf[5] = ((add_len >> 16) & 0xff);
		buf[6] = ((add_len >> 8) & 0xff);
		buf[7] = (add_len & 0xff);

		if (cmd->data_length < 22) {
			spin_unlock(&se_dev->dev_reservation_lock);
			return 0;
		}
		/*
		 * Set the Reservation key.
		 *
		 * From spc4r17, section 5.7.10:
		 * A persistent reservation holder has its reservation key
		 * returned in the parameter data from a PERSISTENT
		 * RESERVE IN command with READ RESERVATION service action as
		 * follows:
		 * a) For a persistent reservation of the type Write Exclusive
		 *    - All Registrants or Exclusive Access ­ All Regitrants,
		 *      the reservation key shall be set to zero; or
		 * b) For all other persistent reservation types, the
		 *    reservation key shall be set to the registered
		 *    reservation key for the I_T nexus that holds the
		 *    persistent reservation.
		 */
		if ((pr_reg->pr_res_type == PR_TYPE_WRITE_EXCLUSIVE_ALLREG) ||
		    (pr_reg->pr_res_type == PR_TYPE_EXCLUSIVE_ACCESS_ALLREG))
			pr_res_key = 0;
		else
			pr_res_key = pr_reg->pr_res_key;

		buf[8] = ((pr_res_key >> 56) & 0xff);
		buf[9] = ((pr_res_key >> 48) & 0xff);
		buf[10] = ((pr_res_key >> 40) & 0xff);
		buf[11] = ((pr_res_key >> 32) & 0xff);
		buf[12] = ((pr_res_key >> 24) & 0xff);
		buf[13] = ((pr_res_key >> 16) & 0xff);
		buf[14] = ((pr_res_key >> 8) & 0xff);
		buf[15] = (pr_res_key & 0xff);
		/*
		 * Set the SCOPE and TYPE
		 */
		buf[21] = (pr_reg->pr_res_scope & 0xf0) |
			  (pr_reg->pr_res_type & 0x0f);
	}
	spin_unlock(&se_dev->dev_reservation_lock);

	return 0;
}

/*
 * PERSISTENT_RESERVE_IN Service Action REPORT_CAPABILITIES
 *
 * See spc4r17 section 6.13.4 Table 165
 */
static int core_scsi3_pri_report_capabilities(se_cmd_t *cmd)
{
	se_device_t *dev = SE_DEV(cmd);
	t10_reservation_template_t *pr_tmpl = &SU_DEV(dev)->t10_reservation;
	unsigned char *buf = (unsigned char *)T_TASK(cmd)->t_task_buf;
	u16 add_len = 8; /* Hardcoded to 8. */

	if (cmd->data_length < 6) {
		printk(KERN_ERR "PRIN SA REPORT_CAPABILITIES SCSI Data Length:"
			" %u too small\n", cmd->data_length);
		return PYX_TRANSPORT_INVALID_CDB_FIELD;
	}

	buf[0] = ((add_len << 8) & 0xff);
	buf[1] = (add_len & 0xff);
	/*
	 * FIXME: Leave these features disabled for now..
	 */
#if 0
	buf[2] |= 0x10; /* CRH: Compatible Reservation Hanlding bit. */
#endif
	buf[2] |= 0x08; /* SIP_C: Specify Initiator Ports Capable bit */
	buf[2] |= 0x04; /* ATP_C: All Target Ports Capable bit */
	buf[2] |= 0x01; /* PTPL_C: Persistence across Target Power Loss bit */
	/*
	 * We are filling in the PERSISTENT RESERVATION TYPE MASK below, so
	 * set the TMV: Task Mask Valid bit.
	 */
	buf[3] |= 0x80;
	/*
	 * Change ALLOW COMMANDs to 0x20 or 0x40 later from Table 166
	 */
	buf[3] |= 0x10; /* ALLOW COMMANDs field 001b */
	/*
	 * PTPL_A: Persistence across Target Power Loss Active bit
	 */
	if (pr_tmpl->pr_aptpl_active)
		buf[3] |= 0x01;
	/*
	 * Setup the PERSISTENT RESERVATION TYPE MASK from Table 167
	 */
	buf[4] |= 0x80; /* PR_TYPE_EXCLUSIVE_ACCESS_ALLREG */
	buf[4] |= 0x40; /* PR_TYPE_EXCLUSIVE_ACCESS_REGONLY */
	buf[4] |= 0x20; /* PR_TYPE_WRITE_EXCLUSIVE_REGONLY */
	buf[4] |= 0x08; /* PR_TYPE_EXCLUSIVE_ACCESS */
	buf[4] |= 0x02; /* PR_TYPE_WRITE_EXCLUSIVE */
	buf[5] |= 0x01; /* PR_TYPE_EXCLUSIVE_ACCESS_ALLREG */

	return 0;
}

/*
 * PERSISTENT_RESERVE_IN Service Action READ_FULL_STATUS
 *
 * See spc4r17 section 6.13.5 Table 168 and 169
 */
static int core_scsi3_pri_read_full_status(se_cmd_t *cmd)
{
	se_device_t *se_dev = SE_DEV(cmd);
	se_node_acl_t *se_nacl;
	se_subsystem_dev_t *su_dev = SU_DEV(se_dev);
	se_portal_group_t *se_tpg;
	t10_pr_registration_t *pr_reg, *pr_reg_tmp;
	t10_reservation_template_t *pr_tmpl = &SU_DEV(se_dev)->t10_reservation;
	unsigned char *buf = (unsigned char *)T_TASK(cmd)->t_task_buf;
	u32 add_desc_len = 0, add_len = 0, desc_len, exp_desc_len;
	u32 off = 8; /* off into first Full Status descriptor */
	int format_code = 0;

	if (cmd->data_length < 8) {
		printk(KERN_ERR "PRIN SA READ_FULL_STATUS SCSI Data Length: %u"
			" too small\n", cmd->data_length);
		return PYX_TRANSPORT_INVALID_CDB_FIELD;
	}

	buf[0] = ((T10_RES(su_dev)->pr_generation >> 24) & 0xff);
	buf[1] = ((T10_RES(su_dev)->pr_generation >> 16) & 0xff);
	buf[2] = ((T10_RES(su_dev)->pr_generation >> 8) & 0xff);
	buf[3] = (T10_RES(su_dev)->pr_generation & 0xff);

	spin_lock(&pr_tmpl->registration_lock);
	list_for_each_entry_safe(pr_reg, pr_reg_tmp,
			&pr_tmpl->registration_list, pr_reg_list) {

		se_nacl = pr_reg->pr_reg_nacl;
		se_tpg = pr_reg->pr_reg_nacl->se_tpg;
		add_desc_len = 0;
		/*
		 * Determine expected length of $FABRIC_MOD specific
		 * TransportID full status descriptor..
		 */
		exp_desc_len = TPG_TFO(se_tpg)->tpg_get_pr_transport_id_len(
				se_tpg, se_nacl, &format_code);

		if ((exp_desc_len + add_len) > cmd->data_length) {
			printk(KERN_WARNING "SPC-3 PRIN READ_FULL_STATUS ran"
				" out of buffer: %d\n", cmd->data_length);
			break;
		}
		/*
		 * Set RESERVATION KEY
		 */
		buf[off++] = ((pr_reg->pr_res_key >> 56) & 0xff);
		buf[off++] = ((pr_reg->pr_res_key >> 48) & 0xff);
		buf[off++] = ((pr_reg->pr_res_key >> 40) & 0xff);
		buf[off++] = ((pr_reg->pr_res_key >> 32) & 0xff);
		buf[off++] = ((pr_reg->pr_res_key >> 24) & 0xff);
		buf[off++] = ((pr_reg->pr_res_key >> 16) & 0xff);
		buf[off++] = ((pr_reg->pr_res_key >> 8) & 0xff);
		buf[off++] = (pr_reg->pr_res_key & 0xff);
		off += 4; /* Skip Over Reserved area */

		/*
		 * Set ALL_TG_PT bit if PROUT SA REGISTER had this set.
		 */
		if (pr_reg->pr_reg_all_tg_pt)
			buf[off] = 0x02;
		/*
		 * The se_lun_t pointer will be present for the
		 * reservation holder for PR_HOLDER bit.
		 *
		 * Also, if this registration is the reservation
		 * holder, fill in SCOPE and TYPE in the next byte.
		 */
		if (pr_reg->pr_res_holder) {
			buf[off++] |= 0x01;
			buf[off++] = (pr_reg->pr_res_scope & 0xf0) |
				     (pr_reg->pr_res_type & 0x0f);
		} else
			off += 2;

		off += 4; /* Skip over reserved area */
		/*
		 * From spc4r17 6.3.15:
		 *
		 * If the ALL_TG_PT bit set to zero, the RELATIVE TARGET PORT
		 * IDENTIFIER field contains the relative port identifier (see
		 * 3.1.120) of the target port that is part of the I_T nexus
		 * described by this full status descriptor. If the ALL_TG_PT
		 * bit is set to one, the contents of the RELATIVE TARGET PORT
		 * IDENTIFIER field are not defined by this standard.
		 */
		if (!(pr_reg->pr_reg_all_tg_pt)) {
			se_port_t *port = pr_reg->pr_reg_tg_pt_lun->lun_sep;

			buf[off++] = ((port->sep_rtpi >> 8) & 0xff);
			buf[off++] = (port->sep_rtpi & 0xff);
		} else
			off += 2; /* Skip over RELATIVE TARGET PORT IDENTIFER */

		/*
		 * Now, have the $FABRIC_MOD fill in the protocol identifier
		 */
		desc_len = TPG_TFO(se_tpg)->tpg_get_pr_transport_id(se_tpg,
				se_nacl, &format_code, &buf[off+4]);
		/*
		 * Set the ADDITIONAL DESCRIPTOR LENGTH
		 */
		buf[off++] = ((desc_len >> 24) & 0xff);
		buf[off++] = ((desc_len >> 16) & 0xff);
		buf[off++] = ((desc_len >> 8) & 0xff);
		buf[off++] = (desc_len & 0xff);
		/*
		 * Size of full desctipor header minus TransportID
		 * containing $FABRIC_MOD specific) initiator device/port
		 * WWN information.
		 *
		 *  See spc4r17 Section 6.13.5 Table 169
		 */
		add_desc_len = (24 + desc_len);

		off += desc_len;
		add_len += add_desc_len;
	}
	spin_unlock(&pr_tmpl->registration_lock);
	/*
	 * Set ADDITIONAL_LENGTH
	 */
	buf[4] = ((add_len >> 24) & 0xff);
	buf[5] = ((add_len >> 16) & 0xff);
	buf[6] = ((add_len >> 8) & 0xff);
	buf[7] = (add_len & 0xff);

	return 0;
}

static int core_scsi3_emulate_pr_in(se_cmd_t *cmd, unsigned char *cdb)
{
	switch (cdb[1] & 0x1f) {
	case PRI_READ_KEYS:
		return core_scsi3_pri_read_keys(cmd);
	case PRI_READ_RESERVATION:
		return core_scsi3_pri_read_reservation(cmd);
	case PRI_REPORT_CAPABILITIES:
		return core_scsi3_pri_report_capabilities(cmd);
	case PRI_READ_FULL_STATUS:
		return core_scsi3_pri_read_full_status(cmd);
	default:
		printk(KERN_ERR "Unknown PERSISTENT_RESERVE_IN service"
			" action: 0x%02x\n", cdb[1] & 0x1f);
		return PYX_TRANSPORT_INVALID_CDB_FIELD;
	}

}

int core_scsi3_emulate_pr(se_cmd_t *cmd)
{
	unsigned char *cdb = &T_TASK(cmd)->t_task_cdb[0];

	return (cdb[0] == PERSISTENT_RESERVE_OUT) ?
	       core_scsi3_emulate_pr_out(cmd, cdb) :
	       core_scsi3_emulate_pr_in(cmd, cdb);
}

static int core_pt_reservation_check(se_cmd_t *cmd, u32 *pr_res_type)
{
	return 0;
}

static int core_pt_reserve(se_cmd_t *cmd)
{
	return 0;
}

static int core_pt_release(se_cmd_t *cmd)
{
	return 0;
}

static int core_pt_seq_non_holder(
	se_cmd_t *cmd,
	unsigned char *cdb,
	u32 pr_reg_type)
{
	return 0;
}

int core_setup_reservations(se_device_t *dev)
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
		printk(KERN_INFO "%s: Using SPC_PASSTHROUGH, no reservation"
			" emulation\n", TRANSPORT(dev)->name);
		return 0;
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
		printk(KERN_INFO "%s: Using SPC3_PERSISTENT_RESERVATIONS"
			" emulation\n", TRANSPORT(dev)->name);
	} else {
		rest->res_type = SPC2_RESERVATIONS;
		rest->t10_reservation_check = &core_scsi2_reservation_check;
		rest->t10_reserve = &core_scsi2_reservation_reserve;
		rest->t10_release = &core_scsi2_reservation_release;
		rest->t10_seq_non_holder =
				&core_scsi2_reservation_seq_non_holder;
		printk(KERN_INFO "%s: Using SPC2_RESERVATIONS emulation\n",
			TRANSPORT(dev)->name);
	}

	return 0;
}
