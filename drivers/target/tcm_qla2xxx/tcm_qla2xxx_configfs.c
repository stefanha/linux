/*******************************************************************************
 * Filename:  tcm_qla2xxx_configfs.c
 *
 * This file contains TCM QLA2XXX fabric module implementation using
 * v4 configfs fabric infrastructure for QLogic target mode HBAs
 *
 * Copyright (c) 2010 Rising Tide, Inc.
 * Copyright (c) 2010 Linux-iSCSI.org
 *
 * Copyright (c) 2010 Nicholas A. Bellinger <nab@linux-iscsi.org>
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
 ****************************************************************************/

#define TCM_QLA2XXX_CONFIGFS_C

#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/version.h>
#include <generated/utsrelease.h>
#include <linux/utsname.h>
#include <linux/init.h>
#include <linux/slab.h>
#include <linux/kthread.h>
#include <linux/types.h>
#include <linux/string.h>
#include <linux/configfs.h>
#include <linux/ctype.h>
#include <asm/unaligned.h>

#include <target/target_core_base.h>
#include <target/target_core_transport.h>
#include <target/target_core_fabric_ops.h>
#include <target/target_core_fabric_configfs.h>
#include <target/target_core_fabric_lib.h>
#include <target/target_core_device.h>
#include <target/target_core_tpg.h>
#include <target/target_core_configfs.h>
#include <target/target_core_base.h>
#include <target/configfs_macros.h>

#include <tcm_qla2xxx_base.h>
#include <tcm_qla2xxx_fabric.h>

#include <qla_def.h>

#undef TCM_QLA2XXX_CONFIGFS_C

/* Local pointer to allocated TCM configfs fabric module */
struct target_fabric_configfs *tcm_qla2xxx_fabric_configfs;
struct target_fabric_configfs *tcm_qla2xxx_npiv_fabric_configfs;

static struct se_node_acl *tcm_qla2xxx_make_nodeacl(
	struct se_portal_group *se_tpg,
	struct config_group *group,
	const char *name)
{
	struct se_node_acl *se_nacl, *se_nacl_new;
	struct tcm_qla2xxx_nacl *nacl;
	u64 wwpn;
	u32 qla2xxx_nexus_depth;

	if (tcm_qla2xxx_parse_wwn(name, &wwpn, 1) < 0)
		return ERR_PTR(-EINVAL);

	se_nacl_new = tcm_qla2xxx_alloc_fabric_acl(se_tpg);
	if (!(se_nacl_new))
		return ERR_PTR(-ENOMEM);
//#warning FIXME: Hardcoded qla2xxx_nexus depth in tcm_qla2xxx_make_nodeacl()
	qla2xxx_nexus_depth = 1;
	/*
	 * se_nacl_new may be released by core_tpg_add_initiator_node_acl()
	 * when converting a NdoeACL from demo mode -> explict
	 */
	se_nacl = core_tpg_add_initiator_node_acl(se_tpg, se_nacl_new,
				name, qla2xxx_nexus_depth);
	if (IS_ERR(se_nacl)) {
		tcm_qla2xxx_release_fabric_acl(se_tpg, se_nacl_new);
		return se_nacl;
	}
	/*
	 * Locate our struct tcm_qla2xxx_nacl and set the FC Nport WWPN
	 */
	nacl = container_of(se_nacl, struct tcm_qla2xxx_nacl, se_node_acl);
	nacl->nport_wwpn = wwpn;
	tcm_qla2xxx_format_wwn(&nacl->nport_name[0], TCM_QLA2XXX_NAMELEN, wwpn);

	return se_nacl;
}

static void tcm_qla2xxx_drop_nodeacl(struct se_node_acl *se_acl)
{
	struct tcm_qla2xxx_nacl *nacl = container_of(se_acl,
				struct tcm_qla2xxx_nacl, se_node_acl);	
	kfree(nacl);
}

static struct se_portal_group *tcm_qla2xxx_make_tpg(
	struct se_wwn *wwn,
	struct config_group *group,
	const char *name)
{
	struct tcm_qla2xxx_lport *lport = container_of(wwn,
			struct tcm_qla2xxx_lport, lport_wwn);
	struct tcm_qla2xxx_tpg *tpg;
	unsigned long tpgt;
	int ret;

	if (strstr(name, "tpgt_") != name)
		return ERR_PTR(-EINVAL);
	if (strict_strtoul(name + 5, 10, &tpgt) || tpgt > USHRT_MAX)
		return ERR_PTR(-EINVAL);
	
	tpg = kzalloc(sizeof(struct tcm_qla2xxx_tpg), GFP_KERNEL);
	if (!(tpg)) {
		printk(KERN_ERR "Unable to allocate struct tcm_qla2xxx_tpg\n");
		return ERR_PTR(-ENOMEM);
	}
	tpg->lport = lport;
	tpg->lport_tpgt = tpgt;

	ret = core_tpg_register(&tcm_qla2xxx_fabric_configfs->tf_ops, wwn,
				&tpg->se_tpg, (void *)tpg,
				TRANSPORT_TPG_TYPE_NORMAL);
	if (ret < 0) {
		kfree(tpg);
		return NULL;
	}
	return &tpg->se_tpg;
}

static void tcm_qla2xxx_drop_tpg(struct se_portal_group *se_tpg)
{
	struct tcm_qla2xxx_tpg *tpg = container_of(se_tpg,
				struct tcm_qla2xxx_tpg, se_tpg);

	core_tpg_deregister(se_tpg);
	kfree(tpg);
}

static struct se_portal_group *tcm_qla2xxx_npiv_make_tpg(
	struct se_wwn *wwn,
	struct config_group *group,
	const char *name)
{
	struct tcm_qla2xxx_lport *lport = container_of(wwn,
			struct tcm_qla2xxx_lport, lport_wwn);
	struct tcm_qla2xxx_tpg *tpg;
	unsigned long tpgt;
	int ret;

	if (strstr(name, "tpgt_") != name)
		return ERR_PTR(-EINVAL);
	if (strict_strtoul(name + 5, 10, &tpgt) || tpgt > USHRT_MAX)
		return ERR_PTR(-EINVAL);

	tpg = kzalloc(sizeof(struct tcm_qla2xxx_tpg), GFP_KERNEL);
	if (!(tpg)) {
		printk(KERN_ERR "Unable to allocate struct tcm_qla2xxx_tpg\n");
		return ERR_PTR(-ENOMEM);
	}
	tpg->lport = lport;
	tpg->lport_tpgt = tpgt;

	ret = core_tpg_register(&tcm_qla2xxx_npiv_fabric_configfs->tf_ops, wwn,
				&tpg->se_tpg, (void *)tpg,
				TRANSPORT_TPG_TYPE_NORMAL);
	if (ret < 0) {
		kfree(tpg);
		return NULL;
	}
	return &tpg->se_tpg;
}


static void tcm_qla2xxx_init_lport(
	struct tcm_qla2xxx_lport *lport,
	struct scsi_qla_host *vha,
	struct scsi_qla_host *npiv_vp)
{
	struct qla_hw_data *ha = vha->hw;

	/*
	 * Setup local pointer to vha, NPIV VP pointer (if present) and
	 * vha->tcm_lport pointer
	 */
	lport->qla_vha = vha;
	lport->qla_npiv_vp = npiv_vp;
	ha->tcm_lport = lport;
}

static struct se_wwn *tcm_qla2xxx_make_lport(
	struct target_fabric_configfs *tf,
	struct config_group *group,
	const char *name)
{
	struct tcm_qla2xxx_lport *lport;
	struct Scsi_Host *host = NULL;
	struct pci_dev *dev = NULL;
	struct scsi_qla_host *vha;
	struct qla_hw_data *ha;
	unsigned long flags;
	u64 wwpn;
	int i, ret = -ENODEV;
	u8 b[8];

	if (tcm_qla2xxx_parse_wwn(name, &wwpn, 1) < 0)
		return ERR_PTR(-EINVAL);

	lport = kzalloc(sizeof(struct tcm_qla2xxx_lport), GFP_KERNEL);
	if (!(lport)) {
		printk(KERN_ERR "Unable to allocate struct tcm_qla2xxx_lport\n");
		return ERR_PTR(-ENOMEM);
	}
	lport->lport_wwpn = wwpn;
	tcm_qla2xxx_format_wwn(&lport->lport_name[0], TCM_QLA2XXX_NAMELEN, wwpn);

	while ((dev = pci_get_device(PCI_VENDOR_ID_QLOGIC, PCI_ANY_ID,
					dev)) != NULL) {

		vha = pci_get_drvdata(dev);
		if (!vha)
			continue;
		ha = vha->hw;
		if (!ha)
			continue;
		host = vha->host;
		if (!host)
			continue;

		if (!(host->hostt->supported_mode & MODE_TARGET))
			continue;

		spin_lock_irqsave(&ha->hardware_lock, flags);
		if (host->active_mode & MODE_TARGET) {
			printk(KERN_INFO "MODE_TARGET already active on qla2xxx"
					"(%d)\n",  host->host_no);
			spin_unlock_irqrestore(&ha->hardware_lock, flags);
			continue;
		}
		spin_unlock_irqrestore(&ha->hardware_lock, flags);

		if (!scsi_host_get(host)) {
			printk(KERN_ERR "Unable to scsi_host_get() for"
				" qla2xxx scsi_host\n");
			ret = -EINVAL;
			goto out;
		}

		printk("qla2xxx HW vha->node_name: ");
		for (i = 0; i < 8; i++)
			printk("%02x ", vha->node_name[i]);
		printk("\n");

		printk("qla2xxx HW vha->port_name: ");
		for (i = 0; i < 8; i++)
			printk("%02x ", vha->port_name[i]);
		printk("\n");

		printk("qla2xxx passed configfs WWPN: ");
		put_unaligned_be64(wwpn, b);
		for (i = 0; i < 8; i++)
			printk("%02x ", b[i]);
		printk("\n");

		if (memcmp(vha->port_name, b, 8)) {
			scsi_host_put(host);
			continue;
		}
		printk("qla2xxx: Found matching HW WWPN: %s for lport\n", name);
		tcm_qla2xxx_init_lport(lport, vha, NULL);
		ret = 0;
		break;
	}

	if (ret != 0)
		goto out;

	return &lport->lport_wwn;
out:
	kfree(lport);
	return ERR_PTR(ret);
}

static void tcm_qla2xxx_drop_lport(struct se_wwn *wwn)
{
	struct tcm_qla2xxx_lport *lport = container_of(wwn,
			struct tcm_qla2xxx_lport, lport_wwn);
	struct scsi_qla_host *vha = lport->qla_vha;
	struct Scsi_Host *sh = vha->host;

	scsi_host_put(sh);
	kfree(lport);
}

static struct se_wwn *tcm_qla2xxx_npiv_make_lport(
	struct target_fabric_configfs *tf,
	struct config_group *group,
	const char *name)
{
	struct tcm_qla2xxx_lport *lport;
	struct Scsi_Host *host = NULL;
	struct pci_dev *dev = NULL;
	struct scsi_qla_host *vha, *npiv_vp;
	struct qla_hw_data *ha;
	struct fc_vport_identifiers vid;
	struct fc_vport *vport;
	unsigned long flags;
	u64 npiv_wwpn, npiv_wwnn;
	int i, ret = -ENODEV;
	u8 b[8], b2[8];

	if (tcm_qla2xxx_npiv_parse_wwn(name, strlen(name)+1,
				&npiv_wwpn, &npiv_wwnn) < 0)
		return ERR_PTR(-EINVAL);

	lport = kzalloc(sizeof(struct tcm_qla2xxx_lport), GFP_KERNEL);
	if (!(lport)) {
		printk(KERN_ERR "Unable to allocate struct tcm_qla2xxx_lport"
				" for NPIV\n");
		return ERR_PTR(-ENOMEM);
	}
	lport->lport_npiv_wwpn = npiv_wwpn;
	lport->lport_npiv_wwnn = npiv_wwnn;
	tcm_qla2xxx_npiv_format_wwn(&lport->lport_npiv_name[0],
			TCM_QLA2XXX_NAMELEN, npiv_wwpn, npiv_wwnn);

	while ((dev = pci_get_device(PCI_VENDOR_ID_QLOGIC, PCI_ANY_ID,
					dev)) != NULL) {

		vha = pci_get_drvdata(dev);
		if (!vha)
			continue;
		ha = vha->hw;
		if (!ha)
			continue;
		host = vha->host;
		if (!host)
			continue;

		if (!(host->hostt->supported_mode & MODE_TARGET))
			continue;

		spin_lock_irqsave(&ha->hardware_lock, flags);
		if (host->active_mode & MODE_TARGET) {
			printk(KERN_INFO "MODE_TARGET already active on qla2xxx"
					"(%d)\n",  host->host_no);
			spin_unlock_irqrestore(&ha->hardware_lock, flags);
			continue;
		}
		spin_unlock_irqrestore(&ha->hardware_lock, flags);

		if (!scsi_host_get(host)) {
			printk(KERN_ERR "Unable to scsi_host_get() for"
				" qla2xxx scsi_host\n");
			ret = -EINVAL;
			goto out;
		}

		printk("qla2xxx HW vha->node_name: ");
		for (i = 0; i < 8; i++)
			printk("%02x ", vha->node_name[i]);
		printk("\n");

		printk("qla2xxx HW vha->port_name: ");
		for (i = 0; i < 8; i++)
			printk("%02x ", vha->port_name[i]);
		printk("\n");

		printk("qla2xxx passed configfs NPIV WWPN: ");
		put_unaligned_be64(npiv_wwpn, b);
		for (i = 0; i < 8; i++)
			printk("%02x ", b[i]);
		printk("\n");

		printk("qla2xxx passed configfs NPIV WWNN: ");
		put_unaligned_be64(npiv_wwnn, b2);
		for (i = 0; i < 8; i++)
			printk("%02x ", b2[i]);
		printk("\n");

		spin_lock_irqsave(&ha->vport_slock, flags);
		list_for_each_entry(npiv_vp, &ha->vp_list, list) {
			if (!npiv_vp->vp_idx)
				continue;

			if (memcmp(npiv_vp->port_name, b, 8) ||
			    memcmp(npiv_vp->node_name, b2, 8))
				continue;

#warning FIXME: Need to add atomic_inc(&npiv_vp->vref_count) before dropping ha->vport_slock..?
			spin_unlock_irqrestore(&ha->vport_slock, flags);

			printk("qla2xxx_npiv: Found matching NPIV WWPN+WWNN: %s "
					" for lport\n", name);
			tcm_qla2xxx_init_lport(lport, vha, npiv_vp);
			/*
			 * Setup fc_vport_identifiers for NPIV containing
			 * the passed WWPN and WWNN for the new libfc vport.
			 */
			memset(&vid, 0, sizeof(vid));
			vid.roles = FC_PORT_ROLE_FCP_INITIATOR;
			vid.vport_type = FC_PORTTYPE_NPIV;
			vid.port_name = npiv_wwpn;
			vid.node_name = npiv_wwnn;
			/* vid.symbolic_name is already zero/NULL's */
			vid.disable = false;	/* always enabled */

			/* we only allow support on Channel 0 !!! */
			vport = fc_vport_create(host, 0, &vid);
			if (!vport) {
				printk(KERN_ERR "fc_vport_create() failed for"
						" NPIV tcm_qla2xxx\n");
				scsi_host_put(host);
				ret = -EINVAL;
				goto out;
			}
			lport->npiv_vport = vport;
			ret = 0;
			spin_lock_irqsave(&ha->vport_slock, flags);
			break;
		}
		spin_unlock_irqrestore(&ha->vport_slock, flags);

		if (!ret)
			break;

		scsi_host_put(host);
	}

	if (ret != 0)
		goto out;

	return &lport->lport_wwn;
out:
	kfree(lport);
	return ERR_PTR(ret);
}

static void tcm_qla2xxx_npiv_drop_lport(struct se_wwn *wwn)
{
	struct tcm_qla2xxx_lport *lport = container_of(wwn,
			struct tcm_qla2xxx_lport, lport_wwn);
	struct scsi_qla_host *vha = lport->qla_vha;
	struct Scsi_Host *sh = vha->host;
	/*
	 * Notify libfc that we want to release the lport->npiv_vport
	 */
	fc_vport_terminate(lport->npiv_vport);

	scsi_host_put(sh);
	kfree(lport);
}


static ssize_t tcm_qla2xxx_wwn_show_attr_version(
	struct target_fabric_configfs *tf,
	char *page)
{
	return sprintf(page, "TCM QLOGIC QLA2XXX NPIV capable fabric module %s on %s/%s"
		" on "UTS_RELEASE"\n", TCM_QLA2XXX_VERSION, utsname()->sysname,
		utsname()->machine);
}

TF_WWN_ATTR_RO(tcm_qla2xxx, version);

static struct configfs_attribute *tcm_qla2xxx_wwn_attrs[] = {
	&tcm_qla2xxx_wwn_version.attr,
	NULL,
};

static struct target_core_fabric_ops tcm_qla2xxx_ops = {
	.get_fabric_name		= tcm_qla2xxx_get_fabric_name,
	.get_fabric_proto_ident		= tcm_qla2xxx_get_fabric_proto_ident,
	.tpg_get_wwn			= tcm_qla2xxx_get_fabric_wwn,
	.tpg_get_tag			= tcm_qla2xxx_get_tag,
	.tpg_get_default_depth		= tcm_qla2xxx_get_default_depth,
	.tpg_get_pr_transport_id	= tcm_qla2xxx_get_pr_transport_id,
	.tpg_get_pr_transport_id_len	= tcm_qla2xxx_get_pr_transport_id_len,
	.tpg_parse_pr_out_transport_id	= tcm_qla2xxx_parse_pr_out_transport_id,
	.tpg_check_demo_mode		= tcm_qla2xxx_check_false,
	.tpg_check_demo_mode_cache	= tcm_qla2xxx_check_true,
	.tpg_check_demo_mode_write_protect = tcm_qla2xxx_check_true,
	.tpg_check_prod_mode_write_protect = tcm_qla2xxx_check_false,
	.tpg_alloc_fabric_acl		= tcm_qla2xxx_alloc_fabric_acl,
	.tpg_release_fabric_acl		= tcm_qla2xxx_release_fabric_acl,
	.tpg_get_inst_index		= tcm_qla2xxx_tpg_get_inst_index,
	.release_cmd_to_pool		= tcm_qla2xxx_release_cmd,
	.release_cmd_direct		= tcm_qla2xxx_release_cmd,
	.shutdown_session		= tcm_qla2xxx_shutdown_session,
	.close_session			= tcm_qla2xxx_close_session,
	.stop_session			= tcm_qla2xxx_stop_session,
	.fall_back_to_erl0		= tcm_qla2xxx_reset_nexus,
	.sess_logged_in			= tcm_qla2xxx_sess_logged_in,
	.sess_get_index			= tcm_qla2xxx_sess_get_index,
	.sess_get_initiator_sid		= NULL,
	.write_pending			= tcm_qla2xxx_write_pending,
	.write_pending_status		= tcm_qla2xxx_write_pending_status,
	.set_default_node_attributes	= tcm_qla2xxx_set_default_node_attrs,
	.get_task_tag			= tcm_qla2xxx_get_task_tag,
	.get_cmd_state			= tcm_qla2xxx_get_cmd_state,
	.new_cmd_failure		= tcm_qla2xxx_new_cmd_failure,
	.queue_data_in			= tcm_qla2xxx_queue_data_in,
	.queue_status			= tcm_qla2xxx_queue_status,
	.queue_tm_rsp			= tcm_qla2xxx_queue_tm_rsp,
	.get_fabric_sense_len		= tcm_qla2xxx_get_fabric_sense_len,
	.set_fabric_sense_len		= tcm_qla2xxx_set_fabric_sense_len,
	.is_state_remove		= tcm_qla2xxx_is_state_remove,
	.pack_lun			= tcm_qla2xxx_pack_lun,
	/*
	 * Setup function pointers for generic logic in target_core_fabric_configfs.c
	 */
	.fabric_make_wwn		= tcm_qla2xxx_make_lport,
	.fabric_drop_wwn		= tcm_qla2xxx_drop_lport,
	.fabric_make_tpg		= tcm_qla2xxx_make_tpg,
	.fabric_drop_tpg		= tcm_qla2xxx_drop_tpg,
	.fabric_post_link		= NULL,
	.fabric_pre_unlink		= NULL,
	.fabric_make_np			= NULL,
	.fabric_drop_np			= NULL,
	.fabric_make_nodeacl		= tcm_qla2xxx_make_nodeacl,
	.fabric_drop_nodeacl		= tcm_qla2xxx_drop_nodeacl,
};

static struct target_core_fabric_ops tcm_qla2xxx_npiv_ops = {
	.get_fabric_name		= tcm_qla2xxx_npiv_get_fabric_name,
	.get_fabric_proto_ident		= tcm_qla2xxx_get_fabric_proto_ident,
	.tpg_get_wwn			= tcm_qla2xxx_npiv_get_fabric_wwn,
	.tpg_get_tag			= tcm_qla2xxx_get_tag,
	.tpg_get_default_depth		= tcm_qla2xxx_get_default_depth,
	.tpg_get_pr_transport_id	= tcm_qla2xxx_get_pr_transport_id,
	.tpg_get_pr_transport_id_len	= tcm_qla2xxx_get_pr_transport_id_len,
	.tpg_parse_pr_out_transport_id	= tcm_qla2xxx_parse_pr_out_transport_id,
	.tpg_check_demo_mode		= tcm_qla2xxx_check_false,
	.tpg_check_demo_mode_cache	= tcm_qla2xxx_check_true,
	.tpg_check_demo_mode_write_protect = tcm_qla2xxx_check_true,
	.tpg_check_prod_mode_write_protect = tcm_qla2xxx_check_false,
	.tpg_alloc_fabric_acl		= tcm_qla2xxx_alloc_fabric_acl,
	.tpg_release_fabric_acl		= tcm_qla2xxx_release_fabric_acl,
	.tpg_get_inst_index		= tcm_qla2xxx_tpg_get_inst_index,
	.release_cmd_to_pool		= tcm_qla2xxx_release_cmd,
	.release_cmd_direct		= tcm_qla2xxx_release_cmd,
	.shutdown_session		= tcm_qla2xxx_shutdown_session,
	.close_session			= tcm_qla2xxx_close_session,
	.stop_session			= tcm_qla2xxx_stop_session,
	.fall_back_to_erl0		= tcm_qla2xxx_reset_nexus,
	.sess_logged_in			= tcm_qla2xxx_sess_logged_in,
	.sess_get_index			= tcm_qla2xxx_sess_get_index,
	.sess_get_initiator_sid		= NULL,
	.write_pending			= tcm_qla2xxx_write_pending,
	.write_pending_status		= tcm_qla2xxx_write_pending_status,
	.set_default_node_attributes	= tcm_qla2xxx_set_default_node_attrs,
	.get_task_tag			= tcm_qla2xxx_get_task_tag,
	.get_cmd_state			= tcm_qla2xxx_get_cmd_state,
	.new_cmd_failure		= tcm_qla2xxx_new_cmd_failure,
	.queue_data_in			= tcm_qla2xxx_queue_data_in,
	.queue_status			= tcm_qla2xxx_queue_status,
	.queue_tm_rsp			= tcm_qla2xxx_queue_tm_rsp,
	.get_fabric_sense_len		= tcm_qla2xxx_get_fabric_sense_len,
	.set_fabric_sense_len		= tcm_qla2xxx_set_fabric_sense_len,
	.is_state_remove		= tcm_qla2xxx_is_state_remove,
	.pack_lun			= tcm_qla2xxx_pack_lun,
	/*
	 * Setup function pointers for generic logic in target_core_fabric_configfs.c
	 */
	.fabric_make_wwn		= tcm_qla2xxx_npiv_make_lport,
	.fabric_drop_wwn		= tcm_qla2xxx_npiv_drop_lport,
	.fabric_make_tpg		= tcm_qla2xxx_npiv_make_tpg,
	.fabric_drop_tpg		= tcm_qla2xxx_drop_tpg,
	.fabric_post_link		= NULL,
	.fabric_pre_unlink		= NULL,
	.fabric_make_np			= NULL,
	.fabric_drop_np			= NULL,
	.fabric_make_nodeacl		= tcm_qla2xxx_make_nodeacl,
	.fabric_drop_nodeacl		= tcm_qla2xxx_drop_nodeacl,
};

static int tcm_qla2xxx_register_configfs(void)
{
	struct target_fabric_configfs *fabric, *npiv_fabric;
	int ret;

	printk(KERN_INFO "TCM QLOGIC QLA2XXX fabric module %s on %s/%s"
		" on "UTS_RELEASE"\n", TCM_QLA2XXX_VERSION, utsname()->sysname,
		utsname()->machine);
	/*
	 * Register the top level struct config_item_type with TCM core
	 */
	fabric = target_fabric_configfs_init(THIS_MODULE, "qla2xxx");
	if (!(fabric)) {
		printk(KERN_ERR "target_fabric_configfs_init() failed\n");
		return -ENOMEM;
	}
	/*
	 * Setup fabric->tf_ops from our local tcm_qla2xxx_ops
	 */
	fabric->tf_ops = tcm_qla2xxx_ops;
	/*
	 * Setup default attribute lists for various fabric->tf_cit_tmpl
	 */
	TF_CIT_TMPL(fabric)->tfc_wwn_cit.ct_attrs = tcm_qla2xxx_wwn_attrs;
	TF_CIT_TMPL(fabric)->tfc_tpg_base_cit.ct_attrs = NULL;
	TF_CIT_TMPL(fabric)->tfc_tpg_attrib_cit.ct_attrs = NULL;
	TF_CIT_TMPL(fabric)->tfc_tpg_param_cit.ct_attrs = NULL;
	TF_CIT_TMPL(fabric)->tfc_tpg_np_base_cit.ct_attrs = NULL;
	TF_CIT_TMPL(fabric)->tfc_tpg_nacl_base_cit.ct_attrs = NULL;
	TF_CIT_TMPL(fabric)->tfc_tpg_nacl_attrib_cit.ct_attrs = NULL;
	TF_CIT_TMPL(fabric)->tfc_tpg_nacl_auth_cit.ct_attrs = NULL;
	TF_CIT_TMPL(fabric)->tfc_tpg_nacl_param_cit.ct_attrs = NULL;
	/*
	 * Register the fabric for use within TCM
	 */
	ret = target_fabric_configfs_register(fabric);
	if (ret < 0) {
		printk(KERN_ERR "target_fabric_configfs_register() failed"
				" for TCM_QLA2XXX\n");
		return ret;
	}
	/*
	 * Setup our local pointer to *fabric
	 */
	tcm_qla2xxx_fabric_configfs = fabric;	
	printk(KERN_INFO "TCM_QLA2XXX[0] - Set fabric -> tcm_qla2xxx_fabric_configfs\n");

	/*
	 * Register the top level struct config_item_type for NPIV with TCM core
	 */
	npiv_fabric = target_fabric_configfs_init(THIS_MODULE, "qla2xxx_npiv");
	if (!(npiv_fabric)) {
		printk(KERN_ERR "target_fabric_configfs_init() failed\n");
		ret = -ENOMEM;
		goto out;
	}
	/*
	 * Setup fabric->tf_ops from our local tcm_qla2xxx_npiv_ops
	 */
	npiv_fabric->tf_ops = tcm_qla2xxx_npiv_ops;
	/*
	 * Setup default attribute lists for various npiv_fabric->tf_cit_tmpl
	 */
	TF_CIT_TMPL(npiv_fabric)->tfc_wwn_cit.ct_attrs = tcm_qla2xxx_wwn_attrs;
	TF_CIT_TMPL(npiv_fabric)->tfc_tpg_base_cit.ct_attrs = NULL;
	TF_CIT_TMPL(npiv_fabric)->tfc_tpg_attrib_cit.ct_attrs = NULL;
	TF_CIT_TMPL(npiv_fabric)->tfc_tpg_param_cit.ct_attrs = NULL;
	TF_CIT_TMPL(npiv_fabric)->tfc_tpg_np_base_cit.ct_attrs = NULL;
	TF_CIT_TMPL(npiv_fabric)->tfc_tpg_nacl_base_cit.ct_attrs = NULL;
	TF_CIT_TMPL(npiv_fabric)->tfc_tpg_nacl_attrib_cit.ct_attrs = NULL;
	TF_CIT_TMPL(npiv_fabric)->tfc_tpg_nacl_auth_cit.ct_attrs = NULL;
	TF_CIT_TMPL(npiv_fabric)->tfc_tpg_nacl_param_cit.ct_attrs = NULL;
	/*
	 * Register the npiv_fabric for use within TCM
	 */
	ret = target_fabric_configfs_register(npiv_fabric);
	if (ret < 0) {
		printk(KERN_ERR "target_fabric_configfs_register() failed"
				" for TCM_QLA2XXX\n");
		goto out;;
	}
	/*
	 * Setup our local pointer to *npiv_fabric
	 */
	tcm_qla2xxx_npiv_fabric_configfs = npiv_fabric;
	printk(KERN_INFO "TCM_QLA2XXX[0] - Set fabric -> tcm_qla2xxx_npiv_fabric_configfs\n");

	return 0;
out:
	if (tcm_qla2xxx_fabric_configfs != NULL)
		target_fabric_configfs_deregister(tcm_qla2xxx_fabric_configfs);

	return ret;
}

static void tcm_qla2xxx_deregister_configfs(void)
{
	if (!(tcm_qla2xxx_fabric_configfs))
		return;

	target_fabric_configfs_deregister(tcm_qla2xxx_fabric_configfs);
	tcm_qla2xxx_fabric_configfs = NULL;
	printk(KERN_INFO "TCM_QLA2XXX[0] - Cleared tcm_qla2xxx_fabric_configfs\n");

	target_fabric_configfs_deregister(tcm_qla2xxx_npiv_fabric_configfs);
	tcm_qla2xxx_npiv_fabric_configfs = NULL;
	printk(KERN_INFO "TCM_QLA2XXX[0] - Cleared tcm_qla2xxx_npiv_fabric_configfs\n");
}

static int __init tcm_qla2xxx_init(void)
{
	int ret;

	ret = tcm_qla2xxx_register_configfs();
	if (ret < 0)
		return ret;

	return 0;
}

static void __exit tcm_qla2xxx_exit(void)
{
	tcm_qla2xxx_deregister_configfs();
}

#ifdef MODULE
MODULE_DESCRIPTION("TCM QLA2XXX series NPIV enabled fabric driver");
MODULE_LICENSE("GPL");
module_init(tcm_qla2xxx_init);
module_exit(tcm_qla2xxx_exit);
#endif
