/*******************************************************************************
 * This file contains TCM QLA2XXX fabric module implementation using
 * v4 configfs fabric infrastructure for QLogic target mode HBAs
 *
 * © Copyright 2010-2011 RisingTide Systems LLC.
 *
 * Licensed to the Linux Foundation under the General Public License (GPL) version 2.
 *
 * Author: Nicholas A. Bellinger <nab@risingtidesystems.com>
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

#include <linux/module.h>
#include <linux/moduleparam.h>
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

#include "tcm_qla2xxx_base.h"
#include "tcm_qla2xxx_fabric.h"

#include <qla_def.h>

/* Local pointer to allocated TCM configfs fabric module */
struct target_fabric_configfs *tcm_qla2xxx_fabric_configfs;
struct target_fabric_configfs *tcm_qla2xxx_npiv_fabric_configfs;

static int tcm_qla2xxx_setup_nacl_from_rport(
	struct se_portal_group *se_tpg,
	struct se_node_acl *se_nacl,
	struct tcm_qla2xxx_lport *lport,
	struct tcm_qla2xxx_nacl *nacl,
	u64 rport_wwnn)
{
	struct scsi_qla_host *vha = lport->qla_vha;
	struct Scsi_Host *sh = vha->host;
	struct fc_host_attrs *fc_host = shost_to_fc_host(sh);
	struct fc_rport *rport;
	struct tcm_qla2xxx_fc_domain *d;
	struct tcm_qla2xxx_fc_area *a;
	struct tcm_qla2xxx_fc_al_pa *p;
	unsigned long flags;
	unsigned char domain, area, al_pa;
	/*
	 * Scan the existing rports, and create a session for the
	 * explict NodeACL is an matching rport->node_name already
	 * exists.
	 */
	spin_lock_irqsave(sh->host_lock, flags);
	list_for_each_entry(rport, &fc_host->rports, peers) {
		if (rport_wwnn != rport->node_name)
			continue;

		pr_debug("Located existing rport_wwpn and rport->node_name:"
			" 0x%016LX, port_id: 0x%04x\n", rport->node_name,
			rport->port_id);
		domain = (rport->port_id >> 16) & 0xff;
		area = (rport->port_id >> 8) & 0xff;
		al_pa = rport->port_id & 0xff;
		nacl->nport_id = rport->port_id;

		pr_debug("fc_rport domain: 0x%02x area: 0x%02x al_pa: %02x\n",
				domain, area, al_pa);
		spin_unlock_irqrestore(sh->host_lock, flags);


		spin_lock_irqsave(&vha->hw->hardware_lock, flags);
		d = &((struct tcm_qla2xxx_fc_domain *)lport->lport_fcport_map)[domain];
		pr_debug("Using d: %p for domain: 0x%02x\n", d, domain);
		a = &d->areas[area];
		pr_debug("Using a: %p for area: 0x%02x\n", a, area);
		p = &a->al_pas[al_pa];
		pr_debug("Using p: %p for al_pa: 0x%02x\n", p, al_pa);

		p->se_nacl = se_nacl;
		pr_debug("Setting p->se_nacl to se_nacl: %p for WWNN: 0x%016LX,"
			" port_id: 0x%04x\n", se_nacl, rport_wwnn,
			nacl->nport_id);
		spin_unlock_irqrestore(&vha->hw->hardware_lock, flags);

		return 1;
	}
	spin_unlock_irqrestore(sh->host_lock, flags);

	return 0;
}

/*
 * Expected to be called with struct qla_hw_data->hardware_lock held
 */
int tcm_qla2xxx_clear_nacl_from_fcport_map(
	struct se_node_acl *se_nacl)
{
	struct se_portal_group *se_tpg = se_nacl->se_tpg;
	struct se_wwn *se_wwn = se_tpg->se_tpg_wwn;
	struct tcm_qla2xxx_lport *lport = container_of(se_wwn,
				struct tcm_qla2xxx_lport, lport_wwn);
	struct tcm_qla2xxx_nacl *nacl = container_of(se_nacl,
				struct tcm_qla2xxx_nacl, se_node_acl);
	struct tcm_qla2xxx_fc_domain *d;
	struct tcm_qla2xxx_fc_area *a;
	struct tcm_qla2xxx_fc_al_pa *p;
	unsigned char domain, area, al_pa;

	domain = (nacl->nport_id >> 16) & 0xff;
	area = (nacl->nport_id >> 8) & 0xff;
	al_pa = nacl->nport_id & 0xff;

	pr_debug("fc_rport domain: 0x%02x area: 0x%02x al_pa: %02x\n",
			domain, area, al_pa);

	d = &((struct tcm_qla2xxx_fc_domain *)lport->lport_fcport_map)[domain];
	pr_debug("Using d: %p for domain: 0x%02x\n", d, domain);
	a = &d->areas[area];
	pr_debug("Using a: %p for area: 0x%02x\n", a, area);
	p = &a->al_pas[al_pa];
	pr_debug("Using p: %p for al_pa: 0x%02x\n", p, al_pa);

	p->se_nacl = NULL;
	pr_debug("Clearing p->se_nacl to se_nacl: %p for WWNN: 0x%016LX,"
		" port_id: 0x%04x\n", se_nacl, nacl->nport_wwnn,
		nacl->nport_id);

	return 0;
}

static struct se_node_acl *tcm_qla2xxx_make_nodeacl(
	struct se_portal_group *se_tpg,
	struct config_group *group,
	const char *name)
{
	struct se_wwn *se_wwn = se_tpg->se_tpg_wwn;
	struct tcm_qla2xxx_lport *lport = container_of(se_wwn,
				struct tcm_qla2xxx_lport, lport_wwn);
	struct se_node_acl *se_nacl, *se_nacl_new;
	struct tcm_qla2xxx_nacl *nacl;
	u64 wwnn;
	u32 qla2xxx_nexus_depth;
	int rc;

	if (tcm_qla2xxx_parse_wwn(name, &wwnn, 1) < 0)
		return ERR_PTR(-EINVAL);

	se_nacl_new = tcm_qla2xxx_alloc_fabric_acl(se_tpg);
	if (!se_nacl_new)
		return ERR_PTR(-ENOMEM);
//#warning FIXME: Hardcoded qla2xxx_nexus depth in tcm_qla2xxx_make_nodeacl()
	qla2xxx_nexus_depth = 1;

	/*
	 * se_nacl_new may be released by core_tpg_add_initiator_node_acl()
	 * when converting a NodeACL from demo mode -> explict
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
	nacl->nport_wwnn = wwnn;
	tcm_qla2xxx_format_wwn(&nacl->nport_name[0], TCM_QLA2XXX_NAMELEN, wwnn);
	/*
	 * Setup a se_nacl handle based on an a matching struct fc_rport setup
	 * via drivers/scsi/qla2xxx/qla_init.c:qla2x00_reg_remote_port()
	 */
	rc = tcm_qla2xxx_setup_nacl_from_rport(se_tpg, se_nacl, lport,
					nacl, wwnn);
	if (rc < 0) {
		tcm_qla2xxx_release_fabric_acl(se_tpg, se_nacl_new);
		return ERR_PTR(rc);
	}

	return se_nacl;;
}

static void tcm_qla2xxx_drop_nodeacl(struct se_node_acl *se_acl)
{
	struct se_portal_group *se_tpg = se_acl->se_tpg;
	struct tcm_qla2xxx_nacl *nacl = container_of(se_acl,
				struct tcm_qla2xxx_nacl, se_node_acl);	

	core_tpg_del_initiator_node_acl(se_tpg, se_acl, 1);
	kfree(nacl);
}

/* Start items for tcm_qla2xxx_tpg_attrib_cit */

#define DEF_QLA_TPG_ATTRIB(name)					\
									\
static ssize_t tcm_qla2xxx_tpg_attrib_show_##name(			\
	struct se_portal_group *se_tpg,					\
	char *page)							\
{									\
	struct tcm_qla2xxx_tpg *tpg = container_of(se_tpg,		\
			struct tcm_qla2xxx_tpg, se_tpg);		\
									\
	return sprintf(page, "%u\n", QLA_TPG_ATTRIB(tpg)->name);	\
}									\
									\
static ssize_t tcm_qla2xxx_tpg_attrib_store_##name(			\
	struct se_portal_group *se_tpg,					\
	const char *page,						\
	size_t count)							\
{									\
	struct tcm_qla2xxx_tpg *tpg = container_of(se_tpg,		\
			struct tcm_qla2xxx_tpg, se_tpg);		\
	unsigned long val;						\
	int ret;							\
									\
	ret = strict_strtoul(page, 0, &val);				\
	if (ret < 0) {							\
		pr_err("strict_strtoul() failed with"		\
				" ret: %d\n", ret);			\
		return -EINVAL;						\
	}								\
	ret = tcm_qla2xxx_set_attrib_##name(tpg, val);			\
									\
	return (!ret) ? count : -EINVAL;				\
}

#define DEF_QLA_TPG_ATTR_BOOL(_name)					\
									\
static int tcm_qla2xxx_set_attrib_##_name(				\
	struct tcm_qla2xxx_tpg *tpg,					\
	unsigned long val)						\
{									\
	struct tcm_qla2xxx_tpg_attrib *a = &tpg->tpg_attrib;		\
									\
	if ((val != 0) && (val != 1)) {					\
		pr_err("Illegal boolean value %lu\n", val);	\
                return -EINVAL;						\
	}								\
									\
	a->_name = val;							\
	return 0;							\
}

#define QLA_TPG_ATTR(_name, _mode)	TF_TPG_ATTRIB_ATTR(tcm_qla2xxx, _name, _mode);

/*
 * Define tcm_qla2xxx_tpg_attrib_s_generate_node_acls
 */
DEF_QLA_TPG_ATTR_BOOL(generate_node_acls);
DEF_QLA_TPG_ATTRIB(generate_node_acls);
QLA_TPG_ATTR(generate_node_acls, S_IRUGO | S_IWUSR);

/*
 Define tcm_qla2xxx_attrib_s_cache_dynamic_acls
 */
DEF_QLA_TPG_ATTR_BOOL(cache_dynamic_acls);
DEF_QLA_TPG_ATTRIB(cache_dynamic_acls);
QLA_TPG_ATTR(cache_dynamic_acls, S_IRUGO | S_IWUSR);

/*
 * Define tcm_qla2xxx_tpg_attrib_s_demo_mode_write_protect
 */
DEF_QLA_TPG_ATTR_BOOL(demo_mode_write_protect);
DEF_QLA_TPG_ATTRIB(demo_mode_write_protect);
QLA_TPG_ATTR(demo_mode_write_protect, S_IRUGO | S_IWUSR);

/*
 * Define tcm_qla2xxx_tpg_attrib_s_prod_mode_write_protect
 */
DEF_QLA_TPG_ATTR_BOOL(prod_mode_write_protect);
DEF_QLA_TPG_ATTRIB(prod_mode_write_protect);
QLA_TPG_ATTR(prod_mode_write_protect, S_IRUGO | S_IWUSR);

static struct configfs_attribute *tcm_qla2xxx_tpg_attrib_attrs[] = {
	&tcm_qla2xxx_tpg_attrib_generate_node_acls.attr,
	&tcm_qla2xxx_tpg_attrib_cache_dynamic_acls.attr,
	&tcm_qla2xxx_tpg_attrib_demo_mode_write_protect.attr,
	&tcm_qla2xxx_tpg_attrib_prod_mode_write_protect.attr,
	NULL,
};

/* End items for tcm_qla2xxx_tpg_attrib_cit */

static ssize_t tcm_qla2xxx_tpg_show_enable(
	struct se_portal_group *se_tpg,
	char *page)
{
	struct tcm_qla2xxx_tpg *tpg = container_of(se_tpg,
			struct tcm_qla2xxx_tpg, se_tpg);

	return snprintf(page, PAGE_SIZE, "%d\n",
			atomic_read(&tpg->lport_tpg_enabled));
}

static ssize_t tcm_qla2xxx_tpg_store_enable(
	struct se_portal_group *se_tpg,
	const char *page,
	size_t count)
{
	struct se_wwn *se_wwn = se_tpg->se_tpg_wwn;
	struct tcm_qla2xxx_lport *lport = container_of(se_wwn,
			struct tcm_qla2xxx_lport, lport_wwn);
	struct scsi_qla_host *vha = lport->qla_vha;
	struct qla_hw_data *ha = vha->hw;
	struct tcm_qla2xxx_tpg *tpg = container_of(se_tpg,
			struct tcm_qla2xxx_tpg, se_tpg);
	char *endptr;
	u32 op;

	op = simple_strtoul(page, &endptr, 0);
	if ((op != 1) && (op != 0)) {
		pr_err("Illegal value for tpg_enable: %u\n", op);
		return -EINVAL;
	}

	if (op) {
		atomic_set(&tpg->lport_tpg_enabled, 1);
		qla_tgt_enable_vha(vha);
	} else {
		if (!ha->qla_tgt) {
			pr_err("truct qla_hw_data *ha->qla_tgt is NULL\n");
			return -ENODEV;
		}
		atomic_set(&tpg->lport_tpg_enabled, 0);
		qla_tgt_stop_phase1(ha->qla_tgt);
	}

	return count;
}

TF_TPG_BASE_ATTR(tcm_qla2xxx, enable, S_IRUGO | S_IWUSR);

static struct configfs_attribute *tcm_qla2xxx_tpg_attrs[] = {
	&tcm_qla2xxx_tpg_enable.attr,
	NULL,
};

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
	
	if (!lport->qla_npiv_vp && (tpgt != 1)) {
		pr_err("In non NPIV mode, a single TPG=1 is used for"
			" HW port mappings\n");
		return ERR_PTR(-ENOSYS);
	}

	tpg = kzalloc(sizeof(struct tcm_qla2xxx_tpg), GFP_KERNEL);
	if (!tpg) {
		pr_err("Unable to allocate struct tcm_qla2xxx_tpg\n");
		return ERR_PTR(-ENOMEM);
	}
	tpg->lport = lport;
	tpg->lport_tpgt = tpgt;
	/*
	 * By default allow READ-ONLY TPG demo-mode access w/ cached dynamic NodeACLs
	 */
	QLA_TPG_ATTRIB(tpg)->generate_node_acls = 1;
	QLA_TPG_ATTRIB(tpg)->demo_mode_write_protect = 1;
	QLA_TPG_ATTRIB(tpg)->cache_dynamic_acls = 1;

	ret = core_tpg_register(&tcm_qla2xxx_fabric_configfs->tf_ops, wwn,
				&tpg->se_tpg, (void *)tpg,
				TRANSPORT_TPG_TYPE_NORMAL);
	if (ret < 0) {
		kfree(tpg);
		return NULL;
	}
	/*
	 * Setup local TPG=1 pointer for non NPIV mode.
	 */
	if (lport->qla_npiv_vp == NULL)
		lport->tpg_1 = tpg;

	return &tpg->se_tpg;
}

static void tcm_qla2xxx_drop_tpg(struct se_portal_group *se_tpg)
{
	struct tcm_qla2xxx_tpg *tpg = container_of(se_tpg,
			struct tcm_qla2xxx_tpg, se_tpg);
	struct tcm_qla2xxx_lport *lport = tpg->lport;
	struct scsi_qla_host *vha = lport->qla_vha;
	struct qla_hw_data *ha = vha->hw;
	/*
	 * Call into qla2x_target.c LLD logic to shutdown the active
	 * FC Nexuses and disable target mode operation for this qla_hw_data
	 */
	if (ha->qla_tgt && !ha->qla_tgt->tgt_stop)
		qla_tgt_stop_phase1(ha->qla_tgt);

	core_tpg_deregister(se_tpg);
	/*
	 * Clear local TPG=1 pointer for non NPIV mode.
	 */
	if (lport->qla_npiv_vp == NULL)
		lport->tpg_1 = NULL;

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
	if (!tpg) {
		pr_err("Unable to allocate struct tcm_qla2xxx_tpg\n");
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

/*
 * Expected to be called with struct qla_hw_data->hardware_lock held
 */
static struct qla_tgt_sess *tcm_qla2xxx_find_sess_by_s_id(
	scsi_qla_host_t *vha,
	const uint8_t *s_id)
{
	struct qla_hw_data *ha = vha->hw;
	struct tcm_qla2xxx_lport *lport;
	struct se_node_acl *se_nacl;
	struct tcm_qla2xxx_nacl *nacl;
	struct tcm_qla2xxx_fc_domain *d;
	struct tcm_qla2xxx_fc_area *a;
	struct tcm_qla2xxx_fc_al_pa *p;
	unsigned char domain, area, al_pa;

	lport = (struct tcm_qla2xxx_lport *)ha->target_lport_ptr;
	if (!lport) {
		pr_err("Unable to locate struct tcm_qla2xxx_lport\n");
		dump_stack();
		return NULL;
	}

	domain = s_id[0];
	area = s_id[1];
	al_pa = s_id[2];

	pr_debug("find_sess_by_s_id: 0x%02x area: 0x%02x al_pa: %02x\n",
			domain, area, al_pa);

	d = &((struct tcm_qla2xxx_fc_domain *)lport->lport_fcport_map)[domain];
	pr_debug("Using d: %p for domain: 0x%02x\n", d, domain);
	a = &d->areas[area];
	pr_debug("Using a: %p for area: 0x%02x\n", a, area);
	p = &a->al_pas[al_pa];
	pr_debug("Using p: %p for al_pa: 0x%02x\n", p, al_pa);

	se_nacl = p->se_nacl;
	if (!se_nacl) {
		pr_debug("Unable to locate s_id: 0x%02x area: 0x%02x"
			" al_pa: %02x\n", domain, area, al_pa);
		return NULL;
	}
	pr_debug("find_sess_by_s_id: located se_nacl: %p,"
		" initiatorname: %s\n", se_nacl, se_nacl->initiatorname);

	nacl = container_of(se_nacl, struct tcm_qla2xxx_nacl, se_node_acl);
	if (!nacl->qla_tgt_sess) {
		pr_err("Unable to locate struct qla_tgt_sess\n");
		return NULL;
	}

	return nacl->qla_tgt_sess;
}

/*
 * Expected to be called with struct qla_hw_data->hardware_lock held
 */
static void tcm_qla2xxx_set_sess_by_s_id(
	struct tcm_qla2xxx_lport *lport,
	struct se_node_acl *new_se_nacl,
	struct tcm_qla2xxx_nacl *nacl,
	struct se_session *se_sess,
	struct qla_tgt_sess *qla_tgt_sess,
	uint8_t *s_id)
{
	struct se_node_acl *saved_nacl;
	struct tcm_qla2xxx_fc_domain *d;
	struct tcm_qla2xxx_fc_area *a;
	struct tcm_qla2xxx_fc_al_pa *p;
	unsigned char domain, area, al_pa;

	domain = s_id[0];
	area = s_id[1];
	al_pa = s_id[2];
	pr_debug("set_sess_by_s_id: domain 0x%02x area: 0x%02x al_pa: %02x\n",
			domain, area, al_pa);

	d = &((struct tcm_qla2xxx_fc_domain *)lport->lport_fcport_map)[domain];
	pr_debug("Using d: %p for domain: 0x%02x\n", d, domain);
	a = &d->areas[area];
	pr_debug("Using a: %p for area: 0x%02x\n", a, area);
	p = &a->al_pas[al_pa];
	pr_debug("Using p: %p for al_pa: 0x%02x\n", p, al_pa);

	saved_nacl = p->se_nacl;
	if (!saved_nacl) {
		pr_debug("Setting up new p->se_nacl to new_se_nacl\n");
		p->se_nacl = new_se_nacl;
		qla_tgt_sess->se_sess = se_sess;
		nacl->qla_tgt_sess = qla_tgt_sess;
		return;
	}

	if (nacl->qla_tgt_sess) {
		if (new_se_nacl == NULL) {
			pr_debug("Clearing existing nacl->qla_tgt_sess"
					" and p->se_nacl\n");
			p->se_nacl = NULL;
			nacl->qla_tgt_sess = NULL;
			return;
		}
		pr_debug("Replacing existing nacl->qla_tgt_sess and"
				" p->se_nacl\n");
		p->se_nacl = new_se_nacl;
		qla_tgt_sess->se_sess = se_sess;
		nacl->qla_tgt_sess = qla_tgt_sess;
		return;
	}

	if (new_se_nacl == NULL) {
		pr_debug("Clearing existing p->se_nacl\n");
		p->se_nacl = NULL;
		return;
	}

	pr_debug("Replacing existing p->se_nacl w/o active"
				" nacl->qla_tgt_sess\n");
	p->se_nacl = new_se_nacl;
	qla_tgt_sess->se_sess = se_sess;
	nacl->qla_tgt_sess = qla_tgt_sess;

	pr_debug("Setup nacl->qla_tgt_sess %p by s_id for se_nacl: %p,"
		" initiatorname: %s\n", nacl->qla_tgt_sess, new_se_nacl,
		new_se_nacl->initiatorname);
}

/*
 * Expected to be called with struct qla_hw_data->hardware_lock held
 */
static struct qla_tgt_sess *tcm_qla2xxx_find_sess_by_loop_id(
	scsi_qla_host_t *vha,
	const uint16_t loop_id)
{
	struct qla_hw_data *ha = vha->hw;
	struct tcm_qla2xxx_lport *lport;
	struct se_node_acl *se_nacl;
	struct tcm_qla2xxx_nacl *nacl;
	struct tcm_qla2xxx_fc_loopid *fc_loopid;

	lport = (struct tcm_qla2xxx_lport *)ha->target_lport_ptr;
	if (!lport) {
		pr_err("Unable to locate struct tcm_qla2xxx_lport\n");
		dump_stack();
		return NULL;
	}

	pr_debug("find_sess_by_loop_id: Using loop_id: 0x%04x\n", loop_id);

	fc_loopid = &((struct tcm_qla2xxx_fc_loopid *)lport->lport_loopid_map)[loop_id];

	se_nacl = fc_loopid->se_nacl;
	if (!se_nacl) {
		pr_debug("Unable to locate se_nacl by loop_id:"
				" 0x%04x\n", loop_id);
		return NULL;
	}

	nacl = container_of(se_nacl, struct tcm_qla2xxx_nacl, se_node_acl);

	if (!nacl->qla_tgt_sess) {
		pr_err("Unable to locate struct qla_tgt_sess\n");
		return NULL;
	}

	return nacl->qla_tgt_sess;
}

/*
 * Expected to be called with struct qla_hw_data->hardware_lock held
 */
static void tcm_qla2xxx_set_sess_by_loop_id(
	struct tcm_qla2xxx_lport *lport,
	struct se_node_acl *new_se_nacl,
	struct tcm_qla2xxx_nacl *nacl,
	struct se_session *se_sess,
	struct qla_tgt_sess *qla_tgt_sess,
	uint16_t loop_id)
{
	struct se_node_acl *saved_nacl;
	struct tcm_qla2xxx_fc_loopid *fc_loopid;

	pr_debug("set_sess_by_loop_id: Using loop_id: 0x%04x\n", loop_id);

	fc_loopid = &((struct tcm_qla2xxx_fc_loopid *)lport->lport_loopid_map)[loop_id];

	saved_nacl = fc_loopid->se_nacl;
	if (!saved_nacl) {
		pr_debug("Setting up new fc_loopid->se_nacl"
				" to new_se_nacl\n");
		fc_loopid->se_nacl = new_se_nacl;
		if (qla_tgt_sess->se_sess != se_sess)
			qla_tgt_sess->se_sess = se_sess;
		if (nacl->qla_tgt_sess != qla_tgt_sess)
			nacl->qla_tgt_sess = qla_tgt_sess;
		return;
	}

	if (nacl->qla_tgt_sess) {
		if (new_se_nacl == NULL) {
			pr_debug("Clearing nacl->qla_tgt_sess and"
					" fc_loopid->se_nacl\n");
			fc_loopid->se_nacl = NULL;
			nacl->qla_tgt_sess = NULL;
			return;
		}

		pr_debug("Replacing existing nacl->qla_tgt_sess and"
				" fc_loopid->se_nacl\n");
		fc_loopid->se_nacl = new_se_nacl;
		if (qla_tgt_sess->se_sess != se_sess)
			qla_tgt_sess->se_sess = se_sess;
		if (nacl->qla_tgt_sess != qla_tgt_sess)
			nacl->qla_tgt_sess = qla_tgt_sess;
		return;
	}

	if (new_se_nacl == NULL) {
		pr_debug("Clearing fc_loopid->se_nacl\n");
		fc_loopid->se_nacl = NULL;
		return;
	}

	pr_debug("Replacing existing fc_loopid->se_nacl w/o"
			" active nacl->qla_tgt_sess\n");
	fc_loopid->se_nacl = new_se_nacl;
	if (qla_tgt_sess->se_sess != se_sess)
		qla_tgt_sess->se_sess = se_sess;
	if (nacl->qla_tgt_sess != qla_tgt_sess)
		nacl->qla_tgt_sess = qla_tgt_sess;

	pr_debug("Setup nacl->qla_tgt_sess %p by loop_id for se_nacl: %p,"
		" initiatorname: %s\n", nacl->qla_tgt_sess, new_se_nacl,
		new_se_nacl->initiatorname);
}

static void tcm_qla2xxx_free_session(struct qla_tgt_sess *sess)
{
	struct qla_tgt *tgt = sess->tgt;
	struct qla_hw_data *ha = tgt->ha;
	struct se_session *se_sess;
	struct se_node_acl *se_nacl;
	struct tcm_qla2xxx_lport *lport;
	struct tcm_qla2xxx_nacl *nacl;
	unsigned char be_sid[3];

	se_sess = sess->se_sess;
	if (!se_sess) {
		pr_err("struct qla_tgt_sess->se_sess is NULL\n");
		dump_stack();
		return;
	}
	se_nacl = se_sess->se_node_acl;
        nacl = container_of(se_nacl, struct tcm_qla2xxx_nacl, se_node_acl);

	lport = (struct tcm_qla2xxx_lport *)ha->target_lport_ptr;
	if (!lport) {
		pr_err("Unable to locate struct tcm_qla2xxx_lport\n");
		dump_stack();
		return;
	}
	/*
	 * Now clear the struct se_node_acl->nacl_sess pointer
	 */
	transport_deregister_session_configfs(sess->se_sess);

        /*
         * And now clear the se_nacl and session pointers from our HW lport
         * mappings for fabric S_ID and LOOP_ID.
         */
	memset(&be_sid, 0, 3);
	be_sid[0] = sess->s_id.b.domain;
	be_sid[1] = sess->s_id.b.area;
	be_sid[2] = sess->s_id.b.al_pa;

        tcm_qla2xxx_set_sess_by_s_id(lport, NULL, nacl, se_sess,
                        sess, be_sid);
        tcm_qla2xxx_set_sess_by_loop_id(lport, NULL, nacl, se_sess,
                        sess, sess->loop_id);
	/*
	 * Release the FC nexus -> target se_session link now.
	 */
	transport_deregister_session(sess->se_sess);
}

/*
 * Called via qla_tgt_create_sess():ha->qla2x_tmpl->check_initiator_node_acl()
 * to locate struct se_node_acl
 */
static int tcm_qla2xxx_check_initiator_node_acl(
	scsi_qla_host_t *vha,
	unsigned char *fc_wwpn,
	void *qla_tgt_sess,
	uint8_t *s_id,
	uint16_t loop_id)
{
	struct qla_hw_data *ha = vha->hw;
	struct tcm_qla2xxx_lport *lport;
	struct tcm_qla2xxx_tpg *tpg;
	struct tcm_qla2xxx_nacl *nacl;
	struct se_portal_group *se_tpg;
	struct se_node_acl *se_nacl;
	struct se_session *se_sess;
	struct qla_tgt_sess *sess = qla_tgt_sess;
	unsigned char port_name[36];
	unsigned long flags;

	lport = (struct tcm_qla2xxx_lport *)ha->target_lport_ptr;
	if (!lport) {
		pr_err("Unable to locate struct tcm_qla2xxx_lport\n");
		dump_stack();
		return -EINVAL;
	}
	/*
	 * Locate the TPG=1 reference..
	 */
	tpg = lport->tpg_1;
	if (!tpg) {
		pr_err("Unable to lcoate struct tcm_qla2xxx_lport->tpg_1\n");
		return -EINVAL;
	}
	se_tpg = &tpg->se_tpg;

	se_sess = transport_init_session();
	if (!se_sess) {
		pr_err("Unable to initialize struct se_session\n");
		return -ENOMEM;
	}
	/*
	 * Format the FCP Initiator port_name into colon seperated values to match
	 * the format by tcm_qla2xxx explict ConfigFS NodeACLs.
	 */
	memset(&port_name, 0, 36);
	snprintf(port_name, 36, "%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x",
		fc_wwpn[0], fc_wwpn[1], fc_wwpn[2], fc_wwpn[3], fc_wwpn[4],
		fc_wwpn[5], fc_wwpn[6], fc_wwpn[7]);
	/*
	 * Locate our struct se_node_acl either from an explict NodeACL created
	 * via ConfigFS, or via running in TPG demo mode.
	 */
	se_sess->se_node_acl = core_tpg_check_initiator_node_acl(se_tpg, port_name);
	if (!se_sess->se_node_acl) {
		transport_free_session(se_sess);
		return -EINVAL;
	}
	se_nacl = se_sess->se_node_acl;
	nacl = container_of(se_nacl, struct tcm_qla2xxx_nacl, se_node_acl);
	/*
	 * And now setup the new se_nacl and session pointers into our HW lport
	 * mappings for fabric S_ID and LOOP_ID.
	 */
	spin_lock_irqsave(&ha->hardware_lock, flags);
	tcm_qla2xxx_set_sess_by_s_id(lport, se_nacl, nacl, se_sess,
			qla_tgt_sess, s_id);
	tcm_qla2xxx_set_sess_by_loop_id(lport, se_nacl, nacl, se_sess,
			qla_tgt_sess, loop_id);
	spin_unlock_irqrestore(&ha->hardware_lock, flags);
	/*
	 * Finally register the new FC Nexus with TCM
	 */
	__transport_register_session(se_nacl->se_tpg, se_nacl, se_sess, sess);

	return 0;
}

/*
 * Calls into tcm_qla2xxx used by qla2xxx LLD I/O path.
 */
static struct qla_tgt_func_tmpl tcm_qla2xxx_template = {
	.handle_cmd		= tcm_qla2xxx_handle_cmd,
	.handle_data		= tcm_qla2xxx_handle_data,
	.handle_tmr		= tcm_qla2xxx_handle_tmr,
	.free_cmd		= tcm_qla2xxx_free_cmd,
	.free_session		= tcm_qla2xxx_free_session,
	.check_initiator_node_acl = tcm_qla2xxx_check_initiator_node_acl,
	.find_sess_by_s_id	= tcm_qla2xxx_find_sess_by_s_id,
	.find_sess_by_loop_id	= tcm_qla2xxx_find_sess_by_loop_id,
};

static int tcm_qla2xxx_init_lport(
	struct tcm_qla2xxx_lport *lport,
	struct scsi_qla_host *vha,
	struct scsi_qla_host *npiv_vp)
{
	struct qla_hw_data *ha = vha->hw;

	lport->lport_fcport_map = vmalloc(
			sizeof(struct tcm_qla2xxx_fc_domain) * 256);
	if (!lport->lport_fcport_map) {
		pr_err("Unable to allocate lport_fcport_map of %lu"
			" bytes\n", sizeof(struct tcm_qla2xxx_fc_domain) * 256);
		return -ENOMEM;
	}
	memset(lport->lport_fcport_map, 0,
			sizeof(struct tcm_qla2xxx_fc_domain) * 256);
	pr_debug("qla2xxx: Allocated lport_fcport_map of %lu bytes\n",
			sizeof(struct tcm_qla2xxx_fc_domain) * 256);

	lport->lport_loopid_map = vmalloc(sizeof(struct tcm_qla2xxx_fc_loopid) *
				65536);
	if (!lport->lport_loopid_map) {
		pr_err("Unable to allocate lport->lport_loopid_map"
			" of %lu bytes\n", sizeof(struct tcm_qla2xxx_fc_loopid)
			* 65536);
		vfree(lport->lport_fcport_map);
		return -ENOMEM;
	}
	memset(lport->lport_loopid_map, 0, sizeof(struct tcm_qla2xxx_fc_loopid)
			* 65536);
	pr_debug("qla2xxx: Allocated lport_loopid_map of %lu bytes\n",
			sizeof(struct tcm_qla2xxx_fc_loopid) * 65536);
	/*
	 * Setup local pointer to vha, NPIV VP pointer (if present) and
	 * vha->tcm_lport pointer
	 */
	lport->qla_vha = vha;
	lport->qla_npiv_vp = npiv_vp;
	/*
	 * Setup the target_lport_ptr and qla2x_tmpl.
	 */
	ha->target_lport_ptr = lport;
	ha->tgt_ops = &tcm_qla2xxx_template;

	return 0;
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
	if (!lport) {
		pr_err("Unable to allocate struct tcm_qla2xxx_lport\n");
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
			pr_debug("MODE_TARGET already active on qla2xxx"
					"(%d)\n",  host->host_no);
			spin_unlock_irqrestore(&ha->hardware_lock, flags);
			continue;
		}
		spin_unlock_irqrestore(&ha->hardware_lock, flags);

		if (!scsi_host_get(host)) {
			pr_err("Unable to scsi_host_get() for"
				" qla2xxx scsi_host\n");
			ret = -EINVAL;
			goto out;
		}

		pr_debug("qla2xxx HW vha->node_name: ");
		for (i = 0; i < 8; i++)
			pr_debug("%02x ", vha->node_name[i]);
		pr_debug("\n");

		pr_debug("qla2xxx HW vha->port_name: ");
		for (i = 0; i < 8; i++)
			pr_debug("%02x ", vha->port_name[i]);
		pr_debug("\n");

		pr_debug("qla2xxx passed configfs WWPN: ");
		put_unaligned_be64(wwpn, b);
		for (i = 0; i < 8; i++)
			pr_debug("%02x ", b[i]);
		pr_debug("\n");

		if (memcmp(vha->port_name, b, 8)) {
			scsi_host_put(host);
			continue;
		}
		pr_debug("qla2xxx: Found matching HW WWPN: %s for lport\n", name);
		ret = tcm_qla2xxx_init_lport(lport, vha, NULL);
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
	struct qla_hw_data *ha = vha->hw;
	struct Scsi_Host *sh = vha->host;
	/*
	 * Call into qla2x_target.c LLD logic to complete the
	 * shutdown of struct qla_tgt after the call to
	 * qla_tgt_stop_phase1() from tcm_qla2xxx_drop_tpg() above..
	 */
	if (ha->qla_tgt && !ha->qla_tgt->tgt_stopped)
		qla_tgt_stop_phase2(ha->qla_tgt);
	/*
	 * Clear the target_lport_ptr qla_target_template pointer in qla_hw_data
	 */
	ha->target_lport_ptr = NULL;
	ha->tgt_ops = NULL;
	/*
	 * Release the Scsi_Host reference for the underlying qla2xxx host
	 */
	scsi_host_put(sh);

	vfree(lport->lport_loopid_map);
	vfree(lport->lport_fcport_map);
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
	if (!lport) {
		pr_err("Unable to allocate struct tcm_qla2xxx_lport"
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
			pr_debug("MODE_TARGET already active on qla2xxx"
					"(%d)\n",  host->host_no);
			spin_unlock_irqrestore(&ha->hardware_lock, flags);
			continue;
		}
		spin_unlock_irqrestore(&ha->hardware_lock, flags);

		if (!scsi_host_get(host)) {
			pr_err("Unable to scsi_host_get() for"
				" qla2xxx scsi_host\n");
			ret = -EINVAL;
			goto out;
		}

		pr_debug("qla2xxx HW vha->node_name: ");
		for (i = 0; i < 8; i++)
			pr_debug("%02x ", vha->node_name[i]);
		pr_debug("\n");

		pr_debug("qla2xxx HW vha->port_name: ");
		for (i = 0; i < 8; i++)
			pr_debug("%02x ", vha->port_name[i]);
		pr_debug("\n");

		pr_debug("qla2xxx passed configfs NPIV WWPN: ");
		put_unaligned_be64(npiv_wwpn, b);
		for (i = 0; i < 8; i++)
			pr_debug("%02x ", b[i]);
		pr_debug("\n");

		pr_debug("qla2xxx passed configfs NPIV WWNN: ");
		put_unaligned_be64(npiv_wwnn, b2);
		for (i = 0; i < 8; i++)
			pr_debug("%02x ", b2[i]);
		pr_debug("\n");

		spin_lock_irqsave(&ha->vport_slock, flags);
		list_for_each_entry(npiv_vp, &ha->vp_list, list) {
			if (!npiv_vp->vp_idx)
				continue;

			if (memcmp(npiv_vp->port_name, b, 8) ||
			    memcmp(npiv_vp->node_name, b2, 8))
				continue;

#warning FIXME: Need to add atomic_inc(&npiv_vp->vref_count) before dropping ha->vport_slock..?
			spin_unlock_irqrestore(&ha->vport_slock, flags);

			pr_debug("qla2xxx_npiv: Found matching NPIV WWPN+WWNN: %s "
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
				pr_err("fc_vport_create() failed for"
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
	.tpg_check_demo_mode		= tcm_qla2xxx_check_demo_mode,
	.tpg_check_demo_mode_cache	= tcm_qla2xxx_check_demo_mode_cache,
	.tpg_check_demo_mode_write_protect = tcm_qla2xxx_check_demo_write_protect,
	.tpg_check_prod_mode_write_protect = tcm_qla2xxx_check_prod_write_protect,
	.tpg_check_demo_mode_login_only = tcm_qla2xxx_check_true,
	.tpg_alloc_fabric_acl		= tcm_qla2xxx_alloc_fabric_acl,
	.tpg_release_fabric_acl		= tcm_qla2xxx_release_fabric_acl,
	.tpg_get_inst_index		= tcm_qla2xxx_tpg_get_inst_index,
	.new_cmd_map			= tcm_qla2xxx_new_cmd_map,
	.check_stop_free		= tcm_qla2xxx_check_stop_free,
	.release_cmd			= tcm_qla2xxx_release_cmd,
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
	.queue_data_in			= tcm_qla2xxx_queue_data_in,
	.queue_status			= tcm_qla2xxx_queue_status,
	.queue_tm_rsp			= tcm_qla2xxx_queue_tm_rsp,
	.get_fabric_sense_len		= tcm_qla2xxx_get_fabric_sense_len,
	.set_fabric_sense_len		= tcm_qla2xxx_set_fabric_sense_len,
	.is_state_remove		= tcm_qla2xxx_is_state_remove,
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
	.tpg_check_demo_mode_login_only	= tcm_qla2xxx_check_true,
	.tpg_alloc_fabric_acl		= tcm_qla2xxx_alloc_fabric_acl,
	.tpg_release_fabric_acl		= tcm_qla2xxx_release_fabric_acl,
	.tpg_get_inst_index		= tcm_qla2xxx_tpg_get_inst_index,
	.release_cmd			= tcm_qla2xxx_release_cmd,
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
	.queue_data_in			= tcm_qla2xxx_queue_data_in,
	.queue_status			= tcm_qla2xxx_queue_status,
	.queue_tm_rsp			= tcm_qla2xxx_queue_tm_rsp,
	.get_fabric_sense_len		= tcm_qla2xxx_get_fabric_sense_len,
	.set_fabric_sense_len		= tcm_qla2xxx_set_fabric_sense_len,
	.is_state_remove		= tcm_qla2xxx_is_state_remove,
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

	pr_debug("TCM QLOGIC QLA2XXX fabric module %s on %s/%s"
		" on "UTS_RELEASE"\n", TCM_QLA2XXX_VERSION, utsname()->sysname,
		utsname()->machine);
	/*
	 * Register the top level struct config_item_type with TCM core
	 */
	fabric = target_fabric_configfs_init(THIS_MODULE, "qla2xxx");
	if (!fabric) {
		pr_err("target_fabric_configfs_init() failed\n");
		return -ENOMEM;
	}
	/*
	 * Setup fabric->tf_ops from our local tcm_qla2xxx_ops
	 */
	fabric->tf_ops = tcm_qla2xxx_ops;
	/*
	 * Setup the struct se_task->task_sg[] chaining bit
	 */
	fabric->tf_ops.task_sg_chaining = 1;
	/*
	 * Setup default attribute lists for various fabric->tf_cit_tmpl
	 */
	TF_CIT_TMPL(fabric)->tfc_wwn_cit.ct_attrs = tcm_qla2xxx_wwn_attrs;
	TF_CIT_TMPL(fabric)->tfc_tpg_base_cit.ct_attrs = tcm_qla2xxx_tpg_attrs;
	TF_CIT_TMPL(fabric)->tfc_tpg_attrib_cit.ct_attrs = tcm_qla2xxx_tpg_attrib_attrs;
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
		pr_err("target_fabric_configfs_register() failed"
				" for TCM_QLA2XXX\n");
		return ret;
	}
	/*
	 * Setup our local pointer to *fabric
	 */
	tcm_qla2xxx_fabric_configfs = fabric;	
	pr_debug("TCM_QLA2XXX[0] - Set fabric -> tcm_qla2xxx_fabric_configfs\n");

	/*
	 * Register the top level struct config_item_type for NPIV with TCM core
	 */
	npiv_fabric = target_fabric_configfs_init(THIS_MODULE, "qla2xxx_npiv");
	if (!npiv_fabric) {
		pr_err("target_fabric_configfs_init() failed\n");
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
		pr_err("target_fabric_configfs_register() failed"
				" for TCM_QLA2XXX\n");
		goto out;;
	}
	/*
	 * Setup our local pointer to *npiv_fabric
	 */
	tcm_qla2xxx_npiv_fabric_configfs = npiv_fabric;
	pr_debug("TCM_QLA2XXX[0] - Set fabric -> tcm_qla2xxx_npiv_fabric_configfs\n");

	return 0;
out:
	if (tcm_qla2xxx_fabric_configfs != NULL)
		target_fabric_configfs_deregister(tcm_qla2xxx_fabric_configfs);

	return ret;
}

static void tcm_qla2xxx_deregister_configfs(void)
{
	if (!tcm_qla2xxx_fabric_configfs)
		return;

	target_fabric_configfs_deregister(tcm_qla2xxx_fabric_configfs);
	tcm_qla2xxx_fabric_configfs = NULL;
	pr_debug("TCM_QLA2XXX[0] - Cleared tcm_qla2xxx_fabric_configfs\n");

	target_fabric_configfs_deregister(tcm_qla2xxx_npiv_fabric_configfs);
	tcm_qla2xxx_npiv_fabric_configfs = NULL;
	pr_debug("TCM_QLA2XXX[0] - Cleared tcm_qla2xxx_npiv_fabric_configfs\n");
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

MODULE_DESCRIPTION("TCM QLA2XXX series NPIV enabled fabric driver");
MODULE_LICENSE("GPL");
module_init(tcm_qla2xxx_init);
module_exit(tcm_qla2xxx_exit);
