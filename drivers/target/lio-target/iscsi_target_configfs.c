/*******************************************************************************
 * Filename:  iscsi_target_configfs.c
 *
 * This file contains the configfs implementation for iSCSI Target mode
 * from the LIO-Target Project.
 *
 * Copyright (c) 2008, 2009, 2010 Rising Tide, Inc.
 * Copyright (c) 2008, 2009, 2010 Linux-iSCSI.org
 *
 * Copyright (c) 2008, 2009, 2010 Nicholas A. Bellinger <nab@linux-iscsi.org>
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
#include <linux/version.h>
#include <generated/utsrelease.h>
#include <linux/utsname.h>
#include <linux/init.h>
#include <linux/slab.h>
#include <linux/types.h>
#include <linux/string.h>
#include <linux/configfs.h>
#include <linux/inet.h>

#include <iscsi_linux_defs.h>
#include <target/target_core_base.h>
#include <target/target_core_transport.h>
#include <target/target_core_fabric_ops.h>
#include <target/target_core_fabric_configfs.h>
#include <target/target_core_fabric_lib.h>
#include <target/target_core_device.h>
#include <target/target_core_tpg.h>
#include <target/target_core_configfs.h>
#include <target/target_core_alua.h>
#include <target/configfs_macros.h>

#include <iscsi_protocol.h>
#include <iscsi_target_core.h>
#include <target/target_core_base.h>
#include <iscsi_target_device.h>
#include <iscsi_target_erl0.h>
#include <iscsi_target_nodeattrib.h>
#include <iscsi_target_tpg.h>
#include <iscsi_target_util.h>
#include <iscsi_target.h>
#ifdef SNMP_SUPPORT
#include <iscsi_target_mib.h>
#endif /* SNMP_SUPPORT */
#include <iscsi_target_configfs.h>

struct target_fabric_configfs *lio_target_fabric_configfs;

struct lio_target_configfs_attribute {
	struct configfs_attribute attr;
	ssize_t (*show)(void *, char *);
	ssize_t (*store)(void *, const char *, size_t);
};

struct iscsi_portal_group *lio_get_tpg_from_tpg_item(
	struct config_item *item,
	struct iscsi_tiqn **tiqn_out)
{
	struct se_portal_group *se_tpg = container_of(to_config_group(item),
					struct se_portal_group, tpg_group);
	struct iscsi_portal_group *tpg =
			(struct iscsi_portal_group *)se_tpg->se_tpg_fabric_ptr;
	int ret;

	if (!(tpg)) {
		printk(KERN_ERR "Unable to locate struct iscsi_portal_group "
			"pointer\n");
		return NULL;
	}
	ret = iscsi_get_tpg(tpg);
	if (ret < 0)
		return NULL;

	*tiqn_out = tpg->tpg_tiqn;
	return tpg;
}

/* Start items for lio_target_portal_cit */

static ssize_t lio_target_np_show_sctp(
	struct se_tpg_np *se_tpg_np,
	char *page)
{
	struct iscsi_tpg_np *tpg_np = container_of(se_tpg_np,
				struct iscsi_tpg_np, se_tpg_np);
	struct iscsi_tpg_np *tpg_np_sctp;
	ssize_t rb;

	tpg_np_sctp = iscsi_tpg_locate_child_np(tpg_np, ISCSI_SCTP_TCP);
	if ((tpg_np_sctp))
		rb = sprintf(page, "1\n");
	else
		rb = sprintf(page, "0\n");

	return rb;
}

static ssize_t lio_target_np_store_sctp(
	struct se_tpg_np *se_tpg_np,
	const char *page,
	size_t count)
{
	struct iscsi_np *np;
	struct iscsi_portal_group *tpg;
	struct iscsi_tpg_np *tpg_np = container_of(se_tpg_np,
				struct iscsi_tpg_np, se_tpg_np);
	struct iscsi_tpg_np *tpg_np_sctp = NULL;
	struct iscsi_np_addr np_addr;
	char *endptr;
	u32 op;
	int ret;

	op = simple_strtoul(page, &endptr, 0);
	 if ((op != 1) && (op != 0)) {
		printk(KERN_ERR "Illegal value for tpg_enable: %u\n", op);
		return -EINVAL;
	}
	np = tpg_np->tpg_np;
	if (!(np)) {
		printk(KERN_ERR "Unable to locate struct iscsi_np from"
				" struct iscsi_tpg_np\n");
		return -EINVAL;
	}

	tpg = tpg_np->tpg;
	if (iscsi_get_tpg(tpg) < 0)
		return -EINVAL;

	if (op) {
		memset((void *)&np_addr, 0, sizeof(struct iscsi_np_addr));
		if (np->np_flags & NPF_NET_IPV6)
			snprintf(np_addr.np_ipv6, IPV6_ADDRESS_SPACE,
				"%s", np->np_ipv6);
		else
			np_addr.np_ipv4 = np->np_ipv4;
		np_addr.np_flags = np->np_flags;
		np_addr.np_port = np->np_port;

		tpg_np_sctp = iscsi_tpg_add_network_portal(tpg, &np_addr,
					tpg_np, ISCSI_SCTP_TCP);
		if (!(tpg_np_sctp) || IS_ERR(tpg_np_sctp))
			goto out;
	} else {
		tpg_np_sctp = iscsi_tpg_locate_child_np(tpg_np, ISCSI_SCTP_TCP);
		if (!(tpg_np_sctp))
			goto out;

		ret = iscsi_tpg_del_network_portal(tpg, tpg_np_sctp);
		if (ret < 0)
			goto out;
	}

	iscsi_put_tpg(tpg);
	return count;
out:
	iscsi_put_tpg(tpg);
	return -EINVAL;
}

TF_NP_BASE_ATTR(lio_target, sctp, S_IRUGO | S_IWUSR);

static struct configfs_attribute *lio_target_portal_attrs[] = {
	&lio_target_np_sctp.attr,
	NULL,
};

/* Stop items for lio_target_portal_cit */

/* Start items for lio_target_np_cit */

#define MAX_PORTAL_LEN		256

struct se_tpg_np *lio_target_call_addnptotpg(
	struct se_portal_group *se_tpg,
	struct config_group *group,
	const char *name)
{
	struct iscsi_portal_group *tpg;
	struct iscsi_tpg_np *tpg_np;
	char *str, *str2, *end_ptr, *ip_str, *port_str;
	struct iscsi_np_addr np_addr;
	u32 ipv4 = 0;
	int ret;
	char buf[MAX_PORTAL_LEN];

	if (strlen(name) > MAX_PORTAL_LEN) {
		printk(KERN_ERR "strlen(name): %d exceeds MAX_PORTAL_LEN: %d\n",
			(int)strlen(name), MAX_PORTAL_LEN);
		return ERR_PTR(-EOVERFLOW);
	}
	memset(buf, 0, MAX_PORTAL_LEN);
	snprintf(buf, MAX_PORTAL_LEN, "%s", name);

	memset((void *)&np_addr, 0, sizeof(struct iscsi_np_addr));

	str = strstr(buf, "[");
	if ((str)) {
		str2 = strstr(str, "]");
		if (!(str2)) {
			printk(KERN_ERR "Unable to locate trailing \"]\""
				" in IPv6 iSCSI network portal address\n");
			return ERR_PTR(-EINVAL);
		}
		str++; /* Skip over leading "[" */
		*str2 = '\0'; /* Terminate the IPv6 address */
		str2 += 1; /* Skip over the "]" */
		port_str = strstr(str2, ":");
		if (!(port_str)) {
			printk(KERN_ERR "Unable to locate \":port\""
				" in IPv6 iSCSI network portal address\n");
			return ERR_PTR(-EINVAL);
		}
		*port_str = '\0'; /* Terminate string for IP */
		port_str += 1; /* Skip over ":" */
		np_addr.np_port = simple_strtoul(port_str, &end_ptr, 0);

		snprintf(np_addr.np_ipv6, IPV6_ADDRESS_SPACE, "%s", str);
		np_addr.np_flags |= NPF_NET_IPV6;
	} else {
		ip_str = &buf[0];
		port_str = strstr(ip_str, ":");
		if (!(port_str)) {
			printk(KERN_ERR "Unable to locate \":port\""
				" in IPv4 iSCSI network portal address\n");
			return ERR_PTR(-EINVAL);
		}
		*port_str = '\0'; /* Terminate string for IP */
		port_str += 1; /* Skip over ":" */
		np_addr.np_port = simple_strtoul(port_str, &end_ptr, 0);

		ipv4 = in_aton(ip_str);
		np_addr.np_ipv4 = htonl(ipv4);
		np_addr.np_flags |= NPF_NET_IPV4;
	}
	tpg = container_of(se_tpg, struct iscsi_portal_group, tpg_se_tpg);
	ret = iscsi_get_tpg(tpg);
	if (ret < 0)
		return ERR_PTR(-EINVAL);

	printk(KERN_INFO "LIO_Target_ConfigFS: REGISTER -> %s TPGT: %hu"
		" PORTAL: %s\n",
		config_item_name(&se_tpg->se_tpg_wwn->wwn_group.cg_item),
		tpg->tpgt, name);
	/*
	 * Assume ISCSI_TCP by default.  Other network portals for other
	 * iSCSI fabrics:
	 *
	 * Traditional iSCSI over SCTP (initial support)
	 * iSER/TCP (TODO, hardware available)
	 * iSER/SCTP (TODO, software emulation with osc-iwarp)
	 * iSER/IB (TODO, hardware available)
	 *
	 * can be enabled with atributes under
	 * sys/kernel/config/iscsi/$IQN/$TPG/np/$IP:$PORT/
	 *
	 */
	tpg_np = iscsi_tpg_add_network_portal(tpg, &np_addr, NULL, ISCSI_TCP);
	if (IS_ERR(tpg_np)) {
		iscsi_put_tpg(tpg);
		return ERR_PTR(PTR_ERR(tpg_np));
	}
	printk(KERN_INFO "LIO_Target_ConfigFS: addnptotpg done!\n");

	iscsi_put_tpg(tpg);
	return &tpg_np->se_tpg_np;
}

static void lio_target_call_delnpfromtpg(
	struct se_tpg_np *se_tpg_np)
{
	struct iscsi_portal_group *tpg;
	struct iscsi_tpg_np *tpg_np;
	struct se_portal_group *se_tpg;
	int ret = 0;

	tpg_np = container_of(se_tpg_np, struct iscsi_tpg_np, se_tpg_np);
	tpg = tpg_np->tpg;
	ret = iscsi_get_tpg(tpg);
	if (ret < 0)
		return;

	se_tpg = &tpg->tpg_se_tpg;
	printk(KERN_INFO "LIO_Target_ConfigFS: DEREGISTER -> %s TPGT: %hu"
		" PORTAL: %s\n", config_item_name(&se_tpg->se_tpg_wwn->wwn_group.cg_item),
		tpg->tpgt, config_item_name(&se_tpg_np->tpg_np_group.cg_item));

	ret = iscsi_tpg_del_network_portal(tpg, tpg_np);
	if (ret < 0)
		goto out;

	printk(KERN_INFO "LIO_Target_ConfigFS: delnpfromtpg done!\n");
out:
	iscsi_put_tpg(tpg);
}

/* End items for lio_target_np_cit */

/* Start items for lio_target_nacl_attrib_cit */

#define DEF_NACL_ATTRIB(name)						\
static ssize_t iscsi_nacl_attrib_show_##name(				\
	struct se_node_acl *se_nacl,					\
	char *page)							\
{									\
	struct iscsi_node_acl *nacl = container_of(se_nacl, struct iscsi_node_acl, \
					se_node_acl);			\
	ssize_t rb;							\
									\
	rb = sprintf(page, "%u\n", ISCSI_NODE_ATTRIB(nacl)->name);	\
	return rb;							\
}									\
									\
static ssize_t iscsi_nacl_attrib_store_##name(				\
	struct se_node_acl *se_nacl,					\
	const char *page,						\
	size_t count)							\
{									\
	struct iscsi_node_acl *nacl = container_of(se_nacl, struct iscsi_node_acl, \
					se_node_acl);			\
	char *endptr;							\
	u32 val;							\
	int ret;							\
									\
	val = simple_strtoul(page, &endptr, 0);				\
	ret = iscsi_na_##name(nacl, val);				\
	if (ret < 0)							\
		return ret;						\
									\
	return count;							\
}

#define NACL_ATTR(_name, _mode) TF_NACL_ATTRIB_ATTR(iscsi, _name, _mode);
/*
 * Define iscsi_node_attrib_s_dataout_timeout
 */
DEF_NACL_ATTRIB(dataout_timeout);
NACL_ATTR(dataout_timeout, S_IRUGO | S_IWUSR);
/*
 * Define iscsi_node_attrib_s_dataout_timeout_retries
 */
DEF_NACL_ATTRIB(dataout_timeout_retries);
NACL_ATTR(dataout_timeout_retries, S_IRUGO | S_IWUSR);
/*
 * Define iscsi_node_attrib_s_default_erl
 */
DEF_NACL_ATTRIB(default_erl);
NACL_ATTR(default_erl, S_IRUGO | S_IWUSR);
/*
 * Define iscsi_node_attrib_s_nopin_timeout
 */
DEF_NACL_ATTRIB(nopin_timeout);
NACL_ATTR(nopin_timeout, S_IRUGO | S_IWUSR);
/*
 * Define iscsi_node_attrib_s_nopin_response_timeout
 */
DEF_NACL_ATTRIB(nopin_response_timeout);
NACL_ATTR(nopin_response_timeout, S_IRUGO | S_IWUSR);
/*
 * Define iscsi_node_attrib_s_random_datain_pdu_offsets
 */
DEF_NACL_ATTRIB(random_datain_pdu_offsets);
NACL_ATTR(random_datain_pdu_offsets, S_IRUGO | S_IWUSR);
/*
 * Define iscsi_node_attrib_s_random_datain_seq_offsets
 */
DEF_NACL_ATTRIB(random_datain_seq_offsets);
NACL_ATTR(random_datain_seq_offsets, S_IRUGO | S_IWUSR);
/*
 * Define iscsi_node_attrib_s_random_r2t_offsets
 */
DEF_NACL_ATTRIB(random_r2t_offsets);
NACL_ATTR(random_r2t_offsets, S_IRUGO | S_IWUSR);

static struct configfs_attribute *lio_target_nacl_attrib_attrs[] = {
	&iscsi_nacl_attrib_dataout_timeout.attr,
	&iscsi_nacl_attrib_dataout_timeout_retries.attr,
	&iscsi_nacl_attrib_default_erl.attr,
	&iscsi_nacl_attrib_nopin_timeout.attr,
	&iscsi_nacl_attrib_nopin_response_timeout.attr,
	&iscsi_nacl_attrib_random_datain_pdu_offsets.attr,
	&iscsi_nacl_attrib_random_datain_seq_offsets.attr,
	&iscsi_nacl_attrib_random_r2t_offsets.attr,
	NULL,
};

/* End items for lio_target_nacl_attrib_cit */

/* Start items for lio_target_nacl_auth_cit */

#define __DEF_NACL_AUTH_STR(prefix, name, flags)			\
static ssize_t __iscsi_##prefix##_show_##name(				\
	struct iscsi_node_acl *nacl,					\
	char *page)							\
{									\
	struct iscsi_node_auth *auth = &nacl->node_auth;		\
	ssize_t rb;							\
									\
	if (!capable(CAP_SYS_ADMIN))					\
		return -EPERM;						\
	rb = snprintf(page, PAGE_SIZE, "%s\n", auth->name);		\
	return rb;							\
}									\
									\
static ssize_t __iscsi_##prefix##_store_##name(				\
	struct iscsi_node_acl *nacl,					\
	const char *page,						\
	size_t count)							\
{									\
	struct iscsi_node_auth *auth = &nacl->node_auth;		\
									\
	if (!capable(CAP_SYS_ADMIN))					\
		return -EPERM;						\
									\
	snprintf(auth->name, PAGE_SIZE, "%s", page);			\
	if (!(strncmp("NULL", auth->name, 4)))				\
		auth->naf_flags &= ~flags;				\
	else								\
		auth->naf_flags |= flags;				\
									\
	if ((auth->naf_flags & NAF_USERID_IN_SET) &&			\
	    (auth->naf_flags & NAF_PASSWORD_IN_SET))			\
		auth->authenticate_target = 1;				\
	else								\
		auth->authenticate_target = 0;				\
									\
	return count;							\
}

#define __DEF_NACL_AUTH_INT(prefix, name)				\
static ssize_t __iscsi_##prefix##_show_##name(				\
	struct iscsi_node_acl *nacl,					\
	char *page)							\
{									\
	struct iscsi_node_auth *auth = &nacl->node_auth;		\
	ssize_t rb;							\
									\
	if (!capable(CAP_SYS_ADMIN))					\
		return -EPERM;						\
									\
	rb = snprintf(page, PAGE_SIZE, "%d\n", auth->name);		\
	return rb;							\
}

#define DEF_NACL_AUTH_STR(name, flags)					\
	__DEF_NACL_AUTH_STR(nacl_auth, name, flags)			\
static ssize_t iscsi_nacl_auth_show_##name(				\
	struct se_node_acl *nacl,					\
	char *page)							\
{									\
	return __iscsi_nacl_auth_show_##name(container_of(nacl,		\
			struct iscsi_node_acl, se_node_acl), page);		\
}									\
static ssize_t iscsi_nacl_auth_store_##name(				\
	struct se_node_acl *nacl,					\
	const char *page,						\
	size_t count)							\
{									\
	return __iscsi_nacl_auth_store_##name(container_of(nacl,	\
			struct iscsi_node_acl, se_node_acl), page, count);	\
}

#define DEF_NACL_AUTH_INT(name)						\
	__DEF_NACL_AUTH_INT(nacl_auth, name)				\
static ssize_t iscsi_nacl_auth_show_##name(				\
	struct se_node_acl *nacl,					\
	char *page)							\
{									\
	return __iscsi_nacl_auth_show_##name(container_of(nacl,		\
			struct iscsi_node_acl, se_node_acl), page);		\
}

#define AUTH_ATTR(_name, _mode)	TF_NACL_AUTH_ATTR(iscsi, _name, _mode);
#define AUTH_ATTR_RO(_name) TF_NACL_AUTH_ATTR_RO(iscsi, _name);

/*
 * One-way authentication userid
 */
DEF_NACL_AUTH_STR(userid, NAF_USERID_SET);
AUTH_ATTR(userid, S_IRUGO | S_IWUSR);
/*
 * One-way authentication password
 */
DEF_NACL_AUTH_STR(password, NAF_PASSWORD_SET);
AUTH_ATTR(password, S_IRUGO | S_IWUSR);
/*
 * Enforce mutual authentication
 */
DEF_NACL_AUTH_INT(authenticate_target);
AUTH_ATTR_RO(authenticate_target);
/*
 * Mutual authentication userid
 */
DEF_NACL_AUTH_STR(userid_mutual, NAF_USERID_IN_SET);
AUTH_ATTR(userid_mutual, S_IRUGO | S_IWUSR);
/*
 * Mutual authentication password
 */
DEF_NACL_AUTH_STR(password_mutual, NAF_PASSWORD_IN_SET);
AUTH_ATTR(password_mutual, S_IRUGO | S_IWUSR);

static struct configfs_attribute *lio_target_nacl_auth_attrs[] = {
	&iscsi_nacl_auth_userid.attr,
	&iscsi_nacl_auth_password.attr,
	&iscsi_nacl_auth_authenticate_target.attr,
	&iscsi_nacl_auth_userid_mutual.attr,
	&iscsi_nacl_auth_password_mutual.attr,
	NULL,
};

/* End items for lio_target_nacl_auth_cit */

/* Start items for lio_target_nacl_param_cit */

#define DEF_NACL_PARAM(name)						\
static ssize_t iscsi_nacl_param_show_##name(				\
	struct se_node_acl *se_nacl,					\
	char *page)							\
{									\
	struct iscsi_session *sess;						\
	struct se_session *se_sess;						\
	ssize_t rb;							\
									\
	spin_lock_bh(&se_nacl->nacl_sess_lock);				\
	se_sess = se_nacl->nacl_sess;					\
	if (!(se_sess)) {						\
		rb = snprintf(page, PAGE_SIZE,				\
			"No Active iSCSI Session\n");			\
	} else {							\
		sess = (struct iscsi_session *)se_sess->fabric_sess_ptr;	\
		rb = snprintf(page, PAGE_SIZE, "%u\n",			\
			(u32)SESS_OPS(sess)->name);			\
	}								\
	spin_unlock_bh(&se_nacl->nacl_sess_lock);			\
									\
	return rb;							\
}

#define NACL_PARAM_ATTR(_name) TF_NACL_PARAM_ATTR_RO(iscsi, _name);

DEF_NACL_PARAM(MaxConnections);
NACL_PARAM_ATTR(MaxConnections);

DEF_NACL_PARAM(InitialR2T);
NACL_PARAM_ATTR(InitialR2T);

DEF_NACL_PARAM(ImmediateData);
NACL_PARAM_ATTR(ImmediateData);

DEF_NACL_PARAM(MaxBurstLength);
NACL_PARAM_ATTR(MaxBurstLength);

DEF_NACL_PARAM(FirstBurstLength);
NACL_PARAM_ATTR(FirstBurstLength);

DEF_NACL_PARAM(DefaultTime2Wait);
NACL_PARAM_ATTR(DefaultTime2Wait);

DEF_NACL_PARAM(DefaultTime2Retain);
NACL_PARAM_ATTR(DefaultTime2Retain);

DEF_NACL_PARAM(MaxOutstandingR2T);
NACL_PARAM_ATTR(MaxOutstandingR2T);

DEF_NACL_PARAM(DataPDUInOrder);
NACL_PARAM_ATTR(DataPDUInOrder);

DEF_NACL_PARAM(DataSequenceInOrder);
NACL_PARAM_ATTR(DataSequenceInOrder);

DEF_NACL_PARAM(ErrorRecoveryLevel);
NACL_PARAM_ATTR(ErrorRecoveryLevel);

static struct configfs_attribute *lio_target_nacl_param_attrs[] = {
	&iscsi_nacl_param_MaxConnections.attr,
	&iscsi_nacl_param_InitialR2T.attr,
	&iscsi_nacl_param_ImmediateData.attr,
	&iscsi_nacl_param_MaxBurstLength.attr,
	&iscsi_nacl_param_FirstBurstLength.attr,
	&iscsi_nacl_param_DefaultTime2Wait.attr,
	&iscsi_nacl_param_DefaultTime2Retain.attr,
	&iscsi_nacl_param_MaxOutstandingR2T.attr,
	&iscsi_nacl_param_DataPDUInOrder.attr,
	&iscsi_nacl_param_DataSequenceInOrder.attr,
	&iscsi_nacl_param_ErrorRecoveryLevel.attr,
	NULL,
};

/* End items for lio_target_nacl_param_cit */

/* Start items for lio_target_acl_cit */

static ssize_t lio_target_nacl_show_info(
	struct se_node_acl *se_nacl,
	char *page)
{
	struct iscsi_session *sess;
	struct iscsi_conn *conn;
	struct se_session *se_sess;
	unsigned char *ip, buf_ipv4[IPV4_BUF_SIZE];
	ssize_t rb = 0;

	spin_lock_bh(&se_nacl->nacl_sess_lock);
	se_sess = se_nacl->nacl_sess;
	if (!(se_sess))
		rb += sprintf(page+rb, "No active iSCSI Session for Initiator"
			" Endpoint: %s\n", se_nacl->initiatorname);
	else {
		sess = (struct iscsi_session *)se_sess->fabric_sess_ptr;

		if (SESS_OPS(sess)->InitiatorName)
			rb += sprintf(page+rb, "InitiatorName: %s\n",
				SESS_OPS(sess)->InitiatorName);
		if (SESS_OPS(sess)->InitiatorAlias)
			rb += sprintf(page+rb, "InitiatorAlias: %s\n",
				SESS_OPS(sess)->InitiatorAlias);

		rb += sprintf(page+rb, "LIO Session ID: %u   "
			"ISID: 0x%02x %02x %02x %02x %02x %02x  "
			"TSIH: %hu  ", sess->sid,
			sess->isid[0], sess->isid[1], sess->isid[2],
			sess->isid[3], sess->isid[4], sess->isid[5],
			sess->tsih);
		rb += sprintf(page+rb, "SessionType: %s\n",
				(SESS_OPS(sess)->SessionType) ?
				"Discovery" : "Normal");
		rb += sprintf(page+rb, "Session State: ");
		switch (sess->session_state) {
		case TARG_SESS_STATE_FREE:
			rb += sprintf(page+rb, "TARG_SESS_FREE\n");
			break;
		case TARG_SESS_STATE_ACTIVE:
			rb += sprintf(page+rb, "TARG_SESS_STATE_ACTIVE\n");
			break;
		case TARG_SESS_STATE_LOGGED_IN:
			rb += sprintf(page+rb, "TARG_SESS_STATE_LOGGED_IN\n");
			break;
		case TARG_SESS_STATE_FAILED:
			rb += sprintf(page+rb, "TARG_SESS_STATE_FAILED\n");
			break;
		case TARG_SESS_STATE_IN_CONTINUE:
			rb += sprintf(page+rb, "TARG_SESS_STATE_IN_CONTINUE\n");
			break;
		default:
			rb += sprintf(page+rb, "ERROR: Unknown Session"
					" State!\n");
			break;
		}

		rb += sprintf(page+rb, "---------------------[iSCSI Session"
				" Values]-----------------------\n");
		rb += sprintf(page+rb, "  CmdSN/WR  :  CmdSN/WC  :  ExpCmdSN"
				"  :  MaxCmdSN  :     ITT    :     TTT\n");
		rb += sprintf(page+rb, " 0x%08x   0x%08x   0x%08x   0x%08x"
				"   0x%08x   0x%08x\n",
			sess->cmdsn_window,
			(sess->max_cmd_sn - sess->exp_cmd_sn) + 1,
			sess->exp_cmd_sn, sess->max_cmd_sn,
			sess->init_task_tag, sess->targ_xfer_tag);
		rb += sprintf(page+rb, "----------------------[iSCSI"
				" Connections]-------------------------\n");

		spin_lock(&sess->conn_lock);
		list_for_each_entry(conn, &sess->sess_conn_list, conn_list) {
			rb += sprintf(page+rb, "CID: %hu  Connection"
					" State: ", conn->cid);
			switch (conn->conn_state) {
			case TARG_CONN_STATE_FREE:
				rb += sprintf(page+rb,
					"TARG_CONN_STATE_FREE\n");
				break;
			case TARG_CONN_STATE_XPT_UP:
				rb += sprintf(page+rb,
					"TARG_CONN_STATE_XPT_UP\n");
				break;
			case TARG_CONN_STATE_IN_LOGIN:
				rb += sprintf(page+rb,
					"TARG_CONN_STATE_IN_LOGIN\n");
				break;
			case TARG_CONN_STATE_LOGGED_IN:
				rb += sprintf(page+rb,
					"TARG_CONN_STATE_LOGGED_IN\n");
				break;
			case TARG_CONN_STATE_IN_LOGOUT:
				rb += sprintf(page+rb,
					"TARG_CONN_STATE_IN_LOGOUT\n");
				break;
			case TARG_CONN_STATE_LOGOUT_REQUESTED:
				rb += sprintf(page+rb,
					"TARG_CONN_STATE_LOGOUT_REQUESTED\n");
				break;
			case TARG_CONN_STATE_CLEANUP_WAIT:
				rb += sprintf(page+rb,
					"TARG_CONN_STATE_CLEANUP_WAIT\n");
				break;
			default:
				rb += sprintf(page+rb,
					"ERROR: Unknown Connection State!\n");
				break;
			}

			if (conn->net_size == IPV6_ADDRESS_SPACE)
				ip = &conn->ipv6_login_ip[0];
			else {
				iscsi_ntoa2(buf_ipv4, conn->login_ip);
				ip = &buf_ipv4[0];
			}
			rb += sprintf(page+rb, "   Address %s %s", ip,
				(conn->network_transport == ISCSI_TCP) ?
				"TCP" : "SCTP");
			rb += sprintf(page+rb, "  StatSN: 0x%08x\n",
				conn->stat_sn);
		}
		spin_unlock(&sess->conn_lock);
	}
	spin_unlock_bh(&se_nacl->nacl_sess_lock);

	return rb;
}

TF_NACL_BASE_ATTR_RO(lio_target, info);

static ssize_t lio_target_nacl_show_cmdsn_depth(
	struct se_node_acl *se_nacl,
	char *page)
{
	return sprintf(page, "%u\n", se_nacl->queue_depth);
}

static ssize_t lio_target_nacl_store_cmdsn_depth(
	struct se_node_acl *se_nacl,
	const char *page,
	size_t count)
{
	struct se_portal_group *se_tpg = se_nacl->se_tpg;
	struct iscsi_portal_group *tpg = container_of(se_tpg,
			struct iscsi_portal_group, tpg_se_tpg);
	struct config_item *acl_ci, *tpg_ci, *wwn_ci;
	char *endptr;
	u32 cmdsn_depth = 0;
	int ret = 0;

	cmdsn_depth = simple_strtoul(page, &endptr, 0);
	if (cmdsn_depth > TA_DEFAULT_CMDSN_DEPTH_MAX) {
		printk(KERN_ERR "Passed cmdsn_depth: %u exceeds"
			" TA_DEFAULT_CMDSN_DEPTH_MAX: %u\n", cmdsn_depth,
			TA_DEFAULT_CMDSN_DEPTH_MAX);
		return -EINVAL;
	}
	acl_ci = &se_nacl->acl_group.cg_item;
	if (!(acl_ci)) {
		printk(KERN_ERR "Unable to locatel acl_ci\n");
		return -EINVAL;
	}
	tpg_ci = &acl_ci->ci_parent->ci_group->cg_item;
	if (!(tpg_ci)) {
		printk(KERN_ERR "Unable to locate tpg_ci\n");
		return -EINVAL;
	}
	wwn_ci = &tpg_ci->ci_group->cg_item;
	if (!(wwn_ci)) {
		printk(KERN_ERR "Unable to locate config_item wwn_ci\n");
		return -EINVAL;
	}

	if (iscsi_get_tpg(tpg) < 0)
		return -EINVAL;
	/*
	 * iscsi_tpg_set_initiator_node_queue_depth() assumes force=1
	 */
	ret = iscsi_tpg_set_initiator_node_queue_depth(tpg,
				config_item_name(acl_ci), cmdsn_depth, 1);

	printk(KERN_INFO "LIO_Target_ConfigFS: %s/%s Set CmdSN Window: %u for"
		"InitiatorName: %s\n", config_item_name(wwn_ci),
		config_item_name(tpg_ci), cmdsn_depth,
		config_item_name(acl_ci));

	iscsi_put_tpg(tpg);
	return (!ret) ? count : (ssize_t)ret;
}

TF_NACL_BASE_ATTR(lio_target, cmdsn_depth, S_IRUGO | S_IWUSR);

static struct configfs_attribute *lio_target_initiator_attrs[] = {
	&lio_target_nacl_info.attr,
	&lio_target_nacl_cmdsn_depth.attr,
	NULL,
};

static struct se_node_acl *lio_target_make_nodeacl(
	struct se_portal_group *se_tpg,
	struct config_group *group,
	const char *name)
{
	struct iscsi_node_acl *acl;
	struct se_node_acl *se_nacl_new, *se_nacl;
	struct iscsi_portal_group *tpg = container_of(se_tpg,
			struct iscsi_portal_group, tpg_se_tpg);
	u32 cmdsn_depth;

	se_nacl_new = lio_tpg_alloc_fabric_acl(se_tpg);

	acl = container_of(se_nacl_new, struct iscsi_node_acl,
				se_node_acl);

	cmdsn_depth = ISCSI_TPG_ATTRIB(tpg)->default_cmdsn_depth;
	/*
	 * se_nacl_new may be released by core_tpg_add_initiator_node_acl()
	 * when converting a NdoeACL from demo mode -> explict
	 */
	se_nacl = core_tpg_add_initiator_node_acl(se_tpg, se_nacl_new,
				name, cmdsn_depth);
	if (IS_ERR(se_nacl))
		return ERR_PTR(PTR_ERR(se_nacl));

	return se_nacl;
}

static void lio_target_drop_nodeacl(
	struct se_node_acl *se_nacl)
{
	struct se_portal_group *se_tpg = se_nacl->se_tpg;
	struct iscsi_node_acl *acl = container_of(se_nacl,
			struct iscsi_node_acl, se_node_acl);

	core_tpg_del_initiator_node_acl(se_tpg, se_nacl, 1);
	kfree(acl);
}

/* End items for lio_target_acl_cit */

/* Start items for lio_target_tpg_attrib_cit */

#define DEF_TPG_ATTRIB(name)						\
									\
static ssize_t iscsi_tpg_attrib_show_##name(				\
	struct se_portal_group *se_tpg,				\
	char *page)							\
{									\
	struct iscsi_portal_group *tpg = container_of(se_tpg,		\
			struct iscsi_portal_group, tpg_se_tpg);	\
	ssize_t rb;							\
									\
	if (iscsi_get_tpg(tpg) < 0)					\
		return -EINVAL;						\
									\
	rb = sprintf(page, "%u\n", ISCSI_TPG_ATTRIB(tpg)->name);	\
	iscsi_put_tpg(tpg);						\
	return rb;							\
}									\
									\
static ssize_t iscsi_tpg_attrib_store_##name(				\
	struct se_portal_group *se_tpg,				\
	const char *page,						\
	size_t count)							\
{									\
	struct iscsi_portal_group *tpg = container_of(se_tpg,		\
			struct iscsi_portal_group, tpg_se_tpg);	\
	char *endptr;							\
	u32 val;							\
	int ret;							\
									\
	if (iscsi_get_tpg(tpg) < 0)					\
		return -EINVAL;						\
									\
	val = simple_strtoul(page, &endptr, 0);				\
	ret = iscsi_ta_##name(tpg, val);				\
	if (ret < 0)							\
		goto out;						\
									\
	iscsi_put_tpg(tpg);						\
	return count;							\
out:									\
	iscsi_put_tpg(tpg);						\
	return ret;							\
}

#define TPG_ATTR(_name, _mode) TF_TPG_ATTRIB_ATTR(iscsi, _name, _mode);

/*
 * Define iscsi_tpg_attrib_s_authentication
 */
DEF_TPG_ATTRIB(authentication);
TPG_ATTR(authentication, S_IRUGO | S_IWUSR);
/*
 * Define iscsi_tpg_attrib_s_login_timeout
 */
DEF_TPG_ATTRIB(login_timeout);
TPG_ATTR(login_timeout, S_IRUGO | S_IWUSR);
/*
 * Define iscsi_tpg_attrib_s_netif_timeout
 */
DEF_TPG_ATTRIB(netif_timeout);
TPG_ATTR(netif_timeout, S_IRUGO | S_IWUSR);
/*
 * Define iscsi_tpg_attrib_s_generate_node_acls
 */
DEF_TPG_ATTRIB(generate_node_acls);
TPG_ATTR(generate_node_acls, S_IRUGO | S_IWUSR);
/*
 * Define iscsi_tpg_attrib_s_default_cmdsn_depth
 */
DEF_TPG_ATTRIB(default_cmdsn_depth);
TPG_ATTR(default_cmdsn_depth, S_IRUGO | S_IWUSR);
/*
 Define iscsi_tpg_attrib_s_cache_dynamic_acls
 */
DEF_TPG_ATTRIB(cache_dynamic_acls);
TPG_ATTR(cache_dynamic_acls, S_IRUGO | S_IWUSR);
/*
 * Define iscsi_tpg_attrib_s_demo_mode_write_protect
 */
DEF_TPG_ATTRIB(demo_mode_write_protect);
TPG_ATTR(demo_mode_write_protect, S_IRUGO | S_IWUSR);
/*
 * Define iscsi_tpg_attrib_s_prod_mode_write_protect
 */
DEF_TPG_ATTRIB(prod_mode_write_protect);
TPG_ATTR(prod_mode_write_protect, S_IRUGO | S_IWUSR);

static struct configfs_attribute *lio_target_tpg_attrib_attrs[] = {
	&iscsi_tpg_attrib_authentication.attr,
	&iscsi_tpg_attrib_login_timeout.attr,
	&iscsi_tpg_attrib_netif_timeout.attr,
	&iscsi_tpg_attrib_generate_node_acls.attr,
	&iscsi_tpg_attrib_default_cmdsn_depth.attr,
	&iscsi_tpg_attrib_cache_dynamic_acls.attr,
	&iscsi_tpg_attrib_demo_mode_write_protect.attr,
	&iscsi_tpg_attrib_prod_mode_write_protect.attr,
	NULL,
};

/* End items for lio_target_tpg_attrib_cit */

/* Start items for lio_target_tpg_param_cit */

#define DEF_TPG_PARAM(name)						\
static ssize_t iscsi_tpg_param_show_##name(				\
	struct se_portal_group *se_tpg,				\
	char *page)							\
{									\
	struct iscsi_portal_group *tpg = container_of(se_tpg,		\
			struct iscsi_portal_group, tpg_se_tpg);	\
	struct iscsi_param *param;						\
	ssize_t rb;							\
									\
	if (iscsi_get_tpg(tpg) < 0)					\
		return -EINVAL;						\
									\
	param = iscsi_find_param_from_key(__stringify(name),		\
				tpg->param_list);			\
	if (!(param)) {							\
		iscsi_put_tpg(tpg);					\
		return -EINVAL;						\
	}								\
	rb = snprintf(page, PAGE_SIZE, "%s\n", param->value);		\
									\
	iscsi_put_tpg(tpg);						\
	return rb;							\
}									\
static ssize_t iscsi_tpg_param_store_##name(				\
	struct se_portal_group *se_tpg,				\
	const char *page,						\
	size_t count)							\
{									\
	struct iscsi_portal_group *tpg = container_of(se_tpg,		\
			struct iscsi_portal_group, tpg_se_tpg);	\
	char *buf;							\
	int ret;							\
									\
	buf = kzalloc(PAGE_SIZE, GFP_KERNEL);				\
	if (!(buf))							\
		return -ENOMEM;						\
	snprintf(buf, PAGE_SIZE, "%s=%s", __stringify(name), page);	\
	buf[strlen(buf)-1] = '\0'; /* Kill newline */			\
									\
	if (iscsi_get_tpg(tpg) < 0)					\
		return -EINVAL;						\
									\
	ret = iscsi_change_param_value(buf, SENDER_TARGET,		\
				tpg->param_list, 1);			\
	if (ret < 0)							\
		goto out;						\
									\
	kfree(buf);							\
	iscsi_put_tpg(tpg);						\
	return count;							\
out:									\
	kfree(buf);							\
	iscsi_put_tpg(tpg);						\
	return -EINVAL;						\
}

#define TPG_PARAM_ATTR(_name, _mode) TF_TPG_PARAM_ATTR(iscsi, _name, _mode);

DEF_TPG_PARAM(AuthMethod);
TPG_PARAM_ATTR(AuthMethod, S_IRUGO | S_IWUSR);

DEF_TPG_PARAM(HeaderDigest);
TPG_PARAM_ATTR(HeaderDigest, S_IRUGO | S_IWUSR);

DEF_TPG_PARAM(DataDigest);
TPG_PARAM_ATTR(DataDigest, S_IRUGO | S_IWUSR);

DEF_TPG_PARAM(MaxConnections);
TPG_PARAM_ATTR(MaxConnections, S_IRUGO | S_IWUSR);

DEF_TPG_PARAM(TargetAlias);
TPG_PARAM_ATTR(TargetAlias, S_IRUGO | S_IWUSR);

DEF_TPG_PARAM(InitialR2T);
TPG_PARAM_ATTR(InitialR2T, S_IRUGO | S_IWUSR);

DEF_TPG_PARAM(ImmediateData);
TPG_PARAM_ATTR(ImmediateData, S_IRUGO | S_IWUSR);

DEF_TPG_PARAM(MaxRecvDataSegmentLength);
TPG_PARAM_ATTR(MaxRecvDataSegmentLength, S_IRUGO | S_IWUSR);

DEF_TPG_PARAM(MaxBurstLength);
TPG_PARAM_ATTR(MaxBurstLength, S_IRUGO | S_IWUSR);

DEF_TPG_PARAM(FirstBurstLength);
TPG_PARAM_ATTR(FirstBurstLength, S_IRUGO | S_IWUSR);

DEF_TPG_PARAM(DefaultTime2Wait);
TPG_PARAM_ATTR(DefaultTime2Wait, S_IRUGO | S_IWUSR);

DEF_TPG_PARAM(DefaultTime2Retain);
TPG_PARAM_ATTR(DefaultTime2Retain, S_IRUGO | S_IWUSR);

DEF_TPG_PARAM(MaxOutstandingR2T);
TPG_PARAM_ATTR(MaxOutstandingR2T, S_IRUGO | S_IWUSR);

DEF_TPG_PARAM(DataPDUInOrder);
TPG_PARAM_ATTR(DataPDUInOrder, S_IRUGO | S_IWUSR);

DEF_TPG_PARAM(DataSequenceInOrder);
TPG_PARAM_ATTR(DataSequenceInOrder, S_IRUGO | S_IWUSR);

DEF_TPG_PARAM(ErrorRecoveryLevel);
TPG_PARAM_ATTR(ErrorRecoveryLevel, S_IRUGO | S_IWUSR);

DEF_TPG_PARAM(IFMarker);
TPG_PARAM_ATTR(IFMarker, S_IRUGO | S_IWUSR);

DEF_TPG_PARAM(OFMarker);
TPG_PARAM_ATTR(OFMarker, S_IRUGO | S_IWUSR);

DEF_TPG_PARAM(IFMarkInt);
TPG_PARAM_ATTR(IFMarkInt, S_IRUGO | S_IWUSR);

DEF_TPG_PARAM(OFMarkInt);
TPG_PARAM_ATTR(OFMarkInt, S_IRUGO | S_IWUSR);

static struct configfs_attribute *lio_target_tpg_param_attrs[] = {
	&iscsi_tpg_param_AuthMethod.attr,
	&iscsi_tpg_param_HeaderDigest.attr,
	&iscsi_tpg_param_DataDigest.attr,
	&iscsi_tpg_param_MaxConnections.attr,
	&iscsi_tpg_param_TargetAlias.attr,
	&iscsi_tpg_param_InitialR2T.attr,
	&iscsi_tpg_param_ImmediateData.attr,
	&iscsi_tpg_param_MaxRecvDataSegmentLength.attr,
	&iscsi_tpg_param_MaxBurstLength.attr,
	&iscsi_tpg_param_FirstBurstLength.attr,
	&iscsi_tpg_param_DefaultTime2Wait.attr,
	&iscsi_tpg_param_DefaultTime2Retain.attr,
	&iscsi_tpg_param_MaxOutstandingR2T.attr,
	&iscsi_tpg_param_DataPDUInOrder.attr,
	&iscsi_tpg_param_DataSequenceInOrder.attr,
	&iscsi_tpg_param_ErrorRecoveryLevel.attr,
	&iscsi_tpg_param_IFMarker.attr,
	&iscsi_tpg_param_OFMarker.attr,
	&iscsi_tpg_param_IFMarkInt.attr,
	&iscsi_tpg_param_OFMarkInt.attr,
	NULL,
};

/* End items for lio_target_tpg_param_cit */

/* Start items for lio_target_tpg_cit */

static ssize_t lio_target_tpg_show_enable(
	struct se_portal_group *se_tpg,
	char *page)
{
	struct iscsi_portal_group *tpg = container_of(se_tpg,
			struct iscsi_portal_group, tpg_se_tpg);
	ssize_t len = 0;

	spin_lock(&tpg->tpg_state_lock);
	len = sprintf(page, "%d\n",
			(tpg->tpg_state == TPG_STATE_ACTIVE) ? 1 : 0);
	spin_unlock(&tpg->tpg_state_lock);

	return len;
}

static ssize_t lio_target_tpg_store_enable(
	struct se_portal_group *se_tpg,
	const char *page,
	size_t count)
{
	struct iscsi_portal_group *tpg = container_of(se_tpg,
			struct iscsi_portal_group, tpg_se_tpg);
	char *endptr;
	u32 op;
	int ret = 0;

	op = simple_strtoul(page, &endptr, 0);
	if ((op != 1) && (op != 0)) {
		printk(KERN_ERR "Illegal value for tpg_enable: %u\n", op);
		return -EINVAL;
	}

	ret = iscsi_get_tpg(tpg);
	if (ret < 0)
		return -EINVAL;

	if (op) {
		ret = iscsi_tpg_enable_portal_group(tpg);
		if (ret < 0)
			goto out;
	} else {
		/*
		 * iscsi_tpg_disable_portal_group() assumes force=1
		 */
		ret = iscsi_tpg_disable_portal_group(tpg, 1);
		if (ret < 0)
			goto out;
	}

	iscsi_put_tpg(tpg);
	return count;
out:
	iscsi_put_tpg(tpg);
	return -EINVAL;
}

TF_TPG_BASE_ATTR(lio_target, enable, S_IRUGO | S_IWUSR);

static struct configfs_attribute *lio_target_tpg_attrs[] = {
	&lio_target_tpg_enable.attr,
	NULL,
};

/* End items for lio_target_tpg_cit */

/* Start items for lio_target_tiqn_cit */

struct se_portal_group *lio_target_tiqn_addtpg(
	struct se_wwn *wwn,
	struct config_group *group,
	const char *name)
{
	struct iscsi_portal_group *tpg;
	struct iscsi_tiqn *tiqn;
	char *tpgt_str, *end_ptr;
	int ret = 0;
	unsigned short int tpgt;

	tiqn = container_of(wwn, struct iscsi_tiqn, tiqn_wwn);
	/*
	 * Only tpgt_# directory groups can be created below
	 * target/iscsi/iqn.superturodiskarry/
	*/
	tpgt_str = strstr(name, "tpgt_");
	if (!(tpgt_str)) {
		printk(KERN_ERR "Unable to locate \"tpgt_#\" directory"
				" group\n");
		return NULL;
	}
	tpgt_str += 5; /* Skip ahead of "tpgt_" */
	tpgt = (unsigned short int) simple_strtoul(tpgt_str, &end_ptr, 0);

	tpg = core_alloc_portal_group(tiqn, tpgt);
	if (!(tpg))
		return NULL;

	ret = core_tpg_register(
			&lio_target_fabric_configfs->tf_ops,
			wwn, &tpg->tpg_se_tpg, (void *)tpg,
			TRANSPORT_TPG_TYPE_NORMAL);
	if (ret < 0)
		return NULL;

	ret = iscsi_tpg_add_portal_group(tiqn, tpg);
	if (ret != 0)
		goto out;

	printk(KERN_INFO "LIO_Target_ConfigFS: REGISTER -> %s\n", tiqn->tiqn);
	printk(KERN_INFO "LIO_Target_ConfigFS: REGISTER -> Allocated TPG: %s\n",
			name);	
	return &tpg->tpg_se_tpg;
out:
	core_tpg_deregister(&tpg->tpg_se_tpg);
	kmem_cache_free(lio_tpg_cache, tpg);
	return NULL;
}

void lio_target_tiqn_deltpg(struct se_portal_group *se_tpg)
{
	struct iscsi_portal_group *tpg;
	struct iscsi_tiqn *tiqn;

	tpg = container_of(se_tpg, struct iscsi_portal_group, tpg_se_tpg);
	tiqn = tpg->tpg_tiqn;
	/*
	 * iscsi_tpg_del_portal_group() assumes force=1
	 */
	printk(KERN_INFO "LIO_Target_ConfigFS: DEREGISTER -> Releasing TPG\n");
	iscsi_tpg_del_portal_group(tiqn, tpg, 1);
}

/* End items for lio_target_tiqn_cit */

/* Start LIO-Target TIQN struct contig_item lio_target_cit */

static ssize_t lio_target_wwn_show_attr_lio_version(
	struct target_fabric_configfs *tf,
	char *page)
{
	return sprintf(page, "Linux-iSCSI.org Target "PYX_ISCSI_VERSION""
		" on %s/%s on "UTS_RELEASE"\n", utsname()->sysname,
		utsname()->machine);
}

TF_WWN_ATTR_RO(lio_target, lio_version);

static struct configfs_attribute *lio_target_wwn_attrs[] = {
	&lio_target_wwn_lio_version.attr,
	NULL,
};

struct se_wwn *lio_target_call_coreaddtiqn(
	struct target_fabric_configfs *tf,
	struct config_group *group,
	const char *name)
{
	struct iscsi_tiqn *tiqn;
	int ret = 0;

	tiqn = core_add_tiqn((unsigned char *)name, &ret);
	if (!(tiqn))
		return NULL;

	printk(KERN_INFO "LIO_Target_ConfigFS: REGISTER -> %s\n", tiqn->tiqn);
	printk(KERN_INFO "LIO_Target_ConfigFS: REGISTER -> Allocated Node:"
			" %s\n", name);
	return &tiqn->tiqn_wwn;
}

void lio_target_call_coredeltiqn(
	struct se_wwn *wwn)
{
	struct iscsi_tiqn *tiqn = container_of(wwn, struct iscsi_tiqn, tiqn_wwn);
	
	printk(KERN_INFO "LIO_Target_ConfigFS: DEREGISTER -> %s\n",
			tiqn->tiqn);
	printk(KERN_INFO "LIO_Target_ConfigFS: DEREGISTER -> Releasing"
			" core_del_tiqn()\n");
	core_del_tiqn(tiqn);
}

/* End LIO-Target TIQN struct contig_lio_target_cit */

/* Start lio_target_discovery_auth_cit */

#define DEF_DISC_AUTH_STR(name, flags)					\
	__DEF_NACL_AUTH_STR(disc, name, flags)				\
static ssize_t iscsi_disc_show_##name(					\
	struct target_fabric_configfs *tf,				\
	char *page)							\
{									\
	return __iscsi_disc_show_##name(&iscsi_global->discovery_acl,	\
		page);							\
}									\
static ssize_t iscsi_disc_store_##name(					\
	struct target_fabric_configfs *tf,				\
	const char *page,						\
	size_t count)							\
{									\
	return __iscsi_disc_store_##name(&iscsi_global->discovery_acl,	\
		page, count);						\
}

#define DEF_DISC_AUTH_INT(name)						\
	__DEF_NACL_AUTH_INT(disc, name)					\
static ssize_t iscsi_disc_show_##name(					\
        struct target_fabric_configfs *tf,				\
        char *page)							\
{									\
	return __iscsi_disc_show_##name(&iscsi_global->discovery_acl, 	\
			page);						\
}

#define DISC_AUTH_ATTR(_name, _mode) TF_DISC_ATTR(iscsi, _name, _mode)
#define DISC_AUTH_ATTR_RO(_name) TF_DISC_ATTR_RO(iscsi, _name)

/*
 * One-way authentication userid
 */
DEF_DISC_AUTH_STR(userid, NAF_USERID_SET);
DISC_AUTH_ATTR(userid, S_IRUGO | S_IWUSR);
/*
 * One-way authentication password
 */
DEF_DISC_AUTH_STR(password, NAF_PASSWORD_SET);
DISC_AUTH_ATTR(password, S_IRUGO | S_IWUSR);
/*
 * Enforce mutual authentication
 */
DEF_DISC_AUTH_INT(authenticate_target);
DISC_AUTH_ATTR_RO(authenticate_target);
/*
 * Mutual authentication userid
 */
DEF_DISC_AUTH_STR(userid_mutual, NAF_USERID_IN_SET);
DISC_AUTH_ATTR(userid_mutual, S_IRUGO | S_IWUSR);
/*
 * Mutual authentication password
 */
DEF_DISC_AUTH_STR(password_mutual, NAF_PASSWORD_IN_SET);
DISC_AUTH_ATTR(password_mutual, S_IRUGO | S_IWUSR);

/*
 * enforce_discovery_auth
 */
static ssize_t iscsi_disc_show_enforce_discovery_auth(
	struct target_fabric_configfs *tf,
	char *page)
{
	struct iscsi_node_auth *discovery_auth = &iscsi_global->discovery_acl.node_auth;

	return sprintf(page, "%d\n", discovery_auth->enforce_discovery_auth);
}

static ssize_t iscsi_disc_store_enforce_discovery_auth(
	struct target_fabric_configfs *tf,
	const char *page,
	size_t count)
{
	struct iscsi_param *param;
	struct iscsi_portal_group *discovery_tpg = iscsi_global->discovery_tpg;
	char *endptr;
	u32 op;

	op = simple_strtoul(page, &endptr, 0);
	if ((op != 1) && (op != 0)) {
		printk(KERN_ERR "Illegal value for enforce_discovery_auth:"
				" %u\n", op);
		return -EINVAL;
	}

	if (!(discovery_tpg)) {
		printk(KERN_ERR "iscsi_global->discovery_tpg is NULL\n");
		return -EINVAL;
	}

	param = iscsi_find_param_from_key(AUTHMETHOD,
				discovery_tpg->param_list);
	if (!(param))
		return -EINVAL;

	if (op) {
		/*
		 * Reset the AuthMethod key to CHAP.
		 */
		if (iscsi_update_param_value(param, CHAP) < 0)
			return -EINVAL;

		discovery_tpg->tpg_attrib.authentication = 1;
		iscsi_global->discovery_acl.node_auth.enforce_discovery_auth = 1;
		printk(KERN_INFO "LIO-CORE[0] Successfully enabled"
			" authentication enforcement for iSCSI"
			" Discovery TPG\n");
	} else {
		/*
		 * Reset the AuthMethod key to CHAP,None
		 */
		if (iscsi_update_param_value(param, "CHAP,None") < 0)
			return -EINVAL;

		discovery_tpg->tpg_attrib.authentication = 0;
		iscsi_global->discovery_acl.node_auth.enforce_discovery_auth = 0;
		printk(KERN_INFO "LIO-CORE[0] Successfully disabled"
			" authentication enforcement for iSCSI"
			" Discovery TPG\n");
	}

	return count;
}

DISC_AUTH_ATTR(enforce_discovery_auth, S_IRUGO | S_IWUSR);

static struct configfs_attribute *lio_target_discovery_auth_attrs[] = {
	&iscsi_disc_userid.attr,
	&iscsi_disc_password.attr,
	&iscsi_disc_authenticate_target.attr,
	&iscsi_disc_userid_mutual.attr,
	&iscsi_disc_password_mutual.attr,
	&iscsi_disc_enforce_discovery_auth.attr,
	NULL,
};

/* End lio_target_discovery_auth_cit */

int iscsi_target_register_configfs(void)
{
	struct target_fabric_configfs *fabric;
	int ret;

	lio_target_fabric_configfs = NULL;
	fabric = target_fabric_configfs_init(THIS_MODULE, "iscsi");
	if (!(fabric)) {
		printk(KERN_ERR "target_fabric_configfs_init() for"
				" LIO-Target failed!\n");
		return -1;
	}
	/*
	 * Setup the fabric API of function pointers used by target_core_mod..
	 */
	fabric->tf_ops.get_fabric_name = &iscsi_get_fabric_name;
	fabric->tf_ops.get_fabric_proto_ident = &iscsi_get_fabric_proto_ident;
	fabric->tf_ops.tpg_get_wwn = &lio_tpg_get_endpoint_wwn;
	fabric->tf_ops.tpg_get_tag = &lio_tpg_get_tag;
	fabric->tf_ops.tpg_get_default_depth = &lio_tpg_get_default_depth;
	fabric->tf_ops.tpg_get_pr_transport_id = &iscsi_get_pr_transport_id;
	fabric->tf_ops.tpg_get_pr_transport_id_len =
				&iscsi_get_pr_transport_id_len;
	fabric->tf_ops.tpg_parse_pr_out_transport_id =
				&iscsi_parse_pr_out_transport_id;
	fabric->tf_ops.tpg_check_demo_mode = &lio_tpg_check_demo_mode;
	fabric->tf_ops.tpg_check_demo_mode_cache =
				&lio_tpg_check_demo_mode_cache;
	fabric->tf_ops.tpg_check_demo_mode_write_protect =
				&lio_tpg_check_demo_mode_write_protect;
	fabric->tf_ops.tpg_check_prod_mode_write_protect =
				&lio_tpg_check_prod_mode_write_protect;
	fabric->tf_ops.tpg_alloc_fabric_acl = &lio_tpg_alloc_fabric_acl;
	fabric->tf_ops.tpg_release_fabric_acl = &lio_tpg_release_fabric_acl;
#ifdef SNMP_SUPPORT
	fabric->tf_ops.tpg_get_inst_index = &lio_tpg_get_inst_index;
#endif /* SNMP_SUPPORT */
	/*
	 * Use transport_generic_allocate_iovecs from target_core_mod
	 */
	fabric->tf_ops.alloc_cmd_iovecs = &transport_generic_allocate_iovecs;
	fabric->tf_ops.release_cmd_to_pool = &lio_release_cmd_to_pool;
	fabric->tf_ops.release_cmd_direct = &lio_release_cmd_direct;
	fabric->tf_ops.shutdown_session = &lio_tpg_shutdown_session;
	fabric->tf_ops.close_session = &lio_tpg_close_session;
	fabric->tf_ops.stop_session = &lio_tpg_stop_session;
	fabric->tf_ops.fall_back_to_erl0 = &lio_tpg_fall_back_to_erl0;
	fabric->tf_ops.sess_logged_in = &lio_sess_logged_in;
#ifdef SNMP_SUPPORT
	fabric->tf_ops.sess_get_index = &lio_sess_get_index;
#endif /* SNMP_SUPPORT */
	fabric->tf_ops.sess_get_initiator_sid = &lio_sess_get_initiator_sid;
	fabric->tf_ops.write_pending = &lio_write_pending;
	fabric->tf_ops.write_pending_status = &lio_write_pending_status;
	fabric->tf_ops.set_default_node_attributes =
				&lio_set_default_node_attributes;
	fabric->tf_ops.get_task_tag = &iscsi_get_task_tag;
	fabric->tf_ops.get_cmd_state = &iscsi_get_cmd_state;
	fabric->tf_ops.new_cmd_failure = &iscsi_new_cmd_failure;
	fabric->tf_ops.queue_data_in = &lio_queue_data_in;
	fabric->tf_ops.queue_status = &lio_queue_status;
	fabric->tf_ops.queue_tm_rsp = &lio_queue_tm_rsp;
	fabric->tf_ops.set_fabric_sense_len = &lio_set_fabric_sense_len;
	fabric->tf_ops.get_fabric_sense_len = &lio_get_fabric_sense_len;
	fabric->tf_ops.is_state_remove = &iscsi_is_state_remove;
	fabric->tf_ops.pack_lun = &iscsi_pack_lun;
	/*
	 * Setup function pointers for generic logic in target_core_fabric_configfs.c
	 */
	fabric->tf_ops.fabric_make_wwn = &lio_target_call_coreaddtiqn;
	fabric->tf_ops.fabric_drop_wwn = &lio_target_call_coredeltiqn;
	fabric->tf_ops.fabric_make_tpg = &lio_target_tiqn_addtpg;
	fabric->tf_ops.fabric_drop_tpg = &lio_target_tiqn_deltpg;
	fabric->tf_ops.fabric_post_link	= NULL;
	fabric->tf_ops.fabric_pre_unlink = NULL;
	fabric->tf_ops.fabric_make_np = &lio_target_call_addnptotpg;
	fabric->tf_ops.fabric_drop_np = &lio_target_call_delnpfromtpg;
	fabric->tf_ops.fabric_make_nodeacl = &lio_target_make_nodeacl;
	fabric->tf_ops.fabric_drop_nodeacl = &lio_target_drop_nodeacl;
	/*
	 * Setup default attribute lists for various fabric->tf_cit_tmpl
	 * sturct config_item_type's
	 */
	TF_CIT_TMPL(fabric)->tfc_discovery_cit.ct_attrs = lio_target_discovery_auth_attrs;
	TF_CIT_TMPL(fabric)->tfc_wwn_cit.ct_attrs = lio_target_wwn_attrs;
	TF_CIT_TMPL(fabric)->tfc_tpg_base_cit.ct_attrs = lio_target_tpg_attrs;
	TF_CIT_TMPL(fabric)->tfc_tpg_attrib_cit.ct_attrs = lio_target_tpg_attrib_attrs;
	TF_CIT_TMPL(fabric)->tfc_tpg_param_cit.ct_attrs = lio_target_tpg_param_attrs;
	TF_CIT_TMPL(fabric)->tfc_tpg_np_base_cit.ct_attrs = lio_target_portal_attrs;
	TF_CIT_TMPL(fabric)->tfc_tpg_nacl_base_cit.ct_attrs = lio_target_initiator_attrs;
	TF_CIT_TMPL(fabric)->tfc_tpg_nacl_attrib_cit.ct_attrs = lio_target_nacl_attrib_attrs;
	TF_CIT_TMPL(fabric)->tfc_tpg_nacl_auth_cit.ct_attrs = lio_target_nacl_auth_attrs;
	TF_CIT_TMPL(fabric)->tfc_tpg_nacl_param_cit.ct_attrs = lio_target_nacl_param_attrs;

	ret = target_fabric_configfs_register(fabric);
	if (ret < 0) {
		printk(KERN_ERR "target_fabric_configfs_register() for"
				" LIO-Target failed!\n");
		target_fabric_configfs_free(fabric);
		return -1;
	}

	lio_target_fabric_configfs = fabric;
	printk(KERN_INFO "LIO_TARGET[0] - Set fabric ->"
			" lio_target_fabric_configfs\n");
	return 0;
}


void iscsi_target_deregister_configfs(void)
{
	if (!(lio_target_fabric_configfs))
		return;
	/*
	 * Shutdown discovery sessions and disable discovery TPG
	 */
	if (iscsi_global->discovery_tpg)
		iscsi_tpg_disable_portal_group(iscsi_global->discovery_tpg, 1);

	target_fabric_configfs_deregister(lio_target_fabric_configfs);
	lio_target_fabric_configfs = NULL;
	printk(KERN_INFO "LIO_TARGET[0] - Cleared"
				" lio_target_fabric_configfs\n");
}
