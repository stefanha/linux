/*******************************************************************************
 * Filename:  iscsi_target_configfs.c
 *
 * This file contains the configfs implementation for iSCSI Target mode
 * from the LIO-Target Project.
 *
 * Copyright (c) 2008-2009 Rising Tide, Inc.
 * Copyright (c) 2008-2009 Linux-iSCSI.org
 *
 * Copyright (c) 2008-2009 Nicholas A. Bellinger <nab@linux-iscsi.org>
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
#include <linux/utsrelease.h>
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

iscsi_portal_group_t *lio_get_tpg_from_tpg_item(
	struct config_item *item,
	iscsi_tiqn_t **tiqn_out)
{
	se_portal_group_t *se_tpg = container_of(to_config_group(item),
					se_portal_group_t, tpg_group);
	iscsi_portal_group_t *tpg =
			(iscsi_portal_group_t *)se_tpg->se_tpg_fabric_ptr;
	int ret;

	if (!(tpg)) {
		printk(KERN_ERR "Unable to locate iscsi_portal_group_t "
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

static ssize_t lio_target_show_np_info(void *p, char *page)
{
	return 0;
}

static struct lio_target_configfs_attribute lio_target_attr_np_info = {
	.attr	= { .ca_owner = THIS_MODULE,
		    .ca_name = "info",
		    .ca_mode = S_IRUGO },
	.show	= lio_target_show_np_info,
	.store	= NULL,
};

static ssize_t lio_target_show_np_sctp(void *p, char *page)
{
	iscsi_tpg_np_t *tpg_np = (iscsi_tpg_np_t *)p, *tpg_np_sctp;
	ssize_t rb;

	tpg_np_sctp = iscsi_tpg_locate_child_np(tpg_np, ISCSI_SCTP_TCP);
	if ((tpg_np_sctp))
		rb = sprintf(page, "1\n");
	else
		rb = sprintf(page, "0\n");

	return rb;
}

static ssize_t lio_target_store_np_sctp(void *p, const char *page, size_t count)
{
	iscsi_np_t *np;
	iscsi_portal_group_t *tpg;
	iscsi_tpg_np_t *tpg_np = (iscsi_tpg_np_t *)p;
	iscsi_tpg_np_t *tpg_np_sctp = NULL;
	iscsi_tiqn_t *tiqn;
	char *endptr;
	iscsi_np_addr_t np_addr;
	u32 op;
	int ret;

	op = simple_strtoul(page, &endptr, 0);
	 if ((op != 1) && (op != 0)) {
		printk(KERN_ERR "Illegal value for tpg_enable: %u\n", op);
		return -EINVAL;
	}
	np = tpg_np->tpg_np;
	if (!(np)) {
		printk(KERN_ERR "Unable to locate iscsi_np_t from"
				" iscsi_tpg_np_t\n");
		return -EINVAL;
	}

	tpg = lio_get_tpg_from_tpg_item(
			&tpg_np->tpg->tpg_se_tpg->tpg_group.cg_item, &tiqn);
	if (!(tpg))
		return -EINVAL;

	if (op) {
		memset((void *)&np_addr, 0, sizeof(iscsi_np_addr_t));
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

static struct lio_target_configfs_attribute lio_target_attr_np_sctp = {
	.attr	= { .ca_owner = THIS_MODULE,
		    .ca_name = "sctp",
		    .ca_mode = S_IRUGO | S_IWUSR },
	.show	= lio_target_show_np_sctp,
	.store	= lio_target_store_np_sctp,
};

static struct configfs_attribute *lio_target_portal_attrs[] = {
	&lio_target_attr_np_info.attr,
	&lio_target_attr_np_sctp.attr,
	NULL,
};

static ssize_t lio_target_portal_show(
	struct config_item *item,
	struct configfs_attribute *attr,
	char *page)
{
	iscsi_tpg_np_t *tpg_np = container_of(to_config_group(item),
			iscsi_tpg_np_t, tpg_np_group);
	struct lio_target_configfs_attribute *lt_attr = container_of(
			attr, struct lio_target_configfs_attribute, attr);

	if (!(lt_attr->show))
		return -EINVAL;

	return lt_attr->show((void *)tpg_np, page);
}

static ssize_t lio_target_portal_store(
	struct config_item *item,
	struct configfs_attribute *attr,
	const char *page,
	size_t count)
{
	iscsi_tpg_np_t *tpg_np = container_of(to_config_group(item),
			iscsi_tpg_np_t, tpg_np_group);
	struct lio_target_configfs_attribute *lt_attr = container_of(
			attr, struct lio_target_configfs_attribute, attr);

	if (!(lt_attr->store))
		return -EINVAL;

	 return lt_attr->store((void *)tpg_np, page, count);
}

static struct configfs_item_operations lio_target_portal_item_ops = {
	.show_attribute		= lio_target_portal_show,
	.store_attribute	= lio_target_portal_store,
};

static struct config_item_type lio_target_portal_cit = {
	.ct_item_ops	= &lio_target_portal_item_ops,
	.ct_attrs	= lio_target_portal_attrs,
	.ct_owner	= THIS_MODULE,
};

/* Stop items for lio_target_portal_cit */

/* Start items for lio_target_np_cit */

#define MAX_PORTAL_LEN		256

static struct config_group *lio_target_call_addnptotpg(
	struct config_group *group,
	const char *name)
{
	iscsi_portal_group_t *tpg;
	iscsi_tiqn_t *tiqn;
	iscsi_tpg_np_t *tpg_np;
	struct config_item *np_ci, *tpg_ci, *tiqn_ci;
	char *str, *str2, *end_ptr, *ip_str, *port_str;
	iscsi_np_addr_t np_addr;
	u32 ipv4 = 0;
	char buf[MAX_PORTAL_LEN];

	np_ci = &group->cg_item;
	if (!(np_ci)) {
		printk(KERN_ERR "Unable to locate config_item np_ci\n");
		return ERR_PTR(-EINVAL);
	}
	tpg_ci = &np_ci->ci_group->cg_item;
	if (!(tpg_ci)) {
		printk(KERN_ERR "Unable to locate config_item tpg_ci\n");
		return ERR_PTR(-EINVAL);
	}
	tiqn_ci = &tpg_ci->ci_group->cg_item;
	if (!(tiqn_ci)) {
		printk(KERN_ERR "Unable to locate config_item tiqn_ci\n");
		return ERR_PTR(-EINVAL);
	}
	if (strlen(name) > MAX_PORTAL_LEN) {
		printk(KERN_ERR "strlen(name): %d exceeds MAX_PORTAL_LEN: %d\n",
			(int)strlen(name), MAX_PORTAL_LEN);
		return ERR_PTR(-EOVERFLOW);
	}
	memset(buf, 0, MAX_PORTAL_LEN);
	snprintf(buf, MAX_PORTAL_LEN, "%s", name);

	memset((void *)&np_addr, 0, sizeof(iscsi_np_addr_t));

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

	tpg = lio_get_tpg_from_tpg_item(tpg_ci, &tiqn);
	if (!(tpg))
		return ERR_PTR(-EINVAL);

	printk(KERN_INFO "LIO_Target_ConfigFS: REGISTER -> %s TPGT: %hu"
		" PORTAL: %s\n", config_item_name(tiqn_ci), tpg->tpgt, name);

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

	config_group_init_type_name(&tpg_np->tpg_np_group, name,
			&lio_target_portal_cit);

	printk(KERN_INFO "LIO_Target_ConfigFS: addnptotpg done!\n");

	iscsi_put_tpg(tpg);
	return &tpg_np->tpg_np_group;
}

static void lio_target_call_delnpfromtpg(
	struct config_group *group,
	struct config_item *item)
{
	iscsi_portal_group_t *tpg;
	iscsi_tiqn_t *tiqn;
	iscsi_tpg_np_t *tpg_np;
	struct config_item *np_ci, *tpg_ci, *tiqn_ci;
	int ret = 0;

	np_ci = &group->cg_item;
	if (!(np_ci)) {
		printk(KERN_ERR "Unable to locate config_item np_ci\n");
		return;
	}
	tpg_ci = &np_ci->ci_group->cg_item;
	if (!(tpg_ci)) {
		printk(KERN_ERR "Unable to locate config_item tpg_ci\n");
		return;
	}
	tiqn_ci = &tpg_ci->ci_group->cg_item;
	if (!(tiqn_ci)) {
		printk(KERN_ERR "Unable to locate config_item tiqn_ci\n");
		return;
	}
	tpg_np = container_of(to_config_group(item),
			iscsi_tpg_np_t, tpg_np_group);
	if (!(tpg_np)) {
		printk(KERN_ERR "Unable to locate iscsi_tpg_np_t\n");
		return;
	}

	tpg = lio_get_tpg_from_tpg_item(tpg_ci, &tiqn);
	if (!(tpg))
		return;

	printk(KERN_INFO "LIO_Target_ConfigFS: DEREGISTER -> %s TPGT: %hu"
		" PORTAL: %s\n", config_item_name(tiqn_ci), tpg->tpgt,
		config_item_name(item));

	config_item_put(item);

	ret = iscsi_tpg_del_network_portal(tpg, tpg_np);
	if (ret < 0)
		goto out;

	printk(KERN_INFO "LIO_Target_ConfigFS: delnpfromtpg done!\n");
out:
	iscsi_put_tpg(tpg);
}

static struct configfs_group_operations lio_target_np_group_ops = {
	.make_group	= lio_target_call_addnptotpg,
	.drop_item	= lio_target_call_delnpfromtpg,
};

static struct config_item_type lio_target_np_cit = {
	.ct_item_ops	= NULL,
	.ct_group_ops	= &lio_target_np_group_ops,
	.ct_attrs	= NULL,
	.ct_owner	= THIS_MODULE,
};

/* End items for lio_target_np_cit */

/* Start items for lio_target_port_cit */

CONFIGFS_EATTR_STRUCT(lio_target_port, se_lun_s);
#define LIO_PORT_ATTR(_name, _mode)					\
static struct lio_target_port_attribute lio_target_port_##_name =	\
	__CONFIGFS_EATTR(_name, _mode,					\
	lio_target_port_show_attr_##_name,				\
	lio_target_port_store_attr_##_name);

#define LIO_PORT_ATTR_RO(_name, _mode)					\
static struct lio_target_port_attribute lio_target_port_##_name =	\
	__CONFIGFS_EATTR_RO(_name,					\
	lio_target_port_show_attr_##_name);

/*
 * alua_tg_pt_gp
 */
static ssize_t lio_target_port_show_attr_alua_tg_pt_gp(
	struct se_lun_s *lun,
	char *page)
{
	if (!(lun->lun_sep))
		return -ENODEV;

	return core_alua_show_tg_pt_gp_info(lun->lun_sep, page);
}

static ssize_t lio_target_port_store_attr_alua_tg_pt_gp(
	struct se_lun_s *lun,
	const char *page,
	size_t count)
{
	if (!(lun->lun_sep))
		return -ENODEV;

	return core_alua_store_tg_pt_gp_info(lun->lun_sep, page, count);
}

LIO_PORT_ATTR(alua_tg_pt_gp, S_IRUGO | S_IWUSR);

/*
 * alua_tg_pt_offline
 */
static ssize_t lio_target_port_show_attr_alua_tg_pt_offline(
	struct se_lun_s *lun,
	char *page)
{
	if (!(lun->lun_sep))
		return -ENODEV;

	return core_alua_show_offline_bit(lun, page);
}

static ssize_t lio_target_port_store_attr_alua_tg_pt_offline(
	struct se_lun_s *lun,
	const char *page,
	size_t count)
{
	if (!(lun->lun_sep))
		return -ENODEV;

	return core_alua_store_offline_bit(lun, page, count);
}

LIO_PORT_ATTR(alua_tg_pt_offline, S_IRUGO | S_IWUSR);

/*
 * alua_tg_pt_status
 */
static ssize_t lio_target_port_show_attr_alua_tg_pt_status(
	struct se_lun_s *lun,
	char *page)
{
	if (!(lun->lun_sep))
		return -ENODEV;

	return core_alua_show_secondary_status(lun, page);
}

static ssize_t lio_target_port_store_attr_alua_tg_pt_status(
	struct se_lun_s *lun,
	const char *page,
	size_t count)
{
	if (!(lun->lun_sep))
		return -ENODEV;

	return core_alua_store_secondary_status(lun, page, count);
}

LIO_PORT_ATTR(alua_tg_pt_status, S_IRUGO | S_IWUSR);

/*
 * alua_tg_pt_write_md
 */
static ssize_t lio_target_port_show_attr_alua_tg_pt_write_md(
	struct se_lun_s *lun,
	char *page)
{
	if (!(lun->lun_sep))
		return -ENODEV;

	return core_alua_show_secondary_write_metadata(lun, page);
}

static ssize_t lio_target_port_store_attr_alua_tg_pt_write_md(
	struct se_lun_s *lun,
	const char *page,
	size_t count)
{
	if (!(lun->lun_sep))
		return -ENODEV;

	return core_alua_store_secondary_write_metadata(lun, page, count);
}

LIO_PORT_ATTR(alua_tg_pt_write_md, S_IRUGO | S_IWUSR);

static struct configfs_attribute *lio_target_port_attrs[] = {
	&lio_target_port_alua_tg_pt_gp.attr,
	&lio_target_port_alua_tg_pt_offline.attr,
	&lio_target_port_alua_tg_pt_status.attr,
	&lio_target_port_alua_tg_pt_write_md.attr,
	NULL,
};

CONFIGFS_EATTR_OPS(lio_target_port, se_lun_s, lun_group);

static int lio_target_port_link(
	struct config_item *lun_ci,
	struct config_item *se_dev_ci)
{
	iscsi_portal_group_t *tpg;
	iscsi_tiqn_t *tiqn;
	se_device_t *dev;
	se_lun_t *lun = container_of(to_config_group(lun_ci),
				se_lun_t, lun_group);
	se_lun_t *lun_p;
	se_subsystem_dev_t *se_dev = container_of(
		to_config_group(se_dev_ci), se_subsystem_dev_t, se_dev_group);
	struct config_item *tpg_ci, *tiqn_ci;
	int ret = 0;

	if (lun->lun_type_ptr != NULL) {
		printk(KERN_ERR "Port Symlink already exists\n");
		return -EEXIST;
	}

	tpg_ci = &lun_ci->ci_parent->ci_group->cg_item;
	if (!(tpg_ci)) {
		printk(KERN_ERR "Unable to locate config_item tpg_ci\n");
		return -EINVAL;
	}
	tiqn_ci = &tpg_ci->ci_group->cg_item;
	if (!(tiqn_ci)) {
		printk(KERN_ERR "Unable to locate config_item tiqn_ci\n");
		return -EINVAL;
	}

	tpg = lio_get_tpg_from_tpg_item(tpg_ci, &tiqn);
	if (!(tpg))
		return -EINVAL;

	dev = se_dev->se_dev_ptr;
	if (!(dev)) {
		printk(KERN_ERR "Unable to locate se_device_t pointer from"
			" %s\n", config_item_name(se_dev_ci));
		ret = -ENODEV;
		goto out;
	}

	lun_p = core_dev_add_lun(tpg->tpg_se_tpg, dev->se_hba, dev,
			lun->unpacked_lun);
	if ((IS_ERR(lun_p)) || !(lun_p)) {
		printk(KERN_ERR "core_dev_add_lun() failed: %d\n", ret);
		ret = -EINVAL;
		goto out;
	}
	iscsi_put_tpg(tpg);

	printk(KERN_INFO "LIO_Target_ConfigFS: Created Port Symlink %s -> %s\n",
		config_item_name(se_dev_ci), config_item_name(lun_ci));

	return 0;
out:
	iscsi_put_tpg(tpg);
	return ret;
}

static int lio_target_port_check_link(
	struct config_item *lun_ci,
	struct config_item *se_dev_ci)
{
	se_lun_t *lun = container_of(to_config_group(lun_ci),
			se_lun_t, lun_group);

	return atomic_read(&lun->lun_acl_count) ? -EPERM : 0;
}

static int lio_target_port_unlink(
	struct config_item *lun_ci,
	struct config_item *se_dev_ci)
{
	iscsi_portal_group_t *tpg;
	iscsi_tiqn_t *tiqn;
	se_lun_t *lun = container_of(to_config_group(lun_ci),
			se_lun_t, lun_group);
	struct config_item *tpg_ci, *tiqn_ci;
	int ret;

	tpg_ci = &lun_ci->ci_parent->ci_group->cg_item;
	if (!(tpg_ci)) {
		printk(KERN_ERR "Unable to locate config_item tpg_ci\n");
		return -EINVAL;
	}
	tiqn_ci = &tpg_ci->ci_group->cg_item;
	if (!(tiqn_ci)) {
		printk(KERN_ERR "Unable to locate config_item tiqn_ci\n");
		return -EINVAL;
	}

	tpg = lio_get_tpg_from_tpg_item(tpg_ci, &tiqn);
	if (!(tpg))
		return -EINVAL;

	ret = core_dev_del_lun(tpg->tpg_se_tpg, lun->unpacked_lun);
	iscsi_put_tpg(tpg);

	printk(KERN_INFO "LIO_Target_ConfigFS: Removed Port Symlink %s -> %s\n",
		config_item_name(se_dev_ci), config_item_name(lun_ci));

	return 0;
}

static struct configfs_item_operations lio_target_port_item_ops = {
	.release		= NULL,
	.show_attribute		= lio_target_port_attr_show,
	.store_attribute	= lio_target_port_attr_store,
	.allow_link		= lio_target_port_link,
	.check_link		= lio_target_port_check_link,
	.drop_link		= lio_target_port_unlink,
};

static struct config_item_type lio_target_port_cit = {
	.ct_item_ops		= &lio_target_port_item_ops,
	.ct_attrs		= lio_target_port_attrs,
	.ct_owner		= THIS_MODULE,
};

/* End items for lio_target_port_cit */

/* Start items for lio_target_lun_cit */

static struct config_group *lio_target_lun_make_group(
	struct config_group *group,
	const char *name)
{
	iscsi_portal_group_t *tpg;
	iscsi_tiqn_t *tiqn;
	se_lun_t *lun_p;
	struct config_item *lun_ci, *tpg_ci, *tiqn_ci;
	char *str, *endptr;
	u32 lun;

	str = strstr(name, "_");
	if (!(str)) {
		printk(KERN_ERR "Unable to locate \'_\" in"
				" \"lun_$LUN_NUMBER\"\n");
		return NULL;
	}
	str++; /* Advance over _ delim.. */
	lun = simple_strtoul(str, &endptr, 0);

	lun_ci = &group->cg_item;
	if (!(lun_ci)) {
		printk(KERN_ERR "Unable to locate config_item lun_ci\n");
		return NULL;
	}
	tpg_ci = &lun_ci->ci_group->cg_item;
	if (!(tpg_ci)) {
		printk(KERN_ERR "Unable to locate config_item tpg_ci\n");
		return NULL;
	}
	tiqn_ci = &tpg_ci->ci_group->cg_item;
	if (!(tiqn_ci)) {
		printk(KERN_ERR "Unable to locate config_item tiqn_ci\n");
		return NULL;
	}

	tpg = lio_get_tpg_from_tpg_item(tpg_ci, &tiqn);
	if (!(tpg))
		return NULL;

	lun_p = core_get_lun_from_tpg(tpg->tpg_se_tpg, lun);
	if (!(lun_p))
		goto out;

	printk(KERN_INFO "LIO_Target_ConfigFS: REGISTER -> %s TPGT: %hu LUN:"
		" %u\n", config_item_name(tiqn_ci), tpg->tpgt, lun);

	config_group_init_type_name(&lun_p->lun_group, name,
			&lio_target_port_cit);

	iscsi_put_tpg(tpg);
	return &lun_p->lun_group;
out:
	iscsi_put_tpg(tpg);
	return NULL;
}

static void lio_target_lun_drop_item(
	struct config_group *group,
	struct config_item *item)
{
	iscsi_portal_group_t *tpg;
	iscsi_tiqn_t *tiqn;
	se_lun_t *lun = container_of(to_config_group(item),
				se_lun_t, lun_group);
	struct config_item *lun_ci, *tpg_ci, *tiqn_ci;

	lun_ci = &group->cg_item;
	if (!(lun_ci)) {
		printk(KERN_ERR "Unable to locate config_item np_ci\n");
		return;
	}
	tpg_ci = &lun_ci->ci_group->cg_item;
	if (!(tpg_ci)) {
		printk(KERN_ERR "Unable to locate config_item tpg_ci\n");
		return;
	}
	tiqn_ci = &tpg_ci->ci_group->cg_item;
	if (!(tiqn_ci)) {
		printk(KERN_ERR "Unable to locate config_item tiqn_ci\n");
		return;
	}

	tpg = lio_get_tpg_from_tpg_item(tpg_ci, &tiqn);
	if (!(tpg))
		return;

	printk(KERN_INFO "LIO_Target_ConfigFS: DEREGISTER -> %s TPGT:"
		" %hu LUN: %u\n", config_item_name(tiqn_ci), tpg->tpgt,
		lun->unpacked_lun);

	config_item_put(item);
	iscsi_put_tpg(tpg);
}

static struct configfs_group_operations lio_target_lun_group_ops = {
	.make_group	= lio_target_lun_make_group,
	.drop_item	= lio_target_lun_drop_item,
};

static struct config_item_type lio_target_lun_cit = {
	.ct_item_ops	= NULL,
	.ct_group_ops	= &lio_target_lun_group_ops,
	.ct_attrs	= NULL,
	.ct_owner	= THIS_MODULE,
};

/* End items for lio_target_lun_cit */

/* Start items for lio_target_nacl_attrib_cit */

#define DEF_NACL_ATTRIB(name)						\
static ssize_t lio_target_show_nacl_attrib_##name(			\
	struct iscsi_node_attrib_s *na,					\
	char *page)							\
{									\
	iscsi_node_acl_t *nacl = na->nacl;				\
	ssize_t rb;							\
									\
	rb = sprintf(page, "%u\n", ISCSI_NODE_ATTRIB(nacl)->name);	\
	return rb;							\
}									\
									\
static ssize_t lio_target_store_nacl_attrib_##name(			\
	struct iscsi_node_attrib_s *na,					\
	const char *page,						\
	size_t count)							\
{									\
	iscsi_node_acl_t *nacl = na->nacl;				\
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

/*
 * Define the iSCSI Node attributes using hybrid wrappers from
 * include/linux/configfs.h
 */
CONFIGFS_EATTR_STRUCT(iscsi_node_attrib, iscsi_node_attrib_s);
#define NACL_ATTR(_name, _mode)						\
static struct iscsi_node_attrib_attribute iscsi_node_attrib_##_name =	\
		__CONFIGFS_EATTR(_name, _mode,				\
		lio_target_show_nacl_attrib_##_name,			\
		lio_target_store_nacl_attrib_##_name);
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
/*
 * Finally, define functions iscsi_node_attrib_s_attr_show() and
 * iscsi_node_attrib_s_attr_store() for lio_target_nacl_attrib_ops below..
 */
CONFIGFS_EATTR_OPS(iscsi_node_attrib, iscsi_node_attrib_s, acl_attrib_group);

static struct configfs_attribute *lio_target_nacl_attrib_attrs[] = {
	&iscsi_node_attrib_dataout_timeout.attr,
	&iscsi_node_attrib_dataout_timeout_retries.attr,
	&iscsi_node_attrib_default_erl.attr,
	&iscsi_node_attrib_nopin_timeout.attr,
	&iscsi_node_attrib_nopin_response_timeout.attr,
	&iscsi_node_attrib_random_datain_pdu_offsets.attr,
	&iscsi_node_attrib_random_datain_seq_offsets.attr,
	&iscsi_node_attrib_random_r2t_offsets.attr,
	NULL,
};

static struct configfs_item_operations lio_target_nacl_attrib_ops = {
	.show_attribute		= iscsi_node_attrib_attr_show,
	.store_attribute	= iscsi_node_attrib_attr_store,
};

static struct config_item_type lio_target_nacl_attrib_cit = {
	.ct_item_ops	= &lio_target_nacl_attrib_ops,
	.ct_attrs	= lio_target_nacl_attrib_attrs,
	.ct_owner	= THIS_MODULE,
};

/* End items for lio_target_nacl_attrib_cit */

/* Start items for lio_target_nacl_auth_cit */

#define DEF_NACL_AUTH_STR(name, flags)					\
static ssize_t lio_target_show_nacl_auth_##name(			\
	struct iscsi_node_auth_s *auth,					\
	char *page)							\
{									\
	ssize_t rb;							\
									\
	if (!capable(CAP_SYS_ADMIN))					\
		return -EPERM;						\
	rb = snprintf(page, PAGE_SIZE, "%s\n", auth->name);		\
	return rb;							\
}									\
static ssize_t lio_target_store_nacl_auth_##name(			\
	struct iscsi_node_auth_s *auth,					\
	const char *page,						\
	size_t count)							\
{									\
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

#define DEF_NACL_AUTH_INT(name)						\
static ssize_t lio_target_show_nacl_auth_##name(			\
	struct iscsi_node_auth_s *auth,					\
	char *page)							\
{									\
	ssize_t rb;							\
									\
	if (!capable(CAP_SYS_ADMIN))					\
		return -EPERM;						\
									\
	rb = snprintf(page, PAGE_SIZE, "%d\n", auth->name);		\
	return rb;							\
}

CONFIGFS_EATTR_STRUCT(iscsi_node_auth, iscsi_node_auth_s);
#define AUTH_ATTR(_name, _mode)						\
static struct iscsi_node_auth_attribute iscsi_node_auth_##_name =	\
		__CONFIGFS_EATTR(_name, _mode,				\
		lio_target_show_nacl_auth_##_name,			\
		lio_target_store_nacl_auth_##_name);

#define AUTH_ATTR_RO(_name)						\
static struct iscsi_node_auth_attribute iscsi_node_auth_##_name =	\
		__CONFIGFS_EATTR_RO(_name,				\
		lio_target_show_nacl_auth_##_name);
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

CONFIGFS_EATTR_OPS(iscsi_node_auth, iscsi_node_auth_s, auth_attrib_group);

static struct configfs_attribute *lio_target_nacl_auth_attrs[] = {
	&iscsi_node_auth_userid.attr,
	&iscsi_node_auth_password.attr,
	&iscsi_node_auth_authenticate_target.attr,
	&iscsi_node_auth_userid_mutual.attr,
	&iscsi_node_auth_password_mutual.attr,
	NULL,
};

static struct configfs_item_operations lio_target_nacl_auth_ops = {
	.show_attribute		= iscsi_node_auth_attr_show,
	.store_attribute	= iscsi_node_auth_attr_store,
};

static struct config_item_type lio_target_nacl_auth_cit = {
	.ct_item_ops	= &lio_target_nacl_auth_ops,
	.ct_attrs	= lio_target_nacl_auth_attrs,
	.ct_owner	= THIS_MODULE,
};

/* End items for lio_target_nacl_auth_cit */

/* Start items for lio_target_nacl_param_cit */

#define DEF_NACL_PARAM(name)						\
static ssize_t lio_target_show_nacl_param_##name(			\
	struct se_node_acl_s *se_nacl,					\
	char *page)							\
{									\
	iscsi_session_t *sess;						\
	se_session_t *se_sess;						\
	ssize_t rb;							\
									\
	spin_lock_bh(&se_nacl->nacl_sess_lock);				\
	se_sess = se_nacl->nacl_sess;					\
	if (!(se_sess)) {						\
		rb = snprintf(page, PAGE_SIZE,				\
			"No Active iSCSI Session\n");			\
	} else {							\
		sess = (iscsi_session_t *)se_sess->fabric_sess_ptr;	\
		rb = snprintf(page, PAGE_SIZE, "%u\n",			\
			(u32)SESS_OPS(sess)->name);			\
	}								\
	spin_unlock_bh(&se_nacl->nacl_sess_lock);			\
									\
	return rb;							\
}

CONFIGFS_EATTR_STRUCT(iscsi_nacl_param, se_node_acl_s);
#define NACL_PARAM_ATTR(_name)						\
static struct iscsi_nacl_param_attribute iscsi_nacl_param_##_name =	\
		__CONFIGFS_EATTR_RO(_name,				\
		lio_target_show_nacl_param_##_name);			\

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

CONFIGFS_EATTR_OPS_RO(iscsi_nacl_param, se_node_acl_s, acl_param_group);

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

static struct configfs_item_operations lio_target_nacl_param_ops = {
	.show_attribute		= iscsi_nacl_param_attr_show,
	.store_attribute	= NULL,
};

static struct config_item_type lio_target_nacl_param_cit = {
	.ct_item_ops	= &lio_target_nacl_param_ops,
	.ct_attrs	= lio_target_nacl_param_attrs,
	.ct_owner	= THIS_MODULE,
};

/* End items for lio_target_nacl_param_cit */

/* Start items for lio_target_initiator_cit */

static int lio_target_initiator_lacl_link(
	struct config_item *lun_acl_ci,
	struct config_item *lun_ci)
{
	iscsi_portal_group_t *tpg;
	iscsi_tiqn_t *tiqn;
	se_dev_entry_t *deve;
	se_lun_t *lun;
	se_lun_acl_t *lacl;
	struct config_item *nacl_ci, *tpg_ci, *tpg_ci_s, *tiqn_ci, *tiqn_ci_s;
	int ret = 0, lun_access;

	nacl_ci = &lun_acl_ci->ci_parent->ci_group->cg_item;
	if (!(nacl_ci)) {
		printk(KERN_ERR "Unable to locate config_item nacl_ci\n");
		return -EINVAL;
	}
	tpg_ci = &nacl_ci->ci_group->cg_item;
	if (!(tpg_ci)) {
		printk(KERN_ERR "Unable to locate config_item tpg_ci\n");
		return -EINVAL;
	}
	tiqn_ci = &tpg_ci->ci_group->cg_item;
	if (!(tiqn_ci)) {
		printk(KERN_ERR "Unable to locate config_item tiqn_ci\n");
		return -EINVAL;
	}
	tpg_ci_s = &lun_ci->ci_parent->ci_group->cg_item;
	if (!(tpg_ci_s)) {
		printk(KERN_ERR "Unable to locate config_item tpg_ci_s\n");
		return -EINVAL;
	}
	tiqn_ci_s = &tpg_ci_s->ci_group->cg_item;
	if (!(tiqn_ci_s)) {
		printk(KERN_ERR "Unable to locate config_item tiqn_ci_s\n");
		return -EINVAL;
	}

	/*
	 * Make sure the SymLink is going to the same iscsi/$IQN/$TPGT
	 */
	if (strcmp(config_item_name(tiqn_ci), config_item_name(tiqn_ci_s))) {
		printk(KERN_ERR "Illegal Initiator ACL SymLink outside of %s\n",
			config_item_name(tiqn_ci));
		return -EINVAL;
	}
	if (strcmp(config_item_name(tpg_ci), config_item_name(tpg_ci_s))) {
		printk(KERN_ERR "Illegal Initiator ACL Symlink outside of %s"
			" TPGT: %s\n", config_item_name(tiqn_ci),
			config_item_name(tpg_ci));
		return -EINVAL;
	}
	/*
	 * Now that we have validated the iscsi/$IQN/$TPGT patch,
	 * grab the se_lun_t
	 */
	lacl = container_of(to_config_group(lun_acl_ci), se_lun_acl_t,
			se_lun_group);
	if (!(lacl)) {
		printk(KERN_ERR "Unable to locate se_lun_acl_t\n");
		return -EINVAL;
	}
	lun = container_of(to_config_group(lun_ci), se_lun_t, lun_group);
	if (!(lun)) {
		printk(KERN_ERR "Unable to locate se_lun_t\n");
		return -EINVAL;
	}

	tpg = lio_get_tpg_from_tpg_item(tpg_ci, &tiqn);
	if (!(tpg))
		return -EINVAL;

	/*
	 * If this iscsi_node_acl was dynamically generated with
	 * tpg_1/attrib/generate_node_acls=1, use the existing deve->lun_flags,
	 * which be will write protected (READ-ONLY) when
	 * tpg_1/attrib/demo_mode_write_protect=1
	 */
	spin_lock_bh(&lacl->se_lun_nacl->device_list_lock);
	deve = &lacl->se_lun_nacl->device_list[lacl->mapped_lun];
	if (deve->lun_flags & TRANSPORT_LUNFLAGS_INITIATOR_ACCESS)
		lun_access = deve->lun_flags;
	else
		lun_access = (ISCSI_TPG_ATTRIB(tpg)->prod_mode_write_protect) ?
			TRANSPORT_LUNFLAGS_READ_ONLY :
			TRANSPORT_LUNFLAGS_READ_WRITE;
	spin_unlock_bh(&lacl->se_lun_nacl->device_list_lock);

	/*
	 * Determine the actual mapped LUN value user wants..
	 *
	 * This value is what the iSCSI Initiator actually sees the
	 * iscsi/$IQN/$TPGT/lun/lun_* as on their iSCSI Initiator Ports.
	 */
	ret = core_dev_add_initiator_node_lun_acl(tpg->tpg_se_tpg, lacl,
				lun->unpacked_lun, lun_access);
	if (ret < 0)
		goto out;

	printk(KERN_INFO "LIO_Target_ConfigFS: Created Initiator LUN ACL"
		" Symlink: %s TPG LUN: %s Mapped LUN: %s Write Protect: %s\n",
		lacl->initiatorname, config_item_name(lun_ci),
		config_item_name(lun_acl_ci),
		(lun_access & TRANSPORT_LUNFLAGS_READ_ONLY) ? "ON" : "OFF");

	iscsi_put_tpg(tpg);
	return 0;
out:
	iscsi_put_tpg(tpg);
	return ret;
}

static int lio_target_initiator_lacl_unlink(
	struct config_item *lun_acl_ci,
	struct config_item *lun_ci)
{
	iscsi_portal_group_t *tpg;
	iscsi_tiqn_t *tiqn;
	se_lun_t *lun;
	se_lun_acl_t *lacl;
	struct config_item *nacl_ci, *tpg_ci, *tiqn_ci;
	int ret = 0;

	nacl_ci = &lun_acl_ci->ci_parent->ci_group->cg_item;
	if (!(nacl_ci)) {
		printk(KERN_ERR "Unable to locate config_item nacl_ci\n");
		return -EINVAL;
	}
	tpg_ci = &nacl_ci->ci_group->cg_item;
	if (!(tpg_ci)) {
		printk(KERN_ERR "Unable to locate config_item tpg_ci\n");
		return -EINVAL;
	}
	tiqn_ci = &tpg_ci->ci_group->cg_item;
	if (!(tiqn_ci)) {
		printk(KERN_ERR "Unable to locate config_item tiqn_ci\n");
		return -EINVAL;
	}
	lacl = container_of(to_config_group(lun_acl_ci), se_lun_acl_t,
			se_lun_group);
	if (!(lacl)) {
		printk(KERN_ERR "Unable to locate se_lun_acl_t\n");
		return -EINVAL;
	}
	lun = container_of(to_config_group(lun_ci), se_lun_t, lun_group);
	if (!(lun)) {
		printk(KERN_ERR "Unable to locate se_lun_t\n");
		return -EINVAL;
	}

	tpg = lio_get_tpg_from_tpg_item(tpg_ci, &tiqn);
	if (!(tpg))
		return -EINVAL;

	ret = core_dev_del_initiator_node_lun_acl(tpg->tpg_se_tpg, lun, lacl);
	if (ret < 0)
		goto out;

	printk(KERN_INFO "LIO_Target_ConfigFS: Removed Initiator LUN ACL"
		" Symlink: %s TPG LUN: %s Mapped LUN: %s\n",
		lacl->initiatorname, config_item_name(lun_acl_ci),
		config_item_name(lun_ci));

	iscsi_put_tpg(tpg);
	return 0;
out:
	iscsi_put_tpg(tpg);
	return ret;
}

/*
 * Define the LUN ACL Attributes using configfs extended attributes.
 */
CONFIGFS_EATTR_STRUCT(lio_target_lacl, se_lun_acl_s);
#define LACL_ATTR(_name, _mode)					\
static struct lio_target_lacl_attribute lacl_attrib_##_name =	\
	__CONFIGFS_EATTR(_name, _mode,				\
	lacl_show_attrib_##_name,				\
	lacl_store_attrib_##_name);

static ssize_t lacl_show_attrib_write_protect(
	struct se_lun_acl_s *lacl,
	char *page)
{
	se_node_acl_t *nacl = lacl->se_lun_nacl;
	se_dev_entry_t *deve;
	ssize_t len;

	spin_lock_bh(&nacl->device_list_lock);
	deve = &nacl->device_list[lacl->mapped_lun];
	len = sprintf(page, "%d\n",
			(deve->lun_flags & TRANSPORT_LUNFLAGS_READ_ONLY) ?
			1 : 0);
	spin_unlock_bh(&nacl->device_list_lock);

	return len;
}

static ssize_t lacl_store_attrib_write_protect(
	struct se_lun_acl_s *lacl,
	const char *page,
	size_t count)
{
	char *endptr;
	u32 op;

	op = simple_strtoul(page, &endptr, 0);
	if ((op != 1) && (op != 0)) {
		printk(KERN_ERR "Illegal value for access: %u\n", op);
		return -EINVAL;
	}
	core_update_device_list_access(lacl->mapped_lun, (op) ?
			TRANSPORT_LUNFLAGS_READ_ONLY :
			TRANSPORT_LUNFLAGS_READ_WRITE,
			lacl->se_lun_nacl);

	printk(KERN_INFO "LIO_Target_ConfigFS: Changed Initiator ACL: %s"
		" Mapped LUN: %u Write Protect bit to %s\n",
		lacl->initiatorname, lacl->mapped_lun, (op) ? "ON" : "OFF");

	return count;
}

LACL_ATTR(write_protect, S_IRUGO | S_IWUSR);

CONFIGFS_EATTR_OPS(lio_target_lacl, se_lun_acl_s, se_lun_group)

static struct configfs_attribute *lio_target_initiator_lacl_attrs[] = {
	&lacl_attrib_write_protect.attr,
	NULL,
};

static struct configfs_item_operations lio_target_initiator_lacl_item_ops = {
	.show_attribute		= lio_target_lacl_attr_show,
	.store_attribute	= lio_target_lacl_attr_store,
	.allow_link		= lio_target_initiator_lacl_link,
	.drop_link		= lio_target_initiator_lacl_unlink,
};

static struct config_item_type lio_target_initiator_lacl_cit = {
	.ct_item_ops		= &lio_target_initiator_lacl_item_ops,
	.ct_attrs		= lio_target_initiator_lacl_attrs,
	.ct_owner		= THIS_MODULE,
};

static struct config_group *lio_target_initiator_lacl_make_group(
	struct config_group *group,
	const char *name)
{
	iscsi_portal_group_t *tpg;
	iscsi_tiqn_t *tiqn;
	se_lun_acl_t *lacl;
	struct config_item *acl_ci, *tpg_ci, *tiqn_ci;
	char *buf, *endptr, *ptr;
	u32 mapped_lun;
	int ret = 0;

	acl_ci = &group->cg_item;
	if (!(acl_ci)) {
		printk(KERN_ERR "Unable to locatel acl_ci\n");
		return NULL;
	}
	tpg_ci = &acl_ci->ci_parent->ci_group->cg_item;
	if (!(tpg_ci)) {
		printk(KERN_ERR "Unable to locate tpg_ci\n");
		return NULL;
	}
	tiqn_ci = &tpg_ci->ci_group->cg_item;
	if (!(tiqn_ci)) {
		printk(KERN_ERR "Unable to locate config_item tiqn_ci\n");
		return NULL;
	}

	tpg = lio_get_tpg_from_tpg_item(tpg_ci, &tiqn);
	if (!(tpg))
		return NULL;

	buf = kzalloc(strlen(name) + 1, GFP_KERNEL);
	if (!(buf)) {
		printk(KERN_ERR "Unable to allocate memory for name buf\n");
		goto out;
	}
	snprintf(buf, strlen(name) + 1, "%s", name);
	/*
	 * Make sure user is creating iscsi/$IQN/$TPGT/acls/$INITIATOR/lun_$ID.
	 */
	ptr = strstr(buf, "lun_");
	if (!(ptr)) {
		printk(KERN_ERR "Unable to locate \"lun_\" from buf: %s"
			" name: %s\n", buf, name);
		goto out;
	}
	ptr += 3; /* Skip to "_" */
	*ptr = '\0'; /* Terminate the string */
	ptr++; /* Advance pointer to next characater */

	/*
	 * Determine the Mapped LUN value.  This is what the iSCSI Initiator
	 * will actually see.
	 */
	mapped_lun = simple_strtoul(ptr, &endptr, 0);

	lacl = core_dev_init_initiator_node_lun_acl(tpg->tpg_se_tpg,
			mapped_lun, config_item_name(acl_ci), &ret);
	if (!(lacl))
		goto out;

	config_group_init_type_name(&lacl->se_lun_group, name,
			&lio_target_initiator_lacl_cit);

	printk(KERN_INFO "LIO_Target_ConfigFS: Initialized Initiator LUN ACL:"
		" %s Mapped LUN: %s\n", config_item_name(acl_ci), name);

	kfree(buf);
	iscsi_put_tpg(tpg);
	return &lacl->se_lun_group;
out:
	kfree(buf);
	iscsi_put_tpg(tpg);
	return NULL;
}

static void lio_target_initiator_lacl_drop_item(
	struct config_group *group,
	struct config_item *item)
{
	iscsi_portal_group_t *tpg;
	iscsi_tiqn_t *tiqn;
	se_lun_acl_t *lacl;
	struct config_item *acl_ci, *tpg_ci, *tiqn_ci;

	acl_ci = &group->cg_item;
	if (!(acl_ci)) {
		printk(KERN_ERR "Unable to locatel acl_ci\n");
		return;
	}
	tpg_ci = &acl_ci->ci_parent->ci_group->cg_item;
	if (!(tpg_ci)) {
		printk(KERN_ERR "Unable to locate tpg_ci\n");
		return;
	}
	tiqn_ci = &tpg_ci->ci_group->cg_item;
	if (!(tiqn_ci)) {
		printk(KERN_ERR "Unable to locate config_item tiqn_ci\n");
		return;
	}

	lacl = container_of(to_config_group(item), se_lun_acl_t,
				se_lun_group);
	if (!(lacl)) {
		printk(KERN_ERR "Unable to locate se_lun_acl_t\n");
		return;
	}

	tpg = lio_get_tpg_from_tpg_item(tpg_ci, &tiqn);
	if (!(tpg))
		return;

	printk(KERN_INFO "LIO_Target_ConfigFS: Freeing Initiator LUN ACL:"
		" %s Mapped LUN: %s\n", lacl->initiatorname,
		config_item_name(item));

	config_item_put(item);

	core_dev_free_initiator_node_lun_acl(tpg->tpg_se_tpg, lacl);
	iscsi_put_tpg(tpg);
}

static ssize_t lio_target_initiator_nacl_info(void *p, char *page)
{
	iscsi_session_t *sess;
	iscsi_conn_t *conn;
	se_node_acl_t *se_nacl = (se_node_acl_t *)p;
	se_session_t *se_sess;
	unsigned char *ip, buf_ipv4[IPV4_BUF_SIZE];
	ssize_t rb = 0;

	spin_lock_bh(&se_nacl->nacl_sess_lock);
	se_sess = se_nacl->nacl_sess;
	if (!(se_sess))
		rb += sprintf(page+rb, "No active iSCSI Session for Initiator"
			" Endpoint: %s\n", se_nacl->initiatorname);
	else {
		sess = (iscsi_session_t *)se_sess->fabric_sess_ptr;

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

static struct lio_target_configfs_attribute lio_target_attr_initiator_info = {
	.attr	= { .ca_owner = THIS_MODULE,
		    .ca_name = "info",
		    .ca_mode = S_IRUGO },
	.show	= lio_target_initiator_nacl_info,
	.store	= NULL,
};

static ssize_t lio_target_initiator_nacl_cmdsn_window_show(void *p, char *page)
{
	se_node_acl_t *se_nacl = (se_node_acl_t *)p;

	return sprintf(page, "%u\n", se_nacl->queue_depth);
}

static ssize_t lio_target_initiator_nacl_cmdsn_window_store(
	void *p,
	const char *page,
	size_t count)
{
	iscsi_portal_group_t *tpg;
	iscsi_tiqn_t *tiqn;
	se_node_acl_t *se_nacl = (se_node_acl_t *)p;
	struct config_item *acl_ci, *tpg_ci, *tiqn_ci;
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
	tiqn_ci = &tpg_ci->ci_group->cg_item;
	if (!(tiqn_ci)) {
		printk(KERN_ERR "Unable to locate config_item tiqn_ci\n");
		return -EINVAL;
	}

	tpg = lio_get_tpg_from_tpg_item(tpg_ci, &tiqn);
	if (!(tpg))
		return -EINVAL;

	/*
	 * iscsi_tpg_set_initiator_node_queue_depth() assumes force=1
	 */
	ret = iscsi_tpg_set_initiator_node_queue_depth(tpg,
				config_item_name(acl_ci), cmdsn_depth, 1);

	printk(KERN_INFO "LIO_Target_ConfigFS: %s/%s Set CmdSN Window: %u for"
		"InitiatorName: %s\n", config_item_name(tiqn_ci),
		config_item_name(tpg_ci), cmdsn_depth,
		config_item_name(acl_ci));

	iscsi_put_tpg(tpg);
	return (!ret) ? count : (ssize_t)ret;
}

static struct lio_target_configfs_attribute
				lio_target_attr_initiator_control = {
	.attr	= { .ca_owner = THIS_MODULE,
		    .ca_name = "cmdsn_depth",
		    .ca_mode = S_IRUGO | S_IWUSR },
	.show	= lio_target_initiator_nacl_cmdsn_window_show,
	.store	= lio_target_initiator_nacl_cmdsn_window_store,
};

static void lio_target_initiator_nacl_release(struct config_item *item)
{
	se_node_acl_t *se_nacl = container_of(
			to_config_group(item), se_node_acl_t, acl_group);
	struct config_group *nacl_cg;

	if (!(se_nacl))
		return;

	nacl_cg = &se_nacl->acl_group;
	kfree(nacl_cg->default_groups);
}

static ssize_t lio_target_initiator_nacl_show(
	struct config_item *item,
	struct configfs_attribute *attr,
	char *page)
{
	se_node_acl_t *se_nacl = container_of(
			to_config_group(item), se_node_acl_t, acl_group);
	struct lio_target_configfs_attribute *lt_attr = container_of(
			attr, struct lio_target_configfs_attribute, attr);

	if (!(lt_attr->show))
		return -EINVAL;

	return lt_attr->show((void *)se_nacl, page);
}

static ssize_t lio_target_initiator_nacl_store(
	struct config_item *item,
	struct configfs_attribute *attr,
	const char *page,
	size_t count)
{
	se_node_acl_t *se_nacl = container_of(
			to_config_group(item), se_node_acl_t, acl_group);
	struct lio_target_configfs_attribute *lt_attr = container_of(
			attr, struct lio_target_configfs_attribute, attr);

	if (!(lt_attr->store))
		return -EINVAL;

	return lt_attr->store((void *)se_nacl, page, count);
}

static struct configfs_attribute *lio_target_initiator_attrs[] = {
	&lio_target_attr_initiator_info.attr,
	&lio_target_attr_initiator_control.attr,
	NULL,
};

static struct configfs_item_operations lio_target_initiator_item_ops = {
	.release		= lio_target_initiator_nacl_release,
	.show_attribute		= lio_target_initiator_nacl_show,
	.store_attribute	= lio_target_initiator_nacl_store,
};

static struct configfs_group_operations lio_target_initiator_group_ops = {
	.make_group		= lio_target_initiator_lacl_make_group,
	.drop_item		= lio_target_initiator_lacl_drop_item,
};

static struct config_item_type lio_target_initiator_cit = {
	.ct_item_ops		= &lio_target_initiator_item_ops,
	.ct_group_ops		= &lio_target_initiator_group_ops,
	.ct_attrs		= lio_target_initiator_attrs,
	.ct_owner		= THIS_MODULE,
};

/* End items for lio_target_initiator_cit */

/* Start items for lio_target_acl_cit */

static struct config_group *lio_target_call_addnodetotpg(
	struct config_group *group,
	const char *name)
{
	iscsi_node_acl_t *acl;
	iscsi_node_attrib_t *nattr;
	iscsi_node_auth_t *auth;
	iscsi_portal_group_t *tpg;
	iscsi_tiqn_t *tiqn;
	se_node_acl_t *se_nacl;
	struct config_group *nacl_cg;
	struct config_item *acl_ci, *tpg_ci, *tiqn_ci;
	u32 cmdsn_depth;

	acl_ci = &group->cg_item;
	if (!(acl_ci)) {
		printk(KERN_ERR "Unable to locate config_item acl_ci_ci\n");
		return NULL;
	}
	tpg_ci = &acl_ci->ci_group->cg_item;
	if (!(tpg_ci)) {
		printk(KERN_ERR "Unable to locate config_item tpg_ci\n");
		return NULL;
	}
	tiqn_ci = &tpg_ci->ci_group->cg_item;
	if (!(tiqn_ci)) {
		printk(KERN_ERR "Unable to locate config_item tiqn_ci\n");
		return NULL;
	}

	tpg = lio_get_tpg_from_tpg_item(tpg_ci, &tiqn);
	if (!(tpg))
		return NULL;
	/*
	 * ISCSI_TPG_ATTRIB(tpg)->default_cmdsn is used for the default.
	 * This can be changed in either with or without an active session.
	 * $FABRIC/$IQN/$TPGT/acl/$INITIATOR_IQN/cmdsn_depth
	 */
	cmdsn_depth = ISCSI_TPG_ATTRIB(tpg)->default_cmdsn_depth;

	acl = iscsi_tpg_add_initiator_node_acl(tpg, name, cmdsn_depth);
	if (!(acl))
		goto out;

	se_nacl = acl->se_node_acl;
	nacl_cg = &se_nacl->acl_group;
	nattr = &acl->node_attrib;
	auth = &acl->node_auth;

	/*
	 * Create the default groups for iscsi_node_acl_t
	 */
	nacl_cg->default_groups = kzalloc(sizeof(struct config_group) * 4,
			GFP_KERNEL);
	if (!(nacl_cg->default_groups))
		goto node_out;

	config_group_init_type_name(&se_nacl->acl_group, name,
			&lio_target_initiator_cit);
	config_group_init_type_name(&se_nacl->acl_param_group, "param",
			&lio_target_nacl_param_cit);
	config_group_init_type_name(&nattr->acl_attrib_group, "attrib",
			&lio_target_nacl_attrib_cit);
	config_group_init_type_name(&auth->auth_attrib_group, "auth",
			&lio_target_nacl_auth_cit);
	nacl_cg->default_groups[0] = &se_nacl->acl_param_group;
	nacl_cg->default_groups[1] = &nattr->acl_attrib_group;
	nacl_cg->default_groups[2] = &auth->auth_attrib_group;
	nacl_cg->default_groups[3] = NULL;

	printk(KERN_INFO "LIO_Target_ConfigFS: REGISTER -> %s TPGT: %hu"
		" Initiator: %s CmdSN Depth: %u\n", config_item_name(tiqn_ci),
		tpg->tpgt, name, se_nacl->queue_depth);

	iscsi_put_tpg(tpg);
	return &se_nacl->acl_group;
node_out:
	iscsi_tpg_del_initiator_node_acl(tpg, se_nacl);
out:
	iscsi_put_tpg(tpg);
	return NULL;
}

static void lio_target_call_delnodefromtpg(
	struct config_group *group,
	struct config_item *item)
{
	iscsi_portal_group_t *tpg;
	iscsi_tiqn_t *tiqn;
	se_node_acl_t *se_nacl = container_of(to_config_group(item),
				se_node_acl_t, acl_group);
	struct config_item *acl_ci, *tpg_ci, *tiqn_ci, *df_item;
	struct config_group *nacl_cg;
	int i;

	acl_ci = &group->cg_item;
	if (!(acl_ci)) {
		printk(KERN_ERR "Unable to locate config_item acl_ci_ci\n");
		return;
	}
	tpg_ci = &acl_ci->ci_group->cg_item;
	if (!(tpg_ci)) {
		printk(KERN_ERR "Unable to locate config_item tpg_ci\n");
		return;
	}
	tiqn_ci = &tpg_ci->ci_group->cg_item;
	if (!(tiqn_ci)) {
		printk(KERN_ERR "Unable to locate config_item tiqn_ci\n");
		return;
	}

	tpg = lio_get_tpg_from_tpg_item(tpg_ci, &tiqn);
	if (!(tpg))
		return;

	printk(KERN_INFO "LIO_Target_ConfigFS: DEREGISTER -> %s TPGT: %hu"
		" Initiator: %s\n", config_item_name(tiqn_ci), tpg->tpgt,
		config_item_name(item));

	nacl_cg = &se_nacl->acl_group;
	for (i = 0; nacl_cg->default_groups[i]; i++) {
		df_item = &nacl_cg->default_groups[i]->cg_item;
		nacl_cg->default_groups[i] = NULL;
		config_item_put(df_item);
	}

	config_item_put(item);

	iscsi_tpg_del_initiator_node_acl(tpg, se_nacl);
	iscsi_put_tpg(tpg);
}

static struct configfs_group_operations lio_target_acl_group_ops = {
	.make_group	= lio_target_call_addnodetotpg,
	.drop_item	= lio_target_call_delnodefromtpg,
};

static struct config_item_type lio_target_acl_cit = {
	.ct_item_ops	= NULL,
	.ct_group_ops	= &lio_target_acl_group_ops,
	.ct_attrs	= NULL,
	.ct_owner	= THIS_MODULE,
};

/* End items for lio_target_acl_cit */

/* Start items for lio_target_tpg_attrib_cit */

#define DEF_TPG_ATTRIB(name)						\
									\
static ssize_t lio_target_show_tpg_attrib_##name(			\
	struct iscsi_tpg_attrib_s *ta,					\
	char *page)							\
{									\
	iscsi_portal_group_t *tpg;					\
	iscsi_tiqn_t *tiqn;						\
	ssize_t rb;							\
									\
	tpg = lio_get_tpg_from_tpg_item(				\
			&ta->tpg->tpg_se_tpg->tpg_group.cg_item, &tiqn); \
	if (!(tpg))							\
		return -EINVAL;						\
									\
	rb = sprintf(page, "%u\n", ISCSI_TPG_ATTRIB(tpg)->name);	\
	iscsi_put_tpg(tpg);						\
	return rb;							\
}									\
									\
static ssize_t lio_target_store_tpg_attrib_##name(			\
	struct iscsi_tpg_attrib_s *ta,					\
	const char *page,						\
	size_t count)							\
{									\
	iscsi_portal_group_t *tpg = ta->tpg;				\
	iscsi_tiqn_t *tiqn;						\
	char *endptr;							\
	u32 val;							\
	int ret;							\
									\
	tpg = lio_get_tpg_from_tpg_item(				\
			&ta->tpg->tpg_se_tpg->tpg_group.cg_item, &tiqn); \
	if (!(tpg))							\
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

/*
 * Define the iSCSI TPG attributes using hybrid wrappers from
 * include/linux/configfs.h
 */
CONFIGFS_EATTR_STRUCT(iscsi_tpg_attrib, iscsi_tpg_attrib_s);
#define TPG_ATTR(_name, _mode)						\
static struct iscsi_tpg_attrib_attribute iscsi_tpg_attrib_##_name =	\
	__CONFIGFS_EATTR(_name, _mode,					\
		lio_target_show_tpg_attrib_##_name,			\
		lio_target_store_tpg_attrib_##_name);

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

/*
 * Finally, define functions iscsi_tpg_attrib_s_attr_show() and
 * iscsi_tpg_attrib_s_attr_store() for lio_target_tpg_attrib_ops below..
 */
CONFIGFS_EATTR_OPS(iscsi_tpg_attrib, iscsi_tpg_attrib_s, tpg_attrib_group);

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

static struct configfs_item_operations lio_target_tpg_attrib_ops = {
	.show_attribute		= iscsi_tpg_attrib_attr_show,
	.store_attribute	= iscsi_tpg_attrib_attr_store,
};

static struct config_item_type lio_target_tpg_attrib_cit = {
	.ct_item_ops	= &lio_target_tpg_attrib_ops,
	.ct_attrs	= lio_target_tpg_attrib_attrs,
	.ct_owner	= THIS_MODULE,
};

/* End items for lio_target_tpg_attrib_cit */

/* Start items for lio_target_tpg_param_cit */

#define DEF_TPG_PARAM(name)						\
static ssize_t lio_target_show_tpg_param_##name(			\
	struct iscsi_portal_group_s *tpg_p,				\
	char *page)							\
{									\
	iscsi_portal_group_t *tpg;					\
	iscsi_tiqn_t *tiqn;						\
	iscsi_param_t *param;						\
	ssize_t rb;							\
									\
	tpg = lio_get_tpg_from_tpg_item(				\
			&tpg_p->tpg_se_tpg->tpg_group.cg_item, &tiqn);	\
	if (!(tpg))							\
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
static ssize_t lio_target_store_tpg_param_##name(			\
	struct iscsi_portal_group_s *tpg_p,				\
	const char *page,						\
	size_t count)							\
{									\
	iscsi_portal_group_t *tpg;					\
	iscsi_tiqn_t *tiqn;						\
	char *buf;							\
	int ret;							\
									\
	buf = kzalloc(PAGE_SIZE, GFP_KERNEL);				\
	if (!(buf))							\
		return -ENOMEM;						\
	snprintf(buf, PAGE_SIZE, "%s=%s", __stringify(name), page);	\
	buf[strlen(buf)-1] = '\0'; /* Kill newline */			\
									\
	tpg = lio_get_tpg_from_tpg_item(				\
			&tpg_p->tpg_se_tpg->tpg_group.cg_item, &tiqn);	\
	if (!(tpg)) {							\
		kfree(buf);						\
		return -EINVAL;						\
	}								\
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

CONFIGFS_EATTR_STRUCT(iscsi_tpg_param, iscsi_portal_group_s);
#define TPG_PARAM_ATTR(_name, _mode)					\
static struct iscsi_tpg_param_attribute iscsi_tpg_param_##_name =	\
	__CONFIGFS_EATTR(_name, _mode,					\
		lio_target_show_tpg_param_##_name,			\
		lio_target_store_tpg_param_##_name)

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

CONFIGFS_EATTR_OPS(iscsi_tpg_param, iscsi_portal_group_s, tpg_param_group);

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

static struct configfs_item_operations lio_target_tpg_param_ops = {
	.show_attribute		= iscsi_tpg_param_attr_show,
	.store_attribute	= iscsi_tpg_param_attr_store,
};

static struct config_item_type lio_target_tpg_param_cit = {
	.ct_item_ops	= &lio_target_tpg_param_ops,
	.ct_attrs	= lio_target_tpg_param_attrs,
	.ct_owner	= THIS_MODULE,
};

/* End items for lio_target_tpg_param_cit */

/* Start items for lio_target_tpg_cit */

static ssize_t lio_target_store_tpg_control(
	void *p,
	const char *page,
	size_t count)
{
	iscsi_portal_group_t *tpg = (iscsi_portal_group_t *)p;

	printk(KERN_INFO "lio_target_store_tpg_control(): tpg: %p %s\n",
			tpg, page);
	return count;
}

static struct lio_target_configfs_attribute lio_target_attr_tpg_control = {
	.attr	= { .ca_owner = THIS_MODULE,
		    .ca_name = "control",
		    .ca_mode = S_IWUSR },
	.show	= NULL,
	.store	= lio_target_store_tpg_control,
};

static ssize_t lio_target_show_tpg_enable(void *p, char *page)
{
	iscsi_portal_group_t *tpg = (iscsi_portal_group_t *)p;
	ssize_t len = 0;

	spin_lock(&tpg->tpg_state_lock);
	len = sprintf(page, "%d\n",
			(tpg->tpg_state == TPG_STATE_ACTIVE) ? 1 : 0);
	spin_unlock(&tpg->tpg_state_lock);

	return len;
}

static ssize_t lio_target_store_tpg_enable(
	void *p,
	const char *page,
	size_t count)
{
	iscsi_portal_group_t *tpg_p = (iscsi_portal_group_t *)p, *tpg;
	iscsi_tiqn_t *tiqn;
	struct config_item *tpg_ci, *tiqn_ci;
	char *endptr;
	u32 op;
	int ret = 0;

	op = simple_strtoul(page, &endptr, 0);
	if ((op != 1) && (op != 0)) {
		printk(KERN_ERR "Illegal value for tpg_enable: %u\n", op);
		return -EINVAL;
	}

	tpg_ci = &tpg_p->tpg_se_tpg->tpg_group.cg_item;
	if (!(tpg_ci)) {
		printk(KERN_ERR "Unable to locate tpg_ci\n");
		return -EINVAL;
	}

	tiqn_ci = &tpg_ci->ci_group->cg_item;
	if (!(tiqn_ci)) {
		printk(KERN_ERR "Unable to locate config_item tiqn_ci\n");
		return -EINVAL;
	}

	tpg = lio_get_tpg_from_tpg_item(tpg_ci, &tiqn);
	if (!(tpg))
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

static struct lio_target_configfs_attribute lio_target_attr_tpg_enable = {
	.attr	= { .ca_owner = THIS_MODULE,
		    .ca_name = "enable",
		    .ca_mode = S_IRUGO | S_IWUSR },
	.show	= lio_target_show_tpg_enable,
	.store	= lio_target_store_tpg_enable,
};

static struct configfs_attribute *lio_target_tpg_attrs[] = {
	&lio_target_attr_tpg_control.attr,
	&lio_target_attr_tpg_enable.attr,
	NULL,
};

static void lio_target_tpg_release(struct config_item *item)
{
	se_portal_group_t *se_tpg = container_of(to_config_group(item),
				se_portal_group_t, tpg_group);
	struct config_group *tpg_cg;

	if (!(se_tpg))
		return;

	tpg_cg = &se_tpg->tpg_group;
	kfree(tpg_cg->default_groups);
}

static ssize_t lio_target_tpg_show(
	struct config_item *item,
	struct configfs_attribute *attr,
	char *page)
{
	se_portal_group_t *se_tpg = container_of(
			to_config_group(item), se_portal_group_t, tpg_group);
	iscsi_portal_group_t *tpg =
		(iscsi_portal_group_t *)se_tpg->se_tpg_fabric_ptr;
	struct lio_target_configfs_attribute *lt_attr = container_of(attr,
			struct lio_target_configfs_attribute, attr);

	if (!(lt_attr->show))
		return -EINVAL;

	return lt_attr->show((void *)tpg, page);
}

static ssize_t lio_target_tpg_store(
	struct config_item *item,
	struct configfs_attribute *attr,
	const char *page,
	size_t count)
{
	se_portal_group_t *se_tpg = container_of(
			to_config_group(item), se_portal_group_t, tpg_group);
	iscsi_portal_group_t *tpg =
			(iscsi_portal_group_t *)se_tpg->se_tpg_fabric_ptr;
	struct lio_target_configfs_attribute *lt_attr = container_of(
			attr, struct lio_target_configfs_attribute, attr);

	if (!(lt_attr->store))
		return -EINVAL;

	return lt_attr->store((void *)tpg, page, count);
}

static struct configfs_item_operations lio_target_tpg_item_ops = {
	.release		= lio_target_tpg_release,
	.show_attribute		= lio_target_tpg_show,
	.store_attribute	= lio_target_tpg_store,
};

static struct config_item_type lio_target_tpg_cit = {
	.ct_item_ops	= &lio_target_tpg_item_ops,
	.ct_attrs	= lio_target_tpg_attrs,
	.ct_owner	= THIS_MODULE,
};


/* End items for lio_target_tpg_cit */

/* Start items for lio_target_tiqn_cit */

static struct config_group *lio_target_tiqn_addtpg(
	struct config_group *group,
	const char *name)
{
	iscsi_portal_group_t *tpg;
	iscsi_tiqn_t *tiqn;
	iscsi_tpg_attrib_t *tattr;
	struct config_group *tpg_cg;
	struct config_item *tiqn_ci;
	char *tpgt_str, *end_ptr;
	int ret = 0;
	unsigned short int tpgt;

	tiqn_ci = &group->cg_item;
	if (!(tiqn_ci)) {
		printk(KERN_ERR "Unable to locate valid group->cg_item"
			" pointer\n");
		return NULL;
	}
	printk(KERN_INFO "lio_target_tiqn_addtpg() parent name: %s\n",
			config_item_name(tiqn_ci));
	tiqn = container_of(to_config_group(tiqn_ci), iscsi_tiqn_t, tiqn_group);
	if (!(tiqn)) {
		printk(KERN_ERR "Unable to locate iscsi_tiqn_t\n");
		return NULL;
	}
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

	tpg->tpg_se_tpg = core_tpg_register(
			&lio_target_fabric_configfs->tf_ops, (void *)tpg,
			TRANSPORT_TPG_TYPE_NORMAL);
	if (IS_ERR(tpg->tpg_se_tpg))
		return NULL;

	tpg_cg = &tpg->tpg_se_tpg->tpg_group;
	/*
	 * Create default configfs groups for iscsi_portal_group_t..
	 */
	tpg_cg->default_groups = kzalloc(sizeof(struct config_group) * 6,
			GFP_KERNEL);
	if (!(tpg_cg->default_groups))
		goto out;

	tattr = &tpg->tpg_attrib;

	config_group_init_type_name(&tpg->tpg_np_group, "np",
			&lio_target_np_cit);
	config_group_init_type_name(&tpg->tpg_lun_group, "lun",
			&lio_target_lun_cit);
	config_group_init_type_name(&tpg->tpg_acl_group, "acls",
			&lio_target_acl_cit);
	config_group_init_type_name(&tpg->tpg_param_group, "param",
			&lio_target_tpg_param_cit);
	config_group_init_type_name(&tattr->tpg_attrib_group, "attrib",
			&lio_target_tpg_attrib_cit);
	tpg_cg->default_groups[0] = &tpg->tpg_np_group;
	tpg_cg->default_groups[1] = &tpg->tpg_lun_group;
	tpg_cg->default_groups[2] = &tpg->tpg_acl_group;
	tpg_cg->default_groups[3] = &tpg->tpg_param_group;
	tpg_cg->default_groups[4] = &tattr->tpg_attrib_group;
	tpg_cg->default_groups[5] = NULL;

	ret = iscsi_tpg_add_portal_group(tiqn, tpg);
	if (ret != 0)
		goto out;

	printk(KERN_INFO "LIO_Target_ConfigFS: REGISTER -> %s\n", tiqn->tiqn);
	config_group_init_type_name(tpg_cg, name, &lio_target_tpg_cit);
	printk(KERN_INFO "LIO_Target_ConfigFS: REGISTER -> Allocated TPG: %s\n",
			tpg_cg->cg_item.ci_name);

	return tpg_cg;
out:
	if (tpg->tpg_se_tpg)
		core_tpg_deregister(tpg->tpg_se_tpg);
	kfree(tpg_cg->default_groups);
	kmem_cache_free(lio_tpg_cache, tpg);
	return NULL;
}

static void lio_target_tiqn_deltpg(
	struct config_group *group,
	struct config_item *item)
{
	se_portal_group_t *se_tpg;
	iscsi_portal_group_t *tpg;
	iscsi_tiqn_t *tiqn;
	struct config_item *tiqn_ci, *df_item;
	struct config_group *tpg_cg;
	char *tpgt_str, *end_ptr;
	int i;
	unsigned short int tpgt;

	printk(KERN_INFO "LIO_Target_ConfigFS: DEREGISTER -> %s\n",
			config_item_name(item));
	tiqn_ci = &group->cg_item;
	if (!(tiqn_ci)) {
		printk(KERN_ERR "Unable to locate group_cg_item\n");
		return;
	}

	tiqn = container_of(to_config_group(tiqn_ci), iscsi_tiqn_t, tiqn_group);
	if (!(tiqn)) {
		printk(KERN_ERR "Unable to locate iscsi_tiqn_t\n");
		return;
	}

	tpgt_str = strstr(config_item_name(item), "tpgt_");
	if (!(tpgt_str)) {
		printk(KERN_ERR "Unable to locate \"tpgt_#\" directory"
			" group\n");
		return;
	}
	tpgt_str += 5; /* Skip ahead of "tpgt_" */
	tpgt = (unsigned short int) simple_strtoul(tpgt_str, &end_ptr, 0);

	se_tpg = container_of(to_config_group(item), se_portal_group_t,
				tpg_group);
	if (!(se_tpg))
		return;
	tpg = (iscsi_portal_group_t *)se_tpg->se_tpg_fabric_ptr;

	printk(KERN_INFO "lio_target_tiqn_deltpg() got container_of: TPGT:"
			" %hu\n", tpg->tpgt);
	printk(KERN_INFO "LIO_Target_ConfigFS: DEREGISTER -> calling"
			" config_item_put()\n");
	/*
	 * Release the default groups the fabric module is using for
	 * se_portal_group_t->tpg_group.
	 */
	tpg_cg = &tpg->tpg_se_tpg->tpg_group;
	for (i = 0; tpg_cg->default_groups[i]; i++) {
		df_item = &tpg_cg->default_groups[i]->cg_item;
		tpg_cg->default_groups[i] = NULL;
		config_item_put(df_item);
	}

	config_item_put(item);
	/*
	 * iscsi_tpg_del_portal_group() assumes force=1
	 */
	printk(KERN_INFO "LIO_Target_ConfigFS: DEREGISTER -> Releasing TPG\n");
	iscsi_tpg_del_portal_group(tiqn, tpg, 1);
}

static struct configfs_group_operations lio_target_tiqn_group_ops = {
	.make_group	= &lio_target_tiqn_addtpg,
	.drop_item	= &lio_target_tiqn_deltpg,
};

static struct config_item_type lio_target_tiqn_cit = {
	.ct_item_ops	= NULL,
	.ct_group_ops	= &lio_target_tiqn_group_ops,
	.ct_attrs	= NULL,
	.ct_owner	= THIS_MODULE,
};

/* End items for lio_target_tiqn_cit */

/* Start LIO-Target TIQN struct contig_item lio_target_cit */

static ssize_t lio_target_attr_show(
	struct config_item *item,
	struct configfs_attribute *attr,
	char *page)
{
	return sprintf(page, "Linux-iSCSI.org Target "PYX_ISCSI_VERSION""
		" on %s/%s on "UTS_RELEASE"\n", utsname()->sysname,
		utsname()->machine);
}

static struct configfs_item_operations lio_target_item_ops = {
	.show_attribute = lio_target_attr_show,
};

static struct configfs_attribute lio_target_item_attr_version = {
	.ca_owner	= THIS_MODULE,
	.ca_name	= "lio_version",
	.ca_mode	= S_IRUGO,
};

static struct config_group *lio_target_call_coreaddtiqn(
	struct config_group *group,
	const char *name)
{
	iscsi_tiqn_t *tiqn;
	int ret = 0;

	printk(KERN_INFO "lio_target_call_coreaddtiqn(): name: %s\n", name);

	tiqn = core_add_tiqn((unsigned char *)name, &ret);
	if (!(tiqn))
		return NULL;

	printk(KERN_INFO "LIO_Target_ConfigFS: REGISTER -> %s\n", tiqn->tiqn);
	config_group_init_type_name(&tiqn->tiqn_group, tiqn->tiqn,
			&lio_target_tiqn_cit);
	printk(KERN_INFO "LIO_Target_ConfigFS: REGISTER -> Allocated Node: %s\n",
			tiqn->tiqn_group.cg_item.ci_name);

	return &tiqn->tiqn_group;
}

static void lio_target_call_coredeltiqn(
	struct config_group *group,
	struct config_item *item)
{
	iscsi_tiqn_t *tiqn = container_of(to_config_group(item),
				iscsi_tiqn_t, tiqn_group);

	printk(KERN_INFO "LIO_Target_ConfigFS: DEREGISTER -> %s\n",
			config_item_name(item));
	printk(KERN_INFO "LIO_Target_ConfigFS: DEREGISTER -> calling"
			" config_item_put()\n");
	config_item_put(item);
	printk(KERN_INFO "LIO_Target_ConfigFS: DEREGISTER -> Releasing"
			" core_del_tiqn()\n");
	core_del_tiqn(tiqn);
}

static struct configfs_group_operations lio_target_group_ops = {
	.make_group	= lio_target_call_coreaddtiqn,
	.drop_item	= lio_target_call_coredeltiqn,
};

static struct configfs_attribute *lio_target_attrs[] = {
	&lio_target_item_attr_version,
	NULL,
};

static struct config_item_type lio_target_cit = {
	.ct_item_ops	= &lio_target_item_ops,
	.ct_group_ops	= &lio_target_group_ops,
	.ct_attrs	= lio_target_attrs,
	.ct_owner	= THIS_MODULE,
};

/* End LIO-Target TIQN struct contig_lio_target_cit */

/* Start lio_target_discovery_auth_cit */

CONFIGFS_EATTR_STRUCT(iscsi_discovery_auth, iscsi_node_auth_s);
#define DISC_AUTH_ATTR(_name, _mode)					\
static struct iscsi_node_auth_attribute iscsi_disc_auth_##_name =	\
		__CONFIGFS_EATTR(_name, _mode,				\
		lio_target_show_da_attr_##_name,			\
		lio_target_store_da_attr_##_name);

/*
 * enforce_discovery_auth
 */
static ssize_t lio_target_show_da_attr_enforce_discovery_auth(
	struct iscsi_node_auth_s *auth,
	char *page)
{
	iscsi_node_auth_t *discovery_auth = &iscsi_global->discovery_auth;

	return sprintf(page, "%d\n", discovery_auth->enforce_discovery_auth);
}

static ssize_t lio_target_store_da_attr_enforce_discovery_auth(
	struct iscsi_node_auth_s *auth,
	const char *page,
	size_t count)
{
	iscsi_param_t *param;
	iscsi_portal_group_t *discovery_tpg = iscsi_global->discovery_tpg;
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
		iscsi_global->discovery_auth.enforce_discovery_auth = 1;
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
		iscsi_global->discovery_auth.enforce_discovery_auth = 0;
		printk(KERN_INFO "LIO-CORE[0] Successfully disabled"
			" authentication enforcement for iSCSI"
			" Discovery TPG\n");
	}

	return count;
}

DISC_AUTH_ATTR(enforce_discovery_auth, S_IRUGO | S_IWUSR);

CONFIGFS_EATTR_OPS(iscsi_discovery_auth, iscsi_node_auth_s, auth_attrib_group);

/*
 * Note that we reuse some of the same configfs structure defines for
 * iscsi_node_auth from lio_target_nacl_auth_cit for the normal iSCSI
 * Initiator Node authentication here the discovery auth group that lives in
 * iscsi_global_t->discovery_auth
 */
static struct configfs_attribute *lio_target_discovery_auth_attrs[] = {
	&iscsi_node_auth_userid.attr,
	&iscsi_node_auth_password.attr,
	&iscsi_node_auth_authenticate_target.attr,
	&iscsi_node_auth_userid_mutual.attr,
	&iscsi_node_auth_password_mutual.attr,
	&iscsi_disc_auth_enforce_discovery_auth.attr,
	NULL,
};

static struct configfs_item_operations lio_target_discovery_auth_ops = {
	.show_attribute		= iscsi_discovery_auth_attr_show,
	.store_attribute	= iscsi_discovery_auth_attr_store,
};

static struct config_item_type lio_target_discovery_auth_cit = {
	.ct_item_ops	= &lio_target_discovery_auth_ops,
	.ct_attrs	= lio_target_discovery_auth_attrs,
	.ct_owner	= THIS_MODULE,
};

/* End lio_target_discovery_auth_cit */

/*
 * Callback for top level fabric module default configfs groups.
 */
void lio_target_reg_defgroups(struct target_fabric_configfs *fabric)
{
	iscsi_node_auth_t *discovery_auth = &iscsi_global->discovery_auth;

	config_group_init_type_name(&discovery_auth->auth_attrib_group,
			"discovery_auth", &lio_target_discovery_auth_cit);
}

int iscsi_target_register_configfs(void)
{
	struct target_fabric_configfs *fabric;
	struct config_group *tf_cg;
	int ret;

	lio_target_fabric_configfs = NULL;

	fabric = target_fabric_configfs_init(&lio_target_cit, "iscsi");
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
	fabric->tf_ops.tpg_get_pr_transport_id = &lio_tpg_get_pr_transport_id;
	fabric->tf_ops.tpg_get_pr_transport_id_len =
				&lio_tpg_get_pr_transport_id_len;
	fabric->tf_ops.tpg_parse_pr_out_transport_id =
				&lio_tpg_parse_pr_out_transport_id;
	fabric->tf_ops.tpg_check_demo_mode = &lio_tpg_check_demo_mode;
	fabric->tf_ops.tpg_check_demo_mode_cache =
				&lio_tpg_check_demo_mode_cache;
	fabric->tf_ops.tpg_check_demo_mode_write_protect =
				&lio_tpg_check_demo_mode_write_protect;
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
	fabric->tf_ops.sess_get_initiator_wwn = &lio_sess_get_initiator_wwn;
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
	 * Setup default configfs group for iSCSI Discovery Authentication.
	 *
	 * Note that the tf_cg->default_groups[] will be registered when
	 * config_group_init_type_name() gets called for fabric->tf_groups
	 * in the local callback lio_target_reg_defgroups() in generic
	 * target_core_mod code in target_core_register_fabric().
	 */
	fabric->reg_default_groups_callback = &lio_target_reg_defgroups;
	tf_cg = &fabric->tf_group;

	tf_cg->default_groups = kzalloc(sizeof(struct config_group) * 2,
			GFP_KERNEL);
	if (!(tf_cg->default_groups)) {
		printk(KERN_ERR "Unable to allocate default fabric groups\n");
		target_fabric_configfs_free(fabric);
		return -1;
	}
	tf_cg->default_groups[0] =
			&iscsi_global->discovery_auth.auth_attrib_group;
	tf_cg->default_groups[1] = NULL;

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

	target_fabric_configfs_deregister(lio_target_fabric_configfs);
	lio_target_fabric_configfs = NULL;
	printk(KERN_INFO "LIO_TARGET[0] - Cleared"
				" lio_target_fabric_configfs\n");
}
