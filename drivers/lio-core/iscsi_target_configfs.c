/*********************************************************************************
 * Filename:  iscsi_target_configfs.c
 *
 * This file contains the configfs implementation for iSCSI Target mode
 * from the LIO-Target Project.
 *
 * Copyright (c) 2008 Nicholas A. Bellinger <nab@linux-iscsi.org>
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

#include <iscsi_linux_os.h>
#include <iscsi_linux_defs.h>

#include <iscsi_debug.h>
#include <iscsi_lists.h>
#include <iscsi_protocol.h>
#include <iscsi_debug_opcodes.h>
#include <iscsi_target_core.h>
#include <iscsi_target_error.h>
#include <iscsi_target_ioctl.h>
#include <iscsi_target_ioctl_defs.h>
#include <iscsi_target_device.h>
#include <iscsi_target_erl0.h>
#include <iscsi_target_tpg.h>
#include <iscsi_target_util.h>
#include <iscsi_target_transport.h>
#include <iscsi_target.h>
#ifdef SNMP_SUPPORT
#include <iscsi_target_mib.h>
#endif /* SNMP_SUPPORT */

#include <target_core_fabric_ops.h>
#include <target_core_configfs.h>
#include <iscsi_target_configfs.h>

static struct target_fabric_configfs *lio_target_fabric_configfs = NULL;

struct lio_target_configfs_attribute {
	struct configfs_attribute attr;
	ssize_t (*show)(void *, char *);
	ssize_t (*store)(void *, const char *, size_t);
};

static u16 get_tpgt_from_tpg_ci (char *str, int *ret)
{
	char *ptr, *endptr;

	if (!(ptr = strstr(str, "tpgt_"))) {
		*ret = -1;
		return(0);
	}
	ptr += 5; /* Skip over "tpgt_" */

	return((u16)simple_strtoul(ptr, &endptr, 0));
}

// Start items for lio_target_portal_cit

static ssize_t lio_target_portal_attr_show (struct config_item *item,
					struct configfs_attribute *attr,
					char *page)
{
	return(sprintf(page, "lio_target_portal_attr_show()!\n"));
}

static struct configfs_attribute lio_target_portal_attr = {
	.ca_owner	= THIS_MODULE,
	.ca_name	= "portal_info",
	.ca_mode	= S_IRUGO,
};

static struct configfs_item_operations lio_target_portal_item_ops = {
	.show_attribute	= lio_target_portal_attr_show,
};

static struct configfs_attribute *lio_target_portal_attrs[] = {
	&lio_target_portal_attr,
	NULL,
};

static struct config_item_type lio_target_portal_cit = {
	.ct_item_ops	= &lio_target_portal_item_ops,
	.ct_attrs	= &lio_target_portal_attrs,
	.ct_owner	= THIS_MODULE,
};

// Stop items for lio_target_portal_cit

// Start items for lio_target_np_cit

static struct iscsi_target *allocate_lio_ioctl_for_net (
	const char *portal)
{
	struct iscsi_target *tg;
	char *ip_str, *port_str, *str, *str2, *end_ptr;
	char buf[256];
	int ipv6 = 0;
	unsigned short int port;

	if (!(tg = kzalloc(sizeof(struct iscsi_target), GFP_KERNEL)))
		return(ERR_PTR(-ENOMEM));

	memset(buf, 0, 256);
	snprintf(buf, 256, "%s", portal);

	/*
	 * Look for iSCSI IPv6 [$IP_ADDR]:PORT..
	 */
	if ((str = strstr(buf, "["))) {
		if (!(str2 = strstr(str, "]")))	{
			printk(KERN_ERR "Unable to locate trailing \"]\""
				" in IPv6 iSCSI network portal address\n");
			goto out;
		}
		str2 += 1; /* Skip over the "]" */
		*str2 = '\0'; /* Terminate the IPv6 address */
		str2 += 1; /* Set str2 to port */
		port = simple_strtoul(str2, &end_ptr, 0);

		sprintf(tg->ip6, "%s", str);
		tg->net_params_set |= PARAM_NET_IPV6_ADDRESS;
		tg->port = port;
		tg->net_params_set |= PARAM_NET_PORT;
	} else {
		ipv6 = 0;
		ip_str = &buf[0];

		if (!(port_str = strstr(ip_str, ":"))) {
			printk(KERN_ERR "Unable to locate \":port\""
				" in IPv4 iSCSI network portal address\n");
			goto out;
		}
		*port_str = '\0'; /* Terminate string for IP */
		port_str += 1; /* Skip over ":" */
		port = simple_strtoul(port_str, &end_ptr, 0);

		tg->ip = in_aton(ip_str);
		tg->ip = htonl(tg->ip);
		tg->net_params_set |= PARAM_NET_IPV4_ADDRESS;
		tg->port = port;
		tg->net_params_set |= PARAM_NET_PORT;
	}

	return(tg);
out:
	kfree(tg);
	return(NULL);
}

static struct config_group *lio_target_call_addnptotpg (
        struct config_group *group,
        const char *name)
{
	iscsi_portal_group_t *tpg;
	iscsi_tiqn_t *tiqn;
	struct config_group *portal_cg = NULL;
	struct config_item *np_ci, *tpg_ci, *tiqn_ci;
	struct iscsi_target *tg = NULL;
	unsigned short int tpgt;
	int network_transport, ret = 0;

	if (!(np_ci = &group->cg_item)) {
		printk(KERN_ERR "Unable to locate config_item np_ci\n");
		return(NULL);
	}
	if (!(tpg_ci = &np_ci->ci_group->cg_item)) {
		printk(KERN_ERR "Unable to locate config_item tpg_ci\n");
		return(NULL);
	}
	if (!(tiqn_ci = &tpg_ci->ci_group->cg_item)) {
		printk(KERN_ERR "Unable to locate config_item tiqn_ci\n");
		return(NULL);
	}

	/*
	 * Get the u16 tpgt from tpg_ci..
	 */
	tpgt = get_tpgt_from_tpg_ci(config_item_name(tpg_ci), &ret);
	if (ret != 0) 
		return(NULL);

	/*
	 * Setup the structure members in struct iscsi_target that 
	 * iscsi_tpg_add_network_portal() depends on..
	 */
	if (!(tg = allocate_lio_ioctl_for_net(name))) 
		return(NULL);

	printk("LIO_Target_ConfigFS: REGISTER -> %s TPGT: %hu PORTAL: %s\n",
			config_item_name(tiqn_ci), tpgt, name);

	if (!(tpg = core_get_tpg_from_iqn(config_item_name(tiqn_ci),
				&tiqn, tpgt, 0)))
		goto out;

	if (!(portal_cg = kzalloc(sizeof(struct config_group), GFP_KERNEL)))
		goto out;

#warning FIXME: Assumes iSCSI/TCP for now..
	network_transport = ISCSI_TCP;

	if ((ret = iscsi_tpg_add_network_portal(tpg, tg, network_transport)) < 0)
		goto out;

	config_group_init_type_name(portal_cg, name, &lio_target_portal_cit);

	printk("LIO_Target_ConfigFS: addnptotpg done!\n");

	kfree(tg);
	iscsi_put_tpg(tpg);
	return(portal_cg);
out:
	kfree(tg);
	kfree(portal_cg);
	iscsi_put_tpg(tpg);
	return(NULL);
}

static void lio_target_call_delnpfromtpg (
        struct config_group *group,
        struct config_item *item)
{   
	iscsi_portal_group_t *tpg;
	iscsi_tiqn_t *tiqn;
	struct config_item *np_ci, *tpg_ci, *tiqn_ci;
	struct iscsi_target *tg;
	int network_transport, ret = 0;
	unsigned short int tpgt;

	if (!(np_ci = &group->cg_item)) {
		printk(KERN_ERR "Unable to locate config_item np_ci\n");
		return;
	}
	if (!(tpg_ci = &np_ci->ci_group->cg_item)) {
		printk(KERN_ERR "Unable to locate config_item tpg_ci\n");
		return;
	}
	if (!(tiqn_ci = &tpg_ci->ci_group->cg_item)) {
		printk(KERN_ERR "Unable to locate config_item tiqn_ci\n");
		return;
	}

	tpgt = get_tpgt_from_tpg_ci(config_item_name(tpg_ci), &ret);
	if (ret != 0)
		return;
	/*
	 * Setup the structure members in struct iscsi_target that 
	 * iscsi_tpg_del_network_portal() depends on..
	 */
	if (!(tg = allocate_lio_ioctl_for_net(config_item_name(item))))
		return;

	printk("LIO_Target_ConfigFS: DEREGISTER -> %s TPGT: %hu PORTAL: %s\n",
			config_item_name(tiqn_ci), tpgt, config_item_name(item));

	if (!(tpg = core_get_tpg_from_iqn(config_item_name(tiqn_ci),
			&tiqn, tpgt, 0))) 
		goto out;

	config_item_put(item);

#warning FIXME: Assumes iSCSI/TCP for now..
	network_transport = ISCSI_TCP;

	ret = iscsi_tpg_del_network_portal(tpg, tg, network_transport);

	printk("LIO_Target_ConfigFS: delnpfromtpg done!\n");

	kfree(tg);
	iscsi_put_tpg(tpg);
	return;
out:
	kfree(tg);
	return;
}

static struct configfs_group_operations lio_target_np_group_ops = {
	.make_group	= lio_target_call_addnptotpg,
	.drop_item	= lio_target_call_delnpfromtpg,
};

static struct config_item_type lio_target_np_cit = {
//	.ct_item_ops	= &lio_target_np_item_ops,
	.ct_group_ops	= &lio_target_np_group_ops,
//	.ct_attrs	= lio_target_np_attrs,
	.ct_owner	= THIS_MODULE,
};

// End items for lio_target_np_cit

// Start items for lio_target_port_cit

static ssize_t lio_target_show_port_info (void *p, char *page)
{
	se_lun_t *lun = (se_lun_t *)p;
	int read_bytes = 0;

	read_bytes += sprintf(page, "lio_target_show_port_info()\n");
	return(read_bytes);
}

static struct lio_target_configfs_attribute lio_target_attr_port_info = {
	.attr	= { .ca_owner = THIS_MODULE,
		    .ca_name = "port_info",
		    .ca_mode = S_IRUGO },
	.show	= lio_target_show_port_info,
	.store	= NULL,
};

static ssize_t lio_target_store_port_control (void *p, const char *page, size_t count)
{
	se_lun_t *lun = (se_lun_t *)p;
	char *buf, *cur;

	if (!(buf = kzalloc(count, GFP_KERNEL))) {
		printk(KERN_ERR "Unable to allocate memory for temporary buffer\n");
		return(-ENOMEM);
	}
	memcpy(buf, page, count);

	printk("lio_target_store_port_control(): %s\n", buf);

	kfree(buf);
	return(count);
}

static struct lio_target_configfs_attribute lio_target_attr_port_control = {
	.attr	= { .ca_owner = THIS_MODULE,
		    .ca_name = "port_control",
		    .ca_mode = S_IWUSR },
	.show	= NULL,
	.store	= lio_target_store_port_control,
};

static struct configfs_attribute *lio_target_port_attrs[] = {
	&lio_target_attr_port_info.attr,
	&lio_target_attr_port_control.attr,
	NULL,
};

static ssize_t lio_target_port_show (struct config_item *item,
				     struct configfs_attribute *attr,
				     char *page)
{
	se_lun_t *lun = container_of(to_config_group(item), se_lun_t, lun_group);
	struct lio_target_configfs_attribute *lt_attr = container_of(
			attr, struct lio_target_configfs_attribute, attr);

	if (!(lt_attr->show))
		return(-EINVAL);

	return(lt_attr->show((void *)lun, page));
}

static ssize_t lio_target_port_store (struct config_item *item,
				      struct configfs_attribute *attr,
				      const char *page, size_t count)
{
	se_lun_t *lun = container_of(to_config_group(item), se_lun_t, lun_group);
	struct lio_target_configfs_attribute *lt_attr = container_of(
			attr, struct lio_target_configfs_attribute, attr);

	if (!(lt_attr->store))
		return(-EINVAL);

	return(lt_attr->store((void *)lun, page, count));
}

static int lio_target_port_link (struct config_item *lun_ci, struct config_item *se_dev_ci)
{
	iscsi_portal_group_t *tpg;
	iscsi_tiqn_t *tiqn;
	se_device_t *dev;
	se_lun_t *lun = container_of(to_config_group(lun_ci), se_lun_t, lun_group);
	se_lun_t *lun_p;
	se_subsystem_dev_t *se_dev = container_of(
		to_config_group(se_dev_ci), se_subsystem_dev_t, se_dev_group);
	struct config_item *tpg_ci, *tiqn_ci;
	int ret = 0;
	unsigned short int tpgt;

	if (lun->lun_type_ptr != NULL) {
		printk(KERN_ERR "Port Symlink already exists\n");
		return(-EEXIST);
	}

	if (!(tpg_ci = &lun_ci->ci_parent->ci_group->cg_item)) {
		printk(KERN_ERR "Unable to locate config_item tpg_ci\n");
		return(-EINVAL);
	}
	if (!(tiqn_ci = &tpg_ci->ci_group->cg_item)) {
		printk(KERN_ERR "Unable to locate config_item tiqn_ci\n");
		return(-EINVAL);
	}

	tpgt = get_tpgt_from_tpg_ci(config_item_name(tpg_ci), &ret);
	if (ret != 0)
		return(-EINVAL);

	if (!(tpg = core_get_tpg_from_iqn(config_item_name(tiqn_ci),
				&tiqn, tpgt, 0)))
		return(-EINVAL);

	if (!(dev = se_dev->se_dev_ptr)) {	
		printk(KERN_ERR "Unable to locate se_device_t pointer from %s\n",
			config_item_name(se_dev_ci));
		ret = -ENODEV;
		goto out;
	}

	if (!(lun_p = iscsi_dev_add_lun(tpg, dev->iscsi_hba, dev, lun->iscsi_lun, &ret))) {
		printk(KERN_ERR "iscsi_dev_add_lun() failed: %d\n", ret);
		ret = -EINVAL;
		goto out;
	}
	iscsi_put_tpg(tpg);

	printk("LIO_Target_ConfigFS: Created Port Symlink %s -> %s\n",
		config_item_name(se_dev_ci), config_item_name(lun_ci));
	return(0);
out:
	iscsi_put_tpg(tpg);
	return(ret);
}

static int lio_target_port_unlink (struct config_item *lun_ci, struct config_item *se_dev_ci)
{
	iscsi_portal_group_t *tpg;
	iscsi_tiqn_t *tiqn;
	se_lun_t *lun = container_of(to_config_group(lun_ci), se_lun_t, lun_group);
	se_subsystem_dev_t *se_dev = container_of(
		to_config_group(se_dev_ci), se_subsystem_dev_t, se_dev_group);
	struct config_item *tpg_ci, *tiqn_ci;
	int ret = 0;
	unsigned short int tpgt;

	printk("se_dev_ci: %s, lun_ci: %s\n", config_item_name(se_dev_ci),
			config_item_name(lun_ci));

	if (!(tpg_ci = &lun_ci->ci_parent->ci_group->cg_item)) {
		printk(KERN_ERR "Unable to locate config_item tpg_ci\n");
		return(-EINVAL);
	}
	if (!(tiqn_ci = &tpg_ci->ci_group->cg_item)) {
		printk(KERN_ERR "Unable to locate config_item tiqn_ci\n");
		return(-EINVAL);
	}

	tpgt = get_tpgt_from_tpg_ci(config_item_name(tpg_ci), &ret);
	if (ret != 0)
		return(-EINVAL);

	if (!(tpg = core_get_tpg_from_iqn(config_item_name(tiqn_ci),
				&tiqn, tpgt, 0)))
		return(-EINVAL);

	ret = iscsi_dev_del_lun(tpg, lun->iscsi_lun);
	iscsi_put_tpg(tpg);

	printk("LIO_Target_ConfigFS: Removed Port Symlink %s -> %s\n",
		config_item_name(se_dev_ci), config_item_name(lun_ci));

	return(0);
}

static struct configfs_item_operations lio_target_port_item_ops = {
	.release		= NULL,
	.show_attribute		= lio_target_port_show,
	.store_attribute	= lio_target_port_store,
	.allow_link		= lio_target_port_link,
	.drop_link		= lio_target_port_unlink,
};

static struct config_item_type lio_target_port_cit = {
	.ct_item_ops		= &lio_target_port_item_ops,
	.ct_attrs		= lio_target_port_attrs,
	.ct_owner		= THIS_MODULE,
};

// End items for lio_target_port_cit

// Start items for lio_target_lun_cit

static struct config_group *lio_target_lun_make_group (
        struct config_group *group,
        const char *name)
{
	iscsi_portal_group_t *tpg;
	iscsi_tiqn_t *tiqn;
	se_lun_t *lun_p;
	struct config_item *lun_ci, *tpg_ci, *tiqn_ci;
	char *str, *endptr;
	u32 lun;
	int ret = 0;
	unsigned short int tpgt;

	if (!(str = strstr(name, "_"))) { 
		printk(KERN_ERR "Unable to locate \'_\" in \"lun_$LUN_NUMBER\"\n");
		return(NULL);
	}
	str++; /* Advance over _ delim.. */
	lun = simple_strtoul(str, &endptr, 0);

	if (!(lun_ci = &group->cg_item)) {
		printk(KERN_ERR "Unable to locate config_item np_ci\n");
		return(NULL);
	}
	if (!(tpg_ci = &lun_ci->ci_group->cg_item)) {
		printk(KERN_ERR "Unable to locate config_item tpg_ci\n");
		return(NULL);
	}
	if (!(tiqn_ci = &tpg_ci->ci_group->cg_item)) {
		printk(KERN_ERR "Unable to locate config_item tiqn_ci\n");
		return(NULL);
	}
	/*
	 * Get the u16 tpgt from tpg_ci..
	 */
	tpgt = get_tpgt_from_tpg_ci(config_item_name(tpg_ci), &ret);
	if (ret != 0) 
		return(NULL);

	printk("LIO_Target_ConfigFS: REGISTER -> %s TPGT: %hu LUN: %u\n",
			config_item_name(tiqn_ci), tpgt, lun);

	if (!(tpg = core_get_tpg_from_iqn(config_item_name(tiqn_ci),
                                &tiqn, tpgt, 0)))
		return(NULL);

	if (!(lun_p = iscsi_get_lun_from_tpg(tpg, lun)))
		goto out;

	config_group_init_type_name(&lun_p->lun_group, name, &lio_target_port_cit);

	iscsi_put_tpg(tpg);
	return(&lun_p->lun_group);
out:
	iscsi_put_tpg(tpg);
	return(NULL);
}

static void lio_target_lun_drop_item (
        struct config_group *group,
        struct config_item *item)
{
	se_lun_t *lun = container_of(to_config_group(item), se_lun_t, lun_group);
	struct config_item *lun_ci, *tpg_ci, *tiqn_ci;
	int ret = 0;
	unsigned short int tpgt;

	if (!(lun_ci = &group->cg_item)) {
		printk(KERN_ERR "Unable to locate config_item np_ci\n");
		return;
	}
	if (!(tpg_ci = &lun_ci->ci_group->cg_item)) {
		printk(KERN_ERR "Unable to locate config_item tpg_ci\n");
		return;
	}
	if (!(tiqn_ci = &tpg_ci->ci_group->cg_item)) {
		printk(KERN_ERR "Unable to locate config_item tiqn_ci\n");
		return;
	}

	tpgt = get_tpgt_from_tpg_ci(config_item_name(tpg_ci), &ret);
	if (ret != 0)
		return;

	printk("LIO_Target_ConfigFS: DEREGISTER -> %s TPGT: %hu LUN: %u\n",
			config_item_name(tiqn_ci), tpgt, lun->iscsi_lun);

	config_item_put(item);
	return;
}

static struct configfs_group_operations lio_target_lun_group_ops = {
	.make_group	= lio_target_lun_make_group,
	.drop_item	= lio_target_lun_drop_item,
};

static struct config_item_type lio_target_lun_cit = {
//	.ct_item_ops	= &lio_target_lun_item_ops,
	.ct_group_ops	= &lio_target_lun_group_ops,
//	.ct_attrs	= lio_target_lun_attrs,
	.ct_owner	= THIS_MODULE,
};

// End items for lio_target_lun_cit

// Start items for lio_target_tpg_cit

static ssize_t lio_target_store_tpg_control (void *p, const char *page, size_t count)
{
	iscsi_portal_group_t *tpg = (iscsi_portal_group_t *)p;

	printk("lio_target_store_tpg_control(): %s\n", page);
	return(count);
}

static struct lio_target_configfs_attribute lio_target_attr_tpg_control = {
	.attr	= { .ca_owner = THIS_MODULE,
		    .ca_name = "tpg_control",
		    .ca_mode = S_IWUSR },
	.show	= NULL,
	.store	= lio_target_store_tpg_control,
};

static ssize_t lio_target_store_tpg_enable (void *p, const char *page, size_t count)
{
	iscsi_portal_group_t *tpg_p = (iscsi_portal_group_t *)p, *tpg;
	iscsi_tiqn_t *tiqn;
	struct config_item *tpg_ci, *tiqn_ci;
	char *endptr;
	u32 op;
	int ret = 0;;

	op = simple_strtoul(page, &endptr, 0);	
	if ((op != 1) && (op != 0)) {
		printk(KERN_ERR "Illegal value for tpg_enable: %u\n", op);
		return(-EINVAL);
	}

	if (!(tpg_ci = &tpg_p->tpg_group.cg_item)) {
		printk(KERN_ERR "Unable to locate tpg_ci\n");
		return(-EINVAL);
	}

	if (!(tiqn_ci = &tpg_ci->ci_group->cg_item)) {
		printk(KERN_ERR "Unable to locate config_item tiqn_ci\n");
		return(-EINVAL);
	}

	if (!(tpg = core_get_tpg_from_iqn(config_item_name(tiqn_ci),
			&tiqn, tpg_p->tpgt, 0)))
		return(-EINVAL);

	if (op) {
#warning WARNING: tpg_enable uses #warning Currently uses generate_node_acls=1,cache_dynamic_acls=1,demo_mode_lun_access=1
		ISCSI_TPG_ATTRIB(tpg)->generate_node_acls = 1;
		ISCSI_TPG_ATTRIB(tpg)->cache_dynamic_acls = 1;
		ISCSI_TPG_ATTRIB(tpg)->demo_mode_lun_access = 1;

		if ((ret = iscsi_tpg_enable_portal_group(tpg)) < 0)
			goto out;
	} else {
#warning FIXME: For disabletpg, sssumes force=1 for now..
		if ((ret = iscsi_tpg_disable_portal_group(tpg, 1)) < 0)
			goto out;
	}

	iscsi_put_tpg(tpg);
	return(count);
out:
	iscsi_put_tpg(tpg);
	return(-EINVAL);
}

static struct lio_target_configfs_attribute lio_target_attr_tpg_enable = {
	.attr	= { .ca_owner = THIS_MODULE,
		    .ca_name = "tpg_enable",
		    .ca_mode = S_IWUSR },
	.show	= NULL,
	.store	= lio_target_store_tpg_enable,
};

static struct configfs_attribute *lio_target_tpg_attrs[] = {
	&lio_target_attr_tpg_control.attr,
	&lio_target_attr_tpg_enable.attr,
};

static ssize_t lio_target_tpg_show (struct config_item *item,
                                    struct configfs_attribute *attr,
                                    char *page)
{
	iscsi_portal_group_t *tpg = container_of(
			to_config_group(item), iscsi_portal_group_t, tpg_group);
	struct lio_target_configfs_attribute *lt_attr = container_of( 
			attr, struct lio_target_configfs_attribute, attr);

	if (!(lt_attr->show))
		 return(-EINVAL);

	return(lt_attr->show((void *)tpg, page));
}

static ssize_t lio_target_tpg_store (struct config_item *item,
				     struct configfs_attribute *attr,
				     const char *page, size_t count)
{
	iscsi_portal_group_t *tpg = container_of(
			to_config_group(item), iscsi_portal_group_t, tpg_group);
	struct lio_target_configfs_attribute *lt_attr = container_of( 
			attr, struct lio_target_configfs_attribute, attr);

	if (!(lt_attr->store))
		return(-EINVAL);

	return(lt_attr->store((void *)tpg, page, count));
}

static struct configfs_item_operations lio_target_tpg_item_ops = {
        .show_attribute		= lio_target_tpg_show,
	.store_attribute	= lio_target_tpg_store,
};

static struct config_item_type lio_target_tpg_cit = {
        .ct_item_ops    = &lio_target_tpg_item_ops,
	.ct_attrs       = lio_target_tpg_attrs,
        .ct_owner       = THIS_MODULE,
};


// End items for lio_target_tpg_cit

// Start items for lio_target_tiqn_cit

static ssize_t lio_target_tiqn_attr_show_nodename (struct config_item *item,
                                      struct configfs_attribute *attr,
                                      char *page)
{
	return(sprintf(page, "lio_target_tpg_attr_show_nodename() called!\n"));
}

static struct configfs_item_operations lio_target_tiqn_item_ops = {
        .show_attribute = lio_target_tiqn_attr_show_nodename,
};

static struct configfs_attribute lio_target_tiqn_attr_nodename = {
        .ca_owner       = THIS_MODULE,
        .ca_name        = "nodename",
        .ca_mode        = S_IRUGO | S_IWUSR,
};

static struct config_group *lio_target_tiqn_addtpg (
        struct config_group *group,
        const char *name)
{
	iscsi_portal_group_t *tpg;
	iscsi_tiqn_t *tiqn;
	struct config_group *tpg_cg;
	struct config_item *tiqn_ci;
	char *tpgt_str, *end_ptr;
	int ret = 0;
	unsigned short int tpgt;

	printk("lio_target_tiqn_addtpg() called: name %s\n", name);

	if (!(tiqn_ci = &group->cg_item)) {
		printk(KERN_ERR "Unable to locate valid group->cg_item pointer\n");
		return(NULL);
	}
	printk("lio_target_tiqn_addtpg() parent name: %s\n", config_item_name(tiqn_ci));

	/*
	 * Only tpgt_# directory groups can be created below target/iscsi/iqn.superturodiskarry/
	*/
	if (!(tpgt_str = strstr(name, "tpgt_"))) {
		printk(KERN_ERR "Unable to locate \"tpgt_#\" directory group\n");
		return(NULL);
	}
	tpgt_str += 5; /* Skip ahead of "tpgt_" */
	tpgt = (unsigned short int) simple_strtoul(tpgt_str, &end_ptr, 0);
	printk("lio_target_tiqn_addtpg() Using TPGT: %hu\n", tpgt);

	if (!(tpg = core_get_tpg_from_iqn(config_item_name(tiqn_ci), &tiqn, tpgt, 1)))
		return(NULL);

	tpg_cg = &tpg->tpg_group;

	/*
	 * Create default configfs groups for iscsi_portal_group_t..
	 */
	if (!(tpg_cg->default_groups = kzalloc(sizeof(struct config_group) * 3,
			GFP_KERNEL)))
		goto out;

	config_group_init_type_name(&tpg->tpg_np_group, "np", &lio_target_np_cit);
	config_group_init_type_name(&tpg->tpg_lun_group, "lun", &lio_target_lun_cit);
	tpg_cg->default_groups[0] = &tpg->tpg_np_group;
	tpg_cg->default_groups[1] = &tpg->tpg_lun_group;
	tpg_cg->default_groups[2] = NULL;

	if ((ret = iscsi_tpg_add_portal_group(tiqn, tpg)) < 0)
		goto out;

	printk("LIO_Target_ConfigFS: REGISTER -> %s\n", tiqn->tiqn);
        config_group_init_type_name(tpg_cg, name, &lio_target_tpg_cit);
        printk("LIO_Target_ConfigFS: REGISTER -> Allocated TPG: %s\n",
                        tpg_cg->cg_item.ci_name);

	iscsi_put_tpg(tpg);
	return(tpg_cg);
out:	
	kfree(tpg_cg->default_groups);
	iscsi_put_tpg(tpg);
	return(NULL);
}

static void lio_target_tiqn_deltpg (
        struct config_group *group,
        struct config_item *item)
{
	iscsi_portal_group_t *tpg;
	iscsi_tiqn_t *tiqn;
	struct config_item *parent;
	char *tpgt_str, *end_ptr;
	int ret = 0;
	unsigned short int tpgt;

	printk("LIO_Target_ConfigFS: DEREGISTER -> %s\n", config_item_name(item));
	if (!(parent = &group->cg_item)) {
		printk(KERN_ERR "Unable to locate group_cg_item\n");
		return;
	}

	if (!(tpgt_str = strstr(config_item_name(item), "tpgt_"))) {
		printk(KERN_ERR "Unable to locate \"tpgt_#\" directory group\n");
		return;	
	}
	tpgt_str += 5; /* Skip ahead of "tpgt_" */
	tpgt = (unsigned short int) simple_strtoul(tpgt_str, &end_ptr, 0);
	printk("lio_target_tiqn_deltpg(): Using TPGT: %hu\n", tpgt);

	if (!(tpg = core_get_tpg_from_iqn(config_item_name(parent), &tiqn, tpgt, 0)))
		return;

	printk("LIO_Target_ConfigFS: DEREGISTER -> calling config_item_put()\n");
	/*
	 * Does the last config_item_put() also release a groups->default_groups..?
	 */
	config_item_put(item);

#warning FIXME: Assming force=1
	printk("LIO_Target_ConfigFS: DEREGISTER -> Releasing TPG\n");
	if ((ret = iscsi_tpg_del_portal_group(tiqn, tpg, 1)) < 0) {
		iscsi_put_tpg(tpg);
		return;
	}

	iscsi_put_tpg(tpg);
	return;
}

static struct configfs_group_operations lio_target_tiqn_group_ops = {
	.make_group	= &lio_target_tiqn_addtpg,
	.drop_item	= &lio_target_tiqn_deltpg,
};

static struct configfs_attribute *lio_target_tiqn_item_attrs[] = {
        &lio_target_tiqn_attr_nodename,
        NULL,
};

static struct config_item_type lio_target_tiqn_cit = {
	.ct_item_ops	= &lio_target_tiqn_item_ops,
	.ct_group_ops	= &lio_target_tiqn_group_ops,
//	.ct_attrs	= lio_target_tiqn_item_attrs,
	.ct_owner	= THIS_MODULE,
};

// End items for lio_target_tiqn_cit

// Start LIO-Target TIQN struct contig_item lio_target_cit..

static ssize_t lio_target_attr_show (struct config_item *item,
                                      struct configfs_attribute *attr,
                                      char *page)
{
        return(sprintf(page, "Linux-iSCSI.org Target "PYX_ISCSI_VERSION""
		" on %s/%s on "UTS_RELEASE"\n", utsname()->sysname,
		utsname()->machine));
}

static struct configfs_item_operations lio_target_item_ops = {
	.show_attribute = lio_target_attr_show,
};

static struct configfs_attribute lio_target_item_attr_version = {
	.ca_owner	= THIS_MODULE,
	.ca_name	= "lio_version",
	.ca_mode	= S_IRUGO,
};

static struct config_group *lio_target_call_coreaddtiqn (
        struct config_group *group,
        const char *name)
{
	struct config_group *tiqn_cg;
	iscsi_tiqn_t *tiqn;
	int ret = 0;

	printk("lio_target_call_coreaddtiqn(): name: %s\n", name);

	if (!(tiqn_cg = kzalloc(sizeof(struct config_group), GFP_KERNEL))) 
		return(ERR_PTR(-ENOMEM));

	if (!(tiqn = core_add_tiqn((unsigned char *)name, &ret)))
		return(NULL);

	printk("LIO_Target_ConfigFS: REGISTER -> %s\n", tiqn->tiqn);	
	config_group_init_type_name(tiqn_cg, tiqn->tiqn, &lio_target_tiqn_cit);
	printk("LIO_Target_ConfigFS: REGISTER -> Allocated Node: %s\n",
			tiqn_cg->cg_item.ci_name);

	return(tiqn_cg);
}

static void lio_target_call_coredeltiqn (
	struct config_group *group,
	struct config_item *item)
{
	printk("LIO_Target_ConfigFS: DEREGISTER -> %s\n", config_item_name(item));
	printk("LIO_Target_ConfigFS: DEREGISTER -> calling config_item_put()\n");
	config_item_put(item);
	printk("LIO_Target_ConfigFS: DEREGISTER -> Releasing core_del_tiqn()\n");
	core_del_tiqn(config_item_name(item));

	return;
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

// End LIO-Target TIQN struct contig_lio_target_cit..

extern int iscsi_target_register_configfs (void)
{
	struct target_fabric_configfs *fabric;
	int ret;

	if (!(fabric = target_fabric_configfs_init(&lio_target_cit, "iscsi"))) {
		printk(KERN_ERR "target_fabric_configfs_init() for LIO-Target failed!\n");
		return(-1);
	}

	/*
	 * Temporary OPs function pointers used by target_core_mod..
	 */
	fabric->tf_ops.release_cmd_to_pool = &iscsi_release_cmd_to_pool;
	fabric->tf_ops.release_cmd_direct = &iscsi_release_cmd_direct;
	fabric->tf_ops.dev_del_lun = &iscsi_dev_del_lun;
	fabric->tf_ops.stop_session = &iscsi_stop_session;
	fabric->tf_ops.fall_back_to_erl0 = &iscsi_fall_back_to_erl0;
	fabric->tf_ops.add_cmd_to_response_queue = &iscsi_add_cmd_to_response_queue;
	fabric->tf_ops.build_r2ts_for_cmd = &iscsi_build_r2ts_for_cmd;
	fabric->tf_ops.dec_nacl_count = &iscsi_dec_nacl_count;
	fabric->tf_ops.scsi_auth_intr_seq_start = &lio_scsi_auth_intr_seq_start;
	fabric->tf_ops.scsi_auth_intr_seq_next = &lio_scsi_auth_intr_seq_next;
	fabric->tf_ops.scsi_auth_intr_seq_show = &lio_scsi_auth_intr_seq_show;
	fabric->tf_ops.scsi_auth_intr_seq_stop = &lio_scsi_auth_intr_seq_stop;
	fabric->tf_ops.scsi_att_intr_port_seq_start = &lio_scsi_att_intr_port_seq_start;
	fabric->tf_ops.scsi_att_intr_port_seq_next = &lio_scsi_att_intr_port_seq_next;
	fabric->tf_ops.scsi_att_intr_port_seq_show = &lio_scsi_att_intr_port_seq_show;
	fabric->tf_ops.scsi_att_intr_port_seq_stop = &lio_scsi_att_intr_port_seq_stop;

	if ((ret = target_fabric_configfs_register(fabric)) < 0) {
		printk(KERN_ERR "target_fabric_configfs_register() for LIO-Target failed!\n");
		target_fabric_configfs_free(fabric);		
		return(-1);
	}

	lio_target_fabric_configfs = fabric;
	printk("LIO_TARGET[0] - Set fabric -> lio_target_fabric_configfs\n");

	return(0);
}


extern void iscsi_target_deregister_configfs (void)
{
	if (!(lio_target_fabric_configfs))
		return;
	
	target_fabric_configfs_deregister(lio_target_fabric_configfs);	
	lio_target_fabric_configfs = NULL;
	printk("LIO_TARGET[0] - Cleared lio_target_fabric_configfs\n");

	return;
}
