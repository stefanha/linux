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

#include <target_core_configfs.h>

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
#include <iscsi_target_tpg.h>
#include <iscsi_target.h>

#include <iscsi_target_configfs.h>

static struct target_fabric_configfs *lio_target_fabric_configfs = NULL;

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

// Start items for lio_target_lun_cit

static struct config_group *lio_target_call_addluntodev (
        struct config_group *group,
        const char *name)
{
	printk("lio_target_call_addluntodev()\n");
	return(NULL);
}

static void lio_target_call_dellunfromdev (
        struct config_group *group,
        struct config_item *item)
{
	printk("lio_target_call_dellunfromdev()\n");
	return;
}

static struct configfs_group_operations lio_target_lun_group_ops = {
	.make_group	= lio_target_call_addluntodev,
	.drop_item	= lio_target_call_dellunfromdev,
};

static struct config_item_type lio_target_lun_cit = {
//	.ct_item_ops	= &lio_target_lun_item_ops,
	.ct_group_ops	= &lio_target_lun_group_ops,
//	.ct_attrs	= lio_target_lun_attrs,
	.ct_owner	= THIS_MODULE,
};

// End items for lio_target_lun_cit

// Start items for lio_target_tpg_cit

static ssize_t lio_target_tpg_attr_show (struct config_item *item,
                                      struct configfs_attribute *attr,
                                      char *page)
{
        return(sprintf(page, "Linux-iSCSI.org Target "PYX_ISCSI_VERSION""
                " on %s/%s on "UTS_RELEASE"\n", utsname()->sysname,
                utsname()->machine));
}

static struct configfs_item_operations lio_target_tpg_item_ops = {
        .show_attribute = lio_target_tpg_attr_show,
};

static struct config_group *lio_target_tpg_make_group (
        struct config_group *group,
        const char *name)
{
	printk("lio_target_tpg_make_group() called\n");
	return(NULL);
}

static void lio_target_tpg_drop_item (
        struct config_group *group,
        struct config_item *item)
{
        printk("lio_target_tpg_drop_item() called\n");
        return;
}

static struct configfs_group_operations lio_target_tpg_group_ops = {
        .make_group     = &lio_target_tpg_make_group,
        .drop_item      = &lio_target_tpg_drop_item,
};
#if 0
static struct configfs_attribute *lio_target_tpg_item_attrs[] = {
        &lio_target_tpg_attr_show,
        NULL,
};
#endif
static struct config_item_type lio_target_tpg_cit = {
        .ct_item_ops    = &lio_target_tpg_item_ops,
        .ct_group_ops   = &lio_target_tpg_group_ops,
//      .ct_attrs       = lio_target_tpg_item_attrs,
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

	if (!(tpg_cg = kzalloc(sizeof(struct config_group), GFP_KERNEL))) {
		iscsi_put_tpg(tpg);
		return(ERR_PTR(-ENOMEM));
	}
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
	kfree(tpg_cg);
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
	struct config_item *iscsi_ci;

	if (!(fabric = target_fabric_configfs_init(&lio_target_cit, "iscsi"))) {
		printk(KERN_ERR "target_fabric_configfs_init() for LIO-Target failed!\n");
		return(-1);
	}

	if (!(iscsi_ci = target_fabric_configfs_register(fabric))) {
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
	printk("LIO_TARGET[0] - Cleared lio_target_fabric_configfs..\n");

	return;
}
