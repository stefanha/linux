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

#include <target_core_configfs.h>

#include <iscsi_linux_os.h>
#include <iscsi_linux_defs.h>

#include <iscsi_debug.h>
#include <iscsi_lists.h>
#include <iscsi_protocol.h>
#include <iscsi_debug_opcodes.h>
#include <iscsi_target_core.h>
#include <iscsi_target_error.h>

#include <iscsi_target_configfs.h>

static struct target_fabric_configfs *lio_target_fabric_configfs = NULL;

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
	printk("lio_target_call_coreaddtiqn(): name: %s\n", name);
	return(NULL);
}

static void lio_target_call_coredeltiqn (
	struct config_group *group,
	struct config_item *item)
{
	printk("lio_target_call_coredeltiqn()\n");
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
