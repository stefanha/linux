/*********************************************************************************
 * Filename:  target_core_configfs.c
 *
 * This file contains ConfigFS logic for the Generic Target Engine project.
 *
 * Copyright (c) 2008  Nicholas A. Bellinger <nab@linux-iscsi.org>
 *
 * based on configfs Copyright (C) 2005 Oracle.  All rights reserved.
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
#include <linux/fs.h>
#include <linux/namei.h>
#include <linux/slab.h>
#include <linux/types.h>
#include <linux/delay.h>
#include <linux/unistd.h>
#include <linux/string.h>
#include <linux/syscalls.h>
#include <linux/configfs.h>

#include <iscsi_debug.h>
#include <iscsi_lists.h>
#include <iscsi_protocol.h>
#include <iscsi_debug_opcodes.h>
#include <iscsi_target_core.h>
#include <iscsi_target_error.h>
#include <iscsi_target_ioctl.h>
#include <iscsi_target_ioctl_defs.h>
#include <target_core_device.h>
#include <iscsi_target_device.h>
#include <iscsi_target_hba.h>
#include <iscsi_target_info.h>
#include <iscsi_target_plugin.h>
#include <iscsi_target_transport.h>
#include <iscsi_target.h>
#ifdef SNMP_SUPPORT
#include <iscsi_target_mib.h>
#endif /* SNMP_SUPPORT */

#include <target_core_fabric_ops.h>
#include <target_core_configfs.h>

extern se_global_t *se_global;

struct config_group target_core_hbagroup;

struct list_head g_tf_list;
struct mutex g_tf_lock;

/*
 * Temporary pointer required for target_core_mod to operate..
 */
struct target_core_fabric_ops *iscsi_fabric_ops = NULL;

/*
 * Tempory function required for target_core_mod to operate..
 */
extern struct target_core_fabric_ops *target_core_get_iscsi_ops (void)
{
	return(iscsi_fabric_ops);
}

struct target_core_configfs_attribute {
	struct configfs_attribute attr;
	ssize_t (*show)(void *, char *);
	ssize_t (*store)(void *, const char *, size_t);
};

/*
 * Attributes for /sys/kernel/config/target/
 */
static ssize_t target_core_attr_show (struct config_item *item,
				      struct configfs_attribute *attr,
				      char *page)
{
	return(sprintf(page, "Target Engine Core ConfigFS Infrastructure %s"
		" on %s/%s on "UTS_RELEASE"\n", TARGET_CORE_CONFIGFS_VERSION,
		utsname()->sysname, utsname()->machine));
}

static struct configfs_item_operations target_core_item_ops = {
	.show_attribute = target_core_attr_show,
};

static struct configfs_attribute target_core_item_attr_version = {
	.ca_owner	= THIS_MODULE,
	.ca_name	= "version",
	.ca_mode	= S_IRUGO,
};

static struct target_fabric_configfs *target_core_get_fabric (
	const char *name)
{
	struct target_fabric_configfs *tf;

	if (!(name))
		return(NULL);
	
	mutex_lock(&g_tf_lock);
	list_for_each_entry(tf, &g_tf_list, tf_list) {
		if (!(strcmp(tf->tf_name, name))) {
			atomic_inc(&tf->tf_access_cnt);
			mutex_unlock(&g_tf_lock);
			return(tf);
		}
	}
	mutex_unlock(&g_tf_lock);

	return(NULL);
}

/*
 * Called with g_tf_lock mutex held, and struct target_fabric_congifs->tf_access_cnt
 * is not incremented..
 */
static struct target_fabric_configfs *__target_core_get_fabric (
	const char *name)
{
	struct target_fabric_configfs *tf;

	if (!(name))
		return(NULL);
	
	list_for_each_entry(tf, &g_tf_list, tf_list) {
		if (!(strcmp(tf->tf_name, name)))
			return(tf);
	}

	return(NULL);
}

static void target_core_put_fabric (
	struct target_fabric_configfs *tf)
{
	atomic_dec(&tf->tf_access_cnt);
	return;
}

/*
 * Called from struct target_core_group_ops->make_group()
 */
static struct config_group *target_core_register_fabric (
	struct config_group *group,
	const char *name)
{
	struct config_group *fabric_cg;
	struct target_fabric_configfs *tf;

	printk("Target_Core_ConfigFS: REGISTER -> group: %p name: %s\n", group, name);

	/*
	 * On a successful target_core_get_fabric() look, the returned 
	 * struct target_fabric_configfs *tf will contain a usage reference.
	 */
	if (!(tf = target_core_get_fabric(name)))
		return(NULL);

	printk("Target_Core_ConfigFS: REGISTER -> Located fabric: %s\n", tf->tf_name);

        if (!(fabric_cg = kzalloc(sizeof(struct config_group), GFP_KERNEL))) {
		target_core_put_fabric(tf);
                return(ERR_PTR(-ENOMEM));
        }

	printk("Target_Core_ConfigFS: REGISTER -> %p\n", tf->tf_fabric_cit);
        config_group_init_type_name(fabric_cg, name, tf->tf_fabric_cit);
        printk("Target_Core_ConfigFS: REGISTER -> Allocated Fabric: %s\n",
			fabric_cg->cg_item.ci_name);

	return(fabric_cg);
}

/*
 * Called from struct target_core_group_ops->drop_item()
 */
static void target_core_deregister_fabric (
	struct config_group *group,
	struct config_item *item)
{
	struct target_fabric_configfs *tf;

	if (!(group) || !(item)) {
		printk(KERN_ERR "Missing group or item parameters\n");
		return;
	}
	printk("Target_Core_ConfigFS: DEREGISTER -> Looking up %s in tf list\n",
			config_item_name(item));

	mutex_lock(&g_tf_lock);
	if (!(tf = __target_core_get_fabric(config_item_name(item)))) {
		mutex_unlock(&g_tf_lock);
		printk(KERN_ERR "Unable to locate tf from item: %s\n",
			config_item_name(item));
		BUG();
	}
	printk("Target_Core_ConfigFS: DEREGISTER -> located fabric: %s\n", tf->tf_name);

	if (!(atomic_dec_and_test(&tf->tf_access_cnt))) {
		mutex_unlock(&g_tf_lock);
		printk(KERN_ERR "Non zero tf->tf_access_cnt for fabric %s\n",
			tf->tf_name);
		BUG();
	}
	list_del(&tf->tf_list);
	mutex_unlock(&g_tf_lock);

	printk("Target_Core_ConfigFS: DEREGISTER -> Releasing tf: %s\n", tf->tf_name);
	tf->tf_fabric_cit = NULL;
	tf->tf_subsys = NULL;
	tf->tf_fabric = NULL;
	kfree(tf);

	printk("Target_Core_ConfigFS: DEREGISTER -> Releasing ci %s\n",
			config_item_name(item));
	config_item_put(item);

	return;
}

static struct configfs_group_operations target_core_group_ops = {
	.make_group	= &target_core_register_fabric,
	.drop_item	= &target_core_deregister_fabric,
};

/*
 * All item attributes appearing in /sys/kernel/target/ appear here.
 */
static struct configfs_attribute *target_core_item_attrs[] = {
	&target_core_item_attr_version,
	NULL,
};

/* 
 * Provides Fabrics Groups and Item Attributes for /sys/kernel/config/target/
 */
static struct config_item_type target_core_fabrics_item = {
	.ct_item_ops	= &target_core_item_ops,
	.ct_group_ops	= &target_core_group_ops,
	.ct_attrs	= target_core_item_attrs,
	.ct_owner	= THIS_MODULE,
};

static struct configfs_subsystem target_core_fabrics = {
	.su_group = {
		.cg_item = {
			.ci_namebuf = "target",
			.ci_type = &target_core_fabrics_item,
		},
	},
};

static struct configfs_subsystem *target_core_subsystem[] = {
	&target_core_fabrics,
	NULL,
};

//##############################################################################
// Start functions called by external Target Fabrics Modules
//##############################################################################

/*
 * First function called by fabric modules to:
 *
 * 1) Allocate a struct target_fabric_configfs and save the *fabric_cit pointer.
 * 2) Add struct target_fabric_configfs to g_tf_list
 * 3) Return struct target_fabric_configfs to fabric module to be passed
 *    into target_fabric_configfs_register().
 */
extern struct target_fabric_configfs *target_fabric_configfs_init (
	struct config_item_type *fabric_cit,
	const char *name)
{
	struct target_fabric_configfs *tf;

	if (!(fabric_cit)) {
		printk(KERN_ERR "Missing struct config_item_type * pointer\n");
		return(NULL);
	}
	if (!(name)) {
		printk(KERN_ERR "Unable to locate passed fabric name\n");
		return(NULL);
	}
	if (strlen(name) > TARGET_FABRIC_NAME_SIZE) {
		printk(KERN_ERR "Passed name: %s exceeds TARGET_FABRIC_NAME_SIZE\n", name);
		return(NULL);
	}

	if (!(tf = kzalloc(sizeof(struct target_fabric_configfs), GFP_KERNEL)))
		return(ERR_PTR(-ENOMEM));

	INIT_LIST_HEAD(&tf->tf_list);
	atomic_set(&tf->tf_access_cnt, 0);
	tf->tf_fabric_cit = fabric_cit;
	tf->tf_subsys = target_core_subsystem[0];
	snprintf(tf->tf_name, TARGET_FABRIC_NAME_SIZE, "%s", name);

	mutex_lock(&g_tf_lock);
	list_add_tail(&tf->tf_list, &g_tf_list);
	mutex_unlock(&g_tf_lock);

	printk("<<<<<<<<<<<<<<<<<<<<<< BEGIN FABRIC API >>>>>>>>>>>>>>>>>>>>>>\n");
	printk("Initialized struct target_fabric_configfs: %p for %s\n", tf, tf->tf_name);
	return(tf);
}

/*
 * Called by fabric plugins after FAILED target_fabric_configfs_register() call..
 */
extern void target_fabric_configfs_free (
	struct target_fabric_configfs *tf)
{
	mutex_lock(&g_tf_lock);
	list_del(&tf->tf_list);
        mutex_unlock(&g_tf_lock);

	kfree(tf);
	return;
}

/* 
 * Note that config_group_find_item() calls config_item_get() and grabs the 
 * reference to the returned struct config_item *
 * It will be released with config_put_item() in target_fabric_configfs_deregister()
 */
extern struct config_item *target_fabric_configfs_find_by_name (
	struct configfs_subsystem *target_su,
	const char *name)
{
	struct config_item *fabric;

	mutex_lock(&target_su->su_mutex);
	fabric = config_group_find_item(&target_su->su_group, name);
	mutex_unlock(&target_su->su_mutex);

	return(fabric);
}

static long do_configfs_mkdir (struct config_item *item, const char *path, int mode)
{
//	char *s;
	struct dentry *dentry;
	struct nameidata nd;
	int error = 0;	
#if 0
	s = __getname();
	if (IS_ERR(s)) {
		printk("__getname() failed\n");
		return(PTR_ERR(s));
	}
#endif
	if ((error = path_lookup(path, LOOKUP_PARENT, &nd))) {
		printk("path_lookup() failed for %s, error: %d\n", path, error);
//		putname(s);
		return(error);
	}

	dentry = lookup_create(&nd, 1);
	error = PTR_ERR(dentry);
	if (IS_ERR(dentry)) {
		printk("lookup_create() returned error: %d\n", error);
		goto out;
	}

	printk("Calling vfs_mkdir() d_inode: %p dentry: %p\n",
		item->ci_dentry->d_inode, dentry);

	error = vfs_mkdir(item->ci_dentry->d_inode, dentry, mode);
	
	dput(dentry);
out:
	mutex_unlock(&nd.path.dentry->d_inode->i_mutex);
	path_put(&nd.path);
//	putname(s);

	return(error);
}

#if 1

/*
 * fs/namei.c:lookup_hash() is not defined as EXPORT_SYMBOL()
 */
extern struct dentry *lookup_hash(struct nameidata *);

static long do_configfs_rmdir (struct config_item *item, const char *path)
{
	struct dentry *dentry;
	struct nameidata nd;
	int error = 0;
	
	if ((error = path_lookup(path, LOOKUP_PARENT, &nd))) {
		printk("path_lookup() failed for %s, error: %d\n", path, error);
		return(error);
	}

	/*
	 * lookup_hash() is not exported from fs/namei.c..
	 */
	mutex_lock_nested(&nd.path.dentry->d_inode->i_mutex, I_MUTEX_PARENT);
	dentry = lookup_hash(&nd);
	error = PTR_ERR(dentry);
	if (IS_ERR(dentry)) {
		printk("lookup_hash() returned error: %d\n", error);
		goto unlock;
	}

	printk("Calling vfs_rmdir() d_inode: %p dentry: %p\n",
		item->ci_dentry->d_inode, dentry);

	error = vfs_rmdir(item->ci_dentry->d_inode, dentry);

	dput(dentry);
unlock:
	mutex_unlock(&nd.path.dentry->d_inode->i_mutex);
	path_put(&nd.path);

	return(error);
}

#else

static long do_configfs_rmdir (struct config_item *item, const char *path)
{
	struct dentry *dentry;
	int error = 0;

	mutex_lock(&item->ci_dentry->d_inode->i_mutex);	
	dentry = lookup_one_len(path, item->ci_dentry, strlen(path));
	error = PTR_ERR(dentry);
	if (IS_ERR(dentry)) {
		printk("lookup_one_len() returned error: %d\n", error);
		goto unlock;
	}

	printk("Calling vfs_rmdir() d_inode: %p dentry: %p\n",
		item->ci_dentry->d_inode, dentry);
	error = vfs_rmdir(item->ci_dentry->d_inode, dentry);
	printk("vfs_rmdir() returned %d\n", error);
	
	dput(dentry);
unlock:
	mutex_unlock(&item->ci_dentry->d_inode->i_mutex);
	return(error);
}

#endif

/*
 * Called 2nd from fabric module with returned parameter of
 * struct target_fabric_configfs * from target_fabric_configfs_init().
 * 
 * Upon a successful registration, the new fabric's struct config_item is return.
 * Also, a pointer to this struct is set in the passted struct target_fabric_configfs.
 */
extern struct config_item *target_fabric_configfs_register (
	struct target_fabric_configfs *tf)
{
	struct config_item *fabric;
	struct config_group *su_group;
	char buf[256];

	if (!(tf)) {
		printk(KERN_ERR "Unable to locate target_fabric_configfs pointer\n");
		return(NULL);
	}
	if (!(tf->tf_subsys)) {
		printk(KERN_ERR "Unable to target struct config_subsystem pointer\n");
		return(NULL);
	}
	if (!(su_group = &tf->tf_subsys->su_group)) {
		printk(KERN_ERR "Unable to locate target struct config_group pointer\n");
		return(NULL);
	}

	memset(buf, 0, 256);
	snprintf(buf, 256, "%s/target/%s", TARGET_CORE_CONFIG_ROOT, tf->tf_name);
	printk("target_fabric_configfs_register(): Using do_configfs_mkdir(%s)\n", buf);

	do_configfs_mkdir(&su_group->cg_item, buf, 600);

	/*
	 * Grab reference to returned config_item *fabric..
	 */
	if (!(fabric = target_fabric_configfs_find_by_name(tf->tf_subsys,
			tf->tf_name))) {
		printk(KERN_ERR "target_fabric_configfs_find_by_name() returned"
				" NULL for %s\n", tf->tf_name);
		return(NULL);
	}
	tf->tf_fabric = fabric;
	printk("target_fabric_configfs_register(): Allocated Fabric: %s\n",
			config_item_name(fabric));
	printk("<<<<<<<<<<<<<<<<<<<<<< END FABRIC API >>>>>>>>>>>>>>>>>>>>>>\n");

	iscsi_fabric_ops = &tf->tf_ops;

	return(fabric);
}

extern void target_fabric_configfs_deregister (
	struct target_fabric_configfs *tf)
{
	struct config_item *fabric;
	struct config_group *su_group;
	struct configfs_subsystem *su;
	char buf[256], name[256];

	if (!(tf)) {
		printk(KERN_ERR "Unable to locate passed target_fabric_configfs\n");
		return;
	}
	if (!(fabric = tf->tf_fabric)) {
		printk(KERN_ERR "Unable to locate passed fabric struct config_item\n");
		return;
	}
	if (!(su = tf->tf_subsys)) {
		printk(KERN_ERR "Unable to locate passed tf->tf_subsys pointer\n");
		return;
	}
	if (!(su_group = &tf->tf_subsys->su_group)) {
		printk(KERN_ERR "Unable to locate target struct config_group pointer\n");
		return;
	}

	memset(name, 0, 256);
	snprintf(name, 256, "%s", tf->tf_name);

	memset(buf, 0, 256);
	snprintf(buf, 256, "%s/target/%s", TARGET_CORE_CONFIG_ROOT,
			config_item_name(fabric));
	/*
	 * Release the fabric's config_item reference that was obtained in
	 * target_fabric_configfs_find_by_name() -> config_group_find_item()
	 */
	config_item_put(fabric);

	printk("<<<<<<<<<<<<<<<<<<<<<< BEGIN FABRIC API >>>>>>>>>>>>>>>>>>>>>>\n");
	printk("target_fabric_configfs_unregister(): Using do_configfs_rmdir(%s)\n", buf);
	do_configfs_rmdir(&su_group->cg_item, buf);

	/*
	 * Make sure the struct config_item *fabric was released..
	 */
	if ((fabric = target_fabric_configfs_find_by_name(su, name))) {
		printk(KERN_ERR "Huh..? struct config_item: %s for fabric %s"
			" still exists\n", config_item_name(fabric), name);
		return;
	}

	printk("target_fabric_configfs_unregister(): Released Fabric: %s\n", name);
	printk("<<<<<<<<<<<<<<<<<<<<<< END FABRIC API >>>>>>>>>>>>>>>>>>>>>>\n");
	return;
}

EXPORT_SYMBOL(target_fabric_configfs_init);
EXPORT_SYMBOL(target_fabric_configfs_free);
EXPORT_SYMBOL(target_fabric_configfs_register);
EXPORT_SYMBOL(target_fabric_configfs_deregister);

//##############################################################################
// Stop functions called by external Target Fabrics Modules
//##############################################################################

//  Start functions for struct config_item_type target_core_dev_cit

static ssize_t target_core_show_dev_info (void *p, char *page)
{
	se_subsystem_dev_t *se_dev = (se_subsystem_dev_t *)p;
	se_hba_t *hba = se_dev->se_dev_hba;
	se_subsystem_api_t *t;
	int ret = 0;
	ssize_t read_bytes = 0;

	t = (se_subsystem_api_t *)plugin_get_obj(PLUGIN_TYPE_TRANSPORT, hba->type, &ret);
	if (!t || (ret != 0)) 
		return(0);
	
	{
	struct target_core_fabric_ops *iscsi_tf = target_core_get_iscsi_ops();
	int bl = 0;

	if (!(iscsi_tf))
		BUG();
	
	if (se_dev->se_dev_ptr)
		iscsi_tf->dump_dev_state(se_dev->se_dev_ptr, page, &bl);
		read_bytes += bl;
	}

	read_bytes += t->show_configfs_dev_params(hba, se_dev, page+read_bytes);
	return(read_bytes);
}

static struct target_core_configfs_attribute target_core_attr_dev_info = {
	.attr	= { .ca_owner = THIS_MODULE,
		    .ca_name = "dev_info",
		    .ca_mode = S_IRUGO },
	.show	= target_core_show_dev_info,
	.store	= NULL,
};

static ssize_t target_core_store_dev_control (void *p, const char *page, size_t count)
{
	se_subsystem_dev_t *se_dev = (se_subsystem_dev_t *)p;
	se_hba_t *hba = se_dev->se_dev_hba;
	se_subsystem_api_t *t;
	int ret = 0;

	if (!(se_dev->se_dev_su_ptr)) {
		printk(KERN_ERR "Unable to locate se_subsystem_dev_t>se_dev_su_ptr\n");
		return(-EINVAL);
	}

	t = (se_subsystem_api_t *)plugin_get_obj(PLUGIN_TYPE_TRANSPORT, hba->type, &ret);
        if (!t || (ret != 0))
		return(-EINVAL);

	return(t->set_configfs_dev_params(hba, se_dev, page, count));
}

static struct target_core_configfs_attribute target_core_attr_dev_control = {
	.attr	= { .ca_owner = THIS_MODULE,
		    .ca_name = "dev_control",
		    .ca_mode = S_IWUSR },
	.show	= NULL,
	.store	= target_core_store_dev_control,
};

static ssize_t target_core_store_dev_enable (void *p, const char *page, size_t count)
{
	se_subsystem_dev_t *se_dev = (se_subsystem_dev_t *)p;
	se_hba_t *hba = se_dev->se_dev_hba;
	se_subsystem_api_t *t;
	char *ptr;
	int ret = 0;
	
	if (!(ptr = strstr(page, "1"))) {
		printk(KERN_ERR "For dev_enable ops, only valid value is \"1\"\n");
		return(-EINVAL);
	}

	t = (se_subsystem_api_t *)plugin_get_obj(PLUGIN_TYPE_TRANSPORT, hba->type, &ret);
	if (!t || (ret != 0)) 
		return(-EINVAL);

	if (t->check_configfs_dev_params(hba, se_dev) < 0)
		return(-EINVAL);

	if (!(se_dev->se_dev_ptr = t->create_virtdevice(hba, se_dev->se_dev_su_ptr)))
		return(-EINVAL);

	printk("Target_Core_ConfigFS: Registered se_dev->se_dev_ptr: %p\n", se_dev->se_dev_ptr);
	return(count);
}

static struct target_core_configfs_attribute target_core_attr_dev_enable = {
	.attr	= { .ca_owner = THIS_MODULE,
		    .ca_name = "dev_enable",
		    .ca_mode = S_IWUSR },
	.show	= NULL,
	.store	= target_core_store_dev_enable,
};

static struct configfs_attribute *lio_core_dev_attrs[] = {
	&target_core_attr_dev_info.attr,
	&target_core_attr_dev_control.attr,
	&target_core_attr_dev_enable.attr,
	NULL,
};

static ssize_t target_core_dev_show (struct config_item *item,
				     struct configfs_attribute *attr,
				     char *page)
{
	se_subsystem_dev_t *se_dev = container_of(
			to_config_group(item), se_subsystem_dev_t, se_dev_group);
	struct target_core_configfs_attribute *tc_attr = container_of(
			attr, struct target_core_configfs_attribute, attr);

	if (!(tc_attr->show))
		return(-EINVAL);
	
	return(tc_attr->show((void *)se_dev, page));
}

static ssize_t target_core_dev_store (struct config_item *item,
				      struct configfs_attribute *attr,
				      const char *page, size_t count)
{
	se_subsystem_dev_t *se_dev = container_of(
			to_config_group(item), se_subsystem_dev_t, se_dev_group);
	struct target_core_configfs_attribute *tc_attr = container_of(
			attr, struct target_core_configfs_attribute, attr);

	if (!(tc_attr->store))
		return(-EINVAL);

	return(tc_attr->store((void *)se_dev, page, count));
}

static struct configfs_item_operations target_core_dev_item_ops = {
	.release		= NULL,
	.show_attribute		= target_core_dev_show,
	.store_attribute	= target_core_dev_store,
};

static struct config_item_type target_core_dev_cit = {
	.ct_item_ops		= &target_core_dev_item_ops,
	.ct_attrs		= lio_core_dev_attrs,
	.ct_owner		= THIS_MODULE,
};

// End functions for struct config_item_type target_core_dev_cit

// Start functions for struct config_item_type target_core_hba_cit

#warning Fix unprotected reference to hba_p
static struct config_group *target_core_call_createdev (
	struct config_group *group,
	const char *name)
{
	se_subsystem_dev_t *se_dev;	
	se_hba_t *hba, *hba_p;
	se_subsystem_api_t *t;
	struct config_item *hba_ci;
	int ret = 0;

	if (!(hba_ci = &group->cg_item)) {
		printk(KERN_ERR "Unable to locate config_item hba_ci\n");
		return(NULL);
	}

	if (!(hba_p = container_of(to_config_group(hba_ci), se_hba_t, hba_group))) {
		printk(KERN_ERR "Unable to locate se_hba_t from struct config_item\n");
		return(NULL);
	}

	if (!(hba = core_get_hba_from_id(hba_p->hba_id, 0)))
		return(NULL);
	/*
	 * Locate the se_subsystem_api_t from parent's se_hba_t.
	 */
	t = (se_subsystem_api_t *)plugin_get_obj(PLUGIN_TYPE_TRANSPORT, hba->type, &ret);
	if (!t || (ret != 0)) {
		core_put_hba(hba);
		return(NULL);
	}

	if (!(se_dev = kzalloc(sizeof(se_subsystem_dev_t), GFP_KERNEL))) {
		printk(KERN_ERR "Unable to allocate memory for se_subsystem_dev_t\n");
		return(NULL);
	}
	se_dev->se_dev_hba = hba;

	/*
	 * Set se_dev_ptr from se_subsystem_api_t returned void ptr..
	 */
	if (!(se_dev->se_dev_su_ptr = t->allocate_virtdevice(hba, name))) {
		printk(KERN_ERR "Unable to locate subsystem dependent pointer from"
				" allocate_virtdevice()\n");
		goto out;
	}

	config_group_init_type_name(&se_dev->se_dev_group, name, &target_core_dev_cit);

	printk("Target_Core_ConfigFS: Allocated se_subsystem_dev_t: %p se_dev_su_ptr: %p\n",
			se_dev, se_dev->se_dev_su_ptr);

	core_put_hba(hba);
	return(&se_dev->se_dev_group);
out:
	kfree(se_dev);
	core_put_hba(hba);
	return(NULL);
}

#warning Fix unprotected reference to hba_p
static void target_core_call_freedev (
	struct config_group *group,
	struct config_item *item)
{
	se_subsystem_dev_t *se_dev = container_of(to_config_group(item), se_subsystem_dev_t, se_dev_group);
	se_hba_t *hba, *hba_p;
	se_subsystem_api_t *t;
	int ret = 0;

	if (!(hba_p = se_dev->se_dev_hba)) {
		printk(KERN_ERR "Unable to locate se_hba_t from se_subsystem_dev_t\n");
		goto out;
	}

	if (!(hba = core_get_hba_from_id(hba_p->hba_id, 0)))
		goto out;

	t = (se_subsystem_api_t *)plugin_get_obj(PLUGIN_TYPE_TRANSPORT, hba->type, &ret);
	if (!t || (ret != 0))
		goto hba_out;

	config_item_put(item);

	/*
	 * This pointer will set when the storage is enabled with:
	 * `echo 1 > $CONFIGFS/core/$HBA/$DEV/dev_enable`
	 */	
	if (se_dev->se_dev_ptr) {
		printk("Target_Core_ConfigFS: Calling se_free_virtual_device() for"
			" se_dev_ptr: %p\n", se_dev->se_dev_ptr);

		if ((ret = se_free_virtual_device(se_dev->se_dev_ptr, hba)) < 0)
			goto hba_out;
	} else {
		/*
		 * Release se_subsystem_dev_t->se_dev_su_ptr..
		 */
		printk("Target_Core_ConfigFS: Calling t->free_device() for"
			" se_dev_su_ptr: %p\n", se_dev->se_dev_su_ptr);

		t->free_device(se_dev->se_dev_su_ptr);
	}

	printk("Target_Core_ConfigFS: Deallocating se_subsystem_dev_t: %p\n", se_dev);

hba_out:
	core_put_hba(hba);
out:
	kfree(se_dev);
	return;
}

static struct configfs_group_operations target_core_hba_group_ops = {
	.make_group		= target_core_call_createdev,
	.drop_item		= target_core_call_freedev,
};

static ssize_t target_core_hba_show (struct config_item *item,
				struct configfs_attribute *attr,
				char *page)
{
	se_hba_t *hba = container_of(to_config_group(item), se_hba_t, hba_group);

	if (!(hba)) {
		printk(KERN_ERR "Unable to locate se_hba_t\n");
		return(0);
	}

	return(sprintf(page, "HBA Index: %d plugin: %s version: %s\n",
			hba->hba_id, hba->transport->name,
			TARGET_CORE_CONFIGFS_VERSION));
}

static struct configfs_attribute target_core_hba_attr = {
	.ca_owner		= THIS_MODULE,
	.ca_name		= "hba_info",
	.ca_mode		= S_IRUGO,
};

static struct configfs_item_operations target_core_hba_item_ops = {
	.show_attribute		= target_core_hba_show,
};

static struct configfs_attribute *target_core_hba_attrs[] = {
	&target_core_hba_attr,
	NULL,
};

static struct config_item_type target_core_hba_cit = {
	.ct_item_ops		= &target_core_hba_item_ops,
	.ct_group_ops		= &target_core_hba_group_ops,
	.ct_attrs		= target_core_hba_attrs,
	.ct_owner		= THIS_MODULE,
};

static struct config_group *target_core_call_addhbatotarget (
	struct config_group *group,
	const char *name)
{
	char *se_plugin_str, *str, *endptr;
	se_hba_t *hba;
	se_hbainfo_t hba_info;
	se_plugin_t *se_plugin;
	struct iscsi_target *tg;
	char buf[TARGET_CORE_NAME_MAX_LEN];
	u32 plugin_dep_id;
	int hba_type = 0, ret;

	memset(buf, 0, TARGET_CORE_NAME_MAX_LEN);
	if (strlen(name) > TARGET_CORE_NAME_MAX_LEN) {
		printk(KERN_ERR "Passed *name strlen(): %d exceeds"
			" TARGET_CORE_NAME_MAX_LEN: %d\n", strlen(name),
			TARGET_CORE_NAME_MAX_LEN);
		return(NULL);
	}
	snprintf(buf, TARGET_CORE_NAME_MAX_LEN, "%s", name);

	if (!(str = strstr(buf, "_"))) {
		printk(KERN_ERR "Unable to locate \"_\" for $PLUGIN_$PLUGIN_ID\n");
		return(NULL);
	}
	se_plugin_str = buf;
	*str = '\0'; /* Terminate for *se_plugin_str */
	str += 1; /* Skip to start of plugin dependent ID */
	if (!(se_plugin = transport_core_get_plugin_by_name(se_plugin_str)))
		return(NULL);

	hba_type = se_plugin->plugin_type;
	plugin_dep_id = simple_strtoul(str, &endptr, 0);
	printk("Target_Core_ConfigFS: Located se_plugin: %p plugin_name: %s"
		" hba_type: %d plugin_dep_id: %u\n", se_plugin,
		se_plugin->plugin_name, hba_type, plugin_dep_id);

	if (!(hba = core_get_next_free_hba()))
		return(NULL);
	
	if (!(tg = kzalloc(sizeof(struct iscsi_target), GFP_KERNEL)))
		return(ERR_PTR(-ENOMEM));
	
#warning This should go into se_subsystem_api_t API
	switch (hba_type) {
	case PSCSI:
		tg->scsi_host_id = plugin_dep_id;
		tg->hba_params_set |= PARAM_HBA_SCSI_HOST_ID;	
		break;
	case IBLOCK:
		tg->iblock_host_id = plugin_dep_id;
		tg->hba_params_set |= PARAM_HBA_IBLOCK_HOST_ID;
		break;
	case FILEIO:
		tg->fd_host_id = plugin_dep_id;
		tg->hba_params_set |= PARAM_HBA_FD_HOST_ID;
		break;
	case RAMDISK_DR:
	case RAMDISK_MCP:
		tg->rd_host_id = plugin_dep_id;
		tg->hba_params_set |= PARAM_HBA_RD_HOST_ID;
		break;
	default:
		printk(KERN_ERR "Unable to setup hba_type: %d name: %s\n",
			hba_type, se_plugin_str);
		goto out;
	}
	tg->hba_type = hba_type;
	tg->params_set |= PARAM_HBA_TYPE;
	tg->hba_id = hba->hba_id;
	tg->params_set |= PARAM_HBA_ID;

	memset(&hba_info, 0, sizeof(se_hbainfo_t));
	hba_info.hba_id = hba->hba_id;
	hba_info.hba_type = hba_type;

	if ((ret = iscsi_hba_check_addhba_params(tg, &hba_info)) < 0)
		goto out;

	if ((ret = iscsi_hba_add_hba(hba, &hba_info, tg)) < 0)
		goto out;

	config_group_init_type_name(&hba->hba_group, name, &target_core_hba_cit);

	kfree(tg);
	core_put_hba(hba);
	return(&hba->hba_group);
out:
	kfree(tg);
	core_put_hba(hba);
	return(NULL);
}


#warning Fix unprotected reference to hba_p
static void target_core_call_delhbafromtarget (
	struct config_group *group,
	struct config_item *item)
{
	se_hba_t *hba_p = container_of(to_config_group(item), se_hba_t, hba_group);
	se_hba_t *hba = NULL;
	struct iscsi_target *tg;
	int ret;

	if (!(hba_p)) {
		printk(KERN_ERR "Unable to locate se_hba_t from struct config_item\n");
		return;
	}

	if (!(tg = kzalloc(sizeof(struct iscsi_target), GFP_KERNEL)))
		return;

	if (!(hba = core_get_hba_from_id(hba_p->hba_id, 0)))
		goto out;
	
	config_item_put(item);

	ret = iscsi_hba_del_hba(hba);
	core_put_hba(hba);
out:
	kfree(tg);
	return;

}

static struct configfs_group_operations target_core_ops = {
	.make_group	= target_core_call_addhbatotarget,
	.drop_item	= target_core_call_delhbafromtarget,
};

static struct config_item_type target_core_cit = {
//	.ct_item_ops	= &target_core_item_ops,
	.ct_group_ops	= &target_core_ops,
//	.ct_attrs	= target_core_attrs,
	.ct_owner	= THIS_MODULE,
};

// Stop functions for struct config_item_type target_core_hba_cit

extern int target_core_init_configfs (void)
{
	struct config_group *target_cg;
	struct configfs_subsystem *subsys;
	int ret;

	subsys = target_core_subsystem[0];	
	config_group_init(&subsys->su_group);
	mutex_init(&subsys->su_mutex);

	/*
	 * Create $CONFIGFS/target/core default group for HBA <-> Storage Object
	 */
	target_cg = &subsys->su_group;
	if (!(target_cg->default_groups = kzalloc(sizeof(struct config_group) * 2,
			GFP_KERNEL))) {
		printk(KERN_ERR "Unable to allocate core_cg\n");
		return(-ENOMEM);
	}

	config_group_init_type_name(&target_core_hbagroup,
		 	"core", &target_core_cit);
	target_cg->default_groups[0] = &target_core_hbagroup;
	target_cg->default_groups[1] = NULL;

	/*
	 * Initialize the global vars, and then register the target subsystem
	 * with configfs.
	 */
	INIT_LIST_HEAD(&g_tf_list);
	mutex_init(&g_tf_lock);

	if ((ret = configfs_register_subsystem(subsys)) < 0) {
		printk(KERN_ERR "Error %d while registering subsystem %s\n",
			ret, subsys->su_group.cg_item.ci_namebuf);
		return(-1);
	}

	printk("TARGET_CORE[0]: Initialized ConfigFS Fabric Infrastructure: %s\n",
                	TARGET_CORE_CONFIGFS_VERSION);

#warning FIXME: Handle failure of init_se_global()
	init_se_global();
	plugin_load_all_classes();

	return(0);
}

extern void target_core_exit_configfs (void)
{
	struct configfs_subsystem *subsys;
	struct config_item *item;
	int i;

	se_global->in_shutdown = 1;

	subsys = target_core_subsystem[0];

	for (i = 0; subsys->su_group.default_groups[i]; i++) {
		item = &subsys->su_group.default_groups[i]->cg_item;	
		subsys->su_group.default_groups[i] = NULL;
		config_item_put(item);
	}

	configfs_unregister_subsystem(subsys);

	printk("TARGET_CORE[0]: Released ConfigFS Fabric Infrastructure\n");

	plugin_unload_all_classes();
	release_se_global();

	return;
}

MODULE_AUTHOR("nab@Linux-iSCSI.org");
MODULE_LICENSE("GPL");

module_init(target_core_init_configfs);
module_exit(target_core_exit_configfs);
