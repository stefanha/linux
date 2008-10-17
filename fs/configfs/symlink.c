/* -*- mode: c; c-basic-offset: 8; -*-
 * vim: noexpandtab sw=8 ts=8 sts=0:
 *
 * symlink.c - operations for configfs symlinks.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public
 * License along with this program; if not, write to the
 * Free Software Foundation, Inc., 59 Temple Place - Suite 330,
 * Boston, MA 021110-1307, USA.
 *
 * Based on sysfs:
 * 	sysfs is Copyright (C) 2001, 2002, 2003 Patrick Mochel
 *
 * configfs Copyright (C) 2005 Oracle.  All rights reserved.
 *
 * Added ConfigFS <-> SysFS Symlink support for Linux-ISCSI.org
 * Copyright (C) 2008 Nicholas A. Bellinger <nab@kernel.org>
 */

#include <linux/fs.h>
#include <linux/module.h>
#include <linux/namei.h>
#include <linux/sysfs.h>
#include <linux/kobject.h>
#include <linux/configfs.h>
#include "configfs_internal.h"
#include "../sysfs/sysfs.h" // SysFS Internal

/* Protects attachments of new symlinks */
DEFINE_MUTEX(configfs_symlink_mutex);

/* Used for sysfs kobject symlinks */
extern struct super_block *sysfs_sb;

static int item_depth(struct config_item * item)
{
	struct config_item * p = item;
	int depth = 0;
	do { depth++; } while ((p = p->ci_parent) && !configfs_is_root(p));
	return depth;
}

static int item_path_length(struct config_item * item)
{
	struct config_item * p = item;
	int length = 1;
	do {
		length += strlen(config_item_name(p)) + 1;
		p = p->ci_parent;
	} while (p && !configfs_is_root(p));
	return length;
}

static void fill_item_path(struct config_item * item, char * buffer, int length)
{
	struct config_item * p;

	--length;
	for (p = item; p && !configfs_is_root(p); p = p->ci_parent) {
		int cur = strlen(config_item_name(p));

		/* back up enough to print this bus id with '/' */
		length -= cur;
		strncpy(buffer + length,config_item_name(p),cur);
		*(buffer + --length) = '/';
	}
}

static int create_link(struct config_item *parent_item,
		       struct config_item *item,
		       struct dentry *dentry)
{
	struct configfs_dirent *target_sd = item->ci_dentry->d_fsdata;
	struct configfs_symlink *sl;
	int ret;

	ret = -ENOENT;
	if (!configfs_dirent_is_ready(target_sd))
		goto out;
	ret = -ENOMEM;
	sl = kzalloc(sizeof(struct configfs_symlink), GFP_KERNEL);
	if (sl) {
		sl->sl_target = config_item_get(item);
		spin_lock(&configfs_dirent_lock);
		if (target_sd->s_type & CONFIGFS_USET_DROPPING) {
			spin_unlock(&configfs_dirent_lock);
			config_item_put(item);
			kfree(sl);
			return -ENOENT;
		}
		list_add(&sl->sl_list, &target_sd->s_links);
		spin_unlock(&configfs_dirent_lock);
		ret = configfs_create_link(sl, parent_item->ci_dentry,
					   dentry);
		if (ret) {
			spin_lock(&configfs_dirent_lock);
			list_del_init(&sl->sl_list);
			spin_unlock(&configfs_dirent_lock);
			config_item_put(item);
			kfree(sl);
		}
	}

out:
	return ret;
}

static int create_link_sysfs(struct config_item *parent_item,
			     struct kobject *kobj,
			     struct dentry *dentry)
{
	struct configfs_symlink *sl;
	int ret = -ENOMEM;

	sl = kzalloc(sizeof(struct configfs_symlink), GFP_KERNEL);
	if (sl) {
		/*
		 * Grab the reference to sysfs's struct kobject.
		 * It will be released in configfs_unlink().
		 */
		sl->sl_kobject = kobject_get(kobj);

		ret = configfs_create_link(sl, parent_item->ci_dentry, dentry);
		if (ret) { 
			kobject_put(kobj);
			kfree(sl);
		}
	}

	return ret;
}

int configfs_symlink(struct inode *dir, struct dentry *dentry, const char *symname)
{
	int ret;
	struct nameidata nd;
	struct configfs_dirent *sd;
	struct config_item *parent_item = NULL;
	struct config_item *target_item;
	struct config_item_type *type;

	ret = -EPERM;  /* What lack-of-symlink returns */
	if (dentry->d_parent == configfs_sb->s_root)
		goto out;

	sd = dentry->d_parent->d_fsdata;
	/*
	 * Fake invisibility if dir belongs to a group/default groups hierarchy
	 * being attached
	 */
	ret = -ENOENT;
	if (!configfs_dirent_is_ready(sd))
		goto out;

	parent_item = configfs_get_config_item(dentry->d_parent);
	type = parent_item->ci_type;

	ret = -EPERM;
	if (!type || !type->ct_item_ops ||
	    (!(type->ct_item_ops->allow_link) &&
	     !(type->ct_item_ops->allow_link_kobject)))
		goto out;
	/*
	 * Populate struct nameidata nd with Symlink SOURCE fs/ pointers..
	 */
	if ((ret = path_lookup(symname, LOOKUP_FOLLOW|LOOKUP_DIRECTORY, &nd)) < 0)
		goto out_put;
	/*
	 * First check if the symlink destination is coming from a configfs
	 * struct config_item..
	 */
	if (nd.path.dentry->d_sb == configfs_sb) {
		if (!(type->ct_item_ops->allow_link)) {
			ret = -EPERM;
			goto out_put;
		}
		if (!(target_item = configfs_get_config_item(nd.path.dentry))) {
			ret = -ENOENT;
			goto out_put;
		}
		if (!(ret = type->ct_item_ops->allow_link(parent_item, target_item))) {
			mutex_lock(&configfs_symlink_mutex);
			ret = create_link(parent_item, target_item, dentry);
			mutex_unlock(&configfs_symlink_mutex);
			if (ret && type->ct_item_ops->drop_link)
				type->ct_item_ops->drop_link(parent_item,
							     target_item);
		}
		/*
		 * Release reference to ConfigFS Symlink SOURCE from 
		 * configfs_get_config_item()
		 */
		config_item_put(target_item);
//	} else if (nd.path.dentry->d_sb == sysfs_sb) {
#warning FIXME: How to determine which nameidata is from sysfs..?
	} else if (1) {
		struct sysfs_dirent *sd = (struct sysfs_dirent *)nd.path.dentry->d_fsdata;
		struct kobject *kobj = sd->s_dir.kobj;

		if (!(type->ct_item_ops->allow_link_kobject)) {
			ret = -EPERM;
			goto out_put;
		}
		/*
		 * Now from a sysfs struct kobject..
		 */
		printk("Using struct kobject: %s for symlink source, %s configfs destination\n",
				kobject_name(kobj), config_item_name(parent_item));

		if (!(ret = type->ct_item_ops->allow_link_kobject(parent_item, kobj))) {
			mutex_lock(&configfs_symlink_mutex);
			ret = create_link_sysfs(parent_item, kobj, dentry);
			mutex_unlock(&configfs_symlink_mutex);
			if (ret && type->ct_item_ops->drop_link_kobject)
				type->ct_item_ops->drop_link_kobject(parent_item,
								     kobj);
		}
	} else {
		ret = -EPERM;
		goto out_put;
	}

out_put:
	path_put(&nd.path);
out:
	config_item_put(parent_item);
	return ret;
}

int configfs_unlink(struct inode *dir, struct dentry *dentry)
{
	struct configfs_dirent *sd = dentry->d_fsdata;
	struct configfs_symlink *sl;
	struct config_item *parent_item;
	struct config_item_type *type;
	int ret;

	ret = -EPERM;  /* What lack-of-symlink returns */
	if (!(sd->s_type & CONFIGFS_ITEM_LINK))
		goto out;

	BUG_ON(dentry->d_parent == configfs_sb->s_root);

	sl = sd->s_element;

	parent_item = configfs_get_config_item(dentry->d_parent);
	type = parent_item->ci_type;

	spin_lock(&configfs_dirent_lock);
	list_del_init(&sd->s_sibling);
	spin_unlock(&configfs_dirent_lock);
	configfs_drop_dentry(sd, dentry->d_parent);
	dput(dentry);
	configfs_put(sd);

	if (sl->sl_target) {
		/*
		 * drop_link() must be called before list_del_init(&sl->sl_list),
		 * so that the order of drop_link(this, target) and drop_item(target)
		 * is preserved.
		 */
		if (type && type->ct_item_ops &&
		    type->ct_item_ops->drop_link)
			type->ct_item_ops->drop_link(parent_item, sl->sl_target);

		spin_lock(&configfs_dirent_lock);
		list_del_init(&sl->sl_list);
		spin_unlock(&configfs_dirent_lock);
		/*
		 * Put reference from create_link()
		 */
		config_item_put(sl->sl_target);
		sl->sl_target = NULL;
	} else if (sl->sl_kobject) {
		if (type && type->ct_item_ops &&
		   type->ct_item_ops->drop_link_kobject)
			type->ct_item_ops->drop_link_kobject(parent_item, sl->sl_kobject);
		/*
		 * Put reference from create_link_sysfs()
		 */
		kobject_put(sl->sl_kobject);
		sl->sl_kobject = NULL;
	}
	kfree(sl);

	config_item_put(parent_item);

	ret = 0;

out:
	return ret;
}

static int configfs_get_target_path(struct config_item * item, struct config_item * target,
				   char *path)
{
	char * s;
	int depth, size;

	depth = item_depth(item);
	size = item_path_length(target) + depth * 3 - 1;
	if (size > PATH_MAX)
		return -ENAMETOOLONG;

	pr_debug("%s: depth = %d, size = %d\n", __func__, depth, size);

	for (s = path; depth--; s += 3)
		strcpy(s,"../");

	fill_item_path(target, path, size);
	pr_debug("%s: path = '%s'\n", __func__, path);

	return 0;
}

static int configfs_getlink(struct dentry *dentry, char * path)
{
	struct config_item *item, *target_item;
	int error = 0;

	item = configfs_get_config_item(dentry->d_parent);
	if (!item)
		return -EINVAL;

	target_item = configfs_get_config_item(dentry);
	if (!target_item) {
		config_item_put(item);
		return -EINVAL;
	}

	down_read(&configfs_rename_sem);
	error = configfs_get_target_path(item, target_item, path);
	up_read(&configfs_rename_sem);

	config_item_put(item);
	config_item_put(target_item);
	return error;

}

static void *configfs_follow_link(struct dentry *dentry, struct nameidata *nd)
{
	int error = -ENOMEM;
	unsigned long page = get_zeroed_page(GFP_KERNEL);

	if (page) {
		error = configfs_getlink(dentry, (char *)page);
		if (!error) {
			nd_set_link(nd, (char *)page);
			return (void *)page;
		}
	}

	nd_set_link(nd, ERR_PTR(error));
	return NULL;
}

static void configfs_put_link(struct dentry *dentry, struct nameidata *nd,
			      void *cookie)
{
	if (cookie) {
		unsigned long page = (unsigned long)cookie;
		free_page(page);
	}
}

const struct inode_operations configfs_symlink_inode_operations = {
	.follow_link = configfs_follow_link,
	.readlink = generic_readlink,
	.put_link = configfs_put_link,
	.setattr = configfs_setattr,
};

