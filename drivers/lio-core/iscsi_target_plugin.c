/*********************************************************************************
 * Filename:  iscsi_target_plugin.c
 *
 * Copyright (c) 2006-2007 SBE, Inc.  All Rights Reserved.
 * Copyright (c) 2007 Rising Tide Software, Inc.
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
 *********************************************************************************/

#define ISCSI_TARGET_PLUGIN_C

#include <linux/net.h>
#include <linux/string.h>
#include <linux/timer.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/smp_lock.h>
#include <linux/in.h>
#include <net/sock.h>
#include <net/tcp.h>

#include <iscsi_linux_os.h>
#include <iscsi_linux_defs.h>

#include <iscsi_lists.h>
#include <iscsi_debug.h>
#include <iscsi_protocol.h>
#include <iscsi_target_core.h>
#include <iscsi_target_error.h>
#include <iscsi_target_ioctl.h>
#include <iscsi_target_ioctl_defs.h>
#include <iscsi_target_device.h>
#include <iscsi_target_hba.h>
#include <iscsi_target_seobj.h>
#include <iscsi_target_tpg.h>
#include <iscsi_target_transport.h>
#include <iscsi_target_util.h>
#include <iscsi_target_plugin.h>
#include <iscsi_target_feature_obj.h>

#undef ISCSI_TARGET_PLUGIN_C

extern iscsi_global_t *iscsi_global;

extern void plugin_load_all_classes (void)
{
	/*
	 * Setup Frontend Plugins
	 */
	plugin_register_class(PLUGIN_TYPE_FRONTEND, "FRONTEND", MAX_PLUGINS);
	frontend_load_plugins();

	/*
	 * Setup Transport Plugins
	 */
	plugin_register_class(PLUGIN_TYPE_TRANSPORT, "TRANSPORT", MAX_PLUGINS);
	transport_load_plugins();
	
	/*
	 * Setup Storage Engine Object Plugins
	 */
	plugin_register_class(PLUGIN_TYPE_OBJ, "OBJ", MAX_PLUGINS);
	se_obj_load_plugins();
		
	/*
	 * Setup Feature Plugins 
	 */
	plugin_register_class(PLUGIN_TYPE_FEATURE, "FEATURE", MAX_PLUGINS);
	core_feature_load_plugins();
	
	return;
}

extern se_plugin_class_t *plugin_get_class (
	u32 plugin_class_type)
{
	se_plugin_class_t *pc;

	if (plugin_class_type > MAX_PLUGIN_CLASSES) {
		TRACE_ERROR("Passed plugin class type: %u exceeds MAX_PLUGIN_CLASSES: %d\n",
			 plugin_class_type, MAX_PLUGIN_CLASSES);
		return(NULL);
	}

	pc = &iscsi_global->plugin_class_list[plugin_class_type];
	if (!pc->plugin_array) {
		TRACE_ERROR("Plugin Class Type: %u does not exist!\n", plugin_class_type);
		return(NULL);
	}

	return(pc);
}

extern int plugin_register_class (
	u32 plugin_class_type,
	unsigned char *plugin_class_name,
	int max_plugins)
{
	u32 i;
	se_plugin_class_t *pc;
	se_plugin_t *p;

	if (strlen(plugin_class_name) > MAX_PLUGIN_CLASS_NAME) {
		TRACE_ERROR("plugin_class_name exceeds MAX_PLUGIN_CLASS_NAME: %u\n",
				MAX_PLUGIN_CLASS_NAME);
		return(-1);
	}
	spin_lock(&iscsi_global->plugin_class_lock);
	if (plugin_class_type > MAX_PLUGIN_CLASSES) {
		TRACE_ERROR("Passed plugin class type: %u exceeds MAX_PLUGIN_CLASSES: %d\n",
				plugin_class_type, MAX_PLUGIN_CLASSES);
		return(-1);
	}

	pc = &iscsi_global->plugin_class_list[plugin_class_type];
	if (pc->plugin_array) {
		TRACE_ERROR("Plugin Class Type: %u already exists\n", plugin_class_type);
		return(-1);
	}
	spin_unlock(&iscsi_global->plugin_class_lock);
		
	if (!(pc->plugin_array = kmalloc(sizeof(se_plugin_t) * max_plugins, GFP_KERNEL))) {
		TRACE_ERROR("Unable to locate pc->plugin_array\n");
		return(-1);
	}
	memset(pc->plugin_array, 0, sizeof(se_plugin_t) * max_plugins);

	spin_lock_init(&pc->plugin_lock);
	pc->max_plugins = max_plugins;
	pc->plugin_class = plugin_class_type;
	snprintf(pc->plugin_class_name, MAX_PLUGIN_CLASS_NAME,
		"%s", plugin_class_name);
	
	for (i = 0; i < max_plugins; i++) {
		p = &pc->plugin_array[i];
		p->plugin_class = pc;
	}
	
	printk("SE_PC[%u] - Registered Plugin Class: %s\n", pc->plugin_class,
		       	pc->plugin_class_name);
	
	return(0);
}

extern int plugin_deregister_class (u32 plugin_class_type)
{
	int i;
	se_plugin_class_t *pc;
	se_plugin_t *p;

	if (!(pc = plugin_get_class(plugin_class_type)))
		return(-1);	
		
	for (i = 0; i < MAX_PLUGINS; i++) {
		p = &pc->plugin_array[i];	

		if (!p->plugin_obj)
			continue;

		plugin_deregister(i, plugin_class_type);
	}

	kfree(pc->plugin_array);
	pc->plugin_array = NULL;
	
	return(0);
}

extern void plugin_unload_all_classes (void)
{
	u32 i;
	se_plugin_class_t *pc;

	for (i = 0; i < MAX_PLUGIN_CLASSES; i++) {
		pc = &iscsi_global->plugin_class_list[i];

		if (!pc->plugin_array)
			continue;
		
		plugin_deregister_class(i);
	}

	return;
}

extern void *plugin_get_obj (
	u32 plugin_class,
	u32 plugin_loc,
	int *ret)
{
	se_plugin_class_t *pc;
	se_plugin_t *p;

	if (!(pc = plugin_get_class(plugin_class)))
		return(NULL);	

	spin_lock(&pc->plugin_lock);
	if (plugin_loc > pc->max_plugins) {
		TRACE_ERROR("Passed plugin_loc: %d exceeds pc->max_plugins: %d\n",
				plugin_loc, pc->max_plugins);
		goto out;
	}

	p = &pc->plugin_array[plugin_loc];
	if (!p->plugin_obj) {
		TRACE_ERROR("Passed plugin_loc: %u does not exist!\n", plugin_loc);
		goto out;
	}
	spin_unlock(&pc->plugin_lock);

	return(p->plugin_obj);
out:
	*ret = -1;
	spin_unlock(&pc->plugin_lock);
	return(NULL);
}

extern struct se_plugin_s *plugin_register (
	void *obj,
	u32 plugin_loc,
	unsigned char *plugin_name,
	u32 plugin_class,
	void (*get_plugin_info)(void *, char *, int *),
	int *ret)
{
	se_plugin_class_t *pc;
	se_plugin_t *p;

	if (!obj) {
		TRACE_ERROR("obj or plugin_class pointers are NULL!\n");
		return(NULL);
	}
	
	if (strlen(plugin_name) > MAX_PLUGIN_NAME) {
		TRACE_ERROR("plugin_name exceeds MAX_PLUGIN_NAME: %u\n",
				MAX_PLUGIN_NAME);
		return(NULL);
	}

	if (!(pc = plugin_get_class(plugin_class)))
		return(NULL);
	
	spin_lock(&pc->plugin_lock);
	if (plugin_loc > pc->max_plugins) {
		TRACE_ERROR("Passed plugin_loc: %u exceeds pc->max_plugins: %d\n",
				plugin_loc, pc->max_plugins);
		*ret = -1;
		goto out;
	}

	p = &pc->plugin_array[plugin_loc];
	if (p->plugin_obj) {
		TRACE_ERROR("Passed plugin_loc: %u already registered\n", plugin_loc);
		*ret = -1;
		goto out;
	}
	
	p->plugin_obj = obj;
	p->get_plugin_info = get_plugin_info;
	p->plugin_state = PLUGIN_REGISTERED;
	p->plugin_type = plugin_loc;
	snprintf(p->plugin_name, MAX_PLUGIN_NAME, "%s", plugin_name);

	printk("PLUGIN_%s[%u] - %s registered\n", pc->plugin_class_name,
			plugin_loc, plugin_name);
	spin_unlock(&pc->plugin_lock);

	return(p);

out:
	spin_unlock(&pc->plugin_lock);
	return(NULL);
}

extern int plugin_deregister (
	u32 plugin_loc,
	u32 plugin_class)
{
	int ret = 0;
	se_plugin_class_t *pc;
	se_plugin_t *p;

	if (!(pc = plugin_get_class(plugin_class)))
		return(-1);

	spin_lock(&pc->plugin_lock);
	if (plugin_loc > pc->max_plugins) {
		TRACE_ERROR("Passed plugin_loc: %u exceeds pc->max_plugins: %d\n",
				plugin_loc, pc->max_plugins);
		ret = -1;
		goto out;
	}

	p = &pc->plugin_array[plugin_loc];
	if (!p->plugin_obj) {
		TRACE_ERROR("Passed plugin_loc: %u not active!\n", plugin_loc);
		ret = -1;
		goto out;
	}

	p->plugin_obj = NULL;
	p->plugin_state = PLUGIN_FREE;

out:
	spin_unlock(&pc->plugin_lock);
	return(ret);
}
