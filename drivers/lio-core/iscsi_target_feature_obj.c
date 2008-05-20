/*********************************************************************************
 * Filename:  iscsi_target_feature_obj.c
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


#define ISCSI_TARGET_SEOBJ_C

#include <linux/string.h>
#include <linux/timer.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/smp_lock.h>
#include <linux/in.h>

#include <iscsi_linux_os.h>
#include <iscsi_linux_defs.h>

#include <iscsi_debug.h>
#include <iscsi_protocol.h>
#include <iscsi_target_core.h>
#include <iscsi_target_ioctl.h>
#include <iscsi_target_ioctl_defs.h>
#include <iscsi_target_device.h>
#include <iscsi_target_transport.h>

#include <iscsi_target_plugin.h>
#include <iscsi_target_seobj.h>
#include <iscsi_target_feature_obj.h>

extern void ha_ap_plugin_info (void *p, char *b, int *bl)
{
	*bl += sprintf(b+*bl, "%s High Availability - Active/Passive Mode\n",
			PYX_ISCSI_VENDOR);
	return;
}

#define SE_FEATURE_HA_AP {					\
	fp_supported_obj:	FP_SO_ALL_OBJS,			\
	get_plugin_info:	ha_ap_plugin_info,		\
};

se_feature_plugin_t se_feature_ha_ap = SE_FEATURE_HA_AP;

/*
 * Returns 1 when a feature plugin located it's metadata on the passed object.
 */
extern int feature_plugin_activate (se_obj_lun_type_t *obj_api, void *obj_ptr, int vol_obj)
{
	se_plugin_class_t *pc;
	se_plugin_t *p;
	se_feature_plugin_t *fp_api;
	int i;
	
	if (!(pc = plugin_get_class(PLUGIN_TYPE_FEATURE)))
		return(-1);

	spin_lock(&pc->plugin_lock);
	for (i = 0; i < MAX_PLUGINS; i++) {	
		p = &pc->plugin_array[i];

		if (!(fp_api = (se_feature_plugin_t *)p->plugin_obj))
			continue;

		if (!fp_api->feature_activate)
			continue;
		
		if (fp_api->fp_supported_obj == FP_SO_NONE) {
			TRACE_ERROR("FEATURE_PLUGIN[%d] - fp_api->fp_supported_obj"
				" == FP_SO_NONE\n", i);
			continue;
		}

		/*
		 * Determine if this feature plugin only supports usage on volume objects.
		 */
		if ((fp_api->fp_supported_obj == FP_SO_VOL_OBJS_ONLY) && !vol_obj)
			continue;
		
		spin_unlock(&pc->plugin_lock);
		
		if ((fp_api->feature_activate(obj_api, obj_ptr)) > 0)
			return(1);

		spin_lock(&pc->plugin_lock);
	}
	spin_unlock(&pc->plugin_lock);

	return(0);
}

extern void feature_plugin_single_release (void)
{
	return;
}

static se_feature_plugin_t *feature_plugin_locate_api (int plugin_loc)
{
        se_plugin_class_t *pc;
	se_plugin_t *p;

        if (!(pc = plugin_get_class(PLUGIN_TYPE_FEATURE)))
                return(NULL);

        spin_lock(&pc->plugin_lock);
        if (plugin_loc > pc->max_plugins) {
                TRACE_ERROR("Passed plugin_loc: %u exceeds pc->max_plugins: %d\n",
                                plugin_loc, pc->max_plugins);
                goto out;
        }

        p = &pc->plugin_array[plugin_loc];
	if (!p->plugin_obj) {
                TRACE_ERROR("Passed plugin_loc: %u does not exist!\n", plugin_loc);
                goto out;
        }
	spin_unlock(&pc->plugin_lock);

	return((se_feature_plugin_t *)p->plugin_obj);
out:
	spin_unlock(&pc->plugin_lock);
	return(NULL);
}

extern se_fp_obj_t *feature_plugin_alloc (
	int fp_type,
	int fp_mode,
	void *fp_ptr,
	se_obj_lun_type_t *se_obj_api,
	void *se_obj_ptr)
{
	se_fp_obj_t *fp_obj;

	if (!se_obj_api || !se_obj_ptr) {
		TRACE_ERROR("Missing SE Object pointers!\n");
		return(NULL);
	}

	if (se_obj_api->check_online(se_obj_ptr) != 0) {
		TRACE_ERROR("se_api->check_online() failed!\n");
		return(NULL);
	}
	
	if (!(fp_obj = kmalloc(sizeof(se_fp_obj_t), GFP_KERNEL))) {
		TRACE_ERROR("Alloc for se_fp_obj_t failed\n");
		return(NULL);
	}
	memset(fp_obj, 0, sizeof(se_fp_obj_t));

	fp_obj->fp_ptr = fp_ptr;
	fp_obj->fp_mode = fp_mode;
	fp_obj->fp_type = fp_type;

	if (!(fp_obj->fp_api = feature_plugin_locate_api(fp_type))) {
		kfree(fp_obj);
		return(NULL);
	}
		
	return(fp_obj);
}

extern int feature_plugin_free (se_fp_obj_t *fp_obj)
{
	if (!fp_obj)
		return(-1);

	kfree(fp_obj);
	return(0);
}

extern void core_feature_load_plugins (void)
{
	int ret;

	ret = 0;
#if 0
	if (plugin_register((void *)&se_feature_ha_ap, FEATURE_PLUGIN_HA_AP, "HA-AP",
			PLUGIN_TYPE_FEATURE, se_feature_ha_ap.get_plugin_info, &ret) < 0) {
		TRACE_ERROR("plugin_register() for FEATURE_PLUGIN_HA_AP failed!\n");
	}
	if (plugin_register((void *)&se_feature_ha_aa, FEATURE_PLUGIN_HA_AA, "HA-AA",
			PLUGIN_TYPE_FEATURE, se_feature_ha.get_plugin_info, &ret) < 0) {
		TRACE_ERROR("plugin_register() for FEATURE_PLUGIN_HA_AA failed!\n");
	}
#endif
	return;
}
