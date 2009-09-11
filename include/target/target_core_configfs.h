/***************************************************************************
 * Filename:  target_core_configfs.h
 *
 * This file contains the configfs defines and prototypes for the
 * Generic Target Engine project.
 *
 * Copyright (c) 2008-2009 Rising Tide, Inc.
 * Copyright (c) 2008-2009 Linux-iSCSI.org
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
 *********************************************************************/

#define TARGET_CORE_CONFIGFS_VERSION "v2.0.0"

#define TARGET_CORE_CONFIG_ROOT	"/sys/kernel/config"

#define TARGET_CORE_NAME_MAX_LEN	64
#define TARGET_FABRIC_NAME_SIZE		32

extern se_global_t *se_global;

extern struct se_hba_s *target_core_get_hba_from_item(struct config_item *);
extern struct target_fabric_configfs *target_fabric_configfs_init(
				struct config_item_type *, const char *name);
extern void target_fabric_configfs_free(struct target_fabric_configfs *);
extern int target_fabric_configfs_register(struct target_fabric_configfs *);
extern void target_fabric_configfs_deregister(struct target_fabric_configfs *);
extern int target_core_init_configfs(void);
extern void target_core_exit_configfs(void);

struct target_fabric_configfs {
	char			tf_name[TARGET_FABRIC_NAME_SIZE];
	atomic_t		tf_access_cnt;
	void (*reg_default_groups_callback)(struct target_fabric_configfs *);
	struct list_head	tf_list;
	struct config_group	tf_group;
	/* Pointer to fabric's config_item */
	struct config_item	*tf_fabric;
	/* Passed from fabric modules */
	struct config_item_type	*tf_fabric_cit;
	/* Pointer to target core subsystem */
	struct configfs_subsystem *tf_subsys;
	struct target_core_fabric_ops tf_ops;
};
