/*******************************************************************************
 * Filename:  target_core_tpg.h
 *
 * This file contains generic Target Portal Group related definitions.
 *
 * Copyright (c) 2002, 2003, 2004, 2005 PyX Technologies, Inc.
 * Copyright (c) 2005, 2006, 2007 SBE, Inc.
 * Copyright (c) 2007-2009 Rising Tide Software, Inc.
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
 ******************************************************************************/


#ifndef TARGET_CORE_TPG_H
#define TARGET_CORE_TPG_H

extern struct se_global *se_global;
 
extern struct se_node_acl *__core_tpg_get_initiator_node_acl(struct se_portal_group *tpg,
						const char *);
extern struct se_node_acl *core_tpg_get_initiator_node_acl(struct se_portal_group *tpg,
						unsigned char *);
extern void core_tpg_add_node_to_devs(struct se_node_acl *,
						struct se_portal_group *);
extern struct se_node_acl *core_tpg_check_initiator_node_acl(
						struct se_portal_group *,
						unsigned char *);
extern void core_tpg_wait_for_nacl_pr_ref(struct se_node_acl *);
extern void core_tpg_clear_object_luns(struct se_portal_group *);
extern struct se_node_acl *core_tpg_add_initiator_node_acl(
					struct se_portal_group *,
					struct se_node_acl *,
					const char *, u32);
extern int core_tpg_del_initiator_node_acl(struct se_portal_group *,
						struct se_node_acl *, int);
extern int core_tpg_set_initiator_node_queue_depth(struct se_portal_group *,
						unsigned char *, u32, int);
extern int core_tpg_register(struct target_core_fabric_ops *,
					struct se_wwn *,
					struct se_portal_group *, void *,
					int);
extern int core_tpg_deregister(struct se_portal_group *);
extern struct se_lun *core_tpg_pre_addlun(struct se_portal_group *, u32);
extern int core_tpg_post_addlun(struct se_portal_group *, struct se_lun *, int, u32,
				void *);
extern void core_tpg_shutdown_lun(struct se_portal_group *,
				struct se_lun *);
extern struct se_lun *core_tpg_pre_dellun(struct se_portal_group *, u32, int, int *);
extern int core_tpg_post_dellun(struct se_portal_group *, struct se_lun *);

#endif /* TARGET_CORE_TPG_H */
