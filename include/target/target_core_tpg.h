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

extern se_global_t *se_global;
 
extern se_node_acl_t *__core_tpg_get_initiator_node_acl(se_portal_group_t *tpg,
						const char *);
extern se_node_acl_t *core_tpg_get_initiator_node_acl(se_portal_group_t *tpg,
						unsigned char *);
extern void core_tpg_add_node_to_devs(struct se_node_acl_s *,
						struct se_portal_group_s *);
extern struct se_node_acl_s *core_tpg_check_initiator_node_acl(
						struct se_portal_group_s *,
						unsigned char *);
extern void core_tpg_wait_for_nacl_pr_ref(struct se_node_acl_s *);
extern void core_tpg_clear_object_luns(struct se_portal_group_s *);
extern struct se_node_acl_s *core_tpg_add_initiator_node_acl(
					struct se_portal_group_s *,
					struct se_node_acl_s *,
					const char *, u32);
extern int core_tpg_del_initiator_node_acl(se_portal_group_t *,
						se_node_acl_t *, int);
extern int core_tpg_set_initiator_node_queue_depth(se_portal_group_t *,
						unsigned char *, u32, int);
extern int core_tpg_register(struct target_core_fabric_ops *,
					struct se_wwn_s *,
					struct se_portal_group_s *, void *,
					int);
extern int core_tpg_deregister(struct se_portal_group_s *);
extern se_lun_t *core_tpg_pre_addlun(se_portal_group_t *, u32);
extern int core_tpg_post_addlun(se_portal_group_t *, se_lun_t *, int, u32,
				void *);
extern void core_tpg_shutdown_lun(struct se_portal_group_s *,
				struct se_lun_s *);
extern se_lun_t *core_tpg_pre_dellun(se_portal_group_t *, u32, int, int *);
extern int core_tpg_post_dellun(se_portal_group_t *, se_lun_t *);

#endif /* TARGET_CORE_TPG_H */
