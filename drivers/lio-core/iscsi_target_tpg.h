/*********************************************************************************
 * Filename:  iscsi_target_tpg.h
 *
 * This file contains iSCSI Target Portal Group related definitions.
 *
 * Copyright (c) 2002, 2003, 2004, 2005 PyX Technologies, Inc.
 * Copyright (c) 2005, 2006, 2007 SBE, Inc. 
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


#ifndef ISCSI_TARGET_TPG_H
#define ISCSI_TARGET_TPG_H

extern void init_iscsi_portal_groups (struct iscsi_tiqn_s *);
extern int core_load_discovery_tpg (void);
extern void core_release_discovery_tpg (void);
extern iscsi_portal_group_t *core_get_tpg_from_np (struct iscsi_tiqn_s *, struct iscsi_np_s *);
extern iscsi_portal_group_t *iscsi_get_tpg_from_tpgt (struct iscsi_tiqn_s *, __u16, int);
extern void iscsi_put_tpg (iscsi_portal_group_t *);
extern void iscsi_clear_tpg_np_login_threads (iscsi_portal_group_t *);
extern iscsi_node_acl_t *__iscsi_tpg_get_initiator_node_acl (iscsi_portal_group_t *, unsigned char *);
extern void iscsi_tpg_add_node_to_devs (iscsi_node_acl_t *, iscsi_portal_group_t *);
extern iscsi_node_acl_t *iscsi_tpg_get_initiator_node_acl (iscsi_portal_group_t *, unsigned char *);
extern iscsi_node_acl_t *iscsi_tpg_check_initiator_node_acl (iscsi_portal_group_t *, unsigned char *);
extern void iscsi_tpg_dump_params (iscsi_portal_group_t *);
extern int iscsi_tpg_persistent_reservation_check (iscsi_cmd_t *);
extern int iscsi_tpg_persistent_reservation_release (iscsi_cmd_t *);
extern int iscsi_tpg_persistent_reservation_reserve (iscsi_cmd_t *);
extern int iscsi_tpg_add_portal_group (iscsi_tiqn_t *, iscsi_portal_group_t *);
extern int iscsi_tpg_del_portal_group (iscsi_tiqn_t *, iscsi_portal_group_t *, int);
extern int iscsi_tpg_enable_portal_group (iscsi_portal_group_t *);
extern int iscsi_tpg_disable_portal_group (iscsi_portal_group_t *, int);
extern int iscsi_tpg_add_initiator_node_acl (iscsi_portal_group_t *, unsigned char *, __u32);
extern int iscsi_tpg_del_initiator_node_acl (iscsi_portal_group_t *, unsigned char *, int);
extern void iscsi_tpg_del_external_nps (iscsi_tpg_np_t *);
extern int iscsi_tpg_add_network_portal (iscsi_portal_group_t *, struct iscsi_target *, int);
extern iscsi_tpg_np_t *iscsi_tpg_del_np_phase0 (iscsi_portal_group_t *, iscsi_np_t *);
extern int iscsi_tpg_del_np_phase1 (iscsi_tpg_np_t *, iscsi_portal_group_t *, iscsi_np_t *);
extern int iscsi_tpg_del_network_portal (iscsi_portal_group_t *, struct iscsi_target *, int);
extern int iscsi_tpg_set_initiator_node_queue_depth (iscsi_portal_group_t *, unsigned char *, __u32, int);
extern se_lun_t *iscsi_tpg_pre_addlun (iscsi_portal_group_t *, u32, int *);
extern int iscsi_tpg_post_addlun (iscsi_portal_group_t *, se_lun_t *, int, u32, void *, struct se_obj_lun_type_s *);
extern se_lun_t *iscsi_tpg_pre_dellun (iscsi_portal_group_t *, u32, int, int *);
extern int iscsi_tpg_post_dellun (iscsi_portal_group_t *, se_lun_t *);
extern int iscsi_tpg_set_attributes (iscsi_portal_group_t *, __u32, __u32);
extern void iscsi_disable_tpgs (struct iscsi_tiqn_s *);
extern void iscsi_disable_all_tpgs (void);
extern void iscsi_remove_tpgs (struct iscsi_tiqn_s *);
extern void iscsi_remove_all_tpgs (void);

#endif /* ISCSI_TARGET_TPG_H */
