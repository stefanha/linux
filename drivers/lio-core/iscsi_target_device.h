/*********************************************************************************
 * Filename:  iscsi_target_device.h
 *
 * Copyright (c) 2003, 2004, 2005 PyX Technologies, Inc.
 * Copyright (c) 2006 SBE, Inc.  All Rights Reserved.
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


#ifndef ISCSI_TARGET_DEVICE_H
#define ISCSI_TARGET_DEVICE_H
 
extern int iscsi_check_devices_access (iscsi_hba_t *);
extern void iscsi_disable_devices_for_hba (iscsi_hba_t *);
extern void se_release_device_for_hba (iscsi_device_t *);
extern iscsi_lun_t *iscsi_get_lun (iscsi_conn_t *, u64);
extern int iscsi_get_lun_for_cmd (iscsi_cmd_t *, u64);
extern void iscsi_determine_maxcmdsn (iscsi_session_t *, iscsi_node_acl_t *);
extern void iscsi_increment_maxcmdsn (iscsi_cmd_t *, iscsi_session_t *);
extern int iscsi_set_queue_depth_for_node (iscsi_portal_group_t *, iscsi_node_acl_t *);
extern int iscsi_create_device_list_for_node (iscsi_node_acl_t *, iscsi_portal_group_t *);
extern int iscsi_free_device_list_for_node (iscsi_node_acl_t *, iscsi_portal_group_t *);
extern void iscsi_update_device_list_for_node (iscsi_lun_t *, u32, u32, iscsi_node_acl_t *, iscsi_portal_group_t *, int);     
extern void iscsi_clear_lun_from_sessions (iscsi_lun_t *, iscsi_portal_group_t *);
extern iscsi_device_t *core_get_device_from_transport (iscsi_hba_t *, iscsi_dev_transport_info_t *);
extern int se_claim_physical_device (iscsi_hba_t *, iscsi_devinfo_t *, struct iscsi_target *);
extern int se_release_physical_device (struct iscsi_target *, iscsi_devinfo_t *, iscsi_hba_t *);
extern void iscsi_clear_lun_from_tpg (iscsi_lun_t *, iscsi_portal_group_t *);
extern void se_clear_dev_ports (iscsi_device_t *);
extern int se_free_virtual_device (iscsi_device_t *, iscsi_hba_t *);
extern int iscsi_check_hba_for_virtual_device (struct iscsi_target *, iscsi_devinfo_t *, iscsi_hba_t *);
extern int iscsi_create_virtual_device (iscsi_hba_t *, iscsi_devinfo_t *, struct iscsi_target *);
extern void se_dev_start (iscsi_device_t *);
extern void se_dev_stop (iscsi_device_t *);
extern int iscsi_dev_add_lun (iscsi_portal_group_t *, iscsi_hba_t *, iscsi_device_t *, iscsi_dev_transport_info_t *);
extern int iscsi_dev_del_lun (iscsi_portal_group_t *, u32);
extern int iscsi_dev_add_initiator_node_lun_acl (iscsi_portal_group_t *, u32, u32, u32, char *);
extern int iscsi_dev_del_initiator_node_lun_acl (iscsi_portal_group_t *, u32, u32, char *);
extern int iscsi_dev_set_initiator_node_lun_access (iscsi_portal_group_t *, u32, u32, char *);
extern iscsi_hba_t *core_get_hba_from_hbaid (struct iscsi_target *tg,
					      iscsi_dev_transport_info_t *dti,
					      int add);

#endif /* ISCSI_TARGET_DEVICE_H */
