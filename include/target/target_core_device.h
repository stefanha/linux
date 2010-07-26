/*******************************************************************************
 * Filename:  target_core_device.h
 *
 * Copyright (c) 2003, 2004, 2005 PyX Technologies, Inc.
 * Copyright (c) 2006 SBE, Inc.  All Rights Reserved.
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


#ifndef TARGET_CORE_DEVICE_H
#define TARGET_CORE_DEVICE_H

extern struct se_global *se_global;

extern struct block_device *__linux_blockdevice_claim(int, int, void *, int *);
extern struct block_device *linux_blockdevice_claim(int, int, void *);
extern int linux_blockdevice_release(int, int, struct block_device *);
extern int linux_blockdevice_check(int, int);
extern void se_disable_devices_for_hba(struct se_hba *);
extern int transport_get_lun_for_cmd(struct se_cmd *, unsigned char *, u32);
extern int transport_get_lun_for_tmr(struct se_cmd *, u32);
extern struct se_dev_entry *core_get_se_deve_from_rtpi(
					struct se_node_acl *, u16);
extern int core_free_device_list_for_node(struct se_node_acl *,
					struct se_portal_group *);
extern void core_dec_lacl_count(struct se_node_acl *, struct se_cmd *);
extern void core_update_device_list_access(u32, u32, struct se_node_acl *);
extern int core_update_device_list_for_node(struct se_lun *, struct se_lun_acl *, u32,
					u32, struct se_node_acl *,
					struct se_portal_group *, int);
extern void core_clear_lun_from_tpg(struct se_lun *, struct se_portal_group *);
extern struct se_port *core_alloc_port(struct se_device *);
extern void core_export_port(struct se_device *, struct se_portal_group *,
					struct se_port *, struct se_lun *);
extern void core_release_port(struct se_device *, struct se_port *);
extern int transport_core_report_lun_response(struct se_cmd *);
extern void se_release_device_for_hba(struct se_device *);
extern void se_release_vpd_for_dev(struct se_device *);
extern void se_clear_dev_ports(struct se_device *);
extern int se_free_virtual_device(struct se_device *, struct se_hba *);
extern void se_dev_start(struct se_device *);
extern void se_dev_stop(struct se_device *);
extern void se_dev_set_default_attribs(struct se_device *);
extern int se_dev_set_task_timeout(struct se_device *, u32);
extern int se_dev_set_emulate_ua_intlck_ctrl(struct se_device *, int);
extern int se_dev_set_emulate_tas(struct se_device *, int);
extern int se_dev_set_enforce_pr_isids(struct se_device *, int);
extern int se_dev_set_queue_depth(struct se_device *, u32);
extern int se_dev_set_max_sectors(struct se_device *, u32);
extern int se_dev_set_block_size(struct se_device *, u32);
extern struct se_lun *core_dev_add_lun(struct se_portal_group *, struct se_hba *,
					struct se_device *, u32);
extern int core_dev_del_lun(struct se_portal_group *, u32);
extern struct se_lun *core_get_lun_from_tpg(struct se_portal_group *, u32);
extern struct se_lun_acl *core_dev_init_initiator_node_lun_acl(struct se_portal_group *,
							u32, char *, int *);
extern int core_dev_add_initiator_node_lun_acl(struct se_portal_group *,
						struct se_lun_acl *, u32, u32);
extern int core_dev_del_initiator_node_lun_acl(struct se_portal_group *,
						struct se_lun *, struct se_lun_acl *);
extern void core_dev_free_initiator_node_lun_acl(struct se_portal_group *,
						struct se_lun_acl *lacl);
extern int core_dev_setup_virtual_lun0(void);
extern void core_dev_release_virtual_lun0(void);

#endif /* TARGET_CORE_DEVICE_H */
