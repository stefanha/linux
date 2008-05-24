/*********************************************************************************
 * Filename:  iscsi_target_seobj.h
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


#ifndef ISCSI_TARGET_SEOBJ_H
#define ISCSI_TARGET_SEOBJ_H

extern struct se_obj_lun_type_s *se_obj_get_api (u32);
extern int se_obj_load_plugins (void);

#define DEV_OBJ_VERSION		"v3.0"

typedef int (*map_func_t)(struct se_task_s *, u32);

typedef struct se_obj_lun_type_s {
	int	se_obj_type;
	struct se_plugin_s *obj_plugin;
	void (*get_obj_info)(void *, struct se_lun_s *, unsigned long long, int, char *, int *);
	void (*get_plugin_info)(void *, char *, int *);
	void *(*get_obj)(void *);
	struct se_queue_obj_s *(*get_queue_obj)(void *);
	void (*start_status_thread)(void *);
	void (*stop_status_thread)(void *);
	int (*start_status_timer)(void *);
	void (*stop_status_timer)(void *);
	int (*claim_obj)(void *);
	void (*release_obj)(void *);
	void (*inc_count)(struct se_obj_s *);
	void (*dec_count)(struct se_obj_s *);
	int (*check_count)(struct se_obj_s *);
	void (*set_feature_obj)(void *);
	void (*clear_feature_obj)(void *);
	int (*enable_feature)(void *, int, int, void *);
	void (*disable_feature)(void *);
	struct se_fp_obj_s *(*get_feature_obj)(void *);
	void (*access_obj)(void *);
	void (*deaccess_obj)(void *);
	void (*put_obj)(void *);
	int (*export_obj)(void *, struct iscsi_portal_group_s *, struct se_lun_s *);
	void (*unexport_obj)(void *, struct iscsi_portal_group_s *, struct se_lun_s *);
	int (*transport_setup_cmd)(void *, struct iscsi_cmd_s *);
	int (*active_tasks)(void *);
	int (*add_tasks)(void *, struct iscsi_cmd_s *);
	int (*execute_tasks)(void *);
	int (*depth_left)(void *);
	int (*queue_depth)(void *);
	int (*blocksize)(void *);
	int (*max_sectors)(void *);
	unsigned long long (*end_lba)(void *, int, struct se_fp_obj_s *);
	unsigned long long (*free_sectors)(void *);
	unsigned long long (*get_next_lba)(void *, unsigned long long);
	unsigned long long (*total_sectors)(void *, int, int);
	int (*do_se_mem_map)(void *, struct se_task_s *, struct list_head *, void *, struct se_mem_s *, struct se_mem_s **, u32 *, u32 *);
	int (*get_mem_buf)(void *, struct iscsi_cmd_s *);
	int (*get_mem_SG)(void *, struct iscsi_cmd_s *);
	map_func_t (*get_map_SG)(void *, int);
	map_func_t (*get_map_non_SG)(void *, int);
	map_func_t (*get_map_none)(void *);
	void *(*get_transport_req)(void *, struct se_task_s *);
	void (*free_tasks)(void *, struct iscsi_cmd_s *);
	int (*activate)(void *);
	void (*deactivate)(void *);
	void (*notify_obj)(void *);
	int (*check_export)(void *);
	int (*check_online)(void *);
	int (*check_shutdown)(void *);
	void (*fail_operations)(void *);
	void (*signal_offline)(void *);
	void (*signal_shutdown)(void *);
	void (*clear_shutdown)(void *);
	int (*obj_start)(void *, struct se_transform_info_s *, unsigned long long);
	unsigned char *(*get_cdb)(void *, struct se_task_s *);
	u32 (*get_cdb_count)(void *, struct se_transform_info_s *, unsigned long long, u32, struct se_mem_s *, struct se_mem_s **, u32 *);
	u32 (*get_cdb_size)(void *, u32, unsigned char *);
	void (*generate_cdb)(void *, unsigned long long, u32 *, unsigned char *, int);
	int (*get_device_access)(void *);
	int (*get_device_type)(void *);
	int (*check_DMA_handler)(void *);
	t10_wwn_t *(*get_t10_wwn)(void *);
	u32 *(*get_uu_id)(void *);
	int (*check_tur_bit)(void *);
	void (*clear_tur_bit)(void *);
	void (*set_tur_bit)(void *);
	void (*get_evpd_prod)(void *, unsigned char *, u32);
	void (*get_evpd_sn)(void *, unsigned char *, u32);
	int (*get_task_timeout)(void *);
	int (*set_task_timeout_handler)(void *, struct se_task_s *);
	int (*task_failure_complete)(void *, struct iscsi_cmd_s *);
	int (*add_obj_to_lun)(struct iscsi_portal_group_s *, struct se_lun_s *);
	int (*del_obj_from_lun)(struct iscsi_portal_group_s *, struct se_lun_s *);
	struct se_obj_lun_type_s *(*get_next_obj_api)(void *, void **);
	int (*obtain_obj_lock)(void *);
	int (*release_obj_lock)(void *);
} se_obj_lun_type_t;

#endif /* ISCSI_TARGET_SEOBJ_H */
