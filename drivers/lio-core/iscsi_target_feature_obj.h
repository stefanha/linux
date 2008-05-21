/*********************************************************************************
 * Filename:  iscsi_target_feature_obj.h
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


#ifndef _ISCSI_TARGET_FEATURE_OBJ_H_
#define _ISCSI_TARGET_FEATURE_OBJ_H_

#define PYX_SE_VERSION		"v3.0"

#define FP_SO_NONE		0
#define FP_SO_VOL_OBJS_ONLY	1
#define FP_SO_ALL_OBJS		2

typedef struct se_feature_plugin_s {
	int fp_supported_obj;
        void (*get_plugin_info)(void *, char *, int *);
	void (*get_feature_info)(void *, char *, int *);
	void (*get_export_info)(void *, struct iscsi_lun_s *, char *, int *);
	int (*feature_activate)(struct se_obj_lun_type_s *, void *);
	int (*feature_destroy)(struct se_fp_obj_s *);
	int (*feature_release)(struct se_fp_obj_s *);
	int (*feature_io)(struct se_fp_obj_s *, struct iscsi_cmd_s *);
	void (*feature_io_check_lun)(struct se_fp_obj_s *, struct iscsi_cmd_s *);
	int (*feature_resize)(struct se_fp_obj_s *, struct se_obj_lun_type_s *, void *, unsigned long long);
	unsigned long long (*feature_sectors_resize)(struct se_fp_obj_s *, unsigned long long, unsigned long long);
	int (*feature_element_offline)(struct se_fp_obj_s *);
	int (*feature_element_online)(struct se_fp_obj_s *);
	int (*feature_inquiry)(struct se_fp_obj_s *, struct iscsi_cmd_s *, unsigned char *, unsigned char *);
	unsigned long long (*feature_read_capacity_16)(struct se_fp_obj_s *, struct iscsi_cmd_s *);
	u32 (*feature_metadata_size)(struct se_fp_obj_s *);
} se_feature_plugin_t;

#define FP_MODE_NONE		0
#define FP_MODE_SINGLE		1
#define FP_MODE_GROUPED		2

typedef struct se_fp_obj_s {
	int			fp_type;
	int			fp_mode;
	void			*fp_ptr;
	struct se_feature_plugin_s *fp_api;
} se_fp_obj_t;

extern int feature_plugin_activate (struct se_obj_lun_type_s *, void *, int);
extern void feature_plugin_single_release (void);
extern struct se_fp_obj_s *feature_plugin_alloc (int, int, void *, struct se_obj_lun_type_s *, void *);
extern int feature_plugin_free (se_fp_obj_t *);
extern void core_feature_load_plugins (void);

#endif   /*** _ISCSI_TARGET_FEATURE_OBJ_H_ ***/
