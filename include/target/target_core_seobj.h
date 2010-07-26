/*******************************************************************************
 * Filename:  target_core_seobj.h
 *
 * Copyright (c) 2006-2007 SBE, Inc.  All Rights Reserved.
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


#ifndef TARGET_CORE_SEOBJ_H
#define TARGET_CORE_SEOBJ_H

typedef int (*map_func_t)(struct se_task_s *, u32);

extern int dev_obj_export(void *, se_portal_group_t *, se_lun_t *);
extern void dev_obj_unexport(void *, se_portal_group_t *, se_lun_t *);
extern int dev_obj_max_sectors(void *);
extern unsigned long long dev_obj_end_lba(void *);
extern int dev_obj_do_se_mem_map(void *, se_task_t *, struct list_head *,
			void *, struct se_mem_s *, struct se_mem_s **,
			u32 *, u32 *);
extern int dev_obj_get_mem_buf(void *, se_cmd_t *);
extern int dev_obj_get_mem_SG(void *, se_cmd_t *);
extern map_func_t dev_obj_get_map_SG(void *, int);
extern map_func_t dev_obj_get_map_non_SG(void *, int);
extern map_func_t dev_obj_get_map_none(void *);
extern int dev_obj_check_online(void *);
extern int dev_obj_check_shutdown(void *);

#endif /* TARGET_CORE_SEOBJ_H */
