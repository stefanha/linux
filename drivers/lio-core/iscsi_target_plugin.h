/*********************************************************************************
 * Filename:  iscsi_target_plugin.h
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


#ifndef ISCSI_TARGET_PLUGIN_H
#define ISCSI_TARGET_PLUGIN_H

#define PLUGIN_TYPE_FRONTEND	0
#define PLUGIN_TYPE_TRANSPORT	1
#define PLUGIN_TYPE_OBJ		2
#define PLUGIN_TYPE_FEATURE	3

#define FRONTEND_RFC3720_TCP	0
#define FRONTEND_RFC3720_SCTP	1
#define FRONTEND_ISER_IWARP_TCP	2
#define FRONTEND_ISER_IWARP_SCTP 3
#define FRONTEND_ISER_IB	4

#define FEATURE_PLUGIN_RAID	0 /* Currently used for replication.. */
#define FEATURE_PLUGIN_MIRROR	0 /* used for online replication */
#define FEATURE_PLUGIN_SNAP	1 /* used for snapshot */
#define FEATURE_PLUGIN_HA_AP	2 /* active-passive high availability */
#define FEATURE_PLUGIN_HA_AA	3 /* active-active high availability */
#define FEATURE_PLUGIN_REPL	4 /* used for offline replication */

#define MAX_PLUGINS		32
#define MAX_PLUGIN_CLASSES	16
#define MAX_PLUGIN_CLASS_NAME	16
#define MAX_PLUGIN_NAME		16

#define PLUGIN_FREE		0
#define PLUGIN_REGISTERED	1

extern void plugin_load_all_classes (void);
extern struct se_plugin_class_s *plugin_get_class (u32);
extern int plugin_register_class (u32, unsigned char *, int);
extern int plugin_deregister_class (u32);
extern void plugin_unload_all_classes (void);
extern void *plugin_get_obj (u32, u32, int *);
extern struct se_plugin_s *plugin_register (void *, u32, unsigned char *, u32, void (*get_plugin_info)(void *, char *, int *), int *);
extern int plugin_deregister (u32, u32);

typedef struct se_plugin_class_s {
	unsigned char		plugin_class_name[MAX_PLUGIN_CLASS_NAME];
	u32			plugin_class;
	u32			max_plugins;
	struct se_plugin_s	*plugin_array;
	spinlock_t		plugin_lock;
} se_plugin_class_t;
	
typedef struct se_plugin_s	{
	unsigned char		plugin_name[MAX_PLUGIN_NAME];
	int			plugin_state;
	u32			plugin_type;
	se_plugin_class_t	*plugin_class;
	void			*plugin_obj;
	void (*get_plugin_info)(void *, char *, int *);
} se_plugin_t;

#endif /* ISCSI_TARGET_PLUGIN_H */
