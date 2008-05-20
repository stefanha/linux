/*********************************************************************************
 * Filename:  iscsi_target_cache.h
 *
 * This file contains the iSCSI Transport Cache definitions.
 *
 * Nicholas A. Bellinger <nab@kernel.org>
 *
 * Copyright (c) 2004-2005 PyX Technologies, Inc.
 * Copyright (c) 2006 SBE, Inc.  All Rights Reserved.
 * Copyright (c) 2007 Rising Tide Software, Inc
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


#ifndef ISCSI_TARGET_CACHE_H
#define ISCSI_TARGET_CACHE_H
 
#define CACHE_VERSION "v0.1"

extern iscsi_cache_entry_t *iscsi_cache_check_for_entry (iscsi_cache_check_entry_t *, iscsi_cmd_t *);
extern void iscsi_cache_add_entry (iscsi_cache_check_entry_t *, iscsi_cmd_t *);
extern int iscsi_cache_init_dev (iscsi_device_t *);
extern void iscsi_cache_free_dev (iscsi_device_t *);

#endif /* ISCSI_TARGET_CACHE_H */
