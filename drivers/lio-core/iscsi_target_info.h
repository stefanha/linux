/*********************************************************************************
 * Filename:  iscsi_target_info.h 
 *
 * This file contains the iSCSI Target Information utility definitions.
 * 
 * Copyright (c) 2003, 2004, 2005 PyX Technologies, Inc.
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


#ifndef ISCSI_TARGET_INFO_H
#define ISCSI_TARGET_INFO_H

#define MAX_SCSI_DEV_TYPE       14

extern int iscsi_get_hba_info_count_for_global (int *);
extern int iscsi_get_hba_info (char *, int, int, int, int);
extern int iscsi_get_dev_info_count_for_hba (u32, int *);
extern int iscsi_get_lun_info_count_for_tpg (unsigned char *, u16, int *);
extern int iscsi_get_hba_dev_info (u32, char *, int, int, int, int);
extern int iscsi_tpg_get_lun_info (unsigned char *, u16, char *, int, int, int, int);
extern void iscsi_dump_dev_state (struct iscsi_device_s *, char *, int *);
extern void iscsi_dump_dev_info (struct iscsi_device_s *, struct iscsi_lun_s *, unsigned long long, char *, int *);
extern int iscsi_get_sess_info_count_for_tpg (unsigned char *, u16, int *);
extern int iscsi_tpg_get_sess_info (unsigned char *, u16, char *, int, int, int, int);
extern int iscsi_get_tpg_info_count_for_global (unsigned char *, int *);
extern int iscsi_get_tpg_info_count_for_tpg (unsigned char *, u16, int *);
extern int iscsi_tpg_get_global_tpg_info (unsigned char *, char *, int, int, int, int);
extern int iscsi_tpg_get_tpg_info (unsigned char *, u16, char *, int, int, int, int);
extern int iscsi_get_plugin_count (int *);
extern int iscsi_get_plugin_info (char *, int, int, int, int);
extern int iscsi_get_node_attrib_info (unsigned char *, u16, char *, char *, int, int, int, int);
extern int iscsi_get_tpg_attrib_info (unsigned char *, u16, char *, char *, int, int, int, int);
extern int core_get_tiqn_count (int *);
extern int core_get_np_count (int *);
extern int core_list_gninfo (char *, int, int, int, int);
extern int core_list_gnpinfo (char *, int, int, int, int);

#endif /* ISCSI_TARGET_INFO_H */

