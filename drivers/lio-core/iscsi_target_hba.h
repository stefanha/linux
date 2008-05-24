/*********************************************************************************
 * Filename:  iscsi_target_hba.h
 *
 * This file contains the iSCSI HBA Transport related definitions.
 *
 * Copyright (c) 2003-2004 PyX Technologies, Inc.
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


#ifndef ISCSI_TARGET_HBA_H
#define ISCSI_TARGET_HBA_H
 
extern int iscsi_hba_check_online (se_dev_transport_info_t *);
extern se_hba_t *__core_get_hba_from_id (se_hba_t *);
extern se_hba_t *core_get_hba_from_id (u32, int);
extern se_hba_t *iscsi_get_hba_from_ptr (void *);
extern void core_put_hba (se_hba_t *);
extern int iscsi_hba_check_addhba_params (struct iscsi_target *, se_hbainfo_t *);
extern int iscsi_hba_add_hba (se_hba_t *, se_hbainfo_t *, struct iscsi_target *);
extern int iscsi_hba_del_hba (se_hba_t *);
extern void iscsi_disable_all_hbas (void);
extern void iscsi_hba_del_all_hbas (void);

#endif /* ISCSI_TARGET_HBA_H */
