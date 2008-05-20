/*********************************************************************************
 * Filename:  iscsi_target_erl2.h
 *
 * This file contains error recovery level two definitions used by
 * the iSCSI Target driver.
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


#ifndef ISCSI_TARGET_ERL2_H
#define ISCSI_TARGET_ERL2_H
 
extern void iscsi_create_conn_recovery_datain_values (iscsi_cmd_t *, __u32);
extern void iscsi_create_conn_recovery_dataout_values (iscsi_cmd_t *);
extern iscsi_conn_recovery_t *iscsi_get_inactive_connection_recovery_entry (iscsi_session_t *, __u16); 
extern void iscsi_free_connection_recovery_entires (iscsi_session_t *);
extern int iscsi_remove_active_connection_recovery_entry (iscsi_conn_recovery_t *, iscsi_session_t *);
extern int iscsi_remove_cmd_from_connection_recovery (iscsi_cmd_t *, iscsi_session_t *);
extern void iscsi_discard_cr_cmds_by_expstatsn (iscsi_conn_recovery_t *, __u32);
extern int iscsi_discard_unacknowledged_ooo_cmdsns_for_conn (iscsi_conn_t *);
extern int iscsi_prepare_cmds_for_realligance (iscsi_conn_t *);
extern int iscsi_connection_recovery_transport_reset (iscsi_conn_t *);

#endif /*** ISCSI_TARGET_ERL2_H ***/

