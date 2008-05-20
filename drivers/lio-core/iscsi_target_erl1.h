/*********************************************************************************
 * Filename:  iscsi_target_erl1.h
 *
 * This file contains error recovery level one definitions used by
 * the iSCSI Target driver.
 *
 * Copyright (c) 2003 PyX Technologies, Inc.
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


#ifndef ISCSI_TARGET_ERL1_H
#define ISCSI_TARGET_ERL1_H
 
extern int iscsi_dump_data_payload (iscsi_conn_t *, __u32, int);
extern int iscsi_create_recovery_datain_values_datasequenceinorder_yes (iscsi_cmd_t *, iscsi_datain_req_t *);
extern int iscsi_create_recovery_datain_values_datasequenceinorder_no (iscsi_cmd_t *, iscsi_datain_req_t *);
extern int iscsi_handle_recovery_datain_or_r2t (iscsi_conn_t *, unsigned char *, __u32, __u32, __u32, __u32);
extern int iscsi_handle_status_snack (iscsi_conn_t *, __u32, __u32, __u32, __u32);
extern int iscsi_handle_data_ack (iscsi_conn_t *, __u32, __u32, __u32);
extern int iscsi_dataout_datapduinorder_no_fbit (iscsi_cmd_t *, iscsi_pdu_t *);
extern int iscsi_recover_dataout_sequence (iscsi_cmd_t *, __u32, __u32);
extern void iscsi_clear_ooo_cmdsns_for_conn (iscsi_conn_t *);
extern void iscsi_free_all_ooo_cmdsns (iscsi_session_t *);
extern int iscsi_execute_ooo_cmdsns (iscsi_session_t *);
extern int iscsi_execute_cmd (iscsi_cmd_t *, int);
extern int iscsi_handle_ooo_cmdsn (iscsi_session_t *, iscsi_cmd_t *, __u32);
extern void iscsi_remove_ooo_cmdsn (iscsi_session_t *, iscsi_ooo_cmdsn_t *);
extern void iscsi_mod_dataout_timer (iscsi_cmd_t *);
extern void iscsi_start_dataout_timer (iscsi_cmd_t *, iscsi_conn_t *);
extern void iscsi_stop_dataout_timer (iscsi_cmd_t *);

#endif /* ISCSI_TARGET_ERL1_H */
