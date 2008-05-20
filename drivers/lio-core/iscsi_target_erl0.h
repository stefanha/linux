/*********************************************************************************
 * Filename:  iscsi_target_erl0.h 
 *
 * This file contains error recovery level zero definitions used by
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


#ifndef ISCSI_TARGET_ERL0_H
#define ISCSI_TARGET_ERL0_H

extern void iscsi_set_dataout_sequence_values (iscsi_cmd_t *);
extern int iscsi_check_pre_dataout (iscsi_cmd_t *, unsigned char *);
extern int iscsi_check_post_dataout (iscsi_cmd_t *, unsigned char *, __u8);
extern void iscsi_start_time2retain_handler (iscsi_session_t *);
extern void iscsi_stop_time2retain_timer (iscsi_session_t *);
extern void iscsi_connection_reinstatement_rcfr (iscsi_conn_t *);
extern void iscsi_cause_connection_reinstatement (iscsi_conn_t *, int);
extern void iscsi_fall_back_to_erl0 (iscsi_conn_t *);
extern void iscsi_take_action_for_connection_exit (iscsi_conn_t *);
extern int iscsi_recover_from_unknown_opcode (iscsi_conn_t *);

#endif   /*** ISCSI_TARGET_ERL0_H ***/

