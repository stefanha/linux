/*********************************************************************************
 * Filename:  iscsi_target_util.h
 *
 * This file contains the iSCSI Target specific utility definitions
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


#ifndef ISCSI_TARGET_UTIL_H
#define ISCSI_TARGET_UTIL_H

#define MARKER_SIZE	8

extern void iscsi_attach_cmd_to_queue (iscsi_conn_t *, iscsi_cmd_t *);
extern void iscsi_remove_cmd_from_conn_list (iscsi_cmd_t *, iscsi_conn_t *);
extern void iscsi_ack_from_expstatsn (iscsi_conn_t *, __u32);
extern void iscsi_remove_conn_from_list (iscsi_session_t *, iscsi_conn_t *);
extern void iscsi_remove_session_from_list (iscsi_session_t *);
extern int iscsi_add_r2t_to_list (iscsi_cmd_t *, __u32, __u32, int, __u32);
extern iscsi_r2t_t *iscsi_get_r2t_for_eos (iscsi_cmd_t *, __u32, __u32);
extern iscsi_r2t_t *iscsi_get_r2t_from_list (iscsi_cmd_t *);
extern void iscsi_free_r2t (iscsi_r2t_t *, iscsi_cmd_t *);
extern void iscsi_free_r2ts_from_list (iscsi_cmd_t *);
extern int iscsi_allocate_iovecs_for_cmd (iscsi_cmd_t *, __u32);
extern iscsi_cmd_t *iscsi_allocate_cmd (iscsi_conn_t *);
extern iscsi_tmr_req_t *iscsi_allocate_tmr_req (void);
extern int iscsi_decide_list_to_build (iscsi_cmd_t *, __u32);
extern iscsi_seq_t *iscsi_get_seq_holder_for_datain (iscsi_cmd_t *, __u32);
extern iscsi_seq_t *iscsi_get_seq_holder_for_r2t (iscsi_cmd_t *);
extern iscsi_r2t_t *iscsi_get_holder_for_r2tsn (iscsi_cmd_t *, __u32);
extern int iscsi_check_received_cmdsn (iscsi_conn_t *, iscsi_cmd_t *, __u32);
extern int iscsi_check_unsolicited_dataout (iscsi_cmd_t *, unsigned char *);
extern iscsi_cmd_t *iscsi_find_cmd_from_itt (iscsi_conn_t *, __u32);
extern iscsi_cmd_t *iscsi_find_cmd_from_itt_or_dump(iscsi_conn_t *, __u32, __u32);
extern iscsi_cmd_t *iscsi_find_cmd_from_ttt (iscsi_conn_t *, __u32);
extern int iscsi_find_cmd_for_recovery (iscsi_session_t *, iscsi_cmd_t **, iscsi_conn_recovery_t **, __u32);
extern void iscsi_add_cmd_to_immediate_queue (iscsi_cmd_t *, iscsi_conn_t *, u8);
extern iscsi_queue_req_t *iscsi_get_cmd_from_immediate_queue (iscsi_conn_t *);
extern void iscsi_add_cmd_to_response_queue (iscsi_cmd_t *, iscsi_conn_t *, u8);
extern iscsi_queue_req_t *iscsi_get_cmd_from_response_queue (iscsi_conn_t *);
extern void iscsi_remove_cmd_from_tx_queues (iscsi_cmd_t *, iscsi_conn_t *);
extern void iscsi_free_queue_reqs_for_conn (iscsi_conn_t *);
extern iscsi_cmd_t *iscsi_get_cmd_from_pool (iscsi_session_t *);
extern void iscsi_release_cmd_direct (iscsi_cmd_t *);
extern void iscsi_dec_nacl_count (iscsi_node_acl_t *, iscsi_cmd_t *);
extern void iscsi_release_cmd_to_pool (iscsi_cmd_t *, iscsi_session_t *);
extern void iscsi_release_all_cmds_in_pool (iscsi_session_t *);
extern __u64 iscsi_pack_lun (unsigned int);
extern __u32 iscsi_unpack_lun (unsigned char *);
extern int iscsi_send_check_condition_and_sense (iscsi_cmd_t *, __u8, int);
extern iscsi_session_t *iscsi_get_tpg_session_from_sid (iscsi_portal_group_t *, __u32);
extern int iscsi_check_session_usage_count (iscsi_session_t *);
extern void iscsi_dec_session_usage_count (iscsi_session_t *);
extern void iscsi_inc_session_usage_count (iscsi_session_t *);
extern int iscsi_set_sync_and_steering_values (iscsi_conn_t *);
extern unsigned char *iscsi_ntoa (__u32);
extern void iscsi_ntoa2 (unsigned char *, __u32);
extern const char *iscsi_ntop6 (const unsigned char *, char *, size_t);
extern int iscsi_pton6 (const char *, unsigned char *);
extern iscsi_conn_t *iscsi_get_conn_from_cid (iscsi_session_t *, __u16);
extern iscsi_conn_t *iscsi_get_conn_from_cid_rcfr (iscsi_session_t *, __u16);
extern void iscsi_check_conn_usage_count (iscsi_conn_t *);
extern void iscsi_dec_conn_usage_count (iscsi_conn_t *);
extern void iscsi_inc_conn_usage_count (iscsi_conn_t *);
extern void iscsi_async_msg_timer_function (unsigned long);
extern int iscsi_check_for_active_network_device (iscsi_conn_t *);
extern void iscsi_get_network_interface_from_conn (iscsi_conn_t *);
extern void iscsi_start_netif_timer (iscsi_conn_t *);
extern void iscsi_stop_netif_timer (iscsi_conn_t *);
extern void iscsi_mod_nopin_response_timer (iscsi_conn_t *);
extern void iscsi_start_nopin_response_timer (iscsi_conn_t *);
extern void iscsi_stop_nopin_response_timer (iscsi_conn_t *);
extern void iscsi_start_nopin_timer (iscsi_conn_t *);
extern void iscsi_stop_nopin_timer (iscsi_conn_t *);
extern int iscsi_send_tx_data (iscsi_cmd_t *, iscsi_conn_t *, int);
extern int iscsi_fe_sendpage_sg (iscsi_unmap_sg_t *, iscsi_conn_t *);
extern int iscsi_tx_login_rsp (iscsi_conn_t *, __u8, __u8);
extern void iscsi_print_session_params (iscsi_session_t *);
extern int iscsi_print_dev_to_proc (char *, char **, off_t, int);
extern int iscsi_print_sessions_to_proc (char *, char **, off_t, int);
extern int iscsi_print_tpg_to_proc (char *, char **, off_t, int);
extern int rx_data (iscsi_conn_t *, struct iovec *, int, int);
extern int tx_data (iscsi_conn_t *, struct iovec *, int, int);
#ifdef SNMP_SUPPORT
extern void iscsi_collect_login_stats (iscsi_conn_t *, __u8, __u8);
extern iscsi_tiqn_t *iscsi_snmp_get_tiqn (iscsi_conn_t *);
#endif

#endif /*** ISCSI_TARGET_UTIL_H ***/

