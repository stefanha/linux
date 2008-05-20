/*********************************************************************************
 * Filename:  iscsi_target.h
 *
 * This file contains definitions related to the main iSCSI Target driver.
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


#ifndef ISCSI_TARGET_H
#define ISCSI_TARGET_H

extern iscsi_tiqn_t *__core_get_default_tiqn (void);
extern iscsi_tiqn_t *core_get_default_tiqn (void);
extern struct iscsi_tiqn_s *core_get_tiqn (unsigned char *);
extern iscsi_tiqn_t *core_add_tiqn (unsigned char *, int *);
extern int core_del_tiqn (unsigned char *);
extern struct iscsi_portal_group_s *core_get_tpg_from_iqn (unsigned char *, struct iscsi_tiqn_s **, u16, int);
extern int core_access_np (iscsi_np_t *, iscsi_portal_group_t *);
extern int core_deaccess_np (iscsi_np_t *, iscsi_portal_group_t *);
extern void *core_get_np_ip (iscsi_np_t *np);
extern struct iscsi_np_s *core_get_np (void *, u16, int);
extern int __core_del_np_ex (iscsi_np_t *, iscsi_np_ex_t *);
extern struct iscsi_np_s *core_add_np (struct iscsi_target *, int, int *);
extern int core_reset_np_thread (iscsi_np_t *);
extern int core_del_np (struct iscsi_target *, int);

extern int iscsi_send_async_msg (iscsi_conn_t *, __u16, __u8, __u8);
extern int iscsi_send_r2t (iscsi_cmd_t *, iscsi_conn_t *);
extern int iscsi_build_r2ts_for_cmd (iscsi_cmd_t *, iscsi_conn_t *, int);
extern int iscsi_target_tx_thread (void *);
extern int iscsi_target_rx_thread (void *);
extern int iscsi_close_connection (iscsi_conn_t *);
extern int iscsi_close_session (iscsi_session_t *);
extern void iscsi_fail_session (iscsi_session_t *);
extern int iscsi_free_session (iscsi_session_t *);
extern int iscsi_stop_session (iscsi_session_t *, int, int);
extern int iscsi_release_sessions_for_tpg (iscsi_portal_group_t *, int);

#endif   /*** ISCSI_TARGET_H ***/
