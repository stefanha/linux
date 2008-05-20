/*********************************************************************************
 * Filename:  iscsi_target_tmr.h
 *
 * This file contains the iSCSI Target specific Task Management definitions. 
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


#ifndef ISCSI_TARGET_TMR_H
#define ISCSI_TARGET_TMR_H

extern __u8 iscsi_tmr_abort_task (iscsi_conn_t *, iscsi_tmr_req_t *, iscsi_lun_t **, unsigned char *);
extern __u8 iscsi_tmr_abort_task_set (iscsi_conn_t *, iscsi_tmr_req_t *, iscsi_lun_t **, unsigned char *);
extern __u8 iscsi_tmr_clear_aca (iscsi_conn_t *, iscsi_tmr_req_t *, iscsi_lun_t **, unsigned char *);
extern __u8 iscsi_tmr_clear_task_set (iscsi_conn_t *, iscsi_tmr_req_t *, iscsi_lun_t **, unsigned char *);
extern __u8 iscsi_tmr_lun_reset (iscsi_conn_t *, iscsi_tmr_req_t *, iscsi_lun_t **, unsigned char *);
extern __u8 iscsi_tmr_task_warm_reset (iscsi_conn_t *, iscsi_tmr_req_t *, unsigned char *);
extern __u8 iscsi_tmr_task_cold_reset (iscsi_conn_t *, iscsi_tmr_req_t *, unsigned char *);
extern __u8 iscsi_tmr_task_reassign (iscsi_conn_t *, iscsi_tmr_req_t *, unsigned char *);
extern int iscsi_tmr_post_handler (iscsi_cmd_t *, iscsi_conn_t *);
extern int iscsi_check_task_reassign_expdatasn (iscsi_tmr_req_t *, iscsi_conn_t *);

#endif /* ISCSI_TARGET_TMR_H */

