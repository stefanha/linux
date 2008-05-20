/*********************************************************************************
 * Filename:  iscsi_target_login.h 
 *
 * This file contains the login definitions used by the iSCSI Target driver.
 *
 * Copyright (c) 2003 PyX Technologies, Inc.
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


#ifndef ISCSI_TARGET_LOGIN_H
#define ISCSI_TARGET_LOGIN_H

extern int iscsi_check_for_session_reinstatement (iscsi_conn_t *);
extern int iscsi_login_post_auth_non_zero_tsih (iscsi_conn_t *, __u16, __u32);
extern int iscsi_target_login_thread (void *);

#endif   /*** ISCSI_TARGET_LOGIN_H ***/

