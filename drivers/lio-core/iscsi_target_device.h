/*********************************************************************************
 * Filename:  iscsi_target_device.h
 *
 * Copyright (c) 2003, 2004, 2005 PyX Technologies, Inc.
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


#ifndef ISCSI_TARGET_DEVICE_H
#define ISCSI_TARGET_DEVICE_H
 
extern int iscsi_get_lun_for_tmr (iscsi_cmd_t *, u64);
extern int iscsi_get_lun_for_cmd (iscsi_cmd_t *, unsigned char *, u64);
extern void iscsi_determine_maxcmdsn (iscsi_session_t *);
extern void iscsi_increment_maxcmdsn (iscsi_cmd_t *, iscsi_session_t *);

#endif /* ISCSI_TARGET_DEVICE_H */
