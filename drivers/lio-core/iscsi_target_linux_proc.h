/*********************************************************************************
 * Filename:  iscsi_target_linux_proc.h
 *
 * This file contains the iSCSI Target Information utility definitions.
 * 
 * Copyright (c) 2004 PyX Technologies, Inc.
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


#ifndef ISCSI_TARGET_LINUX_PROC_H
#define ISCSI_TARGET_LINUX_PROC_H

extern int iscsi_OS_register_info_handlers (u16);
extern void iscsi_OS_unregister_info_handlers( u16);

#endif /* ISCSI_TARGET_LINUX_PROC_H */

