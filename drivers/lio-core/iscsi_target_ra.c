/*********************************************************************************
 * Filename:  iscsi_target_ra.c
 *
 * This file contains the iSCSI Transport Read-ahead related functions.
 *
 * Copyright (c) 2004-2005 PyX Technologies, Inc.
 * Copyright (c) 2006-2007 SBE, Inc.  All Rights Reserved.
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


#define ISCSI_TARGET_RA_C

#include <linux/net.h>
#include <linux/string.h>
#include <linux/timer.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/smp_lock.h>
#include <linux/in.h>
#include <net/sock.h>
#include <net/tcp.h>

#include <iscsi_linux_os.h>
#include <iscsi_linux_defs.h>

#include <iscsi_lists.h>
#include <iscsi_protocol.h>
#include <iscsi_target_core.h>
#include <iscsi_target_transport.h>
#include <iscsi_target_ra.h>

#undef ISCSI_TARGET_RA_C

/*	iscsi_ra_check():
 *
 *
 */
extern int iscsi_ra_check (iscsi_cmd_t *cmd)
{
	iscsi_device_t *dev = ISCSI_DEV(cmd);
	
	return(0);
}
