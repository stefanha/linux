/*********************************************************************************
 * Filename:  iscsi_serial.c
 *
 * This file contains the Serial Number Arithmetic functions.
 * See RFC 1982
 *
 * Copyright (c) 2003 PyX Technologies, Inc.
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


#ifndef ISCSI_SERIAL_C
#define ISCSI_SERIAL_C

#ifdef LINUX
#include <iscsi_linux_os.h>
#endif /* LINUX */

#ifdef FREEBSD
#include <iscsi_freebsd_os.h>
#endif /* FREEBSD */

#include <iscsi_serial.h>

#define SERIAL_BITS	31
#define MAX_BOUND	(u32)2147483647UL

extern int serial_lt (u32 x, u32 y)
{
	return((x != y) && (((x < y) && ((y - x) < MAX_BOUND)) ||
			    ((x > y) && ((x - y) > MAX_BOUND))));
}

extern int serial_lte (u32 x, u32 y)
{
	return((x == y) ? 1 : serial_lt(x, y));
}

extern int serial_gt (u32 x, u32 y)
{
	return((x != y) && (((x < y) && ((y - x) > MAX_BOUND)) ||
			    ((x > y) && ((x - y) < MAX_BOUND))));
}

extern int serial_gte (u32 x, u32 y)
{
	return((x == y) ? 1 : serial_gt(x, y));
}

#endif /* ISCSI_SERIAL_C */
