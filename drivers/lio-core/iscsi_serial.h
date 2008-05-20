/*********************************************************************************
 * Filename:  iscsi_serial.h
 *
 * This file contains the Serial Number Arithmetic definitions.
 * See RFC 1982
 *
 * $HeadURL: svn://subversion.sbei.com/pyx/target/branches/2.9-linux-iscsi.org/pyx-target/include/iscsi_serial.h $
 *   $LastChangedRevision: 4799 $
 *   $LastChangedBy: rickd $
 *   $LastChangedDate: 2006-08-17 16:20:46 -0700 (Thu, 17 Aug 2006) $
 *
 * Copyright (c) 2003 PyX Technologies, Inc.
 * Copyright (c) 2006 SBE, Inc.  All Rights Reserved.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 * For further information, contact via email: support@sbei.com
 * SBE, Inc.  San Ramon, California  U.S.A.
 *********************************************************************************/


#ifndef ISCSI_SERIAL_H
#define ISCSI_SERIAL_H

extern int serial_lt (u32, u32);
extern int serial_lte (u32, u32);
extern int serial_gt (u32, u32);
extern int serial_gte (u32, u32);

#endif   /*** ISCSI_SERIAL_H ***/

