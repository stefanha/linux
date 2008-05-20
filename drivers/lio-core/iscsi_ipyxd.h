/*********************************************************************************
 * Filename:  iscsi_ipyxd.h
 *
 * $HeadURL: svn://subversion.sbei.com/pyx/target/branches/2.9-linux-iscsi.org/pyx-target/include/iscsi_ipyxd.h $
 *   $LastChangedRevision: 4785 $
 *   $LastChangedBy: rickd $
 *   $LastChangedDate: 2006-08-17 15:46:50 -0700 (Thu, 17 Aug 2006) $
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


#ifndef ISCSI_IPYXD
#define ISCSI_IPYXD

#define VERSION_IPYXD	"v0.5.5"

#define MAX_TARGET	8
#define MAX_HOST	8

#ifdef ISCSI_INITIATOR_IOCTL_DEFS_H
#define MAX_LUN		16
#endif /* ISCSI_INITIATOR_IOCTL_DEFS_H */

#ifdef ISCSI_TARGET_IOCTL_DEFS_H
#define MAX_LUN		8
#endif /* ISCSI_TARGET_IOCTL_DEFS_H */

#endif /* ISCSI_IPYXD */
