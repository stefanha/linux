/*********************************************************************************
 * Filename:  iscsi_auth.h
 *
 * This file contains definitions related to the iSCSI Initiator Authentication Daemon.
 *
 * Copyright (c) 2003 PyX Technologies, Inc.
 * Copyright (c) 2006 SBE, Inc.  All Rights Reserved.
 * Copyright (c) 2007-2009 Linux-iSCSI.org
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 * For further information, contact via email: support@sbei.com
 * SBE, Inc.  San Ramon, California  U.S.A.
 *********************************************************************************/


#ifndef ISCSI_AUTH_H
#define ISCSI_AUTH_H

#define TEXT_LEN 	4096
#define AUTH_CLIENT	1
#define AUTH_SERVER	2
#define DECIMAL		0
#define HEX		1

extern void convert_null_to_semi (char *, int);
extern int extract_param (const char *, const char *, unsigned int, char *, unsigned char *);

#endif /* ISCSI_AUTH_H */
