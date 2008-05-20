/*********************************************************************************
 * Filename:  iscsi_auth.h
 *
 * This file contains definitions related to the iSCSI Initiator Authentication Daemon.
 *
 * $HeadURL: svn://subversion.sbei.com/pyx/target/branches/2.9-linux-iscsi.org/pyx-target/include/iscsi_auth.h $
 *   $LastChangedRevision: 4794 $
 *   $LastChangedBy: rickd $
 *   $LastChangedDate: 2006-08-17 16:06:35 -0700 (Thu, 17 Aug 2006) $
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


#ifndef ISCSI_AUTH_H
#define ISCSI_AUTH_H

#define VERSION		"v1.0"
#define AUTH_PORT	5003
#define TEXT_LEN 	4096
#define AUTH_CLIENT	1
#define AUTH_SERVER	2
#define	MAX_AUTH_CONN	16
#define DECIMAL		0
#define HEX		1
#define MAX_USER_LEN	256
#define MAX_PASS_LEN	256
#define MAX_INITIATORNAME 256
#define TARGET_AUTH  "target-authd"
#define SERVER_AUTHPATH "/etc/sysconfig/target_auth"

extern void convert_null_to_semi (char *, int);
extern int extract_param (const char *, const char *, unsigned int, char *, unsigned char *);
extern void remove_auth_conn (unsigned int);

typedef struct auth_conn_s {
	unsigned char	auth_state;
	int		authenticate_target;
	unsigned char	in_use;
	unsigned short	cid;
	unsigned int	sid;
	unsigned int	auth_id;
	int		role;
	int		channel_id;
	unsigned short int tpgt;
	char		initiatorname[MAX_INITIATORNAME];
	void		*auth_protocol;
	char		userid[MAX_USER_LEN];
	char		password[MAX_PASS_LEN];
	char		ma_userid[MAX_USER_LEN];	
	char		ma_password[MAX_PASS_LEN];
} auth_conn_t;

extern int iscsi_get_client_auth_info (auth_conn_t *);
extern int iscsi_get_server_auth_info (auth_conn_t *);

typedef struct auth_daemon_s {
	char		kill_auth_id;
	int		channel_id;
	unsigned short	cid;
	unsigned int	sid;
	unsigned int	auth_id;
	unsigned int	role;
	unsigned short int tpgt;
        char            initiatorname[MAX_INITIATORNAME];
	char		type[15];
	char		in_text[TEXT_LEN];
	unsigned int	in_len;
	char		out_text[TEXT_LEN];
	unsigned int	out_len;
} auth_daemon_t;

#endif /* ISCSI_AUTH_H */
