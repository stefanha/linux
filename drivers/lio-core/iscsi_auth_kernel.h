/*********************************************************************************
 * Filename:  iscsi_auth_kernel.h
 *
 * $HeadURL: svn://subversion.sbei.com/pyx/target/branches/2.9-linux-iscsi.org/pyx-target/include/iscsi_auth_kernel.h $
 *   $LastChangedRevision: 7131 $
 *   $LastChangedBy: nab $
 *   $LastChangedDate: 2007-08-25 17:03:55 -0700 (Sat, 25 Aug 2007) $
 *
 * Copyright (c) 2003-2005 PyX Technologies, Inc.
 * Copyright (c) 2005-2006 SBE, Inc.  All Rights Reserved.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 * For further information, contact via email: support@sbei.com
 * SBE, Inc.  San Ramon, California  U.S.A.
 *********************************************************************************/


#ifndef ISCSI_AUTH_KERNEL_H
#define ISCSI_AUTH_KERNEL_H

#include <iscsi_linux_os.h>
#include <iscsi_linux_defs.h>

#include <iscsi_auth.h>

extern se_global_t *iscsi_global;

/*	iscsi_handle_authetication():
 *
 *
 */
extern u32 iscsi_handle_authentication (
	iscsi_conn_t *conn,
	char *in_buf,
	char *out_buf,
	int in_length,
	int *out_length,
	unsigned char *authtype,
	int role)
{
	u32			rc = 0, ret = 0;
	auth_daemon_t		*iscsi_auth = NULL;
	mm_segment_t		oldfs;
	struct iovec 		iov;
	struct msghdr		msg;
	struct sockaddr_in 	s_addr;
	struct socket 		*authsock = NULL;

	down(&iscsi_global->auth_sem);

	if (!(iscsi_auth = (auth_daemon_t *) kmalloc(sizeof(auth_daemon_t), GFP_KERNEL))) {
		TRACE_ERROR("Unable to allocate memory for iscsi_auth\n");
		up(&iscsi_global->auth_sem);
		return(2);
	}
	memset(iscsi_auth, 0, sizeof(auth_daemon_t));

	if (authtype) {
		memcpy(iscsi_auth->type, authtype, sizeof(iscsi_auth->type)); 
	} else {
		iscsi_auth->kill_auth_id = 1;
		memcpy(iscsi_auth->type, NONE, sizeof(iscsi_auth->type));
	}

	if (in_buf && in_length) {
		memcpy(iscsi_auth->in_text, in_buf, in_length);
		iscsi_auth->in_len = in_length;
	}
	if (out_buf && out_length) {
		memcpy(iscsi_auth->out_text, out_buf, *out_length);
		iscsi_auth->out_len = *out_length;
	}

	iscsi_auth->role = role;
	iscsi_auth->cid = conn->cid;
	iscsi_auth->sid = SESS(conn)->sid;
	iscsi_auth->auth_id = conn->auth_id;
#ifdef _INITIATOR
	iscsi_auth->channel_id = SESS(conn)->channel->channel_id;
#else
	iscsi_auth->tpgt = SESS(conn)->tpg->tpgt;
	if (!SESS(conn)->node_acl) {
		ret = -1;
		goto out;
	}
	strncpy(iscsi_auth->initiatorname, SESS(conn)->node_acl->initiatorname,
		strlen(SESS(conn)->node_acl->initiatorname) + 1);
#ifdef SNMP_SUPPORT
	if (strstr("CHAP", iscsi_auth->type))
		strcpy(SESS(conn)->auth_type, "CHAP");
	else
		strcpy(SESS(conn)->auth_type, NONE);
#endif /* SNMP_SUPPORT */
#endif

	s_addr.sin_family	= AF_INET;
	s_addr.sin_addr.s_addr	= htonl(INADDR_LOOPBACK);
	s_addr.sin_port		= htons(AUTH_PORT);

	if (iscsi_sock_create(&authsock, AF_INET, SOCK_DGRAM, IPPROTO_UDP,
			NULL, NULL) < 0) {
		TRACE_ERROR("iscsi_sock_create() failed!\n");
		ret = -1;
		goto out;
	}

	memset(&iov, 0, sizeof(struct iovec));
	memset(&msg, 0, sizeof(struct msghdr));
	iov.iov_base	= iscsi_auth;
	iov.iov_len	= sizeof(auth_daemon_t);
	msg.msg_iov	= &iov;
	msg.msg_iovlen	= 1;
	msg.msg_name	= &s_addr;
	msg.msg_namelen = sizeof(struct sockaddr_in);
	
	oldfs = get_fs();
	set_fs(KERNEL_DS);
	if (sock_sendmsg(authsock, &msg, sizeof(auth_daemon_t)) < 0) {
		TRACE_ERROR("sock_sendmsg() returned %u\n", rc);
		ret = -1;
		set_fs(oldfs);
		goto out;
	}
	set_fs(oldfs);

	memset(&iov, 0, sizeof(struct iovec));
	memset(&msg, 0, sizeof(struct msghdr));
	iov.iov_base	= iscsi_auth;
	iov.iov_len	= sizeof(auth_daemon_t);
	msg.msg_iov	= &iov;
	msg.msg_iovlen	= 1;
	msg.msg_name	= &s_addr;
	msg.msg_namelen = sizeof(struct sockaddr_in);	

	oldfs = get_fs();
	set_fs(KERNEL_DS);
	if (sock_recvmsg(authsock, &msg, sizeof(auth_daemon_t), 0) < 0) {
		TRACE(TRACE_DEBUG, "sock_recvmsg() returned %u\n", rc);
		set_fs(oldfs);
		ret = -1;
		goto out;
	}
	set_fs(oldfs);

	switch (iscsi_auth->type[0]) {
	case '0':
		goto copy;
	case '1':
		ret = 1;
		goto copy;
	case '2':
		ret = 2;
		goto out;
	case '3':
		ret = 3;
		goto out;
	default:
		ret = -1;
		goto out;
	}

copy:
	if (!out_buf)
		goto out;
	memcpy(out_buf, iscsi_auth->out_text, iscsi_auth->out_len);
	*out_length = iscsi_auth->out_len;
out:
	if (authsock)
		sock_release(authsock);
	if (iscsi_auth)
		kfree(iscsi_auth);

	up(&iscsi_global->auth_sem);

	return(ret);
}

/*	iscsi_remove_failed_auth_entry():
 *
 *
 */
extern void iscsi_remove_failed_auth_entry (
	iscsi_conn_t *conn,
	int role)
{
	iscsi_handle_authentication(conn, NULL, NULL, 0, NULL, NULL, role);

	return;
}

#endif   /*** ISCSI_AUTH_KERNEL_H ***/

