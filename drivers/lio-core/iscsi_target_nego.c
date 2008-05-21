/*********************************************************************************
 * Filename:  iscsi_target_nego.c
 *
 * This file contains main functions related to iSCSI Parameter negotiation.
 *
 * Copyright (c) 2002, 2003, 2004, 2005 PyX Technologies, Inc.
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


#define ISCSI_TARGET_NEGOTIATE_C

#include <linux/string.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/smp_lock.h>
#include <net/sock.h>
#include <net/tcp.h>

#include <iscsi_linux_os.h>
#include <iscsi_linux_defs.h>

#include <iscsi_debug.h>
#include <iscsi_protocol.h>
#include <iscsi_debug_opcodes.h>
#include <iscsi_target_core.h>
#include <iscsi_target_ioctl.h>
#include <iscsi_target_device.h>
#include <iscsi_target_login.h>
#include <iscsi_target_nego.h>
#include <iscsi_target_tpg.h>
#include <iscsi_target_util.h>
#include <iscsi_target.h>
#include <iscsi_auth_kernel.h>
#include <iscsi_parameters.h>
#include <iscsi_crc.h>

#undef ISCSI_TARGET_NEGOTIATE_C

#define MAX_LOGIN_PDUS	7

extern iscsi_global_t *iscsi_global;

/*	iscsi_target_check_login_request():
 *
 *
 */
static int iscsi_target_check_login_request(iscsi_conn_t *conn, iscsi_login_t *login)
{
	int req_csg, req_nsg, rsp_csg, rsp_nsg;
	struct iscsi_init_login_cmnd *login_req;
	struct iscsi_targ_login_rsp *login_rsp;

	TRACE_ENTER

	login_req = (struct iscsi_init_login_cmnd *) login->req;
	login_rsp = (struct iscsi_targ_login_rsp *) login->rsp;

	switch (login_req->opcode & ISCSI_OPCODE) {
		case ISCSI_INIT_LOGIN_CMND:
			break;
		default:
			TRACE_ERROR("Received unknown opcode 0x%02x.\n",
					login_req->opcode & ISCSI_OPCODE);
			iscsi_tx_login_rsp(conn, STAT_CLASS_INITIATOR,
					STAT_DETAIL_INIT_ERROR);
			return(-1);
	}

	if ((login_req->flags & C_BIT) && (login_req->flags & T_BIT)) {
		TRACE_ERROR("Login request has both C_BIT and T_BIT set,"
				" protocol error.\n");
		iscsi_tx_login_rsp(conn, STAT_CLASS_INITIATOR,
				STAT_DETAIL_INIT_ERROR);
		return(-1);
	}

	req_csg = (login_req->flags & CSG) >> CSG_SHIFT;
	rsp_csg = (login_rsp->flags & CSG) >> CSG_SHIFT;
	req_nsg = (login_req->flags & NSG);
	rsp_nsg = (login_rsp->flags & NSG);

	if (req_csg != login->current_stage) {
		TRACE_ERROR("Initiator unexpectedly changed login stage from"
			" %d to %d, login failed.\n", login->current_stage, req_csg);
		iscsi_tx_login_rsp(conn, STAT_CLASS_INITIATOR,
				STAT_DETAIL_INIT_ERROR);
		return(-1);
	}

	if (ISCSI_TPG_C(conn)) {
		if ((req_csg != 0) && !login->auth_complete &&
		     ISCSI_TPG_ATTRIB(ISCSI_TPG_C(conn))->authentication) {
			TRACE_ERROR("Initiator is requesting CSG: %d, has not been"
				" successfully authenticated, and the Target is"
				" enforcing iSCSI Authentication, login failed.\n",
				req_csg);
			iscsi_tx_login_rsp(conn, STAT_CLASS_INITIATOR,
					STAT_DETAIL_NOT_AUTH);
			return(-1);
		}
	}

	if ((req_nsg == 2) || (req_csg >= 2) ||
	   ((login_req->flags & T_BIT) && (req_nsg <= req_csg))) {
		TRACE_ERROR("Illegal login_req->flags Combination, CSG: %d,"
			" NSG: %d, T_BIT: %d.\n", req_csg, req_nsg,
				(login_req->flags & T_BIT));
		iscsi_tx_login_rsp(conn, STAT_CLASS_INITIATOR,
				STAT_DETAIL_INIT_ERROR);
		return(-1);
	}

	if ((login_req->version_max != login->version_max) ||
	    (login_req->version_min != login->version_min)) {
		TRACE_ERROR("Login request changed Version Max/Nin unexpectedly"
			" to 0x%02x/0x%02x, protocol error\n",
			login_req->version_max, login_req->version_min);	
		iscsi_tx_login_rsp(conn, STAT_CLASS_INITIATOR,
				STAT_DETAIL_INIT_ERROR);
		return(-1);
	}

	if (memcmp(login_req->isid, login->isid, 6) != 0) {
		TRACE_ERROR("Login request changed ISID unexpectedly,"
				" protocol error.\n");
		iscsi_tx_login_rsp(conn, STAT_CLASS_INITIATOR,
				STAT_DETAIL_INIT_ERROR);
		return(-1);
	}

	if (login_req->init_task_tag != login->init_task_tag) {
		TRACE_ERROR("Login request changed ITT unexpectedly to 0x%08x,"
			" protocol error.\n", login_req->init_task_tag);
		iscsi_tx_login_rsp(conn, STAT_CLASS_INITIATOR,
				STAT_DETAIL_INIT_ERROR);
		return(-1);
	}

	if (login_req->length > MAX_TEXT_LEN) {
		TRACE_ERROR("Login request payload exceeds default"
			" MaxRecvDataSegmentLength: %u, protocol error.\n",
				MAX_TEXT_LEN);
		return(-1);
	}

	TRACE_LEAVE
	return(0);
}

/*	iscsi_target_check_first_request():
 *
 *
 */
static int iscsi_target_check_first_request(
	iscsi_conn_t *conn,
	iscsi_login_t *login)
{
	iscsi_node_acl_t *acl;
	iscsi_param_t *param = NULL;

	TRACE_ENTER

	login->first_request = 0;

	for (param = conn->param_list->param_start; param; param = param->next) {
		if (!strncmp(param->name, SESSIONTYPE, 11)) {
			if (!IS_PSTATE_ACCEPTOR(param)) {
				TRACE_ERROR("SessionType key not received"
					" in first login request.\n");
				iscsi_tx_login_rsp(conn, STAT_CLASS_INITIATOR,
					STAT_DETAIL_MISSING_PARAMETER);
				return(-1);
			}
			if (!(strncmp(param->value, DISCOVERY, 9)))
				return(0);
		}

		if (!strncmp(param->name, INITIATORNAME, 13)) {
			if (!IS_PSTATE_ACCEPTOR(param)) {
				if (!login->leading_connection)
					continue;
				
				TRACE_ERROR("InitiatorName key not received"
					" in first login request.\n");
				iscsi_tx_login_rsp(conn, STAT_CLASS_INITIATOR,
					STAT_DETAIL_MISSING_PARAMETER);
				return(-1);
			}

			/*
			 * For the non-leading connections, double check that the
			 * received InitiatorName matches the existing session's
			 * iscsi_node_acl_t.
			 */
			if (!login->leading_connection) {
				if (!(acl = SESS(conn)->node_acl)) {
					TRACE_ERROR("Unable to locate iscsi_node_acl_t\n");
					iscsi_tx_login_rsp(conn, STAT_CLASS_INITIATOR,
							STAT_DETAIL_NOT_FOUND);
					return(-1);
				}

				if (strncmp(param->value, acl->initiatorname,
				    strlen(acl->initiatorname))) {
					TRACE_ERROR("Incorrect InitiatorName: %s for"
						" this iSCSI Initiator Node.\n",
						param->value);
					iscsi_tx_login_rsp(conn, STAT_CLASS_INITIATOR,
						STAT_DETAIL_NOT_FOUND);
					return(-1);
				}
			}
		}
	}

	return(0);
}

/*	iscsi_target_do_tx_login_io():
 *
 *
 */
static int iscsi_target_do_tx_login_io(iscsi_conn_t *conn, iscsi_login_t *login)
{	
	__u32 padding = 0;
	iscsi_session_t *sess = SESS(conn);
	struct iscsi_targ_login_rsp *login_rsp;

	TRACE_ENTER

	login_rsp = (struct iscsi_targ_login_rsp *) login->rsp;

	login_rsp->opcode		= ISCSI_TARG_LOGIN_RSP;
	login_rsp->length		= cpu_to_be32(login_rsp->length);
	memcpy(login_rsp->isid, login->isid, 6);
	login_rsp->tsih			= cpu_to_be16(login->tsih);
	login_rsp->init_task_tag	= cpu_to_be32(login->init_task_tag);
	login_rsp->stat_sn		= cpu_to_be32(conn->stat_sn++);
	login_rsp->exp_cmd_sn		= cpu_to_be32(SESS(conn)->exp_cmd_sn);
	login_rsp->max_cmd_sn		= cpu_to_be32(SESS(conn)->max_cmd_sn);

	TRACE(TRACE_LOGIN, "Sending Login Response, Flags: 0x%02x, ITT: 0x%08x,"
		" ExpCmdSN; 0x%08x, MaxCmdSN: 0x%08x, StatSN: 0x%08x, Length: %u\n",
		login_rsp->flags, ntohl(login_rsp->init_task_tag),
		ntohl(login_rsp->exp_cmd_sn), ntohl(login_rsp->max_cmd_sn),
		ntohl(login_rsp->stat_sn), ntohl(login_rsp->length));

	padding = ((-ntohl(login_rsp->length)) & 3);

	if (iscsi_login_tx_data(
			conn,
			login->rsp,
			login->rsp_buf,
	    		ntohl(login_rsp->length) + padding,
			TARGET) < 0)
		return(-1);

	login_rsp->length		= 0;
	login_rsp->tsih			= be16_to_cpu(login_rsp->tsih);
	login_rsp->init_task_tag	= be32_to_cpu(login_rsp->init_task_tag);
	login_rsp->stat_sn		= be32_to_cpu(login_rsp->stat_sn);
	spin_lock(&sess->cmdsn_lock);
	login_rsp->exp_cmd_sn		= be32_to_cpu(sess->exp_cmd_sn);
	login_rsp->max_cmd_sn		= be32_to_cpu(sess->max_cmd_sn);
	spin_unlock(&sess->cmdsn_lock);

	TRACE_LEAVE
	return(0);
}

/*	iscsi_target_do_rx_login_io():
 *
 *
 */
static int iscsi_target_do_rx_login_io(iscsi_conn_t *conn, iscsi_login_t *login)
{
	__u32 padding = 0;
	struct iscsi_init_login_cmnd *login_req;

	TRACE_ENTER

	if (iscsi_login_rx_data(conn, login->req, ISCSI_HDR_LEN, TARGET) < 0)
		return(-1);

	login_req = (struct iscsi_init_login_cmnd *) login->req;
	login_req->length		= be32_to_cpu(login_req->length);
	login_req->tsih			= be16_to_cpu(login_req->tsih);
	login_req->init_task_tag	= be32_to_cpu(login_req->init_task_tag);
	login_req->cid			= be16_to_cpu(login_req->cid);
	login_req->cmd_sn		= be32_to_cpu(login_req->cmd_sn);
	login_req->exp_stat_sn		= be32_to_cpu(login_req->exp_stat_sn);

	TRACE(TRACE_LOGIN, "Got Login Command, Flags 0x%02x, ITT: 0x%08x,"
		" CmdSN: 0x%08x, ExpStatSN: 0x%08x, CID: %hu, Length: %u\n",
		 login_req->flags, login_req->init_task_tag, login_req->cmd_sn,
		 login_req->exp_stat_sn, login_req->cid, login_req->length);

	if (iscsi_target_check_login_request(conn, login) < 0)
		return(-1);

	padding = ((-login_req->length) & 3);
	memset(login->req_buf, 0, MAX_TEXT_LEN);

	if (iscsi_login_rx_data(
			conn,
			login->req_buf,
			login_req->length + padding,
			TARGET) < 0)
		return(-1);

	TRACE_LEAVE
	return(0);
}

/*      iscsi_target_do_login_io():
 *
 *
 */
static int iscsi_target_do_login_io(iscsi_conn_t *conn, iscsi_login_t *login)
{
	TRACE_ENTER

	if (iscsi_target_do_tx_login_io(conn, login) < 0)
		return(-1);

	if (iscsi_target_do_rx_login_io(conn, login) < 0)
		return(-1);

	TRACE_LEAVE
	return(0);
}

static int iscsi_target_get_initial_payload(iscsi_conn_t *conn, iscsi_login_t *login)
{
	__u32 padding = 0;
	struct iscsi_init_login_cmnd *login_req;
	
	TRACE_ENTER

	login_req = (struct iscsi_init_login_cmnd *) login->req;

	TRACE(TRACE_LOGIN, "Got Login Command, Flags 0x%02x, ITT: 0x%08x,"
			" CmdSN: 0x%08x, ExpStatSN: 0x%08x, Length: %u\n",
		login_req->flags, login_req->init_task_tag, login_req->cmd_sn,
			login_req->exp_stat_sn, login_req->length);

	if (iscsi_target_check_login_request(conn, login) < 0)
		return(-1);
	
	padding = ((-login_req->length) & 3);
	
	if (iscsi_login_rx_data(
			conn,
			login->req_buf,
	    		login_req->length + padding,
			TARGET) < 0)
		return(-1);
	
	TRACE_LEAVE
	return(0);
}

/*	iscsi_target_check_for_existing_instances():
 *
 *	NOTE: We check for existing sessions or connections AFTER the initiator
 *	has been successfully authenticated in order to protect against faked
 *	ISID/TSIH combinations.
 */
static int iscsi_target_check_for_existing_instances (iscsi_conn_t *conn, iscsi_login_t *login)
{
	if (login->checked_for_existing)
		return(0);
	
	login->checked_for_existing = 1;
	
	if (!login->tsih)
		return(iscsi_check_for_session_reinstatement(conn));
	else
		return(iscsi_login_post_auth_non_zero_tsih(conn, login->cid,
				login->initial_exp_statsn));	
}

/*	iscsi_target_do_authentication():
 *
 *
 */
static int iscsi_target_do_authentication (iscsi_conn_t *conn, iscsi_login_t *login)
{
	int authret;
	iscsi_param_t *param;
	struct iscsi_init_login_cmnd *login_req;
	struct iscsi_targ_login_rsp *login_rsp;

	TRACE_ENTER

	login_req = (struct iscsi_init_login_cmnd *) login->req;
	login_rsp = (struct iscsi_targ_login_rsp *) login->rsp;

	if (!(param = iscsi_find_param_from_key(AUTHMETHOD, conn->param_list)))
		return(-1);

	authret = iscsi_handle_authentication(
			conn,
			login->req_buf,
		 	login->rsp_buf,
			login_req->length,
			&login_rsp->length,
			param->value,
			AUTH_SERVER);
	switch (authret) {
		case 0:
			PYXPRINT("Received OK response"
			" from iSBE Authentication"
			" Daemon, continuing.\n");
			break;
		case 1:
			PYXPRINT("iSCSI security negotiation"
				" completed sucessfully.\n");
			login->auth_complete = 1;
			if ((login_req->flags & NSG1) && (login_req->flags & T_BIT)) {
				login_rsp->flags |= (NSG1 | T_BIT);
				login->current_stage = 1;
			}
			return(iscsi_target_check_for_existing_instances(conn, login));
		case 2:
			TRACE_ERROR("Security negotiation"
				" failed.\n");
			iscsi_tx_login_rsp(conn, STAT_CLASS_INITIATOR,
					STAT_DETAIL_NOT_AUTH);
			return(-1);
		default:
			TRACE_ERROR ("Received unknown"
			" error %d from iSBE Authentication"
				" Daemon.\n", authret);
			iscsi_tx_login_rsp(conn, STAT_CLASS_TARGET,
					STAT_DETAIL_TARG_ERROR);
			return(-1);
	}

	TRACE_LEAVE
	return(0);
}

/*	iscsi_target_handle_csg_zero():
 *
 *
 */
static int iscsi_target_handle_csg_zero(iscsi_conn_t *conn, iscsi_login_t *login)
{
	int ret;
	iscsi_param_t *param;
	struct iscsi_init_login_cmnd *login_req;
	struct iscsi_targ_login_rsp *login_rsp;

	TRACE_ENTER

	login_req = (struct iscsi_init_login_cmnd *) login->req;
	login_rsp = (struct iscsi_targ_login_rsp *) login->rsp;

	if (!(param = iscsi_find_param_from_key(AUTHMETHOD, conn->param_list)))
		return(-1);

	if ((ret = iscsi_decode_text_input(
			PHASE_SECURITY|PHASE_DECLARATIVE,
			SENDER_INITIATOR|SENDER_RECEIVER,
			login->req_buf,
			login_req->length,
			conn->param_list)) < 0)
		return(-1);

	if (ret > 0) {
		if (login->auth_complete) {
			TRACE_ERROR("Initiator has already been successfully"
			" authenticated, but is still sending %s keys.\n",
				param->value);
			iscsi_tx_login_rsp(conn, STAT_CLASS_INITIATOR,
					STAT_DETAIL_INIT_ERROR);
			return(-1);
		}

		goto do_auth;
	}

	if (login->first_request)
		if (iscsi_target_check_first_request(conn, login) < 0)
			return(-1);

	if ((ret = iscsi_encode_text_output(
			PHASE_SECURITY|PHASE_DECLARATIVE,
			SENDER_TARGET,
			login->rsp_buf,
			&login_rsp->length,
			conn->param_list)) < 0)
		return(-1);

	if (!(iscsi_check_negotiated_keys(conn->param_list))) {
		if (ISCSI_TPG_ATTRIB(ISCSI_TPG_C(conn))->authentication &&
		    !strncmp(param->value, NONE, 4)) {
			TRACE_ERROR("Initiator sent AuthMethod=None but"
				" Target is enforcing iSCSI Authentication,"
					" login failed.\n");
			iscsi_tx_login_rsp(conn, STAT_CLASS_INITIATOR,
					STAT_DETAIL_NOT_AUTH);
			return(-1);
		}
		
		if (ISCSI_TPG_ATTRIB(ISCSI_TPG_C(conn))->authentication &&
		    !login->auth_complete)
			return(0);

		if (strncmp(param->value, NONE, 4) && !login->auth_complete)
			return(0);
		
		if ((login_req->flags & NSG1) && (login_req->flags & T_BIT)) {
			login_rsp->flags |= NSG1|T_BIT;
			login->current_stage = 1;
		}		
	}
	
	TRACE_LEAVE
	return(0);
do_auth:
	TRACE_LEAVE
	return(iscsi_target_do_authentication(conn, login));
}

/*	iscsi_target_handle_csg_one():
 *
 *
 */
static int iscsi_target_handle_csg_one(iscsi_conn_t *conn, iscsi_login_t *login)
{
	int ret;
	struct iscsi_init_login_cmnd *login_req;
	struct iscsi_targ_login_rsp *login_rsp;
	
	TRACE_ENTER

	login_req = (struct iscsi_init_login_cmnd *) login->req;
	login_rsp = (struct iscsi_targ_login_rsp *) login->rsp;

	if ((ret = iscsi_decode_text_input(
			PHASE_OPERATIONAL|PHASE_DECLARATIVE,
			SENDER_INITIATOR|SENDER_RECEIVER,
			login->req_buf,
			login_req->length,
			conn->param_list)) < 0)
		return(-1);

	if (login->first_request) {
		if (iscsi_target_check_first_request(conn, login) < 0)
			return(-1);
		if (iscsi_target_check_for_existing_instances(conn, login) < 0)
			return(-1);
	}

	if ((ret = iscsi_encode_text_output(
			PHASE_OPERATIONAL|PHASE_DECLARATIVE,
			SENDER_TARGET,
			login->rsp_buf,
			&login_rsp->length,
			conn->param_list)) < 0)
		return(-1);

	if (!(iscsi_check_negotiated_keys(conn->param_list)))
		if ((login_req->flags & NSG3) && (login_req->flags & T_BIT))
			login_rsp->flags |= NSG3|T_BIT;

	TRACE_LEAVE
	return(0);
}

/*	iscsi_target_do_login():
 *
 *
 */
static int iscsi_target_do_login(iscsi_conn_t *conn, iscsi_login_t *login)
{
	int pdu_count = 0;
	struct iscsi_init_login_cmnd *login_req;
	struct iscsi_targ_login_rsp *login_rsp;

	TRACE_ENTER

	login_req = (struct iscsi_init_login_cmnd *) login->req;
	login_rsp = (struct iscsi_targ_login_rsp *) login->rsp;

	while (1) {
		if (++pdu_count > MAX_LOGIN_PDUS) {
			TRACE_ERROR("MAX_LOGIN_PDUS count reached.\n");
			iscsi_tx_login_rsp(conn, STAT_CLASS_TARGET,
					STAT_DETAIL_TARG_ERROR);
			return(-1);
		}

		switch ((login_req->flags & CSG) >> CSG_SHIFT) {	
			case 0:
				login_rsp->flags |= (0 & CSG);
				if (iscsi_target_handle_csg_zero(conn, login) < 0)
					return(-1);
				break;
			case 1:
				login_rsp->flags |= CSG1;
				if (iscsi_target_handle_csg_one(conn, login) < 0)
					return(-1);
				if (login_rsp->flags & T_BIT) {
					login->tsih = SESS(conn)->tsih;
					if (iscsi_target_do_tx_login_io(conn, login) < 0)
						return(-1);	
					return(0);
				}
				break;
			default:
				TRACE_ERROR("Illegal CSG: %d received from"
					" Initiator, protocol error.\n",
					(login_req->flags & CSG) >> CSG_SHIFT);
				break;
		}

		if (iscsi_target_do_login_io(conn, login) < 0)
			return(-1);

		if (login_rsp->flags & T_BIT) {
			login_rsp->flags &= ~T_BIT;
			login_rsp->flags &= ~NSG;
		}
	}

	TRACE_LEAVE
	return(0);
}

/*
 * Processes the first Login Request..
 */
static int iscsi_target_locate_portal (
	iscsi_np_t *np,		
	iscsi_conn_t *conn,
	iscsi_login_t *login)
{
	char *i_buf = NULL, *s_buf = NULL, *t_buf = NULL;
	char *tmpbuf, *start = NULL, *end = NULL, *key, *value;
	iscsi_session_t *sess = conn->sess;
	iscsi_tiqn_t *tiqn;
	struct iscsi_init_login_cmnd *login_req;
	struct iscsi_targ_login_rsp *login_rsp;
	int sessiontype = 0, ret = 0;

	TRACE_ENTER

	login_req = (struct iscsi_init_login_cmnd *) login->req;
	login_rsp = (struct iscsi_targ_login_rsp *) login->rsp;

	login->first_request	= 1;
	login->leading_connection = (!login_req->tsih) ? 1 : 0;
	login->current_stage	= (login_req->flags & CSG) >> CSG_SHIFT;
	login->version_min	= login_req->version_min;
	login->version_max	= login_req->version_max;
	memcpy(login->isid, login_req->isid, 6);
	login->cmd_sn		= login_req->cmd_sn;
	login->init_task_tag	= login_req->init_task_tag;
	login->initial_exp_statsn = login_req->exp_stat_sn;
	login->cid		= login_req->cid;
	login->tsih		= login_req->tsih;

	if (iscsi_target_get_initial_payload(conn, login) < 0)
		return(-1);

	if (!(tmpbuf = (char *) kmalloc(login_req->length + 1, GFP_KERNEL))) {
		TRACE_ERROR("Unable to allocate memory for tmpbuf.\n");
		return(-1);
	}
	memset(tmpbuf, 0, login_req->length + 1);

	memcpy(tmpbuf, login->req_buf, login_req->length);
	tmpbuf[login_req->length] = '\0';
	start = tmpbuf;
	end = (start + login_req->length);

	/*
	 * Locate the initial keys expected from the Initiator node in
	 * the first login request in order to progress with the login phase.
	 */
	while (start < end) {
		if (iscsi_extract_key_value(start, &key, &value) < 0) {
			ret = -1;
			goto out;
		}
		
		if (!(strncmp(key, "InitiatorName", 13))) 
			i_buf = value;
		else if (!(strncmp(key, "SessionType", 11)))
			s_buf = value;
		else if (!(strncmp(key, "TargetName", 10)))
			t_buf = value;

		start += strlen(key) + strlen(value) + 2;
	}

	/*
	 * See 5.3.  Login Phase.
	 */
	if (!i_buf) {
		TRACE_ERROR("InitiatorName key not received"
			" in first login request.\n");
		iscsi_tx_login_rsp(conn, STAT_CLASS_INITIATOR,
			STAT_DETAIL_MISSING_PARAMETER);
		ret = -1;
		goto out;
	}
	if (!s_buf) {
		if (!login->leading_connection)
			goto get_target;

		TRACE_ERROR("SessionType key not received"
			" in first login request.\n");
		iscsi_tx_login_rsp(conn, STAT_CLASS_INITIATOR,
			STAT_DETAIL_MISSING_PARAMETER);
		ret = -1;
		goto out;
	}

	/*
	 * Use default portal group for discovery sessions.
	 */
	if (!(sessiontype = strncmp(s_buf, DISCOVERY, 9))) {
		conn->tpg = iscsi_global->discovery_tpg;
		if (!login->leading_connection)
			goto get_target;

		SESS_OPS(sess)->SessionType = sessiontype;
		/*
		 * Serialize access across the discovery iscsi_portal_group_t to
		 * process login attempt.
		 */
		if (core_access_np(np, conn->tpg) < 0) {
			iscsi_tx_login_rsp(conn, STAT_CLASS_TARGET,
				STAT_DETAIL_SERVICE_UNAVAILABLE);
			ret = -1;
			goto out;
		}
		ret = 0;
		goto out;
	}

get_target:
	if (!t_buf) {
		TRACE_ERROR("TargetName key not received"
			" in first login request while"
			" SessionType=Normal.\n");
		iscsi_tx_login_rsp(conn, STAT_CLASS_INITIATOR,
			STAT_DETAIL_MISSING_PARAMETER);
		ret = -1;
		goto out;
	}
	
	/*
	 * Locate Target IQN from Storage Node.
	 */
	if (!(tiqn = core_get_tiqn(t_buf))) {
		TRACE_ERROR("Unable to locate Target IQN: %s in"
			" Storage Node\n", t_buf);
		iscsi_tx_login_rsp(conn, STAT_CLASS_TARGET,
			STAT_DETAIL_SERVICE_UNAVAILABLE);
		ret = -1;
		goto out;
	}
	PYXPRINT("Located Storage Object: %s\n", tiqn->tiqn);

	/*
	 * Locate Target Portal Group from Storage Node.
	 */
	if (!(conn->tpg = core_get_tpg_from_np(tiqn, np))) {
		TRACE_ERROR("Unable to locate Target Portal Group"
				" on %s\n", tiqn->tiqn);
		iscsi_tx_login_rsp(conn, STAT_CLASS_TARGET,
			STAT_DETAIL_SERVICE_UNAVAILABLE);
		ret = -1;
		goto out;
	}
	PYXPRINT("Located Portal Group Object: %hu\n", conn->tpg->tpgt);

	/*
	 * Serialize access across the iscsi_portal_group_t to
	 * process login attempt.
	 */
	if (core_access_np(np, conn->tpg) < 0) {
		iscsi_tx_login_rsp(conn, STAT_CLASS_TARGET,
			STAT_DETAIL_SERVICE_UNAVAILABLE);
		ret = -1;
		goto out;
	}

	/*
	 * SESS(conn)->node_acl will be set when the referenced 
	 * iscsi_session_t is located from received ISID+TSIH in
	 * iscsi_login_non_zero_tsih_s2().
	 */
	if (!login->leading_connection) {
		ret = 0;
		goto out;
	}

	/*
	 * This value is required in iscsi_login_zero_tsih_s2()
	 */
	SESS_OPS(sess)->SessionType = sessiontype;

	/*
	 * Locate incoming Initiator IQN reference from Storage Node.
	 */
	if (!(SESS(conn)->node_acl = iscsi_tpg_check_initiator_node_acl(
			conn->tpg, i_buf))) {
		TRACE_ERROR("iSCSI Initiator Node: %s is not authorized to"
			" access iSCSI target portal group: %hu.\n",
				i_buf, conn->tpg->tpgt);
		iscsi_tx_login_rsp(conn, STAT_CLASS_INITIATOR,
				STAT_DETAIL_NOT_ALLOWED);
		ret = -1;
		goto out;
	}
	ret = 0;

out:
	TRACE_LEAVE
	kfree(tmpbuf);
	return(ret);
}

/*	iscsi_target_init_negotiation():
 *
 *
 */
extern iscsi_login_t *iscsi_target_init_negotiation(
	iscsi_np_t *np,
	iscsi_conn_t *conn,
	char *login_pdu)
{
	iscsi_login_t *login;
	
	TRACE_ENTER

	if (!(login = (iscsi_login_t *) kmalloc(sizeof(iscsi_login_t), GFP_KERNEL))) {
		TRACE_ERROR("Unable to allocate memory for iscsi_login_t.\n");
		iscsi_tx_login_rsp(conn, STAT_CLASS_TARGET,
				STAT_DETAIL_OUT_OF_RESOURCE);
		goto out;
	}
	memset(login, 0, sizeof(iscsi_login_t));
	
	if (!(login->req = (char *) kmalloc(ISCSI_HDR_LEN, GFP_KERNEL))) {
		TRACE_ERROR("Unable to allocate memory for Login Request.\n");
		iscsi_tx_login_rsp(conn, STAT_CLASS_TARGET,
				STAT_DETAIL_OUT_OF_RESOURCE);
		goto out;
	}
	memset(login->req, 0, ISCSI_HDR_LEN);
	memcpy(login->req, login_pdu, ISCSI_HDR_LEN);

	if (!(login->req_buf = (char *) kmalloc(MAX_TEXT_LEN, GFP_KERNEL))) {
		TRACE_ERROR("Unable to allocate memory for response buffer.\n");
		iscsi_tx_login_rsp(conn, STAT_CLASS_TARGET,
				STAT_DETAIL_OUT_OF_RESOURCE);
		goto out;
	}
	memset(login->req_buf, 0, MAX_TEXT_LEN);
	
	/*
	 * SessionType: Discovery
	 *
	 * 	Locates Default Portal
	 *
	 * SessionType: Normal
	 *
	 * 	Locates Target Portal from NP -> Target IQN
	 */
	if (iscsi_target_locate_portal(np, conn, login) < 0) {
		TRACE_ERROR("iSCSI Login negotiation failed.\n");
		goto out;
	}

	return(login);
out:
	kfree(login->req);
	kfree(login->req_buf);
	kfree(login);

	TRACE_LEAVE
	return(NULL);
}

extern int iscsi_target_start_negotiation (
	iscsi_login_t *login,
	iscsi_conn_t *conn)
{
	int ret = -1;

	if (!(login->rsp = (char *) kmalloc(ISCSI_HDR_LEN, GFP_KERNEL))) {
		TRACE_ERROR("Unable to allocate memory for Login Response.\n");
		iscsi_tx_login_rsp(conn, STAT_CLASS_TARGET,
				STAT_DETAIL_OUT_OF_RESOURCE);
		ret = -1;
		goto out;
	}
	memset(login->rsp, 0, ISCSI_HDR_LEN);

	if (!(login->rsp_buf = (char *) kmalloc(MAX_TEXT_LEN, GFP_KERNEL))) {
		TRACE_ERROR("Unable to allocate memory for request buffer.\n");
		iscsi_tx_login_rsp(conn, STAT_CLASS_TARGET,
				STAT_DETAIL_OUT_OF_RESOURCE);
		ret = -1;
		goto out;
	}
	memset(login->rsp_buf, 0, MAX_TEXT_LEN);

	ret = iscsi_target_do_login(conn, login);
out:
	if (ret != 0)
		iscsi_remove_failed_auth_entry(conn, AUTH_SERVER);

	iscsi_target_nego_release(login, conn);
	return(ret);
}

extern void iscsi_target_nego_release (
	iscsi_login_t *login,
	iscsi_conn_t *conn)
{
	kfree(login->req);
	kfree(login->rsp);
	kfree(login->req_buf);
	kfree(login->rsp_buf);
	kfree(login);
	
	return;
}
