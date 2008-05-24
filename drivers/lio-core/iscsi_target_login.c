/*********************************************************************************
 * Filename:  iscsi_target_login.c
 *
 * This file contains the login functions used by the iSCSI Target driver.
 *
 * Copyright (c) 2003, 2004, 2005 PyX Technologies, Inc.
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


#define ISCSI_TARGET_LOGIN_C

#include <linux/string.h>
#include <linux/timer.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/smp_lock.h>
#include <linux/in.h>
#include <linux/inet.h>
#include <net/sock.h>
#include <net/tcp.h>
#include <net/ipv6.h>

#include <iscsi_linux_os.h>
#include <iscsi_linux_defs.h>

#include <iscsi_protocol.h>
#include <iscsi_debug_opcodes.h>
#include <iscsi_debug.h>
#include <iscsi_lists.h>
#include <iscsi_target_core.h>
#include <iscsi_target_ioctl.h>
#include <iscsi_target_device.h>
#include <iscsi_target_nego.h>
#include <iscsi_target_erl0.h>
#include <iscsi_target_erl2.h>
#include <iscsi_target_util.h>
#include <iscsi_target.h>
#include <iscsi_parameters.h>

#undef ISCSI_TARGET_LOGIN_C

extern se_global_t *iscsi_global;
extern int iscsi_close_session (iscsi_session_t *);
extern int iscsi_stop_session (iscsi_session_t *, int, int);

/*	iscsi_login_init_conn():
 *
 *
 */
static void iscsi_login_init_conn (iscsi_conn_t *conn)
{
	init_MUTEX_LOCKED(&conn->conn_post_wait_sem);
	init_MUTEX_LOCKED(&conn->conn_wait_sem);
	init_MUTEX_LOCKED(&conn->conn_wait_rcfr_sem);
	init_MUTEX_LOCKED(&conn->conn_waiting_on_uc_sem);
	init_MUTEX_LOCKED(&conn->conn_logout_sem);
	init_MUTEX_LOCKED(&conn->rx_half_close_sem);
	init_MUTEX_LOCKED(&conn->tx_half_close_sem);
	init_MUTEX_LOCKED(&conn->tx_sem);
	spin_lock_init(&conn->cmd_lock);
	spin_lock_init(&conn->conn_usage_lock);
	spin_lock_init(&conn->immed_queue_lock);
	spin_lock_init(&conn->netif_lock);
	spin_lock_init(&conn->nopin_timer_lock);
	spin_lock_init(&conn->response_queue_lock);
	spin_lock_init(&conn->state_lock);
	
	return;
}

/*	iscsi_login_check_initiator_version():
 *
 *
 */
static int iscsi_login_check_initiator_version(
	iscsi_conn_t *conn,
	__u8 version_max,
	__u8 version_min)
{
	if ((version_max != 0x00) || (version_min != 0x00)) {
		TRACE_ERROR("Unsupported iSCSI IETF Pre-RFC Revision, version"
				" Min/Max 0x%02x/0x%02x, rejecting login.\n",
				version_min, version_max);
		iscsi_tx_login_rsp(conn, STAT_CLASS_INITIATOR,
				STAT_DETAIL_VERSION_NOT_SUPPORTED);
		return(-1);
	}
		
	return(0);
}

/*	iscsi_check_for_session_reinstatement():
 *
 *
 */
extern int iscsi_check_for_session_reinstatement (iscsi_conn_t *conn)
{
	int sessiontype;
	iscsi_param_t *initiatorname_param = NULL, *sessiontype_param = NULL;
	iscsi_portal_group_t *tpg = conn->tpg;
	iscsi_session_t *sess = NULL;
	
	if (!(initiatorname_param = iscsi_find_param_from_key(
			INITIATORNAME, conn->param_list)))
		return(-1);

	if (!(sessiontype_param = iscsi_find_param_from_key(
			SESSIONTYPE, conn->param_list)))
		return(-1);

	sessiontype = (strncmp(sessiontype_param->value, NORMAL, 6)) ? 1 : 0;
	
	spin_lock_bh(&tpg->session_lock);
	for (sess = tpg->session_head; sess; sess = sess->next) {
		spin_lock(&sess->conn_lock);
		if (atomic_read(&sess->session_fall_back_to_erl0) ||
		    atomic_read(&sess->session_logout) ||
		    (sess->time2retain_timer_flags & T2R_TF_EXPIRED)) {
			spin_unlock(&sess->conn_lock);
			continue;
		}
		if (!memcmp((void *)sess->isid, (void *)SESS(conn)->isid, 6) &&
		   (!strcmp((void *)SESS_OPS(sess)->InitiatorName,
			    (void *)initiatorname_param->value) &&
		   (SESS_OPS(sess)->SessionType == sessiontype))) {
			atomic_set(&sess->session_reinstatement, 1);
			spin_unlock(&sess->conn_lock);
			iscsi_inc_session_usage_count(sess);
			iscsi_stop_time2retain_timer(sess);
			break;
		}
		spin_unlock(&sess->conn_lock);
	}
	spin_unlock_bh(&tpg->session_lock);

	/*              
	 * If the Time2Retain handler has expired, the session is already gone.
	 */
	if (!sess)
		return(0);

	TRACE(TRACE_ERL0, "%s iSCSI Session SID %u is still active for %s, preforming"
		" session reinstatement.\n", (sessiontype) ? "Discovery" :
			"Normal", sess->sid, SESS_OPS(sess)->InitiatorName);

	spin_lock_bh(&sess->conn_lock);
	if (sess->session_state == TARG_SESS_STATE_FAILED) {
		spin_unlock_bh(&sess->conn_lock);
		iscsi_dec_session_usage_count(sess);
		return(iscsi_close_session(sess));
	}
	spin_unlock_bh(&sess->conn_lock);
	
	iscsi_stop_session(sess, 1, 1);
	iscsi_dec_session_usage_count(sess);

	return(iscsi_close_session(sess));
}

extern int iscsi_login_disable_FIM_keys (iscsi_param_list_t *, iscsi_conn_t *);

static void iscsi_login_set_conn_values (
	iscsi_session_t *sess,
	iscsi_conn_t *conn,
	u16 cid)
{
	conn->sess		= sess;
	conn->cid 		= cid;
#warning FIXME: Generate random default StatSN for connection
	conn->stat_sn		= 1;

	down(&iscsi_global->auth_id_sem);
	conn->auth_id		= iscsi_global->auth_id++;
	up(&iscsi_global->auth_id_sem);

	return;
}

/*	iscsi_login_zero_tsih():
 *
 *	This is the leading connection of a new session,
 *	or session reinstatement.
 */
static int iscsi_login_zero_tsih_s1 (
	iscsi_conn_t *conn,
	unsigned char *buf)
{
	iscsi_session_t *sess = NULL;
	struct iscsi_init_login_cmnd *pdu = (struct iscsi_init_login_cmnd *) buf;

	if (!(sess = (iscsi_session_t *) kmalloc(sizeof(iscsi_session_t), GFP_KERNEL))) {
		iscsi_tx_login_rsp(conn, STAT_CLASS_TARGET, STAT_DETAIL_OUT_OF_RESOURCE);
		TRACE_ERROR("Could not allocate memory for session\n");
		return(-1);
	}
	memset(sess, 0, sizeof(iscsi_session_t));

	iscsi_login_set_conn_values(sess, conn, pdu->cid);
	sess->init_task_tag	= pdu->init_task_tag;
	memcpy((void *)&sess->isid, (void *)pdu->isid, 6);
	sess->exp_cmd_sn	= pdu->cmd_sn;
	init_MUTEX_LOCKED(&sess->async_msg_sem);
	init_MUTEX_LOCKED(&sess->reinstatement_sem);
	init_MUTEX_LOCKED(&sess->session_wait_sem);
	init_MUTEX_LOCKED(&sess->session_waiting_on_uc_sem);
	spin_lock_init(&sess->cmdsn_lock);
	spin_lock_init(&sess->conn_lock);
	spin_lock_init(&sess->cr_a_lock);
	spin_lock_init(&sess->cr_i_lock);
	spin_lock_init(&sess->pool_lock);
	spin_lock_init(&sess->session_usage_lock);
	spin_lock_init(&sess->ttt_lock);
#ifdef SNMP_SUPPORT
	sess->session_index = get_new_index(ISCSI_SESSION_INDEX);
	sess->creation_time = get_jiffies_64();
	spin_lock_init(&sess->session_stats_lock);
#endif /* SNMP_SUPPORT */

	/*
	 * The FFP CmdSN window values will be allocated from the TPG's Initiator Node's
	 * ACL once the login has been successfully completed.
	 */
	sess->max_cmd_sn	= pdu->cmd_sn;

	if (!(sess->sess_ops = (iscsi_sess_ops_t *)
			kmalloc(sizeof(iscsi_sess_ops_t), GFP_KERNEL))) {
		iscsi_tx_login_rsp(conn, STAT_CLASS_TARGET, STAT_DETAIL_OUT_OF_RESOURCE);
		TRACE_ERROR("Unable to allocate memory for iscsi_sess_ops_t.\n");
		return(-1);
	}
	memset(sess->sess_ops, 0, sizeof(iscsi_sess_ops_t));

	return(0);
}

static int iscsi_login_zero_tsih_s2 (
	iscsi_conn_t *conn)
{
	iscsi_node_acl_t *acl;
	iscsi_session_t *sess = conn->sess;
	unsigned char buf[32];

	sess->tpg = conn->tpg;

	/*
	 * Assign a new TPG Session Handle.  Note this is protected with
	 * iscsi_portal_group_t->np_login_sem from core_access_np().
	 */
	if (!(sess->tsih = ++ISCSI_TPG_S(sess)->ntsih))
		sess->tsih = ++ISCSI_TPG_S(sess)->ntsih;

	/*
	 * Create the default params from user defined values..
	 */
	if (iscsi_copy_param_list(&conn->param_list, ISCSI_TPG_C(conn)->param_list, 1) < 0) {
		iscsi_tx_login_rsp(conn, STAT_CLASS_TARGET, STAT_DETAIL_OUT_OF_RESOURCE);
		return(-1);
	}
	
	iscsi_set_keys_to_negotiate(TARGET, 0, conn->param_list);

	if (!(SESS_OPS(sess)->SessionType))
		return(iscsi_set_keys_irrelevant_for_discovery(conn->param_list));

	acl = sess->node_acl;

	/*
	 * Need to send TargetPortalGroupTag back in first login response
	 * on any iSCSI connection where the Initiator provides TargetName.
	 * See 5.3.1.  Login Phase Start
	 *
	 * In our case, we have already located the iscsi_tiqn_t at this point.
	 */
	memset(buf, 0, 32);
	sprintf(buf, "TargetPortalGroupTag=%hu", ISCSI_TPG_S(sess)->tpgt);
	if (iscsi_change_param_value(buf, TARGET, conn->param_list, 0) < 0) {
		iscsi_tx_login_rsp(conn, STAT_CLASS_TARGET, STAT_DETAIL_OUT_OF_RESOURCE);
		return(-1);
	}

	/*
	 * Workaround for Initiators that have broken connection recovery logic.
	 *
	 * "We would really like to get rid of this." Linux-iSCSI.org team
	 */
	memset(buf, 0, 32);
	sprintf(buf, "ErrorRecoveryLevel=%d", ISCSI_NODE_ATTRIB(acl)->default_erl);
	if (iscsi_change_param_value(buf, TARGET, conn->param_list, 0) < 0) {
		iscsi_tx_login_rsp(conn, STAT_CLASS_TARGET, STAT_DETAIL_OUT_OF_RESOURCE);
		return(-1);
	}

	if (iscsi_login_disable_FIM_keys(conn->param_list, conn) < 0)
		return(-1);

	return(0);
}

/*
 * Remove PSTATE_NEGOTIATE for the four FIM related keys.
 * The Initiator node will be able to enable FIM by proposing them itself.
 */
extern int iscsi_login_disable_FIM_keys (iscsi_param_list_t *param_list, iscsi_conn_t *conn)
{
	iscsi_param_t *param;
	
	if (!(param = iscsi_find_param_from_key("OFMarker", param_list))) {
		TRACE_ERROR("iscsi_find_param_from_key() for OFMarker failed\n");
		iscsi_tx_login_rsp(conn, STAT_CLASS_TARGET, STAT_DETAIL_OUT_OF_RESOURCE);
		return(-1);
	}
	param->state &= ~PSTATE_NEGOTIATE;

	if (!(param = iscsi_find_param_from_key("OFMarkInt", param_list))) {
		TRACE_ERROR("iscsi_find_param_from_key() for IFMarker failed\n");
		iscsi_tx_login_rsp(conn, STAT_CLASS_TARGET, STAT_DETAIL_OUT_OF_RESOURCE);
		return(-1);
	}
	param->state &= ~PSTATE_NEGOTIATE;

	if (!(param = iscsi_find_param_from_key("IFMarker", param_list))) {
		TRACE_ERROR("iscsi_find_param_from_key() for IFMarker failed\n");
		iscsi_tx_login_rsp(conn, STAT_CLASS_TARGET, STAT_DETAIL_OUT_OF_RESOURCE);
		return(-1);
	}
	param->state &= ~PSTATE_NEGOTIATE;

	if (!(param = iscsi_find_param_from_key("IFMarkInt", param_list))) {
		TRACE_ERROR("iscsi_find_param_from_key() for IFMarker failed\n");
		iscsi_tx_login_rsp(conn, STAT_CLASS_TARGET, STAT_DETAIL_OUT_OF_RESOURCE);
		return(-1);
	}
	param->state &= ~PSTATE_NEGOTIATE;

	return(0);
}

static int iscsi_login_non_zero_tsih_s1 (
	iscsi_conn_t *conn,
	unsigned char *buf)
{
	struct iscsi_init_login_cmnd *pdu = (struct iscsi_init_login_cmnd *) buf;

	iscsi_login_set_conn_values(NULL, conn, pdu->cid);
	return(0);
}

/*	iscsi_login_non_zero_tsih_s2():
 *
 *	Add a new connection to an existing session.
 */
static int iscsi_login_non_zero_tsih_s2 (
	iscsi_conn_t *conn,
	unsigned char *buf)
{
	iscsi_portal_group_t *tpg = conn->tpg;
	iscsi_session_t *sess = NULL;
	struct iscsi_init_login_cmnd *pdu = (struct iscsi_init_login_cmnd *) buf;
	
	spin_lock_bh(&tpg->session_lock);
	for (sess = tpg->session_head; sess; sess = sess->next) {
		if (atomic_read(&sess->session_fall_back_to_erl0) ||
		    atomic_read(&sess->session_logout) ||
		   (sess->time2retain_timer_flags & T2R_TF_EXPIRED))
			continue;
		if (!(memcmp((const void *)sess->isid,
		     (const void *)pdu->isid, 6)) &&
		     (sess->tsih == pdu->tsih)) {
			iscsi_inc_session_usage_count(sess);
			iscsi_stop_time2retain_timer(sess);
			break;
		}
	}
	spin_unlock_bh(&tpg->session_lock);

	/*
	 * If the Time2Retain handler has expired, the session is already gone.
	 */
	if (!sess) {
		TRACE_ERROR("Initiator attempting to add a connection to"
			" a non-existent session, rejecting iSCSI Login.\n");
		iscsi_tx_login_rsp(conn, STAT_CLASS_INITIATOR,
				STAT_DETAIL_SESSION_DOES_NOT_EXIST);
		return(-1);
	}

	/*
	 * Stop the Time2Retain timer if this is a failed session, we restart
	 * the timer if the login is not successful.
	 */
	spin_lock_bh(&sess->conn_lock);
	if (sess->session_state == TARG_SESS_STATE_FAILED)
		atomic_set(&sess->session_continuation, 1);
	spin_unlock_bh(&sess->conn_lock);

	iscsi_login_set_conn_values(sess, conn, pdu->cid);
	
	if (iscsi_copy_param_list(&conn->param_list,
			ISCSI_TPG_C(conn)->param_list, 0) < 0) {
		iscsi_tx_login_rsp(conn, STAT_CLASS_TARGET,
				STAT_DETAIL_OUT_OF_RESOURCE);
		return(-1);
	}

	iscsi_set_keys_to_negotiate(TARGET, 0, conn->param_list);

	/*
	 * Need to send TargetPortalGroupTag back in first login response
	 * on any iSCSI connection where the Initiator provides TargetName.
	 * See 5.3.1.  Login Phase Start
	 *
	 * In our case, we have already located the iscsi_tiqn_t at this point.
	 */
	memset(buf, 0, 32);
	sprintf(buf, "TargetPortalGroupTag=%hu", ISCSI_TPG_S(sess)->tpgt);
	if (iscsi_change_param_value(buf, TARGET, conn->param_list, 0) < 0) {
		iscsi_tx_login_rsp(conn, STAT_CLASS_TARGET, STAT_DETAIL_OUT_OF_RESOURCE);		return(-1);
	}

	return(iscsi_login_disable_FIM_keys(conn->param_list, conn));
}

/*	iscsi_login_post_auth_non_zero_tsih():
 *
 *
 */
extern int iscsi_login_post_auth_non_zero_tsih (
	iscsi_conn_t *conn,
	__u16 cid,
	__u32 exp_statsn)
{
	iscsi_conn_t *conn_ptr = NULL;
	iscsi_conn_recovery_t *cr = NULL;
	iscsi_session_t *sess = SESS(conn);
	
	/*
	 * By following item 5 in the login table,  if we have found 
	 * an existing ISID and a valid/existing TSIH and an existing
	 * CID we do connection reinstatement.  Currently we dont not
	 * support it so we send back an non-zero status class to the
	 * initiator and release the new connection.
	 */	
	if ((conn_ptr = iscsi_get_conn_from_cid_rcfr(sess, cid))) {
		TRACE_ERROR("Connection exists with CID %hu for %s, performing"
			" connection reinstatement.\n", conn_ptr->cid,
				SESS_OPS(sess)->InitiatorName);
		iscsi_connection_reinstatement_rcfr(conn_ptr);
		iscsi_dec_conn_usage_count(conn_ptr);
	}
	
	/*
	 * Check for any connection recovery entires containing CID.
	 * We use the original ExpStatSN sent in the first login request
	 * to acknowledge commands for the failed connection.
	 *
	 * Also note that an explict logout may have already been sent,
	 * but the response may not be sent due to additional connection
	 * loss.
	 */
	if (SESS_OPS(sess)->ErrorRecoveryLevel == 2) {
		if ((cr = iscsi_get_inactive_connection_recovery_entry(
				sess, cid))) {
			TRACE(TRACE_ERL2, "Performing implicit logout"
				" for connection recovery on CID: %hu\n",
					conn->cid);
			iscsi_discard_cr_cmds_by_expstatsn(cr, exp_statsn);
		}
	}
	
	/*
	 * Else we follow item 4 from the login table in that we have
	 * found an existing ISID and a valid/existing TSIH and a new
	 * CID we go ahead and continue to add a new connection to the
	 * session.
	 */
	TRACE(TRACE_LOGIN, "Adding CID %hu to existing session for %s.\n",
			cid, SESS_OPS(sess)->InitiatorName);

	if ((atomic_read(&sess->nconn) + 1) > SESS_OPS(sess)->MaxConnections) {		
		TRACE_ERROR("Adding additional connection to this session"
			" would exceed MaxConnections %d, login failed.\n",
				SESS_OPS(sess)->MaxConnections);
		iscsi_tx_login_rsp(conn, STAT_CLASS_INITIATOR,
				STAT_DETAIL_TOO_MANY_CONNECTIONS);
		return(-1);
	}

	return(0);
}

/*	iscsi_post_login_start_timers():
 *
 *
 */
static void iscsi_post_login_start_timers (iscsi_conn_t *conn)
{
	iscsi_session_t *sess = SESS(conn);

//#warning PHY timer is disabled..
#if 0	
	iscsi_get_network_interface_from_conn(conn);

	spin_lock_bh(&conn->netif_lock);
	iscsi_start_netif_timer(conn);
	spin_unlock_bh(&conn->netif_lock);
#endif
	if (!SESS_OPS(sess)->SessionType)
		iscsi_start_nopin_timer(conn);	

	return;
}
	
/*	iscsi_post_login_handler():
 *
 *
 */
static int iscsi_post_login_handler (iscsi_np_t *np, iscsi_conn_t *conn, __u8 zero_tsih)
{
	int stop_timer = 0;
	unsigned char buf_ipv4[IPV4_BUF_SIZE], buf1_ipv4[IPV4_BUF_SIZE];
	unsigned char *ip, *ip_np;
	iscsi_session_t *sess = SESS(conn);
	iscsi_portal_group_t *tpg = ISCSI_TPG_S(sess);
	iscsi_thread_set_t *ts;

	iscsi_inc_conn_usage_count(conn);

#ifdef SNMP_SUPPORT
	iscsi_collect_login_stats(conn, STAT_CLASS_SUCCESS,STAT_DETAIL_SUCCESS);
#endif

	TRACE(TRACE_STATE, "Moving to TARG_CONN_STATE_LOGGED_IN.\n");
	conn->conn_state = TARG_CONN_STATE_LOGGED_IN;

	iscsi_set_connection_parameters(conn->conn_ops, conn->param_list);
	iscsi_set_sync_and_steering_values(conn);

	if (np->np_net_size == IPV6_ADDRESS_SPACE) {
		ip = &conn->ipv6_login_ip[0];
		ip_np = &np->np_ipv6[0];
	} else {
		memset(buf_ipv4, 0, IPV4_BUF_SIZE);
		memset(buf1_ipv4, 0, IPV4_BUF_SIZE);
		iscsi_ntoa2(buf_ipv4, conn->login_ip);
		iscsi_ntoa2(buf1_ipv4, np->np_ipv4);
		ip = &buf_ipv4[0];
		ip_np = &buf1_ipv4[0];
	}
	
	/*
	 * SCSI Initiator -> SCSI Target Port Mapping
	 */
	ts = iscsi_get_thread_set(TARGET);
	if (!zero_tsih) {
		iscsi_set_session_parameters(sess->sess_ops, conn->param_list, 0);
		iscsi_release_param_list(conn->param_list);
		conn->param_list = NULL;

		spin_lock_bh(&sess->conn_lock);
		atomic_set(&sess->session_continuation, 0);
		if (sess->session_state == TARG_SESS_STATE_FAILED) {
			TRACE(TRACE_STATE, "Moving to TARG_SESS_STATE_LOGGED_IN.\n");
			sess->session_state = TARG_SESS_STATE_LOGGED_IN;
			stop_timer = 1;
		}

		PYXPRINT("iSCSI Login successful on CID: %hu from %s to"
			" %s:%hu,%hu\n", conn->cid, ip, ip_np,
				np->np_port, tpg->tpgt);
		
		ADD_ENTRY_TO_LIST(conn, sess->conn_head, sess->conn_tail);
		atomic_inc(&sess->nconn);
		PYXPRINT("Incremented iSCSI Connection count to %hu from node:"
			" %s\n", atomic_read(&sess->nconn), SESS_OPS(sess)->InitiatorName);
		spin_unlock_bh(&sess->conn_lock);

		iscsi_post_login_start_timers(conn);
		iscsi_activate_thread_set(conn, ts);
		iscsi_dec_conn_usage_count(conn);
		if (stop_timer) {
			spin_lock_bh(&tpg->session_lock);
			iscsi_stop_time2retain_timer(sess);
			spin_unlock_bh(&tpg->session_lock);
		}
		iscsi_dec_session_usage_count(sess);
		return(0);
	}
	
	iscsi_set_session_parameters(sess->sess_ops, conn->param_list, 1);
	iscsi_release_param_list(conn->param_list);
	conn->param_list = NULL;

	iscsi_determine_maxcmdsn(sess, sess->node_acl);
		
	spin_lock_bh(&tpg->session_lock);
	ADD_ENTRY_TO_LIST(sess, tpg->session_head, tpg->session_tail);
	TRACE(TRACE_STATE, "Moving to TARG_SESS_STATE_LOGGED_IN.\n");
	sess->session_state = TARG_SESS_STATE_LOGGED_IN;
	
	PYXPRINT("iSCSI Login successful on CID: %hu from %s to %s:%hu,%hu\n",
		conn->cid, ip, ip_np, np->np_port, tpg->tpgt);
	
	spin_lock_bh(&sess->conn_lock);
	ADD_ENTRY_TO_LIST(conn, sess->conn_head, sess->conn_tail);
	atomic_inc(&sess->nconn);
	PYXPRINT("Incremented iSCSI Connection count to %hu from node:"
		" %s\n", atomic_read(&sess->nconn), SESS_OPS(sess)->InitiatorName);
	spin_unlock_bh(&sess->conn_lock);
	
	sess->sid = tpg->sid++;
	if (!sess->sid)
		sess->sid = tpg->sid++;
	PYXPRINT("Established iSCSI session from node: %s\n",
			SESS_OPS(sess)->InitiatorName);
	
	tpg->nsessions++;
	PYXPRINT("Incremented number of active iSCSI sessions to %u on iSCSI"
		" Target Portal Group: %hu\n", tpg->nsessions, tpg->tpgt); 
	spin_unlock_bh(&tpg->session_lock);

	iscsi_post_login_start_timers(conn);
	iscsi_activate_thread_set(conn, ts);

	iscsi_dec_conn_usage_count(conn);

	return(0);
}

/*	iscsi_handle_login_thread_timeout():
 *
 *
 */
#warning FIXME: Reference login timeout to iscsi_portal_group when possible
static void iscsi_handle_login_thread_timeout (unsigned long data)
{
	unsigned char buf_ipv4[IPV4_BUF_SIZE];
	iscsi_np_t *np = (iscsi_np_t *) data;
	
	memset(buf_ipv4, 0, IPV4_BUF_SIZE);
	spin_lock_bh(&np->np_thread_lock);
	iscsi_ntoa2(buf_ipv4, np->np_ipv4);
	
	TRACE_ERROR("iSCSI Login timeout on Network Portal %s:%hu\n",
			buf_ipv4, np->np_port);

	if (np->np_login_timer_flags & TPG_NP_TF_STOP) {
		spin_unlock_bh(&np->np_thread_lock);
		return;
	}
	
	if (np->np_thread)
		send_sig(SIGKILL, np->np_thread, 1);

	np->np_login_timer_flags &= ~TPG_NP_TF_RUNNING;
	spin_unlock_bh(&np->np_thread_lock);

	return;
}

/*	iscsi_start_login_thread_timer():
 *
 *
 */
#warning FIXME: iscsi_start_login_thread_timer() hardcoded timeout
static void iscsi_start_login_thread_timer (iscsi_np_t *np)
{
	
	spin_lock_bh(&np->np_thread_lock);
	init_timer(&np->np_login_timer);
	SETUP_TIMER(np->np_login_timer, /* ISCSI_TPG_ATTRIB(tpg)->login_timeout */ 15,
		np, iscsi_handle_login_thread_timeout);
	np->np_login_timer_flags |= TPG_NP_TF_RUNNING;
	add_timer(&np->np_login_timer);

	TRACE(TRACE_LOGIN, "Added timeout timer to iSCSI login request for"
		" %u seconds.\n", /* ISCSI_TPG_ATTRIB(tpg)->login_timeout */ 15);
	spin_unlock_bh(&np->np_thread_lock);
	
	return;
}

/*	iscsi_stop_login_thread_timer():
 *
 *
 */
static void iscsi_stop_login_thread_timer (iscsi_np_t *np)
{
	spin_lock_bh(&np->np_thread_lock);
	if (!(np->np_login_timer_flags & TPG_NP_TF_RUNNING)) {
		spin_unlock_bh(&np->np_thread_lock);
		return;
	}
	np->np_login_timer_flags |= TPG_NP_TF_STOP;
	spin_unlock_bh(&np->np_thread_lock);

	del_timer_sync(&np->np_login_timer);

	spin_lock_bh(&np->np_thread_lock);
	np->np_login_timer_flags &= ~TPG_NP_TF_RUNNING;
	np->np_login_timer_flags &= ~TPG_NP_TF_STOP;
	spin_unlock_bh(&np->np_thread_lock);
		
	return;
}

/*	iscsi_target_setup_login_socket():
 *
 *
 */
static struct socket *iscsi_target_setup_login_socket (iscsi_np_t *np)
{
	int backlog = 5, ip_proto, sock_type, ret;
	struct socket *sock;
	struct sockaddr_in sock_in;
	struct sockaddr_in6 sock_in6;
	
	switch (np->np_network_transport) {
	case ISCSI_TCP:
		ip_proto = IPPROTO_TCP;
		sock_type = SOCK_STREAM;
		break;
	case ISCSI_SCTP_TCP:
		ip_proto = IPPROTO_SCTP;
		sock_type = SOCK_STREAM;
		break;
	case ISCSI_SCTP_UDP:
		ip_proto = IPPROTO_SCTP;
		sock_type = SOCK_SEQPACKET;
		break;
	case ISCSI_IWARP_TCP:
	case ISCSI_IWARP_SCTP:
	case ISCSI_INFINIBAND:
	default:
		TRACE_ERROR("Unsupported network_transport: %d\n",
				np->np_network_transport);
		goto fail;
	}
	
	if (iscsi_sock_create(&sock, (np->np_flags & NPF_NET_IPV6) ? AF_INET6 :
			AF_INET, sock_type, ip_proto, NULL, NULL) < 0) {
		TRACE_ERROR("iscsi_sock_create() failed.\n");
		goto fail;
	}
	np->np_socket = sock;

	/*
	 * The SCTP stack needs struct socket->file.
	 */
	if ((np->np_network_transport == ISCSI_SCTP_TCP) ||
	    (np->np_network_transport == ISCSI_SCTP_UDP)) {
		if (!sock->file) {
			if (!(sock->file = kmalloc(
					sizeof(struct file), GFP_KERNEL))) {
				TRACE_ERROR("Unable to allocate struct file for SCTP\n");
				goto fail;
			}
			memset(sock->file, 0, sizeof(struct file));

			np->np_flags |= NPF_SCTP_STRUCT_FILE;
		}
	}
	
	if (np->np_flags & NPF_NET_IPV6) {
		memset(&sock_in6, 0, sizeof(struct sockaddr_in6));
		sock_in6.sin6_family = AF_INET6;
		sock_in6.sin6_port = htons(np->np_port);
//		sock_in6.sin6_scope_id = if_nametoindex("eth0");
#if 0
		if ((ret = in6_pton(&np->np_ipv6[0], -1 /* len */,
				(void *)&sock_in6.sin6_addr.in6_u,
				'\\', NULL)) <= 0) {
			TRACE_ERROR("in6_pton returned: %d\n", ret);
			goto fail;
		}
#else
		if ((ret = iscsi_pton6(&np->np_ipv6[0],
				(unsigned char *)&sock_in6.sin6_addr.in6_u)) <= 0) {
			TRACE_ERROR("iscsi_pton6() returned: %d\n", ret);
			goto fail;
		}
#endif
	} else {
		memset(&sock_in, 0, sizeof(struct sockaddr_in));
		sock_in.sin_family = AF_INET;
		sock_in.sin_port = htons(np->np_port);
		sock_in.sin_addr.s_addr = htonl(np->np_ipv4);
	}

	/*
	 * Set SO_REUSEADDR, and disable Nagel Algorithm with TCP_NODELAY.
	 * NOTE: setsockopt() w/ SO_REUSEADDR on LINUX 2.4 is broken,  force it.
	 */
	iscsi_sock_sockopt_on(sock, IPPROTO_TCP, TCP_NODELAY);
	iscsi_sock_sockopt_on(sock, SOL_SOCKET, SO_REUSEADDR);
	sock->sk->sk_reuse = 1;
	
	if (np->np_flags & NPF_NET_IPV6) {
		if ((ret = iscsi_sock_bind(sock, (struct sockaddr *)&sock_in6,
				sizeof(struct sockaddr_in6), NULL)) < 0) {
			TRACE_ERROR("iscsi_sock_bind() failed: %d\n", ret);
			goto fail;
		}
	} else {
		if ((ret = iscsi_sock_bind(sock, (struct sockaddr *)&sock_in,
				sizeof(struct sockaddr), NULL)) < 0) {
			TRACE_ERROR("iscsi_sock_bind() failed: %d\n", ret);
			goto fail;
		}
	}

	if (iscsi_sock_listen(sock, backlog, NULL)) {
		TRACE_ERROR("iscsi_sock_listen() failed.\n");
		goto fail;
	}
	
	return(sock);

fail:
	np->np_socket = NULL;
	if (sock) {
		if (np->np_flags & NPF_SCTP_STRUCT_FILE) {
			kfree(sock->file);
			sock->file = NULL;
		}

		sock_release(sock);
	}
	return(NULL);
}

/*	iscsi_target_login_thread():
 *	
 *
 */
extern int iscsi_target_login_thread (void *arg)
{
	u8 buffer[ISCSI_HDR_LEN], iscsi_opcode, zero_tsih = 0;
	unsigned char *ip = NULL, *ip_init_buf = NULL;
	unsigned char buf_ipv4[IPV4_BUF_SIZE], buf1_ipv4[IPV4_BUF_SIZE];
	int err, ret = 0, start = 1, ip_proto, sock_type, set_sctp_conn_flag = 0;
	iscsi_conn_t *conn = NULL;
	iscsi_login_t *login;
	iscsi_portal_group_t *tpg = NULL;
	struct socket *new_sock, *sock;
	iscsi_np_t *np = (iscsi_np_t *) arg;
	struct iovec iov;
	struct iscsi_init_login_cmnd *pdu;
	struct sockaddr_in sock_in;
	struct sockaddr_in6 sock_in6;
	
	{
	char name[16];
	memset(name, 0, 16);
	sprintf(name, "iscsi_np");
	iscsi_daemon(np->np_thread, name, SHUTDOWN_SIGS);
	}

	if (!(sock = iscsi_target_setup_login_socket(np))) {
		up(&np->np_start_sem);
		return(-1);
	}
	
get_new_sock:
	flush_signals(current);
	ip_proto = sock_type = set_sctp_conn_flag = 0;

	spin_lock_bh(&np->np_thread_lock);
	if (np->np_thread_state == ISCSI_NP_THREAD_RESET)
		up(&np->np_restart_sem);
	spin_unlock_bh(&np->np_thread_lock);

	switch (np->np_network_transport) {
	case ISCSI_TCP:
		ip_proto = IPPROTO_TCP;
		sock_type = SOCK_STREAM;
		break;
	case ISCSI_SCTP_TCP:
		ip_proto = IPPROTO_SCTP;
		sock_type = SOCK_STREAM;
		break;
	case ISCSI_SCTP_UDP:
		ip_proto = IPPROTO_SCTP;
		sock_type = SOCK_SEQPACKET;
		break;
	case ISCSI_IWARP_TCP:
	case ISCSI_IWARP_SCTP:
	case ISCSI_INFINIBAND:
	default:
		TRACE_ERROR("Unsupported network_transport: %d\n",
			np->np_network_transport);
		if (start)
			up(&np->np_start_sem);

		return(-1);
	}
	
	if (iscsi_sock_create(&new_sock, (np->np_flags & NPF_NET_IPV6) ? AF_INET6 :
			AF_INET, sock_type, ip_proto, NULL, NULL) < 0) {
		TRACE_ERROR("iscsi_sock_create() failed for new_sock\n");
		if (start) {
			up(&np->np_start_sem);
			return(0);
		}
		goto get_new_sock;
	}
	new_sock->ops = sock->ops;

	/*
	 * The SCTP stack needs struct socket->file.
	 */
	if ((np->np_network_transport == ISCSI_SCTP_TCP) ||
	    (np->np_network_transport == ISCSI_SCTP_UDP)) {
		if (!new_sock->file) {
			if (!(new_sock->file = kmalloc(
					sizeof(struct file), GFP_KERNEL))) {
				TRACE_ERROR("Unable to allocate struct file for SCTP\n");
				if (start) {
					up(&np->np_start_sem);
					return(0);
				}
				goto get_new_sock;
			}
			memset(new_sock->file, 0, sizeof(struct file));

			set_sctp_conn_flag = 1;
		}
	}
	
	spin_lock_bh(&np->np_thread_lock);
	np->np_thread_state = ISCSI_NP_THREAD_ACTIVE;
	if (start) {
		start = 0;
		up(&np->np_start_sem);
	}
	spin_unlock_bh(&np->np_thread_lock);
	
	if (iscsi_sock_accept(sock, new_sock, NULL) < 0) {
		if (new_sock) {
			if (set_sctp_conn_flag) {
				kfree(new_sock->file);
				new_sock->file = NULL;
			}
			sock_release(new_sock);
		}
		if (signal_pending(current)) {
			spin_lock_bh(&np->np_thread_lock);
			if (np->np_thread_state == ISCSI_NP_THREAD_RESET) {
				spin_unlock_bh(&np->np_thread_lock);
				goto get_new_sock;
			}
			spin_unlock_bh(&np->np_thread_lock);
			goto out;
		}
		goto get_new_sock;
	}

	iscsi_start_login_thread_timer(np);
	
	if (!(conn = (iscsi_conn_t *) kmalloc(
			sizeof(iscsi_conn_t), GFP_KERNEL))) {
		TRACE_ERROR("Could not allocate memory for"
			" new connection\n");
		if (new_sock) {
			if (set_sctp_conn_flag) {
				kfree(new_sock->file);
				new_sock->file = NULL;
			}
			sock_release(new_sock);
		}
		goto get_new_sock;
	}
	memset(conn, 0, sizeof(iscsi_conn_t));
	
	TRACE(TRACE_STATE, "Moving to TARG_CONN_STATE_FREE.\n");
	conn->conn_state = TARG_CONN_STATE_FREE;
	conn->sock = new_sock;

	if (set_sctp_conn_flag)
		conn->conn_flags |= CONNFLAG_SCTP_STRUCT_FILE;
	
	TRACE(TRACE_STATE, "Moving to TARG_CONN_STATE_XPT_UP.\n");
	conn->conn_state = TARG_CONN_STATE_XPT_UP;
	
	/*
	 * Allocate conn->conn_ops early as a failure calling
	 * iscsi_tx_login_rsp() below will call tx_data().
	 * Also initialize the rx_data and tx_data spinlocks.
	 */     
	if (!(conn->conn_ops = (iscsi_conn_ops_t *)kmalloc(
			sizeof(iscsi_conn_ops_t), GFP_KERNEL))) {
		TRACE_ERROR("Unable to allocate memory for"
			" iscsi_conn_ops_t.\n");
		goto new_sess_out;
	}	
	memset(conn->conn_ops, 0, sizeof(iscsi_conn_ops_t));
					
	if (!iscsi_global->targetname_set) {
		TRACE_ERROR("No iSCSI TargetName is for this Node,"
			" rejecting login request.\n");
		iscsi_tx_login_rsp(conn, STAT_CLASS_TARGET,
				STAT_DETAIL_SERVICE_UNAVAILABLE);
		goto new_sess_out;
	}

	if (np->np_net_size == IPV6_ADDRESS_SPACE) 
		ip = &np->np_ipv6[0];
	else {
		memset(buf_ipv4, 0, IPV4_BUF_SIZE);
		iscsi_ntoa2(buf_ipv4, np->np_ipv4);
		ip = &buf_ipv4[0];
	}
	
	spin_lock(&np->np_thread_lock);
	if (np->np_thread_state != ISCSI_NP_THREAD_ACTIVE) {
		spin_unlock(&np->np_thread_lock);
		TRACE_ERROR("iSCSI Network Portal on %s:%hu currently not"
			" active.\n", ip, np->np_port);
		iscsi_tx_login_rsp(conn, STAT_CLASS_TARGET,
				STAT_DETAIL_SERVICE_UNAVAILABLE);
		goto new_sess_out;
	}
	spin_unlock(&np->np_thread_lock);

	if (np->np_net_size == IPV6_ADDRESS_SPACE) {
		memset(&sock_in6, 0, sizeof(struct sockaddr_in6));

		if (conn->sock->ops->getname(conn->sock,
				(struct sockaddr *)&sock_in6, &err, 1) < 0) {
			TRACE_ERROR("sock_ops->getname() failed.\n");
			iscsi_tx_login_rsp(conn, STAT_CLASS_TARGET,
					STAT_DETAIL_TARG_ERROR);
			goto new_sess_out;
		}
#if 0
		if (!(iscsi_ntop6((const unsigned char *)&sock_in6.sin6_addr.in6_u,
				(char *)&conn->ipv6_login_ip[0], IPV6_ADDRESS_SPACE))) {
			TRACE_ERROR("iscsi_ntop6() failed\n");
			iscsi_tx_login_rsp(conn, STAT_CLASS_TARGET,
					STAT_DETAIL_TARG_ERROR);
			goto new_sess_out;
		}
#else
		PYXPRINT("Skipping iscsi_ntop6()\n");
#endif
		ip_init_buf = &conn->ipv6_login_ip[0];
	} else {
		memset(&sock_in, 0, sizeof(struct sockaddr_in));

		if (conn->sock->ops->getname(conn->sock,
				(struct sockaddr *)&sock_in, &err, 1) < 0) {
			TRACE_ERROR("sock_ops->getname() failed.\n");
			iscsi_tx_login_rsp(conn, STAT_CLASS_TARGET,
					STAT_DETAIL_TARG_ERROR);
			goto new_sess_out;
		}
		memset(buf1_ipv4, 0, IPV4_BUF_SIZE);
		conn->login_ip = ntohl(sock_in.sin_addr.s_addr);
		iscsi_ntoa2(buf1_ipv4, conn->login_ip);
		ip_init_buf = &buf1_ipv4[0];
	}
	
	conn->network_transport = np->np_network_transport;
	snprintf(conn->net_dev, ISCSI_NETDEV_NAME_SIZE, "%s", np->np_net_dev);

#ifdef SNMP_SUPPORT
	conn->conn_index = get_new_index(ISCSI_CONNECTION_INDEX);
	conn->local_ip = np->np_ipv4;
	conn->local_port = np->np_port;
#endif

	PYXPRINT("Received iSCSI login request from %s on %s Network Portal"
			" %s:%hu\n", ip_init_buf,
		(conn->network_transport == ISCSI_TCP) ? "TCP" : "SCTP",
			ip, np->np_port);

	TRACE(TRACE_STATE, "Moving to TARG_CONN_STATE_IN_LOGIN.\n");
	conn->conn_state	= TARG_CONN_STATE_IN_LOGIN;

	iscsi_login_init_conn(conn);

	memset(buffer, 0, ISCSI_HDR_LEN);
	memset(&iov, 0, sizeof(struct iovec));
	iov.iov_base	= buffer;
	iov.iov_len	= ISCSI_HDR_LEN;

	if (rx_data(conn, &iov, 1, ISCSI_HDR_LEN) <= 0) {
		TRACE_ERROR("rx_data() returned an error.\n");
		goto new_sess_out;
	}

	iscsi_opcode = (buffer[0] & ISCSI_OPCODE);
	if (!(iscsi_opcode & ISCSI_INIT_LOGIN_CMND)) {
		TRACE_ERROR("First opcode is not login request,"
			" failing login request.\n");
		iscsi_tx_login_rsp(conn, STAT_CLASS_INITIATOR,
				STAT_DETAIL_INIT_ERROR);
		goto new_sess_out;
	}

	pdu			= (struct iscsi_init_login_cmnd *) buffer;
	pdu->length		= be32_to_cpu(pdu->length);
	pdu->cid		= be16_to_cpu(pdu->cid);
	pdu->tsih		= be16_to_cpu(pdu->tsih);
	pdu->init_task_tag	= be32_to_cpu(pdu->init_task_tag);
	pdu->cmd_sn		= be32_to_cpu(pdu->cmd_sn);
	pdu->exp_stat_sn	= be32_to_cpu(pdu->exp_stat_sn);

#ifdef DEBUG_OPCODES
	print_init_login_cmnd(pdu);
#endif
	if (iscsi_login_check_initiator_version(conn, pdu->version_max,
			pdu->version_min) < 0)
		goto new_sess_out;

	if ((zero_tsih = (pdu->tsih == 0x0000))) {
		/*
		 * This is the leading connection of a new session.
		 * We wait until after authentication to check for
		 * session reinstatement.
		 */
		if (iscsi_login_zero_tsih_s1(conn, buffer) < 0)
			goto new_sess_out;
	} else {
		/*
		 * Add a new connection to an existing session.
		 * We check for a non-existant session here based
		 * on ISID/TSIH,  but wait until after authentication
		 * to check for connection reinstatement, etc.
		 */
		if (iscsi_login_non_zero_tsih_s1(conn, buffer) < 0)
			goto new_sess_out;
	}

	/*
	 * This will process the first login request, and call
	 * iscsi_target_locate_portal(), and return a valid iscsi_login_t.
	 */
	if (!(login = iscsi_target_init_negotiation(np, conn, buffer))) {
		tpg = conn->tpg;
		goto new_sess_out;
	}

	if (!(tpg = conn->tpg)) {
		TRACE_ERROR("Unable to locate iscsi_conn_t->tpg\n");
		goto new_sess_out;
	}

	if (zero_tsih) {
		if (iscsi_login_zero_tsih_s2(conn) < 0) {
			iscsi_target_nego_release(login, conn);
			goto new_sess_out;
		}
	} else {
		if (iscsi_login_non_zero_tsih_s2(conn, buffer) < 0) {
			iscsi_target_nego_release(login, conn);
			goto old_sess_out;
		}
	}

	if (iscsi_target_start_negotiation(login, conn) < 0)
		goto new_sess_out;

	if (!SESS(conn)) {
		TRACE_ERROR("iscsi_conn_t session pointer is NULL!\n");
		goto new_sess_out;
	}
	
	iscsi_stop_login_thread_timer(np);

	if (signal_pending(current))
		goto new_sess_out;

	ret = iscsi_post_login_handler(np, conn, zero_tsih);
		
	if (ret < 0)
		goto new_sess_out;
	
	core_deaccess_np(np, tpg);
	tpg = NULL;
	goto get_new_sock;
			
new_sess_out:
	TRACE_ERROR("iSCSI Login negotiation failed.\n");
#ifdef SNMP_SUPPORT
#warning FIXME: Make iscsi_collect_login_stats() return correct failure
	iscsi_collect_login_stats(conn, STAT_CLASS_INITIATOR, 
				  STAT_DETAIL_INIT_ERROR);
#endif

	if (!zero_tsih || !SESS(conn))
		goto old_sess_out;

	if (SESS(conn)->sess_ops)
		kfree(SESS(conn)->sess_ops);
	if (SESS(conn))
		kfree(SESS(conn));
old_sess_out:
	iscsi_stop_login_thread_timer(np);
	/*
	 * If login negotiation fails check if the Time2Retain timer
	 * needs to be restarted.
	 */
	if (!zero_tsih && SESS(conn)) {
		spin_lock_bh(&SESS(conn)->conn_lock);
		if (SESS(conn)->session_state == TARG_SESS_STATE_FAILED) {
			atomic_set(&SESS(conn)->session_continuation, 0);
			spin_unlock_bh(&SESS(conn)->conn_lock);
			spin_lock_bh(&ISCSI_TPG_C(conn)->session_lock);
			iscsi_start_time2retain_handler(SESS(conn));
			spin_unlock_bh(&ISCSI_TPG_C(conn)->session_lock);
		} else
			spin_unlock_bh(&SESS(conn)->conn_lock);
		iscsi_dec_session_usage_count(SESS(conn));
	}

	if (conn->conn_ops)
		kfree(conn->conn_ops);
	if (conn->param_list) {
		iscsi_release_param_list(conn->param_list);
		conn->param_list = NULL;
	}
	if (conn->sock) {
		if (conn->conn_flags & CONNFLAG_SCTP_STRUCT_FILE) {
			kfree(conn->sock->file);
			conn->sock->file = NULL;
		}
		sock_release(conn->sock);
	}
	if (conn)
		kfree(conn);

	if (tpg) {
		core_deaccess_np(np, tpg);
		tpg = NULL;
	}
	
	if (!(signal_pending(current)))
		goto get_new_sock;
	
	if (np->np_thread_state != ISCSI_NP_THREAD_SHUTDOWN)
		goto get_new_sock;	
out:
	iscsi_stop_login_thread_timer(np);
	np->np_thread = NULL;
	up(&np->np_done_sem);
	return(0);
}
