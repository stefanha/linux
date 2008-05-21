/*********************************************************************************
 * Filename:  iscsi_target_util.c
 *
 * This file contains the iSCSI Target specific utility functions.
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


#define ISCSI_TARGET_UTIL_C

#include <linux/string.h>
#include <linux/version.h>
#include <linux/timer.h>
#include <linux/blkdev.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/smp_lock.h>
#include <linux/in.h>
#include <net/sock.h>
#include <net/tcp.h>
#ifdef USE_SCSI_H
#include <scsi.h>
#endif /* USE_SCSI_H */
#ifndef _SCSI_H
#include <scsi/scsi.h>
#endif /* SCSI_H */
#include <scsi/scsi_host.h>

#include <iscsi_linux_os.h>
#include <iscsi_linux_defs.h>

#include <iscsi_lists.h>
#include <iscsi_debug.h>
#include <iscsi_protocol.h>
#include <iscsi_serial.h>
#include <iscsi_target_core.h>
#include <iscsi_target_ioctl.h>
#include <iscsi_target_erl0.h>
#include <iscsi_target_erl1.h>
#include <iscsi_target_erl2.h>
#include <iscsi_target_transport.h>
#include <iscsi_target_util.h>
#include <iscsi_target.h>
#include <iscsi_parameters.h>

#ifdef DEBUG_ERL
#include <iscsi_target_debugerl.h>
#endif /* DEBUG_ERL */

#undef ISCSI_TARGET_UTIL_C

extern iscsi_global_t *iscsi_global;
extern int iscsi_check_acl_for_lun (iscsi_device_t *, iscsi_conn_t *);
extern int iscsi_add_nopin (iscsi_conn_t *, int);

/*	iscsi_attach_cmd_to_queue():
 *
 *
 */
inline void iscsi_attach_cmd_to_queue (iscsi_conn_t *conn, iscsi_cmd_t *cmd)
{
	spin_lock_bh(&conn->cmd_lock);
	if (!conn->cmd_head && !conn->cmd_tail) {
		conn->cmd_head = conn->cmd_tail = cmd;
		cmd->i_prev = cmd->i_next = NULL;
	} else {
		conn->cmd_tail->i_next = cmd;
		cmd->i_prev = conn->cmd_tail;
		conn->cmd_tail = cmd;
	}
	spin_unlock_bh(&conn->cmd_lock);

	atomic_inc(&conn->active_cmds);
	
	return;
}

/*	iscsi_remove_cmd_from_conn_list():
 *
 *	MUST be called with conn->cmd_lock held.
 */
inline void iscsi_remove_cmd_from_conn_list (iscsi_cmd_t *cmd, iscsi_conn_t *conn)
{
	/*
	 * Only element in list.
	 */
	if (!cmd->i_prev && !cmd->i_next)
		conn->cmd_head = conn->cmd_tail = NULL;
	else {
		/*
		 * Head of list.
		 */
		if (!cmd->i_prev) {
			cmd->i_next->i_prev = NULL;
			conn->cmd_head = cmd->i_next;
			if (!conn->cmd_head->i_next)
				conn->cmd_tail = conn->cmd_head;
		} else if (!cmd->i_next) {
			/*
			 * Tail of list.
			 */
			cmd->i_prev->i_next = NULL;
			conn->cmd_tail = cmd->i_prev;
		} else {
			/*
			 * Somewhere in the middle.
			 */
			cmd->i_next->i_prev = cmd->i_prev;
			cmd->i_prev->i_next = cmd->i_next;
		}
		cmd->i_next = cmd->i_prev = NULL;
	}

	atomic_dec(&conn->active_cmds);

	return;
}


/*	iscsi_ack_from_expstatsn():
 *
 *
 */
inline void iscsi_ack_from_expstatsn (iscsi_conn_t *conn, __u32 exp_statsn)
{
	iscsi_cmd_t *cmd = NULL, *cmd_next = NULL;

	conn->exp_statsn = exp_statsn;

	spin_lock_bh(&conn->cmd_lock);
	cmd = conn->cmd_head;
	while (cmd) {
		cmd_next = cmd->i_next;

		spin_lock(&cmd->istate_lock);
		if ((cmd->i_state == ISTATE_SENT_STATUS) &&
		    (cmd->stat_sn < exp_statsn)) {
			cmd->i_state = ISTATE_REMOVE;
			spin_unlock(&cmd->istate_lock);
			iscsi_add_cmd_to_immediate_queue(cmd, conn, cmd->i_state);
			cmd = cmd_next;
			continue;
		}
		spin_unlock(&cmd->istate_lock);

		cmd = cmd_next;
	}
	spin_unlock_bh(&conn->cmd_lock);

	return;
}

/*	iscsi_remove_conn_from_list():
 *
 *	Called with sess->conn_lock held.
 */
extern void iscsi_remove_conn_from_list (iscsi_session_t *sess, iscsi_conn_t *conn)
{
	REMOVE_ENTRY_FROM_LIST(conn, sess->conn_head, sess->conn_tail);
	return;
}

/*	iscsi_remove_session_from_list():
 *
 *
 */
extern void iscsi_remove_session_from_list (iscsi_session_t *sess)
{
	iscsi_portal_group_t *tpg = ISCSI_TPG_S(sess);
	
	spin_lock_bh(&tpg->session_lock);
	REMOVE_ENTRY_FROM_LIST(sess, tpg->session_head, tpg->session_tail);
	spin_unlock_bh(&tpg->session_lock);
		
	return;
}

/*	iscsi_add_r2t_to_list():
 *
 *	Called with cmd->r2t_lock held.
 */
extern int iscsi_add_r2t_to_list (
	iscsi_cmd_t *cmd,
	__u32 offset,
	__u32 xfer_len,
	int recovery,
	u32 r2t_sn)
{
	iscsi_r2t_t *r2t;
	
	if (!(r2t = (iscsi_r2t_t *) kmalloc(sizeof(iscsi_r2t_t), GFP_ATOMIC))) {
		TRACE_ERROR("Unable to allocate memory for iscsi_r2t_t.\n");
		return(-1);
	}
	memset(r2t, 0, sizeof(iscsi_r2t_t));

	r2t->recovery_r2t = recovery;
	r2t->r2t_sn = (!r2t_sn) ? cmd->r2t_sn++ : r2t_sn;
	r2t->offset = offset;
	r2t->xfer_len = xfer_len;

	ADD_ENTRY_TO_LIST(r2t, cmd->r2t_head, cmd->r2t_tail);
	spin_unlock_bh(&cmd->r2t_lock);
	
	iscsi_add_cmd_to_immediate_queue(cmd, CONN(cmd), ISTATE_SEND_R2T);
	
	spin_lock_bh(&cmd->r2t_lock);

	return(0);
}

/*	iscsi_get_r2t_for_eos():
 *
 *
 */
extern iscsi_r2t_t *iscsi_get_r2t_for_eos (
	iscsi_cmd_t *cmd,
	__u32 offset,
	__u32 length)
{
	iscsi_r2t_t *r2t;

	spin_lock_bh(&cmd->r2t_lock);
	for (r2t = cmd->r2t_head; r2t; r2t = r2t->next) {
		if ((r2t->offset <= offset) &&
		    (r2t->offset + r2t->xfer_len) >= (offset + length))
			break;
	}
	spin_unlock_bh(&cmd->r2t_lock);

	if (!r2t) {
		TRACE_ERROR("Unable to locate R2T for Offset: %u, Length:"
				" %u\n", offset, length);
		return(NULL);
	}
		
	return(r2t);
}

/*	iscsi_get_r2t_from_list():
 *
 *
 */
extern iscsi_r2t_t *iscsi_get_r2t_from_list (
	iscsi_cmd_t *cmd)
{
	iscsi_r2t_t *r2t;
	
	spin_lock_bh(&cmd->r2t_lock);
	for (r2t = cmd->r2t_head; r2t; r2t = r2t->next) {
		if (!r2t->sent_r2t)
			break;
	}
	spin_unlock_bh(&cmd->r2t_lock);
	
	if (!r2t) {
		TRACE_ERROR("Unable to locate next R2T to send for ITT:"
			" 0x%08x.\n", cmd->init_task_tag);	
		return(NULL);	
	}

	return(r2t);
}

/*	iscsi_free_r2t():
 *
 *	Called with cmd->r2t_lock held.
 */
extern void iscsi_free_r2t (
	iscsi_r2t_t *r2t,
	iscsi_cmd_t *cmd)
{
	REMOVE_ENTRY_FROM_LIST(r2t, cmd->r2t_head, cmd->r2t_tail);

	return;
}

/*	iscsi_free_r2ts_from_list():
 *
 *
 */
extern void iscsi_free_r2ts_from_list (
	iscsi_cmd_t *cmd)
{
	iscsi_r2t_t *r2t = NULL, *r2t_next = NULL;
	
	spin_lock_bh(&cmd->r2t_lock);
	r2t = cmd->r2t_head;
	while (r2t) {
		r2t_next = r2t->next;
		kfree(r2t);
		r2t = r2t_next;
	}
	spin_unlock_bh(&cmd->r2t_lock);

	TRACE_LEAVE
	return;
}

/*	iscsi_allocate_iovecs_for_cmd():
 *
 *
 */
extern int iscsi_allocate_iovecs_for_cmd (
	iscsi_cmd_t *cmd,
	__u32 iov_count)
{
	/*
	 * See if we already have enough iovecs from a previous iscsi_cmd_t
	 * to fulfill the request.
	 */
	if (cmd->orig_iov_data_count >= iov_count)
		return(0);

	if (cmd->iov_data)
		kfree(cmd->iov_data);

	if (!(cmd->iov_data = (struct iovec *) kmalloc(
			iov_count * sizeof(struct iovec), GFP_ATOMIC))) {
		TRACE_ERROR("Unable to allocate memory for"
			" iscsi_cmd_t->iov_data.\n");
		return(-1);
	}
	memset(cmd->iov_data, 0, iov_count * sizeof(struct iovec));

	cmd->orig_iov_data_count = iov_count;

	return(0);
}

/*	iscsi_allocate_cmd():
 *
 *
 */
inline iscsi_cmd_t *iscsi_allocate_cmd (iscsi_conn_t *conn)
{
	iscsi_cmd_t *cmd;

	if (!(cmd = iscsi_get_cmd_from_pool(SESS(conn)))) {
		if (!(cmd = (iscsi_cmd_t *)
				kmalloc(sizeof(iscsi_cmd_t), GFP_ATOMIC))) {
			TRACE_ERROR("Unable to allocate memory"
				" for iscsi_cmd_t.\n");
			return(NULL);
		}
		memset(cmd, 0, sizeof(iscsi_cmd_t));
	}

	if (!(cmd->t_task = (iscsi_transport_task_t *) kmalloc(
			sizeof(iscsi_transport_task_t), GFP_ATOMIC))) {
		TRACE_ERROR("Unable to allocate cmd->t_task\n");
		return(NULL);
	}
	memset(cmd->t_task, 0, sizeof(iscsi_transport_task_t));
	
	cmd->conn	= conn;	
	init_MUTEX_LOCKED(&cmd->reject_sem);
	init_MUTEX_LOCKED(&cmd->unsolicited_data_sem);
	spin_lock_init(&cmd->datain_lock);
	spin_lock_init(&cmd->dataout_timeout_lock);
	spin_lock_init(&cmd->istate_lock);
	spin_lock_init(&cmd->error_lock);
	spin_lock_init(&cmd->r2t_lock);

	INIT_LIST_HEAD(&T_TASK(cmd)->t_task_list);
	init_MUTEX_LOCKED(&T_TASK(cmd)->transport_lun_fe_stop_sem);
	init_MUTEX_LOCKED(&T_TASK(cmd)->transport_lun_stop_sem);
	init_MUTEX_LOCKED(&T_TASK(cmd)->t_transport_stop_sem);
	init_MUTEX_LOCKED(&T_TASK(cmd)->t_transport_passthrough_sem);
	init_MUTEX_LOCKED(&T_TASK(cmd)->t_transport_passthrough_wsem);
	spin_lock_init(&T_TASK(cmd)->t_state_lock);
	
	return(cmd);
}

/*	iscsi_allocate_tmr_req():
 *
 *
 */
extern iscsi_tmr_req_t *iscsi_allocate_tmr_req (void)
{
	iscsi_tmr_req_t *tmr_req = NULL;

	if (!(tmr_req = (iscsi_tmr_req_t *) kmalloc(sizeof(iscsi_tmr_req_t), GFP_ATOMIC))) {
		TRACE_ERROR("Unable to allocate memory for Task Management command!\n");
		return NULL;
	}
	memset(tmr_req, 0, sizeof(iscsi_tmr_req_t));

	return(tmr_req);
}

/*	iscsi_decide_list_to_build():
 *
 *
 */
extern int iscsi_decide_list_to_build (
	iscsi_cmd_t *cmd,
	__u32 immediate_data_length)
{
	iscsi_build_list_t bl;
	iscsi_conn_t *conn = CONN(cmd);
	iscsi_node_acl_t *acl;
	iscsi_session_t *sess = SESS(conn);
	
	TRACE_ENTER
		
	if (SESS_OPS(sess)->DataSequenceInOrder &&
	    SESS_OPS(sess)->DataPDUInOrder)
		return(0);

	if (cmd->data_direction == ISCSI_NONE)
		return(0);
	
	acl = sess->node_acl;
	memset(&bl, 0, sizeof(iscsi_build_list_t));

	if (cmd->data_direction == ISCSI_READ) {
		bl.data_direction = ISCSI_PDU_READ;
		bl.type = PDULIST_NORMAL;
		if (ISCSI_NODE_ATTRIB(acl)->random_datain_pdu_offsets)
			bl.randomize |= RANDOM_DATAIN_PDU_OFFSETS;
		if (ISCSI_NODE_ATTRIB(acl)->random_datain_seq_offsets)
			bl.randomize |= RANDOM_DATAIN_SEQ_OFFSETS;
	} else {
		bl.data_direction = ISCSI_PDU_WRITE;
		bl.immediate_data_length = immediate_data_length;
		if (ISCSI_NODE_ATTRIB(acl)->random_r2t_offsets)
			bl.randomize |= RANDOM_R2T_OFFSETS;

		if (!cmd->immediate_data && !cmd->unsolicited_data)
			bl.type = PDULIST_NORMAL;
		else if (cmd->immediate_data && !cmd->unsolicited_data)
			bl.type = PDULIST_IMMEDIATE;
		else if (!cmd->immediate_data && cmd->unsolicited_data)
			bl.type = PDULIST_UNSOLICITED;
		else if (cmd->immediate_data && cmd->unsolicited_data)
			bl.type = PDULIST_IMMEDIATE_AND_UNSOLICITED;
	}
	
	TRACE_LEAVE
	return(iscsi_do_build_list(cmd, &bl));
}

/*	iscsi_get_seq_holder_for_datain():
 *
 *
 */
extern iscsi_seq_t *iscsi_get_seq_holder_for_datain (
	iscsi_cmd_t *cmd,
	__u32 seq_send_order)
{
	__u32 i;

	for (i = 0; i < cmd->seq_count; i++)
		if (cmd->seq_list[i].seq_send_order == seq_send_order)
			return(&cmd->seq_list[i]);
		
	return(NULL);
}

/*	iscsi_get_seq_holder_for_r2t():
 *
 *
 */
extern iscsi_seq_t *iscsi_get_seq_holder_for_r2t (
	iscsi_cmd_t *cmd)
{
	__u32 i;
	
	if (!cmd->seq_list) {
		TRACE_ERROR("iscsi_cmd_t->seq_list is NULL!\n");
		return(NULL);
	}
		
	for (i = 0; i < cmd->seq_count; i++) {
		if (cmd->seq_list[i].type != SEQTYPE_NORMAL)
			continue;
		if (cmd->seq_list[i].seq_send_order == cmd->seq_send_order) {
			cmd->seq_send_order++;
			return(&cmd->seq_list[i]);
		}
	}
	
	return(NULL);
}

/*	iscsi_get_holder_for_r2tsn():
 *
 *
 */
extern iscsi_r2t_t *iscsi_get_holder_for_r2tsn (
	iscsi_cmd_t *cmd,
	__u32 r2t_sn)
{
	iscsi_r2t_t *r2t;

	spin_lock_bh(&cmd->r2t_lock);
	for (r2t = cmd->r2t_head; r2t; r2t = r2t->next) {
		if (r2t->r2t_sn == r2t_sn)
			break;
	}
	spin_unlock_bh(&cmd->r2t_lock);

	return((r2t) ? r2t : NULL);
}

/*	iscsi_check_received_cmdsn():
 *
 *
 */
inline int iscsi_check_received_cmdsn (
	iscsi_conn_t *conn,
	iscsi_cmd_t *cmd,
	__u32 cmdsn)
{
	int ret;
	
	TRACE_ENTER
		
#ifdef DEBUG_ERL
	if (iscsi_target_debugerl_cmdsn(conn, cmdsn) < 0)
		return(CMDSN_LOWER_THAN_EXP);
#endif /* DEBUG_ERL */

	/*
	 * This is the proper method of checking received CmdSN against
	 * ExpCmdSN and MaxCmdSN values, as well as accounting for out
	 * or order CmdSNs due to multiple connection sessions and/or
	 * CRC failures.
	 */
	spin_lock(&SESS(conn)->cmdsn_lock);
	if (serial_gt(cmdsn, SESS(conn)->max_cmd_sn)) {
		TRACE_ERROR("Received CmdSN: 0x%08x is greater than MaxCmdSN:"
			" 0x%08x, protocol error.\n", cmdsn,
				SESS(conn)->max_cmd_sn);
		spin_unlock(&SESS(conn)->cmdsn_lock);
		return(CMDSN_ERROR_CANNOT_RECOVER);
	}

	if (!SESS(conn)->cmdsn_outoforder) {
		if (cmdsn == SESS(conn)->exp_cmd_sn) {
			SESS(conn)->exp_cmd_sn++;
			TRACE(TRACE_CMDSN, "Received CmdSN matches ExpCmdSN,"
				" incremented ExpCmdSN to: 0x%08x\n",
					SESS(conn)->exp_cmd_sn);
			ret = iscsi_execute_cmd(cmd, 0);
			spin_unlock(&SESS(conn)->cmdsn_lock);

			return((!ret) ? CMDSN_NORMAL_OPERATION :
					CMDSN_ERROR_CANNOT_RECOVER);
		} else if (serial_gt(cmdsn, SESS(conn)->exp_cmd_sn)) {
			TRACE(TRACE_CMDSN, "Received CmdSN: 0x%08x is greater than"
				" ExpCmdSN: 0x%08x, not acknowledging.\n", cmdsn,
					SESS(conn)->exp_cmd_sn);
			goto ooo_cmdsn;
		} else {
			TRACE_ERROR("Received CmdSN: 0x%08x is less than"
				" ExpCmdSN: 0x%08x, ignoring.\n", cmdsn,
					SESS(conn)->exp_cmd_sn);
			spin_unlock(&SESS(conn)->cmdsn_lock);	
			return(CMDSN_LOWER_THAN_EXP);
		}		
	} else {
		int counter = 0;
		__u32 old_expcmdsn = 0;
		if (cmdsn == SESS(conn)->exp_cmd_sn) {
			old_expcmdsn = SESS(conn)->exp_cmd_sn++;
			TRACE(TRACE_CMDSN, "Got missing CmdSN: 0x%08x matches"
				" ExpCmdSN, incremented ExpCmdSN to 0x%08x.\n",
					cmdsn, SESS(conn)->exp_cmd_sn);

			if (iscsi_execute_cmd(cmd, 0) < 0) {
				spin_unlock(&SESS(conn)->cmdsn_lock);
				return(CMDSN_ERROR_CANNOT_RECOVER);
			}
		} else if (serial_gt(cmdsn, SESS(conn)->exp_cmd_sn)) {
			TRACE(TRACE_CMDSN, "CmdSN: 0x%08x greater than ExpCmdSN:"
				" 0x%08x, not acknowledging.\n", cmdsn,
					SESS(conn)->exp_cmd_sn);
			goto ooo_cmdsn;
		} else {
			TRACE_ERROR("CmdSN: 0x%08x less than ExpCmdSN: 0x%08x,"
				" ignoring.\n", cmdsn, SESS(conn)->exp_cmd_sn);
			spin_unlock(&SESS(conn)->cmdsn_lock);
			return(CMDSN_LOWER_THAN_EXP);
		}

		counter = iscsi_execute_ooo_cmdsns(SESS(conn));
		if (counter < 0) {
			spin_unlock(&SESS(conn)->cmdsn_lock);
			return(CMDSN_ERROR_CANNOT_RECOVER);
		}
		
		if (counter == SESS(conn)->ooo_cmdsn_count) {
			if (SESS(conn)->ooo_cmdsn_count == 1) {
				TRACE(TRACE_CMDSN, "Received final missing"
					" CmdSN: 0x%08x.\n", old_expcmdsn);
			} else {
				TRACE(TRACE_CMDSN, "Received final missing"
					" CmdSNs: 0x%08x->0x%08x.\n",
				old_expcmdsn, (SESS(conn)->exp_cmd_sn - 1));
			}

			SESS(conn)->ooo_cmdsn_count = 0;
			SESS(conn)->cmdsn_outoforder = 0;
		} else {
			SESS(conn)->ooo_cmdsn_count -= counter;
			TRACE(TRACE_CMDSN, "Still missing %hu CmdSN(s),"
				" continuing out of order operation.\n",
				SESS(conn)->ooo_cmdsn_count);
		}
		spin_unlock(&SESS(conn)->cmdsn_lock);
		return(CMDSN_NORMAL_OPERATION);
	}	

ooo_cmdsn:
	ret = iscsi_handle_ooo_cmdsn(SESS(conn), cmd, cmdsn);
	spin_unlock(&SESS(conn)->cmdsn_lock);
	TRACE_LEAVE
	return(ret);
}

/*	iscsi_check_unsolicited_dataout():
 *
 *
 */
extern int iscsi_check_unsolicited_dataout (iscsi_cmd_t *cmd, unsigned char *buf)
{
	iscsi_conn_t *conn = CONN(cmd);
	struct iscsi_init_scsi_data_out *hdr =
		(struct iscsi_init_scsi_data_out *) buf;
	
	TRACE_ENTER

	if (SESS_OPS_C(conn)->InitialR2T) {
		TRACE_ERROR("Received unexpected unsolicited data"
			" while InitialR2T=Yes, protocol error.\n");
		iscsi_send_check_condition_and_sense(cmd,
				UNEXPECTED_UNSOLICITED_DATA, 0);
		return(-1);
	}

	if ((cmd->first_burst_len + hdr->length) >
	     SESS_OPS_C(conn)->FirstBurstLength) {
		TRACE_ERROR("Total %u bytes exceeds FirstBurstLength: %u"
			" for this Unsolicited DataOut Burst.\n",
			(cmd->first_burst_len + hdr->length),
				SESS_OPS_C(conn)->FirstBurstLength);
		iscsi_send_check_condition_and_sense(cmd,
				INCORRECT_AMOUNT_OF_DATA, 0);
		return(-1);
	}

	if (!(hdr->flags & F_BIT))
		return(0);
	
	if (((cmd->first_burst_len + hdr->length) != cmd->data_length) &&
	    ((cmd->first_burst_len + hdr->length) !=
	      SESS_OPS_C(conn)->FirstBurstLength)) {
		TRACE_ERROR("Unsolicited non-immediate data received %u"
			" does not equal FirstBurstLength: %u, and does"
			" not equal ExpXferLen %u.\n",
			(cmd->first_burst_len + hdr->length),
			SESS_OPS_C(conn)->FirstBurstLength, cmd->data_length);
		iscsi_send_check_condition_and_sense(cmd,
				INCORRECT_AMOUNT_OF_DATA, 0);
		return(-1);
	}
	
	TRACE_LEAVE
	return(0);
}

/*	iscsi_find_cmd_from_itt():
 *
 *
 */
extern iscsi_cmd_t *iscsi_find_cmd_from_itt (
	iscsi_conn_t *conn,
	__u32 init_task_tag)
{
	iscsi_cmd_t *cmd = NULL;

	spin_lock_bh(&conn->cmd_lock);
	for (cmd = conn->cmd_head; cmd; cmd = cmd->i_next) {
		if (cmd->init_task_tag == init_task_tag)
			break;
	}
	spin_unlock_bh(&conn->cmd_lock);

	if (!cmd) {
		TRACE_ERROR("Unable to locate ITT: 0x%08x on CID: %hu",
			init_task_tag, conn->cid);
		return(NULL);
	}

	return(cmd);
}

/*	iscsi_find_cmd_from_itt_or_dump():
 *
 *
 */
extern iscsi_cmd_t *iscsi_find_cmd_from_itt_or_dump (
	iscsi_conn_t *conn,
	__u32 init_task_tag,
	__u32 length)
{
	iscsi_cmd_t *cmd = NULL;
	
	spin_lock_bh(&conn->cmd_lock);
	for (cmd = conn->cmd_head; cmd; cmd = cmd->i_next) {
		if (cmd->init_task_tag == init_task_tag)
			break;
	}
	spin_unlock_bh(&conn->cmd_lock);
	
	if (!cmd) {
		TRACE_ERROR("Unable to locate ITT: 0x%08x on CID: %hu,"
			" dumping payload\n", init_task_tag, conn->cid);
		if (length)
			iscsi_dump_data_payload(conn, length, 1);
		return(NULL);
	}

	return(cmd);
}

/*	iscsi_find_cmd_from_ttt():
 *
 *
 */
extern iscsi_cmd_t *iscsi_find_cmd_from_ttt (
	iscsi_conn_t *conn,
	__u32 targ_xfer_tag)
{
	iscsi_cmd_t *cmd = NULL;

	spin_lock_bh(&conn->cmd_lock);
	for (cmd = conn->cmd_head; cmd; cmd = cmd->i_next) {
		if (cmd->targ_xfer_tag == targ_xfer_tag)
			break;
	}
	spin_unlock_bh(&conn->cmd_lock);

	if (!cmd) {
		TRACE_ERROR("Unable to locate TTT: 0x%08x on CID: %hu\n",
			targ_xfer_tag, conn->cid);
		return(NULL);
	}

	return(cmd);
}

/*	iscsi_find_cmd_for_recovery():
 *
 *
 */
extern int iscsi_find_cmd_for_recovery (
	iscsi_session_t *sess,
	iscsi_cmd_t **cmd_ptr,
	iscsi_conn_recovery_t **cr_ptr,
	__u32 init_task_tag)
{
	int found_itt = 0;
	iscsi_cmd_t *cmd = NULL;
	iscsi_conn_recovery_t *cr;

	TRACE_ENTER

	/*
	 * Scan through the inactive connection recovery list's command list.
	 * If init_task_tag matches the command is still alligent.
	 */
	spin_lock(&sess->cr_i_lock);
	for (cr = sess->cr_i_head; cr; cr = cr->next) {
		spin_lock(&cr->conn_recovery_cmd_lock);
		for (cmd = cr->conn_recovery_cmd_head; cmd;
		     cmd = cmd->i_next) {
			if (cmd->init_task_tag == init_task_tag) {
				found_itt = 1;
				break;
			}
		}
		spin_unlock(&cr->conn_recovery_cmd_lock);
		if (found_itt)
			break;	
	}
	spin_unlock(&sess->cr_i_lock);

	if (cmd) {
		*cr_ptr = cr;
		*cmd_ptr = cmd;
		return(-2);
	}

	found_itt = 0;

	/*
	 * Scan through the active connection recovery list's command list.
	 * If init_task_tag matches the command is ready to be reassigned.
	 */
	spin_lock(&sess->cr_a_lock);
	for (cr = sess->cr_a_head; cr; cr = cr->next) {
		spin_lock(&cr->conn_recovery_cmd_lock);
		for (cmd = cr->conn_recovery_cmd_head; cmd;
		     cmd = cmd->i_next) {
			if (cmd->init_task_tag == init_task_tag) {
				found_itt = 1;
				break;
			}
		}
		spin_unlock(&cr->conn_recovery_cmd_lock);
		if (found_itt)
			break;
	}
	spin_unlock(&sess->cr_a_lock);
		
	if (!cmd || !cr)
		return(-1);

	*cr_ptr = cr;
	*cmd_ptr = cmd;
	
	TRACE_LEAVE
	return(0);
}

/*	iscsi_add_cmd_to_immediate_queue():
 *
 *
 */
extern void iscsi_add_cmd_to_immediate_queue (iscsi_cmd_t *cmd, iscsi_conn_t *conn, u8 state)
{
	iscsi_queue_req_t *qr;

	if (!(qr = kmalloc(sizeof(iscsi_queue_req_t), GFP_ATOMIC))) {
		TRACE_ERROR("Unable to allocate memory for iscsi_queue_req_t\n");
		return;
	}
	memset(qr, 0, sizeof(iscsi_queue_req_t));
#if 0
	printk("Adding ITT: 0x%08x state: %d to immediate queue\n", cmd->init_task_tag, state);
#endif
	qr->cmd = cmd;
	qr->state = state;

	spin_lock_bh(&conn->immed_queue_lock);
	ADD_ENTRY_TO_LIST(qr, conn->immed_queue_head, conn->immed_queue_tail);
	atomic_inc(&cmd->immed_queue_count);
	atomic_set(&conn->check_immediate_queue, 1);
	spin_unlock_bh(&conn->immed_queue_lock);

	up(&conn->tx_sem);
	
	return;
}

/*	iscsi_get_cmd_from_immediate_queue():
 *
 *
 */
extern iscsi_queue_req_t *iscsi_get_cmd_from_immediate_queue (iscsi_conn_t *conn)
{
	iscsi_queue_req_t *qr;

	spin_lock_bh(&conn->immed_queue_lock);
	if (!conn->immed_queue_head) {
		spin_unlock_bh(&conn->immed_queue_lock);
		return(NULL);
	}

	qr = conn->immed_queue_head;
	if (qr->cmd)
		atomic_dec(&qr->cmd->immed_queue_count);

	conn->immed_queue_head = conn->immed_queue_head->next;
	qr->next = qr->prev = NULL;
	
	if (!conn->immed_queue_head)
		conn->immed_queue_tail = NULL;
	else
		conn->immed_queue_head->prev = NULL;
	spin_unlock_bh(&conn->immed_queue_lock);

	return(qr);
}

static void iscsi_remove_cmd_from_immediate_queue (iscsi_cmd_t *cmd, iscsi_conn_t *conn)
{
	iscsi_queue_req_t *qr, *qr_next;

	spin_lock_bh(&conn->immed_queue_lock);
	if (!(atomic_read(&cmd->immed_queue_count))) {
		spin_unlock_bh(&conn->immed_queue_lock);
		return;
	}

	qr = conn->immed_queue_head;
	while (qr) {
		qr_next = qr->next;

		if (qr->cmd != cmd) {
			qr = qr_next;
			continue;
		}

		atomic_dec(&qr->cmd->immed_queue_count);
		REMOVE_ENTRY_FROM_LIST(qr, conn->immed_queue_head, conn->immed_queue_tail);
		kfree(qr);

		qr = qr_next;
	}
	spin_unlock_bh(&conn->immed_queue_lock);

	if (atomic_read(&cmd->immed_queue_count)) {
		TRACE_ERROR("ITT: 0x%08x immed_queue_count: %d\n", cmd->init_task_tag,
			atomic_read(&cmd->immed_queue_count));
	}
	
	return;
}

/*	iscsi_add_cmd_to_response_queue():
 *
 *
 */
extern void iscsi_add_cmd_to_response_queue (iscsi_cmd_t *cmd, iscsi_conn_t *conn, u8 state)
{
	iscsi_queue_req_t *qr;

	if (!(qr = kmalloc(sizeof(iscsi_queue_req_t), GFP_ATOMIC))) {
		TRACE_ERROR("Unable to allocate memory for iscsi_queue_req_t\n");
		return;
	}
	memset(qr, 0, sizeof(iscsi_queue_req_t));
#if 0
	printk("Adding ITT: 0x%08x state: %d to response queue\n", cmd->init_task_tag, state);
#endif
	qr->cmd = cmd;
	qr->state = state;

	spin_lock_bh(&conn->response_queue_lock);
	ADD_ENTRY_TO_LIST(qr, conn->response_queue_head, conn->response_queue_tail);
	atomic_inc(&cmd->response_queue_count);
	spin_unlock_bh(&conn->response_queue_lock);

	up(&conn->tx_sem);
	
	return;
}

/*	iscsi_get_cmd_from_response_queue():
 *
 *
 */
extern iscsi_queue_req_t *iscsi_get_cmd_from_response_queue (iscsi_conn_t *conn)
{
	iscsi_queue_req_t *qr;

	spin_lock_bh(&conn->response_queue_lock);
	if (!conn->response_queue_head) {
		spin_unlock_bh(&conn->response_queue_lock);
		return(NULL);
	}

	qr = conn->response_queue_head;
	if (qr->cmd)
		atomic_dec(&qr->cmd->response_queue_count);

	conn->response_queue_head = conn->response_queue_head->next;
	qr->next = qr->prev = NULL;
        
	if (!conn->response_queue_head)
		conn->response_queue_tail = NULL;
	else
		conn->response_queue_head->prev = NULL;
	spin_unlock_bh(&conn->response_queue_lock);

	return(qr);	
}	

/*	iscsi_remove_cmd_from_response_queue():
 *
 *
 */
static void iscsi_remove_cmd_from_response_queue (iscsi_cmd_t *cmd, iscsi_conn_t *conn)
{
	iscsi_queue_req_t *qr, *qr_next;
	
	spin_lock_bh(&conn->response_queue_lock);
	if (!(atomic_read(&cmd->response_queue_count))) {
		spin_unlock_bh(&conn->response_queue_lock);
		return;
	}
		
	qr = conn->response_queue_head;
	while (qr) {
		qr_next = qr->next;

		if (qr->cmd != cmd) {
			qr = qr_next;
			continue;
		}
		
		atomic_dec(&qr->cmd->response_queue_count);
		
		REMOVE_ENTRY_FROM_LIST(qr, conn->response_queue_head, conn->response_queue_tail);
		kfree(qr);

		qr = qr_next;
	}
	spin_unlock_bh(&conn->response_queue_lock);
	
	if (atomic_read(&cmd->response_queue_count)) {
		TRACE_ERROR("ITT: 0x%08x response_queue_count: %d\n", cmd->init_task_tag,
				atomic_read(&cmd->response_queue_count));
	}
	
	return;
}

extern void iscsi_remove_cmd_from_tx_queues (iscsi_cmd_t *cmd, iscsi_conn_t *conn)
{
	iscsi_remove_cmd_from_immediate_queue(cmd, conn);
	iscsi_remove_cmd_from_response_queue(cmd, conn);

	return;
}

/*	iscsi_free_queue_reqs_for_conn():
 *
 *
 */
extern void iscsi_free_queue_reqs_for_conn (iscsi_conn_t *conn)
{
	iscsi_queue_req_t *qr, *qr_next;

	spin_lock_bh(&conn->immed_queue_lock);
	qr = conn->immed_queue_head;
	while (qr) {
		qr_next = qr->next;
		
		if (qr->cmd)
			atomic_dec(&qr->cmd->immed_queue_count);
		
		kfree(qr);
		qr = qr_next;
	}
	conn->immed_queue_head = conn->immed_queue_tail = NULL;
	spin_unlock_bh(&conn->immed_queue_lock);

	spin_lock_bh(&conn->response_queue_lock);
	qr = conn->response_queue_head;
	while (qr) {
		qr_next = qr->next;
		
		if (qr->cmd)
			atomic_dec(&qr->cmd->response_queue_count);
		
		kfree(qr);
		qr = qr_next;
	}
	conn->response_queue_head = conn->response_queue_tail = NULL;
	spin_unlock_bh(&conn->response_queue_lock);

	return;
}

/*	iscsi_get_cmd_from_pool():
 *
 *
 */
extern iscsi_cmd_t *iscsi_get_cmd_from_pool (iscsi_session_t *sess)
{
	iscsi_cmd_t *cmd;

	spin_lock_bh(&sess->pool_lock);
	if (!sess->pool_head) {
		spin_unlock_bh(&sess->pool_lock);
		return (NULL);
	}

	cmd = sess->pool_head;
	sess->pool_head = sess->pool_head->next;

	if (!sess->pool_head)
		sess->pool_tail = NULL;
	spin_unlock_bh(&sess->pool_lock);

	atomic_dec(&sess->pool_count);

	return(cmd);
}

/*	iscsi_release_cmd_direct():
 *
 *
 */
extern void iscsi_release_cmd_direct (iscsi_cmd_t *cmd)
{
	iscsi_free_r2ts_from_list(cmd);
	
	if (cmd->iov_data)
		kfree(cmd->iov_data);
	if (cmd->buf_ptr)
		kfree(cmd->buf_ptr);
	if (cmd->pdu_list)
		kfree(cmd->pdu_list);
	if (cmd->seq_list)
		kfree(cmd->seq_list);

	if (cmd->cmd_flags & ICF_CMD_PASSTHROUGH) 
		kfree(cmd->iscsi_lun);

	if (T_TASK(cmd))
		kfree(T_TASK(cmd));

	memset(cmd, 0, sizeof(iscsi_cmd_t));
	
	kfree(cmd);
	
	return;
}

extern void iscsi_dec_nacl_count (iscsi_node_acl_t *nacl, iscsi_cmd_t *cmd)
{
	iscsi_dev_entry_t *deve;

	if (!cmd)
		return;

	deve = &nacl->device_list[cmd->orig_fe_lun];
	spin_lock_bh(&nacl->device_list_lock);
	deve->deve_cmds--;
	spin_unlock_bh(&nacl->device_list_lock);

	return;
}

/*	iscsi_release_cmd_to_pool():
 *
 *
 */
inline void iscsi_release_cmd_to_pool (iscsi_cmd_t *cmd, iscsi_session_t *sess)
{
	__u32 iov_data_count = 0;
	iscsi_conn_t *conn = CONN(cmd);
	struct iovec *iov = NULL;
	
	if (cmd->orig_iov_data_count) {
		iov = cmd->iov_data;
		iov_data_count = cmd->orig_iov_data_count;
	}

	iscsi_free_r2ts_from_list(cmd);
	
	if (cmd->buf_ptr)
		kfree(cmd->buf_ptr);
	if (cmd->pdu_list)
		kfree(cmd->pdu_list);
	if (cmd->seq_list)
		kfree(cmd->seq_list);
	
	if (conn)
		iscsi_remove_cmd_from_tx_queues(cmd, conn);
	
	if (T_TASK(cmd))
		kfree(T_TASK(cmd));
	
	memset(cmd, 0, sizeof(iscsi_cmd_t));

	if (iov_data_count) {
		cmd->iov_data = iov;
		cmd->orig_iov_data_count = iov_data_count;
	}

	spin_lock_bh(&sess->pool_lock);
	if (!sess->pool_head && !sess->pool_tail)
		sess->pool_head		= cmd;
	else
		sess->pool_tail->next	= cmd;
	sess->pool_tail			= cmd;
	spin_unlock_bh(&sess->pool_lock);

	atomic_inc(&sess->pool_count);

	return;
}

/*	iscsi_release_all_cmds_in_pool():
 *
 *
 */
extern void iscsi_release_all_cmds_in_pool (iscsi_session_t *sess)
{
	__u32 release_cmd_count = 0;
	iscsi_cmd_t *cmd, *cmd_next;

	spin_lock(&sess->pool_lock);
	cmd = sess->pool_head;
	while (cmd) {
		cmd_next = cmd->next;
		
		if (cmd->buf_ptr) 
			kfree(cmd->buf_ptr);
		if (cmd->iov_data)
			kfree(cmd->iov_data);
		if (cmd->pdu_list)
			kfree(cmd->pdu_list);
		if (cmd->seq_list)
			kfree(cmd->seq_list);
		
		kfree(cmd);

		cmd = cmd_next;
		release_cmd_count++;
	}
	spin_unlock(&sess->pool_lock);

	if (release_cmd_count != atomic_read(&sess->pool_count)) {
		TRACE_ERROR("Released cmd pool count %d does not equal"
			" saved value %d.\n", release_cmd_count,
				atomic_read(&sess->pool_count));
	} else {
		TRACE(TRACE_ISCSI, "Released %d cmds from iSCSI Session"
			" Pool.\n", release_cmd_count);
		atomic_set(&sess->pool_count, 0);
	}

	return;
}

/*	iscsi_pack_lun():
 *
 *	Routine to pack an ordinary (LINUX) LUN 32-bit number
 *		into an 8-byte LUN structure
 *	(see SAM-2, Section 4.12.3 page 39)
 *	Thanks to UNH for help with this :-).
 */
inline __u64 iscsi_pack_lun (unsigned int lun)
{
	__u64	result;

	result = ((lun & 0xff) << 8);	/* LSB of lun into byte 1 big-endian */

	if (0) {
		/* use flat space addressing method, SAM-2 Section 4.12.4
			-	high-order 2 bits of byte 0 are 01
			-	low-order 6 bits of byte 0 are MSB of the lun
			-	all 8 bits of byte 1 are LSB of the lun
			-	all other bytes (2 thru 7) are 0
                 */
		result |= 0x40 | ((lun >> 8) & 0x3f);
	}
	/* else use peripheral device addressing method, Sam-2 Section 4.12.5
			-	high-order 2 bits of byte 0 are 00
			-	low-order 6 bits of byte 0 are all 0
			-	all 8 bits of byte 1 are the lun
			-	all other bytes (2 thru 7) are 0
	*/

	return(cpu_to_le64(result));
}

/*	iscsi_unpack_lun():
 *
 *	Routine to pack an 8-byte LUN structure into a ordinary (LINUX) 32-bit LUN number
 *	(see SAM-2, Section 4.12.3 page 39)
 *	Thanks to UNH for help with this :-).
 */
inline __u32 iscsi_unpack_lun (unsigned char *lun_ptr)
{
	__u32	result, temp;

	result = *(lun_ptr+1);  /* LSB of lun from byte 1 big-endian */

	switch (temp=((*lun_ptr)>>6)) {	/* high 2 bits of byte 0 big-endian */
	case 0: /* peripheral device addressing method, Sam-2 Section 4.12.5
		-	high-order 2 bits of byte 0 are 00
		-	low-order 6 bits of byte 0 are all 0
		-	all 8 bits of byte 1 are the lun
		-	all other bytes (2 thru 7) are 0
		 */
		if (*lun_ptr != 0) {
		TRACE_ERROR("Illegal Byte 0 in LUN peripheral device addressing "
			"method %u, expected 0\n", *lun_ptr);
		}
		break;
	case 1: /* flat space addressing method, SAM-2 Section 4.12.4
		-	high-order 2 bits of byte 0 are 01
		-	low-order 6 bits of byte 0 are MSB of the lun
		-	all 8 bits of byte 1 are LSB of the lun
		-	all other bytes (2 thru 7) are 0
		 */
		result += ((*lun_ptr) & 0x3f) << 8;
		break;
	default: /* (extended) logical unit addressing */
		TRACE_ERROR("Unimplemented LUN addressing method %u, "
			"PDA method used instead\n", temp);
		break;
	}

	return(result);
}

/*	iscsi_send_check_condition_and_sense();
 *
 *
 */
extern int iscsi_send_check_condition_and_sense (iscsi_cmd_t *cmd, u8 reason, int from_transport)
{
	u16 size;
	unsigned char *buffer = NULL;
	iscsi_conn_t *conn = CONN(cmd);

	spin_lock_bh(&cmd->istate_lock);
	if (cmd->cmd_flags & ICF_SENT_CHECK_CONDITION) {
		spin_unlock_bh(&cmd->istate_lock);
		return(0);
	}
	cmd->cmd_flags |= ICF_SENT_CHECK_CONDITION;
	spin_unlock_bh(&cmd->istate_lock);

	if (!reason && from_transport)
		goto after_reason;

	if (!from_transport)
		cmd->cmd_flags |= ICF_EMULATED_TASK_SENSE;

	if (!(buffer = (char *) kmalloc(ISCSI_SENSE_SEGMENT_TOTAL, GFP_ATOMIC))) {
		TRACE_ERROR("Unable to allocate memory for SENSE buffer\n");
		return(-1);
	}
	memset(buffer, 0, ISCSI_SENSE_SEGMENT_TOTAL);
	cmd->buf_ptr	= buffer;

	/* 
	 * Data Segment of iSCSI Response PDU.
	 */
	size = ISCSI_SENSE_BUFFER;
	buffer[0]	= ((ISCSI_SENSE_BUFFER >> 8) & 0xff);	/* SenseLength */
	buffer[1]	= (ISCSI_SENSE_BUFFER & 0xff);		/* SenseLength */

	/*
	 * Actual SENSE DATA, see SPC-3 7.23.2
	 */
	switch (reason) {
	case NON_EXISTENT_LUN:
	case UNSUPPORTED_SCSI_OPCODE:
	case SECTOR_COUNT_TOO_MANY:
		buffer[2] = 0x70; /* CURRENT ERROR */
		buffer[4] = 0x05; /* ILLEGAL REQUEST */
		buffer[14] = 0x20; /* INVALID COMMAND OPERATION CODE */
		break;
	case UNKNOWN_MODE_PAGE:
		buffer[2] = 0x70; /* CURRENT ERROR */
		buffer[4] = 0x05; /* ILLEGAL REQUEST */
		buffer[14] = 0x24; /* INVALID FIELD IN CDB */
		break;
	case INCORRECT_AMOUNT_OF_DATA:
		buffer[2] = 0x70; /* CURRENT ERROR */
		buffer[4] = 0x0b; /* ABORTED COMMAND */
		buffer[14] = 0x0c; /* WRITE ERROR */
		buffer[15] = 0x0d; /* NOT ENOUGH UNSOLICITED DATA */			
		break;
	case INVALID_CDB_FIELD:
		buffer[2] = 0x70; /* CURRENT ERROR */
		buffer[4] = 0x0b; /* ABORTED COMMAND */
		buffer[14] = 0x24; /* INVALID FIELD IN CDB */
		break;
	case UNEXPECTED_UNSOLICITED_DATA:
		buffer[2] = 0x70; /* CURRENT ERROR */
		buffer[4] = 0x0b; /* ABORTED COMMAND */
		buffer[14] = 0x0c; /* WRITE ERROR */
		buffer[15] = 0x0c; /* UNEXPECTED_UNSOLICITED_DATA */
		break;
	case SERVICE_CRC_ERROR:
		buffer[2] = 0x70; /* CURRENT ERROR */
		buffer[4] = 0x0b; /* ABORTED COMMAND */
		buffer[14] = 0x47; /* PROTOCOL SERVICE CRC ERROR */
		buffer[15] = 0x05; /* N/A */
		break;
	case SNACK_REJECTED:
		buffer[2] = 0x70; /* CURRENT ERROR */
		buffer[4] = 0x0b; /* ABORTED COMMAND */
		buffer[14] = 0x11; /* READ ERROR */
		buffer[15] = 0x13; /* FAILED RETRANSMISSION REQUEST */
		break;
	case WRITE_PROTECTED:
		buffer[2] = 0x70; /* CURRENT ERROR */
		buffer[4] = 0x07; /* DATA PROTECT */
		buffer[14] = 0x27; /* WRITE PROTECTED */
		break;
	case LOGICAL_UNIT_COMMUNICATION_FAILURE:
	default:
		buffer[2] = 0x70; /* CURRENT ERROR */
		buffer[4] = 0x05; /* ILLEGAL REQUEST */
		buffer[14] = 0x80; /* LOGICAL UNIT COMMUNICATION FAILURE */
		break;
	}

	/*
	 * LINUX defines CHECK_CONDITION as 0x01, but follow SPC-3 anyways.
	 */
	cmd->scsi_status	= 0x02; /* CHECK CONDITION */
	cmd->scsi_sense_length	= ISCSI_SENSE_SEGMENT_LENGTH;	/* Automatically padded */

after_reason:
	if (!(cmd->cmd_flags & ICF_CMD_PASSTHROUGH)) {
		cmd->i_state = ISTATE_SEND_STATUS;
		iscsi_add_cmd_to_response_queue(cmd, conn, cmd->i_state);
	}
	
	return(0);
}

/*	iscsi_get_tpg_session_from_sid():
 *
 *
 */
extern iscsi_session_t *iscsi_get_tpg_session_from_sid (iscsi_portal_group_t *tpg, u32 sid)
{
	iscsi_session_t *sess;

	spin_lock_bh(&tpg->session_lock);
	for (sess = tpg->session_head; sess; sess = sess->next) {
		if (sess->sid == sid) {
			iscsi_inc_session_usage_count(sess);
			break;
		}
	}
	spin_unlock_bh(&tpg->session_lock);

	if (!sess) {
		TRACE_ERROR("Unable to locate iSBE SID: %u on iSCSI TPG: %hu,"
			" ignoring request.\n", sid, tpg->tpgt);
		return(NULL);
	}
	
	return(sess);
}

/*	iscsi_check_session_usage_count():
 *
 *
 */
extern int iscsi_check_session_usage_count (iscsi_session_t *sess)
{
	spin_lock_bh(&sess->session_usage_lock);
	if (atomic_read(&sess->session_usage_count)) {
#if 0
		TRACE_ERROR("atomic_read(&sess->session_usage_count): %d\n",
			atomic_read(&sess->session_usage_count));
#endif
		atomic_set(&sess->session_waiting_on_uc, 1);
		spin_unlock_bh(&sess->session_usage_lock);
		if (in_interrupt())
			return(2);
#if 0
		TRACE_ERROR("Before down(&sess->session_waiting_on_uc_sem);\n");
#endif
		down(&sess->session_waiting_on_uc_sem);
#if 0
		TRACE_ERROR("After down(&sess->session_waiting_on_uc_sem);\n");
#endif
		return(1);
	}
	spin_unlock_bh(&sess->session_usage_lock);
			
	return(0);	
}

/*	iscsi_dec_session_usage_count():
 *
 *
 */
extern void iscsi_dec_session_usage_count (iscsi_session_t *sess)
{
	spin_lock_bh(&sess->session_usage_lock);
	atomic_dec(&sess->session_usage_count);
#if 0
	TRACE_ERROR("Decremented session_usage_count to %d\n",
		atomic_read(&sess->session_usage_count));
#endif
		        
	if (!atomic_read(&sess->session_usage_count) &&
	     atomic_read(&sess->session_waiting_on_uc))
		up(&sess->session_waiting_on_uc_sem);

	spin_unlock_bh(&sess->session_usage_lock);

	return;
}

/*	iscsi_inc_session_usage_count():
 *
 *
 */
extern void iscsi_inc_session_usage_count (iscsi_session_t *sess)
{
	spin_lock_bh(&sess->session_usage_lock);
	atomic_inc(&sess->session_usage_count);
#if 0
	TRACE_ERROR("Incremented session_usage_count to %d\n",
		atomic_read(&sess->session_usage_count));
#endif
	spin_unlock_bh(&sess->session_usage_lock);

	return;
}

/*	iscsi_determine_sync_and_steering_counts():
 *
 *	Used before iscsi_do[rx,tx]_data() to determine iov and [rx,tx]_marker
 *	array counts needed for sync and steering.
 */
static inline int iscsi_determine_sync_and_steering_counts (
	iscsi_conn_t *conn,
	iscsi_data_count_t *count)
{       
	__u32 length = count->data_length;
	__u32 marker, markint;

	count->sync_and_steering = 1;

	marker = (count->type == ISCSI_RX_DATA) ? conn->of_marker : conn->if_marker;
	markint = (count->type == ISCSI_RX_DATA) ? (CONN_OPS(conn)->OFMarkInt * 4) :
				(CONN_OPS(conn)->IFMarkInt * 4);
	count->ss_iov_count = count->iov_count;

	while (length > 0) {
		if (length >= marker) {
			count->ss_iov_count += 3;
			count->ss_marker_count += 2;

			length -= marker;
			marker = markint;
		} else
			length = 0;
	}

	return(0);
}

/*	iscsi_set_sync_and_steering_values():
 *
 * 	Setup conn->if_marker and conn->of_marker values based upon
 * 	the initial marker-less interval. (see iSCSI v19 A.2)
 */
extern int iscsi_set_sync_and_steering_values (iscsi_conn_t *conn)
{
	int login_ifmarker_count = 0, login_ofmarker_count = 0, next_marker = 0;
	/*
	 * IFMarkInt and OFMarkInt are negotiated as 32-bit words.
	 */
	__u32 IFMarkInt = (CONN_OPS(conn)->IFMarkInt * 4);
	__u32 OFMarkInt = (CONN_OPS(conn)->OFMarkInt * 4);
	
	if (CONN_OPS(conn)->OFMarker) {
		/*
		 * Account for the first Login Command received not
		 * via iscsi_recv_msg().
		 */
		conn->of_marker += ISCSI_HDR_LEN;
		if (conn->of_marker <= OFMarkInt) {
			conn->of_marker = (OFMarkInt - conn->of_marker);
		} else {
			login_ofmarker_count = (conn->of_marker / OFMarkInt);
			next_marker = (OFMarkInt * (login_ofmarker_count + 1)) +
					(login_ofmarker_count * MARKER_SIZE);
			conn->of_marker = (next_marker - conn->of_marker);
		}
		conn->of_marker_offset = 0;
		PYXPRINT("Setting OFMarker value to %u based on Initial"
			" Markerless Interval.\n", conn->of_marker);
	}
		
	if (CONN_OPS(conn)->IFMarker) {
		if (conn->if_marker <= IFMarkInt) {
			conn->if_marker = (IFMarkInt - conn->if_marker);
		} else {
			login_ifmarker_count = (conn->if_marker / IFMarkInt);
			next_marker = (IFMarkInt * (login_ifmarker_count + 1)) +
					(login_ifmarker_count * MARKER_SIZE);
			conn->if_marker = (next_marker - conn->if_marker);
		}
		PYXPRINT("Setting IFMarker value to %u based on Initial"
			" Markerless Interval.\n", conn->if_marker);
	}	

	return(0);
}	

extern unsigned char *iscsi_ntoa (__u32 ip)
{
	static unsigned char buf[18];
	
	memset((void *) buf, 0, 18);
	sprintf(buf, "%u.%u.%u.%u", ((ip >> 24) & 0xff), ((ip >> 16) & 0xff),
			((ip >> 8) & 0xff), (ip & 0xff));

	return(buf);
}

extern void iscsi_ntoa2 (unsigned char *buf, __u32 ip)
{
	memset((void *) buf, 0, 18);
	sprintf(buf, "%u.%u.%u.%u", ((ip >> 24) & 0xff), ((ip >> 16) & 0xff),
			((ip >> 8) & 0xff), (ip & 0xff));

	return;
}

#define NS_INT16SZ	 2
#define NS_INADDRSZ	 4
#define NS_IN6ADDRSZ	16

/* const char *
 * inet_ntop4(src, dst, size)
 *	format an IPv4 address
 * return:
 *	`dst' (as a const)
 * notes:
 *	(1) uses no statics
 *	(2) takes a unsigned char* not an in_addr as input
 * author:
 *	Paul Vixie, 1996.
 */
static const char *
iscsi_ntop4(const unsigned char *src, char *dst, size_t size)
{
	static const char *fmt = "%u.%u.%u.%u";
	char tmp[sizeof "255.255.255.255"];
	size_t len;

	len = snprintf(tmp, sizeof tmp, fmt, src[0], src[1], src[2], src[3]);
	if (len >= size) {
		TRACE_ERROR("len: %d >= size: %d\n", (int)len, (int)size);
		return (NULL);
	}
	memcpy(dst, tmp, len + 1);

	return (dst);
}

/* const char *
 * isc_inet_ntop6(src, dst, size)
 * convert IPv6 binary address into presentation (printable) format
 * author:
 *	Paul Vixie, 1996.
 */
extern const char *
iscsi_ntop6(const unsigned char *src, char *dst, size_t size)
{
	/*
	 * Note that int32_t and int16_t need only be "at least" large enough
	 * to contain a value of the specified size.  On some systems, like
	 * Crays, there is no such thing as an integer variable with 16 bits.
	 * Keep this in mind if you think this function should have been coded
	 * to use pointer overlays.  All the world's not a VAX.
	 */
	char tmp[sizeof "ffff:ffff:ffff:ffff:ffff:ffff:255.255.255.255"], *tp;
	struct { int base, len; } best, cur;
	unsigned int words[NS_IN6ADDRSZ / NS_INT16SZ];
	int i, inc;

	best.len = best.base = 0;
	cur.len = cur.base = 0;

	/*
	 * Preprocess:
	 *	Copy the input (bytewise) array into a wordwise array.
	 *	Find the longest run of 0x00's in src[] for :: shorthanding.
	 */
	memset(words, '\0', sizeof words);
	for (i = 0; i < NS_IN6ADDRSZ; i++)
		words[i / 2] |= (src[i] << ((1 - (i % 2)) << 3));
	best.base = -1;
	cur.base = -1;
	for (i = 0; i < (NS_IN6ADDRSZ / NS_INT16SZ); i++) {
		if (words[i] == 0) {
			if (cur.base == -1)
				cur.base = i, cur.len = 1;
			else
				cur.len++;
		} else {
			if (cur.base != -1) {
				if (best.base == -1 || cur.len > best.len)
					best = cur;
				cur.base = -1;
			}
		}
	}
	if (cur.base != -1) {
		if (best.base == -1 || cur.len > best.len)
			best = cur;
	}
	if (best.base != -1 && best.len < 2)
		best.base = -1;

	/*
	 * Format the result.
	 */
	tp = tmp;
	for (i = 0; i < (NS_IN6ADDRSZ / NS_INT16SZ); i++) {
		/* Are we inside the best run of 0x00's? */
		if (best.base != -1 && i >= best.base &&
		    i < (best.base + best.len)) {
			if (i == best.base)
				*tp++ = ':';
			continue;
		}
		/* Are we following an initial run of 0x00s or any real hex? */
		if (i != 0)
			*tp++ = ':';
		/* Is this address an encapsulated IPv4? */
		if (i == 6 && best.base == 0 &&
		    (best.len == 6 || (best.len == 5 && words[5] == 0xffff))) {
			if (!iscsi_ntop4(src+12, tp, sizeof tmp - (tp - tmp)))
				return (NULL);
			tp += strlen(tp);
			break;
		}
		inc = snprintf(tp, 5, "%x", words[i]);
#warning FIXME: Get rid of BUG() here..
		if (inc < 5)
			BUG();
		tp += inc;
	}
	/* Was it a trailing run of 0x00's? */
	if (best.base != -1 && (best.base + best.len) ==
	    (NS_IN6ADDRSZ / NS_INT16SZ))
		*tp++ = ':';
	*tp++ = '\0';

	/*
	 * Check for overflow, copy, and we're done.
	 */
	if ((size_t)(tp - tmp) > size) {
		TRACE_ERROR("(size_t)(tp - tmp): %d > size: %d\n",
			(int)(tp - tmp), (int)size);
		return (NULL);
	}
	memcpy(dst, tmp, tp - tmp);
	return (dst);
}

/* int
 * inet_pton4(src, dst)
 *	like inet_aton() but without all the hexadecimal and shorthand.
 * return:
 *	1 if `src' is a valid dotted quad, else 0.
 * notice:
 *	does not touch `dst' unless it's returning 1.
 * author:
 *	Paul Vixie, 1996.
 */
static int
iscsi_pton4(const char *src, unsigned char *dst)
{
	static const char digits[] = "0123456789";
	int saw_digit, octets, ch;
	unsigned char tmp[NS_INADDRSZ], *tp;

	saw_digit = 0;
	octets = 0;
	*(tp = tmp) = 0;
	while ((ch = *src++) != '\0') {
		const char *pch;

		if ((pch = strchr(digits, ch)) != NULL) {
			unsigned int new = *tp * 10 + (pch - digits);

			if (new > 255)
				return (0);
			*tp = new;
			if (! saw_digit) {
				if (++octets > 4)
					return (0);
				saw_digit = 1;
			}
		} else if (ch == '.' && saw_digit) {
			if (octets == 4)
				return (0);
			*++tp = 0;
			saw_digit = 0;
		} else
			return (0);
	}
	if (octets < 4)
		return (0);
	memcpy(dst, tmp, NS_INADDRSZ);
	return (1);
}

/* int
 * inet_pton6(src, dst)
 *	convert presentation level address to network order binary form.
 * return:
 *	1 if `src' is a valid [RFC1884 2.2] address, else 0.
 * notice:
 *	(1) does not touch `dst' unless it's returning 1.
 *	(2) :: in a full address is silently ignored.
 * credit:
 *	inspired by Mark Andrews.
 * author:
 *	Paul Vixie, 1996.
 */
extern int
iscsi_pton6(const char *src, unsigned char *dst)
{
	static const char xdigits_l[] = "0123456789abcdef",
			  xdigits_u[] = "0123456789ABCDEF";
	unsigned char tmp[NS_IN6ADDRSZ], *tp, *endp, *colonp;
	const char *xdigits, *curtok;
	int ch, saw_xdigit;
	unsigned int val;

	memset((tp = tmp), '\0', NS_IN6ADDRSZ);
	endp = tp + NS_IN6ADDRSZ;
	colonp = NULL;
	/* Leading :: requires some special handling. */
	if (*src == ':')
		if (*++src != ':')
			return (0);
	curtok = src;
	saw_xdigit = 0;
	val = 0;
	while ((ch = *src++) != '\0') {
		const char *pch;

		if ((pch = strchr((xdigits = xdigits_l), ch)) == NULL)
			pch = strchr((xdigits = xdigits_u), ch);
		if (pch != NULL) {
			val <<= 4;
			val |= (pch - xdigits);
			if (val > 0xffff)
				return (0);
			saw_xdigit = 1;
			continue;
		}
		if (ch == ':') {
			curtok = src;
			if (!saw_xdigit) {
				if (colonp)
					return (0);
				colonp = tp;
				continue;
			}
			if (tp + NS_INT16SZ > endp)
				return (0);
			*tp++ = (unsigned char) (val >> 8) & 0xff;
			*tp++ = (unsigned char) val & 0xff;
			saw_xdigit = 0;
			val = 0;
			continue;
		}
		if (ch == '.' && ((tp + NS_INADDRSZ) <= endp) &&
		    iscsi_pton4(curtok, tp) > 0) {
			tp += NS_INADDRSZ;
			saw_xdigit = 0;
			break;	/* '\0' was seen by inet_pton4(). */
		}
		return (0);
	}
	if (saw_xdigit) {
		if (tp + NS_INT16SZ > endp)
			return (0);
		*tp++ = (unsigned char) (val >> 8) & 0xff;
		*tp++ = (unsigned char) val & 0xff;
	}
	if (colonp != NULL) {
		/*
		 * Since some memmove()'s erroneously fail to handle
		 * overlapping regions, we'll do the shift by hand.
		 */
		const int n = tp - colonp;
		int i;

		for (i = 1; i <= n; i++) {
			endp[- i] = colonp[n - i];
			colonp[n - i] = 0;
		}
		tp = endp;
	}
	if (tp != endp)
		return (0);
	memcpy(dst, tmp, NS_IN6ADDRSZ);
	return (1);
}

/*	iscsi_get_conn_from_cid():
 *
 *
 */
extern iscsi_conn_t *iscsi_get_conn_from_cid (iscsi_session_t *sess, __u16 cid)
{
	iscsi_conn_t *conn;

	spin_lock_bh(&sess->conn_lock);
	for (conn = sess->conn_head; conn; conn = conn->next) {
		if ((conn->cid == cid) &&
		    (conn->conn_state == TARG_CONN_STATE_LOGGED_IN)) {
			iscsi_inc_conn_usage_count(conn);
			spin_unlock_bh(&sess->conn_lock);
			return(conn);
		}
	}
	spin_unlock_bh(&sess->conn_lock);

	return(NULL);
}

/*	iscsi_get_conn_from_cid_rcfr():
 *
 *
 */
extern iscsi_conn_t *iscsi_get_conn_from_cid_rcfr (iscsi_session_t *sess, __u16 cid)
{
	iscsi_conn_t *conn;

	spin_lock_bh(&sess->conn_lock);
	for (conn = sess->conn_head; conn; conn = conn->next) {
		if (conn->cid == cid) {
			iscsi_inc_conn_usage_count(conn);
			spin_lock(&conn->state_lock);
			atomic_set(&conn->connection_wait_rcfr, 1);
			spin_unlock(&conn->state_lock);
			spin_unlock_bh(&sess->conn_lock);
			return(conn);
		}
	}
	spin_unlock_bh(&sess->conn_lock);

	return(NULL);
}

/*	iscsi_check_conn_usage_count():
 *
 *
 */
extern void iscsi_check_conn_usage_count (iscsi_conn_t *conn)
{
	spin_lock_bh(&conn->conn_usage_lock);
#if 0
	TRACE_ERROR("atomic_read(&conn->conn_usage_count): %d for CID: %hu\n",
		atomic_read(&conn->conn_usage_count), conn->cid);
#endif
	if (atomic_read(&conn->conn_usage_count)) {
		atomic_set(&conn->conn_waiting_on_uc, 1);
		spin_unlock_bh(&conn->conn_usage_lock);
#if 0
		TRACE_ERROR("Before down(&conn->conn_waiting_on_uc_sem);"
				" for CID: %hu\n", conn->cid);
#endif
		down(&conn->conn_waiting_on_uc_sem);
#if 0
		TRACE_ERROR("After down(&conn->conn_waiting_on_uc_sem);"
				" for CID: %hu\n", conn->cid);
#endif
		return;
	}
	spin_unlock_bh(&conn->conn_usage_lock);

	return;
}

/*	iscsi_dec_conn_usage_count():
 *
 *
 */
extern void iscsi_dec_conn_usage_count (iscsi_conn_t *conn)
{
	spin_lock_bh(&conn->conn_usage_lock);
	atomic_dec(&conn->conn_usage_count);
#if 0
	TRACE_ERROR("Decremented conn_usage_count to %d for CID: %hu\n",
		atomic_read(&conn->conn_usage_count), conn->cid);
#endif
	if (!atomic_read(&conn->conn_usage_count) &&
	     atomic_read(&conn->conn_waiting_on_uc))
		up(&conn->conn_waiting_on_uc_sem);

	spin_unlock_bh(&conn->conn_usage_lock);

	return;
}

/*	iscsi_inc_conn_usage_count():
 *
 *
 */
extern void iscsi_inc_conn_usage_count (iscsi_conn_t *conn)
{
	spin_lock_bh(&conn->conn_usage_lock);
	atomic_inc(&conn->conn_usage_count);
#if 0
	TRACE_ERROR("Incremented conn_usage_count to %d for CID: %hu\n",
		atomic_read(&conn->conn_usage_count), conn->cid);
#endif
	spin_unlock_bh(&conn->conn_usage_lock);

	return;
}
	
/*	iscsi_async_msg_timer_function():
 *
 *
 */
extern void iscsi_async_msg_timer_function (unsigned long data)
{
	TRACE_ENTER
	up((struct semaphore *) data);
	TRACE_LEAVE
}

/*	iscsi_update_counters():
 *
 *
 */
#if 0
static void iscsi_update_counters (iscsi_conn_t *conn, u32 timeout)
{
	u32 i;
	u64 this_count, last_count;
	iscsi_dev_entry_t *deve;
	iscsi_node_acl_t *node_acl = SESS(conn)->node_acl;

	spin_lock_bh(&node_acl->device_list_lock);
	for (i = 0; i < ISCSI_MAX_LUNS_PER_TPG; i++) {
		deve = &node_acl->device_list[i];

		if (!(deve->lun_flags & ISCSI_LUNFLAGS_INITIATOR_ACCESS))
			continue;
		
		this_count = deve->total_bytes;
		last_count = deve->last_byte_count;

		deve->last_byte_count += ((this_count - last_count) / timeout);

		deve->average_bytes += timeout;
		
		deve->last_byte_count = deve->total_bytes;
	}
	spin_unlock_bh(&node_acl->device_list_lock);
	
	return;
}
#endif

/*	Riscsi_check_for_active_network_device():
 *
 *
 */
extern int iscsi_check_for_active_network_device (iscsi_conn_t *conn)
{
	struct net_device *net_dev;

	if (!conn->net_if) {
		TRACE_ERROR("iscsi_conn_t->net_if is NULL for CID:"
			" %hu\n", conn->cid);
		return(0);
	}
	net_dev = conn->net_if;

	return(netif_carrier_ok(net_dev));
}

/*	iscsi_handle_netif_timeou():
 *
 *
 */
static void iscsi_handle_netif_timeout (unsigned long data)
{
	iscsi_conn_t *conn = (iscsi_conn_t *) data;

	iscsi_inc_conn_usage_count(conn);
	
	spin_lock_bh(&conn->netif_lock);	
	if (conn->netif_timer_flags & NETIF_TF_STOP) {
		spin_unlock_bh(&conn->netif_lock);
		iscsi_dec_conn_usage_count(conn);
		return;
	}
	conn->netif_timer_flags &= ~NETIF_TF_RUNNING;
	
	if (iscsi_check_for_active_network_device((void *)conn)) {
		iscsi_start_netif_timer(conn);
		spin_unlock_bh(&conn->netif_lock);
		iscsi_dec_conn_usage_count(conn);
		return;
	}

	TRACE_ERROR("Detected PHY loss on Network Interface: %s for iSCSI"
		" CID: %hu on SID: %u\n", conn->net_dev, conn->cid,
			SESS(conn)->sid);
		
	spin_unlock_bh(&conn->netif_lock);
	
	iscsi_cause_connection_reinstatement(conn, 0);	
	iscsi_dec_conn_usage_count(conn);
	
	return;
}

/*	iscsi_get_network_interface_from_conn():
 *
 *
 */
extern void iscsi_get_network_interface_from_conn (iscsi_conn_t *conn)
{
	struct net_device *net_dev;

	if (!(net_dev = dev_get_by_name(&init_net, conn->net_dev))) {
		TRACE_ERROR("Unable to locate active network interface:"
			" %s\n", strlen(conn->net_dev) ? conn->net_dev : "None");
		conn->net_if = NULL;
		return;
	}

	conn->net_if = net_dev;

	return;
}

/*      iscsi_start_netif_timer():
 *              
 *	Called with conn->netif_lock held.     
 */
extern void iscsi_start_netif_timer (iscsi_conn_t *conn)
{
	iscsi_portal_group_t *tpg = ISCSI_TPG_C(conn);
	
	TRACE_ENTER

	if (!conn->net_if)
		return;

	if (conn->netif_timer_flags & NETIF_TF_RUNNING)
		return;
	
	init_timer(&conn->transport_timer);
	SETUP_TIMER(conn->transport_timer, ISCSI_TPG_ATTRIB(tpg)->netif_timeout,
		conn, iscsi_handle_netif_timeout);
				                
	conn->netif_timer_flags |= NETIF_TF_RUNNING;
	add_timer(&conn->transport_timer);
	
	TRACE_LEAVE
	return;
}

/*	iscsi_stop_netif_timer():
 *
 *
 */
extern void iscsi_stop_netif_timer (iscsi_conn_t *conn)
{
	TRACE_ENTER

	spin_lock_bh(&conn->netif_lock);
	if (!(conn->netif_timer_flags & NETIF_TF_RUNNING)) {
		spin_unlock_bh(&conn->netif_lock);
		return;
	}
	conn->netif_timer_flags |= NETIF_TF_STOP;
	spin_unlock_bh(&conn->netif_lock);

	del_timer_sync(&conn->transport_timer);

	spin_lock_bh(&conn->netif_lock);
	conn->netif_timer_flags &= ~NETIF_TF_RUNNING;
	conn->netif_timer_flags &= ~NETIF_TF_STOP;
	spin_unlock_bh(&conn->netif_lock);
	
	TRACE_LEAVE
	return;
}

/*	iscsi_handle_nopin_response_timeout():
 *
 *
 */
static void iscsi_handle_nopin_response_timeout (
	unsigned long data)
{
	iscsi_conn_t *conn = (iscsi_conn_t *) data;

	TRACE_ENTER

	iscsi_inc_conn_usage_count(conn);
		
	spin_lock_bh(&conn->nopin_timer_lock);
	if (conn->nopin_response_timer_flags & NOPIN_RESPONSE_TF_STOP) {
		spin_unlock_bh(&conn->nopin_timer_lock);
		iscsi_dec_conn_usage_count(conn);
		return;
	}

	TRACE(TRACE_TIMER, "Did not receive response to NOPIN on CID: %hu on"
		" SID: %u, failing connection.\n", conn->cid,
			SESS(conn)->sid);
	conn->nopin_response_timer_flags &= ~NOPIN_RESPONSE_TF_RUNNING;
	spin_unlock_bh(&conn->nopin_timer_lock);

#ifdef SNMP_SUPPORT
	{
	iscsi_portal_group_t *tpg = conn->sess->tpg;
	iscsi_tiqn_t *tiqn = (tpg->tpg_tiqn) ? tpg->tpg_tiqn :
		__core_get_default_tiqn();

	spin_lock_bh(&tiqn->sess_err_stats.lock);
	strcpy(tiqn->sess_err_stats.last_sess_fail_rem_name, 
       	        (void *)SESS_OPS_C(conn)->InitiatorName);
	tiqn->sess_err_stats.last_sess_failure_type =
			ISCSI_SESS_ERR_CXN_TIMEOUT;
	tiqn->sess_err_stats.cxn_timeout_errors++;
	SESS(conn)->conn_timeout_errors++;
	spin_unlock_bh(&tiqn->sess_err_stats.lock);
	}
#endif /* SNMP_SUPPORT */
	
	iscsi_cause_connection_reinstatement(conn, 0);
	iscsi_dec_conn_usage_count(conn);

	TRACE_LEAVE
	return;
}

/*	iscsi_mod_nopin_response_timer():
 *
 *
 */
extern void iscsi_mod_nopin_response_timer (
	iscsi_conn_t *conn)
{
	iscsi_session_t *sess = SESS(conn);
	iscsi_node_acl_t *acl = sess->node_acl;
	
	TRACE_ENTER

	spin_lock_bh(&conn->nopin_timer_lock);
	if (!(conn->nopin_response_timer_flags & NOPIN_RESPONSE_TF_RUNNING)) {
		spin_unlock_bh(&conn->nopin_timer_lock);
		return;
	}

	MOD_TIMER(&conn->nopin_response_timer,
		ISCSI_NODE_ATTRIB(acl)->nopin_response_timeout);	
	spin_unlock_bh(&conn->nopin_timer_lock);
	
	TRACE_LEAVE
	return;
}

/*	iscsi_start_nopin_response_timer():
 *
 *	Called with conn->nopin_timer_lock held.
 */
extern void iscsi_start_nopin_response_timer (
	iscsi_conn_t *conn)
{
	iscsi_session_t *sess = SESS(conn);
	iscsi_node_acl_t *acl = sess->node_acl;
	
	TRACE_ENTER

	spin_lock_bh(&conn->nopin_timer_lock);
	if (conn->nopin_response_timer_flags & NOPIN_RESPONSE_TF_RUNNING) {
		spin_unlock_bh(&conn->nopin_timer_lock);
		return;
	}

	init_timer(&conn->nopin_response_timer);
	SETUP_TIMER(conn->nopin_response_timer,
		ISCSI_NODE_ATTRIB(acl)->nopin_response_timeout,
		conn, iscsi_handle_nopin_response_timeout);

	conn->nopin_response_timer_flags |= NOPIN_RESPONSE_TF_RUNNING;
	add_timer(&conn->nopin_response_timer);

	TRACE(TRACE_TIMER, "Started NOPIN Response Timer on CID: %d to %u"
		" seconds\n", conn->cid,
		ISCSI_NODE_ATTRIB(acl)->nopin_response_timeout);
	spin_unlock_bh(&conn->nopin_timer_lock);
		
	TRACE_LEAVE
	return;
}

/*	iscsi_stop_nopin_response_timer():
 *
 *
 */
extern void iscsi_stop_nopin_response_timer (
	iscsi_conn_t *conn)
{
	spin_lock_bh(&conn->nopin_timer_lock);
	if (!(conn->nopin_response_timer_flags & NOPIN_RESPONSE_TF_RUNNING)) {
		spin_unlock_bh(&conn->nopin_timer_lock);
		return;
	}
	conn->nopin_response_timer_flags |= NOPIN_RESPONSE_TF_STOP;
	spin_unlock_bh(&conn->nopin_timer_lock);

	del_timer_sync(&conn->nopin_response_timer);

	spin_lock_bh(&conn->nopin_timer_lock);
	conn->nopin_response_timer_flags &= ~NOPIN_RESPONSE_TF_RUNNING;
	conn->nopin_response_timer_flags &= ~NOPIN_RESPONSE_TF_STOP;
	spin_unlock_bh(&conn->nopin_timer_lock);
		
	return;
}

/*	iscsi_handle_nopin_timeout():
 *
 *
 */
static void iscsi_handle_nopin_timeout (
	unsigned long data)
{
	iscsi_conn_t *conn = (iscsi_conn_t *) data;
#if 0
	iscsi_session_t *sess = SESS(conn);
	iscsi_node_acl_t *acl = sess->node_acl;
#endif
	
	iscsi_inc_conn_usage_count(conn);
		
	spin_lock_bh(&conn->nopin_timer_lock);
	if (conn->nopin_timer_flags & NOPIN_TF_STOP) {
		spin_unlock_bh(&conn->nopin_timer_lock);
		iscsi_dec_conn_usage_count(conn);
		return;
	}
	conn->nopin_timer_flags &= ~NOPIN_TF_RUNNING;
	spin_unlock_bh(&conn->nopin_timer_lock);
#if 0	
	iscsi_update_counters(conn, ISCSI_NODE_ATTRIB(acl)->nopin_timeout);
#endif
	iscsi_add_nopin(conn, 1);
	iscsi_dec_conn_usage_count(conn);
	
	return;
}

/*	iscsi_start_nopin_timer():
 *
 *
 */
extern void iscsi_start_nopin_timer (
	iscsi_conn_t *conn)
{
	iscsi_session_t *sess = SESS(conn);
	iscsi_node_acl_t *acl = sess->node_acl;
	
	TRACE_ENTER

	spin_lock_bh(&conn->nopin_timer_lock);
	if (conn->nopin_timer_flags & NOPIN_TF_RUNNING) {
		spin_unlock_bh(&conn->nopin_timer_lock);
		return;
	}

	init_timer(&conn->nopin_timer);
	SETUP_TIMER(conn->nopin_timer, ISCSI_NODE_ATTRIB(acl)->nopin_timeout,
			conn, iscsi_handle_nopin_timeout);
	conn->nopin_timer_flags |= NOPIN_TF_RUNNING;
	add_timer(&conn->nopin_timer);

	TRACE(TRACE_TIMER, "Started NOPIN Timer on CID: %d at %u second"
			" interval\n", conn->cid,
			ISCSI_NODE_ATTRIB(acl)->nopin_timeout);
	spin_unlock_bh(&conn->nopin_timer_lock);
		
	TRACE_LEAVE
	return;
}

/*	iscsi_stop_nopin_timer():
 *
 *
 */
extern void iscsi_stop_nopin_timer (
	iscsi_conn_t *conn)
{
	TRACE_ENTER

	spin_lock_bh(&conn->nopin_timer_lock);
	if (!(conn->nopin_timer_flags & NOPIN_TF_RUNNING)) {
		spin_unlock_bh(&conn->nopin_timer_lock);
		return;
	}
	conn->nopin_timer_flags |= NOPIN_TF_STOP;
	spin_unlock_bh(&conn->nopin_timer_lock);

	del_timer_sync(&conn->nopin_timer);
	
	spin_lock_bh(&conn->nopin_timer_lock);
	conn->nopin_timer_flags &= ~NOPIN_TF_RUNNING;
	conn->nopin_timer_flags &= ~NOPIN_TF_STOP;
	spin_unlock_bh(&conn->nopin_timer_lock);
	
	TRACE_LEAVE
	return;
}

/*	iscsi_send_tx_data():
 *
 *
 */
extern int iscsi_send_tx_data (
	iscsi_cmd_t *cmd,
	iscsi_conn_t *conn,
	int use_misc)
{
	int tx_sent, tx_size;
	__u32 iov_count;
	struct iovec *iov;
	
send_data:
	tx_size = cmd->tx_size;
		
	if (!use_misc) {
		iov = &cmd->iov_data[0];
		iov_count = cmd->iov_data_count;
	} else {
		iov = &cmd->iov_misc[0];
		iov_count = cmd->iov_misc_count;
	}

	tx_sent = tx_data(conn, &iov[0], iov_count, tx_size);	
	if (tx_size != tx_sent) {
		if (tx_sent == -EAGAIN) {
			TRACE_ERROR("tx_data() returned -EAGAIN\n");
			goto send_data;
		} else
			return(-1);
	}
	cmd->tx_size = 0;

	return(0);
}

extern int iscsi_fe_sendpage_sg (
	iscsi_unmap_sg_t *u_sg,
	iscsi_conn_t *conn)
{
	int tx_sent;
	iscsi_cmd_t *cmd = u_sg->cmd;
	u32 len = cmd->tx_size, pg_len, se_len, se_off, tx_size;
	struct iovec *iov = &cmd->iov_data[0];
	struct page *page;
	se_mem_t *se_mem = u_sg->cur_se_mem;

send_hdr:
	tx_size = (CONN_OPS(conn)->HeaderDigest) ? ISCSI_HDR_LEN + CRC_LEN : ISCSI_HDR_LEN;
	tx_sent = tx_data(conn, iov, 1, tx_size);
	if (tx_size != tx_sent) {
		if (tx_sent == -EAGAIN) {
			TRACE_ERROR("tx_data() returned -EAGAIN\n");
			goto send_hdr;
		}
		return(-1);
	}

	len -= tx_size;
	len -= u_sg->padding;
	if (CONN_OPS(conn)->DataDigest)
		len -= CRC_LEN;

	/*
	 * Start calculating from the first page of current se_mem_t.
	 */
	page = se_mem->se_page;
	pg_len = (PAGE_SIZE - se_mem->se_off);
	if ((se_len = se_mem->se_len) < pg_len)
		pg_len = se_len;
	se_off = se_mem->se_off;
#if 0	
	TRACE_ERROR("se: %p page: %p se_len: %d se_off: %d pg_len: %d\n",
		se_mem, page, se_len, se_off, pg_len);
#endif	
	/*
	 * Calucate new se_len and se_off based upon u_sg->t_offset into
	 * the current se_mem_t and possibily a different page.
	 */
	while (u_sg->t_offset) {
#if 0
		TRACE_ERROR("u_sg->t_offset: %d, page: %p se_len: %d se_off: %d pg_len: %d\n",
			u_sg->t_offset, page, se_len, se_off, pg_len);
#endif		
		if (u_sg->t_offset >= pg_len) {
			u_sg->t_offset -= pg_len;
			se_len -= pg_len;
			se_off = 0;
			pg_len = PAGE_SIZE;
			page++;
		} else {
			se_off += u_sg->t_offset;
			se_len -= u_sg->t_offset;
			u_sg->t_offset = 0;
		}
	}

	/*
	 * Perform sendpage() for each page in the se_mem_t
	 */
	while (len) {
#if 0
		TRACE_ERROR("len: %d page: %p se_len: %d se_off: %d\n",
			len, page, se_len, se_off);
#endif		
		if (se_len > len)
			se_len = len;
send_pg:
		tx_sent = conn->sock->ops->sendpage(conn->sock, page, se_off, se_len, 0);
		if (tx_sent != se_len) {
			if (tx_sent == -EAGAIN) {
				TRACE_ERROR("tcp_sendpage() returned -EAGAIN\n");
				goto send_pg;
			}

			TRACE_ERROR("tcp_sendpage() failure: %d\n", tx_sent);
			return(-1);
		}

		if (!(len -= se_len))
			break;

		if (!(se_len -= tx_sent)) {
			list_for_each_entry_continue(se_mem, T_TASK(cmd)->t_mem_list, se_list)
				break;

			if (!se_mem) {
				TRACE_ERROR("Unable to locate next se_mem_t\n");
				return(-1);
			}
			
			se_len = se_mem->se_len;
			se_off = se_mem->se_off;
			page = se_mem->se_page;
		} else {
			se_len = PAGE_SIZE;
			se_off = 0;
			page++;
		}
	}

send_padding:
	if (u_sg->padding) {
		struct iovec *iov_p = &cmd->iov_data[cmd->iov_data_count-2];

		tx_sent = tx_data(conn, iov_p, 1, u_sg->padding);
		if (u_sg->padding != tx_sent) {
			if (tx_sent == -EAGAIN) {
				TRACE_ERROR("tx_data() returned -EAGAIN\n");
				goto send_padding;
			}
			return(-1);
		}
	}
	
send_datacrc:
	if (CONN_OPS(conn)->DataDigest) {
		struct iovec *iov_d = &cmd->iov_data[cmd->iov_data_count-1];

		tx_sent = tx_data(conn, iov_d, 1, CRC_LEN);
		if (CRC_LEN != tx_sent) {
			if (tx_sent == -EAGAIN) {
				TRACE_ERROR("tx_data() returned -EAGAIN\n");
				goto send_datacrc;
			}
			return(-1);
		}
	}

	return(0);
}

/*      iscsi_tx_login_rsp():
 *
 *      This function is used for mainly sending a ISCSI_TARG_LOGIN_RSP PDU
 *      back to the Initiator when an expection condition occurs with the
 *      errors set in status_class and status_detail.
 *
 *      Parameters:     iSCSI Connection, Status Class, Status Detail.
 *      Returns:        0 on success, -1 on error.
 */
extern int iscsi_tx_login_rsp (iscsi_conn_t *conn, __u8 status_class, __u8 status_detail)
{
	__u8 iscsi_hdr[ISCSI_HDR_LEN];
	int err;
	struct iovec iov;
	struct iscsi_targ_login_rsp *hdr;

#ifdef SNMP_SUPPORT
	iscsi_collect_login_stats(conn, status_class, status_detail);
#endif

	memset ((void *)&iov, 0, sizeof(struct iovec));
	memset((void *)&iscsi_hdr, 0x0, ISCSI_HDR_LEN);
	
	hdr	= (struct iscsi_targ_login_rsp *)&iscsi_hdr;
	hdr->opcode		= ISCSI_TARG_LOGIN_RSP;
	hdr->status_class	= status_class;
	hdr->status_detail	= status_detail;

	iov.iov_base		= &iscsi_hdr;
	iov.iov_len		= ISCSI_HDR_LEN;

	PRINT_BUFF(iscsi_hdr, ISCSI_HDR_LEN);

	err = tx_data(conn, &iov, 1, ISCSI_HDR_LEN);
	if (err != ISCSI_HDR_LEN) {
		TRACE_ERROR("tx_data returned less than expected\n");
		return(-1);
	}

	return(0);
}

/*	iscsi_print_session_params():
 *
 *
 */
extern void iscsi_print_session_params (iscsi_session_t *sess)
{
	iscsi_conn_t *conn;

	PYXPRINT("-----------------------------[Session Params for SID: %u]"
			"-----------------------------\n", sess->sid);
	spin_lock_bh(&sess->conn_lock);
	for (conn = sess->conn_head; conn; conn = conn->next)
		iscsi_dump_conn_ops(conn->conn_ops);	
	spin_unlock_bh(&sess->conn_lock);

	iscsi_dump_sess_ops(sess->sess_ops);

	return;
}

/*	iscsi_do_rx_data():
 *
 *
 */
static inline int iscsi_do_rx_data (
	iscsi_conn_t *conn,
	iscsi_data_count_t *count)
{
	int data = count->data_length, rx_loop = 0, total_rx = 0;
	__u32 rx_marker_val[count->ss_marker_count], rx_marker_iov = 0;
	struct iovec iov[count->ss_iov_count];
#ifdef LINUX
	mm_segment_t oldfs;
	struct msghdr msg;
#endif /* LINUX */

	if (!conn || !conn->sock || !CONN_OPS(conn))
		return(-1);

	memset(&msg, 0, sizeof(struct msghdr));
	
	if (count->sync_and_steering) {
		int size = 0;
		__u32 i, orig_iov_count = 0;
		__u32 orig_iov_len = 0, orig_iov_loc = 0;
		__u32 iov_count = 0, per_iov_bytes = 0;
		__u32 *rx_marker, old_rx_marker = 0;
		struct iovec *iov_record;

		memset((void *)&rx_marker_val, 0, count->ss_marker_count * sizeof(__u32));
		memset((void *)&iov, 0, count->ss_iov_count * sizeof(struct iovec));

		iov_record = count->iov;
		orig_iov_count = count->iov_count;
		rx_marker = &conn->of_marker;

		i = 0;
		size = data;
		orig_iov_len = iov_record[orig_iov_loc].iov_len;
		while (size > 0) {
			TRACE(TRACE_SSLR, "rx_data: #1 orig_iov_len %u,"
			" orig_iov_loc %u\n", orig_iov_len, orig_iov_loc);
			TRACE(TRACE_SSLR, "rx_data: #2 rx_marker %u, size"
				" %u\n", *rx_marker, size);

			if (orig_iov_len >= *rx_marker) {
				iov[iov_count].iov_len = *rx_marker;
				iov[iov_count++].iov_base =
					(iov_record[orig_iov_loc].iov_base +
					 	per_iov_bytes);

				iov[iov_count].iov_len = (MARKER_SIZE / 2);
				iov[iov_count++].iov_base =
					&rx_marker_val[rx_marker_iov++];
				iov[iov_count].iov_len = (MARKER_SIZE / 2);
				iov[iov_count++].iov_base =
					&rx_marker_val[rx_marker_iov++];
				old_rx_marker = *rx_marker;

				/*
				 * OFMarkInt is in 32-bit words.
				 */
				*rx_marker = (CONN_OPS(conn)->OFMarkInt * 4);
				size -= old_rx_marker;
				orig_iov_len -= old_rx_marker;
				per_iov_bytes += old_rx_marker;

				TRACE(TRACE_SSLR, "rx_data: #3 new_rx_marker"
					" %u, size %u\n", *rx_marker, size);
			} else {
				iov[iov_count].iov_len = orig_iov_len;
				iov[iov_count++].iov_base =
					(iov_record[orig_iov_loc].iov_base +
					 	per_iov_bytes);
		
				per_iov_bytes = 0;
				*rx_marker -= orig_iov_len;
				size -= orig_iov_len;

				if (size)
					orig_iov_len =
					iov_record[++orig_iov_loc].iov_len;

				TRACE(TRACE_SSLR, "rx_data: #4 new_rx_marker"
					" %u, size %u\n", *rx_marker, size);
			}
		}
		data += (rx_marker_iov * (MARKER_SIZE / 2));

		msg.msg_iov	= &iov[0];
		msg.msg_iovlen	= iov_count;

		if (iov_count > count->ss_iov_count) {
			TRACE_ERROR("iov_count: %d, count->ss_iov_count: %d\n",
				iov_count, count->ss_iov_count);
			return(-1);
		}
		if (rx_marker_iov > count->ss_marker_count) {
			TRACE_ERROR("rx_marker_iov: %d, count->ss_marker_count: %d\n",
				rx_marker_iov, count->ss_marker_count);
			return(-1);
		}
	} else {
		msg.msg_iov	= count->iov;
		msg.msg_iovlen	= count->iov_count;
	}

	while (total_rx < data) {
		oldfs = get_fs();
		set_fs(get_ds());

		conn->sock->sk->sk_allocation = GFP_ATOMIC;	
		rx_loop = sock_recvmsg(conn->sock, &msg, (data - total_rx), MSG_WAITALL);

		set_fs(oldfs);

		if (rx_loop <= 0) {
			TRACE(TRACE_NET, "rx_loop: %d total_rx: %d\n",
				rx_loop, total_rx);
			return rx_loop;
		}
		total_rx += rx_loop;
		TRACE(TRACE_NET, "rx_loop: %d, total_rx: %d, data: %d\n",
				rx_loop, total_rx, data);
	}

	if (count->sync_and_steering) {
		int j;
		for (j = 0; j < rx_marker_iov; j++) {
			TRACE(TRACE_SSLR, "rx_data: #5 j: %d, offset: %d\n",
				j, rx_marker_val[j]);
			conn->of_marker_offset = rx_marker_val[j];
		}
		total_rx -= (rx_marker_iov * (MARKER_SIZE / 2));
	}

	return(total_rx);
}

/*	iscsi_do_tx_data():
 *
 *
 */
static inline int iscsi_do_tx_data (
	iscsi_conn_t *conn,
	iscsi_data_count_t *count)
{
	int data = count->data_length, total_tx = 0, tx_loop = 0;
	__u32 tx_marker_val[count->ss_marker_count], tx_marker_iov = 0;
	struct iovec iov[count->ss_iov_count];
#ifdef LINUX
	mm_segment_t oldfs;
	struct msghdr msg;
#endif /* LINUX */

	if (!conn || !conn->sock || !CONN_OPS(conn))
		return(-1);

	if (data <= 0) {
		TRACE_ERROR("Data length is: %d\n", data);
		return(-1);
	}
	
	memset(&msg, 0, sizeof(struct msghdr));
	
	if (count->sync_and_steering) {
		int size = 0;
		__u32 i, orig_iov_count = 0;
		__u32 orig_iov_len = 0, orig_iov_loc = 0;
		__u32 iov_count = 0, per_iov_bytes = 0;
		__u32 *tx_marker, old_tx_marker = 0;
		struct iovec *iov_record;

		memset((void *)&tx_marker_val, 0, count->ss_marker_count * sizeof(__u32));
		memset((void *)&iov, 0, count->ss_iov_count * sizeof(struct iovec));

		iov_record = count->iov;
		orig_iov_count = count->iov_count;
		tx_marker = &conn->if_marker;

		i = 0;
		size = data;
		orig_iov_len = iov_record[orig_iov_loc].iov_len;
		while (size > 0) {
			TRACE(TRACE_SSLT, "tx_data: #1 orig_iov_len %u,"
			" orig_iov_loc %u\n", orig_iov_len, orig_iov_loc);
			TRACE(TRACE_SSLT, "tx_data: #2 tx_marker %u, size"
				" %u\n", *tx_marker, size);

			if (orig_iov_len >= *tx_marker) {
				iov[iov_count].iov_len = *tx_marker;
				iov[iov_count++].iov_base =
					(iov_record[orig_iov_loc].iov_base +
					 	per_iov_bytes);
				
				tx_marker_val[tx_marker_iov] =
						(size - *tx_marker);
				iov[iov_count].iov_len = (MARKER_SIZE / 2);
				iov[iov_count++].iov_base =
					&tx_marker_val[tx_marker_iov++];
				iov[iov_count].iov_len = (MARKER_SIZE / 2);
				iov[iov_count++].iov_base =
					&tx_marker_val[tx_marker_iov++];
				old_tx_marker = *tx_marker;

				/*
				 * IFMarkInt is in 32-bit words.
				 */
				*tx_marker = (CONN_OPS(conn)->IFMarkInt * 4);
				size -= old_tx_marker;
				orig_iov_len -= old_tx_marker;
				per_iov_bytes += old_tx_marker;

				TRACE(TRACE_SSLT, "tx_data: #3 new_tx_marker"
					" %u, size %u\n", *tx_marker, size);
				TRACE(TRACE_SSLT, "tx_data: #4 offset %u\n",
					tx_marker_val[tx_marker_iov-1]);
			} else {
				iov[iov_count].iov_len = orig_iov_len;
				iov[iov_count++].iov_base
					= (iov_record[orig_iov_loc].iov_base +
						per_iov_bytes);

				per_iov_bytes = 0;
				*tx_marker -= orig_iov_len;
				size -= orig_iov_len;

				if (size)
					orig_iov_len =
					iov_record[++orig_iov_loc].iov_len;

				TRACE(TRACE_SSLT, "tx_data: #5 new_tx_marker"
					" %u, size %u\n", *tx_marker, size);
			}
		}

		data += (tx_marker_iov * (MARKER_SIZE / 2));
		
		msg.msg_iov	= &iov[0];
		msg.msg_iovlen = iov_count;

		if (iov_count > count->ss_iov_count) {
			TRACE_ERROR("iov_count: %d, count->ss_iov_count: %d\n",
				iov_count, count->ss_iov_count);
			return(-1);
		}
		if (tx_marker_iov > count->ss_marker_count) {
			TRACE_ERROR("tx_marker_iov: %d, count->ss_marker_count: %d\n",
				tx_marker_iov, count->ss_marker_count);
			return(-1);
		}
	} else {
		msg.msg_iov	= count->iov;
		msg.msg_iovlen	= count->iov_count;
	}

	while (total_tx < data) {
		oldfs = get_fs();
		set_fs(get_ds());

		conn->sock->sk->sk_allocation = GFP_ATOMIC;
		tx_loop = sock_sendmsg(conn->sock, &msg, (data - total_tx));

		set_fs(oldfs);

		if (tx_loop <= 0) {
			TRACE(TRACE_NET, "tx_loop: %d total_tx %d\n",
				tx_loop, total_tx);
			return(tx_loop);
		}
		total_tx += tx_loop;
		TRACE(TRACE_NET, "tx_loop: %d, total_tx: %d, data: %d\n", 
					tx_loop, total_tx, data);
	}

	if (count->sync_and_steering)
		total_tx -= (tx_marker_iov * (MARKER_SIZE / 2));

	return(total_tx);
}

/*	rx_data():
 *
 *
 */
extern int rx_data (
	iscsi_conn_t *conn,
	struct iovec *iov,
	int iov_count,
	int data)
{
	int ret;
	iscsi_data_count_t c;

	if (!conn || !conn->sock || !CONN_OPS(conn))
		return(-1);

	memset(&c, 0, sizeof(iscsi_data_count_t));
	c.iov = iov;
	c.iov_count = iov_count;
	c.data_length = data;
	c.type = ISCSI_RX_DATA;

	if (CONN_OPS(conn)->OFMarker &&
	   (conn->conn_state >= TARG_CONN_STATE_LOGGED_IN)) {
		if (iscsi_determine_sync_and_steering_counts(conn, &c) < 0)
			return(-1);
	}

	ret = iscsi_do_rx_data(conn, &c);


	return(ret);
}

/*	tx_data():
 *
 *
 */
extern int tx_data (
	iscsi_conn_t *conn,
	struct iovec *iov,
	int iov_count,
	int data)
{
	int ret;
	iscsi_data_count_t c;

	if (!conn || !conn->sock || !CONN_OPS(conn))
		return(-1);

	memset(&c, 0, sizeof(iscsi_data_count_t));
	c.iov = iov;
	c.iov_count = iov_count;
	c.data_length = data;
	c.type = ISCSI_TX_DATA;

	if (CONN_OPS(conn)->IFMarker &&
	   (conn->conn_state >= TARG_CONN_STATE_LOGGED_IN)) {
		if (iscsi_determine_sync_and_steering_counts(conn, &c) < 0)
			return(-1);
	}

	ret = iscsi_do_tx_data(conn, &c);

	return(ret);
}

#ifdef SNMP_SUPPORT
/*
 * Collect login statistics 
 */
void iscsi_collect_login_stats (iscsi_conn_t *conn, __u8 status_class,
				__u8 status_detail)
{
	iscsi_param_t *intrname = NULL;
	iscsi_tiqn_t *tiqn;

	tiqn = iscsi_snmp_get_tiqn(conn);

	spin_lock(&tiqn->login_stats.lock);
	if ((conn->login_ip == tiqn->login_stats.last_intr_fail_addr) &&
	    ((get_jiffies_64() - tiqn->login_stats.last_fail_time) < 10)) {
		/* We already have the failure info for this login */
		spin_unlock(&tiqn->login_stats.lock);
		return;
	}

	if (status_class == STAT_CLASS_SUCCESS)
		tiqn->login_stats.accepts++;
	else if (status_class == STAT_CLASS_REDIRECTION) {
		tiqn->login_stats.redirects++;
		tiqn->login_stats.last_fail_type =
						 ISCSI_LOGIN_FAIL_REDIRECT;
	}
	else if ((status_class == STAT_CLASS_INITIATOR)  &&
		 (status_detail == STAT_DETAIL_NOT_AUTH)) {
		tiqn->login_stats.authenticate_fails++;
		tiqn->login_stats.last_fail_type =
						 ISCSI_LOGIN_FAIL_AUTHENTICATE;
	}
	else if ((status_class == STAT_CLASS_INITIATOR)  &&
		 (status_detail == STAT_DETAIL_NOT_ALLOWED)) {
		tiqn->login_stats.authorize_fails++;
		tiqn->login_stats.last_fail_type =
						 ISCSI_LOGIN_FAIL_AUTHORIZE;
	}
	else if ((status_class == STAT_CLASS_INITIATOR)  &&
		 (status_detail == STAT_DETAIL_INIT_ERROR)) {
		tiqn->login_stats.negotiate_fails++;
		tiqn->login_stats.last_fail_type =
						 ISCSI_LOGIN_FAIL_NEGOTIATE;
	}
	else {
		tiqn->login_stats.other_fails++;
		tiqn->login_stats.last_fail_type =
						 ISCSI_LOGIN_FAIL_OTHER;
	}

	/* Save initiator name, ip address and time, if it is a failed login */
#warning FIXME: IPv6
	if (status_class != STAT_CLASS_SUCCESS) {
		if (conn->param_list)
			intrname = iscsi_find_param_from_key(INITIATORNAME,
							     conn->param_list);
		strcpy(tiqn->login_stats.last_intr_fail_name,
		       (intrname ? intrname->value : "Unknown"));
#warning FIXME: IPv6
		tiqn->login_stats.last_intr_fail_addr = conn->login_ip;
		tiqn->login_stats.last_fail_time = get_jiffies_64();
	}
	
	spin_unlock(&tiqn->login_stats.lock);
}

extern iscsi_tiqn_t *iscsi_snmp_get_tiqn (iscsi_conn_t *conn)
{
	iscsi_portal_group_t *tpg;
	
	if (!conn || !conn->sess || !conn->sess->tpg)
		return(core_get_default_tiqn());

	if (!(tpg = conn->sess->tpg))
		return(core_get_default_tiqn());

	return((tpg->tpg_tiqn) ? tpg->tpg_tiqn :
		core_get_default_tiqn());
}
#endif /* SNMP_SUPPORT */
