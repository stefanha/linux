/*******************************************************************************
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
 ******************************************************************************/

#include <linux/string.h>
#include <linux/version.h>
#include <linux/timer.h>
#include <linux/blkdev.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/smp_lock.h>
#include <linux/in.h>
#include <linux/list.h>
#include <net/sock.h>
#include <net/tcp.h>
#include <scsi/scsi.h>
#include <scsi/scsi_host.h>
#include <scsi/libsas.h> /* For TASK_ATTR_* */

#include <iscsi_linux_defs.h>
#include <iscsi_debug.h>
#include <iscsi_protocol.h>
#include <iscsi_serial.h>

#include <target/target_core_base.h>
#include <target/target_core_transport.h>
#include <target/target_core_tmr.h>

#include <iscsi_target_core.h>
#include <iscsi_target_datain_values.h>
#include <iscsi_target_erl0.h>
#include <iscsi_target_erl1.h>
#include <iscsi_target_erl2.h>
#include <iscsi_target_tpg.h>
#include <iscsi_target_util.h>
#include <iscsi_target.h>
#include <iscsi_parameters.h>

#include <target/target_core_fabric_ops.h>
#include <target/target_core_configfs.h>

#ifdef DEBUG_ERL
#include <iscsi_target_debugerl.h>
#endif /* DEBUG_ERL */

/*	iscsi_attach_cmd_to_queue():
 *
 *
 */
inline void iscsi_attach_cmd_to_queue(struct iscsi_conn *conn, struct iscsi_cmd *cmd)
{
	spin_lock_bh(&conn->cmd_lock);
	list_add_tail(&cmd->i_list, &conn->conn_cmd_list);
	spin_unlock_bh(&conn->cmd_lock);

	atomic_inc(&conn->active_cmds);
}

/*	iscsi_remove_cmd_from_conn_list():
 *
 *	MUST be called with conn->cmd_lock held.
 */
inline void iscsi_remove_cmd_from_conn_list(
	struct iscsi_cmd *cmd,
	struct iscsi_conn *conn)
{
	list_del(&cmd->i_list);
	atomic_dec(&conn->active_cmds);
}


/*	iscsi_ack_from_expstatsn():
 *
 *
 */
inline void iscsi_ack_from_expstatsn(struct iscsi_conn *conn, u32 exp_statsn)
{
	struct iscsi_cmd *cmd;

	conn->exp_statsn = exp_statsn;

	spin_lock_bh(&conn->cmd_lock);
	list_for_each_entry(cmd, &conn->conn_cmd_list, i_list) {

		spin_lock(&cmd->istate_lock);
		if ((cmd->i_state == ISTATE_SENT_STATUS) &&
		    (cmd->stat_sn < exp_statsn)) {
			cmd->i_state = ISTATE_REMOVE;
			spin_unlock(&cmd->istate_lock);
			iscsi_add_cmd_to_immediate_queue(cmd, conn,
					cmd->i_state);
			continue;
		}
		spin_unlock(&cmd->istate_lock);
	}
	spin_unlock_bh(&conn->cmd_lock);
}

/*	iscsi_remove_conn_from_list():
 *
 *	Called with sess->conn_lock held.
 */
void iscsi_remove_conn_from_list(struct iscsi_session *sess, struct iscsi_conn *conn)
{
	list_del(&conn->conn_list);
}

/*	iscsi_add_r2t_to_list():
 *
 *	Called with cmd->r2t_lock held.
 */
int iscsi_add_r2t_to_list(
	struct iscsi_cmd *cmd,
	u32 offset,
	u32 xfer_len,
	int recovery,
	u32 r2t_sn)
{
	struct iscsi_r2t *r2t;

	r2t = kmem_cache_zalloc(lio_r2t_cache, GFP_ATOMIC);
	if (!(r2t)) {
		printk(KERN_ERR "Unable to allocate memory for struct iscsi_r2t.\n");
		return -1;
	}
	INIT_LIST_HEAD(&r2t->r2t_list);

	r2t->recovery_r2t = recovery;
	r2t->r2t_sn = (!r2t_sn) ? cmd->r2t_sn++ : r2t_sn;
	r2t->offset = offset;
	r2t->xfer_len = xfer_len;
	list_add_tail(&r2t->r2t_list, &cmd->cmd_r2t_list);
	spin_unlock_bh(&cmd->r2t_lock);

	iscsi_add_cmd_to_immediate_queue(cmd, CONN(cmd), ISTATE_SEND_R2T);

	spin_lock_bh(&cmd->r2t_lock);
	return 0;
}

/*	iscsi_get_r2t_for_eos():
 *
 *
 */
struct iscsi_r2t *iscsi_get_r2t_for_eos(
	struct iscsi_cmd *cmd,
	u32 offset,
	u32 length)
{
	struct iscsi_r2t *r2t;

	spin_lock_bh(&cmd->r2t_lock);
	list_for_each_entry(r2t, &cmd->cmd_r2t_list, r2t_list) {
		if ((r2t->offset <= offset) &&
		    (r2t->offset + r2t->xfer_len) >= (offset + length))
			break;
	}
	spin_unlock_bh(&cmd->r2t_lock);

	if (!r2t) {
		printk(KERN_ERR "Unable to locate R2T for Offset: %u, Length:"
				" %u\n", offset, length);
		return NULL;
	}

	return r2t;
}

/*	iscsi_get_r2t_from_list():
 *
 *
 */
struct iscsi_r2t *iscsi_get_r2t_from_list(struct iscsi_cmd *cmd)
{
	struct iscsi_r2t *r2t;

	spin_lock_bh(&cmd->r2t_lock);
	list_for_each_entry(r2t, &cmd->cmd_r2t_list, r2t_list) {
		if (!r2t->sent_r2t)
			break;
	}
	spin_unlock_bh(&cmd->r2t_lock);

	if (!r2t) {
		printk(KERN_ERR "Unable to locate next R2T to send for ITT:"
			" 0x%08x.\n", cmd->init_task_tag);
		return NULL;
	}

	return r2t;
}

/*	iscsi_free_r2t():
 *
 *	Called with cmd->r2t_lock held.
 */
void iscsi_free_r2t(struct iscsi_r2t *r2t, struct iscsi_cmd *cmd)
{
	list_del(&r2t->r2t_list);
	kmem_cache_free(lio_r2t_cache, r2t);
}

/*	iscsi_free_r2ts_from_list():
 *
 *
 */
void iscsi_free_r2ts_from_list(struct iscsi_cmd *cmd)
{
	struct iscsi_r2t *r2t, *r2t_tmp;

	spin_lock_bh(&cmd->r2t_lock);
	list_for_each_entry_safe(r2t, r2t_tmp, &cmd->cmd_r2t_list, r2t_list) {
		list_del(&r2t->r2t_list);
		kmem_cache_free(lio_r2t_cache, r2t);
	}
	spin_unlock_bh(&cmd->r2t_lock);
}

/*	iscsi_allocate_cmd():
 *
 *	May be called from interrupt context.
 */
struct iscsi_cmd *iscsi_allocate_cmd(struct iscsi_conn *conn)
{
	struct iscsi_cmd *cmd;

	cmd = kmem_cache_zalloc(lio_cmd_cache, GFP_ATOMIC);
	if (!(cmd)) {
		printk(KERN_ERR "Unable to allocate memory for struct iscsi_cmd.\n");
		return NULL;
	}

	cmd->conn	= conn;
	INIT_LIST_HEAD(&cmd->i_list);
	INIT_LIST_HEAD(&cmd->datain_list);
	INIT_LIST_HEAD(&cmd->cmd_r2t_list);
	init_MUTEX_LOCKED(&cmd->reject_sem);
	init_MUTEX_LOCKED(&cmd->unsolicited_data_sem);
	spin_lock_init(&cmd->datain_lock);
	spin_lock_init(&cmd->dataout_timeout_lock);
	spin_lock_init(&cmd->istate_lock);
	spin_lock_init(&cmd->error_lock);
	spin_lock_init(&cmd->r2t_lock);

	return cmd;
}

/*
 * Called from iscsi_handle_scsi_cmd()
 */
struct iscsi_cmd *iscsi_allocate_se_cmd(
	struct iscsi_conn *conn,
	u32 data_length,
	int data_direction,
	int iscsi_task_attr)
{
	struct iscsi_cmd *cmd;
	int sam_task_attr;

	cmd = iscsi_allocate_cmd(conn);
	if (!(cmd))
		return NULL;

	cmd->data_direction = data_direction;
	cmd->data_length = data_length;
	/*
	 * Figure out the SAM Task Attribute for the incoming SCSI CDB
	 */
	if ((iscsi_task_attr == ISCSI_UNTAGGED) ||
	    (iscsi_task_attr == ISCSI_SIMPLE))
		sam_task_attr = TASK_ATTR_SIMPLE;
	else if (iscsi_task_attr == ISCSI_ORDERED)
		sam_task_attr = TASK_ATTR_ORDERED;
	else if (iscsi_task_attr == ISCSI_HEAD_OF_QUEUE)
		sam_task_attr = TASK_ATTR_HOQ;
	else if (iscsi_task_attr == ISCSI_ACA)
		sam_task_attr = TASK_ATTR_ACA;
	else {
		printk(KERN_INFO "Unknown iSCSI Task Attribute: 0x%02x, using"
			" TASK_ATTR_SIMPLE\n", iscsi_task_attr);
		sam_task_attr = TASK_ATTR_SIMPLE;
	}
	/*
	 * Use struct target_fabric_configfs->tf_ops for
	 * lio_target_fabric_configfs
	 */
	cmd->se_cmd = transport_alloc_se_cmd(
			&lio_target_fabric_configfs->tf_ops,
			SESS(conn)->se_sess, (void *)cmd, data_length,
			data_direction, sam_task_attr);
	if (!(cmd->se_cmd))
		goto out;

	return cmd;
out:
	iscsi_release_cmd_to_pool(cmd);
	return NULL;
}

/*	iscsi_allocate_tmr_req():
 *
 *
 */
struct iscsi_cmd *iscsi_allocate_se_cmd_for_tmr(
	struct iscsi_conn *conn,
	u8 function)
{
	struct iscsi_cmd *cmd;
	struct se_cmd *se_cmd = NULL;

	cmd = iscsi_allocate_cmd(conn);
	if (!(cmd))
		return NULL;

	cmd->data_direction = SE_DIRECTION_NONE;

	cmd->tmr_req = kzalloc(sizeof(struct iscsi_tmr_req), GFP_KERNEL);
	if (!(cmd->tmr_req)) {
		printk(KERN_ERR "Unable to allocate memory for"
			" Task Management command!\n");
		return NULL;
	}
	/*
	 * TASK_REASSIGN for ERL=2 / connection stays inside of
	* LIO-Target $FABRIC_MOD
	 */
	if (function == TASK_REASSIGN)
		return cmd;

	cmd->se_cmd = transport_alloc_se_cmd(
				&lio_target_fabric_configfs->tf_ops,
				SESS(conn)->se_sess, (void *)cmd, 0,
				SE_DIRECTION_NONE, TASK_ATTR_SIMPLE);
	if (!(cmd->se_cmd))
		goto out;

	se_cmd = cmd->se_cmd;

	se_cmd->se_tmr_req = core_tmr_alloc_req(se_cmd,
				(void *)cmd->tmr_req, function);
	if (!(se_cmd->se_tmr_req))
		goto out;

	cmd->tmr_req->se_tmr_req = se_cmd->se_tmr_req;

	return cmd;
out:
	iscsi_release_cmd_to_pool(cmd);
	if (se_cmd)
		transport_free_se_cmd(se_cmd);
	return NULL;
}

/*	iscsi_decide_list_to_build():
 *
 *
 */
int iscsi_decide_list_to_build(
	struct iscsi_cmd *cmd,
	u32 immediate_data_length)
{
	struct iscsi_build_list bl;
	struct iscsi_conn *conn = CONN(cmd);
	struct iscsi_session *sess = SESS(conn);
	struct iscsi_node_attrib *na;

	if (SESS_OPS(sess)->DataSequenceInOrder &&
	    SESS_OPS(sess)->DataPDUInOrder)
		return 0;

	if (cmd->data_direction == ISCSI_NONE)
		return 0;

	na = iscsi_tpg_get_node_attrib(sess);
	memset(&bl, 0, sizeof(struct iscsi_build_list));

	if (cmd->data_direction == ISCSI_READ) {
		bl.data_direction = ISCSI_PDU_READ;
		bl.type = PDULIST_NORMAL;
		if (na->random_datain_pdu_offsets)
			bl.randomize |= RANDOM_DATAIN_PDU_OFFSETS;
		if (na->random_datain_seq_offsets)
			bl.randomize |= RANDOM_DATAIN_SEQ_OFFSETS;
	} else {
		bl.data_direction = ISCSI_PDU_WRITE;
		bl.immediate_data_length = immediate_data_length;
		if (na->random_r2t_offsets)
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

	return iscsi_do_build_list(cmd, &bl);
}

/*	iscsi_get_seq_holder_for_datain():
 *
 *
 */
struct iscsi_seq *iscsi_get_seq_holder_for_datain(
	struct iscsi_cmd *cmd,
	u32 seq_send_order)
{
	u32 i;

	for (i = 0; i < cmd->seq_count; i++)
		if (cmd->seq_list[i].seq_send_order == seq_send_order)
			return &cmd->seq_list[i];

	return NULL;
}

/*	iscsi_get_seq_holder_for_r2t():
 *
 *
 */
struct iscsi_seq *iscsi_get_seq_holder_for_r2t(struct iscsi_cmd *cmd)
{
	u32 i;

	if (!cmd->seq_list) {
		printk(KERN_ERR "struct iscsi_cmd->seq_list is NULL!\n");
		return NULL;
	}

	for (i = 0; i < cmd->seq_count; i++) {
		if (cmd->seq_list[i].type != SEQTYPE_NORMAL)
			continue;
		if (cmd->seq_list[i].seq_send_order == cmd->seq_send_order) {
			cmd->seq_send_order++;
			return &cmd->seq_list[i];
		}
	}

	return NULL;
}

/*	iscsi_get_holder_for_r2tsn():
 *
 *
 */
struct iscsi_r2t *iscsi_get_holder_for_r2tsn(
	struct iscsi_cmd *cmd,
	u32 r2t_sn)
{
	struct iscsi_r2t *r2t;

	spin_lock_bh(&cmd->r2t_lock);
	list_for_each_entry(r2t, &cmd->cmd_r2t_list, r2t_list) {
		if (r2t->r2t_sn == r2t_sn)
			break;
	}
	spin_unlock_bh(&cmd->r2t_lock);

	return (r2t) ? r2t : NULL;
}

/*	iscsi_check_received_cmdsn():
 *
 *
 */
inline int iscsi_check_received_cmdsn(
	struct iscsi_conn *conn,
	struct iscsi_cmd *cmd,
	u32 cmdsn)
{
	int ret;

#ifdef DEBUG_ERL
	if (iscsi_target_debugerl_cmdsn(conn, cmdsn) < 0)
		return CMDSN_LOWER_THAN_EXP;
#endif /* DEBUG_ERL */

	/*
	 * This is the proper method of checking received CmdSN against
	 * ExpCmdSN and MaxCmdSN values, as well as accounting for out
	 * or order CmdSNs due to multiple connection sessions and/or
	 * CRC failures.
	 */
	spin_lock(&SESS(conn)->cmdsn_lock);
	if (serial_gt(cmdsn, SESS(conn)->max_cmd_sn)) {
		printk(KERN_ERR "Received CmdSN: 0x%08x is greater than"
			" MaxCmdSN: 0x%08x, protocol error.\n", cmdsn,
				SESS(conn)->max_cmd_sn);
		spin_unlock(&SESS(conn)->cmdsn_lock);
		return CMDSN_ERROR_CANNOT_RECOVER;
	}

	if (!SESS(conn)->cmdsn_outoforder) {
		if (cmdsn == SESS(conn)->exp_cmd_sn) {
			SESS(conn)->exp_cmd_sn++;
			TRACE(TRACE_CMDSN, "Received CmdSN matches ExpCmdSN,"
				" incremented ExpCmdSN to: 0x%08x\n",
					SESS(conn)->exp_cmd_sn);
			ret = iscsi_execute_cmd(cmd, 0);
			spin_unlock(&SESS(conn)->cmdsn_lock);

			return (!ret) ? CMDSN_NORMAL_OPERATION :
					CMDSN_ERROR_CANNOT_RECOVER;
		} else if (serial_gt(cmdsn, SESS(conn)->exp_cmd_sn)) {
			TRACE(TRACE_CMDSN, "Received CmdSN: 0x%08x is greater"
				" than ExpCmdSN: 0x%08x, not acknowledging.\n",
				cmdsn, SESS(conn)->exp_cmd_sn);
			goto ooo_cmdsn;
		} else {
			printk(KERN_ERR "Received CmdSN: 0x%08x is less than"
				" ExpCmdSN: 0x%08x, ignoring.\n", cmdsn,
					SESS(conn)->exp_cmd_sn);
			spin_unlock(&SESS(conn)->cmdsn_lock);
			return CMDSN_LOWER_THAN_EXP;
		}
	} else {
		int counter = 0;
		u32 old_expcmdsn = 0;
		if (cmdsn == SESS(conn)->exp_cmd_sn) {
			old_expcmdsn = SESS(conn)->exp_cmd_sn++;
			TRACE(TRACE_CMDSN, "Got missing CmdSN: 0x%08x matches"
				" ExpCmdSN, incremented ExpCmdSN to 0x%08x.\n",
					cmdsn, SESS(conn)->exp_cmd_sn);

			if (iscsi_execute_cmd(cmd, 0) < 0) {
				spin_unlock(&SESS(conn)->cmdsn_lock);
				return CMDSN_ERROR_CANNOT_RECOVER;
			}
		} else if (serial_gt(cmdsn, SESS(conn)->exp_cmd_sn)) {
			TRACE(TRACE_CMDSN, "CmdSN: 0x%08x greater than"
				" ExpCmdSN: 0x%08x, not acknowledging.\n",
				cmdsn, SESS(conn)->exp_cmd_sn);
			goto ooo_cmdsn;
		} else {
			printk(KERN_ERR "CmdSN: 0x%08x less than ExpCmdSN:"
				" 0x%08x, ignoring.\n", cmdsn,
				SESS(conn)->exp_cmd_sn);
			spin_unlock(&SESS(conn)->cmdsn_lock);
			return CMDSN_LOWER_THAN_EXP;
		}

		counter = iscsi_execute_ooo_cmdsns(SESS(conn));
		if (counter < 0) {
			spin_unlock(&SESS(conn)->cmdsn_lock);
			return CMDSN_ERROR_CANNOT_RECOVER;
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
		return CMDSN_NORMAL_OPERATION;
	}

ooo_cmdsn:
	ret = iscsi_handle_ooo_cmdsn(SESS(conn), cmd, cmdsn);
	spin_unlock(&SESS(conn)->cmdsn_lock);
	return ret;
}

/*	iscsi_check_unsolicited_dataout():
 *
 *
 */
int iscsi_check_unsolicited_dataout(struct iscsi_cmd *cmd, unsigned char *buf)
{
	struct iscsi_conn *conn = CONN(cmd);
	struct se_cmd *se_cmd = SE_CMD(cmd);
	struct iscsi_init_scsi_data_out *hdr =
		(struct iscsi_init_scsi_data_out *) buf;

	if (SESS_OPS_C(conn)->InitialR2T) {
		printk(KERN_ERR "Received unexpected unsolicited data"
			" while InitialR2T=Yes, protocol error.\n");
		transport_send_check_condition_and_sense(se_cmd,
				UNEXPECTED_UNSOLICITED_DATA, 0);
		return -1;
	}

	if ((cmd->first_burst_len + hdr->length) >
	     SESS_OPS_C(conn)->FirstBurstLength) {
		printk(KERN_ERR "Total %u bytes exceeds FirstBurstLength: %u"
			" for this Unsolicited DataOut Burst.\n",
			(cmd->first_burst_len + hdr->length),
				SESS_OPS_C(conn)->FirstBurstLength);
		transport_send_check_condition_and_sense(se_cmd,
				INCORRECT_AMOUNT_OF_DATA, 0);
		return -1;
	}

	if (!(hdr->flags & F_BIT))
		return 0;

	if (((cmd->first_burst_len + hdr->length) != cmd->data_length) &&
	    ((cmd->first_burst_len + hdr->length) !=
	      SESS_OPS_C(conn)->FirstBurstLength)) {
		printk(KERN_ERR "Unsolicited non-immediate data received %u"
			" does not equal FirstBurstLength: %u, and does"
			" not equal ExpXferLen %u.\n",
			(cmd->first_burst_len + hdr->length),
			SESS_OPS_C(conn)->FirstBurstLength, cmd->data_length);
		transport_send_check_condition_and_sense(se_cmd,
				INCORRECT_AMOUNT_OF_DATA, 0);
		return -1;
	}
	return 0;
}

/*	iscsi_find_cmd_from_itt():
 *
 *
 */
struct iscsi_cmd *iscsi_find_cmd_from_itt(
	struct iscsi_conn *conn,
	u32 init_task_tag)
{
	struct iscsi_cmd *cmd;

	spin_lock_bh(&conn->cmd_lock);
	list_for_each_entry(cmd, &conn->conn_cmd_list, i_list) {
		if (cmd->init_task_tag == init_task_tag)
			break;
	}
	spin_unlock_bh(&conn->cmd_lock);

	if (!cmd) {
		printk(KERN_ERR "Unable to locate ITT: 0x%08x on CID: %hu",
			init_task_tag, conn->cid);
		return NULL;
	}

	return cmd;
}

/*	iscsi_find_cmd_from_itt_or_dump():
 *
 *
 */
struct iscsi_cmd *iscsi_find_cmd_from_itt_or_dump(
	struct iscsi_conn *conn,
	u32 init_task_tag,
	u32 length)
{
	struct iscsi_cmd *cmd;

	spin_lock_bh(&conn->cmd_lock);
	list_for_each_entry(cmd, &conn->conn_cmd_list, i_list) {
		if (cmd->init_task_tag == init_task_tag)
			break;
	}
	spin_unlock_bh(&conn->cmd_lock);

	if (!cmd) {
		printk(KERN_ERR "Unable to locate ITT: 0x%08x on CID: %hu,"
			" dumping payload\n", init_task_tag, conn->cid);
		if (length)
			iscsi_dump_data_payload(conn, length, 1);
		return NULL;
	}

	return cmd;
}

/*	iscsi_find_cmd_from_ttt():
 *
 *
 */
struct iscsi_cmd *iscsi_find_cmd_from_ttt(
	struct iscsi_conn *conn,
	u32 targ_xfer_tag)
{
	struct iscsi_cmd *cmd = NULL;

	spin_lock_bh(&conn->cmd_lock);
	list_for_each_entry(cmd, &conn->conn_cmd_list, i_list) {
		if (cmd->targ_xfer_tag == targ_xfer_tag)
			break;
	}
	spin_unlock_bh(&conn->cmd_lock);

	if (!cmd) {
		printk(KERN_ERR "Unable to locate TTT: 0x%08x on CID: %hu\n",
			targ_xfer_tag, conn->cid);
		return NULL;
	}

	return cmd;
}

/*	iscsi_find_cmd_for_recovery():
 *
 *
 */
int iscsi_find_cmd_for_recovery(
	struct iscsi_session *sess,
	struct iscsi_cmd **cmd_ptr,
	struct iscsi_conn_recovery **cr_ptr,
	u32 init_task_tag)
{
	int found_itt = 0;
	struct iscsi_cmd *cmd = NULL;
	struct iscsi_conn_recovery *cr;

	/*
	 * Scan through the inactive connection recovery list's command list.
	 * If init_task_tag matches the command is still alligent.
	 */
	spin_lock(&sess->cr_i_lock);
	list_for_each_entry(cr, &sess->cr_inactive_list, cr_list) {
		spin_lock(&cr->conn_recovery_cmd_lock);
		list_for_each_entry(cmd, &cr->conn_recovery_cmd_list, i_list) {
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
		return -2;
	}

	found_itt = 0;

	/*
	 * Scan through the active connection recovery list's command list.
	 * If init_task_tag matches the command is ready to be reassigned.
	 */
	spin_lock(&sess->cr_a_lock);
	list_for_each_entry(cr, &sess->cr_active_list, cr_list) {
		spin_lock(&cr->conn_recovery_cmd_lock);
		list_for_each_entry(cmd, &cr->conn_recovery_cmd_list, i_list) {
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
		return -1;

	*cr_ptr = cr;
	*cmd_ptr = cmd;

	return 0;
}

/*	iscsi_add_cmd_to_immediate_queue():
 *
 *
 */
void iscsi_add_cmd_to_immediate_queue(
	struct iscsi_cmd *cmd,
	struct iscsi_conn *conn,
	u8 state)
{
	struct iscsi_queue_req *qr;

	qr = kmem_cache_zalloc(lio_qr_cache, GFP_ATOMIC);
	if (!(qr)) {
		printk(KERN_ERR "Unable to allocate memory for"
				" struct iscsi_queue_req\n");
		return;
	}
	INIT_LIST_HEAD(&qr->qr_list);
#if 0
	printk(KERN_INFO "Adding ITT: 0x%08x state: %d to immediate queue\n",
			cmd->init_task_tag, state);
#endif
	qr->cmd = cmd;
	qr->state = state;

	spin_lock_bh(&conn->immed_queue_lock);
	list_add_tail(&qr->qr_list, &conn->immed_queue_list);
	atomic_inc(&cmd->immed_queue_count);
	atomic_set(&conn->check_immediate_queue, 1);
	spin_unlock_bh(&conn->immed_queue_lock);

	up(&conn->tx_sem);
}

/*	iscsi_get_cmd_from_immediate_queue():
 *
 *
 */
struct iscsi_queue_req *iscsi_get_cmd_from_immediate_queue(struct iscsi_conn *conn)
{
	struct iscsi_queue_req *qr;

	spin_lock_bh(&conn->immed_queue_lock);
	if (list_empty(&conn->immed_queue_list)) {
		spin_unlock_bh(&conn->immed_queue_lock);
		return NULL;
	}
	list_for_each_entry(qr, &conn->immed_queue_list, qr_list)
		break;

	list_del(&qr->qr_list);
	if (qr->cmd)
		atomic_dec(&qr->cmd->immed_queue_count);
	spin_unlock_bh(&conn->immed_queue_lock);

	return qr;
}

static void iscsi_remove_cmd_from_immediate_queue(
	struct iscsi_cmd *cmd,
	struct iscsi_conn *conn)
{
	struct iscsi_queue_req *qr, *qr_tmp;

	spin_lock_bh(&conn->immed_queue_lock);
	if (!(atomic_read(&cmd->immed_queue_count))) {
		spin_unlock_bh(&conn->immed_queue_lock);
		return;
	}

	list_for_each_entry_safe(qr, qr_tmp, &conn->immed_queue_list, qr_list) {
		if (qr->cmd != cmd)
			continue;

		atomic_dec(&qr->cmd->immed_queue_count);
		list_del(&qr->qr_list);
		kmem_cache_free(lio_qr_cache, qr);
	}
	spin_unlock_bh(&conn->immed_queue_lock);

	if (atomic_read(&cmd->immed_queue_count)) {
		printk(KERN_ERR "ITT: 0x%08x immed_queue_count: %d\n",
			cmd->init_task_tag,
			atomic_read(&cmd->immed_queue_count));
	}
}

/*	iscsi_add_cmd_to_response_queue():
 *
 *
 */
void iscsi_add_cmd_to_response_queue(
	struct iscsi_cmd *cmd,
	struct iscsi_conn *conn,
	u8 state)
{
	struct iscsi_queue_req *qr;

	qr = kmem_cache_zalloc(lio_qr_cache, GFP_ATOMIC);
	if (!(qr)) {
		printk(KERN_ERR "Unable to allocate memory for"
			" struct iscsi_queue_req\n");
		return;
	}
	INIT_LIST_HEAD(&qr->qr_list);
#if 0
	printk(KERN_INFO "Adding ITT: 0x%08x state: %d to response queue\n",
			cmd->init_task_tag, state);
#endif
	qr->cmd = cmd;
	qr->state = state;

	spin_lock_bh(&conn->response_queue_lock);
	list_add_tail(&qr->qr_list, &conn->response_queue_list);
	atomic_inc(&cmd->response_queue_count);
	spin_unlock_bh(&conn->response_queue_lock);

	up(&conn->tx_sem);
}

/*	iscsi_get_cmd_from_response_queue():
 *
 *
 */
struct iscsi_queue_req *iscsi_get_cmd_from_response_queue(struct iscsi_conn *conn)
{
	struct iscsi_queue_req *qr;

	spin_lock_bh(&conn->response_queue_lock);
	if (list_empty(&conn->response_queue_list)) {
		spin_unlock_bh(&conn->response_queue_lock);
		return NULL;
	}

	list_for_each_entry(qr, &conn->response_queue_list, qr_list)
		break;

	list_del(&qr->qr_list);
	if (qr->cmd)
		atomic_dec(&qr->cmd->response_queue_count);
	spin_unlock_bh(&conn->response_queue_lock);

	return qr;
}

/*	iscsi_remove_cmd_from_response_queue():
 *
 *
 */
static void iscsi_remove_cmd_from_response_queue(
	struct iscsi_cmd *cmd,
	struct iscsi_conn *conn)
{
	struct iscsi_queue_req *qr, *qr_tmp;

	spin_lock_bh(&conn->response_queue_lock);
	if (!(atomic_read(&cmd->response_queue_count))) {
		spin_unlock_bh(&conn->response_queue_lock);
		return;
	}

	list_for_each_entry_safe(qr, qr_tmp, &conn->response_queue_list,
				qr_list) {
		if (qr->cmd != cmd)
			continue;

		atomic_dec(&qr->cmd->response_queue_count);
		list_del(&qr->qr_list);
		kmem_cache_free(lio_qr_cache, qr);
	}
	spin_unlock_bh(&conn->response_queue_lock);

	if (atomic_read(&cmd->response_queue_count)) {
		printk(KERN_ERR "ITT: 0x%08x response_queue_count: %d\n",
			cmd->init_task_tag,
			atomic_read(&cmd->response_queue_count));
	}
}

void iscsi_remove_cmd_from_tx_queues(struct iscsi_cmd *cmd, struct iscsi_conn *conn)
{
	iscsi_remove_cmd_from_immediate_queue(cmd, conn);
	iscsi_remove_cmd_from_response_queue(cmd, conn);
}

/*	iscsi_free_queue_reqs_for_conn():
 *
 *
 */
void iscsi_free_queue_reqs_for_conn(struct iscsi_conn *conn)
{
	struct iscsi_queue_req *qr, *qr_tmp;

	spin_lock_bh(&conn->immed_queue_lock);
	list_for_each_entry_safe(qr, qr_tmp, &conn->immed_queue_list, qr_list) {
		list_del(&qr->qr_list);
		if (qr->cmd)
			atomic_dec(&qr->cmd->immed_queue_count);

		kmem_cache_free(lio_qr_cache, qr);
	}
	spin_unlock_bh(&conn->immed_queue_lock);

	spin_lock_bh(&conn->response_queue_lock);
	list_for_each_entry_safe(qr, qr_tmp, &conn->response_queue_list,
			qr_list) {
		list_del(&qr->qr_list);
		if (qr->cmd)
			atomic_dec(&qr->cmd->response_queue_count);

		kmem_cache_free(lio_qr_cache, qr);
	}
	spin_unlock_bh(&conn->response_queue_lock);
}

/*	iscsi_release_cmd_direct():
 *
 *
 */
void iscsi_release_cmd_direct(struct iscsi_cmd *cmd)
{
	iscsi_free_r2ts_from_list(cmd);
	iscsi_free_all_datain_reqs(cmd);

	kfree(cmd->buf_ptr);
	kfree(cmd->pdu_list);
	kfree(cmd->seq_list);
	kfree(cmd->tmr_req);

	kmem_cache_free(lio_cmd_cache, cmd);
}

void lio_release_cmd_direct(struct se_cmd *se_cmd)
{
	iscsi_release_cmd_direct((struct iscsi_cmd *)se_cmd->se_fabric_cmd_ptr);
}

/*	__iscsi_release_cmd_to_pool():
 *
 *
 */
void __iscsi_release_cmd_to_pool(struct iscsi_cmd *cmd, struct iscsi_session *sess)
{
	struct iscsi_conn *conn = CONN(cmd);

	iscsi_free_r2ts_from_list(cmd);
	iscsi_free_all_datain_reqs(cmd);

	kfree(cmd->buf_ptr);
	kfree(cmd->pdu_list);
	kfree(cmd->seq_list);
	kfree(cmd->tmr_req);

	if (conn)
		iscsi_remove_cmd_from_tx_queues(cmd, conn);

	kmem_cache_free(lio_cmd_cache, cmd);
}

void iscsi_release_cmd_to_pool(struct iscsi_cmd *cmd)
{
	if (!CONN(cmd) && !cmd->sess) {
#if 0
		printk(KERN_INFO "Releasing cmd: %p ITT: 0x%08x i_state:"
			" 0x%02x, deferred_i_state: 0x%02x directly\n", cmd,
			CMD_TFO(se_cmd)->get_task_tag(se_cmd),
			CMD_TFO(se_cmd)->get_cmd_state(se_cmd),
			cmd->deferred_i_state);
#endif
		iscsi_release_cmd_direct(cmd);
	} else {
		__iscsi_release_cmd_to_pool(cmd, (CONN(cmd)) ?
			CONN(cmd)->sess : cmd->sess);
	}
}

void lio_release_cmd_to_pool(struct se_cmd *se_cmd)
{
	iscsi_release_cmd_to_pool((struct iscsi_cmd *)se_cmd->se_fabric_cmd_ptr);
}

/*	iscsi_pack_lun():
 *
 *	Routine to pack an ordinary (LINUX) LUN 32-bit number
 *		into an 8-byte LUN structure
 *	(see SAM-2, Section 4.12.3 page 39)
 *	Thanks to UNH for help with this :-).
 */
inline u64 iscsi_pack_lun(unsigned int lun)
{
	u64	result;

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

	return cpu_to_le64(result);
}

/*	iscsi_unpack_lun():
 *
 *	Routine to pack an 8-byte LUN structure into a ordinary (LINUX) 32-bit
 *	LUN number (see SAM-2, Section 4.12.3 page 39)
 *	Thanks to UNH for help with this :-).
 */
inline u32 iscsi_unpack_lun(unsigned char *lun_ptr)
{
	u32	result, temp;

	result = *(lun_ptr+1);  /* LSB of lun from byte 1 big-endian */

	switch (temp = ((*lun_ptr)>>6)) { /* high 2 bits of byte 0 big-endian */
	case 0: /* peripheral device addressing method, Sam-2 Section 4.12.5
		-	high-order 2 bits of byte 0 are 00
		-	low-order 6 bits of byte 0 are all 0
		-	all 8 bits of byte 1 are the lun
		-	all other bytes (2 thru 7) are 0
		 */
		if (*lun_ptr != 0) {
			printk(KERN_ERR "Illegal Byte 0 in LUN peripheral"
				" device addressing method %u, expected 0\n",
				*lun_ptr);
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
		printk(KERN_ERR "Unimplemented LUN addressing method %u, "
			"PDA method used instead\n", temp);
		break;
	}

	return result;
}

/*	iscsi_check_session_usage_count():
 *
 *
 */
int iscsi_check_session_usage_count(struct iscsi_session *sess)
{
	spin_lock_bh(&sess->session_usage_lock);
	if (atomic_read(&sess->session_usage_count)) {
#if 0
		printk(KERN_INFO "atomic_read(&sess->session_usage_count):"
			" %d\n", atomic_read(&sess->session_usage_count));
#endif
		atomic_set(&sess->session_waiting_on_uc, 1);
		spin_unlock_bh(&sess->session_usage_lock);
		if (in_interrupt())
			return 2;
#if 0
		printk(KERN_INFO "Before"
				" down(&sess->session_waiting_on_uc_sem);\n");
#endif
		down(&sess->session_waiting_on_uc_sem);
#if 0
		printk(KERN_INFO "After"
			" down(&sess->session_waiting_on_uc_sem);\n");
#endif
		return 1;
	}
	spin_unlock_bh(&sess->session_usage_lock);

	return 0;
}

/*	iscsi_dec_session_usage_count():
 *
 *
 */
void iscsi_dec_session_usage_count(struct iscsi_session *sess)
{
	spin_lock_bh(&sess->session_usage_lock);
	atomic_dec(&sess->session_usage_count);
#if 0
	printk(KERN_INFO "Decremented session_usage_count to %d\n",
		atomic_read(&sess->session_usage_count));
#endif
	if (!atomic_read(&sess->session_usage_count) &&
	     atomic_read(&sess->session_waiting_on_uc))
		up(&sess->session_waiting_on_uc_sem);

	spin_unlock_bh(&sess->session_usage_lock);
}

/*	iscsi_inc_session_usage_count():
 *
 *
 */
void iscsi_inc_session_usage_count(struct iscsi_session *sess)
{
	spin_lock_bh(&sess->session_usage_lock);
	atomic_inc(&sess->session_usage_count);
#if 0
	printk(KERN_INFO "Incremented session_usage_count to %d\n",
		atomic_read(&sess->session_usage_count));
#endif
	spin_unlock_bh(&sess->session_usage_lock);
}

/*	iscsi_determine_sync_and_steering_counts():
 *
 *	Used before iscsi_do[rx,tx]_data() to determine iov and [rx,tx]_marker
 *	array counts needed for sync and steering.
 */
static inline int iscsi_determine_sync_and_steering_counts(
	struct iscsi_conn *conn,
	struct iscsi_data_count *count)
{
	u32 length = count->data_length;
	u32 marker, markint;

	count->sync_and_steering = 1;

	marker = (count->type == ISCSI_RX_DATA) ?
			conn->of_marker : conn->if_marker;
	markint = (count->type == ISCSI_RX_DATA) ?
			(CONN_OPS(conn)->OFMarkInt * 4) :
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

	return 0;
}

/*	iscsi_set_sync_and_steering_values():
 *
 * 	Setup conn->if_marker and conn->of_marker values based upon
 * 	the initial marker-less interval. (see iSCSI v19 A.2)
 */
int iscsi_set_sync_and_steering_values(struct iscsi_conn *conn)
{
	int login_ifmarker_count = 0, login_ofmarker_count = 0, next_marker = 0;
	/*
	 * IFMarkInt and OFMarkInt are negotiated as 32-bit words.
	 */
	u32 IFMarkInt = (CONN_OPS(conn)->IFMarkInt * 4);
	u32 OFMarkInt = (CONN_OPS(conn)->OFMarkInt * 4);

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
		printk(KERN_INFO "Setting OFMarker value to %u based on Initial"
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
		printk(KERN_INFO "Setting IFMarker value to %u based on Initial"
			" Markerless Interval.\n", conn->if_marker);
	}

	return 0;
}

unsigned char *iscsi_ntoa(u32 ip)
{
	static unsigned char buf[18];

	memset((void *) buf, 0, 18);
	sprintf(buf, "%u.%u.%u.%u", ((ip >> 24) & 0xff), ((ip >> 16) & 0xff),
			((ip >> 8) & 0xff), (ip & 0xff));

	return buf;
}

void iscsi_ntoa2(unsigned char *buf, u32 ip)
{
	memset((void *) buf, 0, 18);
	sprintf(buf, "%u.%u.%u.%u", ((ip >> 24) & 0xff), ((ip >> 16) & 0xff),
			((ip >> 8) & 0xff), (ip & 0xff));
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
static const char *iscsi_ntop4(
	const unsigned char *src,
	char *dst,
	size_t size)
{
	static const char *fmt = "%u.%u.%u.%u";
	char tmp[sizeof "255.255.255.255"];
	size_t len;

	len = snprintf(tmp, sizeof tmp, fmt, src[0], src[1], src[2], src[3]);
	if (len >= size) {
		printk(KERN_ERR "len: %d >= size: %d\n", (int)len, (int)size);
		return NULL;
	}
	memcpy(dst, tmp, len + 1);

	return dst;
}

/* const char *
 * isc_inet_ntop6(src, dst, size)
 * convert IPv6 binary address into presentation (printable) format
 * author:
 *	Paul Vixie, 1996.
 */
const char *iscsi_ntop6(const unsigned char *src, char *dst, size_t size)
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
				return NULL;
			tp += strlen(tp);
			break;
		}
		inc = snprintf(tp, 5, "%x", words[i]);
		if (inc < 5)
			return NULL;
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
		printk(KERN_ERR "(size_t)(tp - tmp): %d > size: %d\n",
			(int)(tp - tmp), (int)size);
		return NULL;
	}
	memcpy(dst, tmp, tp - tmp);
	return dst;
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
static int iscsi_pton4(const char *src, unsigned char *dst)
{
	static const char digits[] = "0123456789";
	int saw_digit, octets, ch;
	unsigned char tmp[NS_INADDRSZ], *tp;

	saw_digit = 0;
	octets = 0;
	*(tp = tmp) = 0;
	while ((ch = *src++) != '\0') {
		const char *pch;

		pch = strchr(digits, ch);
		if (pch != NULL) {
			unsigned int new = *tp * 10 + (pch - digits);

			if (new > 255)
				return 0;
			*tp = new;
			if (!saw_digit) {
				if (++octets > 4)
					return 0;
				saw_digit = 1;
			}
		} else if (ch == '.' && saw_digit) {
			if (octets == 4)
				return 0;
			*++tp = 0;
			saw_digit = 0;
		} else
			return 0;
	}
	if (octets < 4)
		return 0;
	memcpy(dst, tmp, NS_INADDRSZ);
	return 1;
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
int iscsi_pton6(const char *src, unsigned char *dst)
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
			return 0;
	curtok = src;
	saw_xdigit = 0;
	val = 0;
	while ((ch = *src++) != '\0') {
		const char *pch;

		pch = strchr((xdigits = xdigits_l), ch);
		if (pch == NULL)
			pch = strchr((xdigits = xdigits_u), ch);
		if (pch != NULL) {
			val <<= 4;
			val |= (pch - xdigits);
			if (val > 0xffff)
				return 0;
			saw_xdigit = 1;
			continue;
		}
		if (ch == ':') {
			curtok = src;
			if (!saw_xdigit) {
				if (colonp)
					return 0;
				colonp = tp;
				continue;
			}
			if (tp + NS_INT16SZ > endp)
				return 0;
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
		return 0;
	}
	if (saw_xdigit) {
		if (tp + NS_INT16SZ > endp)
			return 0;
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
			endp[-i] = colonp[n - i];
			colonp[n - i] = 0;
		}
		tp = endp;
	}
	if (tp != endp)
		return 0;
	memcpy(dst, tmp, NS_IN6ADDRSZ);
	return 1;
}

/*	iscsi_get_conn_from_cid():
 *
 *
 */
struct iscsi_conn *iscsi_get_conn_from_cid(struct iscsi_session *sess, u16 cid)
{
	struct iscsi_conn *conn;

	spin_lock_bh(&sess->conn_lock);
	list_for_each_entry(conn, &sess->sess_conn_list, conn_list) {
		if ((conn->cid == cid) &&
		    (conn->conn_state == TARG_CONN_STATE_LOGGED_IN)) {
			iscsi_inc_conn_usage_count(conn);
			spin_unlock_bh(&sess->conn_lock);
			return conn;
		}
	}
	spin_unlock_bh(&sess->conn_lock);

	return NULL;
}

/*	iscsi_get_conn_from_cid_rcfr():
 *
 *
 */
struct iscsi_conn *iscsi_get_conn_from_cid_rcfr(struct iscsi_session *sess, u16 cid)
{
	struct iscsi_conn *conn;

	spin_lock_bh(&sess->conn_lock);
	list_for_each_entry(conn, &sess->sess_conn_list, conn_list) {
		if (conn->cid == cid) {
			iscsi_inc_conn_usage_count(conn);
			spin_lock(&conn->state_lock);
			atomic_set(&conn->connection_wait_rcfr, 1);
			spin_unlock(&conn->state_lock);
			spin_unlock_bh(&sess->conn_lock);
			return conn;
		}
	}
	spin_unlock_bh(&sess->conn_lock);

	return NULL;
}

/*	iscsi_check_conn_usage_count():
 *
 *
 */
void iscsi_check_conn_usage_count(struct iscsi_conn *conn)
{
	spin_lock_bh(&conn->conn_usage_lock);
#if 0
	printk(KERN_INFO "atomic_read(&conn->conn_usage_count): %d for CID:"
		" %hu\n", atomic_read(&conn->conn_usage_count), conn->cid);
#endif
	if (atomic_read(&conn->conn_usage_count)) {
		atomic_set(&conn->conn_waiting_on_uc, 1);
		spin_unlock_bh(&conn->conn_usage_lock);
#if 0
		printk(KERN_INFO "Before down(&conn->conn_waiting_on_uc_sem);"
				" for CID: %hu\n", conn->cid);
#endif
		down(&conn->conn_waiting_on_uc_sem);
#if 0
		printk(KERN_INFO "After down(&conn->conn_waiting_on_uc_sem);"
				" for CID: %hu\n", conn->cid);
#endif
		return;
	}
	spin_unlock_bh(&conn->conn_usage_lock);
}

/*	iscsi_dec_conn_usage_count():
 *
 *
 */
void iscsi_dec_conn_usage_count(struct iscsi_conn *conn)
{
	spin_lock_bh(&conn->conn_usage_lock);
	atomic_dec(&conn->conn_usage_count);
#if 0
	printk(KERN_INFO "Decremented conn_usage_count to %d for CID: %hu\n",
		atomic_read(&conn->conn_usage_count), conn->cid);
#endif
	if (!atomic_read(&conn->conn_usage_count) &&
	     atomic_read(&conn->conn_waiting_on_uc))
		up(&conn->conn_waiting_on_uc_sem);

	spin_unlock_bh(&conn->conn_usage_lock);
}

/*	iscsi_inc_conn_usage_count():
 *
 *
 */
void iscsi_inc_conn_usage_count(struct iscsi_conn *conn)
{
	spin_lock_bh(&conn->conn_usage_lock);
	atomic_inc(&conn->conn_usage_count);
#if 0
	printk(KERN_INFO "Incremented conn_usage_count to %d for CID: %hu\n",
		atomic_read(&conn->conn_usage_count), conn->cid);
#endif
	spin_unlock_bh(&conn->conn_usage_lock);
}

/*	iscsi_async_msg_timer_function():
 *
 *
 */
void iscsi_async_msg_timer_function(unsigned long data)
{
	up((struct semaphore *) data);
}

/*	Riscsi_check_for_active_network_device():
 *
 *
 */
int iscsi_check_for_active_network_device(struct iscsi_conn *conn)
{
	struct net_device *net_dev;

	if (!conn->net_if) {
		printk(KERN_ERR "struct iscsi_conn->net_if is NULL for CID:"
			" %hu\n", conn->cid);
		return 0;
	}
	net_dev = conn->net_if;

	return netif_carrier_ok(net_dev);
}

/*	iscsi_handle_netif_timeou():
 *
 *
 */
static void iscsi_handle_netif_timeout(unsigned long data)
{
	struct iscsi_conn *conn = (struct iscsi_conn *) data;

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

	printk(KERN_ERR "Detected PHY loss on Network Interface: %s for iSCSI"
		" CID: %hu on SID: %u\n", conn->net_dev, conn->cid,
			SESS(conn)->sid);

	spin_unlock_bh(&conn->netif_lock);

	iscsi_cause_connection_reinstatement(conn, 0);
	iscsi_dec_conn_usage_count(conn);
}

/*	iscsi_get_network_interface_from_conn():
 *
 *
 */
void iscsi_get_network_interface_from_conn(struct iscsi_conn *conn)
{
	struct net_device *net_dev;

	net_dev = dev_get_by_name(&init_net, conn->net_dev);
	if (!(net_dev)) {
		printk(KERN_ERR "Unable to locate active network interface:"
			" %s\n", strlen(conn->net_dev) ?
			conn->net_dev : "None");
		conn->net_if = NULL;
		return;
	}

	conn->net_if = net_dev;
}

/*      iscsi_start_netif_timer():
 *
 *	Called with conn->netif_lock held.
 */
void iscsi_start_netif_timer(struct iscsi_conn *conn)
{
	struct iscsi_portal_group *tpg = ISCSI_TPG_C(conn);

	if (!conn->net_if)
		return;

	if (conn->netif_timer_flags & NETIF_TF_RUNNING)
		return;

	init_timer(&conn->transport_timer);
	SETUP_TIMER(conn->transport_timer, ISCSI_TPG_ATTRIB(tpg)->netif_timeout,
		conn, iscsi_handle_netif_timeout);
	conn->netif_timer_flags &= ~NETIF_TF_STOP;
	conn->netif_timer_flags |= NETIF_TF_RUNNING;
	add_timer(&conn->transport_timer);
}

/*	iscsi_stop_netif_timer():
 *
 *
 */
void iscsi_stop_netif_timer(struct iscsi_conn *conn)
{
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
	spin_unlock_bh(&conn->netif_lock);
}

/*	iscsi_handle_nopin_response_timeout():
 *
 *
 */
static void iscsi_handle_nopin_response_timeout(unsigned long data)
{
	struct iscsi_conn *conn = (struct iscsi_conn *) data;

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
	struct iscsi_portal_group *tpg = conn->sess->tpg;
	struct iscsi_tiqn *tiqn = tpg->tpg_tiqn;

	if (tiqn) {
		spin_lock_bh(&tiqn->sess_err_stats.lock);
		strcpy(tiqn->sess_err_stats.last_sess_fail_rem_name,
				(void *)SESS_OPS_C(conn)->InitiatorName);
		tiqn->sess_err_stats.last_sess_failure_type =
				ISCSI_SESS_ERR_CXN_TIMEOUT;
		tiqn->sess_err_stats.cxn_timeout_errors++;
		SESS(conn)->conn_timeout_errors++;
		spin_unlock_bh(&tiqn->sess_err_stats.lock);
	}
	}
#endif /* SNMP_SUPPORT */

	iscsi_cause_connection_reinstatement(conn, 0);
	iscsi_dec_conn_usage_count(conn);
}

/*	iscsi_mod_nopin_response_timer():
 *
 *
 */
void iscsi_mod_nopin_response_timer(struct iscsi_conn *conn)
{
	struct iscsi_session *sess = SESS(conn);
	struct iscsi_node_attrib *na = iscsi_tpg_get_node_attrib(sess);

	spin_lock_bh(&conn->nopin_timer_lock);
	if (!(conn->nopin_response_timer_flags & NOPIN_RESPONSE_TF_RUNNING)) {
		spin_unlock_bh(&conn->nopin_timer_lock);
		return;
	}

	MOD_TIMER(&conn->nopin_response_timer, na->nopin_response_timeout);
	spin_unlock_bh(&conn->nopin_timer_lock);
}

/*	iscsi_start_nopin_response_timer():
 *
 *	Called with conn->nopin_timer_lock held.
 */
void iscsi_start_nopin_response_timer(struct iscsi_conn *conn)
{
	struct iscsi_session *sess = SESS(conn);
	struct iscsi_node_attrib *na = iscsi_tpg_get_node_attrib(sess);

	spin_lock_bh(&conn->nopin_timer_lock);
	if (conn->nopin_response_timer_flags & NOPIN_RESPONSE_TF_RUNNING) {
		spin_unlock_bh(&conn->nopin_timer_lock);
		return;
	}

	init_timer(&conn->nopin_response_timer);
	SETUP_TIMER(conn->nopin_response_timer, na->nopin_response_timeout,
		conn, iscsi_handle_nopin_response_timeout);
	conn->nopin_response_timer_flags &= ~NOPIN_RESPONSE_TF_STOP;
	conn->nopin_response_timer_flags |= NOPIN_RESPONSE_TF_RUNNING;
	add_timer(&conn->nopin_response_timer);

	TRACE(TRACE_TIMER, "Started NOPIN Response Timer on CID: %d to %u"
		" seconds\n", conn->cid, na->nopin_response_timeout);
	spin_unlock_bh(&conn->nopin_timer_lock);
}

/*	iscsi_stop_nopin_response_timer():
 *
 *
 */
void iscsi_stop_nopin_response_timer(struct iscsi_conn *conn)
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
	spin_unlock_bh(&conn->nopin_timer_lock);
}

/*	iscsi_handle_nopin_timeout():
 *
 *
 */
static void iscsi_handle_nopin_timeout(unsigned long data)
{
	struct iscsi_conn *conn = (struct iscsi_conn *) data;

	iscsi_inc_conn_usage_count(conn);

	spin_lock_bh(&conn->nopin_timer_lock);
	if (conn->nopin_timer_flags & NOPIN_TF_STOP) {
		spin_unlock_bh(&conn->nopin_timer_lock);
		iscsi_dec_conn_usage_count(conn);
		return;
	}
	conn->nopin_timer_flags &= ~NOPIN_TF_RUNNING;
	spin_unlock_bh(&conn->nopin_timer_lock);

	iscsi_add_nopin(conn, 1);
	iscsi_dec_conn_usage_count(conn);
}

/*
 * Called with conn->nopin_timer_lock held.
 */
void __iscsi_start_nopin_timer(struct iscsi_conn *conn)
{
	struct iscsi_session *sess = SESS(conn);
	struct iscsi_node_attrib *na = iscsi_tpg_get_node_attrib(sess);
	/*
	* NOPIN timeout is disabled.
	 */
	if (!(na->nopin_timeout))
		return;

	if (conn->nopin_timer_flags & NOPIN_TF_RUNNING)
		return;

	init_timer(&conn->nopin_timer);
	SETUP_TIMER(conn->nopin_timer, na->nopin_timeout, conn,
		iscsi_handle_nopin_timeout);
	conn->nopin_timer_flags &= ~NOPIN_TF_STOP;
	conn->nopin_timer_flags |= NOPIN_TF_RUNNING;
	add_timer(&conn->nopin_timer);

	TRACE(TRACE_TIMER, "Started NOPIN Timer on CID: %d at %u second"
		" interval\n", conn->cid, na->nopin_timeout);
}

/*	iscsi_start_nopin_timer():
 *
 *
 */
void iscsi_start_nopin_timer(struct iscsi_conn *conn)
{
	struct iscsi_session *sess = SESS(conn);
	struct iscsi_node_attrib *na = iscsi_tpg_get_node_attrib(sess);
	/*
	 * NOPIN timeout is disabled..
	 */
	if (!(na->nopin_timeout))
		return;

	spin_lock_bh(&conn->nopin_timer_lock);
	if (conn->nopin_timer_flags & NOPIN_TF_RUNNING) {
		spin_unlock_bh(&conn->nopin_timer_lock);
		return;
	}

	init_timer(&conn->nopin_timer);
	SETUP_TIMER(conn->nopin_timer, na->nopin_timeout, conn,
			iscsi_handle_nopin_timeout);
	conn->nopin_timer_flags &= ~NOPIN_TF_STOP;
	conn->nopin_timer_flags |= NOPIN_TF_RUNNING;
	add_timer(&conn->nopin_timer);

	TRACE(TRACE_TIMER, "Started NOPIN Timer on CID: %d at %u second"
			" interval\n", conn->cid, na->nopin_timeout);
	spin_unlock_bh(&conn->nopin_timer_lock);
}

/*	iscsi_stop_nopin_timer():
 *
 *
 */
void iscsi_stop_nopin_timer(struct iscsi_conn *conn)
{
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
	spin_unlock_bh(&conn->nopin_timer_lock);
}

/*	iscsi_send_tx_data():
 *
 *
 */
int iscsi_send_tx_data(
	struct iscsi_cmd *cmd,
	struct iscsi_conn *conn,
	int use_misc)
{
	int tx_sent, tx_size;
	u32 iov_count;
	struct iovec *iov;

send_data:
	tx_size = cmd->tx_size;

	if (!use_misc) {
		iov = &SE_CMD(cmd)->iov_data[0];
		iov_count = SE_CMD(cmd)->iov_data_count;
	} else {
		iov = &cmd->iov_misc[0];
		iov_count = cmd->iov_misc_count;
	}

	tx_sent = tx_data(conn, &iov[0], iov_count, tx_size);
	if (tx_size != tx_sent) {
		if (tx_sent == -EAGAIN) {
			printk(KERN_ERR "tx_data() returned -EAGAIN\n");
			goto send_data;
		} else
			return -1;
	}
	cmd->tx_size = 0;

	return 0;
}

int iscsi_fe_sendpage_sg(
	struct se_unmap_sg *u_sg,
	struct iscsi_conn *conn)
{
	int tx_sent;
	struct iscsi_cmd *cmd = (struct iscsi_cmd *)u_sg->fabric_cmd;
	struct se_cmd *se_cmd = SE_CMD(cmd);
	u32 len = cmd->tx_size, pg_len, se_len, se_off, tx_size;
	struct iovec *iov = &se_cmd->iov_data[0];
	struct page *page;
	struct se_mem *se_mem = u_sg->cur_se_mem;

send_hdr:
	tx_size = (CONN_OPS(conn)->HeaderDigest) ? ISCSI_HDR_LEN + CRC_LEN :
			ISCSI_HDR_LEN;
	tx_sent = tx_data(conn, iov, 1, tx_size);
	if (tx_size != tx_sent) {
		if (tx_sent == -EAGAIN) {
			printk(KERN_ERR "tx_data() returned -EAGAIN\n");
			goto send_hdr;
		}
		return -1;
	}

	len -= tx_size;
	len -= u_sg->padding;
	if (CONN_OPS(conn)->DataDigest)
		len -= CRC_LEN;

	/*
	 * Start calculating from the first page of current struct se_mem.
	 */
	page = se_mem->se_page;
	pg_len = (PAGE_SIZE - se_mem->se_off);
	se_len = se_mem->se_len;
	if (se_len < pg_len)
		pg_len = se_len;
	se_off = se_mem->se_off;
#if 0
	printk(KERN_INFO "se: %p page: %p se_len: %d se_off: %d pg_len: %d\n",
		se_mem, page, se_len, se_off, pg_len);
#endif
	/*
	 * Calucate new se_len and se_off based upon u_sg->t_offset into
	 * the current struct se_mem and possibily a different page.
	 */
	while (u_sg->t_offset) {
#if 0
		printk(KERN_INFO "u_sg->t_offset: %d, page: %p se_len: %d"
			" se_off: %d pg_len: %d\n", u_sg->t_offset, page,
			se_len, se_off, pg_len);
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
	 * Perform sendpage() for each page in the struct se_mem
	 */
	while (len) {
#if 0
		printk(KERN_INFO "len: %d page: %p se_len: %d se_off: %d\n",
			len, page, se_len, se_off);
#endif
		if (se_len > len)
			se_len = len;
send_pg:
		tx_sent = conn->sock->ops->sendpage(conn->sock,
				page, se_off, se_len, 0);
		if (tx_sent != se_len) {
			if (tx_sent == -EAGAIN) {
				printk(KERN_ERR "tcp_sendpage() returned"
						" -EAGAIN\n");
				goto send_pg;
			}

			printk(KERN_ERR "tcp_sendpage() failure: %d\n",
					tx_sent);
			return -1;
		}

		len -= se_len;
		if (!(len))
			break;

		se_len -= tx_sent;
		if (!(se_len)) {
			list_for_each_entry_continue(se_mem,
					T_TASK(se_cmd)->t_mem_list, se_list)
				break;

			if (!se_mem) {
				printk(KERN_ERR "Unable to locate next struct se_mem\n");
				return -1;
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
		struct iovec *iov_p =
			&se_cmd->iov_data[se_cmd->iov_data_count-2];

		tx_sent = tx_data(conn, iov_p, 1, u_sg->padding);
		if (u_sg->padding != tx_sent) {
			if (tx_sent == -EAGAIN) {
				printk(KERN_ERR "tx_data() returned -EAGAIN\n");
				goto send_padding;
			}
			return -1;
		}
	}

send_datacrc:
	if (CONN_OPS(conn)->DataDigest) {
		struct iovec *iov_d =
			&se_cmd->iov_data[se_cmd->iov_data_count-1];

		tx_sent = tx_data(conn, iov_d, 1, CRC_LEN);
		if (CRC_LEN != tx_sent) {
			if (tx_sent == -EAGAIN) {
				printk(KERN_ERR "tx_data() returned -EAGAIN\n");
				goto send_datacrc;
			}
			return -1;
		}
	}

	return 0;
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
int iscsi_tx_login_rsp(struct iscsi_conn *conn, u8 status_class, u8 status_detail)
{
	u8 iscsi_hdr[ISCSI_HDR_LEN];
	int err;
	struct iovec iov;
	struct iscsi_targ_login_rsp *hdr;

#ifdef SNMP_SUPPORT
	iscsi_collect_login_stats(conn, status_class, status_detail);
#endif

	memset((void *)&iov, 0, sizeof(struct iovec));
	memset((void *)&iscsi_hdr, 0x0, ISCSI_HDR_LEN);

	hdr	= (struct iscsi_targ_login_rsp *)&iscsi_hdr;
	hdr->opcode		= ISCSI_TARG_LOGIN_RSP;
	hdr->status_class	= status_class;
	hdr->status_detail	= status_detail;
	hdr->init_task_tag	= cpu_to_be32(conn->login_itt);

	iov.iov_base		= &iscsi_hdr;
	iov.iov_len		= ISCSI_HDR_LEN;

	PRINT_BUFF(iscsi_hdr, ISCSI_HDR_LEN);

	err = tx_data(conn, &iov, 1, ISCSI_HDR_LEN);
	if (err != ISCSI_HDR_LEN) {
		printk(KERN_ERR "tx_data returned less than expected\n");
		return -1;
	}

	return 0;
}

/*	iscsi_print_session_params():
 *
 *
 */
void iscsi_print_session_params(struct iscsi_session *sess)
{
	struct iscsi_conn *conn;

	printk(KERN_INFO "-----------------------------[Session Params for"
		" SID: %u]-----------------------------\n", sess->sid);
	spin_lock_bh(&sess->conn_lock);
	list_for_each_entry(conn, &sess->sess_conn_list, conn_list)
		iscsi_dump_conn_ops(conn->conn_ops);
	spin_unlock_bh(&sess->conn_lock);

	iscsi_dump_sess_ops(sess->sess_ops);
}

/*	iscsi_do_rx_data():
 *
 *
 */
static inline int iscsi_do_rx_data(
	struct iscsi_conn *conn,
	struct iscsi_data_count *count)
{
	int data = count->data_length, rx_loop = 0, total_rx = 0;
	u32 rx_marker_val[count->ss_marker_count], rx_marker_iov = 0;
	struct iovec iov[count->ss_iov_count];
	mm_segment_t oldfs;
	struct msghdr msg;

	if (!conn || !conn->sock || !CONN_OPS(conn))
		return -1;

	memset(&msg, 0, sizeof(struct msghdr));

	if (count->sync_and_steering) {
		int size = 0;
		u32 i, orig_iov_count = 0;
		u32 orig_iov_len = 0, orig_iov_loc = 0;
		u32 iov_count = 0, per_iov_bytes = 0;
		u32 *rx_marker, old_rx_marker = 0;
		struct iovec *iov_record;

		memset((void *)&rx_marker_val, 0,
				count->ss_marker_count * sizeof(u32));
		memset((void *)&iov, 0,
				count->ss_iov_count * sizeof(struct iovec));

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
			printk(KERN_ERR "iov_count: %d, count->ss_iov_count:"
				" %d\n", iov_count, count->ss_iov_count);
			return -1;
		}
		if (rx_marker_iov > count->ss_marker_count) {
			printk(KERN_ERR "rx_marker_iov: %d, count->ss_marker"
				"_count: %d\n", rx_marker_iov,
				count->ss_marker_count);
			return -1;
		}
	} else {
		msg.msg_iov	= count->iov;
		msg.msg_iovlen	= count->iov_count;
	}

	while (total_rx < data) {
		oldfs = get_fs();
		set_fs(get_ds());

		conn->sock->sk->sk_allocation = GFP_ATOMIC;
		rx_loop = sock_recvmsg(conn->sock, &msg,
				(data - total_rx), MSG_WAITALL);

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

	return total_rx;
}

/*	iscsi_do_tx_data():
 *
 *
 */
static inline int iscsi_do_tx_data(
	struct iscsi_conn *conn,
	struct iscsi_data_count *count)
{
	int data = count->data_length, total_tx = 0, tx_loop = 0;
	u32 tx_marker_val[count->ss_marker_count], tx_marker_iov = 0;
	struct iovec iov[count->ss_iov_count];
	mm_segment_t oldfs;
	struct msghdr msg;

	if (!conn || !conn->sock || !CONN_OPS(conn))
		return -1;

	if (data <= 0) {
		printk(KERN_ERR "Data length is: %d\n", data);
		return -1;
	}

	memset(&msg, 0, sizeof(struct msghdr));

	if (count->sync_and_steering) {
		int size = 0;
		u32 i, orig_iov_count = 0;
		u32 orig_iov_len = 0, orig_iov_loc = 0;
		u32 iov_count = 0, per_iov_bytes = 0;
		u32 *tx_marker, old_tx_marker = 0;
		struct iovec *iov_record;

		memset((void *)&tx_marker_val, 0,
			count->ss_marker_count * sizeof(u32));
		memset((void *)&iov, 0,
			count->ss_iov_count * sizeof(struct iovec));

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
			printk(KERN_ERR "iov_count: %d, count->ss_iov_count:"
				" %d\n", iov_count, count->ss_iov_count);
			return -1;
		}
		if (tx_marker_iov > count->ss_marker_count) {
			printk(KERN_ERR "tx_marker_iov: %d, count->ss_marker"
				"_count: %d\n", tx_marker_iov,
				count->ss_marker_count);
			return -1;
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
			return tx_loop;
		}
		total_tx += tx_loop;
		TRACE(TRACE_NET, "tx_loop: %d, total_tx: %d, data: %d\n",
					tx_loop, total_tx, data);
	}

	if (count->sync_and_steering)
		total_tx -= (tx_marker_iov * (MARKER_SIZE / 2));

	return total_tx;
}

/*	rx_data():
 *
 *
 */
int rx_data(
	struct iscsi_conn *conn,
	struct iovec *iov,
	int iov_count,
	int data)
{
	struct iscsi_data_count c;

	if (!conn || !conn->sock || !CONN_OPS(conn))
		return -1;

	memset(&c, 0, sizeof(struct iscsi_data_count));
	c.iov = iov;
	c.iov_count = iov_count;
	c.data_length = data;
	c.type = ISCSI_RX_DATA;

	if (CONN_OPS(conn)->OFMarker &&
	   (conn->conn_state >= TARG_CONN_STATE_LOGGED_IN)) {
		if (iscsi_determine_sync_and_steering_counts(conn, &c) < 0)
			return -1;
	}

	return iscsi_do_rx_data(conn, &c);
}

/*	tx_data():
 *
 *
 */
int tx_data(
	struct iscsi_conn *conn,
	struct iovec *iov,
	int iov_count,
	int data)
{
	struct iscsi_data_count c;

	if (!conn || !conn->sock || !CONN_OPS(conn))
		return -1;

	memset(&c, 0, sizeof(struct iscsi_data_count));
	c.iov = iov;
	c.iov_count = iov_count;
	c.data_length = data;
	c.type = ISCSI_TX_DATA;

	if (CONN_OPS(conn)->IFMarker &&
	   (conn->conn_state >= TARG_CONN_STATE_LOGGED_IN)) {
		if (iscsi_determine_sync_and_steering_counts(conn, &c) < 0)
			return -1;
	}

	return iscsi_do_tx_data(conn, &c);
}

#ifdef SNMP_SUPPORT
/*
 * Collect login statistics
 */
void iscsi_collect_login_stats(
	struct iscsi_conn *conn,
	u8 status_class,
	u8 status_detail)
{
	struct iscsi_param *intrname = NULL;
	struct iscsi_tiqn *tiqn;
	struct iscsi_login_stats *ls;

	tiqn = iscsi_snmp_get_tiqn(conn);
	if (!(tiqn))
		return;

	ls = &tiqn->login_stats;

	spin_lock(&ls->lock);
	if (((conn->login_ip == ls->last_intr_fail_addr) ||
	    !(memcmp(conn->ipv6_login_ip, ls->last_intr_fail_ip6_addr,
		IPV6_ADDRESS_SPACE))) &&
	    ((get_jiffies_64() - ls->last_fail_time) < 10)) {
		/* We already have the failure info for this login */
		spin_unlock(&ls->lock);
		return;
	}

	if (status_class == STAT_CLASS_SUCCESS)
		ls->accepts++;
	else if (status_class == STAT_CLASS_REDIRECTION) {
		ls->redirects++;
		ls->last_fail_type = ISCSI_LOGIN_FAIL_REDIRECT;
	} else if ((status_class == STAT_CLASS_INITIATOR)  &&
		 (status_detail == STAT_DETAIL_NOT_AUTH)) {
		ls->authenticate_fails++;
		ls->last_fail_type =  ISCSI_LOGIN_FAIL_AUTHENTICATE;
	} else if ((status_class == STAT_CLASS_INITIATOR)  &&
		 (status_detail == STAT_DETAIL_NOT_ALLOWED)) {
		ls->authorize_fails++;
		ls->last_fail_type = ISCSI_LOGIN_FAIL_AUTHORIZE;
	} else if ((status_class == STAT_CLASS_INITIATOR)  &&
		 (status_detail == STAT_DETAIL_INIT_ERROR)) {
		ls->negotiate_fails++;
		ls->last_fail_type = ISCSI_LOGIN_FAIL_NEGOTIATE;
	} else {
		ls->other_fails++;
		ls->last_fail_type = ISCSI_LOGIN_FAIL_OTHER;
	}

	/* Save initiator name, ip address and time, if it is a failed login */
	if (status_class != STAT_CLASS_SUCCESS) {
		if (conn->param_list)
			intrname = iscsi_find_param_from_key(INITIATORNAME,
							     conn->param_list);
		strcpy(ls->last_intr_fail_name,
		       (intrname ? intrname->value : "Unknown"));

		if (conn->ipv6_login_ip != NULL) {
			memcpy(ls->last_intr_fail_ip6_addr,
				conn->ipv6_login_ip, IPV6_ADDRESS_SPACE);
			ls->last_intr_fail_addr = 0;
		} else {
			memset(ls->last_intr_fail_ip6_addr, 0,
				IPV6_ADDRESS_SPACE);
			ls->last_intr_fail_addr = conn->login_ip;
		}
		ls->last_fail_time = get_jiffies_64();
	}

	spin_unlock(&ls->lock);
}

struct iscsi_tiqn *iscsi_snmp_get_tiqn(struct iscsi_conn *conn)
{
	struct iscsi_portal_group *tpg;

	if (!(conn) || !(conn->sess))
		return NULL;

	tpg = conn->sess->tpg;
	if (!(tpg))
		return NULL;

	if (!(tpg->tpg_tiqn))
		return NULL;

	return tpg->tpg_tiqn;
}
#endif /* SNMP_SUPPORT */
