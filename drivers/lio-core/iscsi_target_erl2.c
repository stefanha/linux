/*********************************************************************************
 * Filename:  iscsi_target_erl2.c
 *
 * This file contains error recovery level two functions used by
 * the iSCSI Target driver.
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


#define ISCSI_TARGET_ERL2_C

#include <linux/net.h>
#include <linux/string.h>
#include <linux/timer.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/smp_lock.h>
#include <linux/in.h>
#include <net/sock.h>
#include <net/tcp.h>

#include <iscsi_linux_os.h>
#include <iscsi_linux_defs.h>

#include <iscsi_protocol.h>
#include <iscsi_debug_opcodes.h>
#include <iscsi_crc.h>
#include <iscsi_debug.h>
#include <iscsi_lists.h>
#include <iscsi_target_core.h>
#include <iscsi_target_datain_values.h>
#include <iscsi_target_ioctl.h>
#include <iscsi_target_transport.h>
#include <iscsi_target_util.h>
#include <iscsi_target_erl0.h>
#include <iscsi_target_erl1.h>
#include <iscsi_target_erl2.h> 

#undef ISCSI_TARGET_ERL2_C

extern se_global_t *iscsi_global;
extern int iscsi_send_async_msg (iscsi_conn_t *, __u16, __u8, __u8);
extern int iscsi_close_connection (iscsi_conn_t *);

/*	iscsi_create_conn_recovery_datain_values():
 *
 *	FIXME: Does RData SNACK apply here as well?
 */
extern void iscsi_create_conn_recovery_datain_values (
	iscsi_cmd_t *cmd,
	__u32 exp_data_sn)
{
	__u32 data_sn = 0;
	iscsi_conn_t *conn = CONN(cmd);
	
	cmd->next_burst_len = 0;
	cmd->read_data_done = 0;
		
	while (exp_data_sn > data_sn) {
		if ((cmd->next_burst_len +
		     CONN_OPS(conn)->MaxRecvDataSegmentLength) <
		     SESS_OPS_C(conn)->MaxBurstLength) {
			cmd->read_data_done +=
			       CONN_OPS(conn)->MaxRecvDataSegmentLength;
			cmd->next_burst_len +=
			       CONN_OPS(conn)->MaxRecvDataSegmentLength;
		} else {
			cmd->read_data_done +=
				(SESS_OPS_C(conn)->MaxBurstLength -
				 	cmd->next_burst_len);
			cmd->next_burst_len = 0;
		}
		data_sn++;
	}

	return;
}

/*	iscsi_create_conn_recovery_dataout_values():
 *
 *
 */
extern void iscsi_create_conn_recovery_dataout_values (
	iscsi_cmd_t *cmd)
{
	__u32 write_data_done = 0;
	iscsi_conn_t *conn = CONN(cmd);

	cmd->data_sn = 0;
	cmd->next_burst_len = 0;

	while (cmd->write_data_done > write_data_done) {
		if ((write_data_done + SESS_OPS_C(conn)->MaxBurstLength) <=
		     cmd->write_data_done)
			write_data_done += SESS_OPS_C(conn)->MaxBurstLength;
		else
			break;
	}
	
	cmd->write_data_done = write_data_done;
	
	return;
}

/*	iscsi_attach_active_connection_recovery_entry():
 *
 *
 */
static int iscsi_attach_active_connection_recovery_entry (
	iscsi_session_t *sess,
	iscsi_conn_recovery_t *cr)
{
	spin_lock(&sess->cr_a_lock);
	ADD_ENTRY_TO_LIST(cr, sess->cr_a_head, sess->cr_a_tail);
	spin_unlock(&sess->cr_a_lock);

	return(0);
}

/*	iscsi_attach_inactive_connection_recovery():
 *
 *
 */
static int iscsi_attach_inactive_connection_recovery_entry (
	iscsi_session_t *sess,
	iscsi_conn_recovery_t *cr)
{
	spin_lock(&sess->cr_i_lock);
	ADD_ENTRY_TO_LIST(cr, sess->cr_i_head, sess->cr_i_tail);

	sess->conn_recovery_count++;
	TRACE(TRACE_ERL2, "Incremented connection recovery count to %u for"
		" SID: %u\n", sess->conn_recovery_count, sess->sid);
	spin_unlock(&sess->cr_i_lock);
		
	return(0);
}

/*	iscsi_get_inactive_connection_recovery_entry():
 *
 *
 */
extern iscsi_conn_recovery_t *iscsi_get_inactive_connection_recovery_entry (
	iscsi_session_t *sess,
	__u16 cid)
{
	iscsi_conn_recovery_t *cr;

	spin_lock(&sess->cr_i_lock);
	for (cr = sess->cr_i_head; cr; cr = cr->next) {
		if (cr->cid == cid)
			break;
	}
	spin_unlock(&sess->cr_i_lock);

	return((cr) ? cr : NULL);
}

/*	iscsi_free_connection_recovery_entires():
 *
 *
 */
extern void iscsi_free_connection_recovery_entires (iscsi_session_t *sess)
{
	iscsi_cmd_t *cmd, *cmd_next;
	iscsi_conn_recovery_t *cr, *cr_next;
	
	spin_lock(&sess->cr_a_lock);
	cr = sess->cr_a_head;
	while (cr) {
		cr_next = cr->next;

		spin_unlock(&sess->cr_a_lock);
		spin_lock(&cr->conn_recovery_cmd_lock);
		cmd = cr->conn_recovery_cmd_head;
		while (cmd) {
			cmd_next = cmd->i_next;
		
			cmd->conn = NULL;
			spin_unlock(&cr->conn_recovery_cmd_lock);
			if (!(cmd->cmd_flags & ICF_SE_LUN_CMD) || !cmd->transport_wait_for_tasks)
				iscsi_release_cmd_to_pool(cmd, sess);
			else
				cmd->transport_wait_for_tasks(cmd, 1, 1);
			spin_lock(&cr->conn_recovery_cmd_lock);
			
			cmd = cmd_next;
		}
		spin_unlock(&cr->conn_recovery_cmd_lock);
		spin_lock(&sess->cr_a_lock);

		kfree(cr);
		
		cr = cr_next;
	}
	spin_unlock(&sess->cr_a_lock);

	spin_lock(&sess->cr_i_lock);
	cr = sess->cr_i_head;
	while (cr) {
		cr_next = cr->next;

		spin_unlock(&sess->cr_i_lock);
		spin_lock(&cr->conn_recovery_cmd_lock);
		cmd = cr->conn_recovery_cmd_head;
		while (cmd) {
			cmd_next = cmd->i_next;

			cmd->conn = NULL;
			spin_unlock(&cr->conn_recovery_cmd_lock);
			if (!(cmd->cmd_flags & ICF_SE_LUN_CMD) || !cmd->transport_wait_for_tasks)
				iscsi_release_cmd_to_pool(cmd, sess);
			else
				cmd->transport_wait_for_tasks(cmd, 1, 1);
			spin_lock(&cr->conn_recovery_cmd_lock);

			cmd = cmd_next;
		}
		spin_unlock(&cr->conn_recovery_cmd_lock);
		spin_lock(&sess->cr_i_lock);

		kfree(cr);

		cr = cr_next;
	}
	spin_unlock(&sess->cr_i_lock);

	return;
}

/*	iscsi_remove_active_connection_recovery_entry():
 *
 *
 */
extern int iscsi_remove_active_connection_recovery_entry (
	iscsi_conn_recovery_t *cr,
	iscsi_session_t *sess)
{
	spin_lock(&sess->cr_a_lock);
	REMOVE_ENTRY_FROM_LIST(cr, sess->cr_a_head, sess->cr_a_tail);

	sess->conn_recovery_count--;
	TRACE(TRACE_ERL2, "Decremented connection recovery count to %u for"
		" SID: %u\n", sess->conn_recovery_count, sess->sid);
	spin_unlock(&sess->cr_a_lock);
			
	kfree(cr);

	return(0);
}

/*	iscsi_remove_inactive_connection_recovery_entry():
 *
 *
 */
extern int iscsi_remove_inactive_connection_recovery_entry (
	iscsi_conn_recovery_t *cr,
	iscsi_session_t *sess)
{
	spin_lock(&sess->cr_i_lock);
	REMOVE_ENTRY_FROM_LIST(cr, sess->cr_i_head, sess->cr_i_tail);
	spin_unlock(&sess->cr_i_lock);
		
	return(0);
}

/*	iscsi_remove_cmd_from_connection_recovery():
 *
 *	Called with cr->conn_recovery_cmd_lock help.
 */
extern int iscsi_remove_cmd_from_connection_recovery (
	iscsi_cmd_t *cmd,
	iscsi_session_t *sess)
{
	iscsi_conn_recovery_t *cr;
	
	TRACE_ENTER

	if (!cmd->cr) {
		TRACE_ERROR("iscsi_conn_recovery_t pointer for ITT: 0x%08x"
			" is NULL!\n", cmd->init_task_tag);
		BUG();
	}
	cr = cmd->cr;
		
	/*
	/ * Only element in list.
	 */
	if (!cmd->i_prev && !cmd->i_next)
		cr->conn_recovery_cmd_head =
		cr->conn_recovery_cmd_tail = NULL;
	else {
		/*
		 * Head of list.
		 */
		if (!cmd->i_prev) {
			cmd->i_next->i_prev = NULL;
			cr->conn_recovery_cmd_head = cmd->i_next;
			if (!cr->conn_recovery_cmd_head->i_next)
				cr->conn_recovery_cmd_tail =
				cr->conn_recovery_cmd_head;
		} else if (!cmd->i_next) {
			/*
			 * Tail of list.
			 */
			cmd->i_prev->i_next = NULL;
			cr->conn_recovery_cmd_tail = cmd->i_prev;
		} else {
			/*
			 * Somewhere in the middle.
			 */
			cmd->i_next->i_prev = cmd->i_prev;
			cmd->i_prev->i_next = cmd->i_next;
		}
		cmd->i_next = cmd->i_prev = NULL;
	}
	
	return(--cr->cmd_count);
}

/*	iscsi_discard_cr_cmds_by_expstatsn():
 *
 *
 */
extern void iscsi_discard_cr_cmds_by_expstatsn (
	iscsi_conn_recovery_t *cr,
	__u32 exp_statsn)
{
	__u32 dropped_count = 0;
	iscsi_cmd_t *cmd, *cmd_next;
	iscsi_session_t *sess = cr->sess;

	spin_lock(&cr->conn_recovery_cmd_lock);
	cmd = cr->conn_recovery_cmd_head;
	while (cmd) {
		cmd_next = cmd->i_next;

		if (((cmd->deferred_i_state != ISTATE_SENT_STATUS) &&
		     (cmd->deferred_i_state != ISTATE_REMOVE)) ||
		     (cmd->stat_sn >= exp_statsn)) {
			cmd = cmd_next;
			continue;
		}

		dropped_count++;
		TRACE(TRACE_ERL2, "Dropping Acknowledged ITT: 0x%08x, StatSN:"
			" 0x%08x, CID: %hu.\n", cmd->init_task_tag,
				cmd->stat_sn, cr->cid);
		
		iscsi_remove_cmd_from_connection_recovery(cmd, sess);
		
		spin_unlock(&cr->conn_recovery_cmd_lock);
		if (!(cmd->cmd_flags & ICF_SE_LUN_CMD) || !cmd->transport_wait_for_tasks)
			iscsi_release_cmd_to_pool(cmd, sess);
		else
			cmd->transport_wait_for_tasks(cmd, 1, 0);
		spin_lock(&cr->conn_recovery_cmd_lock);

		cmd = cmd_next;
	}
	spin_unlock(&cr->conn_recovery_cmd_lock);
	
	TRACE(TRACE_ERL2, "Dropped %u total acknowledged commands on"
		" CID: %hu less than old ExpStatSN: 0x%08x\n",
			dropped_count, cr->cid, exp_statsn);

	if (!cr->cmd_count) {
		TRACE(TRACE_ERL2, "No commands to be reassigned for failed"
			" connection CID: %hu on SID: %u\n", cr->cid, sess->sid);
		iscsi_remove_inactive_connection_recovery_entry(cr, sess);
		iscsi_attach_active_connection_recovery_entry(sess, cr);
		PYXPRINT("iSCSI connection recovery successful for CID: %hu"
			" on SID: %u\n", cr->cid, sess->sid);
		iscsi_remove_active_connection_recovery_entry(cr, sess);
	} else {
		iscsi_remove_inactive_connection_recovery_entry(cr, sess);
		iscsi_attach_active_connection_recovery_entry(sess, cr);
	}

	return;
}

/*	iscsi_discard_unacknowledged_ooo_cmdsns_for_conn():
 *
 *
 */
extern int iscsi_discard_unacknowledged_ooo_cmdsns_for_conn (iscsi_conn_t *conn)
{
	__u32 dropped_count = 0;
	iscsi_cmd_t *cmd = NULL, *cmd_next = NULL;
	iscsi_ooo_cmdsn_t *ooo_cmdsn = NULL, *ooo_cmdsn_next = NULL;
	iscsi_session_t *sess = SESS(conn);
	
	spin_lock(&sess->cmdsn_lock);
	ooo_cmdsn = sess->ooo_cmdsn_head;
	while (ooo_cmdsn) {
		ooo_cmdsn_next = ooo_cmdsn->next;
		if (ooo_cmdsn->cid != conn->cid) {
			ooo_cmdsn = ooo_cmdsn_next;
			continue;
		}

		dropped_count++;
		TRACE(TRACE_ERL2, "Dropping unacknowledged CmdSN:"
		" 0x%08x during connection recovery on CID: %hu\n",
			ooo_cmdsn->cmdsn, conn->cid);
		iscsi_remove_ooo_cmdsn(sess, ooo_cmdsn);

		ooo_cmdsn = ooo_cmdsn_next;
	}
	SESS(conn)->ooo_cmdsn_count -= dropped_count;
	spin_unlock(&sess->cmdsn_lock);	

	spin_lock_bh(&conn->cmd_lock);
	cmd = conn->cmd_head;
	while (cmd) {
		cmd_next = cmd->i_next;

		if (!(cmd->cmd_flags & ICF_OOO_CMDSN)) {
			cmd = cmd_next;
			continue;
		}
		
		iscsi_remove_cmd_from_conn_list(cmd, conn);

		spin_unlock_bh(&conn->cmd_lock);
		if (!(cmd->cmd_flags & ICF_SE_LUN_CMD) || !cmd->transport_wait_for_tasks)
			iscsi_release_cmd_to_pool(cmd, sess);
		else
			cmd->transport_wait_for_tasks(cmd, 1, 1);
		spin_lock_bh(&conn->cmd_lock);
		
		cmd = cmd_next;
	}
	spin_unlock_bh(&conn->cmd_lock);

	TRACE(TRACE_ERL2, "Dropped %u total unacknowledged commands on CID:"
		" %hu for ExpCmdSN: 0x%08x.\n", dropped_count, conn->cid,
				sess->exp_cmd_sn);
	return(0);
}

/*	iscsi_prepare_cmds_for_realligance():
 *
 *
 */
extern int iscsi_prepare_cmds_for_realligance (iscsi_conn_t *conn)
{
	__u32 cmd_count = 0;
	iscsi_cmd_t *cmd, *cmd_next;
	iscsi_conn_recovery_t *cr;
	
	/*
	 * Allocate an iscsi_conn_recovery_t for this connection.
	 * Each iscsi_cmd_t contains an iscsi_conn_recovery_t pointer
	 * (iscsi_cmd_t->cr) so we need to allocate this before preparing the
	 * connection's command list for connection recovery.
	 */
	if (!(cr = kmalloc(sizeof(iscsi_conn_recovery_t), GFP_KERNEL))) {
		TRACE_ERROR("Unable to allocate memory for"
			" iscsi_conn_recovery_t.\n");
		return(-1);
	}
	memset(cr, 0, sizeof(iscsi_conn_recovery_t));
		
	/*
	 * Only perform connection recovery on ISCSI_INIT_SCSI_CMND or
	 * ISCSI_INIT_NOP_OUT opcodes.  For all other opcodes call
	 * iscsi_remove_cmd_from_conn_list() to release the command to the
	 * session pool and remove it from the connection's list.
	 *
	 * Also stop the DataOUT timer, which will be restarted after
	 * sending the TMR response.
	 */
	spin_lock_bh(&conn->cmd_lock);
	cmd = conn->cmd_head;
	while (cmd) {
		cmd_next = cmd->i_next;

		if ((cmd->iscsi_opcode != ISCSI_INIT_SCSI_CMND) &&
		    (cmd->iscsi_opcode != ISCSI_INIT_NOP_OUT)) {
			TRACE(TRACE_ERL2, "Not performing realligence on Opcode:"
				" 0x%02x, ITT: 0x%08x, CmdSN: 0x%08x, CID: %hu\n",
				cmd->iscsi_opcode, cmd->init_task_tag, cmd->cmd_sn,
						conn->cid);

			iscsi_remove_cmd_from_conn_list(cmd, conn);

			spin_unlock_bh(&conn->cmd_lock);
			if (!(cmd->cmd_flags & ICF_SE_LUN_CMD) || !cmd->transport_wait_for_tasks)
				iscsi_release_cmd_to_pool(cmd, SESS(conn));
			else
				cmd->transport_wait_for_tasks(cmd, 1, 0);
			spin_lock_bh(&conn->cmd_lock);
			
			cmd = cmd_next;
			continue;
		}

		/*
		 * Special case where commands greater than or equal to
		 * the session's ExpCmdSN are attached to the connection
		 * list but not to the out of order CmdSN list.  The one
		 * obvious case is when a command with immediate data
		 * attached must only check the CmdSN against ExpCmdSN
		 * after the data is received.  The special case below
		 * is when the connection fails before data is received,
		 * but also may apply to other PDUs, so it has been
		 * made generic here.
		 */
		if (!(cmd->cmd_flags & ICF_OOO_CMDSN) && !cmd->immediate_cmd &&
		     (cmd->cmd_sn >= SESS(conn)->exp_cmd_sn)) {
			iscsi_remove_cmd_from_conn_list(cmd, conn);

			spin_unlock_bh(&conn->cmd_lock);
			if (!(cmd->cmd_flags & ICF_SE_LUN_CMD) || !cmd->transport_wait_for_tasks)
				iscsi_release_cmd_to_pool(cmd, SESS(conn));
			else
				cmd->transport_wait_for_tasks(cmd, 1, 1);
			spin_lock_bh(&conn->cmd_lock);

			cmd = cmd_next;
			continue;
		}
		
		cmd_count++;
		TRACE(TRACE_ERL2, "Preparing Opcode: 0x%02x, ITT: 0x%08x, CmdSN: 0x%08x,"
			" StatSN: 0x%08x, CID: %hu for realligence.\n", cmd->iscsi_opcode,
			cmd->init_task_tag, cmd->cmd_sn, cmd->stat_sn, conn->cid);
		
		cmd->deferred_i_state = cmd->i_state;
		cmd->i_state = ISTATE_IN_CONNECTION_RECOVERY;

		if (cmd->data_direction == ISCSI_WRITE)
			iscsi_stop_dataout_timer(cmd);

		cmd->sess = SESS(conn);
		
		spin_unlock_bh(&conn->cmd_lock);
		iscsi_free_all_datain_reqs(cmd);

		if ((cmd->cmd_flags & ICF_SE_LUN_CMD) && cmd->transport_wait_for_tasks)
			cmd->transport_wait_for_tasks(cmd, 0, 0);

		spin_lock_bh(&conn->cmd_lock);

		cmd->cr = cr;
		cmd->conn = NULL;

		cmd = cmd_next;
	}
	spin_unlock_bh(&conn->cmd_lock);

	/*
	 * Fill in the various values in the preallocated iscsi_conn_recovery_t.
	 */
	cr->cid = conn->cid;
	cr->cmd_count = cmd_count;
	cr->maxrecvdatasegmentlength = CONN_OPS(conn)->MaxRecvDataSegmentLength;
	cr->sess = SESS(conn);
	cr->conn_recovery_cmd_head = conn->cmd_head;
	cr->conn_recovery_cmd_tail = conn->cmd_tail;
	spin_lock_init(&cr->conn_recovery_cmd_lock);

	conn->cmd_head = conn->cmd_tail = NULL;
	
	iscsi_attach_inactive_connection_recovery_entry(SESS(conn), cr);
	
	return(0);
}

/*	iscsi_connection_recovery_transport_reset():
 *
 *
 */
extern int iscsi_connection_recovery_transport_reset (iscsi_conn_t *conn)
{
	atomic_set(&conn->connection_recovery, 1);

	if (iscsi_close_connection(conn) < 0)
		return(-1);
	
	return(0);
}

