/*********************************************************************************
 * Filename:  iscsi_target_erl1.c
 *
 * This file contains error recovery level one used by the iSCSI Target driver.
 *
 * Copyright (c) 2003, 2004, 2005 PyX Technologies, Inc.
 * Copyright (c) 2006 SBE, Inc.  All Rights Reserved.
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


#define ISCSI_TARGET_ERL1_C

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
#include <iscsi_target_device.h>
#include <iscsi_target_transport.h>
#include <iscsi_target_util.h>
#include <iscsi_target_erl0.h>
#include <iscsi_target_erl1.h>
#include <iscsi_target_erl2.h>

#undef ISCSI_TARGET_ERL1_C

extern iscsi_global_t *iscsi_global;
extern int iscsi_add_reject_from_cmd (u8, int, int, unsigned char *, iscsi_cmd_t *);
extern int iscsi_build_r2ts_for_cmd (iscsi_cmd_t *, iscsi_conn_t *, int);
extern int iscsi_build_report_luns_response (iscsi_cmd_t *);
extern int iscsi_logout_closesession (iscsi_cmd_t *, iscsi_conn_t *);
extern int iscsi_logout_closeconnection (iscsi_cmd_t *, iscsi_conn_t *);
extern int iscsi_logout_removeconnforrecovery (iscsi_cmd_t *, iscsi_conn_t *);

#define OFFLOAD_BUF_SIZE	32768

/*	iscsi_dump_data_payload():
 *
 *	Used to dump excess datain payload for certain error recovery situations.
 *	Receive in OFFLOAD_BUF_SIZE max of datain per rx_data().
 *
 *	dump_padding_digest denotes if padding and data digests need to be dumped.
 */
extern int iscsi_dump_data_payload (
	iscsi_conn_t *conn,
	__u32 buf_len,
	int dump_padding_digest)
{
	char *buf, pad_bytes[4];
	int ret = DATAOUT_WITHIN_COMMAND_RECOVERY, rx_got;
	__u32 length, padding, offset = 0, size;
	struct iovec iov;

	length = (buf_len > OFFLOAD_BUF_SIZE) ? OFFLOAD_BUF_SIZE : buf_len;

	if (!(buf = (char *) kmalloc(length, GFP_ATOMIC))) {
		TRACE_ERROR("Unable to allocate %u bytes for offload"
				" buffer.\n", length);
		return(-1);
	}
	memset(buf, 0, length);
	memset(&iov, 0, sizeof(struct iovec));

	while (offset < buf_len) {
		size = ((offset + length) > buf_len) ?
			(buf_len - offset) : length;

		iov.iov_len = size;
		iov.iov_base = buf;

		rx_got = rx_data(conn, &iov, 1, size);
		if (rx_got != size) {
			ret = DATAOUT_CANNOT_RECOVER;
			goto out;
		}

		offset += size;
	}

	if (!dump_padding_digest)
		goto out;
	
	if ((padding = ((-buf_len) & 3)) != 0) {
		iov.iov_len = padding;
		iov.iov_base = pad_bytes;

		rx_got = rx_data(conn, &iov, 1, padding);
		if (rx_got != padding) {
			ret = DATAOUT_CANNOT_RECOVER;
			goto out;
		}
	}

	if (CONN_OPS(conn)->DataDigest) {
		__u32 data_crc;
		
		iov.iov_len = CRC_LEN;
		iov.iov_base = &data_crc;

		rx_got = rx_data(conn, &iov, 1, CRC_LEN);
		if (rx_got != CRC_LEN) {
			ret = DATAOUT_CANNOT_RECOVER;
			goto out;
		}
	}

out:
	kfree(buf);
 	return(ret);
}	

/*	iscsi_send_recovery_r2t_for_snack():
 *
 *	Used for retransmitting R2Ts from a R2T SNACK request.
 */
static int iscsi_send_recovery_r2t_for_snack (
	iscsi_cmd_t *cmd,
	iscsi_r2t_t *r2t)
{
	/*
	 * If the iscsi_r2t_t has not been sent yet, we can safely ignore retransmission
	 * of the R2TSN in question.
	 */
	spin_lock_bh(&cmd->r2t_lock);
	if (!r2t->sent_r2t) {
		spin_unlock_bh(&cmd->r2t_lock);
		return(0);
	}
	r2t->sent_r2t = 0;
	spin_unlock_bh(&cmd->r2t_lock);

	iscsi_add_cmd_to_immediate_queue(cmd, CONN(cmd), ISTATE_SEND_R2T);
	
	return(0);
}

/*	iscsi_handle_r2t_snack():
 *
 *
 */
static int iscsi_handle_r2t_snack (
	iscsi_cmd_t *cmd,
	unsigned char *buf,
	__u32 begrun,
	__u32 runlength)
{
	__u32 last_r2tsn;
	iscsi_r2t_t *r2t;
	
	/*
	 * Make sure the initiator is not requesting retransmission
	 * of R2TSNs already acknowledged by a TMR TASK_REASSIGN.
	 */
	if ((cmd->cmd_flags & ICF_GOT_DATACK_SNACK) &&
	    (begrun <= cmd->acked_data_sn)) {
		TRACE_ERROR("ITT: 0x%08x, R2T SNACK requesting retransmission"
			" of R2TSN: 0x%08x to 0x%08x but already acked to"
			" R2TSN: 0x%08x by TMR TASK_REASSIGN, protocol error.\n",
			cmd->init_task_tag, begrun, (begrun + runlength),
				cmd->acked_data_sn);
			return(iscsi_add_reject_from_cmd(REASON_PROTOCOL_ERR, 1, 0, buf, cmd));
	}
		
	if (runlength) {
		if ((begrun + runlength) > cmd->r2t_sn) {
			TRACE_ERROR("Command ITT: 0x%08x received R2T SNACK"
			" with BegRun: 0x%08x, RunLength: 0x%08x, exceeds"
			" current R2TSN: 0x%08x, protocol error.\n",
			cmd->init_task_tag, begrun, runlength, cmd->r2t_sn);
			return(iscsi_add_reject_from_cmd(REASON_INVALID_PDU_FIELD, 1, 0, buf, cmd));
		}
		last_r2tsn = (begrun + runlength);
	} else
		last_r2tsn = cmd->r2t_sn;

	while (begrun < last_r2tsn) {
		if (!(r2t = iscsi_get_holder_for_r2tsn(cmd, begrun)))
			return(-1);
		if (iscsi_send_recovery_r2t_for_snack(cmd, r2t) < 0)
			return(-1);

		begrun++;
	}

	return(0);
}

/*	iscsi_create_recovery_datain_values_datasequenceinorder_yes():
 *
 *	Generates Offsets and NextBurstLength based on Begrun and Runlength
 *	carried in a Data SNACK or ExpDataSN in TMR TASK_REASSIGN.
 *	
 *	For DataSequenceInOrder=Yes and DataPDUInOrder=[Yes,No] only.
 *
 *	FIXME: How is this handled for a RData SNACK?
 */
extern int iscsi_create_recovery_datain_values_datasequenceinorder_yes (
	iscsi_cmd_t *cmd,
	iscsi_datain_req_t *dr)
{
	__u32 data_sn = 0, data_sn_count = 0;
	__u32 pdu_start = 0, seq_no = 0;
	__u32 begrun = dr->begrun;
	iscsi_conn_t *conn = CONN(cmd);

	while (begrun > data_sn++) {
		data_sn_count++;
		if ((dr->next_burst_len +
		     CONN_OPS(conn)->MaxRecvDataSegmentLength) <
		     SESS_OPS_C(conn)->MaxBurstLength) {
			dr->read_data_done +=
				CONN_OPS(conn)->MaxRecvDataSegmentLength;
			dr->next_burst_len +=
				CONN_OPS(conn)->MaxRecvDataSegmentLength;
		} else {
			dr->read_data_done +=
				(SESS_OPS_C(conn)->MaxBurstLength -
				 dr->next_burst_len);
			dr->next_burst_len = 0;
			pdu_start += data_sn_count;
			data_sn_count = 0;
			seq_no++;
		}
	}

	if (!SESS_OPS_C(conn)->DataPDUInOrder) {
		cmd->seq_no = seq_no;
		cmd->pdu_start = pdu_start;
		cmd->pdu_send_order = data_sn_count;
	}
	
	return(0);
}

/*	iscsi_create_recovery_datain_values_datasequenceinorder_no():
 *
 *	Generates Offsets and NextBurstLength based on Begrun and Runlength
 *	carried in a Data SNACK or ExpDataSN in TMR TASK_REASSIGN.
 * 
 *	For DataSequenceInOrder=No and DataPDUInOrder=[Yes,No] only.
 * 
 *	FIXME: How is this handled for a RData SNACK?
 */
extern int iscsi_create_recovery_datain_values_datasequenceinorder_no (
	iscsi_cmd_t *cmd,
	iscsi_datain_req_t *dr)
{
	int found_seq = 0, i;
	__u32 data_sn, read_data_done = 0, seq_send_order = 0;
	__u32 begrun = dr->begrun;
	__u32 runlength = dr->runlength;
	iscsi_conn_t *conn = CONN(cmd);
	iscsi_seq_t *first_seq = NULL, *seq = NULL;

	if (!cmd->seq_list) {
		TRACE_ERROR("iscsi_cmd_t->seq_list is NULL!\n");
		return(-1);
	}

	/*
	 * Calculate read_data_done for all sequences containing a first_datasn and
	 * last_datasn less than the BegRun.
	 *
	 * Locate the iscsi_seq_t the BegRun lies within and calculate
	 * NextBurstLenghth up to the DataSN based on MaxRecvDataSegmentLength.
	 *
	 * Also use iscsi_seq_t->seq_send_order to determine where to start.
	 */ 
	for (i = 0; i < cmd->seq_count; i++) {
		seq = &cmd->seq_list[i];

		if (!seq->seq_send_order)
			first_seq = seq;
	
		/*
		 * No data has been transferred for this DataIN sequence, so the
		 * seq->first_datasn and seq->last_datasn have not been set.
		 */
		if (!seq->sent) {
#if 0
			TRACE_ERROR("Ignoring non-sent sequence 0x%08x -> 0x%08x\n\n",
					seq->first_datasn, seq->last_datasn);
#endif
			continue;
		}

		/*
		 * This DataIN sequence is precedes the received BegRun, add the 
		 * total xfer_len of the sequence to read_data_done and reset
		 * seq->pdu_send_order.
		 */
		if ((seq->first_datasn < begrun) && (seq->last_datasn < begrun)) {
#if 0
			TRACE_ERROR("Pre BegRun sequence 0x%08x -> 0x%08x\n",
					seq->first_datasn, seq->last_datasn);
#endif
			read_data_done += cmd->seq_list[i].xfer_len;
			seq->next_burst_len = seq->pdu_send_order = 0;
			continue;
		}

		/*
		 * The BegRun lies within this DataIN sequence.
		 */
		if ((seq->first_datasn <= begrun) && (seq->last_datasn >= begrun)) {
#if 0
			TRACE_ERROR("Found sequence begrun: 0x%08x in 0x%08x -> 0x%08x\n",
					begrun, seq->first_datasn, seq->last_datasn);
#endif
			seq_send_order = seq->seq_send_order;
			data_sn = seq->first_datasn;
			seq->next_burst_len = seq->pdu_send_order = 0;
			found_seq = 1;

			/*
			 * For DataPDUInOrder=Yes, while the first DataSN of the sequence
			 * is less than the received BegRun, add the MaxRecvDataSegmentLength
			 * to read_data_done and to the sequence's next_burst_len;
			 *
			 * For DataPDUInOrder=No, while the first DataSN of the sequence
			 * is less than the received BegRun, find the iscsi_pdu_t of
			 * the DataSN in question and add the MaxRecvDataSegmentLength to
			 * read_data_done and to the sequence's next_burst_len;
			 */
			if (SESS_OPS_C(conn)->DataPDUInOrder) {
				while (data_sn < begrun) {
					seq->pdu_send_order++;
					read_data_done +=
						CONN_OPS(conn)->MaxRecvDataSegmentLength;
					seq->next_burst_len +=
						CONN_OPS(conn)->MaxRecvDataSegmentLength;
					data_sn++;
				}
			} else {
				int j;
				iscsi_pdu_t *pdu;

				while (data_sn < begrun) {
					seq->pdu_send_order++;

					for (j = 0; j < seq->pdu_count; j++) {
						pdu = &cmd->pdu_list[seq->pdu_start+j];
						if (pdu->data_sn == data_sn) {
							read_data_done += pdu->length;
							seq->next_burst_len += pdu->length;
						}
					}
					data_sn++;
				}
			}
			continue;
		}

		/*
		 * This DataIN sequence is larger than the received BegRun, reset
		 * seq->pdu_send_order and continue.
		 */
		if ((seq->first_datasn > begrun) || (seq->last_datasn > begrun)) {
#if 0
			TRACE_ERROR("Post BegRun sequence 0x%08x -> 0x%08x\n",
					seq->first_datasn, seq->last_datasn);
#endif
			seq->next_burst_len = seq->pdu_send_order = 0;
			continue;
		}
	}

	if (!found_seq) {
		if (!begrun) {
			if (!first_seq) {
				TRACE_ERROR("ITT: 0x%08x, Begrun: 0x%08x but"
					"first_seq is NULL\n",
					cmd->init_task_tag, begrun);
				return(-1);
			}
			seq_send_order = first_seq->seq_send_order;	
			seq->next_burst_len = seq->pdu_send_order = 0;
			goto done;
		}

		TRACE_ERROR("Unable to locate iscsi_seq_t for ITT: 0x%08x,"
			" BegRun: 0x%08x, RunLength: 0x%08x while"
			" DataSequenceInOrder=No and DataPDUInOrder=%s.\n",
				cmd->init_task_tag, begrun, runlength,
			(SESS_OPS_C(conn)->DataPDUInOrder) ? "Yes" : "No");
		return(-1);
	}

done:
	dr->read_data_done = read_data_done;
	dr->seq_send_order = seq_send_order;

	return(0);
}

/*	iscsi_handle_recovery_datain():
 *
 *
 */
static inline int iscsi_handle_recovery_datain (
	iscsi_cmd_t *cmd,
	unsigned char *buf,
	__u32 begrun,
	__u32 runlength)
{
	iscsi_conn_t *conn = CONN(cmd);
	iscsi_datain_req_t *dr;
	
	if (!(atomic_read(&T_TASK(cmd)->t_transport_complete))) {
		TRACE_ERROR("Ignoring ITT: 0x%08x Data SNACK\n", cmd->init_task_tag);
		return(0);
	}

	/*
	 * Make sure the initiator is not requesting retransmission
	 * of DataSNs already acknowledged by a Data ACK SNACK.
	 */
	if ((cmd->cmd_flags & ICF_GOT_DATACK_SNACK) &&
	    (begrun <= cmd->acked_data_sn)) {
		TRACE_ERROR("ITT: 0x%08x, Data SNACK requesting retransmission"
			" of DataSN: 0x%08x to 0x%08x but already acked to"
			" DataSN: 0x%08x by Data ACK SNACK, protocol error.\n",
			cmd->init_task_tag, begrun, (begrun + runlength),
				cmd->acked_data_sn); 
		return(iscsi_add_reject_from_cmd(REASON_PROTOCOL_ERR, 1, 0, buf, cmd));
	}

	/*
	 * Make sure BegRun and RunLength in the Data SNACK are sane.
	 * Note: (cmd->data_sn - 1) will carry the maximum DataSN sent.
	 */
	if ((begrun + runlength) > (cmd->data_sn - 1)) {
		TRACE_ERROR("Initiator requesting BegRun: 0x%08x, RunLength:"
			" 0x%08x greater than maximum DataSN: 0x%08x.\n",
				begrun, runlength, (cmd->data_sn - 1));
		return(iscsi_add_reject_from_cmd(REASON_INVALID_PDU_FIELD, 1, 0, buf, cmd));
	}
		
	if (!(dr = iscsi_allocate_datain_req()))
		return(iscsi_add_reject_from_cmd(REASON_OUT_OF_RESOURCES, 1, 0, buf, cmd));

	dr->data_sn = dr->begrun = begrun;
	dr->runlength = runlength;
	dr->generate_recovery_values = 1;
	dr->recovery = DATAIN_WITHIN_COMMAND_RECOVERY;

	iscsi_attach_datain_req(cmd, dr);

	cmd->i_state = ISTATE_SEND_DATAIN;
	iscsi_add_cmd_to_response_queue(cmd, conn, cmd->i_state);

	return(0);
}

/*	iscsi_handle_recovery_datain_or_r2t():
 *
 *
 */
extern int iscsi_handle_recovery_datain_or_r2t (
	iscsi_conn_t *conn,
	unsigned char *buf,
	__u32 init_task_tag,
	__u32 targ_xfer_tag,
	__u32 begrun,
	__u32 runlength)
{
	iscsi_cmd_t *cmd;

	if (!(cmd = iscsi_find_cmd_from_itt(conn, init_task_tag)))
		return(0);

	/*
	 * FIXME: This will not work for bidi commands.
	 */
	switch (cmd->data_direction) {
	case ISCSI_WRITE:
		return(iscsi_handle_r2t_snack(cmd, buf, begrun, runlength));
	case ISCSI_READ:
		return(iscsi_handle_recovery_datain(cmd, buf, begrun, runlength));
	default:
		TRACE_ERROR("Unknown cmd->data_direction: 0x%02x\n",
				cmd->data_direction);
		return(-1);
	}

	return(0);
}

/*	iscsi_send_recovery_status():
 *
 *
 */
//#warning FIXME: Status SNACK needs to be dependent on OPCODE!!!
extern int iscsi_handle_status_snack (
	iscsi_conn_t *conn,
	__u32 init_task_tag,
	__u32 targ_xfer_tag,
	__u32 begrun,
	__u32 runlength)
{
	__u32 last_statsn;
	iscsi_cmd_t *cmd = NULL;
	
	if (conn->exp_statsn > begrun) {
		TRACE_ERROR("Got Status SNACK Begrun: 0x%08x, RunLength: 0x%08x"
			" but already got ExpStatSN: 0x%08x on CID: %hu.\n",
			begrun, runlength, conn->exp_statsn, conn->cid);
		return(0);
	}
		
	last_statsn = (!runlength) ? conn->stat_sn : (begrun + runlength);

	while (begrun < last_statsn) {
		spin_lock_bh(&conn->cmd_lock);
		for (cmd = conn->cmd_head; cmd; cmd = cmd->i_next) {
			if (cmd->stat_sn == begrun)
				break;
		}
		spin_unlock_bh(&conn->cmd_lock);				

		if (!cmd) {
			TRACE_ERROR("Unable to find StatSN: 0x%08x for"
				" a Status SNACK, assuming this was a"
				" protactic SNACK for an untransmitted"
				" StatSN, ignoring.\n", begrun);
			begrun++;
			continue;
		}

		spin_lock_bh(&cmd->istate_lock);
		if (cmd->i_state == ISTATE_SEND_DATAIN) {
			spin_unlock_bh(&cmd->istate_lock);
			TRACE_ERROR("Ignoring Status SNACK for BegRun: 0x%08x,"
				" RunLength: 0x%08x, assuming this was a"
				" protactic SNACK for an untransmitted StatSN\n",
					begrun, runlength);
			begrun++;
			continue;
		}
		spin_unlock_bh(&cmd->istate_lock);

		cmd->i_state = ISTATE_SEND_STATUS_RECOVERY;
		iscsi_add_cmd_to_response_queue(cmd, conn, cmd->i_state);
		begrun++;
	}

	return(0);
}

/*	iscsi_handle_data_ack():
 *
 *
 */
extern int iscsi_handle_data_ack (
	iscsi_conn_t *conn,
	__u32 targ_xfer_tag,
	__u32 begrun,
	__u32 runlength)
{
	iscsi_cmd_t *cmd = NULL;

	if (!(cmd = iscsi_find_cmd_from_ttt(conn, targ_xfer_tag))) {
		TRACE_ERROR("Data ACK SNACK for TTT: 0x%08x is"
			" invalid.\n", targ_xfer_tag);
		return(-1);
	}

	if (begrun <= cmd->acked_data_sn) {
		TRACE_ERROR("ITT: 0x%08x Data ACK SNACK BegRUN: 0x%08x is"
			" less than the already acked DataSN: 0x%08x.\n",
			cmd->init_task_tag, begrun, cmd->acked_data_sn);
		return(-1);
	}

	/*
	 * For Data ACK SNACK, BegRun is the next expected DataSN.
	 * (see iSCSI v19: 10.16.6)
	 */
	cmd->cmd_flags |= ICF_GOT_DATACK_SNACK;
	cmd->acked_data_sn = (begrun - 1);

	TRACE(TRACE_ISCSI, "Received Data ACK SNACK for ITT: 0x%08x,"
		" updated acked DataSN to 0x%08x.\n",
			cmd->init_task_tag, cmd->acked_data_sn); 
	
	return(0);
}

/*	iscsi_send_recovery_r2t():
 *
 *
 */
static int iscsi_send_recovery_r2t (
	iscsi_cmd_t *cmd,
	__u32 offset,
	__u32 xfer_len)
{
	int ret;
	
	spin_lock_bh(&cmd->r2t_lock);
	ret = iscsi_add_r2t_to_list(cmd, offset, xfer_len, 1, 0);
	spin_unlock_bh(&cmd->r2t_lock);
	
	return(ret);
}

/*	iscsi_dataout_datapduinorder_no_fbit():
 *
 *
 */
extern int iscsi_dataout_datapduinorder_no_fbit (
	iscsi_cmd_t *cmd,
	iscsi_pdu_t *pdu)
{
	int i, send_recovery_r2t = 0, recovery = 0;
	__u32 length = 0, offset = 0, pdu_count = 0, xfer_len = 0;
	iscsi_conn_t *conn = CONN(cmd);
	iscsi_pdu_t *first_pdu = NULL;
	
	/*
	 * Get an iscsi_pdu_t pointer to the first PDU, and total PDU count
	 * of the DataOUT sequence.
	 */	
	if (SESS_OPS_C(conn)->DataSequenceInOrder) {
		 for (i = 0; i < cmd->pdu_count; i++) {
			if (cmd->pdu_list[i].seq_no == pdu->seq_no) {
				 if (!first_pdu)
					 first_pdu = &cmd->pdu_list[i];
				 xfer_len += cmd->pdu_list[i].length;
				 pdu_count++;
			} else if (pdu_count)
				break;
		}
	} else {
		iscsi_seq_t *seq = cmd->seq_ptr;

		first_pdu = &cmd->pdu_list[seq->pdu_start];
		pdu_count = seq->pdu_count;
	}

	if (!first_pdu || !pdu_count)
		return(DATAOUT_CANNOT_RECOVER);

	/*
	 * Loop through the ending DataOUT Sequence checking each iscsi_pdu_t.
	 * The following ugly logic does batching of not received PDUs.
	 */
	for (i = 0; i < pdu_count; i++) {
		if (first_pdu[i].status == ISCSI_PDU_RECEIVED_OK) {
			if (!send_recovery_r2t)
				continue;

			if (iscsi_send_recovery_r2t(cmd, offset, length) < 0)
				return(DATAOUT_CANNOT_RECOVER);

			send_recovery_r2t = length = offset = 0;
			continue;
		}
		/*
		 * Set recovery = 1 for any missing, CRC failed, or timed
		 * out PDUs to let the DataOUT logic know that this sequence
		 * has not been completed yet.
		 * 
		 * Also, only send a Recovery R2T for ISCSI_PDU_NOT_RECEIVED.
		 * We assume if the PDU either failed CRC or timed out
		 * that a Recovery R2T has already been sent.
		 */
		recovery = 1;

		if (first_pdu[i].status != ISCSI_PDU_NOT_RECEIVED)
			continue;

		if (!offset)
			offset = first_pdu[i].offset;
		length += first_pdu[i].length;

		send_recovery_r2t = 1;
	}

	if (send_recovery_r2t)
		if (iscsi_send_recovery_r2t(cmd, offset, length) < 0)
			return(DATAOUT_CANNOT_RECOVER);
	
	return((!recovery) ? DATAOUT_NORMAL : DATAOUT_WITHIN_COMMAND_RECOVERY);
}

/*	iscsi_recalculate_dataout_values():
 *
 *
 */
static int iscsi_recalculate_dataout_values (
	iscsi_cmd_t *cmd,
	__u32 pdu_offset,
	__u32 pdu_length,
	__u32 *r2t_offset,
	__u32 *r2t_length)
{
	int i;
	iscsi_conn_t *conn = CONN(cmd);
	iscsi_pdu_t *pdu = NULL;

	if (SESS_OPS_C(conn)->DataSequenceInOrder) {
		cmd->data_sn = 0;
		
		if (SESS_OPS_C(conn)->DataPDUInOrder) {
			*r2t_offset = cmd->write_data_done;
			*r2t_length = (cmd->seq_end_offset - cmd->write_data_done);
			return(0);
		}
			
		*r2t_offset = cmd->seq_start_offset;
		*r2t_length = (cmd->seq_end_offset - cmd->seq_start_offset);
		
		for (i = 0; i < cmd->pdu_count; i++) {
			pdu = &cmd->pdu_list[i];

			if (pdu->status != ISCSI_PDU_RECEIVED_OK)
				continue;

			if ((pdu->offset >= cmd->seq_start_offset) &&
			   ((pdu->offset + pdu->length) <=
			     cmd->seq_end_offset)) {
				if (!cmd->unsolicited_data) {
					cmd->next_burst_len -= pdu->length;
				} else {
					cmd->first_burst_len -= pdu->length;
				}
				cmd->write_data_done -= pdu->length;
				pdu->status = ISCSI_PDU_NOT_RECEIVED;
			}
		}
	} else {
		iscsi_seq_t *seq = NULL;
		
		if (!(seq = iscsi_get_seq_holder(cmd, pdu_offset, pdu_length)))
			return(-1);

		*r2t_offset = seq->orig_offset;
		*r2t_length = seq->xfer_len;
						
		cmd->write_data_done -= (seq->offset - seq->orig_offset);
		if (cmd->immediate_data)
			cmd->first_burst_len = cmd->write_data_done;

		seq->data_sn = 0;
		seq->offset = seq->orig_offset;
		seq->next_burst_len = 0;
		seq->status = DATAOUT_SEQUENCE_WITHIN_COMMAND_RECOVERY;

		if (SESS_OPS_C(conn)->DataPDUInOrder)
			return(0);

		for (i = 0; i < seq->pdu_count; i++) {
			pdu = &cmd->pdu_list[i+seq->pdu_start];

			if (pdu->status != ISCSI_PDU_RECEIVED_OK)
				continue;

			pdu->status = ISCSI_PDU_NOT_RECEIVED;
		}	
	}
	
	return(0);
}

/*	iscsi_recover_dataout_crc_sequence():
 *
 *
 */
extern int iscsi_recover_dataout_sequence (
	iscsi_cmd_t *cmd,
	__u32 pdu_offset,
	__u32 pdu_length)
{
	__u32 r2t_length = 0, r2t_offset = 0;
	
	spin_lock_bh(&cmd->istate_lock);
	cmd->cmd_flags |= ICF_WITHIN_COMMAND_RECOVERY;
	spin_unlock_bh(&cmd->istate_lock);
	
	if (iscsi_recalculate_dataout_values(cmd, pdu_offset, pdu_length,
			&r2t_offset, &r2t_length) < 0)
		return(DATAOUT_CANNOT_RECOVER);
	
	iscsi_send_recovery_r2t(cmd, r2t_offset, r2t_length);
	
	return(DATAOUT_WITHIN_COMMAND_RECOVERY);
}

/*	iscsi_allocate_ooo_cmdsn():
 *
 *
 */
static inline iscsi_ooo_cmdsn_t *iscsi_allocate_ooo_cmdsn (void)
{
	iscsi_ooo_cmdsn_t *ooo_cmdsn = NULL;

	if (!(ooo_cmdsn = (iscsi_ooo_cmdsn_t *)
	      kmalloc(sizeof(iscsi_ooo_cmdsn_t), GFP_ATOMIC))) {
		TRACE_ERROR("Unable to allocate memory for"
			" iscsi_ooo_cmdsn_t.\n");
		return(NULL);
	}
	memset(ooo_cmdsn, 0, sizeof(iscsi_ooo_cmdsn_t));

	return(ooo_cmdsn);
}
	
/*	iscsi_attach_ooo_cmdsn():
 *
 *	Called with sess->cmdsn_lock held.
 */
static inline int iscsi_attach_ooo_cmdsn (
	iscsi_session_t *sess,
	iscsi_ooo_cmdsn_t *ooo_cmdsn)
{
	/*
	 * We attach the iscsi_ooo_cmdsn_t entry to the out of order
	 * list in increasing CmdSN order.
	 * This allows iscsi_execute_ooo_cmdsns() to detect any
	 * additional CmdSN holes while performing delayed execution.
	 */
	if (!sess->ooo_cmdsn_head && !sess->ooo_cmdsn_tail) {
		sess->ooo_cmdsn_head = sess->ooo_cmdsn_tail = ooo_cmdsn;
		ooo_cmdsn->prev = ooo_cmdsn->next = NULL;
	} else {
		/*
		 * CmdSN is greater than the tail of the list.
		 */
		if (sess->ooo_cmdsn_tail->cmdsn < ooo_cmdsn->cmdsn) {
			sess->ooo_cmdsn_tail->next = ooo_cmdsn;
			ooo_cmdsn->prev = sess->ooo_cmdsn_tail;
			sess->ooo_cmdsn_tail = ooo_cmdsn;
		} else {
			/*
			 * CmdSN is either lower than the head,  or somewhere
			 * in the middle.
			 */
			iscsi_ooo_cmdsn_t *prev_ptr = NULL;
			iscsi_ooo_cmdsn_t *ooo_cmdsn_ptr =
					sess->ooo_cmdsn_head;
			while (ooo_cmdsn_ptr->cmdsn < ooo_cmdsn->cmdsn) {
				prev_ptr = ooo_cmdsn_ptr;
				ooo_cmdsn_ptr = ooo_cmdsn_ptr->next;
			}
			if (!prev_ptr) {
				ooo_cmdsn->next = sess->ooo_cmdsn_head;
				sess->ooo_cmdsn_head->prev = ooo_cmdsn;
				sess->ooo_cmdsn_head = ooo_cmdsn;
			} else {
				ooo_cmdsn->next = ooo_cmdsn_ptr;
				ooo_cmdsn->prev = prev_ptr;
				prev_ptr->next = ooo_cmdsn;
				ooo_cmdsn_ptr->prev = ooo_cmdsn;
			}
		}
	}
	sess->ooo_cmdsn_count++;
	
	TRACE(TRACE_CMDSN, "Set out of order CmdSN count for SID:"
		" %u to %hu.\n", sess->sid, sess->ooo_cmdsn_count);
	
	return(0);
}

/*	iscsi_remove_ooo_cmdsn()
 *
 *	Removes an iscsi_ooo_cmdsn_t from a session's list,
 *	called with iscsi_session_t->cmdsn_lock held.
 */
extern void iscsi_remove_ooo_cmdsn (
	iscsi_session_t *sess,
	iscsi_ooo_cmdsn_t *ooo_cmdsn)
{
	REMOVE_ENTRY_FROM_LIST(ooo_cmdsn, sess->ooo_cmdsn_head, sess->ooo_cmdsn_tail);
	kfree(ooo_cmdsn);

	return;
}

/*	iscsi_clear_ooo_cmdsns_for_conn():
 *
 *
 */
extern void iscsi_clear_ooo_cmdsns_for_conn (iscsi_conn_t *conn)
{
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

		ooo_cmdsn->cmd = NULL;
		
		ooo_cmdsn = ooo_cmdsn_next;
	}
	spin_unlock(&sess->cmdsn_lock);
		
	return;
}

/*	iscsi_execute_ooo_cmdsns():
 *
 *	Called with sess->cmdsn_lock held.
 */
extern int iscsi_execute_ooo_cmdsns (iscsi_session_t *sess)
{
	int ooo_count = 0;
	iscsi_cmd_t *cmd = NULL;
	iscsi_ooo_cmdsn_t *ooo_cmdsn = NULL, *ooo_cmdsn_next = NULL;
	
	ooo_cmdsn = sess->ooo_cmdsn_head;
	while (ooo_cmdsn) {
		ooo_cmdsn_next = ooo_cmdsn->next;
		if (ooo_cmdsn->cmdsn != sess->exp_cmd_sn) {
			ooo_cmdsn = ooo_cmdsn_next;
			continue;
		}

		if (!ooo_cmdsn->cmd) {
			sess->exp_cmd_sn++;
			iscsi_remove_ooo_cmdsn(sess, ooo_cmdsn);
			ooo_cmdsn = ooo_cmdsn_next;
			continue;
		}
		
		cmd = ooo_cmdsn->cmd;
		cmd->i_state = cmd->deferred_i_state;
		cmd->t_state = cmd->deferred_t_state;
		ooo_count++;
		sess->exp_cmd_sn++;
		TRACE(TRACE_CMDSN, "Executing out of order CmdSN: 0x%08x,"
			 " incremented ExpCmdSN to 0x%08x.\n",
			 	cmd->cmd_sn, sess->exp_cmd_sn);

		iscsi_remove_ooo_cmdsn(sess, ooo_cmdsn);

		if (iscsi_execute_cmd(cmd, 1) < 0)
			return(-1);

		ooo_cmdsn = ooo_cmdsn_next;
		continue;
	}

	return(ooo_count);
}

/*	iscsi_execute_cmd():
 *
 *	Called either:
 * 
 *	1. With sess->cmdsn_lock held from iscsi_execute_ooo_cmdsns()
 *	or iscsi_check_received_cmdsn().
 *	2. With no locks held directly from iscsi_handle_XXX_pdu() functions
 *	for immediate commands.
 */
extern int iscsi_execute_cmd (iscsi_cmd_t *cmd, int ooo)
{
	int lr = 0;
	iscsi_tmr_req_t *tmr_req = NULL;
	
	spin_lock_bh(&cmd->istate_lock);
	if (ooo)
		cmd->cmd_flags &= ~ICF_OOO_CMDSN;
	
	switch (cmd->iscsi_opcode) {
	case ISCSI_INIT_SCSI_CMND:
		/*
		 * Go ahead and send the CHECK_CONDITION status for
		 * any SCSI CDB exceptions that may have occurred.
		 */
		if (cmd->cmd_flags & ICF_SCSI_CDB_EXCEPTION) {
			if (cmd->cmd_flags & ICF_SCSI_RESERVATION_CONFLICT) {
				cmd->i_state = ISTATE_SEND_STATUS;
				spin_unlock_bh(&cmd->istate_lock);
				iscsi_add_cmd_to_response_queue(cmd, CONN(cmd), cmd->i_state);
				return(0);
			}
			spin_unlock_bh(&cmd->istate_lock);

			return(iscsi_send_check_condition_and_sense(cmd, cmd->scsi_sense_reason, 0));	
		}
		
		/*
		 * Special case for delayed CmdSN with Immediate
		 * Data and/or Unsolicited Data Out attached.
		 */
		if (cmd->immediate_data) {
			if (cmd->cmd_flags & ICF_GOT_LAST_DATAOUT) {
				spin_unlock_bh(&cmd->istate_lock);
				return(transport_generic_handle_data(cmd));
			}
			spin_unlock_bh(&cmd->istate_lock);

			if (!(cmd->cmd_flags & ICF_NON_IMMEDIATE_UNSOLICITED_DATA)) {
				iscsi_set_dataout_sequence_values(cmd);
				iscsi_build_r2ts_for_cmd(cmd, CONN(cmd), 0);
			}
			return(0);
		}

		/*
		 * Special case for REPORT_LUNs.
		 */
		if (cmd->cmd_flags & ICF_REPORT_LUNS) {
			spin_unlock_bh(&cmd->istate_lock);
			if (iscsi_build_report_luns_response(cmd) < 0)
				return(-1);
	
			return(0);
		} else {
			/*
			 * The default handler.
			 */
			spin_unlock_bh(&cmd->istate_lock);

			if ((cmd->data_direction == ISCSI_WRITE) &&
			    !(cmd->cmd_flags & ICF_NON_IMMEDIATE_UNSOLICITED_DATA)) {
				iscsi_set_dataout_sequence_values(cmd);
				spin_lock_bh(&cmd->dataout_timeout_lock);
				iscsi_start_dataout_timer(cmd, CONN(cmd));
				spin_unlock_bh(&cmd->dataout_timeout_lock);
			}
			
			transport_generic_handle_cdb(cmd);
			return(0);
		}
		break;
	case ISCSI_INIT_NOP_OUT:
	case ISCSI_INIT_TEXT_CMND:
		spin_unlock_bh(&cmd->istate_lock);
		iscsi_add_cmd_to_response_queue(cmd, CONN(cmd), cmd->i_state);
		break;
	case ISCSI_INIT_TASK_MGMT_CMND:
		spin_unlock_bh(&cmd->istate_lock);
		tmr_req = cmd->tmr_req;
//#warning FIXME: TMR execute for non immediate iscsi_cmd_ts
		return(-1);
#if 0
		if (tmr_req->call_transport)
			transport_generic_handle_tmr(cmd, tmr_req);
		else
#endif
		switch (tmr_req->function) {
		case ABORT_TASK:
			TRACE_ERROR("ABORT_TASK:\n");
			break;
		case ABORT_TASK_SET:
			TRACE_ERROR("ABORT_TASK_SET:\n");
			break;
		case CLEAR_ACA:
			TRACE_ERROR("CLEAR_ACA:\n");
			break;
		case CLEAR_TASK_SET:
			TRACE_ERROR("CLEAR_TASK_SET:\n");
			break;
		case LUN_RESET:
			TRACE_ERROR("LUN_RESET:\n");
			break;
		case TARGET_WARM_RESET:
			TRACE_ERROR("TARGET_WARM_RESET:\n");
			break;
		case TARGET_COLD_RESET:
			TRACE_ERROR("TARGET_COLD_RESET:\n");
			break;
		case TASK_REASSIGN:
			TRACE_ERROR("TASK_REASSIGN:\n");
			break;
		default:
			TRACE_ERROR("Unknown TMR 0x%02x\n", tmr_req->function);
			break;
		}
			
		cmd->i_state = ISTATE_SEND_TASKMGTRSP;
		iscsi_add_cmd_to_response_queue(cmd, CONN(cmd), cmd->i_state);
		break;
	case ISCSI_INIT_LOGOUT_CMND:
		spin_unlock_bh(&cmd->istate_lock);
		switch (cmd->logout_reason) {
		case CLOSESESSION:
			lr = iscsi_logout_closesession(cmd, CONN(cmd));
			break;
		case CLOSECONNECTION:
			lr = iscsi_logout_closeconnection(cmd, CONN(cmd));
			break;
		case REMOVECONNFORRECOVERY:
			lr = iscsi_logout_removeconnforrecovery(cmd, CONN(cmd));
			break;
		default:
			TRACE_ERROR("Unknown iSCSI Logout Request Code:"
				" 0x%02x\n", cmd->logout_reason);
			return(-1);
		}

		return(lr);
	default:
		spin_unlock_bh(&cmd->istate_lock);
		TRACE_ERROR("Cannot perform out of order execution for"
		" unknown iSCSI Opcode: 0x%02x\n", cmd->iscsi_opcode);
		return(-1);
	}

	return(0);	
}

/*	iscsi_free_all_ooo_cmdsns():
 *
 *
 */
extern void iscsi_free_all_ooo_cmdsns (iscsi_session_t *sess)
{
	iscsi_ooo_cmdsn_t *ooo_cmdsn, *ooo_cmdsn_next;
	
	spin_lock(&sess->cmdsn_lock);
	ooo_cmdsn = sess->ooo_cmdsn_head;
	while (ooo_cmdsn) {
		ooo_cmdsn_next = ooo_cmdsn->next;

		kfree(ooo_cmdsn);
		
		ooo_cmdsn = ooo_cmdsn_next;
	}
	spin_unlock(&sess->cmdsn_lock);
		
	return;
}

/*	iscsi_handle_ooo_cmdsn():
 *
 * 
 */
extern int iscsi_handle_ooo_cmdsn (
	iscsi_session_t *sess,
	iscsi_cmd_t *cmd,
	__u32 cmdsn)
{
	int batch = 0;
	iscsi_ooo_cmdsn_t *ooo_cmdsn = NULL, *ooo_cmdsn_tail = NULL;
	
	sess->cmdsn_outoforder = 1;

	cmd->deferred_i_state		= cmd->i_state;
	cmd->i_state			= ISTATE_DEFERRED_CMD;
	cmd->deferred_t_state		= cmd->t_state;
	cmd->t_state			= TRANSPORT_DEFERRED_CMD;
	cmd->cmd_flags			|= ICF_OOO_CMDSN;

	if (!sess->ooo_cmdsn_tail)
		batch = 1;
	else {
		ooo_cmdsn_tail = sess->ooo_cmdsn_tail;
		if (ooo_cmdsn_tail->cmdsn != (cmdsn - 1));
			batch = 1;
	}
	
	if (!(ooo_cmdsn = iscsi_allocate_ooo_cmdsn()))
		return(CMDSN_ERROR_CANNOT_RECOVER);

	ooo_cmdsn->cmd			= cmd;
	ooo_cmdsn->batch_count		= (batch) ?
					  (cmdsn - sess->exp_cmd_sn) : 1;
	ooo_cmdsn->cid			= CONN(cmd)->cid;
	ooo_cmdsn->exp_cmdsn		= sess->exp_cmd_sn;
	ooo_cmdsn->cmdsn		= cmdsn;

	if (iscsi_attach_ooo_cmdsn(sess, ooo_cmdsn) < 0) {
		kfree(ooo_cmdsn);
		return(CMDSN_ERROR_CANNOT_RECOVER);
	}
	
	return(CMDSN_HIGHER_THAN_EXP);
}

/*	 iscsi_set_dataout_timeout_values():
 *
 *
 */
static int iscsi_set_dataout_timeout_values (
	iscsi_cmd_t *cmd,
	__u32 *offset,
	__u32 *length)
{
	iscsi_conn_t *conn = CONN(cmd);
	iscsi_r2t_t *r2t;

	if (cmd->unsolicited_data) {
		*offset = 0;
		*length = (SESS_OPS_C(conn)->FirstBurstLength > cmd->data_length) ?
			   cmd->data_length : SESS_OPS_C(conn)->FirstBurstLength;
		return(0);
	}
		
	spin_lock_bh(&cmd->r2t_lock);
	if (!cmd->r2t_head) {
		TRACE_ERROR("cmd->r2t_head is NULL!\n");
		spin_unlock_bh(&cmd->r2t_lock);
		return(-1);
	}
	
	for (r2t = cmd->r2t_head; r2t; r2t = r2t->next) {
		if (r2t->sent_r2t && !r2t->recovery_r2t && !r2t->seq_complete)
			break;
	}
	
	if (!r2t) {
		TRACE_ERROR("Unable to locate any incomplete DataOUT sequences"
			" for ITT: 0x%08x.\n", cmd->init_task_tag);
		spin_unlock_bh(&cmd->r2t_lock);
		return(-1);
	}

	*offset = r2t->offset;
	*length = r2t->xfer_len;
	
	spin_unlock_bh(&cmd->r2t_lock);
	
	return(0);
}

/*	iscsi_handle_dataout_timeout():
 *
 *	NOTE: Called from interrupt (timer) context.
 */
static void iscsi_handle_dataout_timeout (
	unsigned long data)
{
	__u32 pdu_length = 0, pdu_offset = 0;
	__u32 r2t_length = 0, r2t_offset = 0;
	iscsi_cmd_t *cmd = (iscsi_cmd_t *) data;
	iscsi_conn_t *conn = conn = CONN(cmd);
	iscsi_session_t *sess = NULL;
	iscsi_node_acl_t *acl = NULL;

	iscsi_inc_conn_usage_count(conn);
		
	spin_lock_bh(&cmd->dataout_timeout_lock);
	if (cmd->dataout_timer_flags & DATAOUT_TF_STOP) {
		spin_unlock_bh(&cmd->dataout_timeout_lock);
		iscsi_dec_conn_usage_count(conn);
		return;
	}
	cmd->dataout_timer_flags &= ~DATAOUT_TF_RUNNING;
	sess = SESS(conn);
	acl = sess->node_acl;
	
	if (!SESS_OPS(sess)->ErrorRecoveryLevel) {
		TRACE(TRACE_ERL0, "Unable to recover from DataOut timeout while"
			" in ERL=0.\n");
		goto failure;
	}
	
	if (++cmd->dataout_timeout_retries ==
	    ISCSI_NODE_ATTRIB(acl)->dataout_timeout_retries) {
		TRACE(TRACE_TIMER, "Command ITT: 0x%08x exceeded max retries for"
		" DataOUT timeout %u, closing iSCSI connection.\n",
			cmd->init_task_tag,
			ISCSI_NODE_ATTRIB(acl)->dataout_timeout_retries);
		goto failure;
	}

	cmd->cmd_flags |= ICF_WITHIN_COMMAND_RECOVERY;
	
	if (SESS_OPS_C(conn)->DataSequenceInOrder) {
		if (SESS_OPS_C(conn)->DataPDUInOrder) {
			pdu_offset = cmd->write_data_done;
			if ((pdu_offset + (SESS_OPS_C(conn)->MaxBurstLength -
			     cmd->next_burst_len)) > cmd->data_length)
				pdu_length = (cmd->data_length -
					cmd->write_data_done);
			else
				pdu_length = (SESS_OPS_C(conn)->MaxBurstLength -
						cmd->next_burst_len);
		} else {
			pdu_offset = cmd->seq_start_offset;
			pdu_length = (cmd->seq_end_offset -
				cmd->seq_start_offset);
		}
	} else {
		if (iscsi_set_dataout_timeout_values(cmd, &pdu_offset,
				&pdu_length) < 0)
			goto failure;
	}

	if (iscsi_recalculate_dataout_values(cmd, pdu_offset, pdu_length,
			&r2t_offset, &r2t_length) < 0)
		goto failure;
	
	TRACE(TRACE_TIMER, "Command ITT: 0x%08x timed out waiting for completion of"
		" %sDataOUT Sequence Offset: %u, Length: %u\n", cmd->init_task_tag,
			(cmd->unsolicited_data) ? "Unsolicited " : "", r2t_offset,
				r2t_length);

	if (iscsi_send_recovery_r2t(cmd, r2t_offset, r2t_length) < 0)
		goto failure;
	
	iscsi_start_dataout_timer(cmd, conn);
	spin_unlock_bh(&cmd->dataout_timeout_lock);
	iscsi_dec_conn_usage_count(conn);

	return;
	
failure:
	spin_unlock_bh(&cmd->dataout_timeout_lock);
	iscsi_cause_connection_reinstatement(conn, 0);
	iscsi_dec_conn_usage_count(conn);

	return;
}

/*	iscsi_mod_dataout_timer():
 *
 *
 */
extern void iscsi_mod_dataout_timer (iscsi_cmd_t *cmd)
{               
	iscsi_conn_t *conn = CONN(cmd);
	iscsi_session_t *sess = SESS(conn);
	iscsi_node_acl_t *acl = sess->node_acl;
	
	spin_lock_bh(&cmd->dataout_timeout_lock);
	if (!(cmd->dataout_timer_flags & DATAOUT_TF_RUNNING)) {
		spin_unlock_bh(&cmd->dataout_timeout_lock);
		return;
	}
		                        
	MOD_TIMER(&cmd->dataout_timer, ISCSI_NODE_ATTRIB(acl)->dataout_timeout);
	TRACE(TRACE_TIMER, "Updated DataOUT timer for ITT: 0x%08x",
			cmd->init_task_tag);
	spin_unlock_bh(&cmd->dataout_timeout_lock);

	return;
}

/*	iscsi_start_dataout_timer():
 *
 *	Called with cmd->dataout_timeout_lock held.	
 */
extern void iscsi_start_dataout_timer (
	iscsi_cmd_t *cmd,
	iscsi_conn_t *conn)
{
	iscsi_session_t *sess = SESS(conn);
	iscsi_node_acl_t *acl = sess->node_acl;
	
	if (cmd->dataout_timer_flags & DATAOUT_TF_RUNNING)
		return;

	TRACE(TRACE_TIMER, "Starting DataOUT timer for ITT: 0x%08x on"
		" CID: %hu.\n", cmd->init_task_tag, conn->cid);

	init_timer(&cmd->dataout_timer);
	SETUP_TIMER(cmd->dataout_timer, ISCSI_NODE_ATTRIB(acl)->dataout_timeout,
		cmd, iscsi_handle_dataout_timeout);
	cmd->dataout_timer_flags |= DATAOUT_TF_RUNNING;
	add_timer(&cmd->dataout_timer);
	
	return;
}

/*	iscsi_stop_dataout_timer():
 *
 *
 */
extern void iscsi_stop_dataout_timer (iscsi_cmd_t *cmd)
{
	spin_lock_bh(&cmd->dataout_timeout_lock);
	if (!(cmd->dataout_timer_flags & DATAOUT_TF_RUNNING)) {
		spin_unlock_bh(&cmd->dataout_timeout_lock);
		return;
	}
	cmd->dataout_timer_flags |= DATAOUT_TF_STOP;
	spin_unlock_bh(&cmd->dataout_timeout_lock);
	
	del_timer_sync(&cmd->dataout_timer);
	
	spin_lock_bh(&cmd->dataout_timeout_lock);
	cmd->dataout_timer_flags &= ~DATAOUT_TF_RUNNING;
	cmd->dataout_timer_flags &= ~DATAOUT_TF_STOP;
	TRACE(TRACE_TIMER, "Stopped DataOUT Timer for ITT: 0x%08x\n",
			cmd->init_task_tag);
	spin_unlock_bh(&cmd->dataout_timeout_lock);
	
	return;
}

