/******************************************************************************
 * Filename:  iscsi_target_erl0.c
 *
 * This file contains error recovery level zero functions used by
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
 ******************************************************************************/


#define ISCSI_TARGET_ERL0_C

#include <linux/net.h>
#include <linux/string.h>
#include <linux/timer.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/smp_lock.h>
#include <linux/in.h>
#include <net/sock.h>
#include <net/tcp.h>

#include <iscsi_linux_defs.h>
#include <iscsi_protocol.h>
#include <iscsi_debug_opcodes.h>
#include <iscsi_debug.h>
#include <iscsi_target_core.h>
#include <target/target_core_base.h>
#include <target/target_core_transport.h>
#include <iscsi_target_erl0.h>
#include <iscsi_target_erl1.h>
#include <iscsi_target_erl2.h>
#include <iscsi_target_util.h>

#include <iscsi_target.h>

#undef ISCSI_TARGET_ERL0_C

/*	iscsi_set_dataout_sequence_values():
 *
 *	Used to set values in struct iscsi_cmd that iscsi_dataout_check_sequence()
 *	checks against to determine a PDU's Offset+Length is within the current
 *	DataOUT Sequence.  Used for DataSequenceInOrder=Yes only.
 */
void iscsi_set_dataout_sequence_values(
	struct iscsi_cmd *cmd)
{
	struct iscsi_conn *conn = CONN(cmd);
	/*
	 * Still set seq_start_offset and seq_end_offset for Unsolicited
	 * DataOUT, even if DataSequenceInOrder=No.
	 */
	if (cmd->unsolicited_data) {
		cmd->seq_start_offset = cmd->write_data_done;
		cmd->seq_end_offset = (cmd->write_data_done +
			(cmd->data_length >
			 SESS_OPS_C(conn)->FirstBurstLength) ?
			SESS_OPS_C(conn)->FirstBurstLength : cmd->data_length);
		return;
	}

	if (!SESS_OPS_C(conn)->DataSequenceInOrder)
		return;

	if (!cmd->seq_start_offset && !cmd->seq_end_offset) {
		cmd->seq_start_offset = cmd->write_data_done;
		cmd->seq_end_offset = (cmd->data_length >
			SESS_OPS_C(conn)->MaxBurstLength) ?
			(cmd->write_data_done +
			SESS_OPS_C(conn)->MaxBurstLength) : cmd->data_length;
	} else {
		cmd->seq_start_offset = cmd->seq_end_offset;
		cmd->seq_end_offset = ((cmd->seq_end_offset +
			SESS_OPS_C(conn)->MaxBurstLength) >=
			cmd->data_length) ? cmd->data_length :
			(cmd->seq_end_offset +
			 SESS_OPS_C(conn)->MaxBurstLength);
	}
}

/*	iscsi_dataout_within_command_recovery_check():
 *
 *
 */
static inline int iscsi_dataout_within_command_recovery_check(
	struct iscsi_cmd *cmd,
	unsigned char *buf)
{
	struct iscsi_conn *conn = CONN(cmd);
	struct iscsi_init_scsi_data_out *hdr =
		(struct iscsi_init_scsi_data_out *) buf;

	/*
	 * We do the within-command recovery checks here as it is
	 * the first function called in iscsi_check_pre_dataout().
	 * Basically, if we are in within-command recovery and
	 * the PDU does not contain the offset the sequence needs,
	 * dump the payload.
	 *
	 * This only applies to DataPDUInOrder=Yes, for
	 * DataPDUInOrder=No we only re-request the failed PDU
	 * and check that all PDUs in a sequence are received
	 * upon end of sequence.
	 */
	if (SESS_OPS_C(conn)->DataSequenceInOrder) {
		if ((cmd->cmd_flags & ICF_WITHIN_COMMAND_RECOVERY) &&
		    (cmd->write_data_done != hdr->offset))
			goto dump;

		cmd->cmd_flags &= ~ICF_WITHIN_COMMAND_RECOVERY;
	} else {
		struct iscsi_seq *seq;

		seq = iscsi_get_seq_holder(cmd, hdr->offset, hdr->length);
		if (!(seq))
			return DATAOUT_CANNOT_RECOVER;
		/*
		 * Set the struct iscsi_seq pointer to reuse later.
		 */
		cmd->seq_ptr = seq;

		if (SESS_OPS_C(conn)->DataPDUInOrder) {
			if ((seq->status ==
			     DATAOUT_SEQUENCE_WITHIN_COMMAND_RECOVERY) &&
			   ((seq->offset != hdr->offset) ||
			    (seq->data_sn != hdr->data_sn)))
				goto dump;
		} else {
			if ((seq->status ==
			     DATAOUT_SEQUENCE_WITHIN_COMMAND_RECOVERY) &&
			    (seq->data_sn != hdr->data_sn))
				goto dump;
		}

		if (seq->status == DATAOUT_SEQUENCE_COMPLETE)
			goto dump;

		if (seq->status != DATAOUT_SEQUENCE_COMPLETE)
			seq->status = 0;
	}

	return DATAOUT_NORMAL;

dump:
	printk(KERN_ERR "Dumping DataOUT PDU Offset: %u Length: %d DataSN:"
		" 0x%08x\n", hdr->offset, hdr->length, hdr->data_sn);
	return iscsi_dump_data_payload(conn, hdr->length, 1);
}

/*	iscsi_dataout_check_unsolicited_sequence():
 *
 *
 */
static inline int iscsi_dataout_check_unsolicited_sequence(
	struct iscsi_cmd *cmd,
	unsigned char *buf)
{
	__u32 first_burst_len;
	struct iscsi_conn *conn = CONN(cmd);
	struct iscsi_init_scsi_data_out *hdr =
		(struct iscsi_init_scsi_data_out *) buf;

	if ((hdr->offset < cmd->seq_start_offset) ||
	   ((hdr->offset + hdr->length) > cmd->seq_end_offset)) {
		printk(KERN_ERR "Command ITT: 0x%08x with Offset: %u,"
		" Length: %u outside of Unsolicited Sequence %u:%u while"
		" DataSequenceInOrder=Yes.\n", cmd->init_task_tag,
		hdr->offset, hdr->length, cmd->seq_start_offset,
			cmd->seq_end_offset);
		return DATAOUT_CANNOT_RECOVER;
	}

	first_burst_len = (cmd->first_burst_len + hdr->length);

	if (first_burst_len > SESS_OPS_C(conn)->FirstBurstLength) {
		printk(KERN_ERR "Total %u bytes exceeds FirstBurstLength: %u"
			" for this Unsolicited DataOut Burst.\n",
			first_burst_len, SESS_OPS_C(conn)->FirstBurstLength);
		transport_send_check_condition_and_sense(SE_CMD(cmd),
				INCORRECT_AMOUNT_OF_DATA, 0);
		return DATAOUT_CANNOT_RECOVER;
	}

	/*
	 * Perform various MaxBurstLength and F_BIT sanity checks for the
	 * current Unsolicited DataOUT Sequence.
	 */
	if (hdr->flags & F_BIT) {
		/*
		 * Ignore F_BIT checks while DataPDUInOrder=No, end of
		 * sequence checks are handled in
		 * iscsi_dataout_datapduinorder_no_fbit().
		 */
		if (!SESS_OPS_C(conn)->DataPDUInOrder)
			goto out;

		if ((first_burst_len != cmd->data_length) &&
		    (first_burst_len != SESS_OPS_C(conn)->FirstBurstLength)) {
			printk(KERN_ERR "Unsolicited non-immediate data"
			" received %u does not equal FirstBurstLength: %u, and"
			" does not equal ExpXferLen %u.\n", first_burst_len,
				SESS_OPS_C(conn)->FirstBurstLength,
				cmd->data_length);
			transport_send_check_condition_and_sense(SE_CMD(cmd),
					INCORRECT_AMOUNT_OF_DATA, 0);
			return DATAOUT_CANNOT_RECOVER;
		}
	} else {
		if (first_burst_len == SESS_OPS_C(conn)->FirstBurstLength) {
			printk(KERN_ERR "Command ITT: 0x%08x reached"
			" FirstBurstLength: %u, but F_BIT is not set. protocol"
				" error.\n", cmd->init_task_tag,
				SESS_OPS_C(conn)->FirstBurstLength);
			return DATAOUT_CANNOT_RECOVER;
		}
		if (first_burst_len == cmd->data_length) {
			printk(KERN_ERR "Command ITT: 0x%08x reached"
			" ExpXferLen: %u, but F_BIT is not set. protocol"
			" error.\n", cmd->init_task_tag, cmd->data_length);
			return DATAOUT_CANNOT_RECOVER;
		}
	}

out:
	return DATAOUT_NORMAL;
}

/*	iscsi_dataout_check_sequence():
 *
 *
 */
static inline int iscsi_dataout_check_sequence(
	struct iscsi_cmd *cmd,
	unsigned char *buf)
{
	__u32 next_burst_len;
	struct iscsi_conn *conn = CONN(cmd);
	struct iscsi_seq *seq = NULL;
	struct iscsi_init_scsi_data_out *hdr =
		(struct iscsi_init_scsi_data_out *) buf;

	/*
	 * For DataSequenceInOrder=Yes: Check that the offset and offset+length
	 * is within range as defined by iscsi_set_dataout_sequence_values().
	 *
	 * For DataSequenceInOrder=No: Check that an struct iscsi_seq exists for
	 * offset+length tuple.
	 */
	if (SESS_OPS_C(conn)->DataSequenceInOrder) {
		/*
		 * Due to possibility of recovery DataOUT sent by the initiator
		 * fullfilling an Recovery R2T, it's best to just dump the
		 * payload here, instead of erroring out.
		 */
		if ((hdr->offset < cmd->seq_start_offset) ||
		   ((hdr->offset + hdr->length) > cmd->seq_end_offset)) {
			printk(KERN_ERR "Command ITT: 0x%08x with Offset: %u,"
			" Length: %u outside of Sequence %u:%u while"
			" DataSequenceInOrder=Yes.\n", cmd->init_task_tag,
			hdr->offset, hdr->length, cmd->seq_start_offset,
				cmd->seq_end_offset);

			if (iscsi_dump_data_payload(conn, hdr->length, 1) < 0)
				return DATAOUT_CANNOT_RECOVER;
			return DATAOUT_WITHIN_COMMAND_RECOVERY;
		}

		next_burst_len = (cmd->next_burst_len + hdr->length);
	} else {
		seq = iscsi_get_seq_holder(cmd, hdr->offset, hdr->length);
		if (!(seq))
			return DATAOUT_CANNOT_RECOVER;
		/*
		 * Set the struct iscsi_seq pointer to reuse later.
		 */
		cmd->seq_ptr = seq;

		if (seq->status == DATAOUT_SEQUENCE_COMPLETE) {
			if (iscsi_dump_data_payload(conn, hdr->length, 1) < 0)
				return DATAOUT_CANNOT_RECOVER;
			return DATAOUT_WITHIN_COMMAND_RECOVERY;
		}

		next_burst_len = (seq->next_burst_len + hdr->length);
	}

	if (next_burst_len > SESS_OPS_C(conn)->MaxBurstLength) {
		printk(KERN_ERR "Command ITT: 0x%08x, NextBurstLength: %u and"
			" Length: %u exceeds MaxBurstLength: %u. protocol"
			" error.\n", cmd->init_task_tag,
			(next_burst_len - hdr->length),
			hdr->length, SESS_OPS_C(conn)->MaxBurstLength);
		return DATAOUT_CANNOT_RECOVER;
	}

	/*
	 * Perform various MaxBurstLength and F_BIT sanity checks for the
	 * current DataOUT Sequence.
	 */
	if (hdr->flags & F_BIT) {
		/*
		 * Ignore F_BIT checks while DataPDUInOrder=No, end of
		 * sequence checks are handled in
		 * iscsi_dataout_datapduinorder_no_fbit().
		 */
		if (!SESS_OPS_C(conn)->DataPDUInOrder)
			goto out;

		if (SESS_OPS_C(conn)->DataSequenceInOrder) {
			if ((next_burst_len <
			     SESS_OPS_C(conn)->MaxBurstLength) &&
			   ((cmd->write_data_done + hdr->length) <
			     cmd->data_length)) {
				printk(KERN_ERR "Command ITT: 0x%08x set F_BIT"
				" before end of DataOUT sequence, protocol"
				" error.\n", cmd->init_task_tag);
				return DATAOUT_CANNOT_RECOVER;
			}
		} else {
			if (next_burst_len < seq->xfer_len) {
				printk(KERN_ERR "Command ITT: 0x%08x set F_BIT"
				" before end of DataOUT sequence, protocol"
				" error.\n", cmd->init_task_tag);
				return DATAOUT_CANNOT_RECOVER;
			}
		}
	} else {
		if (SESS_OPS_C(conn)->DataSequenceInOrder) {
			if (next_burst_len ==
					SESS_OPS_C(conn)->MaxBurstLength) {
				printk(KERN_ERR "Command ITT: 0x%08x reached"
				" MaxBurstLength: %u, but F_BIT is not set,"
				" protocol error.", cmd->init_task_tag,
				SESS_OPS_C(conn)->MaxBurstLength);
				return DATAOUT_CANNOT_RECOVER;
			}
			if ((cmd->write_data_done + hdr->length) ==
					cmd->data_length) {
				printk(KERN_ERR "Command ITT: 0x%08x reached"
				" last DataOUT PDU in sequence but F_BIT not"
				" set, protocol error.\n", cmd->init_task_tag);
				return DATAOUT_CANNOT_RECOVER;
			}
		} else {
			if (next_burst_len == seq->xfer_len) {
				printk(KERN_ERR "Command ITT: 0x%08x reached"
				" last DataOUT PDU in sequence but F_BIT not"
				" set, protocol error.\n", cmd->init_task_tag);
				return DATAOUT_CANNOT_RECOVER;
			}
		}
	}

out:
	return DATAOUT_NORMAL;
}

/*	iscsi_dataout_check_datasn():
 *
 *	Called from:	iscsi_check_pre_dataout()
 */
static inline int iscsi_dataout_check_datasn(
	struct iscsi_cmd *cmd,
	unsigned char *buf)
{
	int dump = 0, recovery = 0;
	__u32 data_sn = 0;
	struct iscsi_conn *conn = CONN(cmd);
	struct iscsi_init_scsi_data_out *hdr =
		(struct iscsi_init_scsi_data_out *) buf;

	/*
	 * Considering the target has no method of re-requesting DataOUT
	 * by DataSN, if we receieve a greater DataSN than expected we
	 * assume the functions for DataPDUInOrder=[Yes,No] below will
	 * handle it.
	 *
	 * If the DataSN is less than expected, dump the payload.
	 */
	if (SESS_OPS_C(conn)->DataSequenceInOrder)
		data_sn = cmd->data_sn;
	else {
		struct iscsi_seq *seq = cmd->seq_ptr;
		data_sn = seq->data_sn;
	}

	if (hdr->data_sn > data_sn) {
		printk(KERN_ERR "Command ITT: 0x%08x, received DataSN: 0x%08x"
			" higher than expected 0x%08x.\n", cmd->init_task_tag,
				hdr->data_sn, data_sn);
		recovery = 1;
		goto recover;
	} else if (hdr->data_sn < data_sn) {
		printk(KERN_ERR "Command ITT: 0x%08x, received DataSN: 0x%08x"
			" lower than expected 0x%08x, discarding payload.\n",
			cmd->init_task_tag, hdr->data_sn, data_sn);
		dump = 1;
		goto dump;
	}

	return DATAOUT_NORMAL;

recover:
	if (!SESS_OPS_C(conn)->ErrorRecoveryLevel) {
		printk(KERN_ERR "Unable to perform within-command recovery"
				" while ERL=0.\n");
		return DATAOUT_CANNOT_RECOVER;
	}
dump:
	if (iscsi_dump_data_payload(conn, hdr->length, 1) < 0)
		return DATAOUT_CANNOT_RECOVER;

	return (recovery || dump) ? DATAOUT_WITHIN_COMMAND_RECOVERY :
				DATAOUT_NORMAL;
}

/*	iscsi_dataout_pre_datapduinorder_yes():
 *
 *
 */
static inline int iscsi_dataout_pre_datapduinorder_yes(
	struct iscsi_cmd *cmd,
	unsigned char *buf)
{
	int dump = 0, recovery = 0;
	struct iscsi_conn *conn = CONN(cmd);
	struct iscsi_init_scsi_data_out *hdr =
		(struct iscsi_init_scsi_data_out *) buf;

	/*
	 * For DataSequenceInOrder=Yes: If the offset is greater than the global
	 * DataPDUInOrder=Yes offset counter in struct iscsi_cmd a protcol error has
	 * occured and fail the connection.
	 *
	 * For DataSequenceInOrder=No: If the offset is greater than the per
	 * sequence DataPDUInOrder=Yes offset counter in struct iscsi_seq a protocol
	 * error has occured and fail the connection.
	 */
	if (SESS_OPS_C(conn)->DataSequenceInOrder) {
		if (hdr->offset != cmd->write_data_done) {
			printk(KERN_ERR "Command ITT: 0x%08x, received offset"
			" %u different than expected %u.\n", cmd->init_task_tag,
				hdr->offset, cmd->write_data_done);
			recovery = 1;
			goto recover;
		}
	} else {
		struct iscsi_seq *seq = cmd->seq_ptr;

		if (hdr->offset > seq->offset) {
			printk(KERN_ERR "Command ITT: 0x%08x, received offset"
			" %u greater than expected %u.\n", cmd->init_task_tag,
				hdr->offset, seq->offset);
			recovery = 1;
			goto recover;
		} else if (hdr->offset < seq->offset) {
			printk(KERN_ERR "Command ITT: 0x%08x, received offset"
			" %u less than expected %u, discarding payload.\n",
				cmd->init_task_tag, hdr->offset, seq->offset);
			dump = 1;
			goto dump;
		}
	}

	return DATAOUT_NORMAL;

recover:
	if (!SESS_OPS_C(conn)->ErrorRecoveryLevel) {
		printk(KERN_ERR "Unable to perform within-command recovery"
				" while ERL=0.\n");
		return DATAOUT_CANNOT_RECOVER;
	}
dump:
	if (iscsi_dump_data_payload(conn, hdr->length, 1) < 0)
		return DATAOUT_CANNOT_RECOVER;

	return (recovery) ? iscsi_recover_dataout_sequence(cmd,
		hdr->offset, hdr->length) :
	       (dump) ? DATAOUT_WITHIN_COMMAND_RECOVERY : DATAOUT_NORMAL;
}

/*	iscsi_dataout_pre_datapduinorder_no():
 *
 *	Called from:	iscsi_check_pre_dataout()
 */
static inline int iscsi_dataout_pre_datapduinorder_no(
	struct iscsi_cmd *cmd,
	unsigned char *buf)
{
	struct iscsi_pdu *pdu;
	struct iscsi_init_scsi_data_out *hdr =
		(struct iscsi_init_scsi_data_out *) buf;

	pdu = iscsi_get_pdu_holder(cmd, hdr->offset, hdr->length);
	if (!(pdu))
		return DATAOUT_CANNOT_RECOVER;

	cmd->pdu_ptr = pdu;

	switch (pdu->status) {
	case ISCSI_PDU_NOT_RECEIVED:
	case ISCSI_PDU_CRC_FAILED:
	case ISCSI_PDU_TIMED_OUT:
		break;
	case ISCSI_PDU_RECEIVED_OK:
		printk(KERN_ERR "Command ITT: 0x%08x received already gotten"
			" Offset: %u, Length: %u\n", cmd->init_task_tag,
				hdr->offset, hdr->length);
		return iscsi_dump_data_payload(CONN(cmd), hdr->length, 1);
	default:
		return DATAOUT_CANNOT_RECOVER;
	}

	return DATAOUT_NORMAL;
}

/*	iscsi_dataout_update_r2t():
 *
 *
 */
static int iscsi_dataout_update_r2t(struct iscsi_cmd *cmd, u32 offset, u32 length)
{
	struct iscsi_r2t *r2t;

	if (cmd->unsolicited_data)
		return 0;

	r2t = iscsi_get_r2t_for_eos(cmd, offset, length);
	if (!(r2t))
		return -1;

	spin_lock_bh(&cmd->r2t_lock);
	r2t->seq_complete = 1;
	cmd->outstanding_r2ts--;
	spin_unlock_bh(&cmd->r2t_lock);

	return 0;
}

/*	iscsi_dataout_update_datapduinorder_no():
 *
 *
 */
static int iscsi_dataout_update_datapduinorder_no(
	struct iscsi_cmd *cmd,
	u32 data_sn,
	int f_bit)
{
	int ret = 0;
	struct iscsi_pdu *pdu = cmd->pdu_ptr;

	pdu->data_sn = data_sn;

	switch (pdu->status) {
	case ISCSI_PDU_NOT_RECEIVED:
		pdu->status = ISCSI_PDU_RECEIVED_OK;
		break;
	case ISCSI_PDU_CRC_FAILED:
		pdu->status = ISCSI_PDU_RECEIVED_OK;
		break;
	case ISCSI_PDU_TIMED_OUT:
		pdu->status = ISCSI_PDU_RECEIVED_OK;
		break;
	default:
		return DATAOUT_CANNOT_RECOVER;
	}

	if (f_bit) {
		ret = iscsi_dataout_datapduinorder_no_fbit(cmd, pdu);
		if (ret == DATAOUT_CANNOT_RECOVER)
			return ret;
	}

	return DATAOUT_NORMAL;
}

/*	iscsi_dataout_post_crc_passed():
 *
 *	Called from:	iscsi_check_post_dataout()
 */
static inline int iscsi_dataout_post_crc_passed(
	struct iscsi_cmd *cmd,
	unsigned char *buf)
{
	int ret, send_r2t = 0;
	struct iscsi_conn *conn = CONN(cmd);
	struct iscsi_seq *seq = NULL;
	struct iscsi_init_scsi_data_out *hdr =
		(struct iscsi_init_scsi_data_out *) buf;

	if (cmd->unsolicited_data) {
		if ((cmd->first_burst_len + hdr->length) ==
		     SESS_OPS_C(conn)->FirstBurstLength) {
			if (iscsi_dataout_update_r2t(cmd, hdr->offset,
					hdr->length) < 0)
				return DATAOUT_CANNOT_RECOVER;
			send_r2t = 1;
		}

		if (!SESS_OPS_C(conn)->DataPDUInOrder) {
			ret = iscsi_dataout_update_datapduinorder_no(cmd,
				hdr->data_sn, (hdr->flags & F_BIT));
			if (ret == DATAOUT_CANNOT_RECOVER)
				return ret;
		}

		cmd->first_burst_len += hdr->length;

		if (SESS_OPS_C(conn)->DataSequenceInOrder)
			cmd->data_sn++;
		else {
			seq = cmd->seq_ptr;
			seq->data_sn++;
			seq->offset += hdr->length;
		}

		if (send_r2t) {
			if (seq)
				seq->status = DATAOUT_SEQUENCE_COMPLETE;
			cmd->first_burst_len = 0;
			cmd->unsolicited_data = 0;
		}
	} else {
		if (SESS_OPS_C(conn)->DataSequenceInOrder) {
			if ((cmd->next_burst_len + hdr->length) ==
			     SESS_OPS_C(conn)->MaxBurstLength) {
				if (iscsi_dataout_update_r2t(cmd, hdr->offset,
						hdr->length) < 0)
					return DATAOUT_CANNOT_RECOVER;
				send_r2t = 1;
			}

			if (!SESS_OPS_C(conn)->DataPDUInOrder) {
				ret = iscsi_dataout_update_datapduinorder_no(
						cmd, hdr->data_sn,
						(hdr->flags & F_BIT));
				if (ret == DATAOUT_CANNOT_RECOVER)
					return ret;
			}

			cmd->next_burst_len += hdr->length;
			cmd->data_sn++;

			if (send_r2t)
				cmd->next_burst_len = 0;
		} else {
			seq = cmd->seq_ptr;

			if ((seq->next_burst_len + hdr->length) ==
			     seq->xfer_len) {
				if (iscsi_dataout_update_r2t(cmd, hdr->offset,
						hdr->length) < 0)
					return DATAOUT_CANNOT_RECOVER;
				send_r2t = 1;
			}

			if (!SESS_OPS_C(conn)->DataPDUInOrder) {
				ret = iscsi_dataout_update_datapduinorder_no(
						cmd, hdr->data_sn,
						(hdr->flags & F_BIT));
				if (ret == DATAOUT_CANNOT_RECOVER)
					return ret;
			}

			seq->data_sn++;
			seq->offset += hdr->length;
			seq->next_burst_len += hdr->length;

			if (send_r2t) {
				seq->next_burst_len = 0;
				seq->status = DATAOUT_SEQUENCE_COMPLETE;
			}
		}
	}

	if (send_r2t && SESS_OPS_C(conn)->DataSequenceInOrder)
		cmd->data_sn = 0;

	cmd->write_data_done += hdr->length;

	return (cmd->write_data_done == cmd->data_length) ?
		DATAOUT_SEND_TO_TRANSPORT : (send_r2t) ?
		DATAOUT_SEND_R2T : DATAOUT_NORMAL;
}

/*	iscsi_dataout_post_crc_failed():
 *
 *	Called from:	iscsi_check_post_dataout()
 */
static inline int iscsi_dataout_post_crc_failed(
	struct iscsi_cmd *cmd,
	unsigned char *buf)
{
	struct iscsi_conn *conn = CONN(cmd);
	struct iscsi_pdu *pdu;
	struct iscsi_init_scsi_data_out *hdr =
		(struct iscsi_init_scsi_data_out *) buf;

	if (SESS_OPS_C(conn)->DataPDUInOrder)
		goto recover;

	/*
	 * The rest of this function is only called when DataPDUInOrder=No.
	 */
	pdu = cmd->pdu_ptr;

	switch (pdu->status) {
	case ISCSI_PDU_NOT_RECEIVED:
		pdu->status = ISCSI_PDU_CRC_FAILED;
		break;
	case ISCSI_PDU_CRC_FAILED:
		break;
	case ISCSI_PDU_TIMED_OUT:
		pdu->status = ISCSI_PDU_CRC_FAILED;
		break;
	default:
		return DATAOUT_CANNOT_RECOVER;
	}

recover:
	return iscsi_recover_dataout_sequence(cmd, hdr->offset, hdr->length);
}

/*	iscsi_check_pre_dataout():
 *
 *	Called from iscsi_handle_data_out() before DataOUT Payload is received
 *	and CRC computed.
 */
extern int iscsi_check_pre_dataout(
	struct iscsi_cmd *cmd,
	unsigned char *buf)
{
	int ret;
	struct iscsi_conn *conn = CONN(cmd);

	ret = iscsi_dataout_within_command_recovery_check(cmd, buf);
	if ((ret == DATAOUT_WITHIN_COMMAND_RECOVERY) ||
	    (ret == DATAOUT_CANNOT_RECOVER))
		return ret;

	ret = iscsi_dataout_check_datasn(cmd, buf);
	if ((ret == DATAOUT_WITHIN_COMMAND_RECOVERY) ||
	    (ret == DATAOUT_CANNOT_RECOVER))
		return ret;

	if (cmd->unsolicited_data) {
		ret = iscsi_dataout_check_unsolicited_sequence(cmd, buf);
		if ((ret == DATAOUT_WITHIN_COMMAND_RECOVERY) ||
		    (ret == DATAOUT_CANNOT_RECOVER))
			return ret;
	} else {
		ret = iscsi_dataout_check_sequence(cmd, buf);
		if ((ret == DATAOUT_WITHIN_COMMAND_RECOVERY) ||
		    (ret == DATAOUT_CANNOT_RECOVER))
			return ret;
	}

	return (SESS_OPS_C(conn)->DataPDUInOrder) ?
		iscsi_dataout_pre_datapduinorder_yes(cmd, buf) :
		iscsi_dataout_pre_datapduinorder_no(cmd, buf);
}

/*	iscsi_check_post_dataout():
 *
 *	Called from iscsi_handle_data_out() after DataOUT Payload is received
 *	and CRC computed.
 */
int iscsi_check_post_dataout(
	struct iscsi_cmd *cmd,
	unsigned char *buf,
	__u8 data_crc_failed)
{
	struct iscsi_conn *conn = CONN(cmd);

	cmd->dataout_timeout_retries = 0;

	if (!data_crc_failed)
		return iscsi_dataout_post_crc_passed(cmd, buf);
	else {
		if (!SESS_OPS_C(conn)->ErrorRecoveryLevel) {
			printk(KERN_ERR "Unable to recover from DataOUT CRC"
				" failure while ERL=0, closing session.\n");
			iscsi_add_reject_from_cmd(REASON_DATA_DIGEST_ERR,
					1, 0, buf, cmd);
			return DATAOUT_CANNOT_RECOVER;
		}

		iscsi_add_reject_from_cmd(REASON_DATA_DIGEST_ERR,
				0, 0, buf, cmd);
		return iscsi_dataout_post_crc_failed(cmd, buf);
	}
}

/*	iscsi_handle_time2retain_timeout():
 *
 *
 */
static void iscsi_handle_time2retain_timeout(unsigned long data)
{
	struct iscsi_session *sess = (struct iscsi_session *) data;
	struct iscsi_portal_group *tpg = ISCSI_TPG_S(sess);
	struct se_portal_group *se_tpg = &tpg->tpg_se_tpg;

	spin_lock_bh(&se_tpg->session_lock);
	if (sess->time2retain_timer_flags & T2R_TF_STOP) {
		spin_unlock_bh(&se_tpg->session_lock);
		return;
	}
	if (atomic_read(&sess->session_reinstatement)) {
		printk(KERN_ERR "Exiting Time2Retain handler because"
				" session_reinstatement=1\n");
		spin_unlock_bh(&se_tpg->session_lock);
		return;
	}
	sess->time2retain_timer_flags |= T2R_TF_EXPIRED;

	printk(KERN_ERR "Time2Retain timer expired for SID: %u, cleaning up"
			" iSCSI session.\n", sess->sid);
#ifdef SNMP_SUPPORT
	{
	struct iscsi_tiqn *tiqn = tpg->tpg_tiqn;

	if (tiqn) {
		spin_lock(&tiqn->sess_err_stats.lock);
		strcpy(tiqn->sess_err_stats.last_sess_fail_rem_name,
			(void *)SESS_OPS(sess)->InitiatorName);
		tiqn->sess_err_stats.last_sess_failure_type =
				ISCSI_SESS_ERR_CXN_TIMEOUT;
		tiqn->sess_err_stats.cxn_timeout_errors++;
		sess->conn_timeout_errors++;
		spin_unlock(&tiqn->sess_err_stats.lock);
	}
	}
#endif /* SNMP_SUPPORT */

	spin_unlock_bh(&se_tpg->session_lock);
	iscsi_close_session(sess);
}

/*	iscsi_start_session_cleanup_handler():
 *
 *
 */
extern void iscsi_start_time2retain_handler (struct iscsi_session *sess)
{
	int tpg_active;

	/*
	 * Only start Time2Retain timer when the assoicated TPG is still in
	 * an ACTIVE (eg: not disabled or shutdown) state.
	 */
	spin_lock(&ISCSI_TPG_S(sess)->tpg_state_lock);
	tpg_active = (ISCSI_TPG_S(sess)->tpg_state == TPG_STATE_ACTIVE);
	spin_unlock(&ISCSI_TPG_S(sess)->tpg_state_lock);

	if (!(tpg_active))
		return;

	if (sess->time2retain_timer_flags & T2R_TF_RUNNING)
		return;

	TRACE(TRACE_TIMER, "Starting Time2Retain timer for %u seconds on"
		" SID: %u\n", SESS_OPS(sess)->DefaultTime2Retain, sess->sid);

	init_timer(&sess->time2retain_timer);
	SETUP_TIMER(sess->time2retain_timer, SESS_OPS(sess)->DefaultTime2Retain,
			sess, iscsi_handle_time2retain_timeout);
	sess->time2retain_timer_flags &= ~T2R_TF_STOP;
	sess->time2retain_timer_flags |= T2R_TF_RUNNING;
	add_timer(&sess->time2retain_timer);

	return;
}

/*	iscsi_stop_time2retain_timer():
 *
 *	Called with spin_lock_bh(&struct se_portal_group->session_lock) held
 */
extern int iscsi_stop_time2retain_timer(struct iscsi_session *sess)
{
	struct iscsi_portal_group *tpg = ISCSI_TPG_S(sess);
	struct se_portal_group *se_tpg = &tpg->tpg_se_tpg;

	if (sess->time2retain_timer_flags & T2R_TF_EXPIRED)
		return -1;

	if (!(sess->time2retain_timer_flags & T2R_TF_RUNNING))
		return 0;

	sess->time2retain_timer_flags |= T2R_TF_STOP;
	spin_unlock_bh(&se_tpg->session_lock);

	del_timer_sync(&sess->time2retain_timer);

	spin_lock_bh(&se_tpg->session_lock);
	sess->time2retain_timer_flags &= ~T2R_TF_RUNNING;
	TRACE(TRACE_TIMER, "Stopped Time2Retain Timer for SID: %u\n",
			sess->sid);
	return 0;
}

/*	iscsi_connection_reinstatement_rcfr():
 *
 *
 */
void iscsi_connection_reinstatement_rcfr(struct iscsi_conn *conn)
{
	spin_lock_bh(&conn->state_lock);
	if (atomic_read(&conn->connection_exit)) {
		spin_unlock_bh(&conn->state_lock);
		goto sleep;
	}

	if (atomic_read(&conn->transport_failed)) {
		spin_unlock_bh(&conn->state_lock);
		goto sleep;
	}
	spin_unlock_bh(&conn->state_lock);

	iscsi_thread_set_force_reinstatement(conn);

sleep:
	down(&conn->conn_wait_rcfr_sem);
	up(&conn->conn_post_wait_sem);
}

/*	iscsi_cause_connection_reinstatement():
 *
 *
 */
void iscsi_cause_connection_reinstatement(struct iscsi_conn *conn, int sleep)
{
	spin_lock_bh(&conn->state_lock);
	if (atomic_read(&conn->connection_exit)) {
		spin_unlock_bh(&conn->state_lock);
		return;
	}

	if (atomic_read(&conn->transport_failed)) {
		spin_unlock_bh(&conn->state_lock);
		return;
	}

	if (atomic_read(&conn->connection_reinstatement)) {
		spin_unlock_bh(&conn->state_lock);
		return;
	}

	if (iscsi_thread_set_force_reinstatement(conn) < 0) {
		spin_unlock_bh(&conn->state_lock);
		return;
	}

	atomic_set(&conn->connection_reinstatement, 1);
	if (!sleep) {
		spin_unlock_bh(&conn->state_lock);
		return;
	}

	atomic_set(&conn->sleep_on_conn_wait_sem, 1);
	spin_unlock_bh(&conn->state_lock);

	down(&conn->conn_wait_sem);
	up(&conn->conn_post_wait_sem);
}

/*	iscsi_fall_back_to_erl0():
 *
 *
 */
void iscsi_fall_back_to_erl0(struct iscsi_session *sess)
{
	TRACE(TRACE_ERL0, "Falling back to ErrorRecoveryLevel=0 for SID:"
			" %u\n", sess->sid);

	atomic_set(&sess->session_fall_back_to_erl0, 1);
}

/*	iscsi_handle_connection_cleanup():
 *
 *
 */
static void iscsi_handle_connection_cleanup(struct iscsi_conn *conn)
{
	struct iscsi_session *sess = SESS(conn);

	if ((SESS_OPS(sess)->ErrorRecoveryLevel == 2) &&
	    !atomic_read(&sess->session_reinstatement) &&
	    !atomic_read(&sess->session_fall_back_to_erl0))
		iscsi_connection_recovery_transport_reset(conn);
	else {
		TRACE(TRACE_ERL0, "Performing cleanup for failed iSCSI"
			" Connection ID: %hu from %s\n", conn->cid,
			SESS_OPS(sess)->InitiatorName);
		iscsi_close_connection(conn);
	}
}

/*	iscsi_take_action_for_connection_exit():
 *
 *
 */
extern void iscsi_take_action_for_connection_exit(struct iscsi_conn *conn)
{
	spin_lock_bh(&conn->state_lock);
	if (atomic_read(&conn->connection_exit)) {
		spin_unlock_bh(&conn->state_lock);
		return;
	}
	atomic_set(&conn->connection_exit, 1);

	if (conn->conn_state == TARG_CONN_STATE_IN_LOGOUT) {
		spin_unlock_bh(&conn->state_lock);
		iscsi_close_connection(conn);
		return;
	}

	if (conn->conn_state == TARG_CONN_STATE_CLEANUP_WAIT) {
		spin_unlock_bh(&conn->state_lock);
		return;
	}

	TRACE(TRACE_STATE, "Moving to TARG_CONN_STATE_CLEANUP_WAIT.\n");
	conn->conn_state = TARG_CONN_STATE_CLEANUP_WAIT;
	spin_unlock_bh(&conn->state_lock);

	iscsi_handle_connection_cleanup(conn);
}

/*	iscsi_recover_from_unknown_opcode():
 *
 *	This is the simple function that makes the magic of
 *	sync and steering happen in the follow paradoxical order:
 *
 *	0) Receive conn->of_marker (bytes left until next OFMarker)
 *	   bytes into an offload buffer.  When we pass the exact number
 *	   of bytes in conn->of_marker, iscsi_dump_data_payload() and hence
 *	   rx_data() will automatically receive the identical __u32 marker
 *	   values and store it in conn->of_marker_offset;
 *	1) Now conn->of_marker_offset will contain the offset to the start
 *	   of the next iSCSI PDU.  Dump these remaining bytes into another
 *	   offload buffer.
 *	2) We are done!
 *	   Next byte in the TCP stream will contain the next iSCSI PDU!
 *	   Cool Huh?!
 */
int iscsi_recover_from_unknown_opcode(struct iscsi_conn *conn)
{
	/*
	 * Make sure the remaining bytes to next maker is a sane value.
	 */
	if (conn->of_marker > (CONN_OPS(conn)->OFMarkInt * 4)) {
		printk(KERN_ERR "Remaining bytes to OFMarker: %u exceeds"
			" OFMarkInt bytes: %u.\n", conn->of_marker,
				CONN_OPS(conn)->OFMarkInt * 4);
		return -1;
	}

	TRACE(TRACE_ERL1, "Advancing %u bytes in TCP stream to get to the"
			" next OFMarker.\n", conn->of_marker);

	if (iscsi_dump_data_payload(conn, conn->of_marker, 0) < 0)
		return -1;

	/*
	 * Make sure the offset marker we retrived is a valid value.
	 */
	if (conn->of_marker_offset > (ISCSI_HDR_LEN + (CRC_LEN * 2) +
	    CONN_OPS(conn)->MaxRecvDataSegmentLength)) {
		printk(KERN_ERR "OfMarker offset value: %u exceeds limit.\n",
			conn->of_marker_offset);
		return -1;
	}

	TRACE(TRACE_ERL1, "Discarding %u bytes of TCP stream to get to the"
			" next iSCSI Opcode.\n", conn->of_marker_offset);

	if (iscsi_dump_data_payload(conn, conn->of_marker_offset, 0) < 0)
		return -1;

	return 0;
}

