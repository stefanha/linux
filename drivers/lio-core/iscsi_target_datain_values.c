/*********************************************************************************
 * Filename:  iscsi_target_datain_values.c
 *
 * This file contains the iSCSI Target DataIN value generation functions.
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

#define ISCSI_TARGET_DATAIN_VALUES_C

#include <linux/delay.h>
#include <linux/string.h>
#include <linux/timer.h>
#include <linux/slab.h>
#include <linux/init.h>
#include <linux/spinlock.h>
#include <linux/smp_lock.h>
#include <linux/in.h>

#include <iscsi_linux_os.h>
#include <iscsi_linux_defs.h>

#include <iscsi_debug.h>
#include <iscsi_protocol.h>
#include <iscsi_lists.h>
#include <iscsi_target_core.h>
#include <iscsi_target_erl1.h>
#include <iscsi_target_util.h>
#include <iscsi_target_datain_values.h>

#undef ISCSI_TARGET_DATAIN_VALUES_C

extern se_global_t *iscsi_global;

extern iscsi_datain_req_t *iscsi_allocate_datain_req (void)
{
	iscsi_datain_req_t *dr;

	if (!(dr = kmalloc(sizeof(iscsi_datain_req_t), GFP_ATOMIC))) {
		TRACE_ERROR("Unable to allocate memory for iscsi_datain_req_t\n");
		return(NULL);
	}
	memset(dr, 0, sizeof(iscsi_datain_req_t));

	return(dr);
}

extern void iscsi_attach_datain_req (
	iscsi_cmd_t *cmd,
	iscsi_datain_req_t *dr)
{
	spin_lock(&cmd->datain_lock);
	ADD_ENTRY_TO_LIST(dr, cmd->datain_req_head, cmd->datain_req_tail);
	spin_unlock(&cmd->datain_lock);

	return;
}

extern void iscsi_free_datain_req (
	iscsi_cmd_t *cmd,
	iscsi_datain_req_t *dr)
{
	spin_lock(&cmd->datain_lock);
	REMOVE_ENTRY_FROM_LIST(dr, cmd->datain_req_head, cmd->datain_req_tail);
	spin_unlock(&cmd->datain_lock);

	kfree(dr);

	return;
}

extern void iscsi_free_all_datain_reqs (
	iscsi_cmd_t *cmd)
{
	iscsi_datain_req_t *dr, *dr_next = NULL;

	spin_lock(&cmd->datain_lock);
	dr = cmd->datain_req_head;
	while (dr) {
		dr_next = dr->next;
		kfree(dr);	
		dr = dr_next;
	}
	cmd->datain_req_head = cmd->datain_req_tail = NULL;
	spin_unlock(&cmd->datain_lock);

	return;
}

extern iscsi_datain_req_t *iscsi_get_datain_req (
	iscsi_cmd_t *cmd)
{
	if (!cmd->datain_req_head) {
		TRACE_ERROR("cmd->datain_req_head is NULL for ITT: 0x%08x\n", cmd->init_task_tag);
		return(NULL);
	}

	return(cmd->datain_req_head);
}

/*	iscsi_set_datain_values_yes_and_yes():
 *
 *	For Normal and Recovery DataSequenceInOrder=Yes and DataPDUInOrder=Yes.
 */
static inline iscsi_datain_req_t *iscsi_set_datain_values_yes_and_yes (
	iscsi_cmd_t *cmd,
	iscsi_datain_t *datain)
{
	__u32 next_burst_len, read_data_done, read_data_left;
	iscsi_conn_t *conn = CONN(cmd);
	iscsi_datain_req_t *dr;

	if (!(dr = iscsi_get_datain_req(cmd)))
		return(NULL);

	if (dr->recovery && dr->generate_recovery_values) {
		if (iscsi_create_recovery_datain_values_datasequenceinorder_yes(cmd, dr) < 0)
			return(NULL);
		
		dr->generate_recovery_values = 0;
	}

	next_burst_len = (!dr->recovery) ? cmd->next_burst_len : dr->next_burst_len;
	read_data_done = (!dr->recovery) ? cmd->read_data_done : dr->read_data_done;
	
	if (!(read_data_left = (cmd->data_length - read_data_done))) {
		TRACE_ERROR("ITT: 0x%08x read_data_left is zero!\n",
				cmd->init_task_tag);
		return(NULL);
	}
	
	if ((read_data_left <= CONN_OPS(conn)->MaxRecvDataSegmentLength) &&
	    (read_data_left <= (SESS_OPS_C(conn)->MaxBurstLength -
	     next_burst_len))) {
		datain->length = read_data_left;

		datain->flags |= (F_BIT | S_BIT);
		if (SESS_OPS_C(conn)->ErrorRecoveryLevel > 0)
			datain->flags |= A_BIT;
	} else {
		if ((next_burst_len + CONN_OPS(conn)->MaxRecvDataSegmentLength) <
		     SESS_OPS_C(conn)->MaxBurstLength) {
			datain->length = CONN_OPS(conn)->MaxRecvDataSegmentLength;
			next_burst_len += datain->length;
		} else {
			datain->length = (SESS_OPS_C(conn)->MaxBurstLength -
					  next_burst_len);
			next_burst_len = 0;

			datain->flags |= F_BIT;
			if (SESS_OPS_C(conn)->ErrorRecoveryLevel > 0)
				datain->flags |= A_BIT;
		}
	}

	datain->data_sn = (!dr->recovery) ? cmd->data_sn++ : dr->data_sn++;
	datain->offset = read_data_done;
	
	if (!dr->recovery) {
		cmd->next_burst_len = next_burst_len;
		cmd->read_data_done += datain->length;
	} else {
		dr->next_burst_len = next_burst_len;
		dr->read_data_done += datain->length;
	}

	if (!dr->recovery) {
		if (datain->flags & S_BIT)
			dr->dr_complete = DATAIN_COMPLETE_NORMAL;

		return(dr);
	}
	
        if (!dr->runlength) {
		if (datain->flags & S_BIT) {
			dr->dr_complete = (dr->recovery == DATAIN_WITHIN_COMMAND_RECOVERY) ?
				DATAIN_COMPLETE_WITHIN_COMMAND_RECOVERY :
				DATAIN_COMPLETE_CONNECTION_RECOVERY;
		}
	} else {
		if ((dr->begrun + dr->runlength) == dr->data_sn) {
			dr->dr_complete = (dr->recovery == DATAIN_WITHIN_COMMAND_RECOVERY) ?
				DATAIN_COMPLETE_WITHIN_COMMAND_RECOVERY :
				DATAIN_COMPLETE_CONNECTION_RECOVERY;
		}
	}

	return(dr);	
}

/*	iscsi_set_datain_values_no_and_yes():
 *
 *	For Normal and Recovery DataSequenceInOrder=No and DataPDUInOrder=Yes.
 */
static inline iscsi_datain_req_t *iscsi_set_datain_values_no_and_yes (
	iscsi_cmd_t *cmd,
	iscsi_datain_t *datain)
{
	__u32 offset, read_data_done, read_data_left, seq_send_order;
	iscsi_conn_t *conn = CONN(cmd);
	iscsi_datain_req_t *dr;
	iscsi_seq_t *seq;

	if (!(dr = iscsi_get_datain_req(cmd)))
		return(NULL);

	if (dr->recovery && dr->generate_recovery_values) {
		if (iscsi_create_recovery_datain_values_datasequenceinorder_no(cmd, dr) < 0)
			return(NULL);

		dr->generate_recovery_values = 0;
	}

	read_data_done = (!dr->recovery) ? cmd->read_data_done : dr->read_data_done;
	seq_send_order = (!dr->recovery) ? cmd->seq_send_order : dr->seq_send_order;

	if (!(read_data_left = (cmd->data_length - read_data_done))) {
		TRACE_ERROR("ITT: 0x%08x read_data_left is zero!\n",
				cmd->init_task_tag);
		return(NULL);
	}
	
	if (!(seq = iscsi_get_seq_holder_for_datain(cmd, seq_send_order)))
		return(NULL);

	seq->sent = 1;
	
	if (!dr->recovery && !seq->next_burst_len)
		seq->first_datasn = cmd->data_sn;
		
	offset = (seq->offset + seq->next_burst_len);

	if ((offset + CONN_OPS(conn)->MaxRecvDataSegmentLength) >=
	     cmd->data_length) {
		datain->length = (cmd->data_length - offset);
		datain->offset = offset;

		datain->flags |= F_BIT;
		if (SESS_OPS_C(conn)->ErrorRecoveryLevel > 0)
			datain->flags |= A_BIT;
		
		seq->next_burst_len = 0;
		seq_send_order++;
	} else {
		if ((seq->next_burst_len + CONN_OPS(conn)->MaxRecvDataSegmentLength) <
		     SESS_OPS_C(conn)->MaxBurstLength) {
			datain->length = CONN_OPS(conn)->MaxRecvDataSegmentLength;
			datain->offset = (seq->offset + seq->next_burst_len);

			seq->next_burst_len += datain->length;
		} else {
			datain->length = (SESS_OPS_C(conn)->MaxBurstLength -
					  seq->next_burst_len);
			datain->offset = (seq->offset + seq->next_burst_len);

			datain->flags |= F_BIT;
			if (SESS_OPS_C(conn)->ErrorRecoveryLevel > 0)
				datain->flags |= A_BIT;

			seq->next_burst_len = 0;
			seq_send_order++;
		}
	}

	if ((read_data_done + datain->length) == cmd->data_length)
		datain->flags |= S_BIT;
	
	datain->data_sn = (!dr->recovery) ? cmd->data_sn++ : dr->data_sn++;
	if (!dr->recovery) {
		cmd->seq_send_order = seq_send_order;
		cmd->read_data_done += datain->length;
	} else {
		dr->seq_send_order = seq_send_order;
		dr->read_data_done += datain->length;
	}
	
	if (!dr->recovery) {
		if (datain->flags & F_BIT)
			seq->last_datasn = datain->data_sn;
		if (datain->flags & S_BIT)
			dr->dr_complete = DATAIN_COMPLETE_NORMAL;
		
		return(dr);
	}

	if (!dr->runlength) {
		if (datain->flags & S_BIT) {
			dr->dr_complete = (dr->recovery == DATAIN_WITHIN_COMMAND_RECOVERY) ?
				DATAIN_COMPLETE_WITHIN_COMMAND_RECOVERY :
				DATAIN_COMPLETE_CONNECTION_RECOVERY;
		}
	} else {
		if ((dr->begrun + dr->runlength) == dr->data_sn) {
			dr->dr_complete = (dr->recovery == DATAIN_WITHIN_COMMAND_RECOVERY) ?
				DATAIN_COMPLETE_WITHIN_COMMAND_RECOVERY :
				DATAIN_COMPLETE_CONNECTION_RECOVERY;
		}
	}
		
	return(dr);
}

/*	iscsi_set_datain_values_yes_and_no():
 *
 *	For Normal and Recovery DataSequenceInOrder=Yes and DataPDUInOrder=No.
 */
static inline iscsi_datain_req_t *iscsi_set_datain_values_yes_and_no (
	iscsi_cmd_t *cmd,
	iscsi_datain_t *datain)
{
	__u32 next_burst_len, read_data_done, read_data_left;
	iscsi_conn_t *conn = CONN(cmd);
	iscsi_datain_req_t *dr;
	iscsi_pdu_t *pdu;

	if (!(dr = iscsi_get_datain_req(cmd)))
		return(NULL);

	if (dr->recovery && dr->generate_recovery_values) {
		if (iscsi_create_recovery_datain_values_datasequenceinorder_yes(cmd, dr) < 0)
			return(NULL);

		dr->generate_recovery_values = 0;
	}

	next_burst_len = (!dr->recovery) ? cmd->next_burst_len : dr->next_burst_len;
	read_data_done = (!dr->recovery) ? cmd->read_data_done : dr->read_data_done;
	
	if (!(read_data_left = (cmd->data_length - read_data_done))) {
		TRACE_ERROR("ITT: 0x%08x read_data_left is zero!\n",
				cmd->init_task_tag);
		return(dr);
	}

	if (!(pdu = iscsi_get_pdu_holder_for_seq(cmd, NULL)))
		return(dr);

	if ((read_data_done + pdu->length) == cmd->data_length) {
		pdu->flags |= (F_BIT | S_BIT);
		if (SESS_OPS_C(conn)->ErrorRecoveryLevel > 0)
			pdu->flags |= A_BIT;
		
		next_burst_len = 0;
	} else {
		if ((next_burst_len + CONN_OPS(conn)->MaxRecvDataSegmentLength) <
		     SESS_OPS_C(conn)->MaxBurstLength)
			next_burst_len += pdu->length;
		else {
			pdu->flags |= F_BIT;
			if (SESS_OPS_C(conn)->ErrorRecoveryLevel > 0)
				pdu->flags |= A_BIT;

			next_burst_len = 0;
		}
	}

	pdu->data_sn = (!dr->recovery) ? cmd->data_sn++ : dr->data_sn++;
	if (!dr->recovery) {
		cmd->next_burst_len = next_burst_len;
		cmd->read_data_done += pdu->length;
	} else {
		dr->next_burst_len = next_burst_len;
		dr->read_data_done += pdu->length;
	}
	
	datain->flags = pdu->flags;
	datain->length = pdu->length;
	datain->offset = pdu->offset;
	datain->data_sn = pdu->data_sn;

	if (!dr->recovery) {
		if (datain->flags & S_BIT)
			dr->dr_complete = DATAIN_COMPLETE_NORMAL;

		return(dr);
	}

	if (!dr->runlength) {
		if (datain->flags & S_BIT) {
			dr->dr_complete = (dr->recovery == DATAIN_WITHIN_COMMAND_RECOVERY) ?
				DATAIN_COMPLETE_WITHIN_COMMAND_RECOVERY :
				DATAIN_COMPLETE_CONNECTION_RECOVERY;
		}
	} else {
		if ((dr->begrun + dr->runlength) == dr->data_sn) {
			dr->dr_complete = (dr->recovery == DATAIN_WITHIN_COMMAND_RECOVERY) ?
				DATAIN_COMPLETE_WITHIN_COMMAND_RECOVERY :
				DATAIN_COMPLETE_CONNECTION_RECOVERY;
		}
	}
	
	return(dr);
}

/*	iscsi_set_datain_values_no_and_no():
 *
 *	For Normal and Recovery DataSequenceInOrder=No and DataPDUInOrder=No.
 */
static inline iscsi_datain_req_t *iscsi_set_datain_values_no_and_no (
	iscsi_cmd_t *cmd,
	iscsi_datain_t *datain)
{
	__u32 read_data_done, read_data_left, seq_send_order;
	iscsi_conn_t *conn = CONN(cmd);
	iscsi_datain_req_t *dr;
	iscsi_pdu_t *pdu;
	iscsi_seq_t *seq = NULL;

	if (!(dr = iscsi_get_datain_req(cmd)))
		return(NULL);

	if (dr->recovery && dr->generate_recovery_values) {
		if (iscsi_create_recovery_datain_values_datasequenceinorder_no(cmd, dr) < 0)
			return(NULL);

		dr->generate_recovery_values = 0;
	}

	read_data_done = (!dr->recovery) ? cmd->read_data_done : dr->read_data_done;
	seq_send_order = (!dr->recovery) ? cmd->seq_send_order : dr->seq_send_order;
	
	if (!(read_data_left = (cmd->data_length - read_data_done))) {
		TRACE_ERROR("ITT: 0x%08x read_data_left is zero!\n",
				cmd->init_task_tag);
		return(NULL);
	}
	
	if (!(seq = iscsi_get_seq_holder_for_datain(cmd, seq_send_order)))
		return(NULL);

	seq->sent = 1;
	
	if (!dr->recovery && !seq->next_burst_len)
		seq->first_datasn = cmd->data_sn;
	
	if (!(pdu = iscsi_get_pdu_holder_for_seq(cmd, seq)))
		return(NULL);

	if (seq->pdu_send_order == seq->pdu_count) {
		pdu->flags |= F_BIT;
		if (SESS_OPS_C(conn)->ErrorRecoveryLevel > 0)
			pdu->flags |= A_BIT;

		seq->next_burst_len = 0;
		seq_send_order++;
	} else
		seq->next_burst_len += pdu->length;
	
        if ((read_data_done + pdu->length) == cmd->data_length)
		pdu->flags |= S_BIT;

	pdu->data_sn = (!dr->recovery) ? cmd->data_sn++ : dr->data_sn++;
	if (!dr->recovery) {
		cmd->seq_send_order = seq_send_order;
		cmd->read_data_done += pdu->length;
	} else {
		dr->seq_send_order = seq_send_order;
		dr->read_data_done += pdu->length;
	}
	       
	datain->flags = pdu->flags;
	datain->length = pdu->length;
	datain->offset = pdu->offset;
	datain->data_sn = pdu->data_sn;
	
	if (!dr->recovery) {
                if (datain->flags & F_BIT)
			seq->last_datasn = datain->data_sn;
		if (datain->flags & S_BIT)
			dr->dr_complete = DATAIN_COMPLETE_NORMAL;

		return(dr);
	}

	if (!dr->runlength) {
		if (datain->flags & S_BIT) {
			dr->dr_complete = (dr->recovery == DATAIN_WITHIN_COMMAND_RECOVERY) ?
				DATAIN_COMPLETE_WITHIN_COMMAND_RECOVERY :
				DATAIN_COMPLETE_CONNECTION_RECOVERY;
		}
	} else {
		if ((dr->begrun + dr->runlength) == dr->data_sn) {
			dr->dr_complete = (dr->recovery == DATAIN_WITHIN_COMMAND_RECOVERY) ?
				DATAIN_COMPLETE_WITHIN_COMMAND_RECOVERY :
				DATAIN_COMPLETE_CONNECTION_RECOVERY;
		}
	}
	
	return(dr);
}

/*	iscsi_get_datain_values():
 *
 *
 */
extern iscsi_datain_req_t *iscsi_get_datain_values (
	iscsi_cmd_t *cmd,
	iscsi_datain_t *datain)
{
	iscsi_conn_t *conn = CONN(cmd);
	
	if (SESS_OPS_C(conn)->DataSequenceInOrder &&
	    SESS_OPS_C(conn)->DataPDUInOrder)
		return(iscsi_set_datain_values_yes_and_yes(cmd, datain));
	else if (!SESS_OPS_C(conn)->DataSequenceInOrder &&
		  SESS_OPS_C(conn)->DataPDUInOrder)
		return(iscsi_set_datain_values_no_and_yes(cmd, datain));
	else if (SESS_OPS_C(conn)->DataSequenceInOrder &&
		 !SESS_OPS_C(conn)->DataPDUInOrder)
		return(iscsi_set_datain_values_yes_and_no(cmd, datain));
	else if (!SESS_OPS_C(conn)->DataSequenceInOrder &&
		   !SESS_OPS_C(conn)->DataPDUInOrder)
		return(iscsi_set_datain_values_no_and_no(cmd, datain));

	return(NULL);
}

