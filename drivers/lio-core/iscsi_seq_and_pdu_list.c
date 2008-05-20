/*********************************************************************************
 * Filename:  iscsi_seq_and_pdu_list.c
 *
 * This file contains main functions related to iSCSI DataSequenceInOrder=No
 * and DataPDUInOrder=No.
 *
 * Copyright (c) 2003 PyX Technologies, Inc.
 * Copyright (c) 2006-2007 SBE, Inc.  All Rights Reserved.
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


#define ISCSI_SEQ_AND_PDU_LIST_C

#ifdef LINUX
#include <linux/slab.h>
#include <linux/random.h>
#include <iscsi_linux_defs.h>
#endif /* LINUX */

#include <iscsi_protocol.h>
#include <iscsi_debug.h>
#include <iscsi_debug_opcodes.h>
#ifdef _INITIATOR
#include <iscsi_initiator_core.h>
#include <iscsi_initiator_util.h>
#elif _TARGET
#include <iscsi_target_core.h>
#include <iscsi_target_util.h>
#else
#error Neither _INITIATOR or _TARGET defined!
#endif

#undef ISCSI_SEQ_AND_PDU_LIST_C

#define OFFLOAD_BUF_SIZE	32768

extern iscsi_global_t *iscsi_global;

/*	iscsi_dump_seq_list():
 *
 *
 */
extern void iscsi_dump_seq_list (iscsi_cmd_t *cmd)
{
	int i;
	iscsi_seq_t *seq;

	printk("Dumping Sequence List for ITT: 0x%08x:\n", cmd->init_task_tag);

	for (i = 0; i < cmd->seq_count; i++) {
		seq = &cmd->seq_list[i];
		printk("i: %d, pdu_start: %d, pdu_count: %d, offset: %d,"
			" xfer_len: %d, seq_send_order: %d, seq_no: %d\n",
			i, seq->pdu_start, seq->pdu_count, seq->offset,
			seq->xfer_len, seq->seq_send_order, seq->seq_no);
	}

	return;
}

/*	iscsi_dump_pdu_list():
 *
 *
 */
extern void iscsi_dump_pdu_list (iscsi_cmd_t *cmd)
{
	int i;
	iscsi_pdu_t *pdu;

	printk("Dumping PDU List for ITT: 0x%08x:\n", cmd->init_task_tag);
	
	for (i = 0; i < cmd->pdu_count; i++) {
		pdu = &cmd->pdu_list[i];
		printk("i: %d, offset: %d, length: %d, pdu_send_order: %d, seq_no: %d\n",
			i, pdu->offset, pdu->length, pdu->pdu_send_order, pdu->seq_no);	
	}

	return;
}

/*	iscsi_ordered_seq_lists():
 *
 *
 */
static inline void iscsi_ordered_seq_lists (
	iscsi_cmd_t *cmd,
	u8 type)
{
	u32 i, seq_count = 0;

	for (i = 0; i < cmd->seq_count; i++) {
		if (cmd->seq_list[i].type != SEQTYPE_NORMAL)
			continue;
		cmd->seq_list[i].seq_send_order = seq_count++;
	}
		
	return;
}

/*	iscsi_ordered_pdu_lists():
 *
 *
 */
static inline void iscsi_ordered_pdu_lists (
	iscsi_cmd_t *cmd,
	u8 type)
{
	u32 i, pdu_send_order = 0, seq_no = 0;

	for (i = 0; i < cmd->pdu_count; i++) {
redo:
		if (cmd->pdu_list[i].seq_no == seq_no) {
			cmd->pdu_list[i].pdu_send_order = pdu_send_order++;
			continue;
		}
		seq_no++;
		pdu_send_order = 0;
		goto redo;
	}

	return;
}

/*	iscsi_create_random_array():
 *
 *	Generate count random values into array.
 *	Use 0x80000000 to mark generates valued in array[].
 */
static inline void iscsi_create_random_array (u32 *array, u32 count)
{
	int i, j, k;
	
	if (count == 1) {
		array[0] = 0;
		return;
	}
		
	for (i = 0; i < count; i++) {
redo:
		get_random_bytes(&j, sizeof(u32));
		j = (1 + (int) (9999 + 1) - j) % count;
		for (k = 0; k < i + 1; k++) {
			j |= 0x80000000;
			if ((array[k] & 0x80000000) && (array[k] == j))
				goto redo;
		}
		array[i] = j;
	}

	for (i = 0; i < count; i++)
		array[i] &= ~0x80000000;
		
	return;
}

/*	iscsi_randomize_pdu_lists():
 *
 *
 */
static inline int iscsi_randomize_pdu_lists (
	iscsi_cmd_t *cmd,
	u8 type)
{
	int i = 0;
	u32 *array, pdu_count, seq_count = 0, seq_no = 0, seq_offset = 0;

	for (pdu_count = 0; pdu_count < cmd->pdu_count; pdu_count++) {
redo:
		if (cmd->pdu_list[pdu_count].seq_no == seq_no) {	
			seq_count++;
			continue;
		}
		if (!(array = (u32 *) kmalloc(
				seq_count * sizeof(u32), GFP_KERNEL))) {
			TRACE_ERROR("Unable to allocate memory"
				" for random array.\n");
			return(-1);
		}
		memset(array, 0, seq_count * sizeof(u32));
				
		iscsi_create_random_array(array, seq_count);

		for (i = 0; i < seq_count; i++)
			cmd->pdu_list[seq_offset+i].pdu_send_order = array[i];
			
		kfree(array);
			
		seq_offset += seq_count;
		seq_count = 0;
		seq_no++;
		goto redo;
	}

	if (seq_count) {
		if (!(array = (u32 *) kmalloc(
				seq_count * sizeof(u32), GFP_KERNEL))) {
			TRACE_ERROR("Unable to allocate memory for"
				" random array.\n");
			return(-1);
		}
		memset(array, 0, seq_count * sizeof(u32));

		iscsi_create_random_array(array, seq_count);

		for (i = 0; i < seq_count; i++)
			cmd->pdu_list[seq_offset+i].pdu_send_order = array[i];

		kfree(array);
	}

	return(0);
}

/*	iscsi_randomize_seq_lists():
 *
 *
 */
static inline int iscsi_randomize_seq_lists (
	iscsi_cmd_t *cmd,
	u8 type)
{	
	int i, j = 0;
	u32 *array, seq_count = cmd->seq_count;

	if ((type == PDULIST_IMMEDIATE) || (type == PDULIST_UNSOLICITED))
		seq_count--;
	else if (type == PDULIST_IMMEDIATE_AND_UNSOLICITED)
		seq_count -= 2;

	if (!seq_count)
		return(0);
	
	if (!(array = (u32 *) kmalloc(seq_count * sizeof(u32), GFP_KERNEL))) {
		TRACE_ERROR("Unable to allocate memory for random array.\n");
		return(-1);
	}
	memset(array, 0, seq_count * sizeof(u32));

	iscsi_create_random_array(array, seq_count);

	for (i = 0; i < cmd->seq_count; i++) {
		if (cmd->seq_list[i].type != SEQTYPE_NORMAL)
			continue;	
		cmd->seq_list[i].seq_send_order = array[j++];
	}
		
	kfree(array);
	return(0);
}

/*	iscsi_determine_counts_for_list():
 *
 *
 */
static inline void iscsi_determine_counts_for_list (
	iscsi_cmd_t *cmd,
	iscsi_build_list_t *bl,
	u32 *seq_count,
	u32 *pdu_count)
{
	int check_immediate = 0;
	u32 burstlength = 0, offset = 0;
	u32 unsolicited_data_length = 0;
	iscsi_conn_t *conn = CONN(cmd);

	TRACE_ENTER

	if ((bl->type == PDULIST_IMMEDIATE) ||
	    (bl->type == PDULIST_IMMEDIATE_AND_UNSOLICITED))
		check_immediate = 1;

	if ((bl->type == PDULIST_UNSOLICITED) ||
	    (bl->type == PDULIST_IMMEDIATE_AND_UNSOLICITED))
		unsolicited_data_length = (cmd->data_length >
			SESS_OPS_C(conn)->FirstBurstLength) ?
			SESS_OPS_C(conn)->FirstBurstLength : cmd->data_length;

	while (offset < cmd->data_length) {
		*pdu_count += 1;

		if (check_immediate) {
			check_immediate = 0;
			offset += bl->immediate_data_length;
			*seq_count += 1;
			if (unsolicited_data_length)
				unsolicited_data_length -= bl->immediate_data_length;
			continue;
		}
		if (unsolicited_data_length > 0) {
			if ((offset + CONN_OPS(conn)->MaxRecvDataSegmentLength) >=
			     cmd->data_length) {
				unsolicited_data_length -= (cmd->data_length - offset);
				offset += (cmd->data_length - offset);
				continue;
			}
			if ((offset + CONN_OPS(conn)->MaxRecvDataSegmentLength) >=
			     SESS_OPS_C(conn)->FirstBurstLength) {
				unsolicited_data_length -=
					(SESS_OPS_C(conn)->FirstBurstLength - offset);
				offset += (SESS_OPS_C(conn)->FirstBurstLength - offset);
				burstlength = 0;
				*seq_count += 1;
				continue;
			}

			offset += CONN_OPS(conn)->MaxRecvDataSegmentLength;
			unsolicited_data_length -= CONN_OPS(conn)->MaxRecvDataSegmentLength;
			continue;
		}
		if ((offset + CONN_OPS(conn)->MaxRecvDataSegmentLength) >=
		     cmd->data_length) {
			offset += (cmd->data_length - offset);
			continue;
		}
		if ((burstlength + CONN_OPS(conn)->MaxRecvDataSegmentLength) >=
		     SESS_OPS_C(conn)->MaxBurstLength) {
			offset += (SESS_OPS_C(conn)->MaxBurstLength - burstlength);
			burstlength = 0;
			*seq_count += 1;
			continue;
		}

		burstlength += CONN_OPS(conn)->MaxRecvDataSegmentLength;
		offset += CONN_OPS(conn)->MaxRecvDataSegmentLength;
	}

	TRACE_LEAVE
	return;
}
	

/*	iscsi_build_pdu_and_seq_list():
 *
 *	Builds PDU and/or Sequence list,  called while DataSequenceInOrder=No
 *	and DataPDUInOrder=No.
 */
static inline int iscsi_build_pdu_and_seq_list (
	iscsi_cmd_t *cmd,
	iscsi_build_list_t *bl)
{
	int check_immediate = 0, datapduinorder, datasequenceinorder;
	u32 burstlength = 0, offset = 0, i = 0;
	u32 pdu_count = 0, seq_no = 0, unsolicited_data_length = 0;
	iscsi_conn_t *conn = CONN(cmd);
	iscsi_pdu_t *pdu = cmd->pdu_list;
	iscsi_seq_t *seq = cmd->seq_list;

	TRACE_ENTER

	datapduinorder = SESS_OPS_C(conn)->DataPDUInOrder;
	datasequenceinorder = SESS_OPS_C(conn)->DataSequenceInOrder;

	if ((bl->type == PDULIST_IMMEDIATE) ||
	    (bl->type == PDULIST_IMMEDIATE_AND_UNSOLICITED))
		check_immediate = 1;
	
	if ((bl->type == PDULIST_UNSOLICITED) ||
	    (bl->type == PDULIST_IMMEDIATE_AND_UNSOLICITED))
		unsolicited_data_length = (cmd->data_length >
			SESS_OPS_C(conn)->FirstBurstLength) ?
			SESS_OPS_C(conn)->FirstBurstLength : cmd->data_length;
	
	while (offset < cmd->data_length) {
		pdu_count++;
		if (!datapduinorder) {
			pdu[i].offset = offset;
			pdu[i].seq_no = seq_no;
		}
		if (!datasequenceinorder && (pdu_count == 1)) {
			seq[seq_no].pdu_start = i;
			seq[seq_no].seq_no = seq_no;
			seq[seq_no].offset = offset;
			seq[seq_no].orig_offset = offset;
		}

		if (check_immediate) {
			check_immediate = 0;
			if (!datapduinorder) {
				pdu[i].type = PDUTYPE_IMMEDIATE;
				pdu[i++].length = bl->immediate_data_length;
			}
			if (!datasequenceinorder) {
				seq[seq_no].type = SEQTYPE_IMMEDIATE;
				seq[seq_no].pdu_count = 1;
				seq[seq_no].xfer_len = bl->immediate_data_length;
			}
			offset += bl->immediate_data_length;
			pdu_count = 0;
			seq_no++;
			if (unsolicited_data_length)
				unsolicited_data_length -= bl->immediate_data_length;
			continue;
		}
		if (unsolicited_data_length > 0) {
			if ((offset + CONN_OPS(conn)->MaxRecvDataSegmentLength) >=
			     cmd->data_length) {
				if (!datapduinorder) {
					pdu[i].type = PDUTYPE_UNSOLICITED;
					pdu[i].length = (cmd->data_length - offset);
				}
				if (!datasequenceinorder) {
					seq[seq_no].type = SEQTYPE_UNSOLICITED;
					seq[seq_no].pdu_count = pdu_count;
					seq[seq_no].xfer_len = (burstlength +
						(cmd->data_length - offset));
				}
				unsolicited_data_length -= (cmd->data_length - offset);
				offset += (cmd->data_length - offset);
				continue;
			}
			if ((offset + CONN_OPS(conn)->MaxRecvDataSegmentLength) >=
			     SESS_OPS_C(conn)->FirstBurstLength) {
				if (!datapduinorder) {
					pdu[i].type = PDUTYPE_UNSOLICITED;
					pdu[i++].length =
						(SESS_OPS_C(conn)->FirstBurstLength - offset);
				}
				if (!datasequenceinorder) {
					seq[seq_no].type = SEQTYPE_UNSOLICITED;
					seq[seq_no].pdu_count = pdu_count;
					seq[seq_no].xfer_len = (burstlength +
						(SESS_OPS_C(conn)->FirstBurstLength - offset));
				}
				unsolicited_data_length -=
					(SESS_OPS_C(conn)->FirstBurstLength - offset);
				offset += (SESS_OPS_C(conn)->FirstBurstLength - offset);
				burstlength = 0;
				pdu_count = 0;
				seq_no++;
				continue;
			}

			if (!datapduinorder) {
				pdu[i].type = PDUTYPE_UNSOLICITED;
				pdu[i++].length = CONN_OPS(conn)->MaxRecvDataSegmentLength;
			}
			burstlength += CONN_OPS(conn)->MaxRecvDataSegmentLength;
			offset += CONN_OPS(conn)->MaxRecvDataSegmentLength;
			unsolicited_data_length -= CONN_OPS(conn)->MaxRecvDataSegmentLength;
			continue;
		}
		if ((offset + CONN_OPS(conn)->MaxRecvDataSegmentLength) >=
		     cmd->data_length) {
			if (!datapduinorder) {
				pdu[i].type = PDUTYPE_NORMAL;
				pdu[i].length = (cmd->data_length - offset);
			}
			if (!datasequenceinorder) {
				seq[seq_no].type = SEQTYPE_NORMAL;
				seq[seq_no].pdu_count = pdu_count;
				seq[seq_no].xfer_len = (burstlength +
					(cmd->data_length - offset));
			}
			offset += (cmd->data_length - offset);
			continue;
		}
		if ((burstlength + CONN_OPS(conn)->MaxRecvDataSegmentLength) >=
		     SESS_OPS_C(conn)->MaxBurstLength) {
			if (!datapduinorder) {
				pdu[i].type = PDUTYPE_NORMAL;
				pdu[i++].length = (SESS_OPS_C(conn)->MaxBurstLength -
							burstlength);
			}
			if (!datasequenceinorder) {
				seq[seq_no].type = SEQTYPE_NORMAL;
				seq[seq_no].pdu_count = pdu_count;
				seq[seq_no].xfer_len = (burstlength +
					(SESS_OPS_C(conn)->MaxBurstLength - burstlength));
			}
			offset += (SESS_OPS_C(conn)->MaxBurstLength - burstlength);
			burstlength = 0;
			pdu_count = 0;
			seq_no++;
			continue;
		}

		if (!datapduinorder) {
			pdu[i].type = PDUTYPE_NORMAL;
			pdu[i++].length = CONN_OPS(conn)->MaxRecvDataSegmentLength;
		}
		burstlength += CONN_OPS(conn)->MaxRecvDataSegmentLength;
		offset += CONN_OPS(conn)->MaxRecvDataSegmentLength;
	}

	if (!datasequenceinorder) {
		if (bl->data_direction & ISCSI_PDU_WRITE) {
			if (bl->randomize & RANDOM_R2T_OFFSETS) {
				if (iscsi_randomize_seq_lists(cmd, bl->type) < 0)
					return(-1);
			} else
				iscsi_ordered_seq_lists(cmd, bl->type);
		} else if (bl->data_direction & ISCSI_PDU_READ) {
			if (bl->randomize & RANDOM_DATAIN_SEQ_OFFSETS) {
				if (iscsi_randomize_seq_lists(cmd, bl->type) < 0)
					return(-1);
			} else
				iscsi_ordered_seq_lists(cmd, bl-> type);
		}
#if 0
		iscsi_dump_seq_list(cmd);
#endif
	}
	if (!datapduinorder) {
		if (bl->data_direction & ISCSI_PDU_WRITE) {
			if (bl->randomize & RANDOM_DATAOUT_PDU_OFFSETS) {
				if (iscsi_randomize_pdu_lists(cmd, bl->type) < 0)
					return(-1);
			} else
				iscsi_ordered_pdu_lists(cmd, bl->type);
		} else if (bl->data_direction & ISCSI_PDU_READ) {
			if (bl->randomize & RANDOM_DATAIN_PDU_OFFSETS) {
				if (iscsi_randomize_pdu_lists(cmd, bl->type) < 0)
					return(-1);
			} else
				iscsi_ordered_pdu_lists(cmd, bl->type);
		}
#if 0
		iscsi_dump_pdu_list(cmd);
#endif
	}

	TRACE_LEAVE
	return(0);
}

/*	iscsi_do_build_list():
 *
 *	Only called while DataSequenceInOrder=No or DataPDUInOrder=No.
 */
extern int iscsi_do_build_list (
	iscsi_cmd_t *cmd,
	iscsi_build_list_t *bl)
{
	u32 pdu_count = 0, seq_count = 1;
	iscsi_conn_t *conn = CONN(cmd);
	iscsi_pdu_t *pdu = NULL;
	iscsi_seq_t *seq = NULL;

	TRACE_ENTER
		
	iscsi_determine_counts_for_list(cmd, bl, &seq_count, &pdu_count);

	if (!SESS_OPS_C(conn)->DataSequenceInOrder) {
		if (!(seq = (iscsi_seq_t *) kmalloc(
				seq_count * sizeof(iscsi_seq_t), GFP_ATOMIC))) {
			TRACE_ERROR("Unable to allocate iscsi_seq_t list\n");
			return(-1);
		}
		memset(seq, 0, seq_count * sizeof(iscsi_seq_t));

		cmd->seq_list = seq;
		cmd->seq_count = seq_count;
	}

	if (!SESS_OPS_C(conn)->DataPDUInOrder) {
		if (!(pdu = (iscsi_pdu_t *) kmalloc(
				pdu_count * sizeof(iscsi_pdu_t), GFP_ATOMIC))) {
			TRACE_ERROR("Unable to allocate iscsi_pdu_t list.\n");
			if (seq)
				kfree(seq);
			return(-1);
		}
		memset(pdu, 0, pdu_count * sizeof(iscsi_pdu_t));

		cmd->pdu_list = pdu;
		cmd->pdu_count = pdu_count;
	}

	TRACE_LEAVE
	return(iscsi_build_pdu_and_seq_list(cmd, bl));
}

/*	iscsi_get_pdu_holder():
 *
 *
 */
extern iscsi_pdu_t *iscsi_get_pdu_holder (
	iscsi_cmd_t *cmd,
	u32 offset,
	u32 length)
{
	u32 i;
	iscsi_pdu_t *pdu = NULL;
	
	if (!cmd->pdu_list) {
		TRACE_ERROR("iscsi_cmd_t->pdu_list is NULL!\n");
		return(NULL);
	}

	pdu = &cmd->pdu_list[0];
	
	for (i = 0; i < cmd->pdu_count; i++)
		if ((pdu[i].offset == offset) && (pdu[i].length == length))
			return(&pdu[i]);

	TRACE_ERROR("Unable to locate PDU holder for ITT: 0x%08x, Offset:"
		" %u, Length: %u\n", cmd->init_task_tag, offset, length);
	return(NULL);
}

/*	iscsi_get_pdu_holder_for_seq():
 *
 *
 */
extern iscsi_pdu_t *iscsi_get_pdu_holder_for_seq (
	iscsi_cmd_t *cmd,
	iscsi_seq_t *seq)
{
	u32 i;
	iscsi_conn_t *conn = CONN(cmd);
	iscsi_pdu_t *pdu = NULL;
	
	if (!cmd->pdu_list) {
		TRACE_ERROR("iscsi_cmd_t->pdu_list is NULL!\n");
		return(NULL);
	}

	if (SESS_OPS_C(conn)->DataSequenceInOrder) {
redo:
		pdu = &cmd->pdu_list[cmd->pdu_start];

		for (i = 0; pdu[i].seq_no != cmd->seq_no; i++) {
#if 0
			TRACE_ERROR("pdu[i].seq_no: %d, pdu[i].pdu_send_order: %d, pdu[i].offset: %d, pdu[i].length: %d\n",
				pdu[i].seq_no, pdu[i].pdu_send_order, pdu[i].offset, pdu[i].length);
#endif
			if (pdu[i].pdu_send_order == cmd->pdu_send_order) {
				cmd->pdu_send_order++;
				return(&pdu[i]);
			}
		}
		
		cmd->pdu_start += cmd->pdu_send_order;
		cmd->pdu_send_order = 0;
		cmd->seq_no++;

		if (cmd->pdu_start < cmd->pdu_count)
			goto redo;

		TRACE_ERROR("Command ITT: 0x%08x unable to locate iscsi_pdu_t"
			" for cmd->pdu_send_order: %u.\n", cmd->init_task_tag,
				cmd->pdu_send_order);
		return(NULL);
	} else {
		if (!seq) {
			TRACE_ERROR("iscsi_seq_t is NULL!\n");
			return(NULL);
		}
#if 0
		TRACE_ERROR("seq->pdu_start: %d, seq->pdu_count: %d, seq->seq_no: %d\n",
			seq->pdu_start, seq->pdu_count, seq->seq_no);
#endif
		pdu = &cmd->pdu_list[seq->pdu_start];

		if (seq->pdu_send_order == seq->pdu_count) {
			TRACE_ERROR("Command ITT: 0x%08x seq->pdu_send_order: %u"
				" equals seq->pdu_count: %u\n", cmd->init_task_tag,
					seq->pdu_send_order, seq->pdu_count);
			return(NULL);
		}
		
		for (i = 0; i < seq->pdu_count; i++) {
			if (pdu[i].pdu_send_order == seq->pdu_send_order) {
				seq->pdu_send_order++;
				return(&pdu[i]);
			}
		}
		
		TRACE_ERROR("Command ITT: 0x%08x unable to locate iscsi_pdu_t"
			" for seq->pdu_send_order: %u.\n", cmd->init_task_tag,
				seq->pdu_send_order);
		return(NULL);
	}

	return(NULL);
}

/*	iscsi_get_seq_holder():
 *
 *
 */
extern iscsi_seq_t *iscsi_get_seq_holder (
	iscsi_cmd_t *cmd,
	u32 offset,
	u32 length)
{
	u32 i;

	if (!cmd->seq_list) {
		TRACE_ERROR("iscsi_cmd_t->seq_list is NULL!\n");
		return(NULL);
	}

	for (i = 0; i < cmd->seq_count; i++) {
#if 0
		TRACE_ERROR("seq_list[i].orig_offset: %d, seq_list[i].xfer_len: %d, seq_list[i].seq_no %u\n",
				cmd->seq_list[i].orig_offset, cmd->seq_list[i].xfer_len, cmd->seq_list[i].seq_no);
#endif
		if ((cmd->seq_list[i].orig_offset + cmd->seq_list[i].xfer_len) >=
		    (offset + length))
			return(&cmd->seq_list[i]);
	}

	TRACE_ERROR("Unable to locate Sequence holder for ITT: 0x%08x, Offset:"
		" %u, Length: %u\n", cmd->init_task_tag, offset, length);
	return(NULL);
}
