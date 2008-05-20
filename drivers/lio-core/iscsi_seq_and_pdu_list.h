/*********************************************************************************
 * Filename:  iscsi_seq_and_pdu_list.h
 *
 * This file contains main definitions related to iSCSI DataSequenceInOrder=No
 * and DataPDUInOrder=No.
 *
 * $HeadURL: svn://subversion.sbei.com/pyx/target/branches/2.9-linux-iscsi.org/pyx-target/include/iscsi_seq_and_pdu_list.h $
 *   $LastChangedRevision: 4795 $
 *   $LastChangedBy: rickd $
 *   $LastChangedDate: 2006-08-17 16:08:03 -0700 (Thu, 17 Aug 2006) $
 *
 * Copyright (c) 2003 PyX Technologies, Inc.
 * Copyright (c) 2006 SBE, Inc.  All Rights Reserved.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 * For further information, contact via email: support@sbei.com
 * SBE, Inc.  San Ramon, California  U.S.A.
 *********************************************************************************/


#ifndef ISCSI_SEQ_AND_PDU_LIST_H
#define ISCSI_SEQ_AND_PDU_LIST_H

/* iscsi_pdu_t->status */
#define DATAOUT_PDU_SENT			1

/* iscsi_seq_t->type */
#define SEQTYPE_IMMEDIATE			1
#define SEQTYPE_UNSOLICITED			2
#define SEQTYPE_NORMAL				3

/* iscsi_seq_t->status */
#define DATAOUT_SEQUENCE_GOT_R2T		1
#define DATAOUT_SEQUENCE_WITHIN_COMMAND_RECOVERY 2
#define DATAOUT_SEQUENCE_COMPLETE		3

/* iscsi_determine_counts_for_list() type */
#define PDULIST_NORMAL				1
#define PDULIST_IMMEDIATE			2
#define PDULIST_UNSOLICITED			3
#define PDULIST_IMMEDIATE_AND_UNSOLICITED	4

/* iscsi_pdu_t->type */
#define PDUTYPE_IMMEDIATE			1
#define PDUTYPE_UNSOLICITED			2
#define PDUTYPE_NORMAL				3

/* iscsi_pdu_t->status */
#define ISCSI_PDU_NOT_RECEIVED			0
#define ISCSI_PDU_RECEIVED_OK			1
#define ISCSI_PDU_CRC_FAILED			2
#define ISCSI_PDU_TIMED_OUT			3

/* iscsi_build_list_t->randomize */
#define RANDOM_DATAIN_PDU_OFFSETS		0x01
#define RANDOM_DATAIN_SEQ_OFFSETS		0x02
#define RANDOM_DATAOUT_PDU_OFFSETS		0x04
#define RANDOM_R2T_OFFSETS			0x08

/* iscsi_build_list_t->data_direction */
#define ISCSI_PDU_READ				0x01
#define ISCSI_PDU_WRITE				0x02

typedef struct iscsi_build_list_s {
	u8		data_direction;
	u8		randomize;
	u8		type;
	u32		immediate_data_length;
} iscsi_build_list_t;

typedef struct iscsi_pdu_s {
	int		status;
	int		type;
	u8		flags;
	u32		data_sn;
	u32		length;
	u32		offset;
	u32		pdu_send_order;
	u32		seq_no;
} iscsi_pdu_t;

typedef struct iscsi_seq_s {
	int		sent;
	int		status;
	int		type;
	u32		data_sn;
	u32		first_datasn;
	u32		last_datasn;
	u32		next_burst_len;
	u32		pdu_start;
	u32		pdu_count;
	u32		offset;
	u32		orig_offset;
	u32		pdu_send_order;
	u32		r2t_sn;
	u32		seq_send_order;
	u32		seq_no;
	u32		xfer_len;
} iscsi_seq_t;

extern int iscsi_do_build_list (iscsi_cmd_t *, iscsi_build_list_t *);
extern iscsi_pdu_t *iscsi_get_pdu_holder (iscsi_cmd_t *, u32, u32);
extern iscsi_pdu_t *iscsi_get_pdu_holder_for_seq (iscsi_cmd_t *, iscsi_seq_t *);
extern iscsi_seq_t *iscsi_get_seq_holder (iscsi_cmd_t *, u32, u32);

#endif /* ISCSI_SEQ_AND_PDU_LIST_H */
