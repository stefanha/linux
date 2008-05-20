/*********************************************************************************
 * Filename:  iscsi_protocol.h
 *
 * This file contains the iSCSI protocol definitions.
 *
 * $HeadURL: svn://subversion.sbei.com/pyx/target/branches/2.9-linux-iscsi.org/pyx-target/ipyxd/include/iscsi_protocol.h $
 *   $LastChangedRevision: 6374 $
 *   $LastChangedBy: rickd $
 *   $LastChangedDate: 2007-01-04 12:05:15 -0800 (Thu, 04 Jan 2007) $
 *
 * Copyright (c) 2003 PyX Technologies, Inc.
 * Copyright (c) 2006-2007 SBE, Inc.  All Rights Reserved.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 *
 * For further information, contact via email: support@sbei.com
 * SBE, Inc.  San Ramon, California  U.S.A.
 *********************************************************************************/


#ifndef ISCSI_PROTOCOL_H
#define ISCSI_PROTOCOL_H

#ifdef LINUX
#include <iscsi_linux_os.h>
#include <iscsi_linux_defs.h>
#endif /* LINUX */

#ifdef FREEBSD
#include <iscsi_freebsd_os.h>
#include <iscsi_freebsd_defs.h>
#endif /* FREEBSD */

#include <iscsi_debug.h>

#define ISCSI_PORT			3260
#define ISCSI_HDR_LEN			48	
#define ISCSI_CDB_LEN			16
#define CRC_LEN				4
#define MAX_TEXT_LEN			8192
#define MAX_KEY_NAME_LENGTH		63
#define MAX_KEY_VALUE_LENGTH		255
#define INITIATOR                       1
#define TARGET                          2
#define MANAGEMENT			4
#define TRUE                            1
#define NOT_TRUE                        2
#define ON				1
#define OFF				0
#define WHITE_SPACE			" \t\v\f\n\r"
#define ISCSI_MAX_VERSION               0x0
#define ISCSI_MIN_VERSION               0x0

#define STATUS_BYTE(byte)		(byte)
#define MSG_BYTE(byte)			((byte) << 8)
#define HOST_BYTE(byte)			((byte) << 16)
#define DRIVER_BYTE(byte)		((byte) << 24)

#define ISCSI_INIT_NOP_OUT 		0x00 	/* NOP-Out */
#define ISCSI_INIT_SCSI_CMND		0x01 	/* SCSI Command (Encapuslates SCSI CDB) */
#define ISCSI_INIT_TASK_MGMT_CMND	0x02 	/* SCSI Task Management Function Request */
#define ISCSI_INIT_LOGIN_CMND		0x03 	/* Login Command */
#define ISCSI_INIT_TEXT_CMND		0x04	/* Text Request */
#define ISCSI_INIT_SCSI_DATA_OUT	0x05	/* SCSI Data-Out (for WRITE operations */
#define ISCSI_INIT_LOGOUT_CMND		0x06	/* Logout Command */
#define ISCSI_INIT_SNACK		0x10	/* SNACK Request */

#define ISCSI_TARG_NOP_IN		0x20	/* NOP-In */
#define ISCSI_TARG_SCSI_RSP		0x21	/* SCSI Response */
#define ISCSI_TARG_TASK_MGMT_RSP	0x22	/* SCSI Task Managment Function Response */
#define ISCSI_TARG_LOGIN_RSP		0x23	/* Login Response */
#define ISCSI_TARG_TEXT_RSP		0x24	/* Text Response */
#define ISCSI_TARG_SCSI_DATA_IN		0x25	/* SCSI Data-In (for READ Operations) */
#define ISCSI_TARG_LOGOUT_RSP		0x26	/* Logout Response */
#define ISCSI_TARG_R2T			0x31	/* Ready to Transfer */
#define ISCSI_TARG_ASYNC_MSG		0x32	/* Asynchronous Message */
#define ISCSI_TARG_RJT			0x3f	/* Reject */

/* Flag Settings */
#define ISCSI_OPCODE			0x3f
#define F_BIT				0x80	/* Final Bit */
#define R_BIT				0x40	/* SCSI Read Bit */
#define READ_TYPE_CMND			R_BIT
#define W_BIT				0x20	/* SCSI Write Bit */
#define WRITE_TYPE_CMND			W_BIT
#define T_BIT				0x80	/* Transit to Next Login Phase Bit */
#define C_BIT				0x40	/* Used for batching text parameters */
#define I_BIT				0x40	/* Immediate Data Bit */
#define SAM2_ATTR			0x07	/* SAM-2 Task Attribute */
#define CSG				0x0C	/* Current Login Stage 1100 */
#define CSG1				0x04	/* Current Login Stage 0100 */
#define CSG2				0x08	/* Current Login Stage 1000 */
#define CSG3				0x0C	/* Current Login Stage 1100 */
#define CSG_SHIFT			2
#define NSG				0x03	/* Next Login Stage 0011 */
#define NSG1				0x01	/* Next Login Stage 0001 */
#define NSG2				0x02	/* Next Login Stage 0010 */
#define NSG3				0x03	/* Next Login Stage 0011 */
#define A_BIT				0x40	/* Acknowledge Bit */
#define S_BIT				0x01	/* Phase Collapse Bit */
#define U_BIT				0x02	/* Underflow Bit */
#define O_BIT				0x04	/* Overflow Bit */
#define BRO_BIT				0x10	/* Bidirectional Overflow Bit */
#define BRU_BIT				0x08	/* Bidirectional Underflow Bit */

/* iSCSI-v17 6.1.3  Standard Connection State Diagram for an Initiator */
#define INIT_CONN_STATE_FREE			0x1
#define INIT_CONN_STATE_XPT_WAIT		0x2
#define INIT_CONN_STATE_IN_LOGIN		0x4
#define INIT_CONN_STATE_LOGGED_IN		0x5
#define INIT_CONN_STATE_IN_LOGOUT		0x6
#define INIT_CONN_STATE_LOGOUT_REQUESTED	0x7
#define INIT_CONN_STATE_CLEANUP_WAIT		0x8

/* iSCSI-v17  6.1.4  Standard Connection State Diagram for a Target */
#define TARG_CONN_STATE_FREE			0x1
#define TARG_CONN_STATE_XPT_UP			0x3
#define TARG_CONN_STATE_IN_LOGIN		0x4
#define TARG_CONN_STATE_LOGGED_IN		0x5
#define TARG_CONN_STATE_IN_LOGOUT		0x6
#define TARG_CONN_STATE_LOGOUT_REQUESTED	0x7
#define TARG_CONN_STATE_CLEANUP_WAIT		0x8

/* iSCSI-v17  6.2 Connection Cleanup State Diagram for Initiators and Targets */
#define CLEANUP_STATE_CLEANUP_WAIT		0x1
#define CLEANUP_STATE_IN_CLEANUP		0x2
#define CLEANUP_STATE_CLEANUP_FREE		0x3 

/* iSCSI-v17  6.3.1  Session State Diagram for an Initiator */
#define INIT_SESS_STATE_FREE			0x1
#define INIT_SESS_STATE_LOGGED_IN		0x3
#define INIT_SESS_STATE_FAILED			0x4

/* iSCSI-v17  6.3.2  Session State Diagram for a Target */
#define TARG_SESS_STATE_FREE			0x1
#define TARG_SESS_STATE_ACTIVE			0x2
#define TARG_SESS_STATE_LOGGED_IN		0x3
#define TARG_SESS_STATE_FAILED			0x4
#define TARG_SESS_STATE_IN_CONTINUE		0x5

/* SCSI Command ATTR value */
#define ISCSI_UNTAGGED				0
#define ISCSI_SIMPLE				1
#define ISCSI_ORDERED				2
#define ISCSI_HEAD_OF_QUEUE			3
#define ISCSI_ACA				4
#define ISCSI_STATUS				4

/* status_class field in iscsi_targ_login_rsp */
#define STAT_CLASS_SUCCESS                      0x00
#define STAT_CLASS_REDIRECTION                  0x01
#define STAT_CLASS_INITIATOR                    0x02
#define STAT_CLASS_TARGET                       0x03

/* status_detail field in iscsi_targ_login_rsp */
#define STAT_DETAIL_SUCCESS			0x00
#define STAT_DETAIL_TARG_MOVED_TEMP		0x01
#define STAT_DETAIL_TARG_MOVED_PERM		0x02
#define STAT_DETAIL_INIT_ERROR			0x00
#define STAT_DETAIL_NOT_AUTH			0x01
#define STAT_DETAIL_NOT_ALLOWED			0x02
#define STAT_DETAIL_NOT_FOUND			0x03
#define STAT_DETAIL_TARG_REMOVED		0x04
#define STAT_DETAIL_VERSION_NOT_SUPPORTED	0x05
#define STAT_DETAIL_TOO_MANY_CONNECTIONS 	0x06
#define STAT_DETAIL_MISSING_PARAMETER 		0x07
#define STAT_DETAIL_NOT_INCLUDED 		0x08
#define STAT_DETAIL_SESSION_TYPE 		0x09
#define STAT_DETAIL_SESSION_DOES_NOT_EXIST	0x0a
#define STAT_DETAIL_INVALID_DURING_LOGIN	0x0b
#define STAT_DETAIL_TARG_ERROR			0x00
#define STAT_DETAIL_SERVICE_UNAVAILABLE		0x01
#define STAT_DETAIL_OUT_OF_RESOURCE 		0x02

/* reason field in iscsi_targ_rjt */
#define REASON_FULL_BEFORE_LOGIN		0x01
#define REASON_DATA_DIGEST_ERR			0x02
#define REASON_DATA_SNACK			0x03
#define REASON_PROTOCOL_ERR			0x04
#define REASON_COMMAND_NOT_SUPPORTED		0x05
#define REASON_TOO_MANY_IMMEDIATE_COMMANDS	0x06
#define REASON_TASK_IN_PROGRESS			0x07
#define REASON_INVALID_DATA_ACK			0x08
#define REASON_INVALID_PDU_FIELD		0x09
#define REASON_OUT_OF_RESOURCES			0x0a
#define REASON_NEGOTIATION_RESET		0x0b
#define REASON_WAITING_FOR_LOGOUT		0x0c

/* reason_code in iSCSI Logout Request */
#define CLOSESESSION				0
#define CLOSECONNECTION				1
#define REMOVECONNFORRECOVERY			2

/* response in iSCSI Logout Response */
#define CONNORSESSCLOSEDSUCCESSFULLY		0
#define CIDNOTFOUND				1
#define CONNRECOVERYNOTSUPPORTED		2
#define CLEANUPFAILED				3

/* task management function values */
#ifdef ABORT_TASK
#undef ABORT_TASK
#endif /* ABORT_TASK */
#define ABORT_TASK            			1
#ifdef ABORT_TASK_SET
#undef ABORT_TASK_SET
#endif /* ABORT_TASK_SET */
#define ABORT_TASK_SET        			2
#ifdef CLEAR_ACA
#undef CLEAR_ACA
#endif /* CLEAR_ACA */
#define CLEAR_ACA             			3
#ifdef CLEAR_TASK_SET
#undef CLEAR_TASK_SET
#endif /* CLEAR_TASK_SET */
#define CLEAR_TASK_SET        			4
#define LUN_RESET             			5
#define TARGET_WARM_RESET     			6
#define TARGET_COLD_RESET     			7
#define TASK_REASSIGN				8

/* task management response values */
#define FUNCTION_COMPLETE			0
#define TASK_DOES_NOT_EXIST			1
#define LUN_DOES_NOT_EXIST			2
#define TASK_STILL_ALLEGIANT			3
#define TASK_FAILOVER_NOT_SUPPORTED		4
#define TASK_MGMT_FUNCTION_NOT_SUPPORTED	5
#define FUNCTION_AUTHORIZATION_FAILED		6
#define FUNCTION_REJECTED           		255

/* async_event in ISCSI_TARG_ASYNC_MSG opcode */
#define ASYNC_EVENT_SCSI_EVENT			0
#define ASYNC_EVENT_REQUEST_LOGOUT		1
#define ASYNC_EVENT_DROP_CONNECTION		2
#define ASYNC_EVENT_DROP_SESSION		3
#define ASYNC_EVENT_REQUEST_TEXT		4
#define ASYNC_EVENT_VENDOR_SPECIFIC		255

/* SNACK type */
#define SNACK_DATA				0
#define SNACK_R2T				0
#define SNACK_STATUS				1
#define SNACK_DATA_ACK				2
#define SNACK_RDATA				3

/* Vendors */
#define PYX_TECHNOLOGIES			1
#define IBM					2
#define CISCO					3
#define INTEL					4

/* iSCSI message formats based on v12 of the IETF iSCSI Draft. */

/* 9.3 SCSI Command */

struct iscsi_init_scsi_cmnd 
{
	u8	opcode;
	u8	flags;
	u16	reserved;
	u32	length; 
	u64	lun;
	u32	init_task_tag;
	u32	exp_xfer_len;
	u32	cmd_sn;
	u32	exp_stat_sn;
	u8	cdb[16];
	u32	header_digest;
};

/* 9.4 SCSI Response */	

struct iscsi_targ_scsi_rsp
{
	u8	opcode;
	u8	flags;
	u8	response;
	u8	status;
	u32	length; 
	u64	reserved1;
	u32	init_task_tag;
	u32	reserved2;
	u32	stat_sn;
	u32	exp_cmd_sn;
	u32	max_cmd_sn;
	u32	exp_data_sn;
	u32	bidi_res_count;
	u32	res_count;
	u32	header_digest;
};

/* 9.5 Task Management Function Request */

struct iscsi_init_task_mgt_cmnd
{
	u8	opcode;
	u8	function;
	u16	reserved1;
	u32	length;
	u64	lun;
	u32	init_task_tag;
	u32	ref_task_tag;
	u32	cmd_sn;
	u32	exp_stat_sn;
	u32	ref_cmd_sn;
	u32	exp_data_sn;
	u64	reserved2;
	u32	header_digest;
};

/* 9.6 Task Management Function Response */

struct iscsi_targ_task_mgt_rsp
{
	u8	opcode;
	u8	flags;
	u8	response;
	u8	reserved1;
	u32	length;
	u64	reserved2;
	u32	init_task_tag;
	u32	reserved3;
	u32	stat_sn;
	u32	exp_cmd_sn;
	u32	max_cmd_sn;
	u32	reserved4;
	u64	reserved5;
	u32	header_digest;
};	

/* 9.7 SCSI Data-out & SCSI Data-in */

struct iscsi_init_scsi_data_out
{
	u8	opcode;
	u8	flags;
	u16	reserved1;
	u32	length;
	u64	lun;	
	u32	init_task_tag;
	u32	targ_xfer_tag;
	u32	reserved2;
	u32	exp_stat_sn;
	u32	reserved3;
	u32	data_sn;
	u32	offset;
	u32	reserved4;
	u32	header_digest;
};

struct iscsi_targ_scsi_data_in
{
	u8	opcode;
	u8	flags;
	u8	reserved1;
	u8	status;
	u32	length;
	u64	lun;
	u32	init_task_tag;
	u32	targ_xfer_tag;
	u32	stat_sn;
	u32	exp_cmd_sn;
	u32	max_cmd_sn;
	u32	data_sn;
	u32	offset;
	u32	res_count;
	u32	header_digest;
};

/* 9.8 Ready To Transfer (R2T) */

struct iscsi_targ_r2t
{
	u8	opcode;
	u8	flags;
	u16	reserved1;
	u32	length;
	u64	lun;
	u32	init_task_tag;
	u32	targ_xfer_tag;
	u32	stat_sn;
	u32	exp_cmd_sn;
	u32	max_cmd_sn;
	u32	r2t_sn;
	u32	offset;
	u32	xfer_len;
	u32	header_digest;
};

/* 9.9 Asynchronous Message */

struct iscsi_targ_async_msg
{
	u8	opcode;
	u8	flags;
	u16	reserved1;
	u32	length;
	u64	lun;
	u32	reserved2;
	u32	reserved3;
	u32	stat_sn;
	u32	exp_cmd_sn;
	u32	max_cmd_sn;
	u8	async_event;
	u8	async_vcode;
	u16	parameter1;
	u16	parameter2;
	u16	parameter3;
	u32	reserved4;
	u32	header_digest;
	
};

/* 9.10 Text Request */

struct iscsi_init_text_cmnd
{
	u8	opcode;
	u8	flags;
	u16	reserved1;	
	u32	length;
	u64	lun;
	u32	init_task_tag;
	u32	targ_xfer_tag;
	u32	cmd_sn;
	u32	exp_stat_sn;
	u64	reserved2;
	u64	reserved3;
	u32	header_digest;
};

/* 9.11 Text Response */

struct iscsi_targ_text_rsp
{
	u8	opcode;
	u8	flags;
	u16	reserved1;
	u32	length;
	u64	lun;
	u32	init_task_tag;
	u32	targ_xfer_tag;
	u32	stat_sn;
	u32	exp_cmd_sn;
	u32	max_cmd_sn;
	u32	reserved2;
	u64	reserved3;
	u32	header_digest;
};

/* 9.12 Login Request */

struct iscsi_init_login_cmnd
{
	u8	opcode;
	u8	flags;
	u8	version_max;
	u8	version_min;
	u32	length;
	u8	isid[6];
	u16	tsih;
	u32	init_task_tag;
	u16	cid;
	u16	reserved1;
	u32	cmd_sn;
	u32	exp_stat_sn;
	u64	reserved2;
	u64	reserved3;
	u32	header_digest;
};

/* 9.13 Login Response */

struct iscsi_targ_login_rsp
{
	u8	opcode;
	u8	flags;
	u8	version_max;
	u8	version_active;
	u32	length;
	u8	isid[6];
	u16	tsih;
	u32	init_task_tag;
	u32	reserved1;
	u32	stat_sn;
	u32	exp_cmd_sn;
	u32	max_cmd_sn;
	u8	status_class;
	u8	status_detail;
	u16	reserved2;
	u32	reserved3;
	u32	header_digest;
};

/* 9.14 Logout Request */

struct iscsi_init_logout_cmnd
{
	u8	opcode;
	u8	flags;
	u16	reserved1;
	u32	length;
	u64	reserved2;
	u32	init_task_tag;
	u16	cid;
	u16	reserved3;
	u32	cmd_sn;
	u32	exp_stat_sn;
	u64	reserved4;
	u64	reserved5;
	u32	header_digest;
};

/* 9.15 Logout Reponse */

struct iscsi_targ_logout_rsp
{
	u8	opcode;
	u8	flags;
	u8	response;
	u8	reserved1;
	u32	length;
	u64	reserved2;
	u32	init_task_tag;
	u32	reserved3;
	u32	stat_sn;
	u32	exp_cmd_sn;
	u32	max_cmd_sn;
	u32	reserved4;
	u16	time_2_wait;
	u16	time_2_retain;
	u32	reserved5;
	u32	header_digest;
};

/* 9.16 SNACK Request */

struct iscsi_init_snack
{
	u8	opcode;
	u8	type;
	u16	reserved1;
	u32	length;
	u64	lun;
	u32	init_task_tag;
	u32	targ_xfer_tag;
	u32	reserved2;
	u32	exp_stat_sn;
	u64	reserved3;
	u32	begrun;
	u32	runlength;
	u32	header_digest;
};

/* 9.17 Reject */

struct iscsi_targ_rjt
{
	u8	opcode;
	u8	flags;
	u8	reason;
	u8	reserved1;
	u32	length;
	u64	reserved2;
	u32	reserved3;
	u32	reserved4;
	u32	stat_sn;
	u32	exp_cmd_sn;
	u32	max_cmd_sn;
	u32	data_sn;
	u64	reserved5;
	u32	header_digest;
};

/* 9.18 NOP-Out */

struct iscsi_init_nop_out
{
	u8	opcode;
	u8	flags;
	u16	reserved1;
	u32	length;
	u64	lun;
	u32	init_task_tag;
	u32	targ_xfer_tag;
	u32	cmd_sn;
	u32	exp_stat_sn;
	u64	reserved2;
	u64	reserved3;
	u32	header_digest;
};

/* 9.19 NOP-In */

struct iscsi_targ_nop_in
{
	u8	opcode;
	u8	flags;
	u16	reserved1;
	u32	length;
	u64	lun;
	u32	init_task_tag;
	u32	targ_xfer_tag;
	u32	stat_sn;
	u32	exp_cmd_sn;
	u32	max_cmd_sn;
	u32	reserved2;
	u64	reserved3;
	u32	header_digest;
};

typedef struct iscsi_conn_ops_s {
	u8	HeaderDigest;			/* [0,1] == [None,CRC32C] */
	u8	DataDigest;			/* [0,1] == [None,CRC32C] */
	u32	MaxRecvDataSegmentLength;	/* [512..2**24-1] */
	u8	OFMarker;			/* [0,1] == [No,Yes] */
	u8	IFMarker;			/* [0,1] == [No,Yes] */
	u32	OFMarkInt;			/* [1..65535] */
	u32	IFMarkInt;			/* [1..65535] */
} iscsi_conn_ops_t;

typedef struct iscsi_sess_ops_s {
	char	InitiatorName[224];
	char	InitiatorAlias[256];
	char	TargetName[224];
	char	TargetAlias[256];
	char	TargetAddress[256];
	u16	TargetPortalGroupTag;		/* [0..65535] */
	u16	MaxConnections;			/* [1..65535] */
	u8	InitialR2T;			/* [0,1] == [No,Yes] */
	u8	ImmediateData;			/* [0,1] == [No,Yes] */
	u32	MaxBurstLength;			/* [512..2**24-1] */
	u32	FirstBurstLength;		/* [512..2**24-1] */
	u16	DefaultTime2Wait;		/* [0..3600] */
	u16	DefaultTime2Retain;		/* [0..3600] */
	u16	MaxOutstandingR2T;		/* [1..65535] */
	u8	DataPDUInOrder;			/* [0,1] == [No,Yes] */
	u8	DataSequenceInOrder;		/* [0,1] == [No,Yes] */
	u8	ErrorRecoveryLevel;		/* [0..2] */
	u8	SessionType;			/* [0,1] == [Normal,Discovery]*/
} iscsi_sess_ops_t;

#endif /* ISCSI_PROTOCOL_H */
