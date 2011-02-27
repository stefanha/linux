#ifndef ISCSI_PROTOCOL_H
#define ISCSI_PROTOCOL_H

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
#define ON				1
#define OFF				0
#define WHITE_SPACE			" \t\v\f\n\r"
#define ISCSI_MAX_VERSION               0x0
#define ISCSI_MIN_VERSION               0x0

/* NOP-Out */
#define ISCSI_INIT_NOP_OUT 		0x00

/* NOP-In */
#define ISCSI_TARG_NOP_IN		0x20

/* Flag Settings */
#define ISCSI_OPCODE			0x3f
/* Final Bit */
#define F_BIT				0x80
/* Transit to Next Login Phase Bit */
#define T_BIT				0x80
/* Used for batching text parameters */
#define C_BIT				0x40
/* Immediate Data Bit */
#define I_BIT				0x40
/* SAM-2 Task Attribute */
#define SAM2_ATTR			0x07
/* Current Login Stage 1100 */
#define CSG				0x0C
/* Current Login Stage 0100 */
#define CSG1				0x04
/* Current Login Stage 1000 */
#define CSG2				0x08
/* Current Login Stage 1100 */
#define CSG3				0x0C
#define CSG_SHIFT			2
/* Next Login Stage 0011 */
#define NSG				0x03
/* Next Login Stage 0001 */
#define NSG1				0x01
/* Next Login Stage 0010 */
#define NSG2				0x02
/* Next Login Stage 0011 */
#define NSG3				0x03
/* Acknowledge Bit */
#define A_BIT				0x40
/* Phase Collapse Bit */
#define S_BIT				0x01
/* Underflow Bit */
#define U_BIT				0x02
/* Overflow Bit */
#define O_BIT				0x04
/* Bidirectional Overflow Bit */
#define BRO_BIT				0x10
/* Bidirectional Underflow Bit */
#define BRU_BIT				0x08

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

/* iSCSI message formats based on v12 of the IETF iSCSI Draft. */

/* 9.18 NOP-Out */

struct iscsi_init_nop_out {
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

struct iscsi_targ_nop_in {
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

struct iscsi_conn_ops {
	u8	HeaderDigest;			/* [0,1] == [None,CRC32C] */
	u8	DataDigest;			/* [0,1] == [None,CRC32C] */
	u32	MaxRecvDataSegmentLength;	/* [512..2**24-1] */
	u8	OFMarker;			/* [0,1] == [No,Yes] */
	u8	IFMarker;			/* [0,1] == [No,Yes] */
	u32	OFMarkInt;			/* [1..65535] */
	u32	IFMarkInt;			/* [1..65535] */
};

struct iscsi_sess_ops {
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
};

#endif /* ISCSI_PROTOCOL_H */
