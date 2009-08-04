/*********************************************************************************
 * Filename:  iscsi_target_core.h
 *
 * This file contains definitions related to the iSCSI Target Core Driver.
 *
 * Nicholas A. Bellinger <nab@kernel.org>
 *
 * Copyright (c) 2003, 2004, 2005 PyX Technologies, Inc.
 * Copyright (c) 2005, 2006, 2007 SBE, Inc.
 * Copyright (c) 2007 Rising Tide Software, Inc.
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


#ifndef ISCSI_TARGET_CORE_H
#define ISCSI_TARGET_CORE_H

#include <linux/in.h>
#include <linux/configfs.h>
#include <net/sock.h>
#include <net/tcp.h>
#include <iscsi_linux_defs.h>
#ifdef SNMP_SUPPORT
#include <iscsi_target_mib.h>
#endif /* SNMP_SUPPORT */

#include <iscsi_target_version.h>	    /* get version definition */

#define SHUTDOWN_SIGS			(sigmask(SIGKILL)|sigmask(SIGINT)|sigmask(SIGABRT))
#define ISCSI_MISC_IOVECS		5
#define ISCSI_MAX_DATASN_MISSING_COUNT	16
#define ISCSI_TX_THREAD_TCP_TIMEOUT	2
#define ISCSI_RX_THREAD_TCP_TIMEOUT	2
#define ISCSI_IQN_UNIQUENESS		14
#define ISCSI_IQN_LEN			224
#define ISCSI_TIQN_LEN			ISCSI_IQN_LEN
#define SECONDS_FOR_ASYNC_LOGOUT	10
#define SECONDS_FOR_ASYNC_TEXT		10
#define IPV6_ADDRESS_SPACE		48
#define IPV4_ADDRESS_SPACE		4
#define IPV4_BUF_SIZE			18
#define RESERVED			0xFFFFFFFF
#define ISCSI_MAX_LUNS_PER_TPG		TRANSPORT_MAX_LUNS_PER_TPG /* from target_core_base.h */
#define ISCSI_MAX_TPGS			64 /* Maximum Target Portal Groups allowed */
#define ISCSI_NETDEV_NAME_SIZE		12 /* Size of the Network Device Name Buffer */

/* iscsi_tpg_np_t->tpg_np_network_transport */
#define ISCSI_TCP				0
#define ISCSI_SCTP_TCP				1
#define ISCSI_SCTP_UDP				2
#define ISCSI_IWARP_TCP				3
#define ISCSI_IWARP_SCTP			4
#define ISCSI_INFINIBAND			5

#define ISCSI_TCP_VERSION		"v3.0"
#define ISCSI_SCTP_VERSION		"v3.0"

/* iscsi_node_attrib_t sanity values */
#define NA_DATAOUT_TIMEOUT		3
#define NA_DATAOUT_TIMEOUT_MAX		60
#define NA_DATAOUT_TIMEOUT_MIX		2
#define NA_DATAOUT_TIMEOUT_RETRIES	5
#define NA_DATAOUT_TIMEOUT_RETRIES_MAX	15
#define NA_DATAOUT_TIMEOUT_RETRIES_MIN	1
#define NA_NOPIN_TIMEOUT		5
#define NA_NOPIN_TIMEOUT_MAX		60
#define NA_NOPIN_TIMEOUT_MIN		3
#define NA_NOPIN_RESPONSE_TIMEOUT	5
#define NA_NOPIN_RESPONSE_TIMEOUT_MAX	60
#define NA_NOPIN_RESPONSE_TIMEOUT_MIN	3
#define NA_RANDOM_DATAIN_PDU_OFFSETS	0
#define NA_RANDOM_DATAIN_SEQ_OFFSETS	0
#define NA_RANDOM_R2T_OFFSETS		0
#define NA_DEFAULT_ERL			0
#define NA_DEFAULT_ERL_MAX		2
#define NA_DEFAULT_ERL_MIN		0

/* iscsi_tpg_attrib_t sanity values */
#define TA_AUTHENTICATION		1
#define TA_LOGIN_TIMEOUT		15
#define TA_LOGIN_TIMEOUT_MAX		30
#define TA_LOGIN_TIMEOUT_MIN		5
#define TA_NETIF_TIMEOUT		2
#define TA_NETIF_TIMEOUT_MAX		15
#define TA_NETIF_TIMEOUT_MIN		2
#define TA_GENERATE_NODE_ACLS		0
#define TA_DEFAULT_CMDSN_DEPTH		16
#define TA_DEFAULT_CMDSN_DEPTH_MAX	512
#define TA_DEFAULT_CMDSN_DEPTH_MIN	1
#define TA_CACHE_DYNAMIC_ACLS		0
#define TA_DEMO_MODE_WRITE_PROTECT	1 // Enabled by default in demo mode (generic_node_acls=1)
#define TA_PROD_MODE_WRITE_PROTECT	0 // Disabled by default in production mode w/ explict ACLs
#define TA_CACHE_CORE_NPS		0

/* iscsi_data_count_t->type */
#define ISCSI_RX_DATA				1
#define ISCSI_TX_DATA				2

/* iscsi_datain_req_t->dr_done */
#define DATAIN_COMPLETE_NORMAL			1
#define DATAIN_COMPLETE_WITHIN_COMMAND_RECOVERY 2
#define DATAIN_COMPLETE_CONNECTION_RECOVERY	3

/* iscsi_datain_req_t->recovery */
#define DATAIN_WITHIN_COMMAND_RECOVERY		1
#define DATAIN_CONNECTION_RECOVERY		2

/* iscsi_portal_group_t->state */
#define TPG_STATE_FREE				0
#define TPG_STATE_ACTIVE			1
#define TPG_STATE_INACTIVE			2
#define TPG_STATE_COLD_RESET			3

/* iscsi_set_device_attribute() states, don't forget to change descriptions in iscsi_ctl.c! */
#define ISCSI_DEVATTRIB_ENABLE_DEVICE		1
#define ISCSI_DEVATTRIB_DISABLE_DEVICE		2
#define ISCSI_DEVATTRIB_ADD_LUN_ACL		3
#define ISCSI_DEVATTRIB_DELETE_LUN_ACL		4

/* iscsi_cmd_t->data_direction, same values as target_core_base.h
   and se_cmd_t->data_direction  */
#define ISCSI_NONE				0
#define ISCSI_READ				1
#define ISCSI_WRITE				2
#define ISCSI_BIDI				3

/* iscsi_tiqn_t->tiqn_state */
#define TIQN_STATE_ACTIVE			1
#define TIQN_STATE_SHUTDOWN			2

/* iscsi_cmd_t->cmd_flags */
#define ICF_GOT_LAST_DATAOUT			0x00000001
#define ICF_GOT_DATACK_SNACK			0x00000002
#define ICF_NON_IMMEDIATE_UNSOLICITED_DATA	0x00000004
#define ICF_SENT_LAST_R2T			0x00000008
#define ICF_WITHIN_COMMAND_RECOVERY		0x00000010
#define ICF_CONTIG_MEMORY			0x00000020
#define ICF_ATTACHED_TO_RQUEUE			0x00000040
#define ICF_OOO_CMDSN				0x00000080
#define ICF_REJECT_FAIL_CONN			0x00000100

/* iscsi_cmd_t->i_state */
#define ISTATE_NO_STATE				0
#define ISTATE_NEW_CMD				1
#define ISTATE_DEFERRED_CMD			2
#define ISTATE_UNSOLICITED_DATA			3
#define ISTATE_RECEIVE_DATAOUT			4
#define ISTATE_RECEIVE_DATAOUT_RECOVERY		5
#define ISTATE_RECEIVED_LAST_DATAOUT		6
#define ISTATE_WITHIN_DATAOUT_RECOVERY		7
#define ISTATE_IN_CONNECTION_RECOVERY		8
#define ISTATE_RECEIVED_TASKMGT			9	
#define ISTATE_SEND_ASYNCMSG			10
#define ISTATE_SENT_ASYNCMSG			11
#define	ISTATE_SEND_DATAIN			12
#define ISTATE_SEND_LAST_DATAIN			13
#define ISTATE_SENT_LAST_DATAIN			14
#define ISTATE_SEND_LOGOUTRSP			15
#define ISTATE_SENT_LOGOUTRSP			16
#define ISTATE_SEND_NOPIN			17
#define ISTATE_SENT_NOPIN			18
#define ISTATE_SEND_REJECT			19
#define ISTATE_SENT_REJECT			20
#define	ISTATE_SEND_R2T				21
#define ISTATE_SENT_R2T				22
#define ISTATE_SEND_R2T_RECOVERY		23
#define ISTATE_SENT_R2T_RECOVERY		24
#define ISTATE_SEND_LAST_R2T			25
#define ISTATE_SENT_LAST_R2T			26
#define ISTATE_SEND_LAST_R2T_RECOVERY		27
#define ISTATE_SENT_LAST_R2T_RECOVERY		28
#define ISTATE_SEND_STATUS			29
#define ISTATE_SEND_STATUS_BROKEN_PC		30
#define ISTATE_SENT_STATUS			31
#define ISTATE_SEND_STATUS_RECOVERY		32
#define ISTATE_SENT_STATUS_RECOVERY		33
#define ISTATE_SEND_TASKMGTRSP			34
#define ISTATE_SENT_TASKMGTRSP			35
#define ISTATE_SEND_TEXTRSP			36
#define ISTATE_SENT_TEXTRSP			37
#define ISTATE_SEND_NOPIN_WANT_RESPONSE		38
#define ISTATE_SENT_NOPIN_WANT_RESPONSE		39
#define ISTATE_SEND_NOPIN_NO_RESPONSE		40
#define ISTATE_REMOVE				41
#define ISTATE_FREE				42

/* Used in iscsi_conn_t->conn_flags */
#define CONNFLAG_SCTP_STRUCT_FILE		0x01

/* Used for iscsi_recover_cmdsn() return values */
#define CMDSN_ERROR_CANNOT_RECOVER		-1
#define CMDSN_NORMAL_OPERATION			0
#define CMDSN_LOWER_THAN_EXP			1
#define	CMDSN_HIGHER_THAN_EXP			2

/* Used for iscsi_handle_immediate_data() return values */
#define IMMEDIDATE_DATA_CANNOT_RECOVER		-1
#define IMMEDIDATE_DATA_NORMAL_OPERATION	0
#define IMMEDIDATE_DATA_ERL1_CRC_FAILURE	1

/* Used for iscsi_decide_dataout_action() return values */
#define DATAOUT_CANNOT_RECOVER			-1
#define DATAOUT_NORMAL				0
#define DATAOUT_SEND_R2T			1
#define DATAOUT_SEND_TO_TRANSPORT		2
#define DATAOUT_WITHIN_COMMAND_RECOVERY		3

/* Used for iscsi_node_auth_t structure members */
#define MAX_USER_LEN				256
#define MAX_PASS_LEN				256
#define NAF_USERID_SET				0x01
#define NAF_PASSWORD_SET			0x02
#define NAF_USERID_IN_SET			0x04
#define NAF_PASSWORD_IN_SET			0x08

/* Used for iscsi_cmd_t->dataout_timer_flags */
#define DATAOUT_TF_RUNNING			0x01
#define DATAOUT_TF_STOP				0x02

/* Used for iscsi_conn_t->netif_timer_flags */
#define NETIF_TF_RUNNING			0x01
#define NETIF_TF_STOP				0x02

/* Used for iscsi_conn_t->nopin_timer_flags */
#define NOPIN_TF_RUNNING			0x01
#define NOPIN_TF_STOP				0x02

/* Used for iscsi_conn_t->nopin_response_timer_flags */
#define NOPIN_RESPONSE_TF_RUNNING		0x01
#define NOPIN_RESPONSE_TF_STOP			0x02

/* Used for iscsi_session_t->time2retain_timer_flags */
#define T2R_TF_RUNNING				0x01
#define T2R_TF_STOP				0x02
#define T2R_TF_EXPIRED				0x04

/* Used for iscsi_tpg_np->tpg_np_login_timer_flags */
#define TPG_NP_TF_RUNNING			0x01
#define TPG_NP_TF_STOP				0x02

/* Used for iscsi_np_t->np_flags */
#define NPF_IP_NETWORK				0x00
#define NPF_NET_IPV4                            0x01
#define NPF_NET_IPV6                            0x02
#define NPF_SCTP_STRUCT_FILE			0x20 /* Bugfix */

/* Used for iscsi_np_t->np_thread_state */
#define ISCSI_NP_THREAD_ACTIVE			1
#define ISCSI_NP_THREAD_INACTIVE		2
#define ISCSI_NP_THREAD_RESET			3
#define ISCSI_NP_THREAD_SHUTDOWN		4
#define ISCSI_NP_THREAD_EXIT			5

/* Used for debugging various ERL situations. */
#define TARGET_ERL_MISSING_CMD_SN			1
#define TARGET_ERL_MISSING_CMDSN_BATCH			2
#define TARGET_ERL_MISSING_CMDSN_MIX			3
#define TARGET_ERL_MISSING_CMDSN_MULTI			4
#define TARGET_ERL_HEADER_CRC_FAILURE			5
#define TARGET_ERL_IMMEDIATE_DATA_CRC_FAILURE		6
#define TARGET_ERL_DATA_OUT_CRC_FAILURE			7
#define TARGET_ERL_DATA_OUT_CRC_FAILURE_BATCH		8
#define TARGET_ERL_DATA_OUT_CRC_FAILURE_MIX		9
#define TARGET_ERL_DATA_OUT_CRC_FAILURE_MULTI		10
#define TARGET_ERL_DATA_OUT_FAIL			11
#define TARGET_ERL_DATA_OUT_MISSING			12 /* TODO */
#define TARGET_ERL_DATA_OUT_MISSING_BATCH		13 /* TODO */
#define TARGET_ERL_DATA_OUT_MISSING_MIX			14 /* TODO */
#define TARGET_ERL_DATA_OUT_TIMEOUT			15
#define TARGET_ERL_FORCE_TX_TRANSPORT_RESET		16
#define TARGET_ERL_FORCE_RX_TRANSPORT_RESET		17

extern void frontend_load_plugins (void);

typedef struct iscsi_queue_req_s {
	int			state;
	void			*queue_se_obj_ptr;
	struct se_obj_lun_type_s *queue_se_obj_api;
	struct iscsi_cmd_s	*cmd;
	struct iscsi_queue_req_s *next;
	struct iscsi_queue_req_s *prev;
} ____cacheline_aligned iscsi_queue_req_t;

typedef struct iscsi_data_count_s {
	int			data_length;
	int			sync_and_steering;
	int			type;
	__u32			iov_count;
	__u32			ss_iov_count;
	__u32			ss_marker_count;
	struct iovec		*iov;
} ____cacheline_aligned iscsi_data_count_t;

typedef struct iscsi_param_list_s {
	struct iscsi_param_s	*param_start;
	struct iscsi_extra_response_s *extra_response_start;
} ____cacheline_aligned iscsi_param_list_t;

typedef struct iscsi_datain_req_s {
	int			dr_complete;
	int			generate_recovery_values;
	int			recovery;
	__u32			begrun;
	__u32			runlength;
	__u32			data_length;
	__u32			data_offset;
	__u32			data_offset_end;
	__u32			data_sn;
	__u32			next_burst_len;
	__u32			read_data_done;
	__u32			seq_send_order;
	struct iscsi_datain_req_s *next;
	struct iscsi_datain_req_s *prev;
} ____cacheline_aligned iscsi_datain_req_t;

typedef struct iscsi_ooo_cmdsn_s {
	__u16			cid;
	__u32			batch_count;
	__u32			cmdsn;
	__u32			exp_cmdsn;
	struct iscsi_cmd_s	*cmd;
	struct iscsi_ooo_cmdsn_s *next;
	struct iscsi_ooo_cmdsn_s *prev;
} ____cacheline_aligned iscsi_ooo_cmdsn_t;

typedef struct iscsi_datain_s {
	__u8			flags;
	__u32			data_sn;
	__u32			length;
	__u32			offset;
} ____cacheline_aligned iscsi_datain_t;

typedef struct iscsi_r2t_s {
	int			seq_complete;
	int			recovery_r2t;
	int			sent_r2t;
	__u32			r2t_sn;
	__u32			offset;
	__u32			targ_xfer_tag;
	__u32			xfer_len;
	struct iscsi_r2t_s	*next;
	struct iscsi_r2t_s	*prev;
} ____cacheline_aligned iscsi_r2t_t;

typedef union
{
	u32	ts[2];	/* preserve room for long values */
	time_t	time;
} iscsi_rsig_time_t;

struct se_cmd_s;
struct se_device_s;
struct iscsi_map_sg_s;
struct iscsi_unmap_sg_s;
struct se_transport_task_s;
struct se_transform_info_s;
struct se_obj_lun_type_s;
struct scatterlist;

typedef struct iscsi_fe_cmd_s {
	struct iscsi_cmd_s	*fe_cmd;
	struct iscsi_fe_cmd_s	*fe_next;
	struct iscsi_fe_cmd_s	*fe_prev;
} iscsi_fe_cmd_t;

typedef struct iscsi_cmd_s {
	__u8			data_direction;	/* iSCSI data direction */
	__u8			dataout_timer_flags;
	__u8			dataout_timeout_retries; /* DataOUT timeout retries */
	__u8			error_recovery_count; /* Within command recovery count */
	__u8			deferred_i_state; /* iSCSI dependent state for out or order CmdSNs */
	__u8			i_state;	/* iSCSI dependent state */
	__u8			immediate_cmd;	/* Command is an immediate command (I_BIT set) */
	__u8			immediate_data;	/* Immediate data present */
	__u8			iscsi_opcode;	/* iSCSI Opcode */
	__u8			iscsi_response;	/* iSCSI Response Code */
	__u8			logout_reason;	/* Logout reason when iscsi_opcode == ISCSI_INIT_LOGOUT_CMND */
	__u8			logout_response; /* Logout response code when iscsi_opcode == ISCSI_INIT_LOGOUT_CMND */
	__u8			maxcmdsn_inc;	/* MaxCmdSN has been incremented */
	__u8			unsolicited_data; /* Immediate Unsolicited Dataout */
	__u16			logout_cid;	/* CID contained in logout PDU when iscsi_opcode == ISCSI_INIT_LOGOUT_CMND */
	__u32			cmd_flags;	/* Command flags */
	__u32 			init_task_tag;	/* Initiator Task Tag assigned from Initiator */
	__u32			targ_xfer_tag;	/* Target Transfer Tag assigned from Target */
	__u32			cmd_sn;		/* CmdSN assigned from Initiator */
	__u32			exp_stat_sn;	/* ExpStatSN assigned from Initiator */
	__u32			stat_sn;	/* StatSN assigned to this ITT */
	__u32			data_sn;	/* DataSN Counter */
	__u32			r2t_sn;		/* R2TSN Counter */
	__u32			acked_data_sn;	/* Last DataSN acknowledged via DataAck SNACK */
	__u32			buf_ptr_size;	/* Used for echoing NOPOUT ping data */
	__u32			data_crc;	/* Used to store DataDigest */
	__u32			data_length;	/* Total size in bytes associated with command */
	__u32			outstanding_r2ts; /* Counter for MaxOutstandingR2T */
	__u32			r2t_offset;	/* Next R2T Offset when DataSequenceInOrder=Yes */
	__u32			iov_misc_count;  /* Number of miscellaneous iovecs used for IP stack calls */
	__u32			pad_bytes;	/* Bytes used for 32-bit word padding */
	__u32			pdu_count;	/* Number of iscsi_pdu_t in iscsi_cmd_t->pdu_list */
	__u32			pdu_send_order; /* Next iscsi_pdu_t to send in iscsi_cmd_t->pdu_list */
	__u32			pdu_start;	/* Current iscsi_pdu_t in iscsi_cmd_t->pdu_list */
	__u32			residual_count;
	__u32			seq_send_order; /* Next iscsi_seq_t to send in iscsi_cmd_t->seq_list */
	__u32			seq_count;	/* Number of iscsi_seq_t in iscsi_cmd_t->seq_list */
	__u32			seq_no;		/* Current iscsi_seq_t in iscsi_cmd_t->seq_list */ 
	__u32			seq_start_offset; /* Lowest offset in current DataOUT sequence */
	__u32			seq_end_offset; /* Highest offset in current DataOUT sequence */
	__u32			read_data_done;	/* Total size in bytes received so far of READ data */
	__u32			write_data_done; /* Total size in bytes received so far of WRITE data */
	__u32			first_burst_len; /* Counter for FirstBurstLength key */
	__u32			next_burst_len;	/* Counter for MaxBurstLength key */
	__u32			tx_size;	/* Transfer size used for IP stack calls */
	void			*buf_ptr;	/* Buffer used for various purposes */
	unsigned char		pdu[ISCSI_HDR_LEN + CRC_LEN]; /* iSCSI PDU Header + CRC */
	atomic_t		immed_queue_count; /* Number of times iscsi_cmd_t is present in immediate queue */
	atomic_t		response_queue_count;
	atomic_t		transport_sent;
	spinlock_t		datain_lock;
	spinlock_t		dataout_timeout_lock;
	spinlock_t		istate_lock;	/* spinlock for protecting iscsi_cmd_t->i_state */
	spinlock_t		error_lock;	/* spinlock for adding within command recovery entries */
	spinlock_t		r2t_lock;	/* spinlock for adding R2Ts */
	iscsi_datain_req_t	*datain_req_head; /* Start of DataIN list */
	iscsi_datain_req_t	*datain_req_tail; /* End of DataIN list */
	struct semaphore	reject_sem;
	struct semaphore	unsolicited_data_sem; /* Semaphore used for allocating buffer */
	iscsi_r2t_t		*r2t_head;	/* Start of R2T list */
	iscsi_r2t_t		*r2t_tail;	/* End of R2T list */
	struct timer_list	dataout_timer;	/* Timer for DataOUT */
	struct iovec		iov_misc[ISCSI_MISC_IOVECS]; /* Iovecs for miscellaneous purposes */
	struct iscsi_pdu_s	*pdu_list;	/* Array of iscsi_pdu_t used for DataPDUInOrder=No */
	struct iscsi_pdu_s	*pdu_ptr;	/* Current iscsi_pdu_t used for DataPDUInOrder=No */
	struct iscsi_seq_s	*seq_list;	/* Array of iscsi_seq_t used for DataSequenceInOrder=No */
	struct iscsi_seq_s	*seq_ptr;	/* Current iscsi_seq_t used for DataSequenceInOrder=No */
	struct iscsi_tmr_req_s	*tmr_req;	/* TMR Request when iscsi_opcode == ISCSI_INIT_TASK_MGMT_CMND */
	struct iscsi_conn_s 	*conn;		/* Connection this command is alligient to */
	struct iscsi_conn_recovery_s *cr;	/* Pointer to connection recovery entry */
	struct iscsi_session_s	*sess;		/* Session the command is part of,  used for connection recovery */
	struct iscsi_cmd_s	*next;		/* Next command in the session pool */
	struct iscsi_cmd_s	*i_next;	/* Next command in connection list */
	struct iscsi_cmd_s	*i_prev;	/* Previous command in connection list */
	struct iscsi_cmd_s	*t_next;	/* Next command in DAS transport list */
	struct iscsi_cmd_s	*t_prev;	/* Previous command in DAS transport list */
	struct se_cmd_s		*se_cmd;
}  ____cacheline_aligned iscsi_cmd_t;

#define SE_CMD(cmd)		((struct se_cmd_s *)(cmd)->se_cmd)

#include <iscsi_seq_and_pdu_list.h>

typedef struct iscsi_tmr_req_s {
	u32			ref_cmd_sn;
	u32			exp_data_sn;
	struct iscsi_conn_recovery_s *conn_recovery;
	struct se_tmr_req_s	*se_tmr_req;
} ____cacheline_aligned iscsi_tmr_req_t;			

typedef struct iscsi_conn_s {					
	char			net_dev[ISCSI_NETDEV_NAME_SIZE];
	__u8			auth_complete;	/* Authentication Successful for this connection */
	__u8			conn_state;	/* State connection is currently in */
	__u8			conn_logout_reason;
	__u8			netif_timer_flags;
	__u8			network_transport;
	__u8			nopin_timer_flags;
	__u8			nopin_response_timer_flags;
	__u8			tx_immediate_queue;
	__u8			tx_response_queue;
	__u8			which_thread;	/* Used to know what thread encountered a transport failure */
	__u16			cid;		/* connection id assigned by the Initiator */
	int			net_size;
	__u32			auth_id;
	__u32			conn_flags;
	__u32			login_ip;
	__u32			login_itt;	/* Used for iscsi_tx_login_rsp() */
	__u32			exp_statsn;
	__u32			stat_sn;	/* Per connection status sequence number */
	__u32			if_marker;	/* IFMarkInt's Current Value */
	__u32			of_marker;	/* OFMarkInt's Current Value */
	__u32			of_marker_offset; /* Used for calculating OFMarker offset to next PDU */
	unsigned char		bad_hdr[ISCSI_HDR_LEN]; /* Complete Bad PDU for sending reject */
	unsigned char		ipv6_login_ip[IPV6_ADDRESS_SPACE];
#ifdef SNMP_SUPPORT
	__u16			local_port;
	__u32			local_ip;
	__u32			conn_index;
#endif /* SNMP_SUPPORT */
	atomic_t		active_cmds;
	atomic_t		check_immediate_queue;
	atomic_t		conn_logout_remove;
	atomic_t		conn_usage_count;
	atomic_t		conn_waiting_on_uc;
	atomic_t		connection_exit;
	atomic_t		connection_recovery;
	atomic_t		connection_reinstatement;
	atomic_t		connection_wait;
	atomic_t		connection_wait_rcfr;
	atomic_t		sleep_on_conn_wait_sem;
	atomic_t		transport_failed;
	struct net_device		*net_if;
	struct semaphore		conn_post_wait_sem;
	struct semaphore		conn_wait_sem;
	struct semaphore		conn_wait_rcfr_sem;
	struct semaphore		conn_waiting_on_uc_sem;
	struct semaphore		conn_logout_sem;
	struct semaphore		rx_half_close_sem;
	struct semaphore		tx_half_close_sem;
	struct semaphore		tx_sem;		/* Semaphore for conn's tx_thread to sleep on */
	struct socket		*sock;		/* socket used by this connection */
	struct timer_list		nopin_timer;
	struct timer_list		nopin_response_timer;
	struct timer_list		transport_timer;;
	spinlock_t		cmd_lock;	/* Spinlock used for add/deleting cmd's from cmd_head */
	spinlock_t		conn_usage_lock;
	spinlock_t		immed_queue_lock;
	spinlock_t		netif_lock;
	spinlock_t		nopin_timer_lock;
	spinlock_t		response_queue_lock;
	spinlock_t		state_lock;
	iscsi_cmd_t		*cmd_head;	/* Head of command list for this connection */
	iscsi_cmd_t		*cmd_tail;	/* Tail of command list for this connection */
	iscsi_queue_req_t	*immed_queue_head;
	iscsi_queue_req_t	*immed_queue_tail;
	iscsi_queue_req_t	*response_queue_head;
	iscsi_queue_req_t	*response_queue_tail;
	iscsi_conn_ops_t	*conn_ops;
	iscsi_param_list_t	*param_list;
	void			*auth_protocol; /* Used for per connection auth state machine */
	struct iscsi_login_thread_s *login_thread;
	struct iscsi_portal_group_s *tpg;
	struct iscsi_session_s	*sess;		/* Pointer to parent session */
	struct se_thread_set_s	*thread_set;	/* Pointer to thread_set in use for this conn's threads */
	struct iscsi_conn_s 	*next;		/* Pointer to next connection in session */
	struct iscsi_conn_s	*prev;
} ____cacheline_aligned iscsi_conn_t;

#include <iscsi_parameters.h>
#define CONN(cmd)		((struct iscsi_conn_s *)(cmd)->conn)
#define CONN_OPS(conn)		((iscsi_conn_ops_t *)(conn)->conn_ops)

typedef struct iscsi_conn_recovery_s {
	__u16			cid;
	__u32			cmd_count;
	__u32			maxrecvdatasegmentlength;
	int			ready_for_reallegiance;
	iscsi_cmd_t		*conn_recovery_cmd_head;
	iscsi_cmd_t		*conn_recovery_cmd_tail;
	spinlock_t		conn_recovery_cmd_lock;
	struct semaphore		time2wait_sem;
	struct timer_list		time2retain_timer;
	struct iscsi_session_s	*sess;
	struct iscsi_conn_recovery_s *next;
	struct iscsi_conn_recovery_s *prev;
}  ____cacheline_aligned iscsi_conn_recovery_t;	

typedef struct iscsi_session_s {
	__u8			cmdsn_outoforder;
	__u8			initiator_vendor;
	__u8			isid[6];
	__u8			time2retain_timer_flags;
	__u8			version_active;
	__u16			cid_called;
	__u16			conn_recovery_count;
	__u16			tsih;
	__u32			session_state;	/* state session is currently in */
	__u32			init_task_tag;	/* session wide counter: initiator assigned task tag */
	__u32			targ_xfer_tag;	/* session wide counter: target assigned task tag */ 
	__u32			cmdsn_window;
	__u32			exp_cmd_sn;	/* session wide counter: expected command sequence number */
	__u32			max_cmd_sn;	/* session wide counter: maximum allowed command sequence number */
	__u32			ooo_cmdsn_count;
	__u32			sid;		/* PyX specific session ID */
#ifdef SNMP_SUPPORT
	char			auth_type[8];
	__u32			session_index;	/* unique within the target */
	__u32			cmd_pdus;
	__u32			rsp_pdus;
	__u64			tx_data_octets;
	__u64			rx_data_octets;
	__u32			conn_digest_errors;
	__u32			conn_timeout_errors;
	__u64			creation_time;
	spinlock_t		session_stats_lock;
#endif /* SNMP_SUPPORT */
	atomic_t		nconn;		/* Number of active connections */
	atomic_t		session_continuation;
	atomic_t		session_fall_back_to_erl0;
	atomic_t		session_logout;
	atomic_t		session_reinstatement;
	atomic_t		session_stop_active;
	atomic_t		session_usage_count;
	atomic_t		session_waiting_on_uc;
	atomic_t		sleep_on_sess_wait_sem;
	atomic_t		transport_wait_cmds;
	iscsi_conn_t		*conn_head;	/* Pointer to start of connection list */
	iscsi_conn_t		*conn_tail;	/* Pointer to end of connection list */
	iscsi_conn_recovery_t	*cr_a_head;
	iscsi_conn_recovery_t	*cr_a_tail;
	iscsi_conn_recovery_t	*cr_i_head;
	iscsi_conn_recovery_t	*cr_i_tail;
	spinlock_t		cmdsn_lock;
	spinlock_t		conn_lock;
	spinlock_t		cr_a_lock;
	spinlock_t		cr_i_lock;
	spinlock_t		session_usage_lock;
	spinlock_t		ttt_lock;
	iscsi_ooo_cmdsn_t	*ooo_cmdsn_head;
	iscsi_ooo_cmdsn_t	*ooo_cmdsn_tail;
	struct semaphore		async_msg_sem;
	struct semaphore		reinstatement_sem;
	struct semaphore		session_wait_sem;
	struct semaphore		session_waiting_on_uc_sem;
	struct timer_list		time2retain_timer;
	iscsi_sess_ops_t	*sess_ops;
	struct se_session_s	*se_sess;
	struct iscsi_portal_group_s *tpg;
} ____cacheline_aligned iscsi_session_t;

#define SESS(conn)		((iscsi_session_t *)(conn)->sess)
#define SESS_OPS(sess)		((iscsi_sess_ops_t *)(sess)->sess_ops)
#define SESS_OPS_C(conn)	((iscsi_sess_ops_t *)(conn)->sess->sess_ops)
#define SESS_NODE_ACL(sess)	((se_node_acl_t *)(sess)->se_sess->se_node_acl)

typedef struct iscsi_login_s {
	u8 auth_complete;
	u8 checked_for_existing;
	u8 current_stage;
	u8 leading_connection;
	u8 first_request;
	u8 version_min;
	u8 version_max;
	char isid[6];
	u32 cmd_sn;
	u32 init_task_tag;
	u32 initial_exp_statsn;
	u16 cid;
	u16 tsih;
	char *req;
	char *rsp;
	char *req_buf;
	char *rsp_buf;
} ____cacheline_aligned iscsi_login_t;

typedef struct iscsi_logout_s {
	u8		logout_reason;
	u8		logout_response;
	u16		logout_cid;
} ____cacheline_aligned iscsi_logout_t;

#include <iscsi_thread_queue.h>

#ifdef DEBUG_ERL
typedef struct iscsi_debug_erl_s {
	__u8		counter;
	__u8		state;
	__u8		debug_erl;
	__u8		debug_type;
	__u16		cid;
	__u16		tpgt;
	__u32		cmd_sn;
	__u32		count;
	__u32		data_offset;
	__u32		data_sn;
	__u32		init_task_tag;
	__u32		sid;
}  ____cacheline_aligned iscsi_debug_erl_t;
#endif /* DEBUG_ERL */

typedef struct iscsi_cache_entry_s {
	int		ce_entry_active;
	u32		ce_lru_no;
	unsigned long long	ce_lba;
	u32		ce_sectors;
	u32		ce_task_sg_num;
	void		*ce_task_buf;
}  ____cacheline_aligned iscsi_cache_entry_t;

typedef struct iscsi_cache_check_entry_s {
	unsigned long long	lba;
	u32		sectors;
}  ____cacheline_aligned iscsi_cache_check_entry_t;

typedef struct iscsi_node_attrib_s {
	__u32			dataout_timeout;
	__u32			dataout_timeout_retries;
	__u32			default_erl;
	__u32			nopin_timeout;
	__u32			nopin_response_timeout;
	__u32			random_datain_pdu_offsets;
	__u32			random_datain_seq_offsets;
	__u32			random_r2t_offsets;
	__u32			tmr_cold_reset;
	__u32			tmr_warm_reset;
	struct iscsi_node_acl_s *nacl;
	struct config_group	acl_attrib_group;
} ____cacheline_aligned iscsi_node_attrib_t;

struct se_dev_entry_s;

typedef struct iscsi_node_auth_s {
	int			naf_flags;
	int			authenticate_target;
	char			userid[MAX_USER_LEN];
	char			password[MAX_PASS_LEN];
	char			userid_mutual[MAX_USER_LEN];
	char			password_mutual[MAX_PASS_LEN];
	struct config_group	auth_attrib_group;
} ____cacheline_aligned iscsi_node_auth_t;

typedef struct iscsi_node_acl_s {
	iscsi_node_attrib_t	node_attrib;
	iscsi_node_auth_t	node_auth;
	struct se_node_acl_s	*se_node_acl;
} ____cacheline_aligned iscsi_node_acl_t;

#define ISCSI_NODE_ATTRIB(t)	(&(t)->node_attrib)
#define ISCSI_NODE_AUTH(t)	(&(t)->node_auth)

typedef struct iscsi_tpg_attrib_s {
	u32			authentication;
	u32			login_timeout;
	u32			netif_timeout;
	u32			generate_node_acls;
	u32			cache_dynamic_acls;
	u32			default_cmdsn_depth;
	u32			demo_mode_write_protect;
	u32			prod_mode_write_protect;
	u32			cache_core_nps;
	struct iscsi_portal_group_s *tpg;
	struct config_group	tpg_attrib_group;
}  ____cacheline_aligned iscsi_tpg_attrib_t;

typedef struct iscsi_np_ex_s {
	int			np_ex_net_size;
	u16			np_ex_port;
	u32			np_ex_ipv4;
	unsigned char		np_ex_ipv6[IPV6_ADDRESS_SPACE];
	struct list_head	np_ex_list;
} iscsi_np_ex_t;

typedef struct iscsi_np_s {
	unsigned char		np_net_dev[ISCSI_NETDEV_NAME_SIZE];
	int			np_network_transport;
	int			np_thread_state;
	int			np_login_timer_flags;
	int			np_net_size;
	u32			np_exports;
	u32			np_flags;
	u32			np_ipv4;
	unsigned char		np_ipv6[IPV6_ADDRESS_SPACE];
#ifdef SNMP_SUPPORT
	u32			np_index;
#endif
	u16			np_port;
	atomic_t		np_shutdown;
	spinlock_t		np_ex_lock;
	spinlock_t		np_state_lock;
	spinlock_t		np_thread_lock;
	struct semaphore		np_done_sem;
	struct semaphore		np_restart_sem;
	struct semaphore		np_shutdown_sem;
	struct semaphore		np_start_sem;
	struct socket		*np_socket;
	struct task_struct		*np_thread;
	struct timer_list		np_login_timer;
	struct iscsi_portal_group_s *np_login_tpg;
	struct list_head	np_list;
	struct list_head	np_nex_list;
} ____cacheline_aligned iscsi_np_t;

typedef struct iscsi_tpg_np_s {
#ifdef SNMP_SUPPORT
	u32			tpg_np_index;
#endif /* SNMP_SUPPORT */
	iscsi_np_t		*tpg_np;
	struct iscsi_portal_group_s *tpg;
	struct iscsi_tpg_np_s	*tpg_np_parent;
	struct list_head	tpg_np_list;
	struct list_head	tpg_np_child_list;
	struct list_head	tpg_np_parent_list;
	struct config_group	tpg_np_group;
	spinlock_t		tpg_np_parent_lock;
} ____cacheline_aligned iscsi_tpg_np_t;

typedef struct iscsi_np_addr_s {
	u16		np_port;
	u32		np_flags;
	u32		np_ipv4;
	unsigned char	np_ipv6[IPV6_ADDRESS_SPACE];
} ____cacheline_aligned iscsi_np_addr_t;
  
typedef struct iscsi_portal_group_s {
	unsigned char		tpg_chap_id;
	__u8			tpg_state;	/* TPG State */
	__u16			tpgt;		/* Target Portal Group Tag */
	__u16			ntsih;		/* Id assigned to target sessions */
	__u32			ndevs;		/* Number of available iSCSI devices */
	__u32			nluns;		/* Number of active iSCSI LUNs */
	__u32			nsessions;	/* Number of active sessions */
	__u32			num_tpg_nps;	/* Number of Network Portals available for this TPG */
	__u32			sid;		/* Per TPG PyX specific session ID. */
	spinlock_t		tpg_np_lock;	/* Spinlock for adding/removing Network Portals */
	spinlock_t		tpg_state_lock;
	struct se_portal_group_s *tpg_se_tpg;
	struct config_group	tpg_np_group;
	struct config_group	tpg_lun_group;
	struct config_group	tpg_acl_group;
	struct config_group	tpg_param_group;
	struct semaphore	tpg_access_sem;
	struct semaphore	np_login_sem;
	iscsi_tpg_attrib_t	tpg_attrib;
	iscsi_param_list_t	*param_list;	/* Pointer to default list of iSCSI parameters for TPG */
	struct iscsi_tiqn_s	*tpg_tiqn;
	struct iscsi_portal_group_s *next;	/* Pointer to next TPG entry */
	struct iscsi_portal_group_s *prev;
	struct list_head 	tpg_gnp_list;
	struct list_head	tpg_list;
	struct list_head	g_tpg_list;
} ____cacheline_aligned iscsi_portal_group_t;

#define ISCSI_TPG_C(c)		((iscsi_portal_group_t *)(c)->tpg)
#define ISCSI_TPG_LUN(c, lun)	((iscsi_tpg_list_t *)(c)->tpg->tpg_lun_list_t[lun])
#define ISCSI_TPG_S(s)		((iscsi_portal_group_t *)(s)->tpg)
#define ISCSI_TPG_ATTRIB(t)	(&(t)->tpg_attrib)
#define SE_TPG(tpg)		((struct se_portal_group_s *)(tpg)->tpg_se_tpg)

typedef struct iscsi_tiqn_s {
	unsigned char		tiqn[ISCSI_TIQN_LEN];
	int			tiqn_state;
	u32			tiqn_active_tpgs;
	u32			tiqn_ntpgs;
	u32			tiqn_num_tpg_nps;
	u32			tiqn_nsessions;
	struct list_head	tiqn_list;		
	struct list_head	tiqn_tpg_list;
	atomic_t		tiqn_access_count;
	spinlock_t		tiqn_state_lock;
	spinlock_t		tiqn_tpg_lock;
	struct config_group	tiqn_group;
#ifdef SNMP_SUPPORT
	u32			tiqn_index;
        iscsi_sess_err_stats_t  sess_err_stats;
        iscsi_login_stats_t     login_stats;
        iscsi_logout_stats_t    logout_stats;
#endif /* SNMP_SUPPORT */
} ____cacheline_aligned iscsi_tiqn_t;

typedef struct iscsi_global_s {
	char			targetname[ISCSI_IQN_LEN]; /* iSCSI Node Name */
	u32			in_rmmod;	/* In module removal */
	u32			in_shutdown;	/* In core shutdown */
	u32			targetname_set; /* Is the iSCSI Node name set? */
	u32			active_ts;
	u32			auth_id;	/* Unique identifier used for the authentication daemon */
	u32			inactive_ts;
	u32			nluns;		/* Number of active iSCSI LUNs */
	u32			thread_id;	/* Thread ID counter */
	int (*ti_forcechanoffline)(void *);
	struct list_head	g_tiqn_list;
	struct list_head	g_tpg_list;
	struct list_head	tpg_list;
	struct list_head	g_np_list;
	spinlock_t		active_ts_lock;
	spinlock_t		check_thread_lock;
	spinlock_t		discovery_lock; /* Spinlock for adding/removing discovery entries */
	spinlock_t		inactive_ts_lock;
	spinlock_t		login_thread_lock; /* Spinlock for adding/removing login threads */
	spinlock_t		shutdown_lock;
	spinlock_t		thread_set_lock; /* Spinlock for adding/removing thread sets */
	spinlock_t		tiqn_lock;	/* Spinlock for iscsi_tiqn_t */
	spinlock_t		g_tpg_lock;
	spinlock_t		np_lock;	/* Spinlock g_np_list */
	struct semaphore		auth_sem;	/* Semaphore used for communication to authentication daemon */
	struct semaphore		auth_id_sem;	/* Semaphore used for allocate of iscsi_conn_t->auth_id */
	iscsi_portal_group_t	*discovery_tpg;
#ifdef DEBUG_ERL
	iscsi_debug_erl_t	*debug_erl;
	spinlock_t		debug_erl_lock;
#endif /* DEBUG_ERL */
	se_thread_set_t		*active_ts_head;
	se_thread_set_t		*active_ts_tail;
	se_thread_set_t		*inactive_ts_head;
	se_thread_set_t		*inactive_ts_tail;
} ____cacheline_aligned iscsi_global_t;

#define ISCSI_DEBUG_ERL(g)	((iscsi_debug_erl_t *)(g)->debug_erl)

#endif /* ISCSI_TARGET_CORE_H */
