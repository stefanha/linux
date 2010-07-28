#ifndef ISCSI_TARGET_CORE_H
#define ISCSI_TARGET_CORE_H

#include <linux/in.h>
#include <linux/configfs.h>
#include <net/sock.h>
#include <net/tcp.h>
#include <iscsi_linux_defs.h>
#include <iscsi_target_version.h>	    /* get version definition */

#include <target/target_core_base.h>

#define SHUTDOWN_SIGS	(sigmask(SIGKILL)|sigmask(SIGINT)|sigmask(SIGABRT))
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
/* from target_core_base.h */
#define ISCSI_MAX_LUNS_PER_TPG		TRANSPORT_MAX_LUNS_PER_TPG
/* Maximum Target Portal Groups allowed */
#define ISCSI_MAX_TPGS			64
/* Size of the Network Device Name Buffer */
#define ISCSI_NETDEV_NAME_SIZE		12

#include <iscsi_target_mib.h>

/* struct iscsi_tpg_np->tpg_np_network_transport */
#define ISCSI_TCP			0
#define ISCSI_SCTP_TCP			1
#define ISCSI_SCTP_UDP			2
#define ISCSI_IWARP_TCP			3
#define ISCSI_IWARP_SCTP		4
#define ISCSI_INFINIBAND		5

#define ISCSI_TCP_VERSION		"v3.0"
#define ISCSI_SCTP_VERSION		"v3.0"

/* struct iscsi_node_attrib sanity values */
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

/* struct iscsi_tpg_attrib sanity values */
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
/* Enabled by default in demo mode (generic_node_acls=1) */
#define TA_DEMO_MODE_WRITE_PROTECT	1
/* Disabled by default in production mode w/ explict ACLs */
#define TA_PROD_MODE_WRITE_PROTECT	0
#define TA_CACHE_CORE_NPS		0

/* struct iscsi_data_count->type */
#define ISCSI_RX_DATA				1
#define ISCSI_TX_DATA				2

/* struct iscsi_datain_req->dr_done */
#define DATAIN_COMPLETE_NORMAL			1
#define DATAIN_COMPLETE_WITHIN_COMMAND_RECOVERY 2
#define DATAIN_COMPLETE_CONNECTION_RECOVERY	3

/* struct iscsi_datain_req->recovery */
#define DATAIN_WITHIN_COMMAND_RECOVERY		1
#define DATAIN_CONNECTION_RECOVERY		2

/* struct iscsi_portal_group->state */
#define TPG_STATE_FREE				0
#define TPG_STATE_ACTIVE			1
#define TPG_STATE_INACTIVE			2
#define TPG_STATE_COLD_RESET			3

/* iscsi_set_device_attribute() states */
#define ISCSI_DEVATTRIB_ENABLE_DEVICE		1
#define ISCSI_DEVATTRIB_DISABLE_DEVICE		2
#define ISCSI_DEVATTRIB_ADD_LUN_ACL		3
#define ISCSI_DEVATTRIB_DELETE_LUN_ACL		4

/* struct iscsi_cmd->data_direction, same values as target_core_base.h
   and struct se_cmd->data_direction  */
#define ISCSI_NONE				0
#define ISCSI_READ				1
#define ISCSI_WRITE				2
#define ISCSI_BIDI				3

/* struct iscsi_tiqn->tiqn_state */
#define TIQN_STATE_ACTIVE			1
#define TIQN_STATE_SHUTDOWN			2

/* struct iscsi_cmd->cmd_flags */
#define ICF_GOT_LAST_DATAOUT			0x00000001
#define ICF_GOT_DATACK_SNACK			0x00000002
#define ICF_NON_IMMEDIATE_UNSOLICITED_DATA	0x00000004
#define ICF_SENT_LAST_R2T			0x00000008
#define ICF_WITHIN_COMMAND_RECOVERY		0x00000010
#define ICF_CONTIG_MEMORY			0x00000020
#define ICF_ATTACHED_TO_RQUEUE			0x00000040
#define ICF_OOO_CMDSN				0x00000080
#define ICF_REJECT_FAIL_CONN			0x00000100

/* struct iscsi_cmd->i_state */
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

/* Used in struct iscsi_conn->conn_flags */
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

/* Used for struct iscsi_node_auth structure members */
#define MAX_USER_LEN				256
#define MAX_PASS_LEN				256
#define NAF_USERID_SET				0x01
#define NAF_PASSWORD_SET			0x02
#define NAF_USERID_IN_SET			0x04
#define NAF_PASSWORD_IN_SET			0x08

/* Used for struct iscsi_cmd->dataout_timer_flags */
#define DATAOUT_TF_RUNNING			0x01
#define DATAOUT_TF_STOP				0x02

/* Used for struct iscsi_conn->netif_timer_flags */
#define NETIF_TF_RUNNING			0x01
#define NETIF_TF_STOP				0x02

/* Used for struct iscsi_conn->nopin_timer_flags */
#define NOPIN_TF_RUNNING			0x01
#define NOPIN_TF_STOP				0x02

/* Used for struct iscsi_conn->nopin_response_timer_flags */
#define NOPIN_RESPONSE_TF_RUNNING		0x01
#define NOPIN_RESPONSE_TF_STOP			0x02

/* Used for struct iscsi_session->time2retain_timer_flags */
#define T2R_TF_RUNNING				0x01
#define T2R_TF_STOP				0x02
#define T2R_TF_EXPIRED				0x04

/* Used for iscsi_tpg_np->tpg_np_login_timer_flags */
#define TPG_NP_TF_RUNNING			0x01
#define TPG_NP_TF_STOP				0x02

/* Used for struct iscsi_np->np_flags */
#define NPF_IP_NETWORK				0x00
#define NPF_NET_IPV4                            0x01
#define NPF_NET_IPV6                            0x02
#define NPF_SCTP_STRUCT_FILE			0x20 /* Bugfix */

/* Used for struct iscsi_np->np_thread_state */
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

struct iscsi_queue_req {
	int			state;
	void			*queue_se_obj_ptr;
	struct se_obj_lun_type_s *queue_se_obj_api;
	struct iscsi_cmd	*cmd;
	struct list_head	qr_list;
} ____cacheline_aligned;

struct iscsi_data_count {
	int			data_length;
	int			sync_and_steering;
	int			type;
	u32			iov_count;
	u32			ss_iov_count;
	u32			ss_marker_count;
	struct iovec		*iov;
} ____cacheline_aligned;

struct iscsi_param_list {
	struct list_head	param_list;
	struct list_head	extra_response_list;
} ____cacheline_aligned;

struct iscsi_datain_req {
	int			dr_complete;
	int			generate_recovery_values;
	int			recovery;
	u32			begrun;
	u32			runlength;
	u32			data_length;
	u32			data_offset;
	u32			data_offset_end;
	u32			data_sn;
	u32			next_burst_len;
	u32			read_data_done;
	u32			seq_send_order;
	struct list_head	dr_list;
} ____cacheline_aligned;

struct iscsi_ooo_cmdsn {
	u16			cid;
	u32			batch_count;
	u32			cmdsn;
	u32			exp_cmdsn;
	struct iscsi_cmd	*cmd;
	struct list_head	ooo_list;
} ____cacheline_aligned;

struct iscsi_datain {
	u8			flags;
	u32			data_sn;
	u32			length;
	u32			offset;
} ____cacheline_aligned;

struct iscsi_r2t {
	int			seq_complete;
	int			recovery_r2t;
	int			sent_r2t;
	u32			r2t_sn;
	u32			offset;
	u32			targ_xfer_tag;
	u32			xfer_len;
	struct list_head	r2t_list;
} ____cacheline_aligned;

struct iscsi_cmd {
	/* iSCSI data direction */
	u8			data_direction;
	u8			dataout_timer_flags;
	/* DataOUT timeout retries */
	u8			dataout_timeout_retries;
	/* Within command recovery count */
	u8			error_recovery_count;
	/* iSCSI dependent state for out or order CmdSNs */
	u8			deferred_i_state;
	/* iSCSI dependent state */
	u8			i_state;
	/* Command is an immediate command (I_BIT set) */
	u8			immediate_cmd;
	/* Immediate data present */
	u8			immediate_data;
	/* iSCSI Opcode */
	u8			iscsi_opcode;
	/* iSCSI Response Code */
	u8			iscsi_response;
	/* Logout reason when iscsi_opcode == ISCSI_INIT_LOGOUT_CMND */
	u8			logout_reason;
	/* Logout response code when iscsi_opcode == ISCSI_INIT_LOGOUT_CMND */
	u8			logout_response;
	/* MaxCmdSN has been incremented */
	u8			maxcmdsn_inc;
	/* Immediate Unsolicited Dataout */
	u8			unsolicited_data;
	/* CID contained in logout PDU when opcode == ISCSI_INIT_LOGOUT_CMND */
	u16			logout_cid;
	/* Command flags */
	u32			cmd_flags;
	/* Initiator Task Tag assigned from Initiator */
	u32 			init_task_tag;
	/* Target Transfer Tag assigned from Target */
	u32			targ_xfer_tag;
	/* CmdSN assigned from Initiator */
	u32			cmd_sn;
	/* ExpStatSN assigned from Initiator */
	u32			exp_stat_sn;
	/* StatSN assigned to this ITT */
	u32			stat_sn;
	/* DataSN Counter */
	u32			data_sn;
	/* R2TSN Counter */
	u32			r2t_sn;
	/* Last DataSN acknowledged via DataAck SNACK */
	u32			acked_data_sn;
	/* Used for echoing NOPOUT ping data */
	u32			buf_ptr_size;
	/* Used to store DataDigest */
	u32			data_crc;
	/* Total size in bytes associated with command */
	u32			data_length;
	/* Counter for MaxOutstandingR2T */
	u32			outstanding_r2ts;
	/* Next R2T Offset when DataSequenceInOrder=Yes */
	u32			r2t_offset;
	/* Number of miscellaneous iovecs used for IP stack calls */
	u32			iov_misc_count;
	/* Bytes used for 32-bit word padding */
	u32			pad_bytes;
	/* Number of struct iscsi_pdu in struct iscsi_cmd->pdu_list */
	u32			pdu_count;
	/* Next struct iscsi_pdu to send in struct iscsi_cmd->pdu_list */
	u32			pdu_send_order;
	/* Current struct iscsi_pdu in struct iscsi_cmd->pdu_list */
	u32			pdu_start;
	u32			residual_count;
	/* Next struct iscsi_seq to send in struct iscsi_cmd->seq_list */
	u32			seq_send_order;
	/* Number of struct iscsi_seq in struct iscsi_cmd->seq_list */
	u32			seq_count;
	/* Current struct iscsi_seq in struct iscsi_cmd->seq_list */
	u32			seq_no;
	/* Lowest offset in current DataOUT sequence */
	u32			seq_start_offset;
	/* Highest offset in current DataOUT sequence */
	u32			seq_end_offset;
	/* Total size in bytes received so far of READ data */
	u32			read_data_done;
	/* Total size in bytes received so far of WRITE data */
	u32			write_data_done;
	/* Counter for FirstBurstLength key */
	u32			first_burst_len;
	/* Counter for MaxBurstLength key */
	u32			next_burst_len;
	/* Transfer size used for IP stack calls */
	u32			tx_size;
	/* Buffer used for various purposes */
	void			*buf_ptr;
	/* iSCSI PDU Header + CRC */
	unsigned char		pdu[ISCSI_HDR_LEN + CRC_LEN];
	/* Number of times struct iscsi_cmd is present in immediate queue */
	atomic_t		immed_queue_count;
	atomic_t		response_queue_count;
	atomic_t		transport_sent;
	spinlock_t		datain_lock;
	spinlock_t		dataout_timeout_lock;
	/* spinlock for protecting struct iscsi_cmd->i_state */
	spinlock_t		istate_lock;
	/* spinlock for adding within command recovery entries */
	spinlock_t		error_lock;
	/* spinlock for adding R2Ts */
	spinlock_t		r2t_lock;
	/* DataIN List */
	struct list_head	datain_list;
	/* R2T List */
	struct list_head	cmd_r2t_list;
	struct semaphore	reject_sem;
	/* Semaphore used for allocating buffer */
	struct semaphore	unsolicited_data_sem;
	/* Timer for DataOUT */
	struct timer_list	dataout_timer;
	/* Iovecs for miscellaneous purposes */
	struct iovec		iov_misc[ISCSI_MISC_IOVECS];
	/* Array of struct iscsi_pdu used for DataPDUInOrder=No */
	struct iscsi_pdu	*pdu_list;
	/* Current struct iscsi_pdu used for DataPDUInOrder=No */
	struct iscsi_pdu	*pdu_ptr;
	/* Array of struct iscsi_seq used for DataSequenceInOrder=No */
	struct iscsi_seq	*seq_list;
	/* Current struct iscsi_seq used for DataSequenceInOrder=No */
	struct iscsi_seq	*seq_ptr;
	/* TMR Request when iscsi_opcode == ISCSI_INIT_TASK_MGMT_CMND */
	struct iscsi_tmr_req	*tmr_req;
	/* Connection this command is alligient to */
	struct iscsi_conn 	*conn;
	/* Pointer to connection recovery entry */
	struct iscsi_conn_recovery *cr;
	/* Session the command is part of,  used for connection recovery */
	struct iscsi_session	*sess;
	/* Next command in the session pool */
	struct iscsi_cmd	*next;
	/* list_head for connection list */
	struct list_head	i_list;
	/* Next command in DAS transport list */
	struct iscsi_cmd	*t_next;
	/* Previous command in DAS transport list */
	struct iscsi_cmd	*t_prev;
	struct se_cmd		*se_cmd;
}  ____cacheline_aligned;

#define SE_CMD(cmd)		((struct se_cmd *)(cmd)->se_cmd)

#include <iscsi_seq_and_pdu_list.h>

struct iscsi_tmr_req {
	u32			ref_cmd_sn;
	u32			exp_data_sn;
	struct iscsi_conn_recovery *conn_recovery;
	struct se_tmr_req	*se_tmr_req;
} ____cacheline_aligned;

struct iscsi_conn {
	char			net_dev[ISCSI_NETDEV_NAME_SIZE];
	/* Authentication Successful for this connection */
	u8			auth_complete;
	/* State connection is currently in */
	u8			conn_state;
	u8			conn_logout_reason;
	u8			netif_timer_flags;
	u8			network_transport;
	u8			nopin_timer_flags;
	u8			nopin_response_timer_flags;
	u8			tx_immediate_queue;
	u8			tx_response_queue;
	/* Used to know what thread encountered a transport failure */
	u8			which_thread;
	/* connection id assigned by the Initiator */
	u16			cid;
	/* Remote TCP Port */
	u16			login_port;
	int			net_size;
	u32			auth_id;
	u32			conn_flags;
	/* Remote TCP IP address */
	u32			login_ip;
	/* Used for iscsi_tx_login_rsp() */
	u32			login_itt;
	u32			exp_statsn;
	/* Per connection status sequence number */
	u32			stat_sn;
	/* IFMarkInt's Current Value */
	u32			if_marker;
	/* OFMarkInt's Current Value */
	u32			of_marker;
	/* Used for calculating OFMarker offset to next PDU */
	u32			of_marker_offset;
	/* Complete Bad PDU for sending reject */
	unsigned char		bad_hdr[ISCSI_HDR_LEN];
	unsigned char		ipv6_login_ip[IPV6_ADDRESS_SPACE];
	u16			local_port;
	u32			local_ip;
	u32			conn_index;
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
	struct net_device	*net_if;
	struct semaphore	conn_post_wait_sem;
	struct semaphore	conn_wait_sem;
	struct semaphore	conn_wait_rcfr_sem;
	struct semaphore	conn_waiting_on_uc_sem;
	struct semaphore	conn_logout_sem;
	struct semaphore	rx_half_close_sem;
	struct semaphore	tx_half_close_sem;
	/* Semaphore for conn's tx_thread to sleep on */
	struct semaphore	tx_sem;
	/* socket used by this connection */
	struct socket		*sock;
	struct timer_list	nopin_timer;
	struct timer_list	nopin_response_timer;
	struct timer_list	transport_timer;;
	/* Spinlock used for add/deleting cmd's from conn_cmd_list */
	spinlock_t		cmd_lock;
	spinlock_t		conn_usage_lock;
	spinlock_t		immed_queue_lock;
	spinlock_t		netif_lock;
	spinlock_t		nopin_timer_lock;
	spinlock_t		response_queue_lock;
	spinlock_t		state_lock;
	/* list_head of struct iscsi_cmd for this connection */
	struct list_head	conn_cmd_list;
	struct list_head	immed_queue_list;
	struct list_head	response_queue_list;
	struct iscsi_conn_ops	*conn_ops;
	struct iscsi_param_list	*param_list;
	/* Used for per connection auth state machine */
	void			*auth_protocol;
	struct iscsi_login_thread_s *login_thread;
	struct iscsi_portal_group *tpg;
	/* Pointer to parent session */
	struct iscsi_session	*sess;
	/* Pointer to thread_set in use for this conn's threads */
	struct se_thread_set	*thread_set;
	/* list_head for session connection list */
	struct list_head	conn_list;
} ____cacheline_aligned;

#include <iscsi_parameters.h>
#define CONN(cmd)		((struct iscsi_conn *)(cmd)->conn)
#define CONN_OPS(conn)		((struct iscsi_conn_ops *)(conn)->conn_ops)

struct iscsi_conn_recovery {
	u16			cid;
	u32			cmd_count;
	u32			maxrecvdatasegmentlength;
	int			ready_for_reallegiance;
	struct list_head	conn_recovery_cmd_list;
	spinlock_t		conn_recovery_cmd_lock;
	struct semaphore		time2wait_sem;
	struct timer_list		time2retain_timer;
	struct iscsi_session	*sess;
	struct list_head	cr_list;
}  ____cacheline_aligned;

struct iscsi_session {
	u8			cmdsn_outoforder;
	u8			initiator_vendor;
	u8			isid[6];
	u8			time2retain_timer_flags;
	u8			version_active;
	u16			cid_called;
	u16			conn_recovery_count;
	u16			tsih;
	/* state session is currently in */
	u32			session_state;
	/* session wide counter: initiator assigned task tag */
	u32			init_task_tag;
	/* session wide counter: target assigned task tag */
	u32			targ_xfer_tag;
	u32			cmdsn_window;
	/* session wide counter: expected command sequence number */
	u32			exp_cmd_sn;
	/* session wide counter: maximum allowed command sequence number */
	u32			max_cmd_sn;
	u32			ooo_cmdsn_count;
	/* LIO specific session ID */
	u32			sid;
	char			auth_type[8];
	/* unique within the target */
	u32			session_index;
	u32			cmd_pdus;
	u32			rsp_pdus;
	u64			tx_data_octets;
	u64			rx_data_octets;
	u32			conn_digest_errors;
	u32			conn_timeout_errors;
	u64			creation_time;
	spinlock_t		session_stats_lock;
	/* Number of active connections */
	atomic_t		nconn;
	atomic_t		session_continuation;
	atomic_t		session_fall_back_to_erl0;
	atomic_t		session_logout;
	atomic_t		session_reinstatement;
	atomic_t		session_stop_active;
	atomic_t		session_usage_count;
	atomic_t		session_waiting_on_uc;
	atomic_t		sleep_on_sess_wait_sem;
	atomic_t		transport_wait_cmds;
	/* connection list */
	struct list_head	sess_conn_list;
	struct list_head	cr_active_list;
	struct list_head	cr_inactive_list;
	spinlock_t		cmdsn_lock;
	spinlock_t		conn_lock;
	spinlock_t		cr_a_lock;
	spinlock_t		cr_i_lock;
	spinlock_t		session_usage_lock;
	spinlock_t		ttt_lock;
	struct list_head	sess_ooo_cmdsn_list;
	struct semaphore	async_msg_sem;
	struct semaphore	reinstatement_sem;
	struct semaphore	session_wait_sem;
	struct semaphore	session_waiting_on_uc_sem;
	struct timer_list	time2retain_timer;
	struct iscsi_sess_ops	*sess_ops;
	struct se_session	*se_sess;
	struct iscsi_portal_group *tpg;
} ____cacheline_aligned;

#define SESS(conn)		((struct iscsi_session *)(conn)->sess)
#define SESS_OPS(sess)		((struct iscsi_sess_ops *)(sess)->sess_ops)
#define SESS_OPS_C(conn)	((struct iscsi_sess_ops *)(conn)->sess->sess_ops)
#define SESS_NODE_ACL(sess)	((struct se_node_acl *)(sess)->se_sess->se_node_acl)

struct iscsi_login {
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
} ____cacheline_aligned;

#include <iscsi_thread_queue.h>

#ifdef DEBUG_ERL
struct iscsi_debug_erl {
	u8		counter;
	u8		state;
	u8		debug_erl;
	u8		debug_type;
	u16		cid;
	u16		tpgt;
	u32		cmd_sn;
	u32		count;
	u32		data_offset;
	u32		data_sn;
	u32		init_task_tag;
	u32		sid;
}  ____cacheline_aligned;
#endif /* DEBUG_ERL */

struct iscsi_node_attrib {
	u32			dataout_timeout;
	u32			dataout_timeout_retries;
	u32			default_erl;
	u32			nopin_timeout;
	u32			nopin_response_timeout;
	u32			random_datain_pdu_offsets;
	u32			random_datain_seq_offsets;
	u32			random_r2t_offsets;
	u32			tmr_cold_reset;
	u32			tmr_warm_reset;
	struct iscsi_node_acl *nacl;
} ____cacheline_aligned;

struct se_dev_entry_s;

struct iscsi_node_auth {
	int			naf_flags;
	int			authenticate_target;
	/* Used for iscsi_global->discovery_auth,
	 * set to zero (auth disabled) by default */
	int			enforce_discovery_auth;
	char			userid[MAX_USER_LEN];
	char			password[MAX_PASS_LEN];
	char			userid_mutual[MAX_USER_LEN];
	char			password_mutual[MAX_PASS_LEN];
} ____cacheline_aligned;

struct iscsi_node_acl {
	struct iscsi_node_attrib node_attrib;
	struct iscsi_node_auth	node_auth;
	struct se_node_acl	se_node_acl;
} ____cacheline_aligned;

#define ISCSI_NODE_ATTRIB(t)	(&(t)->node_attrib)
#define ISCSI_NODE_AUTH(t)	(&(t)->node_auth)

struct iscsi_tpg_attrib {
	u32			authentication;
	u32			login_timeout;
	u32			netif_timeout;
	u32			generate_node_acls;
	u32			cache_dynamic_acls;
	u32			default_cmdsn_depth;
	u32			demo_mode_write_protect;
	u32			prod_mode_write_protect;
	u32			cache_core_nps;
	struct iscsi_portal_group *tpg;
}  ____cacheline_aligned;

struct iscsi_np_ex {
	int			np_ex_net_size;
	u16			np_ex_port;
	u32			np_ex_ipv4;
	unsigned char		np_ex_ipv6[IPV6_ADDRESS_SPACE];
	struct list_head	np_ex_list;
} ____cacheline_aligned;

struct iscsi_np {
	unsigned char		np_net_dev[ISCSI_NETDEV_NAME_SIZE];
	int			np_network_transport;
	int			np_thread_state;
	int			np_login_timer_flags;
	int			np_net_size;
	u32			np_exports;
	u32			np_flags;
	u32			np_ipv4;
	unsigned char		np_ipv6[IPV6_ADDRESS_SPACE];
	u32			np_index;
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
	struct iscsi_portal_group *np_login_tpg;
	struct list_head	np_list;
	struct list_head	np_nex_list;
} ____cacheline_aligned;

struct iscsi_tpg_np {
	u32			tpg_np_index;
	struct iscsi_np		*tpg_np;
	struct iscsi_portal_group *tpg;
	struct iscsi_tpg_np	*tpg_np_parent;
	struct list_head	tpg_np_list;
	struct list_head	tpg_np_child_list;
	struct list_head	tpg_np_parent_list;
	struct se_tpg_np	se_tpg_np;
	spinlock_t		tpg_np_parent_lock;
} ____cacheline_aligned;

struct iscsi_np_addr {
	u16		np_port;
	u32		np_flags;
	u32		np_ipv4;
	unsigned char	np_ipv6[IPV6_ADDRESS_SPACE];
} ____cacheline_aligned;

struct iscsi_portal_group {
	unsigned char		tpg_chap_id;
	/* TPG State */
	u8			tpg_state;
	/* Target Portal Group Tag */
	u16			tpgt;
	/* Id assigned to target sessions */
	u16			ntsih;
	/* Number of active sessions */
	u32			nsessions;
	/* Number of Network Portals available for this TPG */
	u32			num_tpg_nps;
	/* Per TPG LIO specific session ID. */
	u32			sid;
	/* Spinlock for adding/removing Network Portals */
	spinlock_t		tpg_np_lock;
	spinlock_t		tpg_state_lock;
	struct se_portal_group tpg_se_tpg;
	struct semaphore	tpg_access_sem;
	struct semaphore	np_login_sem;
	struct iscsi_tpg_attrib	tpg_attrib;
	/* Pointer to default list of iSCSI parameters for TPG */
	struct iscsi_param_list	*param_list;
	struct iscsi_tiqn	*tpg_tiqn;
	struct list_head 	tpg_gnp_list;
	struct list_head	tpg_list;
	struct list_head	g_tpg_list;
} ____cacheline_aligned;

#define ISCSI_TPG_C(c)		((struct iscsi_portal_group *)(c)->tpg)
#define ISCSI_TPG_LUN(c, l)  ((iscsi_tpg_list_t *)(c)->tpg->tpg_lun_list_t[l])
#define ISCSI_TPG_S(s)		((struct iscsi_portal_group *)(s)->tpg)
#define ISCSI_TPG_ATTRIB(t)	(&(t)->tpg_attrib)
#define SE_TPG(tpg)		(&(tpg)->tpg_se_tpg)

struct iscsi_tiqn {
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
	struct se_wwn		tiqn_wwn;
	u32			tiqn_index;
	struct iscsi_sess_err_stats  sess_err_stats;
	struct iscsi_login_stats     login_stats;
	struct iscsi_logout_stats    logout_stats;
} ____cacheline_aligned;

struct iscsi_global {
	/* iSCSI Node Name */
	char			targetname[ISCSI_IQN_LEN];
	/* In module removal */
	u32			in_rmmod;
	/* In core shutdown */
	u32			in_shutdown;
	/* Is the iSCSI Node name set? */
	u32			targetname_set;
	u32			active_ts;
	/* Unique identifier used for the authentication daemon */
	u32			auth_id;
	u32			inactive_ts;
	/* Thread ID counter */
	u32			thread_id;
	int (*ti_forcechanoffline)(void *);
	struct list_head	g_tiqn_list;
	struct list_head	g_tpg_list;
	struct list_head	tpg_list;
	struct list_head	g_np_list;
	spinlock_t		active_ts_lock;
	spinlock_t		check_thread_lock;
	/* Spinlock for adding/removing discovery entries */
	spinlock_t		discovery_lock;
	spinlock_t		inactive_ts_lock;
	/* Spinlock for adding/removing login threads */
	spinlock_t		login_thread_lock;
	spinlock_t		shutdown_lock;
	/* Spinlock for adding/removing thread sets */
	spinlock_t		thread_set_lock;
	/* Spinlock for struct iscsi_tiqn */
	spinlock_t		tiqn_lock;
	spinlock_t		g_tpg_lock;
	/* Spinlock g_np_list */
	spinlock_t		np_lock;
	/* Semaphore used for communication to authentication daemon */
	struct semaphore	auth_sem;
	/* Semaphore used for allocate of struct iscsi_conn->auth_id */
	struct semaphore	auth_id_sem;
	/* Used for iSCSI discovery session authentication */
	struct iscsi_node_acl	discovery_acl;
	struct iscsi_portal_group	*discovery_tpg;
#ifdef DEBUG_ERL
	struct iscsi_debug_erl	*debug_erl;
	spinlock_t		debug_erl_lock;
#endif /* DEBUG_ERL */
	struct list_head	active_ts_list;
	struct list_head	inactive_ts_list;
} ____cacheline_aligned;

#define ISCSI_DEBUG_ERL(g)	((struct iscsi_debug_erl *)(g)->debug_erl)

#endif /* ISCSI_TARGET_CORE_H */
