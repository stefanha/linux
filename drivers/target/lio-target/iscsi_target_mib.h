#ifndef ISCSI_TARGET_MIB_H
#define ISCSI_TARGET_MIB_H

/* iSCSI session error types */
#define ISCSI_SESS_ERR_UNKNOWN		0
#define ISCSI_SESS_ERR_DIGEST		1
#define ISCSI_SESS_ERR_CXN_TIMEOUT	2
#define ISCSI_SESS_ERR_PDU_FORMAT	3

/* iSCSI session error stats */
typedef struct iscsi_sess_err_stats_s {
	spinlock_t	lock;
	u32		digest_errors;
	u32		cxn_timeout_errors;
	u32		pdu_format_errors;
	u32		last_sess_failure_type;
	char		last_sess_fail_rem_name[224];
} iscsi_sess_err_stats_t;

/* iSCSI login failure types (sub oids) */
#define ISCSI_LOGIN_FAIL_OTHER		2
#define ISCSI_LOGIN_FAIL_REDIRECT	3
#define ISCSI_LOGIN_FAIL_AUTHORIZE	4
#define ISCSI_LOGIN_FAIL_AUTHENTICATE	5
#define ISCSI_LOGIN_FAIL_NEGOTIATE	6

/* iSCSI login stats */
typedef struct iscsi_login_stats_s {
	spinlock_t	lock;
	u32		accepts;
	u32		other_fails;
	u32		redirects;
	u32		authorize_fails;
	u32		authenticate_fails;
	u32		negotiate_fails;	/* used for notifications */
	u64		last_fail_time;		/* time stamp (jiffies) */
	u32		last_fail_type;
	u32		last_intr_fail_addr;
	unsigned char	last_intr_fail_ip6_addr[IPV6_ADDRESS_SPACE];
	char		last_intr_fail_name[224];
} iscsi_login_stats_t;

/* iSCSI logout stats */
typedef struct iscsi_logout_stats_s {
	spinlock_t	lock;
	u32		normal_logouts;
	u32		abnormal_logouts;
} iscsi_logout_stats_t;

/* Structures for table index support */
typedef enum {
	ISCSI_INST_INDEX,
	ISCSI_PORTAL_INDEX,
	ISCSI_TARGET_AUTH_INDEX,
	ISCSI_SESSION_INDEX,
	ISCSI_CONNECTION_INDEX,
	INDEX_TYPE_MAX
} iscsi_index_t;

typedef struct iscsi_index_table_s {
	spinlock_t	lock;
	u32 		iscsi_mib_index[INDEX_TYPE_MAX];
} iscsi_index_table_t;

extern void *lio_scsi_auth_intr_seq_start(struct seq_file *, loff_t *);
extern void *lio_scsi_auth_intr_seq_next(struct seq_file *, void *, loff_t *);
extern int lio_scsi_auth_intr_seq_show(struct seq_file *, void *);
extern void lio_scsi_auth_intr_seq_stop(struct seq_file *, void *);
extern void *lio_scsi_att_intr_port_seq_start(struct seq_file *, loff_t *);
extern void *lio_scsi_att_intr_port_seq_next(struct seq_file *, void *,
			loff_t *);
extern int lio_scsi_att_intr_port_seq_show(struct seq_file *, void *);
extern void lio_scsi_att_intr_port_seq_stop(struct seq_file *, void *);
extern int init_iscsi_target_mib(void);
extern void remove_iscsi_target_mib(void);
extern void init_iscsi_index_table(void);
extern u32 iscsi_get_new_index(iscsi_index_t);

extern struct se_global *se_global;
extern struct iscsi_global_s *iscsi_global;

#endif   /*** ISCSI_TARGET_MIB_H ***/

