#ifndef ISCSI_TARGET_ERL1_H
#define ISCSI_TARGET_ERL1_H

extern int iscsi_dump_data_payload(iscsi_conn_t *, __u32, int);
extern int iscsi_create_recovery_datain_values_datasequenceinorder_yes(
			iscsi_cmd_t *, iscsi_datain_req_t *);
extern int iscsi_create_recovery_datain_values_datasequenceinorder_no(
			iscsi_cmd_t *, iscsi_datain_req_t *);
extern int iscsi_handle_recovery_datain_or_r2t(iscsi_conn_t *, unsigned char *,
			__u32, __u32, __u32, __u32);
extern int iscsi_handle_status_snack(iscsi_conn_t *, __u32, __u32,
			__u32, __u32);
extern int iscsi_handle_data_ack(iscsi_conn_t *, __u32, __u32, __u32);
extern int iscsi_dataout_datapduinorder_no_fbit(iscsi_cmd_t *, iscsi_pdu_t *);
extern int iscsi_recover_dataout_sequence(iscsi_cmd_t *, __u32, __u32);
extern void iscsi_clear_ooo_cmdsns_for_conn(iscsi_conn_t *);
extern void iscsi_free_all_ooo_cmdsns(iscsi_session_t *);
extern int iscsi_execute_ooo_cmdsns(iscsi_session_t *);
extern int iscsi_execute_cmd(iscsi_cmd_t *, int);
extern int iscsi_handle_ooo_cmdsn(iscsi_session_t *, iscsi_cmd_t *, __u32);
extern void iscsi_remove_ooo_cmdsn(iscsi_session_t *, iscsi_ooo_cmdsn_t *);
extern void iscsi_mod_dataout_timer(iscsi_cmd_t *);
extern void iscsi_start_dataout_timer(iscsi_cmd_t *, iscsi_conn_t *);
extern void iscsi_stop_dataout_timer(iscsi_cmd_t *);

extern struct kmem_cache *lio_ooo_cache;

extern int iscsi_add_reject_from_cmd(u8, int, int, unsigned char *,
			iscsi_cmd_t *);
extern int iscsi_build_r2ts_for_cmd(iscsi_cmd_t *, iscsi_conn_t *, int);
extern int iscsi_logout_closesession(iscsi_cmd_t *, iscsi_conn_t *);
extern int iscsi_logout_closeconnection(iscsi_cmd_t *, iscsi_conn_t *);
extern int iscsi_logout_removeconnforrecovery(iscsi_cmd_t *, iscsi_conn_t *);

#endif /* ISCSI_TARGET_ERL1_H */
