#ifndef ISCSI_TARGET_ERL1_H
#define ISCSI_TARGET_ERL1_H

extern int iscsi_dump_data_payload(struct iscsi_conn *, __u32, int);
extern int iscsi_create_recovery_datain_values_datasequenceinorder_yes(
			struct iscsi_cmd *, struct iscsi_datain_req *);
extern int iscsi_create_recovery_datain_values_datasequenceinorder_no(
			struct iscsi_cmd *, struct iscsi_datain_req *);
extern int iscsi_handle_recovery_datain_or_r2t(struct iscsi_conn *, unsigned char *,
			__u32, __u32, __u32, __u32);
extern int iscsi_handle_status_snack(struct iscsi_conn *, __u32, __u32,
			__u32, __u32);
extern int iscsi_handle_data_ack(struct iscsi_conn *, __u32, __u32, __u32);
extern int iscsi_dataout_datapduinorder_no_fbit(struct iscsi_cmd *, struct iscsi_pdu *);
extern int iscsi_recover_dataout_sequence(struct iscsi_cmd *, __u32, __u32);
extern void iscsi_clear_ooo_cmdsns_for_conn(struct iscsi_conn *);
extern void iscsi_free_all_ooo_cmdsns(struct iscsi_session *);
extern int iscsi_execute_ooo_cmdsns(struct iscsi_session *);
extern int iscsi_execute_cmd(struct iscsi_cmd *, int);
extern int iscsi_handle_ooo_cmdsn(struct iscsi_session *, struct iscsi_cmd *, __u32);
extern void iscsi_remove_ooo_cmdsn(struct iscsi_session *, struct iscsi_ooo_cmdsn *);
extern void iscsi_mod_dataout_timer(struct iscsi_cmd *);
extern void iscsi_start_dataout_timer(struct iscsi_cmd *, struct iscsi_conn *);
extern void iscsi_stop_dataout_timer(struct iscsi_cmd *);

extern struct kmem_cache *lio_ooo_cache;

extern int iscsi_add_reject_from_cmd(u8, int, int, unsigned char *,
			struct iscsi_cmd *);
extern int iscsi_build_r2ts_for_cmd(struct iscsi_cmd *, struct iscsi_conn *, int);
extern int iscsi_logout_closesession(struct iscsi_cmd *, struct iscsi_conn *);
extern int iscsi_logout_closeconnection(struct iscsi_cmd *, struct iscsi_conn *);
extern int iscsi_logout_removeconnforrecovery(struct iscsi_cmd *, struct iscsi_conn *);

#endif /* ISCSI_TARGET_ERL1_H */
