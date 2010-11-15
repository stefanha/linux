#ifndef ISCSI_TARGET_ERL2_H
#define ISCSI_TARGET_ERL2_H

extern void iscsi_create_conn_recovery_datain_values(struct iscsi_cmd *, __u32);
extern void iscsi_create_conn_recovery_dataout_values(struct iscsi_cmd *);
extern struct iscsi_conn_recovery *iscsi_get_inactive_connection_recovery_entry(
			struct iscsi_session *, __u16);
extern void iscsi_free_connection_recovery_entires(struct iscsi_session *);
extern int iscsi_remove_active_connection_recovery_entry(
			struct iscsi_conn_recovery *, struct iscsi_session *);
extern int iscsi_remove_cmd_from_connection_recovery(struct iscsi_cmd *,
			struct iscsi_session *);
extern void iscsi_discard_cr_cmds_by_expstatsn(struct iscsi_conn_recovery *, __u32);
extern int iscsi_discard_unacknowledged_ooo_cmdsns_for_conn(struct iscsi_conn *);
extern int iscsi_prepare_cmds_for_realligance(struct iscsi_conn *);
extern int iscsi_connection_recovery_transport_reset(struct iscsi_conn *);

extern int iscsi_close_connection(struct iscsi_conn *);

#endif /*** ISCSI_TARGET_ERL2_H ***/

