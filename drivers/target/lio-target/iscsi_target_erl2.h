#ifndef ISCSI_TARGET_ERL2_H
#define ISCSI_TARGET_ERL2_H

extern void iscsi_create_conn_recovery_datain_values(iscsi_cmd_t *, __u32);
extern void iscsi_create_conn_recovery_dataout_values(iscsi_cmd_t *);
extern iscsi_conn_recovery_t *iscsi_get_inactive_connection_recovery_entry(
			iscsi_session_t *, __u16);
extern void iscsi_free_connection_recovery_entires(iscsi_session_t *);
extern int iscsi_remove_active_connection_recovery_entry(
			iscsi_conn_recovery_t *, iscsi_session_t *);
extern int iscsi_remove_cmd_from_connection_recovery(iscsi_cmd_t *,
			iscsi_session_t *);
extern void iscsi_discard_cr_cmds_by_expstatsn(iscsi_conn_recovery_t *, __u32);
extern int iscsi_discard_unacknowledged_ooo_cmdsns_for_conn(iscsi_conn_t *);
extern int iscsi_prepare_cmds_for_realligance(iscsi_conn_t *);
extern int iscsi_connection_recovery_transport_reset(iscsi_conn_t *);

extern int iscsi_close_connection(iscsi_conn_t *);

#endif /*** ISCSI_TARGET_ERL2_H ***/

