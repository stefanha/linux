#ifndef ISCSI_TARGET_ERL0_H
#define ISCSI_TARGET_ERL0_H

extern void iscsi_set_dataout_sequence_values(iscsi_cmd_t *);
extern int iscsi_check_pre_dataout(iscsi_cmd_t *, unsigned char *);
extern int iscsi_check_post_dataout(iscsi_cmd_t *, unsigned char *, __u8);
extern void iscsi_start_time2retain_handler(iscsi_session_t *);
extern int iscsi_stop_time2retain_timer(iscsi_session_t *);
extern void iscsi_connection_reinstatement_rcfr(iscsi_conn_t *);
extern void iscsi_cause_connection_reinstatement(iscsi_conn_t *, int);
extern void iscsi_fall_back_to_erl0(iscsi_session_t *);
extern void iscsi_take_action_for_connection_exit(iscsi_conn_t *);
extern int iscsi_recover_from_unknown_opcode(iscsi_conn_t *);

extern iscsi_global_t *iscsi_global;
extern int iscsi_add_reject_from_cmd(u8, int, int, unsigned char *,
			iscsi_cmd_t *);

#endif   /*** ISCSI_TARGET_ERL0_H ***/
