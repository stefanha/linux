#ifndef ISCSI_TARGET_ERL0_H
#define ISCSI_TARGET_ERL0_H

extern void iscsi_set_dataout_sequence_values(struct iscsi_cmd *);
extern int iscsi_check_pre_dataout(struct iscsi_cmd *, unsigned char *);
extern int iscsi_check_post_dataout(struct iscsi_cmd *, unsigned char *, __u8);
extern void iscsi_start_time2retain_handler(struct iscsi_session *);
extern int iscsi_stop_time2retain_timer(struct iscsi_session *);
extern void iscsi_connection_reinstatement_rcfr(struct iscsi_conn *);
extern void iscsi_cause_connection_reinstatement(struct iscsi_conn *, int);
extern void iscsi_fall_back_to_erl0(struct iscsi_session *);
extern void iscsi_take_action_for_connection_exit(struct iscsi_conn *);
extern int iscsi_recover_from_unknown_opcode(struct iscsi_conn *);

extern struct iscsi_global *iscsi_global;
extern int iscsi_add_reject_from_cmd(u8, int, int, unsigned char *,
			struct iscsi_cmd *);

#endif   /*** ISCSI_TARGET_ERL0_H ***/
