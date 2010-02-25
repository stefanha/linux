#ifndef ISCSI_TARGET_TMR_H
#define ISCSI_TARGET_TMR_H

extern __u8 iscsi_tmr_abort_task(iscsi_cmd_t *, unsigned char *);
extern int iscsi_tmr_task_warm_reset(iscsi_conn_t *, iscsi_tmr_req_t *,
			unsigned char *);
extern int iscsi_tmr_task_cold_reset(iscsi_conn_t *, iscsi_tmr_req_t *,
			unsigned char *);
extern __u8 iscsi_tmr_task_reassign(iscsi_cmd_t *, unsigned char *);
extern int iscsi_tmr_post_handler(iscsi_cmd_t *, iscsi_conn_t *);
extern int iscsi_check_task_reassign_expdatasn(iscsi_tmr_req_t *,
			iscsi_conn_t *);

extern int iscsi_build_r2ts_for_cmd(iscsi_cmd_t *, iscsi_conn_t *, int);

#endif /* ISCSI_TARGET_TMR_H */

