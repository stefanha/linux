#ifndef ISCSI_TARGET_TMR_H
#define ISCSI_TARGET_TMR_H

extern __u8 iscsi_tmr_abort_task(struct iscsi_cmd *, unsigned char *);
extern int iscsi_tmr_task_warm_reset(struct iscsi_conn *, struct iscsi_tmr_req *,
			unsigned char *);
extern int iscsi_tmr_task_cold_reset(struct iscsi_conn *, struct iscsi_tmr_req *,
			unsigned char *);
extern __u8 iscsi_tmr_task_reassign(struct iscsi_cmd *, unsigned char *);
extern int iscsi_tmr_post_handler(struct iscsi_cmd *, struct iscsi_conn *);
extern int iscsi_check_task_reassign_expdatasn(struct iscsi_tmr_req *,
			struct iscsi_conn *);

extern int iscsi_build_r2ts_for_cmd(struct iscsi_cmd *, struct iscsi_conn *, int);

#endif /* ISCSI_TARGET_TMR_H */

