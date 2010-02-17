#ifndef ISCSI_TARGET_LOGIN_H
#define ISCSI_TARGET_LOGIN_H

extern int iscsi_check_for_session_reinstatement(iscsi_conn_t *);
extern int iscsi_login_post_auth_non_zero_tsih(iscsi_conn_t *, u16, u32);
extern int iscsi_target_login_thread(void *);
extern int iscsi_login_disable_FIM_keys(iscsi_param_list_t *, iscsi_conn_t *);

extern iscsi_global_t *iscsi_global;
extern struct kmem_cache *lio_sess_cache;
extern struct kmem_cache *lio_conn_cache;

#endif   /*** ISCSI_TARGET_LOGIN_H ***/

