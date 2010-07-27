#ifndef ISCSI_TARGET_H
#define ISCSI_TARGET_H

extern struct iscsi_tiqn *core_get_tiqn_for_login(unsigned char *);
extern struct iscsi_tiqn *core_get_tiqn(unsigned char *, int);
extern void core_put_tiqn_for_login(struct iscsi_tiqn *);
extern struct iscsi_tiqn *core_add_tiqn(unsigned char *, int *);
extern int core_del_tiqn(struct iscsi_tiqn *);
extern int core_access_np(struct iscsi_np *, struct iscsi_portal_group *);
extern int core_deaccess_np(struct iscsi_np *, struct iscsi_portal_group *);
extern void *core_get_np_ip(struct iscsi_np *np);
extern struct iscsi_np *core_get_np(void *, u16, int);
extern int __core_del_np_ex(struct iscsi_np *, struct iscsi_np_ex *);
extern struct iscsi_np *core_add_np(struct iscsi_np_addr *, int, int *);
extern int core_reset_np_thread(struct iscsi_np *, struct iscsi_tpg_np *,
				struct iscsi_portal_group *, int);
extern int core_del_np(struct iscsi_np *);
extern char *iscsi_get_fabric_name(void);
extern struct iscsi_cmd *iscsi_get_cmd(struct se_cmd *);
extern u32 iscsi_get_task_tag(struct se_cmd *);
extern int iscsi_get_cmd_state(struct se_cmd *);
extern void iscsi_new_cmd_failure(struct se_cmd *);
extern int iscsi_is_state_remove(struct se_cmd *);
extern int lio_sess_logged_in(struct se_session *);
#ifdef SNMP_SUPPORT
extern u32 lio_sess_get_index(struct se_session *);
#endif /* SNMP_SUPPORT */
extern u32 lio_sess_get_initiator_sid(struct se_session *,
				unsigned char *, u32);
extern int iscsi_send_async_msg(struct iscsi_conn *, __u16, __u8, __u8);
extern int lio_queue_data_in(struct se_cmd *);
extern int iscsi_send_r2t(struct iscsi_cmd *, struct iscsi_conn *);
extern int iscsi_build_r2ts_for_cmd(struct iscsi_cmd *, struct iscsi_conn *, int);
extern int lio_write_pending(struct se_cmd *);
extern int lio_write_pending_status(struct se_cmd *);
extern int lio_queue_status(struct se_cmd *);
extern u16 lio_set_fabric_sense_len(struct se_cmd *, u32);
extern u16 lio_get_fabric_sense_len(void);
extern int lio_queue_tm_rsp(struct se_cmd *);
extern int iscsi_target_tx_thread(void *);
extern int iscsi_target_rx_thread(void *);
extern int iscsi_close_connection(struct iscsi_conn *);
extern int iscsi_close_session(struct iscsi_session *);
extern void iscsi_fail_session(struct iscsi_session *);
extern int iscsi_free_session(struct iscsi_session *);
extern void iscsi_stop_session(struct iscsi_session *, int, int);
extern int iscsi_release_sessions_for_tpg(struct iscsi_portal_group *, int);

#endif   /*** ISCSI_TARGET_H ***/
