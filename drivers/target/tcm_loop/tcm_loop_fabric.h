extern char *tcm_loop_get_fabric_name(void);
extern u8 tcm_loop_get_fabric_proto_ident(struct se_portal_group *);
extern char *tcm_loop_get_endpoint_wwn(struct se_portal_group *);
extern u16 tcm_loop_get_tag(struct se_portal_group *);
extern u32 tcm_loop_get_default_depth(struct se_portal_group *);
extern u32 tcm_loop_get_pr_transport_id(struct se_portal_group *, struct se_node_acl *,
				struct t10_pr_registration *, int *,
				unsigned char *);
extern u32 tcm_loop_get_pr_transport_id_len(struct se_portal_group *,
				struct se_node_acl *, struct t10_pr_registration *,
				int *);
extern char *tcm_loop_parse_pr_out_transport_id(struct se_portal_group *,
				const char *, u32 *, char **);
extern int tcm_loop_check_demo_mode(struct se_portal_group *);
extern int tcm_loop_check_demo_mode_cache(struct se_portal_group *);
extern int tcm_loop_check_demo_mode_write_protect(struct se_portal_group *);
extern struct se_node_acl *tcm_loop_tpg_alloc_fabric_acl(
				struct se_portal_group *);
void tcm_loop_tpg_release_fabric_acl(struct se_portal_group *, struct se_node_acl *);
#ifdef SNMP_SUPPORT
extern u32 tcm_loop_tpg_get_inst_index(struct se_portal_group *);
#endif /* SNMP_SUPPORT */
extern void tcm_loop_new_cmd_failure(struct se_cmd *);
extern int tcm_loop_is_state_remove(struct se_cmd *);
extern int tcm_loop_sess_logged_in(struct se_session *);
#ifdef SNMP_SUPPORT
extern u32 tpg_loop_sess_get_index(struct se_session *);
#endif /* SNMP_SUPPORT */
extern void tcm_loop_set_default_node_attributes(struct se_node_acl *);
extern u32 tcm_loop_get_task_tag(struct se_cmd *);
extern int tcm_loop_get_cmd_state(struct se_cmd *);
extern int tcm_loop_shutdown_session(struct se_session *);
extern void tcm_loop_close_session(struct se_session *);
extern void tcm_loop_stop_session(struct se_session *, int, int);
extern void tcm_loop_fall_back_to_erl0(struct se_session *);
extern int tcm_loop_write_pending(struct se_cmd *);
extern int tcm_loop_write_pending_status(struct se_cmd *);
extern int tcm_loop_queue_data_in(struct se_cmd *);
extern int tcm_loop_queue_status(struct se_cmd *);
extern int tcm_loop_queue_tm_rsp(struct se_cmd *);
extern u16 tcm_loop_set_fabric_sense_len(struct se_cmd *, u32);
extern u16 tcm_loop_get_fabric_sense_len(void);
extern u64 tcm_loop_pack_lun(unsigned int);

extern int tcm_loop_processing_thread(void *);
