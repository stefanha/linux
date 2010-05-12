extern char *tcm_loop_get_fabric_name(void);
extern u8 tcm_loop_get_fabric_proto_ident(se_portal_group_t *);
extern char *tcm_loop_get_endpoint_wwn(se_portal_group_t *);
extern u16 tcm_loop_get_tag(se_portal_group_t *);
extern u32 tcm_loop_get_default_depth(se_portal_group_t *);
extern u32 tcm_loop_get_pr_transport_id(se_portal_group_t *, se_node_acl_t *,
				t10_pr_registration_t *, int *,
				unsigned char *);
extern u32 tcm_loop_get_pr_transport_id_len(se_portal_group_t *,
				se_node_acl_t *, t10_pr_registration_t *,
				int *);
extern char *tcm_loop_parse_pr_out_transport_id(const char *, u32 *, char **);
extern int tcm_loop_check_demo_mode(se_portal_group_t *);
extern int tcm_loop_check_demo_mode_cache(se_portal_group_t *);
extern int tcm_loop_check_demo_mode_write_protect(se_portal_group_t *);
extern struct se_node_acl_s *tcm_loop_tpg_alloc_fabric_acl(
				se_portal_group_t *);
void tcm_loop_tpg_release_fabric_acl(se_portal_group_t *, se_node_acl_t *);
#ifdef SNMP_SUPPORT
extern u32 tcm_loop_tpg_get_inst_index(se_portal_group_t *);
#endif /* SNMP_SUPPORT */
extern void tcm_loop_new_cmd_failure(se_cmd_t *);
extern int tcm_loop_is_state_remove(se_cmd_t *);
extern int tcm_loop_sess_logged_in(se_session_t *);
#ifdef SNMP_SUPPORT
extern u32 tpg_loop_sess_get_index(se_session_t *);
#endif /* SNMP_SUPPORT */
extern void tcm_loop_set_default_node_attributes(se_node_acl_t *);
extern u32 tcm_loop_get_task_tag(se_cmd_t *);
extern int tcm_loop_get_cmd_state(se_cmd_t *);
extern int tcm_loop_shutdown_session(se_session_t *);
extern void tcm_loop_close_session(se_session_t *);
extern void tcm_loop_stop_session(se_session_t *, int, int);
extern void tcm_loop_fall_back_to_erl0(se_session_t *);
extern int tcm_loop_write_pending(se_cmd_t *);
extern int tcm_loop_write_pending_status(se_cmd_t *);
extern int tcm_loop_queue_data_in(se_cmd_t *);
extern int tcm_loop_queue_status(se_cmd_t *);
extern int tcm_loop_queue_tm_rsp(se_cmd_t *);
extern u16 tcm_loop_set_fabric_sense_len(se_cmd_t *, u32);
extern u16 tcm_loop_get_fabric_sense_len(void);
extern u64 tcm_loop_pack_lun(unsigned int);

extern int tcm_loop_processing_thread(void *);
