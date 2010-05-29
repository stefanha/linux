extern int tcm_qla2xxx_check_true(se_portal_group_t *);
extern int tcm_qla2xxx_check_false(se_portal_group_t *);
extern ssize_t tcm_qla2xxx_parse_wwn(const char *, u64 *, int);
extern ssize_t tcm_qla2xxx_format_wwn(char *, size_t, u64);
extern char *tcm_qla2xxx_get_fabric_name(void);
extern u8 tcm_qla2xxx_get_fabric_proto_ident(se_portal_group_t *);
extern char *tcm_qla2xxx_get_fabric_wwn(se_portal_group_t *);
extern u16 tcm_qla2xxx_get_tag(se_portal_group_t *);
extern u32 tcm_qla2xxx_get_default_depth(se_portal_group_t *);
extern u32 tcm_qla2xxx_get_pr_transport_id(se_portal_group_t *, se_node_acl_t *,
				t10_pr_registration_t *, int *, unsigned char *);
extern u32 tcm_qla2xxx_get_pr_transport_id_len(se_portal_group_t *, se_node_acl_t *,
				t10_pr_registration_t *, int *);
extern char *tcm_qla2xxx_parse_pr_out_transport_id(se_portal_group_t *, const char *,
				u32 *, char **);
extern se_node_acl_t *tcm_qla2xxx_alloc_fabric_acl(se_portal_group_t *);
extern void tcm_qla2xxx_release_fabric_acl(se_portal_group_t *, se_node_acl_t *);
#ifdef SNMP_SUPPORT
extern u32 tcm_qla2xxx_tpg_get_inst_index(se_portal_group_t *);
#endif /* SNMP_SUPPORT */
extern void tcm_qla2xxx_release_cmd(se_cmd_t *);
extern int tcm_qla2xxx_shutdown_session(se_session_t *);
extern void tcm_qla2xxx_close_session(se_session_t *);
extern void tcm_qla2xxx_stop_session(se_session_t *, int, int);
extern void tcm_qla2xxx_reset_nexus(se_session_t *);
extern int tcm_qla2xxx_sess_logged_in(se_session_t *);
#ifdef SNMP_SUPPORT
u32 tcm_qla2xxx_sess_get_index(se_session_t *);
#endif /* SNMP_SUPPORT */
extern int tcm_qla2xxx_write_pending(se_cmd_t *);
extern int tcm_qla2xxx_write_pending_status(se_cmd_t *);
extern void tcm_qla2xxx_set_default_node_attrs(se_node_acl_t *);
extern u32 tcm_qla2xxx_get_task_tag(se_cmd_t *);
extern int tcm_qla2xxx_get_cmd_state(se_cmd_t *);
extern void tcm_qla2xxx_new_cmd_failure(se_cmd_t *);
extern int tcm_qla2xxx_queue_data_in(se_cmd_t *);
extern int tcm_qla2xxx_queue_status(se_cmd_t *);
extern int tcm_qla2xxx_queue_tm_rsp(se_cmd_t *);
extern u16 tcm_qla2xxx_get_fabric_sense_len(void);
extern u16 tcm_qla2xxx_set_fabric_sense_len(se_cmd_t *, u32);
extern int tcm_qla2xxx_is_state_remove(se_cmd_t *);
extern u64 tcm_qla2xxx_pack_lun(unsigned int);
