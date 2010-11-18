extern int tcm_qla2xxx_check_true(struct se_portal_group *);
extern int tcm_qla2xxx_check_false(struct se_portal_group *);
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
extern struct se_node_acl *tcm_qla2xxx_alloc_fabric_acl(struct se_portal_group *);
extern void tcm_qla2xxx_release_fabric_acl(struct se_portal_group *, struct se_node_acl *);
extern u32 tcm_qla2xxx_tpg_get_inst_index(struct se_portal_group *);
extern void tcm_qla2xxx_release_cmd(struct se_cmd *);
extern int tcm_qla2xxx_shutdown_session(struct se_session *);
extern void tcm_qla2xxx_close_session(struct se_session *);
extern void tcm_qla2xxx_stop_session(struct se_session *, int, int);
extern void tcm_qla2xxx_reset_nexus(struct se_session *);
extern int tcm_qla2xxx_sess_logged_in(struct se_session *);
extern u32 tcm_qla2xxx_sess_get_index(struct se_session *);
extern int tcm_qla2xxx_write_pending(struct se_cmd *);
extern int tcm_qla2xxx_write_pending_status(struct se_cmd *);
extern void tcm_qla2xxx_set_default_node_attrs(struct se_node_acl *);
extern u32 tcm_qla2xxx_get_task_tag(struct se_cmd *);
extern int tcm_qla2xxx_get_cmd_state(struct se_cmd *);
extern void tcm_qla2xxx_new_cmd_failure(struct se_cmd *);
extern int tcm_qla2xxx_queue_data_in(struct se_cmd *);
extern int tcm_qla2xxx_queue_status(struct se_cmd *);
extern int tcm_qla2xxx_queue_tm_rsp(struct se_cmd *);
extern u16 tcm_qla2xxx_get_fabric_sense_len(void);
extern u16 tcm_qla2xxx_set_fabric_sense_len(struct se_cmd *, u32);
extern int tcm_qla2xxx_is_state_remove(struct se_cmd *);
extern u64 tcm_qla2xxx_pack_lun(unsigned int);
