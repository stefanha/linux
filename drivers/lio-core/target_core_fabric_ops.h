struct target_core_fabric_ops {
	char *(*get_fabric_name)(void);
	u8 (*get_fabric_proto_ident)(void);
	char *(*tpg_get_wwn)(struct se_portal_group_s *);
	u16 (*tpg_get_tag)(struct se_portal_group_s *);
	u32 (*tpg_get_default_depth)(struct se_portal_group_s *);
	u32 (*tpg_get_pr_transport_id)(struct se_portal_group_s *,
				struct se_node_acl_s *, int *, unsigned char *);
	u32 (*tpg_get_pr_transport_id_len)(struct se_portal_group_s *,
				struct se_node_acl_s *, int *);
	int (*tpg_check_demo_mode)(struct se_portal_group_s *);
	int (*tpg_check_demo_mode_cache)(struct se_portal_group_s *);
	int (*tpg_check_demo_mode_write_protect)(struct se_portal_group_s *);
	void *(*tpg_alloc_fabric_acl)(struct se_portal_group_s *,
					struct se_node_acl_s *);
	void (*tpg_release_fabric_acl)(struct se_portal_group_s *,
					struct se_node_acl_s *);
	u32 (*tpg_get_inst_index)(struct se_portal_group_s *);
	void (*release_cmd_to_pool)(struct se_cmd_s *);
	void (*release_cmd_direct)(struct se_cmd_s *);
	int (*dev_del_lun)(struct se_portal_group_s *, __u32);
	/*
	 * Called with spin_lock_bh(se_portal_group_t->session_lock held.
	 */
	int (*shutdown_session)(struct se_session_s *);
	void (*close_session)(struct se_session_s *);
	void (*stop_session)(struct se_session_s *, int, int);
	void (*fall_back_to_erl0)(struct se_session_s *);
	int (*write_pending)(struct se_cmd_s *);
	void (*set_default_node_attributes)(struct se_node_acl_s *);
	void *(*scsi_auth_intr_seq_start)(struct seq_file *, loff_t *);
	void *(*scsi_auth_intr_seq_next)(struct seq_file *, void *, loff_t *);
	int (*scsi_auth_intr_seq_show)(struct seq_file *, void *);
	void (*scsi_auth_intr_seq_stop)(struct seq_file *, void *);
	void *(*scsi_att_intr_port_seq_start)(struct seq_file *, loff_t *);
	void *(*scsi_att_intr_port_seq_next)(struct seq_file *, void *,
						loff_t *);
	int (*scsi_att_intr_port_seq_show)(struct seq_file *, void *);
	void (*scsi_att_intr_port_seq_stop)(struct seq_file *, void *);
	u32 (*get_task_tag)(struct se_cmd_s *);
	int (*get_cmd_state)(struct se_cmd_s *);
	void (*new_cmd_failure)(struct se_cmd_s *);
	int (*queue_data_in)(struct se_cmd_s *);
	int (*queue_status)(struct se_cmd_s *);
	int (*queue_tm_rsp)(struct se_cmd_s *);
	int (*is_state_remove)(struct se_cmd_s *);
	u64 (*pack_lun)(unsigned int);
};
