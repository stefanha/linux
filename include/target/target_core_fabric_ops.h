struct target_core_fabric_ops {
	struct configfs_subsystem *tf_subsys;
	char *(*get_fabric_name)(void);
	u8 (*get_fabric_proto_ident)(void);
	char *(*tpg_get_wwn)(struct se_portal_group_s *);
	u16 (*tpg_get_tag)(struct se_portal_group_s *);
	u32 (*tpg_get_default_depth)(struct se_portal_group_s *);
	u32 (*tpg_get_pr_transport_id)(struct se_portal_group_s *,
				struct se_node_acl_s *, int *, unsigned char *);
	u32 (*tpg_get_pr_transport_id_len)(struct se_portal_group_s *,
				struct se_node_acl_s *, int *);
	char *(*tpg_parse_pr_out_transport_id)(const char *, u32 *, char **);
	int (*tpg_check_demo_mode)(struct se_portal_group_s *);
	int (*tpg_check_demo_mode_cache)(struct se_portal_group_s *);
	int (*tpg_check_demo_mode_write_protect)(struct se_portal_group_s *);
	void *(*tpg_alloc_fabric_acl)(struct se_portal_group_s *,
					struct se_node_acl_s *);
	void (*tpg_release_fabric_acl)(struct se_portal_group_s *,
					struct se_node_acl_s *);
	u32 (*tpg_get_inst_index)(struct se_portal_group_s *);
	/*
	 * Optional function pointer for TCM fabric modules that use
	 * Linux/NET sockets to allocate struct iovec array to se_cmd_t
	 */
	int (*alloc_cmd_iovecs)(struct se_cmd_s *);
	/*
	 * Optional to release se_cmd_t and fabric dependent allocated
	 * I/O descriptor in transport_cmd_check_stop()
	 */
	void (*check_stop_free)(struct se_cmd_s *);
	void (*release_cmd_to_pool)(struct se_cmd_s *);
	void (*release_cmd_direct)(struct se_cmd_s *);
	int (*dev_del_lun)(struct se_portal_group_s *, u32);
	/*
	 * Called with spin_lock_bh(se_portal_group_t->session_lock held.
	 */
	int (*shutdown_session)(struct se_session_s *);
	void (*close_session)(struct se_session_s *);
	void (*stop_session)(struct se_session_s *, int, int);
	void (*fall_back_to_erl0)(struct se_session_s *);
	int (*sess_logged_in)(struct se_session_s *);
	u32 (*sess_get_index)(struct se_session_s *);
	u32 (*sess_get_initiator_wwn)(struct se_session_s *,
				      unsigned char *, u32);
	int (*write_pending)(struct se_cmd_s *);
	int (*write_pending_status)(struct se_cmd_s *);
	void (*set_default_node_attributes)(struct se_node_acl_s *);
	u32 (*get_task_tag)(struct se_cmd_s *);
	int (*get_cmd_state)(struct se_cmd_s *);
	void (*new_cmd_failure)(struct se_cmd_s *);
	int (*queue_data_in)(struct se_cmd_s *);
	int (*queue_status)(struct se_cmd_s *);
	int (*queue_tm_rsp)(struct se_cmd_s *);
	u16 (*set_fabric_sense_len)(struct se_cmd_s *, u32);
	u16 (*get_fabric_sense_len)(void);
	int (*is_state_remove)(struct se_cmd_s *);
	u64 (*pack_lun)(unsigned int);
};
