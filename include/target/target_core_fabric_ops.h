/* Defined in target_core_configfs.h */
struct target_fabric_configfs;

struct target_core_fabric_ops {
	struct configfs_subsystem *tf_subsys;
	char *(*get_fabric_name)(void);
	u8 (*get_fabric_proto_ident)(struct se_portal_group_s *);
	char *(*tpg_get_wwn)(struct se_portal_group_s *);
	u16 (*tpg_get_tag)(struct se_portal_group_s *);
	u32 (*tpg_get_default_depth)(struct se_portal_group_s *);
	u32 (*tpg_get_pr_transport_id)(struct se_portal_group_s *,
				struct se_node_acl_s *,
				struct t10_pr_registration_s *, int *,
				unsigned char *);
	u32 (*tpg_get_pr_transport_id_len)(struct se_portal_group_s *,
				struct se_node_acl_s *,
				struct t10_pr_registration_s *, int *);
	char *(*tpg_parse_pr_out_transport_id)(struct se_portal_group_s *,
				const char *, u32 *, char **);
	int (*tpg_check_demo_mode)(struct se_portal_group_s *);
	int (*tpg_check_demo_mode_cache)(struct se_portal_group_s *);
	int (*tpg_check_demo_mode_write_protect)(struct se_portal_group_s *);
	int (*tpg_check_prod_mode_write_protect)(struct se_portal_group_s *);
	struct se_node_acl_s *(*tpg_alloc_fabric_acl)(
					struct se_portal_group_s *);
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
	/*
	 * Used only for SCSI fabrics that contain multi-value TransportIDs
	 * (like iSCSI).  All other SCSI fabrics should set this to NULL.
	 */
	u32 (*sess_get_initiator_sid)(struct se_session_s *,
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
	/*
	 * fabric module calls for target_core_fabric_configfs.c
	 */
	struct se_wwn_s *(*fabric_make_wwn)(struct target_fabric_configfs *,
				struct config_group *, const char *);
	void (*fabric_drop_wwn)(struct se_wwn_s *);
	struct se_portal_group_s *(*fabric_make_tpg)(struct se_wwn_s *,
				struct config_group *, const char *);
	void (*fabric_drop_tpg)(struct se_portal_group_s *);
	int (*fabric_post_link)(struct se_portal_group_s *,
				struct se_lun_s *);
	void (*fabric_pre_unlink)(struct se_portal_group_s *,
				struct se_lun_s *);
	struct se_tpg_np_s *(*fabric_make_np)(struct se_portal_group_s *,
				struct config_group *, const char *);
	void (*fabric_drop_np)(struct se_tpg_np_s *);
	struct se_node_acl_s *(*fabric_make_nodeacl)(struct se_portal_group_s *,
				struct config_group *, const char *);
	void (*fabric_drop_nodeacl)(struct se_node_acl_s *);
};
