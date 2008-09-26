struct target_core_fabric_ops {
        void (*release_cmd_to_pool)(struct iscsi_cmd_s *, struct iscsi_session_s *);
        void (*release_cmd_direct)(struct iscsi_cmd_s *);
	int (*dev_del_lun)(struct iscsi_portal_group_s *, __u32);
	int (*stop_session)(struct iscsi_session_s *, int, int);
	void (*fall_back_to_erl0)(struct iscsi_conn_s *);
	void (*add_cmd_to_response_queue)(struct iscsi_cmd_s *, struct iscsi_conn_s *, u8);
	int (*build_r2ts_for_cmd)(struct iscsi_cmd_s *, struct iscsi_conn_s *, int);
	void (*dec_nacl_count)(struct iscsi_node_acl_s *, struct iscsi_cmd_s *);
	void (*dump_dev_info)(struct se_device_s *, struct se_lun_s *, unsigned long long, char *, int *);
	void (*dump_dev_state)(struct se_device_s *, char *, int *);
#ifdef SNMP_SUPPORT
	u32 (*get_new_index)(iscsi_index_t);
#endif
};
