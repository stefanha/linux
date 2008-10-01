struct target_core_fabric_ops {
        void (*release_cmd_to_pool)(struct iscsi_cmd_s *, struct iscsi_session_s *);
        void (*release_cmd_direct)(struct iscsi_cmd_s *);
	int (*dev_del_lun)(struct iscsi_portal_group_s *, __u32);
	int (*stop_session)(struct iscsi_session_s *, int, int);
	void (*fall_back_to_erl0)(struct iscsi_conn_s *);
	void (*add_cmd_to_response_queue)(struct iscsi_cmd_s *, struct iscsi_conn_s *, u8);
	int (*build_r2ts_for_cmd)(struct iscsi_cmd_s *, struct iscsi_conn_s *, int);
	void (*dec_nacl_count)(struct iscsi_node_acl_s *, struct iscsi_cmd_s *);
	void *(*scsi_auth_intr_seq_start)(struct seq_file *, loff_t *);
	void *(*scsi_auth_intr_seq_next)(struct seq_file *, void *, loff_t *);
	int (*scsi_auth_intr_seq_show)(struct seq_file *, void *);
	void (*scsi_auth_intr_seq_stop)(struct seq_file *, void *);
	void *(*scsi_att_intr_port_seq_start)(struct seq_file *, loff_t *);
	void *(*scsi_att_intr_port_seq_next)(struct seq_file *, void *, loff_t *);
	int (*scsi_att_intr_port_seq_show)(struct seq_file *, void *);
	void (*scsi_att_intr_port_seq_stop)(struct seq_file *, void *);
};
