#define TCM_LOOP_VERSION		"v2.0"
#define TL_WWN_ADDR_LEN			256
#define TL_TPGS_PER_HBA			32
/*
 * Defaults for struct scsi_host_template tcm_loop_driver_template
 *
 * We use large can_queue and cmd_per_lun here and let TCM enforce
 * the underlying se_device_t->queue_depth.
 */
#define TL_SCSI_CAN_QUEUE		1024
#define TL_SCSI_CMD_PER_LUN		1024
#define TL_SCSI_MAX_SECTORS		1024
#define TL_SCSI_SG_TABLESIZE		256
/*
 * Used in tcm_loop_driver_probe() for struct Scsi_Host->max_cmd_len
 */
#define TL_SCSI_MAX_CMD_LEN		16

#ifdef TCM_LOOP_CDB_DEBUG
# define TL_CDB_DEBUG(x...)		printk(KERN_INFO x)
#else
# define TL_CDB_DEBUG(x...)
#endif

struct tcm_loop_cmd {
	/* Data Direction from Linux/SCSI CDB+Data descriptor */
	int sc_data_direction;
	/* State of Linux/SCSI CDB+Data descriptor */
	u32 sc_cmd_state;
	/* Pointer to the CDB+Data descriptor from Linux/SCSI subsystem */
	struct scsi_cmnd *sc;
	/* Pointer to the TCM allocated se_cmd_t */
	struct se_cmd_s *tl_se_cmd;
	struct list_head *tl_cmd_list;
};

struct tcm_loop_nexus {
	int it_nexus_active;
	/*
	 * Pointer to Linux/SCSI HBA from linux/include/scsi_host.h
	 */
	struct scsi_host *sh;
	/*
	 * Pointer to TCM session for I_T Nexus
	 */
	struct se_session_s *se_sess;
};

struct tcm_loop_nacl {
	struct se_node_acl_s se_node_acl;
};

struct tcm_loop_tpg {
	unsigned short tl_tpgt;
	struct se_portal_group_s tl_se_tpg;
	struct tcm_loop_hba *tl_hba;
};

struct tcm_loop_hba {
	u8 tl_proto_id;
	unsigned char tl_wwn_address[TL_WWN_ADDR_LEN];
	struct se_hba_s *se_hba;
	struct se_lun_s *tl_hba_lun;
	struct se_port_s *tl_hba_lun_sep;
	struct se_device_s *se_dev_hba_ptr;
	struct se_queue_obj_s *tl_hba_qobj;
	struct task_struct *tl_kthread;
	struct tcm_loop_nexus *tl_nexus;
	struct device dev;
	struct Scsi_Host *sh;
	struct tcm_loop_tpg tl_hba_tpgs[TL_TPGS_PER_HBA];
	struct se_wwn_s tl_hba_wwn;
};
