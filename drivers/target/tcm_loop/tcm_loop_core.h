#define TCM_LOOP_VERSION		"v2.1-rc1"
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
#define TL_SCSI_MAX_CMD_LEN		32

#ifdef CONFIG_TCM_LOOP_CDB_DEBUG
# define TL_CDB_DEBUG(x...)		printk(KERN_INFO x)
#else
# define TL_CDB_DEBUG(x...)
#endif

struct tcm_loop_cmd {
	/* State of Linux/SCSI CDB+Data descriptor */
	u32 sc_cmd_state;
	/* Pointer to the CDB+Data descriptor from Linux/SCSI subsystem */
	struct scsi_cmnd *sc;
	struct list_head *tl_cmd_list;
	/* The TCM I/O descriptor that is accessed via container_of() */
	struct se_cmd tl_se_cmd;
	/* Sense buffer that will be mapped into outgoing status */
	unsigned char tl_sense_buf[TRANSPORT_SENSE_BUFFER];
};

struct tcm_loop_tmr {
	atomic_t tmr_complete;
	wait_queue_head_t tl_tmr_wait;
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
	struct se_session *se_sess;
};

struct tcm_loop_nacl {
	struct se_node_acl se_node_acl;
};

struct tcm_loop_tpg {
	unsigned short tl_tpgt;
	atomic_t tl_tpg_port_count;
	struct se_portal_group tl_se_tpg;
	struct tcm_loop_hba *tl_hba;
};

struct tcm_loop_hba {
	u8 tl_proto_id;
	unsigned char tl_wwn_address[TL_WWN_ADDR_LEN];
	struct se_hba_s *se_hba;
	struct se_lun *tl_hba_lun;
	struct se_port *tl_hba_lun_sep;
	struct se_device_s *se_dev_hba_ptr;
	struct tcm_loop_nexus *tl_nexus;
	struct device dev;
	struct Scsi_Host *sh;
	struct tcm_loop_tpg tl_hba_tpgs[TL_TPGS_PER_HBA];
	struct se_wwn tl_hba_wwn;
};

/*
 * From tcm_loop_configfs.c
 */
extern int tcm_loop_register_configfs(void);
extern void tcm_loop_deregister_configfs(void);

/*
 * From tcm_loop_fabric.c
 */
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
extern int tcm_loop_check_prod_mode_write_protect(struct se_portal_group *);
extern struct se_node_acl *tcm_loop_tpg_alloc_fabric_acl(
				struct se_portal_group *);
void tcm_loop_tpg_release_fabric_acl(struct se_portal_group *, struct se_node_acl *);
extern u32 tcm_loop_get_inst_index(struct se_portal_group *);
extern void tcm_loop_new_cmd_failure(struct se_cmd *);
extern int tcm_loop_is_state_remove(struct se_cmd *);
extern int tcm_loop_sess_logged_in(struct se_session *);
extern u32 tcm_loop_sess_get_index(struct se_session *);
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

/*
 * From tcm_loop_fabric_scsi.c
 */
extern struct kmem_cache *tcm_loop_cmd_cache;

extern int tcm_loop_new_cmd_map(struct se_cmd *);
extern void tcm_loop_check_stop_free(struct se_cmd *);
extern void tcm_loop_deallocate_core_cmd(struct se_cmd *);
extern void tcm_loop_scsi_forget_host(struct Scsi_Host *);
extern void tcm_loop_deallocate_core_cmd(struct se_cmd *);
extern int tcm_loop_setup_hba_bus(struct tcm_loop_hba *, int);
extern int tcm_loop_alloc_core_bus(void);
extern void tcm_loop_release_core_bus(void);
