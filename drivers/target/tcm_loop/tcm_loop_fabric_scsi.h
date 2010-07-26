extern struct kmem_cache *tcm_loop_cmd_cache;

extern int tcm_loop_execute_core_cmd(struct tcm_loop_cmd *, struct scsi_cmnd *);
extern void tcm_loop_check_stop_free(struct se_cmd *);
extern void tcm_loop_deallocate_core_cmd(struct se_cmd *);
extern void tcm_loop_scsi_forget_host(struct Scsi_Host *);
extern void tcm_loop_deallocate_core_cmd(struct se_cmd *);
extern int tcm_loop_setup_hba_bus(struct tcm_loop_hba *, int);
extern int tcm_loop_alloc_core_bus(void);
extern void tcm_loop_release_core_bus(void);
