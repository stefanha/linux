#ifndef TARGET_CORE_STAT_H
#define TARGET_CORE_STAT_H

# if 0
typedef enum {
	SCSI_INST_INDEX,
	SCSI_DEVICE_INDEX,
	SCSI_AUTH_INTR_INDEX,
	SCSI_INDEX_TYPE_MAX
} scsi_index_t;
#endif

extern void target_stat_setup_dev_default_groups(struct se_subsystem_dev *);
extern void target_stat_setup_port_default_groups(struct se_lun *);

#endif   /*** TARGET_CORE_STAT_H ***/
