#ifndef TARGET_CORE_STAT_H
#define TARGET_CORE_STAT_H

/*
 * Called from target_core_configfs.c struct config_group dependent context
 */
extern void target_stat_setup_dev_default_groups(struct se_subsystem_dev *);
extern void target_stat_setup_port_default_groups(struct se_lun *);
extern void target_stat_setup_mappedlun_default_groups(struct se_lun_acl *);

#endif   /*** TARGET_CORE_STAT_H ***/
