/*********************************************************************************
 * Filename:  iscsi_target_transport.h
 *
 * This file contains the iSCSI Target Generic DAS Transport Layer definitions.
 *
 * Copyright (c) 2002, 2003, 2004, 2005 PyX Technologies, Inc.
 * Copyright (c) 2005, 2006, 2007 SBE, Inc. 
 * Copyright (c) 2007 Rising Tide Software, Inc.
 *
 * Nicholas A. Bellinger <nab@kernel.org>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 *
 *********************************************************************************/


#ifndef ISCSI_TARGET_TRANSPORT_H
#define ISCSI_TARGET_TRANSPORT_H

#define PYX_TRANSPORT_WINDOW_CLOSED_THRESHOLD	3  /* Attempts before moving from SHORT to LONG */
#define PYX_TRANSPORT_WINDOW_CLOSED_WAIT_SHORT	3  /* In milliseconds */
#define PYX_TRANSPORT_WINDOW_CLOSED_WAIT_LONG	10 /* In milliseconds */

#define PYX_TRANSPORT_STATUS_INTERVAL		5 /* In seconds */

#define PYX_TRANSPORT_SENT_TO_TRANSPORT		0
#define PYX_TRANSPORT_WRITE_PENDING		1

#define PYX_TRANSPORT_UNKNOWN_SAM_OPCODE	-1
#define PYX_TRANSPORT_HBA_QUEUE_FULL		-2
#define PYX_TRANSPORT_REQ_TOO_MANY_SECTORS	-3
#define PYX_TRANSPORT_OUT_OF_MEMORY_RESOURCES	-4
#define PYX_TRANSPORT_INVALID_CDB_FIELD		-5
#define PYX_TRANSPORT_LOGICAL_UNIT_COMMUNICATION_FAILURE -6
#define PYX_TRANSPORT_UNKNOWN_MODE_PAGE		-7
#define PYX_TRANSPORT_WRITE_PROTECTED		-8
#define PYX_TRANSPORT_TASK_TIMEOUT		-9

#ifndef SAM_STAT_RESERVATION_CONFLICT
#define SAM_STAT_RESERVATION_CONFLICT		0x18
#endif

#define TRANSPORT_PLUGIN_FREE			0
#define TRANSPORT_PLUGIN_REGISTERED		1

#define TRANSPORT_PLUGIN_PHBA_PDEV		1
#define TRANSPORT_PLUGIN_VHBA_PDEV		2
#define TRANSPORT_PLUGIN_VHBA_VDEV		3

/* For SE OBJ Plugins, in seconds */
#define TRANSPORT_TIMEOUT_TUR			10
#define TRANSPORT_TIMEOUT_TYPE_DISK		10
#define TRANSPORT_TIMEOUT_TYPE_ROM		120
#define TRANSPORT_TIMEOUT_TYPE_TAPE		600
#define TRANSPORT_TIMEOUT_TYPE_OTHER		300

/* For iscsi_task->task_state_flags */
#define TSF_EXCEPTION_CLEARED			0x01

/*
 * iSCSI Device related Transport flags
 */
#define DF_READAHEAD_ACTIVE                     0x00000001
#define DF_TRANSPORT_DMA_ALLOC			0x00000002
#define DF_TRANSPORT_BUF_ALLOC			0x00000004
#define DF_DEV_DEBUG				0x00000008
#define DF_CLAIMED_BLOCKDEV			0x00000010
#define DF_PERSISTENT_CLAIMED_BLOCKDEV		0x00000020
#define DF_DISABLE_STATUS_THREAD		0x00000040
#define DF_READ_ONLY				0x00000080


#define SE_MODE_PAGE_BUF			512
#define SE_LVM_UUID_LEN				48

#define MOD_MAX_SECTORS(ms, bs)			(ms % (PAGE_SIZE / bs))

struct se_mem_s;

#ifdef DEBUG_DEV
extern int __iscsi_debug_dev (iscsi_device_t *);
extern int iscsi_debug_dev (iscsi_device_t *);
#endif
extern unsigned char *transport_get_iqn_sn (void);
extern void transport_init_queue_obj (struct se_queue_obj_s *);
extern void transport_check_uuid (u32 *, void *);
extern void transport_load_plugins (void);
extern iscsi_device_t *transport_core_locate_dev (struct iscsi_target *, iscsi_dev_transport_info_t *, int *);
extern void transport_task_dev_remove_state (struct iscsi_task_s *, struct iscsi_device_s *);
extern int transport_add_cmd_to_queue (struct iscsi_cmd_s *, struct se_queue_obj_s *, u8);
extern void transport_complete_cmd (iscsi_cmd_t *, int);
extern void transport_complete_task (struct iscsi_task_s *, int);
extern void transport_add_task_to_execute_queue (struct iscsi_task_s *, struct iscsi_device_s *);
extern void transport_add_tasks_from_cmd (struct iscsi_cmd_s *);
extern struct iscsi_task_s *transport_get_task_from_execute_queue (struct iscsi_device_s *);
extern iscsi_queue_req_t *transport_get_qr_from_queue (struct se_queue_obj_s *);
extern int transport_check_device_tcq (iscsi_device_t *, u32, u32);
extern iscsi_hba_t *transport_add_iscsi_hba (u8 type, u32, void *);
extern iscsi_device_t *transport_add_device_to_iscsi_hba (iscsi_hba_t *, struct iscsi_transport_s *, u32, void *);
extern void transport_generic_activate_device (iscsi_device_t *);
extern void transport_generic_deactivate_device (iscsi_device_t *);
extern int transport_generic_claim_phydevice (iscsi_device_t *);
extern void transport_generic_release_phydevice (iscsi_device_t *, int);
extern void transport_generic_free_device (iscsi_device_t *);
extern int transport_generic_obj_start (struct iscsi_transform_info_s *, struct se_obj_lun_type_s *, void *, unsigned long long);
extern int transport_process_vol_transform (u32 *, struct iscsi_transform_info_s *);
extern int transport_jbod_cdb_count (struct iscsi_cmd_s *, struct iscsi_transform_info_s *);
extern int transport_jbod_allocate_DMA (struct iscsi_cmd_s *cmd, struct iscsi_transform_info_s *);
extern int transport_process_jbod_rw (u32 *, struct iscsi_transform_info_s *);
extern int transport_stripe_cdb_count (struct iscsi_cmd_s *, struct iscsi_transform_info_s *);
extern int transport_stripe_allocate_DMA (struct iscsi_cmd_s *cmd, struct iscsi_transform_info_s *);
extern int transport_process_stripe_rw (u32 *, struct iscsi_transform_info_s *);
extern int transport_generic_re_vol_cdb_count (struct iscsi_cmd_s *, struct iscsi_transform_info_s *);
extern int transport_generic_re_vol_allocate_DMA (struct iscsi_cmd_s *, struct iscsi_transform_info_s *);
extern int transport_process_mirror_write (u32 *, struct iscsi_transform_info_s *);
extern int transport_mirror_vol_write_allocate_DMA (struct iscsi_cmd_s *, struct iscsi_transform_info_s *, struct se_obj_lun_type_s *, void *);
extern int transport_rebuild_cmd (struct iscsi_cmd_s *, int);
extern void transport_device_setup_cmd (iscsi_cmd_t *);
extern int transport_generic_allocate_tasks (iscsi_cmd_t *, unsigned char *);
extern int transport_generic_check_device_location (iscsi_device_t *dev, struct iscsi_dev_transport_info_s *);
extern int transport_generic_handle_cdb (iscsi_cmd_t *);
extern int transport_generic_handle_data (iscsi_cmd_t *);
extern int transport_generic_handle_tmr (iscsi_cmd_t *, iscsi_tmr_req_t *);
extern void transport_stop_tasks_for_cmd (struct iscsi_cmd_s *);
extern int transport_failure_tasks_generic (iscsi_cmd_t *);
extern void transport_generic_request_failure (iscsi_cmd_t *, iscsi_device_t *, int, int); 
extern void transport_direct_request_timeout (iscsi_cmd_t *);
extern void transport_generic_request_timeout (iscsi_cmd_t *);
extern int transport_generic_allocate_buf (iscsi_cmd_t *, u32, u32);
extern int __transport_execute_tasks (struct iscsi_device_s *);
extern int __transport_raid_execute_tasks (struct raid_engine_s *);
extern void transport_new_cmd_failure (struct iscsi_cmd_s *);
extern void transport_start_task_timer (struct iscsi_task_s *);
extern void __transport_stop_task_timer (struct iscsi_task_s *, unsigned long *);
extern void transport_stop_task_timer (struct iscsi_task_s *);
extern void transport_stop_all_task_timers (struct iscsi_cmd_s *);
extern int transport_execute_tasks (struct iscsi_cmd_s *);
extern int transport_generic_emulate_inquiry (struct iscsi_cmd_s *, unsigned char, unsigned char *, unsigned char *, unsigned char *, unsigned char *);
extern int transport_generic_emulate_readcapacity (struct iscsi_cmd_s *, u32, u32);
extern int transport_generic_emulate_readcapacity_16 (struct iscsi_cmd_s *, unsigned long long, u32);
extern int transport_generic_emulate_modesense (struct iscsi_cmd_s *, unsigned char *, unsigned char *, int, int);
extern int transport_get_sense_data (struct iscsi_cmd_s *);
extern void transport_memcpy_read_contig (struct iscsi_cmd_s *, unsigned char *);
extern void transport_memcpy_read_sg (struct iscsi_cmd_s *, struct scatterlist *);
extern void transport_memcpy_write_contig (struct iscsi_cmd_s *, unsigned char *);
extern void transport_memcpy_write_sg (struct iscsi_cmd_s *, struct scatterlist *);
extern iscsi_cmd_t *transport_allocate_passthrough (unsigned char *, int, u32, void *, u32, u32, struct se_obj_lun_type_s *, void *);
extern void transport_passthrough_release (iscsi_cmd_t *);
extern int transport_passthrough_complete (iscsi_cmd_t *);
extern int transport_generic_passthrough_async (iscsi_cmd_t *cmd,
						void (*callback)(iscsi_cmd_t *cmd, void *callback_arg, int complete_status), 
						void *callback_arg);
extern int transport_generic_passthrough (iscsi_cmd_t *);
extern void transport_generic_complete_ok (iscsi_cmd_t *);
extern void transport_free_dev_tasks (iscsi_cmd_t *);
extern void transport_release_tasks (iscsi_cmd_t *);
extern void transport_release_fe_cmd (iscsi_cmd_t *);
extern int transport_generic_remove (iscsi_cmd_t *, int, int);
extern int transport_lun_wait_for_tasks (iscsi_cmd_t *, iscsi_lun_t *);
extern void transport_generic_free_cmd (iscsi_cmd_t *, int, int, int);
extern void transport_generic_wait_for_cmds (iscsi_cmd_t *, int);
extern int transport_generic_do_transform (struct iscsi_cmd_s *, struct iscsi_transform_info_s *);
extern int transport_get_sectors (struct iscsi_cmd_s *, struct se_obj_lun_type_s *, void *);
extern int transport_new_cmd_obj (struct iscsi_cmd_s *, struct iscsi_transform_info_s *, struct se_obj_lun_type_s *, void *, int);
extern unsigned char *transport_get_vaddr (struct se_mem_s *);
extern struct list_head *transport_init_se_mem_list (void);
extern void transport_free_se_mem_list (struct list_head *);
extern int transport_generic_get_mem (struct iscsi_cmd_s *, u32, u32);
extern u32 transport_calc_sg_num (struct iscsi_task_s *, struct se_mem_s *, u32);
extern int transport_map_sg_to_mem (struct iscsi_task_s *, struct list_head *, void *, struct se_mem_s *, struct se_mem_s **, u32 *, u32 *);
extern int transport_map_mem_to_mem (struct iscsi_task_s *, struct list_head *, void *, struct se_mem_s *, struct se_mem_s **, u32 *, u32 *);
extern int transport_map_mem_to_sg (struct iscsi_task_s *, struct list_head *, void *, struct se_mem_s *, struct se_mem_s **, u32 *, u32 *);
extern u32 transport_generic_get_cdb_count (struct iscsi_cmd_s *, struct iscsi_transform_info_s *, struct se_obj_lun_type_s *, void *, unsigned long long, u32, struct se_mem_s *, struct se_mem_s **, u32 *);
extern int transport_generic_new_cmd (iscsi_cmd_t *);
extern void transport_generic_process_write (iscsi_cmd_t *);
extern int transport_generic_do_tmr (iscsi_cmd_t *);
extern void transport_start_status_timer (iscsi_device_t *);
extern void transport_stop_status_timer (iscsi_device_t *);
extern void transport_status_thr_force_offline (iscsi_device_t *, struct se_obj_lun_type_s *, void *);
extern int transport_status_thr_dev_offline (iscsi_device_t *);
extern int transport_status_thr_dev_offline_tasks (iscsi_device_t *, void *);
extern int transport_status_thr_rdev_offline (iscsi_device_t *);
extern void transport_start_status_thread (iscsi_device_t *);
extern void transport_stop_status_thread (iscsi_device_t *);

/*
 * Each iscsi_transport_task_t can have N number of possible iscsi_task_t's
 * for the storage transport(s) to possibly execute.
 * Used primarily for splitting up CDBs that exceed the physical storage
 * HBA's maximum sector count per task.
 */
typedef struct se_mem_s {
	struct page	*se_page;
	u32		se_len;
	u32		se_off;
	struct list_head se_list;
} ____cacheline_aligned se_mem_t;

typedef struct se_port_s {
#ifdef SNMP_SUPPORT
	u32		sep_index;
	scsi_port_stats_t sep_stats;
#endif
	struct iscsi_lun_s *sep_lun;	
	struct iscsi_portal_group_s *sep_tpg;
	struct list_head sep_list;
} se_port_t;

typedef struct iscsi_task_s {
	unsigned char	task_sense;
	unsigned char	*task_buf;
	void		*transport_req;
	u8		task_scsi_status;
	u8		task_flags;
	int		task_error_status;
	int		task_state_flags;
	unsigned long long	task_lba;
	u32		task_no;
	u32		task_sectors;
	u32		task_size;
	u32		task_sg_num;
	u32		task_sg_offset;
	iscsi_cmd_t	*iscsi_cmd;
	iscsi_device_t	*iscsi_dev;
	struct raid_engine_s *iscsi_raid;
	struct semaphore	task_stop_sem;
	atomic_t	task_active;
	atomic_t	task_execute_queue;
	atomic_t	task_timeout;
	atomic_t	task_sent;
	atomic_t	task_stop;
	atomic_t	task_state_active;
	struct timer_list	task_timer;
	int (*transport_map_task)(struct iscsi_task_s *, u32);
	void *se_obj_ptr;
	struct se_obj_lun_type_s *se_obj_api;
	struct iscsi_task_s *t_next;
	struct iscsi_task_s *t_prev;
	struct iscsi_task_s *ts_next;
	struct iscsi_task_s *ts_prev;
	struct list_head t_list;
} ____cacheline_aligned iscsi_task_t;

typedef struct iscsi_transform_info_s {
	int		ti_set_counts;
	u32		ti_data_length;
	unsigned long long	ti_lba;
        struct iscsi_cmd_s *ti_cmd;
        struct iscsi_device_s *ti_dev;
	struct raid_engine_s *ti_raid;
	struct vol_s	*ti_vol;
	void *se_obj_ptr;
	void *ti_obj_ptr;
	struct se_obj_lun_type_s *se_obj_api;
	struct se_obj_lun_type_s *ti_obj_api;
} ____cacheline_aligned iscsi_transform_info_t;

/*
 * Each type of DAS transport that uses the generic command sequencer needs
 * each of the following function pointers set. 
 */
typedef struct iscsi_transport_spc_s {
	int (*inquiry)(iscsi_task_t *, u32);
	int (*none)(iscsi_task_t *, u32);
	int (*read_non_SG)(iscsi_task_t *, u32);
	int (*read_SG)(iscsi_task_t *, u32);
	int (*write_non_SG)(iscsi_task_t *, u32);
	int (*write_SG)(iscsi_task_t *, u32);
} iscsi_transport_spc_t;

/*
 * 	Each type of disk transport supported MUST have a template defined
 *	within its .h file.
 */
typedef struct iscsi_transport_s {
	/*
	 * The Name. :-)
	 */
	char name[16];
	/*
	 * Plugin Type.
	 */
	u8 type;
	/*
	 * Transport Type.
	 */
	u8 transport_type;
	/*
	 * attach_hba():
	 */
	int (*attach_hba)(iscsi_portal_group_t *, iscsi_hba_t *, iscsi_hbainfo_t *);
	/*
	 * detach_hba():
	 */
	int (*detach_hba)(struct iscsi_hba_s *);
	/*
	 * claim_phydevice(): Only for Physical HBAs
	 */
	int (*claim_phydevice)(struct iscsi_hba_s *, struct iscsi_device_s *);
	/*
	 * create_virtdevice(): Only for Virtual HBAs
	 */
	int (*create_virtdevice)(struct iscsi_hba_s *, struct iscsi_devinfo_s *);
	/*
	 * scan_devices(): Only for Physical HBAs
	 */
	int (*scan_devices)(struct iscsi_hba_s *, struct iscsi_hbainfo_s *);
	/*
	 * activate_device():
	 */
	int (*activate_device)(struct iscsi_device_s *);
	/*
	 * deactivate_device():
	 */
	void (*deactivate_device)(struct iscsi_device_s *);
	/*
	 * release_phydevice():
	 */
	int (*release_phydevice)(struct iscsi_device_s *);
	/*
	 * free_device():
	 */
	void (*free_device)(struct iscsi_device_s *);
	/*
	 * check_device_location():
	 */
	int (*check_device_location)(iscsi_device_t *, iscsi_dev_transport_info_t *);
	/*
	 * check_ghost_id():
	 */
	int (*check_ghost_id)(iscsi_hbainfo_t *);
	/*
	 * cmd_sequencer():
	 *
	 * Use transport_generic_cmd_sequencer() for majority of DAS transport drivers
	 * with a iscsi_transport_spc_t struct as mentioned below.
	 * Provided out of convenience.
	 */
	int (*cmd_sequencer)(iscsi_cmd_t *cmd);
	/*
	 * do_tmr():
	 *
	 * Use transport_do_tmr() for majority of DAS transport drivers.
	 * Provided out of convenience.
	 */
	int (*do_tmr)(iscsi_cmd_t *cmd);
	/*
	 * transport_complete():
	 *
	 * Use transport_generic_complete() for majority of DAS transport drivers.
	 * Provided out of convenience.
	 */
	int (*transport_complete)(iscsi_task_t *task);
	/*
	 * allocate_request():
	 */
	void *(*allocate_request)(iscsi_task_t *, iscsi_device_t *);
	/*
	 * allocate_buf():
	 */
	int (*allocate_buf)(iscsi_cmd_t *, u32, u32);
	/*
	 * allocate_DMA();
	 */
	int (*allocate_DMA)(iscsi_cmd_t *, u32, u32);
	/*
	 * free_buf():
	 */
	void (*free_buf)(iscsi_cmd_t *);	
	/*
	 * free_DMA():
	 */
	void (*free_DMA)(iscsi_cmd_t *);
	/*
	 * do_task():
	 */
	int (*do_task)(iscsi_task_t *);
	/*
	 * free_task():
	 */
	void (*free_task)(iscsi_task_t *);
	/*
	 * check_hba_params():
	 */
	int (*check_hba_params)(iscsi_hbainfo_t *, struct iscsi_target *, int);
	/*
	 * check_dev_params():
	 */
	int (*check_dev_params)(iscsi_hba_t *, struct iscsi_target *, iscsi_dev_transport_info_t *);
	/*
	 * check_virtdev_params():
	 */
	int (*check_virtdev_params)(iscsi_devinfo_t *, struct iscsi_target *);
	/*
	 * get_plugin_info():
	 */
	void (*get_plugin_info)(void *, char *, int *);
	/*
	 * get_hba_info():
	 */
	void (*get_hba_info)(iscsi_hba_t *, char *, int *);
	/*
	 * get_dev_info():
	 */
	void (*get_dev_info)(iscsi_device_t *, char *, int *);
	/*
	 * check_lba():
	 */
	int (*check_lba)(unsigned long long lba, iscsi_device_t *);
	/*
	 * check_for_SG():
	 */
	int (*check_for_SG)(iscsi_task_t *);
	/*
	 * get_cdb():
	 */
	unsigned char *(*get_cdb)(iscsi_task_t *);
	/*
	 * get_blocksize():
	 */
	__u32 (*get_blocksize)(iscsi_device_t *);
	/*
	 * get_device_rev():
	 */
	__u32 (*get_device_rev)(iscsi_device_t *);
	/*
	 * get_device_type():
	 */
	__u32 (*get_device_type)(iscsi_device_t *);
	/*
	 * get_dma_length():
	 */
	__u32 (*get_dma_length)(u32, iscsi_device_t *);
	/*
	 * get_evpd_prod():
	 */
	void (*get_evpd_prod)(unsigned char *, u32, iscsi_device_t *);
	/*
	 * get_evpd_sn():
	 */
	void (*get_evpd_sn)(unsigned char *, u32, iscsi_device_t *);
	/*
	 * get_max_cdbs():
	 */
	__u32 (*get_max_cdbs)(iscsi_device_t *);
	/*
	 * get_max_sectors():
	 */
	 __u32 (*get_max_sectors)(iscsi_device_t *);
	/*
	 * get_queue_depth():
	 *
	 */
	__u32 (*get_queue_depth)(iscsi_device_t *);
	/*
	 * transport_timeout_start():
	 */
	int (*transport_timeout_start)(iscsi_device_t *, iscsi_task_t *);
	/*
	 * do_se_mem_map():
	 */
	int (*do_se_mem_map)(iscsi_task_t *, struct list_head *, void *, se_mem_t *, se_mem_t **, u32 *, u32 *);
	/*
	 * get_sense_buffer():
	 */
	unsigned char *(*get_sense_buffer)(iscsi_task_t *);
	/*
	 * get_non_SG():
	 */
	unsigned char *(*get_non_SG)(iscsi_task_t *);
	/*
	 * get_SG():
	 */
	struct scatterlist *(*get_SG)(iscsi_task_t *);
	/*
	 * get_SG_count():
	 */
	__u32 (*get_SG_count)(iscsi_task_t *);
	/*
	 * set_non_SG_buf():
	 */
	int (*set_non_SG_buf)(unsigned char *, iscsi_task_t *);
	/*
	 * map_task_to_SG():
	 */
	void (*map_task_to_SG)(iscsi_task_t *);
	/*
	 * set_iovec_ptrs():
	 */
	int (*set_iovec_ptrs)(iscsi_map_sg_t *, iscsi_unmap_sg_t *);
	/*
	 * shutdown_hba():
	 */
	void (*shutdown_hba)(iscsi_hba_t *);
	/*
	 * write_pending():
	 */
	int (*write_pending)(iscsi_task_t *);
	/*
	 * iscsi_transport_spc_t structure:
	 * 
	 * Contains function pointers of SPC opcodes to call from the generic
	 * command sequencer into a transport driver if the generic command
	 * sequencer is used. (ie: cmd_sequencer() is NULL)
	 */
	iscsi_transport_spc_t *spc;
} ____cacheline_aligned iscsi_transport_t;

#define TRANSPORT(dev)		(dev)->transport
#define TRANSPORT_SPC(dev)	(dev)->transport->spc
#define HBA_TRANSPORT(hba)	(hba)->transport

#endif /* ISCSI_TARGET_TRANSPORT_H */

