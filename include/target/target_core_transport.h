/*******************************************************************************
 * Filename:  target_core_transport.h
 *
 * This file contains the iSCSI Target Generic DAS Transport Layer definitions.
 *
 * Copyright (c) 2002, 2003, 2004, 2005 PyX Technologies, Inc.
 * Copyright (c) 2005, 2006, 2007 SBE, Inc.
 * Copyright (c) 2007-2009 Rising Tide Software, Inc.
 * Copyright (c) 2008-2009 Linux-iSCSI.org
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
 ******************************************************************************/


#ifndef TARGET_CORE_TRANSPORT_H
#define TARGET_CORE_TRANSPORT_H

#define TARGET_CORE_VERSION			TARGET_CORE_MOD_VERSION

/* Attempts before moving from SHORT to LONG */
#define PYX_TRANSPORT_WINDOW_CLOSED_THRESHOLD	3
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
#define PYX_TRANSPORT_INVALID_PARAMETER_LIST	-6
#define PYX_TRANSPORT_LU_COMM_FAILURE		-7
#define PYX_TRANSPORT_UNKNOWN_MODE_PAGE		-8
#define PYX_TRANSPORT_WRITE_PROTECTED		-9
#define PYX_TRANSPORT_TASK_TIMEOUT		-10
#define PYX_TRANSPORT_RESERVATION_CONFLICT	-11
#define PYX_TRANSPORT_ILLEGAL_REQUEST		-12

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
#define TRANSPORT_TIMEOUT_TYPE_DISK		60
#define TRANSPORT_TIMEOUT_TYPE_ROM		120
#define TRANSPORT_TIMEOUT_TYPE_TAPE		600
#define TRANSPORT_TIMEOUT_TYPE_OTHER		300

/* For se_task->task_state_flags */
#define TSF_EXCEPTION_CLEARED			0x01

/*
 * se_subsystem_dev_t->su_dev_flags
*/
#define SDF_FIRMWARE_VPD_UNIT_SERIAL		0x00000001
#define SDF_EMULATED_VPD_UNIT_SERIAL		0x00000002
#define SDF_USING_UDEV_PATH			0x00000004
#define SDF_USING_ALIAS				0x00000008

/*
 * se_device_t->dev_flags
 */
#define DF_READAHEAD_ACTIVE                     0x00000001
#define DF_TRANSPORT_DMA_ALLOC			0x00000002
#define DF_TRANSPORT_BUF_ALLOC			0x00000004
#define DF_DEV_DEBUG				0x00000008
#define DF_CLAIMED_BLOCKDEV			0x00000010
#define DF_PERSISTENT_CLAIMED_BLOCKDEV		0x00000020
#define DF_READ_ONLY				0x00000040
#define DF_SPC3_PERSISTENT_RESERVE		0x00000080
#define DF_SPC2_RESERVATIONS			0x00000100
#define DF_SPC2_RESERVATIONS_WITH_ISID		0x00000200

/*
 * Used as return values from transport_generic_cmd_sequencer()
 */
#define TGCS_DATA_SG_IO_CDB			0
#define TGCS_CONTROL_SG_IO_CDB			1
#define TGCS_CONTROL_NONSG_IO_CDB		2
#define TGCS_NON_DATA_CDB			3
#define TGCS_UNSUPPORTED_CDB			4
#define TGCS_RESERVATION_CONFLICT		5
#define TGCS_INVALID_CDB_FIELD			6
#define TGCS_ILLEGAL_REQUEST			7
#define TGCS_CHECK_CONDITION_UNIT_ATTENTION	8
#define TGCS_CHECK_CONDITION_NOT_READY		9

/* se_dev_attrib_t sanity values */
/* 10 Minutes, see transport_get_default_task_timeout()  */
#define DA_TASK_TIMEOUT_MAX			600
/* Emulation for UNIT ATTENTION Interlock Control */
#define DA_EMULATE_UA_INTLLCK_CTRL		0
/* Emulation for TASK_ABORTED status (TAS) by default */
#define DA_EMULATE_TAS				1
/* No Emulation for PSCSI by default */
#define DA_EMULATE_RESERVATIONS			0
/* No Emulation for PSCSI by default */
#define DA_EMULATE_ALUA				0
/* Enforce SCSI Initiator Port TransportID with 'ISID' for PR */
#define DA_ENFORCE_PR_ISIDS			1
#define DA_STATUS_MAX_SECTORS_MIN		16
#define DA_STATUS_MAX_SECTORS_MAX		8192

#define SE_MODE_PAGE_BUF			512

#define MOD_MAX_SECTORS(ms, bs)			(ms % (PAGE_SIZE / bs))

struct se_mem_s;

extern int init_se_global(void);
extern void release_se_global(void);
#ifdef DEBUG_DEV
extern int __iscsi_debug_dev(se_device_t *);
#endif
extern unsigned char *transport_get_iqn_sn(void);
extern void transport_init_queue_obj(struct se_queue_obj_s *);
extern void transport_load_plugins(void);
extern struct se_plugin_s *transport_core_get_plugin_by_name(const char *name);
extern void transport_check_dev_params_delim(char *, char **);
extern struct se_session_s *transport_init_session(void);
extern void __transport_register_session(struct se_portal_group_s *,
					struct se_node_acl_s *,
					struct se_session_s *, void *);
extern void transport_register_session(struct se_portal_group_s *,
					struct se_node_acl_s *,
					struct se_session_s *, void *);
extern void transport_free_session(struct se_session_s *);
extern void transport_deregister_session_configfs(struct se_session_s *);
extern void transport_deregister_session(struct se_session_s *);
extern void transport_task_dev_remove_state(struct se_task_s *,
						struct se_device_s *);
extern void transport_cmd_finish_abort(struct se_cmd_s *, int);
extern void transport_cmd_finish_abort_tmr(struct se_cmd_s *);
extern int transport_add_cmd_to_queue(struct se_cmd_s *,
					struct se_queue_obj_s *, u8);
extern struct se_queue_req_s *__transport_get_qr_from_queue(
					struct se_queue_obj_s *);
extern void transport_remove_cmd_from_queue(struct se_cmd_s *,
					    struct se_queue_obj_s *);
extern void transport_complete_cmd(se_cmd_t *, int);
extern void transport_complete_task(struct se_task_s *, int);
extern void transport_add_task_to_execute_queue(struct se_task_s *,
						struct se_task_s *,
						struct se_device_s *);
extern void transport_add_tasks_from_cmd(struct se_cmd_s *);
extern struct se_task_s *transport_get_task_from_execute_queue(
						struct se_device_s *);
extern se_queue_req_t *transport_get_qr_from_queue(struct se_queue_obj_s *);
extern int transport_check_device_tcq(se_device_t *, u32, u32);
unsigned char *transport_dump_cmd_direction(struct se_cmd_s *);
extern void transport_dump_dev_state(struct se_device_s *, char *, int *);
extern void transport_dump_dev_info(struct se_device_s *, struct se_lun_s *,
					unsigned long long, char *, int *);
extern void transport_dump_vpd_proto_id(struct t10_vpd_s *,
					unsigned char *, int);
extern int transport_dump_vpd_assoc(struct t10_vpd_s *,
					unsigned char *, int);
extern int transport_dump_vpd_ident_type(struct t10_vpd_s *,
					unsigned char *, int);
extern int transport_dump_vpd_ident(struct t10_vpd_s *,
					unsigned char *, int);
extern int transport_rescan_evpd_device_ident(struct se_device_s *);
extern se_device_t *transport_add_device_to_core_hba(se_hba_t *,
					struct se_subsystem_api_s *,
					struct se_subsystem_dev_s *, u32,
					void *);
extern int transport_generic_activate_device(se_device_t *);
extern void transport_generic_deactivate_device(se_device_t *);
extern int transport_generic_claim_phydevice(se_device_t *);
extern void transport_generic_release_phydevice(se_device_t *, int);
extern void transport_generic_free_device(se_device_t *);
extern int transport_generic_allocate_iovecs(struct se_cmd_s *);
extern void transport_device_setup_cmd(se_cmd_t *);
extern int transport_check_alloc_task_attr(se_cmd_t *);
extern se_cmd_t *transport_alloc_se_cmd(struct target_core_fabric_ops *,
					struct se_session_s *, void *,
					u32, int, int);
extern void transport_free_se_cmd(struct se_cmd_s *);
extern int transport_generic_allocate_tasks(se_cmd_t *, unsigned char *);
extern int transport_generic_handle_cdb(se_cmd_t *);
extern int transport_generic_handle_data(se_cmd_t *);
extern int transport_generic_handle_tmr(se_cmd_t *);
extern int transport_stop_tasks_for_cmd(struct se_cmd_s *);
extern void transport_generic_request_failure(se_cmd_t *, se_device_t *,
						int, int);
extern void transport_direct_request_timeout(se_cmd_t *);
extern void transport_generic_request_timeout(se_cmd_t *);
extern int transport_generic_allocate_buf(se_cmd_t *, u32, u32);
extern int __transport_execute_tasks(struct se_device_s *);
extern void transport_new_cmd_failure(struct se_cmd_s *);
extern u32 transport_get_default_task_timeout(struct se_device_s *);
extern void transport_set_supported_SAM_opcode(struct se_cmd_s *);
extern void transport_start_task_timer(struct se_task_s *);
extern void __transport_stop_task_timer(struct se_task_s *, unsigned long *);
extern void transport_stop_task_timer(struct se_task_s *);
extern void transport_stop_all_task_timers(struct se_cmd_s *);
extern int transport_execute_tasks(struct se_cmd_s *);
extern unsigned char transport_asciihex_to_binaryhex(unsigned char val[2]);
extern int transport_generic_emulate_inquiry(struct se_cmd_s *, unsigned char,
					unsigned char *, unsigned char *,
					unsigned char *);
extern int transport_generic_emulate_readcapacity(struct se_cmd_s *, u32);
extern int transport_generic_emulate_readcapacity_16(struct se_cmd_s *,
							unsigned long long);
extern int transport_generic_emulate_modesense(struct se_cmd_s *,
						unsigned char *,
						unsigned char *, int, int);
extern int transport_generic_emulate_request_sense(struct se_cmd_s *,
						   unsigned char *);
extern int transport_get_sense_data(struct se_cmd_s *);
extern se_cmd_t *transport_allocate_passthrough(unsigned char *, int, u32,
						void *, u32, u32, void *);
extern void transport_passthrough_release(se_cmd_t *);
extern int transport_passthrough_complete(se_cmd_t *);
extern void transport_memcpy_write_contig(se_cmd_t *, struct scatterlist *,
				unsigned char *);
extern void transport_memcpy_read_contig(se_cmd_t *, unsigned char *,
				struct scatterlist *);
extern int transport_generic_passthrough_async(se_cmd_t *cmd,
				void(*callback)(se_cmd_t *cmd,
				void *callback_arg, int complete_status),
				void *callback_arg);
extern int transport_generic_passthrough(se_cmd_t *);
extern void transport_complete_task_attr(se_cmd_t *);
extern void transport_generic_complete_ok(se_cmd_t *);
extern void transport_free_dev_tasks(se_cmd_t *);
extern void transport_release_fe_cmd(se_cmd_t *);
extern int transport_generic_remove(se_cmd_t *, int, int);
extern int transport_generic_map_mem_to_cmd(se_cmd_t *cmd, void *, u32);
extern int transport_lun_wait_for_tasks(se_cmd_t *, se_lun_t *);
extern int transport_clear_lun_from_sessions(se_lun_t *);
extern int transport_check_aborted_status(se_cmd_t *, int);
extern int transport_get_sense_codes(se_cmd_t *, u8 *, u8 *);
extern int transport_set_sense_codes(se_cmd_t *, u8, u8);
extern int transport_send_check_condition_and_sense(se_cmd_t *, u8, int);
extern void transport_send_task_abort(struct se_cmd_s *);
extern void transport_release_cmd_to_pool(se_cmd_t *);
extern void transport_generic_free_cmd(se_cmd_t *, int, int, int);
extern void transport_generic_wait_for_cmds(se_cmd_t *, int);
extern int transport_generic_do_transform(struct se_cmd_s *,
					struct se_transform_info_s *);
extern int transport_get_sectors(struct se_cmd_s *, void *);
extern int transport_new_cmd_obj(struct se_cmd_s *,
				struct se_transform_info_s *, void *, int);
extern unsigned char *transport_get_vaddr(struct se_mem_s *);
extern struct list_head *transport_init_se_mem_list(void);
extern void transport_free_se_mem_list(struct list_head *);
extern int transport_generic_get_mem(struct se_cmd_s *, u32, u32);
extern u32 transport_calc_sg_num(struct se_task_s *, struct se_mem_s *, u32);
extern int transport_map_sg_to_mem(struct se_cmd_s *, struct list_head *,
					void *, u32 *, u32 *);
extern int transport_map_mem_to_mem(struct se_task_s *, struct list_head *,
					void *, struct se_mem_s *,
					struct se_mem_s **, u32 *, u32 *);
extern int transport_map_mem_to_sg(struct se_task_s *, struct list_head *,
					void *, struct se_mem_s *,
					struct se_mem_s **, u32 *, u32 *);
extern u32 transport_generic_get_cdb_count(struct se_cmd_s *,
					struct se_transform_info_s *,
					void *, unsigned long long, u32,
					struct se_mem_s *, struct se_mem_s **,
					u32 *);
extern int transport_generic_new_cmd(se_cmd_t *);
extern void transport_generic_process_write(se_cmd_t *);
extern int transport_generic_do_tmr(se_cmd_t *);

/*
 * Each se_transport_task_t can have N number of possible se_task_t's
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

/*
 * Each type of DAS transport that uses the generic command sequencer needs
 * each of the following function pointers set.
 */
typedef struct se_subsystem_spc_s {
	int (*inquiry)(se_task_t *, u32);
	int (*none)(se_task_t *, u32);
	int (*read_non_SG)(se_task_t *, u32);
	int (*read_SG)(se_task_t *, u32);
	int (*write_non_SG)(se_task_t *, u32);
	int (*write_SG)(se_task_t *, u32);
} se_subsystem_spc_t;

/*
 * 	Each type of disk transport supported MUST have a template defined
 *	within its .h file.
 */
typedef struct se_subsystem_api_s {
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
	int (*attach_hba)(se_hba_t *, u32);
	/*
	 * detach_hba():
	 */
	int (*detach_hba)(struct se_hba_s *);
	/*
	 * pmode_hba(): Used for TCM/pSCSI subsystem plugin HBA ->
	 *		Linux/SCSI struct Scsi_Host passthrough
	*/
	int (*pmode_enable_hba)(struct se_hba_s *, unsigned long);
	/*
	 * claim_phydevice(): Only for Physical HBAs
	 */
	int (*claim_phydevice)(struct se_hba_s *, struct se_device_s *);
	/*
	 * allocate_virtdevice():
	 */
	void *(*allocate_virtdevice)(struct se_hba_s *, const char *);
	/*
	 * create_virtdevice(): Only for Virtual HBAs
	 */
	se_device_t *(*create_virtdevice)(struct se_hba_s *,
				struct se_subsystem_dev_s *, void *);
	/*
	 * activate_device():
	 */
	int (*activate_device)(struct se_device_s *);
	/*
	 * deactivate_device():
	 */
	void (*deactivate_device)(struct se_device_s *);
	/*
	 * release_phydevice():
	 */
	int (*release_phydevice)(struct se_device_s *);
	/*
	 * free_device():
	 */
	void (*free_device)(void *);
	/*
	 * cmd_sequencer():
	 *
	 * Use transport_generic_cmd_sequencer() for majority of DAS transport
	 * drivers with a scsi_transport_spc_t struct as mentioned below.
	 * Provided out of convenience.
	 */
	int (*cmd_sequencer)(se_cmd_t *cmd);
	/*
	 * do_tmr():
	 *
	 * Use transport_do_tmr() for majority of DAS transport drivers.
	 * Provided out of convenience.
	 */
	int (*do_tmr)(se_cmd_t *cmd);
	/*
	 * transport_complete():
	 *
	 * Use transport_generic_complete() for majority of DAS transport
	 * drivers.  Provided out of convenience.
	 */
	int (*transport_complete)(se_task_t *task);
	/*
	 * allocate_request():
	 */
	void *(*allocate_request)(se_task_t *, se_device_t *);
	/*
	 * allocate_buf():
	 */
	int (*allocate_buf)(se_cmd_t *, u32, u32);
	/*
	 * allocate_DMA();
	 */
	int (*allocate_DMA)(se_cmd_t *, u32, u32);
	/*
	 * free_buf():
	 */
	void (*free_buf)(se_cmd_t *);
	/*
	 * free_DMA():
	 */
	void (*free_DMA)(se_cmd_t *);
	/*
	 * do_task():
	 */
	int (*do_task)(se_task_t *);
	/*
	 * free_task():
	 */
	void (*free_task)(se_task_t *);
	/*
	 * check_configfs_dev_params():
	 */
	ssize_t (*check_configfs_dev_params)(se_hba_t *, se_subsystem_dev_t *);
	/*
	 * set_configfs_dev_params():
	 */
	ssize_t (*set_configfs_dev_params)(se_hba_t *, se_subsystem_dev_t *,
						const char *, ssize_t);
	/*
	 * show_configfs_dev_params():
	 */
	ssize_t (*show_configfs_dev_params)(se_hba_t *, se_subsystem_dev_t *,
						char *);
	/*
	 * create_virtdevice_from-fd():
	 */
	se_device_t *(*create_virtdevice_from_fd)(se_subsystem_dev_t *,
						const char *);
	/*
	 * plugin_init():
	 */
	int (*plugin_init)(void);
	/*
	 * plugin_free():
	 */
	void (*plugin_free)(void);
	/*
	 * get_plugin_info():
	 */
	void (*get_plugin_info)(void *, char *, int *);
	/*
	 * get_hba_info():
	 */
	void (*get_hba_info)(se_hba_t *, char *, int *);
	/*
	 * get_dev_info():
	 */
	void (*get_dev_info)(se_device_t *, char *, int *);
	/*
	 * check_lba():
	 */
	int (*check_lba)(unsigned long long lba, se_device_t *);
	/*
	 * check_for_SG():
	 */
	int (*check_for_SG)(se_task_t *);
	/*
	 * get_cdb():
	 */
	unsigned char *(*get_cdb)(se_task_t *);
	/*
	 * get_blocksize():
	 */
	u32 (*get_blocksize)(se_device_t *);
	/*
	 * get_device_rev():
	 */
	u32 (*get_device_rev)(se_device_t *);
	/*
	 * get_device_type():
	 */
	u32 (*get_device_type)(se_device_t *);
	/*
	 * get_dma_length():
	 */
	u32 (*get_dma_length)(u32, se_device_t *);
	/*
	 * get_max_cdbs():
	 */
	u32 (*get_max_cdbs)(se_device_t *);
	/*
	 * get_max_sectors():
	 */
	 u32 (*get_max_sectors)(se_device_t *);
	/*
	 * get_queue_depth():
	 *
	 */
	u32 (*get_queue_depth)(se_device_t *);
	/*
	 * get_max_queue_depth():
	 */
	u32 (*get_max_queue_depth)(se_device_t *);
	/*
	 * do_se_mem_map():
	 */
	int (*do_se_mem_map)(se_task_t *, struct list_head *, void *,
				se_mem_t *, se_mem_t **, u32 *, u32 *);
	/*
	 * get_sense_buffer():
	 */
	unsigned char *(*get_sense_buffer)(se_task_t *);
	/*
	 * map_task_to_SG():
	 */
	void (*map_task_to_SG)(se_task_t *);
	/*
	 * set_iovec_ptrs():
	 */
	int (*set_iovec_ptrs)(se_map_sg_t *, se_unmap_sg_t *);
	/*
	 * write_pending():
	 */
	int (*write_pending)(se_task_t *);
	/*
	 * se_subsystem_spc_t structure:
	 *
	 * Contains function pointers of SPC opcodes to call from the generic
	 * command sequencer into a transport driver if the generic command
	 * sequencer is used. (ie: cmd_sequencer() is NULL)
	 */
	se_subsystem_spc_t *spc;
} ____cacheline_aligned se_subsystem_api_t;

#define TRANSPORT(dev)		((dev)->transport)
#define TRANSPORT_SPC(dev)	((dev)->transport->spc)
#define HBA_TRANSPORT(hba)	((hba)->transport)

#endif /* TARGET_CORE_TRANSPORT_H */

