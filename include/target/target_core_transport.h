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
 * struct se_subsystem_dev->su_dev_flags
*/
#define SDF_FIRMWARE_VPD_UNIT_SERIAL		0x00000001
#define SDF_EMULATED_VPD_UNIT_SERIAL		0x00000002
#define SDF_USING_UDEV_PATH			0x00000004
#define SDF_USING_ALIAS				0x00000008

/*
 * struct se_device->dev_flags
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

/* struct se_dev_attrib sanity values */
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

struct se_mem;

extern int init_se_global(void);
extern void release_se_global(void);
#ifdef DEBUG_DEV
extern int __iscsi_debug_dev(struct se_device *);
#endif
extern unsigned char *transport_get_iqn_sn(void);
extern void transport_init_queue_obj(struct se_queue_obj *);
extern void transport_load_plugins(void);
extern struct se_plugin *transport_core_get_plugin_by_name(const char *name);
extern void transport_check_dev_params_delim(char *, char **);
extern struct se_session *transport_init_session(void);
extern void __transport_register_session(struct se_portal_group *,
					struct se_node_acl *,
					struct se_session *, void *);
extern void transport_register_session(struct se_portal_group *,
					struct se_node_acl *,
					struct se_session *, void *);
extern void transport_free_session(struct se_session *);
extern void transport_deregister_session_configfs(struct se_session *);
extern void transport_deregister_session(struct se_session *);
extern void transport_task_dev_remove_state(struct se_task *,
						struct se_device *);
extern void transport_cmd_finish_abort(struct se_cmd *, int);
extern void transport_cmd_finish_abort_tmr(struct se_cmd *);
extern int transport_add_cmd_to_queue(struct se_cmd *,
					struct se_queue_obj *, u8);
extern struct se_queue_req *__transport_get_qr_from_queue(
					struct se_queue_obj *);
extern void transport_remove_cmd_from_queue(struct se_cmd *,
					    struct se_queue_obj *);
extern void transport_complete_cmd(struct se_cmd *, int);
extern void transport_complete_task(struct se_task *, int);
extern void transport_add_task_to_execute_queue(struct se_task *,
						struct se_task *,
						struct se_device *);
extern void transport_add_tasks_from_cmd(struct se_cmd *);
extern struct se_task *transport_get_task_from_execute_queue(
						struct se_device *);
extern struct se_queue_req *transport_get_qr_from_queue(struct se_queue_obj *);
extern int transport_check_device_tcq(struct se_device *, u32, u32);
unsigned char *transport_dump_cmd_direction(struct se_cmd *);
extern void transport_dump_dev_state(struct se_device *, char *, int *);
extern void transport_dump_dev_info(struct se_device *, struct se_lun *,
					unsigned long long, char *, int *);
extern void transport_dump_vpd_proto_id(struct t10_vpd *,
					unsigned char *, int);
extern int transport_dump_vpd_assoc(struct t10_vpd *,
					unsigned char *, int);
extern int transport_dump_vpd_ident_type(struct t10_vpd *,
					unsigned char *, int);
extern int transport_dump_vpd_ident(struct t10_vpd *,
					unsigned char *, int);
extern int transport_rescan_evpd_device_ident(struct se_device *);
extern struct se_device *transport_add_device_to_core_hba(struct se_hba *,
					struct se_subsystem_api *,
					struct se_subsystem_dev *, u32,
					void *);
extern int transport_generic_activate_device(struct se_device *);
extern void transport_generic_deactivate_device(struct se_device *);
extern int transport_generic_claim_phydevice(struct se_device *);
extern void transport_generic_release_phydevice(struct se_device *, int);
extern void transport_generic_free_device(struct se_device *);
extern int transport_generic_allocate_iovecs(struct se_cmd *);
extern void transport_device_setup_cmd(struct se_cmd *);
extern int transport_check_alloc_task_attr(struct se_cmd *);
extern struct se_cmd *transport_alloc_se_cmd(struct target_core_fabric_ops *,
					struct se_session *, void *,
					u32, int, int);
extern void transport_free_se_cmd(struct se_cmd *);
extern int transport_generic_allocate_tasks(struct se_cmd *, unsigned char *);
extern int transport_generic_handle_cdb(struct se_cmd *);
extern int transport_generic_handle_data(struct se_cmd *);
extern int transport_generic_handle_tmr(struct se_cmd *);
extern int transport_stop_tasks_for_cmd(struct se_cmd *);
extern void transport_generic_request_failure(struct se_cmd *, struct se_device *,
						int, int);
extern void transport_direct_request_timeout(struct se_cmd *);
extern void transport_generic_request_timeout(struct se_cmd *);
extern int transport_generic_allocate_buf(struct se_cmd *, u32, u32);
extern int __transport_execute_tasks(struct se_device *);
extern void transport_new_cmd_failure(struct se_cmd *);
extern u32 transport_get_default_task_timeout(struct se_device *);
extern void transport_set_supported_SAM_opcode(struct se_cmd *);
extern void transport_start_task_timer(struct se_task *);
extern void __transport_stop_task_timer(struct se_task *, unsigned long *);
extern void transport_stop_task_timer(struct se_task *);
extern void transport_stop_all_task_timers(struct se_cmd *);
extern int transport_execute_tasks(struct se_cmd *);
extern unsigned char transport_asciihex_to_binaryhex(unsigned char val[2]);
extern int transport_generic_emulate_inquiry(struct se_cmd *, unsigned char,
					unsigned char *, unsigned char *,
					unsigned char *);
extern int transport_generic_emulate_readcapacity(struct se_cmd *, u32);
extern int transport_generic_emulate_readcapacity_16(struct se_cmd *,
							unsigned long long);
extern int transport_generic_emulate_modesense(struct se_cmd *,
						unsigned char *,
						unsigned char *, int, int);
extern int transport_generic_emulate_request_sense(struct se_cmd *,
						   unsigned char *);
extern int transport_get_sense_data(struct se_cmd *);
extern struct se_cmd *transport_allocate_passthrough(unsigned char *, int, u32,
						void *, u32, u32, void *);
extern void transport_passthrough_release(struct se_cmd *);
extern int transport_passthrough_complete(struct se_cmd *);
extern void transport_memcpy_write_contig(struct se_cmd *, struct scatterlist *,
				unsigned char *);
extern void transport_memcpy_read_contig(struct se_cmd *, unsigned char *,
				struct scatterlist *);
extern int transport_generic_passthrough_async(struct se_cmd *cmd,
				void(*callback)(struct se_cmd *cmd,
				void *callback_arg, int complete_status),
				void *callback_arg);
extern int transport_generic_passthrough(struct se_cmd *);
extern void transport_complete_task_attr(struct se_cmd *);
extern void transport_generic_complete_ok(struct se_cmd *);
extern void transport_free_dev_tasks(struct se_cmd *);
extern void transport_release_fe_cmd(struct se_cmd *);
extern int transport_generic_remove(struct se_cmd *, int, int);
extern int transport_generic_map_mem_to_cmd(struct se_cmd *cmd, void *, u32);
extern int transport_lun_wait_for_tasks(struct se_cmd *, struct se_lun *);
extern int transport_clear_lun_from_sessions(struct se_lun *);
extern int transport_check_aborted_status(struct se_cmd *, int);
extern int transport_get_sense_codes(struct se_cmd *, u8 *, u8 *);
extern int transport_set_sense_codes(struct se_cmd *, u8, u8);
extern int transport_send_check_condition_and_sense(struct se_cmd *, u8, int);
extern void transport_send_task_abort(struct se_cmd *);
extern void transport_release_cmd_to_pool(struct se_cmd *);
extern void transport_generic_free_cmd(struct se_cmd *, int, int, int);
extern void transport_generic_wait_for_cmds(struct se_cmd *, int);
extern int transport_generic_do_transform(struct se_cmd *,
					struct se_transform_info *);
extern int transport_get_sectors(struct se_cmd *, void *);
extern int transport_new_cmd_obj(struct se_cmd *,
				struct se_transform_info *, void *, int);
extern unsigned char *transport_get_vaddr(struct se_mem *);
extern struct list_head *transport_init_se_mem_list(void);
extern void transport_free_se_mem_list(struct list_head *);
extern int transport_generic_get_mem(struct se_cmd *, u32, u32);
extern u32 transport_calc_sg_num(struct se_task *, struct se_mem *, u32);
extern int transport_map_sg_to_mem(struct se_cmd *, struct list_head *,
					void *, u32 *, u32 *);
extern int transport_map_mem_to_mem(struct se_task *, struct list_head *,
					void *, struct se_mem *,
					struct se_mem **, u32 *, u32 *);
extern int transport_map_mem_to_sg(struct se_task *, struct list_head *,
					void *, struct se_mem *,
					struct se_mem **, u32 *, u32 *);
extern u32 transport_generic_get_cdb_count(struct se_cmd *,
					struct se_transform_info *,
					void *, unsigned long long, u32,
					struct se_mem *, struct se_mem **,
					u32 *);
extern int transport_generic_new_cmd(struct se_cmd *);
extern void transport_generic_process_write(struct se_cmd *);
extern int transport_generic_do_tmr(struct se_cmd *);

/*
 * Each se_transport_task_t can have N number of possible struct se_task's
 * for the storage transport(s) to possibly execute.
 * Used primarily for splitting up CDBs that exceed the physical storage
 * HBA's maximum sector count per task.
 */
struct se_mem {
	struct page	*se_page;
	u32		se_len;
	u32		se_off;
	struct list_head se_list;
} ____cacheline_aligned;

/*
 * Each type of DAS transport that uses the generic command sequencer needs
 * each of the following function pointers set.
 */
struct se_subsystem_spc {
	int (*inquiry)(struct se_task *, u32);
	int (*none)(struct se_task *, u32);
	int (*read_non_SG)(struct se_task *, u32);
	int (*read_SG)(struct se_task *, u32);
	int (*write_non_SG)(struct se_task *, u32);
	int (*write_SG)(struct se_task *, u32);
};

/*
 * 	Each type of disk transport supported MUST have a template defined
 *	within its .h file.
 */
struct se_subsystem_api {
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
	int (*attach_hba)(struct se_hba *, u32);
	/*
	 * detach_hba():
	 */
	int (*detach_hba)(struct se_hba *);
	/*
	 * pmode_hba(): Used for TCM/pSCSI subsystem plugin HBA ->
	 *		Linux/SCSI struct Scsi_Host passthrough
	*/
	int (*pmode_enable_hba)(struct se_hba *, unsigned long);
	/*
	 * claim_phydevice(): Only for Physical HBAs
	 */
	int (*claim_phydevice)(struct se_hba *, struct se_device *);
	/*
	 * allocate_virtdevice():
	 */
	void *(*allocate_virtdevice)(struct se_hba *, const char *);
	/*
	 * create_virtdevice(): Only for Virtual HBAs
	 */
	struct se_device *(*create_virtdevice)(struct se_hba *,
				struct se_subsystem_dev *, void *);
	/*
	 * activate_device():
	 */
	int (*activate_device)(struct se_device *);
	/*
	 * deactivate_device():
	 */
	void (*deactivate_device)(struct se_device *);
	/*
	 * release_phydevice():
	 */
	int (*release_phydevice)(struct se_device *);
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
	int (*cmd_sequencer)(struct se_cmd *cmd);
	/*
	 * do_tmr():
	 *
	 * Use transport_do_tmr() for majority of DAS transport drivers.
	 * Provided out of convenience.
	 */
	int (*do_tmr)(struct se_cmd *cmd);
	/*
	 * transport_complete():
	 *
	 * Use transport_generic_complete() for majority of DAS transport
	 * drivers.  Provided out of convenience.
	 */
	int (*transport_complete)(struct se_task *task);
	/*
	 * allocate_request():
	 */
	void *(*allocate_request)(struct se_task *, struct se_device *);
	/*
	 * allocate_buf():
	 */
	int (*allocate_buf)(struct se_cmd *, u32, u32);
	/*
	 * allocate_DMA();
	 */
	int (*allocate_DMA)(struct se_cmd *, u32, u32);
	/*
	 * free_buf():
	 */
	void (*free_buf)(struct se_cmd *);
	/*
	 * free_DMA():
	 */
	void (*free_DMA)(struct se_cmd *);
	/*
	 * do_task():
	 */
	int (*do_task)(struct se_task *);
	/*
	 * free_task():
	 */
	void (*free_task)(struct se_task *);
	/*
	 * check_configfs_dev_params():
	 */
	ssize_t (*check_configfs_dev_params)(struct se_hba *, struct se_subsystem_dev *);
	/*
	 * set_configfs_dev_params():
	 */
	ssize_t (*set_configfs_dev_params)(struct se_hba *, struct se_subsystem_dev *,
						const char *, ssize_t);
	/*
	 * show_configfs_dev_params():
	 */
	ssize_t (*show_configfs_dev_params)(struct se_hba *, struct se_subsystem_dev *,
						char *);
	/*
	 * create_virtdevice_from-fd():
	 */
	struct se_device *(*create_virtdevice_from_fd)(struct se_subsystem_dev *,
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
	void (*get_hba_info)(struct se_hba *, char *, int *);
	/*
	 * get_dev_info():
	 */
	void (*get_dev_info)(struct se_device *, char *, int *);
	/*
	 * check_lba():
	 */
	int (*check_lba)(unsigned long long lba, struct se_device *);
	/*
	 * check_for_SG():
	 */
	int (*check_for_SG)(struct se_task *);
	/*
	 * get_cdb():
	 */
	unsigned char *(*get_cdb)(struct se_task *);
	/*
	 * get_blocksize():
	 */
	u32 (*get_blocksize)(struct se_device *);
	/*
	 * get_device_rev():
	 */
	u32 (*get_device_rev)(struct se_device *);
	/*
	 * get_device_type():
	 */
	u32 (*get_device_type)(struct se_device *);
	/*
	 * get_dma_length():
	 */
	u32 (*get_dma_length)(u32, struct se_device *);
	/*
	 * get_max_cdbs():
	 */
	u32 (*get_max_cdbs)(struct se_device *);
	/*
	 * get_max_sectors():
	 */
	 u32 (*get_max_sectors)(struct se_device *);
	/*
	 * get_queue_depth():
	 *
	 */
	u32 (*get_queue_depth)(struct se_device *);
	/*
	 * get_max_queue_depth():
	 */
	u32 (*get_max_queue_depth)(struct se_device *);
	/*
	 * do_se_mem_map():
	 */
	int (*do_se_mem_map)(struct se_task *, struct list_head *, void *,
				struct se_mem *, struct se_mem **, u32 *, u32 *);
	/*
	 * get_sense_buffer():
	 */
	unsigned char *(*get_sense_buffer)(struct se_task *);
	/*
	 * map_task_to_SG():
	 */
	void (*map_task_to_SG)(struct se_task *);
	/*
	 * set_iovec_ptrs():
	 */
	int (*set_iovec_ptrs)(struct se_map_sg *, struct se_unmap_sg *);
	/*
	 * write_pending():
	 */
	int (*write_pending)(struct se_task *);
	/*
	 * struct se_subsystem_spc structure:
	 *
	 * Contains function pointers of SPC opcodes to call from the generic
	 * command sequencer into a transport driver if the generic command
	 * sequencer is used. (ie: cmd_sequencer() is NULL)
	 */
	struct se_subsystem_spc *spc;
} ____cacheline_aligned;

#define TRANSPORT(dev)		((dev)->transport)
#define TRANSPORT_SPC(dev)	((dev)->transport->spc)
#define HBA_TRANSPORT(hba)	((hba)->transport)

#endif /* TARGET_CORE_TRANSPORT_H */

