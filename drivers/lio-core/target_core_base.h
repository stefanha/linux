/*********************************************************************************
 * Filename:  target_core_base.h
 *
 * This file contains definitions related to the Target Core Engine.
 *
 * Nicholas A. Bellinger <nab@kernel.org>
 *
 * Copyright (c) 2003, 2004, 2005 PyX Technologies, Inc.
 * Copyright (c) 2005, 2006, 2007 SBE, Inc.
 * Copyright (c) 2007 Rising Tide Software, Inc.
 * Copyright (c) 2008 Linux-iSCSI.org
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


#ifndef TARGET_CORE_BASE_H
#define TARGET_CORE_BASE_H

#include <linux/in.h>
#include <linux/configfs.h>
#include <net/sock.h>
#include <net/tcp.h>
#include <iscsi_linux_defs.h>
#ifdef SNMP_SUPPORT
#include <target_core_mib.h>
#endif /* SNMP_SUPPORT */

#define SCSI_CDB_SIZE			16 /* SCSI Command Descriptor Block Size a la SCSI's MAX_COMMAND_SIZE */
#define TRANSPORT_IOV_DATA_BUFFER	5

#define TRANSPORT_MAX_GLOBAL_HBAS           256 /* Maximum Physical or Virtual HBAs globally (not part of a TPG) */
#define TRANSPORT_MAX_LUNS_PER_TPG	    256 /* Maximum Number of LUNs per Target Portal Group */

#define TRANSPORT_SENSE_BUFFER              64 /* Originally from iSCSI RFC, should be from SCSI_SENSE_BUFFERSIZE */
#define TRANSPORT_SENSE_SEGMENT_LENGTH      66 /* Sense Data Segment */
#define TRANSPORT_SENSE_SEGMENT_TOTAL       68 /* TRANSPORT_SENSE_SEGMENT_LENGTH + Padding */

#define TRANSPORT_IQN_LEN			224 /* Currently same as ISCSI_IQN_LEN */

#define EVPD_TMP_BUF_SIZE			128 /* Used to parse EVPD into t10_evpd_t */

/* used by PSCSI and iBlock Transport drivers */
#define READ_BLOCK_LEN          		6
#define READ_CAP_LEN            		8
#define READ_POSITION_LEN       		20
#define INQUIRY_LEN				36
#define INQUIRY_EVPD_SERIAL_LEN			254
#define INQUIRY_EVPD_DEVICE_IDENTIFIER_LEN	254

/* used by PSCSI and iBlock Transport drivers */
#ifndef GET_CONFIGURATION
#define		GET_CONFIGURATION		0x46
#endif
#ifndef LOAD_UNLOAD_MEDIUM
#define		LOAD_UNLOAD_MEDIUM		0xa6
#endif
#ifndef REPORT_LUNS
#define         REPORT_LUNS     		0xa0
#endif
#ifndef READ_16
#define         READ_16         		0x88
#endif
#ifndef WRITE_16
#define         WRITE_16        		0x8a
#endif
#ifndef READ_CD
#define		READ_CD				0xbe
#endif
#ifndef READ_DISK_INFORMATION
#define		READ_DISK_INFORMATION		0x51
#endif
#ifndef READ_DVD_STRUCTURE
#define		READ_DVD_STRUCTURE		0xad
#endif
#ifndef REPORT_KEY
#define		REPORT_KEY			0xa4
#endif
#ifndef SEND_KEY
#define		SEND_KEY			0xa3
#endif
#ifndef READ_TRACK_RZONE_INFO
#define		READ_TRACK_RZONE_INFO		0x52
#endif
#ifndef SET_SPEED
#define		SET_SPEED			0xbb
#endif
#ifndef CLOSE_TRACK
#define		CLOSE_TRACK			0x5b
#endif
#ifndef READ_BUFFER_CAPACITY
#define		READ_BUFFER_CAPACITY		0x5c
#endif
#ifndef SEND_OPC_INFORMATION
#define		SEND_OPC_INFORMATION		0x54
#endif
#ifndef SERVICE_ACTION_IN
#define		SERVICE_ACTION_IN		0x9e
#endif
#ifndef SAI_READ_CAPACITY_16
#define		SAI_READ_CAPACITY_16		0x10
#endif
#ifndef INITIALIZE_ELEMENT_STATUS
#define		INITIALIZE_ELEMENT_STATUS	0x07
#endif
#ifndef VERIFY_16
#define		VERIFY_16			0x8f
#endif

/* se_cmd_t->data_direction */
#define SE_DIRECTION_NONE			0
#define SE_DIRECTION_READ			1
#define SE_DIRECTION_WRITE			2
#define SE_DIRECTION_BIDI			3

/* se_hba_t->hba_flags */
#define HBA_FLAGS_INTERNAL_USE			0x00000001

/* se_hba_t->hba_status and iscsi_tpg_hba->thba_status */
#define HBA_STATUS_FREE				0x00000001
#define HBA_STATUS_ACTIVE			0x00000002
#define HBA_STATUS_INACTIVE			0x00000004

/* se_lun_t->lun_status */
#define TRANSPORT_LUN_STATUS_FREE		0
#define TRANSPORT_LUN_STATUS_ACTIVE		1

/* se_lun_t->lun_type */
#define TRANSPORT_LUN_TYPE_NONE			0
#define TRANSPORT_LUN_TYPE_DEVICE		1

/* se_portal_group_t->se_tpg_type */
#define TRANSPORT_TPG_TYPE_NORMAL		0
#define TRANSPORT_TPG_TYPE_DISCOVERY		1

/* Used for se_node_acl->nodeacl_flags */
#define NAF_DYNAMIC_NODE_ACL                    0x01

/* Special transport agnostic se_cmd_t->t_states */
#define TRANSPORT_NO_STATE			240
#define TRANSPORT_NEW_CMD			241
#define TRANSPORT_DEFERRED_CMD			242
#define TRANSPORT_WRITE_PENDING			243
#define TRANSPORT_PROCESS_WRITE			244
#define TRANSPORT_PROCESSING			245
#define TRANSPORT_COMPLETE_OK			246
#define TRANSPORT_COMPLETE_FAILURE		247
#define TRANSPORT_COMPLETE_TIMEOUT		248
#define TRANSPORT_PROCESS_TMR			249
#define TRANSPORT_TMR_COMPLETE			250
#define TRANSPORT_ISTATE_PROCESSING 		251
#define TRANSPORT_ISTATE_PROCESSED  		252
#define TRANSPORT_KILL				253
#define TRANSPORT_REMOVE			254
#define TRANSPORT_FREE				255

#define SCF_SUPPORTED_SAM_OPCODE                0x00000001
#define SCF_TRANSPORT_TASK_SENSE                0x00000002
#define SCF_EMULATED_TASK_SENSE                 0x00000004
#define SCF_SCSI_DATA_SG_IO_CDB                 0x00000008
#define SCF_SCSI_CONTROL_SG_IO_CDB              0x00000010
#define SCF_SCSI_CONTROL_NONSG_IO_CDB           0x00000020
#define SCF_SCSI_NON_DATA_CDB                   0x00000040
#define SCF_SCSI_CDB_EXCEPTION                  0x00000080
#define SCF_SCSI_RESERVATION_CONFLICT           0x00000100
#define SCF_CMD_PASSTHROUGH                     0x00000200
#define SCF_CMD_PASSTHROUGH_NOALLOC             0x00000400
#define SCF_SE_CMD_FAILED                       0x00000800
#define SCF_SE_LUN_CMD                          0x00001000
#define SCF_SE_ALLOW_EOO                        0x00002000
#define SCF_SE_DISABLE_ONLINE_CHECK             0x00004000
#define SCF_SENT_CHECK_CONDITION		0x00008000
#define SCF_OVERFLOW_BIT                        0x00010000
#define SCF_UNDERFLOW_BIT                       0x00020000

/* se_device_t->type */
#define PSCSI					1
#define SSCSI					2
#define PATA					3
#define IBLOCK					4
#define RAMDISK_DR				5
#define RAMDISK_MCP				6
#define FILEIO					7
#define VROM					8
#define VTAPE					9
#define MEDIA_CHANGER				10

/* se_dev_entry_t->lun_flags and se_lun_t->lun_access */
#define TRANSPORT_LUNFLAGS_NO_ACCESS		0x00000000
#define TRANSPORT_LUNFLAGS_INITIATOR_ACCESS	0x00000001
#define TRANSPORT_LUNFLAGS_READ_ONLY		0x00000002
#define TRANSPORT_LUNFLAGS_READ_WRITE		0x00000004

/* se_device_t->dev_status */
#define TRANSPORT_DEVICE_ACTIVATED		0x01
#define	TRANSPORT_DEVICE_DEACTIVATED		0x02
#define TRANSPORT_DEVICE_QUEUE_FULL		0x04
#define	TRANSPORT_DEVICE_SHUTDOWN		0x08
#define TRANSPORT_DEVICE_OFFLINE_ACTIVATED	0x10
#define TRANSPORT_DEVICE_OFFLINE_DEACTIVATED	0x20

#define	DEV_STATUS_THR_TUR			1
#define DEV_STATUS_THR_TAKE_ONLINE		2
#define DEV_STATUS_THR_TAKE_OFFLINE		3
#define DEV_STATUS_THR_SHUTDOWN			4

/* iscsi_send_check_condition_and_sense() */
#define NON_EXISTENT_LUN			0x1
#define UNSUPPORTED_SCSI_OPCODE			0x2
#define INCORRECT_AMOUNT_OF_DATA		0x3
#define UNEXPECTED_UNSOLICITED_DATA		0x4
#define SERVICE_CRC_ERROR			0x5
#define SNACK_REJECTED				0x6
#define SECTOR_COUNT_TOO_MANY			0x7
#define INVALID_CDB_FIELD			0x8
#define LOGICAL_UNIT_COMMUNICATION_FAILURE	0x9
#define UNKNOWN_MODE_PAGE			0xa
#define WRITE_PROTECTED				0xb

typedef struct se_obj_s {
	atomic_t obj_access_count;
} ____cacheline_aligned se_obj_t;

typedef struct t10_evpd_s {
	unsigned char device_identifier[INQUIRY_EVPD_DEVICE_IDENTIFIER_LEN];
	u32 protocol_identifier;
	u32 device_identifier_code_set;
	u32 association;
	u32 device_identifier_type;
	struct list_head evpd_list;
} t10_evpd_t;

typedef struct t10_wwn_s {
        unsigned char vendor[8];
        unsigned char model[16];
	unsigned char revision[4];
        unsigned char unit_serial[INQUIRY_EVPD_SERIAL_LEN];
	spinlock_t t10_evpd_lock;
	struct list_head t10_evpd_list;
} ____cacheline_aligned t10_wwn_t;

typedef struct se_queue_req_s {
        int                     state;
        void                    *queue_se_obj_ptr;
        void                    *cmd;
        struct se_obj_lun_type_s *queue_se_obj_api;
        struct se_queue_req_s   *next;
        struct se_queue_req_s   *prev;
} ____cacheline_aligned se_queue_req_t;

typedef struct se_queue_obj_s {
	spinlock_t		cmd_queue_lock;
	se_queue_req_t		*queue_head;
	se_queue_req_t		*queue_tail;
	struct semaphore		thread_sem;
	struct semaphore		thread_create_sem;
	struct semaphore		thread_done_sem;
} ____cacheline_aligned se_queue_obj_t;

typedef struct se_transport_task_s {
	unsigned char		t_task_cdb[SCSI_CDB_SIZE];
	unsigned long long	t_task_lba;
	int			t_tasks_failed;
	u32			t_task_cdbs;
	u32			t_task_check;
	u32			t_task_no;
	u32			t_task_sectors;
	u32			t_task_se_num;
	atomic_t		t_fe_count;
	atomic_t		t_se_count;
	atomic_t		t_task_cdbs_left;       
	atomic_t		t_task_cdbs_ex_left;
	atomic_t		t_task_cdbs_timeout_left;
	atomic_t		t_task_cdbs_sent;
	atomic_t		t_transport_active;     
	atomic_t		t_transport_complete;
	atomic_t		t_transport_queue_active;
	atomic_t		t_transport_sent;       
	atomic_t		t_transport_stop;       
	atomic_t		t_transport_timeout;
	atomic_t		transport_lun_active;
	atomic_t		transport_lun_fe_stop;
	atomic_t		transport_lun_stop;
	spinlock_t		t_state_lock;
	struct semaphore	t_transport_stop_sem;   
	struct semaphore	t_transport_passthrough_sem;
	struct semaphore	t_transport_passthrough_wsem;
	struct semaphore	transport_lun_fe_stop_sem;
	struct semaphore	transport_lun_stop_sem;
	void			*t_task_buf;
	void			*t_task_pt_buf;
	struct list_head	t_task_list;
	struct list_head	*t_mem_list;
} ____cacheline_aligned se_transport_task_t;

typedef struct se_task_s {
        unsigned char   task_sense;
	struct scatterlist *task_sg;
        void            *transport_req;
        u8              task_scsi_status;
        u8              task_flags;
        int             task_error_status;
        int             task_state_flags;
        unsigned long long      task_lba;
        u32             task_no;
        u32             task_sectors;
        u32             task_size;
        u32             task_sg_num;
        u32             task_sg_offset;
	struct se_cmd_s	*task_se_cmd;
        struct se_device_s     *se_dev;
        struct semaphore        task_stop_sem;
        atomic_t        task_active;
        atomic_t        task_execute_queue;
        atomic_t        task_timeout;
        atomic_t        task_sent;
        atomic_t        task_stop;
        atomic_t        task_state_active;
        struct timer_list       task_timer;
        int (*transport_map_task)(struct se_task_s *, u32);
        void *se_obj_ptr;
        struct se_obj_lun_type_s *se_obj_api;
        struct se_task_s *t_next;
        struct se_task_s *t_prev;
        struct se_task_s *ts_next;
        struct se_task_s *ts_prev;
        struct list_head t_list;
} ____cacheline_aligned se_task_t;

#define TASK_CMD(task)	((struct se_cmd_s *)task->task_se_cmd)

typedef struct se_transform_info_s {
        int             ti_set_counts;
        u32             ti_data_length;
        unsigned long long      ti_lba;
        struct se_cmd_s *ti_se_cmd;
        struct se_device_s *ti_dev;
        void *se_obj_ptr;
        void *ti_obj_ptr;
        struct se_obj_lun_type_s *se_obj_api;
        struct se_obj_lun_type_s *ti_obj_api;
} ____cacheline_aligned se_transform_info_t;

typedef struct se_offset_map_s {
        int                     map_reset;
        u32                     iovec_length;
        u32                     iscsi_offset;
        u32                     current_offset;
        u32                     orig_offset;
        u32                     sg_count;
        u32                     sg_current;
        u32                     sg_length;
        struct page             *sg_page;
        struct se_mem_s         *map_se_mem;                                                                                 struct se_mem_s         *map_orig_se_mem;                                                                            void                    *iovec_base;
} ____cacheline_aligned se_offset_map_t;
        
typedef struct se_map_sg_s {    
        int                     map_flags;
        u32                     data_length;
        u32                     data_offset;
	void			*fabric_cmd;
        struct se_cmd_s         *se_cmd;
        struct iovec            *iov;
} ____cacheline_aligned se_map_sg_t;
        
typedef struct se_unmap_sg_s {  
        u32                     data_length;
        u32                     sg_count;
        u32                     sg_offset;
        u32                     padding;
        u32                     t_offset;
	void			*fabric_cmd;
        struct se_cmd_s         *se_cmd;
        se_offset_map_t         lmap;
        struct se_mem_s         *cur_se_mem;
} ____cacheline_aligned se_unmap_sg_t;

typedef struct se_cmd_s {
	u8			scsi_status; /* SAM response code being sent to initiator */
	u8			scsi_sense_reason;
	u16			scsi_sense_length;
	int			data_direction;
	int			t_state; /* Transport protocol dependent state */
	int			deferred_t_state; /* Transport protocol dependent state for out of order CmdSNs */
	int			transport_error_status; /* Transport specific error status */
	u32			se_cmd_flags;
	u32			data_length; /* Total size in bytes associated with command */
	u32			cmd_spdtl;  /* SCSI Presented Data Transfer Length */
	u32			residual_count;
	u32			orig_fe_lun;
	u32			iov_data_count; /* Number of iovecs iovecs used for IP stack calls */
	u32			orig_iov_data_count; /* Number of iovecs allocated for iscsi_cmd_t->iov_data */
	atomic_t                transport_sent;
	void			*sense_buffer; /* Used for sense data */
	struct iovec		*iov_data; /* Used with sockets based fabric plugins */
	struct se_device_s      *se_dev;
	struct se_dev_entry_s   *se_deve;
	struct se_lun_s		*se_lun;
	struct se_obj_lun_type_s *se_obj_api;
	void			*se_obj_ptr;
	struct se_obj_lun_type_s *se_orig_obj_api;
	void			*se_orig_obj_ptr;
	void			*se_fabric_cmd_ptr;
	struct se_session_s	*se_sess;
	struct se_transport_task_s *t_task;
	struct target_core_fabric_ops *se_tfo;
        struct se_cmd_s      	*l_next;
        struct se_cmd_s      	*l_prev;
	int (*transport_add_cmd_to_queue)(struct se_cmd_s *, u8);
	int (*transport_allocate_iovecs)(struct se_cmd_s *);
	int (*transport_allocate_resources)(struct se_cmd_s *, u32, u32);
	int (*transport_cdb_transform)(struct se_cmd_s *, struct se_transform_info_s *);
	int (*transport_do_transform)(struct se_cmd_s *, struct se_transform_info_s *);
	int (*transport_emulate_cdb)(struct se_cmd_s *);
	void (*transport_free_resources)(struct se_cmd_s *);
	u32 (*transport_get_lba)(unsigned char *);
	unsigned long long (*transport_get_long_lba)(unsigned char *);
	struct se_task_s *(*transport_get_task)(struct se_transform_info_s *, struct se_cmd_s *, void *, struct se_obj_lun_type_s *);
	int (*transport_map_buffers_to_tasks)(struct se_cmd_s *);
	void (*transport_map_SG_segments)(struct se_unmap_sg_s *);
	void (*transport_passthrough_done)(struct se_cmd_s *);
	void (*transport_unmap_SG_segments)(struct se_unmap_sg_s *);
	int (*transport_set_iovec_ptrs)(struct se_map_sg_s *, struct se_unmap_sg_s *);
	void (*transport_split_cdb)(unsigned long long, u32 *, unsigned char *);
	void (*transport_wait_for_tasks)(struct se_cmd_s *, int, int);
	void (*callback)(struct se_cmd_s *cmd, void *callback_arg, int complete_status);
	void *callback_arg;
} ____cacheline_aligned se_cmd_t;

#define T_TASK(cmd)     ((se_transport_task_t *)(cmd->t_task))
#define CMD_OBJ_API(cmd) ((struct se_obj_lun_type_s *)(cmd->se_obj_api))
#define CMD_ORIG_OBJ_API(cmd) ((struct se_obj_lun_type_s *)(cmd->se_orig_obj_api))
#define CMD_TFO(cmd) ((struct target_core_fabric_ops *)cmd->se_tfo)

typedef struct se_tmr_req_s {
	void 			*fabric_tmr_ptr;	
} ____cacheline_aligned se_tmr_req_t;

typedef struct se_node_acl_s {
	char			initiatorname[TRANSPORT_IQN_LEN];
	int			nodeacl_flags;
	u32			queue_depth;
#ifdef SNMP_SUPPORT
	u32			acl_index;
	u64			num_cmds;
	u64			read_bytes;
	u64			write_bytes;
	spinlock_t		stats_lock;
#endif /* SNMP_SUPPORT */
	struct se_dev_entry_s	*device_list;
	struct se_session_s	*nacl_sess;
	struct se_portal_group_s *se_tpg;
	void			*fabric_acl_ptr;
	spinlock_t		device_list_lock;
	spinlock_t		nacl_sess_lock;
	struct config_group	acl_group;
	struct config_group	acl_param_group;
	struct se_node_acl_s	*next;
	struct se_node_acl_s	*prev;
} ____cacheline_aligned se_node_acl_t;

typedef struct se_session_s {
	struct se_node_acl_s	*se_node_acl;
	struct se_portal_group_s *se_tpg;
	void			*fabric_sess_ptr;
	struct list_head	sess_list;
} ____cacheline_aligned se_session_t;

#define SE_SESS(cmd)		((struct se_session_s *)(cmd)->se_sess)
#define SE_NODE_ACL(sess)	((struct se_node_acl_s *)(sess)->se_node_acl)

struct se_device_s;
struct se_transform_info_s;
struct se_obj_lun_type_s;
struct scatterlist;

typedef struct se_lun_acl_s {
	char			initiatorname[TRANSPORT_IQN_LEN];
	u32			mapped_lun;
	struct se_node_acl_s	*se_lun_nacl;
	struct se_lun_s		*se_lun;
	struct se_lun_acl_s	*next;
	struct se_lun_acl_s	*prev;
	struct config_group	se_lun_group;
}  ____cacheline_aligned se_lun_acl_t;

typedef struct se_dev_entry_s {
	__u32			lun_flags;
	__u32			deve_cmds;
	__u32			mapped_lun;
	__u32			average_bytes;
	__u32			last_byte_count;
	__u32			total_cmds;
	__u32			total_bytes;
#ifdef SNMP_SUPPORT
	__u64			creation_time;
	__u32			attach_count;
	__u64			read_bytes;
	__u64			write_bytes;
#endif /* SNMP_SUPPORT */
	struct se_lun_s		*se_lun;
}  ____cacheline_aligned se_dev_entry_t;

typedef struct se_dev_attrib_s {
        int             status_thread;
        int             status_thread_tur;
	u32		hw_max_sectors;
        u32             max_sectors;
	u32		hw_queue_depth;
        u32             queue_depth;
        u32             task_timeout;
        struct se_subsystem_dev_s *da_sub_dev;
        struct config_group da_group;
} ____cacheline_aligned se_dev_attrib_t;

typedef struct se_subsystem_dev_s {
        struct se_hba_s *se_dev_hba;
        struct se_device_s *se_dev_ptr;
        se_dev_attrib_t se_dev_attrib;
        spinlock_t      se_dev_lock;
        void            *se_dev_su_ptr;
        struct config_group se_dev_group;
} ____cacheline_aligned se_subsystem_dev_t;

typedef struct se_device_s {
	__u8			type;		/* Type of disk transport used for device */
	__u8			thread_active;	/* Set to 1 if thread is NOT sleeping on thread_sem */
	__u8			dev_status_timer_flags;
	__u32			dev_flags;
	__u32			dev_status;
	__u32			dev_tcq_window_closed;
	__u32			queue_depth;	/* Physical device queue depth */
	unsigned long long		dev_sectors_total;
	void 			*dev_ptr; 	/* Pointer to transport specific device structure */
#ifdef SNMP_SUPPORT
	__u32			dev_index;
	__u32			dev_port_count;
	__u64			creation_time;
	__u32			num_resets;
	__u64			num_cmds;
	__u64			read_bytes;
	__u64			write_bytes;
	spinlock_t		stats_lock;
#endif /* SNMP_SUPPORT */
	atomic_t		active_cmds;	/* Active commands on this virtual iSCSI device */
	atomic_t		depth_left;
	atomic_t		dev_tur_active;
	atomic_t		execute_tasks;
	atomic_t		dev_status_thr_count;
	struct se_obj_s		dev_obj;
	struct se_obj_s		dev_access_obj;
	struct se_obj_s		dev_export_obj;
	struct se_obj_s		dev_feature_obj;
	se_queue_obj_t		*dev_queue_obj;
	se_queue_obj_t		*dev_status_queue_obj;
	spinlock_t		execute_task_lock;
	spinlock_t		state_task_lock;
	spinlock_t		dev_state_lock;
	spinlock_t		dev_status_lock;
	spinlock_t		dev_status_thr_lock;
	spinlock_t		se_port_lock;
	struct list_head	dev_sep_list;
	struct timer_list		dev_status_timer;
	struct task_struct		*process_thread; /* Pointer to descriptor for processing thread */
        pid_t                   process_thread_pid;
	struct task_struct		*dev_mgmt_thread;
	t10_wwn_t		t10_wwn;	/* T10 Inquiry and EVPD WWN Information */
	int (*write_pending)(struct se_task_s *);
	void (*dev_generate_cdb)(unsigned long long, u32 *, unsigned char *, int);
	struct se_obj_lun_type_s *dev_obj_api;
	struct se_task_s	*execute_task_head;
	struct se_task_s	*execute_task_tail;
	struct se_task_s	*state_task_head;
	struct se_task_s	*state_task_tail;
	struct se_hba_s		*se_hba;	/* Pointer to associated iSCSI HBA */
	struct se_subsystem_dev_s *se_sub_dev;
	struct se_subsystem_api_s *transport;	/* Pointer to template of function pointers for transport */ 
	struct se_device_s	*next;		/* Pointer to next device in TPG list */
	struct se_device_s	*prev;
}  ____cacheline_aligned se_device_t;

#define ISCSI_DEV(cmd)		((se_device_t *)(cmd)->se_lun->se_dev)
#define DEV_ATTRIB(dev)		(&(dev)->se_sub_dev->se_dev_attrib)
#define DEV_OBJ_API(dev)	((struct se_obj_lun_type_s *)(dev)->dev_obj_api)

typedef struct se_hba_s {
	u8			type;		/* Type of disk transport used for HBA. */
	u16			hba_tpgt;
	u32			hba_status;
	u32			hba_id;
	u32			hba_flags;
	u32			dev_count;      /* Virtual iSCSI devices attached. */
#ifdef SNMP_SUPPORT
	u32			hba_index;
#endif
	atomic_t		dev_mib_access_count;
	atomic_t		load_balance_queue;
	atomic_t		left_queue_depth;
	atomic_t		max_queue_depth; /* Maximum queue depth the HBA can handle. */
	void			*hba_ptr;	/* Pointer to transport specific host structure. */
	se_device_t		*device_head;	/* Pointer to start of devices for this HBA */
	se_device_t		*device_tail;	/* Pointer to end of devices of this HBA */
	spinlock_t		device_lock;	/* Spinlock for adding/removing devices */
	spinlock_t		hba_queue_lock;
	struct config_group	hba_group;
	struct semaphore	hba_access_sem;
	struct se_subsystem_api_s *transport;
	struct se_hba_s		*next;
	struct se_hba_s		*prev;
}  ____cacheline_aligned se_hba_t;

#define ISCSI_HBA(d)		((se_hba_t *)(d)->se_hba)
// Using SE_HBA() for new code
#define SE_HBA(d)		((se_hba_t *)(d)->se_hba)

typedef struct se_lun_s {
	int			lun_type;
	int			lun_status;
	u32			lun_access;
	u32			unpacked_lun;
	spinlock_t		lun_acl_lock;
	spinlock_t		lun_cmd_lock;
	spinlock_t		lun_reservation_lock;
	spinlock_t		lun_sep_lock;
	se_cmd_t		*lun_cmd_head;
	se_cmd_t		*lun_cmd_tail;
	se_lun_acl_t		*lun_acl_head;
	se_lun_acl_t		*lun_acl_tail;
	struct se_node_acl_s	*lun_reserved_node_acl;
	se_device_t		*se_dev;
	void			*lun_type_ptr;
	struct config_group	lun_group;
	struct se_obj_lun_type_s *lun_obj_api;
	struct se_port_s	*lun_sep;
	int (*persistent_reservation_check)(se_cmd_t *);
	int (*persistent_reservation_release)(se_cmd_t *);
	int (*persistent_reservation_reserve)(se_cmd_t *);
} ____cacheline_aligned se_lun_t;

#define ISCSI_LUN(c)            ((se_lun_t *)(c)->se_lun)
#define LUN_OBJ_API(lun)	((struct se_obj_lun_type_s *)(lun)->lun_obj_api)

typedef struct se_port_s {
#ifdef SNMP_SUPPORT
        u32             sep_index;
        scsi_port_stats_t sep_stats;
#endif
        struct se_lun_s *sep_lun;
        struct se_portal_group_s *sep_tpg;
        struct list_head sep_list;
} ____cacheline_aligned se_port_t;

typedef struct se_portal_group_s {
	int			se_tpg_type;	/* Type of target portal group */
	u32			num_node_acls;  /* Number of ACLed Initiator Nodes for this TPG */
	spinlock_t		acl_node_lock;  /* Spinlock for adding/removing ACLed Nodes */
	spinlock_t		session_lock;   /* Spinlock for adding/removing sessions */
	spinlock_t		tpg_lun_lock;
	void			*se_tpg_fabric_ptr; /* Pointer to $FABRIC_MOD portal group */
	struct list_head	se_tpg_list;
	struct se_lun_s		*tpg_lun_list;
	struct se_node_acl_s	*acl_node_head; /* Pointer to start of Initiator ACL list */
	struct se_node_acl_s	*acl_node_tail; /* Pointer to end of Initiator ACL list */
	struct list_head	tpg_sess_list;	/* List of TCM sessions assoicated wth this TPG */
	struct target_core_fabric_ops *se_tpg_tfo; /* Pointer to $FABRIC_MOD dependent code */
} ____cacheline_aligned se_portal_group_t;

#define TPG_TFO(se_tpg)		((struct target_core_fabric_ops *)(se_tpg)->se_tpg_tfo)

typedef struct se_global_s {
	u32			in_shutdown;
	struct list_head	g_se_tpg_list;
        struct se_plugin_class_s *plugin_class_list;
        se_hba_t                *hba_list;
	spinlock_t		hba_lock;
	spinlock_t		plugin_class_lock;
#ifdef DEBUG_DEV
        spinlock_t              debug_dev_lock;
#endif
} ____cacheline_aligned se_global_t;

#endif /* TARGET_CORE_BASE_H */
