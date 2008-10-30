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

#include <iscsi_target_version.h>	    /* get version definition */

#define SCSI_CDB_SIZE			16 /* SCSI Command Descriptor Block Size a la SCSI's MAX_COMMAND_SIZE */

/* se_dev_attrib_t sanity values */
#define DA_TASK_TIMEOUT_MAX		600 /* 10 Minutes, see transport_get_default_task_timeout()  */
#define DA_STATUS_THREAD		1 /* Enabled by default */
#define DA_STATUS_THREAD_TUR		1 /* Enabled by default */
#define DA_STATUS_MAX_SECTORS_MIN	16
#define DA_STATUS_MAX_SECTORS_MAX	8192

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

/* se_hba_t->hba_flags */
#define HBA_FLAGS_INTERNAL_USE			0x00000001

/* se_hba_t->hba_status and iscsi_tpg_hba->thba_status */
#define HBA_STATUS_FREE				0x00000001
#define HBA_STATUS_ACTIVE			0x00000002
#define HBA_STATUS_INACTIVE			0x00000004

/* se_lun_t->lun_status */
#define ISCSI_LUN_STATUS_FREE			0
#define ISCSI_LUN_STATUS_ACTIVE			1

/* se_lun_t->lun_type */
#define ISCSI_LUN_TYPE_NONE			0
#define ISCSI_LUN_TYPE_DEVICE			1

/* Special transport agnostic iscsi_cmd_t->t_states */
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
#define ISCSI_LUNFLAGS_NO_ACCESS		0x00000000
#define ISCSI_LUNFLAGS_INITIATOR_ACCESS		0x00000001
#define ISCSI_LUNFLAGS_READ_ONLY		0x00000002
#define ISCSI_LUNFLAGS_READ_WRITE		0x00000004

/* se_device_t->dev_status */
#define ISCSI_DEVICE_ACTIVATED			0x01
#define	ISCSI_DEVICE_DEACTIVATED		0x02
#define ISCSI_DEVICE_QUEUE_FULL			0x04
#define	ISCSI_DEVICE_SHUTDOWN			0x08
#define ISCSI_DEVICE_OFFLINE_ACTIVATED		0x10
#define ISCSI_DEVICE_OFFLINE_DEACTIVATED	0x20

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
} se_obj_t;

typedef struct t10_wwn_s {
        unsigned char vendor[8];
        unsigned char model[16];
	unsigned char revision[4];
        unsigned char unit_serial[INQUIRY_EVPD_SERIAL_LEN];
	u32 device_identifier_code_set;
	unsigned char device_identifier[INQUIRY_EVPD_DEVICE_IDENTIFIER_LEN];
} t10_wwn_t;

typedef struct se_queue_obj_s {
	spinlock_t		cmd_queue_lock;
	iscsi_queue_req_t	*queue_head;
	iscsi_queue_req_t	*queue_tail;
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
	struct iscsi_cmd_s	*t_task_pt_cmd;
	struct list_head	t_task_list;
	struct list_head	*t_mem_list;
} ____cacheline_aligned se_transport_task_t;

typedef struct se_task_s {
        unsigned char   task_sense;
        unsigned char   *task_buf;
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
        iscsi_cmd_t     *iscsi_cmd;
        struct se_device_s     *iscsi_dev;
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

typedef struct se_transform_info_s {
        int             ti_set_counts;
        u32             ti_data_length;
        unsigned long long      ti_lba;
        struct iscsi_cmd_s *ti_cmd;
        struct se_device_s *ti_dev;
        void *se_obj_ptr;
        void *ti_obj_ptr;
        struct se_obj_lun_type_s *se_obj_api;
        struct se_obj_lun_type_s *ti_obj_api;
} ____cacheline_aligned se_transform_info_t;


struct se_device_s;
struct se_transform_info_s;
struct se_obj_lun_type_s;
struct scatterlist;

typedef struct se_lun_acl_s {
	char			initiatorname[ISCSI_IQN_LEN];
	u32			mapped_lun;
	struct se_lun_s		*iscsi_lun;
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
	struct se_lun_s		*iscsi_lun;
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
	struct se_hba_s		*iscsi_hba;	/* Pointer to associated iSCSI HBA */
	struct se_subsystem_dev_s *se_sub_dev;
	struct se_subsystem_api_s *transport;	/* Pointer to template of function pointers for transport */ 
	struct se_device_s	*next;		/* Pointer to next device in TPG list */
	struct se_device_s	*prev;
}  ____cacheline_aligned se_device_t;

#define ISCSI_DEV(cmd)		((se_device_t *)(cmd)->iscsi_lun->iscsi_dev)
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

#define ISCSI_HBA(d)		((se_hba_t *)(d)->iscsi_hba)
// Using SE_HBA() for new code
#define SE_HBA(d)		((se_hba_t *)(d)->iscsi_hba)

typedef struct se_lun_s {
	int			lun_type;
	int			lun_status;
	u32			lun_access;
	u32			iscsi_lun;
	spinlock_t		lun_acl_lock;
	spinlock_t		lun_cmd_lock;
	spinlock_t		lun_reservation_lock;
	spinlock_t		lun_sep_lock;
	iscsi_cmd_t		*lun_cmd_head;
	iscsi_cmd_t		*lun_cmd_tail;
	se_lun_acl_t		*lun_acl_head;
	se_lun_acl_t		*lun_acl_tail;
	struct iscsi_node_acl_s *lun_reserved_node_acl;
	se_device_t		*iscsi_dev;
	void			*lun_type_ptr;
	struct config_group	lun_group;
	struct se_obj_lun_type_s *lun_obj_api;
	struct se_port_s	*lun_sep;
	int (*persistent_reservation_check)(iscsi_cmd_t *);
	int (*persistent_reservation_release)(iscsi_cmd_t *);
	int (*persistent_reservation_reserve)(iscsi_cmd_t *);
} ____cacheline_aligned se_lun_t;

#define ISCSI_LUN(c)            ((se_lun_t *)(c)->iscsi_lun)
#define LUN_OBJ_API(lun)	((struct se_obj_lun_type_s *)(lun)->lun_obj_api)

typedef struct se_port_s {
#ifdef SNMP_SUPPORT
        u32             sep_index;
        scsi_port_stats_t sep_stats;
#endif
        struct se_lun_s *sep_lun;
        struct iscsi_portal_group_s *sep_tpg;
        struct list_head sep_list;
} se_port_t;

typedef struct se_global_s {
	u32			in_shutdown;
        struct se_plugin_class_s *plugin_class_list;
        se_hba_t                *hba_list;
	spinlock_t		hba_lock;
	spinlock_t		plugin_class_lock;
#ifdef DEBUG_DEV
        spinlock_t              debug_dev_lock;
#endif
} se_global_t;

#endif /* TARGET_CORE_BASE_H */
