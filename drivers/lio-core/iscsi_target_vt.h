/*********************************************************************************
 * Filename:  iscsi_target_vt.h
 *
 * This file contains the iSCSI <-> VTAPE transport specific definitions and prototypes.
 *
 * Copyright (c) 2006-2007 SBE, Inc.  All Rights Reserved.
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


#ifndef ISCSI_TARGET_VT_H
#define ISCSI_TARGET_VT_H

#define VT_VERSION		"v0.1"

#define VT_MAX_DEV_NAME		256
#define VT_HBA_QUEUE_DEPTH	256		/* Maximum queuedepth for the VTAPE HBA */
#define VT_DEVICE_QUEUE_DEPTH	32
#define VT_BLOCKSIZE		512
#define VT_MAX_SECTORS		1024

#define VT_DATA_READ		1
#define VT_DATA_WRITE		2
#define VT_DATA_NONE		3

#ifndef VT_INCLUDE_STRUCTS
extern int vt_CDB_inquiry (se_task_t *, u32);
extern int vt_CDB_none (se_task_t *, u32);
extern int vt_CDB_read_non_SG (se_task_t *, u32);
extern int vt_CDB_read_SG (se_task_t *, u32);
extern int vt_CDB_write_non_SG (se_task_t *, u32);
extern int vt_CDB_write_SG (se_task_t *, u32);

extern int vt_attach_hba (iscsi_portal_group_t *, iscsi_hba_t *, iscsi_hbainfo_t *);
extern int vt_detach_hba (iscsi_hba_t *);
extern int vt_create_virtdevice (iscsi_hba_t *, iscsi_devinfo_t *);
extern int vt_activate_device (se_device_t *);
extern void vt_deactivate_device (se_device_t *);
extern int vt_check_device_location (se_device_t *, iscsi_dev_transport_info_t *);
extern int vt_check_ghost_id (iscsi_hbainfo_t *);
extern void vt_free_device (se_device_t *);
extern se_device_t *vt_add_device_to_list (iscsi_hba_t *, void *);
extern int vt_transport_complete (se_task_t *);
extern void *vt_allocate_request (se_task_t *, se_device_t *);
extern void vt_get_evpd_prod (unsigned char *, u32, se_device_t *);
extern void vt_get_evpd_sn (unsigned char *, u32, se_device_t *);
extern int vt_do_task (se_task_t *);
extern void vt_free_task (se_task_t *);
extern int vt_check_hba_params (iscsi_hbainfo_t *, struct iscsi_target *, int);
extern int vt_check_dev_params (iscsi_hba_t *, struct iscsi_target *, iscsi_dev_transport_info_t *);
extern int vt_check_virtdev_params (iscsi_devinfo_t *, struct iscsi_target *);
extern void vt_get_plugin_info (void *, char *, int *);
extern void vt_get_hba_info (iscsi_hba_t *, char *, int *);
extern void vt_get_dev_info (se_device_t *, char *, int *);
extern int vt_check_lba (unsigned long long, se_device_t *);
extern int vt_check_for_SG (se_task_t *);
extern unsigned char *vt_get_cdb (se_task_t *);
extern u32 vt_get_blocksize (se_device_t *);
extern u32 vt_get_device_rev (se_device_t *);
extern u32 vt_get_device_type (se_device_t *);
extern u32 vt_get_dma_length (u32, se_device_t *);
extern u32 vt_get_max_sectors (se_device_t *);
extern u32 vt_get_queue_depth (se_device_t *);
extern unsigned char *vt_get_non_SG (se_task_t *);
extern struct scatterlist *vt_get_SG (se_task_t *);
extern u32 vt_get_SG_count (se_task_t *);
extern int vt_set_non_SG_buf (unsigned char *, se_task_t *);
extern unsigned char *vt_get_sense_buffer (se_task_t *);
#endif /* ! VT_INCLUDE_STRUCTS */

#define RRF_EMULATE_CDB		0x01
#define RRF_GOT_LBA		0x02

typedef struct vt_request_s {
	unsigned char	vt_scsi_cdb[SCSI_CDB_SIZE]; /* SCSI CDB from iSCSI Command PDU */
	u8		vt_data_direction;	/* Data Direction */
	u32		vt_bufflen;		/* Total length of request */
	u32		vt_req_flags;		/* RD request flags */
	u32		vt_offset;		/* Offset from start of page */
	u32		vt_sg_count;		/* Scatterlist count */
	unsigned long long	vt_lba;			/* Logical Block Address */
	u64		vt_size;
	void		*vt_buf;		/* Data buffer containing scatterlists(s) or contiguous memory segments. */
	struct vt_dev_s	*vt_dev;		/* VTAPE device */
} vt_request_t;

typedef struct vt_dev_sg_table_s {
	u32		page_start_offset;
	u32		page_end_offset;
	u32		vt_sg_count;
	struct scatterlist *sg_table;
} vt_dev_sg_table_t;

typedef struct vt_dev_s {
	u32		vt_dev_id;		/* This must be first because we cast
						between mc_dev_t and vt_dev_t to read
						the id. */
	unsigned char	vt_dev_name[VT_MAX_DEV_NAME];
	u32		vt_hw_id;		/* Hardware emulation code */
	u32		vt_table_count;		/* Number of SG tables in sg_table_array */
	u32		vt_queue_depth;
	u32		vt_mc_host_id;
	u64		vt_written;		/* number of bytes written */
	u64		vt_read_count;
	u64		vt_read_limit;
	atomic_t	vt_lock;
	unsigned long long vt_dev_size;
	struct file	*vt_file;
	struct vt_host_s *vt_host;		/* VTAPE HBA device is connected to */
	struct vt_dev_s *next;			/* Next VTAPE Device entry in list */
	int		vt_sense_flag;
	unsigned char	vt_sense_buffer[96];
} vt_dev_t;

typedef struct vt_host_s {
	u32		vt_host_id;		/* Unique VTAPE Host ID */
} vt_host_t;

#ifndef VT_INCLUDE_STRUCTS
/*
 * We use the generic command sequencer, so we must setup
 * iscsi_transport_spc_t.
 */
#define ISCSI_VTAPE_SPC {					\
	inquiry:		vt_CDB_inquiry,			\
	none:			vt_CDB_none,			\
	read_non_SG:		vt_CDB_read_non_SG,		\
	read_SG:		vt_CDB_read_SG,			\
	write_non_SG:		vt_CDB_write_non_SG,		\
	write_SG:		vt_CDB_write_SG,		\
};

iscsi_transport_spc_t vtape_template_spc = ISCSI_VTAPE_SPC;

#define ISCSI_VTAPE {						\
	name:			"vtape",			\
	type:			VTAPE,				\
	transport_type:		TRANSPORT_PLUGIN_VHBA_VDEV,	\
	attach_hba:		vt_attach_hba,			\
	detach_hba:		vt_detach_hba,			\
	create_virtdevice:	vt_create_virtdevice,		\
	activate_device:	vt_activate_device,		\
	deactivate_device:	vt_deactivate_device,		\
	check_device_location:	vt_check_device_location,	\
	check_ghost_id:		vt_check_ghost_id,		\
	free_device:		vt_free_device,			\
	transport_complete:	vt_transport_complete,		\
	allocate_request:	vt_allocate_request,		\
	do_task:		vt_do_task,			\
	free_task:		vt_free_task,			\
	check_hba_params:	vt_check_hba_params,		\
	check_dev_params:	vt_check_dev_params,		\
	check_virtdev_params:	vt_check_virtdev_params,	\
	get_plugin_info:	vt_get_plugin_info,		\
	get_hba_info:		vt_get_hba_info,		\
	get_dev_info:		vt_get_dev_info,		\
	check_lba:		vt_check_lba,			\
	check_for_SG:		vt_check_for_SG,		\
	get_cdb:		vt_get_cdb,			\
	get_blocksize:		vt_get_blocksize,		\
	get_device_rev:		vt_get_device_rev,		\
	get_device_type:	vt_get_device_type,		\
	get_dma_length:		vt_get_dma_length,		\
	get_evpd_prod:		vt_get_evpd_prod,		\
	get_evpd_sn:		vt_get_evpd_sn,			\
	get_max_sectors:	vt_get_max_sectors,		\
	get_queue_depth:	vt_get_queue_depth,		\
	get_non_SG:		vt_get_non_SG,			\
	get_SG:			vt_get_SG,			\
	get_SG_count:		vt_get_SG_count,		\
	set_non_SG_buf:		vt_set_non_SG_buf,		\
	get_sense_buffer:	vt_get_sense_buffer,		\
	spc:			&vtape_template_spc,		\
};
	
iscsi_transport_t vtape_template = ISCSI_VTAPE;
#endif /* ! VT_INCLUDE_STRUCTS */

#endif /* ISCSI_TARGET_VTAPE_H */
