/*********************************************************************************
 * Filename:  iscsi_target_file.h
 *
 * This file contains the iSCSI <-> FILEIO transport specific definitions and prototypes.
 *
 * Copyright (c) 2005 PyX Technologies, Inc.
 * Copyright (c) 2006 SBE, Inc.  All Rights Reserved.
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


#ifndef ISCSI_TARGET_FILE_H
#define ISCSI_TARGET_FILE_H

#define FD_VERSION		"v3.0"

#define FD_MAX_DEV_NAME		256
#define FD_HBA_QUEUE_DEPTH	256		/* Maximum queuedepth for the FILEIO HBA */
#define FD_DEVICE_QUEUE_DEPTH	32
#define FD_BLOCKSIZE		512
#define FD_MAX_SECTORS		1024

#define FD_DATA_READ		1
#define FD_DATA_WRITE		2
#define FD_DATA_NONE		3

#ifndef FD_INCLUDE_STRUCTS
extern int fd_CDB_inquiry (se_task_t *, u32);
extern int fd_CDB_none (se_task_t *, u32);
extern int fd_CDB_read_non_SG (se_task_t *, u32);
extern int fd_CDB_read_SG (se_task_t *, u32);
extern int fd_CDB_write_non_SG (se_task_t *, u32);
extern int fd_CDB_write_SG (se_task_t *, u32);

extern int fd_attach_hba (iscsi_portal_group_t *, se_hba_t *, iscsi_hbainfo_t *);
extern int fd_detach_hba (se_hba_t *);
extern int fd_claim_phydevice (se_hba_t *, se_device_t *);
extern int fd_release_phydevice (se_device_t *);
extern int fd_create_virtdevice (se_hba_t *, iscsi_devinfo_t *);
extern int fd_activate_device (se_device_t *);
extern void fd_deactivate_device (se_device_t *);
extern int fd_check_device_location (se_device_t *, iscsi_dev_transport_info_t *);
extern int fd_check_ghost_id (iscsi_hbainfo_t *);
extern void fd_free_device (se_device_t *);
extern se_device_t *fd_add_device_to_list (se_hba_t *, void *, iscsi_devinfo_t *);
extern int fd_transport_complete (se_task_t *);
extern void *fd_allocate_request (se_task_t *, se_device_t *);
extern void fd_get_evpd_prod (unsigned char *, u32, se_device_t *);
extern void fd_get_evpd_sn (unsigned char *, u32, se_device_t *);
extern int fd_do_task (se_task_t *);
extern void fd_free_task (se_task_t *);
extern int fd_check_hba_params (iscsi_hbainfo_t *, struct iscsi_target *, int);
extern int fd_check_dev_params (se_hba_t *, struct iscsi_target *, iscsi_dev_transport_info_t *);
extern int fd_check_virtdev_params (iscsi_devinfo_t *, struct iscsi_target *);
extern void fd_get_plugin_info (void *, char *, int *);
extern void fd_get_hba_info (se_hba_t *, char *, int *);
extern void fd_get_dev_info (se_device_t *, char *, int *);
extern int fd_check_lba (unsigned long long, se_device_t *);
extern int fd_check_for_SG (se_task_t *);
extern unsigned char *fd_get_cdb (se_task_t *);
extern u32 fd_get_blocksize (se_device_t *);
extern u32 fd_get_device_rev (se_device_t *);
extern u32 fd_get_device_type (se_device_t *);
extern u32 fd_get_dma_length (u32, se_device_t *);
extern u32 fd_get_max_sectors (se_device_t *);
extern u32 fd_get_queue_depth (se_device_t *);
extern unsigned char *fd_get_non_SG (se_task_t *);
extern struct scatterlist *fd_get_SG (se_task_t *);
extern u32 fd_get_SG_count (se_task_t *);
extern int fd_set_non_SG_buf (unsigned char *, se_task_t *);
#endif /* ! FD_INCLUDE_STRUCTS */

#define RRF_EMULATE_CDB		0x01
#define RRF_GOT_LBA		0x02

typedef struct fd_request_s {
	unsigned char	fd_scsi_cdb[SCSI_CDB_SIZE]; /* SCSI CDB from iSCSI Command PDU */
	u8		fd_data_direction;	/* Data Direction */
	u32		fd_bufflen;		/* Total length of request */
	u32		fd_req_flags;		/* RD request flags */
	u32		fd_offset;		/* Offset from start of page */
	u32		fd_cur_size;
	u32		fd_cur_offset;
	u32		fd_sg_count;		/* Scatterlist count */
	unsigned long long	fd_lba;			/* Logical Block Address */
	u64		fd_size;
	struct kiocb	fd_iocb;
	struct iovec	*fd_iovs;
	void		*fd_buf;		/* Data buffer containing scatterlists(s) or contingous memory segments. */
	struct fd_dev_s	*fd_dev;		/* FILEIO device */
} ____cacheline_aligned fd_request_t;

typedef struct fd_dev_sg_table_s {
	u32		page_start_offset;
	u32		page_end_offset;
	u32		fd_sg_count;
	struct scatterlist *sg_table;
} ____cacheline_aligned fd_dev_sg_table_t;

#define FBDF_HAS_MD_UUID	0x01
#define FBDF_HAS_LVM_UUID	0x02

typedef struct fd_dev_s {
	unsigned char	fbd_lvm_uuid[SE_LVM_UUID_LEN];
	u32		fbd_uu_id[4];
	u32		fbd_flags;
	unsigned char	fd_dev_name[FD_MAX_DEV_NAME];
	int		fd_claim_bd;
	int		fd_major;
	int		fd_minor;
	u32		fd_dev_id;		/* Unique Ramdisk Device ID in Ramdisk HBA */
	u32		fd_table_count;		/* Number of SG tables in sg_table_array */
	u32		fd_queue_depth;
	unsigned long long fd_dev_size;
	struct file	*fd_file;
	struct block_device *fd_bd;
	struct fd_host_s *fd_host;		/* FILEIO HBA device is connected to */
	struct fd_dev_s *next;			/* Next FILEIO Device entry in list */
} ____cacheline_aligned fd_dev_t;

typedef struct fd_host_s {
	u32		fd_host_id;		/* Unique FILEIO Host ID */
} ____cacheline_aligned fd_host_t;

#ifndef FD_INCLUDE_STRUCTS
/*
 * We use the generic command sequencer, so we must setup
 * iscsi_transport_spc_t.
 */
#define ISCSI_FILEIO_SPC {					\
	inquiry:		fd_CDB_inquiry,			\
	none:			fd_CDB_none,			\
	read_non_SG:		fd_CDB_read_non_SG,		\
	read_SG:		fd_CDB_read_SG,			\
	write_non_SG:		fd_CDB_write_non_SG,		\
	write_SG:		fd_CDB_write_SG,		\
};

iscsi_transport_spc_t fileio_template_spc = ISCSI_FILEIO_SPC;

//#warning FIXME v2.8: transport_type for FILEIO will need to change with DIRECT_IO to blockdevs

#define ISCSI_FILEIO {						\
	name:			"fileio",			\
	type:			FILEIO,				\
	transport_type:		TRANSPORT_PLUGIN_VHBA_PDEV,	\
	attach_hba:		fd_attach_hba,			\
	detach_hba:		fd_detach_hba,			\
	claim_phydevice:	fd_claim_phydevice,		\
	release_phydevice:	fd_release_phydevice,		\
	create_virtdevice:	fd_create_virtdevice,		\
	activate_device:	fd_activate_device,		\
	deactivate_device:	fd_deactivate_device,		\
	check_device_location:	fd_check_device_location,	\
	check_ghost_id:		fd_check_ghost_id,		\
	free_device:		fd_free_device,			\
	transport_complete:	fd_transport_complete,		\
	allocate_request:	fd_allocate_request,		\
	do_task:		fd_do_task,			\
	free_task:		fd_free_task,			\
	check_hba_params:	fd_check_hba_params,		\
	check_dev_params:	fd_check_dev_params,		\
	check_virtdev_params:	fd_check_virtdev_params,	\
	get_plugin_info:	fd_get_plugin_info,		\
	get_hba_info:		fd_get_hba_info,		\
	get_dev_info:		fd_get_dev_info,		\
	check_lba:		fd_check_lba,			\
	check_for_SG:		fd_check_for_SG,		\
	get_cdb:		fd_get_cdb,			\
	get_blocksize:		fd_get_blocksize,		\
	get_device_rev:		fd_get_device_rev,		\
	get_device_type:	fd_get_device_type,		\
	get_dma_length:		fd_get_dma_length,		\
	get_evpd_prod:		fd_get_evpd_prod,		\
	get_evpd_sn:		fd_get_evpd_sn,			\
	get_max_sectors:	fd_get_max_sectors,		\
	get_queue_depth:	fd_get_queue_depth,		\
	get_non_SG:		fd_get_non_SG,			\
	get_SG:			fd_get_SG,			\
	get_SG_count:		fd_get_SG_count,		\
	set_non_SG_buf:		fd_set_non_SG_buf,		\
	write_pending:		NULL,				\
	spc:			&fileio_template_spc,		\
};
	
iscsi_transport_t fileio_template = ISCSI_FILEIO;
#endif /* ! FD_INCLUDE_STRUCTS */

#endif /* ISCSI_TARGET_FILE_H */
