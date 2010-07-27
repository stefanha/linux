/*******************************************************************************
 * Filename:  target_core_file.h
 *
 * This file contains the Storage Engine <-> FILEIO transport specific
 * definitions and prototypes.
 *
 * Copyright (c) 2005 PyX Technologies, Inc.
 * Copyright (c) 2006 SBE, Inc.  All Rights Reserved.
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


#ifndef TARGET_CORE_FILE_H
#define TARGET_CORE_FILE_H

#define FD_VERSION		"3.1"

#define FD_MAX_DEV_NAME		256
/* Maximum queuedepth for the FILEIO HBA */
#define FD_HBA_QUEUE_DEPTH	256
#define FD_DEVICE_QUEUE_DEPTH	32
#define FD_MAX_DEVICE_QUEUE_DEPTH 128
#define FD_BLOCKSIZE		512
#define FD_MAX_SECTORS		1024

#define FD_DATA_READ		1
#define FD_DATA_WRITE		2
#define FD_DATA_NONE		3

extern struct se_global *se_global;
extern struct block_device *__linux_blockdevice_claim(int, int, void *, int *);
extern struct block_device *linux_blockdevice_claim(int, int, void *);
extern int linux_blockdevice_release(int, int, struct block_device *);
extern int linux_blockdevice_check(int, int);

#ifndef FD_INCLUDE_STRUCTS
extern int fd_CDB_inquiry(struct se_task *, u32);
extern int fd_CDB_none(struct se_task *, u32);
extern int fd_CDB_read_non_SG(struct se_task *, u32);
extern int fd_CDB_read_SG(struct se_task *, u32);
extern int fd_CDB_write_non_SG(struct se_task *, u32);
extern int fd_CDB_write_SG(struct se_task *, u32);

extern int fd_attach_hba(struct se_hba *, u32);
extern int fd_detach_hba(struct se_hba *);
extern int fd_claim_phydevice(struct se_hba *, struct se_device *);
extern int fd_release_phydevice(struct se_device *);
extern void *fd_allocate_virtdevice(struct se_hba *, const char *);
extern struct se_device *fd_create_virtdevice(struct se_hba *, struct se_subsystem_dev *,
					void *);
extern int fd_activate_device(struct se_device *);
extern void fd_deactivate_device(struct se_device *);
extern void fd_free_device(void *);
extern int fd_transport_complete(struct se_task *);
extern void *fd_allocate_request(struct se_task *, struct se_device *);
extern int fd_do_task(struct se_task *);
extern void fd_free_task(struct se_task *);
extern ssize_t fd_set_configfs_dev_params(struct se_hba *, struct se_subsystem_dev *,
					const char *, ssize_t);
extern ssize_t fd_check_configfs_dev_params(struct se_hba *, struct se_subsystem_dev *);
extern ssize_t fd_show_configfs_dev_params(struct se_hba *, struct se_subsystem_dev *,
					char *);
extern void fd_get_plugin_info(void *, char *, int *);
extern void fd_get_hba_info(struct se_hba *, char *, int *);
extern void fd_get_dev_info(struct se_device *, char *, int *);
extern int fd_check_lba(unsigned long long, struct se_device *);
extern int fd_check_for_SG(struct se_task *);
extern unsigned char *fd_get_cdb(struct se_task *);
extern u32 fd_get_blocksize(struct se_device *);
extern u32 fd_get_device_rev(struct se_device *);
extern u32 fd_get_device_type(struct se_device *);
extern u32 fd_get_dma_length(u32, struct se_device *);
extern u32 fd_get_max_sectors(struct se_device *);
extern u32 fd_get_queue_depth(struct se_device *);
extern u32 fd_get_max_queue_depth(struct se_device *);
#endif /* ! FD_INCLUDE_STRUCTS */

#define RRF_EMULATE_CDB		0x01
#define RRF_GOT_LBA		0x02

struct fd_request {
	/* SCSI CDB from iSCSI Command PDU */
	unsigned char	fd_scsi_cdb[SCSI_CDB_SIZE];
	/* Data Direction */
	u8		fd_data_direction;
	/* Total length of request */
	u32		fd_bufflen;
	/* RD request flags */
	u32		fd_req_flags;
	/* Offset from start of page */
	u32		fd_offset;
	u32		fd_cur_size;
	u32		fd_cur_offset;
	/* Scatterlist count */
	u32		fd_sg_count;
	/* Logical Block Address */
	unsigned long long	fd_lba;
	u64		fd_size;
	struct kiocb	fd_iocb;
	struct iovec	*fd_iovs;
	/* Data buffer containing scatterlists(s) or contingous
	   memory segments */
	void		*fd_buf;
	/* FILEIO device */
	struct fd_dev	*fd_dev;
} ____cacheline_aligned;

#define FBDF_HAS_PATH		0x01
#define FBDF_HAS_SIZE		0x02
#define FDBD_USE_BUFFERED_IO	0x04

struct fd_dev {
	u32		fbd_flags;
	unsigned char	fd_dev_name[FD_MAX_DEV_NAME];
	int		fd_claim_bd;
	int		fd_major;
	int		fd_minor;
	/* Unique Ramdisk Device ID in Ramdisk HBA */
	u32		fd_dev_id;
	/* Number of SG tables in sg_table_array */
	u32		fd_table_count;
	u32		fd_queue_depth;
	unsigned long long fd_dev_size;
	struct file	*fd_file;
	struct block_device *fd_bd;
	/* FILEIO HBA device is connected to */
	struct fd_host *fd_host;
	int (*fd_do_read)(struct fd_request *, struct se_task *);
	int (*fd_do_write)(struct fd_request *, struct se_task *);
} ____cacheline_aligned;

extern void __fd_get_dev_info(struct fd_dev *, char *, int *);

struct fd_host {
	u32		fd_host_dev_id_count;
	/* Unique FILEIO Host ID */
	u32		fd_host_id;
} ____cacheline_aligned;

#ifndef FD_INCLUDE_STRUCTS
/*
 * We use the generic command sequencer, so we must setup
 * struct se_subsystem_spc.
 */
struct se_subsystem_spc fileio_template_spc = {
	.inquiry		= fd_CDB_inquiry,
	.none			= fd_CDB_none,
	.read_non_SG		= fd_CDB_read_non_SG,
	.read_SG		= fd_CDB_read_SG,
	.write_non_SG		= fd_CDB_write_non_SG,
	.write_SG		= fd_CDB_write_SG,
};

/*#warning FIXME v2.8: transport_type for FILEIO will need to change
  with DIRECT_IO to blockdevs */

struct se_subsystem_api fileio_template = {
	.name			= "fileio",
	.type			= FILEIO,
	.transport_type		= TRANSPORT_PLUGIN_VHBA_PDEV,
	.attach_hba		= fd_attach_hba,
	.detach_hba		= fd_detach_hba,
	.claim_phydevice	= fd_claim_phydevice,
	.release_phydevice	= fd_release_phydevice,
	.allocate_virtdevice	= fd_allocate_virtdevice,
	.create_virtdevice	= fd_create_virtdevice,
	.activate_device	= fd_activate_device,
	.deactivate_device	= fd_deactivate_device,
	.free_device		= fd_free_device,
	.transport_complete	= fd_transport_complete,
	.allocate_request	= fd_allocate_request,
	.do_task		= fd_do_task,
	.free_task		= fd_free_task,
	.check_configfs_dev_params = fd_check_configfs_dev_params,
	.set_configfs_dev_params = fd_set_configfs_dev_params,
	.show_configfs_dev_params = fd_show_configfs_dev_params,
	.get_plugin_info	= fd_get_plugin_info,
	.get_hba_info		= fd_get_hba_info,
	.get_dev_info		= fd_get_dev_info,
	.check_lba		= fd_check_lba,
	.check_for_SG		= fd_check_for_SG,
	.get_cdb		= fd_get_cdb,
	.get_blocksize		= fd_get_blocksize,
	.get_device_rev		= fd_get_device_rev,
	.get_device_type	= fd_get_device_type,
	.get_dma_length		= fd_get_dma_length,
	.get_max_sectors	= fd_get_max_sectors,
	.get_queue_depth	= fd_get_queue_depth,
	.get_max_queue_depth	= fd_get_max_queue_depth,
	.write_pending		= NULL,
	.spc			= &fileio_template_spc,
};

#endif /* ! FD_INCLUDE_STRUCTS */

#endif /* TARGET_CORE_FILE_H */
