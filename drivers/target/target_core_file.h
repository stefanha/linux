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

void __init fileio_subsystem_init(void);

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

struct fd_host {
	u32		fd_host_dev_id_count;
	/* Unique FILEIO Host ID */
	u32		fd_host_id;
} ____cacheline_aligned;

#endif /* TARGET_CORE_FILE_H */
