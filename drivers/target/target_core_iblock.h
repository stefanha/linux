/*******************************************************************************
 * Filename:  target_core_iblock.h
 *
 * Copyright (c) 2003, 2004, 2005 PyX Technologies, Inc.
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


#ifndef TARGET_CORE_IBLOCK_H
#define TARGET_CORE_IBLOCK_H

#define IBLOCK_VERSION		"4.0"

#define IBLOCK_HBA_QUEUE_DEPTH	512
#define IBLOCK_DEVICE_QUEUE_DEPTH	32
#define IBLOCK_MAX_DEVICE_QUEUE_DEPTH	128
#define IBLOCK_MAX_CDBS		16
#define IBLOCK_LBA_SHIFT	9

extern struct se_global *se_global;

void __init iblock_subsystem_init(void);

struct iblock_req {
	unsigned char ib_scsi_cdb[SCSI_CDB_SIZE];
	atomic_t ib_bio_cnt;
	u32	ib_sg_count;
	void	*ib_buf;
	struct bio *ib_bio;
	struct iblock_dev *ib_dev;
} ____cacheline_aligned;

#define IBDF_HAS_UDEV_PATH		0x01
#define IBDF_HAS_MAJOR			0x02
#define IBDF_HAS_MINOR			0x04
#define IBDF_HAS_FORCE			0x08

struct iblock_dev {
	unsigned char ibd_udev_path[SE_UDEV_PATH_LEN];
	int	ibd_force;
	int	ibd_major;
	int	ibd_minor;
	u32	ibd_depth;
	u32	ibd_flags;
	struct bio_set	*ibd_bio_set;
	struct block_device *ibd_bd;
	struct iblock_hba *ibd_host;
} ____cacheline_aligned;

struct iblock_hba {
	int		iblock_host_id;
} ____cacheline_aligned;

#endif /* TARGET_CORE_IBLOCK_H */
