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

#define IBLOCK_VERSION		"3.1"

#define IBLOCK_HBA_QUEUE_DEPTH	512
#define IBLOCK_DEVICE_QUEUE_DEPTH	32
#define IBLOCK_MAX_DEVICE_QUEUE_DEPTH	128
#define IBLOCK_MAX_CDBS		16
#define IBLOCK_LBA_SHIFT	9

extern se_global_t *se_global;

#ifndef IBLOCK_INCLUDE_STRUCTS
extern int iblock_CDB_inquiry(se_task_t *, u32);
extern int iblock_CDB_none(se_task_t *, u32);
extern int iblock_CDB_read_non_SG(se_task_t *, u32);
extern int iblock_CDB_read_SG(se_task_t *, u32);
extern int iblock_CDB_write_non_SG(se_task_t *, u32);
extern int iblock_CDB_write_SG(se_task_t *, u32);

extern int iblock_attach_hba(se_hba_t *, u32);
extern int iblock_detach_hba(se_hba_t *);
extern int iblock_claim_phydevice(se_hba_t *, se_device_t *);
extern int iblock_release_phydevice(se_device_t *);
extern void *iblock_allocate_virtdevice(se_hba_t *, const char *);
extern se_device_t *iblock_create_virtdevice(se_hba_t *, se_subsystem_dev_t *,
						void *);
extern int iblock_activate_device(se_device_t *);
extern void iblock_deactivate_device(se_device_t *);
extern void iblock_free_device(void *);
extern int iblock_transport_complete(se_task_t *);
extern void *iblock_allocate_request(se_task_t *, se_device_t *);
extern int iblock_do_task(se_task_t *);
extern void iblock_free_task(se_task_t *);
extern ssize_t iblock_set_configfs_dev_params(se_hba_t *, se_subsystem_dev_t *,
						const char *, ssize_t);
extern ssize_t iblock_check_configfs_dev_params(se_hba_t *,
						se_subsystem_dev_t *);
extern ssize_t iblock_show_configfs_dev_params(se_hba_t *, se_subsystem_dev_t *,
						char *);
extern se_device_t *iblock_create_virtdevice_from_fd(se_subsystem_dev_t *,
						const char *);
extern void iblock_get_plugin_info(void *, char *, int *);
extern void iblock_get_hba_info(se_hba_t *, char *, int *);
extern void iblock_get_dev_info(se_device_t *, char *, int *);
extern int iblock_check_lba(unsigned long long, se_device_t *);
extern int iblock_check_for_SG(se_task_t *);
extern unsigned char *iblock_get_cdb(se_task_t *);
extern u32 iblock_get_blocksize(se_device_t *);
extern u32 iblock_get_device_rev(se_device_t *);
extern u32 iblock_get_device_type(se_device_t *);
extern u32 iblock_get_dma_length(u32, se_device_t *);
extern u32 iblock_get_max_sectors(se_device_t *);
extern u32 iblock_get_queue_depth(se_device_t *);
extern u32 iblock_get_max_queue_depth(se_device_t *);
extern void iblock_bio_done(struct bio *, int);
#endif /* ! IBLOCK_INCLUDE_STRUCTS */

typedef struct iblock_req_s {
	unsigned char ib_scsi_cdb[SCSI_CDB_SIZE];
	atomic_t ib_bio_cnt;
	u32	ib_sg_count;
	void	*ib_buf;
	struct bio *ib_bio;
	struct iblock_dev_s *ib_dev;
} ____cacheline_aligned iblock_req_t;

#define IBDF_HAS_UDEV_PATH		0x01
#define IBDF_HAS_MAJOR			0x02
#define IBDF_HAS_MINOR			0x04
#define IBDF_HAS_FORCE			0x08

typedef struct iblock_dev_s {
	unsigned char ibd_udev_path[SE_UDEV_PATH_LEN];
	int	ibd_force;
	int	ibd_major;
	int	ibd_minor;
	u32	ibd_depth;
	u32	ibd_flags;
	struct bio_set	*ibd_bio_set;
	struct block_device *ibd_bd;
	struct iblock_hba_s *ibd_host;
} ____cacheline_aligned iblock_dev_t;

void __iblock_get_dev_info(iblock_dev_t *, char *, int *);

typedef struct iblock_hba_s {
	int		iblock_host_id;
} ____cacheline_aligned iblock_hba_t;

#ifndef IBLOCK_INCLUDE_STRUCTS
/*
 * We use the generic command sequencer, so we must setup
 * se_subsystem_spc_t.
 */
se_subsystem_spc_t iblock_template_spc = {
	.inquiry		= iblock_CDB_inquiry,
	.none			= iblock_CDB_none,
	.read_non_SG		= iblock_CDB_read_non_SG,
	.read_SG		= iblock_CDB_read_SG,
	.write_non_SG		= iblock_CDB_write_non_SG,
	.write_SG		= iblock_CDB_write_SG,
};

se_subsystem_api_t iblock_template = {
	.name			= "iblock",
	.type			= IBLOCK,
	.transport_type		= TRANSPORT_PLUGIN_VHBA_PDEV,
	.attach_hba		= iblock_attach_hba,
	.detach_hba		= iblock_detach_hba,
	.claim_phydevice	= iblock_claim_phydevice,
	.allocate_virtdevice	= iblock_allocate_virtdevice,
	.create_virtdevice	= iblock_create_virtdevice,
	.activate_device	= iblock_activate_device,
	.deactivate_device	= iblock_deactivate_device,
	.free_device		= iblock_free_device,
	.release_phydevice	= iblock_release_phydevice,
	.transport_complete	= iblock_transport_complete,
	.allocate_request	= iblock_allocate_request,
	.do_task		= iblock_do_task,
	.free_task		= iblock_free_task,
	.check_configfs_dev_params = iblock_check_configfs_dev_params,
	.set_configfs_dev_params = iblock_set_configfs_dev_params,
	.show_configfs_dev_params = iblock_show_configfs_dev_params,
	.create_virtdevice_from_fd = iblock_create_virtdevice_from_fd,
	.get_plugin_info	= iblock_get_plugin_info,
	.get_hba_info		= iblock_get_hba_info,
	.get_dev_info		= iblock_get_dev_info,
	.check_lba		= iblock_check_lba,
	.check_for_SG		= iblock_check_for_SG,
	.get_cdb		= iblock_get_cdb,
	.get_blocksize		= iblock_get_blocksize,
	.get_device_rev		= iblock_get_device_rev,
	.get_device_type	= iblock_get_device_type,
	.get_dma_length		= iblock_get_dma_length,
	.get_max_sectors	= iblock_get_max_sectors,
	.get_queue_depth	= iblock_get_queue_depth,
	.get_max_queue_depth	= iblock_get_max_queue_depth,
	.write_pending		= NULL,
	.spc			= &iblock_template_spc,
};

#endif /* IBLOCK_INCLUDE_STRUCTS */

#endif /* TARGET_CORE_IBLOCK_H */
