/*********************************************************************************
 * Filename:  iscsi_target_iblock.h
 *
 * Copyright (c) 2003, 2004, 2005 PyX Technologies, Inc.
 * Copyright (c) 2005, 2006, 2007 SBE, Inc. 
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


#ifndef ISCSI_TARGET_IBLOCK_H
#define ISCSI_TARGET_IBLOCK_H

#define IBLOCK_VERSION		"v3.0"

#define IBLOCK_BLOCKSIZE	512
#define IBLOCK_MAX_SECTORS	128
#define IBLOCK_HBA_QUEUE_DEPTH	512
#define IBLOCK_DEVICE_QUEUE_DEPTH	32
#define IBLOCK_MAX_CDBS		16
#define IBLOCK_LBA_SHIFT	9

#ifndef IBLOCK_INCLUDE_STRUCTS
extern int iblock_CDB_inquiry (se_task_t *, u32);
extern int iblock_CDB_none (se_task_t *, u32);
extern int iblock_CDB_read_non_SG (se_task_t *, u32);
extern int iblock_CDB_read_SG (se_task_t *, u32);
extern int iblock_CDB_write_non_SG (se_task_t *, u32);
extern int iblock_CDB_write_SG (se_task_t *, u32);

extern int iblock_attach_hba (iscsi_portal_group_t *, se_hba_t *, iscsi_hbainfo_t *);
extern int iblock_detach_hba (se_hba_t *);
extern int iblock_claim_phydevice (se_hba_t *, se_device_t *);
extern int iblock_release_phydevice (se_device_t *);
extern int iblock_create_virtdevice (se_hba_t *, iscsi_devinfo_t *);
extern int iblock_activate_device (se_device_t *);
extern void iblock_deactivate_device (se_device_t *);
extern int iblock_check_device_location (se_device_t *, iscsi_dev_transport_info_t *);
extern int iblock_check_ghost_id (iscsi_hbainfo_t *);
extern void iblock_free_device (se_device_t *);
extern int iblock_transport_complete (se_task_t *);
extern void *iblock_allocate_request (se_task_t *, se_device_t *);
extern void iblock_get_evpd_prod (unsigned char *, u32, se_device_t *);
extern void iblock_get_evpd_sn (unsigned char *, u32, se_device_t *);
extern int iblock_do_task (se_task_t *);
extern void iblock_free_task (se_task_t *);
extern int iblock_check_hba_params (iscsi_hbainfo_t *, struct iscsi_target *, int);
extern int iblock_check_dev_params (se_hba_t *, struct iscsi_target *, iscsi_dev_transport_info_t *);
extern int iblock_check_virtdev_params (iscsi_devinfo_t *di, struct iscsi_target *);
extern void iblock_get_plugin_info (void *, char *, int *);
extern void iblock_get_hba_info (se_hba_t *, char *, int *);
extern void iblock_get_dev_info (se_device_t *, char *, int *);
extern int iblock_check_lba (unsigned long long, se_device_t *);
extern int iblock_check_for_SG (se_task_t *);
extern unsigned char *iblock_get_cdb (se_task_t *);
extern u32 iblock_get_blocksize (se_device_t *);
extern u32 iblock_get_device_rev (se_device_t *);
extern u32 iblock_get_device_type (se_device_t *);
extern u32 iblock_get_dma_length (u32, se_device_t *);
extern u32 iblock_get_max_sectors (se_device_t *);
extern u32 iblock_get_queue_depth (se_device_t *);
extern unsigned char *iblock_get_non_SG (se_task_t *);
extern struct scatterlist *iblock_get_SG (se_task_t *);
extern u32 iblock_get_SG_count (se_task_t *);
extern int iblock_set_non_SG_buf (unsigned char *, se_task_t *);
extern void iblock_bio_done (struct bio *, int);
#endif /* ! IBLOCK_INCLUDE_STRUCTS */

typedef struct iblock_req_s {
	unsigned char ib_scsi_cdb[SCSI_CDB_SIZE];
	atomic_t ib_bio_cnt;
	u32	ib_sg_count;
	void	*ib_buf;
	struct bio *ib_bio;
	struct iblock_dev_s *ib_dev;
} ____cacheline_aligned iblock_req_t;

#define IBDF_HAS_MD_UUID		0x01
#define IBDF_HAS_LVM_UUID		0x02

typedef struct iblock_dev_s {
	unsigned char ibd_lvm_uuid[SE_LVM_UUID_LEN];
	int	ibd_major;
	int	ibd_minor;
	u32	ibd_depth;
	u32	ibd_flags;
	u32	ibd_uu_id[4];
	struct bio_set	*ibd_bio_set;
	struct block_device *ibd_bd;
	struct iblock_hba_s *ibd_host;
} ____cacheline_aligned iblock_dev_t;

typedef struct iblock_hba_s {
	int		iblock_host_id;
} ____cacheline_aligned iblock_hba_t;

#ifndef IBLOCK_INCLUDE_STRUCTS
/*
 * We use the generic command sequencer, so we must setup
 * se_subsystem_spc_t.
 */
#define ISCSI_IBLOCK_SPC { \
	inquiry:		iblock_CDB_inquiry,		\
	none:			iblock_CDB_none,		\
	read_non_SG:		iblock_CDB_read_non_SG,		\
	read_SG:		iblock_CDB_read_SG,		\
	write_non_SG:		iblock_CDB_write_non_SG,	\
	write_SG:		iblock_CDB_write_SG,		\
};

se_subsystem_spc_t iblock_template_spc = ISCSI_IBLOCK_SPC;

#define ISCSI_IBLOCK { \
	name:			"iblock",			\
	type:			IBLOCK,				\
	transport_type:		TRANSPORT_PLUGIN_VHBA_PDEV,	\
	attach_hba:		iblock_attach_hba,		\
	detach_hba:		iblock_detach_hba,		\
	claim_phydevice:	iblock_claim_phydevice,		\
	create_virtdevice:	iblock_create_virtdevice,	\
	activate_device:	iblock_activate_device,		\
	deactivate_device:	iblock_deactivate_device,	\
	check_device_location:	iblock_check_device_location,	\
	check_ghost_id:		iblock_check_ghost_id,		\
	free_device:		iblock_free_device,		\
	release_phydevice:	iblock_release_phydevice,	\
	transport_complete:	iblock_transport_complete,	\
	allocate_request:	iblock_allocate_request,	\
	do_task:		iblock_do_task,			\
	free_task:		iblock_free_task,		\
	check_hba_params:	iblock_check_hba_params,	\
	check_dev_params:	iblock_check_dev_params,	\
	check_virtdev_params:	iblock_check_virtdev_params,	\
	get_plugin_info:	iblock_get_plugin_info,		\
	get_hba_info:		iblock_get_hba_info,		\
	get_dev_info:		iblock_get_dev_info,		\
	check_lba:		iblock_check_lba,		\
	check_for_SG:		iblock_check_for_SG,		\
	get_cdb:		iblock_get_cdb,			\
	get_blocksize:		iblock_get_blocksize,		\
	get_device_rev:		iblock_get_device_rev,		\
	get_device_type:	iblock_get_device_type,		\
	get_dma_length:		iblock_get_dma_length,		\
	get_evpd_prod:		iblock_get_evpd_prod,		\
	get_evpd_sn:		iblock_get_evpd_sn,		\
	get_max_sectors:	iblock_get_max_sectors,		\
	get_queue_depth:	iblock_get_queue_depth,		\
	get_non_SG:		iblock_get_non_SG,		\
	get_SG:			iblock_get_SG,			\
	get_SG_count:		iblock_get_SG_count,		\
	set_non_SG_buf:		iblock_set_non_SG_buf,		\
	write_pending:		NULL,				\
	spc:			&iblock_template_spc,		\
};

se_subsystem_api_t iblock_template = ISCSI_IBLOCK;
#endif /* IBLOCK_INCLUDE_STRUCTS */

#endif /* ISCSI_TARGET_IBLOCK_H */
