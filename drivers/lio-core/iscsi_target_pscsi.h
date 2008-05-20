/*********************************************************************************
 * Filename:  iscsi_target_pscsi.h
 *
 * This file contains the iSCSI <-> Parallel SCSI transport
 * specific definitions and prototypes.
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


#ifndef ISCSI_TARGET_PSCSI_H
#define ISCSI_TARGET_PSCSI_H

#define PSCSI_VERSION		"v2.9"

/* used in pscsi_find_alloc_len() */
#ifndef INQUIRY_DATA_SIZE
#define INQUIRY_DATA_SIZE	0x24
#endif

/* used in pscsi_add_device_to_list() */
#define PSCSI_DEFAULT_QUEUEDEPTH	1

#define PS_RETRY		5
#define PS_TIMEOUT_DISK		15*HZ
#define PS_TIMEOUT_OTHER	500*HZ

extern int pscsi_CDB_inquiry (iscsi_task_t *, u32);
extern int pscsi_CDB_none (iscsi_task_t *, u32);
extern int pscsi_CDB_read_non_SG (iscsi_task_t *, u32);
extern int pscsi_CDB_read_SG (iscsi_task_t *, u32);
extern int pscsi_CDB_write_non_SG (iscsi_task_t *, u32);
extern int pscsi_CDB_write_SG (iscsi_task_t *, u32);

#ifndef PSCSI_INCLUDE_STRUCTS
extern int pscsi_attach_hba (iscsi_portal_group_t *, iscsi_hba_t *, iscsi_hbainfo_t *);
extern int pscsi_detach_hba (iscsi_hba_t *);
extern int pscsi_scan_devices (iscsi_hba_t *, iscsi_hbainfo_t *);
extern int pscsi_claim_phydevice (iscsi_hba_t *, iscsi_device_t *);
extern int pscsi_release_phydevice (iscsi_device_t *);
extern int pscsi_activate_device (iscsi_device_t *);
extern void pscsi_deactivate_device (iscsi_device_t *);
extern iscsi_device_t *pscsi_add_device_to_list (iscsi_hba_t *, struct scsi_device *, int);
extern int pscsi_check_device_location (iscsi_device_t *, iscsi_dev_transport_info_t *);
extern int pscsi_check_ghost_id (iscsi_hbainfo_t *);
extern void pscsi_free_device (iscsi_device_t *);
extern int pscsi_transport_complete (iscsi_task_t *);
extern void *pscsi_allocate_request (iscsi_task_t *, iscsi_device_t *);
extern void pscsi_get_evpd_prod (unsigned char *, u32, iscsi_device_t *);
extern void pscsi_get_evpd_sn (unsigned char *, u32, iscsi_device_t *);
extern int pscsi_do_task (iscsi_task_t *);
extern void pscsi_free_task (iscsi_task_t *);
extern int pscsi_check_hba_params (iscsi_hbainfo_t *, struct iscsi_target *, int);
extern int pscsi_check_dev_params (iscsi_hba_t *, struct iscsi_target *, iscsi_dev_transport_info_t *);
extern void pscsi_get_plugin_info (void *, char *, int *);
extern void pscsi_get_hba_info (iscsi_hba_t *, char *, int *);
extern void pscsi_get_dev_info (iscsi_device_t *, char *, int *);
extern int pscsi_check_lba (unsigned long long, iscsi_device_t *);
extern int pscsi_check_for_SG (iscsi_task_t *);
extern unsigned char *pscsi_get_cdb (iscsi_task_t *);
extern unsigned char *pscsi_get_sense_buffer (iscsi_task_t *);
extern u32 pscsi_get_blocksize (iscsi_device_t *);
extern u32 pscsi_get_device_rev (iscsi_device_t *);
extern u32 pscsi_get_device_type (iscsi_device_t *);
extern u32 pscsi_get_dma_length (u32, iscsi_device_t *);
extern u32 pscsi_get_max_sectors (iscsi_device_t *);
extern u32 pscsi_get_queue_depth (iscsi_device_t *);
extern unsigned char *pscsi_get_non_SG (iscsi_task_t *);
extern struct scatterlist *pscsi_get_SG (iscsi_task_t *);
extern u32 pscsi_get_SG_count (iscsi_task_t *);
extern int pscsi_set_non_SG_buf (unsigned char *, iscsi_task_t *);
extern void pscsi_shutdown_hba (struct iscsi_hba_s *);
# ifdef scsi_execute_async_address
extern void pscsi_req_done (void *, char *, int, int);
# else
extern inline void pscsi_req_done (Scsi_Cmnd *);
#endif
#endif

#include <linux/device.h>
#include <scsi/scsi_driver.h>
#include <scsi/scsi_device.h>
#include <linux/kref.h>
#include <linux/kobject.h>

#ifdef scsi_execute_async_address
typedef struct pscsi_plugin_task_s {
	unsigned char pscsi_cdb[SCSI_CDB_SIZE];
	unsigned char pscsi_sense[SCSI_SENSE_BUFFERSIZE];
	int	pscsi_direction;
	int	pscsi_result;
	u32	pscsi_data_len;
	void	*pscsi_buf;
} pscsi_plugin_task_t;
#endif /* scsi_execute_async_address */

/*
 * We use the generic command sequencer, so we must setup
 * iscsi_transport_spc_t.
 */
#ifndef PSCSI_INCLUDE_STRUCTS
#define ISCSI_PSCSI_SPC { \
	inquiry:		pscsi_CDB_inquiry,		\
	none:			pscsi_CDB_none,			\
	read_non_SG:		pscsi_CDB_read_non_SG,		\
	read_SG:		pscsi_CDB_read_SG,		\
	write_non_SG:		pscsi_CDB_write_non_SG,		\
	write_SG:		pscsi_CDB_write_SG,		\
};

iscsi_transport_spc_t pscsi_template_spc = ISCSI_PSCSI_SPC;

#define ISCSI_PSCSI { \
	name:			"pscsi",			\
	type:			PSCSI,				\
	transport_type:		TRANSPORT_PLUGIN_PHBA_PDEV,	\
	attach_hba:		pscsi_attach_hba,		\
	detach_hba:		pscsi_detach_hba,		\
	scan_devices:		pscsi_scan_devices,		\
	activate_device:	pscsi_activate_device,		\
	deactivate_device:	pscsi_deactivate_device,	\
	claim_phydevice:	pscsi_claim_phydevice,		\
	free_device:		pscsi_free_device,		\
	release_phydevice:	pscsi_release_phydevice,	\
	check_device_location:	pscsi_check_device_location,	\
	check_ghost_id:		pscsi_check_ghost_id,		\
	transport_complete:	pscsi_transport_complete,	\
	allocate_request:	pscsi_allocate_request,		\
	do_task:		pscsi_do_task,			\
	free_task:		pscsi_free_task,		\
	check_hba_params:	pscsi_check_hba_params,		\
	check_dev_params:	pscsi_check_dev_params,		\
	get_plugin_info:	pscsi_get_plugin_info,		\
	get_hba_info:		pscsi_get_hba_info,		\
	get_dev_info:		pscsi_get_dev_info,		\
	check_lba:		pscsi_check_lba,		\
	check_for_SG:		pscsi_check_for_SG,		\
	get_cdb:		pscsi_get_cdb,			\
	get_sense_buffer:	pscsi_get_sense_buffer,		\
	get_blocksize:		pscsi_get_blocksize,		\
	get_device_rev:		pscsi_get_device_rev,		\
	get_device_type:	pscsi_get_device_type,		\
	get_dma_length:		pscsi_get_dma_length,		\
	get_evpd_prod:		pscsi_get_evpd_prod,		\
	get_evpd_sn:		pscsi_get_evpd_sn,		\
	get_max_sectors:	pscsi_get_max_sectors,		\
	get_queue_depth:	pscsi_get_queue_depth,		\
	get_non_SG:		pscsi_get_non_SG,		\
	get_SG:			pscsi_get_SG,			\
	get_SG_count:		pscsi_get_SG_count,		\
	set_non_SG_buf:		pscsi_set_non_SG_buf,		\
	shutdown_hba:		pscsi_shutdown_hba,		\
	write_pending:		NULL,				\
	spc:			&pscsi_template_spc,		\
};

iscsi_transport_t pscsi_template = ISCSI_PSCSI;
#endif

#endif   /*** ISCSI_TARGET_PSCSI_H ***/
