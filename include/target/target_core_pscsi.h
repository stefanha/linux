/*******************************************************************************
 * Filename:  target_core_pscsi.h
 *
 * This file contains the generic target mode <-> Linux SCSI subsystem plugin.
 * specific definitions and prototypes.
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


#ifndef TARGET_CORE_PSCSI_H
#define TARGET_CORE_PSCSI_H

#define PSCSI_VERSION		"v3.1"

/* used in pscsi_find_alloc_len() */
#ifndef INQUIRY_DATA_SIZE
#define INQUIRY_DATA_SIZE	0x24
#endif

/* used in pscsi_add_device_to_list() */
#define PSCSI_DEFAULT_QUEUEDEPTH	1

#define PS_RETRY		5
#define PS_TIMEOUT_DISK		(15*HZ)
#define PS_TIMEOUT_OTHER	(500*HZ)

extern se_global_t *se_global;
extern struct block_device *linux_blockdevice_claim(int, int, void *);
extern int linux_blockdevice_release(int, int, struct block_device *);
extern int linux_blockdevice_check(int, int);

extern int pscsi_CDB_inquiry(se_task_t *, u32);
extern int pscsi_CDB_none(se_task_t *, u32);
extern int pscsi_CDB_read_non_SG(se_task_t *, u32);
extern int pscsi_CDB_read_SG(se_task_t *, u32);
extern int pscsi_CDB_write_non_SG(se_task_t *, u32);
extern int pscsi_CDB_write_SG(se_task_t *, u32);

#ifndef PSCSI_INCLUDE_STRUCTS
extern int pscsi_attach_hba(se_hba_t *, u32);
extern int pscsi_detach_hba(se_hba_t *);
extern int pscsi_claim_phydevice(se_hba_t *, se_device_t *);
extern int pscsi_release_phydevice(se_device_t *);
extern void *pscsi_allocate_virtdevice(se_hba_t *, const char *);
extern se_device_t *pscsi_create_virtdevice(se_hba_t *, se_subsystem_dev_t *,
					void *);
extern int pscsi_activate_device(se_device_t *);
extern void pscsi_deactivate_device(se_device_t *);
extern void pscsi_free_device(void *);
extern int pscsi_transport_complete(se_task_t *);
extern void *pscsi_allocate_request(se_task_t *, se_device_t *);
extern int pscsi_do_task(se_task_t *);
extern void pscsi_free_task(se_task_t *);
extern ssize_t pscsi_set_configfs_dev_params(se_hba_t *, se_subsystem_dev_t *,
						const char *, ssize_t);
extern ssize_t pscsi_check_configfs_dev_params(se_hba_t *,
						se_subsystem_dev_t *);
extern ssize_t pscsi_show_configfs_dev_params(se_hba_t *, se_subsystem_dev_t *,
						char *);
extern se_device_t *pscsi_create_virtdevice_from_fd(se_subsystem_dev_t *,
						const char *);
extern void pscsi_get_plugin_info(void *, char *, int *);
extern void pscsi_get_hba_info(se_hba_t *, char *, int *);
extern void pscsi_get_dev_info(se_device_t *, char *, int *);
extern int pscsi_check_lba(unsigned long long, se_device_t *);
extern int pscsi_check_for_SG(se_task_t *);
extern unsigned char *pscsi_get_cdb(se_task_t *);
extern unsigned char *pscsi_get_sense_buffer(se_task_t *);
extern u32 pscsi_get_blocksize(se_device_t *);
extern u32 pscsi_get_device_rev(se_device_t *);
extern u32 pscsi_get_device_type(se_device_t *);
extern u32 pscsi_get_dma_length(u32, se_device_t *);
extern u32 pscsi_get_max_sectors(se_device_t *);
extern u32 pscsi_get_queue_depth(se_device_t *);
extern void pscsi_shutdown_hba(struct se_hba_s *);
extern void pscsi_req_done(struct request *, int);
#endif

#include <linux/device.h>
#include <scsi/scsi_driver.h>
#include <scsi/scsi_device.h>
#include <linux/kref.h>
#include <linux/kobject.h>

typedef struct pscsi_plugin_task_s {
	unsigned char pscsi_cdb[SCSI_CDB_SIZE];
	unsigned char pscsi_sense[SCSI_SENSE_BUFFERSIZE];
	int	pscsi_direction;
	int	pscsi_result;
	u32	pscsi_resid;
	struct request *pscsi_req;
} pscsi_plugin_task_t;

#define PDF_HAS_CHANNEL_ID	0x01
#define PDF_HAS_TARGET_ID	0x02
#define PDF_HAS_LUN_ID		0x04
#define PDF_HAS_VPD_UNIT_SERIAL 0x08
#define PDF_HAS_VPD_DEV_IDENT	0x10

typedef struct pscsi_dev_virt_s {
	int	pdv_flags;
	int	pdv_channel_id;
	int	pdv_target_id;
	int	pdv_lun_id;
	struct scsi_device *pdv_sd;
	struct se_hba_s *pdv_se_hba;
} pscsi_dev_virt_t;

extern void __pscsi_get_dev_info(pscsi_dev_virt_t *, char *, int *);

/*
 * We use the generic command sequencer, so we must setup
 * se_subsystem_spc_t.
 */
#ifndef PSCSI_INCLUDE_STRUCTS

se_subsystem_spc_t pscsi_template_spc = {
	.inquiry		= pscsi_CDB_inquiry,
	.none			= pscsi_CDB_none,
	.read_non_SG		= pscsi_CDB_read_non_SG,
	.read_SG		= pscsi_CDB_read_SG,
	.write_non_SG		= pscsi_CDB_write_non_SG,
	.write_SG		= pscsi_CDB_write_SG,
};

se_subsystem_api_t pscsi_template = {
	.name			= "pscsi",			\
	.type			= PSCSI,			\
	.transport_type		= TRANSPORT_PLUGIN_PHBA_PDEV,	\
	.attach_hba		= pscsi_attach_hba,		\
	.detach_hba		= pscsi_detach_hba,		\
	.activate_device	= pscsi_activate_device,	\
	.deactivate_device	= pscsi_deactivate_device,	\
	.claim_phydevice	= pscsi_claim_phydevice,	\
	.allocate_virtdevice	= pscsi_allocate_virtdevice,	\
	.create_virtdevice	= pscsi_create_virtdevice,	\
	.free_device		= pscsi_free_device,		\
	.release_phydevice	= pscsi_release_phydevice,	\
	.transport_complete	= pscsi_transport_complete,	\
	.allocate_request	= pscsi_allocate_request,	\
	.do_task		= pscsi_do_task,		\
	.free_task		= pscsi_free_task,		\
	.check_configfs_dev_params = pscsi_check_configfs_dev_params, \
	.set_configfs_dev_params = pscsi_set_configfs_dev_params, \
	.show_configfs_dev_params = pscsi_show_configfs_dev_params, \
	.create_virtdevice_from_fd = pscsi_create_virtdevice_from_fd, \
	.get_plugin_info	= pscsi_get_plugin_info,	\
	.get_hba_info		= pscsi_get_hba_info,		\
	.get_dev_info		= pscsi_get_dev_info,		\
	.check_lba		= pscsi_check_lba,		\
	.check_for_SG		= pscsi_check_for_SG,		\
	.get_cdb		= pscsi_get_cdb,		\
	.get_sense_buffer	= pscsi_get_sense_buffer,	\
	.get_blocksize		= pscsi_get_blocksize,		\
	.get_device_rev		= pscsi_get_device_rev,		\
	.get_device_type	= pscsi_get_device_type,	\
	.get_dma_length		= pscsi_get_dma_length,		\
	.get_max_sectors	= pscsi_get_max_sectors,	\
	.get_queue_depth	= pscsi_get_queue_depth,	\
	.shutdown_hba		= pscsi_shutdown_hba,		\
	.write_pending		= NULL,				\
	.spc			= &pscsi_template_spc,		\
};

#endif

#endif   /*** TARGET_CORE_PSCSI_H ***/
