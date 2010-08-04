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

#define PSCSI_VERSION		"v4.0"
#define PSCSI_VIRTUAL_HBA_DEPTH	2048

/* used in pscsi_find_alloc_len() */
#ifndef INQUIRY_DATA_SIZE
#define INQUIRY_DATA_SIZE	0x24
#endif

/* used in pscsi_add_device_to_list() */
#define PSCSI_DEFAULT_QUEUEDEPTH	1

#define PS_RETRY		5
#define PS_TIMEOUT_DISK		(15*HZ)
#define PS_TIMEOUT_OTHER	(500*HZ)

extern struct se_global *se_global;
extern struct block_device *linux_blockdevice_claim(int, int, void *);
extern int linux_blockdevice_release(int, int, struct block_device *);
extern int linux_blockdevice_check(int, int);

#include <linux/device.h>
#include <scsi/scsi_driver.h>
#include <scsi/scsi_device.h>
#include <linux/kref.h>
#include <linux/kobject.h>

struct pscsi_plugin_task {
	unsigned char pscsi_cdb[SCSI_CDB_SIZE];
	unsigned char pscsi_sense[SCSI_SENSE_BUFFERSIZE];
	int	pscsi_direction;
	int	pscsi_result;
	u32	pscsi_resid;
	struct request *pscsi_req;
} ____cacheline_aligned;

#define PDF_HAS_CHANNEL_ID	0x01
#define PDF_HAS_TARGET_ID	0x02
#define PDF_HAS_LUN_ID		0x04
#define PDF_HAS_VPD_UNIT_SERIAL 0x08
#define PDF_HAS_VPD_DEV_IDENT	0x10
#define PDF_HAS_VIRT_HOST_ID	0x20	

struct pscsi_dev_virt {
	int	pdv_flags;
	int	pdv_host_id;
	int	pdv_channel_id;
	int	pdv_target_id;
	int	pdv_lun_id;
	struct scsi_device *pdv_sd;
	struct se_hba *pdv_se_hba;
} ____cacheline_aligned;

typedef enum phv_modes {
	PHV_VIRUTAL_HOST_ID,
	PHV_LLD_SCSI_HOST_NO
} phv_modes_t;

struct pscsi_hba_virt {
	int			phv_host_id;
	phv_modes_t		phv_mode;
	struct Scsi_Host	*phv_lld_host;
} ____cacheline_aligned;

#endif   /*** TARGET_CORE_PSCSI_H ***/
