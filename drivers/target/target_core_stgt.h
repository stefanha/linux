/*******************************************************************************
 * Filename:  target_core_stgt.h
 *
 * This file contains the generic target mode <-> Linux STGT subsystem plugin.
 * specific definitions and prototypes.
 *
 * Copyright (c) 2009 Rising Tide Systems, Inc.
 * Copyright (c) 2009 Linux-iSCSI.org
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


#ifndef TARGET_CORE_STGT_H
#define TARGET_CORE_STGT_H

#define STGT_VERSION		"v1.0"
#define STGT_NAME		"stgt_tcm"

/* used in pscsi_add_device_to_list() */
#define STGT_DEFAULT_QUEUEDEPTH	1

#define PS_RETRY		5
#define PS_TIMEOUT_DISK		(15*HZ)
#define PS_TIMEOUT_OTHER	(500*HZ)

extern struct se_global *se_global;
extern struct block_device *linux_blockdevice_claim(int, int, void *);
extern int linux_blockdevice_release(int, int, struct block_device *);
extern int linux_blockdevice_check(int, int);

void __init stgt_subsystem_init(void);

#include <linux/device.h>
#include <scsi/scsi_driver.h>
#include <scsi/scsi_device.h>
#include <linux/kref.h>
#include <linux/kobject.h>

struct stgt_plugin_task {
	unsigned char stgt_cdb[SCSI_CDB_SIZE];
	unsigned char stgt_sense[SCSI_SENSE_BUFFERSIZE];
	int	stgt_direction;
	int	stgt_result;
	u32	stgt_resid;
	struct scsi_cmnd *stgt_cmd;
} ____cacheline_aligned;

#define PDF_HAS_CHANNEL_ID	0x01
#define PDF_HAS_TARGET_ID	0x02
#define PDF_HAS_LUN_ID		0x04
#define PDF_HAS_VPD_UNIT_SERIAL 0x08
#define PDF_HAS_VPD_DEV_IDENT	0x10

struct stgt_dev_virt {
	int	sdv_flags;
	int	sdv_legacy; /* Use scsi_execute_async() from HTCL */
	int	sdv_channel_id;
	int	sdv_target_id;
	int	sdv_lun_id;
	struct block_device *sdv_bd; /* Temporary for v2.6.28 */
	struct scsi_device *sdv_sd;
	struct se_hba *sdv_se_hba;
} ____cacheline_aligned;

struct stgt_hba {
	struct device dev;
	struct se_hba *se_hba;
	struct Scsi_Host *scsi_host;
} ____cacheline_aligned;

#endif   /*** TARGET_CORE_STGT_H ***/
