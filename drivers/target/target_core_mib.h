/*******************************************************************************
 * Filename:  target_core_mib.h
 *
 * Copyright (c) 2006 SBE, Inc.  All Rights Reserved.
 * Copyright (c) 2007-2009 Rising Tide Software, Inc.
 * Copyright (c) 2008-2009 Linux-iSCSI.org
 *
 * Nicholas A. Bellinger <nab@linux-iscsi.org>
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


#ifndef TARGET_CORE_MIB_H
#define TARGET_CORE_MIB_H

extern struct se_global *se_global;

typedef enum {
	SCSI_INST_INDEX,
	SCSI_DEVICE_INDEX,
	SCSI_AUTH_INTR_INDEX,
	SCSI_INDEX_TYPE_MAX
} scsi_index_t;

struct scsi_index_table {
	spinlock_t	lock;
	u32 		scsi_mib_index[SCSI_INDEX_TYPE_MAX];
} ____cacheline_aligned;

/* SCSI Port stats */
struct scsi_port_stats {
	u64	cmd_pdus;
	u64	tx_data_octets;
	u64	rx_data_octets;
} ____cacheline_aligned;

extern int init_scsi_target_mib(void);
extern void remove_scsi_target_mib(void);
extern void init_scsi_index_table(void);
extern u32 scsi_get_new_index(scsi_index_t);

#endif   /*** TARGET_CORE_MIB_H ***/

