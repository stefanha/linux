/*********************************************************************************
 * Filename:  iscsi_target_mc.h
 *
 * This file contains the iSCSI <-> media changer transport specific definitions
 * and prototypes.
 *
 * Copyright (c) 2006-2007 SBE, Inc.  All Rights Reserved.
 * Copyright (c) 2007 Rising Tide Software, Inc.
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


#ifndef ISCSI_TARGET_MC_H
#define ISCSI_TARGET_MC_H

#define MC_VERSION		"v0.1"

#define MC_MAX_DEV_NAME		256
#define MC_HBA_QUEUE_DEPTH	256		/* Maximum queuedepth for the media changer HBA */
#define MC_DEVICE_QUEUE_DEPTH	32
#define MC_BLOCKSIZE		512
#define MC_MAX_SECTORS		1024

#define MC_DATA_READ		1
#define MC_DATA_WRITE		2
#define MC_DATA_NONE		3

#ifndef MC_INCLUDE_STRUCTS
extern int mc_CDB_inquiry (se_task_t *, u32);
extern int mc_CDB_none (se_task_t *, u32);
extern int mc_CDB_read_non_SG (se_task_t *, u32);
extern int mc_CDB_read_SG (se_task_t *, u32);
extern int mc_CDB_write_non_SG (se_task_t *, u32);
extern int mc_CDB_write_SG (se_task_t *, u32);

extern int mc_attach_hba (iscsi_portal_group_t *, iscsi_hba_t *, iscsi_hbainfo_t *);
extern int mc_detach_hba (iscsi_hba_t *);
extern int mc_create_virtdevice (iscsi_hba_t *, iscsi_devinfo_t *);
extern int mc_activate_device (se_device_t *);
extern void mc_deactivate_device (se_device_t *);
extern int mc_check_device_location (se_device_t *, iscsi_dev_transport_info_t *);
extern int mc_check_ghost_id (iscsi_hbainfo_t *);
extern void mc_free_device (se_device_t *);
extern se_device_t *mc_add_device_to_list (iscsi_hba_t *, void *);
extern int mc_transport_complete (se_task_t *);
extern void *mc_allocate_request (se_task_t *, se_device_t *);
extern void mc_get_evpd_prod (unsigned char *, u32, se_device_t *);
extern void mc_get_evpd_sn (unsigned char *, u32, se_device_t *);
extern int mc_do_task (se_task_t *);
extern void mc_free_task (se_task_t *);
extern int mc_check_hba_params (iscsi_hbainfo_t *, struct iscsi_target *, int);
extern int mc_check_dev_params (iscsi_hba_t *, struct iscsi_target *, iscsi_dev_transport_info_t *);
extern int mc_check_virtdev_params (iscsi_devinfo_t *, struct iscsi_target *);
extern void mc_get_plugin_info (void *, char *, int *);
extern void mc_get_hba_info (iscsi_hba_t *, char *, int *);
extern void mc_get_dev_info (se_device_t *, char *, int *);
extern int mc_check_lba (unsigned long long, se_device_t *);
extern int mc_check_for_SG (se_task_t *);
extern unsigned char *mc_get_cdb (se_task_t *);
extern u32 mc_get_blocksize (se_device_t *);
extern u32 mc_get_device_rev (se_device_t *);
extern u32 mc_get_device_type (se_device_t *);
extern u32 mc_get_dma_length (u32, se_device_t *);
extern u32 mc_get_max_sectors (se_device_t *);
extern u32 mc_get_queue_depth (se_device_t *);
extern unsigned char *mc_get_non_SG (se_task_t *);
extern struct scatterlist *mc_get_SG (se_task_t *);
extern u32 mc_get_SG_count (se_task_t *);
extern int mc_set_non_SG_buf (unsigned char *, se_task_t *);
extern unsigned char *mc_get_sense_buffer (se_task_t *);
#endif /* ! MC_INCLUDE_STRUCTS */

#define RRF_EMULATE_CDB		0x01
#define RRF_GOT_LBA		0x02

typedef struct mc_request_s {
	unsigned char	mc_scsi_cdb[SCSI_CDB_SIZE]; /* SCSI CDB from iSCSI Command PDU */
	u8		mc_data_direction;	/* Data Direction */
	u32		mc_bufflen;		/* Total length of request */
	u32		mc_req_flags;		/* RD request flags */
	u32		mc_offset;		/* Offset from start of page */
	u32		mc_sg_count;		/* Scatterlist count */
	unsigned long long	mc_lba;			/* Logical Block Address */
	u64		mc_size;
	void		*mc_buf;		/* Data buffer containing scatterlists(s) or contiguous memory segments. */
	struct mc_dev_s	*mc_dev;		/* media changer device */
	u32		mc_sense_flag;
	char		mc_sense_buffer[96];
} mc_request_t;

typedef struct mc_dev_sg_table_s {
	u32		page_start_offset;
	u32		page_end_offset;
	u32		mc_sg_count;
	struct scatterlist *sg_table;
} mc_dev_sg_table_t;

typedef struct mc_dev_s {
	u32		mc_dev_id;		/* This must be first because we cast
						between mc_dev_t and vt_dev_t to read
						the id. */
	unsigned char	mc_dev_name[MC_MAX_DEV_NAME];
	u32		mc_hw_id;		/* Hardware emulation code */
	u32		mc_table_count;		/* Number of SG tables in sg_table_array */
	u32		mc_queue_depth;
	unsigned long long mc_dev_size;
	struct mc_host_s *mc_host;		/* media changer HBA device is connected to */
	struct mc_dev_s *next;			/* Next media changer Device entry in list */
} mc_dev_t;

#define MC_MAX_TAPE 1000
#define MC_MAX_SLOT 1000

typedef struct mc_host_s {
	u32		mc_host_id;		/* Unique media changer Host ID */
	char		mc_path_prefix[MC_MAX_DEV_NAME];
	int		mc_hw_id;
	int		mc_ntape;
	int		mc_nslot;		/* nmte + nse + nxe + ndte */
	int		mc_fmte;		/* first medium transport element */
	int		mc_nmte;		/* number of medium transport elements */
	int		mc_fse;			/* first storage element */
	int		mc_nse;			/* number of storage elements */
	int		mc_fxe;			/* first import/export element */
	int		mc_nxe;			/* number of import/export elements */
	int		mc_fdte;		/* first data transfer element */
	int		mc_ndte;		/* number of data transfer elements */
	char		*mc_tape[MC_MAX_TAPE];
	char		*mc_slot[MC_MAX_SLOT];
} mc_host_t;

#ifndef MC_INCLUDE_STRUCTS
/*
 * We use the generic command sequencer, so we must setup
 * iscsi_transport_spc_t.
 */
#define ISCSI_MC_SPC {					\
	inquiry:		mc_CDB_inquiry,			\
	none:			mc_CDB_none,			\
	read_non_SG:		mc_CDB_read_non_SG,		\
	read_SG:		mc_CDB_read_SG,			\
	write_non_SG:		mc_CDB_write_non_SG,		\
	write_SG:		mc_CDB_write_SG,		\
};

iscsi_transport_spc_t mc_template_spc = ISCSI_MC_SPC;

#define ISCSI_MC {						\
	name:			"media changer",		\
	type:			MEDIA_CHANGER,			\
	transport_type:		TRANSPORT_PLUGIN_VHBA_VDEV,	\
	attach_hba:		mc_attach_hba,			\
	detach_hba:		mc_detach_hba,			\
	create_virtdevice:	mc_create_virtdevice,		\
	activate_device:	mc_activate_device,		\
	deactivate_device:	mc_deactivate_device,		\
	check_device_location:	mc_check_device_location,	\
	check_ghost_id:		mc_check_ghost_id,		\
	free_device:		mc_free_device,			\
	transport_complete:	mc_transport_complete,		\
	allocate_request:	mc_allocate_request,		\
	do_task:		mc_do_task,			\
	free_task:		mc_free_task,			\
	check_hba_params:	mc_check_hba_params,		\
	check_dev_params:	mc_check_dev_params,		\
	check_virtdev_params:	mc_check_virtdev_params,	\
	get_plugin_info:	mc_get_plugin_info,		\
	get_hba_info:		mc_get_hba_info,		\
	get_dev_info:		mc_get_dev_info,		\
	check_lba:		mc_check_lba,			\
	check_for_SG:		mc_check_for_SG,		\
	get_cdb:		mc_get_cdb,			\
	get_blocksize:		mc_get_blocksize,		\
	get_device_rev:		mc_get_device_rev,		\
	get_device_type:	mc_get_device_type,		\
	get_dma_length:		mc_get_dma_length,		\
	get_evpd_prod:		mc_get_evpd_prod,		\
	get_evpd_sn:		mc_get_evpd_sn,			\
	get_max_sectors:	mc_get_max_sectors,		\
	get_queue_depth:	mc_get_queue_depth,		\
	get_non_SG:		mc_get_non_SG,			\
	get_SG:			mc_get_SG,			\
	get_SG_count:		mc_get_SG_count,		\
	set_non_SG_buf:		mc_set_non_SG_buf,		\
	get_sense_buffer:	mc_get_sense_buffer,		\
	spc:			&mc_template_spc,		\
};
	
iscsi_transport_t mc_template = ISCSI_MC;
#endif /* ! MC_INCLUDE_STRUCTS */

#endif /* ISCSI_TARGET_MC_H */
