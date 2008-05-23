/*********************************************************************************
 * Filename:  iscsi_target_rd.h
 *
 * This file contains the iSCSI <-> Ramdisk transport specific definitions and prototypes.
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


#ifndef ISCSI_TARGET_RD_H
#define ISCSI_TARGET_RD_H

#define RD_HBA_VERSION		"v3.0"
#define RD_DR_VERSION		"v3.0"
#define RD_MCP_VERSION		"v3.0"

#define RD_MAX_ALLOCATION_SIZE	65536		/* Largest piece of memory kmalloc can allocate */
#define RD_HBA_QUEUE_DEPTH	256		/* Maximum queuedepth for the Ramdisk HBA */
#define RD_DEVICE_QUEUE_DEPTH	32
#define RD_BLOCKSIZE		512
#define RD_MAX_SECTORS		1024

#define RD_DATA_READ		1
#define RD_DATA_WRITE		2
#define RD_DATA_NONE		3

#ifndef RD_INCLUDE_STRUCTS
extern int rd_CDB_inquiry (se_task_t *, u32);
extern int rd_CDB_none (se_task_t *, u32);
extern int rd_CDB_read_non_SG (se_task_t *, u32);
extern int rd_CDB_read_SG (se_task_t *, u32);
extern int rd_CDB_write_non_SG (se_task_t *, u32);
extern int rd_CDB_write_SG (se_task_t *, u32);

extern int rd_attach_hba (iscsi_portal_group_t *, iscsi_hba_t *, iscsi_hbainfo_t *);
extern int rd_detach_hba (iscsi_hba_t *);
extern int rd_DIRECT_create_virtdevice (iscsi_hba_t *, iscsi_devinfo_t *);
extern int rd_MEMCPY_create_virtdevice (iscsi_hba_t *, iscsi_devinfo_t *);
extern int rd_activate_device (se_device_t *);
extern void rd_deactivate_device (se_device_t *);
extern int rd_check_device_location (se_device_t *, iscsi_dev_transport_info_t *);
extern int rd_mcp_check_ghost_id (iscsi_hbainfo_t *);
extern int rd_dr_check_ghost_id (iscsi_hbainfo_t *);
extern void rd_free_device (se_device_t *);
extern se_device_t *rd_add_device_to_list (iscsi_hba_t *, void *, iscsi_devinfo_t *);
extern int rd_transport_complete (se_task_t *);
extern void *rd_allocate_request (se_task_t *, se_device_t *);
extern void rd_get_evpd_prod (unsigned char *, u32, se_device_t *);
extern void rd_get_evpd_sn (unsigned char *, u32, se_device_t *);
extern int rd_DIRECT_do_task (se_task_t *);
extern int rd_MEMCPY_do_task (se_task_t *);
extern int rd_DIRECT_allocate_DMA (iscsi_cmd_t *, u32, u32);
extern int rd_DIRECT_do_se_mem_map (struct se_task_s *, struct list_head *, void *, struct se_mem_s *, struct se_mem_s **, u32 *, u32 *);
extern void rd_DIRECT_free_DMA (iscsi_cmd_t *);
extern void rd_free_task (se_task_t *);
extern int rd_check_hba_params (iscsi_hbainfo_t *, struct iscsi_target *, int);
extern int rd_check_dev_params (iscsi_hba_t *, struct iscsi_target *, iscsi_dev_transport_info_t *);
extern int rd_check_virtdev_params (iscsi_devinfo_t *, struct iscsi_target *);
extern void rd_dr_get_plugin_info (void *, char *, int *);
extern void rd_mcp_get_plugin_info (void *, char *, int *);
extern void rd_get_hba_info (iscsi_hba_t *, char *, int *);
extern void rd_get_dev_info (se_device_t *, char *, int *);
extern int rd_DIRECT_check_lba (unsigned long long, se_device_t *);
extern int rd_MEMCPY_check_lba (unsigned long long, se_device_t *);
extern int rd_check_for_SG (se_task_t *);
extern unsigned char *rd_get_cdb (se_task_t *);
extern u32 rd_get_blocksize (se_device_t *);
extern u32 rd_get_device_rev (se_device_t *);
extern u32 rd_get_device_type (se_device_t *);
extern u32 rd_get_dma_length (u32, se_device_t *);
extern u32 rd_get_max_sectors (se_device_t *);
extern u32 rd_get_queue_depth (se_device_t *);
extern unsigned char *rd_get_non_SG (se_task_t *);
extern struct scatterlist *rd_get_SG (se_task_t *);
extern u32 rd_get_SG_count (se_task_t *);
extern int rd_set_non_SG_buf (unsigned char *, se_task_t *);
#endif /* ! RD_INCLUDE_STRUCTS */

#define RRF_EMULATE_CDB		0x01
#define RRF_GOT_LBA		0x02

typedef struct rd_request_s {
	unsigned char	rd_scsi_cdb[SCSI_CDB_SIZE]; /* SCSI CDB from iSCSI Command PDU */
	u8		rd_data_direction;	/* Data Direction */
	u32		rd_bufflen;		/* Total length of request */
	u32		rd_req_flags;		/* RD request flags */
	u32		rd_offset;		/* Offset from start of page */
	u32		rd_page;		/* Starting page in Ramdisk for request */
	u32		rd_page_count;		/* Total number of pages needed for request */
	u32		rd_sg_count;		/* Scatterlist count */
	u32		rd_size;
	unsigned long long	rd_lba;			/* Logical Block Address */
	void		*rd_buf;		/* Data buffer containing scatterlists(s) or contiguous memory segments. */
	struct rd_dev_s	*rd_dev;		/* Ramdisk device */
} ____cacheline_aligned rd_request_t;

typedef struct rd_dev_sg_table_s {
	u32		page_start_offset;
	u32		page_end_offset;
	u32		rd_sg_count;
	struct scatterlist *sg_table;
} ____cacheline_aligned rd_dev_sg_table_t;

typedef struct rd_dev_s {
	int		rd_direct;
	u32		rd_dev_id;		/* Unique Ramdisk Device ID in Ramdisk HBA */
	u32		rd_page_count;		/* Total page count for ramdisk device */
	u32		sg_table_count;		/* Number of SG tables in sg_table_array */
	u32		rd_queue_depth;
	rd_dev_sg_table_t *sg_table_array;	/* Array of rd_dev_sg_table_t containing scatterlists */
	struct rd_host_s *rd_host;		/* Ramdisk HBA device is connected to */
	struct rd_dev_s *next;			/* Next RD Device entry in list */
} ____cacheline_aligned rd_dev_t;

typedef struct rd_host_s {
	u32		rd_host_id;		/* Unique Ramdisk Host ID */
} ____cacheline_aligned rd_host_t;

#ifndef RD_INCLUDE_STRUCTS
/*
 * We use the generic command sequencer, so we must setup
 * iscsi_transport_spc_t.
 */
#define ISCSI_RD_SPC {						\
	inquiry:		rd_CDB_inquiry,			\
	none:			rd_CDB_none,			\
	read_non_SG:		rd_CDB_read_non_SG,		\
	read_SG:		rd_CDB_read_SG,			\
	write_non_SG:		rd_CDB_write_non_SG,		\
	write_SG:		rd_CDB_write_SG,		\
};

iscsi_transport_spc_t rd_template_spc = ISCSI_RD_SPC;

#define ISCSI_RD_DR {						\
	name:			"rd_dr",			\
	type:			RAMDISK_DR,			\
	transport_type:		TRANSPORT_PLUGIN_VHBA_VDEV,	\
	attach_hba:		rd_attach_hba,			\
	detach_hba:		rd_detach_hba,			\
	create_virtdevice:	rd_DIRECT_create_virtdevice,	\
	activate_device:	rd_activate_device,		\
	deactivate_device:	rd_deactivate_device,		\
	check_device_location:	rd_check_device_location,	\
	check_ghost_id:		rd_dr_check_ghost_id,		\
	free_device:		rd_free_device,			\
	transport_complete:	rd_transport_complete,		\
	allocate_DMA:		rd_DIRECT_allocate_DMA,		\
	free_DMA:		rd_DIRECT_free_DMA,		\
	allocate_request:	rd_allocate_request,		\
	do_task:		rd_DIRECT_do_task,		\
	free_task:		rd_free_task,			\
	check_hba_params:	rd_check_hba_params,		\
	check_dev_params:	rd_check_dev_params,		\
	check_virtdev_params:	rd_check_virtdev_params,	\
	get_plugin_info:	rd_dr_get_plugin_info,		\
	get_hba_info:		rd_get_hba_info,		\
	get_dev_info:		rd_get_dev_info,		\
	check_lba:		rd_DIRECT_check_lba,		\
	check_for_SG:		rd_check_for_SG,		\
	get_cdb:		rd_get_cdb,			\
	get_blocksize:		rd_get_blocksize,		\
	get_device_rev:		rd_get_device_rev,		\
	get_device_type:	rd_get_device_type,		\
	get_dma_length:		rd_get_dma_length,		\
	get_evpd_prod:		rd_get_evpd_prod,		\
	get_evpd_sn:		rd_get_evpd_sn,			\
	get_max_sectors:	rd_get_max_sectors,		\
	get_queue_depth:	rd_get_queue_depth,		\
	do_se_mem_map:		rd_DIRECT_do_se_mem_map,	\
	get_non_SG:		rd_get_non_SG,			\
	get_SG:			rd_get_SG,			\
	get_SG_count:		rd_get_SG_count,		\
	set_non_SG_buf:		rd_set_non_SG_buf,		\
	write_pending:		NULL,				\
	spc:			&rd_template_spc,		\
};

iscsi_transport_t rd_dr_template = ISCSI_RD_DR;

#define ISCSI_RD_MCP {						\
	name:			"rd_mcp",			\
	type:			RAMDISK_MCP,			\
	transport_type:		TRANSPORT_PLUGIN_VHBA_VDEV,	\
	attach_hba:		rd_attach_hba,			\
	detach_hba:		rd_detach_hba,			\
	create_virtdevice:	rd_MEMCPY_create_virtdevice,	\
	activate_device:	rd_activate_device,		\
	deactivate_device:	rd_deactivate_device,		\
	check_device_location:	rd_check_device_location,	\
	check_ghost_id:		rd_mcp_check_ghost_id,		\
	free_device:		rd_free_device,			\
	transport_complete:	rd_transport_complete,		\
	allocate_request:	rd_allocate_request,		\
	do_task:		rd_MEMCPY_do_task,		\
	free_task:		rd_free_task,			\
	check_hba_params:	rd_check_hba_params,		\
	check_dev_params:	rd_check_dev_params,		\
	check_virtdev_params:	rd_check_virtdev_params,	\
	get_plugin_info:	rd_mcp_get_plugin_info,		\
	get_hba_info:		rd_get_hba_info,		\
	get_dev_info:		rd_get_dev_info,		\
	check_lba:		rd_MEMCPY_check_lba,		\
	check_for_SG:		rd_check_for_SG,		\
	get_cdb:		rd_get_cdb,			\
	get_blocksize:		rd_get_blocksize,		\
	get_device_rev:		rd_get_device_rev,		\
	get_device_type:	rd_get_device_type,		\
	get_dma_length:		rd_get_dma_length,		\
	get_evpd_prod:		rd_get_evpd_prod,		\
	get_evpd_sn:		rd_get_evpd_sn,			\
	get_max_sectors:	rd_get_max_sectors,		\
	get_queue_depth:	rd_get_queue_depth,		\
	get_non_SG:		rd_get_non_SG,			\
	get_SG:			rd_get_SG,			\
	get_SG_count:		rd_get_SG_count,		\
	set_non_SG_buf:		rd_set_non_SG_buf,		\
	write_pending:		NULL,				\
	spc:			&rd_template_spc,		\
};
	
iscsi_transport_t rd_mcp_template = ISCSI_RD_MCP;
#endif /* ! RD_INCLUDE_STRUCTS */

#endif /* ISCSI_TARGET_RD_H */
