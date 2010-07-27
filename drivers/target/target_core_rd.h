/*******************************************************************************
 * Filename:  target_core_rd.h
 *
 * This file contains the Storage Engine <-> Ramdisk transport specific
 * definitions and prototypes.
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


#ifndef TARGET_CORE_RD_H
#define TARGET_CORE_RD_H

#define RD_HBA_VERSION		"v4.0"
#define RD_DR_VERSION		"4.0"
#define RD_MCP_VERSION		"4.0"

/* Largest piece of memory kmalloc can allocate */
#define RD_MAX_ALLOCATION_SIZE	65536
/* Maximum queuedepth for the Ramdisk HBA */
#define RD_HBA_QUEUE_DEPTH	256
#define RD_DEVICE_QUEUE_DEPTH	32
#define RD_MAX_DEVICE_QUEUE_DEPTH 128
#define RD_BLOCKSIZE		512
#define RD_MAX_SECTORS		1024

#define RD_DATA_READ		1
#define RD_DATA_WRITE		2
#define RD_DATA_NONE		3

extern struct se_global *se_global;

extern struct kmem_cache *se_mem_cache;

void __init rd_subsystem_init(void);

#define RRF_EMULATE_CDB		0x01
#define RRF_GOT_LBA		0x02

struct rd_request {
	/* SCSI CDB from iSCSI Command PDU */
	unsigned char	rd_scsi_cdb[SCSI_CDB_SIZE];
	/* Data Direction */
	u8		rd_data_direction;
	/* Total length of request */
	u32		rd_bufflen;
	/* RD request flags */
	u32		rd_req_flags;
	/* Offset from start of page */
	u32		rd_offset;
	/* Starting page in Ramdisk for request */
	u32		rd_page;
	/* Total number of pages needed for request */
	u32		rd_page_count;
	/* Scatterlist count */
	u32		rd_sg_count;
	u32		rd_size;
	/* Logical Block Address */
	unsigned long long	rd_lba;
	 /* Data buffer containing scatterlists(s) or
	  * contiguous memory segments */
	void		*rd_buf;
	/* Ramdisk device */
	struct rd_dev	*rd_dev;
} ____cacheline_aligned;

struct rd_dev_sg_table {
	u32		page_start_offset;
	u32		page_end_offset;
	u32		rd_sg_count;
	struct scatterlist *sg_table;
} ____cacheline_aligned;

#define RDF_HAS_PAGE_COUNT	0x01

struct rd_dev {
	int		rd_direct;
	u32		rd_flags;
	/* Unique Ramdisk Device ID in Ramdisk HBA */
	u32		rd_dev_id;
	/* Total page count for ramdisk device */
	u32		rd_page_count;
	/* Number of SG tables in sg_table_array */
	u32		sg_table_count;
	u32		rd_queue_depth;
	/* Array of rd_dev_sg_table_t containing scatterlists */
	struct rd_dev_sg_table *sg_table_array;
	/* Ramdisk HBA device is connected to */
	struct rd_host *rd_host;
} ____cacheline_aligned;

struct rd_host {
	u32		rd_host_dev_id_count;
	u32		rd_host_id;		/* Unique Ramdisk Host ID */
} ____cacheline_aligned;

#endif /* TARGET_CORE_RD_H */
