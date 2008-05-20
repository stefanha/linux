/*********************************************************************************
 * Filename:  iscsi_target_vrom.h
 *
 * This file contains the iSCSI <-> Virtual ROM transport specific definitions
 * and prototypes.
 *
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


#ifndef ISCSI_TARGET_VROM_H
#define ISCSI_TARGET_VROM_H

#define VR_VERSION		"v1.1"

#define VR_MAX_DEV_NAME		256
#define VR_HBA_QUEUE_DEPTH	256		/* Maximum queuedepth for the VROM HBA */
#define VR_DEVICE_QUEUE_DEPTH	32
#define VR_BLOCKSIZE		2048
#define VR_MAX_SECTORS		1024
#define VR_MAX_CDBS		1

#define VR_DATA_READ		1
#define VR_DATA_WRITE		2
#define VR_DATA_NONE		3

#ifndef VR_INCLUDE_STRUCTS
int vr_CDB_inquiry (iscsi_task_t *, u32);
int vr_CDB_none (iscsi_task_t *, u32);
int vr_CDB_read_non_SG (iscsi_task_t *, u32);
int vr_CDB_read_SG (iscsi_task_t *, u32);
int vr_CDB_write_non_SG (iscsi_task_t *, u32);
int vr_CDB_write_SG (iscsi_task_t *, u32);

int vr_create_virtdevice (iscsi_hba_t *, iscsi_devinfo_t *);
int vr_activate_device (iscsi_device_t *);
void vr_deactivate_device (iscsi_device_t *);
void vr_free_device (iscsi_device_t *);
iscsi_device_t *vr_add_device_to_list (iscsi_hba_t *, void *);
int vr_transport_complete (iscsi_task_t *);
void *vr_allocate_request (iscsi_task_t *, iscsi_device_t *);
int vr_do_task (iscsi_task_t *);
void vr_free_task (iscsi_task_t *);
extern int vr_check_dev_params (iscsi_hba_t *, struct iscsi_target *, iscsi_dev_transport_info_t *);
extern int vr_check_virtdev_params (iscsi_devinfo_t *, struct iscsi_target *);
extern void vr_get_plugin_info (void *, char *, int *);
extern void vr_get_dev_info (iscsi_device_t *, char *, int *);
int vr_check_lba (unsigned long long, iscsi_device_t *);
int vr_check_for_SG (iscsi_task_t *);
unsigned char *vr_get_cdb (iscsi_task_t *);
u32 vr_get_blocksize (iscsi_device_t *);
u32 vr_get_dma_length (iscsi_task_t *);
u32 vr_get_max_cdbs (iscsi_device_t *);
u32 vr_get_max_sectors (iscsi_device_t *);
u32 vr_get_queue_depth (iscsi_device_t *);
unsigned char *vr_get_non_SG (iscsi_task_t *);
struct scatterlist *vr_get_SG (iscsi_task_t *);
u32 vr_get_SG_count (iscsi_task_t *);
int vr_set_non_SG_buf (unsigned char *, iscsi_task_t *);
#endif /* ! VR_INCLUDE_STRUCTS */

#include "../css-auth/css-auth.h"

#define CSSKey1Len 5
#define CSSKey2Len 5
struct rmmc_css {
       u8 authed;

       u8 agid;
       u8 variant;
       u8 chal[10];
       struct block bkey1, bkey2, bbuskey;
};

static inline void swap(unsigned char a[], int i, int j)
{
       unsigned char c;
       c = a[i];
       a[i] = a[j];
       a[j] = c;
}
static inline void rev5(unsigned char a[])
{
       swap(a, 0, 4);
       swap(a, 1, 3);
}

static inline void rev10(unsigned char a[])
{
       int i;
       for (i = 0; i < 5; i++)
               swap(a, i, 9 - i);
}

static inline u8 *genbuskey(struct rmmc_css css[])
{
	rev5(css->bkey1.b);
	rev5(css->bkey2.b);
	memcpy(css->chal, css->bkey1.b, sizeof(css->bkey1.b));
	memcpy(css->chal + sizeof(css->bkey1.b), css->bkey2.b,
			sizeof(css->bkey2.b));
	CryptBusKey(css->variant, css->chal, &css->bbuskey);
	return css->bbuskey.b;
}

static inline u8 *genkey1(struct rmmc_css css[])
{
#if 0
	TRACE_ERROR("Before Challenge: 0x%02x %02x %02x %02x %02x %02x %02x %02x %02x %02x\n",
		css->chal[0], css->chal[1], css->chal[2], css->chal[3], css->chal[4], css->chal[5], css->chal[6], css->chal[7], css->chal[8], css->chal[9]);
#endif
       rev10(css->chal);
#if 0
	TRACE_ERROR("After Challenge: 0x%02x %02x %02x %02x %02x %02x %02x %02x %02x %02x\n",
		css->chal[0], css->chal[1], css->chal[2], css->chal[3], css->chal[4], css->chal[5], css->chal[6], css->chal[7], css->chal[8], css->chal[9]);
#endif

       CryptKey1(css->variant, css->chal, &css->bkey1);
#if 0
       TRACE_ERROR("Before css->bkey1: 0x%02x %02x %02x %02x %02x\n",
		css->bkey1.b[0], css->bkey1.b[1], css->bkey1.b[2], css->bkey1.b[3], css->bkey1.b[4]);
#endif
       rev5(css->bkey1.b);
#if 0
	TRACE_ERROR("After css->bkey1: 0x%02x %02x %02x %02x %02x\n",
		css->bkey1.b[0], css->bkey1.b[1], css->bkey1.b[2], css->bkey1.b[3], css->bkey1.b[4]);
#endif

       return css->bkey1.b;
}

static inline u8 *genkey2(struct rmmc_css css[])
{
       rev10(css->chal);
       CryptKey2(css->variant, css->chal, &css->bkey2);
       rev5(css->bkey2.b);
       return css->bkey2.b;
}

static inline int memcmpkey2(struct rmmc_css css[], u8 a[])
{
#if 0
	TRACE_ERROR("css->bkey2.b: 0x%02x %02x %02x %02x %02x\n", css->bkey2.b[0], css->bkey2.b[1], css->bkey2.b[2], css->bkey2.b[3], css->bkey2.b[4]);
	TRACE_ERROR("key2: 0x%02x %02x %02x %02x %02x\n", a[0], a[1], a[2], a[3], a[4]);
#endif
       return memcmp(a, css->bkey2.b, sizeof(css->bkey2.b));
}

static inline void
encbybuskey(u8 dst[], u8 src[], u32 len, struct rmmc_css css[])
{
       u32 i;
       for (i = 0; i < len; i++)
               dst[i] = src[i] ^ css->bbuskey.b[4 - (i % 5)];
}

#include <linux/cdrom.h>

/*
 * file format
 */
struct rmmc_aux_offlen {
       u32 offset;
       u32 length;
};

/* based upon raw responses */
struct rmmc_aux_discinfo {
       u8 data[0];
};

enum { DslPhys, DslCprt, DslManuf, LastDslData };
struct rmmc_aux_layer {
       /* offset from next 'data' */
       struct rmmc_aux_offlen offlen[LastDslData];

       u8 data[0];
};

struct rmmc_aux_dvdst {
       u8 nlayer;
       u8 pad[3];
       u8 dkey[4 + 2048];

       /* offset from next 'data' */
       struct rmmc_aux_offlen offlen[DVD_LAYERS];

       struct rmmc_aux_layer data[0];
};

struct rmmc_aux_tpa {
       /* un-implemented */
       u8 data[0];
};

enum { Type1_0, Type1_1, LastType1 };
struct rmmc_aux_trkinfo {
       /* offset from next 'data' */
       struct rmmc_aux_offlen offlen[LastType1];

       u8 data[0];
};

struct rmmc_aux_tk {
       /* start and end */
       u32 lba[2];

       u8 cpbits;
       u8 tk[5];
       u8 pad[2];
};

struct rmmc_aux_rkey {
       u32 ntitle;
       struct rmmc_aux_tk data[0];
};

struct rmmc_aux_cprt {
        u16 len;
        u8 res1[2];

        /* copyright info */
        u8 cpst;
        u8 rmt;
        u8 res2[2];
};

enum {
       DISC_INFO,              // GPCMD_READ_DISC_INFO
       DVD_STRUCTURE,          // GPCMD_READ_DVD_STRUCTURE or READ DISC STRUCTURE command
       TOC_PMA_ATIP,           // GPCMD_READ_TOC_PMA_ATIP
       REPORT_KEY1,
//       TRACK_INFO,   // GPCMD_READ_TRACK_RZONE_INFO
       LastCmd
};

#define RmmcAuxMagicStr "rmmcaux"
struct rmmc_aux_file {
       u8 magic[16];
       u32 version;

       /* all data, should be match to the total of 'length's in 'offlen'' */
       u32 size;

       /* sum of all 'data' */
       u32 sum;

       u32 salt[4];

       /* offset from next 'data' */
       struct rmmc_aux_offlen offlen[LastCmd];

       /* responses */
       u8 data[0];
};

struct auxinfo {
       struct rmmc_aux_file *auxfile;
       struct list_head list;
       u8 *auxpath;
       atomic_t ref;
};

/*
#if sizeof(RmmcAuxMagicStr)-1 > sizeof(struct rmmc_aux_file_v0.magic)
#error magic string macro it too long.
#endif
*/

struct rmmc_conn {
       int lasttk;
       struct rmmc_css css;
       int media_event;

       /* statistics */
       struct {
               unsigned long read, sendfile;
       } readstat;
};

static inline void
set_offlen(struct rmmc_aux_offlen p[], u32 offset, u32 length)
{
       p->offset = cpu_to_be32(offset);
       p->length = cpu_to_be32(length);
}

/*
 * simple macros for reading the aux file
 */
#define define_ol(name, basetype, lim) \
static inline void* \
name(basetype base[], int ind, u32 len[]) \
{ \
       struct rmmc_aux_offlen *p; \
       u8 *o; \
       /* if (!base || ind >= (lim)) return NULL */; \
       o = (void*)base->data; \
       p = base->offlen; \
       p += ind; \
       *len = be32_to_cpu(p->length); \
       return o+be32_to_cpu(p->offset); \
}

define_ol(offlenof_aux, struct rmmc_aux_file, LastCmd);
define_ol(offlenof_dvdst,
         struct rmmc_aux_dvdst, ((struct rmmc_aux_dvdst *) base)->nlayer);
define_ol(offlenof_layer, struct rmmc_aux_layer, LastDslData);

static inline struct rmmc_aux_discinfo *offlen_discinfo(struct rmmc_aux_file
                                                       aux[], u32 len[])
{
       return offlenof_aux(aux, DISC_INFO, len);
}
static inline struct rmmc_aux_dvdst *offlen_dvdst(struct rmmc_aux_file aux[],
                                                 u32 len[])
{
       return offlenof_aux(aux, DVD_STRUCTURE, len);
}
static inline struct rmmc_aux_tpa *offlen_tpa(struct rmmc_aux_file aux[],
                                             u32 len[])
{
       return offlenof_aux(aux, TOC_PMA_ATIP, len);
}
static inline struct rmmc_aux_rkey *offlen_rkey(struct rmmc_aux_file aux[],
                                               u32 len[])
{
       return offlenof_aux(aux, REPORT_KEY1, len);
}

static inline struct rmmc_aux_layer *offlen_layer(struct rmmc_aux_dvdst dvdst[],
                                                 int num, u32 len[])
{
       return offlenof_dvdst(dvdst, num, len);
}

static inline struct rmmc_aux_phys *offlen_phys(struct rmmc_aux_layer layer[],
                                               u32 len[])
{
       return offlenof_layer(layer, DslPhys, len);
}
static inline struct rmmc_aux_cprt *offlen_cprt(struct rmmc_aux_layer layer[],
                                               u32 len[])
{
       return offlenof_layer(layer, DslCprt, len);
}
static inline u8 *offlen_manuf(struct rmmc_aux_layer layer[], u32 len[])
{
       return offlenof_layer(layer, DslManuf, len);
}


typedef struct vr_request_s {
	unsigned char	vr_scsi_cdb[SCSI_CDB_SIZE]; /* SCSI CDB from iSCSI Command PDU */
	u8		vr_data_direction;	/* Data Direction */
	u32		vr_bufflen;		/* Total length of request */
	u32		vr_req_flags;		/* RD request flags */
	u32		vr_offset;		/* Offset from start of page */
	u32		vr_sg_count;		/* Scatterlist count */
	u32		vr_lba;			/* Logical Block Address */
	u64		vr_size;
	void		*vr_buf;		/* Data buffer containing scatterlists(s) or contingous memory segments. */
	struct vr_dev_s	*vr_dev;		/* FILEIO device */
} vr_request_t;

typedef struct vr_dev_s {
	unsigned char	vr_dev_name[VR_MAX_DEV_NAME];
	u32		vr_dev_id;		/* Uniqueu Ramdisk Device ID in Ramdisk HBA */
	u32		vr_table_count;		/* Number of SG tables in sg_table_array */
	u32		vr_queue_depth;
	u32		vr_blocksize;
	unsigned long long vr_dev_size;
	struct file	*vr_file;
	struct auxinfo *vr_auxinfo;
	struct vr_host_s *vr_host;		/* FILEIO HBA device is connected to */
	struct vr_dev_s *next;			/* Next FILEIO Device entry in list */
} vr_dev_t;

typedef struct vr_host_s {
	u32		vr_host_id;		/* Unique FILEIO Host ID */
	vr_dev_t	*vr_dev_head;		/* Start of FILEIO devices for this HBA */
	vr_dev_t	*vr_dev_tail;		/* Tail of FILEIO devices for this HBA */
	spinlock_t	vr_dev_lock;		/* Spinlock for controlling access to device list */
} vr_host_t;

#ifndef VR_INCLUDE_STRUCTS
/*
 * We use the generic command sequencer, so we must setup
 * iscsi_transport_spc_t.
 */
#define ISCSI_VROM_SPC {					\
	inquiry:		vr_CDB_inquiry,			\
	none:			vr_CDB_none,			\
	read_non_SG:		vr_CDB_read_non_SG,		\
	read_SG:		vr_CDB_read_SG,			\
	write_non_SG:		vr_CDB_write_non_SG,		\
	write_SG:		vr_CDB_write_SG,		\
};

iscsi_transport_spc_t vrom_template_spc = ISCSI_VROM_SPC;

#define ISCSI_VROM {						\
	name:			"vrom",				\
	type:			VROM,				\
	transport_type:		TRANSPORT_PLUGIN_VHBA_VDEV,	\
	attach_hba:		NULL,				\
	detach_hba:		fd_detach_hba,			\
	create_virtdevice:	vr_create_virtdevice,		\
	activate_device:	vr_activate_device,		\
	deactivate_device:	vr_deactivate_device,		\
	check_ghost_id:		fd_check_ghost_id,		\
	free_device:		vr_free_device,			\
	transport_complete:	vr_transport_complete,		\
	allocate_request:	vr_allocate_request,		\
	get_plugin_info:	vr_get_plugin_info,		\
	do_task:		vr_do_task,			\
	free_task:		vr_free_task,			\
	check_lba:		vr_check_lba,			\
	check_for_SG:		vr_check_for_SG,		\
	get_cdb:		vr_get_cdb,			\
	get_blocksize:		vr_get_blocksize,		\
	get_dma_length:		fd_get_dma_length,		\
	get_max_cdbs:		fd_get_max_cdbs,		\
	get_max_sectors:	vr_get_max_sectors,		\
	get_queue_depth:	vr_get_queue_depth,		\
	get_non_SG:		vr_get_non_SG,			\
	get_SG:			vr_get_SG,			\
	get_SG_count:		vr_get_SG_count,		\
	set_non_SG_buf:		vr_set_non_SG_buf,		\
	write_pending:		NULL,				\
	spc:			&vrom_template_spc,		\
};
	
iscsi_transport_t vrom_template = ISCSI_VROM;
#endif /* ! VR_INCLUDE_STRUCTS */

#endif /* ISCSI_TARGET_VROM_H */
