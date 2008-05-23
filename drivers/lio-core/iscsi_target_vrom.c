/*********************************************************************************
 * Filename:  iscsi_target_vrom.c
 *
 * This file contains the iSCSI <-> VirtualROM transport specific functions.
 *
 * Copyright (c) 2005 PyX Technologies, Inc.
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


#define ISCSI_TARGET_VROM_C

#include <linux/version.h>
#include <linux/string.h>
#include <linux/timer.h>
#include <linux/blkdev.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/smp_lock.h>
#include <scsi/scsi.h>
#include <scsi/scsi_host.h>
#include <linux/cdrom.h>
#include <linux/random.h>

#include <iscsi_linux_os.h> 
#include <iscsi_linux_defs.h>
                                
#include <iscsi_debug.h>
#include <iscsi_protocol.h>
#include <iscsi_target_core.h>
#include <iscsi_target_ioctl.h>
#include <iscsi_target_ioctl_defs.h>
#include <iscsi_target_device.h>
#include <iscsi_target_transport.h>
#include <iscsi_target_util.h>
#include <iscsi_target_file.h>
#include <iscsi_target_vrom.h>
#include <iscsi_target_error.h>

#include <iscsi_target_file.c>
 
extern iscsi_global_t *iscsi_global;

struct rmmc_conn global_conn;

int rmmc_initialize(struct rmmc_conn *mconn)
{
       u8 a[2];

       memset(mconn, 0, sizeof(struct rmmc_conn));
       get_random_bytes(a, 2);
       mconn->css.agid = a[0] & 3;
       mconn->css.variant = a[1] % 10;
       return 0;
}


#define AuxExt ".aux"

static int auxinfo_alloc(struct auxinfo *e, char *auxpath)
{
       struct file *filp = NULL;
       struct inode *inode;
       int n;

       if (!(e->auxpath = kmalloc(strlen(auxpath) + 1, GFP_KERNEL))) {
		TRACE_ERROR("Unable to allocate memory for auxpath\n");
		goto fail;
	}
       strcpy(e->auxpath, auxpath);

       filp = filp_open(auxpath, O_RDONLY | O_LARGEFILE, 0600);
       if (IS_ERR(filp)) {
		TRACE_ERROR("Unable to open auxpath: %s\n", auxpath);
		goto fail;
       }

       inode = filp->f_dentry->d_inode;

	if (!(e->auxfile = kmalloc(inode->i_size, GFP_KERNEL))) {
		TRACE_ERROR("Unable to allocate memory for auxfile\n");
		goto fail;
	}

       n = kernel_read(filp, 0, (void *) e->auxfile, inode->i_size);
       filp_close(filp, NULL);
       filp = NULL;
       if (n != inode->i_size) {
		TRACE_ERROR("kernel_read() failed: %d\n", n);
		goto fail;
	}

       INIT_LIST_HEAD(&e->list);
       atomic_set(&e->ref, 1);

	return(0);
fail:
	kfree(e->auxpath);
	kfree(e->auxfile);
	if (filp)
		filp_close(filp, NULL);
	return(-1);
}

static int getauxinfo(vr_dev_t *vd, char *path)
{
       int n = strlen(path);
       char auxpath[n + sizeof(AuxExt)];

       strcpy(auxpath, path);
       strcpy(auxpath + n, AuxExt);

       printk("creating aux for %s\n", auxpath);
       if (auxinfo_alloc(vd->vr_auxinfo, auxpath) < 0)
		return(-1);

#if 1
       {
               struct rmmc_aux_dvdst *dvdst;
               struct rmmc_aux_rkey *rkey;
               struct rmmc_aux_tk *tk;
               u32 len, res;

               res = -EDOM;
               PYXPRINT("%s %d\n",
                       vd->vr_auxinfo->auxfile->magic,
                       vd->vr_auxinfo->auxfile->version);
               dvdst = offlen_dvdst(vd->vr_auxinfo->auxfile, &len);
               if (!dvdst)
                       return(-1);
               PYXPRINT("layers %d\n", dvdst->nlayer);
               PYXPRINT("dk{%02x %02x %02x %02x %02x}\n",
                       dvdst->dkey[4 + 0], dvdst->dkey[4 + 1],
                       dvdst->dkey[4 + 2], dvdst->dkey[4 + 3],
                       dvdst->dkey[4 + 4]);
               rkey = offlen_rkey(vd->vr_auxinfo->auxfile, &len);
               if (!rkey)
                       return(-1);
               PYXPRINT("titles %d\n", be32_to_cpu(rkey->ntitle));
               tk = rkey->data;
               if (!tk)
                       return(-1);
               PYXPRINT("tk[0]{%02x %02x %02x %02x %02x}\n",
                       tk->tk[0], tk->tk[1], tk->tk[2], tk->tk[3], tk->tk[4]);
       }
#endif
	return(0);
}


/*	vr_create_virtdevice(): (Part of iscsi_transport_t template)
 *
 *
 */
int vr_create_virtdevice (se_hba_t *iscsi_hba, iscsi_devinfo_t *di)
{
	char *dev_p;
	se_device_t *dev;
	vr_dev_t *vr_dev;
	vr_host_t *vr_host = (vr_host_t *) iscsi_hba->hba_ptr;
	mm_segment_t old_fs;
	struct inode *inode;
	
	if (strlen(di->vr_dev_name) > VR_MAX_DEV_NAME) {
		TRACE_ERROR("di->vr_dev_name exceeds VR_MAX_DEV_NAME: %d\n",
				VR_MAX_DEV_NAME);
		return(0);
	}

	if (!(vr_dev = (vr_dev_t *) MALLOC_NORMAL(sizeof(vr_dev_t)))) {
		TRACE_ERROR("Unable to allocate memory for vr_dev_t\n");
		return(0);
	}
	memset(vr_dev, 0, sizeof(vr_dev_t));

	if (!(vr_dev->vr_auxinfo = MALLOC_NORMAL(sizeof(struct auxinfo)))) {
		TRACE_ERROR("Unable to allocate memory for vr_auxinfo\n");
		goto fail;
	}
	memset(vr_dev->vr_auxinfo, 0, sizeof(struct auxinfo));

	vr_dev->vr_dev_id = di->vr_device_id;
	vr_dev->vr_host = vr_host;
	sprintf(vr_dev->vr_dev_name, "%s", di->vr_dev_name);
	
	old_fs = get_fs();
	set_fs(get_ds());
	dev_p = getname(vr_dev->vr_dev_name);	
	set_fs(old_fs);

	putname(dev_p);

	if (IS_ERR(dev_p)) {
		TRACE_ERROR("getname(%s) failed: %lu\n", vr_dev->vr_dev_name,
				IS_ERR(dev_p));
		goto fail;
	}
	
	if (!(vr_dev->vr_file = filp_open(dev_p,  O_RDONLY | O_LARGEFILE, 0600))) {
		TRACE_ERROR("filp_open(%s) failed\n", dev_p);
		goto fail;
	}
	if (IS_ERR(vr_dev->vr_file)) {
		TRACE_ERROR("filp_open(%s) returned %d\n", dev_p, IS_ERR(vr_dev->vr_file));
		vr_dev->vr_file = NULL;
		goto fail;
	}
	
	inode = vr_dev->vr_file->f_dentry->d_inode;
	if (S_ISREG(inode->i_mode)) {
		;
	} else if (S_ISBLK(inode->i_mode)) {
		inode = inode->i_bdev->bd_inode;	
	} else {
		TRACE_ERROR("%s cannot be exported as a virtual ROM\n", dev_p);
		goto fail;
	}

	if ((getauxinfo(vr_dev, dev_p))) {
		TRACE_ERROR("getauxinfo() failed\n");
		goto fail;
	}

	vr_dev->vr_dev_size = inode->i_size;
	vr_dev->vr_blocksize = VR_BLOCKSIZE;
	rmmc_initialize(&global_conn);

	if (!(dev = vr_add_device_to_list(iscsi_hba, vr_dev)))
		goto fail;

	vr_dev->vr_queue_depth = dev->queue_depth;
	
	spin_lock(&vr_host->vr_dev_lock);
	if (!vr_host->vr_dev_head && !vr_host->vr_dev_tail)
		vr_host->vr_dev_head = vr_dev;
	else
		vr_host->vr_dev_tail->next = vr_dev;
	vr_host->vr_dev_tail = vr_dev;
	spin_unlock(&vr_host->vr_dev_lock);
	
	PYXPRINT("iSCSI_VROM[%u] - Added PyX VirtualROM Device ID: %u at %s,"
		" %llu total bytes\n", vr_host->vr_host_id, vr_dev->vr_dev_id,
			vr_dev->vr_dev_name, vr_dev->vr_dev_size);

	return(1);

fail:
	if (vr_dev->vr_file) {
		filp_close(vr_dev->vr_file, NULL);
		vr_dev->vr_file = NULL;
	}
	
	kfree(vr_dev->vr_auxinfo);
	kfree(vr_dev);

	return(0);
}

/*	vr_add_device_to_list():
 *
 *
 */
se_device_t *vr_add_device_to_list (se_hba_t *iscsi_hba, void *vr_dev_p)
{
	se_device_t *dev;
	vr_dev_t *vr_dev = (vr_dev_t *) vr_dev_p;
	
	if (!(dev = transport_add_device_to_iscsi_hba(iscsi_hba, &vrom_template,
			DF_DISABLE_STATUS_THREAD, (void *)vr_dev)))
		return(NULL);

	return(dev);
}

/*	vr_activate_device(): (Part of iscsi_transport_t template)
 *
 *
 */
int vr_activate_device (se_device_t *dev)
{
	vr_dev_t *vr_dev = (vr_dev_t *) dev->dev_ptr;
	vr_host_t *vr_host = vr_dev->vr_host;
	
	PYXPRINT("iSCSI_VROM[%u] - Activating Device with TCQ: %d at VirtualROM"
		" Device ID: %d\n", vr_host->vr_host_id, vr_dev->vr_queue_depth,
		vr_dev->vr_dev_id);

	return(0);
}

/*	vr_deactivate_device(): (Part of iscsi_transport_t template)
 *
 *
 */
void vr_deactivate_device (se_device_t *dev)
{
	vr_dev_t *vr_dev = (vr_dev_t *) dev->dev_ptr;
	vr_host_t *vr_host = vr_dev->vr_host;

	PYXPRINT("iSCSI_VROM[%u] - Deactivating Device with TCQ: %d at VirtualROM"
		" Device ID: %d\n", vr_host->vr_host_id, vr_dev->vr_queue_depth,
		vr_dev->vr_dev_id);

	return;
}

/*	vr_free_device(): (Part of iscsi_transport_t template)
 *
 *
 */
void vr_free_device (se_device_t *dev)
{
	vr_dev_t *vr_dev = (vr_dev_t *) dev->dev_ptr;

	if (vr_dev->vr_file) {
		filp_close(vr_dev->vr_file, NULL);
		vr_dev->vr_file = NULL;
	}
	
	kfree(vr_dev->vr_auxinfo);
	kfree(vr_dev);

	return;
}

/*	vr_transport_complete(): (Part of iscsi_transport_t template)
 *
 *
 */
int vr_transport_complete (se_task_t *task)
{
	return(0);
}

/*	vr_allocate_request(): (Part of iscsi_transport_t template)
 *
 *
 */
void *vr_allocate_request (
	se_task_t *task,
	se_device_t *dev)
{
	vr_request_t *vr_req;
	
	if (!(vr_req = (vr_request_t *) MALLOC_NORMAL(sizeof(vr_request_t)))) {
		TRACE_ERROR("Unable to allocate vr_request_t\n");
		return(NULL);
	}
	memset(vr_req, 0, sizeof(vr_request_t));

	vr_req->vr_dev = (vr_dev_t *) dev->dev_ptr;
	memcpy((void *)vr_req->vr_scsi_cdb, (void *)task->task_cdb, SCSI_CDB_SIZE);

	return((void *)vr_req);
}

static inline struct rmmc_aux_tk *findtk(struct rmmc_conn *mconn,
                                        struct rmmc_aux_rkey *rkey, u32 lba)
{
       struct rmmc_aux_tk *tk, *o;
       int n, old;

       o = rkey->data;
       n = be32_to_cpu(rkey->ntitle);
       old = mconn->lasttk;

       tk = o + mconn->lasttk;
       for (; mconn->lasttk < n; mconn->lasttk++, tk++) {
               if (be32_to_cpu(tk->lba[0]) <= lba
                   && lba <= be32_to_cpu(tk->lba[1]))
                       return tk;
	 }

       mconn->lasttk = 0;
       tk = o;
      for (; mconn->lasttk < old; mconn->lasttk++, tk++) {
               if (be32_to_cpu(tk->lba[0]) <= lba
                   && lba <= be32_to_cpu(tk->lba[1]))
                       return tk;
      }

       return NULL;
}


/*	vr_emulate_inquiry():
 *
 *
 */
void vr_emulate_inquiry (se_task_t *task)
{
	unsigned char *buf;
	vr_request_t *vr_req = (vr_request_t *) task->transport_req;
	
	buf = (unsigned char *) vr_req->vr_buf;
	memset(buf, 0, vr_req->vr_bufflen);
	buf[0]		= TYPE_ROM;
	buf[1]		= 0x80;
	buf[2]		= 0x02;
	buf[3]		= 0x40;
	sprintf((char *)&buf[8], "PYX-TECH");
	sprintf((char *)&buf[16], "VIRTUAL_ROM");
	sprintf((char *)&buf[32], "01  ");	

	return;
}

/*	vr_emulate_read_cap():
 *
 *
 */
void vr_emulate_read_cap (se_task_t *task)
{
	unsigned char *buf;
	unsigned long long blocks;
	vr_dev_t *vr_dev = (vr_dev_t *) task->iscsi_dev->dev_ptr;
	vr_request_t *vr_req = (vr_request_t *) task->transport_req;
#if 1
	blocks = (vr_dev->vr_dev_size / VR_BLOCKSIZE) - 1;
#else
	blocks = (vr_dev->vr_dev_size / vr_dev->vr_blocksize) - 1;
#endif
	buf = (unsigned char *) vr_req->vr_buf;
	memset(buf, 0, vr_req->vr_bufflen);
	buf[0]		= (blocks >> 24) & 0xff;
	buf[1]		= (blocks >> 16) & 0xff;
	buf[2]		= (blocks >> 8) & 0xff;
	buf[3]		= blocks & 0xff;
	buf[4]		= (vr_dev->vr_blocksize >> 24) & 0xff;
	buf[5]		= (vr_dev->vr_blocksize >> 16) & 0xff;
	buf[6]		= (vr_dev->vr_blocksize >> 8) & 0xff;
	buf[7]		= vr_dev->vr_blocksize & 0xff;
	
	return;
}

/*	vr_emulate_mode_sense_10():
 *
 *
 */
int vr_emulate_mode_sense_10 (se_task_t *task)
{
	unsigned char *cdb;
	unsigned char *buf;
	vr_request_t *vr_req = (vr_request_t *) task->transport_req;

	cdb = (unsigned char *)&vr_req->vr_scsi_cdb[0];
	buf = (unsigned char *) vr_req->vr_buf;

	switch (cdb[2] & 0x3f) {
	case GPMODE_CAPABILITIES_PAGE:
		buf[0] = (28 + 4);
		buf[1] = 0x71;
		buf[4] = cdb[2] & 0x3f; /* PS = 0 */
#if 0
		buf[0] = 0x80 | cdb[2] & 0x3f; /* PS = 1 */
#endif
		buf[5] = 28; /* Length */
		buf[6] = 0x08; /* DVD-ROM */
#if 0
		buf[7] = 0x3f; /* Read All DVD */
		buf[9] = 1; /* Audio Play */
#endif
		buf[27] = 1; /* CSS/CPRM */
		break;
#if 0
	case GPMODE_AUDIO_CTL_PAGE:
		break;
#endif
	default:
		TRACE_ERROR("Unsupported Mode Page: 0x%02x for VirtualROM"
			" Plugin\n", cdb[2] & 0x3f);
		return(-1);
	}

	return(0);
}

/*	vr_emulate_read_dvd_structure():
 *
 * 
 */
int vr_emulate_read_dvd_structure (se_task_t *task)
{
	u8 num, *manuf;
	u32 len;
	unsigned char *cdb;
	unsigned char *buf;
	vr_dev_t *vd = (vr_dev_t *) task->iscsi_dev->dev_ptr;
	vr_request_t *vr_req = (vr_request_t *) task->transport_req;
	struct scatterlist *sg = (struct scatterlist *) vr_req->vr_buf;
	struct rmmc_aux_file *aux;
	struct rmmc_aux_dvdst *dvdst;
	struct rmmc_aux_layer *layer;
	struct rmmc_aux_phys *phys;
	struct rmmc_aux_cprt *cprt;
	struct rmmc_css *css;
	enum { Phys, Cprt, DKey,
		Burst_Cutting_Area,
		Manufacturing,
		Cprt_Management,
		Media_Identifier,
		Media_Key,
		ADIP = 0x11,
		Disc_Control = 0x30,
		READ_SEND_DVD_STRUCTURE = 0xff
	};

	cdb = (unsigned char *)&vr_req->vr_scsi_cdb[0];
	buf = page_address(sg->page);
	num = cdb[6];

	if (!(aux = vd->vr_auxinfo->auxfile)) {
		TRACE_ERROR("vd->vr_auxinfo->auxfile is NULL\n");
		return(-1);
	}

	if (!(dvdst = offlen_dvdst(aux, &len))) {
		TRACE_ERROR("offlen_dvdst() failed\n");
		return(-1);
	}

	if (!(layer = offlen_layer(dvdst, num, &len))) {
		TRACE_ERROR("offlen_layer() failed\n");
		return(-1);
	}

	switch (cdb[7]) {
	case Phys:
		if (!(phys = offlen_phys(layer, &len))) {
			TRACE_ERROR("offlen_phys() failed\n");
			return(-1);
		}
		TRACE_ERROR("Phys:\n");
		memcpy(buf, phys, len);
		break;
	case Cprt:
		if (!(cprt = offlen_cprt(layer, &len))) {
			TRACE_ERROR("offlen_cprt() failed\n");
			return(-1);
		}
		TRACE_ERROR("Cprt:\n");
		memcpy(buf, cprt, len);
		break;
	case DKey:
		css = &global_conn.css;
		if (!css->authed) {
			TRACE_ERROR("!css->authed\n");
			return(-1);
		}
		TRACE_ERROR("DKey:\n");
		len = sizeof(dvdst->dkey);
		memcpy(buf, dvdst->dkey, 4);
		encbybuskey(buf + 4, dvdst->dkey + 4, len - 4, css);
		break;
	case Manufacturing:
		TRACE_ERROR("Manufacturing:\n");
		if (!(manuf = offlen_manuf(layer, &len))) {
			TRACE_ERROR("offlen_manuf() failed\n");
			return(-1);
		}
		memcpy(buf, manuf, len);
		break;
	default:
		TRACE_ERROR("Unsupported format: 0x%02x\n", cdb[7]);
		return(-1);
	}

	return(0);
}

/*	vr_emulate_read_disc_info():
 *
 *
 */
int vr_emulate_read_disc_info (se_task_t *task)
{
	u32 len;
	unsigned char *buf;
        vr_dev_t *vd = (vr_dev_t *) task->iscsi_dev->dev_ptr;
	vr_request_t *vr_req = (vr_request_t *) task->transport_req;
	struct scatterlist *sg = (struct scatterlist *) vr_req->vr_buf;
	struct rmmc_aux_file *aux;
	struct rmmc_aux_discinfo *di;

	buf = page_address(sg->page);
        if (!(aux = vd->vr_auxinfo->auxfile)) {
		TRACE_ERROR("vd->vr_auxinfo->auxfile is NULL\n");
		return(-1);
	}

	if (!(di = offlen_discinfo(aux, &len))) {
		TRACE_ERROR("offlen_discinfo() failed\n");
		return(-1);
	}
	if (len > task->task_size) {
		TRACE_ERROR("Disc Info Length: %d exceeds task_size: %d\n", len, task->task_size);
		return(-1);
	}
	memcpy(buf, di, len);

	return(0);
}

/*	vr_emulate_read_toc():
 *
 *
 */
int vr_emulate_read_toc (se_task_t *task)
{
	u32 len = 0;
	unsigned char *cdb;
	unsigned char *buf;
	unsigned int blocks;
	vr_dev_t *vd = (vr_dev_t *) task->iscsi_dev->dev_ptr;
	vr_request_t *vr_req = (vr_request_t *) task->transport_req;
#if 1
	blocks = (vd->vr_dev_size / VR_BLOCKSIZE) - 1;
#else
	blocks = (vd->vr_dev_size / vd->vr_blocksize) - 1;
#endif
	cdb = (unsigned char *)&vr_req->vr_scsi_cdb[0];
	buf = (unsigned char *) vr_req->vr_buf;

	PYXPRINT("time %d, format %x, tr/sess-num %02x, "
               "al-len %02x %02x, ctrl %02x\n",
               ((cdb[1] >> 1) & 1), cdb[2] & 0x0f, cdb[6], cdb[7], cdb[8], cdb[9]);

	TRACE_ERROR("vr_req->vr_bufflen: %d\n", vr_req->vr_bufflen);
	switch (cdb[2] & 0x0f) {
	case 0:
		if (vr_req->vr_bufflen >= 20) {
			buf[1] = 0x12;
			buf[2] = buf[3] = buf[6] = 1;
			buf[5] = buf[13] = 0x14;
			buf[14] = 0xaa;

			if ((cdb[1] >> 1) & 1) {
				memcpy((void *)&buf[8], (void *)cpu_to_be32(0x00000200), 4);	
				memcpy((void *)&buf[16], (void *)cpu_to_be32(0x00ff3b4a), 4);
			} else {
				buf[16] = (blocks >> 24) & 0xff;
				buf[17] = (blocks >> 16) & 0xff;
				buf[18] = (blocks >> 8) & 0xff;
				buf[19] = blocks & 0xff;
			}
		} else {
			buf[1] = 0x12;
			buf[2] = buf[3] = buf[6] = 1;
			buf[5] = 0x14;
		}
		break;
	case 1:
		len = 12;
		memset(buf, 0, len);
		buf[1] = 0x0a;
		buf[2] = buf[3] = buf[6] = 1;
		buf[5] = 0x14;
		if ((cdb[1] >> 1) & 1) {
			TRACE_ERROR("#6\n");
			memcpy((void *)&buf[7], (void *)cpu_to_be32(0x00000200), 4);
			TRACE_ERROR("#7\n");
		}
		break;
	default:
		TRACE_ERROR("Unsupported Format: 0x%02x for VirtualROM"
			" Plugin\n", cdb[2] & 0x0f);
		return(-1);
	}

	return(0);
}

/*	vr_emulate_report_key():
 *
 *
 */
int vr_emulate_report_key (se_task_t *task)
{
	u32 len, lba;
	unsigned char *cdb;
	unsigned char *buf;
	vr_dev_t *vd = (vr_dev_t *) task->iscsi_dev->dev_ptr;
	vr_request_t *vr_req = (vr_request_t *) task->transport_req;
	struct scatterlist *sg = (struct scatterlist *) vr_req->vr_buf;
	struct rmmc_css *css;
	struct rmmc_aux_file *aux;
	struct rmmc_aux_rkey *rkey;
	struct rmmc_aux_tk *tk;
	enum { Agid_CSS_CPPM, ChalKey, Key1,
		TitleKey = 0x04,
		ASF,
		RPCState = 0x08,
		AGID_CPRM = 0x11,
		None = 0x3f
	};

	cdb = (unsigned char *)&vr_req->vr_scsi_cdb[0];
	buf = page_address(sg->page);
	css = &global_conn.css;
	memset(buf, 0, task->task_size);

	switch (cdb[7]) {
	case 0x00:
		break;
	default:
		TRACE_ERROR("Unsupported Key Class: 0x%02x\n", cdb[7]);
		return(-1);
	}

	switch (cdb[10] & 0x3f) {
	case RPCState:
		PYXPRINT("RPCState:\n");
		buf[4] = 0xc0; /* type = 11h, vra = 0, ucca = 0 */
//		buf[5] = 0xfd; /* region mask */
		buf[5] = 0xfe;
		buf[6] = 0x01; /* rpc scheme */
		buf[1] = 0x06;
		break;
	case None:
		PYXPRINT("None\n");
		break;
	case Agid_CSS_CPPM:
		PYXPRINT("Agid_CSS_CPPM:\n");
		PYXPRINT("css->agid: %d\n", css->agid);
		buf[7] = css->agid << 6;
		buf[1] = 0x06;
		break;
	case Key1:
		PYXPRINT("Key1:\n");
		memcpy((void *)&buf[4], (void *)genkey1(css), CSSKey1Len);
#if 0
		PYXPRINT("buf[4]: 0x%02x %02x %02x %02x %02x\n", buf[4], buf[5], buf[6], buf[7], buf[8]);
#endif
		buf[1] = 0x0a;
		break;
	case ChalKey:
		PYXPRINT("ChalKey:\n");
		get_random_bytes(css->chal, sizeof(css->chal));
		memcpy((void *)&buf[4], (void *)css->chal, sizeof(css->chal));
#if 0
		PYXPRINT("buf[4]: 0x%02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x\n",
			buf[4], buf[5], buf[6], buf[7], buf[8], buf[9], buf[10], buf[11], buf[12], buf[13], buf[14]);
#endif
		buf[1] = 0x0e;
		break;
	case ASF:
		PYXPRINT("ASF:\n");
		buf[7] = css->authed;
		buf[1] = 0x06;
		break;
	case TitleKey:
		PYXPRINT("TitleKey:\n");
		if (!css->authed || css->agid != (cdb[10] >> 6)) {
			TRACE_ERROR("Invalid CSS Authentication\n");
			return(-1);
		}
		
		if (!(aux = vd->vr_auxinfo->auxfile)) {
			TRACE_ERROR("vd->vr_auxinfo->auxfile is NULL\n");
			return(-1);
		}

		if (!(rkey = offlen_rkey(aux, &len))) {
			TRACE_ERROR("offlen_rkey() failed\n");
			return(-1);
		}

		lba = (cdb[2] << 24) | (cdb[3] << 16) | (cdb[4] << 8) | cdb[5];
		
		if (!(tk = findtk(&global_conn, rkey, lba))) {
			TRACE_ERROR("findtk() failed\n");
			return(-1);
		}

		buf[4] = tk->cpbits;
		encbybuskey(&buf[5], tk->tk, sizeof(tk->tk), css);
		buf[1] = 0x0a;
		break;
	default:
		TRACE_ERROR("Unsupported Key Format 0x%02x for VirtualROM"
			" Plugin\n", cdb[10] & 0x3f);
		return(-1);
	}

	return(0);
}

/*	vr_emulate_send_key():
 *
 *
 */
int vr_emulate_send_key (se_task_t *task)
{
	u32 len = task->task_size;
	unsigned char *cdb;
	unsigned char *buf; 
	vr_request_t *vr_req = (vr_request_t *) task->transport_req;
	struct scatterlist *sg = (struct scatterlist *) vr_req->vr_buf;
	struct rmmc_css *css;

	cdb = (unsigned char *)&vr_req->vr_scsi_cdb[0];

	if (cdb[7]) {
		TRACE_ERROR("Unsupported Key Class: 0x%02x\n", cdb[7]);
		return(-1);
	}

	if (!vr_req->vr_bufflen) {
		PYXPRINT("vr_req->vr_bufflen is zero for format: 0x%02x\n", cdb[10] & 0x3f);
		return(0);
	}

	css = &global_conn.css;
	buf = page_address(sg->page);

	switch (cdb[10] & 0x3f) {
	case 0x01:	/* challenge key */
		if (len < sizeof(css->chal) + 2) {
			TRACE_ERROR("Length failed\n");
			return(-1);
		}
#if 0
		TRACE_ERROR("0x%02x %02x %02x %02x %02x %02x %02x %02x %02x %02x\n",
				buf[4], buf[5], buf[6], buf[7], buf[8], buf[9], buf[10],
				buf[11], buf[12], buf[13]);
#endif
		memcpy((void *)css->chal, (void *)&buf[4], sizeof(css->chal));
		break;
	case 0x03:	/* key 2 */
		PYXPRINT("key 2\n");
		css->authed = 0;
		if (len < CSSKey2Len + 2) {
			TRACE_ERROR("Length failed\n");
			return(-1);
		}
		genkey2(css);
		css->authed = !memcmpkey2(css, (u8 *)&buf[4]);
		if (!css->authed) {
			TRACE_ERROR("DVD-CSS Authentication failed\n");
			break;
		}
		genbuskey(css);
		break;
	case 0x06:	/* rpc struct */
		PYXPRINT("rpc struct\n");
		return(0);
	case 0x3f:	/* invalidate agid */
		PYXPRINT("invalidate agid\n");
		return(0);
	default:
		TRACE_ERROR("Unsupported Key Format: 0x%02x\n", cdb[10] & 0x3f);
		return(-1);
	}

	return(0);
}

/*	vr_emulate_scsi_cdb():
 *
 *
 */
int vr_emulate_scsi_cdb (se_task_t *task)
{
	vr_request_t *vr_req = (vr_request_t *) task->transport_req;

	switch (vr_req->vr_scsi_cdb[0]) {
	case INQUIRY:
		PYXPRINT("INQUIRY:\n");
		vr_emulate_inquiry(task);
		break;
	case READ_CAPACITY:
		PYXPRINT("READ_CAPACITY:\n");
		vr_emulate_read_cap(task);
		break;
	case MODE_SENSE:
	case MODE_SENSE_10:
		PYXPRINT("MODE_SENSE\n");
		vr_emulate_mode_sense_10(task);
		break;
	case READ_DVD_STRUCTURE:
		PYXPRINT("READ_DVD_STRUCTURE:\n");
		vr_emulate_read_dvd_structure(task);
		break;
	case READ_DISK_INFORMATION:
		PYXPRINT("READ_DISK_INFORMATION:\n");
		vr_emulate_read_disc_info(task);
		break;
	case READ_TOC:
		PYXPRINT("READ_TOC:\n");
		vr_emulate_read_toc(task);
		break;
	case REPORT_KEY:
		PYXPRINT("REPORT_KEY:\n");
		vr_emulate_report_key(task);
		break;
	case SEND_KEY:
		PYXPRINT("SEND_KEY:\n");
		vr_emulate_send_key(task);
		break;
	case ALLOW_MEDIUM_REMOVAL:
	case ERASE:
	case LOAD_UNLOAD_MEDIUM:
	case REZERO_UNIT:
	case SEEK_10:
	case SPACE:
	case START_STOP:
	case SYNCHRONIZE_CACHE:
	case TEST_UNIT_READY:
	case VERIFY:
	case WRITE_FILEMARKS:
		break;
	default:
		TRACE_ERROR("Unsupported SCSI Opcode: 0x%02x for VirtualROM Plugin\n",
				vr_req->vr_scsi_cdb[0]);
		return(PYX_TRANSPORT_UNKNOWN_SAM_OPCODE);
	}

	task->task_scsi_status = GOOD;
	transport_complete_task(task, 1);
	
	return(PYX_TRANSPORT_SENT_TO_TRANSPORT);
}

int vr_do_read (vr_request_t *req)
{
	int ret = 0;
	u32 i;
	unsigned char *buf;
	struct file *fd = req->vr_dev->vr_file;
	struct scatterlist *sg = (struct scatterlist *) req->vr_buf;
	mm_segment_t old_fs;
	u64 lba = req->vr_lba, offset = 0;

	for (i = 0; i < req->vr_sg_count; i++) {
		old_fs = get_fs();
		set_fs(get_ds());
		if (fd->f_op->llseek)
			offset = fd->f_op->llseek(fd, lba * VR_BLOCKSIZE, 0);
		else
			offset = default_llseek(fd, lba * VR_BLOCKSIZE, 0);
		set_fs(old_fs);
		
		if (offset != (lba * VR_BLOCKSIZE)) {
			TRACE_ERROR("offset: %llu not equal to LBA: %llu\n",
				offset, (lba * VR_BLOCKSIZE));
			return(-1);
		}

		if (!(buf = vr_get_SG_page(&sg[i])))
			return(-1);
		
		old_fs = get_fs();
		set_fs(get_ds());
		if ((ret = fd->f_op->read(fd, buf, sg[i].length, &fd->f_pos)) < 0) {
			TRACE_ERROR("fd->f_op->read() returned %d\n", ret);
			set_fs(old_fs);
			return(-1);
		}
		set_fs(old_fs);

		lba += (sg[i].length / VR_BLOCKSIZE);
	}

	return(0);
}
#if 0
tatic int fd_do_write (fd_request_t *req)
{
	int ret = 0;
	u32 i;
	unsigned char *buf;
	struct file *fd = req->vr_dev->fd_file;
	struct scatterlist *sg = (struct scatterlist *) req->vr_buf;
	mm_segment_t old_fs;
	u64 lba = req->fd_lba, offset = 0;

	for (i = 0; i < req->fd_sg_count; i++) {
		old_fs = get_fs();
		set_fs(get_ds());
		if (fd->f_op->llseek)
			offset = fd->f_op->llseek(fd, lba * FD_BLOCKSIZE, 0);
		else
			offset = default_llseek(fd, lba * FD_BLOCKSIZE, 0);
		set_fs(old_fs);

		if (offset != (lba * FD_BLOCKSIZE)) {
			TRACE_ERROR("offset: %llu not equal to LBA: %llu\n",
				offset, (lba * FD_BLOCKSIZE));
			return(-1);
		}

		if (!(buf = fd_get_SG_page(&sg[i])))
			return(-1);

		old_fs = get_fs();
		set_fs(get_ds());
		if ((ret = fd->f_op->write(fd, buf, sg[i].length, &fd->f_pos)) < 0) {
			TRACE_ERROR("fd->f_op->write returned %d\n", ret);
			set_fs(old_fs);
			return(-1);
		}
		set_fs(old_fs);

		lba += (sg[i].length / FD_BLOCKSIZE);
	}

	return(0);
}
#endif
int vr_do_task (se_task_t *task)
{
	int ret;
	vr_request_t *req = (vr_request_t *) task->transport_req;

	if (!(task->iscsi_cmd->cmd_flags & ICF_SCSI_DATA_SG_IO_CDB))
		return(vr_emulate_scsi_cdb(task));

	req->vr_size = task->task_size;

	if (req->vr_data_direction == VR_DATA_READ)
		ret = vr_do_read(req);
	else
#if 0
		ret = vr_do_write(req);
#else
		return(PYX_TRANSPORT_UNKNOWN_SAM_OPCODE);
#endif

	if (ret != 0)       
		return(ret);

	task->task_scsi_status = GOOD;   
	transport_complete_task(task, 1);

	return(PYX_TRANSPORT_SENT_TO_TRANSPORT);
}

/*	vr_free_task(): (Part of iscsi_transport_t template)
 *
 *
 */
void vr_free_task (se_task_t *task)
{
	vr_request_t *req;

	req = (vr_request_t *) task->transport_req;
	kfree(req);
	
	return;
}

extern void vr_get_plugin_info (void *p, char *b, int *bl)
{
        *bl += sprintf(b+*bl, "; %s }---[ Virtual-CD_ROM + DVD_ROM Plugin ]--[%s]--:\n", PYX_ISCSI_VENDOR, VR_VERSION);

        return;
}


/*	vr_map_task_non_SG():
 *
 *
 */
void vr_map_task_non_SG (se_task_t *task)
{
	iscsi_cmd_t *cmd = task->iscsi_cmd;
	vr_request_t *req = (vr_request_t *) task->transport_req;

	req->vr_bufflen		= task->task_size;
	req->vr_buf		= (void *) T_TASK(cmd)->t_task_buf;
	req->vr_sg_count	= 0;
	
	return;
}

/*	vr_map_task_SG():
 *
 *
 */
void vr_map_task_SG (se_task_t *task)
{
	iscsi_cmd_t *cmd = task->iscsi_cmd;
	vr_request_t *req = (vr_request_t *) task->transport_req;

	req->vr_bufflen		= task->task_size;
	req->vr_buf		= (void *)task->task_buf;
	req->vr_sg_count	= task->task_sg_num;

	return;
}

/*      vr_CDB_inquiry():
 *
 *
 */
int vr_CDB_inquiry (se_task_t *task, u32 size)
{      
	vr_request_t *req = (vr_request_t *) task->transport_req;
		        
	req->vr_data_direction  = VR_DATA_READ;
			        
	/*
	 * This causes 255 instead of the requested 256 bytes
	 * to be returned.  This can be safely ignored for now,
	 * and take the Initiators word on INQUIRY data lengths.
	 */
#if 0
	cmd->data_length	= req->vr_bufflen;
#endif
	vr_map_task_non_SG(task);

	return(0);
}

/*      vr_CDB_none():
 *
 *
 */
int vr_CDB_none (se_task_t *task, u32 size)
{
	vr_request_t *req = (vr_request_t *) task->transport_req;

	req->vr_data_direction	= VR_DATA_NONE;
	req->vr_bufflen		= 0;
	req->vr_sg_count	= 0;
	req->vr_buf		= NULL;

	return(0);
}

/*	vr_CDB_read_non_SG():
 *
 *
 */
int vr_CDB_read_non_SG (se_task_t *task, u32 size)
{
	vr_request_t *req = (vr_request_t *) task->transport_req;

	req->vr_data_direction = VR_DATA_READ;
	vr_map_task_non_SG(task);

	return(0);
}

/*	vr_CDB_read_SG):
 *
 *
 */
int vr_CDB_read_SG (se_task_t *task, u32 size)
{
	vr_request_t *req = (vr_request_t *) task->transport_req;

	req->vr_data_direction = VR_DATA_READ;
	vr_map_task_SG(task);

	return(req->vr_sg_count);
}

/*	vr_CDB_write_non_SG():
 *
 *
 */
int vr_CDB_write_non_SG (se_task_t *task, u32 size)
{
	vr_request_t *req = (vr_request_t *) task->transport_req;
	
	req->vr_data_direction = VR_DATA_WRITE;
	vr_map_task_non_SG(task);
	
	return(0);
}

/*	vr_CDB_write_SG():
 *
 *
 */
int vr_CDB_write_SG (se_task_t *task, u32 size)
{
	vr_request_t *req = (vr_request_t *) task->transport_req;

	req->vr_data_direction = VR_DATA_WRITE;
	vr_map_task_SG(task);

	return(req->vr_sg_count);
}

/*	vr_check_lba():
 *
 *
 */
int vr_check_lba (iscsi_lba_t lba, se_device_t *dev)
{
	return(0);
}

/*	vr_check_for_SG(): (Part of iscsi_transport_t template)
 *
 *
 */
int vr_check_for_SG (se_task_t *task)
{
	vr_request_t *req = (vr_request_t *) task->transport_req;
	
	return(req->vr_sg_count);
}

/*	vr_get_cdb(): (Part of iscsi_transport_t template)
 *
 *
 */
unsigned char *vr_get_cdb (se_task_t *task)
{
	vr_request_t *req = (vr_request_t *) task->transport_req;

	return(req->vr_scsi_cdb);
}

/*	vr_get_blocksize(): (Part of iscsi_transport_t template)
 *
 *
 */
u32 vr_get_blocksize (se_device_t *dev)
{
	vr_dev_t *vr_dev = (vr_dev_t *) dev->dev_ptr;

	return(vr_dev->vr_blocksize);
}

/*	vr_get_max_sectors(): (Part of iscsi_transport_t template)
 *
 *
 */
u32 vr_get_max_sectors (se_device_t *dev)
{
	return(VR_MAX_SECTORS);
}

/*	vr_get_queue_depth(): (Part of iscsi_transport_t template)
 *
 *
 */
u32 vr_get_queue_depth (se_device_t *dev)
{
	return(VR_DEVICE_QUEUE_DEPTH);
}

/*	vr_get_non_SG(): (Part of iscsi_transport_t template)
 *
 *
 */
unsigned char *vr_get_non_SG (se_task_t *task)
{
	vr_request_t *req = (vr_request_t *) task->transport_req;

	return((unsigned char *)req->vr_buf);
}

/*	vr_get_SG(): (Part of iscsi_transport_t template)
 *
 *
 */
struct scatterlist *vr_get_SG (se_task_t *task)
{
	vr_request_t *req = (vr_request_t *) task->transport_req;

	return((struct scatterlist *)req->vr_buf);
}

/*	vr_get_SG_count(): (Part of iscsi_transport_t template)
 *
 *
 */
u32 vr_get_SG_count (se_task_t *task)
{
	return(0);
}

/*	vr_set_non_SG_buf():
 *
 *
 */
int vr_set_non_SG_buf (unsigned char *buf, se_task_t *task)
{
	vr_request_t *req = (vr_request_t *) task->transport_req;
	
	req->vr_buf		= (void *) buf;
	req->vr_bufflen         = task->task_size;
	req->vr_sg_count        = 0;

	return(0);
}
