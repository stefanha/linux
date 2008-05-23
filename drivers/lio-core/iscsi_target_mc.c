/*********************************************************************************
 * Filename:  iscsi_target_mc.c
 *
 * This file contains the iSCSI <-> media changer transport specific functions.
 *
 * Copyright (c) 2006 SBE, Inc.  All Rights Reserved.
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


#define ISCSI_TARGET_MC_C

#include <linux/version.h>
#include <linux/string.h>
#include <linux/timer.h>
#include <linux/blkdev.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/smp_lock.h>
#include <scsi/scsi.h>
#include <scsi/scsi_host.h>

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
#include <iscsi_target_mc.h>
#include <iscsi_target_error.h>

#define MC_BUF_LEN 60000
 
extern iscsi_global_t *iscsi_global;
static void mc_read_element_status(se_task_t *);

static struct hw_s {
	char *name;
	int num_medium_transport_elements;
	int num_data_transfer_elements;
	int num_storage_elements;
	int num_import_export_elements;
} hw[] = {

/* Each hardware name string must be exactly 28 bytes long:
 *
 *	Vendor		 8 bytes
 *	Product		16 bytes
 *	Revision	 4 bytes
 *
 *   1234567812345678901234561234
 *   |       |               |        */
  { "GENERIC MEDIA CHANGER   0001",		1,	 6,	120,	 8 },
  { "SPECTRA PYTHON          2000",		1,	 6,	120,	 8 },
  { "SPECTRA T50             0001",		1,	 4,	 50,	 8 },
  { "SPECTRA T950            0001",		1,	24,	950,	 8 },
};

/*	mc_read_tapes_file():
 *
 *	The 'tapes' file defines the file names to use for tape storage
 *	emulation.
 *
 *	The 'tapes' files is a text file with one file name per line.
 *
 *	Each file name should include the entire path prefix.
 */
static int mc_read_tapes_file (mc_host_t *p)
{
	int i, n, ret;
	char *dev_p;
	struct file *f;
	mm_segment_t old_fs;
	char str[256], *buf, *s;

	buf = kmalloc(MC_BUF_LEN + 1, GFP_KERNEL);

	if (buf == NULL)
		return(-1);

	/* read the file into buf */

	sprintf(str, "%s/tapes", p->mc_path_prefix);

	old_fs = get_fs();
	set_fs(get_ds());

	dev_p = getname(str);

	if (IS_ERR(dev_p)) {
		TRACE_ERROR("getname(%s) failed: %lu\n", str,
				IS_ERR(dev_p));
		kfree(buf);
		set_fs(old_fs);
		return(-1);
	}

	f = filp_open(dev_p, O_RDONLY | O_NONBLOCK, 0);

	if (IS_ERR(f) || !f || !f->f_dentry) {
		TRACE_ERROR("filp_open(%s) failed\n", dev_p);
		kfree(buf);
		putname(dev_p);
		set_fs(old_fs);
		return(-1);
	}

	if ((ret = f->f_op->read(f, buf, MC_BUF_LEN, &f->f_pos)) < 0) {
		TRACE_ERROR("f->f_op->read() returned %d\n", ret);
		filp_close(f, NULL);
		kfree(buf);
		putname(dev_p);
		set_fs(old_fs);
		return(-1);
	}

	buf[ret] = 0;

	filp_close(f, NULL);
	putname(dev_p);
	set_fs(old_fs);

	/* scan the buffer */

	s = buf;

	for (i = 0; i < MC_MAX_TAPE; i++) {
		n = sscanf(s, "%s", str);
		if (n < 1)
			break;
		n = strlen(str);
		p->mc_tape[i] = kmalloc(n + 1, GFP_KERNEL);
		strcpy(p->mc_tape[i], str);
		s += n + 1;
	}

	kfree(buf);

	return(0);
}

/*	mc_read_slots_file():
 *
 *	The 'slots' file contains the entire state of the VTL.
 *
 *	This function reads the 'slots' file.
 */
static int mc_read_slots_file (mc_host_t *p)
{
	int i, k, n, ret;
	char *dev_p;
	struct file *f;
	mm_segment_t old_fs;
	char str[256], *buf, *s;

	buf = kmalloc(MC_BUF_LEN + 1, GFP_KERNEL);

	if (buf == NULL)
		return(-1);

	/* read the file into buf */

	sprintf(str, "%s/slots", p->mc_path_prefix);

	old_fs = get_fs();
	set_fs(get_ds());

	dev_p = getname(str);

	if (IS_ERR(dev_p)) {
		TRACE_ERROR("getname(%s) failed: %lu\n", str,
				IS_ERR(dev_p));
		kfree(buf);
		set_fs(old_fs);
		return(-1);
	}

	f = filp_open(dev_p, O_RDONLY | O_NONBLOCK, 0);

	if (IS_ERR(f) || !f || !f->f_dentry) {
		TRACE_ERROR("filp_open(%s) failed\n", dev_p);
		kfree(buf);
		putname(dev_p);
		set_fs(old_fs);
		return(-1);
	}

	if ((ret = f->f_op->read(f, buf, MC_BUF_LEN, &f->f_pos)) < 0) {
		TRACE_ERROR("f->f_op->read() returned %d\n", ret);
		filp_close(f, NULL);
		kfree(buf);
		putname(dev_p);
		set_fs(old_fs);
		return(-1);
	}

	buf[ret] = 0;

	filp_close(f, NULL);
	putname(dev_p);
	set_fs(old_fs);

	/* scan the buffer */

	s = buf;

	while (1) {
		if (*s == 0)
			break;
		n = sscanf(s, "%d %s", &k, str);
		if (n < 2)
			break;
		if (k >= 1 && k < MC_MAX_SLOT) {
			for (i = 0; i < MC_MAX_TAPE; i++) {
				if (p->mc_tape[i] == NULL)
					break;
				if (strcmp(str, p->mc_tape[i]) == 0) {
					p->mc_slot[k] = p->mc_tape[i];
					break;
				}
			}
		}
		while (*s && *s != '\n')
			s++;
		if (*s)
			s++;
	}

	kfree(buf);

	return(0);
}

/*	mc_write_slots_file():
 *
 *	The 'slots' file contains the entire state of the VTL.
 *
 *	This function writes the 'slots' file.
 */
static int mc_write_slots_file (mc_host_t *p)
{
	int i, ret;
	char *dev_p;
	struct file *f;
	mm_segment_t old_fs;
	char str[256], *buf, *s;

	buf = kmalloc(MC_BUF_LEN + 1, GFP_KERNEL);

	if (buf == NULL)
		return(-1);

	/* fill the buffer */

	s = buf;

	for (i = 0; i < MC_MAX_SLOT; i++) {
		if (p->mc_slot[i] == NULL)
			continue;
		sprintf(s, "%d %s\n", i, p->mc_slot[i]);
		while (*s)
			s++;
	}

	/* write the buffer */

	sprintf(str, "%s/slots", p->mc_path_prefix);

	old_fs = get_fs();
	set_fs(get_ds());

	dev_p = getname(str);

	if (IS_ERR(dev_p)) {
		TRACE_ERROR("getname(%s) failed: %lu\n", str,
				IS_ERR(dev_p));
		kfree(buf);
		set_fs(old_fs);
		return(-1);
	}
	

	f = filp_open(dev_p,  O_RDWR | O_NONBLOCK | O_CREAT | O_LARGEFILE | O_TRUNC, 0644);

	if (IS_ERR(f) || !f || !f->f_dentry) {
		TRACE_ERROR("filp_open(%s) failed\n", dev_p);
		kfree(buf);
		putname(dev_p);
		set_fs(old_fs);
		return(-1);
	}

	if ((ret = f->f_op->write(f, buf, strlen(buf), &f->f_pos)) < 0) {
		TRACE_ERROR("f->f_op->write() returned %d\n", ret);
		filp_close(f, NULL);
		kfree(buf);
		putname(dev_p);
		set_fs(old_fs);
		return(-1);
	}

	filp_close(f, NULL);
	kfree(buf);
	putname(dev_p);
	set_fs(old_fs);

	return(0);
}

/*	mc_fixup():
 *
 *	This function ensures that all file names in the 'tapes' file are
 *	represented in the data structure.
 *
 *	This is necessary in case the user adds new file names to the 'tapes'
 *	file.
 */
static void mc_fixup (mc_host_t *p)
{
	int i, j;

	for (i = 0; i < MC_MAX_TAPE; i++) {

		if (p->mc_tape[i] == NULL)
			continue;

		for (j = 1; j < p->mc_nslot; j++)
			if (p->mc_slot[j] == p->mc_tape[i])
				break;

		if (j < p->mc_nslot)
			continue;

		for (j = 1; j < p->mc_nslot; j++)
			if (p->mc_slot[j] == NULL)
				break;

		if (j == p->mc_nslot)
			continue;

		p->mc_slot[j] = p->mc_tape[i];
	}
}

/*	mc_attach_hba(): (Part of iscsi_transport_t template)
 *
 *
 */
extern int mc_attach_hba (
	iscsi_portal_group_t *tpg,
	se_hba_t *hba,
	iscsi_hbainfo_t *hi)
{
	mc_host_t *mc_host;

	if (!(mc_host = kmalloc(sizeof(mc_host_t), GFP_KERNEL))) {
		TRACE_ERROR("Unable to allocate memory for mc_host_t\n");
		return(-1);
	}
	memset(mc_host, 0, sizeof(mc_host_t));

	mc_host->mc_host_id = hi->mc_host_id;
	
	atomic_set(&hba->left_queue_depth, MC_HBA_QUEUE_DEPTH);
	atomic_set(&hba->max_queue_depth, MC_HBA_QUEUE_DEPTH);
	hba->hba_ptr = (void *) mc_host;
	hba->hba_id = hi->hba_id;
	hba->transport = &mc_template;

	PYXPRINT("iSCSI_HBA[%d] - %s Virtual media changer HBA Driver %s for iSCSI"
		" Target Core Stack %s\n", hba->hba_id, PYX_ISCSI_VENDOR, MC_VERSION, PYX_ISCSI_VERSION);
	
	PYXPRINT("iSCSI_HBA[%d] - Attached Virtual media changer HBA: %u to iSCSI Transport with"
		" TCQ Depth: %d MaxSectors: %u\n", hba->hba_id, mc_host->mc_host_id,
		atomic_read(&hba->max_queue_depth), MC_MAX_SECTORS);

	return(0);
}

/*	mc_detach_hba(): (Part of iscsi_transport_t template)
 *
 *
 */
extern int mc_detach_hba (se_hba_t *hba)
{
	int i;
	mc_host_t *mc_host;
	
	if (!hba->hba_ptr) {
		TRACE_ERROR("hba->hba_ptr is NULL!\n");
		return(-1);
	}
	mc_host = (mc_host_t *) hba->hba_ptr;

	PYXPRINT("iSCSI_HBA[%d] - Detached media changer HBA: %u from iSCSI Transport\n",
			hba->hba_id, mc_host->mc_host_id);

	for (i = 0; i < MC_MAX_TAPE; i++) {
		if (mc_host->mc_tape[i]) {
			kfree(mc_host->mc_tape[i]);
			mc_host->mc_tape[i] = NULL;
		}
	}

	kfree(mc_host);
	hba->hba_ptr = NULL;
	
	return(0);
}

extern int vt_create_virtdevice(se_hba_t *, iscsi_devinfo_t *);

/*	mc_create_virtdevice(): (Part of iscsi_transport_t template)
 *
 *
 */
extern int mc_create_virtdevice (se_hba_t *iscsi_hba, iscsi_devinfo_t *di)
{
	int n;
	se_device_t *dev;
	mc_dev_t *mc_dev;
	mc_host_t *mc_host = (mc_host_t *) iscsi_hba->hba_ptr;

	if (di->vt_mc_host_id) {
		di->vt_device_id = di->mc_device_id;
		return vt_create_virtdevice(iscsi_hba, di);
	}

	if (strlen(di->fd_dev_name) > MC_MAX_DEV_NAME) {
		TRACE_ERROR("di->fd_dev_name exceeds MC_MAX_DEV_NAME: %d\n",
				MC_MAX_DEV_NAME);
		return(0);
	}

	if (!(mc_dev = (mc_dev_t *) kmalloc(sizeof(mc_dev_t), GFP_KERNEL))) {
		TRACE_ERROR("Unable to allocate memory for fd_dev_t\n");
		return(0);
	}

	memset(mc_dev, 0, sizeof(mc_dev_t));

	mc_dev->mc_dev_id = di->mc_device_id;
	mc_dev->mc_hw_id = di->mc_hw_id;
	mc_dev->mc_host = mc_host;
	mc_dev->mc_dev_size = di->fd_device_size;
	sprintf(mc_dev->mc_dev_name, "%s", di->fd_dev_name);

	mc_host->mc_hw_id = di->mc_hw_id;
	sprintf(mc_host->mc_path_prefix, "%s", di->fd_dev_name);

	if (!(dev = mc_add_device_to_list(iscsi_hba, mc_dev)))
		goto fail;

	mc_dev->mc_queue_depth = dev->queue_depth;
	
	PYXPRINT("iSCSI_FILE[%u] - Added media changer Device ID: %u at %s,"
		" %llu total bytes\n", mc_host->mc_host_id, mc_dev->mc_dev_id,
			mc_dev->mc_dev_name, mc_dev->mc_dev_size);

	/* set up the element addresses */

	n = mc_host->mc_hw_id;

	mc_host->mc_nmte = hw[n].num_medium_transport_elements;
	mc_host->mc_nse = hw[n].num_storage_elements;
	mc_host->mc_nxe = hw[n].num_import_export_elements;
	mc_host->mc_ndte = hw[n].num_data_transfer_elements;

	/* first medium transport element */

	mc_host->mc_fmte = 0;

	/* first data transfer element */

	mc_host->mc_fdte = mc_host->mc_fmte + mc_host->mc_nmte;

	/* first storage element */

	mc_host->mc_fse = mc_host->mc_fdte + mc_host->mc_ndte;

	/* first import/export element */

	mc_host->mc_fxe = mc_host->mc_fse + mc_host->mc_nse;

	/* total number of elements */

	mc_host->mc_nslot = mc_host->mc_fxe + mc_host->mc_nxe;

	mc_read_tapes_file(mc_host);
	mc_read_slots_file(mc_host);
	mc_fixup(mc_host);
	mc_write_slots_file(mc_host);

	return(1);

fail:

	kfree(mc_dev);

	return(0);
}

/*	mc_add_device_to_list():
 *
 *
 */
extern se_device_t *mc_add_device_to_list (se_hba_t *iscsi_hba, void *mc_dev_p)
{
	se_device_t *dev;
	mc_dev_t *mc_dev = (mc_dev_t *) mc_dev_p;
	
	if (!(dev = transport_add_device_to_iscsi_hba(iscsi_hba, &mc_template, 
				DF_DISABLE_STATUS_THREAD, (void *)mc_dev)))
		return(NULL);

	return(dev);
}

/*	mc_activate_device(): (Part of iscsi_transport_t template)
 *
 *
 */
extern int mc_activate_device (se_device_t *dev)
{
	mc_dev_t *mc_dev = (mc_dev_t *) dev->dev_ptr;
	mc_host_t *mc_host = mc_dev->mc_host;

	PYXPRINT("iSCSI_FILE[%u] - Activating Device with TCQ: %d at MEDIA CHANGER"
		" Device ID: %d\n", mc_host->mc_host_id, mc_dev->mc_queue_depth,
		mc_dev->mc_dev_id);

	return(0);
}

/*	mc_deactivate_device(): (Part of iscsi_transport_t template)
 *
 *
 */
extern void mc_deactivate_device (se_device_t *dev)
{
	mc_dev_t *mc_dev = (mc_dev_t *) dev->dev_ptr;
	mc_host_t *mc_host = mc_dev->mc_host;

	PYXPRINT("iSCSI_FILE[%u] - Deactivating Device with TCQ: %d at MEDIA CHANGER"
		" Device ID: %d\n", mc_host->mc_host_id, mc_dev->mc_queue_depth,
		mc_dev->mc_dev_id);

	return;
}

/*	mc_check_device_location(): (Part of iscsi_transport_t template)
 *
 *
 */
extern int mc_check_device_location (se_device_t *dev, iscsi_dev_transport_info_t *dti)
{
	mc_dev_t *mc_dev = (mc_dev_t *) dev->dev_ptr;

	if (dti->mc_device_id == mc_dev->mc_dev_id)
		return(0);

	return(-1);
}

extern int mc_check_ghost_id (iscsi_hbainfo_t *hi)
{
	int i;          
	se_hba_t *hba;
	mc_host_t *fh;

	spin_lock(&iscsi_global->hba_lock);
	for (i = 0; i < ISCSI_MAX_GLOBAL_HBAS; i++) {
		hba = &iscsi_global->hba_list[i];

		if (!(hba->hba_status & HBA_STATUS_ACTIVE))
			continue;
		if (hba->type != MEDIA_CHANGER)
			continue;

		fh = (mc_host_t *) hba->hba_ptr;
		if (fh->mc_host_id == hi->mc_host_id) {
			TRACE_ERROR("MEDIA CHANGER HBA with MC_HOST_ID: %u already"
				" assigned to iSCSI HBA: %hu, ignoring request\n",
				hi->mc_host_id, hba->hba_id);
			spin_unlock(&iscsi_global->hba_lock);
			return(-1);
		}
	}
	spin_unlock(&iscsi_global->hba_lock);
		
	return(0);
}

/*	mc_free_device(): (Part of iscsi_transport_t template)
 *
 *
 */
extern void mc_free_device (se_device_t *dev)
{
	mc_dev_t *mc_dev = (mc_dev_t *) dev->dev_ptr;

	kfree(mc_dev);

	return;
}

/*	mc_transport_complete(): (Part of iscsi_transport_t template)
 *
 *
 */
extern int mc_transport_complete (se_task_t *task)
{
	int t;
	mc_request_t *req = (mc_request_t *) task->transport_req;
	t = req->mc_sense_flag;
	req->mc_sense_flag = 0;
	return(t);
}

/*	mc_allocate_request(): (Part of iscsi_transport_t template)
 *
 *
 */
extern void *mc_allocate_request (
	se_task_t *task,
	se_device_t *dev)
{
	mc_request_t *mc_req;
	
	if (!(mc_req = (mc_request_t *) kmalloc(sizeof(mc_request_t), GFP_KERNEL))) {
		TRACE_ERROR("Unable to allocate mc_request_t\n");
		return(NULL);
	}
	memset(mc_req, 0, sizeof(mc_request_t));

	mc_req->mc_dev = (mc_dev_t *) dev->dev_ptr;

	return((void *)mc_req);
}

extern void mc_get_evpd_prod (unsigned char *buf, u32 size, se_device_t *dev)
{
	snprintf(buf, size, "MEDIA CHANGER");
	return;
}

extern void mc_get_evpd_sn (unsigned char *buf, u32 size, se_device_t *dev)
{
	mc_dev_t *fdev = (mc_dev_t *) dev->dev_ptr;
	se_hba_t *hba = dev->iscsi_hba;

	snprintf(buf, size, "%u_%u", hba->hba_id, fdev->mc_dev_id);	
	return;
}

/*	mc_emulate_inquiry():
 *
 *
 */
extern int mc_emulate_inquiry (se_task_t *task)
{
	unsigned char prod[64], se_location[128];
	iscsi_cmd_t *cmd = task->iscsi_cmd;
	mc_dev_t *fdev = (mc_dev_t *) task->iscsi_dev->dev_ptr;
	se_hba_t *hba = task->iscsi_dev->iscsi_hba;
	unsigned char *cdb = T_TASK(cmd)->t_task_cdb;
	unsigned char *dst = (unsigned char *) T_TASK(cmd)->t_task_buf;
	unsigned char buf[EVPD_BUF_LEN];
	unsigned int n;

	// if the EVPD bit is zero then return the standard INQUIRY data

	if ((cdb[1] & 1) == 0) {
		memset(dst, 0, cmd->data_length);
		memset(buf, 0, EVPD_BUF_LEN);
		buf[0] = TYPE_MEDIUM_CHANGER;
		buf[1] = 0x80;
		buf[2] = 0x02;
		buf[3] = 0x02;
		buf[4] = 31;
		buf[5] = 0;
		buf[6] = 0;
		buf[7] = 0;
		n = fdev->mc_hw_id;
		if (n > sizeof hw / sizeof (struct hw_s))
			n = 0;
		strncpy(buf + 8, hw[n].name, 28);
		if (cmd->data_length < 36) {
			TRACE_ERROR("Inquiry EVPD Length: %u larger than"
			" cmd->data_length: %u\n", 36, cmd->data_length);
			memcpy(dst, buf, cmd->data_length);
		} else
			memcpy(dst, buf, 36);
		return(0);
	}

	memset(prod, 0, 64);
	memset(se_location, 0, 128);
	
	sprintf(prod, "MEDIA CHANGER");
	sprintf(se_location, "%u_%u", hba->hba_id, fdev->mc_dev_id);
		
	return(transport_generic_emulate_inquiry(cmd, TYPE_MEDIUM_CHANGER, prod, MC_VERSION, se_location, NULL));
}

/* The SCSI standard says tape drives do not support READ_CAPACITY.
   However, something in the iSCSI code is sending it anyway. */

/*	mc_emulate_read_cap():
 *
 *
 */
static int mc_emulate_read_cap (se_task_t *task)
{
	u32 blocks = 1000000000 / MC_BLOCKSIZE - 1;
	return(transport_generic_emulate_readcapacity(task->iscsi_cmd, blocks, MC_BLOCKSIZE));
}

/*	mc_emulate_modesense():
 *
 *
 */
static int mc_emulate_modesense (
	se_task_t *task,
	unsigned char *cdb,
	unsigned char *rbuf,
	int ten,
	int type,
	int swp)
{
	iscsi_cmd_t *cmd = task->iscsi_cmd;
	int page_code;
	int offset = (ten) ? 8 : 4;
	int length = 0;
	unsigned char buf[SE_MODE_PAGE_BUF];
	mc_host_t *p;

	/* task points to a device that points to an hba that points to extra info */

	p = (mc_host_t *) task->iscsi_dev->iscsi_hba->hba_ptr;

	memset(buf, 0, SE_MODE_PAGE_BUF);

	page_code = cdb[2] & 0x3f;

	switch (page_code) {
	case 0x1d:
		buf[offset + 0] = 0x1d;
		buf[offset + 1] = 18;
		buf[offset + 2] = p->mc_fmte >> 8;	/* first medium transport element */
		buf[offset + 3] = p->mc_fmte;
		buf[offset + 4] = p->mc_nmte >> 8;	/* number of medium transport elements */
		buf[offset + 5] = p->mc_nmte;
		buf[offset + 6] = p->mc_fse >> 8;	/* first storage element */
		buf[offset + 7] = p->mc_fse;
		buf[offset + 8] = p->mc_nse >> 8;	/* number of storage elements */
		buf[offset + 9] = p->mc_nse;
		buf[offset + 10] = p->mc_fxe >> 8;	/* first import/export element */
		buf[offset + 11] = p->mc_fxe;
		buf[offset + 12] = p->mc_nxe >> 8;	/* number of import/export elements */
		buf[offset + 13] = p->mc_nxe;
		buf[offset + 14] = p->mc_fdte >> 8;	/* first data transfer element */
		buf[offset + 15] = p->mc_fdte;
		buf[offset + 16] = p->mc_ndte >> 8;	/* number of data transfer elements */
		buf[offset + 17] = p->mc_ndte;
		buf[offset + 18] = 0;			/* reserved */
		buf[offset + 19] = 0;
		length = 20;
		break;
	default:
		TRACE_ERROR("Got Unknown Mode Page: 0x%02x\n", page_code);
		return(PYX_TRANSPORT_UNKNOWN_MODE_PAGE);
	}
	offset += length;

	if (ten) { 
		offset -= 2;
		buf[0] = (offset >> 8) & 0xff;
		buf[1] = offset & 0xff;

//		if (swp)
//			transport_modesense_write_protect(&buf[3], type);
		
		if ((offset + 2) > cmd->data_length)
			offset = cmd->data_length;
		
	} else {
		offset -= 1;
		buf[0] = offset & 0xff;

//		if (swp)
//			transport_modesense_write_protect(&buf[2], type);
		
		if ((offset + 1) > cmd->data_length)
			offset = cmd->data_length;
	}

	memcpy(rbuf, buf, offset); 
	
	return(0);
}

extern int vt_lock(int, int);
extern void vt_unlock(int, int);

/*	mc_move_medium():
 *
 *	The MOVE MEDIUM command requests that the device server move a volume
 *	from a source element to a destination element. Support for the MOVE
 *	MEDIUM command is mandatory.
 */
static int mc_move_medium (se_task_t *task)
{
	int mta, sa, da;
	mc_request_t *req;
	mc_host_t *p;
	unsigned char *b;
	char *t;

	/* task points to a request that points to a cdb */

	req = (mc_request_t *) task->transport_req;
	b = req->mc_scsi_cdb;

	/* task points to a device that points to an hba that points to device
	 * specific info
	 */

	p = (mc_host_t *) task->iscsi_dev->iscsi_hba->hba_ptr;

	/* medium transport address */

	mta = 256 * b[2] + b[3];

	/* source address */

	sa = 256 * b[4] + b[5];

	/* destination address */

	da = 256 * b[6] + b[7];

	/* check the medium transport address
	 *
	 * If the medium transport address is less than the address of the
	 * first medium transport element or greater than the address of the
	 * last medium transport element then return an error.
	 *
	 * The last medium transport address is the address of the first medium
	 * transport element plus the number of medium transport elements
	 * minus 1.
	 */

	if (mta < p->mc_fmte || mta > p->mc_fmte + p->mc_nmte - 1)
		goto invalid_element_address;

	if (sa < 1 || sa >= p->mc_nslot)
		goto invalid_element_address;

	if (da < 1 || da >= p->mc_nslot)
		goto invalid_element_address;

	if (p->mc_slot[sa] == NULL)
		goto source_element_empty;

	if (sa == da)
		return(0);

	if (p->mc_slot[da] != NULL)
		goto destination_element_full;

	/* if sa is a data transfer element then lock
	 *
	 * Add 1 because vt_device_id numbering starts at 1.
	 */

	if (sa >= p->mc_fdte && sa < p->mc_fdte + p->mc_ndte)
		if (!vt_lock(p->mc_host_id, sa - p->mc_fdte + 1))
			goto medium_removal_prevented;

	/* move filnames around */

	t = p->mc_slot[sa];
	p->mc_slot[sa] = NULL;

	mc_write_slots_file(p);

	p->mc_slot[da] = t;

	mc_write_slots_file(p);

	/* if sa is a data transfer element then unlock
	 *
	 * Add 1 because vt_device_id numbering starts at 1.
	 */

	if (sa >= p->mc_fdte && sa < p->mc_fdte + p->mc_ndte)
		vt_unlock(p->mc_host_id, sa - p->mc_fdte + 1);

	return(0);

	/* The MEDIUM TRANSPORT ADDRESS field specifies the medium transport
	 * element that is to be used in executing this command. If the address
	 * specified has not been assigned or has been assigned to an element
	 * other than a medium transport element, the device server shall
	 * return CHECK CONDITION status. The sense key shall be
	 * ILLEGAL REQUEST and the additional sense code
	 * INVALID ELEMENT ADDRESS.
	 */

invalid_element_address:

	req->mc_sense_buffer[0] = 0xf0;
	req->mc_sense_buffer[1] = 0x00;
	req->mc_sense_buffer[2] = 0x05; /* SENSE KEY = ILLEGAL REQUEST */
	req->mc_sense_buffer[3] = 0x00;
	req->mc_sense_buffer[4] = 0x00;
	req->mc_sense_buffer[5] = 0x00;
	req->mc_sense_buffer[6] = 0x00;
	req->mc_sense_buffer[7] = 0x06; /* ADDITIONAL SENSE LENGTH = 6 */
	req->mc_sense_buffer[8] = 0x00;
	req->mc_sense_buffer[9] = 0x00;
	req->mc_sense_buffer[10] = 0x00;
	req->mc_sense_buffer[11] = 0x00;
	req->mc_sense_buffer[12] = 0x21; /* INVALID ELEMENT ADDRESS */
	req->mc_sense_buffer[13] = 0x01; /* ASCQ = 01h */

	return(-1);

	/* If the SOURCE ADDRESS element is empty, the device server shall
	 * return CHECK CONDITION status. The sense key shall be ILLEGAL
	 * REQUEST and the additional sense code MEDIUM SOURCE ELEMENT EMPTY.
	 */

source_element_empty:

	req->mc_sense_buffer[0] = 0xf0;
	req->mc_sense_buffer[1] = 0x00;
	req->mc_sense_buffer[2] = 0x05; /* SENSE KEY = ILLEGAL REQUEST */
	req->mc_sense_buffer[3] = 0x00;
	req->mc_sense_buffer[4] = 0x00;
	req->mc_sense_buffer[5] = 0x00;
	req->mc_sense_buffer[6] = 0x00;
	req->mc_sense_buffer[7] = 0x06; /* ADDITIONAL SENSE LENGTH = 6 */
	req->mc_sense_buffer[8] = 0x00;
	req->mc_sense_buffer[9] = 0x00;
	req->mc_sense_buffer[10] = 0x00;
	req->mc_sense_buffer[11] = 0x00;
	req->mc_sense_buffer[12] = 0x3b; /* MEDIUM SOURCE ELEMENT EMPTY */
	req->mc_sense_buffer[13] = 0x0e; /* ASCQ = 0Eh */

	return(-1);

	/* If the DESTINATION ADDRESS element is full, and different from the
	 * SOURCE ADDRESS element, the device server target shall return CHECK
	 * CONDITION status. The sense key shall be ILLEGAL REQUEST and the
	 * additional sense code MEDIUM DESTINATION ELEMENT FULL.
	 */

destination_element_full:

	req->mc_sense_buffer[0] = 0xf0;
	req->mc_sense_buffer[1] = 0x00;
	req->mc_sense_buffer[2] = 0x05; /* SENSE KEY = ILLEGAL REQUEST */
	req->mc_sense_buffer[3] = 0x00;
	req->mc_sense_buffer[4] = 0x00;
	req->mc_sense_buffer[5] = 0x00;
	req->mc_sense_buffer[6] = 0x00;
	req->mc_sense_buffer[7] = 0x06; /* ADDITIONAL SENSE LENGTH = 6 */
	req->mc_sense_buffer[8] = 0x00;
	req->mc_sense_buffer[9] = 0x00;
	req->mc_sense_buffer[10] = 0x00;
	req->mc_sense_buffer[11] = 0x00;
	req->mc_sense_buffer[12] = 0x3b; /* MEDIUM DESTINATION ELEMENT FULL */
	req->mc_sense_buffer[13] = 0x0d; /* ASCQ = 0Dh */

	return(-1);

	/* If the SOURCE ADDRESS of a MOVE MEDIUM command represents a data
	 * transfer element and a prevention of medium removal condition (see
	 * SPC-3) exists within the data transfer device, the device server
	 * shall return CHECK CONDITION status and shall set the sense key to
	 * ILLEGAL REQUEST and the additional sense code to MEDIUM REMOVAL
	 * PREVENTED BY DATA TRANSFER ELEMENT.
	 */

medium_removal_prevented:

	req->mc_sense_buffer[0] = 0xf0;
	req->mc_sense_buffer[1] = 0x00;
	req->mc_sense_buffer[2] = 0x05; /* SENSE KEY = ILLEGAL REQUEST */
	req->mc_sense_buffer[3] = 0x00;
	req->mc_sense_buffer[4] = 0x00;
	req->mc_sense_buffer[5] = 0x00;
	req->mc_sense_buffer[6] = 0x00;
	req->mc_sense_buffer[7] = 0x06; /* ADDITIONAL SENSE LENGTH = 6 */
	req->mc_sense_buffer[8] = 0x00;
	req->mc_sense_buffer[9] = 0x00;
	req->mc_sense_buffer[10] = 0x00;
	req->mc_sense_buffer[11] = 0x00;
	req->mc_sense_buffer[12] = 0x53; /* MEDIUM REMOVAL PREVENTED */
	req->mc_sense_buffer[13] = 0x02; /* ASCQ = 02h */

	return(-1);
}

/*	mc_emulate_scsi_cdb():
 *
 *
 */
static int mc_emulate_scsi_cdb (se_task_t *task)
{
	int ret;
	mc_request_t *mc_req = (mc_request_t *) task->transport_req;

	mc_req->mc_sense_buffer[0] = 0;

	switch (mc_req->mc_scsi_cdb[0]) {
	case INQUIRY:
		if (mc_emulate_inquiry(task) < 0)
			return(PYX_TRANSPORT_INVALID_CDB_FIELD);
		break;
	case MODE_SENSE:
		if ((ret = mc_emulate_modesense(task,
			mc_req->mc_scsi_cdb, mc_req->mc_buf, 0, TYPE_MEDIUM_CHANGER, 0)) < 0)
			return(ret);
		break;
	case MODE_SENSE_10:
		if ((ret = mc_emulate_modesense(task,
			mc_req->mc_scsi_cdb, mc_req->mc_buf, 1, TYPE_MEDIUM_CHANGER, 0)) < 0)
			return(ret);
		break;
	case READ_ELEMENT_STATUS:
		mc_read_element_status(task);
		break;
	case READ_CAPACITY:
		if ((ret = mc_emulate_read_cap(task)) < 0)
			return(ret);
		break;
	case MOVE_MEDIUM:
		mc_move_medium(task);
		break;
	case TEST_UNIT_READY:
	case VERIFY:
	case RESERVE:
	case RESERVE_10:
	case RELEASE:
	case RELEASE_10:
		break;
	default:
		TRACE_ERROR("Unsupported SCSI Opcode: 0x%02x for MEDIA CHANGER\n",
				mc_req->mc_scsi_cdb[0]);
		return(PYX_TRANSPORT_UNKNOWN_SAM_OPCODE);
	}

	if (mc_req->mc_sense_buffer[0])
		mc_req->mc_sense_flag = 1;
	else
		mc_req->mc_sense_flag = 0;

	task->task_scsi_status = GOOD;
	transport_complete_task(task, 1);
	
	return(PYX_TRANSPORT_SENT_TO_TRANSPORT);
}

extern int mc_do_task (se_task_t *task)
{
	int ret = 0;
	mc_request_t *req = (mc_request_t *) task->transport_req;

	if (!(task->iscsi_cmd->cmd_flags & ICF_SCSI_DATA_SG_IO_CDB))
		return(mc_emulate_scsi_cdb(task));

	req->mc_lba = task->task_lba;
	req->mc_size = task->task_size;

	req->mc_sense_buffer[0] = 0;

//	if (req->mc_data_direction == MC_DATA_READ)
//		ret = mc_do_read(req);
//	else
//		ret = mc_do_write(req);

	if (ret != 0)
		return(ret);

	task->task_scsi_status = GOOD;

	if (req->mc_sense_buffer[0])
		req->mc_sense_flag = 1;
	else
		req->mc_sense_flag = 0;

	transport_complete_task(task, 1);

	return(PYX_TRANSPORT_SENT_TO_TRANSPORT);
}

/*	mc_free_task(): (Part of iscsi_transport_t template)
 *
 *
 */
extern void mc_free_task (se_task_t *task)
{
	mc_request_t *req;

	req = (mc_request_t *) task->transport_req;
	kfree(req);
	
	return;
}

extern int mc_check_hba_params (iscsi_hbainfo_t *hi, struct iscsi_target *t, int virt)
{
	if (!(t->hba_params_set & PARAM_HBA_MC_HOST_ID)) {
		TRACE_ERROR("mc_host_id must be set for"
			" addhbatotarget requests with MEDIA CHANGER"
				" Interfaces\n");
		return(ERR_HBA_MISSING_PARAMS);
	}
	hi->mc_host_id = t->mc_host_id;

	return(0);
}

extern int mc_check_dev_params (se_hba_t *hba, struct iscsi_target *t, iscsi_dev_transport_info_t *dti)
{
	if (!(t->hba_params_set & PARAM_HBA_MC_DEVICE_ID)) {
		TRACE_ERROR("Missing MEDIA CHANGER createvirtdev parameters\n");
		return(ERR_VIRTDEV_MISSING_PARAMS);
	}

	dti->mc_device_id = t->mc_device_id;

	return(0);
}

extern int mc_check_virtdev_params (iscsi_devinfo_t *di, struct iscsi_target *t)
{
	if ((t->hba_params_set & PARAM_HBA_MC_DEVICE_ID) == 0) {
		TRACE_ERROR("Missing MEDIA CHANGER createvirtdev parameters\n");
		return(ERR_VIRTDEV_MISSING_PARAMS);
	}

	di->vt_mc_host_id = t->mc_host_id;

	di->mc_device_id = t->mc_device_id;
	di->vt_device_id = t->vt_device_id;
	di->mc_hw_id = t->mc_hw_id;
	di->vt_hw_id = t->vt_hw_id;
	di->fd_device_size = t->fd_dev_size;

	if (strlen(t->value))
		snprintf(di->fd_dev_name, MC_MAX_DEV_NAME, "%s", t->value);
	else
		snprintf(di->fd_dev_name, MC_MAX_DEV_NAME, "/root/vtape");

	return(0);
}

extern void mc_get_plugin_info (void *p, char *b, int *bl)
{
	*bl += sprintf(b+*bl, "%s Virtual Media Changer Plugin %s\n", PYX_ISCSI_VENDOR, MC_VERSION);
	
	return;
}

extern void mc_get_hba_info (se_hba_t *hba, char *b, int *bl)
{
	*bl += sprintf(b+*bl, "iSCSI Host ID: %u  media changer Host ID: %u\n",
		 hba->hba_id, hba->hba_info.mc_host_id);
	*bl += sprintf(b+*bl, "        iSBE MEDIA CHANGER HBA\n");

	return;
}

extern void mc_get_dev_info (se_device_t *dev, char *b, int *bl)
{
	struct mc_dev_s *fd = (struct mc_dev_s *) dev->dev_ptr;

	*bl += sprintf(b+*bl, "iSBE MEDIA CHANGER ID: %u  MEDIA CHANGER Makeup: %s\n",
			fd->mc_dev_id, TRANSPORT(dev)->name);
	*bl += sprintf(b+*bl, "        File: %s  Size: %llu\n",
			fd->mc_dev_name, fd->mc_dev_size);

	return;
}

/*	mc_map_task_non_SG():
 *
 *
 */
extern void mc_map_task_non_SG (se_task_t *task)
{
	iscsi_cmd_t *cmd = task->iscsi_cmd;
	mc_request_t *req = (mc_request_t *) task->transport_req;

	req->mc_bufflen		= task->task_size;
	req->mc_buf		= (void *) T_TASK(cmd)->t_task_buf;
	req->mc_sg_count	= 0;
	
	return;
}

/*	mc_map_task_SG():
 *
 *
 */
extern void mc_map_task_SG (se_task_t *task)
{
	mc_request_t *req = (mc_request_t *) task->transport_req;

	req->mc_bufflen		= task->task_size;
	req->mc_buf		= (void *)task->task_buf;
	req->mc_sg_count	= task->task_sg_num;

	return;
}

/*      mc_CDB_inquiry():
 *
 *
 */
extern int mc_CDB_inquiry (se_task_t *task, u32 size)
{      
	mc_request_t *req = (mc_request_t *) task->transport_req;
		        
	req->mc_data_direction  = MC_DATA_READ;
			        
	/*
	 * This causes 255 instead of the requested 256 bytes
	 * to be returned.  This can be safely ignored for now,
	 * and take the Initiators word on INQUIRY data lengths.
	 */
#if 0
	cmd->data_length	= req->mc_bufflen;
#endif
	mc_map_task_non_SG(task);

	return(0);
}

/*      mc_CDB_none():
 *
 *
 */
extern int mc_CDB_none (se_task_t *task, u32 size)
{
	mc_request_t *req = (mc_request_t *) task->transport_req;

	req->mc_data_direction	= MC_DATA_NONE;
	req->mc_bufflen		= 0;
	req->mc_sg_count	= 0;
	req->mc_buf		= NULL;

	return(0);
}

/*	mc_CDB_read_non_SG():
 *
 *
 */
extern int mc_CDB_read_non_SG (se_task_t *task, u32 size)
{
	mc_request_t *req = (mc_request_t *) task->transport_req;

	req->mc_data_direction = MC_DATA_READ;
	mc_map_task_non_SG(task);

	return(0);
}

/*	mc_CDB_read_SG):
 *
 *
 */
extern int mc_CDB_read_SG (se_task_t *task, u32 size)
{
	mc_request_t *req = (mc_request_t *) task->transport_req;

	req->mc_data_direction = MC_DATA_READ;
	mc_map_task_SG(task);

	return(req->mc_sg_count);
}

/*	mc_CDB_write_non_SG():
 *
 *
 */
extern int mc_CDB_write_non_SG (se_task_t *task, u32 size)
{
	mc_request_t *req = (mc_request_t *) task->transport_req;
	
	req->mc_data_direction = MC_DATA_WRITE;
	mc_map_task_non_SG(task);
	
	return(0);
}

/*	mc_CDB_write_SG():
 *
 *
 */
extern int mc_CDB_write_SG (se_task_t *task, u32 size)
{
	mc_request_t *req = (mc_request_t *) task->transport_req;

	req->mc_data_direction = MC_DATA_WRITE;
	mc_map_task_SG(task);

	return(req->mc_sg_count);
}

/*	mc_check_lba():
 *
 *
 */
extern int mc_check_lba (unsigned long long lba, se_device_t *dev)
{
	return(0);
}

/*	mc_check_for_SG(): (Part of iscsi_transport_t template)
 *
 *
 */
extern int mc_check_for_SG (se_task_t *task)
{
	mc_request_t *req = (mc_request_t *) task->transport_req;
	
	return(req->mc_sg_count);
}

/*	mc_get_cdb(): (Part of iscsi_transport_t template)
 *
 *
 */
extern unsigned char *mc_get_cdb (se_task_t *task)
{
	mc_request_t *req = (mc_request_t *) task->transport_req;

	return(req->mc_scsi_cdb);
}

/*	mc_get_blocksize(): (Part of iscsi_transport_t template)
 *
 *
 */
extern u32 mc_get_blocksize (se_device_t *dev)
{
	return(MC_BLOCKSIZE);
}

/*	mc_get_device_rev(): (Part of iscsi_transport_t template)
 *
 *
 */
extern u32 mc_get_device_rev (se_device_t *dev)
{
	return(02); 
}

/*	mc_get_device_type(): (Part of iscsi_transport_t template)
 *
 *
 */
extern u32 mc_get_device_type (se_device_t *dev)
{
	return(TYPE_MEDIUM_CHANGER);
}

/*	mc_get_dma_length(): (Part of iscsi_transport_t template)
 *
 *
 */
extern u32 mc_get_dma_length (u32 task_size, se_device_t *dev)
{
	return(PAGE_SIZE);
}

/*	mc_get_max_sectors(): (Part of iscsi_transport_t template)
 *
 *
 */
extern u32 mc_get_max_sectors (se_device_t *dev)
{
	return(MC_MAX_SECTORS);
}

/*	mc_get_queue_depth(): (Part of iscsi_transport_t template)
 *
 *
 */
extern u32 mc_get_queue_depth (se_device_t *dev)
{
	return(MC_DEVICE_QUEUE_DEPTH);
}

/*	mc_get_non_SG(): (Part of iscsi_transport_t template)
 *
 *
 */
extern unsigned char *mc_get_non_SG (se_task_t *task)
{
	mc_request_t *req = (mc_request_t *) task->transport_req;

	return((unsigned char *)req->mc_buf);
}

/*	mc_get_SG(): (Part of iscsi_transport_t template)
 *
 *
 */
extern struct scatterlist *mc_get_SG (se_task_t *task)
{
	mc_request_t *req = (mc_request_t *) task->transport_req;

	return((struct scatterlist *)req->mc_buf);
}

/*	mc_get_SG_count(): (Part of iscsi_transport_t template)
 *
 *
 */
extern u32 mc_get_SG_count (se_task_t *task)
{
	return(0);
}

/*	mc_set_non_SG_buf():
 *
 *
 */
extern int mc_set_non_SG_buf (unsigned char *buf, se_task_t *task)
{
	mc_request_t *req = (mc_request_t *) task->transport_req;
	
	req->mc_buf		= (void *) buf;
	req->mc_bufflen         = task->task_size;
	req->mc_sg_count        = 0;

	return(0);
}

/*	mc_get_sense_buffer():
 *
 *	The iSCSI transport module calls this function to get a pointer to the
 *	media changer's sense buffer.
 */
extern unsigned char *mc_get_sense_buffer (se_task_t *task)
{
	mc_request_t *req;
	req = (mc_request_t *) task->transport_req;
	return((unsigned char *)&req->mc_sense_buffer[0]);
}

/*	mc_get_filename():
 *
 *	The virtual media changer works by simply moving file names around.
 *
 *	When a virtual tape device wants to do something like read or write
 *	data, it needs to get the file from the media changer.
 *
 *	This is the function that the virtual tape device calls to get the
 *	file name.
 *
 *	vt_device_id numbering begins at 1.
 */
extern char *mc_get_filename (int mc_host_id, int vt_device_id)
{
	int i, k;
	unsigned char *filename;
	se_hba_t *hba;
	mc_host_t *p;

	filename = NULL;

	/* find the media changer */

	spin_lock(&iscsi_global->hba_lock);

	for (i = 0; i < ISCSI_MAX_GLOBAL_HBAS; i++) {
		hba = &iscsi_global->hba_list[i];
		if (hba == NULL)
			continue;
		if (hba->type != MEDIA_CHANGER)
			continue;
		if (hba->hba_info.mc_host_id == mc_host_id)
			break;
	}

	if (i < ISCSI_MAX_GLOBAL_HBAS) {
		p = (mc_host_t *) hba->hba_ptr;
		if (vt_device_id > 0 && vt_device_id <= p->mc_ndte) {
			k = p->mc_fdte + vt_device_id - 1;
			filename = p->mc_slot[k];
		}
	}

	spin_unlock(&iscsi_global->hba_lock);

	return(filename);
}

/*	mc_filename_to_barcode()
 *
 *	Use the last part of the filename.
 */
static char *mc_filename_to_barcode(char *str)
{
	int i;
	char *s;
	if (str == NULL)
		return NULL;
	s = str + strlen(str);
	for (i = 0; i < 36; i++) {
		if (s == str)
			break;
		if (s[-1] == '/')
			break;
		s--;
	}
	return s;
}

/*	mc_write_md()
 *
 *	Write a medium transport element descriptor.
 *
 *	buf		where to put the data
 *
 *	addr		element address
 *
 *	voltag		include the volume tag (barcode)
 *
 *	filename	file name of element
 */
static void mc_write_md (
	unsigned char *buf,
	int addr,
	int voltag,
	char *filename)
{
	char *barcode;

	if (voltag)
		memset(buf, 0, 52);
	else
		memset(buf, 0, 16);

	/* element address */

	buf[0] = addr >> 8;
	buf[1] = addr;

	/* if there is a filename then FULL = 1 and MEDIUM TYPE = 1 */

	if (filename) {
		buf[2] |= 0x01;
		buf[9] |= 0x01;
	}

	/* primary volume tag information */

	if (voltag && filename) {
		barcode = mc_filename_to_barcode(filename);
		strncpy(buf + 12, barcode, 36);
	}
}

/*	mc_write_m()
 *
 *	Write medium transport element status.
 *
 *	buf		where to put the data
 *
 *	len		length of buf in bytes
 *
 *	voltag		include volume tag info
 *
 *	addr		starting element address
 *
 *	num		number of elements
 *
 *	p		pointer to mc_host_t
 *
 *	fe		pointer to first element address
 *
 *	ne		pointer to number of elements available
 */
static int mc_write_m (
	unsigned char *buf,
	int len,
	int voltag,
	int addr,
	int num,
	mc_host_t *p,
	int *fe,
	int *ne)
{
	int i, n, t, z;

	if (num == *ne)
		return(0);

	/* find the intersection of request and media changer
	 *
	 *	p->mc_fmte	first medium transport element address
	 *
	 *	p->mc_nmte	number of medium transport elements
	 */

	if (addr < p->mc_fmte)
		addr = p->mc_fmte;

	n = p->mc_fmte + p->mc_nmte - addr;

	if (n < 1)
		return(0);

	if (n > num - *ne)
		n = num - *ne;

	/* update ne */

	*ne += n;

	/* element descriptor length */

	if (voltag)
		z = 52;
	else
		z = 16;

	/* check buffer */

	if (len < 8 + z)
		return(0);

	memset(buf, 0, 8);

	/* ELEMENT TYPE CODE = 1 (medium transport element) */

	buf[0] = 1;

	/* if voltag then PVOLTAG = 1 */

	if (voltag)
		buf[1] |= 0x80;

	/* element descriptor length */

	buf[2] = z >> 8;
	buf[3] = z;

	/* update first element address */

	if (n == *ne)
		*fe = addr;	/* very first update (ne was zero) */
	else if (addr < *fe)
		*fe = addr;

	/* write storage element descriptors */

	t = 8;

	for (i = 0; i < n; i++) {

		/* buffer full? */

		if (t + z > len)
			break;

		mc_write_md(
			buf + t,
			addr + i,
			voltag,
			p->mc_slot[addr + i]);

		t += z;
	}

	/* byte count of descriptor data */

	n = t - 8;

	buf[5] = n >> 16;
	buf[6] = n >> 8;
	buf[7] = n;

	return t;
}

/*	mc_write_sd()
 *
 *	Write a storage element descriptor.
 *
 *	buf		where to put the data
 *
 *	addr		element address
 *
 *	voltag		include the volume tag (barcode)
 *
 *	filename	file name of element
 */
static void mc_write_sd (
	unsigned char *buf,
	int addr,
	int voltag,
	char *filename)
{
	char *barcode;

	if (voltag)
		memset(buf, 0, 52);
	else
		memset(buf, 0, 16);

	/* element address */

	buf[0] = addr >> 8;
	buf[1] = addr;

	/* ACCESS = 1 */

	buf[2] |= 0x08;

	/* if there is a filename then FULL = 1 and MEDIUM TYPE = 1 */

	if (filename) {
		buf[2] |= 0x01;
		buf[9] |= 0x01;
	}

	/* primary volume tag information */

	if (voltag && filename) {
		barcode = mc_filename_to_barcode(filename);
		strncpy(buf + 12, barcode, 36);
	}
}

/*	mc_write_s()
 *
 *	Write storage element status.
 *
 *	buf		where to put the data
 *
 *	len		length of buf in bytes
 *
 *	voltag		include volume tag info
 *
 *	addr		starting element address
 *
 *	num		number of elements
 *
 *	p		pointer to mc_host_t
 *
 *	fe		pointer to first element address
 *
 *	ne		pointer to number of elements available
 */
static int mc_write_s (
	unsigned char *buf,
	int len,
	int voltag,
	int addr,
	int num,
	mc_host_t *p,
	int *fe,
	int *ne)
{
	int i, n, t, z;

	if (num == *ne)
		return(0);

	/* find the intersection of request and media changer
	 *
	 *	p->mc_fse	first storage element address
	 *
	 *	p->mc_nse	number of storage elements
	 */

	if (addr < p->mc_fse)
		addr = p->mc_fse;

	n = p->mc_fse + p->mc_nse - addr;

	if (n < 1)
		return(0);

	if (n > num - *ne)
		n = num - *ne;

	/* update ne */

	*ne += n;

	/* element descriptor length */

	if (voltag)
		z = 52;
	else
		z = 16;

	/* check buffer */

	if (len < 8 + z)
		return(0);

	memset(buf, 0, 8);

	/* ELEMENT TYPE CODE = 2 (storage element) */

	buf[0] = 2;

	/* if voltag then PVOLTAG = 1 */

	if (voltag)
		buf[1] |= 0x80;

	/* element descriptor length */

	buf[2] = z >> 8;
	buf[3] = z;

	/* update first element address */

	if (n == *ne)
		*fe = addr;	/* very first update (ne was zero) */
	else if (addr < *fe)
		*fe = addr;

	/* write storage element descriptors */

	t = 8;

	for (i = 0; i < n; i++) {

		/* buffer full? */

		if (t + z > len)
			break;

		mc_write_sd(
			buf + t,
			addr + i,
			voltag,
			p->mc_slot[addr + i]);

		t += z;
	}

	/* byte count of descriptor data */

	n = t - 8;

	buf[5] = n >> 16;
	buf[6] = n >> 8;
	buf[7] = n;

	return t;
}

/*	mc_write_xd()
 *
 *	Write an import/export element descriptor.
 *
 *	buf		where to put the data
 *
 *	addr		element address
 *
 *	voltag		include the volume tag (barcode)
 *
 *	filename	file name of element
 */
static void mc_write_xd (
	unsigned char *buf,
	int addr,
	int voltag,
	char *filename)
{
	char *barcode;

	if (voltag)
		memset(buf, 0, 52);
	else
		memset(buf, 0, 16);

	/* element address */

	buf[0] = addr >> 8;
	buf[1] = addr;

	/* ACCESS = 1 */

	buf[2] |= 0x08;

	/* if there is a filename then FULL = 1 and MEDIUM TYPE = 1 */

	if (filename) {
		buf[2] |= 0x01;
		buf[9] |= 0x01;
	}

	/* primary volume tag information */

	if (voltag && filename) {
		barcode = mc_filename_to_barcode(filename);
		strncpy(buf + 12, barcode, 36);
	}
}

/*	mc_write_x()
 *
 *	Write import/export element status.
 *
 *	buf		where to put the data
 *
 *	len		length of buf in bytes
 *
 *	voltag		include volume tag info
 *
 *	addr		starting element address
 *
 *	num		number of elements
 *
 *	p		pointer to mc_host_t
 *
 *	fe		pointer to first element address
 *
 *	ne		pointer to number of elements available
 */
static int mc_write_x (
	unsigned char *buf,
	int len,
	int voltag,
	int addr,
	int num,
	mc_host_t *p,
	int *fe,
	int *ne)
{
	int i, n, t, z;

	if (num == *ne)
		return(0);

	/* find the intersection of request and media changer
	 *
	 *	p->mc_fxe	first import/export element address
	 *
	 *	p->mc_nxe	number of import/export elements
	 */

	if (addr < p->mc_fxe)
		addr = p->mc_fxe;

	n = p->mc_fxe + p->mc_nxe - addr;

	if (n < 1)
		return(0);

	if (n > num - *ne)
		n = num - *ne;

	/* update ne */

	*ne += n;

	/* element descriptor length */

	if (voltag)
		z = 52;
	else
		z = 16;

	/* check buffer */

	if (len < 8 + z)
		return(0);

	memset(buf, 0, 8);

	/* ELEMENT TYPE CODE = 3 (import/export element) */

	buf[0] = 3;

	/* if voltag then PVOLTAG = 1 */

	if (voltag)
		buf[1] |= 0x80;

	/* element descriptor length */

	buf[2] = z >> 8;
	buf[3] = z;

	/* update first element address */

	if (n == *ne)
		*fe = addr;	/* very first update (ne was zero) */
	else if (addr < *fe)
		*fe = addr;

	/* write storage element descriptors */

	t = 8;

	for (i = 0; i < n; i++) {

		/* buffer full? */

		if (t + z > len)
			break;

		mc_write_xd(
			buf + t,
			addr + i,
			voltag,
			p->mc_slot[addr + i]);

		t += z;
	}

	/* byte count of descriptor data */

	n = t - 8;

	buf[5] = n >> 16;
	buf[6] = n >> 8;
	buf[7] = n;

	return t;
}

/*	mc_write_dd()
 *
 *	Write a data transfer element descriptor.
 *
 *	buf		where to put the data
 *
 *	addr		element address
 *
 *	voltag		include the volume tag (barcode)
 *
 *	filename	file name of element
 */
static void mc_write_dd (
	unsigned char *buf,
	int addr,
	int voltag,
	char *filename)
{
	char *barcode;

	if (voltag)
		memset(buf, 0, 52);
	else
		memset(buf, 0, 16);

	/* element address */

	buf[0] = addr >> 8;
	buf[1] = addr;

	/* ACCESS = 1 */

	buf[2] |= 0x08;

	/* if there is a filename then FULL = 1 and MEDIUM TYPE = 1 */

	if (filename) {
		buf[2] |= 0x01;
		buf[9] |= 0x01;
	}

	/* primary volume tag information */

	if (voltag && filename) {
		barcode = mc_filename_to_barcode(filename);
		strncpy(buf + 12, barcode, 36);
	}
}

/*	mc_write_d()
 *
 *	Write data transfer element status.
 *
 *	buf		where to put the data
 *
 *	len		length of buf in bytes
 *
 *	voltag		include volume tag info
 *
 *	addr		starting element address
 *
 *	num		number of elements
 *
 *	p		pointer to mc_host_t
 *
 *	fe		pointer to first element address
 *
 *	ne		pointer to number of elements available
 */
static int mc_write_d (
	unsigned char *buf,
	int len,
	int voltag,
	int addr,
	int num,
	mc_host_t *p,
	int *fe,
	int *ne)
{
	int i, n, t, z;

	if (num == *ne)
		return(0);

	/* find the intersection of request and media changer
	 *
	 *	p->mc_fdte	first data transfer element address
	 *
	 *	p->mc_ndte	number of data transfer elements
	 */

	if (addr < p->mc_fdte)
		addr = p->mc_fdte;

	n = p->mc_fdte + p->mc_ndte - addr;

	if (n < 1)
		return(0);

	if (n > num - *ne)
		n = num - *ne;

	/* update ne */

	*ne += n;

	/* element descriptor length */

	if (voltag)
		z = 52;
	else
		z = 16;

	/* check buffer */

	if (len < 8 + z)
		return(0);

	memset(buf, 0, 8);

	/* ELEMENT TYPE CODE = 4 (data transfer element) */

	buf[0] = 4;

	/* if voltag then PVOLTAG = 1 */

	if (voltag)
		buf[1] |= 0x80;

	/* element descriptor length */

	buf[2] = z >> 8;
	buf[3] = z;

	/* update first element address */

	if (n == *ne)
		*fe = addr;	/* very first update (ne was zero) */
	else if (addr < *fe)
		*fe = addr;

	/* write storage element descriptors */

	t = 8;

	for (i = 0; i < n; i++) {

		/* buffer full? */

		if (t + z > len)
			break;

		mc_write_dd(
			buf + t,
			addr + i,
			voltag,
			p->mc_slot[addr + i]);

		t += z;
	}

	/* byte count of descriptor data */

	n = t - 8;

	buf[5] = n >> 16;
	buf[6] = n >> 8;
	buf[7] = n;

	return t;
}

/*	mc_read_element_status():
 *
 *
 */
static void mc_read_element_status (se_task_t *task)
{
	mc_request_t *req;
	int fe;
	int ne;
	int bc;
	int element_type_code;
	int voltag;
	int addr;
	int num;
	int len;
	unsigned char *buf;
	mc_host_t *p;

	/* task points to a device that points to an hba that points to private info */

	p = (mc_host_t *) task->iscsi_dev->iscsi_hba->hba_ptr;

	req = (mc_request_t *) task->transport_req;

	buf = (unsigned char *) T_TASK(task->iscsi_cmd)->t_task_buf;
	memset(buf, 0, task->iscsi_cmd->data_length);

	/* element type code */

	element_type_code = req->mc_scsi_cdb[1] & 0xf;

	/* volume tag */

	voltag = req->mc_scsi_cdb[1] & 0x10;

	/* starting element address */

	addr = 256 * req->mc_scsi_cdb[2] + req->mc_scsi_cdb[3];

	/* number of elements */

	num = 256 * req->mc_scsi_cdb[4] + req->mc_scsi_cdb[5];

	/* allocation length */

	len = 65536 * req->mc_scsi_cdb[7] + 256 * req->mc_scsi_cdb[8] + req->mc_scsi_cdb[9];

	if (len < 8)
		return;

	/* get ready */

	fe = 0;
	ne = 0;
	bc = 0;

	switch (element_type_code) {

	/* element type code = all element types */

	case 0:
		bc += mc_write_m(buf + 8 + bc, len - 8 - bc, voltag, addr, num, p, &fe, &ne);
		bc += mc_write_s(buf + 8 + bc, len - 8 - bc, voltag, addr, num, p, &fe, &ne);
		bc += mc_write_x(buf + 8 + bc, len - 8 - bc, voltag, addr, num, p, &fe, &ne);
		bc += mc_write_d(buf + 8 + bc, len - 8 - bc, voltag, addr, num, p, &fe, &ne);
		break;

	/* element type code = medium transport element */

	case 1:
		bc = mc_write_m(buf + 8, len - 8, voltag, addr, num, p, &fe, &ne);
		break;

	/* element type code = storage element */

	case 2:
		bc = mc_write_s(buf + 8, len - 8, voltag, addr, num, p, &fe, &ne);
		break;

	/* element type code = import/export element */

	case 3:
		bc = mc_write_x(buf + 8, len - 8, voltag, addr, num, p, &fe, &ne);
		break;

	/* element type code = data transfer element */

	case 4:
		bc = mc_write_d(buf + 8, len - 8, voltag, addr, num, p, &fe, &ne);
		break;

	default:
		break;
	}

	/* first element address reported */

	buf[0] = fe >> 8;
	buf[1] = fe;

	/* number of elements available */

	buf[2] = ne >> 8;
	buf[3] = ne;

	/* byte count */

	buf[5] = bc >> 16;
	buf[6] = bc >> 8;
	buf[7] = bc;
}
