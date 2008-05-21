/*********************************************************************************
 * Filename:  iscsi_target_vt.c
 *
 * This file contains the iSCSI <-> VTAPE transport specific functions.
 *
 * Copyright (c) 2006-2007 SBE, Inc.  All Rights Reserved.
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


#define ISCSI_TARGET_VTAPE_C

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
#include <iscsi_target_vt.h>
#include <iscsi_target_error.h>
 
extern iscsi_global_t *iscsi_global;

static int vt_dev_write_filemark(vt_dev_t *, int);
static int vt_write_filemark(iscsi_task_t *, int);
static int vt_mode_sense(iscsi_task_t *);
static int vt_request_sense(iscsi_task_t *);
static int vt_log_sense(iscsi_task_t *);
static int vt_read_position(iscsi_task_t *);

/* make it big endian */

static u64 swap(u64 n)
{
#ifdef ISCSI_BIG_ENDIAN
#else
	unsigned int t;
	t = htonl(((unsigned int *) &n)[0]);
	((unsigned int *) &n)[0] = htonl(((unsigned int *) &n)[1]);
	((unsigned int *) &n)[1] = t;
#endif
	return n;
}

/*	vt_attach_hba(): (Part of iscsi_transport_t template)
 *
 *
 */
extern int vt_attach_hba (
	iscsi_portal_group_t *tpg,
	iscsi_hba_t *hba,
	iscsi_hbainfo_t *hi)
{
	vt_host_t *vt_host;

	if (!(vt_host = kmalloc(sizeof(vt_host_t), GFP_KERNEL))) {
		TRACE_ERROR("Unable to allocate memory for vt_host_t\n");
		return(-1);
	}
	memset(vt_host, 0, sizeof(vt_host_t));

	vt_host->vt_host_id = hi->vt_host_id;

	atomic_set(&hba->left_queue_depth, VT_HBA_QUEUE_DEPTH);
	atomic_set(&hba->max_queue_depth, VT_HBA_QUEUE_DEPTH);
	hba->hba_ptr = (void *) vt_host;
	hba->hba_id = hi->hba_id;
	hba->transport = &vtape_template;

	PYXPRINT("iSCSI_HBA[%d] - %s Virtual TAPE HBA Driver %s for iSCSI"
		" Target Core Stack %s\n", hba->hba_id, PYX_ISCSI_VENDOR, VT_VERSION, PYX_ISCSI_VERSION);
	
	PYXPRINT("iSCSI_HBA[%d] - Attached Virtual TAPE HBA: %u to iSCSI Transport with"
		" TCQ Depth: %d MaxSectors: %u\n", hba->hba_id, vt_host->vt_host_id,
		atomic_read(&hba->max_queue_depth), VT_MAX_SECTORS);

	return(0);
}

/*	vt_detach_hba(): (Part of iscsi_transport_t template)
 *
 *
 */
extern int vt_detach_hba (iscsi_hba_t *hba)
{
	vt_host_t *vt_host;
	
	if (!hba->hba_ptr) {
		TRACE_ERROR("hba->hba_ptr is NULL!\n");
		return(-1);
	}
	vt_host = (vt_host_t *) hba->hba_ptr;

	PYXPRINT("iSCSI_HBA[%d] - Detached Virtual TAPE HBA: %u from iSCSI Transport\n",
			hba->hba_id, vt_host->vt_host_id);

	kfree(vt_host);
	hba->hba_ptr = NULL;

	return(0);
}

extern char *mc_get_filename(int, int);

/*	vt_open_file()
 *
 *	If the tape drive is associated with a media changer then get the file
 *	name from the media changer plug-in.
 */
static int vt_open_file (iscsi_task_t *task, int trunc)
{
	char *dev_p;
	char *filename;
	vt_request_t *req;
	struct file *fd;
	mm_segment_t old_fs;

	req = (vt_request_t *) task->transport_req;

	if (req->vt_dev->vt_file)
		return(0); /* already open */

	req->vt_dev->vt_read_limit = 0;
	req->vt_dev->vt_written = 0;

	if (req->vt_dev->vt_mc_host_id > 0) {
		if (atomic_dec_and_test(&req->vt_dev->vt_lock)) {
			filename = mc_get_filename(req->vt_dev->vt_mc_host_id, req->vt_dev->vt_dev_id);
			if (filename == NULL) {
				atomic_inc(&req->vt_dev->vt_lock);
				return(-1);
			}
		} else {
			return(-1); /* media changer has the lock */
		}
	} else {
		filename = req->vt_dev->vt_dev_name;
		if (filename == NULL)
			return(-1);
	}

	old_fs = get_fs();
	set_fs(get_ds());
	dev_p = getname(filename);
	set_fs(old_fs);

	if (IS_ERR(dev_p)) {
		TRACE_ERROR("getname(%s) failed: %lu\n", filename,
				IS_ERR(dev_p));
		if (req->vt_dev->vt_mc_host_id > 0)
			atomic_inc(&req->vt_dev->vt_lock);
		return(-1);
	}
	
	fd = filp_open(dev_p,  O_RDWR | O_NONBLOCK | O_CREAT | O_LARGEFILE | trunc, 0600);

	putname(dev_p);

	if (IS_ERR(fd) || !fd || !fd->f_dentry) {
		TRACE_ERROR("filp_open(%s) failed\n", dev_p);
		if (req->vt_dev->vt_mc_host_id > 0)
			atomic_inc(&req->vt_dev->vt_lock);
		return(-1);
	}

	req->vt_dev->vt_file = fd;

	return(0);
}

static void vt_dev_close_file (vt_dev_t *vt_dev)
{
	if (vt_dev->vt_file == NULL)
		return;
	if (vt_dev->vt_written)
		vt_dev_write_filemark(vt_dev, 0);
	filp_close(vt_dev->vt_file, NULL);
	vt_dev->vt_file = NULL;
	if (vt_dev->vt_mc_host_id > 0)
		atomic_inc(&vt_dev->vt_lock);
}

static void vt_close_file (iscsi_task_t *task)
{
	vt_request_t *req;
	req = (vt_request_t *) task->transport_req;
	vt_dev_close_file(req->vt_dev);
}

static void vt_write_filemark_maybe (iscsi_task_t *task)
{
	vt_request_t *req;
	vt_dev_t *vt_dev;
	req = (vt_request_t *) task->transport_req;
	vt_dev = req->vt_dev;
	if (vt_dev->vt_written)
		vt_write_filemark(task, 0);
}

/*	vt_create_virtdevice(): (Part of iscsi_transport_t template)
 *
 *
 */
extern int vt_create_virtdevice (iscsi_hba_t *iscsi_hba, iscsi_devinfo_t *di)
{
	iscsi_device_t *dev;
	vt_dev_t *vt_dev;
	vt_host_t *vt_host = (vt_host_t *) iscsi_hba->hba_ptr;

	if (strlen(di->fd_dev_name) > VT_MAX_DEV_NAME) {
		TRACE_ERROR("di->fd_dev_name exceeds VT_MAX_DEV_NAME: %d\n",
				VT_MAX_DEV_NAME);
		return(0);
	}

	if (!(vt_dev = (vt_dev_t *) kmalloc(sizeof(vt_dev_t), GFP_KERNEL))) {
		TRACE_ERROR("Unable to allocate memory for fd_dev_t\n");
		return(0);
	}

	memset(vt_dev, 0, sizeof(vt_dev_t));

	vt_dev->vt_dev_id = di->vt_device_id;
	vt_dev->vt_hw_id = di->vt_hw_id;
	vt_dev->vt_mc_host_id = di->vt_mc_host_id;
	vt_dev->vt_host = vt_host;
	vt_dev->vt_dev_size = di->fd_device_size;
	sprintf(vt_dev->vt_dev_name, "%s", di->fd_dev_name);

	atomic_set(&vt_dev->vt_lock, 1);

	if (!(dev = vt_add_device_to_list(iscsi_hba, vt_dev)))
		goto fail;

	vt_dev->vt_queue_depth = dev->queue_depth;

	PYXPRINT("iSCSI_FILE[%u] - Added Virtual TAPE Device ID: %u at %s,"
		" %llu total bytes\n", vt_host->vt_host_id, vt_dev->vt_dev_id,
			vt_dev->vt_dev_name, vt_dev->vt_dev_size);

	return(1);

fail:

	kfree(vt_dev);

	return(0);
}

/*	vt_add_device_to_list():
 *
 *
 */
extern iscsi_device_t *vt_add_device_to_list (iscsi_hba_t *iscsi_hba, void *vt_dev_p)
{
	iscsi_device_t *dev;
	vt_dev_t *vt_dev = (vt_dev_t *) vt_dev_p;
	
	if (!(dev = transport_add_device_to_iscsi_hba(iscsi_hba, &vtape_template, 
				DF_DISABLE_STATUS_THREAD, (void *)vt_dev)))
		return(NULL);

	return(dev);
}

/*	vt_activate_device(): (Part of iscsi_transport_t template)
 *
 *
 */
extern int vt_activate_device (iscsi_device_t *dev)
{
	vt_dev_t *vt_dev = (vt_dev_t *) dev->dev_ptr;
	vt_host_t *vt_host = vt_dev->vt_host;
	
	PYXPRINT("iSCSI_FILE[%u] - Activating Device with TCQ: %d at VTAPE"
		" Device ID: %d\n", vt_host->vt_host_id, vt_dev->vt_queue_depth,
		vt_dev->vt_dev_id);

	return(0);
}

/*	vt_deactivate_device(): (Part of iscsi_transport_t template)
 *
 *
 */
extern void vt_deactivate_device (iscsi_device_t *dev)
{
	vt_dev_t *vt_dev = (vt_dev_t *) dev->dev_ptr;
	vt_host_t *vt_host = vt_dev->vt_host;

	PYXPRINT("iSCSI_FILE[%u] - Deactivating Device with TCQ: %d at VTAPE"
		" Device ID: %d\n", vt_host->vt_host_id, vt_dev->vt_queue_depth,
		vt_dev->vt_dev_id);

	return;
}

/*	vt_check_device_location(): (Part of iscsi_transport_t template)
 *
 *
 */
extern int vt_check_device_location (iscsi_device_t *dev, iscsi_dev_transport_info_t *dti)
{
	vt_dev_t *vt_dev = (vt_dev_t *) dev->dev_ptr;

	if (dti->vt_device_id == vt_dev->vt_dev_id)
		return(0);

	return(-1);
}

extern int vt_check_ghost_id (iscsi_hbainfo_t *hi)
{
	int i;          
	iscsi_hba_t *hba;
	vt_host_t *fh;

	spin_lock(&iscsi_global->hba_lock);
	for (i = 0; i < ISCSI_MAX_GLOBAL_HBAS; i++) {
		hba = &iscsi_global->hba_list[i];

		if (!(hba->hba_status & HBA_STATUS_ACTIVE))
			continue;
		if (hba->type != VTAPE)
			continue;

		fh = (vt_host_t *) hba->hba_ptr;
		if (fh->vt_host_id == hi->vt_host_id) {
			TRACE_ERROR("VTAPE HBA with VT_HOST_ID: %u already"
				" assigned to iSCSI HBA: %hu, ignoring request\n",
				hi->vt_host_id, hba->hba_id);
			spin_unlock(&iscsi_global->hba_lock);
			return(-1);
		}
	}
	spin_unlock(&iscsi_global->hba_lock);
		
	return(0);
}

/*	vt_free_device(): (Part of iscsi_transport_t template)
 *
 *
 */
extern void vt_free_device (iscsi_device_t *dev)
{
	vt_dev_t *vt_dev = (vt_dev_t *) dev->dev_ptr;
	if (vt_dev == NULL)
		return;
	vt_dev_close_file(vt_dev);
	kfree(vt_dev);
	dev->dev_ptr = NULL;
	return;
}

/*	vt_transport_complete(): (Part of iscsi_transport_t template)
 *
 *
 */
extern int vt_transport_complete (iscsi_task_t *task)
{
	int t;
	vt_request_t *req = (vt_request_t *) task->transport_req;
	t = req->vt_dev->vt_sense_flag;
	req->vt_dev->vt_sense_flag = 0;
	return(t);
}

/*	vt_allocate_request(): (Part of iscsi_transport_t template)
 *
 *
 */
extern void *vt_allocate_request (
	iscsi_task_t *task,
	iscsi_device_t *dev)
{
	vt_request_t *vt_req;
	
	if (!(vt_req = (vt_request_t *) kmalloc(sizeof(vt_request_t), GFP_KERNEL))) {
		TRACE_ERROR("Unable to allocate vt_request_t\n");
		return(NULL);
	}
	memset(vt_req, 0, sizeof(vt_request_t));

	vt_req->vt_dev = (vt_dev_t *) dev->dev_ptr;

	return((void *)vt_req);
}

extern void vt_get_evpd_prod (unsigned char *buf, u32 size, iscsi_device_t *dev)
{
	snprintf(buf, size, "VTAPE");
	return;
}

extern void vt_get_evpd_sn (unsigned char *buf, u32 size, iscsi_device_t *dev)
{
	vt_dev_t *fdev = (vt_dev_t *) dev->dev_ptr;
	iscsi_hba_t *hba = dev->iscsi_hba;

	snprintf(buf, size, "%u_%u", hba->hba_id, fdev->vt_dev_id);	
	return;
}

/* Each string must be exactly 28 bytes long:

	Vendor		 8 bytes
	Product		16 bytes
	Revision	 4 bytes
*/

static char *hw[] = {
//       1234567812345678901234561234
//       |       |               |
	"GENERIC SCSI-2          0001", //  0
	"HP      Ultrium 1-SCSI  E30W", //  1
	"HP      Ultrium 2-SCSI  F38W", //  2
	"HP      Ultrium 3-SCSI  G27D", //  3
	"IBM     ULTRIUM-TD1     18N2", //  4
	"IBM     ULTRIUM-TD2     4770", //  5
	"IBM     ULTRIUM-TD3     4C17", //  6
	"IBM     ULT3580-TD1     22UD", //  7
	"IBM     ULT3580-TD2     333K", //  8
	"IBM     ULT3580-TD3     4C17", //  9
	"IBM     03590E11        F26E", // 10
	"IBM     03590B11        F26E", // 11
	"IBM     03590E1A        F26E", // 12
	"IBM     03590B1A        F26E", // 13
	"IBM     03592J1A        044C", // 14
	"QUANTUM DLT7000         2150", // 15
	"QUANTUM DLT8000         010F", // 16
	"QUANTUM SuperDLT1       1414", // 17
	"QUANTUM SDLT320         V62 ", // 18
	"SEAGATE ULTRIUM06242-XXX1460", // 19
	"SONY    SDX-300C        0101", // 20
	"SONY    SDX-500C        0204", // 21
	"SONY    SDX-700C        0204", // 22
	"SONY    SDZ-100         0200", // 23
	"SONY    SDZ-130         0200", // 24
	"STK     9840                ", // 25
	"STK     T9840B              ", // 26
	"STK     T9940B              ", // 27
};

// Example standard INQUIRY response from IBM tape drive

//	SCSI Payload (Inquiry Response)
//	    LUN: 0x0001
//	    Opcode: Inquiry (0x12)
//	    000. .... = Peripheral Qualifier: Device type is connected to logical unit (0x00)
//	    ...0 0001 = Peripheral Device Type: Sequential Access Device (0x01)
//	    1... .... = Removable: This is a REMOVABLE device
//	    Version: Compliance to ANSI X3.301:1997 (0x03)
//	    Flags: 0x02  RDF:SPC-2/SPC-3
//	        0... .... = AERC: Async event reporting capability is NOT supported
//	        .0.. .... = TrmTsk: Terminate task management functions are NOT supported
//	        ..0. .... = NormACA: Normaca is NOT supported
//	        ...0 .... = HiSup: Hierarchical addressing mode is NOT supported
//	        .... 0010 = Response Data Format: SPC-2/SPC-3 (2)
//	    Additional Length: 53
//	    Flags: 0x00
//	        0... .... = SCCS: Scc is NOT supported
//	        .0.. .... = ACC: Access control coordinator NOT supported
//	        ..00 .... = TPGS: Assymetric LU Access not supported (0)
//	        .... 0... = 3PC: Third party copy is NOT supported
//	        .... ...0 = Protect: Protection information NOT supported
//	    Flags: 0x01
//	        0... .... = BQue: Bque is NOT supported
//	        .0.. .... = EncServ: Enclosed services is NOT supported
//	        ...0 .... = MultiP: This is NOT a multiport device
//	        .... 0... = MChngr: This is a normal device
//	    Flags: 0x30  Sync
//	        0... .... = RelAdr: Relative addressing mode is NOT supported
//	        ...1 .... = Sync: Synchronous data transfer is SUPPORTED
//	        .... 0... = Linked: Linked commands are NOT supported
//	        .... ..0. = CmdQue: Command queuing is NOT supported
//	    Vendor Id: IBM     
//	    Product Id: ULTRIUM-TD2     
//	    Product Revision Level: 4770
//	SCSI Response
//	    LUN: 0x0001
//	    Request in: 29
//	    Time from request: 0.062500000 seconds
//	    Status: Good (0x00)
//
//	0000  05 00 05 00 00 00 f8 30 20 00 05 00 08 00 45 00   .......0 .....E.
//	0010  00 94 b1 f1 00 00 3f 06 16 72 c6 5d 91 6e c6 5d   ......?..r.].n.]
//	0020  94 d7 0c bc 07 99 3a ee d8 b3 66 50 01 4b 50 18   ......:...fP.KP.
//	0030  ff ff b6 99 00 00 25 83 00 00 00 00 00 3a 00 00   ......%......:..
//	0040  00 00 00 00 00 00 00 00 00 0b ff ff ff ff 00 00   ................
//	0050  00 0d 00 00 00 0c 00 00 00 0e 00 00 00 00 00 00   ................
//	0060  00 00 00 00 00 c2 01 80 03 02 35 00 01 30 49 42   ..........5..0IB
//	0070  4d 20 20 20 20 20 55 4c 54 52 49 55 4d 2d 54 44   M     ULTRIUM-TD
//	0080  32 20 20 20 20 20 34 37 37 30 00 00 00 00 00 00   2     4770......
//	0090  00 00 00 00 00 00 00 00 00 00 00 00 00 00 0c 00   ................
//	00a0  00 00                                             ..

/*	vt_inquiry():
 *
 *
 */
static int vt_inquiry (iscsi_task_t *task)
{
	int page_code, len;

	iscsi_cmd_t *cmd = task->iscsi_cmd;
	vt_dev_t *dev = (vt_dev_t *) task->iscsi_dev->dev_ptr;
	unsigned char *cdb = T_TASK(cmd)->t_task_cdb;
	unsigned char *dst = (unsigned char *) T_TASK(cmd)->t_task_buf;
	unsigned char buf[100];
	unsigned int n;

	memset(dst, 0, cmd->data_length);
	memset(buf, 0, 100);

	page_code = cdb[2];

	// if the EVPD bit is zero then return the standard INQUIRY data

	if ((cdb[1] & 1) == 0) {
		buf[0] = TYPE_TAPE;
		buf[1] = 0x80; /* removable media */
		buf[2] = 0x02; /* version */
		buf[3] = 0x02; /* response data format */
		buf[4] = 31; /* additional length */
		buf[5] = 0x00;
		buf[6] = 0x01;
		buf[7] = 0x30;
		n = dev->vt_hw_id;
		if (n > sizeof hw / sizeof (char *))
			n = 0; /* generic */
		strncpy(buf + 8, hw[n], 28);
		len = 36;
		if (len > cmd->data_length)
			len = cmd->data_length;
		memcpy(dst, buf, len);
		return(0);
	}

	buf[0] = TYPE_TAPE;
	buf[1] = page_code;

	switch (page_code) {
	case 0x00: /* supported vital product data pages */
		buf[4] = 0x00;
		buf[5] = 0x80;
		buf[6] = 0x83;
		len = 7;
		break;
	case 0x80: /* unit serial number */
		strcpy(buf + 4, "101100161F");
		len = 14;
		break;
	case 0x83: /* device identification */
		buf[4] = 0x02;
		buf[5] = 0x01;
		buf[6] = 0x00;
		buf[7] = 34; /* length */
		strcpy(buf + 8, "IBM     ULTRIUM-TD2     101100161F");
		len = 42;
		break;
	default:
		TRACE_ERROR("Unknown EVPD Code: 0x%02x\n", page_code);
		len = 4;
		break;
	}

	buf[3] = len - 4; /* length */

	if (len > cmd->data_length)
		len = cmd->data_length;
	memcpy(dst, buf, len);
	return(0);
}

/*	vt_write_filemark():
 *
 *
 */
static int vt_write_filemark(iscsi_task_t *task, int setmark)
{
	vt_request_t *req;
	req = (vt_request_t *) task->transport_req;
	return vt_dev_write_filemark(req->vt_dev, setmark);
}

static int vt_dev_write_filemark(vt_dev_t *vt_dev, int setmark)
{
	int ret;
	struct file *f;
	mm_segment_t old_fs;
	u64 len, mark;

	f = vt_dev->vt_file;

	if (f == NULL) {
		vt_dev->vt_written = 0;
		return(0);
	}

	// if no bytes written then write an empty record

	if (vt_dev->vt_written == 0) {
		mark = 0;
		old_fs = get_fs();
		set_fs(get_ds());
		// write opening mark
		if ((ret = f->f_op->write(f, (char *) &mark, 8, &f->f_pos)) < 0) {
			TRACE_ERROR("f->f_op->write returned %d\n", ret);
			set_fs(old_fs);
			return(-1);
		}
		if (setmark)
			((unsigned char *) &mark)[0] |= 0x80; // set bit 63
		// write closing mark
		if ((ret = f->f_op->write(f, (char *) &mark, 8, &f->f_pos)) < 0) {
			TRACE_ERROR("f->f_op->write returned %d\n", ret);
			set_fs(old_fs);
			return(-1);
		}
		set_fs(old_fs);
		return(0);
	}

	len = vt_dev->vt_written;
	vt_dev->vt_written = 0;

	mark = swap(len); // make it big endian

	old_fs = get_fs();
	set_fs(get_ds());

	// go to start of file

	if (f->f_op->llseek(f, -(len + 8), 1) < 0) {
		TRACE_ERROR("f->f_op->llseek failed\n");
		set_fs(old_fs);
		return(-1);
	}

	// write opening mark

	if ((ret = f->f_op->write(f, (char *) &mark, 8, &f->f_pos)) < 8) {
		TRACE_ERROR("f->f_op->write returned %d\n", ret);
		set_fs(old_fs);
		return(-1);
	}

	// go to end of file

	if (f->f_op->llseek(f, len, 1) < 0) {
		TRACE_ERROR("f->f_op->llseek failed\n");
		set_fs(old_fs);
		return(-1);
	}

	// write closing mark

	if (setmark)
		((unsigned char *) &mark)[0] |= 0x80; // set bit 63

	if ((ret = f->f_op->write(f, (char *) &mark, 8, &f->f_pos)) < 8) {
		TRACE_ERROR("f->f_op->write returned %d\n", ret);
		set_fs(old_fs);
		return(-1);
	}

	set_fs(old_fs);

	return(0);
}

static int vt_emulate_flush(iscsi_task_t *task)
{
	vt_request_t *req;
	struct file *f;
	mm_segment_t old_fs;
	u64 pos;

	req = (vt_request_t *) task->transport_req;
	f = req->vt_dev->vt_file;

	if (f == NULL)
		return(-1);

	// save the current position

	pos = f->f_pos;

	// close then open again

	vt_close_file(task);
	vt_open_file(task, 0);

	// seek to old position

	f = req->vt_dev->vt_file;
	if (f == NULL)
		return(-1);

	old_fs = get_fs();
	set_fs(get_ds());
	if (f->f_op->llseek(f, pos, 0) < 0) {
		TRACE_ERROR("fd->f_op->llseek failed\n");
		set_fs(old_fs);
		return(-1);
	}
	set_fs(old_fs);

	return(0);
}

/*	vt_goto_next_filemark():
 *
 *	return
 *	value
 *
 *	2	at setmark
 *
 *	1	at end of tape
 *
 *	0	ok
 *
 *	-1	error
 */
static int vt_goto_next_filemark(iscsi_task_t *task, int op)
{
	int ret, setmark;
	vt_request_t *req;
	struct file *fd;
	mm_segment_t old_fs;
	u64 len, mark;

	req = (vt_request_t *) task->transport_req;
	fd = req->vt_dev->vt_file;

	// read file length

	old_fs = get_fs();
	set_fs(get_ds());
	ret = fd->f_op->read(fd, (char *) &mark, 8, &fd->f_pos);
	set_fs(old_fs);

	len = swap(mark);

	// end of file?

	if (ret == 0)
		return(1);

	// error?

	if (ret != 8)
		return(-1);

	// llseek to closing mark

	old_fs = get_fs();
	set_fs(get_ds());
	if (fd->f_op->llseek(fd, len, 1) < 0) {
		TRACE_ERROR("fd->f_op->llseek failed\n");
		set_fs(old_fs);
		return(-1);
	}
	set_fs(old_fs);

	// read closing mark

	old_fs = get_fs();
	set_fs(get_ds());
	if ((ret = fd->f_op->read(fd, (char *) &mark, 8, &fd->f_pos)) < 8) {
		TRACE_ERROR("fd->f_op->llseek failed\n");
		set_fs(old_fs);
		return(-1);
	}
	set_fs(old_fs);

	// check for setmark

	setmark = ((unsigned char *) &mark)[0] & 0x80;

	if (setmark && op == 0) {
		old_fs = get_fs();
		set_fs(get_ds());
		if (fd->f_op->llseek(fd, -(len + 16), 1) < 0) {
			TRACE_ERROR("fd->f_op->llseek failed\n");
			set_fs(old_fs);
			return(-1);
		}
		set_fs(old_fs);
	}

	if (setmark)
		return(2);
	else
		return(0);
}

/*	vt_goto_previous_filemark():
 *
 *	return
 *	value
 *
 *	2	at setmark
 *
 *	1	at beginning of tape
 *
 *	0	ok
 *
 *	-1	error
 */
static int vt_goto_previous_filemark(iscsi_task_t *task, int op)
{
	int ret, setmark;
	vt_request_t *req;
	struct file *fd;
	mm_segment_t old_fs;
	u64 len, mark;

	req = (vt_request_t *) task->transport_req;
	fd = req->vt_dev->vt_file;

	// at beginning?

	if (fd->f_pos == 0)
		return(1);

	// go to closing mark

	old_fs = get_fs();
	set_fs(get_ds());
	if (fd->f_op->llseek(fd, -8, 1) < 0) {
		TRACE_ERROR("fd->f_op->llseek failed\n");
		set_fs(old_fs);
		return(-1);
	}
	set_fs(old_fs);

	// read closing mark

	old_fs = get_fs();
	set_fs(get_ds());
	if ((ret = fd->f_op->read(fd, (char *) &mark, 8, &fd->f_pos)) < 8) {
		TRACE_ERROR("fd->f_op->read returned %d\n", ret);
		set_fs(old_fs);
		return(-1);
	}
	set_fs(old_fs);

	setmark = ((unsigned char *) &mark)[0] & 0x80;
	((unsigned char *) &mark)[0] &= ~0x80;
	len = swap(mark);

	if (setmark && op == 0)
		return(2);

	// go to opening mark

	old_fs = get_fs();
	set_fs(get_ds());
	if (fd->f_op->llseek(fd, -(len + 16), 1) < 0) {
		TRACE_ERROR("fd->f_op->llseek failed\n");
		set_fs(old_fs);
		return(-1);
	}
	set_fs(old_fs);

	if (setmark)
		return(2);
	else
		return(0);
}

/*	vt_goto_next_setmark():
 *
 *	return
 *	value
 *
 *	1	at end of tape
 *
 *	0	ok
 *
 *	-1	error
 */
static int vt_goto_next_setmark(iscsi_task_t *task)
{
	int ret;
	vt_request_t *req;
	struct file *fd;

	req = (vt_request_t *) task->transport_req;
	fd = req->vt_dev->vt_file;

	while ((ret = vt_goto_next_filemark(task, 1)) == 0)
		;

	if (ret == 2)
		ret = 0; // convert setmark to ok

	return(ret);
}

/*	vt_goto_previous_setmark():
 *
 *	return
 *	value
 *
 *	1	at beginning of tape
 *
 *	0	ok
 *
 *	-1	error
 */
static int vt_goto_previous_setmark(iscsi_task_t *task)
{
	int ret;
	vt_request_t *req;
	struct file *fd;

	req = (vt_request_t *) task->transport_req;
	fd = req->vt_dev->vt_file;

	// go back until we pass a setmark

	while ((ret = vt_goto_previous_filemark(task, 1)) == 0)
		;

	if (ret == 2) {
		// now go back to the previous setmark
		while ((ret = vt_goto_previous_filemark(task, 0)) == 0)
			;
		if (ret == 2)
			ret = 0; // convert setmark to ok
	}

	return(ret);
}

/*	vt_emulate_space():
 *
 *
 */
static int vt_emulate_space(iscsi_task_t *task, int code, int count)
{
	int i, ret;
	vt_request_t *req;
	struct file *fd;
	mm_segment_t old_fs;
	u64 len;

	vt_open_file(task, 0);

	req = (vt_request_t *) task->transport_req;
	fd = req->vt_dev->vt_file;

	if (fd == NULL)
		return(-1);

	// if the count is zero then do nothing

	if (count == 0)
		return(0);

	// if in the middle of a read then go back to the beginning file mark

	if (req->vt_dev->vt_read_limit) {
		len = req->vt_dev->vt_read_count;
		req->vt_dev->vt_read_count = 0;
		req->vt_dev->vt_read_limit = 0;
		old_fs = get_fs();
		set_fs(get_ds());
		if (fd->f_op->llseek(fd, -(len + 8), 1) < 0) {
			TRACE_ERROR("fd->f_op->llseek failed\n");
			set_fs(old_fs);
			return(-1);
		}
		set_fs(old_fs);
	}

	// if code is 0 or 1 then go to the next file

	if (code == 0 || code == 1) {
		if (count < 0) {
			count = -count;
			for (i = 0; i < count; i++) {
				if ((ret = vt_goto_previous_filemark(task, 0)) < 0)
					return(-1);
				if (ret == 1 || ret == 2)
					return(0); // at beginning of tape (or setmark)
			}
		} else {
			for (i = 0; i < count; i++) {
				if ((ret = vt_goto_next_filemark(task, 0)) < 0)
					return(-1);
				if (ret == 1 || ret == 2)
					return(0); // at end of tape (or setmark)
			}
		}
		return(0);
	}

	// if code is 4 then space over setmarks

	if (code == 4) {
		if (count < 0) {
			count = -count;
			for (i = 0; i < count; i++) {
				if ((ret = vt_goto_previous_setmark(task)) < 0)
					return(-1);
				if (ret == 1)
					return(0); // at beginning of tape
			}
		} else {
			for (i = 0; i < count; i++) {
				if ((ret = vt_goto_next_setmark(task)) < 0)
					return(-1);
				if (ret == 1)
					return(0); // at end of tape
			}
		}
		return(0);
	}

	// if code is 3 then go to the end

	if (code == 3) {
		old_fs = get_fs();
		set_fs(get_ds());
		if (fd->f_op->llseek(fd, 0, 2) < 0) {
			TRACE_ERROR("fd->f_op->llseek failed\n");
			set_fs(old_fs);
			return(-1);
		}
		set_fs(old_fs);
		return(0);
	}

	return(-1);
}

/*	vt_emulate_read_block_limits():
 *
 *
 */
static int vt_emulate_read_block_limits (
	iscsi_cmd_t *cmd, 
	u32 max_len,
	u32 min_len)
{
	unsigned char *buf = (unsigned char *) T_TASK(cmd)->t_task_buf;

	buf[0] = 0;
	buf[1] = max_len >> 16;
	buf[2] = max_len >> 8;
	buf[3] = max_len;
	buf[4] = min_len >> 8;
	buf[5] = min_len;

	return(0);
}

/* The SCSI standard says tape drives do not support READ_CAPACITY.
   However, something in the iSCSI code is sending it anyway. */

/*	vt_emulate_read_cap():
 *
 *
 */
static int vt_emulate_read_cap (iscsi_task_t *task)
{
	u32 blocks = (1000000000 / VT_BLOCKSIZE) - 1;
	return(transport_generic_emulate_readcapacity(task->iscsi_cmd, blocks, VT_BLOCKSIZE));
}

/*	vt_emulate_scsi_cdb():
 *
 *
 */
static int vt_emulate_scsi_cdb (iscsi_task_t *task)
{
	int ret, i, n, code, count, setmark;
	vt_request_t *vt_req = (vt_request_t *) task->transport_req;

	switch (vt_req->vt_scsi_cdb[0]) {
	case INQUIRY:
		vt_inquiry(task);
		break;
	case MODE_SENSE:
		vt_mode_sense(task);
		break;
	case READ_BLOCK_LIMITS:
		vt_emulate_read_block_limits(task->iscsi_cmd, 0xffffff, 1);
		break;
	case REZERO_UNIT:
		vt_close_file(task);
		break;
	case ERASE:
		vt_close_file(task);
		vt_open_file(task, O_TRUNC);
		vt_close_file(task);
		break;
	case WRITE_FILEMARKS:
		setmark = vt_req->vt_scsi_cdb[1] & 2;
		n = (vt_req->vt_scsi_cdb[2] << 16) | (vt_req->vt_scsi_cdb[3] << 8) | vt_req->vt_scsi_cdb[4];
		for (i = 0; i < n; i++) {
			if (vt_write_filemark(task, setmark))
				return(PYX_TRANSPORT_LOGICAL_UNIT_COMMUNICATION_FAILURE);
		}
		if ((ret = vt_emulate_flush(task)) < 0)
			return(ret);
		break;
	case SPACE:
		vt_write_filemark_maybe(task);
		code = vt_req->vt_scsi_cdb[1] & 7;
		count = (vt_req->vt_scsi_cdb[2] << 16) | (vt_req->vt_scsi_cdb[3] << 8) | vt_req->vt_scsi_cdb[4];
		if (count & 0x00800000)
			count |= 0xff000000; // sign extension
		if ((ret = vt_emulate_space(task, code, count)) < 0)
			return(ret);
		break;
	case READ_CAPACITY:
		if ((ret = vt_emulate_read_cap(task)) < 0)
			return(ret);
		break;
	case START_STOP: /* actually, this is LOAD UNLOAD per SCSI spec */
		if ((vt_req->vt_scsi_cdb[4] & 1) == 0)
			vt_close_file(task);
		break;
	case REQUEST_SENSE:
		vt_request_sense(task);
		break;
	case LOG_SENSE:
		vt_log_sense(task);
		break;
	case READ_POSITION:
		vt_read_position(task);
		break;
	case MODE_SELECT:
	case ALLOW_MEDIUM_REMOVAL:
	case LOAD_UNLOAD_MEDIUM:
	case TEST_UNIT_READY:
	case VERIFY:
	case RESERVE:
	case RESERVE_10:
	case RELEASE:
	case RELEASE_10:
		break;
	default:
		TRACE_ERROR("Unsupported SCSI Opcode: 0x%02x for VTAPE\n",
				vt_req->vt_scsi_cdb[0]);
		return(PYX_TRANSPORT_UNKNOWN_SAM_OPCODE);
	}

	task->task_scsi_status = GOOD;
	transport_complete_task(task, 1);

	return(PYX_TRANSPORT_SENT_TO_TRANSPORT);
}

static int vt_do_read (vt_request_t *req)
{
	int i, n, ret;
	unsigned char *buf;
	struct file *fd = req->vt_dev->vt_file;
	struct scatterlist *sg = (struct scatterlist *) req->vt_buf;
	mm_segment_t old_fs = { 0 };
	u64 len, mark;

	if (fd == NULL)
		return(-1);

	if (req->vt_dev->vt_read_limit == 0) {
		old_fs = get_fs();
		set_fs(get_ds());
		// read beginning file mark
		ret = fd->f_op->read(fd, (char *) &mark, 8, &fd->f_pos);
		if (ret != 0 && ret != 8) {
			TRACE_ERROR("fd->f_op->read() returned %d\n", ret);
			set_fs(old_fs);
			return(-1);
		}
		// eof?
		if (ret == 0) {
			set_fs(old_fs);
			// eom
			req->vt_dev->vt_sense_buffer[0] = 0xf0;
			req->vt_dev->vt_sense_buffer[1] = 0;
			req->vt_dev->vt_sense_buffer[2] = 0x40;
			req->vt_dev->vt_sense_buffer[3] = 0;
			req->vt_dev->vt_sense_buffer[4] = 0;
			req->vt_dev->vt_sense_buffer[5] = 0;
			req->vt_dev->vt_sense_buffer[6] = 0;
			req->vt_dev->vt_sense_buffer[7] = 0;
			return(0);
		}
		if (mark == 0) {
			// skip trailing file mark
			if (fd->f_op->llseek(fd, 8, 1) < 0) {
				TRACE_ERROR("fd->f_op->llseek() failed\n");
				set_fs(old_fs);
				return(-1);
			}
			set_fs(old_fs);
			// eof 
			req->vt_dev->vt_sense_buffer[0] = 0xf0;
			req->vt_dev->vt_sense_buffer[1] = 0;
			req->vt_dev->vt_sense_buffer[2] = 0x80;
			req->vt_dev->vt_sense_buffer[3] = 0;
			req->vt_dev->vt_sense_buffer[4] = 0;
			req->vt_dev->vt_sense_buffer[5] = 0;
			req->vt_dev->vt_sense_buffer[6] = 0;
			req->vt_dev->vt_sense_buffer[7] = 0;
			return(0);
		}
		set_fs(old_fs);
		len = swap(mark);
		req->vt_dev->vt_read_limit = len;
		req->vt_dev->vt_read_count = 0;
	}

	for (i = 0; i < req->vt_sg_count; i++) {

		if (!(buf = sg_virt(&sg[i])))
			return(-1);

		if (req->vt_dev->vt_read_count + sg[i].length > req->vt_dev->vt_read_limit)
			n = req->vt_dev->vt_read_limit - req->vt_dev->vt_read_count;
		else
			n = sg[i].length;

		if (n) {
			old_fs = get_fs();
			set_fs(get_ds());
			if ((ret = fd->f_op->read(fd, buf, sg[i].length, &fd->f_pos)) < 0) {
				TRACE_ERROR("fd->f_op->read() returned %d\n", ret);
				set_fs(old_fs);
				return(-1);
			}
			set_fs(old_fs);
		} else
			ret = 0;

		req->vt_dev->vt_read_count += ret;

		// filemark?

		if (n < sg[i].length) {
			// skip trailing file mark
			if (fd->f_op->llseek(fd, 8, 1) < 0) {
				TRACE_ERROR("fd->f_op->llseek() failed\n");
				set_fs(old_fs);
				return(-1);
			}
			// done with read
			req->vt_dev->vt_read_limit = 0;
			req->vt_dev->vt_read_count = 0;
			// put eof in sense buffer
			req->vt_dev->vt_sense_buffer[0] = 0xf0;
			req->vt_dev->vt_sense_buffer[1] = 0;
			req->vt_dev->vt_sense_buffer[2] = 0x80;
			req->vt_dev->vt_sense_buffer[3] = ret >> 24;
			req->vt_dev->vt_sense_buffer[4] = ret >> 16;
			req->vt_dev->vt_sense_buffer[5] = ret >> 8;
			req->vt_dev->vt_sense_buffer[6] = ret;
			req->vt_dev->vt_sense_buffer[7] = 0;
			break;
		}

		// end of media?

		if (ret < n) {
			// done with read
			req->vt_dev->vt_read_limit = 0;
			req->vt_dev->vt_read_count = 0;
			// put eom (end of media) in sense buffer
			req->vt_dev->vt_sense_buffer[0] = 0xf0;
			req->vt_dev->vt_sense_buffer[1] = 0;
			req->vt_dev->vt_sense_buffer[2] = 0x40;
			req->vt_dev->vt_sense_buffer[3] = ret >> 24;
			req->vt_dev->vt_sense_buffer[4] = ret >> 16;
			req->vt_dev->vt_sense_buffer[5] = ret >> 8;
			req->vt_dev->vt_sense_buffer[6] = ret;
			req->vt_dev->vt_sense_buffer[7] = 0;
			break;
		}
	}

	return(0);
}

static int vt_do_write (vt_request_t *req)
{
	int ret = 0;
	u32 i;
	unsigned char *buf;
	struct file *fd = req->vt_dev->vt_file;
	struct scatterlist *sg = (struct scatterlist *) req->vt_buf;
	mm_segment_t old_fs;

	if (fd == NULL)
		return(-1);

	// advance 8 bytes if start of write

	if (req->vt_dev->vt_written == 0) {
		old_fs = get_fs();
		set_fs(get_ds());
		if (fd->f_op->llseek(fd, 8, 1) < 0) {
			TRACE_ERROR("fd->f_op->llseek failed\n");
			set_fs(old_fs);
			return(-1);
		}
		set_fs(old_fs);
	}

	for (i = 0; i < req->vt_sg_count; i++) {

		if (!(buf = sg_virt(&sg[i])))
			return(-1);

		old_fs = get_fs();
		set_fs(get_ds());
		if ((ret = fd->f_op->write(fd, buf, sg[i].length, &fd->f_pos)) < 0) {
			TRACE_ERROR("fd->f_op->write returned %d\n", ret);
			set_fs(old_fs);
			return(-1);
		}
		set_fs(old_fs);

		req->vt_dev->vt_written += sg[i].length;
	}

	return(0);
}

extern int vt_do_task (iscsi_task_t *task)
{
	vt_request_t *req = (vt_request_t *) task->transport_req;

	if (!(task->iscsi_cmd->cmd_flags & ICF_SCSI_DATA_SG_IO_CDB))
		return(vt_emulate_scsi_cdb(task));

//printk("vt_do_task\n");
//printk("%02x %02x %02x %02x %02x %02x\n",
//req->vt_scsi_cdb[0],
//req->vt_scsi_cdb[1],
//req->vt_scsi_cdb[2],
//req->vt_scsi_cdb[3],
//req->vt_scsi_cdb[4],
//req->vt_scsi_cdb[5]);

	req->vt_lba = task->task_lba;
	req->vt_size = task->task_size;

	req->vt_dev->vt_sense_buffer[0] = 0;

	if (vt_open_file(task, 0)) {
		req->vt_dev->vt_sense_buffer[0] = 0xf0;
		req->vt_dev->vt_sense_buffer[1] = 0;
		req->vt_dev->vt_sense_buffer[2] = 0x80;
		req->vt_dev->vt_sense_buffer[3] = 0;
		req->vt_dev->vt_sense_buffer[4] = 0;
		req->vt_dev->vt_sense_buffer[5] = 0;
		req->vt_dev->vt_sense_buffer[6] = 0;
		req->vt_dev->vt_sense_buffer[7] = 0;
	} else if (req->vt_data_direction == VT_DATA_READ) {
		vt_write_filemark_maybe(task);
		vt_do_read(req);
	} else
		vt_do_write(req);

	if (req->vt_dev->vt_sense_buffer[0]) {
		req->vt_dev->vt_sense_flag = 1;
		task->task_scsi_status = CHECK_CONDITION;
	} else {
		req->vt_dev->vt_sense_flag = 0;
		task->task_scsi_status = GOOD;
	}

	transport_complete_task(task, 1);

	return(PYX_TRANSPORT_SENT_TO_TRANSPORT);
}

/*	vt_free_task(): (Part of iscsi_transport_t template)
 *
 *
 */
extern void vt_free_task (iscsi_task_t *task)
{
	vt_request_t *req;

	req = (vt_request_t *) task->transport_req;
	kfree(req);
	
	return;
}

extern int vt_check_hba_params (iscsi_hbainfo_t *hi, struct iscsi_target *t, int virt)
{
	if (!(t->hba_params_set & PARAM_HBA_VT_HOST_ID)) {
		TRACE_ERROR("vt_host_id must be set for"
			" addhbatotarget requests with VTAPE"
				" Interfaces\n");
		return(ERR_HBA_MISSING_PARAMS);
	}
	hi->vt_host_id = t->vt_host_id;
	hi->mc_host_id = t->mc_host_id;

	return(0);
}

extern int vt_check_dev_params (iscsi_hba_t *hba, struct iscsi_target *t, iscsi_dev_transport_info_t *dti)
{
	if (!(t->hba_params_set & PARAM_HBA_VT_DEVICE_ID)) {
		TRACE_ERROR("Missing VTAPE createvirtdev parameters\n");
		return(ERR_VIRTDEV_MISSING_PARAMS);
	}
	dti->vt_device_id = t->vt_device_id;

	return(0);
}

extern int vt_check_virtdev_params (iscsi_devinfo_t *di, struct iscsi_target *t)
{
	if ((t->hba_params_set & PARAM_HBA_VT_DEVICE_ID) == 0) {
		TRACE_ERROR("Missing VTAPE createvirtdev parameters\n");
		return(ERR_VIRTDEV_MISSING_PARAMS);
	}

	di->vt_device_id = t->vt_device_id;
	di->vt_hw_id = t->vt_hw_id;
	di->fd_device_size = t->fd_dev_size;

	if (strlen(t->value))
		snprintf(di->fd_dev_name, VT_MAX_DEV_NAME, "%s", t->value);
	else
		snprintf(di->fd_dev_name, VT_MAX_DEV_NAME, "/root/vtape%d", t->vt_device_id);

	return(0);
}

extern void vt_get_plugin_info (void *p, char *b, int *bl)
{
	*bl += sprintf(b+*bl, "%s Virtual TAPE Plugin %s\n", PYX_ISCSI_VENDOR, VT_VERSION);
	
	return;
}

extern void vt_get_hba_info (iscsi_hba_t *hba, char *b, int *bl)
{
	*bl += sprintf(b+*bl, "iSCSI Host ID: %u  VT Host ID: %u\n",
		 hba->hba_id, hba->hba_info.vt_host_id);
	*bl += sprintf(b+*bl, "        iSBE VTAPE HBA\n");

	return;
}

extern void vt_get_dev_info (iscsi_device_t *dev, char *b, int *bl)
{
	struct vt_dev_s *fd = (struct vt_dev_s *) dev->dev_ptr;

	*bl += sprintf(b+*bl, "iSBE VTAPE ID: %u  VTAPE Makeup: %s\n",
			fd->vt_dev_id, TRANSPORT(dev)->name);
	*bl += sprintf(b+*bl, "        File: %s  Size: %llu\n",
			fd->vt_dev_name, fd->vt_dev_size);

	return;
}

/*	vt_map_task_non_SG():
 *
 *
 */
extern void vt_map_task_non_SG (iscsi_task_t *task)
{
	iscsi_cmd_t *cmd = task->iscsi_cmd;
	vt_request_t *req = (vt_request_t *) task->transport_req;

	req->vt_bufflen		= task->task_size;
	req->vt_buf		= (void *) T_TASK(cmd)->t_task_buf;
	req->vt_sg_count	= 0;
	
	return;
}

/*	vt_map_task_SG():
 *
 *
 */
extern void vt_map_task_SG (iscsi_task_t *task)
{
	vt_request_t *req = (vt_request_t *) task->transport_req;

	req->vt_bufflen		= task->task_size;
	req->vt_buf		= (void *)task->task_buf;
	req->vt_sg_count	= task->task_sg_num;

	return;
}

/*      vt_CDB_inquiry():
 *
 *
 */
extern int vt_CDB_inquiry (iscsi_task_t *task, u32 size)
{      
	vt_request_t *req = (vt_request_t *) task->transport_req;
		        
	req->vt_data_direction  = VT_DATA_READ;
			        
	/*
	 * This causes 255 instead of the requested 256 bytes
	 * to be returned.  This can be safely ignored for now,
	 * and take the Initiators word on INQUIRY data lengths.
	 */
#if 0
	cmd->data_length	= req->vt_bufflen;
#endif
	vt_map_task_non_SG(task);

	return(0);
}

/*      vt_CDB_none():
 *
 *
 */
extern int vt_CDB_none (iscsi_task_t *task, u32 size)
{
	vt_request_t *req = (vt_request_t *) task->transport_req;

	req->vt_data_direction	= VT_DATA_NONE;
	req->vt_bufflen		= 0;
	req->vt_sg_count	= 0;
	req->vt_buf		= NULL;

	return(0);
}

/*	vt_CDB_read_non_SG():
 *
 *
 */
extern int vt_CDB_read_non_SG (iscsi_task_t *task, u32 size)
{
	vt_request_t *req = (vt_request_t *) task->transport_req;

	req->vt_data_direction = VT_DATA_READ;
	vt_map_task_non_SG(task);

	return(0);
}

/*	vt_CDB_read_SG):
 *
 *
 */
extern int vt_CDB_read_SG (iscsi_task_t *task, u32 size)
{
	vt_request_t *req = (vt_request_t *) task->transport_req;

	req->vt_data_direction = VT_DATA_READ;
	vt_map_task_SG(task);

	return(req->vt_sg_count);
}

/*	vt_CDB_write_non_SG():
 *
 *
 */
extern int vt_CDB_write_non_SG (iscsi_task_t *task, u32 size)
{
	vt_request_t *req = (vt_request_t *) task->transport_req;
	
	req->vt_data_direction = VT_DATA_WRITE;
	vt_map_task_non_SG(task);
	
	return(0);
}

/*	vt_CDB_write_SG():
 *
 *
 */
extern int vt_CDB_write_SG (iscsi_task_t *task, u32 size)
{
	vt_request_t *req = (vt_request_t *) task->transport_req;

	req->vt_data_direction = VT_DATA_WRITE;
	vt_map_task_SG(task);

	return(req->vt_sg_count);
}

/*	vt_check_lba():
 *
 *
 */
extern int vt_check_lba (unsigned long long lba, iscsi_device_t *dev)
{
	return(0);
}

/*	vt_check_for_SG(): (Part of iscsi_transport_t template)
 *
 *
 */
extern int vt_check_for_SG (iscsi_task_t *task)
{
	vt_request_t *req = (vt_request_t *) task->transport_req;
	
	return(req->vt_sg_count);
}

/*	vt_get_cdb(): (Part of iscsi_transport_t template)
 *
 *
 */
extern unsigned char *vt_get_cdb (iscsi_task_t *task)
{
	vt_request_t *req = (vt_request_t *) task->transport_req;

	return(req->vt_scsi_cdb);
}

/*	vt_get_blocksize(): (Part of iscsi_transport_t template)
 *
 *
 */
extern u32 vt_get_blocksize (iscsi_device_t *dev)
{
	return(VT_BLOCKSIZE);
}

/*	vt_get_device_rev(): (Part of iscsi_transport_t template)
 *
 *
 */
extern u32 vt_get_device_rev (iscsi_device_t *dev)
{
	return(02); 
}

/*	vt_get_device_type(): (Part of iscsi_transport_t template)
 *
 *
 */
extern u32 vt_get_device_type (iscsi_device_t *dev)
{
	return(TYPE_TAPE);
}

/*	vt_get_dma_length(): (Part of iscsi_transport_t template)
 *
 *
 */
extern u32 vt_get_dma_length (u32 task_size, iscsi_device_t *dev)
{
	return(PAGE_SIZE);
}

/*	vt_get_max_sectors(): (Part of iscsi_transport_t template)
 *
 *
 */
extern u32 vt_get_max_sectors (iscsi_device_t *dev)
{
	return(VT_MAX_SECTORS);
}

/*	vt_get_queue_depth(): (Part of iscsi_transport_t template)
 *
 *
 */
extern u32 vt_get_queue_depth (iscsi_device_t *dev)
{
	return(VT_DEVICE_QUEUE_DEPTH);
}

/*	vt_get_non_SG(): (Part of iscsi_transport_t template)
 *
 *
 */
extern unsigned char *vt_get_non_SG (iscsi_task_t *task)
{
	vt_request_t *req = (vt_request_t *) task->transport_req;

	return((unsigned char *)req->vt_buf);
}

/*	vt_get_SG(): (Part of iscsi_transport_t template)
 *
 *
 */
extern struct scatterlist *vt_get_SG (iscsi_task_t *task)
{
	vt_request_t *req = (vt_request_t *) task->transport_req;

	return((struct scatterlist *)req->vt_buf);
}

/*	vt_get_SG_count(): (Part of iscsi_transport_t template)
 *
 *
 */
extern u32 vt_get_SG_count (iscsi_task_t *task)
{
	return(0);
}

/*	vt_set_non_SG_buf():
 *
 *
 */
extern int vt_set_non_SG_buf (unsigned char *buf, iscsi_task_t *task)
{
	vt_request_t *req = (vt_request_t *) task->transport_req;
	
	req->vt_buf		= (void *) buf;
	req->vt_bufflen         = task->task_size;
	req->vt_sg_count        = 0;

	return(0);
}

/*	vt_get_sense_buffer():
 *
 *
 */
extern unsigned char *vt_get_sense_buffer (iscsi_task_t *task)
{
	vt_request_t *req;
	req = (vt_request_t *) task->transport_req;
	return((unsigned char *)&req->vt_dev->vt_sense_buffer[0]);
}

/*	vt_find_dev()
 *
 *	Find the vt_dev_t from mc_host_id and vt_dev_id.
 */
static vt_dev_t *vt_find_dev (int mc_host_id, int vt_dev_id)
{
	int i;
	iscsi_hba_t *hba;
	iscsi_device_t *dev;
	vt_dev_t *vt_dev;

	spin_lock(&iscsi_global->hba_lock);

	for (i = 0; i < ISCSI_MAX_GLOBAL_HBAS; i++) {
		hba = &iscsi_global->hba_list[i];
		if (hba == NULL)
			continue;
		spin_lock(&hba->device_lock);
		for (dev = hba->device_head; dev; dev = dev->next) {
			if (dev->transport != &vtape_template)
				continue;
			vt_dev = (vt_dev_t *) dev->dev_ptr;
			if (vt_dev == NULL)
				continue;
			if (vt_dev->vt_mc_host_id != mc_host_id)
				continue;
			if (vt_dev->vt_dev_id == vt_dev_id) {
				spin_unlock(&hba->device_lock);
				spin_unlock(&iscsi_global->hba_lock);
				return vt_dev;
			}
		}
		spin_unlock(&hba->device_lock);
	}

	spin_unlock(&iscsi_global->hba_lock);

	return NULL;
}

extern int vt_lock (int mc_host_id, int vt_dev_id)
{
	vt_dev_t *vt_dev;

	vt_dev = vt_find_dev(mc_host_id, vt_dev_id);

	if (vt_dev == NULL)
		return 0;

	if (atomic_dec_and_test(&vt_dev->vt_lock))
		return 1;

	atomic_inc(&vt_dev->vt_lock);

	return 0;
}

extern void vt_unlock (int mc_host_id, int vt_dev_id)
{
	vt_dev_t *vt_dev;

	vt_dev = vt_find_dev(mc_host_id, vt_dev_id);

	if (vt_dev)
		atomic_inc(&vt_dev->vt_lock);
}

static int modesense_rwrecovery (unsigned char *p)
{
	p[0] = 0x01;	/* page code */
	p[1] = 0x0a;	/* length */

	return(12);	/* length + 2 */
}

static int modesense_caching (unsigned char *p)
{
	p[0] = 0x08;	/* page code */
	p[1] = 0x12;	/* length */
//	p[2] = 0x04; /* Write Cache Enable */
	p[12] = 0x20; /* Disabled Read Ahead */

	return(20);	/* length + 2 */
}

static int modesense_control (unsigned char *p)
{
	p[0] = 0x0a;	/* page code */
	p[1] = 0x0a;	/* length */
	p[2] = 2;
	p[8] = 0xff;
	p[9] = 0xff;
	p[11] = 30;

	return(12);	/* length + 2 */
}

static int modesense_0x0f (unsigned char *buf)
{
	buf[0] = 0x0f;	/* page code */
	buf[1] = 0x0e;	/* length */
	buf[2] = 0x40;
	buf[3] = 0x80;
	buf[7] = 0x01;
	buf[11] = 0x01;
	return(16);	/* length + 2 */
}

static int modesense_0x10 (unsigned char *buf)
{
	buf[0] = 0x10;	/* page code */
	buf[1] = 0x0e;	/* length */
	buf[8] = 0x40;
	buf[10] = 0x10;
//	buf[14] = 0x01;
	return(16);	/* length + 2 */
}

/*	vt_mode_sense():
 *
 *	Respond to a MODE SENSE command.
 */
static int vt_mode_sense (iscsi_task_t *task)
{
	int len, dbd, page_code;
	unsigned char buf[SE_MODE_PAGE_BUF];
	iscsi_cmd_t *cmd;
	unsigned char *cdb, *dst;

	memset(buf, 0, SE_MODE_PAGE_BUF);

	cmd = task->iscsi_cmd;
	cdb = T_TASK(cmd)->t_task_cdb;
	dst = (unsigned char *) T_TASK(cmd)->t_task_buf;

	/* get the "disable block descriptors" bit */

	dbd = cdb[1] & 0x08;

	/* get the page code */

	page_code = cdb[2] & 0x3f;

	/* start filling the response buffer */

	len = 4;

	/* medium type */

	buf[1] = 0x18;

	/* device specific parameter */

	buf[2] = 0x10;

	/* block descriptor */

	/* Linux has a bug, it doesn't set DBD then it doesn't like the block
	 * descriptor that comes back. Windows needs the block descriptor so
	 * here is the hack: Just put in the block descriptor for page codes
	 * 0x0f and 0x10.
	 */

	if (dbd == 0 && (page_code == 0x0f || page_code == 0x10)) {
		buf[3] = 8;		/* length */
		buf[4] = 0x40;		/* density code */
		buf[10] = 0x80;		/* block length 32768 */
		len += 8;
	}

	switch (page_code) {

	/* vendor specific */

	case 0x00:
		break;

	case 0x01:
		len += modesense_rwrecovery(buf + len);
		break;

	case 0x08:
		len += modesense_caching(buf + len);
		break;

	case 0x0a:
		len += modesense_control(buf + len);
		break;

	/* data compression */

	case 0x0f:
		len += modesense_0x0f(buf + len);
		break;

	/* device configuration */

	case 0x10:
		len += modesense_0x10(buf + len);
		break;

	case 0x3f:
		len += modesense_rwrecovery(buf + len);
		len += modesense_caching(buf + len);
		len += modesense_control(buf + len);
		len += modesense_0x0f(buf + len);
		len += modesense_0x10(buf + len);
		break;

	default:
		TRACE_ERROR("Got Unknown Mode Page: 0x%02x\n", page_code);
		return(PYX_TRANSPORT_UNKNOWN_MODE_PAGE);
	}

	/* overall length */

	buf[0] = len - 1;

	if (len > cmd->data_length)
		len = cmd->data_length;

	memcpy(dst, buf, len); 
	
	return(0);
}

/*	vt_request_sense():
 *
 *	Respond to a REQUEST SENSE command.
 */
static int vt_request_sense (iscsi_task_t *task)
{
	int len;
	unsigned char buf[8];
	iscsi_cmd_t *cmd;
	unsigned char *cdb, *dst;
	vt_request_t *req;

	cmd = task->iscsi_cmd;
	cdb = T_TASK(cmd)->t_task_cdb;
	dst = (unsigned char *) T_TASK(cmd)->t_task_buf;
	req = (vt_request_t *) task->transport_req;

	if (req->vt_dev->vt_sense_flag) {
		req->vt_dev->vt_sense_flag = 0;
		memcpy(buf, req->vt_dev->vt_sense_buffer, 8);
		len = 8;
	} else {
		memset(buf, 0, 8);
		buf[0] = 0x70;
		len = 8;
	}

	if (len > cmd->data_length)
		len = cmd->data_length;

	memcpy(dst, buf, len);

	return(0);
}

unsigned char foo[36] = {
	0x31, 0x00, 0x00, 0x20, 0x00, 0x01, 0xc0, 0x04, 0x00, 0x01,
	0x74, 0x84, 0x00, 0x02, 0xc0, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0xc0, 0x04, 0x00, 0x01,
	0x74, 0x87, 0x00, 0x04, 0xc0, 0x04, 0x00, 0x00, 0x00, 0x00,
};

/*	vt_log_sense():
 *
 *	Respond to a LOG SENSE command.
 */
static int vt_log_sense (iscsi_task_t *task)
{
	int len;
	unsigned char *dst, *cdb;
	iscsi_cmd_t *cmd;
	vt_request_t *req;

	cmd = task->iscsi_cmd;
	cdb = T_TASK(cmd)->t_task_cdb;
	dst = (unsigned char *) T_TASK(cmd)->t_task_buf;
	req = (vt_request_t *) task->transport_req;

	len = 36;

	if (len > cmd->data_length)
		len = cmd->data_length;

	memcpy(dst, foo, len);

	return(0);
}

static int vt_read_position (iscsi_task_t *task)
{
	unsigned char *dst, *cdb;
	iscsi_cmd_t *cmd;
	vt_request_t *req;

	cmd = task->iscsi_cmd;
	cdb = T_TASK(cmd)->t_task_cdb;
	dst = (unsigned char *) T_TASK(cmd)->t_task_buf;
	req = (vt_request_t *) task->transport_req;

//	service_action = cdb[1] & 0x1f;

//	memset(dst, 0, cmd->data_length);

	dst[0] = 0x80;

	return(0);
}
