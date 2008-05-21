/*********************************************************************************
 * Filename:  iscsi_target_info.c
 *
 * This file houses the iSCSI Target Information utility functions.
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

#define USE_NEW_SIGNATURE  1

#define ISCSI_TARGET_INFO_C

#ifdef LINUX
#include <linux/string.h>
#include <linux/version.h>
#include <linux/utsrelease.h>
#include <linux/timer.h>
#include <linux/blkdev.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/smp_lock.h>
#include <linux/in.h>
#include <linux/utsname.h>
#include <net/sock.h>
#include <net/tcp.h>
#include <scsi/scsi.h>
#include <scsi/scsi_device.h>
#include <scsi/scsi_host.h>

#include <iscsi_linux_os.h>
#include <iscsi_linux_defs.h>
#endif /* LINUX */

#ifdef FREEBSD
#include <iscsi_freebsd_os.h>
#include <iscsi_freebsd_defs.h>
#endif /* FREEBSD */

#include <iscsi_lists.h>
#include <iscsi_debug.h>
#include <iscsi_protocol.h>
#include <iscsi_target_core.h>
#include <iscsi_target_ioctl.h>
#include <iscsi_target_hba.h>
#include <iscsi_target_seobj.h>
#include <iscsi_target_transport.h>
#include <iscsi_target_tpg.h>
#include <iscsi_target_util.h>
#include <iscsi_target.h>

#include <iscsi_target_plugin.h>
#include <iscsi_target_seobj.h>
#include <iscsi_target_feature_obj.h>
#include <iscsi_target_feature_plugins.h>

#include <iscsi_target_info.h>

#undef ISCSI_TARGET_INFO_C

extern iscsi_global_t *iscsi_global;

static int check_and_copy_buf (
	unsigned char *b,
	unsigned char *tb,
	int *cl,
	int *bl,
	int *ml)
{
	if ((*cl + *bl)> *ml)
		return(-1);
	else {
		memcpy(b+*cl, tb, *bl);
		*cl += *bl;
	}

	return(0);
}

#define TMP_BUF_LEN     IOCTL_BUFFER_LEN

static unsigned char *alloc_buf (void)
{
	unsigned char *buf;
	
	if (!(buf = kmalloc(TMP_BUF_LEN, GFP_KERNEL))) {
		TRACE_ERROR("Unable to allocate buffer: %d\n", TMP_BUF_LEN);
		return(NULL);
	}
	memset(buf, 0, TMP_BUF_LEN);

	return(buf);
}

extern int iscsi_get_hba_info_count_for_global (int *count)
{
	u32 i;
	iscsi_hba_t *hba;

	*count = 1;
	
        spin_lock(&iscsi_global->hba_lock);
	for (i = 0; i < ISCSI_MAX_GLOBAL_HBAS; i++) {
                hba = &iscsi_global->hba_list[i];

                if (!(hba->hba_status & HBA_STATUS_ACTIVE))
                        continue;

		*count += 1;
	}
	spin_unlock(&iscsi_global->hba_lock);

	return(0);
}

static void iscsi_dump_hba_info (
	iscsi_hba_t *hba,
	char *b,	/* Pointer to info buffer */
	int *bl)
{
	int ret = 0;
	iscsi_transport_t *t;
	
	t = (iscsi_transport_t *)plugin_get_obj(PLUGIN_TYPE_TRANSPORT, hba->type, &ret);
	if (!t || (ret != 0))
		return;

	t->get_hba_info(hba, b, bl);

        *bl += sprintf(b+*bl, "        Left/Max Queue Depth: %d/%d\n",
                               atomic_read(&hba->left_queue_depth),
                               atomic_read(&hba->max_queue_depth));
        *bl += sprintf(b+*bl, "        Total Devices for HBA: %u\n", hba->dev_count);

	return;
}

extern int iscsi_get_hba_info (
	char *pb,       /* Pointer to info buffer */
        int ml,         /* Max Length in bytes of buffer space */
        int header,
        int counter_offset,
        int single_out)
{
	unsigned char *b;
	int bl = 0, cl = 0, oob = 1, start = 0;
        u32 i;
        iscsi_hba_t *hba;

	if (!(b = alloc_buf()))
		goto done;

        if (header) {
		memset(b, 0, TMP_BUF_LEN);
		bl = sprintf(b, "-----------------------------[Global Storage HBA Info]"
                                "-----------------------------\n");
		if (check_and_copy_buf(pb, b, &cl, &bl, &ml) < 0)
                        goto done;
        }

        spin_lock(&iscsi_global->hba_lock);
        for (i = 0; i < ISCSI_MAX_GLOBAL_HBAS; i++) {
                hba = &iscsi_global->hba_list[i];

		if (!(hba->hba_status & HBA_STATUS_ACTIVE))
			continue;

		if (single_out && (start < counter_offset)) {
			start++;
			continue;
		}
		spin_unlock(&iscsi_global->hba_lock);

		memset(b, 0, TMP_BUF_LEN);
		bl = 0;
		iscsi_dump_hba_info(hba, b, &bl);

		spin_lock(&iscsi_global->hba_lock);
		if (check_and_copy_buf(pb, b, &cl, &bl, &ml) < 0) {
			spin_unlock(&iscsi_global->hba_lock);
			goto done;
		}
				                
		if (single_out)
			break;
        }
	spin_unlock(&iscsi_global->hba_lock);

        oob = 0;
done:
        if (oob) {
                TRACE_ERROR("Ran out of buffer..\n");
        }
	if (b) kfree(b);
        return(cl);
}

extern int iscsi_get_dev_info_count_for_hba (u32 hba_id, int *count)
{
	iscsi_device_t *dev;
	iscsi_hba_t *hba;

	if (!(hba = core_get_hba_from_id(hba_id, 0)))
		return(-1);
		
	*count = 1;

	spin_lock(&hba->device_lock);
	for (dev = hba->device_head; dev; dev = dev->next) {
		*count += 1;
	}
	spin_unlock(&hba->device_lock);

	core_put_hba(hba);
	return(0);
}

extern int iscsi_get_lun_info_count_for_tpg (
	unsigned char *targetname,
	u16 tpgt,
	int *count)
{
	iscsi_lun_t *lun = NULL;
	iscsi_portal_group_t *tpg = NULL;
	iscsi_tiqn_t *tiqn;
	int i;

	if (!(tpg = core_get_tpg_from_iqn(targetname, &tiqn, tpgt, 0)))
		return(-1);

	*count = 1;

	spin_lock(&tpg->tpg_lun_lock);
	for (i = 0; i < ISCSI_MAX_LUNS_PER_TPG; i++) {
		lun = &tpg->tpg_lun_list[i];
		
		if (lun->lun_status != ISCSI_LUN_STATUS_ACTIVE)
			continue;

		if (lun->lun_type == ISCSI_LUN_TYPE_NONE)
			continue;

		*count += 1;
	}
	spin_unlock(&tpg->tpg_lun_lock);

	iscsi_put_tpg(tpg);
	return(0);
}

const char *transport_device_types[MAX_SCSI_DEV_TYPE] = {
	"Direct-Access    ",
	"Sequential-Access",
	"Printer          ",
	"Processor        ",
        "WORM             ",
        "CD-ROM           ",
        "Scanner          ",
        "Optical Device   ",
        "Medium Changer   ",
        "Communications   ",
        "Unknown          ",
        "Unknown          ",
        "RAID             ",
        "Enclosure        ",
};

extern void iscsi_dump_dev_state (
	iscsi_device_t *dev,
	char *b,
	int *bl)
{
	*bl += sprintf(b+*bl, "Status: ");
	switch (dev->dev_status) {
	case ISCSI_DEVICE_ACTIVATED:
		*bl += sprintf(b+*bl, "ACTIVATED");
		break;
	case ISCSI_DEVICE_DEACTIVATED:
		*bl += sprintf(b+*bl, "DEACTIVATED");
		break;
	case ISCSI_DEVICE_SHUTDOWN:
		*bl += sprintf(b+*bl, "SHUTDOWN");
		break;
	case ISCSI_DEVICE_OFFLINE_ACTIVATED:
	case ISCSI_DEVICE_OFFLINE_DEACTIVATED:
		*bl += sprintf(b+*bl, "OFFLINE");
		break;
	default:
		*bl += sprintf(b+*bl, "UNKNOWN=%d", dev->dev_status);
		break;
	}

	*bl += sprintf(b+*bl, "  Execute/Left/Max Queue Depth: %d/%d/%d",
		atomic_read(&dev->execute_tasks), atomic_read(&dev->depth_left),
		dev->queue_depth);
	*bl += sprintf(b+*bl, "  SectorSize: %u  MaxSectors: %u\n",
			TRANSPORT(dev)->get_blocksize(dev), TRANSPORT(dev)->get_max_sectors(dev));
	*bl += sprintf(b+*bl, "        ");

	return;
}

extern void iscsi_dump_dev_info (
	iscsi_device_t *dev,
	iscsi_lun_t *lun,
	unsigned long long total_bytes,
	char *b,        /* Pointer to info buffer */
	int *bl)
{
	int ret = 0;
	iscsi_transport_t *t;

	t = (iscsi_transport_t *)plugin_get_obj(PLUGIN_TYPE_TRANSPORT, dev->type, &ret);
	if (!t || (ret != 0))
		return;
	
	t->get_dev_info(dev, b, bl);
	
	*bl += sprintf(b+*bl, "        ");
	*bl += sprintf(b+*bl, "Type: %s ", (TRANSPORT(dev)->get_device_type(dev) > MAX_SCSI_DEV_TYPE) ?
				"Unknown" : transport_device_types[TRANSPORT(dev)->get_device_type(dev)]);
	*bl += sprintf(b+*bl, "ANSI SCSI revision: %02x  ", TRANSPORT(dev)->get_device_rev(dev));

	if (DEV_OBJ_API(dev)->get_t10_wwn) {
		t10_wwn_t *wwn = DEV_OBJ_API(dev)->get_t10_wwn((void *)dev);

		*bl += sprintf(b+*bl, "Unit Serial: %s  ",
			((strlen(wwn->unit_serial) != 0) ?
			 	(char *)wwn->unit_serial : "None"));
	}
	
	if (dev->dev_fp) {
		unsigned char tbuf[128];
		int len = 0;

		memset(tbuf, 0, 128);
		dev->dev_fp->fp_api->get_feature_info(dev->dev_fp->fp_ptr, &tbuf[0], &len);

		*bl += sprintf(b+*bl, "%s", tbuf);
	
		if ((DEV_OBJ_API(dev)->check_count(&dev->dev_access_obj)) ||
		    (DEV_OBJ_API(dev)->check_count(&dev->dev_feature_obj)))
			*bl += sprintf(b+*bl, "  ACCESSED\n");	
		else if (DEV_OBJ_API(dev)->check_count(&dev->dev_export_obj))
			*bl += sprintf(b+*bl, "  EXPORTED\n");
		else
			*bl += sprintf(b+*bl, "  FREE\n");
	} else {
		*bl += sprintf(b+*bl, "%s", "DIRECT");

		if ((DEV_OBJ_API(dev)->check_count(&dev->dev_access_obj)) ||
		    (DEV_OBJ_API(dev)->check_count(&dev->dev_feature_obj)))
			*bl += sprintf(b+*bl, "  ACCESSED\n");
		else if (DEV_OBJ_API(dev)->check_count(&dev->dev_export_obj))
			*bl += sprintf(b+*bl, "  EXPORTED\n");
		else
			*bl += sprintf(b+*bl, "  FREE\n");
	}
	
	if (lun) {
		*bl += sprintf(b+*bl, "        iSCSI Host ID: %u iSCSI LUN: %u",
			dev->iscsi_hba->hba_id, lun->iscsi_lun);
		if (!(TRANSPORT(dev)->get_device_type(dev))) {
			*bl += sprintf(b+*bl, "  Active Cmds: %d  Total Bytes: %llu\n",
				atomic_read(&dev->active_cmds), total_bytes);
		} else {
			*bl += sprintf(b+*bl, "  Active Cmds: %d\n", atomic_read(&dev->active_cmds));
		}
	} else {
		if (!(TRANSPORT(dev)->get_device_type(dev))) {
			*bl += sprintf(b+*bl, "        iSCSI Host ID: %u  Active Cmds: %d  Total Bytes: %llu\n",
				dev->iscsi_hba->hba_id, atomic_read(&dev->active_cmds), total_bytes);
		} else {
			*bl += sprintf(b+*bl, "        iSCSI Host ID: %u  Active Cmds: %d\n",
				dev->iscsi_hba->hba_id, atomic_read(&dev->active_cmds));
		}
	}

	return;
}

extern int iscsi_get_hba_dev_info (
	u32 hba_id,
	char *pb,       /* Pointer to info buffer */
	int ml,         /* Max Length in bytes of buffer space */
	int header,
	int counter_offset,
	int single_out)
{
	unsigned char *b;
	int bl = 0, cl = 0, oob = 1, start = 0;
	iscsi_device_t *dev;
	iscsi_hba_t *hba;

	if (!(hba = core_get_hba_from_id(hba_id, 0))) {
		oob = 0;
		return(cl);
	}

	if (!(b = alloc_buf()))
		goto done;

	if (header) {
		memset(b, 0, TMP_BUF_LEN);
		bl = sprintf(b, "-----------------------------[Storage Device Info for iSCSI HBA %u]"
			"-----------------------------\n", hba->hba_id);
		if (check_and_copy_buf(pb, b, &cl, &bl, &ml) < 0)
			goto done;
	}

	spin_lock(&hba->device_lock);
	for (dev = hba->device_head; dev; dev = dev->next) {
		if (single_out && (start < counter_offset)) {
			start++;
			continue;
		}
		
		memset(b, 0, TMP_BUF_LEN);
		bl = 0;

		spin_unlock(&hba->device_lock);

		DEV_OBJ_API(dev)->get_obj_info((void *)dev, NULL,
			(DEV_OBJ_API(dev)->total_sectors(dev, 1, 0) *
			 DEV_OBJ_API(dev)->blocksize(dev)), 1, b, &bl);

		spin_lock(&hba->device_lock);

		bl += sprintf(b+bl, "\n");
		
		if (check_and_copy_buf(pb, b, &cl, &bl, &ml) < 0) {
			spin_unlock(&hba->device_lock);
			goto done;
		}
		
		if (single_out)
			break;
	}
	spin_unlock(&hba->device_lock);
	
	oob = 0;
done:                   
	core_put_hba(hba);
	if (oob) { 
		TRACE_ERROR("Ran out of buffer..\n");
	}
	if (b) kfree(b);
	return(cl);
}

/*      iscsi_tpg_get_lun_info():
 *
 *
 */
extern int iscsi_tpg_get_lun_info (
	unsigned char *targetname,
	u16 tpgt,
        char *pb,       /* Pointer to info buffer */
        int ml,         /* Max Length in bytes of buffer space */
	int header,
	int counter_offset,
	int single_out)
{
	unsigned char *b;
	int bl = 0, cl = 0, oob = 1, i, start = 0;
	iscsi_lun_t *lun = NULL;
	iscsi_lun_acl_t *acl = NULL;
	iscsi_portal_group_t *tpg = NULL;
	iscsi_tiqn_t *tiqn;

	if (!(tpg = core_get_tpg_from_iqn(targetname, &tiqn, tpgt, 0))) {
		oob = 0;
		return(cl);
	}

	if (!(b = alloc_buf()))
		goto done;
	
	if (header) {
		memset(b, 0, TMP_BUF_LEN);
		bl = sprintf(b, "-----------------------------[LUN Info for iSCSI TPG %hu]"
			"-----------------------------\n", tpgt);
		if (check_and_copy_buf(pb, b, &cl, &bl, &ml) < 0)
			goto done;
	}
	
	spin_lock(&tpg->tpg_lun_lock);
	for (i = 0; i < ISCSI_MAX_LUNS_PER_TPG; i++) {
		lun = &tpg->tpg_lun_list[i];

		if (lun->lun_status != ISCSI_LUN_STATUS_ACTIVE)
			continue;

		if (single_out && (start < counter_offset)) {
			start++;
			continue;
		}

		memset(b, 0, TMP_BUF_LEN);
		bl = 0;

		spin_unlock(&tpg->tpg_lun_lock);
		LUN_OBJ_API(lun)->get_obj_info(lun->lun_type_ptr, lun,
			(LUN_OBJ_API(lun)->total_sectors(lun->lun_type_ptr, 1, 0) *
			 LUN_OBJ_API(lun)->blocksize(lun->lun_type_ptr)), 1, b, &bl);

		if (check_and_copy_buf(pb, b, &cl, &bl, &ml) < 0)
			goto done;
		spin_lock(&tpg->tpg_lun_lock);
		
		spin_lock(&lun->lun_acl_lock);
		if (lun->lun_acl_head) {
			memset(b, 0, TMP_BUF_LEN);
			bl = sprintf(b, "	ACLed iSCSI Initiator Node(s):\n");

			if (check_and_copy_buf(pb, b, &cl, &bl, &ml) < 0) {
				spin_unlock(&lun->lun_acl_lock);
				spin_unlock(&tpg->tpg_lun_lock);
				goto done;
			}

			for (acl = lun->lun_acl_head; acl; acl = acl->next) {
				bl = sprintf(b, "		%s  %u -> %u\n",
					acl->initiatorname, lun->iscsi_lun, acl->mapped_lun); 
				if (check_and_copy_buf(pb, b, &cl, &bl, &ml) < 0) {
					spin_unlock(&lun->lun_acl_lock);
					spin_unlock(&tpg->tpg_lun_lock);
					goto done;
				}
			}
		}
		spin_unlock(&lun->lun_acl_lock);

		memset(b, 0, TMP_BUF_LEN);
		bl = sprintf(b, "\n");
		if (check_and_copy_buf(pb, b, &cl, &bl, &ml) < 0) {
			spin_unlock(&tpg->tpg_lun_lock);
			goto done;
		}

		if (single_out)
			break;
	}
	spin_unlock(&tpg->tpg_lun_lock);
	
	oob = 0;
done:
	iscsi_put_tpg(tpg);
	if (oob) {
		TRACE_ERROR("Ran out of buffer..\n");
	}
	if (b) kfree(b);
	return(cl);
}

extern int iscsi_get_sess_info_count_for_tpg (
	unsigned char *targetname,
	u16 tpgt,
	int *count)
{
	iscsi_portal_group_t *tpg = NULL;
	iscsi_session_t *sess = NULL;
	iscsi_tiqn_t *tiqn;

	if (!(tpg = core_get_tpg_from_iqn(targetname, &tiqn, tpgt, 0)))
		return(-1);
		
	*count = 1;

	spin_lock_bh(&tpg->session_lock);
	for (sess = tpg->session_head; sess; sess = sess->next) {
		*count += 1;
	}
	spin_unlock_bh(&tpg->session_lock);

	iscsi_put_tpg(tpg);
	return(0);
}

/*	iscsi_tpg_get_sess_info():
 *                      
 *
 */
extern int iscsi_tpg_get_sess_info (
	unsigned char *targetname,
	u16 tpgt,              
	char *pb,       /* Pointer to info buffer */
	int ml,         /* Max Length in bytes of buffer space */
	int header,
	int counter_offset,
	int single_out)
{                            
	unsigned char *b, *ip, buf_ipv4[IPV4_BUF_SIZE];
	int bl = 0, cl = 0, oob = 1, start = 0;
	iscsi_conn_t *conn = NULL;
	iscsi_portal_group_t *tpg = NULL;
	iscsi_session_t *sess = NULL;	
	iscsi_tiqn_t *tiqn;

	if (!(tpg = core_get_tpg_from_iqn(targetname, &tiqn, tpgt, 0))) {
		oob = 0;
		return(cl);
	}

	if (!(b = alloc_buf()))
		goto done;

	if (header) {
		memset(b, 0, TMP_BUF_LEN);
		bl = sprintf(b, "--------------------------[Session Info for TPGT: %hu]--------------------------\n", tpg->tpgt);
		bl += sprintf(b+bl, "iSCSI Target Portal Group: %hu  ", tpg->tpgt);
		bl += sprintf(b+bl, "iSCSI sessions active on TPG: %u\n", tpg->nsessions);
		if (check_and_copy_buf(pb, b, &cl, &bl, &ml) < 0)
			goto done;
	}

	spin_lock_bh(&tpg->session_lock);
	for (sess = tpg->session_head; sess; sess = sess->next) {
		if (single_out && (start < counter_offset)) {
			start++;
			continue;
		}

		memset(b, 0, TMP_BUF_LEN);
		if (SESS_OPS(sess)->InitiatorName) { 
			memset(b, 0, TMP_BUF_LEN);
			bl = sprintf(b, "InitiatorName: %s\n", SESS_OPS(sess)->InitiatorName);
			if (check_and_copy_buf(pb, b, &cl, &bl, &ml) < 0) {
				spin_unlock_bh(&tpg->session_lock);
				goto done;
			}
		}
		if (SESS_OPS(sess)->InitiatorAlias) {
			memset(b, 0, TMP_BUF_LEN);
			bl = sprintf(b, "InitiatorAlias: %s\n", SESS_OPS(sess)->InitiatorAlias);		
			if (check_and_copy_buf(pb, b, &cl, &bl, &ml) < 0) {
				spin_unlock_bh(&tpg->session_lock);
				goto done;
			}
		}

		memset(b, 0, TMP_BUF_LEN);
		bl = sprintf(b, "iSBE Session ID: %u   "
				"ISID: 0x%02x %02x %02x %02x %02x %02x  "
				"TSIH: %hu  ", sess->sid,
				sess->isid[0], sess->isid[1], sess->isid[2],
				sess->isid[3], sess->isid[4], sess->isid[5],
				sess->tsih);
		bl += sprintf(b+bl, "SessionType: %s\n", (SESS_OPS(sess)->SessionType) ?
				"Discovery" : "Normal");
		bl += sprintf(b+bl, "Cmds in Session Pool: %d  ", atomic_read(&sess->pool_count));
		bl += sprintf(b+bl, "Session State: ");
		if (check_and_copy_buf(pb, b, &cl, &bl, &ml) < 0) {
			spin_unlock_bh(&tpg->session_lock);
			goto done;
		}
		
		memset(b, 0, TMP_BUF_LEN);
		switch (sess->session_state) {
		case TARG_SESS_STATE_FREE:
			bl = sprintf(b, "TARG_SESS_FREE\n");
			break;
		case TARG_SESS_STATE_ACTIVE:
			bl = sprintf(b, "TARG_SESS_ACTIVE\n");
			break;
		case TARG_SESS_STATE_LOGGED_IN:
			bl = sprintf(b, "TARG_SESS_LOGGED_IN\n");
			break;
		case TARG_SESS_STATE_FAILED:
			bl = sprintf(b, "TARG_SESS_FAILED\n");
			break;
		case TARG_SESS_STATE_IN_CONTINUE:
			bl = sprintf(b, "TARG_SESS_IN_CONTINUE\n");
			break;
		default:
			bl = sprintf(b, "ERROR: Unknown Session State!\n");
			break;
		}
		if (check_and_copy_buf(pb, b, &cl, &bl, &ml) < 0) {
			spin_unlock_bh(&tpg->session_lock);
			goto done;
		}

		memset(b, 0, TMP_BUF_LEN);
		bl = sprintf(b, "---------------------[iSCSI Session Values]-----------------------\n");
		bl += sprintf(b+bl, "  CmdSN/WR  :  CmdSN/WC  :  ExpCmdSN  :  MaxCmdSN  :     ITT    :     TTT\n");
		bl += sprintf(b+bl, " 0x%08x   0x%08x   0x%08x   0x%08x   0x%08x   0x%08x\n",
				sess->cmdsn_window, (sess->max_cmd_sn - sess->exp_cmd_sn) + 1,
				sess->exp_cmd_sn, sess->max_cmd_sn,
				sess->init_task_tag, sess->targ_xfer_tag);
		bl += sprintf(b+bl, "----------------------[iSCSI Connections]-------------------------\n");
		if (check_and_copy_buf(pb, b, &cl, &bl, &ml) < 0) {
			spin_unlock_bh(&tpg->session_lock);
			goto done;
		}
				
		spin_lock(&sess->conn_lock);
		for (conn = sess->conn_head; conn; conn = conn->next) {
			memset(b, 0, TMP_BUF_LEN);
			bl = sprintf(b, "CID: %hu  Connection State: ", conn->cid);
			switch (conn->conn_state) {
			case TARG_CONN_STATE_FREE:
				bl += sprintf(b+bl, "TARG_CONN_FREE\n");
				break;
			case TARG_CONN_STATE_XPT_UP:
				bl += sprintf(b+bl, "TARG_CONN_XPT_UP\n");
				break;
			case TARG_CONN_STATE_IN_LOGIN:
				bl += sprintf(b+bl, "TARG_CONN_IN_LOGIN\n");
				break;
			case TARG_CONN_STATE_LOGGED_IN:
				bl += sprintf(b+bl, "TARG_CONN_LOGGED_IN\n");
				break;
			case TARG_CONN_STATE_IN_LOGOUT:
				bl += sprintf(b+bl, "TARG_CONN_IN_LOGOUT\n");
				break;
			case TARG_CONN_STATE_LOGOUT_REQUESTED:
				bl += sprintf(b+bl, "TARG_CONN_LOGOUT_REQUESTED\n");
				break;
			case TARG_CONN_STATE_CLEANUP_WAIT:
				bl += sprintf(b+bl, "TARG_CONN_CLEANUP_WAIT\n");
				break;
			default:
				bl += sprintf(b+bl, "ERROR: Unknown Connection State!\n");
				break;
			} 

			if (conn->net_size == IPV6_ADDRESS_SPACE)
				ip = &conn->ipv6_login_ip[0];
			else {
				memset(buf_ipv4, 0, IPV4_BUF_SIZE);
				iscsi_ntoa2(buf_ipv4, conn->login_ip);
				ip = &buf_ipv4[0];
			}
			
			bl += sprintf(b+bl, "	Address %s %s", ip,
				(conn->network_transport == ISCSI_TCP) ?
					"TCP" : "SCTP");
			
			bl += sprintf(b+bl, "  StatSN: 0x%08x\n", conn->stat_sn);
			if (check_and_copy_buf(pb, b, &cl, &bl, &ml) < 0) {
				spin_unlock(&sess->conn_lock);
				spin_unlock_bh(&tpg->session_lock);
				goto done;
			}
		}
		spin_unlock(&sess->conn_lock);

		if (single_out)
			break;
	}
	spin_unlock_bh(&tpg->session_lock);

	oob = 0;
done:
	iscsi_put_tpg(tpg);
	if (oob) {
		TRACE_ERROR("Ran out of buffer..\n");
	}
	if (b) kfree(b);
	return(cl);
}

extern int iscsi_get_tpg_info_count_for_global (unsigned char *targetname, int *count)
{
	u16 i;
	iscsi_portal_group_t *tpg;
	iscsi_tiqn_t *tiqn;
	
	if (!(tiqn = core_get_tiqn(targetname))) {
		TRACE_ERROR("Unable to locate targetname\n");
		return(-1);
	}

	*count = 1;

	spin_lock(&tiqn->tiqn_tpg_lock);
	for (i = 0; i < ISCSI_MAX_TPGS; i++) {
		tpg = &tiqn->tiqn_tpg_list[i];

		if (tpg->tpg_state == TPG_STATE_FREE)
			continue;

		*count += 1;
	}
	spin_unlock(&tiqn->tiqn_tpg_lock);
	
	return(0);
}

extern int iscsi_get_tpg_info_count_for_tpg (unsigned char *targetname, u16 tpgt, int *count)
{
	iscsi_node_acl_t *acl = NULL;
	iscsi_portal_group_t *tpg = NULL;
	iscsi_tiqn_t *tiqn;

	if (!(tpg = core_get_tpg_from_iqn(targetname, &tiqn, tpgt, 0)))
		return(-1);

	*count = 1;

	spin_lock_bh(&tpg->acl_node_lock);
	for (acl = tpg->acl_node_head; acl; acl = acl->next) {
		*count += 1;
	}
	spin_unlock_bh(&tpg->acl_node_lock);

	iscsi_put_tpg(tpg);
	
	return(0);
}

extern int iscsi_tpg_get_global_tpg_info (
	unsigned char *targetname,
	char *pb,       /* Pointer to info buffer */
	int ml,         /* Max Length in bytes of buffer space */
	int header,
	int counter_offset,
	int single_out)
{
	unsigned char *b = NULL;
	u16 i;
	int start = 0;
	int bl = 0, cl = 0, oob = 1;
	iscsi_portal_group_t *tpg = NULL;
	iscsi_tiqn_t *tiqn;

	if (!(tiqn = core_get_tiqn(targetname))) {
		TRACE_ERROR("Unable to locate targetname\n");
		oob = 0;
		goto done;
	}

	if (!(b = alloc_buf()))
		goto done;

	if (header) {
		memset(b, 0, TMP_BUF_LEN);
		bl = sprintf(b, "----------------------------[Global TPG Info]----------------------------\n");
		if (check_and_copy_buf(pb, b, &cl, &bl, &ml) < 0)
			goto done;
	}

	spin_lock(&tiqn->tiqn_tpg_lock);
        for (i = 0; i < ISCSI_MAX_TPGS; i++) {
                tpg = &tiqn->tiqn_tpg_list[i];

                if (tpg->tpg_state == TPG_STATE_FREE)
                        continue;

		if (single_out && (start < counter_offset)) {
			start++;
			continue;
		}

		memset(b, 0, TMP_BUF_LEN);
		bl = sprintf(b, "iSCSI Target Portal Group Tag: %hu  TSIH: %hu\n", tpg->tpgt, tpg->ntsih);
		bl += sprintf (b+bl, "TPG State:  ");

		switch (tpg->tpg_state) {
		case TPG_STATE_ACTIVE:
			bl += sprintf(b+bl, "Active  ");
			break;
		case TPG_STATE_INACTIVE:
			bl += sprintf(b+bl, "Inactive  ");
			break;
		default:
			bl += sprintf(b+bl, "*ERROR* Unknown TPG State: 0x%02x  ", tpg->tpg_state);
			break;
		}
		if (check_and_copy_buf(pb, b, &cl, &bl, &ml) < 0) {
			spin_unlock(&tiqn->tiqn_tpg_lock);
			goto done;
		}

		memset(b, 0, TMP_BUF_LEN);
		bl = sprintf(b, "Enforce iSCSI Authentication: %s\n", 
				ISCSI_TPG_ATTRIB(tpg)->authentication ? "Yes" : "No");
		bl += sprintf(b+bl, "Active iSCSI Sessions: %u\n", tpg->nsessions);
		if (check_and_copy_buf(pb, b, &cl, &bl, &ml) < 0) {
			spin_unlock(&tiqn->tiqn_tpg_lock);
			goto done;
		}

		if (single_out)
			break;
        }
	spin_unlock(&tiqn->tiqn_tpg_lock);
	
	oob = 0;
done:
	if (oob) {
		TRACE_ERROR("Ran out of buffer..\n");
	}
	if (b) kfree(b);
	return(cl);
}

/*	iscsi_tpg_get_tpg_info():
 *
 *
 */
extern int iscsi_tpg_get_tpg_info (
	unsigned char *targetname,
	u16 tpgt,                              
	char *pb,       /* Pointer to info buffer */
	int ml,         /* Max Length in bytes of buffer space */
	int header,
	int counter_offset,
	int single_out)
{
	unsigned char *b, buf_ipv4[IPV4_BUF_SIZE], buf_ipv4_ex[IPV4_BUF_SIZE];
	unsigned char *ip, *ip_ex;
	int j, start = 0;
	int bl = 0, cl = 0, oob = 1;
	iscsi_dev_entry_t *deve = NULL;
	iscsi_portal_group_t *tpg = NULL;
	iscsi_node_acl_t *acl = NULL;
	iscsi_np_ex_t *np_ex;
	iscsi_tiqn_t *tiqn;
	iscsi_tpg_np_t *tpg_np = NULL;
	
	if (!(tpg = core_get_tpg_from_iqn(targetname, &tiqn, tpgt, 0))) {
		oob = 0;
		return(cl);
	}

	if (!(b = alloc_buf()))
		goto done;

	if (header) {
		memset(b, 0, TMP_BUF_LEN);
		bl = sprintf(b, "----------------------------[TPG Info for TPGT: %hu]----------------------------\n", tpg->tpgt);
		bl += sprintf(b+bl, "iSCSI Target Portal Group Tag: %hu  TSIH: %hu\n", tpg->tpgt, tpg->ntsih);
		bl += sprintf (b+bl, "TPG State:  ");

		switch (tpg->tpg_state) {
		case TPG_STATE_ACTIVE:
			bl += sprintf(b+bl, "Active  ");
			break;
		case TPG_STATE_INACTIVE:
			bl += sprintf(b+bl, "Inactive  ");
			break;
		default:
			bl += sprintf(b+bl, "*ERROR* Unknown TPG State: 0x%02x  ", tpg->tpg_state);
			break;
		}
		if (check_and_copy_buf(pb, b, &cl, &bl, &ml) < 0)
			goto done;
	
		memset(b, 0, TMP_BUF_LEN);
		bl = sprintf(b, "Enforce iSCSI Authentication: %s\n", 
			ISCSI_TPG_ATTRIB(tpg)->authentication ? "Yes" : "No");	
		bl += sprintf(b+bl, "Active iSCSI Sessions: %u\n", tpg->nsessions);
		if (check_and_copy_buf(pb, b, &cl, &bl, &ml) < 0)
			goto done;

		memset(b, 0, TMP_BUF_LEN);
		bl = sprintf(b, "Active Exported Network Portals: %u\n", tpg->num_tpg_nps);
		if (check_and_copy_buf(pb, b, &cl, &bl, &ml) < 0)
			goto done;

		spin_lock(&tpg->tpg_np_lock);
		list_for_each_entry(tpg_np, &tpg->tpg_gnp_list, tpg_np_list) {
			memset(b, 0, TMP_BUF_LEN);

			if (tpg_np->tpg_np->np_flags & NPF_NET_IPV6)
				ip = &tpg_np->tpg_np->np_ipv6[0];
			else {
				memset(buf_ipv4, 0, IPV4_BUF_SIZE);
				iscsi_ntoa2(buf_ipv4, tpg_np->tpg_np->np_ipv4);
				ip = &buf_ipv4[0];
			}

			bl = sprintf(b, "        Ethernet at %s %s %s%s%s:%hu\n",
				(tpg_np->tpg_np->np_flags & NPF_NET_IPV6) ?
				"IPv6" : "IPv4", (tpg_np->tpg_np->np_network_transport == ISCSI_TCP)
				? "TCP" : "SCTP", (tpg_np->tpg_np->np_flags & NPF_NET_IPV6) ?
				"[" : "", ip, (tpg_np->tpg_np->np_flags & NPF_NET_IPV6) ?
				 "]" : "", tpg_np->tpg_np->np_port);

			if (check_and_copy_buf(pb, b, &cl, &bl, &ml) < 0) {
				spin_unlock(&iscsi_global->np_lock);
				goto done;
			}

			spin_lock(&tpg_np->tpg_np->np_ex_lock);
			list_for_each_entry(np_ex, &tpg_np->tpg_np->np_nex_list, np_ex_list) {
				memset(b, 0, TMP_BUF_LEN);

				if (tpg_np->tpg_np->np_flags & NPF_NET_IPV6)
					ip_ex = &np_ex->np_ex_ipv6[0];
				else {
					memset(buf_ipv4_ex, 0, IPV4_BUF_SIZE);
					iscsi_ntoa2(buf_ipv4_ex, np_ex->np_ex_ipv4);
					ip_ex = &buf_ipv4_ex[0];
				}

				bl = sprintf(b, "       Ethernet at %s - %s %s:%hu"
					" External: %s:%hu %s\n",
					(strlen(tpg_np->tpg_np->np_net_dev)) ?
					(char *)tpg_np->tpg_np->np_net_dev : "None" ,
					(tpg_np->tpg_np->np_flags & NPF_NET_IPV6) ?
					"IPv6" : "IPv4", ip, tpg_np->tpg_np->np_port,
					ip_ex, np_ex->np_ex_port,
					(tpg_np->tpg_np->np_network_transport == ISCSI_TCP) ?
						"TCP" : "SCTP");

				if (check_and_copy_buf(pb, b, &cl, &bl, &ml) < 0) {
					spin_unlock(&tpg_np->tpg_np->np_ex_lock);
					spin_unlock(&tpg->tpg_np_lock);
					goto done;
				}
			}
			spin_unlock(&tpg_np->tpg_np->np_ex_lock);
		}
		spin_unlock(&tpg->tpg_np_lock);

		memset(b, 0, TMP_BUF_LEN);
		bl = sprintf(b, "Active ACLed iSCSI Initiator Nodes: %u\n", tpg->num_node_acls);
		if (check_and_copy_buf(pb, b, &cl, &bl, &ml) < 0)
			goto done;
	}

	spin_lock_bh(&tpg->acl_node_lock);
	for (acl = tpg->acl_node_head; acl; acl = acl->next) {
		if (single_out && (start < counter_offset)) {
			start++;
			continue;
		}

		memset(b, 0, TMP_BUF_LEN);
		bl = sprintf(b, "	iSCSI Initiator TCQ Depth/Node Name: %u/%s\n",
				acl->queue_depth, acl->initiatorname);
		if (check_and_copy_buf(pb, b, &cl, &bl, &ml) < 0) {
			spin_unlock_bh(&tpg->acl_node_lock);
			goto done;
		}
		
		spin_lock(&acl->device_list_lock);
		for (j = 0; j < ISCSI_MAX_LUNS_PER_TPG; j++) {
			deve = &acl->device_list[j];

			if (!(deve->lun_flags & ISCSI_LUNFLAGS_INITIATOR_ACCESS))
				continue;

			memset(b, 0, TMP_BUF_LEN);
			bl = sprintf(b, "		iSCSI LUN: %u -> %u - %s"
				" - Active/Total Tasks: %u/%u - Average/Total : %s/%uk\n",
				deve->iscsi_lun->iscsi_lun, j,
				(deve->lun_flags & ISCSI_LUNFLAGS_READ_ONLY) ?
				"READ-ONLY" : "READ/WRITE",  deve->deve_cmds,
				deve->total_cmds, "NA", deve->total_bytes);
			if (check_and_copy_buf(pb, b, &cl, &bl, &ml) < 0) {
				spin_unlock(&acl->device_list_lock);
				spin_unlock_bh(&tpg->acl_node_lock);
				goto done;
			}
		}
		spin_unlock(&acl->device_list_lock);

		if (single_out)
			break;
	}
	spin_unlock_bh(&tpg->acl_node_lock);

	oob = 0;
done:
	iscsi_put_tpg(tpg);
	if (oob) {
		TRACE_ERROR("Ran out of buffer..\n");
	}
	if (b) kfree(b);
	return(cl);
}

extern int iscsi_get_plugin_count (int *count)
{
	u32 i, j;
	se_plugin_class_t *pc;
	se_plugin_t *p;

	*count = 1;

	spin_lock(&iscsi_global->plugin_class_lock);
	for (i = 0; i < MAX_PLUGIN_CLASSES; i++) {
		pc = &iscsi_global->plugin_class_list[i];

		if (!pc->plugin_array)
			continue;

		spin_lock(&pc->plugin_lock);
		for (j = 0; j < pc->max_plugins; j++) {	
			p = &pc->plugin_array[j];

			if (p->plugin_state != PLUGIN_REGISTERED)
				continue;

			*count += 1;
		}
		spin_unlock(&pc->plugin_lock);
	}
	spin_unlock(&iscsi_global->plugin_class_lock);

	return(0);
}

extern int iscsi_get_plugin_info (
        char *pb,       /* Pointer to info buffer */
        int ml,         /* Max Length in bytes of buffer space */
        int header,
        int counter_offset,
        int single_out)
{
	se_plugin_class_t *pc;
	se_plugin_t *p;
        unsigned char *b;
        int i, j, start = 0;       
        int bl = 0, cl = 0, oob = 1;    

	if (!(b = alloc_buf()))
		goto done;

	if (header) {
                memset(b, 0, TMP_BUF_LEN);
                bl = sprintf(b, "--------------------[Storage Engine Info]----------------------------\n");
	        bl += sprintf(b+bl, "%s iSCSI Target Core Stack "PYX_ISCSI_VERSION" on %s/%s on "UTS_RELEASE"\n",
                        PYX_ISCSI_VENDOR, utsname()->sysname, utsname()->machine);
		bl += sprintf(b+bl, "--------------------[SE Registered Plugins]--------------------------\n");

		if (check_and_copy_buf(pb, b, &cl, &bl, &ml) < 0)
			goto done;
	}

	spin_lock(&iscsi_global->plugin_class_lock);
	for (i = 0; i < MAX_PLUGIN_CLASSES; i++) {
		pc = &iscsi_global->plugin_class_list[i];

		if (!pc->plugin_array)
			continue;

		if (single_out && (start < counter_offset)) {
			start++;
			continue;
		}

		spin_lock(&pc->plugin_lock);
                for (j = 0; j < pc->max_plugins; j++) {
                        p = &pc->plugin_array[j];

                        if (p->plugin_state != PLUGIN_REGISTERED)
                                continue;

			memset(b, 0, TMP_BUF_LEN);
			bl = sprintf(b, "SE_%s[%d] - [%s] - ",
				pc->plugin_class_name, p->plugin_type, p->plugin_name);

			if (p->get_plugin_info)
				p->get_plugin_info(p, b, &bl);
			else
				bl += sprintf(b+bl, "Unknown\n");

			if (check_and_copy_buf(pb, b, &cl, &bl, &ml) < 0) {
				spin_unlock(&pc->plugin_lock);
				spin_unlock(&iscsi_global->plugin_class_lock);
				goto done;
			}
		}
                spin_unlock(&pc->plugin_lock);

		if (single_out)
			break;
	}
        spin_unlock(&iscsi_global->plugin_class_lock);

	oob = 0;
done:
	if (oob) {
		TRACE_ERROR("Ran out of buffer..\n");
	}
	if (b) kfree(b);
	return(cl);
}

extern int iscsi_get_node_attrib_info (
	unsigned char *targetname,
	u16 tpgt,
	char *initiatorname,
	char *pb,       /* Pointer to info buffer */
	int ml,         /* Max Length in bytes of buffer space */
	int header,
	int counter_offset,
	int single_out)
{
	unsigned char *b;
	int bl = 0, cl = 0, oob = 1;
	iscsi_node_acl_t *nacl = NULL;
	iscsi_portal_group_t *tpg = NULL;
	iscsi_tiqn_t *tiqn;

	if (!(tpg = core_get_tpg_from_iqn(targetname, &tiqn, tpgt, 0))) {
		oob = 0;
		return(cl);
	}

	if (!(b = alloc_buf()))
		goto done;
	
	spin_lock_bh(&tpg->acl_node_lock);
	if (!(nacl = __iscsi_tpg_get_initiator_node_acl(tpg, initiatorname))) {
		spin_unlock_bh(&tpg->acl_node_lock);
		oob = 0;
		goto done;
	}
	spin_unlock_bh(&tpg->acl_node_lock);

	if (header) {
		memset(b, 0, TMP_BUF_LEN);
		bl = sprintf(b, "--------[Node Attributes for %s]--------\n",
				nacl->initiatorname);
		if (check_and_copy_buf(pb, b, &cl, &bl, &ml) < 0)
			goto done;
	}

	memset(b, 0, TMP_BUF_LEN);

	bl = sprintf(b, "       dataout_timeout: %u\n", ISCSI_NODE_ATTRIB(nacl)->dataout_timeout);
	bl += sprintf(b+bl, "       dataout_timeout_retries: %u\n", ISCSI_NODE_ATTRIB(nacl)->dataout_timeout_retries);
	bl += sprintf(b+bl, "       default_erl: %u\n", ISCSI_NODE_ATTRIB(nacl)->default_erl);
	bl += sprintf(b+bl, "       nopin_timeout: %u\n", ISCSI_NODE_ATTRIB(nacl)->nopin_timeout);

	if (check_and_copy_buf(pb, b, &cl, &bl, &ml) < 0)
		goto done;

	memset(b, 0, TMP_BUF_LEN);

	bl = sprintf(b, "       nopin_response_timeout: %u\n", ISCSI_NODE_ATTRIB(nacl)->nopin_response_timeout);
	bl += sprintf(b+bl, "       random_datain_pdu_offsets: %u\n", ISCSI_NODE_ATTRIB(nacl)->random_datain_pdu_offsets);
	bl += sprintf(b+bl, "       random_datain_seq_offsets: %u\n", ISCSI_NODE_ATTRIB(nacl)->random_datain_seq_offsets);
	bl += sprintf(b+bl, "       random_r2t_offsets: %u\n", ISCSI_NODE_ATTRIB(nacl)->random_r2t_offsets);

	if (check_and_copy_buf(pb, b, &cl, &bl, &ml) < 0)
		goto done;

	memset(b, 0, TMP_BUF_LEN);

	bl = sprintf(b, "       tmr_cold_reset: %u\n", ISCSI_NODE_ATTRIB(nacl)->tmr_cold_reset);
	bl += sprintf(b+bl, "       tmr_warm_reset: %u\n", ISCSI_NODE_ATTRIB(nacl)->tmr_warm_reset);
	
	if (check_and_copy_buf(pb, b, &cl, &bl, &ml) < 0)
		goto done;

	oob = 0;
done:
	iscsi_put_tpg(tpg);
	if (oob) {
		TRACE_ERROR("Ran out of buffer..\n");
	}
	if (b) kfree(b);
	return(cl);
}

extern int iscsi_get_tpg_attrib_info (
	unsigned char *targetname,
        u16 tpgt,
        char *initiatorname,
        char *pb,       /* Pointer to info buffer */
        int ml,         /* Max Length in bytes of buffer space */
        int header,
        int counter_offset,
        int single_out)
{
	unsigned char *b;
        int bl = 0, cl = 0, oob = 1;
        iscsi_portal_group_t *tpg = NULL;
	iscsi_tiqn_t *tiqn;

	if (!(tpg = core_get_tpg_from_iqn(targetname, &tiqn, tpgt, 0))) {
                oob = 0;
                return(cl);
	}

	if (!(b = alloc_buf()))
		goto done;

        if (header) {
                memset(b, 0, TMP_BUF_LEN);
                bl = sprintf(b, "--------[TPG Attributes for Portal Group: %hu]--------\n",
                                tpgt);
                if (check_and_copy_buf(pb, b, &cl, &bl, &ml) < 0)
                        goto done;
	}

	memset(b, 0, TMP_BUF_LEN);

	bl = sprintf(b, "       authentication: %u\n", ISCSI_TPG_ATTRIB(tpg)->authentication);
	bl += sprintf(b+bl, "       login_timeout: %u\n", ISCSI_TPG_ATTRIB(tpg)->login_timeout); 
	bl += sprintf(b+bl, "       netif_timeout: %u\n", ISCSI_TPG_ATTRIB(tpg)->netif_timeout);
	bl += sprintf(b+bl, "       generate_node_acls: %u\n", ISCSI_TPG_ATTRIB(tpg)->generate_node_acls);

	if (check_and_copy_buf(pb, b, &cl, &bl, &ml) < 0)
		goto done;

	memset(b, 0, TMP_BUF_LEN);

	bl = sprintf(b, "       cache_dynamic_acls: %u\n", ISCSI_TPG_ATTRIB(tpg)->cache_dynamic_acls);
	bl += sprintf(b+bl, "       default_queue_depth: %u\n", ISCSI_TPG_ATTRIB(tpg)->default_queue_depth);
	bl += sprintf(b+bl, "       demo_mode_lun_access: %u\n", ISCSI_TPG_ATTRIB(tpg)->demo_mode_lun_access);

	if (check_and_copy_buf(pb, b, &cl, &bl, &ml) < 0)
		goto done;

	oob = 0;
done:
	iscsi_put_tpg(tpg);
        if (oob) {
		TRACE_ERROR("Ran out of buffer..\n");
	}
	if (b) kfree(b);
	return(cl);
}

extern int core_get_tiqn_count (int *count)
{
	iscsi_tiqn_t *tiqn;

	spin_lock(&iscsi_global->tiqn_lock);
	list_for_each_entry(tiqn, &iscsi_global->g_tiqn_list, tiqn_list) {
		*count += 1;
	}
	spin_unlock(&iscsi_global->tiqn_lock);

	return(0);
}

extern int core_get_np_count (int *count)
{
	iscsi_np_t *np;

	spin_lock(&iscsi_global->np_lock);
	list_for_each_entry(np, &iscsi_global->g_np_list, np_list) {
		*count += 1;
	}
	spin_unlock(&iscsi_global->np_lock);

	return(0);
}

extern int core_list_gninfo (
	char *pb,       /* Pointer to info buffer */
	int ml,         /* Max Length in bytes of buffer space */
	int header,
	int counter_offset,
	int single_out)
{
	unsigned char *b, *ip, *ip_ex, buf_ipv4[IPV4_BUF_SIZE];
	int start = 0;
	int i, bl = 0, cl = 0, oob = 1;
	iscsi_portal_group_t *tpg;
	iscsi_np_ex_t *np_ex;
	iscsi_tiqn_t *tiqn;
	iscsi_tpg_np_t *tpg_np;

	if (!(b = alloc_buf()))
		goto done;

	if (header) {
		memset(b, 0, TMP_BUF_LEN);
		bl = sprintf(b, "----------------------------[Global Node Info]----------------------------\n");    
		if (check_and_copy_buf(pb, b, &cl, &bl, &ml) < 0)
			goto done;
	}

	spin_lock(&iscsi_global->tiqn_lock);
	list_for_each_entry(tiqn, &iscsi_global->g_tiqn_list, tiqn_list) {
		
		if (single_out && (start < counter_offset)) {
			start++;
			continue;
		}

		memset(b, 0, TMP_BUF_LEN);
		bl = sprintf(b, "TargetName=%s\n", tiqn->tiqn);

		if (check_and_copy_buf(pb, b, &cl, &bl, &ml) < 0) {
			spin_unlock(&tiqn->tiqn_tpg_lock);
			goto done;
		}

#warning FIXME: Extend for unlimited 
		spin_lock(&tiqn->tiqn_tpg_lock);
		for (i = 0; i < ISCSI_MAX_TPGS; i++) {
			tpg = &tiqn->tiqn_tpg_list[i];
			
			spin_lock(&tpg->tpg_state_lock);
			if (tpg->tpg_state == TPG_STATE_FREE) {
				spin_unlock(&tpg->tpg_state_lock);
				continue;
			}
			spin_unlock(&tpg->tpg_state_lock);

			spin_lock(&tpg->tpg_np_lock);
			list_for_each_entry(tpg_np, &tpg->tpg_gnp_list, tpg_np_list) {
				memset(b, 0, TMP_BUF_LEN);

				if (tpg_np->tpg_np->np_flags & NPF_NET_IPV6)
					ip = &tpg_np->tpg_np->np_ipv6[0];
				else {
					memset(buf_ipv4, 0, IPV4_BUF_SIZE);
					iscsi_ntoa2(buf_ipv4, tpg_np->tpg_np->np_ipv4);
					ip = &buf_ipv4[0];
				}

				bl = sprintf(b, "TargetAddress=%s%s%s:%hu,%hu\n",
					(tpg_np->tpg_np->np_flags & NPF_NET_IPV6) ?
					"[" : "", ip, (tpg_np->tpg_np->np_flags & NPF_NET_IPV6) ?
					"]" : "", tpg_np->tpg_np->np_port, tpg->tpgt);
				if (check_and_copy_buf(pb, b, &cl, &bl, &ml) < 0) {
					spin_unlock(&tpg->tpg_np_lock);
					spin_unlock(&tiqn->tiqn_tpg_lock);
					goto done;
				}

				spin_lock(&tpg_np->tpg_np->np_ex_lock);
				list_for_each_entry(np_ex, &tpg_np->tpg_np->np_nex_list,
						np_ex_list) {
					memset(b, 0, TMP_BUF_LEN);

					if (tpg_np->tpg_np->np_flags & NPF_NET_IPV6) 
						ip_ex = &np_ex->np_ex_ipv6[0];
					else {  
						memset(buf_ipv4, 0, IPV4_BUF_SIZE);
						iscsi_ntoa2(buf_ipv4, np_ex->np_ex_ipv4);
						ip_ex = &buf_ipv4[0];
					}

					bl = sprintf(b, "TargetAddress=%s%s%s:%hu,%hu\n",
						(tpg_np->tpg_np->np_flags & NPF_NET_IPV6) ?
						"[" : "", ip_ex, (tpg_np->tpg_np->np_flags & NPF_NET_IPV6) ?
						"]" : "", np_ex->np_ex_port, tpg->tpgt);

					if (check_and_copy_buf(pb, b, &cl, &bl, &ml) < 0) {
						spin_unlock(&tpg_np->tpg_np->np_ex_lock);
						spin_unlock(&tpg->tpg_np_lock);
						spin_unlock(&tiqn->tiqn_tpg_lock);
						goto done;
					}
				}
				spin_unlock(&tpg_np->tpg_np->np_ex_lock);
			}
			spin_unlock(&tpg->tpg_np_lock);
		}
		spin_unlock(&tiqn->tiqn_tpg_lock);

		if (single_out) {
			spin_unlock(&iscsi_global->tiqn_lock);
			oob = 0;
			goto done;
		}
	}
	spin_unlock(&iscsi_global->tiqn_lock);

	oob = 0;
done:
	if (oob) {
		TRACE_ERROR("Ran out of buffer..\n");
	}
	if (b) kfree(b);
	return(cl);
}

extern int core_list_gnpinfo (
        char *pb,       /* Pointer to info buffer */
        int ml,         /* Max Length in bytes of buffer space */
        int header,
        int counter_offset,
        int single_out)
{
	unsigned char *b, *ip, buf_ipv4[IPV4_BUF_SIZE];
	int start = 0;
	int bl = 0, cl = 0, oob = 1;
	iscsi_np_t *np;
	iscsi_np_ex_t *np_ex;

	if (!(b = alloc_buf()))
		goto done;

	if (header) {
		memset(b, 0, TMP_BUF_LEN);
		bl = sprintf(b, "----------------------------[Global Network Portal Info]----------------------------\n");
		if (check_and_copy_buf(pb, b, &cl, &bl, &ml) < 0)
			goto done;
	}

	spin_lock(&iscsi_global->np_lock);
	list_for_each_entry(np, &iscsi_global->g_np_list, np_list) {

		if (single_out && (start < counter_offset)) {
			start++;
			continue;
		}

		memset(b, 0, TMP_BUF_LEN);

		if (np->np_flags & NPF_NET_IPV6)
			ip = &np->np_ipv6[0];
		else {
			memset(buf_ipv4, 0, IPV4_BUF_SIZE);
			iscsi_ntoa2(buf_ipv4, np->np_ipv4);
			ip = &buf_ipv4[0];
		}

		bl = sprintf(b, "Network Portal - Portal Group references: %u\n",
				np->np_exports);

		bl += sprintf(b+bl, "        %s %s %s%s%s:%d\n",
			(np->np_flags & NPF_NET_IPV6) ? "IPv6" : "IPv4",
			(np->np_network_transport == ISCSI_TCP) ?
			"TCP" : "SCTP", (np->np_flags & NPF_NET_IPV6) ? "[" : "",
			ip, (np->np_flags & NPF_NET_IPV6) ? "]" : "", np->np_port);

		if (check_and_copy_buf(pb, b, &cl, &bl, &ml) < 0) {
			spin_unlock(&iscsi_global->np_lock);
			goto done;
		}

		spin_lock(&np->np_ex_lock);
		list_for_each_entry(np_ex, &np->np_nex_list, np_ex_list) {
			memset(b, 0, TMP_BUF_LEN);

			if (np->np_flags & NPF_NET_IPV6) 
				ip = &np_ex->np_ex_ipv6[0];
			else {
				memset(buf_ipv4, 0, IPV4_BUF_SIZE);
				iscsi_ntoa2(buf_ipv4, np_ex->np_ex_ipv4);
				ip = &buf_ipv4[0];
			}

			bl = sprintf(b, "External Portal: %s:%d\n",
				ip, np_ex->np_ex_port);

			if (check_and_copy_buf(pb, b, &cl, &bl, &ml) < 0) {
				spin_unlock(&np->np_ex_lock);
				spin_unlock(&iscsi_global->np_lock);
				goto done;
			}
		}
		spin_unlock(&np->np_ex_lock);

		if (single_out) {
			spin_unlock(&iscsi_global->np_lock);
			oob = 0;
			goto done;
		}
	}
	spin_unlock(&iscsi_global->np_lock);

	oob = 0;
done:
	if (oob) {
		TRACE_ERROR("Ran out of buffer..\n");
	}
	if (b) kfree(b);
	return(cl);
}
