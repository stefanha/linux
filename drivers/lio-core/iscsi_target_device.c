/*********************************************************************************
 * Filename:  iscsi_target_device.c
 *
 * This file contains the iSCSI Virtual Device and Disk Transport
 * agnostic related functions.
 *
 * Copyright (c) 2003, 2004, 2005 PyX Technologies, Inc.
 * Copyright (c) 2005-2006 SBE, Inc.  All Rights Reserved.
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


#define ISCSI_TARGET_DEVICE_C

#include <linux/net.h>
#include <linux/string.h>
#include <linux/delay.h>
#include <linux/timer.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/smp_lock.h>
#include <linux/in.h>
#include <net/sock.h>
#include <net/tcp.h>

#include <iscsi_linux_os.h>
#include <iscsi_linux_defs.h>

#include <iscsi_lists.h>
#include <iscsi_debug.h>
#include <iscsi_protocol.h>
#include <iscsi_target_core.h>
#include <iscsi_target_error.h>
#include <iscsi_target_ioctl.h> 
#include <iscsi_target_ioctl_defs.h>
#include <iscsi_target_device.h>
#include <iscsi_target_hba.h>
#include <iscsi_target_tpg.h>
#include <iscsi_target_transport.h>
#include <iscsi_target_util.h>

#include <iscsi_target_plugin.h>
#include <iscsi_target_seobj.h>
#include <iscsi_target_feature_obj.h>

#undef ISCSI_TARGET_DEVICE_C

extern se_global_t *iscsi_global;
extern __u32 iscsi_unpack_lun (unsigned char *);

extern int iscsi_check_devices_access (se_hba_t *hba)
{
	int ret = 0;
	se_device_t *dev = NULL, *dev_next = NULL;

	spin_lock(&hba->device_lock);
	dev = hba->device_head;
	while (dev) {
		dev_next = dev->next;

		if (DEV_OBJ_API(dev)->check_count(&dev->dev_feature_obj) != 0) {
			TRACE_ERROR("check_count(&dev->dev_feature_obj): %u\n",
				DEV_OBJ_API(dev)->check_count(&dev->dev_feature_obj));
			ret = -1;
		}

		dev = dev_next;
	}
	spin_unlock(&hba->device_lock);

	return(ret);		
}

/*	iscsi_disable_devices_for_hba():
 *
 *
 */
extern void iscsi_disable_devices_for_hba (se_hba_t *hba)
{
	se_device_t *dev, *dev_next;

	spin_lock(&hba->device_lock);
	dev = hba->device_head;
	while (dev) {
		dev_next = dev->next;
		
		spin_lock(&dev->dev_status_lock);
		if ((dev->dev_status & ISCSI_DEVICE_ACTIVATED) ||
		    (dev->dev_status & ISCSI_DEVICE_DEACTIVATED) ||
		    (dev->dev_status & ISCSI_DEVICE_OFFLINE_ACTIVATED) ||
		    (dev->dev_status & ISCSI_DEVICE_OFFLINE_DEACTIVATED)) {
			dev->dev_status |= ISCSI_DEVICE_SHUTDOWN;
			dev->dev_status &= ~ISCSI_DEVICE_ACTIVATED;
			dev->dev_status &= ~ISCSI_DEVICE_DEACTIVATED;
			dev->dev_status &= ~ISCSI_DEVICE_OFFLINE_ACTIVATED;
			dev->dev_status &= ~ISCSI_DEVICE_OFFLINE_DEACTIVATED;

			up(&dev->dev_queue_obj->thread_sem);
		}
		spin_unlock(&dev->dev_status_lock);

		dev = dev_next;
	}
	spin_unlock(&hba->device_lock);

	return;
}

/*	se_release_device_for_hba():
 *
 *
 */
extern void se_release_device_for_hba (se_device_t *dev)
{
	se_hba_t *hba = dev->iscsi_hba;

	if ((dev->dev_status & ISCSI_DEVICE_ACTIVATED) ||
	    (dev->dev_status & ISCSI_DEVICE_DEACTIVATED) ||
	    (dev->dev_status & ISCSI_DEVICE_SHUTDOWN) ||
	    (dev->dev_status & ISCSI_DEVICE_OFFLINE_ACTIVATED) ||
	    (dev->dev_status & ISCSI_DEVICE_OFFLINE_DEACTIVATED))
		se_dev_stop(dev);

	transport_generic_free_device(dev);

	spin_lock(&hba->device_lock);
	REMOVE_ENTRY_FROM_LIST(dev, hba->device_head, hba->device_tail);
	hba->dev_count--;
	spin_unlock(&hba->device_lock);
		
	kfree(dev->dev_status_queue_obj);
	kfree(dev->dev_queue_obj);
	kfree(dev);

	return;
}

/*	iscsi_get_lun():
 *
 *
 */
//#warning FIXME v2.8: Breakage in iscsi_get_lun() for TMRs
extern se_lun_t *iscsi_get_lun (
	iscsi_conn_t *conn,
	u64 lun)
{
	u32 unpacked_lun;
	se_dev_entry_t *deve;
	se_lun_t *iscsi_lun = NULL;
	iscsi_portal_group_t *tpg = conn->tpg;
	iscsi_session_t *sess = SESS(conn);

	unpacked_lun = iscsi_unpack_lun((unsigned char *)&lun);

	if (unpacked_lun > (ISCSI_MAX_LUNS_PER_TPG-1)) {
		TRACE_ERROR("iSCSI LUN: %u exceeds ISCSI_MAX_LUNS_PER_TPG-1:"
			" %u for Target Portal Group: %hu\n", unpacked_lun,
			ISCSI_MAX_LUNS_PER_TPG-1, tpg->tpgt);
		return(NULL);
	}

	spin_lock_bh(&SESS_NODE_ACL(sess)->device_list_lock);
	deve = &SESS_NODE_ACL(sess)->device_list[unpacked_lun];
	if (deve->lun_flags & ISCSI_LUNFLAGS_INITIATOR_ACCESS) {
#if 0
		TRACE_ERROR("deve->deve_cmds incremented to %d\n", deve->deve_cmds);
#endif
		iscsi_lun = deve->iscsi_lun;
	}
	spin_unlock_bh(&SESS_NODE_ACL(sess)->device_list_lock);

	if (!iscsi_lun) {
		TRACE_ERROR("Unable to find Active iSCSI LUN: 0x%08x on"
			" iSCSI TPG: %hu\n", unpacked_lun, tpg->tpgt);
		return(NULL);
	}

	return(iscsi_lun);
}

/*	iscsi_get_lun_for_cmd():
 *
 *
 */
extern int iscsi_get_lun_for_cmd (
	iscsi_cmd_t *cmd,
	u64 lun)
{
	int ret = -1;
	u32 unpacked_lun;
	iscsi_conn_t *conn= CONN(cmd);
	se_dev_entry_t *deve;
	se_lun_t *iscsi_lun = NULL;
	iscsi_portal_group_t *tpg = conn->tpg;
	iscsi_session_t *sess = SESS(conn);
	unsigned long flags;

	unpacked_lun = iscsi_unpack_lun((unsigned char *)&lun);

	if (unpacked_lun > (ISCSI_MAX_LUNS_PER_TPG-1)) {
		TRACE_ERROR("iSCSI LUN: %u exceeds ISCSI_MAX_LUNS_PER_TPG-1:"
			" %u for Target Portal Group: %hu\n", unpacked_lun,
			ISCSI_MAX_LUNS_PER_TPG-1, tpg->tpgt);
		return(-1);
	}
	
	spin_lock_bh(&SESS_NODE_ACL(sess)->device_list_lock);
	deve = cmd->iscsi_deve = &SESS_NODE_ACL(sess)->device_list[unpacked_lun];
	if (deve->lun_flags & ISCSI_LUNFLAGS_INITIATOR_ACCESS) {
		if (cmd) {
			deve->total_cmds++;
			deve->total_bytes += cmd->data_length;

			if (cmd->data_direction == ISCSI_WRITE) {
				if (deve->lun_flags & ISCSI_LUNFLAGS_READ_ONLY) {
					ret = -2;
					goto out;
				}
#ifdef SNMP_SUPPORT
				deve->write_bytes += cmd->data_length;
#endif /* SNMP_SUPPORT */  
			} else if (cmd->data_direction == ISCSI_READ) {
#ifdef SNMP_SUPPORT
				deve->read_bytes += cmd->data_length;
#endif /* SNMP_SUPPORT */
			}
		}
		deve->deve_cmds++;

		iscsi_lun = cmd->iscsi_lun = deve->iscsi_lun;
		cmd->orig_fe_lun = unpacked_lun;
		cmd->orig_fe_lun_type = cmd->iscsi_lun->lun_type;
		cmd->se_orig_obj_api = ISCSI_LUN(cmd)->lun_obj_api;
		cmd->se_orig_obj_ptr = ISCSI_LUN(cmd)->lun_type_ptr;
		cmd->cmd_flags |= ICF_SE_LUN_CMD;
	}
out:
	spin_unlock_bh(&SESS_NODE_ACL(sess)->device_list_lock);

	if (!iscsi_lun) {
		switch (ret) {
		case -2:
			PYXPRINT("Detected READ-ONLY LUN Access for 0x%08x on"
				" iSCSI TPG: %hu\n", unpacked_lun, tpg->tpgt);
			break;
		default:
			PYXPRINT("Unable to find Active iSCSI LUN: 0x%08x on"
				" iSCSI TPG: %hu\n", unpacked_lun, tpg->tpgt);
			break;
		}

		return(ret);
	}

	/*
	 * Determine if the se_lun_t is online.
	 */
	if (LUN_OBJ_API(iscsi_lun)->check_online(iscsi_lun->lun_type_ptr) != 0)
		return(-1);

//#warning FIXME v2.8: Add SNMP bits to se_obj_api 
#ifdef SNMP_SUPPORT
	if (iscsi_lun->lun_type == ISCSI_LUN_TYPE_DEVICE) {
		se_device_t *dev = iscsi_lun->iscsi_dev;

		spin_lock(&dev->stats_lock);
		dev->num_cmds++;
		if (cmd->data_direction == ISCSI_WRITE)
			dev->write_bytes += cmd->data_length;
		else if (cmd->data_direction == ISCSI_READ)
			dev->read_bytes += cmd->data_length;
		spin_unlock(&dev->stats_lock);
	}
#endif /* SNMP_SUPPORT */
	
	/*
	 * REPORT_LUN never gets added to the LUN list because it never makes
	 * it to the storage engine queue.
	 */
	if (cmd->cmd_flags & ICF_REPORT_LUNS)
		return(0);
	
	/*
	 * Add the iscsi_cmd_t to the se_lun_t's cmd list.  This list is used
	 * for tracking state of iscsi_cmd_ts during LUN shutdown events.
	 */
	spin_lock_irqsave(&iscsi_lun->lun_cmd_lock, flags);
	ADD_ENTRY_TO_LIST_PREFIX(l, cmd, iscsi_lun->lun_cmd_head, iscsi_lun->lun_cmd_tail);
	atomic_set(&T_TASK(cmd)->transport_lun_active, 1);
#if 0
	TRACE_ERROR("Adding ITT: 0x%08x to LUN LIST[%d]\n", cmd->init_task_tag, iscsi_lun->iscsi_lun);
#endif
	spin_unlock_irqrestore(&iscsi_lun->lun_cmd_lock, flags);
	
	return(0);
}

/*	iscsi_determine_maxcmdsn():
 * 
 *
 */
extern void iscsi_determine_maxcmdsn (iscsi_session_t *sess, iscsi_node_acl_t *acl)
{
	/*
	 * This is a discovery session, the single queue slot was already assigned in
	 * iscsi_login_zero_tsih().  Since only Logout and Text Opcodes are allowed
	 * during discovery we do not have to worry about the HBA's queue depth here.
	 */
	if (SESS_OPS(sess)->SessionType)
		return;	

	/*
	 * This is a normal session, set the Session's CmdSN window to the
	 * iscsi_node_acl_t->queue_depth value set by iscsi_add_acl_for_tpg() or
	 * iscsi_change_queue_depth().  The value in iscsi_node_acl_t->queue_depth
	 * has already been validated as a legal value in
	 * iscsi_set_queue_depth_for_node().
	 */
	sess->cmdsn_window = acl->queue_depth;
	sess->max_cmd_sn = (sess->max_cmd_sn + acl->queue_depth) - 1;

	return;
}

/*	iscsi_increment_maxcmdsn();
 *
 *	
 */
extern void iscsi_increment_maxcmdsn (iscsi_cmd_t *cmd, iscsi_session_t *sess)
{
	if (cmd->immediate_cmd || cmd->maxcmdsn_inc)
		return;

	cmd->maxcmdsn_inc = 1;
	
	spin_lock(&sess->cmdsn_lock);
	sess->max_cmd_sn += 1;
	TRACE(TRACE_ISCSI, "Updated MaxCmdSN to 0x%08x\n", sess->max_cmd_sn);
	spin_unlock(&sess->cmdsn_lock);
	
	return;
}

/*	iscsi_set_queue_depth_for_node():
 *
 *
 */
extern int iscsi_set_queue_depth_for_node (
	iscsi_portal_group_t *tpg,
	iscsi_node_acl_t *acl)
{
	if (!acl->queue_depth) {
		TRACE_ERROR("Queue depth for iSCSI Initiator Node: %s is 0,"
			" defaulting to 1.\n", acl->initiatorname);
		acl->queue_depth = 1;
	}

	return(0);
}

/*	iscsi_create_device_list_for_node():
 *
 *
 */
extern int iscsi_create_device_list_for_node (iscsi_node_acl_t *nacl, iscsi_portal_group_t *tpg)
{
	if (!(nacl->device_list = (se_dev_entry_t *) kmalloc(
			sizeof(se_dev_entry_t) * ISCSI_MAX_LUNS_PER_TPG, GFP_KERNEL))) {
		TRACE_ERROR("Unable to allocate memory for session"
				" device list.\n");
		return(-1);
	}
	memset(nacl->device_list, 0, sizeof(se_dev_entry_t) *
			ISCSI_MAX_LUNS_PER_TPG);

	return(0);
}

/*	iscsi_free_device_list_for_node():
 *
 *
 */
extern int iscsi_free_device_list_for_node (iscsi_node_acl_t *nacl, iscsi_portal_group_t *tpg)
{
	__u32 i;
	se_dev_entry_t *deve;
	se_lun_t *iscsi_lun;

	if (!nacl->device_list)
		return(0);
		
	spin_lock_bh(&nacl->device_list_lock);
	for (i = 0; i < ISCSI_MAX_LUNS_PER_TPG; i++) {
		deve = &nacl->device_list[i];
		
		if (!(deve->lun_flags & ISCSI_LUNFLAGS_INITIATOR_ACCESS))
			continue;
		
		if (!deve->iscsi_lun) {
			TRACE_ERROR("iSCSI device entries device pointer is"
				" NULL, but Initiator has access.\n");
			continue;
		}

		iscsi_lun = deve->iscsi_lun;

		spin_unlock_bh(&nacl->device_list_lock);
		iscsi_update_device_list_for_node(iscsi_lun, deve->mapped_lun,
				ISCSI_LUNFLAGS_NO_ACCESS, nacl, tpg, 0);
		spin_lock_bh(&nacl->device_list_lock);
	}
	spin_unlock_bh(&nacl->device_list_lock);

	kfree(nacl->device_list);
	nacl->device_list = NULL;
	
	return(0);
}

static int iscsi_check_device_list_access (
	u32 mapped_lun,
	iscsi_node_acl_t *nacl)
{
	int ret = 0;
	se_dev_entry_t *deve;
	
	spin_lock_bh(&nacl->device_list_lock);
	deve = &nacl->device_list[mapped_lun];
	if (deve->lun_flags & ISCSI_LUNFLAGS_INITIATOR_ACCESS)
		ret = -1;
	spin_unlock_bh(&nacl->device_list_lock);

	return(ret);
}

extern int iscsi_update_device_list_access (
	u32 mapped_lun,
	u32 lun_access,
	iscsi_node_acl_t *nacl)
{
	se_dev_entry_t *deve;

	spin_lock_bh(&nacl->device_list_lock);
	deve = &nacl->device_list[mapped_lun];
	if (!(deve->lun_flags & ISCSI_LUNFLAGS_INITIATOR_ACCESS)) {
		TRACE_ERROR("TPG[%u] - Initiator: %s Mapped LUN: %u not present!\n",
			nacl->tpg->tpgt, nacl->initiatorname, mapped_lun);
		spin_unlock_bh(&nacl->device_list_lock);
		return(ERR_LUN_NOT_ACTIVE);
	}
	
	if (deve->lun_flags & ISCSI_LUNFLAGS_READ_ONLY) {
		if (lun_access & ISCSI_LUNFLAGS_READ_WRITE)
			deve->lun_flags &= ~ISCSI_LUNFLAGS_READ_ONLY;
	} else {
		if (lun_access & ISCSI_LUNFLAGS_READ_ONLY)
			deve->lun_flags |= ISCSI_LUNFLAGS_READ_ONLY;
	}
	spin_unlock_bh(&nacl->device_list_lock);

	return(0);
}

/*	iscsi_update_device_list_for_node():
 *
 *
 */
extern void iscsi_update_device_list_for_node (
	se_lun_t *lun,
	u32 mapped_lun,
	u32 lun_access,
	iscsi_node_acl_t *nacl,
	iscsi_portal_group_t *tpg,
	int enable)
{
	int status = 0;
	se_dev_entry_t *deve;

	spin_lock_bh(&nacl->device_list_lock);
	deve = &nacl->device_list[mapped_lun];
	if (enable) {
		if (!(deve->lun_flags & ISCSI_LUNFLAGS_INITIATOR_ACCESS)) {
			deve->iscsi_lun = lun;
			deve->mapped_lun = mapped_lun;
			deve->lun_flags |= ISCSI_LUNFLAGS_INITIATOR_ACCESS;	

			if (lun_access & ISCSI_LUNFLAGS_READ_ONLY)
				deve->lun_flags |= ISCSI_LUNFLAGS_READ_ONLY;
			
			status = 2;
#ifdef SNMP_SUPPORT
			deve->creation_time = get_jiffies_64();
			deve->attach_count++;
#endif /* SNMP_SUPPORT */
		}
	} else {
		if (deve->lun_flags & ISCSI_LUNFLAGS_INITIATOR_ACCESS) {
			deve->iscsi_lun = NULL;
			deve->lun_flags = 0;
			status = 1;
		}
	}
	spin_unlock_bh(&nacl->device_list_lock);
		
	return;
}

//#define DEBUG_CLEAR_LUN
#ifdef DEBUG_CLEAR_LUN
#define DEBUG_CLEAR_L(x...) PYXPRINT(x)
#else
#define DEBUG_CLEAR_L(x...)
#endif

/*	iscsi_clear_lun_from_sessions():
 *
 *
 */
extern void iscsi_clear_lun_from_sessions (se_lun_t *lun, iscsi_portal_group_t *tpg)
{
	iscsi_cmd_t *cmd;
	unsigned long flags;

	/*
	 * Do exception processing and return CHECK_CONDITION status to the 
	 * Initiator Port.
	 */
	spin_lock_irqsave(&lun->lun_cmd_lock, flags);
	while ((cmd = lun->lun_cmd_head)) {
		if (!(T_TASK(cmd))) {
			TRACE_ERROR("ITT: 0x%08x, T_TASK(cmd) = NULL [i,t]_state: %u/%u\n",
				cmd->init_task_tag, cmd->i_state, cmd->t_state);
			BUG();
		}
		
		REMOVE_ENTRY_FROM_LIST_PREFIX(l, cmd, lun->lun_cmd_head, lun->lun_cmd_tail);
		atomic_set(&T_TASK(cmd)->transport_lun_active, 0);

		/*
		 * This will notify iscsi_target_transport.c:transport_cmd_check_stop()
		 * that a LUN shutdown is in progress for the iscsi_cmd_t.
		 */
		spin_lock(&T_TASK(cmd)->t_state_lock);
		DEBUG_CLEAR_L("iSCSI_LUN[%d] - Setting T_TASK(cmd)->transport_lun_stop for"
			" ITT: 0x%08x\n", ISCSI_LUN(cmd)->iscsi_lun, cmd->init_task_tag);
		atomic_set(&T_TASK(cmd)->transport_lun_stop, 1);
		spin_unlock(&T_TASK(cmd)->t_state_lock);

		spin_unlock_irqrestore(&lun->lun_cmd_lock, flags);

		if (!(ISCSI_LUN(cmd))) {
			TRACE_ERROR("ITT: 0x%08x, [i,t]_state: %u/%u\n", cmd->init_task_tag,
					cmd->i_state, cmd->t_state);
			BUG();
		}
		
		/*
		 * If the Storage engine still owns the iscsi_cmd_t, determine and/or
		 * stop its context.
		 */
		DEBUG_CLEAR_L("iSCSI_LUN[%d] - ITT: 0x%08x before transport_lun_wait_for_tasks()\n",
				ISCSI_LUN(cmd)->iscsi_lun, cmd->init_task_tag);

		if (transport_lun_wait_for_tasks(cmd, ISCSI_LUN(cmd)) < 0) {
			spin_lock_irqsave(&lun->lun_cmd_lock, flags);
			continue;
		}

		DEBUG_CLEAR_L("iSCSI_LUN[%d] - ITT: 0x%08x after transport_lun_wait_for_tasks()"
				" SUCCESS\n", ISCSI_LUN(cmd)->iscsi_lun, cmd->init_task_tag);

		/*
		 * The Storage engine stopped this iscsi_cmd_t before it was
		 * send to the iSCSI frontend for delivery back to the iSCSI
		 * Initiator Node.  Return this SCSI CDB back with an CHECK_CONDITION
		 * status.
		 */
		iscsi_send_check_condition_and_sense(cmd, NON_EXISTENT_LUN, 0);

		/*
		 * If the iSCSI frontend is waiting for this iscsi_cmd_t to be released,
		 * notify the waiting thread now that LU has finished accessing it.
		 */ 
		spin_lock_irqsave(&T_TASK(cmd)->t_state_lock, flags);
	        if (atomic_read(&T_TASK(cmd)->transport_lun_fe_stop)) {
	                DEBUG_CLEAR_L("iSCSI_LUN[%d] - Detected FE stop for iscsi_cmd_t:"
                                " %p ITT: 0x%08x\n", lun->iscsi_lun, cmd, cmd->init_task_tag);

			spin_unlock_irqrestore(&T_TASK(cmd)->t_state_lock, flags);
	                up(&T_TASK(cmd)->transport_lun_fe_stop_sem);
			spin_lock_irqsave(&lun->lun_cmd_lock, flags);
			continue;
		}
		atomic_set(&T_TASK(cmd)->transport_lun_stop, 0);
		
		DEBUG_CLEAR_L("iSCSI_LUN[%d] - ITT: 0x%08x finished processing\n",
			lun->iscsi_lun, cmd->init_task_tag);

		spin_unlock_irqrestore(&T_TASK(cmd)->t_state_lock, flags);
		spin_lock_irqsave(&lun->lun_cmd_lock, flags);
	}
	spin_unlock_irqrestore(&lun->lun_cmd_lock, flags);

	return;
}

/*      iscsi_clear_lun_from_tpg():
 *
 *
 */
extern void iscsi_clear_lun_from_tpg (se_lun_t *lun, iscsi_portal_group_t *tpg)
{
	u32 i;
        iscsi_node_acl_t *nacl, *nacl_next;
	se_dev_entry_t *deve;

        spin_lock_bh(&tpg->acl_node_lock);
        nacl = tpg->acl_node_head;
        while (nacl) {
                nacl_next = nacl->next;
		spin_unlock_bh(&tpg->acl_node_lock);

		spin_lock_bh(&nacl->device_list_lock);
		for (i = 0; i < ISCSI_MAX_LUNS_PER_TPG; i++) {
			deve = &nacl->device_list[i];
			if (lun != deve->iscsi_lun)
				continue;
			spin_unlock_bh(&nacl->device_list_lock);

	                iscsi_update_device_list_for_node(lun, deve->mapped_lun,
				ISCSI_LUNFLAGS_NO_ACCESS, nacl, tpg, 0);

			spin_lock_bh(&nacl->device_list_lock);
		}
		spin_unlock_bh(&nacl->device_list_lock);
			
		spin_lock_bh(&tpg->acl_node_lock);
                nacl = nacl_next;
        }
        spin_unlock_bh(&tpg->acl_node_lock);

        return;
}

/*	core_get_device_from_transport():
 *
 *
 */
extern se_device_t *core_get_device_from_transport (se_hba_t *hba, se_dev_transport_info_t *dti)
{
	se_device_t *dev;
	
	spin_lock(&hba->device_lock);
	for (dev = hba->device_head; dev; dev = dev->next) {
		spin_unlock(&hba->device_lock);
		if (!transport_generic_check_device_location(dev, dti))
			return(dev);
		spin_lock(&hba->device_lock);
	}
	spin_unlock(&hba->device_lock);
		
	return(NULL);
}

/*	iscsi_check_hba_for_virtual_device():
 *
 *
 */
extern int iscsi_check_hba_for_virtual_device (struct iscsi_target *tg, se_devinfo_t *di, se_hba_t *hba)
{
	int ret = 0;
	se_subsystem_api_t *t;
	
	if (!(tg->params_set & PARAM_HBA_ID)) {
		TRACE_ERROR("HBA_ID Not passed to createvirtdev, assuming hba_id=0."
			" PLEASE UPDATE SCRIPTS!!\n");
		di->hba_id = 0;
	}
	
	if (!(hba->hba_status & HBA_STATUS_ACTIVE)) {
		TRACE_ERROR("HBA_ID[%u] for create virtual device not active!\n", hba->hba_id); 
		return(ERR_CREATE_VIRTDEV_HBA_NOT_ACTIVE);
	}

	if (!hba->hba_ptr) {
		TRACE_ERROR("Unable to locate active se_hba_t at HBA ID: %u\n",
				hba->hba_id);
		return(ERR_HBA_CANNOT_LOCATE);
	}
	
	t = (se_subsystem_api_t *)plugin_get_obj(PLUGIN_TYPE_TRANSPORT, hba->type, &ret);
	if (!t || (ret != 0))
		return(ret);
	
	if (!t->check_virtdev_params) {
		TRACE_ERROR("createvirtdev is not required for Physical"
			" Storage Transports, ignoring request\n");
		return(-1);
	}

	if ((ret = t->check_virtdev_params(di, tg)) < 0)
		return(ret);
	
	return(0);
}

/*	iscsi_check_create_virtual_device():
 *
 *
 */
static int iscsi_check_create_virtual_device (se_hba_t *hba, se_dev_transport_info_t *dti)
{
	se_device_t *dev;

	if ((dev = core_get_device_from_transport(hba, dti))) {
		TRACE_ERROR("se_device_t already exists on iSCSI HBA:"
			" %u\n", hba->hba_id);
		return(1);
	}

	return(0);
}

/*	iscsi_create_virtual_device():
 *
 *	Used for Virtual Transport Plugins.
 */
extern int iscsi_create_virtual_device (se_hba_t *hba, se_devinfo_t *di, struct iscsi_target *tg)
{
	int ret = 0;
	se_dev_transport_info_t dti;
	se_subsystem_api_t *t;

	memset(&dti, 0, sizeof(se_dev_transport_info_t));

	t = (se_subsystem_api_t *)plugin_get_obj(PLUGIN_TYPE_TRANSPORT, hba->type, &ret);
	if (!t || (ret != 0))
		return(ret);
	
	if ((ret = t->check_dev_params(hba, tg, &dti)) < 0)
		return(ret);
	
	if (iscsi_check_create_virtual_device(hba, &dti))
		return(ERR_CREATE_VIRTDEV_FAILED);

	if (tg->params_set & PARAM_UU_ID) {
		di->uu_id[0] = tg->uu_id[0];
		di->uu_id[1] = tg->uu_id[1];
		di->uu_id[2] = tg->uu_id[2];
		di->uu_id[3] = tg->uu_id[3];
	} else if (tg->params_set & PARAM_LVM_UUID)
		snprintf(di->lvm_uuid, PARAM_LVM_UUID_LEN, "%s", tg->value);

	if (tg->params_set & PARAM_FORCE)
		di->force = 1;

	if (t->create_virtdevice(hba, di) < 1)
		return(ERR_CREATE_VIRTDEV_FAILED);

	return(0);
}

/*
 * Called with se_hba_t->device_lock held.
 */
extern void se_clear_dev_ports (se_device_t *dev)
{
	se_hba_t *hba = dev->iscsi_hba;	
	se_lun_t *lun;
	iscsi_portal_group_t *tpg;
	se_port_t *sep, *sep_tmp;

	spin_lock(&dev->se_port_lock);
	list_for_each_entry_safe(sep, sep_tmp, &dev->dev_sep_list, sep_list) {
		spin_unlock(&dev->se_port_lock);
		spin_unlock(&hba->device_lock);

		lun = sep->sep_lun;
		tpg = sep->sep_tpg;
		spin_lock(&lun->lun_sep_lock);
		if (lun->lun_type_ptr == NULL) {
			spin_unlock(&lun->lun_sep_lock);
			continue;
		}
		spin_unlock(&lun->lun_sep_lock);

		LUN_OBJ_API(lun)->del_obj_from_lun(tpg, lun);
		
		spin_lock(&hba->device_lock);
		spin_lock(&dev->se_port_lock);
	}
	spin_unlock(&dev->se_port_lock);

	return;
}

/*	se_free_virtual_device():
 *
 *	Used for IBLOCK, RAMDISK, and FILEIO Transport Drivers.
 */
extern int se_free_virtual_device (se_device_t *dev, se_hba_t *hba)
{
	spin_lock(&hba->device_lock);
	se_clear_dev_ports(dev);
	spin_unlock(&hba->device_lock);

	se_release_device_for_hba(dev);
	
	return(0);
}

extern se_hba_t *core_get_hba_from_hbaid (
	struct iscsi_target *tg,
	se_dev_transport_info_t *dti,
	int add)
{
	int ret = 0;
	se_hba_t *hba;
	se_subsystem_api_t *t;
	
	if (!(tg->params_set & PARAM_HBA_ID)) {
		TRACE_ERROR("PARAM_HBA_ID not passed!\n");
		return(NULL);
	}
	
	if (dti->hba_id > (ISCSI_MAX_GLOBAL_HBAS-1)) {
		 TRACE_ERROR("Passed HBA ID: %d exceeds ISCSI_MAX_GLOBAL_HBAS-1: %d\n",
			dti->hba_id, ISCSI_MAX_GLOBAL_HBAS-1);
		 return(NULL);
	}
	hba = &iscsi_global->hba_list[dti->hba_id];

	if (!(hba->hba_status & HBA_STATUS_ACTIVE)) {
		TRACE_ERROR("iSCSI HBA ID: %d Status: [HBA,TPG_HBA]_NOT_ACTIVE,"
			" ignoring request\n", dti->hba_id);
		return(NULL);
	}
	
	if (!add)
		return(hba);
	
        t = (se_subsystem_api_t *)plugin_get_obj(PLUGIN_TYPE_TRANSPORT, hba->type, &ret);
	if (!t || (ret != 0))
                return(NULL);

	if ((ret = t->check_dev_params(hba, tg, dti)) < 0)
		return(NULL);
	
	return(hba);
}

extern void se_dev_start (se_device_t *dev)
{
	se_hba_t *hba = dev->iscsi_hba;
	
        spin_lock(&hba->device_lock);
	DEV_OBJ_API(dev)->inc_count(&dev->dev_obj);
        if (DEV_OBJ_API(dev)->check_count(&dev->dev_obj) == 1) {
		if (dev->dev_status & ISCSI_DEVICE_DEACTIVATED) {
			dev->dev_status &= ~ISCSI_DEVICE_DEACTIVATED;
			dev->dev_status |= ISCSI_DEVICE_ACTIVATED;
		} else if (dev->dev_status & ISCSI_DEVICE_OFFLINE_DEACTIVATED) {
			dev->dev_status &= ~ISCSI_DEVICE_OFFLINE_DEACTIVATED;
			dev->dev_status |= ISCSI_DEVICE_OFFLINE_ACTIVATED;	
		}
	}
        spin_unlock(&hba->device_lock);

	return;
}

extern void se_dev_stop (se_device_t *dev)
{
	se_hba_t *hba = dev->iscsi_hba;

	spin_lock(&hba->device_lock);
	DEV_OBJ_API(dev)->dec_count(&dev->dev_obj);
        if (DEV_OBJ_API(dev)->check_count(&dev->dev_obj) == 0) {
		if (dev->dev_status & ISCSI_DEVICE_ACTIVATED) {
			dev->dev_status &= ~ISCSI_DEVICE_ACTIVATED;
			dev->dev_status |= ISCSI_DEVICE_DEACTIVATED;
		} else if (dev->dev_status & ISCSI_DEVICE_OFFLINE_ACTIVATED) {
			dev->dev_status &= ~ISCSI_DEVICE_OFFLINE_ACTIVATED;
			dev->dev_status |= ISCSI_DEVICE_OFFLINE_DEACTIVATED;
		}
	}
	spin_unlock(&hba->device_lock);

	while (atomic_read(&hba->dev_mib_access_count)) 
		msleep(10);

	return;
}

/*	iscsi_dev_add_lun():
 *
 *
 */
extern int iscsi_dev_add_lun (
	iscsi_portal_group_t *tpg,
	se_hba_t *hba,
	se_device_t *dev,
	se_dev_transport_info_t *dti)
{
	se_lun_t *lun;
	se_fp_obj_t *fp;
	u32 lun_access = 0;
	int ret;
	
	if (DEV_OBJ_API(dev)->check_count(&dev->dev_access_obj) != 0) {
		TRACE_ERROR("Unable to export se_device_t while dev_access_obj: %d\n",
			DEV_OBJ_API(dev)->check_count(&dev->dev_access_obj));
		return(ERR_OBJ_ACCESS_COUNT);
	}
				
	if ((fp = DEV_OBJ_API(dev)->get_feature_obj(dev))) {
		if (fp->fp_mode != FP_MODE_SINGLE) {
			if (DEV_OBJ_API(dev)->check_count(&dev->dev_feature_obj)) {
				TRACE_ERROR("Unable to export se_device_t while"
					" dev_feature_obj: %d\n",
					DEV_OBJ_API(dev)->check_count(&dev->dev_feature_obj));
				return(ERR_OBJ_FEATURE_COUNT);
			}
		}
	}
	
	spin_lock(&hba->device_lock);
	if (dti->check_tcq) {
		if (transport_check_device_tcq(dev, dti->iscsi_lun,
				dti->queue_depth) < 0) {
			spin_unlock(&hba->device_lock);
			return(ERR_ADDLUN_CHECK_TCQ_FAILED);
		}
	}
	spin_unlock(&hba->device_lock);

	/*
	 * Now we claim exclusive access to the OS dependant block device.
	 */
	if (transport_generic_claim_phydevice(dev) < 0)
		return(ERR_BLOCKDEV_CLAIMED);
	
	if (!(lun = iscsi_tpg_pre_addlun(tpg, dti->iscsi_lun, &ret)))
		return(ret);

	if (DEV_OBJ_API(dev)->get_device_access((void *)dev) == 0)
		lun_access = ISCSI_LUNFLAGS_READ_ONLY;
	else
		lun_access = ISCSI_LUNFLAGS_READ_WRITE;
	
	if (iscsi_tpg_post_addlun(tpg, lun, ISCSI_LUN_TYPE_DEVICE, lun_access,
			      dev, dev->dev_obj_api) < 0)
		return(ERR_EXPORT_FAILED);

	PYXPRINT("iSCSI_TPG[%hu]_LUN[%u] - Activated iSCSI Logical Unit from"
		" iSCSI HBA: %u\n", tpg->tpgt, lun->iscsi_lun, hba->hba_id);
	
	/*
	 * Update LUN maps for dynamically added initiators when generate_node_acl
	 * is enabled.
	 */
	if (ISCSI_TPG_ATTRIB(tpg)->generate_node_acls) {
		iscsi_node_acl_t *acl;
		spin_lock_bh(&tpg->acl_node_lock);
		for (acl = tpg->acl_node_head; acl; acl = acl->next) {
			if (acl->nodeacl_flags & NAF_DYNAMIC_NODE_ACL) {	
				spin_unlock_bh(&tpg->acl_node_lock);
				iscsi_tpg_add_node_to_devs(acl, tpg);	
				spin_lock_bh(&tpg->acl_node_lock);
			}
		}
		spin_unlock_bh(&tpg->acl_node_lock);
	}

	return(0);
}

/*	iscsi_dev_del_lun():
 *
 *
 */
extern int iscsi_dev_del_lun (
	iscsi_portal_group_t *tpg,
	__u32 iscsi_lun)
{
	se_lun_t *lun;
	int ret = 0;

	if (!(lun = iscsi_tpg_pre_dellun(tpg, iscsi_lun, ISCSI_LUN_TYPE_DEVICE, &ret)))
		return(ret);

	iscsi_tpg_post_dellun(tpg, lun);

	PYXPRINT("iSCSI_TPG[%hu]_LUN[%u] - Deactivated iSCSI Logical Unit from"
		" device object\n", tpg->tpgt, iscsi_lun);
	
	return(0);
}

/*	iscsi_dev_get_lun():
 *
 *
 */
static se_lun_t *iscsi_dev_get_lun (iscsi_portal_group_t *tpg, u32 lun)
{
	se_lun_t *iscsi_lun;

	spin_lock(&tpg->tpg_lun_lock);
	if (lun > (ISCSI_MAX_LUNS_PER_TPG-1)) {
		TRACE_ERROR("iSCSI LUN: %u exceeds ISCSI_MAX_LUNS_PER_TPG-1:"
			" %u for Target Portal Group: %hu\n", lun,
			ISCSI_MAX_LUNS_PER_TPG-1, tpg->tpgt);
		spin_unlock(&tpg->tpg_lun_lock);
		return(NULL);
	}
	iscsi_lun = &tpg->tpg_lun_list[lun];

	if (iscsi_lun->lun_status != ISCSI_LUN_STATUS_ACTIVE) {
		TRACE_ERROR("iSCSI Logical Unit Number: %u is not active on"	
			" iSCSI Target Portal Group: %hu, ignoring request.\n",
			lun, tpg->tpgt);
		spin_unlock(&tpg->tpg_lun_lock);
		return(NULL);
	}
	spin_unlock(&tpg->tpg_lun_lock);
	
	return(iscsi_lun);
}

/*	iscsi_dev_add_initiator_node_lun_acl():
 *
 *
 */
extern int iscsi_dev_add_initiator_node_lun_acl (
	iscsi_portal_group_t *tpg,
	u32 lun,
	u32 mapped_lun,
	u32 lun_access,
	char *initiatorname)
{
	se_lun_t *iscsi_lun;
	se_lun_acl_t *acl;
	iscsi_node_acl_t *nacl;

	if (strlen(initiatorname) > 255) {
		TRACE_ERROR("iSCSI InitiatorName exceeds maximum size.\n"); 
		return(ERR_INITIATORNAME_TOO_LARGE);
	}
	
	if (!(iscsi_lun = iscsi_dev_get_lun(tpg, lun))) {
		TRACE_ERROR("iSCSI Logical Unit Number: %u is not active on"
			" iSCSI Target Portal Group: %hu, ignoring request.\n",
				lun, tpg->tpgt);
		return(ERR_LUN_NOT_ACTIVE);
	}

	if (!(nacl = iscsi_tpg_get_initiator_node_acl(tpg, initiatorname)))
		return(ERR_ADDLUNACL_NODE_ACL_MISSING);

	if (iscsi_check_device_list_access(mapped_lun, nacl) < 0) {
		TRACE_ERROR("ACL Entry already exists for iSCSI"
			" Initiator Node: %s for iSCSI Logout Unit Number: %u->%u"
			" on iSCSI Target Portal Group: %hu, ignoring request\n",
				initiatorname, lun, mapped_lun, tpg->tpgt);
		return(ERR_ADDLUNACL_ALREADY_EXISTS);
	}
	
	spin_lock(&iscsi_lun->lun_acl_lock);
	for (acl = iscsi_lun->lun_acl_head; acl; acl = acl->next) {
		if (!(strncmp(acl->initiatorname, initiatorname, strlen(initiatorname))) &&
		     (acl->mapped_lun == mapped_lun))
		break;
	}

	if (acl) {
		TRACE_ERROR("ACL Entry already exists for iSCSI"
			" Initiator Node: %s for iSCSI Logout Unit Number: %u->%u"
			" on iSCSI Target Portal Group: %hu, ignoring request\n",
				initiatorname, lun, mapped_lun, tpg->tpgt);
		spin_unlock(&iscsi_lun->lun_acl_lock);
		return(ERR_ADDLUNACL_ALREADY_EXISTS);
	}
	spin_unlock(&iscsi_lun->lun_acl_lock);

	if (!(acl = (se_lun_acl_t *) kmalloc(sizeof(se_lun_acl_t), GFP_KERNEL))) {	
		TRACE_ERROR("Unable to allocate memory for se_lun_acl_t.\n");
		return(ERR_NO_MEMORY);
	}
	memset(acl, 0, sizeof(se_lun_acl_t));

	acl->iscsi_lun = iscsi_lun;
	acl->mapped_lun = mapped_lun;
	snprintf(acl->initiatorname, ISCSI_IQN_LEN, "%s", initiatorname);

	spin_lock(&iscsi_lun->lun_acl_lock);
	ADD_ENTRY_TO_LIST(acl, iscsi_lun->lun_acl_head, iscsi_lun->lun_acl_tail);
	spin_unlock(&iscsi_lun->lun_acl_lock);

	if ((iscsi_lun->lun_access & ISCSI_LUNFLAGS_READ_ONLY) &&
	    (lun_access & ISCSI_LUNFLAGS_READ_WRITE))
		lun_access = ISCSI_LUNFLAGS_READ_ONLY;
	
	iscsi_update_device_list_for_node(iscsi_lun, mapped_lun, lun_access, nacl, tpg, 1);

	PYXPRINT("iSCSI_TPG[%hu]_LUN[%u->%u] - Added %s ACL for iSCSI"
		" InitiatorNode: %s\n", tpg->tpgt, lun, mapped_lun,
		(lun_access & ISCSI_LUNFLAGS_READ_WRITE) ? "RW" : "RO",
			initiatorname);
	
	return(0);
}

/*	iscsi_dev_del_initiator_node_lun_acl():
 *
 *
 */
extern int iscsi_dev_del_initiator_node_lun_acl (
	iscsi_portal_group_t *tpg,
	u32 lun,
	u32 mapped_lun,
	char *initiatorname)
{
	se_lun_t *iscsi_lun;
	se_lun_acl_t *acl;
	iscsi_node_acl_t *nacl;

	if (strlen(initiatorname) > 255) {
		TRACE_ERROR("iSCSI InitiatorName exceeds maximum size.\n"); 
		return(ERR_INITIATORNAME_TOO_LARGE);
	}
	
	if (!(iscsi_lun = iscsi_dev_get_lun(tpg, lun))) {
		TRACE_ERROR("iSCSI Logical Unit Number: %u is not active on"
			" iSCSI Target Portal Group: %hu, ignoring request.\n",
				lun, tpg->tpgt);
		return(ERR_LUN_NOT_ACTIVE);
	}

	if (!(nacl = iscsi_tpg_get_initiator_node_acl(tpg, initiatorname)))
		return(ERR_DELLUNACL_NODE_ACL_MISSING);

	spin_lock(&iscsi_lun->lun_acl_lock);
	for (acl = iscsi_lun->lun_acl_head; acl; acl = acl->next) {
		if (!(strncmp(acl->initiatorname, initiatorname, strlen(initiatorname))) &&
		      (acl->mapped_lun == mapped_lun))
			break;
	}

	if (!acl) {
		TRACE_ERROR("Unable to locate LUN ACL for InitiatorName: %s on"
			" iSCSI LUN: %u on iSCSI TPG: %hu.\n", initiatorname,
				lun, tpg->tpgt);
		spin_unlock(&iscsi_lun->lun_acl_lock);
		return(ERR_DELLUNACL_DOES_NOT_EXIST);
	}

	REMOVE_ENTRY_FROM_LIST(acl, iscsi_lun->lun_acl_head, iscsi_lun->lun_acl_tail);
	spin_unlock(&iscsi_lun->lun_acl_lock);
	
	iscsi_update_device_list_for_node(iscsi_lun, mapped_lun,
		ISCSI_LUNFLAGS_NO_ACCESS, nacl, tpg, 0);
	
	kfree(acl);
	
	PYXPRINT("iSCSI_TPG[%hu]_LUN[%u] - Removed ACL for iSCSI"
		" InitiatorNode: %s\n", tpg->tpgt, lun, initiatorname);
	
	return(0);
}

extern int iscsi_dev_set_initiator_node_lun_access (
	iscsi_portal_group_t *tpg,
	u32 mapped_lun,
	u32 lun_access,
	char *initiatorname)
{
	int ret;
	iscsi_node_acl_t *nacl;
	
	if (strlen(initiatorname) > 255) {
		TRACE_ERROR("iSCSI InitiatorName exceeds maximum size.\n");
		return(ERR_INITIATORNAME_TOO_LARGE);
	}

	if (mapped_lun > (ISCSI_MAX_LUNS_PER_TPG-1)) {
		TRACE_ERROR("iSCSI MAPPED LUN: %u exceeds ISCSI_MAX_LUNS_PER_TPG-1:"
			" %u for Target Portal Group: %hu\n", mapped_lun,
			ISCSI_MAX_LUNS_PER_TPG-1, tpg->tpgt);
		return(ERR_LUN_NOT_ACTIVE);
	}
	
	if (!(nacl = iscsi_tpg_get_initiator_node_acl(tpg, initiatorname)))
		 return(ERR_DELLUNACL_NODE_ACL_MISSING);

	ret = iscsi_update_device_list_access(mapped_lun, lun_access, nacl);

	return(ret);
}
