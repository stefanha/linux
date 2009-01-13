/*********************************************************************************
 * Filename:  iscsi_target_device.c
 *
 * This file contains the iSCSI Virtual Device and Disk Transport
 * agnostic related functions.
 *
 * Copyright (c) 2003, 2004, 2005 PyX Technologies, Inc.
 * Copyright (c) 2005-2006 SBE, Inc.  All Rights Reserved.
 * Copyright (c) 2007 Rising Tide Software, Inc.
 * Copyright (c) 2008 Linux-iSCSI.org
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
#include <target_core_base.h>
#include <iscsi_target_error.h>
#include <iscsi_target_device.h>
#include <target_core_device.h>
#include <target_core_hba.h>
#include <iscsi_target_tpg.h>
#include <target_core_transport.h>
#include <iscsi_target_util.h>

#include <target_core_plugin.h>
#include <target_core_seobj.h>

#undef ISCSI_TARGET_DEVICE_C

extern se_global_t *iscsi_global;
extern __u32 iscsi_unpack_lun (unsigned char *);

/*	iscsi_get_lun():
 *
 *
 */
//#warning FIXME v2.8: Breakage in iscsi_get_lun() for TMRs
extern se_lun_t *iscsi_get_lun (
	iscsi_conn_t *conn,
	u64 iscsi_lun)
{
	se_dev_entry_t *deve;
	se_lun_t *lun = NULL;
	iscsi_portal_group_t *tpg = conn->tpg;
	iscsi_session_t *sess = SESS(conn);
	u32 unpacked_lun;

	unpacked_lun = iscsi_unpack_lun((unsigned char *)&iscsi_lun);
	if (unpacked_lun > (ISCSI_MAX_LUNS_PER_TPG-1)) {
		TRACE_ERROR("iSCSI LUN: %u exceeds ISCSI_MAX_LUNS_PER_TPG-1:"
			" %u for Target Portal Group: %hu\n", unpacked_lun,
			ISCSI_MAX_LUNS_PER_TPG-1, tpg->tpgt);
		return(NULL);
	}
#if 0
	spin_lock_bh(&SESS_NODE_ACL(sess)->device_list_lock);
	deve = &SESS_NODE_ACL(sess)->device_list[unpacked_lun];
	if (deve->lun_flags & TRANSPORT_LUNFLAGS_INITIATOR_ACCESS) {
#if 0
		TRACE_ERROR("deve->deve_cmds incremented to %d\n", deve->deve_cmds);
#endif
		iscsi_lun = deve->iscsi_lun;
	}
	spin_unlock_bh(&SESS_NODE_ACL(sess)->device_list_lock);
#endif
	if (!lun) {
		TRACE_ERROR("Unable to find Active iSCSI LUN: 0x%08x on"
			" iSCSI TPG: %hu\n", unpacked_lun, tpg->tpgt);
		return(NULL);
	}

	return(lun);
}

/*	iscsi_get_lun_for_cmd():
 *	
 *	Returns (0) on success
 * 	Returns (< 0) on failure
 */
extern int iscsi_get_lun_for_cmd (
	iscsi_cmd_t *cmd,
	unsigned char *cdb,
	u64 lun)
{
	iscsi_conn_t *conn = CONN(cmd);
	iscsi_portal_group_t *tpg = ISCSI_TPG_C(conn);
	u32 unpacked_lun;
	int ret;

	unpacked_lun = iscsi_unpack_lun((unsigned char *)&lun);
	if (unpacked_lun > (ISCSI_MAX_LUNS_PER_TPG-1)) {
		TRACE_ERROR("iSCSI LUN: %u exceeds ISCSI_MAX_LUNS_PER_TPG-1:"
			" %u for Target Portal Group: %hu\n", unpacked_lun,
			ISCSI_MAX_LUNS_PER_TPG-1, tpg->tpgt);
		return(-1);
	}

	return(transport_get_lun_for_cmd(SE_CMD(cmd), cdb, unpacked_lun));
}

/*	iscsi_determine_maxcmdsn():
 * 
 *
 */
extern void iscsi_determine_maxcmdsn (iscsi_session_t *sess)
{
	se_node_acl_t *se_nacl;

	/*
	 * This is a discovery session, the single queue slot was already assigned in
	 * iscsi_login_zero_tsih().  Since only Logout and Text Opcodes are allowed
	 * during discovery we do not have to worry about the HBA's queue depth here.
	 */
	if (SESS_OPS(sess)->SessionType)
		return;	

	se_nacl = sess->se_sess->se_node_acl;

	/*
	 * This is a normal session, set the Session's CmdSN window to the
	 * se_node_acl_t->queue_depth.  The value in se_node_acl_t->queue_depth
	 * has already been validated as a legal value in
	 * core_set_queue_depth_for_node().
	 */
	sess->cmdsn_window = se_nacl->queue_depth;
	sess->max_cmd_sn = (sess->max_cmd_sn + se_nacl->queue_depth) - 1;

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
