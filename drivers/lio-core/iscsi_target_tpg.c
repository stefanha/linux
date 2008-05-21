/*********************************************************************************
 * Filename:  iscsi_target_tpg.c
 *
 * This file contains iSCSI Target Portal Group related functions.
 *
 * Copyright (c) 2002, 2003, 2004, 2005 PyX Technologies, Inc.
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


#define ISCSI_TARGET_TPG_C

#include <linux/net.h>
#include <linux/string.h>
#include <linux/timer.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/smp_lock.h>
#include <linux/in.h>
#include <net/sock.h>
#include <net/tcp.h>
#include <scsi/scsi.h>
#include <scsi/scsi_cmnd.h>

#include <iscsi_linux_os.h>
#include <iscsi_linux_defs.h>

#include <iscsi_lists.h>
#include <iscsi_debug.h>
#include <iscsi_protocol.h>
#include <iscsi_target_core.h>
#include <iscsi_target_ioctl.h>
#include <iscsi_target_ioctl_defs.h>
#include <iscsi_target_device.h>
#include <iscsi_target_erl0.h>
#include <iscsi_target_error.h>
#include <iscsi_target_hba.h>
#include <iscsi_target_linux_proc.h>
#include <iscsi_target_login.h>
#include <iscsi_target_nodeattrib.h>
#include <iscsi_target_tpg.h>
#include <iscsi_target_transport.h>
#include <iscsi_target_util.h>
#include <iscsi_target.h>
#include <iscsi_parameters.h>

#include <iscsi_target_plugin.h>
#include <iscsi_target_seobj.h>

#undef ISCSI_TARGET_TPG_C

extern iscsi_global_t *iscsi_global;

extern int iscsi_close_session (iscsi_session_t *); 
extern int iscsi_free_session (iscsi_session_t *);
extern int iscsi_stop_session (iscsi_session_t *, int, int);
extern int iscsi_release_sessions_for_tpg (iscsi_portal_group_t *, int);
static int iscsi_ta_set_authentication (iscsi_portal_group_t *, __u32);

/*	init_iscsi_portal_groups():
 *
 *
 */
extern void init_iscsi_portal_groups (iscsi_tiqn_t *tiqn)
{
	int i;
	iscsi_portal_group_t *tpg = NULL;

	for (i = 0; i < ISCSI_MAX_TPGS; i++) {
		tpg = &tiqn->tiqn_tpg_list[i];

		tpg->tpgt = i;
		tpg->tpg_state = TPG_STATE_FREE;
		tpg->tpg_tiqn = tiqn;
		init_MUTEX(&tpg->tpg_access_sem);
		spin_lock_init(&tpg->tpg_state_lock);
	}

	return;
}

static void iscsi_set_default_tpg_attribs (iscsi_portal_group_t *);

extern int core_load_discovery_tpg (void)
{
	iscsi_param_t *param;
	iscsi_portal_group_t *tpg;

	if (!(tpg = kmalloc(sizeof(iscsi_portal_group_t), GFP_KERNEL))) {
		TRACE_ERROR("Unable to allocate iscsi_portal_group_t\n");
		return(-1);
	}
	memset(tpg, 0, sizeof(iscsi_portal_group_t));

	tpg->sid        = 1; /* First Assigned iSBE Session ID */
	INIT_LIST_HEAD(&tpg->tpg_gnp_list);
	init_MUTEX(&tpg->tpg_access_sem);
	spin_lock_init(&tpg->tpg_state_lock);
	init_MUTEX(&tpg->np_login_sem);
	spin_lock_init(&tpg->acl_node_lock);
	spin_lock_init(&tpg->session_lock);
	spin_lock_init(&tpg->tpg_lun_lock);
	spin_lock_init(&tpg->tpg_np_lock);

	iscsi_set_default_tpg_attribs(tpg);

	if (iscsi_create_default_params(&tpg->param_list) < 0)
		goto out;

#warning FIXME: Discovery Session + Authentication breakage
#if 1
	if (!(param = iscsi_find_param_from_key(AUTHMETHOD, tpg->param_list))) 
		goto out;

	if (iscsi_update_param_value(param, NONE) < 0)
		goto out;

	tpg->tpg_attrib.authentication = 0;
#endif
	spin_lock(&tpg->tpg_state_lock);
	tpg->tpg_state  = TPG_STATE_ACTIVE;
	spin_unlock(&tpg->tpg_state_lock);

	iscsi_global->discovery_tpg = tpg;
	PYXPRINT("CORE[0] - Allocated Discovery TPG\n");

	return(0);
out:
	kfree(tpg);
	return(-1);
}

extern void core_release_discovery_tpg (void)
{
	kfree(iscsi_global->discovery_tpg);
	iscsi_global->discovery_tpg = NULL;

	return;
}

extern iscsi_portal_group_t *core_get_tpg_from_np (
	iscsi_tiqn_t *tiqn,
	iscsi_np_t *np)
{
	int i;
	iscsi_portal_group_t *tpg = NULL;
	iscsi_tpg_np_t *tpg_np;

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
			if (tpg_np->tpg_np == np) {
				spin_unlock(&tpg->tpg_np_lock);
				spin_unlock(&tiqn->tiqn_tpg_lock);
				return(tpg);
			}
		}
		spin_unlock(&tpg->tpg_np_lock);
	}
	spin_unlock(&tiqn->tiqn_tpg_lock);

	return(NULL);
}

/*	iscsi_get_tpg_from_tpgt():
 *
 *
 */
extern iscsi_portal_group_t *iscsi_get_tpg_from_tpgt (
	iscsi_tiqn_t *tiqn,
	__u16 tpgt,
	int addtpg)
{
	int i;
	iscsi_portal_group_t *tpg = NULL;

	spin_lock(&tiqn->tiqn_tpg_lock);
	for (i = 0; i < ISCSI_MAX_TPGS; i++) {
		tpg = &tiqn->tiqn_tpg_list[i];

		if (tpg->tpgt != tpgt)
			continue;

		spin_lock(&tpg->tpg_state_lock);
		if ((tpg->tpg_state == TPG_STATE_FREE) && !addtpg) {
			spin_unlock(&tpg->tpg_state_lock);
			break;
		}
		spin_unlock(&tpg->tpg_state_lock);
		spin_unlock(&tiqn->tiqn_tpg_lock);

		down_interruptible(&tpg->tpg_access_sem);
		return((signal_pending(current)) ? NULL : tpg);
	}
	spin_unlock(&tiqn->tiqn_tpg_lock);
	
	TRACE(TRACE_ISCSI, "CORE[%s] - Unable to locate iSCSI target"
		" portal group with TPGT: %hu, ignoring request.\n",
			tiqn->tiqn, tpgt);
	
	return(NULL);
}

/*	iscsi_put_tpg():
 *
 *
 */
extern void iscsi_put_tpg (iscsi_portal_group_t *tpg)
{
	up(&tpg->tpg_access_sem);
	return;
}

static void iscsi_clear_tpg_np_login_thread (
	iscsi_tpg_np_t *tpg_np,
	iscsi_portal_group_t *tpg)
{
	if (!tpg_np->tpg_np) {
		TRACE_ERROR("iscsi_tpg_np_t->tpg_np is NULL!\n");
		return;
	}

	/*
	 * The reset operation need only be performed when the
	 * passed iscsi_portal_group_t has a login in progress
	 * to one of the network portals.
	 */
	spin_lock_bh(&tpg_np->tpg_np->np_thread_lock);
	if (tpg_np->tpg_np->np_login_tpg != tpg) {
		spin_unlock_bh(&tpg_np->tpg_np->np_thread_lock);
		return;
	} 
	spin_unlock_bh(&tpg_np->tpg_np->np_thread_lock);

	core_reset_np_thread(tpg_np->tpg_np);

	return;
}

/*	iscsi_clear_tpg_np_login_threads():
 *
 *
 */
extern void iscsi_clear_tpg_np_login_threads (
	iscsi_portal_group_t *tpg)
{
	iscsi_tpg_np_t *tpg_np;

	spin_lock(&tpg->tpg_np_lock);
	list_for_each_entry(tpg_np, &tpg->tpg_gnp_list, tpg_np_list) {
		if (!tpg_np->tpg_np) {
			TRACE_ERROR("iscsi_tpg_np_t->tpg_np is NULL!\n");
			continue;
		}
		spin_unlock(&tpg->tpg_np_lock);
		iscsi_clear_tpg_np_login_thread(tpg_np, tpg);
		spin_lock(&tpg->tpg_np_lock);
	}
	spin_unlock(&tpg->tpg_np_lock);

	return;
}

/*	iscsi_clear_initiator_node_from_tpg():
 *
 *
 */
static void iscsi_clear_initiator_node_from_tpg (
	iscsi_node_acl_t *nacl,
	iscsi_portal_group_t *tpg)
{
	int i;
	iscsi_dev_entry_t *deve;
	iscsi_lun_t *lun;
	iscsi_lun_acl_t *acl;

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

		lun = deve->iscsi_lun;
		spin_unlock_bh(&nacl->device_list_lock);
		iscsi_update_device_list_for_node(lun, deve->mapped_lun,
			ISCSI_LUNFLAGS_NO_ACCESS, nacl, tpg, 0);

		spin_lock(&lun->lun_acl_lock);
		for (acl = lun->lun_acl_head; acl; acl = acl->next) {
			if (!(strncmp(acl->initiatorname, nacl->initiatorname, strlen(nacl->initiatorname))) &&
			     (acl->mapped_lun == deve->mapped_lun))
				break;
		}

		if (!acl) {
			TRACE_ERROR("Unable to locate iscsi_lun_acl_t for %s, mapped_lun: %u\n",
				nacl->initiatorname, deve->mapped_lun);
			spin_unlock(&lun->lun_acl_lock);
			spin_lock_bh(&nacl->device_list_lock);
			continue;
		}
		
		REMOVE_ENTRY_FROM_LIST(acl, lun->lun_acl_head, lun->lun_acl_tail);
		spin_unlock(&lun->lun_acl_lock);

		spin_lock_bh(&nacl->device_list_lock);
		kfree(acl);
        }
	spin_unlock_bh(&nacl->device_list_lock);

	return;
}

/*	__iscsi_tpg_get_initiator_node_acl():
 *
 *	spin_lock_bh(&tpg->acl_node_lock); must be held when calling
 */
extern iscsi_node_acl_t *__iscsi_tpg_get_initiator_node_acl (
	iscsi_portal_group_t *tpg,
	unsigned char *initiatorname)
{
	iscsi_node_acl_t *acl;
	
	for (acl = tpg->acl_node_head; acl; acl = acl->next) {
		if (!strncmp(acl->initiatorname, initiatorname,
				strlen(initiatorname)))
			return(acl);
	}

	return(NULL);
}

/*	iscsi_tpg_get_initiator_node_acl():
 *
 *
 */     
extern iscsi_node_acl_t *iscsi_tpg_get_initiator_node_acl (
	iscsi_portal_group_t *tpg,
	unsigned char *initiatorname)
{               
	iscsi_node_acl_t *acl;
		                
	spin_lock_bh(&tpg->acl_node_lock);
	for (acl = tpg->acl_node_head; acl; acl = acl->next) {
		if (!strncmp(acl->initiatorname, initiatorname, strlen(initiatorname)) &&
		   (!(acl->nodeacl_flags & NAF_DYNAMIC_NODE_ACL))) {
			spin_unlock_bh(&tpg->acl_node_lock);
			return(acl);
		}
	}
	spin_unlock_bh(&tpg->acl_node_lock);

	return(NULL);
}

/*	iscsi_tpg_add_node_to_devs():
 *
 *
 */
extern void iscsi_tpg_add_node_to_devs (
	iscsi_node_acl_t *acl,
	iscsi_portal_group_t *tpg)
{
	int i = 0;
	u32 lun_access = 0;
	iscsi_lun_t *lun;

	spin_lock(&tpg->tpg_lun_lock);
	for (i = 0; i < ISCSI_MAX_LUNS_PER_TPG; i++) {
		lun = &tpg->tpg_lun_list[i];
		if (lun->lun_status != ISCSI_LUN_STATUS_ACTIVE)
			continue;

		spin_unlock(&tpg->tpg_lun_lock);

		/*
		 * By default, demo_mode_lun_access is ZERO, or READ_ONLY;
		 */
		if (ISCSI_TPG_ATTRIB(tpg)->demo_mode_lun_access) {
			if (LUN_OBJ_API(lun)->get_device_access) {
				if (LUN_OBJ_API(lun)->get_device_access(lun->lun_type_ptr) == 0)
					lun_access = ISCSI_LUNFLAGS_READ_ONLY;
	                        else
                	                lun_access = ISCSI_LUNFLAGS_READ_WRITE;
			} else
				lun_access = ISCSI_LUNFLAGS_READ_WRITE;
		} else {
                        /*
                         * Allow only optical drives to issue R/W in default RO demo mode.
                         */
                        if (LUN_OBJ_API(lun)->get_device_type(lun->lun_type_ptr) == TYPE_DISK)
                                lun_access = ISCSI_LUNFLAGS_READ_ONLY;
			else
				lun_access = ISCSI_LUNFLAGS_READ_WRITE;
		}

		PYXPRINT("TPG[%hu]_LUN[%u] - Adding %s access for LUN in Demo Mode\n",
			tpg->tpgt, lun->iscsi_lun,
			(lun_access == ISCSI_LUNFLAGS_READ_WRITE) ?
			"READ-WRITE" : "READ-ONLY");

		iscsi_update_device_list_for_node(lun, lun->iscsi_lun,
				lun_access, acl, tpg, 1);
		spin_lock(&tpg->tpg_lun_lock);
	}
	spin_unlock(&tpg->tpg_lun_lock);

	return;
}

/*	iscsi_tpg_check_initiator_node_acl()
 *
 *
 */
extern iscsi_node_acl_t *iscsi_tpg_check_initiator_node_acl (
	iscsi_portal_group_t *tpg,
	unsigned char *initiatorname)
{
	iscsi_node_acl_t *acl;

	if ((acl = iscsi_tpg_get_initiator_node_acl(tpg, initiatorname)))
		return(acl);

	if (!ISCSI_TPG_ATTRIB(tpg)->generate_node_acls)
		return(NULL);

	if (!(acl = (iscsi_node_acl_t *) kmalloc(
			sizeof(iscsi_node_acl_t), GFP_KERNEL))) {
		TRACE_ERROR("Unable to allocate memory for iscsi_node_acl_t.\n");
		return(NULL);
	}
	memset((void *)acl, 0, sizeof(iscsi_node_acl_t));

	spin_lock_init(&acl->device_list_lock);
	acl->queue_depth = ISCSI_TPG_ATTRIB(tpg)->default_queue_depth;
	snprintf(acl->initiatorname, ISCSI_IQN_LEN, "%s", initiatorname);
	acl->tpg = tpg;
#ifdef SNMP_SUPPORT
        acl->acl_index = get_new_index(SCSI_AUTH_INTR_INDEX);
        spin_lock_init(&acl->stats_lock);
#endif /* SNMP_SUPPORT */
	acl->nodeacl_flags |= NAF_DYNAMIC_NODE_ACL;

	iscsi_set_default_node_attribues(acl);

	if (iscsi_create_device_list_for_node(acl, tpg)  < 0) {
		kfree(acl);
		return(NULL);
	}

	if (iscsi_set_queue_depth_for_node(tpg, acl) < 0) {
		iscsi_free_device_list_for_node(acl, tpg);
		kfree(acl);
		return(NULL);
	}

	iscsi_tpg_add_node_to_devs(acl, tpg);

	spin_lock_bh(&tpg->acl_node_lock);
	ADD_ENTRY_TO_LIST(acl, tpg->acl_node_head, tpg->acl_node_tail);
	tpg->num_node_acls++;
	spin_unlock_bh(&tpg->acl_node_lock);

	PYXPRINT("iSCSI_TPG[%hu] - Added DYNAMIC ACL with TCQ Depth: %d for iSCSI"
		" Initiator Node: %s\n", tpg->tpgt, acl->queue_depth, initiatorname);

	return(acl);
}

/*	iscsi_tpg_dump_params():
 *
 *
 */
extern void iscsi_tpg_dump_params (iscsi_portal_group_t *tpg)
{
	iscsi_print_params(tpg->param_list);
}

/*	iscsi_tpg_free_network_portals():
 *
 *
 */
static void iscsi_tpg_free_network_portals (iscsi_portal_group_t *tpg)
{
	iscsi_np_t *np;
	iscsi_tpg_np_t *tpg_np, *tpg_np_t;
	unsigned char buf_ipv4[IPV4_BUF_SIZE], *ip;
	
	spin_lock(&tpg->tpg_np_lock);
	list_for_each_entry_safe(tpg_np, tpg_np_t, &tpg->tpg_gnp_list, tpg_np_list) {
		np = tpg_np->tpg_np;
		list_del(&tpg_np->tpg_np_list);
		tpg->num_tpg_nps--;

		if (np->np_net_size == IPV6_ADDRESS_SPACE)
			ip = &np->np_ipv6[0];
		else {
			memset(buf_ipv4, 0, IPV4_BUF_SIZE);
			iscsi_ntoa2(buf_ipv4, np->np_ipv4);
			ip = &buf_ipv4[0];
		}

		PYXPRINT("CORE[%s] - Removed Network Portal: %s:%hu,%hu on %s on"
			" network device: %s\n", tpg->tpg_tiqn->tiqn, ip,
			np->np_port, tpg->tpgt, (np->np_network_transport == ISCSI_TCP) ?
			"TCP" : "SCTP",  (strlen(np->np_net_dev)) ?
			(char *)np->np_net_dev : "None");

		tpg_np->tpg_np = NULL;
		kfree(tpg_np);
		spin_unlock(&tpg->tpg_np_lock);

		spin_lock(&np->np_state_lock);
		np->np_exports--;
		PYXPRINT("CORE[%s]_TPG[%hu] - Decremented np_exports to %u\n",
			tpg->tpg_tiqn->tiqn, tpg->tpgt, np->np_exports);
		spin_unlock(&np->np_state_lock);

		spin_lock(&tpg->tpg_np_lock);
	}
	spin_unlock(&tpg->tpg_np_lock);

	return;
}

/*	iscsi_tpg_free_portal_group_node_acls():
 *
 *
 */
static void iscsi_tpg_free_portal_group_node_acls (iscsi_portal_group_t *tpg)
{
	iscsi_node_acl_t *acl = NULL, *acl_next = NULL;

	spin_lock_bh(&tpg->acl_node_lock);
	acl = tpg->acl_node_head;
	while (acl) {
		acl_next = acl->next;
		kfree(acl);
		tpg->num_node_acls--;
		acl = acl_next;
	}
	tpg->acl_node_head = tpg->acl_node_tail = NULL;
	spin_unlock_bh(&tpg->acl_node_lock);

	return;
}	

/*	iscsi_set_default_tpg_attribs():
 *
 *
 */
static void iscsi_set_default_tpg_attribs (iscsi_portal_group_t *tpg)
{
	iscsi_tpg_attrib_t *a = &tpg->tpg_attrib;
	
	a->authentication = TA_AUTHENTICATION;
	a->login_timeout = TA_LOGIN_TIMEOUT;
	a->netif_timeout = TA_NETIF_TIMEOUT;
	a->default_queue_depth = TA_DEFAULT_QUEUE_DEPTH;
	a->generate_node_acls = TA_GENERATE_NODE_ACLS;
	a->cache_dynamic_acls = TA_CACHE_DYNAMIC_ACLS;
	a->demo_mode_lun_access = TA_DEMO_MODE_LUN_ACCESS;
		
	return;
}

extern int iscsi_tpg_persistent_reservation_check (iscsi_cmd_t *cmd)
{
	int ret;
	iscsi_conn_t *conn = CONN(cmd);
	iscsi_lun_t *lun = ISCSI_LUN(cmd);

	if (!CONN(cmd))
		return(0);

	spin_lock(&lun->lun_reservation_lock);
	if (!lun->lun_reserved_node_acl) {
		spin_unlock(&lun->lun_reservation_lock);
		return(0);
	}
	ret = (lun->lun_reserved_node_acl != SESS(conn)->node_acl) ? -1 : 0;
	spin_unlock(&lun->lun_reservation_lock);

	return(ret);
}

extern int iscsi_tpg_persistent_reservation_release (iscsi_cmd_t *cmd)
{
	iscsi_conn_t *conn = CONN(cmd);
	iscsi_lun_t *lun = ISCSI_LUN(cmd);

	if (!CONN(cmd)) {
		TRACE_ERROR("iscsi_conn_t is NULL!\n");
		return(5);
	}
	
	spin_lock(&lun->lun_reservation_lock);
	if (!lun->lun_reserved_node_acl) {
		spin_unlock(&lun->lun_reservation_lock);
		return(0);
	}

	if (lun->lun_reserved_node_acl != SESS(conn)->node_acl) {
		spin_unlock(&lun->lun_reservation_lock);
		return(0);
	}
	lun->lun_reserved_node_acl = NULL;
	PYXPRINT("Released TPG LUN: %u -> MAPPED LUN: %u for %s\n", ISCSI_LUN(cmd)->iscsi_lun,
		cmd->iscsi_deve->mapped_lun, SESS(conn)->node_acl->initiatorname);
	spin_unlock(&lun->lun_reservation_lock);

	return(0);
}

extern int iscsi_tpg_persistent_reservation_reserve (iscsi_cmd_t *cmd)
{
	iscsi_conn_t *conn = CONN(cmd);
        iscsi_lun_t *lun = ISCSI_LUN(cmd);

	if (!CONN(cmd)) {
		TRACE_ERROR("iscsi_conn_t is NULL!\n");
		return(5);
	}
	
	if ((T_TASK(cmd)->t_task_cdb[1] & 0x01) && (T_TASK(cmd)->t_task_cdb[1] & 0x02)) {
		TRACE_ERROR("LongIO and Obselete Bits set, returning ILLEGAL_REQUEST\n");
		return(7);
	}
	
	spin_lock(&lun->lun_reservation_lock);
	if (lun->lun_reserved_node_acl && (lun->lun_reserved_node_acl != SESS(conn)->node_acl)) {
		TRACE_ERROR("RESERVATION CONFLIFT\n");
		TRACE_ERROR("Original reserver TPG LUN: %u %s\n", lun->iscsi_lun,
				lun->lun_reserved_node_acl->initiatorname);
		TRACE_ERROR("Current attempt - TPG LUN: %u -> MAPPED LUN: %u from %s \n",
				lun->iscsi_lun, cmd->iscsi_deve->mapped_lun,
				SESS(conn)->node_acl->initiatorname);
		spin_unlock(&lun->lun_reservation_lock);
		return(5);
	}
		
	lun->lun_reserved_node_acl = SESS(conn)->node_acl;
	PYXPRINT("Reserved TPG LUN: %u -> MAPPED LUN: %u for %s\n", ISCSI_LUN(cmd)->iscsi_lun,
		cmd->iscsi_deve->mapped_lun, SESS(conn)->node_acl->initiatorname);
	spin_unlock(&lun->lun_reservation_lock);
	
        return(0);
}

/*	iscsi_tpg_add_portal_group():
 *
 *
 */
extern int iscsi_tpg_add_portal_group (iscsi_tiqn_t *tiqn, iscsi_portal_group_t *tpg)
{
	int i;
	iscsi_lun_t *lun;
	
	if (tpg->tpg_state != TPG_STATE_FREE) {
		TRACE_ERROR("Unable to add iSCSI Target Portal Group: %d while"
			" not in TPG_STATE_FREE state.\n", tpg->tpgt);
		return(ERR_ADDTPG_ALREADY_EXISTS);
	}

	iscsi_set_default_tpg_attribs(tpg);

	if (!(tpg->tpg_lun_list = kmalloc((sizeof(iscsi_lun_t) * ISCSI_MAX_LUNS_PER_TPG), GFP_KERNEL))) {
		TRACE_ERROR("Unable to allocate memory for tpg->tpg_lun_list\n");
		goto err_out;
	}
	memset(tpg->tpg_lun_list, 0, (sizeof(iscsi_lun_t) * ISCSI_MAX_LUNS_PER_TPG));

	if (iscsi_create_default_params(&tpg->param_list) < 0)
		goto err_out;

	if (iscsi_OS_register_info_handlers(tpg->tpgt) < 0)
		goto err_out;
	
	tpg->sid	= 1; /* First Assigned iSBE Session ID */
	INIT_LIST_HEAD(&tpg->tpg_gnp_list);
	init_MUTEX(&tpg->np_login_sem);
	spin_lock_init(&tpg->acl_node_lock);
	spin_lock_init(&tpg->session_lock);
	spin_lock_init(&tpg->tpg_lun_lock);
	spin_lock_init(&tpg->tpg_np_lock);

	for (i = 0; i < ISCSI_MAX_LUNS_PER_TPG; i++) {
		lun = &tpg->tpg_lun_list[i];
		lun->iscsi_lun = i;
		lun->lun_type_ptr = NULL;
		lun->persistent_reservation_check = &iscsi_tpg_persistent_reservation_check;
		lun->persistent_reservation_release = &iscsi_tpg_persistent_reservation_release;
		lun->persistent_reservation_reserve = &iscsi_tpg_persistent_reservation_reserve;
		lun->lun_status = ISCSI_LUN_STATUS_FREE;
		spin_lock_init(&lun->lun_acl_lock);
		spin_lock_init(&lun->lun_cmd_lock);
		spin_lock_init(&lun->lun_reservation_lock);
		spin_lock_init(&lun->lun_sep_lock);
	}

	spin_lock(&tpg->tpg_state_lock);
	tpg->tpg_state	= TPG_STATE_INACTIVE;
	spin_unlock(&tpg->tpg_state_lock);

	spin_lock(&tiqn->tiqn_tpg_lock);
	tiqn->tiqn_ntpgs++;
	PYXPRINT("CORE[%s]_TPG[%hu] - Added iSCSI Target Portal Group\n",
			tiqn->tiqn, tpg->tpgt);
	spin_unlock(&tiqn->tiqn_tpg_lock);

	return(0);

err_out:
	kfree(tpg->tpg_lun_list);
	if (tpg->param_list) {
		iscsi_release_param_list(tpg->param_list);
		tpg->param_list = NULL;
	}
	if (tpg)
		kfree(tpg);
	return(ERR_NO_MEMORY);
}	

static void iscsi_tpg_clear_object_luns (iscsi_portal_group_t *tpg)
{
	int i, ret;
	iscsi_lun_t *lun;

	spin_lock(&tpg->tpg_lun_lock);
	for (i = 0; i < ISCSI_MAX_LUNS_PER_TPG; i++) {
		lun = &tpg->tpg_lun_list[i];

		if ((lun->lun_status != ISCSI_LUN_STATUS_ACTIVE) ||
		    (lun->lun_type_ptr == NULL))
			continue;

		spin_unlock(&tpg->tpg_lun_lock);
		ret = LUN_OBJ_API(lun)->del_obj_from_lun(tpg, lun);
		spin_lock(&tpg->tpg_lun_lock);
	}
	spin_unlock(&tpg->tpg_lun_lock);

	return;
}

extern int iscsi_tpg_del_portal_group (
	iscsi_tiqn_t *tiqn,
	iscsi_portal_group_t *tpg,
	int force)
{
	u8 old_state = tpg->tpg_state;

	spin_lock(&tpg->tpg_state_lock);
	tpg->tpg_state = TPG_STATE_INACTIVE;
	spin_unlock(&tpg->tpg_state_lock);

	iscsi_clear_tpg_np_login_threads(tpg);
	
	if (iscsi_release_sessions_for_tpg(tpg, force) < 0) {
		TRACE_ERROR("Unable to delete iSCSI Target Portal Group: %hu"
		" while active sessions exist, and force=0\n", tpg->tpgt);
		tpg->tpg_state = old_state;
		return(ERR_DELTPG_SESSIONS_ACTIVE);
	}

	iscsi_tpg_clear_object_luns(tpg);
	iscsi_tpg_free_network_portals(tpg);
	iscsi_tpg_free_portal_group_node_acls(tpg);
	
	if (tpg->param_list) {
		iscsi_release_param_list(tpg->param_list);
		tpg->param_list = NULL;
	}

	iscsi_OS_unregister_info_handlers(tpg->tpgt);
	
	kfree(tpg->tpg_lun_list);
	tpg->tpg_lun_list = NULL;

	spin_lock(&tpg->tpg_state_lock);
	tpg->tpg_state = TPG_STATE_FREE;
	spin_unlock(&tpg->tpg_state_lock);

	spin_lock(&tiqn->tiqn_tpg_lock);
	tiqn->tiqn_ntpgs--;
	PYXPRINT("CORE[%s]_TPG[%hu] - Deleted iSCSI Target Portal Group\n",
			tiqn->tiqn, tpg->tpgt);
	spin_unlock(&tiqn->tiqn_tpg_lock);
	
	return(0);
}

/*	iscsi_tpg_enable_portal_group():
 *      
 *
 */             
extern int iscsi_tpg_enable_portal_group (iscsi_portal_group_t *tpg)
{
	iscsi_param_t *param;
	iscsi_tiqn_t *tiqn = tpg->tpg_tiqn;
	
	spin_lock(&tpg->tpg_state_lock);
	if (tpg->tpg_state == TPG_STATE_ACTIVE) {
		TRACE_ERROR("iSCSI target portal group: %hu is already active,"
				" ignoring request.\n", tpg->tpgt);
		spin_unlock(&tpg->tpg_state_lock);
		return(ERR_ENABLETPG_ALREADY_ACTIVE);
	}
	if (!tpg->num_tpg_nps) {
		TRACE_ERROR("Unable to activate iSCSI target portal group with"
			" no IP addresses, please add one with addnptotpg.\n");
		spin_unlock(&tpg->tpg_state_lock);
		return(ERR_ENABLETPG_NO_NPS);
	}

	/*
	 * Make sure that AuthMethod does not contain None as an option
	 * unless explictly disabled.  Set the default to CHAP if authentication
	 * is enforced (as per default), and remove the NONE option.
	 */
	if (!(param = iscsi_find_param_from_key(AUTHMETHOD, tpg->param_list))) {
		spin_unlock(&tpg->tpg_state_lock);
		return(ERR_NO_MEMORY);
	}

	if (ISCSI_TPG_ATTRIB(tpg)->authentication) {
		if (!strcmp(param->value, NONE))
			if (iscsi_update_param_value(param, CHAP) < 0) {
				spin_unlock(&tpg->tpg_state_lock);
				return(ERR_NO_MEMORY);
			}
		if (iscsi_ta_set_authentication(tpg, 1) < 0) {
			spin_unlock(&tpg->tpg_state_lock);
			return(ERR_NO_MEMORY);
		}
	}
		
	tpg->tpg_state = TPG_STATE_ACTIVE;
	spin_unlock(&tpg->tpg_state_lock);
	
	spin_lock(&tiqn->tiqn_tpg_lock);
	tiqn->tiqn_active_tpgs++;
	PYXPRINT("iSCSI_TPG[%hu] - Enabled iSCSI Target Portal Group\n", tpg->tpgt);
	spin_unlock(&tiqn->tiqn_tpg_lock);

	return(0);
}		

/*	iscsi_tpg_disable_portal_group():
 *
 *
 */
extern int iscsi_tpg_disable_portal_group (iscsi_portal_group_t *tpg, int force)
{
	iscsi_tiqn_t *tiqn = tpg->tpg_tiqn;
	u8 old_state = tpg->tpg_state;
	
	spin_lock(&tpg->tpg_state_lock);
	if (tpg->tpg_state == TPG_STATE_INACTIVE) {
		TRACE_ERROR("iSCSI Target Portal Group: %hu is already"
			" inactive, ignoring request.\n", tpg->tpgt);
		spin_unlock(&tpg->tpg_state_lock);
		return(ERR_DISABLETPG_NOT_ACTIVE);
	}
	tpg->tpg_state = TPG_STATE_INACTIVE;
	spin_unlock(&tpg->tpg_state_lock);
	
	iscsi_clear_tpg_np_login_threads(tpg);
	
	if (iscsi_release_sessions_for_tpg(tpg, force) < 0) {
		spin_lock(&tpg->tpg_state_lock);
		tpg->tpg_state = old_state;
		spin_unlock(&tpg->tpg_state_lock);
		TRACE_ERROR("Unable to disable iSCSI Target Portal Group: %hu"
		" while active sessions exist, and force=0\n", tpg->tpgt);
		return(ERR_DISABLETPG_SESSIONS_ACTIVE);
	}
	
	spin_lock(&tiqn->tiqn_tpg_lock);
	tiqn->tiqn_active_tpgs--;
	PYXPRINT("iSCSI_TPG[%hu] - Disabled iSCSI Target Portal Group\n", tpg->tpgt);
	spin_unlock(&tiqn->tiqn_tpg_lock);
	
	return(0);
}

/*	iscsi_tpg_add_initiator_node_acl():
 *
 *
 */
extern int iscsi_tpg_add_initiator_node_acl (
	iscsi_portal_group_t *tpg,
	unsigned char *initiatorname,
	__u32 queue_depth)
{
	iscsi_node_acl_t *acl = NULL;

	spin_lock_bh(&tpg->acl_node_lock);
	if ((acl = __iscsi_tpg_get_initiator_node_acl(tpg, initiatorname))) {
		if (acl->nodeacl_flags & NAF_DYNAMIC_NODE_ACL) {
			acl->nodeacl_flags &= ~NAF_DYNAMIC_NODE_ACL;
			PYXPRINT("iSCSI_TPG[%hu] - Replacing dynamic ACL for"
				" %s\n", tpg->tpgt, initiatorname);
			spin_unlock_bh(&tpg->acl_node_lock);
			goto done;
		}

		TRACE_ERROR("ACL entry for iSCSI Initiator"
			" Node %s already exists for TPG %hu, ignoring"
			" request.\n", initiatorname, tpg->tpgt);
		spin_unlock_bh(&tpg->acl_node_lock);
		return(ERR_ADDINITACL_ACL_EXISTS);
	}
	spin_unlock_bh(&tpg->acl_node_lock);

	if (!(acl = (iscsi_node_acl_t *) kmalloc(
			sizeof(iscsi_node_acl_t), GFP_KERNEL))) {
		TRACE_ERROR("Unable to allocate memory for iscsi_node_acl_t.\n");
		return(ERR_NO_MEMORY);
	}
	memset((void *)acl, 0, sizeof(iscsi_node_acl_t));

	spin_lock_init(&acl->device_list_lock);
	acl->queue_depth = queue_depth;
	snprintf(acl->initiatorname, ISCSI_IQN_LEN, "%s", initiatorname);
	acl->tpg = tpg;
#ifdef SNMP_SUPPORT
	acl->acl_index = get_new_index(SCSI_AUTH_INTR_INDEX);
	spin_lock_init(&acl->stats_lock);
#endif /* SNMP_SUPPORT */

	iscsi_set_default_node_attribues(acl);
      
	if (iscsi_create_device_list_for_node(acl, tpg)  < 0) {
		kfree(acl);
		return(ERR_NO_MEMORY);
	}
	
	if (iscsi_set_queue_depth_for_node(tpg, acl) < 0) {
		iscsi_free_device_list_for_node(acl, tpg);
		kfree(acl);
		return(ERR_ADDINITACL_QUEUE_SET_FAILED);
	}
	
	spin_lock_bh(&tpg->acl_node_lock);
	ADD_ENTRY_TO_LIST(acl, tpg->acl_node_head, tpg->acl_node_tail);
	tpg->num_node_acls++;
	spin_unlock_bh(&tpg->acl_node_lock);

done:
	PYXPRINT("iSCSI_TPG[%hu] - Added ACL with TCQ Depth: %d for iSCSI"
		" Initiator Node: %s\n", tpg->tpgt, acl->queue_depth,
			initiatorname);

	return(0);
}

/*	iscsi_tpg_del_initiator_node_acl():
 *
 *
 */
extern int iscsi_tpg_del_initiator_node_acl (
	iscsi_portal_group_t *tpg,
	unsigned char *initiatorname,
	int force)
{
	int dynamic_acl = 0;
	iscsi_session_t *sess;
	iscsi_node_acl_t *acl;

	spin_lock_bh(&tpg->acl_node_lock);
	if (!(acl = __iscsi_tpg_get_initiator_node_acl(tpg, initiatorname))) {
		TRACE_ERROR("Access Control List entry for iSCSI Initiator"
			" Node %s does not exists for TPG %hu, ignoring"
			" request.\n", initiatorname, tpg->tpgt);
		spin_unlock_bh(&tpg->acl_node_lock);
		return(ERR_INITIATORACL_DOES_NOT_EXIST);
	}
	if (acl->nodeacl_flags & NAF_DYNAMIC_NODE_ACL) {
		acl->nodeacl_flags &= ~NAF_DYNAMIC_NODE_ACL;
		dynamic_acl = 1;
	}
	spin_unlock_bh(&tpg->acl_node_lock);
	
	spin_lock_bh(&tpg->session_lock);
	for (sess = tpg->session_head; sess; sess = sess->next) {
		if (sess->node_acl != acl)
			continue;

		if (!force) {
			TRACE_ERROR("Unable to delete Access Control List for"
			" iSCSI Initiator Node: %s while session is operational."
			"  To forcefully delete the session use the \"force=1\""
				" parameter.\n", initiatorname);
			spin_unlock_bh(&tpg->session_lock);
			spin_lock_bh(&tpg->acl_node_lock);
			if (dynamic_acl)
				acl->nodeacl_flags |= NAF_DYNAMIC_NODE_ACL;
			spin_unlock_bh(&tpg->acl_node_lock);
			return(ERR_INITIATORACL_SESSION_EXISTS);
		}
		spin_lock(&sess->conn_lock);
		if (atomic_read(&sess->session_fall_back_to_erl0) ||
		    atomic_read(&sess->session_logout) ||
		    (sess->time2retain_timer_flags & T2R_TF_EXPIRED)) {
			spin_unlock(&sess->conn_lock);
			continue;
		}
		atomic_set(&sess->session_reinstatement, 1);
		spin_unlock(&sess->conn_lock);

		iscsi_inc_session_usage_count(sess);
		iscsi_stop_time2retain_timer(sess);
		break;
	}
	spin_unlock_bh(&tpg->session_lock);
		
	spin_lock_bh(&tpg->acl_node_lock);
	REMOVE_ENTRY_FROM_LIST(acl, tpg->acl_node_head, tpg->acl_node_tail);
	tpg->num_node_acls--;
	spin_unlock_bh(&tpg->acl_node_lock);
	
	/*
	 * If the iSCSI Session for the iSCSI Initiator Node exists,
	 * forcefully shutdown the iSCSI NEXUS.
	 */
	if (sess) {
		iscsi_stop_session(sess, 1, 1);
		iscsi_dec_session_usage_count(sess);
		iscsi_close_session(sess);
	}
	
	iscsi_clear_initiator_node_from_tpg(acl, tpg);
	iscsi_free_device_list_for_node(acl, tpg);

	PYXPRINT("iSCSI_TPG[%hu] - Deleted ACL with TCQ Depth: %d for iSCSI"
		" Initiator Node: %s\n", tpg->tpgt, acl->queue_depth,
			initiatorname);
	kfree(acl);
	
	return(0);
}

/*	iscsi_tpg_add_network_portal():
 *
 *
 */
extern int iscsi_tpg_add_network_portal (
	iscsi_portal_group_t *tpg,
	struct iscsi_target *tg,
	int network_transport)
{
	iscsi_np_t *np;
	iscsi_tpg_np_t *tpg_np;
	unsigned char *ip, *ip_buf;
	int ret = 0;
	unsigned char buf_ipv4[IPV4_BUF_SIZE];

	if (tg->net_params_set & PARAM_NET_IPV6_ADDRESS) {
		ip = ip_buf = &tg->ip6[0];
	} else {
		ip = (void *)&tg->ip;
		memset(buf_ipv4, 0, IPV4_BUF_SIZE);
		iscsi_ntoa2(buf_ipv4, tg->ip);
		ip_buf = &buf_ipv4[0];
	}

	/*
	 * If the Network Portal does not currently exist, start it up now.
	 */
	if (!(np = core_get_np((void *)ip, tg->port, network_transport))) {
		if (!(np = core_add_np(tg, network_transport, &ret)))
			return(ret);
	}

	spin_lock(&tpg->tpg_np_lock);
	list_for_each_entry(tpg_np, &tpg->tpg_gnp_list, tpg_np_list) {
		if (!(memcmp(core_get_np_ip(tpg_np->tpg_np), ip, tpg_np->tpg_np->np_net_size)) &&
		    (tpg_np->tpg_np->np_port == tg->port) &&
		    (tpg_np->tpg_np->np_network_transport == network_transport)) {
			TRACE_ERROR("Network Portal %s:%hu on %s already exists"
				" on TPG %hu, ignoring request.\n", ip_buf,
				tg->port, (network_transport == ISCSI_TCP) ?
				"TCP" : "SCTP", tpg->tpgt);
			spin_unlock(&tpg->tpg_np_lock);
			return(ERR_ADDNPTOTPG_ALREADY_EXISTS);
		}
	}
	spin_unlock(&tpg->tpg_np_lock);
                 
	if (!(tpg_np = (iscsi_tpg_np_t *) kmalloc(
			sizeof(iscsi_tpg_np_t), GFP_KERNEL))) {
		TRACE_ERROR("Unable to allocate memory for iscsi_tpg_np_t.\n");
		return(ERR_NO_MEMORY);
	}
	memset((void *)tpg_np, 0, sizeof(iscsi_tpg_np_t));
#ifdef SNMP_SUPPORT
	tpg_np->tpg_np_index	= get_new_index(ISCSI_PORTAL_INDEX);
#endif /* SNMP_SUPPORT */
	INIT_LIST_HEAD(&tpg_np->tpg_np_list);
	tpg_np->tpg_np		=  np;

	spin_lock(&tpg->tpg_np_lock);
	list_add_tail(&tpg_np->tpg_np_list, &tpg->tpg_gnp_list);
	tpg->num_tpg_nps++;
	spin_unlock(&tpg->tpg_np_lock);

	PYXPRINT("CORE[%s] - Added Network Portal: %s:%hu,%hu on %s on network"
		" device: %s\n", tpg->tpg_tiqn->tiqn, ip_buf,
		tpg_np->tpg_np->np_port, tpg->tpgt,
		(tpg_np->tpg_np->np_network_transport == ISCSI_TCP) ?
		"TCP" : "SCTP", (strlen(tpg_np->tpg_np->np_net_dev)) ?
		(char *)tpg_np->tpg_np->np_net_dev : "None");

	spin_lock(&np->np_state_lock);
	np->np_exports++;
	PYXPRINT("CORE[%s]_TPG[%hu] - Incremented np_exports to %u\n",
		tpg->tpg_tiqn->tiqn, tpg->tpgt, np->np_exports);
	spin_unlock(&np->np_state_lock);

	return(0);
}

extern iscsi_tpg_np_t *iscsi_tpg_del_np_phase0 (
	iscsi_portal_group_t *tpg,
	iscsi_np_t *np)
{
	iscsi_tpg_np_t *tpg_np, *tpg_np_t;

	spin_lock(&tpg->tpg_np_lock);
	list_for_each_entry_safe(tpg_np, tpg_np_t, &tpg->tpg_gnp_list, tpg_np_list) {
		if (tpg_np->tpg_np == np) {
			list_del(&tpg_np->tpg_np_list);
			tpg->num_tpg_nps--;
			spin_unlock(&tpg->tpg_np_lock);
			return(tpg_np);
		}
	}
	spin_unlock(&tpg->tpg_np_lock);

	return(NULL);
}

extern int iscsi_tpg_del_np_phase1 (
	iscsi_tpg_np_t *tpg_np,
	iscsi_portal_group_t *tpg,
	iscsi_np_t *np)
{
	unsigned char *ip;
	unsigned char buf_ipv4[IPV4_BUF_SIZE];
	
	if (np->np_net_size == IPV6_ADDRESS_SPACE)
		ip = &np->np_ipv6[0];
	else {
		memset(buf_ipv4, 0, IPV4_BUF_SIZE);
		iscsi_ntoa2(buf_ipv4, np->np_ipv4);
		ip = &buf_ipv4[0];
	}
	
	iscsi_clear_tpg_np_login_thread(tpg_np, tpg);

	PYXPRINT("CORE[%s] - Removed Network Portal: %s:%hu,%hu on %s on network"
		" device: %s\n", tpg->tpg_tiqn->tiqn, ip,
		tpg_np->tpg_np->np_port, tpg->tpgt,
		(tpg_np->tpg_np->np_network_transport == ISCSI_TCP) ? 
		"TCP" : "SCTP",  (strlen(tpg_np->tpg_np->np_net_dev)) ?
			(char *)tpg_np->tpg_np->np_net_dev : "None");

	tpg_np->tpg_np = NULL;
	kfree(tpg_np);

	/*
	 * Shutdown Network Portal when last TPG reference is released.
	 */
	spin_lock(&np->np_state_lock);
	np->np_exports--;
	PYXPRINT("CORE[%s]_TPG[%hu] - Decremented np_exports to %u\n",
		tpg->tpg_tiqn->tiqn, tpg->tpgt, np->np_exports);
	spin_unlock(&np->np_state_lock);

	return(0);
}

/*	iscsi_tpg_del_network_portal():
 *
 *
 */
extern int iscsi_tpg_del_network_portal (
	iscsi_portal_group_t *tpg,
	struct iscsi_target *tg,
	int network_transport)
{
	iscsi_np_t *np;
	iscsi_tpg_np_t *tpg_np;
	unsigned char *ip, *ip_buf;
	int ret = 0;
	unsigned char buf_ipv4[IPV4_BUF_SIZE];
	
	if (tg->net_params_set & PARAM_NET_IPV6_ADDRESS) {
		ip = ip_buf = &tg->ip6[0];
	} else {
		ip = (void *)&tg->ip;
		memset(buf_ipv4, 0, IPV4_BUF_SIZE);
		iscsi_ntoa2(buf_ipv4, tg->ip);
		ip_buf = &buf_ipv4[0];
	}

	if (!(np = core_get_np((void *)ip, tg->port, network_transport)))
		return(-1);

	if (!(tpg_np = iscsi_tpg_del_np_phase0(tpg, np))) {
		TRACE_ERROR("Network Portal %s:%hu on %s does not exist on TPG %hu,"
			" ignoring request.\n", ip_buf, tg->port,
			(network_transport == ISCSI_TCP) ? "TCP" : "SCTP", tpg->tpgt);
		return(ERR_DELNP_DOES_NOT_EXIST);
	}

	if (iscsi_tpg_del_np_phase1(tpg_np, tpg, np) < 0) 
		ret = ERR_DELNP_DOES_NOT_EXIST;
	
	return(ret);
}

/*	iscsi_tpg_set_initiator_node_queue_depth():
 *
 *
 */
extern int iscsi_tpg_set_initiator_node_queue_depth (
	iscsi_portal_group_t *tpg,
	unsigned char *initiatorname,
	__u32 queue_depth,
	int force)
{
	int dynamic_acl = 0;
	iscsi_session_t *sess = NULL;
	iscsi_node_acl_t *acl;
	
	spin_lock_bh(&tpg->acl_node_lock);
	if (!(acl = __iscsi_tpg_get_initiator_node_acl(tpg, initiatorname))) {
		TRACE_ERROR("Access Control List entry for iSCSI Initiator"
			" Node %s does not exists for TPG %hu, ignoring"
			" request.\n", initiatorname, tpg->tpgt);
		spin_unlock_bh(&tpg->acl_node_lock);
		return(ERR_INITIATORACL_DOES_NOT_EXIST);
	}
	if (acl->nodeacl_flags & NAF_DYNAMIC_NODE_ACL) {
		acl->nodeacl_flags &= ~NAF_DYNAMIC_NODE_ACL;
		dynamic_acl = 1;
	}
	spin_unlock_bh(&tpg->acl_node_lock);
	
	spin_lock_bh(&tpg->session_lock);
	for (sess = tpg->session_head; sess; sess = sess->next) {
		if (sess->node_acl != acl)
			continue;

		if (!force) {
			TRACE_ERROR("Unable to change queue depth for iSCSI Initiator"
				" Node: %s while session is operational.  To forcefully"
				" change the queue depth and force session reinstatement"
				" use the \"force=1\" parameter.\n", initiatorname);
			spin_unlock_bh(&tpg->session_lock);
			spin_lock_bh(&tpg->acl_node_lock);
			if (dynamic_acl)
				acl->nodeacl_flags |= NAF_DYNAMIC_NODE_ACL;
			spin_unlock_bh(&tpg->acl_node_lock);
			return(ERR_INITIATORACL_SESSION_EXISTS);
		}
		spin_lock(&sess->conn_lock);
		if (atomic_read(&sess->session_fall_back_to_erl0) ||
		    atomic_read(&sess->session_logout) ||
		    (sess->time2retain_timer_flags & T2R_TF_EXPIRED)) {
			spin_unlock(&sess->conn_lock);
			continue;
		}
		atomic_set(&sess->session_reinstatement, 1);
		spin_unlock(&sess->conn_lock);

		iscsi_inc_session_usage_count(sess);
		iscsi_stop_time2retain_timer(sess);
		break;
	}

	/*
	 * User has requested to change the queue depth for a iSCSI Initiator Node.
	 * Change the value in the Node's iscsi_node_acl_t, and call
	 * iscsi_set_queue_depth_for_node() to add the requested queue
	 * depth into the TPG HBA's outstanding queue depth.
	 * Finally call iscsi_free_session() to force session reinstatement to occur if
	 * there is an active session for the iSCSI Initiator Node in question.
	 */
	acl->queue_depth = queue_depth;

	if (iscsi_set_queue_depth_for_node(tpg, acl) < 0) {
		spin_unlock_bh(&tpg->session_lock);
		if (sess)
			iscsi_dec_session_usage_count(sess);
		spin_lock_bh(&tpg->acl_node_lock);
		if (dynamic_acl)
			acl->nodeacl_flags |= NAF_DYNAMIC_NODE_ACL;
		spin_unlock_bh(&tpg->acl_node_lock);
		return(ERR_SETINITCQ_SET_FAILED);
	}
	spin_unlock_bh(&tpg->session_lock);

	if (sess) {
		iscsi_stop_session(sess, 1, 1);
		iscsi_dec_session_usage_count(sess);
		iscsi_close_session(sess);
	}	

	PYXPRINT("Successfuly changed queue depth to: %d for Initiator Node:"
		" %s on iSCSI Target Portal Group: %hu\n", queue_depth,
			initiatorname, tpg->tpgt);

	spin_lock_bh(&tpg->acl_node_lock);
	if (dynamic_acl)
		acl->nodeacl_flags |= NAF_DYNAMIC_NODE_ACL;
	spin_unlock_bh(&tpg->acl_node_lock);
		
	return(0);
}

extern iscsi_lun_t *iscsi_tpg_pre_addlun (
	iscsi_portal_group_t *tpg,
	u32 iscsi_lun,
	int *ret)
{
	iscsi_lun_t *lun;
	
	if (iscsi_lun > (ISCSI_MAX_LUNS_PER_TPG-1)) {
		TRACE_ERROR("iSCSI LUN: %u exceeds ISCSI_MAX_LUNS_PER_TPG-1:"
			" %u for Target Portal Group: %hu\n", iscsi_lun,
			ISCSI_MAX_LUNS_PER_TPG-1, tpg->tpgt);
		*ret = ERR_LUN_EXCEEDS_MAX;
		return(NULL);
	}

	spin_lock(&tpg->tpg_lun_lock);
	lun = &tpg->tpg_lun_list[iscsi_lun];
	if (lun->lun_status == ISCSI_LUN_STATUS_ACTIVE) {
		TRACE_ERROR("iSCSI Logical Unit Number: %u is already active"
			" on iSCSI Target Portal Group: %hu, ignoring request.\n",
				iscsi_lun, tpg->tpgt);
		spin_unlock(&tpg->tpg_lun_lock);
		*ret = ERR_ADDLUN_ALREADY_ACTIVE;
		return(NULL);
	}
	spin_unlock(&tpg->tpg_lun_lock);

	return(lun);
}
	
extern int iscsi_tpg_post_addlun (
	iscsi_portal_group_t *tpg,
	iscsi_lun_t *lun,
	int lun_type,
	u32 lun_access,
	void *lun_ptr,
	struct se_obj_lun_type_s *obj_api)
{
	lun->lun_obj_api = obj_api;
	lun->lun_type_ptr = lun_ptr;
	if (LUN_OBJ_API(lun)->export_obj(lun_ptr, tpg, lun) < 0) {
		lun->lun_type_ptr = NULL;
		lun->lun_obj_api = NULL;
		return(-1);
	}
	
	spin_lock(&tpg->tpg_lun_lock);
	lun->lun_access = lun_access;
	lun->lun_type = lun_type;
	lun->lun_status = ISCSI_LUN_STATUS_ACTIVE;
	spin_unlock(&tpg->tpg_lun_lock);

	spin_lock(&tpg->tpg_state_lock);
	tpg->nluns++;
	tpg->ndevs++;
	spin_unlock(&tpg->tpg_state_lock);

	return(0);
}

extern iscsi_lun_t *iscsi_tpg_pre_dellun (
	iscsi_portal_group_t *tpg,
	u32 iscsi_lun,
	int lun_type,
	int *ret)
{
	iscsi_lun_t *lun;
	
	if (iscsi_lun > (ISCSI_MAX_LUNS_PER_TPG-1)) {
		TRACE_ERROR("iSCSI LUN: %u exceeds ISCSI_MAX_LUNS_PER_TPG-1:"
			" %u for Target Portal Group: %hu\n", iscsi_lun,
			ISCSI_MAX_LUNS_PER_TPG-1, tpg->tpgt);
		*ret = ERR_LUN_EXCEEDS_MAX;
		return(NULL);
	}

	spin_lock(&tpg->tpg_lun_lock);
	lun = &tpg->tpg_lun_list[iscsi_lun];
	if (lun->lun_status != ISCSI_LUN_STATUS_ACTIVE) {
		TRACE_ERROR("iSCSI Logical Unit Number: %u is not active on"
			" iSCSI Target Portal Group: %hu, ignoring request.\n",
				iscsi_lun, tpg->tpgt);
		spin_unlock(&tpg->tpg_lun_lock);
		*ret = ERR_DELLUN_NOT_ACTIVE;
		return(NULL);
	}

	if (lun->lun_type != lun_type) {
		TRACE_ERROR("iSCSI Logical Unit Number: %u type: %d does not"
			" match passed type: %d\n", iscsi_lun, lun->lun_type,
				lun_type);
		spin_unlock(&tpg->tpg_lun_lock);
		*ret = ERR_DELLUN_TYPE_MISMATCH;
		return(NULL);
	}
	spin_unlock(&tpg->tpg_lun_lock);

	iscsi_clear_lun_from_tpg(lun, tpg);

	return(lun);
}

extern int iscsi_tpg_post_dellun (
	iscsi_portal_group_t *tpg,
	iscsi_lun_t *lun)
{
	iscsi_lun_acl_t *acl, *acl_next;
	
	iscsi_clear_lun_from_sessions(lun, tpg);

	LUN_OBJ_API(lun)->unexport_obj(lun->lun_type_ptr, tpg, lun);
	LUN_OBJ_API(lun)->release_obj(lun->lun_type_ptr);
	
	spin_lock(&tpg->tpg_lun_lock);
	lun->lun_status = ISCSI_LUN_STATUS_FREE;
	lun->lun_type = 0;
	lun->lun_type_ptr = NULL;
	spin_unlock(&tpg->tpg_lun_lock);

	spin_lock(&lun->lun_acl_lock);
	acl = lun->lun_acl_head;
	while (acl) {
		acl_next = acl->next;
		kfree(acl);
		acl = acl_next;
	}
	lun->lun_acl_head = lun->lun_acl_tail = NULL;
	spin_unlock(&lun->lun_acl_lock);

	spin_lock(&tpg->tpg_state_lock);
	tpg->nluns--;
	tpg->ndevs--;
	spin_unlock(&tpg->tpg_state_lock);

	
	
	return(0);	
}

/*	iscsi_ta_set_authentication():
 *
 *
 */
static int iscsi_ta_set_authentication (iscsi_portal_group_t *tpg, __u32 authentication)
{
	unsigned char buf1[256], buf2[256], *none = NULL;
	int len;
	iscsi_param_t *param;
	iscsi_tpg_attrib_t *a = &tpg->tpg_attrib;
	
	if ((authentication != 1) && (authentication != 0)) {
		TRACE_ERROR("Illegal value for authentication parameter: %u,"
			" ignoring request.\n", authentication);
		return(-1);
	}
		
	memset(buf1, 0, sizeof(buf1));
	memset(buf2, 0, sizeof(buf2));
	if (!(param = iscsi_find_param_from_key(AUTHMETHOD, tpg->param_list)))
		return(-1);

	if (authentication) {
		snprintf(buf1, sizeof(buf1), "%s", param->value);
		if (!(none = strstr(buf1, NONE)))
			goto out;
		if (!strncmp(none + 4, ",", 1)) {
			if (!strcmp(buf1, none))
				sprintf(buf2, "%s", none+5);
			else {
				none--;
				*none = '\0';
				len = sprintf(buf2, "%s", buf1);
				none += 5;
				sprintf(buf2 + len, "%s", none);
			}
		} else {
			none--;
			*none = '\0';
			sprintf(buf2, "%s", buf1);
		}
		if (iscsi_update_param_value(param, buf2) < 0)
			return(-1);
	} else {
		snprintf(buf1, sizeof(buf1), "%s", param->value);
		if ((none = strstr(buf1, NONE)))
			goto out;
		strncat(buf1, ",", strlen(","));
		strncat(buf1, NONE, strlen(NONE));
		if (iscsi_update_param_value(param, buf1) < 0)
			return(-1);
	}

out:	
	a->authentication = authentication;
	PYXPRINT("%s iSCSI Authentication Methods for TPG: %hu.\n",
		a->authentication ? "Enforcing" : "Disabling", tpg->tpgt);
	
	return(0);
}

/*	iscsi_ta_set_login_timeout():
 *
 *
 */
static int iscsi_ta_set_login_timeout (
	iscsi_portal_group_t *tpg,
	__u32 login_timeout)
{
	iscsi_tpg_attrib_t *a = &tpg->tpg_attrib;
	
	if (login_timeout > TA_LOGIN_TIMEOUT_MAX) {
		TRACE_ERROR("Requested Login Timeout %u larger than maximum"
			" %u\n", login_timeout, TA_LOGIN_TIMEOUT_MAX);
		return(-1);
	} else if (login_timeout < TA_LOGIN_TIMEOUT_MIN) {
		TRACE_ERROR("Requested Logout Timeout %u smaller than minimum"
			" %u\n", login_timeout, TA_LOGIN_TIMEOUT_MIN);
		return(-1);
	}

	a->login_timeout = login_timeout;
	PYXPRINT("Set Logout Timeout to %u for Target Portal Group"
		" %hu\n", a->login_timeout, tpg->tpgt);
	
	return(0);
}

/*	iscsi_ta_set_netif_timeout():
 *
 *
 */
static int iscsi_ta_set_netif_timeout (
	iscsi_portal_group_t *tpg,
	__u32 netif_timeout)
{
	iscsi_tpg_attrib_t *a = &tpg->tpg_attrib;

	if (netif_timeout > TA_NETIF_TIMEOUT_MAX) {
		TRACE_ERROR("Requested Network Interface Timeout %u larger"
			" than maximum %u\n", netif_timeout,
				TA_NETIF_TIMEOUT_MAX);	
		return(-1);
	} else if (netif_timeout < TA_NETIF_TIMEOUT_MIN) {
		TRACE_ERROR("Requested Network Interface Timeout %u smaller"
			" than minimum %u\n", netif_timeout,
				TA_NETIF_TIMEOUT_MIN);
		return(-1);
	}

	a->netif_timeout = netif_timeout;
	PYXPRINT("Set Network Interface Timeout to %u for"
		" Target Portal Group %hu\n", a->netif_timeout, tpg->tpgt);
		
	return(0);
}

static int iscsi_ta_generate_node_acls (
	iscsi_portal_group_t *tpg,
	int flag)
{
	iscsi_tpg_attrib_t *a = &tpg->tpg_attrib;

	if ((flag != 0) && (flag != 1)) {
		TRACE_ERROR("Illegal value %d\n", flag);
		return(-1);
	}

	a->generate_node_acls = flag;
	PYXPRINT("iSCSI_TPG[%hu] - Generate Initiator Portal Group ACLs: %s\n",
		tpg->tpgt, (a->generate_node_acls) ? "Enabled" : "Disabled");
	
	return(0);
}

static int iscsi_ta_set_default_tcq (
	iscsi_portal_group_t *tpg,
	u32 tcq_depth)
{
	iscsi_tpg_attrib_t *a = &tpg->tpg_attrib;
	
	if (tcq_depth > TA_DEFAULT_QUEUE_DEPTH_MAX) {
		TRACE_ERROR("Requested Default Queue Depth: %u larger"
			" than maximum %u\n", tcq_depth,
				TA_DEFAULT_QUEUE_DEPTH_MAX);
		return(-1);
	} else if (tcq_depth < TA_DEFAULT_QUEUE_DEPTH_MIN) {
		TRACE_ERROR("Requested Default Queue Depth: %u smaller"
			" than minimum %u\n", tcq_depth,
				TA_DEFAULT_QUEUE_DEPTH_MIN);
		return(-1);
	}

	a->default_queue_depth = tcq_depth;
	PYXPRINT("iSCSI_TPG[%hu] - Set Default TCQ Depth to %u\n", tpg->tpgt,
			a->default_queue_depth);

	return(0);
}

static int iscsi_ta_set_cache_dynamic_acls (
	iscsi_portal_group_t *tpg,
	int flag)
{
	iscsi_tpg_attrib_t *a = &tpg->tpg_attrib;

	if ((flag != 0) && (flag != 1)) {
		TRACE_ERROR("Illegal value %d\n", flag);
		return(-1);
	}

	a->cache_dynamic_acls = flag;
	PYXPRINT("iSCSI_TPG[%hu] - Cache Dynamic Initiator Portal Group ACLs: %s\n",
		tpg->tpgt, (a->cache_dynamic_acls) ? "Enabled" : "Disabled");

	return(0);
}

static int iscsi_ta_set_demo_mode_lun_access (
	iscsi_portal_group_t *tpg,
	int flag)
{
	iscsi_tpg_attrib_t *a = &tpg->tpg_attrib;

	if ((flag != 0) && (flag != 1)) {
		TRACE_ERROR("Illegal value %d\n", flag);
		return(-1);
	}

	a->demo_mode_lun_access = flag;
	PYXPRINT("iSCSI_TPG[%hu] - Demo Mode iSCSI LUN Access: %s\n",
		tpg->tpgt, (a->demo_mode_lun_access) ? "READ-WRITE" : "READ-ONLY");

	return(0);
}

/*	iscsi_tpg_set_attributes():
 *                      
 *              
 */             
extern int iscsi_tpg_set_attributes (
	iscsi_portal_group_t *tpg,
	__u32 ta_attrib,
	__u32 ta_attrib_value)
{
	switch (ta_attrib) {
	case TA_SET_AUTHENTICATION:
		return(iscsi_ta_set_authentication(tpg, ta_attrib_value));
	case TA_SET_LOGIN_TIMEOUT:
		return(iscsi_ta_set_login_timeout(tpg, ta_attrib_value));
	case TA_SET_NETIF_TIMEOUT:
		return(iscsi_ta_set_netif_timeout(tpg, ta_attrib_value));
	case TA_SET_GENERATE_NODE_ACLS:
		return(iscsi_ta_generate_node_acls(tpg, ta_attrib_value));
	case TA_SET_DEFAULT_QUEUE_DEPTH:
		return(iscsi_ta_set_default_tcq(tpg, ta_attrib_value));
	case TA_SET_CACHE_DYNAMIC_ACLS:
		return(iscsi_ta_set_cache_dynamic_acls(tpg, ta_attrib_value));
	case TA_SET_DEMO_MODE_LUN_ACCESS:
		return(iscsi_ta_set_demo_mode_lun_access(tpg, ta_attrib_value));
	default:
		TRACE_ERROR("Unknown TPG Attribute %u, ignoring"
			" request.\n", ta_attrib);
		return(-1);
	}
		                
	return(0);
}

extern void iscsi_disable_tpgs (iscsi_tiqn_t *tiqn)
{
	int i;
	iscsi_portal_group_t *tpg;

	spin_lock(&tiqn->tiqn_tpg_lock);
	for (i = 0; i < ISCSI_MAX_TPGS; i++) {
		tpg = &tiqn->tiqn_tpg_list[i];

		spin_lock(&tpg->tpg_state_lock);
		if ((tpg->tpg_state == TPG_STATE_FREE) ||
		    (tpg->tpg_state == TPG_STATE_INACTIVE)) {
			spin_unlock(&tpg->tpg_state_lock);
			continue;
		}
		spin_unlock(&tpg->tpg_state_lock);
		spin_unlock(&tiqn->tiqn_tpg_lock);

		iscsi_tpg_disable_portal_group(tpg, 1);

		spin_lock(&tiqn->tiqn_tpg_lock);
	}
	spin_unlock(&tiqn->tiqn_tpg_lock);

	return;
}

/*	iscsi_disable_all_tpgs():
 *
 *
 */
extern void iscsi_disable_all_tpgs (void)
{
	iscsi_tiqn_t *tiqn;

	spin_lock(&iscsi_global->tiqn_lock);
	list_for_each_entry(tiqn, &iscsi_global->g_tiqn_list, tiqn_list) {
		spin_unlock(&iscsi_global->tiqn_lock);
		iscsi_disable_tpgs(tiqn);
		spin_lock(&iscsi_global->tiqn_lock);
	}
	spin_unlock(&iscsi_global->tiqn_lock);
		
	return;
}

extern void iscsi_remove_tpgs (iscsi_tiqn_t *tiqn)
{
	int i;
	iscsi_portal_group_t *tpg;

	spin_lock(&tiqn->tiqn_tpg_lock);
	for (i = 0; i < ISCSI_MAX_TPGS; i++) {
		tpg = &tiqn->tiqn_tpg_list[i];

		spin_lock(&tpg->tpg_state_lock);
		if (tpg->tpg_state == TPG_STATE_FREE) {
			spin_unlock(&tpg->tpg_state_lock);
			continue;
		}
		spin_unlock(&tpg->tpg_state_lock);
		spin_unlock(&tiqn->tiqn_tpg_lock);

		iscsi_tpg_del_portal_group(tiqn, tpg, 1);

		spin_lock(&tiqn->tiqn_tpg_lock);
	}
	spin_unlock(&tiqn->tiqn_tpg_lock);

	return;
}

/*	iscsi_remove_all_tpgs():
 *
 *
 */
extern void iscsi_remove_all_tpgs (void)
{
	iscsi_tiqn_t *tiqn;
	
	spin_lock(&iscsi_global->tiqn_lock);
	list_for_each_entry(tiqn, &iscsi_global->g_tiqn_list, tiqn_list) {
		spin_unlock(&iscsi_global->tiqn_lock);
		iscsi_remove_tpgs(tiqn);
		spin_lock(&iscsi_global->tiqn_lock);
	}
	spin_unlock(&iscsi_global->tiqn_lock);

	return;
}
