/*******************************************************************************
 * Filename:  iscsi_target_tpg.c
 *
 * This file contains iSCSI Target Portal Group related functions.
 *
 * Copyright (c) 2002, 2003, 2004, 2005 PyX Technologies, Inc.
 * Copyright (c) 2005, 2006, 2007 SBE, Inc.
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
 ******************************************************************************/

#include <linux/net.h>
#include <linux/string.h>
#include <linux/timer.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/smp_lock.h>
#include <linux/in.h>
#include <linux/ctype.h>
#include <net/sock.h>
#include <net/tcp.h>
#include <scsi/scsi.h>
#include <scsi/scsi_cmnd.h>

#include <iscsi_debug.h>
#include <iscsi_protocol.h>

#include <target/target_core_base.h>
#include <target/target_core_transport.h>
#include <target/target_core_fabric_ops.h>
#include <target/target_core_configfs.h>
#include <target/target_core_tpg.h>

#include <iscsi_target_core.h>
#include <iscsi_target_device.h>
#include <iscsi_target_erl0.h>
#include <iscsi_target_login.h>
#include <iscsi_target_nodeattrib.h>
#include <iscsi_target_tpg.h>
#include <iscsi_target_util.h>
#include <iscsi_target.h>
#include <iscsi_parameters.h>

char *lio_tpg_get_endpoint_wwn(struct se_portal_group *se_tpg)
{
	struct iscsi_portal_group *tpg =
			(struct iscsi_portal_group *)se_tpg->se_tpg_fabric_ptr;

	return &tpg->tpg_tiqn->tiqn[0];
}

u16 lio_tpg_get_tag(struct se_portal_group *se_tpg)
{
	struct iscsi_portal_group *tpg =
			(struct iscsi_portal_group *)se_tpg->se_tpg_fabric_ptr;

	return tpg->tpgt;
}

u32 lio_tpg_get_default_depth(struct se_portal_group *se_tpg)
{
	struct iscsi_portal_group *tpg =
			(struct iscsi_portal_group *)se_tpg->se_tpg_fabric_ptr;

	return ISCSI_TPG_ATTRIB(tpg)->default_cmdsn_depth;
}

int lio_tpg_check_demo_mode(struct se_portal_group *se_tpg)
{
	struct iscsi_portal_group *tpg =
			 (struct iscsi_portal_group *)se_tpg->se_tpg_fabric_ptr;

	return ISCSI_TPG_ATTRIB(tpg)->generate_node_acls;
}

int lio_tpg_check_demo_mode_cache(struct se_portal_group *se_tpg)
{
	struct iscsi_portal_group *tpg =
			(struct iscsi_portal_group *)se_tpg->se_tpg_fabric_ptr;

	return ISCSI_TPG_ATTRIB(tpg)->cache_dynamic_acls;
}

int lio_tpg_check_demo_mode_write_protect(struct se_portal_group *se_tpg)
{
	struct iscsi_portal_group *tpg =
			(struct iscsi_portal_group *)se_tpg->se_tpg_fabric_ptr;

	return ISCSI_TPG_ATTRIB(tpg)->demo_mode_write_protect;
}

int lio_tpg_check_prod_mode_write_protect(struct se_portal_group *se_tpg)
{
	struct iscsi_portal_group *tpg =
			(struct iscsi_portal_group *)se_tpg->se_tpg_fabric_ptr;

	return ISCSI_TPG_ATTRIB(tpg)->prod_mode_write_protect;
}

struct se_node_acl *lio_tpg_alloc_fabric_acl(
	struct se_portal_group *se_tpg)
{
	struct iscsi_node_acl *acl;

	acl = kzalloc(sizeof(struct iscsi_node_acl), GFP_KERNEL);
	if (!(acl)) {
		printk(KERN_ERR "Unable to allocate memory for struct iscsi_node_acl\n");
		return NULL;
	}

	return &acl->se_node_acl;
}

void lio_tpg_release_fabric_acl(
	struct se_portal_group *se_tpg,
	struct se_node_acl *se_acl)
{
	struct iscsi_node_acl *acl = container_of(se_acl,
			struct iscsi_node_acl, se_node_acl);
	kfree(acl);
}

/*
 * Called with spin_lock_bh(struct se_portal_group->session_lock) held..
 *
 * Also, this function calls iscsi_inc_session_usage_count() on the
 * struct iscsi_session in question.
 */
int lio_tpg_shutdown_session(struct se_session *se_sess)
{
	struct iscsi_session *sess = (struct iscsi_session *)se_sess->fabric_sess_ptr;

	spin_lock(&sess->conn_lock);
	if (atomic_read(&sess->session_fall_back_to_erl0) ||
	    atomic_read(&sess->session_logout) ||
	    (sess->time2retain_timer_flags & T2R_TF_EXPIRED)) {
		spin_unlock(&sess->conn_lock);
		return 0;
	}
	atomic_set(&sess->session_reinstatement, 1);
	spin_unlock(&sess->conn_lock);

	iscsi_inc_session_usage_count(sess);
	iscsi_stop_time2retain_timer(sess);

	return 1;
}

/*
 * Calls iscsi_dec_session_usage_count() as inverse of
 * lio_tpg_shutdown_session()
 */
void lio_tpg_close_session(struct se_session *se_sess)
{
	struct iscsi_session *sess = (struct iscsi_session *)se_sess->fabric_sess_ptr;
	/*
	 * If the iSCSI Session for the iSCSI Initiator Node exists,
	 * forcefully shutdown the iSCSI NEXUS.
	 */
	iscsi_stop_session(sess, 1, 1);
	iscsi_dec_session_usage_count(sess);
	iscsi_close_session(sess);
}

void lio_tpg_stop_session(struct se_session *se_sess, int sess_sleep, int conn_sleep)
{
	struct iscsi_session *sess = (struct iscsi_session *)se_sess->fabric_sess_ptr;

	iscsi_stop_session(sess, sess_sleep, conn_sleep);
}

void lio_tpg_fall_back_to_erl0(struct se_session *se_sess)
{
	struct iscsi_session *sess = (struct iscsi_session *)se_sess->fabric_sess_ptr;

	iscsi_fall_back_to_erl0(sess);
}

u32 lio_tpg_get_inst_index(struct se_portal_group *se_tpg)
{
	struct iscsi_portal_group *tpg =
			(struct iscsi_portal_group *)se_tpg->se_tpg_fabric_ptr;

	return tpg->tpg_tiqn->tiqn_index;
}

void lio_set_default_node_attributes(struct se_node_acl *se_acl)
{
	struct iscsi_node_acl *acl = container_of(se_acl, struct iscsi_node_acl,
				se_node_acl);

	ISCSI_NODE_ATTRIB(acl)->nacl = acl;
	iscsi_set_default_node_attribues(acl);
}

struct iscsi_portal_group *core_alloc_portal_group(struct iscsi_tiqn *tiqn, u16 tpgt)
{
	struct iscsi_portal_group *tpg;

	tpg = kmem_cache_zalloc(lio_tpg_cache, GFP_KERNEL);
	if (!(tpg)) {
		printk(KERN_ERR "Unable to get tpg from lio_tpg_cache\n");
		return NULL;
	}

	tpg->tpgt = tpgt;
	tpg->tpg_state = TPG_STATE_FREE;
	tpg->tpg_tiqn = tiqn;
	INIT_LIST_HEAD(&tpg->tpg_gnp_list);
	INIT_LIST_HEAD(&tpg->g_tpg_list);
	INIT_LIST_HEAD(&tpg->tpg_list);
	init_MUTEX(&tpg->tpg_access_sem);
	init_MUTEX(&tpg->np_login_sem);
	spin_lock_init(&tpg->tpg_state_lock);
	spin_lock_init(&tpg->tpg_np_lock);

	return tpg;
}

static void iscsi_set_default_tpg_attribs(struct iscsi_portal_group *);

int core_load_discovery_tpg(void)
{
	struct iscsi_param *param;
	struct iscsi_portal_group *tpg;
	int ret;

	tpg = core_alloc_portal_group(NULL, 1);
	if (!(tpg)) {
		printk(KERN_ERR "Unable to allocate struct iscsi_portal_group\n");
		return -1;
	}

	ret = core_tpg_register(
			&lio_target_fabric_configfs->tf_ops,
			NULL, &tpg->tpg_se_tpg, (void *)tpg,
			TRANSPORT_TPG_TYPE_DISCOVERY);
	if (ret < 0) {
		kfree(tpg);
		return -1;
	}

	tpg->sid = 1; /* First Assigned LIO Session ID */
	iscsi_set_default_tpg_attribs(tpg);

	if (iscsi_create_default_params(&tpg->param_list) < 0)
		goto out;
	/*
	 * By default we disable authentication for discovery sessions,
	 * this can be changed with:
	 *
	 * /sys/kernel/config/target/iscsi/discovery_auth/enforce_discovery_auth
	 */
	param = iscsi_find_param_from_key(AUTHMETHOD, tpg->param_list);
	if (!(param))
		goto out;

	if (iscsi_update_param_value(param, "CHAP,None") < 0)
		goto out;

	tpg->tpg_attrib.authentication = 0;

	spin_lock(&tpg->tpg_state_lock);
	tpg->tpg_state  = TPG_STATE_ACTIVE;
	spin_unlock(&tpg->tpg_state_lock);

	iscsi_global->discovery_tpg = tpg;
	printk(KERN_INFO "CORE[0] - Allocated Discovery TPG\n");

	return 0;
out:
	if (tpg->sid == 1)
		core_tpg_deregister(&tpg->tpg_se_tpg);
	kfree(tpg);
	return -1;
}

void core_release_discovery_tpg(void)
{
	struct iscsi_portal_group *tpg = iscsi_global->discovery_tpg;

	if (!(tpg))
		return;

	core_tpg_deregister(&tpg->tpg_se_tpg);

	kmem_cache_free(lio_tpg_cache, tpg);
	iscsi_global->discovery_tpg = NULL;
}

struct iscsi_portal_group *core_get_tpg_from_np(
	struct iscsi_tiqn *tiqn,
	struct iscsi_np *np)
{
	struct iscsi_portal_group *tpg = NULL;
	struct iscsi_tpg_np *tpg_np;

	spin_lock(&tiqn->tiqn_tpg_lock);
	list_for_each_entry(tpg, &tiqn->tiqn_tpg_list, tpg_list) {

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
				return tpg;
			}
		}
		spin_unlock(&tpg->tpg_np_lock);
	}
	spin_unlock(&tiqn->tiqn_tpg_lock);

	return NULL;
}

int iscsi_get_tpg(
	struct iscsi_portal_group *tpg)
{
	int ret;

	ret = down_interruptible(&tpg->tpg_access_sem);
	return ((ret != 0) || signal_pending(current)) ? -1 : 0;
}

/*	iscsi_put_tpg():
 *
 *
 */
void iscsi_put_tpg(struct iscsi_portal_group *tpg)
{
	up(&tpg->tpg_access_sem);
}

static void iscsi_clear_tpg_np_login_thread(
	struct iscsi_tpg_np *tpg_np,
	struct iscsi_portal_group *tpg,
	int shutdown)
{
	if (!tpg_np->tpg_np) {
		printk(KERN_ERR "struct iscsi_tpg_np->tpg_np is NULL!\n");
		return;
	}

	core_reset_np_thread(tpg_np->tpg_np, tpg_np, tpg, shutdown);
	return;
}

/*	iscsi_clear_tpg_np_login_threads():
 *
 *
 */
void iscsi_clear_tpg_np_login_threads(
	struct iscsi_portal_group *tpg,
	int shutdown)
{
	struct iscsi_tpg_np *tpg_np;

	spin_lock(&tpg->tpg_np_lock);
	list_for_each_entry(tpg_np, &tpg->tpg_gnp_list, tpg_np_list) {
		if (!tpg_np->tpg_np) {
			printk(KERN_ERR "struct iscsi_tpg_np->tpg_np is NULL!\n");
			continue;
		}
		spin_unlock(&tpg->tpg_np_lock);
		iscsi_clear_tpg_np_login_thread(tpg_np, tpg, shutdown);
		spin_lock(&tpg->tpg_np_lock);
	}
	spin_unlock(&tpg->tpg_np_lock);
}

/*	iscsi_tpg_dump_params():
 *
 *
 */
void iscsi_tpg_dump_params(struct iscsi_portal_group *tpg)
{
	iscsi_print_params(tpg->param_list);
}

/*	iscsi_tpg_free_network_portals():
 *
 *
 */
static void iscsi_tpg_free_network_portals(struct iscsi_portal_group *tpg)
{
	struct iscsi_np *np;
	struct iscsi_tpg_np *tpg_np, *tpg_np_t;
	unsigned char buf_ipv4[IPV4_BUF_SIZE], *ip;

	spin_lock(&tpg->tpg_np_lock);
	list_for_each_entry_safe(tpg_np, tpg_np_t, &tpg->tpg_gnp_list,
				tpg_np_list) {
		np = tpg_np->tpg_np;
		list_del(&tpg_np->tpg_np_list);
		tpg->num_tpg_nps--;
		tpg->tpg_tiqn->tiqn_num_tpg_nps--;

		if (np->np_net_size == IPV6_ADDRESS_SPACE)
			ip = &np->np_ipv6[0];
		else {
			memset(buf_ipv4, 0, IPV4_BUF_SIZE);
			iscsi_ntoa2(buf_ipv4, np->np_ipv4);
			ip = &buf_ipv4[0];
		}

		printk(KERN_INFO "CORE[%s] - Removed Network Portal: %s:%hu,%hu"
			" on %s on network device: %s\n", tpg->tpg_tiqn->tiqn,
			ip, np->np_port, tpg->tpgt,
			(np->np_network_transport == ISCSI_TCP) ?
			"TCP" : "SCTP",  (strlen(np->np_net_dev)) ?
			(char *)np->np_net_dev : "None");

		tpg_np->tpg_np = NULL;
		kfree(tpg_np);
		spin_unlock(&tpg->tpg_np_lock);

		spin_lock(&np->np_state_lock);
		np->np_exports--;
		printk(KERN_INFO "CORE[%s]_TPG[%hu] - Decremented np_exports to %u\n",
			tpg->tpg_tiqn->tiqn, tpg->tpgt, np->np_exports);
		spin_unlock(&np->np_state_lock);

		spin_lock(&tpg->tpg_np_lock);
	}
	spin_unlock(&tpg->tpg_np_lock);
}

/*	iscsi_set_default_tpg_attribs():
 *
 *
 */
static void iscsi_set_default_tpg_attribs(struct iscsi_portal_group *tpg)
{
	struct iscsi_tpg_attrib *a = &tpg->tpg_attrib;

	a->authentication = TA_AUTHENTICATION;
	a->login_timeout = TA_LOGIN_TIMEOUT;
	a->netif_timeout = TA_NETIF_TIMEOUT;
	a->default_cmdsn_depth = TA_DEFAULT_CMDSN_DEPTH;
	a->generate_node_acls = TA_GENERATE_NODE_ACLS;
	a->cache_dynamic_acls = TA_CACHE_DYNAMIC_ACLS;
	a->demo_mode_write_protect = TA_DEMO_MODE_WRITE_PROTECT;
	a->prod_mode_write_protect = TA_PROD_MODE_WRITE_PROTECT;
	a->cache_core_nps = TA_CACHE_CORE_NPS;
}

/*	iscsi_tpg_add_portal_group():
 *
 *
 */
int iscsi_tpg_add_portal_group(struct iscsi_tiqn *tiqn, struct iscsi_portal_group *tpg)
{
	if (tpg->tpg_state != TPG_STATE_FREE) {
		printk(KERN_ERR "Unable to add iSCSI Target Portal Group: %d"
			" while not in TPG_STATE_FREE state.\n", tpg->tpgt);
		return -EEXIST;
	}
	iscsi_set_default_tpg_attribs(tpg);

	if (iscsi_create_default_params(&tpg->param_list) < 0)
		goto err_out;

	ISCSI_TPG_ATTRIB(tpg)->tpg = tpg;

	spin_lock(&tpg->tpg_state_lock);
	tpg->tpg_state	= TPG_STATE_INACTIVE;
	spin_unlock(&tpg->tpg_state_lock);

	spin_lock(&tiqn->tiqn_tpg_lock);
	list_add_tail(&tpg->tpg_list, &tiqn->tiqn_tpg_list);
	tiqn->tiqn_ntpgs++;
	printk(KERN_INFO "CORE[%s]_TPG[%hu] - Added iSCSI Target Portal Group\n",
			tiqn->tiqn, tpg->tpgt);
	spin_unlock(&tiqn->tiqn_tpg_lock);

	spin_lock_bh(&iscsi_global->g_tpg_lock);
	list_add_tail(&tpg->g_tpg_list, &iscsi_global->g_tpg_list);
	spin_unlock_bh(&iscsi_global->g_tpg_lock);

	return 0;
err_out:
	if (tpg->param_list) {
		iscsi_release_param_list(tpg->param_list);
		tpg->param_list = NULL;
	}
	kfree(tpg);
	return -ENOMEM;
}

int iscsi_tpg_del_portal_group(
	struct iscsi_tiqn *tiqn,
	struct iscsi_portal_group *tpg,
	int force)
{
	u8 old_state = tpg->tpg_state;

	spin_lock(&tpg->tpg_state_lock);
	tpg->tpg_state = TPG_STATE_INACTIVE;
	spin_unlock(&tpg->tpg_state_lock);

	iscsi_clear_tpg_np_login_threads(tpg, 1);

	if (iscsi_release_sessions_for_tpg(tpg, force) < 0) {
		printk(KERN_ERR "Unable to delete iSCSI Target Portal Group:"
			" %hu while active sessions exist, and force=0\n",
			tpg->tpgt);
		tpg->tpg_state = old_state;
		return -EPERM;
	}

	core_tpg_clear_object_luns(&tpg->tpg_se_tpg);
	iscsi_tpg_free_network_portals(tpg);

	spin_lock_bh(&iscsi_global->g_tpg_lock);
	list_del(&tpg->g_tpg_list);
	spin_unlock_bh(&iscsi_global->g_tpg_lock);

	if (tpg->param_list) {
		iscsi_release_param_list(tpg->param_list);
		tpg->param_list = NULL;
	}

	core_tpg_deregister(&tpg->tpg_se_tpg);
//	tpg->tpg_se_tpg = NULL;

	spin_lock(&tpg->tpg_state_lock);
	tpg->tpg_state = TPG_STATE_FREE;
	spin_unlock(&tpg->tpg_state_lock);

	spin_lock(&tiqn->tiqn_tpg_lock);
	tiqn->tiqn_ntpgs--;
	list_del(&tpg->tpg_list);
	spin_unlock(&tiqn->tiqn_tpg_lock);

	printk(KERN_INFO "CORE[%s]_TPG[%hu] - Deleted iSCSI Target Portal Group\n",
			tiqn->tiqn, tpg->tpgt);

	kmem_cache_free(lio_tpg_cache, tpg);
	return 0;
}

/*	iscsi_tpg_enable_portal_group():
 *
 *
 */
int iscsi_tpg_enable_portal_group(struct iscsi_portal_group *tpg)
{
	struct iscsi_param *param;
	struct iscsi_tiqn *tiqn = tpg->tpg_tiqn;

	spin_lock(&tpg->tpg_state_lock);
	if (tpg->tpg_state == TPG_STATE_ACTIVE) {
		printk(KERN_ERR "iSCSI target portal group: %hu is already"
			" active, ignoring request.\n", tpg->tpgt);
		spin_unlock(&tpg->tpg_state_lock);
		return -EINVAL;
	}
	/*
	 * Make sure that AuthMethod does not contain None as an option
	 * unless explictly disabled.  Set the default to CHAP if authentication
	 * is enforced (as per default), and remove the NONE option.
	 */
	param = iscsi_find_param_from_key(AUTHMETHOD, tpg->param_list);
	if (!(param)) {
		spin_unlock(&tpg->tpg_state_lock);
		return -ENOMEM;
	}

	if (ISCSI_TPG_ATTRIB(tpg)->authentication) {
		if (!strcmp(param->value, NONE))
			if (iscsi_update_param_value(param, CHAP) < 0) {
				spin_unlock(&tpg->tpg_state_lock);
				return -ENOMEM;
			}
		if (iscsi_ta_authentication(tpg, 1) < 0) {
			spin_unlock(&tpg->tpg_state_lock);
			return -ENOMEM;
		}
	}

	tpg->tpg_state = TPG_STATE_ACTIVE;
	spin_unlock(&tpg->tpg_state_lock);

	spin_lock(&tiqn->tiqn_tpg_lock);
	tiqn->tiqn_active_tpgs++;
	printk(KERN_INFO "iSCSI_TPG[%hu] - Enabled iSCSI Target Portal Group\n",
			tpg->tpgt);
	spin_unlock(&tiqn->tiqn_tpg_lock);

	return 0;
}

/*	iscsi_tpg_disable_portal_group():
 *
 *
 */
int iscsi_tpg_disable_portal_group(struct iscsi_portal_group *tpg, int force)
{
	struct iscsi_tiqn *tiqn;
	u8 old_state = tpg->tpg_state;

	spin_lock(&tpg->tpg_state_lock);
	if (tpg->tpg_state == TPG_STATE_INACTIVE) {
		printk(KERN_ERR "iSCSI Target Portal Group: %hu is already"
			" inactive, ignoring request.\n", tpg->tpgt);
		spin_unlock(&tpg->tpg_state_lock);
		return -EINVAL;
	}
	tpg->tpg_state = TPG_STATE_INACTIVE;
	spin_unlock(&tpg->tpg_state_lock);

	iscsi_clear_tpg_np_login_threads(tpg, 0);

	if (iscsi_release_sessions_for_tpg(tpg, force) < 0) {
		spin_lock(&tpg->tpg_state_lock);
		tpg->tpg_state = old_state;
		spin_unlock(&tpg->tpg_state_lock);
		printk(KERN_ERR "Unable to disable iSCSI Target Portal Group:"
			" %hu while active sessions exist, and force=0\n",
			tpg->tpgt);
		return -EPERM;
	}

	tiqn = tpg->tpg_tiqn;
	if (!(tiqn) || (tpg == iscsi_global->discovery_tpg))
		return 0;

	spin_lock(&tiqn->tiqn_tpg_lock);
	tiqn->tiqn_active_tpgs--;
	printk(KERN_INFO "iSCSI_TPG[%hu] - Disabled iSCSI Target Portal Group\n",
			tpg->tpgt);
	spin_unlock(&tiqn->tiqn_tpg_lock);

	return 0;
}

struct iscsi_node_attrib *iscsi_tpg_get_node_attrib(
	struct iscsi_session *sess)
{
	struct se_session *se_sess = sess->se_sess;
	struct se_node_acl *se_nacl = se_sess->se_node_acl;
	struct iscsi_node_acl *acl = container_of(se_nacl, struct iscsi_node_acl,
					se_node_acl);

	return &acl->node_attrib;
}

struct iscsi_tpg_np *iscsi_tpg_locate_child_np(
	struct iscsi_tpg_np *tpg_np,
	int network_transport)
{
	struct iscsi_tpg_np *tpg_np_child, *tpg_np_child_tmp;

	spin_lock(&tpg_np->tpg_np_parent_lock);
	list_for_each_entry_safe(tpg_np_child, tpg_np_child_tmp,
			&tpg_np->tpg_np_parent_list, tpg_np_child_list) {
		if (tpg_np_child->tpg_np->np_network_transport ==
				network_transport) {
			spin_unlock(&tpg_np->tpg_np_parent_lock);
			return tpg_np_child;
		}
	}
	spin_unlock(&tpg_np->tpg_np_parent_lock);

	return NULL;
}

/*	iscsi_tpg_add_network_portal():
 *
 *
 */
struct iscsi_tpg_np *iscsi_tpg_add_network_portal(
	struct iscsi_portal_group *tpg,
	struct iscsi_np_addr *np_addr,
	struct iscsi_tpg_np *tpg_np_parent,
	int network_transport)
{
	struct iscsi_np *np;
	struct iscsi_tpg_np *tpg_np;
	char *ip_buf;
	void *ip;
	int ret = 0;
	unsigned char buf_ipv4[IPV4_BUF_SIZE];

	if (np_addr->np_flags & NPF_NET_IPV6) {
		ip_buf = (char *)&np_addr->np_ipv6[0];
		ip = (void *)&np_addr->np_ipv6[0];
	} else {
		memset(buf_ipv4, 0, IPV4_BUF_SIZE);
		iscsi_ntoa2(buf_ipv4, np_addr->np_ipv4);
		ip_buf = &buf_ipv4[0];
		ip = (void *)&np_addr->np_ipv4;
	}
	/*
	 * If the Network Portal does not currently exist, start it up now.
	 */
	np = core_get_np(ip, np_addr->np_port, network_transport);
	if (!(np)) {
		np = core_add_np(np_addr, network_transport, &ret);
		if (!(np))
			return ERR_PTR(ret);
	}

	tpg_np = kzalloc(sizeof(struct iscsi_tpg_np), GFP_KERNEL);
	if (!(tpg_np)) {
		printk(KERN_ERR "Unable to allocate memory for"
				" struct iscsi_tpg_np.\n");
		return ERR_PTR(-ENOMEM);
	}
	tpg_np->tpg_np_index	= iscsi_get_new_index(ISCSI_PORTAL_INDEX);
	INIT_LIST_HEAD(&tpg_np->tpg_np_list);
	INIT_LIST_HEAD(&tpg_np->tpg_np_child_list);
	INIT_LIST_HEAD(&tpg_np->tpg_np_parent_list);
	spin_lock_init(&tpg_np->tpg_np_parent_lock);
	tpg_np->tpg_np		= np;
	tpg_np->tpg		= tpg;

	spin_lock(&tpg->tpg_np_lock);
	list_add_tail(&tpg_np->tpg_np_list, &tpg->tpg_gnp_list);
	tpg->num_tpg_nps++;
	if (tpg->tpg_tiqn)
		tpg->tpg_tiqn->tiqn_num_tpg_nps++;
	spin_unlock(&tpg->tpg_np_lock);

	if (tpg_np_parent) {
		tpg_np->tpg_np_parent = tpg_np_parent;
		spin_lock(&tpg_np_parent->tpg_np_parent_lock);
		list_add_tail(&tpg_np->tpg_np_child_list,
			&tpg_np_parent->tpg_np_parent_list);
		spin_unlock(&tpg_np_parent->tpg_np_parent_lock);
	}

	printk(KERN_INFO "CORE[%s] - Added Network Portal: %s:%hu,%hu on %s on"
		" network device: %s\n", tpg->tpg_tiqn->tiqn, ip_buf,
		np->np_port, tpg->tpgt,
		(np->np_network_transport == ISCSI_TCP) ?
		"TCP" : "SCTP", (strlen(np->np_net_dev)) ?
		(char *)np->np_net_dev : "None");

	spin_lock(&np->np_state_lock);
	np->np_exports++;
	printk(KERN_INFO "CORE[%s]_TPG[%hu] - Incremented np_exports to %u\n",
		tpg->tpg_tiqn->tiqn, tpg->tpgt, np->np_exports);
	spin_unlock(&np->np_state_lock);

	return tpg_np;
}

static int iscsi_tpg_release_np(
	struct iscsi_tpg_np *tpg_np,
	struct iscsi_portal_group *tpg,
	struct iscsi_np *np)
{
	char *ip;
	char buf_ipv4[IPV4_BUF_SIZE];

	if (np->np_net_size == IPV6_ADDRESS_SPACE)
		ip = &np->np_ipv6[0];
	else {
		memset(buf_ipv4, 0, IPV4_BUF_SIZE);
		iscsi_ntoa2(buf_ipv4, np->np_ipv4);
		ip = &buf_ipv4[0];
	}

	iscsi_clear_tpg_np_login_thread(tpg_np, tpg, 1);

	printk(KERN_INFO "CORE[%s] - Removed Network Portal: %s:%hu,%hu on %s"
		" on network device: %s\n", tpg->tpg_tiqn->tiqn, ip,
		np->np_port, tpg->tpgt,
		(np->np_network_transport == ISCSI_TCP) ?
		"TCP" : "SCTP",  (strlen(np->np_net_dev)) ?
		(char *)np->np_net_dev : "None");

	tpg_np->tpg_np = NULL;
	tpg_np->tpg = NULL;
	kfree(tpg_np);

	/*
	 * Shutdown Network Portal when last TPG reference is released.
	 */
	spin_lock(&np->np_state_lock);
	if ((--np->np_exports == 0) && !(ISCSI_TPG_ATTRIB(tpg)->cache_core_nps))
		atomic_set(&np->np_shutdown, 1);
	printk(KERN_INFO "CORE[%s]_TPG[%hu] - Decremented np_exports to %u\n",
		tpg->tpg_tiqn->tiqn, tpg->tpgt, np->np_exports);
	spin_unlock(&np->np_state_lock);

	if (atomic_read(&np->np_shutdown))
		core_del_np(np);

	return 0;
}

/*	iscsi_tpg_del_network_portal():
 *
 *
 */
int iscsi_tpg_del_network_portal(
	struct iscsi_portal_group *tpg,
	struct iscsi_tpg_np *tpg_np)
{
	struct iscsi_np *np;
	struct iscsi_tpg_np *tpg_np_child, *tpg_np_child_tmp;
	int ret = 0;

	np = tpg_np->tpg_np;
	if (!(np)) {
		printk(KERN_ERR "Unable to locate struct iscsi_np from"
				" struct iscsi_tpg_np\n");
		return -EINVAL;
	}

	if (!tpg_np->tpg_np_parent) {
		/*
		 * We are the parent tpg network portal.  Release all of the
		 * child tpg_np's (eg: the non ISCSI_TCP ones) on our parent
		 * list first.
		 */
		list_for_each_entry_safe(tpg_np_child, tpg_np_child_tmp,
				&tpg_np->tpg_np_parent_list,
				tpg_np_child_list) {
			ret = iscsi_tpg_del_network_portal(tpg, tpg_np_child);
			if (ret < 0)
				printk(KERN_ERR "iscsi_tpg_del_network_portal()"
					" failed: %d\n", ret);
		}
	} else {
		/*
		 * We are not the parent ISCSI_TCP tpg network portal.  Release
		 * our own network portals from the child list.
		 */
		spin_lock(&tpg_np->tpg_np_parent->tpg_np_parent_lock);
		list_del(&tpg_np->tpg_np_child_list);
		spin_unlock(&tpg_np->tpg_np_parent->tpg_np_parent_lock);
	}

	spin_lock(&tpg->tpg_np_lock);
	list_del(&tpg_np->tpg_np_list);
	tpg->num_tpg_nps--;
	if (tpg->tpg_tiqn)
		tpg->tpg_tiqn->tiqn_num_tpg_nps--;
	spin_unlock(&tpg->tpg_np_lock);

	return iscsi_tpg_release_np(tpg_np, tpg, np);
}

/*	iscsi_tpg_set_initiator_node_queue_depth():
 *
 *
 */
int iscsi_tpg_set_initiator_node_queue_depth(
	struct iscsi_portal_group *tpg,
	unsigned char *initiatorname,
	u32 queue_depth,
	int force)
{
	return core_tpg_set_initiator_node_queue_depth(&tpg->tpg_se_tpg,
		initiatorname, queue_depth, force);
}

/*	iscsi_ta_authentication():
 *
 *
 */
int iscsi_ta_authentication(struct iscsi_portal_group *tpg, u32 authentication)
{
	unsigned char buf1[256], buf2[256], *none = NULL;
	int len;
	struct iscsi_param *param;
	struct iscsi_tpg_attrib *a = &tpg->tpg_attrib;

	if ((authentication != 1) && (authentication != 0)) {
		printk(KERN_ERR "Illegal value for authentication parameter:"
			" %u, ignoring request.\n", authentication);
		return -1;
	}

	memset(buf1, 0, sizeof(buf1));
	memset(buf2, 0, sizeof(buf2));

	param = iscsi_find_param_from_key(AUTHMETHOD, tpg->param_list);
	if (!(param))
		return -EINVAL;

	if (authentication) {
		snprintf(buf1, sizeof(buf1), "%s", param->value);
		none = strstr(buf1, NONE);
		if (!(none))
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
			return -EINVAL;
	} else {
		snprintf(buf1, sizeof(buf1), "%s", param->value);
		none = strstr(buf1, NONE);
		if ((none))
			goto out;
		strncat(buf1, ",", strlen(","));
		strncat(buf1, NONE, strlen(NONE));
		if (iscsi_update_param_value(param, buf1) < 0)
			return -EINVAL;
	}

out:
	a->authentication = authentication;
	printk(KERN_INFO "%s iSCSI Authentication Methods for TPG: %hu.\n",
		a->authentication ? "Enforcing" : "Disabling", tpg->tpgt);

	return 0;
}

/*	iscsi_ta_login_timeout():
 *
 *
 */
int iscsi_ta_login_timeout(
	struct iscsi_portal_group *tpg,
	u32 login_timeout)
{
	struct iscsi_tpg_attrib *a = &tpg->tpg_attrib;

	if (login_timeout > TA_LOGIN_TIMEOUT_MAX) {
		printk(KERN_ERR "Requested Login Timeout %u larger than maximum"
			" %u\n", login_timeout, TA_LOGIN_TIMEOUT_MAX);
		return -EINVAL;
	} else if (login_timeout < TA_LOGIN_TIMEOUT_MIN) {
		printk(KERN_ERR "Requested Logout Timeout %u smaller than"
			" minimum %u\n", login_timeout, TA_LOGIN_TIMEOUT_MIN);
		return -EINVAL;
	}

	a->login_timeout = login_timeout;
	printk(KERN_INFO "Set Logout Timeout to %u for Target Portal Group"
		" %hu\n", a->login_timeout, tpg->tpgt);

	return 0;
}

/*	iscsi_ta_netif_timeout():
 *
 *
 */
int iscsi_ta_netif_timeout(
	struct iscsi_portal_group *tpg,
	u32 netif_timeout)
{
	struct iscsi_tpg_attrib *a = &tpg->tpg_attrib;

	if (netif_timeout > TA_NETIF_TIMEOUT_MAX) {
		printk(KERN_ERR "Requested Network Interface Timeout %u larger"
			" than maximum %u\n", netif_timeout,
				TA_NETIF_TIMEOUT_MAX);
		return -EINVAL;
	} else if (netif_timeout < TA_NETIF_TIMEOUT_MIN) {
		printk(KERN_ERR "Requested Network Interface Timeout %u smaller"
			" than minimum %u\n", netif_timeout,
				TA_NETIF_TIMEOUT_MIN);
		return -EINVAL;
	}

	a->netif_timeout = netif_timeout;
	printk(KERN_INFO "Set Network Interface Timeout to %u for"
		" Target Portal Group %hu\n", a->netif_timeout, tpg->tpgt);

	return 0;
}

int iscsi_ta_generate_node_acls(
	struct iscsi_portal_group *tpg,
	u32 flag)
{
	struct iscsi_tpg_attrib *a = &tpg->tpg_attrib;

	if ((flag != 0) && (flag != 1)) {
		printk(KERN_ERR "Illegal value %d\n", flag);
		return -EINVAL;
	}

	a->generate_node_acls = flag;
	printk(KERN_INFO "iSCSI_TPG[%hu] - Generate Initiator Portal Group ACLs: %s\n",
		tpg->tpgt, (a->generate_node_acls) ? "Enabled" : "Disabled");

	return 0;
}

int iscsi_ta_default_cmdsn_depth(
	struct iscsi_portal_group *tpg,
	u32 tcq_depth)
{
	struct iscsi_tpg_attrib *a = &tpg->tpg_attrib;

	if (tcq_depth > TA_DEFAULT_CMDSN_DEPTH_MAX) {
		printk(KERN_ERR "Requested Default Queue Depth: %u larger"
			" than maximum %u\n", tcq_depth,
				TA_DEFAULT_CMDSN_DEPTH_MAX);
		return -EINVAL;
	} else if (tcq_depth < TA_DEFAULT_CMDSN_DEPTH_MIN) {
		printk(KERN_ERR "Requested Default Queue Depth: %u smaller"
			" than minimum %u\n", tcq_depth,
				TA_DEFAULT_CMDSN_DEPTH_MIN);
		return -EINVAL;
	}

	a->default_cmdsn_depth = tcq_depth;
	printk(KERN_INFO "iSCSI_TPG[%hu] - Set Default CmdSN TCQ Depth to %u\n",
		tpg->tpgt, a->default_cmdsn_depth);

	return 0;
}

int iscsi_ta_cache_dynamic_acls(
	struct iscsi_portal_group *tpg,
	u32 flag)
{
	struct iscsi_tpg_attrib *a = &tpg->tpg_attrib;

	if ((flag != 0) && (flag != 1)) {
		printk(KERN_ERR "Illegal value %d\n", flag);
		return -EINVAL;
	}

	a->cache_dynamic_acls = flag;
	printk(KERN_INFO "iSCSI_TPG[%hu] - Cache Dynamic Initiator Portal Group"
		" ACLs %s\n", tpg->tpgt, (a->cache_dynamic_acls) ?
		"Enabled" : "Disabled");

	return 0;
}

int iscsi_ta_demo_mode_write_protect(
	struct iscsi_portal_group *tpg,
	u32 flag)
{
	struct iscsi_tpg_attrib *a = &tpg->tpg_attrib;

	if ((flag != 0) && (flag != 1)) {
		printk(KERN_ERR "Illegal value %d\n", flag);
		return -EINVAL;
	}

	a->demo_mode_write_protect = flag;
	printk(KERN_INFO "iSCSI_TPG[%hu] - Demo Mode Write Protect bit: %s\n",
		tpg->tpgt, (a->demo_mode_write_protect) ? "ON" : "OFF");

	return 0;
}

int iscsi_ta_prod_mode_write_protect(
	struct iscsi_portal_group *tpg,
	u32 flag)
{
	struct iscsi_tpg_attrib *a = &tpg->tpg_attrib;

	if ((flag != 0) && (flag != 1)) {
		printk(KERN_ERR "Illegal value %d\n", flag);
		return -EINVAL;
	}

	a->prod_mode_write_protect = flag;
	printk(KERN_INFO "iSCSI_TPG[%hu] - Production Mode Write Protect bit:"
		" %s\n", tpg->tpgt, (a->prod_mode_write_protect) ?
		"ON" : "OFF");

	return 0;
}

void iscsi_disable_tpgs(struct iscsi_tiqn *tiqn)
{
	struct iscsi_portal_group *tpg;

	spin_lock(&tiqn->tiqn_tpg_lock);
	list_for_each_entry(tpg, &tiqn->tiqn_tpg_list, tpg_list) {

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
}

/*	iscsi_disable_all_tpgs():
 *
 *
 */
void iscsi_disable_all_tpgs(void)
{
	struct iscsi_tiqn *tiqn;

	spin_lock(&iscsi_global->tiqn_lock);
	list_for_each_entry(tiqn, &iscsi_global->g_tiqn_list, tiqn_list) {
		spin_unlock(&iscsi_global->tiqn_lock);
		iscsi_disable_tpgs(tiqn);
		spin_lock(&iscsi_global->tiqn_lock);
	}
	spin_unlock(&iscsi_global->tiqn_lock);
}

void iscsi_remove_tpgs(struct iscsi_tiqn *tiqn)
{
	struct iscsi_portal_group *tpg, *tpg_tmp;

	spin_lock(&tiqn->tiqn_tpg_lock);
	list_for_each_entry_safe(tpg, tpg_tmp, &tiqn->tiqn_tpg_list, tpg_list) {

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
}

/*	iscsi_remove_all_tpgs():
 *
 *
 */
void iscsi_remove_all_tpgs(void)
{
	struct iscsi_tiqn *tiqn;

	spin_lock(&iscsi_global->tiqn_lock);
	list_for_each_entry(tiqn, &iscsi_global->g_tiqn_list, tiqn_list) {
		spin_unlock(&iscsi_global->tiqn_lock);
		iscsi_remove_tpgs(tiqn);
		spin_lock(&iscsi_global->tiqn_lock);
	}
	spin_unlock(&iscsi_global->tiqn_lock);
}
