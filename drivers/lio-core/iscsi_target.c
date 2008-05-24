/********************************************************************************
 * Filename:  iscsi_target.c
 *
 * This file contains the main functions related to the iSCSI Target Core Driver.
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


#define ISCSI_TARGET_C

#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/version.h>
#include <linux/utsrelease.h>
#include <linux/init.h>
#include <linux/kmod.h>
#include <linux/net.h>
#include <linux/miscdevice.h>
#include <linux/string.h>
#include <linux/timer.h>
#include <linux/blkdev.h>
#include <linux/proc_fs.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/smp_lock.h>
#include <linux/in.h>
#include <linux/utsname.h>
#include <net/sock.h>
#include <net/tcp.h>

#include <iscsi_linux_os.h>
#include <iscsi_linux_defs.h>

#include <iscsi_debug.h>
#include <iscsi_lists.h>
#include <iscsi_protocol.h>
#include <iscsi_debug_opcodes.h>
#include <iscsi_target_core.h>
#include <iscsi_target_error.h>
#include <iscsi_target_ioctl.h>
#include <iscsi_target_ioctl_defs.h>
#include <iscsi_target_datain_values.h>
#include <iscsi_target_discovery.h>
#include <iscsi_target_erl0.h>
#include <iscsi_target_erl1.h>
#include <iscsi_target_erl2.h>
#include <iscsi_target_hba.h>
#include <iscsi_target_login.h>
#include <iscsi_target_tmr.h>
#include <iscsi_target_tpg.h>
#include <iscsi_target_transport.h>
#include <iscsi_target_util.h>

#include <iscsi_target_plugin.h>
#include <iscsi_target_feature_obj.h>
#include <iscsi_target_feature_plugins.h>
#include <iscsi_target_frontend_plugin.h>

#include <iscsi_target.h>
#include <iscsi_target_device.h>

#include <iscsi_crc.h>
#include <iscsi_parameters.h>
#include <iscsi_thread_queue.h>

#ifdef DEBUG_ERL
#include <iscsi_target_debugerl.h>
#endif /* DEBUG_ERL */

#ifdef SNMP_SUPPORT
#include <iscsi_target_mib.h>
#endif /* SNMP_SUPPORT */

#undef ISCSI_TARGET_C

iscsi_global_t *iscsi_global = NULL;

extern struct miscdevice iscsi_dev;

extern void register_iscsi_target_ioctl32(void);
extern void unregister_iscsi_target_ioctl32(void);
extern int iscsi_allocate_rl_cmd (iscsi_cmd_t *, unsigned char *, u64);
extern int iscsi_build_report_luns_response (iscsi_cmd_t *);
static void iscsi_rx_thread_wait_for_TCP (iscsi_conn_t *);

static int iscsi_target_detect (void);
static int iscsi_target_release (void);
static int iscsi_handle_immediate_data (iscsi_cmd_t *, unsigned char *buf, __u32);
static inline int iscsi_send_data_in (iscsi_cmd_t *, iscsi_conn_t *, iscsi_unmap_sg_t *, int *);
static inline int iscsi_send_logout_response (iscsi_cmd_t *, iscsi_conn_t *);
static inline int iscsi_send_nopin_response (iscsi_cmd_t *, iscsi_conn_t *);
static inline int iscsi_send_status (iscsi_cmd_t *, iscsi_conn_t *);
static int iscsi_send_task_mgt_rsp (iscsi_cmd_t *, iscsi_conn_t *);
static int iscsi_send_text_rsp (iscsi_cmd_t *, iscsi_conn_t *);
static int iscsi_send_reject (iscsi_cmd_t *, iscsi_conn_t *);
static int iscsi_logout_post_handler (iscsi_cmd_t *, iscsi_conn_t *);

/*
 * Legacy Mode, locate the first valid Target IQN.
 */
extern iscsi_tiqn_t *__core_get_default_tiqn (void)
{
	iscsi_tiqn_t *tiqn = NULL;

	list_for_each_entry(tiqn, &iscsi_global->g_tiqn_list, tiqn_list)
		break;

	if (!tiqn) {
		TRACE_ERROR("Unable to locate Default Target IQN\n");
		return(NULL);
	}

	return(tiqn);
}

extern iscsi_tiqn_t *core_get_default_tiqn (void)
{
	iscsi_tiqn_t *tiqn = NULL;

	spin_lock(&iscsi_global->tiqn_lock);
	list_for_each_entry(tiqn, &iscsi_global->g_tiqn_list, tiqn_list) {
		break;
	}
	spin_unlock(&iscsi_global->tiqn_lock);

	if (!tiqn) {
		TRACE_ERROR("Unable to locate Default Target IQN\n");
		return(NULL);
	}

	return(tiqn);
}

extern iscsi_tiqn_t *core_get_tiqn (unsigned char *buf)
{
	iscsi_tiqn_t *tiqn = NULL;

	if (!(strlen(buf)))
		return(core_get_default_tiqn());

	spin_lock(&iscsi_global->tiqn_lock);
	list_for_each_entry(tiqn, &iscsi_global->g_tiqn_list, tiqn_list) {
		if (!(strncmp(tiqn->tiqn, buf, strlen(tiqn->tiqn)))) {
			spin_unlock(&iscsi_global->tiqn_lock);
			return(tiqn);
		}
	}
	spin_unlock(&iscsi_global->tiqn_lock);

	return(NULL);
}

#warning FIXME: Add IQN format checks to core_add_tiqn()
extern iscsi_tiqn_t *core_add_tiqn (unsigned char *buf, int *ret)
{
	iscsi_tiqn_t *tiqn = NULL;

	if (strlen(buf) > ISCSI_TIQN_LEN) {
		TRACE_ERROR("Target IQN exceeds %d bytes\n", ISCSI_TIQN_LEN);
		*ret = -1;
		return(NULL);
	}

	spin_lock(&iscsi_global->tiqn_lock);
	list_for_each_entry(tiqn, &iscsi_global->g_tiqn_list, tiqn_list) {
		if (!(strncmp(tiqn->tiqn, buf, ISCSI_TIQN_LEN))) {
			TRACE_ERROR("Target IQN: %s already exists in Core\n",
				tiqn->tiqn);
			spin_unlock(&iscsi_global->tiqn_lock);
			*ret = -1;
			return(NULL);
		}
	}
	spin_unlock(&iscsi_global->tiqn_lock);

	if (!(tiqn = kmalloc(sizeof(iscsi_tiqn_t), GFP_KERNEL))) {
		TRACE_ERROR("Unable to allocate iscsi_tiqn_t\n");
		*ret = -1;
		return(NULL);
	}
	memset(tiqn, 0, sizeof(iscsi_tiqn_t));

	sprintf(tiqn->tiqn, "%s", buf);
	INIT_LIST_HEAD(&tiqn->tiqn_list);
	spin_lock_init(&tiqn->tiqn_tpg_lock);
#ifdef SNMP_SUPPORT
	spin_lock_init(&tiqn->sess_err_stats.lock);
	spin_lock_init(&tiqn->login_stats.lock);
	spin_lock_init(&tiqn->logout_stats.lock);
	tiqn->tiqn_index = get_new_index(ISCSI_INST_INDEX);
#endif
	if (!(tiqn->tiqn_tpg_list = kmalloc(
			(sizeof(iscsi_portal_group_t) * ISCSI_MAX_TPGS),
			GFP_KERNEL))) {
		TRACE_ERROR("Unable to allocate tiqn->tiqn_tpg_list\n");
		kfree(tiqn);
		*ret = -1;
		return(NULL);
	}
	memset(tiqn->tiqn_tpg_list, 0, (sizeof(iscsi_portal_group_t) *
			ISCSI_MAX_TPGS));

	init_iscsi_portal_groups(tiqn);

	spin_lock(&iscsi_global->tiqn_lock);
	list_add_tail(&tiqn->tiqn_list, &iscsi_global->g_tiqn_list);
	spin_unlock(&iscsi_global->tiqn_lock);

	PYXPRINT("CORE[0] - Added iSCSI Target IQN: %s\n", tiqn->tiqn);

	return(tiqn);

}

extern int __core_del_tiqn (iscsi_tiqn_t *tiqn)
{
	iscsi_disable_tpgs(tiqn);
	iscsi_remove_tpgs(tiqn);
	kfree(tiqn->tiqn_tpg_list);

	spin_lock(&iscsi_global->tiqn_lock);
	list_del(&tiqn->tiqn_list);
	spin_unlock(&iscsi_global->tiqn_lock);

	PYXPRINT("CORE[0] - Deleted iSCSI Target IQN: %s\n", tiqn->tiqn);
	kfree(tiqn);

	return(0);
}

extern int core_del_tiqn (unsigned char *buf)
{
	iscsi_tiqn_t *tiqn;

	if (!(tiqn = core_get_tiqn(buf))) {
		TRACE_ERROR("Unable to locate iscsi_tiqn_t: %s\n", buf);
		return(-1);
	}

	if (tiqn == iscsi_global->global_tiqn) {
		TRACE_ERROR("Unable to delete original IQN: %s\n", tiqn->tiqn);
		return(-1);
	}

	return(__core_del_tiqn(tiqn));
}

extern int core_release_tiqns (void)
{
	iscsi_tiqn_t *tiqn, *t_tiqn;

	spin_lock(&iscsi_global->tiqn_lock);
	list_for_each_entry_safe(tiqn, t_tiqn, &iscsi_global->g_tiqn_list, tiqn_list) {
		spin_unlock(&iscsi_global->tiqn_lock);

		__core_del_tiqn(tiqn);

		spin_lock(&iscsi_global->tiqn_lock);
	}
	spin_unlock(&iscsi_global->tiqn_lock);

	return(0);
}

extern iscsi_portal_group_t *core_get_tpg_from_iqn (
	unsigned char *iqn,
	iscsi_tiqn_t **tiqn_out,
	u16 tpgt,
	int addtpg)
{
	iscsi_tiqn_t *tiqn;

	/*
	 * Legacy Mode, locate the first valid Target IQN.
	 */
	if (!iqn || !(tiqn = core_get_tiqn(iqn)))
		return(NULL);

	*tiqn_out = tiqn;

	return(iscsi_get_tpg_from_tpgt(tiqn, tpgt, addtpg));
}

extern int core_access_np (iscsi_np_t *np, iscsi_portal_group_t *tpg)
{
	/*
	 * Determine if the network portal is accepting storage traffic.
	 */
	spin_lock_bh(&np->np_thread_lock);
	if (np->np_thread_state != ISCSI_NP_THREAD_ACTIVE) {
		spin_unlock_bh(&np->np_thread_lock);
		return(-1);
	}
	if (np->np_login_tpg) {
		TRACE_ERROR("np->np_login_tpg() is not NULL!\n");
		spin_unlock_bh(&np->np_thread_lock);
		return(-1);
	}
	spin_unlock_bh(&np->np_thread_lock);
	
	/*
	 * Determine if the portal group is accepting storage traffic.
	 */
	spin_lock_bh(&tpg->tpg_state_lock);
	if (tpg->tpg_state != TPG_STATE_ACTIVE) {
		spin_unlock_bh(&tpg->tpg_state_lock);
		return(-1);
	}
	spin_unlock_bh(&tpg->tpg_state_lock);

	/*
	 * Here we serialize access across the TIQN+TPG Tuple.
	 */
	down_interruptible(&tpg->np_login_sem);
	if (signal_pending(current))
		return(-1);

	spin_lock_bh(&tpg->tpg_state_lock);
	if (tpg->tpg_state != TPG_STATE_ACTIVE) {
		spin_unlock_bh(&tpg->tpg_state_lock);
		return(-1);
	}
	spin_unlock_bh(&tpg->tpg_state_lock);

	spin_lock_bh(&np->np_thread_lock);
	np->np_login_tpg = tpg;
	printk("Set np->np_login_tpg to %p\n", tpg);
	spin_unlock_bh(&np->np_thread_lock);

	return(0);
}

extern int core_deaccess_np (iscsi_np_t *np, iscsi_portal_group_t *tpg)
{
	spin_lock_bh(&np->np_thread_lock);
	np->np_login_tpg = NULL;	
	printk("Cleared np->np_login_tpg\n");
	spin_unlock_bh(&np->np_thread_lock);

	up(&tpg->np_login_sem);

	return(0);
}

extern void *core_get_np_ip (iscsi_np_t *np)
{
	return((np->np_flags & NPF_NET_IPV6) ?
	       (void *)&np->np_ipv6[0] :
	       (void *)&np->np_ipv4);
}

extern iscsi_np_t *core_get_np (
	void *ip,
	u16 port,
	int network_transport)
{
	iscsi_np_t *np;

	spin_lock(&iscsi_global->np_lock);
	list_for_each_entry(np, &iscsi_global->g_np_list, np_list) { 
		if (!(memcmp(core_get_np_ip(np), ip, np->np_net_size)) &&
		    (np->np_port == port) &&
		    (np->np_network_transport == network_transport)) {
			spin_unlock(&iscsi_global->np_lock);
			return(np);
		}
	}
	spin_unlock(&iscsi_global->np_lock);

	return(NULL);
}

extern void *core_get_np_ex_ip (iscsi_np_ex_t *np_ex)
{
	return((np_ex->np_ex_net_size == IPV6_ADDRESS_SPACE) ?
	       (void *)&np_ex->np_ex_ipv6 :
	       (void *)&np_ex->np_ex_ipv4);
}

extern int core_del_np_ex (
	iscsi_np_t *np,
	void *ip_ex,
	u16 port_ex,
	int network_transport)
{
	iscsi_np_ex_t *np_ex, *np_ex_t;

	spin_lock(&np->np_ex_lock);
	list_for_each_entry_safe(np_ex, np_ex_t, &np->np_nex_list, np_ex_list) {
		if (!(memcmp(core_get_np_ex_ip(np_ex), ip_ex, np_ex->np_ex_net_size)) &&
		    (np_ex->np_ex_port == port_ex)) {
			__core_del_np_ex(np, np_ex);
			spin_unlock(&np->np_ex_lock);
			return(0);
		}
	}
	spin_unlock(&np->np_ex_lock);

	return(-1);
}

extern int core_add_np_ex (
	iscsi_np_t *np,
	void *ip_ex,
	u16 port_ex,
	int net_size)
{
	iscsi_np_ex_t *np_ex;
	unsigned char *ip_buf = NULL, *ip_ex_buf = NULL;
	unsigned char buf_ipv4[IPV4_BUF_SIZE], buf_ipv4_ex[IPV4_BUF_SIZE];
	u32 ip_ex_ipv4;

	if (!(np_ex = kmalloc(sizeof(iscsi_np_ex_t), GFP_KERNEL))) {
		TRACE_ERROR("iscsi_np_ex_t memory allocate failed!\n");
		return(-1);
	}
	memset(np_ex, 0, sizeof(iscsi_np_ex_t));

	if (net_size == IPV6_ADDRESS_SPACE) {
		ip_buf = (unsigned char *)&np->np_ipv6[0];
		ip_ex_buf = ip_ex;
		snprintf(np_ex->np_ex_ipv6, IPV6_ADDRESS_SPACE, "%s", ip_ex_buf);
	} else {
		memset(buf_ipv4, 0, IPV4_BUF_SIZE);
		memset(buf_ipv4_ex, 0, IPV4_BUF_SIZE);
		iscsi_ntoa2(buf_ipv4, np->np_ipv4);
		memcpy((void *)&ip_ex_ipv4, ip_ex, 4);
		iscsi_ntoa2(buf_ipv4_ex, ip_ex_ipv4);
		ip_buf = &buf_ipv4[0];
		ip_ex_buf = &buf_ipv4_ex[0];

		memcpy((void *)&np_ex->np_ex_ipv4, ip_ex, IPV4_ADDRESS_SPACE);
	}

	np_ex->np_ex_port = port_ex;
	np_ex->np_ex_net_size = net_size;
	INIT_LIST_HEAD(&np_ex->np_ex_list);
	spin_lock_init(&np->np_ex_lock);

	spin_lock(&np->np_ex_lock);
	list_add_tail(&np_ex->np_ex_list, &np->np_nex_list);
	spin_unlock(&np->np_ex_lock);

	PYXPRINT("CORE[0] - Added Network Portal: Internal %s:%hu External %s:%hu"
		" on %s on network device: %s\n", ip_buf, np->np_port,
		ip_ex_buf, port_ex, (np->np_network_transport == ISCSI_TCP) ?
		"TCP" : "SCTP", strlen(np->np_net_dev) ?
			(char *)np->np_net_dev : "None");

	return(0);
}

/*
 * Called with iscsi_np_t->np_ex_lock held.
 */
extern int __core_del_np_ex (
	iscsi_np_t *np,
	iscsi_np_ex_t *np_ex)
{
	unsigned char *ip_buf = NULL, *ip_ex_buf = NULL;
	unsigned char buf_ipv4[IPV4_BUF_SIZE], buf_ipv4_ex[IPV4_BUF_SIZE];

	if (np->np_net_size == IPV6_ADDRESS_SPACE) {
		ip_buf = (unsigned char *)&np->np_ipv6[0];
		ip_ex_buf = (unsigned char *)&np_ex->np_ex_ipv6[0];
	} else {
		memset(buf_ipv4, 0, IPV4_BUF_SIZE);
		memset(buf_ipv4_ex, 0, IPV4_BUF_SIZE);
		iscsi_ntoa2(buf_ipv4, np->np_ipv4);
		iscsi_ntoa2(buf_ipv4_ex, np_ex->np_ex_ipv4);
		ip_buf = &buf_ipv4[0];
		ip_ex_buf = &buf_ipv4_ex[0];
	}

	list_del(&np_ex->np_ex_list);

	PYXPRINT("CORE[0] - Removed Network Portal: Internal %s:%hu"
		" External %s:%hu on %s on network device: %s\n",
		ip_buf, np->np_port, ip_ex_buf, np_ex->np_ex_port,
		(np->np_network_transport == ISCSI_TCP) ?
		"TCP" : "SCTP", strlen(np->np_net_dev) ?
			(char *)np->np_net_dev : "None");
	kfree(np_ex);

	return(0);
}

extern void core_del_np_all_ex (
	iscsi_np_t *np)
{
	iscsi_np_ex_t *np_ex, *np_ex_t;

	spin_lock(&np->np_ex_lock);
	list_for_each_entry_safe(np_ex, np_ex_t, &np->np_nex_list, np_ex_list)
		__core_del_np_ex(np, np_ex);
	spin_unlock(&np->np_ex_lock);
	
	return;
}

static iscsi_np_t *core_add_np_locate (
	void *ip,
	void *ip_ex,
	unsigned char *ip_buf,
	unsigned char *ip_ex_buf,
	u16 port,
	u16 port_ex,
	int network_transport,
	int net_size,
	int *ret)
{
	iscsi_np_t *np;
	iscsi_np_ex_t *np_ex;

	spin_lock(&iscsi_global->np_lock);
	list_for_each_entry(np, &iscsi_global->g_np_list, np_list) {
		if (!(memcmp(core_get_np_ip(np), ip, np->np_net_size)) &&
		    (np->np_port == port) &&
		    (np->np_network_transport == network_transport)) { 
			if (!ip_ex && !port_ex) {
				TRACE_ERROR("Network Portal %s:%hu on %s already"
					" exists, ignoring request.\n", ip_buf,
					port, (network_transport == ISCSI_TCP) ?
					"TCP" : "SCTP"); 
				spin_unlock(&iscsi_global->np_lock);
				*ret = ERR_ADDNPTOTPG_ALREADY_EXISTS;
				return(NULL);
			}

			spin_lock(&np->np_ex_lock);
			list_for_each_entry(np_ex, &np->np_nex_list, np_ex_list) {
				if (!(memcmp(core_get_np_ex_ip(np_ex), ip_ex,
				     np_ex->np_ex_net_size)) &&
				    (np_ex->np_ex_port == port_ex)) {
					TRACE_ERROR("Network Portal Internal: %s:%hu"
						" External: %s:%hu on %s,"
						" ignoring request.\n", ip_buf, port,
						ip_ex_buf, port_ex,
						(network_transport == ISCSI_TCP) ?
						"TCP" : "SCTP");
					spin_unlock(&np->np_ex_lock);
					spin_unlock(&iscsi_global->np_lock);
					*ret = ERR_ADDNPTOTPG_ALREADY_EXISTS;
					return(NULL);
				}
			}
			spin_unlock(&np->np_ex_lock);
			spin_unlock(&iscsi_global->np_lock);

			if ((*ret = core_add_np_ex(np, ip_ex, port_ex, net_size)) < 0)
				return(NULL);

			*ret = 0;
			return(np);
		}
	}
	spin_unlock(&iscsi_global->np_lock);

	*ret = 0;

	return(NULL);
}

extern iscsi_np_t *core_add_np (
	struct iscsi_target *tg,
	int network_transport,
	int *ret)
{
	iscsi_np_t *np = NULL;
	unsigned char *ip_buf = NULL, *ip_ex_buf = NULL;
	void *ip = NULL, *ip_ex = NULL;
	unsigned char buf_ipv4[IPV4_BUF_SIZE], buf_ipv4_ex[IPV4_BUF_SIZE];
	int net_size;

	if (tg->net_params_set & PARAM_NET_IPV6_ADDRESS) {
		ip = ip_buf = &tg->ip6[0];
		ip_ex = (tg->net_params_set & PARAM_NET_IPV6_EX_ADDRESS) ?
				&tg->ip6_ex[0] : NULL;
		ip_ex_buf = (tg->net_params_set & PARAM_NET_IPV6_EX_ADDRESS) ?
				&tg->ip6_ex[0] : NULL;
		net_size = IPV6_ADDRESS_SPACE;
	} else {
		ip = (void *)&tg->ip;
		ip_ex = (tg->net_params_set & PARAM_NET_IPV4_EX_ADDRESS) ?
				&tg->ip_ex : NULL;
		memset(buf_ipv4, 0, IPV4_BUF_SIZE);
		memset(buf_ipv4_ex, 0, IPV4_BUF_SIZE);
		iscsi_ntoa2(buf_ipv4, tg->ip);
		iscsi_ntoa2(buf_ipv4_ex, tg->ip_ex);
		ip_buf = &buf_ipv4[0];
		ip_ex_buf = &buf_ipv4_ex[0];
		net_size = IPV4_ADDRESS_SPACE;
	}

	if ((np = core_add_np_locate(ip, ip_ex, ip_buf, ip_ex_buf, tg->port, tg->port_ex,
			network_transport, net_size, ret)))
		return(np);

	if (*ret != 0)
		return(NULL);

	if (!(np = kmalloc(sizeof(iscsi_np_t), GFP_KERNEL))) {
		TRACE_ERROR("Unable to allocate memory for iscsi_np_t\n");
		*ret = ERR_NO_MEMORY;
		return(NULL);
	}
	memset(np, 0, sizeof(iscsi_np_t));

	np->np_flags |= NPF_IP_NETWORK;
	if (tg->net_params_set & PARAM_NET_IPV6_ADDRESS) {
		np->np_flags |= NPF_NET_IPV6;
		memcpy(np->np_ipv6, tg->ip6, IPV6_ADDRESS_SPACE);
	} else {
		np->np_flags |= NPF_NET_IPV4;
		np->np_ipv4 = tg->ip;
	}
	np->np_port = tg->port;
	np->np_network_transport = network_transport;
	np->np_net_size		= net_size;
#ifdef SNMP_SUPPORT
	np->np_index		= get_new_index(ISCSI_PORTAL_INDEX);
#endif
	spin_lock_init(&np->np_state_lock);
	spin_lock_init(&np->np_thread_lock);
	spin_lock_init(&np->np_ex_lock);
	init_MUTEX_LOCKED(&np->np_done_sem);
	init_MUTEX_LOCKED(&np->np_restart_sem);
	init_MUTEX_LOCKED(&np->np_start_sem);
	INIT_LIST_HEAD(&np->np_list);
	INIT_LIST_HEAD(&np->np_nex_list);

	kernel_thread(iscsi_target_login_thread, np, 0);

	down(&np->np_start_sem);

	spin_lock_bh(&np->np_thread_lock);
	if (np->np_thread_state != ISCSI_NP_THREAD_ACTIVE) {
		spin_unlock_bh(&np->np_thread_lock);
		TRACE_ERROR("Unable to start login thread for iSCSI Network"
			" Portal %s:%hu\n", ip_buf, np->np_port);
		kfree(np);
		*ret = ERR_ADDNPTOTPG_NO_LOGIN_THREAD;
		return(NULL);
	}
	spin_unlock_bh(&np->np_thread_lock);

	if (((tg->net_params_set & PARAM_NET_IPV6_EX_ADDRESS) ||
	     (tg->net_params_set & PARAM_NET_IPV4_EX_ADDRESS)) &&
			tg->port_ex) {
		if ((*ret = core_add_np_ex(np, ip_ex, tg->port_ex, net_size)) < 0) {
			kfree(np);
			return(NULL);
		}
	}

	spin_lock(&iscsi_global->np_lock);
	list_add_tail(&np->np_list, &iscsi_global->g_np_list);
	spin_unlock(&iscsi_global->np_lock);

	PYXPRINT("CORE[0] - Added Network Portal: %s:%hu on %s on network"
		" device: %s\n", ip_buf, np->np_port,
		(np->np_network_transport == ISCSI_TCP) ?
		"TCP" : "SCTP", (strlen(np->np_net_dev)) ?
		(char *)np->np_net_dev : "None");

	*ret = 0;
	return(np);
}

extern int core_reset_np_thread (iscsi_np_t *np)
{
	spin_lock_bh(&np->np_thread_lock);
	if (np->np_thread_state == ISCSI_NP_THREAD_INACTIVE) {
		spin_unlock_bh(&np->np_thread_lock);
		return(0);
	}
	np->np_thread_state = ISCSI_NP_THREAD_RESET;
	if (np->np_thread) {
		spin_unlock_bh(&np->np_thread_lock);
		send_sig(SIGKILL, np->np_thread, 1);
		down(&np->np_restart_sem);
		spin_lock_bh(&np->np_thread_lock);
	}
	spin_unlock_bh(&np->np_thread_lock);

	return(0);
}

extern int core_del_np_thread (iscsi_np_t *np)
{
	spin_lock_bh(&np->np_thread_lock);
	np->np_thread_state = ISCSI_NP_THREAD_SHUTDOWN;
	if (np->np_thread) {
		send_sig(SIGKILL, np->np_thread, 1);
		spin_unlock_bh(&np->np_thread_lock);
		down(&np->np_done_sem);
		spin_lock_bh(&np->np_thread_lock);
	}
	spin_unlock_bh(&np->np_thread_lock);

	return(0);
}

extern int core_del_np_comm (iscsi_np_t *np)
{
	if (!np->np_socket)	
		return(0);

	/*
	 * Some network transports set their own FILEIO, see
	 * if we need to free any additional allocated resources.
	 */
	if (np->np_flags & NPF_SCTP_STRUCT_FILE) {
		kfree(np->np_socket->file);
		np->np_socket->file = NULL;
	}

	sock_release(np->np_socket);
	return(0);
}

static void core_del_tpg_nps (iscsi_np_t *np)
{
	iscsi_portal_group_t *tpg;
	iscsi_tiqn_t *tiqn;		
	iscsi_tpg_np_t *tpg_np;
	int i;

	spin_lock(&iscsi_global->tiqn_lock);
	list_for_each_entry(tiqn, &iscsi_global->g_tiqn_list, tiqn_list) {
		spin_lock(&tiqn->tiqn_tpg_lock);
		for (i = 0; i < ISCSI_MAX_TPGS; i++) {
			tpg = &tiqn->tiqn_tpg_list[i]; 

			spin_lock(&tpg->tpg_state_lock);
			if (tpg->tpg_state == TPG_STATE_FREE) {
				spin_unlock(&tpg->tpg_state_lock);
				continue;
			}
			spin_unlock(&tpg->tpg_state_lock);

			if (!(tpg_np = iscsi_tpg_del_np_phase0(tpg, np)))	
				continue;

			spin_unlock(&tiqn->tiqn_tpg_lock);
			spin_unlock(&iscsi_global->tiqn_lock);
			
			iscsi_tpg_del_np_phase1(tpg_np, tpg, np);

			spin_lock(&iscsi_global->tiqn_lock);
			spin_lock(&tiqn->tiqn_tpg_lock);
		}
		spin_unlock(&tiqn->tiqn_tpg_lock);
	}
	spin_unlock(&iscsi_global->tiqn_lock);

	if (np->np_exports) {
		TRACE_ERROR("np->np_exports != 0\n");
		BUG();
	}
	
	return;
}

extern int __core_del_np (iscsi_np_t *np)
{
	unsigned char *ip = NULL;
	unsigned char buf_ipv4[IPV4_BUF_SIZE];

	core_del_tpg_nps(np);
	core_del_np_thread(np);
	core_del_np_comm(np);
	core_del_np_all_ex(np);

	list_del(&np->np_list);

	if (np->np_net_size == IPV6_ADDRESS_SPACE) {
		ip = &np->np_ipv6[0];
	} else {
		memset(buf_ipv4, 0, IPV4_BUF_SIZE);
		iscsi_ntoa2(buf_ipv4, np->np_ipv4);
		ip = &buf_ipv4[0];
	}

	PYXPRINT("CORE[0] - Removed Network Portal: %s:%hu on %s on network"
		" device: %s\n", ip, np->np_port, 
		(np->np_network_transport == ISCSI_TCP) ? 
		"TCP" : "SCTP",  (strlen(np->np_net_dev)) ?
		(char *)np->np_net_dev : "None");

	kfree(np);
	return(0);
}

extern int core_del_np (
	struct iscsi_target *tg,
	int network_transport)
{
	iscsi_np_t *np;
	unsigned char *ip_buf = NULL, *ip_ex_buf = NULL;
	void *ip = NULL, *ip_ex = NULL;
	unsigned char buf_ipv4[IPV4_BUF_SIZE], buf_ipv4_ex[IPV4_BUF_SIZE];
	int ret;
			              
	if (tg->net_params_set & PARAM_NET_IPV6_ADDRESS) {
		ip = ip_buf = &tg->ip6[0];
		ip_ex = ip_ex_buf = &tg->ip6_ex[0];
	} else {
		ip = (void *)&tg->ip;
		ip_ex = (void *)&tg->ip_ex;
		memset(buf_ipv4, 0, IPV4_BUF_SIZE);
		memset(buf_ipv4_ex, 0, IPV4_BUF_SIZE);
		iscsi_ntoa2(buf_ipv4, tg->ip);
		iscsi_ntoa2(buf_ipv4_ex, tg->ip_ex);
		ip_buf = &buf_ipv4[0];
		ip_ex_buf = &buf_ipv4_ex[0];
	}

	if (!(np = core_get_np(ip, tg->port, network_transport)))
		return(-1);

	if (!(tg->net_params_set & PARAM_NET_IPV6_EX_ADDRESS) ||
	    !(tg->net_params_set & PARAM_NET_IPV4_EX_ADDRESS) ||
	    !tg->port_ex)
		return(__core_del_np(np));

	if (!(ret = core_del_np_ex(np, ip_ex, tg->port_ex, network_transport)))
		return(ret);

	TRACE_ERROR("Network Portal Internal %s:%hu External %s:%hu on %s does"
		" not exist, ignoring request,", ip_buf, tg->port, ip_ex_buf,
		tg->port_ex, (network_transport == ISCSI_TCP) ? "TCP" : "SCTP");

	return(-1);
}

extern void core_reset_nps (void)
{
	iscsi_np_t *np, *t_np;

	spin_lock(&iscsi_global->np_lock);
	list_for_each_entry_safe(np, t_np, &iscsi_global->g_np_list, np_list) {
		spin_unlock(&iscsi_global->np_lock);
		core_reset_np_thread(np);
		spin_lock(&iscsi_global->np_lock);
	}
	spin_unlock(&iscsi_global->np_lock);

	return;
}

extern void core_release_nps (void)
{
	iscsi_np_t *np, *t_np; 

	spin_lock(&iscsi_global->np_lock);
	list_for_each_entry_safe(np, t_np, &iscsi_global->g_np_list, np_list) {
		spin_unlock(&iscsi_global->np_lock);
		__core_del_np(np);
		spin_lock(&iscsi_global->np_lock);
	}
	spin_unlock(&iscsi_global->np_lock);

	return;
}

/* init_iscsi_target():
 *
 * This function is called during module initialization to setup iscsi_global_t.
 */
//#warning FIXME v2.8: Need to move these pieces into feature plugin allocation routines
static int init_iscsi_global (iscsi_global_t *global)
{
	se_hba_t *hba;
	int i;
	
	memset(global, 0, sizeof(iscsi_global_t));
	init_MUTEX(&global->auth_sem);
	init_MUTEX(&global->auth_id_sem);
	spin_lock_init(&global->active_ts_lock);
	spin_lock_init(&global->check_thread_lock);
	spin_lock_init(&global->discovery_lock);
	spin_lock_init(&global->hba_lock);
	spin_lock_init(&global->inactive_ts_lock);
	spin_lock_init(&global->login_thread_lock);
	spin_lock_init(&global->np_lock);
	spin_lock_init(&global->plugin_class_lock);
	spin_lock_init(&global->shutdown_lock);
	spin_lock_init(&global->tiqn_lock);
	INIT_LIST_HEAD(&global->g_tiqn_list);
	INIT_LIST_HEAD(&global->g_np_list);
	
	if (!(global->hba_list = kmalloc((sizeof(se_hba_t) * ISCSI_MAX_GLOBAL_HBAS), GFP_KERNEL))) {
		TRACE_ERROR("Unable to allocate global->hba_list\n");
		goto out;
	}
	memset(global->hba_list, 0, (sizeof(se_hba_t) * ISCSI_MAX_GLOBAL_HBAS));

	for (i = 0; i < ISCSI_MAX_GLOBAL_HBAS; i++) {
		hba = &global->hba_list[i];

		hba->hba_status |= HBA_STATUS_FREE;
		hba->hba_id = i;
		spin_lock_init(&hba->device_lock);
		spin_lock_init(&hba->hba_queue_lock);
		init_MUTEX(&hba->hba_access_sem);
#ifdef SNMP_SUPPORT
		hba->hba_index = get_new_index(SCSI_INST_INDEX);
#endif
	}

	if (!(global->plugin_class_list = kmalloc((sizeof(se_plugin_class_t) * MAX_PLUGIN_CLASSES), GFP_KERNEL))) {
		TRACE_ERROR("Unable to allocate global->plugin_class_list\n");
		goto out;
	}
	memset(global->plugin_class_list, 0, (sizeof(se_plugin_class_t) * MAX_PLUGIN_CLASSES));

	return(0);
out:
	if (global->hba_list)
		kfree(global->hba_list);
	if (global->plugin_class_list)
		kfree(global->plugin_class_list);

	return(-1);
}

static int default_targetname_seq_show (struct seq_file *m, void *p)
{
	if (iscsi_global->targetname_set)
		seq_printf(m, "iSCSI TargetName: %s\n", iscsi_global->targetname);
	
	return(0);
}

static int version_info_seq_show (struct seq_file *m, void *p)
{
	seq_printf(m, "%s iSCSI Target Core Stack "PYX_ISCSI_VERSION" on %s/%s on "UTS_RELEASE"\n",
			PYX_ISCSI_VENDOR, utsname()->sysname, utsname()->machine);

	return(0);
}

static int fp_auto_assign = 0; /* Do not perform feature plugin auto assignment by default */

static int target_check_module_params(void)
{
	iscsi_global->fp_auto_assign = fp_auto_assign;
	printk("SE: fp_auto_assign: %d\n", iscsi_global->fp_auto_assign);

	return(0);
}

static int default_targetname_seq_open (struct inode *inode, struct file *file)
{
	return(single_open(file, default_targetname_seq_show, PDE(inode)->data));
}

static const struct file_operations default_targetname = {
	.open		= default_targetname_seq_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= single_release,
};

static int version_info_seq_open (struct inode *inode, struct file *file)
{
	return(single_open(file, version_info_seq_show, PDE(inode)->data));
}

static const struct file_operations version_info = {
	.open		= version_info_seq_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= single_release,
};

/*	iscsi_target_detect():
 *
 *	This function is called upon module_init and does the following
 *	actions in said order:
 *
 *	0) Allocates and initializes the iscsi_global_t structure.
 *	1) Registers the character device for the IOCTL.
 *	2) Registers /proc filesystem entries.
 *	3) Creates a lookaside cache entry for the iscsi_cmd_t and 
 *	   iscsi_conn_t structures.
 *	4) Allocates threads to handle login requests.
 *	5) Allocates thread_sets for the thread_set queue.
 *	6) Creates the default list of iSCSI parameters.
 *	7) Create server socket and spawn iscsi_target_server_thread to 
 *	   accept connections.
 *
 *	Parameters:	Nothing.
 *	Returns:	0 on success, -1 on error.
 */
/*	FIXME:  getaddrinfo for IPv6 will go here.
 */
static int iscsi_target_detect(void)
{
	int ret = 0;
	struct proc_dir_entry *dir_entry, *name_entry, *ver_entry;

	printk("%s iSCSI Target Core Stack "PYX_ISCSI_VERSION" on %s/%s on "UTS_RELEASE"\n",
		PYX_ISCSI_VENDOR, utsname()->sysname, utsname()->machine);

	if (!(iscsi_global = (iscsi_global_t *)kmalloc(
			sizeof(iscsi_global_t), GFP_KERNEL))) {
		TRACE_ERROR("Unable to allocate memory for iscsi_global\n");
		return(-1);
	}
#ifdef SNMP_SUPPORT
	init_iscsi_index_table();
#endif
	if (init_iscsi_global(iscsi_global) < 0) {
		kfree(iscsi_global);
		return(-1);
	}

	if (target_check_module_params() < 0) {
		kfree(iscsi_global);
		return(-1);
	}

#ifdef DEBUG_ERL
	if (!(iscsi_global->debug_erl = (iscsi_debug_erl_t *)kmalloc(
			sizeof(iscsi_debug_erl_t), GFP_KERNEL))) {
		TRACE_ERROR("Unable to allocate memory for iscsi_debug_erl_t\n");
		ret = -1;
		goto out;
	}

	memset(iscsi_global->debug_erl, 0, sizeof(iscsi_debug_erl_t));
	spin_lock_init(&iscsi_global->debug_erl_lock);
#endif /* DEBUG_ERL */

#ifdef DEBUG_DEV
	spin_lock_init(&iscsi_global->debug_dev_lock);
#endif

	if ((ret = misc_register(&iscsi_dev))) {
		TRACE_ERROR("misc_register returned an error\n");
		ret = -1;
		goto out;
	}

#ifdef CONFIG_PROC_FS
	if (!(dir_entry = proc_mkdir("iscsi_target", 0))) {
		TRACE_ERROR("proc_mkdir() failed.\n");
		ret = -1;
		goto out;
        }
	if (!(name_entry = proc_create_data("iscsi_target/target_nodename",
			0, dir_entry, &default_targetname, NULL))) {
		TRACE_ERROR("create_proc_info_entry() failed.\n");
		remove_proc_entry("iscsi_target", 0);
		ret = -1;
		goto out;
	}
	if (!(ver_entry = proc_create_data("iscsi_target/version_info",
			0, dir_entry, &version_info, NULL))) {
		TRACE_ERROR("create_proc_info_entry() failed.\n");
		remove_proc_entry("iscsi_target/target_node_name", 0);
		remove_proc_entry("iscsi_target", 0);
		ret = -1;
		goto out;
	}

#ifdef SNMP_SUPPORT
	init_iscsi_target_mib();
#endif
#endif /* CONFIG_PROC_FS */

	register_iscsi_target_ioctl32();

	if (iscsi_allocate_thread_sets(TARGET_THREAD_SET_COUNT, TARGET) !=
			TARGET_THREAD_SET_COUNT) {
		TRACE_ERROR("iscsi_allocate_thread_sets() returned"
			" unexpected value!\n");
		ret = -1;
		goto out;
	}

	plugin_load_all_classes();
	if (core_load_discovery_tpg() < 0)
		goto out;

	printk("Loading Complete.\n");

	return(ret);
out:

	plugin_unload_all_classes();
	core_release_discovery_tpg();
	iscsi_deallocate_thread_sets(TARGET);

	unregister_iscsi_target_ioctl32();

	remove_proc_entry("iscsi_target/version_info", 0);
	remove_proc_entry("iscsi_target/target_nodename", 0);
	remove_proc_entry("iscsi_target", 0);
	
	misc_deregister(&iscsi_dev);
#ifdef DEBUG_ERL
	kfree(iscsi_global->debug_erl);
#endif /* DEBUG_ERL */
	kfree(iscsi_global->hba_list);
	kfree(iscsi_global);
	
	return(ret);
}

extern int iscsi_target_release_phase1 (int rmmod)
{
	spin_lock(&iscsi_global->shutdown_lock);
	if (!rmmod) {
		if (iscsi_global->in_shutdown) {
			TRACE_ERROR("Module already in shutdown, aborting\n");
			spin_unlock(&iscsi_global->shutdown_lock);
			return(-1);	
		}

		if (iscsi_global->in_rmmod) {
			TRACE_ERROR("Module already in rmmod, aborting\n");
			spin_unlock(&iscsi_global->shutdown_lock);
			return(-1);		
		}
	} else
		iscsi_global->in_rmmod = 1;
	iscsi_global->in_shutdown = 1;
	spin_unlock(&iscsi_global->shutdown_lock);

	return(0);
}

extern void iscsi_target_release_phase2 (void)
{
	core_reset_nps();
	iscsi_disable_all_tpgs();
	iscsi_deallocate_thread_sets(TARGET);
	iscsi_disable_all_hbas();
	iscsi_remove_all_tpgs();
	core_release_nps();
	feature_plugin_single_release();
	iscsi_hba_del_all_hbas();
	core_release_discovery_tpg();
	core_release_tiqns();
	plugin_unload_all_classes();

	iscsi_global->ti_forcechanoffline = NULL;
	
#ifdef CONFIG_PROC_FS
# ifdef SNMP_SUPPORT
	remove_iscsi_target_mib();
# endif
	remove_proc_entry("iscsi_target/version_info", 0);
	remove_proc_entry("iscsi_target/target_nodename", 0);
	remove_proc_entry("iscsi_target", 0);
#endif
	return;
}

/*	iscsi_target_release():
 * 
 *	
 */
static int iscsi_target_release (void)
{
	int ret = 0;	

	if (!iscsi_global) {
		TRACE_ERROR("iscsi_global is NULL!\n");
		return(-1);
	}
	
	iscsi_target_release_phase1(1);
	
	unregister_iscsi_target_ioctl32();

	iscsi_target_release_phase2();

	if ((ret = misc_deregister(&iscsi_dev))) {
		TRACE_ERROR("misc_deregister returned an error\n");
		ret = -1;
	}

#ifdef DEBUG_ERL
	kfree(iscsi_global->debug_erl);
#endif /* DEBUG_ERL */
	kfree(iscsi_global->hba_list);
	kfree(iscsi_global);
	
	printk("Unloading Complete.\n");

	return(ret);
}

extern void rfc3720_TCP_FE_plugin_info (void *p, char *b, int *bl)
{
        *bl += sprintf(b+*bl, "%s Internet Small Computer Systems Interface (iSCSI/TCP) Plugin %s\n",
			PYX_ISCSI_VENDOR, ISCSI_TCP_VERSION);
        return;
}

#define RFC3720_TCP {									\
	get_plugin_info:		rfc3720_TCP_FE_plugin_info,			\
}

scsi_target_frontend_t rfc3720_TCP_FE_template = RFC3720_TCP;

extern void rfc3720_SCTP_FE_plugin_info (void *p, char *b, int *bl)
{
        *bl += sprintf(b+*bl, "%s Internet Small Computer Systems Interface (iSCSI/SCTP) Plugin %s\n",
			PYX_ISCSI_VENDOR, ISCSI_SCTP_VERSION);
        return;
}

#define RFC3720_SCTP {									\
	get_plugin_info:		rfc3720_SCTP_FE_plugin_info,			\
}

scsi_target_frontend_t rfc3720_SCTP_FE_template = RFC3720_SCTP;

extern void frontend_load_plugins (void)
{
	int ret;

	plugin_register((void *)&rfc3720_TCP_FE_template,
			FRONTEND_RFC3720_TCP, "rfc3720_TCP_FE", PLUGIN_TYPE_FRONTEND,
			rfc3720_TCP_FE_template.get_plugin_info, &ret);

	plugin_register((void *)&rfc3720_SCTP_FE_template,
			FRONTEND_RFC3720_SCTP, "rfc3720_SCTP_FE", PLUGIN_TYPE_FRONTEND,
			rfc3720_SCTP_FE_template.get_plugin_info, &ret);


	return;
}

/*	iscsi_add_nopin():
 *
 *
 */
extern int iscsi_add_nopin (
	iscsi_conn_t *conn,
	int want_response)
{
	u8 state;
	iscsi_cmd_t *cmd;

	if (!(cmd = iscsi_allocate_cmd(conn)))
		return(-1);
		
	cmd->iscsi_opcode = ISCSI_TARG_NOP_IN;
	state = (want_response) ? ISTATE_SEND_NOPIN_WANT_RESPONSE :
			ISTATE_SEND_NOPIN_NO_RESPONSE;
	cmd->init_task_tag = 0xFFFFFFFF;
	spin_lock_bh(&SESS(conn)->ttt_lock);
	cmd->targ_xfer_tag = (want_response) ? SESS(conn)->targ_xfer_tag++ :
			0xFFFFFFFF;
	if (want_response && (cmd->targ_xfer_tag == 0xFFFFFFFF))
		cmd->targ_xfer_tag = SESS(conn)->targ_xfer_tag++;
	spin_unlock_bh(&SESS(conn)->ttt_lock);
		
	iscsi_attach_cmd_to_queue(conn, cmd);
	if (want_response)
		iscsi_start_nopin_response_timer(conn);
	iscsi_add_cmd_to_immediate_queue(cmd, conn, state);
		
	return(0);
}

/*	iscsi_add_reject():
 *
 *
 */
extern int iscsi_add_reject (
	u8 reason,
	int fail_conn,
	unsigned char *buf,
	iscsi_conn_t *conn)
{
	iscsi_cmd_t *cmd;
	struct iscsi_targ_rjt *hdr;

	if (!(cmd = iscsi_allocate_cmd(conn)))
		return(-1);

	cmd->iscsi_opcode = ISCSI_TARG_RJT;
	if (fail_conn)
		cmd->cmd_flags |= ICF_REJECT_FAIL_CONN;

	hdr	= (struct iscsi_targ_rjt *) cmd->pdu;
	hdr->reason = reason;

	if (!(cmd->buf_ptr = kmalloc(ISCSI_HDR_LEN, GFP_ATOMIC))) {
		TRACE_ERROR("Unable to allocate memory for cmd->buf_ptr\n");
		iscsi_release_cmd_to_pool(cmd, SESS(conn));
		return(-1);
	}
	memset(cmd->buf_ptr, 0, ISCSI_HDR_LEN);

	memcpy(cmd->buf_ptr, buf, ISCSI_HDR_LEN);

	iscsi_attach_cmd_to_queue(conn, cmd);

	cmd->i_state = ISTATE_SEND_REJECT;
	iscsi_add_cmd_to_response_queue(cmd, conn, cmd->i_state);

	down_interruptible(&cmd->reject_sem);

	return((!fail_conn) ? 0 : -1);
}

/*	iscsi_add_reject_from_cmd():
 *
 *
 */
extern int iscsi_add_reject_from_cmd (
	u8 reason,
	int fail_conn,
	int add_to_conn,
	unsigned char *buf,
	iscsi_cmd_t *cmd)
{
	iscsi_conn_t *conn;
	struct iscsi_targ_rjt *hdr;

	if (!CONN(cmd)) {
		TRACE_ERROR("cmd->conn is NULL for ITT: 0x%08x\n", cmd->init_task_tag);
		return(-1);
	}
	conn = CONN(cmd);

	cmd->iscsi_opcode = ISCSI_TARG_RJT;
	if (fail_conn)
		cmd->cmd_flags |= ICF_REJECT_FAIL_CONN;

	hdr	= (struct iscsi_targ_rjt *) cmd->pdu;
	hdr->reason = reason;

	if (!(cmd->buf_ptr = kmalloc(ISCSI_HDR_LEN, GFP_ATOMIC))) {
		TRACE_ERROR("Unable to allocate memory for cmd->buf_ptr\n");
		iscsi_release_cmd_to_pool(cmd, SESS(conn));
		return(-1);
	}
	memset(cmd->buf_ptr, 0, ISCSI_HDR_LEN);

	memcpy(cmd->buf_ptr, buf, ISCSI_HDR_LEN);

	if (add_to_conn)
		iscsi_attach_cmd_to_queue(conn, cmd);

	cmd->i_state = ISTATE_SEND_REJECT;
	iscsi_add_cmd_to_response_queue(cmd, conn, cmd->i_state);

	down_interruptible(&cmd->reject_sem);

	return((!fail_conn) ? 0 : -1);
}

/*	iscsi_handle_scsi_cmd():
 *
 *
 */
static inline int iscsi_handle_scsi_cmd (
	iscsi_conn_t *conn,
	unsigned char *buf)
{
	int	cmdsn_ret = 0, immed_ret, ret, transport_ret;
	int	dump_immediate_data = 0, send_check_condition = 0;
	iscsi_cmd_t	*cmd = NULL;
	struct iscsi_init_scsi_cmnd *hdr;	

#ifdef SNMP_SUPPORT
	spin_lock_bh(&SESS(conn)->session_stats_lock);
	SESS(conn)->cmd_pdus++;
	if (SESS_NODE_ACL(SESS(conn))) {
		spin_lock(&SESS_NODE_ACL(SESS(conn))->stats_lock);
		SESS_NODE_ACL(SESS(conn))->num_cmds++;
		spin_unlock(&SESS_NODE_ACL(SESS(conn))->stats_lock);
	}
	spin_unlock_bh(&SESS(conn)->session_stats_lock);
#endif /* SNMP_SUPPORT */

	hdr			= (struct iscsi_init_scsi_cmnd *) buf;
	hdr->length		= be32_to_cpu(hdr->length);
	hdr->init_task_tag	= be32_to_cpu(hdr->init_task_tag);
	hdr->exp_xfer_len	= be32_to_cpu(hdr->exp_xfer_len);
	hdr->cmd_sn		= be32_to_cpu(hdr->cmd_sn);
	hdr->exp_stat_sn	= be32_to_cpu(hdr->exp_stat_sn);

#ifdef DEBUG_OPCODES
	print_init_scsi_cmnd(hdr);
#endif
	/* FIXME; Add checks for AdditionalHeaderSegment */

	if (!(hdr->flags & W_BIT) && !(hdr->flags & F_BIT)) {
		TRACE_ERROR("W_BIT & F_BIT not set. Bad iSCSI Initiator.\n");
		return(iscsi_add_reject(REASON_INVALID_PDU_FIELD, 1, buf, conn));
	}

	if (((hdr->flags & R_BIT) || (hdr->flags & W_BIT)) &&
	     !hdr->exp_xfer_len) {
		/*
		 * Vmware ESX v3.0 uses a modified Cisco Initiator (v3.4.2)
		 * that adds support for RESERVE/RELEASE.  There is a bug
		 * add with this new functionality that sets R/W bits when
		 * neither CDB carries any READ or WRITE datapayloads.
		 */
		if ((hdr->cdb[0] == 0x16) || (hdr->cdb[0] == 0x17)) {
			hdr->flags &= ~R_BIT;
			hdr->flags &= ~W_BIT;
			goto done;
		}

		TRACE_ERROR("R_BIT or W_BIT set when Expected Data Transfer"
			" Length is 0. Bad iSCSI Initiator.\n");
		return(iscsi_add_reject(REASON_INVALID_PDU_FIELD, 1, buf, conn));
	}
done:

	if (!(hdr->flags & R_BIT) && !(hdr->flags & W_BIT) &&
	     (hdr->exp_xfer_len != 0)) {
		TRACE_ERROR("R_BIT and/or W_BIT MUST be set if Expected"
			" Data Transfer Length is not 0. Bad iSCSI Initiator\n");
		return(iscsi_add_reject(REASON_INVALID_PDU_FIELD, 1, buf, conn));
	}

	if ((hdr->flags & R_BIT) && (hdr->flags & W_BIT)) {
		TRACE_ERROR("Bidirectional operations not supported!\n");
		return(iscsi_add_reject(REASON_INVALID_PDU_FIELD, 1, buf, conn));
	}

	if (hdr->opcode & I_BIT) {
		TRACE_ERROR("Illegally set Immediate Bit in iSCSI Initiator"
				" Scsi Command PDU.\n");
		return(iscsi_add_reject(REASON_INVALID_PDU_FIELD, 1, buf, conn));
	}

	if (hdr->length && !SESS_OPS_C(conn)->ImmediateData) {
		TRACE_ERROR("ImmediateData=No but DataSegmentLength=%u,"
			" protocol error.\n", hdr->length);
		return(iscsi_add_reject(REASON_PROTOCOL_ERR, 1, buf, conn));
	}
#if 0
	if (!(hdr->flags & F_BIT) && (hdr->flags & W_BIT) &&
	      SESS_OPS_C(conn)->InitialR2T) { 
		TRACE_ERROR("F Bit is not Set and W Bit and InitialR2T=Yes,"
				" protocol error\n");
		return(iscsi_add_reject(REASON_PROTOCOL_ERR, 1, buf, conn));
	}
#endif
	if ((hdr->exp_xfer_len == hdr->length) && (!(hdr->flags & F_BIT))) {
		TRACE_ERROR("Expected Data Transfer Length and Length of"
			" Immediate Data are the same, but F bit is"
				" not set protocol error\n");
		return(iscsi_add_reject(REASON_PROTOCOL_ERR, 1, buf, conn));
	}

	if (hdr->length > hdr->exp_xfer_len) {
		TRACE_ERROR("DataSegmentLength: %u is greater than"
			" EDTL: %u, protocol error.\n", hdr->length,
				hdr->exp_xfer_len);
		return(iscsi_add_reject(REASON_PROTOCOL_ERR, 1, buf, conn));
	}
		
	if (hdr->length > CONN_OPS(conn)->MaxRecvDataSegmentLength) {
		TRACE_ERROR("DataSegmentLength: %u is greater than"
			" MaxRecvDataSegmentLength: %u, protocol error.\n",
			hdr->length, CONN_OPS(conn)->MaxRecvDataSegmentLength);
		return(iscsi_add_reject(REASON_PROTOCOL_ERR, 1, buf, conn));
	}

	if (hdr->length > SESS_OPS_C(conn)->FirstBurstLength) {
		TRACE_ERROR("DataSegmentLength: %u is greater than"
			" FirstBurstLength: %u, protocol error.\n",
			hdr->length, SESS_OPS_C(conn)->FirstBurstLength);
		return(iscsi_add_reject(REASON_INVALID_PDU_FIELD, 1, buf, conn));
		return(-1);
	}

	if (hdr->opcode & I_BIT) {
		TRACE_ERROR("Initiator sending ISCSI_INIT_SCSI_CMND pdus with"
			" immediate bit set, aborting connection\n");
		return(iscsi_add_reject(REASON_INVALID_PDU_FIELD, 1, buf, conn));
	}
	
	if (!(cmd = iscsi_allocate_cmd(conn)))
		return(iscsi_add_reject(REASON_OUT_OF_RESOURCES, 1, buf, conn));

	TRACE(TRACE_ISCSI, "Got SCSI Command, ITT: 0x%08x, CmdSN: 0x%08x,"
		" ExpXferLen: %u, Length: %u, CID: %hu\n", hdr->init_task_tag,
		hdr->cmd_sn, hdr->exp_xfer_len, hdr->length, conn->cid);

	cmd->iscsi_opcode	= ISCSI_INIT_SCSI_CMND;
	cmd->i_state		= ISTATE_NEW_CMD;
	cmd->immediate_cmd	= ((hdr->opcode & I_BIT) ? 1:0);
	cmd->immediate_data	= (hdr->length ? 1:0);
	cmd->unsolicited_data	= ((!(hdr->flags & F_BIT) &&
				     (hdr->flags & W_BIT)) ? 1:0);
	if (cmd->unsolicited_data)
		cmd->cmd_flags |= ICF_NON_IMMEDIATE_UNSOLICITED_DATA;
	
	SESS(conn)->init_task_tag = cmd->init_task_tag = hdr->init_task_tag;
	if (hdr->flags & R_BIT) {
		spin_lock_bh(&SESS(conn)->ttt_lock);
		cmd->targ_xfer_tag = SESS(conn)->targ_xfer_tag++;
		if (cmd->targ_xfer_tag == 0xFFFFFFFF)
			cmd->targ_xfer_tag = SESS(conn)->targ_xfer_tag++;
		spin_unlock_bh(&SESS(conn)->ttt_lock);
	} else if (hdr->flags & W_BIT)
		cmd->targ_xfer_tag = 0xFFFFFFFF;
	cmd->cmd_sn		= hdr->cmd_sn;
	cmd->exp_stat_sn	= hdr->exp_stat_sn;
	cmd->data_direction	= (hdr->flags & W_BIT) ? ISCSI_WRITE :
				  (hdr->flags & R_BIT) ? ISCSI_READ :
				  		ISCSI_NONE;
	cmd->data_length	= hdr->exp_xfer_len;
	cmd->first_burst_len	= hdr->length;

	if (cmd->data_direction == ISCSI_READ) {
		iscsi_datain_req_t *dr;

		if (!(dr = iscsi_allocate_datain_req()))
			return(iscsi_add_reject_from_cmd(REASON_OUT_OF_RESOURCES, 1, 1, buf, cmd));	

		iscsi_attach_datain_req(cmd, dr);
	}

	/*
	 * REPORT_LUNS never actually goes to the transport layer.
	 */
	if (hdr->cdb[0] == REPORT_LUNS) {
		cmd->cmd_flags |= ICF_REPORT_LUNS;
		if (iscsi_allocate_rl_cmd(cmd, hdr->cdb, hdr->lun) < 0)
			return(iscsi_add_reject_from_cmd(REASON_OUT_OF_RESOURCES, 1, 1, buf, cmd));

		goto build_list;
	}

	/*
	 * The CDB is going to an se_device_t.
	 */
	if ((ret = iscsi_get_lun_for_cmd(cmd, hdr->lun)) < 0) {
		if (ret == -2)
			cmd->scsi_sense_reason = WRITE_PROTECTED;
		else {
			TRACE(TRACE_VANITY, "Responding to non-acl'ed, non-existent or"
				" non-exported LUN: 0x%016Lx\n", (unsigned long long)hdr->lun);

			cmd->scsi_sense_reason = NON_EXISTENT_LUN;
		}

		cmd->cmd_flags |= ICF_SCSI_CDB_EXCEPTION;
		send_check_condition = 1;
		goto attach_cmd;
	}

	/*
	 * The Initiator Node has access to the LUN (the addressing method
	 * is handled inside of iscsi_get_lun_for_cmd()).  Now it's time to
	 * allocate 1->N transport tasks (depending on sector count and
	 * maximum request size the physical HBA(s) can handle.
	 */
	if (!(transport_ret = transport_generic_allocate_tasks(cmd, hdr->cdb)))
		goto build_list;

	if (transport_ret == -1) {
		return(iscsi_add_reject_from_cmd(REASON_OUT_OF_RESOURCES, 1, 1, buf, cmd));
	} else if (transport_ret == -2) {
		/*
		 * Unsupported SAM Opcode.  CHECK_CONDITION will be sent
		 * in iscsi_execute_cmd() during the CmdSN OOO Execution
		 * Mechinism.
		 */
		send_check_condition = 1;
		goto attach_cmd;
	}

build_list:
	if (iscsi_decide_list_to_build(cmd, hdr->length) < 0)
		return(iscsi_add_reject_from_cmd(REASON_OUT_OF_RESOURCES, 1, 1, buf, cmd));

attach_cmd:
	iscsi_attach_cmd_to_queue(conn, cmd);

	/*
	 * Check the CmdSN against ExpCmdSN/MaxCmdSN here if
	 * the Immediate Bit is not set, and no Immediate
	 * Data is attached.
	 *
	 * A PDU/CmdSN carrying Immediate Data can only
	 * be processed after the DataCRC has passed.
	 * If the DataCRC fails, the CmdSN MUST NOT
	 * be acknowledged. (See below)
	 */
	if (!cmd->immediate_data) {
		cmdsn_ret = iscsi_check_received_cmdsn(conn,
				cmd, hdr->cmd_sn);
		if ((cmdsn_ret == CMDSN_NORMAL_OPERATION) ||
		    (cmdsn_ret == CMDSN_HIGHER_THAN_EXP))
			do {} while(0);
		else if (cmdsn_ret == CMDSN_LOWER_THAN_EXP) {
			cmd->i_state = ISTATE_REMOVE;
			iscsi_add_cmd_to_immediate_queue(cmd, conn, cmd->i_state);
			return(0);
		} else { /* (cmdsn_ret == CMDSN_ERROR_CANNOT_RECOVER) */
			return(iscsi_add_reject_from_cmd(REASON_PROTOCOL_ERR, 1, 0, buf, cmd));
		}
	}
	iscsi_ack_from_expstatsn(conn, hdr->exp_stat_sn);

	/* 
	 * If no Immediate Data is attached, it's OK to return now.
	 */
	if (!cmd->immediate_data) {
		if (send_check_condition)
			return(0);

		if (cmd->unsolicited_data) {
			iscsi_set_dataout_sequence_values(cmd);

			spin_lock_bh(&cmd->dataout_timeout_lock);
			iscsi_start_dataout_timer(cmd, CONN(cmd));
			spin_unlock_bh(&cmd->dataout_timeout_lock);
		}
		
		return(0);
	}
	
	/*
	 * Early CHECK_CONDITIONs never make it to the transport processing
	 * thread.  They are processed in CmdSN order by iscsi_check_received_cmdsn()
	 * below.
	 */
	if (send_check_condition) {
		immed_ret = IMMEDIDATE_DATA_NORMAL_OPERATION;
		dump_immediate_data = 1;
		goto after_immediate_data;
	}
	
	/* 
	 * Immediate Data is present, send to the transport and block until
	 * the underlying transport plugin has allocated the buffer to
	 * receive the Immediate Write Data into.
	 */
	transport_generic_handle_cdb(cmd);
	
	down(&cmd->unsolicited_data_sem);

	if (cmd->cmd_flags & ICF_SE_CMD_FAILED) {
		immed_ret = IMMEDIDATE_DATA_NORMAL_OPERATION;
		dump_immediate_data = 1;
		goto after_immediate_data;
	}

	immed_ret = iscsi_handle_immediate_data(cmd, buf, hdr->length);
after_immediate_data:
	if (immed_ret == IMMEDIDATE_DATA_NORMAL_OPERATION) {
		/*
		 * A PDU/CmdSN carrying Immediate Data passed
		 * DataCRC, check against ExpCmdSN/MaxCmdSN if
		 * Immediate Bit is not set.
		 */
		cmdsn_ret = iscsi_check_received_cmdsn(conn,
				cmd, hdr->cmd_sn);
		/*
		 * Special case for Unsupported SAM WRITE Opcodes
		 * and ImmediateData=Yes.
		 */
		if (dump_immediate_data) {
			if (iscsi_dump_data_payload(conn, hdr->length, 1) < 0)
				return(-1);
		} else if (cmd->unsolicited_data) {
			iscsi_set_dataout_sequence_values(cmd);

			spin_lock_bh(&cmd->dataout_timeout_lock);
			iscsi_start_dataout_timer(cmd, CONN(cmd));
			spin_unlock_bh(&cmd->dataout_timeout_lock);
		}		

		if (cmdsn_ret == CMDSN_NORMAL_OPERATION)
			return(0);
		else if (cmdsn_ret == CMDSN_HIGHER_THAN_EXP)
			return(0);
		else if (cmdsn_ret == CMDSN_LOWER_THAN_EXP) {
			cmd->i_state = ISTATE_REMOVE;
			iscsi_add_cmd_to_immediate_queue(cmd, conn, cmd->i_state);
			return(0);
		} else { /* (cmdsn_ret == CMDSN_ERROR_CANNOT_RECOVER) */
			return(iscsi_add_reject_from_cmd(REASON_PROTOCOL_ERR, 1, 0, buf, cmd));
		}
	} else if (immed_ret == IMMEDIDATE_DATA_ERL1_CRC_FAILURE) {
		/*
		 * Immediate Data failed DataCRC and ERL>=1,
		 * silently drop this PDU and let the initiator
		 * plug the CmdSN gap.
		 *
		 * FIXME: Send Unsolicited NOPIN with reserved
		 * TTT here to help the initiator figure out
		 * the missing CmdSN, although they should be
		 * intelligent enough to determine the missing
		 * CmdSN and issue a retry to plug the sequence.
		 */
		cmd->i_state = ISTATE_REMOVE;
		iscsi_add_cmd_to_immediate_queue(cmd, conn, cmd->i_state);
	} else /* immed_ret == IMMEDIDATE_DATA_CANNOT_RECOVER */
		return(-1);

	return(0);
}

/*	iscsi_handle_data_out():
 *
 *
 */
static inline int iscsi_handle_data_out (iscsi_conn_t *conn, unsigned char *buf)
{
	int iov_ret, ooo_cmdsn = 0, ret;
	__u8 data_crc_failed = 0, *pad_bytes[4];
	__u32 checksum, iov_count = 0, padding = 0, rx_got = 0, rx_size = 0;
	iscsi_cmd_t *cmd = NULL;
	iscsi_map_sg_t map_sg;
	iscsi_unmap_sg_t unmap_sg;
	struct iscsi_init_scsi_data_out	*hdr;
	struct iovec *iov;
	unsigned long flags;
	
	hdr			= (struct iscsi_init_scsi_data_out *) buf;
	hdr->length		= be32_to_cpu(hdr->length);
	hdr->lun		= be64_to_cpu(hdr->lun);
	hdr->init_task_tag	= be32_to_cpu(hdr->init_task_tag);
	hdr->targ_xfer_tag	= be32_to_cpu(hdr->targ_xfer_tag);
	hdr->exp_stat_sn	= be32_to_cpu(hdr->exp_stat_sn);
	hdr->data_sn		= be32_to_cpu(hdr->data_sn);
	hdr->offset		= be32_to_cpu(hdr->offset);
	
#ifdef DEBUG_OPCODES
	print_init_scsi_data_out(hdr);
#endif

	if (!hdr->length) {
		TRACE_ERROR("DataOUT payload is ZERO, protocol error.\n");
		return(iscsi_add_reject(REASON_PROTOCOL_ERR, 1, buf, conn));
	}

#ifdef SNMP_SUPPORT
	/* iSCSI write */
	spin_lock_bh(&SESS(conn)->session_stats_lock);
	SESS(conn)->rx_data_octets += hdr->length;
	if (SESS_NODE_ACL(SESS(conn))) {
		spin_lock(&SESS_NODE_ACL(SESS(conn))->stats_lock);
		SESS_NODE_ACL(SESS(conn))->write_bytes += hdr->length;
		spin_unlock(&SESS_NODE_ACL(SESS(conn))->stats_lock);
	}
	spin_unlock_bh(&SESS(conn)->session_stats_lock);
#endif /* SNMP_SUPPORT */
	
	if (hdr->length > CONN_OPS(conn)->MaxRecvDataSegmentLength) {
		TRACE_ERROR("DataSegmentLength: %u is greater than"
			" MaxRecvDataSegmentLength: %u\n",
			hdr->length, CONN_OPS(conn)->MaxRecvDataSegmentLength);
		return(iscsi_add_reject(REASON_PROTOCOL_ERR, 1, buf, conn));
	}
	
	if (!(cmd = iscsi_find_cmd_from_itt_or_dump(conn, hdr->init_task_tag,
			hdr->length)))
		return(0);

	TRACE(TRACE_ISCSI, "Got DataOut ITT: 0x%08x, TTT: 0x%08x,"
		" DataSN: 0x%08x, Offset: %u, Length: %u, CID: %hu\n",
		hdr->init_task_tag, hdr->targ_xfer_tag, hdr->data_sn,
			hdr->offset, hdr->length, conn->cid);
	
	if (cmd->cmd_flags & ICF_GOT_LAST_DATAOUT) {
		TRACE_ERROR("Command ITT: 0x%08x received DataOUT after last"
			" DataOUT received, dumping payload\n", cmd->init_task_tag);
		return(iscsi_dump_data_payload(conn, hdr->length, 1));
	}

	if (cmd->data_direction != ISCSI_WRITE) {
		TRACE_ERROR("Command ITT: 0x%08x received DataOUT for a"
			" NON-WRITE command.\n", cmd->init_task_tag);
		return(iscsi_add_reject_from_cmd(REASON_PROTOCOL_ERR, 1, 0, buf, cmd));
	}
		
	iscsi_mod_dataout_timer(cmd);

	if ((hdr->offset + hdr->length) > cmd->data_length) {
		TRACE_ERROR("DataOut Offset: %u, Length %u greater than iSCSI"
			" Command EDTL %u, protocol error.\n", hdr->offset,
				hdr->length, cmd->data_length);
		return(iscsi_add_reject_from_cmd(REASON_INVALID_PDU_FIELD, 1, 0, buf, cmd));
	}

	/*
	 * Whenever a DataOUT or DataIN PDU contains a valid TTT, the
	 * iSCSI LUN field must be set. iSCSI v20 10.7.4.  Of course,
	 * Cisco cannot figure this out.
	 */
#if 0
	if (hdr->targ_xfer_tag != 0xFFFFFFFF) {
		int lun = iscsi_unpack_lun((unsigned char *)&hdr->lun);
		if (lun != cmd->orig_fe_lun) {
			TRACE_ERROR("Received LUN: %u does not match iSCSI"
				" LUN: %u\n", lun, cmd->orig_fe_lun);
			return(iscsi_add_reject_from_cmd(REASON_INVALID_PDU_FIELD, 1, 0, buf, cmd));
		}
	}
#endif	
	if (cmd->unsolicited_data) {
		int dump_unsolicited_data = 0, wait_for_transport = 0;
		
		if (SESS_OPS_C(conn)->InitialR2T) {
			TRACE_ERROR("Received unexpected unsolicited data"
				" while InitialR2T=Yes, protocol error.\n");
			iscsi_send_check_condition_and_sense(cmd,
					UNEXPECTED_UNSOLICITED_DATA, 0);
			return(-1);
		}

		/*
		 * Special case for dealing with Unsolicited DataOUT
		 * and Unsupported SAM WRITE Opcodes and SE resource allocation
		 * failures;
		 */
		spin_lock_irqsave(&T_TASK(cmd)->t_state_lock, flags);
		wait_for_transport = (cmd->t_state != TRANSPORT_WRITE_PENDING); 
		if (wait_for_transport && cmd->immediate_data)
			wait_for_transport = 0;
		spin_unlock_irqrestore(&T_TASK(cmd)->t_state_lock, flags);

		if (wait_for_transport)
			down(&cmd->unsolicited_data_sem);

		spin_lock_bh(&cmd->istate_lock);
		if (!(cmd->cmd_flags & ICF_SUPPORTED_SAM_OPCODE) ||
		     (cmd->cmd_flags & ICF_SE_CMD_FAILED))
			dump_unsolicited_data = 1;
		spin_unlock_bh(&cmd->istate_lock);

		if (dump_unsolicited_data)
			return(iscsi_dump_data_payload(conn, hdr->length, 1));
	}

	/*
	 * Preform DataSN, DataSequenceInOrder, DataPDUInOrder, and
	 * within-command recovery checks before receiving the payload.
	 */
	ret = iscsi_check_pre_dataout(cmd, buf);
	if (ret == DATAOUT_WITHIN_COMMAND_RECOVERY)
		return(0);
	else if (ret == DATAOUT_CANNOT_RECOVER)
		return(-1);
	
	rx_size += hdr->length;
	iov = &cmd->iov_data[0];
	
	memset((void *)&map_sg, 0, sizeof(iscsi_map_sg_t));
	memset((void *)&unmap_sg, 0, sizeof(iscsi_unmap_sg_t));
	map_sg.cmd = cmd;
	map_sg.iov = iov;
	map_sg.map_flags |= MAP_SG_KMAP;
	map_sg.data_length = hdr->length;
	map_sg.data_offset = hdr->offset;
	unmap_sg.cmd = cmd;
	
	if ((iov_ret = cmd->transport_set_iovec_ptrs(&map_sg, &unmap_sg)) < 0)
		return(-1);
	
	iov_count += iov_ret;	

	if ((padding = ((-hdr->length) & 3)) != 0) {
		iov[iov_count].iov_base	= &pad_bytes;
		iov[iov_count++].iov_len = padding;
		rx_size += padding;
		TRACE(TRACE_ISCSI, "Receiving %u padding bytes.\n", padding);
	}

	if (CONN_OPS(conn)->DataDigest) {
		iov[iov_count].iov_base = &checksum;
		iov[iov_count++].iov_len = CRC_LEN;
		rx_size += CRC_LEN;
	}

	cmd->transport_map_SG_segments(&unmap_sg);
	
	rx_got = rx_data(conn, &cmd->iov_data[0], iov_count, rx_size);

	cmd->transport_unmap_SG_segments(&unmap_sg);
	
	if (rx_got != rx_size)
		return(-1);

	if (CONN_OPS(conn)->DataDigest) {
		__u8 reset_crc = 1;
		__u32 counter = hdr->length, data_crc = 0;
		struct iovec *iov_ptr = &cmd->iov_data[0];

		/* 
		 * Thanks to the IP stack shitting on passed iovecs,  we have to
		 * call set_iovec_data_ptrs() again in order to have a iMD/PSCSI
		 * agnostic way of doing datadigests computations.
		 */
		memset((void *)&map_sg, 0, sizeof(iscsi_map_sg_t));
		map_sg.cmd = cmd;
		map_sg.iov = iov_ptr;
		map_sg.data_length = hdr->length;
		map_sg.data_offset = hdr->offset;
		
		if (cmd->transport_set_iovec_ptrs(&map_sg, &unmap_sg) < 0)
			return(-1);

		while (counter > 0) {
			do_crc(iov_ptr->iov_base, iov_ptr->iov_len,
				reset_crc, &data_crc);
			reset_crc = 0;
			TRACE(TRACE_DIGEST, "Computed CRC32C DataDigest %d"
				" bytes, CRC 0x%08x\n", iov_ptr->iov_len, data_crc);
			counter -= iov_ptr->iov_len;
			iov_ptr++;
		}

		if (padding) {
			do_crc((__u8 *)&pad_bytes, padding, reset_crc, &data_crc);
			reset_crc = 0;
			TRACE(TRACE_DIGEST, "Computed CRC32C DataDigest %d bytes"
				" of padding, CRC 0x%08x\n", padding, data_crc);
		}
#ifdef DEBUG_ERL
		if (iscsi_target_debugerl_data_out_0(conn, buf) < 0)
			data_crc = 0;
#endif /* DEBUG_ERL */

		if (checksum != data_crc) {
			TRACE_ERROR("ITT: 0x%08x, Offset: %u, Length: %u, DataSN:"
				" 0x%08x, CRC32C DataDigest 0x%08x does not match"
				" computed 0x%08x\n", hdr->init_task_tag, hdr->offset,
				hdr->length, hdr->data_sn, checksum, data_crc);
			data_crc_failed = 1;
		} else {
			TRACE(TRACE_DIGEST, "Got CRC32C DataDigest 0x%08x for %u"
				" bytes of Data Out\n", checksum, hdr->length);
		}
	}

#ifdef DEBUG_ERL
	{
	int ret;
	ret = iscsi_target_debugerl_data_out_1(conn, buf);
	if (ret == -1)
		return(0);
	else if (ret == -2)
		return(-1);
	}
#endif /* DEBUG_ERL */

	/*
	 * Increment post receive data and CRC values or perform
	 * within-command recovery.
	 */
	ret = iscsi_check_post_dataout(cmd, buf, data_crc_failed);
	if ((ret == DATAOUT_NORMAL) || (ret == DATAOUT_WITHIN_COMMAND_RECOVERY))
		return(0);
	else if (ret == DATAOUT_SEND_R2T) {
		iscsi_set_dataout_sequence_values(cmd);
		iscsi_build_r2ts_for_cmd(cmd, conn, 0);
	} else if (ret == DATAOUT_SEND_TO_TRANSPORT) {
		/*
		 * Handle extra special case for out of order Unsolicited Data Out.
		 */
		spin_lock_bh(&cmd->istate_lock);
		ooo_cmdsn = (cmd->cmd_flags & ICF_OOO_CMDSN);
		cmd->cmd_flags |= ICF_GOT_LAST_DATAOUT;
		cmd->i_state = ISTATE_RECEIVED_LAST_DATAOUT;
		spin_unlock_bh(&cmd->istate_lock);

		iscsi_stop_dataout_timer(cmd);
		return((!ooo_cmdsn) ? transport_generic_handle_data(cmd) : 0);
	} else /* DATAOUT_CANNOT_RECOVER */
		return(-1);
	
	return(0);
}

/*	iscsi_handle_nop_out():
 *
 *
 */
static inline int iscsi_handle_nop_out (
	iscsi_conn_t *conn,
	unsigned char *buf)
{
	unsigned char *ping_data = NULL;
	int cmdsn_ret, niov = 0, ret = 0, rx_got, rx_size;
	__u8 reset_crc = 1;
	__u32 checksum, data_crc, padding = 0;
	iscsi_cmd_t *cmd = NULL;
	struct iovec *iov = NULL;
	struct iscsi_init_nop_out *hdr;
	
	hdr			= (struct iscsi_init_nop_out *) buf;
	hdr->length		= be32_to_cpu(hdr->length);
	hdr->lun		= be64_to_cpu(hdr->lun);
	hdr->init_task_tag	= be32_to_cpu(hdr->init_task_tag);
	hdr->targ_xfer_tag	= be32_to_cpu(hdr->targ_xfer_tag);
	hdr->cmd_sn		= be32_to_cpu(hdr->cmd_sn);
	hdr->exp_stat_sn	= be32_to_cpu(hdr->exp_stat_sn);
	
#ifdef DEBUG_OPCODES
	print_init_nop_out(hdr);
#endif
	
	if ((hdr->init_task_tag == 0xFFFFFFFF) && !(hdr->opcode & I_BIT)) {
		TRACE_ERROR("NOPOUT ITT is reserved, but Immediate Bit is"
			" not set, protocol error.\n");
		return(iscsi_add_reject(REASON_PROTOCOL_ERR, 1, buf, conn));
	}

	if (hdr->length > CONN_OPS(conn)->MaxRecvDataSegmentLength) {
		TRACE_ERROR("NOPOUT Ping Data DataSegmentLength: %u is greater"
			" than MaxRecvDataSegmentLength: %u, protocol error.\n",
			hdr->length, CONN_OPS(conn)->MaxRecvDataSegmentLength);
		return(iscsi_add_reject(REASON_PROTOCOL_ERR, 1, buf, conn));
	}

	TRACE(TRACE_ISCSI, "Got NOPOUT Ping %s ITT: 0x%08x, TTT: 0x%09x,"
		" CmdSN: 0x%08x, ExpStatSN: 0x%08x, Length: %u\n",
		(hdr->init_task_tag == 0xFFFFFFFF) ? "Response" :
		"Request", hdr->init_task_tag, hdr->targ_xfer_tag,
			hdr->cmd_sn, hdr->exp_stat_sn, hdr->length);
	/*
	 * This is not a response to a Unsolicited NopIN, which means
	 * it can either be a NOPOUT ping request (with a valid ITT),
	 * or a NOPOUT not requesting a NOPIN (with a reserved ITT).
	 * Either way, make sure we allocate an iscsi_cmd_t, as both
	 * can contain ping data.
	 */
	if (hdr->targ_xfer_tag == 0xFFFFFFFF) {
		if (!(cmd = iscsi_allocate_cmd(conn)))
			return(iscsi_add_reject(REASON_OUT_OF_RESOURCES, 1, buf, conn));

		cmd->iscsi_opcode	= ISCSI_INIT_NOP_OUT;
		cmd->i_state		= ISTATE_SEND_NOPIN;
		cmd->immediate_cmd	= ((hdr->opcode & I_BIT) ? 1:0);
		SESS(conn)->init_task_tag = cmd->init_task_tag =
						hdr->init_task_tag;
		cmd->targ_xfer_tag	= 0xFFFFFFFF;
		cmd->cmd_sn		= hdr->cmd_sn;
		cmd->exp_stat_sn	= hdr->exp_stat_sn;
		cmd->data_direction	= ISCSI_NONE;
	}
	
	if (hdr->length && (hdr->targ_xfer_tag == 0xFFFFFFFF)) {
		rx_size = hdr->length;
		if (!(ping_data = (unsigned char *)
				kmalloc(hdr->length + 1, GFP_KERNEL))) {
			TRACE_ERROR("Unable to allocate memory for"
				" NOPOUT ping data.\n");
			ret = -1;
			goto out;
		}
		memset(ping_data, 0, hdr->length + 1);
		
		iov = &cmd->iov_misc[0];
		iov[niov].iov_base	= ping_data;
		iov[niov++].iov_len	= hdr->length;

		if ((padding = ((-hdr->length) & 3)) != 0) {
			TRACE(TRACE_ISCSI, "Receiving %u additional bytes"
				" for padding.\n", padding);
			iov[niov].iov_base	= &cmd->pad_bytes;
			iov[niov++].iov_len	= padding;
			rx_size += padding;
		}
		if (CONN_OPS(conn)->DataDigest) {
			iov[niov].iov_base	= &checksum;
			iov[niov++].iov_len	= CRC_LEN;
			rx_size += CRC_LEN;
		}

		rx_got = rx_data(conn, &cmd->iov_misc[0], niov, rx_size);
		if (rx_got != rx_size) {
			ret = -1;
			goto out;
		}

		if (CONN_OPS(conn)->DataDigest) {
			do_crc((__u8 *) ping_data, hdr->length,
				reset_crc, &data_crc);
			reset_crc = 0;
			if (padding)
				do_crc((__u8 *)&cmd->pad_bytes, padding,
					reset_crc, &data_crc);
			if (checksum != data_crc) {
				TRACE_ERROR("Ping data CRC32C DataDigest"
				" 0x%08x does not match computed 0x%08x\n",
					checksum, data_crc);
				if (!SESS_OPS_C(conn)->ErrorRecoveryLevel) {
					TRACE_ERROR("Unable to recover from"
					" NOPOUT Ping DataCRC failure while in"
						" ERL=0.\n");
					ret = -1;
					goto out;
				} else {
					/*
					 * Silently drop this PDU and let the
					 * initiator plug the CmdSN gap.
					 */
					TRACE(TRACE_ERL1, "Dropping NOPOUT"
					" Command CmdSN: 0x%08x due to"
					" DataCRC error.\n", hdr->cmd_sn);
					ret = 0;
					goto out;
				}
			} else {
				TRACE(TRACE_DIGEST, "Got CRC32C DataDigest"
				" 0x%08x for %u bytes of ping data.\n",
					checksum, hdr->length);
			}
		}
		
		ping_data[hdr->length] = '\0';
		/* 
		 * Attach ping data to iscsi_cmd_t->buf_ptr.
		 */
		cmd->buf_ptr = (void *)ping_data;
		cmd->buf_ptr_size = hdr->length;
		
		TRACE(TRACE_ISCSI, "Got %u bytes of NOPOUT ping"
			" data.\n", hdr->length);
		TRACE(TRACE_ISCSI, "Ping Data: \"%s\"\n", ping_data);
	}

	if (hdr->init_task_tag != 0xFFFFFFFF) {
		if (!cmd) {
			TRACE_ERROR("Checking CmdSN for NOPOUT,"
				" but cmd is NULL!\n");
			return(-1);
		}
		
		/*
		 * Initiator is expecting a NopIN ping reply,
		 */
		iscsi_attach_cmd_to_queue(conn, cmd);

		iscsi_ack_from_expstatsn(conn, hdr->exp_stat_sn);
	
		if (hdr->opcode & I_BIT) {
			iscsi_add_cmd_to_response_queue(cmd, conn, cmd->i_state);
			return(0);
		}
		
		cmdsn_ret = iscsi_check_received_cmdsn(conn, cmd, hdr->cmd_sn);
		if ((cmdsn_ret == CMDSN_NORMAL_OPERATION) ||
		    (cmdsn_ret == CMDSN_HIGHER_THAN_EXP)) {
			return(0);
		} else if (cmdsn_ret == CMDSN_LOWER_THAN_EXP) {
			cmd->i_state = ISTATE_REMOVE;
			iscsi_add_cmd_to_immediate_queue(cmd, conn, cmd->i_state);
			ret = 0;
			goto ping_out;
		} else { /* (cmdsn_ret == CMDSN_ERROR_CANNOT_RECOVER) */
			return(iscsi_add_reject_from_cmd(REASON_PROTOCOL_ERR, 1, 0, buf, cmd));
			ret = -1;
			goto ping_out;
		}

		return(0);
	}

	if (hdr->targ_xfer_tag != 0xFFFFFFFF) {
		/* 
		 * This was a response to a unsolicited NOPIN ping.
		 */
		if (!(cmd = iscsi_find_cmd_from_ttt(conn, hdr->targ_xfer_tag)))
			return(-1);
		
		iscsi_stop_nopin_response_timer(conn);

		cmd->i_state = ISTATE_REMOVE;
		iscsi_add_cmd_to_immediate_queue(cmd, conn, cmd->i_state);
		iscsi_start_nopin_timer(conn);
	} else {
		/*
		 * Initiator is not expecting a NOPIN is response.
		 * Just ignore for now.
		 * 
		 * iSCSI v19-91 10.18
		 * "A NOP-OUT may also be used to confirm a changed
		 *  ExpStatSN if another PDU will not be available
		 *  for a long time."
		 */
		ret = 0;
		goto out;
	}
	
	return(0);
out:
	if (cmd)
		iscsi_release_cmd_to_pool(cmd, SESS(conn));
ping_out:
	if (ping_data)
		kfree(ping_data);

	return(ret);
}

/*	iscsi_handle_task_mgt_cmd():
 *
 *
 */
static inline int iscsi_handle_task_mgt_cmd (
	iscsi_conn_t *conn,
	unsigned char *buf)
{
	__u8 response;
	int call_transport = 0, cmdsn_ret, out_of_order_cmdsn = 0;
	iscsi_cmd_t *cmd;
	se_device_t *dev = NULL;
	se_lun_t *lun = NULL;
	iscsi_tmr_req_t *tmr_req;
	struct iscsi_init_task_mgt_cmnd *hdr;

	hdr			= (struct iscsi_init_task_mgt_cmnd *) buf;
	hdr->length		= be32_to_cpu(hdr->length);
	hdr->init_task_tag	= be32_to_cpu(hdr->init_task_tag);
	hdr->ref_task_tag	= be32_to_cpu(hdr->ref_task_tag);
	hdr->cmd_sn		= be32_to_cpu(hdr->cmd_sn);
	hdr->exp_stat_sn	= be32_to_cpu(hdr->exp_stat_sn);
	hdr->ref_cmd_sn		= be32_to_cpu(hdr->ref_cmd_sn);
	hdr->exp_data_sn	= be32_to_cpu(hdr->exp_data_sn);
	hdr->function &= ~F_BIT;

#ifdef DEBUG_OPCODES
	print_init_task_mgt_command(hdr);
#endif

	TRACE(TRACE_ISCSI, "Got Task Management Request ITT: 0x%08x, CmdSN:"
		" 0x%08x, Function: 0x%02x, RefTaskTag: 0x%08x, RefCmdSN:"
		" 0x%08x, CID: %hu\n", hdr->init_task_tag, hdr->cmd_sn,
		hdr->function, hdr->ref_task_tag, hdr->ref_cmd_sn, conn->cid);

	if ((hdr->function != ABORT_TASK) && ((hdr->function != TASK_REASSIGN) &&
	    (hdr->ref_task_tag != RESERVED))) {
		TRACE_ERROR("RefTaskTag should be set to 0xFFFFFFFF.\n");
	}

	if ((hdr->function == TASK_REASSIGN) && !(hdr->opcode & I_BIT)) {
		TRACE_ERROR("Task Management Request TASK_REASSIGN not issued"
			" as immediate command, bad iSCSI Initiator"
				"implementation\n");
		return(iscsi_add_reject(REASON_PROTOCOL_ERR, 1, buf, conn));
	}
#if 0
	if ((hdr->function != ABORT_TASK) && (hdr->ref_cmd_sn != RESERVED)) {
		TRACE_ERROR("RefCmdSN should be set to 0xFFFFFFFF.\n"); 
	}
#endif
	if (!(tmr_req = iscsi_allocate_tmr_req()))
		return(iscsi_add_reject(REASON_OUT_OF_RESOURCES, 1, buf, conn));

	tmr_req->function = hdr->function;
	switch (hdr->function) {
	case ABORT_TASK:
		response = iscsi_tmr_abort_task(conn, tmr_req, &lun, buf);
		break;
	case ABORT_TASK_SET:
		response = iscsi_tmr_abort_task_set(conn, tmr_req, &lun, buf);
		break;
	case CLEAR_ACA:
		response = iscsi_tmr_clear_aca(conn, tmr_req, &lun, buf);
		break;
	case CLEAR_TASK_SET:
		response = iscsi_tmr_clear_task_set(conn, tmr_req, &lun, buf);
		break;
	case LUN_RESET:
		response = iscsi_tmr_lun_reset(conn, tmr_req, &lun, buf);
		break;
	case TARGET_WARM_RESET:
		response = iscsi_tmr_task_warm_reset(conn, tmr_req, buf);
		break;
	case TARGET_COLD_RESET:
		response = iscsi_tmr_task_cold_reset(conn, tmr_req, buf);
		break;
	case TASK_REASSIGN:
		response = iscsi_tmr_task_reassign(conn, tmr_req, buf);
		/*
		 * Perform sanity checks on the ExpDataSN only if the
		 * TASK_REASSIGN was successful.
		 */
		if (response != FUNCTION_COMPLETE)
			break;
			
		if (iscsi_check_task_reassign_expdatasn(tmr_req, conn) < 0) {
			iscsi_add_reject(REASON_INVALID_PDU_FIELD, 1, buf, conn);
			kfree(tmr_req);
			return(-1);
		}
		break;
	default:
		TRACE_ERROR("Unknown TMR function: 0x%02x, protocol"
			" error.\n", hdr->function);
		kfree(tmr_req);
		return(-1);
	}

	if ((hdr->function != TASK_REASSIGN) && (response == FUNCTION_COMPLETE))
		call_transport = 1;

	if (call_transport && !dev) {
		TRACE_ERROR("Need to call transport for TMR request, but"
			" iscsi_dev is NULL. Cannot continue.\n");
		kfree(tmr_req);
		return(-1);
	}
		
	if (!(cmd = iscsi_allocate_cmd(conn))) {
		iscsi_add_reject(REASON_OUT_OF_RESOURCES, 1, buf, conn);
		kfree(tmr_req);
		return (-1);
	}

	cmd->iscsi_opcode		= ISCSI_INIT_TASK_MGMT_CMND;
	cmd->i_state			= ISTATE_SEND_TASKMGTRSP;
	cmd->t_state			= TRANSPORT_PROCESS_TMR;
	cmd->immediate_cmd		= ((hdr->opcode & I_BIT) ? 1:0);
	cmd->iscsi_lun			= lun;
	SESS(conn)->init_task_tag = cmd->init_task_tag	= hdr->init_task_tag;
	cmd->targ_xfer_tag		= 0xFFFFFFFF;
	cmd->cmd_sn			= hdr->cmd_sn;
	cmd->exp_stat_sn		= hdr->exp_stat_sn;
	cmd->tmr_req			= tmr_req;	
	tmr_req->call_transport		= call_transport;
	tmr_req->function		= hdr->function;
	tmr_req->response		= response;
	tmr_req->task_cmd		= cmd;

	if (!(hdr->opcode & I_BIT)) {
		cmdsn_ret = iscsi_check_received_cmdsn
				(conn, cmd, hdr->cmd_sn);
		if (cmdsn_ret == CMDSN_NORMAL_OPERATION)
			do {} while(0);
		else if (cmdsn_ret == CMDSN_HIGHER_THAN_EXP)
			out_of_order_cmdsn = 1;
		else if (cmdsn_ret == CMDSN_LOWER_THAN_EXP) {
			iscsi_release_cmd_to_pool(cmd, SESS(conn));
			kfree(tmr_req);
			return(0);
		} else { /* (cmdsn_ret == CMDSN_ERROR_CANNOT_RECOVER) */
			iscsi_add_reject_from_cmd(REASON_PROTOCOL_ERR, 1, 0, buf, cmd);
			kfree(tmr_req);
			return(-1);
		}
	}

	iscsi_ack_from_expstatsn(conn, hdr->exp_stat_sn);
	iscsi_attach_cmd_to_queue(conn, cmd);

	if (out_of_order_cmdsn)
		return(0);
	
	/* 
	 * Found the referenced task, send to transport for processing.
	 */
	if (call_transport)
		return(transport_generic_handle_tmr(cmd, tmr_req));

	/* 
	 * Could not find the referenced LUN, task, or Task Management
	 * command not authorized or supported.  Change state and
	 * let the tx_thread send the response.
	 *
	 * For connection recovery, this is also the default action for
	 * TMR TASK_REASSIGN.
	 */
	iscsi_add_cmd_to_response_queue(cmd, conn, cmd->i_state);

	return(0);
}

/* 	iscsi_handle_text_cmd():
 *
 *
 */
//#warning FIXME: Support Text Command parameters besides SendTargets
static inline int iscsi_handle_text_cmd (
	iscsi_conn_t *conn,
	unsigned char *buf)
{ 
	char *text_ptr, *text_in;
	int cmdsn_ret, niov = 0, rx_got, rx_size;
	__u8 reset_crc = 1;
	__u32 checksum = 0, data_crc =0;
	__u32 padding = 0, pad_bytes = 0, text_length = 0;
	iscsi_cmd_t *cmd;
	struct iovec iov[3];
	struct iscsi_init_text_cmnd *hdr;

	TRACE_ENTER

	hdr			= (struct iscsi_init_text_cmnd *) buf;
	hdr->length		= be32_to_cpu(hdr->length);
	hdr->init_task_tag	= be32_to_cpu(hdr->init_task_tag);
	hdr->targ_xfer_tag	= be32_to_cpu(hdr->targ_xfer_tag);
	hdr->cmd_sn		= be32_to_cpu(hdr->cmd_sn);
	hdr->exp_stat_sn	= be32_to_cpu(hdr->exp_stat_sn);	

#ifdef DEBUG_OPCODES
	print_init_text_cmnd(hdr);
#endif

	if (hdr->length > CONN_OPS(conn)->MaxRecvDataSegmentLength) {
		TRACE_ERROR("Unable to accept text parameter length: %u"
			"greater than MaxRecvDataSegmentLength %u.\n",
		       hdr->length, CONN_OPS(conn)->MaxRecvDataSegmentLength);
		return(iscsi_add_reject(REASON_PROTOCOL_ERR, 1, buf, conn));
	}

	TRACE(TRACE_ISCSI, "Got Text Request: ITT: 0x%08x, CmdSN: 0x%08x,"
		" ExpStatSN: 0x%08x, Length: %u\n", hdr->init_task_tag,
			hdr->cmd_sn, hdr->exp_stat_sn, hdr->length);
	
	rx_size = text_length = hdr->length;
	if (text_length) {
		if (!(text_in = (char *) kmalloc(text_length, GFP_KERNEL))) {
			TRACE_ERROR("Unable to allocate memory for"
				" incoming text parameters\n");
			return(-1);
		}
		memset(text_in, 0, text_length);

		memset(iov, 0, 3 * sizeof (struct iovec));
		iov[niov].iov_base	= text_in;
		iov[niov++].iov_len	= text_length;
	
		if ((padding = ((-hdr->length) & 3)) != 0) {
			iov[niov].iov_base = &pad_bytes;
			iov[niov++].iov_len  = padding;
			rx_size += padding;
			TRACE(TRACE_ISCSI, "Receiving %u additional bytes"
					" for padding.\n", padding);
		}
		if (CONN_OPS(conn)->DataDigest) {
			iov[niov].iov_base	= &checksum;
			iov[niov++].iov_len	= CRC_LEN;
			rx_size += CRC_LEN;
		}

		rx_got = rx_data(conn, &iov[0], niov, rx_size);
		if (rx_got != rx_size) {
			kfree(text_in);
			return(-1);
		}

		if (CONN_OPS(conn)->DataDigest) {
			do_crc((__u8 *) text_in, text_length,
				reset_crc, &data_crc);
			reset_crc = 0;
			if (padding)
				do_crc((__u8 *)&pad_bytes, padding,
					reset_crc, &data_crc);
			if (checksum != data_crc) {
				TRACE_ERROR("Text data CRC32C DataDigest 0x%08x"
					" does not match computed 0x%08x\n",
					checksum, data_crc);
				if (!SESS_OPS_C(conn)->ErrorRecoveryLevel) {
					TRACE_ERROR("Unable to recover from"
					" Text Data digest failure while in"
						" ERL=0.\n");
					kfree(text_in);
					return(-1);
				} else {
					/* 
					 * Silently drop this PDU and let the
					 * initiator plug the CmdSN gap.
					 */
					TRACE(TRACE_ERL1, "Dropping Text"
					" Command CmdSN: 0x%08x due to"
					" DataCRC error.\n", hdr->cmd_sn);
					kfree(text_in);
					return(0);
				}
			} else {
				TRACE(TRACE_DIGEST, "Got CRC32C DataDigest 0x%08x"
					" for %u bytes of text data.\n",
						checksum, text_length);
			}
		}
		text_in[text_length - 1] = '\0';
		TRACE(TRACE_ISCSI, "Successfully read %d bytes of text"
				" data.\n", text_length);

		if (strncmp("SendTargets", text_in, 11) != 0) {
			TRACE_ERROR("Received Text Data that is not"
				" SendTargets, cannot continue.\n");
			kfree(text_in);
			return(-1);
		}
		if (!(text_ptr = strchr(text_in, '='))) {
			TRACE_ERROR("No \"=\" separator found in Text Data,"
				"  cannot continue.\n");
			kfree(text_in);
			return(-1);
		}
		if (strncmp("=All", text_ptr, 4) != 0) {
			TRACE_ERROR("Unable to locate All value for"
				" SendTargets key,  cannot continue.\n");
			kfree(text_in);
			return(-1);
		}
//#warning Support SendTargets=(iSCSI Target Name/Nothing) values.
		kfree(text_in); 
	}

	if (!(cmd = iscsi_allocate_cmd(conn)))
		return(iscsi_add_reject(REASON_OUT_OF_RESOURCES, 1, buf, conn));

	cmd->iscsi_opcode	= ISCSI_INIT_TEXT_CMND;
	cmd->i_state		= ISTATE_SEND_TEXTRSP;
	cmd->immediate_cmd	= ((hdr->opcode & I_BIT) ? 1:0);
	SESS(conn)->init_task_tag = cmd->init_task_tag	= hdr->init_task_tag;
	cmd->targ_xfer_tag	= 0xFFFFFFFF;
	cmd->cmd_sn		= hdr->cmd_sn;
	cmd->exp_stat_sn	= hdr->exp_stat_sn;
	cmd->data_direction	= ISCSI_NONE;

	iscsi_attach_cmd_to_queue(conn, cmd);
	iscsi_ack_from_expstatsn(conn, hdr->exp_stat_sn);
	
	if (!(hdr->opcode & I_BIT)) {
		cmdsn_ret = iscsi_check_received_cmdsn(conn, cmd, hdr->cmd_sn);
		if ((cmdsn_ret == CMDSN_NORMAL_OPERATION) ||
		     (cmdsn_ret == CMDSN_HIGHER_THAN_EXP))
			return(0);
		else if (cmdsn_ret == CMDSN_LOWER_THAN_EXP) {
			iscsi_add_cmd_to_immediate_queue(cmd, conn, ISTATE_REMOVE);
			return(0);
		} else { /* (cmdsn_ret == CMDSN_ERROR_CANNOT_RECOVER) */
			return(iscsi_add_reject_from_cmd(REASON_PROTOCOL_ERR, 1, 0, buf, cmd));
		}

		return(0);
	}

	return(iscsi_execute_cmd(cmd, 0));
}

/*	iscsi_logout_closesession():
 *
 *
 */
extern int iscsi_logout_closesession (iscsi_cmd_t *cmd, iscsi_conn_t *conn)
{
	iscsi_conn_t *conn_p;
	iscsi_session_t *sess = SESS(conn);
	
	TRACE_ENTER

	TRACE(TRACE_ISCSI, "Received logout request CLOSESESSION on CID: %hu"
		" for SID: %u.\n", conn->cid, SESS(conn)->sid);

	atomic_set(&sess->session_logout, 1);
	atomic_set(&conn->conn_logout_remove, 1);
	conn->conn_logout_reason = CLOSESESSION;
	
	spin_lock_bh(&sess->conn_lock);
	for (conn_p = sess->conn_head; conn_p; conn_p = conn_p->next) {
		if (conn_p->conn_state != TARG_CONN_STATE_LOGGED_IN)
			continue;
		
		iscsi_inc_conn_usage_count(conn_p);
		TRACE(TRACE_STATE, "Moving to TARG_CONN_STATE_IN_LOGOUT.\n");
		conn_p->conn_state = TARG_CONN_STATE_IN_LOGOUT;
		iscsi_dec_conn_usage_count(conn_p);
	}
	spin_unlock_bh(&sess->conn_lock);
	
	iscsi_add_cmd_to_response_queue(cmd, conn, cmd->i_state);
	
	return(0);
}

/*	iscsi_logout_closeconnection():
 *
 *
 */
extern int iscsi_logout_closeconnection (iscsi_cmd_t *cmd, iscsi_conn_t *conn)
{
	iscsi_conn_t *l_conn;
	iscsi_session_t *sess = SESS(conn);
	
	TRACE(TRACE_ISCSI, "Received logout request CLOSECONNECTION for CID:"
		" %hu on CID: %hu.\n", cmd->logout_cid, conn->cid);

	/*
	 * A Logout Request with a CLOSECONNECTION reason code for a CID
	 * can arrive on a connection with a differing CID.
	 */
	if (conn->cid == cmd->logout_cid) {
		spin_lock(&conn->state_lock);
		TRACE(TRACE_STATE, "Moving to TARG_CONN_STATE_IN_LOGOUT.\n");
		conn->conn_state = TARG_CONN_STATE_IN_LOGOUT;
		atomic_set(&conn->conn_logout_remove, 1);
		conn->conn_logout_reason = CLOSECONNECTION;
		spin_unlock(&conn->state_lock);
	} else {
		/*
		 * Handle all different cid CLOSECONNECTION requests in
		 * iscsi_logout_post_handler_diffcid() as to give enough
		 * time for any non immediate command's CmdSN to be
		 * acknowledged on the connection in question.
		 *
		 * Here we simply make sure the CID is still around.
		 */
		if (!(l_conn = iscsi_get_conn_from_cid(sess,
				cmd->logout_cid))) {
			cmd->logout_response = CIDNOTFOUND;
			iscsi_add_cmd_to_response_queue(cmd, conn, cmd->i_state);
			return(0);
		}

		iscsi_dec_conn_usage_count(l_conn);
	}

	iscsi_add_cmd_to_response_queue(cmd, conn, cmd->i_state);

	return(0);
}

/*	iscsi_logout_removeconnforrecovery():
 *
 *
 */
extern int iscsi_logout_removeconnforrecovery (iscsi_cmd_t *cmd, iscsi_conn_t *conn)
{
	iscsi_session_t *sess = SESS(conn);
	
	TRACE(TRACE_ERL2, "Received explicit REMOVECONNFORRECOVERY logout for"
		" CID: %hu on CID: %hu.\n", cmd->logout_cid, conn->cid);
		
	if (SESS_OPS(sess)->ErrorRecoveryLevel != 2) {
		TRACE_ERROR("Received Logout Request REMOVECONNFORRECOVERY"
			" while ERL!=2.\n");
		cmd->logout_response = CONNRECOVERYNOTSUPPORTED;
		iscsi_add_cmd_to_response_queue(cmd, conn, cmd->i_state);
		return(0);
	}

	if (conn->cid == cmd->logout_cid) {
		TRACE_ERROR("Received Logout Request REMOVECONNFORRECOVERY"
			" with CID: %hu on CID: %hu, implementation error.\n",
				cmd->logout_cid, conn->cid);
		cmd->logout_response = CLEANUPFAILED;
		iscsi_add_cmd_to_response_queue(cmd, conn, cmd->i_state);
		return(0);
	}

	iscsi_add_cmd_to_response_queue(cmd, conn, cmd->i_state);

	return(0);
}

/*	iscsi_handle_logout_cmd():
 *
 *
 */
static inline int iscsi_handle_logout_cmd (
	iscsi_conn_t *conn,
	unsigned char *buf)
{
	int cmdsn_ret, logout_remove = 0;
	u8 reason_code = 0;
	iscsi_cmd_t *cmd;
	struct iscsi_init_logout_cmnd *hdr;

	TRACE_ENTER

	hdr			= (struct iscsi_init_logout_cmnd *) buf;
	reason_code		= (hdr->flags & 0x7f);
	hdr->init_task_tag	= be32_to_cpu(hdr->init_task_tag);
	hdr->cid		= be16_to_cpu(hdr->cid);
	hdr->cmd_sn		= be32_to_cpu(hdr->cmd_sn);
	hdr->exp_stat_sn	= be32_to_cpu(hdr->exp_stat_sn);

#ifdef DEBUG_OPCODES
	print_init_logout_cmnd(hdr);
#endif
#ifdef SNMP_SUPPORT
	{
	iscsi_tiqn_t *tiqn = iscsi_snmp_get_tiqn(conn);

	spin_lock(&tiqn->logout_stats.lock);
	if (reason_code == CLOSESESSION)
		tiqn->logout_stats.normal_logouts++;
	else
		tiqn->logout_stats.abnormal_logouts++;
	spin_unlock(&tiqn->logout_stats.lock);
	}
#endif /* SNMP_SUPPORT */

	TRACE(TRACE_ISCSI, "Got Logout Request ITT: 0x%08x CmdSN: 0x%08x"
		" ExpStatSN: 0x%08x Reason: 0x%02x CID: %hu on CID: %hu\n",
			hdr->init_task_tag, hdr->cmd_sn, hdr->exp_stat_sn,
				reason_code, hdr->cid, conn->cid);

	if (conn->conn_state != TARG_CONN_STATE_LOGGED_IN) {
		TRACE_ERROR("Received logout request on connection that is not"
			" in logged in state, ignoring request.\n");
		return(0);
	}

	if (!(cmd = iscsi_allocate_cmd(conn)))
		return(iscsi_add_reject(REASON_OUT_OF_RESOURCES, 1, buf, conn));
	
	cmd->iscsi_opcode       = ISCSI_INIT_LOGOUT_CMND;
	cmd->i_state            = ISTATE_SEND_LOGOUTRSP; 
	cmd->immediate_cmd      = ((hdr->opcode & I_BIT) ? 1:0);
	SESS(conn)->init_task_tag = cmd->init_task_tag  = hdr->init_task_tag;
	cmd->targ_xfer_tag      = 0xFFFFFFFF;
	cmd->cmd_sn             = hdr->cmd_sn;
	cmd->exp_stat_sn        = hdr->exp_stat_sn;
	cmd->logout_cid         = hdr->cid;
	cmd->logout_reason      = reason_code;
	cmd->data_direction     = ISCSI_NONE;

	/*
	 * We need to sleep in these cases (by returning 1) until the Logout
	 * Response gets sent in the tx thread.
	 */
	if ((reason_code == CLOSESESSION) ||
	   ((reason_code == CLOSECONNECTION) && (hdr->cid == conn->cid)))
		logout_remove = 1;
	
	iscsi_attach_cmd_to_queue(conn, cmd);

	if (reason_code != REMOVECONNFORRECOVERY)
		iscsi_ack_from_expstatsn(conn, hdr->exp_stat_sn);
	
	/*
	 * Non-Immediate Logout Commands are executed in CmdSN order..
	 */
	if (!(hdr->opcode & I_BIT)) {
		cmdsn_ret = iscsi_check_received_cmdsn(conn, cmd, hdr->cmd_sn);
		if ((cmdsn_ret == CMDSN_NORMAL_OPERATION) ||
		    (cmdsn_ret == CMDSN_HIGHER_THAN_EXP))
			return(logout_remove);
		else if (cmdsn_ret == CMDSN_LOWER_THAN_EXP) {
			cmd->i_state = ISTATE_REMOVE;
			iscsi_add_cmd_to_immediate_queue(cmd, conn, cmd->i_state);
			return(0);
		} else { /* (cmdsn_ret == CMDSN_ERROR_CANNOT_RECOVER) */
			return(iscsi_add_reject_from_cmd(REASON_PROTOCOL_ERR, 1, 0, buf, cmd));
		}
        }

	/*
	 * Immediate Logout Commands are executed, well, Immediately.
	 */
	if (iscsi_execute_cmd(cmd, 0) < 0)
		return(-1);

	return(logout_remove);
}

/*	iscsi_handle_snack():
 *
 *
 */
static inline int iscsi_handle_snack (
	iscsi_conn_t *conn,
	unsigned char *buf)
{
	__u32 debug_type;
	struct iscsi_init_snack *hdr;

	hdr			= (struct iscsi_init_snack *) buf;
	hdr->type		&= ~F_BIT;
	hdr->lun		= be64_to_cpu(hdr->lun);
	hdr->init_task_tag	= be32_to_cpu(hdr->init_task_tag);
	hdr->targ_xfer_tag	= be32_to_cpu(hdr->targ_xfer_tag);
	hdr->exp_stat_sn	= be32_to_cpu(hdr->exp_stat_sn);
	hdr->begrun		= be32_to_cpu(hdr->begrun);
	hdr->runlength		= be32_to_cpu(hdr->runlength);

#ifdef DEBUG_OPCODES
	print_init_snack(hdr);
#endif
	debug_type = (hdr->type & 0x02) ? TRACE_ISCSI : TRACE_ERL1;
	TRACE(debug_type, "Got ISCSI_INIT_SNACK, ITT: 0x%08x, ExpStatSN:"
		" 0x%08x, Type: 0x%02x, BegRun: 0x%08x, RunLength: 0x%08x,"
		" CID: %hu\n", hdr->init_task_tag, hdr->exp_stat_sn, hdr->type,
			hdr->begrun, hdr->runlength, conn->cid);

        if (!SESS_OPS_C(conn)->ErrorRecoveryLevel) {
		TRACE_ERROR("Initiator sent SNACK request while in"
			" ErrorRecoveryLevel=0.\n");
		return(iscsi_add_reject(REASON_PROTOCOL_ERR, 1, buf, conn));
	}

	/* 
	 * SNACK_DATA and SNACK_R2T are both 0,  so check which function to
	 * call from inside iscsi_send_recovery_datain_or_r2t().
	 */
	switch (hdr->type & 0x0f) {
	case 0:
		return(iscsi_handle_recovery_datain_or_r2t(conn, buf,
			hdr->init_task_tag, hdr->targ_xfer_tag,
			 	hdr->begrun, hdr->runlength));
		return(0);
	case SNACK_STATUS:
		return(iscsi_handle_status_snack(conn,
			hdr->init_task_tag, hdr->targ_xfer_tag,
				hdr->begrun, hdr->runlength));
	case SNACK_DATA_ACK:
		return(iscsi_handle_data_ack(conn, hdr->targ_xfer_tag,
				hdr->begrun, hdr->runlength));
	case SNACK_RDATA:
		/* FIXME: Support R-Data SNACK */
		TRACE_ERROR("R-Data SNACK Not Supported.\n");
		return(iscsi_add_reject(REASON_PROTOCOL_ERR, 1, buf, conn));
	default:
		TRACE_ERROR("Unknown SNACK type 0x%02x, protocol"
			" error.\n", hdr->type & 0x0f);
		return(iscsi_add_reject(REASON_PROTOCOL_ERR, 1, buf, conn));
	}

	return(0);
}

/*	iscsi_handle_immediate_data():
 *
 *
 */
static int iscsi_handle_immediate_data (
	iscsi_cmd_t *cmd,
	unsigned char *buf,
	__u32 length)
{
	int iov_ret, rx_got = 0, rx_size = 0;
	__u32 checksum, iov_count = 0, padding = 0, pad_bytes = 0;
	iscsi_conn_t *conn = cmd->conn;
	iscsi_map_sg_t map_sg;
	iscsi_unmap_sg_t unmap_sg;
	struct iovec *iov;
	
	memset((void *)&map_sg, 0, sizeof(iscsi_map_sg_t));
	memset((void *)&unmap_sg, 0, sizeof(iscsi_unmap_sg_t));
	map_sg.cmd = cmd;
	map_sg.map_flags |= MAP_SG_KMAP;
	map_sg.iov = &cmd->iov_data[0];
	map_sg.data_length = length;
	map_sg.data_offset = cmd->write_data_done;
	unmap_sg.cmd = cmd;

	if ((iov_ret = cmd->transport_set_iovec_ptrs(&map_sg, &unmap_sg)) < 0)
		return(IMMEDIDATE_DATA_CANNOT_RECOVER);

	rx_size = length;
	iov_count = iov_ret;
	iov = &cmd->iov_data[0];
	
	if ((padding = ((-length) & 3)) != 0) {
		iov[iov_count].iov_base	= &pad_bytes;
		iov[iov_count++].iov_len = padding;
		rx_size += padding; 
	}

	if (CONN_OPS(conn)->DataDigest) {
		iov[iov_count].iov_base 	= &checksum;
		iov[iov_count++].iov_len 	= CRC_LEN;
		rx_size += CRC_LEN;
	}
	
	cmd->transport_map_SG_segments(&unmap_sg);
	
	rx_got = rx_data(conn, &cmd->iov_data[0], iov_count, rx_size);

	cmd->transport_unmap_SG_segments(&unmap_sg);
	
	if (rx_got != rx_size) {
		iscsi_rx_thread_wait_for_TCP(conn);
		return(IMMEDIDATE_DATA_CANNOT_RECOVER);
	}

	if (CONN_OPS(conn)->DataDigest) {
		__u8 reset_crc = 1;
		__u32 counter = length, data_crc;
		struct iovec *iov_ptr = &cmd->iov_data[0];

		/* 
		 * Thanks to the IP stack shitting on passed iovecs,  we have to
		 * call set_iovec_data_ptrs again in order to have a iMD/PSCSI
		 * agnostic way of doing datadigests computations.
		 */
		memset((void *)&map_sg, 0, sizeof(iscsi_map_sg_t));
		map_sg.cmd = cmd;
		map_sg.iov = iov_ptr;
		map_sg.data_length = length;
		map_sg.data_offset = cmd->write_data_done;

		if (cmd->transport_set_iovec_ptrs(&map_sg, &unmap_sg) < 0)
			return(IMMEDIDATE_DATA_CANNOT_RECOVER);

		while (counter > 0) {
			do_crc(iov_ptr->iov_base, iov_ptr->iov_len,
				reset_crc, &data_crc);
			reset_crc = 0;
			TRACE(TRACE_DIGEST, "Computed CRC32C DataDigest %d"
			" bytes, CRC 0x%08x\n", iov_ptr->iov_len, data_crc);
			counter -= iov_ptr->iov_len;
			iov_ptr++;
		}

		if (padding) {
			do_crc((__u8 *)&pad_bytes, padding,
				reset_crc, &data_crc);
			reset_crc = 0;
			TRACE(TRACE_DIGEST, "Computed CRC32C DataDigest %d"
			" bytes of padding, CRC 0x%08x\n", padding, data_crc);
		}
		
#ifdef DEBUG_ERL
		if (iscsi_target_debugerl_immeidate_data(conn, cmd->init_task_tag) < 0)
			data_crc = 0;
#endif /* DEBUG_ERL */
		
		if (checksum != data_crc) {
			TRACE_ERROR("ImmediateData CRC32C DataDigest 0x%08x"
				" does not match computed 0x%08x\n", checksum, data_crc);

			if (!SESS_OPS_C(conn)->ErrorRecoveryLevel) {
				TRACE_ERROR("Unable to recover from Immediate Data"
					" digest failure while in ERL=0.\n");
				iscsi_add_reject_from_cmd(REASON_DATA_DIGEST_ERR, 1, 0, buf, cmd);
				return(IMMEDIDATE_DATA_CANNOT_RECOVER);
			} else {
				iscsi_add_reject_from_cmd(REASON_DATA_DIGEST_ERR, 0, 0, buf, cmd);
				return(IMMEDIDATE_DATA_ERL1_CRC_FAILURE);
			}
		} else {
			TRACE(TRACE_DIGEST, "Got CRC32C DataDigest 0x%08x for %u"
				" bytes of Immediate Data\n", checksum, length);
		}
	}

	cmd->write_data_done += length;

	if (cmd->write_data_done == cmd->data_length) {
		spin_lock_bh(&cmd->istate_lock);
		cmd->cmd_flags |= ICF_GOT_LAST_DATAOUT;
		cmd->i_state = ISTATE_RECEIVED_LAST_DATAOUT;
		spin_unlock_bh(&cmd->istate_lock);
	}

	return(IMMEDIDATE_DATA_NORMAL_OPERATION);
}

/*	iscsi_send_async_msg():
 *
 *	FIXME: Support SCSI AEN.
 */
extern int iscsi_send_async_msg (
	iscsi_conn_t *conn,
	__u16 cid,
	__u8 async_event,
	__u8 async_vcode)
{
	__u8 iscsi_hdr[ISCSI_HDR_LEN+CRC_LEN];
	__u32 tx_send = ISCSI_HDR_LEN, tx_sent = 0;
	struct timer_list async_msg_timer;
	struct iscsi_targ_async_msg *hdr;
	struct iovec iov;

	memset((void *)&iov, 0, sizeof(struct iovec));
	memset((void *)&iscsi_hdr, 0, ISCSI_HDR_LEN);

	hdr		= (struct iscsi_targ_async_msg *)&iscsi_hdr;
	hdr->opcode	= ISCSI_TARG_ASYNC_MSG;
	hdr->flags	|= F_BIT;
	hdr->length	= 0;	
	hdr->lun	= 0;
	hdr->reserved2	= 0xffffffff;
	hdr->stat_sn	= cpu_to_be32(conn->stat_sn++);
	spin_lock(&SESS(conn)->cmdsn_lock);
	hdr->exp_cmd_sn	= cpu_to_be32(SESS(conn)->exp_cmd_sn);
	hdr->max_cmd_sn	= cpu_to_be32(SESS(conn)->max_cmd_sn);
	spin_unlock(&SESS(conn)->cmdsn_lock);
	hdr->async_event = async_event;
	hdr->async_vcode = async_vcode;

	switch (async_event) {
	case ASYNC_EVENT_SCSI_EVENT:
		TRACE_ERROR("ASYNC_EVENT_SCSI_EVENT not supported yet.\n");
		return(-1);
	case ASYNC_EVENT_REQUEST_LOGOUT:
		TRACE(TRACE_STATE, "Moving to TARG_CONN_STATE_LOGOUT_REQUESTED.\n");
		conn->conn_state = TARG_CONN_STATE_LOGOUT_REQUESTED;
		hdr->parameter1 = 0;
		hdr->parameter2 = 0;
		hdr->parameter3 = cpu_to_be16(SECONDS_FOR_ASYNC_LOGOUT);
		break;
	case ASYNC_EVENT_DROP_CONNECTION:
		hdr->parameter1 = cpu_to_be16(cid);
		hdr->parameter2 = cpu_to_be16(SESS_OPS_C(conn)->DefaultTime2Wait);
		hdr->parameter3 = cpu_to_be16(SESS_OPS_C(conn)->DefaultTime2Retain);
		break;
	case ASYNC_EVENT_DROP_SESSION:
		hdr->parameter1 = 0;
		hdr->parameter2 = cpu_to_be16(SESS_OPS_C(conn)->DefaultTime2Wait);
		hdr->parameter3 = cpu_to_be16(SESS_OPS_C(conn)->DefaultTime2Retain);
		break;
	case ASYNC_EVENT_REQUEST_TEXT:
		hdr->parameter1 = 0;
		hdr->parameter2 = 0;
		hdr->parameter3 = cpu_to_be16(SECONDS_FOR_ASYNC_TEXT);
		break;
	case ASYNC_EVENT_VENDOR_SPECIFIC:
		TRACE_ERROR("ASYNC_EVENT_VENDOR_SPECIFIC not"
			" supported yet.\n");
		return(-1);
	default:
		TRACE_ERROR("Unknown AsycnEvent 0x%02x, protocol"
			" error.\n", async_event);
		return(-1);
	}

	iov.iov_base	= &iscsi_hdr;
	iov.iov_len	= ISCSI_HDR_LEN;

	if (CONN_OPS(conn)->HeaderDigest) {
		do_crc((__u8 *)&iscsi_hdr, ISCSI_HDR_LEN, 0x01,
				&hdr->header_digest);
		iov.iov_len += CRC_LEN;
		tx_send += CRC_LEN;
		TRACE(TRACE_DIGEST, "Attaching CRC32 HeaderDigest for Async"
			" Msg PDU 0x%08x\n", hdr->header_digest);
	}

	TRACE(TRACE_ISCSI, "Built Async Message StatSN: 0x%08x, AsyncEvent:"
		" 0x%02x, P1: 0x%04x, P2: 0x%04x, P3: 0x%04x\n", ntohl(hdr->stat_sn),
			hdr->async_event, ntohs(hdr->parameter1), ntohs(hdr->parameter2),
				ntohs(hdr->parameter3));

#ifdef DEBUG_OPCODES
	print_targ_async_msg(hdr);
#endif

	tx_sent = tx_data(conn, &iov, 1, tx_send);
	if (tx_sent != tx_send) {
		TRACE_ERROR("tx_data returned %d expecting %d\n", tx_sent, tx_send);
		return(-1);
	}

	if (async_event == ASYNC_EVENT_REQUEST_LOGOUT) {
		init_timer(&async_msg_timer);
		SETUP_TIMER(async_msg_timer, SECONDS_FOR_ASYNC_LOGOUT,
			&SESS(conn)->async_msg_sem, iscsi_async_msg_timer_function);
		add_timer(&async_msg_timer);
		down(&SESS(conn)->async_msg_sem);
		del_timer_sync(&async_msg_timer);

		if (conn->conn_state == TARG_CONN_STATE_LOGOUT_REQUESTED) {
			TRACE_ERROR("Asynchronous message timer expired without"
				" receiving a logout request,  dropping iSCSI session.\n");
			iscsi_send_async_msg(conn, 0, ASYNC_EVENT_DROP_SESSION, 0);
			iscsi_free_session(SESS(conn));
		}
	}

	return(0);
}

/*	iscsi_build_conn_drop_async_message():
 *
 *	Called with sess->conn_lock held.
 */
//#warning iscsi_build_conn_drop_async_message() only sends out on connections with active network interface
static void iscsi_build_conn_drop_async_message (iscsi_conn_t *conn)
{
	iscsi_cmd_t *cmd;
	iscsi_conn_t *conn_p;
	
	/*
	 * Only send a Asynchronous Message on connections whos network
	 * interface is still functional.
	 */
	for (conn_p = SESS(conn)->conn_head; conn_p; conn_p = conn_p->next) {
		if ((conn_p->conn_state == TARG_CONN_STATE_LOGGED_IN) &&
		    (iscsi_check_for_active_network_device(conn_p))) {
			iscsi_inc_conn_usage_count(conn_p);
			break;
		}
	}

	if (!conn_p)
		return;

	if (!(cmd = iscsi_allocate_cmd(conn_p))) {
		iscsi_dec_conn_usage_count(conn_p);
		return;
	}

	cmd->logout_cid = conn->cid;
	cmd->iscsi_opcode = ISCSI_TARG_ASYNC_MSG;	
	cmd->i_state = ISTATE_SEND_ASYNCMSG;

	iscsi_attach_cmd_to_queue(conn_p, cmd);
	iscsi_add_cmd_to_response_queue(cmd, conn_p, cmd->i_state);

	iscsi_dec_conn_usage_count(conn_p);

	return;
		
}

/*	iscsi_send_conn_drop_async_message():
 *
 *
 */
static int iscsi_send_conn_drop_async_message (
	iscsi_cmd_t *cmd,
	iscsi_conn_t *conn)
{
	struct iscsi_targ_async_msg *hdr;
	
	TRACE_ENTER

	cmd->tx_size = ISCSI_HDR_LEN;
	cmd->iscsi_opcode = ISCSI_TARG_ASYNC_MSG;

	hdr			= (struct iscsi_targ_async_msg *) cmd->pdu;
	hdr->opcode		= ISCSI_TARG_ASYNC_MSG;
	hdr->flags		= F_BIT;
	cmd->init_task_tag	= 0xFFFFFFFF;
	cmd->targ_xfer_tag	= 0xFFFFFFFF;
	hdr->reserved2		= 0xFFFFFFFF;
	cmd->stat_sn		= conn->stat_sn++;
	hdr->stat_sn		= cpu_to_be32(cmd->stat_sn);
	hdr->exp_cmd_sn 	= cpu_to_be32(SESS(conn)->exp_cmd_sn);
	hdr->max_cmd_sn		= cpu_to_be32(SESS(conn)->max_cmd_sn);
	hdr->async_event 	= ASYNC_EVENT_DROP_CONNECTION;
	hdr->parameter1		= cpu_to_be16(cmd->logout_cid);
	hdr->parameter2		= cpu_to_be16(SESS_OPS_C(conn)->DefaultTime2Wait);
	hdr->parameter3		= cpu_to_be16(SESS_OPS_C(conn)->DefaultTime2Retain);
	
	if (CONN_OPS(conn)->HeaderDigest) {
		do_crc((unsigned char *)hdr, ISCSI_HDR_LEN,
			0x01, &hdr->header_digest);
		cmd->tx_size += CRC_LEN;
		TRACE(TRACE_DIGEST, "Attaching CRC32C HeaderDigest to"
			" Async Message 0x%08x\n", hdr->header_digest);
	}

	cmd->iov_misc[0].iov_base	= cmd->pdu;
	cmd->iov_misc[0].iov_len	= cmd->tx_size;
	cmd->iov_misc_count		= 1;

	TRACE(TRACE_ERL2, "Sending Connection Dropped Async Message StatSN:"
		" 0x%08x, for CID: %hu on CID: %hu\n", cmd->stat_sn,
			cmd->logout_cid, conn->cid);
	
#ifdef DEBUG_OPCODES
	print_targ_async_msg(hdr);
#endif

	return(0);
}

/*	iscsi_send_data_in():
 *
 *
 */
static inline int iscsi_send_data_in (
	iscsi_cmd_t *cmd,
	iscsi_conn_t *conn,
	iscsi_unmap_sg_t *unmap_sg,
	int *eodr)
{
	int iov_ret = 0, set_statsn = 0;
	__u8 *pad_bytes, reset_crc = 1;
	__u32 iov_count = 0, tx_size = 0;
	iscsi_datain_t datain;
	iscsi_datain_req_t *dr;
	iscsi_map_sg_t map_sg;
	struct iscsi_targ_scsi_data_in *hdr;
	struct iovec *iov;

	memset(&datain, 0, sizeof(iscsi_datain_t));	
	if (!(dr = iscsi_get_datain_values(cmd, &datain))) {
		TRACE_ERROR("iscsi_get_datain_values failed for ITT: 0x%08x\n",
				cmd->init_task_tag);
		return(-1);
	}

	/*
	 * Be paranoid and double check the logic for now.
	 */
	if ((datain.offset + datain.length) > cmd->data_length) {
		TRACE_ERROR("Command ITT: 0x%08x, datain.offset: %u and"
			" datain.length: %u exceeds cmd->data_length: %u\n",
			cmd->init_task_tag, datain.offset, datain.length,
				cmd->data_length);
		return(-1);
	}

#ifdef SNMP_SUPPORT
	spin_lock_bh(&SESS(conn)->session_stats_lock);
	SESS(conn)->tx_data_octets += datain.length;
	if (SESS_NODE_ACL(SESS(conn))) {
		spin_lock(&SESS_NODE_ACL(SESS(conn))->stats_lock);
		SESS_NODE_ACL(SESS(conn))->read_bytes += datain.length;
		spin_unlock(&SESS_NODE_ACL(SESS(conn))->stats_lock);
	}
	spin_unlock_bh(&SESS(conn)->session_stats_lock);
#endif /* SNMP_SUPPORT */
	
	/*
	 * Special case for successfully execution w/ both DATAIN and Sense Data.
	 */
	if ((datain.flags & S_BIT) && (cmd->cmd_flags & ICF_TRANSPORT_TASK_SENSE))
		datain.flags &= ~S_BIT;
	else {
		if ((dr->dr_complete == DATAIN_COMPLETE_NORMAL) ||
		    (dr->dr_complete == DATAIN_COMPLETE_CONNECTION_RECOVERY)) {
			iscsi_increment_maxcmdsn(cmd, SESS(conn));
			cmd->stat_sn = conn->stat_sn++;
			set_statsn = 1;
		} else if (dr->dr_complete == DATAIN_COMPLETE_WITHIN_COMMAND_RECOVERY)
			set_statsn = 1;
	}

	hdr	= (struct iscsi_targ_scsi_data_in *) cmd->pdu;
	memset(hdr, 0, ISCSI_HDR_LEN);
	hdr->opcode 		= ISCSI_TARG_SCSI_DATA_IN;		
	hdr->flags		= datain.flags;
	if (hdr->flags & S_BIT) {
		if (cmd->cmd_flags & ICF_OVERFLOW_BIT) {
			hdr->flags |= O_BIT;
			hdr->res_count = cpu_to_be32(cmd->residual_count);
		} else if (cmd->cmd_flags & ICF_UNDERFLOW_BIT) {
			hdr->flags |= U_BIT;
			hdr->res_count = cpu_to_be32(cmd->residual_count);
		}
	}
	hdr->length		= cpu_to_be32(datain.length);
	hdr->lun		= (hdr->flags & A_BIT) ?
				   iscsi_pack_lun(cmd->orig_fe_lun) :
				   0xFFFFFFFFFFFFFFFFULL;
	hdr->init_task_tag	= cpu_to_be32(cmd->init_task_tag);
	hdr->targ_xfer_tag	= (hdr->flags & A_BIT) ?
				   cpu_to_be32(cmd->targ_xfer_tag) :
				   0xFFFFFFFF;
	hdr->stat_sn		= (set_statsn) ? cpu_to_be32(cmd->stat_sn) :
						0xFFFFFFFF;
	hdr->exp_cmd_sn		= cpu_to_be32(SESS(conn)->exp_cmd_sn);
	hdr->max_cmd_sn		= cpu_to_be32(SESS(conn)->max_cmd_sn);
	hdr->data_sn		= cpu_to_be32(datain.data_sn);
	hdr->offset		= cpu_to_be32(datain.offset);

	iov = &cmd->iov_data[0];
	iov[iov_count].iov_base	= cmd->pdu;
	iov[iov_count++].iov_len	= ISCSI_HDR_LEN;
	tx_size += ISCSI_HDR_LEN;

	if (CONN_OPS(conn)->HeaderDigest) {
		do_crc((__u8 *)hdr, ISCSI_HDR_LEN, 0x01,
			&hdr->header_digest);
		iov[0].iov_len += CRC_LEN;
		tx_size += CRC_LEN;
		TRACE(TRACE_DIGEST, "Attaching CRC32 HeaderDigest"
			" for DataIN PDU 0x%08x\n", hdr->header_digest);
	}

	memset((void *)&map_sg, 0, sizeof(iscsi_map_sg_t));
	map_sg.cmd = cmd;
	map_sg.map_flags |= MAP_SG_KMAP;
	map_sg.iov = &cmd->iov_data[1];
	map_sg.data_length = datain.length;
	map_sg.data_offset = datain.offset;
	
	if ((iov_ret = cmd->transport_set_iovec_ptrs(&map_sg, unmap_sg)) < 0)
		return(-1);
	
	iov_count += iov_ret;
	tx_size += datain.length;

	if ((unmap_sg->padding = ((-datain.length) & 3)) != 0) {
		if (!(pad_bytes = (__u8 *) kmalloc(
				unmap_sg->padding * sizeof(__u8), GFP_KERNEL))) {
			TRACE_ERROR("Unable to allocate memory for pad_bytes.\n");
			return(-1);
		}
		memset(pad_bytes, 0, unmap_sg->padding);

		cmd->buf_ptr = pad_bytes;
		iov[iov_count].iov_base 	= pad_bytes;
		iov[iov_count++].iov_len 	= unmap_sg->padding;
		tx_size += unmap_sg->padding;

		TRACE(TRACE_ISCSI, "Attaching %u padding bytes\n", unmap_sg->padding);
	}
  
	if (CONN_OPS(conn)->DataDigest) {
		__u32 counter = (datain.length + unmap_sg->padding);
		struct iovec *iov_ptr = &cmd->iov_data[1];
		while (counter > 0) {
			do_crc((__u8 *)iov_ptr->iov_base, iov_ptr->iov_len,
				reset_crc, &cmd->data_crc);
			reset_crc = 0;
			TRACE(TRACE_DIGEST, "Computed CRC32C DataDigest %u"
				" bytes, crc 0x%08x\n", iov_ptr->iov_len,
					cmd->data_crc);
			counter -= iov_ptr->iov_len;
			iov_ptr++;	
		}
		iov[iov_count].iov_base	= &cmd->data_crc;
		iov[iov_count++].iov_len = CRC_LEN;
		tx_size += CRC_LEN;

		TRACE(TRACE_DIGEST, "Attached CRC32C DataDigest %d bytes, crc"
			" 0x%08x\n", datain.length+unmap_sg->padding, cmd->data_crc);
	}

	cmd->iov_data_count = iov_count;		
	cmd->tx_size = tx_size;
	
	TRACE(TRACE_ISCSI, "Built DataIN ITT: 0x%08x, StatSN: 0x%08x,"
		" DataSN: 0x%08x, Offset: %u, Length: %u, CID: %hu\n",
		cmd->init_task_tag, ntohl(hdr->stat_sn),
		ntohl(hdr->data_sn), ntohl(hdr->offset),
			ntohl(hdr->length), conn->cid);

	if (dr->dr_complete) {
		*eodr = (cmd->cmd_flags & ICF_TRANSPORT_TASK_SENSE) ? 2 : 1;
		iscsi_free_datain_req(cmd, dr);
	}
	
#ifdef DEBUG_OPCODES
	print_targ_scsi_data_in(hdr);
#endif

	return(0);
}

/*	iscsi_send_logout_response():
 *
 *
 */
static inline int iscsi_send_logout_response (
	iscsi_cmd_t *cmd,
	iscsi_conn_t *conn)
{
	int niov = 0, tx_size;
	iscsi_conn_t *logout_conn = NULL;
	iscsi_conn_recovery_t *cr = NULL;
	iscsi_session_t *sess = SESS(conn);
	struct iovec *iov;
	struct iscsi_targ_logout_rsp *hdr;
	
	/*
	 * The actual shutting down of Sessions and/or Connections
	 * for CLOSESESSION and CLOSECONNECTION Logout Requests
	 * is done in scsi_logout_post_handler().
	 */
	switch (cmd->logout_reason) {
	case CLOSESESSION:
		TRACE(TRACE_ISCSI, "iSCSI session logout successful, setting"
			" logout response to CONNORSESSCLOSEDSUCCESSFULLY.\n");
		cmd->logout_response = CONNORSESSCLOSEDSUCCESSFULLY;
		iscsi_inc_conn_usage_count(conn);
		iscsi_inc_session_usage_count(sess);
		break;
	case CLOSECONNECTION:
		if (cmd->logout_response == CIDNOTFOUND)
			break;

		if (conn->cid == cmd->logout_cid)
			iscsi_inc_conn_usage_count(conn);
		else {
			/*
			 * For CLOSECONNECTION logout requests carrying
			 * a different CID than the connection it arrived
			 * on, the connection responding to cmd->logout_cid
			 * is stopped in iscsi_logout_post_handler_diffcid().
			 */
			do {} while(0);
		}
		TRACE(TRACE_ISCSI, "iSCSI CID: %hu logout on CID: %hu"
			" successful.\n", cmd->logout_cid, conn->cid);
		cmd->logout_response = CONNORSESSCLOSEDSUCCESSFULLY;
		break;
	case REMOVECONNFORRECOVERY:
		if ((cmd->logout_response == CONNRECOVERYNOTSUPPORTED) ||
		    (cmd->logout_response == CLEANUPFAILED))
			break;
		/*
		 * If the connection is still active from our point of view
		 * force connection recovery to occur.
		 */
		if ((logout_conn = iscsi_get_conn_from_cid_rcfr(sess,
				cmd->logout_cid))) {
			iscsi_connection_reinstatement_rcfr(logout_conn);
			iscsi_dec_conn_usage_count(logout_conn);
		}
		
		if (!(cr = iscsi_get_inactive_connection_recovery_entry(
				SESS(conn), cmd->logout_cid))) {
			TRACE_ERROR("Unable to locate CID: %hu for"
			" REMOVECONNFORRECOVERY Logout Request.\n",
				cmd->logout_cid);
			cmd->logout_response = CIDNOTFOUND;
			break;
		}
		
		iscsi_discard_cr_cmds_by_expstatsn(cr, cmd->exp_stat_sn);

		TRACE(TRACE_ERL2, "iSCSI REMOVECONNFORRECOVERY logout"
			" for recovery for CID: %hu on CID: %hu successful.\n",
				cmd->logout_cid, conn->cid);
		cmd->logout_response = CONNORSESSCLOSEDSUCCESSFULLY;
		break;
	default:
		TRACE_ERROR("Unknown cmd->logout_reason: 0x%02x\n",
				cmd->logout_reason);
		return(-1);
	}
		
	tx_size = ISCSI_HDR_LEN;
	hdr			= (struct iscsi_targ_logout_rsp *)cmd->pdu;
	memset(hdr, 0, ISCSI_HDR_LEN);
	hdr->opcode		= ISCSI_TARG_LOGOUT_RSP;
	hdr->flags		|= F_BIT;
	hdr->response		= cmd->logout_response;
	hdr->init_task_tag	= cpu_to_be32(cmd->init_task_tag);
	cmd->stat_sn		= conn->stat_sn++;
	hdr->stat_sn		= cpu_to_be32(cmd->stat_sn);

	iscsi_increment_maxcmdsn(cmd, SESS(conn));
	hdr->exp_cmd_sn		= cpu_to_be32(SESS(conn)->exp_cmd_sn);
	hdr->max_cmd_sn		= cpu_to_be32(SESS(conn)->max_cmd_sn);

	iov = &cmd->iov_misc[0];
	iov[niov].iov_base	= cmd->pdu;
	iov[niov++].iov_len	= ISCSI_HDR_LEN;
	
	if (CONN_OPS(conn)->HeaderDigest) {
		do_crc((unsigned char *)hdr, ISCSI_HDR_LEN,
			0x01, &hdr->header_digest);
		iov[0].iov_len += CRC_LEN;
		tx_size += CRC_LEN;
		TRACE(TRACE_DIGEST, "Attaching CRC32C HeaderDigest to"
			" Logout Response 0x%08x\n", hdr->header_digest);
	}

	cmd->iov_misc_count = niov;
	cmd->tx_size = tx_size;
	
#ifdef DEBUG_OPCODES
	print_targ_logout_rsp(rsp);
#endif

	TRACE(TRACE_ISCSI, "Sending Logout Response ITT: 0x%08x StatSN:"
		" 0x%08x Response: 0x%02x CID: %hu on CID: %hu\n",
		ntohl(hdr->init_task_tag), ntohl(hdr->stat_sn),	
			hdr->response, cmd->logout_cid, conn->cid);
	
	return(0);
}

/*	iscsi_send_nopin():
 *
 *	Unsolicited NOPIN, either requesting a response or not.
 */
static inline int iscsi_send_unsolicited_nopin (
	iscsi_cmd_t *cmd,
	iscsi_conn_t *conn,
	int want_response)
{
	int tx_size = ISCSI_HDR_LEN;
	struct iscsi_targ_nop_in *hdr;

	TRACE_ENTER

	hdr			= (struct iscsi_targ_nop_in *) cmd->pdu;
	memset(hdr, 0, ISCSI_HDR_LEN);
	hdr->opcode		= ISCSI_TARG_NOP_IN;
	hdr->flags		|= F_BIT;
	hdr->length		= 0;
	hdr->lun		= iscsi_pack_lun(0);
	hdr->init_task_tag	= cpu_to_be32(cmd->init_task_tag);
	hdr->targ_xfer_tag	= cpu_to_be32(cmd->targ_xfer_tag);
	cmd->stat_sn		= conn->stat_sn;
	hdr->stat_sn		= cpu_to_be32(cmd->stat_sn);
	hdr->exp_cmd_sn		= cpu_to_be32(SESS(conn)->exp_cmd_sn);
	hdr->max_cmd_sn		= cpu_to_be32(SESS(conn)->max_cmd_sn);
		
	if (CONN_OPS(conn)->HeaderDigest) {
		do_crc((unsigned char *)hdr, ISCSI_HDR_LEN,
			0x01, &hdr->header_digest);
		tx_size += CRC_LEN;		
		TRACE(TRACE_DIGEST, "Attaching CRC32C HeaderDigest to"
			" NopIN 0x%08x\n", hdr->header_digest);
	}

	cmd->iov_misc[0].iov_base	= cmd->pdu;
	cmd->iov_misc[0].iov_len	= tx_size;
	cmd->iov_misc_count 	= 1;
	cmd->tx_size		= tx_size;
	
	TRACE(TRACE_ISCSI, "Sending Unsolicited NOPIN TTT: 0x%08x StatSN:"
	" 0x%08x CID: %hu\n", hdr->targ_xfer_tag, cmd->stat_sn, conn->cid);

#ifdef DEBUG_OPCODES
	print_targ_nop_in(hdr);
#endif
	
	TRACE_LEAVE
	return(0);
}

/*	iscsi_send_nopin_response():
 *
 *
 */
static inline int iscsi_send_nopin_response (
	iscsi_cmd_t *cmd,
	iscsi_conn_t *conn)
{
	int niov = 0, tx_size;
	__u8 reset_crc = 1;
	__u32 padding = 0;
	struct iovec *iov;
	struct iscsi_targ_nop_in *hdr;
	
	TRACE_ENTER

	tx_size = ISCSI_HDR_LEN;
	hdr			= (struct iscsi_targ_nop_in *) cmd->pdu;
	memset(hdr, 0, ISCSI_HDR_LEN);
	hdr->opcode		= ISCSI_TARG_NOP_IN;
	hdr->flags		|= F_BIT;
	hdr->length		= cpu_to_be32(cmd->buf_ptr_size);
	hdr->lun		= cpu_to_be64(0xFFFFFFFFFFFFFFFFULL);
	hdr->init_task_tag	= cpu_to_be32(cmd->init_task_tag);
	hdr->targ_xfer_tag	= cpu_to_be32(cmd->targ_xfer_tag);
	cmd->stat_sn		= conn->stat_sn++;
	hdr->stat_sn		= cpu_to_be32(cmd->stat_sn);

	iscsi_increment_maxcmdsn(cmd, SESS(conn));
	hdr->exp_cmd_sn		= cpu_to_be32(SESS(conn)->exp_cmd_sn);
	hdr->max_cmd_sn		= cpu_to_be32(SESS(conn)->max_cmd_sn);

	iov = &cmd->iov_misc[0];
	iov[niov].iov_base	= cmd->pdu;
	iov[niov++].iov_len	= ISCSI_HDR_LEN;

	if (CONN_OPS(conn)->HeaderDigest) {
		do_crc((__u8 *)hdr, ISCSI_HDR_LEN,
				0x01, &hdr->header_digest);
		iov[0].iov_len += CRC_LEN;
		tx_size += CRC_LEN;
		TRACE(TRACE_DIGEST, "Attaching CRC32C HeaderDigest"
			" to NopIn 0x%08x\n", hdr->header_digest);
	}

	/*
	 * NOPOUT Ping Data is attached to iscsi_cmd_t->buf_ptr.
	 * NOPOUT DataSegmentLength is at iscsi_cmd_t->buf_ptr_size.
	 */
	if (cmd->buf_ptr_size) {
		iov[niov].iov_base	= cmd->buf_ptr;
		iov[niov++].iov_len	= cmd->buf_ptr_size;
		tx_size += cmd->buf_ptr_size;
			
		TRACE(TRACE_ISCSI, "Echoing back %u bytes of ping"
			" data.\n", cmd->buf_ptr_size);

		if ((padding = ((-cmd->buf_ptr_size) & 3)) != 0) {
			iov[niov].iov_base = &cmd->pad_bytes;
			iov[niov++].iov_len = padding;
			tx_size += padding;
			TRACE(TRACE_ISCSI, "Attaching %u additional"
				" padding bytes.\n", padding);
		}
		if (CONN_OPS(conn)->DataDigest) {
			do_crc((__u8 *)cmd->buf_ptr, cmd->buf_ptr_size,
				reset_crc, &cmd->data_crc);
			reset_crc = 0;
			if (padding)
				do_crc((__u8 *)&cmd->pad_bytes, padding,
					reset_crc, &cmd->data_crc);
				
			iov[niov].iov_base = &cmd->data_crc;
			iov[niov++].iov_len = CRC_LEN;
			tx_size += CRC_LEN;
			TRACE(TRACE_DIGEST, "Attached DataDigest for %u"
				" bytes of ping data, CRC 0x%08x\n",
				cmd->buf_ptr_size, cmd->data_crc);
		}
	}

	cmd->iov_misc_count = niov;
	cmd->tx_size = tx_size;
	
	TRACE(TRACE_ISCSI, "Sending NOPIN Response ITT: 0x%08x, TTT:"
		" 0x%08x, StatSN: 0x%08x, Length %u\n",
		ntohl(hdr->init_task_tag), ntohl(hdr->targ_xfer_tag),
		ntohl(hdr->stat_sn), ntohl(hdr->length));
	
#ifdef DEBUG_OPCODES
	print_targ_nop_in(hdr);
#endif

	TRACE_LEAVE
	return(0);
}

/*	iscsi_send_r2t():
 *
 *
 */
extern int iscsi_send_r2t (
	iscsi_cmd_t *cmd,
	iscsi_conn_t *conn)
{
	int tx_size = 0;
	__u32 trace_type;
	iscsi_r2t_t *r2t;
	struct iscsi_targ_r2t *hdr;

	if (!(r2t = iscsi_get_r2t_from_list(cmd)))
		return(-1);
	
	hdr			= (struct iscsi_targ_r2t *) cmd->pdu;
	memset(hdr, 0, ISCSI_HDR_LEN);
	hdr->opcode		= ISCSI_TARG_R2T;
	hdr->flags		|= F_BIT;
	hdr->lun		= iscsi_pack_lun(cmd->orig_fe_lun);
	hdr->init_task_tag	= cpu_to_be32(cmd->init_task_tag);
	spin_lock_bh(&SESS(conn)->ttt_lock);
	r2t->targ_xfer_tag	= SESS(conn)->targ_xfer_tag++;
	if (r2t->targ_xfer_tag == 0xFFFFFFFF)
		r2t->targ_xfer_tag = SESS(conn)->targ_xfer_tag++;
	spin_unlock_bh(&SESS(conn)->ttt_lock);
	hdr->targ_xfer_tag	= cpu_to_be32(r2t->targ_xfer_tag);
	hdr->stat_sn		= cpu_to_be32(conn->stat_sn);
	hdr->exp_cmd_sn		= cpu_to_be32(SESS(conn)->exp_cmd_sn);
	hdr->max_cmd_sn		= cpu_to_be32(SESS(conn)->max_cmd_sn);
	hdr->r2t_sn		= cpu_to_be32(r2t->r2t_sn);
	hdr->offset		= cpu_to_be32(r2t->offset);
	hdr->xfer_len		= cpu_to_be32(r2t->xfer_len);
		
	cmd->iov_misc[0].iov_base	= cmd->pdu;
	cmd->iov_misc[0].iov_len	= ISCSI_HDR_LEN;
	tx_size += ISCSI_HDR_LEN;

	if (CONN_OPS(conn)->HeaderDigest) {
		do_crc((__u8 *)hdr, ISCSI_HDR_LEN, 0x01, &hdr->header_digest);
		cmd->iov_misc[0].iov_len += CRC_LEN;
		tx_size += CRC_LEN;
		TRACE(TRACE_DIGEST, "Attaching CRC32 HeaderDigest for R2T"
			" PDU 0x%08x\n", hdr->header_digest);
        }

#ifdef DEBUG_OPCODES
	print_targ_r2t(hdr);
#endif

	trace_type = (!r2t->recovery_r2t) ? TRACE_ISCSI : TRACE_ERL1;
	TRACE(trace_type, "Built %sR2T, ITT: 0x%08x, TTT: 0x%08x, StatSN: 0x%08x,"
		" R2TSN: 0x%08x, Offset: %u, DDTL: %u, CID: %hu\n",
		(!r2t->recovery_r2t) ? "" : "Recovery ", cmd->init_task_tag,
		r2t->targ_xfer_tag, ntohl(hdr->stat_sn), r2t->r2t_sn,
			r2t->offset, r2t->xfer_len, conn->cid);

	cmd->iov_misc_count = 1;
	cmd->tx_size = tx_size;

	spin_lock_bh(&cmd->r2t_lock);
	r2t->sent_r2t = 1;
	spin_unlock_bh(&cmd->r2t_lock);
		
	return(0);
}

/*	iscsi_build_r2ts_for_cmd():
 *
 *	type 0: Normal Operation.
 *	type 1: Called from Storage Transport.
 *	type 2: Called from iscsi_task_reassign_complete_write() for
 *	        connection recovery.
 */
extern int iscsi_build_r2ts_for_cmd (
	iscsi_cmd_t *cmd,
	iscsi_conn_t *conn,
	int type)
{
	int first_r2t = 1;
	__u32 offset = 0, xfer_len = 0;
	
	spin_lock_bh(&cmd->r2t_lock);
	if (cmd->cmd_flags & ICF_SENT_LAST_R2T) {
		spin_unlock_bh(&cmd->r2t_lock);
		return(0);
	}
	
	if (SESS_OPS_C(conn)->DataSequenceInOrder && (type != 2))
		if (cmd->r2t_offset < cmd->write_data_done)
			cmd->r2t_offset = cmd->write_data_done;

	while (cmd->outstanding_r2ts < SESS_OPS_C(conn)->MaxOutstandingR2T) {
		if (SESS_OPS_C(conn)->DataSequenceInOrder) {
			offset = cmd->r2t_offset;

			if (first_r2t && (type == 2)) {
				xfer_len = ((offset + (SESS_OPS_C(conn)->MaxBurstLength -
					     cmd->next_burst_len) > cmd->data_length) ?
					    (cmd->data_length - offset) : 
					    (SESS_OPS_C(conn)->MaxBurstLength -
					     cmd->next_burst_len));
			} else {
				xfer_len = ((offset +
					     SESS_OPS_C(conn)->MaxBurstLength) >
					     cmd->data_length) ?
					     (cmd->data_length - offset) :
					     SESS_OPS_C(conn)->MaxBurstLength;
			}
			cmd->r2t_offset += xfer_len;

			if (cmd->r2t_offset == cmd->data_length)
				cmd->cmd_flags |= ICF_SENT_LAST_R2T;
		} else {
			iscsi_seq_t *seq;

			if (!(seq = iscsi_get_seq_holder_for_r2t(cmd))) {
				spin_unlock_bh(&cmd->r2t_lock);
				return(-1);
			}

			offset = seq->offset;
			xfer_len = seq->xfer_len;

			if (cmd->seq_send_order == cmd->seq_count)
				cmd->cmd_flags |= ICF_SENT_LAST_R2T;
		}
		cmd->outstanding_r2ts++;
		first_r2t = 0;

		if (iscsi_add_r2t_to_list(cmd, offset, xfer_len, 0, 0) < 0) {
			spin_unlock_bh(&cmd->r2t_lock);
			return(-1);
		}

		if (cmd->cmd_flags & ICF_SENT_LAST_R2T)
			break;
	}
	spin_unlock_bh(&cmd->r2t_lock);	
		
	return(0);
}

/*	iscsi_send_status():
 *
 *
 */
static inline int iscsi_send_status (
	iscsi_cmd_t *cmd,
	iscsi_conn_t *conn)
{
	__u8 iov_count = 0, recovery;
	__u32 padding = 0, trace_type, tx_size = 0;
	struct iscsi_targ_scsi_rsp *hdr;
	struct iovec *iov;

	recovery = (cmd->i_state != ISTATE_SEND_STATUS);
	if (!recovery)
		cmd->stat_sn = conn->stat_sn++;

#ifdef SNMP_SUPPORT
	spin_lock_bh(&SESS(conn)->session_stats_lock);
	SESS(conn)->rsp_pdus++;
	spin_unlock_bh(&SESS(conn)->session_stats_lock);
#endif /* SNMP_SUPPORT */
	
	hdr			= (struct iscsi_targ_scsi_rsp *) cmd->pdu;
	memset(hdr, 0, ISCSI_HDR_LEN);
	hdr->opcode		= ISCSI_TARG_SCSI_RSP;
	hdr->flags		|= F_BIT;
	if (cmd->cmd_flags & ICF_OVERFLOW_BIT) {
		hdr->flags |= O_BIT;
		hdr->res_count = cpu_to_be32(cmd->residual_count);
	} else if (cmd->cmd_flags & ICF_UNDERFLOW_BIT) {
		hdr->flags |= U_BIT;
		hdr->res_count = cpu_to_be32(cmd->residual_count);
	}
	hdr->response		= cmd->iscsi_response;
	hdr->status		= cmd->scsi_status;
	hdr->length		= 0;
	hdr->init_task_tag	= cpu_to_be32(cmd->init_task_tag);
	hdr->stat_sn		= cpu_to_be32(cmd->stat_sn);

	iscsi_increment_maxcmdsn(cmd, SESS(conn));
	hdr->exp_cmd_sn		= cpu_to_be32(SESS(conn)->exp_cmd_sn);
	hdr->max_cmd_sn		= cpu_to_be32(SESS(conn)->max_cmd_sn);

	iov = &cmd->iov_misc[0];
	
	iov[iov_count].iov_base	= cmd->pdu;
	iov[iov_count++].iov_len = ISCSI_HDR_LEN;
	tx_size += ISCSI_HDR_LEN;

	/* 
	 * Attach SENSE DATA payload to iSCSI Response PDU
	 */
	if (cmd->buf_ptr && ((cmd->cmd_flags & ICF_TRANSPORT_TASK_SENSE) ||
			     (cmd->cmd_flags & ICF_EMULATED_TASK_SENSE))) {
		padding			= -(cmd->scsi_sense_length) & 3;
		hdr->length		= cpu_to_be32(cmd->scsi_sense_length);
		iov[iov_count].iov_base	= cmd->buf_ptr;
		iov[iov_count++].iov_len = (cmd->scsi_sense_length + padding);
		tx_size += cmd->scsi_sense_length;

		if (padding) {
			memset(cmd->buf_ptr + cmd->scsi_sense_length, 0, padding);
			tx_size += padding;
			TRACE(TRACE_ISCSI, "Adding %u bytes of padding to"
				" SENSE.\n", padding);
		}

		if (CONN_OPS(conn)->DataDigest) {
			do_crc((__u8 *)cmd->buf_ptr,
				(cmd->scsi_sense_length + padding), 0x01,
					&cmd->data_crc);
			iov[iov_count].iov_base    = &cmd->data_crc;
			iov[iov_count++].iov_len     = CRC_LEN;
			tx_size += CRC_LEN;

			TRACE(TRACE_DIGEST, "Attaching CRC32 DataDigest for"
				" SENSE, %u bytes CRC 0x%08x\n",
				(cmd->scsi_sense_length + padding), cmd->data_crc);
		}

		TRACE(TRACE_ISCSI, "Attaching SENSE DATA: %u bytes to iSCSI"
				" Response PDU\n", cmd->scsi_sense_length);
	}

	if (CONN_OPS(conn)->HeaderDigest) {
		do_crc((__u8 *)hdr, ISCSI_HDR_LEN, 0x01, &hdr->header_digest);
		iov[0].iov_len += CRC_LEN;
		tx_size += CRC_LEN;
		TRACE(TRACE_DIGEST, "Attaching CRC32 HeaderDigest for Response"
				" PDU 0x%08x\n", hdr->header_digest);
	}

	cmd->iov_misc_count = iov_count;
	cmd->tx_size = tx_size;

#ifdef DEBUG_OPCODES
	print_targ_scsi_rsp(hdr);
#endif
	
	trace_type = (!recovery) ? TRACE_ISCSI : TRACE_ERL1;
	TRACE(trace_type, "Built %sSCSI Response, ITT: 0x%08x, StatSN: 0x%08x,"
		" Response: 0x%02x, SAM Status: 0x%02x, CID: %hu\n", (!recovery) ?
		"" : "Recovery ", cmd->init_task_tag, cmd->stat_sn, 0x00,
			cmd->scsi_status, conn->cid);

	return(0);
}

/*	iscsi_send_task_mgt_rsp():
 *
 *
 */
static int iscsi_send_task_mgt_rsp (
	iscsi_cmd_t *cmd,
	iscsi_conn_t *conn)
{
	__u32 tx_size = 0;
	iscsi_tmr_req_t *tmr_req = cmd->tmr_req;
	struct iscsi_targ_task_mgt_rsp *hdr;
	
	hdr			= (struct iscsi_targ_task_mgt_rsp *) cmd->pdu;
	memset(hdr, 0, ISCSI_HDR_LEN);
	hdr->opcode		= ISCSI_TARG_TASK_MGMT_RSP;
	hdr->response		= tmr_req->response;
	hdr->init_task_tag	= cpu_to_be32(cmd->init_task_tag);
	cmd->stat_sn		= conn->stat_sn++;
	hdr->stat_sn		= cpu_to_be32(cmd->stat_sn);

	iscsi_increment_maxcmdsn(cmd, SESS(conn));
	hdr->exp_cmd_sn		= cpu_to_be32(SESS(conn)->exp_cmd_sn);
	hdr->max_cmd_sn		= cpu_to_be32(SESS(conn)->max_cmd_sn);
	
	cmd->iov_misc[0].iov_base	= cmd->pdu;
	cmd->iov_misc[0].iov_len	= ISCSI_HDR_LEN;
	tx_size += ISCSI_HDR_LEN;

	if (CONN_OPS(conn)->HeaderDigest) {
		do_crc((__u8 *)hdr, ISCSI_HDR_LEN, 0x01, &hdr->header_digest);
		cmd->iov_misc[0].iov_len += CRC_LEN;
		tx_size += CRC_LEN;
		TRACE(TRACE_DIGEST, "Attaching CRC32 HeaderDigest for Task"
			" Mgmt Response PDU 0x%08x\n", hdr->header_digest);			
	}

	cmd->iov_misc_count = 1;
	cmd->tx_size = tx_size;
		
#ifdef DEBUG_OPCODES
	print_targ_task_mgt_rsp(hdr);
#endif

	TRACE(TRACE_ERL2, "Built Task Management Response ITT: 0x%08x,"
		" StatSN: 0x%08x, Response: 0x%02x, CID: %hu\n",
		cmd->init_task_tag, cmd->stat_sn, hdr->response, conn->cid);

	return(0);
}

/*	iscsi_send_text_rsp():
 *
 *
 *	FIXME: Add support for F_BIT and C_BIT when the length is longer than
 *	MaxRecvDataSegmentLength.
 */
static int iscsi_send_text_rsp (
	iscsi_cmd_t *cmd,
	iscsi_conn_t *conn)
{
	__u8 iov_count = 0;
	__u32 padding = 0, text_length = 0, tx_size = 0;
	struct iscsi_targ_text_rsp *hdr;
	struct iovec *iov;
	
	text_length = iscsi_build_sendtargets_response(cmd);

	if ((padding = ((-text_length) & 3)) != 0) {
		memset((void *) (cmd->buf_ptr + text_length), 0, padding);
		TRACE(TRACE_ISCSI, "Attaching %u additional bytes for"
			" padding.\n", padding);
	}

	hdr			= (struct iscsi_targ_text_rsp *) cmd->pdu;
	memset(hdr, 0, ISCSI_HDR_LEN);
	hdr->opcode		= ISCSI_TARG_TEXT_RSP;
	hdr->flags		|= F_BIT;	
	hdr->length		= cpu_to_be32(text_length);
	hdr->init_task_tag	= cpu_to_be32(cmd->init_task_tag);
	hdr->targ_xfer_tag	= cpu_to_be32(cmd->targ_xfer_tag);
	cmd->stat_sn		= conn->stat_sn++;
	hdr->stat_sn		= cpu_to_be32(cmd->stat_sn);

	iscsi_increment_maxcmdsn(cmd, SESS(conn));
	hdr->exp_cmd_sn		= cpu_to_be32(SESS(conn)->exp_cmd_sn);
	hdr->max_cmd_sn		= cpu_to_be32(SESS(conn)->max_cmd_sn);

	iov = &cmd->iov_misc[0];
	
	iov[iov_count].iov_base = cmd->pdu;
	iov[iov_count++].iov_len = ISCSI_HDR_LEN;
	iov[iov_count].iov_base	= cmd->buf_ptr;
	iov[iov_count++].iov_len = text_length + padding;

	tx_size += (ISCSI_HDR_LEN + text_length + padding);

	if (CONN_OPS(conn)->HeaderDigest) {
		do_crc((__u8 *)hdr, ISCSI_HDR_LEN, 0x01,
			&hdr->header_digest);
		iov[0].iov_len += CRC_LEN;
		tx_size += CRC_LEN;
		TRACE(TRACE_DIGEST, "Attaching CRC32 HeaderDigest for"
			" Text Response PDU 0x%08x\n", hdr->header_digest);
        }

	if (CONN_OPS(conn)->DataDigest) {
		do_crc((__u8 *) cmd->buf_ptr, text_length + padding,
				0x01, &cmd->data_crc);
		iov[iov_count].iov_base	= &cmd->data_crc;
		iov[iov_count++].iov_len = CRC_LEN;
		tx_size	+= CRC_LEN;

		TRACE(TRACE_DIGEST, "Attaching DataDigest for %u bytes of text"
			" data, CRC 0x%08x\n", (text_length + padding), cmd->data_crc);
	}
		
	cmd->iov_misc_count = iov_count;
	cmd->tx_size = tx_size;

	TRACE(TRACE_ISCSI, "Built Text Response: ITT: 0x%08x, StatSN: 0x%08x,"
		" Length: %u, CID: %hu\n", cmd->init_task_tag, cmd->stat_sn,
			text_length, conn->cid);

#ifdef DEBUG_OPCODES
	print_targ_text_rsp(hdr);
#endif

	return(0);
}

/*	iscsi_send_reject():
 *
 *
 */
static int iscsi_send_reject (
	iscsi_cmd_t *cmd,
	iscsi_conn_t *conn)
{
	__u32 iov_count = 0, tx_size = 0;
	struct iscsi_targ_rjt *hdr;
	struct iovec *iov;

	hdr			= (struct iscsi_targ_rjt *) cmd->pdu;
	hdr->opcode		= ISCSI_TARG_RJT;
	hdr->reserved1		|= F_BIT;
	hdr->length		= cpu_to_be32(ISCSI_HDR_LEN);
	hdr->reserved3		= 0xffffffff;
        cmd->stat_sn		= conn->stat_sn++;
        hdr->stat_sn		= cpu_to_be32(cmd->stat_sn);
	hdr->exp_cmd_sn	= cpu_to_be32(SESS(conn)->exp_cmd_sn);
	hdr->max_cmd_sn	= cpu_to_be32(SESS(conn)->max_cmd_sn);

	iov = &cmd->iov_misc[0];
	
	iov[iov_count].iov_base = cmd->pdu;
	iov[iov_count++].iov_len = ISCSI_HDR_LEN;
	iov[iov_count].iov_base = cmd->buf_ptr;
	iov[iov_count++].iov_len = ISCSI_HDR_LEN;

	tx_size = (ISCSI_HDR_LEN + ISCSI_HDR_LEN);

	if (CONN_OPS(conn)->HeaderDigest) {
		do_crc((__u8 *)hdr, ISCSI_HDR_LEN, 0x01,
				&hdr->header_digest);
		iov[0].iov_len += CRC_LEN;
		tx_size += CRC_LEN;
		TRACE(TRACE_DIGEST, "Attaching CRC32 HeaderDigest for"
			" REJECT PDU 0x%08x\n", hdr->header_digest);
	}

	if (CONN_OPS(conn)->DataDigest) {
		do_crc((__u8 *)cmd->buf_ptr, ISCSI_HDR_LEN, 0x01, &cmd->data_crc);
		iov[iov_count].iov_base = &cmd->data_crc;
		iov[iov_count++].iov_len  = CRC_LEN;
		tx_size += CRC_LEN;
		TRACE(TRACE_DIGEST, "Attaching CRC32 DataDigest for REJECT"
				" PDU 0x%08x\n", cmd->data_crc);
	}

	cmd->iov_misc_count = iov_count;
	cmd->tx_size = tx_size;

	TRACE(TRACE_ISCSI, "Built Reject PDU StatSN: 0x%08x, Reason: 0x%02x,"
		" CID: %hu\n", ntohl(hdr->stat_sn), hdr->reason, conn->cid);
#if 0
	print_reject_reason(hdr->reason);
#endif
#ifdef DEBUG_OPCODES
	print_targ_rjt(hdr);
#endif

	return(0);
}

/*	iscsi_tx_thread_TCP_timeout():
 *
 *
 */
static void iscsi_tx_thread_TCP_timeout (unsigned long data)
{
	up((struct semaphore *)data);
	return;
}

/*	iscsi_tx_thread_wait_for_TCP():
 *
 *
 */
static void iscsi_tx_thread_wait_for_TCP (iscsi_conn_t *conn)
{
	struct timer_list tx_TCP_timer;

//	TRACE_ERROR("0x%08x\n", conn->sock->sk->sk_shutdown);

	if ((conn->sock->sk->sk_shutdown & SEND_SHUTDOWN) ||
	    (conn->sock->sk->sk_shutdown & RCV_SHUTDOWN)) {
		init_timer(&tx_TCP_timer);
		SETUP_TIMER(tx_TCP_timer, ISCSI_TX_THREAD_TCP_TIMEOUT,
			&conn->tx_half_close_sem, iscsi_tx_thread_TCP_timeout);
		add_timer(&tx_TCP_timer);

		down_interruptible(&conn->tx_half_close_sem);

		del_timer_sync(&tx_TCP_timer);
	}

	return;
}

/*	iscsi_target_tx_thread():
 * 
 *
 */
extern int iscsi_target_tx_thread (void *arg)
{
	u8 state;
	int eodr = 0, map_sg = 0, ret = 0, sent_status = 0, use_misc = 0;
	iscsi_cmd_t *cmd = NULL;
	iscsi_conn_t *conn;
	iscsi_queue_req_t *qr = NULL;
	iscsi_thread_set_t *ts = (iscsi_thread_set_t *) arg;
	iscsi_unmap_sg_t unmap_sg;

	TRACE_ENTER

        {
	    static int x = 0;  /* unique number added to thread name */
            char name[20];

            memset (name,0,20);

	    sprintf (name, "%s/%d", ISCSI_TX_THREAD_NAME, x++);
	    iscsi_daemon(ts->tx_thread, name, SHUTDOWN_SIGS);
        }
	
restart:
	if (!(conn = iscsi_tx_thread_pre_handler(ts, TARGET)))
		goto out;

	eodr = map_sg = ret = sent_status = use_misc = 0;
	
	while (1) {
		down_interruptible(&conn->tx_sem);

		if ((ts->status == ISCSI_THREAD_SET_RESET) || signal_pending(current))
			goto transport_err;

#ifdef DEBUG_ERL                        
		if (iscsi_target_debugerl_tx_thread(conn) < 0) 
			goto transport_err; 
#endif /* DEBUG_ERL */         	

get_immediate:
		if ((qr = iscsi_get_cmd_from_immediate_queue(conn))) {
			atomic_set(&conn->check_immediate_queue, 0);
			cmd = qr->cmd;
			state = qr->state;
			kfree(qr);

			spin_lock_bh(&cmd->istate_lock);
			switch (state) {
			case ISTATE_SEND_R2T:
				spin_unlock_bh(&cmd->istate_lock);
				ret = iscsi_send_r2t(cmd, conn);
				break;
			case ISTATE_REMOVE:
				spin_unlock_bh(&cmd->istate_lock);

				if (cmd->data_direction == ISCSI_WRITE)
					iscsi_stop_dataout_timer(cmd);

				spin_lock_bh(&conn->cmd_lock);
				iscsi_remove_cmd_from_conn_list(cmd, conn);
				spin_unlock_bh(&conn->cmd_lock);

				transport_generic_free_cmd(cmd, 1, 1, 0);
				goto get_immediate;
			case ISTATE_SEND_NOPIN_WANT_RESPONSE:
				spin_unlock_bh(&cmd->istate_lock);
				iscsi_mod_nopin_response_timer(conn);
				ret = iscsi_send_unsolicited_nopin(cmd, conn, 1);
				break;
			case ISTATE_SEND_NOPIN_NO_RESPONSE:
				spin_unlock_bh(&cmd->istate_lock);
				ret = iscsi_send_unsolicited_nopin(cmd, conn, 0);
				break;
			default:
				TRACE_ERROR("Unknown Opcode: 0x%02x ITT: 0x%08x,"
				" i_state: %d on CID: %hu\n", cmd->iscsi_opcode,
					cmd->init_task_tag, state, conn->cid);
				spin_unlock_bh(&cmd->istate_lock);
				goto transport_err;
			}
			if (ret < 0) {
				conn->tx_immediate_queue = 0;
				goto transport_err;
			}

			if (iscsi_send_tx_data(cmd, conn, 1) < 0) {
				conn->tx_immediate_queue = 0;
				iscsi_tx_thread_wait_for_TCP(conn);
				goto transport_err;
			}

			spin_lock_bh(&cmd->istate_lock);
			switch (state) {
			case ISTATE_SEND_R2T:
				spin_unlock_bh(&cmd->istate_lock);
				spin_lock_bh(&cmd->dataout_timeout_lock);
				iscsi_start_dataout_timer(cmd, conn);
				spin_unlock_bh(&cmd->dataout_timeout_lock);
				break;
			case ISTATE_SEND_NOPIN_WANT_RESPONSE:
				cmd->i_state = ISTATE_SENT_NOPIN_WANT_RESPONSE;
				spin_unlock_bh(&cmd->istate_lock);
				break;
			case ISTATE_SEND_NOPIN_NO_RESPONSE:
				cmd->i_state = ISTATE_SENT_STATUS;
				spin_unlock_bh(&cmd->istate_lock);
				break;
			default:
				TRACE_ERROR("Unknown Opcode: 0x%02x ITT: 0x%08x,"
				" i_state: %d on CID: %hu\n", cmd->iscsi_opcode,
					cmd->init_task_tag, state, conn->cid);
				spin_unlock_bh(&cmd->istate_lock);
				goto transport_err;
			}
			goto get_immediate;
		} else
			conn->tx_immediate_queue = 0;

get_response:
		if ((qr = iscsi_get_cmd_from_response_queue(conn))) {
			cmd = qr->cmd;
			state = qr->state;
			kfree(qr);

			spin_lock_bh(&cmd->istate_lock);
check_rsp_state:
			switch (state) {
			case ISTATE_SEND_DATAIN:
				spin_unlock_bh(&cmd->istate_lock);
				memset((void *)&unmap_sg, 0, sizeof(iscsi_unmap_sg_t));
				unmap_sg.cmd = cmd;
				map_sg = 1;
				ret = iscsi_send_data_in(cmd, conn, &unmap_sg, &eodr);
				break;
			case ISTATE_SEND_STATUS:
			case ISTATE_SEND_STATUS_RECOVERY:
				spin_unlock_bh(&cmd->istate_lock);
				use_misc = 1;
				ret = iscsi_send_status(cmd, conn);
				break;
			case ISTATE_SEND_LOGOUTRSP:
				spin_unlock_bh(&cmd->istate_lock);
				use_misc = 1;
				ret = iscsi_send_logout_response(cmd, conn);
				break;
			case ISTATE_SEND_ASYNCMSG:
				spin_unlock_bh(&cmd->istate_lock);
				use_misc = 1;
				ret = iscsi_send_conn_drop_async_message(cmd, conn);
				break;
			case ISTATE_SEND_NOPIN:
				spin_unlock_bh(&cmd->istate_lock);
				use_misc = 1;
				ret = iscsi_send_nopin_response(cmd, conn);
				break;
			case ISTATE_SEND_REJECT:
				spin_unlock_bh(&cmd->istate_lock);
				use_misc = 1;
				ret = iscsi_send_reject(cmd, conn);
				break;
			case ISTATE_SEND_TASKMGTRSP:
				spin_unlock_bh(&cmd->istate_lock);
				use_misc = 1;
				ret = iscsi_send_task_mgt_rsp(cmd, conn);
				if (ret != 0)
					break;
				ret = iscsi_tmr_post_handler(cmd, conn);
				if (ret != 0)
					iscsi_fall_back_to_erl0(conn);
				break;
			case ISTATE_SEND_TEXTRSP:
				spin_unlock_bh(&cmd->istate_lock);
				use_misc = 1;
				ret = iscsi_send_text_rsp(cmd, conn);
				break;
			default:
				TRACE_ERROR("Unknown Opcode: 0x%02x ITT: 0x%08x,"
				" i_state: %d on CID: %hu\n", cmd->iscsi_opcode,
					cmd->init_task_tag, state, conn->cid);
				spin_unlock_bh(&cmd->istate_lock);
				goto transport_err;
			}
			if (ret < 0) {
				conn->tx_response_queue = 0;
				goto transport_err;
			}

			if (map_sg && !CONN_OPS(conn)->IFMarker && T_TASK(cmd)->t_task_se_num) {
				cmd->transport_map_SG_segments(&unmap_sg);
				if (iscsi_fe_sendpage_sg(&unmap_sg, conn) < 0) {
					conn->tx_response_queue = 0;
					iscsi_tx_thread_wait_for_TCP(conn);
					cmd->transport_unmap_SG_segments(&unmap_sg);
					goto transport_err;
				}
				cmd->transport_unmap_SG_segments(&unmap_sg);
				map_sg = 0;
			} else {
				if (map_sg) 
					cmd->transport_map_SG_segments(&unmap_sg);
				if (iscsi_send_tx_data(cmd, conn, use_misc) < 0) {
					conn->tx_response_queue = 0;
					iscsi_tx_thread_wait_for_TCP(conn);
					if (map_sg)
						cmd->transport_unmap_SG_segments(&unmap_sg);
					goto transport_err;
				}
				if (map_sg) {
					cmd->transport_unmap_SG_segments(&unmap_sg);
					map_sg = 0;
				}
			}

			spin_lock_bh(&cmd->istate_lock);
			switch (state) {
			case ISTATE_SEND_DATAIN:
				if (!eodr)
					goto check_rsp_state;

				if (eodr == 1) {
					cmd->i_state = ISTATE_SENT_LAST_DATAIN;
					sent_status = 1;
					eodr = use_misc = 0;
				} else if (eodr == 2) {
					cmd->i_state = state = ISTATE_SEND_STATUS;
					sent_status = 0;
					eodr = use_misc = 0;
					goto check_rsp_state;
				}
				break;
			case ISTATE_SEND_STATUS:
				use_misc = 0;
				sent_status = 1;
				break;
			case ISTATE_SEND_ASYNCMSG:
			case ISTATE_SEND_NOPIN:
			case ISTATE_SEND_STATUS_RECOVERY:
			case ISTATE_SEND_TEXTRSP:
				use_misc = 0;
				sent_status = 1;
				break;
			case ISTATE_SEND_REJECT:
				use_misc = 0;
				if (cmd->cmd_flags & ICF_REJECT_FAIL_CONN) {
					cmd->cmd_flags &= ~ICF_REJECT_FAIL_CONN;
					spin_unlock_bh(&cmd->istate_lock);
					up(&cmd->reject_sem);
					goto transport_err;
				}
				up(&cmd->reject_sem);
				break;
			case ISTATE_SEND_TASKMGTRSP:
				use_misc = 0;
				sent_status = 1;
				break;
			case ISTATE_SEND_LOGOUTRSP:
				spin_unlock_bh(&cmd->istate_lock);
				if (!(iscsi_logout_post_handler(cmd, conn)))
					goto restart;
				spin_lock_bh(&cmd->istate_lock);
				use_misc = 0;
				sent_status = 1;
				break;
			default:
				TRACE_ERROR("Unknown Opcode: 0x%02x ITT: 0x%08x,"
				" i_state: %d on CID: %hu\n", cmd->iscsi_opcode,
					cmd->init_task_tag, cmd->i_state, conn->cid);
				spin_unlock_bh(&cmd->istate_lock);
				goto transport_err;
			}

			if (sent_status) {
				cmd->i_state = ISTATE_SENT_STATUS;
				sent_status = 0;
			}
			spin_unlock_bh(&cmd->istate_lock);

			if (atomic_read(&conn->check_immediate_queue))
				goto get_immediate;
		
			goto get_response;
		} else
			conn->tx_response_queue = 0;
	}

transport_err: 
	iscsi_take_action_for_connection_exit(conn);
	goto restart;
out:
	ts->tx_thread = NULL;
	up(&ts->tx_done_sem);
	TRACE_LEAVE
	return(0);
}

static void iscsi_rx_thread_TCP_timeout (unsigned long data)
{
	up((struct semaphore *)data);
	return;
}

/*	iscsi_rx_thread_wait_for_TCP():
 *
 *
 */
static void iscsi_rx_thread_wait_for_TCP (iscsi_conn_t *conn)
{
	struct timer_list rx_TCP_timer;
	
	if ((conn->sock->sk->sk_shutdown & SEND_SHUTDOWN) ||
	    (conn->sock->sk->sk_shutdown & RCV_SHUTDOWN)) {
		init_timer(&rx_TCP_timer);
		SETUP_TIMER(rx_TCP_timer, ISCSI_RX_THREAD_TCP_TIMEOUT,
			&conn->rx_half_close_sem, iscsi_rx_thread_TCP_timeout);
		add_timer(&rx_TCP_timer);
		
		down_interruptible(&conn->rx_half_close_sem);

		del_timer_sync(&rx_TCP_timer);
	}

	return;
}

/*	iscsi_target_rx_thread():
 *
 *
 */
extern int iscsi_target_rx_thread (void *arg)
{
	int ret;
	__u8 buffer[ISCSI_HDR_LEN], opcode;
	__u32 checksum = 0, digest = 0;
	iscsi_conn_t *conn = NULL;
	iscsi_thread_set_t *ts = (iscsi_thread_set_t *) arg;
	struct iovec iov;

        {
	    static int x = 0;  /* unique number added to thread name */
            char name[20];

            memset (name,0,20);

	    sprintf (name, "%s/%d", ISCSI_RX_THREAD_NAME, x++);
	    iscsi_daemon(ts->rx_thread, name, SHUTDOWN_SIGS);
        }
	
restart:
	if (!(conn = iscsi_rx_thread_pre_handler(ts, TARGET)))
		goto out;
	
	while (1) {
		memset((void *)buffer, 0, ISCSI_HDR_LEN);
		memset((void *)&iov, 0, sizeof(struct iovec));

		iov.iov_base	= buffer;
		iov.iov_len	= ISCSI_HDR_LEN;
		
		ret = rx_data(conn, &iov, 1, ISCSI_HDR_LEN);
		if (ret != ISCSI_HDR_LEN) {
			iscsi_rx_thread_wait_for_TCP(conn);
			goto transport_err;
		}

#ifdef DEBUG_ERL
		if (iscsi_target_debugerl_rx_thread0(conn) < 0)
			goto transport_err;
#endif /* DEBUG_ERL */

		/*
		 * Set conn->bad_hdr for use with REJECT PDUs.
		 */
		memcpy(&conn->bad_hdr, &buffer, ISCSI_HDR_LEN);

		if (CONN_OPS(conn)->HeaderDigest) {
			iov.iov_base	= &digest;
			iov.iov_len	= CRC_LEN;

			ret = rx_data(conn, &iov, 1, CRC_LEN);
			if (ret != CRC_LEN) {
				iscsi_rx_thread_wait_for_TCP(conn);
				goto transport_err;
			}
#ifdef DEBUG_ERL
			if (iscsi_target_debugerl_rx_thread1(conn) < 0)
				digest = 0;
#endif /* DEBUG_ERL */
			do_crc(buffer, ISCSI_HDR_LEN, 0x01, &checksum);
			if (digest != checksum) {
				TRACE_ERROR("HeaderDigest CRC32C failed, received"
					" 0x%08x, computed 0x%08x\n", digest, checksum);
				/*
				 * Set the PDU to 0xff so it will intentionally
				 * hit default in the switch below.
				 */
				memset((void *)buffer, 0xff, ISCSI_HDR_LEN);
#ifdef SNMP_SUPPORT
				spin_lock_bh(&SESS(conn)->session_stats_lock);
				SESS(conn)->conn_digest_errors++;
				spin_unlock_bh(&SESS(conn)->session_stats_lock);
#endif /* SNMP_SUPPORT */
			} else {
				TRACE(TRACE_DIGEST, "Got HeaderDigest CRC32C"
						" 0x%08x\n", checksum);
			}
		}

		if (conn->conn_state == TARG_CONN_STATE_IN_LOGOUT)
			goto transport_err;
		
		opcode = buffer[0] & ISCSI_OPCODE;

		if (SESS_OPS_C(conn)->SessionType &&
		   ((!(opcode & ISCSI_INIT_TEXT_CMND)) ||
		    (!(opcode & ISCSI_INIT_LOGOUT_CMND)))) {
			TRACE_ERROR("Received illegal iSCSI Opcode: 0x%02x"
			" while in Discovery Session, rejecting.\n", opcode);
			iscsi_add_reject(REASON_PROTOCOL_ERR, 1, buffer, conn);
			goto transport_err;
		}
		
		switch (opcode) {
		case ISCSI_INIT_SCSI_CMND:
			if (iscsi_handle_scsi_cmd(conn, buffer) < 0)
				goto transport_err;
			break;
		case ISCSI_INIT_SCSI_DATA_OUT:
			if (iscsi_handle_data_out(conn, buffer) < 0)
				goto transport_err;
			break;
		case ISCSI_INIT_NOP_OUT:
			if (iscsi_handle_nop_out(conn, buffer) < 0)
				goto transport_err;
			break;
		case ISCSI_INIT_TASK_MGMT_CMND:
			if (iscsi_handle_task_mgt_cmd(conn, buffer) < 0)
				goto transport_err;
			break;
		case ISCSI_INIT_TEXT_CMND:
			if (iscsi_handle_text_cmd(conn, buffer) < 0)
				goto transport_err;
			break;
		case ISCSI_INIT_LOGOUT_CMND:
			ret = iscsi_handle_logout_cmd(conn, buffer);
			if (ret > 0) {
				down(&conn->conn_logout_sem);
				goto transport_err;
			} else if (ret < 0)
				goto transport_err;
			break;
		case ISCSI_INIT_SNACK:
			if (iscsi_handle_snack(conn, buffer) < 0)
				goto transport_err;
			break;
		default:
			TRACE_ERROR("Got unknown iSCSI OpCode: 0x%02x\n", opcode);
			if (!SESS_OPS_C(conn)->ErrorRecoveryLevel) {
				TRACE_ERROR("Cannot recover from unknown opcode"
				" while ERL=0, closing iSCSI connection.\n");
				goto transport_err;
			}
			if (!CONN_OPS(conn)->OFMarker) {
				TRACE_ERROR("Unable to recover from unknown"
				" opcode while OFMarker=No, closing iSCSI"
					" connection.\n");
				goto transport_err;
			}
			if (iscsi_recover_from_unknown_opcode(conn) < 0) {
				TRACE_ERROR("Unable to recover from unknown opcode,"
					" closing iSCSI connection.\n");
				goto transport_err;
			}
			break;
		}
	}

transport_err:
	if (!signal_pending(current))
		atomic_set(&conn->transport_failed, 1);
	iscsi_take_action_for_connection_exit(conn);
	goto restart;
out:
	ts->rx_thread = NULL;
	up(&ts->rx_done_sem);
	TRACE_LEAVE
	return(0);
}	

/*	iscsi_release_commands_from_conn():
 *
 *
 */
static void iscsi_release_commands_from_conn (iscsi_conn_t *conn)
{
	iscsi_cmd_t *cmd = NULL, *cmd_next = NULL;
	iscsi_session_t *sess = SESS(conn);
	
	spin_lock_bh(&conn->cmd_lock);
	cmd = conn->cmd_head;
	while (cmd) {
		cmd_next = cmd->i_next;

		if (!(cmd->cmd_flags & ICF_SE_LUN_CMD)) {
			/*
			 * CLOSESESSION and CLOSECONNECTION with a matching
			 * logout_cid will be freed in iscsi_logout_post_handler().
			 */
			if ((cmd->iscsi_opcode == ISCSI_INIT_LOGOUT_CMND) &&
			   ((cmd->logout_reason == CLOSESESSION) ||
			   ((cmd->logout_reason == CLOSECONNECTION) &&
			   (cmd->logout_cid == conn->cid)))) {
				cmd = cmd_next;
				continue;
			}
			spin_unlock_bh(&conn->cmd_lock);

			iscsi_increment_maxcmdsn(cmd, sess);
			iscsi_release_cmd_to_pool(cmd, sess);

			spin_lock_bh(&conn->cmd_lock);
			cmd = cmd_next;
			continue;
		}
		spin_unlock_bh(&conn->cmd_lock);

		iscsi_free_all_datain_reqs(cmd);
		iscsi_increment_maxcmdsn(cmd, sess);

		if (cmd->transport_wait_for_tasks)
			cmd->transport_wait_for_tasks(cmd, 1, 1);

		spin_lock_bh(&conn->cmd_lock);
		
		cmd = cmd_next;
	}
	spin_unlock_bh(&conn->cmd_lock);	

	return;
}

/*	iscsi_stop_timers_for_cmds():
 *
 *
 */
static void iscsi_stop_timers_for_cmds (
	iscsi_conn_t *conn)
{
	iscsi_cmd_t *cmd = NULL, *cmd_next = NULL;

	spin_lock_bh(&conn->cmd_lock);
	cmd = conn->cmd_head;
	while (cmd) {
		cmd_next = cmd->i_next;

		if (cmd->data_direction == ISCSI_WRITE)
			iscsi_stop_dataout_timer(cmd);

		cmd = cmd_next;
	}
	spin_unlock_bh(&conn->cmd_lock);

	return;
}

/*	iscsi_close_connection():
 *
 *
 */
extern int iscsi_close_connection (
	iscsi_conn_t *conn)
{
	int conn_logout = (conn->conn_state == TARG_CONN_STATE_IN_LOGOUT);
	iscsi_session_t	*sess = SESS(conn);

	TRACE(TRACE_ISCSI, "Closing iSCSI connection CID %hu on SID:"
		" %u\n", conn->cid, sess->sid);

	iscsi_stop_netif_timer(conn);

	/*
	 * Always up conn_logout_sem just in case the RX Thread is sleeping
	 * and the logout response never got sent because the connection
	 * failed.
	 */
	up(&conn->conn_logout_sem);
	
	iscsi_release_thread_set(conn, TARGET);

	iscsi_stop_timers_for_cmds(conn);
	iscsi_stop_nopin_response_timer(conn);
	iscsi_stop_nopin_timer(conn);
	iscsi_free_queue_reqs_for_conn(conn);

	/*
	 * During Connection recovery drop unacknowledged out of order
	 * commands for this connection, and prepare the other commands
	 * for realligence.
	 *
	 * During normal operation clear the out of order commands (but
	 * do not free the iscsi_ooo_cmdsn_t's) and release all
	 * iscsi_cmd_ts.
	 */
	if (atomic_read(&conn->connection_recovery)) {
		iscsi_discard_unacknowledged_ooo_cmdsns_for_conn(conn);
		iscsi_prepare_cmds_for_realligance(conn);
	} else {
		iscsi_clear_ooo_cmdsns_for_conn(conn);
		iscsi_release_commands_from_conn(conn);
	}

	/*
	 * Handle decrementing session or connection usage count if
	 * a logout response was not able to be sent because the
	 * connection failed.  Fall back to Session Recovery here.
	 */
	if (atomic_read(&conn->conn_logout_remove)) {
		if (conn->conn_logout_reason == CLOSESESSION) {
			iscsi_dec_conn_usage_count(conn);
			iscsi_dec_session_usage_count(sess);
		}
		if (conn->conn_logout_reason == CLOSECONNECTION)
			iscsi_dec_conn_usage_count(conn);
		
		atomic_set(&conn->conn_logout_remove, 0);
		atomic_set(&sess->session_reinstatement, 0);
		atomic_set(&sess->session_fall_back_to_erl0, 1);
	}
	
	spin_lock_bh(&sess->conn_lock);
	iscsi_remove_conn_from_list(sess, conn);

	/* 
	 * Attempt to let the Initiator know this connection failed by
	 * sending an Connection Dropped Async Message on another
	 * active connection.
	 */
	if (atomic_read(&conn->connection_recovery))
		iscsi_build_conn_drop_async_message(conn);
	
	spin_unlock_bh(&sess->conn_lock);
	
	/*
	 * If connection reinstatement is being performed on this connection,
	 * up the connection reinstatement semaphore that is being blocked on
	 * in iscsi_cause_connection_reinstatement().
	 */
	spin_lock_bh(&conn->state_lock);
	if (atomic_read(&conn->sleep_on_conn_wait_sem)) {
		spin_unlock_bh(&conn->state_lock);
		up(&conn->conn_wait_sem);
		down(&conn->conn_post_wait_sem);
		spin_lock_bh(&conn->state_lock);
	}

	/*
	 * If connection reinstatement is being performed on this connection
	 * by receiving a REMOVECONNFORRECOVERY logout request, up the
	 * connection wait rcfr semaphore that is being blocked on
	 * an iscsi_connection_reinstatement_rcfr().
	 */
	if (atomic_read(&conn->connection_wait_rcfr)) {
		spin_unlock_bh(&conn->state_lock);
		up(&conn->conn_wait_rcfr_sem);
		down(&conn->conn_post_wait_sem);
		spin_lock_bh(&conn->state_lock);
	}
	spin_unlock_bh(&conn->state_lock);

	/*
	 * If any other processes are accessing this connection pointer we
	 * must wait until they have completed.
	 */
	iscsi_check_conn_usage_count(conn);
	
	if (conn->conn_ops) {
		kfree(conn->conn_ops);
		conn->conn_ops = NULL;
	}

	if (conn->sock) {
		if (conn->conn_flags & CONNFLAG_SCTP_STRUCT_FILE) {
			kfree(conn->sock->file);
			conn->sock->file = NULL;
		}
		sock_release(conn->sock);
	}
	
	TRACE(TRACE_STATE, "Moving to TARG_CONN_STATE_FREE.\n");
	conn->conn_state = TARG_CONN_STATE_FREE;
	kfree(conn);
	conn = NULL;

	spin_lock_bh(&sess->conn_lock);
	atomic_dec(&sess->nconn);
	PYXPRINT("Decremented iSCSI connection count to %hu from node:"
		" %s\n", atomic_read(&sess->nconn), SESS_OPS(sess)->InitiatorName);

	/*
	 * Make sure that if one connection fails in an non ERL=2 iSCSI
	 * Session that they all fail.
	 */
	if ((SESS_OPS(sess)->ErrorRecoveryLevel != 2) && !conn_logout &&
	     !atomic_read(&sess->session_logout))
		atomic_set(&sess->session_fall_back_to_erl0, 1);
	
	/*
	 * If this was not the last connection in the session, and we are
	 * performing session reinstatement or falling back to ERL=0, call
	 * iscsi_stop_session() without sleeping to shutdown the other
	 * active connections.
	 */
	if (atomic_read(&sess->nconn)) {
		if (!atomic_read(&sess->session_reinstatement) &&
		    !atomic_read(&sess->session_fall_back_to_erl0)) {
			spin_unlock_bh(&sess->conn_lock);
			return(0);
		}
		if (!atomic_read(&sess->session_stop_active)) {
			atomic_set(&sess->session_stop_active, 1);
			spin_unlock_bh(&sess->conn_lock);
			iscsi_stop_session(sess, 0, 0);
			return(0);
		}
		spin_unlock_bh(&sess->conn_lock);
		return(0);
	}
	
	/*
	 * If this was the last connection in the session and one of the
	 * following is occurring:
	 *
	 * Session Reinstatement is not being performed, and are falling back
	 * to ERL=0 call iscsi_close_session().
	 *
	 * Session Logout was requested.  iscsi_close_session() will be called
	 * elsewhere.
	 * 
	 * Session Continuation is not being performed, start the Time2Retain
	 * handler and check if sleep_on_sess_wait_sem is active.
	 */
	if (!atomic_read(&sess->session_reinstatement) &&
	     atomic_read(&sess->session_fall_back_to_erl0)) {
		spin_unlock_bh(&sess->conn_lock);
		iscsi_close_session(sess);

		return(0);
	} else if (atomic_read(&sess->session_logout)) {
		TRACE(TRACE_STATE, "Moving to TARG_SESS_STATE_FREE.\n");
		sess->session_state = TARG_SESS_STATE_FREE;
		spin_unlock_bh(&sess->conn_lock);

		if (atomic_read(&sess->sleep_on_sess_wait_sem))
			up(&sess->session_wait_sem);

		return(0);
	} else {
		TRACE(TRACE_STATE, "Moving to TARG_SESS_STATE_FAILED.\n");
		sess->session_state = TARG_SESS_STATE_FAILED;

		if (!atomic_read(&sess->session_continuation)) {
			spin_unlock_bh(&sess->conn_lock);
			iscsi_start_time2retain_handler(sess);
		} else
			spin_unlock_bh(&sess->conn_lock);

		if (atomic_read(&sess->sleep_on_sess_wait_sem))
			up(&sess->session_wait_sem);

		return(0);
	}
	spin_unlock_bh(&sess->conn_lock);

	return(0);
}

/*	iscsi_close_session():
 *
 *
 */
extern int iscsi_close_session (
	iscsi_session_t *sess)
{
	iscsi_node_acl_t *acl;
	iscsi_portal_group_t *tpg = ISCSI_TPG_S(sess);
	
	if (atomic_read(&sess->nconn)) {
		TRACE_ERROR("%d connection(s) still exist for iSCSI session"
			" to %s\n", atomic_read(&sess->nconn),
			SESS_OPS(sess)->InitiatorName);
		BUG();
	}
	
	spin_lock_bh(&tpg->session_lock);
	atomic_set(&sess->session_logout, 1);
	atomic_set(&sess->session_reinstatement, 1);
	iscsi_stop_time2retain_timer(sess);
	spin_unlock_bh(&tpg->session_lock);

	/*
	 * If any other processes are accessing this session pointer we must wait until
	 * they have completed.  If we are in an interrupt (the time2retain handler)
	 * and contain and active session usage count we restart the timer and exit.
	 */
	if (!in_interrupt()) {
		if (iscsi_check_session_usage_count(sess) == 1)
			iscsi_stop_session(sess, 1, 1);
	} else {
		if (iscsi_check_session_usage_count(sess) == 2) {
			atomic_set(&sess->session_logout, 0);
			iscsi_start_time2retain_handler(sess);
			return(0);
		}
	}
	
	iscsi_remove_session_from_list(sess);

	if (SESS_OPS(sess)->ErrorRecoveryLevel == 2)
		iscsi_free_connection_recovery_entires(sess);

	/*
	 * Determine if we need to do extra work for this initiator
	 * nodes iscsi_node_acl_t if it had been previously dynamically
	 * generated.
	 */
	spin_lock_bh(&tpg->acl_node_lock);
	if ((acl = sess->node_acl)) {
		if (acl->nodeacl_flags & NAF_DYNAMIC_NODE_ACL) {
			if (!(ISCSI_TPG_ATTRIB(tpg)->cache_dynamic_acls)) {
				REMOVE_ENTRY_FROM_LIST(acl, tpg->acl_node_head,
						tpg->acl_node_tail);
				tpg->num_node_acls--;
				spin_unlock_bh(&tpg->acl_node_lock);
				iscsi_free_device_list_for_node(acl, tpg);
				kfree(acl);
				spin_lock_bh(&tpg->acl_node_lock);
			}
		}
		sess->node_acl = NULL;
	}
	spin_unlock_bh(&tpg->acl_node_lock);

	iscsi_free_all_ooo_cmdsns(sess);
	iscsi_release_all_cmds_in_pool(sess);

	spin_lock_bh(&tpg->session_lock);
	TRACE(TRACE_STATE, "Moving to TARG_SESS_STATE_FREE.\n");
	sess->session_state = TARG_SESS_STATE_FREE;
	PYXPRINT("Released iSCSI session from node: %s\n",
			SESS_OPS(sess)->InitiatorName);
	tpg->nsessions--;
	PYXPRINT("Decremented number of active iSCSI Sessions on"
		" iSCSI TPG: %hu to %u\n", tpg->tpgt, tpg->nsessions);

	if (sess->sess_ops) {
		kfree(sess->sess_ops);
		sess->sess_ops = NULL;
	}
	spin_unlock_bh(&tpg->session_lock);
	
	kfree(sess);
	sess = NULL;

	return(0);
}

/*	iscsi_logout_post_handler_closesession():
 *
 *
 */
static void iscsi_logout_post_handler_closesession (
	iscsi_conn_t *conn)
{
	iscsi_session_t *sess = SESS(conn);
	
	TRACE_ENTER

	iscsi_set_thread_clear(conn, ISCSI_CLEAR_TX_THREAD);
	iscsi_set_thread_set_signal(conn, ISCSI_SIGNAL_TX_THREAD);
	
	atomic_set(&conn->conn_logout_remove, 0);
	up(&conn->conn_logout_sem);
	
	iscsi_dec_conn_usage_count(conn);
	iscsi_stop_session(sess, 1, 1);
	iscsi_dec_session_usage_count(sess);
	iscsi_close_session(sess);
	
	TRACE_LEAVE
	return;
}

/*	iscsi_logout_post_handler_samecid():
 *
 *
 */
static void iscsi_logout_post_handler_samecid (
	iscsi_conn_t *conn)
{
	TRACE_ENTER

	iscsi_set_thread_clear(conn, ISCSI_CLEAR_TX_THREAD);
	iscsi_set_thread_set_signal(conn, ISCSI_SIGNAL_TX_THREAD);

	atomic_set(&conn->conn_logout_remove, 0);
	up(&conn->conn_logout_sem);
	
	iscsi_cause_connection_reinstatement(conn, 1);
	iscsi_dec_conn_usage_count(conn);
	
	TRACE_LEAVE
	return;
}

/*	iscsi_logout_post_handler_diffcid():
 *
 *
 */
static void iscsi_logout_post_handler_diffcid (
	iscsi_conn_t *conn,
	__u16 cid)
{
	iscsi_conn_t *l_conn;
	iscsi_session_t *sess = SESS(conn);

	TRACE_ENTER

	if (!sess)
		return;

	spin_lock_bh(&sess->conn_lock);
	for (l_conn = sess->conn_head; l_conn; l_conn = l_conn->next) {
		if (l_conn->cid == cid) {
			iscsi_inc_conn_usage_count(l_conn);
			break;
		}
	}
	spin_unlock_bh(&sess->conn_lock);

	if (!l_conn)
		return;

	if (l_conn->sock)
		l_conn->sock->ops->shutdown(l_conn->sock, RCV_SHUTDOWN);

	spin_lock(&l_conn->state_lock);
	TRACE(TRACE_STATE, "Moving to TARG_CONN_STATE_IN_LOGOUT.\n");
	l_conn->conn_state = TARG_CONN_STATE_IN_LOGOUT;
	spin_unlock(&l_conn->state_lock);
	
	iscsi_cause_connection_reinstatement(l_conn, 1);
	iscsi_dec_conn_usage_count(l_conn);

	TRACE_LEAVE
	return;
}

/*	iscsi_logout_post_handler():
 *
 *	Return of 0 causes the TX thread to restart.
 */
static int iscsi_logout_post_handler (
	iscsi_cmd_t *cmd,
	iscsi_conn_t *conn)
{
	int ret = 0;
	
	TRACE_ENTER

	switch (cmd->logout_reason) {
	case CLOSESESSION:
		switch (cmd->logout_response) {
		case CONNORSESSCLOSEDSUCCESSFULLY:
		case CLEANUPFAILED:
		default:
			iscsi_logout_post_handler_closesession(conn);
			break;
		}
		ret = 0;
		break;
	case CLOSECONNECTION:
		if (conn->cid == cmd->logout_cid) {
			switch (cmd->logout_response) {
			case CONNORSESSCLOSEDSUCCESSFULLY:
			case CLEANUPFAILED:
			default:
				iscsi_logout_post_handler_samecid(conn);
				break;
			}
			ret = 0;
		} else {
			switch (cmd->logout_response) {
			case CONNORSESSCLOSEDSUCCESSFULLY:
				iscsi_logout_post_handler_diffcid(conn,
					cmd->logout_cid);
				break;
			case CIDNOTFOUND:
			case CLEANUPFAILED:
			default:
				break;
			}
			ret = 1;
		}
		break;
	case REMOVECONNFORRECOVERY:
		switch (cmd->logout_response) {
		case CONNORSESSCLOSEDSUCCESSFULLY:
		case CIDNOTFOUND:
		case CONNRECOVERYNOTSUPPORTED:
		case CLEANUPFAILED:
		default:
			break;
		}
		ret = 1;
		break;
	default:
		break;

	}
	
	TRACE_LEAVE
	return(ret);
}

/*	iscsi_fail_session():
 *
 *	
 */
extern void iscsi_fail_session (iscsi_session_t *sess)
{
	iscsi_conn_t *conn;
	
	TRACE_ENTER

	spin_lock_bh(&sess->conn_lock);
	for (conn = sess->conn_head; conn; conn = conn->next) {
		TRACE(TRACE_STATE, "Moving to TARG_CONN_STATE_CLEANUP_WAIT.\n");
		conn->conn_state = TARG_CONN_STATE_CLEANUP_WAIT;
	}
	spin_unlock_bh(&sess->conn_lock);

	TRACE(TRACE_STATE, "Moving to TARG_SESS_STATE_FAILED.\n");
	sess->session_state = TARG_SESS_STATE_FAILED;

	TRACE_LEAVE
}

/*	iscsi_free_session():
 *
 *
 */
extern int iscsi_free_session (iscsi_session_t *sess)
{
	u16 conn_count = atomic_read(&sess->nconn);
	iscsi_conn_t *conn, *conn_next;
	
	TRACE_ENTER

	spin_lock_bh(&sess->conn_lock);
	atomic_set(&sess->sleep_on_sess_wait_sem, 1);
		
	conn = sess->conn_head;
	while (conn && (conn_count != 0)) {
		iscsi_inc_conn_usage_count(conn);
		spin_unlock_bh(&sess->conn_lock);
		iscsi_cause_connection_reinstatement(conn, 1);
		spin_lock_bh(&sess->conn_lock);

		if (!sess->conn_head)
			conn_next = NULL;
		else {
			if (sess->conn_head == conn)
				conn_next = sess->conn_head->next;
			else
				conn_next = sess->conn_head;
		}

		iscsi_dec_conn_usage_count(conn);
		conn_count--;
		conn = conn_next;
	}

	if (atomic_read(&sess->nconn)) {
		spin_unlock_bh(&sess->conn_lock);
		down(&sess->session_wait_sem);
	} else
		spin_unlock_bh(&sess->conn_lock);

	iscsi_close_session(sess);
		
	TRACE_LEAVE
	return(0);
}

/*	iscsi_stop_session():
 *
 *
 */
extern int iscsi_stop_session (iscsi_session_t *sess, int session_sleep, int connection_sleep)
{
	u16 conn_count = atomic_read(&sess->nconn);
	iscsi_conn_t *conn, *conn_next = NULL;

	TRACE_ENTER

	spin_lock_bh(&sess->conn_lock);
	if (session_sleep)
		atomic_set(&sess->sleep_on_sess_wait_sem, 1);

	if (connection_sleep) {
		conn = sess->conn_head;
		while (conn && (conn_count != 0)) {
			iscsi_inc_conn_usage_count(conn);
			spin_unlock_bh(&sess->conn_lock);
			iscsi_cause_connection_reinstatement(conn, 1);
			spin_lock_bh(&sess->conn_lock);
	
			if (!sess->conn_head)
				conn_next = NULL;
			else {
				if (sess->conn_head == conn)
					conn_next = sess->conn_head->next;
				else
					conn_next = sess->conn_head;
			}

			iscsi_dec_conn_usage_count(conn);
			conn_count--;
			conn = conn_next;
		}
	} else {
		conn = sess->conn_head;
		while (conn) {
			conn_next = conn->next;
		
			iscsi_cause_connection_reinstatement(conn, 0);

			conn = conn_next;
		}
	}

	if (session_sleep && atomic_read(&sess->nconn)) {
		spin_unlock_bh(&sess->conn_lock);
		down(&sess->session_wait_sem);
	} else
		spin_unlock_bh(&sess->conn_lock);

	TRACE_LEAVE
	return(0);
}	

/*	iscsi_release_sessions_for_tpg():
 *
 *
 */
extern int iscsi_release_sessions_for_tpg (iscsi_portal_group_t *tpg, int force)
{
	int session_count = 0;
	iscsi_session_t *sess = NULL, *sess_next = NULL;

	TRACE_ENTER

	spin_lock_bh(&tpg->session_lock);
	if (tpg->nsessions && !force) {
		spin_unlock_bh(&tpg->session_lock);
		return(-1);
	}
	
	sess = tpg->session_head;
	while (sess) {
		sess_next = sess->next;
		
		atomic_set(&sess->session_reinstatement, 1);

		spin_unlock_bh(&tpg->session_lock);
		iscsi_free_session(sess);
		spin_lock_bh(&tpg->session_lock);
		
		session_count++;
		sess = sess_next;
	}
	spin_unlock_bh(&tpg->session_lock);

	TRACE(TRACE_ISCSI, "Released %d iSCSI Session(s) from Target Portal"
			" Group: %hu\n", session_count, tpg->tpgt);

	TRACE_LEAVE
	return(0);
}

//#warning Remove module_init/module_exit from OS independent code
/*	iscsi_target_init_module():
 *
 *
 *
 */
static int iscsi_target_init_module(void)
{
	if (!(iscsi_target_detect()))
		return(0);

	return(-1);
}

/*	iscsi_target_cleanup_module();
 *
 *
 *
 */
static void iscsi_target_cleanup_module(void)
{
	iscsi_target_release();

	return;
}

#ifdef MODULE
MODULE_DESCRIPTION("LIO Target Driver Core 3.x.x Release");
MODULE_LICENSE("GPL");
module_param(fp_auto_assign, int, 0);
module_init(iscsi_target_init_module);
module_exit(iscsi_target_cleanup_module);
#endif /* MODULE */
