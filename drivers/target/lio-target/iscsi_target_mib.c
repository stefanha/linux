/*******************************************************************************
 * Filename:  iscsi_target_mib.c
 *
 * Copyright (c) 2006-2007 SBE, Inc.  All Rights Reserved.
 * Copyright (c) 2007 Rising Tide Software, Inc.
 * Copyright (c) 2008 Linux-iSCSI.org
 *
 * Nicholas A. Bellinger <nab@linux-iscsi.org>
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


#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/delay.h>
#include <linux/timer.h>
#include <linux/string.h>
#include <linux/version.h>
#include <generated/utsrelease.h>
#include <linux/utsname.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/blkdev.h>
#include <scsi/scsi.h>
#include <scsi/scsi_device.h>
#include <scsi/scsi_host.h>

#include <target/target_core_base.h>
#include <target/target_core_hba.h>
#include <target/target_core_transport.h>
#include <target/target_core_plugin.h>
#include <target/target_core_seobj.h>
#include <iscsi_protocol.h>
#include <iscsi_target_core.h>
#include <iscsi_target_device.h>
#include <iscsi_target_tpg.h>
#include <iscsi_target_util.h>
#include <iscsi_target_mib.h>

/* iSCSI mib table index */
struct iscsi_index_table iscsi_index_table;

#ifndef INITIAL_JIFFIES
#define INITIAL_JIFFIES ((unsigned long)(unsigned int) (-300*HZ))
#endif

/* Instance Attributes Table */
#define ISCSI_INST_NUM_NODES		1
#define ISCSI_INST_DESCR		"Storage Engine Target"
#define ISCSI_VENDOR			"Linux-iSCSI.org"
#define ISCSI_INST_LAST_FAILURE_TYPE	0
#define ISCSI_DISCONTINUITY_TIME	0

#define ISCSI_NODE_INDEX		1

#define ISPRINT(a)   ((a >= ' ') && (a <= '~'))

static inline int list_is_first(const struct list_head *list,
				const struct list_head *head)
{
	return list->prev == head;
}

/****************************************************************************
 * iSCSI MIB Tables
 ****************************************************************************/
/*
 * Instance Attributes Table
 */
static int get_num_portals(struct iscsi_tiqn *tiqn)
{
	return tiqn->tiqn_num_tpg_nps;
}

static int get_num_sessions(struct iscsi_tiqn *tiqn)
{
	return tiqn->tiqn_nsessions;
}

static void *locate_tiqn_start(
	struct seq_file *seq,
	loff_t *pos)
{
	spin_lock_bh(&iscsi_global->tiqn_lock);
	return seq_list_start(&iscsi_global->g_tiqn_list, *pos);
}

static void *locate_tiqn_next(
	struct seq_file *seq,
	void *v,
	loff_t *pos)
{
	return seq_list_next(v, &iscsi_global->g_tiqn_list, pos);
}

static void locate_tiqn_stop(struct seq_file *seq, void *v)
{
	spin_unlock_bh(&iscsi_global->tiqn_lock);
}

static void *inst_attr_seq_start(struct seq_file *seq, loff_t *pos)
{
	return locate_tiqn_start(seq, pos);
}

static void *inst_attr_seq_next(struct seq_file *seq, void *v, loff_t *pos)
{
	return locate_tiqn_next(seq, v, pos);
}

static void inst_attr_seq_stop(struct seq_file *seq, void *v)
{
	locate_tiqn_stop(seq, v);
}

static int inst_attr_seq_show(struct seq_file *seq, void *v)
{
	struct iscsi_sess_err_stats *sess_err;
	struct iscsi_tiqn *tiqn = list_entry(v, struct iscsi_tiqn, tiqn_list);
	u32 sess_err_count;

	if (list_is_first(&tiqn->tiqn_list, &iscsi_global->g_tiqn_list))
		seq_puts(seq, "inst min_ver max_ver portals nodes sessions"
			" fail_sess fail_type fail_rem_name disc_time\n");

	seq_printf(seq, "%u %u %u %u %u %u ",
		   tiqn->tiqn_index, ISCSI_MIN_VERSION, ISCSI_MAX_VERSION,
		   get_num_portals(tiqn), ISCSI_INST_NUM_NODES,
		   get_num_sessions(tiqn));

	sess_err = &tiqn->sess_err_stats;

	spin_lock_bh(&sess_err->lock);
	sess_err_count = (sess_err->digest_errors +
			sess_err->cxn_timeout_errors +
			sess_err->pdu_format_errors);

	seq_printf(seq, "%u %u %s %u\n", sess_err_count,
		  sess_err->last_sess_failure_type,
		  sess_err->last_sess_fail_rem_name[0] ?
		  sess_err->last_sess_fail_rem_name : NONE,
		  ISCSI_DISCONTINUITY_TIME);
	spin_unlock_bh(&sess_err->lock);

	/* Display strings one per line */
	if (list_is_last(&tiqn->tiqn_list, &iscsi_global->g_tiqn_list)) {
		seq_printf(seq, "description: %s\n", ISCSI_INST_DESCR);
		seq_printf(seq, "vendor: %s\n", ISCSI_VENDOR);
		seq_printf(seq, "version: %s on %s/%s\n", PYX_ISCSI_VERSION,
			utsname()->sysname, utsname()->machine);
	}
	return 0;
}

static const struct seq_operations inst_attr_seq_ops = {
	.start	= inst_attr_seq_start,
	.next	= inst_attr_seq_next,
	.stop	= inst_attr_seq_stop,
	.show	= inst_attr_seq_show
};

static int inst_attr_seq_open(struct inode *inode, struct file *file)
{
	return seq_open(file, &inst_attr_seq_ops);
}

static const struct file_operations inst_attr_seq_fops = {
	.owner	 = THIS_MODULE,
	.open	 = inst_attr_seq_open,
	.read	 = seq_read,
	.llseek	 = seq_lseek,
	.release = seq_release,
};

/*
 * Instance Session Failure Stats Table
 */
static int sess_err_stats_seq_show(struct seq_file *seq, void *v)
{
	struct iscsi_sess_err_stats *sess_err;
	struct iscsi_tiqn *tiqn = list_entry(v, struct iscsi_tiqn, tiqn_list);

	if (list_is_first(&tiqn->tiqn_list, &iscsi_global->g_tiqn_list))
		seq_puts(seq, "inst digest_errors cxn_errors format_errors\n");

	sess_err = &tiqn->sess_err_stats;

	seq_printf(seq, "%u %u %u %u\n", tiqn->tiqn_index,
		   sess_err->digest_errors, sess_err->cxn_timeout_errors,
		   sess_err->pdu_format_errors);
	return 0;
}

static const struct seq_operations sess_err_seq_ops = {
	.start	= locate_tiqn_start,
	.next	= locate_tiqn_next,
	.stop	= locate_tiqn_stop,
	.show	= sess_err_stats_seq_show
};

static int sess_err_stats_seq_open(struct inode *inode, struct file *file)
{
	return seq_open(file, &sess_err_seq_ops);
}

static const struct file_operations sess_err_stats_seq_fops = {
	.owner	 = THIS_MODULE,
	.open	 = sess_err_stats_seq_open,
	.read	 = seq_read,
	.llseek	 = seq_lseek,
	.release = seq_release,
};

static void *locate_tpg_start(
	struct seq_file *seq,
	loff_t *pos,
	int (*do_check)(void *))
{
	spin_lock_bh(&iscsi_global->g_tpg_lock);
	return seq_list_start(&iscsi_global->g_tpg_list, *pos);
}

static void *locate_tpg_next(
	struct seq_file *seq,
	void *v,
	loff_t *pos,
	int (*do_check)(void *))
{
	return seq_list_next(v, &iscsi_global->g_tpg_list, pos);
}

static void locate_tpg_stop(struct seq_file *seq, void *v)
{
	spin_unlock_bh(&iscsi_global->g_tpg_lock);
}

int do_portal_check(void *p)
{
	struct iscsi_portal_group *tpg = (struct iscsi_portal_group *)p;

	return tpg->num_tpg_nps;
}

/*
 * Portal Attributes Table
 * Iterates through all active TPGs and lists all portals belong to each TPG.
*/
static void *portal_attr_seq_start(struct seq_file *seq, loff_t *pos)
{
	return locate_tpg_start(seq, pos, &do_portal_check);
}

static void *portal_attr_seq_next(struct seq_file *seq, void *v, loff_t *pos)
{
	return locate_tpg_next(seq, v, pos, &do_portal_check);
}

static void portal_attr_seq_stop(struct seq_file *seq, void *v)
{
	locate_tpg_stop(seq, v);
}

static int portal_attr_seq_show(struct seq_file *seq, void *v)
{
	struct iscsi_portal_group *tpg = list_entry(v, struct iscsi_portal_group,
						g_tpg_list);
	struct iscsi_tpg_np *tpg_np, *tpg_np_tmp;
	struct iscsi_param *maxrcvdseg, *hdrdigest, *datadigest, *ofmark;
	struct iscsi_tiqn *tiqn = tpg->tpg_tiqn;

	if (!(tiqn))
		return 0;

	/*
	 * FIXME: Need to add iscsiPortalStorageType here..
	 */
	if (list_is_first(&tpg->g_tpg_list, &iscsi_global->g_tpg_list))
		seq_puts(seq, "inst indx role addr_type addr proto max_rcv "
			"hdr_dgst(pri,sec) data_dgst(pri,sec) rcv_mark\n");

	maxrcvdseg = hdrdigest = datadigest = ofmark = NULL;
	maxrcvdseg = iscsi_find_param_from_key(MAXRECVDATASEGMENTLENGTH,
					       tpg->param_list);
	hdrdigest = iscsi_find_param_from_key(HEADERDIGEST,
					      tpg->param_list);
	datadigest = iscsi_find_param_from_key(DATADIGEST,
					       tpg->param_list);
	ofmark = iscsi_find_param_from_key(OFMARKER, tpg->param_list);

	spin_lock(&tpg->tpg_np_lock);
	list_for_each_entry_safe(tpg_np, tpg_np_tmp, &tpg->tpg_gnp_list,
			tpg_np_list) {

		seq_printf(seq, "%u %u %s %s ",
			   tiqn->tiqn_index, tpg_np->tpg_np_index, "Target",
			   (tpg_np->tpg_np->np_net_size == IPV6_ADDRESS_SPACE) ?
			   "ipv6" : "ipv4");

		if (tpg_np->tpg_np->np_net_size == IPV6_ADDRESS_SPACE)
			seq_printf(seq, "[%s] ", tpg_np->tpg_np->np_ipv6);
		else
			seq_printf(seq, "%08X ", tpg_np->tpg_np->np_ipv4);

		/*
		 * Double check usage of non TCP transports with iSCSI MIBs
		 */
		switch (tpg_np->tpg_np->np_network_transport) {
		case ISCSI_TCP:
			seq_printf(seq, "%s ", "TCP");
			break;
		case ISCSI_SCTP_TCP:
		case ISCSI_SCTP_UDP:
			seq_printf(seq, "%s ", "SCTP");
			break;
		case ISCSI_IWARP_TCP:
		case ISCSI_IWARP_SCTP:
			seq_printf(seq, "%s ", "IWARP");
			break;
		case ISCSI_INFINIBAND:
			seq_printf(seq, "%s ", "IB");
			break;
		default:
			break;
		}

		seq_printf(seq, "%s %s %s %s\n",
			   maxrcvdseg ? maxrcvdseg->value :
				       INITIAL_MAXRECVDATASEGMENTLENGTH,
			   hdrdigest ? hdrdigest->value :
					INITIAL_HEADERDIGEST","NONE,
			   datadigest ? datadigest->value :
					INITIAL_DATADIGEST","NONE,
			   ofmark ? ofmark->value : INITIAL_OFMARKER);
	}
	spin_unlock(&tpg->tpg_np_lock);

	return 0;
}

static const struct seq_operations portal_attr_seq_ops = {
	.start	= portal_attr_seq_start,
	.next	= portal_attr_seq_next,
	.stop	= portal_attr_seq_stop,
	.show	= portal_attr_seq_show
};

static int portal_attr_seq_open(struct inode *inode, struct file *file)
{
	return seq_open(file, &portal_attr_seq_ops);
}

static const struct file_operations portal_attr_seq_fops = {
	.owner	 = THIS_MODULE,
	.open	 = portal_attr_seq_open,
	.read	 = seq_read,
	.llseek	 = seq_lseek,
	.release = seq_release,
};

/*
 * Target Portal Attributes Table
 */
static void *tgt_portal_attr_seq_start(struct seq_file *seq, loff_t *pos)
{
	return locate_tpg_start(seq, pos, &do_portal_check);
}

static void *tgt_portal_attr_seq_next(
	struct seq_file *seq,
	void *v,
	loff_t *pos)
{
	return locate_tpg_next(seq, v, pos, &do_portal_check);
}

static void tgt_portal_attr_seq_stop(struct seq_file *seq, void *v)
{
	locate_tpg_stop(seq, v);
}

static int tgt_portal_attr_seq_show(struct seq_file *seq, void *v)
{
	struct iscsi_portal_group *tpg = list_entry(v, struct iscsi_portal_group,
						g_tpg_list);
	struct iscsi_tpg_np *tpg_np, *tpg_np_tmp;
	struct iscsi_tiqn *tiqn = tpg->tpg_tiqn;

	if (!(tiqn))
		return 0;

	if (list_is_first(&tpg->g_tpg_list, &iscsi_global->g_tpg_list))
		seq_puts(seq, "inst indx node_indx port tag\n");

	spin_lock(&tpg->tpg_np_lock);
	list_for_each_entry_safe(tpg_np, tpg_np_tmp, &tpg->tpg_gnp_list,
			tpg_np_list) {
		seq_printf(seq, "%u %u %u %u %u\n",
			   tiqn->tiqn_index, tpg_np->tpg_np_index,
			   ISCSI_NODE_INDEX, tpg_np->tpg_np->np_port,
			   tpg->tpgt);
	}
	spin_unlock(&tpg->tpg_np_lock);

	return 0;
}

static const struct seq_operations tgt_portal_attr_seq_ops = {
	.start	= tgt_portal_attr_seq_start,
	.next	= tgt_portal_attr_seq_next,
	.stop	= tgt_portal_attr_seq_stop,
	.show	= tgt_portal_attr_seq_show
};

static int tgt_portal_attr_seq_open(struct inode *inode, struct file *file)
{
	return seq_open(file, &tgt_portal_attr_seq_ops);
}

static const struct file_operations tgt_portal_attr_seq_fops = {
	.owner	 = THIS_MODULE,
	.open	 = tgt_portal_attr_seq_open,
	.read	 = seq_read,
	.llseek	 = seq_lseek,
	.release = seq_release,
};

int do_tpg_param_check(void *p)
{
	struct iscsi_portal_group *tpg = (struct iscsi_portal_group *)p;

	return (tpg->param_list) ? 1 : 0;
}

/*
 * Node Attributes Table
 */
static void *node_attr_seq_start(struct seq_file *seq, loff_t *pos)
{
	return locate_tpg_start(seq, pos, &do_tpg_param_check);
}

static void *node_attr_seq_next(struct seq_file *seq, void *v, loff_t *pos)
{
	return locate_tpg_next(seq, v, pos, &do_tpg_param_check);
}

static void node_attr_seq_stop(struct seq_file *seq, void *v)
{
	locate_tpg_stop(seq, v);
}

static int node_attr_seq_show(struct seq_file *seq, void *v)
{
	struct iscsi_param *p1, *p2, *p3, *p4, *p5, *p6;
	struct iscsi_param *p7, *p8, *p9, *p10, *p11;
	struct iscsi_portal_group *tpg = list_entry(v, struct iscsi_portal_group,
					g_tpg_list);
	struct iscsi_tiqn *tiqn = tpg->tpg_tiqn;

	if (!(tiqn))
		return 0;

	if (list_is_first(&tpg->g_tpg_list, &iscsi_global->g_tpg_list))
		seq_puts(seq, "inst indx name role R2T imm_data max_out_R2T "
			 "first_burst max_burst max_conn seq_order pdu_order "
			 "T2W T2R ERL disc_time\n");

	seq_printf(seq, "%s %s %s %s %s %s %s %s %s %s %s ",
	(p1 = iscsi_find_param_from_key(INITIALR2T, tpg->param_list)) ?
			p1->value : INITIAL_INITIALR2T,
	(p2 = iscsi_find_param_from_key(IMMEDIATEDATA, tpg->param_list)) ?
			p2->value : INITIAL_IMMEDIATEDATA,
	(p3 = iscsi_find_param_from_key(MAXOUTSTANDINGR2T, tpg->param_list)) ?
			p3->value : INITIAL_MAXOUTSTANDINGR2T,
	(p4 = iscsi_find_param_from_key(FIRSTBURSTLENGTH, tpg->param_list)) ?
			p4->value : INITIAL_FIRSTBURSTLENGTH,
	(p5 = iscsi_find_param_from_key(MAXBURSTLENGTH, tpg->param_list)) ?
			p5->value : INITIAL_MAXBURSTLENGTH,
	(p6 = iscsi_find_param_from_key(MAXCONNECTIONS, tpg->param_list)) ?
			p6->value : INITIAL_MAXCONNECTIONS,
	(p7 = iscsi_find_param_from_key(DATASEQUENCEINORDER, tpg->param_list)) ?
			p7->value : INITIAL_DATASEQUENCEINORDER,
	(p8 = iscsi_find_param_from_key(DATAPDUINORDER, tpg->param_list)) ?
			p8->value : INITIAL_DATAPDUINORDER,
	(p9 = iscsi_find_param_from_key(DEFAULTTIME2WAIT, tpg->param_list)) ?
			p9->value : INITIAL_DEFAULTTIME2WAIT,
	(p10 = iscsi_find_param_from_key(DEFAULTTIME2RETAIN, tpg->param_list)) ?
			p10->value : INITIAL_DEFAULTTIME2RETAIN,
	(p11 = iscsi_find_param_from_key(ERRORRECOVERYLEVEL, tpg->param_list)) ?
			p11->value : INITIAL_ERRORRECOVERYLEVEL);
	seq_printf(seq, "%u\n", ISCSI_DISCONTINUITY_TIME);

	return 0;
}

static const struct seq_operations node_attr_seq_ops = {
	.start	= node_attr_seq_start,
	.next	= node_attr_seq_next,
	.stop	= node_attr_seq_stop,
	.show	= node_attr_seq_show
};

static int node_attr_seq_open(struct inode *inode, struct file *file)
{
	return seq_open(file, &node_attr_seq_ops);
}

static const struct file_operations node_attr_seq_fops = {
	.owner	 = THIS_MODULE,
	.open	 = node_attr_seq_open,
	.read	 = seq_read,
	.llseek	 = seq_lseek,
	.release = seq_release,
};

/*
 * Target Attributes Table
 */
static int tgt_attr_seq_show(struct seq_file *seq, void *v)
{
	struct iscsi_login_stats *lstat;
	struct iscsi_tiqn *tiqn = list_entry(v, struct iscsi_tiqn, tiqn_list);
	u32 fail_count;

	if (list_is_first(&tiqn->tiqn_list, &iscsi_global->g_tiqn_list))
		seq_puts(seq, "inst indx login_fails last_fail_time"
			" last_fail_type fail_intr_name fail_intr_addr_type"
			" fail_intr_addr\n");

	lstat = &tiqn->login_stats;

	spin_lock(&lstat->lock);
	fail_count = (lstat->redirects + lstat->authorize_fails +
		     lstat->authenticate_fails + lstat->negotiate_fails +
			lstat->other_fails);
	seq_printf(seq, "%u %u %u %u %u %s\n", tiqn->tiqn_index,
		   ISCSI_NODE_INDEX, fail_count,
		   lstat->last_fail_time ?
		   (u32)(((u32)lstat->last_fail_time - INITIAL_JIFFIES)
				* 100 / HZ) : 0,
		   lstat->last_fail_type, lstat->last_intr_fail_name[0] ?
		   lstat->last_intr_fail_name : NONE);
	if (lstat->last_intr_fail_ip6_addr != NULL)
		seq_printf(seq, "ipv6 [%s]\n", lstat->last_intr_fail_ip6_addr);
	else
		seq_printf(seq, "ipv4 %08X\n", lstat->last_intr_fail_addr);
	spin_unlock(&lstat->lock);

	return 0;
}

static const struct seq_operations tgt_attr_seq_ops = {
	.start	= locate_tiqn_start,
	.next	= locate_tiqn_next,
	.stop	= locate_tiqn_stop,
	.show	= tgt_attr_seq_show
};

static int tgt_attr_seq_open(struct inode *inode, struct file *file)
{
	return seq_open(file, &tgt_attr_seq_ops);
}

static const struct file_operations tgt_attr_seq_fops = {
	.owner	 = THIS_MODULE,
	.open	 = tgt_attr_seq_open,
	.read	 = seq_read,
	.llseek	 = seq_lseek,
	.release = seq_release,
};

/*
 * Target Login Stats Table
 */
static int login_stats_seq_show(struct seq_file *seq, void *v)
{
	struct iscsi_login_stats *lstat;
	struct iscsi_tiqn *tiqn = list_entry(v, struct iscsi_tiqn, tiqn_list);

	if (list_is_first(&tiqn->tiqn_list, &iscsi_global->g_tiqn_list))
		seq_puts(seq, "inst indx accepts other_fails redirects"
			" authorize_fails authenticate_fails"
			" negotiate_fails\n");

	lstat = &tiqn->login_stats;
	seq_printf(seq, "%u %u %u %u %u %u %u %u\n", tiqn->tiqn_index,
		   ISCSI_NODE_INDEX, lstat->accepts, lstat->other_fails,
		   lstat->redirects, lstat->authorize_fails,
			lstat->authenticate_fails, lstat->negotiate_fails);
	return 0;
}

static const struct seq_operations login_stats_seq_ops = {
	.start	= locate_tiqn_start,
	.next	= locate_tiqn_next,
	.stop	= locate_tiqn_stop,
	.show	= login_stats_seq_show
};

static int login_stats_seq_open(struct inode *inode, struct file *file)
{
	return seq_open(file, &login_stats_seq_ops);
}

static const struct file_operations login_stats_seq_fops = {
	.owner	 = THIS_MODULE,
	.open	 = login_stats_seq_open,
	.read	 = seq_read,
	.llseek	 = seq_lseek,
	.release = seq_release,
};

/*
 * Target Logout Stats Table
 */
static int logout_stats_seq_show(struct seq_file *seq, void *v)
{
	struct iscsi_tiqn *tiqn = list_entry(v, struct iscsi_tiqn, tiqn_list);

	if (list_is_first(&tiqn->tiqn_list, &iscsi_global->g_tiqn_list))
		seq_puts(seq, "inst indx normal_logouts abnormal_logouts\n");

	seq_printf(seq, "%u %u %u %u\n", tiqn->tiqn_index, ISCSI_NODE_INDEX,
		tiqn->logout_stats.normal_logouts,
		tiqn->logout_stats.abnormal_logouts);
	return 0;
}

static const struct seq_operations logout_stats_seq_ops = {
	.start	= locate_tiqn_start,
	.next	= locate_tiqn_next,
	.stop	= locate_tiqn_stop,
	.show	= logout_stats_seq_show
};

static int logout_stats_seq_open(struct inode *inode, struct file *file)
{
	return seq_open(file, &logout_stats_seq_ops);
}

static const struct file_operations logout_stats_seq_fops = {
	.owner	 = THIS_MODULE,
	.open	 = logout_stats_seq_open,
	.read	 = seq_read,
	.llseek	 = seq_lseek,
	.release = seq_release,
};

/*
 * Target Authorization Attributes Table
 * A list of initiator identities that are authorized to access this Target
 *
 * Iterates through all active TPGs and extracts the info from the ACLs
 */

int do_tgt_auth_check(void *p)
{
	struct iscsi_portal_group *tpg = (struct iscsi_portal_group *)p;

	return SE_TPG(tpg)->num_node_acls;
}

static void *tgt_auth_seq_start(struct seq_file *seq, loff_t *pos)
{
	return locate_tpg_start(seq, pos, &do_tgt_auth_check);
}

static void *tgt_auth_seq_next(struct seq_file *seq, void *v, loff_t *pos)
{
	return locate_tpg_next(seq, v, pos, &do_tgt_auth_check);
}

static void tgt_auth_seq_stop(struct seq_file *seq, void *v)
{
	locate_tpg_stop(seq, v);
}

static int tgt_auth_seq_show(struct seq_file *seq, void *v)
{
	struct iscsi_portal_group *tpg = list_entry(v, struct iscsi_portal_group,
					g_tpg_list);
	struct se_node_acl *acl;
	struct iscsi_tiqn *tiqn = tpg->tpg_tiqn;

	if (!(tiqn))
		return 0;

	if (list_is_first(&tpg->g_tpg_list, &iscsi_global->g_tpg_list))
		seq_puts(seq, "inst node indx intr_name\n");

	spin_lock_bh(&SE_TPG(tpg)->acl_node_lock);
	list_for_each_entry(acl, &SE_TPG(tpg)->acl_node_list, acl_list) {
		seq_printf(seq, "%u %u %u %s\n",
			   tiqn->tiqn_index, ISCSI_NODE_INDEX, acl->acl_index,
			   acl->initiatorname[0] ? acl->initiatorname : NONE);
	}
	spin_unlock_bh(&SE_TPG(tpg)->acl_node_lock);

	return 0;
}

static const struct seq_operations tgt_auth_seq_ops = {
	.start	= tgt_auth_seq_start,
	.next	= tgt_auth_seq_next,
	.stop	= tgt_auth_seq_stop,
	.show	= tgt_auth_seq_show
};

static int tgt_auth_seq_open(struct inode *inode, struct file *file)
{
	return seq_open(file, &tgt_auth_seq_ops);
}

static const struct file_operations tgt_auth_seq_fops = {
	.owner	 = THIS_MODULE,
	.open	 = tgt_auth_seq_open,
	.read	 = seq_read,
	.llseek	 = seq_lseek,
	.release = seq_release,
};

/*
 * Session Attributes Table
 * Iterates through all active TPGs and lists all sessions belong to each TPG
 */
static int do_sess_check(void *p)
{
	struct iscsi_portal_group *tpg = (struct iscsi_portal_group *)p;

	return tpg->nsessions;
}

static void *sess_attr_seq_start(struct seq_file *seq, loff_t *pos)
{
	return locate_tpg_start(seq, pos, &do_sess_check);
}

static void *sess_attr_seq_next(struct seq_file *seq, void *v, loff_t *pos)
{
	return locate_tpg_next(seq, v, pos, &do_sess_check);
}

static void sess_attr_seq_stop(struct seq_file *seq, void *v)
{
	locate_tpg_stop(seq, v);
}

static int sess_attr_seq_show(struct seq_file *seq, void *v)
{
	struct iscsi_portal_group *tpg = list_entry(v, struct iscsi_portal_group,
						g_tpg_list);
	struct iscsi_session *sess;
	struct iscsi_sess_ops *sops;
	struct iscsi_tiqn *tiqn = tpg->tpg_tiqn;
	struct se_session *se_sess;

	if (!(tiqn))
		return 0;

	if (list_is_first(&tpg->g_tpg_list, &iscsi_global->g_tpg_list))
		seq_puts(seq, "inst node indx dir intr_name tgt_name TSIH "
			 "ISID R2T imm_data type out_R2T first_burst "
			 "max_burst conn_num auth_type data_seq_order "
			 "data_pdu_order ERL disc_time\n");

	spin_lock_bh(&SE_TPG(tpg)->session_lock);
	list_for_each_entry(se_sess, &SE_TPG(tpg)->tpg_sess_list, sess_list) {
		sess = (struct iscsi_session *)se_sess->fabric_sess_ptr;
		sops = sess->sess_ops;

		seq_printf(seq, "%u %u %u %s %s %s %u ",
			   tiqn->tiqn_index, sops->SessionType ?
			   0 : ISCSI_NODE_INDEX, sess->session_index, "Inbound",
			   sops->InitiatorName[0] ? sops->InitiatorName : NONE,
			   sops->TargetName[0] ? sops->TargetName : NONE,
			   sess->tsih);
		seq_printf(seq, "%02x %02x %02x %02x %02x %02x %s %s %s %u ",
			   sess->isid[0], sess->isid[1], sess->isid[2],
			   sess->isid[3], sess->isid[4], sess->isid[5],
			   sops->InitialR2T ? "Yes" : "No",
			   sops->ImmediateData ? "Yes" : "No",
			   sops->SessionType ? "Discovery" : "Normal",
			   sops->MaxOutstandingR2T);
		seq_printf(seq, "%u %u %u %s %s %s %u %u\n",
			   sops->FirstBurstLength, sops->MaxBurstLength,
			   atomic_read(&sess->nconn),
			   sess->auth_type[0] ? sess->auth_type : NONE,
			   sops->DataSequenceInOrder ? "Yes" : "No",
			   sops->DataPDUInOrder ? "Yes" : "No",
			   sops->ErrorRecoveryLevel,
			   (u32)(((u32)sess->creation_time - INITIAL_JIFFIES)
					* 100 / HZ));

		seq_printf(seq, "intr_alias: %s\n", sops->InitiatorAlias[0] ?
			   sops->InitiatorAlias : NONE);
		seq_printf(seq, "tgt_alias: %s\n", sops->TargetAlias[0] ?
			   sops->TargetAlias : NONE);
	}
	spin_unlock_bh(&SE_TPG(tpg)->session_lock);

	return 0;
}

static const struct seq_operations sess_attr_seq_ops = {
	.start	= sess_attr_seq_start,
	.next	= sess_attr_seq_next,
	.stop	= sess_attr_seq_stop,
	.show	= sess_attr_seq_show
};

static int sess_attr_seq_open(struct inode *inode, struct file *file)
{
	return seq_open(file, &sess_attr_seq_ops);
}

static const struct file_operations sess_attr_seq_fops = {
	.owner	 = THIS_MODULE,
	.open	 = sess_attr_seq_open,
	.read	 = seq_read,
	.llseek	 = seq_lseek,
	.release = seq_release,
};

/*
 * Session Stats Table
 */
static void *sess_stats_seq_start(struct seq_file *seq, loff_t *pos)
{
	return locate_tpg_start(seq, pos, &do_sess_check);
}

static void *sess_stats_seq_next(struct seq_file *seq, void *v, loff_t *pos)
{
	return locate_tpg_next(seq, v, pos, &do_sess_check);
}

static void sess_stats_seq_stop(struct seq_file *seq, void *v)
{
	locate_tpg_stop(seq, v);
}

static int sess_stats_seq_show(struct seq_file *seq, void *v)
{
	struct iscsi_portal_group *tpg = list_entry(v, struct iscsi_portal_group,
						g_tpg_list);
	struct iscsi_session *sess;
	struct iscsi_tiqn *tiqn = tpg->tpg_tiqn;
	struct se_session *se_sess;

	if (!(tiqn))
		return 0;

	if (list_is_first(&tpg->g_tpg_list, &iscsi_global->g_tpg_list))
		seq_puts(seq,
			 "inst node indx cmd_pdus rsp_pdus txdata_octs"
			" rxdata_octs\n");

	spin_lock_bh(&SE_TPG(tpg)->session_lock);
	list_for_each_entry(se_sess, &SE_TPG(tpg)->tpg_sess_list, sess_list) {
		sess = (struct iscsi_session *)se_sess->fabric_sess_ptr;

		spin_lock_bh(&sess->session_stats_lock);
		seq_printf(seq, "%u %u %u %u %u %llu %llu\n",
			tiqn->tiqn_index,
			sess->sess_ops->SessionType ?
			0 : ISCSI_NODE_INDEX, sess->session_index,
			sess->cmd_pdus, sess->rsp_pdus,
			(unsigned long long)sess->tx_data_octets,
			(unsigned long long)sess->rx_data_octets);
		spin_unlock_bh(&sess->session_stats_lock);
	}
	spin_unlock_bh(&SE_TPG(tpg)->session_lock);

	return 0;
}

static const struct seq_operations sess_stats_seq_ops = {
	.start  = sess_stats_seq_start,
	.next   = sess_stats_seq_next,
	.stop   = sess_stats_seq_stop,
	.show   = sess_stats_seq_show
};

static int sess_stats_seq_open(struct inode *inode, struct file *file)
{
	return seq_open(file, &sess_stats_seq_ops);
}

static const struct file_operations sess_stats_seq_fops = {
	.owner	 = THIS_MODULE,
	.open	 = sess_stats_seq_open,
	.read	 = seq_read,
	.llseek	 = seq_lseek,
	.release = seq_release,
};

/*
 * Session Connection Error Stats Table
 */
static void *sess_conn_err_stats_seq_start(struct seq_file *seq, loff_t *pos)
{
	return locate_tpg_start(seq, pos, &do_sess_check);
}

static void *sess_conn_err_stats_seq_next(
	struct seq_file *seq,
	void *v,
	loff_t *pos)
{
	return locate_tpg_next(seq, v, pos, &do_sess_check);
}

static void sess_conn_err_stats_seq_stop(struct seq_file *seq, void *v)
{
	locate_tpg_stop(seq, v);
}

static int sess_conn_err_stats_seq_show(struct seq_file *seq, void *v)
{
	struct iscsi_portal_group *tpg = list_entry(v, struct iscsi_portal_group,
						g_tpg_list);
	struct iscsi_session *sess;
	struct iscsi_tiqn *tiqn = tpg->tpg_tiqn;
	struct se_session *se_sess;

	if (!(tiqn))
		return 0;

	if (list_is_first(&tpg->g_tpg_list, &iscsi_global->g_tpg_list))
		seq_puts(seq, "inst node indx dgst_errs timeouts\n");

	spin_lock_bh(&SE_TPG(tpg)->session_lock);
	list_for_each_entry(se_sess, &SE_TPG(tpg)->tpg_sess_list, sess_list) {
		sess = (struct iscsi_session *)se_sess->fabric_sess_ptr;

		spin_lock_bh(&sess->session_stats_lock);
		seq_printf(seq, "%u %u %u %u %u\n",
			   tiqn->tiqn_index,
			   sess->sess_ops->SessionType ?
			   0 : ISCSI_NODE_INDEX, sess->session_index,
			   sess->conn_digest_errors,
			   sess->conn_timeout_errors);
		spin_unlock_bh(&sess->session_stats_lock);
	}
	spin_unlock_bh(&SE_TPG(tpg)->session_lock);

	return 0;
}

static const struct seq_operations sess_conn_err_stats_seq_ops = {
	.start	= sess_conn_err_stats_seq_start,
	.next	= sess_conn_err_stats_seq_next,
	.stop	= sess_conn_err_stats_seq_stop,
	.show	= sess_conn_err_stats_seq_show
};

static int sess_conn_err_stats_seq_open(struct inode *inode, struct file *file)
{
	return seq_open(file, &sess_conn_err_stats_seq_ops);
}

static const struct file_operations sess_conn_err_stats_seq_fops = {
	.owner	 = THIS_MODULE,
	.open	 = sess_conn_err_stats_seq_open,
	.read	 = seq_read,
	.llseek	 = seq_lseek,
	.release = seq_release,
};

/*
 * Connection Attributes Table
 * Iterates through all active TPGs and lists all connections belong to each TPG
 */
static void *conn_attr_seq_start(struct seq_file *seq, loff_t *pos)
{
	return locate_tpg_start(seq, pos, &do_sess_check);
}

static void *conn_attr_seq_next(struct seq_file *seq, void *v, loff_t *pos)
{
	return locate_tpg_next(seq, v, pos, &do_sess_check);
}

static void conn_attr_seq_stop(struct seq_file *seq, void *v)
{
	locate_tpg_stop(seq, v);
}

static int conn_attr_seq_show(struct seq_file *seq, void *v)
{
	struct iscsi_portal_group *tpg = list_entry(v, struct iscsi_portal_group,
					g_tpg_list);
	struct iscsi_session *sess;
	struct iscsi_tiqn *tiqn = tpg->tpg_tiqn;
	struct iscsi_conn *conn;
	struct iscsi_conn_ops *conn_ops;
	struct se_session *se_sess;
	char state_str[16];
	char proto_str[16];

	if (!(tiqn))
		return 0;

	if (list_is_first(&tpg->g_tpg_list, &iscsi_global->g_tpg_list))
		seq_puts(seq, "inst node ssn indx cid state addr_type "
			 "local_ip proto local_port rem_ip rem_port "
			"max_rcv_data  max_xmit_data hdr_dgst data_dgst "
			 "rcv_mark send_mark vers_active\n");

	spin_lock_bh(&SE_TPG(tpg)->session_lock);
	list_for_each_entry(se_sess, &SE_TPG(tpg)->tpg_sess_list, sess_list) {
		sess = (struct iscsi_session *)se_sess->fabric_sess_ptr;

		spin_lock(&sess->conn_lock);
		list_for_each_entry(conn, &sess->sess_conn_list, conn_list) {
			switch (conn->conn_state) {
			case TARG_CONN_STATE_IN_LOGIN:
				strcpy(state_str, "login");
				break;
			case TARG_CONN_STATE_LOGGED_IN:
				strcpy(state_str, "full");
				break;
			case TARG_CONN_STATE_IN_LOGOUT:
				strcpy(state_str, "logout");
				break;
			default:
				continue;
			}
			conn_ops = conn->conn_ops;

			switch (conn->network_transport) {
			case ISCSI_TCP:
				strcpy(proto_str, "TCP");
				break;
			case ISCSI_SCTP_TCP:
			case ISCSI_SCTP_UDP:
				strcpy(proto_str, "SCTP");
				break;
			default:
				sprintf(proto_str, "Unknown(%d)",
					conn->network_transport);
			}

			seq_printf(seq, "%u %u %u %u %u %s %s %08X %s %u ",
				   tiqn->tiqn_index,
				   SESS_OPS(sess)->SessionType ?
				   0 : ISCSI_NODE_INDEX, sess->session_index,
				   conn->conn_index, conn->cid,
				   state_str, "ipv4", conn->local_ip,
				   proto_str, conn->local_port);

			if (conn->ipv6_login_ip != NULL)
				seq_printf(seq, "[%s] %u",
						&conn->ipv6_login_ip[0],
						conn->login_port);
			else
				seq_printf(seq, "%08X %u ", conn->login_ip,
						conn->login_port);

			seq_printf(seq, "%u %u %s %s %s %s %u\n",
				   conn_ops->MaxRecvDataSegmentLength,
				   conn_ops->MaxRecvDataSegmentLength,
				   conn_ops->HeaderDigest ? "CRC32C" : "None",
				   conn_ops->DataDigest ? "CRC32C" : "None",
				   conn_ops->OFMarker ? "Yes" : "No",
				   conn_ops->IFMarker ? "Yes" : "No",
				   ISCSI_MAX_VERSION);
		}
		spin_unlock(&sess->conn_lock);
	}
	spin_unlock_bh(&SE_TPG(tpg)->session_lock);

	return 0;
}

static const struct seq_operations conn_attr_seq_ops = {
	.start	= conn_attr_seq_start,
	.next	= conn_attr_seq_next,
	.stop	= conn_attr_seq_stop,
	.show	= conn_attr_seq_show
};

static int conn_attr_seq_open(struct inode *inode, struct file *file)
{
	return seq_open(file, &conn_attr_seq_ops);
}

static const struct file_operations conn_attr_seq_fops = {
	.owner	 = THIS_MODULE,
	.open	 = conn_attr_seq_open,
	.read	 = seq_read,
	.llseek	 = seq_lseek,
	.release = seq_release,
};

/*
 * SCSI Authorized Initiator Table for LIO-Target:
 * It contains the SCSI Initiators authorized to be attached to one of the
 * local Target ports.
 * Iterates through all active TPGs and extracts the info from the ACLs
 */
void *lio_scsi_auth_intr_seq_start(struct seq_file *seq, loff_t *pos)
{
	return locate_tpg_start(seq, pos, &do_portal_check);
}

void *lio_scsi_auth_intr_seq_next(struct seq_file *seq, void *v,
					 loff_t *pos)
{
	return locate_tpg_next(seq, v, pos, &do_portal_check);
}

void lio_scsi_auth_intr_seq_stop(struct seq_file *seq, void *v)
{
	locate_tpg_stop(seq, v);
}

int lio_scsi_auth_intr_seq_show(struct seq_file *seq, void *v)
{
	struct iscsi_portal_group *tpg = list_entry(v, struct iscsi_portal_group,
						g_tpg_list);
	struct se_dev_entry *deve;
	struct se_lun *lun;
	struct se_node_acl *se_nacl;
	struct iscsi_tiqn *tiqn = tpg->tpg_tiqn;
	int j;

	if (!(tiqn))
		return 0;

	spin_lock_bh(&SE_TPG(tpg)->acl_node_lock);
	list_for_each_entry(se_nacl, &SE_TPG(tpg)->acl_node_list, acl_list) {
		spin_lock_bh(&se_nacl->device_list_lock);
		for (j = 0; j < TRANSPORT_MAX_LUNS_PER_TPG; j++) {
			deve = &se_nacl->device_list[j];
			if (!(deve->lun_flags &
					TRANSPORT_LUNFLAGS_INITIATOR_ACCESS) ||
			     (!deve->se_lun))
				continue;

			lun = deve->se_lun;
			if ((lun->lun_type != TRANSPORT_LUN_TYPE_DEVICE) ||
			    (!lun->se_dev))
				continue;

			seq_printf(seq, "%u %u %u %u %u %s %u %u %u %u"
				" %u %u %u %s\n",
				tiqn->tiqn_index, /* scsiInstIndex */
				lun->se_dev->dev_index, /* scsiDeviceIndex */
				tpg->tpgt, /* scsiAuthIntrTgtPortIndex */
				se_nacl->acl_index, /* scsiAuthIntrIndex */
				1, /* scsiAuthIntrDevOrPort */
				se_nacl->initiatorname[0] ?
					se_nacl->initiatorname : NONE,
					/* scsiAuthIntrName */
				0, /* FIXME: scsiAuthIntrLunMapIndex */
				deve->attach_count,
					/* scsiAuthIntrAttachedTimes */
				deve->total_cmds, /* scsiAuthIntrOutCommands */
				(u32)(deve->read_bytes >> 20),
					/* scsiAuthIntrReadMegaBytes */
				(u32)(deve->write_bytes >> 20),
					/* scsiAuthIntrWrittenMegaBytes */
				0, /* FIXME: scsiAuthIntrHSOutCommands */
				(u32)(((u32)deve->creation_time -
					INITIAL_JIFFIES) * 100 / HZ),
					/* scsiAuthIntrLastCreation */
				"Ready"); /* FIXME: scsiAuthIntrRowStatus */
		}
		spin_unlock_bh(&se_nacl->device_list_lock);
	}
	spin_unlock_bh(&SE_TPG(tpg)->acl_node_lock);

	return 0;
}

/*
 * SCSI Attached Initiator Port Table:
 * It lists the SCSI Initiators attached to one of the local Target ports.
 * Iterates through all active TPGs and use active sessions from each TPG
 * to list the info fo this table.
 */
void *lio_scsi_att_intr_port_seq_start(struct seq_file *seq, loff_t *pos)
{
	return locate_tpg_start(seq, pos, &do_portal_check);
}

void *lio_scsi_att_intr_port_seq_next(struct seq_file *seq, void *v,
					 loff_t *pos)
{
	return locate_tpg_next(seq, v, pos, &do_portal_check);
}

void lio_scsi_att_intr_port_seq_stop(struct seq_file *seq, void *v)
{
	locate_tpg_stop(seq, v);
}

int lio_scsi_att_intr_port_seq_show(struct seq_file *seq, void *v)
{
	struct iscsi_portal_group *tpg = list_entry(v, struct iscsi_portal_group,
					g_tpg_list);
	struct iscsi_session *sess;
	struct iscsi_sess_ops *sops;
	struct se_dev_entry *deve;
	struct se_lun *lun;
	struct se_node_acl *se_nacl;
	struct se_session *se_sess;
	struct iscsi_tiqn *tiqn = tpg->tpg_tiqn;
	int j;

	if (!(tiqn))
		return 0;

	spin_lock_bh(&SE_TPG(tpg)->session_lock);
	list_for_each_entry(se_sess, &SE_TPG(tpg)->tpg_sess_list, sess_list) {
		sess = (struct iscsi_session *)se_sess->fabric_sess_ptr;
		sops = sess->sess_ops;

		if ((sess->session_state != TARG_SESS_STATE_LOGGED_IN) ||
		    (!se_sess->se_node_acl) ||
		    (!se_sess->se_node_acl->device_list)) {
			continue;
		}
		se_nacl = se_sess->se_node_acl;

		spin_lock_bh(&se_nacl->device_list_lock);
		for (j = 0; j < TRANSPORT_MAX_LUNS_PER_TPG; j++) {
			deve = &se_nacl->device_list[j];
			if (!(deve->lun_flags &
					TRANSPORT_LUNFLAGS_INITIATOR_ACCESS)
			    || (!deve->se_lun))
				continue;

			lun = deve->se_lun;
			if ((lun->lun_type != TRANSPORT_LUN_TYPE_DEVICE) ||
			    (!lun->se_dev))
				continue;

			seq_printf(seq, "%u %u %u %u %u "
				   "%s+i+%02x%02x%02x%02x%02x%02x\n",
			   tiqn->tiqn_index, /* scsiInstIndex */
			   lun->se_dev->dev_index, /* scsiDeviceIndex */
			   tpg->tpgt, /* scsiPortIndex */
			   sess->session_index,  /* scsiAttIntrPortIndex */
			   se_nacl->acl_index, /* scsiAttIntrPortAuthIntrIdx */
			   sops->InitiatorName[0] ?
				  sops->InitiatorName : NONE,
				/* scsiAttIntrPortName */
			   sess->isid[0], sess->isid[1], sess->isid[2],
			   sess->isid[3], sess->isid[4], sess->isid[5]);
				/* scsiAttIntrPortIdentifier */
		}
		spin_unlock_bh(&se_nacl->device_list_lock);
	}
	spin_unlock_bh(&SE_TPG(tpg)->session_lock);

	return 0;
}

/*
 * Used for IPS Authentication MIB table construction
 */
static void *ips_auth_seq_start(struct seq_file *seq, loff_t *pos)
{
	return locate_tpg_start(seq, pos, &do_portal_check);
}

static void *ips_auth_seq_next(struct seq_file *seq, void *v, loff_t *pos)
{
	return locate_tpg_next(seq, v, pos, &do_portal_check);
}

static void ips_auth_seq_stop(struct seq_file *seq, void *v)
{
	locate_tpg_stop(seq, v);
}

/*
 * Note: This currently shows the storage object nexus authorization
 * required status,
 *
 * FIXME: Need to update this to follow IPS AUTH MIB
 */
static int ips_auth_seq_show(struct seq_file *seq, void *v)
{
	struct iscsi_portal_group *tpg = list_entry(v, struct iscsi_portal_group,
					g_tpg_list);
	struct iscsi_tiqn *tiqn = tpg->tpg_tiqn;

	if (!(tiqn))
		return 0;

	if (list_is_first(&tpg->g_tpg_list, &iscsi_global->g_tpg_list))
		seq_puts(seq, "name tpgt enforce_auth\n");

	seq_printf(seq, "%s%s%u %u\n", tiqn->tiqn, "+", tpg->tpgt,
		ISCSI_TPG_ATTRIB(tpg)->authentication);

	return 0;
}

static const struct seq_operations ips_auth_seq_ops = {
	.start	= ips_auth_seq_start,
	.next	= ips_auth_seq_next,
	.stop	= ips_auth_seq_stop,
	.show	= ips_auth_seq_show
};

static int ips_auth_seq_open(struct inode *inode, struct file *file)
{
	return seq_open(file, &ips_auth_seq_ops);
}

static const struct file_operations ips_auth_seq_fops = {
	.owner	 = THIS_MODULE,
	.open	 = ips_auth_seq_open,
	.read	 = seq_read,
	.llseek	 = seq_lseek,
	.release = seq_release,
};
/****************************************************************************/

/*
 * Remove proc fs entries
 */
void remove_iscsi_target_mib(void)
{
	remove_proc_entry("iscsi_target/mib/inst_attr", NULL);
	remove_proc_entry("iscsi_target/mib/sess_err_stats", NULL);
	remove_proc_entry("iscsi_target/mib/portal_attr", NULL);
	remove_proc_entry("iscsi_target/mib/tgt_portal_attr", NULL);
	remove_proc_entry("iscsi_target/mib/node_attr", NULL);
	remove_proc_entry("iscsi_target/mib/tgt_attr", NULL);
	remove_proc_entry("iscsi_target/mib/login_stats", NULL);
	remove_proc_entry("iscsi_target/mib/logout_stats", NULL);
	remove_proc_entry("iscsi_target/mib/tgt_auth", NULL);
	remove_proc_entry("iscsi_target/mib/sess_attr", NULL);
	remove_proc_entry("iscsi_target/mib/sess_stats", NULL);
	remove_proc_entry("iscsi_target/mib/sess_conn_err_stats", NULL);
	remove_proc_entry("iscsi_target/mib/conn_attr", NULL);
	remove_proc_entry("iscsi_target/mib/ips_auth", NULL);
	remove_proc_entry("iscsi_target/mib", NULL);
}

/*
 * Create proc fs entries for the mib tables
 */
int init_iscsi_target_mib(void)
{
	struct proc_dir_entry *dir_entry;
	struct proc_dir_entry *inst_attr_entry;
	struct proc_dir_entry *sess_err_stats_entry;
	struct proc_dir_entry *portal_attr_entry;
	struct proc_dir_entry *tgt_portal_attr_entry;
	struct proc_dir_entry *node_attr_entry;
	struct proc_dir_entry *tgt_attr_entry;
	struct proc_dir_entry *login_stats_entry;
	struct proc_dir_entry *logout_stats_entry;
	struct proc_dir_entry *tgt_auth_entry;
	struct proc_dir_entry *sess_attr_entry;
	struct proc_dir_entry *sess_stats_entry;
	struct proc_dir_entry *sess_conn_err_stats_entry;
	struct proc_dir_entry *conn_attr_entry;
	struct proc_dir_entry *ips_auth_entry;

	dir_entry = proc_mkdir("iscsi_target/mib", NULL);
	if (!(dir_entry)) {
		printk(KERN_ERR "proc_mkdir() failed.\n");
		return -1;
	}

	inst_attr_entry =
		create_proc_entry("iscsi_target/mib/inst_attr", 0, NULL);
	if (inst_attr_entry)
		inst_attr_entry->proc_fops = &inst_attr_seq_fops;
	else
		goto error;

	sess_err_stats_entry =
		create_proc_entry("iscsi_target/mib/sess_err_stats", 0, NULL);
	if (sess_err_stats_entry)
		sess_err_stats_entry->proc_fops = &sess_err_stats_seq_fops;
	else
		goto error;

	portal_attr_entry =
		create_proc_entry("iscsi_target/mib/portal_attr", 0, NULL);
	if (portal_attr_entry)
		portal_attr_entry->proc_fops = &portal_attr_seq_fops;
	else
		goto error;

	tgt_portal_attr_entry =
		create_proc_entry("iscsi_target/mib/tgt_portal_attr", 0, NULL);
	if (tgt_portal_attr_entry)
		tgt_portal_attr_entry->proc_fops = &tgt_portal_attr_seq_fops;
	else
		goto error;

	node_attr_entry =
		create_proc_entry("iscsi_target/mib/node_attr", 0, NULL);
	if (node_attr_entry)
		node_attr_entry->proc_fops = &node_attr_seq_fops;
	else
		goto error;

	tgt_attr_entry =
		create_proc_entry("iscsi_target/mib/tgt_attr", 0, NULL);
	if (tgt_attr_entry)
		tgt_attr_entry->proc_fops = &tgt_attr_seq_fops;
	else
		goto error;

	login_stats_entry =
		create_proc_entry("iscsi_target/mib/login_stats", 0, NULL);
	if (login_stats_entry)
		login_stats_entry->proc_fops = &login_stats_seq_fops;
	else
		goto error;

	logout_stats_entry =
		create_proc_entry("iscsi_target/mib/logout_stats", 0, NULL);
	if (logout_stats_entry)
		logout_stats_entry->proc_fops = &logout_stats_seq_fops;
	else
		goto error;

	tgt_auth_entry =
		create_proc_entry("iscsi_target/mib/tgt_auth", 0, NULL);
	if (tgt_auth_entry)
		tgt_auth_entry->proc_fops = &tgt_auth_seq_fops;
	else
		goto error;

	sess_attr_entry =
		create_proc_entry("iscsi_target/mib/sess_attr", 0, NULL);
	if (sess_attr_entry)
		sess_attr_entry->proc_fops = &sess_attr_seq_fops;
	else
		goto error;

	sess_stats_entry =
		create_proc_entry("iscsi_target/mib/sess_stats", 0, NULL);
	if (sess_stats_entry)
		sess_stats_entry->proc_fops = &sess_stats_seq_fops;
	else
		goto error;

	sess_conn_err_stats_entry =
	    create_proc_entry("iscsi_target/mib/sess_conn_err_stats", 0, NULL);
	if (sess_conn_err_stats_entry)
		sess_conn_err_stats_entry->proc_fops =
						&sess_conn_err_stats_seq_fops;
	else
		goto error;

	conn_attr_entry =
		create_proc_entry("iscsi_target/mib/conn_attr", 0, NULL);
	if (conn_attr_entry)
		conn_attr_entry->proc_fops = &conn_attr_seq_fops;
	else
		goto error;

	ips_auth_entry =
		create_proc_entry("iscsi_target/mib/ips_auth", 0, NULL);
	if (ips_auth_entry)
		ips_auth_entry->proc_fops = &ips_auth_seq_fops;
	else
		goto error;

	return 0;

error:
	printk(KERN_ERR "create_proc_entry() failed.\n");
	remove_iscsi_target_mib();
	return -1;
}

/*
 * Initialize the index table for allocating unique row indexes to various mib
 * tables
 */
void init_iscsi_index_table(void)
{
	memset(&iscsi_index_table, 0, sizeof(iscsi_index_table));
	spin_lock_init(&iscsi_index_table.lock);
}

/*
 * Allocate a new row index for the entry type specified
 */
u32 iscsi_get_new_index(iscsi_index_t type)
{
	u32 new_index;

	if ((type < 0) || (type >= INDEX_TYPE_MAX)) {
		printk(KERN_ERR "Invalid index type %d\n", type);
		return -1;
	}

	spin_lock(&iscsi_index_table.lock);
	new_index = ++iscsi_index_table.iscsi_mib_index[type];
	if (new_index == 0)
		new_index = ++iscsi_index_table.iscsi_mib_index[type];
	spin_unlock(&iscsi_index_table.lock);

	return new_index;
}
