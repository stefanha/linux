/*********************************************************************************
 * Filename:  iscsi_target_mib.c
 *
 * Copyright (c) 2006-2007 SBE, Inc.  All Rights Reserved.
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


#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/delay.h>
#include <linux/timer.h>
#include <linux/string.h>
#include <linux/version.h>
#ifdef HAS_UTS_RELEASE
#include <linux/utsrelease.h>
#endif
#include <linux/utsname.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/blkdev.h>
#ifdef USE_SCSI_H
#include <scsi.h>
#endif /* USE_SCSI_H */
#ifndef _SCSI_H
#include <scsi/scsi.h>
#include <scsi/scsi_device.h>
#endif /* _SCSI_H */
#include <scsi/scsi_host.h>
#include "iscsi_protocol.h"
#include <iscsi_debug_opcodes.h>
#include "iscsi_target_core.h"
#include <iscsi_target_error.h>
#include <iscsi_target_ioctl.h> 
#include <iscsi_target_ioctl_defs.h>
#include "iscsi_target_device.h"
#include "iscsi_target_ioctl.h"
#include "iscsi_target_tpg.h"
#include "iscsi_target_hba.h"
#include "iscsi_target_info.h"
#include "iscsi_target_transport.h"
#include "iscsi_target_util.h"
#include "iscsi_target_mib.h"

#include <iscsi_target_plugin.h>
#include <iscsi_target_seobj.h>
#include <iscsi_target_feature_obj.h>

extern iscsi_global_t *iscsi_global;

/* iSCSI mib table index */
iscsi_index_table_t iscsi_index_table;

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

/* SCSI Instance Table */
#define SCSI_INST_SW_INDEX		1
#define SCSI_TRANSPORT_INDEX		1

#define ISPRINT(a)   ((a >=' ')&&(a <= '~'))

/****************************************************************************
 * iSCSI MIB Tables
 ****************************************************************************/
/*
 * Instance Attributes Table 
 */
static int __get_num_portals(iscsi_tiqn_t *tiqn)
{
	iscsi_portal_group_t *tpg;
	int i, num_portals = 0;

	for (i = 0; i < ISCSI_MAX_TPGS; i++) {
		tpg = &tiqn->tiqn_tpg_list[i];
		if (tpg->tpg_state == TPG_STATE_ACTIVE)
			num_portals += tpg->num_tpg_nps;
	}

	return(num_portals);
}

static int get_num_portals(iscsi_tiqn_t *tiqn)
{
	int num_portals;

	spin_lock(&tiqn->tiqn_tpg_lock);
	num_portals = __get_num_portals(tiqn);
	spin_unlock(&tiqn->tiqn_tpg_lock);

	return (num_portals);
}

static int get_num_sessions(iscsi_tiqn_t *tiqn)
{
	int i, num_sessions = 0;
	iscsi_portal_group_t *tpg;

	spin_lock(&tiqn->tiqn_tpg_lock);
	for (i = 0; i < ISCSI_MAX_TPGS; i++) {
		tpg = &tiqn->tiqn_tpg_list[i];
		if (tpg->tpg_state == TPG_STATE_ACTIVE)
			num_sessions += tpg->nsessions;
	}
	spin_unlock(&tiqn->tiqn_tpg_lock);

	return(num_sessions);
}

static int inst_attr_seq_show(struct seq_file *seq, void *v)
{
	iscsi_sess_err_stats_t *sess_err;
	iscsi_tiqn_t *tiqn;
	u32 sess_err_count;

	seq_puts(seq, "inst min_ver max_ver portals nodes sessions fail_sess"
		" fail_type fail_rem_name disc_time\n");

	spin_lock(&iscsi_global->tiqn_lock);
	list_for_each_entry(tiqn, &iscsi_global->g_tiqn_list, tiqn_list) {
		seq_printf(seq, "%u %u %u %u %u %u ",
 			   tiqn->tiqn_index, ISCSI_MIN_VERSION, ISCSI_MAX_VERSION,
			   get_num_portals(tiqn), ISCSI_INST_NUM_NODES,
			   get_num_sessions(tiqn));

		sess_err = &tiqn->sess_err_stats;

		spin_lock(&sess_err->lock);
		sess_err_count = (sess_err->digest_errors +
				sess_err->cxn_timeout_errors +
		 		sess_err->pdu_format_errors);

		seq_printf(seq, "%u %u %s %u\n", sess_err_count, 
			  sess_err->last_sess_failure_type,
			  sess_err->last_sess_fail_rem_name[0] ?
			  	sess_err->last_sess_fail_rem_name : NONE,
			  ISCSI_DISCONTINUITY_TIME);
		spin_unlock(&sess_err->lock);
	}
	spin_unlock(&iscsi_global->tiqn_lock);

	/* Display strings one per line */
	seq_printf(seq, "description: %s\n", ISCSI_INST_DESCR);
	seq_printf(seq, "vendor: %s\n", ISCSI_VENDOR);
	seq_printf(seq, "version: %s on %s/%s\n", PYX_ISCSI_VERSION,
		utsname()->sysname, utsname()->machine);

	return(0);
}

static int inst_attr_seq_open(struct inode *inode, struct file *file)
{
	return single_open(file, inst_attr_seq_show, NULL);
}

static struct file_operations inst_attr_seq_fops = {
	.owner	 = THIS_MODULE,
	.open	 = inst_attr_seq_open,
	.read	 = seq_read,
	.llseek	 = seq_lseek,
	.release = single_release,
};

/*
 * Instance Session Failure Stats Table
 */
static int sess_err_stats_seq_show(struct seq_file *seq, void *v)
{
	iscsi_sess_err_stats_t *sess_err;
	iscsi_tiqn_t *tiqn;

	seq_puts(seq, "inst digest_errors cxn_errors format_errors\n");

	spin_lock(&iscsi_global->tiqn_lock);
	list_for_each_entry(tiqn, &iscsi_global->g_tiqn_list, tiqn_list) {

		sess_err = &tiqn->sess_err_stats;

		seq_printf(seq, "%u %u %u %u\n", tiqn->tiqn_index,
			   sess_err->digest_errors, sess_err->cxn_timeout_errors,
			   sess_err->pdu_format_errors);
	}
	spin_unlock(&iscsi_global->tiqn_lock);

	return(0);
}

static int sess_err_stats_seq_open(struct inode *inode, struct file *file)
{
	return single_open(file, sess_err_stats_seq_show, NULL);
}

static struct file_operations sess_err_stats_seq_fops = {
	.owner	 = THIS_MODULE,
	.open	 = sess_err_stats_seq_open,
	.read	 = seq_read,
	.llseek	 = seq_lseek,
	.release = single_release,
};

static void *locate_tpg_start(
	struct seq_file *seq,
	loff_t *pos,
	int (*do_check)(void *))
{
	iscsi_portal_group_t *tpg;
	iscsi_tiqn_t *tiqn;
	table_iter_t *tpg_iter;
	loff_t n = *pos;
	int i, header = (n) ? 0 : 1;

	if (!(tpg_iter = kmalloc(sizeof(table_iter_t), GFP_KERNEL))) 
		return(NULL);
	memset(tpg_iter, 0, sizeof(table_iter_t));
//	printk("%s[%d] - Allocated TPG itr: %p\n", current->comm, current->pid, tpg_iter);

	spin_lock(&iscsi_global->tiqn_lock);
	list_for_each_entry(tiqn, &iscsi_global->g_tiqn_list, tiqn_list) {

		if (!tiqn->tiqn_active_tpgs)
			continue;

		spin_lock(&tiqn->tiqn_tpg_lock);
		for (i = 0; i < ISCSI_MAX_TPGS; i++) {
			tpg = &tiqn->tiqn_tpg_list[i];

			spin_lock(&tpg->tpg_state_lock);
			if (tpg->tpg_state == TPG_STATE_ACTIVE) {
				if (do_check((void *)tpg) == 0) {
					spin_unlock(&tpg->tpg_state_lock);
					continue;
				}
				if (n) {
					n--;
					spin_unlock(&tpg->tpg_state_lock);
					continue;
				}

				tpg_iter->count_max = tiqn->tiqn_active_tpgs;
				tpg_iter->count_cur = 0;
				tpg_iter->ti_header = header;
				tpg_iter->ti_ptr = (void *)tiqn; 
				tpg_iter->ti_offset = tpg->tpgt;

				atomic_inc(&tiqn->tiqn_access_count);
				spin_unlock(&tpg->tpg_state_lock);
				spin_unlock(&tiqn->tiqn_tpg_lock);
				spin_unlock(&iscsi_global->tiqn_lock);
				return((void *)tpg_iter);
			}
			spin_unlock(&tpg->tpg_state_lock);
		}
		spin_unlock(&tiqn->tiqn_tpg_lock);
	}
	spin_unlock(&iscsi_global->tiqn_lock);

	return(NULL);
}

static void *locate_tpg_next(
	struct seq_file *seq,
	void *v,
	loff_t *pos,
	int (*do_check)(void *))
{
	table_iter_t *iterp = (table_iter_t *)v;
	iscsi_portal_group_t *tpg;
	iscsi_tiqn_t *tiqn = (iscsi_tiqn_t *)iterp->ti_ptr;
	int i;

	(*pos)++;

	if (iterp->count_cur < iterp->count_max) {
		iterp->count_cur++;
		
		spin_lock(&tiqn->tiqn_tpg_lock);
		for (i = (iterp->ti_offset + 1); i < ISCSI_MAX_TPGS; i++) {
			tpg = &tiqn->tiqn_tpg_list[i];

			spin_lock(&tpg->tpg_state_lock);
			if (tpg->tpg_state == TPG_STATE_ACTIVE) {
				if (do_check((void *)tpg) == 0) {
					spin_unlock(&tpg->tpg_state_lock);
					continue;
				}

				iterp->ti_offset = tpg->tpgt;
				spin_unlock(&tpg->tpg_state_lock);
				spin_unlock(&tiqn->tiqn_tpg_lock);
				return(v);
			}
			spin_unlock(&tpg->tpg_state_lock);
		}
		spin_unlock(&tiqn->tiqn_tpg_lock);

		return(NULL);
	} else {
		spin_lock(&iscsi_global->tiqn_lock);
		atomic_dec(&tiqn->tiqn_access_count);

		list_for_each_entry_continue(tiqn, &iscsi_global->g_tiqn_list, tiqn_list) {
			if (!tiqn->tiqn_active_tpgs)
				continue;

			spin_lock(&tiqn->tiqn_tpg_lock);
			for (i = 0; i < ISCSI_MAX_TPGS; i++) {
				tpg = &tiqn->tiqn_tpg_list[i];
	
				spin_lock(&tpg->tpg_state_lock);
				if (tpg->tpg_state == TPG_STATE_ACTIVE) {
					if (do_check((void *)tpg) == 0) {
						spin_unlock(&tpg->tpg_state_lock);
						continue;
					}
	
					iterp->count_max = tiqn->tiqn_active_tpgs;
					iterp->ti_ptr = (void *)tiqn;
					iterp->count_cur = 0; 
					iterp->ti_offset = tpg->tpgt;
					iterp->ti_skip_body = 0;

					atomic_inc(&tiqn->tiqn_access_count);
					spin_unlock(&tpg->tpg_state_lock);
					spin_unlock(&tiqn->tiqn_tpg_lock);
					spin_unlock(&iscsi_global->tiqn_lock);

					return(v);
				}
				spin_unlock(&tpg->tpg_state_lock);
			}
			spin_unlock(&tiqn->tiqn_tpg_lock);
		}
		spin_unlock(&iscsi_global->tiqn_lock);
	}

	return(NULL);
}

static void locate_tpg_stop(struct seq_file *seq, void *v)
{       
        table_iter_t *iterp = (table_iter_t *)v;
	iscsi_tiqn_t *tiqn;

	if (!(v))
		return;

	if (iterp && (tiqn = (iscsi_tiqn_t *)iterp->ti_ptr)) {
		atomic_dec(&tiqn->tiqn_access_count);
	}

//	printk("%s[%d] - Releasing iterp: %p\n", current->comm, current->pid, iterp);
	kfree(iterp);

	return;
}

int do_portal_check(void *p)
{
	iscsi_portal_group_t *tpg = (iscsi_portal_group_t *)p;

	return(tpg->num_tpg_nps);
}

/*
 * Portal Attributes Table
 * Iterates through all active TPGs and lists all portals belong to each TPG.
*/
static void *portal_attr_seq_start(struct seq_file *seq, loff_t *pos)
{
	return(locate_tpg_start(seq, pos, &do_portal_check));
}

static void *portal_attr_seq_next(struct seq_file *seq, void *v, loff_t *pos)
{
	return(locate_tpg_next(seq, v, pos, &do_portal_check));
}

static void portal_attr_seq_stop(struct seq_file *seq, void *v)
{
	locate_tpg_stop(seq, v);
}

static int portal_attr_seq_show(struct seq_file *seq, void *v)
{
	iscsi_portal_group_t *tpg;
	iscsi_tpg_np_t *tpg_np;
	table_iter_t *iterp = (table_iter_t *)v;
	iscsi_param_t *maxrcvdseg, *hdrdigest, *datadigest, *ofmark;
	iscsi_tiqn_t *tiqn;

#warning FIXME: Add iscsiPortalStorageType
	if (iterp->ti_header) {
		seq_puts(seq, "inst indx role addr_type addr proto max_rcv "
		         "hdr_dgst(pri,sec) data_dgst(pri,sec) rcv_mark\n");
		iterp->ti_header = 0;
	}
	if (!(tiqn = (iscsi_tiqn_t *)iterp->ti_ptr))
		return(0);

	tpg = NULL;
	maxrcvdseg = hdrdigest = datadigest = ofmark = NULL;
	if ((iterp->ti_offset >= 0) && (tpg = iscsi_get_tpg_from_tpgt(tiqn,
				iterp->ti_offset, 0))) {
		maxrcvdseg = iscsi_find_param_from_key(MAXRECVDATASEGMENTLENGTH,
						       tpg->param_list);
		hdrdigest = iscsi_find_param_from_key(HEADERDIGEST,
						      tpg->param_list);
		datadigest = iscsi_find_param_from_key(DATADIGEST,
						       tpg->param_list);
		ofmark = iscsi_find_param_from_key(OFMARKER, tpg->param_list);
	}

	if (!tpg)
		return(0);

	spin_lock(&tpg->tpg_np_lock);
	list_for_each_entry(tpg_np, &tpg->tpg_gnp_list, tpg_np_list) {
#warning FIXME: T/I Mode
#warning FIXME: DNS 
		seq_printf(seq, "%u %u %s %s ", 
			   tiqn->tiqn_index, tpg_np->tpg_np_index, "Target",
			   (tpg_np->tpg_np->np_net_size == IPV6_ADDRESS_SPACE) ?
			   "ipv6" : "ipv4");

#warning FIXME: Double check usage of brackets around IPv6 address
		if (tpg_np->tpg_np->np_net_size == IPV6_ADDRESS_SPACE)
			seq_printf(seq, "[%s] ", tpg_np->tpg_np->np_ipv6);
		else
			seq_printf(seq, "%08X ", tpg_np->tpg_np->np_ipv4);

#warning FIXME: Double check usage of SNMP of other transports
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
			   maxrcvdseg? maxrcvdseg->value:
				       INITIAL_MAXRECVDATASEGMENTLENGTH,
			   hdrdigest? hdrdigest->value:
					INITIAL_HEADERDIGEST","NONE,
			   datadigest? datadigest->value:
					INITIAL_DATADIGEST","NONE,
			   ofmark? ofmark->value:INITIAL_OFMARKER);
	}
	spin_unlock(&tpg->tpg_np_lock);

	/* Release the semaphore */
	iscsi_put_tpg(tpg);

	return(0);
}

static struct seq_operations portal_attr_seq_ops = {
	.start	= portal_attr_seq_start,
	.next	= portal_attr_seq_next,
	.stop	= portal_attr_seq_stop,
	.show	= portal_attr_seq_show
};

static int portal_attr_seq_open(struct inode *inode, struct file *file)
{
	return seq_open(file, &portal_attr_seq_ops);
}

static struct file_operations portal_attr_seq_fops = {
	.owner	 = THIS_MODULE,
	.open	 = portal_attr_seq_open,
	.read	 = seq_read,
	.llseek	 = seq_lseek,
	.release = seq_release,
};

/*
 * Target Portal Attributes Table
 */
static int tgt_portal_attr_seq_show(struct seq_file *seq, void *v)
{
	iscsi_portal_group_t *tpg;
	iscsi_tpg_np_t *tpg_np;
	iscsi_tiqn_t *tiqn;
	int i;

	seq_puts(seq, "inst indx node_indx port tag\n");

	spin_lock(&iscsi_global->tiqn_lock);
	list_for_each_entry(tiqn, &iscsi_global->g_tiqn_list, tiqn_list) {

		spin_lock(&tiqn->tiqn_tpg_lock);
		for (i = 0; i < ISCSI_MAX_TPGS; i++) {
			tpg = &tiqn->tiqn_tpg_list[i];

			spin_lock(&tpg->tpg_state_lock);
			if (tpg->tpg_state == TPG_STATE_ACTIVE) {
	
				spin_lock(&tpg->tpg_np_lock);
				list_for_each_entry(tpg_np, &tpg->tpg_gnp_list, tpg_np_list) {
					seq_printf(seq, "%u %u %u %u %u\n", 
						   tiqn->tiqn_index, tpg_np->tpg_np_index,
						   ISCSI_NODE_INDEX, tpg_np->tpg_np->np_port,
						   tpg->tpgt);
				}
				spin_unlock(&tpg->tpg_np_lock);
			}
			spin_unlock(&tpg->tpg_state_lock);
		}
		spin_unlock(&tiqn->tiqn_tpg_lock); 
	}
	spin_unlock(&iscsi_global->tiqn_lock);

	return(0);
}

static int tgt_portal_attr_seq_open(struct inode *inode, struct file *file)
{
	return single_open(file, tgt_portal_attr_seq_show, NULL);
}

static struct file_operations tgt_portal_attr_seq_fops = {
	.owner	 = THIS_MODULE,
	.open	 = tgt_portal_attr_seq_open,
	.read	 = seq_read,
	.llseek	 = seq_lseek,
	.release = single_release,
};

int do_tpg_param_check(void *p)
{
	iscsi_portal_group_t *tpg = (iscsi_portal_group_t *)p;

	return((tpg->param_list) ? 1 : 0);
}

/*
 * Node Attributes Table
 */
static void *node_attr_seq_start(struct seq_file *seq, loff_t *pos)
{
        return(locate_tpg_start(seq, pos, &do_tpg_param_check));
}

static void *node_attr_seq_next(struct seq_file *seq, void *v, loff_t *pos)
{
        return(locate_tpg_next(seq, v, pos, &do_tpg_param_check));
}

static void node_attr_seq_stop(struct seq_file *seq, void *v)
{
	locate_tpg_stop(seq, v);
}

static int node_attr_seq_show(struct seq_file *seq, void *v)
{
	iscsi_param_t *p1, *p2, *p3, *p4, *p5, *p6;
	iscsi_param_t *p7, *p8, *p9, *p10, *p11;
	table_iter_t *iterp = (table_iter_t *)v;
	iscsi_portal_group_t *tpg;
	iscsi_tiqn_t *tiqn;

	if (iterp->ti_header) {
		seq_puts(seq, "inst indx name role R2T imm_data max_out_R2T "
			 "first_burst max_burst max_conn seq_order pdu_order "
			 "T2W T2R ERL disc_time\n");
		iterp->ti_header = 0;
	}

	/*
	 * We only display the node output for the first TPG of the storage object.
	 */
	if (iterp->ti_skip_body)
		return(0);
	iterp->ti_skip_body = 1;

	if (!(tiqn = (iscsi_tiqn_t *)iterp->ti_ptr))
		return(0);
	
	seq_printf(seq, "%u %u %s %s ", tiqn->tiqn_index, ISCSI_NODE_INDEX,
			tiqn->tiqn, "Target");

	if ((iterp->ti_offset >= 0) && (tpg = iscsi_get_tpg_from_tpgt(tiqn,
				iterp->ti_offset, 0))) {

		seq_printf(seq, "%s %s %s %s %s %s %s %s %s %s %s ",
		(p1 = iscsi_find_param_from_key(INITIALR2T, tpg->param_list)) ?
				p1->value:INITIAL_INITIALR2T,
		(p2 = iscsi_find_param_from_key(IMMEDIATEDATA, tpg->param_list))?
				p2->value:INITIAL_IMMEDIATEDATA,
		(p3 = iscsi_find_param_from_key(MAXOUTSTANDINGR2T, tpg->param_list)) ?
				p3->value:INITIAL_MAXOUTSTANDINGR2T,
		(p4 = iscsi_find_param_from_key(FIRSTBURSTLENGTH, tpg->param_list)) ?
				p4->value:INITIAL_FIRSTBURSTLENGTH,
		(p5 = iscsi_find_param_from_key(MAXBURSTLENGTH, tpg->param_list)) ?
				p5->value:INITIAL_MAXBURSTLENGTH,
		(p6 = iscsi_find_param_from_key(MAXCONNECTIONS, tpg->param_list)) ?
				p6->value:INITIAL_MAXCONNECTIONS,
		(p7 = iscsi_find_param_from_key(DATASEQUENCEINORDER, tpg->param_list)) ?
				p7->value:INITIAL_DATASEQUENCEINORDER,
		(p8 = iscsi_find_param_from_key(DATAPDUINORDER, tpg->param_list)) ?
				p8->value:INITIAL_DATAPDUINORDER,
		(p9 = iscsi_find_param_from_key(DEFAULTTIME2WAIT, tpg->param_list)) ?
				p9->value:INITIAL_DEFAULTTIME2WAIT,
		(p10 = iscsi_find_param_from_key(DEFAULTTIME2RETAIN, tpg->param_list)) ?
				p10->value:INITIAL_DEFAULTTIME2RETAIN,
		(p11 = iscsi_find_param_from_key(ERRORRECOVERYLEVEL, tpg->param_list)) ?
				p11->value:INITIAL_ERRORRECOVERYLEVEL);
		seq_printf(seq, "%u\n", ISCSI_DISCONTINUITY_TIME);

		iscsi_put_tpg(tpg);
		return(0);
	}

	seq_printf(seq, "%s %s %s %s %s %s %s %s %s %s %s ",
	 	   INITIAL_INITIALR2T, INITIAL_IMMEDIATEDATA,
		   INITIAL_MAXOUTSTANDINGR2T, INITIAL_FIRSTBURSTLENGTH,
		   INITIAL_MAXBURSTLENGTH, INITIAL_MAXCONNECTIONS,
		   INITIAL_DATASEQUENCEINORDER, INITIAL_DATAPDUINORDER,
		   INITIAL_DEFAULTTIME2WAIT, INITIAL_DEFAULTTIME2RETAIN,
		   INITIAL_ERRORRECOVERYLEVEL);
	seq_printf(seq, "%u\n", ISCSI_DISCONTINUITY_TIME);

	return(0);
}

static struct seq_operations node_attr_seq_ops = {
        .start  = node_attr_seq_start,
        .next   = node_attr_seq_next,
        .stop   = node_attr_seq_stop,
        .show   = node_attr_seq_show
};

static int node_attr_seq_open(struct inode *inode, struct file *file)
{
	return(seq_open(file, &node_attr_seq_ops));
}

static struct file_operations node_attr_seq_fops = {
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
	iscsi_login_stats_t *lstat;
	iscsi_tiqn_t *tiqn;
	u32 fail_count;

	seq_puts(seq, "inst indx login_fails last_fail_time last_fail_type "
		 "fail_intr_name fail_intr_addr_type fail_intr_addr\n");

	spin_lock(&iscsi_global->tiqn_lock);
	list_for_each_entry(tiqn, &iscsi_global->g_tiqn_list, tiqn_list) {

		lstat = &tiqn->login_stats;

		spin_lock(&lstat->lock);	
		fail_count = (lstat->redirects + lstat->authorize_fails +
			     lstat->authenticate_fails + lstat->negotiate_fails +
				lstat->other_fails);
#warning FIXME: IPv6
		seq_printf(seq, "%u %u %u %u %u %s %s %08X\n", tiqn->tiqn_index,
			   ISCSI_NODE_INDEX, fail_count, 
			   lstat->last_fail_time ?
			   (u32)(((u32)lstat->last_fail_time - INITIAL_JIFFIES) * 100/HZ):0,
			   lstat->last_fail_type, lstat->last_intr_fail_name[0] ?
			   lstat->last_intr_fail_name : NONE, "ipv4",
			   lstat->last_intr_fail_addr);
		spin_unlock(&lstat->lock);	
	}
	spin_unlock(&iscsi_global->tiqn_lock);

	return(0);
}

static int tgt_attr_seq_open(struct inode *inode, struct file *file)
{
	return single_open(file, tgt_attr_seq_show, NULL);
}

static struct file_operations tgt_attr_seq_fops = {
	.owner	 = THIS_MODULE,
	.open	 = tgt_attr_seq_open,
	.read	 = seq_read,
	.llseek	 = seq_lseek,
	.release = single_release,
};

/*
 * Target Login Stats Table
 */
static int login_stats_seq_show(struct seq_file *seq, void *v)
{
	iscsi_login_stats_t *lstat;
	iscsi_tiqn_t *tiqn;

	seq_puts(seq, "inst indx accepts other_fails redirects authorize_fails "
		 "authenticate_fails negotiate_fails\n");

	spin_lock(&iscsi_global->tiqn_lock);
	list_for_each_entry(tiqn, &iscsi_global->g_tiqn_list, tiqn_list) {
		
		lstat = &tiqn->login_stats;
		seq_printf(seq, "%u %u %u %u %u %u %u %u\n", tiqn->tiqn_index,
			   ISCSI_NODE_INDEX, lstat->accepts, lstat->other_fails,
			   lstat->redirects, lstat->authorize_fails,
				lstat->authenticate_fails, lstat->negotiate_fails);
	}
	spin_unlock(&iscsi_global->tiqn_lock);

	return(0);
}

static int login_stats_seq_open(struct inode *inode, struct file *file)
{
	return single_open(file, login_stats_seq_show, NULL);
}

static struct file_operations login_stats_seq_fops = {
	.owner	 = THIS_MODULE,
	.open	 = login_stats_seq_open,
	.read	 = seq_read,
	.llseek	 = seq_lseek,
	.release = single_release,
};

/*
 * Target Logout Stats Table
 */
static int logout_stats_seq_show(struct seq_file *seq, void *v)
{
	iscsi_tiqn_t *tiqn;

	seq_puts(seq, "inst indx normal_logouts abnormal_logouts\n");
	
	spin_lock(&iscsi_global->tiqn_lock);
	list_for_each_entry(tiqn, &iscsi_global->g_tiqn_list, tiqn_list) {
		seq_printf(seq, "%u %u %u %u\n", tiqn->tiqn_index, ISCSI_NODE_INDEX,
			tiqn->logout_stats.normal_logouts,
			tiqn->logout_stats.abnormal_logouts);
	}
	spin_unlock(&iscsi_global->tiqn_lock);

	return(0);
}

static int logout_stats_seq_open(struct inode *inode, struct file *file)
{
	return single_open(file, logout_stats_seq_show, NULL);
}

static struct file_operations logout_stats_seq_fops = {
	.owner	 = THIS_MODULE,
	.open	 = logout_stats_seq_open,
	.read	 = seq_read,
	.llseek	 = seq_lseek,
	.release = single_release,
};

/*
 * Target Authorization Attributes Table
 * A list of initiator identities that are authorized to access this Target
 *
 * Iterates through all active TPGs and extracts the info from the ACLs
 */

int do_tgt_auth_check(void *p)
{
	iscsi_portal_group_t *tpg = (iscsi_portal_group_t *)p;

	return(tpg->num_node_acls);
}

static void *tgt_auth_seq_start(struct seq_file *seq, loff_t *pos)
{
	return(locate_tpg_start(seq, pos, &do_tgt_auth_check));
}

static void *tgt_auth_seq_next(struct seq_file *seq, void *v, loff_t *pos)
{
	return(locate_tpg_next(seq, v, pos, &do_tgt_auth_check));
}

static void tgt_auth_seq_stop(struct seq_file *seq, void *v)
{
	locate_tpg_stop(seq, v);
}

static int tgt_auth_seq_show(struct seq_file *seq, void *v)
{
	iscsi_portal_group_t *tpg;
	table_iter_t *iterp = (table_iter_t *)v;
	iscsi_node_acl_t *acl;
	iscsi_tiqn_t *tiqn;

	if (iterp->ti_header == 1) {
		seq_puts(seq, "inst node indx intr_name\n");
		iterp->ti_header = 0;
	}
	if (!(tiqn = (iscsi_tiqn_t *)iterp->ti_ptr))
		return(0);
	if (!(tpg = iscsi_get_tpg_from_tpgt(tiqn, iterp->ti_offset, 0)))
		return(0);

	spin_lock_bh(&tpg->acl_node_lock);
	for (acl = tpg->acl_node_head; acl; acl = acl->next) {
		seq_printf(seq,"%u %u %u %s\n",
			   tiqn->tiqn_index, ISCSI_NODE_INDEX, acl->acl_index, 
			   acl->initiatorname[0] ? acl->initiatorname : NONE);
	}
	spin_unlock_bh(&tpg->acl_node_lock);

	/* Release the semaphore */
	iscsi_put_tpg(tpg);

	return(0);
}

static struct seq_operations tgt_auth_seq_ops = {
	.start	= tgt_auth_seq_start,
	.next	= tgt_auth_seq_next,
	.stop	= tgt_auth_seq_stop,
	.show	= tgt_auth_seq_show
};

static int tgt_auth_seq_open(struct inode *inode, struct file *file)
{
	return seq_open(file, &tgt_auth_seq_ops);
}

static struct file_operations tgt_auth_seq_fops = {
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
static int do_sess_check (void *p)
{
        iscsi_portal_group_t *tpg = (iscsi_portal_group_t *)p;

        return(tpg->nsessions);
}

static void *sess_attr_seq_start(struct seq_file *seq, loff_t *pos)
{
	return(locate_tpg_start(seq, pos, &do_sess_check));
}

static void *sess_attr_seq_next(struct seq_file *seq, void *v, loff_t *pos)
{
	return(locate_tpg_next(seq, v, pos, &do_sess_check));
}

static void sess_attr_seq_stop(struct seq_file *seq, void *v)
{
	locate_tpg_stop(seq, v);
}

static int sess_attr_seq_show(struct seq_file *seq, void *v)
{
	iscsi_portal_group_t *tpg;
	iscsi_session_t *sess;
	iscsi_sess_ops_t *sops;
	iscsi_tiqn_t *tiqn;
	table_iter_t *iterp = (table_iter_t *)v;

	if (iterp->ti_header) {
		seq_puts(seq, "inst node indx dir intr_name tgt_name TSIH "
			 "ISID R2T imm_data type out_R2T first_burst "
			 "max_burst conn_num auth_type data_seq_order "
			 "data_pdu_order ERL disc_time\n"); 
		iterp->ti_header = 0;
	}
	if (!(tiqn = (iscsi_tiqn_t *)iterp->ti_ptr))
		return(0);
	if (!(tpg = iscsi_get_tpg_from_tpgt(tiqn, iterp->ti_offset, 0)))
		return(0);

	spin_lock_bh(&tpg->session_lock);
	for (sess = tpg->session_head; sess; sess = sess->next) {
		sops = sess->sess_ops;

		seq_printf(seq, "%u %u %u %s %s %s %u ", 
			   tiqn->tiqn_index, sops->SessionType ?
			   0 : ISCSI_NODE_INDEX, sess->session_index, "Inbound",
			   sops->InitiatorName[0]? sops->InitiatorName:NONE,
			   sops->TargetName[0]? sops->TargetName:NONE,
			   sess->tsih);
		seq_printf(seq, "%02X %02X %02X %02X %02X %02X %s %s %s %u ",
			   sess->isid[0], sess->isid[1], sess->isid[2],
			   sess->isid[3], sess->isid[4], sess->isid[5],
			   sops->InitialR2T? "Yes" :"No",
			   sops->ImmediateData? "Yes":"No",
			   sops->SessionType? "Discovery" : "Normal",
			   sops->MaxOutstandingR2T);
		seq_printf(seq, "%u %u %u %s %s %s %u %u\n",
			   sops->FirstBurstLength, sops->MaxBurstLength,
			   atomic_read(&sess->nconn), 
			   sess->auth_type[0]? sess->auth_type:NONE,
			   sops->DataSequenceInOrder? "Yes":"No",
			   sops->DataPDUInOrder? "Yes":"No",
			   sops->ErrorRecoveryLevel, 
		  	   (u32)(((u32)sess->creation_time - INITIAL_JIFFIES)*100/HZ));

		seq_printf(seq, "intr_alias: %s\n", sops->InitiatorAlias[0]?
			   sops->InitiatorAlias:NONE);
		seq_printf(seq, "tgt_alias: %s\n", sops->TargetAlias[0]?
			   sops->TargetAlias:NONE); 
	}
	spin_unlock_bh(&tpg->session_lock);

	/* Release the semaphore */
	iscsi_put_tpg(tpg);

	return(0);
}

static struct seq_operations sess_attr_seq_ops = {
	.start	= sess_attr_seq_start,
	.next	= sess_attr_seq_next,
	.stop	= sess_attr_seq_stop,
	.show	= sess_attr_seq_show
};

static int sess_attr_seq_open(struct inode *inode, struct file *file)
{
	return seq_open(file, &sess_attr_seq_ops);
}

static struct file_operations sess_attr_seq_fops = {
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
        return(locate_tpg_start(seq, pos, &do_sess_check));
}

static void *sess_stats_seq_next(struct seq_file *seq, void *v, loff_t *pos)
{
        return(locate_tpg_next(seq, v, pos, &do_sess_check));
}

static void sess_stats_seq_stop(struct seq_file *seq, void *v)
{
	locate_tpg_stop(seq, v);
}

static int sess_stats_seq_show(struct seq_file *seq, void *v)
{
	iscsi_portal_group_t *tpg;
	iscsi_session_t *sess;
	iscsi_tiqn_t *tiqn;
	table_iter_t *iterp = (table_iter_t *)v;

	if (iterp->ti_header) {
		seq_puts(seq,
			 "inst node indx cmd_pdus rsp_pdus txdata_octs rxdata_octs\n");
		iterp->ti_header = 0;
	}
	if (!(tiqn = (iscsi_tiqn_t *)iterp->ti_ptr))
		return(0);
	if (!(tpg = iscsi_get_tpg_from_tpgt(tiqn, iterp->ti_offset, 0)))
		return(0);

	spin_lock_bh(&tpg->session_lock);
	for (sess = tpg->session_head; sess; sess = sess->next) {
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
	spin_unlock_bh(&tpg->session_lock);

	iscsi_put_tpg(tpg);

	return(0);
}

static struct seq_operations sess_stats_seq_ops = {
	.start  = sess_stats_seq_start,
	.next   = sess_stats_seq_next,
	.stop   = sess_stats_seq_stop,
	.show   = sess_stats_seq_show
};

static int sess_stats_seq_open(struct inode *inode, struct file *file)
{
	return seq_open(file, &sess_stats_seq_ops);
}

static struct file_operations sess_stats_seq_fops = {
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
        return(locate_tpg_start(seq, pos, &do_sess_check));
}

static void *sess_conn_err_stats_seq_next(struct seq_file *seq, void *v, loff_t *pos)
{
        return(locate_tpg_next(seq, v, pos, &do_sess_check));
}

static void sess_conn_err_stats_seq_stop(struct seq_file *seq, void *v)
{
	locate_tpg_stop(seq, v);
}

static int sess_conn_err_stats_seq_show(struct seq_file *seq, void *v)
{
	iscsi_portal_group_t *tpg;
	iscsi_session_t *sess;
	iscsi_tiqn_t *tiqn;
	table_iter_t *iterp = (table_iter_t *)v;

	if (iterp->ti_header) {
		seq_puts(seq, "inst node indx dgst_errs timeouts\n");
		iterp->ti_header = 0;
	}
	if (!(tiqn = (iscsi_tiqn_t *)iterp->ti_ptr))
		return(0);
	if (!(tpg = iscsi_get_tpg_from_tpgt(tiqn, iterp->ti_offset, 0)))
		return(0);

	spin_lock_bh(&tpg->session_lock);
	for (sess = tpg->session_head; sess; sess = sess->next) {
		spin_lock_bh(&sess->session_stats_lock);
		seq_printf(seq, "%u %u %u %u %u\n", 
			   tiqn->tiqn_index,
			   sess->sess_ops->SessionType ?
			   0 : ISCSI_NODE_INDEX, sess->session_index,
			   sess->conn_digest_errors,
			   sess->conn_timeout_errors);
		spin_unlock_bh(&sess->session_stats_lock);
	}
	spin_unlock_bh(&tpg->session_lock);

	/* Release the semaphore */
	iscsi_put_tpg(tpg);

	return(0);
}

static struct seq_operations sess_conn_err_stats_seq_ops = {
        .start  = sess_conn_err_stats_seq_start,
        .next   = sess_conn_err_stats_seq_next,
        .stop   = sess_conn_err_stats_seq_stop,
        .show   = sess_conn_err_stats_seq_show
};

static int sess_conn_err_stats_seq_open(struct inode *inode, struct file *file)
{
	return seq_open(file, &sess_conn_err_stats_seq_ops);
}

static struct file_operations sess_conn_err_stats_seq_fops = {
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
	return(locate_tpg_start(seq, pos, &do_sess_check));
}

static void *conn_attr_seq_next(struct seq_file *seq, void *v, loff_t *pos)
{
	return(locate_tpg_next(seq, v, pos, &do_sess_check));
}

static void conn_attr_seq_stop(struct seq_file *seq, void *v)
{
	locate_tpg_stop(seq, v);
}

static int conn_attr_seq_show(struct seq_file *seq, void *v)
{
	iscsi_portal_group_t *tpg;
	iscsi_session_t *sess;
	iscsi_tiqn_t *tiqn;
	iscsi_conn_t *conn;
	iscsi_conn_ops_t *conn_ops;
	table_iter_t *iterp = (table_iter_t *)v;
	char state_str[16]; 
	char proto_str[16]; 

	if (iterp->ti_header == 1) {
		seq_puts(seq, "inst node ssn indx cid state addr_type "
			 "local_ip proto local_port rem_ip rem_port "
		         "max_rcv_data  max_xmit_data hdr_dgst data_dgst "
			 "rcv_mark send_mark vers_active\n"); 
		iterp->ti_header = 0;	
	}
	if (!(tiqn = (iscsi_tiqn_t *)iterp->ti_ptr))
		return(0);
	if (!(tpg = iscsi_get_tpg_from_tpgt(tiqn, iterp->ti_offset, 0)))
		return(0);

	spin_lock_bh(&tpg->session_lock);
	for (sess = tpg->session_head; sess; sess = sess->next) {

		spin_lock(&sess->conn_lock);
		for (conn = sess->conn_head; conn; conn = conn->next) {
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

#warning FIXME: IPV6
#warning FIXME: Remote IP and Port is broken
			seq_printf(seq, "%u %u %u %u %u %s %s %08X %s %u "
				   "%08X %u ",
				   tiqn->tiqn_index,
				   SESS_OPS(sess)->SessionType?
				   0:ISCSI_NODE_INDEX, sess->session_index,
				   conn->conn_index, conn->cid,
				   state_str, "ipv4", conn->local_ip,
				   proto_str, conn->local_port, conn->login_ip,
				   conn->local_port);

			seq_printf(seq, "%u %u %s %s %s %s %u\n",
				   conn_ops->MaxRecvDataSegmentLength,
				   conn_ops->MaxRecvDataSegmentLength,
				   conn_ops->HeaderDigest? "CRC32C":"None",
				   conn_ops->DataDigest? "CRC32C":"None",
				   conn_ops->OFMarker? "Yes":"No",
				   conn_ops->IFMarker? "Yes":"No",
				   ISCSI_MAX_VERSION);
		}
		spin_unlock(&sess->conn_lock);
	}
	spin_unlock_bh(&tpg->session_lock);

	iscsi_put_tpg(tpg);

	return(0);
}

static struct seq_operations conn_attr_seq_ops = {
	.start	= conn_attr_seq_start,
	.next	= conn_attr_seq_next,
	.stop	= conn_attr_seq_stop,
	.show	= conn_attr_seq_show
};

static int conn_attr_seq_open(struct inode *inode, struct file *file)
{
	return seq_open(file, &conn_attr_seq_ops);
}

static struct file_operations conn_attr_seq_fops = {
	.owner	 = THIS_MODULE,
	.open	 = conn_attr_seq_open,
	.read	 = seq_read,
	.llseek	 = seq_lseek,
	.release = seq_release,
};

/****************************************************************************
 * SCSI MIB Tables
 ****************************************************************************/

/*
 * SCSI Instance Table
 */
static int scsi_inst_seq_show(struct seq_file *seq, void *v)
{
	iscsi_hba_t *hba;
	int i;

	seq_puts(seq, "inst sw_indx\n");

	spin_lock(&iscsi_global->hba_lock);
	for (i = 0; i < ISCSI_MAX_GLOBAL_HBAS; i++) {
		hba = &iscsi_global->hba_list[i];

		if (!(hba->hba_status & HBA_STATUS_ACTIVE))
			continue;

		if (!hba->transport)
			continue;

		seq_printf(seq, "%u %u\n", hba->hba_index, SCSI_INST_SW_INDEX);
		seq_printf(seq, "plugin: %s version: %s\n", hba->transport->name,
				PYX_ISCSI_VERSION);
	}
	spin_unlock(&iscsi_global->hba_lock);

	return(0);
}

static int scsi_inst_seq_open(struct inode *inode, struct file *file)
{
	return single_open(file, scsi_inst_seq_show, NULL);
}

static struct file_operations scsi_inst_seq_fops = {
	.owner	 = THIS_MODULE,
	.open	 = scsi_inst_seq_open,
	.read	 = seq_read,
	.llseek	 = seq_lseek,
	.release = single_release,
};

static void *locate_hba_start(
	struct seq_file *seq,
	loff_t *pos,
	int (*do_check)(void *))
{
	iscsi_device_t *dev;
	iscsi_hba_t *hba;
	table_iter_t *tpg_iter;
	loff_t n = *pos;
	int i, header = (n) ? 0 : 1;

	if (!(tpg_iter = kmalloc(sizeof(table_iter_t), GFP_KERNEL))) 
		return(NULL);
	memset(tpg_iter, 0, sizeof(table_iter_t));
//	printk("%s[%d] - Allocated HBA itr: %p\n", current->comm, current->pid, tpg_iter);

	spin_lock(&iscsi_global->hba_lock);
	for (i = 0; i < ISCSI_MAX_GLOBAL_HBAS; i++) {
		hba = &iscsi_global->hba_list[i];

		if (!(hba->hba_status & HBA_STATUS_ACTIVE))
			continue;
		if (do_check((void *)hba) == 0)
			continue;

		spin_lock(&hba->device_lock);
		for (dev = hba->device_head; dev; dev = dev->next) {
			if (n) {
				n--;
				continue;
			}
			
			tpg_iter->count_cur = 0;
			tpg_iter->ti_header = header;
			tpg_iter->ti_ptr = (void *)dev;
			tpg_iter->ti_offset = hba->hba_id;
			tpg_iter->count_max = hba->dev_count;

			atomic_inc(&hba->dev_mib_access_count);
			spin_unlock(&hba->device_lock);
			spin_unlock(&iscsi_global->hba_lock);

			return((void *)tpg_iter);
		}
		spin_unlock(&hba->device_lock);
	}
	spin_unlock(&iscsi_global->hba_lock);

	return(NULL);
}

static void *locate_hba_next(
	struct seq_file *seq,
	void *v,
	loff_t *pos,
	int (*do_check)(void *))
{
	table_iter_t *iterp = (table_iter_t *)v;
	iscsi_device_t *dev = (iscsi_device_t *)iterp->ti_ptr, *dev_next = NULL;
	iscsi_hba_t *hba;
	int i;

	(*pos)++;

	if (iterp->count_cur < iterp->count_max) {
		iterp->count_cur++;

		spin_lock(&SE_HBA(dev)->device_lock);
		if (!(dev_next = (void *)dev->next)) {
			spin_unlock(&SE_HBA(dev)->device_lock);
			goto next_hba;
		}
		iterp->ti_ptr = dev_next;
		spin_unlock(&SE_HBA(dev)->device_lock);

		return(v);
	} else {
next_hba:
		spin_lock(&iscsi_global->hba_lock);
		hba = &iscsi_global->hba_list[iterp->ti_offset];
		atomic_dec(&hba->dev_mib_access_count);
		iterp->ti_ptr = NULL;

		for (i = (iterp->ti_offset + 1); i < ISCSI_MAX_GLOBAL_HBAS; i++) {
			hba = &iscsi_global->hba_list[i];

			if (!(hba->hba_status & HBA_STATUS_ACTIVE))
				continue;
			if (do_check((void *)hba) == 0) 
				continue;
				
			spin_lock(&hba->device_lock);
			for (dev = hba->device_head; dev; dev = dev->next) {

				iterp->count_cur = 0;
				iterp->ti_ptr = (void *)dev;
				iterp->ti_offset = hba->hba_id;
				iterp->count_max = hba->dev_count;

				atomic_inc(&hba->dev_mib_access_count);
				spin_unlock(&hba->device_lock);
				spin_unlock(&iscsi_global->hba_lock);
				return(v);
			}
			spin_unlock(&hba->device_lock);
		}
		spin_unlock(&iscsi_global->hba_lock);
	}

	return(NULL);
}

static void locate_hba_stop(struct seq_file *seq, void *v)
{
	table_iter_t *iterp = (table_iter_t *)v;
	iscsi_device_t *dev = NULL;
	iscsi_hba_t *hba;

	if (!(v))
		return;

	if (iterp && (dev = (iscsi_device_t *)iterp->ti_ptr)) {
		hba = dev->iscsi_hba;
		atomic_dec(&hba->dev_mib_access_count);
	}

//	printk("%s[%d] - Releasing iterp: %p\n", current->comm, current->pid, iterp);
	kfree(iterp);
		
	return;
}

/*
 * SCSI Device Table
 */
int do_hba_check(void *p)
{
	iscsi_hba_t *hba = (iscsi_hba_t *)p;

	return(hba->dev_count);
}


static void *scsi_dev_seq_start(struct seq_file *seq, loff_t *pos)
{
	return(locate_hba_start(seq, pos, &do_hba_check));
}

static void *scsi_dev_seq_next(struct seq_file *seq, void *v, loff_t *pos)
{
	return(locate_hba_next(seq, v, pos, &do_hba_check));
}

static void scsi_dev_seq_stop(struct seq_file *seq, void *v)
{
	locate_hba_stop(seq, v);
}

static int scsi_dev_seq_show(struct seq_file *seq, void *v)
{
	iscsi_hba_t *hba;
	iscsi_device_t *dev;
	table_iter_t *iterp = (table_iter_t *)v;
	int k;

	if (iterp->ti_header) {
		seq_puts(seq, "inst indx role ports\n");
		iterp->ti_header = 0;
	}

	if (!(hba = core_get_hba_from_id(iterp->ti_offset, 0))) {
		/* Log error ? */
		return(0);
	}

	spin_lock(&hba->device_lock);
	if ((dev = (iscsi_device_t *)iterp->ti_ptr)) {
		char str[28];

		seq_printf(seq, "%u %u %s %u\n", hba->hba_index,
			   dev->dev_index, "Target", dev->dev_port_count);
		
		memcpy(&str[0], (void *)&dev->t10_wwn, 28);

		/* vendor */
		for (k = 0; k < 8; k++)
			str[k] = ISPRINT(dev->t10_wwn.vendor[k]) ?
					dev->t10_wwn.vendor[k]:0x20;
		str[k] = 0x20;

		/* model */
		for (k = 0; k < 16; k++)
			str[k+9] = ISPRINT(dev->t10_wwn.model[k]) ?
					dev->t10_wwn.model[k]:0x20;
		str[k + 9] = 0;

		seq_printf(seq, "dev_alias: %s\n", str);
	}
	spin_unlock(&hba->device_lock);

	/* Release the semaphore */
	core_put_hba(hba);

	return(0);
}

static struct seq_operations scsi_dev_seq_ops = {
        .start  = scsi_dev_seq_start,
        .next   = scsi_dev_seq_next,
        .stop   = scsi_dev_seq_stop,
        .show   = scsi_dev_seq_show
};

static int scsi_dev_seq_open(struct inode *inode, struct file *file)
{
	return seq_open(file, &scsi_dev_seq_ops);
}

static struct file_operations scsi_dev_seq_fops = {
	.owner	 = THIS_MODULE,
	.open	 = scsi_dev_seq_open,
	.read	 = seq_read,
	.llseek	 = seq_lseek,
	.release = seq_release,
};

/*
 * SCSI Port Table
 */
static void *scsi_port_seq_start(struct seq_file *seq, loff_t *pos)
{
        return(locate_hba_start(seq, pos, &do_hba_check));
}

static void *scsi_port_seq_next(struct seq_file *seq, void *v, loff_t *pos)
{
        return(locate_hba_next(seq, v, pos, &do_hba_check));
}

static void scsi_port_seq_stop(struct seq_file *seq, void *v)
{
	locate_hba_stop(seq, v);
}

static int scsi_port_seq_show(struct seq_file *seq, void *v)
{
	iscsi_hba_t *hba;
	iscsi_device_t *dev;
	se_port_t *sep;
	table_iter_t *iterp = (table_iter_t *)v;

	if (iterp->ti_header) {
		seq_puts(seq, "inst device indx role busy_count\n");
		iterp->ti_header = 0;
	}

	if (!(hba = core_get_hba_from_id(iterp->ti_offset, 0))) {
		/* Log error ? */
		return(0);
	}

	/* FIXME: scsiPortBusyStatuses count */
	spin_lock(&hba->device_lock);
	if ((dev = (iscsi_device_t *)iterp->ti_ptr)) {
		spin_lock(&dev->se_port_lock);
		list_for_each_entry(sep, &dev->dev_sep_list, sep_list) {
			seq_printf(seq, "%u %u %u %s%u %u\n", hba->hba_index,
				dev->dev_index, sep->sep_index, "Device",
				dev->dev_index, 0);
		}
		spin_unlock(&dev->se_port_lock);
	}
	spin_unlock(&hba->device_lock);

	/* Release the semaphore */
	core_put_hba(hba);

	return(0);
}

static struct seq_operations scsi_port_seq_ops = {
        .start  = scsi_port_seq_start,
        .next   = scsi_port_seq_next,
        .stop   = scsi_port_seq_stop,
        .show   = scsi_port_seq_show
};

static int scsi_port_seq_open(struct inode *inode, struct file *file)
{
	return seq_open(file, &scsi_port_seq_ops);
}

static struct file_operations scsi_port_seq_fops = {
	.owner	 = THIS_MODULE,
	.open	 = scsi_port_seq_open,
	.read	 = seq_read,
	.llseek	 = seq_lseek,
	.release = seq_release,
};

/*
 * SCSI Transport Table
 */
static void *scsi_transport_seq_start(struct seq_file *seq, loff_t *pos)
{
        return(locate_hba_start(seq, pos, &do_hba_check));
}

static void *scsi_transport_seq_next(struct seq_file *seq, void *v, loff_t *pos)
{
        return(locate_hba_next(seq, v, pos, &do_hba_check));
}

static void scsi_transport_seq_stop(struct seq_file *seq, void *v)
{
	locate_hba_stop(seq, v);
}

static int scsi_transport_seq_show(struct seq_file *seq, void *v)
{
	iscsi_hba_t *hba;
	iscsi_device_t *dev;
	table_iter_t *iterp = (table_iter_t *)v;
	se_port_t *se;
	t10_wwn_t *wwn;

	if (iterp->ti_header) {
		seq_puts(seq, "inst device indx dev_name\n");
		iterp->ti_header = 0;
	}

	if (!(hba = core_get_hba_from_id(iterp->ti_offset, 0))) {
		/* Log error ? */
		return(0);
	}

	spin_lock(&hba->device_lock);
	if ((dev = (iscsi_device_t *)iterp->ti_ptr)) {
		wwn = &dev->t10_wwn;

		spin_lock(&dev->se_port_lock);
		list_for_each_entry(se, &dev->dev_sep_list, sep_list) {
			seq_printf(seq, "%u %s %u %s+%s\n",
				hba->hba_index, /* scsiTransportIndex */
				"scsiTransportISCSI",  /* scsiTransportType */
				se->sep_tpg->tpg_tiqn->tiqn_index, /* scsiTransportPointer */
				se->sep_tpg->tpg_tiqn->tiqn,
				(strlen(wwn->unit_serial)) ?
				wwn->unit_serial : wwn->vendor);	 /* scsiTransportDevName */
		}
		spin_unlock(&dev->se_port_lock);
	}
	spin_unlock(&hba->device_lock);

	/* Release the semaphore */
	core_put_hba(hba);

	return(0);
}

static struct seq_operations scsi_transport_seq_ops = {
        .start  = scsi_transport_seq_start,
        .next   = scsi_transport_seq_next,
        .stop   = scsi_transport_seq_stop,
        .show   = scsi_transport_seq_show
};

static int scsi_transport_seq_open(struct inode *inode, struct file *file)
{
	return seq_open(file, &scsi_transport_seq_ops);
}

static struct file_operations scsi_transport_seq_fops = {
	.owner	 = THIS_MODULE,
	.open	 = scsi_transport_seq_open,
	.read	 = seq_read,
	.llseek	 = seq_lseek,
	.release = seq_release,
};

/*
 * SCSI Target Device Table
 */
static void *scsi_tgt_dev_seq_start(struct seq_file *seq, loff_t *pos)
{
        return(locate_hba_start(seq, pos, &do_hba_check));
}

static void *scsi_tgt_dev_seq_next(struct seq_file *seq, void *v, loff_t *pos)
{
        return(locate_hba_next(seq, v, pos, &do_hba_check));
}

static void scsi_tgt_dev_seq_stop(struct seq_file *seq, void *v)
{
	locate_hba_stop(seq, v);
}


#define LU_COUNT	1  /* for now */
static int scsi_tgt_dev_seq_show(struct seq_file *seq, void *v)
{
	iscsi_hba_t *hba;
	iscsi_device_t *dev;
	table_iter_t *iterp = (table_iter_t *)v;
	int non_accessible_lus = 0;
	char status[16];

	if (iterp->ti_header) {
		seq_puts(seq, "inst indx num_LUs status non_access_LUs resets\n");
		iterp->ti_header = 0;
	}

	if (!(hba = core_get_hba_from_id(iterp->ti_offset, 0))) {
		/* Log error ? */
		return(0);
	}

	spin_lock(&hba->device_lock);
	if ((dev = (iscsi_device_t *)iterp->ti_ptr)) {
		switch (dev->dev_status) {
		case ISCSI_DEVICE_ACTIVATED:
			strcpy(status, "activated");
			break;
		case ISCSI_DEVICE_DEACTIVATED:
			strcpy(status, "deactivated");
			non_accessible_lus = 1;
			break;
		case ISCSI_DEVICE_SHUTDOWN:
			strcpy(status, "shutdown");
			non_accessible_lus = 1;
			break;
		case ISCSI_DEVICE_OFFLINE_ACTIVATED:
		case ISCSI_DEVICE_OFFLINE_DEACTIVATED:
			strcpy(status, "offline");
			non_accessible_lus = 1;
			break;
		default:
			sprintf(status, "unknown(%d)", dev->dev_status);
			non_accessible_lus = 1;
		}
				
		seq_printf(seq, "%u %u %u %s %u %u\n",
			   hba->hba_index, dev->dev_index, LU_COUNT,
			   status, non_accessible_lus, 0);
	}
	spin_unlock(&hba->device_lock);

	/* Release the semaphore */
	core_put_hba(hba);

	return(0);
}

static struct seq_operations scsi_tgt_dev_seq_ops = {
        .start  = scsi_tgt_dev_seq_start,
        .next   = scsi_tgt_dev_seq_next,
        .stop   = scsi_tgt_dev_seq_stop,
        .show   = scsi_tgt_dev_seq_show
};

static int scsi_tgt_dev_seq_open(struct inode *inode, struct file *file)
{
	return seq_open(file, &scsi_tgt_dev_seq_ops);
}

static struct file_operations scsi_tgt_dev_seq_fops = {
	.owner	 = THIS_MODULE,
	.open	 = scsi_tgt_dev_seq_open,
	.read	 = seq_read,
	.llseek	 = seq_lseek,
	.release = seq_release,
};

/*
 * SCSI Target Port Table
 */	
static void *scsi_tgt_port_seq_start(struct seq_file *seq, loff_t *pos)
{
        return(locate_hba_start(seq, pos, &do_hba_check));
}

static void *scsi_tgt_port_seq_next(struct seq_file *seq, void *v, loff_t *pos)
{
        return(locate_hba_next(seq, v, pos, &do_hba_check));
}

static void scsi_tgt_port_seq_stop(struct seq_file *seq, void *v)
{
	locate_hba_stop(seq, v);
}

static int scsi_tgt_port_seq_show(struct seq_file *seq, void *v)
{
	iscsi_hba_t *hba;
	iscsi_device_t *dev;
	se_port_t *sep;
	table_iter_t *iterp = (table_iter_t *)v;
	u32 rx_mbytes, tx_mbytes;
	unsigned long long num_cmds;

	if (iterp->ti_header) {
		seq_puts(seq, "inst device indx name port_index in_cmds write_mbytes"
				" read_mbytes hs_in_cmds\n");
		iterp->ti_header = 0;
	}

	if (!(hba = core_get_hba_from_id(iterp->ti_offset, 0))) {
		/* Log error ? */
		return(0);
	}

	spin_lock(&hba->device_lock);
	if ((dev = (iscsi_device_t *)iterp->ti_ptr)) {
		spin_lock(&dev->se_port_lock);
		list_for_each_entry(sep, &dev->dev_sep_list, sep_list) {
			seq_printf(seq, "%u %u %u %s%d %s%s%d ", 
			     hba->hba_index,
			     dev->dev_index,
			     sep->sep_index,
			     "iSCSIPort#", sep->sep_index, 
			     sep->sep_tpg->tpg_tiqn->tiqn, "+t+", sep->sep_tpg->tpgt);

			spin_lock(&sep->sep_lun->lun_sep_lock);
			num_cmds = sep->sep_stats.cmd_pdus;
			rx_mbytes = (sep->sep_stats.rx_data_octets >> 20);
			tx_mbytes = (sep->sep_stats.tx_data_octets >> 20);
			spin_unlock(&sep->sep_lun->lun_sep_lock);

			seq_printf(seq, "%llu %u %u %u\n", num_cmds, rx_mbytes, tx_mbytes, 0);
		}
		spin_unlock(&dev->se_port_lock);
	}
	spin_unlock(&hba->device_lock);

	/* Release the semaphore */
	core_put_hba(hba);

	return(0);
}

static struct seq_operations scsi_tgt_port_seq_ops = {
        .start  = scsi_tgt_port_seq_start,
        .next   = scsi_tgt_port_seq_next,
        .stop   = scsi_tgt_port_seq_stop,
        .show   = scsi_tgt_port_seq_show
};

static int scsi_tgt_port_seq_open(struct inode *inode, struct file *file)
{
	return seq_open(file, &scsi_tgt_port_seq_ops);
}

static struct file_operations scsi_tgt_port_seq_fops = {
	.owner	 = THIS_MODULE,
	.open	 = scsi_tgt_port_seq_open,
	.read	 = seq_read,
	.llseek	 = seq_lseek,
	.release = seq_release,
};

/*
 * SCSI Authorized Initiator Table:
 * It contains the SCSI Initiators authorized to be attached to one of the
 * local Target ports.
 * Iterates through all active TPGs and extracts the info from the ACLs
 */
static void *scsi_auth_intr_seq_start(struct seq_file *seq, loff_t *pos)
{
	return(locate_tpg_start(seq, pos, &do_portal_check));
}

static void *scsi_auth_intr_seq_next(struct seq_file *seq, void *v,
					 loff_t *pos)
{
	return(locate_tpg_next(seq, v, pos, &do_portal_check));
}

static void scsi_auth_intr_seq_stop(struct seq_file *seq, void *v)
{
	/* Nothing to be done */
}

static int scsi_auth_intr_seq_show(struct seq_file *seq, void *v)
{
	iscsi_portal_group_t *tpg;
	table_iter_t *iterp = (table_iter_t *)v;
	iscsi_node_acl_t *acl;
	iscsi_dev_entry_t *deve;
	iscsi_lun_t *lun;
	iscsi_tiqn_t *tiqn;
	int j; 

	if (iterp->ti_header) {
		seq_puts(seq, "inst dev port indx dev_or_port intr_name "
			 "map_indx att_count num_cmds read_mbytes "
			 "write_mbytes hs_num_cmds creation_time row_status\n");
		iterp->ti_header = 0;
	}
	if (!(tiqn = (iscsi_tiqn_t *)iterp->ti_ptr))
		return(0);
	if (!(tpg = iscsi_get_tpg_from_tpgt(tiqn, iterp->ti_offset, 0)))
		return(0);

	spin_lock_bh(&tpg->acl_node_lock);
	for (acl = tpg->acl_node_head; acl; acl = acl->next) {
		spin_lock_bh(&acl->device_list_lock);
		for (j = 0; j < ISCSI_MAX_LUNS_PER_TPG; j++) {
			deve = &acl->device_list[j];
			if (!(deve->lun_flags & ISCSI_LUNFLAGS_INITIATOR_ACCESS)
			    || (!deve->iscsi_lun))
				continue;

			lun = deve->iscsi_lun;
			if ((lun->lun_type != ISCSI_LUN_TYPE_DEVICE) ||
			    (!lun->iscsi_dev))
				continue;

			seq_printf(seq,"%u %u %u %u %u %s %u %u %u %u %u %u %u %s\n",
				   tiqn->tiqn_index, /* scsiInstIndex */
				   lun->iscsi_dev->dev_index, /* scsiDeviceIndex */
				   tpg->tpgt, /* scsiAuthIntrTgtPortIndex */
				   acl->acl_index, /* scsiAuthIntrIndex */
				   1, /* scsiAuthIntrDevOrPort */
				   acl->initiatorname[0]?
					  acl->initiatorname:NONE, /* scsiAuthIntrName */
				   0, /* FIXME: scsiAuthIntrLunMapIndex */
				   deve->attach_count,  /* scsiAuthIntrAttachedTimes */
				   deve->total_cmds, /* scsiAuthIntrOutCommands */
				   (u32)(deve->read_bytes >> 20),  /* scsiAuthIntrReadMegaBytes */
				   (u32)(deve->write_bytes >> 20), /* scsiAuthIntrWrittenMegaBytes */
				   0, /* FIXME: scsiAuthIntrHSOutCommands */
				   (u32)(((u32)deve->creation_time - INITIAL_JIFFIES)*100/HZ), /* scsiAuthIntrLastCreation */
				   "Ready"); /* FIXME: scsiAuthIntrRowStatus */
				
		}
		spin_unlock_bh(&acl->device_list_lock);
	}
	spin_unlock_bh(&tpg->acl_node_lock);

	/* Release the semaphore */
	iscsi_put_tpg(tpg);

	return(0);
}

static struct seq_operations scsi_auth_intr_seq_ops = {
	.start	= scsi_auth_intr_seq_start,
	.next	= scsi_auth_intr_seq_next,
	.stop	= scsi_auth_intr_seq_stop,
	.show	= scsi_auth_intr_seq_show
};

static int scsi_auth_intr_seq_open(struct inode *inode, struct file *file)
{
	return seq_open(file, &scsi_auth_intr_seq_ops);
}

static struct file_operations scsi_auth_intr_seq_fops = {
	.owner	 = THIS_MODULE,
	.open	 = scsi_auth_intr_seq_open,
	.read	 = seq_read,
	.llseek	 = seq_lseek,
	.release = seq_release,
};

/*
 * SCSI Attached Initiator Port Table:
 * It lists the SCSI Initiators attached to one of the local Target ports.
 * Iterates through all active TPGs and use active sessions from each TPG 
 * to list the info fo this table.
 */
static void *scsi_att_intr_port_seq_start(struct seq_file *seq, loff_t *pos)
{
	return(locate_tpg_start(seq, pos, &do_portal_check));
}

static void *scsi_att_intr_port_seq_next(struct seq_file *seq, void *v,
					 loff_t *pos)
{
	return(locate_tpg_next(seq, v, pos, &do_portal_check));
}

static void scsi_att_intr_port_seq_stop(struct seq_file *seq, void *v)
{
	/* Nothing to be done */
}

static int scsi_att_intr_port_seq_show(struct seq_file *seq, void *v)
{
	iscsi_portal_group_t *tpg;
	iscsi_session_t *sess;
	iscsi_sess_ops_t *sops;
	table_iter_t *iterp = (table_iter_t *)v;
	iscsi_dev_entry_t *deve;
	iscsi_lun_t *lun;
	iscsi_tiqn_t *tiqn = (iscsi_tiqn_t *)iterp->ti_ptr;
	int j;

	if (iterp->ti_header) {
		seq_puts(seq, "inst dev port indx port_auth_indx port_name port_ident\n");
		iterp->ti_header = 0;
	}

	if (!(tpg = iscsi_get_tpg_from_tpgt(tiqn, iterp->ti_offset, 0)))
		return(0);

	spin_lock_bh(&tpg->session_lock);
	for (sess = tpg->session_head; sess; sess = sess->next) {
		sops = sess->sess_ops;
		if ((sess->session_state != TARG_SESS_STATE_LOGGED_IN) ||
		    (!sess->node_acl) || (!sess->node_acl->device_list)) {
			continue;
		}

		spin_lock_bh(&sess->node_acl->device_list_lock);
		for (j = 0; j < ISCSI_MAX_LUNS_PER_TPG; j++) {
			deve = &sess->node_acl->device_list[j];
			if (!(deve->lun_flags & ISCSI_LUNFLAGS_INITIATOR_ACCESS)
			    || (!deve->iscsi_lun))
				continue;

			lun = deve->iscsi_lun;
			if ((lun->lun_type != ISCSI_LUN_TYPE_DEVICE) ||
			    (!lun->iscsi_dev))
				continue;

			seq_printf(seq,"%u %u %u %u %u "
				   "%s+i+%02X%02X%02X%02X%02X%02X\n",
				   tiqn->tiqn_index, /* scsiInstIndex */
				   lun->iscsi_dev->dev_index, /* scsiDeviceIndex */
				   tpg->tpgt, /* scsiPortIndex */
				   sess->session_index,  /* scsiAttIntrPortIndex */
				   sess->node_acl->acl_index, /* scsiAttIntrPortAuthIntrIdx */
				   sops->InitiatorName[0]?
					  sops->InitiatorName:NONE, /* scsiAttIntrPortName */
				   sess->isid[0], sess->isid[1], sess->isid[2],
				   sess->isid[3], sess->isid[4], sess->isid[5]);
			   					/* scsiAttIntrPortIdentifier */
		}
		spin_unlock_bh(&sess->node_acl->device_list_lock);
	}
	spin_unlock_bh(&tpg->session_lock);

	/* Release the semaphore */
	iscsi_put_tpg(tpg);

	return(0);
}

static struct seq_operations scsi_att_intr_port_seq_ops = {
	.start	= scsi_att_intr_port_seq_start,
	.next	= scsi_att_intr_port_seq_next,
	.stop	= scsi_att_intr_port_seq_stop,
	.show	= scsi_att_intr_port_seq_show
};

static int scsi_att_intr_port_seq_open(struct inode *inode, struct file *file)
{
	return seq_open(file, &scsi_att_intr_port_seq_ops);
}

static struct file_operations scsi_att_intr_port_seq_fops = {
	.owner	 = THIS_MODULE,
	.open	 = scsi_att_intr_port_seq_open,
	.read	 = seq_read,
	.llseek	 = seq_lseek,
	.release = seq_release,
};

static void *scsi_lu_seq_start(struct seq_file *seq, loff_t *pos)
{
        return(locate_hba_start(seq, pos, &do_hba_check));
}

static void *scsi_lu_seq_next(struct seq_file *seq, void *v, loff_t *pos)
{
        return(locate_hba_next(seq, v, pos, &do_hba_check));
}

static void scsi_lu_seq_stop(struct seq_file *seq, void *v)
{
	locate_hba_stop(seq, v);
}

/*
 * SCSI Logical Unit Table
 */
#define SCSI_LU_INDEX		1
static int scsi_lu_seq_show(struct seq_file *seq, void *v)
{
	iscsi_hba_t *hba;
	iscsi_device_t *dev;
	table_iter_t *iterp = (table_iter_t *)v;
	int j;
	char str[28];

	if (iterp->ti_header) {
		seq_puts(seq, "inst dev indx LUN lu_name vend prod rev"
		" dev_type status state-bit num_cmds read_mbytes"
		" write_mbytes rests full_stat hs_num_cmds creation_time\n");
		iterp->ti_header = 0;
	}

	if (!(hba = core_get_hba_from_id(iterp->ti_offset, 0))) {
		/* Log error ? */
		return(0);
	}
	
	spin_lock(&hba->device_lock);
	if ((dev = (iscsi_device_t *)iterp->ti_ptr)) {
		/* Fix LU state, if we can read it from the device */
#warning FIXME: Get scsiLuDefaultLun from transport plugins
		seq_printf(seq, "%u %u %u %llu %s", hba->hba_index,
                                dev->dev_index, SCSI_LU_INDEX,
				(unsigned long long)0, /* scsiLuDefaultLun */
				(strlen(dev->t10_wwn.unit_serial)) ?
				(char *)&dev->t10_wwn.unit_serial[0] : NONE); /* scsiLuWwnName */

		memcpy(&str[0], (void *)&dev->t10_wwn, 28);

		/* scsiLuVendorId */
		for (j = 0; j < 8; j++)
                        str[j] = ISPRINT(dev->t10_wwn.vendor[j]) ?
                                dev->t10_wwn.vendor[j]:0x20;
                str[8] = 0;
                seq_printf(seq, " %s", str);

		/* scsiLuProductId */
		for (j = 0; j < 16; j++)
			str[j] = ISPRINT(dev->t10_wwn.model[j]) ?
		               dev->t10_wwn.model[j]:0x20;
		str[16] = 0;
                seq_printf(seq, " %s", str);

		/* scsiLuRevisionId */
		for (j = 0; j < 4; j++)
                         str[j] = ISPRINT(dev->t10_wwn.revision[j]) ?
	                       dev->t10_wwn.revision[j]:0x20;
	        str[4] = 0;
	        seq_printf(seq, " %s", str);

		seq_printf(seq," %u %s %s %llu %u %u %u %u %u %u\n",
			   dev->dev_obj_api->get_device_type((void *)dev), /* scsiLuPeripheralType */
			   (dev->dev_status == ISCSI_DEVICE_ACTIVATED)?
			   	"available":"notavailable", /* scsiLuStatus */
			   "exposed", 	/* scsiLuState */
			   (unsigned long long)dev->num_cmds,
			   (u32)(dev->read_bytes >> 20),  /* scsiLuReadMegaBytes */
			   (u32)(dev->write_bytes >> 20), /* scsiLuWrittenMegaBytes */
			   0, /* scsiLuInResets */
			   0, /* scsiLuOutTaskSetFullStatus */
			   0, /* scsiLuHSInCommands */
			   (u32)(((u32)dev->creation_time - INITIAL_JIFFIES)*100/HZ));
	}
	spin_unlock(&hba->device_lock);

	/* Release the semaphore */
	core_put_hba(hba);

	return(0);
}

static struct seq_operations scsi_lu_seq_ops = {
        .start  = scsi_lu_seq_start,
        .next   = scsi_lu_seq_next,
        .stop   = scsi_lu_seq_stop,
        .show   = scsi_lu_seq_show
};

static int scsi_lu_seq_open(struct inode *inode, struct file *file)
{
	return seq_open(file, &scsi_lu_seq_ops);
}

static struct file_operations scsi_lu_seq_fops = {
	.owner	 = THIS_MODULE,
	.open	 = scsi_lu_seq_open,
	.read	 = seq_read,
	.llseek	 = seq_lseek,
	.release = seq_release,
};

/*
 * Used for IPS Authentication MIB table construction
 */
static void *ips_auth_seq_start(struct seq_file *seq, loff_t *pos)
{
        return(locate_tpg_start(seq, pos, &do_portal_check));
}

static void *ips_auth_seq_next(struct seq_file *seq, void *v, loff_t *pos)
{
        return(locate_tpg_next(seq, v, pos, &do_portal_check));
}

static void ips_auth_seq_stop(struct seq_file *seq, void *v)
{
        /* Nothing to be done */
}

/*
 * Note: This currently shows the storage object nexus authorization required status,
 */
#warning FIXME: ips_auth_seq_show()
static int ips_auth_seq_show(struct seq_file *seq, void *v)
{
	iscsi_portal_group_t *tpg;
	table_iter_t *iterp = (table_iter_t *)v;
	iscsi_tiqn_t *tiqn = (iscsi_tiqn_t *)iterp->ti_ptr;

	if (iterp->ti_header) {
		seq_puts(seq, "name tpgt enforce_auth\n");
		iterp->ti_header = 0;
	}

	if (!(tpg = iscsi_get_tpg_from_tpgt(tiqn, iterp->ti_offset, 0)))
		return(0);

	seq_printf(seq, "%s%s%u %u\n", tiqn->tiqn, "+", tpg->tpgt,
		ISCSI_TPG_ATTRIB(tpg)->authentication);

	/* Release the semaphore */
	iscsi_put_tpg(tpg);

	return(0);
}

static struct seq_operations ips_auth_seq_ops = {
        .start  = ips_auth_seq_start,
        .next   = ips_auth_seq_next,
        .stop   = ips_auth_seq_stop,
        .show   = ips_auth_seq_show
};

static int ips_auth_seq_open(struct inode *inode, struct file *file)
{
	return seq_open(file, &ips_auth_seq_ops);
}

static struct file_operations ips_auth_seq_fops = {
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
	remove_proc_entry("iscsi_target/mib/scsi_inst", NULL);
	remove_proc_entry("iscsi_target/mib/scsi_dev", NULL);
	remove_proc_entry("iscsi_target/mib/scsi_port", NULL);
	remove_proc_entry("iscsi_target/mib/scsi_transport", NULL);
	remove_proc_entry("iscsi_target/mib/scsi_tgt_dev", NULL);
	remove_proc_entry("iscsi_target/mib/scsi_tgt_port", NULL);
	remove_proc_entry("iscsi_target/mib/scsi_auth_intr", NULL);
	remove_proc_entry("iscsi_target/mib/scsi_att_intr_port", NULL);
	remove_proc_entry("iscsi_target/mib/scsi_lu", NULL);
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
	struct proc_dir_entry *scsi_inst_entry;
	struct proc_dir_entry *scsi_dev_entry;
	struct proc_dir_entry *scsi_port_entry;
	struct proc_dir_entry *scsi_transport_entry;
	struct proc_dir_entry *scsi_tgt_dev_entry;
	struct proc_dir_entry *scsi_tgt_port_entry;
	struct proc_dir_entry *scsi_auth_intr_entry;
	struct proc_dir_entry *scsi_att_intr_port_entry;
	struct proc_dir_entry *scsi_lu_entry;
	struct proc_dir_entry *ips_auth_entry;

	if (!(dir_entry = proc_mkdir("iscsi_target/mib", NULL))) {
		printk("proc_mkdir() failed.\n");
		return(-1);
        }

	inst_attr_entry = 
		create_proc_entry("iscsi_target/mib/inst_attr", 0, NULL);
	if (inst_attr_entry) {
		inst_attr_entry->proc_fops = &inst_attr_seq_fops;
	}
	else {
		goto error;
	}

	sess_err_stats_entry = 
		create_proc_entry("iscsi_target/mib/sess_err_stats", 0, NULL);
	if (sess_err_stats_entry) {
		sess_err_stats_entry->proc_fops = &sess_err_stats_seq_fops;
	}
	else {
		goto error;
	}

	portal_attr_entry = 
		create_proc_entry("iscsi_target/mib/portal_attr", 0, NULL);
	if (portal_attr_entry) {
		portal_attr_entry->proc_fops = &portal_attr_seq_fops;
	}
	else {
		goto error;
	}

	tgt_portal_attr_entry = 
		create_proc_entry("iscsi_target/mib/tgt_portal_attr", 0, NULL);
	if (tgt_portal_attr_entry) {
		tgt_portal_attr_entry->proc_fops = &tgt_portal_attr_seq_fops;
	}
	else {
		goto error;
	}

	node_attr_entry = 
		create_proc_entry("iscsi_target/mib/node_attr", 0, NULL);
	if (node_attr_entry) {
		node_attr_entry->proc_fops = &node_attr_seq_fops;
	}
	else {
		goto error;
	}

	tgt_attr_entry = 
		create_proc_entry("iscsi_target/mib/tgt_attr", 0, NULL);
	if (tgt_attr_entry) {
		tgt_attr_entry->proc_fops = &tgt_attr_seq_fops;
	}
	else {
		goto error;
	}

	login_stats_entry = 
		create_proc_entry("iscsi_target/mib/login_stats", 0, NULL);
	if (login_stats_entry) {
		login_stats_entry->proc_fops = &login_stats_seq_fops;
	}
	else {
		goto error;
	}

	logout_stats_entry = 
		create_proc_entry("iscsi_target/mib/logout_stats", 0, NULL);
	if (logout_stats_entry) {
		logout_stats_entry->proc_fops = &logout_stats_seq_fops;
	}
	else {
		goto error;
	}

	tgt_auth_entry = create_proc_entry("iscsi_target/mib/tgt_auth", 0,NULL);
	if (tgt_auth_entry) {
		tgt_auth_entry->proc_fops = &tgt_auth_seq_fops;
	}
	else {
		goto error;
	}

	sess_attr_entry = 
		create_proc_entry("iscsi_target/mib/sess_attr", 0, NULL);
	if (sess_attr_entry) {
		sess_attr_entry->proc_fops = &sess_attr_seq_fops;
	}
	else {
		goto error;
	}

	sess_stats_entry = 
		create_proc_entry("iscsi_target/mib/sess_stats", 0, NULL);
	if (sess_stats_entry) {
		sess_stats_entry->proc_fops = &sess_stats_seq_fops;
	}
	else {
		goto error;
	}

	sess_conn_err_stats_entry = 
	    create_proc_entry("iscsi_target/mib/sess_conn_err_stats", 0, NULL);
	if (sess_conn_err_stats_entry) {
		sess_conn_err_stats_entry->proc_fops = 
						&sess_conn_err_stats_seq_fops;
	}
	else {
		goto error;
	}

	conn_attr_entry = 
		create_proc_entry("iscsi_target/mib/conn_attr", 0, NULL);
	if (conn_attr_entry) {
		conn_attr_entry->proc_fops = &conn_attr_seq_fops;
	}
	else {
		goto error;
	}

	scsi_inst_entry = 
		create_proc_entry("iscsi_target/mib/scsi_inst", 0, NULL);
	if (scsi_inst_entry) {
		scsi_inst_entry->proc_fops = &scsi_inst_seq_fops;
	}
	else {
		goto error;
	}

	scsi_dev_entry = 
		create_proc_entry("iscsi_target/mib/scsi_dev", 0, NULL);
	if (scsi_dev_entry) {
		scsi_dev_entry->proc_fops = &scsi_dev_seq_fops;
	}
	else {
		goto error;
	}

	scsi_port_entry = 
		create_proc_entry("iscsi_target/mib/scsi_port", 0, NULL);
	if (scsi_port_entry) {
		scsi_port_entry->proc_fops = &scsi_port_seq_fops;
	}
	else {
		goto error;
	}

	scsi_transport_entry = 
		create_proc_entry("iscsi_target/mib/scsi_transport", 0, NULL);
	if (scsi_transport_entry) {
		scsi_transport_entry->proc_fops = &scsi_transport_seq_fops;
	}
	else {
		goto error;
	}

	scsi_tgt_dev_entry = 
		create_proc_entry("iscsi_target/mib/scsi_tgt_dev", 0, NULL);
	if (scsi_tgt_dev_entry) {
		scsi_tgt_dev_entry->proc_fops = &scsi_tgt_dev_seq_fops;
	}
	else {
		goto error;
	}

	scsi_tgt_port_entry = 
		create_proc_entry("iscsi_target/mib/scsi_tgt_port", 0, NULL);
	if (scsi_tgt_port_entry) {
		scsi_tgt_port_entry->proc_fops = &scsi_tgt_port_seq_fops;
	}
	else {
		goto error;
	}

	scsi_auth_intr_entry = 
		create_proc_entry("iscsi_target/mib/scsi_auth_intr", 0, NULL);
	if (scsi_auth_intr_entry) {
		scsi_auth_intr_entry->proc_fops = &scsi_auth_intr_seq_fops;
	}
	else {
		goto error;
	}

	scsi_att_intr_port_entry = 
	      create_proc_entry("iscsi_target/mib/scsi_att_intr_port", 0, NULL);
	if (scsi_att_intr_port_entry) {
		scsi_att_intr_port_entry->proc_fops = 
						&scsi_att_intr_port_seq_fops;
	}
	else {
		goto error;
	}

	scsi_lu_entry = create_proc_entry("iscsi_target/mib/scsi_lu", 0, NULL);
	if (scsi_lu_entry) {
		scsi_lu_entry->proc_fops = &scsi_lu_seq_fops;
	}
	else {
		goto error;
	}

	ips_auth_entry = create_proc_entry("iscsi_target/mib/ips_auth", 0,NULL);
	if (ips_auth_entry) {
		ips_auth_entry->proc_fops = &ips_auth_seq_fops;
	}
	else {
		goto error;
	}

	return(0);

error:
	printk("create_proc_entry() failed.\n");
	remove_iscsi_target_mib();
	return(-1);
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
u32 get_new_index(iscsi_index_t type)
{
	u32 new_index;

	if ((type < 0) || (type >= INDEX_TYPE_MAX)) {
		printk("Invalid index type %d\n", type);
		return(-1);
	}

	spin_lock(&iscsi_index_table.lock);
	new_index = ++iscsi_index_table.iscsi_mib_index[type];
	if (new_index == 0)
		new_index = ++iscsi_index_table.iscsi_mib_index[type];
	spin_unlock(&iscsi_index_table.lock);

	return(new_index);
}
