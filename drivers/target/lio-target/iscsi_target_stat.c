/*******************************************************************************
 * Copyright (c) 2011 Rising Tide Systems
 *
 * Modern ConfigFS group context specific iSCSI statistics based on original
 * iscsi_target_mib.c code
 *
 * Copyright (c) 2006-2007 SBE, Inc.  All Rights Reserved.
 *
 * Nicholas A. Bellinger <nab@risingtidesystems.com>
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
#include <linux/configfs.h>
#include <scsi/scsi.h>
#include <scsi/scsi_device.h>
#include <scsi/scsi_host.h>
#include <scsi/iscsi_proto.h>

#include <target/target_core_base.h>
#include <target/target_core_transport.h>
#include <target/configfs_macros.h>
#include <iscsi_target_core.h>
#include <iscsi_target_device.h>
#include <iscsi_target_tpg.h>
#include <iscsi_target_util.h>
#include <iscsi_target_stat.h>

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

/****************************************************************************
 * iSCSI MIB Tables
 ****************************************************************************/
/*
 * Instance Attributes Table
 */
CONFIGFS_EATTR_STRUCT(iscsi_stat_instance, iscsi_wwn_stat_grps);
#define ISCSI_STAT_INSTANCE_ATTR(_name, _mode)			\
static struct iscsi_stat_instance_attribute			\
			iscsi_stat_instance_##_name =		\
	__CONFIGFS_EATTR(_name, _mode,				\
	iscsi_stat_instance_show_attr_##_name,			\
	iscsi_stat_instance_store_attr_##_name);

#define ISCSI_STAT_INSTANCE_ATTR_RO(_name)			\
static struct iscsi_stat_instance_attribute			\
			iscsi_stat_instance_##_name =		\
	__CONFIGFS_EATTR_RO(_name,				\
	iscsi_stat_instance_show_attr_##_name);

static ssize_t iscsi_stat_instance_show_attr_inst(
	struct iscsi_wwn_stat_grps *igrps, char *page)
{
	struct iscsi_tiqn *tiqn = container_of(igrps,
				struct iscsi_tiqn, tiqn_stat_grps);
	
	return snprintf(page, PAGE_SIZE, "%u\n", tiqn->tiqn_index);
}
ISCSI_STAT_INSTANCE_ATTR_RO(inst);

static ssize_t iscsi_stat_instance_show_attr_min_ver(
	struct iscsi_wwn_stat_grps *igrps, char *page)
{
	return snprintf(page, PAGE_SIZE, "%u\n", ISCSI_DRAFT20_VERSION);
}
ISCSI_STAT_INSTANCE_ATTR_RO(min_ver);

static ssize_t iscsi_stat_instance_show_attr_max_ver(
	struct iscsi_wwn_stat_grps *igrps, char *page)
{
	return snprintf(page, PAGE_SIZE, "%u\n", ISCSI_DRAFT20_VERSION);
}
ISCSI_STAT_INSTANCE_ATTR_RO(max_ver);

static ssize_t iscsi_stat_instance_show_attr_portals(
	struct iscsi_wwn_stat_grps *igrps, char *page)
{
	struct iscsi_tiqn *tiqn = container_of(igrps,
				struct iscsi_tiqn, tiqn_stat_grps);

	return snprintf(page, PAGE_SIZE, "%u\n", tiqn->tiqn_num_tpg_nps);
}
ISCSI_STAT_INSTANCE_ATTR_RO(portals);

static ssize_t iscsi_stat_instance_show_attr_nodes(
	struct iscsi_wwn_stat_grps *igrps, char *page)
{
	return snprintf(page, PAGE_SIZE, "%u\n", ISCSI_INST_NUM_NODES);
}
ISCSI_STAT_INSTANCE_ATTR_RO(nodes);

static ssize_t iscsi_stat_instance_show_attr_sessions(
	struct iscsi_wwn_stat_grps *igrps, char *page)
{
	struct iscsi_tiqn *tiqn = container_of(igrps,
				struct iscsi_tiqn, tiqn_stat_grps);

	return snprintf(page, PAGE_SIZE, "%u\n", tiqn->tiqn_nsessions);
}
ISCSI_STAT_INSTANCE_ATTR_RO(sessions);

static ssize_t iscsi_stat_instance_show_attr_fail_sess(
	struct iscsi_wwn_stat_grps *igrps, char *page)
{
	struct iscsi_tiqn *tiqn = container_of(igrps,
				struct iscsi_tiqn, tiqn_stat_grps);
	struct iscsi_sess_err_stats *sess_err = &tiqn->sess_err_stats;
	u32 sess_err_count;

	spin_lock_bh(&sess_err->lock);
	sess_err_count = (sess_err->digest_errors +
			  sess_err->cxn_timeout_errors +
			  sess_err->pdu_format_errors);
	spin_unlock_bh(&sess_err->lock);

	return snprintf(page, PAGE_SIZE, "%u\n", sess_err_count);
}
ISCSI_STAT_INSTANCE_ATTR_RO(fail_sess);

static ssize_t iscsi_stat_instance_show_attr_fail_type(
	struct iscsi_wwn_stat_grps *igrps, char *page)
{
	struct iscsi_tiqn *tiqn = container_of(igrps,
				struct iscsi_tiqn, tiqn_stat_grps);
	struct iscsi_sess_err_stats *sess_err = &tiqn->sess_err_stats;

	return snprintf(page, PAGE_SIZE, "%u\n",
			sess_err->last_sess_failure_type);
}
ISCSI_STAT_INSTANCE_ATTR_RO(fail_type);

static ssize_t iscsi_stat_instance_show_attr_fail_rem_name(
	struct iscsi_wwn_stat_grps *igrps, char *page)
{
	struct iscsi_tiqn *tiqn = container_of(igrps,
				struct iscsi_tiqn, tiqn_stat_grps);
	struct iscsi_sess_err_stats *sess_err = &tiqn->sess_err_stats;

	return snprintf(page, PAGE_SIZE, "%s\n",
			sess_err->last_sess_fail_rem_name[0] ?
			sess_err->last_sess_fail_rem_name : NONE);
}
ISCSI_STAT_INSTANCE_ATTR_RO(fail_rem_name);

static ssize_t iscsi_stat_instance_show_attr_disc_time(
	struct iscsi_wwn_stat_grps *igrps, char *page)
{
	return snprintf(page, PAGE_SIZE, "%u\n", ISCSI_DISCONTINUITY_TIME);
}
ISCSI_STAT_INSTANCE_ATTR_RO(disc_time);

static ssize_t iscsi_stat_instance_show_attr_description(
	struct iscsi_wwn_stat_grps *igrps, char *page)
{
	return snprintf(page, PAGE_SIZE, "%s\n", ISCSI_INST_DESCR);
}
ISCSI_STAT_INSTANCE_ATTR_RO(description);

static ssize_t iscsi_stat_instance_show_attr_vendor(
	struct iscsi_wwn_stat_grps *igrps, char *page)
{
	return snprintf(page, PAGE_SIZE, "%s\n", ISCSI_VENDOR);
}
ISCSI_STAT_INSTANCE_ATTR_RO(vendor);

static ssize_t iscsi_stat_instance_show_attr_version(
	struct iscsi_wwn_stat_grps *igrps, char *page)
{
	return snprintf(page, PAGE_SIZE, "%s on %s/%s\n", PYX_ISCSI_VERSION,
			utsname()->sysname, utsname()->machine);
}
ISCSI_STAT_INSTANCE_ATTR_RO(version);

CONFIGFS_EATTR_OPS(iscsi_stat_instance, iscsi_wwn_stat_grps,
		iscsi_instance_group);

static struct configfs_attribute *iscsi_stat_instance_attrs[] = {
	&iscsi_stat_instance_inst.attr,
	&iscsi_stat_instance_min_ver.attr,
	&iscsi_stat_instance_max_ver.attr,
	&iscsi_stat_instance_portals.attr,
	&iscsi_stat_instance_nodes.attr,
	&iscsi_stat_instance_sessions.attr,
	&iscsi_stat_instance_fail_sess.attr,
	&iscsi_stat_instance_fail_type.attr,
	&iscsi_stat_instance_fail_rem_name.attr,
	&iscsi_stat_instance_disc_time.attr,
	&iscsi_stat_instance_description.attr,
	&iscsi_stat_instance_vendor.attr,
	&iscsi_stat_instance_version.attr,
	NULL,
};

static struct configfs_item_operations iscsi_stat_instance_item_ops = {
	.show_attribute		= iscsi_stat_instance_attr_show,
	.store_attribute	= iscsi_stat_instance_attr_store,
};

struct config_item_type iscsi_stat_instance_cit = {
	.ct_item_ops		= &iscsi_stat_instance_item_ops,
	.ct_attrs		= iscsi_stat_instance_attrs,
	.ct_owner		= THIS_MODULE,
};
