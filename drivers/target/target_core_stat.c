/*******************************************************************************
 * Filename:  target_core_stat.c
 *
 * Copyright (c) 2011 Rising Tide Systems
 * Copyright (c) 2011 Linux-iSCSI.org
 *
 * Modern ConfigFS group context specific statistics based on original
 * target_core_mib.c code
 *
 * Copyright (c) 2006-2007 SBE, Inc.  All Rights Reserved.
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
#include <linux/configfs.h>
#include <scsi/scsi.h>
#include <scsi/scsi_device.h>
#include <scsi/scsi_host.h>

#include <target/target_core_base.h>
#include <target/target_core_transport.h>
#include <target/target_core_fabric_ops.h>
#include <target/target_core_configfs.h>
#include <target/configfs_macros.h>

#include "target_core_hba.h"
#include "target_core_mib.h"

#ifndef INITIAL_JIFFIES
#define INITIAL_JIFFIES ((unsigned long)(unsigned int) (-300*HZ))
#endif

#define NONE		"None"
#define ISPRINT(a)   ((a >= ' ') && (a <= '~'))

#define SCSI_LU_INDEX			1
#define LU_COUNT			1

/*
 * SCSI Device Table
 */

CONFIGFS_EATTR_STRUCT(target_stat_scsi_dev, se_dev_stat_grps);
#define DEV_STAT_SCSI_DEV_ATTR(_name, _mode)				\
static struct target_stat_scsi_dev_attribute				\
			target_stat_scsi_dev_##_name =			\
	__CONFIGFS_EATTR(_name, _mode,					\
	target_stat_scsi_dev_show_attr_##_name,				\
	target_stat_scsi_dev_store_attr_##_name);

#define DEV_STAT_SCSI_DEV_ATTR_RO(_name)				\
static struct target_stat_scsi_dev_attribute				\
			target_stat_scsi_dev_##_name =			\
	__CONFIGFS_EATTR_RO(_name,					\
	target_stat_scsi_dev_show_attr_##_name);

static ssize_t target_stat_scsi_dev_show_attr_inst(
	struct se_dev_stat_grps *sgrps, char *page)
{
	struct se_subsystem_dev *se_subdev = container_of(sgrps,
			struct se_subsystem_dev, dev_stat_grps);
	struct se_hba *hba = se_subdev->se_dev_hba;
	struct se_device *dev = se_subdev->se_dev_ptr;

	if (!dev)
		return -ENODEV;

	return snprintf(page, PAGE_SIZE, "%u\n", hba->hba_index);
}
DEV_STAT_SCSI_DEV_ATTR_RO(inst);

static ssize_t target_stat_scsi_dev_show_attr_indx(
	struct se_dev_stat_grps *sgrps, char *page)
{
	struct se_subsystem_dev *se_subdev = container_of(sgrps,
			struct se_subsystem_dev, dev_stat_grps);
	struct se_device *dev = se_subdev->se_dev_ptr;

	if (!dev)
		return -ENODEV;

	return snprintf(page, PAGE_SIZE, "%u\n", dev->dev_index);
}
DEV_STAT_SCSI_DEV_ATTR_RO(indx);

static ssize_t target_stat_scsi_dev_show_attr_role(
	struct se_dev_stat_grps *sgrps, char *page)
{
	struct se_subsystem_dev *se_subdev = container_of(sgrps,
			struct se_subsystem_dev, dev_stat_grps);
	struct se_device *dev = se_subdev->se_dev_ptr;

	if (!dev)
		return -ENODEV;

	return snprintf(page, PAGE_SIZE, "Target\n");
}
DEV_STAT_SCSI_DEV_ATTR_RO(role);

static ssize_t target_stat_scsi_dev_show_attr_ports(
	struct se_dev_stat_grps *sgrps, char *page)
{
	struct se_subsystem_dev *se_subdev = container_of(sgrps,
			struct se_subsystem_dev, dev_stat_grps);
	struct se_device *dev = se_subdev->se_dev_ptr;

	if (!dev)
		return -ENODEV;

	return snprintf(page, PAGE_SIZE, "%u\n", dev->dev_port_count);
}
DEV_STAT_SCSI_DEV_ATTR_RO(ports);

CONFIGFS_EATTR_OPS(target_stat_scsi_dev, se_dev_stat_grps, scsi_dev_group);

static struct configfs_attribute *target_stat_scsi_dev_attrs[] = {
	&target_stat_scsi_dev_inst.attr,
	&target_stat_scsi_dev_indx.attr,
	&target_stat_scsi_dev_role.attr,
	&target_stat_scsi_dev_ports.attr,
	NULL,
};

static struct configfs_item_operations target_stat_scsi_dev_attrib_ops = {
	.show_attribute		= target_stat_scsi_dev_attr_show,
	.store_attribute	= target_stat_scsi_dev_attr_store,
};

static struct config_item_type target_stat_scsi_dev_cit = {
	.ct_item_ops		= &target_stat_scsi_dev_attrib_ops,
	.ct_attrs		= target_stat_scsi_dev_attrs,
	.ct_owner		= THIS_MODULE,
};

/*
 * SCSI Target Device Table
 */

CONFIGFS_EATTR_STRUCT(target_stat_scsi_tgt_dev, se_dev_stat_grps);
#define DEV_STAT_SCSI_TGT_DEV_ATTR(_name, _mode)			\
static struct target_stat_scsi_tgt_dev_attribute			\
			target_stat_scsi_tgt_dev_##_name =		\
	__CONFIGFS_EATTR(_name, _mode,					\
	target_stat_scsi_tgt_dev_show_attr_##_name,			\
	target_stat_scsi_tgt_dev_store_attr_##_name);

#define DEV_STAT_SCSI_TGT_DEV_ATTR_RO(_name)				\
static struct target_stat_scsi_tgt_dev_attribute			\
			target_stat_scsi_tgt_dev_##_name =		\
	__CONFIGFS_EATTR_RO(_name,					\
	target_stat_scsi_tgt_dev_show_attr_##_name);

static ssize_t target_stat_scsi_tgt_dev_show_attr_inst(
	struct se_dev_stat_grps *sgrps, char *page)
{
	struct se_subsystem_dev *se_subdev = container_of(sgrps,
			struct se_subsystem_dev, dev_stat_grps);
	struct se_hba *hba = se_subdev->se_dev_hba;
	struct se_device *dev = se_subdev->se_dev_ptr;

	if (!dev)
		return -ENODEV;

	return snprintf(page, PAGE_SIZE, "%u\n", hba->hba_index);
}
DEV_STAT_SCSI_TGT_DEV_ATTR_RO(inst);

static ssize_t target_stat_scsi_tgt_dev_show_attr_indx(
	struct se_dev_stat_grps *sgrps, char *page)
{
	struct se_subsystem_dev *se_subdev = container_of(sgrps,
			struct se_subsystem_dev, dev_stat_grps);
	struct se_device *dev = se_subdev->se_dev_ptr;

	if (!dev)
		return -ENODEV;

	return snprintf(page, PAGE_SIZE, "%u\n", dev->dev_index);
}
DEV_STAT_SCSI_TGT_DEV_ATTR_RO(indx);

static ssize_t target_stat_scsi_tgt_dev_show_attr_num_lus(
	struct se_dev_stat_grps *sgrps, char *page)
{
	struct se_subsystem_dev *se_subdev = container_of(sgrps,
			struct se_subsystem_dev, dev_stat_grps);
	struct se_device *dev = se_subdev->se_dev_ptr;

	if (!dev)
		return -ENODEV;

	return snprintf(page, PAGE_SIZE, "%u\n", LU_COUNT);
}
DEV_STAT_SCSI_TGT_DEV_ATTR_RO(num_lus);

static ssize_t target_stat_scsi_tgt_dev_show_attr_status(
	struct se_dev_stat_grps *sgrps, char *page)
{
	struct se_subsystem_dev *se_subdev = container_of(sgrps,
			struct se_subsystem_dev, dev_stat_grps);
	struct se_device *dev = se_subdev->se_dev_ptr;
	char status[16];

	if (!dev)
		return -ENODEV;

	switch (dev->dev_status) {
	case TRANSPORT_DEVICE_ACTIVATED:
		strcpy(status, "activated");
		break;
	case TRANSPORT_DEVICE_DEACTIVATED:
		strcpy(status, "deactivated");
		break;
	case TRANSPORT_DEVICE_SHUTDOWN:
		strcpy(status, "shutdown");
		break;
	case TRANSPORT_DEVICE_OFFLINE_ACTIVATED:
	case TRANSPORT_DEVICE_OFFLINE_DEACTIVATED:
		strcpy(status, "offline");
		break;
	default:
		sprintf(status, "unknown(%d)", dev->dev_status);
		break;
	}

	return snprintf(page, PAGE_SIZE, "%s\n", status);
}
DEV_STAT_SCSI_TGT_DEV_ATTR_RO(status);

static ssize_t target_stat_scsi_tgt_dev_show_attr_non_access_lus(
	struct se_dev_stat_grps *sgrps, char *page)
{
	struct se_subsystem_dev *se_subdev = container_of(sgrps,
			struct se_subsystem_dev, dev_stat_grps);
	struct se_device *dev = se_subdev->se_dev_ptr;
	int non_accessible_lus;

	if (!dev)
		return -ENODEV;

	switch (dev->dev_status) {
	case TRANSPORT_DEVICE_ACTIVATED:
		non_accessible_lus = 0;
		break;
	case TRANSPORT_DEVICE_DEACTIVATED:
	case TRANSPORT_DEVICE_SHUTDOWN:
	case TRANSPORT_DEVICE_OFFLINE_ACTIVATED:
	case TRANSPORT_DEVICE_OFFLINE_DEACTIVATED:
	default:
		non_accessible_lus = 1;
		break;
	}

	return snprintf(page, PAGE_SIZE, "%u\n", non_accessible_lus);
}
DEV_STAT_SCSI_TGT_DEV_ATTR_RO(non_access_lus);

static ssize_t target_stat_scsi_tgt_dev_show_attr_resets(
	struct se_dev_stat_grps *sgrps, char *page)
{
	struct se_subsystem_dev *se_subdev = container_of(sgrps,
			struct se_subsystem_dev, dev_stat_grps);
	struct se_device *dev = se_subdev->se_dev_ptr;
	
	if (!dev)
		return -ENODEV;

	return snprintf(page, PAGE_SIZE, "%u\n", dev->num_resets);
}
DEV_STAT_SCSI_TGT_DEV_ATTR_RO(resets);
	

CONFIGFS_EATTR_OPS(target_stat_scsi_tgt_dev, se_dev_stat_grps, scsi_tgt_dev_group);

static struct configfs_attribute *target_stat_scsi_tgt_dev_attrs[] = {
	&target_stat_scsi_tgt_dev_inst.attr,
	&target_stat_scsi_tgt_dev_indx.attr,
	&target_stat_scsi_tgt_dev_num_lus.attr,
	&target_stat_scsi_tgt_dev_status.attr,
	&target_stat_scsi_tgt_dev_non_access_lus.attr,
	&target_stat_scsi_tgt_dev_resets.attr,
	NULL,
};

static struct configfs_item_operations target_stat_scsi_tgt_dev_attrib_ops = {
	.show_attribute		= target_stat_scsi_tgt_dev_attr_show,
	.store_attribute	= target_stat_scsi_tgt_dev_attr_store,
};

static struct config_item_type target_stat_scsi_tgt_dev_cit = {
	.ct_item_ops		= &target_stat_scsi_tgt_dev_attrib_ops,
	.ct_attrs		= target_stat_scsi_tgt_dev_attrs,
	.ct_owner		= THIS_MODULE,
};

/*
 * SCSI Logical Unit Table
 */

CONFIGFS_EATTR_STRUCT(target_stat_scsi_lu, se_dev_stat_grps);
#define DEV_STAT_SCSI_LU_ATTR(_name, _mode)				\
static struct target_stat_scsi_lu_attribute target_stat_scsi_lu_##_name = \
	__CONFIGFS_EATTR(_name, _mode,					\
	target_stat_scsi_lu_show_attr_##_name,				\
	target_stat_scsi_lu_store_attr_##_name);

#define DEV_STAT_SCSI_LU_ATTR_RO(_name)					\
static struct target_stat_scsi_lu_attribute target_stat_scsi_lu_##_name = \
	__CONFIGFS_EATTR_RO(_name,					\
	target_stat_scsi_lu_show_attr_##_name);

static ssize_t target_stat_scsi_lu_show_attr_inst(
	struct se_dev_stat_grps *sgrps, char *page)
{
	struct se_subsystem_dev *se_subdev = container_of(sgrps,
			struct se_subsystem_dev, dev_stat_grps);
	struct se_hba *hba = se_subdev->se_dev_hba;
	struct se_device *dev = se_subdev->se_dev_ptr;

	if (!dev)
		return -ENODEV;

	return snprintf(page, PAGE_SIZE, "%u\n", hba->hba_index);
}
DEV_STAT_SCSI_LU_ATTR_RO(inst);

static ssize_t target_stat_scsi_lu_show_attr_dev(
	struct se_dev_stat_grps *sgrps, char *page)
{
	struct se_subsystem_dev *se_subdev = container_of(sgrps,
			struct se_subsystem_dev, dev_stat_grps);
	struct se_device *dev = se_subdev->se_dev_ptr;

	if (!dev)
		return -ENODEV;

	return snprintf(page, PAGE_SIZE, "%u\n", dev->dev_index);
}
DEV_STAT_SCSI_LU_ATTR_RO(dev);

static ssize_t target_stat_scsi_lu_show_attr_indx(
	struct se_dev_stat_grps *sgrps, char *page)
{
	struct se_subsystem_dev *se_subdev = container_of(sgrps,
			struct se_subsystem_dev, dev_stat_grps);
	struct se_device *dev = se_subdev->se_dev_ptr;

	if (!dev)
		return -ENODEV;

	return snprintf(page, PAGE_SIZE, "%u\n", SCSI_LU_INDEX);
}
DEV_STAT_SCSI_LU_ATTR_RO(indx);

static ssize_t target_stat_scsi_lu_show_attr_lun(
	struct se_dev_stat_grps *sgrps, char *page)
{
	struct se_subsystem_dev *se_subdev = container_of(sgrps,
			struct se_subsystem_dev, dev_stat_grps);
	struct se_device *dev = se_subdev->se_dev_ptr;

	if (!dev)
		return -ENODEV;
	/* FIXME: scsiLuDefaultLun */
	return snprintf(page, PAGE_SIZE, "%llu\n", (unsigned long long)0);
}
DEV_STAT_SCSI_LU_ATTR_RO(lun);

static ssize_t target_stat_scsi_lu_show_attr_lu_name(
	struct se_dev_stat_grps *sgrps, char *page)
{
	struct se_subsystem_dev *se_subdev = container_of(sgrps,
			struct se_subsystem_dev, dev_stat_grps);
	struct se_device *dev = se_subdev->se_dev_ptr;

	if (!dev)
		return -ENODEV;
	/* scsiLuWwnName */
	return snprintf(page, PAGE_SIZE, "%s\n",
			(strlen(DEV_T10_WWN(dev)->unit_serial)) ?
			(char *)&DEV_T10_WWN(dev)->unit_serial[0] : "None");
}
DEV_STAT_SCSI_LU_ATTR_RO(lu_name);

static ssize_t target_stat_scsi_lu_show_attr_vend(
	struct se_dev_stat_grps *sgrps, char *page)
{
	struct se_subsystem_dev *se_subdev = container_of(sgrps,
			struct se_subsystem_dev, dev_stat_grps);
	struct se_device *dev = se_subdev->se_dev_ptr;
	int j;
	char str[28];

	if (!dev)
		return -ENODEV;
	/* scsiLuVendorId */
	memcpy(&str[0], (void *)DEV_T10_WWN(dev), 28);
	for (j = 0; j < 8; j++)
		str[j] = ISPRINT(DEV_T10_WWN(dev)->vendor[j]) ?
				DEV_T10_WWN(dev)->vendor[j] : 0x20;
	str[8] = 0;
	return snprintf(page, PAGE_SIZE, "%s\n", str);
}	
DEV_STAT_SCSI_LU_ATTR_RO(vend);

static ssize_t target_stat_scsi_lu_show_attr_prod(
	struct se_dev_stat_grps *sgrps, char *page)
{
	struct se_subsystem_dev *se_subdev = container_of(sgrps,
			struct se_subsystem_dev, dev_stat_grps);
	struct se_device *dev = se_subdev->se_dev_ptr;
	int j;
	char str[28];

	if (!dev)
		return -ENODEV;

	/* scsiLuProductId */
	memcpy(&str[0], (void *)DEV_T10_WWN(dev), 28);
	for (j = 0; j < 16; j++)
		str[j] = ISPRINT(DEV_T10_WWN(dev)->model[j]) ?
				DEV_T10_WWN(dev)->model[j] : 0x20;
	str[16] = 0;
	return snprintf(page, PAGE_SIZE, "%s\n", str);
}
DEV_STAT_SCSI_LU_ATTR_RO(prod);

static ssize_t target_stat_scsi_lu_show_attr_rev(
	struct se_dev_stat_grps *sgrps, char *page)
{
	struct se_subsystem_dev *se_subdev = container_of(sgrps,
			struct se_subsystem_dev, dev_stat_grps);
	struct se_device *dev = se_subdev->se_dev_ptr;
	int j;
	char str[28];

	if (!dev)
		return -ENODEV;

	/* scsiLuRevisionId */
	memcpy(&str[0], (void *)DEV_T10_WWN(dev), 28);
	for (j = 0; j < 4; j++)
		str[j] = ISPRINT(DEV_T10_WWN(dev)->revision[j]) ?
				DEV_T10_WWN(dev)->revision[j] : 0x20;
	str[4] = 0;
	return snprintf(page, PAGE_SIZE, "%s\n", str);
}
DEV_STAT_SCSI_LU_ATTR_RO(rev);

static ssize_t target_stat_scsi_lu_show_attr_dev_type(
	struct se_dev_stat_grps *sgrps, char *page)
{
	struct se_subsystem_dev *se_subdev = container_of(sgrps,
			struct se_subsystem_dev, dev_stat_grps);
	struct se_device *dev = se_subdev->se_dev_ptr;

	if (!dev)
		return -ENODEV;

	/* scsiLuPeripheralType */
	return snprintf(page, PAGE_SIZE, "%u\n",
			TRANSPORT(dev)->get_device_type(dev));
}
DEV_STAT_SCSI_LU_ATTR_RO(dev_type);

static ssize_t target_stat_scsi_lu_show_attr_status(
	struct se_dev_stat_grps *sgrps, char *page)
{
	struct se_subsystem_dev *se_subdev = container_of(sgrps,
			struct se_subsystem_dev, dev_stat_grps);
	struct se_device *dev = se_subdev->se_dev_ptr;

	if (!dev)
		return -ENODEV;

	/* scsiLuStatus */
	return snprintf(page, PAGE_SIZE, "%s\n",
		(dev->dev_status == TRANSPORT_DEVICE_ACTIVATED) ?
		"available" : "notavailable");
}
DEV_STAT_SCSI_LU_ATTR_RO(status);

static ssize_t target_stat_scsi_lu_show_attr_state_bit(
	struct se_dev_stat_grps *sgrps, char *page)
{
	struct se_subsystem_dev *se_subdev = container_of(sgrps,
			struct se_subsystem_dev, dev_stat_grps);
	struct se_device *dev = se_subdev->se_dev_ptr;

	if (!dev)
		return -ENODEV;

	/* scsiLuState */
	return snprintf(page, PAGE_SIZE, "exposed\n");
}
DEV_STAT_SCSI_LU_ATTR_RO(state_bit);

static ssize_t target_stat_scsi_lu_show_attr_num_cmds(
	struct se_dev_stat_grps *sgrps, char *page)
{
	struct se_subsystem_dev *se_subdev = container_of(sgrps,
			struct se_subsystem_dev, dev_stat_grps);
	struct se_device *dev = se_subdev->se_dev_ptr;

	if (!dev)
		return -ENODEV;

	/* scsiLuNumCommands */
	return snprintf(page, PAGE_SIZE, "%llu\n",
			(unsigned long long)dev->num_cmds);
}
DEV_STAT_SCSI_LU_ATTR_RO(num_cmds);

static ssize_t target_stat_scsi_lu_show_attr_read_mbytes(
	struct se_dev_stat_grps *sgrps, char *page)
{
	struct se_subsystem_dev *se_subdev = container_of(sgrps,
			struct se_subsystem_dev, dev_stat_grps);
	struct se_device *dev = se_subdev->se_dev_ptr;

	if (!dev)
		return -ENODEV;

	/* scsiLuReadMegaBytes */
	return snprintf(page, PAGE_SIZE, "%u\n", (u32)(dev->read_bytes >> 20));
}
DEV_STAT_SCSI_LU_ATTR_RO(read_mbytes);

static ssize_t target_stat_scsi_lu_show_attr_write_mbytes(
	struct se_dev_stat_grps *sgrps, char *page)
{
	struct se_subsystem_dev *se_subdev = container_of(sgrps,
			struct se_subsystem_dev, dev_stat_grps);
	struct se_device *dev = se_subdev->se_dev_ptr;

	if (!dev)
		return -ENODEV;

	/* scsiLuWrittenMegaBytes */
	return snprintf(page, PAGE_SIZE, "%u\n", (u32)(dev->write_bytes >> 20));
}
DEV_STAT_SCSI_LU_ATTR_RO(write_mbytes);

static ssize_t target_stat_scsi_lu_show_attr_resets(
	struct se_dev_stat_grps *sgrps, char *page)
{
	struct se_subsystem_dev *se_subdev = container_of(sgrps,
			struct se_subsystem_dev, dev_stat_grps);
	struct se_device *dev = se_subdev->se_dev_ptr;

	if (!dev)
		return -ENODEV;

	/* scsiLuInResets */
	return snprintf(page, PAGE_SIZE, "%u\n", dev->num_resets);
}
DEV_STAT_SCSI_LU_ATTR_RO(resets);

static ssize_t target_stat_scsi_lu_show_attr_full_stat(
	struct se_dev_stat_grps *sgrps, char *page)
{
	struct se_subsystem_dev *se_subdev = container_of(sgrps,
			struct se_subsystem_dev, dev_stat_grps);
	struct se_device *dev = se_subdev->se_dev_ptr;

	if (!dev)
		return -ENODEV;

	/* FIXME: scsiLuOutTaskSetFullStatus */
	return snprintf(page, PAGE_SIZE, "%u\n", 0);
}
DEV_STAT_SCSI_LU_ATTR_RO(full_stat);

static ssize_t target_stat_scsi_lu_show_attr_hs_num_cmds(
	struct se_dev_stat_grps *sgrps, char *page)
{
	struct se_subsystem_dev *se_subdev = container_of(sgrps,
			struct se_subsystem_dev, dev_stat_grps);
	struct se_device *dev = se_subdev->se_dev_ptr;

	if (!dev)
		return -ENODEV;

	/* FIXME: scsiLuHSInCommands */
	return snprintf(page, PAGE_SIZE, "%u\n", 0);
}
DEV_STAT_SCSI_LU_ATTR_RO(hs_num_cmds);

static ssize_t target_stat_scsi_lu_show_attr_creation_time(
	struct se_dev_stat_grps *sgrps, char *page)
{
	struct se_subsystem_dev *se_subdev = container_of(sgrps,
			struct se_subsystem_dev, dev_stat_grps);
	struct se_device *dev = se_subdev->se_dev_ptr;

	if (!dev)
		return -ENODEV;

	/* scsiLuCreationTime */
	return snprintf(page, PAGE_SIZE, "%u\n", (u32)(((u32)dev->creation_time -
				INITIAL_JIFFIES) * 100 / HZ));
}
DEV_STAT_SCSI_LU_ATTR_RO(creation_time);

CONFIGFS_EATTR_OPS(target_stat_scsi_lu, se_dev_stat_grps, scsi_lu_group);

static struct configfs_attribute *target_stat_scsi_lu_attrs[] = {
	&target_stat_scsi_lu_inst.attr,
	&target_stat_scsi_lu_dev.attr,
	&target_stat_scsi_lu_indx.attr,
	&target_stat_scsi_lu_lun.attr,
	&target_stat_scsi_lu_lu_name.attr,
	&target_stat_scsi_lu_vend.attr,
	&target_stat_scsi_lu_prod.attr,
	&target_stat_scsi_lu_rev.attr,
	&target_stat_scsi_lu_dev_type.attr,
	&target_stat_scsi_lu_status.attr,
	&target_stat_scsi_lu_state_bit.attr,
	&target_stat_scsi_lu_num_cmds.attr,
	&target_stat_scsi_lu_read_mbytes.attr,
	&target_stat_scsi_lu_write_mbytes.attr,
	&target_stat_scsi_lu_resets.attr,
	&target_stat_scsi_lu_full_stat.attr,
	&target_stat_scsi_lu_hs_num_cmds.attr,
	&target_stat_scsi_lu_creation_time.attr,
	NULL,
};

static struct configfs_item_operations target_stat_scsi_lu_attrib_ops = {
	.show_attribute		= target_stat_scsi_lu_attr_show,
	.store_attribute	= target_stat_scsi_lu_attr_store,
};

static struct config_item_type target_stat_scsi_lu_cit = {
	.ct_item_ops		= &target_stat_scsi_lu_attrib_ops,
	.ct_attrs		= target_stat_scsi_lu_attrs,
	.ct_owner		= THIS_MODULE,
};

/*
 * Called from target_core_configfs.c:target_core_make_subdev() to setup
 * the target statistics groups + configfs CITs located in target_core_stat.c
 */
void target_stat_setup_dev_default_groups(struct se_subsystem_dev *se_subdev)
{
	struct config_group *dev_stat_grp = &DEV_STAT_GRP(se_subdev)->stat_group;

	config_group_init_type_name(&DEV_STAT_GRP(se_subdev)->scsi_dev_group,
			"scsi_dev", &target_stat_scsi_dev_cit);
	config_group_init_type_name(&DEV_STAT_GRP(se_subdev)->scsi_tgt_dev_group,
			"scsi_tgt_dev", &target_stat_scsi_tgt_dev_cit);
	config_group_init_type_name(&DEV_STAT_GRP(se_subdev)->scsi_lu_group,
			"scsi_lu", &target_stat_scsi_lu_cit);

	dev_stat_grp->default_groups[0] = &DEV_STAT_GRP(se_subdev)->scsi_dev_group;
	dev_stat_grp->default_groups[1] = &DEV_STAT_GRP(se_subdev)->scsi_tgt_dev_group;
	dev_stat_grp->default_groups[2] = &DEV_STAT_GRP(se_subdev)->scsi_lu_group;
	dev_stat_grp->default_groups[3] = NULL;
}
