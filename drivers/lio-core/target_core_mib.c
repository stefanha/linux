/*********************************************************************************
 * Filename:  target_core_mib.c
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
 *********************************************************************************/


#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/delay.h>
#include <linux/timer.h>
#include <linux/string.h>
#include <linux/version.h>
#include <linux/utsrelease.h>
#include <linux/utsname.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/blkdev.h>
#include <scsi/scsi.h>
#include <scsi/scsi_device.h>
#include <scsi/scsi_host.h>

#include "iscsi_protocol.h"
#include <iscsi_debug_opcodes.h>
#include "iscsi_target_core.h"
#include <iscsi_target_error.h>
#include "iscsi_target_device.h"
#include "iscsi_target_ioctl.h"
#include "iscsi_target_hba.h"
#include "iscsi_target_info.h"
#include "iscsi_target_transport.h"
#include "iscsi_target_util.h"

#include "target_core_mib.h"

#include <iscsi_target_plugin.h>
#include <iscsi_target_seobj.h>
#include <iscsi_target_feature_obj.h>

#include <target_core_fabric_ops.h>
#include <target_core_configfs.h>

extern se_global_t *se_global;

/* SCSI mib table index */
scsi_index_table_t scsi_index_table;

#ifndef INITIAL_JIFFIES
#define INITIAL_JIFFIES ((unsigned long)(unsigned int) (-300*HZ))
#endif

/* SCSI Instance Table */
#define SCSI_INST_SW_INDEX		1
#define SCSI_TRANSPORT_INDEX		1

#define ISPRINT(a)   ((a >=' ')&&(a <= '~'))

/* Structure for table row iteration with seq_file */
typedef struct table_iter_s {
	int	ti_skip_body;
	u32	ti_offset;
	void	*ti_ptr;
} table_iter_t;

/****************************************************************************
 * SCSI MIB Tables
 ****************************************************************************/

/*
 * SCSI Instance Table
 */
static int scsi_inst_seq_show(struct seq_file *seq, void *v)
{
	se_hba_t *hba;
	int i;

	seq_puts(seq, "inst sw_indx\n");

	spin_lock(&se_global->hba_lock);
	for (i = 0; i < ISCSI_MAX_GLOBAL_HBAS; i++) {
		hba = &se_global->hba_list[i];

		if (!(hba->hba_status & HBA_STATUS_ACTIVE))
			continue;

		if (!hba->transport)
			continue;

		seq_printf(seq, "%u %u\n", hba->hba_index, SCSI_INST_SW_INDEX);
		seq_printf(seq, "plugin: %s version: %s\n", hba->transport->name,
				PYX_ISCSI_VERSION);
	}
	spin_unlock(&se_global->hba_lock);

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
	se_device_t *dev;
	se_hba_t *hba;
	table_iter_t *tpg_iter;
	int i;

	if (*pos != 0)
		return(NULL);

	if (!(tpg_iter = kmalloc(sizeof(table_iter_t), GFP_KERNEL))) 
		return(NULL);
	memset(tpg_iter, 0, sizeof(table_iter_t));
#if 0
	printk("%s[%d] - Allocating iterp: %p\n", current->comm, current->pid, tpg_iter);
#endif
	seq->private = (void *)tpg_iter;

	spin_lock(&se_global->hba_lock);
	for (i = 0; i < ISCSI_MAX_GLOBAL_HBAS; i++) {
		hba = &se_global->hba_list[i];

		if (!(hba->hba_status & HBA_STATUS_ACTIVE))
			continue;
		if (do_check((void *)hba) == 0)
			continue;

		spin_lock(&hba->device_lock);
		for (dev = hba->device_head; dev; dev = dev->next) {
			tpg_iter->ti_ptr = (void *)dev;
			tpg_iter->ti_offset = hba->hba_id;
			atomic_inc(&hba->dev_mib_access_count);
#if 0
			printk("[%d]: Incremented dev_mib_access_count: %d\n",
				hba->hba_id, atomic_read(&hba->dev_mib_access_count));
#endif
			spin_unlock(&hba->device_lock);
			spin_unlock(&se_global->hba_lock);
			return(SEQ_START_TOKEN);
		}
		spin_unlock(&hba->device_lock);
	}
	spin_unlock(&se_global->hba_lock);

	return(SEQ_START_TOKEN);
}

static void *locate_hba_next(
	struct seq_file *seq,
	void *v,
	loff_t *pos,
	int (*do_check)(void *))
{
	table_iter_t *iterp = (table_iter_t *)seq->private;
	se_device_t *dev, *dev_next = NULL;
	se_hba_t *hba;
	int i;

	(*pos)++;

	if (!(iterp) || !(dev = (se_device_t *)iterp->ti_ptr))
		return(NULL);

	spin_lock(&SE_HBA(dev)->device_lock);
	if ((dev_next = (void *)dev->next)) {
		iterp->ti_ptr = dev_next;
		spin_unlock(&SE_HBA(dev)->device_lock);
		return((void *)iterp);
	}
	spin_unlock(&SE_HBA(dev)->device_lock);

	spin_lock(&se_global->hba_lock);
	hba = &se_global->hba_list[iterp->ti_offset];
	atomic_dec(&hba->dev_mib_access_count);
	iterp->ti_ptr = NULL;

	for (i = (iterp->ti_offset + 1); i < ISCSI_MAX_GLOBAL_HBAS; i++) {
		hba = &se_global->hba_list[i];

		if (!(hba->hba_status & HBA_STATUS_ACTIVE))
			continue;
		if (do_check((void *)hba) == 0) 
			continue;
			
		spin_lock(&hba->device_lock);
		for (dev = hba->device_head; dev; dev = dev->next) {

			iterp->ti_ptr = (void *)dev;
			iterp->ti_offset = hba->hba_id;
			atomic_inc(&hba->dev_mib_access_count);

			spin_unlock(&hba->device_lock);
			spin_unlock(&se_global->hba_lock);
			return((void *)iterp);
		}
		spin_unlock(&hba->device_lock);
	}
	spin_unlock(&se_global->hba_lock);

	return(NULL);
}

static void locate_hba_stop(struct seq_file *seq, void *v)
{
	table_iter_t *iterp = (table_iter_t *)seq->private;

	if (!(iterp))
		return;

	iterp->ti_ptr = NULL;
	kfree(iterp);
	seq->private = NULL;
		
	return;
}

/*
 * SCSI Device Table
 */
int do_hba_check(void *p)
{
	se_hba_t *hba = (se_hba_t *)p;

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
	se_hba_t *hba;
	se_device_t *dev;
	table_iter_t *iterp = (table_iter_t *)seq->private;
	int k;

	if (v == SEQ_START_TOKEN)
		seq_puts(seq, "inst indx role ports\n");

	if (!(hba = core_get_hba_from_id(iterp->ti_offset, 0))) {
		/* Log error ? */
		return(0);
	}

	spin_lock(&hba->device_lock);
	if ((dev = (se_device_t *)iterp->ti_ptr)) {
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
	se_hba_t *hba;
	se_device_t *dev;
	se_port_t *sep, *sep_tmp;
	table_iter_t *iterp = (table_iter_t *)seq->private;

	if (v == SEQ_START_TOKEN)
		seq_puts(seq, "inst device indx role busy_count\n");

	if (!(hba = core_get_hba_from_id(iterp->ti_offset, 0))) {
		/* Log error ? */
		return(0);
	}

	/* FIXME: scsiPortBusyStatuses count */
	spin_lock(&hba->device_lock);
	if ((dev = (se_device_t *)iterp->ti_ptr)) {
		spin_lock(&dev->se_port_lock);
		list_for_each_entry_safe(sep, sep_tmp, &dev->dev_sep_list, sep_list) {
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
	se_hba_t *hba;
	se_device_t *dev;
	table_iter_t *iterp = (table_iter_t *)seq->private;
	se_port_t *se, *se_tmp;
	t10_wwn_t *wwn;

	if (v == SEQ_START_TOKEN)
		seq_puts(seq, "inst device indx dev_name\n");

	if (!(hba = core_get_hba_from_id(iterp->ti_offset, 0))) {
		/* Log error ? */
		return(0);
	}

	spin_lock(&hba->device_lock);
	if ((dev = (se_device_t *)iterp->ti_ptr)) {
		wwn = &dev->t10_wwn;

		spin_lock(&dev->se_port_lock);
		list_for_each_entry_safe(se, se_tmp, &dev->dev_sep_list, sep_list) {
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
	se_hba_t *hba;
	se_device_t *dev;
	table_iter_t *iterp = (table_iter_t *)seq->private;
	int non_accessible_lus = 0;
	char status[16];

	if (v == SEQ_START_TOKEN)
		seq_puts(seq, "inst indx num_LUs status non_access_LUs resets\n");

	if (!(hba = core_get_hba_from_id(iterp->ti_offset, 0))) {
		/* Log error ? */
		return(0);
	}

	spin_lock(&hba->device_lock);
	if ((dev = (se_device_t *)iterp->ti_ptr)) {
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
	se_hba_t *hba;
	se_device_t *dev;
	se_port_t *sep, *sep_tmp;
	table_iter_t *iterp = (table_iter_t *)seq->private;
	u32 rx_mbytes, tx_mbytes;
	unsigned long long num_cmds;

	if (v == SEQ_START_TOKEN)
		seq_puts(seq, "inst device indx name port_index in_cmds write_mbytes"
				" read_mbytes hs_in_cmds\n");

	if (!(hba = core_get_hba_from_id(iterp->ti_offset, 0))) {
		/* Log error ? */
		return(0);
	}

	spin_lock(&hba->device_lock);
	if ((dev = (se_device_t *)iterp->ti_ptr)) {
		spin_lock(&dev->se_port_lock);
		list_for_each_entry_safe(sep, sep_tmp, &dev->dev_sep_list, sep_list) {
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
	struct target_core_fabric_ops *iscsi_tf = target_core_get_iscsi_ops();

	return((iscsi_tf) ? iscsi_tf->scsi_auth_intr_seq_start(seq, pos) : NULL);
}

static void *scsi_auth_intr_seq_next(struct seq_file *seq, void *v,
					 loff_t *pos)
{
	struct target_core_fabric_ops *iscsi_tf = target_core_get_iscsi_ops();
	
	return((iscsi_tf) ? iscsi_tf->scsi_auth_intr_seq_next(seq, v, pos) : NULL);
}

static void scsi_auth_intr_seq_stop(struct seq_file *seq, void *v)
{
	struct target_core_fabric_ops *iscsi_tf = target_core_get_iscsi_ops();

	if (iscsi_tf)
		iscsi_tf->scsi_auth_intr_seq_stop(seq, v);

	return;
}

static int scsi_auth_intr_seq_show(struct seq_file *seq, void *v)
{
	if (v == SEQ_START_TOKEN)
		seq_puts(seq, "inst dev port indx dev_or_port intr_name "
			 "map_indx att_count num_cmds read_mbytes "
			 "write_mbytes hs_num_cmds creation_time row_status\n");

	{
	struct target_core_fabric_ops *iscsi_tf = target_core_get_iscsi_ops();
	
	if (iscsi_tf)
		return(iscsi_tf->scsi_auth_intr_seq_show(seq, v));
	}

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
	struct target_core_fabric_ops *iscsi_tf = target_core_get_iscsi_ops();

	return((iscsi_tf) ? iscsi_tf->scsi_att_intr_port_seq_start(seq, pos) : NULL);
}

static void *scsi_att_intr_port_seq_next(struct seq_file *seq, void *v,
					 loff_t *pos)
{
	struct target_core_fabric_ops *iscsi_tf = target_core_get_iscsi_ops();

	return((iscsi_tf) ? iscsi_tf->scsi_att_intr_port_seq_next(seq, v, pos) : NULL);
}

static void scsi_att_intr_port_seq_stop(struct seq_file *seq, void *v)
{
	struct target_core_fabric_ops *iscsi_tf = target_core_get_iscsi_ops();

	if (iscsi_tf)
		iscsi_tf->scsi_att_intr_port_seq_stop(seq, v);

	return;
}

static int scsi_att_intr_port_seq_show(struct seq_file *seq, void *v)
{
	if (v == SEQ_START_TOKEN)
		seq_puts(seq, "inst dev port indx port_auth_indx port_name port_ident\n");

	{
	struct target_core_fabric_ops *iscsi_tf = target_core_get_iscsi_ops();

	if (iscsi_tf)
		return(iscsi_tf->scsi_att_intr_port_seq_show(seq, v));
	}

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

/*
 * SCSI Logical Unit Table
 */
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

#define SCSI_LU_INDEX		1
static int scsi_lu_seq_show(struct seq_file *seq, void *v)
{
	se_hba_t *hba;
	se_device_t *dev;
	table_iter_t *iterp = (table_iter_t *)seq->private;
	int j;
	char str[28];

	if (v == SEQ_START_TOKEN)
		seq_puts(seq, "inst dev indx LUN lu_name vend prod rev"
		" dev_type status state-bit num_cmds read_mbytes"
		" write_mbytes rests full_stat hs_num_cmds creation_time\n");

	if (!(hba = core_get_hba_from_id(iterp->ti_offset, 0))) {
		/* Log error ? */
		return(0);
	}
	
	spin_lock(&hba->device_lock);
	if ((dev = (se_device_t *)iterp->ti_ptr)) {
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

/****************************************************************************/

/*
 * Remove proc fs entries
 */
void remove_scsi_target_mib(void)
{
	remove_proc_entry("scsi_target/mib/scsi_inst", NULL);
	remove_proc_entry("scsi_target/mib/scsi_dev", NULL);
	remove_proc_entry("scsi_target/mib/scsi_port", NULL);
	remove_proc_entry("scsi_target/mib/scsi_transport", NULL);
	remove_proc_entry("scsi_target/mib/scsi_tgt_dev", NULL);
	remove_proc_entry("scsi_target/mib/scsi_tgt_port", NULL);
	remove_proc_entry("scsi_target/mib/scsi_auth_intr", NULL);
	remove_proc_entry("scsi_target/mib/scsi_att_intr_port", NULL);
	remove_proc_entry("scsi_target/mib/scsi_lu", NULL);
	remove_proc_entry("scsi_target/mib", NULL);
}

/*
 * Create proc fs entries for the mib tables
 */
int init_scsi_target_mib(void)
{
	struct proc_dir_entry *dir_entry;
	struct proc_dir_entry *scsi_inst_entry;
	struct proc_dir_entry *scsi_dev_entry;
	struct proc_dir_entry *scsi_port_entry;
	struct proc_dir_entry *scsi_transport_entry;
	struct proc_dir_entry *scsi_tgt_dev_entry;
	struct proc_dir_entry *scsi_tgt_port_entry;
	struct proc_dir_entry *scsi_auth_intr_entry;
	struct proc_dir_entry *scsi_att_intr_port_entry;
	struct proc_dir_entry *scsi_lu_entry;

	if (!(dir_entry = proc_mkdir("scsi_target/mib", NULL))) {
		printk("proc_mkdir() failed.\n");
		return(-1);
        }

	scsi_inst_entry = 
		create_proc_entry("scsi_target/mib/scsi_inst", 0, NULL);
	if (scsi_inst_entry) {
		scsi_inst_entry->proc_fops = &scsi_inst_seq_fops;
	}
	else {
		goto error;
	}

	scsi_dev_entry = 
		create_proc_entry("scsi_target/mib/scsi_dev", 0, NULL);
	if (scsi_dev_entry) {
		scsi_dev_entry->proc_fops = &scsi_dev_seq_fops;
	}
	else {
		goto error;
	}

	scsi_port_entry = 
		create_proc_entry("scsi_target/mib/scsi_port", 0, NULL);
	if (scsi_port_entry) {
		scsi_port_entry->proc_fops = &scsi_port_seq_fops;
	}
	else {
		goto error;
	}

	scsi_transport_entry = 
		create_proc_entry("scsi_target/mib/scsi_transport", 0, NULL);
	if (scsi_transport_entry) {
		scsi_transport_entry->proc_fops = &scsi_transport_seq_fops;
	}
	else {
		goto error;
	}

	scsi_tgt_dev_entry = 
		create_proc_entry("scsi_target/mib/scsi_tgt_dev", 0, NULL);
	if (scsi_tgt_dev_entry) {
		scsi_tgt_dev_entry->proc_fops = &scsi_tgt_dev_seq_fops;
	}
	else {
		goto error;
	}

	scsi_tgt_port_entry = 
		create_proc_entry("scsi_target/mib/scsi_tgt_port", 0, NULL);
	if (scsi_tgt_port_entry) {
		scsi_tgt_port_entry->proc_fops = &scsi_tgt_port_seq_fops;
	}
	else {
		goto error;
	}

	scsi_auth_intr_entry = 
		create_proc_entry("scsi_target/mib/scsi_auth_intr", 0, NULL);
	if (scsi_auth_intr_entry) {
		scsi_auth_intr_entry->proc_fops = &scsi_auth_intr_seq_fops;
	}
	else {
		goto error;
	}

	scsi_att_intr_port_entry = 
	      create_proc_entry("scsi_target/mib/scsi_att_intr_port", 0, NULL);
	if (scsi_att_intr_port_entry) {
		scsi_att_intr_port_entry->proc_fops = 
						&scsi_att_intr_port_seq_fops;
	}
	else {
		goto error;
	}

	scsi_lu_entry = create_proc_entry("scsi_target/mib/scsi_lu", 0, NULL);
	if (scsi_lu_entry) {
		scsi_lu_entry->proc_fops = &scsi_lu_seq_fops;
	}
	else {
		goto error;
	}

	return(0);

error:
	printk("create_proc_entry() failed.\n");
	remove_scsi_target_mib();
	return(-1);
}

/*
 * Initialize the index table for allocating unique row indexes to various mib 
 * tables
 */ 
void init_scsi_index_table(void)
{
	memset(&scsi_index_table, 0, sizeof(scsi_index_table)); 
	spin_lock_init(&scsi_index_table.lock);
}

/*
 * Allocate a new row index for the entry type specified
 */ 
u32 scsi_get_new_index(scsi_index_t type)
{
	u32 new_index;

	if ((type < 0) || (type >= INDEX_TYPE_MAX)) {
		printk("Invalid index type %d\n", type);
		return(-1);
	}

	spin_lock(&scsi_index_table.lock);
	new_index = ++scsi_index_table.scsi_mib_index[type];
	if (new_index == 0)
		new_index = ++scsi_index_table.scsi_mib_index[type];
	spin_unlock(&scsi_index_table.lock);

	return(new_index);
}

EXPORT_SYMBOL(scsi_get_new_index);
