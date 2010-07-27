/*******************************************************************************
 * Filename:  target_core_device.c (based on iscsi_target_device.c)
 *
 * This file contains the iSCSI Virtual Device and Disk Transport
 * agnostic related functions.
 *
 * Copyright (c) 2003, 2004, 2005 PyX Technologies, Inc.
 * Copyright (c) 2005-2006 SBE, Inc.  All Rights Reserved.
 * Copyright (c) 2007-2009 Rising Tide Software, Inc.
 * Copyright (c) 2008-2009 Linux-iSCSI.org
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
#include <linux/delay.h>
#include <linux/timer.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/smp_lock.h>
#include <linux/in.h>
#include <net/sock.h>
#include <net/tcp.h>
#include <scsi/scsi.h>

#include <target/target_core_base.h>
#include <target/target_core_device.h>
#include <target/target_core_hba.h>
#include <target/target_core_alua.h>
#include <target/target_core_pr.h>
#include <target/target_core_tpg.h>
#include <target/target_core_transport.h>
#include <target/target_core_ua.h>
#include <target/target_core_fabric_ops.h>
#include <target/target_core_plugin.h>
#include <target/target_core_seobj.h>

struct block_device *__linux_blockdevice_claim(
	int major,
	int minor,
	void *claim_ptr,
	int *ret)
{
	dev_t dev;
	struct block_device *bd;

	dev = MKDEV(major, minor);

	bd = bdget(dev);
	if (!(bd)) {
		*ret = -1;
		return NULL;
	}

	if (blkdev_get(bd, FMODE_WRITE|FMODE_READ) < 0) {
		*ret = -1;
		return NULL;
	}
	/*
	 * If no claim pointer was passed from claimee, use struct block_device.
	 */
	if (!claim_ptr)
		claim_ptr = (void *)bd;

	if (bd_claim(bd, claim_ptr) < 0) {
		blkdev_put(bd, FMODE_WRITE|FMODE_READ);
		*ret = 0;
		return bd;
	}

	*ret = 1;
	return bd;
}

struct block_device *linux_blockdevice_claim(
	int major,
	int minor,
	void *claim_ptr)
{
	dev_t dev;
	struct block_device *bd;

	dev = MKDEV(major, minor);

	bd = bdget(dev);
	if (!(bd))
		return NULL;

	if (blkdev_get(bd, FMODE_WRITE|FMODE_READ) < 0)
		return NULL;
	/*
	 * If no claim pointer was passed from claimee, use struct block_device.
	 */
	if (!claim_ptr)
		claim_ptr = (void *)bd;

	if (bd_claim(bd, claim_ptr) < 0) {
		blkdev_put(bd, FMODE_WRITE|FMODE_READ);
		return NULL;
	}

	return bd;
}

int linux_blockdevice_release(int major, int minor, struct block_device *bd_p)
{
	dev_t dev;
	struct block_device *bd;

	if (!bd_p) {
		dev = MKDEV(major, minor);

		bd = bdget(dev);
		if (!(bd))
			return -1;
	} else
		bd = bd_p;

	bd_release(bd);
	blkdev_put(bd, FMODE_WRITE|FMODE_READ);

	return 0;
}

int linux_blockdevice_check(int major, int minor)
{
	struct block_device *bd;

	bd = linux_blockdevice_claim(major, minor, NULL);
	if (!(bd))
		return -1;
	/*
	 * Blockdevice was able to be claimed, now unclaim it and return success
	 */
	linux_blockdevice_release(major, minor, NULL);

	return 0;
}
EXPORT_SYMBOL(linux_blockdevice_check);

/*	se_disable_devices_for_hba():
 *
 *
 */
void se_disable_devices_for_hba(struct se_hba *hba)
{
	struct se_device *dev;

	spin_lock(&hba->device_lock);
	list_for_each_entry(dev, &hba->hba_dev_list, dev_list) {

		spin_lock(&dev->dev_status_lock);
		if ((dev->dev_status & TRANSPORT_DEVICE_ACTIVATED) ||
		    (dev->dev_status & TRANSPORT_DEVICE_DEACTIVATED) ||
		    (dev->dev_status & TRANSPORT_DEVICE_OFFLINE_ACTIVATED) ||
		    (dev->dev_status & TRANSPORT_DEVICE_OFFLINE_DEACTIVATED)) {
			dev->dev_status |= TRANSPORT_DEVICE_SHUTDOWN;
			dev->dev_status &= ~TRANSPORT_DEVICE_ACTIVATED;
			dev->dev_status &= ~TRANSPORT_DEVICE_DEACTIVATED;
			dev->dev_status &= ~TRANSPORT_DEVICE_OFFLINE_ACTIVATED;
			dev->dev_status &=
					~TRANSPORT_DEVICE_OFFLINE_DEACTIVATED;

			wake_up_interruptible(&dev->dev_queue_obj->thread_wq);
		}
		spin_unlock(&dev->dev_status_lock);
	}
	spin_unlock(&hba->device_lock);

	return;
}

extern int __transport_get_lun_for_cmd(
	struct se_cmd *se_cmd,
	u32 unpacked_lun)
{
	struct se_dev_entry *deve;
	struct se_lun *se_lun = NULL;
	struct se_session *se_sess = SE_SESS(se_cmd);
	unsigned long flags;
	int read_only = 0;

	spin_lock_bh(&SE_NODE_ACL(se_sess)->device_list_lock);
	deve = se_cmd->se_deve =
			&SE_NODE_ACL(se_sess)->device_list[unpacked_lun];
	if (deve->lun_flags & TRANSPORT_LUNFLAGS_INITIATOR_ACCESS) {
		if (se_cmd) {
			deve->total_cmds++;
			deve->total_bytes += se_cmd->data_length;

			if (se_cmd->data_direction == SE_DIRECTION_WRITE) {
				if (deve->lun_flags &
						TRANSPORT_LUNFLAGS_READ_ONLY) {
					read_only = 1;
					goto out;
				}
#ifdef SNMP_SUPPORT
				deve->write_bytes += se_cmd->data_length;
#endif /* SNMP_SUPPORT */
			} else if (se_cmd->data_direction ==
				   SE_DIRECTION_READ) {
#ifdef SNMP_SUPPORT
				deve->read_bytes += se_cmd->data_length;
#endif /* SNMP_SUPPORT */
			}
		}
		deve->deve_cmds++;

		se_lun = se_cmd->se_lun = deve->se_lun;
		se_cmd->pr_res_key = deve->pr_res_key;
		se_cmd->orig_fe_lun = unpacked_lun;
		se_cmd->se_orig_obj_ptr = SE_LUN(se_cmd)->lun_type_ptr;
		se_cmd->se_cmd_flags |= SCF_SE_LUN_CMD;
	}
out:
	spin_unlock_bh(&SE_NODE_ACL(se_sess)->device_list_lock);

	if (!se_lun) {
		if (read_only) {
			se_cmd->scsi_sense_reason = WRITE_PROTECTED;
			se_cmd->se_cmd_flags |= SCF_SCSI_CDB_EXCEPTION;
			printk("TARGET_CORE[%s]: Detected WRITE_PROTECTED LUN"
				" Access for 0x%08x\n",
				CMD_TFO(se_cmd)->get_fabric_name(),
				unpacked_lun);
			return -1;
		} else {
			/*
			 * Use the se_portal_group->tpg_virt_lun0 to allow for
			 * REPORT_LUNS, et al to be returned when no active
			 * MappedLUN=0 exists for this Initiator Port.
			 */
			if (unpacked_lun != 0) {
				se_cmd->scsi_sense_reason = NON_EXISTENT_LUN;
				se_cmd->se_cmd_flags |= SCF_SCSI_CDB_EXCEPTION;
				printk("TARGET_CORE[%s]: Detected NON_EXISTENT_LUN"
					" Access for 0x%08x\n",
					CMD_TFO(se_cmd)->get_fabric_name(),
					unpacked_lun);
				return -1;
			}
			/*
			 * Force WRITE PROTECT for virtual LUN 0
			 */
			if ((se_cmd->data_direction != SE_DIRECTION_READ) &&
			    (se_cmd->data_direction != SE_DIRECTION_NONE)) {
				se_cmd->scsi_sense_reason = WRITE_PROTECTED;
				se_cmd->se_cmd_flags |= SCF_SCSI_CDB_EXCEPTION;
				return -1;
			}
#if 0				   
			printk("TARGET_CORE[%s]: Using virtual LUN0! :-)\n",
				CMD_TFO(se_cmd)->get_fabric_name());
#endif
			se_lun = se_cmd->se_lun = &se_sess->se_tpg->tpg_virt_lun0;	
			se_cmd->orig_fe_lun = 0;
			se_cmd->se_orig_obj_ptr = SE_LUN(se_cmd)->lun_type_ptr;
			se_cmd->se_cmd_flags |= SCF_SE_LUN_CMD;
		}
	}
	/*
	 * Determine if the struct se_lun is online.
	 */
/* #warning FIXME: Check for LUN_RESET + UNIT Attention */
	if (dev_obj_check_online(se_lun->lun_type_ptr) != 0) {
		se_cmd->scsi_sense_reason = NON_EXISTENT_LUN;
		se_cmd->se_cmd_flags |= SCF_SCSI_CDB_EXCEPTION;
		return -1;
	}

#ifdef SNMP_SUPPORT
	{
	struct se_device *dev = se_lun->se_dev;
	spin_lock(&dev->stats_lock);
	dev->num_cmds++;
	if (se_cmd->data_direction == SE_DIRECTION_WRITE)
		dev->write_bytes += se_cmd->data_length;
	else if (se_cmd->data_direction == SE_DIRECTION_READ)
		dev->read_bytes += se_cmd->data_length;
	spin_unlock(&dev->stats_lock);
	}
#endif /* SNMP_SUPPORT */

	/*
	 * Add the iscsi_cmd_t to the struct se_lun's cmd list.  This list is used
	 * for tracking state of struct se_cmds during LUN shutdown events.
	 */
	spin_lock_irqsave(&se_lun->lun_cmd_lock, flags);
	list_add_tail(&se_cmd->se_lun_list, &se_lun->lun_cmd_list);
	atomic_set(&T_TASK(se_cmd)->transport_lun_active, 1);
#if 0
	printk(KERN_INFO "Adding ITT: 0x%08x to LUN LIST[%d]\n",
		CMD_TFO(se_cmd)->get_task_tag(se_cmd), se_lun->unpacked_lun);
#endif
	spin_unlock_irqrestore(&se_lun->lun_cmd_lock, flags);

	return 0;
}

extern int transport_get_lun_for_tmr(
	struct se_cmd *se_cmd,
	u32 unpacked_lun)
{
	struct se_device *dev = NULL;
	struct se_dev_entry *deve;
	struct se_lun *se_lun = NULL;
	struct se_session *se_sess = SE_SESS(se_cmd);
	struct se_tmr_req *se_tmr = se_cmd->se_tmr_req;

	spin_lock_bh(&SE_NODE_ACL(se_sess)->device_list_lock);
	deve = se_cmd->se_deve =
			&SE_NODE_ACL(se_sess)->device_list[unpacked_lun];
	if (deve->lun_flags & TRANSPORT_LUNFLAGS_INITIATOR_ACCESS) {
		se_lun = se_cmd->se_lun = se_tmr->tmr_lun = deve->se_lun;
		dev = se_tmr->tmr_dev = se_lun->se_dev;
		se_cmd->pr_res_key = deve->pr_res_key;
		se_cmd->orig_fe_lun = unpacked_lun;
		se_cmd->se_orig_obj_ptr = SE_LUN(se_cmd)->lun_type_ptr;
/*		se_cmd->se_cmd_flags |= SCF_SE_LUN_CMD; */
	}
	spin_unlock_bh(&SE_NODE_ACL(se_sess)->device_list_lock);

	if (!se_lun) {
		printk(KERN_INFO "TARGET_CORE[%s]: Detected NON_EXISTENT_LUN"
			" Access for 0x%08x\n",
			CMD_TFO(se_cmd)->get_fabric_name(),
			unpacked_lun);
		se_cmd->se_cmd_flags |= SCF_SCSI_CDB_EXCEPTION;
		return -1;
	}
	/*
	 * Determine if the struct se_lun is online.
	 */
/* #warning FIXME: Check for LUN_RESET + UNIT Attention */
	if (dev_obj_check_online(se_lun->lun_type_ptr) != 0) {
		se_cmd->se_cmd_flags |= SCF_SCSI_CDB_EXCEPTION;
		return -1;
	}

	spin_lock(&dev->se_tmr_lock);
	list_add_tail(&se_tmr->tmr_list, &dev->dev_tmr_list);
	spin_unlock(&dev->se_tmr_lock);

	return 0;
}
EXPORT_SYMBOL(transport_get_lun_for_tmr);

/*
 * This function is called from core_scsi3_emulate_pro_register_and_move()
 * and core_scsi3_decode_spec_i_port(), and will increment &deve->pr_ref_count
 * when a matching rtpi is found.
 */
struct se_dev_entry *core_get_se_deve_from_rtpi(
	struct se_node_acl *nacl,
	u16 rtpi)
{
	struct se_dev_entry *deve;
	struct se_lun *lun;
	struct se_port *port;
	struct se_portal_group *tpg = nacl->se_tpg;
	u32 i;

	spin_lock_bh(&nacl->device_list_lock);
	for (i = 0; i < TRANSPORT_MAX_LUNS_PER_TPG; i++) {
		deve = &nacl->device_list[i];

		if (!(deve->lun_flags & TRANSPORT_LUNFLAGS_INITIATOR_ACCESS))
			continue;

		lun = deve->se_lun;
		if (!(lun)) {
			printk(KERN_ERR "%s device entries device pointer is"
				" NULL, but Initiator has access.\n",
				TPG_TFO(tpg)->get_fabric_name());
			continue;
		}
		port = lun->lun_sep;
		if (!(port)) {
			printk(KERN_ERR "%s device entries device pointer is"
				" NULL, but Initiator has access.\n",
				TPG_TFO(tpg)->get_fabric_name());
			continue;
		}
		if (port->sep_rtpi != rtpi)
			continue;
		
		atomic_inc(&deve->pr_ref_count);
		smp_mb__after_atomic_inc();
		spin_unlock_bh(&nacl->device_list_lock);

		return deve;
	}
	spin_unlock_bh(&nacl->device_list_lock);

	return NULL;
}

int core_free_device_list_for_node(
	struct se_node_acl *nacl,
	struct se_portal_group *tpg)
{
	struct se_dev_entry *deve;
	struct se_lun *lun;
	u32 i;

	if (!nacl->device_list)
		return 0;

	spin_lock_bh(&nacl->device_list_lock);
	for (i = 0; i < TRANSPORT_MAX_LUNS_PER_TPG; i++) {
		deve = &nacl->device_list[i];

		if (!(deve->lun_flags & TRANSPORT_LUNFLAGS_INITIATOR_ACCESS))
			continue;

		if (!deve->se_lun) {
			printk(KERN_ERR "%s device entries device pointer is"
				" NULL, but Initiator has access.\n",
				TPG_TFO(tpg)->get_fabric_name());
			continue;
		}
		lun = deve->se_lun;

		spin_unlock_bh(&nacl->device_list_lock);
		core_update_device_list_for_node(lun, NULL, deve->mapped_lun,
			TRANSPORT_LUNFLAGS_NO_ACCESS, nacl, tpg, 0);
		spin_lock_bh(&nacl->device_list_lock);
	}
	spin_unlock_bh(&nacl->device_list_lock);

	kfree(nacl->device_list);
	nacl->device_list = NULL;

	return 0;
}

void core_dec_lacl_count(struct se_node_acl *se_nacl, struct se_cmd *se_cmd)
{
	struct se_dev_entry *deve;

	spin_lock_bh(&se_nacl->device_list_lock);
	deve = &se_nacl->device_list[se_cmd->orig_fe_lun];
	deve->deve_cmds--;
	spin_unlock_bh(&se_nacl->device_list_lock);

	return;
}

void core_update_device_list_access(
	u32 mapped_lun,
	u32 lun_access,
	struct se_node_acl *nacl)
{
	struct se_dev_entry *deve;

	spin_lock_bh(&nacl->device_list_lock);
	deve = &nacl->device_list[mapped_lun];
	if (lun_access & TRANSPORT_LUNFLAGS_READ_WRITE) {
		deve->lun_flags &= ~TRANSPORT_LUNFLAGS_READ_ONLY;
		deve->lun_flags |= TRANSPORT_LUNFLAGS_READ_WRITE;
	} else {
		deve->lun_flags &= ~TRANSPORT_LUNFLAGS_READ_WRITE;
		deve->lun_flags |= TRANSPORT_LUNFLAGS_READ_ONLY;
	}
	spin_unlock_bh(&nacl->device_list_lock);

	return;
}
EXPORT_SYMBOL(core_update_device_list_access);

/*      core_update_device_list_for_node():
 *
 *
 */
int core_update_device_list_for_node(
	struct se_lun *lun,
	struct se_lun_acl *lun_acl,
	u32 mapped_lun,
	u32 lun_access,
	struct se_node_acl *nacl,
	struct se_portal_group *tpg,
	int enable)
{
	struct se_port *port = lun->lun_sep;
	struct se_dev_entry *deve = &nacl->device_list[mapped_lun];
	int trans = 0;
	/*
	 * If the MappedLUN entry is being disabled, the entry in
	 * port->sep_alua_list must be removed now before clearing the
	 * struct se_dev_entry pointers below as logic in
	 * core_alua_do_transition_tg_pt() depends on these being present.
	 */
	if (!(enable)) {
		spin_lock_bh(&port->sep_alua_lock);
		list_del(&deve->alua_port_list);
		spin_unlock_bh(&port->sep_alua_lock);
	}

	spin_lock_bh(&nacl->device_list_lock);
	if (enable) {
		/*
		 * Check if the call is handling demo mode -> explict LUN ACL
		 * transition.  This transition must be for the same struct se_lun
		 * + mapped_lun that was setup in demo mode..
		 */
		if (deve->lun_flags & TRANSPORT_LUNFLAGS_INITIATOR_ACCESS) {
			if (deve->se_lun_acl != NULL) {
				printk(KERN_ERR "struct se_dev_entry->se_lun_acl"
					" already set for demo mode -> explict"
					" LUN ACL transition\n");
				return -1;
			}
			if (deve->se_lun != lun) {
				printk(KERN_ERR "struct se_dev_entry->se_lun does"
					" match passed struct se_lun for demo mode"
					" -> explict LUN ACL transition\n");
				return -1;
			}
			deve->se_lun_acl = lun_acl;
			trans = 1;
		} else {
			deve->se_lun = lun;
			deve->se_lun_acl = lun_acl;
			deve->mapped_lun = mapped_lun;
			deve->lun_flags |= TRANSPORT_LUNFLAGS_INITIATOR_ACCESS;
		}

		if (lun_access & TRANSPORT_LUNFLAGS_READ_WRITE) {
			deve->lun_flags &= ~TRANSPORT_LUNFLAGS_READ_ONLY;
			deve->lun_flags |= TRANSPORT_LUNFLAGS_READ_WRITE;
		} else {
			deve->lun_flags &= ~TRANSPORT_LUNFLAGS_READ_WRITE;
			deve->lun_flags |= TRANSPORT_LUNFLAGS_READ_ONLY;
		}

		if (trans) {	
			spin_unlock_bh(&nacl->device_list_lock);
			return 0;
		}
#ifdef SNMP_SUPPORT
		deve->creation_time = get_jiffies_64();
		deve->attach_count++;
#endif /* SNMP_SUPPORT */
		spin_unlock_bh(&nacl->device_list_lock);

		spin_lock_bh(&port->sep_alua_lock);
		list_add_tail(&deve->alua_port_list, &port->sep_alua_list);
		spin_unlock_bh(&port->sep_alua_lock);

		return 0;
	}
	/*
	 * Wait for any in process SPEC_I_PT=1 or REGISTER_AND_MOVE
	 * PR operation to complete.
	 */
	spin_unlock_bh(&nacl->device_list_lock);
	while (atomic_read(&deve->pr_ref_count) != 0)
		msleep(100);
	spin_lock_bh(&nacl->device_list_lock);
	/*
	 * Disable struct se_dev_entry LUN ACL mapping
	 */
	core_scsi3_ua_release_all(deve);
	deve->se_lun = NULL;
	deve->se_lun_acl = NULL;
	deve->lun_flags = 0;
#ifdef SNMP_SUPPORT
	deve->creation_time = 0;
	deve->attach_count--;
#endif /* SNMP_SUPPORT */
	spin_unlock_bh(&nacl->device_list_lock);

	core_scsi3_free_pr_reg_from_nacl(lun->se_dev, nacl);
	return 0;
}

/*      core_clear_lun_from_tpg():
 *
 *
 */
void core_clear_lun_from_tpg(struct se_lun *lun, struct se_portal_group *tpg)
{
	struct se_node_acl *nacl;
	struct se_dev_entry *deve;
	u32 i;

	spin_lock_bh(&tpg->acl_node_lock);
	list_for_each_entry(nacl, &tpg->acl_node_list, acl_list) {
		spin_unlock_bh(&tpg->acl_node_lock);

		spin_lock_bh(&nacl->device_list_lock);
		for (i = 0; i < TRANSPORT_MAX_LUNS_PER_TPG; i++) {
			deve = &nacl->device_list[i];
			if (lun != deve->se_lun)
				continue;
			spin_unlock_bh(&nacl->device_list_lock);

			core_update_device_list_for_node(lun, NULL,
				deve->mapped_lun, TRANSPORT_LUNFLAGS_NO_ACCESS,
				nacl, tpg, 0);

			spin_lock_bh(&nacl->device_list_lock);
		}
		spin_unlock_bh(&nacl->device_list_lock);

		spin_lock_bh(&tpg->acl_node_lock);
	}
	spin_unlock_bh(&tpg->acl_node_lock);

	return;
}

struct se_port *core_alloc_port(struct se_device *dev)
{
	struct se_port *port, *port_tmp;

	port = kzalloc(sizeof(struct se_port), GFP_KERNEL);
	if (!(port)) {
		printk(KERN_ERR "Unable to allocate struct se_port\n");
		return NULL;
	}
	INIT_LIST_HEAD(&port->sep_alua_list);
	INIT_LIST_HEAD(&port->sep_list);
	atomic_set(&port->sep_tg_pt_secondary_offline, 0);
	spin_lock_init(&port->sep_alua_lock);
	mutex_init(&port->sep_tg_pt_md_mutex);

	spin_lock(&dev->se_port_lock);
	if (dev->dev_port_count == 0x0000ffff) {
		printk(KERN_WARNING "Reached dev->dev_port_count =="
				" 0x0000ffff\n");
		spin_unlock(&dev->se_port_lock);
		return NULL;
	}
again:
	/*
	 * Allocate the next RELATIVE TARGET PORT IDENTIFER for this struct se_device
	 * Here is the table from spc4r17 section 7.7.3.8.
	 *
	 *    Table 473 -- RELATIVE TARGET PORT IDENTIFIER field
	 *
	 * Code      Description
	 * 0h        Reserved
	 * 1h        Relative port 1, historically known as port A
	 * 2h        Relative port 2, historically known as port B
	 * 3h to FFFFh    Relative port 3 through 65 535
	 */
	port->sep_rtpi = dev->dev_rpti_counter++;
	if (!(port->sep_rtpi))
		goto again;

	list_for_each_entry(port_tmp, &dev->dev_sep_list, sep_list) {
		/*
		 * Make sure RELATIVE TARGET PORT IDENTIFER is unique
		 * for 16-bit wrap..
		 */
		if (port->sep_rtpi == port_tmp->sep_rtpi)
			goto again;
	}
	spin_unlock(&dev->se_port_lock);

	return port;
}

void core_export_port(
	struct se_device *dev,
	struct se_portal_group *tpg,
	struct se_port *port,
	struct se_lun *lun)
{
	struct se_subsystem_dev *su_dev = SU_DEV(dev);
	struct t10_alua_tg_pt_gp_member *tg_pt_gp_mem = NULL;

	spin_lock(&dev->se_port_lock);
	spin_lock(&lun->lun_sep_lock);
	port->sep_tpg = tpg;
	port->sep_lun = lun;
	lun->lun_sep = port;
	spin_unlock(&lun->lun_sep_lock);

	list_add_tail(&port->sep_list, &dev->dev_sep_list);
	spin_unlock(&dev->se_port_lock);

	if (T10_ALUA(su_dev)->alua_type == SPC3_ALUA_EMULATED) {
		tg_pt_gp_mem = core_alua_allocate_tg_pt_gp_mem(port);
		if (IS_ERR(tg_pt_gp_mem) || !tg_pt_gp_mem) {
			printk(KERN_ERR "Unable to allocate t10_alua_tg_pt"
					"_gp_member_t\n");
			return;
		}
		spin_lock(&tg_pt_gp_mem->tg_pt_gp_mem_lock);
		__core_alua_attach_tg_pt_gp_mem(tg_pt_gp_mem,
			T10_ALUA(su_dev)->default_tg_pt_gp);
		spin_unlock(&tg_pt_gp_mem->tg_pt_gp_mem_lock);
		printk(KERN_INFO "%s/%s: Adding to default ALUA Target Port"
			" Group: alua/default_tg_pt_gp\n",
			TRANSPORT(dev)->name, TPG_TFO(tpg)->get_fabric_name());
	}

	dev->dev_port_count++;
#ifdef SNMP_SUPPORT
	port->sep_index = port->sep_rtpi; /* RELATIVE TARGET PORT IDENTIFER */
#endif
	return;
}

/*
 *	Called with struct se_device->se_port_lock spinlock held.
 */
void core_release_port(struct se_device *dev, struct se_port *port)
{
	/*
	 * Wait for any port reference for PR ALL_TG_PT=1 operation
	 * to complete in __core_scsi3_alloc_registration()
	 */
	spin_unlock(&dev->se_port_lock);
	if (atomic_read(&port->sep_tg_pt_ref_cnt))
		msleep(100);
	spin_lock(&dev->se_port_lock);

	core_alua_free_tg_pt_gp_mem(port);

	list_del(&port->sep_list);
	dev->dev_port_count--;
	kfree(port);

	return;
}

int transport_core_report_lun_response(struct se_cmd *se_cmd)
{
	struct se_dev_entry *deve;
	struct se_lun *se_lun;
	struct se_session *se_sess = SE_SESS(se_cmd);
	struct se_task *se_task;
	unsigned char *buf = (unsigned char *)T_TASK(se_cmd)->t_task_buf;
	u32 cdb_offset = 0, lun_count = 0, offset = 8;
	u64 i, lun;

	list_for_each_entry(se_task, &T_TASK(se_cmd)->t_task_list, t_list)
		break;

	if (!(se_task)) {
		printk(KERN_ERR "Unable to locate struct se_task for struct se_cmd\n");
		return PYX_TRANSPORT_LU_COMM_FAILURE;
	}

	/*
	 * If no struct se_session pointer is present, this struct se_cmd is
	 * coming via a target_core_mod PASSTHROUGH op, and not through
	 * a $FABRIC_MOD.  In that case, report LUN=0 only.
	 */
	if (!(se_sess)) {
		lun = 0;
		buf[offset++] = ((lun >> 56) & 0xff);
		buf[offset++] = ((lun >> 48) & 0xff);
		buf[offset++] = ((lun >> 40) & 0xff);
		buf[offset++] = ((lun >> 32) & 0xff);
		buf[offset++] = ((lun >> 24) & 0xff);
		buf[offset++] = ((lun >> 16) & 0xff);
		buf[offset++] = ((lun >> 8) & 0xff);
		buf[offset++] = (lun & 0xff);
		lun_count = 1;
		goto done;
	}

	spin_lock_bh(&SE_NODE_ACL(se_sess)->device_list_lock);
	for (i = 0; i < TRANSPORT_MAX_LUNS_PER_TPG; i++) {
		deve = &SE_NODE_ACL(se_sess)->device_list[i];
		if (!(deve->lun_flags & TRANSPORT_LUNFLAGS_INITIATOR_ACCESS))
			continue;
		se_lun = deve->se_lun;
		/*
		 * We determine the correct LUN LIST LENGTH even once we
		 * have reached the initial allocation length.
		 * See SPC2-R20 7.19.
		 */
		lun_count++;
		if ((cdb_offset + 8) >= se_cmd->data_length)
			continue;

		lun = cpu_to_be64(CMD_TFO(se_cmd)->pack_lun(deve->mapped_lun));
		buf[offset++] = ((lun >> 56) & 0xff);
		buf[offset++] = ((lun >> 48) & 0xff);
		buf[offset++] = ((lun >> 40) & 0xff);
		buf[offset++] = ((lun >> 32) & 0xff);
		buf[offset++] = ((lun >> 24) & 0xff);
		buf[offset++] = ((lun >> 16) & 0xff);
		buf[offset++] = ((lun >> 8) & 0xff);
		buf[offset++] = (lun & 0xff);
		cdb_offset += 8;
	}
	spin_unlock_bh(&SE_NODE_ACL(se_sess)->device_list_lock);

	/*
	 * See SPC3 r07, page 159.
	 */
done:
	lun_count *= 8;
	buf[0] = ((lun_count >> 24) & 0xff);
	buf[1] = ((lun_count >> 16) & 0xff);
	buf[2] = ((lun_count >> 8) & 0xff);
	buf[3] = (lun_count & 0xff);

	return PYX_TRANSPORT_SENT_TO_TRANSPORT;
}

/*	se_release_device_for_hba():
 *
 *
 */
void se_release_device_for_hba(struct se_device *dev)
{
	struct se_hba *hba = dev->se_hba;

	if ((dev->dev_status & TRANSPORT_DEVICE_ACTIVATED) ||
	    (dev->dev_status & TRANSPORT_DEVICE_DEACTIVATED) ||
	    (dev->dev_status & TRANSPORT_DEVICE_SHUTDOWN) ||
	    (dev->dev_status & TRANSPORT_DEVICE_OFFLINE_ACTIVATED) ||
	    (dev->dev_status & TRANSPORT_DEVICE_OFFLINE_DEACTIVATED))
		se_dev_stop(dev);

	transport_generic_free_device(dev);

	spin_lock(&hba->device_lock);
	list_del(&dev->dev_list);
	hba->dev_count--;
	spin_unlock(&hba->device_lock);

	core_scsi3_free_all_registrations(dev);
	se_release_vpd_for_dev(dev);

	kfree(dev->dev_status_queue_obj);
	kfree(dev->dev_queue_obj);
	kfree(dev);

	return;
}

void se_release_vpd_for_dev(struct se_device *dev)
{
	struct t10_vpd *vpd, *vpd_tmp;

	spin_lock(&DEV_T10_WWN(dev)->t10_vpd_lock);
	list_for_each_entry_safe(vpd, vpd_tmp,
			&DEV_T10_WWN(dev)->t10_vpd_list, vpd_list) {
		list_del(&vpd->vpd_list);
		kfree(vpd);
	}
	spin_unlock(&DEV_T10_WWN(dev)->t10_vpd_lock);

	return;
}

int transport_get_lun_for_cmd(
	struct se_cmd *se_cmd,
	unsigned char *cdb,
	u32 unpacked_lun)
{
	return __transport_get_lun_for_cmd(se_cmd, unpacked_lun);
}
EXPORT_SYMBOL(transport_get_lun_for_cmd);

/*
 * Called with struct se_hba->device_lock held.
 */
void se_clear_dev_ports(struct se_device *dev)
{
	struct se_hba *hba = dev->se_hba;
	struct se_lun *lun;
	struct se_portal_group *tpg;
	struct se_port *sep, *sep_tmp;

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

		core_dev_del_lun(tpg, lun->unpacked_lun);

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
int se_free_virtual_device(struct se_device *dev, struct se_hba *hba)
{
	spin_lock(&hba->device_lock);
	se_clear_dev_ports(dev);
	spin_unlock(&hba->device_lock);

	core_alua_free_lu_gp_mem(dev);
	se_release_device_for_hba(dev);

	return 0;
}
EXPORT_SYMBOL(se_free_virtual_device);

void se_dev_start(struct se_device *dev)
{
	struct se_hba *hba = dev->se_hba;

	spin_lock(&hba->device_lock);
	atomic_inc(&dev->dev_obj.obj_access_count);
	if (atomic_read(&dev->dev_obj.obj_access_count) == 1) {
		if (dev->dev_status & TRANSPORT_DEVICE_DEACTIVATED) {
			dev->dev_status &= ~TRANSPORT_DEVICE_DEACTIVATED;
			dev->dev_status |= TRANSPORT_DEVICE_ACTIVATED;
		} else if (dev->dev_status &
			   TRANSPORT_DEVICE_OFFLINE_DEACTIVATED) {
			dev->dev_status &=
				~TRANSPORT_DEVICE_OFFLINE_DEACTIVATED;
			dev->dev_status |= TRANSPORT_DEVICE_OFFLINE_ACTIVATED;
		}
	}
	spin_unlock(&hba->device_lock);
}

void se_dev_stop(struct se_device *dev)
{
	struct se_hba *hba = dev->se_hba;

	spin_lock(&hba->device_lock);
	atomic_dec(&dev->dev_obj.obj_access_count);
	if (atomic_read(&dev->dev_obj.obj_access_count) == 0) {
		if (dev->dev_status & TRANSPORT_DEVICE_ACTIVATED) {
			dev->dev_status &= ~TRANSPORT_DEVICE_ACTIVATED;
			dev->dev_status |= TRANSPORT_DEVICE_DEACTIVATED;
		} else if (dev->dev_status &
			   TRANSPORT_DEVICE_OFFLINE_ACTIVATED) {
			dev->dev_status &= ~TRANSPORT_DEVICE_OFFLINE_ACTIVATED;
			dev->dev_status |= TRANSPORT_DEVICE_OFFLINE_DEACTIVATED;
		}
	}
	spin_unlock(&hba->device_lock);

	while (atomic_read(&hba->dev_mib_access_count))
		msleep(10);
}

void se_dev_set_default_attribs(struct se_device *dev)
{
	DEV_ATTRIB(dev)->emulate_ua_intlck_ctrl = DA_EMULATE_UA_INTLLCK_CTRL;
	DEV_ATTRIB(dev)->emulate_tas = DA_EMULATE_TAS;
	DEV_ATTRIB(dev)->emulate_reservations = DA_EMULATE_RESERVATIONS;
	DEV_ATTRIB(dev)->emulate_alua = DA_EMULATE_ALUA;
	DEV_ATTRIB(dev)->enforce_pr_isids = DA_ENFORCE_PR_ISIDS;
	/*
	 * block_size is based on subsystem plugin dependent requirements.
	 */
	DEV_ATTRIB(dev)->hw_block_size = TRANSPORT(dev)->get_blocksize(dev);
	DEV_ATTRIB(dev)->block_size = TRANSPORT(dev)->get_blocksize(dev);
	/*
	 * max_sectors is based on subsystem plugin dependent requirements.
	 */
	DEV_ATTRIB(dev)->hw_max_sectors = TRANSPORT(dev)->get_max_sectors(dev);
	DEV_ATTRIB(dev)->max_sectors = TRANSPORT(dev)->get_max_sectors(dev);
	/*
	 * queue_depth is based on subsystem plugin dependent requirements.
	 */
	DEV_ATTRIB(dev)->hw_queue_depth = TRANSPORT(dev)->get_queue_depth(dev);
	DEV_ATTRIB(dev)->queue_depth = TRANSPORT(dev)->get_queue_depth(dev);
	/*
	 * task_timeout is based on device type.
	 */
#if 1
	/*
	 * Disabled by default due to known BUG in some cases when task_timeout
	 * fires..  task_timeout, status_thread and status_thread_tur may end
	 * up being removed in v3.0.
	 */
	DEV_ATTRIB(dev)->task_timeout = 0;
#else
	DEV_ATTRIB(dev)->task_timeout = transport_get_default_task_timeout(dev);
#endif
}

int se_dev_set_task_timeout(struct se_device *dev, u32 task_timeout)
{
	if (task_timeout > DA_TASK_TIMEOUT_MAX) {
		printk(KERN_ERR "dev[%p]: Passed task_timeout: %u larger then"
			" DA_TASK_TIMEOUT_MAX\n", dev, task_timeout);
		return -1;
	} else {
		DEV_ATTRIB(dev)->task_timeout = task_timeout;
		printk(KERN_INFO "dev[%p]: Set SE Device task_timeout: %u\n",
			dev, task_timeout);
	}

	return 0;
}

int se_dev_set_emulate_ua_intlck_ctrl(struct se_device *dev, int flag)
{
	if ((flag != 0) && (flag != 1) && (flag != 2)) {
		printk(KERN_ERR "Illegal value %d\n", flag);
		return -1;
	}

	if (atomic_read(&dev->dev_export_obj.obj_access_count)) {
		printk(KERN_ERR "dev[%p]: Unable to change SE Device"
			" UA_INTRLCK_CTRL while dev_export_obj: %d count"
			" exists\n", dev,
			atomic_read(&dev->dev_export_obj.obj_access_count));
		return -1;
	}
	DEV_ATTRIB(dev)->emulate_ua_intlck_ctrl = flag;
	printk(KERN_INFO "dev[%p]: SE Device UA_INTRLCK_CTRL flag: %d\n",
		dev, DEV_ATTRIB(dev)->emulate_ua_intlck_ctrl);

	return 0;
}

int se_dev_set_emulate_tas(struct se_device *dev, int flag)
{
	if ((flag != 0) && (flag != 1)) {
		printk(KERN_ERR "Illegal value %d\n", flag);
		return -1;
	}

	if (atomic_read(&dev->dev_export_obj.obj_access_count)) {
		printk(KERN_ERR "dev[%p]: Unable to change SE Device TAS while"
			" dev_export_obj: %d count exists\n", dev,
			atomic_read(&dev->dev_export_obj.obj_access_count));
		return -1;
	}
	DEV_ATTRIB(dev)->emulate_tas = flag;
	printk(KERN_INFO "dev[%p]: SE Device TASK_ABORTED status bit: %s\n",
		dev, (DEV_ATTRIB(dev)->emulate_tas) ? "Enabled" : "Disabled");

	return 0;
}

int se_dev_set_enforce_pr_isids(struct se_device *dev, int flag)
{
	if ((flag != 0) && (flag != 1)) {
		printk(KERN_ERR "Illegal value %d\n", flag);
		return -1;
	}
	DEV_ATTRIB(dev)->enforce_pr_isids = flag;
	printk(KERN_INFO "dev[%p]: SE Device enforce_pr_isids bit: %s\n", dev,
		(DEV_ATTRIB(dev)->enforce_pr_isids) ? "Enabled" : "Disabled");
	return 0;
}
/*
 * Note, this can only be called on unexported SE Device Object.
 */
int se_dev_set_queue_depth(struct se_device *dev, u32 queue_depth)
{
	u32 orig_queue_depth = dev->queue_depth;

	if (atomic_read(&dev->dev_export_obj.obj_access_count)) {
		printk(KERN_ERR "dev[%p]: Unable to change SE Device TCQ while"
			" dev_export_obj: %d count exists\n", dev,
			atomic_read(&dev->dev_export_obj.obj_access_count));
		return -1;
	}
	if (!(queue_depth)) {
		printk(KERN_ERR "dev[%p]: Illegal ZERO value for queue"
			"_depth\n", dev);
		return -1;
	}

	if (TRANSPORT(dev)->transport_type == TRANSPORT_PLUGIN_PHBA_PDEV) {
		if (queue_depth > TRANSPORT(dev)->get_queue_depth(dev)) {
			printk(KERN_ERR "dev[%p]: Passed queue_depth: %u"
				" exceeds TCM/SE_Device TCQ: %u\n",
				dev, queue_depth,
				TRANSPORT(dev)->get_queue_depth(dev));
			return -1;
		}
	} else {
		if (queue_depth > TRANSPORT(dev)->get_queue_depth(dev)) {
			if (!(TRANSPORT(dev)->get_max_queue_depth)) {
				printk(KERN_ERR "dev[%p]: Unable to locate "
					"get_max_queue_depth() function"
					" pointer\n", dev);
				return -1;
			}
			if (queue_depth > TRANSPORT(dev)->get_max_queue_depth(
					dev)) {
				printk(KERN_ERR "dev[%p]: Passed queue_depth:"
					" %u exceeds TCM/SE_Device MAX"
					" TCQ: %u\n", dev, queue_depth,
					TRANSPORT(dev)->get_max_queue_depth(
						dev));
				return -1;
			}
		}
	}

	DEV_ATTRIB(dev)->queue_depth = dev->queue_depth = queue_depth;
	if (queue_depth > orig_queue_depth)
		atomic_add(queue_depth - orig_queue_depth, &dev->depth_left);
	else if (queue_depth < orig_queue_depth)
		atomic_sub(orig_queue_depth - queue_depth, &dev->depth_left);

	printk(KERN_INFO "dev[%p]: SE Device TCQ Depth changed to: %u\n",
			dev, queue_depth);
	return 0;
}

/* #warning FIXME: Forcing max_sectors greater than
	get_max_sectors() disabled */
int se_dev_set_max_sectors(struct se_device *dev, u32 max_sectors)
{
	int force = 0; /* Force setting for VDEVS */

	if (atomic_read(&dev->dev_export_obj.obj_access_count)) {
		printk(KERN_ERR "dev[%p]: Unable to change SE Device"
			" max_sectors while dev_export_obj: %d count exists\n",
			dev, atomic_read(&dev->dev_export_obj.obj_access_count));
		return -1;
	}
	if (!(max_sectors)) {
		printk(KERN_ERR "dev[%p]: Illegal ZERO value for"
			" max_sectors\n", dev);
		return -1;
	}
	if (max_sectors < DA_STATUS_MAX_SECTORS_MIN) {
		printk(KERN_ERR "dev[%p]: Passed max_sectors: %u less than"
			" DA_STATUS_MAX_SECTORS_MIN: %u\n", dev, max_sectors,
				DA_STATUS_MAX_SECTORS_MIN);
		return -1;
	}
	if (TRANSPORT(dev)->transport_type == TRANSPORT_PLUGIN_PHBA_PDEV) {
		if (max_sectors > TRANSPORT(dev)->get_max_sectors(dev)) {
			printk(KERN_ERR "dev[%p]: Passed max_sectors: %u"
				" greater than TCM/SE_Device max_sectors:"
				" %u\n", dev, max_sectors,
				TRANSPORT(dev)->get_max_sectors(dev));
			 return -1;
		}
	} else {
		if (!(force) && (max_sectors >
				 TRANSPORT(dev)->get_max_sectors(dev))) {
			printk(KERN_ERR "dev[%p]: Passed max_sectors: %u"
				" greater than TCM/SE_Device max_sectors"
				": %u, use force=1 to override.\n", dev,
				max_sectors,
				TRANSPORT(dev)->get_max_sectors(dev));
			return -1;
		}
		if (max_sectors > DA_STATUS_MAX_SECTORS_MAX) {
			printk(KERN_ERR "dev[%p]: Passed max_sectors: %u"
				" greater than DA_STATUS_MAX_SECTORS_MAX:"
				" %u\n", dev, max_sectors,
				DA_STATUS_MAX_SECTORS_MAX);
			return -1;
		}
	}

	DEV_ATTRIB(dev)->max_sectors = max_sectors;
	printk("dev[%p]: SE Device max_sectors changed to %u\n",
			dev, max_sectors);
	return 0;
}

int se_dev_set_block_size(struct se_device *dev, u32 block_size)
{
	if (atomic_read(&dev->dev_export_obj.obj_access_count)) {
		printk(KERN_ERR "dev[%p]: Unable to change SE Device block_size"
			" while dev_export_obj: %d count exists\n", dev,
			atomic_read(&dev->dev_export_obj.obj_access_count));
		return -1;
	}

	if ((block_size != 512) &&
	    (block_size != 1024) &&
	    (block_size != 2048) &&
	    (block_size != 4096)) {
		printk(KERN_ERR "dev[%p]: Illegal value for block_device: %u"
			" for SE device, must be 512, 1024, 2048 or 4096\n",
			dev, block_size);
		return -1;
	}

	if (TRANSPORT(dev)->transport_type == TRANSPORT_PLUGIN_PHBA_PDEV) {
		printk(KERN_ERR "dev[%p]: Not allowed to change block_size for"
			" Physical Device, use for Linux/SCSI to change"
			" block_size for underlying hardware\n", dev);
		return -1;
	}

	DEV_ATTRIB(dev)->block_size = block_size;
	printk(KERN_INFO "dev[%p]: SE Device block_size changed to %u\n",
			dev, block_size);
	return 0;
}

struct se_lun *core_dev_add_lun(
	struct se_portal_group *tpg,
	struct se_hba *hba,
	struct se_device *dev,
	u32 lun)
{
	struct se_lun *lun_p;
	u32 lun_access = 0;

	if (atomic_read(&dev->dev_access_obj.obj_access_count) != 0) {
		printk(KERN_ERR "Unable to export struct se_device while dev_access_obj: %d\n",
			atomic_read(&dev->dev_access_obj.obj_access_count));
		return NULL;
	}

	lun_p = core_tpg_pre_addlun(tpg, lun);
	if ((IS_ERR(lun_p)) || !(lun_p))
		return NULL;

	if (dev->dev_flags & DF_READ_ONLY)
		lun_access = TRANSPORT_LUNFLAGS_READ_ONLY;
	else
		lun_access = TRANSPORT_LUNFLAGS_READ_WRITE;

	if (core_tpg_post_addlun(tpg, lun_p, TRANSPORT_LUN_TYPE_DEVICE,
			lun_access, dev) < 0) {
		return NULL;
	}

	printk(KERN_INFO "%s_TPG[%u]_LUN[%u] - Activated %s Logical Unit from"
		" CORE HBA: %u\n", TPG_TFO(tpg)->get_fabric_name(),
		TPG_TFO(tpg)->tpg_get_tag(tpg), lun_p->unpacked_lun,
		TPG_TFO(tpg)->get_fabric_name(), hba->hba_id);
	/*
	 * Update LUN maps for dynamically added initiators when
	 * generate_node_acl is enabled.
	 */
	if (TPG_TFO(tpg)->tpg_check_demo_mode(tpg)) {
		struct se_node_acl *acl;
		spin_lock_bh(&tpg->acl_node_lock);
		list_for_each_entry(acl, &tpg->acl_node_list, acl_list) {
			if (acl->nodeacl_flags & NAF_DYNAMIC_NODE_ACL) {
				spin_unlock_bh(&tpg->acl_node_lock);
				core_tpg_add_node_to_devs(acl, tpg);
				spin_lock_bh(&tpg->acl_node_lock);
			}
		}
		spin_unlock_bh(&tpg->acl_node_lock);
	}

	return lun_p;
}
EXPORT_SYMBOL(core_dev_add_lun);

/*      core_dev_del_lun():
 *
 *
 */
int core_dev_del_lun(
	struct se_portal_group *tpg,
	u32 unpacked_lun)
{
	struct se_lun *lun;
	int ret = 0;

	lun = core_tpg_pre_dellun(tpg, unpacked_lun, TRANSPORT_LUN_TYPE_DEVICE,
			&ret);
	if (!(lun))
		return ret;

	core_tpg_post_dellun(tpg, lun);

	printk(KERN_INFO "%s_TPG[%u]_LUN[%u] - Deactivated %s Logical Unit from"
		" device object\n", TPG_TFO(tpg)->get_fabric_name(),
		TPG_TFO(tpg)->tpg_get_tag(tpg), unpacked_lun,
		TPG_TFO(tpg)->get_fabric_name());

	return 0;
}
EXPORT_SYMBOL(core_dev_del_lun);

struct se_lun *core_get_lun_from_tpg(struct se_portal_group *tpg, u32 unpacked_lun)
{
	struct se_lun *lun;

	spin_lock(&tpg->tpg_lun_lock);
	if (unpacked_lun > (TRANSPORT_MAX_LUNS_PER_TPG-1)) {
		printk(KERN_ERR "%s LUN: %u exceeds TRANSPORT_MAX_LUNS"
			"_PER_TPG-1: %u for Target Portal Group: %hu\n",
			TPG_TFO(tpg)->get_fabric_name(), unpacked_lun,
			TRANSPORT_MAX_LUNS_PER_TPG-1,
			TPG_TFO(tpg)->tpg_get_tag(tpg));
		spin_unlock(&tpg->tpg_lun_lock);
		return NULL;
	}
	lun = &tpg->tpg_lun_list[unpacked_lun];

	if (lun->lun_status != TRANSPORT_LUN_STATUS_FREE) {
		printk(KERN_ERR "%s Logical Unit Number: %u is not free on"
			" Target Portal Group: %hu, ignoring request.\n",
			TPG_TFO(tpg)->get_fabric_name(), unpacked_lun,
			TPG_TFO(tpg)->tpg_get_tag(tpg));
		spin_unlock(&tpg->tpg_lun_lock);
		return NULL;
	}
	spin_unlock(&tpg->tpg_lun_lock);

	return lun;
}
EXPORT_SYMBOL(core_get_lun_from_tpg);

/*      core_dev_get_lun():
 *
 *
 */
static struct se_lun *core_dev_get_lun(struct se_portal_group *tpg, u32 unpacked_lun)
{
	struct se_lun *lun;

	spin_lock(&tpg->tpg_lun_lock);
	if (unpacked_lun > (TRANSPORT_MAX_LUNS_PER_TPG-1)) {
		printk(KERN_ERR "%s LUN: %u exceeds TRANSPORT_MAX_LUNS_PER"
			"_TPG-1: %u for Target Portal Group: %hu\n",
			TPG_TFO(tpg)->get_fabric_name(), unpacked_lun,
			TRANSPORT_MAX_LUNS_PER_TPG-1,
			TPG_TFO(tpg)->tpg_get_tag(tpg));
		spin_unlock(&tpg->tpg_lun_lock);
		return NULL;
	}
	lun = &tpg->tpg_lun_list[unpacked_lun];

	if (lun->lun_status != TRANSPORT_LUN_STATUS_ACTIVE) {
		printk(KERN_ERR "%s Logical Unit Number: %u is not active on"
			" Target Portal Group: %hu, ignoring request.\n",
			TPG_TFO(tpg)->get_fabric_name(), unpacked_lun,
			TPG_TFO(tpg)->tpg_get_tag(tpg));
		spin_unlock(&tpg->tpg_lun_lock);
		return NULL;
	}
	spin_unlock(&tpg->tpg_lun_lock);

	return lun;
}

struct se_lun_acl *core_dev_init_initiator_node_lun_acl(
	struct se_portal_group *tpg,
	u32 mapped_lun,
	char *initiatorname,
	int *ret)
{
	struct se_lun_acl *lacl;
	struct se_node_acl *nacl;

	if (strlen(initiatorname) > TRANSPORT_IQN_LEN) {
		printk(KERN_ERR "%s InitiatorName exceeds maximum size.\n",
			TPG_TFO(tpg)->get_fabric_name());
		*ret = -EOVERFLOW;
		return NULL;
	}
	nacl = core_tpg_get_initiator_node_acl(tpg, initiatorname);
	if (!(nacl)) {
		*ret = -EINVAL;
		return NULL;
	}
	lacl = kzalloc(sizeof(struct se_lun_acl), GFP_KERNEL);
	if (!(lacl)) {
		printk(KERN_ERR "Unable to allocate memory for struct se_lun_acl.\n");
		*ret = -ENOMEM;
		return NULL;
	}

	INIT_LIST_HEAD(&lacl->lacl_list);
	lacl->mapped_lun = mapped_lun;
	lacl->se_lun_nacl = nacl;
	snprintf(lacl->initiatorname, TRANSPORT_IQN_LEN, "%s", initiatorname);

	return lacl;
}
EXPORT_SYMBOL(core_dev_init_initiator_node_lun_acl);

int core_dev_add_initiator_node_lun_acl(
	struct se_portal_group *tpg,
	struct se_lun_acl *lacl,
	u32 unpacked_lun,
	u32 lun_access)
{
	struct se_lun *lun;
	struct se_node_acl *nacl;

	lun = core_dev_get_lun(tpg, unpacked_lun);
	if (!(lun)) {
		printk(KERN_ERR "%s Logical Unit Number: %u is not active on"
			" Target Portal Group: %hu, ignoring request.\n",
			TPG_TFO(tpg)->get_fabric_name(), unpacked_lun,
			TPG_TFO(tpg)->tpg_get_tag(tpg));
		return -EINVAL;
	}

	nacl = core_tpg_get_initiator_node_acl(tpg, lacl->initiatorname);
	if (!(nacl))
		return -EINVAL;

	if ((lun->lun_access & TRANSPORT_LUNFLAGS_READ_ONLY) &&
	    (lun_access & TRANSPORT_LUNFLAGS_READ_WRITE))
		lun_access = TRANSPORT_LUNFLAGS_READ_ONLY;

	lacl->se_lun = lun;

	if (core_update_device_list_for_node(lun, lacl, lacl->mapped_lun,
			lun_access, nacl, tpg, 1) < 0)
		return -EINVAL;

	spin_lock(&lun->lun_acl_lock);
	list_add_tail(&lacl->lacl_list, &lun->lun_acl_list);
	atomic_inc(&lun->lun_acl_count);
	smp_mb__after_atomic_inc();
	spin_unlock(&lun->lun_acl_lock);

	printk(KERN_INFO "%s_TPG[%hu]_LUN[%u->%u] - Added %s ACL for "
		" InitiatorNode: %s\n", TPG_TFO(tpg)->get_fabric_name(),
		TPG_TFO(tpg)->tpg_get_tag(tpg), unpacked_lun, lacl->mapped_lun,
		(lun_access & TRANSPORT_LUNFLAGS_READ_WRITE) ? "RW" : "RO",
		lacl->initiatorname);
	/*
	 * Check to see if there are any existing persistent reservation APTPL
	 * pre-registrations that need to be enabled for this LUN ACL..
	 */
	core_scsi3_check_aptpl_registration(lun->se_dev, tpg, lun, lacl);
	return 0;
}
EXPORT_SYMBOL(core_dev_add_initiator_node_lun_acl);

/*      core_dev_del_initiator_node_lun_acl():
 *
 *
 */
int core_dev_del_initiator_node_lun_acl(
	struct se_portal_group *tpg,
	struct se_lun *lun,
	struct se_lun_acl *lacl)
{
	struct se_node_acl *nacl;

	nacl = core_tpg_get_initiator_node_acl(tpg, lacl->initiatorname);
	if (!(nacl))
		return -EINVAL;

	spin_lock(&lun->lun_acl_lock);
	list_del(&lacl->lacl_list);
	atomic_dec(&lun->lun_acl_count);
	smp_mb__after_atomic_dec();
	spin_unlock(&lun->lun_acl_lock);

	core_update_device_list_for_node(lun, NULL, lacl->mapped_lun,
		TRANSPORT_LUNFLAGS_NO_ACCESS, nacl, tpg, 0);

	lacl->se_lun = NULL;

	printk(KERN_INFO "%s_TPG[%hu]_LUN[%u] - Removed ACL for"
		" InitiatorNode: %s Mapped LUN: %u\n",
		TPG_TFO(tpg)->get_fabric_name(),
		TPG_TFO(tpg)->tpg_get_tag(tpg), lun->unpacked_lun,
		lacl->initiatorname, lacl->mapped_lun);

	return 0;
}
EXPORT_SYMBOL(core_dev_del_initiator_node_lun_acl);

void core_dev_free_initiator_node_lun_acl(
	struct se_portal_group *tpg,
	struct se_lun_acl *lacl)
{
	printk("%s_TPG[%hu] - Freeing ACL for %s InitiatorNode: %s"
		" Mapped LUN: %u\n", TPG_TFO(tpg)->get_fabric_name(),
		TPG_TFO(tpg)->tpg_get_tag(tpg),
		TPG_TFO(tpg)->get_fabric_name(),
		lacl->initiatorname, lacl->mapped_lun);

	kfree(lacl);
}
EXPORT_SYMBOL(core_dev_free_initiator_node_lun_acl);

int core_dev_setup_virtual_lun0(void)
{
	struct se_hba *hba;
	struct se_device *dev;
	struct se_subsystem_dev *se_dev = NULL;
	struct se_subsystem_api *t;
	char buf[16];
	int ret;

	hba = core_alloc_hba(RAMDISK_DR);
	if (!(hba))
		return -ENOMEM;

	hba->hba_flags |= HBA_FLAGS_INTERNAL_USE;
	ret = se_core_add_hba(hba, 0);
	if (ret < 0) {
		kmem_cache_free(se_hba_cache, hba);
		return ret;
	}

	se_global->g_lun0_hba = hba;

	t = (struct se_subsystem_api *)plugin_get_obj(PLUGIN_TYPE_TRANSPORT,
			hba->type, &ret);
	if (!t || (ret != 0)) {
		ret = -EINVAL;
		goto out;
	}

	se_dev = kzalloc(sizeof(struct se_subsystem_dev), GFP_KERNEL);
	if (!(se_dev)) {
		printk(KERN_ERR "Unable to allocate memory for"
				" struct se_subsystem_dev\n");
		ret = -ENOMEM;
		goto out;
	}
	INIT_LIST_HEAD(&se_dev->g_se_dev_list);
	INIT_LIST_HEAD(&se_dev->t10_wwn.t10_vpd_list);
	spin_lock_init(&se_dev->t10_wwn.t10_vpd_lock);
	INIT_LIST_HEAD(&se_dev->t10_reservation.registration_list);
	INIT_LIST_HEAD(&se_dev->t10_reservation.aptpl_reg_list);
	spin_lock_init(&se_dev->t10_reservation.registration_lock);
	spin_lock_init(&se_dev->t10_reservation.aptpl_reg_lock);
	INIT_LIST_HEAD(&se_dev->t10_alua.tg_pt_gps_list);
	spin_lock_init(&se_dev->t10_alua.tg_pt_gps_lock);
	spin_lock_init(&se_dev->se_dev_lock);
	se_dev->t10_reservation.pr_aptpl_buf_len = PR_APTPL_BUF_LEN;
	se_dev->t10_wwn.t10_sub_dev = se_dev;
	se_dev->t10_alua.t10_sub_dev = se_dev;
	se_dev->se_dev_attrib.da_sub_dev = se_dev;

	se_dev->se_dev_hba = hba;

	se_dev->se_dev_su_ptr = t->allocate_virtdevice(hba, "virt_lun0");
	if (!(se_dev->se_dev_su_ptr)) {
		printk(KERN_ERR "Unable to locate subsystem dependent pointer"
			" from allocate_virtdevice()\n");
		ret = -ENOMEM;
		goto out;
	}
	se_global->g_lun0_su_dev = se_dev;

	memset(buf, 0, 16);
	sprintf(buf, "rd_pages=8");
	t->set_configfs_dev_params(hba, se_dev, buf, sizeof(buf));

	dev = t->create_virtdevice(hba, se_dev, se_dev->se_dev_su_ptr);
	if (!(dev) || IS_ERR(dev)) {
		ret = -ENOMEM;
		goto out;
	}
	se_dev->se_dev_ptr = dev;
	se_global->g_lun0_dev = dev;

	return 0;
out:
	se_global->g_lun0_su_dev = NULL;
	kfree(se_dev);
	if (se_global->g_lun0_hba) {
		se_core_del_hba(se_global->g_lun0_hba);
		se_global->g_lun0_hba = NULL;
	}
	return ret;
}


void core_dev_release_virtual_lun0(void)
{
	struct se_hba *hba = se_global->g_lun0_hba;
        struct se_subsystem_dev *su_dev = se_global->g_lun0_su_dev;

	if (!(hba))
		return;

	if (se_global->g_lun0_dev)
		se_free_virtual_device(se_global->g_lun0_dev, hba);

	kfree(su_dev);
	se_core_del_hba(hba);
}
