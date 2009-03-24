/*******************************************************************************
 * Filename:  target_core_tmr.c
 *
 * This file contains SPC-3 task management infrastructure
 *
 * Copyright (c) 2009 Rising Tide, Inc.
 * Copyright (c) 2009 Linux-iSCSI.org
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

#define TARGET_CORE_TMR_C

#include <linux/version.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <scsi/scsi.h>
#include <scsi/scsi_cmnd.h>

#include <target_core_base.h>
#include <target_core_device.h>
#include <target_core_hba.h>
#include <target_core_seobj.h>
#include <target_core_tmr.h>
#include <target_core_transport.h>
#include <target_core_alua.h>
#include <target_core_transport_plugin.h>
#include <target_core_fabric_ops.h>
#include <target_core_configfs.h>

#undef TARGET_CORE_TMR_C

#define DEBUG_LUN_RESET
#ifdef DEBUG_LUN_RESET
#define DEBUG_LR(x...) printk(KERN_INFO x)
#else
#define DEBUG_LR(x...)
#endif

se_tmr_req_t *core_tmr_alloc_req(
	se_cmd_t *se_cmd,
	void *fabric_tmr_ptr,
	u8 function)
{
	se_tmr_req_t *tmr;

	tmr = kmem_cache_zalloc(se_tmr_req_cache, GFP_KERNEL);
	if (!(tmr)) {
		printk(KERN_ERR "Unable to allocate se_tmr_req_t\n");
		return ERR_PTR(-ENOMEM);
	}
	tmr->task_cmd = se_cmd;
	tmr->fabric_tmr_ptr = fabric_tmr_ptr;
	tmr->function = function;
	INIT_LIST_HEAD(&tmr->tmr_list);

	return tmr;
}
EXPORT_SYMBOL(core_tmr_alloc_req);

/*
 * Called with se_device_t->se_tmr_lock held.
 */
void __core_tmr_release_req(
	se_tmr_req_t *tmr)
{
	list_del(&tmr->tmr_list);
	kmem_cache_free(se_tmr_req_cache, tmr);
}

void core_tmr_release_req(
	se_tmr_req_t *tmr)
{
	se_device_t *dev = tmr->tmr_dev;

	spin_lock(&dev->se_tmr_lock);
	__core_tmr_release_req(tmr);
	spin_unlock(&dev->se_tmr_lock);
}

int core_tmr_lun_reset(se_device_t *dev, se_tmr_req_t *tmr)
{
	se_cmd_t *cmd;
	se_queue_req_t *qr;
	se_node_acl_t *tmr_nacl = NULL;
	se_portal_group_t *tmr_tpg = NULL;
	se_tmr_req_t *tmr_p, *tmr_pp;
	se_task_t *task;
	unsigned long flags;
	int state, tas;
	/*
	 * TASK_ABORTED status bit, this is configurable via ConfigFS
	 * se_device_t attributes.  spc4r17 section 7.4.6 Control mode page
	 *
	 * A task aborted status (TAS) bit set to zero specifies that aborted
	 * tasks shall be terminated by the device server without any response
	 * to the application client. A TAS bit set to one specifies that tasks
	 * aborted by the actions of an I_T nexus other than the I_T nexus on
	 * which the command was received shall be completed with TASK ABORTED
	 * status (see SAM-4).
	 */
	tas = DEV_ATTRIB(dev)->emulate_tas;
	/*
	 * Determine if this se_tmr is coming from a $FABRIC_MOD
	 * or se_device_t passthrough..
	 */
	if (tmr->task_cmd && tmr->task_cmd->se_sess) {
		tmr_nacl = tmr->task_cmd->se_sess->se_node_acl;
		tmr_tpg = tmr->task_cmd->se_sess->se_tpg;
		if (tmr_nacl && tmr_tpg) {
			DEBUG_LR("LUN_RESET: TMR caller fabric: %s"
				" initiator port %s\n",
				TPG_TFO(tmr_tpg)->get_fabric_name(),
				tmr_nacl->initiatorname);
		}
	}
	DEBUG_LR("LUN_RESET: TMR: %p starting for [%s], tas: %d\n", tmr,
			TRANSPORT(dev)->name, tas);
	/*
	 * Release all pending and outgoing TMRs aside from the received
	 * LUN_RESET tmr..
	 */
	spin_lock(&dev->se_tmr_lock);
	list_for_each_entry_safe(tmr_p, tmr_pp, &dev->dev_tmr_list, tmr_list) {
		/*
		 * Allow the received TMR to return with FUNCTION_COMPLETE.
		 */
		if (tmr && (tmr_p == tmr))
			continue;

		cmd = tmr_p->task_cmd;
		if (!(cmd)) {
			printk(KERN_ERR "Unable to locate se_cmd_t for TMR\n");
			continue;
		}
		spin_unlock(&dev->se_tmr_lock);

		DEBUG_LR("LUN_RESET: Releasing TMR %p Function: 0x%02x,"
			" Response: 0x%02x, t_state: %d\n", tmr_p,
			tmr_p->function, tmr_p->response, cmd->t_state);

		transport_cmd_finish_abort_tmr(cmd);
		spin_lock(&dev->se_tmr_lock);
	}
	spin_unlock(&dev->se_tmr_lock);
	/*
	 * Complete outstanding se_task_t CDBs with TASK_ABORTED SAM status.
	 * This is following sam4r17, section 5.6 Aborting commands, Table 38
	 * for TMR LUN_RESET:
	 *
	 * a) "Yes" indicates that each command that is aborted on an I_T nexus
	 * other than the one that caused the SCSI device condition is
	 * completed with TASK ABORTED status, if the TAS bit is set to one in
	 * the Control mode page (see SPC-4). "No" indicates that no status is
	 * returned for aborted commands.
	 *
	 * d) If the logical unit reset is caused by a particular I_T nexus
	 * (e.g., by a LOGICAL UNIT RESET task management function), then "yes"
	 * (TASK_ABORTED status) applies.
	 *
	 * Otherwise (e.g., if triggered by a hard reset), "no"
	 * (no TASK_ABORTED SAM status) applies.
	 *
	 * Note that this seems to be independent of TAS (Task Aborted Status)
	 * in the Control Mode Page.
	 */
	spin_lock_irqsave(&dev->execute_task_lock, flags);
	while ((task = transport_get_task_from_state_list(dev))) {
		if (!(TASK_CMD(task))) {
			printk(KERN_ERR "TASK_CMD(task) is NULL!\n");
			continue;
		}
		cmd = TASK_CMD(task);

		if (!T_TASK(cmd)) {
			printk(KERN_ERR "T_TASK(cmd) is NULL for task: %p cmd:"
				" %p ITT: 0x%08x\n", task, cmd,
				CMD_TFO(cmd)->get_task_tag(cmd));
			continue;
		}
		spin_unlock_irqrestore(&dev->execute_task_lock, flags);

		spin_lock_irqsave(&T_TASK(cmd)->t_state_lock, flags);
		DEBUG_LR("LUN_RESET: cmd: %p task: %p ITT/CmdSN: 0x%08x/0x%08x"
			", i_state: %d, t_state/def_t_state: %d/%d cdb:"
			" 0x%02x\n", cmd, task, CMD_TFO(cmd)->get_task_tag(cmd),
			0, CMD_TFO(cmd)->get_cmd_state(cmd), cmd->t_state,
			cmd->deferred_t_state, T_TASK(cmd)->t_task_cdb[0]);
		DEBUG_LR("LUN_RESET: ITT[0x%08x] - t_task_cdbs: %d"
			" t_task_cdbs_left: %d t_task_cdbs_sent: %d --"
			" t_transport_active: %d t_transport_stop: %d"
			" t_transport_sent: %d\n",
			CMD_TFO(cmd)->get_task_tag(cmd),
			T_TASK(cmd)->t_task_cdbs,
			atomic_read(&T_TASK(cmd)->t_task_cdbs_left),
			atomic_read(&T_TASK(cmd)->t_task_cdbs_sent),
			atomic_read(&T_TASK(cmd)->t_transport_active),
			atomic_read(&T_TASK(cmd)->t_transport_stop),
			atomic_read(&T_TASK(cmd)->t_transport_sent));

		if (atomic_read(&task->task_active)) {
			atomic_set(&task->task_stop, 1);
			spin_unlock_irqrestore(
				&T_TASK(cmd)->t_state_lock, flags);

			DEBUG_LR("LUN_RESET: Waiting for task: %p to shutdown"
				" for dev: %p\n", task, dev);
			down(&task->task_stop_sem);
			DEBUG_LR("LUN_RESET Completed task: %p shutdown for"
				" dev: %p\n", task, dev);
			spin_lock_irqsave(&T_TASK(cmd)->t_state_lock, flags);
			atomic_dec(&T_TASK(cmd)->t_task_cdbs_left);

			atomic_set(&task->task_active, 0);
			atomic_set(&task->task_stop, 0);
		}
		__transport_stop_task_timer(task, &flags);

		if (!(atomic_dec_and_test(&T_TASK(cmd)->t_task_cdbs_ex_left))) {
			spin_unlock_irqrestore(
					&T_TASK(cmd)->t_state_lock, flags);
			DEBUG_LR("LUN_RESET: Skipping task: %p, dev: %p for"
				" t_task_cdbs_ex_left: %d\n", task, dev,
				atomic_read(&T_TASK(cmd)->t_task_cdbs_ex_left));

			spin_lock_irqsave(&dev->execute_task_lock, flags);
			continue;
		}

		if (atomic_read(&T_TASK(cmd)->t_transport_active)) {
			DEBUG_LR("LUN_RESET: got t_transport_active = 1 for"
				" task: %p, dev: %p\n", task, dev);

			if (atomic_read(&T_TASK(cmd)->t_fe_count)) {
				spin_unlock_irqrestore(
					&T_TASK(cmd)->t_state_lock, flags);
				/*
				 * TASK ABORTED status (TAS) bit support
				 */
				if ((tmr_nacl == cmd->se_sess->se_node_acl) ||
				     tas)
					transport_send_task_abort(cmd);
				transport_cmd_finish_abort(cmd, 0);
			} else {
				spin_unlock_irqrestore(
					&T_TASK(cmd)->t_state_lock, flags);

				transport_cmd_finish_abort(cmd, 1);
			}

			spin_lock_irqsave(&dev->execute_task_lock, flags);
			continue;
		}
		DEBUG_LR("LUN_RESET: Got t_transport_active = 0 for task: %p,"
			" dev: %p\n", task, dev);

		if (atomic_read(&T_TASK(cmd)->t_fe_count)) {
			spin_unlock_irqrestore(
				&T_TASK(cmd)->t_state_lock, flags);
			/*
			 * TASK ABORTED status (TAS) bit support
			 */
			if ((tmr_nacl == cmd->se_sess->se_node_acl) || tas)
				transport_send_task_abort(cmd);
			transport_cmd_finish_abort(cmd, 0);
		} else {
			spin_unlock_irqrestore(
				&T_TASK(cmd)->t_state_lock, flags);

			transport_cmd_finish_abort(cmd, 1);
		}
		spin_lock_irqsave(&dev->execute_task_lock, flags);
	}
	spin_unlock_irqrestore(&dev->execute_task_lock, flags);
	/*
	 * Release all commands remaining in the se_device_t cmd queue.
	 *
	 * This follows the same logic as above for the se_device_t
	 * se_task_t state list, where commands are returned with
	 * TASK_ABORTED status, if there is an outstanding $FABRIC_MOD
	 * reference, otherwise the se_cmd_t is released.
	 */
	spin_lock_irqsave(&dev->dev_queue_obj->cmd_queue_lock, flags);
	while ((qr = __transport_get_qr_from_queue(dev->dev_queue_obj))) {
		spin_unlock_irqrestore(
			&dev->dev_queue_obj->cmd_queue_lock, flags);
		cmd = (se_cmd_t *)qr->cmd;
		state = qr->state;
		kfree(qr);

		DEBUG_LR("LUN_RESET: From Device Queue: cmd: %p t_state: %d\n",
				cmd, state);

		if (atomic_read(&T_TASK(cmd)->t_fe_count)) {
			/*
			 * TASK ABORTED status (TAS) bit support
			 */
			if ((tmr_nacl == cmd->se_sess->se_node_acl) || tas)
				transport_send_task_abort(cmd);
			transport_cmd_finish_abort(cmd, 0);
		} else
			transport_cmd_finish_abort(cmd, 1);

		spin_lock_irqsave(&dev->dev_queue_obj->cmd_queue_lock, flags);
	}
	spin_unlock_irqrestore(&dev->dev_queue_obj->cmd_queue_lock, flags);

	spin_lock(&dev->stats_lock);
	dev->num_resets++;
	spin_unlock(&dev->stats_lock);

	DEBUG_LR("LUN_RESET: TMR for [%s] Complete\n", TRANSPORT(dev)->name);
	return 0;
}
