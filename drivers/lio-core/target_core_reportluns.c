/*********************************************************************************
 * Filename:  target_core_reportluns.c
 *
 * Copyright (c) 2004 PyX Technologies, Inc.
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


#define TARGET_CORE_REPORTLUNS_C

#include <linux/net.h>
#include <linux/string.h>
#include <linux/timer.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/smp_lock.h>
#include <linux/in.h>
#include <net/sock.h>
#include <net/tcp.h>

#include <iscsi_linux_os.h>
#include <iscsi_linux_defs.h>

#include <iscsi_debug.h>
#include <iscsi_protocol.h>
#include <iscsi_debug_opcodes.h>
#include <iscsi_debug.h>
#include <iscsi_target_core.h>
#include <target_core_base.h>
#include <iscsi_target_device.h>
#include <target_core_transport.h>
#include <iscsi_target_util.h>
#include <target_core_reportluns.h>

#include <target_core_fabric_ops.h>

#undef TARGET_CORE_REPORTLUNS_C

static se_subsystem_api_t *rl_template = &_rl_template;

/*	rl_set_iovec_ptrs():
 *
 *	Assumes non-scatterlist buffers.
 */
static int rl_set_iovec_ptrs (
	se_map_sg_t *map_sg,
	se_unmap_sg_t *unmap_sg)
{
	se_cmd_t *se_cmd = map_sg->se_cmd;
	se_task_t *task = NULL;
	rl_cmd_t *rl_cmd = NULL;
	struct iovec *iov = map_sg->iov;

	list_for_each_entry(task, &T_TASK(se_cmd)->t_task_list, t_list) {
		rl_cmd = (rl_cmd_t *) task->transport_req;
	}
	
	iov[0].iov_base = (unsigned char *) rl_cmd->rl_buf + map_sg->data_offset;
	iov[0].iov_len = map_sg->data_length;

	return(1);
}

/*	rl_wait_for_tasks():
 *
 *
 */
static void rl_wait_for_tasks (se_cmd_t *cmd, int remove_cmd, int session_reinstatement)
{
	return;
}

static void rl_nop_SG_segments (se_unmap_sg_t *unmap_sg)
{
	return;
}

/*	rl_allocate_cmd():
 *
 *
 */
static rl_cmd_t *rl_allocate_cmd (se_cmd_t *cmd, u32 size)
{
	rl_cmd_t *rl_cmd;

	if (!(rl_cmd = (rl_cmd_t *) kzalloc(sizeof(rl_cmd_t), GFP_KERNEL))) {
		TRACE_ERROR("Unable to allocate rl_cmd_t for REPORT_LUNS\n");
		return(NULL);
	}
	
	if (!(rl_cmd->rl_buf = (unsigned char *) kzalloc(cmd->data_length, GFP_KERNEL))) {
		TRACE_ERROR("Unable to allocate buffer for REPORT_LUNS\n");
		return(NULL);
	}
	
	rl_cmd->rl_size	= cmd->data_length;
	/*
	 * Setup any additional transport related function pointers now.
	 */
	cmd->transport_set_iovec_ptrs = &rl_set_iovec_ptrs;
	cmd->transport_wait_for_tasks = &rl_wait_for_tasks;
	cmd->transport_map_SG_segments = &rl_nop_SG_segments;
	cmd->transport_unmap_SG_segments = &rl_nop_SG_segments;
	
	return(rl_cmd);
}

/*	rl_allocate_fake_lun():
 *
 *
 */
static int rl_allocate_fake_lun (se_cmd_t *cmd, u32 lun)
{
	se_lun_t *lun_p;
	
	if (!(cmd->se_lun = (se_lun_t *)
			kzalloc(sizeof(se_lun_t), GFP_KERNEL))) {
		TRACE_ERROR("Unable to allocate se_lun_t\n");
		return(-1);
	}
	ISCSI_LUN(cmd)->unpacked_lun = lun;
	lun_p = ISCSI_LUN(cmd);
	
	if (!(lun_p->se_dev = (se_device_t *)
			kzalloc(sizeof(se_device_t), GFP_KERNEL))) {
		TRACE_ERROR("Unable to allocate se_device_t\n");
		kfree(ISCSI_LUN(cmd));
		return(-1);
	}
	ISCSI_DEV(cmd)->transport = rl_template;

	return(0);
}

/*	se_allocate_rl_cmd():
 *
 *
 */
extern int se_allocate_rl_cmd (
	se_cmd_t *cmd,
	unsigned char *cdb,
	u32 unpacked_lun)
{
	rl_cmd_t *rl_cmd = NULL;
	se_task_t *task = NULL;
	unsigned long flags;
	
	cmd->se_cmd_flags |= SCF_REPORT_LUNS;
	cmd->data_length = (cdb[6] << 24) + (cdb[7] << 16) +
			   (cdb[8] << 8) + cdb[9];

	if (rl_allocate_fake_lun(cmd, unpacked_lun) < 0)
		goto failure;
	
	if (!(rl_cmd = rl_allocate_cmd(cmd, cmd->data_length)))
		goto failure;

	rl_cmd->rl_se_cmd = cmd;

	if (!(cmd->t_task = (se_transport_task_t *) kzalloc(
			sizeof(se_transport_task_t), GFP_KERNEL))) {
		TRACE_ERROR("Unable to allocate se_transport_task_t\n");
		goto failure;
	}
	
	init_MUTEX_LOCKED(&T_TASK(cmd)->t_transport_stop_sem);
	spin_lock_init(&T_TASK(cmd)->t_state_lock);
	INIT_LIST_HEAD(&T_TASK(cmd)->t_task_list);

	memcpy(T_TASK(cmd)->t_task_cdb, cdb, SCSI_CDB_SIZE);
	
        if (!(task = kzalloc(sizeof(se_task_t), GFP_KERNEL))) {
                TRACE_ERROR("Unable to allocate se_task_t\n");
		goto failure;
	}

	INIT_LIST_HEAD(&task->t_list);
	init_MUTEX_LOCKED(&task->task_stop_sem);
	task->task_no = 0;
	task->task_se_cmd = cmd;
	task->se_dev = ISCSI_DEV(cmd);
	task->transport_req = (void *) rl_cmd;

        spin_lock_irqsave(&T_TASK(cmd)->t_state_lock, flags);
        list_add(&task->t_list, &T_TASK(cmd)->t_task_list);
        spin_unlock_irqrestore(&T_TASK(cmd)->t_state_lock, flags);
	
	if (transport_allocate_iovecs_for_cmd(cmd, TRANSPORT_IOV_DATA_BUFFER + 1) < 0)
		goto failure;

	transport_set_supported_SAM_opcode(cmd);

	return(0);
failure:
	if (ISCSI_LUN(cmd)) {
		if (ISCSI_DEV(cmd)) {
			kfree(ISCSI_DEV(cmd));
			cmd->se_lun->se_dev = NULL;
		}
		kfree(ISCSI_LUN(cmd));
		cmd->se_lun = NULL;
	}
	if (T_TASK(cmd)) {
		kfree(cmd->t_task);
		cmd->t_task = NULL;
	}
	kfree(task);

	if (rl_cmd) {
		if (rl_cmd->rl_buf) {
			kfree(rl_cmd->rl_buf);
			rl_cmd->rl_buf = NULL;
		}
		kfree(rl_cmd);
	}
	return(-1);
}

/*	iscsi_build_report_luns_response():
 *
 *
 */
extern int iscsi_build_report_luns_response (
	se_cmd_t *se_cmd)
{
	unsigned char *buf = NULL;
	u32 cdb_offset = 0, lun_count = 0, offset = 8;
	u64 i, lun;
	se_dev_entry_t *deve;
	se_lun_t *se_lun;
	se_session_t *sess = SE_SESS(se_cmd);
	se_task_t *task;
	rl_cmd_t *rl_cmd;
	
	list_for_each_entry(task, &T_TASK(se_cmd)->t_task_list, t_list) {
		rl_cmd = (rl_cmd_t *) task->transport_req;
		buf = rl_cmd->rl_buf;
	}
	
	spin_lock_bh(&SE_NODE_ACL(sess)->device_list_lock);
	for (i = 0; i < ISCSI_MAX_LUNS_PER_TPG; i++) {
		deve = &SE_NODE_ACL(sess)->device_list[i];
		if (!(deve->lun_flags & TRANSPORT_LUNFLAGS_INITIATOR_ACCESS))
			continue;
		se_lun = deve->se_lun;

		/*
		 * We determine the correct LUN LIST LENGTH even once we
		 * have reached the initial allocation length.
		 * See SPC2-R20 7.19.
		 */
		lun_count++;
		if ((cdb_offset + 8) > se_cmd->data_length)
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
	spin_unlock_bh(&SE_NODE_ACL(sess)->device_list_lock);

	/*
	 * See SPC3 r07, page 159.
	 */
	lun_count *= 8;
	buf[0] = ((lun_count >> 24) & 0xff);
	buf[1] = ((lun_count >> 16) & 0xff);
	buf[2] = ((lun_count >> 8) & 0xff);
	buf[3] = (lun_count & 0xff);
	
	CMD_TFO(se_cmd)->queue_data_in(se_cmd);

	return(0);
}

/*	rl_check_for_SG():
 *
 *
 */
extern int rl_check_for_SG (se_task_t *task)
{
	return(0);
}

/*	rl_free_task():
 *
 *
 */
extern void rl_free_task (se_task_t *task)
{
	rl_cmd_t *rl_cmd = (rl_cmd_t *) task->transport_req;
	se_cmd_t *se_cmd = rl_cmd->rl_se_cmd;
	
	/*
	 * Free the pseudo device.
	 */
	if (task->se_dev) {
		kfree(task->se_dev);
		task->se_dev = NULL;
	}

	if (se_cmd->se_lun) {
		kfree(se_cmd->se_lun);
		se_cmd->se_lun = NULL;
	}
	
	if (rl_cmd->rl_buf) {
		kfree(rl_cmd->rl_buf);
		rl_cmd->rl_buf = NULL;
	}

	kfree(rl_cmd);
	
	return;
}
