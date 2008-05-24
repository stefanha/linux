/*********************************************************************************
 * Filename:  iscsi_target_transport.c
 *
 * This file contains the iSCSI Target Generic DAS Transport Layer Core.
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


#define ISCSI_TARGET_TRANSPORT_C

#include <linux/version.h>
#include <linux/net.h>
#include <linux/delay.h>
#include <linux/string.h>
#include <linux/timer.h>
#include <linux/slab.h>
#include <linux/blkdev.h>
#include <linux/spinlock.h>
#include <linux/smp_lock.h>
#include <linux/in.h>
#include <net/sock.h>
#include <net/tcp.h>
//#include <asm/div64.h>
#include <scsi/scsi.h>
#include <scsi/scsi_cmnd.h>

#include <iscsi_linux_os.h>
#include <iscsi_linux_defs.h>
        
#include <iscsi_debug.h>
#include <iscsi_protocol.h>
#include <iscsi_lists.h>
#include <iscsi_target_core.h>
#include <iscsi_target_error.h>
#include <iscsi_target_ioctl.h>
#include <iscsi_target_ioctl_defs.h>
#include <iscsi_target_cache.h>
#include <iscsi_target_device.h>
#include <iscsi_target_erl0.h>
#include <iscsi_target_erl1.h>
#include <iscsi_target_hba.h>
#include <iscsi_target_ra.h>
#include <iscsi_target_scdb.h>
#include <iscsi_target_tpg.h>
#include <iscsi_target_util.h>
#include <iscsi_target_transport.h>

#include <iscsi_target_plugin.h>
#include <iscsi_target_seobj.h>
#include <iscsi_target_seobj_plugins.h>
#include <iscsi_target_transport_plugin.h>
#include <iscsi_target_feature_obj.h>
#include <iscsi_target_feature_plugins.h>

#undef ISCSI_TARGET_TRANSPORT_C

//#define DEBUG_CDB_HANDLER
#ifdef DEBUG_CDB_HANDLER
#define DEBUG_CDB_H(x...) PYXPRINT(x)
#else
#define DEBUG_CDB_H(x...)
#endif

//#define DEBUG_CMD_MAP
#ifdef DEBUG_CMD_MAP
#define DEBUG_CMD_M(x...) PYXPRINT(x)
#else
#define DEBUG_CMD_M(x...)
#endif

//#define DEBUG_MEM_ALLOC
#ifdef DEBUG_MEM_ALLOC
#define DEBUG_MEM(x...) PYXPRINT(x)
#else
#define DEBUG_MEM(x...)
#endif

//#define DEBUG_MEM2_ALLOC
#ifdef DEBUG_MEM2_ALLOC
#define DEBUG_MEM2(x...) PYXPRINT(x)
#else
#define DEBUG_MEM2(x...)
#endif

//#define DEBUG_SG_CALC
#ifdef DEBUG_SG_CALC
#define DEBUG_SC(x...) PYXPRINT(x)
#else
#define DEBUG_SC(x...)
#endif

//#define DEBUG_SE_OBJ
#ifdef DEBUG_SE_OBJ
#define DEBUG_SO(x...) PYXPRINT(x)
#else
#define DEBUG_SO(x...)
#endif

//#define DEBUG_CMD_JBOD
#ifdef DEBUG_CMD_JBOD
#define DEBUG_JBOD(x...) PYXPRINT(x)
#else
#define DEBUG_JBOD(x...)
#endif

//#define DEBUG_CMD_STRIPE
#ifdef DEBUG_CMD_STRIPE
#define DEBUG_STRIPE(x...) PYXPRINT(x)
#else
#define DEBUG_STRIPE(x...)
#endif

//#define DEBUG_CMD_VOL
#ifdef DEBUG_CMD_VOL
#define DEBUG_VOL(x...) PYXPRINT(x)
#else
#define DEBUG_VOL(x...)
#endif

//#define DEBUG_CMD_STOP
#ifdef DEBUG_CMD_STOP
#define DEBUG_CS(x...) PYXPRINT(x)
#else
#define DEBUG_CS(x...)
#endif

//#define DEBUG_PASSTHROUGH
#ifdef DEBUG_PASSTHROUGH
#define DEBUG_PT(x...) PYXPRINT(x)
#else
#define DEBUG_PT(x...)
#endif

//#define DEBUG_TASK_STOP
#ifdef DEBUG_TASK_STOP
#define DEBUG_TS(x...) PYXPRINT(x)
#else
#define DEBUG_TS(x...)
#endif

//#define DEBUG_TRANSPORT_STOP
#ifdef DEBUG_TRANSPORT_STOP
#define DEBUG_TRANSPORT_S(x...) PYXPRINT(x)
#else
#define DEBUG_TRANSPORT_S(x...)
#endif

//#define DEBUG_TASK_FAILURE
#ifdef DEBUG_TASK_FAILURE
#define DEBUG_TF(x...) PYXPRINT(x)
#else
#define DEBUG_TF(x...)
#endif

//#define DEBUG_DEV_OFFLINE
#ifdef DEBUG_DEV_OFFLINE
#define DEBUG_DO(x...) PYXPRINT(x)
#else
#define DEBUG_DO(x...)
#endif

//#define DEBUG_TASK_STATE
#ifdef DEBUG_TASK_STATE
#define DEBUG_TSTATE(x...) PYXPRINT(x)
#else
#define DEBUG_TSTATE(x...)
#endif

//#define DEBUG_STATUS_THR
#ifdef DEBUG_STATUS_THR
#define DEBUG_ST(x...) PYXPRINT(x)
#else
#define DEBUG_ST(x...)
#endif

//#define DEBUG_TASK_TIMEOUT
#ifdef DEBUG_TASK_TIMEOUT
#define DEBUG_TT(x...) PYXPRINT(x)
#else
#define DEBUG_TT(x...)
#endif

//#define DEBUG_GENERIC_REQUEST_FAILURE
#ifdef DEBUG_GENERIC_REQUEST_FAILURE
#define DEBUG_GRF(x...) PYXPRINT(x)
#else
#define DEBUG_GRF(x...)
#endif

extern se_global_t *iscsi_global;
extern int iscsi_build_r2ts_for_cmd (iscsi_cmd_t *, iscsi_conn_t *, int);
extern int iscsi_release_sessions_for_tpg (iscsi_portal_group_t *, int);
extern int iscsi_stop_session (iscsi_session_t *, int, int);
static void transport_release_cmd_to_pool (iscsi_cmd_t *);
static int transport_generic_write_pending (iscsi_cmd_t *);
static int transport_processing_thread (void *);

#ifdef DEBUG_DEV

//#warning FIXME: PLUGIN API TODO
extern int __iscsi_debug_dev (se_device_t *dev)
{
	int fail_task = 0;
	fd_dev_t *fd_dev;
	vt_dev_t *vt_dev;
	mc_dev_t *mc_dev;
	rd_dev_t *rd_dev;
	struct scsi_device *sd;

	spin_lock(&iscsi_global->debug_dev_lock);
	switch (dev->iscsi_hba->type) {
	case PSCSI:
		sd = (struct scsi_device *) dev->dev_ptr;
		if (dev->dev_flags & DF_DEV_DEBUG) {
			TRACE_ERROR("iSCSI_HBA[%u] - Failing PSCSI Task for %d/%d/%d\n",
				dev->iscsi_hba->hba_id, sd->channel, sd->id, sd->lun);
			fail_task = 1;
		}
		break;
	case FILEIO:    
		fd_dev = (fd_dev_t *) dev->dev_ptr;
		if (dev->dev_flags & DF_DEV_DEBUG) {
			TRACE_ERROR("iSCSI_HBA[%u] - Failing FILEIO Task for %u\n",
				dev->iscsi_hba->hba_id, fd_dev->fd_dev_id);
			fail_task = 1;
		}
		break;
	case VTAPE:    
		vt_dev = (vt_dev_t *) dev->dev_ptr;
		if (dev->dev_flags & DF_DEV_DEBUG) {
			TRACE_ERROR("iSCSI_HBA[%u] - Failing VTAPE Task for %u\n",
				dev->iscsi_hba->hba_id, vt_dev->vt_dev_id);
			fail_task = 1;
		}
		break;
	case MEDIA_CHANGER:    
		mc_dev = (mc_dev_t *) dev->dev_ptr;
		if (dev->dev_flags & DF_DEV_DEBUG) {
			TRACE_ERROR("iSCSI_HBA[%u] - Failing MEDIA_CHANGER Task for %u\n",
				dev->iscsi_hba->hba_id, mc_dev->mc_dev_id);
			fail_task = 1;
		}
		break;
	case RAMDISK_DR:
	case RAMDISK_MCP:
		rd_dev = (rd_dev_t *) dev->dev_ptr;
		if (dev->dev_flags & DF_DEV_DEBUG) {
			TRACE_ERROR("iSCSI_HBA[%u] - Failing RAMDISK Task for %u\n",
				dev->iscsi_hba->hba_id, rd_dev->rd_dev_id);
			fail_task = 1;
		}
		break;
	default:
		if (dev->dev_flags & DF_DEV_DEBUG) {
			TRACE_ERROR("iSCSI_HBA[%u] - Failing unknown Task\n",
				dev->iscsi_hba->hba_id);
			fail_task = 1;
		}
		break;
	}
	spin_unlock(&iscsi_global->debug_dev_lock);

	return(fail_task);
}

//#warning FIXME: PLUGIN API TODO
extern int iscsi_debug_dev (se_device_t *dev)
{
	int fail_task = 0;
	fd_dev_t *fd_dev;
	vt_dev_t *vt_dev;
	mc_dev_t *mc_dev;
	rd_dev_t *rd_dev;
	struct scsi_device *sd;

	spin_lock_irq(&iscsi_global->debug_dev_lock);
	switch (dev->iscsi_hba->type) {
	case PSCSI:
		sd = (struct scsi_device *) dev->dev_ptr;
		if (dev->dev_flags & DF_DEV_DEBUG) {
			TRACE_ERROR("iSCSI_HBA[%u] - Failing PSCSI Task for %d/%d/%d\n",
				dev->iscsi_hba->hba_id, sd->channel, sd->id, sd->lun);
			fail_task = 1;
		}
		break;
	case FILEIO:
		fd_dev = (fd_dev_t *) dev->dev_ptr;
		if (dev->dev_flags & DF_DEV_DEBUG) {
			TRACE_ERROR("iSCSI_HBA[%u] - Failing FILEIO Task for %u\n",
				dev->iscsi_hba->hba_id, fd_dev->fd_dev_id);
			fail_task = 1;
		}
		break;
	case VTAPE:
		vt_dev = (vt_dev_t *) dev->dev_ptr;
		if (dev->dev_flags & DF_DEV_DEBUG) {
			TRACE_ERROR("iSCSI_HBA[%u] - Failing VTAPE Task for %u\n",
				dev->iscsi_hba->hba_id, vt_dev->vt_dev_id);
			fail_task = 1;
		}
		break;
	case MEDIA_CHANGER:
		mc_dev = (mc_dev_t *) dev->dev_ptr;
		if (dev->dev_flags & DF_DEV_DEBUG) {
			TRACE_ERROR("iSCSI_HBA[%u] - Failing MEDIA_CHANGER Task for %u\n",
				dev->iscsi_hba->hba_id, mc_dev->mc_dev_id);
			fail_task = 1;
		}
		break;
	case RAMDISK_DR:
	case RAMDISK_MCP:
		rd_dev = (rd_dev_t *) dev->dev_ptr;
		if (dev->dev_flags & DF_DEV_DEBUG) {
			TRACE_ERROR("iSCSI_HBA[%u] - Failing RAMDISK Task for %u\n",
				dev->iscsi_hba->hba_id, rd_dev->rd_dev_id);
			fail_task = 1;
		}
		break;
	default:
		if (dev->dev_flags & DF_DEV_DEBUG) {
			TRACE_ERROR("iSCSI_HBA[%u] - Failing unknown Task\n",
				dev->iscsi_hba->hba_id);
			fail_task = 1;
		}
		break;
	}
	spin_unlock_irq(&iscsi_global->debug_dev_lock);
	
	return(fail_task);
}
#endif /* DEBUG_DEV */

extern unsigned char *transport_get_iqn_sn (void)
{
	unsigned char *iqn = NULL;

	if ((iqn = strstr(iscsi_global->targetname, ":sn.")))
		iqn += 1; /* Skip over : */
	else {
		TRACE_ERROR("iSCSI TargetNode name does not contain \":sn.\","
			" using first %u characters for uniqueness\n",
				ISCSI_IQN_UNIQUENESS);

		if (strlen(iscsi_global->targetname) >= ISCSI_IQN_UNIQUENESS)
			iqn = (iscsi_global->targetname +
			      (strlen(iscsi_global->targetname) - ISCSI_IQN_UNIQUENESS));
		else
			iqn = &iscsi_global->targetname[0];
	}

	return(iqn);
}

extern void transport_init_queue_obj (se_queue_obj_t *qobj)
{
	init_MUTEX_LOCKED(&qobj->thread_sem);
	init_MUTEX_LOCKED(&qobj->thread_create_sem);
	init_MUTEX_LOCKED(&qobj->thread_done_sem);
	spin_lock_init(&qobj->cmd_queue_lock);

	return;
}

extern void transport_load_plugins (void)
{
	int ret = 0;
	
#ifdef PARALLEL_SCSI
	plugin_register((void *)&pscsi_template, pscsi_template.type,
			pscsi_template.name, PLUGIN_TYPE_TRANSPORT,
			pscsi_template.get_plugin_info, &ret);
#endif
#ifdef PYX_IBLOCK
	plugin_register((void *)&iblock_template, iblock_template.type,
			iblock_template.name, PLUGIN_TYPE_TRANSPORT,
			iblock_template.get_plugin_info, &ret);
#endif
#ifdef PYX_RAMDISK
	plugin_register((void *)&rd_dr_template, rd_dr_template.type,
			rd_dr_template.name, PLUGIN_TYPE_TRANSPORT,
			rd_dr_template.get_plugin_info, &ret);
	plugin_register((void *)&rd_mcp_template, rd_mcp_template.type,
			rd_mcp_template.name, PLUGIN_TYPE_TRANSPORT,
			rd_mcp_template.get_plugin_info, &ret);
#endif
#ifdef PYX_FILEIO
	plugin_register((void *)&fileio_template, fileio_template.type,
			fileio_template.name, PLUGIN_TYPE_TRANSPORT,
			fileio_template.get_plugin_info, &ret);
#endif
#ifdef PYX_VROM
        plugin_register((void *)&vrom_template, vrom_template.type,
                        vrom_template.name, PLUGIN_TYPE_TRANSPORT,
                        vrom_template.get_plugin_info, &ret);
#endif
#ifdef PYX_VTAPE
	plugin_register((void *)&vtape_template, vtape_template.type,
			vtape_template.name, PLUGIN_TYPE_TRANSPORT,
			vtape_template.get_plugin_info, &ret);
#endif
#ifdef PYX_MEDIA_CHANGER
	plugin_register((void *)&mc_template, mc_template.type,
			mc_template.name, PLUGIN_TYPE_TRANSPORT,
			mc_template.get_plugin_info, &ret);
#endif
	return;
}

static se_device_t *transport_scan_hbas_for_evpd_sn (
	unsigned char *buf,
	u32 len)
{
	u32 i;
	se_device_t *dev = NULL;
	se_hba_t *hba;

	spin_lock(&iscsi_global->hba_lock);
	for (i = 0; i < ISCSI_MAX_GLOBAL_HBAS; i++) {
		hba = &iscsi_global->hba_list[i];

		if (hba->hba_status != HBA_STATUS_ACTIVE)
			continue;

		spin_lock(&hba->device_lock);
		for (dev = hba->device_head; dev; dev = dev->next) {
			if (DEV_OBJ_API(dev)->check_online((void *)dev) != 0) {
				DEBUG_SO("obj_api->check_online() failed!\n");
				continue;
			}
			DEBUG_SO("t10_wwn->unit_serial: %s\n",
				dev->t10_wwn.unit_serial);
			DEBUG_SO("buf: %s\n", buf);

			if (!(strncmp(dev->t10_wwn.unit_serial, buf, len))) {
				spin_unlock(&hba->device_lock);
				spin_unlock(&iscsi_global->hba_lock);
				return(!(__core_get_hba_from_id(hba)) ? NULL : dev);
			}
		}
		spin_unlock(&hba->device_lock);
	}
	spin_unlock(&iscsi_global->hba_lock);

	return(NULL);
}

static se_device_t *transport_scan_hbas_for_evpd_di (
	unsigned char *buf,
	u32 len)
{
	u32 i;
	se_device_t *dev = NULL;
	se_hba_t *hba;

	spin_lock(&iscsi_global->hba_lock);
	for (i = 0; i < ISCSI_MAX_GLOBAL_HBAS; i++) {
		hba = &iscsi_global->hba_list[i];

		if (hba->hba_status != HBA_STATUS_ACTIVE)
			continue;

		spin_lock(&hba->device_lock);
		for (dev = hba->device_head; dev; dev = dev->next) {
			if (DEV_OBJ_API(dev)->check_online((void *)dev) != 0) {
				DEBUG_SO("obj_api->check_online() failed!\n");
				continue;
			}
			DEBUG_SO("t10_wwn->device_identifier: %s\n",
				dev->t10_wwn.device_identifier);
			DEBUG_SO("buf: %s\n", buf);

			if (!(strncmp(dev->t10_wwn.device_identifier, buf, len))) {
				spin_unlock(&hba->device_lock);
				spin_unlock(&iscsi_global->hba_lock);
				return(!(__core_get_hba_from_id(hba)) ? NULL : dev);
			}
		}
		spin_unlock(&hba->device_lock);
	}
	spin_unlock(&iscsi_global->hba_lock);

	return(NULL);
}

#ifdef PYX_IBLOCK

static se_device_t *transport_scan_hbas_for_major_minor (
	int major,
	int minor)
{
	iblock_dev_t *ib_dev = NULL;
	se_device_t *dev = NULL;
	se_hba_t *hba;
	int i;

	spin_lock(&iscsi_global->hba_lock);
	for (i = 0; i < ISCSI_MAX_GLOBAL_HBAS; i++) {
		hba = &iscsi_global->hba_list[i];

		if (hba->hba_status != HBA_STATUS_ACTIVE)
			continue;
		/*
		 * Assume only iblock for now, but this could be used
		 * for PSCSI and FILE eventually as well.
		 */
		if (hba->type != IBLOCK)
			continue;

		spin_lock(&hba->device_lock);
		for (dev = hba->device_head; dev; dev = dev->next) {
			if (DEV_OBJ_API(dev)->check_online((void *)dev) != 0) {
				DEBUG_SO("obj_api->check_online() failed!\n");
				continue;
			}
			if (!(ib_dev = (iblock_dev_t *)dev->dev_ptr)) {
				TRACE_ERROR("Could not locate ptr from dev->dev_ptr!\n");
				continue;
			}

			if ((ib_dev->ibd_major == major) &&
			    (ib_dev->ibd_minor == minor)) {
				spin_unlock(&hba->device_lock);
				spin_unlock(&iscsi_global->hba_lock);
				return(!(__core_get_hba_from_id(hba)) ? NULL : dev);
			}
		}
		spin_unlock(&hba->device_lock);
	}
	spin_unlock(&iscsi_global->hba_lock);

	return(NULL);
}

#endif /* PYX_IBLOCK */

extern se_device_t *transport_core_locate_dev (
	struct iscsi_target *tg,
	se_dev_transport_info_t *dti,
	int *ret)
{
	se_device_t *dev = NULL;
	se_hba_t *hba;

	dti->iscsi_lun = tg->iscsi_lun;
	dti->force = tg->force;

	if (tg->params_set & PARAM_QUEUE_DEPTH) {
		dti->check_tcq = 1;
		dti->queue_depth = tg->queue_depth;
	}

	if (tg->params_set & PARAM_EVPD_UNIT_SERIAL) {
		if (!(dev = transport_scan_hbas_for_evpd_sn(tg->value,
				strlen(tg->value)))) {
			TRACE_ERROR("Unable to locate se_device_t from EVPD SN:"
					" %s\n", tg->value);
			*ret = ERR_ADDLUN_GET_DEVICE_FAILED;
			return(NULL);
		}
		return(dev);
	} else if (tg->params_set & PARAM_EVPD_DEVICE_IDENT) {
		if (!(dev = transport_scan_hbas_for_evpd_di(tg->value,
				strlen(tg->value)))) {
			TRACE_ERROR("Unable to locate se_device_t from EVPD DI:"
					" %s\n", tg->value);
			*ret = ERR_ADDLUN_GET_DEVICE_FAILED;
			return(NULL);
		}
		return(dev);
		/*
		 * Special case for non createvirtdev usage with hba_id parameter
		 * using major/minor location.
		 */
	} else if ((tg->hba_params_set & PARAM_HBA_IBLOCK_MAJOR) &&
	    	   (tg->hba_params_set & PARAM_HBA_IBLOCK_MINOR) &&
		   !(tg->params_set & PARAM_HBA_ID)) {
			if (!(dev = transport_scan_hbas_for_major_minor(tg->iblock_major,
						tg->iblock_minor))) {
				TRACE_ERROR("Unable to locate se_device_t from %d:%d",
						tg->iblock_major, tg->iblock_minor);
				*ret = ERR_ADDLUN_GET_DEVICE_FAILED;
				return(NULL);
			}
			return(dev);
	} else {
		if (!(hba = core_get_hba_from_hbaid(tg, dti, 1))) {
			*ret = ERR_HBA_CANNOT_LOCATE;
			return(NULL);
		}

		if (!(hba = __core_get_hba_from_id(hba))) {
			*ret = ERR_HBA_CANNOT_LOCATE;
			return(NULL);
		}

		if (!(dev = core_get_device_from_transport(hba, dti))) {
			TRACE_ERROR("Unable to locate se_device_t on iSCSI HBA:"
				" %u\n", hba->hba_id);
			core_put_hba(hba);
			*ret = ERR_ADDLUN_GET_DEVICE_FAILED;
			return(NULL);
		}

		return(dev);
	}

	return(dev);
}

/*
 * Called with T_TASK(cmd)->t_state_lock held.
 */
static void transport_all_task_dev_remove_state (iscsi_cmd_t *cmd)
{
	se_device_t *dev;
	se_task_t *task;
	unsigned long flags;

	if (!T_TASK(cmd))
		return;

	list_for_each_entry(task, &T_TASK(cmd)->t_task_list, t_list) {
		if (!(dev = task->iscsi_dev))
			continue;
		
		if (atomic_read(&task->task_active))
			continue;
		
		if (!(atomic_read(&task->task_state_active)))
			continue;

		spin_lock_irqsave(&dev->execute_task_lock, flags);
                REMOVE_ENTRY_FROM_LIST_PREFIX(ts, task,
                        dev->state_task_head, dev->state_task_tail);
		DEBUG_TSTATE("Removed ITT: 0x%08x dev: %p task[%p]\n", cmd->init_task_tag, dev, task);
                spin_unlock_irqrestore(&dev->execute_task_lock, flags);

		atomic_set(&task->task_state_active, 0);
		atomic_dec(&T_TASK(cmd)->t_task_cdbs_ex_left);
	}

	return;
}

/*
 * Called with T_TASK(cmd)->t_state_lock held.
 */
extern void transport_task_dev_remove_state (se_task_t *task, se_device_t *dev)
{
	iscsi_cmd_t *cmd = task->iscsi_cmd;
	unsigned long flags;
	
	/*
	 * We cannot remove the task from the state list while said task is
	 * still active and probably timed out.
	 */
	if (atomic_read(&task->task_active)) {
#if 0
		TRACE_ERROR("Skipping Removal of state for ITT: 0x%08x dev: %p task[%p]\n",
				task->iscsi_cmd->init_task_tag, dev, task);
#endif
		return;
	}

	if (atomic_read(&task->task_state_active)) {
		spin_lock_irqsave(&dev->execute_task_lock, flags);
		REMOVE_ENTRY_FROM_LIST_PREFIX(ts, task,
			dev->state_task_head, dev->state_task_tail);
		DEBUG_TSTATE("Removed ITT: 0x%08x dev: %p task[%p]\n",
				task->iscsi_cmd->init_task_tag, dev, task);
		spin_unlock_irqrestore(&dev->execute_task_lock, flags);

		atomic_set(&task->task_state_active, 0);
		atomic_dec(&T_TASK(cmd)->t_task_cdbs_ex_left);
	}

	return;
}

static void transport_passthrough_check_stop (iscsi_cmd_t *cmd)
{
	if (!(cmd->cmd_flags & ICF_CMD_PASSTHROUGH))
		return;

	if (!cmd->transport_passthrough_done) {
		
		if (cmd->callback)
		{
			cmd->callback(cmd, cmd->callback_arg, transport_passthrough_complete(cmd));
		}
		else
		{
			up(&T_TASK(cmd)->t_transport_passthrough_sem);
		}
		return;
	}

	cmd->transport_passthrough_done(cmd);
	return;
}

/*	transport_cmd_check_stop():
 *
 *	'transport_off = 1' determines if t_transport_active should be cleared.
 *	'transport_off = 2' determines if task_dev_state should be removed.
 *
 *	A non-zero u8 t_state sets cmd->t_state.
 *	Returns 1 when command is stopped, else 0.
 */
static int transport_cmd_check_stop (iscsi_cmd_t *cmd, int transport_off, u8 t_state)
{
	unsigned long flags;

	spin_lock_irqsave(&T_TASK(cmd)->t_state_lock, flags);
	/*
	 * Determine if IOCTL context caller in requesting the stopping of this command
	 * for LUN shutdown purposes.
	 */
	if (atomic_read(&T_TASK(cmd)->transport_lun_stop)) {
		DEBUG_CS("%s:%d atomic_read(&T_TASK(cmd)->transport_lun_stop) == TRUE"
			" for ITT: 0x%08x\n", __FUNCTION__, __LINE__, cmd->init_task_tag);

		cmd->deferred_t_state = cmd->t_state;
		cmd->t_state = TRANSPORT_DEFERRED_CMD;
		atomic_set(&T_TASK(cmd)->t_transport_active, 0);
		if (transport_off == 2)
			transport_all_task_dev_remove_state(cmd);
		spin_unlock_irqrestore(&T_TASK(cmd)->t_state_lock, flags);

		up(&T_TASK(cmd)->transport_lun_stop_sem);
		return(1);
	}
	/*
	 * Determine if frontend context caller is requesting the stopping of this
	 * command for frontend excpections.
	 */
	if (atomic_read(&T_TASK(cmd)->t_transport_stop)) {
		DEBUG_CS("%s:%d atomic_read(&T_TASK(cmd)->t_transport_stop) == TRUE"
			" for ITT: 0x%08x\n", __FUNCTION__, __LINE__, cmd->init_task_tag);

		cmd->deferred_t_state = cmd->t_state;
		cmd->t_state = TRANSPORT_DEFERRED_CMD;
		if (transport_off == 2)
			transport_all_task_dev_remove_state(cmd);

		/*
		 * Clear iscsi_cmd_t->iscsi_lun before the transport_off == 2 handoff
		 * to FE.
		 */
		if ((transport_off == 2) && !(cmd->cmd_flags & ICF_CMD_PASSTHROUGH))
			cmd->iscsi_lun = NULL;
		spin_unlock_irqrestore(&T_TASK(cmd)->t_state_lock, flags);
		
		up(&T_TASK(cmd)->t_transport_stop_sem);
		return(1);
	}
	if (transport_off) {
		atomic_set(&T_TASK(cmd)->t_transport_active, 0);
		if (transport_off == 2)
			transport_all_task_dev_remove_state(cmd);

		/*
		 * Clear iscsi_cmd_t->iscsi_lun before the transport_off == 2 handoff
		 * to FE.
		 */
		if ((transport_off == 2) && !(cmd->cmd_flags & ICF_CMD_PASSTHROUGH))
			cmd->iscsi_lun = NULL;
		spin_unlock_irqrestore(&T_TASK(cmd)->t_state_lock, flags);

		return(0);
	} else if (t_state)
		cmd->t_state = t_state;
	spin_unlock_irqrestore(&T_TASK(cmd)->t_state_lock, flags);

	return(0);
}

static void transport_lun_remove_cmd (iscsi_cmd_t *cmd)
{
	se_lun_t *lun = ISCSI_LUN(cmd);
	unsigned long flags;

	if (!lun) 
		return;
	/*
	 * Do not track passthrough iscsi_cmd_t for now..
	 */
	if (cmd->cmd_flags & ICF_CMD_PASSTHROUGH)
		return;

	/*
	 * REPORT_LUNS will be coming from the FE, and should not
	 * be tracked.
	 */
	if (cmd->cmd_flags & ICF_REPORT_LUNS)
		return;
	
	spin_lock_irqsave(&lun->lun_cmd_lock, flags);
	if (atomic_read(&T_TASK(cmd)->transport_lun_active)) {
		REMOVE_ENTRY_FROM_LIST_PREFIX(l, cmd,
				lun->lun_cmd_head,
				lun->lun_cmd_tail);
		atomic_set(&T_TASK(cmd)->transport_lun_active, 0);
#if 0
		TRACE_ERROR("Removed ITT: 0x%08x from LUN LIST[%d]\n", cmd->init_task_tag, lun->iscsi_lun);
#endif
	}
	spin_unlock_irqrestore(&lun->lun_cmd_lock, flags);
		
	return;
}

extern int transport_add_cmd_to_queue (iscsi_cmd_t *cmd, se_queue_obj_t *qobj, u8 t_state)
{
	iscsi_queue_req_t *qr;
	unsigned long flags;
	
	if (!(qr = kmalloc(sizeof(iscsi_queue_req_t), GFP_ATOMIC))) {
		TRACE_ERROR("Unable to allocate memory for iscsi_queue_req_t\n");
		return(-1);;
	}
	memset(qr, 0, sizeof(iscsi_queue_req_t));

	qr->cmd = cmd;
	qr->state = t_state;
	
	if (t_state) {
		spin_lock_irqsave(&T_TASK(cmd)->t_state_lock, flags);
		cmd->t_state = t_state;
		atomic_set(&T_TASK(cmd)->t_transport_active, 1);
		spin_unlock_irqrestore(&T_TASK(cmd)->t_state_lock, flags); 
	}

	spin_lock_irqsave(&qobj->cmd_queue_lock, flags);
	ADD_ENTRY_TO_LIST(qr, qobj->queue_head, qobj->queue_tail);
	atomic_inc(&T_TASK(cmd)->t_transport_queue_active);
	spin_unlock_irqrestore(&qobj->cmd_queue_lock, flags);

	up(&qobj->thread_sem);

	return(0);
}

static int transport_add_cmd_to_dev_queue (iscsi_cmd_t *cmd, u8 t_state)
{
	se_device_t *dev = cmd->iscsi_dev;
	
	return(transport_add_cmd_to_queue(cmd, dev->dev_queue_obj, t_state));
}

/*
 * Called with se_queue_obj_t->cmd_queue_lock held.
 */
extern iscsi_queue_req_t *__transport_get_qr_from_queue (se_queue_obj_t *qobj)
{
	iscsi_cmd_t *cmd;
	iscsi_queue_req_t *qr;

	if (!qobj->queue_head)
		return(NULL);

	qr = qobj->queue_head;
	if (qr->cmd) {
		cmd = qr->cmd;
		atomic_dec(&T_TASK(cmd)->t_transport_queue_active);
	}

	qobj->queue_head = qobj->queue_head->next;
	qr->next = qr->prev = NULL;

	if (!qobj->queue_head)
		qobj->queue_tail = NULL;
	else
		qobj->queue_head->prev = NULL;

	return(qr);
}
	

extern iscsi_queue_req_t *transport_get_qr_from_queue (se_queue_obj_t *qobj)
{
	iscsi_cmd_t *cmd;
	iscsi_queue_req_t *qr;
	unsigned long flags;

	spin_lock_irqsave(&qobj->cmd_queue_lock, flags);
	if (!qobj->queue_head) {
		spin_unlock_irqrestore(&qobj->cmd_queue_lock, flags);
		return(NULL);
	}

	qr = qobj->queue_head;
	if (qr->cmd) {
		cmd = qr->cmd;
		atomic_dec(&T_TASK(cmd)->t_transport_queue_active);
	}

	qobj->queue_head = qobj->queue_head->next;
	qr->next = qr->prev = NULL;

	if (!qobj->queue_head)
		qobj->queue_tail = NULL;
	else
		qobj->queue_head->prev = NULL;
	spin_unlock_irqrestore(&qobj->cmd_queue_lock, flags);

	return(qr);
}

static void transport_remove_cmd_from_queue (iscsi_cmd_t *cmd, se_queue_obj_t *qobj)
{
	iscsi_cmd_t *q_cmd;
	iscsi_queue_req_t *qr, *qr_next;
	unsigned long flags;

	spin_lock_irqsave(&qobj->cmd_queue_lock, flags);
	if (!(atomic_read(&T_TASK(cmd)->t_transport_queue_active))) {
		spin_unlock_irqrestore(&qobj->cmd_queue_lock, flags);
		return;
	}

	qr = qobj->queue_head;
	while (qr) {
		qr_next = qr->next;

		if (qr->cmd != cmd) {
			qr = qr_next;
			continue;
		}

		q_cmd = qr->cmd;
		atomic_dec(&T_TASK(q_cmd)->t_transport_queue_active);
		REMOVE_ENTRY_FROM_LIST(qr, qobj->queue_head, qobj->queue_tail);
		kfree(qr);

		qr = qr_next;
	}
	spin_unlock_irqrestore(&qobj->cmd_queue_lock, flags);

	if (atomic_read(&T_TASK(cmd)->t_transport_queue_active)) {
		TRACE_ERROR("ITT: 0x%08x t_transport_queue_active: %d\n", cmd->init_task_tag,
				atomic_read(&T_TASK(cmd)->t_transport_queue_active));
	}

	return;
}

extern void transport_complete_cmd (iscsi_cmd_t *cmd, int success)
{
	int t_state;
	unsigned long flags;
	
	spin_lock_irqsave(&T_TASK(cmd)->t_state_lock, flags);
	if (!success) {
		cmd->transport_error_status = PYX_TRANSPORT_LOGICAL_UNIT_COMMUNICATION_FAILURE;
		t_state = TRANSPORT_COMPLETE_FAILURE;
	} else {
		t_state = TRANSPORT_COMPLETE_OK;
	}
	atomic_set(&T_TASK(cmd)->t_transport_complete, 1);
	spin_unlock_irqrestore(&T_TASK(cmd)->t_state_lock, flags);

	cmd->transport_add_cmd_to_queue(cmd, t_state);

	return;
}

/*	transport_complete_task():
 *
 *	Called from interrupt and non interrupt context depending
 *	on the transport plugin.
 */
extern void transport_complete_task (se_task_t *task, int success)
{
	iscsi_cmd_t *cmd = task->iscsi_cmd;
	se_device_t *dev = task->iscsi_dev;
	int t_state;
	unsigned long flags;
#if 0
	TRACE_ERROR("task: %p CDB: 0x%02x obj_ptr: %p\n", task, T_TASK(cmd)->t_task_cdb[0], dev);
#endif	
	if (dev) {
		spin_lock_irqsave(&ISCSI_HBA(dev)->hba_queue_lock, flags);
		atomic_inc(&dev->depth_left);
		atomic_inc(&ISCSI_HBA(dev)->left_queue_depth);
		spin_unlock_irqrestore(&ISCSI_HBA(dev)->hba_queue_lock, flags);
	}

	spin_lock_irqsave(&T_TASK(cmd)->t_state_lock, flags);
	atomic_set(&task->task_active, 0);

	/*
	 * See if any sense data exists, if so set the TASK_SENSE flag.
	 * Also check for any other post completion work that needs to be
	 * done by the plugins.
	 */
	if (!dev)
		goto check_task_stop;

	if (TRANSPORT(dev)->transport_complete(task) != 0) {
		cmd->cmd_flags |= ICF_TRANSPORT_TASK_SENSE;
		task->task_sense = 1;
		success = 1;
	}
	
	/*
	 * See if we are waiting for outstanding se_task_t
	 * to complete for an exception condition
	 */
check_task_stop:
	if (atomic_read(&task->task_stop)) {
		/*
		 * Decrement T_TASK(cmd)->t_se_count if this task had
		 * previously thrown its timeout exception handler.
		 */
		if (atomic_read(&task->task_timeout)) {
			atomic_dec(&T_TASK(cmd)->t_se_count);
			atomic_set(&task->task_timeout, 0);
		}
		spin_unlock_irqrestore(&T_TASK(cmd)->t_state_lock, flags);
		
		up(&task->task_stop_sem);
		return;
	}
	/*
	 * If the task's timeout handler has fired, use the t_task_cdbs_timeout_left
	 * counter to determine when the iscsi_cmd_t is ready to be queued to the
	 * processing thread.
	 */
	if (atomic_read(&task->task_timeout)) {
		if (!(atomic_dec_and_test(&T_TASK(cmd)->t_task_cdbs_timeout_left))) {
			spin_unlock_irqrestore(&T_TASK(cmd)->t_state_lock, flags);
			return;
		}
		t_state = TRANSPORT_COMPLETE_TIMEOUT;
		spin_unlock_irqrestore(&T_TASK(cmd)->t_state_lock, flags);

		cmd->transport_add_cmd_to_queue(cmd, t_state);
		return;
	}
	atomic_dec(&T_TASK(cmd)->t_task_cdbs_timeout_left);

#ifdef DEBUG_DEV
	if (dev) {
		if (__iscsi_debug_dev(dev) != 0) {
			success = 0;
			task->task_scsi_status = 1;
			cmd->transport_error_status = PYX_TRANSPORT_LOGICAL_UNIT_COMMUNICATION_FAILURE;
		}
	}
#endif /* DEBUG_DEV */

	/*
	 * Decrement the outstanding t_task_cdbs_left count.  The last
	 * se_task_t from iscsi_cmd_t will complete itself into the
	 * device queue depending upon int success.
	 */
	if (!(atomic_dec_and_test(&T_TASK(cmd)->t_task_cdbs_left))) {
		if (!success)
			T_TASK(cmd)->t_tasks_failed = 1;

		spin_unlock_irqrestore(&T_TASK(cmd)->t_state_lock, flags);
		return;
	}

	if (!success || T_TASK(cmd)->t_tasks_failed) {
		t_state = TRANSPORT_COMPLETE_FAILURE;
		if (!task->task_error_status) {
			task->task_error_status = PYX_TRANSPORT_UNKNOWN_SAM_OPCODE;
			cmd->transport_error_status = PYX_TRANSPORT_UNKNOWN_SAM_OPCODE;
		}
	} else {
		atomic_set(&T_TASK(cmd)->t_transport_complete, 1);
		t_state = TRANSPORT_COMPLETE_OK;
	}
	spin_unlock_irqrestore(&T_TASK(cmd)->t_state_lock, flags);

	cmd->transport_add_cmd_to_queue(cmd, t_state);

	return;
}

/*	__transport_add_task_to_execute_queue():
 *
 *	Called with iscsi_dev_t->execute_task_lock called.
 */
static void __transport_add_task_to_execute_queue (se_task_t *task, se_device_t *dev)
{
	if (!dev->execute_task_head && !dev->execute_task_tail) {
		dev->execute_task_head = dev->execute_task_tail = task;
		task->t_next = task->t_prev = NULL;
	} else {
		dev->execute_task_tail->t_next	= task;
		task->t_prev = dev->execute_task_tail;
		dev->execute_task_tail = task;
	}
	atomic_inc(&dev->execute_tasks);

	if (atomic_read(&task->task_state_active))
		return;

	ADD_ENTRY_TO_LIST_PREFIX(ts, task, dev->state_task_head, dev->state_task_tail);
	atomic_set(&task->task_state_active, 1);

	DEBUG_TSTATE("Added ITT: 0x%08x task[%p] to dev: %p\n",
		task->iscsi_cmd->init_task_tag, task, dev);

	return;
}

/*	transport_add_task_to_execute_queue():
 *
 *
 */
extern void transport_add_task_to_execute_queue (se_task_t *task, se_device_t *dev)
{
	unsigned long flags;

	spin_lock_irqsave(&dev->execute_task_lock, flags);
	if (!dev->execute_task_head && !dev->execute_task_tail) {
		dev->execute_task_head = dev->execute_task_tail = task;
		task->t_next = task->t_prev = NULL;
	} else {
		dev->execute_task_tail->t_next  = task;
		task->t_prev = dev->execute_task_tail;
		dev->execute_task_tail = task;
	}
	atomic_inc(&dev->execute_tasks);

	if (atomic_read(&task->task_state_active)) {
		spin_unlock_irqrestore(&dev->execute_task_lock, flags);
		return;
	}

	ADD_ENTRY_TO_LIST_PREFIX(ts, task, dev->state_task_head, dev->state_task_tail);
	atomic_set(&task->task_state_active, 1);

	DEBUG_TSTATE("Added ITT: 0x%08x task[%p] to dev: %p\n",
		task->iscsi_cmd->init_task_tag, task, dev);

	spin_unlock_irqrestore(&dev->execute_task_lock, flags);

	return;
}

static void transport_add_tasks_to_state_queue (iscsi_cmd_t *cmd)
{
	se_device_t *dev;
	se_task_t *task;
	unsigned long flags;

	spin_lock_irqsave(&T_TASK(cmd)->t_state_lock, flags);
	list_for_each_entry(task, &T_TASK(cmd)->t_task_list, t_list) {
		dev = task->iscsi_dev;

		if (atomic_read(&task->task_state_active))
			continue;

		spin_lock(&dev->execute_task_lock);
		ADD_ENTRY_TO_LIST_PREFIX(ts, task, dev->state_task_head, dev->state_task_tail);
		atomic_set(&task->task_state_active, 1);

		DEBUG_TSTATE("Added ITT: 0x%08x task[%p] to dev: %p\n",
			task->iscsi_cmd->init_task_tag, task, dev);

		spin_unlock(&dev->execute_task_lock);
	}
	spin_unlock_irqrestore(&T_TASK(cmd)->t_state_lock, flags);

	return;
}

/*	transport_add_tasks_from_cmd():
 *
 *
 */
extern void transport_add_tasks_from_cmd (iscsi_cmd_t *cmd)
{
	se_device_t *dev = ISCSI_DEV(cmd);
	se_task_t *task;
	unsigned long flags;

	spin_lock_irqsave(&dev->execute_task_lock, flags);
	list_for_each_entry(task, &T_TASK(cmd)->t_task_list, t_list) {
		if (atomic_read(&task->task_execute_queue))
			continue;
		
		__transport_add_task_to_execute_queue(task, dev);
		atomic_set(&task->task_execute_queue, 1);
	}
	spin_unlock_irqrestore(&dev->execute_task_lock, flags);

	return;
}

/*	transport_get_task_from_execute_queue():
 *
 *	Called with dev->execute_task_lock held.
 */
extern se_task_t *transport_get_task_from_execute_queue (se_device_t *dev)
{
	se_task_t *task;

	if (!dev->execute_task_head)
		return(NULL);

	task = dev->execute_task_head;
	dev->execute_task_head = dev->execute_task_head->t_next;
	task->t_next = task->t_prev = NULL;

	if (!dev->execute_task_head)
		dev->execute_task_tail = NULL;
	else
		dev->execute_task_head->t_prev = NULL;

	atomic_dec(&dev->execute_tasks);
	
	return(task);
}

/*	transport_remove_task_from_execute_queue():
 *
 *
 */
static void transport_remove_task_from_execute_queue (se_task_t *task, se_device_t *dev)
{
	unsigned long flags;

	spin_lock_irqsave(&dev->execute_task_lock, flags);
	if (!task->t_prev && !task->t_next)
		dev->execute_task_head = dev->execute_task_tail = NULL;
	else {
		if (!task->t_prev) {
			task->t_next->t_prev = NULL;
			dev->execute_task_head = task->t_next;
			if (dev->execute_task_head->t_next)
				dev->execute_task_tail = dev->execute_task_head;
		} else if (task->t_next) {
			task->t_prev->t_next = NULL;
			dev->execute_task_tail = task->t_prev;
		} else {
			task->t_next->t_prev = task->t_prev;	
			task->t_prev->t_next = task->t_next;

		}
		task->t_next = task->t_prev = NULL;
	}
	atomic_dec(&dev->execute_tasks);
	spin_unlock_irqrestore(&dev->execute_task_lock, flags);
		
	return;
}

/*	transport_check_device_tcq():
 *
 *
 */
extern int transport_check_device_tcq (se_device_t *dev, __u32 iscsi_lun, __u32 device_tcq)
{
	if (device_tcq > dev->queue_depth) {
		TRACE_ERROR("Attempting to set storage device queue depth to"
		" %d while transport maximum is %d on iSCSI LUN: %u,"
		" ignoring request\n", device_tcq, dev->queue_depth, iscsi_lun);
		return(-1);
	} else if (!device_tcq) {
		TRACE_ERROR("Attempting to set storage device queue depth to"
			" 0 on iSCSI LUN: %u, ignoring request\n", iscsi_lun);
		return(-1);
	}

	dev->queue_depth = device_tcq;
	atomic_set(&dev->depth_left, dev->queue_depth);
	printk("Reset Device Queue Depth to %u for iSCSI Logical Unit Number:"
			" %u\n", dev->queue_depth, iscsi_lun);

	return(0);
}	

/*	transport_release_all_cmds():
 *
 *
 */
static void transport_release_all_cmds (se_device_t *dev)
{
	iscsi_cmd_t *cmd = NULL;
	iscsi_queue_req_t *qr, *qr_next;
	int bug_out = 0, t_state;
	unsigned long flags;

	spin_lock_irqsave(&dev->dev_queue_obj->cmd_queue_lock, flags);
	qr = dev->dev_queue_obj->queue_head;
	while (qr) {
		qr_next = qr->next;
		spin_unlock_irqrestore(&dev->dev_queue_obj->cmd_queue_lock, flags);

		cmd = qr->cmd;
		t_state = qr->state;
		kfree(qr);

		TRACE_ERROR("Releasing %s ITT: 0x%08x, i_state: %u, t_state: %u directly\n",
			(cmd->cmd_flags & ICF_CMD_PASSTHROUGH) ? "Passthrough" : "Normal",
				cmd->init_task_tag, cmd->i_state, t_state);

		transport_release_fe_cmd(cmd);
		bug_out = 1;

		spin_lock_irqsave(&dev->dev_queue_obj->cmd_queue_lock, flags);
		qr = qr_next;
	}
	spin_unlock_irqrestore(&dev->dev_queue_obj->cmd_queue_lock, flags);
#if 0
	if (bug_out)
		BUG();
#endif	
	return;
}

/*	transport_dev_write_pending_nop():
 *
 *
 */
static int transport_dev_write_pending_nop (se_task_t *task)
{
	return(0);
}

static const char *const scsi_peripheral_types[] = {
	"Direct-Access    ",
	"Sequential-Access",
	"Printer          ",
	"Processor        ",
	"WORM             ",
	"CD-ROM           ",
	"Scanner          ",
	"Optical Device   ",
	"Medium Changer   ",
	"Communications   ",
	"ASC IT8          ",
	"ASC IT8          ",
	"RAID             ",
	"Enclosure        ",
	"Direct-Access-RBC",
	"Optical card     ",
	"Bridge controller",
	"Object storage   ",
	"Automation/Drive ",
};

static const char *scsi_peripheral_type (unsigned type)
{
	if (type == 0x1e)
		return "Well-known LUN   ";
	if (type == 0x1f)
		return "No Device        ";
	if (type >= ARRAY_SIZE(scsi_peripheral_types))
		return "Unknown          ";
	return scsi_peripheral_types[type];
}

static int transport_get_inquiry (se_obj_lun_type_t *obj_api, t10_wwn_t *wwn, void *obj_ptr)
{
	iscsi_cmd_t *cmd;
	unsigned char *buf;
	int i;
	unsigned char cdb[SCSI_CDB_SIZE];
	
	memset(cdb, 0, SCSI_CDB_SIZE);
	cdb[0] = INQUIRY;
	cdb[3] = (INQUIRY_LEN >> 8) & 0xff;
	cdb[4] = (INQUIRY_LEN & 0xff);

	if (!(cmd = transport_allocate_passthrough(&cdb[0], ISCSI_READ, 0, NULL, 0, INQUIRY_LEN,
			 obj_api, obj_ptr))) {
		return(-1);
	}

	if (transport_generic_passthrough(cmd) < 0) { 
		transport_passthrough_release(cmd);
		return(-1);
	}

	buf = (unsigned char *)T_TASK(cmd)->t_task_buf;
	/*
	 * Save the basic Vendor, Model and Revision in passed t10_wwn_t.  We will
	 * obtain the EVPD in a seperate passthrough operation.
	 */
	memcpy((void *)&wwn->vendor[0], (void *)&buf[8], sizeof(wwn->vendor));
	memcpy((void *)&wwn->model[0], (void *)&buf[16], sizeof(wwn->model));
	memcpy((void *)&wwn->revision[0], (void *)&buf[32], sizeof(wwn->revision));

	PYXPRINT("  Vendor: ");
	for (i = 8; i < 16; i++)
		if (buf[i] >= 0x20 && i < buf[4] + 5)
                        PYXPRINT("%c", buf[i]);
                else
                        PYXPRINT(" ");

	PYXPRINT("  Model: ");
	for (i = 16; i < 32; i++)
                if (buf[i] >= 0x20 && i < buf[4] + 5)
                        PYXPRINT("%c", buf[i]);
                else
                        PYXPRINT(" ");

	PYXPRINT("  Revision: ");
	for (i = 32; i < 36; i++)
                if (buf[i] >= 0x20 && i < buf[4] + 5)
                        PYXPRINT("%c", buf[i]);
                else    
                        PYXPRINT(" ");
	                        
        PYXPRINT("\n");           

	i = buf[0] & 0x1f;
	                        
	PYXPRINT("  Type:   %s ", scsi_peripheral_type(i));
	PYXPRINT("                 ANSI SCSI revision: %02x",
	               buf[2] & 0x07);
        if ((buf[2] & 0x07) == 1 && (buf[3] & 0x0f) == 1)
                PYXPRINT(" CCS\n");
        else    
                PYXPRINT("\n");

	transport_passthrough_release(cmd);
		
	return(0);
}

static int transport_get_inquiry_evpd_serial (se_obj_lun_type_t *obj_api, t10_wwn_t *wwn, void *obj_ptr)
{
	unsigned char *buf;
	iscsi_cmd_t *cmd;
	unsigned char cdb[SCSI_CDB_SIZE]; 

	memset(cdb, 0, SCSI_CDB_SIZE);
	cdb[0] = INQUIRY;
	cdb[1] = 0x01; /* Query EVPD */
	cdb[2] = 0x80; /* Unit Serial Number */ 
	cdb[3] = (INQUIRY_EVPD_SERIAL_LEN >> 8) & 0xff;;
	cdb[4] = (INQUIRY_EVPD_SERIAL_LEN & 0xff);

	if (!(cmd = transport_allocate_passthrough(&cdb[0], ISCSI_READ, 0, NULL, 0,
			INQUIRY_EVPD_SERIAL_LEN, obj_api, obj_ptr))) {
		return(-1);
	}

	if (transport_generic_passthrough(cmd) < 0) { 
		transport_passthrough_release(cmd);
		return(-1);
	}

	buf = (unsigned char *)T_TASK(cmd)->t_task_buf;

	PYXPRINT("T10 EVPD Unit Serial Number: %s\n", &buf[4]);
	snprintf(&wwn->unit_serial[0], INQUIRY_EVPD_SERIAL_LEN, "%s", &buf[4]); 

	transport_passthrough_release(cmd);

	return(0);
}

static int transport_get_inquiry_evpd_device_ident (se_obj_lun_type_t *obj_api, t10_wwn_t *wwn, void *obj_ptr)
{
	unsigned char *buf;
	iscsi_cmd_t *cmd;
	unsigned char cdb[SCSI_CDB_SIZE];

	memset(cdb, 0, SCSI_CDB_SIZE);
	cdb[0] = INQUIRY;
	cdb[1] = 0x01; /* Query EVPD */
	cdb[2] = 0x83; /* Device Identifier */
	cdb[3] = (INQUIRY_EVPD_DEVICE_IDENTIFIER_LEN >> 8) & 0xff;
	cdb[4] = (INQUIRY_EVPD_DEVICE_IDENTIFIER_LEN & 0xff);

	if (!(cmd = transport_allocate_passthrough(&cdb[0], ISCSI_READ, 0, NULL, 0,
			INQUIRY_EVPD_DEVICE_IDENTIFIER_LEN, obj_api, obj_ptr))) {
		return(-1);
	}

	if (transport_generic_passthrough(cmd) < 0) {
		transport_passthrough_release(cmd);
		return(-1);
	}

	buf = (unsigned char *)T_TASK(cmd)->t_task_buf;
	wwn->device_identifier_code_set = (buf[4] & 0x0f);

//#warning FIXME v2.8: Finish up EVPD Device Identifier support for Binary + UTF-8 encodings
	switch (wwn->device_identifier_code_set) {
#if 0
	case 0x01: /* Binary */
		break;
#endif
	case 0x02: /* ASCII */
		PYXPRINT("T10 EVPD Device Identifier: %s\n", &buf[8]);
		snprintf(&wwn->device_identifier[0], INQUIRY_EVPD_DEVICE_IDENTIFIER_LEN, "%s", &buf[8]);
		break;
#if 0
	case 0x03: /* UTF-8 */
		break;
#endif
	default:
		PYXPRINT("T10 EVPD Device Identifier encoding unsupported: %02x\n", buf[4]);
		break;
	}

	transport_passthrough_release(cmd);

	return(0);
}

static int transport_get_read_capacity (se_device_t *dev)
{
	unsigned char cdb[SCSI_CDB_SIZE], *buf;
	u32 blocks, v1, v2;
	iscsi_cmd_t *cmd;
	unsigned long long blocks_long;

	memset(cdb, 0, SCSI_CDB_SIZE);
	cdb[0] = 0x25; /* READ_CAPACITY */

	if (!(cmd = transport_allocate_passthrough(&cdb[0], ISCSI_READ, 0, NULL, 0, READ_CAP_LEN,
			DEV_OBJ_API(dev), (void *)dev))) {
		return(-1);
	}

	if (transport_generic_passthrough(cmd) < 0) { 
		transport_passthrough_release(cmd);
		return(-1);
	}

	buf = (unsigned char *)T_TASK(cmd)->t_task_buf;
	blocks = (buf[0] << 24) | (buf[1] << 16) | (buf[2] << 8) | buf[3];

	transport_passthrough_release(cmd);

	if (blocks != 0xFFFFFFFF) {
		dev->dev_sectors_total = blocks;
		dev->dev_generate_cdb = &split_cdb_RW_10;
		return(0);
	}

	PYXPRINT("READ_CAPACITY returned 0xFFFFFFFF, issuing SAI_READ_CAPACITY_16\n");
		
	memset(cdb, 0, SCSI_CDB_SIZE);
	cdb[0] = 0x9e; /* SERVICE_ACTION_IN */
	cdb[1] = 0x10; /* SAI_READ_CAPACITY_16 */
	cdb[13] = 12;

	if (!(cmd = transport_allocate_passthrough(&cdb[0], ISCSI_READ, 0, NULL, 0, 12,
			DEV_OBJ_API(dev), (void *)dev))) {
		return(-1);
	}

	if (transport_generic_passthrough(cmd) < 0) {
		transport_passthrough_release(cmd);
		return(-1);
	}

	buf = (unsigned char *)T_TASK(cmd)->t_task_buf;
	v1 = (buf[0] << 24) | (buf[1] << 16) | (buf[2] << 8) | buf[3];
	v2 = (buf[4] << 24) | (buf[5] << 16) | (buf[6] << 8) | buf[7];
	blocks_long = ((unsigned long long)v2 | (unsigned long long)v1 << 32);
	
	transport_passthrough_release(cmd);

	dev->dev_sectors_total = blocks_long;
	dev->dev_generate_cdb = &split_cdb_RW_16;

	return(0);

}

/*	transport_add_device_to_iscsi_hba():
 *
 *	Note that some plugins (IBLOCK) will pass device_flags == DF_CLAIMED_BLOCKDEV
 *	signifying OS that a dependent block_device has been claimed.  In exception cases we
 *	will release said block_device ourselves.
 */
extern se_device_t *transport_add_device_to_iscsi_hba (
	se_hba_t *hba,
	se_subsystem_api_t *transport,
	u32 device_flags,
	void *transport_dev)
{
	int ret = 0;
	se_device_t  *dev;

	if (!(dev = (se_device_t *) kmalloc(sizeof(se_device_t), GFP_KERNEL))) {
		TRACE_ERROR("Unable to allocate memory for iscsi_dev_t\n");
		return(NULL);
	}
	memset(dev, 0, sizeof (se_device_t));

	if (!(dev->dev_queue_obj = (se_queue_obj_t *) kmalloc(sizeof(se_queue_obj_t), GFP_KERNEL))) {
		TRACE_ERROR("Unable to allocate memory for dev->dev_queue_obj\n");
		kfree(dev);
		return(NULL);
	}
	memset(dev->dev_queue_obj, 0, sizeof(se_queue_obj_t));

	transport_init_queue_obj(dev->dev_queue_obj);

	if (!(dev->dev_status_queue_obj = (se_queue_obj_t *) kmalloc(sizeof(se_queue_obj_t), GFP_KERNEL))) {
		TRACE_ERROR("Unable to allocate memory for dev->dev_status_queue_obj\n");
		kfree(dev->dev_queue_obj);
		kfree(dev);
		return(NULL);
	}
	memset(dev->dev_status_queue_obj, 0, sizeof(se_queue_obj_t));

	transport_init_queue_obj(dev->dev_status_queue_obj);
	
	dev->dev_flags		= device_flags;
	dev->dev_status		|= ISCSI_DEVICE_DEACTIVATED;
	dev->type		= transport->type;
	dev->dev_ptr		= (void *) transport_dev;
	dev->iscsi_hba		= hba;
	dev->transport		= transport;
	atomic_set(&dev->active_cmds, 0);
	INIT_LIST_HEAD(&dev->dev_sep_list);
	init_MUTEX_LOCKED(&dev->dev_queue_obj->thread_create_sem);
	init_MUTEX_LOCKED(&dev->dev_queue_obj->thread_done_sem);
	init_MUTEX_LOCKED(&dev->dev_queue_obj->thread_sem);
	spin_lock_init(&dev->execute_task_lock);
	spin_lock_init(&dev->state_task_lock);
	spin_lock_init(&dev->dev_status_lock);
	spin_lock_init(&dev->dev_status_thr_lock);
	spin_lock_init(&dev->se_port_lock);
	spin_lock_init(&dev->dev_queue_obj->cmd_queue_lock);
	
	dev->queue_depth	= TRANSPORT(dev)->get_queue_depth(dev);
	atomic_set(&dev->depth_left, dev->queue_depth);

//#warning FIXME v2.8: Put into SE OBJ API
	dev->write_pending = (transport->write_pending) ? transport->write_pending :
		&transport_dev_write_pending_nop;

#ifdef SNMP_SUPPORT
	dev->dev_index = get_new_index(SCSI_DEVICE_INDEX);
	dev->creation_time = get_jiffies_64();
	spin_lock_init(&dev->stats_lock);
#endif /* SNMP_SUPPORT */
	
	spin_lock(&hba->device_lock);
	ADD_ENTRY_TO_LIST(dev, hba->device_head, hba->device_tail);
	hba->dev_count++;
	spin_unlock(&hba->device_lock);

	/*
	 * Get this se_device_t's API from the device object plugin.
	 */
	if (!(dev->dev_obj_api = se_obj_get_api(ISCSI_LUN_TYPE_DEVICE)))
		goto out;
	
	transport_generic_activate_device(dev);

	/*
	 * This HBA is reserved for internal storage engine / feature plugin use
	 */
	if (hba->hba_flags & HBA_FLAGS_INTERNAL_USE) {
		if ((ret = transport_get_read_capacity(dev)) < 0)
			goto out;

		return(dev);
	}

	if ((ret = transport_get_inquiry(DEV_OBJ_API(dev), &dev->t10_wwn, (void *)dev)) < 0)
		goto out;
	/*
	 * Locate EVPD WWN Information used for various purposes within the Storage Engine.
	 */
	if (!(transport_get_inquiry_evpd_serial(DEV_OBJ_API(dev), &dev->t10_wwn, (void *)dev))) {
		transport_get_inquiry_evpd_device_ident(DEV_OBJ_API(dev), &dev->t10_wwn, (void *)dev);		
	}

	/*
	 * Only perform the volume scan for peripheral type TYPE_DISK
	 */
	if (TRANSPORT(dev)->get_device_type(dev) != 0)
		return(dev);

	/*
	 * Get the sector count via READ_CAPACITY
	 */
	if ((ret = transport_get_read_capacity(dev)) < 0)
		goto out;
	
	/*
	 * Determine if any feature plugin metadata exists on the se_device_t object.
	 */
	ret = feature_plugin_activate(dev->dev_obj_api, (void *)dev, 0);
	if (ret < 0)
		goto out;
	if (ret > 0) {
		ret = 0;
		goto out;
	}
	
out:
	if (!ret)
		return(dev);

	/*
	 * Release claim to OS dependant block_device that may have been
	 * set by plugin with passed dev_flags.
	 */
	transport_generic_release_phydevice(dev, 0);
	
	/*
	 * Release newly allocated state for se_device_t
	 */
	transport_generic_deactivate_device(dev);

	spin_lock(&hba->device_lock);
	REMOVE_ENTRY_FROM_LIST(dev, hba->device_head, hba->device_tail);
	hba->dev_count--;
	spin_unlock(&hba->device_lock);

	kfree(dev->dev_status_queue_obj);
	kfree(dev->dev_queue_obj);
	kfree(dev);	

	return(NULL);
}

/*	transport_generic_activate_device():
 *
 *
 */
extern void transport_generic_activate_device (se_device_t *dev)
{
	if (TRANSPORT(dev)->activate_device)
		TRANSPORT(dev)->activate_device(dev);
	
	kernel_thread((int (*)(void *)) transport_processing_thread, (void *)dev, 0);
	
	down(&dev->dev_queue_obj->thread_create_sem);

	if (!(dev->dev_flags & DF_DISABLE_STATUS_THREAD))
		DEV_OBJ_API(dev)->start_status_thread((void *)dev);

	return;
}

/*	transport_generic_deactivate_device():
 *
 *
 */
extern void transport_generic_deactivate_device (se_device_t *dev)
{
	if (!(dev->dev_flags & DF_DISABLE_STATUS_THREAD))
		DEV_OBJ_API(dev)->stop_status_thread((void *)dev);

	if (TRANSPORT(dev)->deactivate_device)
		TRANSPORT(dev)->deactivate_device(dev);
	
	send_sig(SIGKILL, dev->process_thread, 1);
	
	down(&dev->dev_queue_obj->thread_done_sem);
	
	return;
}

/*	transport_generic_claim_phydevice()
 *
 *	Obtain exclusive access to OS dependant block-device via
 *	Storage Transport Plugin API.
 * 
 *	In Linux v2.6 this means calling fs/block_dev.c:bd_claim()
 *	that is called in an plugin dependent method for claiming
 *	struct block_device.
 * 
 *	Returns 0 - Already claimed or not able to claim
 *	Returns 1 - Successfuly claimed
 *	Returns < 0 - Error
 */
extern int transport_generic_claim_phydevice (se_device_t *dev)
{
	int ret;
	se_hba_t *hba;
	
	/*
	 * This function pointer is present when handling access
	 * control to a OS dependant block subsystem.
	 */
	if (!TRANSPORT(dev)->claim_phydevice)
		return(0);
	
	if (dev->dev_flags & DF_READ_ONLY)
		return(0);
	
	if (dev->dev_flags & DF_CLAIMED_BLOCKDEV)
		return(0);
		
	if (!(hba = dev->iscsi_hba)) {
		TRACE_ERROR("se_device_t->iscsi_hba is NULL!\n");
		return(-1);
	}
		
	if ((ret = TRANSPORT(dev)->claim_phydevice(hba, dev)) < 0)
		return(ret);

	dev->dev_flags |= DF_CLAIMED_BLOCKDEV;

	return(1);
}

/*	transport_generic_release_phydevice():
 *
 *	Release exclusive access from OS dependant block-device via
 *	Storage Transport Plugin API.
 *
 *	In Linux v2.6 this means calling fs/block_dev.c:bd_release()
 *	see iscsi_target_pscsi.c and iscsi_target_iblock.c functions for
 *	se_subsystem_api_t->[claim,release]_phydevice()
 */
extern void transport_generic_release_phydevice (se_device_t *dev, int check_pscsi)
{
	if (!TRANSPORT(dev)->release_phydevice)
		return;
	
	if (dev->dev_flags & DF_READ_ONLY) {
		if (check_pscsi &&
		   (TRANSPORT(dev)->transport_type != TRANSPORT_PLUGIN_PHBA_PDEV))
				return;

		TRANSPORT(dev)->release_phydevice(dev);
		return;
	}

	if (!(dev->dev_flags & DF_CLAIMED_BLOCKDEV))
		return;
		
	if (!dev->dev_ptr) {
		TRACE_ERROR("se_device_t->dev_ptr is NULL!\n");
		BUG();
	}

	if (check_pscsi) {
		if (TRANSPORT(dev)->transport_type != TRANSPORT_PLUGIN_PHBA_PDEV)
			return;

		if (dev->dev_flags & DF_PERSISTENT_CLAIMED_BLOCKDEV)
			return;
	}
	
	TRANSPORT(dev)->release_phydevice(dev);
	dev->dev_flags &= ~DF_CLAIMED_BLOCKDEV;

	return;
}

/*	transport_generic_free_device():
 *
 *
 */
extern void transport_generic_free_device (se_device_t *dev)
{
	transport_generic_deactivate_device(dev);
	
	transport_generic_release_phydevice(dev, 0);
	
	if (TRANSPORT(dev)->free_device)
		TRANSPORT(dev)->free_device(dev);

	return;
}

/*	transport_generic_allocate_iovecs():
 *
 *	Called from transport_generic_new_cmd() in Transport Processing Thread.
 */
static int transport_generic_allocate_iovecs (
	iscsi_cmd_t *cmd)
{
	u32 iov_count;
	
	if (!(iov_count = T_TASK(cmd)->t_task_se_num))
		iov_count = 1;
#if 0
	TRACE_ERROR("Allocated %d iovecs for ITT: 0x%08x t_task_se_num: %u\n",
		iov_count, cmd->init_task_tag, T_TASK(cmd)->t_task_se_num);
#endif
	iov_count += ISCSI_IOV_DATA_BUFFER;

	if (iscsi_allocate_iovecs_for_cmd(cmd, iov_count))
		return(-1);

	return(0);
}

/*	transport_generic_prepare_cdb():
 *
 *	Since the Initiator sees iSCSI devices as LUNs,  the SCSI CDB will
 *	contain the iSCSI LUN in bits 7-5 of byte 1 as per SAM-2.
 *	The point of this is since we are mapping iSCSI LUNs to
 *	SCSI Target IDs having a non-zero LUN in the CDB will throw the
 *	devices and HBAs for a loop.
 */
static inline void transport_generic_prepare_cdb (
	unsigned char *cdb,
	iscsi_cmd_t *cmd)
{
	switch (cdb[0]) {
	case READ_10: /* SBC - RDProtect */
	case READ_12: /* SBC - RDProtect */
	case READ_16: /* SBC - RDProtect */
	case SEND_DIAGNOSTIC: /* SPC - SELF-TEST Code */
	case VERIFY: /* SBC - VRProtect */
	case VERIFY_16: /* SBC - VRProtect */
	case WRITE_VERIFY: /* SBC - VRProtect */
	case WRITE_VERIFY_12: /* SBC - VRProtect */
		break;
	default:
		cdb[1] &= 0x1f; // clear logical unit number
		break;
	}

	return;
}

/*	transport_check_device_cdb_sector_count():
 *
 *	returns:
 *	0 on supported request sector count.
 *	1 on unsupported request sector count.
 */
static inline int transport_check_device_cdb_sector_count (se_obj_lun_type_t *se_obj_api, void *se_obj_ptr, u32 sectors)
{
	u32 max_sectors;

	if (!(max_sectors = se_obj_api->max_sectors(se_obj_ptr))) {
		TRACE_ERROR("TRANSPORT->get_max_sectors returned zero!\n");
		return(1);
	}

	if (sectors > max_sectors)
		return(-1);

	return(0);
}

/*	transport_generic_get_task():
 *
 *
 */
static se_task_t *transport_generic_get_task (
	iscsi_transform_info_t *ti,
	iscsi_cmd_t *cmd,
	void *se_obj_ptr,
	se_obj_lun_type_t *se_obj_api)
{
	se_task_t *task;
	unsigned long flags;

	if (!(task = kmalloc(sizeof(se_task_t), GFP_KERNEL))) {
		TRACE_ERROR("Unable to allocate se_task_t\n");
		return(NULL);
	}
	memset(task, 0, sizeof(se_task_t));
	
	INIT_LIST_HEAD(&task->t_list);
	init_MUTEX_LOCKED(&task->task_stop_sem);
	task->task_no = T_TASK(cmd)->t_task_no++;
	task->iscsi_cmd = cmd;

	DEBUG_SO("se_obj_ptr: %p\n", se_obj_ptr);
	DEBUG_SO("se_obj_api: %p\n", se_obj_api);
	DEBUG_SO("Plugin: %s\n", se_obj_api->obj_plugin->plugin_name);

	if (!(task->transport_req = se_obj_api->get_transport_req(se_obj_ptr, task)))
		return(NULL);

	spin_lock_irqsave(&T_TASK(cmd)->t_state_lock, flags);
	list_add_tail(&task->t_list, &T_TASK(cmd)->t_task_list);
	spin_unlock_irqrestore(&T_TASK(cmd)->t_state_lock, flags);
	
	task->se_obj_api = se_obj_api;
	task->se_obj_ptr = se_obj_ptr;
	
	return(task);
}

extern int transport_generic_obj_start (iscsi_transform_info_t *ti, se_obj_lun_type_t *obj_api, void *p, unsigned long long starting_lba)
{
	ti->ti_lba = starting_lba;
	ti->ti_obj_api = obj_api;
	ti->ti_obj_ptr = p;
	
	return(0);
}

static int transport_process_data_sg_transform (iscsi_cmd_t *cmd, iscsi_transform_info_t *ti)
{
	/*
	 * Already handled in transport_generic_get_cdb_count()
	 */
	return(0);
}

/*	transport_process_control_sg_transform():
 *
 *
 */
static int transport_process_control_sg_transform (iscsi_cmd_t *cmd, iscsi_transform_info_t *ti)
{
	unsigned char *cdb;
	se_task_t *task;
	se_mem_t *se_mem, *se_mem_lout = NULL;
	int ret;
	u32 se_mem_cnt = 0, task_offset = 0;

	list_for_each_entry(se_mem, T_TASK(cmd)->t_mem_list, se_list)
		break;

	if (!se_mem) {
		TRACE_ERROR("se_mem is NULL!\n");
		return(-1);
	}

	if (!(task = cmd->transport_get_task(ti, cmd, ti->se_obj_ptr, ti->se_obj_api)))
		return(-1);

	task->transport_map_task = ti->se_obj_api->get_map_SG(ti->se_obj_ptr, cmd->data_direction);
	
	if ((cdb = ti->se_obj_api->get_cdb(ti->se_obj_ptr, task)))
		memcpy(cdb, T_TASK(cmd)->t_task_cdb, SCSI_CDB_SIZE);

	task->task_size = cmd->data_length;
	task->task_sg_num = 1;

	atomic_inc(&T_TASK(cmd)->t_fe_count);
	atomic_inc(&T_TASK(cmd)->t_se_count);
	
	if ((ret = ti->se_obj_api->do_se_mem_map(ti->se_obj_ptr, task, T_TASK(cmd)->t_mem_list,
			NULL, se_mem, &se_mem_lout, &se_mem_cnt, &task_offset)) < 0)
		return(ret);

	DEBUG_CDB_H("task_no[%u]: ICF_SCSI_CONTROL_SG_IO_CDB task_size: %d\n", task->task_no, task->task_size);

	return(0);
}

/*	transport_process_control_nonsg_transform():
 *
 *
 */
static int transport_process_control_nonsg_transform (iscsi_cmd_t *cmd, iscsi_transform_info_t *ti)
{
	unsigned char *cdb;
	se_task_t *task;

	if (!(task = cmd->transport_get_task(ti, cmd, ti->se_obj_ptr, ti->se_obj_api)))
		return(-1);

	task->transport_map_task = ti->se_obj_api->get_map_non_SG(ti->se_obj_ptr, cmd->data_direction);
	
	if ((cdb = ti->se_obj_api->get_cdb(ti->se_obj_ptr, task)))
		memcpy(cdb, T_TASK(cmd)->t_task_cdb, SCSI_CDB_SIZE);
		
	task->task_size = cmd->data_length;
	task->task_sg_num = 0;

	atomic_inc(&T_TASK(cmd)->t_fe_count);
	atomic_inc(&T_TASK(cmd)->t_se_count);

	DEBUG_CDB_H("task_no[%u]: ICF_SCSI_CONTROL_NONSG_IO_CDB task_size: %d\n", task->task_no, task->task_size);

	return(0);
}

/*	transport_process_non_data_transform():
 *
 *
 */
static int transport_process_non_data_transform (iscsi_cmd_t *cmd, iscsi_transform_info_t *ti)
{
	unsigned char *cdb;
	se_task_t *task;

	if (!(task = cmd->transport_get_task(ti, cmd, ti->se_obj_ptr, ti->se_obj_api)))
		return(-1);

	task->transport_map_task = ti->se_obj_api->get_map_none(ti->se_obj_ptr);
	
	if ((cdb = ti->se_obj_api->get_cdb(ti->se_obj_ptr, task)))
		memcpy(cdb, T_TASK(cmd)->t_task_cdb, SCSI_CDB_SIZE);
		
	task->task_size = cmd->data_length;
	task->task_sg_num = 0;

	atomic_inc(&T_TASK(cmd)->t_fe_count);
	atomic_inc(&T_TASK(cmd)->t_se_count);

	DEBUG_CDB_H("task_no[%u]: ICF_SCSI_NON_DATA_CDB task_size: %d\n", task->task_no, task->task_size);

	return(0);
}

extern int transport_execute_tasks (iscsi_cmd_t *);
static int transport_generic_cmd_sequencer (iscsi_cmd_t *, unsigned char *);

extern void transport_device_setup_cmd (iscsi_cmd_t *cmd)
{
	cmd->transport_add_cmd_to_queue = &transport_add_cmd_to_dev_queue;
	cmd->iscsi_dev = ISCSI_LUN(cmd)->iscsi_dev;

	return;
}

static void transport_generic_wait_for_tasks (iscsi_cmd_t *, int, int);

/*	transport_generic_allocate_tasks():
 *
 *	Called from the iSCSI RX Thread.
 */
extern int transport_generic_allocate_tasks (
	iscsi_cmd_t *cmd,
	unsigned char *cdb)
{
	int non_data_cdb;
	
	transport_generic_prepare_cdb(cdb, cmd);

	/*
	 * This is needed for early exceptions.
	 */
	cmd->transport_wait_for_tasks = &transport_generic_wait_for_tasks;
	
	CMD_ORIG_OBJ_API(cmd)->transport_setup_cmd(cmd->se_orig_obj_ptr, cmd);
	
	/*
	 * See if this is a CDB which follows SAM, also grab a function
	 * pointer to see if we need to do extra work.
	 */
	if ((non_data_cdb = transport_generic_cmd_sequencer(cmd, cdb)) < 0)
		return(-1);
	/*
	 * Copy the original CDB into T_TASK(cmd).
	 */
	memcpy(T_TASK(cmd)->t_task_cdb, cdb, SCSI_CDB_SIZE);

#ifdef SNMP_SUPPORT
        spin_lock(&cmd->iscsi_lun->lun_sep_lock);
        if (cmd->iscsi_lun->lun_sep)
                cmd->iscsi_lun->lun_sep->sep_stats.cmd_pdus++;
        spin_unlock(&cmd->iscsi_lun->lun_sep_lock);
#endif /* SNMP_SUPPORT */

	switch (non_data_cdb) {
	case 0:
		DEBUG_CDB_H("Set cdb[0]: 0x%02x to ICF_SCSI_DATA_SG_IO_CDB\n", cdb[0]);
		cmd->cmd_flags |= ICF_SCSI_DATA_SG_IO_CDB;

		/*
		 * Get the initial Logical Block Address from the Original Command
		 * Descriptor Block that arrived on the iSCSI wire.
		 */
		T_TASK(cmd)->t_task_lba = (cmd->transport_get_long_lba) ?
			cmd->transport_get_long_lba(cdb) : cmd->transport_get_lba(cdb);

		break;
	case 1:
		DEBUG_CDB_H("Set cdb[0]: 0x%02x to ICF_SCSI_CONTROL_SG_IO_CDB\n", cdb[0]);
		cmd->cmd_flags |= ICF_SCSI_CONTROL_SG_IO_CDB;
		cmd->transport_cdb_transform = &transport_process_control_sg_transform;
		break;
	case 2:
		DEBUG_CDB_H("Set cdb[0]: 0x%02x to ICF_SCSI_CONTROL_NONSG_IO_CDB\n", cdb[0]);
		cmd->cmd_flags |= ICF_SCSI_CONTROL_NONSG_IO_CDB;
		cmd->transport_cdb_transform = &transport_process_control_nonsg_transform;
		break;
	case 3:
		DEBUG_CDB_H("Set cdb[0]: 0x%02x to ICF_SCSI_NON_DATA_CDB\n", cdb[0]);
		cmd->cmd_flags |= ICF_SCSI_NON_DATA_CDB;
		cmd->transport_cdb_transform = &transport_process_non_data_transform;
		break;
	case 4:
		DEBUG_CDB_H("Set cdb[0]: 0x%02x to ICF_SCSI_UNSUPPORTED_CDB\n", cdb[0]);
		cmd->cmd_flags |= ICF_SCSI_CDB_EXCEPTION;
		cmd->scsi_sense_reason = UNSUPPORTED_SCSI_OPCODE;
		return(-2);
	case 5:
		DEBUG_CDB_H("Set cdb[0]: 0x%02x to ICF_SCSI_RESERVATION_CONFLICT\n", cdb[0]);
		cmd->cmd_flags |= ICF_SCSI_CDB_EXCEPTION;
		cmd->cmd_flags |= ICF_SCSI_RESERVATION_CONFLICT;
		cmd->scsi_status = SAM_STAT_RESERVATION_CONFLICT;
		return(-2);
	case 6:
		cmd->cmd_flags |= ICF_SCSI_CDB_EXCEPTION;
		cmd->scsi_sense_reason = INVALID_CDB_FIELD;
		return(-2);
	case 7:
		cmd->cmd_flags |= ICF_SCSI_CDB_EXCEPTION;
		cmd->scsi_sense_reason = ILLEGAL_REQUEST;
		return(-2);
	default:
		break;
	}
	
	return(0);
}

/*	transport_generic_check_device_location():
 *
 *
 */
extern int transport_generic_check_device_location (
	se_device_t *dev,
	se_dev_transport_info_t *dti)
{
	int ret = 0;
	se_hba_t *hba;
	se_subsystem_api_t *t;
	
	if (!dev->iscsi_hba) {
		TRACE_ERROR("se_device_t->iscsi_hba is NULL!\n");
		return(-1);
	}
	hba = dev->iscsi_hba;
	
	if (!(t = (se_subsystem_api_t *)plugin_get_obj(PLUGIN_TYPE_TRANSPORT, hba->type, &ret)))
		return(ret);

	return(t->check_device_location(dev, dti));
}

/*	transport_generic_handle_cdb():
 *
 *
 */
extern int transport_generic_handle_cdb (
	iscsi_cmd_t *cmd)
{
#if 0
	se_device_t *dev;
#endif
	if (!ISCSI_LUN(cmd)) {
		TRACE_ERROR("ISCSI_LUN(cmd) is NULL\n");
		return(-1);
	}

#if 0
	dev = ISCSI_DEV(cmd);
	atomic_inc(&dev->active_cmds);
#endif
	cmd->transport_add_cmd_to_queue(cmd, TRANSPORT_NEW_CMD);

	return(0);
}

/*	transport_generic_handle_data():
 *
 *
 */
extern int transport_generic_handle_data (
	iscsi_cmd_t *cmd)
{
	/*
	 * Make sure that the transport has been disabled by transport_write_pending()
	 * before readding this iscsi_cmd_t to the processing queue.  If it has not yet
         * been reset to zero by the processing thread in cmd->transport_add_cmd_to_queue(),
	 * let other processes run.  If a signal was received, then we assume the connection
	 * is being failed/shutdown, so we return a failure.
	 */
	while (atomic_read(&T_TASK(cmd)->t_transport_active)) {
		msleep_interruptible(10);
		if (signal_pending(current))
			return(-1);
	}
	
	cmd->transport_add_cmd_to_queue(cmd, TRANSPORT_PROCESS_WRITE);
	return(0);
}

/*	transport_generic_handle_tmr():
 *
 *
 */
extern int transport_generic_handle_tmr (
	iscsi_cmd_t *cmd,
	iscsi_tmr_req_t *req)
{
	cmd->transport_add_cmd_to_queue(cmd, TRANSPORT_PROCESS_TMR);
	return(0);
}

/*	transport_stop_tasks_for_cmd():
 *
 *
 */
extern void transport_stop_tasks_for_cmd (iscsi_cmd_t *cmd)
{
	se_task_t *task, *task_tmp;
	unsigned long flags;

	DEBUG_TS("ITT[0x%08x] - Stopping tasks\n", cmd->init_task_tag);

	/*
	 * No tasks remain in the execution queue
	 */
	spin_lock_irqsave(&T_TASK(cmd)->t_state_lock, flags);
	list_for_each_entry_safe(task, task_tmp, &T_TASK(cmd)->t_task_list, t_list) {
		DEBUG_TS("task_no[%d] - Processing task %p\n", task->task_no, task);
		/*
		 * If the se_task_t has not been sent and is not active,
		 * remove the se_task_t from the execution queue.
		 */
		if (!atomic_read(&task->task_sent) &&
		    !atomic_read(&task->task_active)) {
			spin_unlock_irqrestore(&T_TASK(cmd)->t_state_lock, flags);
			transport_remove_task_from_execute_queue(task, task->iscsi_dev);

			DEBUG_TS("task_no[%d] - Removed from execute queue\n", task->task_no);
			spin_lock_irqsave(&T_TASK(cmd)->t_state_lock, flags);
			continue;
		}

		/*
		 * If the se_task_t is active, sleep until it is returned
		 * from the plugin.
		 */
		if (atomic_read(&task->task_active)) {
			atomic_set(&task->task_stop, 1);
			spin_unlock_irqrestore(&T_TASK(cmd)->t_state_lock, flags);

			DEBUG_TS("task_no[%d] - Waiting to complete\n", task->task_no);
			down(&task->task_stop_sem);
			DEBUG_TS("task_no[%d] - Stopped successfully\n", task->task_no);

			spin_lock_irqsave(&T_TASK(cmd)->t_state_lock, flags);
			atomic_dec(&T_TASK(cmd)->t_task_cdbs_left);

			atomic_set(&task->task_active, 0);
			atomic_set(&task->task_stop, 0);
		} else {
			DEBUG_TS("task_no[%d] - Did nothing\n", task->task_no);
		}

		__transport_stop_task_timer(task, &flags);
	}
	spin_unlock_irqrestore(&T_TASK(cmd)->t_state_lock, flags);

	return;
}

static void transport_failure_reset_queue_depth (se_device_t *dev)
{
	unsigned long flags;

	spin_lock_irqsave(&ISCSI_HBA(dev)->hba_queue_lock, flags);;
	atomic_inc(&dev->depth_left);
	atomic_inc(&ISCSI_HBA(dev)->left_queue_depth);
	spin_unlock_irqrestore(&ISCSI_HBA(dev)->hba_queue_lock, flags);

	return;
}

/*
 * Used for se_device_t, JBOD and RAID0.
 */
extern int transport_failure_tasks_generic (iscsi_cmd_t *cmd)
{
	unsigned long flags;
	/*
	 * This causes problems when EVPD INQUIRY fails, disable this functionality
	 * for now.
	 */
	se_task_t *task;

	if (!(cmd->cmd_flags & ICF_SE_DISABLE_ONLINE_CHECK))
		goto done;

	spin_lock_irqsave(&T_TASK(cmd)->t_state_lock, flags);
	list_for_each_entry(task, &T_TASK(cmd)->t_task_list, t_list) {
		DEBUG_TF("Exception Cmd ITT: 0x%08x: task[%p]: se_obj_api: %p"
			" se_obj_ptr: %p task_scsi_status: %d\n", cmd->init_task_tag,
			task, task->se_obj_api, task->se_obj_ptr, task->task_scsi_status);

		spin_unlock_irqrestore(&T_TASK(cmd)->t_state_lock, flags);
		task->se_obj_api->signal_offline(task->se_obj_ptr);
		spin_lock_irqsave(&T_TASK(cmd)->t_state_lock, flags);
	}
	spin_unlock_irqrestore(&T_TASK(cmd)->t_state_lock, flags);

done:
	cmd->transport_error_status = PYX_TRANSPORT_LOGICAL_UNIT_COMMUNICATION_FAILURE;
	return(0);
}

/*	transport_generic_request_failure():
 *
 *	Handle SAM-esque emulation for generic transport request failures.
 */
extern void transport_generic_request_failure (iscsi_cmd_t *cmd, se_device_t *dev, int complete, int sc)
{
	DEBUG_GRF("-----[ Storage Engine Exception for cmd: %p ITT: 0x%08x CDB: 0x%02x\n", cmd,
		cmd->init_task_tag, T_TASK(cmd)->t_task_cdb[0]);
	DEBUG_GRF("-----[ se_obj_api: %p se_obj_ptr: %p\n", cmd->se_obj_api, cmd->se_obj_ptr);
	DEBUG_GRF("-----[ se_orig_obj_api: %p se_orig_obj_ptr: %p\n", cmd->se_orig_obj_api, cmd->se_orig_obj_ptr);
	DEBUG_GRF("-----[ i_state/def_i_state: %d/%d t_state/def_t_state: %d/%d transport_error_status: %d\n", cmd->i_state,
		cmd->deferred_i_state, cmd->t_state, cmd->deferred_t_state, cmd->transport_error_status);
	DEBUG_GRF("-----[ t_task_cdbs: %d t_task_cdbs_left: %d t_task_cdbs_sent: %d t_task_cdbs_ex_left: %d --"
		"  t_transport_active: %d t_transport_stop: %d t_transport_sent: %d\n",
		T_TASK(cmd)->t_task_cdbs, atomic_read(&T_TASK(cmd)->t_task_cdbs_left),
		atomic_read(&T_TASK(cmd)->t_task_cdbs_sent), atomic_read(&T_TASK(cmd)->t_task_cdbs_ex_left),
		atomic_read(&T_TASK(cmd)->t_transport_active), atomic_read(&T_TASK(cmd)->t_transport_stop),
		atomic_read(&T_TASK(cmd)->t_transport_sent));

	transport_stop_all_task_timers(cmd);
	
	if (dev)
		transport_failure_reset_queue_depth(dev);

	if (complete) {
		transport_direct_request_timeout(cmd);
		
		if (CMD_ORIG_OBJ_API(cmd)->task_failure_complete(cmd->se_orig_obj_ptr, cmd) != 0)
			return;
	}

	switch (cmd->transport_error_status) {
	case PYX_TRANSPORT_UNKNOWN_SAM_OPCODE:
		cmd->scsi_sense_reason = UNSUPPORTED_SCSI_OPCODE;
		break;
#if 0
	case PYX_TRANSPORT_HBA_QUEUE_FULL:
		/* Unused for now.. */
		break;
#endif
	case PYX_TRANSPORT_REQ_TOO_MANY_SECTORS:
		cmd->scsi_sense_reason = SECTOR_COUNT_TOO_MANY;
		break;
	case PYX_TRANSPORT_INVALID_CDB_FIELD:
		cmd->scsi_sense_reason = INVALID_CDB_FIELD;
		break;
	case PYX_TRANSPORT_OUT_OF_MEMORY_RESOURCES:
//#warning FIXME: PYX_TRANSPORT_OUT_OF_MEMORY_RESOURCES needs to be looked at again
		if (!(cmd->cmd_flags & ICF_CMD_PASSTHROUGH)) {
			if (!sc)
				transport_new_cmd_failure(cmd);
			
			if (CONN(cmd) && SESS(CONN(cmd))) {
				iscsi_fall_back_to_erl0(CONN(cmd));
				iscsi_stop_session(SESS(CONN(cmd)), 0, 0);
			} else {
				TRACE_ERROR("Huh, conn and sess are NULL for ITT: 0x%08x"
					" t_state: %u\n", cmd->init_task_tag, cmd->t_state);
			}
			goto check_stop;
		} else
			cmd->scsi_sense_reason = LOGICAL_UNIT_COMMUNICATION_FAILURE;
		break;
	case PYX_TRANSPORT_LOGICAL_UNIT_COMMUNICATION_FAILURE:
		cmd->scsi_sense_reason = LOGICAL_UNIT_COMMUNICATION_FAILURE;
		break;
	case PYX_TRANSPORT_UNKNOWN_MODE_PAGE:
		cmd->scsi_sense_reason = UNKNOWN_MODE_PAGE;
		break;
	case PYX_TRANSPORT_WRITE_PROTECTED:
		cmd->scsi_sense_reason = WRITE_PROTECTED;
		break;
	default:
		TRACE_ERROR("Unknown transport error for CDB 0x%02x: %d\n",
			T_TASK(cmd)->t_task_cdb[0], cmd->transport_error_status);
		cmd->scsi_sense_reason = UNSUPPORTED_SCSI_OPCODE;
		break;
	}

	if (!sc)
		transport_new_cmd_failure(cmd);
	else
		iscsi_send_check_condition_and_sense(cmd, cmd->scsi_sense_reason, 0);
	
check_stop:
	transport_lun_remove_cmd(cmd);
	if (!(transport_cmd_check_stop(cmd, 2, 0)))
		transport_passthrough_check_stop(cmd);

	return;
}

extern void transport_direct_request_timeout (iscsi_cmd_t *cmd)
{
	unsigned long flags;	

	spin_lock_irqsave(&T_TASK(cmd)->t_state_lock, flags);
	if (!(atomic_read(&T_TASK(cmd)->t_transport_timeout))) {
		spin_unlock_irqrestore(&T_TASK(cmd)->t_state_lock, flags);
		return;
	}
	if (atomic_read(&T_TASK(cmd)->t_task_cdbs_timeout_left)) {
		spin_unlock_irqrestore(&T_TASK(cmd)->t_state_lock, flags);
		return;
	}

	atomic_sub(atomic_read(&T_TASK(cmd)->t_transport_timeout),
		   &T_TASK(cmd)->t_se_count);

	CMD_ORIG_OBJ_API(cmd)->clear_tur_bit(cmd->se_orig_obj_ptr);
	spin_unlock_irqrestore(&T_TASK(cmd)->t_state_lock, flags);

	return;
}

extern void transport_generic_request_timeout (iscsi_cmd_t *cmd)
{
	unsigned char *cdb;
	se_task_t *task;
	unsigned long flags;
	
	/*
	 * Reset T_TASK(cmd)->t_se_count to allow transport_generic_remove()
	 * to allow last call to free memory resources.
	 */
	spin_lock_irqsave(&T_TASK(cmd)->t_state_lock, flags);
	if (atomic_read(&T_TASK(cmd)->t_transport_timeout) > 1) {
		int tmp = (atomic_read(&T_TASK(cmd)->t_transport_timeout) - 1);
		
		atomic_sub(tmp, &T_TASK(cmd)->t_se_count);
	}
	spin_unlock_irqrestore(&T_TASK(cmd)->t_state_lock, flags);

	/*
	 * Clear the TUR bit that the status thread will be checking to determine
	 * when the next TUR can be sent to this iscsi_cmd_t's object.
	 */
	CMD_ORIG_OBJ_API(cmd)->clear_tur_bit(cmd->se_orig_obj_ptr);

	/*
	 * Handle the scenario where the TUR never made it to the SE object, so
	 * we need to restart it here.
	 */
	list_for_each_entry(task, &T_TASK(cmd)->t_task_list, t_list)
		break;

	if (!task)
		goto out;
		
	if (!(cdb = CMD_ORIG_OBJ_API(cmd)->get_cdb(cmd->se_orig_obj_ptr, task)))
		goto out;

	if ((cdb[0] == TEST_UNIT_READY) && (cmd->cmd_flags & ICF_SE_DISABLE_ONLINE_CHECK))
		CMD_ORIG_OBJ_API(cmd)->start_status_timer(cmd->se_orig_obj_ptr);
	
out:
	transport_generic_remove(cmd, 0, 0);
	return;
}

//#define iscsi_linux_calculate_map_segment_DEBUG
#ifdef iscsi_linux_calculate_map_segment_DEBUG
#define DEBUG_MAP_SEGMENTS(buf...) PYXPRINT(buf)
#else   
#define DEBUG_MAP_SEGMENTS(buf...)
#endif

/*	transport_calculate_map_segment():
 *
 *
 */
static inline void transport_calculate_map_segment (
	u32 *data_length,
	iscsi_offset_map_t *lm)
{
	u32 sg_offset = 0;
	se_mem_t *se_mem = lm->map_se_mem;

	DEBUG_MAP_SEGMENTS(" START Mapping se_mem: %p, Length: %d  Remaining iSCSI Data: %u\n",
			se_mem, se_mem->se_len, *data_length);

	/*
	 * Still working on pages in the current se_mem_t.
	 */
	if (!lm->map_reset) {
		lm->iovec_length = (lm->sg_length > PAGE_SIZE) ?
					PAGE_SIZE : lm->sg_length;
		if (*data_length < lm->iovec_length) {
			DEBUG_MAP_SEGMENTS("LINUX_MAP: Reset lm->iovec_length to %d\n",
					*data_length);

			lm->iovec_length = *data_length;
		}
		lm->iovec_base = page_address(lm->sg_page) + sg_offset;

		DEBUG_MAP_SEGMENTS("LINUX_MAP: Set lm->iovec_base to %p from"
			" lm->sg_page: %p\n", lm->iovec_base, lm->sg_page);

		return;
	}

	/*
	 * First run of an iscsi_linux_map_t.
	 *
	 * OR:
	 *
	 * Mapped all of the pages in the current scatterlist, move
	 * on to the next one.
	 */
	lm->map_reset = 0;
	sg_offset = se_mem->se_off;
	lm->sg_page = se_mem->se_page;
	lm->sg_length = se_mem->se_len;

	DEBUG_MAP_SEGMENTS("LINUX_MAP1[%p]: Starting to se_mem->se_len: %u, se_mem->se_off: %u,"
		" se_mem->se_page: %p\n", se_mem, se_mem->se_len, se_mem->se_off, se_mem->se_page);;
	
	/*
	 * Get the base and length of the current page for use with the iovec.
	 */
recalc:
	lm->iovec_length = (lm->sg_length > (PAGE_SIZE - sg_offset)) ?
			   (PAGE_SIZE - sg_offset) : lm->sg_length;

	DEBUG_MAP_SEGMENTS("LINUX_MAP: lm->iovec_length: %u, lm->sg_length: %u,"
		" sg_offset: %u\n", lm->iovec_length, lm->sg_length, sg_offset);
	/*
	 * See if there is any iSCSI offset we need to deal with.
	 */
	if (!lm->current_offset) {
		lm->iovec_base = page_address(lm->sg_page) + sg_offset;

		if (*data_length < lm->iovec_length) {
			DEBUG_MAP_SEGMENTS("LINUX_MAP1[%p]: Reset lm->iovec_length to %d\n",
				se_mem, *data_length);
			lm->iovec_length = *data_length;
		}
		
		DEBUG_MAP_SEGMENTS("LINUX_MAP2[%p]: No current_offset,"
			" set iovec_base to %p and set Current Page to %p\n",
			se_mem, lm->iovec_base, lm->sg_page);
		
		return;
	}

	/*
	 * We know the iSCSI offset is in the next page of the current
	 * scatterlist.  Increase the lm->sg_page pointer and try again.
	 */
	if (lm->current_offset >= lm->iovec_length) {
		DEBUG_MAP_SEGMENTS("LINUX_MAP3[%p]: Next Page: lm->current_offset:"
			" %u, iovec_length: %u sg_offset: %u\n", se_mem,
			lm->current_offset, lm->iovec_length, sg_offset);

		lm->current_offset -= lm->iovec_length;
		lm->sg_length -= lm->iovec_length;
		lm->sg_page++;
		sg_offset = 0;

		DEBUG_MAP_SEGMENTS("LINUX_MAP3[%p]: ** Skipping to Next Page, updated values:"
			" lm->current_offset: %u\n", se_mem, lm->current_offset);
		
		goto recalc;
	}

	/*
	 * The iSCSI offset is in the current page, increment the iovec
	 * base and reduce iovec length.
	 */
	lm->iovec_base = page_address(lm->sg_page);

	DEBUG_MAP_SEGMENTS("LINUX_MAP4[%p]: Set lm->iovec_base to %p\n", se_mem,
			lm->iovec_base);
	
	lm->iovec_base += sg_offset;
	lm->iovec_base += lm->current_offset;
	DEBUG_MAP_SEGMENTS("****** the OLD lm->iovec_length: %u lm->sg_length: %u\n",
			lm->iovec_length, lm->sg_length);

	if ((lm->iovec_length - lm->current_offset) < *data_length)
		lm->iovec_length -= lm->current_offset;
	else
		lm->iovec_length = *data_length;

	if ((lm->sg_length - lm->current_offset) < *data_length)
		lm->sg_length -= lm->current_offset;
	else
		lm->sg_length = *data_length;

	lm->current_offset = 0;

	DEBUG_MAP_SEGMENTS("****** the NEW lm->iovec_length %u lm->sg_length: %u\n",
		lm->iovec_length, lm->sg_length);
	
	return;
}

//#define iscsi_linux_get_iscsi_offset_DEBUG
#ifdef iscsi_linux_get_iscsi_offset_DEBUG
#define DEBUG_GET_ISCSI_OFFSET(buf...) PYXPRINT(buf)
#else
#define DEBUG_GET_ISCSI_OFFSET(buf...)
#endif

/*	transport_get_iscsi_offset():
 *
 *
 */
static int transport_get_iscsi_offset (
	iscsi_offset_map_t *lmap,
	iscsi_unmap_sg_t *usg)
{
	u32 current_length = 0, current_iscsi_offset = lmap->iscsi_offset;
	u32 total_offset = 0;
	iscsi_cmd_t *cmd = usg->cmd;
	se_mem_t *se_mem;

	list_for_each_entry(se_mem, T_TASK(cmd)->t_mem_list, se_list)
		break;

	if (!se_mem) {
		TRACE_ERROR("Unable to locate se_mem from T_TASK(cmd)->t_mem_list\n");
		return(-1);
	}
	
	/*
	 * Locate the current offset from the passed iSCSI Offset.
	 */
	while (lmap->iscsi_offset != current_length) {
		/*
		 * The iSCSI Offset is within the current se_mem_t.
		 *
		 * Or:
		 *
		 * The iSCSI Offset is outside of the current se_mem_t.
		 * Recalculate the values and obtain the next se_mem_t pointer.
		 */
		total_offset += se_mem->se_len;

		DEBUG_GET_ISCSI_OFFSET("ISCSI_OFFSET: current_length: %u,"
			" total_offset: %u, sg->length: %u\n",
			current_length, total_offset, se_mem->se_len);
		
		if (total_offset > lmap->iscsi_offset) {
			current_length += current_iscsi_offset;
			lmap->orig_offset = lmap->current_offset =
				usg->t_offset = current_iscsi_offset;
			DEBUG_GET_ISCSI_OFFSET("ISCSI_OFFSET: Within Current se_mem_t: %p,"
				" current_length incremented to %u\n",
				se_mem, current_length);
		} else {
			current_length += se_mem->se_len;
			current_iscsi_offset -= se_mem->se_len;

			DEBUG_GET_ISCSI_OFFSET("ISCSI_OFFSET: Outside of Current se_mem: %p,"
				" current_length incremented to %u and"
				" current_iscsi_offset decremented to %u\n",
				se_mem, current_length, current_iscsi_offset);

			list_for_each_entry_continue(se_mem, T_TASK(cmd)->t_mem_list, se_list)
				break;

			if (!se_mem) {
				TRACE_ERROR("Unable to locate se_mem_t\n");
				return(-1);
			}
		}
	}
	lmap->map_orig_se_mem = se_mem;
	usg->cur_se_mem = se_mem;
	
	return(0);
}

//#define iscsi_OS_set_SG_iovec_ptrs_DEBUG
#ifdef iscsi_OS_set_SG_iovec_ptrs_DEBUG
#define DEBUG_IOVEC_SCATTERLISTS(buf...) PYXPRINT(buf)

static void iscsi_check_iovec_map (
	u32 iovec_count,
	u32 map_length,
	iscsi_map_sg_t *map_sg,
	iscsi_unmap_sg_t *unmap_sg)
{       
	u32 i, iovec_map_length = 0;
	iscsi_cmd_t *cmd = (iscsi_cmd_t *) map_sg->cmd;
	struct iovec *iov = map_sg->iov;
	se_mem_t *se_mem;
	
	for (i = 0; i < iovec_count; i++)
		iovec_map_length += iov[i].iov_len;

	if (iovec_map_length == map_length) {
		return;
	}

	PYXPRINT("Calculated iovec_map_length: %u does not match passed"
		" map_length: %u\n", iovec_map_length, map_length);
	PYXPRINT("ITT: 0x%08x data_length: %u data_direction %d\n",
		cmd->init_task_tag, cmd->data_length,
		cmd->data_direction);

	iovec_map_length = 0;

	for (i = 0; i < iovec_count; i++) {
		PYXPRINT("iov[%d].iov_[base,len]: %p / %u bytes-------->\n", i,
				iov[i].iov_base, iov[i].iov_len);

		PYXPRINT("iovec_map_length from %u to %u\n",
			iovec_map_length, iovec_map_length + iov[i].iov_len);
		iovec_map_length += iov[i].iov_len;

		PYXPRINT("XXXX_map_length from %u to %u\n", map_length,
				(map_length - iov[i].iov_len));
		map_length -= iov[i].iov_len;
	}

	list_for_each_entry(se_mem, T_TASK(cmd)->t_mem_list, se_list) {
		PYXPRINT("se_mem[%p]: offset: %u length: %u\n",
			se_mem, se_mem->se_off, se_mem->se_len);
	}

	BUG();
}
		
#else
#define DEBUG_IOVEC_SCATTERLISTS(buf...)
#define iscsi_check_iovec_map(a,b,c,d)
#endif

/*	transport_generic_set_iovec_ptrs():
 *
 *
 */
static int transport_generic_set_iovec_ptrs (
	iscsi_map_sg_t *map_sg,
	iscsi_unmap_sg_t *unmap_sg)
{
	u32 i = 0 /* For iovecs */, j = 0 /* For scatterlists */;
#ifdef iscsi_OS_set_SG_iovec_ptrs_DEBUG
	u32 orig_map_length = map_sg->data_length;
#endif
	iscsi_cmd_t *cmd = (iscsi_cmd_t *) map_sg->cmd;
	iscsi_offset_map_t *lmap = &unmap_sg->lmap;
	struct iovec *iov = map_sg->iov;	

	/*
	 * Used for non scatterlist operations, assume a single iovec.
	 */
	if (!T_TASK(cmd)->t_task_se_num) {
		DEBUG_IOVEC_SCATTERLISTS("ITT: 0x%08x No se_mem_t elements present\n",
				cmd->init_task_tag);
		iov[0].iov_base = (unsigned char *) T_TASK(cmd)->t_task_buf + map_sg->data_offset;
		iov[0].iov_len  = map_sg->data_length;
		return(1);
	}
	
	/*
	 * Set lmap->map_reset = 1 so the first call to transport_calculate_map_segment()
	 * sets up the initial values for iscsi_offset_map_t.
	 */
	lmap->map_reset = 1;

	DEBUG_IOVEC_SCATTERLISTS("[-------------------] ITT: 0x%08x OS Independent Network POSIX"
		" defined iovectors to SE Memory [-------------------]\n\n", cmd->init_task_tag);

	/*
	 * Get a pointer to the first used scatterlist based on the passed offset.
	 * Also set the rest of the needed values in iscsi_linux_map_t.
	 */
	lmap->iscsi_offset = map_sg->data_offset;
	if (map_sg->map_flags & MAP_SG_KMAP) {
		unmap_sg->cmd = map_sg->cmd;
		transport_get_iscsi_offset(lmap, unmap_sg);
		unmap_sg->data_length = map_sg->data_length;
	} else {
		lmap->current_offset = lmap->orig_offset;
	}
	lmap->map_se_mem = lmap->map_orig_se_mem;
	
	DEBUG_IOVEC_SCATTERLISTS("OS_IOVEC: Total map_sg->data_length: %d,"
		" lmap->iscsi_offset: %d, cmd->orig_iov_data_count: %d\n",
		map_sg->data_length, lmap->iscsi_offset, cmd->orig_iov_data_count);

	while (map_sg->data_length) {
		/*
		 * Time to get the virtual address for use with iovec pointers.
		 * This function will return the expected iovec_base address and iovec_length.
		 */
		transport_calculate_map_segment(&map_sg->data_length, lmap);

		/*
		 * Set the iov.iov_base and iov.iov_len from the current values
		 * in iscsi_linux_map_t.
		 */
		iov[i].iov_base = lmap->iovec_base;
		iov[i].iov_len = lmap->iovec_length;

		/*
		 * Subtract the final iovec length from the total length to be
		 * mapped, and the length of the current scatterlist.  Also
		 * perform the paranoid check to make sure we are not going to
		 * overflow the iovecs allocated for this command in the next
		 * pass.
		 */
		map_sg->data_length -= iov[i].iov_len;
		lmap->sg_length -= iov[i].iov_len;

		DEBUG_IOVEC_SCATTERLISTS("OS_IOVEC: iov[%u].iov_len: %u\n",
				i, iov[i].iov_len);
		DEBUG_IOVEC_SCATTERLISTS("OS_IOVEC: lmap->sg_length: from %u"
			" to %u\n", lmap->sg_length + iov[i].iov_len,
				lmap->sg_length);
		DEBUG_IOVEC_SCATTERLISTS("OS_IOVEC: Changed total"
			" map_sg->data_length from %u to %u\n",
			map_sg->data_length + iov[i].iov_len, map_sg->data_length);

		if ((++i + 1) > cmd->orig_iov_data_count) {
			TRACE_ERROR("Current iovec count %u is greater than"
				" iscsi_cmd_t->orig_data_iov_count %u, cannot"
				" continue.\n", i+1, cmd->orig_iov_data_count);
			return(-1);
		}

		/*
		 * All done mapping this scatterlist's pages, move on to
		 * the next scatterlist by setting lmap.map_reset = 1;
		 */
		if (!lmap->sg_length || !map_sg->data_length) {
			list_for_each_entry(lmap->map_se_mem, &lmap->map_se_mem->se_list, se_list)
				break;

			if (!lmap->map_se_mem) {
				TRACE_ERROR("Unable to locate next lmap->map_se_mem_t entry\n");
				return(-1);
			}
			j++;
			
			lmap->sg_page = NULL;
			lmap->map_reset = 1;

			DEBUG_IOVEC_SCATTERLISTS("OS_IOVEC: Done with current"
				" scatterlist, incremented Generic scatterlist"
				" Counter to %d and reset = 1\n", j);
		} else
			lmap->sg_page++;
	}
	
	unmap_sg->sg_count = j;

	iscsi_check_iovec_map(i, orig_map_length, map_sg, unmap_sg);

	return(i);
}

/*	transport_generic_allocate_buf():
 *
 *	Called from transport_generic_new_cmd() in Transport Processing Thread.
 */
extern int transport_generic_allocate_buf (
	iscsi_cmd_t *cmd,
	u32 data_length,
	u32 dma_size)
{
	unsigned char *buf;

	if (!(buf = (unsigned char *) kmalloc(data_length, GFP_KERNEL))) {
		TRACE_ERROR("Unable to allocate memory for buffer\n");
		return(-1);
	}
	memset(buf, 0, data_length);

	T_TASK(cmd)->t_task_se_num = 0;
	T_TASK(cmd)->t_task_buf = buf;
	
	return(0);
}

/*	transport_generic_allocate_none():
 *
 *
 */
static int transport_generic_allocate_none (
	iscsi_cmd_t *cmd,
	u32 data_length,
	u32 dma_size)
{
	return(0);
}

/*	transport_generic_map_SG_segments():
 *
 *
 */
static void transport_generic_map_SG_segments (iscsi_unmap_sg_t *unmap_sg)
{
	u32 i = 0;
	iscsi_cmd_t *cmd = (iscsi_cmd_t *) unmap_sg->cmd;
	se_mem_t *se_mem = unmap_sg->cur_se_mem;

	if (!(T_TASK(cmd)->t_task_se_num))
		return;

	list_for_each_entry_continue(se_mem, T_TASK(cmd)->t_mem_list, se_list) {
		kmap(se_mem->se_page);

		if (++i == unmap_sg->sg_count)
			break;
	}

	return;
}

/*	transport_generic_unmap_SG_segments():
 *
 *
 */
static void transport_generic_unmap_SG_segments (iscsi_unmap_sg_t *unmap_sg)
{
	u32 i = 0;
	iscsi_cmd_t *cmd = (iscsi_cmd_t *) unmap_sg->cmd;
	se_mem_t *se_mem = unmap_sg->cur_se_mem;

	if (!(T_TASK(cmd)->t_task_se_num))
		return;

	list_for_each_entry_continue(se_mem, T_TASK(cmd)->t_mem_list, se_list) {
		kunmap(se_mem->se_page);

		if (++i == unmap_sg->sg_count)
			break;
	}

	return;
}

static inline u32 transport_lba_21 (unsigned char *cdb)
{
	return(((cdb[1] & 0x1f) << 16) | (cdb[2] << 8) | cdb[3]);
}

static inline u32 transport_lba_32 (unsigned char *cdb)
{
	return((cdb[2] << 24) | (cdb[3] << 16) | (cdb[4] << 8) | cdb[5]);
}

static inline unsigned long long transport_lba_64 (unsigned char *cdb)
{
	unsigned int __v1, __v2;
	
	__v1 = (cdb[2] << 24) | (cdb[3] << 16) | (cdb[4] << 8) | cdb[5];
	__v2 = (cdb[6] << 24) | (cdb[7] << 16) | (cdb[8] << 8) | cdb[9];

	return(((unsigned long long)__v2) | (unsigned long long)__v1 << 32);
}

/*	transport_set_supported_SAM_opcode():
 *
 *
 */
static inline void transport_set_supported_SAM_opcode (iscsi_cmd_t *cmd)
{
	spin_lock_bh(&cmd->istate_lock);
	cmd->cmd_flags |= ICF_SUPPORTED_SAM_OPCODE;
	spin_unlock_bh(&cmd->istate_lock);

	return;
}

/*
 * Called from interrupt context.
 */
extern void transport_task_timeout_handler (unsigned long data)
{
	se_task_t *task = (se_task_t *)data;
	iscsi_cmd_t *cmd = task->iscsi_cmd;
	unsigned long flags;

	DEBUG_TT("transport task timeout fired! task: %p cmd: %p\n", task, cmd);

	spin_lock_irqsave(&T_TASK(cmd)->t_state_lock, flags); 
	if (task->task_flags & TF_STOP) {
		spin_unlock_irqrestore(&T_TASK(cmd)->t_state_lock, flags);
		return;
	}
	task->task_flags &= ~TF_RUNNING;

	/*
	 * Determine if transport_complete_task() has already been called.
	 */
	if (!(atomic_read(&task->task_active))) {
		DEBUG_TT("transport task: %p cmd: %p timeout task_active == 0\n", task, cmd);
		spin_unlock_irqrestore(&T_TASK(cmd)->t_state_lock, flags);
		return;
	}
	
	atomic_inc(&T_TASK(cmd)->t_se_count);
	atomic_inc(&T_TASK(cmd)->t_transport_timeout);
	T_TASK(cmd)->t_tasks_failed = 1;

	atomic_set(&task->task_timeout, 1);
	task->task_error_status = PYX_TRANSPORT_TASK_TIMEOUT;
	task->task_scsi_status = 1;
	
	if (atomic_read(&task->task_stop)) {
		DEBUG_TT("transport task: %p cmd: %p timeout task_stop == 1\n", task, cmd);
		spin_unlock_irqrestore(&T_TASK(cmd)->t_state_lock, flags);
		up(&task->task_stop_sem);
		return;
	}

	if (!(atomic_dec_and_test(&T_TASK(cmd)->t_task_cdbs_left))) {
		DEBUG_TT("transport task: %p cmd: %p timeout non zero t_task_cdbs_left\n", task, cmd);
		spin_unlock_irqrestore(&T_TASK(cmd)->t_state_lock, flags);
		return;
	}
	DEBUG_TT("transport task: %p cmd: %p timeout ZERO t_task_cdbs_left\n", task, cmd);
	
	cmd->t_state = TRANSPORT_COMPLETE_FAILURE;
	spin_unlock_irqrestore(&T_TASK(cmd)->t_state_lock, flags);

	cmd->transport_add_cmd_to_queue(cmd, TRANSPORT_COMPLETE_FAILURE);

	return;
}

/*
 * Called with T_TASK(cmd)->t_state_lock held.
 */
extern void transport_start_task_timer (se_task_t *task)
{
	unsigned char *cdb;
	int timeout;

	if (task->task_flags & TF_RUNNING)
		return;

	if (task->se_obj_api->set_task_timeout_handler) {
		if (task->se_obj_api->set_task_timeout_handler(task->se_obj_ptr, task) == 1)
			return;
	}
	
	if (!(cdb = task->se_obj_api->get_cdb(task->se_obj_ptr, task)))
		timeout = task->se_obj_api->get_task_timeout(task->se_obj_ptr);
	else {
		if ((cdb[0] == TEST_UNIT_READY) &&
	            (task->iscsi_cmd->cmd_flags & ICF_SE_DISABLE_ONLINE_CHECK))
			timeout = TRANSPORT_TIMEOUT_TUR;
		else
			timeout = task->se_obj_api->get_task_timeout(task->se_obj_ptr);
	}

	init_timer(&task->task_timer);
	SETUP_TIMER(task->task_timer, timeout, task, transport_task_timeout_handler);
	task->task_flags |= TF_RUNNING;
	add_timer(&task->task_timer);
#if 0
	TRACE_ERROR("Starting task timer for cmd: %p task: %p seconds: %d\n",
			task->iscsi_cmd, task, timeout);
#endif
	return;
}

/*
 * Called with spin_lock_irq(&T_TASK(cmd)->t_state_lock) held.
 */
extern void __transport_stop_task_timer (se_task_t *task, unsigned long *flags)
{
	iscsi_cmd_t *cmd = task->iscsi_cmd;

	if (!(task->task_flags & TF_RUNNING))
		return;

	task->task_flags |= TF_STOP;
	spin_unlock_irqrestore(&T_TASK(cmd)->t_state_lock, *flags);

	del_timer_sync(&task->task_timer);

	spin_lock_irqsave(&T_TASK(cmd)->t_state_lock, *flags);
	task->task_flags &= ~TF_RUNNING;
	task->task_flags &= ~TF_STOP;

	return;
}

extern void transport_stop_task_timer (se_task_t *task)
{
	iscsi_cmd_t *cmd = task->iscsi_cmd;
	unsigned long flags;
#if 0	
	TRACE_ERROR("Stopping task timer for cmd: %p task: %p\n", cmd, task);
#endif	
	spin_lock_irqsave(&T_TASK(cmd)->t_state_lock, flags);
	if (!(task->task_flags & TF_RUNNING)) {
		spin_unlock_irqrestore(&T_TASK(cmd)->t_state_lock, flags);
		return;
	}
	task->task_flags |= TF_STOP;
	spin_unlock_irqrestore(&T_TASK(cmd)->t_state_lock, flags);

	del_timer_sync(&task->task_timer);

	spin_lock_irqsave(&T_TASK(cmd)->t_state_lock, flags);
	task->task_flags &= ~TF_RUNNING;
	task->task_flags &= ~TF_STOP;
	spin_unlock_irqrestore(&T_TASK(cmd)->t_state_lock, flags);

	return;
}

extern void transport_stop_all_task_timers (iscsi_cmd_t *cmd)
{
	se_task_t *task = NULL, *task_tmp;
	unsigned long flags;

	spin_lock_irqsave(&T_TASK(cmd)->t_state_lock, flags);
	list_for_each_entry_safe(task, task_tmp, &T_TASK(cmd)->t_task_list, t_list)
		__transport_stop_task_timer(task, &flags);	
	spin_unlock_irqrestore(&T_TASK(cmd)->t_state_lock, flags);

	return;
}

static inline int transport_tcq_window_closed (se_device_t *dev)
{
	if (dev->dev_tcq_window_closed++ < PYX_TRANSPORT_WINDOW_CLOSED_THRESHOLD) {
		msleep(PYX_TRANSPORT_WINDOW_CLOSED_WAIT_SHORT);
	} else {
		msleep(PYX_TRANSPORT_WINDOW_CLOSED_WAIT_LONG);
	}

	up(&dev->dev_queue_obj->thread_sem);
	return(0);
}

extern int transport_execute_tasks (iscsi_cmd_t *cmd)
{
	if (!(cmd->cmd_flags & ICF_SE_DISABLE_ONLINE_CHECK)) {
		if (CMD_ORIG_OBJ_API(cmd)->check_online(cmd->se_orig_obj_ptr) != 0) {
			cmd->transport_error_status = PYX_TRANSPORT_LOGICAL_UNIT_COMMUNICATION_FAILURE;
			transport_generic_request_failure(cmd, NULL, 0, 1);
			return(0);
		}
	}
	
	/*
	 * transport_process_feature() will determine if this frontend
	 * T_TASK(cmd) is handed off to a feature plugin.
	 */
	if (cmd->transport_feature_io) {
		if (!transport_cmd_check_stop(cmd, 0, TRANSPORT_PROCESSING))
			cmd->transport_feature_io(T_TASK(cmd)->t_fp, cmd);
		return(0);
	}

	/*
	 * Add the task(s) built for the passed iscsi_cmd_t to the
	 * execution queue for this se_device_t.
	 */
	if (!transport_cmd_check_stop(cmd, 0, TRANSPORT_PROCESSING))
		CMD_ORIG_OBJ_API(cmd)->add_tasks(cmd->se_orig_obj_ptr, cmd);

	CMD_ORIG_OBJ_API(cmd)->execute_tasks(cmd->se_orig_obj_ptr);

	return(0);
}

extern int __transport_execute_tasks (se_device_t *dev)
{
	int error;
	iscsi_cmd_t *cmd = NULL;
	se_task_t *task;
        unsigned long flags;
	
	/*
	 * Check if there is enough room in the device and HBA queue to send
	 * se_transport_task_t's to the selected transport.
	 */
check_depth:
	spin_lock_irqsave(&ISCSI_HBA(dev)->hba_queue_lock, flags);
	if (!(atomic_read(&dev->depth_left)) ||
	    !(atomic_read(&ISCSI_HBA(dev)->left_queue_depth))) {
		spin_unlock_irqrestore(&ISCSI_HBA(dev)->hba_queue_lock, flags);
		return(transport_tcq_window_closed(dev));
	}
	dev->dev_tcq_window_closed = 0;

	spin_lock(&dev->execute_task_lock);
	task = transport_get_task_from_execute_queue(dev);
	spin_unlock(&dev->execute_task_lock);

	if (!task) {
		spin_unlock_irqrestore(&ISCSI_HBA(dev)->hba_queue_lock, flags);
		return(0);
	}

	atomic_dec(&dev->depth_left);
	atomic_dec(&ISCSI_HBA(dev)->left_queue_depth);
	spin_unlock_irqrestore(&ISCSI_HBA(dev)->hba_queue_lock, flags);

	cmd = task->iscsi_cmd;

	spin_lock_irqsave(&T_TASK(cmd)->t_state_lock, flags);
	atomic_set(&task->task_active, 1);
	atomic_set(&task->task_sent, 1);
	atomic_inc(&T_TASK(cmd)->t_task_cdbs_sent);

	if (atomic_read(&T_TASK(cmd)->t_task_cdbs_sent) == 
	    T_TASK(cmd)->t_task_cdbs)
		atomic_set(&cmd->transport_sent, 1);

	transport_start_task_timer(task);
	spin_unlock_irqrestore(&T_TASK(cmd)->t_state_lock, flags);

	if ((error = TRANSPORT(dev)->do_task(task)) != 0) {
		cmd->transport_error_status = error;
		atomic_set(&task->task_active, 0);
		atomic_set(&cmd->transport_sent, 0);
		transport_stop_tasks_for_cmd(cmd);
		transport_generic_request_failure(cmd, dev, 0, 1);
	}

	goto check_depth;

	return(0);
}

/*	transport_new_cmd_failure():
 *
 *
 */
extern void transport_new_cmd_failure (iscsi_cmd_t *cmd)
{
	/*
	 * Any unsolicited data will get dumped for failed command.
	 */
	spin_lock_bh(&cmd->istate_lock);
	cmd->cmd_flags |= ICF_SE_CMD_FAILED;
	cmd->cmd_flags |= ICF_SCSI_CDB_EXCEPTION;
	spin_unlock_bh(&cmd->istate_lock);

	if (cmd->immediate_data || cmd->unsolicited_data)
		up(&cmd->unsolicited_data_sem);

	return;
}

static int transport_generic_map_buffers_to_tasks (iscsi_cmd_t *);
static void transport_nop_wait_for_tasks (iscsi_cmd_t *, int, int);

static inline u32 transport_get_sectors_6 (unsigned char *cdb, iscsi_cmd_t *cmd, int *ret)
{
	se_device_t *dev = ISCSI_LUN(cmd)->iscsi_dev;
	
	/*
	 * Assume TYPE_DISK for non se_device_t objects.
	 * Use 8-bit sector value.
	 */
	if (!dev)
		goto type_disk;

	/*
	 * Use 24-bit allocation length for TYPE_TAPE.
	 */
	if (TRANSPORT(dev)->get_device_type(dev) == TYPE_TAPE)
		return((u32)(cdb[2] << 16) + (cdb[3] << 8) + cdb[4]);

	/*
	 * Everything else assume TYPE_DISK Sector CDB location.
	 * Use 8-bit sector value.
	 */
type_disk:
	return((u32)cdb[4]);
}

static inline u32 transport_get_sectors_10 (unsigned char *cdb, iscsi_cmd_t *cmd, int *ret)
{
	se_device_t *dev = ISCSI_LUN(cmd)->iscsi_dev;

	/*
	 * Assume TYPE_DISK for non se_device_t objects.
	 * Use 16-bit sector value.
	 */
	if (!dev)
		goto type_disk;
	
	/*
	 * XXX_10 is not defined in SSC, throw an exception
	 */
	if (TRANSPORT(dev)->get_device_type(dev) == TYPE_TAPE) {
		*ret = -1;
		return(0);
	}

	/*
	 * Everything else assume TYPE_DISK Sector CDB location.
	 * Use 16-bit sector value.
	 */
type_disk:
	return((u32)(cdb[7] << 8) + cdb[8]);
}

static inline u32 transport_get_sectors_12 (unsigned char *cdb, iscsi_cmd_t *cmd, int *ret)
{
	se_device_t *dev = ISCSI_LUN(cmd)->iscsi_dev;

	/*
	 * Assume TYPE_DISK for non se_device_t objects.
	 * Use 32-bit sector value.
	 */
	if (!dev)
		goto type_disk;
	
	/*
	 * XXX_12 is not defined in SSC, throw an exception
	 */
	if (TRANSPORT(dev)->get_device_type(dev) == TYPE_TAPE) {
		*ret = -1;
		return(0);
	}

	/*
	 * Everything else assume TYPE_DISK Sector CDB location.
	 * Use 32-bit sector value.
	 */
type_disk:
	return((u32)(cdb[6] << 24) + (cdb[7] << 16) + (cdb[8] << 8) + cdb[9]);
}

static inline u32 transport_get_sectors_16 (unsigned char *cdb, iscsi_cmd_t *cmd, int *ret)
{
	se_device_t *dev = ISCSI_LUN(cmd)->iscsi_dev;
	
	/*
	 * Assume TYPE_DISK for non se_device_t objects.
	 * Use 32-bit sector value.
	 */
	if (!dev)
		goto type_disk;

	/*
	 * Use 24-bit allocation length for TYPE_TAPE.
	 */
	if (TRANSPORT(dev)->get_device_type(dev) == TYPE_TAPE)
		return((u32)(cdb[12] << 16) + (cdb[13] << 8) + cdb[14]);

type_disk:
	return((u32)(cdb[10] << 24) + (cdb[11] << 16) + (cdb[12] << 8) + cdb[13]);
}

static inline u32 transport_get_size (u32 sectors, unsigned char *cdb, iscsi_cmd_t *cmd)
{
	return(CMD_ORIG_OBJ_API(cmd)->get_cdb_size(cmd->se_orig_obj_ptr, sectors, cdb));
}

static inline void transport_get_maps (iscsi_cmd_t *cmd)
{
	cmd->transport_map_SG_segments = &transport_generic_map_SG_segments;
	cmd->transport_unmap_SG_segments = &transport_generic_unmap_SG_segments;
	return;
}

extern int transport_generic_emulate_inquiry (
	iscsi_cmd_t *cmd,
	unsigned char type,
	unsigned char *prod,
	unsigned char *version,
	unsigned char *se_location,
	unsigned char *sub_sn)
{
	u32 len = 0;
	unsigned char *dst = (unsigned char *) T_TASK(cmd)->t_task_buf;
	unsigned char *cdb = T_TASK(cmd)->t_task_cdb;
	unsigned char *iqn_sn, buf[EVPD_BUF_LEN];
	
	memset(dst, 0, cmd->data_length);
	memset(buf, 0, EVPD_BUF_LEN);

	buf[0] = type;
	
	if (!(cdb[1] & 0x1)) {
		if (type == TYPE_TAPE)
			buf[1] = 0x80;
		buf[2]          = 0x02;
		buf[4]          = 31;
		buf[7]		= 0x32; /* Sync=1 and CmdQue=1 */
		
		sprintf((unsigned char *)&buf[8], "LIO-ORG");
		
		sprintf((unsigned char *)&buf[16], "%s", prod);
		snprintf((unsigned char *)&buf[32], 5, "%s", version);
		len = 32;

		goto copy;
	}

	switch (cdb[2]) {
	case 0x00: /* supported vital product data pages */
		buf[1] = 0x00;
		buf[3] = 3;
		buf[4] = 0x0;
		buf[5] = 0x80;
		buf[6] = 0x83;
		len = 3;
		break;
	case 0x80: /* unit serial number */
		buf[1] = 0x80;
		if (sub_sn)
			len += sprintf((unsigned char *)&buf[4], "%s", sub_sn);
		else {
			iqn_sn = transport_get_iqn_sn();
			len += sprintf((unsigned char *)&buf[4], "%s:%s",
				iqn_sn, se_location);
		}
		buf[3] = len;
		break;
	case 0x83: /* device identification */
		buf[1] = 0x83;
		/* Start Identifier Page */
		buf[4] = 0x2; /* ASCII */
		buf[5] = 0x1;
		buf[6] = 0x0;
		
		len += sprintf((unsigned char *)&buf[8], "%-8s", "LIO-ORG");
		
		if (sub_sn)
			len += sprintf((unsigned char *)&buf[16], "%s:%s", prod, sub_sn);
		else {
			iqn_sn = transport_get_iqn_sn();
			len += sprintf((unsigned char *)&buf[16], "%s:%s:%s", prod,
					iqn_sn, se_location);
		}
		buf[7] = len; /* Identifier Length */
		len += 4;
		buf[3] = len; /* Page Length */
		break;
	default:
		TRACE_ERROR("Unknown EVPD Code: 0x%02x\n", cdb[2]);
		return(-1);
	}

copy:
	if ((len + 4) > cmd->data_length) {
		TRACE_ERROR("Inquiry EVPD Length: %u larger than"
			" cmd->data_length: %u\n", (len + 4), cmd->data_length);
		memcpy(dst, buf, cmd->data_length);
	} else
		memcpy(dst, buf, (len + 4));

	return(0);
}

extern int transport_generic_emulate_readcapacity (
	iscsi_cmd_t *cmd, 
	u32 blocks,
	u32 blocksize)
{
	unsigned char *buf = (unsigned char *) T_TASK(cmd)->t_task_buf;

	buf[0] = (blocks >> 24) & 0xff;
	buf[1] = (blocks >> 16) & 0xff;
	buf[2] = (blocks >> 8) & 0xff;
	buf[3] = blocks & 0xff;
	buf[4] = (blocksize >> 24) & 0xff;
	buf[5] = (blocksize >> 16) & 0xff;
	buf[6] = (blocksize >> 8) & 0xff;
	buf[7] = blocksize & 0xff;
		
	return(0);
}

extern int transport_generic_emulate_readcapacity_16 (
	iscsi_cmd_t *cmd,
	unsigned long long blocks,
	u32 blocksize)
{
	unsigned char *buf = (unsigned char *) T_TASK(cmd)->t_task_buf;

	buf[0] = (blocks >> 56) & 0xff;
	buf[1] = (blocks >> 48) & 0xff;
	buf[2] = (blocks >> 40) & 0xff;
	buf[3] = (blocks >> 32) & 0xff;
	buf[4] = (blocks >> 24) & 0xff;
	buf[5] = (blocks >> 16) & 0xff;
	buf[6] = (blocks >> 8) & 0xff;
	buf[7] = blocks & 0xff;
	buf[8] = (blocksize >> 24) & 0xff;
	buf[9] = (blocksize >> 16) & 0xff;
	buf[10] = (blocksize >> 8) & 0xff;
	buf[11] = blocksize & 0xff;

	return(0);
}

static int transport_modesense_rwrecovery (unsigned char *p)
{
	p[0] = 0x01;
	p[1] = 0x0a;

	return(12);
}

static int transport_modesense_control (unsigned char *p)
{
	p[0] = 0x0a;
	p[1] = 0x0a;
	p[2] = 2;
	p[8] = 0xff;
	p[9] = 0xff;
	p[11] = 30;
	
	return(12);
	
}

static int transport_modesense_caching (unsigned char *p)
{
	p[0] = 0x08;
	p[1] = 0x12;
//	p[2] = 0x04; /* Write Cache Enable */
	p[12] = 0x20; /* Disabled Read Ahead */

	return(20);
}

#if 0
static int transport_modesense_devicecaps (unsigned char *p)
{
	p[0] = 0x2a;
	p[1] = 0x0a;

	return(12);
}
#endif

static void transport_modesense_write_protect (
	unsigned char *buf,
	int type)
{
	/*
	 * I believe that the WP bit (bit 7) in the mode header is the same for
	 * all device types..
	 */
	switch (type) {
	case TYPE_DISK:
	case TYPE_TAPE:
	default:
		buf[0] |= 0x80; /* WP bit */
		break;
	}

	return;
}

extern int transport_generic_emulate_modesense (
	iscsi_cmd_t *cmd,
	unsigned char *cdb,
	unsigned char *rbuf,
	int ten,
	int type)
{
	int offset = (ten) ? 8 : 4;
	int length = 0;
	unsigned char buf[SE_MODE_PAGE_BUF];

	memset(buf, 0, SE_MODE_PAGE_BUF);
	
	switch (cdb[2] & 0x3f) {
	case 0x01:
		length = transport_modesense_rwrecovery(&buf[offset]);
		break;
	case 0x08:
		length = transport_modesense_caching(&buf[offset]);
		break;
	case 0x0a:
		length = transport_modesense_control(&buf[offset]);
		break;
#if 0
	case 0x2a:
		length = transport_modesense_devicecaps(&buf[offset]);
		break;
#endif
	case 0x3f:
		length = transport_modesense_rwrecovery(&buf[offset]);
		length += transport_modesense_caching(&buf[offset+length]);
		length += transport_modesense_control(&buf[offset+length]);
#if 0
		length += transport_modesense_devicecaps(&buf[offset+length]);
#endif
		break;
	default:
		TRACE_ERROR("Got Unknown Mode Page: 0x%02x\n", cdb[2] & 0x3f);
		return(PYX_TRANSPORT_UNKNOWN_MODE_PAGE);
	}
	offset += length;

	if (ten) { 
		offset -= 2;
		buf[0] = (offset >> 8) & 0xff;
		buf[1] = offset & 0xff;

		if ((ISCSI_LUN(cmd)->lun_access & ISCSI_LUNFLAGS_READ_ONLY) ||
		    (cmd->iscsi_deve && (cmd->iscsi_deve->lun_flags & ISCSI_LUNFLAGS_READ_ONLY)))
			transport_modesense_write_protect(&buf[3], type);

		if ((offset + 2) > cmd->data_length)
			offset = cmd->data_length;
		
	} else {
		offset -= 1;
		buf[0] = offset & 0xff;

		if ((ISCSI_LUN(cmd)->lun_access & ISCSI_LUNFLAGS_READ_ONLY) ||
		    (cmd->iscsi_deve && (cmd->iscsi_deve->lun_flags & ISCSI_LUNFLAGS_READ_ONLY)))
			transport_modesense_write_protect(&buf[2], type);

		if ((offset + 1) > cmd->data_length)
			offset = cmd->data_length;
	}

	memcpy(rbuf, buf, offset); 
	
	return(0);
}

extern int transport_get_sense_data (iscsi_cmd_t *cmd)
{
	unsigned char *buffer = NULL, *sense_buffer = NULL;
	se_device_t *dev;
	se_task_t *task = NULL, *task_tmp;
	unsigned long flags;

	if (!ISCSI_LUN(cmd)) {
		TRACE_ERROR("ISCSI_LUN(cmd) is NULL\n");
		return(-1);
	}

	if (cmd->buf_ptr) {
		TRACE_ERROR("iscsi_cmd_t->buf_ptr already present\n");
		return(-1);
	}

	if (!(buffer = (char *) kmalloc(ISCSI_SENSE_SEGMENT_TOTAL, GFP_KERNEL))) {
		TRACE_ERROR("Unable to allocate memory for SENSE buffer\n");
		return(-1);
	}	
	memset(buffer, 0, ISCSI_SENSE_SEGMENT_TOTAL);
	cmd->buf_ptr    = buffer;

	buffer[0]       = ((ISCSI_SENSE_BUFFER >> 8) & 0xff);
	buffer[1]       = (ISCSI_SENSE_BUFFER & 0xff);

	spin_lock_irqsave(&T_TASK(cmd)->t_state_lock, flags);
	list_for_each_entry_safe(task, task_tmp, &T_TASK(cmd)->t_task_list, t_list) {
		
		if (!task->task_sense)
			continue;

		if (!(dev = task->iscsi_dev))
			continue;

		if (!TRANSPORT(dev)->get_sense_buffer) {
			TRACE_ERROR("TRANSPORT(dev)->get_sense_buffer is NULL\n");
			continue;	
		}

		if (!(sense_buffer = TRANSPORT(dev)->get_sense_buffer(task))) {
			TRACE_ERROR("ITT[0x%08x]_TASK[%d]: Unable to locate"
				" sense buffer for task with sense\n",
				cmd->init_task_tag, task->task_no);
			continue;
		}
		spin_unlock_irqrestore(&T_TASK(cmd)->t_state_lock, flags);
		
		memcpy((void *)&buffer[2], (void *)sense_buffer, ISCSI_SENSE_BUFFER);
		cmd->scsi_status = task->task_scsi_status;
		cmd->scsi_sense_length = ISCSI_SENSE_SEGMENT_LENGTH; /* Automatically padded */

		PYXPRINT("HBA_[%u]_PLUG[%s]: Set SAM STATUS: 0x%02x\n",
			dev->iscsi_hba->hba_id, TRANSPORT(dev)->name, cmd->scsi_status);

		return(0);
	}
	spin_unlock_irqrestore(&T_TASK(cmd)->t_state_lock, flags);

	return(-1);
}

/*
 * Generic function pointers for the iSCSI Transport.
 */
#define SET_GENERIC_PYX_TRANSPORT_FUNCTIONS(cmd)					\
	cmd->transport_allocate_iovecs = &transport_generic_allocate_iovecs;		\
	cmd->transport_get_task = &transport_generic_get_task;				\
	cmd->transport_map_buffers_to_tasks = &transport_generic_map_buffers_to_tasks;	\
	cmd->transport_set_iovec_ptrs = &transport_generic_set_iovec_ptrs;

/*	transport_generic_cmd_sequencer():
 *
 *	Generic Command Sequencer that should work for most DAS transport drivers.
 *
 *	Called from transport_generic_allocate_tasks() in the iSCSI RX Thread.
 * 
 *	FIXME: Need to support other SCSI OPCODES where as well.
 */
static int transport_generic_cmd_sequencer (
	iscsi_cmd_t *cmd,
	unsigned char *cdb)
{
	int ret = 0, sector_ret = 0;
	u32 sectors = 0, size = 0;

	if (ISCSI_LUN(cmd)->persistent_reservation_check(cmd) != 0) {
		switch (cdb[0]) {
		case INQUIRY:
	                SET_GENERIC_PYX_TRANSPORT_FUNCTIONS(cmd);
	                size = cdb[4];
	                CMD_ORIG_OBJ_API(cmd)->get_mem_buf(cmd->se_orig_obj_ptr, cmd);
			transport_get_maps(cmd);
	                ret = 2;
	                break;
		case RELEASE:
		case RELEASE_10:
			SET_GENERIC_PYX_TRANSPORT_FUNCTIONS(cmd);
			cmd->transport_allocate_resources = &transport_generic_allocate_none;
			transport_get_maps(cmd);

			ISCSI_LUN(cmd)->persistent_reservation_release(cmd);
			ret = 3;
			break;
		default:
			cmd->transport_wait_for_tasks = &transport_nop_wait_for_tasks;
			transport_get_maps(cmd);
			return(5);
		}
			
		goto check_size;
	}

	switch (cdb[0]) {
	case READ_6:
		SET_GENERIC_PYX_TRANSPORT_FUNCTIONS(cmd);
		sectors = transport_get_sectors_6(cdb, cmd, &sector_ret);
		if (sector_ret)
			return(4);
		size = transport_get_size(sectors, cdb, cmd);
		CMD_ORIG_OBJ_API(cmd)->get_mem_SG(cmd->se_orig_obj_ptr, cmd);
		transport_get_maps(cmd);
		cmd->transport_split_cdb = &split_cdb_XX_6;
		cmd->transport_get_lba = &transport_lba_21;
		break; 
	case READ_10:
		SET_GENERIC_PYX_TRANSPORT_FUNCTIONS(cmd);
		sectors = transport_get_sectors_10(cdb, cmd, &sector_ret);
		if (sector_ret)
			return(4);
		size = transport_get_size(sectors, cdb, cmd);
		CMD_ORIG_OBJ_API(cmd)->get_mem_SG(cmd->se_orig_obj_ptr, cmd);
		transport_get_maps(cmd);
		cmd->transport_split_cdb = &split_cdb_XX_10;
		cmd->transport_get_lba = &transport_lba_32;
		break;
	case READ_12:
		SET_GENERIC_PYX_TRANSPORT_FUNCTIONS(cmd);
		sectors = transport_get_sectors_12(cdb, cmd, &sector_ret);
		if (sector_ret)
			return(4);
		size = transport_get_size(sectors, cdb, cmd);
		CMD_ORIG_OBJ_API(cmd)->get_mem_SG(cmd->se_orig_obj_ptr, cmd);
		transport_get_maps(cmd);
		cmd->transport_split_cdb = &split_cdb_XX_12;
		cmd->transport_get_lba = &transport_lba_32;
		break;
	case READ_16:
		SET_GENERIC_PYX_TRANSPORT_FUNCTIONS(cmd);
		sectors = transport_get_sectors_16(cdb, cmd, &sector_ret);
		if (sector_ret)
			return(4);
		size = transport_get_size(sectors, cdb, cmd);
		CMD_ORIG_OBJ_API(cmd)->get_mem_SG(cmd->se_orig_obj_ptr, cmd);
		transport_get_maps(cmd);
		cmd->transport_split_cdb = &split_cdb_XX_16;
		cmd->transport_get_long_lba = &transport_lba_64;
		break;
	case WRITE_6:
		SET_GENERIC_PYX_TRANSPORT_FUNCTIONS(cmd);
		sectors = transport_get_sectors_6(cdb, cmd, &sector_ret);
		if (sector_ret)
			return(4);
		size = transport_get_size(sectors, cdb, cmd);
		CMD_ORIG_OBJ_API(cmd)->get_mem_SG(cmd->se_orig_obj_ptr, cmd);
		transport_get_maps(cmd);
		cmd->transport_split_cdb = &split_cdb_XX_6;
		cmd->transport_get_lba = &transport_lba_21;
		break;
	case WRITE_10:
		SET_GENERIC_PYX_TRANSPORT_FUNCTIONS(cmd);
		sectors = transport_get_sectors_10(cdb, cmd, &sector_ret);
		if (sector_ret)
			return(4);
		size = transport_get_size(sectors, cdb, cmd);
		CMD_ORIG_OBJ_API(cmd)->get_mem_SG(cmd->se_orig_obj_ptr, cmd);
		transport_get_maps(cmd);
		cmd->transport_split_cdb = &split_cdb_XX_10;
		cmd->transport_get_lba = &transport_lba_32;
		break;
	case WRITE_12:
		SET_GENERIC_PYX_TRANSPORT_FUNCTIONS(cmd);
		sectors = transport_get_sectors_12(cdb, cmd, &sector_ret);
		if (sector_ret)
			return(4);
		size = transport_get_size(sectors, cdb, cmd);
		CMD_ORIG_OBJ_API(cmd)->get_mem_SG(cmd->se_orig_obj_ptr, cmd);
		transport_get_maps(cmd);
		cmd->transport_split_cdb = &split_cdb_XX_12;
		cmd->transport_get_lba = &transport_lba_32;
		break;
	case WRITE_16:
		SET_GENERIC_PYX_TRANSPORT_FUNCTIONS(cmd);
		sectors = transport_get_sectors_16(cdb, cmd, &sector_ret);
		if (sector_ret)
			return(4);
		size = transport_get_size(sectors, cdb, cmd);
		CMD_ORIG_OBJ_API(cmd)->get_mem_SG(cmd->se_orig_obj_ptr, cmd);
		transport_get_maps(cmd);
		cmd->transport_split_cdb = &split_cdb_XX_16;
		cmd->transport_get_long_lba = &transport_lba_64;
		break;
	case SEND_KEY:
		SET_GENERIC_PYX_TRANSPORT_FUNCTIONS(cmd);
		size = (cdb[8] << 8) + cdb[9];
		CMD_ORIG_OBJ_API(cmd)->get_mem_SG(cmd->se_orig_obj_ptr, cmd);
		transport_get_maps(cmd);
		ret = 1;
		break;
	case MODE_SELECT:
		SET_GENERIC_PYX_TRANSPORT_FUNCTIONS(cmd);
		size = cdb[4];
		CMD_ORIG_OBJ_API(cmd)->get_mem_SG(cmd->se_orig_obj_ptr, cmd);
		transport_get_maps(cmd);
		ret = 1;
		break;
	case MODE_SELECT_10:
		SET_GENERIC_PYX_TRANSPORT_FUNCTIONS(cmd);
		size = (cdb[7] << 8) + cdb[8];
		CMD_ORIG_OBJ_API(cmd)->get_mem_SG(cmd->se_orig_obj_ptr, cmd);
		transport_get_maps(cmd);
		ret = 1;
		break;
	case MODE_SENSE:
		SET_GENERIC_PYX_TRANSPORT_FUNCTIONS(cmd);
		size = cdb[4]; 
		CMD_ORIG_OBJ_API(cmd)->get_mem_buf(cmd->se_orig_obj_ptr, cmd);
		transport_get_maps(cmd);
		ret = 2;
		break;
	case MODE_SENSE_10:
	case READ_BUFFER_CAPACITY:
	case SEND_OPC_INFORMATION:
	case LOG_SENSE:
		SET_GENERIC_PYX_TRANSPORT_FUNCTIONS(cmd);
		size = (cdb[7] << 8) + cdb[8];
		CMD_ORIG_OBJ_API(cmd)->get_mem_buf(cmd->se_orig_obj_ptr, cmd);
		transport_get_maps(cmd);
		ret = 2;
		break;
	case READ_BLOCK_LIMITS:
		SET_GENERIC_PYX_TRANSPORT_FUNCTIONS(cmd);
		size = READ_BLOCK_LEN;
		CMD_ORIG_OBJ_API(cmd)->get_mem_buf(cmd->se_orig_obj_ptr, cmd);
		transport_get_maps(cmd);
		ret = 2;
		break;
	case GET_CONFIGURATION:
	case READ_DISK_INFORMATION:
	case READ_TRACK_RZONE_INFO:
	case PERSISTENT_RESERVE_IN:
	case PERSISTENT_RESERVE_OUT:
		SET_GENERIC_PYX_TRANSPORT_FUNCTIONS(cmd);
		size = (cdb[7] << 8) + cdb[8];
		CMD_ORIG_OBJ_API(cmd)->get_mem_SG(cmd->se_orig_obj_ptr, cmd);
		transport_get_maps(cmd);
		ret = 1;
		break;
	case READ_DVD_STRUCTURE:
		SET_GENERIC_PYX_TRANSPORT_FUNCTIONS(cmd);
		size = (cdb[8] << 8) + cdb[9];
		CMD_ORIG_OBJ_API(cmd)->get_mem_SG(cmd->se_orig_obj_ptr, cmd);
		transport_get_maps(cmd);
		ret = 1;
		break;
	case READ_POSITION:
		SET_GENERIC_PYX_TRANSPORT_FUNCTIONS(cmd);
		size = READ_POSITION_LEN;
		CMD_ORIG_OBJ_API(cmd)->get_mem_buf(cmd->se_orig_obj_ptr, cmd);
		transport_get_maps(cmd);
		ret = 2;
		break;
	case REPORT_KEY:
		SET_GENERIC_PYX_TRANSPORT_FUNCTIONS(cmd);
		size = (cdb[8] << 8) + cdb[9];
		CMD_ORIG_OBJ_API(cmd)->get_mem_SG(cmd->se_orig_obj_ptr, cmd);
		transport_get_maps(cmd);
		ret = 1;
		break;
	case INQUIRY:
		SET_GENERIC_PYX_TRANSPORT_FUNCTIONS(cmd);
		size = cdb[4];
		CMD_ORIG_OBJ_API(cmd)->get_mem_buf(cmd->se_orig_obj_ptr, cmd);
		transport_get_maps(cmd);
		ret = 2;
		break;
	case READ_BUFFER:
		SET_GENERIC_PYX_TRANSPORT_FUNCTIONS(cmd);
		size = (cdb[6] << 16) + (cdb[7] << 8) + cdb[8];
		CMD_ORIG_OBJ_API(cmd)->get_mem_buf(cmd->se_orig_obj_ptr, cmd);
		transport_get_maps(cmd);
		ret = 2;
		break;
	case READ_CAPACITY:
		SET_GENERIC_PYX_TRANSPORT_FUNCTIONS(cmd);
		size = READ_CAP_LEN;
		CMD_ORIG_OBJ_API(cmd)->get_mem_buf(cmd->se_orig_obj_ptr, cmd);
		transport_get_maps(cmd);
		ret = 2;
		break;
	case SERVICE_ACTION_IN:
		SET_GENERIC_PYX_TRANSPORT_FUNCTIONS(cmd);
		size = (cdb[10] << 24) | (cdb[11] << 16) | (cdb[12] << 8) | cdb[13];
		CMD_ORIG_OBJ_API(cmd)->get_mem_buf(cmd->se_orig_obj_ptr, cmd);
		transport_get_maps(cmd);
		ret = 2;
		break;
//#warning FIXME: Figure out correct READ_CD blocksize.
#if 0
	case READ_CD:
		SET_GENERIC_PYX_TRANSPORT_FUNCTIONS(cmd);
		sectors = (cdb[6] << 16) + (cdb[7] << 8) + cdb[8];
		size = (2336 * sectors);
		CMD_ORIG_OBJ_API(cmd)->get_mem_buf(cmd->se_orig_obj_ptr, cmd);
		transport_get_maps(cmd);
		ret = 2;
		break;
#endif
	case READ_TOC:  
		SET_GENERIC_PYX_TRANSPORT_FUNCTIONS(cmd);
		size = cdb[8];
		CMD_ORIG_OBJ_API(cmd)->get_mem_buf(cmd->se_orig_obj_ptr, cmd);
		transport_get_maps(cmd);
		ret = 2;
		break;
	case REQUEST_SENSE:
		SET_GENERIC_PYX_TRANSPORT_FUNCTIONS(cmd);
		size = cdb[4];
		CMD_ORIG_OBJ_API(cmd)->get_mem_buf(cmd->se_orig_obj_ptr, cmd);
		transport_get_maps(cmd);
		ret = 2;
		break;
	case READ_ELEMENT_STATUS:
		SET_GENERIC_PYX_TRANSPORT_FUNCTIONS(cmd);
		size = 65536 * cdb[7] + 256 * cdb[8] + cdb[9];
		CMD_ORIG_OBJ_API(cmd)->get_mem_buf(cmd->se_orig_obj_ptr, cmd);
		transport_get_maps(cmd);
		ret = 2;
		break;
	case WRITE_BUFFER:
		SET_GENERIC_PYX_TRANSPORT_FUNCTIONS(cmd);
		size = (cdb[6] << 16) + (cdb[7] << 8) + cdb[8];
		CMD_ORIG_OBJ_API(cmd)->get_mem_buf(cmd->se_orig_obj_ptr, cmd);
		transport_get_maps(cmd);
		ret = 2;
		break;
	case RESERVE:
	case RESERVE_10:
		SET_GENERIC_PYX_TRANSPORT_FUNCTIONS(cmd);
		cmd->transport_allocate_resources = &transport_generic_allocate_none;
		transport_get_maps(cmd);
		
		if ((ret = ISCSI_LUN(cmd)->persistent_reservation_reserve(cmd)))
			return(ret);
		
		ret = 3;
		break;
	case RELEASE:
	case RELEASE_10:
		SET_GENERIC_PYX_TRANSPORT_FUNCTIONS(cmd);
		cmd->transport_allocate_resources = &transport_generic_allocate_none;
		transport_get_maps(cmd);
		
		ISCSI_LUN(cmd)->persistent_reservation_release(cmd);
		ret = 3;
		break;
	case ALLOW_MEDIUM_REMOVAL:
	case CLOSE_TRACK:
	case ERASE:
	case INITIALIZE_ELEMENT_STATUS:
	case LOAD_UNLOAD_MEDIUM:
	case REZERO_UNIT:
	case SEEK_10:
	case SET_SPEED:
	case SPACE:
	case START_STOP:
	case SYNCHRONIZE_CACHE:
	case TEST_UNIT_READY:
	case VERIFY:
	case WRITE_FILEMARKS:
	case MOVE_MEDIUM:
		SET_GENERIC_PYX_TRANSPORT_FUNCTIONS(cmd);
		cmd->transport_allocate_resources = &transport_generic_allocate_none;
		transport_get_maps(cmd);
		ret = 3;
		break;
	case REPORT_LUNS:
		TRACE_ERROR("Huh? REPORT_LUNS in sequencer.\n");
		BUG();
	default:
		TRACE_ERROR("Unsupported SCSI Opcode 0x%02x, sending"
			" CHECK_CONDITION.\n", cdb[0]);
		cmd->transport_wait_for_tasks = &transport_nop_wait_for_tasks;
		transport_get_maps(cmd);
		return(4);
	}

check_size:
	if (size != cmd->data_length) {
		TRACE_ERROR("iSCSI Expected Transfer Length: %u does not"
		" match SCSI CDB Length: %u for SAM Opcode: 0x%02x\n",
			cmd->data_length, size, cdb[0]);

		cmd->cmd_spdtl = size;
#if 1
		if (cmd->data_direction == ISCSI_WRITE) {
			TRACE_ERROR("Rejecting underflow/overflow WRITE data\n");
			return(6);
		}
#endif
		if (size > cmd->data_length) {
			cmd->cmd_flags |= ICF_OVERFLOW_BIT;
			cmd->residual_count = (size - cmd->data_length);
		} else {
			cmd->cmd_flags |= ICF_UNDERFLOW_BIT;
			cmd->residual_count = (cmd->data_length - size);
		}
		cmd->data_length = size;
	}

	transport_set_supported_SAM_opcode(cmd);
	return(ret);
}

extern void transport_memcpy_read_contig (
	iscsi_cmd_t *cmd,
	unsigned char *dst)
{
	u32 i = 0, length = 0, total_length = cmd->data_length;
	struct scatterlist *sg_s = (struct scatterlist *) T_TASK(cmd)->t_task_buf;
	void *src;

	while (total_length) {
		length = sg_s[i].length;

		if (length > total_length)
			length = total_length;

		src = sg_virt(&sg_s[i]);

		memcpy(dst, src, length);

		if (!(total_length -= length))
			return;

		dst += length;
		i++;
	}

	return;
}

extern void transport_memcpy_read_sg (
	iscsi_cmd_t *cmd,
	struct scatterlist *sg_d)
{
	u32 i = 0, j = 0, dst_offset = 0, src_offset = 0;
	u32 length = 0, total_length = cmd->data_length;
	struct scatterlist *sg_s = (struct scatterlist *) T_TASK(cmd)->t_task_buf;
	void *dst, *src;

	while (total_length) {
		if ((sg_d[i].length - dst_offset) < (sg_s[j].length - src_offset)) {
			length = (sg_d[i].length - dst_offset);

			if (length > total_length)
				length = total_length;

			dst = sg_virt(&sg_d[i]) + dst_offset;
			if (!dst)
				BUG();
			i++;
			
			src = sg_virt(&sg_s[j]) + src_offset;
			if (!src)
				BUG();

			dst_offset = 0;
			src_offset = length;
		} else {
			length = (sg_s[j].length - src_offset);

			if (length > total_length)
				length = total_length;

			dst = sg_virt(&sg_d[i]) + dst_offset;
			if (!dst)
				BUG();

			if (sg_d[i].length == length) {
				i++;
				dst_offset = 0;
			} else
				dst_offset = length;

			src = sg_virt(&sg_s[j]) + src_offset;
			if (!src)
				BUG();
			j++;

			src_offset = 0;
		}

		memcpy(dst, src, length);
		
		if (!(total_length -= length))
			return;
	}

	return;
}

extern void transport_memcpy_write_contig (
	iscsi_cmd_t *cmd,       
	unsigned char *src)     
{
	u32 i = 0, length = 0, total_length = cmd->data_length;
	struct scatterlist *sg_d = (struct scatterlist *) T_TASK(cmd)->t_task_buf;
	void *dst;

	while (total_length) {
		length = sg_d[i].length;

		if (length > total_length)
			length = total_length;

		dst = sg_virt(&sg_d[i]);

		memcpy(dst, src, length);

		if (!(total_length -= length))
			return;

		src += length;
		i++;
	}

	return;
}

extern void transport_memcpy_write_sg (
	iscsi_cmd_t *cmd,
	struct scatterlist *sg_s)
{
	u32 i = 0, j = 0, dst_offset = 0, src_offset = 0;
	u32 length = 0, total_length = cmd->data_length;
	struct scatterlist *sg_d = (struct scatterlist *) T_TASK(cmd)->t_task_buf;
	void *dst, *src;

	while (total_length) {
		if ((sg_s[i].length - src_offset) < (sg_d[j].length - dst_offset)) {
			length = (sg_s[i].length - src_offset);

			if (length > total_length)
				length = total_length;

			src = sg_virt(&sg_s[i]) + src_offset;
			if (!src)
				BUG();
			i++;

			dst = sg_virt(&sg_d[j]) + dst_offset;
			if (!dst)
				BUG();

			src_offset = 0;
			dst_offset = length;
		} else {
			length = (sg_d[j].length - dst_offset);

			if (length > total_length)
				length = total_length;

			src = sg_virt(&sg_s[i]) + src_offset;
			if (!src)
				BUG();

			if (sg_s[i].length == length) {
				i++;
				src_offset = 0;
			} else
				src_offset = length;

			dst = sg_virt(&sg_d[j]) + dst_offset;
			if (!dst)
				BUG();
			j++;
			dst_offset = 0;
		}

		memcpy(dst, src, length);

		if (!(total_length -= length))
			return;
	}

	return;
}

extern iscsi_cmd_t *transport_allocate_passthrough (
	unsigned char *cdb,
	int data_direction,
	u32 cmd_flags,
	void *mem,
	u32 se_mem_num,
	u32 length,
	se_obj_lun_type_t *obj_api,
	void *type_ptr)
{
	iscsi_cmd_t *cmd;
	iscsi_transform_info_t ti;
	
	if (!(cmd = (iscsi_cmd_t *) kmalloc(sizeof(iscsi_cmd_t), GFP_KERNEL))) {
		TRACE_ERROR("Unable to allocate iscsi_cmd_t\n");
		return(NULL);
	}
	memset(cmd, 0, sizeof(iscsi_cmd_t));

	if (!(cmd->t_task = (se_transport_task_t *) kmalloc(
			sizeof(se_transport_task_t), GFP_KERNEL))) {
		TRACE_ERROR("Unable to allocate cmd->t_task\n");
		kfree(cmd);
		return(NULL);
	}
	memset(cmd->t_task, 0, sizeof(se_transport_task_t));

	init_MUTEX_LOCKED(&cmd->reject_sem);
	init_MUTEX_LOCKED(&cmd->unsolicited_data_sem);
	spin_lock_init(&cmd->datain_lock);
	spin_lock_init(&cmd->dataout_timeout_lock);
	spin_lock_init(&cmd->istate_lock);
	spin_lock_init(&cmd->error_lock);
	spin_lock_init(&cmd->r2t_lock);
	
	INIT_LIST_HEAD(&T_TASK(cmd)->t_task_list);
	init_MUTEX_LOCKED(&T_TASK(cmd)->transport_lun_fe_stop_sem);
	init_MUTEX_LOCKED(&T_TASK(cmd)->transport_lun_stop_sem);
	init_MUTEX_LOCKED(&T_TASK(cmd)->t_transport_stop_sem);
	init_MUTEX_LOCKED(&T_TASK(cmd)->t_transport_passthrough_sem);
	init_MUTEX_LOCKED(&T_TASK(cmd)->t_transport_passthrough_wsem);
	spin_lock_init(&T_TASK(cmd)->t_state_lock);
	
	/*
	 * Simulate an iSCSI LUN entry need for passing SCSI CDBs into
	 * iscsi_cmd_t.
	 */
	if (!(cmd->iscsi_lun = kmalloc(sizeof(se_lun_t), GFP_KERNEL))) {
		TRACE_ERROR("Unable to allocate cmd->iscsi_lun\n");
		goto fail;
	}
	memset(cmd->iscsi_lun, 0, sizeof(se_lun_t));

	spin_lock_init(&cmd->iscsi_lun->lun_sep_lock);
	ISCSI_LUN(cmd)->lun_type = obj_api->se_obj_type;
	ISCSI_LUN(cmd)->lun_type_ptr = type_ptr;
	ISCSI_LUN(cmd)->lun_obj_api = obj_api;

	cmd->se_orig_obj_api = obj_api;
	cmd->se_orig_obj_ptr = type_ptr;
	cmd->cmd_flags = cmd_flags;
	ISCSI_LUN(cmd)->iscsi_dev = (se_device_t *) type_ptr;

	/*
	 * Double check that the passed object is currently accepting CDBs
	 */
	if (!(cmd_flags & ICF_SE_DISABLE_ONLINE_CHECK)) {
		if (obj_api->check_online(type_ptr) != 0) {
			DEBUG_SO("obj_api->check_online() failed!\n");
			goto fail;
		}
	}

	ISCSI_LUN(cmd)->persistent_reservation_check = &iscsi_tpg_persistent_reservation_check;
	ISCSI_LUN(cmd)->persistent_reservation_release = &iscsi_tpg_persistent_reservation_release;
	ISCSI_LUN(cmd)->persistent_reservation_reserve = &iscsi_tpg_persistent_reservation_reserve;
	cmd->data_length = length;
	cmd->data_direction = data_direction;
	cmd->cmd_flags |= ICF_CMD_PASSTHROUGH;

	if (transport_generic_allocate_tasks(cmd, cdb) < 0)
		goto fail;

	memset(&ti, 0, sizeof(iscsi_transform_info_t));
	ti.ti_data_length = cmd->data_length;
	ti.ti_dev = ISCSI_LUN(cmd)->iscsi_dev;
	ti.ti_cmd = cmd;
	ti.se_obj_ptr = type_ptr;
	ti.se_obj_api = ISCSI_LUN(cmd)->lun_obj_api;

	DEBUG_SO("ti.se_obj_ptr: %p\n", ti.se_obj_ptr);
	DEBUG_SO("ti.se_obj_api: %p\n", ti.se_obj_api);
	DEBUG_SO("Plugin: %s\n", ti.se_obj_api->obj_plugin->plugin_name);

	if (!mem) {
		if (cmd->transport_allocate_resources(cmd, cmd->data_length, PAGE_SIZE) < 0)
			goto fail;
	} else {
		/*
		 * Passed *mem will contain a list_head containing preformatted
		 * se_mem_t elements...
		 */
		T_TASK(cmd)->t_mem_list = (struct list_head *)mem;
		T_TASK(cmd)->t_task_se_num = se_mem_num;
		cmd->cmd_flags |= ICF_CMD_PASSTHROUGH_NOALLOC;

#ifdef DEBUG_PASSTHROUGH
		{
		u32 total_se_length = 0;
		se_mem_t *se_mem, *se_mem_tmp;

		DEBUG_PT("Preallocated se_mem_list: %p se_mem_num: %d\n",
				mem, se_mem_num);

		list_for_each_entry_safe(se_mem, se_mem_tmp, T_TASK(cmd)->t_mem_list, se_list) {
			total_se_length += se_mem->se_len;
			DEBUG_PT("se_mem: %p se_mem->se_page: %p %d:%d\n",
				se_mem, se_mem->se_page, se_mem->se_len, se_mem->se_off);
		}

		DEBUG_PT("Total calculated total_se_length: %u\n", total_se_length);

		if (total_se_length != length) {
			TRACE_ERROR("Passed length: %u does not equal total_se_length: %u\n",
				length, total_se_length);
			BUG();
		}
		}
#endif
	}

	if (transport_get_sectors(cmd, ISCSI_LUN(cmd)->lun_obj_api, type_ptr) < 0)
		goto fail;
	
	if (transport_new_cmd_obj(cmd, &ti, ISCSI_LUN(cmd)->lun_obj_api, type_ptr, 0) < 0)
		goto fail;

	return(cmd);

fail:
	if (T_TASK(cmd))
		transport_release_tasks(cmd);
	kfree(T_TASK(cmd));
	kfree(cmd->iscsi_lun);
	kfree(cmd);
	
	return(NULL);
}

extern void transport_passthrough_release (
	iscsi_cmd_t *cmd)
{
	if (!cmd) {
		TRACE_ERROR("transport_passthrough_release passed NULL iscsi_cmd_t\n");
		return;
	}

	if (cmd->transport_wait_for_tasks)
		cmd->transport_wait_for_tasks(cmd, 0, 0);
	
	transport_generic_remove(cmd, 0, 0);

	return;
}

extern int transport_passthrough_complete (
	iscsi_cmd_t *cmd)
{
	if (cmd->se_orig_obj_api->check_shutdown(cmd->se_orig_obj_ptr) != 0)
		return(-2);

	switch (cmd->scsi_status) {
	case 0x00: /* GOOD */
		DEBUG_PT("SCSI Status: GOOD\n");
		return(0);
	case 0x02: /* CHECK_CONDITION */
		DEBUG_PT("SCSI Status: CHECK_CONDITION\n");
//#warning FIXME: Do some basic return values for Sense Data
		return(-1);
	default:
		DEBUG_PT("SCSI Status: 0x%02x\n", cmd->scsi_status);
		return(-1);
	}

	return(0);
}

/*     transport_generic_passthrough():
 *
 *
 */
extern int transport_generic_passthrough_async (iscsi_cmd_t *cmd,
						void (*callback)(iscsi_cmd_t *cmd, void *callback_arg, int complete_status), 
						void *callback_arg)
{
	int write = (cmd->data_direction == ISCSI_WRITE);
	int no_alloc = (cmd->cmd_flags & ICF_CMD_PASSTHROUGH_NOALLOC);
	int pt_done = (cmd->transport_passthrough_done != NULL);
	
	if (callback)
	{
		cmd->callback=callback;
		cmd->callback_arg = callback_arg;
	}
	
        if (transport_generic_handle_cdb(cmd) < 0)
		return(-1);

	if (write && !no_alloc) {
		down_interruptible(&T_TASK(cmd)->t_transport_passthrough_wsem);
		if (signal_pending(current))
			return(-1);

		transport_generic_process_write(cmd);
	}

	if (callback || pt_done)
		return 0;
	
	down(&T_TASK(cmd)->t_transport_passthrough_sem);   

	return(transport_passthrough_complete(cmd));
}


extern int transport_generic_passthrough(iscsi_cmd_t *cmd)
{
	return transport_generic_passthrough_async(cmd, NULL, NULL);
}

/*	transport_generic_complete_ok():
 *
 *
 */
extern void transport_generic_complete_ok (iscsi_cmd_t *cmd)
{
	int reason = 0;
	iscsi_conn_t *conn = CONN(cmd);
	
	/*
	 * Check if we need to retrieve a sense buffer from
	 * the iscsi_cmd_t in question.
	 */
	if (cmd->cmd_flags & ICF_CMD_PASSTHROUGH) {
		transport_lun_remove_cmd(cmd);
		if (!(transport_cmd_check_stop(cmd, 2, 0)))
			transport_passthrough_check_stop(cmd);
		return;
	} else if (cmd->cmd_flags & ICF_TRANSPORT_TASK_SENSE) {
		if (transport_get_sense_data(cmd) < 0)
			reason = NON_EXISTENT_LUN;

		/*
		 * Only set when an se_task_t->task_scsi_status returned
		 * a non GOOD status.
		 */
		if (cmd->scsi_status) {
			iscsi_send_check_condition_and_sense(cmd, reason, 1);
			transport_lun_remove_cmd(cmd);
			transport_cmd_check_stop(cmd, 2, 0);
			return;
		}
	}

	switch (cmd->data_direction) {
	case ISCSI_READ:
#ifdef SNMP_SUPPORT
		spin_lock(&cmd->iscsi_lun->lun_sep_lock);
		if (ISCSI_LUN(cmd)->lun_sep)
			ISCSI_LUN(cmd)->lun_sep->sep_stats.tx_data_octets += cmd->data_length;
		spin_unlock(&cmd->iscsi_lun->lun_sep_lock);
#endif
		cmd->i_state = ISTATE_SEND_DATAIN;
		iscsi_add_cmd_to_response_queue(cmd, conn, cmd->i_state);
		break;
	case ISCSI_WRITE:
#ifdef SNMP_SUPPORT
		spin_lock(&cmd->iscsi_lun->lun_sep_lock);
		if (ISCSI_LUN(cmd)->lun_sep)
			ISCSI_LUN(cmd)->lun_sep->sep_stats.rx_data_octets += cmd->data_length;
		spin_unlock(&cmd->iscsi_lun->lun_sep_lock);
#endif
	case ISCSI_NONE:
		cmd->i_state = ISTATE_SEND_STATUS;
		iscsi_add_cmd_to_response_queue(cmd, conn, cmd->i_state);
		break;
	default:
		break;
	}

	transport_lun_remove_cmd(cmd);
	transport_cmd_check_stop(cmd, 2, 0);

	return;
}

extern void transport_free_dev_tasks (iscsi_cmd_t *cmd)
{
	se_task_t *task, *task_tmp;
	unsigned long flags;

	spin_lock_irqsave(&T_TASK(cmd)->t_state_lock, flags);
	list_for_each_entry_safe(task, task_tmp, &T_TASK(cmd)->t_task_list, t_list) {
		if (atomic_read(&task->task_active))
			continue;

		if (!task->transport_req)
			continue;
		
		kfree(task->task_buf);
		
		spin_unlock_irqrestore(&T_TASK(cmd)->t_state_lock, flags);
		if (task->iscsi_dev)
			TRANSPORT(task->iscsi_dev)->free_task(task);
		else
			TRACE_ERROR("task[%u] - task->iscsi_dev is NULL\n", task->task_no);
		spin_lock_irqsave(&T_TASK(cmd)->t_state_lock, flags);
		
		list_del(&task->t_list);
		kfree(task);
	}
	spin_unlock_irqrestore(&T_TASK(cmd)->t_state_lock, flags);

	return;
}

static inline void transport_free_pages (iscsi_cmd_t *cmd)
{
	se_mem_t *se_mem, *se_mem_tmp;

	if (T_TASK(cmd)->t_task_buf) {
		kfree(T_TASK(cmd)->t_task_buf);
		T_TASK(cmd)->t_task_buf = NULL;
		return;
	}

	if (cmd->transport_free_resources) {
		cmd->transport_free_resources(cmd);
		return;
	}
	
	/*
	 * Caller will handle releasing of se_mem_t.
	 */
	if (cmd->cmd_flags & ICF_CMD_PASSTHROUGH_NOALLOC)
		return;
	
	if (!(T_TASK(cmd)->t_task_se_num))
		return;
	
	list_for_each_entry_safe(se_mem, se_mem_tmp, T_TASK(cmd)->t_mem_list, se_list) {
		__free_page(se_mem->se_page);

		list_del(&se_mem->se_list);
		kfree(se_mem);
	}

	kfree(T_TASK(cmd)->t_mem_list);
	T_TASK(cmd)->t_mem_list = NULL;
	T_TASK(cmd)->t_task_se_num = 0;
		
	return;
}

extern void transport_release_tasks (iscsi_cmd_t *cmd)
{
	CMD_ORIG_OBJ_API(cmd)->free_tasks(cmd->se_orig_obj_ptr, cmd);

//#warning FIXME v2.8: Make obj->active_cmds use SE_OBJ_API
#if 0
        /*
         * RAID breakage...
         */
        if (ISCSI_DEV(cmd))
		atomic_dec(&ISCSI_DEV(cmd)->active_cmds);
#endif

	return;
}

static inline int transport_dec_and_check (iscsi_cmd_t *cmd)
{
	unsigned long flags;

	spin_lock_irqsave(&T_TASK(cmd)->t_state_lock, flags);
	if (atomic_read(&T_TASK(cmd)->t_fe_count)) {
		if (!(atomic_dec_and_test(&T_TASK(cmd)->t_fe_count))) {
			spin_unlock_irqrestore(&T_TASK(cmd)->t_state_lock, flags);
			return(1);
		}
	}

	if (atomic_read(&T_TASK(cmd)->t_se_count)) {
		if (!(atomic_dec_and_test(&T_TASK(cmd)->t_se_count))) {
			spin_unlock_irqrestore(&T_TASK(cmd)->t_state_lock, flags);
			return(1);
		}
	}
	spin_unlock_irqrestore(&T_TASK(cmd)->t_state_lock, flags);

	return(0);
}			

extern void transport_release_fe_cmd (iscsi_cmd_t *cmd)
{
	unsigned long flags;

	if (transport_dec_and_check(cmd))
		return;
	
	spin_lock_irqsave(&T_TASK(cmd)->t_state_lock, flags);
	transport_all_task_dev_remove_state(cmd);
	spin_unlock_irqrestore(&T_TASK(cmd)->t_state_lock, flags);

	transport_release_tasks(cmd);
	transport_free_pages(cmd);

	iscsi_release_cmd_direct(cmd);

        return;
}       

/*	transport_generic_remove():
 *
 *
 */
extern int transport_generic_remove (iscsi_cmd_t *cmd, int release_to_pool, int session_reinstatement)
{
	unsigned long flags;
	
	if (!(T_TASK(cmd)))
		goto release_cmd;

	if (transport_dec_and_check(cmd)) {
		if (session_reinstatement) {
			spin_lock_irqsave(&T_TASK(cmd)->t_state_lock, flags);
			transport_all_task_dev_remove_state(cmd);
			spin_unlock_irqrestore(&T_TASK(cmd)->t_state_lock, flags);
		}
		return(1);
	}

	spin_lock_irqsave(&T_TASK(cmd)->t_state_lock, flags);
	transport_all_task_dev_remove_state(cmd);
	spin_unlock_irqrestore(&T_TASK(cmd)->t_state_lock, flags);

	transport_release_tasks(cmd);
	transport_free_pages(cmd);

release_cmd:
	if (release_to_pool && !(cmd->cmd_flags & ICF_CMD_PASSTHROUGH))
		transport_release_cmd_to_pool(cmd);
	else
		iscsi_release_cmd_direct(cmd);

	return(0);
}

/*	transport_generic_map_buffers_to_tasks():
 *
 *	Called from transport_generic_new_cmd() in Transport Processing Thread.
 */
static int transport_generic_map_buffers_to_tasks (iscsi_cmd_t *cmd)
{
	se_task_t *task = NULL;
	int ret;

	/*
	 * Deal with non [READ,WRITE]_XX CDBs here.
	 */
	if (cmd->cmd_flags & ICF_SCSI_NON_DATA_CDB)
		goto non_scsi_data;
	else if (cmd->cmd_flags & ICF_SCSI_CONTROL_NONSG_IO_CDB) {
		list_for_each_entry(task, &T_TASK(cmd)->t_task_list, t_list) {
			if (atomic_read(&task->task_sent))
				continue;
			
			if ((ret = task->transport_map_task(task, task->task_size)) < 0)
				return(ret);

			DEBUG_CMD_M("Mapping ICF_SCSI_CONTROL_NONSG_IO_CDB"
				" task_size: %u\n", task->task_size);
		}
		return(0);
	}
	
	/*
	 * Determine the scatterlist offset for each se_task_t,
	 * and segment and set pointers to storage transport buffers
	 * via task->transport_map_task().
	 */
	list_for_each_entry(task, &T_TASK(cmd)->t_task_list, t_list) {
		if (atomic_read(&task->task_sent))
			continue;
		
		if ((ret = task->transport_map_task(task, task->task_size)) < 0)
			return(ret);

		DEBUG_CMD_M("Mapping task[%d]_se_obj_ptr[%p] %s_IO task_lba:"
			" %llu task_size: %u task_sg_num: %d\n",
			task->task_no, task->se_obj_ptr,
			(cmd->cmd_flags & ICF_SCSI_CONTROL_SG_IO_CDB) ?
			"CONTROL" : "DATA", task->task_lba, task->task_size,
			task->task_sg_num);
	}	

	return(0);

non_scsi_data:
	list_for_each_entry(task, &T_TASK(cmd)->t_task_list, t_list) {
		if (atomic_read(&task->task_sent))
			continue;
		
		if ((ret = task->transport_map_task(task, task->task_size)) < 0)
			return(ret);

		DEBUG_CMD_M("Mapping ICF_SCSI_NON_DATA_CDB task_size: %u"
			" task->task_sg_num: %d\n", task->task_size,
				task->task_sg_num);
	}

	return(0);
}

/*	transport_generic_do_transform():
 *
 *
 */
extern int transport_generic_do_transform (iscsi_cmd_t *cmd, iscsi_transform_info_t *ti)
{
	if (cmd->transport_cdb_transform(cmd, ti) < 0)
		return(-1);

	return(0);
}

extern int transport_get_sectors (
	iscsi_cmd_t *cmd,
	se_obj_lun_type_t *obj_api,
	void *obj_ptr)
{
	if (!(cmd->cmd_flags & ICF_SCSI_DATA_SG_IO_CDB))
		return(0);

	if (!(T_TASK(cmd)->t_task_sectors =
	     (cmd->data_length / obj_api->blocksize(obj_ptr))))
		T_TASK(cmd)->t_task_sectors = 1;

	if (obj_api->get_device_type(obj_ptr) != TYPE_DISK)
		return(0);

	if ((T_TASK(cmd)->t_task_lba + T_TASK(cmd)->t_task_sectors) >
	     obj_api->total_sectors(obj_ptr, 1, (cmd->cmd_flags & ICF_SE_ALLOW_EOO))) {
		TRACE_ERROR("LBA: %llu Sectors: %u exceeds"
			" obj_api->total_sectors(): %llu\n", T_TASK(cmd)->t_task_lba,
			T_TASK(cmd)->t_task_sectors, obj_api->total_sectors(obj_ptr, 1,
				(cmd->cmd_flags & ICF_SE_ALLOW_EOO)));
		cmd->cmd_flags |= ICF_SCSI_CDB_EXCEPTION;
		cmd->scsi_sense_reason = SECTOR_COUNT_TOO_MANY;
		return(PYX_TRANSPORT_REQ_TOO_MANY_SECTORS);
	}	

	return(0);
}

extern int transport_new_cmd_obj (
	iscsi_cmd_t *cmd,
	iscsi_transform_info_t *ti,
	se_obj_lun_type_t *obj_api,
	void *obj_ptr,
	int post_execute)
{
	u32 task_cdbs = 0, task_offset = 0;
	se_mem_t *se_mem_out = NULL;

	if (!(cmd->cmd_flags & ICF_SCSI_DATA_SG_IO_CDB)) {
		task_cdbs++;
		T_TASK(cmd)->t_task_cdbs++;
	} else {
		ti->ti_set_counts = 1;

		if (!(task_cdbs = obj_api->get_cdb_count(obj_ptr, ti,
				T_TASK(cmd)->t_task_lba, T_TASK(cmd)->t_task_sectors,
				NULL, &se_mem_out, &task_offset))) {
			cmd->cmd_flags |= ICF_SCSI_CDB_EXCEPTION;
			cmd->scsi_sense_reason = LOGICAL_UNIT_COMMUNICATION_FAILURE;
			return(PYX_TRANSPORT_LOGICAL_UNIT_COMMUNICATION_FAILURE);
		}
		T_TASK(cmd)->t_task_cdbs += task_cdbs;
		
		cmd->transport_cdb_transform = &transport_process_data_sg_transform;
#if 0
		PYXPRINT("[%s]: api: %p ptr: %p data_length: %u, LBA: %llu t_task_sectors: %u,"
				" t_task_cdbs: %u\n", obj_api->obj_plugin->plugin_name,
				obj_api, obj_ptr, cmd->data_length, T_TASK(cmd)->t_task_lba,
				T_TASK(cmd)->t_task_sectors, T_TASK(cmd)->t_task_cdbs);
#endif
	}

	cmd->transport_do_transform = &transport_generic_do_transform;
	if (!post_execute) {
		atomic_set(&T_TASK(cmd)->t_task_cdbs_left, task_cdbs);
		atomic_set(&T_TASK(cmd)->t_task_cdbs_ex_left, task_cdbs);
		atomic_set(&T_TASK(cmd)->t_task_cdbs_timeout_left, task_cdbs);
	} else {
		atomic_add(task_cdbs, &T_TASK(cmd)->t_task_cdbs_left);
		atomic_add(task_cdbs, &T_TASK(cmd)->t_task_cdbs_ex_left);
		atomic_add(task_cdbs, &T_TASK(cmd)->t_task_cdbs_timeout_left);
	}

	return(0);
}

extern unsigned char *transport_get_vaddr (se_mem_t *se_mem)
{
	return(page_address(se_mem->se_page) + se_mem->se_off);
}

extern struct list_head *transport_init_se_mem_list (void)
{
	struct list_head *se_mem_list;

	if (!(se_mem_list = kmalloc(sizeof(struct list_head), GFP_KERNEL))) {
		TRACE_ERROR("Unable to allocate memory for se_mem_list\n");
		return(NULL);
	}
	memset(se_mem_list, 0, sizeof(struct list_head));

	INIT_LIST_HEAD(se_mem_list);
	
	return(se_mem_list);
}

extern void transport_free_se_mem_list (struct list_head *se_mem_list)
{
	se_mem_t *se_mem, *se_mem_tmp;

	if (!se_mem_list)
		return;

	list_for_each_entry_safe(se_mem, se_mem_tmp, se_mem_list, se_list) {
		list_del(&se_mem->se_list);
		kfree(se_mem);
	}
	kfree(se_mem_list);

	return;
}

extern int transport_generic_get_mem (iscsi_cmd_t *cmd, u32 length, u32 dma_size)
{
	unsigned char *buf;
	se_mem_t *se_mem;

	if (!(T_TASK(cmd)->t_mem_list = transport_init_se_mem_list()))
		return(-1);
	
	while (length) {
		if (!(se_mem = kmalloc(sizeof(se_mem_t), GFP_KERNEL))) {
			TRACE_ERROR("Unable to allocate se_mem_t\n");
			goto out;
		}
		memset(se_mem, 0, sizeof(se_mem_t));

		INIT_LIST_HEAD(&se_mem->se_list);
		se_mem->se_len = (length > dma_size) ? dma_size : length;

//#warning FIXME v2.8: Allocate contigous pages for se_mem_t elements
		if (!(se_mem->se_page = (struct page *) alloc_pages(GFP_KERNEL, 0))) {
			TRACE_ERROR("alloc_pages() failed\n");
			goto out;
		}

		if (!(buf = kmap_atomic(se_mem->se_page, KM_IRQ0))) {
			TRACE_ERROR("kmap_atomic() failed\n");
			goto out;
		}
		memset(buf, 0, se_mem->se_len);
		kunmap_atomic(buf, KM_IRQ0);

		list_add_tail(&se_mem->se_list, T_TASK(cmd)->t_mem_list);
		T_TASK(cmd)->t_task_se_num++;

		DEBUG_MEM("Allocated se_mem_t page: %p, Length: %u, Offset: %u\n",
			se_mem->se_page, se_mem->se_len, se_mem->se_off);
		
		length -= se_mem->se_len;
	}

	DEBUG_MEM("Allocated %u total se_mem_t elements\n", T_TASK(cmd)->t_task_se_num);

	return(0);
out:
	return(-1);
}

extern u32 transport_calc_sg_num (
	se_task_t *task,
	se_mem_t *in_se_mem,
	u32 task_offset)
{
	se_mem_t *se_mem = in_se_mem;
	u32 sg_length, sg_offset, task_size = task->task_size;
	u32 saved_task_offset = 0;

	while (task_size) {
		DEBUG_SC("se_mem->se_page: %p se_mem->se_len: %u se_mem->se_off: %u"
			" task_offset: %u\n", se_mem->se_page, se_mem->se_len,
				se_mem->se_off, task_offset);
		
		if (task_offset == 0) {
			if (task_size > se_mem->se_len)
				sg_length = se_mem->se_len;
			else
				sg_length = task_size;

			DEBUG_SC("sg_length: %u task_size: %u\n", sg_length, task_size);

			if (saved_task_offset)
				task_offset = saved_task_offset;
		} else {
			sg_offset = task_offset;

			if ((se_mem->se_len - task_offset) > task_size)
				sg_length = task_size;
			else 
				sg_length = (se_mem->se_len - task_offset);

			DEBUG_SC("sg_length: %u task_size: %u\n", sg_length, task_size);

			saved_task_offset = task_offset;
			task_offset = 0;
		}
		task_size -= sg_length;

		DEBUG_SC("task[%u] - Reducing task_size to %u\n", task->task_no,
				task_size);

		task->task_sg_num++;

		list_for_each_entry_continue(se_mem, task->iscsi_cmd->t_task->t_mem_list, se_list)
			break;

		if (!se_mem)
			break;
	}

	if (!(task->task_buf = kmalloc(task->task_sg_num * sizeof(struct scatterlist), GFP_KERNEL))) {
		TRACE_ERROR("Unable to allocate memory for task->task_buf\n");
		return(0);	
	}
	memset(task->task_buf, 0, task->task_sg_num * sizeof(struct scatterlist));

	sg_init_table((struct scatterlist *)&task->task_buf[0], task->task_sg_num);

	DEBUG_SC("Successfully allocated task->task_sg_num: %u\n", task->task_sg_num);
	
	return(task->task_sg_num);
}

static inline int transport_set_task_sectors_disk (
	se_task_t *task,
	se_obj_lun_type_t *obj_api,
	void *obj_ptr,
	se_fp_obj_t *fp,
	unsigned long long lba,
	u32 sectors,
	int *max_sectors_set)
{
	if ((lba + sectors) > obj_api->end_lba(obj_ptr, 1, fp)) {
		task->task_sectors = ((obj_api->end_lba(obj_ptr, 1, fp) - lba) + 1);
		
		if (task->task_sectors > obj_api->max_sectors(obj_ptr)) {
			task->task_sectors = obj_api->max_sectors(obj_ptr);
			*max_sectors_set = 1;
		}
	} else {
		if (sectors > obj_api->max_sectors(obj_ptr)) {
			task->task_sectors = obj_api->max_sectors(obj_ptr);
			*max_sectors_set = 1;
		} else
			task->task_sectors = sectors;
	}

	return(0);
}

static inline int transport_set_task_sectors_non_disk (
	se_task_t *task,
	se_obj_lun_type_t *obj_api,
	void *obj_ptr,
	se_fp_obj_t *fp,
	unsigned long long lba,
	u32 sectors,
	int *max_sectors_set)
{
	if (sectors > obj_api->max_sectors(obj_ptr)) {
		task->task_sectors = obj_api->max_sectors(obj_ptr);
		*max_sectors_set = 1;
	} else  
		task->task_sectors = sectors;

	return(0);
}

static inline int transport_set_task_sectors (
	se_task_t *task,
	se_obj_lun_type_t *obj_api,
	void *obj_ptr,
	se_fp_obj_t *fp,
	unsigned long long lba,
	u32 sectors,
	int *max_sectors_set)
{
	return((obj_api->get_device_type(obj_ptr) == TYPE_DISK)	?
		transport_set_task_sectors_disk(task, obj_api, obj_ptr,
				fp, lba, sectors, max_sectors_set) :
		transport_set_task_sectors_non_disk(task, obj_api, obj_ptr,
				fp, lba, sectors, max_sectors_set));
}

extern int transport_map_sg_to_mem (
	se_task_t *task,
	struct list_head *se_mem_list,
	void *in_mem,
	se_mem_t *in_se_mem,
	se_mem_t **out_se_mem,
	u32 *se_mem_cnt,
	u32 *task_offset)
{
	se_mem_t *se_mem;
	struct scatterlist *sg_s;
	u32 j = 0, saved_task_offset = 0, task_size = task->task_size;

	if (!in_mem) { 
		TRACE_ERROR("No source scatterlist\n");
		return(-1);
	}
	sg_s = (struct scatterlist *)in_mem;

	while (task_size) {
		if (!(se_mem = kmalloc(sizeof(se_mem_t), GFP_KERNEL))) {
			TRACE_ERROR("Unable to allocate se_mem_t\n");
			return(-1);
		}
		memset(se_mem, 0, sizeof(se_mem_t));

		INIT_LIST_HEAD(&se_mem->se_list);

		if (*task_offset == 0) {
			se_mem->se_page = sg_page(&sg_s[j]);
			se_mem->se_off = sg_s[j].offset;

			if (task_size >= sg_s[j].length)
				se_mem->se_len =  sg_s[j++].length;
			else {
				se_mem->se_len = task_size;

				if (!(task_size -= se_mem->se_len)) {
					*task_offset = (se_mem->se_len + saved_task_offset);
					goto next;
				}
			}

			if (saved_task_offset)
				*task_offset = saved_task_offset;
		} else {
			se_mem->se_page = sg_page(&sg_s[j]);
			se_mem->se_off = (*task_offset + sg_s[j].offset);

			if ((sg_s[j].length - *task_offset) > task_size) {
				 se_mem->se_len = task_size;

				 if (!(task_size -= se_mem->se_len)) {
					*task_offset += se_mem->se_len;
					goto next;
				}
			} else
				se_mem->se_len = (sg_s[j++].length - *task_offset);

			saved_task_offset = *task_offset;
			*task_offset = 0;
		}
		task_size -= se_mem->se_len;
next:
		list_add_tail(&se_mem->se_list, se_mem_list);
		(*se_mem_cnt)++;
	}

	DEBUG_MEM("task[%u] - Mapped %u struct scatterlist segments to %u se_mem_t\n",
			task->task_no, j, *se_mem_cnt);

	return(0);
}

extern int transport_map_mem_to_mem (
	se_task_t *task,
	struct list_head *se_mem_list,
	void *in_mem,
	se_mem_t *in_se_mem, 
	se_mem_t **out_se_mem,
	u32 *se_mem_cnt,
	u32 *task_offset)
{
	se_mem_t *se_mem = in_se_mem, *se_mem_new;
	u32 saved_task_offset = 0, task_size = task->task_size;

	if (!se_mem) { 
		TRACE_ERROR("Invalid se_mem_t pointer\n");
		return(-1);
	}
	
	while (task_size) { 
		if (!(se_mem_new = kmalloc(sizeof(se_mem_t), GFP_KERNEL))) {
			TRACE_ERROR("Unable to allocate se_mem_t\n");
			return(-1);
		}
		memset(se_mem_new, 0, sizeof(se_mem_t));

		INIT_LIST_HEAD(&se_mem_new->se_list);
		
		if (*task_offset == 0) {
			se_mem_new->se_page = se_mem->se_page;
			se_mem_new->se_off = se_mem->se_off;
			
			if (task_size >= se_mem->se_len) {
				se_mem_new->se_len = se_mem->se_len;

				if (!(se_mem = list_entry(se_mem->se_list.next,
							se_mem_t, se_list))) {
					TRACE_ERROR("Unable to locate next se_mem_t!\n");
					return(-1);
				}
			} else {
				se_mem_new->se_len = task_size;

				if (!(task_size -= se_mem_new->se_len)) {
					*task_offset = (se_mem_new->se_len + saved_task_offset);
					goto next;
				}
			}
	
			if (saved_task_offset)
				*task_offset = saved_task_offset;
		} else {
			se_mem_new->se_page = se_mem->se_page;
			se_mem_new->se_off = (*task_offset + se_mem->se_off);
			
			if ((se_mem->se_len - *task_offset) > task_size) {
				se_mem_new->se_len = task_size;

				if (!(task_size -= se_mem_new->se_len)) {
					*task_offset += se_mem_new->se_len;
					goto next;
				}
			} else {
				se_mem_new->se_len = (se_mem->se_len - *task_offset);

				if (!(se_mem = list_entry(se_mem->se_list.next,
							se_mem_t, se_list))) {
					TRACE_ERROR("Unable to locate next se_mem_t!\n");
					return(-1);
				}
			}

			saved_task_offset = *task_offset;
			*task_offset = 0;
		}
		task_size -= se_mem_new->se_len;
next:
		list_add_tail(&se_mem_new->se_list, se_mem_list);
		(*se_mem_cnt)++;

		DEBUG_MEM2("task[%u] - se_mem_cnt: %u se_page: %p se_off: %u se_len: %u\n", task->task_no,
			*se_mem_cnt, se_mem_new->se_page, se_mem_new->se_off, se_mem->se_len);
		DEBUG_MEM2("task[%u] - Reducing task_size to %u\n", task->task_no, task_size);
	}
	*out_se_mem = se_mem;

	return(0);
}

/*	transport_map_mem_to_sg():
 *
 *
 */
extern int transport_map_mem_to_sg (
	se_task_t *task,
	struct list_head *se_mem_list,
	void *in_mem,
	se_mem_t *in_se_mem,
	se_mem_t **out_se_mem,
	u32 *se_mem_cnt,
	u32 *task_offset)
{
	se_mem_t *se_mem = in_se_mem;
	struct scatterlist *sg = (struct scatterlist *)in_mem;
	u32 saved_task_offset = 0, sg_no = 0;
	u32 task_size = task->task_size;

	if (!sg) {
		TRACE_ERROR("Unable to locate valid struct scatterlist pointer\n");
		return(-1);
	}

	while (task_size) {
		if (*task_offset == 0) {
			sg_assign_page(&sg[sg_no], se_mem->se_page);
			sg[sg_no].offset = se_mem->se_off;

			if (task_size >= se_mem->se_len) {
				sg[sg_no].length = se_mem->se_len;

				if (!(se_mem = list_entry(se_mem->se_list.next,
							se_mem_t, se_list))) {
					TRACE_ERROR("Unable to locate next se_mem_t!\n");
					return(-1);
				}
				(*se_mem_cnt)++;
			} else {
				sg[sg_no].length = task_size;
				/*
				 * Determine if we need to calculate an offset into the
				 * se_mem_t on the next go around..
				 */
				if (!(task_size -= sg[sg_no].length)) {
					*task_offset = (sg[sg_no].length + saved_task_offset);
					goto next;
				}
			}
				
			if (saved_task_offset)
				*task_offset = saved_task_offset;
		} else {
			sg_assign_page(&sg[sg_no], se_mem->se_page);
			sg[sg_no].offset = (*task_offset + se_mem->se_off);

			if ((se_mem->se_len - *task_offset) > task_size) {
				sg[sg_no].length = task_size;
				/*
				 * Determine if we need to calculate an offset into the
				 * se_mem_t on the next go around..
				 */
				if (!(task_size -= sg[sg_no].length)) {
					*task_offset += sg[sg_no].length;
					goto next;
				}
			} else {
				sg[sg_no].length = (se_mem->se_len - *task_offset);
				
				if (!(se_mem = list_entry(se_mem->se_list.next,
						se_mem_t, se_list))) {
					TRACE_ERROR("Unable to locate next se_mem_t!\n");
					return(-1);
				}
				(*se_mem_cnt)++;	
			}

			saved_task_offset = *task_offset;
			*task_offset = 0;
		}
		task_size -= sg[sg_no].length;
next:
		DEBUG_MEM("task[%u] - sg[%u] %p %u %u - Reducing task_size"
			" to %u\n", task->task_no, sg_no,
			sg_page(&sg[sg_no]), sg[sg_no].length,
			sg[sg_no].offset, task_size);

		sg_no++;
	}
	*out_se_mem = se_mem;
	task->task_sg_num = sg_no;

	DEBUG_MEM("task[%u] - Mapped %u se_mem_t segments to total %u SGs,"
		" saved task_offset: %u\n", task->task_no, *se_mem_cnt,
			sg_no, *task_offset);

	return(0);
}

extern u32 transport_generic_get_cdb_count (
	iscsi_cmd_t *cmd,
	iscsi_transform_info_t *ti,
	se_obj_lun_type_t *head_obj_api,
	void *head_obj_ptr,
	unsigned long long starting_lba,
	u32 sectors,
	se_mem_t *se_mem_in,
	se_mem_t **se_mem_out,
	u32 *task_offset_in)
{
	unsigned char *cdb = NULL;
	void *obj_ptr, *next_obj_ptr = NULL;
	se_task_t *task;
	se_fp_obj_t *fp = NULL;
	se_mem_t *se_mem, *se_mem_lout = NULL;
	se_obj_lun_type_t *obj_api;
	int max_sectors_set = 0, ret;
	u32 se_mem_cnt = 0, task_cdbs = 0;
	unsigned long long lba;

	if (!se_mem_in) {
		list_for_each_entry(se_mem_in, T_TASK(cmd)->t_mem_list, se_list)
			break;

		if (!se_mem_in) {
			TRACE_ERROR("se_mem_in is NULL!\n");
			return(0);
		}
	}
	se_mem = se_mem_in;
	
	/*
	 * Locate the start volume segment in which the received LBA will be
	 * executed upon.
	 */
	head_obj_api->obtain_obj_lock(head_obj_ptr);
	if (head_obj_api->obj_start(head_obj_ptr, ti, starting_lba) < 0) {
		head_obj_api->release_obj_lock(head_obj_ptr);
		return(0);
	}
	
	/*
	 * Only pass a valid *fp into obj_api->end_lba() when the iscsi_cmd_t is not
	 * accessing the reserved feature metadata area at the end of the object.
	 */
	if (!(cmd->cmd_flags & ICF_SE_ALLOW_EOO))
		fp = head_obj_api->get_feature_obj(head_obj_ptr);
	
	/*
	 * Locate starting object from original starting_lba.
	 */
	lba = ti->ti_lba;
	obj_api = ti->ti_obj_api;
	obj_ptr = ti->ti_obj_ptr;
	DEBUG_VOL("Starting Physical LBA: %llu for head_obj_api -> %p\n", lba, head_obj_api);
	
	while (sectors) {
		if (!obj_api) {
			head_obj_api->release_obj_lock(head_obj_ptr);
			TRACE_ERROR("obj_api is NULL! - LBA: %llu -> Sectors: %u\n", lba, sectors);
			return(0);
		}

		DEBUG_VOL("ITT[0x%08x]: LBA: %llu SectorsLeft: %u EOBJ: %llu\n",
			cmd->init_task_tag, lba, sectors, obj_api->end_lba(obj_ptr, 1, fp));

		head_obj_api->release_obj_lock(head_obj_ptr);

		if (!(task = cmd->transport_get_task(ti, cmd, obj_ptr, obj_api)))
			goto out;

		transport_set_task_sectors(task, obj_api, obj_ptr, fp, lba,
				sectors, &max_sectors_set);

		task->task_lba = lba;
		lba += task->task_sectors;
		sectors -= task->task_sectors;
		task->task_size = (task->task_sectors * obj_api->blocksize(obj_ptr));
		task->transport_map_task = obj_api->get_map_SG(obj_ptr, cmd->data_direction);

		if ((cdb = obj_api->get_cdb(obj_ptr, task))) {
			memcpy(cdb, T_TASK(cmd)->t_task_cdb, SCSI_CDB_SIZE);
			cmd->transport_split_cdb(task->task_lba, &task->task_sectors, cdb);
		}

		/*
		 * Perform the SE OBJ plugin and/or Transport plugin specific mapping
		 * for T_TASK(cmd)->t_mem_list.
		 */
		if ((ret = obj_api->do_se_mem_map(obj_ptr, task, T_TASK(cmd)->t_mem_list,
				NULL, se_mem, &se_mem_lout, &se_mem_cnt, task_offset_in)) < 0)
			goto out;

		head_obj_api->obtain_obj_lock(head_obj_ptr);
		
		se_mem = se_mem_lout;
		*se_mem_out = se_mem_lout;
		task_cdbs++;
		
		DEBUG_VOL("Incremented task_cdbs: %u task->task_sg_num: %u\n",
				task_cdbs, task->task_sg_num);

		if (max_sectors_set) {
			max_sectors_set = 0;
			continue;
		}

		if (!sectors)
			break;

		if ((obj_api = obj_api->get_next_obj_api(obj_ptr, &next_obj_ptr))) {
			obj_ptr = next_obj_ptr;
			lba = obj_api->get_next_lba(obj_ptr, lba);
		}
	}
	head_obj_api->release_obj_lock(head_obj_ptr);

	if (ti->ti_set_counts) {
		atomic_inc(&T_TASK(cmd)->t_fe_count);
		atomic_inc(&T_TASK(cmd)->t_se_count);
	}
	
	DEBUG_VOL("ITT[0x%08x]: total cdbs: %u \n", cmd->init_task_tag, task_cdbs);

	return(task_cdbs);
out:
	return(0);
}

static int transport_process_feature (iscsi_cmd_t *cmd)
{
	se_obj_lun_type_t *obj_api = ISCSI_LUN(cmd)->lun_obj_api;
	
	if (!((T_TASK(cmd)->t_fp = obj_api->get_feature_obj(ISCSI_LUN(cmd)->lun_type_ptr))))
		return(0);
	
	if (cmd->cmd_flags & ICF_SCSI_DATA_SG_IO_CDB) {
		cmd->transport_feature_io = T_TASK(cmd)->t_fp->fp_api->feature_io;

		/*
		 * Determine if additional values need to be set in T_TASK(cmd).
		 */
		if (T_TASK(cmd)->t_fp->fp_api->feature_io_check_lun)
			T_TASK(cmd)->t_fp->fp_api->feature_io_check_lun(T_TASK(cmd)->t_fp, cmd);

		return(1);
	}

	return(0);
}
	
/*	 transport_generic_new_cmd(): Called from transport_processing_thread()
 *
 *	 Allocate storage transport resources from a set of values predefined
 *	 by transport_generic_cmd_sequencer() from the iSCSI Target RX process.
 *	 Any non zero return here is treated as an "out of resource' iSCSI Target
 *	 failure.
 */
extern int transport_generic_new_cmd (iscsi_cmd_t *cmd)
{
	int ret = 0;
	iscsi_transform_info_t ti;
#if 0 /* Cache stuff */
	int cache_hit = 0;
	iscsi_cache_entry_t *ce;
	iscsi_cache_check_entry_t cce;

	/*
	 * Non-DATA CDBs never make it into the cache.
	 */
	if (cmd->data_direction == ISCSI_NONE)
		goto allocate_resources;
	
	/*
	 * See if the LBA/SECTORS combination from the received CDB is
	 * already in the cache.
	 */
	memset(&cce, 0, sizeof(iscsi_cache_check_entry_t));
	cce.lba = 0;
	cce.sectors = 0;
	
	if ((ce = iscsi_cache_check_for_entry(&cce, cmd))) {
		/*
		 * Got a hit!  Set the required T_TASK(cmd)-> values
		 * that cmd->transport_allocate_resources() would normally
		 * set during a cache miss from the returned iscsi_cache_entry_t.
		 */
		cache_hit = 1;
		T_TASK(cmd)->t_task_buf = ce->ce_task_buf;
		T_TASK(cmd)->t_task_se_num = ce->ce_task_sg_num;
		goto allocate_iovecs;
	}
#endif
#if 0 /* Readahead stuff */
	/*
	 * Check if we want to do Readahead here.
	 */
	if ((cmd->data_direction == ISCSI_READ) &&
	    (ISCSI_DEV(cmd)->dev_flags & DF_READAHEAD_ACTIVE))
		iscsi_ra_check(cmd);
#endif	
	/*
	 * Generate se_task_t(s) and/or their payloads for this CDB.
	 */
	memset((void *)&ti, 0, sizeof(iscsi_transform_info_t));
	ti.ti_cmd = cmd;
        ti.se_obj_ptr = ISCSI_LUN(cmd)->lun_type_ptr;
        ti.se_obj_api = ISCSI_LUN(cmd)->lun_obj_api;
	
	if (!(cmd->cmd_flags & ICF_CMD_PASSTHROUGH)) {
//#warning FIXME v2.8: Get rid of PAGE_SIZE usage
		if ((ret = cmd->transport_allocate_resources(cmd, cmd->data_length, PAGE_SIZE)) < 0)
			goto failure;
		
		if ((ret = transport_get_sectors(cmd, ISCSI_LUN(cmd)->lun_obj_api,
					ISCSI_LUN(cmd)->lun_type_ptr)) < 0)
			goto failure;

		if (transport_process_feature(cmd) > 0) {
			if ((ret = cmd->transport_allocate_iovecs(cmd)) < 0) {
				ret = PYX_TRANSPORT_OUT_OF_MEMORY_RESOURCES;
				goto failure;
			}
			goto process;
		}

		if ((ret = transport_new_cmd_obj(cmd, &ti, ISCSI_LUN(cmd)->lun_obj_api,
					ISCSI_LUN(cmd)->lun_type_ptr, 0)) < 0)
			goto failure;

		/*
		 * Allocate iovecs for frontend mappings.  This currently assumes
		 * traditional iSCSI going to sockets.
		 *
		 * FIXME: This should be specific to frontend protocol/hardware.
		 */
		if ((ret = cmd->transport_allocate_iovecs(cmd)) < 0) {
			ret = PYX_TRANSPORT_OUT_OF_MEMORY_RESOURCES;
			goto failure;
		}
	}

	/*
	 * This is dependent upon the storage processing algorithm.
	 */
	if (cmd->transport_do_transform(cmd, &ti) < 0) {
		ret = PYX_TRANSPORT_OUT_OF_MEMORY_RESOURCES;
		goto failure;
	}

	/*
	 * Set the correct (usually DMAable) buffer pointers from the master
	 * buffer list in iscsi_cmd_t to the transport task's native
	 * buffers format.
	 */
	if ((ret = cmd->transport_map_buffers_to_tasks(cmd)) < 0)
		goto failure;

	/*
	 * For WRITEs, let the iSCSI Target RX Thread know its buffer is ready..
	 * This WRITE iscsi_cmd_t (and all of its associated se_task_t's)
	 * will be added to the se_device_t execution queue after its WRITE
	 * data has arrived. (ie: It gets handled by the transport processing
	 * thread a second time)
	 */
process:
	if (cmd->data_direction == ISCSI_WRITE) {
		transport_add_tasks_to_state_queue(cmd);
		return(transport_generic_write_pending(cmd));
	}

	/*
	 * Everything else but a WRITE, add the iscsi_cmd_t's se_task_t's
	 * to the execution queue.
	 */
	transport_execute_tasks(cmd);
	return(0);

failure:
	return(ret);
}

/*	transport_generic_process_write():
 *
 *
 */
extern void transport_generic_process_write (iscsi_cmd_t *cmd)
{
#if 0
	/*
	 * Copy SCSI Presented DTL sector(s) from received buffers allocated to
	 * original EDTL 
	 */
	if (cmd->cmd_flags & ICF_UNDERFLOW_BIT) {
		if (!T_TASK(cmd)->t_task_se_num) {
			unsigned char *dst, *buf = (unsigned char *)T_TASK(cmd)->t_task_buf;	

			if (!(dst = kmalloc(cmd->cmd_spdtl), GFP_KERNEL)) {
				TRACE_ERROR("Unable to allocate memory for WRITE underflow\n");
				transport_generic_request_failure(cmd, NULL, PYX_TRANSPORT_REQ_TOO_MANY_SECTORS, 1);
				return;
			}
			memcpy(dst, buf, cmd->cmd_spdtl);

			kfree(T_TASK(cmd)->t_task_buf);
			T_TASK(cmd)->t_task_buf = dst;
		} else {
			struct scatterlist *sg = (struct scatterlist *sg)T_TASK(cmd)->t_task_buf;	
			struct scatterlist *orig_sg;

			if (!(orig_sg = kmalloc(sizeof(struct scatterlist) * T_TASK(cmd)->t_task_se_num, GFP_KERNEL))) {
				TRACE_ERROR("Unable to allocate memory for WRITE underflow\n");
				transport_generic_request_failure(cmd, NULL, PYX_TRANSPORT_REQ_TOO_MANY_SECTORS, 1);
				return;
			}
			memset(orig_sg, 0, sizeof(struct scatterlist) * T_TASK(cmd)->t_task_se_num);

			memcpy(orig_sg, T_TASK(cmd)->t_task_buf, sizeof(struct scatterlist) * T_TASK(cmd)->t_task_se_num);

			cmd->data_length = cmd->cmd_spdtl;
			
			/*
			 * FIXME, clear out original se_task_t and state information.
			 */
			
			
			if (transport_generic_new_cmd(cmd) < 0) {
				transport_generic_request_failure(cmd, NULL, PYX_TRANSPORT_REQ_TOO_MANY_SECTORS, 1);
				kfree(orig_sg);
				return;
			}
			
			transport_memcpy_write_sg(cmd, orig_sg);
		}
	}
#endif
	
	transport_execute_tasks(cmd);
	return;
}					

/*	transport_generic_write_pending():
 *
 *
 */
static int transport_generic_write_pending (iscsi_cmd_t *cmd)
{
	unsigned long flags;

	if (cmd->cmd_flags & ICF_CMD_PASSTHROUGH) {
		if (!(cmd->cmd_flags & ICF_CMD_PASSTHROUGH_NOALLOC)) {
			up(&T_TASK(cmd)->t_transport_passthrough_wsem);
			transport_cmd_check_stop(cmd, 1, 0);
			return(PYX_TRANSPORT_WRITE_PENDING);
		}

		transport_generic_process_write(cmd);
		transport_cmd_check_stop(cmd, 1, 0);
		return(PYX_TRANSPORT_WRITE_PENDING);
	}

	spin_lock_irqsave(&T_TASK(cmd)->t_state_lock, flags);
	cmd->t_state = TRANSPORT_WRITE_PENDING;
	spin_unlock_irqrestore(&T_TASK(cmd)->t_state_lock, flags);

	if (cmd->immediate_data || cmd->unsolicited_data)
		up(&cmd->unsolicited_data_sem);
	else {
		if (iscsi_build_r2ts_for_cmd(cmd, CONN(cmd), 1) < 0)
			return(PYX_TRANSPORT_OUT_OF_MEMORY_RESOURCES);
	}

	transport_cmd_check_stop(cmd, 1, 0);
	return(PYX_TRANSPORT_WRITE_PENDING);
}

/*	transport_release_cmd_to_pool():
 *
 *
 */
static void transport_release_cmd_to_pool (iscsi_cmd_t *cmd)
{
	if (!CONN(cmd) && !cmd->sess) {
#if 0
		TRACE_ERROR("Releasing cmd: %p ITT: 0x%08x i_state: 0x%02x, deferred_i_state: 0x%02x directly\n",
				cmd, cmd->init_task_tag, cmd->i_state, cmd->deferred_i_state);
#endif
		iscsi_release_cmd_direct(cmd);
	} else {
		iscsi_session_t *sess = (CONN(cmd)) ? CONN(cmd)->sess : cmd->sess;
		iscsi_release_cmd_to_pool(cmd, sess);
	}

	return;
}

/*	transport_generic_free_cmd():
 *
 *	Called from processing frontend to release storage engine resources
 */
extern void transport_generic_free_cmd (
	iscsi_cmd_t *cmd,
	int wait_for_tasks,
	int release_to_pool,
	int session_reinstatement)
{
	if (!(cmd->cmd_flags & ICF_SE_LUN_CMD) || !T_TASK(cmd))
		transport_release_cmd_to_pool(cmd);
	else {
		iscsi_session_t *sess = (CONN(cmd)) ? CONN(cmd)->sess : cmd->sess;

		if (!sess) {
			TRACE_ERROR("Unable to locate iscsi_session_t\n");
			BUG();
		}
		iscsi_dec_nacl_count(SESS_NODE_ACL(sess), cmd);

		if (ISCSI_LUN(cmd)) {
#if 0
			TRACE_ERROR("cmd: %p ITT: 0x%08x contains ISCSI_LUN(cmd)!!!\n",
					cmd, cmd->init_task_tag);
#endif
			transport_lun_remove_cmd(cmd);
		}
		
		if (wait_for_tasks && cmd->transport_wait_for_tasks) 
			cmd->transport_wait_for_tasks(cmd, 0, 0);

		transport_generic_remove(cmd, release_to_pool, session_reinstatement);
	}
		
	return;
}

static void transport_nop_wait_for_tasks (iscsi_cmd_t *cmd, int remove_cmd, int session_reinstatement)
{
	return;
}

/*	transport_lun_wait_for_tasks():
 *
 *	Called from IOCTL context to stop the passed iscsi_cmd_t to allow
 *	an se_lun_t to be successfully shutdown.
 */
extern int transport_lun_wait_for_tasks (iscsi_cmd_t *cmd, se_lun_t *lun)
{
	unsigned long flags;
	
	/*
	 * If the frontend has already requested this iscsi_cmd_t to
	 * be stopped, we can safely ignore this iscsi_cmd_t.
	 */
	spin_lock_irqsave(&T_TASK(cmd)->t_state_lock, flags);
	if (atomic_read(&T_TASK(cmd)->t_transport_stop)) {
		atomic_set(&T_TASK(cmd)->transport_lun_stop, 0);
		DEBUG_TRANSPORT_S("IOCTL: ITT[0x%08x] - t_transport_stop == TRUE,"
				" skipping\n", cmd->init_task_tag);
		spin_unlock_irqrestore(&T_TASK(cmd)->t_state_lock, flags);
		return(-1);
	}
	spin_unlock_irqrestore(&T_TASK(cmd)->t_state_lock, flags);

	CMD_ORIG_OBJ_API(cmd)->notify_obj(cmd->se_orig_obj_ptr);

	DEBUG_TRANSPORT_S("IOCTL: ITT[0x%08x] - stopping cmd....\n", cmd->init_task_tag);
	down(&T_TASK(cmd)->transport_lun_stop_sem);
	DEBUG_TRANSPORT_S("IOCTL: ITT[0x%08x] - stopped cmd....\n", cmd->init_task_tag);

	spin_lock_irqsave(&T_TASK(cmd)->t_state_lock, flags);
	atomic_set(&T_TASK(cmd)->transport_lun_stop, 0);
	spin_unlock_irqrestore(&T_TASK(cmd)->t_state_lock, flags); 

	return(0);
}

/*	transport_generic_wait_for_tasks():
 *
 *	Called from frontend or passthrough context to wait for storage engine to pause
 *	and/or release frontend generated iscsi_cmd_t.
 */
static void transport_generic_wait_for_tasks (iscsi_cmd_t *cmd, int remove_cmd, int session_reinstatement)
{
	unsigned long flags;

	if (!(cmd->cmd_flags & ICF_SE_LUN_CMD))
		return;

	spin_lock_irqsave(&T_TASK(cmd)->t_state_lock, flags);
	/*
	 * If we are already stopped due to an external event (ie: LUN shutdown)
	 * sleep until the connection can have the passed iscsi_cmd_t back.
	 * The T_TASK(cmd)->transport_lun_stopped_sem will be upped by
	 * iscsi_target_device.c:iscsi_clear_lun_from_sessions() once the
	 * IOCTL context caller has completed its operation on the iscsi_cmd_t.
	 */
	if (atomic_read(&T_TASK(cmd)->transport_lun_stop)) {
		atomic_set(&T_TASK(cmd)->transport_lun_fe_stop, 1);
		
		DEBUG_TRANSPORT_S("wait_for_tasks: Stopping down(&T_TASK(cmd)transport_lun_fe_stop_sem);"
			" for ITT: 0x%08x\n", cmd->init_task_tag);
		
		/*
		 * There is a Special case for WRITES where a FE exception + LUN shutdown
		 * means IOCTL context is still sleeping on transport_lun_stop_sem
		 * in transport_lun_wait_for_tasks().  We go ahead and up transport_lun_stop_sem
		 * just to be sure here.
		 */
		spin_unlock_irqrestore(&T_TASK(cmd)->t_state_lock, flags);
		up(&T_TASK(cmd)->transport_lun_stop_sem);
		down(&T_TASK(cmd)->transport_lun_fe_stop_sem);
		spin_lock_irqsave(&T_TASK(cmd)->t_state_lock, flags);
		
		/*
		 * At this point, the frontend who was the originator of this
		 * iscsi_cmd_t, now owns the structure and can be released through
		 * normal means below.
		 */	
		DEBUG_TRANSPORT_S("wait_for_tasks: Stopped down(&T_TASK(cmd)transport_lun_fe_stop_sem);"
			" for ITT: 0x%08x\n", cmd->init_task_tag);

		atomic_set(&T_TASK(cmd)->transport_lun_fe_stop, 0);
		atomic_set(&T_TASK(cmd)->transport_lun_stop, 0);
	}
	if (!atomic_read(&T_TASK(cmd)->t_transport_active))
		goto remove;
	
	atomic_set(&T_TASK(cmd)->t_transport_stop, 1);
	
	DEBUG_TRANSPORT_S("wait_for_tasks: Stopping %p ITT/CmdSN: 0x%08x/0x%08x, i_state/def_i_state: %d/%d,"
		" t_state/def_t_state: %d/%d, t_transport_stop = TRUE\n", cmd, cmd->init_task_tag,
		cmd->cmd_sn, cmd->i_state, cmd->deferred_i_state, cmd->t_state, cmd->deferred_t_state);

	spin_unlock_irqrestore(&T_TASK(cmd)->t_state_lock, flags);

	CMD_ORIG_OBJ_API(cmd)->notify_obj(cmd->se_orig_obj_ptr);

	down(&T_TASK(cmd)->t_transport_stop_sem);

	spin_lock_irqsave(&T_TASK(cmd)->t_state_lock, flags);
	atomic_set(&T_TASK(cmd)->t_transport_active, 0);
	atomic_set(&T_TASK(cmd)->t_transport_stop, 0);

	DEBUG_TRANSPORT_S("wait_for_tasks: Stopped down(&T_TASK(cmd)->t_transport_stop_sem) for ITT:"
			" 0x%08x\n", cmd->init_task_tag);
remove:
	spin_unlock_irqrestore(&T_TASK(cmd)->t_state_lock, flags);
	if (!remove_cmd) 
		return;

	transport_generic_free_cmd(cmd, 0, 0, session_reinstatement);
	return;
}

/*	transport_generic_lun_reset():
 *
 *
 */
static void transport_generic_lun_reset (se_device_t *dev)
{
	return;
}

/*	transport_generic_host_reset():
 *
 *
 */
static void transport_generic_host_reset (se_hba_t *hba)
{
	return;
}

/*	transport_generic_cold_reset():
 *
 *
 */
//#warning FIXME: COLD_RESET
static void transport_generic_cold_reset (se_hba_t *hba)
{
#if 0
	int i, reset_hba = 0;
	iscsi_portal_group_t *tpg = NULL;
	
	return;

	/*
	 * Note that we change the tpg_state here and disallow
	 * logins until after TARGET_COLD_RESET has completed
	 * terminating all sessions on this target portal group.
	 */
	spin_lock(&iscsi_global->tpg_lock);
	for (i = 0 ; i < ISCSI_MAX_TPGS; i++) {
		tpg = &iscsi_global->tpg_list[i];
		spin_lock(&tpg->tpg_state_lock);
		if (tpg->tpg_state == TPG_STATE_COLD_RESET) {
			spin_unlock(&tpg->tpg_state_lock);
			continue;
		}
		if (tpg->tpg_state != TPG_STATE_ACTIVE) {
			spin_unlock(&tpg->tpg_state_lock);
			continue;
		}
		tpg->tpg_state = TPG_STATE_COLD_RESET;
		spin_unlock(&tpg->tpg_state_lock);

		iscsi_clear_tpg_np_login_threads(tpg);
		
		iscsi_release_sessions_for_tpg(tpg, 1);
		
		if (reset_hba) {
			/*
			 * Call iSCSI Transport HOST_ABORT for each addtpgtohba.
			 */	
		}
		
		spin_lock(&tpg->tpg_state_lock);
		tpg->tpg_state = TPG_STATE_ACTIVE;
		spin_unlock(&tpg->tpg_state_lock);
	}
#endif

	return;
}

/*	transport_generic_do_tmr():
 *
 *
 */
//#warning FIXME: RAID Breakage in transport_generic_do_tmr()
extern int transport_generic_do_tmr (iscsi_cmd_t *cmd)
{
	iscsi_cmd_t *ref_cmd;
	se_device_t *dev = ISCSI_DEV(cmd);
	iscsi_tmr_req_t *req = cmd->tmr_req;

	if (TRANSPORT(dev)->do_tmr)
		return(TRANSPORT(dev)->do_tmr(cmd));
	
	switch (req->function) {
	case ABORT_TASK:
		ref_cmd = req->ref_cmd;
		req->response = FUNCTION_REJECTED;
		break;
	case ABORT_TASK_SET:
	case CLEAR_ACA:
	case CLEAR_TASK_SET:
		req->response = FUNCTION_REJECTED;
		break;
	case LUN_RESET:
		transport_generic_lun_reset(dev);
		req->response = FUNCTION_REJECTED;
		break;
	case TARGET_WARM_RESET:
		transport_generic_host_reset(dev->iscsi_hba);
		req->response = FUNCTION_REJECTED;
		break;
	case TARGET_COLD_RESET:
		transport_generic_host_reset(dev->iscsi_hba);
		transport_generic_cold_reset(dev->iscsi_hba);
		req->response = FUNCTION_COMPLETE;
		break;
	default:
		TRACE_ERROR("Unknown TMR function: 0x%02x.\n",
				req->function);
		req->response = FUNCTION_REJECTED;
		break;
	}

	cmd->i_state = ISTATE_SEND_TASKMGTRSP;
	cmd->t_state = TRANSPORT_ISTATE_PROCESSING;
	iscsi_add_cmd_to_response_queue(cmd, CONN(cmd), cmd->i_state);
	
	return(0);
}

static int transport_add_qr_to_queue (se_queue_obj_t *qobj, void *se_obj_ptr, int state)
{
	iscsi_queue_req_t *qr;
	unsigned long flags;

	if (!(qr = kmalloc(sizeof(iscsi_queue_req_t), GFP_ATOMIC))) {
		TRACE_ERROR("Unable to allocate memory for iscsi_queue_req_t\n");
		return(-1);
	}
	memset(qr, 0, sizeof(iscsi_queue_req_t));

	qr->state = state;
	qr->queue_se_obj_ptr = se_obj_ptr;

	spin_lock_irqsave(&qobj->cmd_queue_lock, flags);
	ADD_ENTRY_TO_LIST(qr, qobj->queue_head, qobj->queue_tail);
	spin_unlock_irqrestore(&qobj->cmd_queue_lock, flags);
#if 0
	TRACE_ERROR("Adding obj_ptr: %p state: %d to qobj: %p\n", se_obj_ptr, state, qobj);
#endif	
	up(&qobj->thread_sem);

	return(0);
}

extern void transport_start_status_timer (se_device_t *dev);

static void transport_handle_status_timeout (unsigned long data)
{
	se_device_t *dev = (se_device_t *) data;

	spin_lock_bh(&dev->dev_status_thr_lock);
	if (dev->dev_status_timer_flags & TF_STOP) {
		spin_unlock_bh(&dev->dev_status_thr_lock);
		return;
	}
	dev->dev_status_timer_flags &= ~TF_RUNNING;
	spin_unlock_bh(&dev->dev_status_thr_lock);

	transport_add_qr_to_queue(dev->dev_status_queue_obj, (void *)dev,
			DEV_STATUS_THR_TUR);

	return;
}

extern void transport_start_status_timer (se_device_t *dev)
{
	spin_lock_bh(&dev->dev_status_thr_lock);
	if (dev->dev_status_timer_flags & TF_RUNNING) {
		spin_unlock_bh(&dev->dev_status_thr_lock);
		return;
	}

	init_timer(&dev->dev_status_timer);
	SETUP_TIMER(dev->dev_status_timer, PYX_TRANSPORT_STATUS_INTERVAL, dev,
		transport_handle_status_timeout);

	dev->dev_status_timer_flags |= TF_RUNNING;
	add_timer(&dev->dev_status_timer);

	spin_unlock_bh(&dev->dev_status_thr_lock);

	return;
}

extern void transport_stop_status_timer (se_device_t *dev)
{
	spin_lock_bh(&dev->dev_status_thr_lock);
	if (!(dev->dev_status_timer_flags & TF_RUNNING)) {
		spin_unlock_bh(&dev->dev_status_thr_lock);
		return;
	}
	dev->dev_status_timer_flags |= TF_STOP;
	spin_unlock_bh(&dev->dev_status_thr_lock);

	del_timer_sync(&dev->dev_status_timer);
	
	spin_lock_bh(&dev->dev_status_thr_lock);
	dev->dev_status_timer_flags &= ~TF_RUNNING;
	dev->dev_status_timer_flags &= ~TF_STOP;
	spin_unlock_bh(&dev->dev_status_thr_lock);

	return;
}

static void transport_status_thr_complete (iscsi_cmd_t *cmd)
{
	se_device_t *dev = ISCSI_DEV(cmd);
	int ret;

	ret = transport_passthrough_complete(cmd);	

	/*
	 * Return if the module is being removed.
	 */
	if (iscsi_global->in_shutdown) {
		transport_passthrough_release(cmd);
		return;
	}

	transport_start_status_timer(dev);

	/*
	 * The TEST_UNIT_READY completed with GOOD status.
	 */
	if (!(ret)) {
		CMD_ORIG_OBJ_API(cmd)->clear_tur_bit(cmd->se_orig_obj_ptr);

		/*
		 * If the se_obj had previously been taken offline, notify
		 * the status thread to go back into an ONLINE state.
		 */
		if (DEV_OBJ_API(dev)->check_online((void *)dev) != 0) {
			transport_add_qr_to_queue(dev->dev_status_queue_obj, (void *)dev,
					DEV_STATUS_THR_TAKE_ONLINE);
		}
	} else {
		/*
		 * If an exception condition exists, determine if a timeout did NOT
		 * occur, and clear the TUR bit.
		 */
		if (!(atomic_read(&T_TASK(cmd)->t_transport_timeout)))
			CMD_ORIG_OBJ_API(cmd)->clear_tur_bit(cmd->se_orig_obj_ptr);
		
		/*
		 * Only take the object OFFLINE if said object is currently in an
		 * ONLINE state.
		 */
		if (!(DEV_OBJ_API(dev)->check_online((void *)dev))) {
			transport_add_qr_to_queue(dev->dev_status_queue_obj, (void *)dev,
					DEV_STATUS_THR_TAKE_OFFLINE);
		}
	}

	transport_passthrough_release(cmd);
	return;
}

static int transport_status_thread_tur (se_obj_lun_type_t *obj_api, void *obj_ptr)
{
	iscsi_cmd_t *cmd;
	int ret;
	unsigned char cdb[SCSI_CDB_SIZE];
	
	memset(cdb, 0, SCSI_CDB_SIZE);
	cdb[0] = 0x00; /* TEST_UNIT_READY :-) */

	/*
	 * Only issue a TUR to this object if one had not previously been issued.
	 */
	if (obj_api->check_tur_bit(obj_ptr) != 0)
		return(-1);
	
	/*
	 * Pass ICF_SE_DISABLE_ONLINE_CHECK cmd_flag so we can still
	 * issue TEST_UNIT_READY.
	 */
	if (!(cmd = transport_allocate_passthrough(&cdb[0], ISCSI_NONE,
			ICF_SE_DISABLE_ONLINE_CHECK, NULL, 0, 0, obj_api, obj_ptr)))
		return(-1);
						                                                                
	cmd->transport_passthrough_done = &transport_status_thr_complete;

	DEBUG_ST("Submitting CDB 0x00 to se_obj_api: %p se_obj_ptr: %p\n",
			obj_api, obj_ptr);

	obj_api->set_tur_bit(obj_ptr);

	if ((ret = transport_generic_passthrough(cmd)) < 0) {
		obj_api->clear_tur_bit(obj_ptr);
		transport_passthrough_release(cmd);
	}

	return(ret);
}

/*
 *	Called with spin_lock_irq(&dev->execute_task_lock); held
 *
 */
static se_task_t *transport_get_task_from_state_list (se_device_t *dev)
{
	se_task_t *task;

	if (!dev->state_task_head)
		return(NULL);

	task = dev->state_task_head;
	atomic_set(&task->task_state_active, 0);
	
	dev->state_task_head = dev->state_task_head->ts_next;
	task->ts_next = NULL;

	if (!dev->state_task_head)
		dev->state_task_tail = NULL;

	return(task);
}

extern void transport_status_thr_force_offline (
	se_device_t *dev,
	se_obj_lun_type_t *se_obj_api,
	void *se_obj_ptr)
{
	if (se_obj_api->check_online(se_obj_ptr) != 0)
		return;

	if (se_obj_api->check_shutdown(se_obj_ptr) == 1)
		return;
	
	transport_add_qr_to_queue(dev->dev_status_queue_obj, se_obj_ptr,
			DEV_STATUS_THR_TAKE_OFFLINE);

	return;
}

extern int transport_status_thr_dev_online (se_device_t *dev)
{
	spin_lock(&dev->dev_status_lock);
	if (dev->dev_status & ISCSI_DEVICE_OFFLINE_ACTIVATED) {
		dev->dev_status |= ISCSI_DEVICE_ACTIVATED;
		dev->dev_status &= ~ISCSI_DEVICE_OFFLINE_ACTIVATED;
	} else if (dev->dev_status & ISCSI_DEVICE_OFFLINE_DEACTIVATED) {
		dev->dev_status |= ISCSI_DEVICE_DEACTIVATED;
		dev->dev_status &= ~ISCSI_DEVICE_OFFLINE_DEACTIVATED;
	}
	spin_unlock(&dev->dev_status_lock);

	return(0);
}

extern int transport_status_thr_dev_offline (se_device_t *dev)
{
	spin_lock(&dev->dev_status_lock);
	if (dev->dev_status & ISCSI_DEVICE_ACTIVATED) {
		dev->dev_status |= ISCSI_DEVICE_OFFLINE_ACTIVATED;
		dev->dev_status &= ~ISCSI_DEVICE_ACTIVATED;
	} else if (dev->dev_status & ISCSI_DEVICE_DEACTIVATED) {
		dev->dev_status |= ISCSI_DEVICE_OFFLINE_DEACTIVATED;
		dev->dev_status &= ~ISCSI_DEVICE_DEACTIVATED;
	}
	spin_unlock(&dev->dev_status_lock);

	return(0);
}

extern int transport_status_thr_dev_offline_tasks (se_device_t *dev, void *se_obj_ptr)
{
	iscsi_cmd_t *cmd;
	se_task_t *task, *task_next;
	int complete = 0, remove = 0;
	unsigned long flags;

	spin_lock_irqsave(&dev->execute_task_lock, flags);
	task = dev->state_task_head;
	while (task) {
		task_next = task->ts_next;
		if (!task->iscsi_cmd) {
			TRACE_ERROR("task->iscsi_cmd is NULL!\n");
			BUG();
		}
		cmd = task->iscsi_cmd;

		/*
		 * Only proccess iscsi_cmd_t with matching se_obj_ptr..
		 */
		if (cmd->se_orig_obj_ptr != se_obj_ptr) {
			task = task_next;
			continue;
		}
		spin_unlock_irqrestore(&dev->execute_task_lock, flags);

		spin_lock_irqsave(&T_TASK(cmd)->t_state_lock, flags);
		DEBUG_DO("DO: task: %p cmd: %p ITT/CmdSN: 0x%08x/0x%08x "
			"i_state/def_i_state: %d/%d t_state/def_t_state: %d/%d\n",
			task, cmd, cmd->init_task_tag, cmd->cmd_sn, cmd->i_state,
			cmd->deferred_i_state, cmd->t_state, cmd->deferred_t_state);

		DEBUG_DO("DO: ITT[0x%08x] - t_task_cdbs: %d t_task_cdbs_left:"
			" %d t_task_cdbs_sent: %d t_task_cdbs_ex_left: %d --"
			" t_transport_active: %d t_transport_stop: %d t_transport_sent: %d\n",
				cmd->init_task_tag, T_TASK(cmd)->t_task_cdbs,
				atomic_read(&T_TASK(cmd)->t_task_cdbs_left),
				atomic_read(&T_TASK(cmd)->t_task_cdbs_sent),
				atomic_read(&T_TASK(cmd)->t_task_cdbs_ex_left),
				atomic_read(&T_TASK(cmd)->t_transport_active),
				atomic_read(&T_TASK(cmd)->t_transport_stop),
				atomic_read(&T_TASK(cmd)->t_transport_sent));

		if (atomic_read(&task->task_active)) {
			if (atomic_read(&task->task_timeout)) {
				DEBUG_DO("DO: task->task_timeout == 1, skipping task\n");
				spin_unlock_irqrestore(&T_TASK(cmd)->t_state_lock, flags);
				spin_lock_irqsave(&dev->execute_task_lock, flags);
				task = task_next;
				continue;
			}
			
			atomic_set(&task->task_stop, 1);
			spin_unlock_irqrestore(&T_TASK(cmd)->t_state_lock, flags);

			DEBUG_DO("DO: BEFORE down(&task->task_stop_sem); ITT:"
					" 0x%08x\n", cmd->init_task_tag);
			down(&task->task_stop_sem);
			DEBUG_DO("DO: AFTER down(&task->task_stop_sem); ITT:"
					" 0x%08x\n", cmd->init_task_tag);

			spin_lock_irqsave(&T_TASK(cmd)->t_state_lock, flags);
			if (atomic_dec_and_test(&T_TASK(cmd)->t_task_cdbs_left))
				complete = 1;

			atomic_set(&task->task_active, 0);
			atomic_set(&task->task_stop, 0);
		}
		__transport_stop_task_timer(task, &flags);
		task->task_scsi_status = 1;

		if (!(atomic_dec_and_test(&T_TASK(cmd)->t_task_cdbs_ex_left))) {
			if (!(cmd->cmd_flags & ICF_SCSI_DATA_SG_IO_CDB))
				goto fail_cmd;

			if (!complete) {
				spin_unlock_irqrestore(&T_TASK(cmd)->t_state_lock, flags);

				spin_lock_irqsave(&dev->execute_task_lock, flags);
				REMOVE_ENTRY_FROM_LIST_PREFIX(ts, task,
					dev->state_task_head, dev->state_task_tail);
				task = task_next;
				continue;
			}
		}

		if (!(cmd->cmd_flags & ICF_SCSI_DATA_SG_IO_CDB))
			goto fail_cmd;

		if (cmd->cmd_flags & ICF_TRANSPORT_TASK_SENSE)
			cmd->cmd_flags &= ~ICF_TRANSPORT_TASK_SENSE;

		transport_remove_cmd_from_queue(cmd,
			CMD_ORIG_OBJ_API(cmd)->get_queue_obj(cmd->se_orig_obj_ptr));

		DEBUG_DO("DO: Completing %s ITT: 0x%08x last task: %p\n",
			(cmd->data_direction == ISCSI_READ) ? "READ" : "WRITE",
				cmd->init_task_tag, task);

		cmd->t_state = TRANSPORT_COMPLETE_FAILURE;
		spin_unlock_irqrestore(&T_TASK(cmd)->t_state_lock, flags);

		cmd->transport_add_cmd_to_queue(cmd, TRANSPORT_COMPLETE_FAILURE);
		complete = 0;
				
		spin_lock_irqsave(&dev->execute_task_lock, flags);
		REMOVE_ENTRY_FROM_LIST_PREFIX(ts, task,
			dev->state_task_head, dev->state_task_tail);
		task = task_next;
		continue;

fail_cmd:
		remove = (cmd->i_state == ISTATE_REMOVE);
		spin_unlock_irqrestore(&T_TASK(cmd)->t_state_lock, flags);

		if (!remove)
			iscsi_send_check_condition_and_sense(cmd, LOGICAL_UNIT_COMMUNICATION_FAILURE, 0);

		transport_remove_cmd_from_queue(cmd,
			CMD_ORIG_OBJ_API(cmd)->get_queue_obj(cmd->se_orig_obj_ptr));

		transport_lun_remove_cmd(cmd);
		if (!(transport_cmd_check_stop(cmd, 1, 0)))
			transport_passthrough_check_stop(cmd);
		
		spin_lock_irqsave(&dev->execute_task_lock, flags);
		REMOVE_ENTRY_FROM_LIST_PREFIX(ts, task,
			dev->state_task_head, dev->state_task_tail);
		task = task_next;
	}
	spin_unlock_irqrestore(&dev->execute_task_lock, flags);

	return(0);
}

static void transport_status_empty_queue (se_queue_obj_t *qobj)
{
	iscsi_queue_req_t *qr;
	unsigned long flags;
	
	spin_lock_irqsave(&qobj->cmd_queue_lock, flags);
	while ((qr = __transport_get_qr_from_queue(qobj))) {
#if 0
		TRACE_ERROR("Freeing qr: %p qr->state: %d\n", qr, qr->state);
#endif
		kfree(qr);
	}
	spin_unlock_irqrestore(&qobj->cmd_queue_lock, flags);

	return;
}

static int transport_status_dev_offline (se_device_t *dev)
{
	se_fp_obj_t *fp;	

	if (DEV_OBJ_API(dev)->check_online((void *)dev) != 0) {
		DEBUG_ST("Ignoring DEV_STATUS_THR_TAKE_OFFLINE: while OFFLINE\n");
		return(0);
	}
	transport_status_thr_dev_offline(dev);

	fp = DEV_OBJ_API(dev)->get_feature_obj((void *)dev);
	if (fp && fp->fp_api->feature_element_offline)
		fp->fp_api->feature_element_offline(fp);
	else
		transport_status_thr_dev_offline_tasks(dev, (void *)dev);

	return(0);
}

static int transport_status_dev_online (se_device_t *dev)
{
	se_fp_obj_t *fp;

	if (!(DEV_OBJ_API(dev)->check_online((void *)dev))) {
		DEBUG_ST("Ignoring DEV_STATUS_THR_TAKE_ONLINE: while ONLINE\n");
		return(0);
	}
	transport_status_thr_dev_online(dev);

	fp = DEV_OBJ_API(dev)->get_feature_obj((void *)dev);
	if (fp && fp->fp_api->feature_element_online)
		fp->fp_api->feature_element_online(fp);
				
	return(0);
}

static int transport_status_thread (void *p)
{
	se_obj_lun_type_t *se_obj_api;
	se_device_t *dev = (se_device_t *)p;
	iscsi_queue_req_t *qr;
	void *se_obj_ptr;
	int ret, state;

	{
	char name[16];
	sprintf(name, "LIO_st_%s", TRANSPORT(dev)->name);
	iscsi_daemon(dev->dev_mgmt_thread, name, SHUTDOWN_SIGS);
        }
	
	up(&dev->dev_status_queue_obj->thread_create_sem);
	
	transport_start_status_timer(dev);

	while (1) {
		down_interruptible(&dev->dev_status_queue_obj->thread_sem);
		if (signal_pending(current))
			goto out;

		spin_lock(&dev->dev_status_lock);
		if (dev->dev_status & ISCSI_DEVICE_SHUTDOWN) {
			spin_unlock(&dev->dev_status_lock);
			continue;
		}
		spin_unlock(&dev->dev_status_lock);

		if (!(qr = transport_get_qr_from_queue(dev->dev_status_queue_obj)))
			continue;
		
		se_obj_ptr = qr->queue_se_obj_ptr;
		se_obj_api = qr->queue_se_obj_api;
		state = qr->state;
		kfree(qr);
		
		switch (state) {
		case DEV_STATUS_THR_TUR:
			DEBUG_ST("dev: %p DEV_STATUS_THR_TUR:\n", dev);
			ret = transport_status_thread_tur(DEV_OBJ_API(dev), (void *)dev);
			if (ret != 0) {
				transport_start_status_timer(dev);
				break;
			}
			break;
		case DEV_STATUS_THR_TAKE_OFFLINE:
			DEBUG_ST("dev: %p DEV_STATUS_THR_TAKE_OFFLINE:\n", dev);
			transport_status_dev_offline(dev);
			break;
		case DEV_STATUS_THR_TAKE_ONLINE:
			DEBUG_ST("dev: %p DEV_STATUS_THR_TAKE_ONLINE:\n", dev);
			transport_status_dev_online(dev);
			break;
		case DEV_STATUS_THR_SHUTDOWN:
			DEBUG_ST("dev: %p DEV_STATUS_THR_SHUTDOWN:\n", dev);
			goto out;
		default:
			break;
		}
	}

out:
	transport_status_empty_queue(dev->dev_status_queue_obj);
	transport_stop_status_timer(dev);
	dev->dev_mgmt_thread = NULL;
	up(&dev->dev_status_queue_obj->thread_done_sem);
	return(0);
}

extern void transport_start_status_thread (se_device_t *dev)
{
	spin_lock_bh(&dev->dev_status_thr_lock);
	atomic_inc(&dev->dev_status_thr_count);
	if (atomic_read(&dev->dev_status_thr_count) != 1) {
		spin_unlock_bh(&dev->dev_status_thr_lock);
		return;
	}
	spin_unlock_bh(&dev->dev_status_thr_lock);
	
	kernel_thread(transport_status_thread, (void *)dev, 0);
	down(&dev->dev_status_queue_obj->thread_create_sem);

	return;
}

extern void transport_stop_status_thread (se_device_t *dev)
{
	spin_lock_bh(&dev->dev_status_thr_lock);
	if (!(atomic_dec_and_test(&dev->dev_status_thr_count))) {
		spin_unlock_bh(&dev->dev_status_thr_lock);
		return;
	}

	send_sig(SIGKILL, dev->dev_mgmt_thread, 1);
	spin_unlock_bh(&dev->dev_status_thr_lock);
	
	down(&dev->dev_status_queue_obj->thread_done_sem);
	
	return;
}

static void transport_processing_shutdown (se_device_t *dev)
{
	iscsi_cmd_t *cmd;
	iscsi_queue_req_t *qr;
	se_task_t *task;
	u8 state;
	unsigned long flags;


	/*
	 * Empty the se_device_t's se_task_t state list.
	 */
	spin_lock_irqsave(&dev->execute_task_lock, flags);
	while ((task = transport_get_task_from_state_list(dev))) {
		if (!task->iscsi_cmd) {
			TRACE_ERROR("task->iscsi_cmd is NULL!\n");
			continue;
		}
		cmd = task->iscsi_cmd;
		
		if (!T_TASK(cmd)) {
			TRACE_ERROR("T_TASK(cmd) is NULL for task: %p cmd: %p ITT: 0x%08x\n",
				task, cmd, cmd->init_task_tag);
			continue;
		}
		spin_unlock_irqrestore(&dev->execute_task_lock, flags);

		spin_lock_irqsave(&T_TASK(cmd)->t_state_lock, flags);

		DEBUG_DO("PT: cmd: %p task: %p ITT/CmdSN: 0x%08x/0x%08x, i_state/def_i_state: %d/%d,"
			" t_state/def_t_state: %d/%d cdb: 0x%02x\n", cmd, task, cmd->init_task_tag,
			cmd->cmd_sn, cmd->i_state, cmd->deferred_i_state, cmd->t_state,
			cmd->deferred_t_state, T_TASK(cmd)->t_task_cdb[0]);
		DEBUG_DO("PT: ITT[0x%08x] - t_task_cdbs: %d t_task_cdbs_left: %d t_task_cdbs_sent: %d"
			" -- t_transport_active: %d t_transport_stop: %d t_transport_sent: %d\n",
				cmd->init_task_tag, T_TASK(cmd)->t_task_cdbs,
				atomic_read(&T_TASK(cmd)->t_task_cdbs_left),
				atomic_read(&T_TASK(cmd)->t_task_cdbs_sent),
				atomic_read(&T_TASK(cmd)->t_transport_active),
				atomic_read(&T_TASK(cmd)->t_transport_stop),
				atomic_read(&T_TASK(cmd)->t_transport_sent));

		if (atomic_read(&task->task_active)) {
			atomic_set(&task->task_stop, 1);
			spin_unlock_irqrestore(&T_TASK(cmd)->t_state_lock, flags);

			DEBUG_DO("Waiting for task: %p to shutdown for dev: %p\n", task, dev);
			down(&task->task_stop_sem);
			DEBUG_DO("Completed task: %p shutdown for dev: %p\n", task, dev);

			spin_lock_irqsave(&T_TASK(cmd)->t_state_lock, flags);
			atomic_dec(&T_TASK(cmd)->t_task_cdbs_left);

			atomic_set(&task->task_active, 0);
			atomic_set(&task->task_stop, 0);
		}
		__transport_stop_task_timer(task, &flags);

		if (!(atomic_dec_and_test(&T_TASK(cmd)->t_task_cdbs_ex_left))) {
			spin_unlock_irqrestore(&T_TASK(cmd)->t_state_lock, flags);
			
			DEBUG_DO("Skipping task: %p, dev: %p for t_task_cdbs_ex_left: %d\n",
				task, dev, atomic_read(&T_TASK(cmd)->t_task_cdbs_ex_left));
			
			spin_lock_irqsave(&dev->execute_task_lock, flags);
			continue;
		}

		if (atomic_read(&T_TASK(cmd)->t_transport_active)) {
			DEBUG_DO("got t_transport_active = 1 for task: %p, dev: %p\n", task, dev);

			if (atomic_read(&T_TASK(cmd)->t_fe_count)) {
				spin_unlock_irqrestore(&T_TASK(cmd)->t_state_lock, flags);
				iscsi_send_check_condition_and_sense(cmd, LOGICAL_UNIT_COMMUNICATION_FAILURE, 0);
				transport_remove_cmd_from_queue(cmd,
						CMD_ORIG_OBJ_API(cmd)->get_queue_obj(cmd->se_orig_obj_ptr));

				transport_lun_remove_cmd(cmd);
				if (!(transport_cmd_check_stop(cmd, 1, 0)))
					transport_passthrough_check_stop(cmd);
			} else {
				spin_unlock_irqrestore(&T_TASK(cmd)->t_state_lock, flags);

				transport_remove_cmd_from_queue(cmd,
						CMD_ORIG_OBJ_API(cmd)->get_queue_obj(cmd->se_orig_obj_ptr));
				transport_lun_remove_cmd(cmd);

				if (!(transport_cmd_check_stop(cmd, 1, 0)))
					transport_passthrough_check_stop(cmd);
				else
					transport_generic_remove(cmd, 0, 0);
			}

			spin_lock_irqsave(&dev->execute_task_lock, flags);
			continue;
		}

		DEBUG_DO("Got t_transport_active = 0 for task: %p, dev: %p\n", task, dev);

		if (atomic_read(&T_TASK(cmd)->t_fe_count)) {
			spin_unlock_irqrestore(&T_TASK(cmd)->t_state_lock, flags);	
			iscsi_send_check_condition_and_sense(cmd, LOGICAL_UNIT_COMMUNICATION_FAILURE, 0);
			transport_remove_cmd_from_queue(cmd,
					CMD_ORIG_OBJ_API(cmd)->get_queue_obj(cmd->se_orig_obj_ptr));

			transport_lun_remove_cmd(cmd);
			if (!(transport_cmd_check_stop(cmd, 1, 0)))
				transport_passthrough_check_stop(cmd);
		} else {
			spin_unlock_irqrestore(&T_TASK(cmd)->t_state_lock, flags);

			transport_remove_cmd_from_queue(cmd,
					CMD_ORIG_OBJ_API(cmd)->get_queue_obj(cmd->se_orig_obj_ptr));
			transport_lun_remove_cmd(cmd);

			if (!(transport_cmd_check_stop(cmd, 1, 0)))
				transport_passthrough_check_stop(cmd);
			else
				transport_generic_remove(cmd, 0, 0);
		}

		spin_lock_irqsave(&dev->execute_task_lock, flags);
	}
	spin_unlock_irqrestore(&dev->execute_task_lock, flags);

	/*
	 * Empty the se_device_t's iscsi_cmd_t list.
	 */
	spin_lock_irqsave(&dev->dev_queue_obj->cmd_queue_lock, flags);
	while ((qr = __transport_get_qr_from_queue(dev->dev_queue_obj))) {
		spin_unlock_irqrestore(&dev->dev_queue_obj->cmd_queue_lock, flags);
		cmd = qr->cmd;
		state = qr->state;
		kfree(qr);

		DEBUG_DO("From Device Queue: cmd: %p t_state: %d\n", cmd, state);
		
		if (atomic_read(&T_TASK(cmd)->t_fe_count)) {
			iscsi_send_check_condition_and_sense(cmd, LOGICAL_UNIT_COMMUNICATION_FAILURE, 0);

			transport_lun_remove_cmd(cmd);
			if (!(transport_cmd_check_stop(cmd, 1, 0)))
				transport_passthrough_check_stop(cmd);
		} else {
			transport_lun_remove_cmd(cmd);

			if (!(transport_cmd_check_stop(cmd, 1, 0)))
				transport_passthrough_check_stop(cmd);
			else
				transport_generic_remove(cmd, 0, 0);
		}
		spin_lock_irqsave(&dev->dev_queue_obj->cmd_queue_lock, flags);
	}
	spin_unlock_irqrestore(&dev->dev_queue_obj->cmd_queue_lock, flags);
	
	return;
}

/*	transport_processing_thread():
 *
 *
 */
static int transport_processing_thread (void *param)
{
	int ret, t_state;
	iscsi_cmd_t *cmd;
	se_device_t *dev = (se_device_t *) param;
	iscsi_queue_req_t *qr;

	{
	char name[16];
	sprintf(name, "LIO_%s", TRANSPORT(dev)->name);
	iscsi_daemon(dev->process_thread, name, SHUTDOWN_SIGS);
	}

	up(&dev->dev_queue_obj->thread_create_sem);
	
	while (1) {
		down_interruptible(&dev->dev_queue_obj->thread_sem);
		
		if (signal_pending(current))
			goto out;

		spin_lock(&dev->dev_status_lock);
		if (dev->dev_status & ISCSI_DEVICE_SHUTDOWN) {
			spin_unlock(&dev->dev_status_lock);
			transport_processing_shutdown(dev);
			continue;
		}
		spin_unlock(&dev->dev_status_lock);

get_cmd:
		__transport_execute_tasks(dev);

		if (!(qr = transport_get_qr_from_queue(dev->dev_queue_obj)))
			continue;

		cmd = qr->cmd;
		t_state = qr->state;
		kfree(qr);
		
		switch (t_state) {
		case TRANSPORT_NEW_CMD:
			if ((ret = transport_generic_new_cmd(cmd)) < 0) {
				cmd->transport_error_status = ret;				
				transport_generic_request_failure(cmd, NULL, 0,
					(cmd->data_direction != ISCSI_WRITE));
			}
			break;
		case TRANSPORT_PROCESS_WRITE:
			transport_generic_process_write(cmd);
			break;
		case TRANSPORT_COMPLETE_OK:
			transport_stop_all_task_timers(cmd);
			transport_generic_complete_ok(cmd);
			break;
		case TRANSPORT_REMOVE:
			transport_generic_remove(cmd, 1, 0);
			break;
		case TRANSPORT_PROCESS_TMR:
			transport_generic_do_tmr(cmd);
			break;
		case TRANSPORT_COMPLETE_FAILURE:
			transport_generic_request_failure(cmd, NULL, 1, 1);
			break;
		case TRANSPORT_COMPLETE_TIMEOUT:
			transport_stop_all_task_timers(cmd);
			transport_generic_request_timeout(cmd);
			break;
		default:
			TRACE_ERROR("Unknown t_state: %d deferred_t_state: %d"
				" for ITT: 0x%08x i_state: %d on iSCSI LUN: %u\n",
					t_state, cmd->deferred_t_state,
				cmd->init_task_tag, cmd->i_state, ISCSI_LUN(cmd)->iscsi_lun);
			BUG();
		}

		goto get_cmd;
	}

out:
	transport_release_all_cmds(dev);
	dev->process_thread = NULL;
	up(&dev->dev_queue_obj->thread_done_sem);
	return(0);
}
