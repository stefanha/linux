/*******************************************************************************
 * Filename:  tcm_loop_fabric_scsi.c
 *
 * This file contains the Linux/SCSI LLD virtual SCSI initiator driver
 * for emulated SAS initiator ports
 *
 * Copyright (c) 2009-2010 Rising Tide, Inc.
 * Copyright (c) 2009-2010 Linux-iSCSI.org
 *
 * Copyright (c) 2009-2010 Nicholas A. Bellinger <nab@linux-iscsi.org>
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
 ****************************************************************************/

#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/version.h>
#include <generated/utsrelease.h>
#include <linux/utsname.h>
#include <linux/init.h>
#include <linux/slab.h>
#include <linux/types.h>
#include <linux/string.h>
#include <scsi/scsi.h>
#include <scsi/scsi_tcq.h>
#include <scsi/scsi_host.h>
#include <scsi/scsi_device.h>
#include <scsi/scsi_cmnd.h>
#include <scsi/libsas.h> /* For TASK_ATTR_* */

#include <target/target_core_base.h>
#include <target/target_core_transport.h>
#include <target/target_core_fabric_ops.h>
#include <target/target_core_device.h>
#include <target/target_core_tpg.h>
#include <target/target_core_tmr.h>

#include <tcm_loop_core.h>
#include <tcm_loop_fabric.h>
#include <tcm_loop_fabric_scsi.h>

#define to_tcm_loop_hba(hba)	container_of(hba, struct tcm_loop_hba, dev)

/* 
 * Allocate a tcm_loop cmd descriptor from target_core_mod code
 *
 * Can be called from interrupt context in tcm_loop_queuecommand() below
 */
static struct tcm_loop_cmd *tcm_loop_allocate_core_cmd(
	struct tcm_loop_hba *tl_hba,
	struct se_portal_group *se_tpg,
	struct scsi_cmnd *sc,
	int data_direction)
{
	struct se_session *se_sess;
	struct tcm_loop_nexus *tl_nexus = tl_hba->tl_nexus;
	struct tcm_loop_cmd *tl_cmd;
	int sam_task_attr;

	if (!(tl_nexus)) {
		scmd_printk(KERN_ERR, sc, "TCM_Loop I_T Nexus"
				" does not exist\n");
		return NULL;
	}
	se_sess = tl_nexus->se_sess;

	tl_cmd = kmem_cache_zalloc(tcm_loop_cmd_cache, GFP_ATOMIC);
	if (!(tl_cmd)) {
		printk(KERN_ERR "Unable to allocate struct tcm_loop_cmd\n");
		return NULL;
	}
	/*
	 * Save the pointer to struct scsi_cmnd *sc
	 */
	tl_cmd->sc = sc;

	/*
	 * Locate the SAM Task Attr from struct scsi_cmnd *
	 */
	if (sc->device->tagged_supported) {
		switch (sc->tag) {
		case HEAD_OF_QUEUE_TAG:
			sam_task_attr = TASK_ATTR_HOQ;
			break;
		case ORDERED_QUEUE_TAG:
			sam_task_attr = TASK_ATTR_ORDERED;
			break;
		default:
			sam_task_attr = TASK_ATTR_SIMPLE;
			break;
		}
	} else
		sam_task_attr = TASK_ATTR_SIMPLE;
	/*
	 * Allocate the struct se_cmd descriptor from target_core_mod infrastructure
	 */
	tl_cmd->tl_se_cmd = transport_alloc_se_cmd(se_tpg->se_tpg_tfo,
			se_sess, (void *)tl_cmd, scsi_bufflen(sc),
			data_direction, sam_task_attr);
	if (!(tl_cmd->tl_se_cmd)) {
		kmem_cache_free(tcm_loop_cmd_cache, tl_cmd);
		return NULL;
	}
			
	return tl_cmd;
}

/*
 * Queue up the newly allocated struct tcm_loop_cmd to be processed by
 * tcm_loop_fabri.c:tcm_loop_processing_thread()
 *
 * Can be called from interrupt context in tcm_loop_queuecommand() below
 */
static int tcm_loop_queue_core_cmd(
	struct se_queue_obj *qobj,
	struct tcm_loop_cmd *tl_cmd)
{
	struct se_queue_req *qr;
	unsigned long flags;

	qr = kzalloc(sizeof(struct se_queue_req), GFP_ATOMIC);
	if (!(qr)) {
		printk(KERN_ERR "Unable to allocate memory for"
				" struct se_queue_req\n");
		return -1;	
	}
	INIT_LIST_HEAD(&qr->qr_list);

	qr->cmd = (void *)tl_cmd;
	spin_lock_irqsave(&qobj->cmd_queue_lock, flags);
	list_add_tail(&qr->qr_list, &qobj->qobj_list);
	spin_unlock_irqrestore(&qobj->cmd_queue_lock, flags);

	atomic_inc(&qobj->queue_cnt);
	wake_up_interruptible(&qobj->thread_wq);
	return 0;
}

/*
 * Called by tcm_loop_processing_thread() in tcm_loop_fabric.c
 *
 * Always called in process context
 */
int tcm_loop_execute_core_cmd(struct tcm_loop_cmd *tl_cmd, struct scsi_cmnd *sc)
{
	struct se_cmd *se_cmd = tl_cmd->tl_se_cmd;
	void *mem_ptr;
	int ret;
	/*
	 * Locate the struct se_lun pointer and attach it to struct se_cmd
	 */
	if (transport_get_lun_for_cmd(se_cmd, NULL,
				tl_cmd->sc->device->lun) < 0) {
		/* NON_EXISTENT_LUN */
		transport_send_check_condition_and_sense(se_cmd,
				se_cmd->scsi_sense_reason, 0);
		return 0;
	}
	/*
	 * Allocate the necessary tasks to complete the received CDB+data
	 */
	ret = transport_generic_allocate_tasks(se_cmd, tl_cmd->sc->cmnd);
	if (ret == -1) {
		/* Out of Resources */
		transport_send_check_condition_and_sense(se_cmd,
				LOGICAL_UNIT_COMMUNICATION_FAILURE, 0);
		return 0;
	} else if (ret == -2) {
		/*
		 * Handle case for SAM_STAT_RESERVATION_CONFLICT
		 */
		if (se_cmd->se_cmd_flags & SCF_SCSI_RESERVATION_CONFLICT) {
			tcm_loop_queue_status(se_cmd);
			return 0;
		}
		/*
		 * Otherwise, return SAM_STAT_CHECK_CONDITION and return
		 * sense data.
		 */
		transport_send_check_condition_and_sense(se_cmd,
				se_cmd->scsi_sense_reason, 0);
		return 0;
	}
	/*
	 * Setup the struct scatterlist memory from the received
	 * struct scsi_cmnd.
	 */
	if (scsi_sg_count(sc)) {
		se_cmd->se_cmd_flags |= SCF_PASSTHROUGH_SG_TO_MEM;
		mem_ptr = (void *)scsi_sglist(sc);
	} else {
		/*
		 * Used for DMA_NONE
		 */
                mem_ptr = NULL;
        }
	/*
	 * Map the SG memory into struct se_mem->page linked list using the same
	 * physical memory at sg->page_link.
	 */
	ret = transport_generic_map_mem_to_cmd(se_cmd, mem_ptr,
				scsi_sg_count(sc));
	if (ret < 0) {
		transport_send_check_condition_and_sense(se_cmd,
				LOGICAL_UNIT_COMMUNICATION_FAILURE, 0);
		return 0;
	}
	/*
	 * Queue up the struct se_cmd + tasks to be processed by the
	 * TCM storage object.
	 */
	return transport_generic_handle_cdb(se_cmd);
}

/*
 * Called from struct target_core_fabric_ops->check_stop_free()
 */
void tcm_loop_check_stop_free(struct se_cmd *se_cmd)
{
	/*
	 * Release the struct se_cmd, which will make a callback to release
	 * struct tcm_loop_cmd * in tcm_loop_deallocate_core_cmd()
	 */
	transport_generic_free_cmd(se_cmd, 0, 1, 0);
}

/*
 * Called from struct target_core_fabric_ops->releastruct se_cmdo_pool()
 */
void tcm_loop_deallocate_core_cmd(struct se_cmd *se_cmd)
{
	struct tcm_loop_cmd *tl_cmd =
			(struct tcm_loop_cmd *)se_cmd->se_fabric_cmd_ptr;

	kmem_cache_free(tcm_loop_cmd_cache, tl_cmd);
}

void tcm_loop_scsi_forget_host(struct Scsi_Host *shost)
{
        struct scsi_device *sdev, *tmp;
        unsigned long flags;

        spin_lock_irqsave(shost->host_lock, flags);
        list_for_each_entry_safe(sdev, tmp, &shost->__devices, siblings) {
                spin_unlock_irqrestore(shost->host_lock, flags);
                scsi_remove_device(sdev);
                spin_lock_irqsave(shost->host_lock, flags);
        }
        spin_unlock_irqrestore(shost->host_lock, flags);
}

static int tcm_loop_proc_info(struct Scsi_Host *host, char *buffer,
				char **start, off_t offset,
				int length, int inout)
{
	return sprintf(buffer, "tcm_loop_proc_info()\n");
}

static int tcm_loop_driver_probe(struct device *);
static int tcm_loop_driver_remove(struct device *);

static int pseudo_lld_bus_match(struct device *dev,
				struct device_driver *dev_driver)
{
	return 1;
}

static struct bus_type tcm_loop_lld_bus = {
	.name			= "tcm_loop_bus",
	.match			= pseudo_lld_bus_match,
	.probe			= tcm_loop_driver_probe,
	.remove			= tcm_loop_driver_remove,
};

static struct device_driver tcm_loop_driverfs = {
	.name			= "tcm_loop",
	.bus			= &tcm_loop_lld_bus,
};

static void tcm_loop_primary_release(struct device *dev)
{
	return;
}

static struct device tcm_loop_primary = {
	.init_name		= "tcm_loop_0",
	.release		= tcm_loop_primary_release,
};

/*
 * Copied from drivers/scsi/libfc/fc_fcp.c:fc_change_queue_depth() and
 * drivers/scsi/libiscsi.c:iscsi_change_queue_depth()
 */
static int tcm_loop_change_queue_depth(
	struct scsi_device *sdev,
	int depth,
	int reason)
{
	switch (reason) {
	case SCSI_QDEPTH_DEFAULT:
		scsi_adjust_queue_depth(sdev, scsi_get_tag_type(sdev), depth);
		break;
	case SCSI_QDEPTH_QFULL:
		scsi_track_queue_full(sdev, depth);
		break;
	case SCSI_QDEPTH_RAMP_UP:
		scsi_adjust_queue_depth(sdev, scsi_get_tag_type(sdev), depth);
		break;
	default:
		return -EOPNOTSUPP;
	}
	return sdev->queue_depth;
}

static inline struct tcm_loop_hba *tcm_loop_get_hba(struct scsi_cmnd *sc)
{
	return (struct tcm_loop_hba *)sc->device->host->hostdata[0];
}

/*
 * Main entry point from struct scsi_host_template for incoming SCSI CDB+Data
 * from Linux/SCSI subsystem for SCSI low level device drivers (LLDs)
 */
static int tcm_loop_queuecommand(
	struct scsi_cmnd *sc,
	void (*done)(struct scsi_cmnd *))
{
	struct se_portal_group *se_tpg;
	struct tcm_loop_cmd *tl_cmd;
	struct tcm_loop_hba *tl_hba;
	struct tcm_loop_tpg *tl_tpg;
	int data_direction;

	sc->scsi_done = done;

	TL_CDB_DEBUG("tcm_loop_queuecommand() %d:%d:%d:%d got CDB: 0x%02x"
		" scsi_buf_len: %u\n", sc->device->host->host_no,
		sc->device->id, sc->device->channel, sc->device->lun,
		sc->cmnd[0], scsi_bufflen(sc));

	spin_unlock_irq(sc->device->host->host_lock);
	/*
	 * Locate the tcm_loop_hba_t pointer 
	 */
	tl_hba = tcm_loop_get_hba(sc);
	if (!(tl_hba)) {
		printk(KERN_ERR "Unable to locate struct tcm_loop_hba from"
				" struct scsi_cmnd\n");
		sc->result = host_byte(DID_ERROR);
		(*done)(sc);
		return 0;	
	}
	tl_tpg = &tl_hba->tl_hba_tpgs[sc->device->id];
	se_tpg = &tl_tpg->tl_se_tpg;

	if (sc->sc_data_direction == DMA_TO_DEVICE)
		data_direction = SE_DIRECTION_WRITE;
	else if (sc->sc_data_direction == DMA_FROM_DEVICE)
		data_direction = SE_DIRECTION_READ;
	else if (sc->sc_data_direction == DMA_NONE)
		data_direction = SE_DIRECTION_NONE;
	else {
		spin_lock_irq(sc->device->host->host_lock);
		printk(KERN_ERR "Unsupported sc->sc_data_direction: %d\n",
			sc->sc_data_direction);	
		sc->result = host_byte(DID_ERROR);
		(*done)(sc);
		return 0;
	}
	/*
	 * Determine the SAM Task Attribute and allocate tl_cmd and
	 * tl_cmd->tl_se_cmd from TCM infrastructure
	 */
	tl_cmd = tcm_loop_allocate_core_cmd(tl_hba, se_tpg, sc, data_direction);
	if (!(tl_cmd)) {
		spin_lock_irq(sc->device->host->host_lock);
		sc->result = host_byte(DID_ERROR);
		(*done)(sc);
		return 0;
	}
	/*
	 * Queue the tl_cmd to be executed in process context by the
	 * tcm_loop kernel thread
	 */
	if (tcm_loop_queue_core_cmd(tl_hba->tl_hba_qobj, tl_cmd) < 0) {
		/*
		 * Will free both struct tcm_loop_cmd and struct se_cmd
		 */
		transport_release_cmd_to_pool(tl_cmd->tl_se_cmd);
		/*
		 * Reaquire the struct scsi_host->host_lock, and
		 * complete the struct scsi_cmnd
		 */
		spin_lock_irq(sc->device->host->host_lock);
		sc->result = host_byte(DID_ERROR);
		(*done)(sc);
		return 0;
	}
	/*
	 * Reaquire the the struct scsi_host->host_lock before returning
	 */
	spin_lock_irq(sc->device->host->host_lock);
	return 0;
}

/*
 * Called from SCSI EH process context to issue a LUN_RESET TMR
 * to struct scsi_device
 */
static int tcm_loop_device_reset(struct scsi_cmnd *sc)
{
	struct se_cmd *se_cmd = NULL;
	struct se_portal_group *se_tpg;
	struct se_session *se_sess;
	struct tcm_loop_cmd *tl_cmd = NULL;
	struct tcm_loop_hba *tl_hba;
	struct tcm_loop_nexus *tl_nexus;
	struct tcm_loop_tmr *tl_tmr = NULL;
	struct tcm_loop_tpg *tl_tpg;
	int ret = FAILED;
	/*
	 * Locate the tcm_loop_hba_t pointer 
	 */
	tl_hba = tcm_loop_get_hba(sc);
	if (!(tl_hba)) {
		printk(KERN_ERR "Unable to locate struct tcm_loop_hba from"
				" struct scsi_cmnd\n");
		return FAILED;
	}
	/*
	 * Locate the tl_nexus and se_sess pointers
	 */
	tl_nexus = tl_hba->tl_nexus;
	if (!(tl_nexus)) {
		printk(KERN_ERR "Unable to perform device reset without"
				" active I_T Nexus\n");
		return FAILED;
	}
	se_sess = tl_nexus->se_sess;
	/*
	 * Locate the tl_tpg and se_tpg pointers from TargetID in sc->device->id
	 */
	tl_tpg = &tl_hba->tl_hba_tpgs[sc->device->id];
	se_tpg = &tl_tpg->tl_se_tpg;

	tl_cmd = kmem_cache_zalloc(tcm_loop_cmd_cache, GFP_KERNEL);
	if (!(tl_cmd)) {
		printk(KERN_ERR "Unable to allocate memory for tl_cmd\n");
		return FAILED;
	}

	tl_tmr = kzalloc(sizeof(struct tcm_loop_tmr), GFP_KERNEL);
	if (!(tl_tmr)) {
		printk(KERN_ERR "Unable to allocate memory for tl_tmr\n");
		goto release;
	}
	init_waitqueue_head(&tl_tmr->tl_tmr_wait);
	/*
	 * Allocate the struct se_cmd for a LUN_RESET TMR
	 */
	tl_cmd->tl_se_cmd = transport_alloc_se_cmd(se_tpg->se_tpg_tfo,
			se_sess, (void *)tl_cmd, 0, SE_DIRECTION_NONE,
			TASK_ATTR_SIMPLE);
	if (!(tl_cmd->tl_se_cmd))
		goto release;
	se_cmd = tl_cmd->tl_se_cmd;
	/*
	 * Allocate the LUN_RESET TMR
	 */
	se_cmd->se_tmr_req = core_tmr_alloc_req(se_cmd, (void *)tl_tmr,
				LUN_RESET);
	if (!(se_cmd->se_tmr_req))
		goto release;
	/*
	 * Locate the underlying TCM struct se_lun from sc->device->lun
	 */
	if (transport_get_lun_for_tmr(se_cmd, sc->device->lun) < 0)
		goto release;
	/*
	 * Queue the TMR to TCM Core and sleep waiting for tcm_loop_queue_tm_rsp()
	 * to wake us up.
	 */
	transport_generic_handle_tmr(se_cmd);	
	wait_event(tl_tmr->tl_tmr_wait, atomic_read(&tl_tmr->tmr_complete));
	/*
	 * The TMR LUN_RESET has completed, check the response status and
	 * then release allocations.
	 */
	ret = (se_cmd->se_tmr_req->response == TMR_FUNCTION_COMPLETE) ?
		SUCCESS : FAILED;
release:
	if (se_cmd)
		transport_generic_free_cmd(se_cmd, 1, 1, 0);
	else
		kmem_cache_free(tcm_loop_cmd_cache, tl_cmd);
	kfree(tl_tmr);
	return ret;
}

static struct scsi_host_template tcm_loop_driver_template = {
	.proc_info		= tcm_loop_proc_info,
	.proc_name		= "tcm_loopback",
	.name			= "TCM_Loopback",
	.info			= NULL,
	.slave_alloc		= NULL,
	.slave_configure	= NULL,
	.slave_destroy		= NULL,
	.ioctl			= NULL,
	.queuecommand		= tcm_loop_queuecommand,
	.change_queue_depth	= tcm_loop_change_queue_depth,
	.eh_abort_handler	= NULL,
	.eh_bus_reset_handler	= NULL,
	.eh_device_reset_handler = tcm_loop_device_reset,
	.eh_host_reset_handler	= NULL,
	.bios_param		= NULL,
	.can_queue		= TL_SCSI_CAN_QUEUE,
	.this_id		= -1,
	.sg_tablesize		= TL_SCSI_SG_TABLESIZE,
	.cmd_per_lun		= TL_SCSI_CMD_PER_LUN,
	.max_sectors		= TL_SCSI_MAX_SECTORS,
	.use_clustering		= DISABLE_CLUSTERING,
	.module			= THIS_MODULE,
};

static int tcm_loop_driver_probe(struct device *dev)
{
	struct tcm_loop_hba *tl_hba;
	struct Scsi_Host *sh;
	int error;

	tl_hba = to_tcm_loop_hba(dev);

	sh = scsi_host_alloc(&tcm_loop_driver_template,
			sizeof(struct tcm_loop_hba));
	if (!(sh)) {
		printk(KERN_ERR "Unable to allocate struct scsi_host\n");
		return -ENODEV;
	}
	tl_hba->sh = sh;

	/*
	 * Assign the struct tcm_loop_hba pointer to struct Scsi_Host->hostdata
	 */
	sh->hostdata[0] = (unsigned long)tl_hba;
	/*
	 * Setup single ID, Channel and LUN for now..
	 */
	sh->max_id = 2;
	sh->max_lun = 0;
	sh->max_channel = 0;
	sh->max_cmd_len = TL_SCSI_MAX_CMD_LEN;

	error = scsi_add_host(sh, &tl_hba->dev);
	if (error) {
		printk(KERN_ERR "%s: scsi_add_host failed\n", __func__);
		scsi_host_put(sh);
		return -ENODEV;
	}
	return 0;
}

static int tcm_loop_driver_remove(struct device *dev)
{
	struct tcm_loop_hba *tl_hba;
	struct Scsi_Host *sh;

	tl_hba = to_tcm_loop_hba(dev);
	sh = tl_hba->sh;

	scsi_remove_host(sh);
	scsi_host_put(sh);
	return 0;
}

static void tcm_loop_release_adapter(struct device *dev)
{
	struct tcm_loop_hba *tl_hba = to_tcm_loop_hba(dev);

	kfree(tl_hba->tl_hba_qobj);
	kfree(tl_hba);
}

/*
 * Called from tcm_loop_make_scsi_hba() in tcm_loop_configfs.c
 */
int tcm_loop_setup_hba_bus(struct tcm_loop_hba *tl_hba, int tcm_loop_host_id)
{
	int ret;

	tl_hba->dev.bus = &tcm_loop_lld_bus;
	tl_hba->dev.parent = &tcm_loop_primary;
	tl_hba->dev.release = &tcm_loop_release_adapter;
	dev_set_name(&tl_hba->dev, "tcm_loop_adapter_%d", tcm_loop_host_id);

	ret = device_register(&tl_hba->dev);
	if (ret) {
		printk(KERN_ERR "device_register() failed for"
				" tl_hba->dev: %d\n", ret);
		return -ENODEV;
	}

	return 0;
}

/*
 * Called from tcm_loop_fabric_init() in tcl_loop_fabric.c to load the emulated
 * tcm_loop SCSI bus.
 */
int tcm_loop_alloc_core_bus(void)
{
	int ret;

	ret = device_register(&tcm_loop_primary);
	if (ret) {
		printk(KERN_ERR "device_register() failed for"
				" tcm_loop_primary\n");
		return ret;
	}
	
	ret = bus_register(&tcm_loop_lld_bus);
	if (ret) {
		printk(KERN_ERR "bus_register() failed for tcm_loop_lld_bus\n");
		goto dev_unreg;
	}

	ret = driver_register(&tcm_loop_driverfs);
	if (ret) {
		printk(KERN_ERR "driver_register() failed for"
				"tcm_loop_driverfs\n");
		goto bus_unreg;
	}

	printk(KERN_INFO "Initialized TCM Loop Core Bus\n");
	return ret;

bus_unreg:
	bus_unregister(&tcm_loop_lld_bus);
dev_unreg:
	device_unregister(&tcm_loop_primary);
	return ret;
}

void tcm_loop_release_core_bus(void)
{
	driver_unregister(&tcm_loop_driverfs);
	bus_unregister(&tcm_loop_lld_bus);
	device_unregister(&tcm_loop_primary);

	printk(KERN_INFO "Releasing TCM Loop Core BUS\n");
}
