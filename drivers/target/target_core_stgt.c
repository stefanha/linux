/*******************************************************************************
 * Filename:  target_core_stgt.c
 *
 * This file contains the generic target mode <-> Linux SCSI subsystem plugin.
 *
 * Copyright (c) 2009,2010 Rising Tide Systems
 * Copyright (c) 2009,2010 Linux-iSCSI.org
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

#include <linux/string.h>
#include <linux/parser.h>
#include <linux/timer.h>
#include <linux/blkdev.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/genhd.h>
#include <linux/cdrom.h>
#include <linux/file.h>
#include <scsi/scsi.h>
#include <scsi/scsi_device.h>
#include <scsi/scsi_cmnd.h>
#include <scsi/scsi_host.h>
#include <scsi/scsi_tcq.h>
#include <scsi/scsi_tgt.h>

#include <target/target_core_base.h>
#include <target/target_core_device.h>
#include <target/target_core_transport.h>

#include "target_core_stgt.h"

#define to_stgt_hba(d)	container_of(d, struct stgt_hba, dev)

static int stgt_host_no_cnt;
static struct se_subsystem_api stgt_template ;

static int stgt_transfer_response(struct scsi_cmnd *,
                           void (*done)(struct scsi_cmnd *));

#define ISPRINT(a)  ((a >= ' ') && (a <= '~'))

static int pseudo_lld_bus_match(struct device *dev,
				struct device_driver *dev_driver)
{
	return 1;
}

static int stgt_lld_probe(struct device *);
static int stgt_lld_remove(struct device *);

static struct bus_type stgt_lld_bus = {
	.name		= "stgt_bus",
	.match		= pseudo_lld_bus_match,
	.probe		= stgt_lld_probe,
	.remove		= stgt_lld_remove,
};

static struct device_driver stgt_driverfs_driver = {
	.name		= STGT_NAME,
	.bus		= &stgt_lld_bus,
};

static void stgt_primary_release(struct device *dev)
{
	return;
}

static struct device stgt_primary = {
	.init_name	= "stgt_primary_0",
	.release	= stgt_primary_release,
};

static struct scsi_host_template stgt_driver_template = {
	.name		= STGT_NAME,
	.module		= THIS_MODULE,
	.can_queue	= 1,
	.sg_tablesize	= SG_ALL,
	.use_clustering	= DISABLE_CLUSTERING,
	.max_sectors	= SCSI_DEFAULT_MAX_SECTORS,
	.transfer_response = stgt_transfer_response,
	.eh_abort_handler = NULL,
	.shost_attrs	= NULL,
	.proc_name	= STGT_NAME,
	.supported_mode	= MODE_TARGET,
};

static void stgt_release_adapter(struct device *dev)
{
	struct stgt_hba *stgt_hba;

	stgt_hba = to_stgt_hba(dev);
	kfree(stgt_hba);
}

/*	stgt_attach_hba():
 *
 */
static int stgt_attach_hba(struct se_hba *hba, u32 host_id)
{
	struct stgt_hba *stgt_hba;
	int err;

	stgt_hba = kzalloc(sizeof(struct stgt_hba), GFP_KERNEL);
	if (!stgt_hba) {
		pr_err("Unable to allocate struct stgt_hba\n");
		return -ENOMEM;
	}
	stgt_hba->se_hba = hba;

	stgt_hba->dev.bus = &stgt_lld_bus;
	stgt_hba->dev.parent = &stgt_primary;
	stgt_hba->dev.release = &stgt_release_adapter;
	dev_set_name(&stgt_hba->dev, "stgt_adapter%d", stgt_host_no_cnt);

	err = device_register(&stgt_hba->dev);
	if (err) {
		pr_err("device_register() for stgt_hba failed:"
				" %d\n", err);
		return err;
	}
	stgt_host_no_cnt++;

	return 0;
}


static int stgt_lld_probe(struct device *dev)
{
	struct se_hba *hba;
	struct stgt_hba *stgt_hba;
	struct Scsi_Host *sh;
	int hba_depth, max_sectors, err;

	stgt_hba = to_stgt_hba(dev);

	sh = scsi_host_alloc(&stgt_driver_template, sizeof(stgt_hba));
	if (!sh) {
		pr_err("scsi_host_alloc() failed\n");
		return -ENOMEM;
	}
	hba = stgt_hba->se_hba;
	stgt_hba->scsi_host = sh;

	sh->max_id = 10;
	sh->max_lun = 10;

	/*
	 * Assign the struct stgt_hba pointer to struct Scsi_Host->hostdata..
	 */
	*(struct stgt_hba **)&sh->hostdata = stgt_hba;

	err = scsi_add_host(sh, &stgt_hba->dev);
	if (err) {
		pr_err("scsi_add_host() failed with err: %d\n", err);
		return err;
	}

	max_sectors = sh->max_sectors;
	/*
	 * Usually the SCSI LLD will use the hostt->can_queue value to define
	 * its HBA TCQ depth.  Some other drivers (like 2.6 megaraid) don't set
	 * this at all and set sh->can_queue at runtime.
	 */
	hba_depth = (sh->hostt->can_queue > sh->can_queue) ?
		sh->hostt->can_queue : sh->can_queue;

	hba->hba_ptr = sh;

	pr_debug("CORE_HBA[%d] - TCM STGT HBA Driver %s on"
		" Generic Target Core Stack %s\n", hba->hba_id,
		STGT_VERSION, TARGET_CORE_MOD_VERSION);
	pr_debug("CORE_HBA[%d] - %s\n", hba->hba_id, (sh->hostt->name) ?
			(sh->hostt->name) : "Unknown");
	pr_debug("CORE_HBA[%d] - Attached STGT HBA to Generic"
		" MaxSectors: %hu\n",
		hba->hba_id, max_sectors);

	return 0;
}

static int stgt_lld_remove(struct device *dev)
{
	struct stgt_hba *stgt_hba;
	struct Scsi_Host *sh;

	stgt_hba = to_stgt_hba(dev);
	sh = stgt_hba->scsi_host;

	scsi_remove_host(sh);
	scsi_host_put(sh);

	return 0;
}

static void stgt_detach_hba(struct se_hba *hba)
{
	struct Scsi_Host *scsi_host = hba->hba_ptr;
	struct stgt_hba *stgt_hba = *(struct stgt_hba **)shost_priv(scsi_host);

	pr_debug("CORE_HBA[%d] - Detached STGT HBA: %s from"
		" Generic Target Core\n", hba->hba_id,
		(scsi_host->hostt->name) ? (scsi_host->hostt->name) :
		"Unknown");

	device_unregister(&stgt_hba->dev);
	hba->hba_ptr = NULL;
}

static void *stgt_allocate_virtdevice(struct se_hba *hba, const char *name)
{
	struct stgt_dev_virt *sdv;

	sdv = kzalloc(sizeof(struct stgt_dev_virt), GFP_KERNEL);
	if (!sdv) {
		pr_err("Unable to allocate memory for struct stgt_dev_virt\n");
		return NULL;
	}
	sdv->sdv_se_hba = hba;

	pr_debug("STGT: Allocated sdv: %p for %s\n", sdv, name);
	return sdv;
}

#warning FIXME: implement stgt_create_virtdevice()
static struct se_device *stgt_create_virtdevice(
	struct se_hba *hba,
	struct se_subsystem_dev *se_dev,
	void *p)
{
	struct stgt_dev_virt *sdv = p;
	struct Scsi_Host *sh = hba->hba_ptr;

	if (!sdv) {
		pr_err("Unable to locate struct stgt_dev_virt"
				" parameter\n");
		return NULL;
	}

	pr_err("Unable to locate %d:%d:%d:%d\n", sh->host_no,
		sdv->sdv_channel_id,  sdv->sdv_target_id, sdv->sdv_lun_id);

	return NULL;
}

/*	stgt_free_device(): (Part of se_subsystem_api_t template)
 *
 *
 */
static void stgt_free_device(void *p)
{
	struct stgt_dev_virt *sdv = p;
	struct scsi_device *sd = sdv->sdv_sd;

	if (sdv->sdv_bd)
		sdv->sdv_bd = NULL;

	if (sd) {
		if ((sd->type == TYPE_DISK) || (sd->type == TYPE_ROM))
			scsi_device_put(sd);

		sdv->sdv_sd = NULL;
	}

	kfree(sdv);
}

static inline struct stgt_plugin_task *STGT_TASK(struct se_task *task)
{
	return container_of(task, struct stgt_plugin_task, stgt_task);
}


/*	pscsi_transport_complete():
 *
 *
 */
static int stgt_transport_complete(struct se_task *task)
{
	struct stgt_plugin_task *st = STGT_TASK(task);
	int result;

	result = st->stgt_result;
	if (status_byte(result) & CHECK_CONDITION)
		return 1;

	return 0;
}

static struct se_task *
stgt_alloc_task(unsigned char *cdb)
{
	struct stgt_plugin_task *st;

	st = kzalloc(sizeof(struct stgt_plugin_task), GFP_KERNEL);
	if (!st) {
		pr_err("Unable to allocate struct stgt_plugin_task\n");
		return NULL;
	}

	return &st->stgt_task;
}

/*      stgt_do_task(): (Part of se_subsystem_api_t template)
 *
 *
 */
static int stgt_do_task(struct se_task *task)
{
	struct se_cmd *cmd = task->task_se_cmd;
	struct stgt_plugin_task *st = STGT_TASK(task);
	struct Scsi_Host *sh = task->task_se_cmd->se_dev->se_hba->hba_ptr;
	struct scsi_cmnd *sc;
	int tag = MSG_SIMPLE_TAG;

	sc = scsi_host_get_command(sh, task->task_data_direction,
				   GFP_KERNEL);
	if (!sc) {
		pr_err("Unable to allocate memory for struct"
			" scsi_cmnd\n");
		cmd->scsi_sense_reason = TCM_LOGICAL_UNIT_COMMUNICATION_FAILURE;
		return -ENOMEM;
	}

	target_get_task_cdb(task, st->stgt_cdb);
	memcpy(sc->cmnd, st->stgt_cdb, MAX_COMMAND_SIZE);
	sc->sdb.length = task->task_size;
	sc->sdb.table.sgl = task->task_sg;
	sc->tag = tag;

	BUG();
#warning FIXME: Get struct scsi_lun for scsi_tgt_queue_command()
#if 0
	err = scsi_tgt_queue_command(sc, itn_id, (struct scsi_lun *)&cmd->lun,
			cmd->tag);
	if (err) {
		pr_debug("scsi_tgt_queue_command() failed for sc:"
			" %p\n", sc);
		scsi_host_put_command(sh, sc);
	}
#endif
	return 0;
}

/*	stgt_free_task(): (Part of se_subsystem_api_t template)
 *
 *
 */
static void stgt_free_task(struct se_task *task)
{
	struct stgt_plugin_task *st = STGT_TASK(task);

	kfree(st);
}

enum {
	Opt_scsi_channel_id, Opt_scsi_target_id, Opt_scsi_lun_id, Opt_err
};

static match_table_t tokens = {
	{Opt_scsi_channel_id, "scsi_channel_id=%d"},
	{Opt_scsi_target_id, "scsi_target_id=%d"},
	{Opt_scsi_lun_id, "scsi_lun_id=%d"},
	{Opt_err, NULL}
};

static ssize_t stgt_set_configfs_dev_params(struct se_hba *hba,
	struct se_subsystem_dev *se_dev,
	const char *page,
	ssize_t count)
{
	struct stgt_dev_virt *sdv = se_dev->se_dev_su_ptr;
	struct Scsi_Host *sh = hba->hba_ptr;
	char *orig, *ptr, *opts;
	substring_t args[MAX_OPT_ARGS];
	int ret = 0, arg, token;

	opts = kstrdup(page, GFP_KERNEL);
	if (!opts)
		return -ENOMEM;

	orig = opts;

	while ((ptr = strsep(&opts, ",")) != NULL) {
		if (!*ptr)
			continue;

		token = match_token(ptr, tokens, args);
		switch (token) {
		case Opt_scsi_channel_id:
			match_int(args, &arg);
			sdv->sdv_channel_id = arg;
			pr_debug("STGT[%d]: Referencing SCSI Channel"
				" ID: %d\n",  sh->host_no, sdv->sdv_channel_id);
			sdv->sdv_flags |= PDF_HAS_CHANNEL_ID;
			break;
		case Opt_scsi_target_id:
			match_int(args, &arg);
			sdv->sdv_target_id = arg;
			pr_debug("STGT[%d]: Referencing SCSI Target"
				" ID: %d\n", sh->host_no, sdv->sdv_target_id);
			sdv->sdv_flags |= PDF_HAS_TARGET_ID;
			break;
		case Opt_scsi_lun_id:
			match_int(args, &arg);
			sdv->sdv_lun_id = arg;
			pr_debug("STGT[%d]: Referencing SCSI LUN ID:"
				" %d\n", sh->host_no, sdv->sdv_lun_id);
			sdv->sdv_flags |= PDF_HAS_LUN_ID;
			break;
		default:
			break;
		}
	}

	kfree(orig);
	return (!ret) ? count : ret;
}

static ssize_t stgt_check_configfs_dev_params(
	struct se_hba *hba,
	struct se_subsystem_dev *se_dev)
{
	struct stgt_dev_virt *sdv = se_dev->se_dev_su_ptr;

	if (!(sdv->sdv_flags & PDF_HAS_CHANNEL_ID) ||
	    !(sdv->sdv_flags & PDF_HAS_TARGET_ID) ||
	    !(sdv->sdv_flags & PDF_HAS_TARGET_ID)) {
		pr_err("Missing scsi_channel_id=, scsi_target_id= and"
			" scsi_lun_id= parameters\n");
		return -1;
	}

	return 0;
}

static ssize_t stgt_show_configfs_dev_params(
	struct se_hba *hba,
	struct se_subsystem_dev *se_dev,
	char *b)
{
	struct stgt_dev_virt *sdv = se_dev->se_dev_su_ptr;
	ssize_t bl = 0;

	bl = sprintf(b + bl, "STGT SCSI Device Bus Location:"
		" Channel ID: %d Target ID: %d LUN: %d\n",
		sdv->sdv_channel_id, sdv->sdv_target_id, sdv->sdv_lun_id);

	return bl;
}

/*	stgt_get_sense_buffer():
 *
 *
 */
static unsigned char *stgt_get_sense_buffer(struct se_task *task)
{
	struct stgt_plugin_task *pt = STGT_TASK(task);

	return (unsigned char *)&pt->stgt_sense[0];
}

/*	stgt_get_device_rev():
 *
 *
 */
static u32 stgt_get_device_rev(struct se_device *dev)
{
	struct stgt_dev_virt *sdv = dev->dev_ptr;
	struct scsi_device *sd = sdv->sdv_sd;

	return (sd->scsi_level - 1) ? sd->scsi_level - 1 : 1;
}

/*	stgt_get_device_type():
 *
 *
 */
static u32 stgt_get_device_type(struct se_device *dev)
{
	struct stgt_dev_virt *sdv = dev->dev_ptr;
	struct scsi_device *sd = sdv->sdv_sd;

	return sd->type;
}

/*	stgt_handle_SAM_STATUS_failures():
 *
 *
 */
static inline void stgt_process_SAM_status(
	struct se_task *task,
	struct stgt_plugin_task *st)
{
	task->task_scsi_status = status_byte(st->stgt_result);
	if (task->task_scsi_status) {
		task->task_scsi_status <<= 1;
		pr_debug("PSCSI Status Byte exception at task: %p CDB:"
			" 0x%02x Result: 0x%08x\n", task, st->stgt_cdb[0],
			st->stgt_result);
	}

	switch (host_byte(st->stgt_result)) {
	case DID_OK:
		transport_complete_task(task, (!task->task_scsi_status));
		break;
	default:
		pr_debug("PSCSI Host Byte exception at task: %p CDB:"
			" 0x%02x Result: 0x%08x\n", task, st->stgt_cdb[0],
			st->stgt_result);
		task->task_scsi_status = SAM_STAT_CHECK_CONDITION;
		task->task_se_cmd->scsi_sense_reason =
					TCM_UNSUPPORTED_SCSI_OPCODE;
		transport_complete_task(task, 0);
		break;
	}

	return;
}

/*
 * Use for struct scsi_host_template->transfer_response() function pointer
 * that is called from STGT in drivers/scsi/scsi_tgt_lib.c:
 * scsi_tgt_transfer_response()
 */
static int stgt_transfer_response(struct scsi_cmnd *sc,
			   void (*done)(struct scsi_cmnd *))
{
	struct se_task *task = (struct se_task *)sc->SCp.ptr;
	struct stgt_plugin_task *st = STGT_TASK(task);

	if (!task) {
		pr_err("struct se_task is NULL!\n");
		BUG();
	}
	if (!st) {
		pr_err("struct stgt_plugin_task is NULL!\n");
		BUG();
	}
	st->stgt_result = sc->request->errors;
	st->stgt_resid = sc->request->resid_len;

#warning FIXME: Sense for STGT struct scsi_cmnd usage..
#if 0
	memcpy(st->stgt_sense, sense, SCSI_SENSE_BUFFERSIZE);
#endif
	stgt_process_SAM_status(task, st);
	done(sc);
	return 0;
}

static struct se_subsystem_api stgt_template = {
	.name			= "stgt",
	.owner			= THIS_MODULE,
	.transport_type		= TRANSPORT_PLUGIN_VHBA_PDEV,
	.attach_hba		= stgt_attach_hba,
	.detach_hba		= stgt_detach_hba,
	.allocate_virtdevice	= stgt_allocate_virtdevice,
	.create_virtdevice	= stgt_create_virtdevice,
	.free_device		= stgt_free_device,
	.transport_complete	= stgt_transport_complete,
	.alloc_task		= stgt_alloc_task,
	.do_task		= stgt_do_task,
	.free_task		= stgt_free_task,
	.check_configfs_dev_params = stgt_check_configfs_dev_params,
	.set_configfs_dev_params = stgt_set_configfs_dev_params,
	.show_configfs_dev_params = stgt_show_configfs_dev_params,
	.get_sense_buffer	= stgt_get_sense_buffer,
	.get_device_rev		= stgt_get_device_rev,
	.get_device_type	= stgt_get_device_type,
};

static int __init stgt_module_init(void)
{
	int ret;

	ret = device_register(&stgt_primary);
	if (ret) {
		pr_err("device_register() failed for stgt_primary\n");
		return ret;
	}

	ret = bus_register(&stgt_lld_bus);
	if (ret) {
		pr_err("bus_register() failed for stgt_ldd_bus\n");
		goto out_unregister_device;
	}

	ret = driver_register(&stgt_driverfs_driver);
	if (ret) {
		pr_err("driver_register() failed for"
			" stgt_driverfs_driver\n");
		goto out_unregister_bus;
	}

	ret = transport_subsystem_register(&stgt_template);
	if (ret)
		goto out_unregister_driver;

	return 0;
out_unregister_driver:
	driver_unregister(&stgt_driverfs_driver);
out_unregister_bus:
	bus_unregister(&stgt_lld_bus);
out_unregister_device:
	device_unregister(&stgt_primary);
	return ret;
}

static void stgt_module_exit(void)
{
	transport_subsystem_release(&stgt_template);

	driver_unregister(&stgt_driverfs_driver);
	bus_unregister(&stgt_lld_bus);
	device_unregister(&stgt_primary);
}

MODULE_DESCRIPTION("TCM STGT subsystem plugin");
MODULE_AUTHOR("nab@Linux-iSCSI.org");
MODULE_LICENSE("GPL");

module_init(stgt_module_init);
module_exit(stgt_module_exit);
