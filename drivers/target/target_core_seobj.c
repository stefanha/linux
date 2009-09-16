/*******************************************************************************
 * Filename:  target_core_seobj.c
 *
 * Copyright (c) 2006-2007 SBE, Inc.  All Rights Reserved.
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


#define TARGET_CORE_SEOBJ_C

#include <linux/string.h>
#include <linux/timer.h>
#include <linux/slab.h>
#include <linux/blkdev.h>
#include <linux/spinlock.h>
#include <linux/smp_lock.h>
#include <linux/in.h>
#include <scsi/scsi.h>

#include <target/target_core_base.h>
#include <target/target_core_device.h>
#include <target/target_core_hba.h>
#include <target/target_core_tpg.h>
#include <target/target_core_transport.h>
#include <target/target_core_plugin.h>
#include <target/target_core_seobj.h>
#include <target/target_core_fabric_ops.h>
#include <target/target_core_configfs.h>

#undef TARGET_CORE_SEOBJ_C

#define MAKE_OBJ_TYPE(type, op1, op2)			\
void type##_obj_##op1##_count(struct se_obj_s *obj)	\
{							\
	atomic_##op2(&obj->obj_access_count);		\
}

#define MAKE_OBJ_TYPE_RET(type)				\
int type##_obj_check_count(struct se_obj_s *obj)	\
{							\
	return atomic_read(&obj->obj_access_count);	\
}

MAKE_OBJ_TYPE(dev, inc, inc);
MAKE_OBJ_TYPE(dev, dec, dec);
MAKE_OBJ_TYPE_RET(dev);

void dev_obj_get_obj_info(
	void *p,
	se_lun_t *lun,
	unsigned long long bytes,
	int state,
	char *b,
	int *bl)
{
	se_device_t *dev = (se_device_t *)p;

	if (state)
		transport_dump_dev_state(dev, b, bl);
	transport_dump_dev_info((se_device_t *)p, lun, bytes, b, bl);
}

void dev_obj_get_plugin_info(void *p, char *b, int *bl)
{
	*bl += sprintf(b + *bl, "TCM Device Object Plugin %s\n",
			DEV_OBJ_VERSION);
}

void *dev_obj_get_obj(void *p)
{
	return p;
}

se_queue_obj_t *dev_obj_get_queue_obj(void *p)
{
	se_device_t *dev  = (se_device_t *)p;

	return dev->dev_queue_obj;
}

int dev_obj_claim_obj(void *p)
{
	return transport_generic_claim_phydevice((se_device_t *)p);
}

void dev_obj_release_obj(void *p)
{
	transport_generic_release_phydevice((se_device_t *)p, 1);
}

void dev_access_obj(void *p)
{
	se_device_t *dev  = (se_device_t *)p;

	DEV_OBJ_API(dev)->inc_count(&dev->dev_access_obj);
}

void dev_deaccess_obj(void *p)
{
	se_device_t *dev  = (se_device_t *)p;

	DEV_OBJ_API(dev)->dec_count(&dev->dev_access_obj);
}

void dev_put_obj(void *p)
{
	se_device_t *dev  = (se_device_t *)p;

	core_put_hba(dev->se_hba);
}

int dev_obj_export(void *p, se_portal_group_t *tpg, se_lun_t *lun)
{
	se_device_t *dev  = (se_device_t *)p;
	se_port_t *port;

	port = core_alloc_port(dev);
	if (!(port))
		return -1;

	lun->se_dev = dev;
	if (DEV_OBJ_API(dev)->activate(p) < 0) {
		lun->se_dev = NULL;
		kfree(port);
		return -1;
	}

	DEV_OBJ_API(dev)->inc_count(&dev->dev_export_obj);

	core_export_port(dev, tpg, port, lun);
	return 0;
}

void dev_obj_unexport(void *p, se_portal_group_t *tpg, se_lun_t *lun)
{
	se_device_t *dev  = (se_device_t *)p;
	se_port_t *port = lun->lun_sep;

	spin_lock(&dev->se_port_lock);
	spin_lock(&lun->lun_sep_lock);
	if (lun->lun_type_ptr == NULL) {
		spin_unlock(&dev->se_port_lock);
		spin_unlock(&lun->lun_sep_lock);
		return;
	}
	spin_unlock(&lun->lun_sep_lock);

	DEV_OBJ_API(dev)->dec_count(&dev->dev_export_obj);

	core_release_port(dev, port);
	spin_unlock(&dev->se_port_lock);

	DEV_OBJ_API(dev)->deactivate(p);
	lun->se_dev = NULL;
}

int dev_obj_transport_setup_cmd(void *p, se_cmd_t *cmd)
{
	transport_device_setup_cmd(cmd);
	return 0;
}

int dev_obj_active_tasks(void *p)
{
	se_device_t *dev  = (se_device_t *)p;

	return atomic_read(&dev->execute_tasks);
}

int dev_obj_add_tasks(void *p, se_cmd_t *cmd)
{
	transport_add_tasks_from_cmd(cmd);
	return 0;
}

int dev_obj_execute_tasks(void *p)
{
	se_device_t *dev  = (se_device_t *)p;

	__transport_execute_tasks(dev);
	return 0;
}

int dev_obj_depth_left(void *p)
{
	se_device_t *dev  = (se_device_t *)p;

	return atomic_read(&dev->depth_left);
}

int dev_obj_queue_depth(void *p)
{
	se_device_t *dev  = (se_device_t *)p;

	return dev->queue_depth;
}

int dev_obj_blocksize(void *p)
{
	se_device_t *dev  = (se_device_t *)p;

	return DEV_ATTRIB(dev)->block_size;
}

int dev_obj_max_sectors(void *p)
{
	se_device_t *dev  = (se_device_t *)p;

	if (TRANSPORT(dev)->transport_type == TRANSPORT_PLUGIN_PHBA_PDEV) {
		return (DEV_ATTRIB(dev)->max_sectors >
			TRANSPORT(dev)->get_max_sectors(dev) ?
			TRANSPORT(dev)->get_max_sectors(dev) :
			DEV_ATTRIB(dev)->max_sectors);
	} else
		return DEV_ATTRIB(dev)->max_sectors;
}

unsigned long long dev_obj_end_lba(void *p, int zero_lba)
{
	se_device_t *dev  = (se_device_t *)p;

	 return dev->dev_sectors_total + ((zero_lba) ? 1 : 0);
}

unsigned long long dev_obj_get_next_lba(void *p, unsigned long long lba)
{
	return lba;
}

unsigned long long dev_obj_total_sectors(void *p)
{
	se_device_t *dev  = (se_device_t *)p;

	return  dev->dev_sectors_total + 1;
}

int dev_obj_do_se_mem_map(
	void *p,
	se_task_t *task,
	struct list_head *se_mem_list,
	void *in_mem,
	se_mem_t *in_se_mem,
	se_mem_t **out_se_mem,
	u32 *se_mem_cnt,
	u32 *task_offset)
{
	se_device_t *dev  = (se_device_t *)p;
	u32 tmp_task_offset = *task_offset;
	int ret = 0;

	/*
	 * se_subsystem_api_t->do_se_mem_map is used when internal allocation
	 * has been done by the transport plugin.
	 */
	if (TRANSPORT(dev)->do_se_mem_map) {
		ret = TRANSPORT(dev)->do_se_mem_map(task, se_mem_list,
				in_mem, in_se_mem, out_se_mem, se_mem_cnt,
				task_offset);
		if (ret == 0)
			T_TASK(task->task_se_cmd)->t_task_se_num += *se_mem_cnt;

		return ret;
	}

	/*
	 * Assume default that transport plugin speaks preallocated
	 * scatterlists.
	 */
	if (!(transport_calc_sg_num(task, in_se_mem, tmp_task_offset)))
		return -1;

	/*
	 * se_task_t->task_sg now contains the struct scatterlist array.
	 */
	return transport_map_mem_to_sg(task, se_mem_list, task->task_sg,
		in_se_mem, out_se_mem, se_mem_cnt, task_offset);
}

int dev_obj_get_mem_buf(void *p, se_cmd_t *cmd)
{
	se_device_t *dev  = (se_device_t *)p;

	cmd->transport_allocate_resources = (TRANSPORT(dev)->allocate_buf) ?
		TRANSPORT(dev)->allocate_buf : &transport_generic_allocate_buf;
	cmd->transport_free_resources = (TRANSPORT(dev)->free_buf) ?
		TRANSPORT(dev)->free_buf : NULL;

	return 0;
}

int dev_obj_get_mem_SG(void *p, se_cmd_t *cmd)
{
	se_device_t *dev  = (se_device_t *)p;

	cmd->transport_allocate_resources = (TRANSPORT(dev)->allocate_DMA) ?
		TRANSPORT(dev)->allocate_DMA : &transport_generic_get_mem;
	cmd->transport_free_resources = (TRANSPORT(dev)->free_DMA) ?
		TRANSPORT(dev)->free_DMA : NULL;

	return 0;
}

map_func_t dev_obj_get_map_SG(void *p, int rw)
{
	se_device_t *dev  = (se_device_t *)p;

	return (rw == SE_DIRECTION_WRITE) ? dev->transport->spc->write_SG :
		dev->transport->spc->read_SG;
}

map_func_t dev_obj_get_map_non_SG(void *p, int rw)
{
	se_device_t *dev  = (se_device_t *)p;

	return (rw == SE_DIRECTION_WRITE) ? dev->transport->spc->write_non_SG :
		dev->transport->spc->read_non_SG;
}

map_func_t dev_obj_get_map_none(void *p)
{
	se_device_t *dev  = (se_device_t *)p;

	return dev->transport->spc->none;
}

void *dev_obj_get_transport_req(void *p, se_task_t *task)
{
	se_device_t *dev  = (se_device_t *)p;

	task->se_dev = dev;

	return dev->transport->allocate_request(task, dev);
}

void dev_obj_free_tasks(void *p, se_cmd_t *cmd)
{
	transport_free_dev_tasks(cmd);
}

int dev_obj_activate(void *p)
{
	se_device_t *dev  = (se_device_t *)p;

	se_dev_start(dev);
	return 0;
}

void dev_obj_deactivate(void *p)
{
	se_device_t *dev  = (se_device_t *)p;

	se_dev_stop(dev);
}

void dev_obj_notify_obj(void *p)
{
	se_device_t *dev  = (se_device_t *)p;

	wake_up_interruptible(&dev->dev_queue_obj->thread_wq);
}

int dev_obj_check_online(void *p)
{
	se_device_t *dev  = (se_device_t *)p;
	int ret;

	spin_lock(&dev->dev_status_lock);
	ret = ((dev->dev_status & TRANSPORT_DEVICE_ACTIVATED) ||
	       (dev->dev_status & TRANSPORT_DEVICE_DEACTIVATED)) ? 0 : 1;
	spin_unlock(&dev->dev_status_lock);

	return ret;
}

int dev_obj_check_shutdown(void *p)
{
	se_device_t *dev  = (se_device_t *)p;
	int ret;

	spin_lock(&dev->dev_status_lock);
	ret = (dev->dev_status & TRANSPORT_DEVICE_SHUTDOWN);
	spin_unlock(&dev->dev_status_lock);

	return ret;
}

void dev_obj_signal_shutdown(void *p)
{
	se_device_t *dev  = (se_device_t *)p;

	spin_lock(&dev->dev_status_lock);
	if ((dev->dev_status & TRANSPORT_DEVICE_ACTIVATED) ||
	    (dev->dev_status & TRANSPORT_DEVICE_DEACTIVATED) ||
	    (dev->dev_status & TRANSPORT_DEVICE_OFFLINE_ACTIVATED) ||
	    (dev->dev_status & TRANSPORT_DEVICE_OFFLINE_DEACTIVATED)) {
		dev->dev_status |= TRANSPORT_DEVICE_SHUTDOWN;
		dev->dev_status &= ~TRANSPORT_DEVICE_ACTIVATED;
		dev->dev_status &= ~TRANSPORT_DEVICE_DEACTIVATED;
		dev->dev_status &= ~TRANSPORT_DEVICE_OFFLINE_ACTIVATED;
		dev->dev_status &= ~TRANSPORT_DEVICE_OFFLINE_DEACTIVATED;

		wake_up_interruptible(&dev->dev_queue_obj->thread_wq);
	}
	spin_unlock(&dev->dev_status_lock);
}

void dev_obj_clear_shutdown(void *p)
{
	se_device_t *dev  = (se_device_t *)p;

	spin_lock(&dev->dev_status_lock);
	if (dev->dev_status & TRANSPORT_DEVICE_SHUTDOWN) {
		dev->dev_status &= ~TRANSPORT_DEVICE_SHUTDOWN;
		dev->dev_status |= TRANSPORT_DEVICE_DEACTIVATED;
	}
	spin_unlock(&dev->dev_status_lock);
}

unsigned char *dev_obj_get_cdb(
	void *p,
	se_task_t *task)
{
	se_device_t *dev  = (se_device_t *)p;

	return dev->transport->get_cdb(task);
}

int dev_obj_start(
	void *p,
	se_transform_info_t *ti,
	unsigned long long starting_lba)
{
	se_device_t *dev  = (se_device_t *)p;

	return transport_generic_obj_start(ti, DEV_OBJ_API(dev),
		p, starting_lba);
}

u32 dev_obj_get_cdb_count(
	void *p,
	se_transform_info_t *ti,
	unsigned long long lba,
	u32 sectors,
	se_mem_t *se_mem_in,
	se_mem_t **se_mem_out,
	u32 *task_offset_in)
{
	se_device_t *dev  = (se_device_t *)p;

	ti->ti_dev = dev;
	return transport_generic_get_cdb_count(ti->ti_se_cmd, ti,
		DEV_OBJ_API(dev), p, lba, sectors, se_mem_in, se_mem_out,
		task_offset_in);
}

u32 dev_obj_get_cdb_size(
	void *p,
	u32 sectors,
	unsigned char *cdb)
{
	se_device_t *dev  = (se_device_t *)p;

	if (TRANSPORT(dev)->get_device_type(dev) == TYPE_TAPE) {
		if (cdb[1] & 1) { /* sectors */
			return DEV_ATTRIB(dev)->block_size * sectors;
		} else /* bytes */
			return sectors;
	}

	/* sectors */
#if 0
	printk(KERN_INFO "Returning block_size: %u, sectors: %u == %u for"
			" %s object\n", DEV_ATTRIB(dev)->block_size, sectors,
			DEV_ATTRIB(dev)->block_size * sectors,
			TRANSPORT(dev)->name);
#endif
	return DEV_ATTRIB(dev)->block_size * sectors;
}

void dev_obj_generate_cdb(
	void *p,
	unsigned long long lba,
	u32 *sectors,
	unsigned char *cdb,
	int rw)
{
	se_device_t *dev = (se_device_t *)p;

	dev->dev_generate_cdb(lba, sectors, cdb, rw);
}

int dev_obj_get_device_access(void *p)
{
	se_device_t *dev = (se_device_t *)p;

	return (dev->dev_flags & DF_READ_ONLY) ? 0 : 1;
}

int dev_obj_get_device_type(void *p)
{
	se_device_t *dev = (se_device_t *)p;

	return TRANSPORT(dev)->get_device_type(dev);
}

int dev_obj_check_DMA_handler(void *p)
{
	se_device_t *dev = (se_device_t *)p;

	if (!dev->transport) {
		printk(KERN_ERR "se_device_t->transport is NULL!\n");
		BUG();
	}

	return (TRANSPORT(dev)->allocate_DMA != NULL);
}

t10_wwn_t *dev_obj_get_t10_wwn(void *p)
{
	se_device_t *dev = (se_device_t *)p;

	return DEV_T10_WWN(dev);
}

int dev_obj_get_task_timeout(void *p)
{
	se_device_t *dev = (se_device_t *)p;

	return DEV_ATTRIB(dev)->task_timeout;
}

int dev_add_obj_to_lun(se_portal_group_t *tpg, se_lun_t *lun)
{
	return 0;
}

int dev_del_obj_from_lun(se_portal_group_t *tpg, se_lun_t *lun)
{
	return core_dev_del_lun(tpg, lun->unpacked_lun);
}

se_obj_lun_type_t *dev_get_next_obj_api(void *p, void **next_p)
{
	se_device_t *dev = (se_device_t *)p;

	*next_p = dev;
	return DEV_OBJ_API(dev);
}

int dev_obtain_obj_lock(void *p)
{
	return 0;
}

int dev_release_obj_lock(void *p)
{
	return 0;
}

se_obj_lun_type_t dev_obj_template = {
	.se_obj_type		= TRANSPORT_LUN_TYPE_DEVICE,
	.get_obj_info		= dev_obj_get_obj_info,
	.get_plugin_info	= dev_obj_get_plugin_info,
	.get_obj		= dev_obj_get_obj,
	.get_queue_obj		= dev_obj_get_queue_obj,
	.claim_obj		= dev_obj_claim_obj,
	.release_obj		= dev_obj_release_obj,
	.inc_count		= dev_obj_inc_count,
	.dec_count		= dev_obj_dec_count,
	.check_count		= dev_obj_check_count,
	.access_obj		= dev_access_obj,
	.deaccess_obj		= dev_deaccess_obj,
	.put_obj		= dev_put_obj,
	.export_obj		= dev_obj_export,
	.unexport_obj		= dev_obj_unexport,
	.transport_setup_cmd	= dev_obj_transport_setup_cmd,
	.active_tasks		= dev_obj_active_tasks,
	.add_tasks		= dev_obj_add_tasks,
	.execute_tasks		= dev_obj_execute_tasks,
	.depth_left		= dev_obj_depth_left,
	.queue_depth		= dev_obj_queue_depth,
	.blocksize		= dev_obj_blocksize,
	.max_sectors		= dev_obj_max_sectors,
	.end_lba		= dev_obj_end_lba,
	.get_next_lba		= dev_obj_get_next_lba,
	.total_sectors		= dev_obj_total_sectors,
	.do_se_mem_map		= dev_obj_do_se_mem_map,
	.get_mem_buf		= dev_obj_get_mem_buf,
	.get_mem_SG		= dev_obj_get_mem_SG,
	.get_map_SG		= dev_obj_get_map_SG,
	.get_map_non_SG		= dev_obj_get_map_non_SG,
	.get_map_none		= dev_obj_get_map_none,
	.get_transport_req	= dev_obj_get_transport_req,
	.free_tasks		= dev_obj_free_tasks,
	.activate		= dev_obj_activate,
	.deactivate		= dev_obj_deactivate,
	.notify_obj		= dev_obj_notify_obj,
	.check_online		= dev_obj_check_online,
	.check_shutdown		= dev_obj_check_shutdown,
	.signal_shutdown	= dev_obj_signal_shutdown,
	.clear_shutdown		= dev_obj_clear_shutdown,
	.get_cdb		= dev_obj_get_cdb,
	.obj_start		= dev_obj_start,
	.get_cdb_count		= dev_obj_get_cdb_count,
	.get_cdb_size		= dev_obj_get_cdb_size,
	.generate_cdb		= dev_obj_generate_cdb,
	.get_device_access	= dev_obj_get_device_access,
	.get_device_type	= dev_obj_get_device_type,
	.check_DMA_handler	= dev_obj_check_DMA_handler,
	.get_t10_wwn		= dev_obj_get_t10_wwn,
	.get_task_timeout	= dev_obj_get_task_timeout,
	.add_obj_to_lun		= dev_add_obj_to_lun,
	.del_obj_from_lun	= dev_del_obj_from_lun,
	.get_next_obj_api	= dev_get_next_obj_api,
	.obtain_obj_lock	= dev_obtain_obj_lock,
	.release_obj_lock	= dev_release_obj_lock,
};

se_obj_lun_type_t *se_obj_get_api(u32 plugin_loc)
{
	se_plugin_class_t *pc;
	se_plugin_t *p;

	pc = plugin_get_class(PLUGIN_TYPE_OBJ);
	if (!(pc))
		return NULL;

	spin_lock(&pc->plugin_lock);
	if (plugin_loc > pc->max_plugins) {
		printk(KERN_ERR "Passed plugin_loc: %u exceeds pc->max_plugins:"
			" %d\n", plugin_loc, pc->max_plugins);
		goto out;
	}

	p = &pc->plugin_array[plugin_loc];
	if (!p->plugin_obj) {
		printk(KERN_ERR "Passed plugin_loc: %u does not exist!\n",
				plugin_loc);
		goto out;
	}
	spin_unlock(&pc->plugin_lock);

	return (se_obj_lun_type_t *)p->plugin_obj;
out:
	spin_unlock(&pc->plugin_lock);
	return NULL;
}


int se_obj_load_plugins(void)
{
	int ret = 0;

	dev_obj_template.obj_plugin = plugin_register((void *)&dev_obj_template,
			TRANSPORT_LUN_TYPE_DEVICE, "dev", PLUGIN_TYPE_OBJ,
			dev_obj_template.get_plugin_info, NULL, NULL, &ret);
	if (ret)
		printk(KERN_ERR "plugin_register() failures\n");

	return ret;
}
