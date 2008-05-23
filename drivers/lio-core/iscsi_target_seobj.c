/*********************************************************************************
 * Filename:  iscsi_target_seobj.c
 *
 * Copyright (c) 2006-2007 SBE, Inc.  All Rights Reserved.
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


#define ISCSI_TARGET_SEOBJ_C

#include <linux/string.h>
#include <linux/timer.h>
#include <linux/slab.h>
#include <linux/blkdev.h>
#include <linux/spinlock.h>
#include <linux/smp_lock.h>
#include <linux/in.h>
#include <scsi/scsi.h>

#include <iscsi_linux_os.h>
#include <iscsi_linux_defs.h>

#include <iscsi_lists.h>
#include <iscsi_debug.h>
#include <iscsi_protocol.h>
#include <iscsi_target_core.h>
#include <iscsi_target_error.h>
#include <iscsi_target_ioctl.h>
#include <iscsi_target_ioctl_defs.h>
#include <iscsi_target_device.h>
#include <iscsi_target_hba.h>
#include <iscsi_target_tpg.h>
#include <iscsi_target_transport.h>
#include <iscsi_target_util.h>

#include <iscsi_target_plugin.h>
#include <iscsi_target_seobj.h>
#include <iscsi_target_seobj_plugins.h>
#include <iscsi_target_feature_obj.h>
#include <iscsi_target_feature_plugins.h>

#include <iscsi_target_info.h>

#undef ISCSI_TARGET_SEOBJ_C

#define MAKE_OBJ_TYPE(type, op1, op2)					\
extern void type##_obj_##op1##_count	(struct se_obj_s *obj)		\
{									\
	atomic_##op2(&obj->obj_access_count);				\
}

#define MAKE_OBJ_TYPE_RET(type)						\
extern int type##_obj_check_count (struct se_obj_s *obj)		\
{									\
	return(atomic_read(&obj->obj_access_count));			\
}

MAKE_OBJ_TYPE(dev, inc, inc);
MAKE_OBJ_TYPE(dev, dec, inc);
MAKE_OBJ_TYPE_RET(dev);

extern void dev_obj_get_obj_info (void *p, iscsi_lun_t *lun, unsigned long long bytes, int state, char *b, int *bl)
{
	se_device_t *dev = (se_device_t *)p;
	
	if (state)
		iscsi_dump_dev_state(dev, b, bl);
	iscsi_dump_dev_info((se_device_t *)p, lun, bytes, b, bl);
	return;
}

extern void dev_obj_get_plugin_info (void *p, char *b, int *bl)
{
	*bl += sprintf(b+*bl, "%s Device Object Plugin %s\n", PYX_ISCSI_VENDOR, DEV_OBJ_VERSION);
	return;
}

extern void *dev_obj_get_obj (void *p)
{
	return(p);
}

extern se_queue_obj_t *dev_obj_get_queue_obj (void *p)
{
	se_device_t *dev  = (se_device_t *)p;

	return(dev->dev_queue_obj);
}

extern void dev_obj_start_status_thread (void *p)
{
	se_device_t *dev = (se_device_t *)p;

	if (DEV_OBJ_API(dev)->get_device_type(p) == TYPE_DISK)
		transport_start_status_thread((se_device_t *)p);

	return;
}

extern void dev_obj_stop_status_thread (void *p)
{
	se_device_t *dev = (se_device_t *)p;

	if (DEV_OBJ_API(dev)->get_device_type(p) == TYPE_DISK)
		transport_stop_status_thread((se_device_t *)p);

	return;
}

extern int dev_obj_start_status_timer (void *p)
{
	se_device_t *dev = (se_device_t *)p;

	if (DEV_OBJ_API(dev)->get_device_type(p) == TYPE_DISK)
		transport_start_status_timer((se_device_t *)p);

	return(0);
}

extern void dev_obj_stop_status_timer (void *p)
{
	se_device_t *dev = (se_device_t *)p;

	if (DEV_OBJ_API(dev)->get_device_type(p) == TYPE_DISK)
		transport_stop_status_timer((se_device_t *)p);

	return;
}

extern int dev_obj_claim_obj (void *p)
{
	return(transport_generic_claim_phydevice((se_device_t *)p));
}

extern void dev_obj_release_obj (void *p)
{
	transport_generic_release_phydevice((se_device_t *)p, 1);
	return;
}

extern void dev_obj_set_feature_obj (void *p)
{
	se_device_t *dev  = (se_device_t *)p;

	DEV_OBJ_API(dev)->inc_count(&dev->dev_feature_obj);
	return;
}

extern void dev_obj_clear_feature_obj (void *p)
{
	se_device_t *dev  = (se_device_t *)p;

	DEV_OBJ_API(dev)->dec_count(&dev->dev_feature_obj);
	return;
}

extern int dev_obj_enable_feature (void *p, int f, int fm, void *fp)
{
	se_device_t *dev  = (se_device_t *)p;

	if (!(dev->dev_fp = feature_plugin_alloc(f, fm, fp, DEV_OBJ_API(dev), p)))
		return(-1);

	DEV_OBJ_API(dev)->set_feature_obj(dev);

	if (DEV_OBJ_API(dev)->claim_obj(dev) < 0) {
		feature_plugin_free(dev->dev_fp);
		dev->dev_fp = NULL;
		DEV_OBJ_API(dev)->clear_feature_obj(dev);
		return(-1);
	}

	return(0);
}

extern void dev_obj_disable_feature (void *p)
{
	se_device_t *dev  = (se_device_t *)p;

	if (!(feature_plugin_free(dev->dev_fp))) {
		dev->dev_fp = NULL;
	
		DEV_OBJ_API(dev)->clear_feature_obj(dev);
		DEV_OBJ_API(dev)->release_obj(dev);
	}
	
	return;
}

extern se_fp_obj_t *dev_obj_get_feature_obj (void *p)
{
	se_device_t *dev  = (se_device_t *)p;

	return(dev->dev_fp);
}

extern void dev_access_obj (void *p)
{
	se_device_t *dev  = (se_device_t *)p;

	DEV_OBJ_API(dev)->inc_count(&dev->dev_access_obj);
	return;
}

extern void dev_deaccess_obj (void *p)
{
	se_device_t *dev  = (se_device_t *)p;

	DEV_OBJ_API(dev)->dec_count(&dev->dev_access_obj);
	return;
}

extern void dev_put_obj (void *p)
{
	se_device_t *dev  = (se_device_t *)p;

	core_put_hba(dev->iscsi_hba);
	return;
}

extern int dev_obj_export (void *p, iscsi_portal_group_t *tpg, iscsi_lun_t *lun)
{
	se_device_t *dev  = (se_device_t *)p;
	se_port_t *sep;

	if (!(sep = kmalloc(sizeof(se_port_t), GFP_KERNEL))) {
		TRACE_ERROR("Unable to allocate se_port_t\n");
		return(-1);
	}
	memset(sep, 0, sizeof(se_port_t));
	INIT_LIST_HEAD(&sep->sep_list);

	lun->iscsi_dev = dev;
	if (DEV_OBJ_API(dev)->activate(p) < 0) {
		lun->iscsi_dev = NULL;
		kfree(sep);
		return(-1);
	}

	DEV_OBJ_API(dev)->inc_count(&dev->dev_export_obj);

	spin_lock(&dev->se_port_lock);
	spin_lock(&lun->lun_sep_lock);
	sep->sep_tpg = tpg;
	sep->sep_lun = lun;
	lun->lun_sep = sep;
	spin_unlock(&lun->lun_sep_lock);

	list_add_tail(&sep->sep_list, &dev->dev_sep_list);
	spin_unlock(&dev->se_port_lock);
#ifdef SNMP_SUPPORT
	dev->dev_port_count++;
	sep->sep_index = get_new_index(SCSI_PORT_INDEX);
#endif

	return(0);
}

extern void dev_obj_unexport (void *p, iscsi_portal_group_t *tpg, iscsi_lun_t *lun)
{
	se_device_t *dev  = (se_device_t *)p;
	se_port_t *sep = lun->lun_sep;

	spin_lock(&dev->se_port_lock);
	spin_lock(&lun->lun_sep_lock);
	if (lun->lun_type_ptr == NULL) {
		spin_unlock(&dev->se_port_lock);
		spin_unlock(&lun->lun_sep_lock);
		return;
	}
	spin_unlock(&lun->lun_sep_lock);

	DEV_OBJ_API(dev)->dec_count(&dev->dev_export_obj);

	list_del(&sep->sep_list);
	spin_unlock(&dev->se_port_lock);
#ifdef SNMP_SUPPORT
	dev->dev_port_count--;
#endif  
	kfree(sep);

	DEV_OBJ_API(dev)->deactivate(p);
	lun->iscsi_dev = NULL;
	
	return;
}

extern int dev_obj_transport_setup_cmd (void *p, iscsi_cmd_t *cmd)
{
	transport_device_setup_cmd(cmd);
	return(0);
}

extern int dev_obj_active_tasks (void *p)
{
	se_device_t *dev  = (se_device_t *)p;

	return(atomic_read(&dev->execute_tasks));
}

extern int dev_obj_add_tasks (void *p, iscsi_cmd_t *cmd)
{
	transport_add_tasks_from_cmd(cmd);
	return(0);
}

extern int dev_obj_execute_tasks (void *p)
{
	se_device_t *dev  = (se_device_t *)p;

	__transport_execute_tasks(dev);
	return(0);
}

extern int dev_obj_depth_left (void *p)
{
	se_device_t *dev  = (se_device_t *)p;

	return(atomic_read(&dev->depth_left));
}

extern int dev_obj_queue_depth (void *p)
{
	se_device_t *dev  = (se_device_t *)p;

	return(dev->queue_depth);
}

extern int dev_obj_blocksize (void *p)
{
	se_device_t *dev  = (se_device_t *)p;

	return(TRANSPORT(dev)->get_blocksize(dev));
}

extern int dev_obj_max_sectors (void *p)
{
	se_device_t *dev  = (se_device_t *)p;

	return(TRANSPORT(dev)->get_max_sectors(dev));
}

extern unsigned long long dev_obj_end_lba (void *p, int zero_lba, se_fp_obj_t *fp)
{
	se_device_t *dev  = (se_device_t *)p;
	
	if (!fp)
		 return((dev->dev_sectors_total + ((zero_lba) ? 1 : 0)));
	
	return(((dev->dev_sectors_total + ((zero_lba) ? 1 : 0)) -
		 fp->fp_api->feature_metadata_size(fp)));
}

extern unsigned long long dev_obj_get_next_lba (void *p, unsigned long long lba)
{
	return(lba);
}

extern unsigned long long dev_obj_total_sectors (void *p, int zero_lba, int ignore_fp)
{
	se_device_t *dev  = (se_device_t *)p;
	se_fp_obj_t *fp;

	if (!ignore_fp && (fp = DEV_OBJ_API(dev)->get_feature_obj(p)))
		return(((dev->dev_sectors_total + ((zero_lba) ? 1 : 0)) -
			 fp->fp_api->feature_metadata_size(fp)));
	
	return((dev->dev_sectors_total + ((zero_lba) ? 1 : 0)));
}

extern int dev_obj_do_se_mem_map (
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
	 * iscsi_transport_t->do_se_mem_map is used when internal allocation has
	 * been done by the transport plugin.
	 */
	if (TRANSPORT(dev)->do_se_mem_map) {
		if ((ret = TRANSPORT(dev)->do_se_mem_map(task, se_mem_list, in_mem, in_se_mem,
				out_se_mem, se_mem_cnt, task_offset)) == 0)
			T_TASK(task->iscsi_cmd)->t_task_se_num += *se_mem_cnt;

		return(ret);
	}

	/*
	 * Assume default that transport plugin speaks preallocated scatterlists.
	 */
	if (!(transport_calc_sg_num(task, in_se_mem, tmp_task_offset)))
		return(-1);
	
	/*
	 * se_task_t->task_buf now contains the struct scatterlist array.
	 */
	return(transport_map_mem_to_sg(task, se_mem_list, task->task_buf, in_se_mem, out_se_mem,
			se_mem_cnt, task_offset));
}

extern int dev_obj_get_mem_buf (void *p, iscsi_cmd_t *cmd)
{
	se_device_t *dev  = (se_device_t *)p;

	cmd->transport_allocate_resources = (TRANSPORT(dev)->allocate_buf) ?
		TRANSPORT(dev)->allocate_buf : &transport_generic_allocate_buf;
	cmd->transport_free_resources = (TRANSPORT(dev)->free_buf) ?
		TRANSPORT(dev)->free_buf : NULL;

	return(0);
}

extern int dev_obj_get_mem_SG (void *p, iscsi_cmd_t *cmd)
{
	se_device_t *dev  = (se_device_t *)p;

	cmd->transport_allocate_resources = (TRANSPORT(dev)->allocate_DMA) ?
		TRANSPORT(dev)->allocate_DMA : &transport_generic_get_mem;
	cmd->transport_free_resources = (TRANSPORT(dev)->free_DMA) ?
		TRANSPORT(dev)->free_DMA : NULL;

	return(0);
}

extern map_func_t dev_obj_get_map_SG (void *p, int rw)
{
	se_device_t *dev  = (se_device_t *)p;
	
	return((rw == ISCSI_WRITE) ? dev->transport->spc->write_SG :
		dev->transport->spc->read_SG);
}

extern map_func_t dev_obj_get_map_non_SG (void *p, int rw)
{
	se_device_t *dev  = (se_device_t *)p;

	return((rw == ISCSI_WRITE) ? dev->transport->spc->write_non_SG :
		dev->transport->spc->read_non_SG);
}

extern map_func_t dev_obj_get_map_none (void *p)
{
	se_device_t *dev  = (se_device_t *)p;

	return(dev->transport->spc->none);
}

extern void *dev_obj_get_transport_req (void *p, se_task_t *task)
{
	se_device_t *dev  = (se_device_t *)p;

	task->iscsi_dev = dev;
	
	return(dev->transport->allocate_request(task, dev));
}

extern void dev_obj_free_tasks (void *p, iscsi_cmd_t *cmd)
{
	transport_free_dev_tasks(cmd);
	return;
}

extern int dev_obj_activate (void *p)
{
	se_device_t *dev  = (se_device_t *)p;
	
	se_dev_start(dev);
	return(0);
}

extern void dev_obj_deactivate (void *p)
{
	se_device_t *dev  = (se_device_t *)p;

	se_dev_stop(dev);
	return;
}

extern void dev_obj_notify_obj (void *p)
{
	se_device_t *dev  = (se_device_t *)p;

	up(&dev->dev_queue_obj->thread_sem);
	return;
}

extern int dev_obj_check_online (void *p)
{
	se_device_t *dev  = (se_device_t *)p;
	int ret;

	spin_lock(&dev->dev_status_lock);
	ret = ((dev->dev_status & ISCSI_DEVICE_ACTIVATED) ||
	       (dev->dev_status & ISCSI_DEVICE_DEACTIVATED)) ? 0 : 1;
	spin_unlock(&dev->dev_status_lock);

	return(ret);
}

extern int dev_obj_check_shutdown (void *p)
{
	se_device_t *dev  = (se_device_t *)p;
	int ret;

	spin_lock(&dev->dev_status_lock);
	ret = (dev->dev_status & ISCSI_DEVICE_SHUTDOWN);
	spin_unlock(&dev->dev_status_lock);

	return(ret);
}

extern void dev_obj_fail_operations (void *p)
{
	transport_status_thr_dev_offline((se_device_t *)p);
	transport_status_thr_dev_offline_tasks((se_device_t *)p, p);
	return;
}

extern void dev_obj_signal_offline (void *p)
{
	se_device_t *dev  = (se_device_t *)p;
	
	transport_status_thr_force_offline((se_device_t *)p, DEV_OBJ_API(dev), p);
	return;
}

extern void dev_obj_signal_shutdown (void *p)
{
	se_device_t *dev  = (se_device_t *)p;

	spin_lock(&dev->dev_status_lock);
	if ((dev->dev_status & ISCSI_DEVICE_ACTIVATED) ||
	    (dev->dev_status & ISCSI_DEVICE_DEACTIVATED) ||
	    (dev->dev_status & ISCSI_DEVICE_OFFLINE_ACTIVATED) ||
	    (dev->dev_status & ISCSI_DEVICE_OFFLINE_DEACTIVATED)) {
		dev->dev_status |= ISCSI_DEVICE_SHUTDOWN;
		dev->dev_status &= ~ISCSI_DEVICE_ACTIVATED;
		dev->dev_status &= ~ISCSI_DEVICE_DEACTIVATED;
		dev->dev_status &= ~ISCSI_DEVICE_OFFLINE_ACTIVATED;
		dev->dev_status &= ~ISCSI_DEVICE_OFFLINE_DEACTIVATED;

		up(&dev->dev_queue_obj->thread_sem);
	}
	spin_unlock(&dev->dev_status_lock);

	return;
}

extern void dev_obj_clear_shutdown (void *p)
{
	se_device_t *dev  = (se_device_t *)p;

	spin_lock(&dev->dev_status_lock);
	if (dev->dev_status & ISCSI_DEVICE_SHUTDOWN) {
		dev->dev_status &= ~ISCSI_DEVICE_SHUTDOWN;
		dev->dev_status |= ISCSI_DEVICE_DEACTIVATED;
	}
	spin_unlock(&dev->dev_status_lock);

	return;
}

extern unsigned char *dev_obj_get_cdb (
	void *p,
	se_task_t *task)
{
	se_device_t *dev  = (se_device_t *)p;

	return(dev->transport->get_cdb(task));
}

extern int dev_obj_start (void *p, iscsi_transform_info_t *ti, unsigned long long starting_lba)
{
	se_device_t *dev  = (se_device_t *)p;
	
	return(transport_generic_obj_start(ti, DEV_OBJ_API(dev), p, starting_lba));
}

extern u32 dev_obj_get_cdb_count (
	void *p,
	iscsi_transform_info_t *ti,
	unsigned long long lba,
	u32 sectors,
	se_mem_t *se_mem_in,
	se_mem_t **se_mem_out,
	u32 *task_offset_in)
{
	se_device_t *dev  = (se_device_t *)p;

	ti->ti_dev = dev;
	return(transport_generic_get_cdb_count(ti->ti_cmd, ti, DEV_OBJ_API(dev), p,
		lba, sectors, se_mem_in, se_mem_out, task_offset_in));
}

extern u32 dev_obj_get_cdb_size (
	void *p,
	u32 sectors,
	unsigned char *cdb)
{
	se_device_t *dev  = (se_device_t *)p;

	if (TRANSPORT(dev)->get_device_type(dev) == TYPE_TAPE) {
		if (cdb[1] & 1) { /* sectors */
			return(TRANSPORT(dev)->get_blocksize(dev) * sectors);
		} else /* bytes */
			return(sectors);
	}
	
	/* sectors */
	return(TRANSPORT(dev)->get_blocksize(dev) * sectors);
}

extern void dev_obj_generate_cdb (void *p, unsigned long long lba, u32 *sectors, unsigned char *cdb, int rw)
{
	se_device_t *dev = (se_device_t *)p;

	dev->dev_generate_cdb(lba, sectors, cdb, rw);
	return;
}

extern int dev_obj_get_device_access (void *p)
{
	se_device_t *dev = (se_device_t *)p;

	return((dev->dev_flags & DF_READ_ONLY) ? 0 : 1);
}

extern int dev_obj_get_device_type (void *p)
{
	se_device_t *dev = (se_device_t *)p;

	return(TRANSPORT(dev)->get_device_type(dev));
}

extern int dev_obj_check_DMA_handler (void *p)
{
	se_device_t *dev = (se_device_t *)p;

	if (!dev->transport) {
		TRACE_ERROR("se_device_t->transport is NULL!\n");
		BUG();
	}
	
	return((TRANSPORT(dev)->allocate_DMA != NULL));
}

extern t10_wwn_t *dev_obj_get_t10_wwn (void *p)
{
	se_device_t *dev = (se_device_t *)p;

	return(&dev->t10_wwn);
}

extern int dev_obj_check_tur_bit (void *p)
{
	se_device_t *dev = (se_device_t *)p;

	return(atomic_read(&dev->dev_tur_active));
}

extern void dev_obj_clear_tur_bit (void *p)
{
	se_device_t *dev = (se_device_t *)p;

	atomic_set(&dev->dev_tur_active, 0);
	return;
}

extern void dev_obj_set_tur_bit (void *p)
{
	se_device_t *dev = (se_device_t *)p;

	atomic_set(&dev->dev_tur_active, 1);
	return;
}

extern void dev_obj_get_evpd_prod (void *p, unsigned char *buf, u32 size)
{
	se_device_t *dev = (se_device_t *)p;

	TRANSPORT(dev)->get_evpd_prod(buf, size, dev);
	return;
}

extern void dev_obj_get_evpd_sn (void *p, unsigned char *buf, u32 size)
{
	se_device_t *dev = (se_device_t *)p;

	TRANSPORT(dev)->get_evpd_sn(buf, size, dev);
	return;
}

extern int dev_obj_get_task_timeout (void *p)
{
	se_device_t *dev = (se_device_t *)p;
	
	if (TRANSPORT(dev)->get_device_type(dev) == TYPE_DISK)
		return(TRANSPORT_TIMEOUT_TYPE_DISK); 

	if (TRANSPORT(dev)->get_device_type(dev) == TYPE_ROM)
		return(TRANSPORT_TIMEOUT_TYPE_ROM);

	if (TRANSPORT(dev)->get_device_type(dev) == TYPE_TAPE)
		return(TRANSPORT_TIMEOUT_TYPE_TAPE); 

	return(TRANSPORT_TIMEOUT_TYPE_OTHER);
}

extern int dev_obj_set_task_timeout_handler (void *p, se_task_t *task)
{
	se_device_t *dev = (se_device_t *)p;

	if (TRANSPORT(dev)->transport_timeout_start)
		return(TRANSPORT(dev)->transport_timeout_start(dev, task));

	return(0);
}

extern int dev_obj_task_failure_complete (void *p, iscsi_cmd_t *cmd)
{
	return(transport_failure_tasks_generic(cmd));
}

extern int dev_add_obj_to_lun (iscsi_portal_group_t *tpg, iscsi_lun_t *lun)
{
	return(0);
}

extern int dev_del_obj_from_lun (iscsi_portal_group_t *tpg, iscsi_lun_t *lun)
{
	return(iscsi_dev_del_lun(tpg, lun->iscsi_lun));
}

extern se_obj_lun_type_t *dev_get_next_obj_api (void *p, void **next_p)
{
	se_device_t *dev = (se_device_t *)p;

	*next_p = dev;
	
	return(DEV_OBJ_API(dev));
}

extern int dev_obtain_obj_lock (void *p)
{
	return(0);
}

extern int dev_release_obj_lock (void *p)
{
	return(0);
}

#define DEV_OBJ_PLUGIN {						\
	se_obj_type:		ISCSI_LUN_TYPE_DEVICE,			\
	get_obj_info:		dev_obj_get_obj_info,			\
	get_plugin_info:	dev_obj_get_plugin_info,		\
	get_obj:		dev_obj_get_obj,			\
	get_queue_obj:		dev_obj_get_queue_obj,			\
	start_status_thread:	dev_obj_start_status_thread,		\
	stop_status_thread:	dev_obj_stop_status_thread,		\
	start_status_timer:	dev_obj_start_status_timer,		\
	stop_status_timer:	dev_obj_stop_status_timer,		\
	claim_obj:		dev_obj_claim_obj,			\
	release_obj:		dev_obj_release_obj,			\
	inc_count:		dev_obj_inc_count,			\
	dec_count:		dev_obj_dec_count,			\
	check_count:		dev_obj_check_count,			\
	set_feature_obj:	dev_obj_set_feature_obj,		\
	clear_feature_obj:	dev_obj_clear_feature_obj,		\
	enable_feature:		dev_obj_enable_feature,			\
	disable_feature:	dev_obj_disable_feature,		\
	get_feature_obj:	dev_obj_get_feature_obj,		\
	access_obj:		dev_access_obj,				\
	deaccess_obj:		dev_deaccess_obj,			\
	put_obj:		dev_put_obj,				\
	export_obj:		dev_obj_export,				\
	unexport_obj:		dev_obj_unexport,			\
	transport_setup_cmd:	dev_obj_transport_setup_cmd,		\
	active_tasks:		dev_obj_active_tasks,			\
	add_tasks:		dev_obj_add_tasks,			\
	execute_tasks:		dev_obj_execute_tasks,			\
	depth_left:		dev_obj_depth_left,			\
	queue_depth:		dev_obj_queue_depth,			\
	blocksize:		dev_obj_blocksize,			\
	max_sectors:		dev_obj_max_sectors,			\
	end_lba:		dev_obj_end_lba,			\
	get_next_lba:		dev_obj_get_next_lba,			\
	total_sectors:		dev_obj_total_sectors,			\
	do_se_mem_map:		dev_obj_do_se_mem_map,			\
	get_mem_buf:		dev_obj_get_mem_buf,			\
	get_mem_SG:		dev_obj_get_mem_SG,			\
	get_map_SG:		dev_obj_get_map_SG,			\
	get_map_non_SG:		dev_obj_get_map_non_SG,			\
	get_map_none:		dev_obj_get_map_none,			\
	get_transport_req:	dev_obj_get_transport_req,		\
	free_tasks:		dev_obj_free_tasks,			\
	activate:		dev_obj_activate,			\
	deactivate:		dev_obj_deactivate,			\
	notify_obj:		dev_obj_notify_obj,			\
	check_online:		dev_obj_check_online,			\
	check_shutdown:		dev_obj_check_shutdown,			\
	fail_operations:	dev_obj_fail_operations,		\
	signal_offline:		dev_obj_signal_offline,			\
	signal_shutdown:	dev_obj_signal_shutdown,		\
	clear_shutdown:		dev_obj_clear_shutdown,			\
	get_cdb:		dev_obj_get_cdb,			\
	obj_start:		dev_obj_start,				\
	get_cdb_count:		dev_obj_get_cdb_count,			\
	get_cdb_size:		dev_obj_get_cdb_size,			\
	generate_cdb:		dev_obj_generate_cdb,			\
	get_device_access:	dev_obj_get_device_access,		\
	get_device_type:	dev_obj_get_device_type,		\
	check_DMA_handler:	dev_obj_check_DMA_handler,		\
	get_t10_wwn:		dev_obj_get_t10_wwn,			\
	get_uu_id:		NULL,					\
	check_tur_bit:		dev_obj_check_tur_bit,			\
	clear_tur_bit:		dev_obj_clear_tur_bit,			\
	set_tur_bit:		dev_obj_set_tur_bit,			\
	get_evpd_prod:		dev_obj_get_evpd_prod,			\
	get_evpd_sn:		dev_obj_get_evpd_sn,			\
	get_task_timeout:	dev_obj_get_task_timeout,		\
	set_task_timeout_handler: dev_obj_set_task_timeout_handler,	\
	task_failure_complete:	dev_obj_task_failure_complete,		\
	add_obj_to_lun:		dev_add_obj_to_lun,			\
	del_obj_from_lun:	dev_del_obj_from_lun,			\
	get_next_obj_api:	dev_get_next_obj_api,			\
	obtain_obj_lock:	dev_obtain_obj_lock,			\
	release_obj_lock:	dev_release_obj_lock,			\
};

se_obj_lun_type_t dev_obj_template = DEV_OBJ_PLUGIN;

extern se_obj_lun_type_t *se_obj_get_api (u32 plugin_loc)
{
        se_plugin_class_t *pc;
        se_plugin_t *p;

        if (!(pc = plugin_get_class(PLUGIN_TYPE_OBJ)))
                return(NULL);

        spin_lock(&pc->plugin_lock);
        if (plugin_loc > pc->max_plugins) {
                TRACE_ERROR("Passed plugin_loc: %u exceeds pc->max_plugins: %d\n",
                               plugin_loc, pc->max_plugins);
                goto out;
        }

        p = &pc->plugin_array[plugin_loc];
        if (!p->plugin_obj) {
                TRACE_ERROR("Passed plugin_loc: %u does not exist!\n", plugin_loc);
	        goto out;
	}
	spin_unlock(&pc->plugin_lock);

	return((se_obj_lun_type_t *)p->plugin_obj);

out:
	spin_unlock(&pc->plugin_lock);
	return(NULL);
}


extern int se_obj_load_plugins (void)
{
	int ret = 0;
	
	dev_obj_template.obj_plugin = plugin_register((void *)&dev_obj_template,
			ISCSI_LUN_TYPE_DEVICE, "dev", PLUGIN_TYPE_OBJ,
			dev_obj_template.get_plugin_info, &ret);
	if (ret) {
		TRACE_ERROR("plugin_register() failures\n");
	}
	
	return(ret);
}       


