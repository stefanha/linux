/*******************************************************************************
 * Filename:  target_core_transport.c
 *
 * This file contains the Generic Target Engine Core.
 *
 * Copyright (c) 2002, 2003, 2004, 2005 PyX Technologies, Inc.
 * Copyright (c) 2005, 2006, 2007 SBE, Inc.
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

#include <linux/version.h>
#include <linux/net.h>
#include <linux/delay.h>
#include <linux/string.h>
#include <linux/timer.h>
#include <linux/slab.h>
#include <linux/blkdev.h>
#include <linux/spinlock.h>
#include <linux/smp_lock.h>
#include <linux/kthread.h>
#include <linux/in.h>
#include <linux/cdrom.h>
#include <asm/unaligned.h>
#include <net/sock.h>
#include <net/tcp.h>
#include <scsi/scsi.h>
#include <scsi/scsi_cmnd.h>
#include <scsi/libsas.h> /* For TASK_ATTR_* */

#include <target/target_core_base.h>
#include <target/target_core_device.h>
#include <target/target_core_tmr.h>
#include <target/target_core_tpg.h>
#include <target/target_core_transport.h>
#include <target/target_core_fabric_ops.h>
#include <target/target_core_configfs.h>

#include "target_core_alua.h"
#include "target_core_hba.h"
#include "target_core_pr.h"
#include "target_core_scdb.h"
#include "target_core_seobj.h"
#include "target_core_ua.h"

/* #define DEBUG_CDB_HANDLER */
#ifdef DEBUG_CDB_HANDLER
#define DEBUG_CDB_H(x...) printk(KERN_INFO x)
#else
#define DEBUG_CDB_H(x...)
#endif

/* #define DEBUG_CMD_MAP */
#ifdef DEBUG_CMD_MAP
#define DEBUG_CMD_M(x...) printk(KERN_INFO x)
#else
#define DEBUG_CMD_M(x...)
#endif

/* #define DEBUG_MEM_ALLOC */
#ifdef DEBUG_MEM_ALLOC
#define DEBUG_MEM(x...) printk(KERN_INFO x)
#else
#define DEBUG_MEM(x...)
#endif

/* #define DEBUG_MEM2_ALLOC */
#ifdef DEBUG_MEM2_ALLOC
#define DEBUG_MEM2(x...) printk(KERN_INFO x)
#else
#define DEBUG_MEM2(x...)
#endif

/* #define DEBUG_SG_CALC */
#ifdef DEBUG_SG_CALC
#define DEBUG_SC(x...) printk(KERN_INFO x)
#else
#define DEBUG_SC(x...)
#endif

/* #define DEBUG_SE_OBJ */
#ifdef DEBUG_SE_OBJ
#define DEBUG_SO(x...) printk(KERN_INFO x)
#else
#define DEBUG_SO(x...)
#endif

/* #define DEBUG_CMD_VOL */
#ifdef DEBUG_CMD_VOL
#define DEBUG_VOL(x...) printk(KERN_INFO x)
#else
#define DEBUG_VOL(x...)
#endif

/* #define DEBUG_CMD_STOP */
#ifdef DEBUG_CMD_STOP
#define DEBUG_CS(x...) printk(KERN_INFO x)
#else
#define DEBUG_CS(x...)
#endif

/* #define DEBUG_PASSTHROUGH */
#ifdef DEBUG_PASSTHROUGH
#define DEBUG_PT(x...) printk(KERN_INFO x)
#else
#define DEBUG_PT(x...)
#endif

/* #define DEBUG_TASK_STOP */
#ifdef DEBUG_TASK_STOP
#define DEBUG_TS(x...) printk(KERN_INFO x)
#else
#define DEBUG_TS(x...)
#endif

/* #define DEBUG_TRANSPORT_STOP */
#ifdef DEBUG_TRANSPORT_STOP
#define DEBUG_TRANSPORT_S(x...) printk(KERN_INFO x)
#else
#define DEBUG_TRANSPORT_S(x...)
#endif

/* #define DEBUG_TASK_FAILURE */
#ifdef DEBUG_TASK_FAILURE
#define DEBUG_TF(x...) printk(KERN_INFO x)
#else
#define DEBUG_TF(x...)
#endif

/* #define DEBUG_DEV_OFFLINE */
#ifdef DEBUG_DEV_OFFLINE
#define DEBUG_DO(x...) printk(KERN_INFO x)
#else
#define DEBUG_DO(x...)
#endif

/* #define DEBUG_TASK_STATE */
#ifdef DEBUG_TASK_STATE
#define DEBUG_TSTATE(x...) printk(KERN_INFO x)
#else
#define DEBUG_TSTATE(x...)
#endif

/* #define DEBUG_STATUS_THR */
#ifdef DEBUG_STATUS_THR
#define DEBUG_ST(x...) printk(KERN_INFO x)
#else
#define DEBUG_ST(x...)
#endif

/* #define DEBUG_TASK_TIMEOUT */
#ifdef DEBUG_TASK_TIMEOUT
#define DEBUG_TT(x...) printk(KERN_INFO x)
#else
#define DEBUG_TT(x...)
#endif

/* #define DEBUG_GENERIC_REQUEST_FAILURE */
#ifdef DEBUG_GENERIC_REQUEST_FAILURE
#define DEBUG_GRF(x...) printk(KERN_INFO x)
#else
#define DEBUG_GRF(x...)
#endif

/* #define DEBUG_SAM_TASK_ATTRS */
#ifdef DEBUG_SAM_TASK_ATTRS
#define DEBUG_STA(x...) printk(KERN_INFO x)
#else
#define DEBUG_STA(x...)
#endif

struct se_global *se_global;
EXPORT_SYMBOL(se_global);

struct kmem_cache *se_cmd_cache;
struct kmem_cache *se_task_cache;
struct kmem_cache *se_tmr_req_cache;
struct kmem_cache *se_sess_cache;
struct kmem_cache *se_hba_cache;
struct kmem_cache *se_ua_cache;
struct kmem_cache *se_mem_cache;
EXPORT_SYMBOL(se_mem_cache); /* Used for target_core_rd.c */
struct kmem_cache *t10_pr_reg_cache;
struct kmem_cache *t10_alua_lu_gp_cache;
struct kmem_cache *t10_alua_lu_gp_mem_cache;
struct kmem_cache *t10_alua_tg_pt_gp_cache;
struct kmem_cache *t10_alua_tg_pt_gp_mem_cache;

static int transport_generic_write_pending(struct se_cmd *);
static int transport_processing_thread(void *);

static char *transport_passthrough_get_fabric_name(void)
{
	return "PT";
}

static u32 transport_passthrough_get_task_tag(struct se_cmd *cmd)
{
	return 0;
}

static int transport_passthrough_get_cmd_state(struct se_cmd *cmd)
{
	return 0;
}

static void transport_passthrough_release_cmd_direct(struct se_cmd *cmd)
{
	return;
}

static u16 transport_passthrough_set_fabric_sense_len(
	struct se_cmd *cmd,
	u32 sense_len)
{
	return 0;
}

static u16 transport_passthrough_get_fabric_sense_len(void)
{
	return 0;
}

struct target_core_fabric_ops passthrough_fabric_ops = {
	.release_cmd_direct	= transport_passthrough_release_cmd_direct,
	.get_fabric_name	= transport_passthrough_get_fabric_name,
	.get_task_tag		= transport_passthrough_get_task_tag,
	.get_cmd_state		= transport_passthrough_get_cmd_state,
	.set_fabric_sense_len	= transport_passthrough_set_fabric_sense_len,
	.get_fabric_sense_len	= transport_passthrough_get_fabric_sense_len,
};

int init_se_global(void)
{
	struct se_global *global;

	global = kzalloc(sizeof(struct se_global), GFP_KERNEL);
	if (!(global)) {
		printk(KERN_ERR "Unable to allocate memory for struct se_global\n");
		return -1;
	}

	INIT_LIST_HEAD(&global->g_lu_gps_list);
	INIT_LIST_HEAD(&global->g_se_tpg_list);
	INIT_LIST_HEAD(&global->g_hba_list);
	INIT_LIST_HEAD(&global->g_se_dev_list);
	INIT_LIST_HEAD(&global->g_sub_api_list);
	spin_lock_init(&global->g_device_lock);
	spin_lock_init(&global->hba_lock);
	spin_lock_init(&global->se_tpg_lock);
	spin_lock_init(&global->lu_gps_lock);
	spin_lock_init(&global->plugin_class_lock);
	mutex_init(&global->g_sub_api_mutex);

	se_cmd_cache = kmem_cache_create("se_cmd_cache",
			sizeof(struct se_cmd), __alignof__(struct se_cmd), 0, NULL);
	if (!(se_cmd_cache)) {
		printk(KERN_ERR "kmem_cache_create for struct se_cmd failed\n");
		goto out;
	}
	se_task_cache = kmem_cache_create("se_task_cache",
			sizeof(struct se_task), __alignof__(struct se_task), 0, NULL);
	if (!(se_task_cache)) {
		printk(KERN_ERR "kmem_cache_create for struct se_task failed\n");
		goto out;
	}
	se_tmr_req_cache = kmem_cache_create("se_tmr_cache",
			sizeof(struct se_tmr_req), __alignof__(struct se_tmr_req),
			0, NULL);
	if (!(se_tmr_req_cache)) {
		printk(KERN_ERR "kmem_cache_create() for struct se_tmr_req"
				" failed\n");
		goto out;
	}
	se_sess_cache = kmem_cache_create("se_sess_cache",
			sizeof(struct se_session), __alignof__(struct se_session),
			0, NULL);
	if (!(se_sess_cache)) {
		printk(KERN_ERR "kmem_cache_create() for struct se_session"
				" failed\n");
		goto out;
	}
	se_hba_cache = kmem_cache_create("se_hba_cache",
			sizeof(struct se_hba), __alignof__(struct se_hba),
			0, NULL);
	if (!(se_hba_cache)) {
		printk(KERN_ERR "kmem_cache_create() for struct se_hba"
				" failed\n");
		goto out;
	}
	se_ua_cache = kmem_cache_create("se_ua_cache",
			sizeof(struct se_ua), __alignof__(struct se_ua),
			0, NULL);
	if (!(se_ua_cache)) {
		printk(KERN_ERR "kmem_cache_create() for struct se_ua failed\n");
		goto out;
	}
	se_mem_cache = kmem_cache_create("se_mem_cache",
			sizeof(struct se_mem), __alignof__(struct se_mem), 0, NULL);
	if (!(se_mem_cache)) {
		printk(KERN_ERR "kmem_cache_create() for struct se_mem failed\n");
		goto out;
	}
	t10_pr_reg_cache = kmem_cache_create("t10_pr_reg_cache",
			sizeof(struct t10_pr_registration),
			__alignof__(struct t10_pr_registration), 0, NULL);
	if (!(t10_pr_reg_cache)) {
		printk(KERN_ERR "kmem_cache_create() for struct t10_pr_registration"
				" failed\n");
		goto out;
	}
	t10_alua_lu_gp_cache = kmem_cache_create("t10_alua_lu_gp_cache",
			sizeof(struct t10_alua_lu_gp), __alignof__(struct t10_alua_lu_gp),
			0, NULL);
	if (!(t10_alua_lu_gp_cache)) {
		printk(KERN_ERR "kmem_cache_create() for t10_alua_lu_gp_cache"
				" failed\n");
		goto out;
	}
	t10_alua_lu_gp_mem_cache = kmem_cache_create("t10_alua_lu_gp_mem_cache",
			sizeof(struct t10_alua_lu_gp_member),
			__alignof__(struct t10_alua_lu_gp_member), 0, NULL);
	if (!(t10_alua_lu_gp_mem_cache)) {
		printk(KERN_ERR "kmem_cache_create() for t10_alua_lu_gp_mem_"
				"cache failed\n");
		goto out;
	}
	t10_alua_tg_pt_gp_cache = kmem_cache_create("t10_alua_tg_pt_gp_cache",
			sizeof(struct t10_alua_tg_pt_gp),
			__alignof__(struct t10_alua_tg_pt_gp), 0, NULL);
	if (!(t10_alua_tg_pt_gp_cache)) {
		printk(KERN_ERR "kmem_cache_create() for t10_alua_tg_pt_gp_"
				"cache failed\n");
		goto out;
	}
	t10_alua_tg_pt_gp_mem_cache = kmem_cache_create(
			"t10_alua_tg_pt_gp_mem_cache",
			sizeof(struct t10_alua_tg_pt_gp_member),
			__alignof__(struct t10_alua_tg_pt_gp_member),
			0, NULL);
	if (!(t10_alua_tg_pt_gp_mem_cache)) {
		printk(KERN_ERR "kmem_cache_create() for t10_alua_tg_pt_gp_"
				"mem_t failed\n");
		goto out;
	}

	se_global = global;

	return 0;
out:
	if (se_cmd_cache)
		kmem_cache_destroy(se_cmd_cache);
	if (se_task_cache)
		kmem_cache_destroy(se_task_cache);
	if (se_tmr_req_cache)
		kmem_cache_destroy(se_tmr_req_cache);
	if (se_sess_cache)
		kmem_cache_destroy(se_sess_cache);
	if (se_hba_cache)
		kmem_cache_destroy(se_hba_cache);
	if (se_ua_cache)
		kmem_cache_destroy(se_ua_cache);
	if (se_mem_cache)
		kmem_cache_destroy(se_mem_cache);
	if (t10_pr_reg_cache)
		kmem_cache_destroy(t10_pr_reg_cache);
	if (t10_alua_lu_gp_cache)
		kmem_cache_destroy(t10_alua_lu_gp_cache);
	if (t10_alua_lu_gp_mem_cache)
		kmem_cache_destroy(t10_alua_lu_gp_mem_cache);
	if (t10_alua_tg_pt_gp_cache)
		kmem_cache_destroy(t10_alua_tg_pt_gp_cache);
	if (t10_alua_tg_pt_gp_mem_cache)
		kmem_cache_destroy(t10_alua_tg_pt_gp_mem_cache);
	kfree(global);
	return -1;
}

void release_se_global(void)
{
	struct se_global *global;

	global = se_global;
	if (!(global))
		return;

	kmem_cache_destroy(se_cmd_cache);
	kmem_cache_destroy(se_task_cache);
	kmem_cache_destroy(se_tmr_req_cache);
	kmem_cache_destroy(se_sess_cache);
	kmem_cache_destroy(se_hba_cache);
	kmem_cache_destroy(se_ua_cache);
	kmem_cache_destroy(se_mem_cache);
	kmem_cache_destroy(t10_pr_reg_cache);
	kmem_cache_destroy(t10_alua_lu_gp_cache);
	kmem_cache_destroy(t10_alua_lu_gp_mem_cache);
	kmem_cache_destroy(t10_alua_tg_pt_gp_cache);
	kmem_cache_destroy(t10_alua_tg_pt_gp_mem_cache);
	kfree(global);

	se_global = NULL;
}

#ifdef DEBUG_DEV

/* warning FIXME: PLUGIN API TODO */
int __iscsi_debug_dev(struct se_device *dev)
{
	int fail_task = 0;
	fd_dev_t *fd_dev;
	iblock_dev_t *ib_dev;
	rd_dev_t *rd_dev;
	struct scsi_device *sd;

	spin_lock(&se_global->debug_dev_lock);
	switch (dev->se_hba->type) {
	case PSCSI:
		sd = (struct scsi_device *) dev->dev_ptr;
		if (dev->dev_flags & DF_DEV_DEBUG) {
			printk(KERN_INFO "HBA[%u] - Failing PSCSI Task for"
				" %d/%d/%d\n", dev->se_hba->hba_id,
				sd->channel, sd->id, sd->lun);
			fail_task = 1;
		}
		break;
	case IBLOCK:
		ib_dev = (iblock_dev_t *) dev->dev_ptr;
		if (dev->dev_flags & DF_DEV_DEBUG) {
			printk(KERN_INFO "HBA[%u] - Failing IBLOCK Task for"
				" %u/%u\n", dev->se_hba->hba_id,
				ib_dev->ibd_major, ib_dev->ibd_minor);
			fail_task = 1;
		}
		break;
	case FILEIO:
		fd_dev = (fd_dev_t *) dev->dev_ptr;
		if (dev->dev_flags & DF_DEV_DEBUG) {
			printk(KERN_INFO "HBA[%u] - Failing FILEIO Task for"
				" %u\n", dev->se_hba->hba_id,
				fd_dev->fd_dev_id);
			fail_task = 1;
		}
		break;
	case RAMDISK_DR:
	case RAMDISK_MCP:
		rd_dev = (rd_dev_t *) dev->dev_ptr;
		if (dev->dev_flags & DF_DEV_DEBUG) {
			printk(KERN_INFO "HBA[%u] - Failing RAMDISK Task for"
				" %u\n", dev->se_hba->hba_id,
				rd_dev->rd_dev_id);
			fail_task = 1;
		}
		break;
	default:
		if (dev->dev_flags & DF_DEV_DEBUG) {
			printk(KERN_INFO "HBA[%u] - Failing unknown Task\n",
				dev->se_hba->hba_id);
			fail_task = 1;
		}
		break;
	}
	spin_unlock(&se_global->debug_dev_lock);

	return fail_task;
}

#endif /* DEBUG_DEV */

/* #warning FIXME: transport_get_iqn_sn() for struct se_global */
unsigned char *transport_get_iqn_sn(void)
{
	/*
	 * Assume that for production WWN information will come through
	 * ConfigFS at /sys/kernel/config/target/core/$HBA/$DEV/vpd_unit_serial
	 */
	return "1234567890";
}
EXPORT_SYMBOL(transport_get_iqn_sn);

void transport_init_queue_obj(struct se_queue_obj *qobj)
{
	atomic_set(&qobj->queue_cnt, 0);
	INIT_LIST_HEAD(&qobj->qobj_list);
	init_waitqueue_head(&qobj->thread_wq);
	init_completion(&qobj->thread_create_comp);
	init_completion(&qobj->thread_done_comp);
	spin_lock_init(&qobj->cmd_queue_lock);
}
EXPORT_SYMBOL(transport_init_queue_obj);

static int transport_subsystem_reqmods(void)
{
	int ret;

	ret = request_module("target_core_iblock");
	if (ret != 0)
		printk(KERN_ERR "Unable to load target_core_iblock\n");
		
	ret = request_module("target_core_file");
	if (ret != 0)
		printk(KERN_ERR "Unable to load target_core_file\n");

	ret = request_module("target_core_pscsi");
	if (ret != 0)
		printk(KERN_ERR "Unable to load target_core_pscsi\n");

	ret = request_module("target_core_stgt");
	if (ret != 0)
		printk(KERN_ERR "Unable to load target_core_stgt\n");

	return 0;
}

int transport_subsystem_check_init(void)
{
	if (se_global->g_sub_api_initialized)
		return 0;
	/*
	 * Request the loading of known TCM subsystem plugins..
	 */
	if (transport_subsystem_reqmods() < 0)
		return -1;

	se_global->g_sub_api_initialized = 1;
	return 0;
}

int transport_subsystem_register(
	struct se_subsystem_api *sub_api,
	struct module *sub_owner)
{
	struct se_subsystem_api *s;
	/*
	 * Save struct module * for TFO [attach,detach]_hba() reference
	 * in se_core_add_hba()
	 */
	if (sub_api->external_submod && (sub_owner != NULL))
		sub_api->sub_owner = sub_owner;
	else
		sub_api->sub_owner = NULL;

	mutex_lock(&se_global->g_sub_api_mutex);
	list_for_each_entry(s, &se_global->g_sub_api_list, sub_api_list) {
		if (!(strcmp(s->name, sub_api->name))) {
			printk(KERN_ERR "%p is already registered with"
				" duplicate name %s, unable to process"
				" request\n", s, s->name);
			mutex_unlock(&se_global->g_sub_api_mutex);
			return -EEXIST;
		}
	}
	list_add_tail(&sub_api->sub_api_list, &se_global->g_sub_api_list);
	mutex_unlock(&se_global->g_sub_api_mutex);

	printk(KERN_INFO "TCM: Registered subsystem plugin: %s struct module:"
			" %p\n", sub_api->name, sub_api->sub_owner);
	return 0;
}
EXPORT_SYMBOL(transport_subsystem_register);

void transport_subsystem_release(struct se_subsystem_api *sub_api)
{
	mutex_lock(&se_global->g_sub_api_mutex);
	list_del(&sub_api->sub_api_list);
	mutex_unlock(&se_global->g_sub_api_mutex);
}
EXPORT_SYMBOL(transport_subsystem_release);

struct se_subsystem_api *transport_core_get_sub_by_name(const char *sub_name)
{
	struct se_subsystem_api *s;

	mutex_lock(&se_global->g_sub_api_mutex);
	list_for_each_entry(s, &se_global->g_sub_api_list, sub_api_list) {
		if (!(strcmp(s->name, sub_name))) {
			atomic_inc(&s->sub_api_hba_cnt);
			smp_mb__after_atomic_inc();
			mutex_unlock(&se_global->g_sub_api_mutex);
			return s;
		}
	}
	mutex_unlock(&se_global->g_sub_api_mutex);

	return NULL;
}

void transport_core_put_sub(struct se_subsystem_api *s)
{
	atomic_dec(&s->sub_api_hba_cnt);
	smp_mb__after_atomic_dec();
}

void transport_check_dev_params_delim(char *ptr, char **cur)
{
	char *ptr2;

	if (ptr) {
		ptr2 = strstr(ptr, ",");
		if ((ptr2)) {
			*ptr2 = '\0';
			*cur = (ptr2 + 1); /* Skip over comma */
		} else
			*cur = NULL;
	}
}
EXPORT_SYMBOL(transport_check_dev_params_delim);

struct se_session *transport_init_session(void)
{
	struct se_session *se_sess;

	se_sess = kmem_cache_zalloc(se_sess_cache, GFP_KERNEL);
	if (!(se_sess)) {
		printk(KERN_ERR "Unable to allocate struct se_session from"
				" se_sess_cache\n");
		return ERR_PTR(-ENOMEM);
	}
	INIT_LIST_HEAD(&se_sess->sess_list);
	INIT_LIST_HEAD(&se_sess->sess_acl_list);

	return se_sess;
}
EXPORT_SYMBOL(transport_init_session);

/*
 * Called with spin_lock_bh(&struct se_portal_group->session_lock called.
 */
void __transport_register_session(
	struct se_portal_group *se_tpg,
	struct se_node_acl *se_nacl,
	struct se_session *se_sess,
	void *fabric_sess_ptr)
{
	unsigned char buf[PR_REG_ISID_LEN];

	se_sess->se_tpg = se_tpg;
	se_sess->fabric_sess_ptr = fabric_sess_ptr;
	/*
	 * Used by struct se_node_acl's under ConfigFS to locate active se_session-t
	 *
	 * Only set for struct se_session's that will actually be moving I/O.
	 * eg: *NOT* discovery sessions.
	 */
	if (se_nacl) {
		/*
		 * If the fabric module supports an ISID based TransportID,
		 * save this value in binary from the fabric I_T Nexus now.
		 */
		if (TPG_TFO(se_tpg)->sess_get_initiator_sid != NULL) {
			memset(&buf[0], 0, PR_REG_ISID_LEN);
			TPG_TFO(se_tpg)->sess_get_initiator_sid(se_sess,
					&buf[0], PR_REG_ISID_LEN);
			se_sess->sess_bin_isid = get_unaligned_be64(&buf[0]);
		}
		spin_lock_bh(&se_nacl->nacl_sess_lock);
		/*
		 * The se_nacl->nacl_sess pointer will be set to the
		 * last active I_T Nexus for each struct se_node_acl.
		 */
		se_nacl->nacl_sess = se_sess;

		list_add_tail(&se_sess->sess_acl_list,
			      &se_nacl->acl_sess_list);
		spin_unlock_bh(&se_nacl->nacl_sess_lock);
	}
	list_add_tail(&se_sess->sess_list, &se_tpg->tpg_sess_list);

	printk(KERN_INFO "TARGET_CORE[%s]: Registered fabric_sess_ptr: %p\n",
		TPG_TFO(se_tpg)->get_fabric_name(), se_sess->fabric_sess_ptr);
}
EXPORT_SYMBOL(__transport_register_session);

void transport_register_session(
	struct se_portal_group *se_tpg,
	struct se_node_acl *se_nacl,
	struct se_session *se_sess,
	void *fabric_sess_ptr)
{
	spin_lock_bh(&se_tpg->session_lock);
	__transport_register_session(se_tpg, se_nacl, se_sess, fabric_sess_ptr);
	spin_unlock_bh(&se_tpg->session_lock);
}
EXPORT_SYMBOL(transport_register_session);

void transport_deregister_session_configfs(struct se_session *se_sess)
{
	struct se_node_acl *se_nacl;

	/*
	 * Used by struct se_node_acl's under ConfigFS to locate active struct se_session
	 */
	se_nacl = se_sess->se_node_acl;
	if ((se_nacl)) {
		spin_lock_bh(&se_nacl->nacl_sess_lock);
		list_del(&se_sess->sess_acl_list);
		/*
		 * If the session list is empty, then clear the pointer.
		 * Otherwise, set the struct se_session pointer from the tail
		 * element of the per struct se_node_acl active session list.
		 */
		if (list_empty(&se_nacl->acl_sess_list))
			se_nacl->nacl_sess = NULL;
		else {
			se_nacl->nacl_sess = container_of(
					se_nacl->acl_sess_list.prev,
					struct se_session, sess_acl_list);	
		}
		spin_unlock_bh(&se_nacl->nacl_sess_lock);
	}
}
EXPORT_SYMBOL(transport_deregister_session_configfs);

void transport_free_session(struct se_session *se_sess)
{
	kmem_cache_free(se_sess_cache, se_sess);
}
EXPORT_SYMBOL(transport_free_session);

void transport_deregister_session(struct se_session *se_sess)
{
	struct se_portal_group *se_tpg = se_sess->se_tpg;
	struct se_node_acl *se_nacl;

	if (!(se_tpg)) {
		transport_free_session(se_sess);
		return;
	}

	spin_lock_bh(&se_tpg->session_lock);
	list_del(&se_sess->sess_list);
	se_sess->se_tpg = NULL;
	se_sess->fabric_sess_ptr = NULL;
	spin_unlock_bh(&se_tpg->session_lock);

	/*
	 * Determine if we need to do extra work for this initiator node's
	 * struct se_node_acl if it had been previously dynamically generated.
	 */
	se_nacl = se_sess->se_node_acl;
	if ((se_nacl)) {
		spin_lock_bh(&se_tpg->acl_node_lock);
		if (se_nacl->nodeacl_flags & NAF_DYNAMIC_NODE_ACL) {
			if (!(TPG_TFO(se_tpg)->tpg_check_demo_mode_cache(
					se_tpg))) {
				list_del(&se_nacl->acl_list);
				se_tpg->num_node_acls--;
				spin_unlock_bh(&se_tpg->acl_node_lock);

				core_tpg_wait_for_nacl_pr_ref(se_nacl);
				core_free_device_list_for_node(se_nacl, se_tpg);
				TPG_TFO(se_tpg)->tpg_release_fabric_acl(se_tpg,
						se_nacl);
				spin_lock_bh(&se_tpg->acl_node_lock);
			}
		}
		spin_unlock_bh(&se_tpg->acl_node_lock);
	}

	transport_free_session(se_sess);

	printk(KERN_INFO "TARGET_CORE[%s]: Deregistered fabric_sess\n",
		TPG_TFO(se_tpg)->get_fabric_name());
}
EXPORT_SYMBOL(transport_deregister_session);

/*
 * Called with T_TASK(cmd)->t_state_lock held.
 */
static void transport_all_task_dev_remove_state(struct se_cmd *cmd)
{
	struct se_device *dev;
	struct se_task *task;
	unsigned long flags;

	if (!T_TASK(cmd))
		return;

	list_for_each_entry(task, &T_TASK(cmd)->t_task_list, t_list) {
		dev = task->se_dev;
		if (!(dev))
			continue;

		if (atomic_read(&task->task_active))
			continue;

		if (!(atomic_read(&task->task_state_active)))
			continue;

		spin_lock_irqsave(&dev->execute_task_lock, flags);
		list_del(&task->t_state_list);
		DEBUG_TSTATE("Removed ITT: 0x%08x dev: %p task[%p]\n",
			CMD_TFO(cmd)->tfo_get_task_tag(cmd), dev, task);
		spin_unlock_irqrestore(&dev->execute_task_lock, flags);

		atomic_set(&task->task_state_active, 0);
		atomic_dec(&T_TASK(cmd)->t_task_cdbs_ex_left);
	}
}

/*
 * Called with T_TASK(cmd)->t_state_lock held.
 */
void transport_task_dev_remove_state(struct se_task *task, struct se_device *dev)
{
	struct se_cmd *cmd = task->task_se_cmd;
	unsigned long flags;

	/*
	 * We cannot remove the task from the state list while said task is
	 * still active and probably timed out.
	 */
	if (atomic_read(&task->task_active)) {
#if 0
		printk(KERN_ERR "Skipping Removal of state for ITT: 0x%08x"
			" dev: %p task[%p]\n"
			CMD_TFO(task->task_se_cmd)->tfo_get_task_tag(
			task->task_se_cmd), dev, task);
#endif
		return;
	}

	if (atomic_read(&task->task_state_active)) {
		spin_lock_irqsave(&dev->execute_task_lock, flags);
		list_del(&task->t_state_list);
		DEBUG_TSTATE("Removed ITT: 0x%08x dev: %p task[%p]\n",
			CMD_TFO(task->task_se_cmd)->tfo_get_task_tag(
			task->task_se_cmd), dev, task);
		spin_unlock_irqrestore(&dev->execute_task_lock, flags);

		atomic_set(&task->task_state_active, 0);
		atomic_dec(&T_TASK(cmd)->t_task_cdbs_ex_left);
	}
}

static void transport_passthrough_check_stop(struct se_cmd *cmd)
{
	if (!(cmd->se_cmd_flags & SCF_CMD_PASSTHROUGH))
		return;

	if (!cmd->transport_passthrough_done) {
		if (cmd->callback) {
			cmd->callback(cmd, cmd->callback_arg,
				transport_passthrough_complete(cmd));
		} else
			complete(&T_TASK(cmd)->t_transport_passthrough_comp);

		return;
	}

	cmd->transport_passthrough_done(cmd);
}

/*	transport_cmd_check_stop():
 *
 *	'transport_off = 1' determines if t_transport_active should be cleared.
 *	'transport_off = 2' determines if task_dev_state should be removed.
 *
 *	A non-zero u8 t_state sets cmd->t_state.
 *	Returns 1 when command is stopped, else 0.
 */
static int transport_cmd_check_stop(
	struct se_cmd *cmd,
	int transport_off,
	u8 t_state)
{
	unsigned long flags;

	spin_lock_irqsave(&T_TASK(cmd)->t_state_lock, flags);
	/*
	 * Determine if IOCTL context caller in requesting the stopping of this
	 * command for LUN shutdown purposes.
	 */
	if (atomic_read(&T_TASK(cmd)->transport_lun_stop)) {
		DEBUG_CS("%s:%d atomic_read(&T_TASK(cmd)->transport_lun_stop)"
			" == TRUE for ITT: 0x%08x\n", __func__, __LINE__,
			CMD_TFO(cmd)->get_task_tag(cmd));

		cmd->deferred_t_state = cmd->t_state;
		cmd->t_state = TRANSPORT_DEFERRED_CMD;
		atomic_set(&T_TASK(cmd)->t_transport_active, 0);
		if (transport_off == 2)
			transport_all_task_dev_remove_state(cmd);
		spin_unlock_irqrestore(&T_TASK(cmd)->t_state_lock, flags);

		complete(&T_TASK(cmd)->transport_lun_stop_comp);
		return 1;
	}
	/*
	 * Determine if frontend context caller is requesting the stopping of
	 * this command for frontend excpections.
	 */
	if (atomic_read(&T_TASK(cmd)->t_transport_stop)) {
		DEBUG_CS("%s:%d atomic_read(&T_TASK(cmd)->t_transport_stop) =="
			" TRUE for ITT: 0x%08x\n", __func__, __LINE__,
			CMD_TFO(cmd)->get_task_tag(cmd));

		cmd->deferred_t_state = cmd->t_state;
		cmd->t_state = TRANSPORT_DEFERRED_CMD;
		if (transport_off == 2)
			transport_all_task_dev_remove_state(cmd);

		/*
		 * Clear struct se_cmd->se_lun before the transport_off == 2 handoff
		 * to FE.
		 */
		if ((transport_off == 2) && !(cmd->se_cmd_flags &
						SCF_CMD_PASSTHROUGH))
			cmd->se_lun = NULL;
		spin_unlock_irqrestore(&T_TASK(cmd)->t_state_lock, flags);

		complete(&T_TASK(cmd)->t_transport_stop_comp);
		return 1;
	}
	if (transport_off) {
		atomic_set(&T_TASK(cmd)->t_transport_active, 0);
		if (transport_off == 2) {
			transport_all_task_dev_remove_state(cmd);
			/*
			 * Clear struct se_cmd->se_lun before the transport_off == 2
			 * handoff to fabric module.
			 */
			if (!(cmd->se_cmd_flags & SCF_CMD_PASSTHROUGH))
				cmd->se_lun = NULL;
			/*
			 * Some fabric modules like tcm_loop can release
			 * their internally allocated I/O refrence now and
			 * struct se_cmd now.
			 */
			if (CMD_TFO(cmd)->check_stop_free != NULL) {
				spin_unlock_irqrestore(
					&T_TASK(cmd)->t_state_lock, flags);

				CMD_TFO(cmd)->check_stop_free(cmd);
				return 1;
			}
		}
		spin_unlock_irqrestore(&T_TASK(cmd)->t_state_lock, flags);

		return 0;
	} else if (t_state)
		cmd->t_state = t_state;
	spin_unlock_irqrestore(&T_TASK(cmd)->t_state_lock, flags);

	return 0;
}

static int transport_cmd_check_stop_to_fabric(struct se_cmd *cmd)
{
	return transport_cmd_check_stop(cmd, 2, 0);
}

static void transport_lun_remove_cmd(struct se_cmd *cmd)
{
	struct se_lun *lun = SE_LUN(cmd);
	unsigned long flags;

	if (!lun)
		return;
	/*
	 * Do not track passthrough struct se_cmd for now..
	 */
	if (cmd->se_cmd_flags & SCF_CMD_PASSTHROUGH)
		return;

	spin_lock_irqsave(&T_TASK(cmd)->t_state_lock, flags);
	if (!(atomic_read(&T_TASK(cmd)->transport_dev_active))) {
		spin_unlock_irqrestore(&T_TASK(cmd)->t_state_lock, flags);
		goto check_lun;
	}
	atomic_set(&T_TASK(cmd)->transport_dev_active, 0);
	transport_all_task_dev_remove_state(cmd);
	spin_unlock_irqrestore(&T_TASK(cmd)->t_state_lock, flags);

	transport_free_dev_tasks(cmd);

check_lun:
	spin_lock_irqsave(&lun->lun_cmd_lock, flags);
	if (atomic_read(&T_TASK(cmd)->transport_lun_active)) {
		list_del(&cmd->se_lun_list);
		atomic_set(&T_TASK(cmd)->transport_lun_active, 0);
#if 0
		printk(KERN_INFO "Removed ITT: 0x%08x from LUN LIST[%d]\n"
			CMD_TFO(cmd)->get_task_tag(cmd), lun->unpacked_lun);
#endif
	}
	spin_unlock_irqrestore(&lun->lun_cmd_lock, flags);
}

void transport_cmd_finish_abort(struct se_cmd *cmd, int remove)
{
	transport_remove_cmd_from_queue(cmd, SE_DEV(cmd)->dev_queue_obj);
	transport_lun_remove_cmd(cmd);

	if (transport_cmd_check_stop_to_fabric(cmd))
		return;
	if (remove)
		transport_generic_remove(cmd, 0, 0);
}

void transport_cmd_finish_abort_tmr(struct se_cmd *cmd)
{
	transport_remove_cmd_from_queue(cmd, SE_DEV(cmd)->dev_queue_obj);

	if (transport_cmd_check_stop_to_fabric(cmd))
		return;

	transport_generic_remove(cmd, 0, 0);
}

int transport_add_cmd_to_queue(
	struct se_cmd *cmd,
	struct se_queue_obj *qobj,
	u8 t_state)
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

	qr->cmd = (void *)cmd;
	qr->state = t_state;

	if (t_state) {
		spin_lock_irqsave(&T_TASK(cmd)->t_state_lock, flags);
		cmd->t_state = t_state;
		atomic_set(&T_TASK(cmd)->t_transport_active, 1);
		spin_unlock_irqrestore(&T_TASK(cmd)->t_state_lock, flags);
	}

	spin_lock_irqsave(&qobj->cmd_queue_lock, flags);
	list_add_tail(&qr->qr_list, &qobj->qobj_list);
	atomic_inc(&T_TASK(cmd)->t_transport_queue_active);
	spin_unlock_irqrestore(&qobj->cmd_queue_lock, flags);

	atomic_inc(&qobj->queue_cnt);
	wake_up_interruptible(&qobj->thread_wq);
	return 0;
}

static int transport_add_cmd_to_dev_queue(struct se_cmd *cmd, u8 t_state)
{
	struct se_device *dev = cmd->se_dev;

	return transport_add_cmd_to_queue(cmd, dev->dev_queue_obj, t_state);
}

/*
 * Called with struct se_queue_obj->cmd_queue_lock held.
 */
struct se_queue_req *__transport_get_qr_from_queue(struct se_queue_obj *qobj)
{
	struct se_cmd *cmd;
	struct se_queue_req *qr = NULL;

	if (list_empty(&qobj->qobj_list))
		return NULL;

	list_for_each_entry(qr, &qobj->qobj_list, qr_list)
		break;

	if (qr->cmd) {
		cmd = (struct se_cmd *)qr->cmd;
		atomic_dec(&T_TASK(cmd)->t_transport_queue_active);
	}
	list_del(&qr->qr_list);
	atomic_dec(&qobj->queue_cnt);

	return qr;
}

struct se_queue_req *transport_get_qr_from_queue(struct se_queue_obj *qobj)
{
	struct se_cmd *cmd;
	struct se_queue_req *qr;
	unsigned long flags;

	spin_lock_irqsave(&qobj->cmd_queue_lock, flags);
	if (list_empty(&qobj->qobj_list)) {
		spin_unlock_irqrestore(&qobj->cmd_queue_lock, flags);
		return NULL;
	}

	list_for_each_entry(qr, &qobj->qobj_list, qr_list)
		break;

	if (qr->cmd) {
		cmd = (struct se_cmd *)qr->cmd;
		atomic_dec(&T_TASK(cmd)->t_transport_queue_active);
	}
	list_del(&qr->qr_list);
	atomic_dec(&qobj->queue_cnt);
	spin_unlock_irqrestore(&qobj->cmd_queue_lock, flags);

	return qr;
}

void transport_remove_cmd_from_queue(struct se_cmd *cmd, struct se_queue_obj *qobj)
{
	struct se_cmd *q_cmd;
	struct se_queue_req *qr = NULL, *qr_p = NULL;
	unsigned long flags;

	spin_lock_irqsave(&qobj->cmd_queue_lock, flags);
	if (!(atomic_read(&T_TASK(cmd)->t_transport_queue_active))) {
		spin_unlock_irqrestore(&qobj->cmd_queue_lock, flags);
		return;
	}

	list_for_each_entry_safe(qr, qr_p, &qobj->qobj_list, qr_list) {
		q_cmd = (struct se_cmd *)qr->cmd;
		if (q_cmd != cmd)
			continue;

		atomic_dec(&T_TASK(q_cmd)->t_transport_queue_active);
		atomic_dec(&qobj->queue_cnt);
		list_del(&qr->qr_list);
		kfree(qr);
	}
	spin_unlock_irqrestore(&qobj->cmd_queue_lock, flags);

	if (atomic_read(&T_TASK(cmd)->t_transport_queue_active)) {
		printk(KERN_ERR "ITT: 0x%08x t_transport_queue_active: %d\n",
			CMD_TFO(cmd)->get_task_tag(cmd),
			atomic_read(&T_TASK(cmd)->t_transport_queue_active));
	}
}

void transport_complete_cmd(struct se_cmd *cmd, int success)
{
	int t_state;
	unsigned long flags;

	spin_lock_irqsave(&T_TASK(cmd)->t_state_lock, flags);
	if (!success) {
		cmd->transport_error_status = PYX_TRANSPORT_LU_COMM_FAILURE;
		t_state = TRANSPORT_COMPLETE_FAILURE;
	} else {
		t_state = TRANSPORT_COMPLETE_OK;
	}
	atomic_set(&T_TASK(cmd)->t_transport_complete, 1);
	spin_unlock_irqrestore(&T_TASK(cmd)->t_state_lock, flags);

	cmd->transport_add_cmd_to_queue(cmd, t_state);
}

/*	transport_complete_task():
 *
 *	Called from interrupt and non interrupt context depending
 *	on the transport plugin.
 */
void transport_complete_task(struct se_task *task, int success)
{
	struct se_cmd *cmd = TASK_CMD(task);
	struct se_device *dev = task->se_dev;
	int t_state;
	unsigned long flags;
#if 0
	printk(KERN_INFO "task: %p CDB: 0x%02x obj_ptr: %p\n", task,
			T_TASK(cmd)->t_task_cdb[0], dev);
#endif
	if (dev) {
		spin_lock_irqsave(&SE_HBA(dev)->hba_queue_lock, flags);
		atomic_inc(&dev->depth_left);
		atomic_inc(&SE_HBA(dev)->left_queue_depth);
		spin_unlock_irqrestore(&SE_HBA(dev)->hba_queue_lock, flags);
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
		cmd->se_cmd_flags |= SCF_TRANSPORT_TASK_SENSE;
		task->task_sense = 1;
		success = 1;
	}

	/*
	 * See if we are waiting for outstanding struct se_task
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

		complete(&task->task_stop_comp);
		return;
	}
	/*
	 * If the task's timeout handler has fired, use the t_task_cdbs_timeout
	 * left counter to determine when the struct se_cmd is ready to be queued to
	 * the processing thread.
	 */
	if (atomic_read(&task->task_timeout)) {
		if (!(atomic_dec_and_test(
				&T_TASK(cmd)->t_task_cdbs_timeout_left))) {
			spin_unlock_irqrestore(&T_TASK(cmd)->t_state_lock,
				flags);
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
			cmd->transport_error_status =
				PYX_TRANSPORT_LU_COMM_FAILURE;
		}
	}
#endif /* DEBUG_DEV */

	/*
	 * Decrement the outstanding t_task_cdbs_left count.  The last
	 * struct se_task from struct se_cmd will complete itself into the
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
			task->task_error_status =
				PYX_TRANSPORT_UNKNOWN_SAM_OPCODE;
			cmd->transport_error_status =
				PYX_TRANSPORT_UNKNOWN_SAM_OPCODE;
		}
	} else {
		atomic_set(&T_TASK(cmd)->t_transport_complete, 1);
		t_state = TRANSPORT_COMPLETE_OK;
	}
	spin_unlock_irqrestore(&T_TASK(cmd)->t_state_lock, flags);

	cmd->transport_add_cmd_to_queue(cmd, t_state);
}
EXPORT_SYMBOL(transport_complete_task);

/*
 * Called by transport_add_tasks_from_cmd() once a struct se_cmd's
 * struct se_task list are ready to be added to the active execution list
 * struct se_device

 * Called with se_dev_t->execute_task_lock called.
 */
static inline int transport_add_task_check_sam_attr(
	struct se_task *task,
	struct se_task *task_prev,
	struct se_device *dev)
{
	/*
	 * No SAM Task attribute emulation enabled, add to tail of
	 * execution queue
	 */
	if (dev->dev_task_attr_type != SAM_TASK_ATTR_EMULATED) {
		list_add_tail(&task->t_execute_list, &dev->execute_task_list);
		return 0;
	}
	/*
	 * HEAD_OF_QUEUE attribute for received CDB, which means
	 * the first task that is associated with a struct se_cmd goes to
	 * head of the struct se_device->execute_task_list, and task_prev
	 * after that for each subsequent task
	 */
	if (task->task_se_cmd->sam_task_attr == TASK_ATTR_HOQ) {
		list_add(&task->t_execute_list,
				(task_prev != NULL) ?
				&task_prev->t_execute_list :
				&dev->execute_task_list);

		DEBUG_STA("Set HEAD_OF_QUEUE for task CDB: 0x%02x"
				" in execution queue\n",
				T_TASK(task->task_se_cmd)->t_task_cdb[0]);
		return 1;
	}
	/*
	 * For ORDERED, SIMPLE or UNTAGGED attribute tasks once they have been
	 * transitioned from Dermant -> Active state, and are added to the end
	 * of the struct se_device->execute_task_list
	 */
	list_add_tail(&task->t_execute_list, &dev->execute_task_list);
	return 0;
}

/*	__transport_add_task_to_execute_queue():
 *
 *	Called with se_dev_t->execute_task_lock called.
 */
static void __transport_add_task_to_execute_queue(
	struct se_task *task,
	struct se_task *task_prev,
	struct se_device *dev)
{
	int head_of_queue;

	head_of_queue = transport_add_task_check_sam_attr(task, task_prev, dev);
	atomic_inc(&dev->execute_tasks);

	if (atomic_read(&task->task_state_active))
		return;
	/*
	 * Determine if this task needs to go to HEAD_OF_QUEUE for the
	 * state list as well.  Running with SAM Task Attribute emulation
	 * will always return head_of_queue == 0 here
	 */
	if (head_of_queue)
		list_add(&task->t_state_list, (task_prev) ?
				&task_prev->t_state_list :
				&dev->state_task_list);
	else
		list_add_tail(&task->t_state_list, &dev->state_task_list);

	atomic_set(&task->task_state_active, 1);

	DEBUG_TSTATE("Added ITT: 0x%08x task[%p] to dev: %p\n",
		CMD_TFO(task->task_se_cmd)->get_task_tag(task->task_se_cmd),
		task, dev);
}

static void transport_add_tasks_to_state_queue(struct se_cmd *cmd)
{
	struct se_device *dev;
	struct se_task *task;
	unsigned long flags;

	spin_lock_irqsave(&T_TASK(cmd)->t_state_lock, flags);
	list_for_each_entry(task, &T_TASK(cmd)->t_task_list, t_list) {
		dev = task->se_dev;

		if (atomic_read(&task->task_state_active))
			continue;

		spin_lock(&dev->execute_task_lock);
		list_add_tail(&task->t_state_list, &dev->state_task_list);
		atomic_set(&task->task_state_active, 1);

		DEBUG_TSTATE("Added ITT: 0x%08x task[%p] to dev: %p\n",
			CMD_TFO(task->task_se_cmd)->get_task_tag(
			task->task_se_cmd), task, dev);

		spin_unlock(&dev->execute_task_lock);
	}
	spin_unlock_irqrestore(&T_TASK(cmd)->t_state_lock, flags);
}

/*	transport_add_tasks_from_cmd():
 *
 *
 */
void transport_add_tasks_from_cmd(struct se_cmd *cmd)
{
	struct se_device *dev = SE_DEV(cmd);
	struct se_task *task, *task_prev = NULL;
	unsigned long flags;

	spin_lock_irqsave(&dev->execute_task_lock, flags);
	list_for_each_entry(task, &T_TASK(cmd)->t_task_list, t_list) {
		if (atomic_read(&task->task_execute_queue))
			continue;
		/*
		 * __transport_add_task_to_execute_queue() handles the
		 * SAM Task Attribute emulation if enabled
		 */
		__transport_add_task_to_execute_queue(task, task_prev, dev);
		atomic_set(&task->task_execute_queue, 1);
		task_prev = task;
	}
	spin_unlock_irqrestore(&dev->execute_task_lock, flags);

	return;
}

/*	transport_get_task_from_execute_queue():
 *
 *	Called with dev->execute_task_lock held.
 */
struct se_task *transport_get_task_from_execute_queue(struct se_device *dev)
{
	struct se_task *task;

	if (list_empty(&dev->execute_task_list))
		return NULL;

	list_for_each_entry(task, &dev->execute_task_list, t_execute_list)
		break;

	list_del(&task->t_execute_list);
	atomic_dec(&dev->execute_tasks);

	return task;
}

/*	transport_remove_task_from_execute_queue():
 *
 *
 */
static void transport_remove_task_from_execute_queue(
	struct se_task *task,
	struct se_device *dev)
{
	unsigned long flags;

	spin_lock_irqsave(&dev->execute_task_lock, flags);
	list_del(&task->t_execute_list);
	atomic_dec(&dev->execute_tasks);
	spin_unlock_irqrestore(&dev->execute_task_lock, flags);
}

/*	transport_check_device_tcq():
 *
 *
 */
int transport_check_device_tcq(
	struct se_device *dev,
	u32 unpacked_lun,
	u32 device_tcq)
{
	if (device_tcq > dev->queue_depth) {
		printk(KERN_ERR "Attempting to set storage device queue depth"
			" to %d while transport maximum is %d on LUN: %u,"
			" ignoring request\n", device_tcq, dev->queue_depth,
			unpacked_lun);
		return -1;
	} else if (!device_tcq) {
		printk(KERN_ERR "Attempting to set storage device queue depth"
			" to 0 on LUN: %u, ignoring request\n", unpacked_lun);
		return -1;
	}

	dev->queue_depth = device_tcq;
	atomic_set(&dev->depth_left, dev->queue_depth);
	printk(KERN_INFO "Reset Device Queue Depth to %u for Logical Unit"
		" Number: %u\n", dev->queue_depth, unpacked_lun);

	return 0;
}
EXPORT_SYMBOL(transport_check_device_tcq);

unsigned char *transport_dump_cmd_direction(struct se_cmd *cmd)
{
	switch (cmd->data_direction) {
	case SE_DIRECTION_NONE:
		return "NONE";
	case SE_DIRECTION_READ:
		return "READ";
	case SE_DIRECTION_WRITE:
		return "WRITE";
	case SE_DIRECTION_BIDI:
		return "BIDI";
	default:
		break;
	}

	return "UNKNOWN";
}

void transport_dump_dev_state(
	struct se_device *dev,
	char *b,
	int *bl)
{
	*bl += sprintf(b + *bl, "Status: ");
	switch (dev->dev_status) {
	case TRANSPORT_DEVICE_ACTIVATED:
		*bl += sprintf(b + *bl, "ACTIVATED");
		break;
	case TRANSPORT_DEVICE_DEACTIVATED:
		*bl += sprintf(b + *bl, "DEACTIVATED");
		break;
	case TRANSPORT_DEVICE_SHUTDOWN:
		*bl += sprintf(b + *bl, "SHUTDOWN");
		break;
	case TRANSPORT_DEVICE_OFFLINE_ACTIVATED:
	case TRANSPORT_DEVICE_OFFLINE_DEACTIVATED:
		*bl += sprintf(b + *bl, "OFFLINE");
		break;
	default:
		*bl += sprintf(b + *bl, "UNKNOWN=%d", dev->dev_status);
		break;
	}

	*bl += sprintf(b + *bl, "  Execute/Left/Max Queue Depth: %d/%d/%d",
		atomic_read(&dev->execute_tasks), atomic_read(&dev->depth_left),
		dev->queue_depth);
	*bl += sprintf(b + *bl, "  SectorSize: %u  MaxSectors: %u\n",
		DEV_ATTRIB(dev)->block_size, DEV_ATTRIB(dev)->max_sectors);
	*bl += sprintf(b + *bl, "        ");
}

void transport_dump_dev_info(
	struct se_device *dev,
	struct se_lun *lun,
	unsigned long long total_bytes,
	char *b,        /* Pointer to info buffer */
	int *bl)
{
	struct se_hba *hba = dev->se_hba;
	struct se_subsystem_api *t = hba->transport;

	t->get_dev_info(dev, b, bl);
	*bl += sprintf(b + *bl, "        ");
	*bl += sprintf(b + *bl, "Type: %s ",
		scsi_device_type(TRANSPORT(dev)->get_device_type(dev)));
	*bl += sprintf(b + *bl, "ANSI SCSI revision: %02x  ",
		TRANSPORT(dev)->get_device_rev(dev));

	if (DEV_T10_WWN(dev)) {
		struct t10_wwn *wwn = DEV_T10_WWN(dev);

		*bl += sprintf(b + *bl, "Unit Serial: %s  ",
			((strlen(wwn->unit_serial) != 0) ?
			(char *)wwn->unit_serial : "None"));
	}
	*bl += sprintf(b + *bl, "%s", "DIRECT");

	if (atomic_read(&dev->dev_access_obj.obj_access_count))
		*bl += sprintf(b + *bl, "  ACCESSED\n");
	else if (atomic_read(&dev->dev_export_obj.obj_access_count))
		*bl += sprintf(b + *bl, "  EXPORTED\n");
	else
		*bl += sprintf(b + *bl, "  FREE\n");

	if (lun) {
		*bl += sprintf(b + *bl, "        Core Host ID: %u LUN: %u",
			dev->se_hba->hba_id, lun->unpacked_lun);
		if (!(TRANSPORT(dev)->get_device_type(dev))) {
			*bl += sprintf(b + *bl, "  Active Cmds: %d  Total Bytes"
				": %llu\n", atomic_read(&dev->active_cmds),
			total_bytes);
		} else {
			*bl += sprintf(b + *bl, "  Active Cmds: %d\n",
				atomic_read(&dev->active_cmds));
		}
	} else {
		if (!(TRANSPORT(dev)->get_device_type(dev))) {
			*bl += sprintf(b + *bl, "        Core Host ID: %u"
				"  Active Cmds: %d  Total Bytes: %llu\n",
				dev->se_hba->hba_id,
				atomic_read(&dev->active_cmds), total_bytes);
		} else {
			*bl += sprintf(b + *bl, "        CoreI Host ID: %u"
				"  Active Cmds: %d\n", dev->se_hba->hba_id,
				atomic_read(&dev->active_cmds));
		}
	}
}

/*	transport_release_all_cmds():
 *
 *
 */
static void transport_release_all_cmds(struct se_device *dev)
{
	struct se_cmd *cmd = NULL;
	struct se_queue_req *qr = NULL, *qr_p = NULL;
	int bug_out = 0, t_state;
	unsigned long flags;

	spin_lock_irqsave(&dev->dev_queue_obj->cmd_queue_lock, flags);
	list_for_each_entry_safe(qr, qr_p, &dev->dev_queue_obj->qobj_list,
				qr_list) {

		cmd = (struct se_cmd *)qr->cmd;
		t_state = qr->state;
		list_del(&qr->qr_list);
		kfree(qr);
		spin_unlock_irqrestore(&dev->dev_queue_obj->cmd_queue_lock,
				flags);

		printk(KERN_ERR "Releasing %s ITT: 0x%08x, i_state: %u,"
			" t_state: %u directly\n",
			(cmd->se_cmd_flags & SCF_CMD_PASSTHROUGH) ?
			"Passthrough" : "Normal",
			CMD_TFO(cmd)->get_task_tag(cmd),
			CMD_TFO(cmd)->get_cmd_state(cmd), t_state);

		transport_release_fe_cmd(cmd);
		bug_out = 1;

		spin_lock_irqsave(&dev->dev_queue_obj->cmd_queue_lock, flags);
	}
	spin_unlock_irqrestore(&dev->dev_queue_obj->cmd_queue_lock, flags);
#if 0
	if (bug_out)
		BUG();
#endif
}

/*	transport_dev_write_pending_nop():
 *
 *
 */
static int transport_dev_write_pending_nop(struct se_task *task)
{
	return 0;
}

static int transport_get_inquiry(
	struct t10_wwn *wwn,
	void *obj_ptr)
{
	struct se_cmd *cmd;
	unsigned char *buf;
	int i;
	unsigned char cdb[SCSI_CDB_SIZE];

	memset(cdb, 0, SCSI_CDB_SIZE);
	cdb[0] = INQUIRY;
	cdb[3] = (INQUIRY_LEN >> 8) & 0xff;
	cdb[4] = (INQUIRY_LEN & 0xff);

	cmd = transport_allocate_passthrough(&cdb[0],  SE_DIRECTION_READ,
			0, NULL, 0, INQUIRY_LEN, obj_ptr);
	if (!(cmd))
		return -1;

	if (transport_generic_passthrough(cmd) < 0) {
		transport_passthrough_release(cmd);
		return -1;
	}

	buf = (unsigned char *)T_TASK(cmd)->t_task_buf;
	/*
	 * Save the basic Vendor, Model and Revision in passed struct t10_wwn.
	 * We will obtain the VPD in a seperate passthrough operation.
	 */
	memcpy((void *)&wwn->vendor[0], (void *)&buf[8],
			sizeof(wwn->vendor));
	memcpy((void *)&wwn->model[0], (void *)&buf[16],
			sizeof(wwn->model));
	memcpy((void *)&wwn->revision[0], (void *)&buf[32],
			sizeof(wwn->revision));

	printk("  Vendor: ");
	for (i = 8; i < 16; i++)
		if (buf[i] >= 0x20 && i < buf[4] + 5)
			printk("%c", buf[i]);
		else
			printk(" ");

	printk("  Model: ");
	for (i = 16; i < 32; i++)
		if (buf[i] >= 0x20 && i < buf[4] + 5)
			printk("%c", buf[i]);
		else
			printk(" ");

	printk("  Revision: ");
	for (i = 32; i < 36; i++)
		if (buf[i] >= 0x20 && i < buf[4] + 5)
			printk("%c", buf[i]);
		else
			printk(" ");

	printk("\n");

	i = buf[0] & 0x1f;

	printk("  Type:   %s ", scsi_device_type(i));
	printk("                 ANSI SCSI revision: %02x",
				buf[2] & 0x07);
	if ((buf[2] & 0x07) == 1 && (buf[3] & 0x0f) == 1)
		printk(" CCS\n");
	else
		printk("\n");

	transport_passthrough_release(cmd);
	return 0;
}

static int transport_get_inquiry_vpd_serial(
	struct t10_wwn *wwn,
	void *obj_ptr)
{
	unsigned char *buf;
	struct se_cmd *cmd;
	unsigned char cdb[SCSI_CDB_SIZE];

	memset(cdb, 0, SCSI_CDB_SIZE);
	cdb[0] = INQUIRY;
	cdb[1] = 0x01; /* Query VPD */
	cdb[2] = 0x80; /* Unit Serial Number */
	cdb[3] = (INQUIRY_VPD_SERIAL_LEN >> 8) & 0xff;
	cdb[4] = (INQUIRY_VPD_SERIAL_LEN & 0xff);

	cmd = transport_allocate_passthrough(&cdb[0], SE_DIRECTION_READ,
			0, NULL, 0, INQUIRY_VPD_SERIAL_LEN, obj_ptr);
	if (!(cmd))
		return -1;

	if (transport_generic_passthrough(cmd) < 0) {
		transport_passthrough_release(cmd);
		return -1;
	}

	buf = (unsigned char *)T_TASK(cmd)->t_task_buf;

	printk(KERN_INFO "T10 VPD Unit Serial Number: %s\n", &buf[4]);
	snprintf(&wwn->unit_serial[0], INQUIRY_VPD_SERIAL_LEN, "%s", &buf[4]);

	transport_passthrough_release(cmd);
	return 0;
}

static const char hex_str[] = "0123456789abcdef";

void transport_dump_vpd_proto_id(
	struct t10_vpd *vpd,
	unsigned char *p_buf,
	int p_buf_len)
{
	unsigned char buf[VPD_TMP_BUF_SIZE];
	int len;

	memset(buf, 0, VPD_TMP_BUF_SIZE);
	len = sprintf(buf, "T10 VPD Protocol Identifier: ");

	switch (vpd->protocol_identifier) {
	case 0x00:
		sprintf(buf+len, "Fibre Channel\n");
		break;
	case 0x10:
		sprintf(buf+len, "Parallel SCSI\n");
		break;
	case 0x20:
		sprintf(buf+len, "SSA\n");
		break;
	case 0x30:
		sprintf(buf+len, "IEEE 1394\n");
		break;
	case 0x40:
		sprintf(buf+len, "SCSI Remote Direct Memory Access"
				" Protocol\n");
		break;
	case 0x50:
		sprintf(buf+len, "Internet SCSI (iSCSI)\n");
		break;
	case 0x60:
		sprintf(buf+len, "SAS Serial SCSI Protocol\n");
		break;
	case 0x70:
		sprintf(buf+len, "Automation/Drive Interface Transport"
				" Protocol\n");
		break;
	case 0x80:
		sprintf(buf+len, "AT Attachment Interface ATA/ATAPI\n");
		break;
	default:
		sprintf(buf+len, "Unknown 0x%02x\n",
				vpd->protocol_identifier);
		break;
	}

	if (p_buf)
		strncpy(p_buf, buf, p_buf_len);
	else
		printk(KERN_INFO "%s", buf);
}

void transport_set_vpd_proto_id(struct t10_vpd *vpd, unsigned char *page_83)
{
	/*
	 * Check if the Protocol Identifier Valid (PIV) bit is set..
	 *
	 * from spc3r23.pdf section 7.5.1
	 */
	if (page_83[1] & 0x80) {
		vpd->protocol_identifier = (page_83[0] & 0xf0);
		vpd->protocol_identifier_set = 1;
		transport_dump_vpd_proto_id(vpd, NULL, 0);
	}
}

int transport_dump_vpd_assoc(
	struct t10_vpd *vpd,
	unsigned char *p_buf,
	int p_buf_len)
{
	unsigned char buf[VPD_TMP_BUF_SIZE];
	int ret = 0, len;

	memset(buf, 0, VPD_TMP_BUF_SIZE);
	len = sprintf(buf, "T10 VPD Identifier Association: ");

	switch (vpd->association) {
	case 0x00:
		sprintf(buf+len, "addressed logical unit\n");
		break;
	case 0x10:
		sprintf(buf+len, "target port\n");
		break;
	case 0x20:
		sprintf(buf+len, "SCSI target device\n");
		break;
	default:
		sprintf(buf+len, "Unknown 0x%02x\n", vpd->association);
		ret = -1;
		break;
	}

	if (p_buf)
		strncpy(p_buf, buf, p_buf_len);
	else
		printk("%s", buf);

	return ret;
}

static int transport_set_vpd_assoc(struct t10_vpd *vpd, unsigned char *page_83)
{
	/*
	 * The VPD identification association..
	 *
	 * from spc3r23.pdf Section 7.6.3.1 Table 297
	 */
	vpd->association = (page_83[1] & 0x30);
	return transport_dump_vpd_assoc(vpd, NULL, 0);
}

int transport_dump_vpd_ident_type(
	struct t10_vpd *vpd,
	unsigned char *p_buf,
	int p_buf_len)
{
	unsigned char buf[VPD_TMP_BUF_SIZE];
	int ret = 0, len;

	memset(buf, 0, VPD_TMP_BUF_SIZE);
	len = sprintf(buf, "T10 VPD Identifier Type: ");

	switch (vpd->device_identifier_type) {
	case 0x00:
		sprintf(buf+len, "Vendor specific\n");
		break;
	case 0x01:
		sprintf(buf+len, "T10 Vendor ID based\n");
		break;
	case 0x02:
		sprintf(buf+len, "EUI-64 based\n");
		break;
	case 0x03:
		sprintf(buf+len, "NAA\n");
		break;
	case 0x04:
		sprintf(buf+len, "Relative target port identifier\n");
		break;
	case 0x08:
		sprintf(buf+len, "SCSI name string\n");
		break;
	default:
		sprintf(buf+len, "Unsupported: 0x%02x\n",
				vpd->device_identifier_type);
		ret = -1;
		break;
	}

	if (p_buf)
		strncpy(p_buf, buf, p_buf_len);
	else
		printk("%s", buf);

	return ret;
}

int transport_set_vpd_ident_type(struct t10_vpd *vpd, unsigned char *page_83)
{
	/*
	 * The VPD identifier type..
	 *
	 * from spc3r23.pdf Section 7.6.3.1 Table 298
	 */
	vpd->device_identifier_type = (page_83[1] & 0x0f);
	return transport_dump_vpd_ident_type(vpd, NULL, 0);
}

int transport_dump_vpd_ident(
	struct t10_vpd *vpd,
	unsigned char *p_buf,
	int p_buf_len)
{
	unsigned char buf[VPD_TMP_BUF_SIZE];
	int ret = 0;

	memset(buf, 0, VPD_TMP_BUF_SIZE);

	switch (vpd->device_identifier_code_set) {
	case 0x01: /* Binary */
		sprintf(buf, "T10 VPD Binary Device Identifier: %s\n",
			&vpd->device_identifier[0]);
		break;
	case 0x02: /* ASCII */
		sprintf(buf, "T10 VPD ASCII Device Identifier: %s\n",
			&vpd->device_identifier[0]);
		break;
	case 0x03: /* UTF-8 */
		sprintf(buf, "T10 VPD UTF-8 Device Identifier: %s\n",
			&vpd->device_identifier[0]);
		break;
	default:
		sprintf(buf, "T10 VPD Device Identifier encoding unsupported:"
			" 0x%02x", vpd->device_identifier_code_set);
		ret = -1;
		break;
	}

	if (p_buf)
		strncpy(p_buf, buf, p_buf_len);
	else
		printk("%s", buf);

	return ret;
}

int transport_set_vpd_ident(struct t10_vpd *vpd, unsigned char *page_83)
{
	int j = 0, i = 4; /* offset to start of the identifer */

	/*
	 * The VPD Code Set (encoding)
	 *
	 * from spc3r23.pdf Section 7.6.3.1 Table 296
	 */
	vpd->device_identifier_code_set = (page_83[0] & 0x0f);
	switch (vpd->device_identifier_code_set) {
	case 0x01: /* Binary */
		vpd->device_identifier[j++] =
				hex_str[vpd->device_identifier_type];
		while (i < (4 + page_83[3])) {
			vpd->device_identifier[j++] =
				hex_str[(page_83[i] & 0xf0) >> 4];
			vpd->device_identifier[j++] =
				hex_str[page_83[i] & 0x0f];
			i++;
		}
		break;
	case 0x02: /* ASCII */
	case 0x03: /* UTF-8 */
		while (i < (4 + page_83[3]))
			vpd->device_identifier[j++] = page_83[i++];

		break;
	default:
		break;
	}

	return transport_dump_vpd_ident(vpd, NULL, 0);
}

static int transport_get_inquiry_vpd_device_ident(
	struct t10_wwn *wwn,
	void *obj_ptr)
{
	unsigned char *buf, *page_83;
	struct se_cmd *cmd;
	struct t10_vpd *vpd;
	unsigned char cdb[SCSI_CDB_SIZE];
	int ident_len, page_len, off = 4, ret = 0;

	memset(cdb, 0, SCSI_CDB_SIZE);
	cdb[0] = INQUIRY;
	cdb[1] = 0x01; /* Query VPD */
	cdb[2] = 0x83; /* Device Identifier */
	cdb[3] = (INQUIRY_VPD_DEVICE_IDENTIFIER_LEN >> 8) & 0xff;
	cdb[4] = (INQUIRY_VPD_DEVICE_IDENTIFIER_LEN & 0xff);

	cmd = transport_allocate_passthrough(&cdb[0], SE_DIRECTION_READ,
			0, NULL, 0, INQUIRY_VPD_DEVICE_IDENTIFIER_LEN,
			obj_ptr);
	if (!(cmd))
		return -1;

	if (transport_generic_passthrough(cmd) < 0) {
		transport_passthrough_release(cmd);
		return -1;
	}

	buf = (unsigned char *)T_TASK(cmd)->t_task_buf;
	page_len = (buf[2] << 8) | buf[3];
	printk("T10 VPD Page Length: %d\n", page_len);

	while (page_len > 0) {
		/* Grab a pointer to the Identification descriptor */
		page_83 = &buf[off];
		ident_len = page_83[3];
		if (!(ident_len)) {
			printk(KERN_ERR "page_83[3]: identifier"
					" length zero!\n");
			break;
		}
		printk(KERN_INFO "T10 VPD Identifer Length: %d\n", ident_len);

		vpd = kzalloc(sizeof(struct t10_vpd), GFP_KERNEL);
		if (!(vpd)) {
			printk(KERN_ERR "Unable to allocate memory for"
					" struct t10_vpd\n");
			ret = -1;
			goto out;
		}
		INIT_LIST_HEAD(&vpd->vpd_list);

		transport_set_vpd_proto_id(vpd, page_83);
		transport_set_vpd_assoc(vpd, page_83);

		if (transport_set_vpd_ident_type(vpd, page_83) < 0) {
			off += (ident_len + 4);
			page_len -= (ident_len + 4);
			kfree(vpd);
			continue;
		}
		if (transport_set_vpd_ident(vpd, page_83) < 0) {
			off += (ident_len + 4);
			page_len -= (ident_len + 4);
			kfree(vpd);
			continue;
		}

		list_add_tail(&vpd->vpd_list, &wwn->t10_vpd_list);
		off += (ident_len + 4);
		page_len -= (ident_len + 4);
	}
out:
	transport_passthrough_release(cmd);
	return 0;
}

int transport_rescan_evpd_device_ident(
	struct se_device *dev)
{
	se_release_vpd_for_dev(dev);
	transport_get_inquiry_vpd_device_ident(DEV_T10_WWN(dev), (void *)dev);
	return 0;
}

static int transport_get_read_capacity(struct se_device *dev)
{
	unsigned char cdb[SCSI_CDB_SIZE], *buf;
	u32 blocks, v1, v2;
	struct se_cmd *cmd;
	unsigned long long blocks_long;

	memset(cdb, 0, SCSI_CDB_SIZE);
	cdb[0] = 0x25; /* READ_CAPACITY */

	cmd = transport_allocate_passthrough(&cdb[0], SE_DIRECTION_READ,
			0, NULL, 0, READ_CAP_LEN, (void *)dev);
	if (!(cmd))
		return -1;

	if (transport_generic_passthrough(cmd) < 0) {
		transport_passthrough_release(cmd);
		return -1;
	}

	buf = (unsigned char *)T_TASK(cmd)->t_task_buf;
	blocks = (buf[0] << 24) | (buf[1] << 16) | (buf[2] << 8) | buf[3];

	transport_passthrough_release(cmd);

	if (blocks != 0xFFFFFFFF) {
		dev->dev_sectors_total = blocks;
		dev->dev_generate_cdb = &split_cdb_RW_10;
		return 0;
	}

	printk(KERN_INFO "READ_CAPACITY returned 0xFFFFFFFF, issuing"
			" SAI_READ_CAPACITY_16\n");

	memset(cdb, 0, SCSI_CDB_SIZE);
	cdb[0] = 0x9e; /* SERVICE_ACTION_IN */
	cdb[1] = 0x10; /* SAI_READ_CAPACITY_16 */
	cdb[13] = 12;

	cmd = transport_allocate_passthrough(&cdb[0], SE_DIRECTION_READ,
			0, NULL, 0, 12, (void *)dev);
	if (!(cmd))
		return -1;

	if (transport_generic_passthrough(cmd) < 0) {
		transport_passthrough_release(cmd);
		return -1;
	}

	buf = (unsigned char *)T_TASK(cmd)->t_task_buf;
	v1 = (buf[0] << 24) | (buf[1] << 16) | (buf[2] << 8) | buf[3];
	v2 = (buf[4] << 24) | (buf[5] << 16) | (buf[6] << 8) | buf[7];
	blocks_long = ((unsigned long long)v2 | (unsigned long long)v1 << 32);

	transport_passthrough_release(cmd);

	dev->dev_sectors_total = blocks_long;
	dev->dev_generate_cdb = &split_cdb_RW_16;

	return 0;
}

static void core_setup_task_attr_emulation(struct se_device *dev)
{
	/*
	 * If this device is from Target_Core_Mod/pSCSI, disable the
	 * SAM Task Attribute emulation.
	 *
	 * This is currently not available in upsream Linux/SCSI Target
	 * mode code, and is assumed to be disabled while using TCM/pSCSI.
	 */
	if (TRANSPORT(dev)->transport_type == TRANSPORT_PLUGIN_PHBA_PDEV) {
		dev->dev_task_attr_type = SAM_TASK_ATTR_PASSTHROUGH;
		return;
	}

	dev->dev_task_attr_type = SAM_TASK_ATTR_EMULATED;
	DEBUG_STA("%s: Using SAM_TASK_ATTR_EMULATED for SPC: 0x%02x"
		" device\n", TRANSPORT(dev)->name,
		TRANSPORT(dev)->get_device_rev(dev));
}

/*	transport_add_device_to_core_hba():
 *
 *	Note that some plugins (IBLOCK) will pass device_flags ==
 *	DF_CLAIMED_BLOCKDEV signifying OS that a dependent block_device
 *	has been claimed.  In exception cases we will release said
 *	block_device ourselves.
 */
struct se_device *transport_add_device_to_core_hba(
	struct se_hba *hba,
	struct se_subsystem_api *transport,
	struct se_subsystem_dev *se_dev,
	u32 device_flags,
	void *transport_dev)
{
	int ret = 0, force_pt;
	struct se_device  *dev;

	dev = kzalloc(sizeof(struct se_device), GFP_KERNEL);
	if (!(dev)) {
		printk(KERN_ERR "Unable to allocate memory for se_dev_t\n");
		return NULL;
	}
	dev->dev_queue_obj = kzalloc(sizeof(struct se_queue_obj), GFP_KERNEL);
	if (!(dev->dev_queue_obj)) {
		printk(KERN_ERR "Unable to allocate memory for"
				" dev->dev_queue_obj\n");
		kfree(dev);
		return NULL;
	}
	transport_init_queue_obj(dev->dev_queue_obj);

	dev->dev_status_queue_obj = kzalloc(sizeof(struct se_queue_obj),
					GFP_KERNEL);
	if (!(dev->dev_status_queue_obj)) {
		printk(KERN_ERR "Unable to allocate memory for"
				" dev->dev_status_queue_obj\n");
		kfree(dev->dev_queue_obj);
		kfree(dev);
		return NULL;
	}
	transport_init_queue_obj(dev->dev_status_queue_obj);

	dev->dev_flags		= device_flags;
	dev->dev_status		|= TRANSPORT_DEVICE_DEACTIVATED;
	dev->type		= transport->type;
	dev->dev_ptr		= (void *) transport_dev;
	dev->se_hba		= hba;
	dev->se_sub_dev		= se_dev;
	dev->transport		= transport;
	atomic_set(&dev->active_cmds, 0);
	INIT_LIST_HEAD(&dev->dev_list);
	INIT_LIST_HEAD(&dev->dev_sep_list);
	INIT_LIST_HEAD(&dev->dev_tmr_list);
	INIT_LIST_HEAD(&dev->execute_task_list);
	INIT_LIST_HEAD(&dev->delayed_cmd_list);
	INIT_LIST_HEAD(&dev->ordered_cmd_list);
	INIT_LIST_HEAD(&dev->state_task_list);
	spin_lock_init(&dev->execute_task_lock);
	spin_lock_init(&dev->delayed_cmd_lock);
	spin_lock_init(&dev->ordered_cmd_lock);
	spin_lock_init(&dev->state_task_lock);
	spin_lock_init(&dev->dev_alua_lock);
	spin_lock_init(&dev->dev_reservation_lock);
	spin_lock_init(&dev->dev_status_lock);
	spin_lock_init(&dev->dev_status_thr_lock);
	spin_lock_init(&dev->se_port_lock);
	spin_lock_init(&dev->se_tmr_lock);

	dev->queue_depth	= TRANSPORT(dev)->get_queue_depth(dev);
	atomic_set(&dev->depth_left, dev->queue_depth);
	atomic_set(&dev->dev_ordered_id, 0);

	se_dev_set_default_attribs(dev);

	dev->write_pending = (transport->write_pending) ?
		transport->write_pending : &transport_dev_write_pending_nop;

	dev->dev_index = scsi_get_new_index(SCSI_DEVICE_INDEX);
	dev->creation_time = get_jiffies_64();
	spin_lock_init(&dev->stats_lock);

	spin_lock(&hba->device_lock);
	list_add_tail(&dev->dev_list, &hba->hba_dev_list);
	hba->dev_count++;
	spin_unlock(&hba->device_lock);
	/*
	 * Setup the SAM Task Attribute emulation for struct se_device
	 */
	core_setup_task_attr_emulation(dev);
	/*
	 * Force PR and ALUA passthrough emulation with internal object use.
	 */
	force_pt = (hba->hba_flags & HBA_FLAGS_INTERNAL_USE);
	/*
	 * Setup the Reservations infrastructure for struct se_device
	 */
	core_setup_reservations(dev, force_pt);
	/*
	 * Setup the Asymmetric Logical Unit Assignment for struct se_device
	 */
	if (core_setup_alua(dev, force_pt) < 0)
		goto out;
	/*
	 * Startup the struct se_device processing thread
	 */
	if (transport_generic_activate_device(dev) < 0)
		goto out;

	ret = transport_get_inquiry(DEV_T10_WWN(dev), (void *)dev);
	if (ret < 0)
		goto out;
	/*
	 * Locate VPD WWN Information used for various purposes within
	 * the Storage Engine.
	 */
	if (!(transport_get_inquiry_vpd_serial(DEV_T10_WWN(dev),
				(void *)dev))) {
		/*
		 * If VPD Unit Serial returned GOOD status, try
		 * VPD Device Identification page (0x83).
		 */
		transport_get_inquiry_vpd_device_ident(DEV_T10_WWN(dev),
					(void *)dev);
	}

	/*
	 * Only perform the volume scan for peripheral type TYPE_DISK
	 */
	if (TRANSPORT(dev)->get_device_type(dev) != 0)
		return dev;

	/*
	 * Get the sector count via READ_CAPACITY
	 */
	ret = transport_get_read_capacity(dev);
	if (ret < 0)
		goto out;
out:
	if (!ret)
		return dev;
	/*
	 * Release newly allocated state for struct se_device
	 */
	transport_generic_deactivate_device(dev);

	spin_lock(&hba->device_lock);
	list_del(&dev->dev_list);
	hba->dev_count--;
	spin_unlock(&hba->device_lock);

	se_release_vpd_for_dev(dev);

	kfree(dev->dev_status_queue_obj);
	kfree(dev->dev_queue_obj);
	kfree(dev);

	return NULL;
}
EXPORT_SYMBOL(transport_add_device_to_core_hba);

/*	transport_generic_activate_device():
 *
 *
 */
int transport_generic_activate_device(struct se_device *dev)
{
	char name[16];

	if (TRANSPORT(dev)->activate_device)
		TRANSPORT(dev)->activate_device(dev);

	memset(name, 0, 16);
	snprintf(name, 16, "LIO_%s", TRANSPORT(dev)->name);

	dev->process_thread = kthread_run(transport_processing_thread,
			(void *)dev, name);
	if (IS_ERR(dev->process_thread)) {
		printk(KERN_ERR "Unable to create kthread: %s\n", name);
		return -1;
	}

	wait_for_completion(&dev->dev_queue_obj->thread_create_comp);

	return 0;
}

/*	transport_generic_deactivate_device():
 *
 *
 */
void transport_generic_deactivate_device(struct se_device *dev)
{
	if (TRANSPORT(dev)->deactivate_device)
		TRANSPORT(dev)->deactivate_device(dev);

	kthread_stop(dev->process_thread);

	wait_for_completion(&dev->dev_queue_obj->thread_done_comp);
}

/*	transport_generic_free_device():
 *
 *
 */
void transport_generic_free_device(struct se_device *dev)
{
	if (!(dev->dev_ptr))
		return;

	transport_generic_deactivate_device(dev);

	if (TRANSPORT(dev)->free_device)
		TRANSPORT(dev)->free_device(dev->dev_ptr);
}
EXPORT_SYMBOL(transport_generic_free_device);

static inline int transport_allocate_iovecs_for_cmd(
	struct se_cmd *cmd,
	u32 iov_count)
{
	cmd->iov_data = kzalloc(iov_count * sizeof(struct iovec), GFP_KERNEL);
	if (!(cmd->iov_data)) {
		printk(KERN_ERR "Unable to allocate memory for"
			" iscsi_cmd_t->iov_data.\n");
		return -1;
	}
	cmd->orig_iov_data_count = iov_count;

	return 0;
}

/*	transport_generic_allocate_iovecs():
 *
 *	Attached to struct target_core_fabric_ops->alloc_cmd_iovecs()
 *	for TCM fabric modules using Linux/NET with a struct iovec array.
 *
 *	Called by TCM fabric module in transport_generic_new_cmd() in
 *	transport processing thread context.
 */
int transport_generic_allocate_iovecs(
	struct se_cmd *cmd)
{
	u32 iov_count;

	iov_count = T_TASK(cmd)->t_task_se_num;
	if (!(iov_count))
		iov_count = 1;
#if 0
	printk(KERN_INFO "Allocated %d iovecs for ITT: 0x%08x t_task_se_num:"
		" %u\n", iov_count, CMD_TFO(cmd)->get_task_tag(cmd),
		T_TASK(cmd)->t_task_se_num);
#endif
	iov_count += TRANSPORT_IOV_DATA_BUFFER;

	return transport_allocate_iovecs_for_cmd(cmd, iov_count);
}
EXPORT_SYMBOL(transport_generic_allocate_iovecs);

/*	transport_generic_prepare_cdb():
 *
 *	Since the Initiator sees iSCSI devices as LUNs,  the SCSI CDB will
 *	contain the iSCSI LUN in bits 7-5 of byte 1 as per SAM-2.
 *	The point of this is since we are mapping iSCSI LUNs to
 *	SCSI Target IDs having a non-zero LUN in the CDB will throw the
 *	devices and HBAs for a loop.
 */
static inline void transport_generic_prepare_cdb(
	unsigned char *cdb)
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
		cdb[1] &= 0x1f; /* clear logical unit number */
		break;
	}
}

/*	transport_check_device_cdb_sector_count():
 *
 *	returns:
 *	0 on supported request sector count.
 *	1 on unsupported request sector count.
 */
static inline int transport_check_device_cdb_sector_count(
	void *se_obj_ptr,
	u32 sectors)
{
	u32 max_sectors;

	max_sectors = dev_obj_max_sectors(se_obj_ptr);
	if (!(max_sectors)) {
		printk(KERN_ERR "TRANSPORT->get_max_sectors returned zero!\n");
		return 1;
	}

	if (sectors > max_sectors)
		return -1;

	return 0;
}

/*	transport_generic_get_task():
 *
 *
 */
static struct se_task *transport_generic_get_task(
	struct se_transform_info *ti,
	struct se_cmd *cmd,
	void *se_obj_ptr)
{
	struct se_task *task;
	struct se_device *dev = SE_DEV(cmd);
	unsigned long flags;

	task = kmem_cache_zalloc(se_task_cache, GFP_KERNEL);
	if (!(task)) {
		printk(KERN_ERR "Unable to allocate struct se_task\n");
		return NULL;
	}

	INIT_LIST_HEAD(&task->t_list);
	INIT_LIST_HEAD(&task->t_execute_list);
	INIT_LIST_HEAD(&task->t_state_list);
	init_completion(&task->task_stop_comp);
	task->task_no = T_TASK(cmd)->t_task_no++;
	task->task_se_cmd = cmd;
	task->se_dev = dev;

	DEBUG_SO("se_obj_ptr: %p\n", se_obj_ptr);

	task->transport_req = TRANSPORT(dev)->allocate_request(task, dev);
	if (!(task->transport_req)) {
		kmem_cache_free(se_task_cache, task);
		return NULL;
	}

	spin_lock_irqsave(&T_TASK(cmd)->t_state_lock, flags);
	list_add_tail(&task->t_list, &T_TASK(cmd)->t_task_list);
	spin_unlock_irqrestore(&T_TASK(cmd)->t_state_lock, flags);

	task->se_obj_ptr = se_obj_ptr;

	return task;
}

static inline int transport_generic_obj_start(
	struct se_transform_info *ti,
	void *p,
	unsigned long long starting_lba)
{
	ti->ti_lba = starting_lba;
	ti->ti_obj_ptr = p;

	return 0;
}

static int transport_process_data_sg_transform(
	struct se_cmd *cmd,
	struct se_transform_info *ti)
{
	/*
	 * Already handled in transport_generic_get_cdb_count()
	 */
	return 0;
}

/*	transport_process_control_sg_transform():
 *
 *
 */
static int transport_process_control_sg_transform(
	struct se_cmd *cmd,
	struct se_transform_info *ti)
{
	unsigned char *cdb;
	struct se_task *task;
	struct se_mem *se_mem, *se_mem_lout = NULL;
	struct se_device *dev = SE_DEV(cmd);
	int ret;
	u32 se_mem_cnt = 0, task_offset = 0;

	list_for_each_entry(se_mem, T_TASK(cmd)->t_mem_list, se_list)
		break;

	if (!se_mem) {
		printk(KERN_ERR "se_mem is NULL!\n");
		return -1;
	}

	task = cmd->transport_get_task(ti, cmd, ti->se_obj_ptr);
	if (!(task))
		return -1;

	task->transport_map_task = dev_obj_get_map_SG(ti->se_obj_ptr,
				cmd->data_direction);

	cdb = TRANSPORT(dev)->get_cdb(task);
	if (cdb)
		memcpy(cdb, T_TASK(cmd)->t_task_cdb, SCSI_CDB_SIZE);

	task->task_size = cmd->data_length;
	task->task_sg_num = 1;

	atomic_inc(&T_TASK(cmd)->t_fe_count);
	atomic_inc(&T_TASK(cmd)->t_se_count);

	ret = dev_obj_do_se_mem_map(ti->se_obj_ptr, task,
			T_TASK(cmd)->t_mem_list, NULL, se_mem, &se_mem_lout,
			&se_mem_cnt, &task_offset);
	if (ret < 0)
		return ret;

	DEBUG_CDB_H("task_no[%u]: SCF_SCSI_CONTROL_SG_IO_CDB task_size: %d\n",
			task->task_no, task->task_size);
	return 0;
}

/*	transport_process_control_nonsg_transform():
 *
 *
 */
static int transport_process_control_nonsg_transform(
	struct se_cmd *cmd,
	struct se_transform_info *ti)
{
	struct se_device *dev = SE_DEV(cmd);
	unsigned char *cdb;
	struct se_task *task;

	task = cmd->transport_get_task(ti, cmd, ti->se_obj_ptr);
	if (!(task))
		return -1;

	task->transport_map_task = dev_obj_get_map_non_SG(ti->se_obj_ptr,
				cmd->data_direction);

	cdb = TRANSPORT(dev)->get_cdb(task);
	if (cdb)
		memcpy(cdb, T_TASK(cmd)->t_task_cdb, SCSI_CDB_SIZE);

	task->task_size = cmd->data_length;
	task->task_sg_num = 0;

	atomic_inc(&T_TASK(cmd)->t_fe_count);
	atomic_inc(&T_TASK(cmd)->t_se_count);

	DEBUG_CDB_H("task_no[%u]: SCF_SCSI_CONTROL_NONSG_IO_CDB task_size:"
			" %d\n", task->task_no, task->task_size);
	return 0;
}

/*	transport_process_non_data_transform():
 *
 *
 */
static int transport_process_non_data_transform(
	struct se_cmd *cmd,
	struct se_transform_info *ti)
{
	struct se_device *dev = SE_DEV(cmd);
	unsigned char *cdb;
	struct se_task *task;

	task = cmd->transport_get_task(ti, cmd, ti->se_obj_ptr);
	if (!(task))
		return -1;

	task->transport_map_task = dev_obj_get_map_none(ti->se_obj_ptr);

	cdb = TRANSPORT(dev)->get_cdb(task);
	if (cdb)
		memcpy(cdb, T_TASK(cmd)->t_task_cdb, SCSI_CDB_SIZE);

	task->task_size = cmd->data_length;
	task->task_sg_num = 0;

	atomic_inc(&T_TASK(cmd)->t_fe_count);
	atomic_inc(&T_TASK(cmd)->t_se_count);

	DEBUG_CDB_H("task_no[%u]: SCF_SCSI_NON_DATA_CDB task_size: %d\n",
			task->task_no, task->task_size);
	return 0;
}

static int transport_generic_cmd_sequencer(struct se_cmd *, unsigned char *);

void transport_device_setup_cmd(struct se_cmd *cmd)
{
	cmd->transport_add_cmd_to_queue = &transport_add_cmd_to_dev_queue;
	cmd->se_dev = SE_LUN(cmd)->se_dev;
}

struct se_cmd *__transport_alloc_se_cmd(
	struct target_core_fabric_ops *tfo,
	struct se_session *se_sess,
	void *fabric_cmd_ptr,
	u32 data_length,
	int data_direction,
	int task_attr)
{
	struct se_cmd *cmd;
	int gfp_type = (in_interrupt()) ? GFP_ATOMIC : GFP_KERNEL;

	if (data_direction == SE_DIRECTION_BIDI) {
		printk(KERN_ERR "SCSI BiDirectional mode not supported yet\n");
		return ERR_PTR(-ENOSYS);
	}

	cmd = kmem_cache_zalloc(se_cmd_cache, gfp_type);
	if (!(cmd)) {
		printk(KERN_ERR "kmem_cache_alloc() failed for se_cmd_cache\n");
		return ERR_PTR(-ENOMEM);
	}
	INIT_LIST_HEAD(&cmd->se_lun_list);
	INIT_LIST_HEAD(&cmd->se_delayed_list);
	INIT_LIST_HEAD(&cmd->se_ordered_list);

	cmd->t_task = kzalloc(sizeof(struct se_transport_task), gfp_type);
	if (!(cmd->t_task)) {
		printk(KERN_ERR "Unable to allocate cmd->t_task\n");
		kmem_cache_free(se_cmd_cache, cmd);
		return NULL;
	}

	cmd->sense_buffer = kzalloc(
			TRANSPORT_SENSE_BUFFER + tfo->get_fabric_sense_len(),
			gfp_type);
	if (!(cmd->sense_buffer)) {
		printk(KERN_ERR "Unable to allocate memory for"
			" cmd->sense_buffer\n");
		kfree(cmd->t_task);
		kmem_cache_free(se_cmd_cache, cmd);
		return NULL;
	}
	INIT_LIST_HEAD(&T_TASK(cmd)->t_task_list);
	init_completion(&T_TASK(cmd)->transport_lun_fe_stop_comp);
	init_completion(&T_TASK(cmd)->transport_lun_stop_comp);
	init_completion(&T_TASK(cmd)->t_transport_stop_comp);
	init_completion(&T_TASK(cmd)->t_transport_passthrough_comp);
	init_completion(&T_TASK(cmd)->t_transport_passthrough_wcomp);
	spin_lock_init(&T_TASK(cmd)->t_state_lock);
	atomic_set(&T_TASK(cmd)->transport_dev_active, 1);

	cmd->se_tfo = tfo;
	cmd->se_sess = se_sess;
	cmd->se_fabric_cmd_ptr = fabric_cmd_ptr;
	cmd->data_length = data_length;
	cmd->data_direction = data_direction;
	cmd->sam_task_attr = task_attr;

	return cmd;
}

int transport_check_alloc_task_attr(struct se_cmd *cmd)
{
	/*
	 * Check if SAM Task Attribute emulation is enabled for this
	 * struct se_device storage object
	 */
	if (SE_DEV(cmd)->dev_task_attr_type != SAM_TASK_ATTR_EMULATED)
		return 0;

	if (cmd->sam_task_attr == TASK_ATTR_ACA) {
		DEBUG_STA("SAM Task Attribute ACA"
			" emulation is not supported\n");
		return -1;
	}
	/*
	 * Used to determine when ORDERED commands should go from
	 * Dormant to Active status.
	 */
	cmd->se_ordered_id = atomic_inc_return(&SE_DEV(cmd)->dev_ordered_id);
	smp_mb__after_atomic_inc();
	DEBUG_STA("Allocated se_ordered_id: %u for Task Attr: 0x%02x on %s\n",
			cmd->se_ordered_id, cmd->sam_task_attr,
			TRANSPORT(cmd->se_dev)->name);
	return 0;
}

struct se_cmd *transport_alloc_se_cmd(
	struct target_core_fabric_ops *tfo_api,
	struct se_session *se_sess,
	void *fabric_cmd_ptr,
	u32 data_length,
	int data_direction,
	int task_attr)
{
	return __transport_alloc_se_cmd(tfo_api, se_sess, fabric_cmd_ptr,
				data_length, data_direction, task_attr);
}
EXPORT_SYMBOL(transport_alloc_se_cmd);

void transport_free_se_cmd(
	struct se_cmd *se_cmd)
{
	if (se_cmd->se_tmr_req)
		core_tmr_release_req(se_cmd->se_tmr_req);

	kfree(se_cmd->iov_data);
	kfree(se_cmd->sense_buffer);
	kfree(se_cmd->t_task);
	kmem_cache_free(se_cmd_cache, se_cmd);
}
EXPORT_SYMBOL(transport_free_se_cmd);

static void transport_generic_wait_for_tasks(struct se_cmd *, int, int);

/*	transport_generic_allocate_tasks():
 *
 *	Called from fabric RX Thread.
 */
int transport_generic_allocate_tasks(
	struct se_cmd *cmd,
	unsigned char *cdb)
{
	int non_data_cdb;

	transport_generic_prepare_cdb(cdb);

	/*
	 * This is needed for early exceptions.
	 */
	cmd->transport_wait_for_tasks = &transport_generic_wait_for_tasks;

	transport_device_setup_cmd(cmd);
	/*
	 * See if this is a CDB which follows SAM, also grab a function
	 * pointer to see if we need to do extra work.
	 */
	non_data_cdb = transport_generic_cmd_sequencer(cmd, cdb);
	if (non_data_cdb < 0)
		return -1;
	/*
	 * Copy the original CDB into T_TASK(cmd).
	 */
	memcpy(T_TASK(cmd)->t_task_cdb, cdb, SCSI_CDB_SIZE);
	/*
	 * Check for SAM Task Attribute Emulation
	 */
	if (transport_check_alloc_task_attr(cmd) < 0) {
		cmd->se_cmd_flags |= SCF_SCSI_CDB_EXCEPTION;
		cmd->scsi_sense_reason = INVALID_CDB_FIELD;
		return -2;
	}
	spin_lock(&cmd->se_lun->lun_sep_lock);
	if (cmd->se_lun->lun_sep)
		cmd->se_lun->lun_sep->sep_stats.cmd_pdus++;
	spin_unlock(&cmd->se_lun->lun_sep_lock);

	switch (non_data_cdb) {
	case TGCS_DATA_SG_IO_CDB:
		DEBUG_CDB_H("Set cdb[0]: 0x%02x to "
				"SCF_SCSI_DATA_SG_IO_CDB\n", cdb[0]);
		cmd->se_cmd_flags |= SCF_SCSI_DATA_SG_IO_CDB;

		/*
		 * Get the initial Logical Block Address from the Original
		 * Command Descriptor Block that arrived on the iSCSI wire.
		 */
		T_TASK(cmd)->t_task_lba = (cmd->transport_get_long_lba) ?
			cmd->transport_get_long_lba(cdb) :
			cmd->transport_get_lba(cdb);

		break;
	case TGCS_CONTROL_SG_IO_CDB:
		DEBUG_CDB_H("Set cdb[0]: 0x%02x to"
				" SCF_SCSI_CONTROL_SG_IO_CDB\n", cdb[0]);
		cmd->se_cmd_flags |= SCF_SCSI_CONTROL_SG_IO_CDB;
		cmd->transport_cdb_transform =
				&transport_process_control_sg_transform;
		break;
	case TGCS_CONTROL_NONSG_IO_CDB:
		DEBUG_CDB_H("Set cdb[0]: 0x%02x to "
				"SCF_SCSI_CONTROL_NONSG_IO_CDB\n", cdb[0]);
		cmd->se_cmd_flags |= SCF_SCSI_CONTROL_NONSG_IO_CDB;
		cmd->transport_cdb_transform =
				&transport_process_control_nonsg_transform;
		break;
	case TGCS_NON_DATA_CDB:
		DEBUG_CDB_H("Set cdb[0]: 0x%02x to "
				"SCF_SCSI_NON_DATA_CDB\n", cdb[0]);
		cmd->se_cmd_flags |= SCF_SCSI_NON_DATA_CDB;
		cmd->transport_cdb_transform =
				&transport_process_non_data_transform;
		break;
	case TGCS_UNSUPPORTED_CDB:
		DEBUG_CDB_H("Set cdb[0]: 0x%02x to"
				" SCF_SCSI_UNSUPPORTED_CDB\n", cdb[0]);
		cmd->se_cmd_flags |= SCF_SCSI_CDB_EXCEPTION;
		cmd->scsi_sense_reason = UNSUPPORTED_SCSI_OPCODE;
		return -2;
	case TGCS_RESERVATION_CONFLICT:
		DEBUG_CDB_H("Set cdb[0]: 0x%02x to"
				" SCF_SCSI_RESERVATION_CONFLICT\n", cdb[0]);
		cmd->se_cmd_flags |= SCF_SCSI_CDB_EXCEPTION;
		cmd->se_cmd_flags |= SCF_SCSI_RESERVATION_CONFLICT;
		cmd->scsi_status = SAM_STAT_RESERVATION_CONFLICT;
		/*
		 * For UA Interlock Code 11b, a RESERVATION CONFLICT will
		 * establish a UNIT ATTENTION with PREVIOUS RESERVATION
		 * CONFLICT STATUS.
		 *
		 * See spc4r17, section 7.4.6 Control Mode Page, Table 349
		 */
		if (SE_SESS(cmd) &&
		    DEV_ATTRIB(cmd->se_dev)->emulate_ua_intlck_ctrl == 2)
			core_scsi3_ua_allocate(SE_SESS(cmd)->se_node_acl,
				cmd->orig_fe_lun, 0x2C,
				ASCQ_2CH_PREVIOUS_RESERVATION_CONFLICT_STATUS);
		return -2;
	case TGCS_INVALID_CDB_FIELD:
		cmd->se_cmd_flags |= SCF_SCSI_CDB_EXCEPTION;
		cmd->scsi_sense_reason = INVALID_CDB_FIELD;
		return -2;
	case TGCS_ILLEGAL_REQUEST:
		cmd->se_cmd_flags |= SCF_SCSI_CDB_EXCEPTION;
		cmd->scsi_sense_reason = ILLEGAL_REQUEST;
		return -2;
	case TGCS_CHECK_CONDITION_UNIT_ATTENTION:
		cmd->se_cmd_flags |= SCF_SCSI_CDB_EXCEPTION;
		cmd->scsi_sense_reason = CHECK_CONDITION_UNIT_ATTENTION;
		return -2;
	case TGCS_CHECK_CONDITION_NOT_READY:
		cmd->se_cmd_flags |= SCF_SCSI_CDB_EXCEPTION;
		cmd->scsi_sense_reason = CHECK_CONDITION_NOT_READY;
		return -2;
	default:
		cmd->se_cmd_flags |= SCF_SCSI_CDB_EXCEPTION;
		cmd->scsi_sense_reason = UNSUPPORTED_SCSI_OPCODE;
		return -2;
	}

	return 0;
}
EXPORT_SYMBOL(transport_generic_allocate_tasks);

/*	transport_generic_handle_cdb():
 *
 *
 */
int transport_generic_handle_cdb(
	struct se_cmd *cmd)
{
	if (!SE_LUN(cmd)) {
		printk(KERN_ERR "SE_LUN(cmd) is NULL\n");
		return -1;
	}

	cmd->transport_add_cmd_to_queue(cmd, TRANSPORT_NEW_CMD);
	return 0;
}
EXPORT_SYMBOL(transport_generic_handle_cdb);

/*	transport_generic_handle_data():
 *
 *
 */
int transport_generic_handle_data(
	struct se_cmd *cmd)
{
	/*
	 * Make sure that the transport has been disabled by
	 * transport_write_pending() before readding this struct se_cmd to the
	 * processing queue.  If it has not yet been reset to zero by the
	 * processing thread in cmd->transport_add_cmd_to_queue(), let other
	 * processes run.  If a signal was received, then we assume the
	 * connection is being failed/shutdown, so we return a failure.
	 */
	while (atomic_read(&T_TASK(cmd)->t_transport_active)) {
		msleep_interruptible(10);
		if (signal_pending(current))
			return -1;
	}
	/*
	 * If the received CDB has aleady been ABORTED by the generic
	 * target engine, we now call transport_check_aborted_status()
	 * to queue any delated TASK_ABORTED status for the received CDB to the
	 * fabric module as we are expecting no futher incoming DATA OUT
	 * sequences at this point.
	 */
	if (transport_check_aborted_status(cmd, 1) != 0)
		return 0;

	cmd->transport_add_cmd_to_queue(cmd, TRANSPORT_PROCESS_WRITE);
	return 0;
}
EXPORT_SYMBOL(transport_generic_handle_data);

/*	transport_generic_handle_tmr():
 *
 *
 */
int transport_generic_handle_tmr(
	struct se_cmd *cmd)
{
	/*
	 * This is needed for early exceptions.
	 */
	cmd->transport_wait_for_tasks = &transport_generic_wait_for_tasks;
	transport_device_setup_cmd(cmd);

	cmd->transport_add_cmd_to_queue(cmd, TRANSPORT_PROCESS_TMR);
	return 0;
}
EXPORT_SYMBOL(transport_generic_handle_tmr);

/*	transport_stop_tasks_for_cmd():
 *
 *
 */
int transport_stop_tasks_for_cmd(struct se_cmd *cmd)
{
	struct se_task *task, *task_tmp;
	unsigned long flags;
	int ret = 0;

	DEBUG_TS("ITT[0x%08x] - Stopping tasks\n",
		CMD_TFO(cmd)->get_task_tag(cmd));

	/*
	 * No tasks remain in the execution queue
	 */
	spin_lock_irqsave(&T_TASK(cmd)->t_state_lock, flags);
	list_for_each_entry_safe(task, task_tmp,
				&T_TASK(cmd)->t_task_list, t_list) {
		DEBUG_TS("task_no[%d] - Processing task %p\n",
				task->task_no, task);
		/*
		 * If the struct se_task has not been sent and is not active,
		 * remove the struct se_task from the execution queue.
		 */
		if (!atomic_read(&task->task_sent) &&
		    !atomic_read(&task->task_active)) {
			spin_unlock_irqrestore(&T_TASK(cmd)->t_state_lock,
					flags);
			transport_remove_task_from_execute_queue(task,
					task->se_dev);

			DEBUG_TS("task_no[%d] - Removed from execute queue\n",
				task->task_no);
			spin_lock_irqsave(&T_TASK(cmd)->t_state_lock, flags);
			continue;
		}

		/*
		 * If the struct se_task is active, sleep until it is returned
		 * from the plugin.
		 */
		if (atomic_read(&task->task_active)) {
			atomic_set(&task->task_stop, 1);
			spin_unlock_irqrestore(&T_TASK(cmd)->t_state_lock,
					flags);

			DEBUG_TS("task_no[%d] - Waiting to complete\n",
				task->task_no);
			wait_for_completion(&task->task_stop_comp);
			DEBUG_TS("task_no[%d] - Stopped successfully\n",
				task->task_no);

			spin_lock_irqsave(&T_TASK(cmd)->t_state_lock, flags);
			atomic_dec(&T_TASK(cmd)->t_task_cdbs_left);

			atomic_set(&task->task_active, 0);
			atomic_set(&task->task_stop, 0);
		} else {
			DEBUG_TS("task_no[%d] - Did nothing\n", task->task_no);
			ret++;
		}

		__transport_stop_task_timer(task, &flags);
	}
	spin_unlock_irqrestore(&T_TASK(cmd)->t_state_lock, flags);

	return ret;
}

static void transport_failure_reset_queue_depth(struct se_device *dev)
{
	unsigned long flags;

	spin_lock_irqsave(&SE_HBA(dev)->hba_queue_lock, flags);;
	atomic_inc(&dev->depth_left);
	atomic_inc(&SE_HBA(dev)->left_queue_depth);
	spin_unlock_irqrestore(&SE_HBA(dev)->hba_queue_lock, flags);
}

/*	transport_generic_request_failure():
 *
 *	Handle SAM-esque emulation for generic transport request failures.
 */
void transport_generic_request_failure(
	struct se_cmd *cmd,
	struct se_device *dev,
	int complete,
	int sc)
{
	DEBUG_GRF("-----[ Storage Engine Exception for cmd: %p ITT: 0x%08x"
		" CDB: 0x%02x\n", cmd, CMD_TFO(cmd)->get_task_tag(cmd),
		T_TASK(cmd)->t_task_cdb[0]);
	DEBUG_GRF("-----[ i_state: %d t_state/def_t_state:"
		" %d/%d transport_error_status: %d\n",
		CMD_TFO(cmd)->get_cmd_state(cmd),
		cmd->t_state, cmd->deferred_t_state,
		cmd->transport_error_status);
	DEBUG_GRF("-----[ t_task_cdbs: %d t_task_cdbs_left: %d"
		" t_task_cdbs_sent: %d t_task_cdbs_ex_left: %d --"
		" t_transport_active: %d t_transport_stop: %d"
		" t_transport_sent: %d\n", T_TASK(cmd)->t_task_cdbs,
		atomic_read(&T_TASK(cmd)->t_task_cdbs_left),
		atomic_read(&T_TASK(cmd)->t_task_cdbs_sent),
		atomic_read(&T_TASK(cmd)->t_task_cdbs_ex_left),
		atomic_read(&T_TASK(cmd)->t_transport_active),
		atomic_read(&T_TASK(cmd)->t_transport_stop),
		atomic_read(&T_TASK(cmd)->t_transport_sent));

	transport_stop_all_task_timers(cmd);

	if (dev)
		transport_failure_reset_queue_depth(dev);
	/*
	 * For SAM Task Attribute emulation for failed struct se_cmd
	 */
	if (cmd->se_dev->dev_task_attr_type == SAM_TASK_ATTR_EMULATED)
		transport_complete_task_attr(cmd);

	if (complete) {
		transport_direct_request_timeout(cmd);
		cmd->transport_error_status = PYX_TRANSPORT_LU_COMM_FAILURE;
	}

	switch (cmd->transport_error_status) {
	case PYX_TRANSPORT_UNKNOWN_SAM_OPCODE:
		cmd->scsi_sense_reason = UNSUPPORTED_SCSI_OPCODE;
		break;
	case PYX_TRANSPORT_REQ_TOO_MANY_SECTORS:
		cmd->scsi_sense_reason = SECTOR_COUNT_TOO_MANY;
		break;
	case PYX_TRANSPORT_INVALID_CDB_FIELD:
		cmd->scsi_sense_reason = INVALID_CDB_FIELD;
		break;
	case PYX_TRANSPORT_INVALID_PARAMETER_LIST:
		cmd->scsi_sense_reason = INVALID_PARAMETER_LIST;
		break;
	case PYX_TRANSPORT_OUT_OF_MEMORY_RESOURCES:
		if (!(cmd->se_cmd_flags & SCF_CMD_PASSTHROUGH)) {
			if (!sc)
				transport_new_cmd_failure(cmd);
			/*
			 * Currently for PYX_TRANSPORT_OUT_OF_MEMORY_RESOURCES,
			 * we force this session to fall back to session
			 * recovery.
			 */
			CMD_TFO(cmd)->fall_back_to_erl0(cmd->se_sess);
			CMD_TFO(cmd)->stop_session(cmd->se_sess, 0, 0);

			goto check_stop;
		} else {
			cmd->scsi_sense_reason =
				LOGICAL_UNIT_COMMUNICATION_FAILURE;
		}
		break;
	case PYX_TRANSPORT_LU_COMM_FAILURE:
		cmd->scsi_sense_reason = LOGICAL_UNIT_COMMUNICATION_FAILURE;
		break;
	case PYX_TRANSPORT_UNKNOWN_MODE_PAGE:
		cmd->scsi_sense_reason = UNKNOWN_MODE_PAGE;
		break;
	case PYX_TRANSPORT_WRITE_PROTECTED:
		cmd->scsi_sense_reason = WRITE_PROTECTED;
		break;
	case PYX_TRANSPORT_RESERVATION_CONFLICT:
		/*
		 * No SENSE Data payload for this case, set SCSI Status
		 * and queue the response to $FABRIC_MOD.
		 *
		 * Uses linux/include/scsi/scsi.h SAM status codes defs
		 */
		cmd->scsi_status = SAM_STAT_RESERVATION_CONFLICT;
		/*
		 * For UA Interlock Code 11b, a RESERVATION CONFLICT will
		 * establish a UNIT ATTENTION with PREVIOUS RESERVATION
		 * CONFLICT STATUS.
		 *
		 * See spc4r17, section 7.4.6 Control Mode Page, Table 349
		 */
		if (SE_SESS(cmd) &&
		    DEV_ATTRIB(cmd->se_dev)->emulate_ua_intlck_ctrl == 2)
			core_scsi3_ua_allocate(SE_SESS(cmd)->se_node_acl,
				cmd->orig_fe_lun, 0x2C,
				ASCQ_2CH_PREVIOUS_RESERVATION_CONFLICT_STATUS);

		if (!(cmd->se_cmd_flags & SCF_CMD_PASSTHROUGH))
			CMD_TFO(cmd)->queue_status(cmd);

		goto check_stop;

	case PYX_TRANSPORT_ILLEGAL_REQUEST:
		cmd->scsi_sense_reason = ILLEGAL_REQUEST;
		break;
	default:
		printk(KERN_ERR "Unknown transport error for CDB 0x%02x: %d\n",
			T_TASK(cmd)->t_task_cdb[0],
			cmd->transport_error_status);
		cmd->scsi_sense_reason = UNSUPPORTED_SCSI_OPCODE;
		break;
	}

	if (!sc)
		transport_new_cmd_failure(cmd);
	else
		transport_send_check_condition_and_sense(cmd,
			cmd->scsi_sense_reason, 0);
check_stop:
	transport_lun_remove_cmd(cmd);
	if (!(transport_cmd_check_stop_to_fabric(cmd)))
		transport_passthrough_check_stop(cmd);
}

void transport_direct_request_timeout(struct se_cmd *cmd)
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
	spin_unlock_irqrestore(&T_TASK(cmd)->t_state_lock, flags);
}

void transport_generic_request_timeout(struct se_cmd *cmd)
{
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

	transport_generic_remove(cmd, 0, 0);
}

/* #define iscsi_linux_calculate_map_segment_DEBUG */
#ifdef iscsi_linux_calculate_map_segment_DEBUG
#define DEBUG_MAP_SEGMENTS(buf...) PYXPRINT(buf)
#else
#define DEBUG_MAP_SEGMENTS(buf...)
#endif

/*	transport_calculate_map_segment():
 *
 *
 */
static inline void transport_calculate_map_segment(
	u32 *data_length,
	struct se_offset_map *lm)
{
	u32 sg_offset = 0;
	struct se_mem *se_mem = lm->map_se_mem;

	DEBUG_MAP_SEGMENTS(" START Mapping se_mem: %p, Length: %d"
		"  Remaining iSCSI Data: %u\n", se_mem, se_mem->se_len,
		*data_length);
	/*
	 * Still working on pages in the current struct se_mem.
	 */
	if (!lm->map_reset) {
		lm->iovec_length = (lm->sg_length > PAGE_SIZE) ?
					PAGE_SIZE : lm->sg_length;
		if (*data_length < lm->iovec_length) {
			DEBUG_MAP_SEGMENTS("LINUX_MAP: Reset lm->iovec_length"
				" to %d\n", *data_length);

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

	DEBUG_MAP_SEGMENTS("LINUX_MAP1[%p]: Starting to se_mem->se_len: %u,"
		" se_mem->se_off: %u, se_mem->se_page: %p\n", se_mem,
		se_mem->se_len, se_mem->se_off, se_mem->se_page);;
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
			DEBUG_MAP_SEGMENTS("LINUX_MAP1[%p]: Reset"
				" lm->iovec_length to %d\n", se_mem,
				*data_length);
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
		DEBUG_MAP_SEGMENTS("LINUX_MAP3[%p]: Next Page:"
			" lm->current_offset: %u, iovec_length: %u"
			" sg_offset: %u\n", se_mem, lm->current_offset,
			lm->iovec_length, sg_offset);

		lm->current_offset -= lm->iovec_length;
		lm->sg_length -= lm->iovec_length;
		lm->sg_page++;
		sg_offset = 0;

		DEBUG_MAP_SEGMENTS("LINUX_MAP3[%p]: ** Skipping to Next Page,"
			" updated values: lm->current_offset: %u\n", se_mem,
			lm->current_offset);

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
	DEBUG_MAP_SEGMENTS("****** the OLD lm->iovec_length: %u lm->sg_length:"
		" %u\n", lm->iovec_length, lm->sg_length);

	if ((lm->iovec_length - lm->current_offset) < *data_length)
		lm->iovec_length -= lm->current_offset;
	else
		lm->iovec_length = *data_length;

	if ((lm->sg_length - lm->current_offset) < *data_length)
		lm->sg_length -= lm->current_offset;
	else
		lm->sg_length = *data_length;

	lm->current_offset = 0;

	DEBUG_MAP_SEGMENTS("****** the NEW lm->iovec_length %u lm->sg_length:"
		" %u\n", lm->iovec_length, lm->sg_length);
}

/* #define iscsi_linux_get_iscsi_offset_DEBUG */
#ifdef iscsi_linux_get_iscsi_offset_DEBUG
#define DEBUG_GET_ISCSI_OFFSET(buf...) PYXPRINT(buf)
#else
#define DEBUG_GET_ISCSI_OFFSET(buf...)
#endif

/*	transport_get_iscsi_offset():
 *
 *
 */
static int transport_get_iscsi_offset(
	struct se_offset_map *lmap,
	struct se_unmap_sg *usg)
{
	u32 current_length = 0, current_iscsi_offset = lmap->iscsi_offset;
	u32 total_offset = 0;
	struct se_cmd *cmd = usg->se_cmd;
	struct se_mem *se_mem;

	list_for_each_entry(se_mem, T_TASK(cmd)->t_mem_list, se_list)
		break;

	if (!se_mem) {
		printk(KERN_ERR "Unable to locate se_mem from"
				" T_TASK(cmd)->t_mem_list\n");
		return -1;
	}

	/*
	 * Locate the current offset from the passed iSCSI Offset.
	 */
	while (lmap->iscsi_offset != current_length) {
		/*
		 * The iSCSI Offset is within the current struct se_mem.
		 *
		 * Or:
		 *
		 * The iSCSI Offset is outside of the current struct se_mem.
		 * Recalculate the values and obtain the next struct se_mem pointer.
		 */
		total_offset += se_mem->se_len;

		DEBUG_GET_ISCSI_OFFSET("ISCSI_OFFSET: current_length: %u,"
			" total_offset: %u, sg->length: %u\n",
			current_length, total_offset, se_mem->se_len);

		if (total_offset > lmap->iscsi_offset) {
			current_length += current_iscsi_offset;
			lmap->orig_offset = lmap->current_offset =
				usg->t_offset = current_iscsi_offset;
			DEBUG_GET_ISCSI_OFFSET("ISCSI_OFFSET: Within Current"
				" struct se_mem: %p, current_length incremented to"
				" %u\n", se_mem, current_length);
		} else {
			current_length += se_mem->se_len;
			current_iscsi_offset -= se_mem->se_len;

			DEBUG_GET_ISCSI_OFFSET("ISCSI_OFFSET: Outside of"
				" Current se_mem: %p, current_length"
				" incremented to %u and current_iscsi_offset"
				" decremented to %u\n", se_mem, current_length,
				current_iscsi_offset);

			list_for_each_entry_continue(se_mem,
					T_TASK(cmd)->t_mem_list, se_list)
				break;

			if (!se_mem) {
				printk(KERN_ERR "Unable to locate struct se_mem\n");
				return -1;
			}
		}
	}
	lmap->map_orig_se_mem = se_mem;
	usg->cur_se_mem = se_mem;

	return 0;
}

/* #define iscsi_OS_set_SG_iovec_ptrs_DEBUG */
#ifdef iscsi_OS_set_SG_iovec_ptrs_DEBUG
#define DEBUG_IOVEC_SCATTERLISTS(buf...) PYXPRINT(buf)

static void iscsi_check_iovec_map(
	u32 iovec_count,
	u32 map_length,
	struct se_map_sg *map_sg,
	struct se_unmap_sg *unmap_sg)
{
	u32 i, iovec_map_length = 0;
	struct se_cmd *cmd = map_sg->se_cmd;
	struct iovec *iov = map_sg->iov;
	struct se_mem *se_mem;

	for (i = 0; i < iovec_count; i++)
		iovec_map_length += iov[i].iov_len;

	if (iovec_map_length == map_length)
		return;

	printk(KERN_INFO "Calculated iovec_map_length: %u does not match passed"
		" map_length: %u\n", iovec_map_length, map_length);
	printk(KERN_INFO "ITT: 0x%08x data_length: %u data_direction %d\n",
		CMD_TFO(cmd)->get_task_tag(cmd), cmd->data_length,
		cmd->data_direction);

	iovec_map_length = 0;

	for (i = 0; i < iovec_count; i++) {
		printk(KERN_INFO "iov[%d].iov_[base,len]: %p / %u bytes------"
			"-->\n", i, iov[i].iov_base, iov[i].iov_len);

		printk(KERN_INFO "iovec_map_length from %u to %u\n",
			iovec_map_length, iovec_map_length + iov[i].iov_len);
		iovec_map_length += iov[i].iov_len;

		printk(KERN_INFO "XXXX_map_length from %u to %u\n", map_length,
				(map_length - iov[i].iov_len));
		map_length -= iov[i].iov_len;
	}

	list_for_each_entry(se_mem, T_TASK(cmd)->t_mem_list, se_list) {
		printk(KERN_INFO "se_mem[%p]: offset: %u length: %u\n",
			se_mem, se_mem->se_off, se_mem->se_len);
	}

	BUG();
}

#else
#define DEBUG_IOVEC_SCATTERLISTS(buf...)
#define iscsi_check_iovec_map(a, b, c, d)
#endif

/*	transport_generic_set_iovec_ptrs():
 *
 *
 */
static int transport_generic_set_iovec_ptrs(
	struct se_map_sg *map_sg,
	struct se_unmap_sg *unmap_sg)
{
	u32 i = 0 /* For iovecs */, j = 0 /* For scatterlists */;
#ifdef iscsi_OS_set_SG_iovec_ptrs_DEBUG
	u32 orig_map_length = map_sg->data_length;
#endif
	struct se_cmd *cmd = map_sg->se_cmd;
	struct se_offset_map *lmap = &unmap_sg->lmap;
	struct iovec *iov = map_sg->iov;

	/*
	 * Used for non scatterlist operations, assume a single iovec.
	 */
	if (!T_TASK(cmd)->t_task_se_num) {
		DEBUG_IOVEC_SCATTERLISTS("ITT: 0x%08x No struct se_mem elements"
			" present\n", CMD_TFO(cmd)->get_task_tag(cmd));
		iov[0].iov_base = (unsigned char *) T_TASK(cmd)->t_task_buf +
							map_sg->data_offset;
		iov[0].iov_len  = map_sg->data_length;
		return 1;
	}

	/*
	 * Set lmap->map_reset = 1 so the first call to
	 * transport_calculate_map_segment() sets up the initial
	 * values for struct se_offset_map.
	 */
	lmap->map_reset = 1;

	DEBUG_IOVEC_SCATTERLISTS("[-------------------] ITT: 0x%08x OS"
		" Independent Network POSIX defined iovectors to SE Memory"
		" [-------------------]\n\n", CMD_TFO(cmd)->get_task_tag(cmd));

	/*
	 * Get a pointer to the first used scatterlist based on the passed
	 * offset. Also set the rest of the needed values in iscsi_linux_map_t.
	 */
	lmap->iscsi_offset = map_sg->data_offset;
	if (map_sg->map_flags & MAP_SG_KMAP) {
		unmap_sg->se_cmd = map_sg->se_cmd;
		transport_get_iscsi_offset(lmap, unmap_sg);
		unmap_sg->data_length = map_sg->data_length;
	} else {
		lmap->current_offset = lmap->orig_offset;
	}
	lmap->map_se_mem = lmap->map_orig_se_mem;

	DEBUG_IOVEC_SCATTERLISTS("OS_IOVEC: Total map_sg->data_length: %d,"
		" lmap->iscsi_offset: %d, cmd->orig_iov_data_count: %d\n",
		map_sg->data_length, lmap->iscsi_offset,
		cmd->orig_iov_data_count);

	while (map_sg->data_length) {
		/*
		 * Time to get the virtual address for use with iovec pointers.
		 * This function will return the expected iovec_base address
		 * and iovec_length.
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
			map_sg->data_length + iov[i].iov_len,
			map_sg->data_length);

		if ((++i + 1) > cmd->orig_iov_data_count) {
			printk(KERN_ERR "Current iovec count %u is greater than"
				" struct se_cmd->orig_data_iov_count %u, cannot"
				" continue.\n", i+1, cmd->orig_iov_data_count);
			return -1;
		}

		/*
		 * All done mapping this scatterlist's pages, move on to
		 * the next scatterlist by setting lmap.map_reset = 1;
		 */
		if (!lmap->sg_length || !map_sg->data_length) {
			list_for_each_entry(lmap->map_se_mem,
					&lmap->map_se_mem->se_list, se_list)
				break;

			if (!lmap->map_se_mem) {
				printk(KERN_ERR "Unable to locate next"
					" lmap->map_struct se_mem entry\n");
				return -1;
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

	return i;
}

/*	transport_generic_allocate_buf():
 *
 *	Called from transport_generic_new_cmd() in Transport Processing Thread.
 */
int transport_generic_allocate_buf(
	struct se_cmd *cmd,
	u32 data_length,
	u32 dma_size)
{
	unsigned char *buf;

	buf = kzalloc(data_length, GFP_KERNEL);
	if (!(buf)) {
		printk(KERN_ERR "Unable to allocate memory for buffer\n");
		return -1;
	}

	T_TASK(cmd)->t_task_se_num = 0;
	T_TASK(cmd)->t_task_buf = buf;

	return 0;
}

/*	transport_generic_allocate_none():
 *
 *
 */
static int transport_generic_allocate_none(
	struct se_cmd *cmd,
	u32 data_length,
	u32 dma_size)
{
	return 0;
}

/*	transport_generic_map_SG_segments():
 *
 *
 */
static void transport_generic_map_SG_segments(struct se_unmap_sg *unmap_sg)
{
	u32 i = 0;
	struct se_cmd *cmd = unmap_sg->se_cmd;
	struct se_mem *se_mem = unmap_sg->cur_se_mem;

	if (!(T_TASK(cmd)->t_task_se_num))
		return;

	list_for_each_entry_continue(se_mem, T_TASK(cmd)->t_mem_list, se_list) {
		kmap(se_mem->se_page);

		if (++i == unmap_sg->sg_count)
			break;
	}
}

/*	transport_generic_unmap_SG_segments():
 *
 *
 */
static void transport_generic_unmap_SG_segments(struct se_unmap_sg *unmap_sg)
{
	u32 i = 0;
	struct se_cmd *cmd = unmap_sg->se_cmd;
	struct se_mem *se_mem = unmap_sg->cur_se_mem;

	if (!(T_TASK(cmd)->t_task_se_num))
		return;

	list_for_each_entry_continue(se_mem, T_TASK(cmd)->t_mem_list, se_list) {
		kunmap(se_mem->se_page);

		if (++i == unmap_sg->sg_count)
			break;
	}

	return;
}

static inline u32 transport_lba_21(unsigned char *cdb)
{
	return ((cdb[1] & 0x1f) << 16) | (cdb[2] << 8) | cdb[3];
}

static inline u32 transport_lba_32(unsigned char *cdb)
{
	return (cdb[2] << 24) | (cdb[3] << 16) | (cdb[4] << 8) | cdb[5];
}

static inline unsigned long long transport_lba_64(unsigned char *cdb)
{
	unsigned int __v1, __v2;

	__v1 = (cdb[2] << 24) | (cdb[3] << 16) | (cdb[4] << 8) | cdb[5];
	__v2 = (cdb[6] << 24) | (cdb[7] << 16) | (cdb[8] << 8) | cdb[9];

	return ((unsigned long long)__v2) | (unsigned long long)__v1 << 32;
}

/*	transport_set_supported_SAM_opcode():
 *
 *
 */
void transport_set_supported_SAM_opcode(struct se_cmd *se_cmd)
{
	unsigned long flags;

	spin_lock_irqsave(&T_TASK(se_cmd)->t_state_lock, flags);
	se_cmd->se_cmd_flags |= SCF_SUPPORTED_SAM_OPCODE;
	spin_unlock_irqrestore(&T_TASK(se_cmd)->t_state_lock, flags);
}

/*
 * Called from interrupt context.
 */
void transport_task_timeout_handler(unsigned long data)
{
	struct se_task *task = (struct se_task *)data;
	struct se_cmd *cmd = TASK_CMD(task);
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
		DEBUG_TT("transport task: %p cmd: %p timeout task_active"
				" == 0\n", task, cmd);
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
		DEBUG_TT("transport task: %p cmd: %p timeout task_stop"
				" == 1\n", task, cmd);
		spin_unlock_irqrestore(&T_TASK(cmd)->t_state_lock, flags);
		complete(&task->task_stop_comp);
		return;
	}

	if (!(atomic_dec_and_test(&T_TASK(cmd)->t_task_cdbs_left))) {
		DEBUG_TT("transport task: %p cmd: %p timeout non zero"
				" t_task_cdbs_left\n", task, cmd);
		spin_unlock_irqrestore(&T_TASK(cmd)->t_state_lock, flags);
		return;
	}
	DEBUG_TT("transport task: %p cmd: %p timeout ZERO t_task_cdbs_left\n",
			task, cmd);

	cmd->t_state = TRANSPORT_COMPLETE_FAILURE;
	spin_unlock_irqrestore(&T_TASK(cmd)->t_state_lock, flags);

	cmd->transport_add_cmd_to_queue(cmd, TRANSPORT_COMPLETE_FAILURE);
}

u32 transport_get_default_task_timeout(struct se_device *dev)
{
	if (TRANSPORT(dev)->get_device_type(dev) == TYPE_DISK)
		return TRANSPORT_TIMEOUT_TYPE_DISK;

	if (TRANSPORT(dev)->get_device_type(dev) == TYPE_ROM)
		return TRANSPORT_TIMEOUT_TYPE_ROM;

	if (TRANSPORT(dev)->get_device_type(dev) == TYPE_TAPE)
		return TRANSPORT_TIMEOUT_TYPE_TAPE;

	return TRANSPORT_TIMEOUT_TYPE_OTHER;
}
EXPORT_SYMBOL(transport_get_default_task_timeout);

/*
 * Called with T_TASK(cmd)->t_state_lock held.
 */
void transport_start_task_timer(struct se_task *task)
{
	struct se_device *dev = task->se_obj_ptr;
	int timeout;

	if (task->task_flags & TF_RUNNING)
		return;
	/*
	 * If the task_timeout is disabled, exit now.
	 */
	timeout = DEV_ATTRIB(dev)->task_timeout;
	if (!(timeout))
		return;

	init_timer(&task->task_timer);
	task->task_timer.expires = (get_jiffies_64() + timeout * HZ);
	task->task_timer.data = (unsigned long) task;
	task->task_timer.function = transport_task_timeout_handler;

	task->task_flags |= TF_RUNNING;
	add_timer(&task->task_timer);
#if 0
	printk(KERN_INFO "Starting task timer for cmd: %p task: %p seconds:"
		" %d\n", task->task_se_cmd, task, timeout);
#endif
}

/*
 * Called with spin_lock_irq(&T_TASK(cmd)->t_state_lock) held.
 */
void __transport_stop_task_timer(struct se_task *task, unsigned long *flags)
{
	struct se_cmd *cmd = TASK_CMD(task);

	if (!(task->task_flags & TF_RUNNING))
		return;

	task->task_flags |= TF_STOP;
	spin_unlock_irqrestore(&T_TASK(cmd)->t_state_lock, *flags);

	del_timer_sync(&task->task_timer);

	spin_lock_irqsave(&T_TASK(cmd)->t_state_lock, *flags);
	task->task_flags &= ~TF_RUNNING;
	task->task_flags &= ~TF_STOP;
}

void transport_stop_task_timer(struct se_task *task)
{
	struct se_cmd *cmd = TASK_CMD(task);
	unsigned long flags;
#if 0
	printk(KERN_INFO "Stopping task timer for cmd: %p task: %p\n",
			cmd, task);
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
}

void transport_stop_all_task_timers(struct se_cmd *cmd)
{
	struct se_task *task = NULL, *task_tmp;
	unsigned long flags;

	spin_lock_irqsave(&T_TASK(cmd)->t_state_lock, flags);
	list_for_each_entry_safe(task, task_tmp,
				&T_TASK(cmd)->t_task_list, t_list)
		__transport_stop_task_timer(task, &flags);
	spin_unlock_irqrestore(&T_TASK(cmd)->t_state_lock, flags);
}

static inline int transport_tcq_window_closed(struct se_device *dev)
{
	if (dev->dev_tcq_window_closed++ <
			PYX_TRANSPORT_WINDOW_CLOSED_THRESHOLD) {
		msleep(PYX_TRANSPORT_WINDOW_CLOSED_WAIT_SHORT);
	} else
		msleep(PYX_TRANSPORT_WINDOW_CLOSED_WAIT_LONG);

	wake_up_interruptible(&dev->dev_queue_obj->thread_wq);
	return 0;
}

/*
 * Called from Fabric Module context from transport_execute_tasks()
 *
 * The return of this function determins if the tasks from struct se_cmd
 * get added to the execution queue in transport_execute_tasks(),
 * or are added to the delayed or ordered lists here.
 */
static inline int transport_execute_task_attr(struct se_cmd *cmd)
{
	if (SE_DEV(cmd)->dev_task_attr_type != SAM_TASK_ATTR_EMULATED)
		return 1;
	/*
	 * Check for the existance of HEAD_OF_QUEUE, and if true return 1
	 * to allow the passed struct se_cmd list of tasks to the front of the list.
	 */
	 if (cmd->sam_task_attr == TASK_ATTR_HOQ) {
		atomic_inc(&SE_DEV(cmd)->dev_hoq_count);
		smp_mb__after_atomic_inc();
		DEBUG_STA("Added HEAD_OF_QUEUE for CDB:"
			" 0x%02x, se_ordered_id: %u\n",
			T_TASK(cmd)->t_task_cdb[0],
			cmd->se_ordered_id);
		return 1;
	} else if (cmd->sam_task_attr == TASK_ATTR_ORDERED) {
		spin_lock(&SE_DEV(cmd)->ordered_cmd_lock);
		list_add_tail(&cmd->se_ordered_list,
				&SE_DEV(cmd)->ordered_cmd_list);
		spin_unlock(&SE_DEV(cmd)->ordered_cmd_lock);

		atomic_inc(&SE_DEV(cmd)->dev_ordered_sync);
		smp_mb__after_atomic_inc();

		DEBUG_STA("Added ORDERED for CDB: 0x%02x to ordered"
				" list, se_ordered_id: %u\n",
				T_TASK(cmd)->t_task_cdb[0],
				cmd->se_ordered_id);
		/*
		 * Add ORDERED command to tail of execution queue if
		 * no other older commands exist that need to be
		 * completed first.
		 */
		if (!(atomic_read(&SE_DEV(cmd)->simple_cmds)))
			return 1;
	} else {
		/*
		 * For SIMPLE and UNTAGGED Task Attribute commands
		 */
		atomic_inc(&SE_DEV(cmd)->simple_cmds);
		smp_mb__after_atomic_inc();
	}
	/*
	 * Otherwise if one or more outstanding ORDERED task attribute exist,
	 * add the dormant task(s) built for the passed struct se_cmd to the
	 * execution queue and become in Active state for this struct se_device.
	 */
	if (atomic_read(&SE_DEV(cmd)->dev_ordered_sync) != 0) {
		/*
		 * Otherwise, add cmd w/ tasks to delayed cmd queue that
		 * will be drained upon competion of HEAD_OF_QUEUE task.
		 */
		spin_lock(&SE_DEV(cmd)->delayed_cmd_lock);
		cmd->se_cmd_flags |= SCF_DELAYED_CMD_FROM_SAM_ATTR;
		list_add_tail(&cmd->se_delayed_list,
				&SE_DEV(cmd)->delayed_cmd_list);
		spin_unlock(&SE_DEV(cmd)->delayed_cmd_lock);

		DEBUG_STA("Added CDB: 0x%02x Task Attr: 0x%02x to"
			" delayed CMD list, se_ordered_id: %u\n",
			T_TASK(cmd)->t_task_cdb[0], cmd->sam_task_attr,
			cmd->se_ordered_id);
		/*
		 * Return zero to let transport_execute_tasks() know
		 * not to add the delayed tasks to the execution list.
		 */
		return 0;
	}
	/*
	 * Otherwise, no ORDERED task attributes exist..
	 */
	return 1;
}

/*
 * Called from fabric module context in transport_generic_new_cmd() and
 * transport_generic_process_write()
 */
int transport_execute_tasks(struct se_cmd *cmd)
{
	int add_tasks;

	if (!(cmd->se_cmd_flags & SCF_SE_DISABLE_ONLINE_CHECK)) {
		if (dev_obj_check_online(cmd->se_orig_obj_ptr) != 0) {
			cmd->transport_error_status =
				PYX_TRANSPORT_LU_COMM_FAILURE;
			transport_generic_request_failure(cmd, NULL, 0, 1);
			return 0;
		}
	}
	/*
	 * Call transport_cmd_check_stop() to see if a fabric exception
	 * has occured that prevents execution.
	 */
	if (!(transport_cmd_check_stop(cmd, 0, TRANSPORT_PROCESSING))) {
		/*
		 * Check for SAM Task Attribute emulation and HEAD_OF_QUEUE
		 * attribute for the tasks of the received struct se_cmd CDB
		 */
		add_tasks = transport_execute_task_attr(cmd);
		if (add_tasks == 0)
			goto execute_tasks;
		/*
		 * This calls transport_add_tasks_from_cmd() to handle
		 * HEAD_OF_QUEUE ordering for SAM Task Attribute emulation
		 * (if enabled) in __transport_add_task_to_execute_queue() and
		 * transport_add_task_check_sam_attr().
		 */
		transport_add_tasks_from_cmd(cmd);
	}
	/*
	 * Kick the execution queue for the cmd associated struct se_device
	 * storage object.
	 */
execute_tasks:
	__transport_execute_tasks(SE_DEV(cmd));
	return 0;
}

/*
 * Called to check struct se_device tcq depth window, and once open pull struct se_task
 * from struct se_device->execute_task_list and
 *
 * Called from transport_processing_thread()
 */
int __transport_execute_tasks(struct se_device *dev)
{
	int error;
	struct se_cmd *cmd = NULL;
	struct se_task *task;
	unsigned long flags;

	/*
	 * Check if there is enough room in the device and HBA queue to send
	 * struct se_transport_task's to the selected transport.
	 */
check_depth:
	spin_lock_irqsave(&SE_HBA(dev)->hba_queue_lock, flags);
	if (!(atomic_read(&dev->depth_left)) ||
	    !(atomic_read(&SE_HBA(dev)->left_queue_depth))) {
		spin_unlock_irqrestore(&SE_HBA(dev)->hba_queue_lock, flags);
		return transport_tcq_window_closed(dev);
	}
	dev->dev_tcq_window_closed = 0;

	spin_lock(&dev->execute_task_lock);
	task = transport_get_task_from_execute_queue(dev);
	spin_unlock(&dev->execute_task_lock);

	if (!task) {
		spin_unlock_irqrestore(&SE_HBA(dev)->hba_queue_lock, flags);
		return 0;
	}

	atomic_dec(&dev->depth_left);
	atomic_dec(&SE_HBA(dev)->left_queue_depth);
	spin_unlock_irqrestore(&SE_HBA(dev)->hba_queue_lock, flags);

	cmd = TASK_CMD(task);

	spin_lock_irqsave(&T_TASK(cmd)->t_state_lock, flags);
	atomic_set(&task->task_active, 1);
	atomic_set(&task->task_sent, 1);
	atomic_inc(&T_TASK(cmd)->t_task_cdbs_sent);

	if (atomic_read(&T_TASK(cmd)->t_task_cdbs_sent) ==
	    T_TASK(cmd)->t_task_cdbs)
		atomic_set(&cmd->transport_sent, 1);

	transport_start_task_timer(task);
	spin_unlock_irqrestore(&T_TASK(cmd)->t_state_lock, flags);
	/*
	 * The struct se_cmd->transport_emulate_cdb() function pointer is used
	 * to grab REPORT_LUNS CDBs before they hit the
	 * struct se_subsystem_api->do_task() caller below.
	 */
	if (cmd->transport_emulate_cdb) {
		error = cmd->transport_emulate_cdb(cmd);
		if (error != 0) {
			cmd->transport_error_status = error;
			atomic_set(&task->task_active, 0);
			atomic_set(&cmd->transport_sent, 0);
			transport_stop_tasks_for_cmd(cmd);
			transport_generic_request_failure(cmd, dev, 0, 1);
			goto check_depth;
		}
		/*
		 * Handle the successful completion for transport_emulate_cdb()
		 * usage.
		 */
		cmd->scsi_status = SAM_STAT_GOOD;
		task->task_scsi_status = GOOD;
		transport_complete_task(task, 1);
	} else {
		error = TRANSPORT(dev)->do_task(task);
		if (error != 0) {
			cmd->transport_error_status = error;
			atomic_set(&task->task_active, 0);
			atomic_set(&cmd->transport_sent, 0);
			transport_stop_tasks_for_cmd(cmd);
			transport_generic_request_failure(cmd, dev, 0, 1);
		}
	}

	goto check_depth;

	return 0;
}

/*	transport_new_cmd_failure():
 *
 *
 */
void transport_new_cmd_failure(struct se_cmd *se_cmd)
{
	unsigned long flags;
	/*
	 * Any unsolicited data will get dumped for failed command inside of
	 * the fabric plugin
	 */
	spin_lock_irqsave(&T_TASK(se_cmd)->t_state_lock, flags);
	se_cmd->se_cmd_flags |= SCF_SE_CMD_FAILED;
	se_cmd->se_cmd_flags |= SCF_SCSI_CDB_EXCEPTION;
	spin_unlock_irqrestore(&T_TASK(se_cmd)->t_state_lock, flags);

	CMD_TFO(se_cmd)->new_cmd_failure(se_cmd);
}

static int transport_generic_map_buffers_to_tasks(struct se_cmd *);
static void transport_nop_wait_for_tasks(struct se_cmd *, int, int);

static inline u32 transport_get_sectors_6(
	unsigned char *cdb,
	struct se_cmd *cmd,
	int *ret)
{
	struct se_device *dev = SE_LUN(cmd)->se_dev;

	/*
	 * Assume TYPE_DISK for non struct se_device objects.
	 * Use 8-bit sector value.
	 */
	if (!dev)
		goto type_disk;

	/*
	 * Use 24-bit allocation length for TYPE_TAPE.
	 */
	if (TRANSPORT(dev)->get_device_type(dev) == TYPE_TAPE)
		return (u32)(cdb[2] << 16) + (cdb[3] << 8) + cdb[4];

	/*
	 * Everything else assume TYPE_DISK Sector CDB location.
	 * Use 8-bit sector value.
	 */
type_disk:
	return (u32)cdb[4];
}

static inline u32 transport_get_sectors_10(
	unsigned char *cdb,
	struct se_cmd *cmd,
	int *ret)
{
	struct se_device *dev = SE_LUN(cmd)->se_dev;

	/*
	 * Assume TYPE_DISK for non struct se_device objects.
	 * Use 16-bit sector value.
	 */
	if (!dev)
		goto type_disk;

	/*
	 * XXX_10 is not defined in SSC, throw an exception
	 */
	if (TRANSPORT(dev)->get_device_type(dev) == TYPE_TAPE) {
		*ret = -1;
		return 0;
	}

	/*
	 * Everything else assume TYPE_DISK Sector CDB location.
	 * Use 16-bit sector value.
	 */
type_disk:
	return (u32)(cdb[7] << 8) + cdb[8];
}

static inline u32 transport_get_sectors_12(
	unsigned char *cdb,
	struct se_cmd *cmd,
	int *ret)
{
	struct se_device *dev = SE_LUN(cmd)->se_dev;

	/*
	 * Assume TYPE_DISK for non struct se_device objects.
	 * Use 32-bit sector value.
	 */
	if (!dev)
		goto type_disk;

	/*
	 * XXX_12 is not defined in SSC, throw an exception
	 */
	if (TRANSPORT(dev)->get_device_type(dev) == TYPE_TAPE) {
		*ret = -1;
		return 0;
	}

	/*
	 * Everything else assume TYPE_DISK Sector CDB location.
	 * Use 32-bit sector value.
	 */
type_disk:
	return (u32)(cdb[6] << 24) + (cdb[7] << 16) + (cdb[8] << 8) + cdb[9];
}

static inline u32 transport_get_sectors_16(
	unsigned char *cdb,
	struct se_cmd *cmd,
	int *ret)
{
	struct se_device *dev = SE_LUN(cmd)->se_dev;

	/*
	 * Assume TYPE_DISK for non struct se_device objects.
	 * Use 32-bit sector value.
	 */
	if (!dev)
		goto type_disk;

	/*
	 * Use 24-bit allocation length for TYPE_TAPE.
	 */
	if (TRANSPORT(dev)->get_device_type(dev) == TYPE_TAPE)
		return (u32)(cdb[12] << 16) + (cdb[13] << 8) + cdb[14];

type_disk:
	return (u32)(cdb[10] << 24) + (cdb[11] << 16) +
		    (cdb[12] << 8) + cdb[13];
}

static inline u32 transport_get_size(
	u32 sectors,
	unsigned char *cdb,
	struct se_cmd *cmd)
{
	struct se_device *dev = SE_DEV(cmd);

	if (TRANSPORT(dev)->get_device_type(dev) == TYPE_TAPE) {
		if (cdb[1] & 1) { /* sectors */
			return DEV_ATTRIB(dev)->block_size * sectors;
		} else /* bytes */
			return sectors;
	}
#if 0
	printk(KERN_INFO "Returning block_size: %u, sectors: %u == %u for"
			" %s object\n", DEV_ATTRIB(dev)->block_size, sectors,
			DEV_ATTRIB(dev)->block_size * sectors,
			TRANSPORT(dev)->name);
#endif
	return DEV_ATTRIB(dev)->block_size * sectors;
}

static inline void transport_get_maps(struct se_cmd *cmd)
{
	cmd->transport_map_SG_segments = &transport_generic_map_SG_segments;
	cmd->transport_unmap_SG_segments = &transport_generic_unmap_SG_segments;
}

unsigned char transport_asciihex_to_binaryhex(unsigned char val[2])
{
	unsigned char result = 0;
	/*
	 * MSB
	 */
	if ((val[0] >= 'a') && (val[0] <= 'f'))
		result = ((val[0] - 'a' + 10) & 0xf) << 4;
	else
		if ((val[0] >= 'A') && (val[0] <= 'F'))
			result = ((val[0] - 'A' + 10) & 0xf) << 4;
		else /* digit */
			result = ((val[0] - '0') & 0xf) << 4;
	/*
	 * LSB
	 */
	if ((val[1] >= 'a') && (val[1] <= 'f'))
		result |= ((val[1] - 'a' + 10) & 0xf);
	else
		if ((val[1] >= 'A') && (val[1] <= 'F'))
			result |= ((val[1] - 'A' + 10) & 0xf);
		else /* digit */
			result |= ((val[1] - '0') & 0xf);

	return result;
}
EXPORT_SYMBOL(transport_asciihex_to_binaryhex);

extern int transport_generic_emulate_inquiry(
	struct se_cmd *cmd,
	unsigned char type,
	unsigned char *prod,
	unsigned char *version,
	unsigned char *se_location)
{
	struct se_device *dev = SE_DEV(cmd);
	struct se_lun *lun = SE_LUN(cmd);
	struct se_port *port = NULL;
	struct se_portal_group *tpg = NULL;
	struct t10_alua_lu_gp_member *lu_gp_mem;
	struct t10_alua_tg_pt_gp *tg_pt_gp;
	struct t10_alua_tg_pt_gp_member *tg_pt_gp_mem;
	unsigned char *buf = (unsigned char *) T_TASK(cmd)->t_task_buf;
	unsigned char *cdb = T_TASK(cmd)->t_task_cdb;
	unsigned char *iqn_sn, binary, binary_new;
	u32 prod_len, iqn_sn_len, se_location_len;
	u32 unit_serial_len, off = 0;
	int i;
	u16 len = 0, id_len;

	if (!(cdb[1] & 0x1)) {
		/*
		 * Make sure we at least have 6 bytes of INQUIRY response
		 * payload going back for EVPD=0
		 */
		if (cmd->data_length < 6) {
			printk(KERN_ERR "SCSI Inquiry payload length: %u"
				" too small for EVPD=0\n", cmd->data_length);
			return -1;
		}
		buf[0] = type;

		if (type == TYPE_TAPE)
			buf[1] = 0x80;
		buf[2]          = TRANSPORT(dev)->get_device_rev(dev);
		/*
		 * Enable SCCS and TPGS fields for Emulated ALUA
		 */
		if (T10_ALUA(dev->se_sub_dev)->alua_type ==
				SPC3_ALUA_EMULATED) {
			/*
			 * Set SCCS for MAINTENANCE_IN +
			 * REPORT_TARGET_PORT_GROUPS
			 */
			buf[5]	= 0x80;
			/*
			 * Set TPGS field for explict and/or implict ALUA
			 * access type and opteration.
			 *
			 * See spc4r17 section 6.4.2 Table 135
			 */
			port = lun->lun_sep;
			if (!(port))
				goto after_tpgs;
			tg_pt_gp_mem = port->sep_alua_tg_pt_gp_mem;
			if (!(tg_pt_gp_mem))
				goto after_tpgs;

			spin_lock(&tg_pt_gp_mem->tg_pt_gp_mem_lock);
			tg_pt_gp = tg_pt_gp_mem->tg_pt_gp;
			if (!(tg_pt_gp)) {
				spin_unlock(&tg_pt_gp_mem->tg_pt_gp_mem_lock);
				goto after_tpgs;
			}
			buf[5] |= tg_pt_gp->tg_pt_gp_alua_access_type;
			spin_unlock(&tg_pt_gp_mem->tg_pt_gp_mem_lock);
		}
after_tpgs:
		if (cmd->data_length < 8) {
			buf[4] = 1; /* Set additional length to 1 */
			return 0;
		}

		buf[7]		= 0x32; /* Sync=1 and CmdQue=1 */
		/*
		 * Do not include vendor, product, reversion info in INQUIRY
		 * response payload for cdbs with a small allocation length.
		 */
		if (cmd->data_length < 36) {
			buf[4] = 3; /* Set additional length to 3 */
			return 0;
		}

		snprintf((unsigned char *)&buf[8], 8, "LIO-ORG");
		snprintf((unsigned char *)&buf[16], 16, "%s", prod);
		snprintf((unsigned char *)&buf[32], 4, "%s", version);
		buf[4] = 31; /* Set additional length to 31 */
		return 0;
	}
	/*
	 * Make sure we at least have 4 bytes of INQUIRY response
	 * payload for 0x00 going back for EVPD=1.  Note that 0x80
	 * and 0x83 will check for enough payload data length and
	 * jump to set_len: label when there is not enough inquiry EVPD
	 * payload length left for the next outgoing EVPD metadata
	 */
	if (cmd->data_length < 4) {
		printk(KERN_ERR "SCSI Inquiry payload length: %u"
			" too small for EVPD=1\n", cmd->data_length);
		return -1;
	}
	buf[0] = type;

	switch (cdb[2]) {
	case 0x00: /* supported vital product data pages */
		buf[1] = 0x00;
		buf[3] = 3;
		if (cmd->data_length < 8)
			return 0;
		buf[4] = 0x0;
		buf[5] = 0x80;
		buf[6] = 0x83;
		len = 3;
		break;
	case 0x80: /* unit serial number */
		buf[1] = 0x80;
		if (dev->se_sub_dev->su_dev_flags &
					SDF_EMULATED_VPD_UNIT_SERIAL) {
			unit_serial_len =
				strlen(&DEV_T10_WWN(dev)->unit_serial[0]);
			unit_serial_len++; /* For NULL Terminator */

			if (((len + 4) + unit_serial_len) > cmd->data_length) {
				len += unit_serial_len;
				goto set_len;
			}
			len += sprintf((unsigned char *)&buf[4], "%s",
				&DEV_T10_WWN(dev)->unit_serial[0]);
		 } else {
			iqn_sn = transport_get_iqn_sn();
			iqn_sn_len = strlen(iqn_sn);
			iqn_sn_len++; /* For ":" */
			se_location_len = strlen(se_location);
			se_location_len++; /* For NULL Terminator */

			if (((len + 4) + (iqn_sn_len + se_location_len)) >
					cmd->data_length) {
				len += (iqn_sn_len + se_location_len);
				goto set_len;
			}
			len += sprintf((unsigned char *)&buf[4], "%s:%s",
				iqn_sn, se_location);
		}
		len++; /* Extra Byte for NULL Terminator */
		buf[3] = len;
		break;
	case 0x83:
		/*
		 * Device identification VPD, for a complete list of
		 * DESIGNATOR TYPEs see spc4r17 Table 459.
		 */
		buf[1] = 0x83;
		off = 4;
		/*
		 * NAA IEEE Registered Extended Assigned designator format,
		 * see spc4r17 section 7.7.3.6.5
		 *
		 * We depend upon a target_core_mod/ConfigFS provided
		 * /sys/kernel/config/target/core/$HBA/$DEV/wwn/vpd_unit_serial
		 * value in order to return the NAA id.
		 */
		if (!(dev->se_sub_dev->su_dev_flags &
					SDF_EMULATED_VPD_UNIT_SERIAL))
			goto check_t10_vend_desc;
		if ((off + 20) > cmd->data_length)
			goto check_t10_vend_desc;
		/* CODE SET == Binary */
		buf[off++] = 0x1;
		/* Set ASSOICATION == addressed logical unit: 0)b */
		buf[off] = 0x00;
		/* Identifier/Designator type == NAA identifier */
		buf[off++] = 0x3;
		off++;
		/* Identifier/Designator length */
		buf[off++] = 0x10;
		/*
		 * Start NAA IEEE Registered Extended Identifier/Designator
		 */
		buf[off++] = (0x6 << 4);
		/*
		 * Use OpenFabrics IEEE Company ID: 00 14 05
		 */
		buf[off++] = 0x01;
		buf[off++] = 0x40;
		buf[off] = (0x5 << 4);
		/*
		 * Return ConfigFS Unit Serial Number information for
		 * VENDOR_SPECIFIC_IDENTIFIER and
		 * VENDOR_SPECIFIC_IDENTIFIER_EXTENTION
		 */
		binary = transport_asciihex_to_binaryhex(
					&DEV_T10_WWN(dev)->unit_serial[0]);
		buf[off++] |= (binary & 0xf0) >> 4;
		for (i = 0; i < 24; i += 2) {
			binary_new = transport_asciihex_to_binaryhex(
				&DEV_T10_WWN(dev)->unit_serial[i+2]);
			buf[off] = (binary & 0x0f) << 4;
			buf[off++] |= (binary_new & 0xf0) >> 4;
			binary = binary_new;
		}
		len = 20;
		off = (len + 4);
check_t10_vend_desc:
		/*
		 * T10 Vendor Identifier Page, see spc4r17 section 7.7.3.4
		 */
		id_len = 8; /* For Vendor field */
		prod_len = 4; /* For VPD Header */
		prod_len += 8; /* For Vendor field */
		prod_len += strlen(prod);
		prod_len++; /* For : */

		if (dev->se_sub_dev->su_dev_flags &
					SDF_EMULATED_VPD_UNIT_SERIAL) {
			unit_serial_len =
				strlen(&DEV_T10_WWN(dev)->unit_serial[0]);
			unit_serial_len++; /* For NULL Terminator */

			if ((len + (id_len + 4) +
			    (prod_len + unit_serial_len)) >
					cmd->data_length) {
				len += (prod_len + unit_serial_len);
				goto check_port;
			}
			id_len += sprintf((unsigned char *)&buf[off+12],
					"%s:%s", prod,
					&DEV_T10_WWN(dev)->unit_serial[0]);
		} else {
			iqn_sn = transport_get_iqn_sn();
			iqn_sn_len = strlen(iqn_sn);
			iqn_sn_len++; /* For ":" */
			se_location_len = strlen(se_location);
			se_location_len++; /* For NULL Terminator */

			if ((len + (id_len + 4) + (prod_len + iqn_sn_len +
					se_location_len)) > cmd->data_length) {
				len += (prod_len + iqn_sn_len +
						se_location_len);
				goto check_port;
			}
			id_len += sprintf((unsigned char *)&buf[off+12],
				"%s:%s:%s", prod, iqn_sn, se_location);
		}
		buf[off] = 0x2; /* ASCII */
		buf[off+1] = 0x1; /* T10 Vendor ID */
		buf[off+2] = 0x0;
		memcpy((unsigned char *)&buf[off+4], "LIO-ORG", 8);
		/* Extra Byte for NULL Terminator */
		id_len++;
		/* Identifier Length */
		buf[off+3] = id_len;
		/* Header size for Designation descriptor */
		len += (id_len + 4);
		off += (id_len + 4);
		/*
		 * struct se_port is only set for INQUIRY VPD=1 through $FABRIC_MOD
		 */
check_port:
		port = lun->lun_sep;
		if (port) {
			struct t10_alua_lu_gp *lu_gp;
			u32 padding, scsi_name_len;
			u16 lu_gp_id = 0;
			u16 tg_pt_gp_id = 0;
			u16 tpgt;

			tpg = port->sep_tpg;
			/*
			 * Relative target port identifer, see spc4r17
			 * section 7.7.3.7
			 *
			 * Get the PROTOCOL IDENTIFIER as defined by spc4r17
			 * section 7.5.1 Table 362
			 */
			if (((len + 4) + 8) > cmd->data_length) {
				len += 8;
				goto check_tpgi;
			}
			buf[off] =
				(TPG_TFO(tpg)->get_fabric_proto_ident(tpg) << 4);
			buf[off++] |= 0x1; /* CODE SET == Binary */
			buf[off] = 0x80; /* Set PIV=1 */
			/* Set ASSOICATION == target port: 01b */
			buf[off] |= 0x10;
			/* DESIGNATOR TYPE == Relative target port identifer */
			buf[off++] |= 0x4;
			off++; /* Skip over Reserved */
			buf[off++] = 4; /* DESIGNATOR LENGTH */
			/* Skip over Obsolete field in RTPI payload
			 * in Table 472 */
			off += 2;
			buf[off++] = ((port->sep_rtpi >> 8) & 0xff);
			buf[off++] = (port->sep_rtpi & 0xff);
			len += 8; /* Header size + Designation descriptor */
			/*
			 * Target port group identifier, see spc4r17
			 * section 7.7.3.8
			 *
			 * Get the PROTOCOL IDENTIFIER as defined by spc4r17
			 * section 7.5.1 Table 362
			 */
check_tpgi:
			if (T10_ALUA(dev->se_sub_dev)->alua_type !=
					SPC3_ALUA_EMULATED)
				goto check_scsi_name;

			if (((len + 4) + 8) > cmd->data_length) {
				len += 8;
				goto check_lu_gp;
			}
			tg_pt_gp_mem = port->sep_alua_tg_pt_gp_mem;
			if (!(tg_pt_gp_mem))
				goto check_lu_gp;

			spin_lock(&tg_pt_gp_mem->tg_pt_gp_mem_lock);
			tg_pt_gp = tg_pt_gp_mem->tg_pt_gp;
			if (!(tg_pt_gp)) {
				spin_unlock(&tg_pt_gp_mem->tg_pt_gp_mem_lock);
				goto check_lu_gp;
			}
			tg_pt_gp_id = tg_pt_gp->tg_pt_gp_id;
			spin_unlock(&tg_pt_gp_mem->tg_pt_gp_mem_lock);

			buf[off] =
				(TPG_TFO(tpg)->get_fabric_proto_ident(tpg) << 4);
			buf[off++] |= 0x1; /* CODE SET == Binary */
			buf[off] = 0x80; /* Set PIV=1 */
			/* Set ASSOICATION == target port: 01b */
			buf[off] |= 0x10;
			/* DESIGNATOR TYPE == Target port group identifier */
			buf[off++] |= 0x5;
			off++; /* Skip over Reserved */
			buf[off++] = 4; /* DESIGNATOR LENGTH */
			off += 2; /* Skip over Reserved Field */
			buf[off++] = ((tg_pt_gp_id >> 8) & 0xff);
			buf[off++] = (tg_pt_gp_id & 0xff);
			len += 8; /* Header size + Designation descriptor */
			/*
			 * Logical Unit Group identifier, see spc4r17
			 * section 7.7.3.8
			 */
check_lu_gp:
			if (((len + 4) + 8) > cmd->data_length) {
				len += 8;
				goto check_scsi_name;
			}
			lu_gp_mem = dev->dev_alua_lu_gp_mem;
			if (!(lu_gp_mem))
				goto check_scsi_name;

			spin_lock(&lu_gp_mem->lu_gp_mem_lock);
			lu_gp = lu_gp_mem->lu_gp;
			if (!(lu_gp)) {
				spin_unlock(&lu_gp_mem->lu_gp_mem_lock);
				goto check_scsi_name;
			}
			lu_gp_id = lu_gp->lu_gp_id;
			spin_unlock(&lu_gp_mem->lu_gp_mem_lock);

			buf[off++] |= 0x1; /* CODE SET == Binary */
			/* DESIGNATOR TYPE == Logical Unit Group identifier */
			buf[off++] |= 0x6;
			off++; /* Skip over Reserved */
			buf[off++] = 4; /* DESIGNATOR LENGTH */
			off += 2; /* Skip over Reserved Field */
			buf[off++] = ((lu_gp_id >> 8) & 0xff);
			buf[off++] = (lu_gp_id & 0xff);
			len += 8; /* Header size + Designation descriptor */
			/*
			 * SCSI name string designator, see spc4r17
			 * section 7.7.3.11
			 *
			 * Get the PROTOCOL IDENTIFIER as defined by spc4r17
			 * section 7.5.1 Table 362
			 */
check_scsi_name:
			scsi_name_len = strlen(TPG_TFO(tpg)->tpg_get_wwn(tpg));
			/* UTF-8 ",t,0x<16-bit TPGT>" + NULL Terminator */
			scsi_name_len += 10;
			/* Check for 4-byte padding */
			padding = ((-scsi_name_len) & 3);
			if (padding != 0)
				scsi_name_len += padding;
			/* Header size + Designation descriptor */
			scsi_name_len += 4;

			if (((len + 4) + scsi_name_len) > cmd->data_length) {
				len += scsi_name_len;
				goto set_len;
			}
			buf[off] =
				(TPG_TFO(tpg)->get_fabric_proto_ident(tpg) << 4);
			buf[off++] |= 0x3; /* CODE SET == UTF-8 */
			buf[off] = 0x80; /* Set PIV=1 */
			/* Set ASSOICATION == target port: 01b */
			buf[off] |= 0x10;
			/* DESIGNATOR TYPE == SCSI name string */
			buf[off++] |= 0x8;
			off += 2; /* Skip over Reserved and length */
			/*
			 * SCSI name string identifer containing, $FABRIC_MOD
			 * dependent information.  For LIO-Target and iSCSI
			 * Target Port, this means "<iSCSI name>,t,0x<TPGT> in
			 * UTF-8 encoding.
			 */
			tpgt = TPG_TFO(tpg)->tpg_get_tag(tpg);
			scsi_name_len = sprintf(&buf[off], "%s,t,0x%04x",
					TPG_TFO(tpg)->tpg_get_wwn(tpg), tpgt);
			scsi_name_len += 1 /* Include  NULL terminator */;
			/*
			 * The null-terminated, null-padded (see 4.4.2) SCSI
			 * NAME STRING field contains a UTF-8 format string.
			 * The number of bytes in the SCSI NAME STRING field
			 * (i.e., the value in the DESIGNATOR LENGTH field)
			 * shall be no larger than 256 and shall be a multiple
			 * of four.
			 */
			if (padding)
				scsi_name_len += padding;

			buf[off-1] = scsi_name_len;
			off += scsi_name_len;
			/* Header size + Designation descriptor */
			len += (scsi_name_len + 4);
		}
set_len:
		buf[2] = ((len >> 8) & 0xff);
		buf[3] = (len & 0xff); /* Page Length for VPD 0x83 */
		break;
	default:
		printk(KERN_ERR "Unknown VPD Code: 0x%02x\n", cdb[2]);
		return -1;
	}

	return 0;
}
EXPORT_SYMBOL(transport_generic_emulate_inquiry);

int transport_generic_emulate_readcapacity(
	struct se_cmd *cmd,
	u32 blocks)
{
	struct se_device *dev = SE_DEV(cmd);
	unsigned char *buf = (unsigned char *) T_TASK(cmd)->t_task_buf;

	buf[0] = (blocks >> 24) & 0xff;
	buf[1] = (blocks >> 16) & 0xff;
	buf[2] = (blocks >> 8) & 0xff;
	buf[3] = blocks & 0xff;
	buf[4] = (DEV_ATTRIB(dev)->block_size >> 24) & 0xff;
	buf[5] = (DEV_ATTRIB(dev)->block_size >> 16) & 0xff;
	buf[6] = (DEV_ATTRIB(dev)->block_size >> 8) & 0xff;
	buf[7] = DEV_ATTRIB(dev)->block_size & 0xff;

	return 0;
}
EXPORT_SYMBOL(transport_generic_emulate_readcapacity);

int transport_generic_emulate_readcapacity_16(
	struct se_cmd *cmd,
	unsigned long long blocks)
{
	struct se_device *dev = SE_DEV(cmd);
	unsigned char *buf = (unsigned char *) T_TASK(cmd)->t_task_buf;

	buf[0] = (blocks >> 56) & 0xff;
	buf[1] = (blocks >> 48) & 0xff;
	buf[2] = (blocks >> 40) & 0xff;
	buf[3] = (blocks >> 32) & 0xff;
	buf[4] = (blocks >> 24) & 0xff;
	buf[5] = (blocks >> 16) & 0xff;
	buf[6] = (blocks >> 8) & 0xff;
	buf[7] = blocks & 0xff;
	buf[8] = (DEV_ATTRIB(dev)->block_size >> 24) & 0xff;
	buf[9] = (DEV_ATTRIB(dev)->block_size >> 16) & 0xff;
	buf[10] = (DEV_ATTRIB(dev)->block_size >> 8) & 0xff;
	buf[11] = DEV_ATTRIB(dev)->block_size & 0xff;

	return 0;
}
EXPORT_SYMBOL(transport_generic_emulate_readcapacity_16);

static int transport_modesense_rwrecovery(unsigned char *p)
{
	p[0] = 0x01;
	p[1] = 0x0a;

	return 12;
}

static int transport_modesense_control(struct se_device *dev, unsigned char *p)
{
	p[0] = 0x0a;
	p[1] = 0x0a;
	p[2] = 2;
	/*
	 * From spc4r17, section 7.4.6 Control mode Page
	 *
	 * Unit Attention interlocks control (UN_INTLCK_CTRL) to code 00b
	 *
	 * 00b: The logical unit shall clear any unit attention condition
	 * reported in the same I_T_L_Q nexus transaction as a CHECK CONDITION
	 * status and shall not establish a unit attention condition when a com-
	 * mand is completed with BUSY, TASK SET FULL, or RESERVATION CONFLICT
	 * status.
	 *
	 * 10b: The logical unit shall not clear any unit attention condition
	 * reported in the same I_T_L_Q nexus transaction as a CHECK CONDITION
	 * status and shall not establish a unit attention condition when
	 * a command is completed with BUSY, TASK SET FULL, or RESERVATION
	 * CONFLICT status.
	 *
	 * 11b a The logical unit shall not clear any unit attention condition
	 * reported in the same I_T_L_Q nexus transaction as a CHECK CONDITION
	 * status and shall establish a unit attention condition for the
	 * initiator port associated with the I_T nexus on which the BUSY,
	 * TASK SET FULL, or RESERVATION CONFLICT status is being returned.
	 * Depending on the status, the additional sense code shall be set to
	 * PREVIOUS BUSY STATUS, PREVIOUS TASK SET FULL STATUS, or PREVIOUS
	 * RESERVATION CONFLICT STATUS. Until it is cleared by a REQUEST SENSE
	 * command, a unit attention condition shall be established only once
	 * for a BUSY, TASK SET FULL, or RESERVATION CONFLICT status regardless
	 * to the number of commands completed with one of those status codes.
	 */
	p[4] = (DEV_ATTRIB(dev)->emulate_ua_intlck_ctrl == 2) ? 0x30 :
	       (DEV_ATTRIB(dev)->emulate_ua_intlck_ctrl == 1) ? 0x20 : 0x00;
	/*
	 * From spc4r17, section 7.4.6 Control mode Page
	 *
	 * Task Aborted Status (TAS) bit set to zero.
	 *
	 * A task aborted status (TAS) bit set to zero specifies that aborted
	 * tasks shall be terminated by the device server without any response
	 * to the application client. A TAS bit set to one specifies that tasks
	 * aborted by the actions of an I_T nexus other than the I_T nexus on
	 * which the command was received shall be completed with TASK ABORTED
	 * status (see SAM-4).
	 */
	p[5] = (DEV_ATTRIB(dev)->emulate_tas) ? 0x40 : 0x00;
	p[8] = 0xff;
	p[9] = 0xff;
	p[11] = 30;

	return 12;
}

static int transport_modesense_caching(unsigned char *p)
{
	p[0] = 0x08;
	p[1] = 0x12;
#if 0
	p[2] = 0x04; /* Write Cache Enable */
#endif
	p[12] = 0x20; /* Disabled Read Ahead */

	return 20;
}

#if 0
static int transport_modesense_devicecaps(unsigned char *p)
{
	p[0] = 0x2a;
	p[1] = 0x0a;

	return 12;
}
#endif

static void transport_modesense_write_protect(
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
}

int transport_generic_emulate_modesense(
	struct se_cmd *cmd,
	unsigned char *cdb,
	unsigned char *rbuf,
	int ten,
	int type)
{
	struct se_device *dev = SE_DEV(cmd);
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
		length = transport_modesense_control(dev, &buf[offset]);
		break;
#if 0
	case 0x2a:
		length = transport_modesense_devicecaps(&buf[offset]);
		break;
#endif
	case 0x3f:
		length = transport_modesense_rwrecovery(&buf[offset]);
		length += transport_modesense_caching(&buf[offset+length]);
		length += transport_modesense_control(dev, &buf[offset+length]);
#if 0
		length += transport_modesense_devicecaps(&buf[offset+length]);
#endif
		break;
	default:
		printk(KERN_ERR "Got Unknown Mode Page: 0x%02x\n",
				cdb[2] & 0x3f);
		return PYX_TRANSPORT_UNKNOWN_MODE_PAGE;
	}
	offset += length;

	if (ten) {
		offset -= 2;
		buf[0] = (offset >> 8) & 0xff;
		buf[1] = offset & 0xff;

		if ((SE_LUN(cmd)->lun_access & TRANSPORT_LUNFLAGS_READ_ONLY) ||
		    (cmd->se_deve &&
		    (cmd->se_deve->lun_flags & TRANSPORT_LUNFLAGS_READ_ONLY)))
			transport_modesense_write_protect(&buf[3], type);

		if ((offset + 2) > cmd->data_length)
			offset = cmd->data_length;

	} else {
		offset -= 1;
		buf[0] = offset & 0xff;

		if ((SE_LUN(cmd)->lun_access & TRANSPORT_LUNFLAGS_READ_ONLY) ||
		    (cmd->se_deve &&
		    (cmd->se_deve->lun_flags & TRANSPORT_LUNFLAGS_READ_ONLY)))
			transport_modesense_write_protect(&buf[2], type);

		if ((offset + 1) > cmd->data_length)
			offset = cmd->data_length;
	}
	memcpy(rbuf, buf, offset);

	return 0;
}
EXPORT_SYMBOL(transport_generic_emulate_modesense);

int transport_generic_emulate_request_sense(
	struct se_cmd *cmd,
	unsigned char *cdb)
{
	unsigned char *buf = (unsigned char *) T_TASK(cmd)->t_task_buf;
	u8 ua_asc = 0, ua_ascq = 0;

	if (cdb[1] & 0x01) {
		printk(KERN_ERR "REQUEST_SENSE description emulation not"
			" supported\n");
		return PYX_TRANSPORT_INVALID_CDB_FIELD;
	}
	if (!(core_scsi3_ua_clear_for_request_sense(cmd, &ua_asc, &ua_ascq))) {
		/*
		 * CURRENT ERROR, UNIT ATTENTION
		 */
		buf[0] = 0x70;
		buf[SPC_SENSE_KEY_OFFSET] = UNIT_ATTENTION;
		/*
		 * Make sure request data length is enough for additional
		 * sense data.
		 */
		if (cmd->data_length <= 18) {
			buf[7] = 0x00;
			return 0;
		}
		/*
		 * The Additional Sense Code (ASC) from the UNIT ATTENTION
		 */
		buf[SPC_ASC_KEY_OFFSET] = ua_asc;
		buf[SPC_ASCQ_KEY_OFFSET] = ua_ascq;
		buf[7] = 0x0A;
	} else {
		/*
		 * CURRENT ERROR, NO SENSE
		 */
		buf[0] = 0x70;
		buf[SPC_SENSE_KEY_OFFSET] = NO_SENSE;
		/*
		 * Make sure request data length is enough for additional
		 * sense data.
		 */
		if (cmd->data_length <= 18) {
			buf[7] = 0x00;
			return 0;
		}
		/*
		 * NO ADDITIONAL SENSE INFORMATION
		 */
		buf[SPC_ASC_KEY_OFFSET] = 0x00;
		buf[7] = 0x0A;
	}

	return 0;
}
EXPORT_SYMBOL(transport_generic_emulate_request_sense);

/*
 * Used to obtain Sense Data from underlying Linux/SCSI struct scsi_cmnd
 */
int transport_get_sense_data(struct se_cmd *cmd)
{
	unsigned char *buffer = cmd->sense_buffer, *sense_buffer = NULL;
	struct se_device *dev;
	struct se_task *task = NULL, *task_tmp;
	unsigned long flags;
	u32 offset = 0;

	if (!SE_LUN(cmd)) {
		printk(KERN_ERR "SE_LUN(cmd) is NULL\n");
		return -1;
	}
	spin_lock_irqsave(&T_TASK(cmd)->t_state_lock, flags);
	if (cmd->se_cmd_flags & SCF_SENT_CHECK_CONDITION) {
		spin_unlock_irqrestore(&T_TASK(cmd)->t_state_lock, flags);
		return 0;
	}

	list_for_each_entry_safe(task, task_tmp,
				&T_TASK(cmd)->t_task_list, t_list) {

		if (!task->task_sense)
			continue;

		dev = task->se_dev;
		if (!(dev))
			continue;

		if (!TRANSPORT(dev)->get_sense_buffer) {
			printk(KERN_ERR "TRANSPORT(dev)->get_sense_buffer"
					" is NULL\n");
			continue;
		}

		sense_buffer = TRANSPORT(dev)->get_sense_buffer(task);
		if (!(sense_buffer)) {
			printk(KERN_ERR "ITT[0x%08x]_TASK[%d]: Unable to locate"
				" sense buffer for task with sense\n",
				CMD_TFO(cmd)->get_task_tag(cmd), task->task_no);
			continue;
		}
		spin_unlock_irqrestore(&T_TASK(cmd)->t_state_lock, flags);

		offset = CMD_TFO(cmd)->set_fabric_sense_len(cmd,
				TRANSPORT_SENSE_BUFFER);

		memcpy((void *)&buffer[offset], (void *)sense_buffer,
				TRANSPORT_SENSE_BUFFER);
		cmd->scsi_status = task->task_scsi_status;
		/* Automatically padded */
		cmd->scsi_sense_length =
				(TRANSPORT_SENSE_BUFFER + offset);

		printk(KERN_INFO "HBA_[%u]_PLUG[%s]: Set SAM STATUS: 0x%02x"
				" and sense\n",
			dev->se_hba->hba_id, TRANSPORT(dev)->name,
				cmd->scsi_status);
		return 0;
	}
	spin_unlock_irqrestore(&T_TASK(cmd)->t_state_lock, flags);

	return -1;
}

/*
 * Generic function pointers for target_core_mod/ConfigFS
 */
#define SET_GENERIC_TRANSPORT_FUNCTIONS(cmd)				\
do {									\
	cmd->transport_get_task = &transport_generic_get_task;		\
	cmd->transport_map_buffers_to_tasks =				\
			&transport_generic_map_buffers_to_tasks;	\
	cmd->transport_set_iovec_ptrs =					\
			&transport_generic_set_iovec_ptrs;		\
} while (0)

/*	transport_generic_cmd_sequencer():
 *
 *	Generic Command Sequencer that should work for most DAS transport
 *	drivers.
 *
 *	Called from transport_generic_allocate_tasks() in the $FABRIC_MOD
 *	RX Thread.
 *
 *	FIXME: Need to support other SCSI OPCODES where as well.
 */
static int transport_generic_cmd_sequencer(
	struct se_cmd *cmd,
	unsigned char *cdb)
{
	struct se_device *dev = SE_DEV(cmd);
	struct se_subsystem_dev *su_dev = dev->se_sub_dev;
	int ret, sector_ret = 0;
	u32 sectors = 0, size = 0, pr_reg_type = 0;
	u8 alua_ascq = 0;
	/*
	 * Check for an existing UNIT ATTENTION condition
	 */
	if (core_scsi3_ua_check(cmd, cdb) < 0) {
		cmd->transport_wait_for_tasks =
				&transport_nop_wait_for_tasks;
		transport_get_maps(cmd);
		return TGCS_CHECK_CONDITION_UNIT_ATTENTION;
	}
	/*
	 * Check status of Asymmetric Logical Unit Assignment port
	 */
	ret = T10_ALUA(su_dev)->alua_state_check(cmd, cdb, &alua_ascq);
	if (ret != 0) {
		cmd->transport_wait_for_tasks = &transport_nop_wait_for_tasks;
		transport_get_maps(cmd);
		/*
		 * Set SCSI additional sense code (ASC) to 'LUN Not Accessable';
		 * The ALUA additional sense code qualifier (ASCQ) is determined
		 * by the ALUA primary or secondary access state..
		 */
		if (ret > 0) {
#if 0
			printk(KERN_INFO "[%s]: ALUA TG Port not available,"
				" SenseKey: NOT_READY, ASC/ASCQ: 0x04/0x%02x\n",
				CMD_TFO(cmd)->get_fabric_name(), alua_ascq);
#endif
			transport_set_sense_codes(cmd, 0x04, alua_ascq);
			return TGCS_CHECK_CONDITION_NOT_READY;
		}
		return TGCS_INVALID_CDB_FIELD;
	}
	/*
	 * Check status for SPC-3 Persistent Reservations
	 */
	if (T10_RES(su_dev)->t10_reservation_check(cmd, &pr_reg_type) != 0) {
		if (T10_RES(su_dev)->t10_seq_non_holder(
					cmd, cdb, pr_reg_type) != 0) {
			cmd->transport_wait_for_tasks =
					&transport_nop_wait_for_tasks;
			transport_get_maps(cmd);
			return TGCS_RESERVATION_CONFLICT;
		}
		/*
		 * This means the CDB is allowed for the SCSI Initiator port
		 * when said port is *NOT* holding the legacy SPC-2 or
		 * SPC-3 Persistent Reservation.
		 */
	}

	switch (cdb[0]) {
	case READ_6:
		SET_GENERIC_TRANSPORT_FUNCTIONS(cmd);
		sectors = transport_get_sectors_6(cdb, cmd, &sector_ret);
		if (sector_ret)
			return TGCS_UNSUPPORTED_CDB;
		size = transport_get_size(sectors, cdb, cmd);
		dev_obj_get_mem_SG(cmd->se_orig_obj_ptr, cmd);
		transport_get_maps(cmd);
		cmd->transport_split_cdb = &split_cdb_XX_6;
		cmd->transport_get_lba = &transport_lba_21;
		ret = TGCS_DATA_SG_IO_CDB;
		break;
	case READ_10:
		SET_GENERIC_TRANSPORT_FUNCTIONS(cmd);
		sectors = transport_get_sectors_10(cdb, cmd, &sector_ret);
		if (sector_ret)
			return TGCS_UNSUPPORTED_CDB;
		size = transport_get_size(sectors, cdb, cmd);
		dev_obj_get_mem_SG(cmd->se_orig_obj_ptr, cmd);
		transport_get_maps(cmd);
		cmd->transport_split_cdb = &split_cdb_XX_10;
		cmd->transport_get_lba = &transport_lba_32;
		ret = TGCS_DATA_SG_IO_CDB;
		break;
	case READ_12:
		SET_GENERIC_TRANSPORT_FUNCTIONS(cmd);
		sectors = transport_get_sectors_12(cdb, cmd, &sector_ret);
		if (sector_ret)
			return TGCS_UNSUPPORTED_CDB;
		size = transport_get_size(sectors, cdb, cmd);
		dev_obj_get_mem_SG(cmd->se_orig_obj_ptr, cmd);
		transport_get_maps(cmd);
		cmd->transport_split_cdb = &split_cdb_XX_12;
		cmd->transport_get_lba = &transport_lba_32;
		ret = TGCS_DATA_SG_IO_CDB;
		break;
	case READ_16:
		SET_GENERIC_TRANSPORT_FUNCTIONS(cmd);
		sectors = transport_get_sectors_16(cdb, cmd, &sector_ret);
		if (sector_ret)
			return TGCS_UNSUPPORTED_CDB;
		size = transport_get_size(sectors, cdb, cmd);
		dev_obj_get_mem_SG(cmd->se_orig_obj_ptr, cmd);
		transport_get_maps(cmd);
		cmd->transport_split_cdb = &split_cdb_XX_16;
		cmd->transport_get_long_lba = &transport_lba_64;
		ret = TGCS_DATA_SG_IO_CDB;
		break;
	case WRITE_6:
		SET_GENERIC_TRANSPORT_FUNCTIONS(cmd);
		sectors = transport_get_sectors_6(cdb, cmd, &sector_ret);
		if (sector_ret)
			return TGCS_UNSUPPORTED_CDB;
		size = transport_get_size(sectors, cdb, cmd);
		dev_obj_get_mem_SG(cmd->se_orig_obj_ptr, cmd);
		transport_get_maps(cmd);
		cmd->transport_split_cdb = &split_cdb_XX_6;
		cmd->transport_get_lba = &transport_lba_21;
		ret = TGCS_DATA_SG_IO_CDB;
		break;
	case WRITE_10:
		SET_GENERIC_TRANSPORT_FUNCTIONS(cmd);
		sectors = transport_get_sectors_10(cdb, cmd, &sector_ret);
		if (sector_ret)
			return TGCS_UNSUPPORTED_CDB;
		size = transport_get_size(sectors, cdb, cmd);
		dev_obj_get_mem_SG(cmd->se_orig_obj_ptr, cmd);
		transport_get_maps(cmd);
		cmd->transport_split_cdb = &split_cdb_XX_10;
		cmd->transport_get_lba = &transport_lba_32;
		ret = TGCS_DATA_SG_IO_CDB;
		break;
	case WRITE_12:
		SET_GENERIC_TRANSPORT_FUNCTIONS(cmd);
		sectors = transport_get_sectors_12(cdb, cmd, &sector_ret);
		if (sector_ret)
			return TGCS_UNSUPPORTED_CDB;
		size = transport_get_size(sectors, cdb, cmd);
		dev_obj_get_mem_SG(cmd->se_orig_obj_ptr, cmd);
		transport_get_maps(cmd);
		cmd->transport_split_cdb = &split_cdb_XX_12;
		cmd->transport_get_lba = &transport_lba_32;
		ret = TGCS_DATA_SG_IO_CDB;
		break;
	case WRITE_16:
		SET_GENERIC_TRANSPORT_FUNCTIONS(cmd);
		sectors = transport_get_sectors_16(cdb, cmd, &sector_ret);
		if (sector_ret)
			return TGCS_UNSUPPORTED_CDB;
		size = transport_get_size(sectors, cdb, cmd);
		dev_obj_get_mem_SG(cmd->se_orig_obj_ptr, cmd);
		transport_get_maps(cmd);
		cmd->transport_split_cdb = &split_cdb_XX_16;
		cmd->transport_get_long_lba = &transport_lba_64;
		ret = TGCS_DATA_SG_IO_CDB;
		break;
	case 0xa3:
		SET_GENERIC_TRANSPORT_FUNCTIONS(cmd);
		if (TRANSPORT(dev)->get_device_type(dev) != TYPE_ROM) {
			/* MAINTENANCE_IN from SCC-2 */
			/*
			 * Check for emulated MI_REPORT_TARGET_PGS.
			 */
			if (cdb[1] == MI_REPORT_TARGET_PGS) {
				cmd->transport_emulate_cdb =
				(T10_ALUA(su_dev)->alua_type ==
				 SPC3_ALUA_EMULATED) ?
				&core_scsi3_emulate_report_target_port_groups :
				NULL;
			}
			size = (cdb[6] << 24) | (cdb[7] << 16) |
			       (cdb[8] << 8) | cdb[9];
		} else {
			/* GPCMD_SEND_KEY from multi media commands */
			size = (cdb[8] << 8) + cdb[9];
		}
		dev_obj_get_mem_buf(cmd->se_orig_obj_ptr, cmd);
		transport_get_maps(cmd);
		ret = TGCS_CONTROL_NONSG_IO_CDB;
		break;
	case MODE_SELECT:
		SET_GENERIC_TRANSPORT_FUNCTIONS(cmd);
		size = cdb[4];
		dev_obj_get_mem_SG(cmd->se_orig_obj_ptr, cmd);
		transport_get_maps(cmd);
		ret = TGCS_CONTROL_SG_IO_CDB;
		break;
	case MODE_SELECT_10:
		SET_GENERIC_TRANSPORT_FUNCTIONS(cmd);
		size = (cdb[7] << 8) + cdb[8];
		dev_obj_get_mem_SG(cmd->se_orig_obj_ptr, cmd);
		transport_get_maps(cmd);
		ret = TGCS_CONTROL_SG_IO_CDB;
		break;
	case MODE_SENSE:
		SET_GENERIC_TRANSPORT_FUNCTIONS(cmd);
		size = cdb[4];
		dev_obj_get_mem_buf(cmd->se_orig_obj_ptr, cmd);
		transport_get_maps(cmd);
		ret = TGCS_CONTROL_NONSG_IO_CDB;
		break;
	case MODE_SENSE_10:
	case GPCMD_READ_BUFFER_CAPACITY:
	case GPCMD_SEND_OPC:
	case LOG_SELECT:
	case LOG_SENSE:
		SET_GENERIC_TRANSPORT_FUNCTIONS(cmd);
		size = (cdb[7] << 8) + cdb[8];
		dev_obj_get_mem_buf(cmd->se_orig_obj_ptr, cmd);
		transport_get_maps(cmd);
		ret = TGCS_CONTROL_NONSG_IO_CDB;
		break;
	case READ_BLOCK_LIMITS:
		SET_GENERIC_TRANSPORT_FUNCTIONS(cmd);
		size = READ_BLOCK_LEN;
		dev_obj_get_mem_buf(cmd->se_orig_obj_ptr, cmd);
		transport_get_maps(cmd);
		ret = TGCS_CONTROL_NONSG_IO_CDB;
		break;
	case GPCMD_GET_CONFIGURATION:
	case GPCMD_READ_FORMAT_CAPACITIES:
	case GPCMD_READ_DISC_INFO:
	case GPCMD_READ_TRACK_RZONE_INFO:
		SET_GENERIC_TRANSPORT_FUNCTIONS(cmd);
		size = (cdb[7] << 8) + cdb[8];
		dev_obj_get_mem_SG(cmd->se_orig_obj_ptr, cmd);
		transport_get_maps(cmd);
		ret = TGCS_CONTROL_SG_IO_CDB;
		break;
	case PERSISTENT_RESERVE_IN:
	case PERSISTENT_RESERVE_OUT:
		SET_GENERIC_TRANSPORT_FUNCTIONS(cmd);
		cmd->transport_emulate_cdb =
			(T10_RES(su_dev)->res_type ==
			 SPC3_PERSISTENT_RESERVATIONS) ?
			&core_scsi3_emulate_pr : NULL;
		size = (cdb[7] << 8) + cdb[8];
		dev_obj_get_mem_buf(cmd->se_orig_obj_ptr, cmd);
		transport_get_maps(cmd);
		ret = TGCS_CONTROL_NONSG_IO_CDB;
		break;
	case GPCMD_MECHANISM_STATUS:
	case GPCMD_READ_DVD_STRUCTURE:
		SET_GENERIC_TRANSPORT_FUNCTIONS(cmd);
		size = (cdb[8] << 8) + cdb[9];
		dev_obj_get_mem_SG(cmd->se_orig_obj_ptr, cmd);
		transport_get_maps(cmd);
		ret = TGCS_CONTROL_SG_IO_CDB;
		break;
	case READ_POSITION:
		SET_GENERIC_TRANSPORT_FUNCTIONS(cmd);
		size = READ_POSITION_LEN;
		dev_obj_get_mem_buf(cmd->se_orig_obj_ptr, cmd);
		transport_get_maps(cmd);
		ret = TGCS_CONTROL_NONSG_IO_CDB;
		break;
	case 0xa4:
		SET_GENERIC_TRANSPORT_FUNCTIONS(cmd);
		if (TRANSPORT(dev)->get_device_type(dev) != TYPE_ROM) {
			/* MAINTENANCE_OUT from SCC-2
			 *
			 * Check for emulated MO_SET_TARGET_PGS.
			 */
			if (cdb[1] == MO_SET_TARGET_PGS) {
				cmd->transport_emulate_cdb =
				(T10_ALUA(su_dev)->alua_type ==
					SPC3_ALUA_EMULATED) ?
				&core_scsi3_emulate_set_target_port_groups :
				NULL;
			}

			size = (cdb[6] << 24) | (cdb[7] << 16) |
			       (cdb[8] << 8) | cdb[9];
		} else  {
			/* GPCMD_REPORT_KEY from multi media commands */
			size = (cdb[8] << 8) + cdb[9];
		}
		dev_obj_get_mem_buf(cmd->se_orig_obj_ptr, cmd);
		transport_get_maps(cmd);
		ret = TGCS_CONTROL_NONSG_IO_CDB;
		break;
	case INQUIRY:
		SET_GENERIC_TRANSPORT_FUNCTIONS(cmd);
		size = (cdb[3] << 8) + cdb[4];
		dev_obj_get_mem_buf(cmd->se_orig_obj_ptr, cmd);
		transport_get_maps(cmd);
		/*
		 * Do implict HEAD_OF_QUEUE processing for INQUIRY.
		 * See spc4r17 section 5.3
		 */
		if (SE_DEV(cmd)->dev_task_attr_type == SAM_TASK_ATTR_EMULATED)
			cmd->sam_task_attr = TASK_ATTR_HOQ;
		ret = TGCS_CONTROL_NONSG_IO_CDB;
		break;
	case READ_BUFFER:
		SET_GENERIC_TRANSPORT_FUNCTIONS(cmd);
		size = (cdb[6] << 16) + (cdb[7] << 8) + cdb[8];
		dev_obj_get_mem_buf(cmd->se_orig_obj_ptr, cmd);
		transport_get_maps(cmd);
		ret = TGCS_CONTROL_NONSG_IO_CDB;
		break;
	case READ_CAPACITY:
		SET_GENERIC_TRANSPORT_FUNCTIONS(cmd);
		size = READ_CAP_LEN;
		dev_obj_get_mem_buf(cmd->se_orig_obj_ptr, cmd);
		transport_get_maps(cmd);
		ret = TGCS_CONTROL_NONSG_IO_CDB;
		break;
	case READ_MEDIA_SERIAL_NUMBER:
	case SECURITY_PROTOCOL_IN:
	case SECURITY_PROTOCOL_OUT:
		SET_GENERIC_TRANSPORT_FUNCTIONS(cmd);
		size = (cdb[6] << 24) | (cdb[7] << 16) | (cdb[8] << 8) | cdb[9];
		dev_obj_get_mem_buf(cmd->se_orig_obj_ptr, cmd);
		transport_get_maps(cmd);
		ret = TGCS_CONTROL_NONSG_IO_CDB;
		break;
	case SERVICE_ACTION_IN:
	case ACCESS_CONTROL_IN:
	case ACCESS_CONTROL_OUT:
	case EXTENDED_COPY:
	case READ_ATTRIBUTE:
	case RECEIVE_COPY_RESULTS:
	case WRITE_ATTRIBUTE:
		SET_GENERIC_TRANSPORT_FUNCTIONS(cmd);
		size = (cdb[10] << 24) | (cdb[11] << 16) |
		       (cdb[12] << 8) | cdb[13];
		dev_obj_get_mem_buf(cmd->se_orig_obj_ptr, cmd);
		transport_get_maps(cmd);
		ret = TGCS_CONTROL_NONSG_IO_CDB;
		break;
	case VARIABLE_LENGTH_CMD:
		SET_GENERIC_TRANSPORT_FUNCTIONS(cmd);
		size = (cdb[10] << 8) | cdb[11];
		dev_obj_get_mem_buf(cmd->se_orig_obj_ptr, cmd);
		transport_get_maps(cmd);
		ret = TGCS_CONTROL_NONSG_IO_CDB;
		break;
	case RECEIVE_DIAGNOSTIC:
	case SEND_DIAGNOSTIC:
		SET_GENERIC_TRANSPORT_FUNCTIONS(cmd);
		size = (cdb[3] << 8) | cdb[4];
		dev_obj_get_mem_buf(cmd->se_orig_obj_ptr, cmd);
		transport_get_maps(cmd);
		ret = TGCS_CONTROL_NONSG_IO_CDB;
		break;
/* #warning FIXME: Figure out correct GPCMD_READ_CD blocksize. */
#if 0
	case GPCMD_READ_CD:
		SET_GENERIC_TRANSPORT_FUNCTIONS(cmd);
		sectors = (cdb[6] << 16) + (cdb[7] << 8) + cdb[8];
		size = (2336 * sectors);
		dev_obj_get_mem_buf(cmd->se_orig_obj_ptr, cmd);
		transport_get_maps(cmd);
		ret = TGCS_CONTROL_NONSG_IO_CDB;
		break;
#endif
	case READ_TOC:
		SET_GENERIC_TRANSPORT_FUNCTIONS(cmd);
		size = cdb[8];
		dev_obj_get_mem_buf(cmd->se_orig_obj_ptr, cmd);
		transport_get_maps(cmd);
		ret = TGCS_CONTROL_NONSG_IO_CDB;
		break;
	case REQUEST_SENSE:
		SET_GENERIC_TRANSPORT_FUNCTIONS(cmd);
		size = cdb[4];
		dev_obj_get_mem_buf(cmd->se_orig_obj_ptr, cmd);
		transport_get_maps(cmd);
		ret = TGCS_CONTROL_NONSG_IO_CDB;
		break;
	case READ_ELEMENT_STATUS:
		SET_GENERIC_TRANSPORT_FUNCTIONS(cmd);
		size = 65536 * cdb[7] + 256 * cdb[8] + cdb[9];
		dev_obj_get_mem_buf(cmd->se_orig_obj_ptr, cmd);
		transport_get_maps(cmd);
		ret = TGCS_CONTROL_NONSG_IO_CDB;
		break;
	case WRITE_BUFFER:
		SET_GENERIC_TRANSPORT_FUNCTIONS(cmd);
		size = (cdb[6] << 16) + (cdb[7] << 8) + cdb[8];
		dev_obj_get_mem_buf(cmd->se_orig_obj_ptr, cmd);
		transport_get_maps(cmd);
		ret = TGCS_CONTROL_NONSG_IO_CDB;
		break;
	case RESERVE:
	case RESERVE_10:
		/*
		 * The SPC-2 RESERVE does not contain a size in the SCSI CDB.
		 * Assume the passthrough or $FABRIC_MOD will tell us about it.
		 */
		if (cdb[0] == RESERVE_10)
			size = (cdb[7] << 8) | cdb[8];
		else
			size = cmd->data_length;

		SET_GENERIC_TRANSPORT_FUNCTIONS(cmd);
		cmd->transport_allocate_resources =
				&transport_generic_allocate_none;
		transport_get_maps(cmd);
		/*
		 * Setup the legacy emulated handler for SPC-2 and
		 * >= SPC-3 compatible reservation handling (CRH=1)
		 * Otherwise, we assume the underlying SCSI logic is
		 * is running in SPC_PASSTHROUGH, and wants reservations
		 * emulation disabled.
		 */
		cmd->transport_emulate_cdb =
				(T10_RES(su_dev)->res_type !=
				 SPC_PASSTHROUGH) ?
				&core_scsi2_emulate_crh : NULL;
		ret = TGCS_NON_DATA_CDB;
		break;
	case RELEASE:
	case RELEASE_10:
		/*
		 * The SPC-2 RELEASE does not contain a size in the SCSI CDB.
		 * Assume the passthrough or $FABRIC_MOD will tell us about it.
		*/
		if (cdb[0] == RELEASE_10)
			size = (cdb[7] << 8) | cdb[8];
		else
			size = cmd->data_length;

		SET_GENERIC_TRANSPORT_FUNCTIONS(cmd);
		cmd->transport_allocate_resources =
				&transport_generic_allocate_none;
		transport_get_maps(cmd);
		cmd->transport_emulate_cdb =
				(T10_RES(su_dev)->res_type !=
				 SPC_PASSTHROUGH) ?
				&core_scsi2_emulate_crh : NULL;
		ret = TGCS_NON_DATA_CDB;
		break;
	case ALLOW_MEDIUM_REMOVAL:
	case GPCMD_CLOSE_TRACK:
	case ERASE:
	case INITIALIZE_ELEMENT_STATUS:
	case GPCMD_LOAD_UNLOAD:
	case REZERO_UNIT:
	case SEEK_10:
	case GPCMD_SET_SPEED:
	case SPACE:
	case START_STOP:
	case SYNCHRONIZE_CACHE:
	case TEST_UNIT_READY:
	case VERIFY:
	case WRITE_FILEMARKS:
	case MOVE_MEDIUM:
		SET_GENERIC_TRANSPORT_FUNCTIONS(cmd);
		cmd->transport_allocate_resources =
				&transport_generic_allocate_none;
		transport_get_maps(cmd);
		ret = TGCS_NON_DATA_CDB;
		break;
	case REPORT_LUNS:
		SET_GENERIC_TRANSPORT_FUNCTIONS(cmd);
		cmd->transport_emulate_cdb =
				&transport_core_report_lun_response;
		size = (cdb[6] << 24) | (cdb[7] << 16) | (cdb[8] << 8) | cdb[9];
		dev_obj_get_mem_buf(cmd->se_orig_obj_ptr, cmd);
		transport_get_maps(cmd);
		/*
		 * Do implict HEAD_OF_QUEUE processing for REPORT_LUNS
		 * See spc4r17 section 5.3
		 */
		if (SE_DEV(cmd)->dev_task_attr_type == SAM_TASK_ATTR_EMULATED)
			cmd->sam_task_attr = TASK_ATTR_HOQ;
		ret = TGCS_CONTROL_NONSG_IO_CDB;
		break;
	default:
		printk(KERN_WARNING "TARGET_CORE[%s]: Unsupported SCSI Opcode"
			" 0x%02x, sending CHECK_CONDITION.\n",
			CMD_TFO(cmd)->get_fabric_name(), cdb[0]);
		cmd->transport_wait_for_tasks = &transport_nop_wait_for_tasks;
		transport_get_maps(cmd);
		return TGCS_UNSUPPORTED_CDB;
	}

	if (size != cmd->data_length) {
		printk(KERN_WARNING "TARGET_CORE[%s]: Expected Transfer Length:"
			" %u does not match SCSI CDB Length: %u for SAM Opcode:"
			" 0x%02x\n", CMD_TFO(cmd)->get_fabric_name(),
				cmd->data_length, size, cdb[0]);

		cmd->cmd_spdtl = size;

		if (cmd->data_direction == SE_DIRECTION_WRITE) {
			printk(KERN_ERR "Rejecting underflow/overflow"
					" WRITE data\n");
			return TGCS_INVALID_CDB_FIELD;
		}
		/*
		 * Reject READ_* or WRITE_* with overflow/underflow for
		 * type SCF_SCSI_DATA_SG_IO_CDB.
		 */
		if (!(ret) && (DEV_ATTRIB(dev)->block_size != 512))  {
			printk(KERN_ERR "Failing OVERFLOW/UNDERFLOW for LBA op"
				" CDB on non 512-byte sector setup subsystem"
				" plugin: %s\n", TRANSPORT(dev)->name);
			/* Returns CHECK_CONDITION + INVALID_CDB_FIELD */
			return TGCS_INVALID_CDB_FIELD;
		}

		if (size > cmd->data_length) {
			cmd->se_cmd_flags |= SCF_OVERFLOW_BIT;
			cmd->residual_count = (size - cmd->data_length);
		} else {
			cmd->se_cmd_flags |= SCF_UNDERFLOW_BIT;
			cmd->residual_count = (cmd->data_length - size);
		}
		cmd->data_length = size;
	}

	transport_set_supported_SAM_opcode(cmd);
	return ret;
}

static inline struct se_cmd *transport_alloc_passthrough_cmd(
	u32 data_length,
	int data_direction)
{
	return __transport_alloc_se_cmd(&passthrough_fabric_ops, NULL, NULL,
			data_length, data_direction, TASK_ATTR_SIMPLE);
}

static inline void transport_release_tasks(struct se_cmd *);

struct se_cmd *transport_allocate_passthrough(
	unsigned char *cdb,
	int data_direction,
	u32 se_cmd_flags,
	void *mem,
	u32 se_mem_num,
	u32 length,
	void *type_ptr)
{
	struct se_cmd *cmd;
	struct se_transform_info ti;

	cmd = transport_alloc_passthrough_cmd(length, data_direction);
	if (!(cmd))
		return NULL;
	/*
	 * Simulate an SE LUN entry need for passing SCSI CDBs into
	 * struct se_cmd.
	 */
	cmd->se_lun = kzalloc(sizeof(struct se_lun), GFP_KERNEL);
	if (!(cmd->se_lun)) {
		printk(KERN_ERR "Unable to allocate cmd->se_lun\n");
		goto fail;
	}

	spin_lock_init(&cmd->se_lun->lun_sep_lock);
	SE_LUN(cmd)->lun_type_ptr = type_ptr;

	cmd->se_orig_obj_ptr = type_ptr;
	cmd->se_cmd_flags = se_cmd_flags;
	SE_LUN(cmd)->se_dev = (struct se_device *) type_ptr;

	/*
	 * Double check that the passed object is currently accepting CDBs
	 */
	if (dev_obj_check_online(type_ptr) != 0) {
		DEBUG_SO("dev_obj_check_online() failed!\n");
		goto fail;
	}

	cmd->data_length = length;
	cmd->data_direction = data_direction;
	cmd->se_cmd_flags |= SCF_CMD_PASSTHROUGH;

	if (transport_generic_allocate_tasks(cmd, cdb) < 0)
		goto fail;

	memset(&ti, 0, sizeof(struct se_transform_info));
	ti.ti_data_length = cmd->data_length;
	ti.ti_dev = SE_LUN(cmd)->se_dev;
	ti.ti_se_cmd = cmd;
	ti.se_obj_ptr = type_ptr;

	DEBUG_SO("ti.se_obj_ptr: %p\n", ti.se_obj_ptr);

	if (!mem) {
		if (cmd->transport_allocate_resources(cmd, cmd->data_length,
					PAGE_SIZE) < 0)
			goto fail;
	} else {
		/*
		 * Passed *mem will contain a list_head containing preformatted
		 * struct se_mem elements...
		 */
		T_TASK(cmd)->t_mem_list = (struct list_head *)mem;
		T_TASK(cmd)->t_task_se_num = se_mem_num;
		cmd->se_cmd_flags |= SCF_CMD_PASSTHROUGH_NOALLOC;

#ifdef DEBUG_PASSTHROUGH
		{
		u32 total_se_length = 0;
		struct se_mem *se_mem, *se_mem_tmp;

		DEBUG_PT("Preallocated se_mem_list: %p se_mem_num: %d\n",
				mem, se_mem_num);

		list_for_each_entry_safe(se_mem, se_mem_tmp,
				T_TASK(cmd)->t_mem_list, se_list) {
			total_se_length += se_mem->se_len;
			DEBUG_PT("se_mem: %p se_mem->se_page: %p %d:%d\n",
				se_mem, se_mem->se_page, se_mem->se_len,
				se_mem->se_off);
		}
		DEBUG_PT("Total calculated total_se_length: %u\n",
				total_se_length);

		if (total_se_length != length) {
			printk(KERN_ERR "Passed length: %u does not equal"
				" total_se_length: %u\n", length,
					total_se_length);
			BUG();
		}
		}
#endif
	}

	if (transport_get_sectors(cmd, type_ptr) < 0)
		goto fail;

	if (transport_new_cmd_obj(cmd, &ti, type_ptr, 0) < 0)
		goto fail;

	return cmd;

fail:
	if (T_TASK(cmd))
		transport_release_tasks(cmd);
	kfree(T_TASK(cmd));
	kfree(cmd->se_lun);
	transport_free_se_cmd(cmd);

	return NULL;
}
EXPORT_SYMBOL(transport_allocate_passthrough);

void transport_passthrough_release(
	struct se_cmd *cmd)
{
	if (!cmd) {
		printk(KERN_ERR "transport_passthrough_release passed"
			" NULL struct se_cmd\n");
		return;
	}

	if (cmd->transport_wait_for_tasks)
		cmd->transport_wait_for_tasks(cmd, 0, 0);

	transport_generic_remove(cmd, 0, 0);
}
EXPORT_SYMBOL(transport_passthrough_release);

int transport_passthrough_complete(
	struct se_cmd *cmd)
{
	if (dev_obj_check_shutdown(cmd->se_orig_obj_ptr) != 0)
		return -2;

	switch (cmd->scsi_status) {
	case 0x00: /* GOOD */
		DEBUG_PT("SCSI Status: GOOD\n");
		return 0;
	case 0x02: /* CHECK_CONDITION */
		DEBUG_PT("SCSI Status: CHECK_CONDITION\n");
/* #warning FIXME: Do some basic return values for Sense Data */
		return -1;
	default:
		DEBUG_PT("SCSI Status: 0x%02x\n", cmd->scsi_status);
		return -1;
	}

	return 0;
}

/*
 * This function will copy a contiguous *src buffer into a destination
 * struct scatterlist array.
 */
void transport_memcpy_write_contig(
	struct se_cmd *cmd,
	struct scatterlist *sg_d,
	unsigned char *src)
{
	u32 i = 0, length = 0, total_length = cmd->data_length;
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
}
EXPORT_SYMBOL(transport_memcpy_write_contig);

/*
 * This function will copy a struct scatterlist array *sg_s into a destination
 * contiguous *dst buffer.
 */
void transport_memcpy_read_contig(
	struct se_cmd *cmd,
	unsigned char *dst,
	struct scatterlist *sg_s)
{
	u32 i = 0, length = 0, total_length = cmd->data_length;
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
}
EXPORT_SYMBOL(transport_memcpy_read_contig);

/*     transport_generic_passthrough():
 *
 *
 */
int transport_generic_passthrough_async(
	struct se_cmd *cmd,
	void (*callback)(struct se_cmd *cmd,
		void *callback_arg, int complete_status),
	void *callback_arg)
{
	int write = (cmd->data_direction == SE_DIRECTION_WRITE);
	int no_alloc = (cmd->se_cmd_flags & SCF_CMD_PASSTHROUGH_NOALLOC);
	int pt_done = (cmd->transport_passthrough_done != NULL);

	if (callback) {
		cmd->callback = callback;
		cmd->callback_arg = callback_arg;
	}

	if (transport_generic_handle_cdb(cmd) < 0)
		return -1;

	if (write && !no_alloc) {
		if (wait_for_completion_interruptible(
			&T_TASK(cmd)->t_transport_passthrough_wcomp) != 0)
			return -1;

		transport_generic_process_write(cmd);
	}

	if (callback || pt_done)
		return 0;

	wait_for_completion(&T_TASK(cmd)->t_transport_passthrough_comp);

	return transport_passthrough_complete(cmd);
}

int transport_generic_passthrough(struct se_cmd *cmd)
{
	return transport_generic_passthrough_async(cmd, NULL, NULL);
}
EXPORT_SYMBOL(transport_generic_passthrough);

/*
 * Called from transport_generic_complete_ok() and
 * transport_generic_request_failure() to determine which dormant/delayed
 * and ordered cmds need to have their tasks added to the execution queue.
 */
void transport_complete_task_attr(struct se_cmd *cmd)
{
	struct se_device *dev = SE_DEV(cmd);
	struct se_cmd *cmd_p, *cmd_tmp;
	int new_active_tasks = 0;

	if (cmd->sam_task_attr == TASK_ATTR_SIMPLE) {
		atomic_dec(&dev->simple_cmds);
		smp_mb__after_atomic_dec();
		dev->dev_cur_ordered_id++;
		DEBUG_STA("Incremented dev->dev_cur_ordered_id: %u for"
			" SIMPLE: %u\n", dev->dev_cur_ordered_id,
			cmd->se_ordered_id);
	} else if (cmd->sam_task_attr == TASK_ATTR_HOQ) {
		atomic_dec(&dev->dev_hoq_count);
		smp_mb__after_atomic_dec();
		dev->dev_cur_ordered_id++;
		DEBUG_STA("Incremented dev_cur_ordered_id: %u for"
			" HEAD_OF_QUEUE: %u\n", dev->dev_cur_ordered_id,
			cmd->se_ordered_id);
	} else if (cmd->sam_task_attr == TASK_ATTR_ORDERED) {
		spin_lock(&dev->ordered_cmd_lock);
		list_del(&cmd->se_ordered_list);
		atomic_dec(&dev->dev_ordered_sync);
		smp_mb__after_atomic_dec();
		spin_unlock(&dev->ordered_cmd_lock);

		dev->dev_cur_ordered_id++;
		DEBUG_STA("Incremented dev_cur_ordered_id: %u for ORDERED:"
			" %u\n", dev->dev_cur_ordered_id, cmd->se_ordered_id);
	}
	/*
	 * Process all commands up to the last received
	 * ORDERED task attribute which requires another blocking
	 * boundary
	 */
	spin_lock(&dev->delayed_cmd_lock);
	list_for_each_entry_safe(cmd_p, cmd_tmp,
			&dev->delayed_cmd_list, se_delayed_list) {

		list_del(&cmd_p->se_delayed_list);
		spin_unlock(&dev->delayed_cmd_lock);

		DEBUG_STA("Calling add_tasks() for"
			" cmd_p: 0x%02x Task Attr: 0x%02x"
			" Dormant -> Active, se_ordered_id: %u\n",
			T_TASK(cmd_p)->t_task_cdb[0],
			cmd_p->sam_task_attr, cmd_p->se_ordered_id);

		transport_add_tasks_from_cmd(cmd_p);
		new_active_tasks++;

		spin_lock(&dev->delayed_cmd_lock);
		if (cmd_p->sam_task_attr == TASK_ATTR_ORDERED)
			break;
	}
	spin_unlock(&dev->delayed_cmd_lock);
	/*
	 * If new tasks have become active, wake up the transport thread
	 * to do the processing of the Active tasks.
	 */
	if (new_active_tasks != 0)
		wake_up_interruptible(&dev->dev_queue_obj->thread_wq);
}

/*	transport_generic_complete_ok():
 *
 *
 */
void transport_generic_complete_ok(struct se_cmd *cmd)
{
	int reason = 0;
	/*
	 * Check if we need to move delayed/dormant tasks from cmds on the
	 * delayed execution list after a HEAD_OF_QUEUE or ORDERED Task
	 * Attribute.
	 */
	if (SE_DEV(cmd)->dev_task_attr_type == SAM_TASK_ATTR_EMULATED)
		transport_complete_task_attr(cmd);
	/*
	 * Check if we need to retrieve a sense buffer from
	 * the struct se_cmd in question.
	 */
	if (cmd->se_cmd_flags & SCF_CMD_PASSTHROUGH) {
		transport_lun_remove_cmd(cmd);
		if (!(transport_cmd_check_stop_to_fabric(cmd)))
			transport_passthrough_check_stop(cmd);
		return;
	} else if (cmd->se_cmd_flags & SCF_TRANSPORT_TASK_SENSE) {
		if (transport_get_sense_data(cmd) < 0)
			reason = NON_EXISTENT_LUN;

		/*
		 * Only set when an struct se_task->task_scsi_status returned
		 * a non GOOD status.
		 */
		if (cmd->scsi_status) {
			transport_send_check_condition_and_sense(
					cmd, reason, 1);
			transport_lun_remove_cmd(cmd);
			transport_cmd_check_stop_to_fabric(cmd);
			return;
		}
	}

	switch (cmd->data_direction) {
	case SE_DIRECTION_READ:
		spin_lock(&cmd->se_lun->lun_sep_lock);
		if (SE_LUN(cmd)->lun_sep) {
			SE_LUN(cmd)->lun_sep->sep_stats.tx_data_octets +=
					cmd->data_length;
		}
		spin_unlock(&cmd->se_lun->lun_sep_lock);
		CMD_TFO(cmd)->queue_data_in(cmd);
		break;
	case SE_DIRECTION_WRITE:
		spin_lock(&cmd->se_lun->lun_sep_lock);
		if (SE_LUN(cmd)->lun_sep) {
			SE_LUN(cmd)->lun_sep->sep_stats.rx_data_octets +=
				cmd->data_length;
		}
		spin_unlock(&cmd->se_lun->lun_sep_lock);
		/* Fall through for SE_DIRECTION_WRITE */
	case SE_DIRECTION_NONE:
		CMD_TFO(cmd)->queue_status(cmd);
		break;
	default:
		break;
	}

	transport_lun_remove_cmd(cmd);
	transport_cmd_check_stop_to_fabric(cmd);
}

void transport_free_dev_tasks(struct se_cmd *cmd)
{
	struct se_task *task, *task_tmp;
	unsigned long flags;

	spin_lock_irqsave(&T_TASK(cmd)->t_state_lock, flags);
	list_for_each_entry_safe(task, task_tmp,
				&T_TASK(cmd)->t_task_list, t_list) {
		if (atomic_read(&task->task_active))
			continue;

		if (!task->transport_req)
			continue;

		kfree(task->task_sg);

		spin_unlock_irqrestore(&T_TASK(cmd)->t_state_lock, flags);
		if (task->se_dev)
			TRANSPORT(task->se_dev)->free_task(task);
		else
			printk(KERN_ERR "task[%u] - task->se_dev is NULL\n",
				task->task_no);
		spin_lock_irqsave(&T_TASK(cmd)->t_state_lock, flags);

		list_del(&task->t_list);
		kmem_cache_free(se_task_cache, task);
	}
	spin_unlock_irqrestore(&T_TASK(cmd)->t_state_lock, flags);
}

static inline void transport_free_pages(struct se_cmd *cmd)
{
	struct se_mem *se_mem, *se_mem_tmp;
	int free_page =
		((cmd->se_cmd_flags & SCF_PASSTHROUGH_SG_TO_MEM_NOALLOC) == 0);

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
	 * Caller will handle releasing of struct se_mem.
	 */
	if (cmd->se_cmd_flags & SCF_CMD_PASSTHROUGH_NOALLOC)
		return;

	if (!(T_TASK(cmd)->t_task_se_num))
		return;

	list_for_each_entry_safe(se_mem, se_mem_tmp,
			T_TASK(cmd)->t_mem_list, se_list) {
		/*
		 * We only release call __free_page(struct se_mem->se_page) when
		 * SCF_PASSTHROUGH_SG_TO_MEM_NOALLOC is NOT in use,
		 */
		if (free_page)
			__free_page(se_mem->se_page);

		list_del(&se_mem->se_list);
		kmem_cache_free(se_mem_cache, se_mem);
	}

	kfree(T_TASK(cmd)->t_mem_list);
	T_TASK(cmd)->t_mem_list = NULL;
	T_TASK(cmd)->t_task_se_num = 0;
}

static inline void transport_release_tasks(struct se_cmd *cmd)
{
	transport_free_dev_tasks(cmd);
}

static inline int transport_dec_and_check(struct se_cmd *cmd)
{
	unsigned long flags;

	spin_lock_irqsave(&T_TASK(cmd)->t_state_lock, flags);
	if (atomic_read(&T_TASK(cmd)->t_fe_count)) {
		if (!(atomic_dec_and_test(&T_TASK(cmd)->t_fe_count))) {
			spin_unlock_irqrestore(&T_TASK(cmd)->t_state_lock,
					flags);
			return 1;
		}
	}

	if (atomic_read(&T_TASK(cmd)->t_se_count)) {
		if (!(atomic_dec_and_test(&T_TASK(cmd)->t_se_count))) {
			spin_unlock_irqrestore(&T_TASK(cmd)->t_state_lock,
					flags);
			return 1;
		}
	}
	spin_unlock_irqrestore(&T_TASK(cmd)->t_state_lock, flags);

	return 0;
}

void transport_release_fe_cmd(struct se_cmd *cmd)
{
	unsigned long flags;

	if (transport_dec_and_check(cmd))
		return;

	spin_lock_irqsave(&T_TASK(cmd)->t_state_lock, flags);
	if (!(atomic_read(&T_TASK(cmd)->transport_dev_active))) {
		spin_unlock_irqrestore(&T_TASK(cmd)->t_state_lock, flags);
		goto free_pages;
	}
	atomic_set(&T_TASK(cmd)->transport_dev_active, 0);
	transport_all_task_dev_remove_state(cmd);
	spin_unlock_irqrestore(&T_TASK(cmd)->t_state_lock, flags);

	transport_release_tasks(cmd);
free_pages:
	transport_free_pages(cmd);

	if (cmd->se_cmd_flags & SCF_CMD_PASSTHROUGH)
		kfree(cmd->se_lun);

	CMD_TFO(cmd)->release_cmd_direct(cmd);
	transport_free_se_cmd(cmd);
}

/*	transport_generic_remove():
 *
 *
 */
int transport_generic_remove(
	struct se_cmd *cmd,
	int release_to_pool,
	int session_reinstatement)
{
	unsigned long flags;

	if (!(T_TASK(cmd)))
		goto release_cmd;

	if (transport_dec_and_check(cmd)) {
		if (session_reinstatement) {
			spin_lock_irqsave(&T_TASK(cmd)->t_state_lock, flags);
			transport_all_task_dev_remove_state(cmd);
			spin_unlock_irqrestore(&T_TASK(cmd)->t_state_lock,
					flags);
		}
		return 1;
	}

	spin_lock_irqsave(&T_TASK(cmd)->t_state_lock, flags);
	if (!(atomic_read(&T_TASK(cmd)->transport_dev_active))) {
		spin_unlock_irqrestore(&T_TASK(cmd)->t_state_lock, flags);
		goto free_pages;
	}
	atomic_set(&T_TASK(cmd)->transport_dev_active, 0);
	transport_all_task_dev_remove_state(cmd);
	spin_unlock_irqrestore(&T_TASK(cmd)->t_state_lock, flags);

	transport_release_tasks(cmd);
free_pages:
	transport_free_pages(cmd);

release_cmd:
	if (release_to_pool && !(cmd->se_cmd_flags & SCF_CMD_PASSTHROUGH))
		transport_release_cmd_to_pool(cmd);
	else {
		if (cmd->se_cmd_flags & SCF_CMD_PASSTHROUGH)
			kfree(cmd->se_lun);

		CMD_TFO(cmd)->release_cmd_direct(cmd);
		transport_free_se_cmd(cmd);
	}

	return 0;
}

int transport_generic_map_mem_to_cmd(
	struct se_cmd *cmd,
	void *mem,
	u32 se_mem_num)
{
	u32 se_mem_cnt_out = 0, se_mem_task_off = 0;
	int ret;

	if (!(mem) || !(se_mem_num))
		return 0;
	/*
	 * Passed *mem will contain a list_head containing preformatted
	 * struct se_mem elements...
	 */
	if (!(cmd->se_cmd_flags & SCF_PASSTHROUGH_SG_TO_MEM)) {
		T_TASK(cmd)->t_mem_list = (struct list_head *)mem;
		T_TASK(cmd)->t_task_se_num = se_mem_num;
		cmd->se_cmd_flags |= SCF_CMD_PASSTHROUGH_NOALLOC;
		return 0;
	}
	/*
	 * Otherwise, assume the caller is passing a struct scatterlist
	 * array from include/linux/scatterlist.h
	 */
	if ((cmd->se_cmd_flags & SCF_SCSI_DATA_SG_IO_CDB) ||
	    (cmd->se_cmd_flags & SCF_SCSI_CONTROL_SG_IO_CDB)) {
		/*
		 * For CDB using TCM struct se_mem linked list scatterlist memory
		 * processed into a TCM struct se_subsystem_dev, we do the mapping
		 * from the passed physical memory to struct se_mem->se_page here.
		 */ 
		T_TASK(cmd)->t_mem_list = transport_init_se_mem_list();
		if (!(T_TASK(cmd)->t_mem_list))
			return -1;

		ret = transport_map_sg_to_mem(cmd,
			T_TASK(cmd)->t_mem_list, mem, &se_mem_cnt_out,
			&se_mem_task_off);
		if (ret < 0)
			return -1;

		T_TASK(cmd)->t_task_se_num = se_mem_cnt_out;
		cmd->se_cmd_flags |= SCF_PASSTHROUGH_SG_TO_MEM_NOALLOC;

	} else if (cmd->se_cmd_flags & SCF_SCSI_CONTROL_NONSG_IO_CDB) {
		/*
		 * For CDBs using a contiguous buffer, save the passed
		 * struct scatterlist memory.  After TCM storage object
		 * processing has completed for this struct se_cmd, the calling
		 * TCM fabric module is expected to call 
		 * transport_memcpy_write_contig() to copy the TCM buffer
		 * back into the passed *mem of type struct scatterlist array.
		 */
		cmd->se_cmd_flags |= SCF_PASSTHROUGH_CONTIG_TO_SG;
		T_TASK(cmd)->t_task_pt_buf = mem;
	}

	return 0;
}
EXPORT_SYMBOL(transport_generic_map_mem_to_cmd);
	

/*	transport_generic_map_buffers_to_tasks():
 *
 *	Called from transport_generic_new_cmd() in Transport Processing Thread.
 */
static int transport_generic_map_buffers_to_tasks(struct se_cmd *cmd)
{
	struct se_task *task = NULL;
	int ret;

	/*
	 * Deal with non [READ,WRITE]_XX CDBs here.
	 */
	if (cmd->se_cmd_flags & SCF_SCSI_NON_DATA_CDB)
		goto non_scsi_data;
	else if (cmd->se_cmd_flags & SCF_SCSI_CONTROL_NONSG_IO_CDB) {
		list_for_each_entry(task, &T_TASK(cmd)->t_task_list, t_list) {
			if (atomic_read(&task->task_sent))
				continue;

			ret = task->transport_map_task(task, task->task_size);
			if (ret < 0)
				return ret;

			DEBUG_CMD_M("Mapping SCF_SCSI_CONTROL_NONSG_IO_CDB"
				" task_size: %u\n", task->task_size);
		}
		return 0;
	}

	/*
	 * Determine the scatterlist offset for each struct se_task,
	 * and segment and set pointers to storage transport buffers
	 * via task->transport_map_task().
	 */
	list_for_each_entry(task, &T_TASK(cmd)->t_task_list, t_list) {
		if (atomic_read(&task->task_sent))
			continue;

		ret = task->transport_map_task(task, task->task_size);
		if (ret < 0)
			return ret;

		DEBUG_CMD_M("Mapping task[%d]_se_obj_ptr[%p] %s_IO task_lba:"
			" %llu task_size: %u task_sg_num: %d\n",
			task->task_no, task->se_obj_ptr,
			(cmd->se_cmd_flags & SCF_SCSI_CONTROL_SG_IO_CDB) ?
			"CONTROL" : "DATA", task->task_lba, task->task_size,
			task->task_sg_num);
	}

	return 0;

non_scsi_data:
	list_for_each_entry(task, &T_TASK(cmd)->t_task_list, t_list) {
		if (atomic_read(&task->task_sent))
			continue;

		ret = task->transport_map_task(task, task->task_size);
		if (ret < 0)
			return ret;

		DEBUG_CMD_M("Mapping SCF_SCSI_NON_DATA_CDB task_size: %u"
			" task->task_sg_num: %d\n", task->task_size,
				task->task_sg_num);
	}

	return 0;
}

/*	transport_generic_do_transform():
 *
 *
 */
int transport_generic_do_transform(struct se_cmd *cmd, struct se_transform_info *ti)
{
	if (cmd->transport_cdb_transform(cmd, ti) < 0)
		return -1;

	return 0;
}

int transport_get_sectors(
	struct se_cmd *cmd,
	void *obj_ptr)
{
	struct se_device *dev = SE_DEV(cmd);

	if (!(cmd->se_cmd_flags & SCF_SCSI_DATA_SG_IO_CDB))
		return 0;

	T_TASK(cmd)->t_task_sectors =
		(cmd->data_length / DEV_ATTRIB(dev)->block_size);
	if (!(T_TASK(cmd)->t_task_sectors))
		T_TASK(cmd)->t_task_sectors = 1;

	if (TRANSPORT(dev)->get_device_type(dev) != TYPE_DISK)
		return 0;

	if ((T_TASK(cmd)->t_task_lba + T_TASK(cmd)->t_task_sectors) >
	     dev_obj_end_lba(obj_ptr)) {
		printk(KERN_ERR "LBA: %llu Sectors: %u exceeds"
			" dev_obj_end_lba(): %llu\n",
			T_TASK(cmd)->t_task_lba, T_TASK(cmd)->t_task_sectors,
			dev_obj_end_lba(obj_ptr));
		cmd->se_cmd_flags |= SCF_SCSI_CDB_EXCEPTION;
		cmd->scsi_sense_reason = SECTOR_COUNT_TOO_MANY;
		return PYX_TRANSPORT_REQ_TOO_MANY_SECTORS;
	}

	return 0;
}

int transport_new_cmd_obj(
	struct se_cmd *cmd,
	struct se_transform_info *ti,
	void *obj_ptr,
	int post_execute)
{
	u32 task_cdbs = 0, task_offset = 0;
	struct se_mem *se_mem_out = NULL;
	struct se_device *dev = SE_DEV(cmd);

	if (!(cmd->se_cmd_flags & SCF_SCSI_DATA_SG_IO_CDB)) {
		task_cdbs++;
		T_TASK(cmd)->t_task_cdbs++;
	} else {
		ti->ti_set_counts = 1;
		ti->ti_dev = dev;

		task_cdbs = transport_generic_get_cdb_count(cmd, ti, obj_ptr,
				T_TASK(cmd)->t_task_lba,
				T_TASK(cmd)->t_task_sectors,
				NULL, &se_mem_out, &task_offset);
		if (!(task_cdbs)) {
			cmd->se_cmd_flags |= SCF_SCSI_CDB_EXCEPTION;
			cmd->scsi_sense_reason =
					LOGICAL_UNIT_COMMUNICATION_FAILURE;
			return PYX_TRANSPORT_LU_COMM_FAILURE;
		}
		T_TASK(cmd)->t_task_cdbs += task_cdbs;

		cmd->transport_cdb_transform =
				&transport_process_data_sg_transform;
#if 0
		printk(KERN_INFO "data_length: %u, LBA: %llu t_task_sectors:"
			" %u, t_task_cdbs: %u\n", obj_ptr, cmd->data_length,
			T_TASK(cmd)->t_task_lba, T_TASK(cmd)->t_task_sectors,
			T_TASK(cmd)->t_task_cdbs);
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

	return 0;
}

unsigned char *transport_get_vaddr(struct se_mem *se_mem)
{
	return page_address(se_mem->se_page) + se_mem->se_off;
}

struct list_head *transport_init_se_mem_list(void)
{
	struct list_head *se_mem_list;

	se_mem_list = kzalloc(sizeof(struct list_head), GFP_KERNEL);
	if (!(se_mem_list)) {
		printk(KERN_ERR "Unable to allocate memory for se_mem_list\n");
		return NULL;
	}
	INIT_LIST_HEAD(se_mem_list);

	return se_mem_list;
}

void transport_free_se_mem_list(struct list_head *se_mem_list)
{
	struct se_mem *se_mem, *se_mem_tmp;

	if (!se_mem_list)
		return;

	list_for_each_entry_safe(se_mem, se_mem_tmp, se_mem_list, se_list) {
		list_del(&se_mem->se_list);
		kmem_cache_free(se_mem_cache, se_mem);
	}
	kfree(se_mem_list);
}

int transport_generic_get_mem(struct se_cmd *cmd, u32 length, u32 dma_size)
{
	unsigned char *buf;
	struct se_mem *se_mem;

	T_TASK(cmd)->t_mem_list = transport_init_se_mem_list();
	if (!(T_TASK(cmd)->t_mem_list))
		return -1;

	while (length) {
		se_mem = kmem_cache_zalloc(se_mem_cache, GFP_KERNEL);
		if (!(se_mem)) {
			printk(KERN_ERR "Unable to allocate struct se_mem\n");
			goto out;
		}
		INIT_LIST_HEAD(&se_mem->se_list);
		se_mem->se_len = (length > dma_size) ? dma_size : length;

/* #warning FIXME Allocate contigous pages for struct se_mem elements */
		se_mem->se_page = (struct page *) alloc_pages(GFP_KERNEL, 0);
		if (!(se_mem->se_page)) {
			printk(KERN_ERR "alloc_pages() failed\n");
			goto out;
		}

		buf = kmap_atomic(se_mem->se_page, KM_IRQ0);
		if (!(buf)) {
			printk(KERN_ERR "kmap_atomic() failed\n");
			goto out;
		}
		memset(buf, 0, se_mem->se_len);
		kunmap_atomic(buf, KM_IRQ0);

		list_add_tail(&se_mem->se_list, T_TASK(cmd)->t_mem_list);
		T_TASK(cmd)->t_task_se_num++;

		DEBUG_MEM("Allocated struct se_mem page(%p) Length(%u)"
			" Offset(%u)\n", se_mem->se_page, se_mem->se_len,
			se_mem->se_off);

		length -= se_mem->se_len;
	}

	DEBUG_MEM("Allocated total struct se_mem elements(%u)\n",
			T_TASK(cmd)->t_task_se_num);

	return 0;
out:
	return -1;
}

extern u32 transport_calc_sg_num(
	struct se_task *task,
	struct se_mem *in_se_mem,
	u32 task_offset)
{
	struct se_mem *se_mem = in_se_mem;
	u32 sg_length, sg_offset, task_size = task->task_size;
	u32 saved_task_offset = 0;

	while (task_size) {
		DEBUG_SC("se_mem->se_page(%p) se_mem->se_len(%u)"
			" se_mem->se_off(%u) task_offset(%u)\n",
			se_mem->se_page, se_mem->se_len,
			se_mem->se_off, task_offset);

		if (task_offset == 0) {
			if (task_size > se_mem->se_len)
				sg_length = se_mem->se_len;
			else
				sg_length = task_size;

			DEBUG_SC("sg_length(%u) task_size(%u)\n",
					sg_length, task_size);

			if (saved_task_offset)
				task_offset = saved_task_offset;
		} else {
			sg_offset = task_offset;

			if ((se_mem->se_len - task_offset) > task_size)
				sg_length = task_size;
			else
				sg_length = (se_mem->se_len - task_offset);

			DEBUG_SC("sg_length(%u) task_size(%u)\n",
					sg_length, task_size);

			saved_task_offset = task_offset;
			task_offset = 0;
		}
		task_size -= sg_length;

		DEBUG_SC("task[%u] - Reducing task_size to(%u)\n",
			task->task_no, task_size);

		task->task_sg_num++;

		list_for_each_entry_continue(se_mem,
				task->task_se_cmd->t_task->t_mem_list, se_list)
			break;

		if (!se_mem)
			break;
	}

	task->task_sg = kzalloc(task->task_sg_num *
			sizeof(struct scatterlist), GFP_KERNEL);
	if (!(task->task_sg)) {
		printk(KERN_ERR "Unable to allocate memory for"
				" task->task_sg\n");
		return 0;
	}

	sg_init_table(&task->task_sg[0], task->task_sg_num);

	DEBUG_SC("Successfully allocated task->task_sg_num(%u)\n",
			task->task_sg_num);

	return task->task_sg_num;
}

static inline int transport_set_task_sectors_disk(
	struct se_task *task,
	void *obj_ptr,
	unsigned long long lba,
	u32 sectors,
	int *max_sectors_set)
{
	if ((lba + sectors) > dev_obj_end_lba(obj_ptr)) {
		task->task_sectors = ((dev_obj_end_lba(obj_ptr) - lba) + 1);

		if (task->task_sectors > dev_obj_max_sectors(obj_ptr)) {
			task->task_sectors = dev_obj_max_sectors(obj_ptr);
			*max_sectors_set = 1;
		}
	} else {
		if (sectors > dev_obj_max_sectors(obj_ptr)) {
			task->task_sectors = dev_obj_max_sectors(obj_ptr);
			*max_sectors_set = 1;
		} else
			task->task_sectors = sectors;
	}

	return 0;
}

static inline int transport_set_task_sectors_non_disk(
	struct se_task *task,
	void *obj_ptr,
	unsigned long long lba,
	u32 sectors,
	int *max_sectors_set)
{
	if (sectors > dev_obj_max_sectors(obj_ptr)) {
		task->task_sectors = dev_obj_max_sectors(obj_ptr);
		*max_sectors_set = 1;
	} else
		task->task_sectors = sectors;

	return 0;
}

static inline int transport_set_task_sectors(
	struct se_task *task,
	void *obj_ptr,
	unsigned long long lba,
	u32 sectors,
	int *max_sectors_set)
{
	struct se_device *dev = obj_ptr;	

	return (TRANSPORT(dev)->get_device_type(dev) == TYPE_DISK) ?
		transport_set_task_sectors_disk(task, obj_ptr, lba, sectors,
				max_sectors_set) :
		transport_set_task_sectors_non_disk(task, obj_ptr, lba, sectors,
				max_sectors_set);
}

int transport_map_sg_to_mem(
	struct se_cmd *cmd,
	struct list_head *se_mem_list,
	void *in_mem,
	u32 *se_mem_cnt,
	u32 *task_offset)
{
	struct se_mem *se_mem;
	struct scatterlist *sg_s;
	u32 j = 0, saved_task_offset = 0, task_size = cmd->data_length;

	if (!in_mem) {
		printk(KERN_ERR "No source scatterlist\n");
		return -1;
	}
	sg_s = (struct scatterlist *)in_mem;

	while (task_size) {
		se_mem = kmem_cache_zalloc(se_mem_cache, GFP_KERNEL);
		if (!(se_mem)) {
			printk(KERN_ERR "Unable to allocate struct se_mem\n");
			return -1;
		}
		INIT_LIST_HEAD(&se_mem->se_list);

		if (*task_offset == 0) {
			se_mem->se_page = sg_page(&sg_s[j]);
			se_mem->se_off = sg_s[j].offset;

			if (task_size >= sg_s[j].length)
				se_mem->se_len =  sg_s[j++].length;
			else {
				se_mem->se_len = task_size;

				task_size -= se_mem->se_len;
				if (!(task_size)) {
					*task_offset = (se_mem->se_len +
							saved_task_offset);
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

				task_size -= se_mem->se_len;
				if (!(task_size)) {
					*task_offset += se_mem->se_len;
					goto next;
				}
			} else
				se_mem->se_len = (sg_s[j++].length -
						*task_offset);

			saved_task_offset = *task_offset;
			*task_offset = 0;
		}
		task_size -= se_mem->se_len;
next:
		list_add_tail(&se_mem->se_list, se_mem_list);
		(*se_mem_cnt)++;
	}

	DEBUG_MEM("task[0] - Mapped(%u) struct scatterlist segments to(%u)"
		" struct se_mem\n", j, *se_mem_cnt);

	return 0;
}

int transport_map_mem_to_mem(
	struct se_task *task,
	struct list_head *se_mem_list,
	void *in_mem,
	struct se_mem *in_se_mem,
	struct se_mem **out_se_mem,
	u32 *se_mem_cnt,
	u32 *task_offset)
{
	struct se_mem *se_mem = in_se_mem, *se_mem_new;
	u32 saved_task_offset = 0, task_size = task->task_size;

	if (!se_mem) {
		printk(KERN_ERR "Invalid struct se_mem pointer\n");
		return -1;
	}

	while (task_size) {
		se_mem_new = kmem_cache_zalloc(se_mem_cache, GFP_KERNEL);
		if (!(se_mem_new)) {
			printk(KERN_ERR "Unable to allocate struct se_mem\n");
			return -1;
		}
		INIT_LIST_HEAD(&se_mem_new->se_list);

		if (*task_offset == 0) {
			se_mem_new->se_page = se_mem->se_page;
			se_mem_new->se_off = se_mem->se_off;

			if (task_size >= se_mem->se_len) {
				se_mem_new->se_len = se_mem->se_len;

				se_mem = list_entry(se_mem->se_list.next,
							struct se_mem, se_list);
				if (!(se_mem)) {
					printk(KERN_ERR "Unable to locate next"
							" struct se_mem\n");
					return -1;
				}
			} else {
				se_mem_new->se_len = task_size;

				task_size -= se_mem_new->se_len;
				if (!(task_size)) {
					*task_offset = (se_mem_new->se_len +
							saved_task_offset);
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

				task_size -= se_mem_new->se_len;
				if (!(task_size)) {
					*task_offset += se_mem_new->se_len;
					goto next;
				}
			} else {
				se_mem_new->se_len = (se_mem->se_len -
							*task_offset);

				se_mem = list_entry(se_mem->se_list.next,
							struct se_mem, se_list);
				if (!(se_mem)) {
					printk(KERN_ERR "Unable to locate next"
							" struct se_mem\n");
					return -1;
				}
			}

			saved_task_offset = *task_offset;
			*task_offset = 0;
		}
		task_size -= se_mem_new->se_len;
next:
		list_add_tail(&se_mem_new->se_list, se_mem_list);
		(*se_mem_cnt)++;

		DEBUG_MEM2("task[%u] - se_mem_cnt(%u) se_page(%p) se_off(%u)"
			" se_len(%u)\n", task->task_no, *se_mem_cnt,
			se_mem_new->se_page, se_mem_new->se_off,
			se_mem->se_len);
		DEBUG_MEM2("task[%u] - Reducing task_size to(%u)\n",
			task->task_no, task_size);
	}
	*out_se_mem = se_mem;

	return 0;
}

/*	transport_map_mem_to_sg():
 *
 *
 */
int transport_map_mem_to_sg(
	struct se_task *task,
	struct list_head *se_mem_list,
	void *in_mem,
	struct se_mem *in_se_mem,
	struct se_mem **out_se_mem,
	u32 *se_mem_cnt,
	u32 *task_offset)
{
	struct se_mem *se_mem = in_se_mem;
	struct scatterlist *sg = (struct scatterlist *)in_mem;
	u32 saved_task_offset = 0, sg_no = 0;
	u32 task_size = task->task_size;

	if (!sg) {
		printk(KERN_ERR "Unable to locate valid struct"
				" scatterlist pointer\n");
		return -1;
	}

	while (task_size) {
		if (*task_offset == 0) {
			sg_assign_page(&sg[sg_no], se_mem->se_page);
			sg[sg_no].offset = se_mem->se_off;

			if (task_size >= se_mem->se_len) {
				sg[sg_no].length = se_mem->se_len;

				se_mem = list_entry(se_mem->se_list.next,
							struct se_mem, se_list);
				if (!(se_mem)) {
					printk(KERN_ERR "Unable to locate"
						" next struct se_mem\n");
					return -1;
				}
				(*se_mem_cnt)++;
			} else {
				sg[sg_no].length = task_size;
				/*
				 * Determine if we need to calculate an offset
				 * into the struct se_mem on the next go around..
				 */
				task_size -= sg[sg_no].length;
				if (!(task_size)) {
					*task_offset = (sg[sg_no].length +
							saved_task_offset);
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
				 * Determine if we need to calculate an offset
				 * into the struct se_mem on the next go around..
				 */
				task_size -= sg[sg_no].length;
				if (!(task_size)) {
					*task_offset += sg[sg_no].length;
					goto next;
				}
			} else {
				sg[sg_no].length = (se_mem->se_len -
						*task_offset);

				se_mem = list_entry(se_mem->se_list.next,
						struct se_mem, se_list);
				if (!(se_mem)) {
					printk(KERN_ERR "Unable to locate"
						" next struct se_mem\n");
					return -1;
				}
				(*se_mem_cnt)++;
			}

			saved_task_offset = *task_offset;
			*task_offset = 0;
		}
		task_size -= sg[sg_no].length;
next:
		DEBUG_MEM("task[%u] - sg[%u](%p)(%u)(%u) - Reducing task_size"
			" to(%u)\n", task->task_no, sg_no,
			sg_page(&sg[sg_no]), sg[sg_no].length,
			sg[sg_no].offset, task_size);

		sg_no++;
	}
	*out_se_mem = se_mem;
	task->task_sg_num = sg_no;

	DEBUG_MEM("task[%u] - Mapped(%u) struct se_mem segments to total(%u) SGs"
		" saved task_offset(%u)\n", task->task_no, *se_mem_cnt,
			sg_no, *task_offset);

	return 0;
}

u32 transport_generic_get_cdb_count(
	struct se_cmd *cmd,
	struct se_transform_info *ti,
	void *head_obj_ptr,
	unsigned long long starting_lba,
	u32 sectors,
	struct se_mem *se_mem_in,
	struct se_mem **se_mem_out,
	u32 *task_offset_in)
{
	unsigned char *cdb = NULL;
	void *obj_ptr;
	struct se_task *task;
	struct se_mem *se_mem, *se_mem_lout = NULL;
	struct se_device *dev = SE_DEV(cmd);
	int max_sectors_set = 0, ret;
	u32 se_mem_cnt = 0, task_cdbs = 0;
	unsigned long long lba;

	if (!se_mem_in) {
		list_for_each_entry(se_mem_in, T_TASK(cmd)->t_mem_list, se_list)
			break;

		if (!se_mem_in) {
			printk(KERN_ERR "se_mem_in is NULL\n");
			return 0;
		}
	}
	se_mem = se_mem_in;

	/*
	 * Locate the start volume segment in which the received LBA will be
	 * executed upon.
	 */
	ret = transport_generic_obj_start(ti, head_obj_ptr, starting_lba);
	if (ret < 0)
		return 0;
	/*
	 * Locate starting object from original starting_lba.
	 */
	lba = ti->ti_lba;
	obj_ptr = ti->ti_obj_ptr;
	DEBUG_VOL("Starting Physical LBA(%llu)\n", lba);

	while (sectors) {

		DEBUG_VOL("ITT[0x%08x] LBA(%llu) SectorsLeft(%u) EOBJ(%llu)\n",
			CMD_TFO(cmd)->get_task_tag(cmd), lba, sectors,
			dev_obj_end_lba(obj_ptr));

		task = cmd->transport_get_task(ti, cmd, obj_ptr);
		if (!(task))
			goto out;

		transport_set_task_sectors(task, obj_ptr, lba, sectors,
				&max_sectors_set);

		task->task_lba = lba;
		lba += task->task_sectors;
		sectors -= task->task_sectors;
		task->task_size = (task->task_sectors *
				   DEV_ATTRIB(dev)->block_size);
		task->transport_map_task = dev_obj_get_map_SG(
				obj_ptr, cmd->data_direction);

		cdb = TRANSPORT(dev)->get_cdb(task);
		if ((cdb)) {
			memcpy(cdb, T_TASK(cmd)->t_task_cdb, SCSI_CDB_SIZE);
			cmd->transport_split_cdb(task->task_lba,
					&task->task_sectors, cdb);
		}

		/*
		 * Perform the SE OBJ plugin and/or Transport plugin specific
		 * mapping for T_TASK(cmd)->t_mem_list.
		 */
		ret = dev_obj_do_se_mem_map(obj_ptr, task,
				T_TASK(cmd)->t_mem_list, NULL, se_mem,
				&se_mem_lout, &se_mem_cnt, task_offset_in);
		if (ret < 0)
			goto out;

		se_mem = se_mem_lout;
		*se_mem_out = se_mem_lout;
		task_cdbs++;

		DEBUG_VOL("Incremented task_cdbs(%u) task->task_sg_num(%u)\n",
				task_cdbs, task->task_sg_num);

		if (max_sectors_set) {
			max_sectors_set = 0;
			continue;
		}

		if (!sectors)
			break;
	}

	if (ti->ti_set_counts) {
		atomic_inc(&T_TASK(cmd)->t_fe_count);
		atomic_inc(&T_TASK(cmd)->t_se_count);
	}

	DEBUG_VOL("ITT[0x%08x] total cdbs(%u)\n",
		CMD_TFO(cmd)->get_task_tag(cmd), task_cdbs);

	return task_cdbs;
out:
	return 0;
}

/*	 transport_generic_new_cmd(): Called from transport_processing_thread()
 *
 *	 Allocate storage transport resources from a set of values predefined
 *	 by transport_generic_cmd_sequencer() from the iSCSI Target RX process.
 *	 Any non zero return here is treated as an "out of resource' op here.
 */
int transport_generic_new_cmd(struct se_cmd *cmd)
{
	struct se_portal_group *se_tpg;
	struct se_transform_info ti;
	int ret = 0;
	/*
	 * Generate struct se_task(s) and/or their payloads for this CDB.
	 */
	memset((void *)&ti, 0, sizeof(struct se_transform_info));
	ti.ti_se_cmd = cmd;
	ti.se_obj_ptr = SE_LUN(cmd)->lun_type_ptr;

	if (!(cmd->se_cmd_flags & SCF_CMD_PASSTHROUGH)) {
		/*
		 * Determine is the TCM fabric module has already allocated
		 * physical memory, and is directly calling
		 * transport_generic_map_mem_to_cmd() to setup beforehand
		 * the linked list of physical memory at
		 * T_TASK(cmd)->t_mem_list of struct se_mem->se_page
		 */
		if (!(cmd->se_cmd_flags & SCF_PASSTHROUGH_SG_TO_MEM_NOALLOC)) {
			/* #warning FIXME v3.2: Enable > PAGE_SIZE usage */
			ret = cmd->transport_allocate_resources(cmd,
					cmd->data_length, PAGE_SIZE);
			if (ret < 0)
				goto failure;
		}

		ret = transport_get_sectors(cmd, SE_LUN(cmd)->lun_type_ptr);
		if (ret < 0)
			goto failure;

		ret = transport_new_cmd_obj(cmd, &ti,
					SE_LUN(cmd)->lun_type_ptr, 0);
		if (ret < 0)
			goto failure;
		/*
		 * Determine if the calling TCM fabric module is talking to
		 * Linux/NET via kernel sockets and needs to allocate a
		 * struct iovec array to complete the struct se_cmd
		 */
		se_tpg = SE_LUN(cmd)->lun_sep->sep_tpg;
		if (TPG_TFO(se_tpg)->alloc_cmd_iovecs != NULL) {
			ret = TPG_TFO(se_tpg)->alloc_cmd_iovecs(cmd);
			if (ret < 0) {
				ret = PYX_TRANSPORT_OUT_OF_MEMORY_RESOURCES;
				goto failure;
			}
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
	 * buffer list in struct se_cmd to the transport task's native
	 * buffers format.
	 */
	ret = cmd->transport_map_buffers_to_tasks(cmd);
	if (ret < 0)
		goto failure;
	/*
	 * For WRITEs, let the iSCSI Target RX Thread know its buffer is ready..
	 * This WRITE struct se_cmd (and all of its associated struct se_task's)
	 * will be added to the struct se_device execution queue after its WRITE
	 * data has arrived. (ie: It gets handled by the transport processing
	 * thread a second time)
	 */
	if (cmd->data_direction == SE_DIRECTION_WRITE) {
		transport_add_tasks_to_state_queue(cmd);
		return transport_generic_write_pending(cmd);
	}
	/*
	 * Everything else but a WRITE, add the struct se_cmd's struct se_task's
	 * to the execution queue.
	 */
	transport_execute_tasks(cmd);
	return 0;

failure:
	return ret;
}

/*	transport_generic_process_write():
 *
 *
 */
void transport_generic_process_write(struct se_cmd *cmd)
{
#if 0
	/*
	 * Copy SCSI Presented DTL sector(s) from received buffers allocated to
	 * original EDTL
	 */
	if (cmd->se_cmd_flags & SCF_UNDERFLOW_BIT) {
		if (!T_TASK(cmd)->t_task_se_num) {
			unsigned char *dst, *buf =
				(unsigned char *)T_TASK(cmd)->t_task_buf;

			dst = kzalloc(cmd->cmd_spdtl), GFP_KERNEL);
			if (!(dst)) {
				printk(KERN_ERR "Unable to allocate memory for"
						" WRITE underflow\n");
				transport_generic_request_failure(cmd, NULL,
					PYX_TRANSPORT_REQ_TOO_MANY_SECTORS, 1);
				return;
			}
			memcpy(dst, buf, cmd->cmd_spdtl);

			kfree(T_TASK(cmd)->t_task_buf);
			T_TASK(cmd)->t_task_buf = dst;
		} else {
			struct scatterlist *sg =
				(struct scatterlist *sg)T_TASK(cmd)->t_task_buf;
			struct scatterlist *orig_sg;

			orig_sg = kzalloc(sizeof(struct scatterlist) *
					T_TASK(cmd)->t_task_se_num,
					GFP_KERNEL))) {
			if (!(orig_sg)) {
				printk(KERN_ERR "Unable to allocate memory"
						" for WRITE underflow\n");
				transport_generic_request_failure(cmd, NULL,
					PYX_TRANSPORT_REQ_TOO_MANY_SECTORS, 1);
				return;
			}

			memcpy(orig_sg, T_TASK(cmd)->t_task_buf,
					sizeof(struct scatterlist) *
					T_TASK(cmd)->t_task_se_num);

			cmd->data_length = cmd->cmd_spdtl;
			/*
			 * FIXME, clear out original struct se_task and state
			 * information.
			 */
			if (transport_generic_new_cmd(cmd) < 0) {
				transport_generic_request_failure(cmd, NULL,
					PYX_TRANSPORT_REQ_TOO_MANY_SECTORS, 1);
				kfree(orig_sg);
				return;
			}

			transport_memcpy_write_sg(cmd, orig_sg);
		}
	}
#endif
	transport_execute_tasks(cmd);
}
EXPORT_SYMBOL(transport_generic_process_write);

/*	transport_generic_write_pending():
 *
 *
 */
static int transport_generic_write_pending(struct se_cmd *cmd)
{
	unsigned long flags;
	int ret;

	if (cmd->se_cmd_flags & SCF_CMD_PASSTHROUGH) {
		if (!(cmd->se_cmd_flags & SCF_CMD_PASSTHROUGH_NOALLOC)) {
			complete(&T_TASK(cmd)->t_transport_passthrough_wcomp);
			transport_cmd_check_stop(cmd, 1, 0);
			return PYX_TRANSPORT_WRITE_PENDING;
		}

		transport_generic_process_write(cmd);
		transport_cmd_check_stop(cmd, 1, 0);
		return PYX_TRANSPORT_WRITE_PENDING;
	}

	spin_lock_irqsave(&T_TASK(cmd)->t_state_lock, flags);
	cmd->t_state = TRANSPORT_WRITE_PENDING;
	spin_unlock_irqrestore(&T_TASK(cmd)->t_state_lock, flags);
	/*
	 * Call the fabric write_pending function here to let the
	 * frontend know that WRITE buffers are ready.
	 */
	ret = CMD_TFO(cmd)->write_pending(cmd);
	if (ret < 0) {
		transport_cmd_check_stop(cmd, 1, 0);
		return ret;
	}

	transport_cmd_check_stop(cmd, 1, 0);
	return PYX_TRANSPORT_WRITE_PENDING;
}

/*	transport_release_cmd_to_pool():
 *
 *
 */
void transport_release_cmd_to_pool(struct se_cmd *cmd)
{
	if (cmd->se_cmd_flags & SCF_CMD_PASSTHROUGH)
		kfree(cmd->se_lun);
	/*
	 * Release struct se_cmd->se_fabric_cmd_ptr in fabric
	 */
	CMD_TFO(cmd)->release_cmd_to_pool(cmd);

	transport_free_se_cmd(cmd);
}
EXPORT_SYMBOL(transport_release_cmd_to_pool);

/*	transport_generic_free_cmd():
 *
 *	Called from processing frontend to release storage engine resources
 */
void transport_generic_free_cmd(
	struct se_cmd *cmd,
	int wait_for_tasks,
	int release_to_pool,
	int session_reinstatement)
{
	if (!(cmd->se_cmd_flags & SCF_SE_LUN_CMD) || !T_TASK(cmd))
		transport_release_cmd_to_pool(cmd);
	else {
		core_dec_lacl_count(cmd->se_sess->se_node_acl, cmd);

		if (SE_LUN(cmd)) {
#if 0
			printk(KERN_INFO "cmd: %p ITT: 0x%08x contains"
				" SE_LUN(cmd)\n", cmd,
				CMD_TFO(cmd)->get_task_tag(cmd));
#endif
			transport_lun_remove_cmd(cmd);
		}

		if (wait_for_tasks && cmd->transport_wait_for_tasks)
			cmd->transport_wait_for_tasks(cmd, 0, 0);

		transport_generic_remove(cmd, release_to_pool,
				session_reinstatement);
	}
}
EXPORT_SYMBOL(transport_generic_free_cmd);

static void transport_nop_wait_for_tasks(
	struct se_cmd *cmd,
	int remove_cmd,
	int session_reinstatement)
{
	return;
}

/*	transport_lun_wait_for_tasks():
 *
 *	Called from ConfigFS context to stop the passed struct se_cmd to allow
 *	an struct se_lun to be successfully shutdown.
 */
int transport_lun_wait_for_tasks(struct se_cmd *cmd, struct se_lun *lun)
{
	unsigned long flags;
	int ret;
	/*
	 * If the frontend has already requested this struct se_cmd to
	 * be stopped, we can safely ignore this struct se_cmd.
	 */
	spin_lock_irqsave(&T_TASK(cmd)->t_state_lock, flags);
	if (atomic_read(&T_TASK(cmd)->t_transport_stop)) {
		atomic_set(&T_TASK(cmd)->transport_lun_stop, 0);
		DEBUG_TRANSPORT_S("ConfigFS ITT[0x%08x] - t_transport_stop =="
			" TRUE, skipping\n", CMD_TFO(cmd)->get_task_tag(cmd));
		spin_unlock_irqrestore(&T_TASK(cmd)->t_state_lock, flags);
		transport_cmd_check_stop(cmd, 1, 0);
		return -1;
	}
	atomic_set(&T_TASK(cmd)->transport_lun_fe_stop, 1);
	spin_unlock_irqrestore(&T_TASK(cmd)->t_state_lock, flags);

	wake_up_interruptible(&SE_DEV(cmd)->dev_queue_obj->thread_wq);

	ret = transport_stop_tasks_for_cmd(cmd);

	DEBUG_TRANSPORT_S("ConfigFS: cmd: %p t_task_cdbs: %d stop tasks ret:"
			" %d\n", cmd, T_TASK(cmd)->t_task_cdbs, ret);
	if (!ret) {
		DEBUG_TRANSPORT_S("ConfigFS: ITT[0x%08x] - stopping cmd....\n",
				CMD_TFO(cmd)->get_task_tag(cmd));
		wait_for_completion(&T_TASK(cmd)->transport_lun_stop_comp);
		DEBUG_TRANSPORT_S("ConfigFS: ITT[0x%08x] - stopped cmd....\n",
				CMD_TFO(cmd)->get_task_tag(cmd));
	}
	transport_remove_cmd_from_queue(cmd, SE_DEV(cmd)->dev_queue_obj);

	return 0;
}
EXPORT_SYMBOL(transport_lun_wait_for_tasks);

/* #define DEBUG_CLEAR_LUN */
#ifdef DEBUG_CLEAR_LUN
#define DEBUG_CLEAR_L(x...) printk(KERN_INFO x)
#else
#define DEBUG_CLEAR_L(x...)
#endif

static void __transport_clear_lun_from_sessions(struct se_lun *lun)
{
	struct se_cmd *cmd = NULL;
	unsigned long lun_flags, cmd_flags;
	/*
	 * Do exception processing and return CHECK_CONDITION status to the
	 * Initiator Port.
	 */
	spin_lock_irqsave(&lun->lun_cmd_lock, lun_flags);
	while (!list_empty_careful(&lun->lun_cmd_list)) {
		cmd = list_entry(lun->lun_cmd_list.next,
			struct se_cmd, se_lun_list);
		list_del(&cmd->se_lun_list);

		if (!(T_TASK(cmd))) {
			printk(KERN_ERR "ITT: 0x%08x, T_TASK(cmd) = NULL"
				"[i,t]_state: %u/%u\n",
				CMD_TFO(cmd)->get_task_tag(cmd),
				CMD_TFO(cmd)->get_cmd_state(cmd), cmd->t_state);
			BUG();
		}
		atomic_set(&T_TASK(cmd)->transport_lun_active, 0);
		/*
		 * This will notify iscsi_target_transport.c:
		 * transport_cmd_check_stop() that a LUN shutdown is in
		 * progress for the iscsi_cmd_t.
		 */
		spin_lock(&T_TASK(cmd)->t_state_lock);
		DEBUG_CLEAR_L("SE_LUN[%d] - Setting T_TASK(cmd)->transport"
			"_lun_stop for  ITT: 0x%08x\n",
			SE_LUN(cmd)->unpacked_lun,
			CMD_TFO(cmd)->get_task_tag(cmd));
		atomic_set(&T_TASK(cmd)->transport_lun_stop, 1);
		spin_unlock(&T_TASK(cmd)->t_state_lock);

		spin_unlock_irqrestore(&lun->lun_cmd_lock, lun_flags);

		if (!(SE_LUN(cmd))) {
			printk(KERN_ERR "ITT: 0x%08x, [i,t]_state: %u/%u\n",
				CMD_TFO(cmd)->get_task_tag(cmd),
				CMD_TFO(cmd)->get_cmd_state(cmd), cmd->t_state);
			BUG();
		}
		/*
		 * If the Storage engine still owns the iscsi_cmd_t, determine
		 * and/or stop its context.
		 */
		DEBUG_CLEAR_L("SE_LUN[%d] - ITT: 0x%08x before transport"
			"_lun_wait_for_tasks()\n", SE_LUN(cmd)->unpacked_lun,
			CMD_TFO(cmd)->get_task_tag(cmd));

		if (transport_lun_wait_for_tasks(cmd, SE_LUN(cmd)) < 0) {
			spin_lock_irqsave(&lun->lun_cmd_lock, lun_flags);
			continue;
		}

		DEBUG_CLEAR_L("SE_LUN[%d] - ITT: 0x%08x after transport_lun"
			"_wait_for_tasks(): SUCCESS\n",
			SE_LUN(cmd)->unpacked_lun,
			CMD_TFO(cmd)->get_task_tag(cmd));

		spin_lock_irqsave(&T_TASK(cmd)->t_state_lock, cmd_flags);
		if (!(atomic_read(&T_TASK(cmd)->transport_dev_active))) {
			spin_unlock_irqrestore(&T_TASK(cmd)->t_state_lock, cmd_flags);
			goto check_cond;
		}
		atomic_set(&T_TASK(cmd)->transport_dev_active, 0);
		transport_all_task_dev_remove_state(cmd);
		spin_unlock_irqrestore(&T_TASK(cmd)->t_state_lock, cmd_flags);

		transport_free_dev_tasks(cmd);
		/*
		 * The Storage engine stopped this struct se_cmd before it was
		 * send to the fabric frontend for delivery back to the
		 * Initiator Node.  Return this SCSI CDB back with an
		 * CHECK_CONDITION status.
		 */
check_cond:
		transport_send_check_condition_and_sense(cmd,
				NON_EXISTENT_LUN, 0);
		/*
		 *  If the fabric frontend is waiting for this iscsi_cmd_t to
		 * be released, notify the waiting thread now that LU has
		 * finished accessing it.
		 */
		spin_lock_irqsave(&T_TASK(cmd)->t_state_lock, cmd_flags);
		if (atomic_read(&T_TASK(cmd)->transport_lun_fe_stop)) {
			DEBUG_CLEAR_L("SE_LUN[%d] - Detected FE stop for"
				" struct se_cmd: %p ITT: 0x%08x\n",
				lun->unpacked_lun,
				cmd, CMD_TFO(cmd)->get_task_tag(cmd));

			spin_unlock_irqrestore(&T_TASK(cmd)->t_state_lock,
					cmd_flags);
			transport_cmd_check_stop(cmd, 1, 0);
			complete(&T_TASK(cmd)->transport_lun_fe_stop_comp);
			spin_lock_irqsave(&lun->lun_cmd_lock, lun_flags);
			continue;
		}
		DEBUG_CLEAR_L("SE_LUN[%d] - ITT: 0x%08x finished processing\n",
			lun->unpacked_lun, CMD_TFO(cmd)->get_task_tag(cmd));

		spin_unlock_irqrestore(&T_TASK(cmd)->t_state_lock, cmd_flags);
		spin_lock_irqsave(&lun->lun_cmd_lock, lun_flags);
	}
	spin_unlock_irqrestore(&lun->lun_cmd_lock, lun_flags);
}
EXPORT_SYMBOL(__transport_clear_lun_from_sessions);

static int transport_clear_lun_thread(void *p)
{
	struct se_lun *lun = (struct se_lun *)p;

	__transport_clear_lun_from_sessions(lun);
	complete(&lun->lun_shutdown_comp);	

	return 0;
}

int transport_clear_lun_from_sessions(struct se_lun *lun)
{
	struct task_struct *kt;
	
	kt = kthread_run(transport_clear_lun_thread, (void *)lun,
			"tcm_cl_%u", lun->unpacked_lun);
	if (IS_ERR(kt)) {
		printk(KERN_ERR "Unable to start clear_lun thread\n");
		return -1;
	}
	wait_for_completion(&lun->lun_shutdown_comp);

	return 0;
}
EXPORT_SYMBOL(transport_clear_lun_from_sessions);

/*	transport_generic_wait_for_tasks():
 *
 *	Called from frontend or passthrough context to wait for storage engine
 *	to pause and/or release frontend generated struct se_cmd.
 */
static void transport_generic_wait_for_tasks(
	struct se_cmd *cmd,
	int remove_cmd,
	int session_reinstatement)
{
	unsigned long flags;

	if (!(cmd->se_cmd_flags & SCF_SE_LUN_CMD) && !(cmd->se_tmr_req))
		return;

	spin_lock_irqsave(&T_TASK(cmd)->t_state_lock, flags);
	/*
	 * If we are already stopped due to an external event (ie: LUN shutdown)
	 * sleep until the connection can have the passed struct se_cmd back.
	 * The T_TASK(cmd)->transport_lun_stopped_sem will be upped by
	 * transport_clear_lun_from_sessions() once the ConfigFS context caller
	 * has completed its operation on the struct se_cmd.
	 */
	if (atomic_read(&T_TASK(cmd)->transport_lun_stop)) {

		DEBUG_TRANSPORT_S("wait_for_tasks: Stopping"
			" wait_for_completion(&T_TASK(cmd)transport_lun_fe"
			"_stop_comp); for ITT: 0x%08x\n",
			CMD_TFO(cmd)->get_task_tag(cmd));
		/*
		 * There is a special case for WRITES where a FE exception +
		 * LUN shutdown means ConfigFS context is still sleeping on
		 * transport_lun_stop_comp in transport_lun_wait_for_tasks().
		 * We go ahead and up transport_lun_stop_comp just to be sure
		 * here.
		 */
		spin_unlock_irqrestore(&T_TASK(cmd)->t_state_lock, flags);
		complete(&T_TASK(cmd)->transport_lun_stop_comp);
		wait_for_completion(&T_TASK(cmd)->transport_lun_fe_stop_comp);
		spin_lock_irqsave(&T_TASK(cmd)->t_state_lock, flags);

		transport_all_task_dev_remove_state(cmd);
		/*
		 * At this point, the frontend who was the originator of this
		 * struct se_cmd, now owns the structure and can be released through
		 * normal means below.
		 */
		DEBUG_TRANSPORT_S("wait_for_tasks: Stopped"
			" wait_for_completion(&T_TASK(cmd)transport_lun_fe_"
			"stop_comp); for ITT: 0x%08x\n",
			CMD_TFO(cmd)->get_task_tag(cmd));

		atomic_set(&T_TASK(cmd)->transport_lun_stop, 0);
	}
	if (!atomic_read(&T_TASK(cmd)->t_transport_active))
		goto remove;

	atomic_set(&T_TASK(cmd)->t_transport_stop, 1);

	DEBUG_TRANSPORT_S("wait_for_tasks: Stopping %p ITT: 0x%08x"
		" i_state: %d, t_state/def_t_state: %d/%d, t_transport_stop"
		" = TRUE\n", cmd, CMD_TFO(cmd)->get_task_tag(cmd),
		CMD_TFO(cmd)->get_cmd_state(cmd), cmd->t_state,
		cmd->deferred_t_state);

	spin_unlock_irqrestore(&T_TASK(cmd)->t_state_lock, flags);

	wake_up_interruptible(&SE_DEV(cmd)->dev_queue_obj->thread_wq);

	wait_for_completion(&T_TASK(cmd)->t_transport_stop_comp);

	spin_lock_irqsave(&T_TASK(cmd)->t_state_lock, flags);
	atomic_set(&T_TASK(cmd)->t_transport_active, 0);
	atomic_set(&T_TASK(cmd)->t_transport_stop, 0);

	DEBUG_TRANSPORT_S("wait_for_tasks: Stopped wait_for_compltion("
		"&T_TASK(cmd)->t_transport_stop_comp) for ITT: 0x%08x\n",
		CMD_TFO(cmd)->get_task_tag(cmd));
remove:
	spin_unlock_irqrestore(&T_TASK(cmd)->t_state_lock, flags);
	if (!remove_cmd)
		return;

	transport_generic_free_cmd(cmd, 0, 0, session_reinstatement);
}

int transport_get_sense_codes(
	struct se_cmd *cmd,
	u8 *asc,
	u8 *ascq)
{
	*asc = cmd->scsi_asc;
	*ascq = cmd->scsi_ascq;

	return 0;
}

int transport_set_sense_codes(
	struct se_cmd *cmd,
	u8 asc,
	u8 ascq)
{
	cmd->scsi_asc = asc;
	cmd->scsi_ascq = ascq;

	return 0;
}

int transport_send_check_condition_and_sense(
	struct se_cmd *cmd,
	u8 reason,
	int from_transport)
{
	unsigned char *buffer = cmd->sense_buffer;
	unsigned long flags;
	int offset;
	u8 asc = 0, ascq = 0;

	spin_lock_irqsave(&T_TASK(cmd)->t_state_lock, flags);
	if (cmd->se_cmd_flags & SCF_SENT_CHECK_CONDITION) {
		spin_unlock_irqrestore(&T_TASK(cmd)->t_state_lock, flags);
		return 0;
	}
	cmd->se_cmd_flags |= SCF_SENT_CHECK_CONDITION;
	spin_unlock_irqrestore(&T_TASK(cmd)->t_state_lock, flags);

	if (!reason && from_transport)
		goto after_reason;

	if (!from_transport)
		cmd->se_cmd_flags |= SCF_EMULATED_TASK_SENSE;
	/*
	 * Data Segment and SenseLength of the fabric response PDU.
	 *
	 * TRANSPORT_SENSE_BUFFER is now set to SCSI_SENSE_BUFFERSIZE
	 * from include/scsi/scsi_cmnd.h
	 */
	offset = CMD_TFO(cmd)->set_fabric_sense_len(cmd,
				TRANSPORT_SENSE_BUFFER);
	/*
	 * Actual SENSE DATA, see SPC-3 7.23.2  SPC_SENSE_KEY_OFFSET uses
	 * SENSE KEY values from include/scsi/scsi.h
	 */
	switch (reason) {
	case NON_EXISTENT_LUN:
	case UNSUPPORTED_SCSI_OPCODE:
	case SECTOR_COUNT_TOO_MANY:
		/* CURRENT ERROR */
		buffer[offset] = 0x70;
		/* ILLEGAL REQUEST */
		buffer[offset+SPC_SENSE_KEY_OFFSET] = ILLEGAL_REQUEST;
		/* INVALID COMMAND OPERATION CODE */
		buffer[offset+SPC_ASC_KEY_OFFSET] = 0x20;
		break;
	case UNKNOWN_MODE_PAGE:
		/* CURRENT ERROR */
		buffer[offset] = 0x70;
		/* ILLEGAL REQUEST */
		buffer[offset+SPC_SENSE_KEY_OFFSET] = ILLEGAL_REQUEST;
		/* INVALID FIELD IN CDB */
		buffer[offset+SPC_ASC_KEY_OFFSET] = 0x24;
		break;
	case CHECK_CONDITION_ABORT_CMD:
		/* CURRENT ERROR */
		buffer[offset] = 0x70;
		/* ABORTED COMMAND */
		buffer[offset+SPC_SENSE_KEY_OFFSET] = ABORTED_COMMAND;
		/* BUS DEVICE RESET FUNCTION OCCURRED */
		buffer[offset+SPC_ASC_KEY_OFFSET] = 0x29;
		buffer[offset+SPC_ASCQ_KEY_OFFSET] = 0x03;
		break;
	case INCORRECT_AMOUNT_OF_DATA:
		/* CURRENT ERROR */
		buffer[offset] = 0x70;
		/* ABORTED COMMAND */
		buffer[offset+SPC_SENSE_KEY_OFFSET] = ABORTED_COMMAND;
		/* WRITE ERROR */
		buffer[offset+SPC_ASC_KEY_OFFSET] = 0x0c;
		/* NOT ENOUGH UNSOLICITED DATA */
		buffer[offset+SPC_ASCQ_KEY_OFFSET] = 0x0d;
		break;
	case INVALID_CDB_FIELD:
		/* CURRENT ERROR */
		buffer[offset] = 0x70;
		/* ABORTED COMMAND */
		buffer[offset+SPC_SENSE_KEY_OFFSET] = ABORTED_COMMAND;
		/* INVALID FIELD IN CDB */
		buffer[offset+SPC_ASC_KEY_OFFSET] = 0x24;
		break;
	case INVALID_PARAMETER_LIST:
		/* CURRENT ERROR */
		buffer[offset] = 0x70;
		/* ABORTED COMMAND */
		buffer[offset+SPC_SENSE_KEY_OFFSET] = ABORTED_COMMAND;
		/* INVALID FIELD IN PARAMETER LIST */
		buffer[offset+SPC_ASC_KEY_OFFSET] = 0x26;
		break;
	case UNEXPECTED_UNSOLICITED_DATA:
		/* CURRENT ERROR */
		buffer[offset] = 0x70;
		/* ABORTED COMMAND */
		buffer[offset+SPC_SENSE_KEY_OFFSET] = ABORTED_COMMAND;
		/* WRITE ERROR */
		buffer[offset+SPC_ASC_KEY_OFFSET] = 0x0c;
		/* UNEXPECTED_UNSOLICITED_DATA */
		buffer[offset+SPC_ASCQ_KEY_OFFSET] = 0x0c;
		break;
	case SERVICE_CRC_ERROR:
		/* CURRENT ERROR */
		buffer[offset] = 0x70;
		/* ABORTED COMMAND */
		buffer[offset+SPC_SENSE_KEY_OFFSET] = ABORTED_COMMAND;
		/* PROTOCOL SERVICE CRC ERROR */
		buffer[offset+SPC_ASC_KEY_OFFSET] = 0x47;
		/* N/A */
		buffer[offset+SPC_ASCQ_KEY_OFFSET] = 0x05;
		break;
	case SNACK_REJECTED:
		/* CURRENT ERROR */
		buffer[offset] = 0x70;
		/* ABORTED COMMAND */
		buffer[offset+SPC_SENSE_KEY_OFFSET] = ABORTED_COMMAND;
		/* READ ERROR */
		buffer[offset+SPC_ASC_KEY_OFFSET] = 0x11;
		/* FAILED RETRANSMISSION REQUEST */
		buffer[offset+SPC_ASCQ_KEY_OFFSET] = 0x13;
		break;
	case WRITE_PROTECTED:
		/* CURRENT ERROR */
		buffer[offset] = 0x70;
		/* DATA PROTECT */
		buffer[offset+SPC_SENSE_KEY_OFFSET] = DATA_PROTECT;
		/* WRITE PROTECTED */
		buffer[offset+SPC_ASC_KEY_OFFSET] = 0x27;
		break;
	case CHECK_CONDITION_UNIT_ATTENTION:
		/* CURRENT ERROR */
		buffer[offset] = 0x70;
		/* UNIT ATTENTION */
		buffer[offset+SPC_SENSE_KEY_OFFSET] = UNIT_ATTENTION;
		core_scsi3_ua_for_check_condition(cmd, &asc, &ascq);
		buffer[offset+SPC_ASC_KEY_OFFSET] = asc;
		buffer[offset+SPC_ASCQ_KEY_OFFSET] = ascq;
		break;
	case CHECK_CONDITION_NOT_READY:
		/* CURRENT ERROR */
		buffer[offset] = 0x70;
		/* Not Ready */
		buffer[offset+SPC_SENSE_KEY_OFFSET] = NOT_READY;
		transport_get_sense_codes(cmd, &asc, &ascq);
		buffer[offset+SPC_ASC_KEY_OFFSET] = asc;
		buffer[offset+SPC_ASCQ_KEY_OFFSET] = ascq;
		break;
	case LOGICAL_UNIT_COMMUNICATION_FAILURE:
	default:
		/* CURRENT ERROR */
		buffer[offset] = 0x70;
		/* ILLEGAL REQUEST */
		buffer[offset+SPC_SENSE_KEY_OFFSET] = ILLEGAL_REQUEST;
		/* LOGICAL UNIT COMMUNICATION FAILURE */
		buffer[offset+SPC_ASC_KEY_OFFSET] = 0x80;
		break;
	}
	/*
	 * This code uses linux/include/scsi/scsi.h SAM status codes!
	 */
	cmd->scsi_status = SAM_STAT_CHECK_CONDITION;
	/*
	 * Automatically padded, this value is encoded in the fabric's
	 * data_length response PDU containing the SCSI defined sense data.
	 */
	cmd->scsi_sense_length  = TRANSPORT_SENSE_BUFFER + offset;

after_reason:
	if (!(cmd->se_cmd_flags & SCF_CMD_PASSTHROUGH))
		CMD_TFO(cmd)->queue_status(cmd);

	return 0;
}
EXPORT_SYMBOL(transport_send_check_condition_and_sense);

int transport_check_aborted_status(struct se_cmd *cmd, int send_status)
{
	int ret = 0;

	if (!(cmd->se_cmd_flags & SCF_CMD_PASSTHROUGH))
		return 0;

	if (atomic_read(&T_TASK(cmd)->t_transport_aborted) != 0) {
		if (!(send_status) ||
		     (cmd->se_cmd_flags & SCF_SENT_DELAYED_TAS))
			return 1;
#if 0
		printk(KERN_INFO "Sending delayed SAM_STAT_TASK_ABORTED"
			" status for CDB: 0x%02x ITT: 0x%08x\n",
			T_TASK(cmd)->t_task_cdb[0],
			CMD_TFO(cmd)->get_task_tag(cmd));
#endif
		cmd->se_cmd_flags |= SCF_SENT_DELAYED_TAS;
		CMD_TFO(cmd)->queue_status(cmd);
		ret = 1;
	}
	return ret;
}
EXPORT_SYMBOL(transport_check_aborted_status);

void transport_send_task_abort(struct se_cmd *cmd)
{
	if (cmd->se_cmd_flags & SCF_CMD_PASSTHROUGH)
		return;
	/*
	 * If there are still expected incoming fabric WRITEs, we wait
	 * until until they have completed before sending a TASK_ABORTED
	 * response.  This response with TASK_ABORTED status will be
	 * queued back to fabric module by transport_check_aborted_status().
	 */
	if ((cmd->data_direction == SE_DIRECTION_WRITE) ||
	    (cmd->data_direction == SE_DIRECTION_BIDI)) {
		if (CMD_TFO(cmd)->write_pending_status(cmd) != 0) {
			atomic_inc(&T_TASK(cmd)->t_transport_aborted);
			smp_mb__after_atomic_inc();
			cmd->scsi_status = SAM_STAT_TASK_ABORTED;
			transport_new_cmd_failure(cmd);
			return;
		}
	}
	cmd->scsi_status = SAM_STAT_TASK_ABORTED;
#if 0
	printk(KERN_INFO "Setting SAM_STAT_TASK_ABORTED status for CDB: 0x%02x,"
		" ITT: 0x%08x\n", T_TASK(cmd)->t_task_cdb[0],
		CMD_TFO(cmd)->get_task_tag(cmd));
#endif
	CMD_TFO(cmd)->queue_status(cmd);
}

/*	transport_generic_do_tmr():
 *
 *
 */
int transport_generic_do_tmr(struct se_cmd *cmd)
{
	struct se_cmd *ref_cmd;
	struct se_device *dev = SE_DEV(cmd);
	struct se_tmr_req *tmr = cmd->se_tmr_req;
	int ret;

	switch (tmr->function) {
	case ABORT_TASK:
		ref_cmd = tmr->ref_cmd;
		tmr->response = TMR_FUNCTION_REJECTED;
		break;
	case ABORT_TASK_SET:
	case CLEAR_ACA:
	case CLEAR_TASK_SET:
		tmr->response = TMR_TASK_MGMT_FUNCTION_NOT_SUPPORTED;
		break;
	case LUN_RESET:
		ret = core_tmr_lun_reset(dev, tmr, NULL, NULL);
		tmr->response = (!ret) ? TMR_FUNCTION_COMPLETE :
					 TMR_FUNCTION_REJECTED;
		break;
#if 0
	case TARGET_WARM_RESET:
		transport_generic_host_reset(dev->se_hba);
		tmr->response = TMR_FUNCTION_REJECTED;
		break;
	case TARGET_COLD_RESET:
		transport_generic_host_reset(dev->se_hba);
		transport_generic_cold_reset(dev->se_hba);
		tmr->response = TMR_FUNCTION_REJECTED;
		break;
#endif
	default:
		printk(KERN_ERR "Uknown TMR function: 0x%02x.\n",
				tmr->function);
		tmr->response = TMR_FUNCTION_REJECTED;
		break;
	}

	cmd->t_state = TRANSPORT_ISTATE_PROCESSING;
	CMD_TFO(cmd)->queue_tm_rsp(cmd);

	transport_cmd_check_stop(cmd, 2, 0);
	return 0;
}

/*
 *	Called with spin_lock_irq(&dev->execute_task_lock); held
 *
 */
struct se_task *transport_get_task_from_state_list(struct se_device *dev)
{
	struct se_task *task;

	if (list_empty(&dev->state_task_list))
		return NULL;

	list_for_each_entry(task, &dev->state_task_list, t_state_list)
		break;

	list_del(&task->t_state_list);
	atomic_set(&task->task_state_active, 0);

	return task;
}

static void transport_processing_shutdown(struct se_device *dev)
{
	struct se_cmd *cmd;
	struct se_queue_req *qr;
	struct se_task *task;
	u8 state;
	unsigned long flags;
	/*
	 * Empty the struct se_device's struct se_task state list.
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

		DEBUG_DO("PT: cmd: %p task: %p ITT/CmdSN: 0x%08x/0x%08x,"
			" i_state/def_i_state: %d/%d, t_state/def_t_state:"
			" %d/%d cdb: 0x%02x\n", cmd, task,
			CMD_TFO(cmd)->get_task_tag(cmd), cmd->cmd_sn,
			CMD_TFO(cmd)->get_cmd_state(cmd), cmd->deferred_i_state,
			cmd->t_state, cmd->deferred_t_state,
			T_TASK(cmd)->t_task_cdb[0]);
		DEBUG_DO("PT: ITT[0x%08x] - t_task_cdbs: %d t_task_cdbs_left:"
			" %d t_task_cdbs_sent: %d -- t_transport_active: %d"
			" t_transport_stop: %d t_transport_sent: %d\n",
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

			DEBUG_DO("Waiting for task: %p to shutdown for dev:"
				" %p\n", task, dev);
			wait_for_completion(&task->task_stop_comp);
			DEBUG_DO("Completed task: %p shutdown for dev: %p\n",
				task, dev);

			spin_lock_irqsave(&T_TASK(cmd)->t_state_lock, flags);
			atomic_dec(&T_TASK(cmd)->t_task_cdbs_left);

			atomic_set(&task->task_active, 0);
			atomic_set(&task->task_stop, 0);
		}
		__transport_stop_task_timer(task, &flags);

		if (!(atomic_dec_and_test(&T_TASK(cmd)->t_task_cdbs_ex_left))) {
			spin_unlock_irqrestore(
					&T_TASK(cmd)->t_state_lock, flags);

			DEBUG_DO("Skipping task: %p, dev: %p for"
				" t_task_cdbs_ex_left: %d\n", task, dev,
				atomic_read(&T_TASK(cmd)->t_task_cdbs_ex_left));

			spin_lock_irqsave(&dev->execute_task_lock, flags);
			continue;
		}

		if (atomic_read(&T_TASK(cmd)->t_transport_active)) {
			DEBUG_DO("got t_transport_active = 1 for task: %p, dev:"
					" %p\n", task, dev);

			if (atomic_read(&T_TASK(cmd)->t_fe_count)) {
				spin_unlock_irqrestore(
					&T_TASK(cmd)->t_state_lock, flags);
				transport_send_check_condition_and_sense(
					cmd, LOGICAL_UNIT_COMMUNICATION_FAILURE,
					0);
				transport_remove_cmd_from_queue(cmd,
					SE_DEV(cmd)->dev_queue_obj);

				transport_lun_remove_cmd(cmd);
				if (!(transport_cmd_check_stop(cmd, 1, 0)))
					transport_passthrough_check_stop(cmd);
			} else {
				spin_unlock_irqrestore(
					&T_TASK(cmd)->t_state_lock, flags);

				transport_remove_cmd_from_queue(cmd,
					SE_DEV(cmd)->dev_queue_obj);

				transport_lun_remove_cmd(cmd);

				if (!(transport_cmd_check_stop(cmd, 1, 0)))
					transport_passthrough_check_stop(cmd);
				else
					transport_generic_remove(cmd, 0, 0);
			}

			spin_lock_irqsave(&dev->execute_task_lock, flags);
			continue;
		}
		DEBUG_DO("Got t_transport_active = 0 for task: %p, dev: %p\n",
				task, dev);

		if (atomic_read(&T_TASK(cmd)->t_fe_count)) {
			spin_unlock_irqrestore(
				&T_TASK(cmd)->t_state_lock, flags);
			transport_send_check_condition_and_sense(cmd,
				LOGICAL_UNIT_COMMUNICATION_FAILURE, 0);
			transport_remove_cmd_from_queue(cmd,
				SE_DEV(cmd)->dev_queue_obj);

			transport_lun_remove_cmd(cmd);
			if (!(transport_cmd_check_stop(cmd, 1, 0)))
				transport_passthrough_check_stop(cmd);
		} else {
			spin_unlock_irqrestore(
				&T_TASK(cmd)->t_state_lock, flags);

			transport_remove_cmd_from_queue(cmd,
				SE_DEV(cmd)->dev_queue_obj);
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
	 * Empty the struct se_device's struct se_cmd list.
	 */
	spin_lock_irqsave(&dev->dev_queue_obj->cmd_queue_lock, flags);
	while ((qr = __transport_get_qr_from_queue(dev->dev_queue_obj))) {
		spin_unlock_irqrestore(
				&dev->dev_queue_obj->cmd_queue_lock, flags);
		cmd = (struct se_cmd *)qr->cmd;
		state = qr->state;
		kfree(qr);

		DEBUG_DO("From Device Queue: cmd: %p t_state: %d\n",
				cmd, state);

		if (atomic_read(&T_TASK(cmd)->t_fe_count)) {
			transport_send_check_condition_and_sense(cmd,
				LOGICAL_UNIT_COMMUNICATION_FAILURE, 0);

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
}

/*	transport_processing_thread():
 *
 *
 */
static int transport_processing_thread(void *param)
{
	int ret, t_state;
	struct se_cmd *cmd;
	struct se_device *dev = (struct se_device *) param;
	struct se_queue_req *qr;

	current->policy = SCHED_NORMAL;
	set_user_nice(current, -20);
	spin_lock_irq(&current->sighand->siglock);
	siginitsetinv(&current->blocked, SHUTDOWN_SIGS);
	recalc_sigpending();
	spin_unlock_irq(&current->sighand->siglock);

	complete(&dev->dev_queue_obj->thread_create_comp);

	while (!(kthread_should_stop())) {
		ret = wait_event_interruptible(dev->dev_queue_obj->thread_wq,
				atomic_read(&dev->dev_queue_obj->queue_cnt) ||
				kthread_should_stop());
		if (ret < 0)
			goto out;

		spin_lock(&dev->dev_status_lock);
		if (dev->dev_status & TRANSPORT_DEVICE_SHUTDOWN) {
			spin_unlock(&dev->dev_status_lock);
			transport_processing_shutdown(dev);
			continue;
		}
		spin_unlock(&dev->dev_status_lock);

get_cmd:
		__transport_execute_tasks(dev);

		qr = transport_get_qr_from_queue(dev->dev_queue_obj);
		if (!(qr))
			continue;

		cmd = (struct se_cmd *)qr->cmd;
		t_state = qr->state;
		kfree(qr);

		switch (t_state) {
		case TRANSPORT_NEW_CMD:
			ret = transport_generic_new_cmd(cmd);
			if (ret < 0) {
				cmd->transport_error_status = ret;
				transport_generic_request_failure(cmd, NULL,
					0, (cmd->data_direction !=
					 SE_DIRECTION_WRITE));
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
			printk(KERN_ERR "Unknown t_state: %d deferred_t_state:"
				" %d for ITT: 0x%08x i_state: %d on SE LUN:"
				" %u\n", t_state, cmd->deferred_t_state,
				CMD_TFO(cmd)->get_task_tag(cmd),
				CMD_TFO(cmd)->get_cmd_state(cmd),
				SE_LUN(cmd)->unpacked_lun);
			BUG();
		}

		goto get_cmd;
	}

out:
	transport_release_all_cmds(dev);
	dev->process_thread = NULL;
	complete(&dev->dev_queue_obj->thread_done_comp);
	return 0;
}
