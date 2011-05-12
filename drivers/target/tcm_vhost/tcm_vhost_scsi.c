/*
 * Virtio SCSI HBA server in host kernel
 *
 * Copyright IBM Corp. 2010
 * Copyright Rising Tide Systems, LLC. 2011
 *
 * Authors:
 *  Stefan Hajnoczi   <stefanha@linux.vnet.ibm.com>
 *  Nicholas A. Bellinger <nab@risingtidesystems.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory.
 *
 */

#include <linux/compat.h>
#include <linux/eventfd.h>
#include <linux/vhost.h>
#include <linux/fs.h>
#include <linux/miscdevice.h>
#include <linux/vhost.h>
#include <linux/virtio_net.h> /* TODO vhost.h currently depends on this */
#include <linux/virtio_scsi.h>
#include "../../vhost/vhost.h" /* TODO this is ugly */

#include <scsi/scsi.h>
#include <scsi/scsi_tcq.h>
#include <scsi/libsas.h> /* For TASK_ATTR_* */
#include <target/target_core_base.h>
#include <target/target_core_device.h>
#include <target/target_core_transport.h>

#include "tcm_vhost_base.h"
#include "tcm_vhost_scsi.h"

/* From tcm_vhost_configfs.c */
/* Global spinlock to protect tcm_vhost TPG list for vhost IOCTL access */
extern struct mutex tcm_vhost_mutex;
extern struct list_head tcm_vhost_list;

static struct tcm_vhost_cmd *vhost_scsi_allocate_cmd(
	struct tcm_vhost_tpg *tv_tpg,
	struct virtio_scsi_cmd_header *v_header,
	u32 exp_data_len,
	int data_direction)
{
	struct tcm_vhost_cmd *tv_cmd;
	struct tcm_vhost_nexus *tv_nexus;
	struct se_portal_group *se_tpg = &tv_tpg->se_tpg;
	struct se_session *se_sess;
	struct se_cmd *se_cmd;
	int sam_task_attr;

	tv_nexus = tv_tpg->tpg_nexus;
	if (!tv_nexus) {
		printk(KERN_ERR "Unable to locate active struct tcm_vhost_nexus\n");
		return ERR_PTR(-EIO);
	}
	se_sess = tv_nexus->tvn_se_sess;

	tv_cmd = kzalloc(sizeof(struct tcm_vhost_cmd), GFP_ATOMIC);
	if (!tv_cmd) {
		printk(KERN_ERR "Unable to allocate struct tcm_vhost_cmd\n");
		return ERR_PTR(-ENOMEM);
	}
	tv_cmd->tvc_tag = v_header->tag;

	se_cmd = &tv_cmd->tvc_se_cmd;
	/*
	 * Locate the SAM Task Attr from virtio_scsi_cmd_header
	 */
	switch (v_header->task_attr) {
	case MSG_HEAD_TAG:
		sam_task_attr = TASK_ATTR_HOQ;
		break;
	case MSG_ORDERED_TAG:
		sam_task_attr = TASK_ATTR_ORDERED;
		break;
	case MSG_SIMPLE_TAG:
		/* Fall through */
	default:
		sam_task_attr = TASK_ATTR_SIMPLE;
		break;
	}
	/*
	 * Initialize struct se_cmd descriptor from target_core_mod infrastructure
	 */
	transport_init_se_cmd(se_cmd, se_tpg->se_tpg_tfo, se_sess, exp_data_len,
				data_direction, sam_task_attr,
				&tv_cmd->tvc_sense_buf[0]);

#warning FIXME: vhost_scsi_allocate_cmd() BIDI operation
#if 0
	/*
	 * Signal BIDI usage with T_TASK(cmd)->t_tasks_bidi
	 */
	if (bidi)
		T_TASK(se_cmd)->t_tasks_bidi = 1;
#endif
	/*
	 * Locate the struct se_lun pointer based on the passed v_header->lun,
	 * and attach it to struct se_cmd
	 *
	 * Note this currently assumes v_header->lun has already been unpacked.
	 */
	if (transport_get_lun_for_cmd(se_cmd, NULL, v_header->lun) < 0) {
		kfree(tv_cmd);
		return ERR_PTR(-ENODEV);
	}

	transport_device_setup_cmd(se_cmd);
	/*
	 * From here the rest of the se_cmd will be setup and dispatched
	 * via tcm_vhost_new_cmd_map() from TCM backend thread context
	 * after transport_generic_handle_cdb_map() has been called from
	 * vhost_scsi_handle_vq() below..
	 */
	return tv_cmd;
}

static void vhost_scsi_handle_vq(struct vhost_scsi *vs)
{
	struct vhost_virtqueue *vq = &vs->cmd_vq;
	struct virtio_scsi_cmd_header *v_header;
	struct tcm_vhost_tpg *tv_tpg;
	struct tcm_vhost_cmd *tv_cmd;
	unsigned char *cdb;
	void *private;
	u32 exp_data_len, data_direction;
	unsigned out, in;
	int head;

	private = rcu_dereference_check(vq->private_data, 1);
	if (!private)
		return;

	mutex_lock(&vq->mutex);
	vhost_disable_notify(vq);

	for (;;) {
		head = vhost_get_vq_desc(&vs->dev, vq, vq->iov,
					ARRAY_SIZE(vq->iov), &out, &in,
					NULL, NULL);
		/* On error, stop handling until the next kick. */
		if (unlikely(head < 0))
			break;
		/* Nothing new?  Wait for eventfd to tell us they refilled. */
		if (head == vq->num) {
			if (unlikely(vhost_enable_notify(vq))) {
				vhost_disable_notify(vq);
				continue;
			}
			break;
		}
#warning FIXME: Locate v_header, cdb, exp_data_len and data_direction for vhost_scsi_allocate_cmd()
		tv_tpg = vs->vs_tpg;
		v_header = NULL;
		cdb = NULL;
		exp_data_len = 0;
		data_direction = 0;
		/*
		 * Check that the recieved CDB size does not exceeded our
		 * hardcoded max for t
		 */
		if (scsi_command_size(cdb) > TCM_VHOST_MAX_CDB_SIZE) {
			printk(KERN_ERR "Received SCSI CDB with command_size:"
				" %d that exceeds SCSI_MAX_VARLEN_CDB_SIZE: %d\n",
				scsi_command_size(cdb), TCM_VHOST_MAX_CDB_SIZE);
			break;
		}

		tv_cmd = vhost_scsi_allocate_cmd(tv_tpg, v_header,
					exp_data_len, data_direction);
		if (IS_ERR(tv_cmd))
			break;
		/*
		 * Copy in the recieved CDB descriptor into tv_cmd->tvc_cdb
		 * that will be used by tcm_vhost_new_cmd_map() and down into
		 * transport_generic_allocate_tasks()
		 */
		memcpy(tv_cmd->tvc_cdb, cdb, scsi_command_size(cdb));
		/*
		 * Now set the virtio-scsi SGL memory + SGL counter values in
		 * tv_cmd for use in tcm_vhost_new_cmd_map() and down into
		 * transport_generic_map_mem_to_cmd() code to setup the
		 * virtio-scsi SGL  -> TCM struct se_mem mapping.
		 */
#warning FIXME: Setup tv_cmd->tvc_sgl and tv_cmd->tvc_sgl_count
		tv_cmd->tvc_sgl = NULL;
		tv_cmd->tvc_sgl_count = 0;
		/*
		 * Save the descriptor from vhost_get_vq_desc() to be used to
		 * complete the virtio-scsi request in TCM callback context via
		 * tcm_vhost_queue_data_in() and tcm_vhost_queue_status()
		 */
		tv_cmd->tvc_vq_desc = head;
		/*
		 * Now queue up the newly allocated se_cmd to be processed
		 * within TCM thread context to finish the setup and dispatched
		 * into a TCM backend struct se_device.
		 */
		transport_generic_handle_cdb_map(&tv_cmd->tvc_se_cmd);
	}

	mutex_unlock(&vq->mutex);
}

static void vhost_scsi_handle_kick(struct vhost_work *work)
{
	struct vhost_virtqueue *vq = container_of(work, struct vhost_virtqueue,
						poll.work);
	struct vhost_scsi *vs = container_of(vq->dev, struct vhost_scsi, dev);

	vhost_scsi_handle_vq(vs);
}

/*
 * Used by tcm_vhost_configfs.c:tcm_vhost_tpg_store_dev_index() to
 * create the vhost_scsi device association from the passed dev_index.
 */
#warning FIXME: Add vhost_scsi_dev_index_associate() logic
int vhost_scsi_dev_index_associate(struct tcm_vhost_tpg *tv_tpg, u32 dev_index)
{
	return -ENOSYS;
}

/*
 * Used by tcm_vhost_configfs.c:cm_vhost_tpg_store_dev_index() to
 * release the vhost_scsi device association when 'NULL' has been passed
 * into the /sys/kernel/config/target/vhost/$TARGET_WWN/tpgt_$TPGT/dev_index
 * configfs attribute.
 */
#warning FIXME: Add vhost_scsi_dev_index_release() logic
int vhost_scsi_dev_index_release(struct tcm_vhost_tpg *tv_tpg, u32 dev_index)
{
	return -ENOSYS;
}

static void vhost_scsi_disable_vq(struct vhost_scsi *vs)
{
	struct vhost_virtqueue *vq = &vs->cmd_vq;

	vhost_poll_stop(&vq->poll);
}

static void vhost_scsi_enable_vq(struct vhost_scsi *vs)
{
	struct vhost_virtqueue *vq = &vs->cmd_vq;

	vhost_poll_start(&vq->poll, vq->kick);
}

/*
 * Called from vhost_scsi_ioctl() context to walk the list of available tcm_vhost_tpg
 * with an active struct tcm_vhost_nexus
 */
static int vhost_scsi_set_endpoint(
	struct vhost_scsi *vs,
	struct vhost_vring_target *t)
{
	struct tcm_vhost_tport *tv_tport;
	struct tcm_vhost_tpg *tv_tpg;
	struct vhost_virtqueue *vq = &vs->cmd_vq;

	mutex_lock(&vq->mutex);
	/* Verify that ring has been setup correctly. */
	if (!vhost_vq_access_ok(vq)) {
		mutex_unlock(&vq->mutex);
		return -EFAULT;
	}
	if (vs->vs_tpg) {
		mutex_unlock(&vq->mutex);
		return -EEXIST;
	}
	mutex_unlock(&vq->mutex);

	mutex_lock(&tcm_vhost_mutex);
	list_for_each_entry(tv_tpg, &tcm_vhost_list, tv_tpg_list) {
		mutex_lock(&tv_tpg->tv_tpg_mutex);
		if (!tv_tpg->tpg_nexus) {
			mutex_unlock(&tv_tpg->tv_tpg_mutex);
			continue;
		}
		if (atomic_read(&tv_tpg->tv_tpg_vhost_count)) {
			mutex_unlock(&tv_tpg->tv_tpg_mutex);
			continue;
		}
		tv_tport = tv_tpg->tport;

		if (!strcmp(tv_tport->tport_name, t->vhost_wwpn) &&
		    (tv_tpg->tport_tpgt == t->vhost_tpgt)) {
			atomic_inc(&tv_tpg->tv_tpg_vhost_count);
			smp_mb__after_atomic_inc();
			mutex_unlock(&tv_tpg->tv_tpg_mutex);
			mutex_unlock(&tcm_vhost_mutex);

			mutex_lock(&vq->mutex);
			vs->vs_tpg = tv_tpg;
			atomic_inc(&vs->vhost_ref_cnt);
			smp_mb__after_atomic_inc();
			mutex_unlock(&vq->mutex);
			return 0;
		}
		mutex_unlock(&tv_tpg->tv_tpg_mutex);
	}
	mutex_unlock(&tcm_vhost_mutex);

	return -EINVAL;
}

static int vhost_scsi_clear_endpoint(
	struct vhost_scsi *vs,
	struct vhost_vring_target *t)
{
	struct tcm_vhost_tport *tv_tport;
	struct tcm_vhost_tpg *tv_tpg;
	struct vhost_virtqueue *vq = &vs->cmd_vq;

	mutex_lock(&vq->mutex);
	/* Verify that ring has been setup correctly. */
	if (!vhost_vq_access_ok(vq)) {
		mutex_unlock(&vq->mutex);
		return -EFAULT;
	}
	if (!vs->vs_tpg) {
		mutex_unlock(&vq->mutex);
		return -ENODEV;
	}
	tv_tpg = vs->vs_tpg;
	tv_tport = tv_tpg->tport;

	if (strcmp(tv_tport->tport_name, t->vhost_wwpn) ||
	    (tv_tpg->tport_tpgt != t->vhost_tpgt)) {
		mutex_unlock(&vq->mutex);
		printk(KERN_WARNING "tv_tport->tport_name: %s, tv_tpg->tport_tpgt: %hu"
			" does not match t->vhost_wwpn: %s, t->vhost_tpgt: %hu\n");
		return -EINVAL;
	}
	vs->vs_tpg = NULL;
	mutex_unlock(&vq->mutex);

	return 0;
}

static int vhost_scsi_open(struct inode *inode, struct file *f)
{
	struct vhost_scsi *s;
	int r;

	s = kmalloc(sizeof(*s), GFP_KERNEL);
	if (!s)
		return -ENOMEM;

	r = vhost_dev_init(&s->dev, &s->cmd_vq, 1);
	if (r < 0) {
		kfree(s);
		return r;
	}

	f->private_data = s;
	return 0;
}

static int vhost_scsi_release(struct inode *inode, struct file *f)
{
	struct vhost_scsi *s = f->private_data;

	vhost_dev_cleanup(&s->dev);
	kfree(s);
	return 0;
}

static long vhost_scsi_ioctl(struct file *f, unsigned int ioctl,
				unsigned long arg)
{
	struct vhost_scsi *vs = f->private_data;
	struct vhost_vring_target backend;
	void __user *argp = (void __user *)arg;
	u64 __user *featurep = argp;
	u64 features;
	int r;

	switch (ioctl) {
	case VHOST_SCSI_SET_ENDPOINT:
		if (copy_from_user(&backend, argp, sizeof backend))
			return -EFAULT;

		return vhost_scsi_set_endpoint(vs, &backend);
	case VHOST_SCSI_CLEAR_ENDPOINT:
		if (copy_from_user(&backend, argp, sizeof backend))
			return -EFAULT;

		return vhost_scsi_clear_endpoint(vs, &backend);
	default:
		return -ENOSYS;
	}

	return 0;
}

static const struct file_operations vhost_scsi_fops = {
	.owner          = THIS_MODULE,
	.release        = vhost_scsi_release,
	.unlocked_ioctl = vhost_scsi_ioctl,
	/* TODO compat ioctl? */
	.open           = vhost_scsi_open,
	.llseek		= noop_llseek,
};

static struct miscdevice vhost_scsi_misc = {
	MISC_DYNAMIC_MINOR,
	"vhost-scsi",
	&vhost_scsi_fops,
};

int __init vhost_scsi_register(void)
{
	return misc_register(&vhost_scsi_misc);
}

int vhost_scsi_deregister(void)
{
	return misc_deregister(&vhost_scsi_misc);
}
