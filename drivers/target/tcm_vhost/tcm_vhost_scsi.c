/*
 * Virtio SCSI HBA server in host kernel
 *
 * Copyright IBM Corp. 2010
 *
 * Authors:
 *  Stefan Hajnoczi   <stefanha@linux.vnet.ibm.com>
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
#include "../../vhost/vhost.h" /* TODO this is ugly */

struct vhost_scsi {
	struct vhost_dev dev;
	struct vhost_virtqueue cmd_vq;
};

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
	return -EINVAL;
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
