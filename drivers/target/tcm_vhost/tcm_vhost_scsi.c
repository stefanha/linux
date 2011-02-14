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

static int vhost_scsi_open(struct inode *inode, struct file *f)
{
	return -EINVAL;
}

static int vhost_scsi_release(struct inode *inode, struct file *f)
{
	return -EINVAL;
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
