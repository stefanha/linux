/*
 * Virtio SCSI HBA driver
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

#include <linux/virtio.h>
#include <linux/virtio_ids.h>

static int virtscsi_probe(struct virtio_device *dev)
{
	return -EINVAL;
}

static void virtscsi_remove(struct virtio_device *dev)
{
}

static struct virtio_device_id id_table[] = {
	{ VIRTIO_ID_SCSI, VIRTIO_DEV_ANY_ID },
	{ 0 },
};

static struct virtio_driver virtio_scsi_driver = {
	.driver.name = KBUILD_MODNAME,
	.driver.owner = THIS_MODULE,
	.id_table = id_table,
	.probe = virtscsi_probe,
	.remove = __devexit_p(virtscsi_remove),
};

static int __init init(void)
{
	return register_virtio_driver(&virtio_scsi_driver);
}

static void __exit fini(void)
{
	unregister_virtio_driver(&virtio_scsi_driver);
}
module_init(init);
module_exit(fini);

MODULE_DEVICE_TABLE(virtio, id_table);
MODULE_DESCRIPTION("Virtio SCSI HBA driver");
MODULE_LICENSE("GPL");
