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

#include <linux/slab.h>
#include <linux/virtio.h>
#include <linux/virtio_ids.h>
#include <linux/virtio_config.h>
#include <scsi/scsi_host.h>

struct virtio_scsi {
	/* Queue for commands and task management requests */
	struct virtqueue *cmd_vq;
};

static void virtscsi_cmd_done(struct virtqueue *vq)
{
	/* TODO */
}

static int virtscsi_queuecommand(struct Scsi_Host *sh, struct scsi_cmnd *sc)
{
	/* TODO */
	return SCSI_MLQUEUE_HOST_BUSY;
}

static struct scsi_host_template virtscsi_host_template = {
	.module = THIS_MODULE,
	.name = "Virtio SCSI HBA",
	.proc_name = "virtio_scsi",
	.queuecommand = virtscsi_queuecommand,
	.this_id = -1,

	/* TODO correct these */
	.can_queue = 1024,
	.sg_tablesize = 256,
	.max_sectors = 1024,
	.dma_boundary = DISABLE_CLUSTERING,
	.cmd_per_lun = 1,
};

static int __devinit virtscsi_probe(struct virtio_device *vdev)
{
	struct Scsi_Host *shost;
	struct virtio_scsi *vscsi;
	int err;

	shost = scsi_host_alloc(&virtscsi_host_template, sizeof(*vscsi));
	if (!shost)
		return -ENOMEM;

	vdev->priv = shost;
	vscsi = shost_priv(shost);

	vscsi->cmd_vq = virtio_find_single_vq(vdev, virtscsi_cmd_done, "cmd");
	if (IS_ERR(vscsi->cmd_vq)) {
		err = PTR_ERR(vscsi->cmd_vq);
		goto virtio_find_single_vq_failed;
	}

	/* TODO correct these */
	shost->max_id = 64;
	shost->max_lun = 8;
	shost->max_channel = 0;
	shost->max_cmd_len = 32;

	err = scsi_add_host(shost, &vdev->dev);
	if (err)
		goto scsi_add_host_failed;

	return 0;

scsi_add_host_failed:
	vdev->config->del_vqs(vdev);
virtio_find_single_vq_failed:
	scsi_host_put(shost);
	return err;
}

static void __devexit virtscsi_remove(struct virtio_device *vdev)
{
	struct Scsi_Host *shost = vdev->priv;

	scsi_remove_host(shost);

	/* Stop all the virtqueues. */
	vdev->config->reset(vdev);

	vdev->config->del_vqs(vdev);
	scsi_host_put(shost);
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
	int ret = register_virtio_driver(&virtio_scsi_driver);
	return ret;
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
