struct vhost_scsi {
	atomic_t vhost_ref_cnt;
	struct tcm_vhost_tpg *vs_tpg;
	struct vhost_dev dev;
	struct vhost_virtqueue cmd_vq;
};

extern int __init vhost_scsi_register(void);
extern int vhost_scsi_deregister(void);
