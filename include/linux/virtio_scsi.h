#ifndef _LINUX_VIRTIO_SCSI_H
#define _LINUX_VIRTIO_SCSI_H
/* This header is BSD licensed so anyone can use the definitions to implement
 * compatible drivers/servers. */

/*
 * TODO
 * Asynchronous events (AER) - might need an AER virtqueue
 */

/* Request type */
typedef __u8 virtio_scsi_header_type;
#define VIRTIO_SCSI_TYPE_CMD	0	/* Command */
#define VIRTIO_SCSI_TYPE_TMR	1	/* Task Management Request */

/* SCSI command */
struct virtio_scsi_cmd_header {
	virtio_scsi_header_type header_type;
	__u64 lun;		/* Logical Unit Number */
	__u64 tag;		/* Command identifier */
	__u8 task_attr;		/* Task attribute */

/*
 * TODO check if we need these:
 * crn
 * cmd_prio
 */
} __attribute__((packed));

/* Task Management Request */
struct virtio_scsi_tmr_header {
	virtio_scsi_header_type header_type;
	__u64 lun;		/* Logical Unit Number */
	__u64 tag;		/* Tag of task */
	__u8 task_mgmt_func;	/* Task management function */
/* TODO #define management functions */
} __attribute__((packed));

/* Response */
struct virtio_scsi_footer {
	__u32 resid;		/* Residual bytes in data buffer */
	__u16 status_qualifier;	/* Status qualifier */
	__u8 status;		/* Command completion status */
	__u8 sense_len;		/* Sense data length */
	__u8 sense[96];		/* Sense data */
} __attribute__((packed));

/* TODO fix field alignment in all structs */

#endif /* _LINUX_VIRTIO_SCSI_H */
