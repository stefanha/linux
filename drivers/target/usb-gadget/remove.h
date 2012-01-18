#ifndef _REMOVE_H_
#define _REMOVE_H_

/* This file will go once the header movements I made reach upstream */

/*
 * Bulk only data structures
 */

/* command block wrapper */
struct bulk_cb_wrap {
	__le32  Signature;              /* contains 'USBC' */
	__u32   Tag;                    /* unique per command id */
	__le32  DataTransferLength;     /* size of data */
	__u8    Flags;                  /* direction in bit 0 */
	__u8    Lun;                    /* LUN normally 0 */
	__u8    Length;                 /* of of the CDB */
	__u8    CDB[16];                /* max command */
};

#define US_BULK_CB_WRAP_LEN    31
#define US_BULK_CB_SIGN                0x43425355      /*spells out USBC */
#define US_BULK_FLAG_IN                (1 << 7)
#define US_BULK_FLAG_OUT       0

/* command status wrapper */
struct bulk_cs_wrap {
	__le32  Signature;      /* should = 'USBS' */
	__u32   Tag;            /* same as original command */
	__le32  Residue;        /* amount not transferred */
	__u8    Status;         /* see below */
	__u8    Filler[18];
};

#define US_BULK_CS_WRAP_LEN    13
#define US_BULK_CS_SIGN                0x53425355      /* spells out 'USBS' */
#define US_BULK_STAT_OK                0
#define US_BULK_STAT_FAIL      1
#define US_BULK_STAT_PHASE     2

/* bulk-only class specific requests */
#define US_BULK_RESET_REQUEST   0xff
#define US_BULK_GET_MAX_LUN     0xfe

#include <scsi/scsi.h>
#include <scsi/scsi_cmnd.h>

/* Common header for all IUs */
struct iu {
	__u8 iu_id;
	__u8 rsvd1;
	__be16 tag;
};

enum {
	IU_ID_COMMAND           = 0x01,
	IU_ID_STATUS            = 0x03,
	IU_ID_RESPONSE          = 0x04,
	IU_ID_TASK_MGMT         = 0x05,
	IU_ID_READ_READY        = 0x06,
	IU_ID_WRITE_READY       = 0x07,
};

struct command_iu {
	__u8 iu_id;
	__u8 rsvd1;
	__be16 tag;
	__u8 prio_attr;
	__u8 rsvd5;
	__u8 len;
	__u8 rsvd7;
	struct scsi_lun lun;
	__u8 cdb[16];   /* XXX: Overflow-checking tools may misunderstand */
};

/*
 * Also used for the Read Ready and Write Ready IUs since they have the
 * same first four bytes
 */
struct sense_iu {
	__u8 iu_id;
	__u8 rsvd1;
	__be16 tag;
	__be16 status_qual;
	__u8 status;
	__u8 rsvd7[7];
	__be16 len;
	__u8 sense[SCSI_SENSE_BUFFERSIZE];
};
struct usb_pipe_usage_descriptor {
	__u8  bLength;
	__u8  bDescriptorType;

	__u8  bPipeID;
	__u8  Reserved;
} __attribute__((__packed__));

enum {
	CMD_PIPE_ID             = 1,
	STATUS_PIPE_ID          = 2,
	DATA_IN_PIPE_ID         = 3,
	DATA_OUT_PIPE_ID        = 4,

	UAS_SIMPLE_TAG          = 0,
	UAS_HEAD_TAG            = 1,
	UAS_ORDERED_TAG         = 2,
	UAS_ACA                 = 4,
};

#endif
