/*
 *  qla_target.h SCSI LLD infrastructure for QLogic 22xx/23xx/24xx/25xx
 *
 *  based on qla2x00t.h code:
 *
 *  Copyright (C) 2004 - 2010 Vladislav Bolkhovitin <vst@vlnb.net>
 *  Copyright (C) 2004 - 2005 Leonid Stoljar
 *  Copyright (C) 2006 Nathaniel Clark <nate@misrule.us>
 *  Copyright (C) 2006 - 2010 ID7 Ltd.
 *
 *  Forward port and refactoring to modern qla2xxx and target/configfs
 *
 *  Copyright (C) 2010 Nicholas A. Bellinger <nab@kernel.org>
 *
 *  This program is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU General Public License
 *  as published by the Free Software Foundation, version 2
 *  of the License.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 *  GNU General Public License for more details.
 */

#ifndef __QLA_TARGET_H
#define __QLA_TARGET_H

#include "qla_tgt_def.h"

#define QLA_TGT_TIMEOUT			10	/* in seconds */

#define QLA_TGT_MAX_HW_PENDING_TIME	60 /* in seconds */

/* Immediate notify status constants */
#define IMM_NTFY_LIP_RESET          0x000E
#define IMM_NTFY_LIP_LINK_REINIT    0x000F
#define IMM_NTFY_IOCB_OVERFLOW      0x0016
#define IMM_NTFY_ABORT_TASK         0x0020
#define IMM_NTFY_PORT_LOGOUT        0x0029
#define IMM_NTFY_PORT_CONFIG        0x002A
#define IMM_NTFY_GLBL_TPRLO         0x002D
#define IMM_NTFY_GLBL_LOGO          0x002E
#define IMM_NTFY_RESOURCE           0x0034
#define IMM_NTFY_MSG_RX             0x0036
#define IMM_NTFY_SRR                0x0045
#define IMM_NTFY_ELS                0x0046

/* Immediate notify task flags */
#define IMM_NTFY_TASK_MGMT_SHIFT    8

#define QLA_TGT_CLEAR_ACA               0x40
#define QLA_TGT_TARGET_RESET            0x20
#define QLA_TGT_LUN_RESET               0x10
#define QLA_TGT_CLEAR_TS                0x04
#define QLA_TGT_ABORT_TS                0x02
#define QLA_TGT_ABORT_ALL_SESS          0xFFFF
#define QLA_TGT_ABORT_ALL               0xFFFE
#define QLA_TGT_NEXUS_LOSS_SESS         0xFFFD
#define QLA_TGT_NEXUS_LOSS              0xFFFC

/* Notify Acknowledge flags */
#define NOTIFY_ACK_RES_COUNT        BIT_8
#define NOTIFY_ACK_CLEAR_LIP_RESET  BIT_5
#define NOTIFY_ACK_TM_RESP_CODE_VALID BIT_4

/* Command's states */
#define QLA_TGT_STATE_NEW               0	/* New command and target processing it */
#define QLA_TGT_STATE_NEED_DATA         1	/* target needs data to continue */
#define QLA_TGT_STATE_DATA_IN           2	/* Data arrived and target is processing */
#define QLA_TGT_STATE_PROCESSED         3	/* target done processing */
#define QLA_TGT_STATE_ABORTED           4	/* Command aborted */

/* Special handles */
#define QLA_TGT_NULL_HANDLE             0
#define QLA_TGT_SKIP_HANDLE             (0xFFFFFFFF & ~CTIO_COMPLETION_HANDLE_MARK)

/* ATIO task_codes field */
#define ATIO_SIMPLE_QUEUE           0
#define ATIO_HEAD_OF_QUEUE          1
#define ATIO_ORDERED_QUEUE          2
#define ATIO_ACA_QUEUE              4
#define ATIO_UNTAGGED               5

/* TM failed response codes, see FCP (9.4.11 FCP_RSP_INFO) */
#define	FC_TM_SUCCESS               0
#define	FC_TM_BAD_FCP_DATA          1
#define	FC_TM_BAD_CMD               2
#define	FC_TM_FCP_DATA_MISMATCH     3
#define	FC_TM_REJECT                4
#define FC_TM_FAILED                5

/*
 * Error code of qla_tgt_pre_xmit_response() meaning that cmd's exchange was
 * terminated, so no more actions is needed and success should be returned
 * to target.
 */
#define QLA_TGT_PRE_XMIT_RESP_CMD_ABORTED	0x1717

#if (BITS_PER_LONG > 32) || defined(CONFIG_HIGHMEM64G)
#define pci_dma_lo32(a) (a & 0xffffffff)
#define pci_dma_hi32(a) ((((a) >> 16)>>16) & 0xffffffff)
#else
#define pci_dma_lo32(a) (a & 0xffffffff)
#define pci_dma_hi32(a) 0
#endif

#define QLA_TGT_SENSE_VALID(sense)  ((sense != NULL) && \
				(((const uint8_t *)(sense))[0] & 0x70) == 0x70)

struct qla_tgt {
	struct scsi_qla_host *vha;
	struct qla_hw_data *ha;

	/*
	 * To sync between IRQ handlers and qla_tgt_target_release(). Needed,
	 * because req_pkt() can drop/reaquire HW lock inside. Protected by
	 * HW lock.
	 */
	int irq_cmd_count;

	int datasegs_per_cmd, datasegs_per_cont;

	/* Target's flags, serialized by pha->hardware_lock */
	unsigned int tgt_enable_64bit_addr:1;	/* 64-bits PCI addressing enabled */
	unsigned int link_reinit_iocb_pending:1;
	unsigned int tm_to_unknown:1; /* TM to unknown session was sent */
	unsigned int sess_works_pending:1; /* there are sess_work entries */

	/*
	 * Protected by tgt_mutex AND hardware_lock for writing and tgt_mutex
	 * OR hardware_lock for reading.
	 */
	int tgt_stop; /* the target mode driver is being stopped */
	int tgt_stopped; /* the target mode driver has been stopped */

	/* Count of sessions refering qla_tgt. Protected by hardware_lock. */
	int sess_count;

	/* Protected by hardware_lock. Addition also protected by tgt_mutex. */
	struct list_head sess_list;

	/* Protected by hardware_lock */
	struct list_head del_sess_list;
	struct delayed_work sess_del_work;

	spinlock_t sess_work_lock;
	struct list_head sess_works_list;
	struct work_struct sess_work;

	notify24xx_entry_t link_reinit_iocb;
	wait_queue_head_t waitQ;
	int notify_ack_expected;
	int abts_resp_expected;
	int modify_lun_expected;

	int ctio_srr_id;
	int imm_srr_id;
	spinlock_t srr_lock;
	struct list_head srr_ctio_list;
	struct list_head srr_imm_list;
	struct work_struct srr_work;

	atomic_t tgt_global_resets_count;

	struct list_head tgt_list_entry;
};

/*
 * Equivilant to IT Nexus (Initiator-Target)
 */
struct qla_tgt_sess {
	uint16_t loop_id;
	port_id_t s_id;

	unsigned int conf_compl_supported:1;
	unsigned int deleted:1;
	unsigned int local:1;

	struct se_session *se_sess;
	scsi_qla_host_t *vha;
	struct qla_tgt *tgt;

	int sess_ref; /* protected by hardware_lock */

	struct list_head sess_list_entry;
	unsigned long expires;
	struct list_head del_list_entry;

	uint8_t port_name[WWN_SIZE];
};

struct qla_tgt_cmd {
	struct qla_tgt_sess *sess;
	int state;
	atomic_t cmd_done;
	atomic_t cmd_stop_free;
	struct se_cmd se_cmd;
	/* Sense buffer that will be mapped into outgoing status */
	unsigned char sense_buffer[TRANSPORT_SENSE_BUFFER];

	unsigned int conf_compl_supported:1;/* to save extra sess dereferences */
	unsigned int sg_mapped:1;
	unsigned int free_sg:1;
	unsigned int aborted:1; /* Needed in case of SRR */
	unsigned int write_data_transferred:1;

	struct scatterlist *sg;	/* cmd data buffer SG vector */
	int sg_cnt;		/* SG segments count */
	int bufflen;		/* cmd buffer length */
	int offset;
	uint32_t tag;
	dma_addr_t dma_handle;
	enum dma_data_direction dma_data_direction;

	uint16_t loop_id;		    /* to save extra sess dereferences */
	struct qla_tgt *tgt;		    /* to save extra sess dereferences */
	scsi_qla_host_t *vha;

	union {
		atio7_entry_t atio7;
		atio_entry_t atio2x;
	} __attribute__((packed)) atio;
};

struct qla_tgt_sess_work_param {
	struct list_head sess_works_list_entry;

#define QLA_TGT_SESS_WORK_CMD	0
#define QLA_TGT_SESS_WORK_ABORT	1
#define QLA_TGT_SESS_WORK_TM	2
	int type;

	union {
		struct qla_tgt_cmd *cmd;
		abts24_recv_entry_t abts;
		notify_entry_t tm_iocb;
		atio7_entry_t tm_iocb2;
	};
};

struct qla_tgt_mgmt_cmd {
	uint8_t tmr_func;
	uint8_t fc_tm_rsp;
	struct qla_tgt_sess *sess;
	struct se_cmd se_cmd;
	struct se_tmr_req *se_tmr_req;
	unsigned int flags;
#define Q24_MGMT_SEND_NACK	1
	union {
		atio7_entry_t atio7;
		notify_entry_t notify_entry;
		notify24xx_entry_t notify_entry24;
		abts24_recv_entry_t abts;
	} __attribute__((packed)) orig_iocb;
};

struct qla_tgt_prm {
	struct qla_tgt_cmd *cmd;
	struct qla_tgt *tgt;
	void *pkt;
	struct scatterlist *sg;	/* cmd data buffer SG vector */
	int seg_cnt;
	int req_cnt;
	uint16_t rq_result;
	uint16_t scsi_status;
	unsigned char *sense_buffer;
	int sense_buffer_len;
	int residual;
	int add_status_pkt;
};

struct srr_imm {
	struct list_head srr_list_entry;
	int srr_id;
	union {
		notify_entry_t notify_entry;
		notify24xx_entry_t notify_entry24;
	} __attribute__((packed)) imm;
};

struct srr_ctio {
	struct list_head srr_list_entry;
	int srr_id;
	struct qla_tgt_cmd *cmd;
};

#define QLA_TGT_XMIT_DATA		1
#define QLA_TGT_XMIT_STATUS		2
#define QLA_TGT_XMIT_ALL		(QLA_TGT_XMIT_STATUS|QLA_TGT_XMIT_DATA)

#endif /* __QLA_TARGET_H */
