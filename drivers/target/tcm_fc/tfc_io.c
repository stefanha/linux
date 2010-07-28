/*
 * Copyright (c) 2010 Cisco Systems, Inc.
 *
 * Portions based on tcm_loop_fabric_scsi.c and libfc/fc_fcp.c
 *
 * Copyright (c) 2007 Intel Corporation. All rights reserved.
 * Copyright (c) 2008 Red Hat, Inc.  All rights reserved.
 * Copyright (c) 2008 Mike Christie
 * Copyright (c) 2009 Rising Tide, Inc.
 * Copyright (c) 2009 Linux-iSCSI.org
 * Copyright (c) 2009 Nicholas A. Bellinger <nab@linux-iscsi.org>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin St - Fifth Floor, Boston, MA 02110-1301 USA.
 */

/* XXX TBD some includes may be extraneous */

#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/version.h>
#include <generated/utsrelease.h>
#include <linux/utsname.h>
#include <linux/init.h>
#include <linux/slab.h>
#include <linux/kthread.h>
#include <linux/types.h>
#include <linux/string.h>
#include <linux/configfs.h>
#include <linux/ctype.h>
#include <linux/hash.h>
#include <asm/unaligned.h>
#include <scsi/scsi.h>
#include <scsi/scsi_host.h>
#include <scsi/scsi_device.h>
#include <scsi/scsi_cmnd.h>
#include <scsi/libfc.h>
#include <scsi/fc_encode.h>

#include <target/target_core_base.h>
#include <target/target_core_transport.h>
#include <target/target_core_fabric_ops.h>
#include <target/target_core_device.h>
#include <target/target_core_tpg.h>
#include <target/target_core_configfs.h>
#include <target/target_core_base.h>
#include <target/configfs_macros.h>

#include "tcm_fc.h"

/*
 * Deliver read data back to initiator.
 * XXX TBD handle resource problems later.
 */
int ft_queue_data_in(struct se_cmd *se_cmd)
{
	struct ft_cmd *cmd = se_cmd->se_fabric_cmd_ptr;
	struct se_transport_task *task;
	struct fc_frame *fp = NULL;
	struct fc_exch *ep;
	struct fc_lport *lport;
	struct se_mem *mem;
	size_t remaining;
	u32 f_ctl = FC_FC_EX_CTX | FC_FC_REL_OFF;
	u32 mem_off;
	u32 fh_off = 0;
	u32 frame_off = 0;
	size_t frame_len = 0;
	size_t mem_len;
	size_t tlen;
	struct page *page;
	int use_sg;
	int error;
	void *from;
	void *to = NULL;

	ep = fc_seq_exch(cmd->seq);
	lport = ep->lp;
	cmd->seq = lport->tt.seq_start_next(cmd->seq);

	task = T_TASK(se_cmd);
	BUG_ON(!task);
	remaining = se_cmd->data_length;

	/*
	 * Setup to use first mem list entry if any.
	 */
	if (task->t_task_se_num) {
		mem = list_first_entry(task->t_mem_list,
			 struct se_mem, se_list);
		mem_len = mem->se_len;
		mem_off = mem->se_off;
		page = mem->se_page;
	} else {
		mem = NULL;
		mem_len = remaining;
		mem_off = 0;
		page = NULL;
	}

	/* no scatter/gather in skb for odd word length due to fc_seq_send() */
	use_sg = !(remaining % 4);
	use_sg = 0;	/* XXX to test the non-sg path */

	while (remaining) {
		if (!mem_len) {
			BUG_ON(!mem);
			mem = list_entry(mem->se_list.next,
				struct se_mem, se_list);
			mem_len = min((size_t)mem->se_len, remaining);
			mem_off = mem->se_off;
			page = mem->se_page;
		}
		if (!frame_len) {
			frame_len = cmd->sess->max_frame;
			frame_len = min(frame_len, remaining);
			fp = fc_frame_alloc(lport, use_sg ? 0 : frame_len);
			if (!fp)
				return -ENOMEM;
			to = fc_frame_payload_get(fp, 0);
			fh_off = frame_off;
			frame_off += frame_len;
		}
		tlen = min(mem_len, frame_len);

		if (use_sg) {
			if (!mem)
				page = virt_to_page(task->t_task_buf + mem_off);
			get_page(page);
			skb_fill_page_desc(fp_skb(fp),
					   skb_shinfo(fp_skb(fp))->nr_frags,
					   page, mem_off, tlen);
			fr_len(fp) += tlen;
			fp_skb(fp)->data_len += tlen;
			fp_skb(fp)->truesize +=
					PAGE_SIZE << compound_order(page);
		} else if (mem) {
			BUG_ON(!page);
			from = kmap_atomic(page + (mem_off >> PAGE_SHIFT),
					   KM_SOFTIRQ0);
			WARN_ON(!from);
			if (!from)
				break;	/* XXX for now initiator will retry */
			from += mem_off & ~PAGE_MASK;
			tlen = min(tlen, PAGE_SIZE - (mem_off & ~PAGE_MASK));
			memcpy(to, from, tlen);
			kunmap_atomic(page + (mem_off >> PAGE_SHIFT),
				      KM_SOFTIRQ0);
			to += tlen;
		} else {
			from = task->t_task_buf + mem_off;
			memcpy(to, from, tlen);
			to += tlen;
		}

		mem_off += tlen;
		mem_len -= tlen;
		frame_len -= tlen;
		remaining -= tlen;

		if (frame_len)
			continue;
		if (!remaining)
			f_ctl |= FC_FC_END_SEQ;
		fc_fill_fc_hdr(fp, FC_RCTL_DD_SOL_DATA, ep->did, ep->sid,
			       FC_TYPE_FCP, f_ctl, fh_off);
		error = lport->tt.seq_send(lport, cmd->seq, fp);
		if (error) {
			WARN_ON(1);
			/* XXX For now, initiator will retry */
		}
	}
	return ft_queue_status(se_cmd);
}

/*
 * Receive write data frame.
 */
void ft_recv_write_data(struct ft_cmd *cmd, struct fc_frame *fp)
{
	struct se_cmd *se_cmd = cmd->se_cmd;
	struct se_transport_task *task;
	struct fc_frame_header *fh;
	struct se_mem *mem;
	u32 mem_off;
	u32 rel_off;
	size_t frame_len;
	size_t mem_len;
	size_t tlen;
	struct page *page;
	void *from;
	void *to;

	task = T_TASK(se_cmd);
	BUG_ON(!task);

	fh = fc_frame_header_get(fp);
	if (!(ntoh24(fh->fh_f_ctl) & FC_FC_REL_OFF))
		goto drop;
	rel_off = ntohl(fh->fh_parm_offset);
	frame_len = fr_len(fp);
	if (frame_len <= sizeof(*fh))
		goto drop;
	frame_len -= sizeof(*fh);
	from = fc_frame_payload_get(fp, 0);
	if (rel_off >= se_cmd->data_length)
		goto drop;
	if (frame_len + rel_off > se_cmd->data_length)
		frame_len = se_cmd->data_length - rel_off;

	/*
	 * Setup to use first mem list entry if any.
	 */
	if (task->t_task_se_num) {
		mem = list_first_entry(task->t_mem_list,
				       struct se_mem, se_list);
		mem_len = mem->se_len;
		mem_off = mem->se_off;
		page = mem->se_page;
	} else {
		mem = NULL;
		page = NULL;
		mem_off = 0;
		mem_len = frame_len;
	}

	while (frame_len) {
		if (!mem_len) {
			BUG_ON(!mem);
			mem = list_entry(mem->se_list.next,
					 struct se_mem, se_list);
			mem_len = mem->se_len;
			mem_off = mem->se_off;
			page = mem->se_page;
		}
		if (rel_off >= mem_len) {
			rel_off -= mem_len;
			mem_len = 0;
			continue;
		}
		mem_off += rel_off;
		mem_len -= rel_off;
		rel_off = 0;

		tlen = min(mem_len, frame_len);

		if (mem) {
			to = kmap_atomic(page + (mem_off >> PAGE_SHIFT),
					 KM_SOFTIRQ0);
			if (!to)
				break;
			to += mem_off & ~PAGE_MASK;
			tlen = min(tlen, PAGE_SIZE - (mem_off & ~PAGE_MASK));
			memcpy(to, from, tlen);
			kunmap_atomic(page + (mem_off >> PAGE_SHIFT),
				      KM_SOFTIRQ0);
		} else {
			to = task->t_task_buf + mem_off;
			memcpy(to, from, tlen);
		}
		from += tlen;
		frame_len -= tlen;
		mem_off += tlen;
		mem_len -= tlen;
		cmd->write_data_len += tlen;
	}
	if (cmd->write_data_len == se_cmd->data_length)
		transport_generic_handle_data(se_cmd);
drop:
	fc_frame_free(fp);
}
