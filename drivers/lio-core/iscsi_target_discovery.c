/*********************************************************************************
 * Filename:  iscsi_target_discovery.c
 *
 * This file contains iSCSI Target discovery specific functions.
 * 
 * Copyright (c) 2002, 2003, 2004, 2005 PyX Technologies, Inc.
 * Copyright (c) 2005, 2006, 2007 SBE, Inc. 
 * Copyright (c) 2007 Rising Tide Software, Inc.
 *
 * Nicholas A. Bellinger <nab@kernel.org>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 *
 *********************************************************************************/


#define ISCSI_TARGET_DISCOVERY_C

#include <linux/delay.h>
#include <linux/string.h>
#include <linux/timer.h>
#include <linux/slab.h>
#include <linux/spinlock.h>

#include <iscsi_linux_os.h>
#include <iscsi_linux_defs.h>

#include <iscsi_protocol.h>
#include <iscsi_target_core.h>
#include <iscsi_debug.h>
#include <iscsi_target_discovery.h>

#undef ISCSI_TARGET_DISCOVERY_C

extern iscsi_global_t *iscsi_global;
extern void iscsi_ntoa2 (unsigned char *, __u32);

/*	iscsi_build_sendtargets_response():
 *
 *
 */
extern int iscsi_build_sendtargets_response (iscsi_cmd_t *cmd)
{
	char *ip, *ip_ex, *payload = NULL;
	iscsi_conn_t *conn = CONN(cmd);
	iscsi_np_ex_t *np_ex;
	iscsi_portal_group_t *tpg;
	iscsi_tiqn_t *tiqn;
	iscsi_tpg_np_t *tpg_np;
	int i, buffer_len, end_of_buf = 0, len = 0, payload_len = 0;
	unsigned char buf[256];
	unsigned char buf_ipv4[IPV4_BUF_SIZE];

	TRACE_ENTER

	buffer_len = (CONN_OPS(conn)->MaxRecvDataSegmentLength > 32768) ?
			32768 : CONN_OPS(conn)->MaxRecvDataSegmentLength;

	if (!(payload = (char *) kmalloc(buffer_len, GFP_KERNEL))) {
		TRACE_ERROR("Unable to allocate memory for sendtargets"
			" response.\n");
		return(-1);
	}
	memset((void *)payload, 0, buffer_len);
	
	spin_lock(&iscsi_global->tiqn_lock);
	list_for_each_entry(tiqn, &iscsi_global->g_tiqn_list, tiqn_list) {
		memset((void *)buf, 0, 256);

		len = sprintf(buf, "TargetName=%s", tiqn->tiqn);
		len += 1;

		if ((len + payload_len) > buffer_len) {
			spin_unlock(&tiqn->tiqn_tpg_lock);
			end_of_buf = 1;
			goto eob;
		}
		memcpy((void *)payload + payload_len, buf, len);
		payload_len += len;

		spin_lock(&tiqn->tiqn_tpg_lock);
		for (i = 0; i < ISCSI_MAX_TPGS; i++) {
			tpg = &tiqn->tiqn_tpg_list[i];

			spin_lock(&tpg->tpg_state_lock);
			if ((tpg->tpg_state == TPG_STATE_FREE) ||
			    (tpg->tpg_state == TPG_STATE_INACTIVE)) {
				spin_unlock(&tpg->tpg_state_lock);
				continue;
			}
			spin_unlock(&tpg->tpg_state_lock);

			spin_lock(&tpg->tpg_np_lock);
			list_for_each_entry(tpg_np, &tpg->tpg_gnp_list, tpg_np_list) {
				memset((void *)buf, 0, 256);

				if (tpg_np->tpg_np->np_flags & NPF_NET_IPV6)
					ip = &tpg_np->tpg_np->np_ipv6[0];
				else {
					memset(buf_ipv4, 0, IPV4_BUF_SIZE);
					iscsi_ntoa2(buf_ipv4, tpg_np->tpg_np->np_ipv4);
					ip = &buf_ipv4[0];
				}

				len = sprintf(buf, "TargetAddress=%s%s%s:%hu,%hu\n",
					(tpg_np->tpg_np->np_flags & NPF_NET_IPV6) ?
					"[" : "", ip, (tpg_np->tpg_np->np_flags & NPF_NET_IPV6) ?
					"]" : "", tpg_np->tpg_np->np_port, tpg->tpgt);
				len += 1;

				if ((len + payload_len) > buffer_len) {
					spin_unlock(&tpg->tpg_np_lock);
					spin_unlock(&tiqn->tiqn_tpg_lock);
					end_of_buf = 1;
					goto eob;
				}

				memcpy((void *)payload + payload_len, buf, len);
				payload_len += len;

				spin_lock(&tpg_np->tpg_np->np_ex_lock);
				list_for_each_entry(np_ex, &tpg_np->tpg_np->np_nex_list, np_ex_list) {
					if (tpg_np->tpg_np->np_flags & NPF_NET_IPV6)
						ip_ex = &np_ex->np_ex_ipv6[0];
					else {
						memset(buf_ipv4, 0, IPV4_BUF_SIZE);
						iscsi_ntoa2(buf_ipv4, np_ex->np_ex_ipv4);
						ip_ex = &buf_ipv4[0];
					}
					len = sprintf(buf, "TargetAddress=%s%s%s:%hu,%hu",
						(tpg_np->tpg_np->np_flags & NPF_NET_IPV6) ?
						"[" : "", ip_ex, (tpg_np->tpg_np->np_flags & NPF_NET_IPV6) ?
						"]" : "", np_ex->np_ex_port, tpg->tpgt);
					len += 1;

					if ((len + payload_len) > buffer_len) {
						spin_unlock(&tpg_np->tpg_np->np_ex_lock);
						spin_unlock(&tpg->tpg_np_lock);
						spin_unlock(&tiqn->tiqn_tpg_lock);
						end_of_buf = 1;
						goto eob;
					}
					
					memcpy((void *)payload + payload_len, buf, len);
					payload_len += len;
				}
				spin_unlock(&tpg_np->tpg_np->np_ex_lock);
			}
			spin_unlock(&tpg->tpg_np_lock);
		}
		spin_unlock(&tiqn->tiqn_tpg_lock);
eob:
		if (end_of_buf)
			break;
	}
	spin_unlock(&iscsi_global->tiqn_lock);

	cmd->buf_ptr = payload;

	TRACE_LEAVE
	return(payload_len);
}
