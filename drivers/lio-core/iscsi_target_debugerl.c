/*********************************************************************************
 * Filename:  iscsi_target_debugerl.c
 *
 * This file contains error injection functions used by the iSCSI Target driver.
 *
 * Copyright (c) 2003 PyX Technologies, Inc.
 * Copyright (c) 2006 SBE, Inc.  All Rights Reserved.
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


#define ISCSI_TARGET_DEBUGERL_C

#include <linux/delay.h>
#include <linux/string.h>
#include <linux/timer.h>
#include <linux/slab.h>
#include <linux/init.h>
#include <linux/spinlock.h>
#include <linux/smp_lock.h>
#include <linux/in.h>

#include <iscsi_linux_os.h>
#include <iscsi_linux_defs.h>

#include <iscsi_protocol.h>
#include <iscsi_debug.h>
#include <iscsi_target_core.h>
#include <iscsi_target_util.h>
#include <iscsi_target_debugerl.h>

#undef ISCSI_TARGET_DEBUGERL_C

extern iscsi_global_t *iscsi_global;

/*	iscsi_target_check_debug_erl():
 *
 *	
 */
static int iscsi_target_check_debug_erl (iscsi_conn_t *conn, __u8 debug_type)
{
	spin_lock(&iscsi_global->debug_erl_lock);
	if (ISCSI_DEBUG_ERL(iscsi_global)->debug_erl &&
	   (ISCSI_DEBUG_ERL(iscsi_global)->tpgt == ISCSI_TPG_C(conn)->tpgt) &&
	   (ISCSI_DEBUG_ERL(iscsi_global)->sid == SESS(conn)->sid) &&
	   (ISCSI_DEBUG_ERL(iscsi_global)->debug_type == debug_type)) {
		spin_unlock(&iscsi_global->debug_erl_lock);
		return(1);
	}
	spin_unlock(&iscsi_global->debug_erl_lock);
	return(0);
}

/*	iscsi_target_debugerl_tx_thread():
 *
 *
 */
extern int iscsi_target_debugerl_tx_thread (iscsi_conn_t *conn)
{
	if (iscsi_target_check_debug_erl(conn, TARGET_ERL_FORCE_TX_TRANSPORT_RESET)) {
		spin_lock(&iscsi_global->debug_erl_lock);
		if (conn->cid != ISCSI_DEBUG_ERL(iscsi_global)->cid) {
			spin_unlock(&iscsi_global->debug_erl_lock);
			return(0);
		}

		memset(ISCSI_DEBUG_ERL(iscsi_global), 0, sizeof(iscsi_debug_erl_t));
		spin_unlock(&iscsi_global->debug_erl_lock);
		PYXPRINT("TARGET_ERL_FORCE_TX_TRANSPORT_RESET: CID: %hu.\n", conn->cid);
		return(-1);
	}

	return(0);
}

/*	iscsi_target_debugerl_rx_thread0():
 *
 *
 */
extern int iscsi_target_debugerl_rx_thread0 (iscsi_conn_t *conn)
{
	if (iscsi_target_check_debug_erl(conn, TARGET_ERL_FORCE_RX_TRANSPORT_RESET)) {
		spin_lock(&iscsi_global->debug_erl_lock);
		if (conn->cid != ISCSI_DEBUG_ERL(iscsi_global)->cid) {
			spin_unlock(&iscsi_global->debug_erl_lock);
			return(0);
		}

		memset(ISCSI_DEBUG_ERL(iscsi_global), 0, sizeof(iscsi_debug_erl_t));
		spin_unlock(&iscsi_global->debug_erl_lock);
		PYXPRINT("TARGET_ERL_FORCE_RX_TRANSPORT_RESET: CID: %hu.\n", conn->cid);
		return(-1);
	}

	return(0);
}

/*	iscsi_target_debugerl_rx_thread1():
 *
 *
 */
extern int iscsi_target_debugerl_rx_thread1 (iscsi_conn_t *conn)
{
	if (iscsi_target_check_debug_erl(conn, TARGET_ERL_HEADER_CRC_FAILURE)) {
		spin_lock(&iscsi_global->debug_erl_lock);
		memset(ISCSI_DEBUG_ERL(iscsi_global), 0, sizeof(iscsi_debug_erl_t));
		spin_unlock(&iscsi_global->debug_erl_lock);
		PYXPRINT("TARGET_ERL_HEADER_CRC_FAILURE: CID: %hu.\n", conn->cid);
		return(-1);
	}

	return(0);
}

/*	iscsi_target_debugerl_data_out_0():
 *
 *
 */
extern int iscsi_target_debugerl_data_out_0 (iscsi_conn_t *conn, unsigned char *buf)
{
	struct iscsi_init_scsi_data_out *hdr = (struct iscsi_init_scsi_data_out *) buf;

	if (iscsi_target_check_debug_erl(conn, TARGET_ERL_DATA_OUT_CRC_FAILURE)) {
		spin_lock(&iscsi_global->debug_erl_lock);
		if (hdr->offset != ISCSI_DEBUG_ERL(iscsi_global)->count) {
			spin_unlock(&iscsi_global->debug_erl_lock);
			return(0);
		}
		memset(ISCSI_DEBUG_ERL(iscsi_global), 0, sizeof(iscsi_debug_erl_t));
		spin_unlock(&iscsi_global->debug_erl_lock);
		PYXPRINT("TARGET_ERL_DATA_OUT_CRC_FAILURE: ITT: 0x%08x, DataSN: 0x%08x,"
			" Offset: %u\n", hdr->init_task_tag, hdr->data_sn, hdr->offset);
		return(-1);
	}

	if (iscsi_target_check_debug_erl(conn, TARGET_ERL_DATA_OUT_CRC_FAILURE_BATCH)) {
		spin_lock(&iscsi_global->debug_erl_lock);
		if (!ISCSI_DEBUG_ERL(iscsi_global)->state) {
			ISCSI_DEBUG_ERL(iscsi_global)->counter = 1;
			ISCSI_DEBUG_ERL(iscsi_global)->state = 1;
			ISCSI_DEBUG_ERL(iscsi_global)->init_task_tag = hdr->init_task_tag;
			spin_unlock(&iscsi_global->debug_erl_lock);
			PYXPRINT("TARGET_ERL_DATA_OUT_CRC_FAILURE_BATCH: STATE: 0, ITT: 0x%08x,"
				" DataSN: 0x%08x, Offset %u\n", hdr->init_task_tag,
					hdr->data_sn, hdr->offset);
			return(-1);
		} else if (ISCSI_DEBUG_ERL(iscsi_global)->state == 1) {
			if (ISCSI_DEBUG_ERL(iscsi_global)->init_task_tag != hdr->init_task_tag) {
				spin_unlock(&iscsi_global->debug_erl_lock);
				return(0);
			}
			if (ISCSI_DEBUG_ERL(iscsi_global)->counter <
			    ISCSI_DEBUG_ERL(iscsi_global)->count) {
				ISCSI_DEBUG_ERL(iscsi_global)->counter++;
				spin_unlock(&iscsi_global->debug_erl_lock);
				PYXPRINT("TARGET_ERL_DATA_OUT_CRC_FAILURE_BATCH: STATE: 1, ITT:"
					" 0x%08x, DataSN: 0x%08x, Offset %u\n", hdr->init_task_tag,
						hdr->data_sn, hdr->offset);
				return(-1);
			} else {
				memset(ISCSI_DEBUG_ERL(iscsi_global), 0, sizeof(iscsi_debug_erl_t));
				spin_unlock(&iscsi_global->debug_erl_lock);
				return(0);
			}
		}
		spin_unlock(&iscsi_global->debug_erl_lock);
		return(0);
	}
	
	if (iscsi_target_check_debug_erl(conn, TARGET_ERL_DATA_OUT_CRC_FAILURE_MIX)) {
		spin_lock(&iscsi_global->debug_erl_lock);
		if (!ISCSI_DEBUG_ERL(iscsi_global)->state) {
			ISCSI_DEBUG_ERL(iscsi_global)->counter = 1;
			ISCSI_DEBUG_ERL(iscsi_global)->state = 1;
			ISCSI_DEBUG_ERL(iscsi_global)->init_task_tag = hdr->init_task_tag;
			spin_unlock(&iscsi_global->debug_erl_lock);
			PYXPRINT("TARGET_ERL_DATA_OUT_CRC_FAILURE_MIX: STATE: 0, ITT: 0x%08x, DataSN:"
				" 0x%08x, Offset %u\n", hdr->init_task_tag, hdr->data_sn, hdr->offset);
			return(-1);
		} else if (ISCSI_DEBUG_ERL(iscsi_global)->state == 1) {
			if (ISCSI_DEBUG_ERL(iscsi_global)->init_task_tag != hdr->init_task_tag) {
				spin_unlock(&iscsi_global->debug_erl_lock);
				return(0);
			}
			if (ISCSI_DEBUG_ERL(iscsi_global)->counter < ISCSI_DEBUG_ERL(iscsi_global)->count) {
				ISCSI_DEBUG_ERL(iscsi_global)->counter++;
				spin_unlock(&iscsi_global->debug_erl_lock);
				return(0);
			} else {
				memset(ISCSI_DEBUG_ERL(iscsi_global), 0, sizeof(iscsi_debug_erl_t));
				spin_unlock(&iscsi_global->debug_erl_lock);
				PYXPRINT("TARGET_ERL_DATA_OUT_CRC_FAILURE_MIX: STATE: 1, ITT: 0x%08x,"
					" DataSN: 0x%08x, Offset %u\n", hdr->init_task_tag,
						hdr->data_sn, hdr->offset);
				return(-1);
			}
		}
		spin_unlock(&iscsi_global->debug_erl_lock);
		return(0);
	}
			
	if (iscsi_target_check_debug_erl(conn, TARGET_ERL_DATA_OUT_CRC_FAILURE_MULTI)) {
		spin_lock(&iscsi_global->debug_erl_lock);
		if (!ISCSI_DEBUG_ERL(iscsi_global)->state) {
			ISCSI_DEBUG_ERL(iscsi_global)->counter = 1;
			ISCSI_DEBUG_ERL(iscsi_global)->state = 1;
			ISCSI_DEBUG_ERL(iscsi_global)->data_offset = hdr->offset;
			ISCSI_DEBUG_ERL(iscsi_global)->init_task_tag = hdr->init_task_tag;
			spin_unlock(&iscsi_global->debug_erl_lock);
			PYXPRINT("TARGET_ERL_DATA_OUT_CRC_FAILURE_MULTI: STATE: 0, ITT: 0x%08x,"
				" DataSN: 0x%08x, Offset %u\n", hdr->init_task_tag,
					hdr->data_sn, hdr->offset);
			return(-1);
		} else if (ISCSI_DEBUG_ERL(iscsi_global)->state == 1) {
			if (ISCSI_DEBUG_ERL(iscsi_global)->init_task_tag != hdr->init_task_tag) {
				spin_unlock(&iscsi_global->debug_erl_lock);
				return(0);
			}
			if (ISCSI_DEBUG_ERL(iscsi_global)->data_offset != hdr->offset) {
				spin_unlock(&iscsi_global->debug_erl_lock);
				return(0);
			}
			if (ISCSI_DEBUG_ERL(iscsi_global)->counter <
			    ISCSI_DEBUG_ERL(iscsi_global)->count) {		
				ISCSI_DEBUG_ERL(iscsi_global)->counter++;
				spin_unlock(&iscsi_global->debug_erl_lock);
				PYXPRINT("TARGET_ERL_DATA_OUT_CRC_FAILURE_MULTI: STATE: 1 ITT: 0x%08x,"
					" DataSN: 0x%08x, Offset %u\n", hdr->init_task_tag,
						hdr->data_sn, hdr->offset);
				return(-1);
			} else {
				memset(ISCSI_DEBUG_ERL(iscsi_global), 0, sizeof(iscsi_debug_erl_t));
				spin_unlock(&iscsi_global->debug_erl_lock);
				PYXPRINT("TARGET_ERL_DATA_OUT_CRC_FAILURE_MULTI: STATE: 2 ITT: 0x%08x,"
					" DataSN: 0x%08x, Offset %u\n", hdr->init_task_tag,
						hdr->data_sn, hdr->offset);
				return(0);
			}
		}
		spin_unlock(&iscsi_global->debug_erl_lock);
		return(0);
	}	
			
	return(0);
}

/*	iscsi_target_debugerl_data_out_1():
 *
 *
 */
extern int iscsi_target_debugerl_data_out_1 (iscsi_conn_t *conn, unsigned char *buf)
{
	struct iscsi_init_scsi_data_out *hdr = (struct iscsi_init_scsi_data_out *) buf;
	
	if (iscsi_target_check_debug_erl(conn, TARGET_ERL_DATA_OUT_TIMEOUT)) {
		spin_lock(&iscsi_global->debug_erl_lock);
		if (!ISCSI_DEBUG_ERL(iscsi_global)->state) {
			if (ISCSI_DEBUG_ERL(iscsi_global)->count != hdr->offset) {
				spin_unlock(&iscsi_global->debug_erl_lock);
				return(0);
			}

			ISCSI_DEBUG_ERL(iscsi_global)->state = 1;
			ISCSI_DEBUG_ERL(iscsi_global)->data_offset = hdr->offset;
			ISCSI_DEBUG_ERL(iscsi_global)->init_task_tag = hdr->init_task_tag;
			spin_unlock(&iscsi_global->debug_erl_lock);
			PYXPRINT("TARGET_ERL_DATA_OUT_TIMEOUT: ITT: 0x%08x, STATE: 0, DataSN:"
				" 0x%08x, Offset: %d\n", hdr->init_task_tag, hdr->data_sn, hdr->offset);
			return(-1);
		} else if (ISCSI_DEBUG_ERL(iscsi_global)->state == 1) {
			if (ISCSI_DEBUG_ERL(iscsi_global)->init_task_tag != hdr->init_task_tag) {
				spin_unlock(&iscsi_global->debug_erl_lock);
				return(0);
			}
#if 0
			if (ISCSI_DEBUG_ERL(iscsi_global)->data_offset != hdr->offset) {
				spin_unlock(&iscsi_global->debug_erl_lock);
				PYXPRINT("TARGET_ERL_DATA_OUT_TIMEOUT: ITT: 0x%08x, STATE: 1,"
					" DataSN: 0x%08x, Offset: %d\n", hdr->init_task_tag,
						hdr->data_sn, hdr->offset);
				return(-1);
			}
#endif
			memset(ISCSI_DEBUG_ERL(iscsi_global), 0, sizeof(iscsi_debug_erl_t));
			spin_unlock(&iscsi_global->debug_erl_lock);
			PYXPRINT("TARGET_ERL_DATA_OUT_TIMEOUT: ITT: 0x%08x, STATE: 1, DataSN:"
				" 0x%08x, Offset: %d\n", hdr->init_task_tag, hdr->data_sn, hdr->offset);
			return(0);
		}
		spin_unlock(&iscsi_global->debug_erl_lock);
		return(0);
	}

	if (iscsi_target_check_debug_erl(conn, TARGET_ERL_DATA_OUT_FAIL)) {
		spin_lock(&iscsi_global->debug_erl_lock);
		if (ISCSI_DEBUG_ERL(iscsi_global)->count != hdr->offset) {
			spin_unlock(&iscsi_global->debug_erl_lock);
			return(0);
		}
		memset(ISCSI_DEBUG_ERL(iscsi_global), 0, sizeof (iscsi_debug_erl_t));
		spin_unlock(&iscsi_global->debug_erl_lock);
		PYXPRINT("TARGET_ERL_DATA_OUT_FAIL: 0x%08x, DataSN: 0x%08x\n",
				hdr->init_task_tag, hdr->data_sn);
		return(-2);
	}
	
	return(0);
}

/*	iscsi_target_debugerl_immeidate_data():
 *
 *
 */
extern int iscsi_target_debugerl_immeidate_data (iscsi_conn_t *conn, __u32 init_task_tag)
{
	if (iscsi_target_check_debug_erl(conn, TARGET_ERL_IMMEDIATE_DATA_CRC_FAILURE)) {
		spin_lock(&iscsi_global->debug_erl_lock);
		memset(ISCSI_DEBUG_ERL(iscsi_global), 0, sizeof (iscsi_debug_erl_t));
		spin_unlock(&iscsi_global->debug_erl_lock);
		PYXPRINT("TARGET_ERL_IMMEDIATE_DATA_CRC_FAILURE: ITT: 0x%08x.\n", init_task_tag);
		return(-1);
	}

	return(0);
}

/*	iscsi_target_debugerl_cmdsn():
 *
 *
 */
extern int iscsi_target_debugerl_cmdsn (iscsi_conn_t *conn, __u32 cmdsn)
{
	if (iscsi_target_check_debug_erl(conn, TARGET_ERL_MISSING_CMD_SN)) {
		spin_lock(&iscsi_global->debug_erl_lock);
		memset(ISCSI_DEBUG_ERL(iscsi_global), 0, sizeof(iscsi_debug_erl_t));
		spin_unlock(&iscsi_global->debug_erl_lock);
		PYXPRINT("TARGET_ERL_MISSING_CMD_SN: CmdSN: 0x%08x.\n", cmdsn);
		return(-1);
	}

	if (iscsi_target_check_debug_erl(conn, TARGET_ERL_MISSING_CMDSN_BATCH)) {
		spin_lock(&iscsi_global->debug_erl_lock);
		if (!ISCSI_DEBUG_ERL(iscsi_global)->state) {
			ISCSI_DEBUG_ERL(iscsi_global)->counter = 1;
			ISCSI_DEBUG_ERL(iscsi_global)->state = 1;
			ISCSI_DEBUG_ERL(iscsi_global)->cmd_sn = cmdsn;
			spin_unlock(&iscsi_global->debug_erl_lock);
			PYXPRINT("TARGET_ERL_MISSING_CMDSN_BATCH: CmdSN: 0x%08x, STATE: 0.\n", cmdsn);
			return(-1);
		} else if (ISCSI_DEBUG_ERL(iscsi_global)->state == 1) {
			if (ISCSI_DEBUG_ERL(iscsi_global)->counter < ISCSI_DEBUG_ERL(iscsi_global)->count) {
				ISCSI_DEBUG_ERL(iscsi_global)->counter++;
				spin_unlock(&iscsi_global->debug_erl_lock);
				PYXPRINT("TARGET_ERL_MISSING_CMDSN_BATCH: CmdSN: 0x%08x, STATE: 1.\n", cmdsn);
				return(-1);
			} else {
				memset(ISCSI_DEBUG_ERL(iscsi_global), 0, sizeof(iscsi_debug_erl_t));
				PYXPRINT("TARGET_ERL_MISSING_CMDSN_BATCH: CmdSN: 0x%08x, STATE: 2.\n", cmdsn);
				spin_unlock(&iscsi_global->debug_erl_lock);
				return(0);
			}
		}
		spin_unlock(&iscsi_global->debug_erl_lock);
		return(0);
	}

	if (iscsi_target_check_debug_erl(conn, TARGET_ERL_MISSING_CMDSN_MIX)) {
		spin_lock(&iscsi_global->debug_erl_lock);
		if (!ISCSI_DEBUG_ERL(iscsi_global)->state) {
			ISCSI_DEBUG_ERL(iscsi_global)->counter = 1;
			ISCSI_DEBUG_ERL(iscsi_global)->state = 1;
			ISCSI_DEBUG_ERL(iscsi_global)->cmd_sn = cmdsn;
			spin_unlock(&iscsi_global->debug_erl_lock);
			PYXPRINT("TARGET_ERL_MISSING_CMDSN_MIX: CmdSN: 0x%08x, STATE: 0.\n", cmdsn);
			return(-1);
		} else if (ISCSI_DEBUG_ERL(iscsi_global)->state == 1) {
			if (ISCSI_DEBUG_ERL(iscsi_global)->counter < ISCSI_DEBUG_ERL(iscsi_global)->count) {
				ISCSI_DEBUG_ERL(iscsi_global)->counter++;
				spin_unlock(&iscsi_global->debug_erl_lock);
				return(0);
			} else {
				memset(ISCSI_DEBUG_ERL(iscsi_global), 0, sizeof(iscsi_debug_erl_t));
				spin_unlock(&iscsi_global->debug_erl_lock);
				PYXPRINT("TARGET_ERL_MISSING_CMDSN_MIX: CmdSN: 0x%08x, STATE: 1.\n", cmdsn);
				return(-1);
			}
		}
		spin_unlock(&iscsi_global->debug_erl_lock);
		return(0);
	}
			
	if (iscsi_target_check_debug_erl(conn, TARGET_ERL_MISSING_CMDSN_MULTI)) {
		spin_lock(&iscsi_global->debug_erl_lock);
		if (!ISCSI_DEBUG_ERL(iscsi_global)->state) {
			ISCSI_DEBUG_ERL(iscsi_global)->counter = 1;
			ISCSI_DEBUG_ERL(iscsi_global)->state = 1;
			ISCSI_DEBUG_ERL(iscsi_global)->cmd_sn = cmdsn;
			spin_unlock(&iscsi_global->debug_erl_lock);
			PYXPRINT("TARGET_ERL_MISSING_CMDSN_MULTI: CmdSN: 0x%08x, STATE: 0.\n", cmdsn);
			return(-1);
		} else if (ISCSI_DEBUG_ERL(iscsi_global)->state == 1) {
			if (ISCSI_DEBUG_ERL(iscsi_global)->cmd_sn != cmdsn) {
				spin_unlock(&iscsi_global->debug_erl_lock);
				return(0);
			}
			if (ISCSI_DEBUG_ERL(iscsi_global)->counter < ISCSI_DEBUG_ERL(iscsi_global)->count) {
				ISCSI_DEBUG_ERL(iscsi_global)->counter++;
				spin_unlock(&iscsi_global->debug_erl_lock);
				PYXPRINT("TARGET_ERL_MISSING_CMDSN_MULTI: CmdSN: 0x%08x, STATE: 1.\n", cmdsn);
				return(-1);
			} else {
				memset(ISCSI_DEBUG_ERL(iscsi_global), 0, sizeof(iscsi_debug_erl_t));
				spin_unlock(&iscsi_global->debug_erl_lock);
				PYXPRINT("TARGET_ERL_MISSING_CMDSN_MULTI: CmdSN: 0x%08x, STATE: 2.\n", cmdsn);
				return(0);
			}
		}
		spin_unlock(&iscsi_global->debug_erl_lock);
		return(0);
	}
			
	return(0);
}
