/*********************************************************************************
 * Filename:  iscsi_debug_opcodes.c
 *
 * This file contains the iSCSI protocol debugging methods.
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


#ifdef LINUX
#include <linux/string.h>
#include <linux/timer.h>
#include <linux/slab.h>

#include <iscsi_linux_os.h>
#endif /* LINUX */

#define __ISCSI_DEBUG_OPCODES_C
#include <iscsi_debug.h>
#include <iscsi_protocol.h>
#include <iscsi_debug_opcodes.h>

void print_status_class_and_detail(u8 status_class, u8 status_detail)
{
	PYXPRINT("Status-Class: ");
	switch (status_class) {
	case STAT_CLASS_SUCCESS:
		PYXPRINT("Success, ");
		PYXPRINT("Status-Detail: ");
		switch (status_detail) {
			case STAT_DETAIL_SUCCESS:
				PYXPRINT("Login is prcedding OK.\n");
				break;
			default:
				PYXPRINT("ERROR Unknown Status-Detail!\n");
				break;
		}
		break;
	case STAT_CLASS_REDIRECTION:
		PYXPRINT("Redirection, ");
		PYXPRINT("Status-Detail: ");
		switch (status_detail) {
			case STAT_DETAIL_TARG_MOVED_TEMP:
				PYXPRINT("The requested iSCSI Target Name"
				" has temporarily moved to the address"
					" provided.\n");
				break;
			case STAT_DETAIL_TARG_MOVED_PERM:
				PYXPRINT("The requested iSCSI Target Name"
				" permanently moved to the address"
					" provided.\n");
				break;
			default:
				PYXPRINT("ERROR Unknown Status-Detail!\n");
				break;
		}
		break;
	case STAT_CLASS_INITIATOR:
		PYXPRINT("Initiator Error, ");
		PYXPRINT("Status-Detail: ");
		switch (status_detail) {
			case STAT_DETAIL_INIT_ERROR:
				PYXPRINT("Miscellaneous iSCSI Initiator"
						" errors.\n");
				break;
			case STAT_DETAIL_NOT_AUTH:
				PYXPRINT("The initiator could not be"
				" successfully authenticated or target"
				" authentication is not supported.\n");
				break;
			case STAT_DETAIL_NOT_ALLOWED:
				PYXPRINT("The initiator is not allowed"
				" access to the given target.\n");
				break;
			case STAT_DETAIL_NOT_FOUND:
				PYXPRINT("The requested iSCSI Target Name"
				" does not exist at this address.\n");
				break;
			case STAT_DETAIL_TARG_REMOVED:
				PYXPRINT("The requested iSCSI Target Name"
				" has been removed and no forwarding"
				" address is provided.\n");
				break;
			case STAT_DETAIL_VERSION_NOT_SUPPORTED:
				PYXPRINT("The requested iSCSI version range"
				" is not supported by the target.\n");
				break;
			case STAT_DETAIL_TOO_MANY_CONNECTIONS:
				PYXPRINT("Too many connections on this SSID.\n");
				break;
			case STAT_DETAIL_MISSING_PARAMETER:
				PYXPRINT("Missing parameters (e.g., iSCSI"
				" Initiator and/or Target Name).\n");
				break;
			case STAT_DETAIL_NOT_INCLUDED:
				PYXPRINT("Target does not support session"
				" spanning to this connection (address).\n");
				break;
			case STAT_DETAIL_SESSION_TYPE:
				PYXPRINT("Target does not support this type"
				" of session or not from this Initiator.\n");
			case STAT_DETAIL_SESSION_DOES_NOT_EXIST:
				PYXPRINT("Attempt to add a connections to a"
				" non-existent session.\n");
				break;
			case STAT_DETAIL_INVALID_DURING_LOGIN:
				PYXPRINT("Invalid Request type during Login.\n");
				break;
			default:
				PYXPRINT("ERROR Unknown Status-Detail!\n");
				break;
		}
		break;
	case STAT_CLASS_TARGET:
		PYXPRINT("Target Error, ");
		PYXPRINT("Status-Detail: ");
		switch(status_detail) {
			case STAT_DETAIL_TARG_ERROR:
				PYXPRINT("Target hardware or software error.\n");
				break;
			case STAT_DETAIL_SERVICE_UNAVAILABLE:
				PYXPRINT("The iSCSI server or target is not"
				" currently operational.\n");
				break;
			case STAT_DETAIL_OUT_OF_RESOURCE:
				PYXPRINT("The target has insufficient session,"
				" connection, or other resources.\n");
				break;
			default:
				PYXPRINT("ERROR Unknown Status-Detail!\n");
				break;
		}
		break;
	default:
		PYXPRINT("ERROR: Unknown Login Status Class\n");
		break;
	}
}

void print_reject_reason(u8 reason)
{
	printk("Reject Reason: ");
	switch (reason) {
	case REASON_FULL_BEFORE_LOGIN:
		printk("REASON_FULL_BEFORE_LOGIN");
		break;
	case REASON_DATA_DIGEST_ERR:
		printk("REASON_DATA_DIGEST_ERR");
		break;
	case REASON_DATA_SNACK:
		printk("REASON_DATA_SNACK");
		break;
	case REASON_PROTOCOL_ERR:
		printk("REASON_PROTOCOL_ERR");
		break;
	case REASON_COMMAND_NOT_SUPPORTED:
		printk("REASON_COMMAND_NOT_SUPPORTED");
		break;
	case REASON_TOO_MANY_IMMEDIATE_COMMANDS:
		printk("REASON_TOO_MANY_IMMEDIATE_COMMANDS");
		break;
	case REASON_TASK_IN_PROGRESS:
		printk("REASON_TASK_IN_PROGRESS");
		break;
	case REASON_INVALID_DATA_ACK:
		printk("REASON_INVALID_DATA_ACK");
		break;
	case REASON_INVALID_PDU_FIELD:
		printk("REASON_INVALID_PDU_FIELD");
		break;
	case REASON_OUT_OF_RESOURCES:
		printk("REASON_OUT_OF_RESOURCES");
		break;
	case REASON_NEGOTIATION_RESET:
		printk("REASON_NEGOTIATION_RESET");
		break;
	case REASON_WAITING_FOR_LOGOUT:
		printk("REASON_WAITING_FOR_LOGOUT");
		break;
	default:
		printk("ERROR: Unknown Reject Reason!");
		break;
	}
	printk("\n");
}

#ifdef DEBUG_OPCODES

void print_reserved8(int n, unsigned char reserved)
{
	printk("\treserved%d: 0x%02x\n", n, reserved);
}

void print_reserved16(int n, u16 reserved)
{
	printk("\treserved%d: 0x%04x\n", n, reserved);
}

void print_reserved32(int n, u32 reserved)
{
	printk("\treserved%d: 0x%08x\n", n, reserved);
}

void print_reserved64(int n, u64 reserved)
{
	printk("\treserved%d: 0x%016Lx\n", n, reserved);
}

void print_opcode(u8 opcode)
{
	printk("\topcode: 0x%02x\n", (opcode & 0x3f));
}

void print_flags(u8 flags)
{
	printk("\tflags: 0x%02x\n", flags);
}

void print_dataseglength(u32 length)
{
	printk("\tDataSegmentLength: 0x%08x\n", length);
}
	
void print_expxferlen(u32 expxferlen)
{
	printk("\tExpXferLen: 0x%08x\n", expxferlen);
}

void print_lun(u64 lun)
{
	printk("\tLUN: 0x%016Lx\n", lun);
}

void print_itt(u32 itt)
{
	printk("\tITT: 0x%08x\n", itt);
}

void print_ttt(u32 ttt)
{
	printk("\tTTT: 0x%08x\n", ttt);
}

void print_cmdsn(u32 cmdsn)
{
	printk("\tCmdSN: 0x%08x\n", cmdsn);
}

void print_expcmdsn(u32 expcmdsn)
{
	printk("\tExpCmdSN: 0x%08x\n", expcmdsn);
}

void print_maxcmdsn(u32 maxcmdsn)
{
	printk("\tMaxCmdSN: 0x%08x\n", maxcmdsn);
}

void print_statsn(u32 statsn)
{
	printk("\tStatSN: 0x%08x\n", statsn);
}

void print_expstatsn(u32 expstatsn)
{
	printk("\tExpStatSN: 0x%08x\n", expstatsn);
}

void print_datasn(u32 datasn)
{
	printk("\tDataSN: 0x%08x\n", datasn);
}

void print_expdatasn(u32 expdatasn)
{
	printk("\tExpDataSN: 0x%08x\n", expdatasn);
}

void print_r2tsn(u32 r2tsn)
{
	printk("\tR2TSN: 0x%08x\n", r2tsn);
}

void print_offset(u32 offset)
{
	printk("\toffset: 0x%08x\n", offset);
}

void print_cid(u16 cid)
{
	printk("\tCID: 0x%04x\n", cid);
}

void print_isid(u8 isid[6])
{
	printk("\tISID: 0x%02x %02x %02x %02x %02x %02x\n",
		isid[0], isid[1], isid[2], isid[3], isid[4], isid[5]);
}

void print_tsih(u16 tsih)
{
	printk("\tTSIH: 0x%04x\n", tsih);
}	

void print_scsicdb(u8 cdb[16])
{
	printk("\tSCSI CDB: 0x%02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x\n",
		cdb[0], cdb[1], cdb[2], cdb[3],
		cdb[4], cdb[5], cdb[6], cdb[7],
		cdb[8], cdb[9], cdb[10],cdb[11],
		cdb[12], cdb[13], cdb[14], cdb[15]);
} 

void print_init_scsi_cmnd(struct iscsi_init_scsi_cmnd *cmd)
{
	printk("Dumping ISCSI_INIT_SCSI_CMND PDU\n");
	print_opcode(cmd->opcode);
	print_flags(cmd->flags);
	print_reserved16(1, cmd->reserved);
	print_dataseglength(cmd->length);
	print_lun(cmd->lun);
	print_itt(cmd->init_task_tag);
	print_expxferlen(cmd->exp_xfer_len);
	print_cmdsn(cmd->cmd_sn);
	print_expstatsn(cmd->exp_stat_sn);
	print_scsicdb(cmd->cdb);
}

void print_targ_scsi_rsp(struct iscsi_targ_scsi_rsp *cmd)
{
	printk("Dumping ISCSI_TARG_SCSI_RSP PDU\n");
	print_opcode(cmd->opcode);
	print_flags(cmd->flags);
	printk("\tResponse: 0x%02x\n", cmd->response);
	printk("\tStatus: 0x%02x\n", cmd->status);
	print_dataseglength(cmd->length);
	print_reserved64(1, cmd->reserved1);
	print_itt(cmd->init_task_tag);
	print_reserved32(2, cmd->reserved2);
	print_statsn(cmd->stat_sn);
	print_expcmdsn(cmd->exp_cmd_sn);
	print_maxcmdsn(cmd->max_cmd_sn);
	print_expdatasn(cmd->exp_data_sn);
	printk("\tBidiResidualCount: 0x%08x\n", cmd->bidi_res_count);
	printk("\tResidualCount: 0x%08x\n", cmd->res_count);
}

void print_init_task_mgt_command(struct iscsi_init_task_mgt_cmnd *cmd)
{
	printk("Dumping ISCSI_INIT_TASK_MGT_CMND PDU\n");
	print_opcode(cmd->opcode);
	printk("\tFunction: 0x%02x\n", cmd->function);
	print_reserved16(1, cmd->reserved1);
	print_dataseglength(cmd->length);
	print_lun(cmd->lun);
	print_itt(cmd->init_task_tag);
	printk("\tRefTaskTag: 0x%08x\n", cmd->ref_task_tag);
	print_cmdsn(cmd->cmd_sn);
	print_expstatsn(cmd->exp_stat_sn);
	printk("\tRefCmdSN: 0x%08x\n", cmd->ref_cmd_sn);
	print_expdatasn(cmd->exp_data_sn);
	print_reserved64(2, cmd->reserved2);
}

void print_targ_task_mgt_rsp(struct iscsi_targ_task_mgt_rsp *cmd)
{
	printk("Dumping ISCSI_TARG_TASK_MGT_RSP PDU\n");
	print_opcode(cmd->opcode);
	print_flags(cmd->flags);
	printk("\tResponse: 0x%02x\n", cmd->response);
	print_reserved8(1, cmd->reserved1);
	print_dataseglength(cmd->length);
	print_reserved64(2, cmd->reserved2);
	print_itt(cmd->init_task_tag);
	print_reserved32(3, cmd->reserved3);
	print_statsn(cmd->stat_sn);
	print_expcmdsn(cmd->exp_cmd_sn);
	print_maxcmdsn(cmd->max_cmd_sn);
	print_reserved32(4, cmd->reserved4);
	print_reserved64(5, cmd->reserved5);
}

void print_init_scsi_data_out(struct iscsi_init_scsi_data_out *cmd)
{
	printk("Dumping ISCSI_INIT_SCSI_DATA_OUT PDU\n");
	print_opcode(cmd->opcode);
	print_flags(cmd->flags);
	print_reserved16(1, cmd->reserved1);
	print_dataseglength(cmd->length);
	print_lun(cmd->lun);
	print_itt(cmd->init_task_tag);
	print_ttt(cmd->targ_xfer_tag);
	print_reserved32(2, cmd->reserved2);
	print_expstatsn(cmd->exp_stat_sn);
	print_reserved32(3, cmd->reserved3);
	print_datasn(cmd->data_sn);
	print_offset(cmd->offset);
	print_reserved32(4, cmd->reserved4);
}

void print_targ_scsi_data_in(struct iscsi_targ_scsi_data_in *cmd)
{
	printk("Dumping ISCSI_TARG_SCSI_DATA_IN PDU\n");
	print_opcode(cmd->opcode);
	print_flags(cmd->flags);
	print_reserved8(1, cmd->reserved1);
	printk("\tstatus: 0x%02x\n", cmd->status);
	print_dataseglength(cmd->length);
	print_lun(cmd->lun);
	print_itt(cmd->init_task_tag);
	print_ttt(cmd->targ_xfer_tag);
	print_statsn(cmd->stat_sn);
	print_expcmdsn(cmd->exp_cmd_sn);
	print_maxcmdsn(cmd->max_cmd_sn);
	print_datasn(cmd->data_sn);
	print_offset(cmd->offset);
	printk("\tResidualCount: 0x%08x\n", cmd->res_count);
}

void print_targ_r2t(struct iscsi_targ_r2t *cmd)
{
	printk("Dumping ISCSI_TARG_R2T PDU\n");
	print_opcode(cmd->opcode);
	print_flags(cmd->flags);
	print_reserved16(1, cmd->reserved1);
	print_dataseglength(cmd->length);
	print_lun(cmd->lun);
	print_itt(cmd->init_task_tag);
	print_ttt(cmd->targ_xfer_tag);
	print_statsn(cmd->stat_sn);
	print_expcmdsn(cmd->exp_cmd_sn);
	print_maxcmdsn(cmd->max_cmd_sn);
	print_r2tsn(cmd->r2t_sn);
	print_offset(cmd->offset);
	printk("\tDDTL: 0x%08x\n", cmd->xfer_len);
}

void print_targ_async_msg(struct iscsi_targ_async_msg *cmd)
{
	printk("Dumping ISCSI_TARG_ASYNC_MSG PDU\n");
	print_opcode(cmd->opcode);
	print_flags(cmd->flags);
	print_reserved16(1, cmd->reserved1);
	print_dataseglength(cmd->length);
	print_lun(cmd->lun);
	print_reserved64(2, cmd->reserved2);
	print_statsn(cmd->stat_sn);
	print_expcmdsn(cmd->exp_cmd_sn);
	print_maxcmdsn(cmd->max_cmd_sn);
	printk("\tAsyncEvent: 0x%02x\n", cmd->async_event);
	printk("\tAsyncVcode: 0x%02x\n", cmd->async_vcode);
	printk("\tParameter1: 0x%04x\n", cmd->parameter1);
	printk("\tParameter2: 0x%04x\n", cmd->parameter2);
	printk("\tParameter3: 0x%04x\n", cmd->parameter3);
	print_reserved32(3, cmd->reserved3);
}

void print_init_text_cmnd(struct iscsi_init_text_cmnd *cmd)
{
	printk("Dumping ISCSI_INIT_TEXT_CMND PDU\n");
	print_opcode(cmd->opcode);
	print_flags(cmd->flags);
	print_reserved16(1, cmd->reserved1);
	print_dataseglength(cmd->length);
	print_lun(cmd->lun);
	print_itt(cmd->init_task_tag);
	print_ttt(cmd->targ_xfer_tag);
	print_cmdsn(cmd->cmd_sn);
	print_expstatsn(cmd->exp_stat_sn);
	print_reserved64(2, cmd->reserved2);
	print_reserved64(3, cmd->reserved3);
}

void print_targ_text_rsp(struct iscsi_targ_text_rsp *cmd)
{
	printk("Dumping ISCSI_TARG_TEXT_RSP PDU\n");
	print_opcode(cmd->opcode);
	print_flags(cmd->flags);
	print_reserved16(1, cmd->reserved1);
	print_dataseglength(cmd->length);
	print_lun(cmd->lun);
	print_itt(cmd->init_task_tag);
	print_ttt(cmd->targ_xfer_tag);
	print_statsn(cmd->stat_sn);
	print_expcmdsn(cmd->exp_cmd_sn);
	print_maxcmdsn(cmd->max_cmd_sn);
	print_reserved32(2, cmd->reserved2);
	print_reserved64(3, cmd->reserved3);
}

void print_init_login_cmnd(struct iscsi_init_login_cmnd *cmd)
{
	printk("\tDumping ISCSI_INIT_LOGIN_CMND PDU\n");
	print_opcode(cmd->opcode);
	print_flags(cmd->flags);
	printk("\tT_BIT: %d\n", (cmd->flags & T_BIT) ? 1 : 0);
	printk("\tCSG: %d, NSG: %d\n", ((cmd->flags & CSG) >> 2), cmd->flags & NSG);
	printk("\tVersionMax: 0x%02x\n", cmd->version_max);
	printk("\tVersionMin: 0x%02x\n", cmd->version_min);
	print_dataseglength(cmd->length);
	print_isid(cmd->isid);
	print_tsih(cmd->tsih);
	print_itt(cmd->init_task_tag);
	print_cid(cmd->cid);
	print_reserved16(1, cmd->reserved1);
	print_cmdsn(cmd->cmd_sn);
	print_expstatsn(cmd->exp_stat_sn);
	print_reserved64(2, cmd->reserved2);
	print_reserved64(3, cmd->reserved3);
}	

void print_targ_login_rsp(struct iscsi_targ_login_rsp *cmd)
{
	printk("Dumping ISCSI_TARG_LOGIN_RSP PDU\n");
	print_opcode(cmd->opcode);
	print_flags(cmd->flags);
	printk("\tT_BIT: %d\n", (cmd->flags & T_BIT) ? 1 : 0);
	printk("\tCSG: %d, NSG: %d\n", ((cmd->flags & CSG) >> 2), cmd->flags & NSG);
	printk("\tVersionMax: 0x%02x\n", cmd->version_max);
	printk("\tVersionActive: 0x%02x\n", cmd->version_active);
	print_dataseglength(cmd->length);
	print_isid(cmd->isid);
	print_tsih(cmd->tsih);
	print_itt(cmd->init_task_tag);
	print_reserved32(1, cmd->reserved1);
	print_statsn(cmd->stat_sn);
	print_expcmdsn(cmd->exp_cmd_sn);
	print_maxcmdsn(cmd->max_cmd_sn);
	printk("\tStatusClass: 0x%02x\n", cmd->status_class);
	printk("\tStatusDetail: 0x%02x\n", cmd->status_detail);
	print_reserved16(2, cmd->reserved2);
	print_reserved32(3, cmd->reserved3);
}

void print_init_logout_cmnd(struct iscsi_init_logout_cmnd *cmd)
{
	printk("Dumping ISCSI_INIT_LOGOUT_CMND PDU\n");
	print_opcode(cmd->opcode);
	print_flags(cmd->flags);
	print_reserved16(1, cmd->reserved1);
	print_dataseglength(cmd->length);
	print_reserved64(2, cmd->reserved2);
	print_itt(cmd->init_task_tag);
	print_cid(cmd->cid);
	print_reserved8(3, cmd->reserved3);
	print_cmdsn(cmd->cmd_sn);
	print_expstatsn(cmd->exp_stat_sn);
	print_reserved32(4, cmd->reserved4);
	print_reserved64(5, cmd->reserved5);
}

void print_targ_logout_rsp(struct iscsi_targ_logout_rsp *cmd)
{
	printk("Dumping ISCSI_TARG_LOGOUT_RSP PDU\n");
	print_opcode(cmd->opcode);
	print_flags(cmd->flags);
	printk("\tResponse: 0x%02x\n", cmd->response);
	print_reserved8(1, cmd->reserved1);
	print_dataseglength(cmd->length);
	print_reserved64(2, cmd->reserved2);
	print_itt(cmd->init_task_tag);
	print_reserved32(3, cmd->reserved3);
	print_statsn(cmd->stat_sn);
	print_expcmdsn(cmd->exp_cmd_sn);
	print_maxcmdsn(cmd->max_cmd_sn);
	print_reserved32(4, cmd->reserved4);
	printk("\tTime2Wait: 0x%04x\n", cmd->time_2_wait);
	printk("\tTime2Retain: 0x%04x\n", cmd->time_2_retain);
	print_reserved32(5, cmd->reserved5);
}

void print_init_snack(struct iscsi_init_snack *cmd)
{
	printk("Dumping ISCSI_INIT_SNACK PDU\n");
	print_opcode(cmd->opcode);
	printk("\tType: 0x%02x\n", cmd->type);
	print_reserved16(1, cmd->reserved1);
	print_dataseglength(cmd->length);
	print_lun(cmd->lun);
	print_itt(cmd->init_task_tag);
	print_ttt(cmd->targ_xfer_tag);
	print_reserved32(2, cmd->reserved2);
	print_expstatsn(cmd->exp_stat_sn);
	print_reserved64(3, cmd->reserved3);
	printk("\tBegRun: 0x%08x\n", cmd->begrun);
	printk("\tRunLength: 0x%08x\n", cmd->runlength);
}

void print_targ_rjt(struct iscsi_targ_rjt *cmd)
{
	printk("Dumping ISCSI_TARG_RJT PDU\n");
	print_opcode(cmd->opcode);
	print_flags(cmd->flags);
	printk("\tReason: 0x%02x\n", cmd->reason);
	print_reserved8(1, cmd->reserved1);
	print_dataseglength(cmd->length);
	print_reserved64(2, cmd->reserved2);
	print_reserved32(3, cmd->reserved3);
	print_statsn(cmd->stat_sn);
	print_expcmdsn(cmd->exp_cmd_sn);
	print_maxcmdsn(cmd->max_cmd_sn);
	print_datasn(cmd->data_sn);
	print_reserved64(4, cmd->reserved4);
}

void print_init_nop_out(struct iscsi_init_nop_out *cmd)
{
	printk("Dumping ISCSI_INIT_NOP_OUT PDU\n");
	print_opcode(cmd->opcode);
	print_flags(cmd->flags);
	print_reserved16(1, cmd->reserved1);
	print_dataseglength(cmd->length);
	print_lun(cmd->lun);
	print_itt(cmd->init_task_tag);
	print_ttt(cmd->targ_xfer_tag);
	print_cmdsn(cmd->cmd_sn);
	print_expstatsn(cmd->exp_stat_sn);
	print_reserved64(2, cmd->reserved2);
	print_reserved64(3, cmd->reserved3);
}

void print_targ_nop_in(struct iscsi_targ_nop_in *cmd)
{
	printk("Dumping ISCSI_TARG_NOP_IN PDU\n");
	print_opcode(cmd->opcode);
	print_flags(cmd->flags);
	print_reserved16(1, cmd->reserved1);
	print_dataseglength(cmd->length);
	print_lun(cmd->lun);
	print_itt(cmd->init_task_tag);
	print_ttt(cmd->targ_xfer_tag);
	print_statsn(cmd->stat_sn);
	print_expcmdsn(cmd->exp_cmd_sn);
	print_maxcmdsn(cmd->max_cmd_sn);
	print_reserved32(2, cmd->reserved2);
	print_reserved64(3, cmd->reserved2);	
}

#endif /* DEBUG_OPCODES */
