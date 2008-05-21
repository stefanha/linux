/*********************************************************************************
 * Filename:  iscsi_debug_opcodes.h
 *
 * $HeadURL: svn://subversion.sbei.com/pyx/target/branches/2.9-linux-iscsi.org/pyx-target/include/iscsi_debug_opcodes.h $
 *   $LastChangedRevision: 4793 $
 *   $LastChangedBy: rickd $
 *   $LastChangedDate: 2006-08-17 16:05:03 -0700 (Thu, 17 Aug 2006) $
 *
 * Copyright (c) 2003 PyX Technologies, Inc.
 * Copyright (c) 2006 SBE, Inc.  All Rights Reserved.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 * For further information, contact via email: support@sbei.com
 * SBE, Inc.  San Ramon, California  U.S.A.
 *********************************************************************************/


#ifndef ISCSI_OPCODES_DEBUG_H
#define ISCSI_OPCODES_DEBUG_H

#include <iscsi_linux_os.h>
#include <iscsi_linux_defs.h>

void print_status_class_and_detail (u8, u8);
void print_reject_reason(u8);
void print_reserved8(int, unsigned char);
void print_reserved16(int, u16);
void print_reserved32(int, u32);
void print_reserved64(int, u64);
void print_opcode(u8);
void print_flags(u8);
void print_dataseglength(u32);
void print_expxferlen(u32);
void print_lun(u64);
void print_itt(u32);
void print_ttt(u32);
void print_cmdsn(u32);
void print_expcmdsn(u32);
void print_maxcmdsn(u32);
void print_statsn(u32);
void print_expstatsn(u32);
void print_datasn(u32);
void print_expdatasn(u32);
void print_r2tsn(u32);
void print_offset(u32);
void print_cid(u16);
void print_isid(u8 []);
void print_tsih(u16);
void print_scsicdb(u8 []);
void print_init_scsi_cmnd(struct iscsi_init_scsi_cmnd *);
void print_targ_scsi_rsp(struct iscsi_targ_scsi_rsp *);
void print_init_task_mgt_command(struct iscsi_init_task_mgt_cmnd *);
void print_targ_task_mgt_rsp(struct iscsi_targ_task_mgt_rsp *);
void print_init_scsi_data_out(struct iscsi_init_scsi_data_out *);
void print_targ_scsi_data_in(struct iscsi_targ_scsi_data_in *);
void print_targ_r2t(struct iscsi_targ_r2t *);
void print_targ_async_msg(struct iscsi_targ_async_msg *);
void print_init_text_cmnd(struct iscsi_init_text_cmnd *);
void print_targ_text_rsp(struct iscsi_targ_text_rsp *);
void print_init_login_cmnd(struct iscsi_init_login_cmnd *);
void print_targ_login_rsp(struct iscsi_targ_login_rsp *);
void print_init_logout_cmnd(struct iscsi_init_logout_cmnd *);
void print_targ_logout_rsp(struct iscsi_targ_logout_rsp *);
void print_init_snack(struct iscsi_init_snack *);
void print_targ_rjt(struct iscsi_targ_rjt *);
void print_init_nop_out(struct iscsi_init_nop_out *);
void print_targ_nop_in(struct iscsi_targ_nop_in *);

#endif /* ISCSI_OPCODES_DEBUG_H */
