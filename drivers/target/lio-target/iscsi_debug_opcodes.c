/*******************************************************************************
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
 ******************************************************************************/


#include <linux/string.h>
#include <linux/timer.h>
#include <linux/slab.h>
#include <iscsi_debug.h>
#include <iscsi_protocol.h>
#include <iscsi_debug_opcodes.h>

#ifdef DEBUG_OPCODES

void print_reserved8(int n, unsigned char reserved)
{
	printk(KERN_INFO "\treserved%d: 0x%02x\n", n, reserved);
}

void print_reserved16(int n, u16 reserved)
{
	printk(KERN_INFO "\treserved%d: 0x%04x\n", n, reserved);
}

void print_reserved32(int n, u32 reserved)
{
	printk(KERN_INFO "\treserved%d: 0x%08x\n", n, reserved);
}

void print_reserved64(int n, u64 reserved)
{
	printk(KERN_INFO "\treserved%d: 0x%016Lx\n", n, reserved);
}

void print_opcode(u8 opcode)
{
	printk(KERN_INFO "\topcode: 0x%02x\n", (opcode & 0x3f));
}

void print_flags(u8 flags)
{
	printk(KERN_INFO "\tflags: 0x%02x\n", flags);
}

void print_dataseglength(u32 length)
{
	printk(KERN_INFO "\tDataSegmentLength: 0x%08x\n", length);
}

void print_expxferlen(u32 expxferlen)
{
	printk(KERN_INFO "\tExpXferLen: 0x%08x\n", expxferlen);
}

void print_lun(u64 lun)
{
	printk(KERN_INFO "\tLUN: 0x%016Lx\n", lun);
}

void print_itt(u32 itt)
{
	printk(KERN_INFO "\tITT: 0x%08x\n", itt);
}

void print_ttt(u32 ttt)
{
	printk(KERN_INFO "\tTTT: 0x%08x\n", ttt);
}

void print_cmdsn(u32 cmdsn)
{
	printk(KERN_INFO "\tCmdSN: 0x%08x\n", cmdsn);
}

void print_expcmdsn(u32 expcmdsn)
{
	printk(KERN_INFO "\tExpCmdSN: 0x%08x\n", expcmdsn);
}

void print_maxcmdsn(u32 maxcmdsn)
{
	printk(KERN_INFO "\tMaxCmdSN: 0x%08x\n", maxcmdsn);
}

void print_statsn(u32 statsn)
{
	printk(KERN_INFO "\tStatSN: 0x%08x\n", statsn);
}

void print_expstatsn(u32 expstatsn)
{
	printk(KERN_INFO "\tExpStatSN: 0x%08x\n", expstatsn);
}

void print_datasn(u32 datasn)
{
	printk(KERN_INFO "\tDataSN: 0x%08x\n", datasn);
}

void print_expdatasn(u32 expdatasn)
{
	printk(KERN_INFO "\tExpDataSN: 0x%08x\n", expdatasn);
}

void print_r2tsn(u32 r2tsn)
{
	printk(KERN_INFO "\tR2TSN: 0x%08x\n", r2tsn);
}

void print_offset(u32 offset)
{
	printk(KERN_INFO "\toffset: 0x%08x\n", offset);
}

void print_cid(u16 cid)
{
	printk(KERN_INFO "\tCID: 0x%04x\n", cid);
}

void print_isid(u8 isid[6])
{
	printk(KERN_INFO "\tISID: 0x%02x %02x %02x %02x %02x %02x\n",
		isid[0], isid[1], isid[2], isid[3], isid[4], isid[5]);
}

void print_tsih(u16 tsih)
{
	printk(KERN_INFO "\tTSIH: 0x%04x\n", tsih);
}

void print_scsicdb(u8 cdb[16])
{
	printk(KERN_INFO "\tSCSI CDB: 0x%02x %02x %02x %02x %02x %02x %02x %02x"
		" %02x %02x %02x %02x %02x %02x %02x %02x\n", cdb[0], cdb[1],
		cdb[2], cdb[3], cdb[4], cdb[5], cdb[6], cdb[7], cdb[8], cdb[9],
		cdb[10], cdb[11], cdb[12], cdb[13], cdb[14], cdb[15]);
}

#endif /* DEBUG_OPCODES */
