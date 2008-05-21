/*********************************************************************************
 * Filename:  iscsi_target_scdb.c
 *
 * This file contains the iSCSI Transport Split CDB related functions.
 *
 * Copyright (c) 2004-2005 PyX Technologies, Inc.
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


#define ISCSI_TARGET_SCDB_C

#include <linux/net.h>
#include <linux/string.h>
#include <linux/timer.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/smp_lock.h>
#include <linux/in.h>
#include <net/sock.h>
#include <net/tcp.h>

#include <iscsi_linux_os.h>
#include <iscsi_linux_defs.h>

#include <iscsi_lists.h>
#include <iscsi_protocol.h>
#include <iscsi_target_core.h>
#include <iscsi_target_ioctl.h>
#include <iscsi_target_hba.h>
#include <iscsi_target_transport.h>
#include <iscsi_target_util.h>
#include <iscsi_target_scdb.h>

#undef ISCSI_TARGET_SCDB_C

/*	split_cdb_XX_6():
 *
 *      21-bit LBA w/ 8-bit SECTORS
 */
extern void split_cdb_XX_6 (unsigned long long lba, u32 *sectors, unsigned char *cdb)
{       
	cdb[1] = (lba >> 16) & 0x1f;
	cdb[2] = (lba >> 8) & 0xff;
	cdb[3] = lba & 0xff;
	cdb[4] = *sectors & 0xff;
					        
	return;
}

extern void split_cdb_RW_6 (unsigned long long lba, u32 *sectors, unsigned char *cdb, int rw)
{
	cdb[0] = (rw) ? 0x0a : 0x08;
	split_cdb_XX_6(lba, sectors, &cdb[0]);

	return;
}

/*	split_cdb_XX_10():
 *
 *	32-bit LBA w/ 16-bit SECTORS 
 */
extern void split_cdb_XX_10 (unsigned long long lba, u32 *sectors, unsigned char *cdb)
{       
	cdb[2] = (lba >> 24) & 0xff;
	cdb[3] = (lba >> 16) & 0xff;
	cdb[4] = (lba >> 8) & 0xff;
	cdb[5] = lba & 0xff;
	cdb[7] = (*sectors >> 8) & 0xff;
	cdb[8] = *sectors & 0xff;
							        
	return;
}

extern void split_cdb_RW_10 (unsigned long long lba, u32 *sectors, unsigned char *cdb, int rw)
{
	cdb[0] = (rw) ? 0x2a : 0x28;
	split_cdb_XX_10(lba, sectors, &cdb[0]);

	return;
}

/*	split_cdb_XX_12():
 *
 *	32-bit LBA w/ 32-bit SECTORS
 */
extern void split_cdb_XX_12 (unsigned long long lba, u32 *sectors, unsigned char *cdb)
{       
	cdb[2] = (lba >> 24) & 0xff;
	cdb[3] = (lba >> 16) & 0xff;
	cdb[4] = (lba >> 8) & 0xff;
	cdb[5] = lba & 0xff;
	cdb[6] = (*sectors >> 24) & 0xff;
	cdb[7] = (*sectors >> 16) & 0xff;
	cdb[8] = (*sectors >> 8) & 0xff;
	cdb[9] = *sectors & 0xff;
						        
	return;
}

extern void split_cdb_RW_12 (unsigned long long lba, u32 *sectors, unsigned char *cdb, int rw)
{
	cdb[0] = (rw) ? 0xaa : 0xa8;
	split_cdb_XX_12(lba, sectors, &cdb[0]);

	return;
}

/*	split_cdb_XX_16():
 *
 *	64-bit LBA w/ 32-bit SECTORS
 */
extern void split_cdb_XX_16 (unsigned long long lba, u32 *sectors, unsigned char *cdb)
{
	cdb[2] = (lba >> 56) & 0xff;
	cdb[3] = (lba >> 48) & 0xff;
	cdb[4] = (lba >> 40) & 0xff;
	cdb[5] = (lba >> 32) & 0xff;
	cdb[6] = (lba >> 24) & 0xff;
	cdb[7] = (lba >> 16) & 0xff;
	cdb[8] = (lba >> 8) & 0xff;
	cdb[9] = lba & 0xff;
	cdb[10] = (*sectors >> 24) & 0xff;
	cdb[11] = (*sectors >> 16) & 0xff;
	cdb[12] = (*sectors >> 8) & 0xff;
	cdb[13] = *sectors & 0xff;

	return;
}

extern void split_cdb_RW_16 (unsigned long long lba, u32 *sectors, unsigned char *cdb, int rw)
{
	cdb[0] = (rw) ? 0x8a : 0x88;
	split_cdb_XX_16(lba, sectors, &cdb[0]);

	return;
}
