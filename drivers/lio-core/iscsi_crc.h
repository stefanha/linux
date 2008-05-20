/*********************************************************************************
 * Filename:  iscsi_crc.h
 *
 * $HeadURL: svn://subversion.sbei.com/pyx/target/branches/2.9-linux-iscsi.org/pyx-target/include/iscsi_crc.h $
 *   $LastChangedRevision: 4537 $
 *   $LastChangedBy: rickd $
 *   $LastChangedDate: 2006-08-02 11:25:26 -0700 (Wed, 02 Aug 2006) $
 *
 * -- PYX - CONFIDENTIAL --
 * Copyright (c) 2003 PyX Technologies, Inc.
 * Copyright (c) 2006 SBE, Inc.  All Rights Reserved.
 *
 *********************************************************************************/


#ifndef _ISCSI_CRC_H_
#define _ISCSI_CRC_H_

#ifdef LINUX
#include <iscsi_linux_os.h>
#include <iscsi_linux_defs.h>
#endif /* LINUX */

#ifdef FREEBSD
#include <iscsi_freebsd_os.h>
#include <iscsi_freebsd_defs.h>
#endif /* FREEBSD */

/*	calculate a 32-bit crc	*/
/*	if restart has 0x01 set, initialize the accumulator */
/*	if restart has 0x02 set, save result in network byte order */
extern void do_crc(__u8 *data, __u32 len, int restart, __u32 *result);

#endif /*** _ISCSI_CRC_H_ ***/
