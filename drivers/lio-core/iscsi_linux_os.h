/*********************************************************************************
 * Filename:  iscsi_linux_os.h
 *
 * $HeadURL: svn://subversion.sbei.com/pyx/target/branches/2.9-linux-iscsi.org/pyx-target/include/iscsi_linux_os.h $
 *   $LastChangedRevision: 6660 $
 *   $LastChangedBy: nab $
 *   $LastChangedDate: 2007-02-15 12:59:08 -0800 (Thu, 15 Feb 2007) $
 *
 * -- PYX - CONFIDENTIAL --
 * Copyright (c) 2003 PyX Technologies, Inc.
 * Copyright (c) 2006 SBE, Inc.  All Rights Reserved.
 *
 *********************************************************************************/

#ifndef _ISCSI_LINUX_OS_H_
#define _ISCSI_LINUX_OS_H_

#include <linux/version.h>

#include <asm/byteorder.h>
#ifdef __BIG_ENDIAN
# define ISCSI_BIG_ENDIAN 1
#endif
#include <asm/types.h>
#include <linux/types.h>

#endif    /*** _ISCSI_LINUX_OS_H_ ***/

