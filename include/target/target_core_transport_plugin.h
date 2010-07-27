/*******************************************************************************
 * Filename:  target_core_transport_plugin.h
 *
 * Copyright (c) 2002, 2003, 2004, 2005 PyX Technologies, Inc.
 * Copyright (c) 2005, 2006, 2007 SBE, Inc.
 * Copyright (c) 2007-2009 Rising Tide Software, Inc.
 * Copyright (c) 2008-2009 Linux-iSCSI.org
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


#ifndef _TARGET_CORE_TRANSPORT_PLUGIN_H_
#define _TARGET_CORE_TRANSPORT_PLUGIN_H_

#ifdef PARALLEL_SCSI
#define PSCSI_INCLUDE_STRUCTS
#include <target/target_core_pscsi.h>
#undef PSCSI_INCLUDE_STRUCTS
extern struct se_subsystem_api pscsi_template;
#endif /* PARALLEL_SCSI */

#ifdef STGT_PLUGIN
#define STGT_INCLUDE_STRUCTS
#include <target/target_core_stgt.h>
#undef STGT_INCLUDE_STRUCTS
extern struct se_subsystem_api stgt_template;
#endif /* STGT_PLUGIN */

#ifdef PYX_IBLOCK
#define IBLOCK_INCLUDE_STRUCTS
#include <target/target_core_iblock.h>
#undef IBLOCK_INCLUDE_STRUCTS
extern struct se_subsystem_api iblock_template;
#endif /* PYX_IBLOCK */

#ifdef PYX_RAMDISK
#define RD_INCLUDE_STRUCTS
#include <target/target_core_rd.h>
#undef RD_INCLUDE_STRUCTS
extern struct se_subsystem_api rd_dr_template;
extern struct se_subsystem_api rd_mcp_template;
#endif /* PYX_RAMDISK */

#ifdef PYX_FILEIO
#define FD_INCLUDE_STRUCTS
#include <target/target_core_file.h>
#undef FD_INCLUDE_STRUCTS
extern struct se_subsystem_api fileio_template;
#endif /* PYX_FILEIO */

#endif    /*** _TARGET_CORE_TRANSPORT_PLUGIN_H_ ***/
