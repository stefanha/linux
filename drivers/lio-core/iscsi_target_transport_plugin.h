/*********************************************************************************
 * Filename:  iscsi_target_transport_plugin.h
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


#ifndef _ISCSI_TARGET_TRANSPORT_PLUGIN_H_
#define _ISCSI_TARGET_TRANSPORT_PLUGIN_H_

#ifdef PARALLEL_SCSI
#define PSCSI_INCLUDE_STRUCTS
#include <iscsi_target_pscsi.h>
#undef PSCSI_INCLUDE_STRUCTS
extern se_subsystem_api_t pscsi_template;
#endif /* PARALLEL_SCSI */

#ifdef PYX_IBLOCK
#define IBLOCK_INCLUDE_STRUCTS
#include <iscsi_target_iblock.h>
#undef IBLOCK_INCLUDE_STRUCTS
extern se_subsystem_api_t iblock_template;
#endif /* PYX_IBLOCK */

#ifdef PYX_RAMDISK
#define RD_INCLUDE_STRUCTS
#include <iscsi_target_rd.h>
#undef RD_INCLUDE_STRUCTS
extern se_subsystem_api_t rd_dr_template;
extern se_subsystem_api_t rd_mcp_template;
#endif /* PYX_RAMDISK */

#ifdef PYX_FILEIO
#define FD_INCLUDE_STRUCTS
#include <iscsi_target_file.h>
#undef FD_INCLUDE_STRUCTS
extern se_subsystem_api_t fileio_template;
#endif /* PYX_FILEIO */

#ifdef PYX_VROM
#define VR_INCLUDE_STRUCTS
#include <iscsi_target_vrom.h>
#undef VR_INCLUDE_STRUCTS
extern se_subsystem_api_t vrom_template;
#endif /* PYX_VROM */

#ifdef PYX_VTAPE
#define VT_INCLUDE_STRUCTS
#include <iscsi_target_vt.h>
#undef VT_INCLUDE_STRUCTS
extern se_subsystem_api_t vtape_template;
#endif /* PYX_VTAPE */

#ifdef PYX_MEDIA_CHANGER
#define MC_INCLUDE_STRUCTS
#include <iscsi_target_mc.h>
#undef MC_INCLUDE_STRUCTS
extern se_subsystem_api_t mc_template;
#endif /* PYX_MEDIA_CHANGER */

#endif    /*** _ISCSI_TARGET_TRANSPORT_PLUGIN_H_ ***/

