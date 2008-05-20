/*********************************************************************************
 * Filename:  iscsi_target_datain_values.h
 *
 * This file contains the iSCSI Target DataIN value generation definitions.
 *
 * Copyright (c) 2003, 2004, 2005 PyX Technologies, Inc.
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


#ifndef ISCSI_TARGET_DATAIN_VALUES_H
#define ISCSI_TARGET_DATAIN_VALUES_H

extern iscsi_datain_req_t *iscsi_allocate_datain_req (void);
extern void iscsi_attach_datain_req (iscsi_cmd_t *, iscsi_datain_req_t *);
extern void iscsi_free_datain_req (iscsi_cmd_t *, iscsi_datain_req_t *);
extern void iscsi_free_all_datain_reqs (iscsi_cmd_t *);
extern iscsi_datain_req_t *iscsi_get_datain_req (iscsi_cmd_t *);
extern iscsi_datain_req_t *iscsi_get_datain_values (iscsi_cmd_t *, iscsi_datain_t *);

#endif   /*** ISCSI_TARGET_DATAIN_VALUES_H ***/

