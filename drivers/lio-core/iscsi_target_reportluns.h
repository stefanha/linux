/*********************************************************************************
 * Filename:  iscsi_target_reportluns.h 
 *
 * This file contains the iSCSI Target REPORT_LUNS definitions.
 *
 * Copyright (c) 2004 PyX Technologies, Inc.
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


#ifndef ISCSI_TARGET_REPORTLUNS_H
#define ISCSI_TARGET_REPORTLUNS_H

typedef struct rl_cmd_s {
	unsigned char *rl_buf;
	u32 rl_size;
} rl_cmd_t;

extern int iscsi_allocate_rl_cmd (iscsi_cmd_t *, unsigned char *, u64);
extern int iscsi_build_report_luns_response (iscsi_cmd_t *);

static int rl_check_for_SG (iscsi_task_t *);
static void rl_free_task (iscsi_task_t *);
static unsigned char *rl_get_non_SG (iscsi_task_t *);

#define ISCSI_RL { 					\
	name:			"RL",			\
	check_for_SG:		rl_check_for_SG,	\
	free_task:		rl_free_task,		\
	get_non_SG:		rl_get_non_SG,		\
};

iscsi_transport_t rl_template = ISCSI_RL;

#endif   /*** ISCSI_TARGET_REPORTLUNS_H ***/

