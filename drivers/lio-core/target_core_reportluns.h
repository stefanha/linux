/*********************************************************************************
 * Filename:  target_core_reportluns.h 
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


#ifndef TARGET_CORE_REPORTLUNS_H
#define TARGET_CORE_REPORTLUNS_H

typedef struct rl_cmd_s {
	struct se_cmd_s *rl_se_cmd;
	unsigned char *rl_buf;
	u32 rl_size;
} rl_cmd_t;

extern int se_allocate_rl_cmd (se_cmd_t *, unsigned char *, u32);
extern int se_build_report_luns_response (se_cmd_t *);

#ifndef RL_INCLUDE_STRUCTS
extern int rl_check_for_SG (se_task_t *);
extern void rl_free_task (se_task_t *);

#define TARGET_CORE_RL { 				\
	name:			"RL",			\
	check_for_SG:		rl_check_for_SG,	\
	free_task:		rl_free_task,		\
};

se_subsystem_api_t _rl_template = TARGET_CORE_RL;
#endif /* RL_INCLUDE_STRUCTS */

#endif   /*** TARGET_CORE_REPORTLUNS_H ***/

