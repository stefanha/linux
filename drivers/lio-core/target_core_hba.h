/*******************************************************************************
 * Filename:  target_core_hba.h
 *
 * This file contains the iSCSI HBA Transport related definitions.
 *
 * Copyright (c) 2003-2004 PyX Technologies, Inc.
 * Copyright (c) 2005, 2006, 2007 SBE, Inc.
 * Copyright (c) 2007 Rising Tide Software, Inc.
 * Copyright (c) 2008 Linux-iSCSI.org
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


#ifndef TARGET_CORE_HBA_H
#define TARGET_CORE_HBA_H

extern se_global_t *se_global;

extern struct se_hba_s *__core_get_hba_from_id(struct se_hba_s *);
extern struct se_hba_s *core_get_hba_from_id(u32, int);
extern struct se_hba_s *core_get_next_free_hba(void);
extern void core_put_hba(struct se_hba_s *);
extern int se_core_add_hba(struct se_hba_s *, u32);
extern int se_core_del_hba(struct se_hba_s *);
extern void iscsi_disable_all_hbas(void);
extern void iscsi_hba_del_all_hbas(void);

#endif /* TARGET_CORE_HBA_H */
