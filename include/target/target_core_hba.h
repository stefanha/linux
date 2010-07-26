/*******************************************************************************
 * Filename:  target_core_hba.h
 *
 * This file contains the iSCSI HBA Transport related definitions.
 *
 * Copyright (c) 2003-2004 PyX Technologies, Inc.
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


#ifndef TARGET_CORE_HBA_H
#define TARGET_CORE_HBA_H

extern struct se_global *se_global;

extern struct kmem_cache *se_hba_cache;

extern int core_get_hba(struct se_hba *);
extern struct se_hba *core_alloc_hba(int);
extern void core_put_hba(struct se_hba *);
extern int se_core_add_hba(struct se_hba *, u32);
extern int se_core_del_hba(struct se_hba *);

#endif /* TARGET_CORE_HBA_H */
