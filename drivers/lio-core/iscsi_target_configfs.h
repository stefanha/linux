/*********************************************************************************
 * Filename:  iscsi_target_configfs.h
 *
 * This file contains the configfs defines and prototypes for the
 * LIO Target.
 *
 * Copyright (c) 2008  Nicholas A. Bellinger <nab@linux-iscsi.org>
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
 ****************************************************************************/

extern int iscsi_target_register_configfs (void);
extern void iscsi_target_deregister_configfs (void);

extern struct kmem_cache *lio_tpg_cache;
