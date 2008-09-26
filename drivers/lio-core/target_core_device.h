/*********************************************************************************
 * Filename:  target_core_device.h
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


#ifndef TARGET_CORE_DEVICE_H
#define TARGET_CORE_DEVICE_H
 
extern struct block_device *__linux_blockdevice_claim (int, int, void *, int *);
extern struct block_device *linux_blockdevice_claim (int, int, void *);
extern int linux_blockdevice_release (int, int, struct block_device *);
extern int linux_blockdevice_check (int, int);
extern int iscsi_check_devices_access (se_hba_t *);
extern void iscsi_disable_devices_for_hba (se_hba_t *);
extern void se_release_device_for_hba (se_device_t *);
extern se_device_t *core_get_device_from_transport (se_hba_t *, se_dev_transport_info_t *);
extern int se_claim_physical_device (se_hba_t *, se_devinfo_t *, struct iscsi_target *);
extern int se_release_physical_device (struct iscsi_target *, se_devinfo_t *, se_hba_t *);
extern void se_clear_dev_ports (se_device_t *);
extern int se_free_virtual_device (se_device_t *, se_hba_t *);
extern int iscsi_check_hba_for_virtual_device (struct iscsi_target *, se_devinfo_t *, se_hba_t *);
extern int iscsi_create_virtual_device (se_hba_t *, se_devinfo_t *, struct iscsi_target *);
extern void se_dev_start (se_device_t *);
extern void se_dev_stop (se_device_t *);
extern se_hba_t *core_get_hba_from_hbaid (struct iscsi_target *tg,
					      se_dev_transport_info_t *dti,
					      int add);
extern void se_dev_set_default_attribs (se_device_t *);
extern int se_dev_set_attrib (se_device_t *, u32, u32, int);

#endif /* TARGET_CORE_DEVICE_H */
