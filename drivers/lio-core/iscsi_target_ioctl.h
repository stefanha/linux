/*********************************************************************************
 * Filename:  iscsi_target_ioctl.h
 *
 * This file contains the definitions related to the Target IOCTL.
 *
 * $HeadURL: svn://subversion.sbei.com/pyx/target/branches/2.9-linux-iscsi.org/pyx-target/include/iscsi_target_ioctl.h $
 *   $LastChangedRevision: 7156 $
 *   $LastChangedBy: nab $
 *   $LastChangedDate: 2007-08-28 17:17:22 -0700 (Tue, 28 Aug 2007) $
 *
 * Copyright (c) 2003, 2004, 2005 PyX Technologies, Inc.
 * Copyright (c) 2006 SBE, Inc.  All Rights Reserved.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 * For further information, contact via email: support@sbei.com
 * SBE, Inc.  San Ramon, California  U.S.A.
 *********************************************************************************/


#ifndef ISCSI_TARGET_IOCTL_H
#define ISCSI_TARGET_IOCTL_H

#define IOCTL_BUFFER_LEN	16384
#define IOCTL_NET_DEV		12
#define IOCTL_IQN		224
#define IOCTL_PARAM_BUF_LEN	256
#define IOCTL_PARAM_IP6_LEN	48
/*
 * The EVPD params must not exceed ISCSI_PARAM_BUF_LEN
 */
#define PARAM_EVPD_UNIT_SERIAL_LEN	36
#define PARAM_EVDP_DEVICE_IDENT_LEN	68
#define PARAM_LVM_UUID_LEN		48 /* Must be smaller than IOCTL_PARAM_BUF_LEN */
      
typedef  enum {SNAPSHOT_POLICY_INVALID,
	       SNAPSHOT_POLICY_KILL_OLDEST,
	       SNAPSHOT_POLICY_SWITCH_TO_READONLY} snapshot_policy_t;


struct iscsi_target {
  char out_buf[IOCTL_BUFFER_LEN];
  char dev[IOCTL_NET_DEV];
  unsigned char ip6[IOCTL_PARAM_IP6_LEN];
  unsigned char ip6_ex[IOCTL_PARAM_IP6_LEN];
  char key[IOCTL_PARAM_BUF_LEN];
  char value[IOCTL_PARAM_BUF_LEN];
  char keytext[513]; /* key size + = + value size */
  char targetname[IOCTL_IQN+1];
  unsigned int ioctl_ret;
  short debug_type;
  short force;
  short int cid;
  short int port;
  short int port_ex;
  short int tpgt;
  int count;
  int hba_type;
  int na_params_set_count;
  int internal_dma_alloc;
  int pata_if_id;
  int pata_primary;
  int out_state;
  int out_count;
  int out_count_cur;
  int raid_devices;
  int raid_type;
  int rd_direct;
  int scsi_channel_id;
  int scsi_host_id;
  int scsi_lun_id;
  int scsi_target_id;
  int iscsi_channel_id;   /* T/Initiator support */
  int os_claim_devices;   /* T/Initiator support */
  int ta_params_set_count;
  unsigned short int isid;
  unsigned short int tsih;
  unsigned int hba_id;
  unsigned int fd_device_id;
  unsigned int fd_host_id;
  unsigned int iblock_host_id;
  unsigned int iblock_major;
  unsigned int iblock_minor;
  unsigned int na_attrib;
  unsigned int na_params_set;
  unsigned int na_value;
  unsigned int net_params_set;
  unsigned int ip;
  unsigned int ip_ex;
  unsigned int iscsi_lun;
  unsigned int mapped_lun;
  unsigned int lun_access;
  unsigned int hba_params_set;
  unsigned int params_set;
  unsigned int out_size;
  unsigned int out_buf_size;
  unsigned int queue_depth;
  unsigned int raid_dev;
  unsigned int raid_id;
  unsigned int raid_chunksize;
  unsigned int rd_device_id;
  unsigned int rd_host_id;
  unsigned int rd_pages;
  unsigned int sid;
  unsigned int ta_attrib;
  unsigned int ta_params_set;
  unsigned int ta_value;
  unsigned int vol_id;
  unsigned int uu_id[4];  /* 128-bit Universal Unit Identifier */
  unsigned int vt_device_id;
  unsigned int vt_host_id;
  unsigned int vt_hw_id;
  unsigned int mc_device_id;
  unsigned int mc_host_id;
  unsigned int mc_hw_id;
  unsigned long long sectors __attribute__ ((aligned (8))); /* must keep long longs aligned */
  unsigned long long fd_dev_size;
  
  unsigned int repl_params_set;
  unsigned int repl_id;              /* target-ctl repl_id=N */
  unsigned int repl_devid_to;        /* target-ctl replcreate repl_devid_to */
  unsigned int repl_reserve;         /* target-ctl raidaddev ... repl_reserve=1 */
  unsigned int repl_qdepth;          /* target-ctl raidaddev ... repl_queue_depth=N */
  unsigned int repl_ack_mode;        /* target-ctl raidaddev ... repl_sync/repl_async=1 */
  unsigned int repl_policy;          /* target-ctl replpolicy */
  unsigned int repl_nice;            /* target-ctl replnice */

  unsigned int       snap_params_set;
  unsigned int       snap_nice;
  unsigned long long snap_time;
  unsigned long long snap_data_sectors;
  unsigned long long snap_snap_sectors;
  unsigned long long snap_max_trans_update;
  unsigned long long snap_update_interval;
  snapshot_policy_t  snap_policy;
};

typedef struct iscsi_target  iscsi_target_t;


#ifdef __KERNEL__
#ifdef ISCSI_TARGET_IOCTL_C

#include <linux/miscdevice.h>
#include <linux/major.h>

extern int iscsi_open (struct inode *, struct file *);
extern int iscsi_close(struct inode *, struct file *);
extern int iscsi_ioctl(struct inode *, struct file *, unsigned int, unsigned long);
#ifdef CONFIG_COMPAT
extern long iscsi_compat_ioctl(struct file *, unsigned int, unsigned long);
#endif /* CONFIG_COMPAT */

extern se_global_t *iscsi_global;

#define ISCSI_MINOR	203

static struct file_operations iscsi_fops = {
        owner:          THIS_MODULE,
        ioctl:          iscsi_ioctl,
#ifdef CONFIG_COMPAT
	compat_ioctl:	iscsi_compat_ioctl,
#endif /* CONFIG_COMPAT */
        open:           iscsi_open,
        release:        iscsi_close,
};

struct miscdevice iscsi_dev = { ISCSI_MINOR, "iscsi1", &iscsi_fops };

#endif /* ISCSI_TARGET_IOCTL_C */
#else /* !__KERNEL__ */

#define ISCSI_TARGET_DEVICE	"/dev/iscsi1"
#define	ISCSI_TARGET_MINOR	203

#endif /* __KERNEL__ */
#endif /* ISCSI_TARGET_IOCTL_H */
