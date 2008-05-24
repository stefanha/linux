/*********************************************************************************
 * Filename:  iscsi_target_linux_proc.c
 *
 * This file contains the Linux Proc utility functions.
 *
 * Copyright (c) 2004, 2005 PyX Technologies, Inc.
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


#define ISCSI_TARGET_LINUX_PROC_C

#include <linux/string.h>
#include <linux/version.h>
#include <linux/timer.h>
#include <linux/blkdev.h>
#include <linux/proc_fs.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/smp_lock.h>
#include <linux/in.h>
#include <net/sock.h>
#include <net/tcp.h>
#include <scsi/scsi.h>
#include <scsi/scsi_host.h>

#include <iscsi_linux_os.h>
#include <iscsi_linux_defs.h>

#include <iscsi_lists.h>
#include <iscsi_debug.h>
#include <iscsi_protocol.h>
#include <iscsi_target_core.h>
#include <iscsi_target_ioctl.h>
#include <iscsi_target_transport.h>
#include <iscsi_target_tpg.h>
#include <iscsi_target_util.h>

#include <iscsi_target_plugin.h>
#include <iscsi_target_feature_obj.h>
#include <iscsi_target_feature_plugins.h>

#include <iscsi_target_info.h>

#undef ISCSI_TARGET_LINUX_PROC_C

extern se_global_t *iscsi_global;

#define ISCSI_MAX_PROC_LENGTH   PAGE_SIZE

#if 0
# define PROC_DEV_INFO_FUNCTION(num)								\
	int linux_proc_dev_##num##_info (char *buf, char **start, off_t offset, int len)	\
	{											\
		return(iscsi_tpg_get_lun_info(NULL, num, buf, ISCSI_MAX_PROC_LENGTH, 1, 0, 0));	\
	}

# define PROC_SESS_INFO_FUNCTION(num)								\
	int linux_proc_sess_##num##_info (char *buf, char **start, off_t offset, int len)	\
	{											\
		return(iscsi_tpg_get_sess_info(NULL, num, buf, ISCSI_MAX_PROC_LENGTH, 1, 0, 0));	\
	}

# define PROC_TPG_INFO_FUNCTION(num)								\
	int linux_proc_tpg_##num##_info (char *buf, char **start, off_t offset, int len)	\
	{											\
		return(iscsi_tpg_get_tpg_info(NULL, num, buf, ISCSI_MAX_PROC_LENGTH, 1, 0, 0));	\
	}

#define MK_PROC_FUNCS(n) 		\
	PROC_DEV_INFO_FUNCTION(n);	\
	PROC_SESS_INFO_FUNCTION(n);	\
	PROC_TPG_INFO_FUNCTION(n);

MK_PROC_FUNCS(0);MK_PROC_FUNCS(1);MK_PROC_FUNCS(2);MK_PROC_FUNCS(3);MK_PROC_FUNCS(4);
MK_PROC_FUNCS(5);MK_PROC_FUNCS(6);MK_PROC_FUNCS(7);MK_PROC_FUNCS(8);MK_PROC_FUNCS(9);
MK_PROC_FUNCS(10);MK_PROC_FUNCS(11);MK_PROC_FUNCS(12);MK_PROC_FUNCS(13);MK_PROC_FUNCS(14);
MK_PROC_FUNCS(15);MK_PROC_FUNCS(16);MK_PROC_FUNCS(17);MK_PROC_FUNCS(18);MK_PROC_FUNCS(19);
MK_PROC_FUNCS(20);MK_PROC_FUNCS(21);MK_PROC_FUNCS(22);MK_PROC_FUNCS(23);MK_PROC_FUNCS(24);
MK_PROC_FUNCS(25);MK_PROC_FUNCS(26);MK_PROC_FUNCS(27);MK_PROC_FUNCS(28);MK_PROC_FUNCS(29);
MK_PROC_FUNCS(30);MK_PROC_FUNCS(31);MK_PROC_FUNCS(32);MK_PROC_FUNCS(33);MK_PROC_FUNCS(34);
MK_PROC_FUNCS(35);MK_PROC_FUNCS(36);MK_PROC_FUNCS(37);MK_PROC_FUNCS(38);MK_PROC_FUNCS(39);
MK_PROC_FUNCS(40);MK_PROC_FUNCS(41);MK_PROC_FUNCS(42);MK_PROC_FUNCS(43);MK_PROC_FUNCS(44);
MK_PROC_FUNCS(45);MK_PROC_FUNCS(46);MK_PROC_FUNCS(47);MK_PROC_FUNCS(48);MK_PROC_FUNCS(49);
MK_PROC_FUNCS(50);MK_PROC_FUNCS(51);MK_PROC_FUNCS(52);MK_PROC_FUNCS(53);MK_PROC_FUNCS(54);
MK_PROC_FUNCS(55);MK_PROC_FUNCS(56);MK_PROC_FUNCS(57);MK_PROC_FUNCS(58);MK_PROC_FUNCS(59);
MK_PROC_FUNCS(60);MK_PROC_FUNCS(61);MK_PROC_FUNCS(62);MK_PROC_FUNCS(63);

#define MK_FUNCTION_POINTER_ARRAY(name)						\
	int (*linux_proc_##name##_array[])(char *, char **, off_t, int) = {	\
		linux_proc_##name##_0_info, linux_proc_##name##_1_info,         \
            	linux_proc_##name##_2_info, linux_proc_##name##_3_info,         \
             	linux_proc_##name##_4_info, linux_proc_##name##_5_info,         \
		linux_proc_##name##_6_info, linux_proc_##name##_7_info,         \
          	linux_proc_##name##_8_info, linux_proc_##name##_9_info,         \
          	linux_proc_##name##_10_info, linux_proc_##name##_11_info,       \
          	linux_proc_##name##_12_info, linux_proc_##name##_13_info,       \
            	linux_proc_##name##_14_info, linux_proc_##name##_15_info,       \
         	linux_proc_##name##_16_info, linux_proc_##name##_17_info,       \
         	linux_proc_##name##_18_info, linux_proc_##name##_19_info,       \
         	linux_proc_##name##_20_info, linux_proc_##name##_21_info,       \
         	linux_proc_##name##_22_info, linux_proc_##name##_23_info,       \
		linux_proc_##name##_24_info, linux_proc_##name##_25_info,       \
        	linux_proc_##name##_26_info, linux_proc_##name##_27_info,       \
        	linux_proc_##name##_28_info, linux_proc_##name##_29_info,       \
        	linux_proc_##name##_30_info, linux_proc_##name##_31_info,       \
        	linux_proc_##name##_32_info, linux_proc_##name##_33_info,       \
        	linux_proc_##name##_34_info, linux_proc_##name##_35_info,       \
        	linux_proc_##name##_36_info, linux_proc_##name##_37_info,       \
     		linux_proc_##name##_38_info, linux_proc_##name##_39_info,       \
        	linux_proc_##name##_40_info, linux_proc_##name##_41_info,       \
       		linux_proc_##name##_42_info, linux_proc_##name##_43_info,       \
       		linux_proc_##name##_44_info, linux_proc_##name##_45_info,       \
      		linux_proc_##name##_46_info, linux_proc_##name##_47_info,       \
      		linux_proc_##name##_48_info, linux_proc_##name##_49_info,       \
      		linux_proc_##name##_50_info, linux_proc_##name##_51_info,       \
      		linux_proc_##name##_52_info, linux_proc_##name##_53_info,       \
      		linux_proc_##name##_54_info, linux_proc_##name##_55_info,       \
      		linux_proc_##name##_56_info, linux_proc_##name##_57_info,       \
      		linux_proc_##name##_58_info, linux_proc_##name##_59_info,       \
     		linux_proc_##name##_60_info, linux_proc_##name##_61_info,       \
      		linux_proc_##name##_62_info, linux_proc_##name##_63_info,       };

MK_FUNCTION_POINTER_ARRAY(dev);
MK_FUNCTION_POINTER_ARRAY(sess);
MK_FUNCTION_POINTER_ARRAY(tpg);

#define GET_PROC_FUNCTION(name, num)    linux_proc_##name##_array[num];

#else

static int dev_proc_seq_show (struct seq_file *m, void *p)
{
	return(0);
}

static int dev_proc_fops_open (struct inode *inode, struct file *file)
{
	return(single_open(file, dev_proc_seq_show, PDE(inode)->data));
}

static const struct file_operations dev_proc_ops = {
	.open		= dev_proc_fops_open,
	.read 		= seq_read,
	.llseek		= seq_lseek,
	.release	= single_release,
	.owner		= THIS_MODULE,
};

static int sess_proc_seq_show (struct seq_file *m, void *p)
{
	return(0);
}

static int sess_proc_fops_open (struct inode *inode, struct file *file)
{
	return(single_open(file, sess_proc_seq_show, PDE(inode)->data));
}

static const struct file_operations sess_proc_ops = {
	.open		= sess_proc_fops_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= single_release,
	.owner		= THIS_MODULE,
};

static int tpg_proc_seq_show (struct seq_file *m, void *p)
{
	return(0);
}

static int tpg_proc_fops_open (struct inode *inode, struct file *file)
{
	return(single_open(file, tpg_proc_seq_show, PDE(inode)->data));
}

static const struct file_operations tpg_proc_ops = {
	.open		= tpg_proc_fops_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= single_release,
	.owner		= THIS_MODULE,
};

#endif

extern int iscsi_OS_register_info_handlers (u16 tpgt)
{
#if 0
	unsigned char dir_buf[128], dev_buf[128], sess_buf[128];
	unsigned char tpg_buf[128];
	struct proc_dir_entry *iscsi_tpg;
	struct proc_dir_entry *dev_info, *sess_info, *tpg_info;	
	int (*proc_func)(char *, char **, off_t, int);

	memset(dir_buf, 0, 128);
	memset(dev_buf, 0, 128);
	memset(sess_buf, 0, 128);
	memset(tpg_buf, 0, 128);
	
	sprintf(dir_buf, "iscsi_target/tpg_%d", tpgt);
	if (!(iscsi_tpg = proc_mkdir(dir_buf, 0))) {
		TRACE_ERROR("proc_mkdir failed\n");
		return(-1);
	}

	sprintf(dev_buf, "iscsi_target/tpg_%d/dev_info", tpgt);
	if (!(dev_info = proc_create_data(dev_buf, 0, iscsi_tpg, &dev_proc_ops, (void *)&tpgt))) {
		remove_proc_entry(dir_buf, 0);
		TRACE_ERROR("create_proc_data() failed.\n");
		return(-1);
	}

	sprintf(sess_buf, "iscsi_target/tpg_%d/sess_info", tpgt);
	if (!(sess_info = proc_create_data(sess_buf, 0, iscsi_tpg, &sess_proc_ops, (void *)&tpgt))) {
		remove_proc_entry(dev_buf, 0);
		remove_proc_entry(dir_buf, 0);
		TRACE_ERROR("create_proc_data() failed.\n");
		return(-1);
	}

	sprintf(tpg_buf, "iscsi_target/tpg_%d/tpg_info", tpgt);
	if (!(tpg_info = proc_create_data(tpg_buf, 0, iscsi_tpg, &tpg_proc_ops, (void *)&tpgt))) {
		remove_proc_entry(sess_buf, 0);
		remove_proc_entry(dev_buf, 0);
		remove_proc_entry(dir_buf, 0);
		TRACE_ERROR("create_proc_data() failed.\n");
		return(-1);
	}
#endif		
	return(0);
}

extern void iscsi_OS_unregister_info_handlers(u16 tpgt)
{
#if 0
	unsigned char dir_buf[128], dev_buf[128], sess_buf[128];
	unsigned char tpg_buf[128];

	memset(dir_buf, 0, 128);
	memset(dev_buf, 0, 128);
	memset(sess_buf, 0, 128);
	memset(tpg_buf, 0, 128);
	
	sprintf(tpg_buf, "iscsi_target/tpg_%d/tpg_info", tpgt);
	remove_proc_entry(tpg_buf, 0);
	sprintf(sess_buf, "iscsi_target/tpg_%d/sess_info", tpgt);
	remove_proc_entry(sess_buf, 0);
	sprintf(dev_buf, "iscsi_target/tpg_%d/dev_info", tpgt);
	remove_proc_entry(dev_buf, 0);
	sprintf(dir_buf, "iscsi_target/tpg_%d", tpgt);
	remove_proc_entry(dir_buf, 0);
#endif	
	return;
}

