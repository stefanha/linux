##################################################################################
# Filename:  Makefile
#
# Copyright (c) 2002, 2003, 2004, 2005 PyX Technologies, Inc.
# Copyright (c) 2005, 2006, 2007 SBE, Inc. 
# Copyright (c) 2007 Rising Tide Software, Inc.
#
# Nicholas A. Bellinger <nab@kernel.org>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
#
##################################################################################

CWD=$(shell pwd)


include $(CWD)/drivers/lio-core/MCONFIG_TARGET
include $(CWD)/drivers/lio-core/MCONFIG_ALL

obj-m				+=	iscsi_target_mod.o
iscsi_target_mod-objs		+=	iscsi_crc.o \
					iscsi_debug_opcodes.o \
					iscsi_parameters.o \
					iscsi_seq_and_pdu_list.o \
					iscsi_serial.o \
					iscsi_thread_queue.o \
					iscsi_target_datain_values.o \
					$(ISCSI_TARGET_DEBUGERL) \
					iscsi_target_device.o \
					iscsi_target_discovery.o \
					iscsi_target_erl0.o \
					iscsi_target_erl1.o \
					iscsi_target_erl2.o \
					iscsi_target_feature_obj.o \
					$(ISCSI_TARGET_FILE) \
					iscsi_target_hba.o \
					iscsi_target_info.o \
					iscsi_target_ioctl.o \
					iscsi_target_linux_proc.o \
					iscsi_target_login.o \
					iscsi_target_nego.o \
					iscsi_target_nodeattrib.o \
					iscsi_target_plugin.o \
					$(ISCSI_TARGET_PSCSI) \
					$(ISCSI_TARGET_RD) \
					iscsi_target_reportluns.o \
					iscsi_target_scdb.o \
					iscsi_target_seobj.o \
					iscsi_target_tmr.o \
					iscsi_target_tpg.o \
					iscsi_target_transport.o \
					iscsi_target_util.o \
					$(ISCSI_TARGET_VROM) \
					iscsi_target.o \
                                        div64.o

ifeq ($(LINUX_IBLOCK), 1)
iscsi_target_mod-objs           +=      iscsi_target_iblock.o
EXTRA_CFLAGS                    +=      -DPYX_IBLOCK
endif
ifeq ($(DEBUG_ERL), 1)
iscsi_target_mod-objs           +=      iscsi_target_debugerl.o
EXTRA_CFLAGS                    +=      -DDEBUG_ERL
endif
ifeq ($(LINUX_PARALLEL_SCSI), 1)
iscsi_target_mod-objs           +=      iscsi_target_pscsi.o
EXTRA_CFLAGS                    +=      -DPARALLEL_SCSI
endif
ifeq ($(LINUX_RAMDISK), 1)
iscsi_target_mod-objs           +=      iscsi_target_rd.o
EXTRA_CFLAGS                    +=      -DPYX_RAMDISK
endif
ifeq ($(LINUX_FILEIO), 1)
iscsi_target_mod-objs           +=      iscsi_target_file.o
EXTRA_CFLAGS                    +=      -DPYX_FILEIO
endif
ifeq ($(LINUX_VROM), 1)
iscsi_target_mod-objs           +=      iscsi_target_vrom.o
EXTRA_CFLAGS                    +=      -DPYX_VROM
endif
ifeq ($(LINUX_VTAPE), 1)
iscsi_target_mod-objs           +=      iscsi_target_vt.o
EXTRA_CFLAGS                    +=      -DPYX_VTAPE
endif
ifeq ($(LINUX_MEDIA_CHANGER), 1)
iscsi_target_mod-objs           +=      iscsi_target_mc.o
EXTRA_CFLAGS                    +=      -DPYX_MEDIA_CHANGER
endif
ifeq ($(SNMP_FEATURE), 1)
iscsi_target_mod-objs           +=      iscsi_target_mib.o
EXTRA_CFLAGS                    +=      -DSNMP_SUPPORT
endif
ifeq ($(ERLTWO), 1)
EXTRA_CFLAGS += -DERLONE -DERLTWO
else
ifeq ($(ERLONE), 1)
EXTRA_CFLAGS += -DERLONE
endif
endif
ifeq ($(LINUX_EVPD_PAGE_CHECK), 1)
EXTRA_CFLAGS += -DLINUX_EVPD_PAGE_CHECK
endif
ifeq ($(LINUX_SCSI_MEDIA_ROM), 1)
EXTRA_CFLAGS += -DLINUX_SCSI_MEDIA_ROM
endif

ifeq ($(DEBUG_DEV), 1)
EXTRA_CFLAGS += -DDEBUG_DEV
endif


ifeq ($(DEBUG_ISCSI),1)
EXTRA_CFLAGS += -DCONFIG_ISCSI_DEBUG=1
endif

EXTRA_CFLAGS+=-I$(CWD)/drivers/lio-core/
EXTRA_CFLAGS+=-D_TARGET -DLINUX -DLINUX_KERNEL_26 -DLINUX_SCSI_HOST_LOCK -DLINUX_USE_SIGHAND
EXTRA_CFLAGS+=-DLINUX_SCATTERLIST_HAS_PAGE -DPYX_ISCSI_VENDOR='"Linux-iSCSI.org"'  -DIQN_PREFIX='"iqn.2003-01.org.linux-iscsi"'

all:
	$(MAKE) -C $(KERNEL_DIR) SUBDIRS=$(CWD) modules CWD=$(CWD) ARCH=$(ARCH) KBUILD_VERBOSE=0

install ins:
	rm -f /lib/modules/`uname -r`/kernel/drivers/scsi/iscsi_target_mod.ko
	rm -f /lib/modules/`uname -r`/kernel/drivers/iscsi/iscsi_target_mod.ko
	mkdir -p /lib/modules/`uname -r`/kernel/drivers/iscsi
	cp -f iscsi_target_mod.ko /lib/modules/`uname -r`/kernel/drivers/iscsi
	depmod -ae



clean:
	rm -f $(foreach prog,$(iscsi_target_mod-objs) $(obj-m),$(CWD)/$(prog)) $(CWD)/iscsi_target_mod.mod.o
	rm -f iscsi_target_mod.ko iscsi_target_mod.mod.c 
	rm -f .*.cmd ../common/.*.cmd .make_autoconfig *~
	rm -fr .tmp_versions


