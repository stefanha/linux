CWD=$(shell pwd)

include $(CWD)/drivers/target/MCONFIG_TARGET
include $(CWD)/drivers/target/MCONFIG_ALL

obj-$(CONFIG_TARGET_CORE)		+=	target_core_mod.o
target_core_mod-objs			:=	target_core_configfs.o \
						target_core_device.o \
						target_core_hba.o \
						target_core_plugin.o \
						target_core_pr.o \
						target_core_alua.o \
						target_core_scdb.o \
						target_core_seobj.o \
						target_core_tmr.o \
						target_core_tpg.o \
						target_core_transport.o \
						target_core_ua.o \
						div64.o

ifeq ($(LINUX_IBLOCK), 1)
target_core_mod-objs			+=	target_core_iblock.o
EXTRA_CFLAGS				+=	-DPYX_IBLOCK
endif
ifeq ($(LINUX_PARALLEL_SCSI), 1)
target_core_mod-objs			+=	target_core_pscsi.o
EXTRA_CFLAGS				+=	-DPARALLEL_SCSI
endif
ifeq ($(LINUX_STGT), 1)
target_core_mod-objs			+=	target_core_stgt.o
EXTRA_CFLAGS				+=	-DSTGT_PLUGIN
endif
ifeq ($(LINUX_RAMDISK), 1)
target_core_mod-objs			+=	target_core_rd.o
EXTRA_CFLAGS				+=	-DPYX_RAMDISK
endif
ifeq ($(LINUX_FILEIO), 1)
target_core_mod-objs			+=	target_core_file.o
EXTRA_CFLAGS				+=	-DPYX_FILEIO
endif
ifeq ($(SNMP_FEATURE), 1)
target_core_mod-objs			+=	target_core_mib.o
EXTRA_CFLAGS				+=	-DSNMP_SUPPORT
endif
ifeq ($(LINUX_VPD_PAGE_CHECK), 1)
EXTRA_CFLAGS += -DLINUX_VPD_PAGE_CHECK
endif
ifeq ($(LINUX_SCSI_MEDIA_ROM), 1)
EXTRA_CFLAGS += -DLINUX_SCSI_MEDIA_ROM
endif
ifeq ($(DEBUG_DEV), 1)
EXTRA_CFLAGS += -DDEBUG_DEV
endif


EXTRA_CFLAGS+=-I$(CWD)/drivers/target/ -I$(CWD)/drivers/scsi/
EXTRA_CFLAGS+=-D_TARGET -DLINUX -DLINUX_KERNEL_26 -DLINUX_SCSI_HOST_LOCK -DLINUX_USE_SIGHAND
EXTRA_CFLAGS+=-DLINUX_SCATTERLIST_HAS_PAGE -DPYX_ISCSI_VENDOR='"Linux-iSCSI.org"'

all:
	$(MAKE) -C $(KERNEL_DIR) SUBDIRS=$(CWD) modules CWD=$(CWD) ARCH=$(ARCH) KBUILD_VERBOSE=0

install ins:
	rm -f /lib/modules/`uname -r`/kernel/drivers/scsi/iscsi_target_mod.ko
	rm -f /lib/modules/`uname -r`/kernel/drivers/iscsi/iscsi_target_mod.ko
	mkdir -p /lib/modules/`uname -r`/kernel/drivers/iscsi
	cp -f iscsi_target_mod.ko /lib/modules/`uname -r`/kernel/drivers/iscsi
	cp -f target_core_mod.ko /lib/modules/`uname -r`/kernel/drivers/iscsi
	depmod -ae



clean:
	rm -f $(foreach prog,$(target_core_mod-objs) $(obj-m),$(CWD)/$(prog)) $(CWD)/target_core_mod.mod.o
	rm -f target_core_mod.ko target_core_mod.mod.c
	rm -f .*.cmd ../common/.*.cmd .make_autoconfig *~
	rm -fr .tmp_versions


