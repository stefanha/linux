CWD=$(shell pwd)

# Transport Plugins and Devices.
 #
LINUX_PARALLEL_SCSI ?= 1
LINUX_STGT ?= 1
LINUX_PARALLEL_ATA ?= 0
LINUX_IBLOCK ?= 1
LINUX_RAMDISK ?= 1
LINUX_FILEIO ?= 1

LINUX_VPD_PAGE_CHECK?=1

DEBUG_DEV ?= 0
SNMP_FEATURE ?= 1

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
						target_core_ua.o

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
ifeq ($(DEBUG_DEV), 1)
EXTRA_CFLAGS += -DDEBUG_DEV
endif

EXTRA_CFLAGS+=-I$(CWD)/drivers/target/ -I$(CWD)/drivers/scsi/
