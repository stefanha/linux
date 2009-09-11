CWD=$(shell pwd)


PYX_ISCSI_VENDOR ?="Linux-iSCSI.org"
LIO_TARGET_CONFIGFS?=1

MODVER ?= 1
USEGDB ?= 1
DEBUG_ISCSI ?= 0
DEBUG_OPCODES ?= 0
SNMP_FEATURE ?= 1

obj-$(CONFIG_LIO_TARGET)	+=	iscsi_target_mod.o
iscsi_target_mod-objs		:=	iscsi_auth_chap.o \
					iscsi_crc.o \
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
					iscsi_target_login.o \
					iscsi_target_nego.o \
					iscsi_target_nodeattrib.o \
					iscsi_target_tmr.o \
					iscsi_target_tpg.o \
					iscsi_target_util.o \
					iscsi_target.o \
                                        div64.o

ifeq ($(DEBUG_ERL), 1)
iscsi_target_mod-objs           +=      iscsi_target_debugerl.o
EXTRA_CFLAGS                    +=      -DDEBUG_ERL
endif
ifeq ($(SNMP_FEATURE), 1)
iscsi_target_mod-objs           +=      iscsi_target_mib.o
EXTRA_CFLAGS                    +=      -DSNMP_SUPPORT
endif
ifeq ($(LIO_TARGET_CONFIGFS), 1)
iscsi_target_mod-objs		+=	iscsi_target_configfs.o
EXTRA_CFLAGS			+=	-DLIO_TARGET_CONFIGFS
endif

EXTRA_CFLAGS += -DERLONE -DERLTWO

ifeq ($(DEBUG_ISCSI),1)
EXTRA_CFLAGS += -DCONFIG_ISCSI_DEBUG=1
endif

EXTRA_CFLAGS+=-I$(CWD)/drivers/lio-core/ -I$(CWD)/drivers/scsi/
EXTRA_CFLAGS+=-D_TARGET -DLINUX -DLINUX_KERNEL_26 -DLINUX_SCSI_HOST_LOCK -DLINUX_USE_SIGHAND
EXTRA_CFLAGS+=-DLINUX_SCATTERLIST_HAS_PAGE -DPYX_ISCSI_VENDOR='"Linux-iSCSI.org"'  -DIQN_PREFIX='"iqn.2003-01.org.linux-iscsi"'

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
	rm -f $(foreach prog,$(iscsi_target_mod-objs) $(obj-m),$(CWD)/$(prog)) $(CWD)/iscsi_target_mod.mod.o
	rm -f iscsi_target_mod.ko iscsi_target_mod.mod.c
	rm -f .*.cmd ../common/.*.cmd .make_autoconfig *~
	rm -fr .tmp_versions


