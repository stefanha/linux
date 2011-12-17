qla2xxx-y := qla_os.o qla_init.o qla_mbx.o qla_iocb.o qla_isr.o qla_gs.o \
		qla_dbg.o qla_sup.o qla_attr.o qla_mid.o qla_dfs.o qla_bsg.o \
        qla_nx.o qla_target.o

obj-$(CONFIG_SCSI_QLA_FC) += qla2xxx.o

tcm_qla2xxx-objs := tcm_qla2xxx_fabric.o tcm_qla2xxx_configfs.o

obj-$(CONFIG_TCM_QLA2XXX) += tcm_qla2xxx.o

EXTRA_CFLAGS    := -Idrivers/scsi/qla2xxx/ -Idrivers/target/ -Idrivers/target/tcm_qla2xxx/
