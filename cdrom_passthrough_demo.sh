#!/bin/bash
mount -t configfs none /sys/kernel/config
modprobe target_core_mod
modprobe target_core_pscsi
modprobe tcm_vhost
cd /sys/kernel/config/target/
mkdir -p /sys/kernel/config/target/vhost/naa.60014059811d880b/tpgt_1/lun/lun_0
mkdir -p /sys/kernel/config/target/core/pscsi_0/sr0
echo -n 'scsi_host_id=1,scsi_channel_id=0,scsi_target_id=0,scsi_lun_id=0' >/sys/kernel/config/target/core/pscsi_0/sr0/control
echo -n '/dev/sr0' >/sys/kernel/config/target/core/pscsi_0/sr0/udev_path
echo -n 1 >/sys/kernel/config/target/core/pscsi_0/sr0/enable
echo -n naa.60014059811d880d >/sys/kernel/config/target/vhost/naa.60014059811d880b/tpgt_1/nexus
cd /sys/kernel/config/target/vhost/naa.60014059811d880b/tpgt_1/lun/lun_0
ln -s ../../../../../core/pscsi_0/sr0/ .
cd - >/dev/null
#/home/stefanha/qemu/x86_64-softmmu/qemu-system-x86_64 -enable-kvm -m 512 -nographic -kernel arch/x86/boot/bzImage -initrd virtio_scsi_guest_initramfs.gz -append console=ttyS0 -vhost-scsi id=vhost-scsi0,wwpn=naa.60014059811d880b,tpgt=1 -device virtio-scsi-pci,vhost-scsi=vhost-scsi0,event_idx=off
