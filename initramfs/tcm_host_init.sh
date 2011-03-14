#!/bin/sh
mount -t proc none /proc
mount -t sysfs none /sys
mount -t configfs none /sys/kernel/config
mount -t debugfs none /sys/kernel/debug
mount -t tmpfs none /tmp
insmod /lib/modules/$(uname -r)/kernel/drivers/target/tcm_vhost/tcm_vhost.ko
mknod /dev/vhost-scsi c $(tr ':' ' ' </sys/class/misc/vhost-scsi/dev)
cd /sys/kernel/config/target
/usr/bin/qemu -m 512 -nographic -kernel /boot/bzImage -initrd /boot/initramfs.gz -append console=ttyS0 -device virtio-scsi-pci,wwpn=0,tpgt=0
exec /bin/sh -i
