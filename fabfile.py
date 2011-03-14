from fabric.api import *

def _initramfs(name):
    local('initramfs/geninitramfs %s >%s_initramfs.gz' % (name, name))

def virtio_scsi_guest_initramfs():
    _initramfs('virtio_scsi_guest')

def tcm_host_initramfs():
    _initramfs('tcm_host')

def initramfs():
    virtio_scsi_guest_initramfs()
    tcm_host_initramfs()

def run():
    local('/home/stefanha/qemu/x86_64-softmmu/qemu-system-x86_64 -enable-kvm -m 1024 -nographic -kernel arch/x86/boot/bzImage -initrd tcm_host_initramfs.gz -append console=ttyS0', capture=False)
