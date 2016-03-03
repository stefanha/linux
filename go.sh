#!/bin/bash
set -e

NFSUTILSDIR=../nfs-utils/utils

mode="$1"

rmmod_nofail() {
	if lsmod | grep -q "$1"
	then
		sudo rmmod "$1" || true
	fi
}

nfsd_start() {
	for mod in net/sunrpc/sunrpc.ko \
		   net/sunrpc/auth_gss/auth_rpcgss.ko \
		   fs/lockd/lockd.ko \
		   fs/nfs_common/nfs_acl.ko \
		   fs/nfsd/nfsd.ko
	do
		sudo insmod $mod dyndbg==p
	done

	sudo sysctl sunrpc.rpc_debug=65535
	sudo sysctl sunrpc.nfs_debug=65535
	sudo sysctl sunrpc.nfsd_debug=65535

	sudo systemctl start var-lib-nfs-rpc_pipefs.mount
	sudo systemctl start proc-fs-nfsd.mount
	case "$mode" in
	*tcp*)
		sudo systemctl start nfs-server.service
		;;
	*vsock*)
		sudo systemctl start rpcbind.service
		sudo "$NFSUTILSDIR/mountd/mountd"
		sudo "$NFSUTILSDIR/exportfs/exportfs" -r
		sudo "$NFSUTILSDIR/nfsd/nfsd" -TU -N3 -V4.1 -v 2049
		;;
	esac
}

nfsd_stop() {
	case "$mode" in
	*tcp*)
		sudo systemctl stop nfs-server.service
		;;
	*vsock*)
		sudo "$NFSUTILSDIR/nfsd/nfsd" 0 || true
		sudo "$NFSUTILSDIR/exportfs/exportfs" -au || true
		sudo "$NFSUTILSDIR/exportfs/exportfs" -f || true
		sudo pkill mountd || true
		sudo systemctl stop rpcbind.service
		;;
	esac
	sudo systemctl stop proc-fs-nfsd.mount
	sudo systemctl stop var-lib-nfs-rpc_pipefs.mount
	for mod in nfsd nfs_acl lockd rpcsec_gss_krb5 auth_rpcgss sunrpc
	do
		rmmod_nofail $mod
	done
}

vhost_start() {
	sudo insmod drivers/vhost/vhost.ko dyndbg==p
	sudo insmod net/vmw_vsock/vsock.ko dyndbg==p
	sudo insmod net/vmw_vsock/virtio_transport_common.ko dyndbg==p
	sudo insmod drivers/vhost/vhost_vsock.ko dyndbg==p
}

vhost_stop() {
	rmmod_nofail vhost_vsock
	rmmod_nofail virtio_transport_common
	rmmod_nofail vsock
	rmmod_nofail vhost
}

build_modules() {
	make M=net/sunrpc modules
	make M=fs/nfs modules
	make M=fs/nfsd modules
	make M=drivers/virtio CONFIG_VIRTIO_PCI=m modules
	make M=net/vmw_vsock CONFIG_VIRTIO_VSOCKETS=m modules
	make M=drivers/vhost CONFIG_VHOST_VSOCK=m modules
}

case "$mode" in
nfs_*)
	nfsd_stop
	;;
esac
vhost_stop
case "$mode" in
*stop*)
	exit
	;;
esac
build_modules
vhost_start
case "$mode" in
nfs_*)
	nfsd_start
	;;
esac

usr/gen_init_cpio initramfs/cpio-list | gzip >initramfs.gz
if [ "$mode" = "nfs_tcp" ]
then
	kill_nc_vsock() {
		sudo pkill nc-vsock
	}
	trap kill_nc_vsock EXIT
	sudo ./nc-vsock -l 2049 -t 127.0.0.1 2049 &
fi
sudo gdb -x ~/.gdbinit --ex r \
	--args ~/qemu/x86_64-softmmu/qemu-system-x86_64 \
	-m 1024 \
	-enable-kvm \
	-device vhost-vsock-pci,id=vhost-vsock-pci0,guest-cid=3 \
	-kernel arch/x86_64/boot/bzImage \
	-initrd initramfs.gz \
	-append "console=ttyS0 stefan_mode=$mode" \
	-nographic
