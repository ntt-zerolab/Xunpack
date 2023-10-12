#!/bin/sh
(
# set uuid
if [ $# -ge 2 ]; then
    UUID=$2
else
    UUID=`uuidgen`
fi
# set seeptime
if [ $# -ge 3 ]; then
    SLEEPTIME=$3
else
    SLEEPTIME=300
fi

EXTRA_ARGS='-serial stdio'
#ENTRYPOINT=`objdump -x ${1} | egrep "start address 0x[0-9|a-f]+" | cut -d ' ' -f 3`
IMAGE=bzImage
QEMU_ROOT=/home/ubuntu/qemu/build
SCRIPT_ROOT=/home/ubuntu/scripts
VMLINUX_TO_ELF=/home/ubuntu/vmlinux-to-elf/vmlinux-to-elf

res=`file ${IMAGE} | grep ELF`

if [ $? = 0 ]; then
    cp ${IMAGE} /tmp/vmlinux
else
    ${VMLINUX_TO_ELF} ${IMAGE} /tmp/vmlinux
fi

# copy `S99unpack'
# copy malware with changing its name to `malware.exe`
sudo mount -o loop rootfs.ext2 /mnt/rootfs/
sudo cp ${SCRIPT_ROOT}/S99unpack /mnt/rootfs/etc/init.d/S99unpack
sudo chmod +x /mnt/rootfs/etc/init.d/S99unpack
sudo cp ${1} /mnt/rootfs/root/malware.exe
sudo chmod +x /mnt/rootfs/root/malware.exe
sudo umount /mnt/rootfs

# generate the arguments for xunpacker
PLUGIN_ARGS=`python3 ${SCRIPT_ROOT}/gen_args.py ${1} /tmp/vmlinux --size=64 --sex=1`
rm /tmp/vmlinux

echo qemu-system-x86_64 -M pc -m 256 -kernel ${IMAGE} -drive file=rootfs.ext2,if=virtio,format=raw -append \"rootwait root=/dev/vda console=tty1 console=ttyS0\" -net nic,model=virtio -net user -qmp unix:./qmp-sock,server,nowait -plugin ${QEMU_ROOT}/contrib/plugins/libxunpack64.so,${PLUGIN_ARGS},arg=uuid:${UUID} -D /tmp/qemu.log -d plugin -snapshot ${EXTRA_ARGS} &

exec qemu-system-x86_64 -M pc -m 256 -kernel ${IMAGE} -drive file=rootfs.ext2,if=virtio,format=raw -append "rootwait root=/dev/vda console=tty1 console=ttyS0"  -net nic,model=virtio -net user -qmp unix:./qmp-sock,server,nowait -plugin ${QEMU_ROOT}/contrib/plugins/libxunpack64.so,${PLUGIN_ARGS},arg=uuid:${UUID} -D /tmp/qemu.log -d plugin -snapshot ${EXTRA_ARGS} &

sleep ${SLEEPTIME}

python3 ${SCRIPT_ROOT}/qmp/guest_terminate.py -s `pwd`/qmp-sock

)
