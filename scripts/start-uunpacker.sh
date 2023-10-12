#!/bin/sh
(
# set uuid
if [ $# -ge 2 ]; then
    UUID=$2
else
    UUID=`uuidgen`
fi

QEMU_ROOT=/home/ubuntu/qemu/build

exec qemu-x86_64 -plugin ${QEMU_ROOT}/contrib/plugins/libuunpack.so,arg=uuid:${UUID} -D /tmp/qemu.log -d plugin ${1}

)
