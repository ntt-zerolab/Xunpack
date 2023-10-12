#!/usr/bin/env python3

import sys
from elftools.elf.elffile import ELFFile
from elfpack import ELFPack
from elfesteem.elf import *
import struct 
import subprocess
import os

from argparse import ArgumentParser

#sudo mount -o loop rootfs.ext2 /mnt/rootfs/
## copy `S99unpack'
#sudo cp ../../../scripts/S99unpack /mnt/rootfs/etc/init.d/S99unpack
#sudo chmod +x /mnt/rootfs/etc/init.d/S99unpack
## copy malware with changing its name to `malware.exe`
#sudo cp ${1} /mnt/rootfs/root/malware.exe
#sudo chmod +x /mnt/rootfs/root/malware.exe
#sudo umount /mnt/rootfs
#exec /workfolder/unpacker/qemu/build/qemu-system-mips -M malta -kernel vmlinux -drive file=rootfs.ext2,format=raw -append "rootwait root=/dev/hda" -net nic,model=pcnet -net user -qmp unix:./qmp-sock,server,nowait -plugin /workfolder/unpacker/qemu/build/contrib/plugins/libxunpack.so,arg=start_addr:${ENTRYPOINT},arg=target_range:0x00400000:0x000089ba,arg=target_range:0x00410000:0x00011f98 -D /tmp/qemu.log -d plugin -snapshot ${EXTRA_ARGS}

def virt2raw(elf, ep):
    for seg in elf.iter_segments():
        vaddr = seg.header['p_vaddr']
        memsz = seg.header['p_memsz']
        if ep >= vaddr and ep < vaddr+memsz:
            off = ep - vaddr
            return seg.header['p_offset'] + off

    raise ValueError()

def get_kernel_base(elf):
    base = 0xffffffffffffffff
    for seg in elf.iter_segments():
        if seg.header['p_type'] == "PT_LOAD":
            if seg.header['p_vaddr'] != 0:
                if seg.header['p_vaddr'] < base:
                    base = seg.header['p_vaddr']
    return base

def process_file(filename, vmlinux, size=None, sex=None):

    plugin_args=""

#    import IPython; IPython.embed()
#    try:
#        elf_in = ELFPack(open(filename, 'rb').read())
#    except KeyError:
#        if size is not None and sex is not None:
#            print("Trying second chance", file=sys.stderr)
#            elf_in = ELFPack(open(filename, 'rb').read(), size=size, sex=sex)
#        else:
#            raise KeyError()


    if size is not None and sex is not None:
        elf_in = ELFPack(open(filename, 'rb').read(), size=size, sex=sex)
    else:
        elf_in = ELFPack(open(filename, 'rb').read())

    e_machine   = elf_in.Ehdr.machine
    e_flags     = elf_in.Ehdr.flags
    e_entry     = elf_in.Ehdr.entry

    etnry_addr = 0
    if e_machine == EM_PPC64 and e_flags == 1: # abiv1
        # function descriptor
        entry_addr = struct.unpack(">Q", elf_in.virt.get(e_entry, e_entry+8))[0]
    else:
        #print("e_machine={} e_flags={}".format(e_machine, e_flags))
        entry_addr = e_entry

    #print("entry_addr={:016x}".format(entry_addr), file=sys.stderr)
    plugin_args+="arg=start_addr:0x{:016x}".format(entry_addr)

    start_dword = struct.unpack("I", elf_in.virt.get(entry_addr, entry_addr+4))[0]

    #print("start_dword 0x{:x}".format(start_dword),file=sys.stderr)
    plugin_args+=",arg=start_bytes:0x{:x}".format(start_dword)

    for p in elf_in.ph.phlist:
        if p.ph.type == PT_LOAD:
            plugin_args+=",arg=target_range:0x{:016x}:0x{:016x}".format(
                            p.ph.vaddr, 
                            p.ph.vaddr + p.ph.memsz)

    if vmlinux == "FreeBSD":
        plugin_args+=",arg=kernel_base:0x{:016x}".format(0x00800000)
    elif vmlinux == "NetBSD":
        plugin_args+=",arg=kernel_base:0x{:016x}".format(0x00800000)
    else:
        f = open(vmlinux, 'rb')
        kern = ELFFile(f)
        kernel_base = get_kernel_base(kern)
        f.close()
        plugin_args+=",arg=kernel_base:0x{:016x}".format(kernel_base)

    print(plugin_args)

if __name__ == '__main__':
    parser = ArgumentParser("generating xunpacker arguments")
    parser.add_argument("binary", help="input binary to analyze")
    parser.add_argument("kernel",   help="kernel image, e.g., vmlinux")
    parser.add_argument("--size", choices=['32','64'], help="32bt or 64bit")
    parser.add_argument("--sex", choices=['1','2'], help="1: little endian, 2: big endian")

    args = parser.parse_args()

    # argv[1]:target elf binary, argv[2]:kernel image(ELF)
    if args.size and args.sex:
        process_file(args.binary, args.kernel, int(args.size), int(args.sex))
    else:
        process_file(args.binary, args.kernel)

