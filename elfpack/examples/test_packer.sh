#!/bin/sh

# x86
python3 packer_x86.py ../test/packers/hello.i686 hello.i686.packed --bit=32
chmod +x hello.i686.packed
/workfolder/unpacker/qemu/build/qemu-i386 hello.i686.packed

# x86_64
python3 packer_x86.py ../test/packers/hello.x86_64 hello.x86_64.packed --bit=64
chmod +x hello.x86_64.packed
/workfolder/unpacker/qemu/build/qemu-x86_64 hello.x86_64.packed

# riscv32
python3 packer_riscv.py ../test/packers/hello.riscv32 hello.riscv32.packed --bit=32
chmod +x hello.riscv32.packed
/workfolder/unpacker/qemu/build/qemu-riscv32 hello.riscv32.packed

# riscv64
python3 packer_riscv.py ../test/packers/hello.riscv64 hello.riscv64.packed --bit=64
chmod +x hello.riscv64.packed
/workfolder/unpacker/qemu/build/qemu-riscv64 hello.riscv64.packed

# sparc32
python3 packer_sparc.py ../test/packers/hello.sparc32 hello.sparc32.packed --bit=32
chmod +x hello.sparc32.packed
/workfolder/unpacker/qemu/build/qemu-sparc32 hello.sparc32.packed

# sparc64
python3 packer_sparc.py ../test/packers/hello.sparc64 hello.sparc64.packed --bit=64
chmod +x hello.sparc64.packed
/workfolder/unpacker/qemu/build/qemu-sparc64 hello.sparc64.packed



