#!/bin/sh

# i686
python3 recon_elf.py --arch=i686 ../test/recon/dump/i686-glibc/
python3 /workfolder/unpacker/xunpacker_assist_tools/simple_matcher.py /workfolder/unpacker/xunpacker_assist_tools/patterns/x86-i686--glibc--stable-2020.08-1.yara _output.elf | tee _output.elf.funclist
python3 recon_symtab.py _output.elf _output.elf.funclist _output.elf-sym
readelf -S _output.elf-sym
objdump -d -M intel _output.elf-sym | grep "<_start>"
objdump -d -M intel ../test/recon/orig/i686-buildroot-2020.08.3-glibc | grep "<_start>"

# x86_64
python3 recon_elf.py --arch=x86_64 ../test/recon/dump/x86_64-glibc/
python3 /workfolder/unpacker/xunpacker_assist_tools/simple_matcher.py /workfolder/unpacker/xunpacker_assist_tools/patterns/x86-64-core-i7--glibc--stable-2020.08-1.yara _output.elf | tee _output.elf.funclist
python3 recon_symtab.py _output.elf _output.elf.funclist _output.elf-sym
readelf -S _output.elf-sym
objdump -d -M intel _output.elf-sym | grep "<__libc_start_main>"
objdump -d -M intel ../test/recon/orig/x86_64-buildroot-2020.08.3-glibc | grep "<__libc_start_main>"
