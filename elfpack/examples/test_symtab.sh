#!/bin/sh

python3 recon_symtab.py ../test/symbols/hello.i686-strip ../test/symbols/hello.i686-strip.funclist hello.i686-symtab
readelf -s hello.i686-symtab
objdump -t hello.i686-symtab

python3 recon_symtab.py ../test/symbols/hello.x86_64-strip ../test/symbols/hello.x86_64-strip.funclist hello.x86_64-symtab
readelf -s hello.x86_64-symtab
objdump -t hello.x86_64-symtab

