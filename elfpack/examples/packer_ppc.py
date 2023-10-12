import sys
from elfpack import ELFPack
from keystone import *
from elfesteem.elf import *
import struct

from argparse import ArgumentParser

sc_template_ppc = (
    "nop;"
    # start addr -> r5
    "lis 5, 0x{hi_start:x};"
    "ori 5, 5, 0x{lo_start:x};"
    # end addr -> r6
    "lis 6, 0x{hi_end:x};"
    "ori 6, 6, 0x{lo_end:x};"
    # decode
    "loop:;"
    "lbz 7, 0(5);"
    "xori 7, 7, {value:d};"
    "stb 7, 0(5);"
    "addi 5, 5, 1;"
    "cmpw cr7, 5, 6;"
    "bne cr7, loop;"
    # jmp entry
    "lis 8, 0x{hi_entry:x};"
    "ori 8, 8, 0x{lo_entry:x};"
    "mtlr 8;"
    "blr;"
)

sc_template_ppc64 = (
    "nop;"
    # start addr -> r5
    "lis 5, 0x{hi_start:x};"
    "ori 5, 5, 0x{lo_start:x};"
    # end addr -> r6
    "lis 6, 0x{hi_end:x};"
    "ori 6, 6, 0x{lo_end:x};"
    # decode
    "loop:;"
    "lbz 7, 0(5);"
    "li 8, 0x{value:d};"
    "xor 7, 7, 8;"
    "stb 7, 0(5);"
    "addi 5, 5, 1;"
    "cmpw cr7, 5, 6;"
    "bne cr7, loop;"
    # jmp entry
    "lis 8, 0x{hi_entry:x};"
    "ori 8, 8, 0x{lo_entry:x};"
    "mtlr 8;"
    "blr;"
)

def main(inputfile, outputfile, bitsize, endian, libc):

    elf_in = ELFPack(open(inputfile, 'rb').read())

    # xor encode with 0x71
    text_sec = elf_in.getsectionbyname(".text")
    elf_in.xor_encode(text_sec.sh.addr, text_sec.sh.addr+text_sec.sh.size, 0x71)

    # allocate a space for xor decoder
    if bitsize == 32: # Todo: not support uclibc, musl
        (sec_addr, s) = elf_in.alloc_exec(256, base_sec=".sbss")
        entry = elf_in.get_entry()
    elif bitsize == 64:
        if libc == 'glibc':
            (sec_addr, s) = elf_in.alloc_exec(256, base_sec=".tbss")
            # get e_entry address
            e_entry = (elf_in.Ehdr.entry & 0x00ffffff) - 0x10000 # Todo : why need subtract offset(0x10000)?
            # get target binary bytecode and convert to list
            e_bytecode_list = list(struct.unpack('B'*len(bytes(elf_in)), bytes(elf_in)))
            # get current start address
            start_hex_list=e_bytecode_list[e_entry+4:e_entry+8]
            orig_start_addr = int(hex(start_hex_list[0] << 24), 16)
            orig_start_addr = orig_start_addr + int(hex(start_hex_list[1] << 16), 16)
            orig_start_addr = orig_start_addr + int(hex(start_hex_list[2] << 8), 16)
            orig_start_addr = orig_start_addr + int(hex(start_hex_list[3]), 16)
            # overwrite new start address
            new_entry_str = str(hex(sec_addr))
            ent_hex_0 = int(new_entry_str[2:4], 16)
            ent_hex_1 = int(new_entry_str[4:6], 16)
            ent_hex_2 = int(new_entry_str[6:8], 16)
            ent_hex_3 = int(new_entry_str[8:10], 16)
            e_bytecode_list[e_entry+4:e_entry+8] = [ent_hex_0, ent_hex_1, ent_hex_2, ent_hex_3]
            # update elf_in
            elf_in = ELFPack(struct.pack('B'*len(e_bytecode_list), *e_bytecode_list))
            entry = orig_start_addr
        elif libc == 'musl':
            (sec_addr, s) = elf_in.alloc_exec(256, base_sec=".bss")
            entry = elf_in.get_entry()

    if bitsize == 32:
        hi_entry = (entry & 0xffff0000) >> 16
        lo_entry = entry & 0x0000ffff

        hi_start = (text_sec.sh.addr & 0xffff0000) >> 16
        lo_start = text_sec.sh.addr & 0x0000ffff

        hi_end = ((text_sec.sh.addr+text_sec.sh.size) & 0xffff0000) >> 16
        lo_end = (text_sec.sh.addr+text_sec.sh.size) & 0x0000ffff

        sc = sc_template_ppc.format(
                hi_start=hi_start,
                lo_start=lo_start,
                hi_end=hi_end,
                lo_end=lo_end,
                value=0x71,
                hi_entry=hi_entry,
                lo_entry=lo_entry,
                )
        if endian == 'little':
            ks = Ks(KS_ARCH_PPC, KS_MODE_PPC32)
        elif endian == 'big':
            ks = Ks(KS_ARCH_PPC, KS_MODE_PPC32 + KS_MODE_BIG_ENDIAN)
    elif bitsize == 64:
        hi_entry = (entry & 0xffff0000) >> 16
        lo_entry = entry & 0x0000ffff

        hi_start = (text_sec.sh.addr & 0xffff0000) >> 16
        lo_start = text_sec.sh.addr & 0x0000ffff

        hi_end = ((text_sec.sh.addr+text_sec.sh.size) & 0xffff0000) >> 16
        lo_end = (text_sec.sh.addr+text_sec.sh.size) & 0x0000ffff

        sc = sc_template_ppc.format(
                hi_start=hi_start,
                lo_start=lo_start,
                hi_end=hi_end,
                lo_end=lo_end,
                value=0x71,
                hi_entry=hi_entry,
                lo_entry=lo_entry,
                )
        if endian == 'little':
            ks = Ks(KS_ARCH_PPC, KS_MODE_PPC64)
        elif endian == 'big':
            ks = Ks(KS_ARCH_PPC, KS_MODE_PPC64 + KS_MODE_BIG_ENDIAN)
        else:
            exit(-1)
    else:
        exit(-1)

    encoding, count = ks.asm(sc, sec_addr)
    assert(count < 256)

    # write the decoder into the newly-allocated space
    elf_in.virt.set(sec_addr, encoding)

    # update `entry` to the xor decoder
    if bitsize == 32:
        elf_in.update_entry(sec_addr)
    elif bitsize == 64:
        if libc == 'glibc':
            None
        elif libc == 'musl':
            elf_in.update_entry(sec_addr)

    # add write permission to `.text` section
    ph = elf_in.getphbyvad(text_sec.sh.addr)
    ph.ph.flags |= PF_W

    # write into a file
    open(outputfile, 'wb').write(bytes(elf_in))

if __name__ == "__main__":

    parser = ArgumentParser("Simple Packer for PPC 32/64")
    parser.add_argument("input", help="input binary to pack")
    parser.add_argument("output",   help="output binary, i.e., packed binary")
    parser.add_argument("--bit", choices=['32','64'], help="32 or 64", required=True)
    parser.add_argument("--endian", choices=['little', 'big'], help="little or big", required=True)
    #parser.add_argument("--libc", default='glibc', choices=['glibc', 'musl'], help="little or big", required=True)
    parser.add_argument("--libc", default='glibc', choices=['glibc', 'musl'], help="little or big")

    args = parser.parse_args()

    #main(args.input, args.output, int(args.bit))
    main(args.input, args.output, int(args.bit), args.endian, args.libc)
