import sys
from elfpack import ELFPack
from keystone import *
from elfesteem.elf import *

from argparse import ArgumentParser

sc_template_mips = (
    #"break;" # dbg
    # start addr -> $8
    "li $8, 0x{hi_start:x};"
    "ori $8, $8, 0x{lo_start:x};"
    # end addr -> $9
    "li $9, 0x{hi_end:x};"
    "ori $9, $9, 0x{lo_end:x};"
    #"addiu $9, $9, 1;"
    # decode
    "loop:"
    "lb $10, 0($8);"
    "xori $10, $10, 0x{value:x};"
    "sb $10, 0($8);"
    "addiu $8, $8, 1;"
    "bne $8, $9, loop;"
    # jmp entry
    "li $10, 0x{hi_entry:x};"
    "ori $10, $10, 0x{lo_entry:x};"
    "jr $10;"
    "nop;" #delay slot
)

sc_template_mips64 = (
    #"break;" # dbg
    # start addr -> $8
    "li $8, 0x{hi_top_start:x};"
    "ori $8, $8, 0x{hi_bot_start:x};"
    "dsll $8, $8, 16;"
    "ori $8, $8, 0x{lo_top_start:x};"
    "dsll $8, $8, 16;"
    "ori $8, $8, 0x{lo_bot_start:x};"
    # end addr -> $9
    "li $9, 0x{hi_top_end:x};"
    "ori $9, $9, 0x{hi_bot_end:x};"
    "dsll $9, $9, 16;"
    "ori $9, $9, 0x{lo_top_end:x};"
    "dsll $9, $9, 16;"
    "ori $9, $9, 0x{lo_bot_end:x};"
    # decode
    "loop:"
    "lb $10, 0($8);"
    "xori $10, $10, 0x{value:x};"
    "sb $10, 0($8);"
    "daddiu $8, $8, 1;"
    "bne $8, $9, loop;"
    # jmp entry
    "li $10, 0x{hi_top_entry:x};"
    "ori $10, $10, 0x{hi_bot_entry:x};"
    "dsll $10, $10, 16;"
    "ori $10, $10, 0x{lo_top_entry:x};"
    "dsll $10, $10, 16;"
    "ori $10, $10, 0x{lo_bot_entry:x};"
    "jr $10;"
    "nop;" #delay slot
)

def set_64bit_value(addr):
    hi_top_addr = (addr & 0xffff000000000000) >> 32
    hi_bot_addr = (addr & 0x0000ffff00000000) >> 32
    lo_top_addr = (addr & 0x00000000ffff0000) >> 16
    lo_bot_addr = (addr & 0x000000000000ffff)
    return hi_top_addr, hi_bot_addr, lo_top_addr, lo_bot_addr

def main(inputfile, outputfile, bitsize, endian):

    elf_in = ELFPack(open(inputfile, 'rb').read())

    # xor encode with 0x71
    text_sec = elf_in.getsectionbyname(".text")
    elf_in.xor_encode(text_sec.sh.addr, text_sec.sh.addr+text_sec.sh.size, 0x71)

    # allocate a space for xor decoder
    if bitsize == 32: # Todo: not support uclibc, musl
        (sec_addr, s) = elf_in.alloc_exec(256, base_sec=".sbss")
    elif bitsize == 64:
        (sec_addr, s) = elf_in.alloc_exec(256, base_sec=".sbss")
    #print('sec_addr=:', hex(sec_addr))

    # prepare xor decoder which is being inserted.
    entry = elf_in.get_entry()

    #print("entry : ", hex(entry))
    #print("start1: ", hex(text_sec.sh.addr))
    #print("end   : ", hex(text_sec.sh.addr + text_sec.sh.size))

    if bitsize == 32:
        hi_entry = entry & 0xffff0000
        lo_entry = entry & 0x0000ffff

        hi_start = text_sec.sh.addr & 0xffff0000
        lo_start = text_sec.sh.addr & 0x0000ffff

        hi_end = (text_sec.sh.addr+text_sec.sh.size) & 0xffff0000
        lo_end = (text_sec.sh.addr+text_sec.sh.size) & 0x0000ffff

        sc = sc_template_mips.format(
                hi_start=hi_start,
                lo_start=lo_start,
                hi_end=hi_end,
                lo_end=lo_end,
                value=0x71,
                hi_entry=hi_entry,
                lo_entry=lo_entry,
                )
        if endian == 'little':
            ks = Ks(KS_ARCH_MIPS, KS_MODE_MIPS32)
        elif endian == 'big':
            ks = Ks(KS_ARCH_MIPS, KS_MODE_MIPS32 + KS_MODE_BIG_ENDIAN)
    elif bitsize == 64:
        hi_top_entry, hi_bot_entry, lo_top_entry, lo_bot_entry = \
                set_64bit_value(entry)

        hi_top_start, hi_bot_start, lo_top_start, lo_bot_start = \
                set_64bit_value(text_sec.sh.addr)

        hi_top_end, hi_bot_end, lo_top_end, lo_bot_end = \
                set_64bit_value(text_sec.sh.addr+text_sec.sh.size)

        sc = sc_template_mips64.format(
                hi_top_start=hi_top_start,
                hi_bot_start=hi_bot_start,
                lo_top_start=lo_top_start,
                lo_bot_start=lo_bot_start,
                hi_top_end=hi_top_end,
                hi_bot_end=hi_bot_end,
                lo_top_end=lo_top_end,
                lo_bot_end=lo_bot_end,
                value=0x71,
                hi_top_entry=hi_top_entry,
                hi_bot_entry=hi_bot_entry,
                lo_top_entry=lo_top_entry,
                lo_bot_entry=lo_bot_entry,
                )

        if endian == 'little':
            ks = Ks(KS_ARCH_MIPS, KS_MODE_MIPS64)
        elif endian == 'big':
            ks = Ks(KS_ARCH_MIPS, KS_MODE_MIPS64 + KS_MODE_BIG_ENDIAN)
        else:
            exit(-1)
    else:
        exit(-1)

    encoding, count = ks.asm(sc, sec_addr)
    assert(count < 256)

    # write the decoder into the newly-allocated space
    elf_in.virt.set(sec_addr, encoding)

    # update `entry` to the xor decoder
    elf_in.update_entry(sec_addr)

    # add write permission to `.text` section
    ph = elf_in.getphbyvad(text_sec.sh.addr)
    ph.ph.flags |= PF_W

    # write into a file
    open(outputfile, 'wb').write(bytes(elf_in))

if __name__ == "__main__":

    parser = ArgumentParser("Simple Packer for MIPS 32/64")
    parser.add_argument("input", help="input binary to pack")
    parser.add_argument("output",   help="output binary, i.e., packed binary")
    parser.add_argument("--bit", choices=['32','64'], help="32 or 64", required=True)
    parser.add_argument("--endian", choices=['little', 'big'], help="little or big", required=True)

    args = parser.parse_args()

    #main(args.input, args.output, int(args.bit))
    main(args.input, args.output, int(args.bit), args.endian)
