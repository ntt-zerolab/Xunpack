import sys
from elfpack import ELFPack
from keystone import *
from elfesteem.elf import *

from argparse import ArgumentParser

sc_template_arm = (
    # start addr -> r1
    "ldr r1, =0x{start_addr:x};"
    # end addr -> r2
    "ldr r2, =0x{end_addr:x};"
    # decode
    "loop:"
    "ldr r4, [r1, #0];"
    "eor r4, r4, #{value:d};"
    "str r4, [r1, #0];"
    "add r1, r1, #1;"
    "cmp r1, r2;"
    "bne loop;"
    # jmp entry
    "ldr r3, =0x{entry_addr:x};"
    "mov pc, r3;"
)

sc_template_aarch64 = (
    # start addr -> r1
    "ldr x1, =0x{start_addr:x};"
    # end addr -> r2
    "ldr x2, =0x{end_addr:x};"
    # decode
    "loop:"
    "ldr x4, [x1, #0];"
    "ldr x5, =0x{value:x};"
    "eor x4, x4, x5;"
    "str x4, [x1, #0];"
    "add x1, x1, #1;"
    "cmp x1, x2;"
    "bne loop;"
    # jmp entry
    "ldr x30, =0x{entry_addr:x};"
    "ret;"
)

def main(inputfile, outputfile, bitsize, endian):

    elf_in = ELFPack(open(inputfile, 'rb').read())

    # xor encode with 0x71
    text_sec = elf_in.getsectionbyname(".text")
    elf_in.xor_encode(text_sec.sh.addr, text_sec.sh.addr+text_sec.sh.size, 0x71)

    # allocate a space for xor decoder
    (sec_addr, s) = elf_in.alloc_exec(256, base_sec=".bss")

    # prepare xor decoder which is being inserted.
    entry_addr = elf_in.get_entry()
    start_addr = text_sec.sh.addr
    end_addr = text_sec.sh.addr+text_sec.sh.size

    if bitsize == 32:
        sc = sc_template_arm.format(
                entry_addr=entry_addr,
                start_addr=start_addr,
                value=0x71,
                end_addr=end_addr,
                )
        if endian == 'little':
            ks = Ks(KS_ARCH_ARM, KS_MODE_ARM)
        elif endian == 'big':
            ks = Ks(KS_ARCH_ARM, KS_MODE_ARM+KS_MODE_BIG_ENDIAN)
    elif bitsize == 64:
        sc = sc_template_aarch64.format(
                entry_addr=entry_addr,
                start_addr=start_addr,
                value=0x71,
                end_addr=end_addr,
                )
        if endian == 'little':
            ks = Ks(KS_ARCH_ARM64, KS_MODE_LITTLE_ENDIAN)
        elif endian == 'big':
            ks = Ks(KS_ARCH_ARM64, KS_MODE_BIG_ENDIAN)
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

    parser = ArgumentParser("Simple Packer for ARM/AArch64")
    parser.add_argument("input", help="input binary to pack")
    parser.add_argument("output",   help="output binary, i.e., packed binary")
    parser.add_argument("--bit", choices=['32','64'], help="32 or 64", required=True)
    parser.add_argument("--endian", choices=['little', 'big'], help="little or big", required=True)

    args = parser.parse_args()

    #main(args.input, args.output, int(args.bit))
    main(args.input, args.output, int(args.bit), args.endian)
