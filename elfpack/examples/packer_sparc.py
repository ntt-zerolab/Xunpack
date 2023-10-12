import sys
sys.path.append("..")
from elfpack import ELFPack
from keystone import *
from elfesteem.elf import *

from argparse import ArgumentParser

sc_template_sparc = (
# start addr -> %l1
"   sethi %hi(0x{hi_start:x}), %l1;"
"   or %l1, 0x{lo_start:x}, %l1;"
# end_addr -> %l2
"   sethi %hi(0x{hi_end:x}), %l2;"
"   or %l2, 0x{lo_end:x}, %l2;"
# %l3 -> temp (address)
# %l4 -> temp (value)
"   mov %l1, %l3;"
"   loop:"
"   ldub [%l3], %l4;"
"   xor %l4, {value:d}, %l4;"
"   stb %l4, [%l3];"
"   add %l3, 1, %l3;"
# compare $l3, %l2(end_addr)
"   cmp %l3, %l2;"
"   bne loop;"
# jmp entry
"   sethi %hi(0x{hi_entry:x}), %l1;"
"   or %l1, 0x{lo_entry:x}, %l1;"
"   jmpl %l1, %l0;"
"   nop"
)

def main(inputfile, outputfile, bitsize):

    elf_in = ELFPack(open(inputfile, 'rb').read())

    # xor encode with 0x71
    text_sec = elf_in.getsectionbyname(".text")
    elf_in.xor_encode(text_sec.sh.addr, text_sec.sh.addr+text_sec.sh.size, 0x71)

    # allocate a space for xor decoder
    (sec_addr, s) = elf_in.alloc_exec(256, base_sec=".tbss")

    # prepare xor decoder which is being inserted.
    entry = elf_in.get_entry()

    hi_entry = entry & 0xfffff000
    lo_entry = entry & 0x00000fff

    hi_start = text_sec.sh.addr & 0xfffff000
    lo_start = text_sec.sh.addr & 0x00000fff

    hi_end = (text_sec.sh.addr+text_sec.sh.size) & 0xfffff000
    lo_end = (text_sec.sh.addr+text_sec.sh.size) & 0x00000fff

    sc = sc_template_sparc.format(
                            hi_start=hi_start,
                            lo_start=lo_start,
                            hi_end=hi_end,
                            lo_end=lo_end,
                            value=0x71,
                            hi_entry=hi_entry,
                            lo_entry=lo_entry)

    if bitsize == 32:
        ks = Ks(KS_ARCH_SPARC, KS_MODE_SPARC32+KS_MODE_BIG_ENDIAN)
    elif bitsize == 64:
        ks = Ks(KS_ARCH_SPARC, KS_MODE_SPARC64+KS_MODE_BIG_ENDIAN)
    else:
        assert(False)

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

    parser = ArgumentParser("Simple Packer for SPARC32/64")
    parser.add_argument("input", help="input binary to pack")
    parser.add_argument("output",   help="output binary, i.e., packed binary")
    parser.add_argument("--bit", choices=['32','64'], help="32 or 64", required=True)

    args = parser.parse_args()

    main(args.input, args.output, int(args.bit))





