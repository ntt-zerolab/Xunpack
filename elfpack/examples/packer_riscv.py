import sys
from elfpack import ELFPack
from elfesteem.elf import *

from riscv_assembler.convert import *
from riscv_assembler.utils import *

import struct
from argparse import ArgumentParser

sc_template_riscv = (
    "mv t0 x0\n"
    "mv t1 x0\n"
    "mv t2 x0\n"
    "li t0 %d\n"
    "li t1 %d\n"
    "lbu t2 0(t0)\n"
    "xori t2 t2 %d\n"
    "sb  t2 0(t0)\n"
    "addi t0 t0 1\n"
)

def gen_decoder(start_text, end_text, entry, start_sc):
    """ generating the risc-v decoder

    li      t0, [Start addr of .text]
    li      t1, [End addr of .text]
loop:
    lbu     t2, 0(t0)
    xori    t2, 0x71
    sb      t2, 0(t0)
    addi    t0, t0, 1
    bne     t0, t1, loop
    jal     x0, [Address of Entry]
    """

    encoding = b""
    count = 0

    print("start_text {:x} end_text {:x}".format(start_text, end_text))

    sc = sc_template_riscv % (start_text, end_text, 0x71)

    out_arr = []
    cnv = AssemblyConverter()
    encoded = cnv.convert_from_string(sc)

    # t0 is mapped to x5 and t2 is to x7, respectively.
    # `CalcJump` in riscv-assembler does not handle 
    # a negative value properly. So, we added the 
    # following two instructions separately.

    encoded.append(cnv.SB_type("bne", "x5", "x6", -16))
    if end_text > 2**11:
        offset = 56 # Since li t1, [End addr of .text] is expaneded to 3 instructions.
    else:
        offset = 48 # the offset of `jal` from `start_sc`
    encoded.append(cnv.UJ_type("jal", entry - (start_sc + offset), "x0")) 

    print("encoded={}".format(encoded))

    tk = Toolkit()
    for linecode in encoded:
        b = int(tk.hex(linecode), 16)
        encoding += struct.pack("<I", b)
        count += 4

    return (encoding, count)


def main(inputfile, outputfile, bitsize):

    elf_in = ELFPack(open(inputfile, 'rb').read())

    # xor encode with 0x71
    text_sec = elf_in.getsectionbyname(".text")
    elf_in.xor_encode(text_sec.sh.addr, text_sec.sh.addr+text_sec.sh.size, 0x71)

    if bitsize == 32:
        (sec_addr, s) = elf_in.alloc_exec(256, 
                            target_secname="__libc_freeres_ptrs",
                            base_sec=".tdata")
    elif bitsize == 64:

        tbss_sec = elf_in.getsectionbyname(".tbss")
        if tbss_sec:
            (sec_addr, s) = elf_in.alloc_exec(256, base_sec=".tbss")
        else:
            init_array_sec = elf_in.getsectionbyname(".init_array")
            if init_array_sec:
                (sec_addr, s) = elf_in.alloc_exec(256, base_sec=".init_array")
            else:
                assert(False)
    else:
        assert(False)

    # set jmp to the entrypoint
    entry = elf_in.get_entry()

    # assembler and write it into a new section
    encoding, count = gen_decoder(text_sec.sh.addr, 
                                text_sec.sh.addr + text_sec.sh.size, 
                                entry,
                                sec_addr)
    assert(count < 256)

    elf_in.virt.set(sec_addr, encoding)

    # update the original entrypoint
    elf_in.update_entry(sec_addr)

    # add write permission to `.text` section
    ph = elf_in.getphbyvad(text_sec.sh.addr)
    ph.ph.flags |= PF_W

    # write into a file
    open(outputfile, 'wb').write(bytes(elf_in))


if __name__ == "__main__":

    parser = ArgumentParser("Simple Packer for RISC32/64")
    parser.add_argument("input", help="input binary to pack")
    parser.add_argument("output",   help="output binary, i.e., packed binary")
    parser.add_argument("--bit", choices=['32','64'], help="32 or 64", required=True)

    args = parser.parse_args()

    main(args.input, args.output, int(args.bit))





