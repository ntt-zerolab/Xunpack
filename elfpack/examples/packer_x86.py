import sys
from elfpack import ELFPack
from keystone import *
from elfesteem.elf import *
from argparse import ArgumentParser

sc_template_x86 = (
"   pushad;"
"decoder:"
"   mov edi, 0x%08x;"
"   xor ecx, ecx;"
"   add ecx, 0x%08x;"
"decode:"
"   xor byte ptr [edi], 0x71;"
"   inc edi;"
"   loop decode;"
"   popad;"
"   jmp 0x%08x;"
)

sc_template_x86_64 = (
"decoder:"
"   mov rdi, 0x%016lx;"
"   xor rcx, rcx;"
"   add rcx, 0x%016lx;"
"decode:"
"   xor byte ptr [rdi], 0x71;"
"   inc rdi;"
"   loop decode;"
"   jmp 0x%016lx;"
)

def main(inputfile, outputfile, bitsize):

    elf_in = ELFPack(open(inputfile, 'rb').read())

    # xor encode with 0x71
    text_sec = elf_in.getsectionbyname(".text")
    elf_in.xor_encode(text_sec.sh.addr, text_sec.sh.addr+text_sec.sh.size, 0x71)

    # allocate a space for xor decoder
    (sec_addr, s) = elf_in.alloc_exec(256)

    # prepare xor decoder which is being inserted. 
    entry = elf_in.get_entry()

    if bitsize == 32:
        sc = sc_template_x86 % (text_sec.sh.addr, text_sec.sh.size, entry)
        ks = Ks(KS_ARCH_X86, KS_MODE_32)
    elif bitsize == 64:
        sc = sc_template_x86_64 % (text_sec.sh.addr, text_sec.sh.size, entry)
        ks = Ks(KS_ARCH_X86, KS_MODE_64)
    else:
        assert(false)

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

    parser = ArgumentParser("Simple Packer for x86/x86_64")
    parser.add_argument("input", help="input binary to pack")
    parser.add_argument("output",   help="output binary, i.e., packed binary")
    parser.add_argument("--bit", choices=['32','64'], help="32 or 64", required=True)

    args = parser.parse_args()

    main(args.input, args.output, int(args.bit))






