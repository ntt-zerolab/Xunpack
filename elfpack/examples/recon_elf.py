import sys
from elfpack import ELFPack
from keystone import *
from elfesteem.elf import *
from elfesteem.elf_init import *
import struct
import re
import os

from elfhdr_templates import *

from argparse import ArgumentParser

def create_empty_elf(arch):

    # create an empty ELF file
    elf_params = elf_template[arch]

    elf_out = ELFPack(elfstr=None, 
                        size=elf_params["size"], 
                        sex=elf_params["sex"])

    # Ehdr initial setup
    elf_out.Ehdr.ident      = elf_params["ident"]
    elf_out.Ehdr.type       = elf_params["type"]
    elf_out.Ehdr.machine    = elf_params["machine"]
    elf_out.Ehdr.version    = elf_params["version"]
    elf_out.Ehdr.flags      = elf_params["flags"]

    elf_out.Ehdr.entry = 0
    elf_out.Ehdr.phoff = 0
    elf_out.Ehdr.shoff = elf_out.sizeof_struct(Ehdr)
    elf_out.Ehdr.ehsize = elf_out.sizeof_struct(Ehdr)
    if elf_out.size == 32:
        elf_out.Ehdr.phentsize = elf_out.sizeof_struct(Phdr)
    elif elf_out.size == 64:
        elf_out.Ehdr.phentsize = elf_out.sizeof_struct(Phdr64)

    elf_out.Ehdr.phnum = 0
    elf_out.Ehdr.shentsize = elf_out.sizeof_struct(Shdr)
    #elf_out.Ehdr.shnum = 2
    #elf_out.Ehdr.shstrndx = 1

    elf_out._content = bytes(elf_out.Ehdr)

    # Add NullSection
    null_sechdr = WShdr(elf_out, elf_out.sex, elf_out.size)
    null_sechdr.name    = 0
    null_sechdr.type    = SHT_NULL
    null_sechdr.flags   = 0
    null_sechdr.addr    = 0
    null_sechdr.offset  = elf_out.sizeof_struct(Ehdr) # 52
    null_sechdr.size    = 0
    null_sechdr.link    = 0
    null_sechdr.info    = 0
    null_sechdr.addralign = 0
    null_sechdr.ensize  = 0

    null_sec = Section(elf_out.sh, elf_out.sex, elf_out.size, shstr=bytes(null_sechdr))
    null_sec.parse_content(elf_out.sex, elf_out.size)
    elf_out.sh.shlist.append(null_sec)

    # Update shoff/shnum/shstrndx later

    # Add ".shstrtab"
    shstrtab_sechdr = WShdr(elf_out, elf_out.sex, elf_out.size)
    shstrtab_sechdr.name    = 1
    shstrtab_sechdr.type    = SHT_STRTAB
    shstrtab_sechdr.flags   = 0
    shstrtab_sechdr.addr    = 0
    shstrtab_sechdr.offset  = elf_out.sizeof_struct(Ehdr) # 52
    shstrtab_sechdr.size    = len(b"\x00") + len(b".shstrtab\x00")
    shstrtab_sechdr.link    = 0
    shstrtab_sechdr.info    = 0
    shstrtab_sechdr.addralign = 1
    shstrtab_sechdr.ensize  = 0

    shstrtab_sec = Section(elf_out.sh, elf_out.sex, elf_out.size, shstr=bytes(shstrtab_sechdr))
    # 0: NULL(pointed from NullSection), 1:".shstrtab"
    shstrtab_sec._content = b"\x00" + b".shstrtab\x00"
    shstrtab_sec.parse_content(elf_out.sex, elf_out.size)
    elf_out.sh.shlist.append(shstrtab_sec)

    # update SHList
    elf_out.sh._shstr = shstrtab_sec

    # update content with `.shstrtab` section
    elf_out._content += shstrtab_sec._content

    # update Ehdr
    elf_out.Ehdr.shoff += len(b"\x00") + len(b".shstrtab\x00")
    elf_out.Ehdr.shnum = 2
    elf_out.Ehdr.shstrndx = 1

    # update content with section header
    #
    # totally, elf.content should be 
    # Ehdr + ".shstrtab" + SectionHeader(null, shstrtab)

    elf_out._content += bytes(null_sechdr)
    elf_out._content += bytes(shstrtab_sechdr)

    return elf_out


def main(rootdir, arch, output_file):

    # create an empty ELF file
    elf_out = create_empty_elf(arch)

    files = sorted(os.listdir(rootdir))

    for pos, f in enumerate(files):
        m = re.match("([0-9|a-f]{16})\-([0-9|a-f]{16})\.raw", f)
        sec_start = int(m.group(1), 16)
        sec_end   = int(m.group(2), 16)

        sec_size = sec_end - sec_start

        f_in = open(rootdir + "/" + f, "rb")
        raw_data = f_in.read()
        f_in.close()

        sec_args = {
            "name"      : ".sec{:02d}".format(pos),
            "type"      : SHT_PROGBITS,
            "flags"     : SHF_WRITE | SHF_EXECINSTR,
            "addr"      : sec_start,
            "offset"    : 0x1000, # fake
            "size"      : sec_size, 
            "entsize"   : 0, 
            "link"      : 0, 
            "info"      : 0, 
            "addralign" : 0x1000, 
            "data"      : raw_data
        }

        (_, sec) = elf_out.alloc_section_by_element_index( 
                                            pos, 
                                            **sec_args)

        sec.sh.addr = sec_start

    # TODO: Create program headers

    open(output_file, 'wb').write(bytes(elf_out))

if __name__ == "__main__":

    arch_list = elf_template.keys()

    parser = ArgumentParser("ELF Executable Reconstruction")
    parser.add_argument("rootdir", help="directory containing dump files")
    parser.add_argument("--arch", choices=arch_list, 
                        help="specify your target arch", 
                        required=True)
    parser.add_argument("--output", default="_output.elf",
                        help="output elf filename")
                        

    args = parser.parse_args()

    main(args.rootdir, args.arch, args.output)
