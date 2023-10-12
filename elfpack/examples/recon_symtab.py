import sys
from elfpack import ELFPack
from keystone import *
from elfesteem.elf import *
from elfesteem.elf_init import *

# key: offset, value: funcname
symbol_dict = {}

def read_funclist(funclist):
    f = open(funclist)
    lines = f.readlines()
    f.close()

    for l in lines:
        l = l.rstrip()
        e = l.split(" ")
        if len(e[1:]) > 1:
            continue
        offset = int(e[0], 16)
        symbol_dict[offset] = e[1]

if __name__ == "__main__":

    elf_in = ELFPack(open(sys.argv[1], 'rb').read())

    if elf_in.size == 32:
        WSym = WSym32
        entsize = elf_in.sizeof_struct(Sym32)
    elif elf_in.size == 64:
        WSym = WSym64
        entsize = elf_in.sizeof_struct(Sym64)
    else:
        assert False

    print("entsize={}".format(entsize))

    strtab_args = {
        "name"      : b".strtab",
        "type"      : SHT_STRTAB,
        "flags"     : 0,
        "addr"      : 0,
        "offset"    : 0x1000, # fake
        "size"      : 0, 
        "entsize"   : 0, 
        "link"      : 0, 
        "info"      : 0, 
        "addralign" : 1, 
        "data"      : b"" 
    }

    last_sec = elf_in.get_last_section()
    last_idx = elf_in.get_section_index(last_sec.sh.name.decode('utf-8'))

    (_, strtab_sec) = elf_in.alloc_section_by_element_index( 
                                            last_idx - 1, 
                                            **strtab_args)

    # key: fn, value:offset in strtab
    offset_in_strtab = {}

    read_funclist(sys.argv[2])

    for off, fn in symbol_dict.items():
        o = strtab_sec.add_name(fn)
        offset_in_strtab[fn] = o

    link_idx = elf_in.sh.shlist.index(strtab_sec)

    # create symbol entry:
    # `info`: should be one greater than the symbol table index 
    # of the last local symbol

    symtab_args = {
        "name"      : b".symtab",
        "type"      : SHT_SYMTAB,
        "flags"     : 0,
        "addr"      : 0,
        "offset"    : 0x1000, # fake
        "size"      : 0, 
        "entsize"   : entsize, 
        "link"      : link_idx, 
        "info"      : len(symbol_dict), 
        "addralign" : int(elf_in.size/8), 
        "data"      : b"" 
    }

    (_, sym_sec) = elf_in.alloc_section_by_element(
                                            ".strtab", 
                                            **symtab_args)

    total_symtab_size = 0

    for off, fn in symbol_dict.items():
        sym = WSym(sym_sec, elf_in.sex, elf_in.size, b'\x00'*entsize)
        sym.name = offset_in_strtab[fn]
        va = elf_in.get_rva_from_offset(off)
        sym.value = va 
        sym.size = 0
        sym.info = STT_FUNC
        sym.other = 0

        s = elf_in.getsectionbyvad(va)
        sym.shndx = elf_in.get_section_index(s.sh.name.decode("utf-8"))

        sym_sec.content = bytes(sym_sec.content) + bytes(sym)
        sym_sec.symtab.append(sym)
        sym_sec[sym.name] = sym
        total_symtab_size += entsize

    # Need to adjust the offset of the ".shstrtab" section
    # because we manually added each symbol entry.
    shstrtab_sec = elf_in.get_last_section()
    shstrtab_sec.sh.offset += total_symtab_size

    open(sys.argv[3], 'wb').write(bytes(elf_in))
