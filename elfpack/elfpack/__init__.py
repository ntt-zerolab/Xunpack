from elfesteem.elf_init import *
from elfesteem.strpatchwork import StrPatchwork
from elfesteem.elf import *
import struct
import sys

DF_1_PIE = 0x08000000

class ELFPack(ELF):

    def __init__(self, elfstr=None, size=None, sex=None):
        """
        sex = 1: little endian
        sex = 2: big endian
        """

        if elfstr == None:
            self.size = size
            self.sex  = sex
            self.Ehdr = WEhdr(self, self.sex, self.size, b"\x00"*52)
            self.sh   = SHList(self, self.sex, self.size)
            self.ph   = PHList(self, self.sex, self.size)
        else:
            super(ELFPack, self).__init__(elfstr, size, sex, ignore_no_sechdr=True)

    def get_last_section(self):
        if self.sh is None:
            return None
        return self.sh[-1]

    def getsectionbyindex(self, index):
        if self.sh is None:
            return None
        return self.sh[index]

    def get_section_index(self, name):
        if self.sh is None:
            return None
        for idx, s in enumerate(self.sh):
            if s.sh.name.decode('utf-8').strip('\x00') == name:
                return idx
        return None

    def get_raw_size(self):
        # Not sure if this calculation is correct.
        return self.Ehdr.shoff + (self.Ehdr.shentsize * self.Ehdr.shnum)

    def replace_section_name(self, old, new):
        assert len(old) == len(new), "Need to be the same size"

        str_tab = self.getsectionbyname(".shstrtab")
        if str_tab is None:
            assert False
        str_tab.mod_name(old, new)

    def _insert_section(self, sh_idx, 
                        sh_name=".uk", sh_type=SHT_NULL, sh_flag=0, 
                        sh_addr=0, sh_off=0, sh_size=0, data=None, 
                        sh_entsize=0, link=0, info=0, addralign=0x1000,
                        base_sec_index=0, dry_run=False, 
                        symtab_adjust=True):
        """
        Create a new section and insert it into just after `sh_idx` section.
        Recommended: inserting a new section at the end of virtual address.

        Parameters
        ----------
        sh_idx: int
            The index of the section that the new section is inserting. 

        sh_addr: int
            If `sh_addr` equals to 0, we dont perform the calculation 
            of the virtual address of the inserting section. Otherwise,
            we do a proper virtual address.

        sh_off: int
            Not used.

        (need update)base_sec: str
            `base_sec` is the name of section from which we calculate the gap 
            of virtual address to that of the inserting section.

        symtab_adjust: bool
            If `.symtab` is located at the higher section the inserted section,
            we need to adjust `link` of the `.symtab` section. You dont need to
            enable it, when you deal with a stripped binary,i.e., no `symtab`.
        """


        if self.sh is None:
            raise NoSectionHeaderError()

        s = self.sh[self.Ehdr.shstrndx]
        off = s.add_name(sh_name)
        s.parse_content(self.sex, self.size)

        shdr = WShdr(self, self.sex, self.size, self.content)
        shdr.name   = off
        shdr.type   = sh_type
        shdr.flags  = sh_flag
        shdr.size   = sh_size
        shdr.link   = link 
        shdr.info   = info
        shdr.addralign = addralign
        shdr.entsize   = sh_entsize

        # Find the section 'prev_sec' that is the one before the inserting section
        if sh_addr:
            prev_sec = None
            prev_addr = 0

            for s in self.sh[:sh_idx]:
                if s.sh.addr >= prev_addr:
                    prev_addr = s.sh.addr
                    prev_sec = s

            prev_offset = prev_sec.sh.offset
            prev_size   = prev_sec.sh.size

            if ((prev_addr + prev_sec.sh.size) % shdr.addralign) == 0:
                n = int((prev_addr + prev_sec.sh.size) / shdr.addralign)
            else:
                n = int(((prev_addr + prev_sec.sh.size) / shdr.addralign) + 1)

            shdr.addr = shdr.addralign * n
        else:
            prev_sec    = None
            prev_addr   = 0
            prev_offset = 0
            prev_size   = 0
            shdr.addr   = 0

        base_sec = self.getsectionbyindex(base_sec_index)

        if sh_addr:
            the_gap = shdr.addr - base_sec.sh.addr
        else:
            # if `base_sec` does not have the virtual address, 
            # we calculate the gap simply from the offset of it.
            the_gap = base_sec.sh.size

        if ((base_sec.sh.offset + the_gap) % shdr.addralign) == 0:
            n = int((base_sec.sh.offset + the_gap) / shdr.addralign)
        else:
            n = int((base_sec.sh.offset + the_gap) / shdr.addralign) + 1

        shdr.offset = shdr.addralign * n

        print("shdr.addr={:x} link={}".format(shdr.addr, shdr.link))
        print("\tbase_sec.sh.addr={:x}".format(base_sec.sh.addr))
        print("\tbase_sec.sh.size={:x}".format(base_sec.sh.size))
        print("\tbase_sec.sh.name={}".format(base_sec.sh.name))
        print("\tprev_size={:x}".format(prev_size))
        print("\tprev_add={:x}".format(prev_addr))
        print("shdr.offset={:x}".format(shdr.offset))
        print("\tthe_gap={:x}".format(the_gap))

        # Create Section Header
        print("shdr={}".format(shdr))
        new_sec = Section(self.sh, self.sex, self.size, shstr=bytes(shdr))

        if dry_run:
            return (new_sec.sh.offset, new_sec.sh.addr)

        # Create Section Body

        # Caution: Should put into _content. Otherwise,
        # The size of new_sec is going to be a strange value. 
        new_sec._content = StrPatchwork(data)
        new_sec.parse_content(self.sex, self.size)
        self.sh.do_add_section(new_sec)

        self.sh.shlist.insert(sh_idx, new_sec)
        self.Ehdr.shnum += 1

        # offset adjust

        # The new section is started at 'shdr.offset', i.e., 'shdr.addr'.
        # The size of it is 'sh_size'. So, we have to move the sections after
        # the inserted one by at least 'the_gap' + 'sh_size'.
        for i in range(sh_idx+1, self.Ehdr.shnum):
            prev_offset = self.sh.shlist[i-1].sh.offset
            prev_sz = self.sh.shlist[i-1].sh.size
            align = self.sh.shlist[i].sh.addralign

            if align not in [0,1]:
                if ((prev_offset + prev_sz) % align) == 0:
                    n = int((prev_offset + prev_sz)/align)
                else:
                    n = int(((prev_offset + prev_sz)/align) + 1)
                new_offset = align * n
            else:
                new_offset = prev_offset + prev_sz

            self.sh.shlist[i].sh.offset = new_offset

        # if .symtab section is higher than the inserted section.
        if symtab_adjust:
            symtab = self.getsectionbyname(".symtab")
            if symtab:
                symtab.sh.link += 1

        # adjust the program header
        s = self.get_last_section()
        if s == None:
            assert False, ".shstrtab is None"

        self.Ehdr.shoff = s.sh.offset + s.sh.size
        self.Ehdr.shstrndx += 1

        return new_sec

    @classmethod
    def dump_fields(cls, sht):
        for field, t in sht.wrapped._fields:
            value = getattr(sht, field)
            print("{}:\t{} {}".format(field, value, t))

    def sizeof_struct(self, classtype):
        """
        Calc the total size of a give data structure. 
        Need to care about the differece of ABIs.
        """
        type2byte = {
            "u64": 8, 
            "u32": 4, 
            "u16": 2, 
            "u08": 1,
        }

        total = 0

        for k, v in classtype._fields:
            if v in type2byte.keys():
                total += type2byte[v]
            else:
                if v[-1] == 's':
                    total += int(v[:-1])
                elif v == "ptr":
                    total += int(self.size/8)

        return total;


    def dump_sections(self):

        if self.sh is None:
            print("Invalid Section Header")
            return

        print("Section Offset:")
        for s in self.sh:
            print("%-30s:%016x : %016x"%(s.sh.name.decode('utf-8'), 
                                    s.sh.offset, 
                                    s.sh.offset+s.sh.size))
        print("Section Addr:")
        for s in self.sh:
            print("%-30s:%016x : %016x"%(s.sh.name.decode('utf-8'), 
                                    s.sh.addr, 
                                    s.sh.addr+s.sh.size))

    def dump_segments(self, offset=True, vaddr=True):
        if offset:
            print("Segment Offset:")
            for p in self.ph.phlist:
                print("p.ph.offset:%016x : %016x"%(p.ph.offset, p.ph.offset+p.ph.filesz))
        if vaddr:
            print("Segment Vaddr:")
            for p in self.ph.phlist:
                print("p.ph.vaddr:%016x : %016x"%(p.ph.vaddr, p.ph.vaddr+p.ph.memsz))

    def is_in_section(self, vaddr):
        # same as `is_in_virt_address` in elf_init.py
        raise NotImplementedError()

    def is_in_segment_by_offset(self, offset):
        for p in self.ph.phlist:
            if p.ph.offset <= offset < p.ph.offset + p.ph.filesz:
                return p
        return None

    def get_rva_from_offset(self, offset):
        # RVA? VirtualAddress?
        # which is better?

        s = self.is_in_section_by_offset(offset)
        if s is None:
            raise ValueError()
        return s.sh.addr + (offset - s.sh.offset)

#        p = self.is_in_segment_by_offset(offset)
#        if p is None:
#            raise ValueError()
#        return p.ph.vaddr + (offset - p.ph.offset)

    def is_in_section_by_offset(self, offset):
        if self.sh is None:
            return None

        for s in self.sh:
            if s.sh.offset <= offset < s.sh.offset + s.sh.size:
                return s
        return None

    def build_content_from(self, e):
        """ Build the content (string) from another ELFPack/ELF instance.
        """
        c = StrPatchwork()
        c[0] = str(e.Ehdr)
        c[e.Ehdr.phoff] = str(e.ph)
        for s in e.sh:
            c[s.sh.offset] = str(s.content)
        c[e.Ehdr.shoff] = str(e.sh)
        return str(c)

    def find_symbol(self, sym_name):
        sec = self.getsectionbyname(".symtab")
        if sec:
            if sym_name in sec.symbols.keys():
                return sec.symbols[sym_name]
        return None

    def get_image_base(self):
        # The address of PHDR segment - its file offset
        return self.ph.phlist[0].ph.vaddr - self.ph.phlist[0].ph.offset

    def alloc_section_by_element(self, target_secname, **args):

        target_idx = self.get_section_index(target_secname)
        sh_idx = target_idx + 1

        new_sec = self._insert_section(sh_idx,
                sh_name = args["name"],
                sh_type = args["type"],
                sh_flag = args["flags"],
                sh_addr = args["addr"],
                sh_off  = 0x1000,       # fake, args["offset"]
                sh_size = args["size"],
                data    = args["data"],
                sh_entsize  = args["entsize"],
                link    = args["link"], 
                info    = args["info"],
                addralign = args["addralign"],
                base_sec_index = target_idx,
                dry_run = False,
                symtab_adjust = False)

        return (new_sec.sh.addr, new_sec)

    def alloc_section_by_element_index(self, target_idx, **args):

        sh_idx = target_idx + 1

        new_sec = self._insert_section(sh_idx,
                sh_name = args["name"],
                sh_type = args["type"],
                sh_flag = args["flags"],
                sh_addr = args["addr"],
                sh_off  = 0x1000,       # fake, args["offset"]
                sh_size = args["size"],
                data    = args["data"],
                sh_entsize  = args["entsize"],
                link    = args["link"], 
                info    = args["info"],
                addralign   = args["addralign"],
                base_sec_index = target_idx,
                dry_run = False,
                symtab_adjust = False)

        return (new_sec.sh.addr, new_sec)


    def alloc_section(self, section):
        """
        Allocate a new section at the end of the given binary.
        Each parameter is copied from `section`.

        Caution: adding the section at the end of a binary may 
        not create a syntaxtically corrected binary. 
        """

        target_sec = self.get_last_section()

        if self.sh is None:
            raise NoSectionHeaderError()

        target_idx = self.sh.shlist.index(target_sec)
        sh_idx = target_idx + 1

        new_sec = self._insert_section(sh_idx,
                    sh_name=section.sh.name,
                    sh_type=section.sh.type,
                    sh_flag=section.sh.flags,
                    sh_addr=0, 
                    sh_off=0x1000000,  # fake
                    sh_size=section.sh.size,
                    data=section.content,
                    sh_entsize=section.sh.entsize,
                    link=0, # update later
                    info=section.sh.info,
                    addralign=section.sh.addralign,
                    base_sec_index=target_idx,
                    dry_run=False,
                    symtab_adjust=True)

        return (new_sec.sh.addr, new_sec)

    def alloc_exec(self, size, name=".sc", target_secname=".bss", 
                    base_sec=".data", flags=(SHF_ALLOC | SHF_EXECINSTR)):

        """ Allocate a memory space after `bss` for storing shellcode.

        Parameters
        ----------
            size :int 
                Page aligned. Necessary size for shellcode.

        Returns
        -------
            (int,Section) 
                The start virtual address of the expanded section 
                and its Section instance. 
        """

#        if size % self.PAGE_SIZE == 0:
#            n_pages = int(size/self.PAGE_SIZE)
#        else:
#            n_pages = int((size/self.PAGE_SIZE) + 1)

        # Adding a new section after .bss by default
        target_idx = self.get_section_index(target_secname)
        sh_idx = target_idx + 1

        base_idx = self.get_section_index(base_sec)

        new_sec = self._insert_section(sh_idx,
                sh_name=name, 
                sh_type=SHT_PROGBITS,
                sh_flag=flags,
                sh_addr=0x1000000, # fake
                sh_off=0x1000000,  # fake
                sh_size=size, 
                data=bytes(bytearray([0 for _ in range(0,size)])),
                base_sec_index=base_idx)

        raw_file_size = self.get_raw_size()

        # Find the segment containing '.data' section" 
        # in order to add the executable permission and 
        # adjust the size.

        # We need to load .bss section as well.
        #data_sec = self.getsectionbyname(".data")

        data_sec = self.getsectionbyname(base_sec)
        data_ph = self.getphbyvad(data_sec.sh.addr)

        the_gap = new_sec.sh.addr - data_ph.ph.vaddr

        data_ph.ph.filesz += the_gap + size
        data_ph.ph.memsz  += the_gap + size
        data_ph.ph.flags |= PF_X
        #data_ph.ph.flags &= ~PF_W

        return (new_sec.sh.addr, new_sec)

    def update_entry(self, new_entry):
        self.Ehdr.entry = new_entry

    def get_entry(self):
        return self.Ehdr.entry

    def xor_encode(self, start_addr, end_addr, xor_val):
        data = self.virt.get(start_addr, end_addr)
        print("len(data)=%d"%(len(data)))
        buf = b''
        for v in data:
            v = v ^ xor_val;
            buf += struct.pack("B", v)
        self.virt.set(start_addr, buf)

if __name__ == "__main__":

    elf_in = ELFPack(open(sys.argv[1], 'rb').read())
    #elf_in.replace_section_name(".comment", ".xxxx___")
    elf_in.dump_sections()
    #open(sys.argv[2], 'wb').write(bytes(elf_in))



