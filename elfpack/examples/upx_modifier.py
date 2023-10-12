import sys
from elfpack import ELFPack
from elfesteem.cstruct import CStruct
from elfesteem.elf_init import StructWrapper
from elfesteem.strpatchwork import StrPatchwork

from argparse import ArgumentParser
import os
import struct

TYPE_UPX_MAGIC              = 1
TYPE_FILE_AND_BLOCK_SIZE    = 2
TYPE_JUNK_BYTES             = 3
TYPE_ELF_MAGIC              = 4

def sizeof_struct(classtype):

    type2byte = {
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

    return total;


class L_Info(CStruct):
    _fields = [ ("l_checksum","u32"),
                ("l_magic","4s"), # UPX! magic
                ("l_lsize","u16"),
                ("l_version","u08"),
                ("l_format","u08")]

class P_Info(CStruct):
    _fields = [ ("p_progid"  ,"u32"),
                ("p_filesize","u32"),
                ("p_blocksize","u32")]

class B_Info(CStruct):
    _fields = [ ("sz_unc"  ,"u32"),
                ("sz_cpr"  ,"u32"),
                ("b_method","u08"),
                ("b_ftid"  ,"u08"),
                ("b_cto8"  ,"u08"),
                ("b_unused","u08")]

class UPX_Terminator(CStruct):
    _fields = [ ("terminator"   ,"12s")]

class PackHdr(CStruct):
    _fields = [ ("l_magic"      ,"4s"), # UPX! magic
                ("version"      ,"u08"),
                ("format"       ,"u08"),
                ("method"       ,"u08"),
                ("level"        ,"u08"),
                ("u_adler"      ,"u32"),
                ("c_adler"      ,"u32"),
                ("u_len"        ,"u32"),
                ("c_len"        ,"u32"),
                ("u_file_size"  ,"u32"),
                ("filter"       ,"u08"),
                ("filter_cto"   ,"u08"),
                ("mru"          ,"u08"),
                ("checksum"     ,"u08")]

class WTerminator(StructWrapper):
    wrapped = UPX_Terminator

class WPackHeader(StructWrapper):
    wrapped = PackHdr

class WL_Info(StructWrapper):
    wrapped = L_Info

class WP_Info(StructWrapper):
    wrapped = P_Info

class WB_Info(StructWrapper):
    wrapped = B_Info

class UPXHeader(object):

    def __init__(self, parent, sex, size, hdstr):
        self.l_info = WL_Info(self, sex, size, hdstr[:sizeof_struct(L_Info)])
        off_start = sizeof_struct(L_Info)
        off_end = sizeof_struct(L_Info) + sizeof_struct(P_Info)
        self.p_info = WP_Info(self, sex, size, hdstr[off_start : off_end])

    def __bytes__(self):
        return bytes(self.l_info) + bytes(self.p_info)

class Terminator(object):
    def __init__(self, parent, sex, size, hdstr):
        self.terminator = WTerminator(self, sex, size, hdstr)

    def __bytes__(self):
        return bytes(self.terminator)

class PackHeader(object):
    def __init__(self, parent, sex, size, hdstr):
        self.pack_header = WPackHeader(self, sex, size, hdstr)

    def __bytes__(self):
        return bytes(self.pack_header)


class ELFUpx(ELFPack):

    def __init__(self, elfstr=None):

        if elfstr == None:
            raise NotImplementedError()
        else:
            super(ELFUpx, self).__init__(elfstr)

            # UPX Header
            off_start = self.Ehdr.phoff + self.Ehdr.phentsize * self.Ehdr.phnum
            #off_start = 0x94
            off_size  = sizeof_struct(L_Info) + sizeof_struct(P_Info)
            self.upxhdr = UPXHeader(self, 
                            self.sex, 
                            self.size, 
                            self.content[off_start:off_start+off_size])

            # 00000000 UPX! 00000000
            pattern = b"\x00\x00\x00\x00\x55\x50\x58\x21\x00\x00\x00\x00"
            self.offset = self.content.find(pattern)
            if self.offset < 0:
                print(self.offset)
                raise ValueError()

            # Terminator
            off_start = self.offset
            off_size  = sizeof_struct(UPX_Terminator)
            self.terminator = Terminator(self, 
                            self.sex, 
                            self.size, 
                            self.content[off_start:off_start+off_size])

            self.gap = (4 - (self.offset % 4)) & 0x3

            # PackHeader
            off_start = self.offset + sizeof_struct(UPX_Terminator)+self.gap
            off_size = sizeof_struct(PackHdr)
            self.packhdr = PackHeader(self,
                            self.sex,
                            self.size,
                            self.content[off_start:off_start+off_size])


    def build_content(self):
        c = StrPatchwork()
        c[0] = bytes(self.Ehdr)
        c[self.Ehdr.phoff] = bytes(self.ph)

        # UPXHeader(12+12=24bytes)
        off_start = self.Ehdr.phoff + self.Ehdr.phentsize * self.Ehdr.phnum
        #off_start = 0x94
        c[off_start] = bytes(self.upxhdr)

        off_start += sizeof_struct(L_Info) + sizeof_struct(P_Info)
        off_end  = self.offset
        c[off_start] = self.content[off_start:off_end]

        # Terminator(12bytes)
        off_start = self.offset
        c[off_start] =  bytes(self.terminator)

        if self.gap > 0:
            c[self.offset+sizeof_struct(UPX_Terminator)] = b"\x00"*self.gap

        # PackHeader(32bytes)
        off_start = self.offset + sizeof_struct(UPX_Terminator) + self.gap
        c[off_start] = bytes(self.packhdr)

        # The rest 
        off_start = self.offset + \
                    sizeof_struct(UPX_Terminator) + \
                    self.gap + sizeof_struct(PackHdr)

        c[off_start] = self.content[off_start:]

        return bytes(c)

    def replace_upx_magic(self, new_magic):
        assert len(new_magic) == 4
        self.upxhdr.l_info.l_magic = new_magic

    def replace_filesize(self, new_size):
        self.upxhdr.p_info.p_filesize = new_size

    def replace_blocksize(self, new_size):
        self.upxhdr.p_info.p_blocksize = new_size

    def replace_terminator(self, random_pattern):
        assert len(random_pattern) == 12
        self.terminator.terminator = random_pattern

    def destroy_packhdr(self):
        self.packhdr.pack_header.l_magic = os.urandom(4)
        self.packhdr.pack_header.version = struct.unpack("B", os.urandom(1))[0]
        self.packhdr.pack_header.format  = struct.unpack("B", os.urandom(1))[0]
        self.packhdr.pack_header.method  = struct.unpack("B", os.urandom(1))[0]
        self.packhdr.pack_header.level   = struct.unpack("B", os.urandom(1))[0]
        self.packhdr.pack_header.u_adler = struct.unpack("I", os.urandom(4))[0]
        self.packhdr.pack_header.c_adler = struct.unpack("I", os.urandom(4))[0]
        self.packhdr.pack_header.u_len   = struct.unpack("I", os.urandom(4))[0]
        self.packhdr.pack_header.c_len   = struct.unpack("I", os.urandom(4))[0]
        self.packhdr.pack_header.u_file_size = struct.unpack("I", os.urandom(4))[0]
        self.packhdr.pack_header.filter  = struct.unpack("B", os.urandom(1))[0]
        self.packhdr.pack_header.filter_cto = struct.unpack("B", os.urandom(1))[0]
        self.packhdr.pack_header.mru     = struct.unpack("B", os.urandom(1))[0]
        self.packhdr.pack_header.checksum = struct.unpack("B", os.urandom(1))[0]

    def elf_magic(self):
        e_ident = bytearray(self.Ehdr.ident)
        e_ident[5] = struct.unpack("B", os.urandom(1))[0]
        e_ident[6] = struct.unpack("B", os.urandom(1))[0]
        e_ident[7] = struct.unpack("B", os.urandom(1))[0]
        e_ident[8] = struct.unpack("B", os.urandom(1))[0]
        self.Ehdr.ident = bytes(e_ident)

def main(inputfile, outputfile, mod_type):

    elf_in = ELFUpx(open(inputfile, 'rb').read())

    if mod_type == TYPE_UPX_MAGIC:
        #new_magic = b"AAAA"
        new_magic = os.urandom(4)
        elf_in.replace_upx_magic(new_magic)

    if mod_type == TYPE_FILE_AND_BLOCK_SIZE:
        elf_in.replace_filesize(0)
        elf_in.replace_blocksize(0)

    if mod_type == TYPE_JUNK_BYTES:
        #random_pattern = b"\x41"*12
        random_pattern = os.urandom(12)
        elf_in.replace_terminator(random_pattern)
        elf_in.destroy_packhdr()

    if mod_type == TYPE_ELF_MAGIC:
        elf_in.elf_magic()

    open(outputfile, 'wb').write(bytes(elf_in))

if __name__ == "__main__":

    parser = ArgumentParser("UPX Modifier")
    parser.add_argument("input", help="upx-packed binary")
    parser.add_argument("output",   help="output binary")
    parser.add_argument("--type", 
                        choices=['1', '2', '3', '4'], 
                        help=("Variant Type 1: UPX Magic "
                              "Variant Type 2: p_info.p_filesize/p_info.p_blocksize " 
                              "Variant Type 3: Junk Bytes " 
                              "Variant Type 4: ELF Magic"), 
                        required=True)

    args = parser.parse_args()
    main(args.input, args.output, int(args.type))


