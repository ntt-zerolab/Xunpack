import sys
import os
from collections import defaultdict
import re
import argparse
import math
import hashlib
import logging

logger = logging.getLogger("SelectiveDump")
logger.setLevel(logging.INFO)

sh = logging.StreamHandler()
fh = logging.FileHandler(filename="selective_dump.log")

logger.addHandler(sh)
logger.addHandler(fh)

for _ in logging.root.manager.loggerDict:
    logging.getLogger(_).setLevel(logging.CRITICAL)
    #logging.getLogger(_).disabled = True

from elfpack import *

def get_virt(elf, start_addr, end_addr):

    if elf is None:
        return None

    data = b''
    addr = start_addr
    while addr < end_addr:

        if elf.is_in_virt_address(addr):
            try:
                data += elf.virt.get(addr, addr+1)
            except ValueError:
                data += b'\x00'
        else:
            data += b'\x00'

        addr += 1

    return data

def auto_int(x):
    return int(x, 0)

def set_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('rootdir',      help = 'a')
    parser.add_argument('--packed',     help = 'a', default=None)
    parser.add_argument('--original',   help = 'a', default=None)
    parser.add_argument('--delta',      help = 'a', type=auto_int, default=0x1000)
    parser.add_argument('--text_addr',  help = 'a', type=auto_int, default=0)
    parser.add_argument('--text_size',  help = 'a', type=auto_int, default=0)
    parser.add_argument('--output_dir', help = 'a')
    parser.add_argument("--size", choices=['32','64'], help="32bt or 64bit", default=0)
    parser.add_argument("--sex", choices=['1','2'], help="1: little endian, 2: big endian", default=0)

    args = parser.parse_args()
    return args

H_cache = {}

def H(data):
    ''' Calculate the entropy of a given data block '''

    k = hashlib.md5(data).hexdigest()
    if k in H_cache.keys():
        return H_cache[k]

    entropy = 0
    for x in range(256):
        p_x = data.count(x)/len(data)
        if p_x > 0:
            entropy += -p_x*math.log(p_x, 2)

    H_cache[k] = entropy

    return entropy

def block_entropy(data, block_size):
    ''' Generator for calculating the entropy of a file,
        given a size for the data blocks '''
    for x in range(0, len(data)//block_size):
        start = x * block_size
        end = start + block_size
        yield H(data[start:end])

def bindiff(l_bin, r_bin):

    if len(l_bin) != len(r_bin):
        print("warning: size is diff")
        return [None]

    diff_offset = defaultdict(int)

    offset = 0
    sz = 0
    off = 0

    for lb, rb in zip(l_bin, r_bin):
        if lb != rb:
            if offset == 0:
                offset = off
                sz = 1
            else:
                sz += 1
        else:
            if offset != 0:
                diff_offset[offset] = sz
                offset = 0
                sz = 0
        off += 1
    else:
        if offset != 0:
            diff_offset[offset] = sz

    for k, v in diff_offset.items():
        d = r_bin[k:k+v]

    return diff_offset


def check_in_range(mem_ranges, va):

    for (s_addr, e_addr, filepath) in mem_ranges:
        if va >= s_addr and va < e_addr:
            return True
    return False

def read_rawbytes(mem_ranges, _start_addr, _end_addr):

    b = b""

    start_addr = _start_addr
    end_addr   = _end_addr

    for (s_addr, e_addr, filepath) in mem_ranges:

        #print("start_addr:",hex(start_addr), 
        #        "end_addr", hex(end_addr), 
        #        "s_addr", hex(s_addr), 
        #        "e_addr", hex(e_addr), 
        #        "filepath", filepath)

        if start_addr >= s_addr and start_addr < e_addr:

            off_start = start_addr - s_addr
            off_end = 0
            read_size = 0

            if end_addr <= e_addr:
                off_end = end_addr - s_addr
            elif end_addr > e_addr:
                off_end = e_addr - s_addr

            read_size = off_end - off_start
            assert(read_size != 0)

            with open(filepath, "rb") as f:
                f.seek(off_start)
                b += f.read(read_size)

            start_addr = start_addr + read_size
            if start_addr == end_addr:
                break;

    return b

def parse_dir(dirpath):

    mem_ranges = list()
    files = os.listdir(dirpath)
    for f in files:
        m = re.match("([0-9|a-f]{16})\-([0-9|a-f]{16})\.raw", f)
        if m is None:
            continue

        raw_start_addr = (int(m.group(1), 16) & ~(0xfff))
        raw_end_addr   = (int(m.group(2), 16) & ~(0xfff))

        mem_ranges.append((raw_start_addr, raw_end_addr, dirpath+"/"+f))

    return mem_ranges

def is_zerofill(d):
    for b in d:
        if b != 0:
            return False
    return True

def to_hex(data):
    return ''.join([r'\x{:02X}'.format(b) for b in data])

def comp_dict_values(l_memo, r_memo):
    for l in l_memo.values():
        if l not in list(r_memo.values()):
            return False
    return True

def find_common_bytes(_target_mem, args):

    common_bytes = dict()

    target_mem = []

    for m in _target_mem:
        if not is_zerofill(m):
           target_mem.append(m) 

    for offset in range(0, args.delta):

        b = target_mem[0][offset]

        for m in target_mem[1:]:
            if m[offset] != b:
                break
        else:
            common_bytes[offset] = b

    return common_bytes

def find_chunk_meta(common_bytes, args):

    chunks = list() # list of tuple(start, end)

    start = -1
    end   = 0
    size  = 0

    for offset in range(0, args.delta):

        if offset not in common_bytes.keys():
            if start == -1:
                start = offset # start of a chunk
                size = 1
            else:
                size += 1
        else:
            if start != -1: # end of a chunk
                end = offset - 1
                logger.info("{:x} {:x} {:x}".format(start, end, size))
                chunks.append((start, end, size))
                start = -1
                size = 0

    if start != -1:
        end = args.delta
        chunks.append((start, end, size))

    return chunks

def merge_chunk_meta(chunk_meta, min_chunk_len=8):

    new_chunk_meta = []
    for (start, end, size) in chunk_meta:

        if size < min_chunk_len:

            if len(new_chunk_meta) != 0:

                (s, e, sz) = new_chunk_meta.pop(-1)

                logger.info("merge_chunk_meta: start {:x} end {:x} size {:d} prev_start {:x} prev_end {:x} prev_sz {:d}".format(start, end, size, s, e, sz))

                if e + 1 == start:
                    new_chunk_meta.append((s, end, sz+size))
                    continue
                else:
                    new_chunk_meta.append((s, e, sz))

        new_chunk_meta.append((start, end, size))

    return new_chunk_meta


def find_chunk_data(target_mem, chunk_meta, packed_m):

    chunk_data = defaultdict(list)

    for (start, end, size) in chunk_meta:
        for m in target_mem:
            d = m[start:start+size]

            if packed_m:
                packed_d = packed_m[start:start+size]
                logger.info("hash(d)  "+ hashlib.md5(d).hexdigest())
                logger.info("hash(pd) "+ hashlib.md5(packed_d).hexdigest())

                if d == packed_d:
                    logger.info("Same pattern with the packed: start {:x} end {:x} len(d) {:d}".format(start, start+size, len(d)))
                    continue
                else:
                    logger.info("memory: "+ to_hex(d[:32]))
                    logger.info("packed: "+ to_hex(packed_d[:32]))
                    diff_offset = bindiff(d, packed_d)
                    for off, sz in diff_offset.items():
                        logger.info("off {:x} sz {:d}".format(off, sz))
                    #hexdump(d)
                    #hexdump(packed_d)
                    logger.info("\n")

            if len(d) != size:
                logger.info("invalid size of data: start {:x} end {:x} size {} len(d) {}".format(start, end, size, len(d)))
                continue

            if d not in chunk_data[start] and not is_zerofill(d):
                logger.info("[!] d is added to chunk_data len(chunk_data[start]):{}".format(len(chunk_data[start])))
                chunk_data[start].append(d)
            else:
                logger.info("[!] d is not added to chunk_data len(chunk_data[start]):{}".format(len(chunk_data[start])))

    return chunk_data

def normalize_target_mem(target_mem):

    new_target_mem = []

    pos_list = []
    for m in target_mem:
        for pos, b in enumerate(m):
            if b in [0xcc]:
                pos_list.append(pos)

    logger.info(pos_list)

    for m in target_mem:
        new_m = b''
        for pos, b in enumerate(m):
            if pos in pos_list:
                new_m += struct.pack("B", 0)
            else:
                new_m += struct.pack("B", b)
        new_target_mem.append(new_m)

    for m1, m2 in zip(target_mem, new_target_mem):
        logger.debug("old "+to_hex(m1[:64]))
        logger.debug("new "+to_hex(m2[:64]))

    return new_target_mem

def collect_target_mem(start_addr, end_addr, subdirs, args):

    uniq_hashes = []
    target_subdirs = []
    target_mem = []

    for subdir in subdirs:

        dirpath = args.rootdir+"/"+subdir
        mem_ranges = parse_dir(dirpath)

        # check if the all target range (start_addr - end_addr) is accessible
        is_skip = False
        for va in range(start_addr, end_addr, args.delta):
            if not check_in_range(mem_ranges, va):
                is_skip = True
                break

        # mainly for reducing the depulications.
        if not is_skip:
            d = read_rawbytes(mem_ranges, start_addr, end_addr)
            assert(len(d) != 0)

            h = hashlib.md5(d).hexdigest()
            if h in uniq_hashes:
                is_skip = True
            else:
                uniq_hashes.append(h)
                target_mem.append(d)

        if not is_skip:
            target_subdirs.append((mem_ranges, dirpath))

    return (target_subdirs, target_mem)


def merge_chunk_data(chunk_data, chunk_meta, split_points, base_addr):

    new_chunk_data = defaultdict(list)
    prev_chunk = None

    # heuristically determined
    min_chunk_len = 8
    prev_offset = 0

    for offset, seqlist in chunk_data.items():

        logger.info("merge_chunk_data: off={:x} len(seqlist)={:d} len(seq[0])={:d}".format(offset, len(seqlist), len(seqlist[0])))

        if len(seqlist[0]) < min_chunk_len:

            if prev_offset == 0:
                new_chunk_data[offset] = seqlist
                prev_offset = offset
                continue

            # check if they are combinable
            va = base_addr + offset

            if va not in split_points.keys():
                logger.info("offset {:x}({:x}) not a split point".format(va, offset))
                new_chunk_data[offset] = seqlist
                prev_offset = offset
                continue

            logger.info("prev_offset {:x} offset {:x}".format(prev_offset, offset))

            if len(new_chunk_data[prev_offset][0]) + prev_offset != offset:
                logger.info("the chunk {:x}({:x}) is not aligned to the prev {:x}".format(va, offset, prev_offset))
                new_chunk_data[offset] = seqlist
                prev_offset = offset
                continue

            # combine all pattern to make `new_seqlist`
            new_seqlist = []
            for prev_seq in new_chunk_data[prev_offset]:
                for add_seq in seqlist:
                    new_seqlist.append(prev_seq + add_seq)

            assert(len(new_seqlist)!=0)

            new_chunk_data[prev_offset] = new_seqlist

            # No need to update `prev_offset`
            continue

        else:
            new_chunk_data[offset] = seqlist

        prev_offset = offset

    return (new_chunk_data, chunk_meta)


def split_chunk_data(chunk_data, chunk_meta, base_addr, min_chunk_len=8):

    split_points = dict()
    new_chunk_data = defaultdict(list)
    new_chunk_meta = list()

    # Find changing points

    for offset, seqlist in chunk_data.items():

        logger.info("va {:x} offset {:x} len(seqlist)={} len(seqlist[0])={}".format(
                base_addr+offset, offset, len(seqlist), len(seqlist[0])))

        split_pos = []
        prev_memo = {}

        # the case of pos = 1
        # set the 1st unique byte of each seq to `prev_memo`
        for i, seq in enumerate(seqlist):

            if is_zerofill(seq):
                continue

            logger.info("{}:{}".format(i, hashlib.md5(seq).hexdigest()))

            if seq[0] not in prev_memo.keys():
                prev_memo[seq[0]] = []

            prev_memo[seq[0]].append(i)

        logger.info("[-] @ {:x} {}".format(base_addr+offset,  
                ["0x%02x:%s"%(k, prev_memo[k]) for k in prev_memo.keys()]))

        for pos in range(1, len(seqlist[0])):

            curr_memo = {}
            for i, seq in enumerate(seqlist):

                if is_zerofill(seq):
                    continue

                if pos == 0xf0:
                    logger.info("[i] idx={} seq[pos]={:02x}".format(i, seq[pos]))

                if seq[pos] not in curr_memo.keys():
                    curr_memo[seq[pos]] = []

                curr_memo[seq[pos]].append(i)

            # check the difference between prev_memo and curr_memo
            msg = ""
            if not comp_dict_values(curr_memo, prev_memo):
                split_pos.append(pos)
                msg += "[x]"
            else:
                msg += "[-]"

            msg +=" @ {:x} {}".format(
                    base_addr + offset + pos, 
                    ["0x%02x:%s"%(k, curr_memo[k]) for k in curr_memo.keys()])

            logger.info(msg)

            prev_memo = curr_memo

        prev_pos = 0
        adj_split_pos = []

        for end_pos in split_pos:
            new_sz = end_pos - prev_pos

            if new_sz >= min_chunk_len and len(seqlist[0]) - end_pos >= min_chunk_len:
                logger.info("@ {:x}({:x}) is a split point. new_size {:d}".format(base_addr+offset+end_pos, end_pos, new_sz))

                adj_split_pos.append(end_pos)
                prev_pos = end_pos
            else:
                logger.info("@ {:x}({:x}) is not a split point. new_size {:d}".format(base_addr+offset+end_pos,end_pos, new_sz))


        logger.info("Split:")

        # need to adjust `chunk_data`
        if len(adj_split_pos) == 0:
            new_chunk_data[offset] = seqlist
        else:
            curr_pos = 0
            for end_pos in adj_split_pos:
                for n, seq in enumerate(seqlist):

                    if is_zerofill(seq):
                        continue

                    sz = end_pos - curr_pos
                    if seq[curr_pos:end_pos] not in new_chunk_data[offset+curr_pos]:
                        new_chunk_data[offset+curr_pos].append(seq[curr_pos:end_pos])

                    logger.info("@{:x}({}) cur:{} end:{} {}".format(
                                    offset+curr_pos, 
                                    end_pos - curr_pos, 
                                    curr_pos, 
                                    end_pos, 
                                    to_hex(seq[curr_pos:end_pos][:32])))
                curr_pos = end_pos
            else:
                end_pos = len(seq)

                for n, seq in enumerate(seqlist):
                    sz = end_pos - curr_pos

                    if seq[curr_pos:end_pos] not in new_chunk_data[offset+curr_pos]:
                        new_chunk_data[offset+curr_pos].append(seq[curr_pos:end_pos])

                    logger.info("@{:x}({}) cur:{} end:{} {}".format(
                                    offset+curr_pos, 
                                    end_pos - curr_pos, 
                                    curr_pos, 
                                    end_pos, 
                                    to_hex(seq[curr_pos:end_pos][:32])))

    logger.info("len(new_chunk_data) {}".format(len(new_chunk_data)))

    return (new_chunk_data, new_chunk_meta)

def count_matches(l_bin, r_bin):
    matched = 0
    for lb, rb in zip(l_bin, r_bin):
        if lb == rb:
            matched += 1
    return matched

def select_chunks(chunk_data, start_addr, elf_packed, args):

    selected_chunks = dict()

    sz = int(args.size)
    sex = int(args.sex)

    for offset in chunk_data.keys():

        if len(chunk_data[offset]) == 0:
            continue

        if args.packed:
            start_va = offset+start_addr
            end_va = offset+start_addr+len(chunk_data[offset][0])
            packed_mem = get_virt(elf_packed, start_va, end_va)

        if args.original:
            elf_orig = ELFPack(open(args.original, 'rb').read())
            start_va = offset+start_addr
            end_va = offset+start_addr+len(chunk_data[offset][0])
            orig_mem = get_virt(elf_orig, start_va, end_va)

        logger.info("%08x - %08x (%d):"%(offset + start_addr, 
                                offset + start_addr + len(chunk_data[offset][0]), 
                                len(chunk_data[offset][0])))
        # check zerofill
        target_chunk_data = []
        for d in chunk_data[offset]:
            if not is_zerofill(d):
                target_chunk_data.append(d)

        logger.info("len(target_chunk_data):{}".format(len(target_chunk_data)))

        selected = None
        is_ok = False

        if len(target_chunk_data) == 0:
            # No target chunks, i.e., all candidates are zerofilled. 
            # So, we can select any of them. 

            selected = chunk_data[offset][0]
            if args.packed and args.original:
                logger.info("\t selected: {} due to only this. matches {},{}".format(
                                            to_hex(selected[:32]), 
                                            count_matches(selected, packed_mem),
                                            count_matches(selected, orig_mem)))
            else:
                logger.info("\t selected: {} due to only this.".format(
                                            to_hex(selected[:32])))

            selected_chunks[offset] = selected
            continue

        elif len(target_chunk_data) == 1:
            selected = target_chunk_data[0]
            if args.packed and args.original:
                logger.info("\t selected: {} due to only this. matches {},{}".format(
                                            to_hex(selected[:32]), 
                                            count_matches(selected, packed_mem),
                                            count_matches(selected, orig_mem)))
            else:
                logger.info("\t selected: {} due to only this.".format(
                                            to_hex(selected[:32])))

            selected_chunks[offset] = selected
            continue

        selected = target_chunk_data[0]
        entropy = math.floor(H(selected) * 100) / 100

        for d in target_chunk_data:
            entropy = math.floor(H(d) * 100) / 100

            logger.info("\t%020f %s"%(entropy, to_hex(d[:32])))

            # We should ignore 0 entropy
            if entropy == 0:
                continue

            if entropy < math.floor(H(selected)*100)/100:
                logger.info("found a lower entropy {} {}".format(entropy, H(selected)))
                selected = d
                is_ok = True

        matches = 0

        if is_ok:
            logger.info("found the lowest entropy")
        else:
            # check the matched rate with packed
            if args.packed:
                min_matched = count_matches(selected, packed_mem)

                for i, d in enumerate(target_chunk_data):
                    matches = count_matches(d, packed_mem)
                    if min_matched > matches:
                        selected = d
                        min_matched = matches

        if args.original:
            logger.info("\t selected: {} matches = {},{}".format(
                                        to_hex(selected[:32]), 
                                        matches,
                                        count_matches(selected, orig_mem)))
        else:
            logger.info("\t selected: {} ".format(
                                        to_hex(selected[:32])))

        selected_chunks[offset] = selected

    return selected_chunks

def dump2file(chunk_data, common_bytes, selected_chunks, start_addr, end_addr, args):

    if args.output_dir:
        fn = args.output_dir+"/%016x-%016x.raw" % (start_addr, end_addr)
    else:
        fn = "%016x-%016x.raw" % (start_addr, end_addr)

    f = open(fn, 'wb')
    offset = 0
    while offset < args.delta:

        if offset in chunk_data.keys():
            if selected_chunks[offset]:
                f.write(selected_chunks[offset])
                logger.info("writing offset={:x} {:x}".format(
                                    offset, 
                                    len(selected_chunks[offset])))
                offset += len(selected_chunks[offset])
            else:
                assert False, "No Selected Chunk"
        else:
            b = common_bytes[offset]
            try:
                f.write(struct.pack("B", b))
            except:
                print("offset:", hex(offset), "b:",b)
                assert False, "invalid viz_mem"
            logger.info("writing offset={:x} 1".format(offset))
            offset += 1

    f.close()

def main(args):

    text_start = args.text_addr
    text_size  = args.text_size

    sz = int(args.size)
    sex = int(args.sex)

    subdirs = os.listdir(args.rootdir)
    subdirs.sort()

    if args.packed:
        if sz != 0 and sex != 0:
            elf_packed = ELFPack(open(args.packed, 'rb').read(), size=sz, sex=sex)
        else:
            elf_packed = ELFPack(open(args.packed, 'rb').read())
    else:
        elf_packed = None

    for start_addr in range(text_start, text_start + text_size, args.delta):

        end_addr = start_addr + args.delta
        packed_mem = get_virt(elf_packed, start_addr, end_addr)

        logger.info("start_addr {:x}, end_addr {:x}, delta {:x}".format(
                                        start_addr, end_addr, args.delta))

        target_subdirs, target_mem = collect_target_mem(start_addr, 
                                                    end_addr, 
                                                    subdirs, 
                                                    args)
        if len(target_subdirs) == 0:
            logger.warning("No target_subdirs")
            continue

        #target_mem = normalize_target_mem(target_mem)

        # identify the common bytes in the all `d`
        #common_bytes = find_common_bytes(target_mem, args)

        common_bytes = dict()

        logger.info("common bytes: %d/%d"%(len(common_bytes),len(target_mem[0])))
#        for offset, b in common_bytes.items():
#            logger.info("[common] {:x} {:02x}".format(offset, b))

        if len(common_bytes) == len(target_mem[0]):
            logger.info("no chunk found") # should go to a part for writing to a file
            continue

        # chunk_meta: a list containing the positions of chunks.
        #  a list of (chunk_start, chunk_end, chunk_size)
        chunk_meta = find_chunk_meta(common_bytes, args)
        logger.info("len(chunk_meta) {}".format(len(chunk_meta)))

        # chunk_data: a dict containing the candidate byte-sequences of each chunk
        #  key:offset, value: a list of byte-sequence
        chunk_data = find_chunk_data(target_mem, chunk_meta, packed_mem)

        # if necessary, split the chunks.
        chunk_data, chunk_meta = split_chunk_data(chunk_data, 
                                                    chunk_meta, 
                                                    start_addr)

        logger.info("len(chunk_data) after split {}".format(len(chunk_data)))

        # debug
#        for off, datalist in chunk_data.items():
#            logger.info("split:[d] offset:{:x} {:d}".format(off, len(datalist)))
#            for d in datalist:
#                logger.info("{:d} {:s}".format(len(d), to_hex(d[:32])))

        # calc the entropy of each chunk
        selected_chunks = select_chunks(chunk_data, start_addr, elf_packed, args)

        # Dump to a file 
        dump2file(chunk_data, common_bytes, selected_chunks, start_addr, end_addr, args)


def validate_byte_as_printable(byte):
    if is_character_printable(byte):
        return byte
    else:
        return 46

def is_character_printable(s):
    if s < 126 and s >= 33:
        return True 

def print_headers():
    print("")
    print("#### BINARY TO HEX DUMP - USING PYTHON3.6 ####")
    print("")
    print("Offset 00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F Encode to ASCII")
    print("")

def hexdump(d, start_addr=0):
    ascii_string = ""
    memory_address = start_addr
    print_headers()

    output = ""

    for byte in d:
        ascii_string = ascii_string + chr(validate_byte_as_printable(byte))
        if memory_address%16 == 0:
            output += format(memory_address, '06X')
            output += " " + hex(byte)[2:].zfill(2)
        elif memory_address%16 == 15:
            output +=" " + hex(byte)[2:].zfill(2)
            output +=" " + ascii_string + '\n'
            ascii_string = ""
        else:
            output += " " + hex(byte)[2:].zfill(2)
        memory_address = memory_address + 1

    logger.info(output)

if __name__ == '__main__':

    args = set_args()
    main(args)



