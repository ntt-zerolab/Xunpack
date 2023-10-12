import sys
import os
import re
import subprocess
import argparse
import math
import logging
import multiprocessing

from SelectiveDump import collect_target_mem,find_chunk_meta,find_chunk_data,split_chunk_data,get_virt,H,bindiff,check_in_range,read_rawbytes,parse_dir,is_zerofill,to_hex,comp_dict_values,find_common_bytes,merge_chunk_meta,normalize_target_mem,merge_chunk_data,hexdump,dump2file,select_chunks,set_args


logger = logging.getLogger("SelectiveDumpMP")
logger.setLevel(logging.INFO)

sh = logging.StreamHandler()
fh = logging.FileHandler(filename="selective_dump_mp.log")

logger.addHandler(sh)
logger.addHandler(fh)

for _ in logging.root.manager.loggerDict:
    logging.getLogger(_).setLevel(logging.CRITICAL)
    #logging.getLogger(_).disabled = True

from elfpack import *

def worker(range_info, args):

    text_start = range_info[0]
    text_size  = range_info[1]

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
        for offset, b in common_bytes.items():
            logger.info("[common] {:x} {:02x}".format(offset, b))

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
        for off, datalist in chunk_data.items():
            logger.info("split:[d] offset:{:x} {:d}".format(off, len(datalist)))
            for d in datalist:
                logger.info("{:d} {:s}".format(len(d), to_hex(d[:32])))

        # calc the entropy of each chunk
        selected_chunks = select_chunks(chunk_data, start_addr, elf_packed, args)

        # Dump to a file 
        dump2file(chunk_data, common_bytes, selected_chunks, start_addr, end_addr, args)

def main(args):

    num_of_workers = 4

    start_addr = args.text_addr

    args_list = list()
    if args.text_size <= 0x1000:
        # No need to multipe process
        args_list.append((start_addr, args.text_size))
        args_list.append((0, 0))
        args_list.append((0, 0))
        args_list.append((0, 0))
    else:
        adjust_size = (args.text_size & ~0xfff) + 0x1000
        size = int(adjust_size/num_of_workers) & ~0xfff

        for i in range(num_of_workers):

            start_addr = args.text_addr + size * i

            if args.text_size + args.text_addr > start_addr + size:
                end_addr = start_addr + size
            else:
                end_addr = args.text_addr + args.text_size

            args_list.append((start_addr, end_addr-start_addr)) #start, size

    p1 = multiprocessing.Process(name="p1", target=worker, args=(args_list[0], args))
    p2 = multiprocessing.Process(name="p2", target=worker, args=(args_list[1], args))
    p3 = multiprocessing.Process(name="p3", target=worker, args=(args_list[2], args))
    p4 = multiprocessing.Process(name="p4", target=worker, args=(args_list[3], args))

    p1.start()
    p2.start()
    p3.start()
    p4.start()

    p1.join()
    p2.join()
    p3.join()
    p4.join()

if __name__ == '__main__':

    args = set_args()
    main(args)



