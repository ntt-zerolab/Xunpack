import sys
import os
from collections import defaultdict
import re
import hashlib
from tabulate import tabulate
import subprocess
import argparse
import math
from elfpack import *

def get_virt(elf, start_addr, end_addr):

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
    parser.add_argument('src_file',    help = 'a binary to compare from')
    parser.add_argument('dst_file',  help = 'a binary to compared to')
    parser.add_argument('--text_addr',  help = 'the address of .text section', type=auto_int, default=0)
    parser.add_argument('--text_size',  help = 'the size of .text section', type=auto_int, default=0)
    parser.add_argument('--funclist',  help = '(optional) function list')
    parser.add_argument('--instlist',  help = '(optional) instruction list')
    parser.add_argument('--ignore',  help = '(optional) ignore 0xCC for comparison', action="store_true", default=False)

    args = parser.parse_args()
    return args

def H(data):
    ''' Calculate the entropy of a given data block '''
    entropy = 0
    for x in range(256):
        p_x = data.count(x)/len(data)
        if p_x > 0:
            entropy += -p_x*math.log(p_x, 2)
    return entropy

def block_entropy(data, block_size):
    ''' Generator for calculating the entropy of a file,
        given a size for the data blocks '''
    for x in range(0, len(data)//block_size):
        start = x * block_size
        end = start + block_size
        yield H(data[start:end])

def func_based_match(elf_src, elf_dst, args):

    funclist, instlist = read_funclist(args.funclist, args.instlist)

    total_size = 0
    g_matched  = 0
    g_ignored  = 0
    g_func_cnt = 0

    false_counts = defaultdict(list)
    zerofill_counts = defaultdict(list)

    for func_start, func_end in funclist.items():

        matched = 0
        ignored = 0

        if func_start > args.text_addr + args.text_size or func_end < args.text_addr:
            continue

        func_size = func_end - func_start

        if func_size == 0:
            continue

        dst_func = get_virt(elf_dst, func_start, func_end)
        src_func = get_virt(elf_src, func_start, func_end)

        off = 0
        for src_d, dst_d in zip(src_func, dst_func):

            if args.ignore:
                if dst_d == 0xcc and src_d != 0xcc:
                    ignored += 1

            if src_d == dst_d:
                matched += 1
            else:
                if dst_d != 0x00:
                    false_counts[func_start].append(off)
                else:
                    zerofill_counts[func_start].append(off)
            off += 1

        if func_size - ignored == 0:
            continue

        if instlist[func_start] > 0 and (float(matched)/(func_size - ignored)) < 0.9:
            res = "[x]"
        else:
            res = "[-]"

        print(res, "%08x - %08x"%(func_start, func_end), 
                float(matched)/(func_size - ignored), 
                "matched:", matched, 
                "funcsize:",func_size, 
                "#exec:",   instlist[func_start], 
                "#ignored:", ignored)

        g_matched += matched
        g_ignored += ignored
        g_func_cnt += 1

        total_size += func_size

    for func, offsets in false_counts.items():
        if instlist[func] > 0:
            print("[+]",hex(func), len(offsets), ",".join(["0x%x"%(x+func) for x in offsets]))

    for func, offsets in zerofill_counts.items():
        if instlist[func] > 0:
            print("[z]",hex(func), len(offsets), ",".join(["0x%x"%(x+func) for x in offsets]))

    return (g_matched, g_ignored, g_func_cnt, total_size)

def binary_based_match(elf_src, elf_dst, args):

    start = args.text_addr
    end = start + args.text_size

    total_matched = 0
    total_ignored = 0
    total_size    = 0

    for va in range(start, end, 0x1000):
        #src_data = get_virt(elf_src, args.text_addr, args.text_addr+args.text_size) 
        #dst_data = get_virt(elf_dst, args.text_addr, args.text_addr+args.text_size) 
        src_data = get_virt(elf_src, va, va+0x1000) 
        dst_data = get_virt(elf_dst, va, va+0x1000)

        matched = 0
        ignored = 0

        #for n, d in enumerate(src_d):
        for src_d, dst_d in zip(src_data, dst_data):

            if args.ignore:
                if dst_d == 0xcc and src_d != 0xcc:
                    ignored += 1

            if src_d == dst_d:
                matched += 1

        total_matched += matched
        total_ignored += ignored
        data_sz = len(src_data)
        print("[-] {:x}-{:x}: matched:{:d} ignored:{:d} score:{}".format(va, va+0x1000, matched, ignored, float(matched)/float(data_sz)))

        total_size += len(src_data)

    return (total_matched, total_ignored, 0, total_size)

def read_funclist(fd, inst_fd=None):

    funclist = defaultdict(int)

    f = open(fd)
    lines = f.readlines()
    f.close()

    for l in lines:
        l = l.rstrip()
        e = l.split(",")
        start_addr = int(e[0], 16)
        end_addr = int(e[1], 16)
        funclist[start_addr] = end_addr

    instlist = defaultdict(int)

    if inst_fd:

        f = open(inst_fd)
        lines = f.readlines()
        f.close()

        for l in lines:
            l = l.rstrip()
            addr = int(l, 16)

            for start, end in funclist.items():
                if addr >= start and addr < end:
                    instlist[start]+=1

    return (funclist, instlist)

def main():
    args = set_args()

    elf_src = ELFPack(open(args.src_file, 'rb').read())
    elf_dst = ELFPack(open(args.dst_file, 'rb').read())

    if args.funclist:
        (matched, ignored, func_cnt, total_size) = func_based_match(
                                                    elf_src,
                                                    elf_dst,
                                                    args)
    else:
        (matched, ignored, func_cnt, total_size) = binary_based_match(
                                                    elf_src,
                                                    elf_dst, 
                                                    args)

    print("matched:", float(matched)/float(total_size - ignored))
    print("\ttotal_size:{} matched:{} ignored:{} func_cnt:{}".format(
                total_size, matched, ignored, func_cnt))

if __name__ == '__main__':
    main()
