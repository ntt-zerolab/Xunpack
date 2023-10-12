from os import path
from zelos import Zelos, HookType
from zelos.exceptions import MemoryReadUnmapped
import sys
import os
import subprocess
import uuid
from hexdump import hexdump

curr_layer = 0
layers = {}
dump_index = 0
text_addr = 0
text_size = 0

dumproot = "/tmp/dump"

def write2file(filepath, data):
    print("write2file: fp", filepath)

    f = open(filepath, 'wb')
    f.write(data)
    f.close()


def dumps(zelos, min_addr, max_addr):

    global dump_index

    print("dumps min {:x} - {:x}".format(min_addr, max_addr))

    dumpdir = dumproot + "/%08x"%(dump_index)

    os.makedirs(dumpdir, exist_ok=True)

    start_va = (min_addr >> 12) << 12
    end_va = ((max_addr >> 12) << 12) + 0x1000

    buf = b''
    fstart_va = 0

    for va in range(start_va, end_va, 0x1000):

        if fstart_va == 0:
            fstart_va = va

        try:
            d = zelos.memory.read(va, 0x1000)
        except MemoryReadUnmapped:

            if len(buf):
                fend_va = fstart_va + len(buf) - 0x1000
                write2file(dumpdir+"/%016lx-%016lx.raw"%(fstart_va, fend_va), buf)
                buf = b''

            fstart_va = 0
            continue

        buf += d

        #print("\tva:{:x}".format(va), "len",len(d), dumpdir) 

    else:
        fend_va = fstart_va + len(buf) - 0x1000
        write2file(dumpdir+"/%016lx-%016lx.raw"%(fstart_va, fend_va), buf)

    dump_index += 1

def mem_hook_callback(zelos: Zelos, access: int, address: int, size: int, value: int):

    global layers

    ip = zelos.regs.getIP()

    layer = 0
    if ip in layers.keys():
        layer = layers[ip]

#    if address >= text_addr and address+size < text_addr + text_size:
#        print("found written layer=",layer+1, "@{:x}".format(address), "ip {:x}".format(ip), "value %x size:%x"%(value, size))

    for va in range(address, address+size):
        layers[va] = layer + 1

def single_instr_hook(zelos, address, size):
    pass


def block_hook(zelos: Zelos, address: int, size: int):

    global curr_layer

    if address not in layers.keys():
        layer = 0
    else:
        layer = layers[address]

    #print("@{:x} curr_layer={:d} layer={:d}".format(address, curr_layer, layer))

    if layer:
        if layer != curr_layer:
            print("Found Change. to {:d} from {:d}".format(layer, curr_layer))
            dumps(zelos, text_addr, text_addr+text_size)
            curr_layer = layer
    else:
        if curr_layer != 0:
            print("Found Change. to {:d} from {:d}".format(layer, curr_layer))
            dumps(zelos, text_addr, text_addr+text_size)
            curr_layer = layer

def syscall_hook(zelos, sys_name, args, ret_val):
    if sys_name == "set_thread_area":
        print(sys_name, args, dir(args), type(args))
        arg_val = getattr(args, "u_info", None)
        print("arg_val",hex(arg_val))
        b = zelos.memory.read(arg_val, 1024)
        hexdump(b)

#    if sys_name == "uname":
#        print(sys_name, args, dir(args), type(args))
#        arg_val = getattr(args, "buf", None)
#        b = zelos.memory.read(arg_val, 1024)
#        print("b=",b)
#        va = arg_val
#        offset = 0
#        for i in range(5):
#            s = zelos.memory.read_string(va)
#            print(hex(va), s)
#            va += (len(s) + 1)

        
# Initialize Zelos
#z = Zelos(path.join(DATA_DIR, "hello.bin"))
#z = Zelos(sys.argv[1], inst=False)
#z = Zelos(sys.argv[1], no_feeds=True)

target_path = sys.argv[1]
orig_path = sys.argv[2]
uuid_str = sys.argv[3]

if not uuid_str:
    dumproot = "/tmp/dump/"+str(uuid.uuid4())
else:
    dumproot = "/tmp/dump/"+uuid_str

#z = Zelos(target_path, env_vars='ELFCRYPT=password', inst=True, fasttrace=True)
#z = Zelos(target_path, env_vars='ELFCRYPT=password')
z = Zelos(target_path, inst=True, fasttrace=True)
#z = Zelos(target_path)

# text_addr and text_size
res = subprocess.run("readelf -S -W {} | grep text | cut -d \" \" -f 26".format(orig_path), shell=True, capture_output=True)
print(res.stdout)

text_addr = int(res.stdout.decode('utf-8'), 16) & (~0xfff)

res = subprocess.run("readelf -S -W {} | grep text | cut -d \" \" -f 28".format(orig_path), shell=True, capture_output=True)
text_size = (int(res.stdout.decode('utf-8'), 16) & (~0xfff)) + 0x1000

# HookType.MEMORY.READ
z.hook_memory(HookType.MEMORY.WRITE, mem_hook_callback)
z.hook_execution(HookType.EXEC.BLOCK, block_hook)
#z.hook_execution(HookType.EXEC.INST, single_instr_hook, ip_low=0, ip_high=0xffffffff, end_condition=lambda: False)
#z.hook_execution(HookType.EXEC.INST, single_instr_hook, end_condition=lambda: True)
#z.hook_syscalls(
#    HookType.SYSCALL.AFTER, syscall_hook
#)

z.hook_syscalls(
    HookType.SYSCALL.AFTER, syscall_hook
)

# Start Execution
try:
    z.start()
except:
    sys.exit(1)
