# Copyright (C) 2020 Zeropoint Dynamics

# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as
# published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.

# You should have received a copy of the GNU Affero General Public
# License along with this program.  If not, see
# <http://www.gnu.org/licenses/>.
# ======================================================================

from os import path
from zelos import Zelos, HookType
import sys

layers = {}

DATA_DIR = path.dirname(path.abspath(__file__))

def mem_hook_callback(zelos: Zelos, access: int, address: int, size: int, value: int):
    "Prints the destination and contents of every memory write."
#    print(f"mem_hook_callback Address: {address:x}, Value: {value:x}")
    for va in range(address, address+size):
        layer = 0
        if va in layers.keys():
            layer = layers[va]
        layers[va] = layer+1

def single_instr_hook(zelos, address, size):
    pass
 #   print(f"single_instr_hook Address: {address:x}, Size: {size:x}")

curr_layer = 0

def block_hook(zelos, address, size):

    global curr_layer

    if address not in layers.keys():
        return

    layer = layers[address]

    print("curr_layer={:d} layer={:d}".format(curr_layer, layer))

    if layer:
        if layer != curr_layer:
            print(f"Found Change")
            curr_layer = layer
    else:
        if curr_layer != 0:
            print(f"Found Change")
            curr_layer = layer


#           struct utsname {
#               char sysname[];    /* Operating system name (e.g., "Linux") */
#               char nodename[];   /* Name within communications network
#                                     to which the node is attached, if any */
#               char release[];    /* Operating system release
#                                     (e.g., "2.6.28") */
#               char version[];    /* Operating system version */
#               char machine[];    /* Hardware type identifier */
#           #ifdef _GNU_SOURCE
#               char domainname[]; /* NIS or YP domain name */
#           #endif
#           };


def syscall_hook(zelos, sys_name, args, ret_val):
    if sys_name == "uname":
        print(sys_name, args, dir(args), type(args))
        arg_val = getattr(args, "buf", None)
        b = zelos.memory.read(arg_val, 1024)
        print("b=",b)
        va = arg_val
        offset = 0
        for i in range(5):
            s = zelos.memory.read_string(va)
            print(hex(va), s)
            va += (len(s) + 1)

        
# Initialize Zelos
#z = Zelos(path.join(DATA_DIR, "hello.bin"))
#z = Zelos(sys.argv[1], inst=False)
#z = Zelos(sys.argv[1], no_feeds=True)
z = Zelos(sys.argv[1])

# HookType.MEMORY.READ
z.hook_memory(HookType.MEMORY.WRITE, mem_hook_callback)
z.hook_execution(HookType.EXEC.BLOCK, block_hook)
#z.hook_execution(HookType.EXEC.INST, single_instr_hook, ip_low=0, ip_high=0xffffffff, end_condition=lambda: False)
#z.hook_execution(HookType.EXEC.INST, single_instr_hook, end_condition=lambda: True)
z.hook_syscalls(
    HookType.SYSCALL.AFTER, syscall_hook
)

# Start Execution
try:
    z.start()
except:
    sys.exit(1)
