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

layers = {}

DATA_DIR = path.dirname(path.abspath(__file__))

def mem_hook_callback(zelos: Zelos, access: int, address: int, size: int, value: int):
    "Prints the destination and contents of every memory write."
    print(f"mem_hook_callback Address: {address:x}, Value: {value:x}")

def single_instr_hook(zelos, address, size):
    print(f"single_instr_hook Address: {address:x}, Size: {size:x}")

def block_hook(zelos, address, size):
    print(f"block_hook Address: {address:x}, Size: {size:x}")

# Initialize Zelos
z = Zelos(path.join(DATA_DIR, "hello.bin"))

# HookType.MEMORY.READ
z.hook_memory(HookType.MEMORY.WRITE, mem_hook_callback)
z.hook_execution(HookType.EXEC.BLOCK, block_hook)
z.hook_execution(HookType.EXEC.INST, single_instr_hook, ip_low=0, ip_high=0xffffffff, end_condition=lambda: False)
#z.hook_execution(HookType.EXEC.INST, single_instr_hook, end_condition=lambda: True)

# Start Execution
z.start()
