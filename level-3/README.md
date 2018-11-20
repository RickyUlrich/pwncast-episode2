
## Exploit binary security settings
```
In [2]: ELF("level-3")
[*] '/vagrant/level-3/level-3'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
    FORTIFY:  Enabled
```

## x64 calling convention
RDI, RSI, RDX, RCX, R8, R9

## Reverse engineering of code
```
# global variable
char *executable_buffer_ptr;

# play_the_game - 0x970
char local_fh
int *local_10h

executable_buffer_ptr = mmap(0, 0x1000, 7, 0x22, i -1, 0)

printf("I have a pointer %p\n", executable_buffer_ptr)

while (true) {
	read(0, &local_fh, 1)
	// absolute arbitrary 1 byte write
	if (local_fh == 1) {
		read(0, &local_10h, 8)
		read(0, &local_fh, 1)
                *local_10h = local_fh

	// absolute arbitrary 1 byte leak
	} else if (local_fh == 2) {
		read(0, &local_10h, 8)
		write(1, local_10h, 1)

	} else {
		break;
        }
}
```

## Final exploit execution
```
$ ~/libc-database/find write 140 mmap 9d0 setvbuf
2f0 puts 9c0
http://ftp.osuosl.org/pub/ubuntu/pool/main/g/glibc/libc6_2.27-3ubuntu1_amd64.deb (id libc6_2.27-3ubuntu1_amd64)
$ ~/libc-database/dump libc6_2.27-3ubuntu1_amd64 puts environ
offset_puts = 0x00000000000809c0
offset_environ = 0x00000000003ee098

# put these offset at the top of level-3-pwn.py
# and comment out respective variables according to target
./level-3-pwn.py
...
ls -a
```

## Exploit explanation
  1. generate/write out shellcode
     executable buffer is roughly generated like this c code below
     executable_buffer_ptr = mmap(0, 0x1000, 7, 0x22, i -1, 0)
  2. get libc base address
  3. get environ address
  4. read stack address from environ variable
  5. read stack values until we find saved return address on stack
  6. corrupt stack address
