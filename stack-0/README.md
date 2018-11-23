
## Hardening measures
```
>>> ELF("stack-0")
[*] '/vagrant/stack-0/stack-0'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
    FORTIFY:  Enabled
```

## reverse engineering of code
### `World_s_greatest_stack_calculator()`
```
puts("World's greatest stack calculator!\n");

// stack = rsp + 0x10
// next_variable (?) = rsp + 0x58
unsigned long long stack[9];
int stack_head = 0;
char cmd;
while(1)
{
    read(0, &cmd, sizeof(cmd));

    /* "The base of the calculator stack is %d" */
    if (cmd == 0) {
	printf("The base of the calculator stack is %p", stack);
    
    /*
    qword on the stack
    "Give me 8 bytes for the next qword on the calculator stack"
    */
    } else if (cmd == 1) {
	stack_head += 1;
	read(0, &stack[stack_head], 8);

    /* "push(+ pop() pop())" */
    } else if (cmd == 2) {
	if (stack_head == 0) {
	    puts("No funny business!\n");
	    exit(0);
	}
	val2 = stack[stack_head];
	stack_head -= 1
	stack[stack_head] += val2;

    /* "jumble" */
    } else if (cmd == 3) {
	rdx = 0
	rdi = stack[stack_head];
	mask = r13 = 0xfff00000 00000000
	while (rdx != 0xc35a) {
	    rax = rdi + rdx
	    rsi = rax
	    rax <<= 12
	    rsi >>= 12
	    rax &= 0xfff00000 00000000
	    rax |= rsi
	    rdi ^= rax
	    
	    // c representation
	    foo = rdi + rdx
	    //   abcd efgh ijkl mnop
	    //   000a bcde fghi jklm
	    // | defg hijk lmno p000
	    // ----------------------
	    // | def? ???? ???? ?klm
	    wtf = ((foo << 12) & mask) | (foo >> 12)
	    rdi ^= wtf

	    rdx += 1;
	}
	stack[stack_head] = rdi

    } else { break; }
}
```

## Useful links
- https://stackoverflow.com/questions/3003339/how-can-i-get-gdb-to-tell-me-what-address-caused-a-segfault
- https://blog.eadom.net/uncategorized/pwntools-quick-reference-guide/
