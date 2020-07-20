
#include <stdio.h>
#include <stdlib.h>
/*
   mov rdi, qword [rsp + rdx*8 + 0x10]j
   xor edx, edx
   0x9a0 ;[gm]                                                
   || ; JMP XREF from 0x000009c3 (sub.World_s_greatest_stack_calcu
   || lea rax, [rdi + rdx]
   || add rdx, 1
   || mov rsi, rax
   || shl rax, 0xc
   || shr rsi, 0xc
   || and rax, r13
   || or rax, rsi
   || xor rdi, rax
   || cmp rdx, 0xc35a
   || jne 0x9a0;[gm]

*/
unsigned long long jumble_asm(unsigned long long num) {
    unsigned long long counter = 0;
    unsigned long long out;
    // mask = 0xfff00000 00000000
    unsigned long long mask = 0xfff0000000000000;

    while (counter != 0xc35a) {
	asm volatile (
            "mov %%rdi, %%rax\n\t"
            "add %%rdx, %%rax\n\t"
            "add $1, %%rdx\n\t"
            "mov %%rax, %%rsi\n\t"
            "shl $0xc, %%rax\n\t"
            "shr $0xc, %%rsi\n\t"
            "and %%rcx, %%rax\n\t"
            "or %%rsi, %%rax\n\t"
            "xor %%rax, %%rdi\n\t"
            "mov %%rdi, %%rax\n\t"
	    : "=r" (out), "=rdx" (counter)
	    : "rdx" (counter), "rcx" (mask), "rdi" (num));
    }

    return out;
}

unsigned long long jumble(unsigned long long num) {
    unsigned long long wtf, left, right, tmp, counter = 0;
    // mask = 0xfff00000 00000000
    unsigned long long mask = 0xfff0000000000000;

    while (counter != 0xc35a) {
        tmp = num + counter;
	counter += 1;

	left = tmp << 12;
	right = tmp >> 12;
        wtf = (left & mask) | right;
        num ^= wtf;
    }
    
    return num;
}

typedef struct strong_long {
    unsigned long long val;
} strong_long;

strong_long jumble_strong(strong_long num) {
    strong_long wtf, left, right, tmp, counter = (strong_long) { .val = 0 };
    // mask = 0xfff00000 00000000
    strong_long mask = (strong_long) { .val = 0xfff0000000000000 };

    while (counter.val != 0xc35a) {
        tmp.val = num.val + counter.val;
	counter.val += 1;

	left.val = tmp.val << 12;
	right.val = tmp.val >> 12;
        wtf.val = (left.val & mask.val) | right.val;
        num.val ^= wtf.val;
    }
    
    return num;
}

void show_convert_strong(unsigned long long i) {
    strong_long strong = (strong_long) { .val = i };
    printf("%016llx -> %016llx\n", i, jumble_strong(strong).val);
}

void show_convert(unsigned long long i) {
    printf("%016llx -> %016llx\n", i, jumble(i));
}


int main(void) {
    printf("%016llx\n", jumble_strong((strong_long) { .val = 5 }).val);
    printf("%016llx\n", jumble(5));
    // srand(0);
    // for (int i = 0; i < 1000; i++) {
    //     // show_convert(0 - rand());
    //     show_convert(i);
    // }
    // return 0;
}
