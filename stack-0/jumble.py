#!/usr/bin/env python3

def jumble(num):
    # mask = 0xfff00000 00000000
    mask = 0xfff0000000000000

    for i in range(0xc35a):
        foo = (num + i) & 0xffffffffffffffff
        wtf = ((foo << 12) & mask) | (foo >> 12)
        num ^= wtf
    
    return num

def jumble_reverse(num):
    # mask = 0xfff00000 00000000
    mask = 0xfff0000000000000

    for i in range(0xc35a - 1, -1, -1):
        foo = (num + i) & 0xffffffffffffffff
        wtf = ((foo << 12) & mask) | (foo >> 12)
        num ^= wtf
    
    return num

def show_convert(i):
    # print("{} -> {}".format(i, jumble(i)))
    print("{:08x} -> {:08x}".format(i, jumble(i)))

if __name__ == "__main__":
    for i in range(100):
        show_convert(i)
