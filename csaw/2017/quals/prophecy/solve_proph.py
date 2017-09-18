#!/usr/bin/env python2
# this is just my way to send input to the server, not really a solver script
# all the text was found with RE, hexrays made it easy
from pwn import *
context.log_level = 'DEBUG'

#r = process("./prophecy")
r = remote("reversing.chal.csaw.io", 7668)
#r = process("linux_serverx64")

scrt_name = ".starcraft"

r.recvuntil(">>")
r.sendline(scrt_name)
r.recvuntil(">>")
cha1 = "Z" # O, or Z, or K, or J
cha2 = "\x03" # 01 or 03
buf = "\x08\x25\x20\x17"  +"a" + "\x00"+ "a" * 6 + cha1 + cha2 + "\x93\xea\xe4\x00" + "ZERATUL\x00" + "SAVED"
r.sendline(buf)
print r.recvall()
#raw_input()
