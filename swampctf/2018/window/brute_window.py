#!/usr/bin/env python2

from pwn import *
import sys
from datetime import datetime
context.log_level = 'WARN'
# Bruteforces a patched window binary to find the correct key

#st = 1522428771
st = 1522428690


ctr = 0
while True:
    p = process("FAKE_TIME_START=" + str(st) + " LD_PRELOAD=./libfaketime.so ./OS.BIN_p", shell = True)
    res = p.recvall()
    if "NOT AUTHORIZED" not in res:
        print("found the flag!")
        print(res)
        sys.exit(0)
    st -= 1
    if ctr % 100000 == 0:
        print(str(datetime.fromtimestamp(st)))
    ctr += 1


