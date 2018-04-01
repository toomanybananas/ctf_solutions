#!/usr/bin/env python2
# correct token is 0xff4fdc56
# Prints out the next 100 times that the flag can be retrieved
from pwn import *
from numpy import uint32
import sys
from datetime import datetime

def gettoken(t):
    tv_sec = uint32(t)
    res = (((tv_sec & 0xFFC) << 16) - uint32(348403646)) ^ ((tv_sec & 0xF0) << 8) | ((tv_sec & 0xFFC) << 8) | ((tv_sec >> 8) << 24) | tv_sec & 0xFC
    return res & 0xffffffff

st = 1522429623
ctr = 0
while True:
    tok = gettoken(st)
    st += 1
    if tok == 0xff4fdc56:
        print("can get flag at: ")
        print(str(datetime.fromtimestamp(st)))
        ctr += 1
        if ctr == 100:
            sys.exit(0)
    #if ctr % 100000 == 0:
        #print(str(datetime.fromtimestamp(st)))
    #ctr += 1
