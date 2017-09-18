import z3

mask= [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0xFF, 
  0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0xFF, 0xFF, 0xFF, 
  0xFF, 0xFF, 0xFF, 0xFF]
for i in range(0, len(mask)):
    mask[i] = z3.BitVecVal(mask[i], 16)

ncheck_arr = [0x70, 0x02, 0x11, 0x02, 0x55, 0x02, 0x29, 0x02, 0x91, 0x02, 
  0x5E, 0x02, 0x33, 0x02, 0xF9, 0x01, 0x78, 0x02, 0x7B, 0x02, 
  0x21, 0x02, 0x09, 0x02, 0x5D, 0x02, 0x90, 0x02, 0x8F, 0x02, 
  0xDF, 0x02]

# fix check_arr
check_arr = []
for i in range(0, len(ncheck_arr), 2):
    n = ncheck_arr[i+1] << 8
    n += ncheck_arr[i]
    check_arr.append(n)
    #print(hex(n))
#print([hex(n) for n in check_arr])

fb = [0xB8, 0x13, 0x00, 0xCD, 0x10, 0x0F, 0x20, 0xC0, 0x83, 0xE0, 0xFB, 0x83, 0xC8, 0x02, 0x0F, 0x22]
#fb = [0 for _ in range(len(fbn))]
# shuffle the array
# this ended up being not necessary, but was needed to unscramble the flag at the end
# implementation of pshufd
'''shufy = 0x1e
for i in range(0, len(fbn), 4):
    n = fbn[i] + (fbn[i+1] << 8) + (fbn[i+2] << 16) + (fbn[i+3] << 24)
    sy = ((0x1e & [3, 12, 48, 192][i/4]) >> [0, 2, 4, 6][i/4]) * 4
    #print(sy)
    fb[sy] = fbn[i]
    fb[sy+1] = fbn[i+1]
    fb[sy+2] = fbn[i+2]
    fb[sy+3] = fbn[i+3]'''
#print(fbn)
#print(fb)

def abs(x):
    return z3.If(x >= 0,x,-x)


c = []
for i in range(0, 16):
    c.append(z3.BitVec('c' + str(i), 16))


s = z3.Solver()
for k in c:
    s.add(0 <= k)
    s.add(k < 256)

#fm = 8
for fm in range(8, 0, -1):
    wantn = check_arr[(fm-1)*2]# + (check_arr[((i-1)*4) + 1] << 8)
    wantn2 = check_arr[ ( (fm-1)*2 ) + 1]
    #print(hex(wantn))
    #print(hex(wantn2))
    # ugly implementation of sum of absoulte differences
    s.add((abs( fb[0] - (c[0] & mask[fm])) + abs( fb[1] - (c[1] & mask[fm+1])) + abs( fb[2] - (c[2] & mask[fm+2])) + abs( fb[3] - (c[3] & mask[fm+3])) + abs( fb[4] - (c[4] & mask[fm+4])) + abs(fb[5] -  (c[5] & mask[fm+5])) + abs( fb[6] - (c[6] & mask[fm+6])) + abs(fb[7] -  (c[7] & mask[fm+7]))) == z3.BitVecVal(wantn, 16))
    s.add((abs( fb[8] - (c[8] & mask[fm+8])) + abs( fb[9] - (c[9] & mask[fm+9])) + abs( fb[10] - (c[10] & mask[fm+10])) + abs( fb[11] - (c[11] & mask[fm+11])) + abs( fb[12] - (c[12] & mask[fm+12])) + abs(fb[13] -  (c[13] & mask[fm+13])) + abs( fb[14] - (c[14] & mask[fm+14])) + abs(fb[15] -  (c[15] & mask[fm+15]))) == z3.BitVecVal(wantn2, 16))
    fb = [wantn2 & 0xff, (wantn2 & 0xff00) >> 8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, wantn & 0xff, (wantn & 0xff00) >> 8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]

print(s.check())
m = s.model()

for k in c:
    print(chr(m[k]))
