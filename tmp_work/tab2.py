import sys, os, struct
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import re_dis
R = re_dis.load()
base = 0x498000
for n in range(1, 0x1b):
    off = base + (n-1)*10
    b = R.raw(off, 10)
    w = b[0]
    p18 = struct.unpack('<H', b[2:4])[0]
    p58 = struct.unpack('<h', b[4:6])[0]
    sx  = struct.unpack('<H', b[6:8])[0]
    sy  = struct.unpack('<H', b[8:10])[0]
    print(f' type 0x230000{n:02X}: rec@{off:#x}  w={w:3d} +0x18={p18:5d} (+0x58={p58:6d}) rect=({sx},{sy},{sx+2*w-1},{sy+2*w-1})')
