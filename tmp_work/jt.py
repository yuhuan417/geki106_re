import sys, os, struct
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import re_dis
R = re_dis.load()
def dw(a): return struct.unpack('<I', R.raw(a,4))[0]
base=int(sys.argv[1],16); n=int(sys.argv[2],16); lo=int(sys.argv[3],16) if len(sys.argv)>3 else 0
for k in range(n):
    v=dw(base+4*k)
    print(f'  [{k:#04x}] {v:#010x}   type={lo+k:#010x}')
