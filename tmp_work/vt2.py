import sys, os, struct
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import re_dis
R = re_dis.load()
def dw(a): return struct.unpack('<I', R.raw(a,4))[0]
base=0x498700
print('==== raw 0x498700..0x498790')
for i in range(0, 0x90, 4):
    v = dw(base+i)
    code = R.tva <= v < R.tend
    print(f'  {base+i:#08x}  {v:#010x}  {"CODE" if code else ""}')
