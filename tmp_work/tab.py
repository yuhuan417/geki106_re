import sys, os, struct
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import re_dis
R = re_dis.load()
def dw(a): return struct.unpack('<I', R.raw(a,4))[0]
# byte table at 0x40e2f0 for 0xf3 entries
bt = R.raw(0x40e2f0, 0xF3)
print('byte table max index:', max(bt))
tgt = [dw(0x40e2e0+4*k) for k in range(max(bt)+1)]
for k,v in enumerate(tgt): print(f'  case[{k}] -> {v:#x}')
# group ranges
prev=None; start=None
for i,b in enumerate(bt):
    x = 0xF0+i
    if b!=prev:
        if prev is not None: print(f'   x {start:#x}..{0xF0+i-1:#x} -> case {prev} ({tgt[prev]:#x})')
        prev=b; start=x
print(f'   x {start:#x}..{0xF0+0xF2:#x} -> case {prev} ({tgt[prev]:#x})')
