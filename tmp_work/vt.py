import sys, os, struct
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import re_dis
R = re_dis.load()
def dw(a): return struct.unpack('<I', R.raw(a,4))[0]
for base in (0x498734, 0x49874c):
    print('==== vtable', hex(base))
    for i in range(0, 0x50, 4):
        v = dw(base+i)
        tag = ''
        ins = R.insns.get(v)
        print(f'  +{i:#04x}  {v:#010x}', (ins.mnemonic+' '+ins.op_str) if ins else '')
