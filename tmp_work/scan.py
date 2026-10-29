import sys, os, struct
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import re_dis
R = re_dis.load()
t = R.text
for tgt in [int(x,16) for x in sys.argv[1:]]:
    print(f'== raw call/jmp to {tgt:#x}')
    for i in range(len(t)-5):
        b = t[i]
        if b in (0xE8,0xE9):
            rel = struct.unpack('<i', t[i+1:i+5])[0]
            va = R.tva + i
            if va+5+rel == tgt:
                print(f'   {va:#x}  {"call" if b==0xE8 else "jmp"}')
