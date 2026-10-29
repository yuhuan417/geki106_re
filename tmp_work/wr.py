import sys, os, struct
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import re_dis
R = re_dis.load()
for v in [0x49872c,0x498734,0x49874c,0x498750,0x498754,0x498758]:
    print(f'== writes_to {v:#x}')
    for va, ins in R.writes_to(v):
        print(f'   {va:#x}  {ins.mnemonic} {ins.op_str}')
    print(f'== xrefs {v:#x}')
    for va, ins, i in R.xrefs(v):
        print(f'   {va:#x}  {ins.mnemonic} {ins.op_str}')
