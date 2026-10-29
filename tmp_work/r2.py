import sys, os, struct
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import re_dis
R = re_dis.load()
def show(v):
    print(f'== {v:#x}')
    for va, ins, i in R.xrefs(v):
        print(f'   {va:#x}  {ins.mnemonic} {ins.op_str}')
for a in sys.argv[1:]:
    show(int(a,16))
