import sys, os, struct
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import re_dis
R = re_dis.load()
for a in [int(x,16) for x in sys.argv[1:]]:
    print(f'== callers of {a:#x}')
    for va, ins in R.xrefs(a):
        if ins.mnemonic in ('call','jmp'):
            print(f'   {va:#x}  {ins.mnemonic} <- func {[f for f in (va,)]}')
