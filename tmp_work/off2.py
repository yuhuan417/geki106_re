import sys, os, struct
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import re_dis, capstone
R = re_dis.load()
fe = sorted(R.funcs)
import bisect
def fn_of(va):
    i = bisect.bisect_right(fe, va)-1
    return fe[i] if i>=0 and va-fe[i] < 0x900 else None
for off in [0x48,0x4c,0x50,0x54,0x58]:
    print(f'== writes to [esi+{off:#x}]')
    seen=set()
    for va, ins in R.insns.items():
        op = ins.operands[0] if ins.operands else None
        if op and op.type==capstone.x86.X86_OP_MEM and op.mem.disp==off and op.mem.base==capstone.x86.X86_REG_ESI and ins.mnemonic not in ('cmp','test','push'):
            f = fn_of(va)
            if f in seen: continue
            seen.add(f)
            print(f'   {va:#x}  {ins.mnemonic} {ins.op_str}   in fn {f and hex(f)}')
