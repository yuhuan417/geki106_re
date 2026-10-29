import sys, os, struct, bisect
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import re_dis
R = re_dis.load()
t = R.text
def next_call(va, n=8):
    pc = va
    for _ in range(n):
        ins = R.insns.get(pc) or R.dec(pc)
        if ins is None: return None, None
        if ins.mnemonic=='call': return pc, ins.operands[0].imm if ins.operands[0].type==2 else None
        pc += ins.size
    return None, None
for q in [0x4ad43c,0x4ad4cc,0x4ad4fc,0x4ad52c,0x4ad40c,0x4ad49c,0x4ad46c,0x4ad55c]:
    hits={}
    for va, ins, i in R.xrefs(q):
        if ins.mnemonic=='mov' and ins.op_str.startswith('ecx'):
            cva, ctgt = next_call(va)
            if ctgt: hits.setdefault(ctgt, []).append(va)
        if ins.mnemonic=='push' and ins.op_str == hex(q):
            cva, ctgt = next_call(va)
            if ctgt: hits.setdefault(('push',ctgt), []).append(va)
    print(f'== queue {q:#x}')
    for k,v in sorted(hits.items(), key=lambda kv: -len(kv[1]))[:6]:
        print(f'   -> {k}  x{len(v)}  first {v[0]:#x}')
