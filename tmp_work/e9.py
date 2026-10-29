import sys; sys.path.insert(0,"/home/yuhuan/geki106_re")
import re_dis, capstone
R = re_dis.load()
def callers(target):
    out=[]
    for va, ins in R.insns.items():
        if ins.mnemonic in ('call','jmp') and ins.operands and ins.operands[0].type==capstone.x86.X86_OP_IMM:
            if ins.operands[0].imm==target: out.append((va,ins.mnemonic))
    return out
for t in (0x430740, 0x4307e0):
    print(f"{t:#x}:", [ (hex(a),m) for a,m in callers(t)][:10])
# also find any thunk jumping to 0x430740
for va, ins in R.insns.items():
    if ins.mnemonic=='jmp' and ins.operands and ins.operands[0].type==capstone.x86.X86_OP_IMM and ins.operands[0].imm==0x430740:
        print("thunk to 0x430740:", hex(va), "callers:", [(hex(a),m) for a,m in callers(va)][:10])
