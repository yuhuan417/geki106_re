import sys; sys.path.insert(0,"/home/yuhuan/geki106_re")
import re_dis, capstone
R = re_dis.load()
pat = {0x280: 'w', 0x1e0: 'h'}
for va, ins in R.insns.items():
    if ins.mnemonic!='mov' or len(ins.operands)!=2: continue
    a,b=ins.operands
    if a.type!=capstone.x86.X86_OP_MEM or b.type!=capstone.x86.X86_OP_IMM: continue
    if b.imm in pat and a.mem.disp in (0,4,8,0xc,0x10,0x14):
        print(f"{va:#x}  {ins.mnemonic} {ins.op_str}")
