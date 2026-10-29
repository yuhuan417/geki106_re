import sys; sys.path.insert(0,"/home/yuhuan/geki106_re")
import re_dis, capstone
R = re_dis.load()
for va in sorted(R.insns):
    if not (0x430000 <= va < 0x470000): continue
    ins=R.insns[va]
    ops=ins.operands
    if not ops: continue
    # byte-sized memory operand at disp 0x10 or 0xc
    for o in ops:
        if o.type==capstone.x86.X86_OP_MEM and o.size==1 and o.mem.disp in (0x10,0xc,0x4c) and o.mem.base!=0:
            print(f"{va:#x}  {ins.mnemonic:<8} {ins.op_str}")
            break
