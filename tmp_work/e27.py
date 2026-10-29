import sys; sys.path.insert(0,"/home/yuhuan/geki106_re")
import re_dis, capstone
R = re_dis.load()
for va in sorted(R.insns):
    if not (0x430000 <= va < 0x470000): continue
    ins=R.insns[va]
    if not ins.operands: continue
    o=ins.operands[0]
    if o.type==capstone.x86.X86_OP_MEM and o.mem.disp==0x18 and o.mem.base!=0 and getattr(o,'size',0)==4:
        if ins.mnemonic in ('mov','dec','inc','sub','add','and','or'):
            print(f"{va:#x}  {ins.mnemonic:<8} {ins.op_str}")
