import sys; sys.path.insert(0,"/home/yuhuan/geki106_re")
import re_dis
R = re_dis.load()
for v in (0x401e65, 0x401a1e, 0x4011d1):
    print(f"--- callers of {v:#x}")
    for va, ins in R.insns.items():
        if ins.mnemonic=='call' and ins.operands and ins.operands[0].type==1 and ins.operands[0].imm==v:
            print(f"  {va:#x}  {ins.mnemonic:<8} {ins.op_str}")
