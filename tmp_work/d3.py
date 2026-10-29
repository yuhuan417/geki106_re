import sys; sys.path.insert(0,"/home/yuhuan/geki106_re")
import re_dis
R = re_dis.load()
# find extent of function at 0x40d940: walk until ret
pc=0x40d940
n=0
while n<600:
    ins=R.insns.get(pc) or R.dec(pc)
    if ins is None: break
    print(f"{pc:#x}  {ins.mnemonic:<8} {ins.op_str}")
    if ins.mnemonic in ('ret','jmp') : break
    pc+=ins.size; n+=1
