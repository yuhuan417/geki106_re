import sys; sys.path.insert(0,"/home/yuhuan/geki106_re")
import re_dis, capstone
R = re_dis.load()
for t in (0x430110,0x435290,0x43a250,0x43bb70,0x445920,0x448e70,0x44afc0):
    sites=[va for va,ins in R.insns.items() if ins.mnemonic in('call','jmp') and ins.operands and ins.operands[0].type==capstone.x86.X86_OP_IMM and ins.operands[0].imm==t]
    print(f"ctor {t:#x}: {[hex(s) for s in sorted(sites)]}")
