import sys; sys.path.insert(0,"/home/yuhuan/geki106_re")
import re_dis, capstone
R = re_dis.load()
R.dis(0x4306c0, 0x430735, 'hit test')
# find thunk + callers
ths=[va for va,ins in R.insns.items() if ins.mnemonic=='jmp' and ins.operands and ins.operands[0].type==capstone.x86.X86_OP_IMM and ins.operands[0].imm==0x4306c0]
print("thunks:", [hex(t) for t in ths])
calls=[va for va,ins in R.insns.items() if ins.mnemonic=='call' and ins.operands and ins.operands[0].type==capstone.x86.X86_OP_IMM and ins.operands[0].imm in ths]
print("callers:", [hex(c) for c in sorted(calls)][:20], "count", len(calls))
