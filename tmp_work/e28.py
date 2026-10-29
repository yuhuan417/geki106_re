import sys; sys.path.insert(0,"/home/yuhuan/geki106_re")
import re_dis
R = re_dis.load()
t=R.dec(0x401fdc); print("0x401fdc:", t.mnemonic, t.op_str)
if t.mnemonic=='jmp':
    R.dis(t.operands[0].imm, t.operands[0].imm+0x60, 'on-hit handler')
