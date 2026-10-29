import sys; sys.path.insert(0,"/home/yuhuan/geki106_re")
import re_dis
R = re_dis.load()
for a in (0x401e01, 0x4013b1, 0x40139d, 0x401569, 0x402540, 0x402004):
    ins=R.dec(a); print(f"{a:#x}: {ins.mnemonic} {ins.op_str}")
R.dis(0x4568c8, 0x4568e8, 'ctor for 4AD43C')
