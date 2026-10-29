import sys; sys.path.insert(0,"/home/yuhuan/geki106_re")
import re_dis
R = re_dis.load()
for a in (0x401929, 0x402531, 0x4020d1, 0x401f0a, 0x401843, 0x401fdc):
    i=R.dec(a); print(f"{a:#x}: {i.mnemonic} {i.op_str}")
