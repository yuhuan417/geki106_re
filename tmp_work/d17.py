import sys; sys.path.insert(0,"/home/yuhuan/geki106_re")
import re_dis
R = re_dis.load()
for a in (0x40131b, 0x4010f0, 0x446450):
    ins = R.dec(a)
    print(f"{a:#x}: {ins.mnemonic} {ins.op_str}")
