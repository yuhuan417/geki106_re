import sys; sys.path.insert(0,"/home/yuhuan/geki106_re")
import re_dis
R = re_dis.load()
for va in sorted(R.insns):
    if 0x456930 <= va < 0x456ae0:
        i=R.insns[va]
        print(f"{va:#x}  {i.mnemonic:<8} {i.op_str}")
