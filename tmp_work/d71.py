import sys; sys.path.insert(0,"/home/yuhuan/geki106_re")
import re_dis
R = re_dis.load()
for v in (0x459f70, 0x459fe0, 0x45a070, 0x4307e0, 0x430800):
    print(f"--- xrefs to {v:#x}")
    for va, ins, i in R.xrefs(v):
        print(f"  {va:#x}  {ins.mnemonic:<8} {ins.op_str}")
