import sys; sys.path.insert(0,"/home/yuhuan/geki106_re")
import re_dis
R = re_dis.load()
for v in (0x498738, 0x499344):
    print(f"--- xrefs to {v:#x}")
    for va, ins, i in R.xrefs(v):
        print(f"  {va:#x}  {ins.mnemonic:<8} {ins.op_str}")
