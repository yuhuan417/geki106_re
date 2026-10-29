import sys; sys.path.insert(0,"/home/yuhuan/geki106_re")
import re_dis, struct
R = re_dis.load()
for k in range(12):
    v=struct.unpack('<I', R.raw(0x499344+4*k,4))[0]
    print(f"[{k}] {v:#x}")
