import sys; sys.path.insert(0,"/home/yuhuan/geki106_re")
import re_dis, struct
R = re_dis.load()
for k in range(26):
    v=struct.unpack('<I', R.raw(0x40de98+4*k,4))[0]
    print(f"[{k}] type=0x{k+0x23000001:08X} -> {v:#x}")
