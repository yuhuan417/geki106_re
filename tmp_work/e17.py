import sys; sys.path.insert(0,"/home/yuhuan/geki106_re")
import re_dis, struct
R = re_dis.load()
for base in (0x498730, 0x498740, 0x498750, 0x498760):
    vals=[struct.unpack('<I', R.raw(base+4*k,4))[0] for k in range(4)]
    print(f"{base:#x}: " + ' '.join(f"{v:#010x}" for v in vals))
d=R.raw(0x498734,0x40)
print(' '.join(f"{b:02x}" for b in d))
