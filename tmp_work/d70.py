import sys; sys.path.insert(0,"/home/yuhuan/geki106_re")
import re_dis, struct
R = re_dis.load()
for base in (0x4ad40c,0x4ad43c,0x4ad46c,0x4ad49c,0x4ad4cc,0x4ad4fc,0x4ad52c,0x4ad55c):
    d=R.raw(base,0x30)
    vals=struct.unpack('<12I', d)
    print(f"{base:#x}: " + ' '.join(f"{v:08x}" for v in vals))
