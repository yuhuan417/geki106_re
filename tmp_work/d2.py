import sys; sys.path.insert(0,"/home/yuhuan/geki106_re")
import re_dis
R = re_dis.load()
R.dis(0x4013d9, 0x4013f0, 'thunk')
print(R.raw(0x4013d9,8).hex())
