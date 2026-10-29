import sys; sys.path.insert(0,"/home/yuhuan/geki106_re")
import re_dis
R = re_dis.load()
R.dis(0x43c0d0, 0x43c150, 'hit handling?')
print("0x401843:", R.dec(0x401843).mnemonic, R.dec(0x401843).op_str)
