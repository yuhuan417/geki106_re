import sys; sys.path.insert(0,"/home/yuhuan/geki106_re")
import re_dis
R = re_dis.load()
for a in (0x4307e0, 0x459fe0, 0x43bbd0):
    print(f"{a:#x}: " + ' '.join(f'{b:02x}' for b in R.raw(a,16)))
# also 0x430740 raw
print("0x430740: " + ' '.join(f'{b:02x}' for b in R.raw(0x430740,32)))
print("0x401feb:", R.dec(0x401feb).mnemonic, R.dec(0x401feb).op_str)
