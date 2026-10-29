import sys; sys.path.insert(0,"/home/yuhuan/geki106_re")
import re_dis
R = re_dis.load()
def dump(a, n=140, label=''):
    print(f"===== {label} {a:#x}")
    pc=a
    for i in range(n):
        ins=R.insns.get(pc) or R.dec(pc)
        if ins is None:
            print(pc, '??', R.raw(pc,8).hex()); break
        print(f"{pc:#x}  {ins.mnemonic:<8} {ins.op_str}")
        if ins.mnemonic in ('ret','retf','int3') : break
        pc+=ins.size
for t,l in [(0x401f5a,'4ad55c'),(0x401235,'4ad40c'),(0x40220c,'4ad46c'),(0x401929,'4ad43c'),(0x402077,'4ad49c'),(0x40161d,'4ad4cc'),(0x40123f,'4ad4fc'),(0x401681,'4cd484')]:
    dump(t, 3, l)
