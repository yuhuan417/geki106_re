import sys; sys.path.insert(0,"/home/yuhuan/geki106_re")
import re_dis
R = re_dis.load()
for a in (0x40227f, 0x401848):
    ins=R.dec(a); print(f"{a:#x}: {ins.mnemonic} {ins.op_str}")
def dump(a, n=60, label=''):
    print(f"===== {label} {a:#x}")
    pc=a
    for i in range(n):
        ins=R.insns.get(pc) or R.dec(pc)
        if ins is None:
            print(pc, '??', R.raw(pc,8).hex()); break
        print(f"{pc:#x}  {ins.mnemonic:<8} {ins.op_str}")
        if ins.mnemonic in ('ret','retf','int3') : break
        pc+=ins.size
dump(0x45a360, 60, '0x45a360')
