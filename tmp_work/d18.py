import sys; sys.path.insert(0,"/home/yuhuan/geki106_re")
import re_dis
R = re_dis.load()
def dump(a, n=160, label=''):
    print(f"===== {label} {a:#x}")
    pc=a
    for i in range(n):
        ins=R.insns.get(pc) or R.dec(pc)
        if ins is None:
            print(pc, '??', R.raw(pc,8).hex()); break
        print(f"{pc:#x}  {ins.mnemonic:<8} {ins.op_str}")
        if ins.mnemonic in ('ret','retf','int3') : break
        pc+=ins.size
dump(0x43ad40, 120, '0x43ad40 queue add/remove?')
dump(0x43bed0, 90, '0x43bed0 remove')
