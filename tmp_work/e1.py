import sys; sys.path.insert(0,"/home/yuhuan/geki106_re")
import re_dis
R = re_dis.load()
def dump(a, b, label=''):
    print(f"===== {label} {a:#x}-{b:#x}")
    pc=a
    while pc < b:
        ins=R.insns.get(pc) or R.dec(pc)
        if ins is None:
            print(pc, '??', R.raw(pc,8).hex()); break
        print(f"{pc:#x}  {ins.mnemonic:<8} {ins.op_str}")
        pc+=ins.size
dump(0x40d940, 0x40d9d0, 'dispatch 0x23 family + case 1')
dump(0x40e100, 0x40e1f0, 'behavior 0x40E100')
