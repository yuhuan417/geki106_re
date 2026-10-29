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
print("0x43ad40:", R.dec(0x43ad40).mnemonic, R.dec(0x43ad40).op_str)
print("0x40154b:", R.dec(0x40154b).mnemonic, R.dec(0x40154b).op_str)
dump(0x43bed0, 0x43bf20, 'remove entity 0x43BED0')
