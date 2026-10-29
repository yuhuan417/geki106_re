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
dump(0x43a7f0, 0x43a8b0, 'ctor 0x43A7F0')
for a in (0x40131b, 0x4010f0, 0x402455, 0x40213f, 0x4013d9, 0x401ff0):
    ins=R.dec(a); print(f"{a:#x}: {ins.mnemonic} {ins.op_str}")
