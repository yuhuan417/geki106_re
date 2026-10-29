import sys; sys.path.insert(0,"/home/yuhuan/geki106_re")
import re_dis
R = re_dis.load()
ins=R.dec(0x402374); print("0x402374:", ins.mnemonic, ins.op_str)
def dump(a, b, label=''):
    print(f"===== {label} {a:#x}-{b:#x}")
    pc=a
    while pc < b:
        ins=R.insns.get(pc) or R.dec(pc)
        if ins is None:
            print(pc, '??', R.raw(pc,8).hex()); break
        print(f"{pc:#x}  {ins.mnemonic:<8} {ins.op_str}")
        pc+=ins.size
dump(0x430290, 0x4302d0, 'base dtor?')
