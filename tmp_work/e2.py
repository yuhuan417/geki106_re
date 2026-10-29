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
dump(0x43ac30, 0x43ad00, '0x402455 = 0x43AC30 (sprite table init)')
dump(0x43bc70, 0x43bd00, 'queue 4AD43C tick 0x43BC70')
