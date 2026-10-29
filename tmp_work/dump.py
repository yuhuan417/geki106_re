import sys, os, struct
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import re_dis
R = re_dis.load()
def pad_end(start, limit=0x4000):
    d = R.data; o = start - R.ib
    i = d.find(b'\xcc\xcc\xcc\xcc', o, o+limit)
    return (R.ib+i) if i>=0 else None
out = open(sys.argv[1], 'w')
addrs = [int(x,16) for x in sys.argv[2:]]
for a in addrs:
    e = pad_end(a)
    if e is None: e = a+0x400
    out.write(f"===== {a:#x}-{e:#x} len={e-a:#x} ({e-a})\n")
    pc = a
    while pc < e:
        ins = R.insns.get(pc) or R.dec(pc)
        if ins is None:
            out.write(f"{pc:#x}  ?? {R.raw(pc,8).hex()}\n"); pc+=1; continue
        out.write(f"{pc:#x}  {ins.mnemonic:<9}{ins.op_str}\n")
        pc += ins.size
    out.write("\n")
out.close()
print('ok', sys.argv[1])
