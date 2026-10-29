import sys; sys.path.insert(0,"/home/yuhuan/geki106_re")
import re_dis, capstone
R = re_dis.load()
ins=R.dec(0x4013e3); print("0x4013e3:", ins.mnemonic, ins.op_str)
sites=[(va,ins2) for va,ins2 in R.insns.items() if ins2.mnemonic=='call' and ins2.operands and ins2.operands[0].type==capstone.x86.X86_OP_IMM and ins2.operands[0].imm==0x4013e3]
for va,_ in sorted(sites):
    # show previous 4 insns
    out=[]; pc=va
    for k in range(4):
        for d in range(1,20):
            c=R.insns.get(pc-d)
            if c and pc-d+c.size==pc:
                out.insert(0,f"{pc-d:#x} {c.mnemonic} {c.op_str}"); pc=pc-d; break
        else: break
    print(f"{va:#x}: " + ' | '.join(out))
