import sys; sys.path.insert(0,"/home/yuhuan/geki106_re")
import re_dis, capstone
R = re_dis.load()
base=0x4aa7b0
reg=None
for va in sorted(R.insns):
    if not (0x456800 <= va < 0x456c80): continue
    ins=R.insns[va]
    if ins.mnemonic=='lea' and ins.op_str.startswith('ecx, [esi + '):
        off=int(ins.op_str.split('+ ')[1].rstrip(']'),16)
        pc=va+ins.size
        # find next call
        for k in range(6):
            i2=R.insns.get(pc)
            if i2 is None: break
            if i2.mnemonic=='call' and i2.operands and i2.operands[0].type==capstone.x86.X86_OP_IMM:
                t=i2.operands[0].imm
                print(f"{va:#x} obj={base+off:#x} (esi+{off:#x}) call {t:#x}")
                break
            pc+=i2.size
