import sys; sys.path.insert(0,"/home/yuhuan/geki106_re")
import re_dis, capstone
R = re_dis.load()
ct = [0x430110,0x435290,0x43a250,0x43bb70,0x445920,0x448e70,0x44afc0]
queues=[0x4ad40c,0x4ad43c,0x4ad46c,0x4ad49c,0x4ad4cc,0x4ad4fc,0x4ad52c]
for va in sorted(R.insns):
    ins=R.insns[va]
    if ins.mnemonic=='mov' and ins.op_str.startswith('ecx, 0x4ad'):
        imm=int(ins.op_str.split(', ')[1],16)
        if imm not in queues: continue
        pc=va+ins.size
        for k in range(3):
            i2=R.insns.get(pc)
            if i2 is None: break
            if i2.mnemonic=='call' and i2.operands and i2.operands[0].type==capstone.x86.X86_OP_IMM:
                t=i2.operands[0].imm
                print(f"queue {imm:#x} <- call {t:#x} at {pc:#x}")
                break
            pc+=i2.size
