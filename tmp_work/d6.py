import sys; sys.path.insert(0,"/home/yuhuan/geki106_re")
import re_dis
R = re_dis.load()
print("--- 0x40180c base ctor ---")
R.dis(0x40180c, 0x4018c0, 'base')
print("--- 0x402455 ---")
print(R.raw(0x402455,8).hex())
pc=0x402455
for i in range(6):
    ins=R.insns.get(pc) or R.dec(pc)
    print(f"{pc:#x}  {ins.mnemonic:<8} {ins.op_str}")
    if ins.mnemonic=='jmp': break
    pc+=ins.size
