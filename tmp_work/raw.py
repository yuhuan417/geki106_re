import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import re_dis, capstone
R = re_dis.load()
a=int(sys.argv[1],16); n=int(sys.argv[2],16)
print(R.raw(a,n).hex(' '))
md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
for i in md.disasm(R.raw(a,n), a):
    print(f'{i.address:#x}  {i.bytes.hex():<20} {i.mnemonic:<8}{i.op_str}')
