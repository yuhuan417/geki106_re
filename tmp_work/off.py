import sys, os, struct, collections
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import re_dis, capstone
R = re_dis.load()
offs = [int(x,16) for x in sys.argv[1:]]
cnt = collections.Counter()
for va, ins in R.insns.items():
    for i,op in enumerate(ins.operands):
        if op.type==capstone.x86.X86_OP_MEM and op.mem.disp in offs and op.mem.base==capstone.x86.X86_REG_ESI:
            cnt[(op.mem.disp, i==0 and ins.mnemonic not in ('cmp','test','push'))]+=1
for k,v in sorted(cnt.items()):
    print(f'  disp={k[0]:#x} write={k[1]} count={v}')
