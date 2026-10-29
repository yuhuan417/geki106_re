import sys, os, struct
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import re_dis, capstone
R = re_dis.load()
md = R.md
X86_OP_REG, X86_OP_IMM, X86_OP_MEM = 1,2,3
a=int(sys.argv[1],16); b=int(sys.argv[2],16)
esp = 0   # relative to entry ESP (e0)
pc=a
while pc < b:
    ins = md.disasm(R.raw(pc,16), pc).__next__()
    note=''
    # pre-execution stack reference
    refs=[]
    for op in ins.operands:
        if op.type==X86_OP_MEM and op.mem.base==capstone.x86.X86_REG_ESP:
            refs.append(op.mem.disp + esp)
    if ins.mnemonic=='push': esp -= 4
    if ins.mnemonic=='pop': esp += 4
    if ins.mnemonic=='ret': esp += 4
    if ins.mnemonic in ('ret',) and ins.operands: esp += ins.operands[0].imm
    if ins.mnemonic in ('sub','add') and ins.operands[0].type==X86_OP_REG and ins.operands[0].reg==capstone.x86.X86_REG_ESP:
        v = ins.operands[1].imm
        esp += (-v if ins.mnemonic=='sub' else v)
    extra = ''
    if refs: extra = '  ; [e0%+d]' % refs[0] if len(refs)==1 else '  ; ' + ','.join('[e0%+d]'%r for r in refs)
    if ins.mnemonic=='push':
        extra += '  (arg/stack slot e0%+d)' % esp
    print(f'{pc:#x}  esp={esp:+#5x}  {ins.mnemonic:<8}{ins.op_str}{extra}')
    pc += ins.size
