import pefile, capstone, struct
pe = pefile.PE('/home/yuhuan/geki106/geki106.exe')
ib = pe.OPTIONAL_HEADER.ImageBase
data = pe.get_memory_mapped_image()
sec = pe.sections[0]; text = sec.get_data(); tva = ib + sec.VirtualAddress
md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32); md.detail=True

def insn_ending_at(end, maxback=10):
    """find instruction whose bytes end exactly at `end`"""
    for st in range(end-maxback, end):
        if st<tva: continue
        ins = next(md.disasm(text[st-tva:st-tva+maxback+2], st), None)
        if ins and ins.address+ins.size==end:
            if ins.address==st:
                return ins
    return None

def scan(val,label):
    print(f"\n##### {hex(val)} {label} #####")
    pat=struct.pack('<I',val); i=0; n=0
    while True:
        i=text.find(pat,i)
        if i<0: break
        h=tva+i
        ins=insn_ending_at(h+4)
        if ins:
            ops=[o for o in ins.operands]
            wr = ins.operands and ins.operands[0].type==capstone.x86.X86_OP_MEM and ins.mnemonic not in ('cmp','test','push')
            txt=f"{ins.address:#x}  {ins.mnemonic} {ins.op_str}"
            print(("W " if wr else "r ")+txt)
            n+=1
        i+=4
    print("count",n)
for v,l in [(0x4AB59C,'cmdX'),(0x4AB5A0,'cmdY')]:
    scan(v,l)
