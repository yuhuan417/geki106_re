import pefile, capstone, struct, sys
pe = pefile.PE('/home/yuhuan/geki106/geki106.exe')
ib = pe.OPTIONAL_HEADER.ImageBase
data = pe.get_memory_mapped_image()
sec = pe.sections[0]; text = sec.get_data(); tva = ib + sec.VirtualAddress
tend = tva + len(text)
md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
md.detail = False

def decode_at(start, maxlen=40):
    out=[]
    off = start - tva
    for ins in md.disasm(text[off:off+maxlen], start):
        out.append((ins.address, ins.size, ins.mnemonic, ins.op_str, ins.bytes))
        if len(out)>=10: break
    return out

def containing(h):
    """resync: find best instruction start <= h whose instruction covers h"""
    cands=[]
    for st in range(h-20, h+1):
        if st < tva: continue
        ins = decode_at(st, 25)
        if not ins: continue
        a,s,m,o,b = ins[0]
        if a <= h < a+s:
            # score: consecutive valid bytes from st
            good = sum(i[1] for i in ins)
            cands.append((good, st, ins))
    if not cands: return None
    cands.sort(key=lambda x:(-x[0], -x[1]))
    return cands[0]

def scan(val, label):
    print(f"\n##### refs to {hex(val)} ({label}) #####")
    pat = struct.pack('<I', val)
    i=0
    while True:
        i = text.find(pat, i)
        if i<0: break
        h = tva + i
        r = containing(h)
        if r:
            good, st, ins = r
            print(f"--- hit {h:#x} (insn start {st:#x}) ---")
            for a,s,m,o,b in ins[:4]:
                mark = ' <<<' if a<=h<a+s else ''
                print(f"  {a:#x}  {m} {o}{mark}")
        else:
            print(f"--- hit {h:#x} (no decode) ---")
        i += 1

for v,l in [(0x4AB59C,'x'),(0x4AB5A0,'y')]:
    scan(v,l)
