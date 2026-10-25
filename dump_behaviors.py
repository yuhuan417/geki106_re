import pefile, capstone, struct
pe = pefile.PE('/home/yuhuan/geki106/geki106.exe')
ib = pe.OPTIONAL_HEADER.ImageBase
data = pe.get_memory_mapped_image()
sec = pe.sections[0]; text = sec.get_data(); tva = ib + sec.VirtualAddress
md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
def thunk(va):
    off = va - ib
    return va + 5 + struct.unpack('<i', data[off+1:off+5])[0] if data[off] == 0xe9 else va
BEHAVIORS = [0x401FF0,0x401B1D,0x401BD1,0x401528,0x4015AA,0x401181,0x401609,0x40210D,
             0x401BA9,0x40138E,0x401DC5,0x4015B4,0x401D48,0x401951,0x4013BB,0x401B31,0x40242D,0x401C44]
out = open('behaviors.asm','w')
for b in BEHAVIORS:
    t = thunk(b)
    out.write(f"\n===== behavior {b:#x} -> {t:#x} =====\n")
    for ins in md.disasm(text[t-tva:t-tva+0x120], t):
        out.write(f"{ins.address:#x}  {ins.mnemonic} {ins.op_str}\n")
out.close()
print("dumped behaviors.asm")
