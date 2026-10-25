import pefile, capstone, struct

pe = pefile.PE('/home/yuhuan/geki106/geki106.exe')
ib = pe.OPTIONAL_HEADER.ImageBase
data = pe.get_memory_mapped_image()
sec = pe.sections[0]  # .text
text = sec.get_data()
tva = ib + sec.VirtualAddress

for magic in [b'GGPD', b'GROD', b'GRCD', b'GRPD']:
    i = 0
    while True:
        i = text.find(magic, i)
        if i < 0: break
        print(f"{magic.decode()} inline at va={hex(tva+i)}")
        i += 1

# disassemble around resource.rom usage 0x45db5b
md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
def dis(va, back=200, fwd=400):
    # find containing area: just disassemble from va-back with linear sweep attempt
    off = va - ib - back
    code = data[va - ib - back : va - ib + fwd]
    for ins in md.disasm(code, va - back):
        marker = ' <<<<' if ins.address <= va < ins.address + ins.size else ''
        print(f"{ins.address:#x}  {ins.mnemonic} {ins.op_str}{marker}")

print("\n===== around resource.rom ref =====")
dis(0x45db5b, back=100, fwd=300)
