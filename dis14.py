import pefile, capstone, struct
pe = pefile.PE('/home/yuhuan/geki106/geki106.exe')
ib = pe.OPTIONAL_HEADER.ImageBase
data = pe.get_memory_mapped_image()
sec = pe.sections[0]; text = sec.get_data(); tva = ib + sec.VirtualAddress
md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
def dis(a, b, label):
    print(f"===== {label} =====")
    for ins in md.disasm(text[a-tva:b-tva], a):
        print(f"{ins.address:#x}  {ins.mnemonic} {ins.op_str}")
dis(0x457c00, 0x457e00, "emitter bank methods")
