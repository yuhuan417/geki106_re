import pefile, capstone, struct

pe = pefile.PE('/home/yuhuan/geki106/geki106.exe')
ib = pe.OPTIONAL_HEADER.ImageBase
data = pe.get_memory_mapped_image()
md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)

def dis(va_start, va_end):
    code = data[va_start - ib:va_end - ib]
    for ins in md.disasm(code, va_start):
        print(f"{ins.address:#x}  {ins.mnemonic} {ins.op_str}")

print("===== resource.rom loader full =====")
dis(0x45dba3, 0x45dcb4)
