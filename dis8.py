import pefile, capstone
pe = pefile.PE('/home/yuhuan/geki106/geki106.exe')
ib = pe.OPTIONAL_HEADER.ImageBase
data = pe.get_memory_mapped_image()
md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
def dis(a, b, label):
    print(f"===== {label} {hex(a)} =====")
    for ins in md.disasm(data[a-ib:b-ib], a):
        print(f"{ins.address:#x}  {ins.mnemonic} {ins.op_str}")
dis(0x460d80, 0x460f80, "mci site 5 + timer")
