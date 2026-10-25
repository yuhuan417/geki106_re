import pefile, capstone, struct
pe = pefile.PE('/home/yuhuan/geki106/geki106.exe')
ib = pe.OPTIONAL_HEADER.ImageBase
data = pe.get_memory_mapped_image()
md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)

# what import is at 0x5e7384?
for entry in pe.DIRECTORY_ENTRY_IMPORT:
    for imp in entry.imports:
        if imp.address and 0x5e7380 <= imp.address <= 0x5e7390:
            print("IAT 0x5e7384:", entry.dll.decode(), imp.name, imp.ordinal)

def dis(a, b, label):
    print(f"===== {label} {hex(a)} =====")
    for ins in md.disasm(data[a-ib:b-ib], a):
        print(f"{ins.address:#x}  {ins.mnemonic} {ins.op_str}")
dis(0x44f71c, 0x44f870, "wave loader cont")

# dump data at 0x499d38
off = 0x499d38 - ib
print("data@0x499d38:", data[off:off+32].hex())
# strings at 0x4999e8, 0x499c48, 0x4a47a0
for va in [0x4999e8, 0x499c48, 0x4a47a0]:
    o = va - ib
    end = data.find(b'\0', o)
    print(hex(va), data[o:end])
