import pefile, capstone, struct
pe = pefile.PE('/home/yuhuan/geki106/geki106.exe')
ib = pe.OPTIONAL_HEADER.ImageBase
data = pe.get_memory_mapped_image()
md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
# 0x401e8d is a thunk: jmp XXXX
off = 0x401e8d - ib
assert data[off] == 0xe9
rel = struct.unpack('<i', data[off+1:off+5])[0]
target = 0x401e8d + 5 + rel
print("thunk target:", hex(target))
def dis(a, b, label):
    print(f"===== {label} {hex(a)} =====")
    for ins in md.disasm(data[a-ib:b-ib], a):
        print(f"{ins.address:#x}  {ins.mnemonic} {ins.op_str}")
dis(target, target+0x260, "resource loader")
