import pefile, capstone, struct, sys

pe = pefile.PE('/home/yuhuan/geki106/geki106.exe')
image_base = pe.OPTIONAL_HEADER.ImageBase
sections = []
for s in pe.sections:
    sections.append((image_base + s.VirtualAddress, s.VirtualAddress, s.Misc_VirtualSize, s.get_data()))

data = pe.get_memory_mapped_image()

def va2off(va):
    rva = va - image_base
    return pe.get_offset_from_rva(rva)

# find string addresses
def find_str(s):
    b = s.encode() if isinstance(s, str) else s
    res = []
    start = 0
    while True:
        i = data.find(b + b'\0', start)
        if i < 0: break
        res.append(image_base + i)
        start = i + 1
    return res

md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
md.detail = False

targets = {
    'GROD': find_str('GROD'),
    'GGPD': find_str('GGPD'),
    'GRCD': find_str('GRCD'),
    'GRPD': find_str('GRPD'),
    'resource.rom': find_str('resource.rom'),
    '106A': [a for a in find_str('106A')],
}

for name, addrs in targets.items():
    print(f"### {name}: {[hex(a) for a in addrs]}")

# scan .text for references to these addresses (any 4-byte LE value equal to addr)
text_va = image_base + pe.sections[0].VirtualAddress
text_data = pe.sections[0].get_data()
print("\n### xrefs (imm32 in .text):")
for name, addrs in targets.items():
    for a in addrs:
        b = struct.pack('<I', a)
        i = 0
        while True:
            i = text_data.find(b, i)
            if i < 0: break
            va = text_va + i
            print(f"{name} str@{hex(a)} referenced at {hex(va)}")
            i += 1
