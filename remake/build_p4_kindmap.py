"""导出 `0x457938` 一级表（256 字节）与 `0x457908` 二级跳表（12 个 dword）→ remake/p4_kindmap.json。

依据（页4 §16.149）：
  0x4577DF  cl = byte[0x457938 + kind]
  0x4577E5  jmp dword ptr [ecx*4 + 0x457908]
"""
import json
import pathlib

import pefile

EXE = "../geki106/geki106.exe"
OUT = pathlib.Path(__file__).with_name("p4_kindmap.json")

kindmap_base = 0x457938
jump_base = 0x457908
jump_n = 12

pe = pefile.PE(EXE, fast_load=True)
ib = pe.OPTIONAL_HEADER.ImageBase
img = pe.get_memory_mapped_image()

kindmap = list(img[kindmap_base - ib:kindmap_base - ib + 0x100])
jumps = [int.from_bytes(img[jump_base - ib + i * 4:jump_base - ib + i * 4 + 4], "little")
         for i in range(jump_n)]

OUT.write_text(json.dumps({
    "kindmap_base": kindmap_base, "kindmap": kindmap,
    "jump_base": jump_base, "jumps": [hex(x) for x in jumps],
}, ensure_ascii=False), encoding="utf-8")
print(f"写出 {OUT}：kindmap {len(kindmap)} 项、jumps {len(jumps)} 项")
print("跳表:", [hex(x) for x in jumps])
for k in (0, 6, 10, 16, 24, 32, 48, 72, 108, 160, 240):
    print(f"  kind {k:3d} → 分支 {kindmap[k]}")
