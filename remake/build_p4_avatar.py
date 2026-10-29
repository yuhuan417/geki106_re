#!/usr/bin/env python3
"""导出页4 头像/光标帧表 0x498A88（每项 14 字节 = 7 个 u16）→ remake/p4_avatar.json。

依据：`0x44E4A0` 逐字
    0x44E4AB eax = fid*8 ; 0x44E4B5 eax -= fid          ⇒ fid*7
    0x44E4B7 ecx = 0x498A88 + eax*2                     ⇒ 0x498A88 + fid*14
    0x44E4BE 复制 3 dword + 1 word（14 字节）到 [mgr+0x4C]
该表在 .rdata（段表：.rdata 起 0x498000、虚长 0x4A2308）⇒ 只读静态、可直接抄。
"""
import json
import pathlib
import struct

import pefile

HERE = pathlib.Path(__file__).resolve().parent
EXE = HERE.parent.parent / "geki106" / "geki106.exe"
BASE = 0x498A88
COUNT = 32          # fid 到 0x17 都还有效，0x18 起为 0（表尾）

pe = pefile.PE(str(EXE), fast_load=True)
ib = pe.OPTIONAL_HEADER.ImageBase
img = pe.get_memory_mapped_image()
rows = {}
for fid in range(COUNT):
    off = BASE - ib + fid * 14
    rows[str(fid)] = list(struct.unpack("<7H", img[off:off + 14]))
out = HERE / "p4_avatar.json"
out.write_text(json.dumps({"base": BASE, "stride": 14, "frames": rows},
                          ensure_ascii=False, indent=1), encoding="utf-8")
print(f"写出 {out}：{COUNT} 帧")
