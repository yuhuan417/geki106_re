#!/usr/bin/env python3
"""导出页4 输入配置表 0x498A88（每项 14 字节 = 7 个 u16）→ remake/p4_avatar.json。

**这不是 sprite 帧表**（2026-10-29 由消费点定案）：`0x44E8B5` 读 byte[mgr+0x4C] 作摇杆启用位
（为 0 则整段摇杆处理跳过）、`0x44E917` 读 byte[mgr+0x4E]、`0x44E91C` 读 movsx word[mgr+0x50]
作灵敏度并按 ±0x3E8 归一。`0x44E4A0(mgr,fid,dir)` 把本表整项覆盖到 `+0x4C` 起 ⇒ 按 fid 切换输入配置。

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
cfgs = {}
for fid in range(COUNT):
    off = BASE - ib + fid * 14
    w = struct.unpack("<7H", img[off:off + 14])
    rows[str(fid)] = list(w)
    # 字节视图：+0x4C=w0.lo（摇杆启用）、+0x4E=w1.lo（标志）、+0x50=w2（灵敏度）
    cfgs[str(fid)] = {
        "raw": list(w),
        "joy_enable": w[0] & 0xFF,      # [mgr+0x4C]
        "flag_4e": w[1] & 0xFF,         # [mgr+0x4E]
        "sens_50": w[2],                # [mgr+0x50]，Poll 用 movsx word
    }
out = HERE / "p4_avatar.json"
out.write_text(json.dumps({"base": BASE, "stride": 14,
                           "fields": {"0x4C": "joy_enable", "0x4E": "flag_4e", "0x50": "sens_50"},
                           "configs": cfgs, "frames": rows},
                          ensure_ascii=False, indent=1), encoding="utf-8")
print(f"写出 {out}：{COUNT} 项输入配置")
for fid in (0, 7, 9, 0x17):
    print(f"  fid {fid:2} → {cfgs[str(fid)]}")
