#!/usr/bin/env python3
"""导出 HUD 全局键表 `0x4993C4`（256 个 dword）→ `remake/p4_hudkeys.json`。

依据 `0x45EF50`（HUD 取值器）：

```
0x45EF6D  if ((key & 0xFF000000) == 0x21000000)
0x45EF84      eax = dword[0x4993C4 + (key & 0xFF)*4]      ; 全局键表
否则
0x45EF94      edx = dword[[h+0xEC] + (key & 0xFF)*4]      ; 按 kind 的表
```

每项由 `0x45DFB0` 拆包（`p4_hud_unpack`）：**值 = (v & 0x1F) × 10^((v>>5)&7)**，
另有 `(v>>8)&0xF`、`(v>>12)&0xF`、`v>>16` 三个字段。实测解出 0/100/200/80/600/500 等整数，
故这是**打包的十进制参数表**，不是文本/字形表（早前按 `v & 0xFF` 读出 'A'/'F' 是巧合）。
"""
import json
import pathlib
import struct

import pefile

EXE = pathlib.Path(__file__).resolve().parent.parent.parent / "geki106" / "geki106.exe"
BASE = 0x4993C4
COUNT = 256

pe = pefile.PE(str(EXE), fast_load=True)
ib = pe.OPTIONAL_HEADER.ImageBase
img = pe.get_memory_mapped_image()
off = BASE - ib
rows = list(struct.unpack("<%dI" % COUNT, img[off:off + COUNT * 4]))
out = pathlib.Path(__file__).resolve().parent / "p4_hudkeys.json"
out.write_text(json.dumps({"base": BASE, "keys": rows}, ensure_ascii=False), encoding="utf-8")
print(f"写出 {out}：{COUNT} 项")
print("  前 8 项 =", [hex(v) for v in rows[:8]])
print("  低字节样例 =", [chr(v & 0xFF) if 32 <= (v & 0xFF) < 127 else v & 0xFF for v in rows[:12]])
