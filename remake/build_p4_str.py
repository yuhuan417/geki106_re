#!/usr/bin/env python3
"""导出两张页4 数据表到 remake/pygame/：

- `0x499798` → `p4_str_table.json`（`0x4602D0` 用的字形 id word 表）
- `0x4993C4` → `p4_tbl_4993c4.json`（`0x45FAD0` 在 0x21000000 族查的 256 项 dword 表）

`0x4602D0(this, sid)` 用 `word[0x499798 + sid*2]` 逐项取 id（0 为终止），
`0x4600F0` 再把队首 id 交给 `0x45DDA0`/`0x45DDE0` 取出资源位图。
"""
import json
import struct
import sys
from pathlib import Path

import pefile

EXE = Path(__file__).resolve().parents[2] / "geki106" / "geki106.exe"
BASE = 0x499798
TBL_4993C4 = 0x4993C4
LIMIT = 64


def main() -> int:
    pe = pefile.PE(str(EXE), fast_load=True)
    ib = pe.OPTIONAL_HEADER.ImageBase
    img = pe.get_memory_mapped_image()
    words = []
    for i in range(LIMIT):
        v = struct.unpack_from("<H", img, BASE - ib + i * 2)[0]
        words.append(v)
        if v == 0 and len(words) > 9:
            break
    out = Path(__file__).resolve().parent / "pygame" / "p4_str_table.json"
    out.write_text(json.dumps(words, separators=(",", ":")))
    print(f"{BASE:#x}: {len(words)} words -> {out}")
    print(" ".join(str(w) for w in words))

    tbl = [struct.unpack_from("<I", img, TBL_4993C4 - ib + i * 4)[0] for i in range(256)]
    out2 = Path(__file__).resolve().parent / "pygame" / "p4_tbl_4993c4.json"
    out2.write_text(json.dumps(tbl, separators=(",", ":")))
    print(f"{TBL_4993C4:#x}: 256 dwords ({sum(1 for v in tbl if v)} 非零) -> {out2}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
