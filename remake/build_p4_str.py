#!/usr/bin/env python3
"""导出 `0x499798` 的字形 id 表（UTF-16 word 表）到 remake/pygame/p4_str_table.json。

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
    return 0


if __name__ == "__main__":
    sys.exit(main())
