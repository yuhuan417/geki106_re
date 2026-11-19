#!/usr/bin/env python3
"""属性表审计：把 page4 的 ENT_PROP / ENT_PROP_FAM 与 exe 的 7 张 10 字节表逐项对账。

表定义（0x43AC30 的 `push <表址>`）：
  0x23:0x498000  0x24:0x498138  0x25:0x498208  0x26:0x498290
  0x27:0x4983B0  0x28:0x498480  0x29:0x4985A0
每项：`[0]` 半径 byte、`[2]` 存活门 word（0 ⇒ −1）、`[4]` `+0x58` **s16**、
`[6]`/`[8]` 源矩形 word。索引 = `type & 0xFF` 再 −1（`0x43AC47 lea eax,[eax+eax*4]`，
`0x43AC4A ... -0xa`）。

用法：python3 remake/audit_props.py；rc=0 通过。
"""
import os
import struct
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(HERE, "pygame"))
sys.path.insert(0, ROOT)

os.environ.setdefault("SDL_VIDEODRIVER", "dummy")
os.environ.setdefault("SDL_AUDIODRIVER", "dummy")

import page4                                                # noqa: E402
import re_dis                                               # noqa: E402

BASE = 0x400000
TABLES = {
    0x23: 0x498000, 0x24: 0x498138, 0x25: 0x498208, 0x26: 0x498290,
    0x27: 0x4983B0, 0x28: 0x498480, 0x29: 0x4985A0,
}


def s16(v: int) -> int:
    v &= 0xFFFF
    return v - 0x10000 if v & 0x8000 else v


def main() -> int:
    R = re_dis.load()
    bad = 0
    for fam in range(0x23, 0x2A):
        table = getattr(page4, f"ENT{fam:02X}_INIT", None)
        if not table:
            continue
        base = TABLES[fam]
        for typ in sorted(table):
            addr = base + ((typ & 0xFF) - 1) * 10
            b = R.data[addr - BASE: addr - BASE + 10]
            if len(b) != 10:
                print(f"✗ {typ:#010x}: exe 表越界 @ {addr:#x}")
                bad += 1
                continue
            gate = struct.unpack_from("<H", b, 2)[0]
            exp = (b[0], -1 if gate == 0 else gate,
                   s16(struct.unpack_from("<H", b, 4)[0]),
                   struct.unpack_from("<H", b, 6)[0],
                   struct.unpack_from("<H", b, 8)[0])
            got = page4.ENT_PROP_FAM.get(typ)
            if got is None and fam == 0x23:
                got = page4.ENT_PROP.get(typ & 0xFF)
            if got is None:
                print(f"✗ {typ:#010x}: 缺属性项，exe={exp}")
                bad += 1
                continue
            got = (got[0], got[1], s16(got[2]), got[3], got[4])
            # exe 把 gate==0 改写成 −1（0x43AC59..0x43AC65），表里写 0 等价。
            got = (got[0], -1 if got[1] in (0, -1) else got[1], got[2], got[3], got[4])
            exp = (exp[0], -1 if exp[1] in (0, -1) else exp[1], exp[2], exp[3], exp[4])
            if got != exp:
                print(f"✗ {typ:#010x}: py={got} exe={exp}")
                bad += 1
    if bad:
        print(f"[audit_props] {bad} 处不一致")
        return 1
    print("[audit_props] 全部一致")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
