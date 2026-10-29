#!/usr/bin/env python3
"""从 `docs/p4_listings/01_enter_4505B0.txt`（真实反汇编）机械提取 `0x4505B0` 参数块的常量表。

为什么重做：旧 `build_p4_block.py` 用 capstone 抽象求值，遇到
`mov word ptr [esp+0x3e], ax` 这类 **16 位子寄存器** 就静默留 0 ⇒ 分支 C 的四张表
（0x3C/0x44/0x4C/0x54）全成 0；`0x5C` 还串到了别的区间。

本脚本的两条硬规则（都可人工核对）：

1. **`push` 位移陷阱**：`mov [esp+X], …` 的块偏移 = `X - 0x10 - pend`，`pend` = 当前
   已压入、尚未被 callee 吃掉的实参个数（`push` +1，`call` 归 0，`pop` -1，`add esp`
   归 0）。本函数只有 `0x450651 push ebx` 造成 pend=1（`0x450657` 那条写 `+0x10`）。
2. **16 位子寄存器**：`mov word [esp+X], ax|cx|dx|di` 取最近一次 `mov <32位>, IMM` 的低 16 位；
   `bx`/`bl` 恒为 0（`0x4505BA xor ebx,ebx` 之后 ebx 无写入）。

输出 `remake/p4_block_tables.py`（纯数据），由 `page4.p4_block()` 使用。
"""
from __future__ import annotations

import re
from pathlib import Path

HERE = Path(__file__).resolve().parent
LISTING = HERE.parent / "docs" / "p4_listings" / "01_enter_4505B0.txt"
OUT = HERE / "p4_block_tables.py"

B = 0x10          # 块基址 = esp + 0x10
RANGES = {"A": (0x45069A, 0x450943), "A_flag": (0x450651, 0x450686),
          "B": (0x450943, 0x45096E), "C": (0x45096E, 0x450A25)}

LINE = re.compile(r"^0x([0-9a-f]+)\s+(\w+)\s*(.*)$")
STORE = re.compile(
    r"^(word|byte) ptr \[esp \+ (0x[0-9a-f]+)\], "
    r"(0x[0-9a-f]+|\d+|eax|ebx|ecx|edx|edi|esi|ax|bx|cx|dx|di|al|bl|cl|dl)$")
MOVREG = re.compile(r"^(eax|ebx|ecx|edx|edi|esi), (0x[0-9a-f]+)$")

# 表在**块内**的基址（读出侧 `mov reg, word ptr [esp+eax+TBL]` ⇒ 块偏移 TBL-0x10）
TABLES = {"0x3c": (0x3C - B, 8), "0x4c": (0x4C - B, 4), "0x54": (0x54 - B, 4),
          "0x5c": (0x5C - B, 4), "0x64": (0x64 - B, 32), "0xa4": (0xA4 - B, 32)}


def main():
    rows = []
    for ln in LISTING.read_text(encoding="utf-8").splitlines():
        m = LINE.match(ln)
        if m:
            rows.append((int(m.group(1), 16), m.group(2), m.group(3).strip()))

    regs = {"eax": 0, "ebx": 0, "ecx": 0, "edx": 0, "edi": 0, "esi": 0}
    words: dict[str, dict[int, int]] = {k: {} for k in RANGES}
    pend = 0

    for addr, mn, op in rows:
        if mn == "push":
            pend += 1
            continue
        if mn == "pop":
            pend = max(0, pend - 1)
            continue
        if mn == "call":
            pend = 0
            continue
        if mn == "add" and op.startswith("esp"):
            pend = 0
            continue
        if mn == "xor" and op == "ebx, ebx":
            regs["ebx"] = 0
            continue
        if mn != "mov":
            continue

        name = next((k for k, (lo, hi) in RANGES.items() if lo <= addr < hi), None)
        mm = MOVREG.match(op)
        if mm:
            regs[mm.group(1)] = int(mm.group(2), 16)
            continue
        sm = STORE.match(op)
        if not (sm and name):
            continue

        size, off, src = sm.group(1), int(sm.group(2), 16), sm.group(3)
        key = off - B - pend
        if src[0].isdigit():
            val = int(src, 0)
        elif src in ("bx", "bl", "ebx"):
            val = 0
        else:
            base = {"ax": "eax", "al": "eax", "cx": "ecx", "cl": "ecx", "dx": "edx",
                    "dl": "edx", "di": "edi", "eax": "eax", "ecx": "ecx", "edx": "edx",
                    "edi": "edi", "esi": "esi"}[src]
            val = regs[base] & (0xFF if size == "byte" else 0xFFFF)
        words[name][key] = val & (0xFF if size == "byte" else 0xFFFF)

    def table(base: int, n: int) -> list[int]:
        """取该表覆盖的 n 个字；缺失即报错（不允许静默补 0）。"""
        cands = [k for k, mem in words.items() if base in mem]
        if not cands:
            return [0] * n
        name = cands[0]
        mem = words[name]
        out = []
        for i in range(n):
            o = base + i * 2
            if o not in mem:
                raise SystemExit(f"表 0x{base + B:x} 缺项 at +0x{o:x}（分支 {name}）")
            out.append(mem[o])
        return out

    tables = {k: table(base, n) for k, (base, n) in TABLES.items()}

    lines = ['"""由 `remake/gen_p4_block.py` 从反汇编机械生成，勿手改。"""', "",
             "BLOCK_SIZE = 0xD4", "", "TABLES = {"]
    for k, v in tables.items():
        lines.append(f"    {k!r}: {v},")
    lines += ["}", "", "LITERALS = {"]
    for name in ("A", "A_flag", "B", "C"):
        items = ", ".join(f"{o:#04x}: {v:#06x}" for o, v in sorted(words[name].items()))
        lines.append(f"    {name!r}: {{{items}}},")
    lines += ["}", ""]
    OUT.write_text("\n".join(lines), encoding="utf-8")
    print(f"wrote {OUT}")
    for k, v in tables.items():
        print(f"  table {k}: {v}")


main()
