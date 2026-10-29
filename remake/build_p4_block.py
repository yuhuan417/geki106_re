#!/usr/bin/env python3
"""`0x4505B0`（页4 阶段进场）里那个 0xD2 字节参数块的**机械提取器**。

为什么用脚本而不是手抄：函数体 `0x45069A..0x450A25` 是 100 多条
`mov word ptr [esp+X], imm` / `mov word ptr [esp+X], reg`，中间只有两处查表
（`0x450833 mov cx,word[esp+eax+0xA4]`、`0x450903 mov ax,word[esp+eax+0x64]`）。
逐条手抄必错，所以这里对三条分支各跑一遍**寄存器/栈的抽象求值**，把结果导出成 JSON。

分支（`si=[0x4AB5C8]` 关、`bp=word[0x4AB5CA]` 周目）：
    A  `0x45069A` si<8 且 bp<=3
    B  `0x450943` si<8 且 bp>3（走 `0x45096E`? 不，见入口比较：0x450686 jge 0x45096e / 0x450694 jg 0x450943）
    C  `0x45096E` si>=8
    A' `0x450651` 分支：si<8、bp<=3 且 `0x45B030(0x4AB5B0,1)` 为真（只写 5 个字段，其余留 0）
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import capstone
import pefile

HERE = Path(__file__).resolve().parent
EXE = HERE.parent.parent / "geki106" / "geki106.exe"
BASE = 0x400000

BRANCHES = {"A": 0x45069A, "A_flag": 0x450651, "B": 0x450943, "C": 0x45096E}
STOP = 0x450A25  # `lea eax,[esp+0x10]`：参数块构造结束

# 分支 C 里按 bp 查的 4 张表（基址, 元素宽度, 元素数）
C_TABLES = {"0x3c": (0x3C, 2, 8), "0x4c": (0x4C, 2, 8),
            "0x54": (0x54, 2, 8), "0x5c": (0x5C, 2, 8)}


def disasm():
    pe = pefile.PE(str(EXE), fast_load=True)
    ib = pe.OPTIONAL_HEADER.ImageBase
    d = pe.get_memory_mapped_image()
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    return ib, d, md


ALIAS = {"ax": "eax", "bx": "ebx", "cx": "ecx", "dx": "edx",
         "al": "eax", "bl": "ebx", "cl": "ecx", "dl": "edx",
         "di": "edi", "si_": "esi"}


def reg_name(op: str) -> str | None:
    for r in ("eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "ax", "bx", "cx", "dx", "al", "bl", "cl", "dl"):
        if op == r:
            return r
    return None


def evaluate(insns, start, si, bp, flag1):
    """从 start 顺序求值到 STOP；返回 {字节偏移: (值, 尺寸)} 与查表记录。"""
    mem: dict[int, tuple[int, int]] = {}
    reg = {"eax": 0, "ebx": 0, "ecx": 0, "edx": 0, "esi": si, "edi": 0, "ebp": bp, "si": si, "bp": bp}
    # 16 位子寄存器别名（写 ax 会改 eax 低 16 位，这里只关心低 16 位）
    lookups: list[dict] = []
    started = False
    for ins in insns:
        a = ins.address
        if a == start:
            started = True
        if not started:
            continue
        if a >= STOP or ins.mnemonic == "jmp":
            break
        mn, op = ins.mnemonic, ins.op_str
        ops = [p.strip() for p in op.split(",")] if op else []
        if mn == "mov" and len(ops) == 2:
            dst, src = ops
            # mov reg, imm / reg
            if reg_name(dst):
                r = reg_name(dst)
                src_a = ALIAS.get(src, src)
                if src_a in reg:
                    reg[r] = reg[src_a]
                    if dst in ALIAS:      # 写 16 位子寄存器：只保留低 16 位语义
                        reg[ALIAS[dst]] = reg[r] & 0xFFFF
                elif src.startswith("0x") or src.isdigit():
                    reg[r] = int(src, 0)
                elif src == "bp":
                    reg[r] = bp
                elif src == "si":
                    reg[r] = si
            elif dst.startswith("word ptr [esp + eax + 0x"):
                tbl = int(dst.rsplit("0x", 1)[1].rstrip("]"), 16)
                lookups.append({"dst": None, "tbl": tbl, "idx": (si + bp * 8), "reg": dst.split(",")[0]})
                a_ = ALIAS.get(dst.split(",")[0], dst.split(",")[0])
                reg[a_] = 0
            elif dst.startswith("word ptr [esp + 0x"):
                off = int(dst.split("0x")[1].rstrip("]"), 16)
                if ALIAS.get(src, src) in reg:
                    val = reg[ALIAS.get(src, src)]
                    mem[off] = (val & 0xFFFF, 2)
                elif src.startswith("0x") or src.isdigit():
                    mem[off] = (int(src, 0) & 0xFFFF, 2)
                elif src == "bx":
                    mem[off] = (reg["ebx"] & 0xFFFF, 2)
            elif dst.startswith("byte ptr [esp + 0x"):
                off = int(dst.split("0x")[1].rstrip("]"), 16)
                if ALIAS.get(src, src) in reg:
                    mem[off] = (reg[ALIAS.get(src, src)] & 0xFF, 1)
                elif src.startswith("0x") or src.isdigit():
                    mem[off] = (int(src, 0) & 0xFF, 1)
        elif mn in ("movsx",) and len(ops) == 2 and reg_name(ops[0]):
            r = reg_name(ops[0])
            if ops[1] == "bp":
                reg[r] = bp
            elif ops[1] == "si":
                reg[r] = si
        elif mn == "lea" and len(ops) == 2:
            r = reg_name(ops[0])
            if r:
                e = ops[1]
                if e.startswith("[esi*4 + 0x"):
                    reg[r] = si * 4 + int(e.split("+")[1].strip().rstrip("]"), 16)
                elif e == "[eax + edx*8]":
                    reg[r] = reg["eax"] + reg["edx"] * 8
                elif e.startswith("[ecx + ecx*4]"):
                    reg[r] = reg["ecx"] * 5
                elif e.startswith("[edi + edi*2"):
                    reg[r] = reg["edi"] * 3
                elif e.startswith("[eax + eax*2"):
                    reg[r] = reg["eax"] * 3
                elif e.startswith("[eax + eax*4]"):
                    reg[r] = reg["eax"] * 5
        elif mn == "shl" and len(ops) == 2 and reg_name(ops[0]):
            reg[reg_name(ops[0])] <<= int(ops[1], 0)
        elif mn == "add" and len(ops) == 2 and reg_name(ops[0]) and reg_name(ops[1]):
            reg[reg_name(ops[0])] += reg[reg_name(ops[1])]
        elif mn in ("cmp", "test", "jmp", "jne", "je", "jge", "jg", "jl", "sbb", "neg", "and", "sar", "shr", "inc", "dec", "imul", "rep", "stosd", "push", "pop", "call"):
            continue
    # 查表：0x450833 / 0x450903 用 eax = (si + bp*8)*2
    return mem


def main() -> int:
    ib, d, md = disasm()
    insns = list(md.disasm(d[0x45069a - ib:0x450a2a - ib], 0x45069a))

    # 1) 先把三条分支各自的 16 位栈表（0x3C..0xE2）与两处查表抽出来
    out = {"note": "0x4505B0 参数块机械提取（remake/build_p4_block.py 生成）", "branches": {}}
    for name, start in BRANCHES.items():
        cases = {}
        for si in range(0, 12):
            for bp in range(0, 5):
                mem = evaluate(insns, start, si, bp, True)
                key = f"{si},{bp}"
                cases[key] = {f"0x{off:x}": {"v": v, "size": sz} for off, (v, sz) in sorted(mem.items())}
        out["branches"][name] = {"start": hex(start), "cases": cases}
    # 2) 收尾：把三条分支整理成「常量字段 + 查表 + 表内容」
    ref = out["branches"]["A"]["cases"]["1,0"]
    tables = {}
    for base, n in ((0x3C, 8), (0x44, 8), (0x4C, 8), (0x54, 8), (0x5C, 8),
                    (0x64, 32), (0xA4, 32)):
        tables[f"0x{base:02x}"] = []
        for i in range(n):
            off = base + 2 * i if base not in (0x44,) else base + 2 * i
            tables[f"0x{base:02x}"].append(ref.get(f"0x{off:x}", {"v": 0})["v"])
    final = {"note": "0x4505B0 参数块（build_p4_block.py 生成；块基址 [esp+0x10]，尺寸 0xD4）",
             "size": 0xD4, "tables": tables, "branches": {}}
    skip = {0x20, 0x22, 0x24, 0x26, 0x29, 0x2A}
    for name in ("A", "A_flag", "B", "C"):
        cases = out["branches"][name]["cases"]
        key = "1,0" if name in ("A", "A_flag", "B") else "9,0"
        imm = {k: v["v"] for k, v in cases[key].items() if int(k, 16) not in skip}
        final["branches"][name] = {"start": out["branches"][name]["start"], "imm": imm}
    json.dump(final, open(HERE.parent / "remake" / "p4_block.json", "w"), indent=1)
    print("wrote remake/p4_block.json")
    print("tables 0xa4 =", tables["0xa4"])
    print("tables 0x64 =", tables["0x64"])
    print("A imm =", final["branches"]["A"]["imm"])
    return 0


if __name__ == "__main__":
    sys.exit(main())
