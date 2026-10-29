#!/usr/bin/env python3
"""按控制流遍历导出**一个函数**的完整反汇编（递归下降，不会误把跳转目标漏掉）。

用法: python3 dump_func.py 0x4505B0 [--out FILE] [--max 0x6000]

输出按地址排序，并在跳转目标处打标签；行尾 `; → 0xXXXX` 表示 thunk 解析后的真实目标。
不进入 call（只标注目标），所以一个函数看得到全貌、又不会被 callee 撑爆。
"""
import argparse
import re_dis

THUNK_LO, THUNK_HI = 0x400000, 0x402400


def ins_at(R, pc):
    return R.insns.get(pc) or R.dec(pc)


def resolve(R, addr, depth=0):
    if depth > 4 or not (THUNK_LO <= addr < THUNK_HI):
        return addr
    ins = ins_at(R, addr)
    if ins is None:
        return addr
    if ins.mnemonic in ("jmp", "call") and ins.op_str.startswith("0x"):
        tgt = int(ins.op_str, 16)
        if tgt != addr:
            return resolve(R, tgt, depth + 1)
    return addr


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("start", type=lambda s: int(s, 16))
    ap.add_argument("--max", type=lambda s: int(s, 16), default=0x6000)
    ap.add_argument("--out", default="")
    a = ap.parse_args()
    R = re_dis.load()

    lo, hi = a.start, a.start + a.max
    todo = [a.start]
    seen = set()
    calls = {}
    while todo:
        pc = todo.pop()
        while lo <= pc < hi and pc not in seen:
            ins = ins_at(R, pc)
            if ins is None:
                seen.add(pc)
                break
            seen.add(pc)
            mn = ins.mnemonic
            nxt = pc + ins.size
            if mn == "ret":
                break
            if mn == "jmp":
                op = ins.op_str
                if op.startswith("0x"):
                    tgt = int(op, 16)
                    if lo <= tgt < hi:
                        todo.append(tgt)
                break
            if mn.startswith("j"):          # 条件跳转
                op = ins.op_str
                if op.startswith("0x"):
                    tgt = int(op, 16)
                    if lo <= tgt < hi:
                        todo.append(tgt)
                pc = nxt
                continue
            if mn == "call" and ins.op_str.startswith("0x"):
                calls[pc] = resolve(R, int(ins.op_str, 16))
            pc = nxt

    targets = set()
    for pc in seen:
        ins = ins_at(R, pc)
        if ins is None:
            continue
        if ins.mnemonic == "jmp" or ins.mnemonic.startswith("j"):
            if ins.op_str.startswith("0x"):
                t = int(ins.op_str, 16)
                if lo <= t < hi:
                    targets.add(t)

    out = [f"; func {a.start:#x}  ({len(seen)} insns)", ""]
    for pc in sorted(seen):
        if pc in targets:
            out.append(f"loc_{pc:x}:")
        ins = ins_at(R, pc)
        if ins is None:
            out.append(f"{pc:#010x}  ?? {R.raw(pc, 8).hex()}")
            continue
        note = ""
        if ins.mnemonic in ("jmp", "call") and ins.op_str.startswith("0x"):
            t = int(ins.op_str, 16)
            real = resolve(R, t)
            if real != t:
                note = f"   ; → {real:#x}"
            elif ins.mnemonic == "call":
                note = f"   ; call {real:#x}"
        out.append(f"{pc:#010x}  {ins.mnemonic:<7} {ins.op_str}{note}")
    text = "\n".join(out) + "\n"
    if a.out:
        with open(a.out, "w", encoding="utf-8") as f:
            f.write(text)
        print(f"wrote {a.out} ({len(seen)} insns, {len(targets)} labels)")
    else:
        print(text)


main()
