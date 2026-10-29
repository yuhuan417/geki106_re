#!/usr/bin/env python3
"""线性反汇编导出：从入口按地址顺序打印，并解析 0x40xxxx thunk 的真实目标。

用法: python3 dump_linear.py 0x459360 0x4593C2 [--out FILE]

call/jmp 后面带 `; → 0xXXXX` 表示该调用经过 thunk 落到实函数。
"""
import argparse
import re_dis

THUNK_LO, THUNK_HI = 0x400000, 0x402400


def ins_at(R, pc):
    return R.insns.get(pc) or R.dec(pc)


def resolve(R, addr, depth=0):
    """跟随 0x40xxxx thunk 一跳，返回真实目标。"""
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
    ap.add_argument("end", type=lambda s: int(s, 16))
    ap.add_argument("--out", default="")
    a = ap.parse_args()
    R = re_dis.load()
    out = [f"; {a.start:#x}..{a.end:#x}  linear listing", ""]
    pc = a.start
    while pc < a.end:
        ins = ins_at(R, pc)
        if ins is None:
            out.append(f"{pc:#010x}  ?? {R.raw(pc, 8).hex()}")
            pc += 1
            continue
        note = ""
        if ins.mnemonic in ("jmp", "call") and ins.op_str.startswith("0x"):
            tgt = int(ins.op_str, 16)
            real = resolve(R, tgt)
            if real != tgt:
                note = f"   ; → {real:#x}"
        out.append(f"{ins.address:#010x}  {ins.mnemonic:<7} {ins.op_str}{note}")
        pc += ins.size

    text = "\n".join(out) + "\n"
    if a.out:
        with open(a.out, "w", encoding="utf-8") as f:
            f.write(text)
        print(f"wrote {a.out} ({len(out) - 2} insns)")
    else:
        print(text)


main()
