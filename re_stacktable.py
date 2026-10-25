#!/usr/bin/env python3
"""栈帧表还原器：把函数里所有 `mov [esp+X], imm` 按"相对 prologue 之后 esp"的偏移归一化，
自动还原栈上的表（帧/类型/时间点…），避免手工折算 push 偏移出错。

用法:
    python3 re_stacktable.py 0x43DE30 0x43E0F7
    python3 re_stacktable.py 0x43DE30 0x43E0F7 --dump
"""
from __future__ import annotations

import struct
import sys

import capstone
import re_dis

CS = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
CS.detail = True


def walk(va_lo: int, va_hi: int):
    """线性遍历（函数体是连续代码，遇到 ret/跳表边界由区间控制）。产出 (va, insn, sp_delta)。"""
    R = re_dis.load()
    sp = 0
    insns = []
    pc = va_lo
    while pc < va_hi:
        code = R.raw(pc, 16)
        got = list(CS.disasm(code, pc, 1))
        if not got:
            pc += 1
            continue
        ins = got[0]
        m, ops = ins.mnemonic, ins.operands
        # 栈指针跟踪
        if m == "push":
            sp -= 4
        elif m == "pop":
            sp += 4
        elif m == "sub" and ops and ops[0].type == capstone.x86.X86_OP_REG and \
                ins.reg_name(ops[0].reg) == "esp" and ops[1].type == capstone.x86.X86_OP_IMM:
            sp -= ops[1].imm
        elif m == "add" and ops and ops[0].type == capstone.x86.X86_OP_REG and \
                ins.reg_name(ops[0].reg) == "esp" and ops[1].type == capstone.x86.X86_OP_IMM:
            sp += ops[1].imm
        elif m == "ret":
            sp += 4
            insns.append((pc, ins, sp))
            break
        insns.append((pc, ins, sp))
        pc += ins.size
    return insns


def stores(va_lo: int, va_hi: int):
    """返回 [(frame_off, size, value_or_reg, va)]，frame_off 以 prologue 之后 esp 为 0。"""
    out = []
    for va, ins, sp in walk(va_lo, va_hi):
        if ins.mnemonic not in ("mov", "movzx", "movsx"):
            continue
        ops = ins.operands
        if len(ops) != 2 or ops[0].type != capstone.x86.X86_OP_MEM:
            continue
        mem = ops[0].mem
        if ins.reg_name(mem.base) != "esp" or mem.index != 0:
            continue
        off = sp + mem.disp
        src = ops[1]
        if src.type == capstone.x86.X86_OP_IMM:
            val = src.imm
        elif src.type == capstone.x86.X86_OP_REG:
            val = f"%{ins.reg_name(src.reg)}"
        else:
            continue
        size = {1: "b", 2: "w", 4: "d"}.get(ins.operands[0].size, "?")
        out.append((off, size, val, va))
    return out


def main(argv):
    lo = int(argv[1], 16)
    hi = int(argv[2], 16)
    st = stores(lo, hi)
    print(f'# {lo:#x}..{hi:#x}: {len(st)} 条栈写')
    by_off: dict[int, list] = {}
    for off, size, val, va in st:
        by_off.setdefault(off, []).append((size, val, va))
    for off in sorted(by_off):
        for size, val, va in by_off[off]:
            v = f'{val:#x}' if isinstance(val, int) else val
            print(f'  [frame+0x{off:02x}] {size} = {v:>12}   (at {va:#x})')


if __name__ == "__main__":
    main(sys.argv)
