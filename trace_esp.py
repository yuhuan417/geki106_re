#!/usr/bin/env python3
"""带 esp 基准标注的线性反汇编追踪器（逆向对照用）。

用法：python3 trace_esp.py <start_va> <end_va> [baseline_va]

- baseline_va：esp 视为 F+0 的指令地址（一般取函数序言最后一个 push 之后的第一条）。
- call 的 esp 修正：按被调方的 ret imm 弹回字节数回补（默认 0=plain ret，即 cdecl；
  0x401fa5/0x43bdc0/0x430820 等 ret 4 的已内置）。这修正了"call 只减不加"的常见误读。
- 已知 thunk 目标：0x4023c4→0x430400(记录打包,plain ret)、0x401753→0x45a690(双值返回)、
  0x462d71(截断 divmod)、0x401fa5→0x43bdc0(入队,ret 4)、0x401352→0x430820(ret 4)。
"""
import sys
import re_dis

RET_IMM = {
    0x4023c4: 0, 0x401753: 0, 0x462d71: 0, 0x401fa5: 4, 0x401352: 4,
    0x43bdc0: 4, 0x430820: 4,
}


def trace(start, end, baseline):
    R = re_dis.load()
    esp = None
    insns = list(R.md.disasm(R.text[start - R.tva:end - R.tva], start))
    for ins in insns:
        m, ops = ins.mnemonic, ins.op_str
        ann = "esp=F+%#x" % esp if esp is not None else "esp=?"
        net = 0
        if m == 'call':
            try:
                tgt = int(ops, 16)
            except Exception:
                tgt = None
            net = RET_IMM.get(tgt, 0)
        d = 0
        if m == 'push':
            d = -4
        elif m == 'pop':
            d = 4
        elif m in ('sub', 'add') and ops.split(',')[0].strip() == 'esp':
            v = int(ops.split(',')[1].strip(), 0)
            d = -v if m == 'sub' else v
        if ins.address == baseline:
            esp = 0
            d = 0
        elif esp is not None:
            esp += d + net
        print(f"{ins.address:#x}  {ann:12s} {m} {ops}")


if __name__ == '__main__':
    a = int(sys.argv[1], 16) if sys.argv[1].startswith('0x') else int(sys.argv[1], 0)
    b = int(sys.argv[2], 16) if sys.argv[2].startswith('0x') else int(sys.argv[2], 0)
    base = int(sys.argv[3], 16) if len(sys.argv) > 3 else a
    trace(a, b, base)
