#!/usr/bin/env python3
"""分支感知的 esp 跟踪：按 CFG 走（跟随 jmp / 两侧都走），逐路径维护 esp 增量。

用法：python3 esp_flow.py 0x447F90 0x448192 [--tail N]
对每个 `[esp+X]` 操作数给出"相对函数序言结束后的栈帧偏移"；
若同一指令经不同路径得到不同偏移，标注 CONFLICT。
`call` 视为净 0（不跟进被调函数）。
"""
import sys, re
import pefile, capstone

pe = pefile.PE('../geki106/geki106.exe', fast_load=True)
ib = pe.OPTIONAL_HEADER.ImageBase
img = pe.get_memory_mapped_image()
md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)

_ret_n_cache = {}

def ret_n(target):
    """被调函数的 `ret N` 里的 N（callee 清栈字节数）；找不到就返回 0。"""
    if target in _ret_n_cache:
        return _ret_n_cache[target]
    t = target
    n = 0
    while 0x401000 <= t <= 0x4026FF and img[t - ib] == 0xE9:
        rel = int.from_bytes(img[t + 1 - ib:t + 5 - ib], "little", signed=True)
        t = t + 5 + rel
        n += 1
        if n > 4:
            break
    val = 0
    cnt = 0
    for i in md.disasm(img[t - ib:t - ib + 0x600], t):
        if i.mnemonic == "ret":
            if i.op_str:
                val = int(i.op_str, 0)
            break
        cnt += 1
        if cnt > 220:
            break
    _ret_n_cache[target] = val
    return val


def build(start, end):
    ins = {}
    for i in md.disasm(img[start - ib:end - ib], start):
        if i.address >= end:
            break
        ins[i.address] = i
    return ins

def esp_ops(ops):
    out = []
    for mo in re.finditer(r"\[esp (\+|-) (0x[0-9a-f]+)\]", ops):
        v = int(mo.group(2), 16)
        out.append(v if mo.group(1) == "+" else -v)
    for mo in re.finditer(r"\[esp\]", ops):
        out.append(0)
    for mo in re.finditer(r"\[esp \+ [a-z0-9]+\*\d \+ (0x[0-9a-f]+)\]", ops):
        out.append(int(mo.group(1), 16))
    return out

def flow(start, end):
    ins = build(start, end)
    seen = {}                      # addr -> set(delta)
    mem = {}                       # addr -> {raw: set(frame)}
    stack = [(start, 0)]
    while stack:
        a, d = stack.pop()
        while True:
            if a not in ins:
                break
            if a in seen:
                if d in seen[a] or len(seen[a]) >= 3 or abs(d) > 0x400:
                    break
                seen[a].add(d)
                # 继续走，记录冲突
            else:
                seen[a] = {d}
            i = ins[a]
            for raw in esp_ops(i.op_str):
                mem.setdefault(a, {}).setdefault(raw, set()).add(raw + d)
            m, ops = i.mnemonic, i.op_str
            nd = d
            if m == "push":
                nd -= 4
            elif m == "pop":
                nd += 4
            elif m in ("add", "sub") and ops.startswith("esp,"):
                v = ops.split(",", 1)[1].strip()
                n = int(v, 0) if v.lower().startswith("0x") else int(v)
                nd += n if m == "add" else -n
            elif m == "sub" and ops.startswith("esp,") and "0x6c" in ops:
                pass
            if m == "call":
                mt = re.search(r"0x([0-9a-f]+)", ops)
                if mt:
                    nd += ret_n(int(mt.group(1), 16))
            if m == "ret":
                break
            if m in ("jmp", "j") or m[0] == "j":
                mt = re.search(r"0x([0-9a-f]+)", ops)
                if mt:
                    stack.append((int(mt.group(1), 16), nd))
                if m == "jmp":
                    break
            a = a + i.size
            d = nd
    return mem

if __name__ == "__main__":
    a, b = int(sys.argv[1], 0), int(sys.argv[2], 0)
    mem = flow(a, b)
    for addr in sorted(mem):
        for raw, frames in sorted(mem[addr].items()):
            tag = "  CONFLICT " + str(sorted(hex(f) for f in frames)) if len(frames) > 1 else ""
            print(f"  {addr:08X} esp+0x{raw & 0xffff:x}  ⇒ 帧+0x{sorted(frames)[0]:x}{tag}")
