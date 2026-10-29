#!/usr/bin/env python3
"""esp 模拟：把一个函数内所有 [esp+X] 操作数换算成相对栈帧基准的偏移。

用法：python3 esp_track.py 0x447F90 0x448192
`call` 视为净 0（它自己 push/pop 返回地址），`rep movsd` 不改 esp。
输出里 `F+0x14` 表示"相对本函数 sub esp 之后的基准偏移 0x14"。
"""
import sys, re
import pefile, capstone

pe = pefile.PE('../geki106/geki106.exe', fast_load=True)
ib = pe.OPTIONAL_HEADER.ImageBase
img = pe.get_memory_mapped_image()
md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)

def track(start, end, verbose=False):
    delta = 0
    suspect = 0          # 经过条件跳转后 delta 可能只对其中一条路径成立
    out = []
    for i in md.disasm(img[start - ib:end - ib], start):
        m, ops = i.mnemonic, i.op_str
        offs = []
        for mo in re.finditer(r"\[esp \+ (0x[0-9a-f]+)\]", ops):
            offs.append(int(mo.group(1), 16))
        for mo in re.finditer(r"\[esp - (0x[0-9a-f]+)\]", ops):
            offs.append(-int(mo.group(1), 16))
        if offs:
            for x in offs:
                out.append((i.address, m, ops, x, x + delta, suspect))
        if m == "push":
            delta -= 4
        elif m == "pop":
            delta += 4
        elif m[0] == "j" and m != "jmp":
            # 线性走会把分支两侧的 push 都算进去，之后的偏移不可全信
            suspect += 1
        elif m in ("add", "sub") and ops.startswith("esp,"):
            v = ops.split(",")[1].strip()
            n = int(v, 0) if v.startswith("0x") else int(v)
            delta += n if m == "add" else -n
    return out

if __name__ == "__main__":
    a, b = int(sys.argv[1], 0), int(sys.argv[2], 0)
    for addr, m, ops, raw, fr, sus in track(a, b):
        mark = f"  ← 经 {sus} 次条件跳转后，仅对单条路径成立" if sus else ""
        print(f"  {addr:08X} {m:7} {ops:28} esp+0x{raw:x}  ⇒ F+0x{fr:x}{mark}")
