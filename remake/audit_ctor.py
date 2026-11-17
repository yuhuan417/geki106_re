#!/usr/bin/env python3
"""ctor 字段审计：把各族 ctor 跳表逐 case 的「dword [esi+X]=imm」与「0x40238D 前的矩形 push」
与 page4 的 ENT*_INIT 表逐字段比对。

用法：python3 remake/audit_ctor.py
退出码 0 = 无差异（等价默认值不计）；1 = 发现差异。
"""
import os
import struct
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(HERE, "pygame"))
sys.path.insert(0, ROOT)     # re_dis.py 在仓库根

import capstone                                            # noqa: E402
import re_dis                                              # noqa: E402
import page4                                               # noqa: E402

# (族基址, ctor 跳表地址, 对应表)
FAMS = [
    (0x23000000, 0x40DE98, page4.ENT23_INIT),
    (0x24000000, 0x410CF4, page4.ENT24_INIT),
    (0x25000000, 0x4120C8, page4.ENT25_INIT),
    (0x26000000, None, page4.ENT26_INIT),
    (0x29000000, 0x41CBDC, page4.ENT29_INIT),
    (0x2A000000, 0x40A7F8, page4.ENT2A_INIT),
    (0x2C000000, 0x4044D8, page4.ENT2C_INIT),
    (0x2D000000, 0x40845C, page4.ENT2D_INIT),
]


# 这些字段由 ctor 的**自定义段**写入（不是在 case 体里直接 imm），
# 已在各自 handler 里实现并经运行时实测；审计时跳过，避免误报。
CUSTOM_WRITTEN = {
    (0x29000007, 0x18), (0x29000008, 0x18), (0x29000009, 0x18),
    (0x2900000A, 0x18), (0x2900000B, 0x18),      # s2907：x!=0 → 0x14 / x==0 → 0xB4
    (0x2A000005, 0x0C), (0x2A000005, 0x18),      # s2a05
    (0x2C000009, 0x18),                          # s2c09：0x20
    (0x2C00000D, 0x18), (0x2C00000D, 0x30),      # s2c0d：0xE / 0x10
    (0x2C000005, 0x18),                          # s2c05：1
    (0x2C000001, 0x20),                          # s20_seed
    (0x23000016, 0x18),                          # s2316：p[2]==0 → -1
}


def case_info(R, md, addr, limit=None):
    """返回 (imm 字典, rect 四元组或 None)。limit = 下一个 case 地址（不越界）。"""
    size = 0x140 if limit is None else max(0x10, min(0x140, limit - addr))
    b = R.data[addr - 0x400000: addr - 0x400000 + size]
    imm = {}
    pushes = []
    for i in md.disasm(b, addr):
        if (i.mnemonic == "mov" and i.op_str.startswith("dword ptr [esi +")
                and ", " in i.op_str):
            off = int(i.op_str.split("[")[1].split("]")[0].split("+")[1], 16)
            val = i.op_str.split(", ")[1]
            try:
                v = int(val, 16) if val.startswith("0x") else int(val)
            except ValueError:
                continue
            imm[off] = v
        if i.mnemonic == "push":
            pushes.append(i.op_str)
        if "0x40238d" in i.op_str:
            last = pushes[-4:]
            if len(last) == 4 and all(p.startswith("0x") for p in last):
                b_, r_, t_, l_ = (int(x, 16) for x in last)
                return imm, (l_, t_, r_, b_)
            return imm, None
        if i.mnemonic in ("ret", "jmp"):
            break
    return imm, None


def main() -> int:
    R = re_dis.load()
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    diffs = []
    checked = 0
    for base, tab, table in FAMS:
        if tab is None:
            continue
        for n in range(0x30):
            addr = struct.unpack_from("<I", R.data, tab - 0x400000 + n * 4)[0]
            typ = base | (n + 1)
            if addr == 0 or typ not in table:
                continue
            info = table[typ]
            nxt = None
            for k in range(n + 1, 0x30):
                cand = struct.unpack_from("<I", R.data, tab - 0x400000 + k * 4)[0]
                if cand:
                    nxt = cand
                    break
            imm, rect = case_info(R, md, addr, nxt)
            checked += 1
            for off in (0x0C, 0x18):
                if off not in imm:
                    continue
                ex = imm[off] - 0x100000000 if imm[off] >= 0x80000000 else imm[off]
                got = info.get("imm", {}).get(off)
                if got is None:
                    if (typ, off) in CUSTOM_WRITTEN:
                        continue
                    diffs.append((typ, hex(off), hex(ex), "表未列（可能由自定义段写）"))
                elif got != ex:
                    diffs.append((typ, hex(off), hex(ex), hex(got)))
            node = info.get("node")
            if node is not None and rect is not None:
                mine = tuple(node[1:5])
                if mine != rect:
                    diffs.append((typ, "rect",
                                  tuple(hex(x) for x in rect),
                                  tuple(hex(x) for x in mine)))
    print(f"[audit_ctor] 检查 {checked} 个 case，差异 {len(diffs)}")
    for d in diffs:
        print("  ", hex(d[0]), d[1], "exe=", d[2], "ours=", d[3])
    return 0 if not diffs else 1


if __name__ == "__main__":
    sys.exit(main())
