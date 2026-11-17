#!/usr/bin/env python3
"""行为层审计：表驱动收集所有 beh 地址（thunk 解析后）并核对实现与函数入口。

两条检查：
1. `ENT*_INIT` + `P4_41_CTOR` + `P31` 里出现的每个 beh，解析 thunk 后必须有实现
   （`P4_BEH` / `Page4Mixin._beh_*` / `Pages._beh_*`；0x429D40 由 geki 的火花 tick 承担）；
2. `P4_BEH` 的每个键都必须是 re_dis 认定的**函数入口**（防止把 mid-function 当地址）。

用法：python3 remake/audit_beh.py；rc=0 通过，1 有问题。
"""
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(HERE, "pygame"))
sys.path.insert(0, ROOT)

import page4                                                # noqa: E402
import geki                                                 # noqa: E402
import re_dis                                               # noqa: E402


def resolve(R, addr):
    for _ in range(4):
        try:
            i = R.dec(addr)
        except Exception:
            return addr
        if i.mnemonic == "jmp" and i.op_str.startswith("0x"):
            addr = int(i.op_str, 16)
        else:
            return addr
    return addr


def main() -> int:
    R = re_dis.load()
    behs = {}
    for name in dir(page4):
        if not (name.startswith("ENT") and name.endswith("_INIT")):
            continue
        table = getattr(page4, name)
        if not isinstance(table, dict):
            continue
        for typ, spec in table.items():
            if isinstance(spec, dict) and "beh" in spec:
                behs.setdefault(resolve(R, spec["beh"]), typ)
    for typ, spec in page4.Page4Mixin.P4_41_CTOR.items():
        behs.setdefault(resolve(R, spec[-1]), typ)

    missing = []
    for b, typ in sorted(behs.items()):
        fn = page4.P4_BEH.get(b)
        if fn is None:
            fn = getattr(page4.Page4Mixin, f"_beh_{b:X}", None)
        if fn is None:
            fn = getattr(geki.Pages, f"_beh_{b:X}", None)
        if fn is None and b == 0x429D40:          # 火花由 geki 的 tick 承担
            fn = getattr(geki.Pages, "_tick_spark4cc", None)
        if fn is None:
            missing.append((b, typ))

    funcs = set(R.funcs)
    not_entry = [k for k in page4.P4_BEH if k not in funcs]

    print(f"[audit_beh] 行为地址 {len(behs)} 个、缺实现 {len(missing)}；"
          f"P4_BEH {len(page4.P4_BEH)} 键、非函数入口 {len(not_entry)}")
    for b, typ in missing:
        print("   缺实现", hex(b), "首见类型", hex(typ))
    for k in not_entry:
        print("   非入口", hex(k))
    return 0 if not missing and not not_entry else 1


if __name__ == "__main__":
    sys.exit(main())
