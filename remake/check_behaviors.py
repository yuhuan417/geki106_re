#!/usr/bin/env python3
"""行为覆盖自检：所有 ctor 表登记的 beh 是否都有实现；0x31 全型能否跑帧。

用法：
    python3 remake/check_behaviors.py

退出码：0 = 全通过；1 = 有缺失/异常（打印清单）。
不修改任何文件，不参与金标。
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE / "pygame"))
os.environ.setdefault("SDL_VIDEODRIVER", "dummy")
os.environ.setdefault("SDL_AUDIODRIVER", "dummy")

import pygame  # noqa: E402

pygame.display.init()
pygame.font.init()
pygame.display.set_mode((640, 480))

import audio  # noqa: E402
import geki  # noqa: E402
import page4  # noqa: E402


def _has_beh(a: int) -> bool:
    """行为是否可实现分派：P4_BEH、模块级 _beh_XXXX、或 Page4Mixin 方法。"""
    return (page4.P4_BEH.get(a) is not None
            or hasattr(page4, f"_beh_{a:X}")
            or hasattr(page4.Page4Mixin, f"_beh_{a:X}")
            or hasattr(geki.Pages, f"_beh_{a:X}"))


# op5 0x6x 控制器子实体：ctor 已落地，行为尚未逐条实现（2026-11-17 核出）。
KNOWN_MISSING_BEH: set[int] = set()


def geki_beh_assignments() -> tuple[set[int], set[int]]:
    """geki.py 里 `e.beh = 0x...` 的地址集合 → (全部, 未实现且不在已知清单)。"""
    import re
    root = Path(__file__).resolve().parent / "pygame"
    src = (root / "geki.py").read_text(encoding="utf-8")
    all_addr = {int(m, 16) for m in re.findall(r"e\.beh\s*=\s*(0x[0-9A-Fa-f]+)", src)}
    miss = set()
    for a in all_addr:
        if not _has_beh(a) and a not in KNOWN_MISSING_BEH:
            miss.add(a)
    return all_addr, miss


def missing_behaviours() -> list[tuple[str, str, str]]:
    tables = ("ENT24_INIT", "ENT25_INIT", "ENT26_INIT", "ENT27_INIT",
              "ENT28_INIT", "ENT29_INIT", "ENT2A_INIT", "ENT2C_INIT",
              "ENT2D_INIT")
    miss = []
    for name in tables:
        for ty, info in getattr(page4, name).items():
            th = info.get("beh")
            if th is None:
                continue
            real = page4.ENT23_BEH_THUNK.get(th, th)
            if not _has_beh(real):
                miss.append((hex(ty), name, hex(real)))
    for ty, spec in geki.P31_CTOR.items():
        real = page4.ENT23_BEH_THUNK.get(spec[0], spec[0])
        if not _has_beh(real):
            miss.append((hex(ty), "P31_CTOR", hex(real)))
    return miss


def undefined_self_calls() -> list[tuple[str, int]]:
    """扫描 page4.py 里 `self.X(...)`，X 在 page4+geki 的任何类方法/实例属性里都找不到。"""
    import ast
    root = Path(__file__).resolve().parent / "pygame"
    srcs = [(root / "page4.py").read_text(encoding="utf-8"),
            (root / "geki.py").read_text(encoding="utf-8")]
    defined: set[str] = set()
    for src in srcs:
        for node in ast.walk(ast.parse(src)):
            if isinstance(node, ast.FunctionDef):
                defined.add(node.name)
            if (isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name)
                    and node.value.id == "self" and isinstance(node.ctx, ast.Store)):
                defined.add(node.attr)
    tree = ast.parse(srcs[0])
    out = []
    for node in ast.walk(tree):
        if (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                and isinstance(node.func.value, ast.Name)
                and node.func.value.id == "self"
                and node.func.attr not in defined):
            if not hasattr(page4.Page4Mixin, node.func.attr):
                out.append((node.func.attr, node.lineno))
    return out


def main() -> int:
    data = geki.load_data()
    palette = geki.load_palette()
    canvas = geki.Canvas()
    text = geki.TextRenderer(palette)
    inp = geki.Input()
    inp.kbd_move = False
    pages = geki.Pages(data, palette, text, canvas, inp,
                       geki.Timer(), geki.Flags(), audio.Audio(enabled=False))
    pages.start(12)
    pages.p4_460c00 = lambda: None
    for f in range(1200):
        inp.rec.e0 = (f == 25)
        pages.advance()
        if pages.page == 4:
            break

    miss = missing_behaviours()
    bad = []
    tested = 0
    for name in ("ENT24_INIT", "ENT25_INIT", "ENT26_INIT", "ENT27_INIT",
                 "ENT28_INIT", "ENT29_INIT", "ENT2A_INIT", "ENT2C_INIT",
                 "ENT2D_INIT"):
        for ty in getattr(page4, name):
            tested += 1
            try:
                e = pages._p4_ent43c(ty, 320, 240, 0)
                for _ in range(20):
                    pages.p4_call_behaviour(e)
            except Exception as ex:  # noqa: BLE001
                bad.append((name, hex(ty), repr(ex)))
    for ty in sorted(geki.P31_CTOR):
        a3 = (0, 0)
        if ty == 0x31000012:
            a3 = 0x384
        elif ty == 0x31000015:
            a3 = (0xC, 0, 1)
        elif ty == 0x3100001D:
            a3 = 0x10010
        q = pages._p4_q("ui49c")
        try:
            pages.spawn(q, ty, 320, 240, a3)
            e = q[-1]
            for _ in range(30):
                pages.p4_call_behaviour(e)
        except Exception as ex:  # noqa: BLE001
            bad.append((hex(ty), repr(ex)))

    if miss:
        print("缺失行为：")
        for m in miss:
            print("  ", m)
    if bad:
        print("0x31 跑帧异常：")
        for b in bad:
            print("  ", b)
    beh_all, beh_miss = geki_beh_assignments()
    pending = sorted(a for a in KNOWN_MISSING_BEH if not _has_beh(a))
    if beh_miss:
        print("geki.py 新引用但未实现的行为：")
        for a in sorted(beh_miss):
            print("   ", hex(a))
    undef = undefined_self_calls()
    if undef:
        print("未定义的 self 方法调用：")
        for u in undef:
            print("  ", u)
    if not miss and not bad and not undef and not beh_miss:
        print(f"OK：行为全登记（geki 内 {len(beh_all)} 个 beh 引用，"
              f"{len(pending)} 个待实现）、无未定义 self 调用，"
              f"ENT 表 {tested} 型各 20 帧、0x31 {len(geki.P31_CTOR)} 型各 30 帧无异常")
        return 0
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
