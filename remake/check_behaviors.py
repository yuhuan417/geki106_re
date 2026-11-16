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
            if (page4.P4_BEH.get(real) is None
                    and not hasattr(page4, f"_beh_{real:X}")):
                miss.append((hex(ty), name, hex(real)))
    for ty, spec in geki.P31_CTOR.items():
        real = page4.ENT23_BEH_THUNK.get(spec[0], spec[0])
        if (page4.P4_BEH.get(real) is None
                and not hasattr(page4, f"_beh_{real:X}")):
            miss.append((hex(ty), "P31_CTOR", hex(real)))
    return miss


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
    if not miss and not bad:
        print(f"OK：行为全登记，0x31 {len(geki.P31_CTOR)} 型各 30 帧无异常")
        return 0
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
