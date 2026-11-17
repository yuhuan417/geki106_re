#!/usr/bin/env python3
"""页 4 长跑冒烟：无头跑 N 帧、随机输入，检查异常 / 未实现行为 / 队列泄漏。

用法：
    python3 remake/longrun_p4.py [帧数]

退出码：0 = 无异常、无未实现行为、队列有界；1 = 否则。
只读，不参与金标。
"""
from __future__ import annotations

import os
import random
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

QUEUES = ("p4_q43c", "p4_ui49c", "ui4cc", "ui52c", "p4_q4fc", "actorq")
LIMIT = 4000          # 单队列上限（长跑防泄漏）


def main() -> int:
    frames = int(sys.argv[1]) if len(sys.argv) > 1 else 3600
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
    for f in range(1800):
        inp.rec.e0 = (f == 25)
        pages.advance()
        if pages.page == 4:
            break

    rnd = random.Random(1)
    err = None
    done = 0
    try:
        for f in range(frames):
            inp.rec.b1 = (f % 7) < 4
            inp.rec.r1 = (f % 11) == 0
            inp.rec.e0 = (f % 13) == 0
            inp.rec.dx = rnd.choice((-1, 0, 1))
            inp.rec.dy = rnd.choice((-1, 0, 1))
            pages.advance()
            done += 1
    except Exception as ex:  # noqa: BLE001
        err = repr(ex)

    miss = dict(getattr(pages, "p4_beh_missing", {}))
    sizes = {k: len(getattr(pages, k)) for k in QUEUES if hasattr(pages, k)}
    over = {k: v for k, v in sizes.items() if v > LIMIT}

    print(f"frames={done} err={err}")
    print(f"missing={miss}")
    print(f"queues={sizes}")
    if err or miss or over:
        if over:
            print(f"队列超限：{over}")
        return 1
    print("OK：长跑无异常、无未实现行为、队列有界")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
