#!/usr/bin/env python3
"""VM 脚本全量回放：把 26 条脚本链各跑一遍，检查异常 / op 覆盖 / 终止性。

用法：
    python3 remake/replay_scripts.py

退出码：0 = 全部无异常；1 = 有异常或新的 op 缺失。
不断言“必须终止”（阶段流会 `op0` 循环回卷），只记录。

只读，不参与金标。
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

MAX_FRAMES = 20000


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
    for f in range(1800):
        inp.rec.e0 = (f == 25)
        pages.advance()
        if pages.page == 4:
            break

    bank = page4.ScriptBank(HERE.parent / "resource_dec.bin")
    chains = pages._p4_block_data()["vm_chains"]
    starts = [i for i in range(len(chains))
              if chains[i] != 0 and (i == 0 or chains[i - 1] == 0)]

    bad = []
    ops_used = set()
    for i in starts:
        vm = page4.ScriptVM(bank, chains, owner=pages)
        pages.vm = vm
        try:
            vm.load_chain(i)
            frames = 0
            while frames < MAX_FRAMES:
                if vm.step() == 1:
                    break
                frames += 1
            ops_used.update(k for k, v in vm.out.items() if v)
            if frames >= MAX_FRAMES:
                print(f"  chain[{i}] cur={vm.cur_id} 未终止（{MAX_FRAMES} 帧，游标循环）")
        except Exception as ex:  # noqa: BLE001
            bad.append((i, repr(ex)))

    print(f"chains={len(starts)} 异常={len(bad)} op 覆盖={sorted(hex(o) for o in ops_used)}")
    miss = dict(getattr(pages, "p4_beh_missing", {}))
    print(f"未实现行为={miss}")
    if bad:
        for b in bad:
            print("  ", b)
        return 1
    if miss:
        return 1
    print("OK：26 条脚本链回放无异常，op 覆盖 1..0xD")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
