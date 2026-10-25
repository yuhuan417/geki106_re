#!/usr/bin/env python3
"""页1-3 运行器（pygame）：自己的 60Hz 帧门 + 8bpp 画布，不依赖任何引擎循环。

用法:
    python3 remake/pygame/run.py                     # 从页1 开始跑（ESC 退出，1/2/3 调试切页）
    python3 remake/pygame/run.py --page 2            # 直接进页2
    python3 remake/pygame/run.py --frames 300 --headless --fixed   # 无窗口跑 300 帧（脚本/CI）
    python3 remake/pygame/run.py --frames 300 --shot 250 --out /tmp   # 第 250 帧存 PNG
"""
from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import numpy as np  # noqa: E402
import pygame  # noqa: E402

import geki  # noqa: E402

# 原作分辨率固定 640x480，不允许缩放/resize
WINDOW_SIZE = (geki.W, geki.H)

# 0x498A60：DIK 扫描码 → 键码。pygame 的 K_* 直接映射到 DIK 语义
KEYCODES = {
    pygame.K_ESCAPE: geki.KEY_ESC,
    pygame.K_p: geki.KEY_PAUSE,
    pygame.K_PAUSE: geki.KEY_PAUSE,
    pygame.K_SPACE: geki.KEY_SPACE,
    pygame.K_PRINT: geki.KEY_PRINTSCR,
    pygame.K_TAB: geki.KEY_TAB,
}
for i in range(1, 13):
    KEYCODES[getattr(pygame, f"K_F{i}")] = 0x0F + i   # F1→0x10 … F12→0x1B


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="撃破伝 页1-3 复刻（pygame）")
    ap.add_argument("--page", type=int, default=1, help="起始页（1/2/3）")
    ap.add_argument("--frames", type=int, default=0, help="跑 N 帧后退出（0=无限）")
    ap.add_argument("--shot", type=int, default=-1, help="第 N 帧存 PNG")
    ap.add_argument("--shots", default="", help="多个帧号，逗号分隔（做对比图用）")
    ap.add_argument("--out", default=str(HERE / "shots"), help="PNG 输出目录")
    ap.add_argument("--headless", action="store_true", help="无窗口（SDL dummy）")
    ap.add_argument("--fixed", action="store_true", help="不按真实时间，尽快跑帧")
    ap.add_argument("--debug-hud", action="store_true", help="叠加调试信息（非原作内容）")
    args = ap.parse_args(argv)

    if args.headless:
        os.environ.setdefault("SDL_VIDEODRIVER", "dummy")
    # 原作是固定 640x480 8bpp 全屏；这里固定 640x480 窗口，1:1 像素，不缩放、不可 resize
    os.environ.setdefault("SDL_VIDEO_HIGHDPI_DISABLED", "1")
    pygame.init()
    pygame.display.set_caption("撃破伝 v1.06 — 640x480 (pages 1-3)")
    screen = pygame.display.set_mode(WINDOW_SIZE, 0, 32)
    if tuple(screen.get_size()) != WINDOW_SIZE:
        print(f"[video] 警告: 实际窗口 {screen.get_size()} != {WINDOW_SIZE}", file=sys.stderr)
    else:
        print(f"[video] 固定 {WINDOW_SIZE[0]}x{WINDOW_SIZE[1]}（1:1，无缩放）")
    # 原作每帧 SetCursorPos(320,240) + 相对位移采样，系统光标不可见
    pygame.mouse.set_visible(False)
    clock_font = pygame.font.Font(None, 16) if args.debug_hud else None

    data = geki.load_data()
    palette = geki.load_palette()
    canvas = geki.Canvas()
    text = geki.TextRenderer(palette)
    inp = geki.Input()
    timer = geki.Timer()
    flags = geki.Flags()
    pages = geki.Pages(data, palette, text, canvas, inp, timer, flags)
    pages.start(args.page)

    out_dir = Path(args.out)
    shot_frames: set[int] = set()
    if args.shot >= 0:
        shot_frames.add(args.shot)
    for tok in args.shots.split(","):
        tok = tok.strip()
        if tok:
            shot_frames.add(int(tok))
    if shot_frames:
        out_dir.mkdir(parents=True, exist_ok=True)

    frame = 0
    running = True
    while running and pages.page != 0 and not pages.quit:
        # ---- 泵消息（0x458B80 的 PeekMessage/Translate/Dispatch 等价物）
        mouse_delta = (0, 0)
        keycode = 0
        for ev in pygame.event.get():
            if ev.type == pygame.QUIT:
                running = False
            elif ev.type == pygame.KEYDOWN:
                keycode = KEYCODES.get(ev.key, 0)
                if ev.key == pygame.K_1:
                    pages.finish(); pages.page = 1; pages.enter()
                elif ev.key == pygame.K_2:
                    pages.finish(); pages.page = 2; pages.enter()
                elif ev.key == pygame.K_3:
                    pages.finish(); pages.page = 3; pages.enter()
                elif ev.key == pygame.K_q:
                    running = False
            elif ev.type == pygame.MOUSEMOTION:
                mouse_delta = ev.rel

        keys = pygame.key.get_pressed()
        state = {
            "shot": keys[pygame.K_c],
            "lock": keys[pygame.K_x] or keys[pygame.K_v],
            "left": keys[pygame.K_LEFT], "right": keys[pygame.K_RIGHT],
            "up": keys[pygame.K_UP], "down": keys[pygame.K_DOWN],
        }
        # 0x44EB60 + 0x44E660：每帧建记录（页1/2/3 都在 step 开头做）
        inp.build(state, pygame.mouse.get_pressed(), mouse_delta, keycode)

        # ---- 帧门 0x45A5A0：到期才走一帧
        if args.fixed or timer.due():
            if args.fixed:
                timer.consumed += 1
            pages.advance()
            frame += 1
            # ---- 显示（0x44C350 索引→RGB + present）
            rgb = canvas.to_rgb(getattr(pages, "pal_now", getattr(pages, "pal", palette)))
            if geki.FLIP_SCREEN:
                rgb = rgb[::-1]
            rgb = np.ascontiguousarray(rgb.transpose(1, 0, 2))
            pygame.surfarray.blit_array(screen, rgb)
            if args.debug_hud:
                hud = (f"page {pages.page} frame {frame} flags 0x{flags.bits:X} "
                       f"ptr ({inp.x},{inp.y})")
                screen.blit(clock_font.render(hud, True, (255, 255, 255)), (6, 6))
            pygame.display.flip()
            if frame in shot_frames:
                out_dir.mkdir(parents=True, exist_ok=True)
                pygame.image.save(screen, str(out_dir / f"page{pages.page}_f{frame}.png"))
                print(f"[shot] {out_dir / f'page{pages.page}_f{frame}.png'}")
            if args.frames and frame >= args.frames:
                running = False
        elif not args.headless:
            pygame.time.wait(1)

    print(f"[end] page={pages.page} frame={frame} flags=0x{flags.bits:X}")
    for line in pages.trace:
        print("[trace]", line)
    pygame.quit()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
