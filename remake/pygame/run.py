#!/usr/bin/env python3
"""页1/2/3/13 运行器（pygame）：自己的 60Hz 帧门 + 8bpp 画布，不依赖任何引擎循环。

用法:
    python3 remake/pygame/run.py                     # 从页1 开始跑（ESC 退出，1/2/3 调试切页）
    python3 remake/pygame/run.py --page 2            # 直接进页2（3/13 同理）
    python3 remake/pygame/run.py --frames 300 --headless --fixed   # 无窗口跑 300 帧（脚本/CI）
    python3 remake/pygame/run.py --frames 300 --shot 250 --out /tmp   # 第 250 帧存 PNG
"""
from __future__ import annotations

import argparse
import os
import sys
import time
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
    ap = argparse.ArgumentParser(description="撃破伝 页1/2/3/13 复刻（pygame）")
    ap.add_argument("--page", type=int, default=1, help="起始页（1/2/3/13）")
    ap.add_argument("--frames", type=int, default=0, help="跑 N 帧后退出（0=无限）")
    ap.add_argument("--shot", type=int, default=-1, help="第 N 帧存 PNG")
    ap.add_argument("--shots", default="", help="多个帧号，逗号分隔（做对比图用）")
    ap.add_argument("--out", default=str(HERE / "shots"), help="PNG 输出目录")
    ap.add_argument("--headless", action="store_true", help="无窗口（SDL dummy）")
    ap.add_argument("--video", default="", help="强制 SDL 视频驱动（x11 / wayland / dummy）")
    ap.add_argument("--fixed", action="store_true", help="不按真实时间，尽快跑帧")
    ap.add_argument("--debug-hud", action="store_true", help="叠加调试信息（非原作内容）")
    ap.add_argument("--no-kbd-menu", action="store_true",
                    help="禁用方向键选菜单（默认开启，与真机一致：一按一档）")
    args = ap.parse_args(argv)

    if args.video:
        os.environ["SDL_VIDEODRIVER"] = args.video
    if args.headless:
        os.environ.setdefault("SDL_VIDEODRIVER", "dummy")
    # 原作是固定 640x480 8bpp 全屏；这里固定 640x480 窗口，1:1 像素，不缩放、不可 resize
    os.environ.setdefault("SDL_VIDEO_HIGHDPI_DISABLED", "1")
    # WSLg 下窗口有时会被摆到屏幕外/异常的坐标上（表现为"窗口没弹出来"但 active=True）
    os.environ.setdefault("SDL_VIDEO_WINDOW_POS", "80,80")
    # 复刻版没有音频：把音频子系统钉成 dummy，并**不用 pygame.init()**（它会连带初始化
    # mixer，在没有声卡的 WSLg/容器里会卡住或长时间探测 ALSA，表现为"启动就卡"）。
    os.environ.setdefault("SDL_AUDIODRIVER", "dummy")
    pygame.display.init()
    pygame.font.init()
    pygame.display.set_caption("撃破伝 v1.06 — 640x480 (pages 1-3, 13)")
    # depth 交给 SDL 自己选（XWayland 上硬要 32bpp visual 有可能拿不到，窗口建了却不显示）
    screen = pygame.display.set_mode(WINDOW_SIZE, 0)
    if tuple(screen.get_size()) != WINDOW_SIZE:
        print(f"[video] 警告: 实际窗口 {screen.get_size()} != {WINDOW_SIZE}", file=sys.stderr)
    else:
        print(f"[video] 固定 {WINDOW_SIZE[0]}x{WINDOW_SIZE[1]}（1:1，无缩放）")
        _drv = pygame.display.get_driver()
        print(f"[video] SDL 驱动 = {_drv}  DISPLAY={os.environ.get('DISPLAY','(未设置)')!r}  "
              f"WAYLAND_DISPLAY={os.environ.get('WAYLAND_DISPLAY','(未设置)')!r}", flush=True)
        # 立刻推一帧并泵一次事件，强制窗口被映射（WSLg 下有些情况下不会自己 map）
        pygame.event.pump()
        screen.fill((0, 0, 0))
        pygame.display.flip()
        try:
            _pos = pygame.display.get_window_position()
        except Exception:
            _pos = "?"
        print(f"[video] window_size={pygame.display.get_window_size()} pos={_pos} "
              f"active={pygame.display.get_active()} bits={screen.get_bitsize()} "
              f"displays={pygame.display.get_num_displays()}", flush=True)
        if _drv in ("offscreen", "dummy"):
            print(f"[video] 警告：SDL 驱动是 {_drv} ⇒ 有帧率但**不会显示窗口**。"
                  "WSLg 下通常是 Wayland 不可用（libdecor 失败）后 SDL 自动回退，"
                  "或 X server 无响应（可先 `xset -q` 自检）。", file=sys.stderr, flush=True)
        elif _drv == "dummy":
            print("[video] 警告：当前是 dummy 驱动 ⇒ 不会弹窗！WSLg 请执行 "
                  "export DISPLAY=:0（或 unset SDL_VIDEODRIVER）后重跑。", file=sys.stderr, flush=True)
    # 原作每帧 SetCursorPos(320,240) + 相对位移采样，系统光标不可见
    pygame.mouse.set_visible(False)
    clock_font = pygame.font.Font(None, 16) if args.debug_hud else None

    data = geki.load_data()
    palette = geki.load_palette()
    canvas = geki.Canvas()
    text = geki.TextRenderer(palette)
    inp = geki.Input()
    inp.kbd_move = not bool(args.no_kbd_menu)   # 真机默认：方向键一按一档
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
    pend_dx = pend_dy = 0          # 自上一"帧"以来累积的鼠标位移
    pend_key = 0                   # 自上一帧以来最后一次映射到的键码
    pend_shot = pend_lock = False  # 自上一帧以来是否出现过按下（防慢帧漏采样）
    pend_dir = {"left": 0, "right": 0, "up": 0, "down": 0}   # 方向键的点按次数
    _t_last = time.perf_counter()
    while running and pages.page != 0 and not pages.quit:
        # ---- 泵消息（0x458B80 的 PeekMessage/Translate/Dispatch 等价物）
        keycode = 0
        for ev in pygame.event.get():
            if ev.type == pygame.QUIT:
                running = False
            elif ev.type == pygame.KEYDOWN:
                keycode = KEYCODES.get(ev.key, 0)
                if ev.key == pygame.K_c:
                    pend_shot = True
                elif ev.key in (pygame.K_x, pygame.K_v):
                    pend_lock = True
                elif ev.key == pygame.K_LEFT:
                    pend_dir["left"] += 1
                elif ev.key == pygame.K_RIGHT:
                    pend_dir["right"] += 1
                elif ev.key == pygame.K_UP:
                    pend_dir["up"] += 1
                elif ev.key == pygame.K_DOWN:
                    pend_dir["down"] += 1
                if ev.key == pygame.K_1:
                    pages.finish(); pages.page = 1; pages.enter()
                elif ev.key == pygame.K_2:
                    pages.finish(); pages.page = 2; pages.enter()
                elif ev.key == pygame.K_3:
                    pages.finish(); pages.page = 3; pages.enter()
                elif ev.key == pygame.K_q:
                    running = False
            elif ev.type == pygame.MOUSEMOTION:
                # 位移要跨"非到期"循环累积，否则会随 build 一起丢掉
                pend_dx += ev.rel[0]
                pend_dy += ev.rel[1]

        if keycode:
            pend_key = keycode

        keys = pygame.key.get_pressed()
        state = {
            # 慢帧（Python 渲染 0.3~0.7s/帧）时按住状态可能在两帧之间被跳过，
            # 所以把"本间隔内出现过 KEYDOWN"也算作按下，只作用于下一个到期帧。
            "shot": keys[pygame.K_c] or pend_shot,
            "lock": keys[pygame.K_x] or keys[pygame.K_v] or pend_lock,
            # 方向键同理：按住靠 get_pressed()，**点按**靠事件锁存（否则一次快按会落在两帧之间）
            "left": keys[pygame.K_LEFT] or pend_dir["left"] > 0,
            "right": keys[pygame.K_RIGHT] or pend_dir["right"] > 0,
            "up": keys[pygame.K_UP] or pend_dir["up"] > 0,
            "down": keys[pygame.K_DOWN] or pend_dir["down"] > 0,
        }

        # ---- 帧门 0x45A5A0：到期才走一帧
        if args.fixed or timer.due():
            if args.fixed:
                timer.consumed += 1
            # 0x44EB60 + 0x44E660：**每帧**建一次记录（原件在 step 开头做）。
            # 注意：不能放在帧门之外 —— Input.build 会推进按键的"上帧状态"，
            # 非到期帧也调用会把按下沿（e0/e1）吃掉，导致"按 C 没反应"。
            inp.build(state, pygame.mouse.get_pressed(), (pend_dx, pend_dy), pend_key)
            pend_dx = pend_dy = 0
            pend_key = 0
            pend_shot = pend_lock = False
            for _k in pend_dir:
                pend_dir[_k] = 0
            pages.advance()
            frame += 1
            # 活体指示：窗口模式每秒报一次帧率（不是原作内容，只用于排查"看着像卡住"）
            if not args.headless and frame % 30 == 0:
                _now = time.perf_counter()
                _fps = 30.0 / max(1e-6, _now - _t_last)
                _t_last = _now
                print(f"[fps] frame={frame} page={pages.page} {_fps:.1f} fps", flush=True)
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
