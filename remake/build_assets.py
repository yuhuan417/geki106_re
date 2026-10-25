#!/usr/bin/env python3
"""资产编译器: 原版 geki106 资源 -> Godot 工程标准格式.

产物 (remake/godot/assets/):
  bg/stage_0..6.png        关卡背景 (图层RLE解码)
  atlas/atlas_79..82.png   敌机精灵图集
  ggd/*.png                字库/UI 图 (151)
  sfx/se_21..44.wav        音效 (s16 PCM)
  bgm/bgm_01..20.wav       BGM (MIDI 占位合成; 有 fluidsynth 时可用它重渲)
  scripts/stage_1..7.json  关卡脚本 (记录已解析)
"""
from __future__ import annotations

import json
import os
import struct
import sys
import wave

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from geki import assets
from geki.scriptvm import SIZES

OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "godot", "assets")

STAGE_STREAMS = {1: 46, 2: 47, 3: 48, 4: 49, 5: 50, 6: 51, 7: 52}


def save_png(pixels: bytes, w: int, h: int, pal, path: str):
    from PIL import Image

    img = Image.new("P", (w, h))
    img.putpalette([c for rgb in pal for c in rgb] + [0, 0, 0] * (256 - len(pal)))
    img.frombytes(pixels)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    img.save(path)


def save_wav(path: str, samples, rate: int):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    import numpy as np

    data = (np.clip(samples, -1, 1) * 32767).astype("<i2").tobytes()
    with wave.open(path, "wb") as w:
        w.setnchannels(1)
        w.setsampwidth(2)
        w.setframerate(rate)
        w.writeframes(data)


# ------------------------------------------------------------ MIDI 占位合成
def midi_render(smf: bytes, rate: int = 22050) -> "np.ndarray":
    """极简 SMF 渲染器 (占位音色: 衰减正弦+方波)."""
    import numpy as np

    assert smf[:4] == b"MThd"
    hlen = struct.unpack(">I", smf[4:8])[0]
    fmt, ntrk, division = struct.unpack(">HHH", smf[8:14])
    if division & 0x8000:
        raise ValueError("SMPTE timing not supported")
    events = []  # (time_ticks, type, note, vel, ch)
    pos = 8 + hlen
    for _ in range(ntrk):
        if smf[pos : pos + 4] != b"MTrk":
            break
        tlen = struct.unpack(">I", smf[pos + 4 : pos + 8])[0]
        track = smf[pos + 8 : pos + 8 + tlen]
        pos += 8 + tlen
        i = 0
        tick = 0
        running = None
        notes_open = {}
        while i < len(track):
            # vlq delta
            delta = 0
            while True:
                b = track[i]
                i += 1
                delta = (delta << 7) | (b & 0x7F)
                if not b & 0x80:
                    break
            tick += delta
            status = track[i]
            if status < 0x80:
                status = running
            else:
                i += 1
                if status < 0xF0:
                    running = status
            if status in (0xFF,):  # meta
                mtype = track[i]
                i += 1
                ln = track[i]
                i += 1
                i += ln
            elif status in (0xF0, 0xF7):  # sysex
                ln = track[i]
                i += 1 + ln
            else:
                hi = status & 0xF0
                ch = status & 0x0F
                if hi in (0x80, 0x90):
                    note, vel = track[i], track[i + 1]
                    i += 2
                    if hi == 0x90 and vel > 0:
                        events.append((tick, 1, note, vel, ch))
                        notes_open[(ch, note)] = tick
                    else:
                        st = notes_open.pop((ch, note), tick)
                        events.append((tick, 0, note, vel, ch, st))
                elif hi in (0xA0, 0xB0, 0xE0):
                    i += 2
                elif hi in (0xC0, 0xD0):
                    i += 1
    if not events:
        return np.zeros(1, dtype=np.float32)
    total_ticks = max(e[0] for e in events)
    sec_per_tick = 60.0 / 120.0 / division  # 假定 120BPM (SMF 未解析 tempo)
    dur = total_ticks * sec_per_tick + 2.0
    buf = np.zeros(int(dur * rate), dtype=np.float32)
    evs = sorted(events, key=lambda e: e[0])
    for e in evs:
        if e[1] != 0:
            continue
        _, _, note, vel, ch, st = e
        t0 = st * sec_per_tick
        length = max(e[0] - st, 1) * sec_per_tick
        freq = 440.0 * 2 ** ((note - 69) / 12.0)
        n = int(length * rate)
        if n < 2 or t0 >= dur:
            continue
        t = np.arange(n) / rate
        env = np.exp(-t * max(1.0, 2.5 / max(length, 0.05)))
        vol = 0.12 * (vel / 127.0)
        if ch == 9:  # 打击乐: 噪声
            rng = np.random.default_rng(note)
            wavef = rng.standard_normal(n) * env
        else:
            wavef = (0.6 * np.sin(2 * np.pi * freq * t) + 0.25 * np.sign(np.sin(2 * np.pi * freq * t))) * env
        s0 = int(t0 * rate)
        s1 = min(s0 + n, len(buf))
        buf[s0:s1] += (wavef[: s1 - s0] * vol).astype(np.float32)
    peak = np.abs(buf).max()
    if peak > 0:
        buf *= 0.8 / peak
    return buf


# ------------------------------------------------------------ 脚本 -> JSON
def script_to_json(data: bytes) -> list[dict]:
    recs = []
    pos = 0
    n = len(data)
    while pos + 4 <= n:
        op, time = struct.unpack("<HH", data[pos : pos + 4])
        if op > 0xE:
            break
        if op == 9:
            cnt = struct.unpack("<I", data[pos + 12 : pos + 16])[0]
            size = 16 + cnt * 4
        else:
            size = SIZES[op]
        if op == 0:
            recs.append({"op": 0, "t": time})
            break
        body = data[pos + 4 : pos + size]
        r: dict = {"op": op, "t": time}
        if op == 0xE:
            r["name"] = body.split(b"\0")[0].decode("ascii", "replace")
        elif op in (1, 2, 3, 4, 5):
            r["args"] = list(struct.unpack("<4I", body[:16]))
        elif op in (6, 7):
            r["ch"] = struct.unpack("<I", body[:4])[0]
            r["delta"] = [v / 65536.0 for v in struct.unpack("<20i", body[4:84])]
            r["tail"] = list(struct.unpack("<2I", body[84:92])) if op == 7 else list(struct.unpack("<1I", body[84:88]))
        elif op == 8:
            r["ch"] = struct.unpack("<I", body[:4])[0]
        elif op == 9:
            a0, a1, cnt = struct.unpack("<3I", body[:12])
            r["args"] = [a0, a1]
            r["vals"] = list(struct.unpack(f"<{cnt}I", body[12 : 12 + cnt * 4]))
        elif op == 0xA:
            r["args"] = list(struct.unpack("<2I", body[:8]))
        elif op == 0xB:
            r["layers"] = list(struct.unpack("<14I", body[:56]))
        elif op in (0xC, 0xD):
            r["arg"] = struct.unpack("<I", body[:4])[0]
        recs.append(r)
        pos += size
    return recs


# ---------------------------------------------------------------- main
def main():
    res = assets.Resources.load()
    pal = assets.load_palette()

    # 背景 + 图集 + GGD
    for stage in range(7):
        bg = assets.load_stage_bg(res, stage)
        save_png(bg, 640, 480, pal, f"{OUT}/bg/stage_{stage}.png")
        print(f"bg stage_{stage}.png")
    for idx in (79, 80, 81, 82):
        ent = res.get(idx)
        save_png(ent, 320, len(ent) // 320, pal, f"{OUT}/atlas/atlas_{idx}.png")
    ggd_dir = os.path.join(assets.GAME_DIR)
    count = 0
    for root, _, files in os.walk(ggd_dir):
        for fn in files:
            if fn.endswith(".ggd"):
                p = os.path.join(root, fn)
                try:
                    w, h, px = assets.ggd_load(p)
                except Exception:
                    continue
                rel = os.path.relpath(p, ggd_dir).replace(os.sep, "_").replace(".ggd", ".png")
                save_png(px, w, h, pal, f"{OUT}/ggd/{rel}")
                count += 1
    print(f"ggd: {count}")

    # 音效
    for idx in range(21, 45):
        pcm = res.get(idx)
        save_wav(f"{OUT}/sfx/se_{idx:02d}.wav",
                 __import__("numpy").frombuffer(pcm[: len(pcm) // 2 * 2], dtype="<i2") / 32768.0,
                 11025)
    print("sfx: 24")

    # BGM
    try:
        import numpy  # noqa: F401

        for idx in range(1, 21):
            smf = assets.load_midi(res, idx)
            try:
                buf = midi_render(smf)
                save_wav(f"{OUT}/bgm/bgm_{idx:02d}.wav", buf, 22050)
            except Exception as e:
                print(f"bgm {idx} render fail: {e}")
        print("bgm: 20")
    except ImportError:
        print("numpy missing: skip bgm")

    # 脚本 JSON
    for stage, sid in STAGE_STREAMS.items():
        recs = script_to_json(res.get(sid))
        os.makedirs(f"{OUT}/scripts", exist_ok=True)
        json.dump(recs, open(f"{OUT}/scripts/stage_{stage}.json", "w"))
        print(f"script stage_{stage}: {len(recs)} records")


if __name__ == "__main__":
    main()


# ============================================================ 精灵切片 + 行为表
def slice_atlas() -> list:
    """连通域自动切片 #79-82 图集 -> 单个精灵 PNG + sprites.json.
    (精确的 16x16 图块组合链 0x43F230 留待后续, 视觉上等效)"""
    import numpy as np
    from PIL import Image

    res = assets.Resources.load()
    pal = assets.load_palette()
    meta = []
    for idx in (79, 80, 81, 82):
        ent = res.get(idx)
        w, h = 320, len(ent) // 320
        arr = np.frombuffer(ent[: w * h], dtype=np.uint8).reshape(h, w)
        # 背景色 0xB4 视为透明
        mask = arr != 0xB4
        # 简单连通域 (4邻接, 无scipy时用洪泛)
        visited = np.zeros_like(mask, dtype=bool)
        sprites = []
        from collections import deque
        for y in range(h):
            for x in range(w):
                if mask[y, x] and not visited[y, x]:
                    q = deque([(y, x)])
                    visited[y, x] = True
                    minx = maxx = x
                    miny = maxy = y
                    while q:
                        cy, cx = q.popleft()
                        minx, maxx = min(minx, cx), max(maxx, cx)
                        miny, maxy = min(miny, cy), max(maxy, cy)
                        for dy, dx in ((1,0),(-1,0),(0,1),(0,-1)):
                            ny, nx = cy+dy, cx+dx
                            if 0 <= ny < h and 0 <= nx < w and mask[ny,nx] and not visited[ny,nx]:
                                visited[ny,nx] = True
                                q.append((ny,nx))
                    if maxx-minx >= 6 and maxy-miny >= 6:  # 忽略碎屑
                        sprites.append((minx, miny, maxx-minx+1, maxy-miny+1))
        for si, (sx, sy, sw, sh) in enumerate(sprites):
            sub = np.ascontiguousarray(arr[sy:sy+sh, sx:sx+sw])
            img = Image.new("P", (sw, sh))
            img.putpalette([c for rgb in pal for c in rgb] + [0,0,0]*(256-len(pal)))
            img.frombytes(sub.tobytes())
            img.save(f"{OUT}/sprites/a{idx}_{si:03d}.png")
            meta.append({"atlas": idx, "id": si, "x": sx, "y": sy, "w": sw, "h": sh})
    os.makedirs(f"{OUT}/sprites", exist_ok=True)
    json.dump(meta, open(f"{OUT}/sprites/sprites.json", "w"))
    print(f"sprites: {len(meta)}")
    return meta


# 0x23 型 26 个子变体行为表 (exe 0x40D940 跳转表 0x40DE98 提取)
# fn = 行为函数地址; v1/v2/v3 = entity+0x1C/+0x20/+0x24 常量 (速度/参数)
VARIANT_23 = [
    {"fn": "0x401FF0", "v1": "y?", "v2": "dir", "v3": -16},
    {"fn": "0x401B1D", "v1": "cmd.d", "v2": -4, "v3": 0},
    {"fn": "0x401BD1", "v1": 0, "v2": -30, "v3": "cmd.d"},
    {"fn": "0x401BD1", "v1": 0, "v1": 0, "v3": 0},
    {"fn": "0x401BD1", "v3": 0},
    {"fn": "0x401528", "v1": "cmd.d", "v2": 0},
    {"fn": "0x4015AA", "v1": 0x500},
    {"fn": "0x401181", "v1": 0x500},
    {"fn": "0x401181", "v1": -6, "v2": -48},
    {"fn": "0x401609", "v2": -30},
    {"fn": "0x40210D"},
    {"fn": "0x401BA9"},
    {"fn": "0x401BA9"},
    {"fn": "0x40138E"},
    {"fn": "0x401DC5", "v1": 0x24},
    {"fn": "0x401DC5"},
    {"fn": "0x401DC5"},
    {"fn": "0x4015B4", "v2": -32},
    {"fn": "0x401D48"},
    {"fn": None},
    {"fn": "0x401D48", "v2": 0x30},
    {"fn": "0x401951", "v2": 0x30},
    {"fn": "0x4013BB", "v2": -24, "v3": 15},
    {"fn": "0x401B31", "v3": 0x60},
    {"fn": "0x40242D", "v3": -64},
    {"fn": "0x40242D", "v3": -64},
]
