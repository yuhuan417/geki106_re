#!/usr/bin/env python3
"""汉字精灵拼装器 — exe 瓦片链 1:1 复刻 (0x43F230/0x43F560 还原)
管线: GGD字库(按装载表) -> 虚拟层5/6 (656x496)
      -> 源采样 (x=行*8, y=字节*8, 16x16)
      -> 目标拼装 (x=(b&0xF0)+8±, y=((b&0xF)*16)+8±, 行奇偶/字节bit0 各±8)
用法: python3 kanji_compose.py [atlas_res=79] [row] -> 拼出该敌机类型的汉字精灵
"""
import sys, os, json
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), 'remake'))
from geki import assets
from PIL import Image

GAME = '/home/yuhuan/geki106'

# GGD 装载表 (exe 0x43F560 栈表还原): (state_code, layer, param)
# 初始装载: 层6 <- 通用字库; 层5/6 素材 = bmcm 通用 + 每关 bm_sX
LOAD_ORDER = [
    'bmcm/bm_cmgo.ggd',   # 256x224 通用
    'bmcm/bm_cm32.ggd',   # 320x256 通用32
    'bmcm/bm_cm48.ggd',   # 240x528 通用48
    'bmcm/bm_cmrc.ggd',   # 432x192
    'bmcm/bm_cmrs.ggd',   # 288x312
]

def build_tile_lib() -> Image.Image:
    """把通用 GGD 字库纵向拼成 656 宽虚拟瓦片库 (近似层5的装载结果)."""
    lib = Image.new('RGB', (656, 496), (20, 20, 30))
    y = 0
    for rel in LOAD_ORDER:
        p = os.path.join(GAME, rel)
        if not os.path.exists(p):
            continue
        w, h, px = assets.ggd_load(p)
        img = Image.new('P', (w, h))
        pal = assets.load_palette()
        img.putpalette([c for rgb in pal for c in rgb])
        img.frombytes(px)
        if y + h <= lib.height:
            lib.paste(img.convert('RGB'), (0, y))
            y += h
    return lib

def compose(atlas_res: int, row: int, lib: Image.Image) -> Image.Image:
    res = assets.Resources.load()
    t = res.get(atlas_res)
    canvas = Image.new('RGB', (272, 272), (25, 25, 40))
    W = 320
    row_bytes = t[row*W:(row+1)*W]
    for bi in range(80):
        b = row_bytes[bi]
        if b == 0:
            continue
        sx = (b & 0xF0)
        sy = (b & 0xF) * 16
        # ±8 半格偏移 (行奇偶 -> x; 字节bit0 -> y) — 0x43F230
        dx = 8 if (row & 1) else 0
        dy = 8 if (b & 1) else 0
        src_x, src_y = row * 8, b * 8
        if src_x + 16 > lib.width or src_y + 16 > lib.height:
            continue
        tile = lib.crop((src_x, src_y, src_x + 16, src_y + 16))
        tx, ty = sx + dx, sy + dy
        if tx + 16 <= canvas.width and ty + 16 <= canvas.height:
            canvas.paste(tile, (tx, ty))
    return canvas

if __name__ == '__main__':
    lib = build_tile_lib()
    atlas = int(sys.argv[1]) if len(sys.argv) > 1 else 79
    rows = [int(sys.argv[2])] if len(sys.argv) > 2 else list(range(0, 60, 6))
    for row in rows:
        img = compose(atlas, row, lib)
        img.save(f'/tmp/kanji_a{atlas}_r{row}.png')
        print(f'row {row} -> /tmp/kanji_a{atlas}_r{row}.png')
