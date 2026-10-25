#!/usr/bin/env python3
"""汉字字形切割器: bm_sX.ggd (16px 部件网格) -> Godot 字形表.
发现: 游戏所有实体(自机/敌机/弹)都由 16x16 汉字部件渲染 (对应 exe 图块链 0x43F230).
"""
import os, sys, struct
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from geki import assets
from PIL import Image

OUT = "godot/assets/glyphs"
CELL = 16

def atlas_cells(name: str):
    """-> (grid_image_p, cols, rows): 16px 部件格."""
    w, h, px = assets.ggd_load(f"{assets.GAME_DIR}/{name}")
    img = Image.new("P", (w, h))
    pal = assets.load_palette()
    img.putpalette([c for rgb in pal for c in rgb])
    img.frombytes(px)
    cols, rows = w // CELL, h // CELL
    return img, cols, rows

def main():
    os.makedirs(OUT, exist_ok=True)
    meta = {}
    for stage in range(1, 8):
        name = ({"s7a": "bms7/bm_s7a.ggd", "s7b": "bms7/bm_s7b.ggd"}.get(f"s{stage}", f"bms{stage}/bm_s{stage}.ggd")) if stage == 7 else f"bms{stage}/bm_s{stage}.ggd"
        img, cols, rows = atlas_cells(name)
        img.save(f"{OUT}/font_s{stage}.png")
        meta[f"s{stage}"] = {"w": img.width, "h": img.height, "cols": cols, "rows": rows, "cell": CELL}
        print(f"{name}: {img.width}x{img.height} = {cols}x{rows} cells")
    # 通用字库
    for fn, key in [("bmcm/bm_cm32.ggd", "cm32"), ("bmcm/bm_cm48.ggd", "cm48"), ("bmcm/bm_cmgo.ggd", "cmgo")]:
        img, cols, rows = atlas_cells(fn)
        img.save(f"{OUT}/font_{key}.png")
        meta[key] = {"w": img.width, "h": img.height, "cols": cols, "rows": rows, "cell": CELL}
    import json
    json.dump(meta, open(f"{OUT}/fonts.json", "w"))
    print("glyphs exported")

if __name__ == "__main__":
    main()
