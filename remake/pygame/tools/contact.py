#!/usr/bin/env python3
"""把页1 的关键帧拼成一张对照图（每帧带帧号/事件标注）。"""
import subprocess, sys, os
from pathlib import Path
from PIL import Image, ImageDraw

HERE = Path(__file__).resolve().parent.parent
FRAMES = [10, 30, 50, 80, 100, 130, 170, 200, 230, 260, 290, 300]
OUT = HERE / "shots"
OUT.mkdir(exist_ok=True)
env = dict(os.environ)
subprocess.run([sys.executable, str(HERE / "run.py"), "--frames", "301", "--headless", "--fixed",
                "--shots", ",".join(map(str, FRAMES)), "--out", str(OUT)], check=True,
               env=env, stdout=subprocess.DEVNULL)
cols, scale = 4, 0.5
w, h = int(640 * scale), int(480 * scale)
rows = (len(FRAMES) + cols - 1) // cols
sheet = Image.new("RGB", (cols * w, rows * (h + 14)), (20, 20, 20))
d = ImageDraw.Draw(sheet)
for i, f in enumerate(FRAMES):
    p = OUT / f"page1_f{f}.png"
    if not p.exists():
        continue
    im = Image.open(p).convert("RGB").resize((w, h), Image.NEAREST)
    x, y = (i % cols) * w, (i // cols) * (h + 14)
    sheet.paste(im, (x, y + 14))
    d.text((x + 4, y + 2), f"t={f}", fill=(255, 255, 0))
out = HERE / "shots" / "contact_page1.png"
sheet.save(out)
print(out)
