#!/usr/bin/env python3
"""撃破伝 背景/页2 渲染机制复刻 (纯逆向机制, 无原版像素拷贝)
机制1 (exe 0x4562A0 + 0x44D290): 天空 = 序列表逐带色填充 (调色板 LUT 色)
机制2 (exe 0x44D330): 楼墙/文字 = 系统字体 CreateFont+TextOut (灰字+投影)
原版色带表来自序列引擎 (#77/数列関数) 运行时计算; 此处从 pscr0000 实测提取.
"""
from PIL import Image, ImageDraw, ImageFont
import numpy as np
import sys

SRC = sys.argv[1] if len(sys.argv) > 1 else '/home/yuhuan/geki106/pscr0000.bmp'
W, H = 640, 480

pim = Image.open(SRC)
arr = np.array(pim)
pal = pim.getpalette()

# 机制1: 色带表 (每行众数 → 游程压缩) — 原版由 0x4CD484 序列引擎逐帧计算
bands = []
for y in range(336):
    vals, cnts = np.unique(arr[y], return_counts=True)
    v = int(vals[cnts.argmax()])
    if bands and bands[-1][1] == v: bands[-1][0] += 1
    else: bands.append([1, v])

img = Image.new('RGB', (W, H))
dr = ImageDraw.Draw(img)
y = 0
for h, c in bands:                     # 0x4562A0 循环体
    dr.rectangle([0, y, W, y + h], fill=tuple(pal[c*3:c*3+3]))  # 0x44D290 colorfill
    y += h
dr.rectangle([0, 336, W, H], fill=(102, 102, 153))

# 机制2: 楼墙 = 明朝体汉字 + 投影, 三行视差
def kanji(x, y, ch, size, fill, shadow=(51, 51, 102), s=3):
    f = ImageFont.truetype('/usr/share/fonts/opentype/noto/NotoSerifCJK-Bold.ttc', size)
    dr.text((x + s, y + s), ch, font=f, fill=shadow)   # 投影 0xAB
    dr.text((x, y), ch, font=f, fill=fill)

for i in range(16): kanji(i*42-20, 306+(i%3)*8, '都', 38, (102,102,153))
for i in range(11): kanji(i*62-30, 348+(i%2)*14, '者' if i%3==1 else '都', 62, (102,102,153))
for i in range(7):  kanji(i*98-40, 398+(i%2)*22, '都', 110, (102,102,153) if i%2 else (102,102,102))

# 文字层 (0x44D330): 关卡标题 + 弹/擊/狙/敌 + HUD
g36 = ImageFont.truetype('/usr/share/fonts/opentype/noto/NotoSansCJK-Bold.ttc', 36)
dr.text((150, 200), '第一幕  市街', font=g36, fill=(255,255,255))
dr.text((40, 180), '擊', font=g36, fill=(255,0,0))
for x in range(140, 560, 80): dr.text((x, 180), '弹', font=g36, fill=(102,255,255))
dr.text((250, 260), '狙', font=g36, fill=(0,153,0))
dr.text((290, 280), '敌', font=g36, fill=(255,153,0))
h18 = ImageFont.truetype('/usr/share/fonts/opentype/noto/NotoSansCJK-Bold.ttc', 18)
dr.text((10, 8), '残撃  伍', font=h18, fill=(255,255,255))
dr.text((10, 34), '捕獲  可', font=h18, fill=(0,255,0))
dr.text((560, 8), '零点', font=h18, fill=(255,255,255))

img.save('replica_bg.png')
orig = pim.convert('RGB')
comp = Image.new('RGB', (1280, 480), (0, 0, 0))
comp.paste(orig, (0, 0)); comp.paste(img, (640, 0))
comp.save('replica_compare.png')
print("replica_bg.png + replica_compare.png (左原版|右复刻)")
