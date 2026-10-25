#!/usr/bin/env python3
"""Convert geki106 .ggd (GGPD106A) files to PNG with bmcm/bm_pal*.bmp palettes."""
import struct, sys, os
from PIL import Image

def load_pal(path):
    d = open(path,'rb').read()
    off = struct.unpack('<I', d[10:14])[0]  # bfOffBits; palette at 54
    pal = []
    for i in range(256):
        b,g,r,_ = d[54+i*4:58+i*4]
        pal.append((r,g,b))
    return pal

def ggd_to_png(ggd_path, pal, out_path, scale=1):
    d = open(ggd_path,'rb').read()
    assert d[:4] == b'GGPD', d[:8]
    w, h = struct.unpack('<HH', d[8:12])
    stride = (w + 3) & ~3
    img = Image.new('P', (w,h))
    img.putpalette([c for rgb in pal for c in rgb])
    px = img.load()
    for y in range(h):
        row = d[12+y*stride : 12+y*stride+w]
        for x in range(w):
            px[x,y] = row[x]
    if scale != 1:
        img = img.resize((w*scale, h*scale), Image.NEAREST)
    img.save(out_path)
    return w,h

if __name__ == '__main__':
    pal  = load_pal('/home/yuhuan/geki106/bmcm/bm_pal.bmp')
    pald = load_pal('/home/yuhuan/geki106/bmcm/bm_pald.bmp')
    pals = load_pal('/home/yuhuan/geki106/bmcm/bm_pals.bmp')
    src = sys.argv[1] if len(sys.argv)>1 else '/home/yuhuan/geki106/bms1/bm_s1.ggd'
    out = sys.argv[2] if len(sys.argv)>2 else 'extracted/ggd_png/test.png'
    w,h = ggd_to_png(src, pal, out, scale=1)
    print(f"{src} {w}x{h} -> {out}")
