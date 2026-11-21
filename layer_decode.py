#!/usr/bin/env python3
"""#83-89 关卡图层解码器（exe 0x45BC00 还原）
资源布局: [0x00..0x17] 23+1 字节字词典 (值=input[i-8], i=8..30) | [0x18..] token 流
token (input[edi] 起 4 字节 LE=eax):
 B 零跳  : (al&0x18)==0; n=((eax>>2)&0x18)|(eax&7); al&0x80: n|=(eax>>3)&0x1FE0, 2B; else 1B; x+=n+1
 A1 短RLE: (al&0x1F)!=0x1F; val=dict[al&0x1F]; run=(eax>>5)&3; al&0x80: run|=(eax>>6)&0x3FC, 2B; else 1B; fill run+1
 A2 长RLE: (al&0x1F)==0x1F:
   - (ah&3)==0: n=eax>>5 (22bit), 4B, 零跳 n+1
   - else: val=dict[(eax>>5)&0x1F]; run=eax>>10, 4B, fill run+1
输出: 640x480 8bpp (行环绕)
"""
import sys

def layer_decode(src, width=640, height=480):
    out = bytearray(width*height)
    pos = 0x18          # token 流起点
    x = 0               # 当前行内位置
    rowptr = 0
    total = width*height
    n_tok = 0
    while pos + 4 <= len(src):
        eax = int.from_bytes(src[pos:pos+4], 'little')
        al = eax & 0xFF
        val = None
        if (al & 0x18) == 0:
            n = ((eax >> 2) & 0x18) | (eax & 7)
            if al & 0x80:
                n |= (eax >> 3) & 0x1FE0
                pos += 2
            else:
                pos += 1
            x += n + 1
        else:
            d = al & 0x1F
            if d != 0x1F:
                idx = d - 8
                val = src[idx] if 0 <= idx < len(src) else 0
                run = (eax >> 5) & 3
                if al & 0x80:
                    run |= (eax >> 6) & 0x3FC
                    pos += 2
                else:
                    pos += 1
                run += 1
            else:
                if (eax >> 8) & 3 == 0:
                    n = eax >> 5
                    pos += 4
                    x += n + 1
                else:
                    idx = ((eax >> 5) & 0x1F) - 8
                    val = src[idx] if 0 <= idx < len(src) else 0
                    run = (eax >> 10) + 1
                    pos += 4
            if val is not None:
                # 填充, 行环绕
                while run > 0:
                    if x >= width:
                        x -= width
                        rowptr += width
                        if rowptr >= total:
                            return out, n_tok, pos
                    take = min(run, width - x)
                    out[rowptr+x : rowptr+x+take] = bytes([val])*take
                    x += take
                    run -= take
        # 零跳后的行推进
        while x >= width:
            x -= width
            rowptr += width
            if rowptr >= total:
                return out, n_tok, pos
        n_tok += 1
        if rowptr + x >= total:
            break
    return out, n_tok, pos

if __name__ == '__main__':
    from PIL import Image
    d = open('resource_dec.bin','rb').read()
    def off(i): return int.from_bytes(d[(i-1)*3:(i-1)*3+3],'little')
    def getent(idx):
        o = off(idx); e = off(idx+1)
        return d[o:e]
    import os
    game = os.environ.get('GEKI_DIR') or os.path.join(
        os.path.dirname(os.path.abspath(__file__)), '..', 'geki106')
    pal = []
    pb = open(os.path.join(game, 'bmcm', 'bm_pal.bmp'), 'rb').read()
    for i in range(256):
        b,g,r,_ = pb[54+i*4:58+i*4]
        pal.append((r,g,b))
    os.makedirs('extracted/stage_bg', exist_ok=True)
    for idx in range(83, 90):
        ent = getent(idx)
        out, ntok, consumed = layer_decode(ent)
        img = Image.new('P', (640,480))
        img.putpalette([c for rgb in pal for c in rgb])
        img.frombytes(bytes(out))
        img.save(f'extracted/stage_bg/stage_{idx-83:02d}.png')
        print(f"#{idx}: {len(ent)}B -> {ntok} tokens, consumed {consumed}/{len(ent)}, nonzero={sum(1 for b in out if b)}")
