import sys
sys.path.insert(0, 'remake')
from geki import assets

def decode83(ent, width=640, height=480):
    d = ent
    out = bytearray(width * height)
    pos = 0x18; x = 0; rowptr = 0; total = width * height
    while pos + 4 <= len(d) and rowptr + x < total:
        eax = int.from_bytes(d[pos:pos+4], 'little')
        al = eax & 0xFF
        val = None
        if (al & 0x18) == 0:
            n = ((eax >> 2) & 0x18) | (eax & 7)
            if al & 0x80:
                n |= (eax >> 3) & 0x1FE0; pos += 2
            else:
                pos += 1
            x += n + 1
        else:
            dd = al & 0x1F
            if dd != 0x1F:
                val = d[dd - 8]
                run = (eax >> 5) & 3
                if al & 0x80:
                    run |= (eax >> 6) & 0x3FC; pos += 2
                else:
                    pos += 1
                run += 1
            else:
                if (eax >> 8) & 3 == 0:
                    n = eax >> 5; pos += 4; x += n + 1
                else:
                    val = d[((eax >> 5) & 0x1F) - 8]; run = (eax >> 10) + 1; pos += 4
            if val is not None:
                while run > 0:
                    if x >= width:
                        x -= width; rowptr += width
                        if rowptr >= total: return bytes(out)
                    take = min(run, width - x)
                    out[rowptr+x:rowptr+x+take] = bytes([val]) * take
                    x += take; run -= 1
        while x >= width:
            x -= width; rowptr += width
            if rowptr >= total: break
    return bytes(out)

if __name__ == '__main__':
    import numpy as np
    res = assets.Resources.load()
    bg = np.frombuffer(decode83(res.get(83)), dtype=np.uint8).reshape(480, 640)
    for y in range(0, 480, 10):
        vals, cnts = np.unique(bg[y], return_counts=True)
        top2 = sorted(zip(vals.tolist(), cnts.tolist()), key=lambda x: -x[1])[:2]
        print(f"y={y:3d}: {[(hex(v), c) for v, c in top2]}")
