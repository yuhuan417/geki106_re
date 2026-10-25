#!/usr/bin/env python3
"""Optimized static-Huffman decoder for geki106 resource entries."""
import struct, pefile

pe = pefile.PE('/home/yuhuan/geki106/geki106.exe')
ib = pe.OPTIONAL_HEADER.ImageBase
img = pe.get_memory_mapped_image()
codes = struct.unpack('<256H', img[0x498c48-ib:0x498c48-ib+512])
lens  = img[0x498e48-ib:0x498e48-ib+256]

# build lookup: (eff_len, code) -> symbol, honoring table priority (first symbol wins)
lut = {}
for s in range(256):
    L = lens[s]
    key = (L+1, codes[s])
    if key not in lut:
        lut[key] = s
by_len = {}
for (k, c), s in lut.items():
    by_len.setdefault(k, {})[c] = s

def huff_decode(src, out_len):
    out = bytearray()
    bits = 0
    end = len(src) - 3
    while len(out) < out_len:
        pos = bits >> 3
        window = int.from_bytes(src[pos:pos+4], 'little') if pos+4 <= end else \
                 int.from_bytes((src[pos:end] + b'\0\0\0\0')[:4], 'little')
        window >>= (bits & 7)
        for k in range(1, 17):
            d = by_len.get(k)
            if d is not None:
                s = d.get(window & ((1 << k) - 1))
                if s is not None:
                    out.append(s)
                    bits += k
                    break
        else:
            raise ValueError(f"no code at bit {bits}")
    return bytes(out)

if __name__ == '__main__':
    d = open('resource_dec.bin','rb').read()
    def off(i): return int.from_bytes(d[(i-1)*3:(i-1)*3+3],'little')
    n = 294 // 3
    def getent(idx):
        o = off(idx); e = off(idx+1) if idx < n else len(d)
        return d[o:e]
    for idx in [1, 2, 21, 45, 66, 79]:
        ent = getent(idx)
        out_len = int.from_bytes(ent[-3:], 'little')
        try:
            out = huff_decode(ent, out_len)
            print(f"#{idx}: {len(ent)} -> {len(out)}  head={out[:24].hex()} ascii={out[:24]}")
        except Exception as e:
            print(f"#{idx}: {len(ent)} trailer={out_len} FAIL: {e}")
