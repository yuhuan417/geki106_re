#!/usr/bin/env python3
"""Static-Huffman decoder (exe 0x44f0b0) for resource.rom entries.
Entry layout: huffman bitstream || u24 LE decoded-length trailer.
Tables: lens[256] (stored len-1), codes[256] u16, LSB-first bit order."""
import struct, pefile

pe = pefile.PE('/home/yuhuan/geki106/geki106.exe')
ib = pe.OPTIONAL_HEADER.ImageBase
img = pe.get_memory_mapped_image()
codes = struct.unpack('<256H', img[0x498c48-ib:0x498c48-ib+512])
lens  = img[0x498e48-ib:0x498e48-ib+256]

def huff_decode(src, out_len):
    out = bytearray()
    bits = 0
    end = len(src) - 3
    while len(out) < out_len:
        pos = bits >> 3
        if pos + 4 > end:
            window = int.from_bytes(src[pos:end] + b'\0'*4, 'little')
        else:
            window = struct.unpack('<I', src[pos:pos+4])[0]
        window >>= (bits & 7)
        for s in range(256):
            L = lens[s]
            if window & ((1 << (L+1)) - 1) == codes[s]:
                out.append(s)
                bits += L + 1
                break
        else:
            raise ValueError(f"no code match at bit {bits}")
    return bytes(out)

if __name__ == '__main__':
    d = open('resource_dec.bin','rb').read()
    def off(i): return int.from_bytes(d[(i-1)*3:(i-1)*3+3],'little')
    n = 294 // 3
    def getent(idx):
        o = off(idx); e = off(idx+1) if idx < n else len(d)
        return d[o:e]
    for idx in [1, 2, 21, 45, 66, 77, 78, 79]:
        ent = getent(idx)
        out_len = int.from_bytes(ent[-3:], 'little')
        try:
            out = huff_decode(ent, out_len)
            print(f"#{idx}: {len(ent)} -> {len(out)}  head={out[:24].hex()} ascii={out[:24]}")
        except Exception as e:
            print(f"#{idx}: {len(ent)} trailer={out_len} FAIL: {e}")
