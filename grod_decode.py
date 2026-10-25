#!/usr/bin/env python3
"""GROD106A decoder - reverse engineered from geki106.exe sub_45b6e0
resource.rom = 'GROD' '106A' u32 N | [checksum(1)] [marker(1)] [tokens...]
Token: literal byte | marker 0x00 (literal marker) | marker count -> LZ ref
       distance = count>>3 (0..31; 0 => fills zeros), length = (count&7)*4+4
Checksum: src[0] ^ XOR_{i=0..N-1}( out[i]*(i&0xFF) & 0xFF ) == 0
"""
import struct, sys

def grod_decode(data):
    assert data[:4] == b'GROD' and data[4:8] == b'106A', "bad magic"
    N = struct.unpack('<I', data[8:12])[0]
    src = data[12:]
    checksum, marker = src[0], src[1]
    out = bytearray(N)          # zero-initialised, like the game's buffer
    i, o = 2, 0
    while i < N and o < N - 4:
        al = src[i]
        if al == marker:
            count = src[i+1]; i += 2
            if count == 0:
                out[o] = marker; o += 1
            else:
                dist = count >> 3
                length = (count & 7) * 4 + 4
                spos = o - dist
                for k in range(length):
                    if o >= N: break
                    out[o] = out[spos + k]   # spos+k may be >= o (dist==0) -> stays 0
                    o += 1
        else:
            out[o] = al; o += 1; i += 1
    while o < N:
        out[o] = src[i]; i += 1; o += 1
    c = checksum
    for idx in range(N):
        c ^= (out[idx] * (idx & 0xFF)) & 0xFF
    print(f"N={N} decoded={len(out)} checksum_ok={c == 0}", file=sys.stderr)
    return bytes(out)

if __name__ == '__main__':
    data = open('/home/yuhuan/geki106/resource.rom', 'rb').read()
    out = grod_decode(data)
    open('resource_dec.bin', 'wb').write(out)
    print("written", len(out))
    print(out[:96].hex())
