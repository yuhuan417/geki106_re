#!/usr/bin/env python3
import struct, os, sys
sys.path.insert(0, '.')
from huff_fast import huff_decode

d = open('resource_dec.bin','rb').read()
def off(i): return int.from_bytes(d[(i-1)*3:(i-1)*3+3],'little')
n = 294 // 3
def getent(idx):
    o = off(idx); e = off(idx+1) if idx < n else len(d)
    return d[o:e]

os.makedirs('extracted/midi', exist_ok=True)
kinds = {}
for idx in range(1, n+1):
    ent = getent(idx)
    trailer = int.from_bytes(ent[-3:], 'little')
    kind = '?'
    if ent[:4] == b'GRPD':
        kind = 'replay099F'
    elif ent[:4] == b'\x0e\x00\x00\x00' or ent[:4] == b'\x05\x00\x00\x00':
        kind = 'script'
    elif len(ent) < trailer < 1_000_000 and trailer > 200:
        try:
            out = huff_decode(ent, trailer)
            if out[:4] == b'MThd':
                kind = 'MIDI'
                open(f'extracted/midi/bgm_{idx:02d}.mid','wb').write(out)
            elif out[:4] == b'RIFF':
                kind = 'RIFF'
        except Exception:
            kind = '?'
    print(f"#{idx:2d} size={len(ent):7d} trailer={trailer:8d} {kind} {ent[:12].hex()}")
