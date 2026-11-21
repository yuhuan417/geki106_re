#!/usr/bin/env python3
"""geki106 (撃破伝 v1.06) 完整资源提取器
- resource.rom: GROD106A 容器 → LZ 解压 → u24 偏移表 → 98 个条目
- MIDI 条目 (#1-20): 静态Huffman 解压 → 标准 SMF
- 其余条目按类型原样导出
- *.ggd: 8bpp 索引图 + bm_pal 调色板 → PNG
- 波形条目 (#21-44): s16le PCM → WAV (11025Hz 基准, 需按 SetFrequency 表变调)
"""
import struct, os, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from huff_fast import huff_decode

# 原作目录：env GEKI_DIR 优先，默认本仓库的兄弟目录 ../geki106（zip 解压到这里）
GAME = os.environ.get('GEKI_DIR') or os.path.abspath(
    os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'geki106'))
OUT  = 'extracted'
os.makedirs(f'{OUT}/midi', exist_ok=True)
os.makedirs(f'{OUT}/wave', exist_ok=True)
os.makedirs(f'{OUT}/script', exist_ok=True)
os.makedirs(f'{OUT}/data', exist_ok=True)
os.makedirs(f'{OUT}/replay', exist_ok=True)
os.makedirs(f'{OUT}/ggd_png', exist_ok=True)

def inner_lz(src, N):
    out = bytearray(N); i, o = 2, 0
    marker = src[1]
    while i < N and o < N - 4:
        al = src[i]
        if al == marker:
            count = src[i+1]; i += 2
            if count == 0: out[o] = marker; o += 1
            else:
                spos = o - (count >> 3)
                for k in range(((count & 7) * 4 + 4)):
                    if o >= N: break
                    out[o] = out[spos+k] if spos+k < N else 0; o += 1
        else:
            out[o] = al; o += 1; i += 1
    while o < N:
        out[o] = src[i]; i += 1; o += 1
    return bytes(out)

def grod_decode(data):
    assert data[:8] == b'GROD106A'
    N = struct.unpack('<I', data[8:12])[0]
    return inner_lz(data[12:], N)

# --- resource.rom ---
rom = open(f'{GAME}/resource.rom','rb').read()
blob = grod_decode(rom)
open(f'{OUT}/resource_dec.bin','wb').write(blob)
def off(i): return int.from_bytes(blob[(i-1)*3:(i-1)*3+3],'little')
N_ENTRIES = off(1) // 3
summary = []
for idx in range(1, N_ENTRIES+1):
    o = off(idx); e = off(idx+1) if idx < N_ENTRIES else len(blob)
    ent = blob[o:e]
    trailer = int.from_bytes(ent[-3:], 'little')
    if 1 <= idx <= 20:                       # BGM: huffman → MIDI
        out = huff_decode(ent, trailer)
        open(f'{OUT}/midi/bgm_{idx:02d}.mid','wb').write(out)
        summary.append((idx,'MIDI(SMF)',len(ent),len(out)))
    elif 21 <= idx <= 44:                    # SE: raw s16 PCM
        import wave
        n = len(ent)//2
        w = wave.open(f'{OUT}/wave/se_{idx:02d}.wav','wb')
        w.setnchannels(1); w.setsampwidth(2); w.setframerate(11025)
        w.writeframes(ent[:n*2]); w.close()
        summary.append((idx,'PCM s16 mono',len(ent),n))
    elif idx <= 76:
        name = ent[4:4+ent[0] if ent[0]<64 else 4+16].split(b'\0')[0]
        try: nm = ent[4:20].split(b'\0')[0].decode('ascii','ignore')
        except: nm = ''
        open(f'{OUT}/script/res_{idx:02d}.bin','wb').write(ent)
        summary.append((idx,f'script {nm}',len(ent),0))
    elif idx <= 89:
        open(f'{OUT}/data/res_{idx:02d}.bin','wb').write(ent)
        summary.append((idx,'game data table',len(ent),0))
    elif idx <= 97:
        open(f'{OUT}/replay/res_{idx:02d}.bin','wb').write(ent)
        summary.append((idx,'demo replay GRPD099F',len(ent),0))
    else:
        summary.append((idx,'build date marker',len(ent),0))

# --- GGD → PNG ---
from PIL import Image
def load_pal(p):
    d = open(p,'rb').read()
    return [tuple(d[54+i*4:56+i*4]) + (d[58+i*4],) for i in range(256)]
pal = load_pal(f'{GAME}/bmcm/bm_pal.bmp')
pald = load_pal(f'{GAME}/bmcm/bm_pald.bmp')
pals = load_pal(f'{GAME}/bmcm/bm_pals.bmp')
count = 0
for root,_,files in os.walk(GAME):
    for fn in files:
        if fn.endswith('.ggd'):
            p = os.path.join(root,fn)
            d = open(p,'rb').read()
            if d[:4] != b'GGPD': continue
            w,h = struct.unpack('<HH', d[8:12])
            stride = (w+3)&~3
            img = Image.frombytes('P',(w,h),bytes()) if False else Image.new('P',(w,h))
            flat = b''.join(d[12+y*stride:12+y*stride+w] for y in range(h))
            img.frombytes(flat)
            img.putpalette([c for rgb in pal for c in rgb[:3]])
            rel = os.path.relpath(p, GAME).replace('/','_').replace('.ggd','')
            img.save(f'{OUT}/ggd_png/{rel}.png'); count += 1
print(f"GGD converted: {count}")
for s in summary: print(s)
