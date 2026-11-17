#!/usr/bin/env python3
"""GROD106A encoder — 与 grod_decode.py / exe 0x45B6E0 解码器逐字节兼容。

容器：'GROD' '106A' u32 N | [checksum(1)] [marker(1)] [tokens...]
- checksum = XOR_{i=0..N-1}(src[i] * i & 0xFF)（0x45B37A..0x45B389 倒序累计）
- marker   = 源里出现次数最多的字节值（0x45B3CE..0x45B402 直方图取大）
- token：literal byte | marker(escape→下一字节为 literal marker) |
         marker + count（dist=count>>3 ∈0..31、len=(count&7)*4+4 ∈{4,8,…,32}）
- 尾部：o < N 且输入耗尽 → 剩余以 literal 补齐（0x45B3F1..0x45B3F9 的 while）

编码用贪心匹配（窗口 31、长度 4..32），不追求与 exe 逐字节同输出——
容器契约（解码器可还原）一致即可，exe 的 0x45B6E0 与 grod_decode.py 均可读。
"""
import struct

WINDOW = 31          # dist = count>>3 ∈ 0..31（0 = 补零）
MIN_LEN = 4
MAX_LEN = 32         # len = (count&7)*4+4


def _match(src, pos, n):
    """在 pos 找最长匹配：返回 (dist, length) 或 None。dist 0 = 补零运行。"""
    best = None
    max_len = min(MAX_LEN, n - pos)
    if max_len < MIN_LEN:
        return None
    # dist 0：全零运行。count = (0<<3)|((l-4)>>2) —— l=4 时 count=0 与 escape
    # 冲突（解码器 count==0 = literal marker），故 dist 0 最短 8（count=1）。
    if src[pos] == 0:
        l = 0
        while l < max_len and src[pos + l] == 0:
            l += 1
        if l >= 8:
            best = (0, l)
    # dist 1..31
    for d in range(1, WINDOW + 1):
        if pos - d < 0:
            break
        l = 0
        while l < max_len and src[pos + l] == src[pos - d + l]:
            l += 1
        if l >= MIN_LEN and (best is None or l > best[1]):
            best = (d, l)
            if l >= max_len:
                break
    return best


def grod_encode(src: bytes) -> bytes:
    n = len(src)
    chk = 0
    for i, v in enumerate(src):
        chk ^= (v * (i & 0xFF)) & 0xFF
    # marker = 直方图最大（同值取先见者；0x45B3F1 的扫描顺序 = 字节值 0..255）
    hist = [0] * 256
    for v in src:
        hist[v] += 1
    marker = max(range(256), key=lambda k: (hist[k], -k))
    out = bytearray()
    out += b'GROD'
    out += b'106A'
    out += struct.pack('<I', n)
    out.append(chk)
    out.append(marker)
    i = 0
    o = 0
    while i < n and o < n - 4:                   # 与解码器主循环同界（含 o < N-4）
        m = _match(src, i, n)
        if m is None:
            if src[i] == marker:
                out.append(marker)       # escape：marker+0x00 = literal marker
                out.append(0)
            else:
                out.append(src[i])
            i += 1
            o += 1
            continue
        d, l = m
        count = (d << 3) | ((l - 4) >> 2)
        if count == 0:                       # dist0+len4 → 不可编码，按 literal
            if src[i] == marker:
                out.append(marker)
                out.append(0)
            else:
                out.append(src[i])
            i += 1
            o += 1
            continue
        out.append(marker)
        out.append(count & 0xFF)
        i += l
        o += l
    # 解码器尾部：`while o < N: out[o] = src[i]`——把剩余输出字节以 literal
    # 原样附在 token 流尾，使尾部 raw 拷贝还原正确
    out += src[o:]
    return bytes(out)


def grod_decode(data: bytes) -> bytes:
    """与 grod_decode.py 同逻辑（本地自包含，供回放装载用）。"""
    assert data[:4] == b'GROD' and data[4:8] == b'106A', "bad magic"
    n = struct.unpack('<I', data[8:12])[0]
    src = data[12:]
    marker = src[1]
    out = bytearray(n)
    i, o = 2, 0
    while i < len(src) and o < n:
        al = src[i]
        if al == marker:
            count = src[i + 1]
            i += 2
            if count == 0:
                out[o] = marker
                o += 1
            else:
                dist = count >> 3
                length = (count & 7) * 4 + 4
                spos = o - dist
                for k in range(length):
                    if o >= n:
                        break
                    out[o] = out[spos + k]
                    o += 1
        else:
            out[o] = al
            o += 1
            i += 1
    return bytes(out)


if __name__ == '__main__':
    import sys
    sys.path.insert(0, '/home/yuhuan/geki106_re')
    from grod_decode import grod_decode as ref_dec
    for sample in (b'', b'\x00' * 100, bytes(range(256)) * 4,
                   b'GROD106A' * 50, bytes(216000)):
        enc = grod_encode(sample)
        dec = grod_decode(enc)
        dec2 = ref_dec(enc)
        assert dec == sample and dec2 == sample, f"roundtrip fail len={len(sample)}"
        print(f"len {len(sample):7d} → {len(enc):7d}  ✓")
    print("grod_encode roundtrip OK")
