"""撃破伝 (Gekihaden) v1.06 重制版 - 资源管线。

所有容器/压缩/图形格式均从 geki106.exe 逆向还原:
  - resource.rom (GROD106A): 自定义 LZ 容器 -> u24 偏移表 -> 98 个资源条目
  - MIDI 条目 (#1-20): 静态 Huffman 压缩的标准 SMF
  - 音效条目 (#21-44): 裸 s16le PCM 单声道
  - 图层条目 (#83-89): 字典 RLE 位流 -> 640x480 8bpp 关卡背景
  - *.ggd (GGPD106A): 8bpp 索引图 (行 4 字节对齐)
  - bmcm/bm_pal*.bmp: 256 色调色板 (借 8x8 BMP 存放)
"""
from __future__ import annotations

import os
import struct
import wave

GAME_DIR = os.environ.get("GEKI106_DIR", "/home/yuhuan/geki106")

# ---------------------------------------------------------------- GROD 容器


def inner_lz(src: bytes, n: int) -> bytes:
    """exe 0x45b6e0: [checksum][marker][tokens...]; marker+count -> 回引复制."""
    out = bytearray(n)
    i, o = 2, 0
    marker = src[1]
    while i < n and o < n - 4:
        al = src[i]
        if al == marker:
            count = src[i + 1]
            i += 2
            if count == 0:
                out[o] = marker
                o += 1
            else:
                spos = o - (count >> 3)
                for k in range((count & 7) * 4 + 4):
                    if o >= n:
                        break
                    out[o] = out[spos + k] if spos + k < n else 0
                    o += 1
        else:
            out[o] = al
            o += 1
            i += 1
    while o < n:
        out[o] = src[i]
        i += 1
        o += 1
    return bytes(out)


def grod_decode(data: bytes) -> bytes:
    assert data[:8] == b"GROD106A", "bad GROD header"
    n = struct.unpack("<I", data[8:12])[0]
    return inner_lz(data[12:], n)


class Resources:
    """resource.rom 的 98 个条目 (id 从 1 起, off(id)=u24@(id-1)*3)."""

    N_ENTRIES = 98

    def __init__(self, blob: bytes):
        self.blob = blob

    def _off(self, i: int) -> int:
        return int.from_bytes(self.blob[(i - 1) * 3 : (i - 1) * 3 + 3], "little")

    def get(self, idx: int) -> bytes:
        a = self._off(idx)
        b = self._off(idx + 1) if idx < self.N_ENTRIES else len(self.blob)
        return self.blob[a:b]

    def size(self, idx: int) -> int:
        return len(self.get(idx))

    @classmethod
    def load(cls, path: str | None = None) -> "Resources":
        path = path or os.path.join(GAME_DIR, "resource.rom")
        return cls(grod_decode(open(path, "rb").read()))


# ------------------------------------------------------------- Huffman MIDI

_HUFF_CODES = None
_HUFF_LENS = None


def _huff_tables():
    global _HUFF_CODES, _HUFF_LENS
    if _HUFF_CODES is None:
        import pefile

        pe = pefile.PE(os.path.join(GAME_DIR, "geki106.exe"))
        img = pe.get_memory_mapped_image()
        ib = pe.OPTIONAL_HEADER.ImageBase
        _HUFF_CODES = struct.unpack("<256H", img[0x498C48 - ib : 0x498C48 - ib + 512])
        _HUFF_LENS = img[0x498E48 - ib : 0x498E48 - ib + 256]
    return _HUFF_CODES, _HUFF_LENS


def huffman_decode(src: bytes, out_len: int) -> bytes:
    """exe 0x44f0b0: 静态 Huffman, LSB-first, 暴力码表匹配."""
    codes, lens = _huff_tables()
    by_len: dict[int, dict[int, int]] = {}
    for s in range(256):
        by_len.setdefault(lens[s] + 1, {})[codes[s]] = s
    out = bytearray()
    bits = 0
    end = len(src) - 3
    while len(out) < out_len:
        pos = bits >> 3
        window = int.from_bytes((src[pos : pos + 4] + b"\0\0\0\0")[:4], "little")
        window >>= bits & 7
        for k in range(1, 17):
            d = by_len.get(k)
            if d is not None:
                s = d.get(window & ((1 << k) - 1))
                if s is not None:
                    out.append(s)
                    bits += k
                    break
            else:
                continue
        else:
            raise ValueError(f"huffman: no code at bit {bits}")
    return bytes(out)


def load_midi(res: Resources, idx: int) -> bytes:
    ent = res.get(idx)
    out_len = int.from_bytes(ent[-3:], "little")
    return huffman_decode(ent, out_len)


# ------------------------------------------------------------- 关卡图层


def layer_decode(src: bytes, width: int = 640, height: int = 480) -> bytes:
    """exe 0x45bc00: 字典 RLE 位流 -> 640x480 8bpp.

    头 24 字节 = 字典 (dict[i] = src[i-8], i=8..30), token 流从 0x18 起.
    零跳 token 前进不写 (行缓冲已清零), 填充 token 写 run+1 字节并按 640 环绕.
    """
    out = bytearray(width * height)
    pos = 0x18
    x = 0
    rowptr = 0
    total = width * height
    while pos + 4 <= len(src) and rowptr + x < total:
        eax = int.from_bytes(src[pos : pos + 4], "little")
        al = eax & 0xFF
        val = None
        if (al & 0x18) == 0:  # 零跳
            n = ((eax >> 2) & 0x18) | (eax & 7)
            if al & 0x80:
                n |= (eax >> 3) & 0x1FE0
                pos += 2
            else:
                pos += 1
            x += n + 1
        else:
            d = al & 0x1F
            if d != 0x1F:  # 短 RLE
                val = src[d - 8]
                run = (eax >> 5) & 3
                if al & 0x80:
                    run |= (eax >> 6) & 0x3FC
                    pos += 2
                else:
                    pos += 1
                run += 1
            else:  # 长 token
                if (eax >> 8) & 3 == 0:
                    n = eax >> 5
                    pos += 4
                    x += n + 1
                else:
                    val = src[((eax >> 5) & 0x1F) - 8]
                    run = (eax >> 10) + 1
                    pos += 4
            if val is not None:
                while run > 0:
                    if x >= width:
                        x -= width
                        rowptr += width
                        if rowptr >= total:
                            return bytes(out)
                    take = min(run, width - x)
                    out[rowptr + x : rowptr + x + take] = bytes([val]) * take
                    x += take
                    run -= 1
        while x >= width:
            x -= width
            rowptr += width
            if rowptr >= total:
                break
    return bytes(out)


# ------------------------------------------------------------- GGD / 调色板


def load_palette(name: str = "bm_pal.bmp") -> list[tuple[int, int, int]]:
    d = open(os.path.join(GAME_DIR, "bmcm", name), "rb").read()
    pal = []
    for i in range(256):
        b, g, r, _ = d[54 + i * 4 : 58 + i * 4]
        pal.append((r, g, b))
    return pal


def ggd_load(path: str):
    """-> (w, h, bytes 8bpp). 行按 4 字节对齐 (实际文件均 4 的倍数宽)."""
    d = open(path, "rb").read()
    if d[:4] != b"GGPD":
        raise ValueError(f"not GGD: {path}")
    w, h = struct.unpack("<HH", d[8:12])
    stride = (w + 3) & ~3
    rows = [d[12 + y * stride : 12 + y * stride + w] for y in range(h)]
    return w, h, b"".join(rows)


# ----------------------------------------------------------------- 便捷


def load_stage_bg(res: Resources, stage: int, second_loop: bool = False) -> bytes:
    """stage 0-6 -> 资源 83+stage (一周) / 87+stage (二周, stage!=3)."""
    idx = 83 + stage + (4 if second_loop and stage != 3 else 0)
    return layer_decode(res.get(idx))


def dump_wav(path: str, pcm: bytes, rate: int = 11025) -> None:
    with wave.open(path, "wb") as w:
        w.setnchannels(1)
        w.setsampwidth(2)
        w.setframerate(rate)
        w.writeframes(pcm[: len(pcm) // 2 * 2])
