"""#77 背景图层动画流 (exe 0x459D60 还原).

流格式: [u16 count][count x 9字节记录]... 每帧消费一组.
9 字节记录 (rec[0..8]):
  rect1.x = rec[0] | ((rec[8]&0x0C)<<6)    10bit
  rect1.y = rec[1] | ((rec[8]&0x10)<<4)     9bit
  rect1.w = rec[2] | ((rec[8]&0x60)<<3)    10bit
  rect1.h = rec[3] | ((rec[8]&0x80)<<1)     9bit
  rect2   = (rec[4], rec[5], rec[6], rec[7]) 8bit each
  layer   = (rec[8]&3)+7                     -> 图层 7..10
语义: 对图层管理器 (0x4AA7B0) 执行 Blt(rect1, rect2, flags) — 矩形滚动/搬运.
"""
from __future__ import annotations

import struct


class LayerAnimator:
    def __init__(self, data: bytes):
        self.data = data
        self.cursor = 0
        self.finished = False
        self.stats = {"blits": 0, "frames": 0, "layers": {}}

    def _read_records(self):
        d = self.data
        if self.cursor + 2 > len(d):
            self.finished = True
            return []
        (count,) = struct.unpack("<H", d[self.cursor : self.cursor + 2])
        self.cursor += 2
        recs = []
        for i in range(count):
            if self.cursor + 9 > len(d):
                self.finished = True
                break
            r = d[self.cursor : self.cursor + 9]
            b8 = r[8]
            recs.append({
                "x": r[0] | ((b8 & 0x0C) << 6),
                "y": r[1] | ((b8 & 0x10) << 4),
                "w": r[2] | ((b8 & 0x60) << 3),
                "h": r[3] | ((b8 & 0x80) << 1),
                "sx": r[4], "sy": r[5], "sw": r[6], "sh": r[7],
                "layer": (b8 & 3) + 7,
            })
            self.cursor += 9
        return recs

    def tick(self, on_blit):
        """每帧: 解析一组记录并回调 on_blit(rec)."""
        if self.finished:
            return False
        recs = self._read_records()
        self.stats["frames"] += 1
        for r in recs:
            self.stats["blits"] += 1
            self.stats["layers"][r["layer"]] = self.stats["layers"].get(r["layer"], 0) + 1
            on_blit(r)
        if self.cursor >= len(self.data):
            self.finished = True
        return True
