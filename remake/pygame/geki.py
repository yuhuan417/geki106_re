#!/usr/bin/env python3
"""撃破伝 v1.06 —— 页机 + 页1-3 复刻（pygame 实现）

设计原则：**和原作一样，用一块 640x480 的 8bpp 索引画布当"屏幕"**，不做任何引擎级
渲染/循环介入。所有常量与控制流来自 geki106.exe 反汇编（地址见注释与 ANALYSIS.md §16）：

    页机        0x459360（消息 0x46A 的 handler，while(页号!=0) 重复分发）
    页1         0x451E00 进场 / 0x451F80 每帧 / 0x452010 收尾
    页2         0x452A00 / 0x452EB0 / 0x452F80
    页3         0x4520A0 / 0x452220 / 0x4522A0
    层          0x44C560 重建 / 0x44CE60 SetColorKey / 0x44C640+0x44BE10 装载
    帧节奏      0x4AB570 (0x45A3F0 timeBegin / 0x45A490 SetPeriod / 0x45A510 Kill)
    输入        0x4AB454 (0x44E660 Poll / 0x44EB60 BuildRecord)
    键命令      0x458FD0（键码表 0x498A60、命令映射 0x459280）
    全屏填充    0x44D200
    文字        0x44D330（高度=arg&0xFF，字色/底色=调色板索引）
    显示节点    0x45A0E0 / 0x45A690 / 0x45A170（层+源矩形 → 目标点，BltFast）

数据表（层尺寸、页2 时间轴、页1 换色/文字表、调色板、字符串表）由
remake/build_pages_data.py 从 exe 提取到 remake/pages_data.json。
"""
from __future__ import annotations

import json
import math
import os
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path

import numpy as np

HERE = Path(__file__).resolve().parent
REMAKE = HERE.parent
GAME_DIR = Path(os.environ.get("GEKI_DIR", REMAKE.parent.parent / "geki106"))
DATA_PATH = REMAKE / "pages_data.json"

W, H = 640, 480

# 行序/朝向开关（见 §16.9）：
#   FLIP_GGD_ROWS = True  → GGD 自底向上（DIB）解析，即装载时行倒序
#   FLIP_SCREEN  = True  → 整屏纵向翻转（若原作的表面是自底向上，则等价）
FLIP_GGD_ROWS = os.environ.get("GEKI_NO_FLIP_GGD", "") == ""
FLIP_SCREEN = os.environ.get("GEKI_FLIP_SCREEN", "") != ""
# 显示表渲染：0x430840 = `add ecx,4; jmp 0x45A170`（按队列渲染显示表）。
# 页1-3 的 step 0x458F80 每帧调它两次：0x458F8F(4CC 之后) 与 0x458FAD(4FC 之后)。
DRAW_DISPLAY_NODES = os.environ.get("GEKI_PANELS", "1") != "0"
# ini 的 OPMOVIE / CHANGEDISPLAY（0x458AE0 = CWinApp::GetProfileInt，读 geki.ini/注册表）：
#   页1 t=290 时只看 [ent+0x24]=bitindex(0x4AB5B0,0x2000)==OPMOVIE：非0 → 生成 0x6F000002（Now Loading 预载屏）
#   页2 进场看 (CHANGEDISPLAY==0 || OPMOVIE!=0) 决定是否挂资源77记录流
# 原目录没有 geki.ini ⇒ 取默认 0（与 MFC GetProfileInt 无该项时返回默认值一致）
OPMOVIE = os.environ.get("GEKI_OPMOVIE", "0") != "0"
CHANGEDISPLAY = os.environ.get("GEKI_CHANGEDISPLAY", "0") != "0"

# 0x4AB5C0 旗标（已实证）
FLAG_LAYER_FAIL = 0x2
FLAG_ESC = 0x200
FLAG_CLICK = 0x10000
SYS_FLAG_LEAVE = 0x10          # 0x56CC84 的 0x10：离开本页（0x45AFF0 命中即让亮度渐变实体自尽并复位）
FLAG_SELECT = 0x200000
FLAG_EXIT = 0x40

# 键码（0x498A60 归一后的值）
KEY_ESC, KEY_PAUSE, KEY_SPACE, KEY_PRINTSCR, KEY_TAB = 1, 2, 3, 4, 5

# 键码-1 → cmd（0x459280 表，0x458FD0 内 map 查表）
CMD_MAP = [0, 11, 11, 1, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 2,
           3, 4, 5, 6, 7, 8, 9, 10, 11, 1, 1]


# ---------------------------------------------------------------------------- 数据
def load_data() -> dict:
    with open(DATA_PATH, encoding="utf-8") as f:
        return json.load(f)


# 0x44CAA0 载入调色板时先做的一次"亮度/对比"变换（0x44CCBD 的 0x44B790 调用）：
#   a2 = field(0xFE000000)*4 - 0xC8、a3 = field(0x1FC0000)*4 - 0xC8
#   （0x45AFC0 返回的是 `([App+4] & mask) >> 位号` 的**字段值**，不是位号）
# 字段 = 50 时 a2 = a3 = 0 ⇒ 恒等变换。这两个字段由 GRPD/配置数据写进 [App+4]，
# 游戏内没有对应 ini 键（ini 只有 OPMOVIE/CHANGEDISPLAY/SND/MOUSE1-2/JOY1-3/...），
# 出厂默认下为恒等，故复刻版取 (0,0)；若将来解出配置来源再填。
PAL_ADJUST = (0, 0)


def load_palette() -> np.ndarray:
    """bmcm/bm_pal.bmp → (256,3) uint8；与 pages_data.json 的 palette 一致，优先读 bmp。"""
    p = GAME_DIR / "bmcm" / "bm_pal.bmp"
    if p.exists():
        from PIL import Image
        im = Image.open(p)
        pal = np.array(im.getpalette()[: 256 * 3], dtype=np.uint8).reshape(256, 3)
        return pal
    data = load_data()
    return np.array(data["palette"], dtype=np.uint8)


def ggd_load(path: Path, flip_rows: bool | None = None) -> tuple[int, int, np.ndarray]:
    """GGD → (w, h, uint8[y,x])。格式见 ANALYSIS §5（'GGPD'，行 4 字节对齐）。

    **行序**：GGD 内的像素是 DIB 自底向上存放（文件第 0 行 = 画面最下一行），
    0x44BE10 写入表面时按行倒序落盘（§6.4 "行序倒序"）。用户实测确认：不倒序则整块图形上下颠倒。
    """
    d = path.read_bytes()
    if d[:4] != b"GGPD":
        raise ValueError(f"not GGD: {path}")
    w = int.from_bytes(d[8:10], "little")
    h = int.from_bytes(d[10:12], "little")
    stride = (w + 3) & ~3
    raw = np.frombuffer(d[12:12 + stride * h], dtype=np.uint8)
    buf = raw.reshape(h, stride)[:, :w].copy()
    if FLIP_GGD_ROWS if flip_rows is None else flip_rows:
        buf = np.ascontiguousarray(buf[::-1])
    return w, h, buf


# ---------------------------------------------------------------------------- 画布
def fade_palette(pal: np.ndarray, a: int, b: int) -> np.ndarray:
    """0x44B790(mgr, dst, src, a=[mgr+0xC94], b=[mgr+0xC98])：

        v = clamp(src + ((src - 0x80) * b >> 6), 0, 255)
        dst = clamp(v + a, 0, 255)

    原码 `ecx = 0xFF` ⇒ **只处理 0..254 共 255 项**（第 255 项原样保留，循环体里
    `lodsb×3 / stosb×3 / inc esi / inc edi` 跳过每项的 4 号字节）。b=0 时就是纯亮度 a
    （a=-256 → 全黑，a=0 → 原色）。调用方 `add esp,0x28` 自己清栈（0x44B790 是裸 `ret`）。
    """
    out = pal.copy()
    v = pal[:255].astype(np.int32)
    v = v + (((v - 128) * int(b)) >> 6)
    np.clip(v, 0, 255, out=v)
    v = v + int(a)
    np.clip(v, 0, 255, out=v)
    out[:255] = v.astype(np.uint8)
    return out


class Canvas:
    """640x480 8bpp 索引画布（= 原作的离屏表面 + 主表面合成结果）。"""

    def __init__(self, w: int = W, h: int = H):
        self.w, self.h = w, h
        self.buf = np.zeros((h, w), dtype=np.uint8)

    def fill(self, idx: int) -> None:
        """0x44D200：全屏 640x480 色填充。"""
        self.buf[:, :] = idx & 0xFF

    def fill_rect(self, rect, idx: int) -> None:
        """0x44D290(mgr, &rect, 0, color)：COLORFILL 到主表面（屏幕）的矩形。"""
        l, t, r, b = (int(v) for v in rect)
        l = max(0, min(l, self.w)); r = max(0, min(r, self.w))
        t = max(0, min(t, self.h)); b = max(0, min(b, self.h))
        if r > l and b > t:
            self.buf[t:b, l:r] = idx & 0xFF

    def blit(self, src: np.ndarray, src_rect: tuple[int, int, int, int],
             dst: tuple[int, int], key: int | None = None) -> None:
        """0x45A170：裁剪后把层的子矩形贴到 (x,y)（BltFast 语义，无色键）。"""
        x0, y0, x1, y1 = src_rect
        sh, sw = src.shape
        x0 = max(0, min(int(x0), sw)); x1 = max(0, min(int(x1), sw))
        y0 = max(0, min(int(y0), sh)); y1 = max(0, min(int(y1), sh))
        if x1 <= x0 or y1 <= y0:
            return
        dx, dy = int(dst[0]), int(dst[1])
        bw, bh = x1 - x0, y1 - y0
        # 目标裁剪
        if dx < 0:
            x0 += -dx; bw += dx; dx = 0
        if dy < 0:
            y0 += -dy; bh += dy; dy = 0
        bw = min(bw, self.w - dx); bh = min(bh, self.h - dy)
        if bw <= 0 or bh <= 0:
            return
        patch = src[y0:y0 + bh, x0:x0 + bw]
        if key is None:
            self.buf[dy:dy + bh, dx:dx + bw] = patch
        else:
            region = self.buf[dy:dy + bh, dx:dx + bw]
            m = patch != (key & 0xFF)
            region[m] = patch[m]

    def blit_scaled(self, src: np.ndarray, src_rect: tuple[int, int, int, int],
                    dst_rect: tuple[int, int, int, int], key: int | None = None) -> None:
        """0x44D0B0 → IDirectDrawSurface::Blt(主表面 ← 层, flags 0x1008000=KEYSRC|WAIT)。

        源矩形与目标矩形尺寸不同 ⇒ DirectDraw 会拉伸；这里用最近邻采样复刻。
        """
        sl, st, sr, sb = (int(v) for v in src_rect)
        dl, dt, dr, db = (int(v) for v in dst_rect)
        sh, sw = src.shape
        sl = max(0, min(sl, sw)); sr = max(0, min(sr, sw))
        st = max(0, min(st, sh)); sb = max(0, min(sb, sh))
        sw2, sh2 = sr - sl, sb - st
        dw, dh = dr - dl, db - dt
        if sw2 <= 0 or sh2 <= 0 or dw <= 0 or dh <= 0:
            return
        # 目标裁剪
        cx0, cy0 = max(0, -dl), max(0, -dt)
        cx1, cy1 = min(dw, self.w - dl), min(dh, self.h - dt)
        if cx1 <= cx0 or cy1 <= cy0:
            return
        xs = (np.arange(cx0, cx1) * sw2 // dw).clip(0, sw2 - 1)
        ys = (np.arange(cy0, cy1) * sh2 // dh).clip(0, sh2 - 1)
        patch = src[st:sb, sl:sr][np.ix_(ys, xs)]
        region = self.buf[dt + cy0:dt + cy1, dl + cx0:dl + cx1]
        if key is None:
            region[:, :] = patch
        else:
            m = patch != (key & 0xFF)
            region[m] = patch[m]

    def to_rgb(self, palette: np.ndarray) -> np.ndarray:
        """索引 → RGB（显示格式转换 0x44C350 的等价物）。"""
        return palette[self.buf]


# ---------------------------------------------------------------------------- 层
class Layer:
    __slots__ = ("w", "h", "buf", "dirty", "ckey", "bind_id", "off")

    def __init__(self, w: int, h: int):
        self.w, self.h = w, h
        self.buf = np.zeros((h, w), dtype=np.uint8)
        self.dirty = False      # 是否有内容（决定是否参与合成）
        self.ckey = -1          # 0x44CE60 SetColorKey 的色号
        self.bind_id = -1       # 0x44C640 已绑定 GGD id
        self.off = (0, 0)


class Layers:
    """0x4AA7B0 里的层表（14 个 IDirectDrawSurface）。"""

    def __init__(self, data: dict):
        self.data = data
        self.strings: dict[str, str] = data["string_table"]
        self.tab: dict[int, Layer] = {n: Layer(W, H) for n in range(14)}

    def create(self, n: int, w: int, h: int) -> bool:
        """0x44C560：销毁并重建层表面。"""
        if w <= 0 or h <= 0:
            return False
        self.tab[n] = Layer(int(w), int(h))
        return True

    def color_key(self, n: int, idx: int) -> None:
        """0x44CE60：SetColorKey(DDCKEY_SRCBLT, idx) —— 设色键，不是清屏。"""
        if n in self.tab:
            self.tab[n].ckey = idx & 0xFF

    def ggd_path(self, ggd_id: int) -> Path | None:
        name = self.strings.get(str(ggd_id))
        if not name:
            return None
        rel = name.replace("\\", "/")
        p = GAME_DIR / rel
        return p if p.exists() else None

    def load(self, n: int, ggd_id: int) -> bool:
        """0x44BE10：LoadStringA(id) → 打开 GGD → 逐像素写入层（整幅，左上角）。"""
        lay = self.tab.get(n)
        p = self.ggd_path(ggd_id)
        if lay is None or p is None:
            return False
        w, h, px = ggd_load(p)
        h = min(h, lay.h); w = min(w, lay.w)
        lay.buf[0:h, 0:w] = px[0:h, 0:w]
        lay.bind_id = ggd_id          # 记录“这一层当前装的是哪个 GGD”
        lay.dirty = True
        return True

    def copy(self, src: int, dst: int, rect=(0, 0, W, H), pt=(0, 0)) -> None:
        """0x44D060(src,dst,pt,rect)：把层 src 的 rect 拷到层 dst 的 pt（Blt，flags 0x10）。"""
        a, b = self.tab.get(src), self.tab.get(dst)
        if a is None or b is None:
            return
        x0, y0, x1, y1 = (max(0, rect[0]), max(0, rect[1]),
                          min(a.w, rect[2]), min(a.h, rect[3]))
        w, h = x1 - x0, y1 - y0
        px, py = int(pt[0]), int(pt[1])
        if w <= 0 or h <= 0 or px >= b.w or py >= b.h:
            return
        w = min(w, b.w - px); h = min(h, b.h - py)
        b.buf[py:py + h, px:px + w] = a.buf[y0:y0 + h, x0:x0 + w]
        b.dirty = True

    def snapshot(self, n: int, canvas: "Canvas") -> None:
        """0x44D190：BltFast(层n ← 主表面, srcRect=(0,0,640,480), 无键)。"""
        lay = self.tab.get(n)
        if lay is None:
            return
        w = min(W, lay.w); h = min(H, lay.h)
        lay.buf[0:h, 0:w] = canvas.buf[0:h, 0:w]
        lay.dirty = True

    def bind(self, n: int, ggd_id: int) -> bool:
        """0x44C640：与已绑定 id 不同才重新装载。"""
        lay = self.tab.get(n)
        if lay is not None and lay.bind_id == ggd_id:
            return True
        ok = self.load(n, ggd_id)
        if ok:
            lay.bind_id = ggd_id
        return ok


class P2Stream:
    """0x459D60：资源 77 的"记录流播放器"（页2 背景动画）。

    每帧：`count = i16[cursor]`，随后 `count` 条 9 字节记录：
        b0..b3 (+b8 高位)  = 目标矩形 10bit（left, top, right, bottom）
        b4..b7             = 源矩形 8bit（层内坐标）
        b8 bits0-1         = 层号 7..10，bits2-3/4/5-6/7 = 目标矩形高位
    0x459D60 每次调用处理一帧；`cursor >= end` 时返回 0（播完）。
    """

    def __init__(self, path: Path):
        self.data = path.read_bytes()
        self.pos = 0
        self.frames = 0

    @property
    def size(self) -> int:
        return len(self.data)

    def advance(self):
        if self.pos >= len(self.data):
            return None
        cnt = int.from_bytes(self.data[self.pos:self.pos + 2], "little", signed=True)
        self.pos += 2
        if cnt <= 0:
            return None
        recs = []
        d = self.data
        for _ in range(cnt):
            r = d[self.pos:self.pos + 9]
            self.pos += 9
            if len(r) < 9:
                return None
            b8 = r[8]
            dl = r[0] | (((b8 >> 2) & 3) << 8)
            dt = r[1] | (((b8 >> 4) & 1) << 8)
            dr = r[2] | (((b8 >> 5) & 3) << 8)
            db = r[3] | (((b8 >> 7) & 1) << 8)
            recs.append((7 + (b8 & 3), (r[4], r[5], r[6], r[7]), (dl, dt, dr, db)))
        self.frames += 1
        return recs


# ---------------------------------------------------------------------------- 文字
class TextRenderer:
    """0x44D330：CreateFontIndirectA(高度=arg&0xFF, 宽=一半) + SetTextColor(调色板[arg])
    + SetBkColor(调色板[arg]) + TextOutA。原作字体是 ＭＳ明朝，这里用 Noto Serif CJK
    （报告形状必然随字体而异，见 ANALYSIS §6.3）。"""

    def __init__(self, palette: np.ndarray, font_path: str | None = None):
        import pygame
        self.palette = palette
        self._cache: dict[tuple[str, int], np.ndarray] = {}
        if font_path is None:
            for cand in ("/usr/share/fonts/opentype/noto/NotoSerifCJK-Regular.ttc",
                         str(REMAKE / "godot/assets/fonts/NotoSansCJK-Regular.ttc")):
                if Path(cand).exists():
                    font_path = cand
                    break
        self.font_path = font_path
        self._pygame = pygame
        try:
            pygame.font.init()
        except Exception:
            pass
        self._fonts: dict[int, "pygame.font.Font"] = {}

    def _font(self, height: int):
        height = max(6, int(height))
        if height not in self._fonts:
            self._fonts[height] = self._pygame.font.Font(self.font_path, height)
            # 关闭抗锯齿渲染（GDI TextOut 是 1bit 掩码）
        return self._fonts[height]

    def mask(self, s: str, height: int) -> np.ndarray:
        """返回 (cell_h=height, width) 的 1bit 掩码，**不做纵向重采样**（避免模糊）。

        GDI：lfHeight = 字符单元高（decimal），lfWidth = 高/2 ⇒ 每个字符占 高/2 宽的格子，
        字形在格子内排布。这里：pygame 在 size=11 时 get_height()=16（正好等于 lfHeight），
        逐字符渲染后把每格**按最近邻压到 高/2 宽**再拼接 ⇒ 与原作一样是 1bit、锐利、
        且字距 = 高/2（页1 的英文行实测对齐屏幕坐标 32/147/262/377/492 的间隔）。
        """
        key = (s, height)
        m = self._cache.get(key)
        if m is None:
            cw = max(2, int(height) // 2)                 # lfWidth = height/2
            # GDI lfHeight 是单元高；Noto 下 size≈0.7*lfHeight 时 get_height()≈单元高
            font = self._font(max(6, int(round(height * 0.70))))
            cells = []
            for ch in s:
                surf = font.render(ch, False, (255, 255, 255))
                arr = self._pygame.surfarray.array3d(surf)[:, :, 0].T   # (h, w)
                if arr.shape[0] < height:                  # 补齐到单元高（顶部对齐）
                    arr = np.vstack([arr, np.zeros((height - arr.shape[0], arr.shape[1]), arr.dtype)])
                elif arr.shape[0] > height:
                    arr = arr[:height, :]
                w = arr.shape[1]
                if w <= 0:
                    arr = np.zeros((height, 1), np.uint8); w = 1
                # 水平最近邻压/拉到 cw（GDI 的 lfWidth 挤压）
                idx = (np.arange(cw) * w // cw).clip(0, w - 1)
                cells.append(arr[:, idx])
            m = np.hstack(cells) if cells else np.zeros((height, 0), np.uint8)
            m = np.ascontiguousarray(m > 127)          # bool 掩码（1bit）
        return m

    def draw(self, canvas: Canvas, s: str, x: int, y: int, height: int,
             fg: int, bg: int | None = None) -> None:
        m = self.mask(s, height)
        mh, mw = m.shape
        x = int(x); y = int(y)
        # 目标裁剪
        sx0 = max(0, -x); sy0 = max(0, -y)
        dx0 = max(0, x);  dy0 = max(0, y)
        ww = min(mw - sx0, canvas.w - dx0)
        hh = min(mh - sy0, canvas.h - dy0)
        if ww <= 0 or hh <= 0:
            return
        sub = m[sy0:sy0 + hh, sx0:sx0 + ww]
        dst = canvas.buf[dy0:dy0 + hh, dx0:dx0 + ww]
        if bg is not None:
            dst[:, :] = bg & 0xFF
        dst[sub] = fg & 0xFF


# ---------------------------------------------------------------------------- 输入
@dataclass
class Record:
    """0x4AB594 的 0x18 字节帧记录（本复刻用到的字段）。"""
    b0: bool = False   # +0 按钮0 按住
    b1: bool = False   # +1 按钮1 按住
    e0: bool = False   # +2 按钮0 按下沿
    e1: bool = False   # +3 按钮1 按下沿
    r0: bool = False   # +4 按钮0 释放沿
    r1: bool = False   # +5 按钮1 释放沿
    key: int = 0       # +6 键码（0x498A60 归一）
    x: int = 0         # +8
    y: int = 0         # +0xC
    dx: int = 0        # +0x10
    dy: int = 0        # +0x14


class Input:
    """0x4AB454 输入管理器（0x44E660 轮询 / 0x44EB60 建记录）。预设 0x17：键盘 4px/帧、
    鼠标限幅 5px/帧、边界 (0,0)-(448,400)。"""

    SPEED = 4
    RADIUS = 5

    def __init__(self):
        self.rec = Record()
        self.x, self.y = 320, 240
        self.base = (0, 0)
        self._prev = (False, False)

    def build(self, keys, mouse_buttons, mouse_delta=(0, 0), keycode: int = 0) -> Record:
        b0 = bool(mouse_buttons[0]) or keys.get("shot", False)
        b1 = bool(mouse_buttons[2]) or keys.get("lock", False)
        r = Record()
        r.b0, r.b1 = b0, b1
        r.e0 = b0 and not self._prev[0]
        r.e1 = b1 and not self._prev[1]
        r.r0 = (not b0) and self._prev[0]
        r.r1 = (not b1) and self._prev[1]
        self._prev = (b0, b1)
        dx = dy = 0
        if keys.get("left"): dx -= self.SPEED
        if keys.get("right"): dx += self.SPEED
        if keys.get("up"): dy -= self.SPEED
        if keys.get("down"): dy += self.SPEED
        mdx, mdy = mouse_delta
        if mdx or mdy:
            # 0x44E9xx：鼠标相对位移限幅到 radius
            n = math.hypot(mdx, mdy)
            if n > self.RADIUS:
                mdx = int(round(mdx / n * self.RADIUS))
                mdy = int(round(mdy / n * self.RADIUS))
            dx += mdx; dy += mdy
        self.x = max(0, min(448, self.x + dx))
        self.y = max(0, min(400, self.y + dy))
        r.x, r.y, r.dx, r.dy = self.x, self.y, dx, dy
        r.key = keycode
        self.rec = r
        return r


# ---------------------------------------------------------------------------- 帧节奏
class Timer:
    """0x4AB570：0x45A490 SetPeriod（0→60）、0x45A3B0 每 tick 累加、0x45A5A0 判定。"""

    def __init__(self, period: int = 60):
        self.period = period or 60
        self.consumed = 0
        self.catchup = 0
        self._t0 = time.perf_counter()
        self._frozen_at: float | None = None

    def set_period(self, period: int) -> bool:
        """0x45A490：period==0 → 0x3C。"""
        self.period = int(period) or 60
        self.consumed = 0
        self._t0 = time.perf_counter()
        self._frozen_at = None          # 0x45A490 重建定时器
        return True

    def kill(self) -> bool:
        """0x45A510。"""
        self._frozen_at = time.perf_counter()
        return True

    def target(self) -> int:
        """已过 tick 数（定时器累加的 [+0x14] 等价物）。"""
        t = self._frozen_at if self._frozen_at is not None else time.perf_counter()
        # 0x45A490: period = 每秒 tick 数（60），tick 间隔 = 1000/period ms
        return int((t - self._t0) * self.period)

    def due(self) -> bool:
        """0x45A5A0 返回 1 的等价：还有积压 tick 就放行一帧。"""
        if self.target() > self.consumed:
            self.consumed += 1
            return True
        self.catchup += 1
        return False


# ---------------------------------------------------------------------------- 旗标
class Flags:
    """0x4AB5C0 位图（0x45AF10 清 / 0x45AF30 置位 / 0x45AFF0 测试）。"""

    def __init__(self):
        self.bits = 0

    def clear(self) -> None:
        self.bits = 0

    def set(self, mask: int) -> None:
        self.bits |= mask

    def test(self, mask: int) -> bool:
        return (self.bits & mask) == 0 if mask == 0 else (self.bits & mask) != 0

    def is_empty(self) -> bool:
        return self.bits == 0

    def consume(self, mask: int) -> bool:
        """0x45AFF0(obj, mask)：test-and-clear，返回原值是否置位。"""
        hit = bool(self.bits & mask)
        self.bits &= ~mask
        return hit

    def lowest(self) -> int:
        """0x45B070：最低置位，无置位返回 0。"""
        b = self.bits
        if b == 0:
            return 0
        return b & (-b)


# ---------------------------------------------------------------------------- UI 实体
@dataclass
class DisplayNode:
    """0x45A0E0 分配的 0x28B 显示节点（+0 源层、+4..+0x10 源矩形、+0x14/+0x18 目标、+0x1C 激活）。"""
    layer: int
    rect: list[int]          # [left, top, right, bottom]
    dst: list[int]           # [x, y]
    active: bool = True

    def grow(self, dl: int, dt: int, dr: int, db: int) -> None:
        """0x45A790：矩形逐分量加减。"""
        self.rect[0] += dl; self.rect[1] += dt
        self.rect[2] += dr; self.rect[3] += db


@dataclass
class UiEntity:
    type_word: int
    t: int = 0
    a3: int = 0
    a4: int = 0
    alive: bool = True
    beh: str = ""
    p: dict = field(default_factory=dict)
    disp: DisplayNode | None = None
    bgc: int = -1
    aux: int = 0
    texts: list = field(default_factory=list)


# ---------------------------------------------------------------------------- 页机
class Pages:
    """0x459360 页机 + 页1/2/3（页4 由原 main.py 的 game 逻辑接手）。"""

    def __init__(self, data: dict, palette: np.ndarray, text: TextRenderer,
                 canvas: Canvas, inp: Input, timer: Timer, flags: Flags):
        self.data = data
        self.pal = palette
        self.p2_stream: P2Stream | None = None
        self.sky_color = -1
        # 色带引擎（0x4CD484 / 0x4561D0 push、0x4562A0 draw、0x456270+0x4560C0 advance）
        self.band_table: list[list[int]] = [[0xB4, 0x200]]   # 0x456180 初始：一条 {color=0xB4,h=0x200}
        self.band_count = 1
        self.band_start = 0
        self.band_scroll = 0
        self.band_speed = 0
        self.band_frames = 0
        # 0x44D740 的调色板操作状态：bit0=亮度(a) bit1=… bit2=…；[mgr+0xC90] 帧计数
        self.pal_flags = 0
        self.fade_a = 0
        self.fade_b = 0
        self.pal_frame = 0
        self.pal_now = palette
        self.text = text
        self.canvas = canvas
        self.inp = inp
        self.timer = timer
        self.flags = flags
        self.sysf = Flags()          # 0x56CC84：系统旗标（0x10 = 离开本页）
        self.layers = Layers(data)
        self.page = 0
        self.ui52c: list[UiEntity] = []
        self.ui4fc: list[UiEntity] = []
        self.ui46c: list[UiEntity] = []
        self.screen_fill = -1
        self.trace: list[str] = []
        self.p1_done: set[int] = set()
        self.p2_loaded: dict[int, int] = {}
        self.p2_sky: set[int] = set()
        self.quit = False

    # ---- 日志
    def log(self, s: str) -> None:
        self.trace.append(s)
        if len(self.trace) > 400:
            self.trace.pop(0)

    # ---- 页机 -------------------------------------------------------------
    def start(self, page: int) -> None:
        self.page = page
        self.enter()

    def enter(self) -> None:
        """0x459360：每次分发前清 0x4AB5CC/0x4AB5C0。"""
        self.flags.clear()
        self.screen_fill = -1
        if self.page == 1:
            self.page1_enter()
        elif self.page == 2:
            self.page2_enter()
        elif self.page == 3:
            self.page3_enter()
        elif self.page == 4:
            self.log("page 4 = 游戏本体（由 main.py 的 game 循环接手）")
            self.quit = True
        else:
            self.log(f"page {self.page} 未实现 → quit")
            self.page = 0

    def step(self) -> bool:
        if self.page == 1:
            return self.page1_step()
        if self.page == 2:
            return self.page2_step()
        if self.page == 3:
            return self.page3_step()
        return False

    def finish(self) -> None:
        self.sysf.set(SYS_FLAG_LEAVE)                     # 离页：亮度渐变实体自尽并复位亮度
        if self.page == 1:
            self.page1_finish()
        elif self.page == 2:
            self.page2_finish()
        elif self.page == 3:
            self.page3_finish()

    def advance(self) -> None:
        """一帧：step 返回 0 → finish（页号切换）→ 页机重新分发。"""
        if self.page == 0 or self.quit:
            return
        if not self.step():
            self.finish()
            if self.page != 0 and not self.quit:
                self.enter()

    # ---- 页1（0x451E00 / 0x451F80 / 0x452010）------------------------------
    def page1_enter(self) -> None:
        self.layers.bind(13, 9)                # 0x44C640(mgr,13,9) → bm_tilg
        self.layers.create(2, W, H)            # 0x44C560(2,640,480)
        self.layers.color_key(13, 0)           # 0x44CE60(13,0)
        self.inp.x, self.inp.y = 0, 0          # 0x44E620(预设0,0,0,0) + 0x44EDA0(0)
        # 0x458D60 → 0x4301F0：场景重置会清空**全部**队列（4CC/4FC/52C），
        # 漏清 4CC 会让页1 的擦入节点（层13=bm_tilg）残留到页2 前几帧 ⇒ 玩家看到的"小红撃"闪现。
        self.ui46c.clear(); self.ui4fc.clear(); self.ui52c.clear()
        self.p1_done.clear()
        # a3 = bitindex(0x4AB5B0, 0x2000) 即 ini 的 OPMOVIE 开关（0x43E09A 分支用）
        self.spawn(self.ui52c, 0x6F000001, a3=1 if OPMOVIE else 0)
        self.timer.set_period(0)                   # SetPeriod(0) → 60fps
        self.log("page1.enter")

    def page1_step(self) -> bool:
        # 0x451F80：2×0x458B80 → 0x458CB0 → 0x44EB60 → SetCursorPos → 0x458FD0
        #           → 0x4562A0 → 0x458F80
        self.tick_ui(self.ui52c)
        self.tick_ui(self.ui4fc)
        self.ui4fc = [e for e in self.ui4fc if e.alive]
        self.key_command(self.inp.rec.key)
        self.draw()
        return self.flags.is_empty()

    def page1_finish(self) -> None:
        # 0x452010：KillTimer → 0x44CEE0 → r=0x45B070(flags)
        self.timer.kill()
        r = self.flags.lowest()
        self.screen_fill = -1
        if r in (0x100, 0x200):
            self.page = 0
        elif r == FLAG_CLICK:
            self.page = 2
        else:
            self.page = 0xFF
        self.log(f"page1.finish flags=0x{self.flags.bits:X} -> page {self.page}")

    # ---- 页2（0x452A00 / 0x452EB0 / 0x452F80）------------------------------
    # ---- 色带引擎 0x456180/0x4561D0/0x4562A0/0x456240/0x456270 -------------------
    def band_push(self, table: list[list[int]], count: int, start: int, scroll: int) -> None:
        """0x4561D0(seq, table, count, startIdx, scroll)：整表替换（表按 4 字节项 {u8 color,u8 pad,i16 h}）。"""
        self.band_table = [[int(c) & 0xFF, int(h)] for (c, h) in table][:count]
        self.band_count = len(self.band_table)
        self.band_start = int(start)
        self.band_scroll = int(scroll)

    def band_draw(self) -> None:
        """0x4562A0(seq)：从 y=0 起逐条铺色带，高 = 条目高 - 累计滚动，超出 480 截断。"""
        y = 0
        i = self.band_start
        while y < H:
            if i >= self.band_count:
                break
            color, h = self.band_table[i]
            hh = h - self.band_scroll
            if y + hh > H:
                hh = H - y
            if hh > 0:
                self.canvas.fill_rect((0, y, W, y + hh), color)
            y += hh
            i += 1
            if hh <= 0:
                break

    def band_advance(self) -> None:
        """0x456270(seq) + 0x4560C0(seq, delta)：按 speed 推进滚动量，超过当前带高则吃掉该带。"""
        if self.band_frames > 0:
            self.band_frames -= 1
            self.band_scroll += self.band_speed
            while self.band_start < self.band_count and \
                    self.band_scroll >= self.band_table[self.band_start][1]:
                self.band_scroll -= self.band_table[self.band_start][1]
                self.band_start += 1

    def band_scroll_for(self, speed: int, frames: int) -> None:
        """0x456240(seq, speed, frames)。"""
        self.band_speed = int(speed)
        self.band_frames = int(frames)

    def page2_enter(self) -> None:
        p2 = self.data["page2"]
        # 0x452A4E..0x452BCC：13 次 0x44C560（层尺寸见 PAGE2_LAYER_SIZES）
        for (n, w, h) in p2.get("layer_sizes") or p2["layers"]:
            self.layers.create(int(n), int(w), int(h))
        # 0x452BD4..0x452CD0：逐层 0x44CE60(layer, 0)
        for n in p2["clear"]:
            self.layers.color_key(int(n), 0)
        # 0x452A07..0x452A41：0x44CDF0(mgr, 1, …) → 载 bm_pal + 设淡入参数
        if "palettes" in self.data:
            self.pal = np.array(self.data["palettes"]["1"], dtype=np.uint8)
            self.pal_now = self.pal
        self.inp.x, self.inp.y = 0, 0
        self.screen_fill = -1                       # 页2 的底色来自色带，不是 0x44D200
        # 0x458D60 → 0x456180：色带表重置为单条 {0xB4, 0x200}
        self.band_table = [[0xB4, 0x200]]
        self.band_count, self.band_start, self.band_scroll = 1, 0, 0
        self.band_speed = self.band_frames = 0
        self.sky_color = 0xB4
        # 0x458D60 → 0x4301F0：场景重置会清空**全部**队列（4CC/4FC/52C），
        # 漏清 4CC 会让页1 的擦入节点（层13=bm_tilg）残留到页2 前几帧 ⇒ 玩家看到的"小红撃"闪现。
        self.ui46c.clear(); self.ui4fc.clear(); self.ui52c.clear()
        self.p2_loaded.clear(); self.p2_sky.clear()
        # 0x452D3E：0x459C90(0x56B95C, cfg) —— CHANGEDISPLAY==0 或 OPMOVIE!=0 时挂上资源 77 记录流
        self.p2_stream = None
        p = REMAKE / "pygame" / str(p2.get("stream", "assets/p2_stream.bin"))
        # 0x452D15..0x452D44：ok1=GetProfileInt("CHANGEDISPLAY"), ok2=GetProfileInt("OPMOVIE")
        #   eax = (ok1==0) ? 1 : (ok2==0 ? 0 : ok2)  → 非 0 才挂记录流
        armed = (not CHANGEDISPLAY) or OPMOVIE
        if armed and p.exists():
            self.p2_stream = P2Stream(p)
        self.spawn(self.ui52c, int(p2["spawn_type"]))
        self.timer.set_period(int(p2["timer_period"]))    # 0x452D94 SetPeriod(0x3E=62)
        self.log(f"page2.enter（记录流={'开' if self.p2_stream else '关'}）")

    def begin_frame(self) -> None:
        """0x44D740 的 ±255 整屏填充（0x44D81B..0x44D83D），在帧首、绘制之前。"""
        if self.fade_a == -255:
            self.canvas.fill(0xB4)      # 0x44D200(0xB4)
        elif self.fade_a == 255:
            self.canvas.fill(0xD9)      # 0x44D200(0xD9)

    def page2_step(self) -> bool:
        # 0x452EB0：0x458B80(一次) → 0x458CB0(present) → 0x44EB60 → SetCursorPos(320,240)
        self.inp.x, self.inp.y = 320, 240
        # [0x4AB596]/[0x4AB597]（左右键按下沿）→ flags |= 0x10000 → 收尾去页3
        if self.inp.rec.e0 or self.inp.rec.e1:
            self.flags.set(FLAG_CLICK)
            self.log(f"page2 click → flags=0x{self.flags.bits:X}")
        self.key_command(self.inp.rec.key)
        self.begin_frame()
        # 0x4562A0：色带（栈式，只铺带子，不整屏清！—— mosaic 像素靠这个保留下来）
        self.band_draw()
        # 0x445A30：0x6F000008 时间轴（层装载 / 快照拷贝 / 记录流）
        self.tick_ui(self.ui52c)
        self.draw()                                 # 4CC/4FC 显示表（页2 无节点）
        self.band_advance()                         # 0x456270 帧末推进色带
        return self.flags.is_empty()

    def page2_finish(self) -> None:
        # 0x452F80：0x44FDD0(MIDI) → 0x45A510(计时器) → 0x44D200(0xB4)+present ×2
        #          → 0x44CEE0 → 0x45B070 → 0x100/0x200→页0、0x10000→页3、else→页0xFF
        # 0x452F83 0x44FDD0(0x4AB514) = 停 DirectMusic（复刻版无音频，仅记日志）
        # 0x452FA7 0x44D200(0xB4) → 0x458CB0(present) → 0x44D200(0xB4) → 0x458CB0(present)
        self.log("page2.finish：停 MIDI（0x44FDD0）+ 两次整屏黑 + present")
        self.timer.kill()
        self.canvas.fill(0xB4)
        self.present()
        self.canvas.fill(0xB4)
        self.present()
        self.p2_stream = None
        r = self.flags.lowest()
        if r in (0x100, 0x200):
            self.page = 0
        elif r == FLAG_CLICK:
            self.page = 3
        else:
            self.page = 0xFF
        self.log(f"page2.finish flags=0x{self.flags.bits:X} → page {self.page}")

    # ---- 页3（0x4520A0 / 0x452220 / 0x4522A0）------------------------------
    def page3_enter(self) -> None:
        # 0x4520A0：0x44CDF0(mgr,2,…) 载 bmcm\bm_pald.bmp（暗色调色板）
        if "palettes" in self.data and "2" in self.data["palettes"]:
            self.pal = np.array(self.data["palettes"]["2"], dtype=np.uint8)
            self.pal_now = self.pal
        self.layers.bind(13, 10)                   # 0x44C640(13,10) → bmetc\bm_mn.ggd
        self.layers.color_key(13, 0)               # 0x44CE60(13,0)
        self.inp.x, self.inp.y = 0, 0
        self.screen_fill = -1
        # 0x458D60 → 0x4301F0：场景重置会清空**全部**队列（4CC/4FC/52C），
        # 漏清 4CC 会让页1 的擦入节点（层13=bm_tilg）残留到页2 前几帧 ⇒ 玩家看到的"小红撃"闪现。
        self.ui46c.clear(); self.ui4fc.clear(); self.ui52c.clear()
        self.spawn(self.ui4fc, 0x5F000005)         # 菜单总控（行为 0x4255D0 状态机）
        self.timer.set_period(0)
        self.log("page3.enter（层13←bm_mn，调色板 bm_pald，脚本链 0x24 预载）")

    def page3_step(self) -> bool:
        # 0x452220：0x458B80 → 0x458CB0 → 0x44EB60 → SetCursorPos → 0x458FD0 → 0x4562A0 → 0x458F80
        self.inp.x, self.inp.y = 320, 240
        if self.inp.rec.e0 or self.inp.rec.e1:
            self.flags.set(FLAG_CLICK)
        self.key_command(self.inp.rec.key)
        self.tick_ui(self.ui52c)          # 0x445A30：菜单总控/淡入/OPMOVIE 驱动
        self.tick_ui(self.ui4fc)          # 0x44B0D0：8 个菜单行实体
        self.ui52c = [e for e in self.ui52c if e.alive]
        self.ui4fc = [e for e in self.ui4fc if e.alive]
        self.draw()
        return self.flags.is_empty()

    def page3_finish(self) -> None:
        """0x4522A0：0x45A510 → 0x44D200(0xB4)+present ×2 → 0x44CEE0 → 0x45B070 映射

            0x100/0x200 → 页0（退出）    0x20000 → 页13
            0x40000 → 页5               0x80000 → 页6
            0x100000 → 页0              0x2000000 → 页14
            其它 → 页0xFF（错误退出）
        """
        self.timer.kill()
        self.canvas.fill(0xB4)
        self.canvas.fill(0xB4)
        r = self.flags.lowest()
        if r in (0x100, 0x200, 0x100000):
            self.page = 0
        elif r == 0x20000:
            self.page = 0x0D
        elif r == 0x40000:
            self.page = 5
        elif r == 0x80000:
            self.page = 6
        elif r == 0x2000000:
            self.page = 0x0E
        else:
            self.page = 0xFF
        self.log(f"page3.finish flags=0x{self.flags.bits:X} → page {self.page}")

    # ---- 键命令 0x458FD0 --------------------------------------------------
    def key_command(self, key: int) -> None:
        if key == 0:
            return
        k = (key & 0xFF) - 1
        if k < 0 or k > 0x1A:
            return
        cmd = CMD_MAP[k]
        if cmd == 0:                       # ESC
            self.flags.set(FLAG_ESC)
            self.log("cmd.esc")

    # ---- UI 实体（0x43D430 / 0x424410）------------------------------------
    def spawn(self, queue: list, type_word: int, x: int = 0, y: int = 0,
              a3: int = 0, a4: int = 0) -> UiEntity:
        e = UiEntity(type_word=type_word, a3=a3, a4=a4)
        hi = type_word & 0xFF000000
        if hi == 0x6F000000:
            idx = type_word - 0x6F000001
            if idx == 0:
                e.beh = "open_timeline"          # 0x43DE30
                e.bgc = 0xB4                     # ctor: [ent+0x20] = 0xB4
            elif idx == 1:
                e.beh = "opmovie"                # 0x43E1C0
            elif idx == 7:
                e.beh = "title_timeline"         # 0x43F560
                e.t = int(self.data["page2"]["timer_start"])
            else:
                e.beh = f"unimpl_6F_{idx}"
                self.log(f"ui 0x6F idx {idx} 未实现（§16.7）")
        elif hi == 0x61000000:
            # 跳表 0x4273C0，索引 = type + 0x9EFFFFFF：
            #   1→0x427450  5→0x427600(亮度渐变,-255→0 步进)  6→0x430520  7→0x427690  8→0x427710(快照环)
            if type_word == 0x61000005:
                e.beh = "flash"                 # 0x42730B + 行为 0x427600
                e.aux, e.a3, e.a4 = 0, 0, 0      # 由生成方按 desc 填 (-255/0/8 等)
            else:
                e.beh = "fade_in"
                self.log(f"ui 0x61 type 0x{type_word:X} 未实现")
        elif hi == 0x5F000000:
            idx = type_word - 0x5F000002
            if idx == 0:                          # 0x424434 / 0x4254F0
                e.beh = "wipe_v"
                e.disp = DisplayNode(0x0D, [0, 0, 0x211, 4], [0x37, 0x114])
            elif idx == 1:                        # 0x424491 / 0x425560
                edi = 0x14 if a3 else 0
                # ctor 0x424491：`[ent+0x1C]=0`（寿命计数器）、`[ent+0x20]=edi`（只用于算 rect）
                e.t = 0
                e.aux = edi
                e.beh = "wipe_h"
                # push 顺序（0x4244D2..0x4244D8）：a5=0xDC+edi→bottom, a4=0x5A→right,
                # a3=0xC8+edi→top, a2=0x46→left  ⇒ 源窗口 = 行 200+edi .. 220+edi（RAM 文本行）
                e.disp = DisplayNode(0x0D, [0x46, 0xC8 + edi, 0x5A, 0xDC + edi],
                                     [0x7D, 0x118 + edi])
            elif idx == 3:                        # 0x424513 / 0x4255D0（菜单总控）
                e.beh = "menu_root"
                # 0x424513 的显示节点：层13,(0,0,0x17F,0x7F)@(0x80,0x50) = bm_mn 上半（撃破伝logo）；
                # bm_mn 的下半 4 组菜单行由状态0 生成的 8 个 0x5F000006 以 9-slice 方式各自铺出。
                # 这里先用**整幅** bm_mn（0,0,384,296）@(128,80) 一次性显示，逐行实体待补。
                e.disp = DisplayNode(0x0D, [0, 0, 383, 295], [0x80, 0x50])
            else:
                e.beh = f"unimpl_5F_{idx}"
                self.log(f"ui 0x5F idx {idx} 未实现（§16.7）")
        else:
            e.beh = "default"                     # 0x43DA4F / 0x449AA7
        queue.append(e)
        self.log(f"spawn type=0x{type_word:X} beh={e.beh}")
        return e

    def tick_ui(self, queue: list) -> None:
        for e in queue:
            if not e.alive:
                continue
            if e.beh == "open_timeline":
                self._open_timeline(e)
            elif e.beh == "title_timeline":
                self._title_timeline(e)
            elif e.beh == "opmovie":
                self._opmovie(e)
            elif e.beh == "menu_root":
                self._menu_root(e)
            elif e.beh == "fade_in":
                self._fade_in(e)
            elif e.beh == "flash":
                self._flash(e)
            elif e.beh == "wipe_v":
                self._wipe_v(e)
            elif e.beh == "wipe_h":
                self._wipe_h(e)
            else:
                e.t += 1

    # 0x43DE30
    def _open_timeline(self, e: UiEntity) -> None:
        p1 = self.data["page1"]
        e.t += 1
        t = e.t
        # ① 3 条生成表
        for i, it in enumerate(p1["timeline"]):
            if t == int(it["frame"]) and i not in self.p1_done:
                self.p1_done.add(i)
                self.spawn(self.ui4fc, int(it["type"]), a3=int(it["flag"]))
                self.log(f"page1 timeline t={t} spawn 0x{int(it['type']):X}")
        # ② 换色表（0x44D200 全屏填充）
        for f in p1["fade"]:
            if t == int(f["t"]):
                e.bgc = int(f["color"])
                self.log(f"page1 fade t={t} → 0x{e.bgc:X}")
        if e.bgc >= 0:
            self.screen_fill = e.bgc
        # ③ 文字
        had = bool(e.texts)
        e.texts = []
        if t == int(p1["text_t"][0]) or (int(p1["text_t"][1]) <= t < int(p1["text_t"][2])):
            for tx in p1["texts"]:
                if tx["when"] == "bottom" or t != int(p1["text_t"][0]):
                    e.texts.append(tx)
            if not had:
                self.log(f"page1 text on t={t} ({len(e.texts)} 条)")
        elif had:
            self.log(f"page1 text off t={t}")
        # ④ 结束判定
        if self.inp.rec.e0 or t == int(p1["end_t"]):
            e.alive = False
            e.texts = []
            if e.a3:
                self.spawn(self.ui52c, 0x6F000002)      # OPMOVIE 分支
                self.log(f"page1 end → OPMOVIE (t={t})")
            else:
                self.flags.set(FLAG_CLICK)
                self.log(f"page1 end → flags |= 0x10000 (t={t})")

    # 0x43E1C0（0x6F000002，OPMOVIE / "Now Loading" 进度屏）
    def _opmovie(self, e: UiEntity) -> None:
        # 0x43E1C0：t<0xF4 时按 RT_STRING id=t 取文件名，只对 .ggd/.bmp 调 0x455090 载入；
        # 每帧用 0x44D200(0xB4) 清屏 + 0x44D330 打 "Now Loading...%3d/%3d"，t++；
        # t>0xF4 → flags |= 0x10000（进页2）。0x43DD20(t,0xF) 负责把这一帧的图形合成上屏
        # （0x45FE10：把描述子里的 GGD id 逐个绑到层 0..n-1，再把层0贴屏）。
        import re as _re
        if e.t < 0xF4:                                  # 0..243：按字符串 id = 帧号装载资源
            name = self.layers.strings.get(str(e.t), "")
            if name and _re.search(r"(?i)\.ggd$", name):
                ok = self.layers.load(13, e.t)          # 0x455090 装载（进层13，仅副作用）
                self.log(f"opmovie load id={e.t} {name} -> {ok}")
            elif name and _re.search(r"(?i)\.bmp$", name):
                self.log(f"opmovie palette id={e.t} {name}")   # 调色板类资源（bm_pal/pald/pals）
        # 0x44D200(mgr,0xB4) + "Now Loading...%3d/%3d"（0x44D330，h=0x20，fg=0xD9，bg=0xB4）
        self.screen_fill = 0xB4
        e.texts = [{"str": "Now Loading...%3d/%3d" % (e.t, 0xF4),
                    "x": 0, "y": 0, "h": 0x20, "fg": 0xD9}]
        e.t += 1
        if e.t > 0xF4:
            self.flags.set(FLAG_CLICK)
            self.log(f"opmovie done → flags=0x{self.flags.bits:X}")

    # 0x4254F0（0x5F000002）
    def _wipe_v(self, e: UiEntity) -> None:
        d = e.disp
        if d.rect[3] < 0xC7:
            d.grow(0, 0, 0, 5)
            d.dst[1] -= 5
        e.t += 1
        if e.t >= 0x78 or self.inp.rec.e0:
            e.alive = False
            d.active = False

    def _flash(self, e: UiEntity) -> None:
        """0x427600（0x61000005 的亮度渐变）：cur=[0x1C]、target=[0x20]、step=[0x24]。"""
        if self.sysf.consume(SYS_FLAG_LEAVE):         # 0x45AFF0(0x56CC84, 0x10)
            self.fade_to(0, 0)                        # 0x44DC10(mgr, 0, 0)
            e.alive = False
            return
        cur = e.aux + e.a4
        if e.a4 > 0 and cur > e.a3:
            cur = e.a3
        elif e.a4 < 0 and cur < e.a3:
            cur = e.a3
        e.aux = cur
        self.fade_to(cur, 0)                          # 0x44DC10(mgr, cur, 0)
        if cur == e.a3:
            e.alive = False

    # 0x427710（0x61000008 = 状态快照环驱动，页2 不用）
    def _fade_in(self, e: UiEntity) -> None:
        """0x427385 的初值 + 0x427710 的推进：

        [ent+0x1C] = (rec0+0xF)<<5, [ent+0x20]=rec0, [ent+0x24]=0xFFFFFF00(-256), [ent+0x28]=8；
        每帧 0x44DC10(mgr, 0, [ent+0x24]) → 下一偶数帧按 0x44B790 的公式把调色板调到该亮度；
        [ent+0x24] += 8，到 0 后停（0x42775C 重设步进/推进状态，本复刻到淡入完成即止）。
        """
        if e.t == 0:
            e.aux = -256                  # [ent+0x24] = 0xFFFFFF00
        self.fade_to(e.aux, 0)            # 0x44DC10(mgr, [ent+0x24], 0)
        e.t += 1
        if e.aux >= 0:                    # 已经到 0 → 本帧把 0 应用上去后结束
            e.alive = False
            return
        e.aux = min(0, e.aux + 8)         # [ent+0x28] = 8

    # 0x4255D0（0x5F000005 = 菜单总控）：状态机 [ent+0x1C] 0..4，跳表 0x42583C
    def _menu_root(self, e: UiEntity) -> None:
        """状态 0（0x4255FF）：生成 8 个 0x5F000006（菜单行）+ 1 个 0x61000005，然后推进状态。

        本实现先做到"状态 0 的生成"为止：8 行菜单 + 面板实体的行为尚未解码（§16.12）。
        """
        if e.t == 0:
            for i in range(8):
                self.spawn(self.ui4fc, 0x5F000006, a3=i)     # rec[0] = 行号 0..7
            # 0x425658：push 8 / push type / push 0 / push 0xFFFFFF01 / push &out
            #   ⇒ desc = {a2=-255, a3=0, type, a5=8} → 0x42730B: [0x1C]=-255、[0x20]=0、[0x24]=8
            f = self.spawn(self.ui52c, 0x61000005)
            f.beh = "flash"; f.aux = -255; f.a3 = 0; f.a4 = 8
            self.log("page3 菜单：8×0x5F000006 + 0x61000005 已生成（行为待补）")
            e.t = 1                    # 状态 0 之后由 0x5F000006 自行驱动（行为待补）
        # 总控实体的显示节点常驻（显示表与实体生命周期在引擎里是分开的）

    # 0x425560（0x5F000003）
    def _wipe_h(self, e: UiEntity) -> None:
        d = e.disp
        if d.rect[2] < 0x1FE:
            d.grow(0, 0, 0x14, 0)
        e.t += 1
        if e.t >= 0x46 or self.inp.rec.e0:
            e.alive = False
            d.active = False

    # 0x43F560（页2 时间轴）
    def _title_timeline(self, e: UiEntity) -> None:
        """0x43F560：页2 标题时间轴（计时器从 -420 起，62Hz）。

        helper — 0x44BE10 载层；0x44CDF0 换调色板；0x4561D0 推色带（页2 = 单条全屏色）；
        0x44D190/0x44D060 快照/拷贝；0x459D60 推进资源 77 的记录流并逐条缩放 Blt 到屏幕。
        """
        p2 = self.data["page2"]
        t = e.t
        e.t += 1

        # 调色板切换（0x43F81B：t==0 → id3 bm_pals；0x43F866：t==0x204 → id1 bm_pal）
        for (tt, sid) in p2.get("palette_switch", []):
            if t == int(tt):
                key = str(int(sid))
                if key in self.data.get("palettes", {}):
                    self.pal = np.array(self.data["palettes"][key], dtype=np.uint8)
                    self.pal_now = self.pal
                    self.log(f"page2 t={t} palette <- id{int(sid)}")

        # 层装载表（0x43F7F5 循环：state 命中即 0x44BE10(layer, ggd)）
        for ent in p2["layer_table"]:
            ts = int(ent["state"])
            if ts >= 0x8000:
                ts -= 0x10000
            if t == ts:
                self.layers.load(int(ent["layer"]), int(ent["ggd"]))
                self.log(f"page2 t={t} layer{int(ent['layer'])} <- ggd 0x{int(ent['ggd']):X}")

        # 天空色：0x43F962 起，表基址是 **[esp+0x28]**（0x43F8AE `mov word [esp+0x28],di` 是第 0 项的时间），
        # 循环 `mov ecx,edi(-420) / lea esi,[esp+0x28]` → 第 0 项就是 (t=-420, color=0xB4)，
        # 命中后用 `[esi+2]` 取该项颜色、`[esi+4]` 取下一项时间、esi+=4 ⇒ **正常对齐配对**。
        # 所以：t=-420 → 0xB4（黑），t=0 → 0xD9（白），t=0xAB → 0xB4 ……
        for (tt, c) in p2.get("sky", []):
            if t == int(tt):
                self.sky_color = int(c) & 0xFF
                # 0x43F974..0x43F996：0x4561D0(seq, &{0xD0,0x1F4}{color,0x1F4}, 2, 1, 0)
                self.band_push([[0xD0, 0x1F4], [self.sky_color, 0x1F4]], 2, 1, 0)
                self.log(f"page2 t={t} sky <- 0x{self.sky_color:02X}")

        # 明暗脉冲表（0x43FE77）：到期项 → 0x430400(&out, a, b, 0x61000005, c)
        #   0x61000005 的 init 是 **0x42730B**、行为 **0x427600**：
        #   [ent+0x1C]=a（起始亮度）、[ent+0x20]=b（目标亮度）、[ent+0x24]=c（步进，signed byte）
        for (tt, fa, fb, fc) in p2.get("flash", []):
            if t == int(tt):
                va, vb = int(fa), int(fb)
                if va >= 0x8000: va -= 0x10000
                if vb >= 0x8000: vb -= 0x10000
                vc = int(fc) & 0xFF
                if vc >= 0x80: vc -= 0x100
                e2 = self.spawn(self.ui52c, 0x61000005)
                e2.beh = "flash"
                e2.aux = va          # [0x1C]
                e2.a3 = vb           # [0x20]
                e2.a4 = vc           # [0x24]
                self.log(f"page2 t={t} 亮度 {va} → {vb} 每帧 {vc:+d}")

        # 0x456240(seq, speed, frames)：t=0x899 → (-40,12)、t=0xB93 → (-28,17)
        # （速度是**负**的：0x4560C0 里 `if ([seq+0xC] <= 0) return` ⇒ 滚动量变负时不吞带，
        #   而 0x4562A0 的 h=500-(-40)=540 被 480 截断 ⇒ 这两次调用在当前带表下是"无视觉变化"的，
        #   但按原码保留调用）
        for (tt, sp, fr) in ((0x899, -0x28, 0xC), (0xB93, -0x1C, 0x11)):
            if t == tt:
                self.band_scroll_for(sp, fr)
                self.log(f"page2 t={t} band scroll speed={sp} frames={fr}")

        # 快照/拷贝表（0x43FB03）
        for (tt, lay, flag) in p2.get("copy", []):
            if t != int(tt):
                continue
            lay = int(lay)
            if int(flag):
                self.layers.snapshot(lay, self.canvas)       # 0x44D190(layer)
                self.canvas.fill(0xB4)                       # 0x44D200(0xB4)
                self.log(f"page2 t={t} 屏幕 → layer{lay} + 填0xB4")
            else:
                self.layers.copy(lay, 6, (0, 0, W, H), (0, 0))  # 0x44D060(6,(0,0),layer,(0,0,640,480))
                self.log(f"page2 t={t} layer{lay} → layer6")

        # ★ 通知页（图3）：0x43FEE4..0x440040 在栈上建 18 字节记录表 {i16 t, u8 layer, dst(x,y), src(l,t,r,b)}
        #   记录 0：t=-58、layer=6、dst=(0x30,0x80)=(48,128)、src=(0,-,0x220=544,0x20=32)
        #   记录 1：dst=(48,176)、src t=0x20,b=0x40 ；记录 2：dst=(48,224) … 共 5 条（48 = h*1.5）
        #   0x4405EA 的循环按 `[rec-4]`(=t) 与计时器比较，命中即 0x44D010(mgr, layer=6, &src, &dst)
        #   ⇒ **bm_otit(544x160) 的 5 条 32px 条带被贴到 (48,128+48*i)** —— 正是玩家截图里的图3。
        if t >= -58:
            # 0x4405EA 的记录表循环**每帧**执行（按 t 过滤），所以通知页是持续显示的
            lay6 = self.layers.tab.get(6)
            if lay6 is not None:
                for i in range(5):
                    self.canvas.blit(lay6.buf, (0, i * 32, 544, i * 32 + 32),
                                     (48, 128 + i * 48), key=0)

        # 记录流窗口（0x43FA2D）：**只在 [start, end) 内**才 0x459D60 取一帧并贴屏；
        # 原实现只判了 end（`end >= t`），导致 t<-350 就开始播 ⇒ 页2 开头闪出记录里的一小块
        # 红色「撃」（玩家实测：图3 之前有一闪而过的小红字）。
        if self.p2_stream is not None:
            for (s0, s1) in p2.get("windows", []):
                if int(s0) <= t < int(s1):
                    recs = self.p2_stream.advance()
                    if recs is None:
                        self.flags.set(1)                    # 0x43FA47：流播完 → flags |= 1
                        self.log(f"page2 t={t} 记录流结束 → flags=0x{self.flags.bits:X}")
                    else:
                        for (lay, src, dst) in recs:
                            lay_tab = self.layers.tab.get(lay)
                            if lay_tab is not None:
                                self.canvas.blit_scaled(lay_tab.buf, src, dst, key=0)
                    break

    def present(self) -> None:
        """0x44D740 的调色板部分：`frame=++[0xC90]`，仅偶数帧且 [0xC8C]!=0 时执行。

        bit0 → 0x44B790(&pal, [0xC94], [0xC98])（亮度/对比度）；
        执行后 [0xC8C]=0（一次性）。窗口模式下随后 Blt(primary ← screen)。
        """
        self.pal_frame = (self.pal_frame + 1) & 0xFFFFFFFF
        if not (self.pal_frame & 1) and self.pal_flags:
            if self.pal_flags & 1:
                self.pal_now = fade_palette(self.pal, self.fade_a, self.fade_b)
            self.pal_flags = 0
        elif not (self.pal_frame & 1) and not self.pal_flags:
            self.pal_now = self.pal
        # ±255 的整屏填充在 0x44D740 里，而 0x44D740 是**帧首**（0x458CB0）调的，
        # 所以放在 present() 里会盖掉本帧的绘制 ⇒ 移到 begin_frame()。

    def fade_to(self, a: int, b: int = 0) -> None:
        """0x44DC10(mgr, a, b)：设亮度/对比度并置 bit0（下一偶数帧生效）。"""
        self.fade_a = int(a) & 0xFFFFFFFF if int(a) < 0 else int(a)
        self.fade_b = int(b)
        if self.fade_a >= 0x80000000:                   # 16bit 有符号回绕
            self.fade_a -= 0x100000000
        self.pal_flags |= 1

    def draw(self) -> None:
        """按 0x458F80 的实证帧序合成（页1-3）：

            0x4562A0 色带  →  0x430840(4CC 显示表)  →  0x44D200 填充 + 0x44D330 文字
            →  0x430840(4FC 显示表)

        注意：4FC 的显示节点（0x5F 擦入效果）是**最后**画的，会盖在文字上面。
        """
        c = self.canvas
        if DRAW_DISPLAY_NODES:
            self._render_queue(c, self.ui46c)
        if self.screen_fill >= 0:
            c.fill(self.screen_fill)
        for e in self.ui52c:
            for tx in e.texts:
                # 0x44D330(mgr, y, x, str, h, fg, bg)：bg = SetBkColor ⇒ 先铺一格底色
                self.text.draw(c, tx["str"], int(tx["x"]), int(tx["y"]),
                               int(tx["h"]), int(tx["fg"]), int(tx.get("bg", -1)) & 0xFF)
        if DRAW_DISPLAY_NODES:
            self._render_queue(c, self.ui4fc)
        self.present()          # 0x458CB0 → 0x44D740（调色板操作 + Blt）

    def _render_queue(self, c: "Canvas", q) -> None:
        """0x430840(`add ecx,4; jmp 0x45A170`)：按队列遍历显示表并 BltFast。"""
        for e in q:
            d = e.disp
            if d is None or not d.active:
                continue
            lay = self.layers.tab.get(int(d.layer))
            if lay is None:
                continue
            left, top, right, bottom = (int(v) for v in d.rect)
            if right > left and bottom > top:
                c.blit(lay.buf, (left, top, right, bottom), (int(d.dst[0]), int(d.dst[1])),
                       key=lay.ckey)

