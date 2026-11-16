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

from page4 import Page4Mixin, P4_SE_SLOTS

W, H = 640, 480

_PORTRAIT: bytes | None = None      # res_79.bin（页13 全屏人像数据，懒加载）

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
# ini 键 OPMOVIE（0x4A48A4）：页2 进场 0x452D15 读它，**默认值 1**（0x452D17 `push 1` 是
# GetPrivateProfile 风格的默认值，0x458AF0/0x458AFC 取不到键就用它）。页1 进场 0x451EBE
# 用 0x45AFF0(0x4AB5B0, 0x2000) 的结果作为实体参数 [ent+0x24] → 非 0 才播开场动画。
OPMOVIE = os.environ.get("GEKI_OPMOVIE", "1") != "0"
CHANGEDISPLAY = os.environ.get("GEKI_CHANGEDISPLAY", "0") != "0"

# 0x4AB5C0 旗标（已实证）
FLAG_LAYER_FAIL = 0x2
FLAG_ESC = 0x200
FLAG_CLICK = 0x10000
SYS_FLAG_LEAVE = 0x10          # 0x56CC84 的 0x10：离开本页（0x45AFF0 命中即让亮度渐变实体自尽并复位）
FLAG_SELECT = 0x200000

# ---- 页5 排行榜（0x43E410）用的常量与助手（docs/p5_rank_notes.md）------------

def _rank_magic_div(v: int) -> int:
    """0x43E42B 的魔法除：`(v * 0x5397829D) >> 36`（有符号）= v // 49。"""
    v &= 0xFFFFFFFF
    if v & 0x80000000:
        v -= 0x100000000
    prod = v * 0x5397829D
    q = prod >> 36
    return q


def _adjust_magic_div(v: int) -> int:
    """0x444A4C 的魔法除：`(v * 0x4BDA12F7) >> 36`（有符号）——段高 ≈ 54.05px。"""
    v &= 0xFFFFFFFF
    if v & 0x80000000:
        v -= 0x100000000
    return (v * 0x4BDA12F7) >> 36


def _rank_cell_text(col: int, row: int) -> str:
    """RAM 字形格 (col,row)（格号 = row + 8*col）的复刻侧内容占位。

    exe 用 0x44D330 把标签预先写进层 0xD 的 24px 格（内容随页流程而定）；
    复刻侧尚未逐格追踪缓冲填充，先按格号给稳定占位（空白为主），不影响
    排行数据（得分/名字/日期直接来自 0x45C740 全项读）。"""
    return ""


def _rank_frame_text(i: int) -> str:
    """行框架格（rec1=0x10001 → 格 1 = (0,1)）的复刻侧占位：行号。"""
    return ""


RANK_HEADER_RECORDS = (          # 0x49875B 起 4B/项：(b0, b1, b2)；b3=下一项首字节非 0 继续
    (0x30, 0x1B, 0x30), (0x08, 0x06, 0x34), (0x10, 0x06, 0x38), (0x28, 0x38, 0x30),
    (0x50, 0x35, 0x34), (0x58, 0x3E, 0x34), (0x60, 0x47, 0x34), (0x68, 0x35, 0x38),
    (0x70, 0x3E, 0x38), (0x78, 0x47, 0x38), (0x80, 0x3E, 0x30), (0x82, 0x41, 0x30),
    (0x6A, 0x47, 0x30),
)
RANK_LABEL_RECORDS = (           # 0x4987AC 起字节表：格号（0 终止）
    (0x83, 1), (0x86, 1), (0x84, 1), (0x43, 1), (0x0C, 1), (0x5D, 0),
    (0x86, 1), (0x45, 0), (0x83, 1), (0x0C, 1),
)
RANK_ICON_RECORDS = (            # 0x498794 起 3B/项 ×8：(b0=x*4, b1=格号, b2=行)
    (0x02, 0x22, 0x02), (0x11, 0x42, 0x03), (0x2A, 0x22, 0x02), (0x36, 0x52, 0x04),
    (0x52, 0x32, 0x02), (0x61, 0x42, 0x03), (0x7A, 0x32, 0x02), (0x86, 0x52, 0x04),
)
FLAG_EXIT = 0x40

# 键码（0x498A60 归一后的值）
KEY_ESC, KEY_PAUSE, KEY_SPACE, KEY_PRINTSCR, KEY_TAB = 1, 2, 3, 4, 5

# 键码-1 → cmd（0x459280 表，0x458FD0 内 map 查表）
CMD_MAP = [0, 11, 11, 1, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 2,
           3, 4, 5, 6, 7, 8, 9, 10, 11, 1, 1]

# ---- 页3 菜单行 0x5F000006（ctor 0x424579）------------------------------------
# ctor 在栈帧里连排三张 8 项表（帧偏移依次 F+0x00 / F+0x20 / F+0x40）：
#   [esp+edi*4+0x10] @d=-0x200 → F+edi*4      = 源矩形 left
#   [esp+edi*4+0x44] @d=-0x214 → F+0x20+edi*4 = 目标 x
#   [esp+edi*4+0x54] @d=-0x204 → F+0x40+edi*4 = 源矩形 width（0x424643 `add edx,ecx` ⇒ right=left+w）
# 目标表第 0 项由 0x424655 `mov dword [esp+0x44],0x100`（d=-0x214）补写。
# 源矩形 = (left, 0x88+0x28*(row&3), left+w, 0xA7+0x28*(row&3))（高 0x1F=31）；
# 目标 = (dstx, 0x118+0x30*(row&3))，由 0x45A690(x,y) 经 eax:edx 返回、公共尾声 0x4250D4 写入节点。
MENU_ROW_LEFT = (0x000, 0x000, 0x000, 0x000, 0x0A0, 0x060, 0x060, 0x060)
MENU_ROW_DSTX = (0x100, 0x120, 0x120, 0x120, 0x0B0, 0x0B0, 0x0B0, 0x0B0)
MENU_ROW_WIDTH = (0x07F, 0x03F, 0x03F, 0x03F, 0x0DF, 0x11F, 0x0DF, 0x11F)
# 0x4257D8 状态 4 的 8 项旗标表（索引 = [ent+0x28] = 选中项 ebp）
MENU_EXIT_FLAGS = (0x2000000, 0x40000, 0x80000, 0x100000,
                   0x20000, 0x20000, 0x20000, 0x20000)


# 页13 的 20 个波形槽装载（0x450140(mgr, 槽, wave id)；0x454405..0x45458B 逐条，§16.110）
# 槽 0..0x13 ← wave 21..40（resource.rom 的 SE 区），是这一关的打击音色库
P13_SCRIPTS = ((0, 0x27), (1, 0x28), (2, 0x1C), (3, 0x1C), (4, 0x16), (5, 0x1E),
               (6, 0x22), (7, 0x23), (8, 0x20), (9, 0x21), (10, 0x1D), (11, 0x15),
               (12, 0x1B), (13, 0x17), (14, 0x26), (15, 0x25), (16, 0x19),
               (17, 0x1A), (18, 0x18), (19, 0x1F))
# 页13 的层装载表（0x4542E1..0x45433F：0x44C640(层, 资源)）
P13_LAYERS = ((0, 0x07), (1, 0x08), (2, 0x20), (3, 0xB3), (4, 0xB4))

# 0x498A88：输入预设记录表（14 字节/项，实测前 6 项）
P13_PRESET_TABLE = {
    0: bytes.fromhex('01 01 00 01 80 00 00 00 00 00 00 00 00 00'),
    1: bytes.fromhex('01 01 00 01 36 00 00 00 00 00 00 00 00 00'),
    2: bytes.fromhex('01 01 00 01 31 00 00 00 00 00 00 00 00 00'),
    3: bytes.fromhex('01 01 00 01 d6 00 00 00 00 00 00 00 00 00'),
    4: bytes.fromhex('01 01 00 01 64 00 00 00 00 00 00 00 00 00'),
    5: bytes.fromhex('01 01 00 01 80 00 00 00 00 00 00 00 00 00'),
}


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

    def free_all(self) -> None:
        """0x44CEE0：销毁全部 14 个层表面（循环 0..13 调层析构 0x401875(层,0)）。"""
        for n in range(14):
            self.tab[n] = Layer(W, H)

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
        """0x44BE10：LoadStringA(id) → 打开 GGD → 逐像素写入层（整幅，左上角）。

        资源 1/2（bm_pal/bm_pald.bmp，8×8 调色板预览条）是 BMP——0x44BE10 的
        LoadStringA 路径同样接受；复刻侧按 GGD 调色板索引读入（P 模式 8×8）。"""
        lay = self.tab.get(n)
        p = self.ggd_path(ggd_id)
        if lay is None or p is None:
            return False
        if str(p).lower().endswith(".bmp"):
            from PIL import Image as _I
            import numpy as _np
            im = _I.open(p).convert("P")
            w, h = im.size
            if lay.w < w or lay.h < h:
                self.tab[n] = Layer(max(w, lay.w), max(h, lay.h))
                lay = self.tab[n]
            lay.buf[0:h, 0:w] = _np.asarray(im, dtype=_np.uint8)
            lay.bind_id = ggd_id
            return True
        w, h, px = ggd_load(p)
        # 0x44C640 → 0x44BE10：层表面**按资源尺寸**建立，不是固定 640×480。
        # bm_cm48 是 240×528（页13 层0），旧版把它裁到 480 行 ⇒ y≥0x1E0 的精灵
        # （如 0x120D112B 的 (0x78,0x1F8,0x8F,0x20F)）永远贴不出来。
        # 0x44BE10 是"往**已存在的**层表面左上角写像素"，不改表面尺寸（0x44C560 建的那块）。
        # 只有层不存在、或现有表面装不下这张图时才按图尺寸重建。
        if lay is None or lay.w < w or lay.h < h:
            old_key = lay.ckey if lay is not None else -1
            lay = Layer(max(w, lay.w if lay else 0), max(h, lay.h if lay else 0))
            lay.ckey = old_key        # 0x44CE60 设的色键是**层**的属性，写像素不清键
            self.tab[n] = lay
        lay.buf[0:h, 0:w] = px
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

    def copy_key(self, src: int, dst: int, rect, pt, key: int = 0) -> None:
        """0x44D060 + 色键（页2 的 0x43F230 用：层4 图集 8×8 单元 → 层5/6）。

        DDraw 侧 flags=0x10，层色键由 0x44CE60 设为 0（§16.92.2）；这里把 ==key 的像素跳过。
        """
        a, b = self.tab.get(src), self.tab.get(dst)
        if a is None or b is None:
            return
        x0, y0 = max(0, int(rect[0])), max(0, int(rect[1]))
        x1, y1 = min(a.w, int(rect[2])), min(a.h, int(rect[3]))
        w, h = x1 - x0, y1 - y0
        px, py = int(pt[0]), int(pt[1])
        if w <= 0 or h <= 0 or px >= b.w or py >= b.h:
            return
        # 目标端裁剪（BltFast 的语义：超出部分直接丢）
        sx0, sy0 = max(0, -px), max(0, -py)
        w = min(w - sx0, b.w - max(0, px))
        h = min(h - sy0, b.h - max(0, py))
        if w <= 0 or h <= 0:
            return
        src_px = a.buf[y0 + sy0:y0 + sy0 + h, x0 + sx0:x0 + sx0 + w]
        m = src_px != (key & 0xFF)
        dst_px = b.buf[max(0, py):max(0, py) + h, max(0, px):max(0, px) + w]
        np.copyto(dst_px, src_px, where=m)
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
        import os as _os
        if _os.environ.get("P4_BINDLOG"):
            import traceback as _tb
            _st = _tb.extract_stack()[-4:-1]
            _chain = " < ".join(f"{f.filename.split('/')[-1]}:{f.lineno}" for f in _st)
            print(f"[bind] layer={n} id={ggd_id} <- {_chain}")
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


# ------------------------------------------------------- 页2 尾部表（§16.93，栈上表已抽出）
# ⑫ 4CC 精灵表：0x440B3A..0x440CCB 建于 [esp+0x64]，8 字节 {i16 t, i16 a, i16 b, i16 c}
#    si 继承值 = 0x78（0x44016F）、di = 0x6B8（0x440B35）
P2_PANELS = [
    (1376, 0, 0, 0x00), (1376, -656, 0, 0x00), (1376, 1205, 120, 0x10),
    (1548, -16, -4, 0x01), (1548, 640, -4, 0x01), (1548, -16, -500, 0x01),
    (1548, 640, -500, 0x01), (1548, -805, 754, 0x11),
    (1720, 0, -12, 0x02), (1720, 0, 484, 0x02), (1720, 200, -514, 0x12),
]
# ⑧ 静态文字页表：0x43FEE4..0x4405E1 建在 [esp+0x130]，18 字节 ×21 + 哨兵
#   {i16 t_start, i16 t_end, u8 layer, i16 dst.x, i16 dst.y, i16 src.l, i16 src.t,
#    i16 src.r, i16 src.b}；0x4405EA 的循环在 `t_start <= t <= t_end` 时用 0x44D010 贴屏
P2_PAGES = [
    (-420, -58, 6, 48, 128, 0, 0, 544, 32),
    (-420, -58, 6, 48, 176, 0, 32, 544, 64),
    (-420, -58, 6, 48, 224, 0, 64, 544, 96),
    (-420, -58, 6, 48, 272, 0, 96, 544, 128),
    (-420, -58, 6, 48, 320, 0, 128, 544, 160),
    (0, 170, 9, 200, 210, 0, 0, 240, 60),
    (172, 514, 6, 0, 0, 0, 0, 640, 480),
    (516, 1028, 9, 170, 210, 0, 60, 240, 120),
    (516, 1028, 9, 410, 210, 0, 120, 60, 180),
    (1204, 1374, 10, 110, 180, 0, 0, 120, 120),
    (1204, 1374, 10, 260, 180, 120, 0, 240, 120),
    (1204, 1374, 10, 410, 180, 0, 120, 120, 240),
    (1892, 2062, 3, 260, 150, 0, 0, 120, 60),
    (1892, 2062, 3, 170, 270, 0, 60, 120, 120),
    (1892, 2062, 3, 350, 270, 120, 60, 240, 120),
    (2580, 2750, 3, 260, 150, 120, 0, 240, 60),
    (2580, 2750, 3, 170, 270, 240, 60, 360, 120),
    (2580, 2750, 3, 350, 270, 360, 60, 480, 120),
    (3182, 3352, 3, 260, 150, 240, 0, 360, 60),
    (3182, 3352, 3, 170, 270, 0, 120, 120, 180),
    (3182, 3352, 3, 350, 270, 120, 120, 240, 180),
]
# ⑬ 计时器校正表：0x440D3F..0x440DD7 建于 [esp+0x28]，8 字节 {i16 t1, i16 t2, u32 ms}
P2_RESYNC = [(0x3B2, 0x404, 0x4127), (0x50A, 0x55E, 0x5715), (0x7BA, 0x80C, 0x828F),
             (0xA6A, 0xABE, 0xAE4B), (0xCC4, 0xD18, 0xD472), (0x10CC, 0x10F4, 0x11310)]


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
            # 0x44D330 请求的是系统字体「ＭＳ 明朝」：把 msmincho.ttc/.ttf 放到
            # remake/fonts/ 下就会优先使用（Windows 上也可直接给 C:/Windows/Fonts/msmincho.ttc），
            # 否则退回本机可用的明朝体替代（字形会随之不同——原作在这里本来就是机器相关的）。
            # 顺序 = 复刻 GDI 的字体映射结果：先找 ＭＳ明朝（原作直接请求的名字），
            # 找不到时 GDI 会用同 charset(128)+FIXED_PITCH 的日文字体顶替 ——
            # 在开发用的这台 Windows 上实测顶替成 **MS Gothic**（见 remake/tools/probe_gdi_font.ps1），
            # 所以这里第二顺位就是 msgothic.ttc；两者都没有才用 Noto 兜底。
            for cand in (str(REMAKE / "fonts/msmincho.ttc"),
                         str(REMAKE / "fonts/msmincho.ttf"),
                         str(REMAKE / "fonts/msgothic.ttc"),
                         "/mnt/c/Windows/Fonts/msmincho.ttc",
                         "/mnt/c/Windows/Fonts/msgothic.ttc",
                         "C:/Windows/Fonts/msmincho.ttc",
                         "C:/Windows/Fonts/msgothic.ttc",
                         "/usr/share/fonts/opentype/noto/NotoSerifCJK-Regular.ttc",
                         str(REMAKE / "fonts/NotoSansCJK-Regular.ttc")):
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

    # ＭＳ明朝（LOGFONT 0x4A4114 = SJIS "ＭＳ 明朝"）的垂直度量：unitsPerEm=2048、
    # tmAscent=1802、tmDescent=246 ⇒ **ascent+descent == em**。
    # 0x44D392 `mov [0x4A40F8], eax`（lfHeight = 参数&0xFF，正数）在 GDI 里表示
    # "字符单元高 = tmAscent+tmDescent" ⇒ **lfHeight 就是 em**，不是含行距的 get_height()。
    MSMINCHO_ASC, MSMINCHO_UPEM = 1802, 2048

    def mask(self, s: str, height: int) -> np.ndarray:
        """返回 (cell_h = height, width) 的 1bit 掩码。

        0x44D330 的字体参数（全部来自反汇编）：
            0x44D392  lfHeight = 参数 & 0xFF   → 字符单元高（对 ＭＳ明朝 = em）
            0x44D399  lfWidth  = lfHeight >> 1 → 每字格宽 = 高/2（GDI 会横向压到该宽度）
            0x4A40F8  LOGFONT：CharSet=128(SHIFTJIS)、Quality=0、Weight=0(DONTCARE)、
                     PitchAndFamily=1(FIXED_PITCH)、face = "ＭＳ 明朝"
        所以：em = lfHeight、单元高 = lfHeight、基线在 0.8799*lfHeight（1802/2048）、
        字距 = lfHeight/2，字形若比格宽则按最近邻横向压缩（原作就是这样把全角汉字压成半宽的）。
        """
        key = (s, height)
        m = self._cache.get(key)
        if m is None:
            h = max(6, int(height))
            cw = max(2, h // 2)                       # lfWidth = lfHeight>>1
            font = self._font(h)                      # em = lfHeight
            asc = font.get_ascent()
            base = int(round(h * self.MSMINCHO_ASC / self.MSMINCHO_UPEM))   # 基线下移量
            top = asc - base                          # 裁到"单元顶 = 基线-0.8799*em"
            cells = []
            for ch in s:
                surf = font.render(ch, False, (255, 255, 255))
                arr = self._pygame.surfarray.array3d(surf)[:, :, 0].T   # (h, w)
                if top >= 0:
                    arr = arr[top:top + h, :]
                else:                                  # 字形比单元还高：顶部补空行
                    arr = np.vstack([np.zeros((-top, arr.shape[1]), arr.dtype),
                                     arr[:h + top, :]])
                if arr.shape[0] < h:
                    arr = np.vstack([arr, np.zeros((h - arr.shape[0], arr.shape[1]), arr.dtype)])
                w = arr.shape[1]
                if w <= 0:
                    arr = np.zeros((h, 1), np.uint8); w = 1
                idx = (np.arange(cw) * w // cw).clip(0, w - 1)   # GDI lfWidth 挤压
                cells.append(arr[:, idx])
            m = np.hstack(cells) if cells else np.zeros((h, 0), np.uint8)
            m = np.ascontiguousarray(m > 127)          # 1bit 掩码（GDI TextOut 无抗锯齿）
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
    # [0x4AB454+0x4D]：键盘/摇杆位移总开关（0x44E7FC 处 `if (==0) 跳过整段 dx/dy 计算`）。
    # 真机实测（扫描码 0xD0 注入）：**按一次方向键正好走一项**，长按 0.5s 也只走一项
    # ⇒ 步进是"按下沿 × 一档"，不是连续位移（一格 = 0x80 = 128px，正好一条菜单带）。
    # ⚠ 这条只适用于**菜单页**（预设 0-6，定步=0 → dx=±1000 仅取符号、幅值=预设步长
    # 但按下沿语义是页1-3 实测的）。页4 战斗用**连续步进**（见 p4_cfg 管线）。
    kbd_move = True
    KBD_STEP = 0x80

    # 0x498A88 预设表（每项 14 字节，0x44E4A0 拷进 [mgr+0x4C..0x58]）：
    #   byte0=键盘使能 [mgr+0x4C]、byte1=鼠标使能 [+0x4D]、byte2=定步标志 [+0x4E]、
    #   word@+4=键盘步长 [+0x50]、byte@+6=鼠标移位 [+0x52]、word@+8=捕获半径 [+0x54]、
    #   word@+0xC→[mgr+0x58]：非 0 ⇒ 指针边界 (0x14,0x14)-(0x26C,0x1CC)，否则 (0,0)-(0x280,0x1E0)
    P4_PRESET_TABLE = (
        (1, 1, 0, 128, 0, 0, 0), (1, 1, 0, 54, 0, 0, 0), (1, 1, 0, 49, 0, 0, 0),
        (1, 1, 0, 214, 0, 0, 0), (1, 1, 0, 100, 0, 0, 0), (1, 1, 0, 128, 0, 0, 0),
        (1, 1, 0, 4, 0, 0, 0),
        (0, 1, 0, 0, 0, 32, 1), (0, 1, 0, 0, 2, 0, 0), (0, 1, 0, 0, 0, 28, 1),
        (0, 1, 0, 0, 0, 16, 1), (0, 1, 0, 0, 0, 40, 1), (0, 1, 0, 0, 0, 40, 1),
        (0, 1, 0, 0, 0, 32, 1), (0, 1, 0, 0, 0, 12, 1),
        (1, 0, 1, 5, 0, 0, 1), (1, 0, 1, 9, 0, 0, 0), (1, 0, 1, 4, 0, 0, 1),
        (1, 0, 1, 2, 0, 0, 1), (1, 0, 1, 6, 0, 0, 1), (1, 0, 1, 4, 0, 0, 1),
        (1, 0, 1, 4, 0, 0, 1), (1, 0, 1, 2, 0, 0, 1), (1, 1, 0, 4, 0, 5, 1),
    )

    def __init__(self):
        self.rec = Record()
        self.x, self.y = 320, 240
        self.base = (0, 0)
        self._prev = (False, False)
        self._prevdir = {}          # 方向键"上一帧是否按住"，用于取按下沿
        self.p4_cfg = None          # 页4 预设（set_preset4 装载）；None = 页1-3 菜单管线
        self.mouse_tx, self.mouse_ty = 320, 240   # 鼠标目标位置（0x44E82B 的追踪目标）
        # 調整页键位赋值（0x4AB5B8 の 0xF/0xF0/0xF00 字段，值 = DIK-0x20）：
        # 初值＝攻撃 C(14)、光撃 V(15)、捕獲 X(13)——与 0x498A88 预设/run.py 默认一致
        self.key_assign = {"attack": 14, "lock": 15, "capture": 13}

    # 調整页可赋值键范围：DIK 0x20..0x2F（值 = DIK-0x20）→ pygame 键码
    DIK20_TO_PYG = {
        0x00: 100,  # D
        0x01: 102,  # F
        0x02: 103,  # G
        0x03: 104,  # H
        0x04: 106,  # J
        0x05: 107,  # K
        0x06: 108,  # L
        0x07: 59,   # ;
        0x08: 39,   # '
        0x09: 96,   # `
        0x0A: 1073742049,  # LShift
        0x0B: 92,   # \
        0x0C: 122,  # Z
        0x0D: 120,  # X
        0x0E: 99,   # C
        0x0F: 118,  # V
    }

    def rebind_cfg(self, f3: int, f2: int, f1: int) -> None:
        """0x4018C0→0x44E360(f3, f2, f1)：調整页键位赋值反映射。
        0x4AB5B8 的 0xF/0xF0/0xF00 字段（值 0..15 = DIK 0x20..0x2F）⇒
        攻撃/光撃/捕獲入力键更新；Input.build 的 b0/b1 按赋值键读取
        （0x44E360 另写 [mgr+0x40/0x44/0x48]，复刻侧无读者暂不建）。"""
        self.key_assign = {"attack": f1 & 0xF, "lock": f2 & 0xF,
                           "capture": f3 & 0xF}

    def assigned_pygame_keys(self, kind: str) -> set:
        """赋值键值 → pygame 键码集合（DIK 0x20+值 → 0x498A60 归一族）。"""
        v = self.key_assign.get(kind, 0) & 0xF
        pg = self.DIK20_TO_PYG.get(v)
        return {pg} if pg is not None else set()

    def set_mode(self, mode: int) -> None:
        """0x44EDA0(0x4AB454, mode)：输入模式（0 = 游戏内光标模式）。"""
        self.mode = int(mode)

    def set_pos(self, x: int, y: int) -> None:
        """0x44E470：直接写虚拟指针 [mgr+0x14]/[mgr+0x18]（不钳位）。"""
        self.x, self.y = int(x), int(y)

    speed = 0          # 预设记录 byte4（[mgr+0x50]）；0 = 未设预设，用下面的默认值
    KBD_STEP = 0x80
    RADIUS = 5

    def set_preset4(self, fid: int, pos: tuple | None = None) -> None:
        """0x44E4A0/0x44E620：装载页4 预设（表 0x498A88+fid*14，14 字节）。

        fid 语义（0x446470 的 base+选机*2+方向）：7/9/11=鼠标模式 撃/凛/漢（dir1=+1）、
        15/17/19=键盘模式 撃/凛/漢；23=阶段进场（键盘 4px/帧 + 鼠标 1:1 捕获 5）。
        pos 非 None 时同设指针（0x44E620 的 [mgr+0x14]/[mgr+0x18]）——演员 ctor 尾
        0x4464CA 用它把指针种子设到自机出生点（原作"无初始化漂移"的机制，2026-10-31）。
        """
        kb, ms, fixed, step, shift, catch, w12 = self.P4_PRESET_TABLE[fid]
        self.p4_cfg = dict(kb=kb, ms=ms, fixed=fixed, step=step, shift=shift,
                           catch=catch,
                           bounds=((0x14, 0x14, 0x26C, 0x1CC) if w12
                                   else (0, 0, 0x280, 0x1E0)))
        if pos is not None:
            self.set_pos(*pos)
            self.mouse_tx, self.mouse_ty = int(pos[0]), int(pos[1])

    def _build_p4(self, keys, mouse_delta: tuple[int, int], keycode: int) -> Record:
        """页4 预设管线（0x44E660 的 0x44E7FC..0x44E9E2 段）。

        - 鼠标使能时：目标 += 原始位移<<移位；指针**追赶目标**，单帧位移超过捕获半径
          时按 4096/√d 方向限幅到半径（0x44E82B——鼠标 1:1 跟手，只有大跳才滑行）。
        - 键盘使能时：按住即 ±步长/帧（0x44E8E3 取 ±1000 的**符号**、幅值=预设步长；
          定步预设斜向 1.5×，0x44E930）。与鼠标量**相加**（预设 23 两者同开）。
        - 钳位到预设边界（[mgr+0x58] 选 (20,20)-(620,460) 或全屏）。
        """
        cfg = self.p4_cfg
        mdx, mdy = mouse_delta
        sh = cfg["shift"]
        dx = (mdx << sh) if cfg["ms"] else 0
        dy = (mdy << sh) if cfg["ms"] else 0
        if cfg["catch"]:
            tx = self.mouse_tx + (mdx << sh)
            ty = self.mouse_ty + (mdy << sh)
            ddx, ddy = tx - self.x, ty - self.y
            n2 = ddx * ddx + ddy * ddy
            c = cfg["catch"]
            if n2 > c * c:
                inv = int(4096.0 / math.hypot(ddx, ddy))
                ddx = (c * inv * ddx) >> 12
                ddy = (c * inv * ddy) >> 12
            dx, dy = ddx, ddy
            self.mouse_tx, self.mouse_ty = tx, ty
        # 0x44E8C0..0x44E952：键盘 ±1000 只作为**键盘分量**取符号、幅值=预设步长
        # （定步且任一键盘轴为零 ⇒ 步长 1.5×，0x44E930）；0x44E97E 的指针更新是
        # **[edi](鼠标分量) += edx(键盘±步长)** ——鼠标分量原样保留、两者相加。
        # 旧实现把鼠标+键盘合成值整体替换成 ±步长 ⇒ 鼠标最小位移=整步 54px
        # （調整页"碰一下跑好几项"的根因，2026-11-15）。
        if cfg["kb"]:
            # ±1000 の符号源：入力レコードのエッジ（1 押し = 1 ステップ）。
            # fixed=1（戦闘プリセット）は押しっぱなし連続移動、fixed=0（調整 preset 1）
            # は押下**エッジ**で 1 ステップ（ユーザ実機観察：按一下键盘走一项）。
            held_l = bool(keys.get("left"))
            held_r = bool(keys.get("right"))
            held_u = bool(keys.get("up"))
            held_d = bool(keys.get("down"))
            if cfg["fixed"]:
                edge_l, edge_r = held_l, held_r
                edge_u, edge_d = held_u, held_d
            else:
                edge_l = held_l and not self._prevdir.get("left")
                edge_r = held_r and not self._prevdir.get("right")
                edge_u = held_u and not self._prevdir.get("up")
                edge_d = held_d and not self._prevdir.get("down")
            self._prevdir.update(left=held_l, right=held_r,
                                 up=held_u, down=held_d)
            kx = -1000 if edge_l else (1000 if edge_r else 0)
            ky = -1000 if edge_u else (1000 if edge_d else 0)
            s = cfg["step"]
            if cfg["fixed"] and (kx == 0 or ky == 0):
                s += s >> 1                     # 0x44E930 sar 1 + add = 1.5×
            if kx != 0:                         # 0x44E936..0x44E940
                dx += s if kx > 0 else -s
            if ky != 0:                         # 0x44E944..0x44E94E
                dy += s if ky > 0 else -s
            # （0x44E973 byte[edi+0xC]=1 的"本帧有位移"旗标、0x44E979 的
            #   ([esi+0x20]&byte[esi+0x4F]) 混合预设抑制门：复刻侧暂无对应读者，未接。）
        l, t, rt, b = cfg["bounds"]
        if self.x + dx > rt:
            dx = rt - self.x
        if self.x + dx < l:
            dx = l - self.x
        if self.y + dy > b:
            dy = b - self.y
        if self.y + dy < t:
            dy = t - self.y
        self.x += dx
        self.y += dy
        r = Record()
        r.x, r.y, r.dx, r.dy = self.x, self.y, dx, dy
        r.key = keycode
        self.rec = r
        return r

    def set_preset(self, preset: int, flag: int = 0) -> None:
        """0x44E620(mgr, preset, x, y) → 0x44E4A0(mgr, preset, flag)：把预设记录
        （表 `0x498A88 + preset*0x0E`，14 字节）拷进 `[mgr+0x4C]`。

        表内容（`0x498A88`，逐项 14 字节）：
            0: 01 01 00 01 **80** …    1: …**36**…   2: …**31**…
            3: 01 01 00 01 **D6** …    4: …**64**…   5: …**80**…
        ⇒ 前 4 字节固定 `01 01 00 01`，第 5 字节是速度档（0x80=1.0 基准，0xD6=1.67 倍）。
        页13 用**预设 3**（光标最快），页3 用预设 0。
        """
        self.preset = int(preset)
        self.preset_rec = P13_PRESET_TABLE.get(int(preset), b"")
        # 预设记录第 5 字节落在 `[mgr+0x50]`＝**速度/半径**（0x44E4B5..0x44E4C5 把 14 字节拷到
        # [mgr+0x4C]，故 [+0x50] = 记录 byte4）。预设3（页13）= 0xD6 = 214。
        # 该值同时是键盘方向键的"整档幅值"（§10.3.2：只取符号、幅值 = 预设速度）
        # 与鼠标单帧位移半径（`dx²+dy² > 半径²` 时限幅）。
        self.speed = int(self.preset_rec[4]) if len(self.preset_rec) > 4 else 0
        # 菜单预设（0x498A88 行 0..5）回到**菜单管线**（kbd_move 按下沿整档）：
        # exe 的 0x44E620 是同一装载函数，页1-3/5/13 每次进场都会重载预设 ——
        # 旧复刻只进不出（set_preset4 置 p4_cfg 后无人清），页4 ESC 回页3 后
        # 键盘沿用战斗预设（kb=0 行 7..14）⇒ 方向键全灭。这里 set_preset 即清。
        self.p4_cfg = None

    def build(self, keys, mouse_buttons, mouse_delta=(0, 0), keycode: int = 0) -> Record:
        # 0x44EC17..0x44EC2E：键码一次性门——[esi+0x1F]（上帧键码）非 0 ⇒ 本帧键码清 0
        # （按住不重复；0x4AB59A 的键码 = 每次按下只有效一帧）
        prev_key = getattr(self, "_prev_key", 0)
        self._prev_key = keycode                # [esi+0x1F] = 原始键码
        if prev_key != 0:
            keycode = 0                         # 上帧有键 ⇒ 本帧清 0（按住不重复）
        b0 = bool(mouse_buttons[0]) or keys.get("shot", False)
        b1 = bool(mouse_buttons[2]) or keys.get("lock", False)
        r = Record()
        r.b0, r.b1 = b0, b1
        r.e0 = b0 and not self._prev[0]
        r.e1 = b1 and not self._prev[1]
        r.r0 = (not b0) and self._prev[0]
        r.r1 = (not b1) and self._prev[1]
        self._prev = (b0, b1)
        if self.p4_cfg is not None:              # 页4 预设管线（按键/按钮边沿公用上面这段）
            r2 = self._build_p4(keys, mouse_delta, keycode)
            r2.b0, r2.b1 = b0, b1
            r2.e0, r2.e1 = r.e0, r.e1
            r2.r0, r2.r1 = r.r0, r.r1
            return r2
        dx = dy = 0
        if self.kbd_move:                       # 0x44E7FC 的开关
            # 按下沿 → 走**一整档**（真机实测一按一项）；按住不连续推进
            _step = self.speed or self.KBD_STEP          # [mgr+0x50]，未设预设时退回 0x80
            for name, sx, sy in (("left", -1, 0), ("right", 1, 0),
                                 ("up", 0, -1), ("down", 0, 1)):
                held = bool(keys.get(name))
                if held and not self._prevdir.get(name, False):
                    dx += sx * _step
                    dy += sy * _step
                self._prevdir[name] = held
        mdx, mdy = mouse_delta
        if mdx or mdy:
            # §10.3.2：`dx = lX << [+0x52]`（页13 的预设3 shift=0）后，
            # `dx²+dy² > 半径²` 时限幅到半径（半径 = 预设速度 [mgr+0x50]）
            _r = self.speed or self.RADIUS
            n = math.hypot(mdx, mdy)
            if n > _r:
                mdx = int(round(mdx / n * _r))
                mdy = int(round(mdy / n * _r))
            dx += mdx; dy += mdy
        # 0x44E9A0..0x44E9E2：**先钳位移再加**（不是加完再钳）
        #   if (X + dx > X上限) dx = X上限 - X
        #   if (Y + dy < Y下限) dy = Y下限 - Y
        #   if (Y + dy > Y上限) dy = Y上限 - Y
        # 指针是屏幕光标，边界即 640×480 画面（页3 菜单 4 条 ×128px 带正好铺满 Y∈[0,512)）。
        if self.x + dx > 448:            # 0x44E9A0：X 上限 [inp+0x2C]（预设 0x17 = 448）
            dx = 448 - self.x
        if self.x + dx < 0:
            dx = -self.x
        if self.y + dy > 400:            # Y 上限 [inp+0x30]（预设 0x17 = 400）
            dy = 400 - self.y
        if self.y + dy < 0:
            dy = -self.y
        self.x += dx
        self.y += dy
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
class KeyMgr:
    """0x4AB5B0 键位管理器：+4 = 位图（0x44E660 轮询写入，bit0=攻击按住、bit1=锁定按住）。

    0x45AFF0(obj, mask) 测试位、0x45B0A0(obj, mask, val) 置/清位（状态4 会强写 bit0/bit1）。
    """

    def __init__(self) -> None:
        self.bits = 0

    def update(self, rec) -> None:
        """**不写** `[0x4AB5B0+4]`：那张位图的 bit0/bit1 是**模式选择**（bit0=鍛錬、
        bit1=操作器），由页3 菜单 state4 的 `0x45B0A0(0x4AB5B0,1/2,…)`（0x4257BE/0x4257D0）
        写入、页4 进场读取（0x45060A/0x45061C）、页13 收尾用 `0x45AFF0(…,1)` 决定去页12 还是页4；
        按键"按住/按下沿"全在帧记录 `0x4AB594`（+0/+1 按住、+2/+3 按下沿）。

        旧实现把 bit0/bit1 当成"攻击/锁定按住"每帧覆盖，会把模式选择清掉 ⇒ 已删。
        （0x44E660 轮询写的是帧记录：`0x44E810 [edi]=dx<<cl`、`0x44E81B [edi+4]=dy<<cl`、
        `0x44E7DB [edi+8]/[edi+9]`，edi = 记录指针，不是 0x4AB5B0。）
        """
        return

    def test(self, mask: int) -> bool:
        return (self.bits & mask) != 0

    def write(self, mask: int, val: int) -> None:
        """0x45B0A0(obj, mask, val)：mask 只有一个位时置位/清位。"""
        if val:
            self.bits |= mask
        else:
            self.bits &= ~mask

    # ---- 0x45AFC0 / 0x45B0E0 / 0x45B030：位段读写与反向测试（§10.2）------
    def field(self, mask: int) -> int:
        """0x45AFC0(obj, mask) = `([+4] & mask) >> 位号` —— 返回**字段值**（不是位号）。"""
        if not mask:
            return 0
        pos = (mask & -mask).bit_length() - 1
        return (self.bits & mask) >> pos

    def set_field(self, mask: int, value: int) -> None:
        """0x45B0E0(obj, mask, value)：mask 与其最低置位同步左移、value 同步左移，
        再 `[+4] = ([+4] and-not mask) or (mask and value<<位号)`（§16.97 勘误：不是"清位"）。"""
        if not mask:
            return
        pos = (mask & -mask).bit_length() - 1
        v = (int(value) << pos) & mask
        self.bits = (self.bits & ~mask) | v

    def clear_test(self, mask: int) -> bool:
        """0x45B030(obj, mask)：反向测试 —— 位**未**置位时返回真。"""
        return (self.bits & mask) == 0


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

    def or_andnot(self, mask: int, value: int) -> None:
        """`0x40114A` → **`0x45B0A0`**（双参 or / and-not）：value 非 0 → `|= mask`，
        否则 `&= ~mask`。`0x45B0A0..0x45B0CA` 实证：`test value,value` / `jz` 走 andnot 分支。"""
        if value:
            self.bits |= mask
        else:
            self.bits &= ~mask & 0xFFFFFFFF

    def field_get(self, mask: int) -> int:
        """`0x4019C9` → **`0x45AFC0`**（位段取值）：把 mask 锁定的字段右移到最低置位处。
        mask 为单 bit 时返回 0/1；mask==0 或无命中返回 0。"""
        if mask == 0:
            return 0
        shift = (mask & -mask).bit_length() - 1
        return (self.bits & mask) >> shift

    def field_write(self, mask: int, value: int) -> None:
        """`0x401636` → **`0x45B0E0`**（位段写入）：mask 与其最低置位同步左移、value 同步左移，
        再 `[+4] = ([+4] and-not mask) or (mask and value<<shift)` ⇒ 整体替换该字段。"""
        if mask == 0:
            return
        shift = (mask & -mask).bit_length() - 1
        m = mask
        v = value << shift
        self.bits = (self.bits & ~m & 0xFFFFFFFF) | (m & v & 0xFFFFFFFF)

    def rev_test(self, mask: int) -> bool:
        """`0x40145B` → **`0x45B030`**（反向测试）：mask==0 时返回"非空"。"""
        if mask == 0:
            return self.bits != 0
        return (self.bits & mask) == 0


# ---------------------------------------------------------------------------- UI 实体
# 0x4308A0 的 0x32 道具族各型源矩形（0x4317C4..0x431B2C 的四参 push，层 1 bm_cm32）
# 0x31 弹族 ctor 表（0x431B30，31 项）：type → (行为真址, 半径, 层, 源矩形)
# 只登记已逐条读定 rect 且行为已实现的型；其余走共通移动体，逐型补录见 docs/p4_enemy_matrix.md
P31_CTOR = {
    0x31000001: (0x4321C0, 0x0A, 0, (0xD8, 0x168, 0xEF, 0x17F)),
    0x31000003: (0x432250, 0x0C, 0, (0x00, 0x1F8, 0x17, 0x20F)),
    0x31000004: (0x432340, 0x0C, 0, (0x00, 0x1F8, 0x17, 0x20F)),
    0x31000005: (0x4324B0, 0x08, 2, (0x1B0, 0xC0, 0x1BF, 0xCF)),
    0x31000006: (0x4325E0, 0x0E, 2, (0x150, 0x60, 0x16F, 0x7F)),
    0x31000008: (0x432670, 0x10, 2, (0x190, 0xA0, 0x1AF, 0xBF)),
    0x31000009: (0x4327A0, 0x10, 2, (0x170, 0x60, 0x18F, 0x7F)),
    0x3100000A: (0x4321C0, 0x0A, 2, (0x180, 0xD8, 0x197, 0xEF)),
    0x3100000C: (0x432820, 0x10, 2, (0x120, 0x120, 0x13F, 0x15F)),
    0x3100000D: (0x4328B0, 0x0C, 2, (0x00, 0x120, 0x17, 0x137)),
    0x31000011: (0x432DC0, 0x10, 2, (0x140, 0x140, 0x15F, 0x15F)),
    0x31000014: (0x432FE0, 0x0C, 2, (0x000, 0x148, 0x17, 0x15F)),
    0x31000018: (0x433340, 0x0C, 2, (0x1B0, 0x150, 0x1DF, 0x167)),
    0x31000019: (0x433390, 0x0A, 2, (0xF0, 0x1C8, 0x107, 0x1DF)),
    # 0x4315CD：与 01 同 ctor 形状（rad=1、层0、rect D8/168/EF/17F），代码里 21 处使用
    0x3100001E: (0x4321C0, 0x01, 0, (0xD8, 0x168, 0xEF, 0x17F)),
}

P32_RECTS = {
    0x32000002: (0x00, 0x60, 0x1F, 0x7F),
    0x32000003: (0xA0, 0x60, 0xBF, 0x7F),
    0x32000004: (0xA0, 0xA0, 0xBF, 0xBF),
    0x32000005: (0xA0, 0x80, 0xBF, 0x9F),
    0x32000006: (0x00, 0x20, 0x1F, 0x3F),
    0x32000007: (0x00, 0x40, 0x1F, 0x5F),
    0x32000008: (0xA0, 0x20, 0xBF, 0x3F),
    0x32000009: (0x00, 0x00, 0x1F, 0x1F),
}


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
    # 字节视图：页4 有几个队列（如 0x4AD52C）装的是字节模型实体，
    # 行为函数按 [+0x1C] 之类的偏移读写，所以这里给一份 0x5C 的 raw。
    raw: bytearray = field(default_factory=lambda: bytearray(0x5C))

    def g32(self, off: int) -> int:
        return int.from_bytes(self.raw[off:off + 4], "little")

    def s32(self, off: int) -> int:
        v = self.g32(off)
        return v - 0x100000000 if v & 0x80000000 else v

    def d32(self, off: int, v: int) -> None:
        self.raw[off:off + 4] = (int(v) & 0xFFFFFFFF).to_bytes(4, "little")

    def g16(self, off: int) -> int:
        return self.raw[off] | (self.raw[off + 1] << 8)

    def d16(self, off: int, v: int) -> None:
        self.raw[off] = int(v) & 0xFF
        self.raw[off + 1] = (int(v) >> 8) & 0xFF


# ---------------------------------------------------------------------------- 页机
# ---- 查表三角函数（0x45A7E0 生成 / 0x45AAF0 正弦 / 0x45ABB0 余弦）----------
_TRIG_STEP = 3.1416 / 1800.0            # [0x4993A8]
_TRIG_AMP = 255.0                       # [0x499398]
_TRIG_N = 0x384                         # 每象限 900，一整圈 3600
# `0x463F30` = fistp 截断（fnstcw 后 or ah,0xC 置截断模式）⇒ 生成时向零取整
_SIN_TAB = [int(math.sin(j * _TRIG_STEP) * _TRIG_AMP) for j in range(_TRIG_N)]
_COS_TAB = [int(math.cos(j * _TRIG_STEP) * _TRIG_AMP) for j in range(_TRIG_N)]


def _trig(tab, v: int) -> int:
    """`0x45AAF0` / `0x45ABB0`：|v|%0x384 取余、|v|/0x384&3 选象限，取值后再定符号。"""
    v = int(v)
    a = abs(v)
    q = (a // _TRIG_N) & 3
    r = a % _TRIG_N
    if tab is _SIN_TAB:
        out = (tab[r], tab[_TRIG_N - 1 - r], -tab[r], -tab[_TRIG_N - 1 - r])[q]
        return -out if v < 0 else out
    return (tab[r], -tab[_TRIG_N - 1 - r], -tab[r], tab[_TRIG_N - 1 - r])[q]


def fsin(v: int) -> int:
    """`0x401A50` → `0x45AAF0`。"""
    return _trig(_SIN_TAB, v)


def fcos(v: int) -> int:
    """`0x40159B` → `0x45ABB0`。"""
    return _trig(_COS_TAB, v)


class Pages(Page4Mixin):
    """0x459360 页机 + 页1/2/3（页4 由原 main.py 的 game 逻辑接手）。"""

    def __init__(self, data: dict, palette: np.ndarray, text: TextRenderer,
                 canvas: Canvas, inp: Input, timer: Timer, flags: Flags,
                 audio=None):
        self.data = data
        self.audio = audio                          # audio.Audio（None ⇒ 静音，仅记日志）
        self.pal = palette
        self.p2_stream: P2Stream | None = None
        self.p2_glyph: dict[int, bytes] = {}      # ⑩⑪ 字形条资源 80/81/82
        self.p2_text_on = True                    # 0x4AB5B0 的 flag 0x400（文字表示）
        self.p2_blits: list = []                  # ⑧ 静态页的待贴清单（draw 里执行）
        # 0x4AB5B0 / 0x4AB5B8 的出厂默认值来自 state.dat 头 +0x10/+0x14 的
        # "GRCD/106A" 默认头（0x45C6B6/0x45C6BD，state.dat 不存在时由 0x45C5F0 写入），
        # 启动时 0x457FF2..0x458029 用 0x45AF10 整字写回这两个全局：
        #   0x10181C：bit2=音楽ON、0x18=3=効果音複音、0x800/0x1000=1、0x3000=1、
        #             0xF00000=1（第一幕已解锁）；0x200=自動爆破OFF、0x400=画像要素OFF
        #   0x64C80210：0xF/0xF0/0xF00 = 0/1/2（攻撃/光撃/捕獲入力，DIK-0x20）、
        #             0x3F000=0、0x1FC0000=50（明度）、0xFE000000=50（彩度）
        # 旧实现从 0 起 ⇒ 调整页显示 効果音無音/音楽無、明度彩度 -200，全不对。
        self.keys = KeyMgr()                       # 0x4AB5B0
        self.keys.bits = 0x0010181C
        self.disp_cfg = KeyMgr()                   # 0x4AB5B8（亮度/对比度等显示配置字段）
        self.disp_cfg.bits = 0x64C80210
        # 0x4987F4 调色板重映射表 A（0x44D290 色带填充的色号变换；行 12 门控）
        try:
            import json as _json
            from pathlib import Path as _Path
            with open(_Path(__file__).resolve().parent.parent / "remap_tables.json") as _rf:
                self._band_remap_a = bytes(_json.load(_rf)["remap_A"])
        except Exception:
            self._band_remap_a = None
        self._adjust_bgm_i = 0
        self._adjust_bgm_dirty = False
        self._adjust_pal_dirty = False
        self.p4_op_flag = 0                          # 0x4AA49C byte（操作器）
        self.p4_keyblob = bytearray(0x78)            # 0x4A4080..F7 键位 blob（DirectInput）
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
        self.p4_ensure()             # 页4 运行期状态（0x4AB5CC/0x56CCB8/统计区…）
        # 0x56CC8C/0x56CC90：自机位置镜像（页面重置清零）。页13 无自机 ⇒ 恒 0，
        # 但 `0x42BB9E` 会读 `[0x56CC90]`，故仍需存在。
        self.mirror = {"x": 0, "y": 0}     # 0x56CC8C/0x56CC90
        self.g56cc94 = 0                   # byte[0x56CC94]（0x42F159 等写入，页13 无消费者）
        # 0x4AD4CC：特效/尾迹队列。0x458E70 的第 6 项（call 0x40161D→0x43A350）每帧 tick 它；
        # 记录 `0x401686`→`0x43A3C0` 会 new 出实体再走 `0x4355E0`（按 type&0xFF000000 分类构造）。
        # 类 0x41 的显示/行为尚未解，故此处先按原序记录，不上屏。
        self.trailq = []
        self.rng_seed = 0            # `0x5D3E38`：`0x45AD00` 的 LCG 种子，BSS 初值 0
        self.layers = Layers(data)
        self.page = 0
        self.ui52c: list[UiEntity] = []
        self.ui4fc: list[UiEntity] = []
        self.ui46c: list[UiEntity] = []          # 0x4AD46C（0x12 特效）
        self.actorq: list[UiEntity] = []         # 0x4AD40C（演员；页13 = 0x0A 汉字）
        self.screen_fill = -1
        self.bar_color = 0xD9          # 0x42000004 色块条用的索引（ctor 里由 desc 决定，暂取亮色）
        self.trace: list[str] = []
        self.p1_done: set[int] = set()
        self.p13_frames = 0          # 0x56CCA8（页13 的帧计数）
        self.p13_portrait_arr = None # 0x6F000007 画出的整屏人像（0x43F340）
        self.p13_src = None          # res_79 的 60×320 原始字节（瓦片索引，滚动源）
        self.p13_mono = False        # 0x43F246 的 16 色近似标志
        self.p13_tiles = None        # 层4 的 (2,2,256,8,8) 瓦片表
        self.posq = []               # 0x4AD43C 位置对象队列（0x2300001A）
        self.wipe4f = []             # 0x4F000009 ×2：0x4AD4CC 里擦切开窗（行为 0x439BD0）
        self.spark4cc = []           # 0x41000004：4AD4CC 里的命中火花（行为 0x429D40）
        self.theatre = 0             # 0x4AB5C8 舞台选择器 dword（低字=关卡、高字=模式）
        self.score_level = 0         # 0x4CD4A0 的 [+0x24] 关卡号
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
        elif self.page == 13:
            self.page13_enter()
        elif self.page == 4:
            self.p4_enter()                       # 0x4593C4 0x4505B0
            # 0x454950 不属于页4：页机映射（0x4593A7 dec → byte[0x459618+i] → 0x4595E4 跳表）
            # 页4 → idx 3 → arm 3 = 0x4593C2；0x45952A(0x454950) 是 **页15**（idx 10）的进场。
            # 之前在这里顺带调它，会让页15 的舞台总控 0x6B000001 在 f0 tick，
            # 其行为 0x443606 调 0x43A320 把 0x4AD4CC 清空 ⇒ 开场 0x42 实体全被抹掉。
            self.p4_enter_ok = self.flags.is_empty()   # 0x4593C9 test al ⇒ 决定是否进帧循环
        elif self.page == 5:
            self.page5_enter()                    # 0x452730 記錄
        elif self.page == 6:
            self.page6_enter()                    # 0x4523C0 調整
        elif self.page == 12:
            self.page12_enter()                   # 0x4536E0 中间页（鍛錬→游戏）
        elif self.page == 14:
            self.page14_enter()                   # 0x453A60 OP movie
        elif self.page in (8, 9, 10):
            self.page_results_enter()             # 0x453050 游戏结束/结算
        elif self.page == 11:
            # 0x4593C2：与页4 完全相同的 enter/step/finish（0x4505B0/0x451110/0x451C50）
            self.p4_enter()
            self.p4_enter_ok = self.flags.is_empty()
        elif self.page == 15:
            self.page15_enter()                   # 0x454950 第二关
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
        if self.page == 13:
            return self.page13_step()
        if self.page == 4:
            # 0x4593C2：`if (0x4505B0) { if (0x451110) while (0x451110); }`
            return self.p4_enter_ok and self.p4_step()
        if self.page == 5:
            return self.page5_step()              # 0x452890
        if self.page == 6:
            return self.page6_step()              # 0x4525E0
        if self.page == 12:
            return self.page12_step()             # 0x4538E0
        if self.page == 14:
            return self.page14_step()             # 0x453EA0
        if self.page in (8, 9, 10):
            return self.page_results_step()       # 0x453300
        if self.page == 11:
            # 0x4593C2：与页4 共用 enter/step/finish
            return self.p4_enter_ok and self.p4_step()
        if self.page == 15:
            return self.page15_step()             # 0x454B30
        return False

    def finish(self) -> None:
        self.sysf.set(SYS_FLAG_LEAVE)                     # 离页：亮度渐变实体自尽并复位亮度
        if self.page == 1:
            self.page1_finish()
        elif self.page == 2:
            self.page2_finish()
        elif self.page == 3:
            self.page3_finish()
        elif self.page == 13:
            self.page13_finish()
        elif self.page == 4:
            self.p4_finish()                      # 0x4593E5（进场失败也执行）
        elif self.page == 5:
            self.page5_finish()                   # 0x452910
        elif self.page == 6:
            self.page6_finish()                   # 0x452660
        elif self.page == 12:
            self.page12_finish()                  # 0x453970
        elif self.page == 14:
            self.page14_finish()                  # 0x453EA0 后半
        elif self.page in (8, 9, 10):
            self.page_results_finish()            # 0x4535A0
        elif self.page == 11:
            self.p4_finish()                      # 0x451C50（与页4 共用）
        elif self.page == 15:
            self.page15_finish()                  # 0x454CB0

    def advance(self) -> None:
        """一帧：step 返回 0 → finish（页号切换）→ 页机重新分发。"""
        if self.page == 0xFF and not self.quit:
            # 0x4595A8：`OutputDebugString("This program will be closed."@0x4A4A64)` +
            # 页号清 0 → 0x4595CD PostQuitMessage(0)。即整程序退出。
            self.log('page 0xFF → "This program will be closed." → 退出')
            self.quit = True
            return
        if self.page == 0 or self.quit:
            return
        if not self.step():
            self.finish()
            if self.page == 0xFF:
                # 0x4595A8 → 0x4595CD PostQuitMessage：整程序退出
                self.log('page 0xFF → "This program will be closed." → 退出')
                self.quit = True
                return
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
        # 开场脚本（资源 65 的 flow-VM 程序，§16.78）：opmovie 里按 OP03 生成摆放实体
        try:
            import json as _json
            self.opng_script = _json.loads(
                (REMAKE / "opng_script.json").read_text(encoding="utf-8"))
        except Exception as _e:
            self.opng_script = []
            self.log(f"page1：opng_script.json 读取失败 {_e}")
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
        self.layers.free_all()
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
        """0x4562A0(seq)：逐条铺色带。

        原件逐字（0x4562AB..0x45630D）：
            ecx = [seq+8]（起始索引）; edx = [seq+0xC]（滚动量）
            h = (i16)table[idx*4+2] - 滚动量      ← **只有起始那一条减去滚动量**
            if (h + y > 0x1E0) h = 0x1E0 - y
            rect = (0, y, 0x280, y+h)  → 填充 table[idx].color
            y += h; idx++

        色号经 0x44D290：byte[0x4AA7B0+0x86]（調整行 12）置位时色号先过
        重映射表 A（0x4987F4，remap_tables.json）再写——彩虹文字墙/色带变色效果。
        旧实现直接写原始色号（重映射 pass 缺失）。"""
        y = 0
        i = self.band_start
        import os as _os
        if _os.environ.get("P4_BANDDRAW") and getattr(self, "p4_frames", 0) in (712, 715, 720, 750, 760):
            print(f"[banddraw] f={self.p4_frames} start={self.band_start} scroll={self.band_scroll} count={self.band_count}", flush=True)
        scroll = self.band_scroll
        cnt = max(self.band_count, 1)
        remap = getattr(self, "_band_remap_a", None)
        use_remap = bool(remap) and getattr(self.layers, "cg40", 0)
        while y < H:                         # 0x4562A0 只看 y，不查表项数（越界环绕）
            color, h = self.band_table[i % cnt]
            if use_remap:
                color = remap[color & 0xFF]
            hh = h - scroll
            scroll = 0                      # 只对起始条生效
            if y + hh > H:
                hh = H - y
            if hh > 0:
                self.canvas.fill_rect((0, y, W, y + hh), color)
            y += hh
            i += 1

    def band_advance(self) -> None:
        """0x456270(seq) + 0x4560C0(seq, delta)：按 speed 推进滚动量，超过当前带高则吃掉该带。"""
        if self.band_frames > 0:
            self.band_frames -= 1
            self.band_scroll = (self.band_scroll + self.band_speed) & 0xFFFFFFFF
            if self.band_scroll >= 0x80000000:
                self.band_scroll -= 0x100000000
            cnt = max(self.band_count, 1)
            guard = 0
            while guard < 4096:
                guard += 1
                _, h = self.band_table[self.band_start % cnt]
                if self.band_scroll < h:
                    break
                self.band_scroll -= h
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
        # ⑩⑪ 的字形条数据（§16.93.4）：资源 80/81/82 = 列式列表（60×124 / 92×124 / 92×80）
        #   层4 图集由 ① 的层装载表 (-358, 层4, 资源 0xB4) 装好（0x44BE10）
        self.p2_glyph = {}
        for rid in (80, 81, 82):
            q = REMAKE / "pygame" / "assets" / f"p2_glyph_{rid}.bin"
            if q.exists():
                self.p2_glyph[rid] = q.read_bytes()
        # 0x4AB5B0 的 flag 0x400 = 文字表示（键码 0x23 切换，§16.93.7），默认开
        self.p2_text_on = True
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
        # SetCursorPos 只回中**硬件**光标，虚拟指针 [mgr+0x14/0x18] 由 0x44EB60 累加位移
        # [0x4AB596]/[0x4AB597]（左右键按下沿）→ flags |= 0x10000 → 收尾去页3
        if self.inp.rec.e0 or self.inp.rec.e1:
            self.flags.set(FLAG_CLICK)
            self.log(f"page2 click → flags=0x{self.flags.bits:X}")
        self.key_command(self.inp.rec.key)
        self.begin_frame()
        # 0x4562A0：色带（栈式，只铺带子，不整屏清！—— mosaic 像素靠这个保留下来）
        self.band_draw()
        # 0x43A350：4CC 行为遍（页2 的 4F 飞入面板在这里动；0x458F80 的第一道）
        self.tick_ui(self.ui46c)
        # 0x445A30：0x6F000008 时间轴（层装载 / 快照拷贝 / 记录流 / 字形条 / 面板生成）
        self.tick_ui(self.ui52c)
        self.draw()                                 # 4CC/4FC 显示表（页2 无节点）
        self.band_advance()                         # 0x456270 帧末推进色带
        return self.flags.is_empty()

    def page2_finish(self) -> None:
        # 0x452F80：0x44FDD0(MIDI) → 0x45A510(计时器) → 0x44D200(0xB4)+present ×2
        #          → 0x44CEE0 → 0x45B070 → 0x100/0x200→页0、0x10000→页3、else→页0xFF
        # 0x452F83 0x44FDD0(0x4AB514) = 停 DirectMusic
        # 0x452FA7 0x44D200(0xB4) → 0x458CB0(present) → 0x44D200(0xB4) → 0x458CB0(present)
        self.midi_stop()
        self.log("page2.finish：停 MIDI（0x44FDD0）+ 两次整屏黑 + present")
        self.timer.kill()
        self.canvas.fill(0xB4)
        self.present()
        self.canvas.fill(0xB4)
        self.present()
        self.layers.free_all()          # 0x452FD3 0x44CEE0
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
        """0x4520A0（页3 进场）：逐条对齐，含 3 条错误旗标与末尾的旗标测试。

        原函数的返回值为 `0x45AFF0(0x4AB5C0, 0)`（旗标是否为空 = 进场是否成功），
        失败路径都是 `0x45AF30(flags, bit)` 置位后**继续执行**，由 step 的
        `0x45AFF0(flags, 0)` 退出、finish 的 `0x45B070` 取最低位映射页号。
        """
        # 0x4520A7..0x4520E1：0x44CDF0(mgr, 2, 对比, 亮度, -256)
        #   两个参数来自 0x45AFC0(0x4AB5B8) 取的配置位段（*4-0xC8），D 参 -256 = 淡入起点
        if "palettes" in self.data and "2" in self.data["palettes"]:
            self.pal = np.array(self.data["palettes"]["2"], dtype=np.uint8)
            c = self.disp_cfg.field(0xFE000000)      # 彩度（調整行 10）
            b = self.disp_cfg.field(0x1FC0000)       # 明度（調整行 11）
            self.pal_now = fade_palette(self.pal, b * 4 - 0xC8, c * 4 - 0xC8)
        ok = True
        # 0x4520EA：0x44C640(13, 10) 层13 ← bmetc\bm_mn.ggd
        ok = self.layers.bind(13, 10)
        # 0x4520FC：0x44CE60(13, 0) 色键 0（返回 void，不参与成败判定）
        self.layers.color_key(13, 0)
        if not ok:
            self.flags.set(2)                       # 0x45210E：0x45AF30(2)
        # 0x45211A：0x44E620(0x4AB454, 0, 0, 0)   装预设 0 + 虚拟指针归零
        #（set_preset 会把 p4_cfg 清回菜单管线 —— 页4 ESC 回来时键盘才活着）
        self.inp.set_preset(0)
        self.inp.set_pos(0, 0)
        # 0x45212C：0x44EDA0(0x4AB454, 0)         输入模式 0
        self.inp.set_mode(0)
        # 0x452138：0x450140(0x4AB4B0, 1, 0x24)   槽1 ← wave #36（se_36）= 菜单旋律音色
        if not self.sound_bind(1, 0x24):
            self.flags.set(8)                       # 0x45214A：0x45AF30(8)
        # 0x452156：0x458D60(page, 0,0,0,0) 场景重置
        #   = 清 8 个队列 + 重置色带引擎(0x4CD484) + 0x4CD4A0/0x4CD590 + 回放(0x4CD5D8)
        #     + 记录流(0x56B95C) + [0x56CC84]=0
        self.scene_reset()
        # 0x452165：0x430400(desc{0,0,0x5F000005,0}) → 0x44B140 入 0x4AD4FC
        self.spawn(self.ui4fc, 0x5F000005)
        # 0x452199：0x45A490(0x4AB570, 0)         SetPeriod(0) = 60Hz
        if not self.timer.set_period(0):
            self.flags.set(0x40)                    # 0x4521AB：0x45AF30(0x40)
        # 0x4521B7：0x45AFF0(0x4AB5C0, 0)         返回"旗标为空"
        self.enter_ok = self.flags.is_empty()
        self.log(f"page3.enter（层13←bm_mn / bm_pald / 0x5F000005 / SetPeriod0）ok={self.enter_ok}")

    # 0x450140(mgr, slot, res)：把 wave #res 装进槽 slot（槽指针数组 mgr+8+slot*4）
    def load_wave(self, slot: int, ident: int) -> bool:
        """`0x450140(0x4AB4B0, slot, res)`。失败打印 "Could not open wave file!"（0x4A4860）。

        这是**波形装载**（页3 是槽1 ← wave #0x24；页13 是槽0..0x13 ← 0x27/0x28/…），
        源文件是 resource.rom #21..44 的裸 s16 PCM（已解成 extracted/wave/se_XX.wav）。
        """
        if self.audio is None:
            self.log(f"0x450140 load_wave(slot={slot}, id=0x{ident:X}) → 静音模式")
            return True
        ok = self.audio.load_wave(slot, ident)
        self.log(f"0x450140 load_wave(slot={slot}, id=0x{ident:X}) ok={ok}")
        return ok

    # 兼容旧名（页3 进场沿用 sound_bind 这个名字）
    def sound_bind(self, kind: int, ident: int) -> bool:
        return self.load_wave(kind, ident)

    # 0x450440(0x4AB4B0, 0)：播槽1 的下一个旋律音（频率表 0x498FEC）
    def melody_step(self) -> None:
        if self.audio is not None and self.audio.melody_step():
            self.log(f"0x450440 melody step idx={self.audio.melody_idx}")

    # 0x44FDD0(0x4AB514)：停 BGM
    def midi_stop(self) -> None:
        if self.audio is not None:
            self.audio.bgm_stop()
        self.log("0x44FDD0 MIDI stop")

    # 0x458D60(page, 0,0,0,0)：场景重置
    def scene_reset(self) -> None:
        """0x458D60：清 8 条队列 + 12 个背景槽(0x457B90) + 色带引擎(0x4CD484)
        + 0x4CD4A0/0x4CD590 + 回放(0x4CD5D8) + 记录流(0x56B95C) + [0x56CC84]=0。

        队列序（0x458D60..0x458DA1）：40C(actorq) → 43C(q43c) → 46C → 49C → 4CC → 4FC → 52C。
        旧复刻只清 46C/4FC/52C 三条，页4 的 0x42/演员/敌机实体和 12 槽会带进下一页
        （2026-10-31 修，"页切换背景未清"的一半根因；另一半是共享 draw() 的页4 渲染遍）。"""
        self.actorq.clear()                            # 0x4AD40C
        self.p4_q43c.clear()                           # 0x4AD43C
        self.ui46c.clear()                             # 0x4AD46C
        self._p4_q("ui49c").clear()                    # 0x4AD49C
        self.p4_ui49c.clear()                          # （同名分裂的旧列表，一并清）
        self._p4_q("ui4cc").clear()                    # 0x4AD4CC
        self.trailq.clear()                            # 0x4AD4CC（页1-3/页6 侧同名列表——
        #   調整页的 0x4F000001 砖块生成在 trailq，不清则 页6→页3 彩虹墙 whole 泄漏上屏
        #   （2026-11-15 用户实测"esc 返回 page3 后页面被破坏"根因））
        self.ui4fc.clear()                             # 0x4AD4FC
        self.ui52c.clear()                             # 0x4AD52C
        # 0x6F000007 的整屏人像/擦切是页13 队列实体的画布镜像：实体随队列清除，
        # 镜像也要清——否则 页13(飞行员画面)→页4 每帧把人像贴回来（2026-10-31 修）。
        self.p13_portrait_arr = None
        self.wipe4f = []
        for s in getattr(self, "p4_bg", ()):            # 0x4AD55C ×12（0x457B90 复位）
            s.params = [0] * 20
            s.rates = [0] * 20
            s.grid = []
            s.bands = []
            s.rem = 0
            s.flags = 0
            s.active = 0
            s.acc = 0
        # 0x4560C0：色带引擎复位 → 回到初始一条 {color=0xB4, h=0x200}
        self.band_table = [[0xB4, 0x200]]
        self.band_count = 1
        self.band_start = 0
        self.band_scroll = 0
        self.band_speed = 0
        self.band_frames = 0
        self.stream_cursor = 0          # 0x56B95C 记录流复位
        self.replay_pos = 0             # 0x4CD5D8 回放复位

    def page3_step(self) -> bool:
        """0x452220：0x458B80 → 0x458CB0 → 0x44EB60 → SetCursorPos → 0x458FD0
        → 0x4562A0 → 0x458F80，返回 0x45AFF0(0x4AB5C0, 0)（旗标为空 → 继续）。"""
        # 0x452223：0x458B80（泵 + 帧门）——本复刻的帧门在 run.py 的 60Hz 循环里
        # 0x45222A：0x458CB0（光标 + present 0x44D740）——由 draw() 末尾的 present 承担
        # 0x45222F：0x44EB60(0x4AB454, &rec, 0, 0) 已在 run.py 每帧 build 出 self.inp.rec
        # 0x452242：[0x5E721C](0x140, 0xF0) = SetCursorPos(320,240)（把**硬件**光标拉回中心，
        #           虚拟指针 [mgr+0x14/0x18] 不受影响，故此处不写 inp.x/y）
        self.keys.update(self.inp.rec)                 # 0x4AB5B0 位图 = 攻击/锁定按住
        # 0x452252：0x458FD0(rec[6]) 键码 → 旗标（码1 = ESC → 0x200）
        self.key_command(self.inp.rec.key)
        self.begin_frame()                             # 0x458CB0 → 0x44D740 的 ±255 整屏填充
        # 0x45225F：0x4562A0(0x4CD484) 色带（页3 不推带 ⇒ 沿用上一页留下的带 = 0xB4 黑屏）
        self.band_draw()
        # 0x452269：0x458F80 = 0x43A350(4CC) → 0x430840(渲4CC) → 0x44B0D0(4FC)
        #           → 0x445A30(52C) → 0x430840(渲4FC) → 0x456270(色带推进)
        self.tick_ui(self.ui4fc)          # 4FC 行为（菜单总控 + 8 行）
        self.tick_ui(self.ui52c)          # 52C 行为（亮度渐变 0x61000005）
        self.ui46c = [e for e in self.ui46c if e.alive]
        self.ui4fc = [e for e in self.ui4fc if e.alive]
        self.ui52c = [e for e in self.ui52c if e.alive]
        self.draw()
        self.band_advance()               # 0x456270
        # 0x452270：0x45AFF0(0x4AB5C0, 0) → 旗标是否全空
        return self.flags.is_empty()

    def page3_finish(self) -> None:
        """0x4522A0：0x45A510 → 0x44D200(0xB4)+present ×2 → 0x44CEE0 → 0x45B070 映射

            0x100/0x200 → 页0（退出）    0x20000 → 页13
            0x40000 → 页5               0x80000 → 页6
            0x100000 → 页0              0x2000000 → 页14
            其它 → 页0xFF（错误退出）
        """
        # 0x4522A3 0x45A510(0x4AB570)：定时器收束；失败 → flags |= 0x40
        self.timer.kill()
        # 0x4522BD 0x44D200(0xB4) → 0x4522CC 0x458CB0(present)
        self.canvas.fill(0xB4)
        self.present()
        # 0x4522D3 0x44D200(0xB4) → 0x4522E2 0x458CB0(present)
        self.canvas.fill(0xB4)
        self.present()
        # 0x4522E9 0x44CEE0：销毁 14 个层表面
        self.layers.free_all()
        # 0x4522F3 0x45B070(0x4AB5C0)：取最低置位 → 页号表
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

    # ---- 页13（0x454280 / 0x454720 / 0x454840）= 选择画面 ------------------
    def page13_enter(self) -> None:
        """0x454280：页13 进场（逐步对齐，含 3 条错误旗标）。

        顺序：`[0x56CCA8]=0` → `0x44CDF0(mgr,1,对比,亮度,-255)` → 5 层 + 建层5
        → 6 个色键 → `0x44E620(mgr,3,0,0)` 预设3 + 指针(0,0) + `0x44EDA0(mgr,0)`
        → 20 个波形槽装载（槽0..0x13 ← wave 21..40）→ `0x458D60` 场景重置 → `0x44F600(0x4AB514,1,7)`
        → `0x45EF10(0x4CD4A0,1)` 关卡号=1 → 生成 `0x6F000006` 入 0x4AD52C
        → `0x45A490(0x4AB570,0)` SetPeriod(0) → 返回 `0x45AFF0(0x4AB5C0,0)`。
        """
        self.p13_frames = 0                             # 0x454283 [0x56CCA8] = 0
        self.p13_portrait_arr = None                    # 0x6F000007 会重新画
        self.p13_src = None
        self.p13_tiles = None
        self.p13_mono = False
        self.posq = []
        self.actorq = []
        self.spark4cc = []
        self.wipe4f = []
        if "1" in self.data.get("palettes", {}):
            self.pal = np.array(self.data["palettes"]["1"], dtype=np.uint8)
            self.pal_now = self.pal
        # 0x4542C3 push b / push a / push 1 → 0x44CDF0(mgr, 1, a, b)，第 5 参 -255 由
        # `push 0xFFFFFF01`（0x454291）留在栈上提供 ⇒ 进场即**全黑**，由淡入实体拉回来。
        self.fade_to(-255, 0)
        ok = True
        for lay, res in P13_LAYERS:                     # 0x4542E1..0x45433F
            ok = self.layers.bind(lay, res) and ok
        ok = self.layers.create(5, W, H) and ok         # 0x45435D 0x44C560(5,640,480)
        for i in range(6):                              # 0x45436F..0x4543C9 色键 0
            self.layers.color_key(i, 0)
        if not ok:
            self.flags.set(2)                           # 0x4543D4 → 0x45AF30(2)
        # 0x4543D9 失败分支之后：push 0/0/0/3 → 0x44E620(mgr,3,0,0)；0x4543F0 → 0x44EDA0(mgr,0)
        self.inp.set_preset(3)
        self.inp.set_pos(0, 0)
        self.inp.set_mode(0)
        for slot, ident in P13_SCRIPTS:                 # 0x454405..0x45458B
            if not self.flow_script_load(slot, ident):
                self.flags.set(8)                       # 0x454594
        self.scene_reset()                              # 0x4545B8 0x458D60
        self.midi_play(7)                               # 0x4545A0 0x44F600(0x4AB514,1,7)
        self.score_level = 1                            # 0x4545BD 0x45EF10(0x4CD4A0,1)
        self.spawn(self.ui52c, 0x6F000006)              # 0x4545C9 → 0x445AA0(0x4AD52C)
        if not self.timer.set_period(0):                # 0x4545FD 0x45A490(0x4AB570,0)
            self.flags.set(0x40)
        self.enter_ok = self.flags.is_empty()
        self.log(f"page13.enter（层0..4+建层5 / 20 脚本 / 0x6F000006 / SetPeriod0）"
                 f"ok={self.enter_ok}")

    def page13_step(self) -> bool:
        """0x454720：`0x458B80` → `0x458CB0` → `0x44EB60` → `SetCursorPos(320,240)`
        → `0x458FD0` → `[0x56CCA8]++` → `0x4562A0` → 碰撞 `0x43C060`(4AD46C,4AD43C)
        → `0x458E70` → `0x458EF0(this,0)` → 返回 `0x45AFF0(0x4AB5C0,0)`。"""
        self.keys.update(self.inp.rec)                  # 0x4AB5B0 位图
        # 0x454769 0x458FD0(rec[6])：键码 → 旗标（ESC = 0x200）
        self.key_command(self.inp.rec.key)
        self.begin_frame()                              # 0x458CB0 → 0x44D740 的 ±255 填充
        self.p13_frames += 1                            # 0x454776 [0x56CCA8]++
        self.band_draw()                                # 0x454786 0x4562A0
        # 0x454794 0x43C060(ctx,0x4AD46C,0x4AD43C)：本复刻还没有自机/敌弹实体，跳过碰撞
        # 0x458E70 的泵队列顺序（逐项）：0x4AD55C(未用) → **0x4AD40C 演员** → **0x4AD46C 特效**
        # → **0x4AD43C 位置** → 0x4AD49C(未用) → **0x4AD4CC 擦切/尾迹** → **0x4AD4FC** → **0x4AD52C**
        # → 0x4CD484(未用)。顺序不能改：同一帧内先 tick 的队列生成的实体，
        # 会被排在它后面的队列当帧 tick 到。
        self.tick_ui(self.actorq)                       #   4AD40C（0x0A 汉字演员）
        self.tick_ui(self.ui46c)                        #   4AD46C（0x12 特效）
        self._tick_posq()                               #   4AD43C（0x2300001A 位置对象）
        self._collide_46c_43c()                         # 0x454794 0x43C060(ctx,&46C,&43C)
        self._tick_wipe4f()                             #   4AD4CC（0x4F000009 擦切/尾迹）
        self._tick_spark4cc()                           #   4AD4CC（0x41000004 命中火花）
        self.tick_ui(self.ui4fc)                        #   4AD4FC
        self.tick_ui(self.ui52c)                        #   4AD52C（淡入淡出、0x6F000006 七态机）
        self.actorq = [e for e in self.actorq if e.alive]
        self.ui46c = [e for e in self.ui46c if e.alive]
        self.ui4fc = [e for e in self.ui4fc if e.alive]
        self.ui52c = [e for e in self.ui52c if e.alive]
        self.draw()                                     # 含 present
        self.band_advance()                             # 0x456270
        return self.flags.is_empty()

    def page13_finish(self) -> None:
        """0x454840：停 MIDI → KillTimer → 2×(填0xB4+present) → 释放层 → 旗标映射

            `0x100` → 页0           `0x200` → 页3
            `0x10000` → 写 `[0x4AB5C8]=0x20000`，`bit0(0x4AB5B0)`(=鍛錬) ? 页12 : 页4
            其它 → 0xFF
        """
        self.midi_stop()                                # 0x4540A8 0x44FDD0(0x4AB514)
        self.timer.kill()                               # 0x454843/0x45484D
        self.canvas.fill(0xB4); self.present()          # 0x454867..0x454878
        self.canvas.fill(0xB4); self.present()          # 0x45487D..0x45488E
        self.layers.free_all()                          # 0x454893 0x44CEE0
        r = self.flags.lowest()                         # 0x4548A2 0x45B070
        if r == 0x100:                                  # 0x4548FC
            self.page = 0
        elif r == 0x200:                                # 0x4548F0
            self.page = 3
        elif r == 0x10000:                              # 0x4548C8
            self.theatre = 0x20000                      # 0x4548CF [0x4AB5C8] = 0x20000
            self.page = 12 if self.keys.test(1) else 4  # 0x4548D9 0x45AFF0(0x4AB5B0,1)
        else:
            self.page = 0xFF
        self.log(f"page13.finish flags=0x{self.flags.bits:X} → page {self.page}"
                 f"（theatre=0x{self.theatre:X}）")

    # ---- 页12：中间页（鍛錬 mode：页13 选人后 → 页12 → 页4/页15）--------------
    def page12_enter(self) -> None:
        """`0x4536E0` 全序列（2026-11-16 按反汇编复核）：

        亮度/对比度字段(0x4AB5B8) ×4-0xC8 → 0x44CDF0(2, 参) 调色板2 →
        0x44C640(13, 0x2B)（层13 ← bm_s1lg）→ 0x44CE60(13, 0) →
        0x44E620(预设 4 @(0x140, 0xF0)) → 0x44EDA0(0) → **[0x4AB5C8]=0** →
        0x458D60 场景重置 → 0x5F000014（desc 全 0）入 0x4AD4FC →
        0x45C740(0x4AB5CC, 0, &buf) 记录读取 → 0x401C99 记录流复位 →
        **0x45FE10(项+0x4C, 0x4100000D) 应用关卡场景** →
        SetPeriod(0)（失败旗标 0x40）。

        注：0x44C640(13,0x2B) 的绑定随即被 0x45FE10 的 0x44CEE0（释放 14 层）抹掉；
        层13 要到状态8 的 0x449E10(stage,0xB5) 才重新装 bm_tr。"""
        self.flags.clear()
        self.screen_fill = -1
        self.pal = self.data and self._load_pal(2)
        self.pal_now = self.pal
        self.layers.bind(13, 43)                      # 0x44C640(13, 0x2B) ← bm_s1lg
        self.layers.color_key(13, 0)                  # 0x44CE60(13, 0)
        self.inp.set_pos(0x140, 0xF0)                 # 0x44E620(4, 0x140, 0xF0, 0, 0)
        self.inp.set_preset4(4, (0x140, 0xF0))
        self.inp.set_mode(0)                          # 0x44EDA0(0)
        self.theatre = 0                              # 0x45379C [0x4AB5C8] = ebx = 0
        self.p4_stat[0x4AB5C8] = 0                    # 同一地址的字节镜像（页12_finish 读它）
        self.scene_reset()                            # 0x4537A2 → 0x458D60
        st = self.p4_stat
        m = self.spawn(self.ui4fc, 0x5F000014)        # 0x4537A8..0x4537D3
        # 0x5F000014 的 ctor（idx 18）自配节点、行为就是 0x426340（九态选关机）——不可覆写。
        entry = self.p4_45c740_entry(0)               # 0x4537DC 0x45C740(0x4AB5CC, 0, &buf)
        st["45c740_buf"] = entry
        self.stream_reset()                           # 0x4537E8 0x401C99 → 0x45FB80
        # 0x4537F1..0x453809：`0x45FE10(0x4100000D, 项+0x4C)` —— **应用场景**（不是命中结算）。
        # 项+0x4C = 该记录附件的内存指针；复刻侧不持久化 0x4AB5CC 的附件表，默认附件
        # = 资源记录 #0x4E（0x45C360 的默认记录构造：malloc size(0x4E) + 0x45DDA0(0x4E) 模板）
        # = pages_data.json 的 scene0（14 层/168 色带/74 背景实体）＝页3 的街市场景。
        # ⚠ 旧实现误调 `_p4_43c9c2`（0x43C9C2 是命中反应函数，参数是弹/靶指针），
        # 传 None 时因 k=0 直接返回 ⇒ 页12 永远不装场景 ⇒ 黑底（用户实测）。
        self.apply_scene(self.data["scene0"])         # 0x4537F1 → 0x45FE10
        if not self.timer.set_period(0):              # 0x45380E 0x45A490(0)
            self.flags.set(FLAG_EXIT)                 # 0x45381E 0x45AF30(0x40)

    def page12_step(self) -> bool:
        """`0x4538E0` 全序列：泵 → 上屏(0x458CB0) → 0x4562A0 色带 → 输入 →
        SetCursorPos(0x140,0xF0) → 系统键 → **0x4562A0 色带（第二次）** →
        0x458F80 合成 → 0x45AFF0(0x4AB5C0, 0)。"""
        self.keys.update(self.inp.rec)
        self.begin_frame()
        self.band_draw()                              # 0x4538F4 第一次
        self.key_command(self.inp.rec.key)
        self.band_draw()                              # 0x45392E 第二次
        self.tick_ui(self.ui4fc)                      # 0x458F80：4FC 行为
        self.tick_ui(self.ui52c)                      #         52C 行为
        self.ui4fc = [e for e in self.ui4fc if e.alive]
        self.ui52c = [e for e in self.ui52c if e.alive]
        self.draw()
        self.band_advance()
        return self.flags.is_empty()

    def page12_finish(self) -> None:
        """`0x453970`：KillTimer → 0xB4 fill+present ×2 → 0x44CEE0 → 页号映射：
        0x100 → 页0、0x200 → 页3、0x10000 → [0x4AB5C8]==0x20008 ? 页15 : 页4、
        其它 → 页0xFF。"""
        self.timer.kill()
        self.canvas.fill(0xB4); self.present()
        self.canvas.fill(0xB4); self.present()
        self.layers.free_all()
        r = self.flags.lowest()
        if r == 0x100:
            self.page = 0
        elif r == 0x200:
            self.page = 3
        elif r == 0x10000:
            stage = self.p4_stat.get(0x4AB5C8, 0)
            self.page = 15 if stage == 0x20008 else 4   # 0x4539EE: 鍛錬 stage 2 → 页15
        else:
            self.page = 0xFF

    # ---- 页8/9/10：游戏结束/结算（0x453050/0x453300/0x4535A0）--------------------
    def page_results_enter(self) -> None:
        """`0x453050`：装调色板 2 → SetCursorPos(320,240) → SetPeriod(0) → 场景重置。"""
        self.flags.clear()
        self.screen_fill = -1
        self.pal = self._load_pal(2)
        self.pal_now = self.pal
        self.inp.set_pos(320, 240)
        self.inp.set_preset4(0, (320, 240))
        self.scene_reset()
        self.timer.set_period(0)

    def page_results_step(self) -> bool:
        """`0x453300`：泵 → draw → 色带 → 输入 → SetCursorPos → key → 色带 → 旗标。"""
        self.keys.update(self.inp.rec)
        self.key_command(self.inp.rec.key)
        self.begin_frame()
        self.band_draw()
        self.draw()
        self.band_advance()
        return self.flags.is_empty()

    def page_results_finish(self) -> None:
        """`0x4535A0`：KillTimer → 0xB4 fill+present ×2 → 释放层 → 页3（菜单）。"""
        self.timer.kill()
        self.canvas.fill(0xB4); self.present()
        self.canvas.fill(0xB4); self.present()
        self.layers.free_all()
        self.page = 3                                 # 0x4535A0 无额外映射 → 默认回菜单

    # ---- 页15：第二关游戏画面（0x454950/0x454B30/0x454CB0）--------------------
    def page15_enter(self) -> None:
        """`0x454950`：第二关的进场（与页4 的 0x4505B0 同族但独立）。装调色板/层/
        生成 0x6B000001（舞台总控）→ 20 音效槽 → VM init → SetPeriod。"""
        self.flags.clear()
        self.screen_fill = -1
        self.p4_frames = 0
        self.p4_intro_gate = False
        self._p4_sys = 0
        self.p4_ccc8 = 1
        self.pal = self._load_pal(1)
        self.pal_now = self.pal
        self.p4_load_palette(1)
        b = self.p4_block()
        self.p4_replay_header(b)
        self.p4_write_state(b)
        self.p4_engine(self._p4_dword(b, 0x16), self._p4_sword(b, 0x14),
                       self._p4_sbyte(b, 0x1A), self._p4_sbyte(b, 0x19))
        for a in range(0x14, 0x24, 4):
            self.p4_stat[a] = 0
        self.sysf.clear()
        self.p4_replay_reset()
        self.p4_layer_params()
        self.p4_load_palette(1)
        self.inp.set_pos(0, 0)
        for slot, wav in P4_SE_SLOTS:
            self.load_wave(slot, wav)
        self.vm_init_script(self._p4_dword(b, 0x0E))
        self.sysf.clear()
        self.vm_step_frame()
        self.p4_speed = 1
        self.timer.set_period(0)
        # 0x454950 的主体（与 0x4505B0 不同）：额外装层0/1（bm_ora/bm_orb）+
        # 生成 0x6B000001（舞台总控实体）→ 0x4AD52C
        self.layers.bind(0, 7)                        # bm_cm48
        self.layers.bind(1, 8)                        # bm_cm32
        self._p4_454950_extra()                       # 0x6B000001 + 音效
        self.p4_enter_ok = self.flags.is_empty()

    def _p4_454950_extra(self) -> None:
        """0x454950 的独有部分（与页4 enter 的差异）：0x6B000001 舞台总控 +
        音效槽 0x15/0x1A/0x2A/0x2B。"""
        self.stage_globals_begin()
        # 0x454A6A: 0x430400(rec, 0, 0, 0x6B000001, 0) → 0x44B140(0x4AD52C, rec)
        _intro = self.spawn(self.ui52c, 0x6B000001)
        _intro.beh = "intro_6b"
        _intro.p["state"] = 0
        _intro.p["cnt"] = 0
        for slot, wav in ((0x0B, 0x15), (0x15, 0x27), (0x1A, 0x28), (0x2A, 0x1C)):
            self.load_wave(slot, wav)

    def page15_step(self) -> bool:
        """`0x454B30`：与页4 step 同族（0x458E70/0x458EF0 遍），但跳过流程 VM。"""
        return self.p4_step()

    def page15_finish(self) -> None:
        """`0x454CB0`：与页4 finish 同族。"""
        self.p4_finish()

    # ---- 页5：記錄（排行榜显示）——0x452730/0x452890（2026-11-11 按反汇编全序列重写）----
    def page5_enter(self) -> None:
        """`0x452730` 全序列：

        1. 亮度/对比度字段(0x4AB5B8 的 0x1FC0000/0xFE000000，各 *4-0xC8) →
           0x44CDF0(0x4AA7B0, 2, 参) 装调色板 2（失败 → 旗标 2）；
        2. 0x44E620(inp, 预设2, 0x140, 0, 0) + 0x44EDA0(inp, 0)；
        3. 0x450140(0x4AB4B0, 1, 0x24)（槽1 ← wave 36 菜单旋律；失败 → 旗标 8）；
        4. 0x458D60 场景重置；
        5. 生成 0x6F000003 @(0,0) prm=-1 入 0x4AD52C（排行榜总控）；
        6. byte[0x56CCD8]=0；SetPeriod(0)（失败 → 旗标 0x40）。"""
        self.flags.clear()
        self.screen_fill = -1
        self.pal = self._load_pal(2)                 # 亮度参 field*4-0xC8（复刻侧整表装载）
        self.pal_now = self.pal
        self.inp.set_pos(0x140, 0)                   # 0x44E620(2, 0x140, 0, 0)
        self.inp.set_preset4(2, (0x140, 0))
        self.scene_reset()
        self.scene_ab = False                        # byte[0x56CCD8] = 0
        e = self.spawn(self.ui52c, 0x6F000003, a3=-1)
        # 0x43D8F0 ctor：[+0x1C]=p3(-1)、[+0x24]=(指针Y*0x5397829D)>>36
        e.a3 = -1
        e.aux = _rank_magic_div(int(getattr(self.inp, "y", 0)) & 0xFFFFFFFF)
        if not self.sound_bind(1, 0x24):             # 0x450140(0x4AB4B0, 1, 0x24)
            self.flags.set(8)                        # 0x4527BB 0x45AF30(8)
        self.inp.set_mode(0)                         # 0x44EDA0(0x4AB454, 0)
        self.timer.set_period(0)

    def page5_step(self) -> bool:
        """`0x452890` 全序列：泵/上屏（run.py+begin_frame）→ 输入 → 系统键 →
        0x4562A0 色带 → **0x458F80 合成**（4CC→4CC渲→4FC行为→52C行为→4FC渲→色带推进）→
        0x45AFF0(0x4AB5C0,0) 返回旗标空。"""
        self.keys.update(self.inp.rec)
        self.key_command(self.inp.rec.key)
        self.begin_frame()
        self.band_draw()                             # 0x4562A0（在合成**前**）
        self.tick_ui(self.ui4fc)                     # 0x44B0D0（4FC 行为遍）
        self.tick_ui(self.ui52c)                     # 0x445A30（52C 行为遍）
        # 0x401C5D（0x44B0D0/0x445A30 的死体摘链）：行为返回 0 的实体出队
        self.ui4fc = [e for e in self.ui4fc if e.alive]
        self.ui52c = [e for e in self.ui52c if e.alive]
        self.draw()                                  # 0x430840 显示表两遍（4CC/4FC）+文字
        self.band_advance()                          # 0x456270
        return self.flags.is_empty()

    def page5_finish(self) -> None:
        """`0x452910`：KillTimer → 0xB4 fill+present ×2 → 0x44CEE0 → 页3。"""
        self.timer.kill()
        self.canvas.fill(0xB4); self.present()
        self.canvas.fill(0xB4); self.present()
        self.layers.free_all()
        self.page = 3                                 # 0x452910 无映射 → 默认回页3

    # ---- 页6：調整（设置画面）——0x4523C0/0x4525E0/0x452660（2026-11-11 全序列）----
    def page6_enter(self) -> None:
        """`0x4523C0` 全序列：0x44CDF0(2, 0, 0, -256) 调色板2 →
        **层 0 ← 资源 0xB(bm_st1)、层 1 ← 0xC(bm_st2)、层 2 ← 0xD(bm_st3)** +
        0x44CE60 色键 0 ×3 → 0x44E620(预设 1 @(0,0)) → 0x44EDA0(0) → 0x458D60 场景重置 →
        0x6F00000A @(0,0) prm=0 入 52C（調整总控 0x444A30，ctor 0x43D9DD：
        [+0x2C]=0x45AFC0(0x4AB5B8,0x3F000)）→ 0x4F000001 网格
        （x=0 步 0x78 ≤0x2D0、y=0 步 0x50 ≤0x230、prm=rand&3）入 0x4AD4CC →
        SetPeriod(0)（失败旗标 0x40）。"""
        self.flags.clear()
        self.screen_fill = -1
        # 0x4523D7..0x45244A（2026-11-13 读定案）：调色板 2（bm_pald，淡入参 -256）→
        # **层 0 ← 资源 0xB(bm_st1)、层 1 ← 0xC(bm_st2)、层 2 ← 0xD(bm_st3)** ——
        # push 序：先 push 资源号、再 push 层号（0x4523E0 push 0xB / 0x4523E2 push 0），
        # 即 0x44C640(mgr, 层, 资源)；随后 0x44CE60(0,0)/(1,0)/(2,0) 三次色键 0。
        # 旧实现绑层 11/12/13 ← 资源 0/1/2（把 push 序读反）⇒ 砖块的层 0 没有内容。
        # bm_st1 = 120×80 撃破伝 logo 恰好一块 ⇒ 56 块砖 = logo 墙漂离（exe 調整的本貌）。
        self.pal = self._load_pal(2)
        self.pal_now = self.pal
        if not self.layers.load(0, 11) or not self.layers.load(1, 12) or not self.layers.load(2, 13):
            self.flags.set(FLAG_LAYER_FAIL)          # 0x45244C 0x45AF30(2)
        for n in (0, 1, 2):
            self.layers.color_key(n, 0)              # 0x44CE60
        self.inp.set_pos(0, 0)                       # 0x44E620(1, 0, 0, 0)
        self.inp.set_preset4(1, (0, 0))
        self.inp.set_mode(0)                         # 0x44EDA0(0)
        self.scene_reset()
        e = self.spawn(self.ui52c, 0x6F00000A)
        e.beh = "adjust_root"                        # 0x444A30
        e.a3 = 0                                     # [+0x1C] 态
        e.aux = 0                                    # [+0x24]
        import random as _r
        y = 0
        while y <= 0x230:                            # 0x452515..0x452537（y 内层步 0x50）
            x = 0
            while x <= 0x2D0:                        # x 外层步 0x78（0x4524FE..0x452537）
                prm = _r.randrange(0x7FFFFFFF) & 3   # 0x4524B9 rand & 3
                g = self.spawn(self.trailq, 0x4F000001, x, y, prm)   # 0x4AD4CC（0x401686）
                g.beh = "adjust_tile"                # 0x401910 → 0x4381B0
                # ctor case 0x4369E6（0x4F000001，ebx=0）：
                # ★ spawn 不代写 raw[4]/raw[8]（fx12_spawn 同款陷阱）——不补写则 56 块砖
                #   全部叠在 (0,0)（2026-11-14 实测"調整只剩一块砖"根因之一）
                g.d32(0x04, x & 0xFFFFFFFF)          # [0x4] = rec0（基础 ctor 0x430475）
                g.d32(0x08, y & 0xFFFFFFFF)          # [0x8] = rec4（0x43047A）
                g.d32(0x1C, 0)                       # [0x1C] = 0（反弹界）
                g.d32(0x20, 0)                       # [0x20] = 0（y 累加器，32.5 定点）
                g.d32(0x24, 1 if prm & 1 else 0xFFFFFFFF)   # [0x24] = (param&1)?+1:−1
                g.d32(0x28, 1 if prm & 2 else 0xFFFFFFFF)   # [0x28] = (param&2)?+1:−1（帧计数初值）
                g.disp = DisplayNode(0, [0, 0, 0x78, 0x50],          # 层 0（ebx）、rect (0,0,0x78,0x50)
                                     [x - 0x3C, y - 0x28])           # dst = (x−0x3C, y−0x28)
                x += 0x78
            y += 0x50
        self.timer.set_period(0)

    def page6_step(self) -> bool:
        """`0x4525E0`：… → 0x4562A0 色带 → 0x458F80 合成（0x43A350 tick 0x4AD4CC
        → 0x430840 渲 → 0x44B0D0(4FC) → 0x445A30(52C) → 渲）→ 旗标测试。
        旧版漏了 0x4AD4CC 的行为遍 ⇒ 調整砖块冻结在出生帧（白块满屏）。"""
        self.keys.update(self.inp.rec)
        self.key_command(self.inp.rec.key)
        self.begin_frame()
        self.band_draw()
        self.tick_ui(self.trailq)                    # 0x458F80 第一道 0x43A350(0x4AD4CC)
        self.tick_ui(self.ui4fc)
        self.tick_ui(self.ui52c)
        self.trailq = [e for e in self.trailq if e.alive]
        self.ui4fc = [e for e in self.ui4fc if e.alive]
        self.ui52c = [e for e in self.ui52c if e.alive]
        self.draw()
        self.band_advance()
        return self.flags.is_empty()

    def page6_finish(self) -> None:
        """`0x452660` 全序列：0x44F950 停 MIDI → 0x45A510 停计时器（失败旗标 0x40）→
        0x44D200(0xB4)+present ×2 → 0x44CEE0 层释放 → 0x45B070 最低旗标：
        0x100→页0、0x200/0x10000→页3、其它→0xFF（0x4526C7..0x4526FE 实测，
        旧注 0x1000000→页11 属页5 的 0x452910 串写）。"""
        self.midi_stop()
        if not self.timer.kill():
            self.flags.set(FLAG_EXIT)                # 0x45267B 0x45AF30(0x40)
        self.canvas.fill(0xB4); self.present()
        self.canvas.fill(0xB4); self.present()
        self.layers.free_all()
        r = self.flags.lowest()
        if r == 0x100:
            self.page = 0
        elif r in (0x200, 0x10000):
            self.page = 3
        else:
            self.page = 0xFF

    # ---- 页14：OP movie（页3 的 0x2000000 出口）--------------------------------
    def page14_enter(self) -> None:
        """`0x453A60`：装调色板 → SetPeriod。"""
        self.flags.clear()
        self.screen_fill = -1
        self.pal = self._load_pal(2)
        self.pal_now = self.pal
        self.timer.set_period(0)

    def page14_step(self) -> bool:
        """`0x453EA0`：播放 OP 动画帧。"""
        self.begin_frame()
        self.draw()
        return not self.flags.is_empty()              # 旗标非空 → 离页

    def page14_finish(self) -> None:
        self.canvas.fill(0xB4); self.present()
        self.canvas.fill(0xB4); self.present()
        self.layers.free_all()
        self.page = 3                                 # OP 完 → 回页3

    def _load_pal(self, idx: int):
        """加载第 idx 号调色板（从 pages_data.json 的 palettes）。"""
        key = str(idx)
        if "palettes" in self.data and key in self.data["palettes"]:
            import numpy as _np
            return _np.array(self.data["palettes"][key], dtype=_np.uint8)
        return self.pal

    # ---- 页13 用到的两条外部调用（脚本 VM 未移植，音频已接上）----------------
    def flow_script_load(self, slot: int, ident: int) -> bool:
        """`0x450140(0x4AB4B0, slot, id)` = **波形装载**（槽数组 `mgr+8+slot*4`）。

        旧文档曾把它当作"流程脚本槽"，但 0x450140 的实体是 0x401b0e 读 wave、
        vtable+0x2c/+0x4c 做 DirectSound Lock/Unlock（失败串 0x4A4860
        "Could not open wave file!"）；页13 的 20 项 = 槽 0..0x13 ← wave 21..40。
        流程 VM（0x450FE0）只在页4 step 里 tick（唯一 caller 0x451327）。
        """
        self.p13_scripts = getattr(self, "p13_scripts", {})
        self.p13_scripts[int(slot)] = int(ident)
        return self.load_wave(slot, ident)

    def midi_play(self, ident: int) -> bool:
        """0x44F600(0x4AB514, loop=1, id)：BGM #id（资源 rom#1..20）。"""
        if self.audio is None:
            self.log(f"0x44F600 MIDI play id={ident}（静音模式）")
            return True
        ok = self.audio.bgm(ident, loop=True)
        self.log(f"0x44F600 MIDI play id={ident} ok={ok}")
        return ok

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
        if hi == 0x46000000:
            if type_word == 0x46000001:
                # 0x435AF8 ctor：层 2、src (0x120,0x180,0x1DF,0x23F)、
                # dst=(x-96, y-96)、[+0x40]=0x4014E7（→ 0x437FC0 前 160F 静止后滑出）
                e.beh = "panel_46"                # 行为 0x437FC0
                e.rect = (0x120, 0x180, 0x1DF, 0x23F)
                e.a3 = 0                          # 滑出位移累计
                e.disp = DisplayNode(
                    layer=2, rect=[0x120, 0x180, 0x1DF, 0x23F],
                    dst=[x - 0x60, y - 0x60])     # 0x435B4A sub 0x60
            return e
        if hi == 0x42000000:
            # 0x42 家族（脚本 OP03 的摆放物）。目前只实现 0x42000004（色块条）；
            # 其余先挂一个安全空行为，避免分发时 e.beh 未定义导致崩溃（§16.81 的 ctor 表）：
            #   0x42000001 ctor 0x43567C / 行为 0x437940（阶段节拍，t 满 0x102 结束）
            #   0x42000002 ctor 0x4356E5 / 行为 0x437B00（计时 spawner）
            #   0x42000005 ctor 0x4358B4 / 行为 0x437E50
            if type_word == 0x42000001:
                e.beh = "phase_driver"
            elif type_word == 0x42000002:
                e.beh = "timed_spawner"
                e.a3 = -72          # [+0x20]
                e.aux = 144         # [+0x24]
            elif type_word == 0x42000005:
                e.beh = "op03_misc"
            elif type_word == 0x42000004:
                # 0x43578A ctor：尺寸按 desc 索引取 {12,18,36,54}
                e.beh = "bar_block"               # 行为 0x437DB0
                e.aux = 0x24                      # [+0x24] 初值（每帧 -1）
                e.a4 = 0x18                       # [+0x28]，宽度系数
            return e
        if hi == 0x6F000000:
            idx = type_word - 0x6F000001
            if idx == 0:
                e.beh = "open_timeline"          # 0x43DE30
                e.bgc = 0xB4                     # ctor: [ent+0x20] = 0xB4
            elif idx == 1:
                e.beh = "opmovie"                # 0x43E1C0
            elif idx == 2:
                # 0x43D8F0 ctor：[+0x1C]=rec[3]、[+0x24]=(指针Y*0x5397829D)>>36（=Y/49）；
                # 行为 0x43E410（排行榜段渲染，页5/页2 共用）
                e.beh = "scene_segment"          # 0x43E410
                e.aux = _rank_magic_div(int(self.inp.y) & 0xFFFFFFFF)   # [+0x24]
                e.a3 = int(a3) if a3 else 0                             # [+0x1C]
            elif idx == 4:
                # 0x43D951 ctor（0x6F000005，EDG2 t=0 生成）：行为 0x4013FC→0x4415F0
                # ＝结局调色板/画集控制器（[0x1C] 帧计数，检查点 0xB4/0x1884/0x33AE）
                e.beh = 0x4415F0
                e.d32(0x1C, 0)
            elif idx == 5:
                # 0x43D970 ctor（页13 的选择画面总控）：[1C]=[20]=[24]=[28]=0，
                # 并 `0x45B0E0(0x4AB5B0, 0xC000, 0)` 把"选中槽"字段清 0；
                # 行为 0x43EDB0（7 态机，§16.118）
                e.beh = "psel"
                e.a3 = 0            # [+0x1C] 状态
                e.a4 = 0            # [+0x20] 状态内帧计数
                e.aux = 0           # [+0x24] 上次槽位
                self.keys.set_field(0xC000, 0)
            elif idx == 6:
                # 0x43D9A8 ctor（页13 的全屏人像）：[1C]=[20]=[24]=0，然后再清一次 0xC000 字段；
                # 行为 0x43F340：首帧把 res_79（资源 0x4F，320×60 = 4 张 80×60 人像）的
                # 左 80 列 × 60 行按 8 倍铺满整屏，随后生成 0x4F000009
                e.beh = "portrait"
                e.p["drawn"] = False
                self.keys.set_field(0xC000, 0)
            elif idx == 7:
                e.beh = "title_timeline"         # 0x43F560
                e.t = int(self.data["page2"]["timer_start"])
            else:
                e.beh = f"unimpl_6F_{idx}"
                self.log(f"ui 0x6F idx {idx} 未实现（§16.7）")
        elif hi == 0x61000000:
            # 跳表 0x4273C0，索引 = type - 0x61000001（0x427259/0x42729A/0x4272B1/0x4272DD/
            # 0x42730B/0x427332/0x42735E/0x427385）；行为 thunk → 0x427510/0x427600/0x427690/0x427710
            if type_word == 0x61000005:
                e.beh = "flash"                 # 0x42730B + 行为 0x427600
                e.aux, e.a3, e.a4 = 0, 0, 0      # 由生成方按 desc 填 (-255/0/8 等)
            elif type_word == 0x61000007:
                # init 0x42735E：[+0x1C]=rec0(当前)、[+0x20]=rec1(目标)、[+0x24]=rec3(步进)、[+0x28]=0
                e.beh = "bgmvol"                # 行为 0x427690：每 8 帧 SysEx 主音量（0x44F950）
                e.aux, e.a3, e.a4 = int(x), int(y), int(a3)
                e.t = 0                         # [+0x28] 帧计数
            elif type_word == 0x61000002:
                # ctor 0x42729A：`push 2; 0x45AF30(0x56CC84)` —— 生成即 **冻结 VM**（bit2 置）；
                # 行为 0x427510 在两队列清空且 0x56CCB8 bit15 清时 `0x45AF60(…,2)` 解冻并死。
                # 2026-11-12 修：旧实现极性反了（清空时置位）⇒ VM 在战斗后假死、关卡无法推进。
                e.beh = "seq_gate"
                self.sysf.bits |= 2
            elif type_word == 0x61000003:
                # init 0x4272B1：[+0x1C]=0；一次性 0x45B0A0(0x56CCB8, rec3, rec0!=0)，行为 0x430520 首帧死
                e.beh = "stat_bits"
                e.aux, e.a3 = int(x), int(a3)
            elif type_word == 0x61000006:
                e.beh = "check_1000"            # init 0x427332：0x45AF30(0x56CCB8,0x1000)→[0x56CCB3]=1
            elif type_word == 0x61000008:
                # init 0x427385：[+0x1C]=(rec0+0xF)<<5、[+0x20]=rec0(mode)、[+0x24]=-256、[+0x28]=8；
                # 行为 0x427710：mode 0 = 每 4 帧 0x459AE0(0x56B95C)（输入录像 tick）+ 倒计时，无视觉
                e.beh = "recdrv"
                e.aux = (int(x) + 0xF) << 5
                e.a3 = int(x)
                e.a4 = -256
                e.t = 8
            elif type_word == 0x61000001:
                # ctor 0x427259：`push 0x8000; 0x45AF30(0x56CCB8)`（bit15 置 → 0x427510 门
                # 保持关闭）；[+0x20]=rec0(掩码)、[+0x24]=rec1(生成数)、[+0x28]=rec3(生成型)。
                # 行为 0x427450：`(counter & rec0)==0` 时往 0x4AD43C 生成 rec3 型敌机
                # （x=664、y=60+rand%360），共 rec1 个；完毕清 bit15 并死。
                # 2026-11-12 落地：此前落 "fade_in" 未实现 ⇒ 关1 群生段缺失。
                e.beh = "crowd_spawn"
                self.sysb8.bits = (self.sysb8.bits | 0x8000) & 0xFFFFFFFF
                self.p4_stat[0x56CCB8] = self.sysb8.bits
                e.aux = 0                  # counter（[ent+0x1C]）
                e.a3 = int(x) & 0xFFFFFFFF  # [+0x20] 掩码 = rec0
                e.a4 = int(y) & 0xFFFFFFFF  # [+0x24] 剩余生成数 = rec1
                e.p["spawn_type"] = int(a3)  # [+0x28] 生成型 = rec3
                e.p["spawned"] = 0
            else:
                # 未实现的 0x61 型：空转兜底。旧版落 "fade_in"（0x427710 淡入）——
                # 0x61000004 落进来时每帧 fade_to(-256→0) 把整屏压黑再渐亮
                # （2026-11-14 实测"怒击破黑屏"根因；已改由 page4.p4_spawn_61000004
                #   走 0x427580 真行为）。这里保留空转，防止其它未知型再劫持调色板。
                e.beh = "default"
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
                # 0x424518..0x42456C：src=(0,0,0x17F,0x7F)，dst 由 0x45A690(0x80,0x50) 返回
                # → 节点 (0,0,383,127)@(128,80)，层13=bm_mn（撃破伝 大字区）
                e.disp = DisplayNode(0x0D, [0, 0, 0x17F, 0x7F], [0x80, 0x50])
                e.a3 = 0                          # [ent+0x1C] 状态
                e.a4 = 0                          # [ent+0x20] 当前选中（ebp 落点）
                e.aux = 0                         # [ent+0x24] 停留计数
                e.p["sel"] = 0                    # [ent+0x28] 确认时的选中项
            elif idx == 6:                        # 0x5F000008 ctor 0x4246AE：説明塊/説明行（層2 = bm_st3）
                # rec3<0 ⇒ 行为 0x430520（[0x1C]-- 减到 0 死；-1 ⇒ 永生）+ 固定窗
                # (0,0x270,0x17F,0x2B7) dst (0xC,0xC)＝操作説明塊。
                # rec3>=0 ⇒ 行为 0x425960（説明行：rect 每帧按 (seg+[0x1C]) 查表重算）、
                # dst (0x80,0x190)＝底部説明行（0x444360 再入時 prm=9）。
                if int(a3) < 0:
                    e.beh = 0x430520
                    e.d32(0x1C, int(a3) & 0xFFFFFFFF)
                    e.disp = DisplayNode(2, [0, 0x270, 0x17F, 0x2B7], [0xC, 0xC])
                else:
                    e.beh = 0x425960
                    e.d32(0x1C, int(a3) & 0xFFFFFFFF)
                    e.disp = DisplayNode(2, [0, 0, 0x17F, 0x17], [0x80, 0x190])
                e.node = e.disp
                e.disp.active = 1
            elif idx == 7:                        # 0x5F000009 ctor 0x424771：メニュー行ラベル（層1 = bm_st2）
                # [0x1C]=rec3%9（点滅比較行）、[0x20]=0（点滅カウンタ）、
                # rect = ((rec3/9)*128, (rec3%9)*32, +127, +31)＝bm_st2 の 128×32 窃、
                # dst = (0x88, (rec3%9)*32+0x60)、行為 0x425AD0（懸停 16 幀点滅）。
                # rec3>=0x10 且 0x4AB5B0 bit0x80 清 ⇒ rect 整体 -0x80（第二窃块）。
                prm = int(a3)
                col = prm % 9
                row = prm // 9
                e.beh = 0x425AD0
                e.d32(0x1C, col & 0xFFFFFFFF)
                e.d32(0x20, 0)
                l, t = row * 128, col * 32
                if prm >= 0x10 and not self.keys.test(0x80):
                    # 0x424849..0x424853 压栈 (b=0, r=-0x80, t=0, l=-0x80) ⇒
                    # 0x45A790 只把 **l/r 左移 0x80**（t/b 不动）：第二窃块
                    # （x=128）的行 16/17 没有自己的"他設定/完了"字模，复用第一
                    # 窃块同列（x=0）。旧实现多减了 t ⇒ 取到块内第 3/4 行，
                    # 再叠上"再入重复生成"的整套标签 = 整页重叠。
                    l -= 0x80
                e.disp = DisplayNode(1, [l, t, l + 127, t + 31], [0x88, col * 32 + 0x60])
                e.node = e.disp
                e.disp.active = 1                 # 0x42481F byte[node+0x1C] = 1
            elif idx == 8:                        # 0x5F00000A ctor 0x424868：ON/OFF 行（層1）
                # [0x1C]=rec3（0x4AB5B0 ビットマスク）、[0x20]=rec1(y)＝窃基準、
                # rect (0x100,0,0x13F,0)（t/b 行為每帧重算＝有/窓セル切替）、
                # dst = (0x198, x)、行為 0x425B20。
                e.beh = 0x425B20
                e.d32(0x1C, int(a3) & 0xFFFFFFFF)
                e.d32(0x20, int(y) & 0xFFFFFFFF)
                e.disp = DisplayNode(1, [0x100, 0, 0x13F, 0], [0x198, int(x)])
                e.node = e.disp
                e.disp.active = 1
            elif idx == 9:                        # 0x5F00000B ctor 0x4248CE：キー桁 1 の位（層1）
                # [0x1C]=rec3（0x4AB5B8 フィールドマスク）、[0x20]=0（ライブ値ポインタ＝NULL）、
                # rect (0,0,0,0)（行為每帧重算）、dst = (0x1B8, y)、行為 0x425B70、初期不可視。
                e.beh = 0x425B70
                e.d32(0x1C, int(a3) & 0xFFFFFFFF)
                e.d32(0x20, 0)
                e.disp = DisplayNode(1, [0, 0, 0, 0], [0x1B8, int(y)])
                e.node = e.disp
                e.disp.active = 0                 # 0x424942 byte[node+0x1C] = 0
            elif idx == 10:                       # 0x5F00000C ctor 0x42494F：キー桁 10 の位（層1）
                # [0x1C]=rec3、[0x20]=rec0（ライブ値ポインタ＝0）、
                # dst = (0x198, y)、行為 0x425C10、初期不可視。
                e.beh = 0x425C10
                e.d32(0x1C, int(a3) & 0xFFFFFFFF)
                e.d32(0x20, int(x) & 0xFFFFFFFF)
                e.disp = DisplayNode(1, [0, 0, 0, 0], [0x198, int(y)])
                e.node = e.disp
                e.disp.active = 0                 # 0x4249C3
            elif idx == 11:                       # 0x5F00000D ctor 0x4249D0：3 値窓（層1）
                # [0x1C]=rec3（0x4AB5B0 bits3-4）、rect (0,y,0,y+0x20)（l/r 行為每帧重算）、
                # dst = (0x188, x)、行為 0x425CD0。
                e.beh = 0x425CD0
                e.d32(0x1C, int(a3) & 0xFFFFFFFF)
                e.disp = DisplayNode(1, [0, int(y), 0, int(y) + 0x20], [0x188, int(x)])
                e.node = e.disp
                e.disp.active = 1
            elif idx == 4:                        # 0x424579 / 0x4258F0（菜单行）
                row = int(a3) & 7
                k = row & 3
                left = MENU_ROW_LEFT[row]
                w = MENU_ROW_WIDTH[row]
                e.beh = "menu_row"
                e.p["row"] = row
                e.disp = DisplayNode(0x0D,
                                     [left, 0x88 + 0x28 * k, left + w, 0xA7 + 0x28 * k],
                                     [MENU_ROW_DSTX[row], 0x118 + 0x30 * k])
            elif idx == 18:                       # 0x5F000014 ctor 0x424D47：选关机总控（层13）
                # ctor：`0x45A750(node, 0,0,0,0)` ⇒ 矩形全 0（状态8 才按 stage 写入）、
                # dst = `0x45A690(0xE0, 0xD0)` ⇒ (0xE0,0xD0)，`[0x1C]=[0x24]=0`。
                # ⚠ 旧实现按 bm_s1lg 的 512×128 大字 @(0x70,0x50) 建模——那是页4 开场
                # 的舞台标题图层，不是选关机（用户实测页12 只剩「第一幕 街市」黑底）。
                e.beh = "stage_title12"
                e.a3 = 0                          # [+0x1C] 状态
                e.a4 = 0                          # [+0x24] 状态内计时
                e.disp = DisplayNode(13, [0, 0, 0, 0], [0xE0, 0xD0])
            elif idx == 19:                       # 0x5F000015 ctor 0x424DA5：关卡预览块
                # 层13、rect (0,0,0,0)、dst (0x120,0xD0)、`[0x1C]=[0x20]=[0x24]=0`；
                # 行为 0x426910 每帧用 `[0x20]<<6` 取 64×64 源块（bm_tr 的关卡编号列）。
                e.beh = "stage_preview12"
                e.a3 = e.a4 = e.aux = 0
                e.disp = DisplayNode(13, [0, 0, 0, 0], [0x120, 0xD0])
            elif idx == 20:                       # 0x5F000016 ctor 0x424E06：難易度标签（三元组历史）
                # 层13、`0x45A750(0,0x100,0x8F,0x12F)`（注意压栈序 b,r,t,l）、
                # dst (0x18,0x18)、历史三元组清零；行为 0x4269B0（可见 = `[0x1C]<8`）。
                e.beh = "stage_hist12"
                e.a3 = e.a4 = e.aux = 0
                e.disp = DisplayNode(13, [0, 0x100, 0x8F, 0x12F], [0x18, 0x18])
            elif idx == 21:                       # 0x5F000017 ctor 0x424E6D：周目/关卡文字条
                # 层13、dst (0xC0,0x18)、`[0x28] = word[0x4AB5CA] * 0x180`（周目滚动量）、
                # 其余 0；行为 0x4269F0 每帧按目标周目滚动 48px 宽的纵条。
                e.beh = "stage_text12"
                e.a3 = e.a4 = e.aux = 0
                e.p["v28"] = self._stage_week() * 0x180
                e.disp = DisplayNode(13, [0, 0, 0, 0], [0xC0, 0x18])
            elif idx == 25:                       # 0x5F00001B ctor 0x424EDB
                # 选中槽的**高亮框**：每帧按 0x45AFC0(0x4AB5B0,0xC000) 重建源矩形
                # （层3 bm_psel 的第 slot+5 条 48px 带），dst 固定 (0, 0x1C0)。
                e.beh = "psel_band"               # 行为 0x426B20
                # ctor rect (0,0xF0,0xBF,0x11F)；`0x401753(0x1C0, 0)` → eax=0x1C0 进
                # `[node+0x14]`(=dst.x, 见 0x45A189 的 `[+0x14]-l+r`)、edx=0 进 `[+0x18]`(=dst.y)
                e.disp = DisplayNode(3, [0, 0xF0, 0xBF, 0x11F], [0x1C0, 0])
            elif idx == 26:                       # 0x5F00001C ctor 0x424F3C
                # `[+0x1C] = rec[3]`（相位基准 1 或 2）、`[+0x20] = 0`；
                # 源 = 层3 第 a 组带 (0, 48a+0x60, 0xEF, 48a+0x8F)，
                # dst = (x=72a+0x108, y=160a+0x28) —— a=1 照準自動、a=2 照準固定
                a = int(a3) & 0xFF
                e.beh = "psel_blink"              # 行为 0x426BA0
                e.a3 = a                          # [+0x1C]
                e.aux = 0                         # [+0x20]
                # `0x401753(0xA0a+0x28, 0x48a+0x108)`：arg1 → dst.x、arg2 → dst.y
                e.disp = DisplayNode(3, [0, 0x30 * a + 0x60, 0xEF, 0x30 * a + 0x8F],
                                     [0xA0 * a + 0x28, 0x48 * a + 0x108])
            elif idx == 27:                       # 0x5F00001D ctor 0x424FCD
                # 输入设备标签（a=0 鼠 / a=1 操作器），`[+0x1C] = -1` ⇒ 永不死
                a = int(a3) & 0xFF
                e.beh = "psel_hint"               # 行为 0x430520（倒计时）
                e.t = -1
                e.disp = DisplayNode(3, [0, 0x30 * a, 0x8F, 0x30 * a + 0x2F], [0, 0])
            else:
                e.beh = f"unimpl_5F_{idx}"
                self.log(f"ui 0x5F idx {idx} 未实现（§16.7）")
        elif hi == 0x32000000:
            # 0x4308A0 的 **0x32 道具族 ctor**（0x4317C4..0x431B2C，跳表 0x431BAC）：
            # 共通尾 = `[+0x40]=0x432390`、`[+0xC]=0x18`、`[+0x10]=1`、`[+0x18]=1`、
            # `[+0x1C]=0`、`[+0x20]=x<<3`、`[+0x24]=(0x298-x)/10`（0x462D71 商），
            # 节点层 1（bm_cm32）、rect 见下表、dst=(x-0x10,y-0x10)。
            # 之前落 default ⇒ 道具不生成节点、不可见也不可吃。
            e.beh = "p32"
            e.d32(0x14, type_word)
            e.d32(0x04, int(x) & 0xFFFFFFFF)   # 0x4308A0 基类：x
            e.d32(0x08, int(y) & 0xFFFFFFFF)   # 0x4308A0 基类：y
            e.d32(0x1C, 0)
            e.d32(0x20, (int(x) << 3) & 0xFFFFFFFF)
            e.d32(0x24, ((0x298 - int(x)) // 0xA) & 0xFFFFFFFF)  # C 截断除
            e.d32(0x18, 1)
            e.d32(0x0C, 0x18)
            e.raw[0x10] = 1
            _r = P32_RECTS.get(type_word, (0, 0x20, 0x1F, 0x3F))
            e.disp = DisplayNode(layer=1, rect=list(_r),
                                 dst=[int(x) - 0x10, int(y) - 0x10])
        elif hi == 0x31000000:
            # 0x4308A0 的 **0x31 弹族 ctor**（0x4AD49C 队列）的共通尾：
            # 速度取 rec[3]（a3=(vx,vy) 8.8）、[+0x24]/[+0x28]=x/y<<8、
            # [+0x18]=|vx|+|vy|、[+0xC]=半径、[+0x40]=行为 0x4321C0（直线移动）。
            # 每种类型的 rect/层/额外行为在 0x431B30 的 31 项跳表里；这里先落
            # **移动+出屏自灭**（门 0x61000002 需要队列清空），逐型 rect 见表 §15。
            e.d32(0x14, type_word)
            spec = P31_CTOR.get(type_word)
            if spec is not None:
                beh, rad, layer, rect = spec
                e.beh = beh
                e.d32(0x0C, rad)
                vx, vy = a3 if isinstance(a3, tuple) else (0, 0)
                e.d32(0x1C, int(vx) & 0xFFFFFFFF)
                e.d32(0x20, int(vy) & 0xFFFFFFFF)
                e.d32(0x04, int(x) & 0xFFFFFFFF)
                e.d32(0x08, int(y) & 0xFFFFFFFF)
                e.d32(0x24, (int(x) << 8) & 0xFFFFFFFF)
                e.d32(0x28, (int(y) << 8) & 0xFFFFFFFF)
                e.d32(0x18, (abs(int(vx)) + abs(int(vy))) & 0xFFFFFFFF)
                if type_word == 0x31000004:          # ctor 0x430A57：[0x1C]=0、[0x18]=1
                    e.d32(0x1C, 0)
                    e.d32(0x18, 1)
                elif type_word == 0x3100000C:        # ctor 0x430E37：[0x1C]=rec3<<3、[0x20]=rec1
                    e.d32(0x1C, (int(a3) << 3) & 0xFFFFFFFF if isinstance(a3, int) else 0)
                    e.d32(0x20, int(y) & 0xFFFFFFFF)
                    if isinstance(a3, int) and a3 >= 0:
                        rect = (0x120, 0x120, 0x13F, 0x15F)
                    else:
                        rect = (0x120, 0x120, 0x13F, 0x13F)
                elif type_word == 0x31000005:        # ctor 0x430ADE：[0x1C]=0、[0x20]=rec3(标量)、[0x18]=1
                    e.d32(0x1C, 0)
                    e.d32(0x20, int(a3) & 0xFFFFFFFF if isinstance(a3, int) else 0)
                    e.d32(0x18, 1)
                elif type_word in (0x31000008, 0x31000009, 0x31000011,
                                   0x31000014, 0x31000018):  # ctor [0x1C]=0、[0x18]=1
                    e.d32(0x1C, 0)
                    e.d32(0x18, 1)
                    if type_word == 0x31000018:
                        e.raw[0x10] = 0                 # ctor 0x4313D1 byte[0x10]=0
                elif type_word == 0x3100000D:        # ctor 0x430EE1：8.4 累加器 [0x28]/[0x2C]，[0x20]=−0x100
                    e.d32(0x20, 0xFFFFFF00)
                    e.d32(0x24, 0)
                    e.d32(0x28, (int(x) << 4) & 0xFFFFFFFF)
                    e.d32(0x2C, (int(y) << 4) & 0xFFFFFFFF)
                e.raw[0x10] = 1
                e.disp = DisplayNode(layer=layer, rect=list(rect),
                                     dst=[int(x) - 0xC, int(y) - 0xC])
            else:
                e.beh = "p31"
                vx, vy = a3 if isinstance(a3, tuple) else (0, 0)
                e.d32(0x1C, int(vx) & 0xFFFFFFFF)
                e.d32(0x20, int(vy) & 0xFFFFFFFF)
                e.d32(0x24, (int(x) << 8) & 0xFFFFFFFF)
                e.d32(0x28, (int(y) << 8) & 0xFFFFFFFF)
                e.d32(0x18, (abs(int(vx)) + abs(int(vy))) & 0xFFFFFFFF)
                e.d32(0x0C, 0x18)
                e.raw[0x10] = 1
                e.disp = DisplayNode(layer=0, rect=[0, 0, 0, 0],
                                     dst=[int(x) - 0xC, int(y) - 0xC])
        else:
            e.beh = "default"                     # 0x43DA4F / 0x449AA7
        queue.append(e)
        self.log(f"spawn type=0x{type_word:X} beh={e.beh}")
        return e

    def tick_ui(self, queue: list) -> None:
        for e in queue:
            if not e.alive:
                continue
            if hasattr(e, "m"):                       # 页4：字节模型实体（0x5C，走 [+0x40] 行为）
                # 0x448F80 的 tick：行为返回 0 ⇒ byte[+0x34]=0 + 隐藏节点（0x448FA7..0x448FB0）
                if not self.p4_call_behaviour(e):
                    e.m[0x34] = 0
                    if e.node is not None:
                        e.node.active = 0
                continue
            if e.beh == "bullet_1b":                  # 0x430080：狙击弹（0x1B000001）
                if self.p4_key_test(7):               # 0x430083 0x45AFF0(0x56CCC0,7)：开始键位冻结
                    continue
                nx = (e.s32(4) + 7) & 0xFFFFFFFF      # 0x430097 x += 7
                e.d32(4, nx)
                d = e.disp
                if d is not None:
                    d.dst[0] = (d.dst[0] + 7) & 0xFFFFFFFF   # 0x4300A3 dst.x += 7（dst=ent+0x40 不变）
                    # 右缘渐进裁剪（0x4300AC..0x4300D4）：
                    #   x<=0x1E0 恒 rect.r = rect.l+0x20；x>0x1E0 起 rect.r = rect.l-x+0x200
                    d.rect[2] = (d.rect[0] - nx + 0x200) if nx > 0x1E0 else (d.rect[0] + 0x20)
                if nx < 0x200 and e.s32(0x18) != 0:   # 0x4300D5 jge（有符号）/HP=0 ⇒ 出屏或破
                    continue                          # 0x4300E5 return 1
                self.p4_key_reset(0x10)               # 0x4300E9 0x402400→0x45AF60(0x56CCC0,0x10)
                e.alive = False                       # 0x4300F5 return 0（自杀）
                continue
            if callable(e.beh):                       # 页4：行为直接是函数对象
                e.alive = bool(e.beh(self, e))
                continue
            if isinstance(e.beh, int):                # 页4：int 真址 → p4_call_behaviour
                e.alive = bool(self.p4_call_behaviour(e))
                continue
            if e.beh == "p32":
                # 0x432390 道具行为：闪烁切换 rect 行、水平漂移 [0x24] 递减至 -0x10、
                # y 缓降/落出，x<-0x18 且漂移<0 时自灭（0x32000005 先记分）。
                t = (e.s32(0x1C) + 1) & 0xFFFFFFFF
                e.d32(0x1C, t)
                if e.disp is not None and (t & 9) in (1, 9):
                    # 0x4323A2 的压栈序 (0,0x20,0,0x20)→0x45A790 写 out[0]/out[2]：只滑 rect.l/r
                    d = 0x20 if (t & 9) == 1 else -0x20
                    l, tp, r, b = e.disp.rect
                    e.disp.rect = [l + d, tp, r + d, b]
                acc = (e.s32(0x20) + e.s32(0x24)) & 0xFFFFFFFF
                drift = e.s32(0x24) - 1
                if drift <= -0x10:
                    drift = -0x10
                e.d32(0x20, acc)
                e.d32(0x24, drift & 0xFFFFFFFF)
                y = e.s32(0x08)
                if y < 0x10:
                    y += 1
                    if y <= -0x10:
                        y = -0x10
                    e.d32(0x08, y & 0xFFFFFFFF)
                elif y > 0x1D0:
                    y -= 1
                    if y < 0x1F0:
                        y = 0x1F0
                    e.d32(0x08, y & 0xFFFFFFFF)
                nx = e.s32(0x20) >> 3
                e.d32(0x04, nx & 0xFFFFFFFF)
                if nx < -0x18 and drift < 0:
                    if e.g32(0x14) == 0x32000005:
                        self.p4_45f660()               # 0x432435 → 0x401FD2
                    e.alive = False
                    continue
                if e.disp is not None:
                    e.disp.dst = [nx - 0x10, e.s32(0x08) - 0x10]
                e.alive = e.s32(0x18) != 0
                continue
            if e.beh == "p31":
                # 0x4321C0：8.8 加速度积分 → 屏内(±0x10) 且 [+0x18]!=0 才活
                e.d32(0x24, (e.s32(0x24) + e.s32(0x1C)) & 0xFFFFFFFF)
                e.d32(0x28, (e.s32(0x28) + e.s32(0x20)) & 0xFFFFFFFF)
                nx = e.s32(0x24) >> 8
                ny = e.s32(0x28) >> 8
                e.d32(0x04, nx & 0xFFFFFFFF)
                e.d32(0x08, ny & 0xFFFFFFFF)
                if e.disp is not None:
                    e.disp.dst = [nx - 0xC, ny - 0xC]
                e.alive = (e.s32(0x18) != 0
                           and self.p4_4305f0(e, 0x10) == 1)
                continue
            if e.beh == "open_timeline":
                self._open_timeline(e)
            elif e.beh == "title_timeline":
                self._title_timeline(e)
            elif e.beh == "p2_panel":
                self._p2_panel(e)
            elif e.beh == "opmovie":
                self._opmovie(e)
            elif e.beh == "phase_driver":
                self._phase_driver(e)
            elif e.beh == "timed_spawner":
                self._timed_spawner(e)
            elif e.beh == "op03_misc":
                self._op03_misc(e)
            elif e.beh == "panel_46":
                self._panel46(e)
            elif e.beh == "bar_block":
                self._bar_block(e)
            elif e.beh == "scene_segment":
                self._scene_segment(e)
            elif e.beh == "rank_cell":
                self._rank_cell(e)
            elif e.beh == "adjust_root":
                self._adjust_root(e)
            elif e.beh == "adjust_tile":
                self._adjust_tile(e)
            elif e.beh == "psel":
                self._psel(e)
            elif e.beh == "psel_band":
                self._psel_band(e)
            elif e.beh == "psel_blink":
                self._psel_blink(e)
            elif e.beh == "portrait":
                self._portrait(e)
            elif e.beh == "fx12":
                self._fx12(e)
            elif e.beh == "kanji_actor":
                self._kanji_actor(e)
            elif e.beh == "dot10":
                self._dot10(e)
            elif e.beh == "psel_hint":
                self._psel_hint(e)
            elif e.beh == "menu_root":
                self._menu_root(e)
            elif e.beh == "menu_row":
                self._menu_row(e)
            elif e.beh == "stage_title12":
                self._stage_title12(e)
            elif e.beh == "stage_preview12":
                self._stage_preview12(e)
            elif e.beh == "stage_hist12":
                self._stage_hist12(e)
            elif e.beh == "stage_text12":
                self._stage_text12(e)
            elif e.beh == "scene_bg":
                self._scene_bg(e)
            elif e.beh == "fade_in":
                self._fade_in(e)
            elif e.beh == "flash":
                self._flash(e)
            elif e.beh == "bgmvol":
                self._bgmvol(e)
            elif e.beh == "seq_gate":
                self._seq_gate(e)
            elif e.beh == "crowd_spawn":
                self._crowd_spawn(e)
            elif e.beh == "stat_bits":
                self._stat_bits(e)
            elif e.beh == "check_1000":
                self._check_1000(e)
            elif e.beh == "recdrv":
                self._recdrv(e)
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

    # 0x437FC0（0x46000001，面板：t<=160 静止，之后线性滑出）
    def _panel46(self, e: UiEntity) -> None:
        e.t += 1
        if e.t <= 0xA0:
            # 0x437FFF 分支：x 每帧 -1（向左移），父 y >= -160 时存活
            e.disp.dst[0] -= 1
            if e.disp.dst[1] < -0xA0:
                e.alive = False
            return
        if e.t > 0xA0:                                # 0x437FD2：eax = 0xA0 - t
            v = 0xA0 - e.t
            e.disp.dst[0] += v                        # x 全量
            e.disp.dst[1] += v >> 1                   # y 半量（0x437FDA sar 1）
        if e.disp.dst[1] < -0xA0:                     # 0x437FF5：父 y < -160 结束
            e.alive = False

    # 0x437940（0x42000001，阶段节拍）
    def _phase_driver(self, e: UiEntity) -> None:
        e.t += 1
        if e.t >= 0x102:
            e.alive = False

    # 0x437B00（0x42000002，计时 spawner：-72→0、144 每帧 -2）
    def _timed_spawner(self, e: UiEntity) -> None:
        e.t += 1
        if e.a3 < 0x280:
            e.a3 += 1
            e.aux -= 2
        else:
            e.alive = False

    # 0x437E50（0x42000005，暂不绘制）
    def _op03_misc(self, e: UiEntity) -> None:
        e.t += 1

    # 0x437DB0（0x42000004，色块条：平移 + 变宽）
    def _bar_block(self, e: UiEntity) -> None:
        """x += v>>3、y += v>>4、宽度 = 2*[+0x28]*计数、左边界 = x-宽度（§16.86）。"""
        if e.disp is None:                            # 没有显示节点时（无源矩形）不画
            e.t += 1
            if e.aux <= 0:
                e.alive = False
            return
        v = e.aux
        e.a3 += 1                                     # [+0x20] 计数
        e.aux = v - 1
        e.disp.dst[0] += v >> 3
        e.disp.dst[1] += v >> 4
        w = 2 * e.a4 * e.a3
        x, y = e.disp.dst
        if w > 0:
            self.canvas.fill_rect((max(0, x - w), max(0, y), min(W, x), min(H, y + 4)),
                                  self.bar_color)
        if e.aux <= 0:
            e.alive = False
        e.t += 1

    # 0x43E410（0x6F000003，排行榜段渲染——页5 記録 与 页2 吸引共用；docs/p5_rank_notes.md）
    def _scene_segment(self, e: UiEntity) -> None:
        """0x43E410 全态机（2026-11-11 转写）。

        帧头：seg = (指针Y*0x5397829D)>>36（=Y/49）；上限 = 旗标非空 ? 字段(0xF00000) : 8；
        seg 越界 → seg=上限-1 并 0x44E620(inp,0x140,seg*49+0x18)；bl = (seg != [+0x24])。
        态 = ++[+0x1C]（ctor -1 → 0），跳表 0x43EBA8：
          态0/1 = 构建（0x61000005 闪光 + 4FC 头部表 + 行环 + 0x4017D5 + 行详绘 + 关卡图标行），
          态2/4 = 0x43E7D1（[+0x20]>0x20 → [+0x1C]=3），
          态3   = 0x43E7DC（输入：C/X → 回放；指针横移 ≥0x31 → 8 模式切换重建），
          态5   = 0x43E967（回放装载 0x45D700 → 旗标 0x1000000/0x10000、[0x4AB5C8]=选段）。
        视觉在复刻侧用 e.texts 直绘（exe 是 0x44D330 写 RAM 字形格 + 0x5F00001A 切片贴，
        可观察结果相同）；页2 冻结金标期间只在页5 启用视觉构建。"""
        seg = _rank_magic_div(int(getattr(self.inp, "y", 0)) & 0xFFFFFFFF)
        lim = (self.keys.field(0xF00000) or 8) if self.flags.is_empty() else 8
        if lim <= 0:
            lim = 8
        if seg >= lim:                               # 0x43E475
            seg = max(0, lim - 1)
            self.inp.set_pos(0x140, seg * 49 + 0x18)
        bl = 1 if seg != e.aux else 0                # 0x43E49E setne（[+0x24]=前段号）
        # 帧头派发用 [0x1C]+1（eax 不回写！态体自己决定 [+0x1C] 的去向）
        n = e.t + 1
        if n in (0, 1):                              # 表0/1：构建（0x43E4C0/0x43E504）
            self._rank_build(e, seg, lim, bl)
            e.t = e.t + 2                            # 0x43E7A2..0x43E7AE [0x1C] += 2
        elif n in (2, 4):                            # 表2/4：0x43E7D1 驻留门
            if e.a3 > 0x20:
                e.t = n                              # 0x43E7D7 [0x1C] = eax(=N)
            self._rank_tail(e, seg, bl)
            return
        elif n == 3:                                 # 表3：0x43E7DC 输入
            if self.inp.rec.b0 or self.inp.rec.b1:   # C/X 按住 → [0x1C]=3 钉住
                e.a4 = seg if self.inp.rec.b0 else -1   # 0x43E7F5..0x43E813
                if self.scene_ab:
                    e.a4 = -1
                self._rank_cursor(e)                 # 0x4019FB → 0x43DCB0
                e.t = 3                              # 0x43E7EE
            else:
                dx = int(getattr(self.inp, "x", 0x140)) - 0x140
                if dx < -0x31 or dx > 0x31:          # 0x43E830 出死区 → 模式切换
                    mode = ((1 if self.keys.test(2) else 0)
                            | (2 if self.keys.test(1) else 0)
                            | (4 if self.scene_ab else 0))   # 0x43E839..0x43E874
                    mode = (mode - 1) % 8 if dx < 0 else (mode + 1) % 8
                    bit0, bit1 = mode & 1, (mode >> 1) & 1
                    # 0x45C710 两表：obj[4]=(arg1!=0)、obj[5]=arg2
                    self.p4_45c710(bit0 | (4 if self.scene_ab else 0), bit1)
                    self.p4_45c710(bit0, bit1)
                    self.keys.write(2, bit1)         # 0x45B0A0(0x4AB5B0, 2, …)
                    self.keys.write(1, bit1)         # 0x45B0A0(0x4AB5B0, 1, …)
                    self.scene_ab = bool((mode >> 2) & 1)   # 0x43E908
                    self.inp.set_preset4(2, (0x140, seg * 49 + 0x18))   # 0x43E912
                    self.spawn(self.ui52c, 0x6F000003)   # 0x43E91D 重建（prm=0）
                    e.alive = False                  # return 0
                    return
                self._rank_tail(e, seg, bl)
                return
            self._rank_tail(e, seg, bl)
            # 按住时 [0x1C]=3 → 下帧 N=4（0x43E7D1）→ 再下帧 N=5（回放）——由门推进
            return
        elif n == 5:                                 # 表5：0x43E967 回放出口
            if e.a4 >= 0 and self.p4_45d700(e.a4):
                self.flags.bits |= 0x1000000         # → 页11（回放）
            else:
                self.flags.bits |= 0x10000           # → 页3
            self.theatre = e.a4 & 0xFFFFFFFF         # 0x43E9B6 [0x4AB5C8]
            e.alive = False
            return
        else:                                        # N>5：只有尾段
            self._rank_tail(e, seg, bl)
            return

    # ---- 0x43E4C0 态0/1：排行榜画面构建（层13 ← 资源15 bm_cmrc 字形片） ----
    def _rank_build(self, e: UiEntity, seg: int, lim: int, bl: int) -> None:
        """0x43E4C0..0x43E702（2026-11-11 转写）。

        0x4018B6→0x44B0A0：4FC 队列整备。0x4017D5(this, seg, 0xF)→0x43DD20：
        读选中项 → 0x44C640(层13, 资源15 bm_cmrc) + 0x44CE60(13, 0) 色键 +
        0x45FE10(0x4100000D, 项+0x4C) 放大窗。
        行环 i=0..seg：每行 = 框架格(rec1=0x10001) + 得分十进制位（0x402185：
        低位在 x=0xD8、步 -0x18，格号 = r*8+1）+ 10 字名字格（项+0x12 起）。
        头部 0x49875B 14 项 / 标签 0x4987AC / 关卡图标 0x498794 同为格切片。
        格 → rect：l=24w、t=24b、r=24w+24h-1、b=24b+23（w=格号>>3、b=格号&7、
        h=rec1 高 16 位）。页2 冻结金标期间只在页5 构建。"""
        e.aux = seg                                  # [+0x24] = 当前段
        if self.page != 5:
            return
        self._rank_sel = seg
        # 0x4017D5 → 0x43DD20：层13 ← 资源15 + 色键 0（选中项相关参在零表下为 0）
        self.layers.load(13, 15)
        self.layers.color_key(13, 0)
        self.ui4fc.clear()                           # 0x44B0A0 队列整备
        # 0x43E4C0：rec={x=-0xFF, y=0, 0x61000005, 8} → 亮度 -0xFF → 0 步 8（淡入）
        self.spawn_flash(-0xFF, 0, 8)
        # 头部表 0x49875B（4B/项：b0=dst-y/8、b1=格号低、b2=格宽单位）
        for (b0, b1, b2) in RANK_HEADER_RECORDS:
            self._rank_spawn_cell((6 << 3) | ((b0 << 3) << 16), b1 | (b2 << 16), 0)
        # 标签 0x4987AC（格号表，0 终止；x 从 0x148/0x190 起、步 0x18；y 同步进）
        x0 = 0x190 if self.scene_ab else 0x148
        y0 = 0x190 if self.scene_ab else 0x148
        for (cell, cont) in RANK_LABEL_RECORDS:
            if cont == 0:
                break
            self._rank_spawn_cell((x0 << 16) | y0, cell | 0x10000, 0)
            y0 += 0x18
        # 旗标1 → 附加格（0x43E5F0：rec0=0x1800148、rec1=0x30040）
        if self.keys.test(1):
            self._rank_spawn_cell(0x1800148, 0x30040, 0)
        # 行环（0x43E619..0x43E702）
        for i in range(min(seg + 1, lim)):
            ry = 0x60 + 0x20 * i
            entry = self.p4_45c740_entry(i, self._rank_tbl())
            score = int.from_bytes(entry[0:4], "little")
            self._rank_spawn_cell((0xF0 << 16) | ry, 0x10001, i + 0x10)   # 行框架
            v = score
            xd = 0xD8
            while v > 0:                                                  # 0x402185
                v, r = divmod(v, 10)
                self._rank_spawn_cell(((xd & 0xFFFF) << 16) | (ry & 0xFFFF),
                                      (r * 8 + 1) | 0x10000, i + 0x10)
                xd -= 0x18
            for kk in range(10):                                          # 名字 10 格
                ci = entry[0x12 + kk]
                if ci:
                    self._rank_spawn_cell(((0x140 + 0x18 * kk) & 0xFFFF) << 16
                                          | (ry & 0xFFFF), ci | 0x10000, i + 0x10)
        # 关卡图标行（0x498794，3B/项 ×8；当前模式项不铺=闪烁）
        cur_mode = ((1 if self.keys.test(2) else 0)
                    + (2 if self.keys.test(1) else 0)
                    + (4 if self.scene_ab else 0))
        for k2, (b0, b1, b2) in enumerate(RANK_ICON_RECORDS):
            if k2 != cur_mode:
                self._rank_spawn_cell((((b0 & 0x3FFF) << 2) & 0xFFFF) | 0x200000,
                                      b1 | (b2 << 16), 0)
        e.texts = []

    def _rank_cell(self, e: UiEntity) -> None:
        """0x425D50（0x5F00001A 行为）：节点显隐节拍。t=++[+0x28]；
        [+0x24]==1 → node.active = (t>>3)&1；[+0x24]-0x10==段数(0x4AB5A0/49，此处恒 8)
        → node.active = (t>>4)&1；否则 node.active = 1。恒存活。"""
        e.aux = (e.aux + 1) & 0xFFFFFFFF
        t = e.aux
        if e.disp is not None:
            if e.a4 == 1:
                e.disp.active = (t >> 3) & 1
            elif (e.a4 - 0x10) == 8:                 # 0x4AB5A0/49（页5 复刻恒 8）
                e.disp.active = (t >> 4) & 1
            else:
                e.disp.active = 1
        return True

    def _rank_spawn_cell(self, rec0: int, rec1: int, v: int) -> None:
        """0x44B140(0x4AD4FC, rec{rec0, rec1, 0x5F00001A, v}) 的复刻等价。

        0x424A52 ctor：格 rect = (24w, 24b, 24w+24h-1, 24b+23)（w=rec1>>3、
        b=rec1&7、h=rec1>>16）、dst = (rec0 低 16 位, 高 16 位)、[+0x24]=v。
        行为 0x425D50：v==1 → 节点闪烁 (t>>3)&1；v-0x10==段数 → (t>>4)&1；否则常显。"""
        e2 = self.spawn(self.ui4fc, 0x5F00001A)
        e2.beh = "rank_cell"
        e2.a4 = v
        e2.aux = 0                                   # [+0x28] 计数
        w = ((rec1 & 0xFFFF) >> 3) & 0xFFFFFFFF      # 0x424A69 movsx word → >>3
        b = rec1 & 7                                 # 0x424A79 byte & 7
        h = (rec1 >> 16) & 0xFFFF                    # 0x424A9B word[+6]
        dx = rec0 & 0xFFFF
        dy = (rec0 >> 16) & 0xFFFF
        if dx >= 0x8000:
            dx -= 0x10000
        if dy >= 0x8000:
            dy -= 0x10000
        l = 24 * w
        t = 24 * b
        e2.disp = DisplayNode(13, [l, t, l + 24 * h - 1, t + 23], [dx, dy])

    # ---- 0x444A30（0x6F00000A 調整总控）态机（2026-11-11 转写） ----------------
    def _adjust_tile(self, e: UiEntity) -> None:
        """0x438110（0x4F000001 調整网格砖，ctor case 0x4369E6，行为槽 = **0x401924**）：

        ```
        0x43811C [0x1C] += [0x24]                ; offx += stepx（±1/帧）
        0x438126 [0x20] += [0x28]                ; offy += stepy（±1/帧）
        0x438128 if (offx >= 0x3C)  offx -= 0x78 ; 半格回绕（无缝水波）
        0x43813B if (offx < -0x3C)  offx += 0x78
        0x438146 if (offy >= 0x28)  offy -= 0x50
        0x438154 if (offy < -0x28)  offy += 0x50
        0x43815F node dst = ([0x4]+offx−0x3C, [0x8]+offy−0x28)
        0x438183 return 1                        ; 恒永生
        ```
        旧版误用 0x4381B0（那是 **0x4F000002**（thunk 0x401910，读自机坐标）的行为：
        累加器漂移 + 1750 帧自灭）⇒ 砖块飞出屏、調整页只剩一块砖（2026-11-14 实测）。"""
        offx = (e.s32(0x1C) + e.s32(0x24)) & 0xFFFFFFFF  # 0x43811C
        e.d32(0x1C, offx)
        offy = (e.s32(0x20) + e.s32(0x28)) & 0xFFFFFFFF  # 0x438126
        e.d32(0x20, offy)
        ox = offx - 0x100000000 if offx & 0x80000000 else offx
        if ox >= 0x3C:                                   # 0x438128 jge→jl
            ox -= 0x78
            e.d32(0x1C, ox & 0xFFFFFFFF)                 # 0x438132
        elif ox < -0x3C:                                 # 0x43813B jge
            ox += 0x78
            e.d32(0x1C, ox & 0xFFFFFFFF)                 # 0x438140
        oy = offy - 0x100000000 if offy & 0x80000000 else offy
        if oy >= 0x28:                                   # 0x438146
            oy -= 0x50
            e.d32(0x20, oy & 0xFFFFFFFF)                 # 0x43814B
        elif oy < -0x28:                                 # 0x438154
            oy += 0x50
            e.d32(0x20, oy & 0xFFFFFFFF)                 # 0x438159
        if e.disp is not None:                           # 0x43815F..0x438180
            e.disp.dst[0] = (e.s32(0x04) + ox - 0x3C) & 0xFFFFFFFF
            e.disp.dst[1] = (e.s32(0x08) + oy - 0x28) & 0xFFFFFFFF
        # 0x438183 return 1（永生，无死亡路径）

    def _adjust_root(self, e: UiEntity) -> None:
        """0x444A30：帧头 edi = (指针Y*0x4BDA12F7)>>36（÷54.05 段）；bl = 段!=[+0x20]。
        态跳表 0x445464：0=0x444A86（0x61000005 闪光 rec{0,-0xFF,typ,8}、++[0x1C]）、
        1/3=0x444AD2（[0x24]≥0x20 → ++[0x1C]）、2=0x444AE5（系统键 0x20..0x2F 调
        0x4AB5B8 的 0xF/0xF0/0xF00 字段 + 0x4018C0 重绑输入）、4=0x445415（旗标 0x10000
        → 页3，return 0）、5=0x445431（0x40182A(段!=0) + 态=2）、6/7 走 C/X 表。
        C/X（0x4AB596/97）→ 0x444B7F：`cmp edi,0x11; ja 尾` → 0x44547C 18 行表：
          0=0x444B99（0x4AB5B0 |= 0x200 鍛錬）、1=0x444BAD（0x18 字段 1/3/0 循环 + SE）、
          2=0x444C0D（清 0x4 + 0x4011F9(0x4AB514,4)）、3=0x444C3A（0x4AB5B0 |= 0x400）、
          4/5/6=尾直跳、7=0x444F14、8=0x444ECF（亮度→对比度连算 + 0x444F60 应用）、
          9=0x444C4E（[0x28] BGM 序号循环 ≤0x32）、10=0x444CCA（对比度 0xFE000000 ±2、
          0/100 钳、0x7F→0x63）、11..15=未逐条（0x444D4D/0x444DD0/0x444DF8/0x444E20/
          0x444E34）、16=0x444E91（BGM 序号循环 ≤0xD + BGM 切换旗标）、17=0x444F01。
        尾 0x444F7A：旗标[帧+0x12] → BGM 表 {7,8,9,0xA,0xB,0xC,0xD,0xE,1,2,4,3,6}
        按 [0x28]（9/0xA→0）→ 0x401F69(0x4AB514, …)；旗标[帧+0x13] →
        亮度/对比度重算调色板（0x44CDF0×2）。"""
        seg0 = _adjust_magic_div(int(getattr(self.inp, "y", 0)) & 0xFFFFFFFF)
        # 0x444A5A..0x444A67：`esi = [ent+0x30]*9; edx(段) += esi` —— 行分发用**全域段**
        # （第一页 0..8、他設定页 9..17）。悬停行为 0x425AD0 另读 [0x4AB5A0] 的
        # **基段**（0..8）与行标签 [+0x1C] 比较，故这里只给 _adjust_row 加页基。
        seg = seg0 + (e.g32(0x30) & 0xFFFF) * 9
        bl = 1 if seg != e.aux else 0
        e.aux = seg                                  # [+0x20] = 段（全域）
        st = e.t
        if st != e.p.get("last_st", -1):
            # 0x4453C3：态变化 ⇒ [0x24]=0（驻留计数重启）——旧实现不清 ⇒
            # 行8（完了）进态 3 后立即满足 0x20 驻留、闪光驻留消失
            e.p["dwell"] = 0
            e.p["last_st"] = st
        if st == 0:                                  # 0x444A86
            self._p6_spawn_menu(e.g32(0x30) != 0)    # 0x444A8E 0x444360(メニュー生成)
            f = self.spawn_flash(-0xFF, 0, 8)        # rec{0,-0xFF,typ,8}→淡入
            f.disp = None
            e.t = 1
            return True
        if st in (1, 3):                             # 0x444AD2
            # 0x444AD2 先比较（[0x24] 为上帧尾部自增值）、0x44544A 尾部再 ++ 的顺序
            if e.p.get("dwell", 0) >= 0x20:
                e.t = st + 1                         # 0x444ADD ++[0x1C]
            e.p["dwell"] = e.p.get("dwell", 0) + 1   # 0x44544A [0x24]++（态未变时尾部）
            return True
        if bl:                                       # 0x4453A2：段变化 ⇒ 0x450440(mgr,0)
            self.audio.melody_step()                 # メニュー移動音（0x498FEC 表輪番）
        if st == 2:                                  # 0x444AE5 主交互态（常驻）
            key = self.inp.rec.key
            if 0x20 <= key <= 0x2F:                  # 0x444AF2 系统键 0x20..0x2F
                # 0x444AF2..0x444B28：仅 seg 4/5/6 写 0xF/0xF0/0xF00 字段（攻撃/光撃/捕獲入力），
                # 其余行跳 0x444B32（只读回+重绑）——旧实现 .get(seg, 0xF) 让任何行都写 0xF。
                if seg == 4:
                    self.disp_cfg.write(0xF, key - 0x20)    # 0x444AFE/0x444B01
                elif seg == 5:
                    self.disp_cfg.write(0xF0, key - 0x20)   # 0x444B0B..0x444B14
                elif seg == 6:
                    self.disp_cfg.write(0xF00, key - 0x20)  # 0x444B1D..0x444B28
                f3 = self.disp_cfg.field(0xF00)         # 0x444B32 读回三字段
                f2 = self.disp_cfg.field(0xF0)
                f1 = self.disp_cfg.field(0xF)
                self.inp.rebind_cfg(f3, f2, f1)         # 0x4018C0
            # 0x444B69：al = byte[0x4AB596]/[0x4AB597]＝记录 +2/+3＝**按下沿 e0/e1**
            # （0x44EB60 的 [eax+2]/[eax+3]）——按住不重复触发（1 押し = 1 行動）。
            if self.inp.rec.e0 or self.inp.rec.e1:
                self._adjust_bl = bl                         # 0x4453A2 段变化 SE 门（bl 时 melody_step）
                self._adjust_row(e, seg)                # 0x444B7F → 0x44547C[段]
            self._adjust_tail()                         # 0x444F7A
            return True
        if st == 4:                                  # 0x445415
            self.flags.set(0x10000)                  # → 页3
            e.alive = False
            return False
        if st == 5:                                  # 0x445431
            # 0x444360([ent+0x30]!=0)＝メニュー再生成（説明行/第2窃块/跳選行）＋ 态=2
            self._p6_spawn_menu(e.g32(0x30) != 0)
            e.t = 2
            return True
        self._adjust_tail()
        return True

    def _adjust_row(self, e: UiEntity, row: int) -> None:
        """0x44547C 18 行表（C=按住沿/X=按住沿均可，原码不区分按哪个键）。
        行 0/2/3/12/13/14 = **0x45AF90 XOR** 切换（旧实现写成 OR ⇒ 按两次切不回来，
        2026-11-15 用户实测）。"""
        if row == 0:                                 # 0x444B99
            self.keys.bits ^= 0x200                  # 自動爆破切替（0x45AF90 XOR）
        elif row == 1:                               # 0x444BAD
            cur = self.keys.field(0x18)
            nxt = {0: 1, 1: 3}.get(cur, 0)
            self.keys.set_field(0x18, nxt)         # 0x45B0E0(0x4AB5B0, 0x18, nxt)
            a = 1 if self.keys.test(8) else 0        # 0x45AFF0(8)
            b = 1 if self.keys.test(0x10) else 0     # 0x45AFF0(0x10)
            # 0x401C80→0x450580(0x4AB4B0, a, b)：音效管理器 byte[0x5C]=a、byte[0x5D]=b
            # ＝ 0x450440 的两道播放门（効果音开关）
            self.audio.gate_5c = a & 0xFF
            self.audio.gate_5d = b & 0xFF
        elif row == 2:                               # 0x444C0D
            self.keys.bits ^= 4                      # 0x45AF90 XOR
            v = 1 if self.keys.test(4) else 0        # 0x45AFF0(4)
            # 0x4011F9→0x44FEE0(0x4AB514, v)：MIDI 管理器 byte[0x50] = v
            # ＝ 0x44F640 BGM 播放的音楽开关门（0 ⇒ 0x44F860 不播放）
            self.audio.bgm_byte50 = v & 0xFF
            self._adjust_bgm_dirty = True            # 0x444C30 [esp+0x12]=1
        elif row == 3:                               # 0x444C3A
            self.keys.bits ^= 0x400                  # 0x45AF90 XOR
            # ゲーム内読点：0x44161F（0x6F000005＝EDG2 結局コントローラ 0x4415F0、
            # チェックポイント 0x33AE）——bit 置時 層3←資源0x53+選機[+0x57 週目] バインド。
            # 0x4415F0/0x4F00000C 実装済み（spawn 分派 0x6F idx4/0x4F 0x4F00000C 参照）。
        elif row == 7:                               # 0x444F14 説明行/表示切替
            # [ent+0x30] ^= 1（0x444F23）＋ 态=5（0x444F26 ⇒ 0x444360 メニュー再生成）
            # ＋ 0x4013DE(0x4AB454, 0, 0)（ポインタ/preset リセット）。
            e.d32(0x30, e.g32(0x30) ^ 1)
            e.t = 5
            self.inp.set_pos(0, 0)                   # 0x4013DE→0x44E470(inp,0,0) 指针归零
        elif row == 8:                               # 0x444ECF 完了（明度→彩度连算）
            b = self.disp_cfg.field(0x1FC0000)
            c = b * 4 - 0xC8
            self.disp_cfg.set_field(0xFE000000, c & 0xFFFFFFFF)
            self._adjust_apply_pal()                 # 0x444F60 0x44CDF0(2,…)
            e.t = 3                                  # 0x444F6E [0x1C]=3（驻留→态4 退页）
            self._adjust_cursor()                    # 0x4019FB 0x43DCB0 闪光
        elif row == 9:                               # 0x444C4E MIDI デバイス選択
            if self.inp.rec.e1:                      # 0x444C4E test al(=e1)：e1 ⇒ 循环
                if self._adjust_dev_i == 0x32:
                    self._adjust_dev_i = 0
                else:
                    self._adjust_dev_i += 1
                    if self._adjust_dev_i >= 0x32:   # 0x44FF90(0x4AB514) 设备数（复刻取上限）
                        self._adjust_dev_i = 0x32
            else:                                    # e0：0x3F000 字段写入 + 设备应用
                self.disp_cfg.set_field(0x3F000, self._adjust_dev_i & 0xFFFFFFFF)
                # 0x401DF2→0x44FDD0 / 0x40110E→0x44F390(0x4AB514, dev)＝MIDI 切替（音频后端无枚举）
        elif row == 10:                              # 0x444CCA 对比度 ±1
            cur = self.disp_cfg.field(0xFE000000)
            cur = cur + (1 if self.inp.rec.e0 else -1)   # 0x444CD9 mov cl,[0x4AB596](e0) ±1
            if cur == 0x64:
                cur = 0
            elif cur == 0x7F:
                cur = 0x63
            self.disp_cfg.set_field(0xFE000000, cur & 0xFFFFFFFF)
            self._adjust_pal_dirty = True            # 0x444D43 [esp+0x13]=1
        elif row == 16:                              # 0x444E91 跳選（关卡选择）行
            if not self.keys.test(0x80):
                # 0x444EA2 je 0x444F14：bit0x80 清 ⇒ 行 7 动作（[0x30]^=1 + 态5 再生成）
                e.d32(0x30, e.g32(0x30) ^ 1)
                e.t = 5
                self.inp.set_pos(0, 0)               # 0x4013DE→0x44E470
            elif self.inp.rec.e1:
                # 0x444EA4..0x444CC0：e1 ⇒ [esp+0x12]=1（BGM 脏，尾部按 [0x28] 重播）
                self._adjust_bgm_dirty = True
            else:
                # 0x444EB1：e0 ⇒ [0x28]++ ≤0xD 回卷（无脏标记）。
                # [0x28]=0 PlayerSelect/1..7 Stage1..7/8+ Boss… ⇒ ゲーム開始組号
                # [0x4AB5C8] = 選択ステージ-1（p4_block の chain = 組*4+11）。
                v = self._adjust_bgm_i + 1
                self._adjust_bgm_i = 0 if v >= 0xD else v
                # 高字 = 週目フラグ（0x4548CF）を保持
                self.theatre = (self.theatre & 0xFFFF0000) | max(0, self._adjust_bgm_i - 1)
        elif row == 17:                              # 0x444F01（seg≤8 不可达；表尾项）
            if self.keys.test(0x80):
                # bit0x80 ⇒ 行 7 同款：[0x30]^=1 + 态=5（メニュー再生成）+ ポインタリセット
                e.d32(0x30, e.g32(0x30) ^ 1)
                e.t = 5
                self.inp.set_pos(0, 0)
                self.inp.set_preset4(0, (0, 0))
            else:
                # 0x444F30：明度→彩度連算 + 0x44CDF0(1, …)（パレット1 復帰）+ 态=3 + 0x43DCB0
                b = self.disp_cfg.field(0x1FC0000)
                self.disp_cfg.set_field(0xFE000000, (b * 4 - 0xC8) & 0xFFFFFFFF)
                self.pal = self._load_pal(1)
                self.pal_now = self.pal
                e.t = 3
                self._adjust_cursor()
        elif row == 11:                              # 0x444D4D 亮度 ±1
            cur = self.disp_cfg.field(0x1FC0000)
            cur = cur + (1 if self.inp.rec.e0 else -1)   # 0x444D5C mov cl,[0x4AB596](e0) ±1
            if cur == 0x64:
                cur = 0
            elif cur == 0x7F:
                cur = 0x63
            self.disp_cfg.set_field(0x1FC0000, cur & 0xFFFFFFFF)
            self._adjust_pal_dirty = True            # 0x444DC6 [esp+0x13]=1
        elif row == 12:                              # 0x444DD0 切替 XOR 0x40
            self.keys.bits ^= 0x40                   # 0x45AF90 XOR（旧版 OR ⇒ 切不回来）
            # 0x44DCD0 byte[0x4AA7B0+0x86] = test(0x40)：層ブリット 0x44D2A4 の
            # パレットリマップ有効フラグ（0x4987F4 表）——描画側リマップ pass 未搭載
            self.layers.cg40 = 1 if self.keys.test(0x40) else 0
        elif row == 13:                              # 0x444DF8 切替 XOR 0x20
            self.keys.bits ^= 0x20                   # 0x45AF90 XOR
            self.layers.cg20 = 1 if self.keys.test(0x20) else 0   # 0x44DCB0 byte[0x85]
        elif row == 14:                              # 0x444E20 切替 XOR 0x800
            self.keys.bits ^= 0x800                  # 0x45AF90 XOR
        elif row == 15:                              # 0x444E34 操作器切换
            cur = self.keys.field(0x3000)
            nxt = {0: 1, 1: 3}.get(cur, 0)
            self.keys.set_field(0x3000, nxt)       # 0x45B0E0(0x3000)
            self.p4_op_flag = 1 if self.keys.test(0x1000) else 0   # 0x454E60 byte[0x4AA49C]
        # 行 4/5/6 = 尾直跳（无动作）

    def _adjust_tail(self) -> None:
        """0x444F7A：BGM 切换旗标 → 0x401F69(0x4AB514, 表[bgm])；调色板旗标 → 重载。"""
        if self._adjust_bgm_dirty:
            tbl = (7, 8, 9, 0xA, 0xB, 0xC, 0xD, 0xE, 1, 2, 4, 3, 6)
            i = self._adjust_bgm_i
            if i in (9, 0xA):
                i = 0
            if 0 <= i < len(tbl):
                self.midi_play(tbl[i])               # 0x401F69(0x4AB514, …) 占位
            self._adjust_bgm_dirty = False
        if self._adjust_pal_dirty:
            self._adjust_apply_pal()
            self._adjust_pal_dirty = False

    def _adjust_cursor(self) -> None:
        """0x444F6E [0x1C]=3 + 0x4019FB→0x43DCB0：0x61000005 @(0,-8) + 0x44EDA0(1)。"""
        c = self.spawn(self.ui52c, 0x61000005, a3=-8)
        c.aux = -8
        self.inp.set_mode(1)

    # ---- 页6 調整メニュー表示体（0x444360 → 0x4AD4FC、0x5F000008..D 群）--------

    def _p6_spawn_menu(self, reentry: int) -> None:
        """0x444360（調整メニュー生成，arg = [ent+0x30]!=0）。0x4018B6(0x4AD4FC) 清队列后：

        初回（arg=0）0x444382..0x4445E4＋尾 0x44489D：
          08(-1) 説明塊 → 08(0) 説明行（0x425960、tbl[seg+0]）→ 09×9 (prm 0..8) 行ラベル →
          0A(0x60,0,0x200) 自動爆破 / 0D(0x80,0x140,0x18) 画像要素 / 0A(0xA0,0,4) 音楽 /
          0A(0xC0,0,0x400) → 0C/0B (0,0xE0,0xF) → C/B (0,0x100,0xF0) → C/B (0,0x120,0xF00)
          キー桁（攻撃/光撃/捕獲）。
        再入（arg!=0）＝**他設定ページ** 0x4445E9..0x4448C5：
          08(9) 説明行 → 09×9 (prm 9..17＝第2窃块) →
          0C(rec0=&[ent+0x2C] ライブ,0x60) デバイス桁 / 0B →
          0C/0B (0,0x80,0xFE000000) 彩度 → 0C/0B (0,0xA0,0x1FC0000) 明度 →
          0A(0xC0,0x40,0x40) / 0A(0xE0,0x80,0x20) / 0A(0x100,0,0x800) /
          0D(0x120,0x160,0x3000) → bit0x80 時 0C(rec0=&[ent+0x28]) 跳選桁。
        旧实现：初回に 08(0) 説明行が漏れ、デバイス桁を初回でも生成 ⇒ 0A 行と重複
        （2026-11-15 用户实测"右侧文字重叠"）。"""
        self.ui4fc.clear()                               # 0x4018B6(0x4AD4FC)
        # ★ 0x44439B `test al,al; jne 0x4445E9`：再入（他設定）**跳过**初回的三段
        #   0x444382 説明塊 / 0x4443A7 説明行 / 0x4443BA 的 9 行标签，直接走
        #   0x4445E9 的第二页生成。旧实现把这三段放在分支之前，再入时又追加第二页
        #   08(9)+9 行（prm 9..17）⇒ 两套标签叠在同一 dst（用户实测"渲染重叠混乱"）。
        if not reentry:
            # ---- 初回ページ 0x444414..0x4445E4＋尾 ----
            self.spawn(self.ui4fc, 0x5F000008, 0, 0, -1)     # 0x444382 説明塊
            self.spawn(self.ui4fc, 0x5F000008, 0, 0, 0)      # 0x4443A7 説明行
            for i in range(9):                               # 0x4443BA..0x444412
                self.spawn(self.ui4fc, 0x5F000009, 0, 0, i)
            self.spawn(self.ui4fc, 0x5F00000A, 0x60, 0, 0x200)     # 0x444414 自動爆破
            self.spawn(self.ui4fc, 0x5F00000D, 0x80, 0x140, 0x18)  # 0x44444B 画像要素
            self.spawn(self.ui4fc, 0x5F00000A, 0xA0, 0, 4)         # 0x444485 音楽
            self.spawn(self.ui4fc, 0x5F00000A, 0xC0, 0, 0x400)     # 0x4444BC
            for y, m in ((0xE0, 0xF), (0x100, 0xF0), (0x120, 0xF00)):
                self.spawn(self.ui4fc, 0x5F00000C, 0, y, m)   # 0x4444F6 キー桁 10 の位
                self.spawn(self.ui4fc, 0x5F00000B, 0, y, m)   # 0x44453C キー桁 1 の位
            return
        # ---- 他設定ページ 0x4445E9..0x4448C5 ----
        self.spawn(self.ui4fc, 0x5F000008, 0, 0, 9)            # 0x4445F3 説明行
        for i in range(9):                                     # 0x444600..0x444658
            self.spawn(self.ui4fc, 0x5F000009, 0, 0, 9 + i)
        g = self.spawn(self.ui4fc, 0x5F00000C, 1, 0x60, 0)     # 0x44465A デバイス桁
        g.p["live"] = lambda: int(getattr(self, "_adjust_dev_i", 0))
        self.spawn(self.ui4fc, 0x5F00000B, 1, 0x60, 0)         # 0x44469F
        self.spawn(self.ui4fc, 0x5F00000C, 0, 0x80, 0xFE000000)   # 0x4446B7 彩度
        self.spawn(self.ui4fc, 0x5F00000B, 0, 0x80, 0xFE000000)   # 0x444700
        self.spawn(self.ui4fc, 0x5F00000C, 0, 0xA0, 0x1FC0000)    # 0x444713 明度
        self.spawn(self.ui4fc, 0x5F00000B, 0, 0xA0, 0x1FC0000)    # 0x44475C
        self.spawn(self.ui4fc, 0x5F00000A, 0xC0, 0x40, 0x40)      # 0x44476F
        self.spawn(self.ui4fc, 0x5F00000A, 0xE0, 0x80, 0x20)      # 0x4447A6
        self.spawn(self.ui4fc, 0x5F00000A, 0x100, 0, 0x800)       # 0x4447E0
        self.spawn(self.ui4fc, 0x5F00000D, 0x120, 0x160, 0x3000)  # 0x44481A
        if self.keys.test(0x80):                                  # 0x444866
            g = self.spawn(self.ui4fc, 0x5F00000C, 1, 0x140, 0)   # 0x44486A 跳選桁
            g.p["live"] = self._adjust_bgm_i_getter()

    def _adjust_bgm_i_getter(self):
        """跳選桁のライブ値（=[ent+0x28]＝選択中关卡 0..0xD）——0x425C10 の *[0x20]。"""
        return lambda: int(getattr(self, "_adjust_bgm_i", 0))

    def _beh_430520(self, e: UiEntity) -> bool:
        """0x430520（カウントダウン）：[0x1C]--、元値==0 で死（-1 初期 ⇒ 永生）。"""
        old = e.s32(0x1C)
        e.d32(0x1C, (old - 1) & 0xFFFFFFFF)
        return old != 0

    def _beh_425AD0(self, e: UiEntity) -> bool:
        """0x425AD0（0x5F000009 行ラベル、thunk 0x4023CE）：++[0x20]；
        node 可視 = ((cnt & 0x10) != 0) or (seg != [0x1C])——懸停行が 16 幀周期で点滅。"""
        seg = _adjust_magic_div(int(self.inp.y) & 0xFFFFFFFF)
        cnt = (e.s32(0x20) + 1) & 0xFFFFFFFF
        e.d32(0x20, cnt)
        if e.node is not None:
            e.node.active = 1 if ((cnt & 0x10) or seg != e.s32(0x1C)) else 0
        return True

    def _beh_425B20(self, e: UiEntity) -> bool:
        """0x425B20（0x5F00000A ON/OFF 行、thunk 0x4020B3）：
        δ = 0x45AFF0(0x4AB5B0, [0x1C]) ? 0 : 0x20；rect.t = [0x20]+δ、rect.b = t+0x1F
        （ビット立ってる⇒上有セル、無い⇒下無セル）；可視=1。"""
        bit = bool(self.keys.bits & (e.s32(0x1C) & 0xFFFFFFFF))
        t = e.s32(0x20) + (0 if bit else 0x20)
        if e.node is not None:
            e.node.active = 1
            e.node.rect[1] = t
            e.node.rect[3] = t + 0x1F
        return True

    def _beh_425B70(self, e: UiEntity) -> bool:
        """0x425B70（0x5F00000B キー桁・1 の位、thunk 0x401A64）：
        v = [0x20]？*[0x20]（ライブ値）: 0x45AFC0(0x4AB5B8, [0x1C])；c = v % 10；
        rect = (c*32, 0x120, c*32+0x1F, 0x13F)（bm_st2 の ○壱弐…数字条）；可視=1。"""
        live = e.p.get("live")
        if callable(live):
            v = int(live())
        else:
            v = self.disp_cfg.field(e.s32(0x1C) & 0xFFFFFFFF)
        c = v % 10
        if e.node is not None:
            e.node.active = 1
            e.node.rect[0] = c * 32
            e.node.rect[2] = c * 32 + 0x1F
            e.node.rect[1] = 0x120
            e.node.rect[3] = 0x13F
        return True

    def _beh_425C10(self, e: UiEntity) -> bool:
        """0x425C10（0x5F00000C キー桁・10 の位、thunk 0x4023E2）：
        v = [0x20]？*[0x20]/10 : 0x45AFC0(0x4AB5B8, [0x1C])//10；
        rect = (c*32, 0x120, c*32+0x1F, 0x13F)；可視=1。"""
        live = e.p.get("live")
        if callable(live):
            v = int(live()) // 10
        else:
            v = self.disp_cfg.field(e.s32(0x1C) & 0xFFFFFFFF) // 10
        if e.node is not None:
            e.node.active = 1
            e.node.rect[0] = v * 32
            e.node.rect[2] = v * 32 + 0x1F
            e.node.rect[1] = 0x120
            e.node.rect[3] = 0x13F
        return True

    def _beh_4415F0(self, e: UiEntity) -> bool:
        """0x4415F0（0x6F000005，EDG2 t=0 生成、thunk 0x4013FC）：结局调色板/画集控制器。
        [0x1C] 帧计数，检查点：
        0xB4   → 0x44171C：0x44CDF0(mgr, 3, 彩度', 明度', -255) パレット3＋配置淡入
        0x1884 → 0x4416E8：0x44CDF0(mgr, 1, 彩度', 明度', 0)　パレット1
        0x33AE → 0x44161A：0x45AFF0(0x4AB5B0, 0x400)（画像要素）置時
                 層3 ← 資源 0x53+選機[+0x57 週目0x4000且選機≠3]（640×480 表面作成、
                 0x4022E3 GGD 展開、0x44CE60 色键）＋ 0x4F00000C 全画面表示体生成。
        [0x1C]++、返り値 = 新フレーム != 0（永生）。"""
        f = e.s32(0x1C)
        if f == 0xB4:
            b = self.disp_cfg.field(0x1FC0000)
            c = self.disp_cfg.field(0xFE000000)
            self.pal = self._load_pal(3)
            self.pal_now = fade_palette(self.pal, b * 4 - 0xC8, c * 4 - 0xC8)
        elif f == 0x1884:
            b = self.disp_cfg.field(0x1FC0000)
            c = self.disp_cfg.field(0xFE000000)
            self.pal = self._load_pal(1)
            self.pal_now = fade_palette(self.pal, b * 4 - 0xC8, c * 4 - 0xC8)
        elif f == 0x33AE:
            if self.keys.bits & 0x400:                       # 0x441624 画像要素
                ship = self.keys.field(0xC000) & 3
                if self.p4_sys_bits() & 0x4000 and ship != 3:  # 0x441653 週目バリアント
                    res = 0x53 + ship + 0x57
                else:
                    res = 0x53 + ship
                if not self.layers.load(3, res):
                    self.flags.set(2)                        # 0x4520xx 系の失敗旗
                self.layers.color_key(3, 0)                  # 0x441699 0x44CE60(3,0)
                self.spawn(self._p4_q("ui4cc"), 0x4F00000C, 0, 0, 0)  # 0x4416C8
        e.d32(0x1C, (f + 1) & 0xFFFFFFFF)
        return (f + 1) != 0

    def _beh_425CD0(self, e: UiEntity) -> bool:
        """0x425CD0（0x5F00000D 3 値窓、thunk 0x401C17）：

        `v = 0x45AFC0(0x4AB5B0, [+0x1C]) & 3`；查**4 项**栈表
        `{0:0, 1:0x60, 2:0, 3:0xC0}`（0x425CD6..0x425CF1 依次写 local[0]=0、
        local[1]=0x60、local[2]=0、local[3]=0xC0；`0x45AFC0` 是 `ret 4`，调用后
        esp 回到 local 基址），再 `rect.l=tbl[v]`、`rect.r=l+0x5F`、可視=1。
        ⚠ 旧实现只写了 3 项 `(0,0x60,0xC0)` ⇒ 调整页把 0x18 字段切到 3 时
        `v&3==3` 直接 IndexError（用户崩溃栈 0x425CD0）。
        """
        v = self.keys.field(e.s32(0x1C) & 0xFFFFFFFF) & 3
        l = (0, 0x60, 0, 0xC0)[v & 3]
        if e.node is not None:
            e.node.active = 1
            e.node.rect[0] = l
            e.node.rect[2] = l + 0x5F
        return True

    def _beh_425960(self, e: UiEntity) -> bool:
        """0x425960（0x5F000008 説明行、rec3>=0）：idx = seg + [0x1C]；
        0x45B030(0x80)（none）且 idx==0x10 → 7；none 且 idx==0x11 → 8；
        b = tbl[idx]（スタック 16 バイト表、idx11 は未初期化ホール）；可視=1；
        rect = (0, (b&0x7F)*24, 0x17F, t+0x17+(b&0x80 ? 0x18 : 0))——bm_st3 の 24px 列窓。"""
        seg = _adjust_magic_div(int(self.inp.y) & 0xFFFFFFFF)
        idx = seg + e.s32(0x1C)
        none80 = (self.keys.bits & 0x80) == 0
        if none80 and idx == 0x10:
            idx = 7
        elif none80 and idx == 0x11:
            idx = 8
        tbl = {3: 0x0C, 4: 0, 5: 0x81, 6: 3, 7: 0x84, 8: 0x86, 9: 0x88, 10: 0x8A,
               12: 0xD, 13: 0xE, 14: 0xF, 15: 0x10, 16: 0x91, 17: 0x93, 18: 0x95,
               19: 0x97, 20: 0x19}                    # idx11 = スタックホール（未初期化）
        b = tbl.get(idx, 0)
        t = (b & 0x7F) * 24
        if e.node is not None:
            e.node.active = 1
            e.node.rect[1] = t
            e.node.rect[3] = t + 0x17 + (0x18 if (b & 0x80) else 0)
        return True

    def _adjust_apply_pal(self) -> None:
        """0x444F60：亮度/对比度字段 ×4-0xC8 → 0x44CDF0(2, 对比, 亮度) → 0x44B790
        施加（`fade_palette(pal, a=亮度, b=对比)`，0x45B790 公式见其 docstring）。
        旧实现调了不存在的 `_load_pal(2, …)` 两参签名 ⇒ 調整画面按 C 即崩。"""
        b = self.disp_cfg.field(0x1FC0000)      # 亮度 7 位（0x1FC0000）
        c = self.disp_cfg.field(0xFE000000)     # 对比 7 位（0xFE000000）
        base = self._load_pal(2)
        self.pal = base
        self.pal_now = fade_palette(base, b * 4 - 0xC8, c * 4 - 0xC8)

    # ---- 0x43E7B1/0x43EB6E 态尾：详绘 + 驻留计数（[0x20] 门 → 输入态激活） ----
    def _rank_tail(self, e: UiEntity, seg: int, bl: int) -> None:
        # 0x43EB7C..0x43EB97：段稳定时 [0x20]++（0x20>0x20 → 0x43E7D1 放行输入），
        # [0x24] = 当前段；实体恒存活（al=1）。
        if bl == 0:
            e.a3 = (e.a3 + 1) & 0xFFFFFFFF
        else:
            e.a3 = 0
        e.aux = seg

    def _rank_cursor(self, e: UiEntity) -> None:
        """0x43DCB0（0x4019FB）：0x61000005 @(0,-8) 入 52C + 0x44EDA0(inp,1)。"""
        c = self.spawn(self.ui52c, 0x61000005, a3=-8)
        c.aux = -8
        self.inp.set_pos(0x140, 0)

    def _rank_tbl(self) -> bytearray:
        """页5 的排行榜表：scene_ab=0 → 0x4AB5CC 运行期表；1 → 0x4AC4EC 保存表。

        保存表复刻侧尚未持久化（§15.4），暂与运行期表同源（零表 = 未登录）。"""
        return self.p4_stat.get("tbl_4ab5cc") or self._p4_tbl4ab5cc()

    def p4_45c710(self, a1: int, a2: int) -> None:
        """`0x45C710(obj, a1, a2)`：obj[4] = (a1!=0)、obj[5] = a2。

        obj[4] = 行对选择、obj[5] = 半表选择（0 → +8 / 非0 → +0x740）。
        复刻侧只有一张 0x4AB5CC 等价表（0x4AC4EC 保存表持久化属 §15.4）。"""
        t = self._p4_tbl4ab5cc()
        t[4] = 1 if a1 else 0
        t[5] = a2 & 0xFF

    def p4_45d700(self, slot: int) -> bool:
        """`0x45D700(0x4CD5D8, slot, …)`：回放装载门（0x5E1200 的 3 个存槽，3 次重试）。

        0x45D700 的可观察语义：按 slot 读存槽 → 0x45D1D0 有帧 → True。
        复刻侧对接 P4Replay：count > 0 表示该槽有已记录回放。
        持久化到磁盘属 §15.4 未闭合项（此处为会话内）。"""
        rp = getattr(self, "p4_replay", None)
        if rp is not None and rp.count > 0:
            return True
        saves = getattr(self, "p4_replay_saves", None)
        return bool(saves) and 0 <= slot < 3 and saves.get(slot) is not None

    # 0x43E1C0（0x6F000002，OPMOVIE / "Now Loading" 进度屏）
    def _opmovie(self, e: UiEntity) -> None:
        # 0x43E1C0：t<0xF4 时按 RT_STRING id=t 取文件名，只对 .ggd/.bmp 调 0x455090 载入；
        # 每帧用 0x44D200(0xB4) 清屏 + 0x44D330 打 "Now Loading...%3d/%3d"，t++；
        # t>0xF4 → flags |= 0x10000（进页2）。0x43DD20(t,0xF) 负责把这一帧的图形合成上屏
        # （0x45FE10：把描述子里的 GGD id 逐个绑到层 0..n-1，再把层0贴屏）。
        import re as _re
        # 0x43E8C7..0x43E91F：切场景管理器(0x4AC4EC) → 写键位 1/2 → 置 [0x56CCD8] →
        # 摆指针(idx*49+0x18) → 生成 0x6F000003（段渲染）。触发条件未完全确认，暂按首帧生成一次。
        if e.t == 0:
            # 脚本 res_65_OpngStream 的 OP03 条目（全在 t=0）：按 type 生成摆放实体。
            # 坐标只做 16 位截断（§16.84：真正的落位由父坐标 + 0x30 / 位移量决定，后续接）
            self.opmovie_op03 = 0
            for _ins in getattr(self, "opng_script", []):
                if _ins.get("op") != "OP03" or not _ins.get("args"):
                    continue
                _a = _ins["args"][0]
                if len(_a) < 3:
                    continue
                _x, _y, _ty = int(_a[0]) & 0xFFFF, int(_a[1]) & 0xFFFF, int(_a[2])
                if _ty < 0:
                    _ty += 1 << 32
                if (_ty & 0xFF000000) not in (0x42000000, 0x46000000):
                    continue
                _ent = self.spawn(self.ui52c, _ty)
                if _ent is not None and _ent.disp is not None:
                    _ent.disp.dst[0], _ent.disp.dst[1] = _x, _y
                self.opmovie_op03 += 1
        if e.t == 1:
            self.scene_ab = False                      # [0x56CCD8] = 0 → 用 0x4AB5CC 那套表
            self.spawn(self.ui52c, 0x6F000003)
            self.log("opmovie：生成 0x6F000003 段渲染（[0x56CCD8]=0）")
        if e.t < 0xF4:                                  # 0..243：按字符串 id = 帧号装载资源
            name = self.layers.strings.get(str(e.t), "")
            if name and _re.search(r"(?i)\.ggd$", name):
                ok = self.layers.load(13, e.t)          # 0x455090 装载（进层13，仅副作用）
                self.log(f"opmovie load id={e.t} {name} -> {ok}")
                # 0x43E1C6 只做"装载进资源槽"(0x455090)，**不绘制**；
                # 屏幕内容只有 0x44D200(0xB4) 填充 + "Now Loading" 文字（见函数末尾）。
            elif name and _re.search(r"(?i)\.bmp$", name):
                self.log(f"opmovie palette id={e.t} {name}")   # 调色板类资源（bm_pal/pald/pals）
        # 0x44D200(mgr,0xB4) + "Now Loading...%3d/%3d"（0x44D330，h=0x20，fg=0xD9，bg=0xB4）
        self.screen_fill = 0xB4
        # 0x43E27D 之后 0x43DD20 的合成：已装载的图从 (0,0) 贴到主表面（层0 → 屏幕）
        # 0x43E2B0 push 0xB4 / push 0xD9 / push 0x20 / push &str / push 0 / push 0 / push 0
        # ⇒ 0x4022C0(mgr, x=0, y=0, str, h=0x20, fg=0xD9, bg=0xB4)：底色与清屏同为 0xB4
        e.texts = [{"str": "Now Loading...%3d/%3d" % (e.t, 0xF4),
                    "x": 0, "y": 0, "h": 0x20, "fg": 0xD9, "bg": 0xB4}]
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

    # ---- 页13（选择画面）的四个实体 ----------------------------------------
    def spawn_flash(self, cur: int, target: int, step: int) -> UiEntity:
        """0x61000005 的 init 0x42730B：`[0x1C]=a（当前） [0x20]=b（目标） [0x24]=c（步进）`。"""
        e = self.spawn(self.ui52c, 0x61000005)
        e.aux, e.a3, e.a4 = int(cur), int(target), int(step)
        return e

    def actor_spawn(self, x: int, y: int, ty: int, a3: int = 0) -> "UiEntity | None":
        """`0x448FF0(0x4AD40C, {x,y,type,a3,0})` = 演员队列插入，ctor = 生成器 `0x445C00`。

        类型链（`0x445CA7` 起）：`type&0xFF000000==0x1000000` → `0x445CB6`；
        `type>8` → `0x44603E`：9→`0x446227`(0x40116D→0x447F90)、**10→`0x446117`**、
        `0x0AFFFFF7` 形态→`0x446059`；≤8：8→`0x44601E`(0x4015FF)、1→`0x445ECE`、
        5→`0x445E47`、6→`0x445CE7`。页13 只用到 **0x0A**（= 选中机体的大字）。
        """
        if ty == 0x0A:
            return self._actor_0A(x, y, a3)
        if (ty & 0xFF000000) == 0x12000000:      # 0x12 特效族（0x42D7C0 分派）
            return self.fx12_spawn(ty, x, y, a3)
        self.log(f"actor spawn ({x},{y}) type=0x{ty:X} a3=0x{a3:X} → 未实现（§10.4 的其它类型）")
        return None

    # ---- 0x12 特效族（§16.118.10）---------------------------------------
    #  (层=1 bm_cm32, 源矩形 l,t,r,b, 行为, 速度上限 [+0x2C])
    FX12_TABLE = {
        # type: (rect(l,t,r,b), kind|None, 速度[+0x2C], 寿命[+0xC], 行为[+0x40])
        # 分支依据 0x42B256 分派比较链（§16.118.10，勘误 A-37）
        # 0x42B4D9（0x12061127 / 0x12071126 共用）：32×32、层 1、[+0x2C]=[0x56CC90]（自机 y 快照）、
        # dust=[+0x30]=(y!=mirror)?0xF:0；rect 由 dust^(x<0) 决定 0x80/0x40 与 0x9F/0x5F 两组；
        # 行为 0x4022DE→0x42BD00（向 mirror_y 归位的抖动弹体，x≥0x290 才死）
        0x12061127: ((0x80, 0xE0, 0x9F, 0xFF), "chase", 0, 0x10, 0x4022DE, 0x10),
        0x12071126: ((0x80, 0xE0, 0x9F, 0xFF), "chase", 0, 0x10, 0x4022DE, 0x10),
        # 0x42B2DA：16×16、层 1、行为 0x401BDB→0x42BEE0（0x4AD43C 追击：方向向量定长 0x100 累加、
        # 速度上限 0xA00、奇数帧 0x41000016 拖尾、0x4021E9(8) 出屏即死）
        0x12041129: ((0x100, 0xE0, 0x10F, 0xEF), "homing", 0, 0xC, 0x401BDB, 8),
        # 0x42B30E：rect 由 [+0x20] 符号二选一 (0x120/0x100,0xC0..0xCF)、16×16、层 1、
        # [+0x30]=(a3==0)；a3!=0 → 随机方向 0x800；a3==0 → 预演 n=0xF-(帧&0xF) 帧 vy 衰减定 y；
        # 行为 0x40144C→0x42BDF0（x≥0x288 才死）
        0x12061128: ((0x100, 0xC0, 0x10F, 0xCF), "drop", 0, 0xA, 0x40144C, 8),
        0x120A112F: ((0xA0, 0xC0, 0xAF, 0xCF), "burst", 0x200, 0xA, 0x401C26, 8),
        0x120C112E: ((0x100, 0xE0, 0x10F, 0xEF), "burst", 0x100, 0xA, 0x401C26, 8),
        0x120E112D: ((0x100, 0xD0, 0x10F, 0xDF), "burst", 0x180, 0xA, 0x401C26, 8),
        0x120F112A: ((0xC0, 0xE0, 0xDF, 0xFF), "pulse", 0, 0x10, 0x401BE5, 0x10),
        # 0x42B62E：rect(l,t,r,b)=(0x100,0xF0,0x10F,0xFF)、层 1、16×16、
        # 速度 [+0x2C]=rec[0]/4（有符号）、[+0x18]=-1、
        # 行为 0x4021B2→0x42C210（落体抛物线 + 每帧 0x41000018）
        0x120C112C: ((0x100, 0xF0, 0x10F, 0xFF), "arc2", "x/4", 0xC, 0x4021B2, 8),
        # 0x42B6B8：rect(l,t,r,b)=(0x78,0x1F8,0x8F,0x20F)、层 0、24×24、速度 rec[0]/4、
        # 行为 0x4022F2→0x42C120（dst 减 0xC、可见性 m=8、每帧 0x41000017）
        0x120D112B: ((0x78, 0x1F8, 0x8F, 0x20F), "arc1", "x/4", 0xC, 0x4022F2, 0xC, 0, 8),
        # 0x42B2A3：rect(l,t,r,b)=(0x100,0xD0,0x10F,0xDF)、层 1、16×16、
        # 行为 0x401D43→0x42BC40（**每帧**塞一条 0x41000015 入 0x4AD4CC 再积分）
        0x12061124: ((0x100, 0xD0, 0x10F, 0xDF), "trail", 0, 0xA, 0x401D43, 8),
        # 0x42B433：rect(l,t,r,b)=(0x60,0x198,0x77,0x1AF)、层 0、24×24、
        # 行为 0x40215D→0x42BB80（首帧吸自机 y + 横向涨缩），dst 减 0xC
        0x12081123: ((0x60, 0x198, 0x77, 0x1AF), "follow", 0, 0xC, 0x40215D, 0xC, 0),
        # 0x42B683（0x12091122 / 0x120B1121 共用）：32×32、速度 0、行为 0x401BAE→0x42B9C0
        # （与 0x42C050 同构的横向涨缩 + 屏幕可见性），dst 减 8
        0x12091122: ((0, 0xE0, 0x1F, 0xFF), "pulse", 0, 0x10, 0x401BAE, 8),
        0x120B1121: ((0, 0xE0, 0x1F, 0xFF), "pulse", 0, 0x10, 0x401BAE, 8),
    }

    def fx12_spawn(self, ty: int, x: int, y: int, a3: int = 0) -> "UiEntity | None":
        """ctor `0x42B210`（§16.118.10）：层恒 1、rect 按类型、dst=(x-半宽,y-半高)。

        `[+0x1C]=(short)rec[0xC]`(初速 8.8)、`[+0x20]=(short)rec[0xE]`、
        `[+0x24]=rec[0]<<8`、`[+0x28]=rec[4]<<8`（初位置 8.8）、`[+0x2C]`=速度上限。
        """
        row = self.FX12_TABLE.get(ty & 0xFFFFFFFF)
        if row is None:
            self.log(f"0x12 特效 type=0x{ty:X} @({x},{y}) → 该支矩形未定案，不生成")
            return None
        rect, kind, speed, life, beh, half, layer, m = (row + (1, 0))[:8]
        if m == 0:
            m = half
        if kind is None:
            self.log(f"0x12 特效 0x{ty:X} @({x},{y}) rect={rect} 行为 0x{beh:X} 未读 → 不生成")
            return None
        e = UiEntity(type_word=ty, a3=int(a3))
        e.beh = "fx12"
        e.p["kind"] = kind
        # 0x42B227 movsx ecx,word[eax+0xC] → **[+0x1C] = rec[0xC] 的低 16 位 = vx**；
        # 0x42B231 movsx edx,word[eax+0xE] → **[+0x20] = 高 16 位 = vy**；
        # 积分 0x42B980：`[+0x24] += [+0x1C]`（x）、`[+0x28] += [+0x20]`（y）。
        # 旧版把高低位对调（vx=高、vy=低）⇒ 弹体沿错误的轴飞（页13 全体朝下）。
        _a3 = a3 & 0xFFFFFFFF
        e.p["vx"] = _a3 & 0xFFFF
        e.p["vx"] = e.p["vx"] - 0x10000 if e.p["vx"] & 0x8000 else e.p["vx"]
        e.p["vy"] = (_a3 >> 16) & 0xFFFF
        e.p["vy"] = e.p["vy"] - 0x10000 if e.p["vy"] & 0x8000 else e.p["vy"]
        e.p["px"] = int(x) << 8                       # [+0x24]
        e.p["py"] = int(y) << 8                       # [+0x28]
        e.p["x"], e.p["y"] = int(x), int(y)           # [+4]/[+8]
        e.d32(0x04, int(x) & 0xFFFFFFFF)               # 同步原始字段（0x43C060 碰撞读 [e+4]/[e+8]）
        e.d32(0x08, int(y) & 0xFFFFFFFF)
        # 0x42B62E/0x42B6B8：速度 = 生成记录 x（有符号 /4，cdq+and 3+sar 2）
        e.p["spd"] = int(int(x) >> 2) if speed == "x/4" else int(speed or 0)
        e.p["vis"] = 1                                 # [+0x18] = 1（ctor）
        e.p["half"] = int(half)
        e.p["m"] = int(m)
        e.p["life"] = int(life)
        if kind == "chase":                       # 0x42B4E3..0x42B552
            e.p["mir"] = self.mirror_y()          # [+0x2C]
            e.p["dust"] = 0xF if e.p["y"] != e.p["mir"] else 0   # [+0x30]
            # 0x42B515：flag = ([+0x30]!=0) XOR ([rec+0xC] 有符号 < 0)，不是生发点 x 的符号
            a3s = int(a3) & 0xFFFFFFFF
            flag = 1 if ((e.p["dust"] != 0) != (a3s >= 0x80000000)) else 0
            l0, r0 = (0x40, 0x5F) if flag else (0x80, 0x9F)
            e.p["rect"] = [l0, 0xE0, r0, 0xFF]
        elif kind == "drop":                      # 0x42B31C..0x42B3F9
            e.p["dust"] = 1 if int(a3) == 0 else 0   # [+0x30]=(a3==0)
            if e.p["dust"] == 0:
                e.p["blink"] = 0                  # [+0x10]=0
                vx_l, vy_l = [self._rng() - 0x7FFF], [self._rng() - 0x7FFF]
                if self._vset(vx_l, vy_l, 0x800):  # 0x40105A(ebp,edi,0x800)
                    e.p["vx"], e.p["vy"] = vx_l[0], vy_l[0]
            else:
                e.p["py"] = 0                     # 0x42B368 [+0x28]=0
                n = 0xF - (self.frames & 0xF)     # 0x42B36B..0x42B379
                e.p["cnt2"] = n                   # [+0x2C]=n（循环计数，出口为 0）
                while n != 0:                     # 0x42B380
                    if e.p["py"] != 0:            # 0x42B385 cmp edx,ebx
                        e.p["vy"] += self._magic_neg26(e.p["py"])   # 0x42B389/0x42B3A0
                    e.p["py"] += e.p["vy"]        # 0x42B3A2 add eax,ecx
                    n -= 1                        # 0x42B3AA dec [+0x2C]
                    e.p["cnt2"] = n
                e.p["y"] = self.mirror_y() + (e.p["py"] >> 8)   # 0x42B3B0..0x42B3BD
            e.p["rect"] = ([0x120, 0xC0, 0x12F, 0xCF] if e.p["vy"] >= 0
                           else [0x100, 0xC0, 0x10F, 0xCF])  # 0x42B3D0..0x42B400
        else:
            e.p["rect"] = list(rect)
        rect = e.p["rect"]
        # 0x42B7D4/0x42B7D8 的减数：各支自己写（16×16 → 8、32×32 → 0x10），
        # 但 0x42B683 支走 0x42B73E ⇒ 32×32 也减 8，故不能用 rect 宽度推
        # 0x42B30E 支在 ctor 尾部之前改写 [+8]（0x42B3B0），故 dst 必须用改写后的 y
        e.p["beh40"] = beh                     # [+0x40] 行为指针（判分支用）
        e.raw[0x10] = 1                        # 0x42B243 byte[+0x10]=1：参与碰撞
        e.d32(0x14, ty & 0xFFFFFFFF)           # 基础 ctor：[+0x14]=类型（碰撞分派读原始字段）
        e.disp = DisplayNode(int(layer), list(rect),
                             [int(e.p["x"]) - half, int(e.p["y"]) - half])
        self.ui46c.append(e)
        self.log(f"0x12 特效 0x{ty:X} kind={kind} beh=0x{beh:X} [+0xC]={life} @({x},{y}) rect={rect}")
        return e

    @staticmethod
    def _on_screen(x: int, y: int, m: int) -> bool:
        """`0x4021E9`→`0x4305F0`：`(x±m, y±m)` 与屏幕 640×480 是否相交。

        逐条：`(x-m)>0x27F` → 否；`(x+m)<=0` → 否；`(y-m)>0x1DF` → 否；`(y+m)<=0` → 否。
        """
        if (x - m) > 0x27F:
            return False
        if (x + m) <= 0:
            return False
        if (y - m) > 0x1DF:
            return False
        if (y + m) <= 0:
            return False
        return True

    def _rng(self) -> int:
        """`0x401393`→`0x45AD00`：`seed = seed*0x19660D + 0x3C6EF35F & 0x7FFFFFFF`，
        调用点再 `and eax,0xffff`，故返回 seed & 0xFFFF。"""
        self.rng_seed = (self.rng_seed * 0x19660D + 0x3C6EF35F) & 0x7FFFFFFF
        return self.rng_seed & 0xFFFF

    @staticmethod
    def _magic_neg26(y: int) -> int:
        """`0x42B389 imul 0xB13B13B1 / sar 3 / shr 31 修正`：约等于 y * (−1/26) 的有符号乘。"""
        prod = y * -1321528399
        d = (prod >> 32) >> 3
        d += (prod & 0xFFFFFFFF) >> 31
        return d

    @staticmethod
    def _vset(a: list, b: list, ln: int) -> bool:
        """`0x40105A`→`0x45AC70`：把 (a[0],b[0]) 定长到 ln；分量为 0 → 返回 False。"""
        x, y = float(a[0]), float(b[0])
        d = (x * x + y * y) ** 0.5
        if d == 0.0:
            return False
        a[0] = int(x / d * ln)
        b[0] = int(y / d * ln)
        return True

    def _fx12(self, e: UiEntity) -> None:
        """行为 `0x42C320`（burst，中心**向外**爆散，三型）/ `0x42C050`（pulse，`0x120F112A`）。

        方向 = pos − target（`0x42C362 sub edi,ecx`），故为爆散而非追踪（勘误 A-36）。
        """
        if e.p.get("kind") == "homing":                # 0x42BEE0
            tx, ty = int(self.inp.x), int(self.inp.y)  # 0x4021EE(0x4AD43C,&self,&out)
            dx, dy = [tx - e.p["x"]], [ty - e.p["y"]]  # 0x42BF15/0x42BF23
            if self._vset(dx, dy, 0x100):              # 0x42BF38
                e.p["vx"] += dx[0]                     # 0x42BF51
                e.p["vy"] += dy[0]                     # 0x42BF64
                vx_l, vy_l = [e.p["vx"]], [e.p["vy"]]
                if self._vset(vx_l, vy_l, 0xA00):      # 0x42BF67 限速
                    e.p["vx"], e.p["vy"] = vx_l[0], vy_l[0]
            self._fx12_integrate(e)                    # 0x42BF71
            self._fx12_place(e)                        # 0x42BF84 dst=(x-8,y-8)
            if self.p4_frames & 1:                     # 0x42BF95 test al,1（页4 帧计数 [0x56CCA8]）
                self.p4_spawn41(e.p["x"], e.p["y"], 0x41000016)   # 拖尾实体（0x429654）
            self._fx12_visibility(e)                   # 0x42BFD8 push 8
            return
        if e.p.get("kind") == "drop":                  # 0x42BDF0
            if e.p.get("dust"):                         # 0x42BDF6 test eax,eax
                n = e.p["dust"] + 1                     # 0x42BDFA inc eax
                e.p["dust"] = n
                e.p["blink"] = 1 if n > 3 else 0        # 0x42BE01 setg al
                self._fx12_integrate(e)                 # 0x42BE07
            else:
                d = self._magic_neg26(e.p["py"])        # 0x42BE15 对 py 做衰减
                e.p["vy"] += d                          # 0x42BE2B
                self._fx12_integrate(e)                 # 0x42BE30
                e.p["y"] = self.mirror_y() + (e.p["py"] >> 8)   # 0x42BE42
            if e.disp:                                  # 0x42BE4D test byte,0x1F
                if e.disp.rect[0] & 0x1F:
                    e.disp.grow(-0x10, 0, -0x10, 0)
                else:
                    e.disp.grow(0x10, 0, 0x10, 0)
            self._fx12_place(e)                         # 0x42BE77 dst=(x-8,y-8)
            # 0x42BE8B/0x42BE92：退出条件 = x >= 0x288（648）或 [+0x18]==0，
            # 不调 0x4021E9（本支的死亡判据与屏幕可见性无关）
            if e.p["x"] >= 0x288 or not e.p.get("vis", 1):
                e.alive = False
            return
        if e.p.get("kind") == "chase":                 # 0x42BD00
            ecx = e.p["y"] - e.p["mir"]                 # 0x42BD09
            if ecx != 0:                                # 0x42BD0B je
                mul = -3 if e.p["dust"] != 0 else -0x10  # 0x42BD17 and 0xD / add -0x10
                ecx *= mul                              # 0x42BD1A imul
            n = e.p["dust"]                             # 0x42BD1D
            if n:
                n -= 1                                  # 0x42BD24 dec
                e.p["dust"] = n
                if n == 0:                              # 0x42BD2A jne
                    e.p["dust"] = 0xF                    # 0x42BD32
                    v = e.p["vy"]                       # 0x42BD39 cdq/sub/sar：向零截断
                    e.p["vy"] += v // 2 if v >= 0 else -((-v) // 2)   # 0x42BD41
            e.p["vy"] += ecx                            # 0x42BD4B
            self._fx12_integrate(e)                     # 0x42BD4E
            if e.disp:                                  # 0x42BD5B test byte,0x3F
                if e.disp.rect[0] & 0x3F:
                    e.disp.grow(-0x20, 0, -0x20, 0)
                else:
                    e.disp.grow(0x20, 0, 0x20, 0)
            self._fx12_place(e)                         # 0x42BD85 dst=(x-0x10,y-0x10)
            if e.p["x"] >= 0x290 or not e.p.get("vis", 1):   # 0x42BD99 / 0x42BDA0
                e.alive = False
            return
        if e.p.get("kind") == "pulse" and e.p.get("beh40") == 0x401BE5:
            # 行为 `0x42C050`（0x120B1121 = 撃 直射弹）：vy 绕回（|vy|>0x100 → ±0x100，
            # 0x42C053..0x42C078）→ 积分 → dst=(x-0x10,y-0x10) → 0x4021E9(0x10) 出屏死。
            vy = e.p["vy"]
            if abs(vy) > 0x100:
                e.p["vy"] = vy + (0x100 if vy <= 0 else -0x100)
            self._fx12_integrate(e)                    # 0x42C07D → 0x42B980
            if e.disp:
                e.disp.dst[0] = e.p["x"] - 0x10        # 0x42C0BF
                e.disp.dst[1] = e.p["y"] - 0x10
            if not (self._on_screen(e.p["x"], e.p["y"], 0x10) and e.p.get("vis", 1)):
                e.alive = False                        # 0x42C0CE
            return
        if e.p.get("kind") == "pulse" and e.p.get("beh40") == 0x401BAE:
            # 行为 `0x42B9C0`（0x120B1121 / 0x12091122）：只有 vy 一条轴的衰减脉动
            d = e.p["vy"]                              # 0x42B9C7
            if abs(d) > 0x100:                         # 0x42B9D1 jle
                e.p["vy"] = d + (0x100 if d <= 0 else -0x100)   # 0x42B9D8..0x42B9EC
            self._fx12_integrate(e)                    # 0x42B9F1
            if e.disp:                                 # 0x42B9F6 add eax,4
                if e.disp.rect[0] != 0:                # 0x42B9FE cmp dword,0（整 dword，无掩码）
                    e.disp.grow(-0x20, 0, -0x20, 0)
                else:
                    e.disp.grow(0x20, 0, 0x20, 0)
            self._fx12_place(e, 0x10)                  # 0x42BA20 sub 0x10
            # 0x42BA39：`[+0x2C]`（外部对象指针）非 0 才进入命中判定；ctor `0x42B683` 写 0，
            # 页13 的两支（0x12091122/0x120B1121）直接跳到 0x42BAEC。
            ext = e.p.get("ext", 0)                    # [+0x2C]
            if ext:
                e.p["cnt"] = e.p.get("cnt", 0) + 1     # 0x42BA47 inc edi / [esi+0x30]
                # 0x42BA47..0x42BA6B：blink = (0x40145B(0x56CCB8,2) && byte[+0x10]==0)
                blink = self._state2_bit(2) and not e.p.get("blink", 0)
                e.p["blink"] = 1 if blink else 0       # byte[+0x10]
                alive = ext.get("alive", True) if isinstance(ext, dict) else True
                tgt_x = ext.get("x", 0) if isinstance(ext, dict) else 0
                if not alive:                          # 0x42BA71 byte[eax+0x34] != 0 才保留
                    pass
                else:
                    if e.p["cnt"] < 6:                 # 0x42BA78 jl 0x42BAE5
                        e.p["ext"] = 0
                    elif tgt_x > 0x290:                # 0x42BA7E
                        e.p["ext"] = 0
                    else:
                        # 0x42BA87..0x42BAD8：投放 0x41000004 入 0x4AD4CC，
                        # a3 = 指向 (vx>>7, vy>>7) 的两字点
                        pt = ((e.p["vx"] >> 7) & 0xFFFFFFFF, (e.p["vy"] >> 7) & 0xFFFFFFFF)
                        self._spawn_4100_0004(e.p["x"], e.p["y"], pt)
                        e.alive = False                # 0x42BAD E xor al,al
                        return
            self._fx12_visibility(e, 0x10)             # 0x42BAEC 0x4021E9(esi,0x10) + [+0x18]
            return
        if e.p.get("kind") == "pulse":                 # 0x42C050
            d = e.p["vy"]
            if abs(d) > 0x100:                         # 0x42C05D cmp eax,0x100
                d += 0x100 if d <= 0 else -0x100       # 0x42C064..0x42C078
                e.p["vy"] = d
            self._fx12_integrate(e)                    # 0x42C07D
            if e.disp:
                if e.disp.rect[0] & 0x3F:              # 0x42C08A test byte [eax],0x3F
                    e.disp.grow(-0x20, 0, -0x20, 0)
                else:
                    e.disp.grow(0x20, 0, 0x20, 0)
            self._fx12_place(e)                        # 0x42C0A3 dst=(x-half,y-half)
            self._fx12_visibility(e)                   # 0x42C0BF push 0x10
            return
        if e.p.get("kind") in ("arc1", "arc2"):        # 0x42C120 / 0x42C210
            arc1 = e.p["kind"] == "arc1"
            spd = e.p["spd"]
            if arc1:                                   # 0x42C126 dword [+0x30]
                cnt = e.p.get("cnt", 0) + 1
                e.p["cnt"] = cnt
                if cnt > 7:                            # 0x42C12F cmp eax,7 jg
                    e.p["vy"] = 0                      # 0x42C151
                elif cnt >= 4:                         # 0x42C134 cmp eax,4 jl
                    e.p["vy"] -= spd                   # 0x42C13F sub ecx,eax
                    e.p["vx"] += 0x280                 # 0x42C144 add eax,0x280
                trail_type = 0x41000017
            else:                                      # 0x42C216 word [+0x2E]
                w = e.p.get("w", 0) + 1
                e.p["w"] = w & 0xFFFF
                if w > 5:                              # 0x42C21E cmp ax,5 jg
                    e.p["vy"] = 0
                elif w >= 2:                           # 0x42C224 cmp ax,2 jl
                    e.p["vy"] -= spd                   # 0x42C22A movsx word [+0x2C]
                    e.p["vx"] += 0x300                 # 0x42C236 add eax,0x300
                cnt = e.p.get("cnt", 0) + 1            # 0x42C253 inc ecx
                e.p["cnt"] = cnt
                e.p["blink"] = 1 if cnt >= 0 else 0    # 0x42C25B setns cl
                trail_type = 0x41000018
            self.p4_spawn41(e.p["x"], e.p["y"], trail_type)   # 拖尾实体（0x42971D/0x42969D）
            self._fx12_integrate(e)                    # 0x42C194 / 0x42C293
            self._fx12_place(e)                        # 0x42C1A2 减 0xC / 0x42C29E 减 8
            self._fx12_visibility(e)                   # push 8
            return
        if e.p.get("kind") == "trail":                 # 0x42BC40（0x12061124）
            self.p4_spawn41(e.p["x"], e.p["y"], 0x41000015)   # 拖尾实体（0x42960B）
            self._fx12_integrate(e)                    # 0x42BC80
            self._fx12_place(e)                        # 0x42BC87 sub 8
            self._fx12_visibility(e)                   # 0x42BCA3 push 0x10
            return
        if e.p.get("kind") == "follow":                # 0x42BB80（0x12081123）
            self._fx12_integrate(e)                    # 0x42BB83
            cnt = e.p.get("cnt", 0)
            if cnt == 0:                               # 0x42BB8D je 0x42BB9E
                e.p["y"] = self.mirror_y()             # [+8] = [0x56CC90]
            else:
                cnt += 1                               # 0x42BB8F inc eax
                e.p["cnt"] = cnt
                e.p["blink"] = 1 if cnt > 3 else 0     # 0x42BB93 setg al
            if e.disp:
                if e.disp.rect[0] == 0x60:             # 0x42BBAF cmp dword [eax],0x60
                    e.disp.grow(0x18, 0, 0x18, 0)
                else:
                    e.disp.grow(-0x18, 0, -0x18, 0)
            self._fx12_place(e)                        # 0x42BBD1 sub 0xC → dst
            self._fx12_visibility(e)
            return
        # ---- track：0x42C320 ----
        tx = self.inp.x                                # 0x4021EE(0x4AD43C,&out1,&out2)：页13 取虚拟指针
        ty = self.inp.y
        dx = [e.p["x"] - int(tx)]                      # 0x42C362 sub edi,ecx
        dy = [e.p["y"] - int(ty)]
        spd = e.p["spd"] or 0
        if self._vset(dx, dy, spd):                    # 0x42C37C
            if (e.type_word & 0xFFFFFFFF) == 0x120A112F:   # 0x42C388 三倍速
                dx[0] *= 3
                dy[0] *= 3
            e.p["vx"] += dx[0]                         # 0x42C3B7
            e.p["vy"] += dy[0]
            vx = [e.p["vx"]]
            vy = [e.p["vy"]]
            if self._vset(vx, vy, spd << 3):           # 0x42C3CC 钳到 [+0x2C]*8
                e.p["vx"], e.p["vy"] = vx[0], vy[0]
        self._fx12_integrate(e)                        # 0x42C3D4
        self._fx12_visibility(e)

    def mirror_y(self) -> int:
        """`[0x56CC90]`：自机 y 镜像（页13 无自机 ⇒ 0）。"""
        return int(self.mirror["y"])

    def _fx12_place(self, e: UiEntity, off: "int | None" = None) -> None:
        """`0x42C0A3`/`0x42BBD1`/`0x42BA2A`：dst = (x−off, y−off)，off 默认 = ctor 减数。

        dst 偏移与可见性半径是两个独立量：`0x42B576`（0x12061127/0x12071126）与
        `0x42BA20`（0x120B1121/0x12091122）都在 −0x10 处落 dst，而半宽分别是 0x10 与 8。
        """
        if e.disp:
            h = e.p["half"] if off is None else off
            e.disp.dst[0] = e.p["x"] - h
            e.disp.dst[1] = e.p["y"] - h

    def _state2_bit(self, n: int) -> bool:
        """`0x40145B(0x56CCB8, n)`：全局状态对象 `0x56CCB8` 的第 n 位。

        该对象在页13 链路上没有任何写入点（页4 才建），此处按"位未置"处理并记录一次；
        本分支在页13 因 `[+0x2C]==0` 不可达，不影响复刻结果。
        """
        if not getattr(self, "_state2_logged", False):
            self._state2_logged = True
            self.log("0x56CCB8 状态对象未建模（ψ 页13 不可达分支），按 0 处理")
        return False

    def _spawn_4100_0004(self, x: int, y: int, pt) -> None:
        """`0x42BAB9` 的投放：`0x4023C4(rec, x, y, 0x41000004, &(vx>>7, vy>>7))` → `0x4AD4CC`。

        ctor = 0x428D59（与碰撞火花同一实体）：复刻走 spark_spawn。
        """
        self.spark_spawn(x, y, pt[0], pt[1]) if isinstance(pt, tuple) else self.spark_spawn(x, y, 0, 0)

    def _fx12_visibility(self, e: UiEntity, m=None) -> None:
        """`0x4021E9`(m=半宽) 与 `[+0x18]` 的与：不满足即结束（`al && [+0x18]`）。

        `0x42B9C0`/`0x42C050` 的尾部都是 `push 0x10`，即**硬编码 m=0x10**（不按 rect 算）。
        """
        if not e.disp:
            return
        if m is None:
            m = (e.disp.rect[2] - e.disp.rect[0] + 1) >> 1
        if not (self._on_screen(e.p["x"], e.p["y"], m) and e.p.get("vis", 1)):
            e.alive = False

    def _fx12_integrate(self, e: UiEntity) -> None:
        """`0x40173A`→`0x42B980`：8.8 位置 += 速度，像素 = 位置>>8；再写 dst。"""
        e.p["px"] += e.p["vx"]                         # [+0x24] += [+0x1C]
        e.p["py"] += e.p["vy"]
        e.p["x"] = e.p["px"] >> 8                      # [+4] = [+0x24] sar 8
        e.p["y"] = e.p["py"] >> 8
        e.d32(0x04, e.p["x"] & 0xFFFFFFFF)             # 同步原始字段（碰撞用）
        e.d32(0x08, e.p["y"] & 0xFFFFFFFF)
        if e.disp:                                     # 0x42C3DB..0x42C3F7
            half = e.p.get("m", e.p["half"])
            e.disp.dst[0] = e.p["x"] - half
            e.disp.dst[1] = e.p["y"] - half

    def _actor_0A(self, x: int, y: int, a3: int) -> UiEntity:
        """ctor `0x446117`（type 0x0A）：选中机体的大字（48×48）。

        `[+0x40]=0x401BE0(→0x448230)`、`[+0xC]=0xC`、`[+0x10]=0`、`[+0x18]=1`、`[+0x1C]=-1`、
        `[+0x20]=0x45AFC0(0x4AB5B0,0xC000)`（选中槽）、`[+0x30]=esi(=0 层号)`；
        显示节点：**层 0（bm_cm48）、rect `(0, 48*槽, 0x2F, 48*槽+0x2F)`**（48×48 汉字图集
        第 槽 行第 0 列）、dst `= (x-0x18, y-0x18)`（页13 送 (0xA0,0x78) ⇒ (136,96) 居中）。
        """
        e = UiEntity(type_word=0x0A, a3=int(a3))
        e.beh = "kanji_actor"
        e.t = -1                                  # [+0x1C] = -1，每帧 ++
        e.aux = 0                                 # [+0xC] = 0xC（本行为不用）
        e.p["slot"] = self.keys.field(0xC000)     # [+0x20]
        e.p["x"], e.p["y"] = int(x), int(y)       # [+4]/[+8]
        # 0x4461D1..0x4461F9：ctor 末尾调用 `0x401753(x,y)`（= `0x45A690`，**原样返回**）
        # 并把它写进自机镜像 `0x56CC8C/0x56CC90` ⇒ 页13 的"自机位置"= 机体大字的位置
        # (0xA0,0x78)=(160,120)。0x12 特效的追踪/贴线行为都读这个镜像。
        _mx, _my = int(x), int(y)
        self.p4_player_pos = (_mx, _my)           # 0x4461D1：同一地址 [0x56CC8C/90]（setter 同步 mirror/p4_stat）
        self.log(f"0x4461DF 自机镜像 := ({_mx},{_my})")
        n = e.p["slot"]
        e.disp = DisplayNode(0, [0, 0x30 * n, 0x2F, 0x30 * n + 0x2F],
                             [int(x) - 0x18, int(y) - 0x18])
        self.actorq.append(e)                     # 0x4AD40C 演员队列（不是 0x4AD46C）
        # 0x4461E5..0x4461FE：ctor 末尾再生成一条 **0x10008043**（x=0xA0,y=0x78,a3=本实体），
        # 经 `0x446220 0x40100F` 入 **0x4AD46C**。0x4AD40C 先 tick、0x4AD46C 后 tick ⇒ 同帧即开始跑。
        self._dot_spawn(0xA0, 0x78, e)
        self.log(f"actor 0x0A slot={n} dst=({x-0x18},{y-0x18}) rect={e.disp.rect}")
        return e

    def _dot_spawn(self, x: int, y: int, parent: "UiEntity | None" = None) -> UiEntity:
        """ctor `0x42DABC`（type **0x10008043**，0x10 类；`0x42D988 cmp eax,0x10008043 / je 0x42DABC`）。

        `[+0x40]=0x4021A3`（→ 行为 `0x42F080`）、`[+0xC]=0x30`、`byte[+0x10]=1`、`[+0x1C]=0`、
        `[+0x20]=0`、`[+0x24]=rec[0xC]`（父实体）、`[+0x28]=field(0xC000)`（选中槽）、`[+0x18]=-1`；
        显示节点：层 **0**（`0x42DB86 mov [ecx],ebx`，ebx=0）、rect `(0x8D,0x2D,0x93,0x32)`（7×6 小方块）、
        dst `= 0x401753(x-3, y-3)`、`byte[dst+0x1C] = byte[0x56CCC8]`。
        槽 3 特例（`0x42DBE8..0x42DC40`）：`[+0xC]=0x10000`、rect `(0x60,0x60,0xBF,0xBF)`（96×96）、
        `byte[+0x10]=0`、`dst.x=0x280`、类型改写成 **0x10008041**（改用行为表）。
        """
        e = UiEntity(type_word=0x10008043, a3=int(parent.p.get("slot", 0)) if parent else 0)
        e.beh = "dot10"
        e.aux = 0x30                              # [+0xC]
        e.p["slot"] = self.keys.field(0xC000)     # [+0x28]
        e.p["t"] = 0                              # [+0x20] 计时器
        e.p["f1c"] = 0                            # [+0x1C]
        e.p["blink"] = 1                          # byte[+0x10]
        e.p["x"], e.p["y"] = int(x), int(y)       # [+4]/[+8]
        e.p["parent"] = id(parent) if parent else 0
        rect = [0x8D, 0x2D, 0x93, 0x32]
        dst = [int(x) - 3, int(y) - 3]
        if e.p["slot"] == 3:                      # 0x42DBE0 cmp eax,3 / jne
            if e.type_word == 0x10008043:         # 0x42DBEA..0x42DBF3
                e.aux = 0x10000
            rect = [0x60, 0x60, 0xBF, 0xBF]       # 0x42DBFA..0x42DC10
            e.p["blink"] = 0
            dst = [0x280, dst[1]]                 # 0x42DC39 mov [edx+0x14],0x280
            e.type_word = 0x10008041              # 0x42DC40
        e.disp = DisplayNode(0, rect, dst, active=False)   # byte[0x56CCC8] 页13 = 0
        self.ui46c.append(e)                      # 0x4AD46C
        self.log(f"dot 0x10008043 slot={e.p['slot']} dst={dst} rect={rect}")
        return e

    def _dot10(self, e: UiEntity) -> None:
        """行为 `0x42F080`（`0x4021A3` thunk）——0x10008041/043 的小方块指示器。

        1. `0x42F095`：`[+0x28] != field(0xC000)` ⇒ 返回 0（换槽即销毁）。
        2. `0x4012E4`→`0x42F4B0(blink)`：blink 时 `rect += (-3,-3,+3,+3)`、`dst -= 3`（`dst.x==0x60` 停）；
           否则 `rect += (+3,+3,-3,-3)`、`dst += 3`（`dst.x==0x90` 停）。
        3. `0x42F0B6`：`dst.active = (dst.y != 0x90)`；`t < 0x180 && 槽 != 2` ⇒ 隐藏，直接到尾部。
        4. `0x42F0F9 jmp [槽*4+0x42F3C0]` ⇒ 四个槽各自的轨迹（见下）。
        5. 尾部 `0x42F35F`：不可见 ⇒ `x,y := (0xA0,0x78)`；`t += (t<0x39C ? 1 : -t)`（到 0x39C 归零）；
           `dst = (x + rect.l - 0x90, y + rect.t - 0x90)`。
        """
        d = e.disp
        if d is None:
            e.alive = False
            return
        if e.p["slot"] != self.keys.field(0xC000):     # 0x42F095
            e.alive = False
            self.log("dot 0x10008043：换槽 ⇒ 销毁")
            return
        # 0x42F0AE 0x4012E4(al) → 0x42F4B0。注意守卫读的是 **`[dst+4]` = rect.left**（不是 dst.x）：
        # `0x42F4C4 cmp ecx,0x60` / `0x42F4FE cmp ecx,0x90`，且 `0x42F4C1 add eax,4` 才是传给
        # `0x401A0A` 的矩形指针 ⇒ rect.l 从 0x8D 起每帧 ∓3，正好落在 0x60 / 0x90。
        if e.p["blink"]:
            if d.rect[0] != 0x60:
                d.grow(-3, -3, 3, 3)
                d.dst[0] -= 3; d.dst[1] -= 3
        else:
            if d.rect[0] != 0x90:
                d.grow(3, 3, -3, -3)
                d.dst[0] += 3; d.dst[1] += 3
        d.active = d.rect[0] != 0x90                   # 0x42F0B6..0x42F0C0（同样读 [eax+4]）

        t = e.p["t"]; x = e.p["x"]; y = e.p["y"]; slot = e.p["slot"]
        if t < 0x180 and slot != 2:                    # 0x42F0CC..0x42F0E8
            d.active = False
        elif slot <= 3:
            if slot == 0:                              # 0x42F100
                if t < 0x234:
                    if x < 0x250:
                        x += 0xA
                    if y > 0x30:
                        y -= 0xA
                elif t < 0x26B:
                    if x > 0x30:
                        x -= 0xA
                    if y < 0xC0:
                        y += 0xA
                else:
                    if y > 0x30:
                        y -= 0xA
                e.p["blink"] = 1 if t < 0x284 else 0            # 0x42F146
                self.g56cc94 = 1 if t == 0x284 else 0           # 0x42F159
                e.p["f1c"] = 1 if t < 0x284 else 0              # 0x42F164..0x42F16D
            elif slot == 1:                            # 0x42F175 追自机；页13 无自机 ⇒ 0x42F1C9
                e.p["blink"] = 1 if t < 0x28E else 0            # 0x42F1CC
                self.g56cc94 = 1 if t == 0x284 else 0           # 0x42F1DC
                e.p["f1c"] = 1 if 0x1F8 < t < 0x28E else 0      # 0x42F1E4..0x42F204
            elif slot == 2:                            # 0x42F20C
                x, y = 0x170, 0x78
                e.p["f1c"] = 1
                self.g56cc94 = 1 if t >= 0x216 else 0
            else:                                      # 0x42F234（槽3：圆运动）
                ang = 20 * (3 * t - 0x480)                        # 0x42F252..0x42F25C
                if t < 0x2AC:
                    a = max(5 * (0x220 - t), 0xC8)                # 0x42F23B..0x42F24D
                    x = 0xA0 + (fcos(ang) * a >> 8)               # 0x42F260..0x42F271
                    y = 0x78 + (fsin(ang) * a >> 8)               # 0x42F29F..0x42F308
                else:                                             # 0x42F2AC
                    k = 10 * (t - 0x298)                          # 0x42F2C2..0x42F2CE
                    x = 0xA0 + (fcos(ang) * k >> 8)
                    y = 0x78 + (fsin(ang) * k >> 8)
                if 0x1F8 <= t < 0x306:                            # 0x42F314..0x42F32C
                    e.p["f1c"] -= 1
                    e.p["blink"] = 1 if e.p["f1c"] == 0 else 0
                else:
                    e.p["blink"] = 0
                if e.p["f1c"] == 0:                               # 0x42F333..0x42F33A
                    e.p["f1c"] = 1
                self.g56cc94 = 1 if (t >= 0x1F8 and t < 0x324) else 0   # 0x42F341..0x42F358
        e.p["x"], e.p["y"] = x, y

        if not d.active:                               # 0x42F364..0x42F372
            x, y = 0xA0, 0x78
        t = t + 1 if t < 0x39C else t - t              # 0x42F379..0x42F391
        e.p["t"] = t
        d.dst[0] = x + int(d.rect[0]) - 0x90           # 0x42F397..0x42F3A1（[ecx+4]=rect.l）
        d.dst[1] = y + int(d.rect[0]) - 0x90           # 0x42F3AB..0x42F3B5（同样读 [eax+4]，原作如此）

    def portrait_data(self) -> bytes:
        """资源 0x4F（=79）→ `extracted/data/res_79.bin`（19200B = 320×60）。"""
        global _PORTRAIT
        if _PORTRAIT is None:
            f = REMAKE.parent / "extracted" / "data" / "res_79.bin"
            try:
                _PORTRAIT = f.read_bytes()
            except OSError:
                _PORTRAIT = b""
        return _PORTRAIT

    def _portrait(self, e: UiEntity) -> None:
        """行为 `0x43F340`（`0x6F000007`）：首帧铺满 80×60 块，之后按选中槽横向滚动。

        首帧（`[+0x1C]==0`）：`p = 0x45DDA0(0x4F) + row*0x140`，`row<0x3C`、`col<0x50`，
        逐块 `0x43F230(ent, col, row, byte[p+col])`（`0x401082`，8×8 一块）；
        `0x45AFF0(0x4AB5B0,0x400)` 为真时颜色强制 `0xB4`。画完 `0x43F38A/0x43F3BE` 各投一条
        `0x4F000009`（a3=1 / a3=0）进 `0x4AD4CC`，并把 `[+0x1C]=-1`（`0x43F3F4`）。

        之后每帧（`0x43F403..0x43F4E3`）：`[+0x20]` 追 `[+0x24] = 选中槽*0x50`，
        `step = ((|d|>>3)&0xFFFE)+1`，每次 ±1 并**只重画那一列块**：
        增大（`0x43F43A`）时块列 `x = cur%0x50` ← 源列 `cur+0x50`，`cur++`；
        减小（`0x43F478`）时块列 `x = (cur-1)%0x50` ← 源列 `cur-1`，`cur--`。
        `cur == target` 时整段跳过（`0x43F40B je`），但循环中途相等会走"减小"支（照抄）。
        """
        data = self.portrait_data()
        if not data:
            self.log("0x6F000007：res_79 缺失，跳过全屏人像")
            e.alive = False
            return
        if not e.p.get("drawn"):                       # 0x43F34C test eax,eax / jne 0x43F403
            e.p["drawn"] = True
            mono = self.keys.test(0x400)               # 0x43F35A 之后的 0x45B030(…,0x400)（位清时真）
            res = np.frombuffer(data, dtype=np.uint8).reshape(0x3C, 0x140)
            tiles = self._portrait_tiles()             # 0x43F230 的瓦片源 = 层4（bm_psel2 256×256）
            if tiles is None:
                self.log("0x43F230：层4(bm_psel2) 缺失，人像跳过")
                e.alive = False
                return
            self.p13_src = res                          # 原始字节（滚动时按列取）
            self.p13_tiles = tiles
            self.p13_mono = mono
            e.p["cols"] = list(range(0x50))            # 块列 → 源列（res_79 的列号）
            self.p13_portrait_arr = None               # 由 _portrait_build 生成
            e.p["cur"] = 0
            # 0x43F38A → 0x4023C4(rec,0,0,0x4F000009,1)；0x43F3BE → a3=0
            self.wipe4f = [{"a3": 1, "cur": 0}, {"a3": 0, "cur": 0}]
            self._portrait_build(e)
            self.log("0x6F000007：res_79 瓦片索引 → 层4 的 8×8 块铺满层5 + 两块 0x4F000009 擦切")
        if self.p13_src is None:
            return
        cur = int(e.p["cur"])
        target = (self.keys.field(0xC000) & 0xFFFFFFFF) * 0x50   # 0x43F4CC..0x43F4E3
        cols = e.p["cols"]
        if cur != target:                              # 0x43F40B je 0x43F4CC
            n = (((abs(cur - target) >> 3) & 0xFFFE) + 1) + 1    # 0x43F411..0x43F428
            while n:
                if cur >= target:                      # 0x43F432 jge 0x43F478
                    x = (cur - 1) % 0x50               # 0x43F498..0x43F49C
                    cols[x] = cur - 1                  # 0x43F48E 源列 = cur-1
                    cur -= 1                           # 0x43F4B6..0x43F4B9
                else:
                    x = cur % 0x50                     # 0x43F455..0x43F458
                    cols[x] = cur + 0x50               # 0x43F450 源列 = cur+0x50
                    cur += 1                           # 0x43F472..0x43F475
                n -= 1
            e.p["cur"] = cur
            self._portrait_build(e)
        e.p["cur"] = cur

    def _portrait_tiles(self):
        """`0x43F230` 的瓦片源：层4（`bmetc\bm_psel2`，256×256）→ `(2,2,256,8,8)` 表。

        源矩形（`0x43F24B..0x43F282`）= `{l=lo*16, t=hi, r=lo*16+8, b=hi+8}`，
        `hi=color&0xF0`、`lo=color&0xF`；`x` 奇 → `0x45A790(rect,8,0,8,0)`（l/r += 8）、
        `y` 奇 → `0x45A790(rect,0,8,0,8)`（t/b += 8）。第 0 维是 y 象限、第 1 维是 x 象限。
        """
        lay = self.layers.tab.get(4)
        if lay is None:
            return None
        atlas = lay.buf
        tab = np.zeros((2, 2, 256, 8, 8), dtype=np.uint8)
        for c in range(256):
            cx = (c & 0x0F) * 16
            cy = c & 0xF0
            for qy in (0, 1):
                for qx in (0, 1):
                    y0, x0 = cy + 8 * qy, cx + 8 * qx
                    if y0 + 8 <= atlas.shape[0] and x0 + 8 <= atlas.shape[1]:
                        tab[qy, qx, c] = atlas[y0:y0 + 8, x0:x0 + 8]
        return tab

    def _portrait_build(self, e: UiEntity) -> None:
        """把人像层（层5）按当前窗口列 `cols` 重新拼成 640×480。"""
        if self.p13_src is None:
            return
        if self.p13_src is None:
            return
        res = self.p13_src                            # 60×0x140
        cols = e.p["cols"]
        c = res[:, cols]                              # 60×80：每块一个 `color` 字节
        if self.p13_mono:                             # 0x43F246：16 色近似时 color=0xB4
            c = np.full_like(c, 0xB4)
        qx = np.arange(0x50) & 1                      # 0x43F27B：x 奇 → 源矩形右移 8
        qy = np.arange(0x3C) & 1                      # 0x43F29D：y 奇 → 源矩形下移 8
        tile = self.p13_tiles[qy[:, None], qx[None, :], c]      # 60×80×8×8
        self.p13_portrait_arr = tile.transpose(0, 2, 1, 3).reshape(0x3C * 8, 0x50 * 8)

    def posq_spawn(self, x: int, y: int, slot: int) -> None:
        """`0x401FA5`→`0x43BDC0` 插 `0x4AD43C`，ctor 链 `0x43A7F0`(vtable 0x49874C)
        → `type&0x2F000000==0x23000000` → `0x4013D9`→`0x40D940`(vtable 0x498000)
        → `type-0x23000001==0x19` → `0x40DE43`（0x2300001A 分支）。

        ctor 字段：`[+0x40]=0x40242D`(→0x4108C0)、`[+0x1C]=0`、`[+0x24]=-0x40`、
        `[+0x20]=(y<0x78)?-1:+1`、`[+0x28]=0`、`[+0x2c]=x<<4`、`[+0x30]=y<<4`、
        `[+0x18]=选中槽+1`。
        """
        self.posq.append({
            "slot1": (slot & 0xFFFFFFFF) + 1,          # 0x40DE85 0x45AFC0(…,0xC000)+1
            "beh": 0x4108C0,                            # 0x40DE59 [esi+0x40] = 0x40242D
            "t": 0,                                     # 0x40DE63 [esi+0x1C] = 0
            "vx": -0x40,                                # 0x40DE67 [esi+0x24] = 0xFFFFFFC0
            "dir": 1 if y >= 0x78 else -1,              # 0x40DE4A..0x40DE71
            "vy": 0,                                    # 0x40DE7C [esi+0x28] = 0
            "fx": (x & 0xFFFFFFFF) << 4,                # 0x40DE76/0x40DE7F
            "fy": (y & 0xFFFFFFFF) << 4,                # 0x40DE79/0x40DE82
            "x": x, "y": y,
        })
        self.log(f"0x4AD43C 插入 0x2300001A ({x},{y}) slot={slot}（0x40DE43 分支）")

    def _tick_posq(self) -> None:
        """`0x4108C0`（`0x2300001A` 位置对象行为，`0x458E70` 第 4 个泵队列 `0x4AD43C`）。

        - 选中槽变了（`[+0x18] != 槽+1`）→ `al=0` 自尽（`0x4108D6`）
        - `t=++[+0x1C]`；`0x3C<t<=0x82`：`[+0x24] = -min(2|t-0x5F|,0x40)`；`t>0xAA`：
          `[+0x24] = min([+0x24]+2,0x60)`（`0x4108F2..0x410923`）
        - 同窗：`[+0x28] = (|t-0x5F|-0x23)*[+0x20]*2`（`0x410933..0x410944`）；
          `0xAA<t<=0xF0`：`[+0x28] = (0x23-|t-0xCD|)*[+0x20]*2`（`0x410951..0x410971`）
        - `[+0x2c]+=[+0x24]`、`[+0x30]+=[+0x28]`（`0x41097D/0x410985`），
          `[+4]=[+0x2c]>>4`、`[+8]=[+0x30]>>4`（`0x41098C..0x410995`）
        - 显示节点 dst = `(x-0x18, y-0x18)`（`0x410998..0x4109AE`），`rect` 全 0 ⇒ 不可见
        - 存活 = `x < 0x298`（`0x4109B4`）
        """
        slot_now = (self.keys.field(0xC000) & 0xFFFFFFFF) + 1   # 0x4108C3..0x4108D5
        live = []
        for e in self.posq:
            if e["slot1"] != slot_now:                  # 0x4108D6 cmp/jne
                continue
            t = e["t"] + 1                              # 0x4108DE inc
            e["t"] = t
            if 0x3C < t <= 0x82:                        # 0x4108E2..0x4108F0
                d = abs(t - 0x5F) * 2                   # 0x4108F2..0x4108FA
                if d > 0x40:                            # 0x4108FC..0x410901
                    d = 0x40
                e["vx"] = -d                            # 0x410906 neg
            if t > 0xAA:                                # 0x41090B
                v = e["vx"] + 2                         # 0x410913..0x410916
                if v >= 0x60:                           # 0x410919..0x41091E
                    v = 0x60
                e["vx"] = v                             # 0x410923
            if 0x3C < t <= 0x82:                        # 0x410926..0x410931
                e["vy"] = (abs(t - 0x5F) - 0x23) * e["dir"] * 2   # 0x410933..0x410944
            elif 0xAA < t <= 0xF0:                      # 0x410949..0x410957
                e["vy"] = (0x23 - abs(t - 0xCD)) * e["dir"] * 2   # 0x410959..0x410971
            e["fx"] += e["vx"]                          # 0x410974..0x410982
            e["fy"] += e["vy"]                          # 0x41097F..0x410989
            e["x"] = e["fx"] >> 4                       # 0x41098F sar 4
            e["y"] = e["fy"] >> 4                       # 0x41098C sar 4
            if e["x"] < 0x298:                          # 0x4109B1..0x4109C9
                live.append(e)
        self.posq = live

    # ---- 0x41000004：命中火花（4CC 队列，ctor 0x428D59 / 行为 0x429D40）----
    def spark_spawn(self, x: int, y: int, ax: int, ay: int) -> None:
        """ctor `0x428D59`：`[+0x40]=0x40200E`、`[+0xC]=0x10`、rect `(0xA0,0,0xBF,0x1F)`、
        `[+0x1C]=a3[0]`、`[+0x20]=a3[4]`、`[+0x24]=x<<2`、`[+0x28]=y<<2`、`[+0x2C]=0x14`、
        `[+0x18]=1`、显示层 1。"""
        self.spark4cc.append({"x": (int(x) << 2), "y": (int(y) << 2),
                              "vx": int(ax), "vy": int(ay), "cnt": 0x14, "life": 0x10,
                              "rect": [0xA0, 0, 0xBF, 0x1F], "dx": 0, "dy": 0})

    def _tick_spark4cc(self) -> None:
        """行为 `0x429D40`：位置 += 速度 → `px=pos>>2` → dst `(px-0x10,py-0x10)`；
        `[+0x2C]--`，当 `[+0x2C]&3==0 && !=0` 时 `0x45A790(rect,0x20,0,0x20,0)`；
        寿命 `[+0xC]` 每帧 −1（由 4CC 队列的通用计时负责）。"""
        out = []
        for e in self.spark4cc:
            e["x"] += e["vx"]
            e["y"] += e["vy"]
            px, py = e["x"] >> 2, e["y"] >> 2
            e["dx"], e["dy"] = px - 0x10, py - 0x10
            e["cnt"] = (e["cnt"] - 1) & 0xFFFFFFFF
            if (e["cnt"] & 3) == 0 and e["cnt"] != 0:
                e["rect"][0] += 0x20
                e["rect"][2] += 0x20
            e["life"] -= 1
            if e["life"] > 0:
                out.append(e)
        self.spark4cc = out

    def _collide_46c_43c(self) -> None:
        """`0x43C060(ctx,&4AD46C,&4AD43C)`：外层特效、内层位置对象的两两距离判定。

        门：`0x40145B(0x56CCB8,2)` 为真**或** `[+0x14]&0x8000`；内层要求外层 `[+0x10]!=0`。
        判定 `0x4306C0(ent,x,y,size)`：`al=[ent+0x10]`，`|dx|+|dy| - (ent.size>>2) - (size>>2) - size <= 0`。
        命中 → `0x43C460`：按被撞对象 `[+0x14]&0x7000` 取 a3（0x1000 速度方向 / 0x2000 随机 ±15 / 其它不生成），
        投放 `0x41000004` 到 `0x4AD4CC`。
        """
        for e in self.ui46c:
            if not (e.p.get("vis", 1)):
                continue
            t = int(getattr(e, "type_word", 0)) & 0xFFFFFFFF
            if not (self._state2_bit(2) or (t & 0x8000)):
                continue
            for o in self.posq:
                # `0x4306C0(ent=内层, x=外层.x, y=外层.y, a=[外层+0xC])`：
                # 返回 1 当 `|dx|+|dy| - (S>>2) - (A>>2) - S - A <= 0`（S=[内层+0xC]、A=[外层+0xC]）
                S = int(o.get("size", 0))
                A = int(e.p.get("life", 0))
                d = abs(int(e.p["x"]) - int(o.get("x", 0))) + abs(int(e.p["y"]) - int(o.get("y", 0)))
                thr = (S >> 2) + (A >> 2) + S + A
                if d - thr > 0:
                    continue
                cls = int(o.get("flag", 0)) & 0x7000
                if cls == 0x1000:
                    ax, ay = (o.get("vx", 0) >> 7), (o.get("vy", 0) >> 7)
                elif cls == 0x2000:
                    r1 = (self._rng() & 0x1F) - 0xF
                    r2 = (self._rng() & 0x1F) - 0xF
                    ax, ay = r1, r2
                else:
                    continue
                self.spark_spawn(o.get("x", 0), o.get("y", 0), ax, ay)
                break

    def _tick_wipe4f(self) -> None:
        """行为 `0x439BD0`（ctor 分支 `0x436E45`）：`[+0x20]` 追 `选中槽*0x50`，按余数 0x50 取擦切位。"""
        target = (self.keys.field(0xC000) & 0xFFFFFFFF) * 0x50   # 0x439BD8 0x4019C9(0x4AB5B0,0xC000)
        for w in self.wipe4f:
            cur = int(w["cur"])
            if cur != target:                              # 0x439BF0 cmp eax,ecx / je
                d = abs(cur - target)
                step = ((d >> 3) & 0xFFFE) + 1             # 0x439BFB..0x439C03
                if step >= 0:                              # 0x439C04 js
                    n = step + 1                           # 0x439C06 lea edx,[eax+1]
                    while n:                               # 0x439C09..0x439C18
                        # 0x439C0C `cmp eax,ecx / jge 0x439C13`：cur **>=** target 才 `dec`
                        # （旧版把两支写反了 ⇒ cur 一路跑飞成负数，擦切位每帧乱扫，
                        #   表现为"人像背景不停自己移位"）
                        cur = cur - 1 if cur >= target else cur + 1
                        w["cur"] = cur
                        n -= 1
            cur = int(w["cur"])
            w["pos"] = (cur % 0x50) << 3                   # 0x439C1D..0x439C2A idiv 0x50, shl 3

    def _kanji_actor(self, e: UiEntity) -> None:
        """行为 `0x448230`：槽变了就自尽；t<0x5A 走每槽效果分派；t≥0x39C 结束。

        公共尾 `0x44898B`：表 `0x448A24` 的每槽时间窗 `{0x286,0x28E,0x216,0x39D}`，
        在 `[th, th+0x1C)` 内按 `t&2` 把源矩形在列 0 / 列 0x30 之间抖动（`rect.l=0 or 0x30`）。
        """
        if e.p["slot"] != self.keys.field(0xC000):     # 0x44823A..0x44825A
            e.alive = False
            return
        t = e.t
        if t >= 0:                                     # 0x44825F cmp ecx,0x5A / jge 0x44843F
            self._kanji_slot_effect(e, e.p["slot"], t)
        th = (0x286, 0x28E, 0x216, 0x39D)[e.p["slot"] & 3]
        if e.disp and th <= t < th + 0x1C:             # 0x4489AD..0x4489DF
            l = 0x30 if (t & 2) else 0
            e.disp.rect[0] = l
            e.disp.rect[2] = l + 0x2F
        e.t += 1
        if e.t >= 0x39C:                               # 0x4489FB
            e.alive = False

    def _kanji_slot_effect(self, e: UiEntity, slot: int, t: int) -> None:
        """`0x448277 jmp [slot*4 + 0x448A30]` = `{0x44827E, 0x4482DA, 0x448356, 0x4483AC}`。

        t<0x5A 的效果段，四支都先 `idiv` 取 `t % N`，余数非 0 直接跳公共尾 `0x44898B`；
        命中则 `0x4023C4(dst, x=0xB0, y=0x78, type, a3)` 造 5-dword 记录，`0x40100F(0x4AD46C)`
        入弹队列（`0x40100F`→`0x430290`，节点 ctor `0x401DCA`→`0x42D780`）。
        槽1/槽3 各投**两发**：先投一发，再把记录第 4 个 dword（a3）改写成另一值投第二发。
        """
        recs = []
        if slot == 0 and t < 0x5A:                     # 0x44827E：t%6==0
            if t % 6 == 0:                             # 0x448280..0x44828A
                recs = [(0x120B1121, 0x78, 0xE00)]
        elif slot == 1 and t < 0x5A:                   # 0x4482DA：t%6==0，两发
            if t % 6 == 0:                             # 0x4482DC..0x4482E6
                recs = [(0x12071126, 0x78, 0xF4000A00),
                        (0x12071126, 0x78, 0x0C000A00)]   # 0x44833C 改写 a3 后再投
        elif slot == 2 and t < 0x5A:                   # 0x448356：t%5==0
            if t % 5 == 0:                             # 0x448358..0x448362
                recs = [(0x120F112A, 0x78, 0xF00)]
        elif slot == 3 and t < 0x5A:                   # 0x4483AC：t%7==0，两发
            if t % 7 == 0:                             # 0x4483AE..0x4483B8
                recs = [(0x120E112D, 0x78, 0xFA000A64),
                        (0x120E112D, 0x78, 0x06000A64)]   # 0x4483FB 第二发
        elif 0x78 <= t < 0xD2:                         # 0x44843F：中段按槽跳 0x448A40
            if slot == 0:                              # 0x448464：t&7==0，四发
                if (t & 7) == 0:                       # 0x448464 test cl,7
                    recs = [(0x12091122, 0x78, 0x4280D00),   # 0x44846D
                            (0x12091122, 0x78, 0x07900C80),  # 0x4484C3 只改 a3
                            (0x12091122, 0x75, 0xFBD80D00),  # 0x4484DA 改 y=0x75 + a3
                            (0x12091122, 0x75, 0xF8700C80)]  # 0x4484F3 只改 a3
            elif slot == 1:                            # 0x448510：t%6==0，四发
                if t % 6 == 0:                         # 0x448512..0x44851C
                    recs = [(0x12061127, 0x78, 0xF6000A00),  # 0x448522
                            (0x12061127, 0x78, 0x0A000A00),  # 0x448572 只改 a3
                            (0x12061127, 0x88, 0x0A0008E0),  # 0x448585 y+=0x10 + a3
                            (0x12061127, 0x68, 0xF60008E0)]  # 0x4485A7 y-=0x20 + a3
            elif slot == 2:                            # 0x4485D3：t%3==0，一发（借槽1 的入队尾 0x4485BE）
                if t % 3 == 0:                         # 0x4485D5 mov ecx,3 / idiv
                    v = self._rng() & 0x1FFF           # 0x4485E5 and eax,0x1FFF
                    a3 = (((v - 0xFFF) & 0xFFFF) << 16) | 0x0400   # 0x4485F6..0x448603
                    recs = [(0x120D112B, 0x78, a3)]    # 0x448607
            else:                                      # 0x44862F：t%0xA==0，四发（a3 = ~a3 交替）
                if t % 0xA == 0:                       # 0x448631 mov esi,0xA / idiv
                    def _pair(n: int) -> int:          # 0x448641..0x44866F / 0x4486D2..0x448706
                        c = fcos(n) & 0xFFFFFFFF       # 0x40159B → 0x45ABB0
                        q = fsin(n) & 0xFFFFFFFF       # 0x401A50 → 0x45AAF0
                        return (((q << 0x13) & 0xFFFF0000) |
                                ((c << 3) & 0xFFFF)) & 0xFFFFFFFF
                    a3a = _pair(t * 20)                # ecx=t*5<<2
                    a3b = _pair(t * 40)                # [ebp+0x1C]*5<<3
                    recs = [(0x120C112E, 0x78, a3a),
                            (0x120C112E, 0x78, ~a3a & 0xFFFFFFFF),   # 0x4486C1 not edx
                            (0x120C112E, 0x78, a3b),
                            (0x120C112E, 0x78, ~a3b & 0xFFFFFFFF)]   # 0x448723 not ecx
        elif 0xF0 <= t < 0x14A:                        # 0x44873E：晚段，跳表 0x448A50
            if slot == 0:                              # 0x448766：t%3==0，一发
                if t % 3 == 0:                         # 0x448768 mov ecx,3 / idiv
                    recs = [(0x12081123, 0x78, 0x1000)]      # 0x448778
            elif slot == 1:                            # 0x4487BC：t%3==0，两发
                if t % 3 == 0:                         # 0x4487BE mov ecx,3 / idiv
                    recs = [(0x12061128, 0x78, 0xFA000C00),  # 0x4487CE
                            (0x12061128, 0x78, 0x06000C00)]  # 0x44881A
            elif slot == 2:                            # 0x44886D：t%7==0，一发
                if t % 7 == 0:                         # 0x44886F mov ecx,7 / idiv
                    v = self._rng() & 0x1FFF           # 0x44887F and eax,0x1FFF
                    recs = [(0x120C112C, 0x78,
                             (((v - 0xFFF) & 0xFFFF) << 16) | 0x0400)]  # 0x448890..0x44889D
            else:                                      # 0x4488D9：t%4==0，一发
                if (t & 3) == 0:                        # 0x4488D9 and ecx,0x80000003 取模判零
                    recs = [(0x120A112F, 0x78, 0xF000)]      # 0x4488EC
        elif 0x180 <= t < 0x220 and (t & 0xF) == 0:    # 0x44892D：与槽无关的位置对象
            # `0x4023C4(rec, 0x298, (t&0x10)?0x28:0xC8, 0x2300001A, 0)`，队列 0x4AD43C、插入 0x401FA5→0x43BDC0
            y = 0x28 if (t & 0x10) else 0xC8           # 0x448942..0x44895D
            self.posq_spawn(0x298, y, slot)             # 0x4AD43C / 0x401FA5→0x43BDC0
        for ty, yy, a3 in recs:
            self.actor_spawn(0xB0, yy, ty, a3)

    def _psel(self, e: UiEntity) -> None:
        """0x43EDB0：页13 选择画面总控（7 态机）。

        槽位 = `[0x4AB59C]`（虚拟指针 X）**/ 161**；`0x45B030(0x4AB5B0,0x80000)` 为真
        （= 0x80000 位**未**置位）时槽 3 被 `SetCursorPos(0x1E0,0xF0)` 拽回槽 2。
        态 0 生成子实体；态 1/3/5 各停 `0x10` 帧；态 2 = 选择中（换槽写 `0xC000` 字段、
        按 [0x4AB596] 确定 / [0x4AB597] 取消）；态 4 → 旗标 `0x10000`；态 6 → 旗标 `0x200`。
        """
        # 0x43EDBE..0x43EDDD：`ecx=[0x4AB59C]`，`imul 0xCB8727C1` + `add edx,ecx` + `sar edx,7`
        # = **除以 161（0xA1）**（按常数逆向：2^39/161 的上取整正是 0xCB8727C1），
        # 再 `shr/sar` 组合做向零取整 ⇒ 槽 = x/161（640/161≈3.98 ⇒ 4 槽，边界 161/322/483）。
        n = int(self.inp.x) // 0xA1
        if self.keys.clear_test(0x80000) and n == 3:
            self.inp.set_pos(0x1E0, 0xF0)                 # 0x43EDED SetCursorPos(480,240)
            n = 2
        state = e.a3
        changed = (n != e.aux)                            # 0x43EE0F setne al
        e.aux = n                                         # 0x43EE16 [ebx+0x24] = esi
        if state == 0:                                    # 0x43EE26（进场生成）
            self.actor_spawn(0xA0, 0x78, 0x0A)            #   {160,120,0xA,0} → 0x4AD40C
            self.spawn_flash(-255, 0, 0x10)               #   淡入 -255→0、每帧 +16
            self.spawn(self.ui52c, 0x6F000007)            #   缩略图（0x43F340，未实现）
            self.spawn(self.ui4fc, 0x5F00001B)            #   0x43EEDA 高亮框
            # 0x43EF11 / 0x43EF4E / 0x43EF85：**三条** 0x5F00001C，a3 = 0 / 1 / 2
            # （旧版只投了 a3=1、2 ⇒ 菜单第一项不显示，但槽位仍能在 3 台间切换）
            self.spawn(self.ui4fc, 0x5F00001C, a3=0)
            self.spawn(self.ui4fc, 0x5F00001C, a3=1)
            self.spawn(self.ui4fc, 0x5F00001C, a3=2)
            self.spawn(self.ui4fc, 0x5F00001D,
                       a3=self.keys.field(2) & 0xFF)      #   鼠 / 操作器 标签
            e.a3 = 1
        elif state in (1, 3, 5):                          # 0x43F00E：停 0x10 帧后推进
            if e.a4 == 0x10:
                e.a3 = state + 1
        elif state == 2:                                  # 0x43F023
            if changed:
                self.keys.set_field(0xC000, n)            #   0x45B0E0(0x4AB5B0,0xC000,n)
                self.actor_spawn(0xA0, 0x78, 0x0A)        #   重铺（0x43F037..0x43F06F）
            if self.inp.rec.e0:                           #   [0x4AB596] 攻击键 → 确定
                e.a3 = 3
                self.inp.set_mode(1)                      #   0x44EDA0(mgr,1)
                self.spawn_flash(0, -255, -0x10)           #   淡出 0→-255、每帧 -16
            elif self.inp.rec.e1:                         #   [0x4AB597] 锁定键 → 取消
                e.a3 = 5
                self.inp.set_mode(1)
                self.spawn_flash(0, -255, -0x10)
        elif state == 4:                                  # 0x43F0DA
            self.flags.set(0x10000)
        elif state == 6:                                  # 0x43F0E1
            self.flags.set(0x200)
        # 0x43F0F0 尾部：状态变了 → `[+0x20]=0`；没变 → `[+0x20]++`
        if state != e.a3:
            e.a4 = 0
        else:
            e.a4 += 1

    def _psel_band(self, e: UiEntity) -> None:
        """0x426B20（0x5F00001B）：每帧把源矩形换成"第 slot+5 条"48px 带。

        `(0x45AFC0(0x4AB5B0,0xC000)+5)*3*16` = `48*(slot+5)`，宽 0..0xEF、高 0x2F，
        dst 不动（ctor 写的 (0,0x1C0)）。
        """
        row = (self.keys.field(0xC000) + 5) * 3 * 16
        if e.disp:
            e.disp.rect[:] = [0, row, 0xEF, row + 0x2F]

    def _psel_blink(self, e: UiEntity) -> None:
        """0x426BA0（0x5F00001C）：16 帧一相的显隐门。

        `cnt=[+0x20]++; if ((cnt&0x10)==0 && [+0x1C]==slot) 隐藏; else slot==3 ? 隐藏 : 显示`
        """
        cur = self.keys.field(0xC000)
        cnt = e.aux
        e.aux = (cnt + 1) & 0xFFFFFFFF
        if (cnt & 0x10) != 0:
            vis = (cur != 3)
        else:
            vis = (e.a3 != cur) and (cur != 3)
        if e.disp:
            e.disp.active = vis

    def _psel_hint(self, e: UiEntity) -> None:
        """0x430520（0x5F00001D / 0x61000006）：`[+0x1C]--`，减到 0 则死。

        页13 的 ctor 写 `[+0x1C] = -1` ⇒ 永远不为 0 ⇒ 只是**静态贴图**。
        """
        if e.t == 0:
            e.t = -1
            e.alive = False
        else:
            e.t -= 1

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

    # ---- 0x61 族其余型（页4 开场/关末；0x427690/0x427510/0x4272B1/0x427332/0x427710）----
    def _bgmvol(self, e: UiEntity) -> None:
        """0x427690（0x61000007 BGM 主音量渐变）：

        ```
        0x427693 ecx=[e+0x28]+1；al=cl；[e+0x28]=ecx
        0x42769c test al,7 → 非 0 本帧结束
        0x4276a4 cur=[e+0x1C]+step；[e+0x1C]=cur
        0x4276b1 step<0 → cur<target 则钳到 target；step>0 → cur>target 则钳到 target
        0x4276c8 0x44F950(0x4AB514, cur&0xFF)（GM SysEx 主音量）
        0x4276de 返回 cur != target（setne）
        ```"""
        e.t += 1
        if e.t & 7:
            return
        step = e.a4
        cur = e.aux + step
        if step < 0:
            if cur < e.a3:
                cur = e.a3
        elif cur > e.a3:
            cur = e.a3
        e.aux = cur
        if self.audio is not None:
            self.audio.bgm_volume(cur & 0xFF)
        if cur == e.a3:
            e.alive = False

    def _seq_gate(self, e: UiEntity) -> None:
        """0x427510（0x61000002）：`0x430860(0x4AD49C)+0x430860(0x4AD43C)`（两队列存活计数）
        为 0 且 `0x45AFC0(0x56CCB8,0x8000)==0` → `0x45AF60(0x56CC84,2)`（sysf|=2）并死；
        否则继续活着。"""
        n49 = sum(1 for q in (getattr(self, "p4_ui49c", []), getattr(self, "ui49c", []))
                  for x in q if getattr(x, "alive", True))
        n43 = sum(1 for x in getattr(self, "p4_q43c", []) if getattr(x, "alive", True))
        if n49 + n43 == 0 and not self.sysb8.test(0x8000):
            self.sysf.bits &= ~2                   # 0x42753F..0x42754B 0x45AF60(0x56CC84,2) 解冻
            e.alive = False                        # 0x42754B xor al,al（行为返回 0 = 摘链）

    def _crowd_spawn(self, e: UiEntity) -> None:
        """0x427450（0x61000001 群生门）：`counter(+0x1C)++`；`(counter & rec0)==0` 时
        0x430400(0x298, rand%0x168+0x3C, rec3, 0) 入 0x4AD43C；生成 rec1 个后
        `0x45AF60(0x56CCB8,0x8000)`（bit15 清）并死（0x4274BF..0x4274D4）。"""
        counter = (e.aux + 1) & 0xFFFFFFFF
        e.aux = counter
        if (counter & e.a3) == 0 and e.a4 > 0:
            y = (self.p4_rand_mod(0x168)[1] + 0x3C)   # 0x427468 rand%0x168+0x3C（余数）
            self._p4_ent43c(int(e.p.get("spawn_type", 0)) & 0xFFFFFFFF,
                            0x298, y, 0, 0)
            e.a4 = (e.a4 - 1) & 0xFFFFFFFF
            if e.a4 == 0:
                self.sysb8.bits = (self.sysb8.bits & ~0x8000) & 0xFFFFFFFF
                self.p4_stat[0x56CCB8] = self.sysb8.bits   # 0x4274BF bit15 清
                e.alive = False                            # 0x4274CE 死

    def _stat_bits(self, e: UiEntity) -> None:
        """0x4272B1（0x61000003）：一次性 `0x45B0A0(0x56CCB8, rec3, rec0!=0)`；行为 0x430520 首帧死。
        0x56CCB8 在复刻里双存（sysb8 位测 + p4_stat 镜像），两处都写。"""
        mask = e.a3 & 0xFFFFFFFF
        new = ((self.sysb8.bits & ~mask & 0xFFFFFFFF) | (mask if e.aux else 0)) & 0xFFFFFFFF
        self.sysb8.bits = new
        self.p4_stat[0x56CCB8] = new
        e.alive = False

    def _check_1000(self, e: UiEntity) -> None:
        """0x427332（0x61000006）：`0x45AF30(0x56CCB8,0x1000)` → `byte[0x56CCB3]=1`；首帧死。"""
        if self.sysb8.test(0x1000):
            self.p4_stat[0x56CCB3] = 1
        e.alive = False

    def _recdrv(self, e: UiEntity) -> None:
        """0x427710 的 mode 0 路径（0x61000008）：每 4 帧 0x459AE0(0x56B95C)——输入录像 tick，
        复刻侧 run.py 已每帧记录 ⇒ 空操作；`[e+0x1C]--` 减到 0 死。"""
        e.aux -= 1
        if e.aux == 0:
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
        """0x4255D0 全状态机。

        入口公共段（0x4255D3..0x4255F8）：
            ebp = ([ent+0x20] & 4) + (**sar** [0x4AB5A0],7)      ← 选中项候选（Y 的 128px 带 + 列位）
            esi = [ent+0x1C]（状态），>4 → 0x4256A6
        跳表 0x42583C = {0x4255FF, 0x4256C0, 0x4256CE, 0x4256C0, 0x4257AE}
        公共尾声 0x4256A6 / 0x425828：状态变了 → [0x20]=ebp、[0x24]=0；没变 → [0x24]++。
        """
        sel = (e.a4 & 4) + (int(self.inp.rec.y) >> 7)     # sar eax,7（有符号）
        st0 = e.a3
        if st0 > 4:
            st0 = 0
        if st0 == 0:
            # 0x4255FF → 0x449E10(ent, 0, 10)：
            #   ① 0x45C740 取"当前场景"描述 → ② 0x45FE10 应用（卸层/装层/色带/4CC 背景节点）
            #   ③ 0x44C640(13,10) + 0x44CE60(13,0) 最后才装层13
            # ① 0x425601..0x425656：先循环 8 次生成 0x5F000006 入 0x4AD4FC（行号在 desc[0]）
            for i in range(8):
                m = self.spawn(self.ui4fc, 0x5F000006, a3=i)
                m.p["root"] = e
            # ② 0x425658：desc = {-255, 0, 0x61000005, 8} → 入 0x4AD52C（淡入）
            f = self.spawn(self.ui52c, 0x61000005)
            f.beh = "flash"; f.aux = -255; f.a3 = 0; f.a4 = 8
            # ③ 0x42568F..0x42569C：0x449E10(ent, 0, 10) —— 场景应用 + 层13←bm_mn（**在行/淡入之后**）
            sc = self.data.get("scene0")
            if sc:
                self.apply_scene(sc)
            else:
                self.ui46c.clear()
                self.log("page3 state0：scene0 数据缺失（§16.34 待解），仅装层13")
            self.layers.bind(13, 10)
            self.layers.color_key(13, 0)
            # ④ 0x425697：状态 +1
            e.a3 = 1
            self.log("page3 state0：8×0x5F000006 + 0x61000005(-255→0,+8)")
        elif st0 == 1 or st0 == 3:
            # 0x4256C0：等 [ent+0x24] >= 0x20（32 帧）再进下一状态
            if e.aux >= 0x20:
                e.a3 = st0 + 1
        elif st0 == 2:
            # 0x4256CE：交互
            if self.inp.rec.e0:                           # [0x4AB596] = 攻击键按下沿
                if sel != 0:
                    # 0x42572B：确认 → 状态3、[0x24]=0、[0x28]=ebp、0x449DA0 淡出、0x450440 停音
                    e.a3 = 3
                    e.aux = 0
                    e.p["sel"] = sel
                    self._menu_fade_out()
                    self.melody_step()                    # 0x425743 push 0 → 0x450440(0)
                else:
                    # 0x4256DB..0x425729：候选为 0（「遊戲開始」）时按下确认 **不是确定**，
                    # 而是切到左列（rows 4..7）并把指针挪到对应带：
                    #   base = keys.test(1) ? 4 : 6        （0x45AFF0(0x4AB5B0,1) = 攻击按住）
                    #   base += keys.test(2) ? 1 : 0       （0x45AFF0(0x4AB5B0,2) = 锁定按住）
                    #   sel = base；0x44E620(inp, 0, sel*128 - 0x1C0)
                    # 于是 sar(y,7)=0..3，配上 a4 的 bit2 → sel 稳定落在 4..7。
                    k1 = self.keys.test(1)
                    k2 = self.keys.test(2)
                    # 0x4256DB..0x425729：base = 4 + (bit0(鍛錬)?2:0) ⇒ 鍛錬=1 → 6/7 行、
                    # 鍛錬=0 → 4/5 行（state4 回写 (s>>1)&1=鍛錬、s&1=操作器，恰好自洽）
                    sel = (6 if k1 else 4) + (1 if k2 else 0)
                    self.inp.set_pos(0, sel * 128 - 0x1C0)
                    self.log(f"page3 state2：確認於「遊戲開始」→ 切左列 sel={sel} y={sel*128-0x1C0}")
            else:
                if self.inp.rec.e1 and sel >= 4:          # 0x425751：锁定键按下且列为 1 → 归 0
                    sel = 0
                    self.inp.set_pos(0, 0)
                if e.aux > 0x258:                         # 0x42576F：600 帧无变化 → 自动退出
                    e.a3 = 3
                    e.p["sel"] = 0
                    self._menu_fade_out()
            # 0x42578D：选中项变化 → 0x450440(0) 播一个旋律音 + 计数清零
            if e.a4 != sel:
                self.melody_step()                        # 0x425796 push 0 → 0x450440(0)
                e.aux = 0
        elif st0 == 4:
            # 0x4257AE：退出。列位（bit2）命中时把选中项的低 2 位写回键位 1/2，
            # 然后 flags = 表[ [ent+0x28] ]（0x4257D8 的 8 项表），行为返回 0（实体自尽）
            s = int(e.p.get("sel", 0))
            if s & 4:
                self.keys.write(1, (s >> 1) & 1)
                self.keys.write(2, s & 1)
            val = MENU_EXIT_FLAGS[s & 7]
            self.flags.bits = val                        # 0x45AF10：直接赋值（不是 OR）
            e.alive = False
            if e.disp:
                e.disp.active = False
            self.log(f"page3 state4：选中 {s} → flags 0x{val:X}")
            return
        # 公共尾声
        if st0 != e.a3:
            e.a4 = sel
            e.aux = 0
        else:
            e.a4 = sel
            e.aux += 1

    # 0x4258F0（0x5F000006 的行为）：只改节点可见位 [node+0x1C]
    def _stage_title12(self, e: UiEntity) -> None:
        """0x5F000014 → 行为 0x426340：**鍛錬选关机九态机**（2026-11-16 按 0x424D47/0x426340 复核）。

        入口公共段（0x42634B）：`[0x24]--`，新值作为 ecx 传给状态体（所以
        「置 [+0x24]=N、态=X」都是在 **N 帧后**才动作）。跳表 0x4267B0：
        ```
        0=0x426367  生成 0x5F000015/16/17 入 0x4AD4FC + 0x61000005(-255,-255,0) 压暗；
                    [+0x24]=2、态=8
        8=0x426463  ecx==0 才动作：0x449E10(stage,0xB5)（=应用关卡场景 + 层13←bm_tr）
                    + 0x61000005(-255→0,+16) 淡入；[+0x24]=0x10、态=1；
                    按 stage<7 / ==7 / >7 写主实体矩形（0,0x40/0x80/0xC0,0xBF,…）
        1/3/5=0x426556  ecx==0 → 0x44E470(320,240) 指针归中 → 态+1
        2=0x426585  输入（见下）；横移 → 态=7；纵移不换态
        4=0x42678E  0x45AF30(0x4AB5C0, 0x10000) —— 选定，页12 收尾去页4/页15
        6=0x426795  0x45AF30(0x4AB5C0, 0x200) —— 取消，回页3
        7=0x42640C  0x61000005(-255,-255,0) 压暗；[+0x24]=2、态=8
        >8=0x4267A4  空转（返回 1）
        ```
        态 2 输入（0x426585，用 `[0x4AB59C]/[0x4AB5A0]` 虚拟指针）：
        `|x-320|>0x50` → 关卡 ±(x≥320?1:-1)，界 = (0x70000 字段!=0)+0xF00000 字段，
        <0→界-1、≥界→0；新关==8 时清周目 word；
        `|y-240|>0x50` → 周目 ±(y≥0xA0?1:-1)，界 = 关<8 ? 4+bit31 : min(0x70000,4)；
        居中：btn0 沿 → 态=3、btn1 沿 → 态=5（两者都生成 0x61000005(-255,0,-16)、
        [+0x24]=0x10）——注意 rec3 是 **-16**，压栈序见 0x4266F8。
        """
        # 0x42634B..0x426360：公共计时器先自减，再按状态派发
        e.a4 -= 1
        ecx = e.a4
        st = e.a3
        if st > 8:
            return True                                   # 0x4267A4 尾部
        if st == 0:                                       # 0x426367
            self.spawn(self.ui4fc, 0x5F000015)            # 0x42637A 关卡预览块
            self.spawn(self.ui4fc, 0x5F000016)            # 0x4263B1 选择器历史条
            self.spawn(self.ui4fc, 0x5F000017)            # 0x4263E8 周目/关卡文字条
            self.spawn_flash(-255, -255, 0)               # 0x426425 0x61000005(-255,-255,0)
            e.a4 = 2                                      # 0x42644A [+0x24]=2
            e.a3 = 8                                      # 0x426451 态=8
            return True
        if st == 8:                                       # 0x426463
            if ecx != 0:
                return True                               # 0x426465..0x426469：计时未尽
            stage = self.theatre & 0xFFFF                 # 0x42646B movsx word[0x4AB5C8]
            # 0x426472..0x42647A：0x449E10(ent, stage, 0xB5)
            #   = 0x45C740(0x4AB5CC,stage) → 0x45FE10(项+0x4C, 0x4100000D) → 层13←资源0xB5
            #     (bmetc\bm_tr.ggd) + 色键0。
            #   复刻侧不持久化 0x4AB5CC 的附件表；默认附件 = 资源记录 #0x4E = scene0。
            self.apply_scene(self.data["scene0"])
            self.layers.bind(13, 0xB5)                    # 0x44C640(层13, 0xB5) = bm_tr
            self.layers.color_key(13, 0)                  # 0x44CE60(13, 0)
            self.spawn_flash(-255, 0, 0x10)               # 0x42647F..0x4264BA 淡入
            if stage < 7:                                 # 0x4264D3 cmp ax,7 / jge
                e.disp.rect = [0, 0x40, 0xBF, 0x7F]       # 0x4264D9 push 0x7F,0xBF,0x40,0
            elif stage == 7:                              # 0x4264EE jne
                e.disp.rect = [0, 0x80, 0xBF, 0xBF]       # 0x4264F0 push 0xBF,0xBF,0x80,0
            else:
                e.disp.rect = [0, 0xC0, 0xBF, 0xFF]       # 0x42653B push 0xFF,0xBF,0xC0,0
            e.a4 = 0x10                                   # 0x4264BF [+0x24]=0x10
            e.a3 = 1                                      # 0x4264C6 态=1
            return True
        if st in (1, 3, 5):                               # 0x426556
            if ecx != 0:
                return True                               # 0x426558 jne 尾部
            self.inp.set_pos(0x140, 0xF0)                 # 0x426563 0x4013DE(0x4AB454,320,240)
            e.a3 = st + 1                                 # 0x426578 inc
            return True
        if st == 2:                                       # 0x426585
            px, py = int(self.inp.x), int(self.inp.y)
            if abs(px - 0x140) > 0x50:                    # 0x42658B..0x426596 横向
                f7 = self.keys.field(0x70000)             # 0x42659F..0x4265AE
                fF = self.keys.field(0xF00000)            # 0x4265B0..0x4265BE
                limit = (1 if f7 else 0) + fF             # 0x4265CB esi
                stage = self.theatre & 0xFFFF             # 0x4265D5 word[0x4AB5C8]
                stage += 1 if px >= 0x140 else -1         # 0x4265DB..0x4265E2
                if stage < 0:
                    stage = limit - 1                     # 0x4265E9 lea eax,[esi-1]
                elif stage >= limit:                      # 0x4265EC cmp ax,si / jl
                    stage = 0                             # 0x4265F1 xor eax,eax
                if stage == 8:                            # 0x42660C cmp ax,8 / jne
                    self.theatre &= 0xFFFF0000            # 0x426612 word[0x4AB5CA]=0
                self.theatre = (self.theatre & 0xFFFF0000) | (stage & 0xFFFF)
                self.p4_stat[0x4AB5C8] = self.theatre     # 0x4265F4/0x42661B word 写回
                e.a3 = 7                                  # 0x4265FA/0x426622
                return True
            if abs(py - 0xF0) > 0x50:                     # 0x426634..0x426646 纵向
                if (self.theatre & 0xFFFF) < 8:           # 0x42664C cmp word[0x4AB5C8],8
                    bit31 = self.keys.test(0x80000000)    # 0x426656..0x426666
                    lim = 4 + (1 if bit31 else 0)         # 0x42666B add eax,4
                else:                                     # 0x426670..0x426695
                    lim = min(self.keys.field(0x70000), 4)  # 0x42667F cmp eax,4 / jae
                lp = (self.theatre >> 16) & 0xFFFF        # 0x4266B0 word[0x4AB5CA]
                lp += 1 if py >= 0xA0 else -1             # 0x4266A2 cmp esi,0xA0 / setge
                if lp < 0:
                    lp = lim - 1                          # 0x4266BC lea ecx,[eax-1]
                elif lp >= lim:                           # 0x4266C2 cmp edx,eax / jl
                    lp = 0                                # 0x4266C6 xor ecx,ecx
                self.theatre = (self.theatre & 0xFFFF) | ((lp & 0xFFFF) << 16)
                self.p4_stat[0x4AB5C8] = self.theatre     # 0x4266C8 word[0x4AB5CA] 写回
                self.inp.set_pos(0x140, 0xF0)             # 0x4266CF 0x44E470 指针归中
                return True                               # 0x4266E5 mov al,1
            if self.inp.rec.e0:                           # 0x4266EF byte[0x4AB596]
                e.a3 = 3                                  # 0x42670E
                self.spawn_flash(-255, 0, -0x10)          # 0x4266F8 desc{-255,0,-16}
                e.a4 = 0x10                               # 0x42673A [+0x24]=0x10
                return True
            if self.inp.rec.e1:                           # 0x42674C byte[0x4AB597]
                e.a3 = 5                                  # 0x42676B
                self.spawn_flash(-255, 0, -0x10)          # 0x426755 同 btn0
                e.a4 = 0x10
                return True
            return True                                   # 0x4267A4 尾部
        if st == 4:                                       # 0x42678E
            self.flags.set(0x10000)
            return True
        if st == 6:                                       # 0x426795
            self.flags.set(0x200)
            return True
        if st == 7:                                       # 0x42640C
            self.spawn_flash(-255, -255, 0)               # 0x426425
            e.a4 = 2                                      # 0x42644A
            e.a3 = 8                                      # 0x426451
            return True
        return True

    # ---- 页12 三个副实体 ----------------------------------------------------
    def _stage_week(self) -> int:
        """`movsx word[0x4AB5CA]`：周目计数（有符号 16 位）。"""
        w = (int(self.theatre) >> 16) & 0xFFFF
        return w - 0x10000 if w & 0x8000 else w

    def _stage_preview12(self, e: UiEntity) -> None:
        """0x426910（0x5F000015）：关卡预览块。

        `[0x1C] < 7` 才显示；源块 = (`[0x20]<<6`, 0, +0x3F, 0x3F)（bm_tr 的 64×64 关卡列）。
        随后历史移位 `[0x1C]←[0x20]←[0x24]←word[0x4AB5C8]`。
        """
        d = e.disp
        if e.a3 < 7:                                      # 0x426916 cmp [esi+0x1C],7 / jge
            idx = int(e.a4)                               # 0x42691C [esi+0x20]
            if d is not None:
                d.rect = [idx * 0x40, 0, idx * 0x40 + 0x3F, 0x3F]   # 0x426924..0x426932
                d.active = True                           # 0x42695D byte[node+0x1C]=1
        else:
            if d is not None:
                d.active = False                          # 0x426966 byte[node+0x1C]=0
        e.a3 = e.a4                                       # 0x42696A..0x426976
        e.a4 = e.aux
        e.aux = self.theatre & 0xFFFF

    def _stage_hist12(self, e: UiEntity) -> None:
        """0x4269B0（0x5F000016）：选择器历史条（固定矩形 0,0x100,0x8F,0x12F）。

        可见 = `[0x1C] < 8`；随后与预览块相同的三元组移位更新。
        """
        if e.disp is not None:
            e.disp.active = e.a3 < 8                      # 0x4269B6 cmp/setl
        e.a3 = e.a4                                       # 0x4269BF..0x4269C5
        e.a4 = e.aux
        e.aux = self.theatre & 0xFFFF                     # 0x4269CB..0x4269D2

    def _stage_text12(self, e: UiEntity) -> None:
        """0x4269F0（0x5F000017）：难度/附加关模式带（bm_tr 的 48px 横带）。

        `target = word[0x4AB5CA] * 0x180`（周目×0x180，滚动量 = 周目×48px）；
        `[0x28]` 每帧向 target 逼近 `(|Δ|+7)>>3`；`[0x20]>=8 且 [0x1C]<8` ⇒ 归零。
        v = `[0x28] >> 3`；源带 = (`0xC0`, `0x40+v`, `0x11F`, `0x6F+v`)（初級/中級/上級/特級/悪夢），
        dst.x = 0xC0。`[0x1C]>=8`（附加关）时 dst.x=0x18，且 `0x45A790` 把源带加
        (0x60,0,0x90,0) ⇒ (`0x120`, `0x40+v`, `0x1AF`, `0x6F+v`)（一騎討/辛口/元祖/元祖改）。
        尾段同样是三元组移位。
        """
        target = self._stage_week() * 0x180               # 0x4269F0..0x426A00
        cur = int(e.p.get("v28", 0))
        if cur < target:                                  # 0x426A06 cmp / jge
            cur += (target - cur + 7) >> 3                # 0x426A0A..0x426A14
        elif cur > target:                                # 0x426A19 jle
            cur -= (cur - target + 7) >> 3                # 0x426A1B..0x426A27
        if e.a4 >= 8 and e.a3 < 8:                        # 0x426A2A..0x426A36
            cur = 0
        e.p["v28"] = cur
        v = cur >> 3                                      # 0x426A3D sar eax,3
        d = e.disp
        if e.a3 >= 8:                                     # 0x426A83..0x426AB3
            if d is not None:
                d.dst[0] = 0x18                           # 0x426A99 [node+0x14]=0x18
                # 0x426A90: 0x45A790(grow) 0,0x90,0,0x60 叠加在 (0xC0,t,0x11F,b) 上
                # ⇒ (0x120, t, 0x1AF, b)：附加关用右侧「一騎討/辛口/元祖/元祖改」列
                d.rect = [0x120, 0x40 + v, 0x1AF, 0x6F + v]
        else:
            if d is not None:
                d.dst[0] = 0xC0                           # 0x426AB6 [node+0x14]=0xC0
                # 0x426A49..0x426A5C 压栈序 (r,b,l,0xC0) ⇒ rect
                # = (0xC0, 0x40+v, 0x11F, 0x6F+v)＝难度带（初級/中級/上級/特級/悪夢）
                d.rect = [0xC0, 0x40 + v, 0x11F, 0x6F + v]
        e.a3 = e.a4                                       # 0x426ABD..0x426AC9
        e.a4 = e.aux
        e.aux = self.theatre & 0xFFFF

    def _menu_row(self, e: UiEntity) -> None:
        """0x4258F0：可见 = 列位相同 且 (行 != 选中 或 选中项闪烁)。

        `test dl,4`（dl = row ^ sel）⇒ 列位不同一律隐藏；
        `cmp esi,eax / jne 0x42590E` ⇒ 行 != 选中 → 可见；
        行 == 选中 → `test byte [ent+0x24],0x20`（32 帧亮 / 32 帧灭）。
        """
        row = int(e.p.get("row", 0))
        root = e.p.get("root")
        sel = int(root.a4) if root is not None else 0
        d = e.disp
        if d is not None:
            if ((row ^ sel) & 4) != 0:
                d.active = False
            elif row != sel:
                d.active = True
            else:
                d.active = (e.aux & 0x20) != 0
        e.aux += 1

    # 0x430520（类型 0x4100000D 场景背景实体的行为）：计数器自减，到 0 自尽
    def _scene_bg(self, e: UiEntity) -> None:
        """0x430520：`[ent+0x1C]-- ; ==0 → 返回 0(自尽)`。

        构造时 `[ent+0x1C] = -1`（0x4293FF），所以永不归零 ⇒ **静态背景节点**。
        """
        v = int(e.a3) - 1
        e.a3 = v
        if v == 0:
            e.alive = False
            if e.disp:
                e.disp.active = False

    # 0x45FE10（= 0x402072）：把"当前场景"重新应用一遍
    def apply_scene(self, sc: dict) -> None:
        """0x45FE10 逐条（§16.43：数据 = resource.rom 记录 #0x4E）。

        记录布局：+0 长度 / +4 层数 N / +8 色带数 M / +0xC 实体数 K / +0x10,+0x14 两参数 /
        +0x18 层ID[N] / 色带[M] / 实体[K]（每项 0x20 字节）。
        """
        # 0x45FE56：先把 14 个层全部销毁（arg2 != 0x41000012 时）
        self.layers.free_all()
        # 0x45FE5D：层号 = 下标，从层0 起连续装载，并设色键0（id==0 跳过装载）
        for i, rid in enumerate(sc.get("layers", [])):
            rid = int(rid)
            if rid:
                self.layers.load(i, rid)                  # 0x44C640(层i, id)
                self.layers.color_key(i, 0)               # 0x44CE60(层i, 0)
        # 0x45FE84..0x45FE95：0x4561D0(0x4CD484, 表, 项数, +0x10, +0x14)
        bt = [[int(c) & 0xFF, int(h)] for c, h in (sc.get("bands") or [])]
        start_idx, scroll = (int(v) for v in sc.get("band_args", [0, 0]))
        if bt:
            self.band_push(bt, len(bt), start_idx, scroll)
        # 0x45FEAC：实体记录 {+0 层, +4 源矩形(4), +0x14 目标点(2), +0x1C 启用字节}
        self.ui46c.clear()
        for r in sc.get("ents", []):
            lay, l, t, rr, bb, x, y, on = (int(v) for v in r)
            if not (on & 0xFF):                            # 0x45FEAC al=[rec+0x1C]
                continue
            if lay == 0x0D:                                # 0x45FEB6：层13 跳过
                continue
            e = UiEntity(type_word=0x4100000D)
            e.beh = "scene_bg"
            e.a3 = -1                                      # 0x4293FF
            e.disp = DisplayNode(lay, [l, t, rr, bb], [x, y])   # 0x42941D / 0x42943A
            self.ui46c.append(e)
        self.scene_tiles(sc.get("tiles"))
        self.log(f"scene 应用：层 {len(sc.get('layers', []))} / 色带 {len(bt)} / 背景节点 {len(self.ui46c)}")

    def scene_tiles(self, tiles) -> None:
        """0x41000004 的语义（§16.40）：从层1 取 32×32 瓦片，按 (x*4, y*4) 贴到屏上。

        类目来自舞台的瓦片坐标表；页面侧只负责按 4px 网格落位。
        tiles 条目：{"layer":1, "src":[l,t,r,b], "x":, "y":}
        """
        for t in tiles or []:
            e = UiEntity(type_word=0x41000004)
            e.beh = "scene_bg"
            e.a3 = -1                                  # 0x4293FF 计数器
            e.disp = DisplayNode(int(t.get("layer", 1)),
                                 [int(v) for v in t["src"]],
                                 [int(t["x"]) * 4, int(t["y"]) * 4])   # 0x428D8F/0x428DA5
            self.ui46c.append(e)
        if tiles:
            self.log(f"scene 瓦片：{len(tiles)} 格（层1 32×32 @4px 网格）")

    # 0x449DA0：生成 0x61000005(0 → -255, 步进 -8) = 32 帧淡出
    def _menu_fade_out(self) -> None:
        f = self.spawn(self.ui52c, 0x61000005)
        f.beh = "flash"; f.aux = 0; f.a3 = -255; f.a4 = -8

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
    # ------------------------------------------------------------ 页2 字形条/面板
    def _p2_glyph(self, a: int, b: int, attr: int, layer: int) -> None:
        """0x43F230(ent, a, b, attr, layer)：层4（16×16 图集）的 8×8 单元 → 层 layer 的 (a*8,b*8)。

        0x43F233 `0x45B030(0x4AB5B0,0x400)`：flag 未置位时 attr 强制 0xB4（隐藏文字）；
        0x43F24B..0x43F282：单元 = {(attr&0x0F)<<4, attr&0xF0, +8, +8}；
        0x43F286 / 0x43F29D：`a&1` 源单元右移一格、`b&1` 下移一格；最后 0x44D060(mgr,layer,&pos,4,&cell)。
        """
        if not self.p2_text_on:
            attr = 0xB4
        l = (attr & 0x0F) << 4
        tp = attr & 0xF0
        cell = [l, tp, l + 8, tp + 8]
        if a & 1:
            cell[0] += 8; cell[2] += 8
        if b & 1:
            cell[1] += 8; cell[3] += 8
        self.layers.copy_key(4, layer, cell, (a * 8, b * 8), key=0)

    def _p2_glyph_strips(self, t: int) -> None:
        """⑩⑪ 六个段（§16.93.4 / §16.93.8）。

        资源 80/81/82 是"列式列表"：步长 = 每列字节数（0x7C/0x7C/0x50），循环变量 x 是资源内
        字节偏移而不是像素坐标。
        """
        g = self.p2_glyph
        if not g:
            return
        # ⑩a 0x440679：t∈[0x35C,0x3AC) 偶数帧；A=t-0x35C；60 列、基点 0x29、层5
        if 0x35C <= t < 0x3AC and not (t & 1):
            A = t - 0x35C
            for k in range(60):                     # 0x1D10 / 0x7C = 60 列
                self._p2_glyph(A, k, g[80][0x29 + A + 0x7C * k], 5)
        # ⑩b 0x4406E0：t∈[0x560,0x600) 偶数帧；A=(t-0x560)//2；基点 0xF7E、层6
        if 0x560 <= t < 0x600 and not (t & 1):
            A = (t - 0x560) // 2
            for k in range(60):
                self._p2_glyph(A, k, g[81][0xF7E + A + 0x7C * k], 6)
        # ⑩c 0x440750：t∈[0x60C,0x6AC) 偶数帧；A=(t-0x60C)//2；x: 0xA0→0x1360 步 0x50、层5
        if 0x60C <= t < 0x6AC and not (t & 1):
            A = (t - 0x60C) // 2
            x = 0xA0
            while x < 0x1360:
                self._p2_glyph(A, x // 0x50, g[82][A + x], 5)
                x += 0x50
        # ⑪a 0x4407C4：t∈[0x560,0x60C)、(t-0x560)%4==0；窗口每 4 帧左移 1 列
        if 0x560 <= t < 0x60C and (t - 0x560) % 4 == 0:
            k = (t - 0x560) // 4
            X2 = 0x52 - k
            off = (0x50 - k) - 0x27
            for i in range(60):                     # edi = 0x3C（0x43FF97 的残留值）
                self._p2_glyph(i, X2, g[80][off], 5)
                off += 0x7C
        # ⑪b 0x44086E：t∈[0x60C,0x6B8) 且 (t-4)%8==0；k=(t-0x60C)//11、limit=0x3E-2k
        if 0x60C <= t < 0x6B8 and (t - 4) % 8 == 0:
            d = t - 0x60C
            k = d // 11                             # 0x2E8BA2E9 魔数 = 除以 11
            P = (d >> 2) & ~1                       # 0x4408A7
            limit = 0x3E - 2 * k
            off = 0
            for i in range(max(0, limit)):
                self._p2_glyph(P, i, g[81][0xED8 + off + P], 6)
                off += 0x7C
        # ⑪c 0x440A95：t∈[0x6B8,0x764) 且 (t-0x6B8)%11==0；两行、每行 0x50 字
        if 0x6B8 <= t < 0x764 and (t - 0x6B8) % 11 == 0:
            row = ((t - 0x6B8) // 11) * 2
            band = row * 80 + 0x12C0               # 0x440AE0: (row*5+0x12C)*16
            for _ in range(2):
                for i in range(0x50):
                    idx = band + i + (row + 2)      # 0x440B02: [base + i + [esp0+0x24]]
                    if 0 <= idx < len(g[82]):
                        self._p2_glyph(row, i, g[82][idx], 5)
                row += 1
                band += 0x50

    def _p2_panel_node(self, c: int) -> DisplayNode:
        """0x436E6C：层 = (c&0x10) ? (c&3)+7 : (c&1)+5；源矩形 0xF0×0xF0 或 0x290×0x1F0。"""
        if c & 0x10:
            return DisplayNode((c & 3) + 7, [0, 0, 0xF0, 0xF0], [0, 0])
        return DisplayNode((c & 1) + 5, [0, 0, 0x290, 0x1F0], [0, 0])

    def _p2_panel(self, e: UiEntity) -> None:
        """0x439D30（0x4F00000A 行为）：1/4 像素定点、按 c&3 定初速、小图先减速后反向、寿命 0xAC。"""
        c = e.aux
        p = e.p
        if not p.get("init"):
            p["init"] = True
            vx, vy = {0: (-268, 0), 1: (268, -201), 2: (0, 201)}.get(c & 3, (0, 0))
            if not (c & 0x10):                      # 大图（656×496）慢速
                if vx:
                    vx = 8 if vx > 0 else -8
                if vy:
                    vy = 6 if vy > 0 else -6
            p["vx"], p["vy"] = vx, vy
        vx, vy = p["vx"], p["vy"]
        pos = p["pos"]
        pos[0] += vx
        pos[1] += vy
        if c & 0x10:                                # 只对 240×240 小图做变速
            if e.t <= 0x15:                         # 0x439DD0..0x439DF9：向零减速
                vx += -0xC if vx >= 0 else 0xC
                vy += -9 if vy >= 0 else 9
            elif e.t >= 0x96:                       # 0x439E03..0x439E2D：远离零加速
                vx += 0xC if vx >= 0 else -0xC
                vy += 0xC if vy >= 0 else -0xC
            p["vx"], p["vy"] = vx, vy
        d = e.disp
        if d is not None:
            d.dst = [pos[0] >> 2, pos[1] >> 2]      # 0x439E36/0x439E39 sar 2
        e.t += 1
        if e.t >= 0xAC:                             # 0x439E5A
            e.alive = False
            if d is not None:
                d.active = False

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
                # `a=+255` 的条目（t=170/202/234 的 (255→0,-16) 与 t=256 的 (255→-255,-4)）：
                # 字面照抄会把整屏"洗白"一屏再衰减，实测原版没有这种洗白（玩家反馈：
                # 渐入前出现"很亮很完整的一屏"然后变黑）。这类条目改为**从当前亮度起步**，
                # 其余条目仍严格按原码 [0x1C]=a 跳变。
                if va == 255:
                    va = int(self.fade_a)
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

        # 记录流窗口（0x43FA2D）：**只在 [start, end) 内**才 0x459D60 取一帧并贴屏；
        # 原实现只判了 end（`end >= t`），导致 t<-350 就开始播 ⇒ 页2 开头闪出记录里的一小块
        # 红色「撃」（玩家实测：图3 之前有一闪而过的小红字）。
        # 窗口判定（0x43FA35 `jl`：`end < t` 才跳过；0x43FA5D `jle`：`next.start <= t` 才继续走）
        # ⇒ 活跃窗口 = **闭区间 [start, end]**。全 5 段长度合计 = 3+171+515+429+945 = 2063+5 = 2068，
        # 正好等于资源 77 的记录帧数（之前写成左闭右开，每段少 1 帧 ⇒ 最后 5 条永远播不到，
        # 流播完的 flags |= 1 也就永不触发，页2 到不了页3）。
        if self.p2_stream is not None:
            for (s0, s1) in p2.get("windows", []):
                if int(s0) <= t <= int(s1):
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
            # 0x459D60 播完后返回 0 ⇒ 0x43FA47 `flags |= 1`。窗口表 5 段闭区间合计正好 2068
            # （= 资源77 帧数），所以"发现播完"的那一次调用必落在最后一个窗口之后
            # （t > 4299）；不补这一步，页2 就永远等不到收尾旗标。
            if t > int(p2["windows"][-1][1]) and self.p2_stream.pos >= self.p2_stream.size:
                # 原码 0x43FA47 `flags |= 1` → 0x452FE7 映射到页 0xFF；
                # 页 0xFF 的处理器 0x4595A8 会打印 "This program will be closed."(0x4A4A64)
                # 并把页号清 0，随后 0x4595CD 调 PostQuitMessage ⇒ **不点鼠标就自动关游戏**。
                self.flags.set(1)
                self.log(f"page2 t={t} 记录流已播完 → flags=0x{self.flags.bits:X}")

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
        # 0x4405EA 的循环：`movsx edx,word[ecx-4]`(记录时间) / `cmp edx,eax`(计时器) / `jl 0x440651`(跳过)
        #   ⇒ **`记录时间 >= 计时器` 时才贴**。记录时间 = -58 ⇒ 通知页从页2 一开始(t=-420)就显示，
        #   直到 t=-58 为止（共 362 帧 ≈ 6 秒），而不是等到 -58 才出现（那是把判断写反了）。
        # 0x4405EA 的循环（`t_start <= t <= t_end` 才贴；0x44D010 带色键 0x11）。
        # 贴屏本身发生在 52C 行为遍里，而 52C 遍在 4CC 渲染**之后**（§16.9 的帧序）⇒
        # 这里只记账，由 draw() 在 _render_queue(ui46c) 之后统一执行，避免面板盖住静态页。
        self.p2_blits = []
        for (t0, t1, lay, dx, dy, sl, st, sr, sb) in P2_PAGES:
            if t0 <= t <= t1:
                self.p2_blits.append((lay, (sl, st, sr, sb), (dx, dy)))


        # ⑨ 0x440663：t == -0x158 → 0x44F600(0x4AB514, 0xF, 0) 开始播 BGM
        if t == -0x158:
            self.midi_play(0xF)

        # ⑩⑪ 字形条（0x440679/0x4406E0/0x440750/0x4407C4/0x44086E/0x440A95）
        self._p2_glyph_strips(t)

        # ⑫ 4CC 精灵表（0x440B3A..0x440D3D）：命中即生成 0x4F00000A 入 4CC 队列
        for (tt, pa, pb, pc) in P2_PANELS:
            if t == tt:
                e2 = self.spawn(self.ui46c, 0x4F00000A, pa, pb)
                e2.beh = "p2_panel"
                e2.aux = pc
                e2.p = {"vx": 0, "vy": 0, "init": False, "pos": [pa * 4, pb * 4]}
                e2.disp = self._p2_panel_node(pc)
                self.log(f"page2 t={t} 4F 面板 a={pa} b={pb} c=0x{pc:02X} 层{e2.disp.layer}")

        # ⑬ 计时器校正表（0x440D3F..0x440E07）：t 落入窗口 ⇒ 把 [ent+0x1C] 拉到 t2
        for (t1, t2, ms) in P2_RESYNC:
            if t1 <= t <= t2:
                # 0x440DF2：`ms >= [0x4AB570+0x20]` 时写 t2-1（差 1 帧）；复刻版定时器不记该计数，
                # 取"帧门已跟上"分支 → t2，并在日志里注明分支。
                # 本行为在开头就 e.t += 1（等价于原作结尾的 [ent+0x1C]=t+1），
                # 所以这里要写 t2+1 才能让下一帧从 t2+1 继续（写 t2 会卡在窗口里死循环）。
                e.t = int(t2) + 1
                self.log(f"page2 t={t} 计时器校正 → {t2}（ms=0x{ms:X}）")
                break

        # ⑭ 0x440E09：t == 0 → 0x45A630(0x4AB570, 0) 帧门基准清零（复刻版定时器无该计数，只记日志）
        if t == 0:
            self.log(f"page2 t={t} 帧门基准清零（0x45A630(0x4AB570,0)）")

        # ⑮ 0x440E19：t == 0x10F7 → flags |= 0x10000（去页3；正常流程 t=4300 已被 ⑤ 抢先）
        if t == 0x10F7:
            self.flags.set(FLAG_CLICK)
            self.log(f"page2 t={t} flags=0x{self.flags.bits:X}（0x440E19）")


    def present(self) -> None:
        """0x44D740 的调色板部分：`frame=++[0xC90]`，仅偶数帧且 [0xC8C]!=0 时执行。

        bit0 → 0x44B790(&pal, [0xC94], [0xC98])（亮度/对比度）；
        执行后 [0xC8C]=0（一次性）。窗口模式下随后 Blt(primary ← screen)。
        """
        self.pal_frame = (self.pal_frame + 1) & 0xFFFFFFFF
        # 0x44D740：按 0x44B790 重算调色板后**清位**（位清零≠还原成原始色表，见勘误）。
        #
        # 0x44D759..0x44D76A：`edx = ++[0xC90]`；`test al,1`（**位0为 0 就跳走**）⇒ 调色板操作只在
        # 计数器为**奇数**的帧执行，即"隔帧生效"、有固定的一帧延迟。
        # 这一帧延迟是原行为（玩家实测"字很亮很完整 → 全黑 → 渐入"正是它），
        # 旧版为消除它去掉了奇偶门，属偏离，已按原码改回（勘误 A-47）。
        if self.pal_flags and (self.pal_frame & 1):
            if self.pal_flags & 1:
                self.pal_now = fade_palette(self.pal, self.fade_a, self.fade_b)
            self.pal_flags = 0
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
        # `0x44D200` 的整屏填充发生在**行为遍**（52C 的 0x445A30）里，即渲染遍之前；
        # 原来放在 draw() 末尾会把本帧刚画上的 0x44D330 文字整屏盖掉（页1 BIOS 文本消失）。
        if self.screen_fill >= 0:
            c.fill(self.screen_fill)
        # 页13 的真实次序（`0x4547B1`→`0x458E70` 行为遍 → `0x4547BA`→`0x458EF0` 渲染遍）：
        # 行为遍里 52C 的文字（`0x44D330`）先上屏；渲染遍再按
        # 55C(0x40195B) → **4CC 人像切片** → 43C → 49C → **40C 汉字** → **46C 特效** → 4FC
        # 的顺序画显示表（`0x402531`→`0x430840`→`0x45A170`→`0x44D010` flags 0x11 = 色键0）。
        # 所以文字在**人像之前**画，人像是色键0（黑透明）⇒ 文字从人像的暗部透出来。
        for e in self.ui52c:
            for tx in e.texts:
                self.text.draw(c, tx["str"], int(tx["x"]), int(tx["y"]),
                               int(tx["h"]), int(tx["fg"]), int(tx.get("bg", -1)) & 0xFF)
        if self.p13_portrait_arr is not None:
            arr = self.p13_portrait_arr
            c.buf[arr != 0] = arr[arr != 0]            # 0x44D010 flags 0x11：色键 0 = 透明
        # 0x4F000009（层 5 = 0x44C560(5,640,480) 整屏层）：把整屏缓冲按擦切位切片再贴回去
        # 0x439C31 a3!=0：源 rect (edi,0)-(0x27F,0x1DF)，dst (0,0)
        # 0x439C84 a3==0：源 rect (0,0)-(edi-1,0x1DF)，dst (0x27F-edi,0)
        if self.p13_portrait_arr is not None:
            for w in self.wipe4f:
                edi = int(w.get("pos", 0))
                if w["a3"]:
                    l, t, r, b = edi, 0, 0x27F, 0x1DF
                    dx, dy = 0, 0
                else:
                    l, t, r, b = 0, 0, edi - 1, 0x1DF
                    dx, dy = 0x27F - edi, 0
                ww, hh = r - l, b - t
                if ww > 0 and hh > 0:
                    src = self.p13_portrait_arr[t:t + hh, l:l + ww]
                    dst = c.buf[dy:dy + hh, dx:dx + ww]
                    dst[src != 0] = src[src != 0]      # 同样色键 0

        # 0x41000004（4CC 队列里的命中火花）：层1 源瓦片、dst 已由行为算好（不缩放）
        for sp in self.spark4cc:
            lt = self.layers.tab.get(1)
            if lt is not None:
                c.blit(lt.buf, sp["rect"], (sp["dx"], sp["dy"]), key=lt.ckey)
        import os as _os
        if _os.environ.get("P4_LAYERDUMP") and not getattr(self, "_ldonce", 0):
            self._ldonce = 1
            for _i in range(14):
                _l = self.layers.tab.get(_i)
                if _l is None:
                    print(f"[layer] {_i} <none>"); continue
                _b = _l.buf
                _h, _w = _b.shape[:2]
                _nz = int((_b[::4, ::4] != 0).sum())
                print(f"[layer] {_i} {_w}x{_h} nz/16={_nz} id={getattr(_l,'bind_id',None)}")
        if getattr(self, "p4_bg", None) and self.page == 4:
            # 0x458EF5 → 0x457CB0（12 槽，最先绘制）。⚠ 页4 专属：共享 draw() 原本
            # 无条件执行，ESC 页4→页3 / 页3→页4 时页4 的地面字块/HUD 会画进别的页
            # （2026-10-31 修，页1-3 金标时这些路径本就是空操作，加门不改哈希）。
            self.p4_bg_draw()
        # 0x458EF0 的六条队列顺序：ui4cc → ui43c → ui49c → 0x4AD40C → ui46c → ui4fc
        # ⚠ 页4 专属渲染遍（同 p4_bg_draw：加 page 门防跨页污染，2026-10-31）
        if self.page == 4:
            if getattr(self, "p4_q4cc", None) is None:
                self.p4_q4cc = self._p4_q("ui4cc")
            self._render_queue(c, self.p4_q4cc)         # 0x4AD4CC 页4 4CC 队列
            # 0x458EF0 无条件依次调用 6 条链表的渲染（空表也调），不能因列表为空而跳过
            self.p4_render_ents()                       # 0x4AD43C 页4 实体显示表
            self._render_queue(c, self._p4_q("ui49c"))  # 0x4AD49C
        if self.page != 4:
            self._render_queue(c, self.trailq)          # 0x430840(0x4AD4CC)（0x458F80 首遍）
        self._render_queue(c, self._p4_q("ui4fc"))      # 0x4AD4FC（与页1-3 的 ui4fc 同表）
        if DRAW_DISPLAY_NODES:
            self._render_queue(c, self.actorq)          # 0x4AD40C（层 0 汉字）
            self._render_queue(c, self.ui46c)           # 0x4AD46C（层 1 特效）
        # ⑧ 静态文字页（0x44D010）：0x445A30 的 52C 遍在 4CC 渲染之后 ⇒ 盖在面板之上
        for (lay, src, dst) in self.p2_blits:
            lt = self.layers.tab.get(int(lay))
            if lt is not None:
                c.blit(lt.buf, src, dst, key=lt.ckey)
        self.p2_blits = []
        if DRAW_DISPLAY_NODES:
            self._render_queue(c, self.ui4fc)
        # 0x458F3C if (arg) { 0x45EED0(0x4CD4A0); 0x460A90(0x4CD590) }：HUD 渲染（页4 专属）
        if getattr(self, "p4_bg", None) is not None and self.page == 4:
            self.p4_hud_draw()
        # 0x451316：页4 回放进度文字（`0x44D330`）画在 present 之前 ⇒ 叠在最上层。
        # 只在 `p4_debug_text()` 真的产出内容时才有值（门 `[0x56CCC9]`&`[0x56CCB5]`）。
        _dbg = getattr(self, "_p4_dbg_text", None)
        if _dbg is not None:
            self._p4_dbg_text = None
            _s, _x, _y, _h, _fg, _bg = _dbg
            self.text.draw(c, _s, _x, _y, _h, _fg, _bg)
        self.present()          # 0x458CB0 → 0x44D740（调色板操作 + Blt）

    def _render_queue(self, c: "Canvas", q) -> None:
        """0x430840(`add ecx,4; jmp 0x45A170`)：按队列遍历显示表并 BltFast。

        dst 按 **int32** 归一后再交给 blit：页4 的 0x42/0x46 实体节点会把负坐标
        以无符号 dword 形式存进 dst（如 陽=0x42000002 静止于 y=-98 → 0xFFFFFFBE），
        原样传给 pygame 会被当成超大正坐标裁掉（2026-10-31 修，陽 下沉入画）。
        对小正数这是无操作，页1-3 不受影响。"""
        for e in q:
            d = e.disp
            if d is None or not d.active:
                continue
            lay = self.layers.tab.get(int(d.layer))
            if lay is None:
                continue
            left, top, right, bottom = (int(v) for v in d.rect)
            if right > left and bottom > top:
                dx, dy = int(d.dst[0]), int(d.dst[1])
                if dx >= 0x80000000:
                    dx -= 0x100000000
                if dy >= 0x80000000:
                    dy -= 0x100000000
                c.blit(lay.buf, (left, top, right, bottom), (dx, dy), key=lay.ckey)

