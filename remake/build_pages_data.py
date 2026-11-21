#!/usr/bin/env python3
"""从 geki106.exe 提取 pygame 页机使用的静态数据，生成 remake/pages_data.json。

数据来源（全部为反汇编实证，见 ANALYSIS.md §16）：
  * RT_STRING 字符串表            → GGD 文件名（LoadStringA 用，0x44BE10 内）
  * 0x452A00 (页2 进场)           → 每层重建尺寸 / 清屏色
  * 0x451E00 (页1 进场)           → 层2/13 尺寸
  * 0x43F560 (页2 时间轴实体)      → 状态→(层,GGD) 表 + 天空流时间点
  * 0x43DE30 (页1 时间轴实体)      → 帧号→生成类型
用法: python3 build_pages_data.py
"""
import json
import os
import struct

import pefile

GAME = os.environ.get("GEKI_DIR") or os.path.join(os.path.dirname(os.path.dirname(
    os.path.dirname(os.path.abspath(__file__)))), "geki106")
EXE = os.environ.get("GEKI_EXE") or os.path.join(GAME, "geki106.exe")
GAME_DIR = '/home/yuhuan/geki106'
OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'pages_data.json')


def string_table(pe):
    """RT_STRING → {id: name}"""
    strs = {}
    for entry in pe.DIRECTORY_ENTRY_RESOURCE.entries:
        if entry.id != 6:
            continue
        for e2 in entry.directory.entries:
            base = (e2.id - 1) * 16
            d = e2.directory.entries[0].data.struct
            raw = pe.get_data(int(d.OffsetToData), int(d.Size))
            i = k = 0
            while i + 2 <= len(raw) and k < 16:
                ln = int.from_bytes(raw[i:i + 2], 'little')
                i += 2
                s = raw[i:i + ln * 2].decode('utf-16le', 'replace')
                i += ln * 2
                if s:
                    strs[base + k] = s
                k += 1
    return {str(k): v for k, v in sorted(strs.items())}


# ---- 0x452A00: 页2 进场重建的层 (层号, w, h) —— push h, push w, push layer

# 页2 层尺寸（0x452A00 的 0x44C560 调用序列）
PAGE2_LAYER_SIZES = [
    (3, 480, 180), (4, 256, 256), (5, 656, 496), (6, 656, 496),
    (7, 240, 240), (8, 240, 240), (9, 240, 240), (10, 240, 240),
    (11, 640, 480), (12, 640, 480), (13, 640, 480), (2, 640, 480), (0, 640, 480),
]
# 天空色带表：0x43F8AC..0x43F95C，4 字节项 {i16 t, u8 color, u8 pad}（帧 +0x24 起）
PAGE2_SKY = [
    (-0x1A4, 0xB4), (0x000, 0xD9), (0x0AB, 0xB4), (0x80F, 0xB3), (0x967, 0xD2),
    (0x9BD, 0xD7), (0xA13, 0xB4), (0xABF, 0xB3), (0xB15, 0xD6), (0xC6D, 0xB4),
    (0xD19, 0xA7), (0xD6F, 0x7F), (0xDC5, 0xB4), (0xFC9, 0xD9), (0x2710, 0x00),
]
# 快照/拷贝表：0x43FA72..0x43FAED，4 字节项 {u8 layer, u8 flag, i16 t}（帧 +0x00 起）
PAGE2_COPY = [
    (-0x15E, 11, 1), (-0x15D, 12, 1), (-0x15C, 13, 1), (-0x15B, 2, 1),
    (0x0AC, 11, 0), (0x0CC, 12, 0), (0x0EC, 13, 0), (0x102, 2, 0),
]
# 记录流播放窗口：0x43F9DB..0x43FA26，4 字节项 {i16 start, i16 end}（帧 +0x04 起）
PAGE2_WINDOWS = [
    (-0x15E, -0x15B), (0x408, 0x4B3), (0x810, 0xA13), (0xAC0, 0xC6D), (0xD1A, 0x10CB),
]
# 明暗脉冲表：0x43FE77 循环消费，8 字节项 {i16 t, i16 a, i16 b, u8 c}
#   每个到期项 → 0x430400(&out, a, b, 0x61000005, c) → 0x427385 ctor：
#   [ent+0x1C]=(a+0xF)<<5（寿命/分支低位）、[ent+0x20]=a（=0 时跳过脉冲）、
#   [ent+0x24]=0xFFFFFF00（亮度，从 -256 每帧 +8 到 0）、[ent+0x28]=8、0x459AB0(0x56B95C, c)
PAGE2_FLASH = [
    (-420, 0xFF01, 0, 4), (-120, 0, 0xFF01, 0xFC), (0, 0xFF01, 0, 2),
    (170, 0xFF, 0, 0xF0), (202, 0xFF, 0, 0xF0), (234, 0xFF, 0, 0xF0),
    (256, 0xFF, 0xFF01, 0xFC), (516, 0xFF01, 0, 4), (860, 0, 0xFF01, 0xFC),
    (1030, 0, 0, 1), (1376, 0xFF01, 0, 0x10), (1530, 0, 0xFF01, 0xF0),
    (1548, 0xFF01, 0, 0x10), (1704, 0, 0xFF01, 0xF0), (1720, 0xFF01, 0, 0x10),
    (1876, 0, 0xFF01, 0xF0), (1894, 0, 0, 1), (2062, 0xFF, 0, 0xFC),
    (2836, 0xFF, 0, 0xFC), (4008, 0, 0xFF, 8), (4042, 0, 0, 8), (4268, 0, 0xFF, 8),
]

# 调色板切换：(t, RT_STRING id)：t=0 → id3 bm_pals；t=0x204 → id1 bm_pal
PAGE2_PALETTE = [(0x000, 3), (0x204, 1)]

PAGE2_LAYERS = [(3, 480, 180), (4, 256, 256), (5, 656, 496), (6, 656, 496),
                (7, 240, 240), (8, 240, 240), (9, 240, 240), (10, 240, 240),
                (11, 640, 480), (12, 640, 480), (13, 640, 480),
                (0, 640, 480), (2, 640, 480)]
# 0x452A00 之后逐层 0x44CE60(layer, 0) 清屏色
PAGE2_CLEAR = [3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 0, 2]
# ---- 0x451E00: 页1 进场
PAGE1_LAYERS = [(2, 640, 480)]
PAGE1_CLEAR = [13]

# ---- 0x43F560: 状态→(层, GGD id)。条目 8 字节 {u16 state, u8 layer, pad, u32 id}
TITLE_LAYER_TABLE = [
    (0xFE5C, 6, 0xC0), (0xFE99, 3, 0xC1), (0xFE9A, 4, 0xB4), (0xFE9B, 7, 0xC4),
    (0xFE9C, 8, 0xC5), (0xFE9D, 9, 0xC6), (0xFEAC, 9, 0xC7), (0xFEAD, 7, 0xC8),
    (0xFEAE, 10, 0xC9), (0x04B6, 7, 0xCC), (0x04B8, 8, 0xCD), (0x04BA, 9, 0xCE),
    (0x0766, 7, 0xD0), (0x0768, 8, 0xD1), (0x076A, 9, 0xD2), (0x076C, 10, 0xD3),
    (0x0A16, 7, 0xD4), (0x0A18, 8, 0xD5), (0x0C70, 7, 0xD8), (0x0C72, 8, 0xD9),
    (0x0C74, 9, 0xDA), (0x0C76, 10, 0xDB),
]
# ---- 0x43FA2B: 天空流 (#77, 0x459D60) 触发帧号（有符号 u16）
TITLE_SKY_EVENTS = [0xFEA2, 0xFEA5, 0x0408, 0x04B3, 0x0810, 0x0A13, 0x0AC0,
                    0x0C6D, 0x0D1A, 0x10CB]
# ---- 0x43F5xx: 计时器初值 = -420 (0xFFFFFE5C), 上限 0x2710
TITLE_TIMER_START = -420

# ---- 0x43FB6F 第二张表 {u16 timer, u8 layer, u8 flag}：
#      flag=1 → 0x44D190(层) = 把离屏(offscr)整幅拷进该层；flag=0 → 0x44D060(6,层,(0,0),(0,0,640,480))
#      = 把层6 整幅拷进该层（层6 = 0xFE5C 时装入 bm_otit 的"屏幕缓冲"）
TITLE_COPY_TABLE = [
    (0xFEA2, 11, 1), (0xFEA3, 12, 1), (0xFEA4, 13, 1), (0xFEA5, 2, 1),
    (0x00AC, 11, 0), (0x00CC, 12, 0), (0x00EC, 13, 0), (0x0102, 2, 0),
]

# ---- 0x43DE30: 页1 时间轴 {帧号, 生成类型}（表在栈上, 3 项）
# 表在栈上：frames[0x10..0x13]={30,80,100}, types[0x24,0x28,0x2C]={0x5F000002,0x5F000003,0x5F000003}
#   （0x43DE3C/0x43DE40 的 mov [esp+0x20]/[esp+0x24] 发生在 push ebp 之后、push edi 之前，
#    折算到 3 次 push 后的帧就是 0x28/0x2C；0x43DE67 写 0x24 = 第 0 项）
PAGE1_TIMELINE = [
    {"frame": 0x1E, "type": 0x5F000002, "flag": 0},   # t=30  → wipe_v
    {"frame": 0x50, "type": 0x5F000003, "flag": 0},   # t=80  → wipe_h (edi=0)
    {"frame": 0x64, "type": 0x5F000003, "flag": 1},   # t=100 → wipe_h (edi=0x14, cmp ebp,2; sete dl)
]

# ---- 0x43DE30: 全屏填充色（0x44D200(mgr, idx)）换色时间点
#       [ent+0x20] 初值 0xB4（变体 0 的 ctor 写入），表 {t,idx} 来自 0x43DF0B 循环
PAGE1_FADE = [{"t": 0x0A, "color": 0xD3}, {"t": 0xA5, "color": 0xB5},
              {"t": 0xAA, "color": 0xD3}, {"t": 0x122, "color": 0xB4}]

# ---- 0x43DE30: 文字（0x44D330）——{字符串 VA, x, y, 高度, 文字色, 底色, 出现条件}
#      bottom: t==200 或 230<=t<290；top: 230<=t<290（t==200 时跳过）
PAGE1_TEXTS = [
    {"s": 0x4A4020, "x": 0x20, "y": 0x20,  "h": 0x10, "fg": 0xD9, "bg": 0xD3, "when": "top"},
    {"s": 0x4A3FEC, "x": 0x20, "y": 0x30,  "h": 0x10, "fg": 0xD9, "bg": 0xD3, "when": "top"},
    {"s": 0x4A3FD0, "x": 0x20, "y": 0x40,  "h": 0x10, "fg": 0xD9, "bg": 0xD3, "when": "top"},
    {"s": 0x4A405C, "x": 0x20,  "y": 0x1B0, "h": 0x10, "fg": 0xD9, "bg": 0xD3, "when": "bottom"},
    {"s": 0x4A4054, "x": 0x93,  "y": 0x1B0, "h": 0x10, "fg": 0xD9, "bg": 0xD3, "when": "bottom"},
    {"s": 0x4A404C, "x": 0x106, "y": 0x1B0, "h": 0x10, "fg": 0xD9, "bg": 0xD3, "when": "bottom"},
    {"s": 0x4A4044, "x": 0x179, "y": 0x1B0, "h": 0x10, "fg": 0xD9, "bg": 0xD3, "when": "bottom"},
    {"s": 0x4A4040, "x": 0x1EC, "y": 0x1B0, "h": 0x10, "fg": 0xD9, "bg": 0xD3, "when": "bottom"},
]
PAGE1_END_T = 0x122          # 计时器到此（或按攻击键）→ 离页
PAGE1_TEXT_T = [0xC8, 0xE6, 0x122]   # 200 单帧 / [230,290) 区间

# ---- 0x43D430: 0x6F0000xx 行为表 (idx → 行为地址, 参数写入)
UI_6F_VARIANTS = [
    {"idx": 0, "behavior": "0x43DE30", "note": "opening timeline"},
    {"idx": 1, "behavior": "0x43E1C0"},
    {"idx": 2, "behavior": "0x43E410"},
    {"idx": 3, "behavior": "0x441550"},
    {"idx": 4, "behavior": "0x4415F0"},
    {"idx": 5, "behavior": "0x401AFA->?"},
    {"idx": 6, "behavior": "0x40167C->?"},
    {"idx": 7, "behavior": "0x43F560", "note": "title layer-loader timeline"},
    {"idx": 8, "behavior": "default(no behavior)"},
    {"idx": 9, "behavior": "0x444A30", "note": "注意: 与敌机帧更新同址"},
    {"idx": 10, "behavior": "0x445780"},
]


def read_cstr(pe, va, image_base=0x400000):
    rva = va - image_base
    data = pe.get_data(rva, 256)
    end = data.find(b'\x00')
    return data[:end].decode('cp932', 'replace')


def load_palette_bmp(path):
    """bm_pal.bmp → [(r,g,b)]*256（8bpp 调色板）"""
    from PIL import Image
    im = Image.open(path)
    pal = im.getpalette() or []
    out = []
    for i in range(256):
        if i * 3 + 2 < len(pal):
            out.append([pal[i * 3], pal[i * 3 + 1], pal[i * 3 + 2]])
        else:
            out.append([0, 0, 0])
    return out


def main():
    pe = pefile.PE(EXE)
    data = {
        "source": "geki106.exe (v1.06) — 由 build_pages_data.py 提取",
        "string_table": string_table(pe),
        "palette": load_palette_bmp(os.path.join(GAME_DIR, 'bmcm', 'bm_pal.bmp')),
        # 页2 会切调色板：id1=bm_pal、id2=bm_pald、id3=bm_pals（0x44CDF0 → 0x44C800 载 BMP 调色板）
        "palettes": {
            "1": load_palette_bmp(os.path.join(GAME_DIR, 'bmcm', 'bm_pal.bmp')),
            "2": load_palette_bmp(os.path.join(GAME_DIR, 'bmcm', 'bm_pald.bmp')),
            "3": load_palette_bmp(os.path.join(GAME_DIR, 'bmcm', 'bm_pals.bmp')),
        },
        "page1": {
            "layers": PAGE1_LAYERS,
            "layers_special": [{"fn": "0x44C640", "layer": 13, "arg": 9}],
            "clear": PAGE1_CLEAR,
            "timeline": PAGE1_TIMELINE,
            "spawn_type": 0x6F000001,
            "fade": PAGE1_FADE,
            "texts": [{**t, "str": read_cstr(pe, t["s"])} for t in PAGE1_TEXTS],
            "end_t": PAGE1_END_T,
            "text_t": PAGE1_TEXT_T,
        },
        "page2": {
            "layers": PAGE2_LAYERS,
            "clear": PAGE2_CLEAR,
            "spawn_type": 0x6F000008,
            "timer_start": TITLE_TIMER_START,
            "timer_period": 62,
            "state_end": 0x2710,
            "layer_table": [{"state": s, "layer": l, "ggd": g} for s, l, g in TITLE_LAYER_TABLE],
            "sky_events": TITLE_SKY_EVENTS,
            "copy_table": [{"t": t, "layer": l, "flag": f} for t, l, f in TITLE_COPY_TABLE],
            # 本轮新增（§16.11）：层尺寸 / 天空色带 / 快照拷贝 / 记录流窗口 / 调色板切换
            "layer_sizes": [[n, w, h] for (n, w, h) in PAGE2_LAYER_SIZES],
            "sky": [[t, c] for (t, c) in PAGE2_SKY],
            "copy": [[t, layer, flag] for (t, layer, flag) in PAGE2_COPY],
            "windows": [[s0, s1] for (s0, s1) in PAGE2_WINDOWS],
            "palette_switch": [[t, sid] for (t, sid) in PAGE2_PALETTE],
            "flash": [[t, a, b, c] for (t, a, b, c) in PAGE2_FLASH],
            "stream": "assets/p2_stream.bin",
        },
        "page3": {
            "spawn_type": 0x5F000005,
            "script_slot": 1,
            "script_chain": 0x24,
            "input_preset": 0,
            "timer_period": 0,
        },
        "ui_6f_variants": UI_6F_VARIANTS,
        "flags": {
            "leave_esc": 0x200,        # 0x458FD0 cmd0
            "leave_click": 0x10000,    # 页2 step: btn0/btn1 按下沿
            "leave_select": 0x200000,  # 0x450FE0 cmd9
            "layer_fail": 0x2,
            "exit": 0x40,
        },
    }
    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    with open(OUT, 'w', encoding='utf-8') as f:
        json.dump(data, f, ensure_ascii=False, indent=1)
    print('wrote', OUT, len(json.dumps(data)), 'bytes')

    # 页2 背景动画：资源 77 的记录流 → pygame/assets/p2_stream.bin
    # （0x459C90 用 0x45DDE0(0x4D) 取长度，0x459D60 逐帧读 {i16 count, count×9B}）
    _here = os.path.dirname(os.path.abspath(__file__))          # remake/
    src77 = os.path.join(os.path.dirname(_here), 'extracted', 'data', 'res_77.bin')
    dst77 = os.path.join(_here, 'pygame', 'assets', 'p2_stream.bin')
    os.makedirs(os.path.dirname(dst77), exist_ok=True)
    if os.path.exists(src77):
        with open(src77, 'rb') as f: _b = f.read()
        with open(dst77, 'wb') as f: f.write(_b)
        print('stream77 ->', dst77, len(_b), 'bytes')


if __name__ == '__main__':
    main()
