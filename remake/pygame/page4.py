"""页4（游戏本体）—— 按 geki106.exe 反汇编逐步实现。

地址依据（§10.7 / §16.119 / `docs/p4_step_0x451110.md`）：

    页机            0x459360（字节表 0x459618 把页 4/11 映射到跳表 0x4595E4 第 3 项）
    页4 handler     0x4593C2   if (0x4505B0(App)) do { if (!0x451110(App)) break; } 0x451C50(App)
    阶段进场        0x4505B0
    进场公共尾      0x450A3D   状态字回写 / 0x458D60 引擎 / 清统计 / 21 槽脚本预载 / VM 初始化
    每帧            0x451110   （S1..S25，见 `p4_step`）
    阶段首帧        0x451630   （`[0x56CCB4]` 门控；唯一置 1 处在 `0x423B7B`）
    页收尾          0x451C50
    净化序列        0x458D60   （`0x401262` thunk：10 队列 + 0x45EB40 + 0x460930 + 0x45D110）
    流程 VM 每帧    0x450FE0

本模块是 `geki.Pages` 的 mixin（`self.*` 指向 Pages 实例属性）。
"""

from __future__ import annotations

_P4_BLOCK: dict | None = None

# 0x450BBD..0x450D59：`0x40127B` = `0x450140(0x4AB4B0, slot, wav)` 共 21 条（**音效槽装载**，
# 不是脚本！0x4AB4B0 是 DirectSound 21 槽管理器），任一失败 → `0x450D62 0x4AB5C0 |= 8`
P4_SE_SLOTS = [
    (0x00, 0x27), (0x01, 0x28), (0x02, 0x1C), (0x03, 0x1C), (0x04, 0x16),
    (0x05, 0x1E), (0x06, 0x22), (0x07, 0x23), (0x08, 0x20), (0x09, 0x21),
    (0x0A, 0x1D), (0x0B, 0x15), (0x0C, 0x1B), (0x0D, 0x17), (0x0E, 0x26),
    (0x0F, 0x25), (0x10, 0x19), (0x11, 0x1A), (0x12, 0x18), (0x13, 0x1F),
    (0x14, 0x2C),
]

# 0x450AB1..0x450B37：进场清零的统计区（地址 → 0）
P4_STAT_ZERO = [0x56CC98, 0x56CC9C, 0x56CCA0, 0x56CCA4, 0x56CCA8, 0x56CCAC,
                0x56CCCC, 0x56CCD0, 0x56CCD4]



# ---------------------------------------------------------------------------
# 脚本流状态机（`0x56CC4C`）：`0x460350` 一帧一步
# ---------------------------------------------------------------------------
_P4_TBL_4993C4 = None


def p4_tbl_4993c4():
    """`0x4993C4` 的 256 项 dword 表（由 `remake/build_p4_str.py` 一并导出）。"""
    global _P4_TBL_4993C4
    if _P4_TBL_4993C4 is None:
        try:
            import json as _j
            from pathlib import Path as _P
            _P4_TBL_4993C4 = _j.loads((_P(__file__).with_name("p4_tbl_4993c4.json")).read_text())
        except Exception:
            _P4_TBL_4993C4 = []
    return _P4_TBL_4993C4


_P4_STR_TABLE = None


def p4_str_table():
    """`0x499798` 的字形 id 表（由 `remake/build_p4_str.py` 从 exe 导出）。"""
    global _P4_STR_TABLE
    if _P4_STR_TABLE is None:
        try:
            import json as _j
            from pathlib import Path as _P
            _P4_STR_TABLE = _j.loads((_P(__file__).with_name("p4_str_table.json")).read_text())
        except Exception:
            _P4_STR_TABLE = []
    return _P4_STR_TABLE


class ScriptBank:
    """资源访问：`0x45DDA0(id)` = 指针、`0x45DDE0(id)` = 长度。

    表头是 24 位、基址相对的紧凑偏移表（`resource_dec.bin` 前 294 字节 = 98 项），id 从 1 起；
    id 45..76 = 32 个脚本。
    """

    def __init__(self, path):
        self.d = path.read_bytes()
        self.n = 294 // 3

    def _u24(self, i: int) -> int:
        o = 3 * (i - 1)                       # 0x45DDA0：3*(id-1)
        return int.from_bytes(self.d[o:o + 3], "little")

    def get(self, sid: int) -> bytes:
        """`0x45DDA0(id)`..`0x45DDE0(id)`。"""
        o = self._u24(sid)
        e = self._u24(sid + 1) if sid < self.n else len(self.d)
        return self.d[o:e]


class ScriptVM:
    """`0x56CC4C` 的字段级复刻（`docs/p4_vm_0x460350.md`）。

    +04 帧计数｜+08 当前流 id｜+0A 待播队列 w[16]｜+2A 链索引｜+2C 缓冲｜+30 游标｜+34 终止｜+38 旗标
    """

    # 记录总长（含 4 字节头）；op9 变长，op0 特例 edi=0
    SIZES = {0x0: 4, 0x1: 0x14, 0x2: 0x14, 0x3: 0x14, 0x4: 0x14, 0x5: 0x14,
             0x6: 0x5C, 0x7: 0x60, 0x8: 8, 0xA: 0xC, 0xB: 0x3C, 0xC: 8, 0xD: 8, 0xE: 0x14}

    def __init__(self, bank: ScriptBank, chains: list[int], owner=None):
        self.bank = bank
        self.chains = chains
        self.owner = owner
        self.frame = 0            # +04
        self.cur_id = 0           # +08
        self.queue: list[int] = []  # +0A
        self.chain = 0            # +2A
        self.buf = b""            # +2C
        self.cur = 0              # +30
        self.term = 0             # +34
        self.flags = 0            # +38
        self.out = {1: [], 2: [], 3: [], 4: [], 5: [], 6: [], 7: [], 8: [],
                    9: [], 0xA: [], 0xB: [], 0xC: [], 0xD: [], 0xE: []}

    # 0x4602D0(this, chain)
    def load_chain(self, chain: int) -> None:
        self.flags = 0                       # 0x4602D4 0x401064
        chain &= 0xFFFF
        c = chain - 0x10000 if chain & 0x8000 else chain
        self.chain = c & 0xFFFF              # 0x4602E2 word[+0x2A]
        i, n = c, 0
        while 0 <= i < len(self.chains) and n < 0xF:     # 0x4602F6 cmp esi,0xF
            v = self.chains[i]
            if v == 0:
                break
            self.queue.append(v)             # 0x4602FB word[edx]=ax
            n += 1
            i += 1
        self.queue = self.queue[:0xF]
        self.load_next()                     # 0x460313 尾调

    # 0x4600F0：取队列头装新流
    def load_next(self) -> bool:
        if not self.queue:
            self.term = 1                    # 0x46021C
            return False
        self.cur_id = self.queue[0]           # 0x460108 word[+8]
        self.queue = self.queue[1:] + [0] * (0xF - len(self.queue) + 1)   # 0x460111..0x46011C 左移 15 字
        self.queue = [q for q in self.queue if q] or []
        self.buf = self.bank.get(self.cur_id) if self.cur_id else b""
        self.cur = 0
        self.frame = 0                        # +04 清 0
        self.term = 0 if self.buf else 1
        return bool(self.buf)

    # 0x460350：一帧；返回 1 = 本流/链已耗尽，0 = 运行中
    def step(self) -> int:
        if not self.buf or self.term:         # 0x46036B
            return 1
        if self.flags:                        # 0x460376 0x45B030(+0x38,0) ⇒ [+4]!=0
            return 0
        while True:
            if self.cur + 4 > len(self.buf):
                self.term = 1
                return 1
            t = int.from_bytes(self.buf[self.cur + 2:self.cur + 4], "little")
            if t > self.frame:                # 有符号比较 0x460388
                self.frame += 1               # 0x46069C
                return 0
            op = int.from_bytes(self.buf[self.cur:self.cur + 2], "little")
            if op > 0xE:                      # 0x4603A2 非法 op
                edi = 0
            elif op == 0x9:
                n = int.from_bytes(self.buf[self.cur + 0xC:self.cur + 0x10], "little")
                edi = 0x10 + n * 4
            else:
                edi = self.SIZES[op]
            if op == 0:                       # 0x460686 → 0x4600F0
                if not self.load_next():
                    self.term = 1             # 0x460691
                    return 1
                continue                      # 游标已重置，不叠加 edi
            self.exec_op(op, self.buf[self.cur + 4:self.cur + edi])
            self.cur += edi                   # 0x4603EE
            if not self.buf:                  # 0x460404
                return 1

    def exec_op(self, op: int, body: bytes) -> None:
        if op == 0xE:                                            # 0x4603E9 注释
            self.out[0xE].append(body.split(b"\0")[0])
        elif 1 <= op <= 5:                                       # 0x46044F/3AD/411/490/4D1
            rec = tuple(int.from_bytes(body[i:i + 4], "little") for i in (0, 4, 8, 0xC))
            self.out[op].append(rec)
            if self.owner is not None:
                self.owner.p4_vm_entity(op, rec)
        elif op == 0x6:                                          # 0x460554 立即触发
            rec = (int.from_bytes(body[0:4], "little"), body[4:0x54],
                   int.from_bytes(body[0x54:0x58], "little"))
            self.out[6].append(rec)
            if self.owner is not None:
                self.owner.p4_bg_record(6, *rec, 0)              # 0x457C00
        elif op == 0x7:                                          # 0x460574 只改参数
            rec = (int.from_bytes(body[0:4], "little"), body[4:0x54],
                   int.from_bytes(body[0x54:0x58], "little"),
                   int.from_bytes(body[0x58:0x5C], "little"))
            self.out[7].append(rec)
            if self.owner is not None:
                self.owner.p4_bg_record(7, *rec)                 # 0x457C40
        elif op == 0x8:                                          # 0x4605C6 停通道
            self.out[8].append(int.from_bytes(body[0:4], "little"))
        elif op == 0x9:                                          # 0x460512 变长表
            n = int.from_bytes(body[8:0xC], "little")
            vals = [int.from_bytes(body[0xC + 4 * i:0x10 + 4 * i], "little") for i in range(n)]
            self.out[9].append((int.from_bytes(body[0:4], "little"),
                                int.from_bytes(body[4:8], "little"), vals))
        elif op == 0xA:                                          # 0x460538
            self.out[0xA].append((int.from_bytes(body[0:4], "little"),
                                  int.from_bytes(body[4:8], "little")))
        elif op == 0xB:                                          # 0x460600 装层
            res = [int.from_bytes(body[i:i + 4], "little") for i in range(0, 0x38, 4)]
            self.out[0xB].append(res)
            if self.owner is not None:
                self.owner.p4_load_layers(res)
        elif op == 0xC:                                          # 0x46064A 播 BGM
            v = int.from_bytes(body[0:4], "little") & 0xFFFF
            self.out[0xC].append(v)
            if self.owner is not None:
                self.owner.p4_play_bgm(v)
        elif op == 0xD:                                          # 0x46066D 关卡号
            v = int.from_bytes(body[0:4], "little") & 0xFFFF
            self.out[0xD].append(v)
            if self.owner is not None:
                self.owner.p4_set_level(v)


# ---------------------------------------------------------------------------
# 实体（0x5C 字节通用对象，vtable 0x49874c）
# ---------------------------------------------------------------------------
# `0x40D940`（0x23 族子 ctor，`ret 4`）：`eax = type - 0x23000001`，`cmp eax,0x19` →
# `jmp [eax*4 + 0x40DE98]`（26 项）。每项就是"写 `[ent+0x40]` 行为指针 + 若干字段"。
ENT23_INIT = {
    0x23000001: {"beh": 0x401C44, "imm": {0x1C: 0}},
    0x23000002: {"beh": 0x401FF0, "imm": {0x24: -0x10, 0x28: 0, 0x2C: 0}, "d_to": 0x1C,
                 "d20": True},                      # 0x40D985..0x40D9B8
    0x23000003: {"beh": 0x401B1D, "imm": {0x20: -4, 0x24: 0}, "d_to": 0x1C},
    0x23000004: {"beh": 0x40118B, "imm": {0x1C: 0, 0x20: -0x1E}, "d_to": 0x24},
    0x23000005: {"beh": 0x401BD1, "imm": {0x1C: 0, 0x20: 0, 0x24: 0, 0x28: 0}, "d_to": 0x2C},
    0x23000006: {"beh": 0x401BD1, "imm": {}},
    0x23000007: {"beh": 0x402180, "imm": {0x20: 0}, "d_to": 0x1C},
    0x23000008: {"beh": 0x401528, "imm": {0x1C: 0, 0x20: -8}},
    0x23000009: {"beh": 0x4015AA, "imm": {}},
    0x2300000A: {"beh": 0x401181, "imm": {}},
    0x2300000D: {"beh": 0x40210D, "imm": {}},
    0x23000012: {"beh": 0x4015B4, "imm": {}},
    0x23000013: {"beh": 0x40231A, "imm": {}},
    0x23000015: {"beh": 0x4017EE, "imm": {}},
    0x23000016: {"beh": 0x401D48, "imm": {}},
    0x23000017: {"beh": 0x401951, "imm": {}},
    0x23000018: {"beh": 0x4013BB, "imm": {}},
    0x23000019: {"beh": 0x401B31, "imm": {}},
    0x2300001A: {"beh": 0x40242D, "imm": {}},
}


# `0x498000`：每型 10 字节属性记录（索引 = type & 0xFF，1 基），`0x43AC30` 读它填公共字段：
#   u16 +0 = 半径、u16 +2 = 存活门（写 [+0x18]）、u16 +4 = 写 [+0x58]、
#   u16 +6 = 源矩形 left、u16 +8 = 源矩形 top（矩形宽高都是 0x30，0x43AC8E 的 lea 用 *2-1 算右下）
ENT_PROP = {
    0x01: (24, 1, 0x200, 0x00, 0), 0x02: (24, 1, 0x180, 0x30, 0),
    0x03: (24, 0x14, 0x200, 0x00, 0), 0x04: (24, 0x140, 0xFD80, 0x180, 0),
    0x05: (24, 0x48, 0x00, 0xC0, 0), 0x06: (24, 1, 0x1C0, 0xF0, 0),
    0x07: (24, 1, 0x00, 0x90, 0), 0x08: (24, 0x64, 0x00, 0x120, 0),
    0x09: (24, 0x28, 0x2C0, 0x150, 0),
}


# 行为 thunk（写进 `[ent+0x40]`）→ 真实函数（`jmp rel32` 解引用）。
# `P4_BEH` 一律按**真实地址**登记，ctor 时就把 thunk 解成真实地址存进 `Ent.beh`。
ENT23_BEH_THUNK = {
    0x401C44: 0x40E070, 0x401FF0: 0x40E100, 0x401B1D: 0x40E230, 0x40118B: 0x40E460,
    0x401BD1: 0x40E520, 0x402180: 0x40E790, 0x401528: 0x40E8C0, 0x401181: 0x40EAF0,
}


import random as _random

rng = _random.Random(0x4593C2)     # 原作用的是 CRT rand()，复刻侧固定种子以便无头复现

BG_LADDER = (6, 10, 16, 24, 32, 48, 72, 108, 160, 240)   # 0x457050 栈上阶梯表

# `0x457938`：241 字节 kind → 阶梯序号表（非阶梯值一律 0x0B = 不改层；0 = 隐藏）
BG_KIND_IDX = [0x0B] * 241
for _k, _i in ((0, 0), (6, 1), (10, 2), (16, 3), (24, 4), (32, 5),
               (48, 6), (72, 7), (108, 8), (160, 9), (240, 10)):
    BG_KIND_IDX[_k] = _i


class BgBand:
    """背景带（`0x457540` ctor；链表 next = `[band+0x30]`）。"""

    __slots__ = ("slot", "pos", "jit_x", "jit_y", "kind", "w", "h", "row",
                 "layer", "src", "dst", "visible")

    def __init__(self, slot, idx):
        self.slot = slot
        self.pos = idx            # +0x0C 位置（格单位）
        prm = slot.params
        self.jit_x = rng.randrange(prm[8] + 1) if prm[8] >= 0 else 0   # +0x14
        self.jit_y = rng.randrange(prm[9] + 1) if prm[9] >= 0 else 0   # +0x18
        self.kind = -1            # +0x1C
        self.w = 0                # +0x20
        self.h = 0                # +0x24
        # +0x10 行号：param[0x3C]/[0x40]/[0x44]/[0x48]（块 dword 15..18）加权随机
        wts = [max(0, prm[15]), max(0, prm[16]), max(0, prm[17]), max(0, prm[18])]
        tot = sum(wts)
        if tot > 0:
            r = rng.randrange(tot)
            acc = 0
            self.row = 0
            for i, wv in enumerate(wts):
                acc += wv
                if r < acc:
                    self.row = i
                    break
        else:
            self.row = 0
        self.layer = 0            # 节点 [+0]
        self.src = (0, 0, 0, 0)   # 节点 [+4..]
        self.dst = (0, 0)         # 节点 [+0x14]/[+0x18]
        self.visible = 0          # 节点 [+0x1C]


class BgSlot:
    """`0x4AD55C` 的 12 个背景槽之一（元素 0x2A98 字节，`0x457B60` → `0x463C4F`）。"""

    __slots__ = ("params", "rates", "grid", "bands", "rem", "flags", "active", "acc")

    def __init__(self):
        self.params = [0] * 20     # +0x30（0x456D50 拷入）
        self.rates = [0] * 20      # +0x80（0x457330 拷入）
        self.grid = []             # +0xD0：每条 3 dword {x, y, kind}
        self.bands = []            # +0x04 带链表
        self.rem = 0               # +0x2A88 速率剩余帧
        self.flags = 0             # +0x2A8C 分发位
        self.active = 0            # +0x2A90
        self.acc = 0               # +0x2A94 滚动累加

    # +0x58 = 格数；+0x64 = 阈值；+0x68 = 每帧滚动量
    @property
    def count(self) -> int:
        return self.params[10]


class DNode:
    """显示节点（`[ent+0x38]` 指向它；`0x45A0E0` 是节点池取节点）。"""

    def __init__(self, layer: int, l: int, t: int):
        self.layer = layer            # [+0]（0x43ACC3 = 2）
        self.rect = (l, t, l + 0x2F, t + 0x2F)   # [+4..+0x10]
        self.dst = (0, 0)             # [+0x14]/[+0x18]
        self.active = 1               # [+0x1C]


class Ent:
    """0x5C 字节实体；`[+0x34]` 存活字节、`[+0x40]` 行为指针、`[+0x14]` 类型。"""

    SZ = 0x5C

    def g16(self, off: int) -> int:
        return self.m[off] | (self.m[off + 1] << 8)

    def d16(self, off: int, v: int) -> None:
        self.m[off] = v & 0xFF
        self.m[off + 1] = (v >> 8) & 0xFF

    def __init__(self, a: int, b: int, typ: int, d: int):
        self.m = bytearray(self.SZ)
        self.d32(0x00, 0x49874C)          # 0x43045E vtable（0x43A82C 再改成 0x49874c）
        self.d32(0x04, a)                 # 0x430475 payload[0]
        self.d32(0x08, b)                 # 0x43047A payload[4]
        self.d32(0x14, typ)               # 0x430480 payload[8]
        self.d32(0x3C, 0)                 # 0x43046A payload[0x10]（栈残留，这里取 0）
        self.d32(0x38, 0)                 # 0x43048F 0x4020D1(...)
        self.m[0x34] = 1                  # 0x430486 存活
        self.d32(0x40, 0)
        self.beh = 0
        self.node: DNode | None = None
        self.buf2c = None                 # 0x4601CB 字形位图缓冲（0x4602D0 家族）
        self.flags38 = 0                  # 0x4602B2 标志字
        self.link24 = None                # 0x43CD77 演员链表头
        if (typ & 0x2F000000) == 0x23000000:      # 0x40D940 0x23 族
            prop = ENT_PROP.get(typ & 0xFF)       # 0x43AC30 的 0x498000 记录
            if prop is not None:
                self.d32(0x0C, prop[0])           # 半径
                self.d32(0x18, prop[1])           # 存活门
                self.d32(0x58, prop[2])
                self.m[0x10] = 1                  # 0x43ACC0 参与碰撞
                self.node = DNode(2, prop[3], prop[4])   # 0x43ACC3 层号恒 2
                self.node.dst = (self.s32(4) - 0x18, self.s32(8) - 0x18)
            info = ENT23_INIT.get(typ)
            if info is not None:
                thunk = info["beh"]
                self.d32(0x40, thunk)                  # 原版存 thunk
                self.beh = ENT23_BEH_THUNK.get(thunk, thunk)   # 复刻侧按真实地址分派
                for off, val in info["imm"].items():
                    self.d32(off, val & 0xFFFFFFFF)
                if "d_to" in info:
                    self.d32(info["d_to"], d & 0xFFFFFFFF)
                if info.get("d20"):       # 0x40D98E：`[+0x20] = (b<=0xF0) ? -1 : 1`
                    self.d32(0x20, 0xFFFFFFFF if b <= 0xF0 else 1)

    def d32(self, off: int, val: int) -> None:
        self.m[off:off + 4] = int(val & 0xFFFFFFFF).to_bytes(4, "little")

    def g32(self, off: int) -> int:
        return int.from_bytes(self.m[off:off + 4], "little")

    def s32(self, off: int) -> int:
        v = self.g32(off)
        return v - 0x100000000 if v & 0x80000000 else v

    def __repr__(self) -> str:
        return f"<Ent 0x{self.g32(0x14):08X} beh=0x{self.beh:06X} a={self.g32(4)} b={self.g32(8)} d={self.g32(0x1C)}>"

def _beh_23000001(self, e) -> bool:
    """`0x401C44` → `0x40E070`（类型 0x23000001，1 个/关）：计时驱动的移动。

    `t=++[+0x1C]`；`t<=0x78` → `y-=1`；`t==0x1A4` → `0x43B070(ent,0)`；`t>0x21C` → `x-=2`。
    节点 dst = `(x-0x18, y-0x18)`；存活 `[+0x18]!=0 && x>-0x18`。
    """
    t = (e.s32(0x1C) + 1) & 0xFFFFFFFF
    e.d32(0x1C, t)
    if t <= 0x78:                                  # 0x40E07C
        e.d32(0x08, (e.s32(0x08) - 1) & 0xFFFFFFFF)
    elif t == 0x1A4:                               # 0x40E086
        self.p4_43B070(e, 0)
    elif t > 0x21C:                                # 0x40E098
        e.d32(0x04, (e.s32(0x04) - 2) & 0xFFFFFFFF)
    if e.node is not None:
        e.node.dst = (e.s32(0x04) - 0x18, e.s32(0x08) - 0x18)
    return e.g32(0x18) != 0 and e.s32(0x04) > -0x18


def _beh_23000007(self, e) -> bool:
    """`0x402180` → `0x40E790`：分裂型。`[+0x1C]` 为分裂数，>0 时一次性生成 N 个 0x23000007
    到主队列 `0x4AD43C`（x=rand%0x500、y=rand%0x1E0+0x298）然后自身死亡；否则左移 6/帧并向玩家 y 靠拢。
    """
    n = e.s32(0x1C)
    if n:
        for _ in range(n):                                   # 0x40E7AA..0x40E7FB
            x = rng.randrange(0x500)                         # 0x401393 → 0x45AD00, 0x462D71 取商
            y = rng.randrange(0x1E0) + 0x298                 # 余数 + 0x298
            self.spawn(self.p4_q43c, 0x23000007, x, y)       # 0x401FA5(0x4AD43C, rec)
        return False
    x = e.s32(0x04)
    dy = 0 if x > 0x298 else (self.p4_player_y() - e.s32(0x08))   # 0x56CC90 = 自机 y
    x -= 6
    e.d32(0x04, x)
    if dy:
        e.d32(0x08, (e.s32(0x08) + ((dy + 0x1F) >> 6)) & 0xFFFFFFFF)   # 0x40E82B
    if e.node is not None:
        e.node.dst = (e.s32(0x04) - 0x18, e.s32(0x08) - 0x18)
    return x >= -0x18 and e.g32(0x18) != 0


def _beh_23000008(self, e) -> bool:
    """`0x401528` → `0x40E8C0`：定时变速直线。t=0x10 减速为 0、t=0xC0 生成 0x23000009 于 (x-0x18,y)、
    t=0x100 加速为 8、t=0x113 自毁；x += [+0x20]。
    """
    t = e.s32(0x1C)
    e.d32(0x1C, (t + 1) & 0xFFFFFFFF)
    if t > 0x100:
        if t == 0x113:                                       # 0x40E931
            return False
    elif t == 0x100:
        e.d32(0x20, 8)                                       # 0x40E928
    elif t == 0x10:
        e.d32(0x20, 0)                                       # 0x40E91F
    elif t == 0xC0:
        self.spawn(self.p4_q43c, 0x23000009, e.s32(0x04) - 0x18, e.s32(0x08))   # 0x40E8E5
    e.d32(0x04, (e.s32(0x04) + e.s32(0x20)) & 0xFFFFFFFF)    # 0x40E93B
    if e.node is not None:
        e.node.dst = (e.s32(0x04) - 0x18, e.s32(0x08) - 0x18)
    return e.g32(0x18) != 0


def _beh_23000005_06(self, e) -> bool:
    """`0x401BD1` → `0x40E520`（类型 0x23000005/06）：连发 + 定时变轨 + 子实体死后随机镜像。

    ```
    ① 0x40E528 if ([+0x2C]) { 0x4023C4(&rec, x, y, 0x23000006, [+0x2C]);
                             do { rec.速度 = [+0x2C]*-8; 0x401FA5(0x4AD43C,&rec) } while (--[+0x2C]); }
    ② [0x20]==0    → [+0x24]=-3; [+0x28]=(y<=0xF0)?-3:3
       [0x20]==0x4B → [+0x24]=-1; [+0x28]=-([+0x28]*4)/3
       [0x20]==0x78 → 仅 0x23000006：0x40213F(ent,0)
       [0x20]==0x96 → [+0x24]=4;  [+0x28]=-([+0x28]/4)
    ③ [+0x1C]!=0 && [[+0x1C]+0x34]==0 → if ([+0x20]<0) return 0;
                                        [+0x1C]=0; [+0x20]=0x14A; rand&1 随机镜像
    0x40E6A3 [+0x20]++; x += [+0x24]; y += [+0x28]; dst=(x-0x18,y-0x18)
    ```
    """
    n = e.s32(0x2C)
    if n:
        for i in range(n):                                    # ① 0x40E575 循环
            v = (n - i)
            self.spawn(self.p4_q43c, 0x23000006, e.s32(0x04), e.s32(0x08))
            if self.p4_q43c:
                self.p4_q43c[-1].d32(0x28, (-8 * v) & 0xFFFFFFFF)   # 0x40E57C neg/shl 3
        e.d32(0x2C, 0)
    if e.s32(0x1C) == 0 and e.s32(0x14) != 0x23000005 and e.s32(0x20) == 0x172:
        e.d32(0x1C, 0)                                        # 0x40E599
        self.p4_43B070(e, e.s32(0x58) + 0x80)
    t = e.s32(0x20)
    if t == 0:                                                # 0x40E5D9
        e.d32(0x24, 0xFFFFFFFD)
        e.d32(0x28, 0xFFFFFFFD if e.s32(0x08) <= 0xF0 else 3)  # 0x40E5DE
    elif t == 0x4B:                                           # 0x40E5FA
        e.d32(0x24, 0xFFFFFFFF)
        v = e.s32(0x28) * 4
        q = -v // 3 if v >= 0 else -((-v) // 3)               # 0x40E602 imul 0x55555556（向零取整）
        e.d32(0x28, q & 0xFFFFFFFF)
    elif t == 0x78 and e.s32(0x14) == 0x23000006:              # 0x40E621
        self.p4_43B070(e, 0)
    elif t == 0x96:                                           # 0x40E63A
        e.d32(0x24, 4)
        v = e.s32(0x28)
        e.d32(0x28, (-(v // 4)) & 0xFFFFFFFF)                  # 0x40E64C 向零取整
    child = e.g32(0x1C)
    if child and not self.p4_child_alive(child):               # 0x40E659
        if e.s32(0x20) < 0:
            return False
        vx, vy = e.s32(0x24), e.s32(0x28)
        e.d32(0x1C, 0)
        e.d32(0x20, 0x14A)
        if rng.randrange(2):                                   # 0x40E68B rand&1
            e.d32(0x24, vy & 0xFFFFFFFF)
            e.d32(0x28, (-vx) & 0xFFFFFFFF)
        else:
            e.d32(0x28, (-vy) & 0xFFFFFFFF)
            e.d32(0x24, vx & 0xFFFFFFFF)
    e.d32(0x20, (t + 1) & 0xFFFFFFFF)                          # 0x40E6AF
    e.d32(0x04, (e.s32(0x04) + e.s32(0x24)) & 0xFFFFFFFF)      # 0x40E6B8
    e.d32(0x08, (e.s32(0x08) + e.s32(0x28)) & 0xFFFFFFFF)      # 0x40E6B0
    if e.node is not None:
        e.node.dst = (e.s32(0x04) - 0x18, e.s32(0x08) - 0x18)
    return True

    def p4_child_alive(self, ptr: int) -> bool:
        """`[[+0x1C]+0x34]`：子实体存活标志。"""
        for q in (self.p4_q43c, self._p4_q("ui49c")):
            for x in q:
                if x.g32(0x34):
                    return True
        return False


def _beh_23000009(self, e) -> bool:
    """`0x401181` → `0x40EAF0`：正弦航迹 + 周期射击。

    ```
    0x40EAF3  if (++[+0x20] == 0) { if ([+0x1C] > 0) 0x43B070(ent,0) }     ; 计数归零打一发
    0x40EB0C  else if ([+0x20] == 0x30) {
                  [+0x20] = 0xFFFFFFD1                                     ; -0x2F
                  [+0x1C] = ([+0x1C] == -6) ? 4 : -6                       ; 0x40EB1B..0x40EB27
              }
    0x40EB2A  [+0x24] += [+0x20]                                            ; 相位
    0x40EB3D  y = ([+0x24] >> 3) + 0x1C8                                     ; 航迹高度
    0x40EB45  x += [+0x1C]
    0x40EB4D  dst = (x-0x18, y-0x18)
    0x40EB69  存活 = x > -0x18 && [+0x18] != 0
    ```
    """
    n = (e.s32(0x20) + 1) & 0xFFFFFFFF
    e.d32(0x20, n)
    if n == 0:
        if e.s32(0x1C) > 0:
            self.p4_43B070(e, 0)                     # 0x40EB03
    elif e.s32(0x20) == 0x30:                        # 0x40EB0C
        e.d32(0x20, 0xFFFFFFD1)                      # -0x2F
        e.d32(0x1C, 4 if e.s32(0x1C) == -6 else -6)  # 0x40EB1B..0x40EB27
    e.d32(0x24, (e.s32(0x24) + e.s32(0x20)) & 0xFFFFFFFF)
    y = (e.s32(0x24) >> 3) + 0x1C8                   # 0x40EB3D
    e.d32(0x08, y)
    x = (e.s32(0x04) + e.s32(0x1C)) & 0xFFFFFFFF     # 0x40EB45
    e.d32(0x04, x)
    if e.node is not None:
        e.node.dst = (e.s32(0x04) - 0x18, y - 0x18)
    return e.s32(0x04) > -0x18 and e.g32(0x18) != 0  # 0x40EB69


def p4_446540(self, e) -> None:
    """`0x446540`：出场初始化 —— 生成"头像"实体 `0x1000001` 入 `0x4AD40C`，并记到 `[+0x24]`。

    ```
    0x446548 0x4023C4(&rec, 0, 0, 0x1000001, ebx)   ; (x=0, y=0, type, 控制器指针)
    0x446580 0x4016E5(0x4AD40C, &rec) → eax         ; 入队并返回新实体
    0x446594 [ebx+0x24] = eax                       ; 记住子实体（供后续驱动）
    0x446597 第二发：记录 +0x18 = 5                  ; 子实体参数
    ```
    """
    q = self._p4_q("ui40c")
    c1 = self.spawn(q, 0x1000001, 0, 0)               # 0x446548
    if c1 is not None:
        e.d32(0x24, id(c1) & 0xFFFFFFFF)              # 0x446594
    c2 = self.spawn(q, 0x1000001, 0, 0)               # 0x44658A 第二发
    if c2 is not None:
        c2.d32(0x18, 5)                               # 0x446597 参数 5


def p4_446470(self, e, a: int, b: int) -> None:
    """`0x446470(e, bl, dl)`：头像帧号选择 + 方向位维护（`ret 8`）。

    ```
    0x446475 0x40208B(0x4AB5B0, 0x2) ; neg al; sbb eax,eax; and eax,8; add eax,7
             ⇒ base = 7（位2 未置，操作器 A）或 0xF（已置，操作器 B）
    0x446497 0x4019C9(0x4AB5B0, 0xC000) → mode ; 0x4464A4 mode <<= 1
    0x4464A8 ecx = (bl != 0) ? 1 : 0
    0x4464AF dl = [e+0x1C] & 1                       ; 方向位
    0x4464B2 if (dl != 0) { ecx += mode*2 + base ; 0x4019B0(0x4AB454, ecx, e.x, e.y, dir) }
    0x4464D1 else        { ecx += mode*2 + base ; 0x40115E(0x4AB454, ecx, dir) }
    0x4464E4 if (bl) [e+0x1C] |= 2 else [e+0x1C] &= 1
    ```
    """
    base = 0xF if self.keys.test(2) else 7            # 0x446481
    mode = getattr(self, "p4_mode", 0) & 3            # 0x45AFC0(0x4AB5B0,0xC000)
    fid = base + mode * 2 + (1 if a else 0)           # 0x4464A8/0x4464B7/0x4464C1
    d = e.g32(0x1C) & 1                               # 0x4464AF
    if b:
        p4_446470_play(self, fid, e, d)                # 0x4019B0(0x4AB454, fid, x, y, dir)
    else:
        p4_446470_play(self, fid, e, d)                # 0x40115E(0x4AB454, fid, dir)
    if a:                                             # 0x4464E7
        e.d32(0x1C, e.g32(0x1C) | 2)
    else:
        e.d32(0x1C, e.g32(0x1C) & 1)


def p4_446470_play(self, fid: int, e, d: int) -> None:
    """`0x4019B0 → 0x44E620` / `0x40115E → 0x44E4A0`：**切换输入配置**（非头像帧）。

    ```
    0x44E4AB eax = fid*7 ; 0x44E4B7 表 = 0x498A88 + fid*14
    0x44E4BE 复制 14 字节到 [mgr+0x4C]      ; 覆盖 +0x4C 摇杆启用 / +0x4E 标志 / +0x50 灵敏度
    0x44E620 另写 [mgr+0x14] = x、[mgr+0x18] = y   ; 指针坐标
    ```
    """
    self.p4_stat[0x446470] = self.p4_stat.get(0x446470, 0) + 1
    self.p4_avatar_fid = fid
    rec = p4_avatar_rect(self, fid)                    # 0x4C 帧记录（图集现算）
    if rec is not None:
        self.p4_avatar_rec = rec


_P4TAB = {}


def p4_hud_unpack(v: int) -> dict:
    """`0x45DFB0`：把 `0x4993C4` / 按 kind 表里的 dword 拆成 10 字节结构。

    ```
    0x45DFB8 [out+0] = v & 0x1F                       ; 尾数（0..31）
    0x45DFC1 n = (v >> 5) & 7                         ; 十进制指数（0..7）
    0x45DFCC 循环 n 次： [out+0] *= 10                 ; ⇒ 值 = 尾数 * 10^n
    0x45DFD9 [out+4] = (v >> 8) & 0xF
    0x45DFE6 [out+5] = (v >> 12) & 0xF
    0x45DFF2 word[out+6] = v >> 16
    ```

    所以这些表项是**打包的十进制参数**（值 = 尾数 × 10^指数），不是字符/文本。
    早前"低位是字符码 'A'/'B'/'F'"的读法是错的 —— `v & 0xFF` 把 5 位尾数 + 3 位指数
    混在一起，恰好拼出可打印字符，纯属巧合。
    """
    mant = v & 0x1F
    exp = (v >> 5) & 7
    val = mant
    for _ in range(exp):
        val *= 10
    return {
        "value": val,          # [out+0] 尾数 * 10^指数
        "mant": mant,
        "exp": exp,
        "b4": (v >> 8) & 0xF,  # [out+4]
        "b5": (v >> 12) & 0xF,  # [out+5]
        "w6": (v >> 16) & 0xFFFF,  # word[out+6]
    }


def p4_hud_accum(self, h, desc: dict, f2: int = 0, f3: int = 0) -> None:
    """`0x45E670(h, desc, f2, f3)`：把描述字的 `value` 累加进 HUD 的布局累计量。

    ```
    0x45E670 al = byte[desc+0]  ; 即 value 的低字节
    0x45E67C dl = 1
    0x45E67E if (al != 0) {                                  ; value 非 0 才累加
    0x45E680   if (!(desc->b4 & 1)) [h+0x20] += desc->value
    0x45E68F   if (!(desc->b4 & 2)) [h+0x10] += desc->value
             }
    0x45E69F if (f2 != 0) { 同两位门控 → [h+0x18] / [h+8] }
    0x45E6C5 if (f3 != 0) { 同两位门控 → [h+0x1C] / [h+0xC] }
    ```

    即三对累加器（`+0x20/+0x10`、`+0x18/+8`、`+0x1C/+0xC`），
    第一对只受 `value != 0` 控制，后两对还要各自开关；
    `desc->b4` 的 bit0/bit1 决定**跳过哪个累加器**（`test byte[desc+4],1/2`）。
    """
    v = int(desc.get("value", 0)) & 0xFFFFFFFF
    b4 = desc.get("b4", 0)
    if v & 0xFF:                                   # 0x45E675 / 0x45E67E
        if not (b4 & 1):                           # 0x45E680
            h.d32(0x20, (h.g32(0x20) + v) & 0xFFFFFFFF)
        if not (b4 & 2):                           # 0x45E68F
            h.d32(0x10, (h.g32(0x10) + v) & 0xFFFFFFFF)
    if f2:                                         # 0x45E69F
        if not (b4 & 1):
            h.d32(0x18, (h.g32(0x18) + v) & 0xFFFFFFFF)
        if not (b4 & 2):
            h.d32(0x08, (h.g32(0x08) + v) & 0xFFFFFFFF)
    if f3:                                         # 0x45E6C5
        if not (b4 & 1):
            h.d32(0x1C, (h.g32(0x1C) + v) & 0xFFFFFFFF)
        if not (b4 & 2):
            h.d32(0x0C, (h.g32(0x0C) + v) & 0xFFFFFFFF)


def p4_hud_keys(self):
    """`0x4993C4` 全局键表（256 个 dword，`build_p4_hudkeys.py` 导出）。

    每项经 `0x45DFB0`（`p4_hud_unpack`）拆成「尾数×10^指数 + 两个 4 位字段 + 一个 16 位字段」，
    是**打包的十进制参数表**，不是文本/字形表。
    """
    tab = getattr(self, "_p4_hudkeys", None)
    if tab is None:
        try:
            import json
            import pathlib
            f = pathlib.Path(__file__).resolve().parent.parent / "p4_hudkeys.json"
            tab = json.loads(f.read_text(encoding="utf-8"))["keys"]
            self._p4_hudkeys = tab
        except Exception:
            return None
    return tab


def p4_hud_get(self, key: int):
    """`0x45EF50`：HUD 键 → 描述字（None 表示该键不产出值）。

    ```
    0x45EF56  ecx = [h+0xEC]                     ; 按 kind 的表
    0x45EF5C  if (ecx == 0) → 直接返回
    0x45EF64  if (key == 0x28000015) → 直接返回   ; 该键被显式排除
    0x45EF6D  if ((key & 0xFF000000) == 0x21000000)
    0x45EF84      val = dword[0x4993C4 + (key & 0xFF)*4]   ; 全局表
    0x45EF94  else val = dword[ecx + (key & 0xFF)*4]        ; 按 kind 表
    0x45EF9D  0x4020D6→0x45DFB0(&out, val)                  ; 转换（待解）
    0x45EFA9  if (key & 4) → 跳过写回
    0x45EFBA  0x401451→0x45E670(h, &out, 1, 0, 0)           ; 写回（待解）
    ```

    本函数做「选表 + 取第 `key & 0xFF` 项 + 0x45DFB0 拆包」，返回 `p4_hud_unpack` 的字典。
    0x45EFBA 的写回（`0x45E670`，及 `key & 4` 时跳过）尚未解，故不执行。
    """
    h = getattr(self, "p4_hud", None)
    if h is None:
        return None
    if h.g32(0xEC) == 0 or key == 0x28000015:   # 0x45EF5C / 0x45EF64
        return None
    idx = key & 0xFF
    if (key & 0xFF000000) == 0x21000000:        # 0x45EF73
        tab = p4_hud_keys(self)
        raw = None if tab is None else tab[idx]
    else:                                        # 0x45EF94
        vals = getattr(self, "_p4_hud_kindvals", None)
        raw = None if not vals else vals[idx]
    if raw is None:
        return None
    desc = p4_hud_unpack(raw)                    # 0x45EF9D → 0x45DFB0
    if not (key & 4):                            # 0x45EFA9：key&4 时跳过写回
        p4_hud_accum(self, h, desc, 0, 0)        # 0x45EFBA → 0x45E670(h, desc, 0, 0)
    return desc


def p4_tables():
    """按 `0x45A7E7`/`0x45A82E`/`0x45A863` 的填表代码生成的定点表（`build_p4_tables.py`）。"""
    if not _P4TAB:
        try:
            import pathlib
            import numpy as np
            f = pathlib.Path(__file__).resolve().parent.parent / "p4_tables.npz"
            z = np.load(f)
            _P4TAB["sin"] = z["sin900"]
            _P4TAB["cos"] = z["cos900"]
            _P4TAB["isqrt"] = z["isqrt65536"]
            _P4TAB["atan"] = z["atan256"]
        except Exception:
            return None
    return _P4TAB


def p4_isqrt(v: int) -> int:
    """`0x5B3AB4` 表：`trunc(4096/sqrt(i))`，i 由 1 起（`0x45A82E` 段）。"""
    t = p4_tables()
    if t is None or v <= 0:
        return 0
    i = min(int(v), 65535)
    return int(t["isqrt"][65535 - i])      # 表按 i 递减存放：i=0xFFFF → 首项


def p4_atan2(a: int, b: int) -> int:
    """`0x5D3E36` 表：`trunc(atan2(a,b)*3600/(2*3.1416))`，单位 0.1°。"""
    t = p4_tables()
    if t is None:
        return 0
    return int(t["atan"][a & 0xFF, b & 0xFF])


_P4_BG_TIER = (0, 6, 0x0A, 0x10, 0x18, 0x20, 0x30, 0x48, 0x6C, 0xA0, 0xF0, 0)

# `0x457938` 的 256 字节一级表（`build_p4_kindmap.py` 导出到 p4_kindmap.json）。
# 只有上表 _P4_BG_TIER 的 11 个值有专属分支，其余一律 0xB（无操作）。
_P4_KIND_LAYER = {0: None, 6: 3, 10: 4, 16: 5, 24: 6, 32: 7,
                  48: 8, 72: 9, 108: 0xA, 160: 0xB, 240: 0xC}


def p4_bg_kind_layer(kind: int):
    """`0x4577DF`：`kind` → (渲染层号 | None)。

    一级表 `0x457938[kind]` 给出分支号，二级表 `0x457908` 跳到分支体；
    各分支体做的都是 `[[band+0x2C]] = N`：

    ```
    kind   0 → 分支 0  (0x4577EC)：把渲染对象可见位清 0（隐藏）
    kind   6 → 分支 1  (0x4577F5)：层 3
    kind  10 → 分支 2  (0x457800)：层 4
    kind  16 → 分支 3  (0x45780B)：层 5
    kind  24 → 分支 4  (0x457816)：层 6
    kind  32 → 分支 5  (0x457821)：层 7
    kind  48 → 分支 6  (0x45782C)：层 8
    kind  72 → 分支 7  (0x457837)：层 9
    kind 108 → 分支 8  (0x457842)：层 0xA
    kind 160 → 分支 9  (0x45784D)：层 0xB
    kind 240 → 分支 10 (0x457858)：层 0xC
    其它     → 分支 11 (0x457861)：无操作（直接进尾部）
    ```

    层号 = `3 + 档位`，档位就是 `_P4_BG_TIER` 的序号（1 起）。
    198 个未列出的 kind 值在表里都是 0xB，故返回 `None` 表示"不改层"。
    """
    return _P4_KIND_LAYER.get(int(kind) & 0xFF, None)



def p4_bg_kind_ladder(grid, count: int, ratio: int, acc: int) -> int:
    """`0x457050`：按累积量给每条分配「层级/带型」（写第 3 个 dword），返回新累积量。

    ```
    0x457053 edi(N) = [this+0x58]；0x457057 esi(acc) = [this+0x38]
    0x45705D 12 字节常量表：[0,6,0xA,0x10,0x18,0x20,0x30,0x48,0x6C,0xA0,0xF0,0]
    0x45709E ebp = this+0xD8                     ; grid[k] 的第 3 个 dword
    0x4570A4 loop: edx = 1 ; al = 6
        0x4570B3 while (acc >= (al<<6)):
        0x4570B7     al = 表[edx+5] ; edx++ ; if (al == 0) break
    0x4570C5 grid[k].kind = 表[edx+3]
    0x4570CC acc += ([this+0x44] * acc) >> 6     ; 几何增长
    ```

    阈值阶梯 6,10,16,24,32,48,72,108,160,240（单位 = 值<<6）；层级值取自同表 `edx+3`。
    """
    n = min(int(count), len(grid))
    if n <= 0:
        return acc
    tab = _P4_BG_TIER
    acc = int(acc)
    for k in range(n):
        edx = 1                                        # 0x4570A4
        al = 6                                         # 0x4570A9
        while acc >= (al << 6):                        # 0x4570B3
            idx = edx + 5
            al = tab[idx] if idx < len(tab) else 0     # 0x4570B7
            edx += 1                                   # 0x4570BB
            if al == 0:                                # 0x4570BC
                break
        kidx = edx + 3
        grid[k][2] = tab[kidx] if kidx < len(tab) else 0   # 0x4570C5
        acc += (int(ratio) * acc) >> 6                 # 0x4570CC
    return acc


def p4_bg_strip_axis(slot, axis: int, count: int, step0: int, ratio: int) -> None:
    """`0x456FB0`（x）/ `0x457000`（y）：递增间距的带状排布。

    ```
    0x456FB0  edx = [this+0x30]      ; y 版 0x457000 读 [+0x34]
    0x456FB3  eax = [this+0x3C]      ; y 版读 [+0x40]  ← 首段间距
    0x456FB8  edi = [this+0x58]      ; 条数 N
    0x456FBD  if (N <= 0) return
    0x456FC2  edi = this+0xD0        ; y 版 +0xD4
    0x456FC8  loop:
                ebx = edx
                edx += eax                     ; 位置前进 step
                [edi] = sar ebx,6              ; 存的是**前进之前**的 edx>>6
                ebx = eax * [this+0x48]        ; y 版 [+0x4C] ← 间距增长率
                eax += sar ebx,6               ; step += (step*ratio)>>6（几何增长）
                ebx = [this+0x58]; i++; edi += 0xC
    ```

    ⇒ 每格间距按 `1 + ratio/64` 递增（等比排布），第 k 格位置为累积和。
    """
    n = min(int(count), len(slot.grid))
    if n <= 0:
        return
    pos = int(slot.params[axis])                  # 0x456FB0/0x457000 的 edx
    step = int(step0)                             # 0x3C / 0x40
    ratio = int(ratio)                            # 0x48 / 0x4C
    for k in range(n):
        slot.grid[k][axis] = pos >> 6             # 存前进之前的值（sar 6）
        pos += step                               # 0x456FCA
        step += (step * ratio) >> 6               # 0x456FD3/0x456FD7


def p4_bg_place_axis(slot, axis: int, count: int) -> None:
    """`0x456F30`（x 轴，`+0x30`→`+0xD0`）/ `0x456F70`（y 轴，`+0x34`→`+0xD4`）。

    ```
    0x456F30  edx = [this+0x30]        ; (y 版 0x456F70 读 +0x34)
    0x456F33  eax = this+0xD0          ; (y 版 +0xD4)
    0x456F3B  esi = [eax]              ; 第 0 条的当前值
    0x456F3D  edi = [this+0x58]        ; 条数 N
    0x456F40  edx = sar edx,6          ; 基准 = 参数 >> 6
    0x456F43  edx -= esi               ; delta = 基准 - 第0条的当前值
    0x456F47  if (N <= 0) return
    0x456F4B  loop: edi=[eax]; eax+=0xC; edi+=edx; i++; [eax-0xC]=edi
    0x456F56         edi = [this+0x58]（每轮重读）; if (i < edi) 继续
    ```

    含义：把 `N` 条记录（**步长 0xC = 3 dword**）在某一轴上整体平移，
    使第 0 条正好落在 `参数 >> 6`。x 版写每条的第 1 个 dword、y 版写第 2 个
    ⇒ 记录布局 = `{x, y, kind}`（与 `BgSlot.grid` 注释一致）。
    `sar` 是算术右移，Python 的 `>>` 对负数同义。
    """
    n = min(int(count), len(slot.grid))
    if n <= 0:
        return
    base = int(slot.params[axis]) >> 6            # 0x456F40
    delta = base - int(slot.grid[0][axis])        # 0x456F43
    for k in range(n):                            # 0x456F4B..0x456F5B
        slot.grid[k][axis] = int(slot.grid[k][axis]) + delta


def p4_queue_sweep(self, head, unlink=None, clear_active=True):
    """`0x430220` / `0x4353A0` 等 6 个队列扫描函数的**统一骨架**。

    反汇编里 6 处扫描（0x430220、0x4353A0、0x448F80、0x43BC70、0x44B0D0、0x445A30）
    结构完全相同，只有「行为分发 thunk」与「摘链助手」不同：

    ```
    0x430228 esi = [this+0x28]                     ; 头节点
    0x430231 cmp byte[esi+0x34], 0 ; je 摘链        ; 未存活 → 直接摘
    0x430236 call <dispatch>                        ; 全部是 `jmp [ecx+0x40]`,
                                                    ;   落点 0x42E440/0x432120/0x446450/
                                                    ;        0x43AD40/0x449EF0/0x43DC90
    0x43023D test al,al ; jne 保留                  ; 行为返回非 0 ⇒ 存活
    0x430241 eax = [esi+0x38]                       ; 所属实体
    0x430244 byte[esi+0x34] = 0                     ; 清存活
    0x430247 byte[esi+0x10] = 0                     ; 清激活
    0x43024A byte[eax+0x1C] = 0                     ; 清实体占用位
    0x43024F esi = [esi+0x44]                       ; next
    0x430254 call <unlink>(prev, node)              ; 0x430370/0x401627/0x4490C0/
                                                    ;   0x43BED0/0x44B210/0x445B70/0x435550
    ```

    参数 `head` 用鸭子协议：`alive`(+0x34)、`active`(+0x10)、`owner`(+0x38)、
    `behaviour`(+0x40)、`next`(+0x44)。复刻侧的实体列表模型与此等价，
    本函数用于逐条对齐验证与将来切换成节点池。
    """
    prev = None
    node = head
    while node is not None:
        nxt = getattr(node, "next", None)
        if not getattr(node, "alive", 0):          # 0x430231
            if unlink is not None:
                nxt = unlink(prev, node)           # 0x430254
            else:
                nxt = getattr(node, "next", None)
            node = nxt
            continue
        if getattr(node, "behaviour", None) and not node.behaviour():   # 0x430236/0x43023D
            owner = getattr(node, "owner", None)                        # 0x430241
            node.alive = 0                                             # 0x430244
            if clear_active:
                # 只有 0x430220/0x4353A0/0x448F80/0x43BC70 会清 +0x10；
                # 0x44B0D0/0x445A30/0x43A350 不清（见 §16.152 的两族差异）。
                node.active = 0                                        # 0x430247
            if owner is not None:
                owner.busy = 0                                         # 0x43024A
        prev = node                                                    # 0x43024D
        node = getattr(node, "next", None)                             # 0x43024F


def p4_angle(a: int, b: int) -> int:
    """`0x401091 → 0x45A9A0`：**atan2，单位 0.1°，整圈 = 3600**。

    ```
    0x45A9A9  if (b == 0 && a == 0) return 0
    0x45A9B5  归一化：while (|b| >= 0x100 || |a| >= 0x100) { b >>= 1; a >>= 1 }
    0x45A9D7  四象限查表（表 0x5B3E38，word，index = (a<<8) + b）
                b>=0, a>=0 → v                     ; 第一象限
                b>=0, a<0  → 0xE10(3600) - v       ; 第二象限
                b<0,  a>=0 → 0x708(1800) - v       ; 第三象限
                b<0,  a<0  → 0x708(1800) + v       ; 第四象限（负索引镜像寻址）
    ```

    表内容由 `0x45A863` 段生成、`fpatan` 栈序给出 `atan2(外层 i, 内层 j)`，
    配合 `index = (a<<8)+b` ⇒ **表值 = atan2(a, b)**（第一参数在前）。
    """
    if a == 0 and b == 0:
        return 0
    while abs(b) >= 0x100 or abs(a) >= 0x100:
        if a == 0 and b == 0:
            return 0
        b >>= 1
        a >>= 1
    t = p4_tables()
    if t is None:
        return 0
    # 四个象限都用**绝对值**做索引（第二象限 `sub esi,ecx`、第三象限
    # `sub ecx,esi`、第四象限负索引镜像，等价于取模），符号只由下面的
    # 3600-v / 1800-v / 1800+v 三个修正式体现。
    v = int(t["atan"][abs(a) & 0xFF, abs(b) & 0xFF])   # 表值 = atan2(|a|, |b|)
    if b >= 0:
        return v if a >= 0 else 0xE10 - v      # 第一/第二象限
    return 0x708 - v if a >= 0 else 0x708 + v  # 第三/第四象限


def p4_sin_q(arg: int, which: str = "sin") -> int:
    """`0x45ABB0`（cos 表）/`0x45AAF0`（sin 表）：`|arg|%3600` 归一 + 象限重组。

    四个分支（`0x45ABEA`/`0x45ABF4`/`0x45AC03`/`0x45AC0F` 与
    `0x45AB2D`/`0x45AB37`/`0x45AB44`/`0x45AB50`）的取值方式：

    ```
    idx = (|arg| / 900) & 3 ; rem = |arg| % 900
    idx0 (0x45AB2D): al = +byte[基址 + rem]      ; 正向
    idx1 (0x45AB37): al = +byte[中心 - rem]      ; 镜像
    idx2 (0x45AB44): al = -byte[基址 + rem]      ; 负正向
    idx3 (0x45AB50): al = -byte[中心 - rem]      ; 负镜像
    ```

    其中 `中心 = 基址 + 899`（`0x5D41BF = 0x5D3E3C+899`、`0x5B3E37 = 0x5B3AB4+899`）。
    公共尾部 `0x45AB63`：`test edi,edi` → 原参数为负时 `neg eax`（额外一次符号翻转）。
    表里中心项对应角度 0、负半区以补码字节存放。

    **注意**：本函数只复现"取哪个字节、是否取负"这两件事，返回值就是
    `mov al, byte[...]` 得到的 0..255 或 `neg eax` 后的 -0..-255。
    **角色已由调用点定案**：`0x45AC70` 是二维向量旋转/缩放，它把
    `0x45ABB0(angle)` 的结果当**余弦分量**写回 x、把 `0x45AAF0(angle)` 当**正弦分量**写回 y，
    并做四舍五入定点乘 `(v*scale + 0x80) >> 8`。

    **两张表各 900 项、都是纯第一象限**（`0x45A7E5 xor esi,esi`；`dec esi`；
    `(esi+0x383) >= 0` ⇒ 900 次）：`表[k] = trunc(trig(k*0.1°)*255)`，k=0..899。
    - `0x45AAF0` 读基址 **`0x5B3AB4`**（镜像 `0x5B3E37`）= **sin 表** ⇒ `which="sin"`
    - `0x45ABB0` 读基址 **`0x5D3E3C`**（镜像 `0x5D41BF`）= **cos 表** ⇒ `which="cos"`

    两者对 3600 个整周步逐点验证：`cos` 槽 vs `round(255*cos(a*0.1°))`、
    `sin` 槽 vs `round(255*sin(a*0.1°))` 全部超差 ≤1。

    **返回的是补码字节（0..255）**：表按 `mov byte[..], al` 只存低字节，`-180` 存成 `0x4C=76`，
    故 `arg=450` 返回 76 而不是 180 —— 这**不是**映射错误，是原件的行为（调用方需自行带符号解释）。
    另：表的原点比调用者晚 90°（`rem=0` 对应 -89.9°、`rem=899` 对应 0°），
    与角度的对齐取决于 `0x401091` 的返回值口径（是否含 +900），该项待查。
    """
    t = p4_tables()
    if t is None:
        return 0
    a = abs(int(arg))
    idx = (a // 900) & 3
    rem = a % 900
    tab = t["cos"] if which == "cos" else t["sin"]
    # 两个函数各自的跳表顺序不同（cos 在 0x45AC24、sin 在 0x45AB6C）：
    #   cos: [+base+rem, -镜像, -base+rem, +镜像]
    #   sin: [+base+rem, +镜像, -base+rem, -镜像]
    if which == "cos":
        neg = (1, -1, -1, 1)
    else:
        neg = (1, 1, -1, -1)
    mirror = (0, 1, 0, 1)
    if mirror[idx]:
        v = neg[idx] * int(tab[899 - rem])
    else:
        v = neg[idx] * int(tab[rem])
    if arg < 0:                                # 0x45AB63 test edi,edi / 0x45AB69 neg eax
        v = -v
    return v


class P4Replay:
    """回放三数组（`0x4CD5D8` 对象内 +0x30 / +0x34BF0 / +0x697B0）。

    `0x45CEA0` 打包（`ret 8`，this=arg1, rec=arg2）：

    ```
    bits = ((byte[rec+9]&1) << 1) | (byte[rec+8]&1)    ; 2 个按键位
    bits = (bits << 10) | (dword[rec+4] & 0x3FF)       ; dy 10 bit
    bits = (bits << 11) | (dword[rec+0] & 0x7FF)       ; dx 11 bit ⇒ 23 bit
    byte[this+pos+0x30]    = bits
    byte[this+pos+0x34BF0] = bits >> 8
    byte[this+pos+0x697B0] = bits >> 16
    ```

    `0x45CF20` 解包：`bits = b0 | b1<<8 | b2<<16`，然后
    `dx = bits & 0x7FF`（bit10 为符号，`+0xFFFFF800` 补）、
    `dy = (bits>>11) & 0x3FF`（bit9 为符号，`+0xFFFFFC00` 补）、
    按键在 bit21/22（`shr 0x15`/`shr 0x16` 后 `and al,1`）。
    """

    CAP = 0x34BC0            # 0x34BF0-0x30 ⇒ 数组长度

    def __init__(self) -> None:
        self.a = bytearray(self.CAP)
        self.b = bytearray(self.CAP)
        self.c = bytearray(self.CAP)
        self.pos = 0             # [this+0x9E37C]
        self.flag = 0            # [this+0x9E378]
        self.count = 0           # [this+0x9E380]

    def record(self, frame: bytearray) -> None:
        """`0x45D1D0(this, frame)`：把一帧写进三数组并把该帧缓存到 `[this+0x9E370]`。

        帧结构（由 `0x45D1D0` 的读取点定案，无歧义）：

        ```
        0x45D1DB 暂存 dword[frame+0x10] → 临时记录 +0（dx）
        0x45D1DE 暂存 dword[frame+0x14] → 临时记录 +4（dy）
        0x45D1E5 暂存 byte [frame+0]    → 临时记录 +8（btn0）
        0x45D1EB 暂存 byte [frame+1]    → 临时记录 +9（btn1）
        0x45D204 0x401893 → 0x45CEA0(this, pos, 临时记录)   ; 打包
        0x45D21D 临时记录（14 字节）复制到 [this+0x9E370..]  ; 末帧缓存
        0x45D217 count = [this+0x9E380]
        ```
        """
        tmp = bytearray(16)
        tmp[0:4] = bytes(frame[0x10:0x14])
        tmp[4:8] = bytes(frame[0x14:0x18])
        tmp[8] = frame[0]
        tmp[9] = frame[1]
        self.pack(tmp)
        self.last = tmp                              # [this+0x9E370]
        self.count += 1                              # [this+0x9E380]

    def play(self, frame: bytearray) -> None:
        """`0x45D2B0(this, frame)`：从三数组解出一帧填入 frame。

        ```
        0x45D2C7 0x401104 → 0x45CF20(this, pos, 临时记录)   ; 解包
        0x45D2DC [frame+0x10] = 临时记录 +0（dx）
        0x45D2DF [frame+0x14] = 临时记录 +4（dy）
        0x45D2E2 byte[frame] = 临时记录 +8（btn0）
        0x45D2E4 byte[frame+1] = 临时记录 +9（btn1）
        0x45D2E7 byte[frame+2] = ([this+0x9E378] == 0) & btn0
        ```
        """
        tmp = bytearray(16)
        self.unpack(tmp)
        frame[0x10:0x14] = tmp[0:4]
        frame[0x14:0x18] = tmp[4:8]
        frame[0] = tmp[8]
        frame[1] = tmp[9]
        frame[2] = ((1 if self.flag == 0 else 0) & tmp[8]) & 0xFF

    def pack(self, rec: bytearray) -> None:      # 0x45CEA0，rec 为 ≥10 字节记录
        bits = (((rec[9] & 1) << 1) | (rec[8] & 1))
        bits = (bits << 10) | (int.from_bytes(rec[4:8], "little") & 0x3FF)
        bits = (bits << 11) | (int.from_bytes(rec[0:4], "little") & 0x7FF)
        i = self.pos
        self.a[i] = bits & 0xFF
        self.b[i] = (bits >> 8) & 0xFF
        self.c[i] = (bits >> 16) & 0xFF

    def unpack(self, out: bytearray) -> None:    # 0x45CF20，out 为 ≥10 字节记录
        i = self.pos
        bits = self.a[i] | (self.b[i] << 8) | (self.c[i] << 16)
        dx = bits & 0x7FF
        if dx & 0x400:
            dx -= 0x800
        dy = (bits >> 11) & 0x3FF
        if dy & 0x200:
            dy -= 0x400
        out[0:4] = (dx & 0xFFFFFFFF).to_bytes(4, "little")
        out[4:8] = (dy & 0xFFFFFFFF).to_bytes(4, "little")
        out[8] = (bits >> 21) & 1
        out[9] = (bits >> 22) & 1


def p4_input_cfg(self, fid: int):
    """`0x498A88 + fid*14` → 输入配置（`build_p4_avatar.py` 导出 `configs`）。

    字段按 `0x44E660` Poll 的消费点命名：
    `+0x4C` = 摇杆启用字节（`0x44E8B5`，为 0 则整段摇杆处理跳过）、
    `+0x4E` = 标志字节（`0x44E917`）、`+0x50` = 灵敏度 word（`0x44E91C`，按 ±0x3E8 归一）。
    """
    cfg = getattr(self, "p4_input_cfgs", None)
    if cfg is None:
        try:
            import json
            import pathlib
            f = pathlib.Path(__file__).resolve().parent.parent / "p4_avatar.json"
            cfg = json.loads(f.read_text(encoding="utf-8"))["configs"]
            self.p4_input_cfgs = cfg
        except Exception:
            return None
    return cfg.get(str(fid))


def p4_avatar_rect(self, fid: int):
    """`0x498A88 + fid*14`：**输入配置表**（不是 sprite 帧表）。

    `0x44E4A0` 把整项 14 字节复制到输入管理器 `0x4AB454` 的 `+0x4C` 起，而 Poll（`0x44E660`）
    随后这么用它：

    ```
    0x44E8B5 al = byte [mgr+0x4C] ; 0x44E8BA if (al == 0) 跳过整个摇杆处理
    0x44E917 bl = byte [mgr+0x4E]
    0x44E91C ecx = movsx word [mgr+0x50]        ; 速度/灵敏度
    0x44E932 sar ebx,1 ; add ecx,ebx            ; 按该值放大轴量
    ```

    ⇒ `+0x4C` = 摇杆启用字节、`+0x4E` = 附加标志、`+0x50` = 灵敏度 word；
    14 字节 = 7 个 u16 的**输入配置预设**。名字沿用历史命名，语义以此为准。
    """
    tab = getattr(self, "p4_avatar_table", None)
    if tab is None:
        try:
            import json
            import pathlib
            f = pathlib.Path(__file__).resolve().parent.parent / "p4_avatar.json"
            tab = json.loads(f.read_text(encoding="utf-8"))["frames"]
            self.p4_avatar_table = tab
        except Exception:
            return None
    v = tab.get(str(fid))
    return tuple(v) if v else None


def p4_446600(self, e) -> bool:
    """`0x40212B` → `0x446600`：定时出场/闪烁门。返回 False = 本帧不继续。

    ```
    0x446606 if ([+0x20] <= 0x12C) {
    0x446613     == -1  → 0x446540(e); [+0x10]=1; [+0x20]=0x12D; node[+0x1C]=1
    0x44662C     == 0x28 → if (0x44D490(0x4CD590) == 0) return 0
    0x446644     == 0x78 → 0x446540(e); [+0x10]=1
    0x446658     == 0x12C → node[+0x1C]=1; [0x56CCB2]=0
    0x44666E     > 0x78  → node[+0x1C] = [+0x20] & 1        ; 闪烁
              }
    0x44667E [+0x20]++; 0x446681 ++[+0x2C]; if ([+0x30]) --[+0x30]
    ```
    """
    t = e.s32(0x20)
    if t <= 0x12C:
        if t == -1:
            p4_446540(self, e)
            e.d32(0x10, 1)
            e.d32(0x20, 0x12D)
            if e.node is not None:
                e.node.visible = 1
        elif t == 0x28:
            if not bool(getattr(self, "_p4_busy", 1)):
                return False
        elif t == 0x78:
            p4_446540(self, e)
            e.d32(0x10, 1)
        elif t == 0x12C:
            if e.node is not None:
                e.node.visible = 1
            self.p4_ccc2 = 0
        elif t > 0x78 and e.node is not None:
            e.node.visible = t & 1
    e.d32(0x20, (t + 1) & 0xFFFFFFFF)
    e.d32(0x2C, (e.s32(0x2C) + 1) & 0xFFFFFFFF)
    if e.g32(0x30):
        e.d32(0x30, (e.s32(0x30) - 1) & 0xFFFFFFFF)
    return True


def p4_45A690(x: int, y: int):
    """`0x401753 → 0x45A690`：**恒等**（`eax = arg1; edx = arg2; ret`），不是坐标变换。"""
    return x, y


def _beh_type1_follow_b(self, e) -> bool:
    """`0x4467D0`（type 1 行为 B）：无条件跟随 + 把显示节点摆到左上偏移 (-0x18,-0x18)。

    ```
    0x4467D3 if (!0x446600(e)) return
    0x4467DE dx = [0x4AB59C] - x ; dy = [0x4AB5A0] - y     ; 无 [0x4AB595] 分支
    0x4467F3 if (dx >= 0) dx += 3 ; dx >>= 2 ; 同 dy
    0x446802 x += dx ; 0x446816 y += dy
    0x446819 0x401753(x, y) → [0x56CC8C] = eax, [0x56CC90] = edx     ; 恒等
    0x44682F 0x401753(x-0x18, y-0x18)
    0x446842 node[+0x38].dst = (x-0x18, y-0x18)                      ; 48x48 居中
    0x44684A return [e+0x18] != 0
    ```
    """
    if not p4_446600(self, e):
        return False
    px, py = self.p4_ptr()                                  # 0x4AB59C / 0x4AB5A0
    dx = px - e.s32(0x04)
    dy = py - e.s32(0x08)
    dx = (dx + 3) >> 2 if dx >= 0 else dx >> 2              # 0x4467F3
    dy = (dy + 3) >> 2 if dy >= 0 else dy >> 2              # 0x446802
    e.d32(0x04, (e.s32(0x04) + dx) & 0xFFFFFFFF)
    e.d32(0x08, (e.s32(0x08) + dy) & 0xFFFFFFFF)
    nx, ny = p4_45A690(e.s32(0x04), e.s32(0x08))            # 0x446819（恒等）
    self.p4_player_pos = (nx, ny)                           # 0x56CC8C / 0x56CC90
    ox, oy = p4_45A690(nx - 0x18, ny - 0x18)                # 0x44682F
    if e.node is not None:
        e.node.dst = (ox, oy)                               # 0x446842
    return e.g32(0x18) != 0                                 # 0x44684A


def _beh_type1_follow(self, e) -> bool:
    """`0x4466F0`（type 1 行为 A）：`b1`/`r1` 两个输入字节决定「跟随」还是「调用 0x446470」。

    ```
    0x4466F3 if (!0x446600(e)) return false
    0x4466FE al = byte[0x4AB595]   ; = rec.b1（按钮1 按住）
    0x446705 al = byte[0x4AB599]   ; = rec.r1（按钮1 释放沿）
    0x44670A b1 != 0 → 0x446747：若 r1 == 0 → 0x446756（不移动），否则 0x44674B
    0x44670C b1 == 0：r1 != 0 → 0x44674B，否则 0x446710（插值）
    0x44674B 0x446470(e, 0, 1)
    ── 0x446710 插值 ──
    0x446710 dx = [0x4AB59C] - [e+4] ; dy = [0x4AB5A0] - [e+8]
    0x446726 if (dx >= 0) dx += 3 ; dx >>= 2（sar）
    0x446732 同 dy
    ── 0x446756 共用尾 ──
    0x446756 0x45A690(x, y) → [0x56CC8C] = eax, [0x56CC90] = edx
    0x44676E 0x45A690(x - 0x18, y - 0x18) → 显示节点 [+0x14]/[+0x18]
    0x44678F return [e+0x18] != 0
    ```
    """
    if not p4_446600(self, e):
        return False
    b1 = bool(getattr(self.inp.rec, "b1", 0))               # 0x4466FE byte[0x4AB595]
    r1 = bool(getattr(self.inp.rec, "r1", 0))               # 0x446705 byte[0x4AB599]
    if b1:
        if r1:                                              # 0x446747 test al,al / jne 落 0x44674B
            p4_446470(self, e, 0, 1)                        # 0x446751
    elif r1:                                                # 0x44670C jne 0x44674B
        p4_446470(self, e, 0, 1)                            # 0x446751
    else:                                                   # 0x446710
        px, py = self.p4_ptr()
        dx = px - e.s32(0x04)
        dy = py - e.s32(0x08)
        dx = (dx + 3) >> 2 if dx >= 0 else dx >> 2          # 0x446726/0x44672D
        dy = (dy + 3) >> 2 if dy >= 0 else dy >> 2          # 0x446732/0x44673C
        e.d32(0x04, (e.s32(0x04) + dx) & 0xFFFFFFFF)
        e.d32(0x08, (e.s32(0x08) + dy) & 0xFFFFFFFF)
    nx, ny = p4_45A690(e.s32(0x04), e.s32(0x08))            # 0x44675E（恒等）
    self.p4_player_pos = (nx, ny)                           # 0x56CC8C / 0x56CC90
    ox, oy = p4_45A690(nx - 0x18, ny - 0x18)                # 0x44677C
    if e.node is not None:
        e.node.dst = (ox, oy)                               # 0x446787
    return e.g32(0x18) != 0                                 # 0x44678F


def _beh_447410(self, e) -> bool:
    """`0x4015FF` → `0x447410`（特殊类；ctor `0x446030` 另置 `[+0x20]=5`）：**四发上限**的 `0x10008431` 发射器。

    ```
    0x447410 al = byte[0x4AB596] ; ebp = ent ; ebx = [ent+0x1C]（子对象）
    0x447422 if (al)      [ent+0x20] = 0
    0x44742D if (byte[0x4AB597]) [ent+0x24] = 0
    0x447439 edx = [ent+0x20] + [ent+0x24]
    0x447445 if (edx >= 4) → 0x447528        ; 合计到 4 就冻结
    0x447448 [ent+0x24]++ ; [ent+0x20]++     ; 两计数器同增
    0x447454 需要 btn0 或 btn1 按下沿，且 [sub+0x28] != 1、byte[sub+0x34] != 0
    0x44747F slot = 0x45AFC0(0x4AB5B0,0xC000)
    0x44748E slot == 3 → 0x44750C
    0x447493 否则：若 [sub+0x28] != 0 → 清零后 0x447521，否则 0x4474A0
    0x4474A0 0x45FAB0(0x4CD4A0) 为假 → 0x447528   ; word[0x4CD4A0+0x26] >= 0xA0
    0x4474AE 造 0x10008431（位置 = sub、第 5 字段 = [ent+0x1C]）入 0x4AD46C
    0x4474F6 [sub+0x28] = 1 ; 0x447503 0x4013A2(0xC, ([sub+4]−0x140)<<4)  ; 声像
    ── 0x44750C ──
    0x44750C 同样先测 0x45FAB0(0x4CD4A0)
    0x44751A [ent+0x28] = 0x3C
    0x447521 [sub+0x20] = 0x79
    ── 0x447528 ──
    0x447528 if (slot != 3) → 0x4475A1
    0x44753C [sub+0x28] = 0 ; 0x44753F t = [ent+0x28] ; t == 0 → 尾部
    0x447546 t-- ; [ent+0x28] = t ; 0x447547 if (t & 3) != 0 → 尾部
    0x44754E 造 0x10008431 + 0x44759C 0x4013A2(0xC, ([sub+4]−0x140)<<4)  ; 不置 [sub+0x28]
    ── 0x4475A1 ──
    0x4475A1 if (byte[0x56CCB3] && [sub+0x28] != 2 && != 3) byte[0x56CCB3] = 0
    0x4475BF 返回 byte[sub+0x34]
    ```
    """
    sub = e.p.get("sub")                              # 0x44741F ebx = [ebp+0x1C]
    if sub is None:
        return False
    b0e = self.p4_btn0_edge()                         # 0x4AB596
    b1e = self.p4_btn1_edge()                         # 0x4AB597
    if b0e:                                           # 0x447422
        e.d32(0x20, 0)
    if b1e:                                           # 0x44742D
        e.d32(0x24, 0)
    c20, c24 = e.s32(0x20), e.s32(0x24)
    if c20 + c24 < 4:                                 # 0x447445
        e.d32(0x24, (c24 + 1) & 0xFFFFFFFF)           # 0x447448
        e.d32(0x20, (c20 + 1) & 0xFFFFFFFF)           # 0x44744B
        if (b0e or b1e) and sub.s32(0x28) != 1 and sub.g32(0x34):
            slot = self.keys.field(0xC000)            # 0x44747F
            if slot == 3:                             # 0x44748E
                if self.p4_4cd4a0_ge_a0():            # 0x44750C
                    e.d32(0x28, 0x3C)                 # 0x44751A
                    sub.d32(0x20, 0x79)               # 0x447521
            else:
                if sub.s32(0x28) != 0:                # 0x447493
                    sub.d32(0x28, 0)
                elif self.p4_4cd4a0_ge_a0():          # 0x4474A0
                    self.p4_fire_8431(sub)   # 0x4474AE
                    sub.d32(0x28, 1)                  # 0x4474F6
                    self.p4_se_pan(0x0C, (sub.s32(0x04) - 0x140) << 4)   # 0x447503
    if self.keys.field(0xC000) == 3:                  # 0x447528
        sub.d32(0x28, 0)                              # 0x44753C
        t = e.s32(0x28)                               # 0x44753F
        if t != 0:
            t -= 1
            e.d32(0x28, t & 0xFFFFFFFF)               # 0x447549
            if (t & 3) == 0:                          # 0x447547 每 4 帧
                self.p4_fire_8431(sub)           # 0x44754E
                self.p4_se_pan(0x0C, (sub.s32(0x04) - 0x140) << 4)   # 0x44759C
    if self.p4_stat.get(0x56CCB3, 0):                  # 0x4475A1
        v = sub.s32(0x28)
        if v != 2 and v != 3:
            self.p4_stat[0x56CCB3] = 0                # 0x4475B8
    return bool(sub.g32(0x34))                        # 0x4475BF


def p4_laser(self, e, variant: str) -> bool:
    """type-5 激光族四行为（§16.194）：`0x446C50` / `0x446D30` / `0x446E20` / `0x446F10`。

    四者共用同一发射段：`ebp = [ent+0x1C]`（**子对象指针**）、
    `0x430400(rec, [ebp+4], [ebp+8], 0x10008041, ebp)` 入 `0x4AD46C`
    （第 5 字段传的是**父指针**），随后 `0x446470(ebp, a, b)` 与 `[ent+0x20] = 1`。

    差异（逐条对应反汇编）：

    | 变体 | btn1 门 | `[0x56CC98]` 屏蔽 | 入口置 `[0x56CC94]` | 结算参数 | 释放时 `[ebp+0x30]` 下限 |
    |---|---|---|---|---|---|
    | `0x446C50` | 有 | 无 | 无 | `(1,1)` 开火 / 无 0 号 | 0x1E（仅当 `[0x56CC9C]==0`） |
    | `0x446D30` | 有 | 有 | 无 | `(1,1)` 开火 / `(0,1)` 释放 | 0x1E |
    | `0x446E20` | 无（用 `[+0x20]==0`） | 无 | `=[0x56CC98]!=[0x56CCA0]` | `(0,1)` | 0x3C（仅当 `[0x56CC98]==[0x56CCA0]`） |
    | `0x446F10` | 有 | 有 | `=1` | `(1,1)` 开火 / `(0,1)` 释放 | 无 |
    """
    sub = e.p.get("sub")                     # 0x446C5E ebp = [ebx+0x1C]
    s98 = self.p4_stat.get(0x56CC98, 0)
    sa0 = self.p4_stat.get(0x56CCA0, 0)

    def fire(a: int, b: int) -> None:
        if sub is None:
            return
        # 0x446C78 / 0x446D61 / 0x446E5F / 0x446F4B：位置取子对象，第 5 字段传父指针
        self.spawn(self._p4_q("ui46c"), 0x10008041,
                   sub.s32(0x04), sub.s32(0x08), sub)
        self.p4_stat[0x446470] = self.p4_stat.get(0x446470, 0) + 1   # 0x401AA5 记账

    def raise_floor(v: int) -> None:
        if sub is not None and sub.s32(0x30) < v:                # 0x446CE1 / 0x446DD3 / 0x446EC3
            sub.d32(0x30, v)

    if variant == "e20":
        # 0x446E20..0x446E3A：先算 [0x56CC94] = ([0x56CC98] != [0x56CCA0])
        self.p4_stat[0x56CC94] = 1 if s98 != sa0 else 0
        if e.g32(0x20) == 0:                                     # 0x446E40
            fire(0, 1)
            e.d32(0x20, 1)                                       # 0x446E8E
        if self.p4_btn1_edge() and self.p4_stat.get(0x56CCA0, 0):
            self.p4_stat[0x56CC94] = 1                           # 0x446EB0
            if self.p4_stat.get(0x56CC98, 0) == self.p4_stat.get(0x56CCA0, 0):
                raise_floor(0x3C)                                # 0x446EBE
        return bool(sub is not None and sub.g32(0x34))            # 0x446ECA

    btn = self.p4_btn1_edge()                                    # 0x4AB597 按下沿
    if variant in ("d30", "f10") and s98:                        # 0x446D43 / 0x446F2A
        btn = False
    if variant == "f10":
        self.p4_stat[0x56CC94] = 1                               # 0x446F21
    if btn:
        fire(1, 1)                                               # 0x446C9C / 0x446D85 / 0x446F6F
        e.d32(0x20, 1)
    if e.g32(0x20):                                              # 0x446CB0 / 0x446D99 / 0x446F83
        if self.p4_btn1_release() or (sub is not None and not sub.g32(0x34)):
            if variant in ("d30", "f10"):
                # 0x446DB0 / 0x446F9A：0 号结算（0x401AA5）
                self.p4_stat[0x446470] = self.p4_stat.get(0x446470, 0) + 1
            if self.p4_stat.get(0x56CCA0, 0):                     # 0x446CC7 / 0x446DBB / 0x446FA5
                if variant == "c50":
                    if not self.p4_stat.get(0x56CC9C, 0):         # 0x446CD0
                        raise_floor(0x1E)
                else:
                    raise_floor(0x1E)                             # 0x446DCB
                self.p4_stat[0x56CC94] = 1                        # 0x446CE8 / 0x446DC4 / 0x446FAE
            e.d32(0x20, 0)                                        # 0x446CEF / 0x446DDA / 0x446FB5
    return bool(sub is not None and sub.g32(0x34))                # 0x446CF6 / 0x446DE1 / 0x446FBC


def _beh_446C50(self, e) -> bool:
    """`0x446C50`：激光族变体（无 `[0x56CC98]` 屏蔽、无入口置位）。见 `p4_laser`。"""
    return p4_laser(self, e, "c50")


def _beh_446D30(self, e) -> bool:
    """`0x446D30`：激光族变体（有屏蔽、无入口置位）。见 `p4_laser`。"""
    return p4_laser(self, e, "d30")


def _beh_446E20(self, e) -> bool:
    """`0x446E20`：激光族变体（无按键门，按 `[+0x20]` 状态一次性开火）。见 `p4_laser`。"""
    return p4_laser(self, e, "e20")


P4_447640_TYPES = (0x11FFA321, 0x11FFA321, 0x1180A322, 0x1140A323,
                   0x11FFA324, 0x1140A325, 0x11C0A326)   # 0x4476A6..0x4476D9
P4_447640_TAB = (0, 3, 3, 3, 3, 3, 3, 3, 1, 3, 1, 3, 2, 3, 2)  # 0x447DA0


def _beh_447640(self, e) -> bool:
    """`0x4020BD` → `0x447640`（type 6）：7 项扇形爆发 + 十余状态动画 + 每帧轨道三向（§16.202/16.203/16.204）。

    结构（三相位，按 `[sub+0x28]` 与 `byte[sub+0x34]` 分派）：

    ```
    0x44764C if ([sub+0x28] == 0)  → 相位 0（爆发），末了 jmp 0x4477E9 → return
    0x44772B if (byte[sub+0x34] != 0) → 0x447802（相位 1b）
    相位 1a： 0x41000001 + 10 发抖动 0x41000004 → 0x4477E9 → return
    相位 1b： 0x56CCB3 非 0 时向左飘；飘到 [ent+4] < -[ent+0xC] 则 [sub+0x28]=0 + 结算 + return
    其后（0x44785A）：状态机 + 0x447C2D 轨道三向，每帧
    ```
    """
    sub = e.p.get("sub")                                 # 0x447649
    if sub is None:
        return False                                     # 不可能：type 6 必带子对象
    if sub.g32(0x28) == 0:                               # 0x44764C
        self._p4_447640_burst(e)
        return True
    if sub.g32(0x34) == 0:                               # 0x44772B
        self._p4_447640_spawn(e)
        return True
    if self.p4_stat.get(0x56CCB3, 0):                    # 0x44780B
        d = (e.g32(0x2C) - 1) & 0xFFFFFFFF               # 0x447814 dec
        e.d32(0x2C, d)                                   # 0x447817
        e.d32(0x04, (e.g32(0x04) + d) & 0xFFFFFFFF)      # 0x44781A
        node = e.node
        if node is not None:                             # 0x447822 节点 x 同步
            node.d32(0x14, (node.g32(0x14) + d) & 0xFFFFFFFF)
        if e.s32(0x04) < -e.s32(0x0C):                   # 0x44782D jge → 状态机
            sub.d32(0x28, 0)                             # 0x447831
            # 0x44784B 0x402112(0x4CD4A0, [0x56CC8C], [0x56CC90])：结算调用，目标体未读（§15）
            return True
    self._p4_447640_states(e, sub)                       # 0x44785A
    self._p4_447640_orbit(e)                             # 0x447C2D
    return True


def _p4_447640_burst(self, e) -> None:
    """相位 0（`0x447657..0x447721`）：音效 + 7 项类型扇形 30 发。"""
    self.p4_se_pan(0x0E, (e.s32(0x04) - 0x140) << 4)       # 0x44765A 0x450350(0x4AB4B0,0x0E,…)
    rec = [e.s32(0x04), e.s32(0x08), 0x11FFA321, 0]       # 0x447684
    idx = (e.s32(0x28) >> 8) & 0xF                        # 0x4476B3/0x4476B6
    t = P4_447640_TYPES[idx]                              # 0x4476E1（越界见 §16.202）
    n = 0                                                 # 0x4476E5 计数器 → vel
    while n < 0x3C:                                       # 0x447707
        self.spawn(self._p4_q("ui46c"), t, rec[0], rec[1], n)
        n += 2                                            # 0x447704
    self.p4_stat[0x56CCB2] = 1                            # 0x44771A


def _p4_447640_spawn(self, e) -> None:
    """相位 1a（`0x447731..0x4477E7`）：0x41000001 一发 + 10 发抖动 0x41000004。"""
    self.spawn(self._p4_q("ui4cc"), 0x41000001, e.s32(0x04), e.s32(0x08))
    for _ in range(10):                                   # 0x4477A4 esi = 0xA
        jx = _random.randrange(0x20) - 0xF
        jy = _random.randrange(0x20) - 0xF
        self.spawn(self._p4_q("ui4cc"), 0x41000004,
                   e.s32(0x04) + jx, e.s32(0x08) + jy, (jx, jy))
    self._p4_447640_flag()                                # 0x4477E9


def _p4_447640_flag(self) -> None:
    """`0x402400` → `0x45AF60(0x56CCB8, 0x1000)`：置 bit12。"""
    self._p4_sys = int(getattr(self, "_p4_sys", 0)) | 0x1000


def _p4_447640_states(self, e, sub) -> None:
    """`0x44785A..0x447C2D`：按 `[ent+0x28] & 0xF000` 分派的状态机（§16.203/16.204）。"""
    n = (e.g32(0x20) + 1) & 0xFFFFFFFF                    # 0x44785D/0x447862
    e.d32(0x20, n)
    v = e.g32(0x28)
    st = v & 0xF000                                       # 0x447863
    node = e.node
    if node is None:
        return
    lo = node.g32(0x04)                                   # 节点 +4
    hi = node.g32(0x08)                                   # 节点 +8

    def add(dy: int, dh: int) -> None:                    # 0x447C25 0x45A790(node+4,0,dy,0,dh)
        node.d32(0x04, (node.g32(0x04) + 0) & 0xFFFFFFFF)
        node.d32(0x08, (node.g32(0x08) + dy) & 0xFFFFFFFF)
        node.d32(0x0C, (node.g32(0x0C) + 0) & 0xFFFFFFFF)
        node.d32(0x10, (node.g32(0x10) + dh) & 0xFFFFFFFF)

    def bump(d: int) -> None:                             # 推进状态位
        e.d32(0x28, (e.g32(0x28) + d) & 0xFFFFFFFF)

    def ceil_div(a: int, b: int):
        """`0x462D71`：x86 `idiv` 语义（商截断向零、余数随被除数符号）。

        `0x462D8A` 那句 `if (a<0 && r>0) {q++; r-=b;}` 在 x86 下**永远不会触发**
        （`idiv` 的余数符号跟随被除数，a<0 时 r≤0），是编译器留下的死分支。
        """
        q = abs(a) // abs(b)
        if (a < 0) != (b < 0):
            q = -q
        return q, a - q * b

    if st == 0x1000:                                      # 0x44788D/0x4478FF
        if lo == 0x180:                                   # 0x447905
            bump(0x1000)                                  # 0x44790D
        if (n & 3) == 0:                                  # 0x447916
            add(0x30, 0x30)                               # 0x44791F
    elif st == 0x2000:                                    # 0x447894/0x4478D4
        if lo == 0:
            bump(-0x1000)                                 # 0x4478DF
        if (n & 3) == 0:
            add(-0x30, -0x30)
    elif st == 0x3000:                                    # 0x44789B
        if lo == 0x120:
            bump(0x1000)                                  # 0x4478B4
        if (n & 3) == 0:
            add(0x30, 0x30)
    elif st == 0x4000:                                    # 0x447887/0x44792D
        if lo == 0:
            bump(-0x1000)
        if (n & 3) == 0:
            add(-0x30, -0x30)
    elif st == 0x5000:                                    # 0x44795F/0x44796F
        if hi == 0:
            bump(-0x1000)                                 # 0x447979 add 0xFFFFB000
        if (n & 7) == 0:
            add(-0x30, -0x30)
    elif st in (0x6000, 0x9000):                          # 0x447964 → 0x447BD9
        if st == 0x9000 and lo == 0xF0:                   # 0x4479EA
            bump(0x1000)                                  # 0x4479F2
            if (n & 3) == 0:
                add(0x30, 0x30)
        elif st == 0x6000 and (n & 7) == 0:               # 0x447BD9 test bl,7
            _q, r = ceil_div(hi, 0xC0)                    # 0x447BEB
            add(-0x90, -0x90) if r == 0x90 else add(0x30, 0x30)
    elif st == 0x7000:                                    # 0x447876/0x44799C
        if (n & 7) == 0:
            if lo == 0x150:                               # 0x4479AD
                add(-0x60, -0x60)                         # 0x4479B5
            else:
                add(0x30, 0x30)                           # 0x447A06
    elif st == 0x8000:                                    # 0x4479D7/0x447A12
        k = n & 0xF
        if k <= 0xE:                                      # 0x447A1A
            h = P4_447640_TAB[k]                          # 0x447A22
            if h == 0:                                    # 0x447A2F 分块贴图循环
                _q, r = ceil_div(hi, 0x90)                # 0x447A3B
                if r < 0x60:                              # 0x447A46 jge 结束
                    while True:
                        add(0x30, 0x30)
                        _q, r = ceil_div(node.g32(0x08), 0x90)
                        if r >= 0x60:
                            break
            elif h == 1:                                  # 0x447A86
                add(-0x30, -0x30)
            elif h == 2:                                  # 0x447A91
                add(0x30, 0x30)
    elif st == 0xA000:                                    # 0x4479C6/0x447AA5
        if lo == 0:
            bump(-0x1000)
        if (n & 3) == 0:
            add(-0x30, -0x30)
    elif st == 0xB000:                                    # 0x447AD5/0x447B10
        if not self.p4_stat.get(0x56CCB3, 0):
            dx = e.s32(0x04) - node.s32(0x04)
            dy = e.s32(0x08) - node.s32(0x08)
            self.spawn(self._p4_q("ui4cc"), 0x46000004,
                       e.s32(0x04) + (((dx * 8 - dx) + 4) >> 3),
                       e.s32(0x08) + (((dy * 8 - dy) + 4) >> 3))
    elif st == 0xC000:                                    # 0x447ADC/0x447AE2
        if node.g32(0x00) == 2 and (self.p4_stat.get(0x56CC4C, 0) >> 0) & 0xFFFF == 9:
            node.d32(0x00, 3)                             # 0x447B05


def _p4_447640_orbit(self, e) -> None:
    """`0x447C2D..0x447D60`：每帧三向轨道发射（角度步长 113、按半径缩放、>>16）。"""
    n = e.g32(0x20) & 0x1F
    ang = n * 113                                         # 0x447C33 lea 链
    r = e.s32(0x0C)
    co = p4_sin_q(ang, "cos") * (r >> 1)                  # 0x447C4A..0x447C52
    sn = p4_sin_q(ang, "sin") * ((r >> 2) + r)            # 0x447C5F..0x447C68
    many = 7 < n < 0x18                                   # 0x447D10/0x447D17
    for dx, dy in ((0x100, 0), (-0x80, 0xDE), (-0x80, -0xDE)):   # 0x447C74 表
        x = e.s32(0x04) + ((co * dy + sn * dx) >> 16)     # 0x447CD3/0x447CDF
        y = e.s32(0x08) + ((sn * dy + co * dx) >> 16)     # 0x447CD6
        if many:
            self.spawn(self._p4_q("ui46c"), 0x10000051, x, y)    # 0x447D20
        else:
            self.spawn(self._p4_q("ui4cc"), 0x4100000F, x, y)    # 0x447D3F
    node = e.node
    if node is not None:                                  # 0x447D66..0x447D80
        node.d32(0x14, e.s32(0x08) - r)


# `0x448230` 三张相位表（跳表 0x448A30 / 0x448A40 / 0x448A50），每项 = (模数, type, vel…)
P4_448230_A = ((6, 0x120B1121, ((0xB0, 0x0E00),)),
               (6, 0x12071126, ((0xB0, 0xF4000A00), (0xB0, 0xC000A00))),
               (5, 0x120F112A, ((0xB0, 0x0F00),)),
               (7, 0x120E112D, ((0xB0, 0xFA000A64), (0xB0, 0x6000A64))))
P4_448230_B = ((8, 0x12091122, ((0xB0, 0x4280D00),)),
               (6, 0x12061127, ((0xB0, 0xF6000A00), (0xB0, 0xA000A00),
                                (0xC0, 0xA0008E0), (0x90, 0xF60008E0))),
               (3, 0x120D112B, ((0x90, 0xF60008E0),)),
               (0, 0x120C112E, ()))          # vel 用 sin(寿命*40) 现场算，再 not 发第二发
P4_448230_C = ((3, 0x12081123, ((0xB0, 0x1000),)),
               (3, 0x12061128, ((0xB0, 0xFA000C00),)),
               (7, 0x120C112C, ()),          # vel 随机
               (4, 0x120A112F, ((0xB0, 0xF000),)))
P4_448230_BLINK = (0x286, 0x28E, 0x216, 0x39D)   # 0x448991


def _beh_448230(self, e) -> bool:
    """`0x448230`（type 10 后半）：按键字段闸门 + 四段寿命窗口 × 四相位激光 + 闪烁尾（§16.206/16.207）。

    ```
    0x448242 0x4019C9→0x45AFC0(0x4AB5B0, 0xC000) 取 bits14-15
    0x44824C if ([ent+0x20] != 该字段) return 0
    寿命 [ent+0x1C] 分段： A [0,0x5A) / B [0x78,0xD2) / C [0xF0,0x14A) / D [0x180,0x220)
    每段按 [ent+0x20] (0..3) 查表发射，帧门是 idiv 取余或 test cl,mask
    0x44898B 闪烁尾：节点 [+4] = ([ent+0x1C] & 2) ? 0 : 0x30
    0x4489E2 收尾：按 ebx 放音效，[ent+0x1C] 自增，>= 0x39C 归零，返回 1
    ```
    """
    ph = e.g32(0x20)                                     # 0x44823F
    if ph != ((self.keys.bits & 0xC000) >> 14):           # 0x448242..0x44824C
        return False
    life = e.s32(0x1C)                                   # 0x44825B
    ebx = 0xFF                                           # 0x448263
    if ph <= 3:                                          # 0x448271
        if life < 0x5A:                                  # 0x44825F
            if self._p4_448230_fire(e, ph, life, P4_448230_A):
                ebx = 0
        elif 0x78 <= life < 0xD2:                        # 0x44843F
            if self._p4_448230_fire(e, ph, life, P4_448230_B):
                ebx = 0
        elif 0xF0 <= life < 0x14A:                       # 0x44873E
            if self._p4_448230_fire(e, ph, life, P4_448230_C):
                ebx = 0
        elif 0x180 <= life < 0x220 and (life & 0xF) == 0:  # 0x44892D
            y = 0xA0 if (life & 0x10) else 0x28          # 0x448942..0x44895D
            self.spawn(self._p4_q("ui46c"), 0x2300001A, 0xB0, y)
            ebx = 0
        # 0x44898B 闪烁尾（ph>3 时原作越界读栈，不实现）
        node = e.node
        if node is not None:
            lo = P4_448230_BLINK[ph]                      # 0x4489AD movsx word[esp+ph*2+0x24]
            if lo <= life < lo + 0x1C:                   # 0x4489B2..0x4489BB
                v = 0 if (life & 2) else 0x30            # 0x4489C0..0x4489C6
                node.d32(0x04, v)
                node.d32(0x08, v)                        # 0x4489CC 同法（用 dl）
    if ebx != 0xFF:                                      # 0x4489E2
        self.p4_se_pan(ebx, 0)                           # 0x4489F2 0x450350(0x4AB4B0, ebx, 0)
    n = e.s32(0x1C) + 1                                  # 0x448A09
    if n >= 0x39C:                                       # 0x448A02
        n = 0                                            # 0x448A19..0x448A1C
    e.d32(0x1C, n)                                       # 0x448A0E
    return True                                          # 0x448A0C al = 1


def _p4_448230_fire(self, e, ph: int, life: int, tbl, y: int = 0x78) -> bool:
    """按相位表发射一轮；返回是否真的发了（决定 `ebx` 是否被清 0）。"""
    mod, t, recs = tbl[ph]
    if mod:
        if life % mod:                                   # idiv + test edx,edx
            return False
    if not recs:                                         # 只有 B[3] 与 C[2] 走这里
        if t == 0x120C112E:                              # 0x4486D2：sin 现场算 vel
            a = (life * 40) & 0xFFFFFFFF                 # 0x4486D5 lea [eax+eax*4] / shl 3
            v = ((p4_sin_q(a, "sin") << 0x13) & 0xFFFF0000) | 0x0400   # 0x4486FB / 0x4486E9
            self.spawn(self._p4_q("ui46c"), t, 0xB0, y, v)
            self.spawn(self._p4_q("ui46c"), t, 0xB0, y, (~v) & 0xFFFFFFFF)   # 0x4486C1 not
        else:                                            # 0x120C112C：随机 vel（0x44887F..0x44889D）
            r = (_random.randrange(0x2000) << 0x10) & 0xFFFFFFFF
            r = ((r - 0xFFE0001) & 0xFFFFFFFF) & 0xFFFF0400
            r |= 0x0400
            self.spawn(self._p4_q("ui46c"), t, 0xB0, y, r)
        return True
    for xx, v in recs:
        self.spawn(self._p4_q("ui46c"), t, xx, y, v)
    return True


def _beh_447F90(self, e) -> bool:
    """`0x40116D` → `0x447F90`（type 10 行为）：**三向旋转散射**（§16.200/§16.201）。

    ```
    0x447F99 n = [ent+0x20] + 1                        ; 帧计数
    0x447FA2 ang = (n & 0xF) * 225                     ; 22.5°，满圆 3600 ⇒ 16 等分
    0x447FAF 0x40159B→0x45ABB0(ang) = cos ; 0x447FB7 shl 1      ⇒ co2 = 2cos
    0x447FB9 0x401A50→0x45AAF0(ang) = sin ; 0x447FBE *5         ⇒ sn5 = 5sin
    0x447FD8 方向表 (0x100,0) / (−0x80,0xDE) / (−0x80,−0xDE)   ; 半径≈256、三向 120°
    0x448023 edx = (dy·co2 + dx·sn5) >> 13  ⇒ y = py − edx
    0x44803E eax = (dy·sn5 + dx·co2) >> 13  ⇒ x = px + eax
    0x448062 t = 7 < (n & 0x1F) < 0x18 ? 0x10000052→0x4AD46C : 0x41000010→0x4AD4CC
    0x4480D4 if (0x45AFF0(0x56CCB8, 0x20)) 跳过尾部
    0x4480E8 尾部再补一发：n 奇 → (sn5*2, co2*5)，偶 → (sn5*4, co2*10)
    0x448127 y = py − (b >> 5) ; 0x448135 x = px − (a >> 5)
    0x44817F 0x40114A→0x45B0A0(0x56CCB8, 0x10, byte[sub+0x34])  ; 置/清 bit4
    0x44818A return byte[sub+0x34]
    ```
    """
    sub = e.p.get("sub")                                # 0x447FD5 eax = [ebp+0x1C]
    if sub is None:
        return False
    n = (e.g32(0x20) + 1) & 0xFFFFFFFF                  # 0x447F99
    e.d32(0x20, n)                                      # 0x447F9F
    ang = (n & 0xF) * 225                               # 0x447FA2 (lea 链 25×9)
    co2 = p4_sin_q(ang, "cos") * 2                      # 0x447FAF + 0x447FB7 shl 1
    sn5 = p4_sin_q(ang, "sin") * 5                      # 0x447FB9 + 0x447FBE ×5
    px, py = sub.s32(0x04), sub.s32(0x08)               # 0x447FF0 / 0x447FF3
    many = 7 < (n & 0x1F) < 0x18                        # 0x448080 / 0x448085
    for dx, dy in ((0x100, 0), (-0x80, 0xDE), (-0x80, -0xDE)):   # 0x447FD8 表
        y = py - ((dy * co2 + dx * sn5) >> 13)          # 0x448035..0x448040
        x = px + ((dy * sn5 + dx * co2) >> 13)          # 0x44803E..0x44804D
        if many:
            self.spawn(self._p4_q("ui46c"), 0x10000052, x, y)     # 0x44808E
        else:
            self.spawn(self._p4_q("ui4cc"), 0x41000010, x, y)     # 0x4480AD
    if not (self.p4_sys_bits() & 0x20):                 # 0x4480D4 0x45AFF0(…,0x20)
        if n & 1:                                       # 0x4480E8
            a, b = sn5 * 2, co2 * 5                     # 0x448101 / 0x448104
        else:
            a, b = sn5 * 4, co2 * 10                    # 0x4480F2 / 0x4480F9 + shl
        self.spawn(self._p4_q("ui46c"), 0x10000052,
                   px - (a >> 5), py - (b >> 5))        # 0x448135 / 0x448127
    alive = sub.g32(0x34)                               # 0x448179
    self._p4_sys = (int(getattr(self, "_p4_sys", 0)) & ~0x10) | (0x10 & (1 if alive else 0))
    return bool(alive)                                  # 0x44818A


def _beh_446F10(self, e) -> bool:
    """`0x446F10`：激光族变体（入口置 `[0x56CC94]=1`，释放时 0 号结算）。见 `p4_laser`。"""
    return p4_laser(self, e, "f10")


def _beh_446BD0(self, e) -> bool:
    """`0x402199` → `0x446BD0`（type 1 变体）：**直接吸附**到指针位置（无 /4 插值）。

    ```
    0x446BD3 0x40212B→0x446600(e) ; al == 0 → ret
    0x446BDE [esi+4] = [0x4AB59C]      ; 0x446BE6 [esi+8] = [0x4AB5A0]（直接赋值，不插值）
    0x446BF3 [0x56CC8C]/[0x56CC90] = (x, y)
    0x446C03 节点 +0x14/+0x18 = (x−0x18, y−0x18)
    0x446C24 返回 ([esi+0x18] != 0)
    ```
    函数体到 `0x446C2D ret` 为止，后接 nop/int3 填充。
    """
    if not p4_446600(self, e):                       # 0x446BD3 / 0x446BDA
        return False
    px, py = self.p4_ptr()                           # 0x446BDE / 0x446BE6
    e.d32(0x04, px & 0xFFFFFFFF)                     # 0x446BE3 直接写入
    e.d32(0x08, py & 0xFFFFFFFF)                     # 0x446BEE
    if e.node is not None:                           # 0x446C16 节点镜像
        e.node.dst = (px - 0x18, py - 0x18)          # 0x446C09 / 0x446C0C
    return e.g32(0x18) != 0                          # 0x446C24 setne


def _beh_446A10(self, e) -> bool:
    """`0x446A10`（type 1 行为，索引 4）：与 `0x4466F0` 同构，但「移动」是**直接吸附**不是 1/4 步进。

    ```
    0x446A13 if (!0x446600(e)) return false
    0x446A1E al = byte[0x4AB595] = rec.b1 ; 0x446A25 al = byte[0x4AB599] = rec.r1
    0x446A2A b1 != 0 → 0x446A43：r1 == 0 → 0x446A52（**不移动**），否则 0x446A47
    0x446A2C b1 == 0：r1 != 0 → 0x446A47，否则 0x446A30
    0x446A47 0x446470(e, 0, 1) → 0x446A52
    0x446A30 [e+4] = [0x4AB59C] ; [e+8] = [0x4AB5A0]      ; ★ 吸附，无 /4
    ── 0x446A52 共用尾 ──
    0x446A5A 0x45A690(x, y) → [0x56CC8C]/[0x56CC90]
    0x446A78 0x45A690(x-0x18, y-0x18) → 显示节点 [+0x14]/[+0x18]
    0x446A93 return [e+0x18] != 0
    ```
    """
    if not p4_446600(self, e):
        return False
    b1 = bool(getattr(self.inp.rec, "b1", 0))               # 0x446A1E
    r1 = bool(getattr(self.inp.rec, "r1", 0))               # 0x446A25
    if b1:
        if r1:                                              # 0x446A43 test al,al / je 0x446A52
            p4_446470(self, e, 0, 1)                        # 0x446A4D
    elif r1:                                                # 0x446A2E jne 0x446A47
        p4_446470(self, e, 0, 1)                            # 0x446A4D
    else:                                                   # 0x446A30 吸附
        px, py = self.p4_ptr()
        e.d32(0x04, px & 0xFFFFFFFF)
        e.d32(0x08, py & 0xFFFFFFFF)
    nx, ny = p4_45A690(e.s32(0x04), e.s32(0x08))            # 0x446A5A
    self.p4_player_pos = (nx, ny)                           # 0x56CC8C / 0x56CC90
    ox, oy = p4_45A690(nx - 0x18, ny - 0x18)                # 0x446A78
    if e.node is not None:
        e.node.dst = (ox, oy)                               # 0x446A83
    return e.g32(0x18) != 0                                 # 0x446A93


def _beh_446AD0(self, e) -> bool:
    """`0x446AD0`（type 1 行为，索引 5）：**无条件吸附**，没有任何输入分支。

    ```
    0x446AD3 if (!0x446600(e)) return false
    0x446ADE [e+4] = [0x4AB59C] ; 0x446AEC [e+8] = [0x4AB5A0]
    0x446AF8 0x45A690(x, y) → [0x56CC8C]/[0x56CC90]
    0x446B11 0x45A690(x-0x18, y-0x18) → 显示节点 [+0x14]/[+0x18]
    0x446B2D return [e+0x18] != 0
    ```
    """
    if not p4_446600(self, e):
        return False
    px, py = self.p4_ptr()
    e.d32(0x04, px & 0xFFFFFFFF)                            # 0x446AE3
    e.d32(0x08, py & 0xFFFFFFFF)                            # 0x446AEE
    nx, ny = p4_45A690(e.s32(0x04), e.s32(0x08))            # 0x446AF3
    self.p4_player_pos = (nx, ny)                           # 0x446AF8
    ox, oy = p4_45A690(nx - 0x18, ny - 0x18)                # 0x446B11
    if e.node is not None:
        e.node.dst = (ox, oy)                               # 0x446B1C
    return e.g32(0x18) != 0                                 # 0x446B2D


def _beh_446950(self, e) -> bool:
    """`0x401XXX` → `0x446950`（type 1 变体）：只有 `0x446600` 门 + 1/4 步进逼近，**无**锁定击破分支。

    ```
    0x446953 0x40212B→0x446600(e) ; al == 0 → ret（本帧不继续）
    0x44695E eax = [0x4AB59C] − [esi+4] ; 0x44696B ecx = [0x4AB5A0] − [esi+8]
    0x446973 if (eax >= 0) eax += 3 ; 0x44697D sar 2      ; 朝零取整的 /4
    0x446980 [esi+4] += eax       ; 0x446992 [esi+8] += ecx
    0x44699E [0x56CC8C] = x ; [0x56CC90] = y             ; 0x401753 恒等透传后写回
    0x4469AF 节点 +0x14/+0x18 = (x−0x18, y−0x18)          ; 48px 字形居中
    0x4469CA 返回 ([esi+0x18] != 0)
    ```
    """
    if not p4_446600(self, e):                       # 0x446953 / 0x44695A
        return False
    px, py = self.p4_ptr()                           # 0x44695E / 0x44696B
    dx = px - e.s32(0x04)
    dy = py - e.s32(0x08)
    dx = (dx + 3) >> 2 if dx >= 0 else dx >> 2       # 0x446977 / 0x44697D sar
    dy = (dy + 3) >> 2 if dy >= 0 else dy >> 2       # 0x446989 / 0x44698F sar
    e.d32(0x04, (e.s32(0x04) + dx) & 0xFFFFFFFF)     # 0x446980
    e.d32(0x08, (e.s32(0x08) + dy) & 0xFFFFFFFF)     # 0x446992
    nx, ny = p4_45A690(e.s32(0x04), e.s32(0x08))     # 0x446999（恒等）
    self.p4_player_pos = (nx, ny)                    # 0x44699E [0x56CC8C] / [0x4469A3 0x56CC90]
    if e.node is not None:                           # 0x4469BC 节点镜像
        e.node.dst = (nx - 0x18, ny - 0x18)          # 0x4469C2
    return e.g32(0x18) != 0                          # 0x4469CA setne


def _beh_10000001(self, e) -> bool:
    """`0x401E06` → `0x448C70`（自机行为；自机实体类型是 **`0x0B000001`**，函数名沿用旧名）。

    ```
    0x448C78 t = ++[ent+0x1C]
    0x448C87 if ([node+4] == 0) goto 激活流程         ; 显示矩形左边界为 0 ⇒ 隐藏中
    0x448C8C   if ((t & 0xF) == 0) 0x45A790(node+4,-0x20,0,-0x20,0)   ; 每 16 帧换动画帧
    0x448CA5   if ([node+8] == 0) 0x45AF60(0x56CCC0,1)
    0x448CBC   return 1
    激活：0x448CC1 if (0x45AFF0(0x56CCC0,7)) return 1  ; 开始键未按就等
           x=[0x4AB59C]; y=[0x4AB5A0]; [ent+4]=x; [ent+8]=y
           if (x>0x1BE) x=0x1BE, 0x44E470(0x4AB454,x,y)   ; 钳 446
           if (y>0x190) y=0x190, 0x44E470(...)            ; 钳 400
           [0x56CC8C] = 0x401753(x,y); node.dst = 0x401753(x+0x40,y)
           if ([0x4AB594] && !0x45AFF0(0x56CCC0,0x10))
               生成 0x1B000001 于 (x+0x13, y) 入 0x4AD46C
           if ([ent+0x18]) return 1
           if (--[ent+0x20]) { 生成 0x0B000001 于 (200,200) 入 0x4AD40C; return 0 }
           else { 0x45AF30(0x56CCC0,0x40); return 0 }
    ```
    """
    e.d32(0x1C, (e.s32(0x1C) + 1) & 0xFFFFFFFF)
    e.d32(0x1C, e.g32(0x1C))
    hidden = getattr(e, "rect_left", 0) == 0
    if not hidden:                                   # 已显示：原地待机
        if e.s32(0x1C) & 0xF == 0 and e.node is not None:
            self.p4_anim_step(e)                     # 0x45A790
        if e.g32(0x24) == 0:
            self.p4_key_reset(1)                     # 0x45AF60(0x56CCC0,1)
        return True
    if self.p4_key_test(7):                          # 0x45AFF0(0x56CCC0,7) 开始键
        return True
    x, y = self.p4_ptr()
    if x > 0x1BE:                                    # 0x448CE5 钳 446
        x = 0x1BE
        self.p4_ptr_set(x, y)                        # 0x44E470
    if y > 0x190:                                    # 0x448D00 钳 400
        y = 0x190
        self.p4_ptr_set(x, y)
    e.d32(0x04, x)
    e.d32(0x08, y)
    self.p4_player_pos = (x, y)                      # 0x56CC8C
    if e.node is not None:
        e.node.dst = (x + 0x40, y)
        e.node.visible = 1
    if self.p4_btn_attack() and not self.p4_key_test(0x10):
        self.spawn(self._p4_q("ui46c"), 0x1B000001, x + 0x13, y)   # 0x448D68..0x448D9E
    if e.g32(0x18):
        return True
    n = (e.s32(0x20) - 1) & 0xFFFFFFFF              # 0x448DAE 剩余重生次数
    e.d32(0x20, n)
    if n:
        self.spawn(self._p4_q("ui40c"), 0x0B000001, 200, 200)      # 0x448DB9
        return False
    self.p4_key_raw_set(0x40)                        # 0x448DFB → 0x45AF30(0x56CCC0,0x40)
    return False


def _beh_23000004(self, e) -> bool:
    """`0x40118B` → `0x40E460`（类型 0x23000004）：加速直线运动 + 定时打一发。"""
    acc = e.s32(0x20)
    if acc:
        acc = (acc + 1) & 0xFFFFFFFF
        e.d32(0x20, acc)
    t = e.s32(0x1C)
    e.d32(0x1C, (t + 1) & 0xFFFFFFFF)
    if t == e.s32(0x24):                       # 0x40E47C 到点打一发
        self.p4_43B070(e, 0)
    elif (t + 1) == 0x168:                     # 0x40E489 360 帧时加速计数复位 1
        e.d32(0x20, 1)
    acc = e.s32(0x20)
    x = (e.s32(0x04) + (acc >> 1)) & 0xFFFFFFFF   # 0x40E49E x += [+0x20]>>1
    e.d32(0x04, x)
    if e.node is not None:
        e.node.dst = (e.s32(0x04) - 0x18, e.s32(0x08) - 0x18)
    alive = (acc <= 0 or e.s32(0x04) < 0x298) and e.g32(0x18) != 0
    return bool(alive)


def _beh_23000002(self, e) -> bool:
    """`0x401FF0` → `0x40E100`（类型 0x23000002，36 个/关；四段互斥时间窗改速度）。"""
    t = e.s32(0x2C)
    if 0x14 <= t < 0x28:
        e.d32(0x28, (e.s32(0x28) + e.s32(0x20)) & 0xFFFFFFFF)
    elif 0x28 <= t < 0x3C:
        e.d32(0x28, (e.s32(0x28) - e.s32(0x20)) & 0xFFFFFFFF)
    elif 0x8C <= t < 0x9C:
        e.d32(0x24, (e.s32(0x24) + 1) & 0xFFFFFFFF)
        e.d32(0x28, (e.s32(0x28) + e.s32(0x20)) & 0xFFFFFFFF)
    elif 0x9C <= t < 0xAC:
        e.d32(0x24, (e.s32(0x24) + 1) & 0xFFFFFFFF)
        e.d32(0x28, (e.s32(0x28) - e.s32(0x20)) & 0xFFFFFFFF)
    # x += (vy+2)>>2 ; y += (v28+2)>>2（sar 3 步算术右移）
    vx = (e.s32(0x24) + 2) >> 2
    vy = (e.s32(0x28) + 2) >> 2
    x = e.s32(0x04) + vx
    y = e.s32(0x08) + vy
    e.d32(0x04, x & 0xFFFFFFFF)
    e.d32(0x08, y & 0xFFFFFFFF)
    if x == 0x190 and e.s32(0x1C) == 1:        # 0x40E1xx → 0x43B070(ent,0)
        self.p4_43B070(e, 0)
    e.d32(0x2C, (t + 1) & 0xFFFFFFFF)
    if e.node is not None:
        e.node.dst = (x - 0x18, y - 0x18)       # [+0x14]/[+0x18]
    return e.g32(0x18) != 0 and x < 0x2A8       # 存活判据


def _beh_23000003(self, e) -> bool:
    """`0x401B1D` → `0x40E230`（类型 0x23000003，10 个/关）。

    x 落在字节表 `0x40E2F0` 的 3 个触发点之一时改速度（`0x40E251/0x40E272/0x40E282`），
    然后 `[+4]+=[+0x20]`、`[+8]+=[+0x24]`，显示节点 dst = `(x-0x18, y-0x18)`（`0x45A690` 是恒等）。
    """
    x = e.s32(0x04)
    i = x - 0xF0
    if 0 <= i <= 0xF2:
        case = ENT23_SW03[i] if i < len(ENT23_SW03) else 3
        if case == 2:                          # 0x40E251
            e.d32(0x20, 0xFFFFFFFF)
            e.d32(0x24, 2 if e.s32(0x08) <= 0xF0 else 0xFFFFFFFE)
        elif case == 1:                        # 0x40E272
            e.d32(0x20, 0xFFFFFFFD)
            e.d32(0x24, 0)
        elif case == 0:                        # 0x40E282
            if e.g32(0x1C) != 0:
                self.p4_43B070(e, 0)
        # case 3 (0x40E292) = 无动作
    e.d32(0x04, (x + e.s32(0x20)) & 0xFFFFFFFF)          # 0x40E292
    e.d32(0x08, (e.s32(0x08) + e.s32(0x24)) & 0xFFFFFFFF)
    node = e.g32(0x38)
    if node:
        self.p4_stat[node + 0x14] = (e.s32(0x04) - 0x18) & 0xFFFFFFFF   # 0x45A690 恒等
        self.p4_stat[node + 0x18] = (e.s32(0x08) - 0x18) & 0xFFFFFFFF
    return bool(e.g32(0x18)) and e.s32(0x04) > -0x18      # 0x40E2C5/0x40E2CC


# `0x40E2F0`：243 项字节表（x-0xF0 索引 → case 选择子，`0x40E2E0` 为 4 项跳表）
ENT23_SW03 = [0, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 1, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 0, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 2]

# ---- 特殊类 `0x42C4D0` 的 12 项行为（§16.176 / §16.180 / §16.181 / §16.182）----
# 键 = 行为地址；值 = (间隔阈值, ((弹型, 速度, x 偏移), ...), 节奏模式)
#   节奏模式 "single"   ：[+0x1C] > 阈值即发，发后清零（每 阈值+1 帧一发）
#   节奏模式 "cadence3" ：帧 3 发、帧 6 发并清零（相邻间隔恒 3 帧，§16.182）
# 速度可以是整数，也可以是 `f(self) -> int`（随机/三角算出来的槽）。


def _p4_slot_vel_rand_d150(self) -> int:
    """`0x42D150` 的速度：随机水平 ±16、垂直 +4（§16.184）。

    ```
    0x42D178 0x45AD00()（rand）  0x42D17D and eax,0x1FFF   ; 0..8191
    0x42D185 shl eax,0x10        0x42D188 sub eax,0x0FFE0001
    0x42D190 and eax,0xFFFF0400  0x42D199 or ah,4          ; 低 16 = 0x0400
    ```
    等价于 `((r & 0x1FFF) - 0x0FFF) << 16 | 0x0400`（已对全部 8192 个输入穷举验证），
    即水平 `[-15.996, +16.0]` 像素/帧、垂直 `+4.0` 像素/帧。
    """
    return (((rng.randrange(0x2000) - 0x0FFF) << 16) | 0x0400) & 0xFFFFFFFF


def _p4_slot_vel_trig_d4a0(self, owner) -> int:
    """`0x42D4A0` 的速度：由**发射者 `[+0x24]`** 决定方向（§16.185）。

    ```
    0x42D4CA eax = [ebp+0x24] ; ×25 ; shl 3   ⇒ arg = [+0x24] * 200（0.1° 单位 = ×20°）
    0x42D4D9 0x45ABB0(arg) ; shl 3 ; esi = eax & 0xFFFF      ; 低 16 = cos×8
    0x42D4F6 0x45AAF0(arg) ; shl 0x13 ; and 0xFFFF0000       ; 高 16 = sin×8
    0x42D50A or esi, eax                                     ; vel
    ```
    """
    arg = (owner.s32(0x24) * 200) & 0xFFFFFFFF
    lo = (p4_sin_q(arg, "cos") * 8) & 0xFFFF
    hi = ((p4_sin_q(arg, "sin") * 8) << 16) & 0xFFFF0000
    return (hi | lo) & 0xFFFFFFFF


# 12 个槽至此全部登记（0x42D6A0 的速度 0xF000 = 正上方 16 像素/帧）。
P4_SPAWN_SLOTS = {
    0x42C810: (5, ((0x120B1121, 0x00000E00, 0x10),), "single"),
    0x42CC50: (5, ((0x12071126, 0xF4000A00, 0x10),
                   (0x12071126, 0x0C000A00, 0x10)), "single"),
    0x42D070: (4, ((0x120F112A, 0x00000F00, 0x10),), "single"),
    0x42D370: (6, ((0x120E112D, 0xFA000A64, 0x10),
                   (0x120E112D, 0x06000A64, 0x10)), "single"),
    0x42C8F0: (7, ((0x12091122, 0x04280D00, 0x10),), "single"),
    0x42CD70: (5, ((0x12061127, 0xF6000A00, 0x10),
                   (0x12061127, 0x0A000A00, 0x10),
                   (0x12061127, 0x0A0008E0, 0x10),
                   (0x12061127, 0xF60008E0, 0x10)), "single"),
    0x42D150: (3, ((0x120D112B, _p4_slot_vel_rand_d150, 0x10),), "single"),
    0x42D260: (6, ((0x120C112C, _p4_slot_vel_rand_d150, 0x10),), "single"),
    0x42D4A0: (9, ((0x120C112E, _p4_slot_vel_trig_d4a0, 0x10),), "single"),
    0x42D6A0: (3, ((0x120A112F, 0x0000F000, 0x10),), "single"),
    0x42CA70: (5, ((0x12081123, 0x00001000, 0x10),), "cadence3"),
    0x42CEF0: (5, ((0x12061128, 0xFA000C00, 0x10),
                   (0x12061128, 0x06000C00, 0x10)), "cadence3"),
}


def _p4_slot_behaviour(spec):
    """生成一个槽行为（12 项表共用骨架，§16.181）。"""
    thr, shots, mode = spec

    def beh(self, e) -> bool:
        e.d32(0x1C, (e.s32(0x1C) + 1) & 0xFFFFFFFF)          # 0x42CA7D 帧计数
        t = e.s32(0x1C)
        owner = e.p.get("owner")                             # 0x42CA7A ebp=[+0x20]
        if self.p4_btn_attack() and owner is not None:       # 0x42CA81 byte[0x4AB594]
            if mode == "cadence3":
                # 0x42CA91 cmp 2/jle → 0x42CB12（连 SE 都不播）
                if t > 2:
                    if t == 3 or t > 5:                      # 0x42CA96 je / 0x42CA9B jle
                        for tw, vel, dx in shots:
                            self.p4_fire_slot(owner, tw, vel, dx)
                    if t > 5:                                # 0x42CAE2 共用尾
                        self.p4_42C600(e)                    # 0x42CAEA
                        e.d32(0x1C, 0)                       # 0x42CAEF
                    self.p4_slot_se()                        # 0x42CAF6 玩家声像
            else:
                if t > thr:                                  # 0x42D08D cmp 阈值/jle
                    for tw, vel, dx in shots:
                        self.p4_fire_slot(owner, tw, vel, dx)
                    self.p4_42C600(e)                        # 0x42C874 / 0x42CD03
                    e.d32(0x1C, 0)                           # 0x42C879 / 0x42D0D2
                    self.p4_slot_se()                        # 0x42C880 / 0x42D0D9
        # 0x42C89E 存活判定：byte[ebp+0x34] 与 [ent+0x18] 同时非零
        return bool(owner is not None and owner.s32(0x34) != 0 and e.g32(0x18) != 0)

    return beh


for _a, _spec in P4_SPAWN_SLOTS.items():
    globals()[f"_beh_p4slot_{_a:06X}"] = _p4_slot_behaviour(_spec)


P4_BEH: dict[int, object] = {
    0x40E070: _beh_23000001,
    0x40E100: _beh_23000002,
    0x40E460: _beh_23000004,
    0x446950: _beh_446950,
    0x446890: _beh_446950,          # §16.193：与 0x446950 逐字节相同（仅 call 位移不同）
    0x446BD0: _beh_446BD0,
    0x446C50: _beh_446C50,
    0x446D30: _beh_446D30,
    0x446E20: _beh_446E20,
    0x446F10: _beh_446F10,
    0x447410: _beh_447410,
    0x448C70: _beh_10000001,
    0x447F90: _beh_447F90,
    0x447640: _beh_447640,
    0x448230: _beh_448230,
    0x40E790: _beh_23000007,
    0x40E8C0: _beh_23000008,
    0x40EAF0: _beh_23000009,
    0x40E520: _beh_23000005_06,
    0x4466F0: _beh_type1_follow,
    0x4467D0: _beh_type1_follow_b,
    0x446A10: _beh_446A10,
    0x446AD0: _beh_446AD0,
    0x40E230: _beh_23000003,
    **{a: globals()[f"_beh_p4slot_{a:06X}"] for a in P4_SPAWN_SLOTS},
}     # 行为地址 → 实现函数（每实现一个就登记，未登记即"未实现"）


class Page4Mixin:
    # ---- 0x4505B0 参数块 -----------------------------------------------
    @staticmethod
    def _p4_block_data() -> dict:
        """`remake/p4_block.json`（`remake/build_p4_block.py` 从 `0x4505B0` 机械提取）。"""
        global _P4_BLOCK
        if _P4_BLOCK is None:
            import json
            from pathlib import Path
            f = Path(__file__).resolve().parent.parent / "p4_block.json"
            _P4_BLOCK = json.loads(f.read_text(encoding="utf-8"))
        return _P4_BLOCK

    def p4_block(self) -> bytearray:
        """`0x4505B0` 的参数块：`esp+0x10..esp+0xE3` = 0xD4 字节。

        分支选择：
          · `0x450648 0x45B030(0x4AB5B0,1)`（位已置返回 0）⇒ `je 0x450686` 继续分 A/B/C；
            位清零 → 落 `0x450651`（`A_flag` 变体，只有 5 个字段非零）。
          · A `0x45069A`（关<8 且 周目<=3）、B `0x450943`（周目>3）、C `0x45096E`（关>=8）。
        块内 `+0x10/+0x12/+0x14/+0x16` 是 (关,周目) 查表结果，其余是四组常量表。
        """
        d = self._p4_block_data()
        si = int(self.stage_no) & 0xFFFF          # [0x4AB5C8]
        bp = int(self.loop_no) & 0xFFFF           # word[0x4AB5CA]
        tbl = d["tables"]
        blk = bytearray(d["size"])

        def put(o: int, v: int) -> None:
            blk[o] = v & 0xFF
            blk[o + 1] = (v >> 8) & 0xFF

        if not self.keys.test(1):                 # 0x450648 → 0x450651 变体
            for off, val in d["branches"]["A_flag"]["imm"].items():
                o = int(off, 16) - 0x10
                blk[o] = val & 0xFF
                blk[o + 1] = (val >> 8) & 0xFF
            blk[0x1A] = 0x06                      # [esp+0x2A]=6（0x450665）
            blk[0x14] = 0x00                      # [esp+0x24]=0
            blk[0x12] = 0x00                      # [esp+0x22]=0
            blk[0x16] = 0x00                      # [esp+0x26]=0
            blk[0x19] = 0x64                      # [esp+0x29]=0x64（0x45065C..0x450678）
            return blk

        name = "A" if (si < 8 and bp <= 3) else ("B" if si < 8 else "C")
        for off, val in d["branches"][name]["imm"].items():
            o = int(off, 16) - 0x10
            blk[o] = val & 0xFF
            blk[o + 1] = (val >> 8) & 0xFF
        if name == "A":
            put(0x10, si * 4 + 0x0B)               # 0x4506F1/0x450700
            put(0x12, tbl["0xa4"][si + bp * 8])    # 0x450833 → 0x450908
            v = tbl["0x64"][si + bp * 8]           # 0x450903 → 0x45090D
            put(0x14, v)
            put(0x16, min(v // 7, 0x0C))           # 0x450915..0x450932（魔数 0x92492493，/7 后钳 0xC）
            blk[0x1A] = 0xFF                       # 0x450939
        elif name == "B":
            put(0x10, si * 4 + 0x38)               # 0x450943
            put(0x12, 0x320)                       # 0x45094A
            put(0x14, 0x64)                        # 0x450956
            put(0x16, 0x0C)                        # 0x45095D
            blk[0x1A] = 0xFF                       # 0x450964
        else:                                      # C：四张按周目查的表（0x4509B7..0x450A21）
            put(0x10, tbl["0x54"][bp])
            put(0x12, tbl["0x4c"][bp])
            put(0x14, tbl["0x5c"][bp])
            put(0x16, tbl["0x3c"][bp])
            blk[0x19] = 0                          # [esp+0x29]=bl
            blk[0x1A] = tbl["0x44"][bp] & 0xFF     # [esp+0x2A]=dl
        # 这 4 个字节都在**多压了一个参数**之后才写（esp 已 -4），故块内偏移比 esp 偏移小 4：
        #   0x450611 `mov byte[esp+0x2F],al` (esp=X-4) ⇒ 块 +0x1B；0x450621 ⇒ +0x1C；
        #   0x450634 ⇒ +0x1D；0x450644 (push 0xc000 后) ⇒ +0x18。
        blk[0x18] = (self.keys.bits >> 14) & 3         # 0x450638/0x450644 0x45AFC0(0x4AB5B0,0xC000)
        blk[0x1B] = 1 if self.keys.test(0x200) else 0  # 0x450605/0x450611 0x40208B(…,0x200)
        blk[0x1C] = 1 if self.keys.test(1) else 0      # 0x450615/0x450621 0x40208B(…,1)
        blk[0x1D] = 1 if self.keys.test(2) else 0      # 0x450625/0x450634 0x40208B(…,2)
        return blk

    @staticmethod
    def _p4_sword(b, o: int) -> int:
        v = b[o] | (b[o + 1] << 8)
        return v - 0x10000 if v & 0x8000 else v

    @staticmethod
    def _p4_dword(b, o: int) -> int:
        return b[o] | (b[o + 1] << 8) | (b[o + 2] << 16) | (b[o + 3] << 24)

    @staticmethod
    def _p4_sbyte(b, o: int) -> int:
        v = b[o]
        return v - 0x100 if v & 0x80 else v

    # ---- 0x4505B0 -------------------------------------------------------
    def p4_enter(self) -> None:
        """阶段进场。返回语义同 `0x45AFF0(0x4AB5C0,0)`（旗标是否为空）。"""
        self.p4_frames = 0                        # [0x56CCA8]
        self.p4_speed = 1                         # 0x450D98 `[App+0x2C4] = 1`（1=常速，8=快进，0=4×泵）
        self.p4_intro_gate = False                # [0x56CCB4]（只有 0x423B7B 置 1）
        self._p4_sys = 0                          # 0x450B00 0x401AAA→0x45AF10(0x56CCB8) 清系统位
        self.p4_ccc8 = 1                          # 0x450B10 mov byte[0x56CCC8],1
        b = self.p4_block()                       # 0x4505F5..0x450A25

        self.p4_replay_header(b)                  # 0x450A25 0x401EB0 → 0x45D160
        self.p4_write_state(b)                    # 0x450A3D..0x450A83

        # 0x450A88..0x450AA1：0x458D60(App, a1..a4)（落点见 0x45EB7B/0x45EB95/0x460958/0x460961）
        #   a1=dword[blk+0x16] → 0x4CD4A0+0x2C（连击种子，取低字节）
        #   a2=word [blk+0x14] → 0x4CD4A0+0x30（倍率/本关帧数）
        #   a3=sbyte[blk+0x1A] → 0x4CD590+0x30（关卡，0xFF=-1 ⇒ 关卡数字节点隐藏）
        #   a4=sbyte[blk+0x19] → 0x4CD590+0x3C（倒数参数）
        self.p4_engine(self._p4_dword(b, 0x16), self._p4_sword(b, 0x14),
                       self._p4_sbyte(b, 0x1A), self._p4_sbyte(b, 0x19))

        # 0x450AAB..0x450B68：统计区 / 输入 / 回放清零 + 层参数
        self.p4_stat[0x56CC94] = 0                # 0x450AAB byte[0x56CC94]=0
        for a in P4_STAT_ZERO:                    # 0x450AB1..0x450B37
            self.p4_stat[a] = 0
        self.sysf.clear()                         # 0x450B05 0x45AF10(0x56CC84,0)
        self.p4_replay_reset()                    # 0x450B17 0x40224D
        self.p4_layer_params()                    # 0x450B3D..0x450B68（含 0x44CDF0 载调色板 1）
        self.p4_load_palette(1)                   # 0x450B60 0x44CDF0(0x4AA7B0,1,…) = bm_pal

        # 0x450B90 0x4013DE(0x4AB454,0,0)=SetBase(0,0)；0x450BA5 首次输入记录
        # 复刻侧：`run.py` 已在每次 `advance()` 之前调过 `0x44EB60`（`inp.build`），
        # 这里不再重建，否则会把按下沿（e0/e1）吃掉。
        self.inp.set_pos(0, 0)

        # 0x450BBD..0x450D59：21 条音效槽装载（0x450140）
        ok = True
        for slot, wav in P4_SE_SLOTS:
            if not self.load_wave(slot, wav):
                ok = False
                break
        if not ok:
            self.flags.set(8)                     # 0x450D62 `0x4AB5C0 |= 8`

        # 0x450D6E..0x450DA2
        self.vm_init_script(self._p4_dword(b, 0x0E))   # 0x401D84 → 0x4602D0(0x56CC4C,?)
        self.sysf.clear()                         # 0x450D7D 0x45AF10(0x56CC84,0)
        self.vm_step_frame()                      # 0x450D88 0x402149 → 0x460350
        self.p4_speed = 1                         # 0x450D98 `[App+0x2C4] = 1`
        if not self.timer.set_period(0):          # 0x450DA2 0x401CA3 → 0x45A490
            self.flags.set(0x40)                  # 0x450DAB
        self.log("page4.enter（0x4505B0）：参数块 → 0x401EB0 回放头 → 0x458D60 → 21 音效槽 → VM")
        print(f"[p4enter] flags=0x{self.flags.bits:X} vm_queue={self.vm.queue[:4]} "
              f"intro_gate={self.p4_intro_gate}", flush=True)

    def p4_write_state(self, b: bytearray) -> None:
        """`0x450A3D..0x450A83`：参数块 → 状态字四个位段。

        `0x450A5F movsx eax, byte[esp+0x20]` 读块内 `+0x10` 低字节（关索引字），与
        "`0xC000` = 自机选择"冲突，见 §16.119「仍待解」；此处按反汇编原样写入。
        """
        # 正常路径是**恒等回写**（读回的正是写进去的 4 个字节）；回放路径用录像值覆盖状态字。
        self._p4_or_andnot(self.keys, 1, b[0x1C])       # 0x450A3D/0x450A49 → bit0 鍛錬
        self._p4_or_andnot(self.keys, 2, b[0x1D])       # 0x450A4E/0x450A5A → bit1 操作器
        self.keys.set_field(0xC000, b[0x18])            # 0x450A5F/0x450A6F → bits14-15
        self._p4_or_andnot(self.keys, 0x200, b[0x1B])   # 0x450A74/0x450A83 → bit9

    @staticmethod
    def _p4_or_andnot(obj, mask: int, value: int) -> None:
        """`0x45B0A0`：`[+4] = ([+4] and-not mask) or (mask and value)`。"""
        obj.bits = (obj.bits & ~mask) | (mask & int(value))

    # ---- 0x458D60 -------------------------------------------------------
    def p4_engine(self, a1: int, a2: int, a3: int, a4: int) -> None:
        """10 队列 tick → `0x45EB40(a1,a2)` → `0x460930(a3,a4)` → `0x45D110`
        → `0x45C710(0x4AB5CC, bit0, bit1)` → `0x459A80(0x56B95C)` → `0x45AF10(0x56CC84,0)`。"""
        self.scene_reset()                        # 0x458D60..0x458DB5
        self.stage_globals(a1, a2)                # 0x458DBA 0x40163B → 0x45EB40
        self.stage_layers(a3, a4)                 # 0x458DCE 0x402522 → 0x460930
        self.replay_advance()                     # 0x458DE2 0x40160E → 0x45D110
        # 0x458DF3/0x458E00 `0x45C710(0x4AB5CC, bit0, bit1)`：记录流两档标志
        # （0x45C710 的字段语义待 §12 细读；此处按"两档位"写入）
        # 0x458DF3 `0x45AFF0(0x4AB5B0,1)` → arg2；0x458E00 `0x45AFF0(0x4AB5B0,2)` → arg1；
        # 0x458E0B `0x401D7A→0x45C710(ecx=0x4AB5CC, arg1, arg2)`：
        #   0x45C71A setne ⇒ byte[+4] = (arg1 != 0)
        #   0x45C720        ⇒ byte[+5] = byte(arg2)
        # 是两个**独立字节**，不是位掩码。
        self.sysf2.b4 = 1 if self.keys.test(2) else 0     # byte[0x4AB5CC+4]
        self.sysf2.b5 = 1 if self.keys.test(1) else 0     # byte[0x4AB5CC+5]
        self.stream_reset()                       # 0x458E15 0x402081 → 0x459A80(0x56B95C)
        self.sysf.clear()                         # 0x458E1C 0x45AF10(0x56CC84,0)

    # ---- 0x450FE0 -------------------------------------------------------
    def p4_flow_vm(self) -> None:
        """`0x450FE0`（0xF0 字节）：流程 VM 每帧一步 + 命令字分发。

        `0x450FF9 0x45B030(0x4AB5B0,1)`：位已置返回 0 ⇒ `je 0x451091`。
        故 **bit0 置 → 0x2E/0x58 分支；bit0 清 → cmd 0/9 分支**（与 §10.7 一致）。
        返回值被 `0x451110` 丢弃（`docs/p4_step_0x451110.md` 更正 2）。
        """
        if not self.vm_step_frame():              # 0x450FE5 0x402149 → 0x460350
            return
        cmd = self.vm_command()                   # 0x450FF2 0x40111D → 0x460800
        if self.keys.test(1):                     # 0x450FF9（位已置 ⇒ je 0x451091）
            if cmd == 0x2E:                       # 0x451096
                self.flags.set(0x400000)          # 0x4510A6
            elif cmd == 0x58:                     # 0x4510B6
                self.flags.set(0x800000)          # 0x4510C6
            return
        if cmd == 0:                              # 0x451015
            if self.sequence_started():           # 0x451055 0x460EE0(0x4CD590) 非 0
                self.stage_globals_end()          # 0x451025 0x45F760(0x4CD4A0)
                self.flags.set(0x200000)          # 0x451072
                return
            self.vm_restart(9)                    # 0x45107F 0x4602D0(0x56CC4C,9)
            self.sysf.clear()                     # 0x45108B 0x45AF10(0x56CC84,0)
            return
        if cmd == 9:                              # 0x451017
            self.stage_globals_end()              # 0x451025
            self.flags.set(0x400000 if self.sysb8.test(0x40) else 0x200000)  # 0x45102A..0x451049

    # ---- 0x451110 -------------------------------------------------------
    def p4_step(self) -> bool:
        """页4 每帧（S1..S25）。返回 `0x45AFF0(0x4AB5C0,0)`：旗标空 ⇒ 继续。"""
        skip = False
        # S1-S2（0x45112B `eax=[App+0x2C4]`；`je 0x451156` 时走"常速"）：只有 [App+0x2C4]!=0
        # 才做 `0x462D71([0x56CCA8], speed)` 取余，余数!=0 ⇒ `[esp+7]=0` 且 `jmp 0x451325` 整帧跳过。
        skip = self.p4_speed != 0 and self.p4_skip_mod()
        n = 1 if self.p4_speed != 0 else 4        # S3 0x451156 neg/sbb/and al,0xFD/add 4
        self.p4_pump(n)                           # S4 0x45116D
        if skip:
            # 0x451151 `jmp 0x451325`：跳过的是"泵 + 调试文字 + present"，**VM/输入/键码/帧计数照跑**，
            # 随后 0x451448 因 `[esp+7]==0` 改走 0x4CD484 序列引擎而不是碰撞/行为/绘制。
            self.p4_flow_vm()                     # 0x451327
            self.p4_after_vm()                    # 0x45132C..0x451423
            self.p4_frames += 1                   # 0x451442 [0x56CCA8]++
            self.p4_seq_tick()                    # 0x451457 0x4CD484
            return self.flags.is_empty()
        self.p4_debug_text()                      # S5-S6 0x451186（门 0x56CCC9 & 0x56CCB5）
        self.begin_frame()                        # S7 0x458CB0（含 present）
        self.p4_flow_vm()                         # S8 0x450FE0（返回值丢弃）
        self.p4_after_vm()                        # S9-S14
        self.p4_frames += 1                       # S15 0x451442
        self.band_draw()                          # S16 0x451457 0x4562A0
        if self.p4_collide() is not None:          # 0x4017FD → 0x43BF60（vtable 初始化，无副作用）
            self.p4_collide_pair(self._p4_q("ui40c"), self.p4_q43c)   # 0x451480 0x43BFD0(0x4AD40C,0x4AD43C)
            self.p4_43c060(self._p4_q("ui46c"), self.p4_q43c)         # 0x451493 0x43C060(0x4AD46C,0x4AD43C)
            self.p4_43c0f0(self._p4_q("ui49c"), self._p4_q("ui40c"))  # 0x4514A6 0x43C0F0(0x4AD49C,0x4AD40C)
        self.p4_bg_update()                       # S21 第一条 0x458E75 → 0x457BD0
        self.p4_dispatch()                        # S21 0x4514AD 0x458E70
        self.draw()                               # S22 0x4514B2 0x458EF0(App,1)
        self.band_advance()                       # 0x456270（0x458EF0 内尾调）
        self._p4_dbg()
        if self.p4_intro_gate:                    # S23 0x4514C3
            while self.p4_intro_frame():
                pass
        return self.flags.is_empty()              # S24 0x4514E9

    def p4_after_vm(self) -> None:
        """S9-S14：输入记录 / 回放 / SetCursorPos / 键命令 / 暂停 / 快进。"""
        # 0x45132C `0x44EB60(0x4AB454,0x56CC8C,0)`：复刻侧由 run.py 每帧调一次（同上）
        self.replay_record()                      # 0x451343 0x45D1D0
        self.replay_play()                        # 0x45135F（回放页）
        # 0x4513E3 `SetCursorPos(0x140,0xF0)`：把**系统光标**拉回画面中心，使下一帧的
        # 相对位移不越界。复刻侧由 run.py 每帧重置鼠标绝对基准（`_abs_mouse`），等价，
        # 这里不写 `inp.x/y`（那会把自机瞬移回中心）。
        self._p4_recenter_cursor()
        key = self.inp.rec.key
        if key:
            self.key_command(key)                 # 0x4513F3 0x458FD0（键2/5 在其内是空操作）
        if key == 2:                              # 0x451404 → 0x451B10 暂停循环
            self.p4_pause()
        elif key == 5:                            # 0x451423：`[App+0x2C4] = (旧==1 ? 8 : 1)`
            self.p4_speed = 8 if self.p4_speed == 1 else 1

    # ---- 0x451630 -------------------------------------------------------
    def p4_intro_frame(self) -> bool:
        """阶段首帧（`[0x56CCB4]` 门控）。返回 1 = 继续停在进场循环，0 = 进正常帧。"""
        if self.p4_intro_gate:
            self.p4_intro_gate = False            # 0x4516A3
            self.inp.set_preset(5)                # 0x451652 0x44E620(0x4AB454,5,0x140,0xF0,0)
            self.inp.set_pos(320, 240)
            # 0x45168E 0x44CDF0(0x4AA7B0,2,f(0xFE000000),f(0x1FC0000),0)：RT_STRING 2 = bm_pald
            if not self.p4_load_palette(2):
                self.flags.set(2)                 # 0x45169E
        self.begin_frame()                        # 0x4516AC/0x4516B3
        self.replay_record()                      # 0x4516BA（记录已由 run.py 建好）
        self._p4_recenter_cursor()                # 0x451779 SetCursorPos(0x140,0xF0)
        key = self.inp.rec.key
        if key:
            self.key_command(key)                 # 0x451788（无条件）
        self.band_draw()                          # 0x451792（无条件）
        self.draw()                               # 0x45179B 0x458EF0(App,1)（无条件）
        self.p4_hud()                             # 0x4517E1 HUD + 两准星
        if not self.flags.is_empty() or self.btn0_edge():   # 0x451974
            self.p4_load_palette(1)               # 0x451993 恢复亮调色板
            if self.btn0_edge() and self.inp.rec.x < 0x140:
                self.sequence_start()             # 0x4519F4 0x460E40(0x4CD590)
                self.stage_globals_begin()        # 0x4519FE 0x45F5C0(0x4CD4A0)
            return False
        return True                               # 0x45198D

    # ---- 0x451C50 -------------------------------------------------------
    def p4_finish(self) -> None:
        """页收尾：三条快退旗标直接返回；否则存盘 → 填 0xB4 + present ×2 → 释放层 → 页号映射。"""
        if self.audio is not None:
            self.audio.stop_bgm()
        if not self.timer.kill():                     # 0x451C62 0x45A510
            self.flags.set(0x40)                      # 0x451C72
        low = self.flags.lowest()                     # 0x451C7C 0x45B070
        if low in (0x200000, 0x400000, 0x800000):     # 0x451D86 / 0x451D7A / 0x451D6E
            self.page = {0x200000: 8, 0x400000: 9, 0x800000: 0x0A}[low]
            return
        if not self.replay_mode:                      # 0x451CA2 判 [0x56CCB5]
            self.replay_save_score()                  # 0x451CAB/0x451CB2
        for _ in range(2):                            # 0x451CC4/0x451CDA
            self.canvas.fill(0xB4)
            self.draw()
        self.layers.free_all()                        # 0x451CF5 0x44CEE0（14 层）
        low = self.flags.lowest()                     # 0x451CFF
        if low == 0x100:
            self.page = 0                             # 0x451D62
        elif low in (0x200, 0x10000):
            if self.replay_mode:
                self.page = 5                         # 0x451D38
            elif self.keys.test(1):
                self.page = 0x0C                      # 0x451D56
            else:
                self.page = 3                         # 0x451D60
        else:
            self.page = 0xFF                          # 0x451D19
        self.log(f"page4.finish（0x451C50）→ 页 {self.page:#x}（最低旗标 {low:#x}）")

    # ---- 复刻侧的胶水层（未定案的部分显式标注，不猜）----------------------
    def p4_ensure(self) -> None:
        """页4 的运行期状态（首次进入时建立）。"""
        if getattr(self, "_p4_ready", False):
            return
        self._p4_ready = True
        from geki import Flags
        self.p4_stat: dict[int, int] = {}
        self.p4_frames = 0
        self.p4_speed = 1
        self.p4_intro_gate = False
        self.p4_skip = 0
        self.sysf2 = Flags()          # 0x4AB5CC
        self.p4_bg = [BgSlot() for _ in range(12)]   # 0x4AD55C：12 槽 × 0x2A98
        self.sysb8 = Flags()          # 0x56CCB8
        self.replay_mode = False      # [0x56CCB5]
        self.stage_no = 0             # [0x4AB5C8]（关，0 基）
        self.loop_no = 0              # word[0x4AB5CA]（周目）
        self.p4_cstream: list[tuple[int, int]] = []
        self.p4_collide_ctx = None
        self.p4_ui49c: list = []
        self.p4_emit = []             # 0x4AD55C 发射器 12 通道
        self.p4_seq = None            # 0x4CD484 序列引擎
        self.p4_q43c: list = []       # 0x4AD43C 主实体队列（所有实体类型共用）
        self.p4_n43c = 0
        self.p4_beh_missing: dict[int, int] = {}
        self.p4_other: dict[int, list] = {}   # op1/3/4/5 的记录（ctor 未实现）
        # 0x56CC4C 脚本流状态机 + 资源表（0x45DDA0/0x45DDE0）
        from pathlib import Path
        bank = ScriptBank(Path(__file__).resolve().parent.parent.parent / "resource_dec.bin")
        self.vm = ScriptVM(bank, self._p4_block_data()["vm_chains"], owner=self)
        self.p4_level = 0             # 0x56CCB0"Level"

    def inp_keys(self):
        """run.py 每帧把键盘状态挂在 `self.kbd`（dict：shot/lock/left/right/up/down）。"""
        return getattr(self, "kbd", {}) or {}

    # -- 0x451110 的辅助
    def _p4_recenter_cursor(self) -> None:
        """0x4513E3/0x451779 `SetCursorPos(0x140,0xF0)`（见上：由 run.py 的绝对基准重置承担）。"""
        return

    def p4_pump(self, n: int) -> None:
        """0x45116D：`do { 0x458B80(App); [0x56CCAC]++ } while (--n)`。
        本复刻的帧门在 run.py 的 60Hz 循环里，这里只累计计数。"""
        for _ in range(max(1, n)):
            self.p4_stat[0x56CCAC] = self.p4_stat.get(0x56CCAC, 0) + 1

    def p4_skip_mod(self) -> bool:
        """0x451135 `0x462D71([0x56CCA8], [App+0x2C4])`：快进时按余数整帧跳过。
        余数非 0 ⇒ `[esp+7]=0` 并 `jmp 0x451325`（跳过绘制段）。"""
        f = self.p4_speed
        if f <= 1:
            return False
        return (self.p4_frames % f) != 0

    def p4_replay_frame(self) -> None:
        """`0x45134B`/`0x45135F`：每帧的回放录制或回放。

        ```
        ; [0x56CCB5] == 0（录制）
        0x451337 0x4010A5→0x44EB60(0x4AB454, 0x4AB594, 0x56CC8C)   ; BuildRecord
        0x45134B 0x402310→0x45D1D0(0x4CD5D8, 0x4AB594)             ; 记一帧
        ; [0x56CCB5] != 0（回放）
        0x45135F 0x402405→0x45D2B0(0x4CD5D8, &tmp)                 ; 取一帧
        0x451372 0x44EB60(0x4AB454, 0x4AB594, 0x56CC8C, &tmp)     ; 用回放帧建记录
        0x451387 if (byte[tmp+2]) App[0x2C4]++                      ; [0x4AB596] 加速
        0x451396 if (byte[tmp+3]) App[0x2C4] = 0                    ; [0x4AB597] 停
        0x4513A9 tmp[0..5] 复制到 [0x4AB594..0x4AB599]
        ```
        """
        rp = getattr(self, "p4_replay", None)
        if rp is None:
            rp = P4Replay()
            self.p4_replay = rp
        rec = self.inp.rec
        if self.replay_mode:                                  # 0x45135F
            tmp = bytearray(0x20)
            rp.play(tmp)                                      # 0x45D2B0
            rec.b0 = bool(tmp[0] & 1)                         # 0x4513A9 起 6 字节
            rec.b1 = bool(tmp[1] & 1)
            rec.e0 = bool(tmp[2] & 1)
            rec.e1 = bool(tmp[3] & 1)
            rec.r0 = bool(tmp[4] & 1)
            rec.r1 = bool(tmp[5] & 1)
            rec.dx = int.from_bytes(tmp[0x10:0x14], "little", signed=True)
            rec.dy = int.from_bytes(tmp[0x14:0x18], "little", signed=True)
            if tmp[2]:
                self.p4_speed += 1                            # 0x451390
            if tmp[3]:
                self.p4_speed = 0                             # 0x45139F
            rp.pos += 1
        else:                                                 # 0x45134B
            frame = bytearray(0x20)
            frame[0] = 1 if rec.b0 else 0
            frame[1] = 1 if rec.b1 else 0
            frame[0x10:0x14] = (rec.dx & 0xFFFFFFFF).to_bytes(4, "little")
            frame[0x14:0x18] = (rec.dy & 0xFFFFFFFF).to_bytes(4, "little")
            rp.record(frame)                                  # 0x45D1D0
            rp.pos += 1

    def p4_seq_tick(self) -> None:
        """`0x451457 0x402036 → 0x4562A0(0x4CD484)`：**色带引擎**（不是"序列引擎"）。

        反汇编逐字（`0x4562AB..0x456329`）：

        ```
        0x4562AB ecx=[obj+8]（起始索引）; edx=[obj+0xC]（滚动量）
        0x4562BB w = (i16)table[idx*4+2] - scroll          ; 只有起始条减滚动量
        0x4562C5 if (w + y > 0x1E0) w = 0x1E0 - y          ; 裁到屏高
        0x4562E5 rect = 0x40238D(0, y, 0x280, y+w)         ; 满屏宽竖条
        0x456316 0x401794(0x4AA7B0, 0, &rect, table[idx*4]) ; 用该条颜色填充
        0x456322 y += w; idx++ ; 直到 y >= 0x1E0
        ```
        ⇒ 与页1-3 的色带是**同一个函数**，页4 只是换了对象 `0x4CD484`。复刻侧复用 `band_draw()`。
        """
        if getattr(self, "band_table", None):
            self.band_draw()
        else:
            self.p4_stat[0x4CD484] = self.p4_stat.get(0x4CD484, 0) + 1

    def p4_debug_text(self) -> None:
        """0x451186..0x45131C：调试进度文字（门 `[0x56CCC9]` & `[0x56CCB5]`）。
        两个全局在页4 常态为 0 ⇒ 整段不执行；这里只记录门状态。"""
        return

    def p4_collide(self) -> None:
        """0x451461..0x4514A6：`0x43BF60` 建上下文，`ctx+0x54=0`，再跑三组：
        `0x43BFD0(ctx,0x4AD40C,0x4AD43C)`（演员×自弹）、`0x43C060(ctx,0x4AD46C,0x4AD43C)`
        （46C×自弹）、`0x43C0F0(ctx,0x4AD49C,0x4AD40C)`（49C×演员）。
        TODO(§10.7)：页4 的碰撞判定式（0x401843）与命中处理（0x401028/0x401136）尚未实现。"""
        return

    def p4_dispatch(self) -> None:
        """0x458E70：9 队列「行为 + 绘制」（顺序不能改：先 tick 的队列本帧生成的实体，
        会被后排队列当帧 tick 到）。页13 已按同一顺序实现，这里沿用。"""
        # 反汇编 0x458E70 的真实调用序（每条都是 `mov ecx,<队列>; call`）：
        #   0x458E75 0x4AD55C → 0x457BD0   背景 12 槽（本函数前于 S21 由 p4_bg_update 执行）
        #   0x458E7F 0x4AD40C → 0x448F80   演员
        #   0x458E89 0x4AD46C → 0x430220   节点池扫描（jmp [node+0x40] 行为）
        #   0x458E93 0x4AD43C → 0x43BC70   敌机/实体
        #   0x458E9D 0x4AD49C → 0x4353A0
        #   0x458EA7 0x4AD4CC → 0x43A350
        #   0x458EB1 0x4AD4FC → 0x44B0D0
        #   0x458EBB 0x4AD52C → 0x445A30
        #   0x458EC0 0x4CD484 → 0x456270   色带推进（复刻侧在 draw 之后单独调 band_advance）
        self.tick_ui(self.actorq)                 # 0x4AD40C → 0x448F80
        self.tick_ui(self.ui46c)                  # 0x4AD46C → 0x430220
        self._p4_tick_ents()                      # 0x4AD43C → 0x43BC70
        self.tick_ui(self.p4_ui49c)               # 0x4AD49C → 0x4353A0
        self._tick_wipe4f()                       # 0x4AD4CC → 0x43A350（同队列的另一半工作）
        self._tick_spark4cc()                     # 0x4AD4CC → 0x43A350（同上，不是独立队列）
        self.tick_ui(self.ui4fc)                  # 0x4AD4FC → 0x44B0D0
        self.tick_ui(self.ui52c)                  # 0x4AD52C → 0x445A30

    # ---- 自机输入/队列辅助（0x448C70 用）----------------------------------
    # ---- 碰撞（0x451461..0x4514A6 三组）------------------------------
    def p4_bit_any(self, mask: int) -> bool:
        """`0x45AFF0(obj, mask)`：**任一位被置**（`neg/sbb/neg` = `!!(v & mask)`）。

        mask 为 0 时退化为 `v == 0`（`0x45B006` 的 `sete`）。
        """
        return bool(self.p4_sys_bits() & mask) if mask else self.p4_sys_bits() == 0

    def p4_bit_none(self, mask: int) -> bool:
        """`0x45B030(obj, mask)`：**所有位都清**（`neg/sbb/inc` = `!(v & mask)`）。

        ★ 与 `0x45AFF0` 只差最后一条 `inc eax`（`0x45B041`）对 `neg eax`（`0x45B001`），
        语义正好相反。mask 为 0 时退化为 `v != 0`（`0x45B04C` 的 `setne`）。
        """
        return not (self.p4_sys_bits() & mask) if mask else self.p4_sys_bits() != 0

    def p4_sys_bits(self) -> int:
        """`0x56CCB8`：页4 系统状态位图（`0x43BFD4` 用它做碰撞总开关）。"""
        return int(getattr(self, "_p4_sys", 0))

    def p4_hit_test(self, e, x: int, y: int, r: int) -> bool:
        """`0x4306C0(ent, x, y, r)`：菱形（L1）判定。

        ```
        0x4306C0 if (!ent[0x10]) return 0
        0x4306D3 d = |ent[4]-x| + |ent[8]-y|          ; cdq/xor/sub 取绝对值
        0x4306F4 d += (ent[0xC]>>2) + (r>>2) - ent[0xC] - r
        0x430706 return d <= 0
        ```
        ⇒ 命中条件 `|dx| + |dy| <= r_e + r - (r_e>>2) - (r>>2)`。
        """
        if not e.g32(0x10):
            return False
        dx = e.s32(0x04) - x
        dy = e.s32(0x08) - y
        d = abs(dx) + abs(dy)
        er = e.s32(0x0C)
        d += (er >> 2) + (r >> 2) - er - r
        return d <= 0

    def p4_collide_pair(self, qa, qb) -> int:
        """`0x43BFD0(qa, qb)`：外层取 arg2 的 `[+0x28]` 链表、内层取 arg1 的，
        对每对 (a,b) 做 `0x4306C0(b, a[4], a[8], a[0xC])`，命中则 `0x43C170(this, b, a)`。"""
        hits = 0
        if self.p4_sys_bits() & 2:                    # 0x43BFD4 0x45AFF0(0x56CCB8,2)
            return 0
        for a in list(qa):
            if not a.g32(0x10):
                continue
            for b in list(qb):
                if not b.g32(0x10):
                    continue
                if self.p4_hit_test(b, a.s32(0x04), a.s32(0x08), a.s32(0x0C)):   # 0x43C011
                    self.p4_hit_cb(b, a)                                          # 0x43C01E → 0x43C170
                    hits += 1
        return hits

    def p4_hit_cb(self, b, a) -> None:
        """`0x43C170(b, a)`：命中回调。`b` = 我方子弹（arg1）、`a` = 被击中实体（arg2）。

        ```
        0x43C181 t = b[0x14]; dec → t==1：0x43C344 分支
        0x43C18B sub 5 → t==6：0x43C1AF 命中特效
        0x43C190 sub eax,0x0AFFFFFB → t == **0x0B000001**：自机被击中 ⇒
                 0x43C38B 0x460C00(0x4CD590) → 0x43C395 0x45F570(0x4CD4A0)
                 → 0x43C39F byte[0x10]=0 / [0x18]=0
        其余 → 直接返回
        ```

        ★ 自机类型是 **`0x0B000001`**（`0x44604E sub eax,0xAFFFFF7` 反推，
        并由此处 `0x43C190` 的 `sub eax,0x0AFFFFFB` 二次确认；
        `0x0B000001` 在二进制里只出现两处：`0x44372C`（帧处理）与 `0x448DBB`（自机行为内部））。
        旧笔记把它写成 `0x10000001`，那是**另一类实体**
        （`0x10000001` 出现在 `0x43F7D8` / `0x43FE59` / `0x440054` 与数据表 `0x49CE45`）——
        见勘误 A-57。
        """
        t = b.s32(0x14)
        if t == 1:                                        # 0x43C344
            if b.g32(0x30) or b.s32(0x20) <= 0x12C:
                return
            if a.s32(0x14) in (0x27000011, 0x29000013):
                return
            if b.s32(0x28) == 3:
                b.d32(0x28, 0)
                b.d32(0x20, 0x79)
                return
            b.d32(0x10, 0)                                # 0x43C39F
            b.d32(0x18, 0)
            return
        if t == 6:                                        # 0x43C1AF 命中特效
            jx = (rng.randrange(0x20) - 0xF)
            jy = (rng.randrange(0x20) - 0xF)
            self.spawn(self._p4_q("ui4cc"), 0x41000004,
                       a.s32(0x04) + jx, a.s32(0x08) + jy)   # 0x43C1DA..0x43C20A
            if a.s32(0x18) <= 1:                          # 0x43C212 ja → 血量>1 才走扣血
                self.p4_stat[0xC2] = self.p4_stat.get(0xC2, 0) + 1   # 0x43C21B.. 最后一击特判（待实现）
        elif t == 0x0B000001:                             # 0x43C190 自机被击中
            self.p4_460c00()                              # 0x43C38B 死亡演出/命数
            self.p4_45f570()                              # 0x43C395 量表重置
            b.d32(0x10, 0)                                # 0x43C39F byte[+0x10] = 0
            b.d32(0x18, 0)                                # 0x43C3A2 [+0x18] = 0
            return
        else:
            return
        a.d32(0x18, (a.s32(0x18) - 1) & 0xFFFFFFFF)       # 0x43C30D 血量减一
        if self.p4_frame_no() & 7:                        # 0x43C311 [0x56CCA8] & 7
            return
        self.p4_se_pan(5, (a.s32(0x04) - 0x140) << 4)     # 0x43C326 0x4013A2(0x4AB4B0,5,…)

    def p4_hud_rect(self, value: int) -> tuple:
        """`0x460A90`：数字字形矩形。`eax = ([+0x30]-1) % 10`，每字 24 px，行 0x150..0x167。

        ```
        0x460A98 ecx = 10; push 0x167
        0x460AA2 eax = [esi+0x30]; dec eax; idiv 10   ; edx = 余数
        0x460AA9 eax = edx*3; shl eax,3               ; *24
        0x460AAF edx = eax + 0x17
        0x460ABD 0x40238D(&rect, eax, 0x150, eax+0x17, 0x167)
        ```
        """
        d = (value - 1) % 10                              # 0x460AA2..0x460AA7
        x = d * 0x18                                      # 0x460AA9
        return (x, 0x150, x + 0x17, 0x167)

    class HudObj:
        """HUD 对象：`0x45EF10` 要写 `+0xEC`，比 0x5C 的实体大，故独立缓冲。"""

        def __init__(self) -> None:
            self.buf = bytearray(0x100)

        def d32(self, off: int, v: int) -> None:
            self.buf[off:off + 4] = (v & 0xFFFFFFFF).to_bytes(4, "little")

        def g32(self, off: int) -> int:
            return int.from_bytes(self.buf[off:off + 4], "little")

        def s32(self, off: int) -> int:
            v = self.g32(off)
            return v - 0x100000000 if v >= 0x80000000 else v

        def s16(self, off: int) -> int:
            v = int.from_bytes(self.buf[off:off + 2], "little")
            return v - 0x10000 if v >= 0x8000 else v

    # HUD 对象 `0x4A4B64` 的种类表（`0x45EF2C mov edx,[eax*4+0x4A4B64]`）
    P4_HUD_KIND = (0x0, 0x4993CC, 0x499438, 0x499480, 0x4994B0,
                   0x499514, 0x49955C, 0x4995C0)

    def p4_hud_ctor(self, h, kind: int) -> None:
        """`0x45EF10(ret 4)`：HUD 对象构造。

        ```
        0x45EF10 edx = ecx+0x14; eax = 0
        0x45EF15 [edx..edx+0xC] 清 4 个 dword
        0x45EF20 ax = arg(word); [ecx+0x24] = ax
        0x45EF2C edx = [eax*4 + 0x4A4B64]     ; 种类表
        0x45EF33 [ecx+0xEC] = edx
        ```
        """
        if isinstance(h, int) or h is None:
            h = self.HudObj()
        for i in range(4):
            h.d32(0x14 + 4 * i, 0)
        h.d32(0x24, kind & 0xFFFF)                       # 0x45EF25
        h.d32(0xEC, self.P4_HUD_KIND[kind & 0xFF] if (kind & 0xFF) < len(self.P4_HUD_KIND) else 0)
        return h

    def p4_hud_draw(self, h) -> None:
        """`0x45EED0`：HUD 每帧入口。

        ```
        0x45EED3 if ([h+0xE1]) { 0x401203→0x45E020(h); [h+0xE1] = 0 }
        0x45EEEB 0x401695→0x45E340(h)
        0x45EEF3 0x4011FE→0x45A170(h+0x64)      ; 渲染显示表
        ```
        `0x45E020`（一次性重建）与 `0x45E340`（数字排版）尚未逐条展开，先按序调用占位统计。
        """
        if h.g32(0xE1):
            self.p4_hud_rebuild(h)                   # 0x45E020
            h.d32(0xE1, 0)
        self.p4_hud_layout(h)                        # 0x45E340
        self.p4_stat[0x45A170] = self.p4_stat.get(0x45A170, 0) + 1   # 0x45EEF3 渲染 h+0x64

    def p4_hud_rebuild(self, h) -> None:
        """`0x45E020`：HUD 一次性重建（待展开）。"""
        self.p4_stat[0x45E020] = self.p4_stat.get(0x45E020, 0) + 1

    def p4_hud_layout(self, h) -> None:
        """`0x45E340`：血条/能量条排版。

        ```
        0x45E347 v = s16[+0x26]
        0x45E34B if (v < 0xA0) {                      ; 未满：分段小格
                    i = v >> 4
                    node[+0xDC].src = (i*0x18, 0x1E0, i*0x18+0x17, 0x1F7);  return }
        0x45E3A6 if (node[+0xDC].src.top != 0x1C8) {   ; 首次满格
                    node.src = (0x48, 0x1C8, 0x5F, 0x1DF); [+0xE0] = 0 }
        0x45E3FD [+0xE0] = (node.src.left == 0)
        0x45E41A [+0xE0] ? 0x45A790(node, 0x18,0,0x18,0) : 0x45A790(node,-0x18,0,-0x18,0)
        ```
        """
        v = h.s16(0x26)
        if v < 0xA0:                                       # 0x45E34B
            i = (v >> 4) & 0xF
            x = i * 0x18
            if h.node is not None:
                h.node.src = (x, 0x1E0, x + 0x17, 0x1F7)
            return
        if h.node is not None and h.node.src[1] != 0x1C8:  # 0x45E3A6
            h.node.src = (0x48, 0x1C8, 0x5F, 0x1DF)
            h.d32(0xE0, 0)
        if h.node is not None:
            h.d32(0xE0, 1 if h.node.src[0] == 0 else 0)    # 0x45E3FD 至 0x45E40E
            d = 0x18 if h.g32(0xE0) else -0x18             # 0x45E41A / 0x45E435
            self.p4_anim_step(h)

    def p4_hud_update(self, e) -> None:
        """`0x460A90`：把数字矩形写进显示节点 `[+0x2C]+4`，再 `0x4011FE` 推进渲染表。"""
        if e.node is not None:
            e.node.src = self.p4_hud_rect(e.s32(0x30))    # 0x460ACE..0x460AE4
            e.node.visible = 1
        self.p4_stat[0x11FE] = self.p4_stat.get(0x11FE, 0) + 1   # 0x460AE7 → 0x45A170

    def p4_frame_no(self) -> int:
        """`[0x56CCA8]`：全局帧计数器（`0x451442` 每帧 ++）。"""
        return int(getattr(self, "p4_frames", 0))

    def p4_460c00(self) -> None:
        """`0x460C00(0x4CD590)`（`0x43C38B` 调用）：自机死亡演出 + 命数递减（§16.198/§16.199）。

        ```
        0x460C00 word[0x56CCB0] -= min(…, 8)                    ; 饱和减 8
        0x460C2A 0x450350(0x0B, ([0x56CC8C]−0x140)<<4)          ; SE 0x0B + 声像
        0x460C59 0x41000001 @ ([0x56CC8C],[0x56CC90]) → 0x4AD4CC
        0x460C8C 0x4100000E × 4（vel 0..3）                      → 0x4AD4CC
        0x460CBD 0x41000004 × 30，抖动 (rand&0x7F)−0x3F，第 5 字段 = &(jx,jy)
        0x460D08 类型 1 @ 自机位置，vel 1                        → 0x4AD40C（演员队列）
        0x460D24 [+0x34]++ / [+0x38]++ ; [+0x30] 命数递减（− 1 = 无限）
        0x460D42 byte[[0x4CD590+0x2C] + 0x1C] = 0 ; 0x51000002 @ (0,0) → 0x4AD4FC
        ```
        """
        M = 0x4CD590
        ax = self.p4_stat.get(0x56CCB0, 0) & 0xFFFF          # 0x460C00
        sax = ax - 0x10000 if ax & 0x8000 else ax            # 0x460C12 movsx
        d = 8 if sax >= 8 else sax                           # 0x460C09 / 0x460C17
        self.p4_stat[0x56CCB0] = (ax - d) & 0xFFFF           # 0x460C24
        px = self.p4_stat.get(0x56CC8C, 0)
        py = self.p4_stat.get(0x56CC90, 0)
        self.p4_se_pan(0x0B, (px - 0x140) << 4)              # 0x460C3A
        qfx = self._p4_q("ui4cc")                            # 0x4AD4CC
        self.spawn(qfx, 0x41000001, px, py)                  # 0x460C59
        for i in range(4):                                   # 0x460C9C..0x460CB7
            self.spawn(qfx, 0x4100000E, px, py, i)           # vel = 0,1,2,3
        for _ in range(0x1E):                                # 0x460CCE..0x460D06
            jx = rng.randrange(0x80) - 0x3F                  # 0x460CD3 / 0x460CD6
            jy = rng.randrange(0x80) - 0x3F                  # 0x460CDF / 0x460CE2
            self.spawn(qfx, 0x41000004, px + jx, py + jy)    # 第 5 字段 = &(jx,jy)
        self.spawn(self._p4_q("ui40c"), 1, px, py, 1)        # 0x460D1F 演员队列
        self.p4_stat[M + 0x34] = self.p4_stat.get(M + 0x34, 0) + 1   # 0x460D2D
        self.p4_stat[M + 0x38] = self.p4_stat.get(M + 0x38, 0) + 1   # 0x460D32
        lives = self.p4_stat.get(M + 0x30, 0)                # 0x460D2A
        if lives != 0xFFFFFFFF:                              # 0x460D2F cmp eax,-1
            lives = (lives - 1) & 0xFFFFFFFF                 # 0x460D3A
            self.p4_stat[M + 0x30] = lives
            if lives == 0:                                   # 0x460D40 jne
                # 0x460D42 是 `byte[[0x4CD590+0x2C] + 0x1C] = 0`——该指针的写入点
                # 尚未定位（§15），故此处不写，避免凭空造一个实体。
                self.spawn(self._p4_q("ui4fc"), 0x51000002, 0, 0)   # 0x460D78

    def p4_45f660(self) -> None:
        """`0x401FD2` → `0x45F660(0x4CD4A0)`：`[+0x30] = max(0, [+0x30] − 5)`（饱和减 5）。

        ```
        0x45F660 eax = [ecx+0x30] ; 0x45F663 cmp eax,5 ; 0x45F666 jbe → 置 0 ; 否则 eax -= 5
        ```
        """
        v = self.p4_stat.get(0x4CD4A0 + 0x30, 0) & 0xFFFFFFFF
        self.p4_stat[0x4CD4A0 + 0x30] = (v - 5) & 0xFFFFFFFF if v > 5 else 0

    # ---- `0x4CD4A0` 命中/得分显示结构的四个写入口（§16.209）----
    def p4_45f5f0(self, x: int, y: int) -> None:
        """`0x45F5F0(mgr, x, y)`：主计数 —— 每命中一次 `[+0x14]` 与 `[+4]` 各加 `n*200`。

        ```
        0x45F5F3 eax = [+0x30] ; inc ; [+0x30] = eax        ; 连击数 n
        0x45F5F6 word[+0x5E]++                              ; 另一个计数
        0x45F604 lea [eax+eax*4] ×2 → 25n ; 0x45F612 shl 3 → **200n**
        0x45F615/0x45F619 [+0x14] += 200n
        0x45F617/0x45F620 [+4]    += 200n
        0x45F62C 0x45E4A0(mgr, 200n, y, x)                  ; 数字渲染（未实现）
        0x45F631 byte[+0xE1] = 1
        ```
        """
        n = (self.p4_stat.get(0x4CD4A0 + 0x30, 0) + 1) & 0xFFFFFFFF
        self.p4_stat[0x4CD4A0 + 0x30] = n                       # 0x45F5FE
        self.p4_stat[0x4CD4A0 + 0x5E] = (self.p4_stat.get(0x4CD4A0 + 0x5E, 0) + 1) & 0xFFFF
        e = (n * 200) & 0xFFFFFFFF                              # 0x45F604..0x45F612
        self.p4_stat[0x4CD4A0 + 0x14] = (self.p4_stat.get(0x4CD4A0 + 0x14, 0) + e) & 0xFFFFFFFF
        self.p4_stat[0x4CD4A0 + 0x04] = (self.p4_stat.get(0x4CD4A0 + 0x04, 0) + e) & 0xFFFFFFFF
        self.p4_45e4a0(e, x, y)                                 # 0x45F62C 0x45E4A0(mgr, e, x, y)
        self.p4_stat[0x4CD4A0 + 0xE1] = 1                       # 0x45F631

    def p4_45f690(self, x: int, y: int) -> None:
        """`0x45F690`：`word[+0x2C] == 0xC` 才进位（`0x45F69B` 的 `66 3D 0C 00`）。"""
        ax = self.p4_stat.get(0x4CD4A0 + 0x2C, 0) & 0xFFFF      # 0x45F693
        self.p4_stat[0x4CD4A0 + 0x60] = (self.p4_stat.get(0x4CD4A0 + 0x60, 0) + 1) & 0xFFFF
        if ax == 0xC:                                           # 0x45F69B
            self.p4_45f5f0(x, y)                                # 0x45F6AD
            self.p4_stat[0x4CD4A0 + 0x26] = (self.p4_stat.get(0x4CD4A0 + 0x26, 0) + 8) & 0xFFFF

    def p4_45f6e0(self, x: int, y: int) -> None:
        """`0x45F6E0`：先 `word[+0x26] = 0xA0` 再计数。"""
        self.p4_stat[0x4CD4A0 + 0x26] = 0xA0                     # 0x45F6EA
        self.p4_45f5f0(x, y)                                    # 0x45F6F0

    def p4_460e00(self, x: int, y: int) -> None:
        """`0x460E00`：十次一循环，`-1` 是已满标记。"""
        eax = self.p4_stat.get(0x4CD4A0 + 0x30, 0)              # 0x460E00
        if eax >= 0xA or eax == -1:                             # 0x460E03 / 0x460E08
            self.p4_45f690(x, y)                                # 0x460E23
        else:
            self.p4_stat[0x4CD4A0 + 0x30] = eax + 1             # 0x460E0D

    def p4_45e7a0(self, a: int, b: int) -> int:
        """`0x45E7A0(a, b)` = **`a*1000/b`**（无符号），`a > 0x200000` 时两边同步右移防溢出。

        ```
        0x45E7A4 if (b == 0) return 0                    ; 0x45E7A8 xor ax,ax
        0x45E7B2 while (a > 0x200000) { a >>= 1 ; b >>= 1 }
        0x45E7C4 lea ×3 → a*125 ; 0x45E7CF shl 3 → **a*1000**
        0x45E7D2 div ecx                                 ; 无符号除
        ```
        `ecx`（this）在函数体里从未使用 —— 它是被忽略的 `__thiscall` 第一参数。
        """
        if b == 0:
            return 0                                     # 0x45E7A8
        a &= 0xFFFFFFFF
        b &= 0xFFFFFFFF
        while a > 0x200000:                              # 0x45E7B2
            a >>= 1
            b >>= 1
        if b == 0:
            return 0
        return (a * 1000) // b                           # 0x45E7C4..0x45E7D2

    def p4_45f760(self) -> None:
        """`0x45F760(obj)`：结算时把三项得分累加进 `obj[+4]`。

        `obj` 是 **`0x4CD4A0`** 那个大结构（与 `0x45F5F0` 同一个；注意它比 `Ent` 的 0x5C 大得多，
        `[+0xE1]` 就在 `Ent.SZ` 之外）。

        ```
        0x45F76D r1 = 0x45E7A0(obj, [+8], [+0x10]) & 0xFFFF
        0x45F77A lea ×2 → r1*25 ; 0x45F783 shl 4 → **r1*400**
        0x45F788 [+4] += r1*400
        0x45F792 r2 = 0x45E7A0(obj, [+0xC], [+8]) & 0xFFFF
        0x45F7AF [+4] += r2*400
        0x45F7B2 v = 0x460EA0(0x4CD590) = **[0x4CD590+0x30]**（0x460EA0 就是 `mov eax,[ecx+0x30]; ret`）
        0x45F7B7 if (v != -1) { 0x45F7C6 lea ×5 → v*3125 ; shl 6 → **v*200000** ; [+4] += v*200000 }
        0x45F7E0 byte[+0xE1] = 1
        ```
        """
        m = 0x4CD4A0
        base = self.p4_stat.get(m + 0x04, 0)                                 # 0x45F788 的累加器
        r1 = self.p4_45e7a0(self.p4_stat.get(m + 0x08, 0), self.p4_stat.get(m + 0x10, 0)) & 0xFFFF
        base = (base + r1 * 400) & 0xFFFFFFFF                               # 0x45F788
        r2 = self.p4_45e7a0(self.p4_stat.get(m + 0x0C, 0), self.p4_stat.get(m + 0x08, 0)) & 0xFFFF
        base = (base + r2 * 400) & 0xFFFFFFFF                               # 0x45F7AF
        self.p4_stat[m + 0x04] = base
        v = self.p4_stat.get(0x4CD590 + 0x30, 0) & 0xFFFFFFFF               # 0x45F7B2
        if v != 0xFFFFFFFF:                                                 # 0x45F7BA je 0x45F7E0
            self.p4_stat[m + 0x04] = (base + ((v * 200000) & 0xFFFFFFFF)) & 0xFFFFFFFF   # 0x45F7DD
        self.p4_stat[m + 0xE1] = 1                                          # 0x45F7E0

    def p4_460280(self, o) -> None:
        """`0x460280(this)`：清空文本对象（释放 `[+0x2C]` 缓冲并复位所有字段）。"""
        o.d32(0x04, 0)                                  # 0x460289
        o.d16(0x08, 0)                                  # 0x460292
        o.d16(0x0A, 0)                                  # 0x460296
        o.buf2c = None                             # 0x460299 0x47C7E9 释放
        o.d32(0x2C, 0)                                  # 0x4602AC
        o.d32(0x30, 0)                                  # 0x4602B2
        o.m[0x34] = 0                                   # 0x4602B6
        o.d32(0x38, 0)                                  # 0x4602B2 0x45AF10(this+0x38, 0xFF) 清标志字
        o.flags38 = 0

    def p4_4602d0(self, o, sid: int) -> None:
        """`0x4602D0(this, sid)`：按 `0x499798` 表把一串字形 id 填进 `this+0xA`（最多 15 个）。

        ```
        0x460284 0x460280(this)                          ; 先清空
        0x4602DF movsx eax,cx ; 0x4602E2 word[this+0x2A] = sid
        0x4602E6 ax = word[0x499798 + sid*2]
        0x4602F6 while (n < 0xF && ax) { word[this+0xA+2n] = ax ; n++ ; sid++ ; ax = 表[sid] }
        0x460315 word[this+0xA+2n] = 0                   ; 结尾 0
        0x46031C 0x4600F0(this)                          ; 立刻推进一个
        ```
        表内容（`0x499798`，见 `remake/p4_str_table.json`）= `45 46 47 48 49 50 51 52 0 60 0`。
        """
        self.p4_460280(o)                               # 0x460284
        o.d16(0x2A, sid & 0xFFFF)                       # 0x4602E2
        tab = p4_str_table()
        n = 0
        i = sid
        while n < 0xF:                                  # 0x4602F6
            ch = tab[i] if 0 <= i < len(tab) else 0
            if ch == 0:                                 # 0x4602F1
                break
            o.d16(0x0A + n * 2, ch)
            n += 1
            i += 1
        o.d16(0x0A + n * 2, 0)                          # 0x460315
        self.p4_4600f0(o)                               # 0x46031C

    def p4_45e670(self, rec, f: int, g: int, h: int) -> None:
        """`0x45E670(mgr, rec, f, g, h)`：按 `rec[4]` 的 bit0/bit1 把 `rec[0]`（word）累加到 mgr。

        ```
        0x45E675 f = byte[arg2]  0x45E69F g = byte[arg3]  0x45E6C5 h = byte[arg4]
        每块：if (flag) { if (!(rec[4]&1)) [mgr+A] += rec[0] ; if (!(rec[4]&2)) [mgr+B] += rec[0] }
        f → A=0x20 B=0x10 ; g → A=0x18 B=0x08 ; h → A=0x1C B=0x0C
        ```
        """
        m = 0x4CD4A0
        val = rec["b0"] if isinstance(rec, dict) else 0
        fl = rec["b4"] if isinstance(rec, dict) else 0
        for flag, (fa, fb) in ((f, (0x20, 0x10)), (g, (0x18, 0x08)), (h, (0x1C, 0x0C))):
            if not flag:
                continue
            if not (fl & 1):                                    # 0x45E680 / 0x45E6A6 / 0x45E6CC
                self.p4_stat[m + fa] = (self.p4_stat.get(m + fa, 0) + val) & 0xFFFFFFFF
            if not (fl & 2):                                    # 0x45E68F / 0x45E6B5 / 0x45E6DB
                self.p4_stat[m + fb] = (self.p4_stat.get(m + fb, 0) + val) & 0xFFFFFFFF

    def p4_45eff0(self, typ: int, arg2: int = 0, arg3: int = 0, arg4: int = 0) -> None:
        """`0x45EFF0(mgr, type, a, b, c)`：**全局效果分发**（数值累加 + 字形 + 里程）。

        ```
        0x45F00E if ([mgr+0xEC] == 0) → ret            ; 表未就绪
        0x45F024 [mgr+0x50]++                          ; 调用计数
        0x45F029 eax = 0x21 族 ? [0x4993C4+i] : [[mgr+0xEC]+i*4]
        0x45F05F 0x45DFB0(&rec, eax)                   ; 位域拆包
        0x45F074 0x45E670(mgr, &rec, 0, 1, 0)
        0x45F079 if (rec[4] & 4) 0x45E670(mgr, &rec, 1, 0, 0)
        0x45F092 按 (type & 0xF00) 五路：
          0x100 → eb = rec[0] ; word[mgr+0x26]++
          0x200 → eb = rec[0]*2 ; word[mgr+0x26]++
          0x300 → 0x45E670(mgr,&rec,0,0,1) ; eb = 0x45E710(&rec, 8) ; 0x45E4A0(mgr, eb, arg2, arg3)
          0x400 → word[mgr+0x58]++ ; word[mgr+0x26]=0 ; 0x45E670(mgr,&rec,0,0,1) ; eb = 0x45E710(&rec, 2)
          0x500 → [mgr+0x54]++ ; word[mgr+0x26]++ ; 0x45E670(mgr,&rec,0,0,1)
                  eb = 0x45E710(&rec, word[0x56CCA4]) ; 0x45E4A0(mgr, eb, arg2, arg3)
                  word[mgr+0x28]++ ; 满 0x32 → 造 0x32000004 入 0x4AD49C 且 word[mgr+0x28]=0
                  byte[mgr+0x2A] 非零 → word[0x56CCB0]++ 且造 0x32000005
          其它  → eb = rec[0]
        0x45F244 [mgr+4] += eb ; [mgr+0x14] += eb
        0x45F2FB 尾段 → p4_45f2fb
        ```

        未落地：`[mgr+4] > [mgr+0xE4]` 时的缓冲重建（`0x45FB80`/`0x45FBF0`/`0x45FCB0`/`0x45FBD0`）。
        """
        m = 0x4CD4A0
        base = self.p4_stat.get(m + 0xEC, 0)                     # 0x45F00E
        if not base:
            return
        self.p4_stat[m + 0x50] = (self.p4_stat.get(m + 0x50, 0) + 1) & 0xFFFFFFFF   # 0x45F024
        i = typ & 0xFF
        if (typ & 0xFF000000) == 0x21000000:                    # 0x45F031
            tbl = p4_tbl_4993c4()
            entry = tbl[i] if 0 <= i < len(tbl) else 0
        else:
            entry = self.p4_stat.get(base + i * 4, 0) & 0xFFFFFFFF
        rec = self.p4_45dfb0(entry)                             # 0x45F05F
        self.p4_45e670(rec, 0, 1, 0)                            # 0x45F074
        if rec["b4"] & 4:                                       # 0x45F079
            self.p4_45e670(rec, 1, 0, 0)                        # 0x45F08D
        sel = typ & 0xF00                                       # 0x45F092
        eb = rec["b0"]
        if sel == 0x100:                                        # 0x45F0C9
            self.p4_stat[m + 0x26] = (self.p4_stat.get(m + 0x26, 0) + 1) & 0xFFFF
        elif sel == 0x200:                                      # 0x45F0B9
            eb = (rec["b0"] * 2) & 0xFFFFFFFF
            self.p4_stat[m + 0x26] = (self.p4_stat.get(m + 0x26, 0) + 1) & 0xFFFF
        elif sel == 0x300:                                      # 0x45F0D6
            self.p4_45e670(rec, 0, 0, 1)
            eb = self.p4_45e710(rec, 8)                         # 0x45F0F1
            self.p4_45e4a0(eb, arg2, arg3)                      # 0x45F10B
        elif sel == 0x400:                                      # 0x45F212
            self.p4_stat[m + 0x58] = (self.p4_stat.get(m + 0x58, 0) + 1) & 0xFFFF
            self.p4_stat[m + 0x26] = 0
            self.p4_45e670(rec, 0, 0, 1)
            eb = self.p4_45e710(rec, 2)                         # 0x45F237
        elif sel == 0x500:                                      # 0x45F12B
            self.p4_stat[m + 0x54] = (self.p4_stat.get(m + 0x54, 0) + 1) & 0xFFFFFFFF
            self.p4_stat[m + 0x26] = (self.p4_stat.get(m + 0x26, 0) + 1) & 0xFFFF
            self.p4_45e670(rec, 0, 0, 1)
            eb = self.p4_45e710(rec, self.p4_stat.get(0x56CCA4, 0) & 0xFFFF)   # 0x45F156
            self.p4_45e4a0(eb, arg2, arg3)                      # 0x45F170
            n = (self.p4_stat.get(m + 0x28, 0) + 1) & 0xFFFF    # 0x45F175
            self.p4_stat[m + 0x28] = n
            if n >= 0x32:                                       # 0x45F17D
                self.spawn(self._p4_q("ui49c"), 0x32000004, arg2, arg3, 0)   # 0x45F194
                self.p4_stat[m + 0x28] = 0                      # 0x45F1C6
            if self.p4_stat.get(m + 0x2A, 0) & 0xFF:            # 0x45F1CF
                self.p4_stat[0x56CCB0] = (self.p4_stat.get(0x56CCB0, 0) + 1) & 0xFFFF   # 0x45F1D3
                # 0x45F1DA..0x45F1FB 造 0x32000005 并入队；因该区间线性反汇编失步，
                # 入队目标队列尚未确认，故暂不生成实体（§15）。
        self.p4_stat[m + 0x04] = (self.p4_stat.get(m + 0x04, 0) + eb) & 0xFFFFFFFF   # 0x45F252
        self.p4_stat[m + 0x14] = (self.p4_stat.get(m + 0x14, 0) + eb) & 0xFFFFFFFF   # 0x45F25E
        # 0x45F25C：分数超过阈值 → 重建 HUD 缓冲并推进阈值档位
        if (self.p4_stat[m + 0x04] & 0xFFFFFFFF) > self.p4_stat.get(m + 0xE4, 0):
            self.p4_stat[m + 0xE8] = bytearray(self.p4_45fbf0())     # 0x45F294 0x47C7C0(size)
            # 0x45F2A7 0x45FCB0(0xE8, buf) 填充缓冲 —— 该函数未读，内容暂缺（§15）
            ax = self.p4_stat.get(m + 0xE2, 0) & 0xFFFF             # 0x45F2AC
            if ax == 0:
                self.p4_stat[m + 0xE4] = 0xFFFFFFFF                  # 0x45F2B8（无限）
            else:
                ax -= 1
                self.p4_stat[m + 0xE2] = ax                          # 0x45F2C8
                self.p4_stat[m + 0xE4] = self.p4_45c740(ax)           # 0x45F2D9
        self.p4_45f2fb()                                        # 0x45F2FB

    def p4_45e710(self, rec, d: int) -> int:
        """`0x45E710(mgr, rec, d)`：连击倍率 —— 把 `d` 与 `rec[5]`、`rec[0]` 乘起来。

        ```
        0x45E710 ax = word[mgr+0x5A] ; 0x45E71B if (ax > d) 保留 ax 否则 ax = d
        0x45E725 word[mgr+0x5A] = ax                       ; 记录历史最大值
        0x45E729 bl = rec[5]
        0x45E72E if (bl == 0) → 0x45E75B: eax = 1
        0x45E730 dx = min(d, 0x64)                         ; 封顶 100
        0x45E73E ax = word[mgr+0x2C] ; 0x45E749 封顶 0xA
        0x45E750 eax = (ax + dx)
        0x45E756 eax *= (signed char)bl
        0x45E760 dx = word[mgr+0x5C] ; 0x45E767 if (dx <= eax) dx = eax
        0x45E76E word[mgr+0x5C] = dx                       ; 又一个最大值
        0x45E772 eax *= rec[0]                             ; imul eax,[esi]
        ```
        ★ 返回值是**未封顶的** `(min(word[0x2C],10) + min(d,100)) * rec[5] * rec[0]`；
        `word[mgr+0x5A]` / `word[mgr+0x5C]` 只是旁路记录最大值，不参与返回。
        """
        m = 0x4CD4A0
        a = self.p4_stat.get(m + 0x5A, 0) & 0xFFFF              # 0x45E710
        a = a if a > (d & 0xFFFF) else (d & 0xFFFF)             # 0x45E71B
        self.p4_stat[m + 0x5A] = a                              # 0x45E725
        if isinstance(rec, dict):
            b0, bl = rec["b0"], rec["b5"]                        # 0x45E710 rec[0] / rec[5]
        else:
            b0, bl = (rec[0] if rec else 0), (rec[5] if len(rec) > 5 else 0)
        if bl == 0:
            e = 1                                               # 0x45E75B
        else:
            dx = min(d & 0xFFFF, 0x64)                          # 0x45E730
            ax = min(self.p4_stat.get(m + 0x2C, 0) & 0xFFFF, 0xA)   # 0x45E73E
            e = (ax + dx) & 0xFFFFFFFF                          # 0x45E750
            sb = bl - 0x100 if bl & 0x80 else bl                # movsx
            e = (e * sb) & 0xFFFFFFFF                           # 0x45E756
        c = self.p4_stat.get(m + 0x5C, 0) & 0xFFFF              # 0x45E760
        if c <= e:
            c = e
        self.p4_stat[m + 0x5C] = c                              # 0x45E76E
        return (e * b0) & 0xFFFFFFFF                            # 0x45E772

    # `0x4AB5CC` 是**运行期对象**（exe 镜像里全 0，属 BSS），由某处构造器填充，
    # 没有静态数据可提取（`re_dis.writes_to(0x4AB5CC)` = 0，只能经 `this` 写）。
    P4_TBL_4AB5CC_SIZE = 0x740 + 0x40 * 0x54

    def _p4_tbl4ab5cc(self) -> bytearray:
        t = self.p4_stat.get("tbl_4ab5cc")
        if not isinstance(t, bytearray) or len(t) != self.P4_TBL_4AB5CC_SIZE:
            t = bytearray(self.P4_TBL_4AB5CC_SIZE)
            self.p4_stat["tbl_4ab5cc"] = t
        return t

    def p4_44dcf0(self, key, idx: int) -> int:
        """`0x44DCF0(this, idx)` = `mov eax,[ecx+eax*4+0x4C]; ret` —— 取 `+0x4C` 起的 dword 数组第 idx 项。

        `0x45FCB0` 用它把 0xE 项的层表逐条写进快照（`0x44DCF0(0x4AA7B0, i)`）。
        `key` 是这块运行期内存的标识（复刻侧用 `p4_stat` 里的 `bytearray` 承载）。
        """
        buf = self.p4_stat.get(key)
        off = idx * 4 + 0x4C
        if not isinstance(buf, (bytes, bytearray)) or off + 4 > len(buf):
            return 0
        return int.from_bytes(buf[off:off + 4], "little")

    def p4_4563d0(self, key, dst: bytearray, off: int = 0) -> int:
        """`0x4563D0(mgr, dst)` = **memcpy `[mgr+4]*4` 字节，源是 `[mgr+0x10]` 指向的块**。

        ```
        0x4563D8 ecx = [eax+4]        ; 段字节数
        0x4563DB esi = [eax+0x10]     ; 源指针
        0x4563DE ecx <<= 2
        0x4563E6 rep movsd / rep movsb
        ```

        返回拷贝的字节数（`[mgr+4]*4`）。`0x45FCB0` 用它在头部之后写入段数据块，
        随后 `esi += [obj+0xC]*4`。
        """
        buf = self.p4_stat.get(key)
        if not isinstance(buf, (bytes, bytearray)) or len(buf) < 0x14:
            return 0
        n = int.from_bytes(buf[4:8], "little") * 4          # 0x4563D8/0x4563DE
        src_off = int.from_bytes(buf[0x10:0x14], "little")  # 0x4563DB
        if not isinstance(self.p4_stat.get(("blk", key)), (bytes, bytearray)):
            return 0
        src = self.p4_stat[("blk", key)]
        n = min(n, max(0, len(src) - src_off), max(0, len(dst) - off))
        dst[off:off + n] = src[src_off:src_off + n]
        return n

    def p4_45ff80(self, ents, buf, off: int = 0) -> int:
        """`0x45FF80(obj, head, dst)`：把一条实体链写进快照缓冲，**每条 0x20 字节**，返回写入字节数。

        ```
        0x45FF87 eax = 0x45A310(arg1)                 ; 队首
        0x45FF8C while ([eax+0x24] != 0 || 首条) :
        0x45FFA2 [dst+0x00] = [eax+0x00]              ; vtable
        0x45FFAD [dst+0x04..0x10] = [eax+4..eax+0x10] ; x / y / 半径 / 活跃
        0x45FFC6 [dst+0x14] = [eax+0x14]              ; 类型
        0x45FFCC [dst+0x18] = [eax+0x18]              ; HP
        0x45FFD2 byte[dst+0x1C] = byte[eax+0x1C]      ; 帧计数低字节
        0x45FFD8 eax = [eax+0x24]                     ; 链表 +0x24
        0x45FFAF edi += 0x20                          ; 累计字节数
        ```

        ⇒ 记录 = 8 dword = `0x20`，与 `0x45FBF0` 的 `total*8` 完全对齐。
        复刻侧直接用队列列表代替 `+0x24` 链（两者元素集合相同）。
        """
        n = 0
        for e in ents or ():
            b = off + n
            for i, src in enumerate((0x00, 0x04, 0x08, 0x0C, 0x10, 0x14, 0x18)):
                buf[b + i * 4:b + i * 4 + 4] = e.g32(src).to_bytes(4, "little")
            buf[b + 0x1C] = e.m[0x1C] & 0xFF                  # 0x45FFD2
            n += 0x20                                         # 0x45FFAF
        return n

    def p4_45c740(self, idx: int) -> int:
        """`0x45C740(this, idx, out)`：从 `0x4AB5CC` 拷一条 **0x54 字节**记录到 `out`。

        ```
        0x45C740 al = byte[this+5]                     ; 选基址
        0x45C749 sel = byte[this+4]
        0x45C755 k = sel + idx*2
        0x45C75F..0x45C764 k*21*4 = k*0x54 ; 基址 = this+0x740（byte[+5] 非零）或 this+8
        0x45C76B rep movsd 0x15（=0x54 字节）
        ```

        调用点 `0x45F2D9` 只取 `out[0]` 当新阈值。
        """
        t = self._p4_tbl4ab5cc()
        sel = t[4] if len(t) > 4 else 0                          # 0x45C749 movsx byte[ecx+4]
        flag = t[5] if len(t) > 5 else 0                         # 0x45C740 byte[ecx+5]
        off = (0x740 if flag else 8) + (sel + idx * 2) * 0x54    # 0x45C764 / 0x45C792
        if off + 4 > len(t):
            return 0
        return int.from_bytes(t[off:off + 4], "little")           # out[0]

    def p4_430860(self, q) -> int:
        """`0x430860(queue)` = `mov eax,[ecx+0x24]; ret` —— **`+0x24` 是队列计数**。

        `0x45FBF0` 用它累加 `total`；复刻侧队列就是列表，故等价于 `len(q)`。
        """
        return len(q) if isinstance(q, (list, tuple)) else int(q) if isinstance(q, int) else 0

    def p4_430880(self, q):
        """`0x430880(queue)` = `lea eax,[ecx+4]; ret` —— 返回**链表头指针** `queue+4`，
        与 `0x430860`（计数）是**两个不同的函数**，只差一个 nibble：

        ```
        0x430860 mov eax,[ecx+0x24] ; ret      ; 计数
        0x430880 lea eax,[ecx+4]    ; ret      ; 头指针
        ```

        `0x45FCB0` 用 `0x430880(...)`→`0x45FF80(obj, head, dst)`；复刻侧队列即列表本身。
        """
        return q

    def p4_45fbf0(self) -> int:
        """`0x45FBF0(obj)`：**算 HUD 缓冲总字节数**，返回 `(A + total*8 + 0xE)*4 + 0x18`。

        ```
        0x45FBF9 [obj+8] = 0xE
        0x45FC00 A = 0x456370(0x4CD484)          ; 段数
        0x45FC0A [obj+0xC] = A
        0x45FC0D edi = 0x457CE0(0x4AD55C)        ; 背景槽占用
        0x45FC19..0x45FC53 edi += 0x430860(0x4AD4FC / 0x4AD4CC / 0x4AD49C /
                                           0x4AD43C / 0x4AD46C / 0x4AD40C)
        0x45FC55 eax = 0x430860(0x4AD40C)
        0x45FC5F [obj+0x10] = edi + eax          ; total
        0x45FC63 edx = A + total*8
        0x45FC66 edx += [obj+8]
        0x45FC72 [obj+4] = edx*4 + 0x18          ; ← 返回值
        ```
        """
        seg = int(self.p4_stat.get("45fbf0_seg", 0))                 # 0x456370(0x4CD484)
        bg = int(self.p4_stat.get("45fbf0_bg", 0))                   # 0x457CE0(0x4AD55C)
        total = bg
        for name in ("ui4fc", "ui4cc", "ui49c", "ui43c", "ui46c", "ui40c"):
            total += self.p4_430860(getattr(self, name, []))         # 0x430860 六次
        total += self.p4_430860(getattr(self, "ui40c", []))          # 0x45FC55 再算一次 ui40c
        self.p4_stat["45fbf0_seg"] = seg
        self.p4_stat["45fbf0_total"] = total
        size = (seg + total * 8 + 0xE) * 4 + 0x18                    # 0x45FC6B
        self.p4_stat["45fbf0_size"] = size
        return size

    def p4_45f2fb(self) -> None:
        """`0x45EFF0` 的尾段（`0x45F2FB..0x45F3F0`）：**里程门槛递进**。

        分数超过当前门槛时，先按 `0x4CD590[+0x30]` 决定加哪一种加成实体，再把门槛抬到下一档。

        ```
        0x45F2FB eax = [mgr+0x34]（门槛）; ecx = [mgr+4]（分数）
        0x45F303 if (分数 <= 门槛) → 0x45F3F0
        0x45F30B if (门槛 == 0)    → 0x45F3F0
        0x45F311 word[0x56CCB0] += 8
        0x45F31E v = 0x460EA0(0x4CD590) = [0x4CD590+0x30]
        0x45F325 if (v == -1 /*esi*/) → 0x45F368 → 0x32000008
        0x45F334 if (v >= 0xA)        → 0x45F368 → 0x32000008
        0x45F336 否则 → 0x430400(rec, 0x298, 0x78, 0x21000001, 0x32000003)
        0x45F398 0x43BDC0(0x4AD43C, &rec)                 ; 入队
        0x45F3A2 门槛递进：
          < 0x989680 (10,000,000)  → += 0xF4240 (1,000,000)
          < 0x1C9C380 (30,000,000) → += 0x1E8480 (2,000,000)
          < 0x3938700 (60,000,000) → += 0x2DC6C0 (3,000,000)
          < 0x5F5E100 (100,000,000)→ += 0x3D0900 (4,000,000)
          否则                     → = 0
        0x45F3F0 byte[mgr+0xE1] = 1
        ```
        """
        m = 0x4CD4A0
        th = self.p4_stat.get(m + 0x34, 0)                               # 0x45F2FB
        score = self.p4_stat.get(m + 0x04, 0)                            # 0x45F2FE
        if score <= th or th == 0:                                       # 0x45F303 / 0x45F30B
            self.p4_stat[m + 0xE1] = 1                                   # 0x45F3F2
            return
        self.p4_stat[0x56CCB0] = (self.p4_stat.get(0x56CCB0, 0) + 8) & 0xFFFF   # 0x45F311
        v = self.p4_stat.get(0x4CD590 + 0x30, 0)                         # 0x45F31E
        if v == 0xFFFFFFFF or v >= 0xA:                                  # 0x45F325 / 0x45F334
            typ = 0x32000008                                             # 0x45F368
        else:
            typ = 0x32000003                                             # 0x45F336
        self.spawn(self._p4_q("ui43c"), 0x21000001, 0x298, 0x78, typ)     # 0x45F34C / 0x45F398
        if th < 0x989680:                                                # 0x45F3A5
            th += 0xF4240
        elif th < 0x1C9C380:                                             # 0x45F3B6
            th += 0x1E8480
        elif th < 0x3938700:                                             # 0x45F3C7
            th += 0x2DC6C0
        elif th < 0x5F5E100:                                             # 0x45F3D8
            th += 0x3D0900
        else:
            th = 0                                                       # 0x45F3E9
        self.p4_stat[m + 0x34] = th & 0xFFFFFFFF
        self.p4_stat[m + 0xE1] = 1                                       # 0x45F3F2

    def p4_45dfb0(self, v: int) -> dict:
        """`0x45DFB0(out, v)`：把 32 位值拆成 8 字节记录（**无返回值**，只写 `out`）。

        ```
        0x45DFBA out[0] = v & 0x1F
        0x45DFC1 m = (v >> 5) & 7
        0x45DFCC while (m--) out[0] *= 10            ; lea [ecx+ecx*4] 再 shl 1 = ×10
        0x45DFDB out[4] = (v >> 8)  & 0xF
        0x45DFE6 out[5] = (v >> 0xC) & 0xF
        0x45DFEC out[6] = word(v >> 0x10)
        ```
        """
        out = {"b0": v & 0x1F}                          # 0x45DFBA
        m = (v >> 5) & 7                                # 0x45DFC1
        while m:                                        # 0x45DFC7
            out["b0"] *= 10                             # 0x45DFCE/0x45DFD1
            m -= 1
        out["b4"] = (v >> 8) & 0xF                      # 0x45DFE1
        out["b5"] = (v >> 0xC) & 0xF                    # 0x45DFEF
        out["w6"] = (v >> 0x10) & 0xFFFF                # 0x45DFF2
        return out

    def p4_45fad0(self, typ: int) -> int:
        """`0x45FAD0(mgr, type)`：按 `type & 0xFF` 查表，返回表项的**高 16 位**。

        ```
        0x45FAD0 ecx = [mgr+0xEC] ; 为 0 直接返回 0
        0x45FAF1 (type & 0xFF000000) == 0x21000000 → eax = [0x4993C4 + (type&0xFF)*4]
        0x45FB12 否则                              → eax = [[mgr+0xEC] + (type&0xFF)*4]
        0x45FB1B 0x45DFB0(&out, eax)                ; 只为了…不，下面直接读 out 的高字
        0x45FB20 return word[out+6] & 0xFFFF        ; = (entry >> 16) & 0xFFFF
        ```
        """
        base = self.p4_stat.get(0x4CD4A0 + 0xEC, 0)      # 0x45FAD0
        if not base:
            return 0                                    # 0x45FADD
        i = typ & 0xFF
        if (typ & 0xFF000000) == 0x21000000:            # 0x45FAF1
            tbl = p4_tbl_4993c4()
            entry = tbl[i] if 0 <= i < len(tbl) else 0
        else:
            entry = self.p4_stat.get(base + i * 4, 0) & 0xFFFFFFFF
        return (entry >> 0x10) & 0xFFFF                 # 0x45FB20

    def p4_460800(self, o) -> int:
        """`0x460800(obj)` = `mov ax,[ecx+0x2A]; ret` —— 取当前字形队列 id（`0x4602D0` 存的那个）。"""
        return o.g16(0x2A)

    def p4_4600f0(self, o) -> bool:
        """`0x4600F0(this)`：取走队首字形 id、左移字符串、并把该资源的位图拷进 `[+0x2C]`。

        ```
        0x4600F6 cx = word[this+0xA] ; 若 0 → 0x46021C（直接收尾）
        0x460108 word[this+8] = cx
        0x46010C 15 次 [this+0xA+2k] = [this+0xA+2(k+1)]     ; 左移一格
        0x46011E 局部表 = 0x2E,0x2F,0x30,0x31,0x32,0x33,0x34,0x3C（8 项）
        0x460167 for (i = 1..8) if (c == 表[i-1] && 0x45AFC0(0x4AB5B0,0xF00000) < i)
                    0x45B0E0(0x4AB5B0, 0xF00000, i)      ; 记录最大编号
        0x4601A2 if (c == 0x46) 0x45AF30(0x4AB5B0, 0x80000000)   ; 'F' 置标志
        0x4601BD 0x45DDE0(c) → len ; 0x47C7C0(len) → buf[+0x2C]
        0x4601D7 0x45DDE0(c) → src ; 0x45DDA0(c) → n ; memcpy(buf, src, n)
        0x460208 [+0x30] = buf ; byte[+0x34] = 0 ; [+4] = 0
        ```
        """
        c = o.g16(0x0A)                                 # 0x4600F6
        if c == 0:
            return False                                # 0x46021C
        o.d16(0x08, c)                                  # 0x460108
        for k in range(0xF):                            # 0x46010C..0x46011C
            o.d16(0x0A + k * 2, o.g16(0x0A + (k + 1) * 2))
        for i, key in enumerate((0x2E, 0x2F, 0x30, 0x31, 0x32, 0x33, 0x34, 0x3C), 1):
            if c == key:                                # 0x46016F
                cur = self.keys.field(0xF00000)         # 0x46017D 0x45AFC0
                if cur < i:                             # 0x460182
                    self.keys.set_field(0xF00000, i)    # 0x460191 0x45B0E0
        if c == 0x46:                                   # 0x4601A2
            self.keys.set_field(0xF00000, self.keys.field(0xF00000) | 0x80000000)   # 0x45AF30
        data = self.bank.get(c) if getattr(self, "bank", None) else b""   # 0x45DDA0/0x45DDE0
        o.buf2c = data                             # 0x4601CB
        o.d32(0x30, len(data))                          # 0x460208
        o.m[0x34] = 0                                   # 0x46020B
        o.d32(0x04, 0)                                  # 0x46020F
        return True

    def p4_45e4a0(self, value: int, x: int, y: int) -> None:
        """`0x45E4A0(mgr, value, x, y)`：把数值渲染成至多 3 个数字实体（type `0x4100000C`）。

        实参顺序由 `0x45F627..0x45F62C` 的三条 `push` 定：`push y` / `push x` / `push eax(=200n)`，
        最后压的是 arg1 ⇒ `(mgr, value, x, y)`；函数内 `[esp+0x4C]` = arg2 = **x**、
        `[esp+0x50]` = arg3 = **y**。

        ```
        0x45E4AA if (value >= 10) 反复 idiv 10 取余（只留最后一次 = 首位数），[esp+0x18] 复用同一槽
        0x45E4D2 if (cnt > 3) { groups = cnt >> 2 ; cnt -= groups*4 }     ; 每 4 位进一组
        0x45E4E8 if (q == 1 && cnt != 0) q = 0                            ; 首位数 1 被丢弃
        0x45E4F3 bx = x + 0xC
        0x45E4FC if (q) bx -= 0xC ; 0x45E503 if (cnt) bx -= 0xC ; 0x45E50E if (groups) bx -= 0xC
        0x45E513 q       ? spawn(0x4100000C, bx, y, q-1)         → 0x4AD4CC
        0x45E55F cnt     ? spawn(0x4100000C, bx+=0x18, y, cnt+9) → 0x4AD4CC
        0x45E5AD groups  ? spawn(0x4100000C, bx+=0x18, y, groups+0xC)
        ```
        """
        q = value & 0xFFFFFFFF
        cnt = 1
        groups = 0
        if q >= 0xA:                                        # 0x45E4AA
            while True:
                d = abs(q) // 10
                if q < 0:
                    d = -d
                q = d                                       # 0x45E4C0 idiv（商向零）
                cnt += 1                                    # 0x45E4C8
                if q < 0xA:                                 # 0x45E4C9
                    break
        if cnt > 3:                                         # 0x45E4D2
            groups = cnt >> 2                               # 0x45E4D9
            cnt -= groups * 4                               # 0x45E4E4
        if q == 1 and cnt != 0:                             # 0x45E4E8
            q = 0                                           # 0x45E4F1
        bx = x + 0xC                                        # 0x45E4F9
        if q:
            bx -= 0xC                                       # 0x45E4FE
        if cnt:
            bx -= 0xC                                       # 0x45E505
        if groups:
            bx -= 0xC                                       # 0x45E510
        if q:                                               # 0x45E513
            self.spawn(self._p4_q("ui4cc"), 0x4100000C, bx, y, q - 1)
            bx += 0x18                                      # 0x45E5AA
        if cnt:                                             # 0x45E55F
            self.spawn(self._p4_q("ui4cc"), 0x4100000C, bx, y, cnt + 9)
            bx += 0x18
        if groups:                                          # 0x45E5AD
            self.spawn(self._p4_q("ui4cc"), 0x4100000C, bx, y, groups + 0xC)

    # ---- `0x43CCC0` 子弹→目标的命中处置（§16.208）----
    def p4_43ccc0(self, b, tgt) -> None:
        """`0x43CCC0(b, tgt)`：按 `[b+0x14] & 0x3F000000` 三路分流。"""
        cls = b.g32(0x14) & 0x3F000000                          # 0x43CCD4
        if cls in (0x31000000, 0x33000000):                     # 0x43CCDE / 0x43CCEB
            self._p4_43cefb(b, tgt)
            return
        if cls != 0x32000000:                                   # 0x43CCE4
            self._p4_43d0bf(b)                                  # 0x43CCF6
            return
        if tgt.g32(0x14) != 1:                                  # 0x43CD02
            return
        self.p4_stat[0x56CCB0] = (self.p4_stat.get(0x56CCB0, 0) + 2) & 0xFFFF   # 0x43CD10
        tgt.d32(0x30, 0x3C)                                     # 0x43CD18
        idx = (b.g32(0x14) - 0x32000002) & 0xFFFFFFFF           # 0x43CD22
        if idx > 7:                                             # 0x43CD27
            self._p4_43ced5(b)
            return
        x, y = tgt.s32(0x04), tgt.s32(0x08)
        if idx == 0:                                            # 0x43CDC7
            v = (tgt.g32(0x1C) | 1) & 0xFFFFFFFF
            tgt.d32(0x1C, v)                                    # 0x43CDD0
            p4_446470(self, tgt, (v >> 1) & 1, 0)               # 0x43CDD8
        elif idx == 1:                                          # 0x43CE54
            self.p4_460e00(x, y)
        elif idx in (2, 3, 6):                                  # 0x43CE1B / 0x43CDE2 / 0x43CE68
            tgt.d32(0x2C, 0xFFFFFF10)                           # 0x43CDEC / 0x43CE25 / 0x43CE72
            if (self.p4_stat.get(0x4AB5B0 + 0x04, 0) & 0xC000) >> 14 == 2:
                tgt.d32(0x30, 0x78)                             # 0x43CDFD / 0x43CE36 / 0x43CE83
            if idx == 2:
                self.p4_45f690(x, y)                            # 0x43CE4A
            elif idx == 3:
                self.p4_45f5f0(x, y)                            # 0x43CE11
            else:
                self.p4_45f6e0(x, y)                            # 0x43CE97
        elif idx in (4, 5):                                     # 0x43CD37 / 0x43CD7F
            # 0x43CD4C/0x43CD94 先清旧链表的 [+0x18]，再造演员并把新记录挂到 [tgt+0x24]
            old = getattr(tgt, "link24", None)
            if old is not None and hasattr(old, "d32"):
                old.d32(0x18, 0)
            t = 0x01000002 if idx == 4 else 0x01000003
            tgt.link24 = self.spawn(self._p4_q("ui40c"), t, 0, 0, tgt)
        elif idx == 7:                                          # 0x43CE9E
            self.spawn(self._p4_q("ui40c"), 9, x, y, tgt)
        self._p4_43ced5(b)

    def _p4_43cefb(self, b, tgt) -> None:
        """`0x43CEFB`（类 0x31/0x33）：玩家被击破的判定链。"""
        if tgt.g32(0x14) != 1:                                  # 0x43CF02
            return
        if tgt.g32(0x30) != 0:                                  # 0x43CF08
            return
        if tgt.s32(0x20) <= 0x12C:                              # 0x43CF11
            return
        if not self.p4_bit_none(0x10):                          # 0x43CF21 0x45B030(…,0x10)：bit4 清才继续
            return
        if tgt.s32(0x28) == 3:                                  # 0x43CF2A
            tgt.d32(0x28, 0)                                    # 0x43CF30
            tgt.d32(0x20, 0x79)                                 # 0x43CF33
            return
        self.p4_460c00()                                        # 0x43CF3C
        self.p4_45f570()                                        # 0x43CF4B
        tgt.d32(0x18, 0)                                        # 0x43CF50
        tgt.d32(0x10, 0)                                        # 0x43CF53 byte

    def _p4_43ced5(self, b) -> None:
        """`0x43CED5`：子弹 HP 清零 + SE 0x13 + 声像。"""
        b.d32(0x18, 0)                                          # 0x43CED5
        self.p4_se_pan(0x13, (self.p4_stat.get(0x56CC8C, 0) - 0x140) << 4)   # 0x43CEF1
        self._p4_43d0bf(b)

    def _p4_43d0bf(self, b) -> None:
        """`0x43D0BF`：`[b+0x18] != 0` 则不销毁。"""
        if b.g32(0x18) != 0:                                    # 0x43D0BF
            return
        b.d32(0x10, 0)                                          # 0x43D0C6 byte

    def p4_43ae60(self, e) -> int:
        """`0x43AE60(e)`：**剩余血量层数**（0 = 无可扣）。

        ```
        0x43AE60 if (word[0x56CCA8] <= [e+0x54]) → 0        ; 无敌/未到可伤时刻
        0x43AE6C if ([e+0x18] & 0xF0000000) → return 1 - [e+0x48]   ; 特化实体（负数/一次性）
        0x43AE84 H = ([e+0x18] + 0x3F) >> 6
        0x43AE8C if (H <= [e+0x48]) → 0
        0x43AE8E return H - [e+0x48]
        ```
        """
        if (self.p4_stat.get(0x56CCA8, 0) & 0xFFFF) <= (e.g32(0x54) & 0xFFFF):   # 0x43AE68
            return 0
        hp = e.g32(0x18)
        if hp & 0xF0000000:                                    # 0x43AE6F
            return (1 - e.g32(0x48)) & 0xFFFFFFFF              # 0x43AE7E
        h = ((hp + 0x3F) & 0xFFFFFFFF) >> 6                    # 0x43AE84
        if h <= e.g32(0x48):                                   # 0x43AE8C
            return 0
        return (h - e.g32(0x48)) & 0xFFFFFFFF                  # 0x43AE8E

    def p4_45af30(self, bits: int) -> int:
        """`0x45AF30(mgr, bits)`：`word[mgr+4] |= bits`，返回新值。"""
        w = (self.p4_stat.get(0x4AB5B0 + 4, 0) | bits) & 0xFFFFFFFF   # 0x45AF37/0x45AF39
        self.p4_stat[0x4AB5B0 + 4] = w
        return w                                                     # 0x45AF3C

    def p4_45af60(self, bits: int) -> int:
        """`0x45AF60(mgr, bits)`：`word[mgr+4] &= ~bits`，返回新值。"""
        w = (self.p4_stat.get(0x4AB5B0 + 4, 0) & ~bits) & 0xFFFFFFFF  # 0x45AF67/0x45AF69
        self.p4_stat[0x4AB5B0 + 4] = w
        return w                                                     # 0x45AF6E

    def p4_afc0(self, mask: int) -> int:
        """`0x45AFC0(mgr, mask)`：取 `word[mgr+4] & mask`，**右移到 mask 的最低位**。

        ```
        0x45AFC0 eax = [ecx+4] & mask
        0x45AFC9 eax == 0 → return 0
        0x45AFCB mask & 1 → return eax（已经在最低位）
        0x45AFD0 循环：mask >>= 1 ; eax >>= 1 ; 直到 mask & 1
        ```
        ⇒ `0x45AFC0(0x4AB5B0, 0xC000)` = **操作器选择（0..3）**。
        """
        v = (self.p4_stat.get(0x4AB5B0 + 4, 0) & mask) & 0xFFFFFFFF   # 0x45AFC0/0x45AFC7
        if v == 0:                                              # 0x45AFC9
            return 0
        while not (mask & 1):                                   # 0x45AFCB / 0x45AFD4
            mask >>= 1
            v >>= 1
        return v                                                # 0x45AFD9

    def _p4_43c55d(self, p, a) -> None:
        """`0x43C55D`（类型 `0x10008431`）：伤害数字 —— 命中则生成 type 6 实体，未命中走 `0x43C691`。

        ```
        0x43C55D 0x45FAD0(0x4CD4A0, [a+0x14]) ; == 0 → 0x43C691
        0x43C594 0x430400(dst, &a[4], <fad0 第二次>, 6, [p+0x1C])
        0x43C5B8 k = [esp+0x34] & 0xF；k==8 或 0x45AFF0(0x4AB5B0,0x200) → 3，否则 2
        0x43C5D7/0x43C5E6 写 [[p+0x1C] + 0x28]
        0x43C5F7 0x448FF0(0x4AD40C, &rec)
        0x43C61D 0x45EFF0(0x4CD4A0, [a+0x14], [a+4], [a+8], 0x10008431)   ; **未落地**
        0x43C612 [a+0x18] = 0 ; 0x43C619 byte[a+0x10] = 0
        0x43C636 0x450350(0x4AB4B0, 0xD, ([p+4]-0x140) << 4)
        0x43C63B if ([a+0x14] == 0x29000006 && 0x460800(0x56CC4C) == 0)
                   → 0x45AF30(0x56CCB8, 0x1000) ; [p+0x18] = 0 ; byte[p+0x10] = 0
        ```

        ★ `rec[0]` 是**位置三元组的地址**（`&a[4]`）。type 6 的构造器 `0x445CE7` 会解引用它：
        `0x445CF2 edx = [[ebp]]` → `node+4`，`[[ebp]+4]` → `node+8`，`[[ebp]+8]` → `node+0xC`。
        所以这里传 `a` 的 x/y/r 三个量，而不是把地址当坐标。
        ★ `k` 读的是未初始化栈（§16.227），只保留 `0x45AFF0(0x4AB5B0, 0x200)` 那一半。
        """
        ta = a.g32(0x14)
        hit = self.p4_45fad0(ta)                               # 0x43C565 / 0x43C585
        if hit == 0:                                           # 0x43C56B
            self._p4_43c691(p)
            return
        r = 3 if self.p4_bit_any(0x200) else 2                  # 0x43C5C2..0x43C5E6
        target = p.g32(0x1C)
        if target:
            self.p4_stat[target + 0x28] = r
        self.spawn(self._p4_q("ui40c"), 6,
                   a.s32(0x04), a.s32(0x08), hit, p.g32(0x1C))  # 0x43C5F7 / 0x43C594
        self.p4_45eff0(ta, a.s32(0x04), a.s32(0x08), 0x10008431)   # 0x43C61D
        a.d32(0x18, 0)                                          # 0x43C612
        a.d32(0x10, 0)                                          # 0x43C619
        self.p4_se_pan(0xD, (p.s32(0x04) - 0x140) << 4)         # 0x43C636
        if ta == 0x29000006 and self.p4_460800(0x56CC4C) == 0:  # 0x43C63B
            self.p4_45af30(0x1000)                              # 0x43C65D
            p.d32(0x18, 0)                                      # 0x43C662
            p.d32(0x10, 0)                                      # 0x43C669

    def _p4_43c691(self, p) -> None:
        """`0x43C691`：`0x43C55D` 的**未命中**路径 —— 再入列一份爆炸记录，然后注销 `p`。

        ```
        0x43C691 0x45A690(0, 0x28) → eax:edx ; 结果写 [esp+0x24]/[esp+0x2c]
        0x43C6AF 0x43A3C0(0x4AD4CC, &rec)     ; rec 沿用 0x43C488 填好的 [x, y, 0x41000004, &buf]
        0x43C6B4 [p+0x18] = 0 ; 0x43C6BB byte[p+0x10] = 0
        ```

        `[esp+0x24]`/`[esp+0x2c]` 与 `0x43C8CD` 一样是 `rec+0x14`/`rec+0x1C` 的死写（§16.226），不复现。
        """
        self.spawn(self._p4_q("ui4cc"), 0x41000004,
                   p.s32(0x04), p.s32(0x08), 0)                 # 0x43C6AF
        p.d32(0x18, 0)                                          # 0x43C6B4
        p.d32(0x10, 0)                                          # 0x43C6BB

    def _p4_43c8cd(self, p, a) -> None:
        """`0x43C8CD`（类型 `0x10FF0053`）：在 `p` 附近撒一个抖动特效到 `0x4AD4CC`。

        ```
        0x43C8D8 if ([a+0x14] == 0x2A000001) [p+0x18] = 0
        0x43C8E8 rec[0] = [p+4] + (rand()&0x1F) - 0x10
        0x43C8FB rec[1] = [p+8] + (rand()&0x3F) - 0x20
        0x43C90E/0x43C91A 两次 (rand()&0x1F - 0xF) 交给 0x45A690，结果写 [esp+0x24]/[esp+0x2c]
        0x43C940 0x43A3C0(0x4AD4CC, &rec)
        ```

        ★ 两处必须说明（都已在 §16.226 定案）：
        1. 这一段**没有** `0x430400`，类型槽 `rec[2]` 沿用前面 `0x43C488` 写下的 `0x41000004`；
        2. `[esp+0x24]` / `[esp+0x2c]` 是 `rec+0x14` / `rec+0x1C`，而入队链只读 `rec[0..0x10]`
           （`0x430450`）且 `0x430820` 会把 `rec+0x10` **覆盖**掉，所以这两个写入是**死写**，
           对外不可观测 —— 故这里不复现。
        同理 `rec[3]`（`a3`）在原版是 `0x43C488` 留下的**栈地址**，任何逻辑都不可能依赖它，
           复刻侧传 0。
        """
        if a.g32(0x14) == 0x2A000001:                          # 0x43C8D8
            p.d32(0x18, 0)                                     # 0x43C8E1
        x = p.s32(0x04) + (_random.randrange(0x20) & 0x1F) - 0x10   # 0x43C8F3
        y = p.s32(0x08) + (_random.randrange(0x40) & 0x3F) - 0x20   # 0x43C906
        self.spawn(self._p4_q("ui4cc"), 0x41000004, x, y, 0)   # 0x43C940

    def _p4_43c868(self, p) -> None:
        """`0x43C868`（类型 `0x10142214`）：在 `p` 原址连发 **20 个 `0x10032215`** 到 `0x4AD46C`。

        ```
        0x43C86E..0x43C87F 0x430400(rec, [p+4], [p+8], 0x10032215, 0)   ; a3 槽先清 0
        0x43C8A3 [esp+0x1c] = 0        ← 注意 rec 在 esp+0x10，[esp+0x1c] = rec+0xC = **a3 槽**
        0x43C8AB 0x430290(0x4AD46C, &rec)
        0x43C8BA eax = [esp+0x1c] + 1 ; 0x43C8C6 if (eax < 0x14) 继续
        ```
        ⇒ 同一个坐标发 20 份，**a3 依次为 0..0x13**（不是 20 个随机位置）。
        """
        x = p.s32(0x04)                                        # 0x43C86B
        y = p.s32(0x08)                                        # 0x43C868
        for i in range(0x14):                                  # 0x43C8BF cmp eax,0x14
            self.spawn(self._p4_q("ui46c"), 0x10032215, x, y, i)   # 0x43C8B5

    def _p4_43c6c4(self, p, a, u: int) -> None:
        """`0x43C6C4`（类型 `0x10008041`）：命中演出 —— 4 个 `0x41000005` 碎片 + 1 条 `0x41400507` 记录。

        ```
        0x43C6C6 0x43AE60(a) ; == 0 → 共用尾
        0x43C6D3 if (byte[a+0x4C] == 0) {
            byte[a+0x4C] = 1
            0x430400(rec, [a+4], [a+8], 0x41000006, [p+0x24]) ; rec[4] = a（0x43C6FE 补写第 5 槽）
            0x43A3C0(0x4AD4CC, &rec)
        }
        0x43C748 0x430400(rec, 4, 4, 0x41000005, a) → 入队          ; y = 4
        0x43C78A rec[1] = -4 → 入队（0x43C78E）                      ; 注意 push 之后 [esp+0x18] = rec+0x14
        0x43C7A1 rec[1] =  4 → 入队（0x43C7A9）
        0x43C7BC rec[1] = -4 → 入队
        0x43C7D4 0x430400(rec, p, [a+0x48], 0x41400507, a) → 入队    ; rec[0] 存的是**指针**
        0x43C7FF [a+0x48]++ ; [a+0x54] = word[0x56CCA8] + 0x10
        0x43C81B word[0x56CC98]++ ; 0x43C821 word[0x56CCA0]++
        0x43C833 0x450350(0x4AB4B0, 6, ([p+4] - 0x140) << 4)
        0x43C84A 0x45AFC0(0x4AB5B0, 0xC000) == 3 → byte[p+0x10] = 0、[p+0x1C] = 4
        ```
        """
        if self.p4_43ae60(a) == 0:                              # 0x43C6C6
            return
        if a.m[0x4C] == 0:                                      # 0x43C6D3
            a.m[0x4C] = 1                                       # 0x43C6DD
            self.spawn(self._p4_q("ui4cc"), 0x41000006,
                       a.s32(0x04), a.s32(0x08), p.g32(0x24))   # 0x43C703
        for dy in (4, -4, 4, -4):                               # 0x43C748..0x43C7BC
            self.spawn(self._p4_q("ui4cc"), 0x41000005, 4, dy, a)
        self.spawn(self._p4_q("ui4cc"), 0x41400507,
                   p.g32(0x00), a.g32(0x48), a)                 # 0x43C7D4
        a.d32(0x48, (a.g32(0x48) + 1) & 0xFFFFFFFF)             # 0x43C7FF
        a.d32(0x54, (self.p4_stat.get(0x56CCA8, 0) + 0x10) & 0xFFFFFFFF)   # 0x43C80A
        self.p4_stat[0x56CC98] = (self.p4_stat.get(0x56CC98, 0) + 1) & 0xFFFF   # 0x43C81B
        self.p4_stat[0x56CCA0] = (self.p4_stat.get(0x56CCA0, 0) + 1) & 0xFFFF   # 0x43C821
        self.p4_se_pan(6, (p.s32(0x04) - 0x140) << 4)           # 0x43C83B
        if self.p4_afc0(0xC000) == 3:                           # 0x43C84F
            p.d32(0x10, 0)                                      # 0x43C858
            p.d32(0x1C, 4)                                      # 0x43C85C

    def p4_43c460(self, p, a=None) -> None:
        """`0x43C460(hit)`：`0x4AD46C × 0x4AD43C` 这对队列的命中处理（**目前只落地前半段**）。

        ★ `0x43C0B6` 的 `call 0x401136` 经 thunk 指向 **`0x43C460`**，不是 `0x43C170`
        （后者是 `0x43BFD0` 那条链的回调）。此前 `p4_43c060` 误接了 `p4_hit_cb`，本轮改正。

        前半段（已落地）：按 `hit[0x14] & 0x7000` 决定爆炸的初速，然后生成一个 `0x41000004`
        特效记录并入队 `0x4AD4CC`。

        ```
        0x43C46B ebx = hit
        0x43C474/0x43C481 x = hit[4]、y = hit[8]
        0x43C488 0x430400(rec, x, y, 0x41000004, …)
        0x43C49D t = hit[0x14] & 0x7000
        0x43C4B2 t == 0x1000 → 0x45A690(hit[0x1C] >> 7, hit[0x20] >> 7)   ; 用速度当偏移
        0x43C4BB t == 0x2000 → 0x45A690(rand()&0x1F - 0xF, rand()&0x1F - 0xF)  ; 随机抖动
        0x43C4F5 rec[5] = eax ; rec[6] = edx
        0x43C503 0x43A3C0(0x4AD4CC, &rec)
        ```

        后半段 `0x43C508` 起是 **20+ 个类型的线性 cmp 链**（`0x12061128` / `0x10142214` /
        `0x10008041` / `0x10008431` …），尚未落地（§15）。
        """
        x = p.s32(0x04)                                        # 0x43C474
        y = p.s32(0x08)                                        # 0x43C477
        t0 = p.s32(0x14)                                       # 0x43C4A2 保存完整类型
        t = t0 & 0x7000                                        # 0x43C49D
        if t == 0x1000:                                        # 0x43C4B9
            ox = p.s32(0x1C) >> 7                              # 0x43C4E5
            oy = p.s32(0x20) >> 7                              # 0x43C4E1
        elif t == 0x2000:                                      # 0x43C4C0
            ox = _random.randrange(0x20) - 0xF                 # 0x43C4C7
            oy = _random.randrange(0x20) - 0xF                 # 0x43C4D3
        else:
            self._p4_43c460_dispatch(p, a, t0)                 # 0x43C4C0 jne 0x43C508 之前的分支
            return
        self.spawn(self._p4_q("ui4cc"), 0x41000004, x, y, (ox, oy))   # 0x43C488 / 0x43C503
        self._p4_43c460_dispatch(p, a, t0)                     # 0x43C508 起

    def _p4_43c987(self, p, u: int) -> None:
        """`0x43C987`（类型 `0x12061128` / `0x12081123`）：`[p+0x30] == 0` 时才造一份同类型实体入 `0x4AD46C`。

        ```
        0x43C987 ecx = [ebx+0x30] ; 0x43C98C if (ecx != 0) → 0x43C9C2
        0x43C994..0x43C99E 0x430400(rec, [ebx+4], [ebx+8], eax=type, 0)
        0x43C9B8 0x430290(0x4AD46C, &rec)      ; 0x40100F thunk
        ```
        """
        if p.g32(0x30) != 0:                                   # 0x43C98A
            return
        self.spawn(self._p4_q("ui46c"), u, p.s32(0x04), p.s32(0x08), 0)   # 0x43C99D / 0x43C9BD

    def _p4_43c9c2(self, p, a, k: int) -> None:
        """`0x43C9C2` 共用尾 —— **命中反应**：减寿命 → 撞击特效 → 注销靶 → 结算分数。

        ```
        0x43C9C2 ecx = k（= byte[type+2]，即 (type>>16)&0xFF）
        0x43C9C8 k == 0 → 0x43CAFA（**函数返回**，什么都不做）
        0x43C9CE eax = [p+0x18]；==0 或 ==-1 不递减，否则 [p+0x18] = eax-1
        0x43C9DE [p+0x18] == 0 → byte[p+0x10] = 0            ; 弹寿命耗尽
        0x43C9E9 if ([a+0x18] > k) → 0x43CACF                ; 靶还硬
        0x43CACF   if ([a+0x18] != -1) [a+0x18] -= k
        0x43CAD9   if ([p+0x14] == 0x10FF0053) → 返回
        0x43CAE2   0x450350(0x4AB4B0, 5, ([a+4]-0x140)<<4)   ; SE 5
        0x43CAF5   → 返回
        ---- 否则靶被击破 ----
        0x43C9F4 if ([a+0xC] == 0x30 且 [a+0x14] 不在六个例外里)
        0x43CA3B     0x430400(dst, [a+4], [a+8], 0x61000004, 0x30) → 0x445AA0(0x4AD52C, &rec)
        0x43CA61 否则 0x430400(dst, [a+4], [a+8], 0x41000001, 0)   → 0x43A3C0(0x4AD4CC, &rec)
        0x43CA99 [a+0x18] = 0 ; byte[a+0x10] = 0
        0x43CAB9 0x45EFF0(0x4CD4A0, [a+0x14], [a+4], [a+8], [p+0x14])
        ```

        六个例外：`0x24000011` / `0x2300000E` / `0x27000011` / `0x29000013` / `0x2C00000B` / `0x2C00000A`。
        """
        if k == 0:                                             # 0x43C9C8 → 0x43CAFA
            return
        lt = p.g32(0x18)                                       # 0x43C9CE
        if lt != 0 and lt != 0xFFFFFFFF:                       # 0x43C9D3 / 0x43C9D5
            lt -= 1
            p.d32(0x18, lt)                                    # 0x43C9DB
        if p.g32(0x18) == 0:                                   # 0x43C9E1
            p.d32(0x10, 0)                                     # 0x43C9E5
        if a.s32(0x18) > k:                                    # 0x43C9EE ja
            if a.g32(0x18) != 0xFFFFFFFF:                      # 0x43CACF
                a.d32(0x18, (a.g32(0x18) - k) & 0xFFFFFFFF)    # 0x43CAD4
            if p.g32(0x14) == 0x10FF0053:                      # 0x43CAD9
                return
            self.p4_se_pan(5, (a.s32(0x04) - 0x140) << 4)      # 0x43CAF5
            return
        ta = a.g32(0x14)
        if a.g32(0x0C) == 0x30 and ta not in (0x24000011, 0x2300000E, 0x27000011,
                                              0x29000013, 0x2C00000B, 0x2C00000A):
            self.spawn(self._p4_q("ui52c"), 0x61000004,
                       a.s32(0x04), a.s32(0x08), 0x30)         # 0x43CA5A
        else:
            self.spawn(self._p4_q("ui4cc"), 0x41000001,
                       a.s32(0x04), a.s32(0x08), 0)            # 0x43CA94
        a.d32(0x18, 0)                                         # 0x43CA9F
        a.d32(0x10, 0)                                         # 0x43CAA6
        self.p4_45eff0(ta, a.s32(0x04), a.s32(0x08), p.g32(0x14))   # 0x43CAB9

    def _p4_43c460_dispatch(self, p, a, t: int) -> None:
        """`0x43C508..0x43C9C2`：按**完整类型**做**无符号**二叉查找式的 cmp 链。

        ```
        0x43C525 t >  0x12061128 → 0x43C947：0x12081123 / 0x120C112C / 0x1B000001
        0x43C530 t == 0x12061128 → 0x43C987
        0x43C53B t >  0x10142214 → 0x43C8CD：0x10FF0053
        0x43C541 t == 0x10142214 → 0x43C868
        0x43C54C t == 0x10008041 → 0x43C6C4
        0x43C557 t == 0x10008431 → 0x43C55D
        其余 → 0x43C9C2
        ```

        `0x43C9C2` 共用尾：`ecx = (t >> 16) & 0xFF`（`0x43C516 xor edx,edx` / `0x43C518 mov dl,byte[esp+0x2E]`），
        `ecx == 0` 转 `0x43CAFA`；否则 `[p+0x18]` 减一（`== 0` 或 `== -1` 不递减），归零则 `byte[p+0x10] = 0`。
        """
        u = t & 0xFFFFFFFF
        if u > 0x12061128:                                     # 0x43C525 → 0x43C947
            if u == 0x12081123:                                # 0x43C94C
                self._p4_43c987(p, u)
            elif u == 0x120C112C:                              # 0x43C953 → 0x43C97E
                p.d32(0x30, 0xFFFFFFFD)                        # 0x43C97E [+0x30] = -3
            elif u == 0x1B000001:                              # 0x43C95A
                p.d32(0x18, 0)                                 # 0x43C963
                return                                         # 0x43C97B ret 8（**不走**共用尾）
        elif u == 0x12061128:                                  # 0x43C530 → 0x43C987
            self._p4_43c987(p, u)
        elif u > 0x10142214:                                   # 0x43C53B → 0x43C8CD：只剩 0x10FF0053
            self._p4_43c8cd(p, a)
        elif u == 0x10142214:                                  # 0x43C541 → 0x43C868
            self._p4_43c868(p)
        elif u == 0x10008041:                                  # 0x43C54C → 0x43C6C4
            self._p4_43c6c4(p, a, u)
        elif u == 0x10008431:                                  # 0x43C557 → 0x43C55D
            self._p4_43c55d(p, a)
        # 0x43C9C2 共用尾（完整版，含撞击特效与击破结算）。
        # `a is None` 只出现在审计桩里（真实调用点 0x43C0B2 一定有靶）。
        if a is not None:
            self._p4_43c9c2(p, a, (t >> 16) & 0xFF)

    def p4_43c060(self, qa, qb) -> int:
        """`0x43C060(a, b)`：与 `0x43BFD0` 同形，但有两处不同（**不是同一个函数**）。

        ```
        0x43C075 0x45B030(0x56CCB8, 2)          ; 注意是 0x45B030，不是 0x45AFF0
        0x43C083 jne 0x43C08D                   ; 非 0 时**不整体跳过**，只跳过下面的类型过滤
        0x43C085 eax = [esi+0x14] ; test ah,0x80 ; je 跳过该 esi
        ```

        ⇒ 当 `0x56CCB8` 的 bit2 为 0 时，只处理**类型带 0x8000 位**的实体。
        """
        hits = 0
        # 0x43C075 0x45B030(0x56CCB8, 2)：**bit2 清**时返回 1 → jne 跳过类型过滤
        bit2_clear = self.p4_bit_none(0x02)
        for e in list(qa):
            if not e.g32(0x10):                                 # 0x43C094
                continue
            if not bit2_clear and not (e.g32(0x14) & 0x8000):   # 0x43C085 test ah,0x80
                continue
            for t in list(qb):
                if not t.g32(0x10):
                    continue
                if self.p4_hit_test(t, e.s32(0x04), e.s32(0x08), e.s32(0x0C)):   # 0x43C0A9
                    self.p4_43c460(e, t)                        # 0x43C0B2 push edi / 0x43C0B3 push esi
                    hits += 1
        return hits

    def p4_43c0f0(self, qa, qb) -> int:
        """`0x43C0F0(a, b)`：与 `0x43BFD0` 同形，但命中回调是 `0x43CCC0`（`0x43C135`）。"""
        hits = 0
        for e in list(qa):
            if not e.g32(0x10):                                 # 0x43C108 byte
                continue
            for t in list(qb):
                if not t.g32(0x10):
                    continue
                if self.p4_hit_test(t, e.s32(0x04), e.s32(0x08), e.s32(0x0C)):
                    self.p4_43ccc0(e, t)                        # 0x43C135 → 0x401FDC
                    hits += 1
        return hits

    def p4_45f570(self) -> None:
        """`0x45F570(0x4CD4A0)`：自机被击破后的量表重置（**唯一**把 `+0x26` 写成 `0xA0` 的地方）。

        ```
        0x45F573 0x401FD2→0x45F660               ; [+0x30] 饱和减 5
        0x45F578 ax = word[+0x2C]
        0x45F57C ecx = (movsx(ax) >= 2) ? 2 : movsx(ax)
        0x45F58A eax = ax − ecx                  ; 最多减 2
        0x45F58C word[+0x26] = 0xA0              ; ★ 正是 0x45FAB0 比较的字段
        0x45F592 word[+0x2C] = ax
        0x45F596 word[+0x28] = 0
        0x45F59C byte[+0x2A] = 0
        ```
        """
        self.p4_45f660()                                   # 0x45F573
        ax = self.p4_stat.get(0x4CD4A0 + 0x2C, 0) & 0xFFFF
        sax = ax - 0x10000 if ax & 0x8000 else ax          # 0x45F580 movsx
        d = 2 if sax >= 2 else sax                         # 0x45F583 / 0x45F585
        self.p4_stat[0x4CD4A0 + 0x26] = 0xA0               # 0x45F58C
        self.p4_stat[0x4CD4A0 + 0x2C] = (ax - d) & 0xFFFF  # 0x45F592
        self.p4_stat[0x4CD4A0 + 0x28] = 0                  # 0x45F596 word
        self.p4_stat[0x4CD4A0 + 0x2A] = 0                  # 0x45F59C byte

    def p4_4cd4a0_ge_a0(self) -> bool:
        """`0x4016EF`→`0x45FAB0`：`word[0x4CD4A0+0x26] >= 0xA0`（真 = 达标）。"""
        return (self.p4_stat.get(0x4CD4A0 + 0x26, 0) & 0xFFFF) >= 0xA0

    def p4_fire_8431(self, sub) -> None:
        """`0x4474AE`/`0x44754E`：造 `0x10008431`（位置 = 子对象，第 5 字段 = 子对象指针）入 `0x4AD46C`。"""
        self.spawn(self._p4_q("ui46c"), 0x10008431, sub.s32(0x04), sub.s32(0x08), sub)

    def p4_se_pan(self, se: int, pan: int) -> None:
        """`0x4013A2(0x4AB4B0, se, pan)`：带声像的音效（见 §11）。"""
        self.p4_stat[0x3A2] = self.p4_stat.get(0x3A2, 0) + 1

    def p4_ptr(self):
        """`[0x4AB59C]`/`[0x4AB5A0]`：指针坐标（0x44E660 Poll 写、0x44EB60 记录）。"""
        return int(self.inp.x), int(self.inp.y)

    def p4_ptr_set(self, x: int, y: int) -> None:
        """`0x44E470`（钳位后回写指针）。"""
        self.inp.x, self.inp.y = int(x), int(y)

    def p4_in_bits(self) -> int:
        """`0x56CCC0`：页4 输入状态位图（**与 `0x4AB5B0` 键位管理器是两个对象**）。

        `0x45AFF0(0x56CCC0, mask)` 才是"攻击/暂停/无敌"这类运行期位；`0x4AB5B0` 存的是模式选择
        （bit0 鍛錬 / bit1 操作器），两者的写入点完全不同（见 `0x45060A` vs `0x451423`）。
        """
        if not hasattr(self, "_p4_in"):
            self._p4_in = 0
        return self._p4_in

    def p4_in_set(self, bits: int) -> None:
        self._p4_in = bits & 0xFFFFFFFF

    def p4_key_test(self, mask: int) -> bool:
        """`0x45AFF0(0x56CCC0, mask)`：测输入状态位。"""
        return bool(self.p4_in_bits() & mask)

    def p4_key_reset(self, mask: int) -> None:
        """`0x45AF60(0x56CCC0, mask)`：清位。"""
        self.p4_in_set(self.p4_in_bits() & ~mask)

    def p4_key_raw_set(self, mask: int) -> None:
        """`0x45AF30(0x56CCC0, mask)`：置位。"""
        self.p4_in_set(self.p4_in_bits() | mask)

    def p4_player_y(self) -> int:
        """`[0x56CC90]`：自机缓存 y（`0x448D2D` 写）。"""
        pos = getattr(self, "p4_player_pos", None)
        return int(pos[1]) if pos else int(self.inp.y)

    def p4_btn_attack(self) -> bool:
        """`[0x4AB594]`：btn0（C/左键=攻击）当前状态。"""
        return bool(self.p4_in_bits() & 1)

    def p4_btn0_edge(self) -> bool:
        """`byte[0x4AB596]`：btn0 **按下沿**（输入记录第 3 字节，`rec.e0`）。"""
        return bool(getattr(self.inp.rec, "e0", 0))

    def p4_btn1_edge(self) -> bool:
        """`byte[0x4AB597]`：btn1 **按下沿**（输入记录第 4 字节，`rec.e1`）。"""
        return bool(getattr(self.inp.rec, "e1", 0))

    def p4_btn1_release(self) -> bool:
        """`byte[0x4AB599]`：btn1 **松开沿**（输入记录第 6 字节，`rec.r1`）。"""
        return bool(getattr(self.inp.rec, "r1", 0))

    def p4_anim_step(self, e) -> None:
        """`0x45A790(节点+4, -0x20, 0, -0x20, 0)`：按 16 帧周期切自机动画帧。"""
        e.d32(0x28, (e.s32(0x28) + 1) & 3)

    def _p4_q(self, name: str) -> list:
        q = getattr(self, name, None)
        if q is None:
            q = []
            setattr(self, name, q)
        return q

    # ---- 背景槽 0x4AD55C -------------------------------------------------
    def p4_bg_record(self, op: int, ch: int, block: bytes, flags: int, rep: int = 0) -> None:
        """op06 `0x457C00`（立即触发）/ op07 `0x457C40`（只改参数）。
        `ch >= 0xC` ⇒ 对 12 个槽广播；block 是记录的 20 个 dword（记录 +8 起）。"""
        vals = [int.from_bytes(block[4 * i:4 * i + 4], "little", signed=True) for i in range(20)]
        if getattr(self, "p4_trace_bg", False):
            print(f"[bgrec] op{op} ch={ch} count={vals[10]} flags=0x{flags:X} rep={rep}", flush=True)
        targets = range(12) if ch >= 12 else [ch]
        for i in targets:
            slot = self.p4_bg[i]
            if op == 6:                                  # 0x4572E0
                slot.flags = flags & 0xFFFFFFFF          # +0x2A8C
                slot.rem = 0                             # +0x2A88
                slot.active = 1                          # +0x2A90
                slot.params = list(vals)                 # 0x456D50 直拷 20 dword
                self._bg_dispatch(slot)                  # 0x456EB0
            else:                                        # 0x457330
                if not slot.active:
                    continue
                slot.flags = flags & 0xFFFFFFFF
                slot.rem = rep                           # +0x2A88
                slot.rates = list(vals)                  # +0x80

    def _bg_dispatch(self, slot) -> None:
        """`0x456EB0`：按 `[+0x2A8C]` 的 5 个位分别调 5 个分支。"""
        f = slot.flags
        if f & 0x0001:
            self._bg_shift(slot, 0)                      # 0x456F30（x）
        if f & 0x0100:
            self._bg_init_x(slot)                        # 0x456FB0
        if f & 0x0010:
            self._bg_shift(slot, 1)                      # 0x456F70（y）
        if f & 0x1000:
            self._bg_init_y(slot)                        # 0x457000
        if f & 0x10000:
            self._bg_grid(slot)                          # 0x457050

    def _bg_grid(self, slot) -> None:
        """`0x457050`：填每格 kind。`[slot+0x58]`=格数、`[+0x38]`=起始尺寸、`[+0x44]`=增长率。"""
        count = slot.params[10]
        if count <= 0 or count > 894:                    # 0x2A98-0xD0 容量上限
            return
        grid = slot.grid
        while len(grid) < count:
            grid.append([0, 0, 0])
        del grid[count:]
        cur = slot.params[2]
        growth = slot.params[5]
        for i in range(count):
            kind = BG_LADDER[0]
            k = 1
            while cur >= (kind << 6) and k < len(BG_LADDER):
                kind = BG_LADDER[k]
                k += 1
            grid[i][2] = kind
            cur += (growth * cur) >> 6

    def _bg_init_x(self, slot) -> None:
        """`0x456FB0`（bit8）：用 P[0]/P[3]/P[6] 线性铺开每格的 x（像素）。

        ```
        edx = P[0]; eax = P[3]; count = P[10]
        for i: grid[i].x = edx >> 6; eax += (eax * P[6]) >> 6; edx += eax
        ```
        """
        n = slot.params[10]
        if n <= 0 or n > 894:
            return
        while len(slot.grid) < n:
            slot.grid.append([0, 0, 0])
        edx = slot.params[0]
        eax = slot.params[3]
        for i in range(n):
            slot.grid[i][0] = (edx >> 6) & 0xFFFFFFFF
            eax = (eax + ((eax * slot.params[6]) >> 6)) & 0xFFFFFFFF
            edx = (edx + eax) & 0xFFFFFFFF

    def _bg_init_y(self, slot) -> None:
        """`0x457000`（bit12）：与 `0x456FB0` 同构，写每格的 y（像素）。

        ```
        edx = P[1]（slot+0x34）; eax = P[4]（slot+0x40）; 增长率 = P[7]（slot+0x4C）
        for i: grid[i].y = edx >> 6; eax += (eax * P[7]) >> 6; edx += eax
        ```
        """
        n = slot.params[10]
        if n <= 0 or n > 894:
            return
        while len(slot.grid) < n:
            slot.grid.append([0, 0, 0])
        edx = slot.params[1]
        eax = slot.params[4]
        for i in range(n):
            slot.grid[i][1] = (edx >> 6) & 0xFFFFFFFF
            eax = (eax + ((eax * slot.params[7]) >> 6)) & 0xFFFFFFFF
            edx = (edx + eax) & 0xFFFFFFFF

    def _bg_shift(self, slot, axis: int) -> None:
        """`0x456F30`（axis=0，x/+0xD0）与 `0x456F70`（axis=1，y/+0xD4）：
        整表平移 `delta = (params[axis]>>6) - grid[0][axis]`；`0x456FB0`/`0x457000` 同构。"""
        n = slot.params[10]
        if n <= 0 or not slot.grid:
            return
        col = axis
        if col > 1:                                      # 0x456FB0/0x457000 的分支形式
            col = axis - 2
        delta = (slot.params[col] >> 6) - slot.grid[0][col]
        for g in slot.grid[:n]:
            g[col] = (g[col] + delta) & 0xFFFFFFFF

    def _bg_spawn_band(self, slot, idx: int) -> None:
        """`0x457120`：按格索引建一条带并挂到 `[+0x04]` 链表头。

        格数上限 890（`0x457282 mov ecx,0xA6E`）；索引越界的带在 `0x457750` 里
        首帧就会被判出界摘链，这里直接不建（等价结果，省一次分配）。
        """
        n = slot.params[10]
        if idx < 0 or idx >= n:
            return
        if len(slot.bands) >= 890:
            return
        slot.bands.append(BgBand(slot, idx))

    def _bg_band(self, band) -> bool:
        """`0x457750`：位置推进 → 可见性 → 出界判据 → kind/w/h → 层号 → 节点矩形。
        返回 0 表示出界该摘链（`0x457210`）。"""
        slot = band.slot
        prm = slot.params
        # `0x45775D mov ecx,[eax+0x38]`，eax = [band+8] = &slot[0x30]
        # ⇒ 偏移 0x38 = (0x68-0x30)/4 = **块内第 14 个 dword**（关1 ch0 = 48）。
        # pos 是**整数格索引**（0x4578AB 的 *3 寻址全程无移位）；48 格/帧 = 36px/帧，格→像素在格子表里。
        band.pos = (band.pos + prm[14]) & 0xFFFFFFFF
        pos = band.pos if band.pos < 0x80000000 else band.pos - 0x100000000
        # 可见窗 [param[0x2C], param[0x30]] 且 param[0x4C] != 0
        lo, hi, vis = prm[11], prm[12], prm[19] & 0xFF
        band.visible = 1 if (lo <= pos <= hi and vis) else 0
        if pos < 0 or pos >= prm[10]:                         # param[0x28] = 格数
            return False
        grid = slot.grid
        kind = grid[pos][2] if pos < len(grid) else 0
        if kind != band.kind:
            band.w = (band.jit_x * kind) >> 6                # [+0x20]
            band.h = (band.jit_y * kind) >> 6                # [+0x24]
            band.kind = kind
            if kind > 0xF0:
                layer = band.layer
            else:
                idx = BG_KIND_IDX[kind] if kind < len(BG_KIND_IDX) else 0x0B
                if idx == 0:                             # 0x4577EC：隐藏
                    band.visible = 0
                elif idx != 0x0B:                        # 0x4577F5..：层号 = 2 + 序号
                    band.layer = idx + 2
        # 源矩形 (0, row*kind, kind-1, (row+1)*kind-1)；目标 = 格内 (x,y) + 抖动
        gx = grid[pos][0] if pos < len(grid) else 0
        gy = grid[pos][1] if pos < len(grid) else 0
        band.src = (0, band.row * kind, kind - 1, (band.row + 1) * kind - 1)
        band.dst = (gx + band.w - (kind >> 1), gy + band.h - (kind >> 1))
        return True

    def _bg_update(self, slot) -> None:
        """`0x457380`：速率生效 → 参数+=速率 → 分发 → 遍历带 → 滚动累加补带。"""
        if not slot.active:
            return
        if slot.rem:
            # 0x456D80(params@+0x30, rates@+0x80)：**完全展开的 19 项** dword 加法
            # （偏移 0x00..0x48，最后一条写 [eax+0x48]；函数体到 0x456E6D 结束）。
            # 第 20 项（+0x4C）不在本函数里推进 —— 那属于紧随其后的 0x456EB0。
            for i in range(19):
                slot.params[i] = (slot.params[i] + slot.rates[i]) & 0xFFFFFFFF
            slot.rem -= 1
            self._bg_dispatch(slot)
        alive = []
        for band in slot.bands:
            if self._bg_band(band):
                alive.append(band)
        slot.bands = alive                                   # 0x457210 摘链
        step = slot.params[14]                               # [slot+0x68]
        slot.acc = (slot.acc + step) & 0xFFFFFFFF
        acc = slot.acc if slot.acc < 0x80000000 else slot.acc - 0x100000000
        thresh = slot.params[13]                             # [slot+0x64]
        if abs(acc) < thresh:
            return
        if step >= 0:
            slot.acc = (acc - thresh) & 0xFFFFFFFF
            self._bg_spawn_band(slot, acc - thresh)
        else:
            slot.acc = (acc + thresh) & 0xFFFFFFFF
            self._bg_spawn_band(slot, slot.params[10] + acc - 1)

    def p4_bg_update(self) -> None:
        """S21 第一条 `0x458E75` → `0x457BD0` → 12× `0x457380`。"""
        for slot in self.p4_bg:
            self._bg_update(slot)

    def p4_bg_draw(self) -> None:
        """S22 第一条 `0x458EF5` → `0x457CB0` → 12× `0x457490`（add ecx,0xC → 0x45A170 → 0x44D010）。"""
        c = self.canvas
        for slot in self.p4_bg:
            if not slot.active:
                continue
            for band in slot.bands:
                if not band.visible or band.kind <= 0 or band.kind > 0xF0:
                    continue
                lay = self.layers.tab.get(band.layer)
                if lay is None:
                    continue
                l, t, r, b = band.src
                c.blit(lay.buf, (l, t, r + 1, b + 1), band.dst, key=lay.ckey)
                self.p4_stat[0xB6] = self.p4_stat.get(0xB6, 0) + 1

    def p4_render_ents(self) -> None:
        """`0x458EF0` 渲染遍里 0x4AD43C 队列那一轮：`0x45A170`→`0x44D010` flags=0x11（色键 0），
        源矩形先按 (0,0,640,480) 裁剪窗裁（`0x459F70` 给的整屏）。"""
        c = self.canvas
        for e in self.p4_q43c:
            nd = e.node
            if nd is None or not nd.active or e.g32(0x14) & 0x2F000000 != 0x23000000:
                continue
            lay = self.layers.tab.get(nd.layer)
            if lay is None:
                continue
            l, t, r, b = nd.rect
            dx, dy = nd.dst
            c.blit(lay.buf, (l, t, r + 1, b + 1), (dx, dy), key=lay.ckey)

    # ---- 特殊类槽行为用到的三个助手（§16.180/§16.181）------------------
    def p4_fire_slot(self, owner, type_word, vel, dx: int) -> None:
        """`0x430400` 造记录 + `0x430290` 入 `0x4AD46C`：从**发射者子对象**位置发弹。

        `0x42C83A` 记录 =(速度, 弹型, y=[owner+8], x=[owner+4]+dx)；
        记录 +0xC 是速度字段（§16.180 由"槽 0 该位为 0xE00、槽 1 改成镜像值"实证）。
        """
        if callable(vel):
            try:
                v = vel(self, owner)
            except TypeError:
                v = vel(self)
        else:
            v = vel
        self.spawn(self._p4_q("ui46c"), type_word,
                   owner.s32(0x04) + dx, owner.s32(0x08), v)

    def p4_slot_se(self) -> None:
        """`0x42C880`：声像量 = `([0x56CC8C] - 0x140) << 4`，音效号 0。"""
        pos = getattr(self, "p4_player_pos", (0x140, 0))
        self.p4_se_pan(0, ((int(pos[0]) - 0x140) << 4) & 0xFFFFFFFF)

    def p4_42C600(self, e) -> None:
        """`0x42C600`（`0x401776` 蹦床）：12 个槽发射后的**追加两发追踪弹**（§16.188）。

        ```
        0x42C604 ebx = [ecx+0x20]                     ; 发射者子对象
        0x42C607 if ([ebx+0x2C] >= 0) → ret           ; jge 整段跳过
        0x42C639 0x4021EE(0x4AD43C, &pt, &pt2)        ; 目标点 = 自机
        第一发：0x42C6A0 原点 (x+0xC, y−0xC)，默认 0xF3460CBA = (−12.73, +12.73)
                0x42C66A jns ⇒ 仅当 (ty−y+0xC) < 0 才改朝自机
        第二发：0x42C75C 原点 (x+0xC, y+0xC)，默认 0x0CBA0CBA = (+12.73, +12.73)
                0x42C72C jle ⇒ 仅当 (ty−y−0xC) > 0 才改朝自机
        定向速度 = 0x40105A 把 (tx−x−0xC, ty−y±0xC) 定长到 0x1200（= 18.0 像素/帧）
        ```
        """
        owner = e.p.get("owner")
        if owner is None:
            return
        if owner.s32(0x2C) >= 0:                       # 0x42C60A test / jge 0x42C79B
            return
        ox, oy = owner.s32(0x04), owner.s32(0x08)
        tx, ty = int(self.inp.x), int(self.inp.y)      # 0x4021EE 取到的目标点
        for dx, dy, dflt, above in ((0xC, -0xC, 0xF3460CBA, True),
                                    (0xC, 0xC, 0x0CBA0CBA, False)):
            v = dflt
            ddy = ty - oy - dy                         # 相对各自原点
            if (ddy < 0) if above else (ddy > 0):      # 0x42C66A jns / 0x42C72C jle
                vx, vy = [tx - ox - 0xC], [ddy]
                if self._vset(vx, vy, 0x1200):         # 0x40105A 定长
                    v = ((vy[0] << 16) | (vx[0] & 0xFFFF)) & 0xFFFFFFFF
            self.spawn(self._p4_q("ui46c"), 0x12061124,
                       ox + dx, oy + dy, v)            # 0x42C6A0 / 0x42C75C


    def p4_43B070(self, e, arg: int) -> None:
        """`0x43B070`：朝 `[0x56CC8C]/[0x56CC90]` 生成一枚实体进 **0x4AD49C** 队列
        （类型由 `0x43B020` 按族算出，0x23 族 → `0x31000001`）。四个几何子函数未定案，先只登记。"""
        self.p4_other.setdefault(0x4AD49C, []).append(
            (0x31000001, e.s32(0x04), e.s32(0x08), arg))

    def _p4_dbg(self) -> None:
        import os
        if not os.environ.get("GEKI_P4_DEBUG"):
            return
        k = getattr(self, "_p4_dbg_n", 0)
        self._p4_dbg_n = k + 1
        if k % 120:
            return
        lay = self.layers.tab.get(2)
        nz = 0 if lay is None else int((lay.buf != 0).sum())
        print(f"[p4dbg] f={k} ents={len(self.p4_q43c)} lay2={nz} px "
              f"fade_a={getattr(self,'fade_a',None)} pal_flags={getattr(self,'pal_flags',None)} "
              f"intro={getattr(self,'p4_intro_gate',None)} flags=0x{self.flags.bits:X} "
              f"canvas_nz={int((self.canvas.buf != 0).sum())} "
              f"pal={self.pal[:3].tolist() if hasattr(self,'pal') else None} "
              f"ui52c={len(self.ui52c)} out={ {k:len(v) for k,v in self.vm.out.items() if v} } "
              f"pal_now0={None if getattr(self,'pal_now',None) is None else self.pal_now[:3].tolist()} "
              f"canvas0={self.canvas.buf[0,:6].tolist()} "
              f"bg_act={sum(1 for x in self.p4_bg if x.active)} "
              f"bg_cnt={[x.params[10] for x in self.p4_bg[:3]]} "
              f"bg_grid={[len(x.grid) for x in self.p4_bg[:3]]} "
              f"bg_band={[len(x.bands) for x in self.p4_bg[:6]]} "
              f"bg_layer={sorted({b.layer for x in self.p4_bg for b in x.bands})} "
              f"bg_flags={[hex(x.flags) for x in self.p4_bg[:8]]} "
              f"bg_kind0={[x.grid[0][2] if x.grid else None for x in self.p4_bg[:8]]} "
              "S0=%s" % ([[self.p4_bg[0].params[i] for i in (10, 11, 12, 13, 14)],
                          self.p4_bg[0].acc if self.p4_bg[0].acc < 0x80000000 else self.p4_bg[0].acc - 0x100000000,
                          [b.pos for b in self.p4_bg[0].bands][:4]],), flush=True)

    def p4_hud(self) -> None:
        """0x4517E1：`0x44D010(0x4AA7B0,&{0xE0,0x88},0xD,&{0,0x40,0xBF,0x6F})` + 两个准星。
        准星源矩形按 `[0x4AB59C] < 0x140`（指针在左半屏）二选一。层 0xD 的资源由
        `0x460930` 装载，待该规格落地后接上。"""
        lay = self.layers.tab.get(0xD)
        if lay is None:
            return
        x = self.inp.rec.x if self.inp.rec else 0
        left = x < 0x140
        # HUD 条
        self.canvas.blit(lay.buf, (0, 0x40, 0xBF, 0x6F), (0xE0, 0x88), key=lay.ckey)
        # 准星 #1（点 0x128,0xC8）
        r1 = (0, 0x70, 0x2F, 0x9F) if left else (0x60, 0x70, 0x8F, 0x9F)
        self.canvas.blit(lay.buf, r1, (0x128, 0xC8), key=lay.ckey)
        # 准星 #2（点 0x128,0x188）
        r2 = (0x90, 0x70, 0xBF, 0x9F) if left else (0x30, 0x70, 0x5F, 0x9F)
        self.canvas.blit(lay.buf, r2, (0x128, 0x188), key=lay.ckey)

    def p4_pause(self) -> None:
        """`0x451B10`：暂停嵌套循环（每轮一帧）。

        ```
        0x451B10 if ([0x4AB59A] == 2) {              ; 特殊模式（回放/演示）
                     0x44CDF0(0x4AA7B0, 2, [0x4AB5B8]>>… *4-0xC8, …)   ; 载暗调色板
                     if (!ok) 0x45AF30(0x4AB5C0, 2) }
        0x451B68 0x458B80(this)                      ; 泵 + 帧门
        0x451B6F 0x44EB60(0x4AB454, 0x4AB594)        ; 输入记录（复刻侧 run.py 已做）
        0x451B7E SetCursorPos(0x140, 0xF0)
        0x451B96 0x458FD0(this, [0x4AB59A])          ; 键码 → 旗标
        0x451BA3 if (0x45B070(0x4AB5C0) == 0         ; 旗标为空
                     && [0x4AB59A] != 2) return 1     ; ⇒ 继续暂停
        0x451BB9 0x44CDF0(0x4AA7B0, 1, …)            ; 恢复亮调色板 ⇒ 退出暂停
        ```
        """
        n = 0
        while n < 4096:
            n += 1
            if getattr(self, "p4_ab59a", 0) == 2:            # 0x451B16
                if not self.p4_load_palette(2):               # 0x451B53
                    self.flags.set(2)                         # 0x451B5C 0x45AF30(0x4AB5C0,2)
            self.p4_pump(1)                                  # 0x451B6A
            self._p4_recenter_cursor()                       # 0x451B7E
            self.key_command(self.inp.rec.key)               # 0x451B97
            if self.flags.bits == 0 and getattr(self, "p4_ab59a", 0) != 2:
                continue                                     # 0x451BA8 仍在暂停
            self.p4_load_palette(1)                          # 0x451BF0 恢复亮版
            return
        self.log("page4.pause（0x451B10）：无头模式下限次退出")

    def btn0_edge(self) -> bool:
        """`[0x4AB596]`：输入记录 +2 的 btn0 按下沿。"""
        return bool(getattr(self.inp.rec, "e0", 0)) if self.inp.rec else False

    def p4_load_palette(self, ident: int) -> bool:
        """0x44CDF0(mgr, id, 对比, 亮度, 淡入)：按 RT_STRING id 载调色板。
        页4 阶段首帧载 id 2（bm_pald，暗版），退出时恢复 id 1（bm_pal）。"""
        pal = self.data.get("palettes", {}).get(str(ident))
        if not pal:
            return False
        import numpy as np
        self.pal = np.array(pal, dtype=np.uint8)
        self.pal_now = self.pal
        return True

    # -- 0x458D60 / 进场里尚未定案的四段（显式占位，不猜行为）
    def stage_globals(self, a1: int, a2: int) -> None:
        """0x458DBA → `0x45EB40(a1,a2)`（0x4CD4A0 的初值装配）。待规格 `docs/p4_stage_*.md`。"""
        self.p4_stat[0x4CD4A0] = 0
        return

    def stage_layers(self, a3: int, a4: int) -> None:
        """0x458DCE → `0x460930(a3,a4)`（0x4CD590 的层/调色板装配）。待同上规格。"""
        return

    def p4_layer_params(self) -> None:
        """0x450B3D..0x450B68：`0x45AFC0(0x4AB5B8,0x1FC0000)` / `(…,0xFE000000)` → `0x4010C3`。"""
        self.p4_stat[0x56CCB8] = self.keys.field(0x1FC0000)
        return

    def p4_replay_reset(self) -> None:
        """0x40224D（0x4CD5D8 回放管理器）复位。"""
        self.p4_stat[0x4CD5D8] = 0

    def p4_replay_header(self, b: bytearray) -> None:
        """0x450A25..0x450A2F：`0x401EB0(0x4CD5D8, &block)` = `0x45D160` 回放头填充
        （memcpy 0x2C 字节 + 写 "GRPD"/"106A"），在四个实参被读之前执行。回放未实现 ⇒ 占位。"""
        return

    def replay_advance(self) -> None:
        """0x458DE2 → `0x45D110(0x4CD5D8)`。"""
        return

    def replay_record(self) -> None:
        """0x451343 → `0x45D1D0(0x4CD5D8, 0x4AB594)`：录一帧 23bit。"""
        return

    def replay_play(self) -> None:
        """0x45135F → `0x45D2B0` 回放播放（仅回放页）。"""
        return

    def replay_save_score(self) -> None:
        """0x451CAB/0x451CB2：`0x45FB60(0x4CD4A0)` 取分 + `0x45D460(0x4CD5D8,0x63,分)`。"""
        return

    def stream_reset(self) -> None:
        """0x458E15 → `0x459A80(0x56B95C)`：记录流复位。"""
        self.stream_cursor = 0

    # -- 流程 VM 接口（0x4602D0 / 0x460350 / 0x460800 / 0x460E40 / 0x45F5C0 / 0x45F760）
    def cstream_preload(self, slot: int, script_id: int) -> bool:
        """（已废弃的命名）0x40127B = 0x450140 音效槽装载，见 `P4_SE_SLOTS`。"""
        return self.load_wave(slot, script_id)

    def vm_init_script(self, arg: int) -> None:
        """0x4602D0(0x56CC4C, 组号)：按 `0x499798` 链表把最多 15 个脚本 id 装进 `+0x0A` 队列，
        再 `0x4600F0` 装首流（帧计数清 0）。组号来自参数块 `+0x10`。"""
        self.vm.load_chain(arg)

    def vm_step_frame(self) -> bool:
        """0x460350(0x56CC4C)：执行一帧记录。返回 1 = 本流/链已耗尽（`0x450FE5 test al,al` 用它
        决定是否去取命令字）。"""
        return self.vm.step() != 0

    def vm_command(self) -> int:
        """0x460800 = `mov ax,word[ecx+0x2A]`：命令字就是**链索引**。"""
        return self.vm.chain

    def vm_restart(self, arg: int) -> None:
        """`0x4602D0(0x56CC4C, 9)`：命令 0 的另一条路 => 进链 9（[60]）。"""
        self.vm.load_chain(arg)

    def _p4_tick_ents(self) -> None:
        """`0x445A30`（0x4AD43C 队列行为遍）：从 `[queue+0x28]` 沿 `[ent+0x44]` 遍历；
        `[ent+0x34]` 为 0（死）→ `0x4018D4` 摘链；否则 `0x4012AD`→`0x446450 = jmp [ent+0x40]`，
        行为返回 0 → `[ent+0x34]=0` 且 `[[ent+0x38]+0x1C]=0`（隐藏显示节点）。"""
        q = self.p4_q43c
        i = 0
        while i < len(q):
            e = q[i]
            if e.m[0x34] == 0:
                del q[i]
                continue
            if not self.p4_call_behaviour(e):
                e.m[0x34] = 0
                node = e.g32(0x38)
                if node:
                    self.p4_stat[node + 0x1C] = 0
            i += 1

    def p4_call_behaviour(self, e: "Ent") -> bool:
        """`0x446450 = jmp [ent+0x40]`：按行为指针分派。未实现的行为先返回"存活"并计数，
        绝不假装完成——实现一个就在 `P4_BEH` 里登记一个。"""
        fn = P4_BEH.get(e.beh)
        if fn is None:
            self.p4_beh_missing[e.beh] = self.p4_beh_missing.get(e.beh, 0) + 1
            return True
        return fn(self, e)

    def p4_vm_entity(self, op: int, rec: tuple) -> None:
        """op1..op5 → 五个队列原语（`0x448FF0`/`0x43BDC0`/`0x43A3C0`/`0x44B140`/`0x445AA0`）。

        `0x43BDC0` 的挂链方式（`0x43BE14`/`0x43BE4C`）：`[queue+0x28]` 为空 → 头，否则挂
        `[queue+0x2C]` 尾 ⇒ **尾插**。实体内存 0x5C 字节，ctor `0x43A7F0`。
        其它四族的 ctor（`0x4355E0`/`0x449150`/`0x43D430`/`0x448FF0`）尚未实现，只登记。
        """
        a, b, c, d = rec
        if op == 2:
            self.p4_q43c.append(Ent(a, b, c, d))       # 0x43BDC0 → 0x43A7F0
            self.p4_n43c += 1
        elif op == 5 and c == 0x61000005:
            # 0x61000005：init 0x42730B（`[+0x1C]=a` 当前、`[+0x20]=b` 目标、`[+0x24]=d` 步进）
            # 链路 0 的载荷是 (-255, 0, 0x61000005, 16) = 16 帧淡入，正是开场把画面点亮的那条
            self.spawn_flash(a, b, d)
        else:
            self.p4_other.setdefault(op, []).append(rec)

    def p4_load_layers(self, res: list[int]) -> None:
        """op 0x0B → `0x460600`：`0x44CEE0` 清层，再 14 层 `0x44C640(i,res[i])`+`0x44CE60(i,0)`，
        `res[i]==5` 跳过；任一失败 → `0x4AB5C0 |= 2` 且 `[+0x38] |= 1` 并结束本流。"""
        self.layers.free_all()                    # 0x460614
        for i in range(14):                       # 0x46062F
            v = res[i] if i < len(res) else 5
            if v == 5:
                continue
            if not self.layers.bind(i, v):        # 0x44C640
                self.flags.set(2)                 # 0x4606B3
                self.vm.flags |= 1                # 0x4606BD
                break
            self.layers.color_key(i, 0)           # 0x460635 0x44CE60(i,0)

    def p4_play_bgm(self, track: int) -> None:
        """op 0x0C → `0x44F600(0x4AB514, arg1=(param!=3), arg2=param)`（资源 1..20 = 20 首 MIDI）。"""
        if self.audio is not None:
            self.audio.bgm(track)

    def p4_set_level(self, level: int) -> None:
        """op 0x0D → `0x45EF10(0x4CD4A0, word[+4])`：清 +0x14..+0x20、`word[+0x24]=level`、
        `[+0xEC]=0x4A4B64[level]`。"""
        for a in range(0x14, 0x24, 4):
            self.p4_stat[0x4CD4A0 + a] = 0
        self.p4_level = level
        self.p4_stat[0x4CD4A0 + 0x24] = level

    def sequence_started(self) -> bool:
        """0x460EE0(0x4CD590)：序列是否已启动。"""
        return False

    def sequence_start(self) -> None:
        """0x460E40(0x4CD590)：启动序列。"""
        return

    def stage_globals_begin(self) -> None:
        """0x45F5C0(0x4CD4A0)。"""
        return

    def stage_globals_end(self) -> None:
        """0x45F760(0x4CD4A0)：结算/收尾。"""
        return
