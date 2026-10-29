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


def _beh_10000001(self, e) -> bool:
    """`0x401E06` → `0x448C70`（自机，类型 0x10000001）。

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

P4_BEH: dict[int, object] = {
    0x40E070: _beh_23000001,
    0x40E100: _beh_23000002,
    0x40E460: _beh_23000004,
    0x448C70: _beh_10000001,
    0x40E790: _beh_23000007,
    0x40E8C0: _beh_23000008,
    0x40EAF0: _beh_23000009,
    0x40E520: _beh_23000005_06,
    0x40E230: _beh_23000003,
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
        self.sysf2.bits = (1 if self.keys.test(1) else 0) | (2 if self.keys.test(2) else 0)
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
            self.p4_collide_pair(self._p4_q("ui46c"), self.p4_q43c)   # 0x451493 0x43C060(0x4AD46C,0x4AD43C)
            self.p4_collide_pair(self._p4_q("ui40c"), self._p4_q("ui49c"))  # 0x4514A6 0x43C0F0(0x4AD40C,0x4AD49C)
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

    def p4_seq_tick(self) -> None:
        """`0x4CD484` 序列引擎的 tick（跳过帧与正常帧都会走它；规格待落地）。"""
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
        self.tick_ui(self.actorq)                 # 0x4AD40C
        self.tick_ui(self.ui46c)                  # 0x4AD46C
        self._p4_tick_ents()                      # 0x4AD43C（页4 实体队列）
        self.tick_ui(self.p4_ui49c)               # 0x4AD49C
        self._tick_wipe4f()                       # 0x4AD4CC
        self._tick_spark4cc()                     # 0x4AD4CC
        self.tick_ui(self.ui4fc)                  # 0x4AD4FC
        self.tick_ui(self.ui52c)                  # 0x4AD52C
        # 0x4AD55C 发射器 / 0x4CD484 序列引擎：待 VM 规格落地后实现

    # ---- 自机输入/队列辅助（0x448C70 用）----------------------------------
    # ---- 碰撞（0x451461..0x4514A6 三组）------------------------------
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
        0x43C190 sub 0xAFFFFFB → t==0x10000001：b[0x18]=0（自机被击中）
        其余 → 直接返回
        ```
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
        elif t == 0x10000001:                             # 0x43C19B 自机被击中
            b.d32(0x18, 0)
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

    def p4_hud_update(self, e) -> None:
        """`0x460A90`：把数字矩形写进显示节点 `[+0x2C]+4`，再 `0x4011FE` 推进渲染表。"""
        if e.node is not None:
            e.node.src = self.p4_hud_rect(e.s32(0x30))    # 0x460ACE..0x460AE4
            e.node.visible = 1
        self.p4_stat[0x11FE] = self.p4_stat.get(0x11FE, 0) + 1   # 0x460AE7 → 0x45A170

    def p4_frame_no(self) -> int:
        """`[0x56CCA8]`：全局帧计数器（`0x451442` 每帧 ++）。"""
        return int(getattr(self, "p4_frames", 0))

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
            for i in range(20):                              # 0x456D80
                slot.params[i] = (slot.params[i] + slot.rates[i]) & 0xFFFFFFFF
            slot.params[19] = (slot.params[19] & ~0xFF) | (slot.rates[19] & 0xFF)
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
        """0x451B10 暂停循环：`0x44ECC0` 重读键盘 → SetCursorPos → 键命令，
        条件 `0x4AB5C0 非空 || 键码==2` 才退出。无头模式下直接返回（不阻塞）。"""
        self.log("page4.pause（0x451B10）：无头模式跳过阻塞循环")

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
