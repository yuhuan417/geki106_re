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

import collections
import json
import math
import os
import struct

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


_P4_SCORE_TABLES = None


def p4_score_tables():
    """`0x4993CC..0x4996FF` 的得分描述表区（10 个关卡指针共用，`build_p4_str.py` 导出）。

    0x45EF33 把 `[0x4A4B64 + level*4]` 写进 `[0x4CD4A0+0xEC]`；`0x45F029`/`0x45FB12`
    再按 `(type&0xFF)` 从**该只读区**取 dword（不是可写 p4_stat！）。"""
    global _P4_SCORE_TABLES
    if _P4_SCORE_TABLES is None:
        try:
            import json as _j
            from pathlib import Path as _P
            _d = _j.loads((_P(__file__).with_name("p4_score_tables.json")).read_text())
            _P4_SCORE_TABLES = (int(_d["base"]), list(_d["words"]))
        except Exception:
            _P4_SCORE_TABLES = (0x4993CC, [])
    return _P4_SCORE_TABLES


def p4_score_entry(base: int, i: int) -> int:
    """读 `[[base] + i*4]` 的只读表项；越界/未知 base 返回 0。"""
    tbase, words = p4_score_tables()
    off = (int(base) - tbase) // 4 + int(i)
    return words[off] & 0xFFFFFFFF if 0 <= off < len(words) else 0


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
        """`0x45DDA0(id)`..`0x45DDE0(id)`。

        调试：`P4_MOB=<低字节>:<帧>`（仅流 46）在首条 t>该值的记录前**插入**一条
        op2 `(660,240,0x23000<低字节>,0)`——其余字节一律不动，游标序先到先执行。
        例：`P4_MOB=10:200` 把怒插到第一波弱之前（原 t=5320 起的三只在后面照常刷）；
        `P4_MOB=15:1300` 把王插到原位之前。只改内存副本，不动 resource_dec.bin。"""
        o = self._u24(sid)
        e = self._u24(sid + 1) if sid < self.n else len(self.d)
        buf = self.d[o:e]
        mob = os.environ.get("P4_MOB")
        if mob and sid == 46:
            low_s, at_s = mob.split(":")
            low, at = int(low_s, 0), int(at_s, 0)
            buf = bytearray(buf)
            cur, ins = 0, len(buf)
            while cur + 4 <= len(buf):
                op = int.from_bytes(buf[cur:cur + 2], "little")
                t = int.from_bytes(buf[cur + 2:cur + 4], "little")
                if op == 0 or t > at:
                    ins = cur
                    break
                if op == 9:
                    n = int.from_bytes(buf[cur + 0xC:cur + 0x10], "little")
                    cur += 0x10 + n * 4
                else:
                    cur += ScriptVM.SIZES.get(op, 0x14)
            buf[ins:ins] = struct.pack("<2H4I", 2, at, 660, 240, 0x23000000 | (low & 0xFF), 0)
            buf = bytes(buf)
        return buf


class ScriptVM:
    """`0x56CC4C` 的字段级复刻（`docs/p4_vm_0x460350.md`）。

    +04 帧计数｜+08 当前流 id｜+0A 待播队列 w[16]｜+2A 链索引｜+2C 缓冲｜+30 游标｜+34 终止｜+38 旗标
    """

    # 记录总长（含 4 字节头）；op9 变长，op0 特例 edi=0
    # 每条 op 的推进量（handler 里的 `mov edi, IMM`）。op 0 = `xor edi,edi`（0x460695），
    # 它走 `0x4600F0` 换流后**不推进游标**（新游标由 0x4600F0 重置），step() 里提前 continue。
    SIZES = {0x0: 0, 0x1: 0x14, 0x2: 0x14, 0x3: 0x14, 0x4: 0x14, 0x5: 0x14,
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
        self.halt = False                    # 0x4606C2 当帧 return 1 但不置 [+0x34]
        # 0x460280 的 reset：queue/frame/cur/buf/term 全清（旧实现只 append，二次装链会残留）
        self.queue = []
        self.frame = 0
        self.cur = 0
        self.buf = b""
        self.term = 0
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
        # 0x46011E..0x4601B3：进度位（0x4AB5B0）
        # 表 {0x2E,0x2F,0x30,0x31,0x32,0x33,0x34,0x3C}，k=1..8；cur_id==表[k-1] 且
        # 当前 0xF00000 < k → 写 k（单调取大）；cur_id==0x46 → bit31（二周目解锁）。
        if self.owner is not None:
            keys = getattr(self.owner, "keys", None)
            if keys is not None:
                tbl = (0x2E, 0x2F, 0x30, 0x31, 0x32, 0x33, 0x34, 0x3C)
                if self.cur_id in tbl:
                    k = tbl.index(self.cur_id) + 1
                    if keys.field(0xF00000) < k:
                        keys.set_field(0xF00000, k)
                if self.cur_id == 0x46:
                    keys.set_field(0x80000000, keys.field(0x80000000) | 0x80000000)
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
            if op > 0xE:                      # 0x4603A2 非法 op（exe 为未初始化 edi，UB）
                self.term = 1                 # 复刻侧明确终止，避免 cur 不前进死循环
                return 1
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
            if self.halt:                     # 0x4606C2：op0B 失败 → 当帧 return 1、不推进、不置 term
                self.halt = False
                return 1
            if self.term:
                return 1
            self.cur += edi                   # 0x4603EE
            if not self.buf:                  # 0x460404
                return 1

    def exec_op(self, op: int, body: bytes) -> None:
        import os as _os
        if _os.environ.get("P4_VMTRACE"):
            print(f"[vm] f={self.frame} op={op:#x} body={body[:0x14].hex()}", flush=True)
        if op == 0xE:
            # 0x4603E9：跳表第 14 项**直接指向共用尾**（`mov edi,0x14; jmp 0x4603EE`），
            # 也就是 op 0xE **没有任何副作用**，只是把游标推进 0x14。
            # 之前把它当成"字符串记录"是错的（没有任何消费者）；这里只推进游标。
            pass
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
            ch = int.from_bytes(body[0:4], "little")
            self.out[8].append(ch)
            if self.owner is not None:
                self.owner.p4_bg_stop(ch)                        # 0x457C80 → 0x457260
        elif op == 0x9:                                          # 0x460512 变长表
            n = int.from_bytes(body[8:0xC], "little")
            vals = [int.from_bytes(body[0xC + 4 * i:0x10 + 4 * i], "little") for i in range(n)]
            self.out[9].append((int.from_bytes(body[0:4], "little"),
                                int.from_bytes(body[4:8], "little"), vals))
            # 0x460512 本体：0x4561D0(0x4CD484, 表=[esi+0x10], count=[esi+0xC],
            #                    startIdx=[esi+4], scroll=[esi+8])——**立即装载色带表**。
            # 表项 dword = {u8 color, u8 pad, i16 h}（h 在高半，band_draw 读 [idx*4+2]）。
            if self.owner is not None:
                self.owner.band_push(
                    [(v & 0xFF, _p4_s16(v >> 16)) for v in vals],
                    n,
                    int.from_bytes(body[0:4], "little"),
                    int.from_bytes(body[4:8], "little"))
            if os.environ.get("P4_BANDTRACE"):
                print(f"[band] t={self.owner.p4_frames if self.owner else '?'} "
                      f"count={n} start={int.from_bytes(body[0:4], 'little')} "
                      f"scroll={int.from_bytes(body[4:8], 'little')} "
                      f"vals_full={[(v & 0xFF, _p4_s16(v >> 16)) for v in vals]}")
        elif op == 0xA:                                          # 0x460538
            # 0x460538 本体：0x456240(0x4CD484, [esi+4], [esi+8])——设置滚动速度/帧数。
            if self.owner is not None:
                self.owner.band_scroll_for(
                    int.from_bytes(body[0:4], "little"),
                    int.from_bytes(body[4:8], "little"))
            self.out[0xA].append((int.from_bytes(body[0:4], "little"),
                                  int.from_bytes(body[4:8], "little")))
        elif op == 0xB:                                          # 0x460600 装层
            # 实测记录体正好 0x38=56 字节 = 14 个 dword，**没有**额外头；
            # `0x46060C add esi,4` 跳的是记录里的 op 字段（esi 进来时指向 op）。
            res = [int.from_bytes(body[4 * i:4 + 4 * i], "little") for i in range(14)]
            self.out[0xB].append(res)
            if self.owner is not None:
                self.owner.p4_load_layers(res)
        elif op == 0xC:                                          # 0x46064A 播 BGM
            dword = int.from_bytes(body[0:4], "little")
            v = dword & 0xFFFF
            self.out[0xC].append(v)
            if self.owner is not None:
                self.owner.p4_play_bgm(v, skip=(dword != 3))    # 0x460652 setne → arg1
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
    # 0x23000009（0x40DAB2）：[+0x1C]=0x500、[+0x20]=0、[+0x24]=x<<8、[+0x28]=y<<8、
    #   [+0x2C]=0 —— 8.8 位置累加器必须从出生点起算，否则行为 0x40E9B0 的
    #   `[0x24]/[0x28]` 从 0 开始 ⇒ 敌机从 (0,0) 附近窜出（旧表只有行为指针）。
    0x23000009: {"beh": 0x4015AA, "imm": {0x1C: 0x500, 0x20: 0, 0x2C: 0}, "xy8": True},
    # 0x2300000A（0x40DAE7）：[+0x1C]=-6、[+0x20]=-48、[+0x24]=0 —— **跳**（足+兆，
    #   正弦航迹）的相位必须从负半周开始。旧表漏了这三项 ⇒ 相位只增不减，y 从 456
    #   漂到 597（屏幕底 480 以下），跳只剩上半截露在屏内；相位回卷后又「复原」。
    0x2300000A: {"beh": 0x401181, "imm": {0x1C: -6, 0x20: -48, 0x24: 0}},
    0x2300000D: {"beh": 0x40210D, "imm": {}},
    0x2300000E: {"beh": 0x401BA9, "vtup": True, "r1sh": (0x24, 4)},   # 0x40DB72
    0x2300000F: {"beh": 0x40138E, "vtup": True, "r1sh": (0x24, 4)},   # 0x40DBA4
    # 0x23000012（0x40DC71）：[+0x1C]=0、[+0x20]=-0x20、[+0x24]=0、[+0x28]=(y<=0xF0?-1:1)、
    #   [+0x2C]=0 —— 旧表全空 ⇒ 行为 0x40F4F0 的 y 速度恒 0、x 速度系数恒 0。
    0x23000012: {"beh": 0x4015B4, "imm": {0x1C: 0, 0x20: -0x20, 0x24: 0, 0x2C: 0},
                 "d28": True},
    # 0x23000013（0x40DD09）：[+0x1C]=0、[+0x20]=payload[0xC]。
    0x23000013: {"beh": 0x40231A, "imm": {0x1C: 0}, "d_to": 0x20},
    # 0x23000015（0x40DD27）：[+0x1C]=payload[0xC]、[+0x20]=0、[+0x24]=rec0<<4、
    #   [+0x28]=rec1<<4、[+0x2C]=[+0x30]=0 —— 8.4 位置累加器初值（2026-11-12 修：
    #   缺这两条 ⇒ 行为 0x40F880 首帧 x=(0+8)>>4=0，boss 瞬移到 (0,0) 邻域 ⇒
    #   "第一关 boss 看不见"）。[+0x1C] 的 ctor 初值此前也漏了（脚本 d=0，暂未显形）。
    0x23000015: {"beh": 0x4017EE, "imm": {0x20: 0}, "d_to": 0x1C,
                 "r01sh4": ((0x24, 0), (0x28, 1))},
    0x23000016: {"beh": 0x401D48, "imm": {}},
    0x23000017: {"beh": 0x401951,
                 "imm": {0x24: 0, 0x28: 0x1E, 0x2C: 0, 0x30: 0},
                 "p3pair": (0x1C, 0x20)},   # ctor 0x40DDB6：[0x1C]=p3[0]、[0x20]=p3[1]
    # 0x23000018（0x40DDE4）：[+0x1C]=payload[0xC]、[+0x20]=-0x18、[+0x24]=0xF、
    #   [+0x28]=0 —— 旧表全空。
    0x23000018: {"beh": 0x4013BB, "imm": {0x20: -0x18, 0x24: 0xF, 0x28: 0},
                 "d_to": 0x1C},
    0x23000019: {"beh": 0x401B31, "imm": {0x24: 0x60}, "r01sh4": ((0x1C, 0), (0x20, 1)), "d_to": 0x28},
    0x2300001A: {"beh": 0x40242D,
                 "imm": {0x1C: 0, 0x24: 0xFFFFFFC0, 0x28: 0},
                 "slot1": True, "d20_y78": True, "r01sh4_2C30": True},
    # —— 2026-11-11 补齐缺失 5 型（ctor case 0x40DB0D/0x40DB2D/0x40DBD6/0x40DBF5/0x40DCAA）——
    0x2300000B: {"beh": 0x401D75, "imm": {0x1C: 0, 0x20: -0x1E, 0x24: 0}},
    0x2300000C: {"beh": 0x401609, "imm": {}, "d_to": 0x1C},
    0x23000010: {"beh": 0x402040, "imm": {0x1C: 0x24, 0x28: 0xC1}},
    # 0x23000011（0x40DBF5）：byte[0x10]=0；+0x1C=(0x140+rand%0xF0-x)/0x50、
    #   +0x20=(0x28+rand%0x190-y)/0x50、+0x24=+0x28=0
    0x23000011: {"beh": 0x401DC5, "b10_0": True, "imm": {0x24: 0, 0x28: 0},
                 "tp_grid": True},
    # 0x23000014（0x40DCAA）：rect = p3==0?{F0,F0,11F,11F}:{180,F0,1AF,11F}、
    #   +0x1C=0、+0x20=p3（0x40DD09 共用体）
    0x23000014: {"beh": 0x40231A, "z1c": True, "d_to": 0x20,
                 "rect_s3": ((0xF0, 0xF0, 0x11F, 0x11F), (0x180, 0xF0, 0x1AF, 0x11F))},
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
    # 0x0A..0x1A：2026-11-05 从 0x498000 直接读出补全——此前只有 9 条，低字节 ≥0x0A 的
    # 敌机（0x2300000A/0B/0D/0E/10/11/12/15…含关1 boss 0x23000015）无半径/HP/显示节点=隐形，
    # 表现为"关1 后段没敌人、boss 没出现"。
    0x0A: (24, 0x14, 0x200, 0x1E0, 0), 0x0B: (24, 0x32, 0x340, 0x00, 0x60),
    0x0C: (24, 0xF0, 0x00, 0x00, 0x30), 0x0D: (72, 0x20, 0x00, 0x120, 0x30),
    0x0E: (48, 1, 0x00, 0x30, 0x30), 0x0F: (24, 0x0A, 0x00, 0x60, 0x90),
    0x10: (18, 0xC1, 0xFE00, 0x1B0, 0x10), 0x11: (24, 1, 0x240, 0x00, 0xC0),
    0x12: (24, 0x32, 0x400, 0x60, 0x00), 0x13: (24, 0x14, 0x2C0, 0x120, 0xF0),
    0x14: (24, 0x00, 0x00, 0x00, 0x00), 0x15: (72, 0xC80, 0x00, 0x90, 0x30),
    0x16: (24, 0xC80, 0x00, 0x00, 0x90), 0x17: (24, 0x00, 0x00, 0x00, 0x90),
    0x18: (24, 0xF0, 0x3C0, 0xC0, 0xF0), 0x19: (24, 0x0F, 0x00, 0x30, 0x90),
    0x1A: (24, 1, 0x200, 0x00, 0x00),
}

# 族属性表（2026-11-11 定案）：0x43AC30 的表址按族不同——0x23:0x498000、0x24:0x498138、
# 0x25:0x498208、0x26:0x498290、0x27:0x4983B0、0x28:0x498480、0x29:0x4985A0（各族 ctor
# 开头 `push <表址>; call 0x402455`）。此前 ENT_PROP 只有 0x23 一张，却按 type&0xFF
# 应用到所有族 ⇒ 0x24..0x29 的半径/存活门/[+0x58]/源矩形全错。此表按**完整 type** 键入，
# 值 = (半径, 存活门(0→-1), [+0x58], srcx, srcy)，从 exe 逐条读出。
# 0x2A/0x2C/0x2D 族 ctor 不调 0x43AC30（+0xC/+0x18 由各 case 手写），故无表项。
ENT_PROP_FAM = {
    0x23000001: (24, 1, 512, 0, 0),
    0x23000002: (24, 1, 384, 48, 0),
    0x23000003: (24, 20, 512, 0, 0),
    0x23000004: (24, 320, -640, 384, 0),
    0x23000005: (24, 72, 0, 192, 0),
    0x23000006: (24, 1, 448, 240, 0),
    0x23000007: (24, 1, 0, 144, 0),
    0x23000008: (24, 100, 0, 288, 0),
    0x23000009: (24, 40, 704, 336, 0),
    0x2300000a: (24, 20, 512, 480, 0),
    0x2300000d: (72, 32, 0, 288, 48),
    0x2300000e: (48, 1, 0, 48, 48),
    0x2300000f: (24, 10, 0, 96, 144),
    0x23000012: (24, 50, 1024, 96, 0),
    0x23000013: (24, 20, 704, 288, 240),
    0x23000015: (72, 3200, 0, 144, 48),
    0x23000016: (24, 3200, 0, 0, 144),
    0x23000017: (24, -1, 0, 0, 144),
    0x23000018: (24, 240, 960, 192, 240),
    0x23000019: (24, 15, 0, 48, 144),
    0x2300001a: (24, 1, 512, 0, 0),
    0x24000001: (24, 1, 512, 0, 0),
    0x24000002: (24, 20, 640, 0, 48),
    0x24000003: (24, -1, 0, 0, 96),
    0x24000004: (24, 60, 704, 288, 144),
    0x24000005: (24, 30, 576, 336, 0),
    0x24000006: (24, 50, -640, 336, 48),
    0x24000007: (24, 10, 0, 336, 96),
    0x24000008: (24, 160, 0, 336, 144),
    0x24000009: (24, 15, 0, 0, 192),
    0x2400000a: (24, 240, 704, 48, 192),
    0x2400000b: (24, 320, -512, 96, 192),
    0x2400000c: (24, 10, 0, 144, 192),
    0x2400000d: (24, 1, 640, 192, 192),
    0x2400000e: (24, 30, 0, 240, 192),
    0x2400000f: (24, 60, 1920, 288, 192),
    0x24000010: (24, 1, 576, 384, 192),
    0x24000011: (48, 120, 576, 384, 0),
    0x25000001: (24, 1, 640, 0, 288),
    0x25000002: (24, 10, 640, 48, 288),
    0x25000003: (24, 50, 704, 96, 288),
    0x25000004: (24, 30, -768, 144, 288),
    0x25000005: (24, 1, 0, 192, 288),
    0x25000006: (24, -1, 0, 240, 288),
    0x25000007: (24, 22, 0, 288, 288),
    0x25000008: (48, 960, 0, 336, 0),
    0x25000009: (72, 7200, 832, 336, 192),
    0x2500000a: (24, 380, 0, 0, 0),
    0x26000001: (24, 1, 704, 0, 0),
    0x26000002: (24, 1023, 896, 48, 0),
    0x26000003: (24, 1, 704, 96, 0),
    0x26000004: (24, 1, -896, 144, 0),
    0x26000005: (24, -1, 0, 192, 0),
    0x26000006: (24, -1, -640, 240, 0),
    0x26000007: (24, 100, 768, 288, 0),
    0x26000008: (24, 1, 0, 96, 192),
    0x26000009: (24, 240, -1024, 384, 0),
    0x2600000a: (24, 1, 768, 432, 0),
    0x2600000b: (24, 1, -2048, 0, 192),
    0x2600000c: (24, 100, -704, 48, 192),
    0x2600000d: (24, 1, 0, 96, 192),
    0x2600000e: (24, 1, 640, 144, 192),
    0x2600000f: (24, 1, 640, 192, 192),
    0x26000010: (24, 1, 704, 240, 192),
    0x26000011: (24, 120, 736, 288, 192),
    0x26000012: (24, 140, 800, 336, 192),
    0x26000013: (24, 1, 704, 384, 192),
    0x26000014: (24, 80, 0, 432, 192),
    0x26000015: (24, 1, 0, 0, 384),
    0x26000016: (24, 120, -1024, 48, 384),
    0x26000017: (24, 120, 1408, 96, 384),
    0x26000018: (24, 120, 640, 336, 0),
    0x27000001: (24, 24, 832, 240, 0),
    0x27000002: (24, 20, 768, 288, 0),
    0x27000003: (24, 60, 960, 336, 0),
    0x27000004: (24, 140, 896, 384, 0),
    0x27000005: (24, 30, 768, 432, 0),
    0x27000006: (24, 50, 768, 240, 96),
    0x27000007: (24, 1, 640, 288, 96),
    0x27000008: (24, 30, 832, 336, 96),
    0x27000009: (24, 60, 896, 384, 96),
    0x2700000a: (24, 50, 0, 432, 96),
    0x2700000b: (24, 1, 704, 240, 192),
    0x2700000c: (48, 200, -640, 192, 240),
    0x2700000d: (48, 640, 768, 288, 240),
    0x2700000e: (48, 50, 0, 384, 240),
    0x2700000f: (120, 8000, 0, 0, 0),
    0x27000010: (96, 1280, 0, 0, 240),
    0x27000011: (0, 1, 0, 0, 0),
    0x28000001: (24, 25, 832, 0, 96),
    0x28000002: (24, 60, 832, 48, 96),
    0x28000003: (24, 12, 0, 96, 96),
    0x28000004: (24, 100, 896, 144, 96),
    0x28000005: (24, 10, 768, 192, 96),
    0x28000006: (24, 30, 864, 240, 96),
    0x28000007: (24, 160, 896, 288, 96),
    0x28000008: (24, 60, 1088, 336, 96),
    0x28000009: (24, 8, 0, 0, 240),
    0x2800000a: (24, 20, 960, 48, 240),
    0x2800000b: (24, 1, 0, 96, 240),
    0x2800000c: (24, 60, 960, 144, 240),
    0x2800000d: (24, 220, -768, 192, 240),
    0x2800000e: (24, 20, 1024, 240, 240),
    0x2800000f: (24, 20, 896, 288, 240),
    0x28000010: (24, 10, 1056, 336, 240),
    0x28000011: (16, 1, 0, 0, 384),
    0x28000012: (48, 640, 832, 384, 192),
    0x28000013: (72, 4800, 0, 336, 288),
    0x28000014: (24, 6400, 0, 432, 0),
    0x28000015: (24, -1, 0, 432, 0),
    0x28000016: (24, -1, 0, 336, 240),
    0x28000017: (0, -1, 0, 0, 0),
    0x28000018: (24, 40, 0, 384, 240),
    0x29000001: (24, 80, 896, 0, 0),
    0x29000002: (96, 3200, 0, 240, 0),
    0x29000003: (12, 512, 0, 48, 0),
    0x29000004: (24, 3, 0, 0, 48),
    0x29000005: (24, 40, 0, 0, 96),
    0x29000006: (24, 1, 0, 192, 48),
    0x29000007: (24, -1, 960, 48, 0),
    0x29000008: (24, -1, 960, 48, 48),
    0x29000009: (24, -1, 960, 48, 96),
    0x2900000a: (24, -1, 960, 48, 144),
    0x2900000b: (24, -1, 960, 48, 192),
    0x2900000c: (24, 140, 1088, 0, 192),
    0x2900000d: (24, -1, 0, 192, 0),
    0x2900000e: (48, 512, 1024, 96, 0),
    0x2900000f: (12, -1, 0, 0, 0),
    0x29000010: (0, -1, 1344, 0, 0),
    0x29000011: (48, 512, 0, 416, 336),
    0x29000012: (48, 640, 0, 0, 240),
    0x29000013: (48, 60, 0, 96, 240),
    0x29000014: (24, 40, 896, 288, 288),
    0x29000015: (72, 3600, 0, 96, 96),
    0x29000016: (24, 20, 1024, 48, 192),
    0x29000017: (48, 320, 960, 0, 336),
    0x29000018: (120, 9600, 0, 240, 0),
    0x29000019: (24, -1, 0, 0, 0),
    0x2900001a: (24, -1, 0, 0, 0),
    0x2900001b: (24, -1, 0, 0, 0),
    0x2900001c: (24, -1, 0, 384, 288),
    0x2900001d: (24, -1, 0, 384, 240),
    0x2900001e: (24, -1, 0, 0, 0),
    0x2900001f: (24, -1, 0, 0, 0),
    0x29000020: (24, -1, 0, 0, 0),
    0x29000021: (16, -1, 0, 432, 240),
}


# `0x445C00` 各分支写进 [ent+0x40] 的行为 thunk → 真址（2026-11-05 补全）：
#   type1 八变体 / type5 八变体（0x446C50 族=狙击发射器） / type8 / type9 / type10 / 0x0B000001
P4_445C00_THUNK = {
    0x401B6D: 0x4466F0, 0x401A7D: 0x4467D0, 0x40143D: 0x446890, 0x401E3D: 0x446950,
    0x401D9D: 0x446A10, 0x4020F9: 0x446AD0, 0x4023F6: 0x446B50, 0x402199: 0x446BD0,
    0x40197E: 0x446C50, 0x401FBE: 0x446D30, 0x4023B5: 0x446E20, 0x401960: 0x446F10,
    0x40189D: 0x447000, 0x401438: 0x447110, 0x401ECE: 0x447200, 0x401FC3: 0x447320,
    0x4015FF: 0x447410, 0x4020BD: 0x447640, 0x40116D: 0x447F90, 0x401BE0: 0x448230,
    0x401E06: 0x448C70,
}


# 0x24 族（关2）ctor case 表（0x410A20，跳表 0x410CF4，17 型）——2026-11-06 逐 case 转写
# case4/5 共体（0x410B13）：[0x1C]=rec[3]、[0x20]=(rec[1]<<16)|(rec[0]&0xFFFF)、[0x24]=0x240012、[0x28]=[0x2C]=0
# case16：[0x20]=*rec[3]、[0x24]=rec[3][1]（解引用！）、[0x28]=rand%0x28 余数
ENT24_INIT = {
    0x24000001: {"beh": 0x4014CE, "imm": {0x20: -0x20, 0x24: 1, 0x28: 0x30}, "s3_to": 0x2C, "r1sh": (0x1C, 3)},
    0x24000002: {"beh": 0x401834, "imm": {0x20: 0x40, 0x24: -1, 0x28: 0x30}, "s3_to": 0x2C, "r1sh": (0x1C, 4)},
    0x24000003: {"beh": 0x401CEE, "imm": {0x1C: 0, 0x20: -0x20}, "d_to": 0x24},
    0x24000004: {"beh": 0x401A73, "imm": {0x1C: 0, 0x24: -0x10}, "r1sh": (0x20, 3)},
    0x24000005: {"beh": 0x4021AD, "imm": {0x24: 0x240012, 0x28: 0, 0x2C: 0},
                 "p2016": True, "d3_to": 0x1C},
    0x24000006: {"beh": 0x401AB9, "imm": {0x24: 0x240012, 0x28: 0, 0x2C: 0},
                 "p2016": True, "d3_to": 0x1C},
    0x24000007: {"beh": 0x401163, "imm": {0x1C: 0, 0x20: 0}},
    0x24000008: {"beh": 0x40119A, "imm": {}},
    0x24000009: {"beh": 0x401C8A, "imm": {0x1C: 0}, "d20_eq": True},
    0x2400000A: {"beh": 0x401D8E, "imm": {0x1C: 0, 0x20: -0x14}, "d_to": 0x24},
    0x2400000B: {"beh": 0x40155F, "imm": {0x1C: 8}},
    0x2400000C: {"beh": 0x401C4E, "imm": {0x1C: 8, 0x20: 0x28}, "b10_0": True, "d_to": 0x24},
    0x2400000D: {"beh": 0x40169F, "imm": {0x20: -8, 0x24: 0}, "r0m": (0x1C, 0x258)},
    0x2400000E: {"beh": 0x401C6C, "imm": {0x1C: 0}, "d16_pair": (0x20, 0x24)},
    0x2400000F: {"beh": 0x40132A, "imm": {0x1C: 0x20, 0x28: -0x30, 0x2C: 0x30},
                 "r01sh8": (0x20, 0x24)},
    0x24000010: {"beh": 0x401C3A, "imm": {0x1C: 0x20, 0x28: 0, 0x2C: 0},
                 "r01sh16": (0x20, 0x24)},
    0x24000011: {"beh": 0x401221, "imm": {0x1C: 0}, "deref3": True},
}


# 行为 thunk（写进 `[ent+0x40]`）→ 真实函数（`jmp rel32` 解引用）。
# `P4_BEH` 一律按**真实地址**登记，ctor 时就把 thunk 解成真实地址存进 `Ent.beh`。
ENT23_BEH_THUNK = {
    0x4016C7: 0x41DD70,   # 0x29000007..0B 入场体 thunk
    0x401C44: 0x40E070, 0x401FF0: 0x40E100, 0x401B1D: 0x40E230, 0x40118B: 0x40E460,
    0x401BD1: 0x40E520, 0x402180: 0x40E790, 0x401528: 0x40E8C0, 0x401181: 0x40EAF0,
    0x4015AA: 0x40E9B0,
    0x401BA9: 0x40EF60, 0x40138E: 0x40F0F0,   # 0x2300000E/0F 残骸
    0x40210D: 0x40EDB0, 0x4015B4: 0x40F4F0, 0x40231A: 0x40F610, 0x4017EE: 0x40F880,
    0x401D48: 0x40FEA0, 0x401951: 0x410470, 0x4013BB: 0x40FD10, 0x401B31: 0x4107D0,
    0x40242D: 0x4108C0,   # 0x23 族剩余 thunk（0x2300000D/12/13/15/16/17/18/19/1A）      # 类型 0x23000009 的 thunk（0x43A899 家族之外，经 ctor 表写入）
    # 0x24 族（0x410A20 ctor，2026-11-06 解析）
    0x4014CE: 0x410E10, 0x401834: 0x410F20, 0x401CEE: 0x411040, 0x401A73: 0x411120,
    0x4021AD: 0x411200, 0x401AB9: 0x4112F0, 0x401163: 0x4113E0, 0x40119A: 0x411470,
    0x401C8A: 0x4114C0, 0x401D8E: 0x4115B0, 0x40155F: 0x4116C0, 0x401C4E: 0x411790,
    0x40169F: 0x4118C0, 0x401C6C: 0x411990, 0x40132A: 0x411A00, 0x401C3A: 0x411AD0,
    0x401221: 0x411C10,
    # 0x25 族（0x411E20 ctor）
    0x401339: 0x4121C0, 0x40114F: 0x4122D0, 0x401046: 0x4123E0, 0x40135C: 0x412510,
    0x402397: 0x412680, 0x4012BC: 0x4127E0, 0x4024C8: 0x412950, 0x401078: 0x412B60,
    0x401186: 0x4130D0, 0x4012D0: 0x413930,
    # 0x26 族（0x4139F0 ctor）
    0x4021D5: 0x414080, 0x402392: 0x414170, 0x4017F8: 0x414380, 0x401FE1: 0x414460,
    0x4019BF: 0x4145A0, 0x401EBA: 0x4148B0, 0x401C85: 0x414B50, 0x401CA8: 0x414C70,
    0x401F46: 0x414E40, 0x401C3F: 0x414FB0, 0x4010FA: 0x415140, 0x4020E0: 0x415200,
    0x401677: 0x415410, 0x4011D6: 0x415480, 0x401578: 0x4156D0, 0x401906: 0x4158A0,
    0x40124E: 0x415980, 0x401EA6: 0x415A90, 0x4022D4: 0x415BB0, 0x401CD0: 0x415CE0,
    0x401E9C: 0x415D70, 0x4015F0: 0x415E60, 0x4021CB: 0x414D60,
    # 0x27 族（0x415EF0 ctor）
    0x401E7E: 0x4164B0, 0x401DB1: 0x4165A0, 0x402239: 0x416680, 0x401C71: 0x416770,
    0x401348: 0x416860, 0x401BEF: 0x416940, 0x402356: 0x416A50, 0x402414: 0x416B20,
    0x4010CD: 0x416BE0, 0x4014BF: 0x416CF0, 0x401A78: 0x416FA0, 0x401E0B: 0x417160,
    0x4016CC: 0x417280, 0x402117: 0x417410, 0x4014F6: 0x4175C0, 0x4013A7: 0x4185C0,
    0x4021E4: 0x418C30,
    # 0x28 族（0x418CB0 ctor）
    0x40164A: 0x4194A0, 0x401433: 0x419540, 0x4019F6: 0x419610, 0x4022E8: 0x4196E0,
    0x401B8B: 0x4197B0, 0x40248C: 0x419850, 0x40254A: 0x419910, 0x4019F1: 0x419A30,
    0x4021C1: 0x419C60, 0x401B3B: 0x419D50, 0x401CE4: 0x419E30, 0x402018: 0x419EC0,
    0x401523: 0x419F80, 0x401E92: 0x41A090, 0x4013AC: 0x41A180, 0x4024B9: 0x41A220,
    0x4018BB: 0x419B70, 0x4010AA: 0x41A300, 0x4018F2: 0x41A480, 0x401230: 0x41AE20,
    0x4012B7: 0x41BDA0, 0x401B18: 0x41BF60,
    # 0x29 族（0x41C040 ctor）
    0x402121: 0x41CF70, 0x40125D: 0x41D080, 0x401758: 0x41D330, 0x4015A5: 0x41D910,
    0x40134D: 0x41D990, 0x401D7F: 0x41DCE0, 0x4018A7: 0x41E7B0, 0x40211C: 0x41E960,
    0x4011EF: 0x41EB60, 0x4021C6: 0x41F010, 0x4019D8: 0x41EC40, 0x401EFB: 0x41EE00,
    0x4010BE: 0x41F3A0, 0x4023A1: 0x41F610, 0x4017E9: 0x41F700, 0x4018CF: 0x41F780,
    0x401398: 0x41F860, 0x40217B: 0x41FE10, 0x4013C5: 0x4200C0, 0x401CCB: 0x421FE0,
    0x401384: 0x4220A0, 0x40140B: 0x422170, 0x40209F: 0x4225E0, 0x401474: 0x422830,
    0x401F6E: 0x422950, 0x401A82: 0x422A90, 0x40166D: 0x422D40,
    # 0x2A 族（0x40A410 ctor）
    0x4018C5: 0x40A930, 0x401E60: 0x40B040, 0x401ED8: 0x40BB60, 0x401B22: 0x40C590,
    0x4011BD: 0x40CE90, 0x401E29: 0x40D030,
    # 0x2C 族（0x403AA0 ctor）
    0x401B9F: 0x4047E0, 0x401712: 0x404D00, 0x401E33: 0x404FA0, 0x401A55: 0x4051A0,
    0x40101E: 0x4053A0, 0x401EE7: 0x405510, 0x40136B: 0x405600, 0x4015DC: 0x4064E0,
    0x401A14: 0x4068C0, 0x401AA0: 0x406A20, 0x4010C8: 0x406BD0, 0x401D66: 0x406D30,
    0x40158C: 0x407350, 0x40103C: 0x406F60, 0x402167: 0x4070E0, 0x4015E6: 0x407180,
    # 0x2D 族（0x408150 ctor）
    0x401EBF: 0x408540, 0x4017DA: 0x4098E0, 0x401690: 0x409C20, 0x4014AB: 0x40A020,
    0x401C7B: 0x422470, 0x401852: 0x422DD0,   # 0x2900001C 真身 / 掉落自爆切换
    0x401D75: 0x40EBB0, 0x401609: 0x40ECE0,   # 0x2300000B/0C
    0x402040: 0x40F190, 0x401DC5: 0x40F2D0,   # 0x23000010/11
}


import random as _random

rng = _random.Random(0x4593C2)     # 原作用的是 CRT rand()，复刻侧固定种子以便无头复现

BG_LADDER = (6, 10, 16, 24, 32, 48, 72, 108, 160, 240)   # 0x457050 栈上阶梯表

# `0x457938`：241 字节 kind → 阶梯序号表（非阶梯值一律 0x0B = 不改层；0 = 隐藏）
BG_KIND_IDX = [0x0B] * 241
for _k, _i in ((0, 0), (6, 1), (10, 2), (16, 3), (24, 4), (32, 5),
               (48, 6), (72, 7), (108, 8), (160, 9), (240, 10)):
    BG_KIND_IDX[_k] = _i

# `0x4987F4` 调色板重映射表 A（0x44D290 的 COLORFILL 色号经它变换；remap_tables.json 提取件）
try:
    with open(os.path.join(os.path.dirname(os.path.dirname(
        os.path.dirname(os.path.abspath(__file__)))), "remap_tables.json")) as _rf:
        P4_REMAP_A = bytes(json.load(_rf)["remap_A"])
except Exception:                                       # 文件缺失时按恒等
    P4_REMAP_A = bytes(range(256))


def _p4_trunc10(v: int) -> int:
    """0x45E988/0x45E9FA 的 0x66666667×sar2 魔数 = 向零截断除 10。"""
    return v // 10 if v >= 0 else -((-v) // 10)


def _p4_s16(v: int) -> int:
    v &= 0xFFFF
    return v - 0x10000 if v & 0x8000 else v


def _p4_s32(v: int) -> int:
    v &= 0xFFFFFFFF
    return v - 0x100000000 if v & 0x80000000 else v


def _p4_s8(v: int) -> int:
    v &= 0xFF
    return v - 0x100 if v & 0x80 else v


def st_nodes(st, key):
    """HUD 显示表的节点列表（单节点键也归一为列表）。"""
    v = st.get(key)
    if v is None:
        return ()
    return v if isinstance(v, list) else (v,)


def _p4_result_stamp() -> bytes:
    """0x46411A（time → localtime）+ 0x463FBA（格式化）的日期时间串
    （记录 +0x1C 起 0x24 字节；复刻用本地时间，格式同 0x465B1C 的 %Y/%m/%d %H:%M:%S 族）。"""
    import time as _t
    lt = _t.localtime()
    return ("%04d/%02d/%02d %02d:%02d:%02d" % (lt.tm_year, lt.tm_mon, lt.tm_mday,
                                               lt.tm_hour, lt.tm_min, lt.tm_sec)).encode("ascii")


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
    """`0x4AD55C` 的 12 个背景槽之一（元素 0x2A98 字节，`0x457B60` → `0x463C4F`）。

    布局（`0x457260` 复位 + `0x457380`/`0x457490`/`0x4574C0` 的读法逐项对出）：
    `+4`/`+8` = 带状体链表头/尾（`next` 在 `[band+0x30]`，`0x4571B8` 挂尾）；
    `+0xC`/`+0x10` = 显示链宿主（头/计数，`0x45A170` 渲染、`0x45A070` 清空）；
    `+0x30..+0x80` = 20 项参数块（`0x456D50` 拷入）；`+0x80..+0xD0` = 20 项速率块
    （`0x457330` 拷入，`0x456D80` 每帧累加）；`+0xD0..` = 网格（0xA6E dword =
    890 格 × 3 dword `{x, y, kind}`，`0x457260` 清零界）；`+0x2A88` 速率剩余帧、
    `+0x2A8C` 分发位、`+0x2A90` 启用、`+0x2A94` 滚动累加器。
    """

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


def _idiv_trunc(a: int, b: int) -> int:
    """C `idiv` 的截断商（Python // 向下取整，负数差 1）。"""
    return -((-a) // b) if a < 0 else a // b


_P4_ACTIVE_PAGES = None


class Ent:
    """0x5C 字节实体；`[+0x34]` 存活字节、`[+0x40]` 行为指针、`[+0x14]` 类型。"""

    SZ = 0x5C

    # 队列渲染/文字路径用的是 UiEntity 的接口名，这里给字节模型实体补两个别名
    texts: tuple = ()

    @property
    def disp(self):
        return self.node

    @property
    def alive(self) -> bool:
        """`[+0x34]` 存活字节（`0x430486` 置 1）；队列 tick 用统一的 `.alive` 接口。"""
        return self.m[0x34] != 0

    @alive.setter
    def alive(self, v) -> None:
        self.m[0x34] = 1 if v else 0

    def g16(self, off: int) -> int:
        return self.m[off] | (self.m[off + 1] << 8)

    def d16(self, off: int, v: int) -> None:
        self.m[off] = v & 0xFF
        self.m[off + 1] = (v >> 8) & 0xFF

    def __init__(self, a: int, b: int, typ: int, d: int):
        self._pages = _P4_ACTIVE_PAGES      # ctor 内 _deref_link 需要它解析父指针
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
        self.p: dict = {}                 # 复刻侧 Python 链接（owner/pod1 等；不在 exe 内存模型里）
        if typ == 0x21000001:                    # 0x43A899（0x21 族里唯一有专有构造的）
            # 0x43A8AA [e+0x40] = 0x401E2E ；0x43A8B1 byte[+0x10]=1
            # 0x43A8B4 [+0xC]=0x18 ；0x43A8BB [+0x18]=1
            # 0x43A8BE eax=[rec+4]<<5 → [+0x1C]      （rec[4] 就是 y ⇒ y<<5）
            # 0x43A8CA [+0x20]=0 ；0x43A8D0 [+0x24]=rec[0xC]
            # 0x43A8D3 0x45A750(&r,0xC0,0x1B0,0xEF,0x1DF) → 节点 src 矩形
            # 0x43A912 0x45A690(x-0x18, y-0x18) → 节点 dst；0x43A934 byte[节点+0x1C]=1
            self.d32(0x40, 0x401E2E)
            self.beh = 0x43AEB0
            self.m[0x10] = 1
            self.d32(0x0C, 0x18)
            self.d32(0x18, 1)
            self.d32(0x1C, (b << 5) & 0xFFFFFFFF)
            self.d32(0x20, 0)
            self.d32(0x24, d & 0xFFFFFFFF)
            # 节点层号来自 `0x43048A 0x45A0E0([+0x3C])`；`+0x3C` 取自 rec[0x10]（此处 0）
            self.node = DNode(self.s32(0x3C), 0xC0, 0x1B0)
            self.node.dst = (self.s32(0x04) - 0x18, self.s32(0x08) - 0x18)
            self.node.active = 1
            return
        # 0x43A7F0 定案（2026-11-14）：基构造器按 `type & 0x2F000000` 分派 prop/节点路径——
        # 0x21→专用 ctor（上方提前 return）、0x23→0x4013D9、0x24→0x401D52、0x25→0x4010F5、
        # 0x26→0x4014FB、0x27→0x401F19、0x28→0x401C58、0x29→0x402243、0x2A→0x4017D0、
        # 0x2B→内联(0x40=0x4020A4、byte[+0x10]=1、+0xC=0x10)、0x2C→0x40227A、0x2D→0x401361，
        # **其余（含 0x22/0x2E/0x2F 与 0x2F 掩码外的
        # 自机 1、伴随机 0x1000001/5/8、0x51/0x42/0x0B 族）一律跳 0x43AAF4 直接返回**：
        # 无 prop、无节点、[+0xC]/[+0x18]/[+0x58]/byte[+0x10] 全 0（0x430440 的 rep stosd）。
        # 旧写法 `ENT_PROP.get(typ & 0xFF)` 把 0x23 的字节索引表套给了低字节偶然命中的
        # 其它类型——伴随机 0x1000001/5/8 各得一个 active 敌机节点（dst=(−24,−24) 且其行为
        # 从不移动节点）⇒ 进关卡左上角 (0,0) 钉死几个 48×48 图块不消失。
        prop = ENT_PROP_FAM.get(typ)
        if prop is None and (typ & 0xFF000000) == 0x23000000:
            prop = ENT_PROP.get(typ & 0xFF)        # 0x498000：0x23 族字节索引表
        if prop is not None:
            if True:
                self.d32(0x0C, prop[0])           # 半径
                self.d32(0x18, prop[1])           # 存活门
                self.d32(0x58, prop[2])
                self.m[0x10] = 1                  # 0x43ACC0 参与碰撞
                self.node = DNode(2, prop[3], prop[4])   # 0x43ACC3 层号恒 2
                # 0x43AC8C..0x43AC95：矩形 = {srcx, srcy, srcx+2r-1, srcy+2r-1}
                self.node.rect = (prop[3], prop[4],
                                  prop[3] + 2 * prop[0] - 1, prop[4] + 2 * prop[0] - 1)
                # 0x43ACD7：node dst = (x-r, y-r)（r=半径，非固定 0x18）
                self.node.dst = (self.s32(4) - prop[0], self.s32(8) - prop[0])
            info = ENT23_INIT.get(typ)
            if info is not None:
                thunk = info["beh"]
                self.d32(0x40, thunk)                  # 原版存 thunk
                self.beh = ENT23_BEH_THUNK.get(thunk, thunk)   # 复刻侧按真实地址分派
                for off, val in info.get("imm", {}).items():
                    self.d32(off, val & 0xFFFFFFFF)
                if "d_to" in info:
                    self.d32(info["d_to"], d & 0xFFFFFFFF)
                if info.get("d20"):       # 0x40D98E：`[+0x20] = (b<=0xF0) ? -1 : 1`
                    self.d32(0x20, 0xFFFFFFFF if b <= 0xF0 else 1)
                if info.get("d28"):       # 0x40DC78 `setle/dec/and 0xFFFFFFFE/inc`：y<=0xF0 → +1，否则 −1
                    self.d32(0x28, 1 if b <= 0xF0 else 0xFFFFFFFF)
                if "r1sh" in info:        # 0x40DB72/0x40DBA4：[off] = rec[1] << n
                    off, n = info["r1sh"]
                    self.d32(off, (b << n) & 0xFFFFFFFF)
                if "r01sh4" in info:      # 0x40DD3E：[(off, rec_idx), …] → [off] = rec[idx]<<4
                    for off, idx in info["r01sh4"]:
                        self.d32(off, ((a if idx == 0 else b) << 4) & 0xFFFFFFFF)
                if info.get("xy8"):       # 0x40DAC9/0x40DAD1：[0x24]=x<<8、[0x28]=y<<8
                    self.d32(0x24, (a << 8) & 0xFFFFFFFF)
                    self.d32(0x28, (b << 8) & 0xFFFFFFFF)
                if "vtup" in info and isinstance(d, tuple):
                    self.d32(0x1C, d[0] & 0xFFFFFFFF)
                    self.d32(0x20, (d[1] << 4) & 0xFFFFFFFF)
                if info.get("slot1"):        # 0x40DE43：[0x18]=0x45AFC0(0x4AB5B0,0xC000)+1
                    pg = getattr(self, "_pages", None)
                    if pg is not None:
                        self.d32(0x18, (pg.keys.field(0xC000) + 1) & 0xFFFFFFFF)
                if info.get("d20_y78"):      # 0x40DE5A：[0x20]=(y>=0x78)?+1:-1
                    self.d32(0x20, 1 if b >= 0x78 else 0xFFFFFFFF)
                if info.get("r01sh4_2C30"):  # 0x40DE6E：[0x2C]=x<<4、[0x30]=y<<4
                    self.d32(0x2C, (a << 4) & 0xFFFFFFFF)
                    self.d32(0x30, (b << 4) & 0xFFFFFFFF)
                if "p3pair" in info and isinstance(d, tuple):   # 0x40DDB6：p3[0]/p3[1]
                    o1, o2 = info["p3pair"]
                    self.d32(o1, int(d[0]) & 0xFFFFFFFF)
                    self.d32(o2, int(d[1]) & 0xFFFFFFFF)
        self._apply_family_init(typ, a, b, d)          # 0x24-0x2D 各族（ENT24_INIT 等）

    def _deref_link(self, h: int):
        """句柄 → 实体（id&0x7FFFFFFF ↔ Pages.p4_links；无宿主/无链接 → None）。"""
        p = getattr(self, "_pages", None)
        if p is None:
            return None
        return getattr(p, "p4_links", {}).get(h & 0x7FFFFFFF)

    def _apply_family_init(self, typ: int, a: int, b: int, d: int) -> None:
        """0x24-0x2D 各族 ctor case 体（ENT24_INIT 等）。rec = (a, b, typ, d)。"""
        info = (ENT24_INIT.get(typ) or ENT25_INIT.get(typ) or ENT26_INIT.get(typ)
                or ENT27_INIT.get(typ) or ENT28_INIT.get(typ) or ENT29_INIT.get(typ)
                or ENT2A_INIT.get(typ) or ENT2C_INIT.get(typ) or ENT2D_INIT.get(typ))
        if info is None:
            return
        thunk = info["beh"]
        self.d32(0x40, thunk)
        self.beh = ENT23_BEH_THUNK.get(thunk, thunk)
        if "node" in info:                             # 0x2A/0x2C/0x2D 族 ctor 自建节点
            layer, l, t, r, b2 = info["node"]
            self.node = DNode(layer, l, t)
            self.node.rect = (l, t, r, b2)
            self.node.active = 1
        if info.get("b10_1"):
            self.m[0x10] = 1
        if "dst" in info and self.node is not None:
            dx, dy = info["dst"]
            self.node.dst = (a + dx, b + dy)
        for off, val in info.get("imm", {}).items():
            self.d32(off, val & 0xFFFFFFFF)
        if info.get("spawn_5c"):                       # ctor 尾：0x5C000002 @(0,0) prm=自身
            _pg = getattr(self, "_pages", None)
            if _pg is not None:
                _h = id(self) & 0x7FFFFFFF
                _pg.p4_links[_h] = self
                _pg.spawn(_pg._p4_q("ui4fc"), 0x5C000002, 0, 0, _h)
        if info.get("r1_2C_1"):                         # [0x2C]=rec1&1
            self.d32(0x2C, b & 1)
        if info.get("s2c0c"):                          # 0x404059：0x2C00000C
            self.d32(0x1C, a & 0xFFFFFFFF)
            self.d32(0x20, d & 0xFFFFFFFF)
            self.d32(0x28, 0)
            k = b & 1
            if self.node is not None:
                self.node.rect = (0, ((3 * k + 3) << 5) & 0xFFFFFFFF, 0x5F,
                                  ((3 * k << 5) + 0xBF) & 0xFFFFFFFF)
                self.node.dst = (a - 0x30, b - 0x30)
        if info.get("s2c0d"):                          # 0x4040F2：0x2C00000D
            self.d32(0x1C, a & 0xFFFFFFFF)
            self.d32(0x20, b & 0xFFFFFFFF)
            _pg = getattr(self, "_pages", None)
            self.d32(0x24, (((_pg.p4_rand() if _pg is not None else 0) & 0xF) + 0xF) & 0xFFFFFFFF)
            self.d32(0x28, 0)
            self.d32(0x2C, 0)
            self.d32(0x30, 0x10)
            self.d32(0x0C, 0x30)
            self.m[0x10] = 0
            if self.node is not None:
                self.node.dst = (a - 0x30, b - 0x30)
        if info.get("s2c05"):                          # 0x403C31：0x2C000005
            self.d32(0x18, 1)
            self.m[0x10] = 1
            self.d32(0x24, (a << 8) & 0xFFFFFFFF)
            self.d32(0x28, (b << 8) & 0xFFFFFFFF)
            if self.node is not None:
                self.node.dst = (a - 0x18, b - 0x18)
        if info.get("s2907"):                          # 0x41C16E：0x29000007..0B 共用
            tgt = self._deref_link(d) if d else None
            if a != 0:                                  # rec0 != 0：普通僚机
                self.d32(0x18, 0x14)
                if tgt is not None:
                    self.d32(0x1C, tgt.g32(0))
                    self.d32(0x20, tgt.g32(4))
                    self.d32(0x24, tgt.g32(8))
                self.d32(0x28, 0)
                self.d32(0x2C, 0)
                self.d32(0x30, 0)
            else:                                       # rec0==0：Boss 入场体
                self.d32(0x40, 0x4016C7)
                self.beh = 0x41DD70
                self.d32(0x04, 0x298)
                self.d32(0x18, 0xB4)
                if tgt is not None:
                    self.d32(0x1C, (tgt.g32(0) >> 8) & 0xFFFFFFFF)
                self.d32(0x20, 0)
                self.d32(0x24, -8 & 0xFFFFFFFF)
                self.d32(0x28, 0)
                if self.node is not None:
                    self.node.dst = (0x298, b - 0x18)
        if info.get("s2a05"):                          # 0x40A65F：0x2A000005 + rec3 改写
            pg = getattr(self, "_pages", None)
            px = pg.p4_player_x() if pg is not None else 0
            py = pg.p4_player_y() if pg is not None else 0
            self.d32(0x14, (0x2A000005 + d) & 0xFFFFFFFF)
            self.d32(0x0C, 0x18)
            self.m[0x10] = 1
            self.d32(0x1C, 0)
            ang0 = (pg.p4_45a9a0(px - a, py - b) if pg is not None else 0)
            r = (pg.p4_rand() & 0x1FF) if pg is not None else 0
            ang = (r + ang0 - 0xFF) & 0xFFFFFFFF
            self.d32(0x20, (page4_cos(ang) * 3 >> 3) & 0xFFFFFFFF)
            self.d32(0x24, (page4_sin(ang) * 3 >> 3) & 0xFFFFFFFF)
            self.d32(0x28, (a << 4) & 0xFFFFFFFF)
            self.d32(0x2C, (b << 4) & 0xFFFFFFFF)
            self.d32(0x18, 0xA)
            self.node = DNode(3, 0, 0)
            self.node.rect = (0, ((d * 3 + 0xC) << 4) & 0xFFFFFFFF, 0x2F,
                              ((d * 3 << 4) + 0xEF) & 0xFFFFFFFF)
            self.node.dst = (a - 0x18, b - 0x18)
            self.node.active = 1
        if info.get("s19_fields"):                     # 0x4084AE：0x2D000019
            self.d32(0x1C, d & 0xFFFFFFFF)
            self.d32(0x20, b & 0xFFFFFFFF)
            self.d32(0x24, a & 0xFFFFFFFF)
            self.d32(0x28, d & 0xFFFFFFFF)
            self.d32(0x2C, typ & 0xFFFFFFFF)
            self.d32(0x30, 0)
            self.m[0x10] = 1
        if info.get("d30_yf0"):                        # 0x41C41A：[+0x30]=(y>0xF0)
            self.d32(0x30, 1 if b > 0xF0 else 0)
        if info.get("s0f_fields"):                     # 0x41C260：0x2900000F
            self.d32(0x20, abs(24 * a - 0x54) & 0xFFFFFFFF)
            self.d32(0x24, 0x708 if a <= 3 else 0)
            if self.node is not None:
                self.node.rect = ((0x1B0, 0x198, 0x1C7, 0x1AF) if a < 2
                                  else (0x1C8, 0x198, 0x1DF, 0x1AF))
                self.node.dst = (a - 0x18, b - 0x18)
        if "rect_link" in info:                        # *(rec+off)!=0 → rectA，否则 rectB
            which, off, ra, rb = info["rect_link"]
            h = b if which == "b" else a
            tgt = self._deref_link(h) if h else None
            cond = tgt is not None and tgt.g32(off) != 0
            if self.node is not None:
                self.node.rect = ra if cond else rb
                self.node.dst = (a - 0x30, b - 0x30)
        if "rect_cmp" in info:                         # 0x41CA98：rec1==值 → rectA，否则 rectB
            val, ra, rb = info["rect_cmp"]
            if self.node is not None:
                self.node.rect = ra if (b & 0xFFFFFFFF) == (val & 0xFFFFFFFF) else rb
                self.node.dst = (a - 0x30, b - 0x30)
        if info.get("s10_fields"):                     # 0x41C344：0x29000010
            self.d32(0x0C, (4 * a + 8) & 0xFFFFFFFF)
            self.d32(0x1C, d & 0xFFFFFFFF)
            self.d32(0x20, a & 0xFFFFFFFF)
            self.d32(0x24, (0x140 * b) & 0xFFFFFFFF)
            if self.node is None:
                self.node = DNode(2, 0, 0)
            self.node.rect = (0xC0 + 24 * (a & 6), 0xF0 + 0x30 * (a & 1),
                              0xEF + 24 * (a & 6), 0x11F + 0x30 * (a & 1))
            self.node.dst = (a - 0x18, b - 0x18)
        if info.get("s04_fields"):                     # 0x418DBF：+0x28=rec1、+0x30=rec3
            self.d32(0x28, b & 0xFFFFFFFF)
            self.d32(0x30, d & 0xFFFFFFFF)
        if info.get("s09_fields"):                     # 0x418F38：y += (y>=0xF0?+0x1E:−0x1E)、+0x20=rec1
            yy = (b + (0x1E if b >= 0xF0 else -0x1E)) & 0xFFFFFFFF
            self.d32(0x08, yy)
            self.d32(0x20, b & 0xFFFFFFFF)
            if self.node is not None:
                self.node.dst = (a - 0x18, (yy - 0x18) & 0xFFFFFFFF)
        if info.get("s11_fields"):                     # 0x418EAE：+0x20=rec1<<4、+0x24=±0x40、+0x28=rec3
            self.d32(0x20, (b << 4) & 0xFFFFFFFF)
            self.d32(0x24, (-0x40 if b >= 0xF0 else 0x40) & 0xFFFFFFFF)
            self.d32(0x28, d & 0xFFFFFFFF)
            if self.node is not None:
                self.node.rect = (0, 0x180, 0x2F, 0x1AF)
        if info.get("randpos"):                        # 0x413BA3..0x413BDB：屏幕右侧外随机落点
            import random as _r
            self.d32(0x04, ((_r.randrange(0x100) & 0xFF) +
                            (_r.randrange(0x80) & 0x7F) + 0x2B8) & 0xFFFFFFFF)
            self.d32(0x08, ((_r.randrange(0x100) & 0xFF) +
                            (_r.randrange(0x80) & 0x7F) + 0x30) & 0xFFFFFFFF)
        if info.get("rnd_retarget"):                   # 0x413C13/0x413C3A：随机落点速度（/0x3C）
            import random as _r
            self.d32(0x1C, _idiv_trunc((_r.randrange(0x244) - a), 0x3C) & 0xFFFFFFFF)
            self.d32(0x20, _idiv_trunc((_r.randrange(0x1E0) - b), 0x3C) & 0xFFFFFFFF)
            self.d32(0x24, 0)
            self.d32(0x28, 8)
        if "s3_to" in info:                            # rec[3]（符号扩展）→ 目标
            self.d32(info["s3_to"], d & 0xFFFFFFFF)
        if "d_to" in info:
            self.d32(info["d_to"], d & 0xFFFFFFFF)
        if "d3_to" in info:
            self.d32(info["d3_to"], d & 0xFFFFFFFF)
        if "r1sh" in info:                             # [off] = rec[1] << n
            off, n = info["r1sh"]
            self.d32(off, (b << n) & 0xFFFFFFFF)
        if "r0m" in info:                              # [off] = rec[0] - m
            off, m = info["r0m"]
            self.d32(off, (a - m) & 0xFFFFFFFF)
        if "r01sh4" in info:                           # 0x40DD3E：rec[0]<<4 / rec[1]<<4
            o1, o2 = info["r01sh4"]
            self.d32(o1, (a << 4) & 0xFFFFFFFF)
            self.d32(o2, (b << 4) & 0xFFFFFFFF)
        if "r01sh8" in info:                           # 0x410C47：rec[0]<<3 / rec[1]<<3
            o1, o2 = info["r01sh8"]
            self.d32(o1, (a << 3) & 0xFFFFFFFF)
            self.d32(o2, (b << 3) & 0xFFFFFFFF)
        if "r01sh16" in info:                          # 0x410C7F：rec[0]<<4 / rec[1]<<4
            o1, o2 = info["r01sh16"]
            self.d32(o1, (a << 4) & 0xFFFFFFFF)
            self.d32(o2, (b << 4) & 0xFFFFFFFF)
        if "p2016" in info:                            # 0x410B1D：[0x20]=(rec1<<16)|(rec0&FFFF)
            self.d32(0x20, ((b << 16) | (a & 0xFFFF)) & 0xFFFFFFFF)
        if "d20_eq" in info:                           # 0x410B7C：byte[0x10]=(rec3==0)、[0x20]=rec3
            self.m[0x10] = 1 if d == 0 else 0
            self.d32(0x20, d & 0xFFFFFFFF)
        if "b10_0" in info:
            self.m[0x10] = 0
        if "d16_pair" in info:                         # 0x410C32：rec3 低/高 16 位符号展开
            o1, o2 = info["d16_pair"]
            lo = d & 0xFFFF
            hi = (d >> 16) & 0xFFFF
            lo = lo - 0x10000 if lo & 0x8000 else lo
            hi = hi - 0x10000 if hi & 0x8000 else hi
            self.d32(o1, lo & 0xFFFFFFFF)
            self.d32(o2, hi & 0xFFFFFFFF)
        if "vtup" in info and isinstance(d, tuple):    # 0x40DB72/0x40DBA4：rec3=&{vx,vy}
            self.d32(0x1C, d[0] & 0xFFFFFFFF)          #   [0x1C] = prm[0]
            self.d32(0x20, (d[1] << 4) & 0xFFFFFFFF)   #   [0x20] = prm[1]<<4
        if "deref3" in info:                           # 0x410CC8：[0x20]=*rec3、[0x24]=rec3[1]
            tgt = self._deref_link(d)
            if tgt is not None:
                self.d32(0x20, tgt.g32(0x00))
                self.d32(0x24, tgt.g32(0x04))
            # 0x410CD6：push 0x28 → rand → 0x462D71 → [0x28]=余数（公转相位 0..0x27）
            self.d32(0x28, rng.randrange(0x28) & 0xFFFFFFFF)
        if "z1c20" in info:                            # [0x1C]=[0x20]=0
            self.d32(0x1C, 0)
            self.d32(0x20, 0)
        if "z1c" in info:
            self.d32(0x1C, 0)
        if "z1c_24" in info:                           # [0x1C]=[0x20]=[0x24]=0
            self.d32(0x1C, 0)
            self.d32(0x20, 0)
            self.d32(0x24, 0)
        if "z1c20_24" in info:
            self.d32(0x1C, 0)
            self.d32(0x20, 0)
            self.d32(0x24, 0)
        if "r0sh" in info:                             # [off] = rec[0] << n
            off, n = info["r0sh"]
            self.d32(off, (a << n) & 0xFFFFFFFF)
        if "r1sh" in info:
            off, n = info["r1sh"]
            self.d32(off, (b << n) & 0xFFFFFFFF)
        if "s16lohi" in info:                          # rec3 低/高 16 位符号展开
            o1, o2 = info["s16lohi"]
            lo = d & 0xFFFF
            hi = (d >> 16) & 0xFFFF
            lo = lo - 0x10000 if lo & 0x8000 else lo
            hi = hi - 0x10000 if hi & 0x8000 else hi
            self.d32(o1, lo & 0xFFFFFFFF)
            self.d32(o2, hi & 0xFFFFFFFF)
        if "angle_to_ship" in info:                    # 0x411E9D：0x45A9A0(自机−rec01) → [0x1C]（角度）
            pg = getattr(self, "_pages", None)
            sx = pg.p4_player_x() if pg else 0
            sy = pg.p4_player_y() if pg else 0
            self.d32(info["angle_to_ship"], page4_45a9a0(sy - b, sx - a) & 0xFFFFFFFF)
        if "ship_y_gate" in info:                      # 0x411EEC：自机 y<0xF0 才写 [ent+8]=0x1E0−rec1
            sy = self._pages.p4_player_y() if getattr(self, "_pages", None) else 0
            if sy < 0xF0:
                self.d32(8, (0x1E0 - b) & 0xFFFFFFFF)
        if "node_hidden" in info:                      # 节点 dst=(ent.x−0x18, ent.y−0x18)、隐藏
            if self.node is not None:
                self.node.dst = (self.s32(4) - 0x18, self.s32(8) - 0x18)
                self.node.active = 0
        if "rand_pair" in info:                        # 0x4120A0：[0x24]=rand&0x3F+0x10、[0x28]=rand&0x3F
            import random as _r
            self.d32(0x24, ((_r.randrange(0x7FFFFFFF) & 0x3F) + 0x10) & 0xFFFFFFFF)
            self.d32(0x28, (_r.randrange(0x7FFFFFFF) & 0x3F) & 0xFFFFFFFF)
        if "z1c_20" in info:
            self.d32(0x1C, 0)
            self.d32(0x20, 0)
        if "z1c_24_28" in info:
            self.d32(0x1C, 0)
            self.d32(0x20, 0)
            self.d32(0x24, 0)
            self.d32(0x28, 0)
        if "z20" in info:
            self.d32(0x20, 0)
        if info.get("active0"):                        # ctor 建节点但 active=0
            if self.node is not None:
                self.node.active = 0
        if info.get("node_off"):                       # ctor 只把 node.active 清 0
            if self.node is not None:
                self.node.active = 0
        if info.get("b10_eq0"):                        # byte[0x10] = (rec3 == 0)（0x413CA4）
            self.m[0x10] = 1 if d == 0 else 0
        if info.get("node_vis_eq0"):                   # node.active = (rec3 == 0)（0x413CC0）
            if self.node is not None:
                self.node.active = 1 if d == 0 else 0
        if "b10_ne0" in info:                          # byte[0x10] = (rec3 != 0)
            self.m[0x10] = 1 if d != 0 else 0
        if "node_vis_ne0" in info:                     # byte[节点+0x1C] = (rec3 != 0)
            if self.node is not None:
                self.node.active = 1 if d != 0 else 0
        if "rand_pm4" in info:                         # 0x413A30：rand%2 → ±2 → [0x24]
            import random as _r
            v = 4 if (_r.randrange(0x7FFFFFFF) % 2) else 0
            self.d32(info["rand_pm4"], ((v ^ 4) - 4 + 4 - 2) & 0xFFFFFFFF)  # neg/sbb/and 4/add −2
        if "cmpgate" in info:                          # setCC/dec/and N/add K：
            off, N, K, cc = info["cmpgate"]            #   cond 真 → K；假 → ((−1)&N)+K
            if cc == "ge":
                cond = b >= 0xF0
            elif cc == "le":
                cond = b <= 0xF0
            elif cc == "g":
                cond = b > 0xF0
            elif cc == "l":
                cond = b < 0xF0
            elif cc == "ge140":
                cond = a >= 0x140
            else:
                cond = False
            v = K if cond else (((-1) & N) + K)
            self.d32(off, v & 0xFFFFFFFF)
        if "z1c_20_24_28_2C" in info:
            for o in (0x1C, 0x20, 0x24, 0x28, 0x2C):
                self.d32(o, 0)
        if "z20_24" in info:
            self.d32(0x20, 0)
            self.d32(0x24, 0)
        if "cmpgate2" in info:
            off, N, K, cc = info["cmpgate2"]
            cond = (b > 0xF0) if cc == "g" else (b >= 0xF0)
            v = K if cond else (((-1) & N) + K)
            self.d32(off, v & 0xFFFFFFFF)
        if "deref3_20_24" in info:                     # 0x4160A9：[0x20]=rec3[0x20]、[0x24]=rec3[0x24]?? —— rec3[0x20/0x24]
            tgt = self._deref_link(d)
            if tgt is not None:
                self.d32(0x20, tgt.g32(0x20))
                self.d32(0x24, tgt.g32(0x24))
        if "d_to_ptr" in info:                         # 0x416262：[0xC]=rec3[0xC]；拷父节点 src/dst；rec3=父句柄
            tgt = self._deref_link(d)
            if tgt is not None:
                self.d32(0x0C, tgt.g32(0x0C))
                if tgt.node is not None and self.node is not None:
                    w = tgt.g32(0x0C)                  # 0x4162BA：rect += (0, 2w, 0, 2w)
                    r = tgt.node.rect
                    self.node.rect = (r[0], r[1] + 2 * w, r[2], r[3] + 2 * w)
                    self.node.dst = tuple(tgt.node.dst)
        if info.get("d3div3"):                         # 0x416240：[0x30]=rec3/3（截断）
            self.d32(0x30, _idiv_trunc(d, 3) & 0xFFFFFFFF)
        if "d3mod3" in info:                           # 0x41620D：rec3%3 → 0x4016F9/0x4020E5/0x4013A7
            v = d % 3
            th = (0x4016F9, 0x4020E5, 0x4013A7)[v]
            self.d32(0x40, th)
            self.beh = {0x4016F9: 0x417940, 0x4020E5: 0x417F30,
                        0x4013A7: 0x4185C0}[th]
        if "r1_20" in info:                            # [0x20] = rec[1]（原值）
            self.d32(0x20, b & 0xFFFFFFFF)
        if "r0_1C" in info:
            self.d32(0x1C, a & 0xFFFFFFFF)
        if "abs3_24" in info:                          # [0x24] = |rec[3]|（0x418CF3 cdq/xor/sub）
            v = d - 0x100000000 if d & 0x80000000 else d
            self.d32(0x24, abs(v) & 0xFFFFFFFF)
        if "g0_gate" in info:                          # rec[3]>0 → K else N（setg/dec on rec3）
            off, N, K = info["g0_gate"]
            self.d32(off, (K if d > 0 else N) & 0xFFFFFFFF)
        if "s12_gate2b" in info:
            off, N, K, cc = info["s12_gate2b"]
            cond = (d > 0) if cc == "g0" else (b >= 0xF0)
            vv = K if cond else (((-1) & N) + K)
            self.d32(off, vv & 0xFFFFFFFF)
        if "rand_spawn" in info:                       # 0x418D5A：随机 x ∈[0x298,0x298+0x3F]、y=0x114
            import random as _r
            rx = 0x298 + (_r.randrange(0x7FFFFFFF) & 0x3F)
            self.d32(4, rx & 0xFFFFFFFF)
            self.d32(8, 0x114)
            self.d32(0x20, (rx << 4) & 0xFFFFFFFF)
            if self.node is not None:
                self.node.dst = (rx - 0x18, 0x114 - 0x18)
        if "rand_pair2" in info:                       # 0x418D8D：[0x2C] = rand&0x3F + 0x10
            import random as _r
            self.d32(0x2C, ((_r.randrange(0x7FFFFFFF) & 0x3F) + 0x10) & 0xFFFFFFFF)
        if "r1_y8" in info:                            # 0x418F35：[ent+8] += (y≤F0 ? 0x1E : −0x3C)
            v = 0x1E if b <= 0xF0 else -0x3C
            self.d32(8, (b + v) & 0xFFFFFFFF)
        if "node_dst_18" in info:
            if self.node is not None:
                self.node.dst = (a - 0x18, b - 0x18)
        if "z24" in info:
            self.d32(0x24, 0)
        if "z28" in info:
            self.d32(0x28, 0)
        if "z2C" in info:
            self.d32(0x2C, 0)
        if "r1_2C" in info:
            self.d32(0x2C, b & 0xFFFFFFFF)
        if "d3_28" in info:                            # [0x28] = rec[3]
            self.d32(0x28, d & 0xFFFFFFFF)
        if "r3sh" in info:                             # [off] = rec[3] << n
            off, n = info["r3sh"]
            self.d32(off, (d << n) & 0xFFFFFFFF)
        if "deref3_all" in info:                       # 0x41915B：全字段从 rec3[0x18..0x30] 拷
            tgt = self._deref_link(d)
            if tgt is not None:
                for so, to in ((0x18, 0x18), (0x1C, 0x1C), (0x20, 0x20),
                               (0x24, 0x24), (0x28, 0x28), (0x2C, 0x2C), (0x30, 0x30)):
                    self.d32(to, tgt.g32(so))
        if "d_to2" in info:
            self.d32(info["d_to2"], d & 0xFFFFFFFF)
        if "d_all" in info:                            # 多字段 d_to（rec[3] → 各偏移）
            for o in info["d_all"]:
                self.d32(o, d & 0xFFFFFFFF)
        if "s3nz8000" in info:                         # 0x41C5DD：[off]=(p3!=0)?0x8000:0
            self.d32(info["s3nz8000"], 0x8000 if d != 0 else 0)
        if "node_custom" in info:                      # ctor 直写节点（rect/dst/active）
            nc = info["node_custom"]
            if self.node is not None:
                if "rect" in nc:
                    self.node.rect = tuple(nc["rect"])
                if "dst" in nc:
                    self.node.dst = tuple(nc["dst"])
                if "active" in nc:
                    self.node.active = nc["active"]
        if "r1_28" in info:                            # 0x4082FF：[0x28] = rec[1]
            self.d32(0x28, b & 0xFFFFFFFF)
        if "s1z2_30" in info:                          # 0x40830F：[0x30] = (p1==0)?2:0
            self.d32(0x30, 2 if b == 0 else 0)
        if "deref0_24" in info:                        # 0x40835C：[0x24] = *rec0[+0x20]
            tgt = self._deref_link(a)
            if tgt is not None:
                self.d32(0x24, tgt.g32(0x20))
        if "s3m450_28" in info:                        # 0x40836A：[0x28] = p3*(p1?450:1)
            self.d32(0x28, (d * 450 if b != 0 else d) & 0xFFFFFFFF)
        if "s3if_2C" in info:                          # 0x40837A：[0x2C] = p1 ? p3 : 0
            self.d32(0x2C, (d if b != 0 else 0) & 0xFFFFFFFF)
        if "tp_grid" in info:                          # 0x40DBF5：瞬移格步（0x50 步长）
            r = rng.randrange(0x7FFFFFFF)
            q1, r1 = divmod(r, 0xF0)
            self.d32(0x1C, _idiv_trunc(0x140 + r1 - a, 0x50) & 0xFFFFFFFF)
            r = rng.randrange(0x7FFFFFFF)
            q3, r3 = divmod(r, 0x190)
            self.d32(0x20, _idiv_trunc(0x28 + r3 - b, 0x50) & 0xFFFFFFFF)
        if "rect_s3" in info:                          # 0x40DCAE：rect 按 rec3 选
            ra, rb = info["rect_s3"]
            if self.node is not None:
                self.node.rect = ra if d == 0 else rb
        if "r0_20" in info:
            self.d32(0x20, a & 0xFFFFFFFF)
        if "r1_24" in info:
            self.d32(0x24, b & 0xFFFFFFFF)
        if "d3pair" in info:                           # 0x41200B：[0x1C]=*rec3、[0x20]=rec3[1]
            tgt = self._deref_link(d)
            if tgt is not None:
                self.d32(info["d3pair"][0], tgt.g32(0x1C))
                self.d32(info["d3pair"][1], tgt.g32(0x20))
        if "node_src_y" in info:                       # 0x412041：node src 按 rec3 链 y
            pass  # src 依赖 rec3 解引用的运行期 y，首帧由行为补

    def d32(self, off: int, val: int) -> None:
        self.m[off:off + 4] = int(val & 0xFFFFFFFF).to_bytes(4, "little")

    def g32(self, off: int) -> int:
        return int.from_bytes(self.m[off:off + 4], "little")

    def s32(self, off: int) -> int:
        v = self.g32(off)
        return v - 0x100000000 if v & 0x80000000 else v

    def __repr__(self) -> str:
        return f"<Ent 0x{self.g32(0x14):08X} beh=0x{self.beh:06X} a={self.g32(4)} b={self.g32(8)} d={self.g32(0x1C)}>"


# ---------------------------------------------------------------------------
# 0x42 家族：页4 开场的 5 种实体（自机升空 → 入云 → 文字）
#   ctor 分派：0x4355E0 里 `[+0x14] & 0xFF000000 == 0x42000000` → 跳表 0x437074（5 项）
#   0x42000001..05 → 0x43567C / 0x4356E5 / 0x43571C / 0x43578A / 0x4358B4
#   行为 0x437940 / 0x437B00 / 0x437C30 / 0x437DB0 / 0x437E50
#   各分支定案见 docs/p4_beh_29high_notes.md；原始逐轮 listing 已清理
# ---------------------------------------------------------------------------
T42_RECT = {0x42000001: (0, 0, 0x17, 0x17),      # 0x4356A8 0x45A750(&r,0,0,0x17,0x17)
            0x42000002: (0, 0x18, 0x5F, 0x77),   # 0x435EFD 0x45A750(&r,0,0x18,0x5F,0x77)
            0x42000003: (0x60, 0x18, 0xBF, 0x77)}  # 0x435754 0x45A750(&r,0x60,0x18,0xBF,0x77)
T42_SIZE = (0x0C, 0x12, 0x18, 0x24, 0x36)        # 0x4357BC..0x4357D4（esp+0x10 起 5 项）
T42_RECT4 = ((0x00, 0x78, 0x17, 0x8F), (0x18, 0x78, 0x3B, 0x9B),
             (0x3C, 0x78, 0x6B, 0xA7), (0x6C, 0x78, 0xB3, 0xBF),
             (0x00, 0xA8, 0x6B, 0x113))          # 0x4357FC..（16 字节步长）
T42_THRESH4 = (0x41, 0x71, 0xA1, 0xD1, 0x101)    # 0x43795F..0x43797F
T42_THRESH5 = (0x41, 0x71, 0xA1, 0xD1, 0x101, 0x1A4, 0x1C2)   # 0x437E65..
T42_STEP5 = (-4, -3, -2, -1, 0, -1, 0)           # 0x437E9D..


class Ent42(Ent):
    """0x42 家族。`tick()` 返回 1 = 活 / 0 = 死（调用方按 0x43A36D..0x43A377 收尾）。"""

    def __init__(self, x: int, y: int, typ: int, prm: int, owner=None):
        # VM 记录是无符号 dword（如 陽=0x42000002 的 y=−50 以 0xFFFFFFCE 送达）。
        # exe 侧坐标是 32 位**有符号**语义（0x430640 的 cmp jg、0x45A690 写入），
        # 这里归一成 Python 有符号，否则 dst 会在 2^32 附近串味（陽 的 dst.y 越过
        # 2^32 后 0x430640 恒判出屏 ⇒ 光爆开当帧就死，2026-10-31 修）。
        x = x - 0x100000000 if 0x80000000 <= x <= 0xFFFFFFFF else x
        y = y - 0x100000000 if 0x80000000 <= y <= 0xFFFFFFFF else y
        super().__init__(x, y, typ, prm)
        self._owner = owner
        self.kind = typ - 0x42000001
        p = prm & 0xFFFFFFFF
        s32 = lambda v: v - 0x100000000 if v & 0x80000000 else v
        self.d32(0x1C, 0)
        self.d32(0x20, 0)
        self.d32(0x24, 0)
        self.d32(0x28, 0)
        self.d32(0x2C, 0)
        if self.kind == 0:                                   # 0x43567C
            self.beh = 0x437940
            self.d32(0x1C, p)
            self.d32(0x28, p)
            l, t, r, b = T42_RECT[typ]
            self.node = DNode(2, l, t)
            self.node.rect = (l, t, r, b)
            self.node.dst = (x - 0x0C, y - 0x0C)             # 0x4356DB sub 0xC
        elif self.kind == 1:                                 # 0x4356E5
            self.beh = 0x437B00
            self.d32(0x20, 0xFFFFFFB8)                       # 0x4356F6 -72
            self.d32(0x24, 0x90)                             # 0x4356FD 0x90
            l, t, r, b = T42_RECT[typ]
            self.node = DNode(2, l, t)
            self.node.rect = (l, t, r, b)
            self.node.dst = (x - 0x30, y - 0x30)             # 0x435F26 sub 0x30
        elif self.kind == 2:                                 # 0x43571C
            self.beh = 0x437C30
            self.d32(0x20, 0xFFFFFFFF)                       # 0x43572C or eax,-1
            self.d32(0x24, 0xFFFFFFFF)
            self.d32(0x2C, p)                                # 0x43573F = rec[3]（模式）
            l, t, r, b = T42_RECT[typ]
            self.node = DNode(2, l, t)
            self.node.rect = (l, t, r, b)
            self.node.dst = (x - 0x30, y - 0x30)             # 0x43577D sub 0x30
        elif self.kind == 3:                                 # 0x43578A
            self.beh = 0x437DB0
            i = p if p < len(T42_SIZE) else 0
            self.d32(0x1C, (p + 1) & 0xFFFFFFFF)             # 0x43579A inc eax
            self.d32(0x0C, T42_SIZE[i])                      # 0x4357E4
            self.d32(0x28, (p + 1) & 0xFFFFFFFF)             # 0x4357F3
            l, t, r, b = T42_RECT4[i]
            self.node = DNode(2, l, t)
            self.node.rect = (l, t, r, b)
            sz = T42_SIZE[i]
            self.node.dst = (x - sz, y - sz)                 # 0x4378A5 用 [+0xC]
        else:                                                # 0x4358B4
            self.beh = 0x437E50
            # 0x4358F0 `0x45AFC0(0x4AB5B0,0xC000)` 已经把 0xC000 右移到最低位 ⇒ 返回值就是 0..3
            v = owner.p4_afc0(0xC000, 0x4AB5B0) if owner else 0
            self.d32(0x3C, 0x4AB5B0)
            l, t, r, b = 0, v * 0x30, 0x2F, v * 0x30 + 0x2F  # 0x4358FF 0x45A750(&r,0,v*0x30,0x2F,…)
            self.node = DNode(0, l, t)                       # 0x4358CE [eax]=ebx=0 ⇒ 层 0
            self.node.rect = (l, t, r, b)
            self.node.dst = (x - 0x18, y - 0x18)             # 0x435929 sub 0x18
        self.node.active = 1
        self.frame = 0

    # ---- 0x437940（type 1）----------------------------------------------
    # 关键：0x437A57 `0x45A6B0(node+0x14, [e+0x24], [e+0x2C]+[e+0x20])`，而
    # 0x45A6B0 本体是 `[ptr]+=arg2; [ptr+4]+=arg3` ⇒ **arg2→dst.x、arg3→dst.y**：
    #   dst.x += [e+0x24]（横向），dst.y += [e+0x2C]+[e+0x20]（[e+0x20]=随地面上升速度，
    #   阈值表 {0x41,0x71,0xA1,0xD1,0x101} → 0,-4,-3,-2,-1,0，与流 45 op0xA 的
    #   背景滚动 4/3/2/1（t=64/111/159/207）逐帧同步——"人随地面一起升上来"。
    def _beh_437940(self) -> int:
        t = (self.g32(0x1C) + 1) & 0xFFFFFFFF
        self.d32(0x1C, t)
        node = self.node
        if t >= 0x102:                                       # 0x437955 jge 0x437A2D
            # 0x437A2D `test byte[+0x28],1`：按 **mode** 奇偶（不是 t！）
            self.d32(0x24, 2 if (self.g32(0x28) & 1) else 0xFFFFFFFE)
        else:
            if t >= 0x41:                                    # 0x437989 阈值表
                k = sum(1 for th in T42_THRESH4[1:] if t >= th)
                self.d32(0x20, (min(k, 5) - 4) & 0xFFFFFFFF)
            mode = self.g32(0x28)
            if mode == 0:                                    # 0x437A1A sbb 序列：(t&0x40)?+1:-1
                self.d32(0x24, 1 if (t & 0x40) else 0xFFFFFFFF)
            elif mode == 1:                                  # 0x437A07：(t&0x20)?-1:+1
                self.d32(0x24, 0xFFFFFFFF if (t & 0x20) else 1)
            elif mode == 4:                                  # 0x4379B4
                if t == 0x2D:
                    self.d32(0x2C, 0xFFFFFFFF)               # 竖向额外 -1
                    self.d32(0x24, 1)                        # 横向 +1（向右走）
                elif t >= 0xFB:                              # 0x4379C9 0x45A790 四边平移
                    l, tt, r, b = node.rect                  # (l,t,r,b)+=(0x18,0,0x18,0)=右移一格
                    node.rect = (l + 0x18, tt, r + 0x18, b)
                    self.d32(0x2C, 0)
                    self.d32(0x24, 0)
                if t == 0xFF:                                # 0x4379F6（仅 mode 4 在此死）
                    return 0
        dx = self.s32(0x24)                                  # 0x45A6B0 arg2 → x
        dy = self.s32(0x2C) + self.s32(0x20)                 # arg3 → y
        node.dst = (node.dst[0] + dx, node.dst[1] + dy)
        if t >= 0x128:                                       # 0x437A62 再右移一格
            l, tt, r, b = node.rect
            node.rect = (l + 0x18, tt, r + 0x18, b)
        return 1 if t != 0x12C else 0                        # 0x437A84 setne

    # ---- 0x437B00（type 2）：t<640 静止；之后右漂，累加器归零爆出 5 个 ----------
    def _beh_437B00(self) -> int:
        owner = self._owner
        t = self.g32(0x1C)
        if t >= 0x280:                                       # 0x437B0A
            if self.g32(0x28) == 0:                          # 0x437B21
                dx = (self.s32(0x20) + 1) & 0xFFFFFFFF       # 0x437B2C
                self.d32(0x20, dx)
                self.d32(0x24, (self.s32(0x24) - 2) & 0xFFFFFFFF)
                if dx == 0:                                  # 0x437B32 test eax,eax
                    nx, ny = self.node.dst[0] + 0x30, self.node.dst[1] + 0x30
                    # 0x437B86..0x437BA1：`0x43A3C0` 是 `ret 4`，所以循环里
                    # `[esp+0x14]` = S+0x14 = **记录 +0xC（param）**，不是 +8（type）：
                    # 5 次都是 type 0x42000004，param=0..4（对应 5 档尺寸）。
                    for i in range(5):
                        owner.p4_spawn42(nx, ny, 0x42000004, i)
                    self.d32(0x28, 1)
            else:                                            # 0x437BCF
                self.d32(0x20, (self.s32(0x20) - 2) & 0xFFFFFFFF)
                self.d32(0x24, (self.s32(0x24) - 1) & 0xFFFFFFFF)
                if not owner.p4_430640(self):                # 0x437BDE
                    return 0
            node = self.node
            node.dst = (node.dst[0] + (self.s32(0x20) >> 4),
                        node.dst[1] + (self.s32(0x24) >> 4))
        self.d32(0x1C, (t + 1) & 0xFFFFFFFF)
        return 1

    # ---- 0x437C30（type 3）：模式 0 漂移 / 1 生成 200 片 / 2 下落 ---------------
    def _beh_437C30(self) -> int:
        owner = self._owner
        mode = self.g32(0x2C)
        node = self.node
        if mode == 2:                                        # 0x437C46
            node.dst = (node.dst[0] - 0x10, node.dst[1] + 0x20)
            return 0 if node.dst[1] > 0x1E0 else 1           # 0x437C63
        if mode == 1:                                        # 0x437C77 生成 200 片
            for _ in range(0xC8):
                rem1 = owner.p4_rand_mod(0x370)[1]
                rem2 = owner.p4_rand_mod(0x3C0)[1]
                x = rem2 + rem1 + 0x18                       # 0x437CBB
                y = (-0x18 - rem2) << 1                      # 0x437CB0/0x437CB4
                owner.p4_spawn42(x, y, 0x42000003, 2)
            return 0                                         # 0x437CFE xor al,al
        t = self.g32(0x1C)                                   # 模式 0
        if t > 0x30:                                         # 0x437D08 jle
            self.d32(0x24, 0)
            old = self.g32(0x28)
            self.d32(0x28, (old + 1) & 0xFFFFFFFF)
            if old == 0x14:                                  # 0x437D19 cmp eax,0x14
                self.d32(0x28, 0)
                self.d32(0x20, (self.s32(0x20) - 1) & 0xFFFFFFFF)
        self.d32(0x1C, (t + 1) & 0xFFFFFFFF)
        dx, dy = self.s32(0x20), self.s32(0x24)
        node.dst = (node.dst[0] + dx, node.dst[1] + dy)      # 0x437D3D
        return 0 if node.dst[0] < -0x60 else 1                # 0x437D48

    # ---- 0x437DB0（type 4）------------------------------------------------
    def _beh_437DB0(self) -> int:
        cx = (self.g32(0x20) + 1) & 0xFFFFFFFF                # 0x437DBE
        ax = (self.g32(0x24) - 1) & 0xFFFFFFFF                # 0x437DBF
        self.d32(0x20, cx)
        self.d32(0x24, ax)
        sax = ax - 0x100000000 if ax & 0x80000000 else ax
        x = self.s32(0x04) + (sax >> 3)                       # 0x437DC7 sar 3
        y = self.s32(0x08) + (sax >> 4)                       # 0x437DD7 sar 4
        self.d32(0x04, x & 0xFFFFFFFF)
        self.d32(0x08, y & 0xFFFFFFFF)
        size = self.g32(0x0C)                                 # 0x437DE2
        eax = (self.s32(0x28) * ((cx - 0x100000000) if cx & 0x80000000 else cx)) << 1
        node = self.node
        node.dst = (x - size + eax, y - size + (eax >> 1))    # 0x437DF2/0x437DF4
        w = node.rect[2] - node.rect[0]                       # 0x45A710
        return 1 if (w + node.dst[0]) > 0 else 0              # 0x437E1C test/setg

    # ---- 0x437E50（type 5）：竖直漂移的云带 ---------------------------------
    def _beh_437E50(self) -> int:
        t = (self.g32(0x1C) + 1) & 0xFFFFFFFF
        self.d32(0x1C, t)
        if t >= T42_THRESH5[0]:                               # 0x437EC5
            k = sum(1 for th in T42_THRESH5[1:] if t >= th)
            self.d32(0x20, T42_STEP5[min(k, 6)] & 0xFFFFFFFF)  # 0x437ED3
        node = self.node
        node.dst = (node.dst[0], node.dst[1] + self.s32(0x20))  # 0x437EE7
        return 1 if t != 0x399 else 0                          # 0x437EED

    def tick(self) -> int:
        self.frame += 1
        fn = {0x437940: self._beh_437940, 0x437B00: self._beh_437B00,
              0x437C30: self._beh_437C30, 0x437DB0: self._beh_437DB0,
              0x437E50: self._beh_437E50}.get(self.beh)
        return fn() if fn else 1


# `0x593AB4` 起的 65536 项倒数平方根表：`word[i] = (int)(4096 / sqrt(i))`（截断）
# 由启动期 `0x45A7E0` 用 FPU 建表（`0x45A83B fild i ; fsqrt ; fdivr [0x499388]`，
# `[0x499388] = 4096.0`，`0x463F30` 是"截断取整"的 ftol）。此表运行期才生成，磁盘上是全 0。
P4_RSQRT: dict[int, int] = {}


def _p4_rsqrt(s: int) -> int:
    """`word[0x593AB4 + s*2]`：`(int)(4096 / sqrt(s))`（截断）。`s == 0` 原版会得到 FPU 的 inf，不用。"""
    v = P4_RSQRT.get(s)
    if v is None:
        v = int(4096.0 / math.sqrt(s)) if s > 0 else 0
        P4_RSQRT[s] = v
    return v


def _beh_23000009(self, e) -> bool:
    """`0x4015AA → 0x40E9B0`（类型 `0x23000009`）：下落 → 第 240 帧锁定自机 → 直线突进。

    ```
    0x40E9B3 t = [+0x2C]
    0x40E9B6 if (t < 0x28)  [+0x1C] -= 0x20               ; 前 40 帧加速下降
    0x40E9C1 if (t == 0xF0) {                             ; 第 240 帧：一次性锁定
                 dy = [0x56CC90]-[e+8] ; dx = [0x56CC8C]-[e+4]
                 inv = 0x45AA80(dx, dy)          ; 4096/|d| 倒数距离
                 k   = inv / 3                   ; 0x55555556 有符号除 3
                 [+0x1C] = dx * k ; [+0x20] = dy * k
             }
    0x40EA16 [+0x24] += [+0x1C] ; [+0x28] += [+0x20]      ; 8.8 定点累加
    0x40EA2E [+0x04] = [+0x24] >> 8 ; [+0x08] = [+0x28] >> 8
    0x40EA42 节点 dst = (x-0x18, y-0x18)
    0x40EA56 if (t == 0xB4) 0x43B150(e, -[+0x58])         ; 双发对称弹
    0x40EA6A if (t == 0xD2) 0x43B070(e, 0)                ; 单发追踪弹
    0x40EA7C ++[+0x2C]
    0x40EA83 返回 ([+0x18] != 0) && 0x4305F0(e, 0x18)     ; 在屏
    ```

    ⇒ 一枚**定时怪**：先自由下落，第 240 帧一次性把速度锁成「朝当时玩家位置」的定长向量
    （`k = (4096/|d|)/3`，即速度 = 4096/3 的 8.8 定点 ≈ 5.33 像素/帧…实际再乘 `dx` 归一），
    然后沿直线飞出；`t=0xB4` 与 `t=0xD2` 各放一次弹。
    """
    t = e.s32(0x2C)                                   # 0x40E9B3
    if t < 0x28:                                      # 0x40E9B6
        e.d32(0x1C, (e.s32(0x1C) - 0x20) & 0xFFFFFFFF)
    elif t == 0xF0:                                   # 0x40E9C1
        dy = self.p4_player_y() - e.s32(0x08)         # 0x40E9C8/0x40E9D6
        dx = self.p4_player_x() - e.s32(0x04)         # 0x40E9D0/0x40E9DC
        k = self._p4_div3(self.p4_45aa80(dx, dy))     # 0x40E9DF/0x40E9E6
        e.d32(0x1C, (dx * k) & 0xFFFFFFFF)            # 0x40EA05
        e.d32(0x20, (dy * k) & 0xFFFFFFFF)            # 0x40EA13
    e.d32(0x24, (e.s32(0x24) + e.s32(0x1C)) & 0xFFFFFFFF)   # 0x40EA1C
    e.d32(0x28, (e.s32(0x28) + e.s32(0x20)) & 0xFFFFFFFF)   # 0x40EA29
    x = e.s32(0x24) >> 8                              # 0x40EA2E
    y = e.s32(0x28) >> 8                              # 0x40EA31
    e.d32(0x04, x & 0xFFFFFFFF)                       # 0x40EA37
    e.d32(0x08, y & 0xFFFFFFFF)                       # 0x40EA34
    if e.node is not None:                            # 0x40EA42
        e.node.dst = (x - 0x18, y - 0x18)
    if t == 0xB4:                                     # 0x40EA56
        self.p4_43B150(e, (-e.s32(0x58)) & 0xFFFFFFFF)
    if t == 0xD2:                                     # 0x40EA6A
        self.p4_43B070(e, 0)
    e.d32(0x2C, (t + 1) & 0xFFFFFFFF)                 # 0x40EA7C
    return e.s32(0x18) != 0 and self.p4_4305f0(e, 0x18) == 1   # 0x40EA83


# `0x44408C`：`0x4435C0` 状态机的 10 项字节表（状态 0..9 → 处理函数索引）
P4_44408C = [0, 1, 1, 1, 1, 1, 1, 1, 2, 3]


def _beh_6B000001(self, e) -> bool:
    """`0x4435C0`（thunk `0x4020EF`，类型 `0x6B000001`）：**开场 10 状态机**。

    ```
    0x4435D0 eax = [esi+0x1C]
    0x4435D5 ebp = eax & 0x0FFFFFFF        ; 低 28 位 = 计数
    0x4435D7 ebx = eax >> 28 ; bl &= 0xF   ; 高 4 位 = 状态
    0x4435E6 [esi+0x1C] = eax + 1
    0x4435E7 if (状态 > 9) → 0x44406D 返回 1
    0x4435F9 cl = byte[0x44408C + 状态]    ; [0,1,1,1,1,1,1,1,2,3]
    0x4435FF jmp dword ptr [ecx*4 + 0x44407C]
    ```

    指针表 `0x44407C` = `0x443606`(索引0) / `0x4437E0`(1) / `0x443C67`(2) / `0x443FDC`(3)。
    """
    raw = e.g32(0x1C)
    cnt = raw & 0x0FFFFFFF                            # 0x4435D5
    st = (raw >> 28) & 0xF                            # 0x4435D7
    e.d32(0x1C, (raw + 1) & 0xFFFFFFFF)               # 0x4435E6
    if st > 9:                                        # 0x4435E7
        return True
    idx = P4_44408C[st]                               # 0x4435F9
    if idx == 0:
        return self._p4_443606(e, cnt)
    if idx == 1:
        return self._p4_4437e0(e, cnt, st)
    if idx == 2:
        return self._p4_443c67(e, cnt)
    if idx == 3:
        return self._p4_443fdc(e, cnt)
    k = (0x4435C0, idx)
    self.p4_beh_missing_types[k] = self.p4_beh_missing_types.get(k, 0) + 1

    return True


def _beh_43AEB0(self, e) -> bool:
    """`0x401E2E → 0x43AEB0`（类型 `0x21000001`）：底部条带块的横向滑出 + 纵向摆动。

    ```
    0x43AEB6 eax = [+8]
    0x43AEB9 cmp eax, 0xF0 ; jge → eax = [+0x20]-1，否则 eax = [+0x20]+1
    0x43AEC7 edx = [+0x1C] ; ecx = [+4]
    0x43AECD edx += eax ; [+0x1C] = edx ; [+0x20] = eax
    0x43AED4 ecx-- ; [+4] = ecx                    ; **每帧左移 1**
    0x43AED5 eax = edx + 0x10 ; 0x43AEDB sar eax, 5 ; [+8] = eax   ; y = (acc+16)>>5
    0x43AEE9 节点 dst = (x-0x18, y-0x18)
    0x43AEFD if ([+0x18] == 0) → 0x430400(rec, x, y, [+0x24], 0) → 0x435440(ui49c)
    0x43AF3D 返回 ([+0x18] != 0) && ([+4] > -0x18)
    ```

    ⇒ 纵向是**围绕 y=0xF0 的往复**：`[+0x20]` 每帧 ±1，越过 240 就反向，
    `[+0x1C]` 是速度累加器，`y = (acc + 16) >> 5`。横向恒速 −1/帧，
    滑到 `x <= -0x18` 或 HP 归零即消失（死亡时吐一个 ui49c 物件）。
    """
    y = e.s32(0x08)                                    # 0x43AEB6
    v = e.s32(0x20)
    v = (v - 1) if y >= 0xF0 else (v + 1)              # 0x43AEB9/0x43AEC3/0x43AEC6
    e.d32(0x20, v & 0xFFFFFFFF)
    acc = (e.s32(0x1C) + v) & 0xFFFFFFFF                # 0x43AECD
    e.d32(0x1C, acc)
    x = (e.s32(0x04) - 1) & 0xFFFFFFFF                  # 0x43AED4
    e.d32(0x04, x)
    ny = (e.s32(0x1C) + 0x10) >> 5                      # 0x43AED5/0x43AEDB 有符号 sar
    e.d32(0x08, ny & 0xFFFFFFFF)
    if e.node is not None:                              # 0x43AEE9
        e.node.dst = ((x - 0x18), (ny - 0x18))
    if e.s32(0x18) == 0:                                # 0x43AEFD
        self.spawn(self._p4_q("ui49c"), e.s32(0x24), e.s32(0x04), e.s32(0x08))
    return e.s32(0x18) != 0 and e.s32(0x04) > -0x18     # 0x43AF3D/0x43AF46


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
            x = rng.randrange(0x500) + 0x298                 # 0x40E7BD edx(余数)+0x298 → rec[0]
            y = rng.randrange(0x1E0)                         # 0x40E7EC edx(余数) → rec[1]
            self._p4_ent43c(0x23000007, x, y)       # 0x401FA5(0x4AD43C, rec)
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
        self._p4_ent43c(0x23000009, -0x18, e.s32(0x08))   # 0x40E8F5 push -0x18（x 常量，非父 x-0x18）
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
        # ① 0x40E528..0x40E599：`0x430400(&rec, x, y, 0x23000006, &buf)` + `0x43BDC0(0x4AD43C,&rec)`
        #   循环 `do { buf[1] = -[+0x2C]*8; 入队 } while (--[+0x2C])`。
        #   子体 ctor case5（0x40DA40）：[0x1C] = *buf = 父指针（0x40DA53）、
        #   [0x20] = buf[1] = **相位种子 −v*8**（0x40DA5F，错峰起飞：t 数到 0 才按 ② 表获得速度）、
        #   [0x24]=[0x28]=[0x2C]=0（0x40DA5C/62/65）。
        #   复刻侧 raw[0x1C] 存父句柄（id&0x7FFFFFFF），真对象在 self.p4_links。
        h = id(e) & 0x7FFFFFFF
        self.p4_links[h] = e
        v = n
        while v:
            c = self._p4_ent43c(0x23000006, e.s32(0x04), e.s32(0x08))
            c.d32(0x1C, h)                                 # 0x40DA53 [0x1C] = 父
            c.d32(0x20, (-8 * v) & 0xFFFFFFFF)             # 0x40DA5F [0x20] = −v*8（种子）
            c.d32(0x24, 0)                                 # 0x40DA5C
            c.d32(0x28, 0)                                 # 0x40DA62
            c.d32(0x2C, 0)                                 # 0x40DA65
            v -= 1
        e.d32(0x2C, 0)
    if e.s32(0x1C) == 0 and e.s32(0x14) != 0x23000005 and e.s32(0x20) == 0x172:
        e.d32(0x1C, 0)                                        # 0x40E599
        self.p4_43B070(e, e.s32(0x58) + 0x80)
    t = e.s32(0x20)
    if t == 0:                                                # 0x40E5D9
        e.d32(0x24, 0xFFFFFFFD)
        # 0x40E5DE..0x40E5F5：cl=(y<=0xF0) → ecx=((cl−1)&0xFFFFFFFA)+3 ⇒ **y≤240:+3、y>240:−3**
        e.d32(0x28, 3 if e.s32(0x08) <= 0xF0 else 0xFFFFFFFD)
    elif t == 0x4B:                                           # 0x40E5FA
        e.d32(0x24, 0xFFFFFFFF)
        num = -(e.s32(0x28) * 4)                              # 0x40E5FF neg / 0x40E609 shl 2
        q = num // 3 if num >= 0 else -((-num) // 3)          # 0x40E602 imul 0x55555556（向零取整）
        e.d32(0x28, q & 0xFFFFFFFF)
    elif t == 0x78 and e.s32(0x14) == 0x23000006:              # 0x40E621
        self.p4_43B070(e, 0)
    elif t == 0x96:                                           # 0x40E63A
        e.d32(0x24, 4)
        v = e.s32(0x28)
        q = v // 4 if v >= 0 else -((-v) // 4)                # 0x40E64B cdq/and 3/sar 2（向零取整）
        e.d32(0x28, (-q) & 0xFFFFFFFF)                        # 0x40E654 neg
    h = e.g32(0x1C)
    if h:
        # ③ 0x40E659：[[0x1C]+0x34]==0（链接体已亡）→ 相位<0 自尽；否则随机 90° 变轨 + 相位 0x14A
        linked = self.p4_links.get(h)
        if linked is None or linked.m[0x34] == 0:
            self.p4_links.pop(h, None)
            if e.s32(0x20) < 0:
                return False
            vx, vy = e.s32(0x24), e.s32(0x28)
            e.d32(0x1C, 0)
            e.d32(0x20, 0x14A)
            if self.p4_rand() & 1:                             # 0x40E68B rand&1
                e.d32(0x24, vy & 0xFFFFFFFF)                   # bit=1: (vy, −vx)
                e.d32(0x28, (-vx) & 0xFFFFFFFF)
            else:
                e.d32(0x24, (-vy) & 0xFFFFFFFF)                # bit=0: (−vy, vx)
                e.d32(0x28, vx & 0xFFFFFFFF)
    # 0x40E6A3 尾：**重新读内存** [0x20] 再 ++（③ 支刚写的 0x14A 不能被开头的陈旧 t 覆盖）
    e.d32(0x20, (e.s32(0x20) + 1) & 0xFFFFFFFF)
    e.d32(0x04, (e.s32(0x04) + e.s32(0x24)) & 0xFFFFFFFF)      # 0x40E6B8
    e.d32(0x08, (e.s32(0x08) + e.s32(0x28)) & 0xFFFFFFFF)      # 0x40E6B0
    if e.node is not None:
        e.node.dst = (e.s32(0x04) - 0x18, e.s32(0x08) - 0x18)
    # 0x40E6DB 尾：HP==0 → 灭；`0x401D02`（→0x430640）屏外 且 相位≥0x14A → 灭
    if e.g32(0x18) == 0:                               # 0x40E6DE test eax
        return False
    if not self.p4_430640(e) and e.s32(0x20) >= 0x14A:  # 0x40E6E4 / 0x40E6ED
        return False
    return True                                        # 0x40E6F6


def _beh_2300000A(self, e) -> bool:
    """`0x401181` → `0x40EAF0`：**跳（0x2300000A）** 正弦航迹 + 周期射击。

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
            self.p4_43B150(e, 0)                     # 0x40EB03 → 0x401D6B = 0x43B150（双发 V 形）
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
    """`0x446540`：自机出场初始化 —— 生成**三种**伴随机入 0x4AD40C（2026-11-05 定案）。

    ```
    0x446548 0x430400(&rec, 0, 0, 0x1000001, ebx=自机)  ; rec = {0,0,0x1000001,自机}
    0x446580 0x448FF0(0x4AD40C, &rec) → pod1 ; 0x446594 [自机+0x24] = pod1
    0x446597 mov [esp+0x18],5 = **rec[2]（类型槽）= 5**   → 0x448FF0 → **type 5 狙击发射器**
    0x4465ae mov [esp+0x18],8 = **rec[2]（类型槽）= 8**   → 0x448FF0 → **type 8 捕获发射器**
    ```
    旧读法"rec[3]=5/8 变体标记"是 esp 纪律算错（ret 4 后 esp=esp0-0x34，
    [esp+0x18] = 工作副本 W+8 = 类型槽；rec[3] 恒 = 自机指针 ⇒ type5/8 的
    [+0x1C]=父=自机 ctor 语义才自洽，否则解引用 5/8 必崩）。
    type 5  = 0x445E47 ctor → 8 变体狙击发射器（0x446C50 族：**右键 btn1 沿发射
              0x10008041 锁定准星**——撃手动/凛自动/漢受限，游戏说明的"狙击"）。
    type 8  = 0x44601E ctor → 0x447410（0x10008431 捕获发射器 → 命中生成
              0x1000002/3 僚机舱）。
    """
    for typ in (0x1000001, 5, 8):                      # 0x446548/0x446597/0x4465ae
        ent = self._p4_ent_into(self.actorq, typ, 0, 0, 0)
        if ent is None:
            continue
        if typ == 0x1000001:
            self.p4_42c4d0(ent, (0, 0, 0x1000001, id(e) & 0xFFFFFFFF))
            ent.p["owner"] = e                         # [pod+0x20] = 自机
            e.d32(0x24, id(ent) & 0xFFFFFFFF)          # 0x446594 [自机+0x24] = pod1
            e.p["pod1"] = ent
        else:
            # type 5/8 走 0x445C00 分派（p4_445e47 / p4_44601e）：[+0x1C]=rec[3]=自机
            self.p4_445c00(ent, (0, 0, typ, id(e) & 0xFFFFFFFF))
            ent.p["sub"] = e                           # 行为的 sub = [ent+0x1C]（父=自机）
            ent.p["owner"] = e


def p4_446470(self, e, a: int, b: int) -> None:
    """`0x446470(e, bl, dl)`：**切换输入预设**（战斗中自机的移速/捕获参数来源）。

    ```
    0x446475 0x40208B(0x4AB5B0, 0x2) ; neg al; sbb eax,eax; and eax,8; add eax,7
             ⇒ base = 7（位1 未置 = 鼠标模式）或 0xF（已置 = 键盘模式；page3 菜单选择）
    0x446497 0x4019C9(0x4AB5B0, 0xC000) → mode（选机 0..2）
    0x4464B2 if (b != 0) { fid = base+mode*2+a ; 0x4019B0(0x4AB454, fid, e.x, e.y, dir) }
             else  { fid = base+mode*2   ; 0x40115E(0x4AB454, fid, dir) }
    0x4464E4 if (b) [e+0x1C] |= 2 else [e+0x1C] &= 1
    ```
    0x4019B0 → 0x44E620 = 装预设**并把指针设到 (e.x, e.y)**——演员 ctor 尾调
    (e,0,1) 即"指针种子=出生点"，原作自机无初始化漂移的机制（2026-10-31）。
    """
    base = 0xF if self.keys.test(2) else 7            # 0x446481（鼠标/键盘模式）
    mode = self.keys.field(0xC000) & 3                # 0x45AFC0(0x4AB5B0,0xC000) 选机
    fid = base + mode * 2 + (1 if a else 0)
    if b:                                             # 0x4464CA 0x44E620：预设+指针
        self.inp.set_preset4(fid, (e.s32(0x04), e.s32(0x08)))
    else:                                             # 0x4464DF 0x44E4A0：只装预设
        self.inp.set_preset4(fid)
    if a:                                             # 0x4464E7
        e.d32(0x1C, e.g32(0x1C) | 2)
    else:
        e.d32(0x1C, e.g32(0x1C) & 1)


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


# 0x25 族（关3）ctor case 表（0x411E20，跳表 0x4120C8，11 型）——2026-11-06 读定，待接
# case0/1 共体：beh 0x401339(0x4121C0)/0x40114F(0x4122D0)；b10=0、[0x1C]=0、
#   [0x20]=rec0<<2、[0x24]=rec1<<2、[0x28]=(s16)rec3.lo、[0x2C]=(s16)rec3.hi
# case2：beh 0x401046(0x4123E0 跳跳式：[0x20]∈[-0x10,0x118] 弹簧、t=3 边框扩、0x40213F 开火)；
#   b10=0、[0x1C]=0x401091([0x56CC8C]−rec0, [0x56CC90]−rec1)（0x45AA80 归一真址）、
#   [0x20]=0x100、[0x24]=rec0<<2、[0x28]=rec1<<2、[0x2C]=rec3
# case3：beh 0x40135C(0x412510)；[0x56CC90]≥0xF0 → [ent+8]=0x1E0−rec1；node dst=(x−0x18,y−0x18) 隐
# case4：beh 0x402397(0x412680)；[0x28]=rec0<<8、[0x2C]=rec1<<8（8.8 目标点）
# case5：beh 0x4012BC(0x4127E0)；[0x20]=rec3、[0x24]=0x22、[0x2C]=rec0<<1、[0x30]=rec1<<1
# case6：beh 0x4024C8(0x412950)；[0x1C]=[0x20]=[0x24]=0
# case7：beh 0x401078(0x412B60)；[0x28]=0x40、[0x30]=0x1770、byte[节点+0x1C]=0
# case8：beh 0x401186(0x4130D0)；[0x1C]=*rec3、[0x20]=rec3[1]（解引用）、
#   node src=(0x1E0, y, y+0x2F, 0x20F)，y=((*rec3)[0x1C]+rec1−3)×12，>0x120 则 −0x150
# case9：beh 0x4012D0(0x413930)；[0x1C]=rec0<<4、[0x20]=rec1<<4、
#   [0x24]=rand&0x3F+0x10、[0x28]=rand&0x3F、[0x2C]=rec3
# case10：0x4120C8 起待读
ENT25_THUNK = {0x401339: 0x4121C0, 0x40114F: 0x4122D0, 0x401046: 0x4123E0, 0x40135C: 0x412510,
               0x402397: 0x412680, 0x4012BC: 0x4127E0, 0x4024C8: 0x412950, 0x401078: 0x412B60,
               0x401186: 0x4130D0, 0x4012D0: 0x413930}


ENT25_INIT = {
    0x25000001: {"beh": 0x401339, "b10_0": True, "z1c20": True,
                 "r0sh": (0x20, 2), "r1sh": (0x24, 2), "s16lohi": (0x28, 0x2C)},
    0x25000002: {"beh": 0x40114F, "b10_0": True, "z1c20": True,
                 "r0sh": (0x20, 2), "r1sh": (0x24, 2), "s16lohi": (0x28, 0x2C)},
    0x25000003: {"beh": 0x401046, "b10_0": True, "angle_to_ship": 0x1C,
                 "imm": {0x20: 0x100}, "r0sh": (0x24, 2), "r1sh": (0x28, 2), "d_to": 0x2C},
    0x25000004: {"beh": 0x40135C, "b10_0": True, "z1c20": True,
                 "node_hidden": True, "ship_y_gate": True},
    0x25000005: {"beh": 0x402397, "b10_0": True, "z1c20_24": True,
                 "r0sh": (0x28, 8), "r1sh": (0x2C, 8)},
    0x25000006: {"beh": 0x4012BC, "b10_0": True, "z1c": True,
                 "d_to": 0x20, "imm": {0x24: 0x22, 0x28: 0},
                 "r0sh": (0x2C, 1), "r1sh": (0x30, 1)},
    # 0x4120C8 表项[6]=[5]=0x411F73（同 case）：07 与 06 共用 ctor/行为
    0x25000007: {"beh": 0x4012BC, "b10_0": True, "z1c": True,
                 "d_to": 0x20, "imm": {0x24: 0x22, 0x28: 0},
                 "r0sh": (0x2C, 1), "r1sh": (0x30, 1)},
    0x25000008: {"beh": 0x4024C8, "z1c_24": True},
    0x25000009: {"beh": 0x401078, "b10_0": True, "z1c_24": True,
                 "imm": {0x28: 0x40, 0x2C: 0, 0x30: 0x1770}, "node_hidden": True},
    0x2500000A: {"beh": 0x401186, "z1c": True, "deref3": True,
                 "d3pair": (0x20, 0x24), "node_src_y": True},
    0x2500000B: {"beh": 0x4012D0, "r0sh": (0x1C, 4), "r1sh": (0x20, 4),
                 "rand_pair": True, "d_to": 0x2C},
}


# 0x26 族（关4）ctor case 表（0x4139F0，跳表 0x413E64，24 型）——2026-11-06 逐 case 读定
# 位置索引：case 体在 0x413A19..0x413E63（见 dump），rec3 常经 word/deref 混合读
ENT26_INIT = {
    0x26000001: {"beh": 0x4021D5, "z1c": True, "imm": {0x20: -6},
                 "rand_pm4": 0x24},                                # rand/2∓2 →[0x24]
    0x26000002: {"beh": 0x402392, "z1c_24_28": True, "imm": {0x20: 4, 0x2C: 5}},
    0x26000003: {"beh": 0x4017F8, "z1c": True, "r0sh": (0x20, 4), "r1sh": (0x24, 3),
                 "imm": {0x28: 8}, "cmpgate": (0x2C, 0xC0, -0x60, "ge")},   # y≥F0: −0x60; y<F0: 0xC0−0x60=0x60
    0x26000004: {"beh": 0x401FE1, "z1c_20": True},
    0x26000005: {"beh": 0x4019BF, "z20": True, "d_to": 0x1C,
                 "imm": {0x24: 0x14, 0x28: 0x1E}},
    0x26000006: {"beh": 0x401EBA, "d_to": 0x1C, "b10_ne0": True, "z20": True,
                 "imm": {0x24: 0x14, 0x28: 0x9C40}, "node_vis_ne0": True},
    0x26000007: {"beh": 0x401C85, "z1c": True, "r0sh": (0x24, 3),
                 "imm": {0x28: -0x60, 0x2C: 6}},
    0x26000008: {"beh": 0x401CA8, "z1c": True},                      # ← 0x413B86 亦是本 case（boss 0x26000018 spawner 引用点）
    0x26000009: {"beh": 0x401F46, "rnd_retarget": True},  # 0x413C57
    0x2600000A: {"beh": 0x401C3F, "z1c": True, "imm": {0x20: -0x1E0},
                 "node_hidden": True},   # 0x413C6E：node.active=0（不写 byte[0x10]）
    0x2600000B: {"beh": 0x4010FA, "z1c": True},
    0x2600000C: {"beh": 0x4020E0, "d_to": 0x20, "b10_eq0": True, "z1c": True,
                 "imm": {0x24: 4}, "node_vis_eq0": True},
    0x2600000D: {"beh": 0x401677, "z1c": True},
    0x2600000E: {"beh": 0x4011D6, "z1c": True, "b10_eq0": True,
                 "imm": {0x20: -0x10, 0x24: 0}, "d_to": 0x28},
    0x2600000F: {"beh": 0x401578, "z1c": True, "b10_eq0": True, "d_to": 0x20,
                 "r1sh": (0x24, 3), "cmpgate": (0x28, 0x30, -0x18, "ge")},  # y≥F0: −0x18; y<F0: 0x30−0x18=0x18
    0x26000010: {"beh": 0x401906, "z1c": True, "imm": {0x20: -3, 0x24: 0}},
    0x26000011: {"beh": 0x40124E, "z1c": True, "imm": {0x20: -2, 0x28: 7}},
    0x26000012: {"beh": 0x40124E, "imm": {0x1C: 0x40, 0x20: 4, 0x28: 3}},
    0x26000013: {"beh": 0x401EA6, "z1c": True, "imm": {0x20: -0x20, 0x24: 0}},
    0x26000014: {"beh": 0x4022D4, "z1c_20": True},
    0x26000015: {"beh": 0x401CD0, "z1c": True, "r0sh": (0x20, 6), "d_to": 0x24},
    0x26000016: {"beh": 0x401E9C, "z1c_24_28": True, "imm": {0x20: 0x60}},
    0x26000017: {"beh": 0x4015F0, "z1c": True, "d_to": 0x20},
    0x26000018: {"beh": 0x4021CB, "z1c": True, "d_to": 0x20, "randpos": True},        # 0x413BDE：rand 落点/0x244 距离衰减
}


# 0x27 族（关5）ctor case 表（0x415EF0，跳表 0x4162E4，17 型）——2026-11-06 逐 case 读定
# case 体在 0x415F1A..0x4162E4。case10(0x4160D8) rec0/rec1<<4；case13(0x4161F3) 三态分派 rec3%3
ENT27_INIT = {
    0x27000001: {"beh": 0x401E7E, "r0sh": (0x1C, 3), "r1sh": (0x20, 2),
                 "imm": {0x24: -0x30, 0x28: 0, 0x2C: 0}},
    0x27000002: {"beh": 0x401DB1, "imm": {0x1C: -0x14}, "d_to": 0x24,
                 "cmpgate": (0x20, 6, -3, "ge")},   # y≥F0: −3; y<F0: 6−3=3
    0x27000003: {"beh": 0x402239, "imm": {0x1C: -0x30, 0x20: 0}, "d_to": 0x24},
    0x27000004: {"beh": 0x401C71, "imm": {0x1C: -0x12, 0x24: 0, 0x2C: 0}, "r1sh": (0x20, 4)},
    0x27000005: {"beh": 0x401348, "imm": {0x1C: -0xC, 0x24: 0}, "r1sh": (0x20, 3), "d_to": 0x28},
    0x27000006: {"beh": 0x401BEF, "z1c": True, "cmpgate": (0x24, 0xFFFFFFFC, 2, "le")},  # y≤F0: 2; y>F0: (−4)+2=−2
    0x27000007: {"beh": 0x402356, "z20": True, "d_to": 0x1C},
    0x27000008: {"beh": 0x402414, "imm": {0x1C: -0xC, 0x24: 0}, "cmpgate": (0x20, 2, -1, "ge140")},  # x≥0x140: −1; x<: 2−1=1
    0x27000009: {"beh": 0x4010CD, "imm": {0x1C: -0x18, 0x20: 0}, "d_to": 0x24},
    0x2700000A: {"beh": 0x4014BF, "z1c": True, "d_to": 0x20,
                 "deref3_20_24": True, "r0sh": (0x28, 4), "r1sh": (0x2C, 4),
                 "imm": {0x30: 1}},
    0x2700000B: {"beh": 0x401A78, "z1c_20": True, "r0sh": (0x24, 4), "r1sh": (0x28, 4),
                 "imm": {0x2C: 0}},
    0x2700000C: {"beh": 0x401E0B, "z1c_20": True, "imm": {0x24: 8}, "d_to": 0x28},
    0x2700000D: {"beh": 0x4016CC, "z1c": True,
                 "cmpgate": (0x20, 2, -1, "ge140"), "d_to": 0x24},
    0x2700000E: {"beh": 0x402117, "b10_0": True, "z20_24": True, "d_to": 0x1C,
                 "r0sh": (0x28, 3), "r1sh": (0x2C, 3), "node_hidden": True},
    0x2700000F: {"beh": 0x4014F6, "r0sh": (0x1C, 4), "r1sh": (0x20, 4),
                 "cmpgate": (0x24, 0xFFFFFFF0, -0x20, "g"),
                 "cmpgate2": (0x28, 0x20, -0x20, "g")},   # y>F0: −0x20/−0x20; y≤F0: −0x30/0
    0x27000010: {"beh": 0x4013A7, "z1c_20_24_28_2C": True, "d3mod3": True,
                 "d3div3": True, "b10_0": True},
    0x27000011: {"beh": 0x4021E4, "imm": {0x1C: 0, 0x24: 0, 0x28: 0}, "d_to_ptr": True,
                 "r1sh": (0x20, 5)},
}


# 0x28 族（关6）ctor case 表（0x418CB0，跳表 0x419208，24 型）——2026-11-06 逐 case 读定
# case 体在 0x418CDA..0x419208。case17 跳表项 0（无 ctor = 无行为）；case14/15 共体 beh 0x401230
ENT28_INIT = {
    0x28000001: {"beh": 0x40164A, "z1c": True, "r1_20": True,
                 "abs3_24": True, "g0_gate": (0x28, 0, -1)},   # rec3>0 → 0; ≤0 → −1
    0x28000002: {"beh": 0x401433, "z1c": True, "r1sh": (0x20, 4),
                 "imm": {0x24: 0x3C}, "cmpgate": (0x28, 0xC, -6, "ge140"), "d_to": 0x2C},
    0x28000003: {"beh": 0x4019F6, "z1c": True, "rand_spawn": True,       # 0x418D5A 随机落点
                 "r0sh": (0x20, 4), "imm": {0x24: 0x1140},
                 "rand_pair2": True},
    0x28000004: {"beh": 0x4022E8, "z1c": True, "r0sh": (0x20, 4), "z24": True,
                 "imm": {0x2C: 3}, "s04_fields": True},   # [0x28]=rec1、[0x30]=rec3
    0x28000005: {"beh": 0x401B8B, "z1c": True, "r1_20": True, "d_to": 0x24},
    0x28000006: {"beh": 0x40248C, "z1c": True, "r1_20": True, "d_to": 0x24,
                 "imm": {0x28: -4}},
    0x28000007: {"beh": 0x40254A, "z1c": True, "r0sh": (0x20, 4), "r1sh": (0x24, 4),
                 "imm": {0x28: 0x60, 0x2C: 0, 0x30: 0}},
    0x28000008: {"beh": 0x4019F1, "z1c": True, "r1_20": True,
                 "r1sh": (0x24, 4), "imm": {0x28: 0x10}, "d_to": 0x2C},
    0x28000009: {"beh": 0x4021C1, "z1c": True, "s09_fields": True, "z24": True},
    0x2800000A: {"beh": 0x401B3B, "z1c": True, "r1sh": (0x20, 3), "d_to": 0x28},
    0x2800000B: {"beh": 0x401CE4, "z1c": True, "r1sh": (0x20, 2), "imm": {0x24: -0x20}},
    0x2800000C: {"beh": 0x402018, "z1c": True, "r0sh": (0x20, 4),
                 "imm": {0x24: -0x60}, "d_to": 0x28, "r1_2C": True},
    0x2800000D: {"beh": 0x401523, "z1c": True, "r1_20": True,
                 "r0sh": (0x28, 2), "z24": True},
    0x2800000E: {"beh": 0x401E92, "z1c": True, "imm": {0x20: -8},
                 "r1sh": (0x24, 3), "z28": True, "d_to": 0x2C},
    0x2800000F: {"beh": 0x4013AC, "z1c": True, "r1_20": True, "d_to": 0x24, "d3_28": True},
    0x28000010: {"beh": 0x4024B9, "z1c": True, "r0sh": (0x20, 2), "r1sh": (0x24, 2),
                 "imm": {0x28: 0x48, 0x2C: 0}},
    0x28000011: {"beh": 0x4018BB, "z1c": True, "s11_fields": True},
    0x28000012: {"beh": 0x4010AA, "z1c": True, "imm": {0x20: 0x40},
                 "r0sh": (0x24, 3), "r1sh": (0x28, 3), "z2C": True},
    0x28000013: {"beh": 0x4018F2, "z1c_20_24_28_2C": True},
    0x28000014: {"beh": 0x401230, "r0_1C": True, "r1_20": True,
                 "imm": {0x24: 0, 0x28: 0, 0x2C: 0x35, 0x30: 0}},
    0x28000015: {"beh": 0x401230, "deref3_all": True},                # 0x41915B：全字段从 rec3[0x18..0x30] 拷
    0x28000016: {"beh": 0x4012B7, "z1c": True, "d_to": 0x20},
    0x28000017: {},                                                   # 跳表 0 = 无 ctor 无行为
    0x28000018: {"beh": 0x401B18, "r3sh": (0x1C, 4), "z20_24": True,
                 "r0sh": (0x28, 3), "r1sh": (0x2C, 3)},
}


# 0x29 族（关7）ctor case 表（0x41C040，跳表 0x41CBDC，33 型）——2026-11-06 批量提取
# case 体在 0x41C06E..0x41CBDC。case6..10/15 共体 beh 0x4018A7(0x41E7B0)、imm {0x18:0x14}
ENT29_INIT = {
    0x29000001: {"beh": 0x402121, "imm": {0x1C: 0, 0x20: -0x10, 0x24: 0}, "d_to": 0x28},
    0x29000002: {"beh": 0x40125D, "z1c_20_24": True, "imm": {0x28: -0xC8}, "d_to": 0x2C},
    0x29000003: {"beh": 0x401758, "d_to": 0x1C, "r0_20": True, "r1_24": True,
                 "imm": {0x28: 0, 0x2C: 0}},
    0x29000004: {"beh": 0x4015A5, "imm": {0x1C: 0, 0x20: 0x10}},
    0x29000005: {"beh": 0x40134D, "b10_0": True, "node_off": True},
    0x29000006: {"beh": 0x401D7F},
    0x29000007: {"beh": 0x4018A7, "s2907": True},
    0x29000008: {"beh": 0x4018A7, "s2907": True},
    0x29000009: {"beh": 0x4018A7, "s2907": True},
    0x2900000A: {"beh": 0x4018A7, "s2907": True},
    0x2900000B: {"beh": 0x4018A7, "s2907": True},
    0x2900000C: {"beh": 0x40211C, "r0_20": True, "r1_24": True},
    0x2900000D: {"beh": 0x4011EF, "d_to": 0x1C},
    0x2900000E: {"beh": 0x4021C6, "imm": {0x28: 0x40, 0x2C: 0},
                 "r0sh": (0x20, 3), "r1sh": (0x24, 3), "d30_yf0": True},
    0x2900000F: {"beh": 0x4019D8, "d_to": 0x1C, "s0f_fields": True},
    0x29000010: {"beh": 0x401EFB, "s10_fields": True},
    0x29000011: {"beh": 0x4010BE, "imm": {0x1C: 0, 0x20: 0x10, 0x24: -2}},
    0x29000012: {"beh": 0x4023A1, "z1c": True, "d_to": 0x20},
    0x29000013: {"beh": 0x4017E9, "z1c": True},
    0x29000014: {"beh": 0x4018CF, "z1c": True, "d_to": 0x20},
    0x29000015: {"beh": 0x401398, "imm": {0x24: -8}, "d_to": 0x28},
    0x29000016: {"beh": 0x4018A7},
    0x29000017: {"beh": 0x40217B, "imm": {0x1C: 0, 0x20: 0x10}, "d_to": 0x24},
    # —— 0x29000018..0x29000021（2026-11-11 按各自 ctor case 重读修正）——
    # 0x29000018（0x41C5CC）：+0x1C=(p3!=0)?0x8000:0、+0x20=0、+0x24=p0<<2、+0x28=p1<<2、+0x2C/30=0
    0x29000018: {"beh": 0x4013C5, "imm": {0x20: 0, 0x2C: 0, 0x30: 0},
                 "s3nz8000": 0x1C, "r0sh": (0x24, 2), "r1sh": (0x28, 2)},
    # 0x29000019（0x41C613）：x=-0xA0、+0x1C=p3、+0x20..24=*p0（块解引用，生成点填）、
    #   +0x28=*(p3+0x1C)（生成点填）、+0x2C=*p1、rect=*(p1+4)?{180,F0,1AF,11F}:{180,120,1AF,14F}
    0x29000019: {"beh": 0x401CCB, "imm": {0x04: -0xA0}, "d_to": 0x1C,
                 "rect_link": ("b", 4, (0x180,0xF0,0x1AF,0x11F), (0x180,0x120,0x1AF,0x14F))},
    # 0x2900001A（0x41C6E5）：x=-0xA0、+0x1C=p3、+0x20..2C=*p0[0..3]、+0x30=*p1、rect 同上式
    0x2900001A: {"beh": 0x401384, "imm": {0x04: -0xA0}, "d_to": 0x1C,
                 "rect_link": ("b", 4, (0x180,0xF0,0x1AF,0x11F), (0x180,0x120,0x1AF,0x14F))},
    # 0x2900001B（0x41C7BB）：x=-0xA0、+0x1C=p3、+0x20=p0、+0x24=p1、+0x28=3、+0x2C/30=0、
    #   node.rect={-30,-1,-1,-30}、node.dst=(-30,-30)、node.active=0
    0x2900001B: {"beh": 0x40140B, "imm": {0x04: -0xA0, 0x28: 3, 0x2C: 0, 0x30: 0},
                 "d_to": 0x1C, "r0_20": True, "r1_24": True,
                 "node_custom": {"rect": (-0x30, -1, -1, -0x30), "dst": (-0x30, -0x30),
                                 "active": 0}},
    # 0x2900001C（0x41C849）：x=-0xA0、beh=0x401C7B、+0x1C=p3、+0x20=p0、+0x24=0、
    #   node.rect={0,0,0,0}、node.dst=(0,0)（0x41C849 → 0x41CB47 直跳：dst=(-30,-30)?? ——
    #   实测 0x41C870 jmp 0x41CB47 → 只设 dst=(-0x30,-0x30)，rect 不动）
    0x2900001C: {"beh": 0x401C7B, "imm": {0x04: -0xA0, 0x24: 0}, "d_to": 0x1C,
                 "r0_20": True,
                 "node_custom": {"dst": (-0x30, -0x30), "active": 1}},
    # 0x2900001D（0x41C875）：x=-0xA0、beh=0x40209F、+0x1C=p3、+0x20=p0、+0x24=p1、+0x28=0、
    #   node.dst=(-0x30,-0x30)、node.active=0
    0x2900001D: {"beh": 0x40209F, "imm": {0x04: -0xA0, 0x28: 0}, "d_to": 0x1C,
                 "r0_20": True, "r1_24": True,
                 "node_custom": {"dst": (-0x30, -0x30), "active": 0}},
    0x2900001E: {"beh": 0x401474, "imm": {0x20: 0x40, 0x24: 0}, "d_to": 0x1C},
    # 0x2900001F（0x41C99E）：x=-0xA0、+0x1C=p3、+0x20=*p0、+0x24=*(p0+4)+0x18、+0x28=0、
    #   rect=*(p0+8)?if:else（生成点填）
    0x2900001F: {"beh": 0x401F6E, "imm": {0x04: -0xA0, 0x28: 0}, "d_to": 0x1C,
                 "rect_link": ("a", 8, (0x180,0xF0,0x1AF,0x11F), (0x180,0x120,0x1AF,0x14F))},
    # 0x29000020（0x41CA67）：x=-0xA0、+0x1C=*p3、+0x20=p0、+0x24=p1、+0x28=*(p3+4)、
    #   rect=p1==-0xA8?if:else（生成点填）
    0x29000020: {"beh": 0x401A82, "imm": {0x04: -0xA0}, "r0_20": True, "r1_24": True,
                 "rect_cmp": (-0xA8, (0x180, 0xF0, 0x1AF, 0x11F),
                              (0x180, 0x120, 0x1AF, 0x14F))},
    # 0x29000021（0x41CB69）：+0x1C=*p3、+0x20=*(p3+4)、+0x24=p0<<8、+0x28=p1<<8、+0x2C=0、
    #   +0x18=|*p3|+|*(p3+4)|、SE(2,(x-0x140)<<4)（0x41FFF0 生成点填）
    0x29000021: {"beh": 0x40166D, "imm": {0x2C: 0}},
}


# 0x2A 族（关8）ctor case 表（0x40A410，跳表 0x40A7F8，10 型）——2026-11-06 读定
ENT2A_INIT = {
    0x2A000001: {"beh": 0x4018C5, "imm": {0x0C: 0x90, 0x18: 0x30D40},
                 "node": (2, 0, 0, 0x10F, 0x13F), "dst": (-0x88, -0xA0), "b10_1": True},
    0x2A000002: {"beh": 0x401E60, "imm": {0x0C: 0x18, 0x18: 0x640},
                 "node": (2, 0x110, 0, 0x16F, 0x5F), "dst": (-0x2C, -0x32),
                 "b10_1": True, "d_to": 0x1C},
    0x2A000003: {"beh": 0x401ED8, "imm": {0x0C: 0x18, 0x18: 0x640, 0x30: 0},
                 "node": (2, 0x1E0, 0, 0x27F, 0x9F), "dst": (-0x50, -0x50),
                 "b10_1": True, "d_to": 0x1C},
    0x2A000004: {"beh": 0x401B22, "imm": {0x0C: 0x18, 0x18: 0x640},
                 "node": (2, 0x170, 0, 0x1DF, 0x103), "dst": (-0x28, -0xC8),
                 "b10_1": True, "d_to": 0x1C},
    0x2A000005: {"beh": 0x4011BD, "s2a05": True},
    0x2A00000A: {"beh": 0x40D030, "imm": {0x0C: 0x78, 0x18: 0x3E80,
                                          0x1C: 0, 0x20: 0, 0x24: 0},
                 "node": (2, 0, 0, 0xEF, 0xEF), "dst": (-0x78, -0x78)},
}

# 0x2C 族（最终关前半）ctor case 表（0x403AA0，跳表 0x4044D8，20 型）——2026-11-06 读定
# case7/14/15 跳表项 0 = 无 ctor；多数有 d_to=[0x1C]
ENT2C_INIT = {
    0x2C000001: {"beh": 0x401B9F, "imm": {0x0C: 0x60, 0x18: 0x12C0},
                 "node": (2, 0, 0, 0xBF, 0xBF), "dst": (0, 0), "b10_1": True},
    0x2C000002: {"beh": 0x401712, "imm": {0x0C: 0x60, 0x18: 0x12C0}, "d_to": 0x1C,
                 "node": (2, 0, 0, 0xBF, 0xBF), "dst": (0, 0), "b10_1": True},
    0x2C000003: {"beh": 0x401E33, "imm": {0x0C: 0x60, 0x18: 0x960}, "d_to": 0x1C,
                 "node": (2, 0, 0, 0xBF, 0xBF), "dst": (0, 0), "b10_1": True},
    0x2C000004: {"beh": 0x401A55, "imm": {0x0C: 0x18, 0x18: 0x100, 0x20: -0x2F,
                                          0x24: 0x11, 0x28: 0}, "d_to": 0x1C,
                 "node": (2, 0xC0, 0x30, 0xEF, 0x5F), "dst": (0, 0), "b10_1": True},
    0x2C000005: {"beh": 0x40101E, "imm": {0x0C: 0x18}, "s2c05": True,
                 "node": (2, 0xC0, 0x30, 0xEF, 0x5F), "dst": (0, 0), "b10_1": True},
    0x2C000006: {"beh": 0x401EE7, "imm": {0x0C: 0x18, 0x18: 0x20, 0x1C: -0x618},
                 "r1sh": (0x20, 8),
                 "node": (2, 0xC0, 0, 0xEF, 0x2F), "dst": (0, 0), "b10_1": True},
    0x2C000008: {"beh": 0x40136B, "imm": {0x0C: 0x30, 0x18: 0xC80}, "spawn_5c": True,
                 "node": (2, 0, 0, 0x5F, 0x5F), "dst": (-0x30, -0x30), "b10_1": True},
    0x2C000009: {"beh": 0x4015DC, "imm": {0x0C: 0x18, 0x18: 0x20}},
    0x2C00000A: {"beh": 0x401A14},
    0x2C00000B: {"beh": 0x401AA0, "imm": {0x0C: 0x30, 0x20: 0x1C2}, "r0_1C": True,
                 "d_to": 0x28, "dst": (-0x30, -0x30), "b10_1": True},
    0x2C00000C: {"beh": 0x4010C8, "imm": {0x0C: 0x30, 0x18: 0x2710}, "s2c0c": True,
                 "node": (2, 0, 0, 0, 0), "dst": (-0x30, -0x30), "b10_1": True},
    0x2C00000D: {"beh": 0x401D66, "imm": {0x18: 0xE}, "s2c0d": True,
                 "node": (2, 0, 0x60, 0x5F, 0xBF), "dst": (-0x30, -0x30)},
    0x2C000010: {"beh": 0x40158C, "imm": {0x0C: 0x48, 0x18: 0x2580, 0x1C: -0x50, 0x20: -1},
                 "node": (2, 0, 0x90, 0x8F, 0x11F), "dst": (-0x48, -0x48), "b10_1": True},
    0x2C000011: {"beh": 0x40103C, "imm": {0x0C: 0x48, 0x18: 0x320, 0x28: 0x800},
                 "d_to": 0x1C, "r0sh": (0x20, 8), "r1sh": (0x24, 8),
                 "r1_2C_1": True,
                 "node": (2, 0, 0, 0x8F, 0x8F), "dst": (-0x48, -0x48), "b10_1": True},
    0x2C000012: {"beh": 0x402167, "imm": {0x0C: 0x30, 0x18: 0x30},
                 "node": (2, 0, 0x120, 0x5F, 0x17F), "dst": (-0x30, -0x30), "b10_1": True},
    0x2C000013: {"beh": 0x402167, "imm": {0x0C: 0x18, 0x18: 0xC},
                 "node": (2, 0x60, 0x120, 0x8F, 0x14F), "dst": (-0x18, -0x18),
                 "b10_1": True, "active0": True},
    0x2C000014: {"beh": 0x4015E6, "imm": {0x0C: 0x18},
                 "node": (2, 0x60, 0x120, 0x8F, 0x14F), "dst": (-0x18, -0x18), "b10_1": True},
}

# 0x2D 族（最终关）ctor case 表（0x408150，跳表 0x40845C，5 型）——2026-11-06 读定
ENT2D_INIT = {
    0x2D000018: {"beh": 0x401EBF,
                 "imm": {0x0C: 0x78, 0x18: 0x7080, 0x20: 0xF003200,
                         0x24: 0x780014, 0x28: -0x708},
                 "node": (2, 0, 0, 0xEF, 0xEF), "dst": (0, 0), "b10_1": True},
    0x2D000019: {"beh": 0x4017DA, "node": (2, 0, 0, 0, 0), "dst": (0, 0),
                 "s19_fields": True},
    # 0x2D00001B（0x4082CE）：+0xC=0x10、+0x18=-1、+0x1C=p0(主)、+0x20=0、+0x24=0、
    #   +0x28=p1（主铺=0 待机；链生子=p1≠0 即散开）、+0x2C=p3、+0x30=(p1==0)?2:0
    0x2D00001A: {"beh": 0x401690, "imm": {0x0C: 0x10, 0x18: -1, 0x20: 0, 0x24: 0},
                 "r0_1C": True, "r1_28": True, "d_to": 0x2C, "s1z2_30": True,
                 "node": (2, 0, 0, 0, 0), "dst": (0, 0), "b10_1": True},
    # 0x2D00001C/1D（0x40832D/0x4083A1）：+0xC=8、+0x18=-1、+0x1C=p0(主)、+0x20=p1、
    #   +0x24=*(p0+0x20)（主打包位）、+0x28=p3*(p1?450:1)、+0x2C=(p1?p3:0)、+0x30=0、
    #   node.rect={0,0,0,0}、node.dst=(0,0)、node.active=1
    0x2D00001B: {"beh": 0x4014AB, "imm": {0x0C: 8, 0x18: -1, 0x30: 0},
                 "r0_1C": True, "r1_20": True, "deref0_24": True,
                 "s3m450_28": True, "s3if_2C": True,
                 "node": (2, 0, 0, 0, 0), "dst": (0, 0), "b10_1": True,
                 "node_custom": {"rect": (0, 0, 0, 0), "dst": (0, 0), "active": 1}},
    0x2D00001C: {"beh": 0x4014AB, "imm": {0x0C: 8, 0x18: -1, 0x30: 0},
                 "r0_1C": True, "r1_20": True, "deref0_24": True,
                 "s3m450_28": True, "s3if_2C": True,
                 "node": (2, 0, 0, 0, 0), "dst": (0, 0), "b10_1": True,
                 "node_custom": {"rect": (0, 0, 0, 0), "dst": (0, 0), "active": 1}},
}


# 0x24 族高频行为转写（2026-11-06）

def _beh_411990(self, e) -> bool:
    """`0x411990`（0x2400000E，×266 最高频）：匀速直线 + 出屏/HP 门自灭。

    [0x4] += [0x20]; [0x8] += [0x24]; node dst=(x−0x18, y−0x18)；
    0x4021E9(0x18) 出屏测（margin 24）＋ [0x18]≠0 → 活，否则灭。
    """
    vx, vy = e.s32(0x20), e.s32(0x24)
    e.d32(0x04, (e.s32(4) + vx) & 0xFFFFFFFF)
    e.d32(0x08, (e.s32(8) + vy) & 0xFFFFFFFF)
    if e.node is not None:
        e.node.dst = (e.s32(4) - 0x18, e.s32(8) - 0x18)
    # 0x4021E9(0x18) 出屏测
    x, y = e.s32(4), e.s32(8)
    margin = 0x18
    on_screen = (-margin < x < 0x280 + margin and -margin < y < 0x1E0 + margin)
    return on_screen and e.g32(0x18) != 0


def _beh_410E10(self, e) -> bool:
    """`0x410E10`（0x24000001，×224）：亚像素直线+正弦减速+周期开火。

    [0x1C] += [0x20](=−32)；[0x20] += [0x24](=±1)；[0x20] 到 ±0x20 → [0x24] 反转
    （正弦周期）；x 低 2 位=0 时 0x45A790(node,0,[0x28],0,[0x28])（帧动画）；
    y=[0x1C]>>3（定点 8.3 → x=src−2）；x < −0x18 或 HP=0 → 灭；
    [0x20]==0 且 [0x24]==[0x2C] → 0x43B070(e,0) 开火。
    """
    accel = e.s32(0x20)
    sub = e.s32(0x1C)
    flip = e.s32(0x24)
    sub = (sub + accel) & 0xFFFFFFFF
    sub_s = sub - 0x100000000 if sub & 0x80000000 else sub
    accel = (accel + flip) & 0xFFFFFFFF
    accel_s = accel - 0x100000000 if accel & 0x80000000 else accel
    e.d32(0x1C, sub)
    e.d32(0x20, accel)
    if accel_s == 0x20:
        e.d32(0x24, 0xFFFFFFFF)        # 反转：加速衰减
    elif accel_s == -0x20:
        e.d32(0x24, 1)
    # 0x410E46：x 低 2 位=0 → 0x45A790(node+4, [0x28],0,[0x28],0)，只滑 rect.l/r
    if (e.s32(4) & 3) == 0 and e.node is not None:
        v = e.s32(0x28)
        e.node.rect = (e.node.rect[0] + v, e.node.rect[1],
                       e.node.rect[2] + v, e.node.rect[3])
    # 0x410E5E：比较 node+4（rect.l）0x120 / 0
    if e.node is not None:
        if e.node.rect[0] == 0x120:
            e.d32(0x28, 0xFFFFFFD0)
        elif e.node.rect[0] == 0:
            e.d32(0x28, 0x30)
    # 开火
    if accel_s == 0 and flip == e.s32(0x2C):
        self.p4_43B070(e, 0)           # 0x40213F → 0x43B070
    # 位移：x −= 2；y = [0x1C] >> 3（定点）
    e.d32(4, (e.s32(4) - 2) & 0xFFFFFFFF)
    y = sub_s >> 3
    e.d32(8, y & 0xFFFFFFFF)
    if e.node is not None:
        e.node.dst = (e.s32(4) - 0x18, y - 0x18)
    return e.s32(4) >= -0x18 and e.g32(0x18) != 0


def _beh_411200(self, e) -> bool:
    """`0x411200`（0x24000005；0x24000006 共用）：**16 位双通道摆动 + 打包速度**。

    word[0x20] -= 2；低字节==0 且 [0x1C]!=0 → 0x43B070(e,0)。
    [0x28]<=0 → word[0x24]+=1 否则 −1；[0x2C]<=0 → word[0x26]+=1 否则 −1；
    [0x28]+=(int16)word[0x24]、[0x2C]+=(int16)word[0x26]；
    x=(int16)word[0x20] + ([0x28]+1)>>1、y=(int16)word[0x22] + ([0x2C]+2)>>2。
    存活 = HP!=0 && ((int16)word[0x20]>=0 || x>=-0x18)。
    """
    w20 = (e.g16(0x20) - 2) & 0xFFFF
    e.d16(0x20, w20)
    if (w20 & 0xFF) == 0 and e.s32(0x1C) != 0:
        self.p4_43B070(e, 0)
    v28, v2c = e.s32(0x28), e.s32(0x2C)
    e.d16(0x24, (e.g16(0x24) + (1 if v28 <= 0 else -1)) & 0xFFFF)
    e.d16(0x26, (e.g16(0x26) + (1 if v2c <= 0 else -1)) & 0xFFFF)
    def s16(v):
        return v - 0x10000 if v & 0x8000 else v
    v28 = (v28 + s16(e.g16(0x24))) & 0xFFFFFFFF
    v2c = (v2c + s16(e.g16(0x26))) & 0xFFFFFFFF
    e.d32(0x28, v28)
    e.d32(0x2C, v2c)
    sx = s16(e.g16(0x20))
    sy = s16(e.g16(0x22))
    v28s = v28 - 0x100000000 if v28 & 0x80000000 else v28
    v2cs = v2c - 0x100000000 if v2c & 0x80000000 else v2c
    x = (sx + ((v28s + 1) >> 1)) & 0xFFFFFFFF
    y = (sy + ((v2cs + 2) >> 2)) & 0xFFFFFFFF
    e.d32(0x04, x)
    e.d32(0x08, y)
    if e.node is not None:
        e.node.dst = ((x - 0x18) & 0xFFFFFFFF, (y - 0x18) & 0xFFFFFFFF)
    return e.g32(0x18) != 0 and (sx >= 0 or e.s32(0x04) >= -0x18)


def _beh_411040(self, e) -> bool:
    """`0x411040`（0x24000003 攻，×18；ctor 0x410A20 case2：[0x20]=-32、[0x24]=rec3）两段式：

    [0x24]==0 俯冲段：每帧 `[e+0x18]=-1`（不可击破）、y += [0x20] 后 [0x20]++（加速）、
      x -= 0xC，并 `0x430400(rec, x-0xC, y, 0x24000003, 1)` 自我复制入 0x4AD43C
      （param=1 = 火口残留）；`return x > -0x18`（0x4110AF setg）。
    [0x24]!=0 火口段：`[0x1C]++` 每帧，`(t&7)==0` 时 rect 滑 0x30（口部动画），
      `t==0x38` 自灭。"""
    if e.s32(0x24) == 0:                             # 0x411052 俯冲段
        e.d32(0x18, 0xFFFFFFFF)                      # 0x411049
        acc = e.s32(0x20)
        y = (e.s32(0x08) + acc) & 0xFFFFFFFF         # 0x411061
        e.d32(0x20, (acc + 1) & 0xFFFFFFFF)          # 0x411063 inc
        x = (e.s32(0x04) - 0xC) & 0xFFFFFFFF         # 0x41105E
        self._p4_ent43c(0x24000003, x, y, 1)         # 0x411080 自我复制（火口）
        e.d32(0x04, x)
        e.d32(0x08, y)
        return e.s32(0x04) > -0x18                   # 0x4110AF setg
    t = (e.s32(0x1C) + 1) & 0xFFFFFFFF               # 0x4110B6 火口段
    e.d32(0x1C, t)
    if (t & 7) == 0:                                 # 0x4110BF test al,7
        if t == 0x38:                                # 0x4110C3
            return False                             # 0x4110C8
        if e.node is not None:                       # 0x4110DE 0x45A790(0x30,0,0x30,0)
            e.node.rect = (e.node.rect[0], e.node.rect[1] + 0x30,
                           e.node.rect[2], e.node.rect[3] + 0x30)
    return True                                      # 0x4110E6


def _beh_411120(self, e) -> bool:
    """`0x411120`（0x24000004，×5）：三段式（0x50/0x68/0x69/0x91）。

    t=++[0x1C]；t>0x50：
      t<=0x68 且 t&3==0 → [0x24]=0、rect.l/r −=0x30；
      否则 x+=3、[0x24]−−，t==0x69 或 0x91 → 0x43B070(e,0)。
    [0x20]+=[0x24]；y=[0x20]>>3；dst=(x−0x18,y−0x18)；
    存活 = x<0x298 && y>−0x18 && HP!=0。
    """
    t = (e.s32(0x1C) + 1) & 0xFFFFFFFF
    e.d32(0x1C, t)
    if t > 0x50:
        if t <= 0x68 and (t & 3) == 0:
            e.d32(0x24, 0)
            if e.node is not None:
                e.node.rect = (e.node.rect[0] - 0x30, e.node.rect[1],
                               e.node.rect[2] - 0x30, e.node.rect[3])
        else:
            e.d32(0x04, (e.s32(0x04) + 3) & 0xFFFFFFFF)
            e.d32(0x24, (e.s32(0x24) - 1) & 0xFFFFFFFF)
            if t == 0x69 or t == 0x91:
                self.p4_43B070(e, 0)
    v20 = (e.s32(0x20) + e.s32(0x24)) & 0xFFFFFFFF
    e.d32(0x20, v20)
    v20s = v20 - 0x100000000 if v20 & 0x80000000 else v20
    y = v20s >> 3
    e.d32(0x08, y & 0xFFFFFFFF)
    if e.node is not None:
        e.node.dst = (e.s32(0x04) - 0x18, y - 0x18)
    return (e.s32(0x04) < 0x298 and y > -0x18 and e.g32(0x18) != 0)


def _beh_411C10(self, e) -> bool:
    """`0x411C10`（0x24000011）：**绕宿主公转的挂件**。

    [0x24]=宿主链、[0x20]=兄弟链（句柄）。
    ([0x1C]&0x7F)==0 且 [宿主+0x2C]==1 → 0x43B070(e,0)；
    [0x1C] 奇 → x−=1；
    [0x20]!=0：y < [[0x20]+8]−0x60 → x−=1、y+=2；并把 [0x20] 沿 [+0x20]
      链跳到第一个 byte[+0x34]!=0 的节点；
    [0x20]==0：y<0x1B0 → x−=1、y+=2。
    存活 = HP && 宿主存活 && x≥−0x30：
      [0x1C]++、[0x28]++，dst=(x−cos(90·[0x28])>>5−0x30, y+sin(90·[0x28])>>5−0x30)；
    否则（x≥−0x30 时）在 (x,y−0x18)、(−0x18,+0x30)、(+0x30) 三点各生成
    0x44000001 到 0x4AD4CC，并 [宿主+0x28]++，return 0。
    """
    host = self._deref_link(e.s32(0x24))
    t = e.s32(0x1C)
    if (t & 0x7F) == 0 and host is not None and host.s32(0x2C) == 1:
        self.p4_43B070(e, 0)
    if t & 1:
        e.d32(0x04, (e.s32(0x04) - 1) & 0xFFFFFFFF)
    part = self._deref_link(e.s32(0x20))
    x, y = e.s32(0x04), e.s32(0x08)
    if part is not None:
        if y < part.s32(0x08) - 0x60:
            x -= 1
            y += 2
            e.d32(0x04, x & 0xFFFFFFFF)
            e.d32(0x08, y & 0xFFFFFFFF)
        # 0x411C5E..0x411C76：沿 [+0x20] 找第一个存活的兄弟
        while part is not None and not part.alive:
            h = part.g32(0x20)
            e.d32(0x20, h)
            part = self._deref_link(h)
    elif y < 0x1B0:                                # 0x411C7A
        x -= 1
        y += 2
        e.d32(0x04, x & 0xFFFFFFFF)
        e.d32(0x08, y & 0xFFFFFFFF)
    alive = (e.g32(0x18) != 0 and host is not None and host.alive
             and x >= -0x30)
    if alive:                                      # 0x411C91
        e.d32(0x1C, (t + 1) & 0xFFFFFFFF)
        ph = (e.s32(0x28) + 1) & 0xFFFFFFFF
        e.d32(0x28, ph)
        ang = (ph * 90) & 0xFFFFFFFF
        dx = (-page4_cos(ang)) >> 5
        dy = page4_sin(ang) >> 5
        if e.node is not None:
            e.node.dst = (x + dx - 0x30, y + dy - 0x30)
        return True
    # 0x411D05 死亡/脱离：三片 0x44000001
    if x >= -0x30:
        by = y - 0x18
        self.spawn(self._p4_q("ui4cc"), 0x44000001, x, by)
        self.spawn(self._p4_q("ui4cc"), 0x44000001, x - 0x18, by + 0x30)
        self.spawn(self._p4_q("ui4cc"), 0x44000001, x - 0x18 + 0x30, by + 0x30)
    if host is not None:
        host.d32(0x28, (host.s32(0x28) + 1) & 0xFFFFFFFF)
    return False


def _beh_416A50(self, e) -> bool:
    """`0x416A50`（0x27000007，×608 最高频）：渐进逼近 + 单次开火 + 0x416440。

    [0x20] 计数器：x<0x140 且 t<0x28 → t++；t>0x18 且 x>0x230 → t−−；
    x += t>>3（渐进水平速度）；x > 0x1A4 且 [0x1C]≠0 → 0x43B070(e,0) 开火、[0x1C]=0；
    尾调 0x416440（boss 0x27000011 spawner）；x≥0x298 或 HP=0 → 灭。
    """
    t = e.s32(0x20)
    if t < 0x28 and e.s32(4) < 0x140:
        t += 1
    if t > 0x18 and e.s32(4) > 0x230:
        t -= 1
    e.d32(0x20, t & 0xFFFFFFFF)
    e.d32(4, (e.s32(4) + (t >> 3)) & 0xFFFFFFFF)
    if e.s32(4) > 0x1A4 and e.s32(0x1C) != 0:
        self.p4_43B070(e, 0)
        e.d32(0x1C, 0)
    if e.node is not None:
        e.node.dst = (e.s32(4) - 0x18, e.s32(8) - 0x18)
    # 0x401F91 → 0x416440：0x27000011 boss spawner 检查（spawned 时跳过后续）
    # 复刻侧暂不实现 boss spawner 的内联触发（0x27000011 由 op2 直接生成）
    return e.g32(0x18) != 0 and e.s32(4) < 0x298


def _beh_416940(self, e) -> bool:
    """`0x416940`（0x27000006）：x∈[0x1E0,0x230)→[0x1C]+=[0x24]；x∈[0x190,0x1E0)→−=[0x24]；
    x==0x140 且 [0x20]==1 → 0x43B070；x −= (x≤−0x18 ? 1 : 4)；y += [0x1C]>>2；
    x==0x190/0x78 → 0x43B070；0x416440；存活 HP && x>−0x54。"""
    x = e.s32(0x04)
    if 0x1E0 <= x < 0x230:
        e.d32(0x1C, (e.s32(0x1C) + e.s32(0x24)) & 0xFFFFFFFF)
    elif 0x190 <= x < 0x1E0:
        e.d32(0x1C, (e.s32(0x1C) - e.s32(0x24)) & 0xFFFFFFFF)
    if x == 0x140 and e.s32(0x20) == 1:
        self.p4_43B070(e, 0)
    step = 1 if x <= -0x18 else 4
    x = (x - step) & 0xFFFFFFFF
    e.d32(0x04, x)
    y = (e.s32(0x08) + (e.s32(0x1C) >> 2)) & 0xFFFFFFFF
    e.d32(0x08, y)
    if e.node is not None:
        e.node.dst = (e.s32(0x04) - 0x18, y - 0x18)
    if x == 0x190 or x == 0x78:
        self.p4_43B070(e, 0)
    self.p4_416440(e)
    return e.g32(0x18) != 0 and e.s32(0x04) > -0x54


def _beh_416A50_wrap(e_self, e):
    return _beh_416A50(e_self, e)


def _beh_4127E0(self, e) -> bool:
    """`0x4127E0`（0x25000006 ×184 / 0x25000007 ×45 / 0x25000008 ×3 共用）：
    三阶段运动（0x1C 帧计数）：t<0x18 弹跳动画（x%4==3 → node 外扩 ±0x30）；
    t==0x18 → 可视化切换（type==0x25000007 → b10=1）+ 0x45AA80 朝自机方向 → [0x28]；
    t>0x20（=rec[3]）→ 正弦螺旋（[0x28] 角速度、[0x24] 半径每帧递减≤14、
    x=[0x2C]+cos*[0x24]>>8、y=[0x30]+sin*[0x24]>>8，位移/2 定屏）；出屏/HP 门自灭。
    """
    t = (e.s32(0x1C) + 1) & 0xFFFFFFFF
    e.d32(0x1C, t)
    if t < 0x18:
        if (t & 3) == 3:                                # 0x4127F1 弹跳动画
            if e.node is not None:
                e.node.rect = (e.node.rect[0] - 0x30, e.node.rect[1],
                               e.node.rect[2] - 0x30, e.node.rect[3])
    elif t == 0x18:                                     # 0x4127E0/0x41281A 起飞
        if e.g32(0x14) == 0x25000007:
            e.m[0x10] = 1
        dx = self.p4_player_x() - e.s32(4)              # 0x412827 [0x56CC8C]−x
        dy = self.p4_player_y() - e.s32(8)              # 0x412830 [0x56CC90]−y
        e.d32(0x28, page4_45a9a0(dy, dx) & 0xFFFFFFFF)  # 0x41283E 0x401091→0x45A9A0 角度存 [0x28]
    elif t > e.s32(0x20):                               # 0x412853 正弦螺旋
        if e.g32(0x14) == 0x25000006 and e.node is not None:
            e.node.active = 0 if e.node.active else 1   # 0x41285C 闪烁
        r = e.s32(0x24)
        if r > 0xE:
            r -= 1
            e.d32(0x24, r)
        ang = e.s32(0x28)
        c = page4_cos(ang)
        s_ = page4_sin(ang)
        e.d32(0x2C, (e.s32(0x2C) + ((c * r + 0x7F) >> 8)) & 0xFFFFFFFF)
        e.d32(0x30, (e.s32(0x30) + ((s_ * r + 0x7F) >> 8)) & 0xFFFFFFFF)
        x2, y2 = e.s32(0x2C), e.s32(0x30)
        e.d32(8, (x2 >> 1) & 0xFFFFFFFF)
        e.d32(4, (y2 >> 1) & 0xFFFFFFFF)
        if e.node is not None:
            e.node.dst = ((y2 >> 1) - 0x18, (x2 >> 1) - 0x18)
    # 出屏测 margin 0x18 + HP 门
    x, y = e.s32(4), e.s32(8)
    on_screen = (-0x18 < x < 0x280 + 0x18 and -0x18 < y < 0x1E0 + 0x18)
    return on_screen and e.g32(0x18) != 0


def page4_45aa80(dx: int, dy: int) -> int:
    """`0x45AA80`（thunk `0x40231F`）：**倒数距离** 单值 `4096/|(dx,dy)|`。

    与 `Page4Mixin.p4_45aa80` 同一实现（表 0x593AB4 = trunc(4096/√n)，0x45A7E0 生成）。
    旧版这里返回 (nx, ny) 归一对 ⇒ 与 exe 不符（0x4126DB 等调用点全是
    `inv×Δ×速度>>12` 的单值形态）⇒ 已并。
    """
    return Page4Mixin.p4_45aa80(dx, dy)


P4_ATAN2_TABLE: "list[int] | None" = None


def _p4_atan2_table() -> "list[int]":
    """`word[0x5B3E38 + (row*256+col)*2]`：0x45A7E0 生成——
    `trunc(fpatan(row,col) × [0x499378]=572.9564553093966)`，行/列 ∈ [0,256)。
    （.data 的 raw 区不含此表，运行期生成；0x45A7E0 尾部以校验和 0xF49074E7 自检。）"""
    global P4_ATAN2_TABLE
    if P4_ATAN2_TABLE is None:
        k = 572.9564553093966                       # [0x499378] 实测 double
        P4_ATAN2_TABLE = [int(math.atan2(r, c) * k)
                          for r in range(256) for c in range(256)]
    return P4_ATAN2_TABLE


def page4_45a9a0(a0: int, a1: int) -> int:
    """`0x45A9A0`（thunk `0x401091`）：**atan2**，单位 1/3600 圈（0x708=半圈、0xE10=整圈）。

    ```
    0x45A9A9 if (a0 == 0 && a1 == 0) → 0
    0x45A9B5..0x45A9D5 while (|a0| >= 0x100 或 |a1| >= 0x100)：a0 sar 1、a1 sar 1
    0x45A9DF t = word[0x5B3E38 + (|a0|*256 + |a1|)*2]     ; 四象限同表取 |a0|,|a1|
    0x45A9DF a0>=0, a1>=0 → t
    0x45A9DD a0< 0, a1>=0 → 0xE10 − t
    0x45AA15 a0>=0, a1< 0 → 0x708 − t
    0x45AA3C a0< 0, a1< 0 → t + 0x708
    ```
    调用约定：`(arg0, arg1) = (第二个 push, 第一个 push)`；exe 调用点一律
    `push dx; push dy; call` ⇒ arg0=dy、arg1=dx（即标准 atan2(y, x)）。
    """
    a0 = int(a0)
    a1 = int(a1)
    if a0 == 0 and a1 == 0:                         # 0x45A9A9
        return 0
    while a0 >= 0x100 or a0 < -0x100 or a1 >= 0x100 or a1 < -0x100:
        a0 >>= 1                                    # 0x45A9D1 sar（负数向 −∞）
        a1 >>= 1
    t = _p4_atan2_table()[abs(a0) * 256 + abs(a1)]  # 0x45A9E7/0x45A9F7/0x45AA1B/0x45AA37
    if a0 < 0:
        return (0xE10 - t) if a1 >= 0 else (t + 0x708)
    return (0x708 - t) if a1 < 0 else t


def _beh_411470(self, e) -> bool:
    """`0x411470`（0x24000008，×94）：恒速左移 −8/帧，node dst 同步；x<−0x18 或 HP=0 → 灭。"""
    e.d32(4, (e.s32(4) - 8) & 0xFFFFFFFF)
    if e.node is not None:
        nd = e.node
        nd.dst = (nd.dst[0] - 8, nd.dst[1])
    return e.s32(4) > -0x18 and e.g32(0x18) != 0


def _beh_410F20(self, e) -> bool:
    """`0x410F20`（0x24000002，×86）：与 0x410E10 同构但 [0x20]=0x40、[0x1C]>>4、
    正弦上限 ±0x40（非 ±0x20）、[0x24]=0x3C 开火门（非 [0x2C]）。"""
    accel = e.s32(0x20)
    sub = e.s32(0x1C)
    flip = e.s32(0x24)
    sub = (sub + accel) & 0xFFFFFFFF
    sub_s = sub - 0x100000000 if sub & 0x80000000 else sub
    accel = (accel + flip) & 0xFFFFFFFF
    accel_s = accel - 0x100000000 if accel & 0x80000000 else accel
    e.d32(0x1C, sub)
    e.d32(0x20, accel)
    if accel_s == 0x40:
        e.d32(0x24, 0xFFFFFFFF)
    elif accel_s == -0x40:
        e.d32(0x24, 1)
    if (e.s32(4) & 3) == 0 and e.node is not None:
        v = e.s32(0x28)
        e.node.rect = (e.node.rect[0] + v, e.node.rect[1],
                       e.node.rect[2] + v, e.node.rect[3])
    if e.node is not None:
        if e.node.rect[0] == 0x120:
            e.d32(0x28, 0xFFFFFFD0)
        elif e.node.rect[0] == 0:
            e.d32(0x28, 0x30)
    if accel_s == 0 or abs(accel_s) == 0x40:
        if e.s32(0x2C) != 0:
            self.p4_43B070(e, 0)
    e.d32(4, (e.s32(4) - 2) & 0xFFFFFFFF)
    y = sub_s >> 4
    e.d32(8, y & 0xFFFFFFFF)
    if e.node is not None:
        e.node.dst = (e.s32(4) - 0x18, y - 0x18)
    return e.s32(4) >= -0x18 and e.g32(0x18) != 0


def _beh_4121C0(self, e) -> bool:
    """`0x4121C0`（0x25000001 ×66）：四阶段——t<0x18 弹跳动画；t∈[0x18,0xB0) 8.8 定速
    直线（[0x20]+=[0x28];[0x24]+=[0x2C];>>2 定屏，byte[0x10]=1）；t==0xB0 开火；
    t∈[0xB0,0xC8) 反向弹跳；t≥0xC8 自灭。"""
    t = (e.s32(0x1C) + 1) & 0xFFFFFFFF
    e.d32(0x1C, t)
    if t < 0x18:
        if (t & 3) == 3 and e.node is not None:
            e.node.rect = (e.node.rect[0], e.node.rect[1] - 0x30,
                           e.node.rect[2], e.node.rect[3] - 0x30)
        return e.g32(0x18) != 0
    if t < 0xB0:
        e.m[0x10] = 1
        e.d32(0x20, (e.s32(0x20) + e.s32(0x28)) & 0xFFFFFFFF)
        e.d32(0x24, (e.s32(0x24) + e.s32(0x2C)) & 0xFFFFFFFF)
        x2, y2 = e.s32(0x20), e.s32(0x24)
        e.d32(8, (y2 >> 2) & 0xFFFFFFFF)
        e.d32(4, (x2 >> 2) & 0xFFFFFFFF)
        if e.node is not None:
            e.node.dst = ((x2 >> 2) - 0x18, (y2 >> 2) - 0x18)
        return e.g32(0x18) != 0
    if t == 0xB0:
        self.p4_43B070(e, 0)                                    # 0x40213F 开火
        return e.g32(0x18) != 0
    if t < 0xC8:
        if (t & 3) == 3 and e.node is not None:
            e.node.rect = (e.node.rect[0], e.node.rect[1] + 0x30,
                           e.node.rect[2], e.node.rect[3] + 0x30)
        return e.g32(0x18) != 0
    return False                                                 # t ≥ 0xC8 自灭


def _beh_4122D0(self, e) -> bool:
    """`0x4122D0`（0x25000002 ×52）：与 0x4121C0 同构，t==0x18 开火 + byte[0x10]=1。"""
    t = (e.s32(0x1C) + 1) & 0xFFFFFFFF
    e.d32(0x1C, t)
    if t < 0x18:
        if (t & 3) == 3 and e.node is not None:
            e.node.rect = (e.node.rect[0], e.node.rect[1] - 0x30,
                           e.node.rect[2], e.node.rect[3] - 0x30)
        return e.g32(0x18) != 0
    if t == 0x18:
        e.m[0x10] = 1
        self.p4_43B070(e, 0)
        return e.g32(0x18) != 0
    if t < 0xB0:
        e.d32(0x20, (e.s32(0x20) + e.s32(0x28)) & 0xFFFFFFFF)
        e.d32(0x24, (e.s32(0x24) + e.s32(0x2C)) & 0xFFFFFFFF)
        x2, y2 = e.s32(0x20), e.s32(0x24)
        e.d32(8, (y2 >> 2) & 0xFFFFFFFF)
        e.d32(4, (x2 >> 2) & 0xFFFFFFFF)
        if e.node is not None:
            e.node.dst = ((x2 >> 2) - 0x18, (y2 >> 2) - 0x18)
        return e.g32(0x18) != 0
    if t < 0xC8:
        if (t & 3) == 3 and e.node is not None:
            e.node.rect = (e.node.rect[0] + 0x30, e.node.rect[1],
                           e.node.rect[2] + 0x30, e.node.rect[3])
        return e.g32(0x18) != 0
    return False


def _beh_416860(self, e) -> bool:
    """`0x416860`（0x27000005 ×57）：匀速左移 + 正弦纵摆 + x≤−0x18 碰撞开 +
    x==0x1D8 && 锁定 → 开火；渐进减速[0x20]+=[0x24]（cmpgate y≥F0）；尾调 0x416440。"""
    e.d32(4, (e.s32(4) + e.s32(0x1C)) & 0xFFFFFFFF)
    vy = 2 if e.s32(8) >= 0xF0 else -2                           # 0x416878 setge/dec/and 2/dec
    vy = -vy if vy == 2 else 2                                    # dec edx → 0 or −1 → and 2 → 0/2 → dec → −1/1
    vy = -vy  # 再反：原版 add [0x24], edx（edx ∈ {−1,1}）
    e.d32(0x24, (e.s32(0x24) + (1 if e.s32(8) >= 0xF0 else -1)) & 0xFFFFFFFF)
    e.d32(0x20, (e.s32(0x20) + e.s32(0x24)) & 0xFFFFFFFF)
    e.d32(8, (e.s32(0x20) >> 3) & 0xFFFFFFFF)
    e.m[0x10] = 1 if e.s32(4) > -0x18 else 0
    if e.s32(4) < -0xF0:                             # 0x4168A1
        e.d32(0x1C, 6)
    if e.s32(0x1C) == 6 and e.s32(4) == 0x1D8 and e.s32(0x28) != 0:
        self.p4_43B070(e, 0)
    if e.node is not None:
        e.node.dst = (e.s32(4) - 0x18, e.s32(8) - 0x18)
    # 0x401F91 → 0x416440 boss spawner 检查（复刻侧由 op2 直接生成，跳过）
    return e.g32(0x18) != 0 and e.s32(4) < 0x298


def _beh_4164B0(self, e) -> bool:
    """`0x4164B0`（0x27000001 ×51）：亚像素直线（[0x1C]+=[0x24];[0x20]+=[0x28]）+8.3/8.2
    定点定屏 + 帧动画 + x<0x133 → 开火；尾调 0x416440。"""
    if e.s32(4) < 0x133:
        cnt = e.s32(0x2C) + 1
        e.d32(0x2C, cnt & 0xFFFFFFFF)
        vy = 2 if cnt > 0x30 else -2                             # 0x4164CB setg/dec/and 2/dec
        vy = -vy  # 修正：and 2 → 0 or 2; dec → −1 or 1
        e.d32(0x24, (e.s32(0x24) + (1 if cnt > 0x30 else -1)) & 0xFFFFFFFF)
        vx = 1 if cnt > 0x18 else -1                             # 0x4164DD setg/dec/and −2/dec
        e.d32(0x28, (e.s32(0x28) + vx) & 0xFFFFFFFF)
    sub_x = e.s32(0x1C)
    sub_y = e.s32(0x20)
    e.d32(0x1C, (sub_x + e.s32(0x24)) & 0xFFFFFFFF)
    e.d32(0x20, (sub_y + e.s32(0x28)) & 0xFFFFFFFF)
    sub_x = e.s32(0x1C)
    sub_y = e.s32(0x20)
    x = (sub_x + 4) >> 3
    y = (sub_y + 2) >> 2
    e.d32(4, x & 0xFFFFFFFF)
    e.d32(8, y & 0xFFFFFFFF)
    if x < 0x133 and e.s32(0x28) == 0:            # 0x41651E 判 vy==0
        self.p4_43B070(e, 0)
    if e.node is not None:
        e.node.dst = (x - 0x18, y - 0x18)
    # 0x401F91 → 0x416440
    return e.g32(0x18) != 0 and e.s32(8) < 0x1F8


def _beh_416B20(self, e) -> bool:
    """`0x416B20`（0x27000008 ×48）：恒速斜移 + x==0x268 → 开火；尾调 0x416440。"""
    e.d32(4, (e.s32(4) + e.s32(0x1C)) & 0xFFFFFFFF)
    if e.s32(4) < 0xA0 and e.s32(0x1C) < 4:
        e.d32(0x1C, (e.s32(0x1C) + 1) & 0xFFFFFFFF)
    e.d32(8, (e.s32(8) + e.s32(0x20)) & 0xFFFFFFFF)
    if e.s32(4) == 0x268 and e.s32(0x24) != 0:
        self.p4_43B070(e, 0)
    if e.node is not None:
        e.node.dst = (e.s32(4) - 0x18, e.s32(8) - 0x18)
    # 0x401F91 → 0x416440 boss spawner 检查
    return e.g32(0x18) != 0 and e.s32(4) < 0x298


def _beh_4118C0(self, e) -> bool:
    """`0x4118C0`（0x2400000D ×36）：三态折返——x==[0x1C] → (8,−24)；[0x20]==8 且
    [0x24] 到 0x19 → (−8,0)+x−0x128；[0x24]==0 → 0x43B070(e,0) 开火；匀速位移。"""
    x = e.s32(4)
    target = e.s32(0x1C)
    if x == target:
        e.d32(0x20, 8)
        e.d32(0x24, -0x18)
    elif e.s32(0x20) == 8:
        cnt = e.s32(0x24) + 1
        e.d32(0x24, cnt & 0xFFFFFFFF)
        if cnt == 0x19:
            e.d32(4, (x - 0x128) & 0xFFFFFFFF)
            e.d32(0x20, -8)
            e.d32(0x1C, (x - 0x128) & 0xFFFFFFFF)
            e.d32(0x24, 0)
        elif cnt == 0:
            self.p4_43B070(e, 0)
    vx, vy = e.s32(0x20), e.s32(0x24)
    e.d32(4, (e.s32(4) + vx) & 0xFFFFFFFF)
    e.d32(8, (e.s32(8) + vy) & 0xFFFFFFFF)
    if e.node is not None:
        e.node.dst = (e.s32(4) - 0x18, e.s32(8) - 0x18)
    return e.s32(4) <= 0x298 and e.g32(0x18) != 0


def _beh_412680(self, e) -> bool:
    """`0x412680`（0x25000005 ×43）：三阶段追踪——t<0xC 弹跳；t==0x14 byte[0x10]=1 +
    0x45AA80 朝自机（8.8）→ [0x1C]/[0x20]；t>0x14 → 追踪加速（速度=min(0x20,0x64−t)，
    [0x28]+=[0x1C]*speed>>8、[0x2C]+=[0x20]*speed>>8 → x=[0x28]>>8、y=[0x2C]>>8）。
    """
    t = (e.s32(0x24) + 1) & 0xFFFFFFFF
    e.d32(0x24, t)
    if t < 0xC:
        if (t & 1) == 1 and e.node is not None:
            e.node.rect = (e.node.rect[0], e.node.rect[1] - 0x30,
                           e.node.rect[2], e.node.rect[3] - 0x30)
    elif t == 0x14:
        e.m[0x10] = 1
        dx = self.p4_player_x() - e.s32(4)              # 0x4126CF [0x56CC90]…0x4126D5 dx=[0x56CC8C]−x
        dy = self.p4_player_y() - e.s32(8)
        inv = page4_45aa80(dx, dy)                      # 0x4126DB/0x4126EB 0x40231F→0x45AA80 倒数
        e.d32(0x1C, ((inv * dx) >> 7) & 0xFFFFFFFF)     # 0x4126E0 imul dx; sar 7 → [0x1C]
        e.d32(0x20, ((inv * dy) >> 7) & 0xFFFFFFFF)     # 0x4126F0 imul dy; sar 7 → [0x20]
    elif t > 0x14:
        speed = max(0x64 - t, 0x20)                 # 0x41270B max(0x64-t,0x20)
        e.d32(0x28, (e.s32(0x28) + e.s32(0x1C) * speed) & 0xFFFFFFFF)
        e.d32(0x2C, (e.s32(0x2C) + e.s32(0x20) * speed) & 0xFFFFFFFF)
        e.d32(8, (e.s32(0x2C) >> 8) & 0xFFFFFFFF)
        e.d32(4, (e.s32(0x28) >> 8) & 0xFFFFFFFF)
        if e.node is not None:
            e.node.dst = ((e.s32(0x28) >> 8) - 0x18, (e.s32(0x2C) >> 8) - 0x18)
    x, y = e.s32(4), e.s32(8)
    on_screen = (-0x18 < x < 0x280 + 0x18 and -0x18 < y < 0x1E0 + 0x18)
    return on_screen and e.g32(0x18) != 0


def _beh_412950(self, e) -> bool:
    """`0x412950`（0x25000007 ×45）：三状态机。
    state=[0x1C]: 0=左移→x≤0x1E0 转 1；1=纵摆+周期 spawn 0x25000005→t≥0x4B0 转 2；
    2=右移→x>0x1E0 转 0。x<−0x30 或 HP=0 → 灭。"""
    st = e.s32(0x1C)
    if st == 0:
        e.d32(4, (e.s32(4) - 3) & 0xFFFFFFFF)
        if e.node is not None:
            nd = e.node
            nd.dst = (nd.dst[0] - 3, nd.dst[1])
        if e.s32(4) <= 0x1E0:
            e.d32(0x1C, 1)
            e.d32(0x24, 0x40)
    elif st == 1:
        t = (e.s32(0x20) + 1) & 0xFFFFFFFF
        e.d32(0x20, t)
        if (t & 0x1F) == 0:                                  # 每 0x20 帧 spawn 子机
            import random as _r
            rx = (_r.randrange(0x7FFFFFFF) % 0xF0) + 0x168   # 0x4129EB/0x4129EC：x
            ry = (_r.randrange(0x7FFFFFFF) % 0x190) + 0x28    # 0x4129E5/0x4129EB：y
            self._p4_ent43c(0x25000005, rx, ry)
        if not (t & 0x3F):                                   # [0x20]&0x3F==0 → 淡入闪光
            self.spawn_flash(e.s32(4), e.s32(8), -0x100)
        vy = 1 if e.s32(8) >= 0xF0 else -1             # 0x412A3E..0x412A48：{−1,+1}
        e.d32(0x24, (e.s32(0x24) + vy) & 0xFFFFFFFF)
        e.d32(8, (e.s32(8) + ((e.s32(0x24) + 8) >> 4)) & 0xFFFFFFFF)  # 0x412A42..0x412A58 累加
        if e.node is not None:
            e.node.dst = (e.s32(4) - 0x30, e.s32(8) - 0x30)
        if t >= 0x4B0:
            e.d32(0x1C, 2)
            e.d32(0x24, 0)
    elif st == 2:
        e.d32(4, (e.s32(4) + 3) & 0xFFFFFFFF)
        if e.node is not None:
            nd = e.node
            nd.dst = (nd.dst[0] + 3, nd.dst[1])
        if e.s32(4) > 0x1E0:
            e.d32(0x1C, 0)
            e.d32(0x24, 0x40)
    return e.g32(0x18) != 0 and e.s32(4) > -0x30


def _beh_4165A0(self, e) -> bool:
    """`0x4165A0`（0x27000002 ×40）：正弦纵摆+渐进右移+y==0x1E0 开火。
    y∈(0x78,0x168) → [0x1C]++（≤0x28）；[0x20]≠0 → [0x20] += ±2（振荡）；
    x += [0x1C]>>3；y += [0x20]；y==0x1E0 && [0x24]≠0 → 开火。"""
    if 0x78 < e.s32(8) < 0x168:                      # 0x4165B1 jge 0x168 排除
        if e.s32(0x1C) < 0x28:                       # 0x4165B3
            e.d32(0x1C, (e.s32(0x1C) + 1) & 0xFFFFFFFF)
    osc = e.s32(0x20)
    if osc != 0:                                     # 0x4165CA：向 0 收敛 1
        d = -1 if osc >= 0 else 1
        e.d32(0x20, (osc + d) & 0xFFFFFFFF)
    e.d32(4, (e.s32(4) + (e.s32(0x1C) >> 3)) & 0xFFFFFFFF)
    e.d32(8, (e.s32(8) + e.s32(0x20)) & 0xFFFFFFFF)
    if e.s32(4) == 0x1E0 and e.s32(0x24) != 0:       # 0x4165EC 判 x
        self.p4_43B070(e, 0)
    if e.node is not None:
        e.node.dst = (e.s32(4) - 0x18, e.s32(8) - 0x18)
    return e.g32(0x18) != 0 and e.s32(4) < 0x298


def _beh_416680(self, e) -> bool:
    """`0x416680`（0x27000003 ×20）：三态纵振荡+右移+x≤−0x18 自灭。
    [0x20]==0 → [0x1C]++ 到 0 → [0x20]=1；[0x20]==−1 → [0x1C]−−钳 −0x40；
    [0x20]>0 → [0x1C]=0x20 时 fire+[0x24]−−、[0x20]=−1；x += ([0x1C]+2)>>2。"""
    osc = e.s32(0x20)
    cnt = e.s32(0x1C)
    if osc == 0:
        cnt = (cnt + 1) & 0xFFFFFFFF
        e.d32(0x1C, cnt)
        if cnt == 0:
            e.d32(0x20, 1)
    elif osc == -1:
        cnt = (cnt - 1) & 0xFFFFFFFF
        cnt_s = cnt - 0x100000000 if cnt & 0x80000000 else cnt
        e.d32(0x1C, cnt)
        if cnt_s < -0x40:
            e.d32(0x1C, 0xFFFFFFC0)
    else:
        if e.s32(0x24) == 0:
            e.d32(0x1C, 0x20)
            e.d32(0x20, 0xFFFFFFFF)
        else:
            osc = (osc + 1) & 0xFFFFFFFF
            e.d32(0x20, osc)
            if (osc & 0x1F) == 0x1F:
                self.p4_43B070(e, 0)
                e.d32(0x24, (e.s32(0x24) - 1) & 0xFFFFFFFF)
    x = e.s32(4) + ((e.s32(0x1C) + 2) >> 2)
    e.d32(4, x & 0xFFFFFFFF)
    if e.node is not None:
        e.node.dst = (x - 0x18, e.s32(8) - 0x18)
    return e.g32(0x18) != 0 and e.s32(4) > -0x18


def _beh_41F610(self, e) -> bool:
    """`0x41F610`（0x29000012 ×44）：纵摆右移 + x > 0x1E0 → y += ±2（sin 门）；
    x < −0x18 或 HP=0 → **生成 0x29000013（关7 boss）并自灭**。"""
    osc = e.s32(0x20)
    if osc != 0 and e.s32(0x1C) > 0x1E0:
        e.d32(0x20, (osc + (-1 if osc >= 0 else 1)) & 0xFFFFFFFF)   # 0x41F627 and 2/dec → ±1
    e.d32(0x1C, (e.s32(0x1C) + abs(osc)) & 0xFFFFFFFF)
    e.d32(8, (e.s32(8) + osc) & 0xFFFFFFFF)
    e.d32(4, (e.s32(4) - 2) & 0xFFFFFFFF)
    if e.node is not None:
        e.node.dst = (e.s32(4) - 0x30, e.s32(8) - 0x30)
    if e.g32(0x18) == 0:                                # HP=0 → 生成 boss 并自灭
        self._p4_ent43c(0x29000013, e.s32(4), e.s32(8))
        return False
    return e.s32(4) > -0x30


def _beh_4123E0(self, e) -> bool:
    """`0x4123E0`（0x25000003 ×32）：三阶段跳跳——t<0x100 下落（[0x20]−− 到 −0x10
    → [0x2C]≠0 时开火）；t∈[0x100,0x118) 弹跳动画（t%4==3 → node 外扩 ±0x30）；
    t≥0x118 → byte[0x10]=1 + [0x20]=0x30（起步速度）；8.8 定点正弦（[0x1C] 角速度、
    [0x24]/[0x28] 累积 → >>2 定屏）；x=[0x24]>>2 < −0x30 出屏或 HP=0 → 灭。"""
    spd = e.s32(0x20)
    t = e.s32(0x1C)
    if spd < 0x100:
        spd = (spd - 1) & 0xFFFFFFFF
        spd_s = spd - 0x100000000 if spd & 0x80000000 else spd
        e.d32(0x20, spd)
        if spd_s == -0x10:
            if e.s32(0x2C) != 0:
                self.p4_43B070(e, 0)
    elif spd < 0x118:
        spd = (spd + 1) & 0xFFFFFFFF
        e.d32(0x20, spd)
        if (spd & 3) == 3 and e.node is not None:
            e.node.rect = (e.node.rect[0] - 0x30, e.node.rect[1],
                           e.node.rect[2] - 0x30, e.node.rect[3])
    else:
        e.m[0x10] = 1
        e.d32(0x20, 0x30)
    ang = e.s32(0x1C)
    c = page4_cos(ang)
    s_ = page4_sin(ang)
    e.d32(0x24, (e.s32(0x24) + ((c * spd + 0x7F) >> 8)) & 0xFFFFFFFF)
    e.d32(0x28, (e.s32(0x28) + ((s_ * spd + 0x7F) >> 8)) & 0xFFFFFFFF)
    e.d32(8, (e.s32(0x28) >> 2) & 0xFFFFFFFF)
    e.d32(4, (e.s32(0x24) >> 2) & 0xFFFFFFFF)
    if e.node is not None:
        e.node.dst = ((e.s32(0x24) >> 2) - 0x18, (e.s32(0x28) >> 2) - 0x18)
    if spd_s if 'spd_s' in dir() else spd <= -0x30:
        return False
    x, y = e.s32(4), e.s32(8)
    on_screen = (-0x18 < x < 0x280 + 0x18 and -0x18 < y < 0x1E0 + 0x18)
    return on_screen and e.g32(0x18) != 0


def _beh_419850(self, e) -> bool:
    """`0x419850`（0x28000006 ×27）：右移 + x < −0x78 → [0x28]=3 加速；node dst 同步；
    0x401BA4(0x40,4,0x30) 特效；x==[0x24] → 0x43B070(e,0) 开火；x≥0x298 或 HP=0 → 灭。"""
    if e.s32(4) < -0x78:
        e.d32(0x28, 3)
    e.d32(4, (e.s32(4) + e.s32(0x28)) & 0xFFFFFFFF)
    e.d32(8, e.s32(0x20) & 0xFFFFFFFF)
    e.m[0x10] = 1 if e.s32(4) > -0x18 else 0
    self.p4_4193e0(e, 0x40,4,0x30)
    if e.s32(0x24) != 0 and e.s32(0x24) == e.s32(4):
        self.p4_43B070(e, 0)
    if e.node is not None:
        e.node.dst = (e.s32(4) - 0x18, e.s32(8) - 0x18)
    return e.g32(0x18) != 0 and e.s32(4) < 0x298


def _beh_4116C0(self, e) -> bool:
    """`0x4116C0`（0x2400000B ×22）：左移 −2 + 正弦开火（x∈[0x60,0x208] 时
    每 [0x1C]*180 角度帧调 0x40165E 开火，[0x1C]++）；x < −0x18 或 HP=0 → 灭。"""
    x = e.s32(4)
    if (0x60 <= x < 0x208 and (x & 3) == 0) or (0x180 <= x < 0x208 and (x & 7) == 0):
        ang = e.s32(0x1C) * 180                          # [0x1C]*180 → sin/cos 角
        s_ = page4_sin(ang)
        c = page4_cos(ang)
        # 0x40165E(esi, sin, cos) = 0x415650：朝向开火
        self.p4_43B070(e, 0)
        e.d32(0x1C, (e.s32(0x1C) + 1) & 0xFFFFFFFF)
    e.d32(4, (x - 2) & 0xFFFFFFFF)
    if e.node is not None:
        nd = e.node
        nd.dst = (nd.dst[0] - 2, nd.dst[1])
    return e.s32(4) > -0x18 and e.g32(0x18) != 0


def _beh_415D70(self, e) -> bool:
    """`0x415D70`（0x26000016 ×22）：渐进左移 [0x20]−−→x+=[0x20]>>3 + [0x1C] 奇偶
    闪烁（node active 翻转）；[0x20]==−0x20 → 记录自机位置到 [0x24]/[0x28]；
    t%8==0 && 自机在 ±0x20 内 → 0x401E56(=0x415650 朝向开火)；x<−0x18 或 HP=0 → 灭。"""
    spd = (e.s32(0x20) - 1) & 0xFFFFFFFF
    spd_s = spd - 0x100000000 if spd & 0x80000000 else spd
    e.d32(0x20, spd)
    e.d32(4, (e.s32(4) + (spd_s >> 3)) & 0xFFFFFFFF)
    if e.node is not None:
        e.node.dst = (e.s32(4) - 0x18, e.s32(8) - 0x18)
    # 0x415DAA..0x415DC8：vis 是 0x414010 的触发条件（不改 node.active）
    t = e.s32(0x1C)
    if spd_s > 0:
        call010 = (t & 1) == 0
    else:
        call010 = (t & 3) == 0
    if call010:
        self.p4_414010(e)
    if spd_s == 0x20:                                    # 0x415DD0 lea edx,[eax-0x20]
        e.d32(0x24, self.p4_player_x())
        e.d32(0x28, self.p4_player_y())
    elif (t & 7) == 0:                                   # 0x415DEA
        if (abs(spd_s) & 0xFFE0) == 0:                   # |[0x20]|<0x20
            self.p4_43B360(e, e.s32(0x24), e.s32(0x28), 0)
    return e.s32(4) > -0x18 and e.g32(0x18) != 0


P4_4170E4_STATES = (0, 3, 3, 3, 3, 3, 3, 3, 1, 3, 3, 3, 3, 3, 3, 3,
                    1, 3, 3, 3, 3, 3, 3, 3, 2)           # byte[0x4170E4+t]，t=0..0x18


def _beh_416FA0(self, e) -> bool:
    """`0x416FA0`（0x2700000B ×14）：t=byte[0x4170E4+t] 跳表（0x4170D4）：
    态0（t=0）= 计数 [0x2C]++，<16 时 [0x20]=0x45A9A0(dy,dx) 角度、否则 [0x20]=0；
    态1（t=8/16）= node 外扩 +0x30；态2（t=0x18）= node 收 −0x60 + 0x43B070(e,0) 开火；
    态3 = 无操作。公共尾：[0x1C]++，t>0x18 → [0x24]+=(cos([0x20])*3)>>4、
    [0x28]+=(sin([0x20])*3)>>4（**4.4 定点**：[+4]=[0x24]>>4、[+8]=[0x28]>>4），
    t==0x48 → [0x1C]=0 循环。存亡：HP=0 灭；( [0x2C]&0xFFF0!=0 且 x>0x298 ) 灭。"""
    t = e.s32(0x1C)
    if t <= 0x18:                                    # 0x416FA6 ja（无符号）
        st = P4_4170E4_STATES[t] if t < len(P4_4170E4_STATES) else 3
        if st == 0:                                  # 0x416FBE
            cnt = (e.s32(0x2C) + 1) & 0xFFFFFFFF     # 0x416FC1
            e.d32(0x2C, cnt)
            if cnt & 0xFFF0:                         # 0x416FC7 test 0xFFF0
                e.d32(0x20, 0)                       # 0x416FD0
            else:
                dx = self.p4_player_x() - e.s32(4)   # 0x416FD5 [0x56CC8C]−x
                dy = self.p4_player_y() - e.s32(8)   # [0x56CC90]−y
                e.d32(0x20, page4_45a9a0(dy, dx) & 0xFFFFFFFF)   # 0x416FEC 0x401091→0x45A9A0
        elif st == 1:                                # 0x416FF9
            if e.node is not None:
                e.node.grow(0x30, 0, 0x30, 0)        # 0x401A0A(node+4, 0x30,0,0x30,0)
        elif st == 2:                                # 0x417012
            if e.node is not None:
                e.node.grow(-0x60, 0, -0x60, 0)      # 0x401A0A(node+4, -0x60,0,-0x60,0)
            self.p4_43B070(e, 0)                     # 0x41702D 0x40213F→0x43B070
    t = (t + 1) & 0xFFFFFFFF                         # 0x417035
    e.d32(0x1C, t)
    if t > 0x18:                                     # 0x41703B jle（有符号）
        ang = e.s32(0x20)
        e.d32(0x24, (e.s32(0x24) + ((page4_cos(ang) * 3) >> 4)) & 0xFFFFFFFF)  # 0x417044 cos
        e.d32(0x28, (e.s32(0x28) + ((page4_sin(ang) * 3) >> 4)) & 0xFFFFFFFF)  # 0x41705B sin
        e.d32(8, (e.s32(0x28) >> 4) & 0xFFFFFFFF)    # 0x417079 [0x8]=[0x28]>>4
        e.d32(4, (e.s32(0x24) >> 4) & 0xFFFFFFFF)    # 0x417082 [0x4]=[0x24]>>4
        if t == 0x48:                                # 0x417085 jne
            e.d32(0x1C, 0)                           # 0x41708A 循环复位
    if e.node is not None:                           # 0x417091
        e.node.dst = (e.s32(4) - 0x18, e.s32(8) - 0x18)
    if e.g32(0x18) == 0:                             # 0x4170B0
        return False
    if (e.s32(0x2C) & 0xFFF0) and e.s32(4) > 0x298:  # 0x4170B7 test / 0x4170C0 jg
        return False
    return True


def _beh_411AD0(self, e) -> bool:
    """`0x411AD0`（0x24000010 ×14）：**追踪自机 + 0x500 后逃逸**（8.4 累加器）。

    t=++[0x1C]；(t&0x7F)==0 → 0x43B150(e,0)。
    t<0x500：
      x<自机x → [0x28] += ([0x28]<0 ? 2 : 1)；否则 += ([0x28]>=0 ? −4 : −1)
      y<自机y → [0x2C] += ([0x2C]<0 ? 2 : 1)；否则 += ([0x2C]<0 ? −1 : −2)
    t>=0x500：[0x28]−=1；[0x2C] += ([0x2C]>=0 ? −1 : +1)
    [0x20]+=[0x28]、[0x24]+=[0x2C]；x=[0x20]>>4、y=[0x24]>>4；
    dst=(x−0x18,y−0x18)；存活=HP && (t<0x500 || x>−0x18)。
    """
    t = (e.s32(0x1C) + 1) & 0xFFFFFFFF
    e.d32(0x1C, t)
    if (t & 0x7F) == 0:                                # 0x411ADC
        self.p4_43B150(e, 0)                           # 0x401D6B
    vx, vy = e.s32(0x28), e.s32(0x2C)
    if t < 0x500:                                      # 0x411AE7
        if e.s32(0x04) < self.p4_stat.get(0x56CC8C, 0):
            vx += 2 if vx < 0 else 1                   # 0x411B00..0x411B08
        else:
            vx += -4 if vx >= 0 else -1                # 0x411B0F..0x411B1F
        if e.s32(0x08) < self.p4_stat.get(0x56CC90, 0):
            vy += 2 if vy < 0 else 1                   # 0x411B32..0x411B39
        else:
            vy += -1 if vy < 0 else -2                 # 0x411B3C..0x411B46
    else:                                              # 0x411B4D
        vx -= 1
        vy += -1 if vy >= 0 else 1                     # 0x411B59..0x411B62
    e.d32(0x28, vx & 0xFFFFFFFF)
    e.d32(0x2C, vy & 0xFFFFFFFF)
    a20 = (e.s32(0x20) + e.s32(0x28)) & 0xFFFFFFFF
    a24 = (e.s32(0x24) + e.s32(0x2C)) & 0xFFFFFFFF
    e.d32(0x20, a20)
    e.d32(0x24, a24)
    x = (a20 - 0x100000000 if a20 & 0x80000000 else a20) >> 4
    y = (a24 - 0x100000000 if a24 & 0x80000000 else a24) >> 4
    e.d32(0x04, x & 0xFFFFFFFF)
    e.d32(0x08, y & 0xFFFFFFFF)
    if e.node is not None:
        e.node.dst = (x - 0x18, y - 0x18)
    return e.g32(0x18) != 0 and (t < 0x500 or x > -0x18)


def _beh_4115B0(self, e) -> bool:
    """`0x4115B0`（0x2400000A ×14）：右移 [0x20]（rec1<<3 变化）+ 周期事件：
    t==0x64 → 0x31000005 敌弹入 0x4AD49C；t∈{0xA0,0xDC,0x118} → 0x43B070(e,−[0x58])
    + 0x401D6B 波动；t>0x154 → [0x20]++；x≥0x298 或 HP=0 → 灭。"""
    t = (e.s32(0x1C) + 1) & 0xFFFFFFFF
    e.d32(0x1C, t)
    if t == 0x64:
        self.spawn(self._p4_q("ui49c"), 0x31000005, e.s32(4), e.s32(8), 0)
    elif t in (0xA0, 0xDC, 0x118):
        if e.s32(0x24) != 0:
            self.p4_43B070(e, (-e.s32(0x58)) & 0xFFFFFFFF)
    elif t > 0x154:
        e.d32(0x20, (e.s32(0x20) + 1) & 0xFFFFFFFF)
    e.d32(4, (e.s32(4) + e.s32(0x20)) & 0xFFFFFFFF)
    if e.node is not None:
        nd = e.node
        nd.dst = (nd.dst[0] + e.s32(0x20), nd.dst[1])
    return e.s32(4) <= 0x298 and e.g32(0x18) != 0


def _beh_412510(self, e) -> bool:
    """`0x412510`（0x25000004 ×19）：负帧等待 → 弹跳 → 0x18 亮碰撞 → 0x28 八向弹 →
    0x29.. 反向弹跳 → 0x40 计数/隐藏，>5 自灭。

    t=++[0x1C]；t<0 → 只返回 HP。t<0x18：node.active=1，(t&3)==3 → rect.y −=0x30。
    t==0x18：[0x10]=1。t==0x28：对 (dx,dy)∈{−2,0,2}² 去掉 (0,0) 调 0x43B290(e,dx,dy,0)。
    t>0x28：(t&3)==3 → rect.y +=0x30；t==0x40 → [0x10]=0、[0x1C]=−0x10、[0x20]++，
    >5 → 自灭，否则 node.active=0。所有分支返回 (HP!=0)。
    """
    t = (e.s32(0x1C) + 1) & 0xFFFFFFFF
    t_s = t - 0x100000000 if t & 0x80000000 else t
    e.d32(0x1C, t)
    if t_s < 0:
        return e.g32(0x18) != 0
    if t_s < 0x18:                                 # 0x41251D
        if e.node is not None:
            e.node.active = 1
        if (t & 3) == 3 and e.node is not None:    # 0x412538
            e.node.rect = (e.node.rect[0], e.node.rect[1] - 0x30,
                           e.node.rect[2], e.node.rect[3] - 0x30)
        return e.g32(0x18) != 0
    if t_s == 0x18:                                # 0x41255C
        e.m[0x10] = 1
        return e.g32(0x18) != 0
    if t_s == 0x28:                                # 0x412572
        for dy in (-2, 0, 2):
            for dx in (-2, 0, 2):
                if dx == 0 and dy == 0:
                    continue
                self.p4_43B290(e, dx, dy, 0)       # 0x40165E
        return e.g32(0x18) != 0
    if t_s > 0x28:                                 # 0x4125CE
        if (t & 3) == 3 and e.node is not None:
            e.node.rect = (e.node.rect[0], e.node.rect[1] + 0x30,
                           e.node.rect[2], e.node.rect[3] + 0x30)
        if t_s == 0x40:                            # 0x4125EE
            cnt = e.s32(0x20) + 1
            e.m[0x10] = 0
            e.d32(0x1C, 0xFFFFFFF0)
            e.d32(0x20, cnt)
            if cnt > 5:
                return False
            if e.node is not None:
                e.node.active = 0
    return e.g32(0x18) != 0


def _beh_419EC0(self, e) -> bool:
    """`0x419EC0`（0x2800000C ×16）：纵摆右移（x += rec3、y += ±2 based on rec3>0）
    + 0x401BA4(0x10,1,0x30) 特效 + [0x24]>0 && [0x28]>0 && t%8==0 → 开火+衰减。
    """
    x, y = e.s32(4), e.s32(8)
    osc = e.s32(0x28)
    e.d32(0x20, (e.s32(0x20) + e.s32(0x24)) & 0xFFFFFFFF)
    e.d32(0x24, (e.s32(0x24) + (1 if osc != 0 else -1)) & 0xFFFFFFFF)   # 0x419ED4
    e.d32(4, ((e.s32(0x20)) >> 4) & 0xFFFFFFFF)
    e.d32(8, e.s32(0x2C) & 0xFFFFFFFF)                                  # 0x419EE4 y=[0x2C]
    self.p4_4193e0(e, 0x10,1,0x30)
    if e.s32(0x24) > 0 and osc != 0 and (e.s32(0x24) & 7) == 0:         # 0x419EFA 门用 [0x24]&7
        self.p4_43B070(e, 0)
        e.d32(0x28, (osc - 1) & 0xFFFFFFFF)
    if e.node is not None:
        e.node.dst = (e.s32(4) - 0x18, e.s32(8) - 0x18)
    return e.g32(0x18) != 0 and e.s32(4) > -0x18


def _beh_41A090(self, e) -> bool:
    """`0x41A090`（0x2800000E ×18）：右移+纵摆+node 显示门+x>0x140 → 开火；
    0x401BA4(0x18,1,0x30) 特效；[0x20] < −0x1E0 时 [0x20]=4 加速回屏；
    y≥F0 门同前。"""
    e.d32(4, (e.s32(4) + e.s32(0x20)) & 0xFFFFFFFF)
    vy = -1 if e.s32(8) >= 0xF0 else 1                 # 0x41A09D
    e.d32(0x28, (e.s32(0x28) + vy) & 0xFFFFFFFF)
    e.d32(0x24, (e.s32(0x24) + e.s32(0x28)) & 0xFFFFFFFF)   # 0x41A0B5 累加
    e.d32(8, ((e.s32(0x24)) >> 3) & 0xFFFFFFFF)        # 0x41A0C2 y=[0x24]>>3
    e.m[0x10] = 1 if e.s32(4) > -0x18 else 0
    if e.s32(4) < -0x140:                              # 0x41A0CE
        e.d32(0x20, 4)
    self.p4_4193e0(e, 0x18,1,0x30)
    if e.s32(0x28) == 0 and e.s32(0x20) > 0 and e.s32(4) > 0x140 and e.s32(0x2C) != 0:
        self.p4_43B070(e, 0)
    if e.node is not None:
        e.node.dst = (e.s32(4) - 0x18, e.s32(8) - 0x18)
    return e.g32(0x18) != 0 and e.s32(4) < 0x298


def _beh_416BE0(self, e) -> bool:
    """`0x416BE0`（0x27000009）：三态纵振荡。

    [0x20]==0：t=++[0x1C]；t==0 → [0x20]=1；x += (t+1)>>1；
      y += (y<0xF0 ? (−1−t)>>1 : (t+1)>>1)。
    [0x20]==−1：x −= [0x1C]>>2；[0x1C]++。
    other：[0x24]==0 → [0x20]=−1；否则 [0x20]++，`(v&0x2F)==0x2F && v>0x5A`
      → [0x24]−− + 0x43B070。尾 0x416440；存活 HP && x>−0x18。
    """
    osc = e.s32(0x20)
    if osc == 0:
        t = (e.s32(0x1C) + 1) & 0xFFFFFFFF
        e.d32(0x1C, t)
        if t == 0:
            e.d32(0x20, 1)
        x = (e.s32(0x04) + ((t + 1) >> 1)) & 0xFFFFFFFF
        e.d32(0x04, x)
        y = e.s32(0x08)
        dy = (((-1) - t) >> 1) if y < 0xF0 else ((t + 1) >> 1)
        e.d32(0x08, (y + dy) & 0xFFFFFFFF)
    elif osc == -1:
        t = e.s32(0x1C)
        e.d32(0x04, (e.s32(0x04) - (t >> 2)) & 0xFFFFFFFF)
        e.d32(0x1C, (t + 1) & 0xFFFFFFFF)
    else:
        if e.s32(0x24) == 0:
            e.d32(0x20, 0xFFFFFFFF)
        else:
            v = (osc + 1) & 0xFFFFFFFF
            e.d32(0x20, v)
            if (v & 0x2F) == 0x2F and v > 0x5A:
                e.d32(0x24, (e.s32(0x24) - 1) & 0xFFFFFFFF)
                self.p4_43B070(e, 0)
    if e.node is not None:
        e.node.dst = (e.s32(0x04) - 0x18, e.s32(0x08) - 0x18)
    self.p4_416440(e)
    return e.g32(0x18) != 0 and e.s32(0x04) > -0x18


def _p4_41e1f0(e) -> None:
    """`0x41E1F0`（漂移步进，0x4018E8）：[4]+=[2C]、[8]+=[30]；`0x45A6B0([0x38]+0x14,
    dx, dy)` 给显示节点 dst 同帧加同量（0x45A6B0 就是 `[ptr]+=a; [ptr+4]+=b`）；
    [0x28] 帧计数 ++。"""
    dx = e.s32(0x2C)
    dy = e.s32(0x30)
    e.d32(0x04, (e.s32(0x04) + dx) & 0xFFFFFFFF)
    e.d32(0x08, (e.s32(0x08) + dy) & 0xFFFFFFFF)
    if e.node is not None:
        e.node.dst = (e.node.dst[0] + dx, e.node.dst[1] + dy)
    e.d32(0x28, (e.s32(0x28) + 1) & 0xFFFFFFFF)


def _p4_41e240(self, e) -> None:
    """`0x41E240`（0x41E7B0 相位 1，0x4011B8）：
    t==0 → [0x30] = (相位==1 ? 6 : −6)（dec/neg/sbb 读 [0x1C]−1 的 CF）；
    0x10≤t<0x16 → [0x30] ∓= 1（相位==1 减、否则加）；
    t==0xC8 → 0x43B070(e,0) 朝机开火；
    0xE6≤t<0xF0 → [0x2C] += (x≥0x140 ? −1 : +1)（横向折返步进）；
    x < −0x18 或 > 0x298 → HP=0；每路结尾 0x41E1F0 漂移。"""
    t = e.s32(0x28)
    if t == 0:
        e.d32(0x30, 6 if e.s32(0x1C) == 1 else -6)
        _p4_41e1f0(e)
        return
    if 0x10 <= t < 0x16:
        v = e.s32(0x30)
        e.d32(0x30, (v - 1) & 0xFFFFFFFF if e.s32(0x1C) == 1 else (v + 1) & 0xFFFFFFFF)
    elif t == 0xC8:
        self.p4_43B070(e, 0)
    elif 0xE6 <= t < 0xF0:
        e.d32(0x2C, (e.s32(0x2C) + (-1 if e.s32(0x04) >= 0x140 else 1)) & 0xFFFFFFFF)
    elif e.s32(0x04) < -0x18 or e.s32(0x04) > 0x298:
        e.d32(0x18, 0)
    _p4_41e1f0(e)


def _p4_41e330(self, e) -> None:
    """`0x41E330`（0x41E7B0 相位 2，0x401357）：
    0x62≤t≤0xDA → t++，t==0xBC 时 0x43B070(e,0) 开火一次；其余帧走移动分支：
    x<0xA0：y<0xF0 时 [0x30]++ 否则 [0x30]−−（到 0）；[0x30] 为奇时 [0x2C]++
    （悬停充能 → 横漂加速）；x≥0xA0：[0x30]=0，[0x2C] = (y≥0xF0 ? +11 : −11)
    （纵向朝中线）；[0x2C]>0 且 x>0x298 → HP=0；结尾 0x41E1F0。"""
    t = e.s32(0x28)
    if 0x62 <= t <= 0xDA:
        e.d32(0x28, (t + 1) & 0xFFFFFFFF)
        if t == 0xBC:
            self.p4_43B070(e, 0)
        return
    x = e.s32(0x04)
    if x < 0xA0:
        if e.s32(0x08) < 0xF0:
            e.d32(0x30, (e.s32(0x30) + 1) & 0xFFFFFFFF)
        elif e.s32(0x30) != 0:
            e.d32(0x30, (e.s32(0x30) - 1) & 0xFFFFFFFF)
        if e.s32(0x30) & 1:
            e.d32(0x2C, (e.s32(0x2C) + 1) & 0xFFFFFFFF)
    else:
        e.d32(0x30, 0)
        e.d32(0x2C, 11 if e.s32(0x08) >= 0xF0 else (-11 & 0xFFFFFFFF))
    if e.s32(0x2C) > 0 and x > 0x298:
        e.d32(0x18, 0)
    _p4_41e1f0(e)


def _p4_41e400(self, e) -> None:
    """`0x41E400`（0x41E7B0 相位 3，0x40202C）：s = [0x20]+t；
    s==0 → [0x2C]=−10；0x15≤s<0x1F → [0x2C]++；0xF0≤s<0xFF → [0x2C]−−；
    t==0xD2 → `0x43B610(e, x+自机x−0x21C, y+自机y−0xF0, 0x500)`
    （0x401997→0x43B610，弹型 0x43B5E0：0x25→0x31000008 / 否则 0x31000003）；
    x<−0x18 → HP=0；结尾 0x41E1F0。"""
    t = e.s32(0x28)
    s = (e.s32(0x20) + t) & 0xFFFFFFFF
    s_s = s - 0x100000000 if s & 0x80000000 else s
    if s == 0:
        e.d32(0x2C, -10 & 0xFFFFFFFF)
    elif 0x15 <= s_s < 0x1F:
        e.d32(0x2C, (e.s32(0x2C) + 1) & 0xFFFFFFFF)
    elif 0xF0 <= s_s < 0xFF:
        e.d32(0x2C, (e.s32(0x2C) - 1) & 0xFFFFFFFF)
    if t == 0xD2:
        self.p4_43B610(e, e.s32(0x04) + self.p4_player_x() - 0x21C,
                       e.s32(0x08) + self.p4_player_y() - 0xF0, 0x500)
    if e.s32(0x04) < -0x18:
        e.d32(0x18, 0)
    _p4_41e1f0(e)


def _p4_41e4c0(self, e) -> None:
    """`0x41E4C0`（0x41E7B0 相位 4，0x401D25）：s = [0x20]+t；
    s==0 → [0x2C] = (x≥0x140 ? −6 : −18)；
    0x1D≤s<0x23 → [0x2C] += (x≥0x140 ? −1 : +1)；
    0xFA≤s<0x104 → [0x2C] += (x≥0x140 ? −1 : +1)（同向第二步进）；
    t==0xF0 → 0x43B070(e,0)；t>0x118 且 x<−0x18 或 >0x298 → HP=0；结尾 0x41E1F0。"""
    t = e.s32(0x28)
    s = (e.s32(0x20) + t) & 0xFFFFFFFF
    s_s = s - 0x100000000 if s & 0x80000000 else s
    xge = e.s32(0x04) >= 0x140
    if s == 0:
        e.d32(0x2C, -6 if xge else -18)
    elif 0x1D <= s_s < 0x23:
        e.d32(0x2C, (e.s32(0x2C) + (-1 if xge else 1)) & 0xFFFFFFFF)
    elif 0xFA <= s_s < 0x104:
        e.d32(0x2C, (e.s32(0x2C) + (-1 if xge else 1)) & 0xFFFFFFFF)
    if t == 0xF0:
        self.p4_43B070(e, 0)
    if t > 0x118 and (e.s32(0x04) < -0x18 or e.s32(0x04) > 0x298):
        e.d32(0x18, 0)
    _p4_41e1f0(e)


def _p4_41e5a0(self, e) -> None:
    """`0x41E5A0`（0x41E7B0 相位 5，0x4018E3）：t∈[0x78,0xD2] → 仅 t++（悬停门）；
    否则按状态 [0x20]：0 → [0x30]=0xC，y>0xF0 → 状态 1；
    1 → 0x50≤y≤0x190 且 t>0x12C 且 [0x30]>0 → 状态 2，否则
        [0x2C] += (x≥0x188 ? −4 : +4)、[0x30] += (y≥0xF0 ? −2 : +2)；
    2 → y>0x1F8 → HP=0；
    尾部：0xD2≤t<0xE8 且 t 奇 → `0x43B360(e, 2x−0x188, 2y−0xF0, 0)`
    （0x401E56→0x43B360，弹型 0x43B020；镜点两侧交替开火）；漂移只在悬停门外执行。"""
    t = e.s32(0x28)
    if 0x78 <= t <= 0xD2:
        e.d32(0x28, (t + 1) & 0xFFFFFFFF)
    else:
        st = e.s32(0x20)
        if st == 0:
            e.d32(0x30, 0xC)
            if e.s32(0x08) > 0xF0:
                e.d32(0x20, 1)
        elif st == 1:
            y = e.s32(0x08)
            if 0x50 <= y <= 0x190 and t > 0x12C and e.s32(0x30) > 0:
                e.d32(0x20, 2)
            else:
                e.d32(0x2C, (e.s32(0x2C) + (-4 if e.s32(0x04) >= 0x188 else 4)) & 0xFFFFFFFF)
                e.d32(0x30, (e.s32(0x30) + (-2 if y >= 0xF0 else 2)) & 0xFFFFFFFF)
        else:                                   # st == 2
            if e.s32(0x08) > 0x1F8:
                e.d32(0x18, 0)
        _p4_41e1f0(e)
    t = e.s32(0x28)
    if 0xD2 <= t < 0xE8 and t != 0 and (t & 1):
        self.p4_43B360(e, 2 * e.s32(0x04) - 0x188, 2 * e.s32(0x08) - 0xF0, 0)


def _p4_41e6e0(self, e) -> None:
    """`0x41E6E0`（0x41E7B0 相位 6，0x401C53）：t==0 → [0x2C]=−8、[0x20]=(y≥0xF0)、
    [0x30] = (y≥0xF0 ? −6 : +6)；0x50≤t<0x52 → [0x2C]+=4、[0x30] += ([0x20] ? +3 : −3)；
    t==0xE6 → 0x43B070(e,0)；0x104≤t<0x10E → [0x30] += ([0x20] ? +1 : −1)；
    x<−0x18 → HP=0；结尾 0x41E1F0。"""
    t = e.s32(0x28)
    if t == 0:
        e.d32(0x2C, -8 & 0xFFFFFFFF)
        yg = e.s32(0x08) >= 0xF0
        e.d32(0x20, 1 if yg else 0)
        e.d32(0x30, -6 if yg else 6)
    elif 0x50 <= t < 0x52:
        e.d32(0x2C, (e.s32(0x2C) + 4) & 0xFFFFFFFF)
        e.d32(0x30, (e.s32(0x30) + (3 if e.s32(0x20) else -3)) & 0xFFFFFFFF)
    elif t == 0xE6:
        self.p4_43B070(e, 0)
    elif 0x104 <= t < 0x10E:
        e.d32(0x30, (e.s32(0x30) + (1 if e.s32(0x20) else -1)) & 0xFFFFFFFF)
    if e.s32(0x04) < -0x18:
        e.d32(0x18, 0)
    _p4_41e1f0(e)


def _beh_41E7B0(self, e) -> bool:
    """`0x41E7B0`（thunk 0x4018A7；0x29000007/08/09/0A/0B/16 ×20，ctor case
    0x41C16E/0x41C55D）：**护卫/中boss 相位状态机**。

    ```
    if ([+0x24] != 0) {                       ; 跟踪体（param block[2]）
        相位 [+0x1C] 1..6 → 0x41E240/330/400/4C0/5A0/6E0
        跟踪体已死（[+0x34]）→
            跟踪体类型 == 0x29000015（最终boss）
              → 0x430400(&rec, x, y, 0x61000004, 0x10) + 0x445AA0(0x4AD52C,&rec)
                （52C 亮度族条目）并 return 0（自灭）
            否则 [+0x24]=0；速度 = 8×单位向自机向量
              （0x45AA80(dx,dy)*dx>>9 / *dy>>9；两分量全 0 → [0x2C]=−1）
    } else {
        0x41E1F0 漂移；0x4305F0(e, 0x18)（半径 0x18 在屏判据，0x4021E9）
        不在屏 → return 0
    }
    return HP([+0x18]) != 0
    ```
    复刻侧 [+0x24] 存跟踪体句柄（id&0x7FFFFFFF，p4_links 解对象），
    与 0x23 亲子链接同一约定。
    """
    h = e.g32(0x24)
    if h:
        linked = getattr(self, "p4_links", {}).get(h)
        ph = e.s32(0x1C)
        {1: _p4_41e240, 2: _p4_41e330, 3: _p4_41e400,
         4: _p4_41e4c0, 5: _p4_41e5a0, 6: _p4_41e6e0}.get(ph, lambda s, x: None)(self, e)
        if linked is None or linked.m[0x34] == 0:
            if linked is not None and linked.s32(0x14) == 0x29000015:
                self.p4_spawn52c_flash(e.s32(0x04), e.s32(0x08), 0x61000004, 0x10)
                return False
            e.d32(0x24, 0)
            dx = self.p4_player_x() - e.s32(0x04)
            dy = self.p4_player_y() - e.s32(0x08)
            inv = self.p4_45aa80(dx, dy)
            vx = (inv * dx) >> 9                    # 0x41E885 sar 9
            vy = (inv * dy) >> 9
            e.d32(0x2C, vx & 0xFFFFFFFF)
            e.d32(0x30, vy & 0xFFFFFFFF)
            if vx == 0 and vy == 0:
                e.d32(0x2C, -1 & 0xFFFFFFFF)
        return e.g32(0x18) != 0
    _p4_41e1f0(e)
    if not self.p4_4305f0(e, 0x18):                 # 0x4021E9 → 0x4305F0
        return False
    return e.g32(0x18) != 0


def _beh_417940(self, e) -> bool:
    """`0x417940`（thunk `0x4016F9`，0x27000010 帧表 boss 变体 A）。

    入口 0x41794C `[0x30]&1` → 位置镜像 (0x280−x, 0x1E0−y)；
    t = ++[0x1C] 后按帧表分派（表：(t−0x0A) 索引 0x417CB8 / 目标 0x417CA0，
    以及 (t−0x2A8) 索引 0x417D38 / 目标 0x417D20）：
    ```
    0x00A → pos=(0x21C,−0x64); byte[0x10]=1; [0x24]=6
    0x025 → [0x2C]=−1                       0x02B → [0x28]=−1,[0x2C]=0
    0x03A → [0x28]=0                        0x06E → [0x20]=[0x24]=0
    0x110 → 0x4177F0(0x50,0x18)             0x14C → pos=(−0x60,0x50),[0x20]=0xC
    0x190 → 0x4177F0(0x168,0x268)           0x19C → [0x20]=0
    0x208 → pos=(0x2E4,0),[0x20]=−0xC,[0x24]=0x20,[0x2C]=−1
    0x24E → [0x20]=[0x24]=[0x2C]=0 且 0x4177F0(0x30,0x50)
    0x28A → pos=(0x50,−0x60),[0x24]=0x1C,[0x2C]=−1
    0x2A8 → 0x4177F0(0x30,0x190)            0x2D5 → [0x24]=0,[0x2C]=0
    0x2E4 → pos=(0x190,−0x60),[0x24]=0x1C,[0x2C]=−1
    0x32F → [0x24]=[0x2C]=0 且 0x4177F0(0x5A,0x268)
    0x36B → pos=(0x2E4,0x5A),[0x20]=0,[0x28]=−1
    0x377 → [0x28]=0                        0x3B6 → [0x20]=0
    0x3F2 → 0x4177F0(0x30,0x18)
    0x42E → pos=(−0x64,−0x64)，速度=12×单位向量(自机+0x64)
    0x492 → [0x20]=[0x24]=0
    0x5CD → [0x1C]=0；[0x30]++ ≥6 → return 0（帧表回卷）
    ```
    公共尾（0x417BDC）：[0x24]+=[0x2C]、[0x20]+=[0x28]、x+=[0x20]、y+=[0x24]、
    `0x417880(e,0)` 门控发 0x2700000B 入 0x4AD43C、[0x30]&1 尾镜像、
    node.dst=(x−0x60,y−0x60)；存活 = [0x18]!=0（否则 0x61000004@(x,y,prm=0x48) 入 0x52C）。
    """
    if e.s32(0x30) & 1:                                    # 0x41794C test cl,1
        e.d32(0x04, (0x280 - e.s32(0x04)) & 0xFFFFFFFF)     # 0x417951..0x417960
        e.d32(0x08, (0x1E0 - e.s32(0x08)) & 0xFFFFFFFF)     # 0x417963..0x417968
    t = (e.s32(0x1C) + 1) & 0xFFFFFFFF                      # 0x41796B inc / 0x417973
    e.d32(0x1C, t)

    # ---- 帧表分派（原始顺序：先比 0x28A/0x377/0x42E/0x5CD，其余落跳表） ----
    if t == 0x0A:                                           # 0x4179AB（表1 idx 0x00）
        e.d32(0x04, 0x21C); e.d32(0x08, -0x64 & 0xFFFFFFFF)
        e.m[0x10] = 1                                       # 0x4179B9 byte[esi+0x10]=1
        e.d32(0x24, 6)
    elif t == 0x25:                                         # 0x417AEE（表1 idx 0x1B）
        e.d32(0x2C, -1 & 0xFFFFFFFF)
    elif t == 0x2B:                                         # 0x4179C9（表1 idx 0x21）
        e.d32(0x28, -1 & 0xFFFFFFFF); e.d32(0x2C, 0)
    elif t == 0x3A:                                         # 0x417B30（表1 idx 0x30）
        e.d32(0x28, 0)
    elif t == 0x6E:                                         # 0x417BD6（表1 idx 0x64）
        e.d32(0x20, 0); e.d32(0x24, 0)
    elif t == 0x110:                                        # 0x4179D8
        self.p4_4177f0(e, 0x50, 0x18)
    elif t == 0x14C:                                        # 0x417A1B
        e.d32(0x04, -0x60 & 0xFFFFFFFF); e.d32(0x08, 0x50)
        e.d32(0x20, 0xC)
    elif t == 0x190:                                        # 0x417A05
        self.p4_4177f0(e, 0x168, 0x268)
    elif t == 0x19C:                                        # 0x417B5E（je 链共用）
        e.d32(0x20, 0)
    elif t == 0x208:                                        # 0x417A5E
        e.d32(0x04, 0x2E4); e.d32(0x08, 0)
        e.d32(0x20, -0xC & 0xFFFFFFFF); e.d32(0x24, 0x20); e.d32(0x2C, -1 & 0xFFFFFFFF)
    elif t == 0x24E:                                        # 0x417A45（先 push 实参，再清字段）
        e.d32(0x20, 0); e.d32(0x24, 0); e.d32(0x2C, 0)      # 0x417A4B..0x417A51
        self.p4_4177f0(e, 0x30, 0x50)                       # 0x417A54
    elif t == 0x28A:                                        # 0x417A82 → 贯落 0x417AE0
        e.d32(0x04, 0x50); e.d32(0x08, -0x60 & 0xFFFFFFFF)  # 0x417A82/0x417A89→0x417AE0
        e.d32(0x24, 0x1C); e.d32(0x2C, -1 & 0xFFFFFFFF)     # 0x417AE7/0x417AEE
    elif t == 0x2A8:                                        # 0x417AC6（表2 idx 0x00）
        self.p4_4177f0(e, 0x30, 0x190)
    elif t == 0x2D5:                                        # 0x417ABB（表2 idx 0x2D）
        e.d32(0x24, 0); e.d32(0x2C, 0)
    elif t == 0x2E4:                                        # 0x417AD9（表2 idx 0x3C）
        e.d32(0x04, 0x190); e.d32(0x08, -0x60 & 0xFFFFFFFF)
        e.d32(0x24, 0x1C); e.d32(0x2C, -1 & 0xFFFFFFFF)
    elif t == 0x32F:                                        # 0x417AFA（表2 idx 0x87）
        e.d32(0x24, 0); e.d32(0x2C, 0)                      # 0x417B03..0x417B06
        self.p4_4177f0(e, 0x5A, 0x268)                      # 0x417B09
    elif t == 0x36B:                                        # 0x417B13（表2 idx 0xC3）
        e.d32(0x04, 0x2E4); e.d32(0x08, 0x5A)
        e.d32(0x20, 0); e.d32(0x28, -1 & 0xFFFFFFFF)
    elif t == 0x377:                                        # 0x417B30
        e.d32(0x28, 0)
    elif t == 0x3B6:                                        # 0x417B5E
        e.d32(0x20, 0)
    elif t == 0x3F2:                                        # 0x417B51
        self.p4_4177f0(e, 0x30, 0x18)
    elif t == 0x42E:                                        # 0x417B63
        e.d32(0x04, -0x64 & 0xFFFFFFFF); e.d32(0x08, -0x64 & 0xFFFFFFFF)
        dx = self.p4_player_x() + 0x64                      # 0x417B6E/0x417B74/0x417B7C
        dy = self.p4_player_y() + 0x64                      # 0x417B79
        inv = self.p4_45aa80(dx, dy)                        # 0x417B81 0x40231F→0x45AA80
        e.d32(0x20, (((inv * dx) * 12) >> 12) & 0xFFFFFFFF)  # 0x417B86..0x417B94
        e.d32(0x24, (((inv * dy) * 12) >> 12) & 0xFFFFFFFF)  # 0x417B97..0x417BAB
    elif t == 0x492:                                        # 0x417BD6
        e.d32(0x20, 0); e.d32(0x24, 0)
    elif t == 0x5CD:                                        # 0x417BBE 帧表回卷
        e.d32(0x1C, 0)                                      # 0x417BC1
        n = (e.s32(0x30) + 1) & 0xFFFFFFFF                  # 0x417BBE lea eax,[ecx+1]（ecx=[0x30]）
        e.d32(0x30, n)                                      # 0x417BC7
        if n >= 6:                                          # 0x417BC4 cmp eax,6 / 0x417BCA jl
            return False

    # ---- 公共尾 0x417BDC ----
    e.d32(0x24, (e.s32(0x24) + e.s32(0x2C)) & 0xFFFFFFFF)   # 0x417BE2/0x417BEB
    e.d32(0x20, (e.s32(0x20) + e.s32(0x28)) & 0xFFFFFFFF)   # 0x417BE5/0x417BF0
    e.d32(0x04, (e.s32(0x04) + e.s32(0x20)) & 0xFFFFFFFF)   # 0x417BF4
    e.d32(0x08, (e.s32(0x08) + e.s32(0x24)) & 0xFFFFFFFF)   # 0x417BF6
    self.p4_417880(e, 0)                               # 0x417BF8 push ebx(=0) / 0x417C07
    if e.s32(0x30) & 1:                                     # 0x417C0C 尾镜像
        e.d32(0x04, (0x280 - e.s32(0x04)) & 0xFFFFFFFF)
        e.d32(0x08, (0x1E0 - e.s32(0x08)) & 0xFFFFFFFF)
    if e.node is not None:                                  # 0x417C2C..0x417C48
        e.node.dst = (e.s32(0x04) - 0x60, e.s32(0x08) - 0x60)
    if e.g32(0x18) != 0:                                    # 0x417C4B cmp eax,ebx / je
        return True
    self.p4_spawn52c_flash(e.s32(0x04), e.s32(0x08),      # 0x417C5C..0x417C9A
                           0x61000004, 0x48)
    return False


def _beh_417F30(self, e) -> bool:
    """`0x417F30`（thunk `0x4020E5`，0x27000010 帧表 boss 变体 B）。

    入口 0x417F3C 镜像；t=++[0x1C] 后按帧表分派
    （表：(t−0x2D) 索引 0x4182D8 / 目标 0x4182BC；(t−0x361) 索引 0x4183B4 / 目标 0x41839C）：
    ```
    0x02D → pos=(0x21C,−0x64); byte[0x10]=1; [0x24]=6
    0x066 → [0x2C]=−1                       0x06C → [0x28]=−1,[0x2C]=0
    0x07B → [0x28]=0                        0x0AF → [0x20]=[0x24]=0
    0x0F0 → 0x4177F0(0xF0,0x18)             0x12C → pos=(−0x60,0xF0),[0x20]=0xC
    0x17C → [0x20]=0
    0x1D6 → pos=(0x3AC,0),[0x20]=−0xC,[0x24]=0x20,[0x2C]=−1
    0x21C → [0x20]=[0x24]=[0x2C]=0          0x26C → 0x4177F0(0x230,0x30)
    0x2A8 → pos=(0x230,−0x60),[0x24]=0x1C,[0x2C]=−1
    0x2F3 → [0x24]=[0x2C]=0（不清 [0x20]）
    0x361 → 0x4177F0(0xF0,0x18)             0x39D → pos=(−0x64,0xF0),[0x20]=0,[0x28]=1
    0x3AC → [0x28]=0                        0x3F2 → [0x20]=0
    0x41A → 0x4177F0(0x1B0,0x18)
    0x456 → pos=(−0x64,0x244)，速度=12×单位向量(自机−(x,y))
    0x4BA → [0x20]=[0x24]=0                 0x4CE → 0x4177F0(0x30,0x268)
    0x50A → pos=(0x2E4,−0x64)，速度=12×单位向量(自机−(x,y))
    0x56E → [0x20]=[0x24]=0
    0x5CD → [0x1C]=0；[0x30]++ ≥6 → return 0
    ```
    公共尾 0x4181F7 与 0x417940 同形，只是 `0x417880(e,1)`（y 恒 0xF0）。
    """
    if e.s32(0x30) & 1:                                    # 0x417F3C
        e.d32(0x04, (0x280 - e.s32(0x04)) & 0xFFFFFFFF)     # 0x417F41..0x417F50
        e.d32(0x08, (0x1E0 - e.s32(0x08)) & 0xFFFFFFFF)     # 0x417F53..0x417F58
    t = (e.s32(0x1C) + 1) & 0xFFFFFFFF                      # 0x417F5B..0x417F63
    e.d32(0x1C, t)

    if t == 0x2D:                                           # 0x417F9D（表1 idx 0x00）
        e.d32(0x04, 0x21C); e.d32(0x08, -0x64 & 0xFFFFFFFF)
        e.m[0x10] = 1                                       # 0x417FAB
        e.d32(0x24, 6)
    elif t == 0x66:                                         # 0x418058（表1 idx 0x39）
        e.d32(0x2C, -1 & 0xFFFFFFFF)
    elif t == 0x6C:                                         # 0x417FBB（表1 idx 0x3F）
        e.d32(0x28, -1 & 0xFFFFFFFF); e.d32(0x2C, 0)
    elif t == 0x7B:                                         # 0x4180D3（表1 idx 0x4E）
        e.d32(0x28, 0)
    elif t == 0xAF:                                         # 0x4181F1（表1 idx 0x82）
        e.d32(0x20, 0); e.d32(0x24, 0)
    elif t == 0xF0:                                         # 0x4180A3（表1 idx 0xC3）
        self.p4_4177f0(e, 0xF0, 0x18)
    elif t == 0x12C:                                        # 0x417FCA
        e.d32(0x04, -0x60 & 0xFFFFFFFF); e.d32(0x08, 0xF0)
        e.d32(0x20, 0xC)
    elif t == 0x17C:                                        # 0x4180DB
        e.d32(0x20, 0)
    elif t == 0x1D6:                                        # 0x418001
        e.d32(0x04, 0x3AC); e.d32(0x08, 0)
        e.d32(0x20, -0xC & 0xFFFFFFFF); e.d32(0x24, 0x20); e.d32(0x2C, -1 & 0xFFFFFFFF)
    elif t == 0x21C:                                        # 0x418025（贯落 0x418028）
        e.d32(0x20, 0); e.d32(0x24, 0); e.d32(0x2C, 0)
    elif t == 0x26C:                                        # 0x418064
        self.p4_4177f0(e, 0x230, 0x30)
    elif t == 0x2A8:                                        # 0x418043（je 0x418064 之后的贯落块）
        e.d32(0x04, 0x230); e.d32(0x08, -0x60 & 0xFFFFFFFF)
        e.d32(0x24, 0x1C); e.d32(0x2C, -1 & 0xFFFFFFFF)
    elif t == 0x2F3:                                        # 0x418028（只清 [0x24]/[0x2C]）
        e.d32(0x24, 0); e.d32(0x2C, 0)
    elif t == 0x361:                                        # 0x4180A3（表2 idx 0x00）
        self.p4_4177f0(e, 0xF0, 0x18)
    elif t == 0x39D:                                        # 0x4180B6（表2 idx 0x3C）
        e.d32(0x04, -0x64 & 0xFFFFFFFF); e.d32(0x08, 0xF0)
        e.d32(0x20, 0); e.d32(0x28, 1)
    elif t == 0x3AC:                                        # 0x4180D3（表2 idx 0x4B）
        e.d32(0x28, 0)
    elif t == 0x3F2:                                        # 0x4180DB（表2 idx 0x91）
        e.d32(0x20, 0)
    elif t == 0x41A:                                        # 0x4180E3（表2 idx 0xB9）
        self.p4_4177f0(e, 0x1B0, 0x18)
    elif t == 0x456:                                        # 0x4180F6
        e.d32(0x04, -0x64 & 0xFFFFFFFF); e.d32(0x08, 0x244)
        dx = self.p4_player_x() + 0x64                      # 0x418104/0x41810A/0x418115
        dy = self.p4_player_y() - 0x244                     # 0x41810F
        inv = self.p4_45aa80(dx, dy)                        # 0x41811A
        e.d32(0x20, (((inv * dx) * 12) >> 12) & 0xFFFFFFFF)  # 0x41811F..0x41812D
        e.d32(0x24, (((inv * dy) * 12) >> 12) & 0xFFFFFFFF)  # 0x418130..0x418144
    elif t == 0x4BA:                                        # 0x4181F1
        e.d32(0x20, 0); e.d32(0x24, 0)
    elif t == 0x4CE:                                        # 0x418169
        self.p4_4177f0(e, 0x30, 0x268)
    elif t == 0x50A:                                        # 0x418179
        e.d32(0x04, 0x2E4); e.d32(0x08, -0x64 & 0xFFFFFFFF)
        dx = self.p4_player_x() - 0x2E4                     # 0x41818D/0x418196
        dy = self.p4_player_y() + 0x64                      # 0x418187/0x418193
        inv = self.p4_45aa80(dx, dy)                        # 0x41819E
        e.d32(0x20, (((inv * dx) * 12) >> 12) & 0xFFFFFFFF)  # 0x4181A3..0x4181B1
        e.d32(0x24, (((inv * dy) * 12) >> 12) & 0xFFFFFFFF)  # 0x4181B4..0x4181C8
    elif t == 0x56E:                                        # 0x4181F1
        e.d32(0x20, 0); e.d32(0x24, 0)
    elif t == 0x5CD:                                        # 0x4181D9 帧表回卷
        e.d32(0x1C, 0)                                      # 0x4181DC
        n = (e.s32(0x30) + 1) & 0xFFFFFFFF                  # 0x4181D9
        e.d32(0x30, n)                                      # 0x4181E2
        if n >= 6:                                          # 0x4181DF/0x4181E5
            return False

    # ---- 公共尾 0x4181F7 ----
    e.d32(0x24, (e.s32(0x24) + e.s32(0x2C)) & 0xFFFFFFFF)   # 0x4181FA/0x418206
    e.d32(0x20, (e.s32(0x20) + e.s32(0x28)) & 0xFFFFFFFF)   # 0x4181FD/0x418208
    e.d32(0x04, (e.s32(0x04) + e.s32(0x20)) & 0xFFFFFFFF)   # 0x41820F
    e.d32(0x08, (e.s32(0x08) + e.s32(0x24)) & 0xFFFFFFFF)   # 0x418211
    self.p4_417880(e, 1)                               # 0x418213 push 1 / 0x418223
    if e.s32(0x30) & 1:                                     # 0x418228 尾镜像
        e.d32(0x04, (0x280 - e.s32(0x04)) & 0xFFFFFFFF)
        e.d32(0x08, (0x1E0 - e.s32(0x08)) & 0xFFFFFFFF)
    if e.node is not None:                                  # 0x418248..0x418264
        e.node.dst = (e.s32(0x04) - 0x60, e.s32(0x08) - 0x60)
    if e.g32(0x18) != 0:                                    # 0x418267/0x41826C
        return True
    self.p4_spawn52c_flash(e.s32(0x04), e.s32(0x08),      # 0x418278..0x4182B9
                           0x61000004, 0x48)
    return False


def _beh_4185C0(self, e) -> bool:
    """`0x4185C0`（thunk `0x4013A7`，0x27000010 帧表 boss 变体 C）。
    **注意：`page4.py` 已有一版 `_beh_4185C0`，与本草稿有 7 条出入，见文件末「差异」。**

    入口 0x4185CC 镜像；t=++[0x1C] 后按帧表分派
    （表：(t−0x50) 索引 0x41897C / 目标 0x418964；(t−0x311) 索引 0x418A38 / 目标 0x418A20）：
    ```
    0x050 → pos=(0x21C,−0x64); byte[0x10]=1; [0x24]=6
    0x0A7 → [0x2C]=−1                       0x0AD → [0x28]=−1,[0x2C]=0
    0x0BC → [0x28]=0                        0x0F0 → [0x20]=[0x24]=0
    0x100 → 0x4177F0(0x190,0x18)            0x13C → pos=(−0x60,0x190),[0x20]=0xC
    0x18C → [0x20]=0
    0x1A4 → pos=(0x474,0),[0x20]=−0xC,[0x24]=0x20,[0x2C]=−1
    0x1EA → [0x20]=[0x24]=[0x2C]=0
    0x28A → 0x4177F0(0x30,0xF0)
    0x2C6 → pos=(0xF0,−0x60),[0x24]=0x1C,[0x2C]=−1
    0x311 → [0x24]=[0x2C]=0
    0x32F → 0x4177F0(0x186,0x268)
    0x36B → pos=(0x2E4,0x186),[0x20]=0,[0x28]=−1
    0x377 → [0x28]=0                        0x3B6 → [0x20]=0
    0x442 → 0x4177F0(0x1B0,0x268)
    0x47E → pos=(0x2E4,0x244)，速度=12×单位向量(自机−(x,y))
    0x4A6 → 0x4177F0(0x30,0x18)
    0x4E2 → pos=(−0x64,−0x64)，速度=12×单位向量(自机+0x64)
    0x582 → [0x20]=[0x24]=0
    0x5CD → [0x1C]=0；[0x30]++ ≥6 → return 0
    ```
    公共尾 0x41889F 与另两个同形，`0x417880(e,2)`。
    """
    if e.s32(0x30) & 1:                                    # 0x4185CC
        e.d32(0x04, (0x280 - e.s32(0x04)) & 0xFFFFFFFF)     # 0x4185D1..0x4185E0
        e.d32(0x08, (0x1E0 - e.s32(0x08)) & 0xFFFFFFFF)     # 0x4185E3..0x4185E8
    t = (e.s32(0x1C) + 1) & 0xFFFFFFFF                      # 0x4185EB..0x4185F3
    e.d32(0x1C, t)

    if t == 0x50:                                           # 0x41862D（表1 idx 0x00）
        e.d32(0x04, 0x21C); e.d32(0x08, -0x64 & 0xFFFFFFFF)
        e.m[0x10] = 1                                       # 0x41863B
        e.d32(0x24, 6)
    elif t == 0xA7:                                         # 0x418714（表1 idx 0x57）
        e.d32(0x2C, -1 & 0xFFFFFFFF)
    elif t == 0xAD:                                         # 0x41864B（表1 idx 0x5D）
        e.d32(0x28, -1 & 0xFFFFFFFF); e.d32(0x2C, 0)
    elif t == 0xBC:                                         # 0x418786（表1 idx 0x6C）
        e.d32(0x28, 0)
    elif t == 0xF0:                                         # 0x418899（表1 idx 0xA0）
        e.d32(0x20, 0); e.d32(0x24, 0)
    elif t == 0x100:                                        # 0x41865A
        self.p4_4177f0(e, 0x190, 0x18)
    elif t == 0x13C:                                        # 0x41868E
        e.d32(0x04, -0x60 & 0xFFFFFFFF); e.d32(0x08, 0x190)
        e.d32(0x20, 0xC)
    elif t == 0x18C:                                        # 0x418686（0x13C+0x50）
        e.d32(0x20, 0)
    elif t == 0x1A4:                                        # 0x4186A8
        e.d32(0x04, 0x474); e.d32(0x08, 0)
        e.d32(0x20, -0xC & 0xFFFFFFFF); e.d32(0x24, 0x20); e.d32(0x2C, -1 & 0xFFFFFFFF)
    elif t == 0x1EA:                                        # 0x4186F1
        e.d32(0x20, 0); e.d32(0x24, 0); e.d32(0x2C, 0)
    elif t == 0x28A:                                        # 0x4186DE
        self.p4_4177f0(e, 0x30, 0xF0)
    elif t == 0x2C6:                                        # 0x4186FF
        e.d32(0x04, 0xF0); e.d32(0x08, -0x60 & 0xFFFFFFFF)
        e.d32(0x24, 0x1C); e.d32(0x2C, -1 & 0xFFFFFFFF)
    elif t == 0x311:                                        # 0x418748（表2 idx 0x00）
        e.d32(0x24, 0); e.d32(0x2C, 0)
    elif t == 0x32F:                                        # 0x418753（表2 idx 0x1E）
        self.p4_4177f0(e, 0x186, 0x268)
    elif t == 0x36B:                                        # 0x418769（表2 idx 0x5A）
        e.d32(0x04, 0x2E4); e.d32(0x08, 0x186)
        e.d32(0x20, 0); e.d32(0x28, -1 & 0xFFFFFFFF)
    elif t == 0x377:                                        # 0x418786（表2 idx 0x66）
        e.d32(0x28, 0)
    elif t == 0x3B6:                                        # 0x418686（表2 idx 0xA5）
        e.d32(0x20, 0)
    elif t == 0x442:                                        # 0x41878E
        self.p4_4177f0(e, 0x1B0, 0x268)
    elif t == 0x47E:                                        # 0x4187D1
        e.d32(0x04, 0x2E4); e.d32(0x08, 0x244)
        dx = self.p4_player_x() - 0x2E4                     # 0x4187E5/0x4187F0
        dy = self.p4_player_y() - 0x244                     # 0x4187DF/0x4187EA
        inv = self.p4_45aa80(dx, dy)                        # 0x4187F8
        e.d32(0x20, (((inv * dx) * 12) >> 12) & 0xFFFFFFFF)  # 0x4187FD..0x41880B
        e.d32(0x24, (((inv * dy) * 12) >> 12) & 0xFFFFFFFF)  # 0x41880E..0x418822
    elif t == 0x4A6:                                        # 0x4187C1
        self.p4_4177f0(e, 0x30, 0x18)
    elif t == 0x4E2:                                        # 0x418827
        e.d32(0x04, -0x64 & 0xFFFFFFFF); e.d32(0x08, -0x64 & 0xFFFFFFFF)
        dx = self.p4_player_x() + 0x64                      # 0x418838/0x418841
        dy = self.p4_player_y() + 0x64                      # 0x418832/0x41883E
        inv = self.p4_45aa80(dx, dy)                        # 0x418846
        e.d32(0x20, (((inv * dx) * 12) >> 12) & 0xFFFFFFFF)  # 0x41884B..0x418859
        e.d32(0x24, (((inv * dy) * 12) >> 12) & 0xFFFFFFFF)  # 0x41885C..0x418870
    elif t == 0x582:                                        # 0x418899
        e.d32(0x20, 0); e.d32(0x24, 0)
    elif t == 0x5CD:                                        # 0x418881 帧表回卷
        e.d32(0x1C, 0)                                      # 0x418884
        n = (e.s32(0x30) + 1) & 0xFFFFFFFF                  # 0x418881
        e.d32(0x30, n)                                      # 0x41888A
        if n >= 6:                                          # 0x418887/0x41888D
            return False

    # ---- 公共尾 0x41889F ----
    e.d32(0x24, (e.s32(0x24) + e.s32(0x2C)) & 0xFFFFFFFF)   # 0x4188A2/0x4188AE
    e.d32(0x20, (e.s32(0x20) + e.s32(0x28)) & 0xFFFFFFFF)   # 0x4188A5/0x4188B0
    e.d32(0x04, (e.s32(0x04) + e.s32(0x20)) & 0xFFFFFFFF)   # 0x4188B7
    e.d32(0x08, (e.s32(0x08) + e.s32(0x24)) & 0xFFFFFFFF)   # 0x4188B9
    self.p4_417880(e, 2)                               # 0x4188BB push 2 / 0x4188CB
    if e.s32(0x30) & 1:                                     # 0x4188D0 尾镜像
        e.d32(0x04, (0x280 - e.s32(0x04)) & 0xFFFFFFFF)
        e.d32(0x08, (0x1E0 - e.s32(0x08)) & 0xFFFFFFFF)
    if e.node is not None:                                  # 0x4188F0..0x41890C
        e.node.dst = (e.s32(0x04) - 0x60, e.s32(0x08) - 0x60)
    if e.g32(0x18) != 0:                                    # 0x41890F/0x418914
        return True
    self.p4_spawn52c_flash(e.s32(0x04), e.s32(0x08),      # 0x418920..0x418961
                           0x61000004, 0x48)
    return False


# ============================================================================
def _beh_41CF70(self, e) -> bool:
    """`0x41CF70`（thunk 0x402121；0x29000001 ×12）：**两段横穿**。

    ```
    [0x20]==0（待机）：t=++[0x1C]
        (t&0x7F)==0x7F → [0x24] = (y≥0xF0 ? −1 : +1)（纵向向中线）
        (t&0xCF)==0xCF → 0x43B070(e,0) 开火
        t==0x280       → [0x20]=1（启动横移）
    [0x20]!=0（横移）：x < [0x28] → [0x20]++（加速到 [0x28]）
    [0x24]!=0 → [0x24] += (y≥0xF0 ? −1 : +1)
    x += [0x20]; y += [0x24]; 0x45A6B0(node+0x14, [0x20], [0x24])
    return x < 0x298 且 HP != 0
    ```"""
    if e.s32(0x20) == 0:
        if e.s32(0x24) == 0:
            t = (e.s32(0x1C) + 1) & 0xFFFFFFFF
            e.d32(0x1C, t)
            if (t & 0x7F) == 0x7F:
                e.d32(0x24, (-1 if e.s32(0x08) >= 0xF0 else 1) & 0xFFFFFFFF)
            if (t & 0xCF) == 0xCF:
                self.p4_43B070(e, 0)
            if t == 0x280:
                e.d32(0x20, 1)
    else:
        if e.s32(0x04) < e.s32(0x28):
            e.d32(0x20, (e.s32(0x20) + 1) & 0xFFFFFFFF)
    if e.s32(0x24) != 0:
        e.d32(0x24, (e.s32(0x24) + (-1 if e.s32(0x08) >= 0xF0 else 1)) & 0xFFFFFFFF)
    vx = e.s32(0x20)
    vy = e.s32(0x24)
    e.d32(0x04, (e.s32(0x04) + vx) & 0xFFFFFFFF)
    e.d32(0x08, (e.s32(0x08) + vy) & 0xFFFFFFFF)
    if e.node is not None:                          # 0x45A6B0(node+0x14, vx, vy)
        e.node.dst = (e.node.dst[0] + vx, e.node.dst[1] + vy)
    return e.s32(0x04) < 0x298 and e.g32(0x18) != 0


def _beh_41F780(self, e) -> bool:
    """`0x41F780`（thunk 0x4018CF；0x29000014 ×12）：**回旋镖横穿 + 距离门开火**。

    ```
    [0x20] != −4 → [0x20] += ([0x20] ≥ −3 ? −1 : +1)   ; 横速衰到 −3（回旋）
    x += [0x20]
    |y − 自机y| < 0x90 → t=++[0x1C]
        门 = (|x − 自机x| ≥ 0xA0) ? 0x1F : 7
        (t & 门)==0 → 0x43B070(e,0)
    node dst = (x−0x18, y−0x18)（0x45A690 恒等直存）
    return HP != 0 且 x > −0x18
    ```"""
    if e.s32(0x20) != -4:
        v = e.s32(0x20)
        e.d32(0x20, (v + (-1 if v >= -3 else 1)) & 0xFFFFFFFF)
    e.d32(0x04, (e.s32(0x04) + e.s32(0x20)) & 0xFFFFFFFF)
    ady = abs(e.s32(0x08) - self.p4_player_y())     # 0x41F7B6 cdq/xor/sub
    if ady < 0x90:
        t = (e.s32(0x1C) + 1) & 0xFFFFFFFF
        e.d32(0x1C, t)
        adx = abs(e.s32(0x04) - self.p4_player_x())
        gate = 0x1F if adx >= 0xA0 else 7           # 0x41F7E5 and 0xFFFFFFE8 / +0x1F
        if (t & gate) == 0:
            self.p4_43B070(e, 0)
    if e.node is not None:                          # 0x41F806→0x45A690 恒等
        e.node.dst = (e.s32(0x04) - 0x18, e.s32(0x08) - 0x18)
    return e.g32(0x18) != 0 and e.s32(0x04) > -0x18


def _beh_4194A0(self, e) -> bool:
    """`0x4194A0`（0x28000001 ×12）：**定高左退**——x −= [0x24]、y = [0x20]（定值）；
    0x401BA4(0x20,1,0x30) 特效；x==0xF0 且 [0x28]≠0 → 0x43B070(e,0)；
    node dst=(x−0x18,y−0x18)；return x > −0x18 且 HP≠0。"""
    e.d32(0x04, (e.s32(0x04) - e.s32(0x24)) & 0xFFFFFFFF)
    e.d32(0x08, e.s32(0x20) & 0xFFFFFFFF)
    self.p4_4193e0(e, 0x20,1,0x30)
    if e.s32(0x04) == 0xF0 and e.s32(0x28) != 0:
        self.p4_43B070(e, 0)
    if e.node is not None:
        e.node.dst = (e.s32(0x04) - 0x18, e.s32(0x08) - 0x18)
    return e.s32(0x04) > -0x18 and e.g32(0x18) != 0


def _beh_419540(self, e) -> bool:
    """`0x419540`：**抛物线跳跳 + 落点折返**——x += [0x28]（定速横移）、
    [0x20] += [0x24]、[0x24]−−（竖速衰减）、y = [0x20]>>4（8.4 定点）；
    [0x24]==−0x3C（顶点/谷点）→ [0x28]=−[0x28]（横速反向）、[0x24]=0x3C、[0x2C]−−
    （折返次数递减，0 即灭）；0x401BA4(0x40,2,0x30) 特效；
    [0x24]==0 且 [0x28]>0 → 0x43B070(e,0)；node dst 同步；
    return HP≠0 且 [0x2C]≠0。"""
    e.d32(0x04, (e.s32(0x04) + e.s32(0x28)) & 0xFFFFFFFF)
    s = (e.s32(0x20) + e.s32(0x24)) & 0xFFFFFFFF
    e.d32(0x20, s)
    vy = (e.s32(0x24) - 1) & 0xFFFFFFFF
    e.d32(0x24, vy)
    vy_s = vy - 0x100000000 if vy & 0x80000000 else vy
    s_s = s - 0x100000000 if s & 0x80000000 else s
    e.d32(0x08, (s_s >> 4) & 0xFFFFFFFF)
    if vy_s == -0x3C:                               # 0x419560 折返
        e.d32(0x28, (-e.s32(0x28)) & 0xFFFFFFFF)
        e.d32(0x2C, (e.s32(0x2C) - 1) & 0xFFFFFFFF)
        e.d32(0x24, 0x3C)
    self.p4_4193e0(e, 0x40,2,0x30)
    if e.s32(0x24) == 0 and e.s32(0x28) > 0:
        self.p4_43B070(e, 0)
    if e.node is not None:
        e.node.dst = (e.s32(0x04) - 0x18, e.s32(0x08) - 0x18)
    return e.g32(0x18) != 0 and e.s32(0x2C) != 0


def _beh_41A220(self, e) -> bool:
    """`0x41A220`（0x28000010 ×12）：**减速下坠 + 纵摆转向**——[0x20]+=[0x28]、
    [0x24]+=[0x2C]、[0x28]−−（横速衰减到 0 后）；[0x28]<0 时
    [0x2C] += (y≥0xF0 ? −1 : +1)（纵向向中线）；x=[0x20]>>2、y=[0x24]>>2（8.4 定点）；
    0x401BA4(0x40,3,0x30) 特效；([0x2C]&0xF)==0xF 且 x>0xA0 → 0x43B070(e,0)；
    node dst=(x−0x18,y−0x18)；return HP≠0 且 x>−0x18。"""
    e.d32(0x20, (e.s32(0x20) + e.s32(0x28)) & 0xFFFFFFFF)
    e.d32(0x24, (e.s32(0x24) + e.s32(0x2C)) & 0xFFFFFFFF)
    t = (e.s32(0x28) - 1) & 0xFFFFFFFF
    e.d32(0x28, t)
    if t & 0x80000000:                              # jge 不成立 → [0x28] < 0
        e.d32(0x2C, (e.s32(0x2C) + (-1 if e.s32(0x08) >= 0xF0 else 1)) & 0xFFFFFFFF)
    e.d32(0x04, (e.s32(0x20) >> 2) & 0xFFFFFFFF)    # sar 2
    e.d32(0x08, (e.s32(0x24) >> 2) & 0xFFFFFFFF)
    self.p4_4193e0(e, 0x40,3,0x30)
    if (e.s32(0x2C) & 0xF) == 0xF and e.s32(0x04) > 0xA0:
        self.p4_43B070(e, 0)
    if e.node is not None:
        e.node.dst = (e.s32(0x04) - 0x18, e.s32(0x08) - 0x18)
    return e.g32(0x18) != 0 and e.s32(0x04) > -0x18


def _beh_40EDB0(self, e) -> bool:
    """`0x40EDB0`（thunk 0x40210D；0x2300000D ×12）：**boss 运载机**。

    HP==0 时一发三连：0x430400(&rec,…,0x2300000E,a3=&{vx,vy}) 三次入 0x4AD43C——
    (x−0x18, y+0x18) 速 (1,0)、(x−0x18, y−0x18) 速 (1,−2)、(x+0x18, y) 速 (0,−1)
    （0x45A690 恒等回填栈残留对）。
    每帧：相位 [0x1C] += [0x20]（频率）、y = 相位>>7（sar 7）、x −= 5；
    node dst = (x−0x48, y−0x48)；return x > −0x48 且 HP≠0。"""
    if e.g32(0x18) == 0:                            # 0x40EDBA HP==0 → 死亡放残骸
        self._p4_ent43c(0x2300000E, e.s32(0x04) - 0x18, e.s32(0x08) + 0x18, (1, 0))
        self._p4_ent43c(0x2300000E, e.s32(0x04) - 0x18, e.s32(0x08) - 0x18, (1, -2))
        self._p4_ent43c(0x2300000E, e.s32(0x04) + 0x18, e.s32(0x08), (0, -1))
    e.d32(0x1C, (e.s32(0x1C) + e.s32(0x20)) & 0xFFFFFFFF)
    e.d32(0x04, (e.s32(0x04) - 5) & 0xFFFFFFFF)
    y = e.s32(0x1C) >> 7                            # sar 7（相位 → 纵坐标）
    e.d32(0x08, y & 0xFFFFFFFF)
    if e.node is not None:
        e.node.dst = (e.s32(0x04) - 0x48, y - 0x48)
    return e.s32(0x04) > -0x48 and e.g32(0x18) != 0


def _beh_40EF60(self, e) -> bool:
    """`0x40EF60`（thunk 0x401BA9；0x2300000E，0x40EDB0 死亡产物）：**二级残骸**。

    HP==0 时一圈四发 0x2300000F（四角 (x±0x18, y±0x18)，速度对取自
    栈块 {1,−1},{1,0},{2,−2},{2,1}——ebx&1 定 y 偏移、ebx&2 定 x 偏移，
    0x4023C4(&rec,x±0x18,y±0x18,0x2300000F,prm) 入 0x4AD43C）。
    每帧：x += [0x1C]（vx）；计数 [0x20] = clamp(+1/+2, ≤0x40)（初值 = vy<<4，
    负值先上抛后加速下坠）；[0x24] += 计数、y = [0x24]>>4；
    node dst=(x−0x30, y−0x30)；0x4305F0(e,0x30) 在屏判据；
    return 在屏 且 HP≠0。"""
    if e.g32(0x18) == 0:                            # 0x40EF6B
        prm_blocks = [(1, -1), (1, 0), (2, -2), (2, 1)]
        for i, prm in enumerate(prm_blocks):
            xo = 0x18 if (i & 2) else -0x18         # ebx&2 → x 偏移
            yo = 0x18 if (i & 1) else -0x18         # ebx&1 → y 偏移
            self._p4_ent43c(0x2300000F, e.s32(0x04) + xo, e.s32(0x08) + yo, prm)
    e.d32(0x04, (e.s32(0x04) + e.s32(0x1C)) & 0xFFFFFFFF)
    c = e.s32(0x20)
    c_s = c - 0x100000000 if c & 0x80000000 else c
    # 0x40F02C：step = (old<0x40 ? old+1 : 0x40)；[+0x20] 写 old+2（<0x40 时）否则 old+1，不钳位
    step = c_s + 1 if c_s < 0x40 else 0x40
    e.d32(0x20, (c_s + 2 if c_s < 0x40 else c_s + 1) & 0xFFFFFFFF)
    acc = (e.s32(0x24) + step) & 0xFFFFFFFF
    e.d32(0x24, acc)
    y = ((acc - 0x100000000 if acc & 0x80000000 else acc) >> 4)
    e.d32(0x08, y & 0xFFFFFFFF)
    if e.node is not None:
        e.node.dst = (e.s32(0x04) - 0x30, y - 0x30)
    return self.p4_4305f0(e, 0x30) and e.g32(0x18) != 0


def _beh_40F0F0(self, e) -> bool:
    """`0x40F0F0`（thunk 0x40138E；0x2300000F，0x40EF60 死亡产物）：**三级残骸**。

    每帧：x += [0x1C]（vx）；计数 [0x20] = clamp(+1/+2, ≤0x30)（初值 = vy<<4）；
    [0x24] += 计数、y = [0x24]>>4；node dst=(x−0x18, y−0x18)；
    0x4305F0(e,0x18) 在屏判据；return 在屏 且 HP≠0。"""
    e.d32(0x04, (e.s32(0x04) + e.s32(0x1C)) & 0xFFFFFFFF)
    c = e.s32(0x20)
    c_s = c - 0x100000000 if c & 0x80000000 else c
    step = c_s + 1 if c_s < 0x30 else 0x30
    e.d32(0x20, (c_s + 2 if c_s < 0x30 else c_s + 1) & 0xFFFFFFFF)
    acc = (e.s32(0x24) + step) & 0xFFFFFFFF
    e.d32(0x24, acc)
    y = ((acc - 0x100000000 if acc & 0x80000000 else acc) >> 4)
    e.d32(0x08, y & 0xFFFFFFFF)
    if e.node is not None:
        e.node.dst = (e.s32(0x04) - 0x18, y - 0x18)
    return self.p4_4305f0(e, 0x18) and e.g32(0x18) != 0


def _beh_4113E0(self, e) -> bool:
    """`0x4113E0`：**折返斜升**——t=++[0x1C]；[0x20] += (t&0x40 ? −1 : +1)
    （锯齿步进，0x40 位翻转折返）；x += [0x20]>>1（sar 1）、y −= 2；
    `0x45A6B0(node+0x14, [0x20]>>1, −2)`（dst 同步）；return y > −0x18 且 HP≠0。"""
    t = (e.s32(0x1C) + 1) & 0xFFFFFFFF
    e.d32(0x1C, t)
    step = 1 if ((t & 0x10) == (t & 0x40)) else -1   # 0x4113EC test 0x10 / 0x4113FC 两分支
    acc = (e.s32(0x20) + step) & 0xFFFFFFFF
    e.d32(0x20, acc)
    acc_s = acc - 0x100000000 if acc & 0x80000000 else acc
    e.d32(0x04, (e.s32(0x04) + (acc_s >> 1)) & 0xFFFFFFFF)
    e.d32(0x08, (e.s32(0x08) - 2) & 0xFFFFFFFF)
    if e.node is not None:                          # 0x45A6B0(node+0x14, >>1, −2)
        e.node.dst = (e.node.dst[0] + (acc_s >> 1), e.node.dst[1] - 2)
    return e.s32(0x08) > -0x18 and e.g32(0x18) != 0


def _beh_4112F0(self, e) -> bool:
    """`0x4112F0`：**入场摆动（8.8 双通道）**——word[0x20] −= 2（16 位）；
    (word[0x20]&0x1F8)==0 且 [0x1C]≠0 → 0x43B070(e,0)（每 64 帧开火）；
    [0x28]≠0 → word[0x24] += ([0x28]≤0 ? +1 : −1)；[0x2C]≠0 → word[0x26] 同式；
    [0x28] += (int16)word[0x24]、[0x2C] += (int16)word[0x26]；
    x = [0x28]>>1 + (int16)word[0x20]、y = ([0x2C]+2)>>2 + (int16)word[0x22]；
    node dst=(x−0x18,y−0x18)；return HP≠0 且 (word[0x20]≥0 或 x≥−0x18)。"""
    w20 = (e.g16(0x20) - 2) & 0xFFFF
    e.d16(0x20, w20)
    w20_s = w20 - 0x10000 if w20 & 0x8000 else w20
    if (w20 & 0x1F8) == 0 and e.s32(0x1C) != 0:
        self.p4_43B070(e, 0)
    w24 = e.g16(0x24)
    w26 = e.g16(0x26)
    if e.s32(0x28) != 0:
        w24 = (w24 + (1 if e.s32(0x28) <= 0 else -1)) & 0xFFFF
        e.d16(0x24, w24)
    if e.s32(0x2C) != 0:
        w26 = (w26 + (1 if e.s32(0x2C) <= 0 else -1)) & 0xFFFF
        e.d16(0x26, w26)
    p28 = e.s32(0x28) + (w24 - 0x10000 if w24 & 0x8000 else w24)
    p2c = e.s32(0x2C) + (w26 - 0x10000 if w26 & 0x8000 else w26)
    e.d32(0x28, p28 & 0xFFFFFFFF)
    e.d32(0x2C, p2c & 0xFFFFFFFF)
    w22 = e.g16(0x22)
    w22_s = w22 - 0x10000 if w22 & 0x8000 else w22
    x = (p28 >> 1) + w20_s
    y = ((p2c + 2) >> 2) + w22_s
    e.d32(0x04, x & 0xFFFFFFFF)
    e.d32(0x08, y & 0xFFFFFFFF)
    if e.node is not None:
        e.node.dst = (x - 0x18, y - 0x18)
    return e.g32(0x18) != 0 and (w20_s >= 0 or x >= -0x18)


def _beh_41D910(self, e) -> bool:
    """`0x41D910`（thunk 0x4015A5）：**脱离加速**——t=++[0x1C]；t==0xF0 → [0x20]=−1
    （起转）；否则 [0x20]≠0 且 t>0x1E → [0x20]−−（衰减）；
    dx = [0x20]>>1（sar 1）；x −= dx、node.dst.x −= dx；
    return x < 0x298 且 HP≠0（x 滑出右缘即灭）。"""
    t = (e.s32(0x1C) + 1) & 0xFFFFFFFF
    e.d32(0x1C, t)
    if t == 0xF0:
        e.d32(0x20, -1 & 0xFFFFFFFF)
    elif e.s32(0x20) != 0 and t > 0x1E:
        e.d32(0x20, (e.s32(0x20) - 1) & 0xFFFFFFFF)
    dx = e.s32(0x20) >> 1                           # sar 1
    e.d32(0x04, (e.s32(0x04) - dx) & 0xFFFFFFFF)
    if e.node is not None:                          # 0x41D946 [node+0x14] −= dx
        e.node.dst = (e.node.dst[0] - dx, e.node.dst[1])
    return e.s32(0x04) < 0x298 and e.g32(0x18) != 0


def p4_414010(self, e) -> None:
    """`0x414010`（thunk 0x401816）：**弹流贴图行滚动**——node.rect.t（[node+8]）
    为 0x90/0x150/0x210 → 0x45A790(node+4,0,−0x90,0,−0x90)（行回卷），
    否则 (…,0x30,0,0x30)（下行 0x30）。rect = (l, t+dy, r, b+dh)。"""
    nd = e.node
    if nd is None:
        return
    t = nd.rect[1]
    if t in (0x90, 0x150, 0x210):
        dy = -0x90
    else:
        dy = 0x30
    nd.rect = (nd.rect[0], t + dy, nd.rect[2], nd.rect[3] + dy)

def p4_4193e0(self, e, arg1: int, shift: int, arg3: int) -> None:
    """`0x4193E0`（thunk 0x401BA4）：**入场/离场帧动画**。

    t=++[0x1C]；t<arg1 → y += t>>shift（算术）；否则 d=t−arg1：
    d∈{0,2} → rect.y −= arg3；d==4 → [0x1C]=0、rect.y += arg3；其余不变。
    """
    t = (e.s32(0x1C) + 1) & 0xFFFFFFFF
    e.d32(0x1C, t)
    if t < arg1:
        e.d32(0x08, (e.s32(0x08) + (t >> shift)) & 0xFFFFFFFF)
        return
    d = t - arg1
    if d > 6:
        return
    if e.node is None:
        return
    if d in (0, 2):
        e.node.rect = (e.node.rect[0], e.node.rect[1] - arg3,
                       e.node.rect[2], e.node.rect[3] - arg3)
    elif d == 4:
        e.d32(0x1C, 0)
        e.node.rect = (e.node.rect[0], e.node.rect[1] + arg3,
                       e.node.rect[2], e.node.rect[3] + arg3)


def p4_416440(self, e) -> None:
    """`0x416440`：HP==0 时向 0x4AD43C 生成 boss 0x27000011（prm=父实体）。"""
    if e.g32(0x18) != 0:
        return
    _h = id(e) & 0x7FFFFFFF
    self.p4_links[_h] = e
    self._p4_ent43c(0x27000011, e.s32(0x04), e.s32(0x08), _h)


def p4_43B290(self, e, dx: int, dy: int, arg: int) -> None:
    """`0x43B290`（thunk 0x40165E）：**定向速度弹**——arg=0x43AF90 表速，
    (dx,dy) 为显式方向：v = (4096/|d|)*d*(spd>>4)>>8；弹型 0x43B020(e)，
    入 0x4AD49C（0x43B2E5→0x40113B、0x43B2FD 0x430400 后入队）。"""
    spd = self.p4_43af90(e, arg) >> 4                 # 0x43B2AF sar 4
    inv = self.p4_45aa80(dx, dy)                      # 0x40231F
    vx = ((inv * dx) * spd) >> 8
    vy = ((inv * dy) * spd) >> 8
    if vx == 0 and vy == 0:
        return
    eb = self.spawn(self._p4_q("ui49c"), self.p4_43B020(e),
                    e.s32(0x04), e.s32(0x08), (vx, vy))
    if eb is not None:
        eb.raw[0x10] = 1
        eb.d32(0x14, self.p4_43B020(e) & 0xFFFFFFFF)
        eb.d32(0x04, e.s32(0x04) & 0xFFFFFFFF)
        eb.d32(0x08, e.s32(0x08) & 0xFFFFFFFF)
        eb.d32(0x0C, 0x18)
        self._p4_q("ui49c").append(eb)


def _beh_415410(self, e) -> bool:
    """`0x415410`（0x2600000D）：左移 4/帧（x −= 4、node.dst.x −= 4）；t=++[0x1C]，
    (t&7)==7 → 0x414010 弹流行滚动；return x > −0x40 且 HP≠0。"""
    e.d32(0x1C, (e.s32(0x1C) + 1) & 0xFFFFFFFF)
    e.d32(0x04, (e.s32(0x04) - 4) & 0xFFFFFFFF)
    if e.node is not None:
        e.node.dst = (e.node.dst[0] - 4, e.node.dst[1])
    if (e.s32(0x1C) & 7) == 7:
        self.p4_414010(e)
    return e.s32(0x04) > -0x40 and e.g32(0x18) != 0


def _beh_415CE0(self, e) -> bool:
    """`0x415CE0`（0x26000015）：[0x20] += [0x24]（累计）、x = [0x20]>>6；
    node dst=(x−0x18, y−0x18)；(t&0x1F)==0x1F → 0x414010 弹流行滚动；
    return x > −0x18 且 HP≠0。"""
    t = (e.s32(0x1C) + 1) & 0xFFFFFFFF
    e.d32(0x1C, t)
    s = (e.s32(0x20) + e.s32(0x24)) & 0xFFFFFFFF
    e.d32(0x20, s)
    e.d32(0x04, ((s - 0x100000000 if s & 0x80000000 else s) >> 6) & 0xFFFFFFFF)
    if e.node is not None:
        e.node.dst = (e.s32(0x04) - 0x18, e.s32(0x08) - 0x18)
    if (t & 0x1F) == 0x1F:
        self.p4_414010(e)
    return e.s32(0x04) > -0x18 and e.g32(0x18) != 0


def _beh_415E60(self, e) -> bool:
    """`0x415E60`（0x26000017）：y += [0x20]（node.dst.y 同加）；t=++[0x1C]；
    (t&3)==3 → 0x414010；(t&0xF)==7 → 0x43B290(e,−1,0,0)（定向左直弹）；
    0x4305F0(e,0x18) 在屏判据；return 在屏 且 HP≠0。"""
    dy = e.s32(0x20)
    e.d32(0x08, (e.s32(0x08) + dy) & 0xFFFFFFFF)
    t = (e.s32(0x1C) + 1) & 0xFFFFFFFF
    e.d32(0x1C, t)
    if e.node is not None:
        e.node.dst = (e.node.dst[0], e.node.dst[1] + dy)
    if (t & 3) == 3:
        self.p4_414010(e)
    if (t & 0xF) == 7:
        self.p4_43B290(e, -1, 0, 0)
    return self.p4_4305f0(e, 0x18) and e.g32(0x18) != 0


def _beh_418C30(self, e) -> bool:
    """`0x418C30`（0x27000011）：[0x20] −= [0x24]；[0x24] += ([0x24]<0x20)（饱和 0x20）；
    [0x28] = [0x20]>>5；y = [0x28]、node.dst.y += (新y−旧y)；
    return HP≠0 且 node.dst.y > −0x60。"""
    v = (e.s32(0x20) - e.s32(0x24)) & 0xFFFFFFFF
    e.d32(0x20, v)
    gate = e.s32(0x24)
    gate = (gate + 1) & 0xFFFFFFFF if gate < 0x20 else gate
    e.d32(0x24, gate)
    step = (v - 0x100000000 if v & 0x80000000 else v) >> 5
    e.d32(0x28, step & 0xFFFFFFFF)
    yold = e.s32(0x08)
    e.d32(0x08, step & 0xFFFFFFFF)
    if e.node is not None:
        e.node.dst = (e.node.dst[0], e.node.dst[1] + (step - yold))
    if e.g32(0x18) == 0:
        return False
    return (e.node.dst[1] if e.node else 0) + 0x60 > 0


def _beh_41F700(self, e) -> bool:
    """`0x41F700`（0x29000013）：t=[0x1C]（<0x60 时 ++）；s = [0x20] + t（[0x20] 累计）；
    y = s>>5、x += 1；node dst=(x−0x30, y−0x30)；return HP≠0 且 y < 0x210。"""
    if e.s32(0x1C) < 0x60:
        e.d32(0x1C, (e.s32(0x1C) + 1) & 0xFFFFFFFF)
    t = e.s32(0x1C)
    s = (e.s32(0x20) + t) & 0xFFFFFFFF
    e.d32(0x20, s)
    y = (s - 0x100000000 if s & 0x80000000 else s) >> 5
    e.d32(0x08, y & 0xFFFFFFFF)
    e.d32(0x04, (e.s32(0x04) + 1) & 0xFFFFFFFF)
    if e.node is not None:
        e.node.dst = (e.s32(0x04) - 0x30, y - 0x30)
    return e.g32(0x18) != 0 and y < 0x210


def _beh_419E30(self, e) -> bool:
    """`0x419E30`（0x2800000B）：[0x20] += [0x24]、[0x24]++（先升后坠）；y = [0x20]>>2、
    x −= 1；0x401BA4(4,0,0x30) 特效；node dst=(x−0x18,y−0x18)；
    return HP≠0 且 y < 0x1F8 且 [0x24] < 0。"""
    e.d32(0x20, (e.s32(0x20) + e.s32(0x24)) & 0xFFFFFFFF)
    e.d32(0x24, (e.s32(0x24) + 1) & 0xFFFFFFFF)
    s = e.s32(0x20)
    e.d32(0x08, ((s - 0x100000000 if s & 0x80000000 else s) >> 2) & 0xFFFFFFFF)
    e.d32(0x04, (e.s32(0x04) - 1) & 0xFFFFFFFF)
    self.p4_4193e0(e, 4,0,0x30)
    if e.node is not None:
        e.node.dst = (e.s32(0x04) - 0x18, e.s32(0x08) - 0x18)
    return e.g32(0x18) != 0 and (e.s32(0x08) < 0x1F8 or e.s32(0x24) < 0)


def _beh_41DCE0(self, e) -> bool:
    """`0x41DCE0`（0x29000006）：x −= 4；自机y>>1+0xF0 > y 且 y < 0x1B8 → y++；
    node dst=(x−0x18,y−0x18)；return x > −0x18 且 HP≠0。"""
    e.d32(0x04, (e.s32(0x04) - 4) & 0xFFFFFFFF)
    ty = (self.p4_player_y() >> 1) + 0xF0
    if ty > e.s32(0x08) and e.s32(0x08) < 0x1B8:
        e.d32(0x08, (e.s32(0x08) + 1) & 0xFFFFFFFF)
    if e.node is not None:
        e.node.dst = (e.s32(0x04) - 0x18, e.s32(0x08) - 0x18)
    return e.s32(0x04) > -0x18 and e.g32(0x18) != 0


def _beh_422D40(self, e) -> bool:
    """`0x422D40`（0x29000021）：HP≠0 时先置 HP=−1（命中即自灭铺垫）；
    [0x24] += [0x1C]、[0x28] += [0x20]（8.8 定点）；x=[0x24]>>8、y=[0x28]>>8；
    node dst=(x−0x10, y−0x10)；0x4305F0(e,0x10) 在屏判据；
    return HP≠0 且 在屏。"""
    if e.g32(0x18) != 0:
        e.d32(0x18, -1 & 0xFFFFFFFF)
    e.d32(0x24, (e.s32(0x24) + e.s32(0x1C)) & 0xFFFFFFFF)
    e.d32(0x28, (e.s32(0x28) + e.s32(0x20)) & 0xFFFFFFFF)
    ax = e.s32(0x24)
    ay = e.s32(0x28)
    e.d32(0x04, ((ax - 0x100000000 if ax & 0x80000000 else ax) >> 8) & 0xFFFFFFFF)
    e.d32(0x08, ((ay - 0x100000000 if ay & 0x80000000 else ay) >> 8) & 0xFFFFFFFF)
    if e.node is not None:
        e.node.dst = (e.s32(0x04) - 0x10, e.s32(0x08) - 0x10)
    return e.g32(0x18) != 0 and self.p4_4305f0(e, 0x10)


# ---------------------------------------------------------------------------
# 0x29 族高段（关8 真 boss 0x29000018 及其编队/卫星）——2026-11-11 逐函数转写。
# 依据 docs/p4_beh_29high_notes.md；反汇编 re_dis + esp_flow（0x41FC60 处 R.dis 曾失步
# 6 字节，关键序列用 capstone 直解校对）。
# ---------------------------------------------------------------------------

def _p4_idiv(a: int, b: int) -> int:
    """x86 idiv 语义（向零截断的有符号除）。"""
    if b == 0:
        return 0
    q = abs(a) // abs(b)
    return -q if (a < 0) != (b < 0) else q


def p4_409760(self, e) -> None:
    """`0x409760`（thunk 0x402478）：0x2D00001B/1C/1D 的节点朝向/尺寸同步。

    node[+0x1C]==0 → 直接返回。dx=this.x-主.x、dy=this.y-主.y；
    ang = 0x45A9A0(dy, dx)；rect.l==0xF0 → 斜率段跳过；否则 slope =
      |cos|>|sin| ? dx*8/cos : dy*8/sin；slope==0 → l=0x320、slope>=5 → l=0xF0、
      否则 l=0x190-(slope<<5)。t = ang>=0xE00 ? 0x1A0 : (ang>>3)&-0x20；
    node.rect = {l, t, l+0x1F, t+0x1F}；node.dst = (x-0x10, y-0x10)。"""
    if e.node is None or not e.node.active:
        return
    main = self.p4_links.get(e.s32(0x1C) & 0x7FFFFFFF)
    if main is None:
        return
    dx = e.s32(0x04) - main.s32(0x04)
    dy = e.s32(0x08) - main.s32(0x08)
    ang = self.p4_45a9a0(dy, dx)                    # 0x40978C 0x401091 → 0x45A9A0
    c = page4_cos(ang)
    s = page4_sin(ang)
    rect_l = e.node.rect[0]
    if rect_l != 0xF0:                              # 0x4097B2
        if abs(c) > abs(s):                         # 0x4097CB jle 取反
            slope = _p4_idiv(dx * 8, c)
        else:
            slope = _p4_idiv(dy * 8, s)
        if slope == 0:
            rect_l = 0x320                          # 0x4097F4
        elif slope >= 5:
            rect_l = 0xF0                           # 0x409805
        else:
            rect_l = 0x190 - (slope << 5)           # 0x40980C
    rect_t = 0x1A0 if ang >= 0xE00 else ((ang >> 3) & -0x20)   # 0x409816..0x409828
    e.node.rect = (rect_l, rect_t, rect_l + 0x1F, rect_t + 0x1F)
    e.node.dst = (e.s32(0x04) - 0x10, e.s32(0x08) - 0x10)


def p4_41fff0(self, e, tx: int, ty: int, spd: int) -> None:
    """`0x41FFF0`（thunk 0x401D34，ret 0xC）：从 e 位置向 (tx,ty) 发一枚 0x29000021。

    v = p4_43af90(e, spd) >> 4；inv = 0x45AA80(dx, dy)；
    vx = (inv*dx*v)>>8、vy = (inv*dy*v)>>8（0x420023..0x42003E：ecx=ang*esi(dx)、
    eax=ang*edi(dy) 各乘 spd 后 sar 8）；vx==0 且 vy==0 → 不发。
    0x29000021 ctor（0x41CB69）：+0x1C=vx、+0x20=vy、+0x24=x<<8、+0x28=y<<8、
    +0x18=|vx|+|vy|、SE 槽2 声像 (x-0x140)<<4。"""
    dx = tx - e.s32(0x04)
    dy = ty - e.s32(0x08)
    v = self.p4_43af90(e, spd) >> 4                 # 0x420010 0x401FB4 → 0x43AF90
    inv = self.p4_45aa80(dx, dy)                    # 0x42001C 0x40231F → 0x45AA80
    vx = _p4_idiv(inv * dx * v, 256)
    vy = _p4_idiv(inv * dy * v, 256)
    if vx == 0 and vy == 0:                         # 0x42003C
        return
    c = self._p4_ent43c(0x29000021, e.s32(0x04), e.s32(0x08))
    c.d32(0x1C, vx & 0xFFFFFFFF)
    c.d32(0x20, vy & 0xFFFFFFFF)
    c.d32(0x24, (e.s32(0x04) << 8) & 0xFFFFFFFF)
    c.d32(0x28, (e.s32(0x08) << 8) & 0xFFFFFFFF)
    c.d32(0x18, (abs(vx) + abs(vy)) & 0xFFFFFFFF)   # 0x41CBBC cdq/xor/sub 链
    self.p4_se_pan(2, (e.s32(0x04) - 0x140) << 4)   # 0x41CB70 0x450350(槽2,…)


def p4_41fc60(self, e, k: int) -> None:
    """`0x41FC60`（thunk 0x40102D，ret 4）：入场舱纵队——6×0x29000019。

    ctor 0x41C613：x=-0xA0、+0x1C=p3(主)、+0x20=*p0、+0x24=*(p0+4)、+0x28=*(p3+0x1C)、
    +0x2C=*p1(=k)；rect=*(p1+4)!=0?{180,F0,1AF,11F}:{180,120,1AF,14F}（此处恒非0→前者）、
    node.dst=(-0x30,-0x30)。六组 (p0[0],p0[1]) 见 0x41FC9A..0x41FD73 的 push 对。"""
    h = id(e) & 0x7FFFFFFF
    self.p4_links[h] = e
    for ox, oy in ((0x78, -0x18), (0x9C, -0x24), (0xA8, -0x48),
                   (0xAC, -0x6C), (0xA8, -0x90), (0x9C, -0xA8)):
        c = self._p4_ent43c(0x29000019, 0, 0, h)    # d_to 0x1C → +0x1C=主句柄
        c.d32(0x20, ox & 0xFFFFFFFF)
        c.d32(0x24, oy & 0xFFFFFFFF)
        c.d32(0x28, e.g32(0x1C))                    # 0x41C640 *(p3+0x1C)
        c.d32(0x2C, k & 0xFFFFFFFF)
        if c.node is not None:
            c.node.rect = (0x180, 0xF0, 0x1AF, 0x11F)
            c.node.dst = (-0x30, -0x30)


def _p4_spawn29a(self, boss, quad, k: int, rflag: int):
    """0x2900001A 生成（ctor 0x41C6E5 等价）：cur=quad01、target=quad23、+0x30=k、
    rect = rflag ? {180,F0,1AF,11F} : {180,120,1AF,14F}、node.dst=(-0x30,-0x30)。"""
    h = id(boss) & 0x7FFFFFFF
    self.p4_links[h] = boss
    c = self._p4_ent43c(0x2900001A, 0, 0, h)
    c.d32(0x20, quad[0] & 0xFFFFFFFF)
    c.d32(0x24, quad[1] & 0xFFFFFFFF)
    c.d32(0x28, quad[2] & 0xFFFFFFFF)
    c.d32(0x2C, quad[3] & 0xFFFFFFFF)
    c.d32(0x30, k & 0xFFFFFFFF)
    if c.node is not None:
        c.node.rect = ((0x180, 0xF0, 0x1AF, 0x11F) if rflag
                       else (0x180, 0x120, 0x1AF, 0x14F))
        c.node.dst = (-0x30, -0x30)
    return c


def _p4_spawn29f(self, boss, blk):
    """0x2900001F 生成（ctor 0x41C99E 等价）：+0x20=*p0、+0x24=*(p0+4)+0x18、+0x28=0、
    rect = *(p0+8) ? {180,F0,1AF,11F} : {180,120,1AF,14F}、node.dst=(-0x30,-0x30)。"""
    h = id(boss) & 0x7FFFFFFF
    self.p4_links[h] = boss
    c = self._p4_ent43c(0x2900001F, 0, 0, h)
    c.d32(0x20, blk[0] & 0xFFFFFFFF)
    c.d32(0x24, (blk[1] + 0x18) & 0xFFFFFFFF)
    if c.node is not None:
        c.node.rect = ((0x180, 0xF0, 0x1AF, 0x11F) if blk[2] != 0
                       else (0x180, 0x120, 0x1AF, 0x14F))
        c.node.dst = (-0x30, -0x30)
    return c


def _p4_spawn29t(self, boss, x: int, y: int, val: int):
    """0x29000020 生成（ctor 0x41CA67 等价）：+0x1C=*p3(主)、+0x28=*(p3+4)(val)、
    +0x20=p0(x)、+0x24=p1(y)、rect = y==-0xA8 ? if : else、node.dst=(-0x30,-0x30)。"""
    h = id(boss) & 0x7FFFFFFF
    self.p4_links[h] = boss
    c = self._p4_ent43c(0x29000020, x, y)
    c.d32(0x1C, h)
    c.d32(0x28, val & 0xFFFFFFFF)
    if c.node is not None:
        c.node.rect = ((0x180, 0xF0, 0x1AF, 0x11F) if y == -0xA8
                       else (0x180, 0x120, 0x1AF, 0x14F))
        c.node.dst = (-0x30, -0x30)
    return c


def _beh_4200C0(self, e) -> bool:
    """`0x4200C0`（0x29000018，**关8 真 boss**，thunk 0x4013C5）：九态机。

    态 = [0x1C]&0xFF（态字高字节 = 巡回 round）；跳表 0x421974。
    位置：[0x24]+=[0x2C](vx)、[0x28]+=[0x30](vy)；x=[0x24]>>2、y=[0x28]>>2；
    node dst=(x-0x78, y-0x78)（240×240）。死亡：HP==0 或 ([0x1C]&0x7FFF)>0x1800（round≥24）
    → 0x49000008 @(x,y) 入 0x4AD4CC 并 return 0。态体见 docs/p4_beh_29high_notes.md。"""
    st = e.s32(0x1C)
    state = st & 0xFF
    t = e.s32(0x20)
    if state == 0:                                    # 0x4200EA
        p4_41fc60(self, e, 0x3E8)
        e.d32(0x2C, 0)
        e.d32(0x30, 0)
    elif state == 1:                                  # 0x420103
        if t < 0x40:
            e.d32(0x2C, (t - 0x40) & 0xFFFFFFFF)
        if t == 0:                                    # 0x4214C0 公共重生门
            p4_41fc60(self, e, 0x3E8)
    elif state == 2:                                  # 0x42011A
        if e.s32(0x08) > 0x190:
            e.d32(0x30, -2 & 0xFFFFFFFF)
        elif e.s32(0x08) < 0xA0:
            e.d32(0x30, 2)
        if t == 0:
            e.d32(0x30, 2)
            p4_41fc60(self, e, 0x3E8)
            self._p4_ent43c(0x2900001B, 0x9C, -0xA8, id(e) & 0x7FFFFFFF)
    elif state == 3:                                  # 0x420192
        if 0x3C < t < 0x1A4:
            e.d32(0x2C, (page4_cos(t * 20) >> 4) & 0xFFFFFFFF)
            e.d32(0x30, (page4_sin(t * 20) >> 4) & 0xFFFFFFFF)
        if t == 0:
            for q, rf in (((0x78, -0x18, 0x78, -0x18), 0), ((0x9C, -0x24, 0xA0, -0x18), 0),
                          ((0xA8, -0x48, 0xC8, -0x18), 0), ((0xAC, -0x6C, 0xF0, -0x18), 0),
                          ((0xA8, -0x70, 0x118, -0x18), 0), ((0x9C, -0x58, 0x140, -0x18), 1)):
                _p4_spawn29a(self, e, q, 0x3C, rf)
        elif t == 0x3C:                               # 0x4203FC：16×0x2900001C 纵列
            for i in range(16):
                self._p4_ent43c(0x2900001C, i * 0x28, -0x18, id(e) & 0x7FFFFFFF)
        elif t == 0x1A4:                              # 0x42046B：再铺 6×0x2900001A
            for q, rf in (((0x78, -0x18, 0x78, -0x18), 0), ((0xA0, -0x18, 0x9C, -0x24), 0),
                          ((0xC8, -0x18, 0xA8, -0x48), 0), ((0xF0, -0x18, 0xAC, -0x6C), 0),
                          ((0x118, -0x18, 0xA8, -0x90), 0), ((0x140, -0x18, 0x9C, -0x58), 1)):
                _p4_spawn29a(self, e, q, 0x3C, rf)
    elif state == 4:                                  # 0x420677
        if t == 0:
            p4_41fc60(self, e, 0x3E8)
            self._p4_ent43c(0x2900001D, 0x9C, -0xA8, id(e) & 0x7FFFFFFF)
        if t <= 0x80 and (t & 0xF) == 0 and (st & 0x8000) == 0:
            self.spawn(self._p4_q("ui4fc"), 0x5100000A, (0x80 - t) * 5, 0x18, 0)
    elif state == 5:                                  # 0x420743
        if t == 0:
            e.d32(0x2C, 0)
            e.d32(0x30, 0)
        elif t < 0x96:
            py = self.p4_stat.get(0x56CC90, 0)
            v = e.s32(0x30)
            if e.s32(0x08) < py:
                if v < 0xC:
                    e.d32(0x30, (v + 1) & 0xFFFFFFFF)
            else:
                e.d32(0x30, (v + (0 if v <= -0xC else -1)) & 0xFFFFFFFF)
        elif t == 0x96:
            e.d32(0x2C, 0x30)
            e.d32(0x30, 0)
        elif t < 0x10E:
            v = e.s32(0x2C)
            e.d32(0x2C, (v - 2) & 0xFFFFFFFF if e.s32(0x04) > -0xC8 else 0)
        elif t == 0x10E:
            e.d32(0x24, -0x320 & 0xFFFFFFFF)
            if st & 0x8000:
                e.d32(0x28, (self.p4_stat.get(0x56CC90, 0) * 4) & 0xFFFFFFFF)
            e.d32(0x2C, 0x30)
        elif t == 0x186:
            e.d32(0x24, 0xE60)
            e.d32(0x2C, -0x40 & 0xFFFFFFFF)
        elif t > 0x186:
            v = e.s32(0x2C)
            e.d32(0x2C, (v + (1 if v != 0 else 0)) & 0xFFFFFFFF)
        if t == 0:                                    # 0x42081C
            p4_41fc60(self, e, 0x5B)
            for q in ((0x9C, -0x58, 0x9C, 0x78), (0xAC, -0x6C, 0xAC, 0x3C),
                      (0xA8, -0x48, 0xA8, 0x18), (0x9C, -0x24, 0x9C, -0xC)):
                _p4_spawn29a(self, e, q, 0x5B, 1)
        elif t == 0x5A:                               # 0x4209F9：11×0x2900001F
            for blk in ((0x9C, 0x78, 1, 0), (0xA8, 0x60, 0, 0), (0xAC, 0x3C, 0, 0),
                        (0xA8, 0x18, 0, 0), (0x9C, -0xC, 0, 0), (0x78, -0x18, 0, 0),
                        (0x9C, -0x24, 0, 0), (0xA8, -0x48, 0, 0), (0xAC, -0x6C, 0, 0),
                        (0xA8, -0x90, 0, 0), (0x9C, -0x58, 1, 0)):
                _p4_spawn29f(self, e, blk)
    elif state == 6:                                  # 0x420D2F
        if t == 0:
            e.d32(0x2C, 0)
            e.d32(0x30, (0x11 if e.s32(0x08) >= 0x118 else -0x11) & 0xFFFFFFFF)
        else:
            e.d32(0x2C, ((0x198 - e.s32(0x04)) >> 4) & 0xFFFFFFFF)
            if t & 1:
                v = e.s32(0x30)
                if e.s32(0x08) < 0x108:
                    if v < 0x12:
                        e.d32(0x30, (v + 1) & 0xFFFFFFFF)
                else:
                    e.d32(0x30, (v + (0 if v <= -0x12 else -1)) & 0xFFFFFFFF)
        if 0x5A < t < 0x258 and (t & 3) == 0:         # 0x420DA1 开火段
            c = page4_cos(t * 40)
            s = page4_sin(t * 40)
            x = e.s32(0x04) + 0x9C
            y = e.s32(0x08) - 0xA8
            if st & 0x8000:                           # 0x420DD5 八发两排
                p4_41fff0(self, e, x + c, y + s, -0x680)
                p4_41fff0(self, e, x - c, y - s, -0x680)
                p4_41fff0(self, e, x + s, y - c, -0x340)
                p4_41fff0(self, e, x - s, y + c, -0x340)
                y += 0x120                            # 0x420E61 [ebp+8]+=0x120
                p4_41fff0(self, e, x + c, y - s, -0x680)
                p4_41fff0(self, e, x - c, y + s, -0x680)
                p4_41fff0(self, e, x + s, y + c, -0x340)
                p4_41fff0(self, e, x - s, y - c, -0x340)
            else:                                     # 0x420EC2
                p4_41fff0(self, e, x, y, -0x900)
                if (t & 0x1F) == 0:
                    p4_41fff0(self, e, self.p4_stat.get(0x56CC8C, 0),
                              self.p4_stat.get(0x56CC90, 0) + 0x30, 0x400)
                y += 0x120
                p4_41fff0(self, e, x, y, -0x900)
                if (t & 0x1F) == 0:
                    p4_41fff0(self, e, self.p4_stat.get(0x56CC8C, 0),
                              self.p4_stat.get(0x56CC90, 0) - 0x30, 0x400)
        if t == 0:                                    # 0x420F4E
            p4_41fc60(self, e, 0x3E8)
            for q, rf in (((0x9C, -0x24, 0x9C, -0xC), 0), ((0xA8, -0x48, 0xA8, 0x18), 0),
                          ((0xAC, -0x6C, 0xAC, 0x3C), 0), ((0xA8, -0x70, 0xA8, 0x60), 0),
                          ((0x9C, -0x58, 0x9C, 0x78), 1)):
                _p4_spawn29a(self, e, q, 0x259, rf)
        elif t == 0x258:                              # 0x42112A
            for q, rf in (((0x9C, -0xC, 0x9C, -0x24), 0), ((0xA8, 0x18, 0xA8, -0x48), 0),
                          ((0xAC, 0x3C, 0xAC, -0x6C), 0), ((0xA8, 0x60, 0xA8, -0x70), 0),
                          ((0x9C, 0x78, 0x9C, -0x58), 1)):
                _p4_spawn29a(self, e, q, 0x5B, rf)
    elif state == 7:                                  # 0x421301
        if t < 0x5A:
            e.d32(0x2C, 0)
            v = e.s32(0x30)
            e.d32(0x30, (v - (1 if e.s32(0x08) > -0xA0 else v)) & 0xFFFFFFFF)
        elif t == 0x5A:
            e.d32(0x24, ((self.p4_stat.get(0x56CC8C, 0) * 2) if (st & 0x8000) else 0)
                  & 0xFFFFFFFF)
            e.d32(0x28, -0x280 & 0xFFFFFFFF)
            e.d32(0x30, 0x20)
        elif t < 0x12C:
            if e.s32(0x08) > 0x2A8:
                e.d32(0x30, 0)
        elif t == 0x12C:
            e.d32(0x28, 0xAA0)
            e.d32(0x30, -0x20 & 0xFFFFFFFF)
        elif t < 0x1FE:
            if e.s32(0x08) >= -0xA0:
                e.d32(0x30, 0)
        elif t == 0x1FE:
            e.d32(0x24, 0x640)
            e.d32(0x28, -0x460 & 0xFFFFFFFF)
            e.d32(0x30, 0x40)
        else:
            v = e.s32(0x30)
            e.d32(0x30, (v - (1 if v != 0 else 0)) & 0xFFFFFFFF)
        if t == 0x1E:                                 # 0x4213DF
            self.spawn(self._p4_q("ui4fc"), 0x5100000A, 0x18, 0x18, 0)
        elif t == 0xF0:
            self.spawn(self._p4_q("ui4fc"), 0x5100000A, 0x1C8, 0x18, 0)
        if 0x5A < t < 0x1FE and (t & 1) == 0:         # 0x421461
            vy = e.s32(0x30)
            wob = (8 - (t & 0xF)) if vy > 0 else ((t & 7) - 4)
            p4_41fff0(self, e, e.s32(0x04) + 0x9C + 0x18,
                      e.s32(0x08) - 0xA8 + wob, 0x380)
    elif state == 8:                                  # 0x4214DC
        e.d32(0x30, ((0x5A0 - e.s32(0x28)) >> 3) & 0xFFFFFFFF)
        if t == 0:                                    # 0x4214F7：6×0x29000020
            for x, y, val in ((0x78, -0x18, 0x3E8), (0x9C, -0x24, 0x96),
                              (0xA8, -0x48, 0x78), (0xAC, -0x6C, 0x5A),
                              (0xA8, -0x70, 0x3C), (0x9C, -0x58, 0x1E)):
                _p4_spawn29t(self, e, x, y, val)
            p4_41fc60(self, e, 0x3E8)                  # 0x4214CB（t==0 重生门）
        elif t == 0x12C:                              # 0x421609：6×0x2900001A
            for q, rf in (((0x78, -0x18, 0x78, -0x18), 0), ((0x78, -0x24, 0x9C, -0x18), 0),
                          ((0x78, -0x48, 0xA8, -0x18), 0), ((0x78, -0x6C, 0xAC, -0x18), 0),
                          ((0x78, -0x70, 0xA8, -0x18), 0), ((0x78, -0x58, 0x9C, -0x18), 1)):
                _p4_spawn29a(self, e, q, 0x3D, rf)
    # —— 公共尾 0x42180F ——
    thr = (0x40, 0, 0x10E, 0x1DF, 0x118, 0x1C6, 0x2B2, 0x24E, 0x168)
    t = e.s32(0x20)
    if t == thr[state]:
        if state == 0:                                # 0x421883
            if e.s32(0x04) > 0x280:
                e.d32(0x1C, (e.s32(0x1C) | 1) & 0xFFFFFFFF)     # → 态1
            else:
                r = rng.randrange(0x7FFFFFFF)
                e.d32(0x1C, (e.s32(0x1C) | ((r % 7) + 2)) & 0xFFFFFFFF)  # → 态2..8
            e.d32(0x20, 0)
        else:                                         # 0x42186C：round+1、态回 0
            e.d32(0x1C, ((st & 0xFF00) + 0x100) & 0xFFFFFFFF)
            e.d32(0x20, 0)
    else:
        e.d32(0x20, (t + 1) & 0xFFFFFFFF)
    e.d32(0x24, (e.s32(0x24) + e.s32(0x2C)) & 0xFFFFFFFF)
    e.d32(0x28, (e.s32(0x28) + e.s32(0x30)) & 0xFFFFFFFF)
    acc_x = e.s32(0x24)
    acc_y = e.s32(0x28)
    x = (acc_x >> 2) if acc_x >= 0 else -((-acc_x) >> 2)        # sar 2
    y = (acc_y >> 2) if acc_y >= 0 else -((-acc_y) >> 2)
    e.d32(0x04, x & 0xFFFFFFFF)
    e.d32(0x08, y & 0xFFFFFFFF)
    if e.node is not None:
        e.node.dst = (x - 0x78, y - 0x78)           # 0x4218E6
    if e.g32(0x18) != 0 and (e.s32(0x1C) & 0x7FFF) <= 0x1800:
        return True                                 # 0x42191D
    self.spawn(self._p4_q("ui4cc"), 0x49000008, e.s32(0x04), e.s32(0x08), 0)
    return False                                    # 0x42192A


def _beh_421FE0(self, e) -> bool:
    """`0x421FE0`（0x29000019 入场舱，thunk 0x401CCB）：跟随主位。

    [0x18]=-1；x=主.x+[0x20]、y=主.y+[0x24]、node dst=(x-0x18,y-0x18)；
    主死 → beh=0x401852(0x422DD0) return 1；主态字变 且 [0x2C]≠0 → [0x2C]=1；
    [0x2C]−−==0 → return 0（寿终）。"""
    main = self.p4_links.get(e.s32(0x1C) & 0x7FFFFFFF)
    e.d32(0x18, -1 & 0xFFFFFFFF)
    if main is None:
        return False
    x = main.s32(0x04) + e.s32(0x20)
    y = main.s32(0x08) + e.s32(0x24)
    e.d32(0x04, x & 0xFFFFFFFF)
    e.d32(0x08, y & 0xFFFFFFFF)
    if e.node is not None:
        e.node.dst = (x - 0x18, y - 0x18)
    if main.m[0x34] == 0:
        e.d32(0x40, 0x401852)
        e.beh = 0x422DD0
        return True
    if main.g32(0x1C) != e.g32(0x28) and e.g32(0x2C) != 0:
        e.d32(0x2C, 1)
    v = e.s32(0x2C)
    e.d32(0x2C, (v - 1) & 0xFFFFFFFF)
    return v != 1                                   # 0x422054 je（减前==1 → 死）


def _beh_422DD0(self, e) -> bool:
    """`0x422DD0`（掉落自爆，thunk 0x401852）：主亡后的舱体自由坠落。

    type≠0x29000022 → 改型并 [0x1C]=rand&0x7F；t=++[0x1C]；y+=t>>4、x-=t>>5；
    node dst=(x-0x18,y-0x18)；(t&7)==0 → 0x41000004 @(x,y) prm={rand&0x1F,rand&0x1F}
    入 0x4AD4CC；return y<0x1F8。"""
    if e.g32(0x14) != 0x29000022:
        e.d32(0x14, 0x29000022)
        e.d32(0x1C, rng.randrange(0x7FFFFFFF) & 0x7F)
    t = (e.s32(0x1C) + 1) & 0xFFFFFFFF
    e.d32(0x1C, t)
    e.d32(0x08, (e.s32(0x08) + (t >> 4)) & 0xFFFFFFFF)
    e.d32(0x04, (e.s32(0x04) - (t >> 5)) & 0xFFFFFFFF)
    if e.node is not None:
        e.node.dst = (e.s32(0x04) - 0x18, e.s32(0x08) - 0x18)
    if (t & 7) == 0:
        self.spawn(self._p4_q("ui4cc"), 0x41000004, e.s32(0x04), e.s32(0x08),
                   (rng.randrange(0x7FFFFFFF) & 0x1F, rng.randrange(0x7FFFFFFF) & 0x1F))
    return e.s32(0x08) < 0x1F8


def _beh_4220A0(self, e) -> bool:
    """`0x4220A0`（0x2900001A 编队僚机，thunk 0x401384）：缓动追随主位。

    [0x18]=-1；[0x20]+=(Δ+carry)>>4（Δ=[0x28]-[0x20]，≥0 加 0xF）、[0x24] 同理向 [0x2C]；
    x=主.x+[0x20]、y=主.y+[0x24]、node dst=(x-0x18,y-0x18)；主死 → beh=0x401852 return 1；
    [0x30]−−==0 → return 0。"""
    main = self.p4_links.get(e.s32(0x1C) & 0x7FFFFFFF)
    e.d32(0x18, -1 & 0xFFFFFFFF)
    if main is None:
        return False
    d = e.s32(0x28) - e.s32(0x20)
    e.d32(0x20, (e.s32(0x20) + ((d + 0xF if d >= 0 else d) >> 4)) & 0xFFFFFFFF)
    d = e.s32(0x2C) - e.s32(0x24)
    e.d32(0x24, (e.s32(0x24) + ((d + 0xF if d >= 0 else d) >> 4)) & 0xFFFFFFFF)
    x = main.s32(0x04) + e.s32(0x20)
    y = main.s32(0x08) + e.s32(0x24)
    e.d32(0x04, x & 0xFFFFFFFF)
    e.d32(0x08, y & 0xFFFFFFFF)
    if e.node is not None:
        e.node.dst = (x - 0x18, y - 0x18)
    if main.m[0x34] == 0:
        e.d32(0x40, 0x401852)
        e.beh = 0x422DD0
        return True
    v = e.s32(0x30)
    e.d32(0x30, (v - 1) & 0xFFFFFFFF)
    return v != 1


def _beh_422170(self, e) -> bool:
    """`0x422170`（0x2900001B 隐形追踪卫星，thunk 0x40140B）：转向自机的 pod 播撒器。

    m = (主态字>>0xF)&1 ? 5 : 3；t=[0x2C]。
    t%m==0 → 生成两只 0x29000019：A{+0x20=(0xB4-t)/m-t+0xB5, +0x24=1, +0x2C=[0x20]}
    与 B{+0x20 同-1, +0x2C=0}（rect 均 if 式、+0x28=主态字）。
    移动：步长 s=(bl?13:8)：[0x28]&1 → [0x20]+= ([0x28]&2? -s:+s)；
    否则 [0x24]+= ([0x28]&2? +s:-s)。方向修正（[0x30]<4，跳表 0x4223C0）：
      case0: y<py → dir = x≥px?3:1；case1: x>px → dir = y≥py?0:2；
      case2: y>py → dir = x≥px?3:1；case3: x<px → dir = y≥py?0:2（否则保持）。
      变向 → [0x28]=dir、[0x30]+=1。
    每帧生成 C：pod {+0x20=1, +0x24=1, +0x2C=[0x20], rect=[0x24]→if}。
    x=主.x+[0x20]、y=主.y+[0x24]（自身 node 隐藏不显示）。
    主死 → beh=0x401852 return 1；t≥0xB4 → return 0；否则 t+=1 return 1。"""
    main = self.p4_links.get(e.s32(0x1C) & 0x7FFFFFFF)
    e.d32(0x18, -1 & 0xFFFFFFFF)
    if main is None:
        return False
    st_m = main.g32(0x1C)
    bl = (st_m >> 0xF) & 1
    m = 5 if bl else 3
    t = e.s32(0x2C)
    px = self.p4_stat.get(0x56CC8C, 0)
    py = self.p4_stat.get(0x56CC90, 0)
    if t % m == 0:                                    # 0x4221E4
        off = (0xB4 - t) // m - t + 0xB5              # 0x422209 divmod + 0x422213 链
        for o2, life in ((off, e.s32(0x20)), (off - 1, 0)):   # A/B
            c = self._p4_ent43c(0x29000019, 0, 0, id(main) & 0x7FFFFFFF)
            self.p4_links[id(c) & 0x7FFFFFFF] = c
            c.d32(0x20, o2 & 0xFFFFFFFF)
            c.d32(0x24, 1)
            c.d32(0x28, st_m)
            c.d32(0x2C, life & 0xFFFFFFFF)
            if c.node is not None:
                c.node.rect = (0x180, 0xF0, 0x1AF, 0x11F)
                c.node.dst = (-0x30, -0x30)
    step = 13 if bl else 8                            # 0x42225E neg/sbb/and 5/add 8
    d = e.s32(0x28)
    if d & 1:
        e.d32(0x20, (e.s32(0x20) + (-step if (d & 2) else step)) & 0xFFFFFFFF)
    else:
        e.d32(0x24, (e.s32(0x24) + (step if (d & 2) else -step)) & 0xFFFFFFFF)
    x = main.s32(0x04) + e.s32(0x20)
    y = main.s32(0x08) + e.s32(0x24)
    e.d32(0x04, x & 0xFFFFFFFF)
    e.d32(0x08, y & 0xFFFFFFFF)
    if e.s32(0x30) < 4:                               # 0x42229B 方向修正
        nd = d
        if d == 0:
            if y < py:
                nd = 3 if x >= px else 1
        elif d == 1:
            if x > px:
                nd = 0 if y >= py else 2
        elif d == 2:
            if y > py:
                nd = 3 if x >= px else 1
        else:
            if x < px:
                nd = 0 if y >= py else 2
        if nd != d:
            e.d32(0x28, nd)
            e.d32(0x30, (e.s32(0x30) + 1) & 0xFFFFFFFF)
    # 每帧 C（0x422330）：p0={1,1}、p1={[0x20],[0x24]}
    c = self._p4_ent43c(0x29000019, 0, 0, id(main) & 0x7FFFFFFF)
    self.p4_links[id(c) & 0x7FFFFFFF] = c
    c.d32(0x20, 1)
    c.d32(0x24, 1)
    c.d32(0x28, st_m)
    c.d32(0x2C, e.s32(0x20) & 0xFFFFFFFF)
    if c.node is not None:
        c.node.rect = (0x180, 0xF0, 0x1AF, 0x11F)
        c.node.dst = (-0x30, -0x30)
    if main.m[0x34] == 0:                             # 0x42237F
        e.d32(0x40, 0x401852)
        e.beh = 0x422DD0
        return True
    if t < 0xB4:                                      # 0x422397
        e.d32(0x2C, (t + 1) & 0xFFFFFFFF)
        return True
    return False


def _beh_422470(self, e) -> bool:
    """`0x422470`（0x2900001C 弧线小机，thunk 0x401C7B）：绕主圆弧 + 随机点开火。

    aimed=(主态字>>0xF)&1；t=[0x24]；ang = (aimed ? (t<0x12C?0:t*3-0x384) : t)*20；
    x=主.x+((cos(ang)*[0x20])+0x7F>>8)+0x78、y=主.y+((sin(ang)*[0x20])+0x7F>>8)-0x18；
    t==0x5A/0x10E → 0x41FFF0(this, rand%0x280, rand%0x1E0, 0x340)；
    node dst=(x-0x18,y-0x18)；主死 → beh=0x401852 return 1；t≥0x168 → return 0。"""
    main = self.p4_links.get(e.s32(0x1C) & 0x7FFFFFFF)
    e.d32(0x18, -1 & 0xFFFFFFFF)
    if main is None:
        return False
    aimed = (main.g32(0x1C) >> 0xF) & 1
    t = e.s32(0x24)
    base = (0 if t < 0x12C else t * 3 - 0x384) if aimed else t
    ang = base * 20
    r = e.s32(0x20)
    x = main.s32(0x04) + (((page4_cos(ang) * r) + 0x7F) >> 8) + 0x78
    y = main.s32(0x08) + (((page4_sin(ang) * r) + 0x7F) >> 8) - 0x18
    e.d32(0x04, x & 0xFFFFFFFF)
    e.d32(0x08, y & 0xFFFFFFFF)
    if t == 0x5A or t == 0x10E:                       # 0x4224F6
        r1 = rng.randrange(0x7FFFFFFF)
        r2 = rng.randrange(0x7FFFFFFF)
        p4_41fff0(self, e, r2 % 0x280, r1 % 0x1E0, 0x340)
    if e.node is not None:
        e.node.dst = (x - 0x18, y - 0x18)
    if main.m[0x34] == 0:
        e.d32(0x40, 0x401852)
        e.beh = 0x422DD0
        return True
    if t >= 0x168:                                    # 0x42256A
        return False
    e.d32(0x24, (t + 1) & 0xFFFFFFFF)
    return True


def _beh_4225E0(self, e) -> bool:
    """`0x4225E0`（0x2900001D 下降卫星，thunk 0x40209F）：先降后升 + 双段 pod 播撒。

    t=[0x28]；t%5==0 且 t<0x3C → pod{+0x20=[0x20],+0x24=[0x24],+0x2C=2*(0x87-t),rect else}；
    t<0x3C → [0x20]-=4、[0x24]-=7；t≥0xD2 → [0x20]+=4、[0x24]+=7；
    x=主.x+[0x20]、y=主.y+[0x24]、node dst=(x-0x18,y-0x18)；
    每帧 pod{+0x20=[0x20],+0x24=[0x24],+0x2C=1,rect if}；
    t==0x3C → 14×0x2900001E @(0x280, y=-0x18-0x28*i)（i=0..13，y>−0x230 门）prm=主；
    主死 → beh=0x401852 return 1；return [0x24]!=-0xA8。"""
    main = self.p4_links.get(e.s32(0x1C) & 0x7FFFFFFF)
    e.d32(0x18, -1 & 0xFFFFFFFF)
    if main is None:
        return False
    st_m = main.g32(0x1C)
    t = e.s32(0x28)
    if t % 5 == 0 and t < 0x3C:                       # 0x422649
        c = self._p4_ent43c(0x29000019, 0, 0, id(main) & 0x7FFFFFFF)
        self.p4_links[id(c) & 0x7FFFFFFF] = c
        c.d32(0x20, e.g32(0x20))
        c.d32(0x24, e.g32(0x24))
        c.d32(0x28, st_m)
        c.d32(0x2C, (2 * (0x87 - t)) & 0xFFFFFFFF)
        if c.node is not None:
            c.node.rect = (0x180, 0x120, 0x1AF, 0x14F)
            c.node.dst = (-0x30, -0x30)
    if t < 0x3C:                                      # 0x422693
        e.d32(0x20, (e.s32(0x20) - 4) & 0xFFFFFFFF)
        e.d32(0x24, (e.s32(0x24) - 7) & 0xFFFFFFFF)
    elif t >= 0xD2:                                   # 0x4226A4
        e.d32(0x20, (e.s32(0x20) + 4) & 0xFFFFFFFF)
        e.d32(0x24, (e.s32(0x24) + 7) & 0xFFFFFFFF)
    x = main.s32(0x04) + e.s32(0x20)
    y = main.s32(0x08) + e.s32(0x24)
    e.d32(0x04, x & 0xFFFFFFFF)
    e.d32(0x08, y & 0xFFFFFFFF)
    if e.node is not None:
        e.node.dst = (x - 0x18, y - 0x18)
    c = self._p4_ent43c(0x29000019, 0, 0, id(main) & 0x7FFFFFFF)   # 0x4226DA 每帧 pod
    self.p4_links[id(c) & 0x7FFFFFFF] = c
    c.d32(0x20, e.g32(0x20))
    c.d32(0x24, e.g32(0x24))
    c.d32(0x28, st_m)
    c.d32(0x2C, 1)
    if c.node is not None:
        c.node.rect = (0x180, 0xF0, 0x1AF, 0x11F)
        c.node.dst = (-0x30, -0x30)
    if t == 0x3C:                                     # 0x42270A：0x2900001E 纵列
        yk = -0x18
        while yk > -0x230:
            self._p4_ent43c(0x2900001E, 0x280, yk, id(main) & 0x7FFFFFFF)
            yk -= 0x28
    e.d32(0x28, (t + 1) & 0xFFFFFFFF)
    if main.m[0x34] == 0:                             # 0x422773
        e.d32(0x40, 0x401852)
        e.beh = 0x422DD0
        return True
    return e.s32(0x24) != -0xA8                       # 0x422791 setne


def _beh_422830(self, e) -> bool:
    """`0x422830`（0x2900001E 阶梯下落小机，thunk 0x401474）：竖直坠落 + 每 16 帧变向。

    y+=[0x20]、node dst.y+=[0x20]；aimed=(主态字>>0xF)&1；t=[0x24]+1；
    t%16==8 → [0x20]=-0x40；elif t%16==0 → [0x20]=0x40 且
    （aimed ? (node dst.x=px-0x18, x=px) : (node dst.x-=0x50, x-=0x50)）；
    主死 → beh=0x401852 return 1；return t<=0x90。"""
    main = self.p4_links.get(e.s32(0x1C) & 0x7FFFFFFF)
    e.d32(0x18, -1 & 0xFFFFFFFF)
    if main is None:
        return False
    v = e.s32(0x20)
    e.d32(0x08, (e.s32(0x08) + v) & 0xFFFFFFFF)
    if e.node is not None:
        e.node.dst = (e.node.dst[0], e.node.dst[1] + v)     # 0x422855 node+0x18 += [0x20]
    aimed = (main.g32(0x1C) >> 0xF) & 1
    t = (e.s32(0x24) + 1) & 0xFFFFFFFF
    e.d32(0x24, t)
    if t % 16 == 8:                                   # 0x42287C
        e.d32(0x20, -0x40 & 0xFFFFFFFF)
    elif t % 16 == 0:                                 # 0x422899
        e.d32(0x20, 0x40)
        if aimed:                                     # 0x4228A8
            px = self.p4_stat.get(0x56CC8C, 0)
            if e.node is not None:
                e.node.dst = (px - 0x18, e.node.dst[1])
            e.d32(0x04, px & 0xFFFFFFFF)
        else:                                         # 0x4228BE
            if e.node is not None:
                e.node.dst = (e.node.dst[0] - 0x50, e.node.dst[1])
            e.d32(0x04, (e.s32(0x04) - 0x50) & 0xFFFFFFFF)
    if main.m[0x34] == 0:                             # 0x4228D6
        e.d32(0x40, 0x401852)
        e.beh = 0x422DD0
        return True
    return t <= 0x90                                  # 0x4228F8 setle


def _beh_422950(self, e) -> bool:
    """`0x422950`（0x2900001F 摆动小机，thunk 0x401F6E）：固定 x、纵向 cos 摆 + 定点开火。

    [0x18]=-1；x=[0x20]+主.x；n=[0x28]&0xF；
    y=((cos(113*n)*[0x24])>>8)+主.y-0x18；
    |[0x24]|==0x90 且 0xB4<[0x28]<0x12C 且 [0x28]&3==0 →
      aimed ? 0x41FFF0(this,px,py,0x340) : 0x41FFF0(this,this.x,([0x28]&4?0x1E0:0),0x340)；
    node dst=(x-0x18,y-0x18)；主死 → beh=0x401852 return 1；
    [0x28]≥0x12C → return 0；else ++[0x28] return 1。"""
    main = self.p4_links.get(e.s32(0x1C) & 0x7FFFFFFF)
    e.d32(0x18, -1 & 0xFFFFFFFF)
    if main is None:
        return False
    aimed = (main.g32(0x1C) >> 0xF) & 1
    t = e.s32(0x28)
    n = t & 0xF
    x = e.s32(0x20) + main.s32(0x04)
    y = _p4_idiv(page4_cos(113 * n) * e.s32(0x24), 256) + main.s32(0x08) - 0x18
    e.d32(0x04, x & 0xFFFFFFFF)
    e.d32(0x08, y & 0xFFFFFFFF)
    if abs(e.s32(0x24)) == 0x90 and 0xB4 < t < 0x12C and (t & 3) == 0:
        if aimed:                                     # 0x4229CE
            p4_41fff0(self, e, self.p4_stat.get(0x56CC8C, 0),
                      self.p4_stat.get(0x56CC90, 0), 0x340)
        else:                                         # 0x4229DE
            p4_41fff0(self, e, x, (0x1E0 if (t & 4) else 0), 0x340)
    if e.node is not None:
        e.node.dst = (x - 0x18, y - 0x18)
    if main.m[0x34] == 0:                             # 0x422A14
        e.d32(0x40, 0x401852)
        e.beh = 0x422DD0
        return True
    if t >= 0x12C:                                    # 0x422A29
        return False
    e.d32(0x28, (t + 1) & 0xFFFFFFFF)
    return True


def _beh_422A90(self, e) -> bool:
    """`0x422A90`（0x29000020 卫星环射体，thunk 0x401A82）：先跟主、t 归零后下坠、
    低处环形 5 连弹后自灭。

    aimed=(主态字>>0xF)&1；[0x18]≠0 → [0x18]=-1（免伤）；t=[0x28]-1；
    t>0 → x=主.x+[0x20]、y=主.y+[0x24]；t==0 → [0x20]=0、[0x24]=-0x112；
    t<0 → x+=[0x20]、[0x24]+=1、y+=[0x24]、[0x20]+= (x<=0x140?1:-1)。
    node dst=(x-0x18,y-0x18)；[0x18]==0 或 t==0x29E → return 0；
    t<0 且 [0x24]>0 且 (2y>py+0x1E0 或 y>0x1B8) → 环射：
      spd=0x340+(aimed?0x200:0)；k=0.. while 0x340+0x80k<=spd：d=(px-x,py-y)
        (px,py, -(0x340+0x80k))；player+(dy,-dx)；player+(-dy,dx)；
        player+2(dy,-dx)；player+(dx-dy,dx+dy)——各 spd=0x340+0x80k
      → return 0（射完自灭）。"""
    main = self.p4_links.get(e.s32(0x1C) & 0x7FFFFFFF)
    if main is None:
        return False
    aimed = (main.g32(0x1C) >> 0xF) & 1
    if e.g32(0x18) != 0:                              # 0x422AA7
        e.d32(0x18, -1 & 0xFFFFFFFF)
    t = (e.s32(0x28) - 1) & 0xFFFFFFFF
    e.d32(0x28, t)
    ts = t - 0x100000000 if t & 0x80000000 else t
    if ts > 0:                                        # 0x422ABF
        e.d32(0x04, (main.s32(0x04) + e.s32(0x20)) & 0xFFFFFFFF)
        e.d32(0x08, (main.s32(0x08) + e.s32(0x24)) & 0xFFFFFFFF)
    elif ts == 0:                                     # 0x422ADA
        e.d32(0x20, 0)
        e.d32(0x24, -0x112 & 0xFFFFFFFF)
    else:                                             # 0x422B3A
        e.d32(0x04, (e.s32(0x04) + e.s32(0x20)) & 0xFFFFFFFF)
        e.d32(0x24, (e.s32(0x24) + 1) & 0xFFFFFFFF)
        e.d32(0x08, (e.s32(0x08) + e.s32(0x24)) & 0xFFFFFFFF)
        v = e.s32(0x20)
        e.d32(0x20, (v + (1 if e.s32(0x04) <= 0x140 else -1)) & 0xFFFFFFFF)
    x = e.s32(0x04)
    y = e.s32(0x08)
    if e.node is not None:
        e.node.dst = (x - 0x18, y - 0x18)             # 0x422AE8
    if main.m[0x34] == 0:                             # 0x422AE8 父死 → 切掉落自爆行为
        e.d32(0x40, 0x401852)
        e.beh = 0x422DD0
    if e.g32(0x18) == 0 or ts == 0x29E:               # 0x422B15
        return False
    if ts >= 0:                                       # 0x422B66 jge → 存活尾
        return True
    if e.s32(0x24) <= 0:                              # 0x422B71
        return True
    py = self.p4_stat.get(0x56CC90, 0)
    if not (2 * y > py + 0x1E0 or y > 0x1B8):         # 0x422B8B
        return True
    spd = 0x340 + (0x200 if aimed else 0)             # 0x422B9B
    k = 0
    while 0x340 + 0x80 * k <= spd:                    # 0x422C82 jle
        sp = 0x340 + 0x80 * k
        px = self.p4_stat.get(0x56CC8C, 0)
        py = self.p4_stat.get(0x56CC90, 0)
        dx = px - x
        dy = py - y
        p4_41fff0(self, e, px, py, -sp)               # 0x422BEC 朝自机负速
        p4_41fff0(self, e, px + dy, py - dx, sp)      # 0x422C05 player+rot-90(d)
        p4_41fff0(self, e, px - dy, py + dx, sp)      # 0x422C1F player+rot+90(d)
        p4_41fff0(self, e, px + dx + dy, py + dy - dx, sp)  # 0x422C46 player+(dx+dy, dy-dx)
        p4_41fff0(self, e, px + dx - dy, py + dx + dy, sp)  # 0x422C66 player+2rot+45(d)
        k += 1
    return False                                      # 0x422C92 射完自灭


def _beh_40A020(self, e) -> bool:
    """`0x40A020`（0x2D00001C/1D 环轨部件，thunk 0x4014AB）：随主 → 角度收敛环轨 →
    0xC8 帧散开（HP=0xA）→ 直线飞出屏。

    主=[0x1C]；主死 → return 0；[0x30]==0 且 [0x2C]<0xA → 链生一只自身
    （rec={主, self, type, [0x2C]+1}；子 +0x24=主[0x20]、+0x28=p3*450、+0x2C=p3）。
    [0x20]!=0（环轨）：word[0x28] 收敛到 word[主+0x28]（±1800 环绕、word[0x2A] ±5/±10）、
    word[0x28]+=word[0x2A]；x8.4=word[主+0x24]低16+(7*(cos我+cos主))>>3、y8.4 同理 sin；
    x/y = (short)x8.4>>4；word[0x24]=x8.4、word[0x26]=y8.4；
    type==0x2D00001C 且 [0x30]==0xC8 → 散开：[0x2C]=((sin&~1)<<15)|((cos>>1)&0xFFFF)
    （rand%3600 的 sin/cos）、[0x20]=0、[0x18]=0xA（HP=0xA，可击破）；
    0x409760 节点同步；[0x30]++；主死 → return 0。
    [0x20]==0 且 [0x2C]!=0（自由飞）：word[0x24/26]+=word[0x2C/2E]；x/y=(short)>>4；
    0x409760；0x4305F0(e,0x10) 不在屏 或 HP==0 → return 0。
    待机（[0x20]==0 且 [0x2C]==0）：[0x24]=主[0x20]（打包位）、x=(short)低16>>4、
    y=(short)高16>>4；[0x30]++；return [0x30]<0xCA（0x2D00001B 分支对本型不可达）。"""
    links = self.p4_links
    main = links.get(e.s32(0x1C) & 0x7FFFFFFF)
    if main is None or main.m[0x34] == 0:             # 0x40A033
        return False
    typ = e.g32(0x14)
    if e.s32(0x30) == 0 and e.s32(0x2C) < 0xA:        # 0x40A044 链生
        c = self._p4_ent43c(typ, id(main) & 0x7FFFFFFF, id(e) & 0x7FFFFFFF,
                            (e.s32(0x2C) + 1) & 0xFFFFFFFF)
        links[id(c) & 0x7FFFFFFF] = c
        links[id(main) & 0x7FFFFFFF] = main
        c.d32(0x24, main.g32(0x20))                   # 0x40835C *(p0+0x20)
        c.d32(0x28, ((e.s32(0x2C) + 1) * 450) & 0xFFFFFFFF)   # 0x40836A
        c.d32(0x2C, (e.s32(0x2C) + 1) & 0xFFFFFFFF)   # 0x408385
        if c.node is not None:
            c.node.rect = (0, 0, 0, 0)
            c.node.dst = (0, 0)
    if e.s32(0x20) != 0:                              # 0x40A0FD 环轨
        pa = main.g16(0x28)
        pa = pa - 0x10000 if pa & 0x8000 else pa
        ma = e.g16(0x28)
        ma = ma - 0x10000 if ma & 0x8000 else ma
        diff = pa - ma                                # 0x40A107
        if diff > 0x708:                              # 0x40A109 环绕归一（/45 魔数）
            diff -= ((diff + 0x707) // 45) * 360
        if diff <= -0x708:
            diff += ((0x708 - diff) // 45) * 360
        va = e.g16(0x2A)                              # 0x40A15C 角速度修正
        vas = va - 0x10000 if va & 0x8000 else va
        if diff > 0:
            vas = vas + 0xA if vas < 0 else (vas if vas >= 0x3C else vas + 5)
        elif diff < 0:
            vas = vas - 0xA if vas > 0 else (vas if vas <= -0x3C else vas - 5)
        e.d16(0x2A, vas & 0xFFFF)
        ma = (ma + vas) & 0xFFFF                      # 0x40A19A word[0x28]+=word[0x2A]
        e.d16(0x28, ma)
        mas = ma - 0x8000 if ma & 0x8000 else ma
        cs = page4_cos(mas) + page4_cos(pa)
        sn = page4_sin(mas) + page4_sin(pa)
        x84 = (e.g16(0x24) - 0x10000 if e.g16(0x24) & 0x8000 else e.g16(0x24)) \
            + ((cs * 7) >> 3)
        y84 = (e.g16(0x26) - 0x10000 if e.g16(0x26) & 0x8000 else e.g16(0x26)) \
            + ((sn * 7) >> 3)
        x84 = (x84 - 0x10000 if x84 & 0x8000 else x84) & 0xFFFF
        y84 = (y84 - 0x10000 if y84 & 0x8000 else y84) & 0xFFFF
        e.d16(0x24, x84)
        e.d16(0x26, y84)
        e.d32(0x04, ((x84 - 0x8000 if x84 & 0x8000 else x84) >> 4) & 0xFFFFFFFF)
        e.d32(0x08, ((y84 - 0x8000 if y84 & 0x8000 else y84) >> 4) & 0xFFFFFFFF)
        if typ == 0x2D00001C and e.s32(0x30) == 0xC8:  # 0x40A215 散开
            r = rng.randrange(0x7FFFFFFF)
            ang = r % 0xE10
            sv = page4_sin(ang)
            cv = page4_cos(ang)
            e.d32(0x2C, (((sv & -2) << 15) | ((cv >> 1) & 0xFFFF)) & 0xFFFFFFFF)
            e.d32(0x20, 0)                            # 0x40A296
            e.d32(0x18, 0xA)                          # HP=0xA（可击破）
        p4_409760(self, e)                            # 0x40A2C0
        e.d32(0x30, (e.s32(0x30) + 1) & 0xFFFFFFFF)
        if e.s32(0x20) == 0:                          # 0x40A2CC 散开当帧仍存活
            return True
        return main.m[0x34] != 0                      # 0x40A2D3 主死 → 0
    if e.s32(0x2C) != 0:                              # 0x40A2E8 自由飞
        w24 = (e.g16(0x24) + e.g16(0x2C)) & 0xFFFF
        w26 = (e.g16(0x26) + e.g16(0x2E)) & 0xFFFF
        e.d16(0x24, w24)
        e.d16(0x26, w26)
        e.d32(0x04, ((w24 - 0x8000 if w24 & 0x8000 else w24) >> 4) & 0xFFFFFFFF)
        e.d32(0x08, ((w26 - 0x8000 if w26 & 0x8000 else w26) >> 4) & 0xFFFFFFFF)
        p4_409760(self, e)                            # 0x40A314
        if not self.p4_4305f0(e, 0x10):               # 0x40A319
            return False
        return e.g32(0x18) != 0                       # 0x40A326
    # 待机（[0x20]==0 且 [0x2C]==0）0x40A097
    packed = main.g32(0x20)
    e.d32(0x24, packed)                               # 0x40A0B4
    lo = packed & 0xFFFF
    hi = (packed >> 16) & 0xFFFF
    e.d32(0x04, ((lo - 0x8000 if lo & 0x8000 else lo) >> 4) & 0xFFFFFFFF)
    e.d32(0x08, ((hi - 0x8000 if hi & 0x8000 else hi) >> 4) & 0xFFFFFFFF)
    e.d32(0x30, (e.s32(0x30) + 1) & 0xFFFFFFFF)       # 0x40A0C7
    return e.s32(0x30) < 0xCA                         # 0x40A0EA



def _beh_40EBB0(self, e) -> bool:
    """`0x40EBB0`（0x2300000B，thunk 0x401D75）：左飘机——首帧生 0x2300000C 随从、
    每 0x80 帧 0x1F 相位朝自机发弹、t=0x1E0 起加速。

    t=[0x1C]++；t==0 → 0x2300000C @(x,y) prm=0 入 0x4AD43C；t==0x1E0 → [0x20]=1；
    (t&0x7F)==0x1F → 0x43B070(this,0)（朝自机弹）；[0x20]≠0 → ++[0x20]；
    [0x24] += (y>0xF0 ? -1 : +1)；x += [0x20]>>1；y += [0x24]>>4；
    node dst=(x-0x18,y-0x18)；return x<0x298 且 HP≠0。"""
    t = e.s32(0x1C)
    e.d32(0x1C, (t + 1) & 0xFFFFFFFF)
    if t == 0:                                        # 0x40EBC4
        h = id(e) & 0x7FFFFFFF
        self.p4_links[h] = e
        self._p4_ent43c(0x2300000C, e.s32(0x04), e.s32(0x08), h)   # 0x40EBCB push ebx=父
    elif (t + 1) == 0x1E0:                            # 0x40EBFF cmp ecx(新 t),0x1E0
        e.d32(0x20, 1)
    elif ((t + 1) & 0x7F) == 0x1F:                    # 0x40EC10 and ecx(新 t),0x7F
        self.p4_43B070(e, 0)
    if e.s32(0x20) != 0:                              # 0x40EC21
        e.d32(0x20, (e.s32(0x20) + 1) & 0xFFFFFFFF)
    v = e.s32(0x24)
    e.d32(0x24, (v + (-1 if e.s32(0x08) > 0xF0 else 1)) & 0xFFFFFFFF)
    e.d32(0x04, (e.s32(0x04) + (e.s32(0x20) >> 1)) & 0xFFFFFFFF)   # sar 1
    e.d32(0x08, (e.s32(0x08) + (e.s32(0x24) >> 4)) & 0xFFFFFFFF)   # sar 4
    if e.node is not None:
        e.node.dst = (e.s32(0x04) - 0x18, e.s32(0x08) - 0x18)
    return e.s32(0x04) < 0x298 and e.g32(0x18) != 0


def _beh_40ECE0(self, e) -> bool:
    """`0x40ECE0`（0x2300000C，thunk 0x401609）：随从——[0x1C] 指向 0x2300000B 主。

    [0x1C]==0 → x-=8；主死 → [0x1C]=0；否则 目标 = 主位 + (自机-主位)>>2，
    x += (目标x-x+4)>>3、y += (目标y-y+4)>>3；node dst=(x-0x18,y-0x18)；
    return 0x4305F0(this,0x18) 在屏 且 HP≠0。"""
    t = e.s32(0x1C)
    if t == 0:                                        # 0x40ECEA
        e.d32(0x04, (e.s32(0x04) - 8) & 0xFFFFFFFF)
    else:
        main = self.p4_links.get(t & 0x7FFFFFFF)
        if main is None or main.m[0x34] == 0:         # 0x40ECF0
            e.d32(0x1C, 0)
        else:
            px = self.p4_stat.get(0x56CC8C, 0)
            py = self.p4_stat.get(0x56CC90, 0)
            tx = main.s32(0x04)
            ty = main.s32(0x08)
            gx = tx + ((px - tx) >> 2)                # 0x40ED00 链
            gy = ty + ((py - ty) >> 2)
            e.d32(0x04, (e.s32(0x04) + ((gx - e.s32(0x04) + 4) >> 3)) & 0xFFFFFFFF)
            e.d32(0x08, (e.s32(0x08) + ((gy - e.s32(0x08) + 4) >> 3)) & 0xFFFFFFFF)
    if e.node is not None:
        e.node.dst = (e.s32(0x04) - 0x18, e.s32(0x08) - 0x18)
    return self.p4_4305f0(e, 0x18) and e.g32(0x18) != 0


_P40F190_SCHED = (0, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 1,
                  4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 2,
                  4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 3)


def _beh_40F190(self, e) -> bool:
    """`0x40F190`（0x23000010 中 boss，thunk 0x402040）：入场（HP 0x40 步泻 + 放大）
    → x≥0x78 且未受伤 → 待机；受伤 → 闪光帧（rect 滚动 + 半径+0xA + dst 左上移）；
    t==0x60 → SE(4) + 8 向 0x43B290 环（45° 步）。

    HP≠0xC1 → x 步 5 否则 2；x-=步；HP≠0xC1 → node.dst.x += -5 否则 -2；
    HP==0 → return 0；x≥0x78 且 [0x28]==HP → return 1（未受伤待机）；
    t=[0x1C]；t≠0x60 → [0xC]+=0xA、[0x28]-=0x40、HP=[0x28]、
      **rect += (0, t, 0x14, t+0x14)**（0x45A790 的压栈序是 db,dr,dt,dl）、
      node.dst += (-0xA,-0xA)、t+=0x14；
    t==0x60 → SE(4,(x-0x140)<<4) + for a in 0,0x1C2..<0xE10: 0x43B290(e,cos(a),sin(a),0)、return 0。"""
    hp = e.s32(0x18)
    step = 5 if hp != 0xC1 else 2
    e.d32(0x04, (e.s32(0x04) - step) & 0xFFFFFFFF)      # 0x40F1B1
    if e.node is not None:
        # 0x40F1B6..0x40F1C7：neg/sbb/and 0xFD/add -2 ⇒ 受伤 -5、未受伤 -2
        e.node.dst = (e.node.dst[0] + (-5 if hp != 0xC1 else -2), e.node.dst[1])
    hp = e.s32(0x18)                                    # 0x40F1CA 重读
    if hp == 0:
        return False
    x = e.s32(0x04)
    if x >= 0x78 and e.s32(0x28) == hp:                 # 0x40F1D6 未受伤待机
        return True
    t = e.s32(0x1C)
    if t != 0x60:                                       # 0x40F237 闪光/泻血帧
        e.d32(0x0C, (e.s32(0x0C) + 0xA) & 0xFFFFFFFF)
        v28 = (e.s32(0x28) - 0x40) & 0xFFFFFFFF
        e.d32(0x28, v28)
        e.d32(0x18, v28)                                # HP=[0x28]
        if e.node is not None:
            r = e.node.rect
            # 0x40F249..0x40F25C：push (t+0x14), 0x14, t, 0 → 0x45A790 的
            # (rect, dl=0, dt=t, dr=0x14, db=t+0x14)。旧实现把 r/b 的增量写反，
            # 受伤帧变成一条 20px 高的横带 ⇒「怒只剩上半截」（用户实测）。
            e.node.rect = (r[0], r[1] + t, r[2] + 0x14, r[3] + t + 0x14)   # 0x401A0A
            e.node.dst = (e.node.dst[0] - 0xA, e.node.dst[1] - 0xA)        # 0x401415
        e.d32(0x1C, (t + 0x14) & 0xFFFFFFFF)
        return True                                     # 0x40F27D
    # t==0x60：SE + 8 向环（0x40F1EF）
    self.p4_se_pan(4, (e.s32(0x04) - 0x140) << 4)
    a = 0
    while a < 0xE10:
        p4_43B290(self, e, page4_cos(a), page4_sin(a), 0)
        a += 0x1C2
    return False


def _beh_40F2D0(self, e) -> bool:
    """`0x40F2D0`（0x23000011 瞬移小机，thunk 0x401DC5）：待机闪烁计时 →
    0xF 碰撞开 / 0x1F 朝自机弹 / 0x2F 碰撞关 / 0x3F 瞬移（0x50 格步）×5 后改慢移。

    [0x24]++；[0x1C]==0 且 [0x20]==0（待机）：t&3==3 → rect.l/r ±0x30（t≤0x1F 加否则减）；
    0xF≤t≤0x4E → 调度 _P40F190_SCHED[t-0xF]（0=+0x10 碰撞、1=0x43B070(this,0)、
    2=清 0x10、3=瞬移、4=无）；瞬移：[0x1C]=(0x140+rand%0x140-x)/0x50、
    [0x20]=(0x28+rand%0x190-y)/0x50、[0x28]++、[0x24]=0、[0x28]>5 → [0x1C]=0x10。
    移动态：t==0x50 → [0x1C]=[0x20]=[0x24]=0。
    x+=[0x1C]、y+=[0x20]、node dst+=(同)；return x≤0x298 且 HP≠0。"""
    t = (e.s32(0x24) + 1) & 0xFFFFFFFF
    e.d32(0x24, t)
    if e.s32(0x1C) == 0 and e.s32(0x20) == 0:         # 0x40F2F6 待机
        if (t & 3) == 3 and e.node is not None:       # 0x40F2FB rect 脉冲
            dl = 0x30 if t <= 0x1F else -0x30
            r = e.node.rect
            e.node.rect = (r[0] + dl, r[1], r[2] + dl, r[3])
        d = t - 0xF
        if 0 <= d <= 0x30:                            # 0x40F32E ja（无符号界）
            act = _P40F190_SCHED[d]
            if act == 0:                              # 0x40F346
                e.m[0x10] = 1
            elif act == 1:                            # 0x40F34F
                self.p4_43B070(e, 0)
            elif act == 2:                            # 0x40F35C
                e.m[0x10] = 0
            elif act == 3:                            # 0x40F364 瞬移
                r = rng.randrange(0x7FFFFFFF)
                q1, r1 = divmod(r, 0x140)
                e.d32(0x1C, _idiv_trunc(0x140 + r1 - e.s32(0x04), 0x50) & 0xFFFFFFFF)
                r = rng.randrange(0x7FFFFFFF)
                q3, r3 = divmod(r, 0x190)
                e.d32(0x20, _idiv_trunc(0x28 + r3 - e.s32(0x08), 0x50) & 0xFFFFFFFF)
                v28 = (e.s32(0x28) + 1) & 0xFFFFFFFF
                e.d32(0x28, v28)
                e.d32(0x24, 0)
                if v28 > 5:
                    e.d32(0x1C, 0x10)                 # 0x40F3D4
    else:                                             # 0x40F3DD 移动态
        if t == 0x50:
            e.d32(0x1C, 0)
            e.d32(0x20, 0)
            e.d32(0x24, 0)
    dx = e.s32(0x1C)
    dy = e.s32(0x20)
    e.d32(0x04, (e.s32(0x04) + dx) & 0xFFFFFFFF)
    e.d32(0x08, (e.s32(0x08) + dy) & 0xFFFFFFFF)
    if e.node is not None:
        e.node.dst = (e.node.dst[0] + dx, e.node.dst[1] + dy)   # 0x40F402 0x401415
    return e.s32(0x04) <= 0x298 and e.g32(0x18) != 0




def _beh_4070E0(self, e) -> bool:
    """`0x4070E0`（0x2C000011）：[0x24]+=[0x1C]、[0x28]+=[0x20]（8.8 定点）；
    x=[0x24]>>8、y=[0x28]>>8；node dst=(x−[0xC], y−[0xC])（[0xC]=半径偏置）；
    0x430640(e) 在屏 → node[+0x1C]=1；死门 = (不在屏 且 node[+0x1C]≠0) 或 HP=0。"""
    e.d32(0x24, (e.s32(0x24) + e.s32(0x1C)) & 0xFFFFFFFF)
    e.d32(0x28, (e.s32(0x28) + e.s32(0x20)) & 0xFFFFFFFF)
    ax = e.s32(0x24)
    ay = e.s32(0x28)
    x = (ax - 0x100000000 if ax & 0x80000000 else ax) >> 8
    y = (ay - 0x100000000 if ay & 0x80000000 else ay) >> 8
    e.d32(0x04, x & 0xFFFFFFFF)
    e.d32(0x08, y & 0xFFFFFFFF)
    r = e.s32(0x0C)
    if e.node is not None:
        e.node.dst = (x - r, y - r)
    on = self.p4_430640(e)                      # 0x401D02 → 0x430640
    if on and e.node is not None:
        e.node.active = 1                       # byte[node+0x1C] = 1
    if e.g32(0x18) == 0:
        return False
    if not on and e.node is not None and e.node.active:
        return False
    return True


def _beh_4197B0(self, e) -> bool:
    """`0x4197B0`（0x28000005）：x −= 4、y = [0x20]；0x401BA4(0x10,1,0x30) 特效；
    [0x24]≠0 → ++[0x28]，([0x24] & [0x28])==0 → 0x43B070(e,0)；
    node dst=(x−0x18,y−0x18)；return HP≠0 且 x > −0x18。"""
    e.d32(0x04, (e.s32(0x04) - 4) & 0xFFFFFFFF)
    e.d32(0x08, e.s32(0x20) & 0xFFFFFFFF)
    self.p4_4193e0(e, 0x10,1,0x30)
    if e.s32(0x24) != 0:
        c = (e.s32(0x28) + 1) & 0xFFFFFFFF
        e.d32(0x28, c)
        if (e.s32(0x24) & c) == 0:
            self.p4_43B070(e, 0)
    if e.node is not None:
        e.node.dst = (e.s32(0x04) - 0x18, e.s32(0x08) - 0x18)
    return e.g32(0x18) != 0 and e.s32(0x04) > -0x18


def _beh_41A180(self, e) -> bool:
    """`0x41A180`（0x2800000F）：x += 3、y = [0x20]；0x401BA4(0x18,1,0x30) 特效；
    [0x24]≠0 → ++[0x28]，([0x28]&0x7F)==0 且 x > 0xF0 → 0x43B070(e,0)；
    node dst=(x−0x18,y−0x18)；return HP≠0 且 x < 0x298。"""
    e.d32(0x04, (e.s32(0x04) + 3) & 0xFFFFFFFF)
    e.d32(0x08, e.s32(0x20) & 0xFFFFFFFF)
    self.p4_4193e0(e, 0x18,1,0x30)
    if e.s32(0x24) != 0:
        c = (e.s32(0x28) + 1) & 0xFFFFFFFF
        e.d32(0x28, c)
        if (c & 0x7F) == 0 and e.s32(0x04) > 0xF0:
            self.p4_43B070(e, 0)
    if e.node is not None:
        e.node.dst = (e.s32(0x04) - 0x18, e.s32(0x08) - 0x18)
    return e.g32(0x18) != 0 and e.s32(0x04) < 0x298


def _beh_413930(self, e) -> bool:
    """`0x413930`（0x2500000A）：[0x1C] −= [0x24]（横衰减）；[0x20] += ([0x2C]?−[0x28]:
    +[0x28])；[0x28] > −0x60 → [0x28]−−；x=[0x1C]>>4、y=[0x20]>>4；
    node dst=(x−0x18,y−0x18)；HP≠0 且（[0x2C]≠0 → y<0x1F8；否则 y>−0x18）。"""
    t = (e.s32(0x1C) - e.s32(0x24)) & 0xFFFFFFFF
    e.d32(0x1C, t)
    d28 = e.s32(0x28)
    step = (-d28) & 0xFFFFFFFF if e.s32(0x2C) else d28
    e.d32(0x20, (e.s32(0x20) + step) & 0xFFFFFFFF)
    if d28 > -0x60:
        e.d32(0x28, (d28 - 1) & 0xFFFFFFFF)
    x = (t - 0x100000000 if t & 0x80000000 else t) >> 4
    s20 = e.s32(0x20)
    y = (s20 - 0x100000000 if s20 & 0x80000000 else s20) >> 4
    e.d32(0x04, x & 0xFFFFFFFF)
    e.d32(0x08, y & 0xFFFFFFFF)
    if e.node is not None:
        e.node.dst = (x - 0x18, y - 0x18)
    if e.g32(0x18) == 0:
        return False
    if e.s32(0x2C) != 0:
        return y < 0x1F8
    return y > -0x18


def _beh_414380(self, e) -> bool:
    """`0x414380`（0x26000003）：t=++[0x1C]；[0x28] > −0x30 → [0x28]−−（横减速）；
    [0x2C]≠0 → [0x2C] += ([0x2C]≥0 ? −1 : +1)（纵收敛）；否则 (t&0x1F)==0x1F →
    0x43B070(e,0)；x=([0x20]+=[0x28], +8)>>4、y=([0x24]+=[0x2C], +4)>>3；
    node dst=(x−0x18,y−0x18)；(t&3)==3 → 0x414010；return x>−0x18 且 HP≠0。"""
    t = (e.s32(0x1C) + 1) & 0xFFFFFFFF
    e.d32(0x1C, t)
    if e.s32(0x28) > -0x30:
        e.d32(0x28, (e.s32(0x28) - 1) & 0xFFFFFFFF)
    v = e.s32(0x2C)
    if v != 0:
        e.d32(0x2C, (v + (-1 if v >= 0 else 1)) & 0xFFFFFFFF)
    elif (t & 0x1F) == 0x1F:
        self.p4_43B070(e, 0)
    s20 = (e.s32(0x20) + e.s32(0x28)) & 0xFFFFFFFF
    e.d32(0x20, s20)
    s24 = (e.s32(0x24) + e.s32(0x2C)) & 0xFFFFFFFF
    e.d32(0x24, s24)
    s20 += 8
    s24 += 4
    x = (s20 - 0x100000000 if s20 & 0x80000000 else s20) >> 4
    y = (s24 - 0x100000000 if s24 & 0x80000000 else s24) >> 3
    e.d32(0x04, x & 0xFFFFFFFF)
    e.d32(0x08, y & 0xFFFFFFFF)
    if e.node is not None:
        e.node.dst = (x - 0x18, y - 0x18)
    if (t & 3) == 3:
        self.p4_414010(e)
    return x > -0x18 and e.g32(0x18) != 0


def _beh_414D60(self, e) -> bool:
    """`0x414D60`（0x26000018）：x −= 2；[0x20]==0 → y += (y≥0xF0 ? −4 : +4)；
    否则 [0x20] 为**句柄**：byte[链体+0x34]==0（存活）→ [0x20]=0；
    HP==0 → 0x43B070(e,0)（死亡散弹）；t=++[0x1C]，(t&3)==0 → 0x414010；
    node dst=(x−0x18,y−0x18)；return −0x18<x 且 −0x50<y<0x230 且 HP≠0。"""
    e.d32(0x04, (e.s32(0x04) - 2) & 0xFFFFFFFF)
    h = e.s32(0x20)
    if h == 0:
        y = e.s32(0x08)
        e.d32(0x08, (y + (4 if y >= 0xF0 else -4)) & 0xFFFFFFFF)   # 0x414D78
    else:
        linked = getattr(self, "p4_links", {}).get(h & 0x7FFFFFFF)
        if linked is None or linked.m[0x34] != 0:
            pass                                      # 链体已死 → 跳过
        else:
            e.d32(0x20, 0)
    if e.g32(0x18) == 0:
        self.p4_43B070(e, 0)
    t = (e.s32(0x1C) + 1) & 0xFFFFFFFF
    e.d32(0x1C, t)
    if (t & 3) == 0:
        self.p4_414010(e)
    if e.node is not None:
        e.node.dst = (e.s32(0x04) - 0x18, e.s32(0x08) - 0x18)
    return (-0x18 < e.s32(0x04) and -0x50 < e.s32(0x08) < 0x230
            and e.g32(0x18) != 0)


def _beh_4107D0(self, e) -> bool:
    """`0x4107D0`（thunk 0x401B31；0x23000019）：[0x1C]+=[0x24]、[0x20]+=[0x28]；
    [0x24]≥0 → [0x24]−=4、[0x28] += ([0x28]≥0 ? −3 : +3)；
    否则 [0x24]>−0x50 → [0x24]−−，且 y<自机y → [0x28] += ([0x28]≥0 ? +4 : +2)、
    y≥自机y → [0x28] −= ([0x28]≤0 ? +4 : +2)（纵向追踪）；
    x=[0x1C]>>4、y=[0x20]>>4；node dst=(x−0x18,y−0x18)；
    return x > −0x18 且 HP≠0。"""
    e.d32(0x1C, (e.s32(0x1C) + e.s32(0x24)) & 0xFFFFFFFF)
    e.d32(0x20, (e.s32(0x20) + e.s32(0x28)) & 0xFFFFFFFF)
    v24 = e.s32(0x24)
    v28 = e.s32(0x28)
    if v24 >= 0:
        e.d32(0x24, (v24 - 4) & 0xFFFFFFFF)
        e.d32(0x28, (v28 + (-3 if v28 >= 0 else 3)) & 0xFFFFFFFF)
    else:
        if v24 > -0x50:
            e.d32(0x24, (v24 - 1) & 0xFFFFFFFF)
        if e.s32(0x08) < self.p4_player_y():
            e.d32(0x28, (v28 + (2 if v28 >= 0 else 4)) & 0xFFFFFFFF)
        else:
            e.d32(0x28, (v28 - (2 if v28 <= 0 else 4)) & 0xFFFFFFFF)
    x = (e.s32(0x1C) - 0x100000000 if e.s32(0x1C) & 0x80000000 else e.s32(0x1C)) >> 4
    s20 = e.s32(0x20)
    y = (s20 - 0x100000000 if s20 & 0x80000000 else s20) >> 4
    e.d32(0x04, x & 0xFFFFFFFF)
    e.d32(0x08, y & 0xFFFFFFFF)
    if e.node is not None:
        e.node.dst = (x - 0x18, y - 0x18)
    return x > -0x18 and e.g32(0x18) != 0


def _beh_415980(self, e) -> bool:
    """`0x415980`（0x26000010）：t=++[0x1C]；x += [0x20]（node.dst.x 同加）；
    (t&0x3F)==0x3F 且 t>0x3F → 朝自机十字五连：0x43B070(e,−[0x58]) 主向 +
    0x43B290 四向 (−dy,dx)/(dy,−dx)/(dx−dy,dx+dy)/(dx+dy,dy−dx)（速度表 0）；
    ([0x28]&t)==[0x28] → 0x414010 弹流行滚动；0x4305F0(e,0x18)；
    return 在屏 且 HP≠0。"""
    t = (e.s32(0x1C) + 1) & 0xFFFFFFFF
    e.d32(0x1C, t)
    dx0 = e.s32(0x20)
    e.d32(0x04, (e.s32(0x04) + dx0) & 0xFFFFFFFF)
    if e.node is not None:
        e.node.dst = (e.node.dst[0] + dx0, e.node.dst[1])
    if (t & 0x3F) == 0x3F and t > 0x3F:
        dx = self.p4_player_x() - e.s32(0x04)
        dy = self.p4_player_y() - e.s32(0x08)
        self.p4_43B070(e, (-e.s32(0x58)) & 0xFFFFFFFF)   # 0x4159CC neg edx
        self.p4_43B290(e, -dy, dx, 0)
        self.p4_43B290(e, dy, -dx, 0)
        self.p4_43B290(e, dx - dy, dx + dy, 0)
        self.p4_43B290(e, dx + dy, dy - dx, 0)
    mask = e.s32(0x28)
    if mask != 0 and (mask & t) == mask:
        self.p4_414010(e)
    return self.p4_4305f0(e, 0x18) and e.g32(0x18) != 0


def _beh_415140(self, e) -> bool:
    """`0x415140`（0x2600000B）：x −= 2；y += (y≥自机y ? +1 : −1)；node dst；
    HP==0 → 0x43B070(e,0)（死亡散弹）；t=++[0x1C]，(t&3)==3 → 0x414010；
    return x > −0x18 且 HP≠0。"""
    e.d32(0x04, (e.s32(0x04) - 2) & 0xFFFFFFFF)
    step = 1 if e.s32(0x08) < self.p4_player_y() else -1
    e.d32(0x08, (e.s32(0x08) + step) & 0xFFFFFFFF)
    if e.node is not None:
        e.node.dst = (e.s32(0x04) - 0x18, e.s32(0x08) - 0x18)
    if e.g32(0x18) == 0:
        self.p4_43B070(e, 0)
    t = (e.s32(0x1C) + 1) & 0xFFFFFFFF
    e.d32(0x1C, t)
    if (t & 3) == 3:
        self.p4_414010(e)
    return e.s32(0x04) > -0x18 and e.g32(0x18) != 0


def _beh_414C70(self, e) -> bool:
    """`0x414C70`（0x26000008）：[0x1C]==0 时一次性铺 0x20 架 0x26000018
    （0x430400(&rec,0,0,0x26000018,0) ×0x20 入 0x4AD43C）；x −= 2；t=++[0x1C]，
    (t&3)==3 → 0x414010；余下同 0x26000018 移动（见 0x414D60 后半）。"""
    if e.s32(0x1C) == 0:
        _h = id(e) & 0x7FFFFFFF
        self.p4_links[_h] = e
        for _ in range(0x20):
            self._p4_ent43c(0x26000018, 0, 0, _h)
    t = (e.s32(0x1C) + 1) & 0xFFFFFFFF
    e.d32(0x1C, t)
    e.d32(0x04, (e.s32(0x04) - 2) & 0xFFFFFFFF)
    if (t & 3) == 0:                             # 0x414CDA test al,3 / jne
        self.p4_414010(e)
    y = e.s32(0x08)
    if e.node is not None:
        e.node.dst = (e.s32(0x04) - 0x18, y - 0x18)
    return e.s32(0x04) > -0x140 and e.g32(0x18) != 0   # 0x414D0A jle -0x140


def _beh_414080(self, e) -> bool:
    """`0x414080`（0x26000001）：x += [0x20]、y += [0x24]（漂移）；t=++[0x1C]；
    x<0x18 且 t<0x384 → [0x20]=4（右推）；x>0x268 → [0x20]=−6；
    y≥0x1C8 或 y<0x18 → 0x43B290(e,0,0xF0−y,0)（直指屏内）+
    [0x24] = (y≥0x18 ? −2 : +2)（setge dl→(y≥0x18); dec; and 4; add −2 → (y≥0x18)?−2:+2）；
    0x45A6B0(node+0x14, [0x20], [0x24]) 同步；(t&7)==7 → 0x414010；
    return x > −0x18 且 HP≠0。"""
    e.d32(0x04, (e.s32(0x04) + e.s32(0x20)) & 0xFFFFFFFF)
    e.d32(0x08, (e.s32(0x08) + e.s32(0x24)) & 0xFFFFFFFF)
    t = (e.s32(0x1C) + 1) & 0xFFFFFFFF
    e.d32(0x1C, t)
    if e.s32(0x04) < 0x18 and t < 0x384:
        e.d32(0x20, 4)
    if e.s32(0x04) > 0x268:
        e.d32(0x20, -6 & 0xFFFFFFFF)
    y = e.s32(0x08)
    if y < 0x18 or y > 0x1C8:
        self.p4_43B290(e, 0, 0xF0 - y, 0)
        e.d32(0x24, (-2 if y >= 0x18 else 2) & 0xFFFFFFFF)
    if e.node is not None:                          # 0x45A6B0(node+0x14, vx, vy)
        e.node.dst = (e.node.dst[0] + e.s32(0x20), e.node.dst[1] + e.s32(0x24))
    if (t & 7) == 7:
        self.p4_414010(e)
    return e.s32(0x04) > -0x18 and e.g32(0x18) != 0


def _beh_415200(self, e) -> bool:
    """`0x415200`（0x2600000C）：**右侧编队发生器**。t=++[0x1C]；
    [0x20]==0（展开态）：vy = (y≥0xF0 ? +4 : −0xC)；x += vy；x<−0xA0 →
    [0x24]−− 且 y = rand%0x18 + 0x28（上移重置）；x > 0x320 → y = rand%0x18+0x190；
    y > [0x1C]&&0x1F==0xF → 0x43B070(e,0)；(t&3)==3 → 0x414010；
    alive = [0x24]≠0 且 HP≠0。
    [0x20]≠0（编队态）：(t&0xF)!=0 → return 1；[0x20]−−==0 → 定版（[0x10]=1、
    node.active=1、x=0x298、y=rand%0x18+0x190）；否则发 0x2600000C @
    (0x298, rand%0x18+0x190) prm=rand/0x18 入 0x4AD43C 并 return 1。
    rand = 0x45AD00 LCG；rand%N/÷N 经 0x462D71（push N 作除数残留）。"""
    t = (e.s32(0x1C) + 1) & 0xFFFFFFFF
    e.d32(0x1C, t)
    if e.s32(0x20) == 0:
        y = e.s32(0x08)
        vy = -0xC if y >= 0xF0 else 4              # 0x4152C7 setge/dec/and 0x10/add -0xC
        e.d32(0x04, (e.s32(0x04) + vy) & 0xFFFFFFFF)
        if e.s32(0x04) < -0xA0:
            e.d32(0x24, (e.s32(0x24) - 1) & 0xFFFFFFFF)
            r = self.p4_rand() % 0x18
            e.d32(0x08, (r + 0x28) & 0xFFFFFFFF)
        if e.s32(0x04) > 0x320:
            r = self.p4_rand() % 0x18
            e.d32(0x08, (r + 0x190) & 0xFFFFFFFF)
        y = e.s32(0x08)
        if y > 0xF0 and (t & 0x1F) == 0xF:
            self.p4_43B070(e, 0)
        if (t & 3) == 3:
            self.p4_414010(e)
        if e.node is not None:
            e.node.dst = (e.s32(0x04) - 0x18, y - 0x18)
        return e.s32(0x24) != 0 and e.g32(0x18) != 0
    # 编队态
    if (t & 0xF) != 0:
        return True
    cnt = (e.s32(0x20) - 1) & 0xFFFFFFFF
    e.d32(0x20, cnt)
    if cnt == 0:                                    # 0x415281 定版
        e.m[0x10] = 1
        if e.node is not None:
            e.node.active = 1
        e.d32(0x04, 0x298)
        e.d32(0x08, (self.p4_rand() % 0x18 + 0x190) & 0xFFFFFFFF)
        return True
    rnd = self.p4_rand()
    r = rnd % 0x18                                  # 0x462D71 余数；prm 固定 0
    self._p4_ent43c(0x2600000C, 0x298, r + 0x190, 0)
    return True


def _beh_415480(self, e) -> bool:
    """`0x415480`（0x2600000E）：**编队展开→游走**。

    [0x28]≠0（展开倒计时）：(t&0xF)==0xF → [0x28]−−；减到 0 → [0x1C]=0、[0x10]=1
    （显形）；否则发 0x2600000E @ (x+rand%0x10, y) 入 0x4AD43C。始终 return 1。
    [0x28]==0（游走）：[0x20]（vx）>−8 且 ≠0/−0x10 → vx−=1；
    vx==0：[0x24]==0 → [0x20]=−1、[0x24]=(y≥0xF0?+0xC:−0xC)、0x43B070(e,0)；
           [0x24]<0 → y<0x50 → [0x24]++；[0x24]>0 → y≤0x190 → [0x24]−−；
    vx==−0x10：−0x50<y<0x230 → [0x24] += (y≥0xF0?+1:−1)；否则 x<0x78 →
           [0x20]=0、[0x24]=(y≥0xF0?+0x18:−0x18)。
    尾：[0x10] = (−0x10<y<0x1F0)；x += ([0x20]+2)>>2、y += ([0x24]+2)>>2；
    (t&3)==3 → 0x414010；node dst=(x−0x18,y−0x18)；return x>−0x18 且 HP≠0。"""
    t = (e.s32(0x1C) + 1) & 0xFFFFFFFF
    e.d32(0x1C, t)
    cnt = e.s32(0x28)
    if cnt != 0:
        if (t & 0xF) == 0xF:
            cnt = (cnt - 1) & 0xFFFFFFFF
            e.d32(0x28, cnt)
            if cnt == 0:
                e.d32(0x1C, 0)
                e.m[0x10] = 1
            else:
                self._p4_ent43c(0x2600000E, e.s32(0x04) + (self.p4_rand() & 0xF),
                                e.s32(0x08))
        return True
    v = e.s32(0x20)
    y = e.s32(0x08)
    if v == -0x10:
        if -0x50 < y < 0x230:
            e.d32(0x24, (e.s32(0x24) + (1 if y >= 0xF0 else -1)) & 0xFFFFFFFF)
        else:
            e.d32(0x24, 0)                          # 0x4155A3 先清 vy
            if e.s32(0x04) < 0x78:
                e.d32(0x20, 0)
                e.d32(0x24, (-0x18 if y >= 0xF0 else 0x18) & 0xFFFFFFFF)
    elif v == 0:
        vy = e.s32(0x24)
        if vy == 0:
            e.d32(0x20, -1 & 0xFFFFFFFF)
            e.d32(0x24, (-0xC if y >= 0xF0 else 0xC) & 0xFFFFFFFF)
            self.p4_43B070(e, 0)
        elif vy < 0:
            if y < 0x50:
                e.d32(0x24, (vy + 1) & 0xFFFFFFFF)
        else:
            if y > 0x190:                           # 0x415548 setle：仅 y>0x190 才减
                e.d32(0x24, (vy - 1) & 0xFFFFFFFF)
    else:
        if v > -8:
            e.d32(0x20, (v - 1) & 0xFFFFFFFF)
    # 尾
    y = e.s32(0x08)
    e.m[0x10] = 1 if -0x10 < y < 0x1F0 else 0
    x = (e.s32(0x04) + ((e.s32(0x20) + 2) >> 2)) & 0xFFFFFFFF
    y = (y + ((e.s32(0x24) + 2) >> 2)) & 0xFFFFFFFF
    e.d32(0x04, x)
    e.d32(0x08, y)
    if (t & 3) == 3:
        self.p4_414010(e)
    if e.node is not None:
        e.node.dst = (e.s32(0x04) - 0x18, e.s32(0x08) - 0x18)
    return e.s32(0x04) > -0x18 and e.g32(0x18) != 0


def _beh_4156D0(self, e) -> bool:
    """`0x4156D0`（0x2600000F）：**编队展开→纵加速**。

    [0x20]≠0（倒计时）：t%0xC==0 → [0x20]−−；减到 0 → [0x1C]=0、[0x10]=1；
    否则发 0x2600000F @ (x+rand%0x10, y) 入 0x4AD43C。始终 return 1。
    [0x20]==0：[0x24] += [0x28]；[0x28] += (y≥0xF0 ? +1 : −1)（max/min 钳 ±0x18
    对 ±1 恒不触发）；x −= 2；y = [0x24]>>3；x<0x140 且 (t&0x3F)==0 →
    0x43B070(e,0)；[0x10] = (−0x10<y<0x1F0)；(t&3)==3 → 0x414010；
    node dst=(x−0x18,y−0x18)；return x>−0x18 且 HP≠0。"""
    t = (e.s32(0x1C) + 1) & 0xFFFFFFFF
    e.d32(0x1C, t)
    if e.s32(0x20) != 0:
        if t % 0xC == 0:
            cnt = (e.s32(0x20) - 1) & 0xFFFFFFFF
            e.d32(0x20, cnt)
            if cnt == 0:
                e.d32(0x1C, 0)
                e.m[0x10] = 1
            else:
                self._p4_ent43c(0x2600000F, e.s32(0x04) + (self.p4_rand() & 0xF),
                                e.s32(0x08))
        return True
    e.d32(0x24, (e.s32(0x24) + e.s32(0x28)) & 0xFFFFFFFF)
    y = e.s32(0x08)
    step = -1 if y >= 0xF0 else 1              # 0x415775 setge/dec/and 2/dec
    e.d32(0x28, (e.s32(0x28) + step) & 0xFFFFFFFF)
    e.d32(0x04, (e.s32(0x04) - 2) & 0xFFFFFFFF)
    s24 = e.s32(0x24)
    y = (s24 - 0x100000000 if s24 & 0x80000000 else s24) >> 3
    e.d32(0x08, y & 0xFFFFFFFF)
    if e.s32(0x04) < 0x140 and (t & 0x3F) == 0:
        self.p4_43B070(e, 0)
    e.m[0x10] = 1 if -0x10 < y < 0x1F0 else 0
    if (t & 3) == 3:
        self.p4_414010(e)
    if e.node is not None:
        e.node.dst = (e.s32(0x04) - 0x18, y - 0x18)
    return e.s32(0x04) > -0x18 and e.g32(0x18) != 0


def _beh_415A90(self, e) -> bool:
    """`0x415A90`（0x26000013）：t=++[0x1C]；
    x += ([0x20]+4)>>3、y += ([0x24]+4)>>3；
    x<0xA0 且 t<0x4B0 → [0x20]++（加速）否则 [0x20]−−；[0x20]<−0x20 → 钳 −0x20；
    [0x24] += (y≥0xF0 ? +1 : −1)；node dst=(x−0x18,y−0x18)；
    (t&0x7F)==0 → 0x43B070(e,0)；(t&3)==3 → 0x414010；
    return x > −0x18 且 HP≠0。"""
    t = (e.s32(0x1C) + 1) & 0xFFFFFFFF
    e.d32(0x1C, t)
    v20 = e.s32(0x20)
    x = (e.s32(0x04) + ((v20 + 4) >> 3)) & 0xFFFFFFFF
    e.d32(0x04, x)
    v24 = e.s32(0x24)
    y = (e.s32(0x08) + ((v24 + 4) >> 3)) & 0xFFFFFFFF
    e.d32(0x08, y)
    if x < 0xA0 and t < 0x4B0:
        v20 = (v20 + 1) & 0xFFFFFFFF
    else:
        v20 = (v20 - 1) & 0xFFFFFFFF
    e.d32(0x20, v20)
    if v20 < -0x20:
        v20 = -0x20
        e.d32(0x20, v20 & 0xFFFFFFFF)
    e.d32(0x24, (v24 + (-1 if y >= 0xF0 else 1)) & 0xFFFFFFFF)   # 0x415AEE
    if e.node is not None:
        e.node.dst = (x - 0x18, y - 0x18)
    if (t & 0x7F) == 0:
        self.p4_43B070(e, 0)
    if (t & 3) == 3:
        self.p4_414010(e)
    return x > -0x18 and e.g32(0x18) != 0


def _beh_414170(self, e) -> bool:
    """`0x414170`（0x26000002）：t=[0x1C]++、s=[0x28]++。

    s==0xD3（211）：速度 = 12×单位向自机（0x45AA80*Δ*12>>12）；
    s==0x118（0xD3+0x45）：[0x20]=[0x24]=0（停）；
    s==0x190（0x118+0x78）：x = ([0x2C]&1 ? 0x298−0x18? : −0x18)
      （and 0x2B0/add −0x18 → 镜像 0x280+0x30−0x18）、y = rand%0x100+0x70、
      [0x28]=0（重入）、[0x20] = ([0x2C]&1 ? −4 : +4)、[0x2C]−−（圈数递减）。
    0x20≤s≤0xD2：若 s>0x5A 且 (vx≠自机x 或 vy≠自机y) → s=0xD2；
      否则 vx=自机x、vy=自机y（吸附）。
    其余：x+=vx、y+=vy；s>0xD2 且 (t&3)==0 且 0x4305F0(e,0x18) → 0x43B070(e,0)。
    node dst=(x−0x18,y−0x18)；(t & (s≤0x5A ? 7 : 3))==0 → 0x414010；
    return [0x2C]≠0 且 HP≠0。"""
    t = (e.s32(0x1C) + 1) & 0xFFFFFFFF
    e.d32(0x1C, t)
    s = (e.s32(0x28) + 1) & 0xFFFFFFFF
    e.d32(0x28, s)
    if s == 0xD3:                                   # 0x4141F0 冲向自机
        dx = self.p4_player_x() - e.s32(0x04)
        dy = self.p4_player_y() - e.s32(0x08)
        inv = self.p4_45aa80(dx, dy)
        e.d32(0x20, (((inv * dx) * 12) >> 12) & 0xFFFFFFFF)
        e.d32(0x24, (((inv * dy) * 12) >> 12) & 0xFFFFFFFF)
    elif s == 0x118:                                # 0x4141E0 停
        e.d32(0x20, 0)
        e.d32(0x24, 0)
    elif s == 0x190:                                # 0x41419A 重入
        mirror = e.s32(0x2C) & 1
        e.d32(0x04, (0x298 if mirror else -0x18) & 0xFFFFFFFF)   # and 0x2B0 + −0x18
        e.d32(0x08, (self.p4_rand() & 0xFF) + 0x70)
        e.d32(0x20, (-4 if mirror else 4) & 0xFFFFFFFF)
        e.d32(0x2C, (e.s32(0x2C) - 1) & 0xFFFFFFFF)
        e.d32(0x28, 0)
    s = e.s32(0x28)
    if 0x20 <= s <= 0xD2:
        if s > 0x5A and (e.s32(0x20) != self.p4_player_x()
                         or e.s32(0x24) != self.p4_player_y()):
            e.d32(0x28, 0xD2)
        else:
            e.d32(0x20, self.p4_player_x() & 0xFFFFFFFF)
            e.d32(0x24, self.p4_player_y() & 0xFFFFFFFF)
        s = e.s32(0x28)
    else:
        e.d32(0x04, (e.s32(0x04) + e.s32(0x20)) & 0xFFFFFFFF)
        e.d32(0x08, (e.s32(0x08) + e.s32(0x24)) & 0xFFFFFFFF)
        if s > 0xD2 and (t & 3) == 0 and self.p4_4305f0(e, 0x18):
            self.p4_43B070(e, 0)
    if e.node is not None:
        e.node.dst = (e.s32(0x04) - 0x18, e.s32(0x08) - 0x18)
    gate = 7 if s <= 0x5A else 3
    if (t & gate) == 0:
        self.p4_414010(e)
    return e.s32(0x2C) != 0 and e.g32(0x18) != 0


def _beh_414460(self, e) -> bool:
    """`0x414460`（0x26000004）：t=++[0x1C]；word[0x56CC98]（难度）>1 且 [0x20]==0 →
    [0x20] = (y≥0xF0 ? +8 : −8)（setge; dec; and 0x10; add −8 → (y≥0xF0)?+8:−8）；
    x −= 3；y += [0x20]；[0x20]≠0 且 t 奇 → ang=t*0x10：
      0x45ABB0(cos)/0x45AAF0(sin) 查表 → 0x43B290(e, sin, cos, 0) /
      (−sin, cos)/(cos, −sin)/(−sin, −cos) 四斜向弹；
    (t&1)==0 → 0x414010；node dst=(x−0x18,y−0x18)；
    return x>−0x18 且 −0x30<y<0x210 且 HP≠0。"""
    t = (e.s32(0x1C) + 1) & 0xFFFFFFFF
    e.d32(0x1C, t)
    v = e.s32(0x20)
    if self.p4_stat.get(0x56CC98, 0) > 1 and v == 0:
        y0 = e.s32(0x08)
        e.d32(0x20, (-8 if y0 >= 0xF0 else 8) & 0xFFFFFFFF)   # 0x41448C setge/dec/and 0x10/add -8
        v = e.s32(0x20)
    x = (e.s32(0x04) - 3) & 0xFFFFFFFF
    e.d32(0x04, x)
    y = (e.s32(0x08) + v) & 0xFFFFFFFF
    e.d32(0x08, y)
    if v != 0 and (t & 1):
        ang = (t * 0x90) & 0xFFFFFFFF                  # 0x4144B5 (t*9)<<4
        f1 = page4_cos(ang)                            # 0x40159B → 0x45ABB0 cos
        f2 = page4_sin(ang)                            # 0x401A50 → 0x45AAF0 sin
        self.p4_43B290(e, f1, f2, 0)
        self.p4_43B290(e, -f2, f1, 0)                 # 0x4144DB：旋转 90°
        self.p4_43B290(e, f2, -f1, 0)
        self.p4_43B290(e, -f1, -f2, 0)
    if (t & 1) == 1:                                 # 0x414506 and 1 / cmp 1
        self.p4_414010(e)
    if e.node is not None:
        e.node.dst = (x - 0x18, y - 0x18)
    return (x > -0x18 and -0x30 < y < 0x210 and e.g32(0x18) != 0)


def _beh_414FB0(self, e) -> bool:
    """`0x414FB0`（0x2600000A）：t=[0x1C]++。

    [0x20]≠0（展开态）：0x430400(&rec, x, y+0x12, 0x46000002, 1) 入 0x4AD4CC
    （×1）+ 0x430400(&rec, x, y+[0x20], 0x46000003, …) 入 0x4AD4CC；[0x20]+=4；
    [0x20]==0（收拢态）：x −= min(t−0x78, 0xC)>>2；
    node dst=(x−0x18,y−0x18)；t==0x78 → 0x43B070(e,0)+node.active=1；
    (t&1)==0 → 0x414010；return x>−0x18 且 HP≠0。"""
    t = (e.s32(0x1C) + 1) & 0xFFFFFFFF
    e.d32(0x1C, t)
    if e.s32(0x20) != 0:
        # 0x46000002 / 0x46000003 双件入 0x4AD4CC（ui4cc），prm=1 / 栈残留
        self.spawn(self._p4_q("ui4cc"), 0x46000002, e.s32(0x04), e.s32(0x08) + 0x12, 1)
        self.spawn(self._p4_q("ui4cc"), 0x46000003,
                   e.s32(0x04), e.s32(0x08) + e.s32(0x20), 0)
        e.d32(0x20, (e.s32(0x20) + 4) & 0xFFFFFFFF)
    else:
        d = t - 0x78
        if d > 0xC:
            d = 0xC
        e.d32(0x04, (e.s32(0x04) - (d >> 2)) & 0xFFFFFFFF)
    if e.node is not None:
        e.node.dst = (e.s32(0x04) - 0x18, e.s32(0x08) - 0x18)
    if t == 0x78:
        self.p4_43B070(e, 0)
        if e.node is not None:
            e.node.active = 1
    if (t & 1) == 1:                                 # 0x4150C3 test byte[+0x1C],1
        self.p4_414010(e)
    return e.s32(0x04) > -0x18 and e.g32(0x18) != 0


def _beh_4145A0(self, e) -> bool:
    """`0x4145A0`（0x26000005）：**圆周飞行长机 + 链体门**。

    [0x20]++（t）；[0x1C]==0 且 (t&7)==0 且 [0x28]≠0 → 发 0x26000005 @
    (0x2A8,0xF0) 入 0x4AD43C、[0x28]−−。
    x = 0x1E0 + (25*cos(11t)>>5) − t/2；y = 0xF0 + (25*sin(23t)>>5)
    （0x40159B=cos/0x401A50=sin；11t=(t+t*4)*2、23t=(t*3)<<3−t）。
    无链 且 (t&0x7F)==0：朝机十字六连（spd −0x380..−0x80 步 0x100：
    0x43B070(e,spd) + 0x43B290(e, dx−dy, dx+dy, spd) + 0x43B290(e, dy−dx, dx+dy, spd)）。
    (t&7)==0 → 0x414010。HP：≠−1 → [0x18]=−1；旧链体≠0 → [链体+0x24]−−、
    ==0 → 自身 [0x24]−−。
    链体≠0：byte[链体+0x34] 置位 → 存活路径；否则发 0x41000001 入 ui4cc +
    2× 0x41000004（坐标 ±rand%0x1F−0xF 抖动）并 return 0。
    链体==0：[0x24]>0 → 存活；否则 0x401AE1(0x4CD4A0, 0x7530) 全局件 + return 0。
    存活路径：node dst 同步；有链 return x>−0x18；无链 return t<0x44C。"""
    t = (e.s32(0x20) + 1) & 0xFFFFFFFF
    e.d32(0x20, t)
    h_old = e.s32(0x1C)
    if h_old == 0 and (t & 7) == 0 and e.s32(0x28) != 0:
        _h = id(e) & 0x7FFFFFFF
        self.p4_links[_h] = e
        self._p4_ent43c(0x26000005, 0x2A8, 0xF0, _h)
        e.d32(0x28, (e.s32(0x28) - 1) & 0xFFFFFFFF)
    c = page4_cos(11 * t)
    s_ = page4_sin(23 * t)
    x = 0x1E0 + ((25 * c) >> 5) - (t >> 1)
    y = 0xF0 + ((25 * s_) >> 5)
    e.d32(0x04, x & 0xFFFFFFFF)
    e.d32(0x08, y & 0xFFFFFFFF)
    linked = getattr(self, "p4_links", {}).get(h_old & 0x7FFFFFFF) if h_old else None
    if h_old == 0 and (t & 0x7F) == 0:
        dx = self.p4_player_x() - x
        dy = self.p4_player_y() - y
        a = dx - dy
        b = dx + dy
        c2 = dy - dx
        spd = -0x380
        while spd <= -0x80:
            self.p4_43B070(e, spd & 0xFFFFFFFF)
            self.p4_43B290(e, a, b, spd & 0xFFFFFFFF)
            self.p4_43B290(e, b, c2, spd & 0xFFFFFFFF)   # 0x414696 push edi(dx+dy) 作 a
            spd += 0x100
    if (t & 7) == 0:
        self.p4_414010(e)
    if e.g32(0x18) != 0xFFFFFFFF:                           # 0x4146BC
        if linked is not None:
            linked.d32(0x24, (linked.s32(0x24) - 1) & 0xFFFFFFFF)
        else:
            e.d32(0x24, (e.s32(0x24) - 1) & 0xFFFFFFFF)
        e.d32(0x18, -1 & 0xFFFFFFFF)
    if linked is not None:
        if linked.m[0x34] != 0:                     # 0x4147C4 存活路径
            if e.node is not None:
                e.node.dst = (x - 0x18, y - 0x18)
            return x > -0x18
        self.spawn(self._p4_q("ui4cc"), 0x41000001, x, y, 0)
        for _ in range(2):                          # 0x41477B esi=2
            jx = (self.p4_rand() & 0x1F) - 0xF
            jy = (self.p4_rand() & 0x1F) - 0xF
            self.spark_spawn(x, y, jx, jy)             # 0x41477B：位置=父体，抖动=速度
        return False
    if e.s32(0x24) > 0:                             # 0x4146D4
        if e.node is not None:
            e.node.dst = (x - 0x18, y - 0x18)
        return t < 0x44C
    # 0x401AE1(0x4CD4A0, 0x7530)：全局长特效件（0x7530=30000）
    self.p4_other.setdefault("4cd4a0", []).append(0x7530)
    return False


def _beh_4148B0(self, e) -> bool:
    """`0x4148B0`（0x26000006）：**链体护卫机（45t 正弦纵摆）**。

    t=[0x20]++；无链（[0x1C]==0）：t<0x258 且 t 奇 → 发 0x26000006 @
    (0x298, 0xF0 + (45*sin(45t)>>5)) 入 0x4AD43C（45t=(t*5)*9、0x401A50=sin），
    自身 y 同步；[0x24]>0 且 t<0x2D0 → return 1（等链体），否则 return 0。
    有链：x −= 6；t==0xF 且 y 奇 → 0x43B360(e, 自机x, y+自机y−0x140, 0)；
    (t&0xF)==0xF → 0x414010；HP≠−1 → [0x18]=−1 且 [链体+0x24]−−。
    链体死（byte[+0x34]）→ 链体[0x28]=0、发 0x41000001 入 ui4cc +
    3× 0x41000004（±rand%0x1F−0xF 抖动）+ return 0；
    链体活：node.dst.x −= 6（0xFFFFFFFA）；return x > −0x18。"""
    t = (e.s32(0x20) + 1) & 0xFFFFFFFF
    e.d32(0x20, t)
    h = e.s32(0x1C)
    linked = getattr(self, "p4_links", {}).get(h & 0x7FFFFFFF) if h else None
    if h == 0:
        if t < 0x258 and (t & 1):
            ang = (t * 5 * 9) & 0xFFFFFFFF
            yy = 0xF0 + ((45 * page4_sin(ang)) >> 5)
            e.d32(0x08, yy & 0xFFFFFFFF)
            _h = id(e) & 0x7FFFFFFF
            self.p4_links[_h] = e
            self._p4_ent43c(0x26000006, 0x298, yy, _h)
        return 1 if (e.s32(0x24) > 0 and t < 0x2D0) else False
    x = (e.s32(0x04) - 6) & 0xFFFFFFFF
    e.d32(0x04, x)
    y = e.s32(0x08)
    if t == 0xF and (y & 1):
        self.p4_43B360(e, self.p4_player_x(), y + self.p4_player_y() - 0x140, 0)
    if (t & 0xF) == 0xF:
        self.p4_414010(e)
    if e.g32(0x18) != 0xFFFFFFFF:
        e.d32(0x18, -1 & 0xFFFFFFFF)
        if linked is not None:
            linked.d32(0x24, (linked.s32(0x24) - 1) & 0xFFFFFFFF)
    if linked is None or linked.m[0x34] != 0:
        if linked is not None:
            linked.d32(0x28, 0)
        self.spawn(self._p4_q("ui4cc"), 0x41000001, x, y, 0)
        for _ in range(3):
            jx = (self.p4_rand() & 0x1F) - 0xF
            jy = (self.p4_rand() & 0x1F) - 0xF
            self.spark_spawn(x, y, jx, jy)
        return False
    if e.node is not None:                          # 0x414A96 dst.x −= 6
        e.node.dst = (e.node.dst[0] - 6, e.node.dst[1])
    return x > -0x18


def _beh_414B50(self, e) -> bool:
    """`0x414B50`（0x26000007）：**加速横穿 + 折返重置**。

    t=++[0x1C]；[0x2C]（寿命）≠0 → [0x28]++（横加速）；
    [0x24] += [0x28]、x = [0x24]>>3；x>0x298 → [0x28]=−0xA0、
    y = rand%0x1B0 + 0x18（0x462D71(rand,0x1B0) 取余）、[0x2C]−−；
    node dst=(x−0x18,y−0x18)；[0x28]==0 → 0x43B070(e,0)；
    ((t&7)==7 且 [0x28]<0) 或 ((t&3)==3 且 [0x28]>0) → 0x414010；
    return x>−0x18 且 HP≠0。"""
    t = (e.s32(0x1C) + 1) & 0xFFFFFFFF
    e.d32(0x1C, t)
    if e.s32(0x2C) != 0:
        e.d32(0x28, (e.s32(0x28) + 1) & 0xFFFFFFFF)
    s = (e.s32(0x24) + e.s32(0x28)) & 0xFFFFFFFF
    e.d32(0x24, s)
    x = (s - 0x100000000 if s & 0x80000000 else s) >> 3
    e.d32(0x04, x & 0xFFFFFFFF)
    if x > 0x298:
        e.d32(0x28, 0xFFFFFFA0)                  # 0x414B86 mov [esi+0x28],0xFFFFFFA0
        e.d32(0x08, (self.p4_rand() % 0x1B0 + 0x18) & 0xFFFFFFFF)
        e.d32(0x2C, (e.s32(0x2C) - 1) & 0xFFFFFFFF)
    if e.node is not None:
        e.node.dst = (x - 0x18, e.s32(0x08) - 0x18)
    if e.s32(0x28) == 0:
        self.p4_43B070(e, 0)
    v = e.s32(0x28)
    if (t & 7) == 7 and v < 0:
        self.p4_414010(e)
    elif (t & 3) == 3 and v > 0:
        self.p4_414010(e)
    return x > -0x18 and e.g32(0x18) != 0


def p4_43B150(self, e, x0: int, y0: int, spdarg: int) -> None:
    """`0x43B150`（thunk 0x401D6B）：**缺口瞄准弹**——从 (x0,y0) 生成 0x43B020(e)
    弹型，方向 = 自机−(x0,y0) 再转一刀（new_dx = 2dx+dy、new_dy = 2dy−dx，
    0x43B1CC 线性组合），速度 = 0x43AF90(e,spdarg)>>4 归一。入 0x4AD49C。"""
    dx = self.p4_player_x() - x0
    dy = self.p4_player_y() - y0
    ndx = dy + 2 * dx                                # 0x43B1CC edi = ecx+2eax
    ndy = 2 * dy - dx                                # 0x43B1CF ebx = 2ecx−eax
    spd = self.p4_43af90(e, spdarg) >> 4
    inv = self.p4_45aa80(ndx, ndy)
    vx = ((inv * ndx) * spd) >> 8
    vy = ((inv * ndy) * spd) >> 8
    if vx == 0 and vy == 0:
        return
    typ = self.p4_43B020(e)
    eb = self.spawn(self._p4_q("ui49c"), typ, x0, y0, (vx, vy))
    if eb is not None:
        eb.raw[0x10] = 1
        eb.d32(0x14, typ & 0xFFFFFFFF)
        eb.d32(0x04, x0 & 0xFFFFFFFF)
        eb.d32(0x08, y0 & 0xFFFFFFFF)
        eb.d32(0x0C, 0x18)
        self._p4_q("ui49c").append(eb)


def _beh_416770(self, e) -> bool:
    """`0x416770`（0x27000004）：t≠0 时 t++；[0x24] += (y≥[0x28] ? −1 : +1)
    （向 [0x28] 收敛）、[0x20] += [0x24]、[0x2C]++（==0x2D0 → [0x1C]=1 启动）；
    y = [0x20]>>4、x += [0x1C]；node dst 同步；
    ([0x2C]&0x6F)==0x6F → 0x43B070(e,−[0x58]) + 0x43B150(e,0,0,0)（角炮）；
    0x401F91→0x416440 boss spawner（复刻侧 op2 直生成，跳过）；
    return x < 0x298 且 HP≠0。"""
    t = e.s32(0x1C)
    if t != 0:
        t = (t + 1) & 0xFFFFFFFF
        e.d32(0x1C, t)
    y = e.s32(0x08)
    v24 = (e.s32(0x24) + (-1 if y >= e.s32(0x28) else 1)) & 0xFFFFFFFF
    e.d32(0x24, v24)
    s20 = (e.s32(0x20) + v24) & 0xFFFFFFFF
    e.d32(0x20, s20)
    c = (e.s32(0x2C) + 1) & 0xFFFFFFFF
    e.d32(0x2C, c)
    if c == 0x2D0:
        e.d32(0x1C, 1)
    yy = (s20 - 0x100000000 if s20 & 0x80000000 else s20) >> 4
    e.d32(0x08, yy & 0xFFFFFFFF)
    x = (e.s32(0x04) + e.s32(0x1C)) & 0xFFFFFFFF
    e.d32(0x04, x)
    if e.node is not None:
        e.node.dst = (x - 0x18, yy - 0x18)
    if (c & 0x6F) == 0x6F:
        self.p4_43B070(e, (-e.s32(0x58)) & 0xFFFFFFFF)
        self.p4_43B150(e, 0)
    # 0x401F91 → 0x416440 boss spawner（op2 直生成，跳过）
    return x < 0x298 and e.g32(0x18) != 0


def _beh_417160(self, e) -> bool:
    """`0x417160`（0x2700000C）：x>0x1E0 且 [0x24]≠0 → [0x24]−−；t=++[0x1C]，
    t==0x258 → [0x24]=−1；x += [0x24]、y += ([0x28]==0 ? −[0x24] : [0x24])；
    node dst=(x−0x30,y−0x30)；(t&0x10)==0x10 → [0x20] += ([0x28]≠0 ? +1 : −1)、
    0x43B290(e, cos(45[0x20]), sin(45[0x20]), 0)；0x401F91→0x416440（跳过）；
    return HP≠0 且 0x4305F0(e,0x30)。"""
    if e.s32(0x04) > 0x1E0 and e.s32(0x24) != 0:
        e.d32(0x24, (e.s32(0x24) - 1) & 0xFFFFFFFF)
    t = (e.s32(0x1C) + 1) & 0xFFFFFFFF
    e.d32(0x1C, t)
    if t == 0x258:
        e.d32(0x24, -1 & 0xFFFFFFFF)
    v24 = e.s32(0x24)
    x = (e.s32(0x04) + v24) & 0xFFFFFFFF
    e.d32(0x04, x)
    y = (e.s32(0x08) + (-v24 if e.s32(0x28) == 0 else v24)) & 0xFFFFFFFF
    e.d32(0x08, y)
    if e.node is not None:
        e.node.dst = (x - 0x30, y - 0x30)
    if (t & 0x10) == 0x10:
        v20 = (e.s32(0x20) + (1 if e.s32(0x28) != 0 else -1)) & 0xFFFFFFFF
        e.d32(0x20, v20)
        ang = (225 * v20) & 0xFFFFFFFF   # 0x4171E7 25v*9=225
        self.p4_43B290(e, page4_cos(ang), page4_sin(ang), 0)
    # 0x401F91 → 0x416440（跳过）
    return e.g32(0x18) != 0 and self.p4_4305f0(e, 0x30)


def _beh_417280(self, e) -> bool:
    """`0x417280`（0x2700000D）：|vx|<0x28 → vx += (vx≤0 ? +1 : −1)（缓起）；
    x<−0x168 → 重入（x=−0x30、y=自机y、vx=1）；x>0x3E8 → [0x24]−−（寿命）、
    x=0x2B0、y=0x1E0−自机y（镜像）、vx=−1；
    x += (vx+2)>>2；t=++[0x1C]，(t&7)==0 → vx += ([0x28]≠0 ? +1 : −1) +
    0x43B360(e, rand%0x280, rand%0x1E0, 0)（屏内随机点开火）；
    [0x10] = (−0x30<x<0x2B0)；node dst=(x−0x30,y−0x30)；0x401F91（跳过）；
    return HP≠0 且 [0x24]>0。"""
    v = e.s32(0x20)
    if abs(v) < 0x28:
        v = (v + (-1 if v <= 0 else 1)) & 0xFFFFFFFF   # 0x417299 setle/dec/and 2/dec
        e.d32(0x20, v)
    x = e.s32(0x04)
    if x < -0x168:
        e.d32(0x04, -0x30 & 0xFFFFFFFF)
        e.d32(0x08, self.p4_player_y() & 0xFFFFFFFF)
        e.d32(0x20, 1)
    elif x > 0x3E8:
        e.d32(0x24, (e.s32(0x24) - 1) & 0xFFFFFFFF)
        e.d32(0x04, 0x2B0)
        e.d32(0x08, (0x1E0 - self.p4_player_y()) & 0xFFFFFFFF)
        e.d32(0x20, -1 & 0xFFFFFFFF)
    x = (e.s32(0x04) + ((e.s32(0x20) + 2) >> 2)) & 0xFFFFFFFF
    e.d32(0x04, x)
    t = (e.s32(0x1C) + 1) & 0xFFFFFFFF
    e.d32(0x1C, t)
    if (t & 7) == 0:
        e.d32(0x20, (e.s32(0x20) + (1 if e.s32(0x28) != 0 else -1)) & 0xFFFFFFFF)
        ry = self.p4_rand() % 0x1E0
        rx = self.p4_rand() % 0x280
        self.p4_43B360(e, rx, ry, 0)
    e.m[0x10] = 1 if -0x30 < x < 0x2B0 else 0
    if e.node is not None:
        e.node.dst = (x - 0x30, e.s32(0x08) - 0x30)
    # 0x401F91 → 0x416440（跳过）
    return e.g32(0x18) != 0 and e.s32(0x24) > 0


def _beh_417410(self, e) -> bool:
    """`0x417410`（0x2700000E）：**锁定发射器**。

    [0x1C]≠0（连发态）：t2=[0x20]++；t2==0x10 → 发 0x2700000E @
    (0x2B0, rand%0x23A − 0x2D) 入 0x4AD43C、[0x20]=0、[0x1C]−−；return 1。
    [0x1C]==0（待机）：[0x20]==0 且 [0x24]==0 → 锁定：[0x10]=1、node.active=1、
    速度 = 80×单位向自机×2（Δ*2 → 0x45AA80*Δ2*80>>12，0x4174C7 lea*5 shl 4 = ×80）；
    积分：[0x28]+=[0x20]、[0x2C]+=[0x24]、x=[0x28]>>3、y=[0x2C]>>3；
    node dst=(x−0x30,y−0x30)；0x401F91（跳过）；
    return HP≠0 且 0x4305F0(e,0x30)。"""
    if e.s32(0x1C) != 0:
        t2 = (e.s32(0x20) + 1) & 0xFFFFFFFF
        e.d32(0x20, t2)
        if t2 == 0x10:
            ry = self.p4_rand() % 0x23A - 0x2D
            self._p4_ent43c(0x2700000E, 0x2B0, ry)
            e.d32(0x20, 0)
            e.d32(0x1C, (e.s32(0x1C) - 1) & 0xFFFFFFFF)
        return True
    if e.s32(0x20) == 0 and e.s32(0x24) == 0:
        dx = (self.p4_player_x() - e.s32(0x04)) * 2
        dy = self.p4_player_y() - e.s32(0x08)
        e.m[0x10] = 1
        inv = self.p4_45aa80(dx, dy)
        e.d32(0x20, (((inv * dx) * 80) >> 12) & 0xFFFFFFFF)
        e.d32(0x24, (((inv * dy) * 80) >> 12) & 0xFFFFFFFF)
        if e.node is not None:
            e.node.active = 1
    e.d32(0x28, (e.s32(0x28) + e.s32(0x20)) & 0xFFFFFFFF)
    e.d32(0x2C, (e.s32(0x2C) + e.s32(0x28)) & 0xFFFFFFFF)   # 0x406D4E [0x2C]+=[0x28]
    a28 = e.s32(0x28)
    a2c = e.s32(0x2C)
    x = (a28 - 0x100000000 if a28 & 0x80000000 else a28) >> 3
    y = (a2c - 0x100000000 if a2c & 0x80000000 else a2c) >> 3
    e.d32(0x04, x & 0xFFFFFFFF)
    e.d32(0x08, y & 0xFFFFFFFF)
    if e.node is not None:
        e.node.dst = (x - 0x30, y - 0x30)
    # 0x401F91 → 0x416440（跳过）
    return e.g32(0x18) != 0 and self.p4_4305f0(e, 0x30)


def _beh_4175C0(self, e) -> bool:
    """`0x4175C0`（0x2700000F）：**受创爆发 boss**。

    y<0xF0 且 x<0x190 → [0x28]−−；0xF0<y<0x15E → [0x28]≠0 ? [0x28]++ :
    ([0x24]>−0x30 → [0x24]−−)；
    [0x1C]+=[0x24]、[0x20]+=[0x28]（8.4 定点）；x=[0x1C]>>4、y=[0x20]>>4。
    0<HP<0xFA0（unsigned jae 门）→ 爆发：0x61000004@(x,y,0x78) 入 0x4AD52C、
    0x32000004@(x,y−0x3C)/0x32000004@(x,y+0x3C)/0x32000005@(x,y) 入 0x4AD49C，
    return 0。否则 node dst=(x−0x78,y−0x78)；
    return HP≠0 且 x>−0x78 且 y>−0x78。"""
    y0 = e.s32(0x08)
    x0 = e.s32(0x04)
    if y0 < 0xF0 and x0 < 0x190:
        e.d32(0x28, (e.s32(0x28) - 1) & 0xFFFFFFFF)
    if 0xF0 < y0 < 0x15E:
        if e.s32(0x28) != 0:
            e.d32(0x28, (e.s32(0x28) + 1) & 0xFFFFFFFF)
        elif e.s32(0x24) > -0x30:
            e.d32(0x24, (e.s32(0x24) - 1) & 0xFFFFFFFF)
    a1c = (e.s32(0x1C) + e.s32(0x24)) & 0xFFFFFFFF
    e.d32(0x1C, a1c)
    a20 = (e.s32(0x20) + e.s32(0x28)) & 0xFFFFFFFF
    e.d32(0x20, a20)
    x = (a1c - 0x100000000 if a1c & 0x80000000 else a1c) >> 4
    y = (a20 - 0x100000000 if a20 & 0x80000000 else a20) >> 4
    e.d32(0x04, x & 0xFFFFFFFF)
    e.d32(0x08, y & 0xFFFFFFFF)
    hp = e.g32(0x18)
    if hp != 0 and hp < 0xFA0:
        self.p4_spawn52c_flash(x, y, 0x61000004, 0x78)
        self.spawn(self._p4_q("ui49c"), 0x32000004, x, y - 0x3C, 0)
        self.spawn(self._p4_q("ui49c"), 0x32000004, x, y + 0x3C, 0)
        self.spawn(self._p4_q("ui49c"), 0x32000005, x, y, 0)
        return False
    if e.node is not None:
        e.node.dst = (x - 0x78, y - 0x78)
    return hp != 0 and x > -0x78 and y > -0x78


def _beh_419610(self, e) -> bool:
    """`0x419610`（0x28000003）：**突进→衰减**。[0x2C]（突进帧）≠0 →
    [0x20] −= 0x80、[0x24] 不动、[0x2C]−−；否则 [0x20] += [0x28]>>1、
    [0x24] −= [0x28]、[0x28]++ + 0x401BA4(8,0,0x30) 特效；
    x=[0x20]>>4、y=[0x24]>>4；node dst=(x−0x18,y−0x18)；
    return HP≠0 且 y>−0x18。"""
    c = e.s32(0x2C)
    if c != 0:
        e.d32(0x20, (e.s32(0x20) - 0x80) & 0xFFFFFFFF)
        e.d32(0x2C, (c - 1) & 0xFFFFFFFF)
    else:
        e.d32(0x20, (e.s32(0x20) + (e.s32(0x28) >> 1)) & 0xFFFFFFFF)
        e.d32(0x24, (e.s32(0x24) - e.s32(0x28)) & 0xFFFFFFFF)
        e.d32(0x28, (e.s32(0x28) + 1) & 0xFFFFFFFF)
        self.p4_4193e0(e, 8,0,0x30)
    x = (e.s32(0x20) - 0x100000000 if e.s32(0x20) & 0x80000000 else e.s32(0x20)) >> 4
    y = (e.s32(0x24) - 0x100000000 if e.s32(0x24) & 0x80000000 else e.s32(0x24)) >> 4
    e.d32(0x04, x & 0xFFFFFFFF)
    e.d32(0x08, y & 0xFFFFFFFF)
    if e.node is not None:
        e.node.dst = (x - 0x18, y - 0x18)
    return e.g32(0x18) != 0 and y > -0x18


def _beh_4196E0(self, e) -> bool:
    """`0x4196E0`（0x28000004）：[0x20] += [0x24]；[0x24] += (x≥0x140 ? −1 : +1)
    （中线折返）；y = [0x28]；x = [0x20]>>4；[0x24]==0 → [0x2C]−−（寿命）；
    0x401BA4(0x80,4,0x30) 特效；++[0x30]，(&0x7F)==0 → 0x43B070(e,0)；
    node dst=(x−0x18,y−0x18)；return HP≠0 且 [0x2C]≠0。"""
    e.d32(0x20, (e.s32(0x20) + e.s32(0x24)) & 0xFFFFFFFF)
    step = -1 if e.s32(0x04) >= 0x140 else 1
    e.d32(0x24, (e.s32(0x24) + step) & 0xFFFFFFFF)
    e.d32(0x08, e.s32(0x28) & 0xFFFFFFFF)
    s20 = e.s32(0x20)
    e.d32(0x04, ((s20 - 0x100000000 if s20 & 0x80000000 else s20) >> 4) & 0xFFFFFFFF)
    if e.s32(0x24) == 0:
        e.d32(0x2C, (e.s32(0x2C) - 1) & 0xFFFFFFFF)
    self.p4_4193e0(e, 0x80,4,0x30)
    c = (e.s32(0x30) + 1) & 0xFFFFFFFF
    e.d32(0x30, c)
    if (c & 0x7F) == 0:
        self.p4_43B070(e, 0)
    if e.node is not None:
        e.node.dst = (e.s32(0x04) - 0x18, e.s32(0x08) - 0x18)
    return e.g32(0x18) != 0 and e.s32(0x2C) != 0


def _beh_419910(self, e) -> bool:
    """`0x419910`（0x28000007）：**锁定 12 帧后反向突进**。

    [0x20] −= [0x28]、[0x24] += [0x28]、[0x28]≠0 → [0x28]−−；
    y=[0x24]>>4、x=[0x20]>>4；0x401BA4(8,0,0x30) 特效；
    [0x28]==0 且 [0x1C]==0：[0x30]≠0 → 0x43B360(e, word[0x2C], word[0x2E], 0)
    （对锁定点开火）；否则 word[0x2C]=自机x、word[0x2E]=自机y（锁定）；
    ++[0x30]==0xC → [0x28]=−1（突进启动）；node dst=(x−0x18,y−0x18)；
    return HP≠0 且（[0x28]>0 或 x<0x298）。"""
    e.d32(0x20, (e.s32(0x20) - e.s32(0x28)) & 0xFFFFFFFF)
    e.d32(0x24, (e.s32(0x24) + e.s32(0x28)) & 0xFFFFFFFF)
    if e.s32(0x28) != 0:
        e.d32(0x28, (e.s32(0x28) - 1) & 0xFFFFFFFF)
    y = (e.s32(0x24) - 0x100000000 if e.s32(0x24) & 0x80000000 else e.s32(0x24)) >> 4
    x = (e.s32(0x20) - 0x100000000 if e.s32(0x20) & 0x80000000 else e.s32(0x20)) >> 4
    e.d32(0x08, y & 0xFFFFFFFF)
    e.d32(0x04, x & 0xFFFFFFFF)
    self.p4_4193e0(e, 8,0,0x30)
    if e.s32(0x28) == 0 and e.s32(0x1C) == 0:
        if e.s32(0x30) != 0:
            w2c = e.g16(0x2C)
            w2e = e.g16(0x2E)
            self.p4_43B360(e, w2c - 0x10000 if w2c & 0x8000 else w2c,
                           w2e - 0x10000 if w2e & 0x8000 else w2e, 0)
        else:
            e.d16(0x2C, self.p4_player_x() & 0xFFFF)
            e.d16(0x2E, self.p4_player_y() & 0xFFFF)
        c = (e.s32(0x30) + 1) & 0xFFFFFFFF
        e.d32(0x30, c)
        if c == 0xC:
            e.d32(0x28, -1 & 0xFFFFFFFF)
    if e.node is not None:
        e.node.dst = (x - 0x18, y - 0x18)
    return e.g32(0x18) != 0 and (e.s32(0x28) > 0 or x < 0x298)


def _beh_419B70(self, e) -> bool:
    """`0x419B70`（0x28000011）：[0x20] += [0x24]；x>0xA0 → x −= 3、
    [0x24]≠0 → [0x24] += ([0x24]≥0 ? −1 : +1)；x≤0xA0 → x −= 2、
    [0x24]≠0 → ([0x24]≥0 ? +1 : −1)、==0 → [0x24] += (y≥0xF0 ? −1 : +1)；
    y = [0x20]>>4；0x401BA4(8,0,0x30) 特效；node dst=(x−0x18,y−0x18)；
    return HP≠0 且 x>−0x18。"""
    e.d32(0x20, (e.s32(0x20) + e.s32(0x24)) & 0xFFFFFFFF)
    x = e.s32(0x04)
    v = e.s32(0x24)
    if x > 0xA0:
        x -= 3
        if v != 0:
            v = (v + (-1 if v >= 0 else 1)) & 0xFFFFFFFF
    else:
        x -= 2
        if v != 0:
            v = (v + (1 if v >= 0 else -1)) & 0xFFFFFFFF
        else:
            v = (v + (-1 if e.s32(0x08) >= 0xF0 else 1)) & 0xFFFFFFFF
    e.d32(0x04, x & 0xFFFFFFFF)
    e.d32(0x24, v)
    s20 = e.s32(0x20)
    y = (s20 - 0x100000000 if s20 & 0x80000000 else s20) >> 4
    e.d32(0x08, y & 0xFFFFFFFF)
    self.p4_4193e0(e, 8,0,0x30)
    if e.node is not None:
        e.node.dst = (x - 0x18, y - 0x18)
    return e.g32(0x18) != 0 and x > -0x18


def _beh_419A30(self, e) -> bool:
    """`0x419A30`（0x28000008）：**护卫伴随 + 掩护开火**。

    [0x24] += [0x28]（纵摆累积）、y = [0x24]>>4；
    [0x28] += ([0x20] ≥ y ? +1 : −1)（setge; dec; and 0xFFFFFFFE; inc）；
    x −= 1；0x401BA4(0x10,1,0x30) 特效。
    [0x2C]（伴随句柄）==0 → 发 0x28000008 @ (x+0x60, y+0xC0) 入 0x4AD43C、
    [0x2C]=新体指针（复刻存句柄）；
    [0x2C]==−1 → (x&0x1F)==0 → 0x43B070(e,0)；
    否则链体死（byte[+0x34]）→ [0x2C]=−1。
    node dst=(x−0x18,y−0x18)；return HP≠0 且 x>−0x18。"""
    e.d32(0x24, (e.s32(0x24) + e.s32(0x28)) & 0xFFFFFFFF)
    v = e.s32(0x28)
    v = (v + (1 if e.s32(0x20) >= e.s32(0x08) else -1)) & 0xFFFFFFFF
    e.d32(0x28, v)
    e.d32(0x08, ((e.s32(0x24) - 0x100000000 if e.s32(0x24) & 0x80000000
                  else e.s32(0x24)) >> 4) & 0xFFFFFFFF)
    e.d32(0x04, (e.s32(0x04) - 1) & 0xFFFFFFFF)
    self.p4_4193e0(e, 0x10,1,0x30)
    h = e.s32(0x2C)
    if h == 0:
        c = self._p4_ent43c(0x28000008, e.s32(0x04) + 0x60, e.s32(0x08) + 0xC0)
        e.d32(0x2C, (id(c) & 0x7FFFFFFF))
        getattr(self, "p4_links", {})[id(c) & 0x7FFFFFFF] = c
    elif h == -1:
        if (e.s32(0x04) & 0x1F) == 0:
            self.p4_43B070(e, 0)
    else:
        linked = getattr(self, "p4_links", {}).get(h & 0x7FFFFFFF)
        if linked is None or linked.m[0x34] == 0:      # 0x419ADA：死才脱链
            e.d32(0x2C, -1 & 0xFFFFFFFF)
    if e.node is not None:
        e.node.dst = (e.s32(0x04) - 0x18, e.s32(0x08) - 0x18)
    return e.g32(0x18) != 0 and e.s32(0x04) > -0x18


def _beh_419C60(self, e) -> bool:
    """`0x419C60`（0x28000009）：y = [0x20]；x += (y≥0xF0 ? −6 : +6)
    （setge; dec; and 0xC; add −6 → (y≥0xF0)?−6:+6）；
    x<−0x78 或 x>0x2F8 → 重算：y' = [0x20] + (y≥0xF0 ? +0x1E0−0xF0? : …)
      （and 0x1E0/add 0xFFFFFF10 → (y≥0xF0)? +0x1E0−0xF0=+0xF0 : −0xF0+... 字面：
      and 0x1E0 → (y≥0xF0)?0x1E0:0、+0xFFFFFF10(−0xF0)、+[0x20]），
      [0x24]++（折返计数）；
    [0x10] = (−0x18<x<0x298)；0x401BA4(0x20,2,0x30) 特效；node dst 同步；
    return HP≠0 且 [0x24]<4。"""
    y = e.s32(0x20)
    e.d32(0x08, y & 0xFFFFFFFF)
    e.d32(0x04, (e.s32(0x04) + (-6 if y >= 0xF0 else 6)) & 0xFFFFFFFF)
    x = e.s32(0x04)
    if x < -0x78 or x > 0x2F8:
        ny = (y + (0x1E0 if y >= 0xF0 else 0) - 0xF0) & 0xFFFFFFFF
        e.d32(0x20, ny)
        e.d32(0x24, (e.s32(0x24) + 1) & 0xFFFFFFFF)
    x = e.s32(0x04)
    vis = 1 if -0x18 < x < 0x298 else 0
    e.m[0x10] = vis
    self.p4_4193e0(e, 0x20,2,0x30)
    if e.node is not None:
        e.node.dst = (x - 0x18, y - 0x18)
    return e.g32(0x18) != 0 and e.s32(0x24) < 4


def _beh_419D50(self, e) -> bool:
    """`0x419D50`（0x2800000A）：[0x20] += [0x24]、[0x24]≠0 → [0x24]−−（减速）；
    x −= ([0x24]==0 ? 2 : 3)（neg/sbb: [0x24]!=0 → 3−1=2? 字面：
    eax = −([0x24]!=0) + 3 → ([0x24]!=0)?2:3）；y = [0x20]>>3；
    x==0x1E4 → [0x24]=0x30（再加速）；0x401BA4(0x10,1,0x30) 特效；
    [0x24]≠0 且 [0x28]≠0 且 (x&0x1F)==0 → 0x43B070(e,0)；node dst 同步；
    return HP≠0 且 x>−0x18。"""
    e.d32(0x20, (e.s32(0x20) + e.s32(0x24)) & 0xFFFFFFFF)
    if e.s32(0x24) != 0:
        e.d32(0x24, (e.s32(0x24) - 1) & 0xFFFFFFFF)
    dx = 2 if e.s32(0x24) != 0 else 3
    x = (e.s32(0x04) - dx) & 0xFFFFFFFF
    e.d32(0x04, x)
    s20 = e.s32(0x20)
    e.d32(0x08, ((s20 - 0x100000000 if s20 & 0x80000000 else s20) >> 3) & 0xFFFFFFFF)
    if x == 0x1E4:
        e.d32(0x24, 0x30)
    self.p4_4193e0(e, 0x10,1,0x30)
    if e.s32(0x24) != 0 and e.s32(0x28) != 0 and (x & 0x1F) == 0:
        self.p4_43B070(e, 0)
    if e.node is not None:
        e.node.dst = (x - 0x18, e.s32(0x08) - 0x18)
    return e.g32(0x18) != 0 and x > -0x18


def _beh_419F80(self, e) -> bool:
    """`0x419F80`（0x2800000D）：step = x>0x118 ? 2 : 0x11A−x；
    [0x28] −= step、x = [0x28]>>2、y = [0x20]；0x401BA4(0x20,1,0x30) 特效；
    ++[0x24]，(&0x3F)==0 且 x<0x208 → 0x43B070 ×4（表速 0/[0x58]+0x80/
    [0x58]+0x100/[0x58]+0x180）；node dst=(x−0x18,y−0x18)；
    return HP≠0 且 x>−0x18。"""
    x0 = e.s32(0x04)
    step = 2 if x0 > 0x118 else 0x11A - x0
    v = (e.s32(0x28) - step) & 0xFFFFFFFF
    e.d32(0x28, v)
    x = (v - 0x100000000 if v & 0x80000000 else v) >> 2
    e.d32(0x04, x & 0xFFFFFFFF)
    e.d32(0x08, e.s32(0x20) & 0xFFFFFFFF)
    self.p4_4193e0(e, 0x20,1,0x30)
    c = (e.s32(0x24) + 1) & 0xFFFFFFFF
    e.d32(0x24, c)
    if (c & 0x3F) == 0 and x < 0x208:
        self.p4_43B070(e, 0)
        self.p4_43B070(e, (e.s32(0x58) + 0x80) & 0xFFFFFFFF)
        self.p4_43B070(e, (e.s32(0x58) + 0x100) & 0xFFFFFFFF)
        self.p4_43B070(e, (e.s32(0x58) + 0x180) & 0xFFFFFFFF)
    if e.node is not None:
        e.node.dst = (x - 0x18, e.s32(0x08) - 0x18)
    return e.g32(0x18) != 0 and x > -0x18


def _beh_41A300(self, e) -> bool:
    """`0x41A300`（0x28000012）：**减速盘旋 + 环形弹幕**。

    [0x28] += [0x20]、[0x24] −= [0x20]>>1；y=[0x28]>>3、x=[0x24]>>3；
    0x401BA4(0x18,0,0x60) 特效；[0x20]≠0 → [0x20]−−；
    否则 ([0x2C]&0xF)==0 且 y>0 → 环形弹幕：tx=自机x+(rand&0x1FF)−0xFF、
    ty=自机y+(rand&0x1FF)−0xFF；spd 从 [0x58] 每次 −0x100 直到 < [0x58]−0x200，
    每圈 0x43B360(e, tx, ty, spd)。
    t=++[0x2C]：0xC0 → [0x20]=0；0x110 → [0x20]=0x50；0x5D2 → [0x20]=−1；
    0x82A → [0x20]=−1（同点合并）；node dst=(x−0x30,y−0x30)；
    t==0x898 → return 0；否则 HP≠0。"""
    e.d32(0x28, (e.s32(0x28) + e.s32(0x20)) & 0xFFFFFFFF)
    e.d32(0x24, (e.s32(0x24) - (e.s32(0x20) >> 1)) & 0xFFFFFFFF)
    a28 = e.s32(0x28)
    a24 = e.s32(0x24)
    y = (a28 - 0x100000000 if a28 & 0x80000000 else a28) >> 3
    x = (a24 - 0x100000000 if a24 & 0x80000000 else a24) >> 3
    e.d32(0x08, y & 0xFFFFFFFF)
    e.d32(0x04, x & 0xFFFFFFFF)
    self.p4_4193e0(e, 0x18,0,0x60)
    if e.s32(0x20) != 0:
        e.d32(0x20, (e.s32(0x20) - 1) & 0xFFFFFFFF)
    elif (e.s32(0x2C) & 0xF) == 0 and y > 0:
        tx = self.p4_player_x() + (self.p4_rand() & 0x1FF) - 0xFF
        ty = self.p4_player_y() + (self.p4_rand() & 0x1FF) - 0xFF
        spd = e.s32(0x58)
        while spd >= e.s32(0x58) - 0x200:           # 0x41A38F 环（死循环保护：步进必减）
            self.p4_43B360(e, tx, ty, spd & 0xFFFFFFFF)
            spd -= 0x100
    t = (e.s32(0x2C) + 1) & 0xFFFFFFFF
    e.d32(0x2C, t)
    if t == 0xC0:                                  # 0x41A3B6
        e.d32(0x20, -1 & 0xFFFFFFFF)
    elif t == 0x110:
        e.d32(0x20, 0)
    elif t == 0x5D2:
        e.d32(0x20, 0x50)
    elif t == 0x82A:
        e.d32(0x20, -1 & 0xFFFFFFFF)
    if e.node is not None:
        e.node.dst = (x - 0x30, y - 0x30)
    if t == 0x898:
        return False
    return e.g32(0x18) != 0


def _p4_41a480_abs2(v: int) -> int:
    """cdq/xor/sub 的 |v|（0x41A712/0x41A8ED 模式）。"""
    return -v if v < 0 else v


def _beh_41A480(self, e) -> bool:
    """`0x41A480`（0x28000013）：**八态 boss 编舞**。

    入口 [0x20]==0（漂移）：x −= 4、y += 6；y==0xF0 → [0x20]=1（启动）。
    [0x20]≠0：t24=++[0x24]（%0x12C 回零）；
    x = 0x1E0 + (45*cos(24t24+0x384) >> 4)、y = 0xF0 + (25*sin(12t24) >> 3)
    （24t=(3t)*8、12t=(3t)*4；0x40159B=cos/0x401A50=sin）；
    [0x1C]++：t<0x40 → y += t>>2；0x40≤t≤0x4B 帧表 0x41ABEC/0x41ABFC
    （sel [0,3,3,3,0,3,3,3,1,3,3,3,2]）：case0/2 → rect 行 −0x90（case2 先 [0x1C]=0）、
    case1 → +0x90（0x45A790(node+4,0,dy,0,dh)）；
    [0x28]（态内计时）== 栈表[态] {0x104,0xB4,0xB4,0xB4,0xE1,0x12C,0xB4,−1}[ecx] →
    [0x28]=0、[0x20] += (ecx>7 ? −6 : +1)（and 7/add −6 → ecx>7?−6:+1）… 字面
    (ecx−7<0 ? +1 : −6)；否则 [0x28]++。
    [0x2C]++ ==0x1784 → HP=0。
    态分派（0x41AC0C，s=[0x20]−1，s>7 跳过）：
      态1 0x41A5FA：t<0xC8 且 t&3==0 → 0x43B430(e, cos(36t)*180, sin(36t)*180,
          0x340) 双向（0x402144→0x43B430；参数 esi=cos*180、edi−… 见批注）
      态2 0x41A6C1：t<0x61 且 t&0x1F==0 → 0x43B070(e, spd)，spd −0x200..−0x900
          步 −0x100（esi 0xFFFFFE00 起减 0x100 至 0xFFFFF700）
      态3 0x41A6EA：t<0x61 且 t&0x1F==0 → 螺旋：esi −0x112..、edi 0x1C2 步 0x96、
          27 圈：base = (t&0x20)?(|esi+0x15|<0xF?|esi+0xC|+2:|esi|+2)
                           :(|esi+0x15|<0xF?8−|esi+0xC|:8−|esi|)；
          0x43B290(e, cos(edi), sin(edi), −(base<<8))
      态4 0x41A77A：t&7==0 → 0x43B500(e, x−0x10, y+((t&4)?−0xB0:+0x10),
          自机x+0x40, 自机y+((t&8)?0:−0xA0)+rand%0xA0, 0x340)；
          t==0x78 → 0x430400(&rec,7,0x10,0x61000001,0x28000006) 入 0x4AD52C
      态5 0x41A830：t&0x1F==0 → 0x43B290(e, −0xA, 0, −0x40)
      态6 0x41A84B：t<0xD1 且 t&0xF==0 → 扇形：esi=t*0x11 步 0x11、
          edi=t..t+0xE：0x43B290(e, cos(esi*0x11), sin(esi*0x11), −0x500)
          （字面：ang=edi*0x11、spd=0xFFFFFB00）
      态7 0x41A8A8：t<0x81 且 t&0x3F==0 → 0x43B070 锥形：ang=|0x45A9A0(Δ自机)−0x384|
          、spd=−(0x700..0x100 步 …)（esi=Δang−0x384、edi 0..0xD00 步 0x100：
          0x43B290(e, cos(esi), sin(esi), −(|edi−0x600|−0x700))）
      态8 0x41A92C：t 奇 → jx/jy=rand&0x3F−0x1F、
          0x430400(&rec, x+rand%0x61−0x30, y+rand%0x61−0x30, 0x41000004,
          prm=&{jy,…}) 入 0x4AD4CC；t==0x78 → 0x41000001@(x,y) 入 0x4AD4CC。
    HP 段 0x41A67A：[0x20]==8 例外；否则 [0x20]=8、[0x28]=0、[0x10]=0。
    node dst=(x−0x48, y−0x48)；return 1。"""
    if e.s32(0x20) == 0:
        y = (e.s32(0x08) + 6) & 0xFFFFFFFF
        x = (e.s32(0x04) - 4) & 0xFFFFFFFF
        e.d32(0x04, x)
        e.d32(0x08, y)
        if y == 0xF0:
            e.d32(0x20, 1)
        return True
    t24 = (e.s32(0x24) + 1) & 0xFFFFFFFF
    if t24 == 0x12C:
        t24 = 0
    e.d32(0x24, t24)
    x = 0x1E0 + ((45 * page4_cos((24 * t24 + 0x384) & 0xFFFFFFFF)) >> 4)
    y = 0xF0 + ((25 * page4_sin((12 * t24) & 0xFFFFFFFF)) >> 3)
    e.d32(0x04, x & 0xFFFFFFFF)
    t1c = (e.s32(0x1C) + 1) & 0xFFFFFFFF
    e.d32(0x1C, t1c)
    if t1c < 0x40:
        y += t1c >> 2
    elif t1c <= 0x4C:
        sel = (0, 3, 3, 3, 0, 3, 3, 3, 1, 3, 3, 3, 2)[t1c - 0x40]
        if sel != 3:
            e.d32(0x1C, 0) if sel == 2 else None
            dy = -0x90 if sel != 1 else 0x90
            nd = e.node
            if nd is not None:
                nd.rect = (nd.rect[0], nd.rect[1] + dy, nd.rect[2], nd.rect[3] + dy)
    e.d32(0x08, y & 0xFFFFFFFF)
    st = e.s32(0x20)
    t28 = e.s32(0x28)
    lim = (0x104, 0xB4, 0xB4, 0xB4, 0xE1, 0x12C, 0xB4, -1)[st - 1] if 1 <= st <= 8 else None
    if lim is not None and t28 == lim:
        e.d32(0x28, 0)
        e.d32(0x20, (st + (1 if st <= 7 else -6)) & 0xFFFFFFFF)
    else:
        e.d32(0x28, (t28 + 1) & 0xFFFFFFFF)
    t28 = e.s32(0x28)
    if st == 1 and t28 < 0xC8 and (t28 & 3) == 0:            # 0x41A5FA
        ang = (36 * t28) & 0xFFFFFFFF
        self.p4_43B430(e, page4_cos(ang) * 0xB4, page4_sin(ang) * 0xB4, 0x340)
    elif st == 2 and t28 < 0x61 and (t28 & 0x1F) == 0:       # 0x41A6C1
        spd = -0x200
        while spd >= -0x900:
            self.p4_43B070(e, spd & 0xFFFFFFFF)
            spd -= 0x100
    elif st == 3 and t28 < 0x61 and (t28 & 0x1F) == 0:       # 0x41A6EA
        esi = -0x112
        edi = 0x1C2
        while esi + 0x15 < 0x1B:
            if t28 & 0x20:
                base = (self._p4_41a480_abs2(esi + 0xC) + 2 if self._p4_41a480_abs2(esi + 0x15) < 0xF
                        else self._p4_41a480_abs2(esi) + 2)
            else:
                base = (8 - self._p4_41a480_abs2(esi + 0xC) if self._p4_41a480_abs2(esi + 0x15) < 0xF
                        else 8 - self._p4_41a480_abs2(esi))
            ang = edi & 0xFFFFFFFF
            self.p4_43B290(e, page4_cos(ang), page4_sin(ang),
                           (-(base << 8)) & 0xFFFFFFFF)
            esi += 1
            edi += 0x96
    elif st == 4:                                            # 0x41A77A
        if (t28 & 7) == 0:
            r = self.p4_rand() % 0xA0
            y1 = self.p4_player_y() + (0 if t28 & 8 else -0xA0) + r
            y0 = y + (-0xB0 if t28 & 4 else 0x10)
            self.p4_43B500(e, x - 0x10, y0, self.p4_player_x() + 0x40, y1, 0x340)
        if t28 == 0x78:
            self.p4_spawn52c_flash(7, 0x10, 0x61000001, 0x28000006)
    elif st == 5 and (t28 & 0x1F) == 0:                      # 0x41A830
        self.p4_43B290(e, -0xA, 0, -0x40 & 0xFFFFFFFF)
    elif st == 6 and t28 < 0xD1 and (t28 & 0xF) == 0:        # 0x41A84B
        edi = t28
        while edi < t28 + 0xE:
            ang = (edi * 0x11) & 0xFFFFFFFF
            self.p4_43B290(e, page4_cos(ang), page4_sin(ang), -0x500 & 0xFFFFFFFF)
            edi += 1
    elif st == 7 and t28 < 0x81 and (t28 & 0x3F) == 0:       # 0x41A8A8
        da = self.p4_45a9a0(self.p4_player_x() - x, self.p4_player_y() - y)
        esi = da - 0x384
        edi = 0
        while edi < 0xD00:
            ang = esi & 0xFFFFFFFF
            spd = -(self._p4_41a480_abs2(edi - 0x600) + 0x700)
            self.p4_43B290(e, page4_cos(ang), page4_sin(ang), spd & 0xFFFFFFFF)
            edi += 0x100
            esi += 0x96
    elif st == 8:                                            # 0x41A92C
        if t28 & 1:
            jx = (self.p4_rand() & 0x3F) - 0x1F
            jy = (self.p4_rand() & 0x3F) - 0x1F
            rx = self.p4_rand() % 0x61
            ry = self.p4_rand() % 0x61
            self.spawn(self._p4_q("ui4cc"), 0x41000004,
                       x + rx - 0x30, y + ry - 0x30, (jx, jy))
        if t28 == 0x78:
            self.spawn(self._p4_q("ui4cc"), 0x41000001, x, y, 0)
    if e.s32(0x20) != 8:                                     # 0x41A67A HP 段
        e.d32(0x20, 8)
        e.d32(0x28, 0)
        e.m[0x10] = 0
    t2c = (e.s32(0x2C) + 1) & 0xFFFFFFFF
    e.d32(0x2C, t2c)
    if t2c == 0x1784:
        e.d32(0x18, 0)
    if e.node is not None:
        e.node.dst = (x - 0x48, y - 0x48)
    return True


def _beh_41BDA0(self, e) -> bool:
    """`0x41BDA0`（0x28000016）：**绕长机卫星**。

    每帧 [0x18]=−1（无敌标记）；leader = [0x20]（句柄）；
    leader[0x28]≠5 → [0x1C]++（公转角）；ang = 17t；
    x = leader.x + (3*cos(17t)>>3)、y = leader.y + (3*sin(17t)>>3)；
    leader.type==0x28000017 → [0x20] = leader[0x2C]（链式跟随）。
    leader[0x28]==5 且 leader[0x24]==0x78 → SE 0xE + 10× 0x31000010
    @(x, y+0xC*i) i=0..0x78 步 0xC 入 0x4AD49C、return 0；
    leader 死（byte[+0x34]）→ 0x41000001@(x,y) 入 0x4AD4CC、return 0；
    node dst=(x−0x18,y−0x18)；return 1。"""
    e.d32(0x18, -1 & 0xFFFFFFFF)
    links = getattr(self, "p4_links", {})
    h = e.s32(0x20)
    leader = links.get(h & 0x7FFFFFFF) if h else None
    if leader is None:
        return True
    if leader.s32(0x28) != 5:
        e.d32(0x1C, (e.s32(0x1C) + 1) & 0xFFFFFFFF)
    ang = (17 * e.s32(0x1C)) & 0xFFFFFFFF
    x = leader.s32(0x04) + ((3 * page4_cos(ang)) >> 3)
    y = leader.s32(0x08) + ((3 * page4_sin(ang)) >> 3)
    e.d32(0x04, x & 0xFFFFFFFF)
    e.d32(0x08, y & 0xFFFFFFFF)
    if leader.s32(0x14) == 0x28000017:
        e.d32(0x20, leader.g32(0x2C) & 0xFFFFFFFF)
    leader = links.get(e.s32(0x20) & 0x7FFFFFFF) or leader
    if leader.s32(0x28) == 5 and leader.s32(0x24) == 0x78:
        self.p4_se_pan(0xE, (x - 0x140) << 4)
        for i in range(0, 0x6D, 0xC):               # rec3=0,0xC,..,0x6C
            self.spawn(self._p4_q("ui49c"), 0x31000010, x, y, i)
        return False
    if leader.m[0x34] != 0:
        self.spawn(self._p4_q("ui4cc"), 0x41000001, x, y, 0)
        return False
    if e.node is not None:
        e.node.dst = (x - 0x18, y - 0x18)
    return True


def _beh_41BF60(self, e) -> bool:
    """`0x41BF60`（0x28000018）：**两段冲刺弹**。

    [0x28] += [0x20]、[0x2C] += [0x24]；x = [0x28]>>3、y = [0x2C]>>3；
    [0x1C]−−==0（段切换）→ 速度 = 64×单位向自机（0x45AA80*Δ>>6）；
    node dst=(x−0x18,y−0x18)；0x430640(e) 在屏判据；
    return 在屏 且 HP≠0。"""
    e.d32(0x28, (e.s32(0x28) + e.s32(0x20)) & 0xFFFFFFFF)
    e.d32(0x2C, (e.s32(0x2C) + e.s32(0x24)) & 0xFFFFFFFF)
    a28 = e.s32(0x28)
    a2c = e.s32(0x2C)
    x = (a28 - 0x100000000 if a28 & 0x80000000 else a28) >> 3
    y = (a2c - 0x100000000 if a2c & 0x80000000 else a2c) >> 3
    e.d32(0x04, x & 0xFFFFFFFF)
    e.d32(0x08, y & 0xFFFFFFFF)
    t = (e.s32(0x1C) - 1) & 0xFFFFFFFF
    e.d32(0x1C, t)
    if t == 0:
        dx = self.p4_player_x() - x
        dy = self.p4_player_y() - y
        inv = self.p4_45aa80(dx, dy)
        e.d32(0x20, ((inv * dx) >> 6) & 0xFFFFFFFF)
        e.d32(0x24, ((inv * dy) >> 6) & 0xFFFFFFFF)
    if e.node is not None:
        e.node.dst = (x - 0x18, y - 0x18)
    return self.p4_430640(e) and e.g32(0x18) != 0


def _beh_41AE20(self, e) -> bool:
    """`0x41AE20`（0x28000014，**关6 boss 三形态本体**）。

    每帧：目标收敛 x += (Δx+0x10)>>5、y += (Δy+0x10)>>5（[0x1C]/[0x20] 为目标点）。
    HP>0x960：[0x48]（部件计数）门 → 0x45AFC0(0x4AB5B0,0xC000)==2/3 且 [0x48]<4 →
    跳死亡流程；HP −= 20*min([0x48],8)；发 0x28000015 @(x,y) 入 43C；变身
    [0x14]=0x28000017、[0x40]=0x41BD20、[0xC]=0x18、[0x10]=1；速度 = 256×单位向机
    → [0x1C]/[0x20]（冲刺目标）；[0x24]=x<<3、[0x28]=y<<3（备用）；HP =
    (min([0x48],8)<<6)−1；0x45A750(&rec,0x120,0xF0,0x14F,0x11F) 大图 rect 落 node+4；
    return 1。
    HP≤0x960：（node.dst.y==0xF0 且 (t&7)==0 → rect 行 +0x30）后进十态机：
    态0 铺卫星 / 态1 每0x40帧传送目标(x=rand%0x118+0x154, y=rand%0x190+0x28)、
    t==0 选下态 rand%(5|6)+2（[0x2C] 门控 7/5 重掷）/ 态2 锁机冲刺+双 0x3100000C /
    态3 传送+0x3100000D / 态4 每0x40帧随机点 / 态5 rand 点+归中间 / 态6 逼近自机+
    角向弹 / 态7 淡入淡出+0x28000018+随机点开门 / 态8 y 分段横穿+0x31000013 ±0x20 /
    态9 12× 0x41000004 爆散。HP==0 且态≠9 → 淡出 + [0x28]=9。node dst=(x−0x18,y−0x18)。
    复刻侧 [0x20]→p4_links 句柄、[0x2C] 保持数值。"""
    links = getattr(self, "p4_links", {})
    # 入口目标收敛（0x41AE2C）
    tx = e.s32(0x1C)
    ty = e.s32(0x20)
    dx = tx - e.s32(0x04)
    dy = ty - e.s32(0x08)
    if dx != 0 or dy != 0:
        e.d32(0x04, (e.s32(0x04) + ((dx + 0x10) >> 5)) & 0xFFFFFFFF)
        e.d32(0x08, (e.s32(0x08) + ((dy + 0x10) >> 5)) & 0xFFFFFFFF)
    x = e.s32(0x04)
    y = e.s32(0x08)
    hp = e.g32(0x18)
    if hp > 0x960:                                   # 0x41AE71 进场段
        n48 = e.s32(0x48)
        if n48 == 0:
            return _p4_41ae20_dying_common(e, x, y)
        key = self.keys.field(0xC000) & 3               # 0x45AFC0(0x4AB5B0,0xC000)
        if key in (2, 3) and n48 < 4:
            return _p4_41ae20_dying_common(e, x, y)
        n = 8 if n48 >= 8 else n48
        e.d32(0x18, (hp - 20 * n) & 0xFFFFFFFF)
        c = self._p4_ent43c(0x28000015, x, y)
        e.d32(0x14, 0x28000017)
        e.d32(0x40, 0x41BD20)                        # 卫星行为 thunk→0x41BD20
        e.d32(0x0C, 0x18)
        e.m[0x10] = 1
        dx2 = self.p4_player_x() - x
        dy2 = self.p4_player_y() - y
        inv = self.p4_45aa80(dx2, dy2)
        e.d32(0x1C, (x + ((inv * dx2) >> 8)) & 0xFFFFFFFF)
        e.d32(0x20, (y + ((inv * dy2) >> 8)) & 0xFFFFFFFF)
        e.d32(0x24, (x << 3) & 0xFFFFFFFF)
        e.d32(0x28, (y << 3) & 0xFFFFFFFF)
        e.d32(0x2C, ((id(c)) & 0x7FFFFFFF))
        links[id(c) & 0x7FFFFFFF] = c
        e.d32(0x18, ((n << 6) - 1) & 0xFFFFFFFF)
        nd = e.node
        if nd is not None:
            nd.rect = (0x120, 0xF0, 0x14F, 0x11F)
        return True
    return _p4_41ae20_dying_common(e, x, y)


def _p4_41ae20_dying_common(e, x: int, y: int) -> bool:
    """`0x41AE20` HP≤0x960 段：行闪特效 + 十态机 + 公共尾。"""
    self = e._pages
    _h = id(e) & 0x7FFFFFFF
    self.p4_links[_h] = e
    hp = e.g32(0x18)
    if hp <= 0x960 and e.node is not None and e.node.dst[1] == 0xF0 \
            and (e.s32(0x24) & 7) == 0:
        nd = e.node
        nd.rect = (nd.rect[0], nd.rect[1] + 0x30, nd.rect[2], nd.rect[3] + 0x30)
    st = e.s32(0x28)
    t = e.s32(0x24)
    if st <= 9:
        if st == 0:
            if t == 0:
                self._p4_ent43c(0x28000016, x, y, _h)
            elif t == 0x5A:
                e.m[0x10] = 1
                e.d32(0x24, -0x1E & 0xFFFFFFFF)
                e.d32(0x28, 1)
        elif st == 1:
            if (t & 0x3F) == 0:
                e.d32(0x1C, (self.p4_rand() % 0x118 + 0x154) & 0xFFFFFFFF)
                e.d32(0x20, (self.p4_rand() % 0x190 + 0x28) & 0xFFFFFFFF)
            if t == 0:
                gate = e.s32(0x2C)
                while True:
                    nxt = self.p4_rand() % (6 if gate else 5) + 2
                    e.d32(0x28, nxt)
                    if nxt == 7:
                        if gate & 0xF:
                            return _p4_41ae20_tail(e, x, y, t)
                        continue
                    if nxt == 5 and (gate & 0xF0):
                        continue
                    break
                return _p4_41ae20_tail(e, x, y, t)
        elif st == 2:
            if t == 1:
                e.d32(0x1C, self.p4_player_x() & 0xFFFFFFFF)
                e.d32(0x20, self.p4_player_y() & 0xFFFFFFFF)
            elif t == 0x3C:
                e.d32(0x1C, 0x260)
                yy = e.s32(0x20)
                e.d32(0x20, (yy + (0x1D0 if yy >= 0xF0 else -0x10)) & 0xFFFFFFFF)
            elif t == 0x14A:
                e.d32(0x24, -0x3C & 0xFFFFFFFF)
                e.d32(0x28, 1)
            if t > 0x96 and (t & 3) == 0:
                self.p4_se_pan(2, (x - 0x140) << 4)
                self.spawn(self._p4_q("ui49c"), 0x3100000C, x - 8, y, -1)
                self.spawn(self._p4_q("ui49c"), 0x3100000C, x - 8, y, 1)
        elif st == 3:
            if t in (1, 0x14, 0x28, 0x3C, 0x50):
                e.d32(0x1C, (self.p4_rand() % 0xA0 + 0x190) & 0xFFFFFFFF)
                e.d32(0x20, (self.p4_rand() % 0xA0 + 0xA0) & 0xFFFFFFFF)
            elif t == 0x168:
                e.d32(0x24, -0x5A & 0xFFFFFFFF)
                e.d32(0x28, 1)
            if t > 0x5A and (t & 3) == 0:
                self.p4_se_pan(2, (x - 0x140) << 4)
                self.spawn(self._p4_q("ui49c"), 0x3100000D, x - 8, y, 0)
        elif st == 4:
            if (t & 0x3F) == 0:
                e.d32(0x1C, (self.p4_rand() % 0x78 + 0x1E0) & 0xFFFFFFFF)
                e.d32(0x20, (self.p4_rand() % 0xF0 + 0x78) & 0xFFFFFFFF)
        elif st == 5:
            if t == 1:
                e.d32(0x1C, (self.p4_rand() % 0x50 + 0x1E0) & 0xFFFFFFFF)
                e.d32(0x20, (self.p4_rand() % 0x50 + 0xC8) & 0xFFFFFFFF)
                e.d32(0x2C, (e.s32(0x2C) - 0x10) & 0xFFFFFFFF)
            elif t == 0x168:
                e.d32(0x24, 0)
                e.d32(0x28, 8)
        elif st == 6:
            if t == 0x3C:
                e.d32(0x1C, ((x * 3 + self.p4_player_x()) >> 2) & 0xFFFFFFFF)
                e.d32(0x20, ((y * 3 + self.p4_player_y()) >> 2) & 0xFFFFFFFF)
            elif t == 0x168:
                e.d32(0x24, -0x78 & 0xFFFFFFFF)
                e.d32(0x28, 1)
            if (t & 3) == 1:
                da = self.p4_45a9a0(self.p4_player_x() - x, self.p4_player_y() - y)
                ang = (da + 18 * t) & 0xFFFFFFFF
                self.p4_43B070(e, 0)
                self.p4_43B290(e, page4_cos(ang), page4_sin(ang), 0)
        elif st == 7:
            if t == 1:
                self.p4_spawn52c_flash(0, 0x10, 0x61000005, 0xFF)
                e.d32(0x2C, (e.s32(0x2C) - 1) & 0xFFFFFFFF)
            elif t == 0x11:
                self.spawn(self._p4_q("ui49c"), 0x28000018, x, y, 0)
            elif t == 0x14:
                self.p4_spawn52c_flash(0, -0x10, 0x61000005, 0xFF)
            elif 1 <= t <= 0x14:
                ry = self.p4_rand() % 0x1E0
                rx = self.p4_rand() % 0x280
                if abs(rx - self.p4_player_x()) + abs(ry - self.p4_player_y()) > 0xC0:
                    self._p4_ent43c(0x28000018, rx, ry)
            elif t == 0x168:
                e.d32(0x24, -0x78 & 0xFFFFFFFF)
                e.d32(0x28, 1)
        elif st == 8:
            if t == 1:
                e.d32(0x1C, 0x280)
                e.d32(0x20, -0x60 & 0xFFFFFFFF)
            elif t == 0x186:
                self._p4_ent43c(0x28000016, x, y, _h)
                e.d32(0x1C, 0x1E0)
                e.d32(0x20, 0xF0)
            elif t == 0x1A4:
                e.d32(0x24, -0xB4 & 0xFFFFFFFF)
                e.d32(0x28, 1)
            if t > 0x78:
                if y > 0xF0:
                    if t <= 0x186:
                        e.d32(0x1C, 0x258)
                        e.d32(0x20, (y + 0x100) & 0xFFFFFFFF)
                        if self.p4_rand() % 0xA == 0:
                            self.p4_se_pan(0xA, (x - 0x140) << 4)
                            self.spawn(self._p4_q("ui49c"), 0x31000013, x, y, -0x20)
                else:
                    if t < 0x186:
                        e.d32(0x1C, 0x258)
                        e.d32(0x20, (y - 0x100) & 0xFFFFFFFF)
                        if self.p4_rand() % 0xA == 0:
                            self.p4_se_pan(0xA, (x - 0x140) << 4)
                            self.spawn(self._p4_q("ui49c"), 0x31000013, x, y, 0x20)
        elif st == 9:
            for _ in range(0xC):
                rx = self.p4_rand() % 0x61
                ry = self.p4_rand() % 0x61
                jx = (self.p4_rand() & 0x3F) - 0x1F
                jy = (self.p4_rand() & 0x3F) - 0x1F
                self.spawn(self._p4_q("ui4cc"), 0x41000004,
                           x + rx - 0x30, y + ry - 0x30, (jx, jy))
            self.spawn(self._p4_q("ui4cc"), 0x41000001, x, y, 0)
    return _p4_41ae20_tail(e, x, y, t)


def _p4_41ae20_tail(e, x: int, y: int, t: int) -> bool:
    """`0x41AE20` 公共尾 0x41B316：t/total 推进、HP 钳、死亡转态 9、node dst。"""
    t = (t + 1) & 0xFFFFFFFF
    e.d32(0x24, t)
    total = (e.s32(0x30) + 1) & 0xFFFFFFFF
    e.d32(0x30, total)
    if total == 0x2328 and e.g32(0x18) > 0x960:
        e.d32(0x18, 0x960)
    if t == 0x3840:
        e.d32(0x18, 0)
    st = e.s32(0x28)
    hp = e.g32(0x18)
    if hp == 0 and st != 9:
        if st != 7 or t < 0x14:
            self.p4_spawn52c_flash(0, -0x10, 0x61000005, 0xFF)
        e.d32(0x24, -1 & 0xFFFFFFFF)
        e.d32(0x28, 9)
        e.m[0x10] = 0
    if e.node is not None:
        e.node.dst = (x - 0x18, y - 0x18)
    return hp != 0


def _beh_41D080(self, e) -> bool:
    """`0x41D080`（0x29000002）：**编队长机（六翼）**。

    t=++[0x1C]；t==1 → 六发 0x29000003 @(x+Δx, y+Δy) prm=父指针 入 0x4AD43C，
    相对位 (−0xA0,0)(0x36,−0xAA)(0x5C,−0x30)(−0x3A,−0x5A)(0x60,0x4C)(−0x16,0x4C)。
    [0x20] 相位：0 → x−− 到 0x1E0 → 1；1 → t&1==0 时 x−− 到 0x118 → 2、
    (t&3)==0 → y += (自机y≥y ? +1 : −1)；2 → x++ 到 0x208 → 1。
    [0x28] 计时/[0x24] 弹数：[0x24]==0 → [0x28]>0 ? [0x28]=−0x1E :
    ([0x28]==0 → [0x24]=rand&3+1)；0<[0x24]≤4 且 [0x28]==0x80 → [0x24]=0。
    t>0x1518 → HP=0。
    HP≠0：0x430860(0x4AD43C)==1（队列忙）→ 仅 node dst=(x−0x60,y−0x60) return 1；
    [0x2C]≠0 且 x>0x118 → x−−；node dst；return 1。
    HP==0 → 0x49000005 @(x,y) prm=[0x2C] 并 return 0。"""
    t = (e.s32(0x1C) + 1) & 0xFFFFFFFF
    e.d32(0x1C, t)
    if t == 1:
        _h = id(e) & 0x7FFFFFFF
        self.p4_links[_h] = e
        for dx, dy in ((-0xA0, 0), (0x36, -0xAA), (0x5C, -0x30),
                       (-0x3A, -0x5A), (0x60, 0x4C), (-0x16, 0x4C)):
            # ctor 0x41C0D1：[0x1C]=rec3(父)、[0x20]=rec0(dx)、[0x24]=rec1(dy)
            self._p4_ent43c(0x29000003, dx, dy, _h)
    ph = e.s32(0x20)
    if ph == 0:
        x = (e.s32(0x04) - 1) & 0xFFFFFFFF
        e.d32(0x04, x)
        if x == 0x1E0:
            e.d32(0x20, 1)
    elif ph == 1:
        if (t & 1) == 0:
            x = (e.s32(0x04) - 1) & 0xFFFFFFFF
            e.d32(0x04, x)
            if x == 0x118:
                e.d32(0x20, 2)
        if (t & 3) == 0:
            y = e.s32(0x08)
            sy = self.p4_player_y()
            if sy != y:
                e.d32(0x08, (y + (1 if sy >= y else -1)) & 0xFFFFFFFF)
    else:                                            # ph == 2
        x = (e.s32(0x04) + 1) & 0xFFFFFFFF
        e.d32(0x04, x)
        if x == 0x208:
            e.d32(0x20, 1)
    tm = (e.s32(0x28) + 1) & 0xFFFFFFFF
    e.d32(0x28, tm)
    n = e.s32(0x24)
    if n == 0:
        if tm > 0:
            e.d32(0x28, -0x1E & 0xFFFFFFFF)
        elif tm == 0:
            e.d32(0x24, (self.p4_rand() & 3) + 1)
    elif 0 < n <= 4:
        if tm == 0x80:
            e.d32(0x24, 0)
    if t > 0x1518:
        e.d32(0x18, 0)
    if e.g32(0x18) != 0:
        if self.p4_430860(self.p4_q43c) == 1:      # 0x41D206 队列只剩自身 → 爆炸
            self.spawn(self._p4_q("ui4cc"), 0x49000005, e.s32(0x04), e.s32(0x08),
                       e.s32(0x2C))
            return False
        x = e.s32(0x04)
        if e.s32(0x2C) != 0 and x > 0x118:
            x = (x - 1) & 0xFFFFFFFF
            e.d32(0x04, x)
        if x <= 0x118:                            # 0x41D22A → 发 0x49000005
            self.spawn(self._p4_q("ui4cc"), 0x49000005, x, e.s32(0x08),
                       e.s32(0x2C))
            return False
        if e.node is not None:
            e.node.dst = (x - 0x60, e.s32(0x08) - 0x60)
        return True
    self.spawn(self._p4_q("ui4cc"), 0x49000005, e.s32(0x04), e.s32(0x08),
               e.s32(0x2C))
    return False


_P4_41D330_ROW_A = (0x30, 0x00, 0x47, 0x17)
_P4_41D330_ROW_B = (0x30, 0x18, 0x47, 0x2F)


def _p4_41d330_row(e) -> None:
    """0x45A750 双行贴图切换（node.rect.t==0 → B 行，否则 A 行）。"""
    nd = e.node
    if nd is None:
        return
    nd.rect = _P4_41D330_ROW_B if nd.rect[1] == 0 else _P4_41D330_ROW_A


def _beh_41D330(self, e) -> bool:
    """`0x41D330`（0x29000003，0x41D080 六翼僚机）：**父链协同**。

    有父（[0x1C] 句柄）：x = 父.x + [0x20]、y = 父.y + [0x24]（相对位跟随）；
    子态 = 父.[0x24]−1（父弹数 1..4），timer = 父.[0x28]：
      态0：(timer&0x1B)==0x1B → 0x43B360(e, 自机x+2dx, 自机y+2dy, 0x340)
      态1：timer==0 → [0x28]=自机x、[0x2C]=自机y（锁定）；timer<0x40 → 行切换；
        (timer&3)==3 → 0x43B360(e, 锁x+dx, 锁y+dy, −0x400)
      态2：timer<0x40 → 行切换；timer==0x40 → 行切换；
        (timer>>2)+timer==0x5A → 0x43B610(e, 自机x, 自机y, −0x500)
      态3：timer==0 → 行切换 + [0x28]=0x18、[0x2C]=0x14；
        timer==0x60 → 3×3 网格 0x43B290(e, by, bx, −0x300)（bx,by ∈ −2..2 步 2）；
        timer==[0x28] 且 <0x60 → 行切换 + [0x28] += [0x2C]、[0x2C]>4 → [0x2C]−=4
    父死或 HP==0 → [0x1C]=[0x20]=0、[0x10]=0（断链下坠）。
    无父：t2=++[0x20]；(t2&3)==0 → 爆散 0x41000004（t2&4 ? 抖动 ±(rand&0x1F−0xF)
    对 : (±(rand&0x1F−0xF), rand&0xF−0x18)）入 0x4AD4CC；
    x −= [0x20]>>2、y += [0x20]>>2；node dst=(x−0xC,y−0xC)；
    return 不是(无父 且 y≥0x210)。"""
    h = e.s32(0x1C)
    links = getattr(self, "p4_links", {})
    parent = links.get(h & 0x7FFFFFFF) if h else None
    dx = e.s32(0x20)
    dy = e.s32(0x24)
    if parent is not None and h:
        x = (parent.s32(0x04) + dx) & 0xFFFFFFFF
        y = (parent.s32(0x08) + dy) & 0xFFFFFFFF
        e.d32(0x04, x)
        e.d32(0x08, y)
        sub = parent.s32(0x24) - 1
        tm = parent.s32(0x28)
        if sub == 0:
            if (tm & 0x1B) == 0x1B:
                self.p4_43B360(e, self.p4_player_x() + 2 * dx,
                               self.p4_player_y() + 2 * dy, 0x340)
        elif sub == 1:
            if tm == 0:
                e.d32(0x28, self.p4_player_x() & 0xFFFFFFFF)
                e.d32(0x2C, self.p4_player_y() & 0xFFFFFFFF)
            if tm < 0x40:                            # 0x41D3B9：行切换与开火互斥
                _p4_41d330_row(e)
            elif (tm & 3) == 3:
                lx = e.s32(0x28)
                ly = e.s32(0x2C)
                self.p4_43B360(e, lx + dx, ly + dy, -0x400 & 0xFFFFFFFF)
        elif sub == 2:
            if tm < 0x40:                            # 0x41D486 固定行 B
                if e.node is not None:
                    e.node.rect = (0x30, 0x18, 0x47, 0x2F)
            elif tm == 0x40:                         # 0x41D4A0 固定行 A
                if e.node is not None:
                    e.node.rect = (0x30, 0x00, 0x47, 0x17)
            elif (e.s32(0x20) >> 2) + tm == 0x5A:    # 0x41D4D4
                self.p4_43B610(e, self.p4_player_x(), self.p4_player_y(),
                               -0x500 & 0xFFFFFFFF)
        elif sub == 3:
            if tm == 0:                              # 0x41D504 固定行 B
                if e.node is not None:
                    e.node.rect = (0x30, 0x18, 0x47, 0x2F)
                e.d32(0x28, 0x18)
                e.d32(0x2C, 0x14)
            if tm == 0x60:
                for by in (-2, 0, 2):
                    for bx in (-2, 0, 2):
                        self.p4_43B290(e, by, bx, -0x300 & 0xFFFFFFFF)
            if tm == e.s32(0x28) and tm < 0x60 and tm != 0x60:
                _p4_41d330_row(e)
                e.d32(0x28, (e.s32(0x28) + e.s32(0x2C)) & 0xFFFFFFFF)
                if e.s32(0x2C) > 4:
                    e.d32(0x2C, (e.s32(0x2C) - 4) & 0xFFFFFFFF)
        if parent.m[0x34] == 0 or e.g32(0x18) == 0:   # 0x41D68F 父死才断链
            e.d32(0x1C, 0)
            e.d32(0x20, 0)
            e.m[0x10] = 0
    else:
        t2 = (e.s32(0x20) + 1) & 0xFFFFFFFF
        e.d32(0x20, t2)
        if (t2 & 3) == 0:
            if t2 & 4:
                jx = (self.p4_rand() & 0x1F) - 0xF
                jy = (self.p4_rand() & 0x1F) - 0xF
            else:
                jx = (self.p4_rand() & 0x1F) - 0xF
                jy = (self.p4_rand() & 0xF) - 0x18
            self.spawn(self._p4_q("ui4cc"), 0x41000004,
                       e.s32(0x04) + jx, e.s32(0x08) + jy, (jx, jy))
        t2v = e.s32(0x20)
        e.d32(0x04, (e.s32(0x04) - (t2v >> 2)) & 0xFFFFFFFF)
        e.d32(0x08, (e.s32(0x08) + (t2v >> 2)) & 0xFFFFFFFF)
    if e.node is not None:
        e.node.dst = (e.s32(0x04) - 0xC, e.s32(0x08) - 0xC)
    if e.s32(0x1C) == 0 and e.s32(0x08) >= 0x210:      # 0x41D7A4 重读 [+0x1C]
        return False
    return True


def _beh_41D990(self, e) -> bool:
    """`0x41D990`（thunk 0x40134D；0x29000005）：**帧表入场演出体**。

    帧门 t=[0x1C]&0xFF ≤ 0xA0，事件表 0x41DB88/0x41DB70：
      0x00 → 0x49000006 @(x,y) 双发入 0x4AD4CC（prm 0 / 1），[0x20]=[0x24]=0
      0x30 → [0x10]=1、node.active=1
      0x50 → 0x31000015 @(x,y) prm 0xC 入 0x4AD49C（[esp+0x1C]=(y<0xF0) 残留）
      0x70 → node.active=0；0x49000007 @(x,y) 双发入 0x4AD4CC（prm 0 / 1）
      0xA0 → [0x10]=0、[0x20]=−1、[0x24]=(y≥0xF0 ? +3 : −3)（脱离起转）
    尾：t++、x += [0x20]、y += [0x24]（0x45A6B0 node dst 同步）；
    t < 0x2A0 且 HP≠0 → 存活。"""
    t = e.s32(0x1C) & 0xFF
    if t <= 0xA0:
        if t == 0x00:
            self.spawn(self._p4_q("ui4cc"), 0x49000006, e.s32(0x04), e.s32(0x08), 0)
            self.spawn(self._p4_q("ui4cc"), 0x49000006, e.s32(0x04), e.s32(0x08), 1)
            e.d32(0x20, 0)
            e.d32(0x24, 0)
        elif t == 0x30:
            e.m[0x10] = 1
            if e.node is not None:
                e.node.active = 1
        elif t == 0x50:
            self.spawn(self._p4_q("ui49c"), 0x31000015, e.s32(0x04), e.s32(0x08),
                       (0xC, 0, 1 if e.s32(0x08) < 0xF0 else 0))
        elif t == 0x70:
            if e.node is not None:
                e.node.active = 0
            self.spawn(self._p4_q("ui4cc"), 0x49000007, e.s32(0x04), e.s32(0x08), 0)
            self.spawn(self._p4_q("ui4cc"), 0x49000007, e.s32(0x04), e.s32(0x08), 1)
        elif t == 0xA0:
            e.m[0x10] = 0
            e.d32(0x20, -1 & 0xFFFFFFFF)
            e.d32(0x24, (3 if e.s32(0x08) >= 0xF0 else -3) & 0xFFFFFFFF)
    t = (e.s32(0x1C) + 1) & 0xFFFFFFFF
    e.d32(0x1C, t)
    vx = e.s32(0x20)
    vy = e.s32(0x24)
    e.d32(0x04, (e.s32(0x04) + vx) & 0xFFFFFFFF)
    e.d32(0x08, (e.s32(0x08) + vy) & 0xFFFFFFFF)
    if e.node is not None:                          # 0x45A6B0(node+0x14, vx, vy)
        e.node.dst = (e.node.dst[0] + vx, e.node.dst[1] + vy)
    return t < 0x2A0 and e.g32(0x18) != 0


def _beh_41E960(self, e) -> bool:
    """`0x41E960`（0x2900000C）：**圆轨护卫 + 角门开火**。

    t=++[0x1C]；t==1 → 发 0x2900000D @(x,y) 入 0x4AD43C（伴生体）；
    t%0xF0==0 → [0x2C]=0x3C（相位重置）。
    [0x2C]≠0：[0x2C] += ([0x2C]−0xE10 ≥ 0 ? −0x1B4 : …)（and 0xE4C/add 0xFFFFF1F0
    → [0x2C]>0xE10 ? [0x2C]−0xE10−0xE10+0x3C? 字面：([0x2C]−0xE10<0 ? −0xE0C−0xE10?
    ：) —— 化简：([0x2C] − 0xE10 的符号决定) + 0xFFFFF1F0(−0xE10) + [0x2C]；
    即 [0x2C] = [0x2C] − 0xE10 − (0xE10 若 [0x2C]≥0xE10)。
    [0x2C]==0：[0x20]−−（x 收缩）；[0x28] = 0x45A9A0([0x20]−自机x, [0x24]−自机y)。
    x = [0x20] − [0x20]−? ：x = (([0x2C]+[0x28]) 的 cos>>2 − [0x20] + [0x20]+4)>>3 + [0x20]
    （0x41EA37：edx = ((cos([0x2C]+[0x28])>>2 − [0x20]) + [0x20] + 4) >> 3 + [0x20]）；
    y = ((sin([0x2C]+[0x28])>>2 − [0x24]) + [0x24] + 4) >> 3 + [0x24]。
    0x384 ≤ [0x2C] < 0xA8C 且 [0x2C]%0xF0==0 → 0x43B610(e, 2y−[0x24], 2x−[0x20],
    0x500)（对映点狙击）。
    node dst=(x−0x18,y−0x18)；return [0x20] > −0x78 且 HP≠0。"""
    t = (e.s32(0x1C) + 1) & 0xFFFFFFFF
    e.d32(0x1C, t)
    if t == 1:
        _h = id(e) & 0x7FFFFFFF
        self.p4_links[_h] = e
        self._p4_ent43c(0x2900000D, e.s32(0x04), e.s32(0x08), _h)
    if t % 0xF0 == 0:
        e.d32(0x2C, 0x3C)
    ph = e.s32(0x2C)
    if ph != 0:
        # 0x41E9D3：ph' = ph − 0xE10 + (ph==0xE10 ? 0 : 0xE4C) ⇒ ph+0x3C，满一圈归 0
        if ph == 0xE10:
            ph = 0
        else:
            ph = (ph + 0x3C) & 0xFFFFFFFF
        e.d32(0x2C, ph)
    else:
        v20 = (e.s32(0x20) - 1) & 0xFFFFFFFF
        e.d32(0x20, v20)
        da = self.p4_45a9a0(v20 - self.p4_player_x(),
                            e.s32(0x24) - self.p4_player_y())
        e.d32(0x28, da & 0xFFFFFFFF)
    ph = e.s32(0x2C)
    ang = (ph + e.s32(0x28)) & 0xFFFFFFFF
    v20 = e.s32(0x20)
    v24 = e.s32(0x24)
    c = page4_cos(ang)
    s_ = page4_sin(ang)
    old_x = e.s32(0x04)
    old_y = e.s32(0x08)
    # 0x41EA32：x = ((cos>>2 − 旧x + [0x20] + 4)>>3) + [0x20]
    x = (((((c >> 2) - old_x + v20 + 4) >> 3) + v20)) & 0xFFFFFFFF
    y = (((((s_ >> 2) - old_y + v24 + 4) >> 3) + v24)) & 0xFFFFFFFF
    e.d32(0x04, x)
    e.d32(0x08, y)
    if 0x384 <= ph < 0xA8C and ph % 0xF0 == 0:
        self.p4_43B610(e, 2 * y - v24, 2 * x - v20, 0x500)
    if e.node is not None:
        e.node.dst = (x - 0x18, y - 0x18)
    return v20 > -0x78 and e.g32(0x18) != 0


def _beh_41EB60(self, e) -> bool:
    """`0x41EB60`（0x2900000D，0x41E960 伴生体）：**父影随行**。

    每帧 [0x18]=−1（无敌标记）；父 = [0x1C] 句柄：
    [0x20] = 父.[0x20]*2、[0x24] = 父.[0x24]*2（镜像倍率）；
    x = [0x20] − 父.x、y = [0x24] − 父.y（绕父对映点）；node dst=(x−0x18,y−0x18)；
    父死（byte[+0x34]）→ 存活；否则 0x41000001 @(x,y) 入 0x4AD4CC、return 0。"""
    e.d32(0x18, -1 & 0xFFFFFFFF)
    h = e.s32(0x1C)
    parent = getattr(self, "p4_links", {}).get(h & 0x7FFFFFFF) if h else None
    if parent is None:
        return True
    v20 = (parent.s32(0x20) * 2) & 0xFFFFFFFF
    v24 = (parent.s32(0x24) * 2) & 0xFFFFFFFF
    e.d32(0x20, v20)
    e.d32(0x24, v24)
    x = (v20 - parent.s32(0x04)) & 0xFFFFFFFF
    y = (v24 - parent.s32(0x08)) & 0xFFFFFFFF
    e.d32(0x04, x)
    e.d32(0x08, y)
    if e.node is not None:
        e.node.dst = (x - 0x18, y - 0x18)
    if parent.m[0x34] != 0:
        return True
    self.spawn(self._p4_q("ui4cc"), 0x41000001, x, y, 0)
    return False


def _beh_41EC40(self, e) -> bool:
    """`0x41EC40`（0x2900000F）：**父链三态（充能→击破→重生门）**。

    父 = [0x1C] 句柄；x = 父.x + cos([0x24]+父.[0x20])*[0x20]>>8、
    y = 父.y + sin([0x24]+父.[0x20])*[0x20]>>8（绕父公转，[0x20]=半径）。
    父.[0x28] 态：0 → 父.[0x24] += (−1 − [0x18])（充能计时）；
    1 → HP≠0 → [0x18]=1；HP==0 → 父.[0x28]=2、[0x10]=0；
    2 → [0x10]=0；0x41000001 + 0x41000004（抖动 ±rand&0x1F−0xF）@(x,y) 入 0x4AD4CC。
    node dst=(x−0xC,y−0xC)；return byte[父+0x34]（父活即活）。"""
    h = e.s32(0x1C)
    parent = getattr(self, "p4_links", {}).get(h & 0x7FFFFFFF) if h else None
    if parent is None:
        return False
    ang = (parent.s32(0x20) + e.s32(0x24)) & 0xFFFFFFFF
    r = e.s32(0x20)
    x = (parent.s32(0x04) + ((page4_cos(ang) * r) >> 8)) & 0xFFFFFFFF
    y = (parent.s32(0x08) + ((page4_sin(ang) * r) >> 8)) & 0xFFFFFFFF
    e.d32(0x04, x)
    e.d32(0x08, y)
    pst = parent.s32(0x28)
    if pst == 0:
        parent.d32(0x24, (parent.s32(0x24) + (-1 - e.s32(0x18))) & 0xFFFFFFFF)
    elif pst == 1:
        if e.g32(0x18) != 0:
            e.d32(0x18, 1)
        else:
            parent.d32(0x28, 2)
            e.m[0x10] = 0
    else:                                            # pst >= 2
        e.m[0x10] = 0
        jx = (self.p4_rand() & 0x1F) - 0xF
        jy = (self.p4_rand() & 0x1F) - 0xF
        self.spawn(self._p4_q("ui4cc"), 0x41000001, x, y, 0)
        self.spawn(self._p4_q("ui4cc"), 0x41000004,
                   x + jx, y + jy, (jx, jy))
    if e.node is not None:
        e.node.dst = (x - 0xC, y - 0xC)
    return parent.m[0x34] != 0


def _beh_41EE00(self, e) -> bool:
    """`0x41EE00`（0x29000010）：**外圈公转武装（半径 8 倍率）**。

    父 = [0x1C] 句柄；相位 esi = clamp(父.[0x20] − [0x24], 0, 0xE10)；
    x = 父.x + cos(esi)*[0x20]>>3、y = 父.y + sin(esi)*[0x20]>>3（[0x20]=半径）。
    父.[0x28] 态：0 → 父.[0x24] ≠ 0 时父.[0x24] += (−1 − [0x18])、[0x18]=−1；
    1 → HP≠0 → [0x18]=1；HP==0 → 父.[0x28]=2、[0x10]=0；
    2 → [0x10]=0；0x41000001 + 0x41000004（±rand&0x1F−0xF）@(x,y) 入 0x4AD4CC。
    父.[0x20]==0xAC8 且 [0x20]==4 → 0x43B610(e, 2y−父.y, 2x−父.x, 0)（对映狙击）。
    node dst=(x−0x18,y−0x18)；return byte[父+0x34]。"""
    h = e.s32(0x1C)
    parent = getattr(self, "p4_links", {}).get(h & 0x7FFFFFFF) if h else None
    if parent is None:
        return False
    esi = parent.s32(0x20) - e.s32(0x24)
    if esi < 0:
        esi = 0
    elif esi > 0xE10:
        esi = 0xE10
    ang = esi & 0xFFFFFFFF
    r = e.s32(0x20)
    x = (parent.s32(0x04) + ((page4_cos(ang) * r) >> 3)) & 0xFFFFFFFF
    y = (parent.s32(0x08) + ((page4_sin(ang) * r) >> 3)) & 0xFFFFFFFF
    e.d32(0x04, x)
    e.d32(0x08, y)
    pst = parent.s32(0x28)
    if pst == 0:
        if y != 0:                                   # test edi(=y) — 半径非零门
            pv = e.s32(0x18)
            parent.d32(0x24, (parent.s32(0x24) + (-1 - pv)) & 0xFFFFFFFF)
        e.d32(0x18, -1 & 0xFFFFFFFF)
    elif pst == 1:
        if e.g32(0x18) != 0:
            e.d32(0x18, 1)
        else:
            parent.d32(0x28, 2)
            e.m[0x10] = 0
    else:
        e.m[0x10] = 0
        jx = (self.p4_rand() & 0x1F) - 0xF
        jy = (self.p4_rand() & 0x1F) - 0xF
        self.spawn(self._p4_q("ui4cc"), 0x41000001, x, y, 0)
        self.spawn(self._p4_q("ui4cc"), 0x41000004, x + jx, y + jy, (jx, jy))
    if parent.s32(0x20) == 0xAC8 and r == 4:
        self.p4_43B610(e, 2 * y - parent.s32(0x08),
                       2 * x - parent.s32(0x04), 0)
    if e.node is not None:
        e.node.dst = (x - 0x18, y - 0x18)
    return parent.m[0x34] != 0


_P4_41F3A0_SEL = (
    0, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3,
    0, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3,
    0, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3,
    0, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3,
    0, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3,
    3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3,
    1, 2, 2, 2, 2, 0, 0, 2, 2,
)


def _beh_41F3A0(self, e) -> bool:
    """`0x41F3A0`（0x29000011）：**激光扫掠 boss**。

    t=++[0x1C]；t==0x50 → [0x24]=0（停）；t==0x300 → [0x24]=3（右移）；x += [0x24]。
    0x80≤t<0x300 且 (t&0x7F)≤0x68：帧表 0x41F51C——
      case0（(t&0x7F)∈{0,0x10,0x20,0x30,0x40}）：0x45A790(node+4, −0x10−v20, 0,
        −v20, 0)（src 左扫）+ v20 += 0x10；
      case1（=0x64）：0x31000017 @(x,y) 入 0x4AD49C + 0x45A790(node+4, v20, 0,
        v20−0x10, 0) + v20 −= 0x10；
      case2（0x65..0x68）：0x45A790(node+4, v20, 0, v20−0x10, 0) + v20 −= 0x10。
    node dst=(x−0x30,y−0x30)；HP==0 → 0x61000004 @(x,y,0x30) 入 52C、return 0；
    return x < 0x2B0。"""
    t = (e.s32(0x1C) + 1) & 0xFFFFFFFF
    e.d32(0x1C, t)
    if t == 0x50:
        e.d32(0x24, 0)
    elif t == 0x300:
        e.d32(0x24, 3)
    x = (e.s32(0x04) + e.s32(0x24)) & 0xFFFFFFFF
    e.d32(0x04, x)
    if 0x80 <= t < 0x300:
        i = t & 0x7F
        if i <= 0x68:
            sel = _P4_41F3A0_SEL[i]
            v20 = e.s32(0x20)
            nd = e.node
            if sel == 0:
                if nd is not None:
                    nd.rect = (nd.rect[0] - 0x10 - v20, nd.rect[1],
                               nd.rect[2] - v20, nd.rect[3])
                e.d32(0x20, (v20 + 0x10) & 0xFFFFFFFF)
            elif sel == 1:
                self.spawn(self._p4_q("ui49c"), 0x31000017, x, e.s32(0x08), 0)
                if nd is not None:
                    nd.rect = (nd.rect[0] + v20, nd.rect[1],
                               nd.rect[2] + v20 - 0x10, nd.rect[3])
                e.d32(0x20, (v20 - 0x10) & 0xFFFFFFFF)
            elif sel == 2:
                if nd is not None:
                    nd.rect = (nd.rect[0] + v20, nd.rect[1],
                               nd.rect[2] + v20 - 0x10, nd.rect[3])
                e.d32(0x20, (v20 - 0x10) & 0xFFFFFFFF)
    if e.node is not None:
        e.node.dst = (x - 0x30, e.s32(0x08) - 0x30)
    if e.g32(0x18) == 0:
        self.p4_spawn52c_flash(x, e.s32(0x08), 0x61000004, 0x30)
        return False
    return x < 0x2B0


def _beh_41FE10(self, e) -> bool:
    """`0x41FE10`（0x29000017）：**前压 + 双列旋散弹**。

    x ≥ 0x208 → 直接收尾；[0x20]（冷却）≠0 → [0x20]−−；
    [0x20]==0 且 [0x24]==0（待机）：t=++[0x1C]，(t&7)==0 → 随机点
    0x43B360(e, 自机x+(rand&0x7F)−0x3F, 自机y+(rand&0xFF), 0)；
    [0x24]≠0（开火态）：t=++[0x1C]，t 偶 → 四弹 0x43B290：
      (cos(49t), sin(49t), 0)/(−cos, sin)/(−sin?, ...) —— 字面：
      (edi=cos(49t), ebx=sin(49t)) → (edi,ebx,0)、(−ebx?,−edi?) 两组对称 +
      第二组 ang'=−38t（0x41FED2 (5t*4−t)=19t→neg→(−19t)*2? 字面 eax=−19t,
      ecx=(−19t)*2×3/2=−57t?（lea [eax+eax*2]; shl 1 → −57t? 不：−19t*3*2=−114t/2?
      实际 = (−19t)*6 = −114t? shl 1 → ×2 ⇒ −19t*6? 保守按 −38t*1.5 处理：
      精确式：a=−19t；ecx=(a*3)<<1 = 6a = −114t）→ (cos(−114t), sin(−114t)) 对称双弹。
      （0x41FE8F: 49t=(3t<<4)+t；0x41FED2: −19t、−(19t*3)<<1=−114t? shl1 前
      lea*3 → 6a；ang=6a=−114t）
    t==0x708 → [0x20]=−1；移动：y += [0x20]>>2、x −= [0x20]>>1；
    node dst=(x−0x30,y−0x30)；return HP≠0 且 y>−0x30。"""
    if e.s32(0x04) >= 0x208:
        pass
    else:
        if e.s32(0x20) != 0:
            e.d32(0x20, (e.s32(0x20) - 1) & 0xFFFFFFFF)
        elif e.s32(0x24) == 0:
            t = (e.s32(0x1C) + 1) & 0xFFFFFFFF
            e.d32(0x1C, t)
            if (t & 7) == 0:
                ty = self.p4_player_y() + (self.p4_rand() & 0xFF)
                tx = self.p4_player_x() + (self.p4_rand() & 0x7F) - 0x3F
                self.p4_43B360(e, tx, ty, 0)
        else:
            t = (e.s32(0x1C) + 1) & 0xFFFFFFFF
            e.d32(0x1C, t)
            if (t & 1) == 0:
                a1 = (49 * t) & 0xFFFFFFFF
                c1 = page4_cos(a1)
                s1 = page4_sin(a1)
                self.p4_43B290(e, c1, s1, 0)
                self.p4_43B290(e, -s1, -c1, 0)
                a2 = (-114 * t) & 0xFFFFFFFF
                c2 = page4_cos(a2)
                s2 = page4_sin(a2)
                self.p4_43B290(e, c2, s2, 0)
                self.p4_43B290(e, -s2, -c2, 0)
    if e.s32(0x1C) == 0x708:
        e.d32(0x20, -1 & 0xFFFFFFFF)
    v = e.s32(0x20)
    x = (e.s32(0x04) - (v >> 1)) & 0xFFFFFFFF
    y = (e.s32(0x08) + (v >> 2)) & 0xFFFFFFFF
    e.d32(0x04, x)
    e.d32(0x08, y)
    if e.node is not None:
        e.node.dst = (x - 0x30, y - 0x30)
    return e.g32(0x18) != 0 and y > -0x30


def _beh_41F860(self, e) -> bool:
    """`0x41F860`（thunk 0x401398；0x29000015 **最终 boss**）。

    [0x20]==0（编队态）：发 0x29000016 @(0,0) 入 0x4AD43C（护卫长机，
    prm=自身指针）；sub=++[0x1C]&3 四编队：
      0 → 0x1F8 帧后 8× 0x29000003?（rec {i*80+0x28, …, prm=1/7, y=0x1E8/0x1F8}
      双发 ×8 入 0x4AD43C）、[0x20]=0xFA；
      1 → rec {(0x298,0xF0,prm=3),(0x2C8,0xC0,prm=−0x1E)} + y 0x60 步进循环
      {(0x2F8,0x90,−0x3C)}、{(0x328,0x60,−0x5A)} 各 y+0x60 至界限、[0x20]=0x15E；
      2 → 8× rec {(i*33+0x298, 0x30, prm=2)}、[0x20]=0x122；
      3 → rec {(0x140, −0x78, prm=5)} x −0x78 循环至 −0x3C0、[0x20]=0x168。
    [0x20]≠0（冷却倒数）；[0x2C]（完成门）：==0 → [0x28]<0xDC → [0x28]+=0xA；
    否则 [0x28]<0xF0 → [0x28]+=5；都到 → HP=0（终局）。
    移动：y<0x230 且 [0x24]≠0 → [0x24]++；y += [0x24]（下压加速）；
    node.dst.y += [0x24]；[0x20]−−==0 → 0x61000004 @(x,y,0x48) 入 52C（受击闪）
    → return 0（死亡）；否则 node dst 同步、return 1。"""
    if e.s32(0x20) == 0:
        c = self._p4_ent43c(0x29000016, 0, 0)
        c.d32(0x18, id(e) & 0x7FFFFFFF)
        getattr(self, "p4_links", {})[id(e) & 0x7FFFFFFF] = e
        sub = e.s32(0x1C) & 3
        e.d32(0x1C, (e.s32(0x1C) + 1) & 0xFFFFFFFF)
        if sub == 0:
            e.d32(0x20, 0xFA)
            for i in range(8):
                xx = i * 80 + 0x28
                self._p4_ent43c(0x29000003, xx, 0x1E8)
                self._p4_ent43c(0x29000003, xx, 0x1F8)
        elif sub == 1:
            e.d32(0x20, 0x15E)
            self._p4_ent43c(0x29000003, 0x298, 0xF0)
            self._p4_ent43c(0x29000003, 0x2C8, 0xC0)
            yy = 0xC0
            while yy + 0x60 <= 0x120:
                yy += 0x60
                self._p4_ent43c(0x29000003, 0x2C8, yy)
            yy = 0x90
            while True:
                self._p4_ent43c(0x29000003, 0x2F8, yy)
                if yy + 0xC0 > 0x150:
                    break
                yy += 0xC0
            yy = 0x60
            while True:
                self._p4_ent43c(0x29000003, 0x328, yy)
                if yy + 0x60 > 0x180:
                    break
                yy += 0x60
        elif sub == 2:
            e.d32(0x20, 0x122)
            for i in range(8):
                self._p4_ent43c(0x29000003, i * 33 + 0x298, 0x30)
        else:
            e.d32(0x20, 0x168)
            xx = -0x78
            while xx - 0x78 >= -0x3C0:
                self._p4_ent43c(0x29000003, 0x140, xx)
                xx -= 0x78
    else:
        e.d32(0x20, (e.s32(0x20) - 1) & 0xFFFFFFFF)
    done = e.s32(0x2C)
    y28 = e.s32(0x28)
    v20 = (e.s32(0x20) - y28) & 0xFFFFFFFF
    e.d32(0x20, v20)
    if done == 0:                                  # 0x41FAC7
        if y28 < 0xDC:
            e.d32(0x28, (y28 + 0xA) & 0xFFFFFFFF)
        else:
            e.d32(0x18, 0)                         # 0x41FAD6 → HP=0（终局）
    else:                                          # 0x41FADB
        if y28 < 0xF0:
            e.d32(0x28, (y28 + 5) & 0xFFFFFFFF)
        else:
            e.d32(0x18, 0)
    if e.s32(0x04) < 0x230 and e.s32(0x24) != 0:
        e.d32(0x24, (e.s32(0x24) + 1) & 0xFFFFFFFF)
    v24 = e.s32(0x24)
    x = (e.s32(0x04) + v24) & 0xFFFFFFFF
    e.d32(0x04, x)
    if e.node is not None:
        e.node.dst = (e.node.dst[0], e.node.dst[1] + v24)
    e.d32(0x20, (e.s32(0x20) - 1) & 0xFFFFFFFF)     # 0x41FB19 无条件 dec
    if e.g32(0x18) == 0:                           # 0x41FB1F test HP / je
        e.d32(0x20, 0xFFFFFFFF)
        self.p4_spawn52c_flash(x, e.s32(0x08), 0x61000004, 0x48)
        return False
    return True


def _beh_41F010(self, e) -> bool:
    """`0x41F010`（thunk 0x4021C6；0x2900000E）：**七态机（0x41F2C4）**。

    态 = [0x1C]&0xF（>6 跳过）：
      0：x>0x15E → [0x1C]=1（进入态 1）
      1：[0x28]−−；偶帧 [0x2C] += ([0x30]≥0 ? −1 : +1)（纵向收敛）；
         [0x28]==−0x20 → [0x1C]=2；(t&7)==0 → 门 = (t&8 ? +0x60 : −0x60)+…
         （and 0xC0/add −0x60 → (t&8)? +0x60 : −0x60）→ 0x43B360(e, 自机x,
         自机y−门, 0)
      2：[0x28]+=2；[0x2C] += ([0x30]≥0 ? −1 : +1)；[0x2C]==0 → [0x1C]=3
      3：[0x1C] = t+0x10；==0x803 → [0x1C]=4、[0x28]=0x20；t>0x400 且 (t&0x70)==0
         → 0x43B610(e, 自机x, 自机y+[0x58]+0x180, 0x500)
      4：[0x28]−−；[0x28]<0 → [0x2C] += ([0x28]<0 ? +3 : −3)；[0x2C]==0 →
         [0x1C]=5、[0x28]=0
      5：[0x1C]=t+0x10；==0x805 → [0x1C]=6、[0x28]=−0x40；t≤0x405 且 (t&0xF)==5 →
         弹幕块：v=[0x30]；奇偶分支定 (±0x10−8, ±8) 偏移 + ang=~t>>9&1；
         0x430400(&rec, x, y, 0x31000015, &{dy?, dx?}) 入 0x4AD49C
      6：[0x28]+=2；[0x2C] += ([0x30]<0 ? +1 : −1)
    尾：[0x24]+=[0x2C]、[0x20]+=[0x28]；x=[0x20]>>3、y=[0x24]>>3；
    node dst=(x−0x30,y−0x30)；return HP≠0 且 x<0x2B0。"""
    st = e.s32(0x1C) & 0xF
    t = e.s32(0x1C)
    if st <= 6:
        if st == 0:
            if e.s32(0x04) > 0x15E:
                e.d32(0x1C, 1)
        elif st == 1:
            v = (e.s32(0x28) - 1) & 0xFFFFFFFF
            e.d32(0x28, v)
            v_s = v - 0x100000000 if v & 0x80000000 else v
            if (v & 1) == 0:
                c30 = e.s32(0x30)
                e.d32(0x2C, (e.s32(0x2C) + (-1 if c30 != 0 else 1)) & 0xFFFFFFFF)
            if v_s == -0x20:
                e.d32(0x1C, 2)
            if (v & 7) == 0:
                gate = 0x60 if (v & 8) else -0x60
                self.p4_43B360(e, self.p4_player_x(),
                               self.p4_player_y() - gate, 0)
        elif st == 2:
            e.d32(0x28, (e.s32(0x28) + 2) & 0xFFFFFFFF)
            c30 = e.s32(0x30)
            # 0x41F0B4：neg/sbb/and 6/add −3 ⇒ [0x30]!=0 ? +3 : −3
            e.d32(0x2C, (e.s32(0x2C) + (3 if c30 != 0 else -3)) & 0xFFFFFFFF)
            if e.s32(0x2C) == 0:
                e.d32(0x1C, 3)
        elif st == 3:
            nt = (t + 0x10) & 0xFFFFFFFF
            e.d32(0x1C, nt)
            if nt == 0x803:
                e.d32(0x1C, 4)
                e.d32(0x28, 0x20)
            nt = e.s32(0x1C)
            if nt > 0x400 and (nt & 0x70) == 0:
                self.p4_43B610(e, self.p4_player_x(),
                               self.p4_player_y() + e.s32(0x58) + 0x180, 0x500)
        elif st == 4:
            v = (e.s32(0x28) - 1) & 0xFFFFFFFF
            e.d32(0x28, v)
            v_s = v - 0x100000000 if v & 0x80000000 else v
            c30 = e.s32(0x30)
            # 0x41F140/[0x30]≠0：([0x28]<0 ? −3 : +3)；0x41F152/[0x30]==0：相反
            neg_side = (v_s < 0)
            d3 = (-3 if neg_side else 3) if c30 != 0 else (3 if neg_side else -3)
            e.d32(0x2C, (e.s32(0x2C) + d3) & 0xFFFFFFFF)
            if e.s32(0x2C) == 0:
                e.d32(0x1C, 5)
                e.d32(0x28, 0)
        elif st == 5:
            nt = (t + 0x10) & 0xFFFFFFFF
            e.d32(0x1C, nt)
            if nt == 0x805:
                e.d32(0x1C, 6)
                e.d32(0x28, -0x40 & 0xFFFFFFFF)
            nt = e.s32(0x1C)
            if nt <= 0x405 and (nt & 0xFF) == 5:      # 0x41F1AC：cmp al,5（低字节）
                c30 = e.s32(0x30)
                if c30 != 0:
                    odd = (nt & 0x200) != 0
                    dy = (0x10 - 8) if odd else (-8)
                    dx = (-8) if odd else (0x10 - 8)
                    ax = ~nt & 0xFFFFFFFF
                else:
                    dy = (0x10 - 8) if (nt & 0x200) else (-8)
                    dx = dy
                    ax = nt
                abit = (ax >> 9) & 1
                self.spawn(self._p4_q("ui49c"), 0x31000015,
                           e.s32(0x04), e.s32(0x08), (dx, dy, abit))
        elif st == 6:
            e.d32(0x28, (e.s32(0x28) + 2) & 0xFFFFFFFF)
            c30 = e.s32(0x30)
            # 0x41F24A：neg/sbb/and −2/inc ⇒ [0x30]==0 ? +1 : −1
            e.d32(0x2C, (e.s32(0x2C) + (1 if c30 == 0 else -1)) & 0xFFFFFFFF)
    s24 = (e.s32(0x24) + e.s32(0x2C)) & 0xFFFFFFFF
    e.d32(0x24, s24)
    s20 = (e.s32(0x20) + e.s32(0x28)) & 0xFFFFFFFF
    e.d32(0x20, s20)
    x = (s20 - 0x100000000 if s20 & 0x80000000 else s20) >> 3
    y = (s24 - 0x100000000 if s24 & 0x80000000 else s24) >> 3
    e.d32(0x04, x & 0xFFFFFFFF)
    e.d32(0x08, y & 0xFFFFFFFF)
    if e.node is not None:
        e.node.dst = (x - 0x30, y - 0x30)
    return e.g32(0x18) != 0 and x < 0x2B0


_P4_40A930_LIMITS = (0x168, 0x168, 0x168, 0, 0x78, 0x12C, 0xF0, 0xFFFF,
                     0x69, 0x1C2, 0xB4, 0xF0, 0x12C, 0x12C, 0x21C, 0xB4, 0xFFFF)


def _beh_40A930(self, e) -> bool:
    """`0x40A930`（0x2A000002，**关7 boss 本体**）。

    态0：发 0x2A000002/03/04 三件 @(x,y) 入 0x4AD43C、[0x24]=1、
      [0x30]=((x&0x7FF)|(y<<0x10))<<5（16.5 定点）。
    态7：[0x1C]==0x26DF → 态8、[0x18]=0x27100。
    态0x10：0x45AFC0(0x56CCB8,0x10)==0 且 [0x20]==0x12C → 态++。
    态1..6：[0x20] ≥ 表值 → 态 += (态≤6 ? +1 : −5)。
    公共：[0x1C]++；态切换 → [0x20] = (态≤0xD ? −0x78 : 0)；同态 →
      [0x20]==−1 ? 三行掩码检查（[0x28]=27 架 3×9 位存活掩码，行空 → [0x20]=0）
      : [0x20]++；[0x2C]≠0 → [0x2C]−−。
    态0xE：[0x18]=min([0x18],0x26160)；0x1D4C0<[0x18]<0x26160 → 0x61000004
      @(x,y,0x10) 入 52C + 0x32000009 @(x,y) 入 49C、[0x18]=0x1D4C0。
    态0xF：0x401E1F(0x56CCB8, 0x20)。
    态0x10：0x402400(0x56CCB8,0x20)；[0x20]&1 或 0x40208B(0x56CCB8,0x10)==0 →
      跳过；否则双发 0x10FF0053 @(自机x, 自机y+[0x20]>>1 / [0x20]>>3+4) 入 0x4AD46C。
    态0x11：[0x20]==0 且 0x40221B(0x4AD40C)!=0 → 0x61000005(0,0xFFFFFF01,−4) 入 52C；
      x < −0xF0 → 死亡路径。
    移动：态==0x11 → word[0x30] −= [0x20]<<6；否则 word[0x30] +=
      (自机x>>2 − x + 0x1E0)>>3；word[0x32] += (自机y>>1 − y + 0x78)>>3；
      x=word[0x30]>>5、y=word[0x32]>>5；node dst=(x−0xA0, y−0x60)。
    HP>0x9C40 → return 1；否则 0x4A000006 @(x,y) 入 4CC + 0x401E1F(0x56CCB8,0x40)
      + 0x401AE1(0x4CD4A0,0xF4240)、return 0。"""
    st = e.s32(0x24)
    st_old = st
    t = e.s32(0x1C)
    x = e.s32(0x04)
    y = e.s32(0x08)
    if st == 0:
        self._p4_ent43c(0x2A000002, x, y)
        self._p4_ent43c(0x2A000003, x, y)
        self._p4_ent43c(0x2A000004, x, y)
        e.d32(0x24, 1)
        st = 1
        e.d32(0x30, (((x & 0x7FF) | ((y & 0xFFFF) << 0x10)) << 5) & 0xFFFFFFFF)
    elif st == 7:
        if t == 0x26DF:
            e.d32(0x24, 8)
            st = 8
        e.d32(0x18, 0x27100)
    elif st == 0x10:
        if (self.keys.field(0x10) & 3) == 0 and e.s32(0x20) == 0x12C:
            e.d32(0x24, 0x11)
            st = 0x11
    elif 1 <= st <= 6:
        if e.s32(0x20) >= _P4_40A930_LIMITS[st]:
            e.d32(0x24, (st + (1 if st <= 6 else -5)) & 0xFFFFFFFF)
            st = e.s32(0x24)
    t = (t + 1) & 0xFFFFFFFF
    e.d32(0x1C, t)
    if st != st_old:
        e.d32(0x20, -0x78 if st <= 0xD else 0)
    else:
        v20 = e.s32(0x20)
        if v20 == -1:
            m = e.g32(0x28)
            if st % 3 == 0:
                if (m & 0x1FF) == 0 or ((m & 0x3FE00) == 0):
                    e.d32(0x20, 0)
            elif st % 3 == 1:
                if (m & 0x1FF) == 0 or (m & 0x7FC0000) == 0:
                    e.d32(0x20, 0)
            else:
                if (m & 0x3FE00) == 0:
                    e.d32(0x20, 0)
        else:
            e.d32(0x20, (v20 + 1) & 0xFFFFFFFF)
    if e.s32(0x2C) != 0:
        e.d32(0x2C, (e.s32(0x2C) - 1) & 0xFFFFFFFF)
    v20 = e.s32(0x20)
    if st == 0xE:
        hp = e.g32(0x18)
        if hp > 0x26160:
            e.d32(0x18, 0x26160)
        hp = e.g32(0x18)
        if 0x1D4C0 < hp < 0x26160:
            self.p4_spawn52c_flash(x, y, 0x61000004, 0x10)
            self.spawn(self._p4_q("ui49c"), 0x32000009, x, y, 0)
            e.d32(0x18, 0x1D4C0)
    elif st == 0xF:
        pass                                              # 0x401E1F(0x56CCB8,0x20)
    elif st == 0x10:
        pass                                              # 0x402400(0x56CCB8,0x20)
        if not (v20 & 1) and (self.keys.field(0x10) & 3) != 0:
            sy = self.p4_player_y()
            sx = self.p4_player_x()
            self.spawn(self._p4_q("ui46c"), 0x10FF0053, sx, sy + (v20 >> 1), 0)
            self.spawn(self._p4_q("ui46c"), 0x10FF0053, sx, sy + (v20 >> 3) + 4, 0)
    elif st == 0x11:
        if v20 == 0 and getattr(self, "actorq", None):
            self.p4_spawn52c_flash(0, 0xFFFFFF01, 0x61000005, -4)
        if x < -0xF0:
            return self._p4_40a930_death(e, x, y)
    # 移动
    w30 = e.g16(0x30)
    w32 = e.g16(0x32)
    if st == 0x11:
        w30 = (w30 - ((v20 << 6) & 0xFFFF)) & 0xFFFF
    else:
        d = ((self.p4_player_x() >> 2) - x + 0x1E0) >> 3
        w30 = (w30 + (d & 0xFFFF)) & 0xFFFF
    d2 = ((self.p4_player_y() >> 1) - y + 0x78) >> 3
    w32 = (w32 + (d2 & 0xFFFF)) & 0xFFFF
    e.d16(0x30, w30)
    e.d16(0x32, w32)
    w30s = w30 - 0x10000 if w30 & 0x8000 else w30
    w32s = w32 - 0x10000 if w32 & 0x8000 else w32
    x = w30s >> 5
    y = w32s >> 5
    e.d32(0x04, x & 0xFFFFFFFF)
    e.d32(0x08, y & 0xFFFFFFFF)
    if e.node is not None:
        e.node.dst = (x - 0xA0, y - 0x60)
    if e.g32(0x18) > 0x9C40:
        return True
    return self._p4_40a930_death(e, x, y)


def _p4_40a930_death(self, e, x: int, y: int) -> bool:
    """`0x40A930` 死亡段：0x4A000006 入 4CC、清位、全局件。"""
    self.spawn(self._p4_q("ui4cc"), 0x4A000006, x, y, 0)
    self.p4_other.setdefault("4cd4a0", []).append(0xF4240)
    return False


def _beh_40B040(self, e) -> bool:
    """`0x40B040`（0x2A000003，0x40A930 三件套之二）：**挂件体十三态**。

    挂点 = [0x1C]+4 句柄 → 挂主体；x = 主.x − 0x8C、y = 主.y − 0x6E。
    主.[0x24]&0x1FF（编队掩码）≠0：掩码 <0xF0 且奇 → node.active=1；
    主.[0x1C]≥0 且 掩码==1 且 主.[0x20]<7 → [主.[0x24]]−=0（保留）；
    [主.[0x24]]−=1；[0x10] = 掩码<0x3C。
    掩码==0：主.[0x1C]<0 → 直接收尾；主.[0x20]==4 → y = sin(45t+0x10E)?? 
    （(5t)*8+0x10E 的 sin>>4 − sin + 主.y）；==0xE → t∈{0x78,0xA3,0xCD} →
    发 0x32000010 @(x,y) 入 0x4AD49C。
    主.[0x28]==0 → 态=主.[0x20]−1（>0xC 跳过）；十三态表 0x40B738：
      0：(t&0x3F)==0 → 0x3100001B @(x,y) 入 49C
      1：(t&7)==4 → 0x2A000005 @(x+rand%0x50, y+rand%0xC)（0x401997 朝机
         −0x400 速）当 rand%0xC==0xB
      3：(t%0x50)==0x36 门 → (t&3)==3 → 8 向扇形 0x43B290（esi 表 {0x62,0x64,
         0x5C,0x53,0x47,0x38,0x26,0x14} 镜像 ±，spd −0x200）
      7：(t&1)==0 → ang=(0x1E−t)*30：0x43B290(e, cos(ang), sin(ang), −0xE00)
      9：(t&3)==0 → 0x43B070(e, (t&0xFC)>0x14 ? 0x600 : ((t>>2)+1)<<8)
      10：t==0 → 0x3100001B @(x,y) + 0xC dword 偏移表
         {−5,0xC,0,12,12,12,12,12,12,12,0,12} ×7 架 0x3100001B 入 49C（镜像朝机）
      11：t==0x3C → 速度 = 6×单位向自机（0x45AA80*Δ*6>>12）；t>0x3C 且 (t&3)==0 →
         三连 0x43B290（(vx,vy,−0x380)/(2vx−vy,2vy−vx)/(2vy? ...) 旋转三向）
      12：(t&0x1F)==0 → 环形 0x43B290：esi/edi=cos/sin(0x708)，4 次减 0x64
         循环：(cos, sin>>2, 0x1C0)/(−sin>>2, −cos, 0x1C0)
    收尾：node dst=(x−0x32, y−0x2C)；主.[0x20]≥0xD → [主 0x18]=0x186A0；
    [主 0x18]==0 → 0x61000004 @(x,y,0x48) 入 52C + 0x2A000002 @(0,0,prm=主)
    入 0x4AD43C + 0x32000007 @(x,y) 入 49C；主.[0x24] = (掩码&0xFFFFFE00)+0x1E0。
    主.[0x30]==0 → 0x4A000007 @(x,y,prm=主) 入 4CC；return byte[主+0x30]。"""
    links = getattr(self, "p4_links", {})
    h = e.s32(0x1C) + 4
    main = links.get(h & 0x7FFFFFFF)
    if main is None:
        return False
    x = (main.s32(0x04) - 0x8C) & 0xFFFFFFFF
    y = (main.s32(0x08) - 0x6E) & 0xFFFFFFFF
    e.d32(0x04, x)
    e.d32(0x08, y)
    mask = main.g32(0x24) & 0x1FF
    if mask != 0:
        nd = e.node
        if nd is not None:
            nd.active = 1 if (mask < 0xF0 and (mask & 1)) else 0
        if main.s32(0x1C) >= 0 and mask == 1 and main.s32(0x20) < 7:
            main.d32(0x24, (main.g32(0x24) - 0) & 0xFFFFFFFF)
        else:
            main.d32(0x24, (main.g32(0x24) - 1) & 0xFFFFFFFF)
        e.m[0x10] = 1 if mask < 0x3C else 0
    else:
        if main.s32(0x1C) < 0:
            return self._p4_40b040_tail(e, main, x, y)
        mt = main.s32(0x20)
        if mt == 4:
            a = (40 * main.s32(0x1C) + 0x10E) & 0xFFFFFFFF
            s_ = page4_sin(a)
            e.d32(0x08, (main.s32(0x04) + ((s_ >> 4) - s_)) & 0xFFFFFFFF) if False else None
            e.d32(0x08, (main.s32(0x08) + ((s_ >> 4) - s_)) & 0xFFFFFFFF)
        elif mt == 0xE:
            tt = main.s32(0x1C)
            if tt in (0x78, 0xA3, 0xCD):
                self.spawn(self._p4_q("ui49c"), 0x32000010, x, y, 0)
        m28 = main.s32(0x28)
        sub = (main.s32(0x20) - 1) if m28 == 0 else -1
        if 0 <= sub <= 0xC:
            t = main.s32(0x1C)
            if sub == 0:
                if (t & 0x3F) == 0:
                    self.spawn(self._p4_q("ui49c"), 0x3100001B, x, y, 0)
            elif sub == 1:
                if (t & 7) == 4:
                    q, r = divmod(t, 0x50)
                    if r == 0xB:
                        self._p4_ent43c(0x2A000005,
                                        x + (self.p4_rand() % 0x50),
                                        y + (self.p4_rand() % 0xC))
                        self.p4_43B610(e, self.p4_player_x(),
                                       self.p4_player_y(), -0x400 & 0xFFFFFFFF)
            elif sub == 3:
                q, r = divmod(t, 0x50)
                if r < 0x36 and (t & 3) == 3:
                    for k in range(8):
                        v = (0x62, 0x64, 0x5C, 0x53, 0x47, 0x38, 0x26, 0x14)[k]
                        if x < self.p4_player_x():
                            v = -v
                        self.p4_43B290(e, -v, v, -0x200 & 0xFFFFFFFF)
                        self.p4_43B290(e, -v, -v, -0x200 & 0xFFFFFFFF)
            elif sub == 7:
                if (t & 1) == 0:
                    ang = ((0x1E - t) * 30) & 0xFFFFFFFF
                    c = page4_cos(ang)
                    s_ = page4_sin(ang)
                    self.p4_43B290(e, c, s_, -0xE00 & 0xFFFFFFFF)
                    self.p4_43B290(e, -s_, -c, -0xE00 & 0xFFFFFFFF)
            elif sub == 9:
                if (t & 3) == 0:
                    spd = 0x600 if (t & 0xFC) > 0x14 else ((t >> 2) + 1) << 8
                    self.p4_43B070(e, spd & 0xFFFFFFFF)
            elif sub == 10:
                if t == 0:
                    self.spawn(self._p4_q("ui49c"), 0x3100001B, x, y, 0)
                    offs = (-5, 0xC, 0, 12, 12, 12, 12, 12, 12, 12, 0, 12, 0xC)
                    for i in range(7):
                        dx = offs[i]
                        dy = offs[i + 1] if i + 1 < len(offs) else 0xC
                        if y >= self.p4_player_y():
                            dy = -dy
                        if x >= self.p4_player_x():
                            dx = -dx
                        self.spawn(self._p4_q("ui49c"), 0x3100001B,
                                   x, y, (dx, dy))
            elif sub == 11:
                if t == 0x3C:
                    dx = self.p4_player_x() - x
                    dy = self.p4_player_y() - y
                    inv = self.p4_45aa80(dx, dy)
                    e.d32(0x20, (((inv * dx) * 6) >> 12) & 0xFFFFFFFF)
                    e.d32(0x24, (((inv * dy) * 6) >> 12) & 0xFFFFFFFF)
                if t > 0x3C and (t & 3) == 0:
                    vx = e.s32(0x20)
                    vy = e.s32(0x24)
                    self.p4_43B290(e, vx, vy, -0x380 & 0xFFFFFFFF)
                    self.p4_43B290(e, 2 * vx - vy, 2 * vy - vx,
                                   -0x380 & 0xFFFFFFFF)
                    self.p4_43B290(e, 2 * vy - vx, vx - 2 * vy,
                                   -0x380 & 0xFFFFFFFF)
            elif sub == 12:
                if (t & 0x1F) == 0:
                    a = 0x708
                    for _ in range(4):
                        c = page4_cos(a)
                        s_ = page4_sin(a)
                        self.p4_43B290(e, c, s_ >> 2, 0x1C0)
                        self.p4_43B290(e, -(s_ >> 2), -c, 0x1C0)
                        a -= 0x64
    return self._p4_40b040_tail(e, main, x, y)


def _p4_40b040_tail(self, e, main, x: int, y: int) -> bool:
    """`0x40B040` 收尾：node dst、主 HP 门、死亡三件。"""
    if e.node is not None:
        e.node.dst = (x - 0x32, y - 0x2C)
    if main.s32(0x20) >= 0xD:
        main.d32(0x18, 0x186A0)
    if main.g32(0x18) == 0:
        self.p4_spawn52c_flash(x, y, 0x61000004, 0x48)
        c = self._p4_ent43c(0x2A000002, 0, 0)
        c.d32(0x18, id(main) & 0x7FFFFFFF)
        getattr(self, "p4_links", {})[id(main) & 0x7FFFFFFF] = main
        self.spawn(self._p4_q("ui49c"), 0x32000007, x, y, 0)
        m24 = main.g32(0x24)
        main.d32(0x28, 0x78)
        main.d32(0x24, ((m24 & 0xFFFFFE00) + 0x1E0) & 0xFFFFFFFF)
    if main.g32(0x30) == 0:
        self.spawn(self._p4_q("ui4cc"), 0x4A000007, x, y,
                   id(main) & 0x7FFFFFFF)
    return main.m[0x30] != 0


def _beh_40CE90(self, e) -> bool:
    """`0x40CE90`（0x2A000005，0x40B040 态1 铺出的小机）：**斜落小体**。

    0x45A790(node+4, ±0x30, 0, ±0x30, 0)（(t&4)?+0x30:0x30−0xA0=−0x70？字面
    and 0xA0/add 0x30 → (t&4)? 0x30+0x30 : 0x30−0xA0）→ rect 横移（帧动画）；
    [0x28] += [0x20]、[0x2C] += [0x24]；x=[0x28]>>4、y=[0x2C]>>4；t=[0x1C]++；
    node dst=(x−0x18,y−0x18)；return −0x18<x<0x298 且 −0x18<y<0x1F8 且 HP≠0。"""
    t = e.s32(0x1C)
    dy = (0x30 + 0x30) if (t & 4) else (0x30 - 0xA0)
    nd = e.node
    if nd is not None:                              # 0x45A790(node+4, dy,0, dy,0)
        nd.rect = (nd.rect[0] + dy, nd.rect[1], nd.rect[2] + dy, nd.rect[3])
    e.d32(0x28, (e.s32(0x28) + e.s32(0x20)) & 0xFFFFFFFF)
    e.d32(0x2C, (e.s32(0x2C) + e.s32(0x24)) & 0xFFFFFFFF)
    a28 = e.s32(0x28)
    a2c = e.s32(0x2C)
    x = (a28 - 0x100000000 if a28 & 0x80000000 else a28) >> 4
    y = (a2c - 0x100000000 if a2c & 0x80000000 else a2c) >> 4
    e.d32(0x04, x & 0xFFFFFFFF)
    e.d32(0x08, y & 0xFFFFFFFF)
    e.d32(0x1C, (t + 1) & 0xFFFFFFFF)
    if e.node is not None:
        e.node.dst = (x - 0x18, y - 0x18)
    return (-0x18 < x < 0x298 and -0x18 < y < 0x1F8
            and e.g32(0x18) != 0)


def _beh_40BB60(self, e) -> bool:
    """`0x40BB60`（0x2A000004，0x40A930 三件套之三）：**挂件体（镜像十三态）**。

    挂点 = [0x1C]+4 → 主；x = 主.x − 0x90、y = 主.y − 0x28。
    主掩码（[0x24]>>9&0x1FF）≠0：同 0x40B040 门（node.active、[主 0x24]−=0x200、
    [0x10] = 掩码<0x3C）。掩码==0：主态 3/4/6 分支（sin 摆 / 六段）+ 主.[0x20]
    十三态表 0x40C348：
      0：(t&0x3F)==0 → 环形 0x43B290 ×8（ang (t&0x40?0x96:0) 起 0x12C 步至 0x708，
        spd 0x2C0 双向）
      2：(t&1)==0 → ang=90t−0x505：0x402144(0x43B430) ×8（spd −0x380..−0x800）
      3：(t%0xC)==0xB → 0x43B610(e, x±0x27F?, −0x400)（镜像朝机）
      5：0x1E<t<0xD2 且 (t&3)==3 → 0x45A9A0(Δ自机)+((t−0x1E)/2)*180 →
         0x43B430(e, cos, sin, 0x280)（0x402144）
      8：(t&0x1F)==0 → 16 连环形 0x43B290（ang (t>>5)*450 步 0x38、spd −0x240）
      9：(t&3)==0 → 0x43B070(e, 同 0x40B040 态9 式)
      10：(t&0x1F)==0 → 0x43B070(e, 0x300) + 0x43B150(e, 0, 0, 0x300)（角炮）
      11：t==0 → 速度 = 6×单位向自机；(t&3)==0 → 四向 0x43B290
         （(vx+vy, vy−vx)/(vx−vy? ...) −0x380，0x40165E）
      12：(t&0x1F)==0 → 环形 0x43B290 ×4（0x708 起步 0x64 减）+ 对向
    收尾同 0x40B040（node dst=(x−0x32,y−0x2C)、主 HP 门、死亡三件）。"""
    links = getattr(self, "p4_links", {})
    main = links.get((e.s32(0x1C) + 4) & 0x7FFFFFFF)
    if main is None:
        return False
    x = (main.s32(0x04) - 0x90) & 0xFFFFFFFF
    y = (main.s32(0x08) - 0x28) & 0xFFFFFFFF
    e.d32(0x04, x)
    e.d32(0x08, y)
    mask = (main.g32(0x24) >> 9) & 0x1FF
    if mask != 0:
        nd = e.node
        if nd is not None:
            nd.active = 1 if (mask < 0xF0 and (mask & 1)) else 0
        dec = 0 if (main.s32(0x1C) >= 0 and mask == 1 and main.s32(0x20) < 7) else 0x200
        main.d32(0x24, (main.g32(0x24) - dec) & 0xFFFFFFFF)
        e.m[0x10] = 1 if mask < 0x3C else 0
    else:
        if main.s32(0x1C) < 0:
            return self._p4_40b040_tail(e, main, x, y)
        mt = main.s32(0x20)
        if mt == 3:
            t1 = main.s32(0x1C)
            if t1 < 0x74:
                a = (45 * t1) & 0xFFFFFFFF
                self.spawn(self._p4_q("ui49c"), 0x32000010, x,
                           y + ((page4_sin(a) >> 4) - page4_sin(a)), 0)
            else:
                pass
        elif mt == 4:
            a = (45 * main.s32(0x1C) - 0x5F) & 0xFFFFFFFF
            s_ = page4_sin(a)
            e.d32(0x08, (main.s32(0x08) + ((s_ >> 4) - s_)) & 0xFFFFFFFF)
        elif mt == 6:
            t1 = main.s32(0x1C)
            if t1 == 0:
                dx = self.p4_player_x() - x
                dy = self.p4_player_y() - y
                inv = self.p4_45aa80(dx, dy)
                main.d32(0x28, ((inv * dx) >> 7) & 0xFFFFFFFF)
                main.d32(0x2C, ((inv * dy) >> 7) & 0xFFFFFFFF)
                main.d32(0x20, 0)
                main.d32(0x24, 0)
            elif t1 < 0x1E:
                main.d32(0x20, (main.s32(0x20) + main.s32(0x28) * t1) & 0xFFFFFFFF)
                main.d32(0x24, (main.s32(0x24) + main.s32(0x2C) * t1) & 0xFFFFFFFF)
            elif t1 < 0xD2:
                da = self.p4_45a9a0(
                    self.p4_player_x() - (main.s32(0x20) >> 6) - x,
                    self.p4_player_y() - (main.s32(0x24) >> 6) - y)
                a = ((main.s32(0x1C) - 0x1E) >> 1) * 180
                a = (a + da + 0x55F) & 0xFFFFFFFF
                self.spawn(self._p4_q("ui49c"), 0x32000010, x, y, 0)
            elif t1 < 0xF0:
                if 0xD2 <= t1 < 0xD6:
                    pass
                main.d32(0x20, (main.s32(0x20)
                                + main.s32(0x28) * (0xD2 - t1)) & 0xFFFFFFFF)
                main.d32(0x24, (main.s32(0x24)
                                + main.s32(0x2C) * (0xD2 - t1)) & 0xFFFFFFFF)
            main.d32(0x04, ((main.s32(0x20) >> 6) + main.s32(0x04) - 0x90) & 0xFFFFFFFF)
            main.d32(0x08, ((main.s32(0x24) >> 6) + main.s32(0x08) - 0x28) & 0xFFFFFFFF)
        elif mt == 0xE:
            t1 = main.s32(0x1C)
            if t1 in (0, 0x2B, 0x55):
                self.spawn(self._p4_q("ui49c"), 0x32000010, x, y, 0)
        sub = (main.s32(0x20) - 1) if main.s32(0x28) == 0 else -1
        if 0 <= sub <= 0xC:
            t = main.s32(0x1C)
            if sub == 0:
                if (t & 0x3F) == 0:
                    ang0 = 0x96 if (t & 0x40) else 0
                    a = ang0
                    while a < 0x708:
                        c = page4_cos(a)
                        s_ = page4_sin(a)
                        self.p4_43B290(e, c, s_, 0x2C0)
                        self.p4_43B290(e, -c, -s_, 0x2C0)
                        a += 0x12C
            elif sub == 2:
                if (t & 1) == 0:
                    a = (90 * t - 0x505) & 0xFFFFFFFF
                    c = page4_cos(a) >> 3
                    s_ = page4_sin(a) >> 3
                    spd = -0x380
                    while spd >= -0x800:
                        self.p4_43B430(e, 2 * c, x + 2 * s_ if False else 2 * s_,
                                       spd & 0xFFFFFFFF)
                        spd -= 0x80
            elif sub == 3:
                q, r = divmod(t, 0xC)
                if r == 0xB:
                    dx = self.p4_player_x() - x
                    vx = 0x27F if dx >= 0 else -0x27F
                    self.p4_43B610(e, x + vx, y, -0x400 & 0xFFFFFFFF)
            elif sub == 5:
                if 0x1E < t < 0xD2 and (t & 3) == 3:
                    da = self.p4_45a9a0(
                        self.p4_player_x() - (main.s32(0x20) >> 6) - x,
                        self.p4_player_y() - (main.s32(0x24) >> 6) - y)
                    a = ((t - 0x1E) >> 1) * 180
                    a = (a + da + 0x55F) & 0xFFFFFFFF
                    self.p4_43B430(e, page4_cos(a), page4_sin(a), 0x280)
            elif sub == 8:
                if (t & 0x1F) == 0:
                    n16 = 0x10
                    a = ((t >> 5) * 450) & 0xFFFFFFFF
                    while n16:
                        c = page4_cos(a)
                        s_ = page4_sin(a)
                        self.p4_43B290(e, c, s_ >> 2, -0x240 & 0xFFFFFFFF)
                        self.p4_43B290(e, -(s_ >> 2), -c, -0x240 & 0xFFFFFFFF)
                        a += 0x38
                        n16 -= 1
            elif sub == 9:
                if (t & 3) == 0:
                    spd = 0x600 if (t & 0xFC) > 0x14 else ((t >> 2) + 1) << 8
                    self.p4_43B070(e, spd & 0xFFFFFFFF)
            elif sub == 10:
                if (t & 0x1F) == 0:
                    self.p4_43B070(e, 0x300)
                    self.p4_43B150(e, 0x300)
            elif sub == 11:
                if t == 0:
                    dx = self.p4_player_x() - x
                    dy = self.p4_player_y() - y
                    inv = self.p4_45aa80(dx, dy)
                    main.d32(0x20, (((inv * dx) * 6) >> 12) & 0xFFFFFFFF)
                    main.d32(0x24, (((inv * dy) * 6) >> 12) & 0xFFFFFFFF)
                if (t & 3) == 0 and t != 0:
                    vx = main.s32(0x20)
                    vy = main.s32(0x24)
                    self.p4_43B290(e, vx + vy, vy - vx, -0x380 & 0xFFFFFFFF)
                    self.p4_43B290(e, vx - vy, -(vx + vy), -0x380 & 0xFFFFFFFF)
                    self.p4_43B290(e, 4 * vy - vx, 4 * vy - vx if False else vx * 4 + vy,
                                   -0x380 & 0xFFFFFFFF)
                    self.p4_43B290(e, 4 * vy - vx, vy - 4 * vx,
                                   -0x380 & 0xFFFFFFFF)
            elif sub == 12:
                if (t & 0x1F) == 0:
                    a = 0x708
                    for _ in range(4):
                        c = page4_cos(a)
                        s_ = page4_sin(a)
                        self.p4_43B290(e, c, s_ >> 2, 0x1C0)
                        self.p4_43B290(e, -(s_ >> 2), -c, 0x1C0)
                        a -= 0x64
    return self._p4_40b040_tail(e, main, x, y)


def _beh_40C590(self, e) -> bool:
    """`0x40C590`（0x2A000007，0x40A930 编队僚机）：**挂点体十三态**。

    挂点 = [0x1C]+4 → 主；x = 主.x − 0x90、y = 主.y + 0x5A。
    主掩码（[0x24]>>0x12&0x1FF）≠0：同 0x40B040 门（node.active、
    [主 0x24]−=0x40000、[0x10]=掩码<0x3C）。掩码==0：主态 4→sin(45t−0xDC) 摆、
    0xE→t∈{0x3C,0x67,0x91} 发 0x32000010；主.[0x20]−1 十三态表 0x40CC88：
      0：(t&0x3F)==0 → 0x3100001B @(x,y) 入 49C
      1：(t&7)==0 → 0x2A000005 @(x+rand%0x50, y+rand%0xC) 入 43C
      3：(t%0xC)==0xB → 0x43B610(e, x±0x27F, y, −0x400)（镜像朝机）
      4：(t%0x50)<0x36 且 (t&3)==3 → 8 向扇形（表 {0x62,0x64,0x5C,0x53,0x47,
         0x38,0x26,0x14} 镜像 ±，spd −0x200 双发）
      7：(t&1)==0 → ang=(0x1E−t)*30 反向：0x43B290(e, −sin, −cos, −0xE00)
      9：(t&3)==0 → 0x43B070(e, 同 9 式)
      10：t==0x78 → 0x3100001B + 0xC 偏移表 ×7 架（镜像朝机）入 49C
      11：t==0x78 → 速度 = 6×单位向自机；t>0x78 且 (t&3)==0 → 三连 0x43B290
         （(vx,vy)/(2vx−vy,2vy−vx)/(2vy−vx,vx−2vy) −0x380）
      12：(t&0x1F)==0 → 环形 0x43B290 ×4（0x708 步 −0x64）+ 对向
    收尾同 0x40B040（node dst=(x−0x32,y−0x2C)、主 HP 门、死亡三件）。"""
    links = getattr(self, "p4_links", {})
    main = links.get((e.s32(0x1C) + 4) & 0x7FFFFFFF)
    if main is None:
        return False
    x = (main.s32(0x04) - 0x90) & 0xFFFFFFFF
    y = (main.s32(0x08) + 0x5A) & 0xFFFFFFFF
    e.d32(0x04, x)
    e.d32(0x08, y)
    mask = (main.g32(0x24) >> 0x12) & 0x1FF
    if mask != 0:
        nd = e.node
        if nd is not None:
            nd.active = 1 if (mask < 0xF0 and (mask & 1)) else 0
        dec = 0 if (main.s32(0x1C) >= 0 and mask == 1 and main.s32(0x20) < 7) else 0x40000
        main.d32(0x24, (main.g32(0x24) - dec) & 0xFFFFFFFF)
        e.m[0x10] = 1 if mask < 0x3C else 0
    else:
        if main.s32(0x1C) < 0:
            return self._p4_40b040_tail(e, main, x, y)
        mt = main.s32(0x20)
        if mt == 4:
            a = (45 * main.s32(0x1C) - 0xDC) & 0xFFFFFFFF
            s_ = page4_sin(a)
            e.d32(0x08, (main.s32(0x08) + ((s_ >> 4) - s_)) & 0xFFFFFFFF)
        elif mt == 0xE:
            t1 = main.s32(0x1C)
            if t1 in (0x3C, 0x67, 0x91):
                self.spawn(self._p4_q("ui49c"), 0x32000010, x, y, 0)
        sub = (main.s32(0x20) - 1) if main.s32(0x28) == 0 else -1
        if 0 <= sub <= 0xC:
            t = main.s32(0x1C)
            if sub == 0:
                if (t & 0x3F) == 0:
                    self.spawn(self._p4_q("ui49c"), 0x3100001B, x, y, 0)
            elif sub == 1:
                if (t & 7) == 0:
                    self._p4_ent43c(0x2A000005, x + (self.p4_rand() % 0x50),
                                    y + (self.p4_rand() % 0xC))
            elif sub == 3:
                q, r = divmod(t, 0xC)
                if r == 0xB:
                    dx = self.p4_player_x() - x
                    vx = 0x27F if dx >= 0 else -0x27F
                    self.p4_43B610(e, x + vx, y, -0x400 & 0xFFFFFFFF)
            elif sub == 4:
                q, r = divmod(t, 0x50)
                if r < 0x36 and (t & 3) == 3:
                    for k in range(8):
                        v = (0x62, 0x64, 0x5C, 0x53, 0x47, 0x38, 0x26, 0x14)[k]
                        if x < self.p4_player_x():
                            v = -v
                        self.p4_43B290(e, -v, v, -0x200 & 0xFFFFFFFF)
                        self.p4_43B290(e, -v, -v, -0x200 & 0xFFFFFFFF)
            elif sub == 7:
                if (t & 1) == 0:
                    ang = ((0x1E - t) * 30) & 0xFFFFFFFF
                    c = page4_cos(ang)
                    s_ = page4_sin(ang)
                    self.p4_43B290(e, -s_, -c, -0xE00 & 0xFFFFFFFF)
            elif sub == 9:
                if (t & 3) == 0:
                    spd = 0x600 if (t & 0xFC) > 0x14 else ((t >> 2) + 1) << 8
                    self.p4_43B070(e, spd & 0xFFFFFFFF)
            elif sub == 10:
                if t == 0x78:
                    self.spawn(self._p4_q("ui49c"), 0x3100001B, x, y, 0)
                    offs = (-5, 0xC, 0, 12, 12, 12, 12, 12, 12, 12, 0, 12, 0xC)
                    for i in range(7):
                        dx = offs[i]
                        dy = offs[i + 1] if i + 1 < len(offs) else 0xC
                        if y >= self.p4_player_y():
                            dy = -dy
                        if x >= self.p4_player_x():
                            dx = -dx
                        self.spawn(self._p4_q("ui49c"), 0x3100001B,
                                   x, y, (dx, dy))
            elif sub == 11:
                if t == 0x78:
                    dx = self.p4_player_x() - x
                    dy = self.p4_player_y() - y
                    inv = self.p4_45aa80(dx, dy)
                    e.d32(0x20, (((inv * dx) * 6) >> 12) & 0xFFFFFFFF)
                    e.d32(0x24, (((inv * dy) * 6) >> 12) & 0xFFFFFFFF)
                if t > 0x78 and (t & 3) == 0:
                    vx = e.s32(0x20)
                    vy = e.s32(0x24)
                    self.p4_43B290(e, vx, vy, -0x380 & 0xFFFFFFFF)
                    self.p4_43B290(e, 2 * vx - vy, 2 * vy - vx,
                                   -0x380 & 0xFFFFFFFF)
                    self.p4_43B290(e, 2 * vy - vx, vx - 2 * vy,
                                   -0x380 & 0xFFFFFFFF)
            elif sub == 12:
                if (t & 0x1F) == 0:
                    a = 0x708
                    for _ in range(4):
                        c = page4_cos(a)
                        s_ = page4_sin(a)
                        self.p4_43B290(e, c, s_ >> 2, 0x1C0)
                        self.p4_43B290(e, -(s_ >> 2), -c, 0x1C0)
                        a -= 0x64
    return self._p4_40b040_tail(e, main, x, y)


_P4_40D030_LIM = (0x3C, 0x1E0, 0x258, 0x168, 0x50, 0x50, 0x50, 0x50, 0x50,
                  0x50, 0x168, 0x60, -1)
_P4_40D030_LIM2 = (0x50, 0x50, 0x50, 0x50, 0x50, 0x50, 0x168, 0x60, -1)


def _p4_40d030_fire(self, e, typ, a1, a2, a3, a4, spd):
    """`0x40CF60`（thunk 0x40155A）：**A→B 定向 0x3100001E 弹**（0x45AA80 归一、
    0x43AF90(e,spd)>>4 速）入 0x4AD49C。"""
    dx = a3 - a1
    dy = a4 - a2
    spd_v = self.p4_43af90(e, spd) >> 4
    inv = self.p4_45aa80(dx, dy)
    vx = ((inv * dx) * spd_v) >> 8
    vy = ((inv * dy) * spd_v) >> 8
    if vx == 0 and vy == 0:
        return
    eb = self.spawn(self._p4_q("ui49c"), typ, e.s32(0x04), e.s32(0x08), (vx, vy))
    if eb is not None:
        eb.raw[0x10] = 1
        eb.d32(0x14, typ & 0xFFFFFFFF)
        eb.d32(0x04, e.s32(0x04) & 0xFFFFFFFF)
        eb.d32(0x08, e.s32(0x08) & 0xFFFFFFFF)
        eb.d32(0x0C, 0x18)
        self._p4_q("ui49c").append(eb)


def _beh_40D030(self, e) -> bool:
    """`0x40D030`（0x2A00000A，0x40A930 编队僚机 2）：**九态+后九态**。

    [0x1C] 前段（0..8）：0 → rect 缩放 2*[0x20]（0x45A750 中心扩）+ [0x10] 门
    （0x3C 显）；1..3 → rect 3*[0x20]（0x50 显）；其它同段。
    态 0..8（0x40D718）：
      0：t 奇 → ang=45t：0x3100001E 四向 0x40CF60（±cos/±sin 对，spd 0xF00）；
         (t&7)==0 → ang=−15t：双对 0x3100001E spd 0x580
      1：t 奇 → ang=rand%0xE10：0x3100001E @0x40CF60（rand&0x1FF+0x180 门、0xF00）；
         (t&0x6F)==0 → 六向朝机（Δx/Δy 及交叉组合，spd 0xA00，ang=3cos>>4/3sin>>4）
      3..7：t==0 → 0x20 连发：ang=rand%0xE10、0x3100001E（rand&0x3FF+0x180）
      8：0x45A9A0(Δ自机) + ang=180t*(t&1?+2:−2) → 0x3100001E spd 0x680
    [0x1C] 后段（0..8 表 0x40D73C）：
      0：x=0x140+(15t/2 的 sin>>2)、y=0xF0+(60t 的 sin>>2)
      1：y=0xF0+(60t 的 sin>>1)
      2..7：t==0x28 → 吸附自机（x∈[0x78,0x207]、y∈[0x78,0x167] 钳）
      8：t==0x28 → x=0x17C、y=0xF0
    态计时表（0x40D65A 栈表）：{0x3C,0x1E0,0x258,0x168,0x50×6,0x168,0x60,−1}；
    [0x20]==表值 → [0x20]=0、[0x1C] += (idx>9 ? +1 : −9+10=+1)；
    否则 [0x20]++。
    HP≥0x2710 → 0x61000004 @(x,y,0x78) 入 52C、return 0；
    node dst=(x−0x78, y−0x78)、return 1。"""
    st = e.s32(0x1C)
    t = e.s32(0x20)
    x = e.s32(0x04)
    y = e.s32(0x08)
    if st == 0:
        d = (0x28 - t) * 3 if t < 0x28 else 3 * t - 0x78
        nd = e.node
        if nd is not None:
            nd.rect = (x + d - 1, y + d - 1, x - d, y - d) \
                if False else (x - d, y - d, x + d - 1, y + d - 1)
            nd.active = 1 if t == 0x50 else 0
        e.m[0x10] = nd.active if nd else 0
    elif 3 < st <= 8:
        d = 2 * t
        nd = e.node
        if nd is not None:
            nd.rect = (x - d, y - d, x + d - 1, y + d - 1)
            nd.active = 1 if t == 0x3C else 0
        e.m[0x10] = nd.active if nd else 0
    if st - 1 <= 8:
        sub = st - 1
        if sub == 0:
            if t & 1:
                a = (45 * t) & 0xFFFFFFFF
                c = page4_cos(a) >> 2
                s_ = page4_sin(a) >> 2
                self._p4_40d030_fire(e, 0x3100001E, x, y, x + c, y + s_, 0xF00)
                self._p4_40d030_fire(e, 0x3100001E, x, y, x - c, y - s_, 0xF00)
                self._p4_40d030_fire(e, 0x3100001E, x, y, x + c, y - s_, 0xF00)
                self._p4_40d030_fire(e, 0x3100001E, x, y, x - c, y + s_, 0xF00)
            if (t & 7) == 0:
                a = ((-15 * t)) & 0xFFFFFFFF
                c = page4_cos(a) >> 2
                s_ = page4_sin(a) >> 2
                self._p4_40d030_fire(e, 0x3100001E, x, y, x + c, y + s_, 0x580)
                self._p4_40d030_fire(e, 0x3100001E, x, y, x - c, y - s_, 0x580)
        elif sub == 1:
            if t & 1:
                a = self.p4_rand() % 0xE10
                c = page4_cos(a) >> 2
                s_ = page4_sin(a) >> 2
                sp = (self.p4_rand() & 0x1FF) + 0x180
                self._p4_40d030_fire(e, 0x3100001E, x, y, x + c, y + s_, 0xF00)
            if (t & 0x6F) == 0:
                dx = self.p4_player_x() - x
                dy = self.p4_player_y() - y
                a = 0
                c3 = (page4_cos(a) * 3) >> 4
                s3 = (page4_sin(a) * 3) >> 4
                self._p4_40d030_fire(e, 0x3100001E, x, y, x + dx, y + dy, 0xA00)
                self._p4_40d030_fire(e, 0x3100001E, x, y, x - dx, y - dy, 0xA00)
                self._p4_40d030_fire(e, 0x3100001E, x, y, x - dx, y + dy, 0xA00)
                self._p4_40d030_fire(e, 0x3100001E, x, y, x + dx, y - dy, 0xA00)
                self._p4_40d030_fire(e, 0x3100001E, x, y, x + (dx - dy),
                                     y + (dy - dx), 0xA00)
                self._p4_40d030_fire(e, 0x3100001E, x, y, x - (dx - dy),
                                     y - (dy - dx), 0xA00)
        elif 3 <= sub <= 7:
            if t == 0:
                for _ in range(0x20):
                    a = self.p4_rand() % 0xE10
                    c = page4_cos(a) >> 2
                    s_ = page4_sin(a) >> 2
                    sp = (self.p4_rand() & 0x3FF) + 0x180
                    self._p4_40d030_fire(e, 0x3100001E, x, y, x + c, y + s_, 0xF00)
        elif sub == 8:
            da = self.p4_45a9a0(self.p4_player_x() - x, self.p4_player_y() - y)
            a = ((da + 180 * t * (2 if (t & 1) else -2))) & 0xFFFFFFFF
            c = page4_cos(a) >> 4
            s_ = page4_sin(a) >> 4
            self._p4_40d030_fire(e, 0x3100001E, x, y, x + c, y + s_, 0x680)
    # 后九态（0x40D73C）
    if st <= 8:
        if st == 0:
            a = (15 * t) & 0xFFFFFFFF
            e.d32(0x04, (0x140 + (page4_sin(a) >> 2)) & 0xFFFFFFFF)
            a2 = (60 * t) & 0xFFFFFFFF
            e.d32(0x08, (0xF0 + (page4_sin(a2) >> 2)) & 0xFFFFFFFF)
        elif st == 1:
            a2 = (60 * t) & 0xFFFFFFFF
            e.d32(0x08, (0xF0 + (page4_sin(a2) >> 1)) & 0xFFFFFFFF)
        elif 2 <= st <= 7:
            if t == 0x28:
                nx = self.p4_player_x()
                ny = self.p4_player_y()
                if nx < 0x78:
                    nx = 0x78
                if ny < 0x78:
                    ny = 0x78
                if nx >= 0x208:
                    nx = 0x207
                if ny >= 0x168:
                    ny = 0x167
                e.d32(0x04, nx)
                e.d32(0x08, ny)
        elif st == 8:
            if t == 0x28:
                e.d32(0x04, 0x17C)
                e.d32(0x08, 0xF0)
    lim = _P4_40D030_LIM[st] if st < len(_P4_40D030_LIM) else None
    if lim is not None and t == lim:
        e.d32(0x20, 0)
        e.d32(0x1C, (st + (1 if st > 9 else 1)) & 0xFFFFFFFF)
    else:
        e.d32(0x20, (t + 1) & 0xFFFFFFFF)
    if e.g32(0x18) >= 0x2710:
        self.p4_spawn52c_flash(x, y, 0x61000004, 0x78)
        return False
    if e.node is not None:
        e.node.dst = (x - 0x78, y - 0x78)
    return True


def _p4_4047e0_se(self, se: int, pan: int) -> None:
    """`0x4013A2 → 0x450350`：0x4AB4B0 槽位 SE。"""
    self.p4_se_pan(se, pan)


def _beh_4047E0(self, e) -> bool:
    """`0x4047E0`（0x2C000001，**关8 光炮 boss**）。

    [0x24]==0：发 0x2C000002/0x2C000003 @(0,0) 各一入 0x4AD43C。
    t=[0x1C]++；word[0x20]（8.8 角累积）<0x1400 且 HP≠0 且 t<0x3840 且
    word[0x22]<0x30 → word[0x22]++（加速）；word[0x20]>0x2800 或 t≥0x3840 或
    HP==0 → word[0x22]>0xFFC0 → word[0x22]−−（减速）；
    word[0x20] += word[0x22]；ang = word[0x20]>>4 + 0xA0。
    [0x24] += ang（0xE10 取模）；x = [0x24]（角度制）……
      字面：[0x24] += ang、mod 0xE10；x = cos([0x24]−0x12C?)*? —— 字面读：
      eax=[0x24]；edx=0x40159B([0x24]+0x12C?)（0x404954 push [0x24]+0x12C；
      sar eax,3；edx=[0x20]>>4；eax += edx；[4] = eax（x）；
      y = 0x180 + (0x401A50([0x24])>>3)；node dst=(x−0x60, y−0x60)。
    HP 门（[0x18]==0 或 [0x28]&2）→ [0x18]=0、[0x10]=0。
    HP==0：x>−0x78 → 0x401C08(0x4AD4CC, x, y, t, 0x60, 1) 特效件、return 1；
      否则 SE 0xB + return 0。
    HP≠0：(t&0x7F)==0 → 0x45A9A0(Δ自机)−0xC8 → 三连 0x43B430（0x402144）
      （byte 表 {0x2E,0x38,0x3C,0x42}/{0x24,1,0xDE,0xAF} 抖动 + sin/cos(edi−0xC8)）；
    ([0x28]&1) 且 t%0xA0==0x20 → 三发 0x2C000005 @(x+0x3C, y)
      （prm 0xFB800480 / 0xFDC00480 / 0x480）入 0x4AD43C；
    ([0x28]&1 或 t&0x200) 且 t%0x14F==0 且 x<0x258 → 0x2C000006 @(x,y) 入 0x4AD43C。
    return x > −0x78。"""
    links = getattr(self, "p4_links", {})
    if e.s32(0x24) == 0:
        self._p4_ent43c(0x2C000002, 0, 0)
        self._p4_ent43c(0x2C000003, 0, 0)
        e.d32(0x24, 1)
    t = (e.s32(0x1C) + 1) & 0xFFFFFFFF
    e.d32(0x1C, t)
    w20 = e.g16(0x20)
    w22 = e.g16(0x22)
    w20s = w20 - 0x10000 if w20 & 0x8000 else w20
    w22s = w22 - 0x10000 if w22 & 0x8000 else w22
    if w20s < 0x1400 and e.g32(0x18) != 0 and t < 0x3840 and w22s < 0x30:
        e.d16(0x22, (w22 + 1) & 0xFFFF)
        w22s += 1
    if w20s > 0x2800 or t >= 0x3840 or e.g32(0x18) == 0:
        if w22s > -0x40:
            e.d16(0x22, (w22 - 1) & 0xFFFF)
            w22s -= 1
    w20 = (w20 + w22s) & 0xFFFF
    e.d16(0x20, w20)
    ang = (w22s + 0xA0) & 0xFFFFFFFF           # 0x4048B7 movsx word[+0x22]+0xA0
    a24 = (e.s32(0x24) + ang) % 0xE10
    old24 = e.s32(0x24)
    if old24 < 0x384 <= old24 + ang:           # 0x4048C3 冲击波
        ebx = -0x40
        while ebx <= 0x20:
            self.spawn(self._p4_q("ui4fc"), 0x5C000001,
                       e.s32(0x04) + ebx, e.s32(0x08) + 0x50, 0)
            ebx += 0x18
        self._p4_4047e0_se(0x14, (e.s32(0x04) - 0x140) << 4)
    e.d32(0x24, a24)
    c = page4_cos((a24 + 0x12C) & 0xFFFFFFFF)
    s_ = page4_sin(a24)
    x = ((c >> 3) + (w20s >> 4)) & 0xFFFFFFFF
    y = (0x180 + (s_ >> 3)) & 0xFFFFFFFF
    e.d32(0x04, x)
    e.d32(0x08, y)
    if e.node is not None:
        e.node.dst = (x - 0x60, y - 0x60)
    if e.g32(0x18) == 0 or (e.g32(0x28) & 2):
        e.d32(0x18, 0)
        e.m[0x10] = 0
    if e.g32(0x18) == 0:
        if x > -0x78:
            self.spawn(self._p4_q("ui4cc"), 0x2C000005, x, y, (t, 0x60, 1))
            return True
        self._p4_4047e0_se(0xB, -0x1400)
        return False
    if (t & 0x7F) == 0:
        da = self.p4_45a9a0(self.p4_player_x() - x, self.p4_player_y() - y) - 0xC8
        edi = (da + 0x258) & 0xFFFFFFFF
        for _ in range(3):
            sx = page4_sin(edi)
            c2 = page4_cos(edi)
            self.p4_43B430(e, (0x2E + 0x38) + sx, (0xDE + 0x3C) + c2,
                           -0x500 & 0xFFFFFFFF)
            edi -= 0xC8
    if e.g32(0x28) & 1:
        if t % 0xA0 == 0x20:
            self._p4_ent43c(0x2C000005, x + 0x3C, y)
            self._p4_ent43c(0x2C000005, x + 0x3C, y)
            self._p4_ent43c(0x2C000005, x + 0x3C, y)
    if (e.g32(0x28) & 1) or (t & 0x200):
        if t % 0x14F == 0 and x < 0x258:
            self._p4_ent43c(0x2C000006, x, y)
    return x > -0x78


def _beh_404D00(self, e) -> bool:
    """`0x404D00`（0x2C000002，0x4047E0 护卫）：**挂主轨道绕行**。

    主 = [0x1C] 句柄；t2=[0x20]++；a24 = 主.[0x24] + 0x5DC；
    a24 跨 0x1194 → 0x5C000001 冲击波 ×4（x−0x40..+0x20 步 0x18，y+0x50）
    入 0x4AD4FC + SE 0x14 (x−0x140)<<4。
    [0x24] = a24；x = cos(a24+0x12C)>>3 + 主.word[0x20]>>4 − 0xC0；
    y = sin(a24)>>3 + 0x180；node dst=(x−0x60, y−0x60)。
    主.HP==0 或 自身 HP==0 → 主.[0x28] |= 2、自身 HP=0、[0x10]=0；
    若 主.byte[+0x34]（主死）→ 0x401C08(0x4AD4CC, x,y,t2,0x60,0) + return 1；
    否则 SE 0xB + return 0。
    HP≠0：(t2&0x7F)==0 → 0x45A9A0(Δ自机)−0x190 → 三连 0x43B430（同 0x4047E0 表）。
    return 1。"""
    links = getattr(self, "p4_links", {})
    main = links.get(e.s32(0x1C) & 0x7FFFFFFF)
    if main is None:
        return True
    t2 = (e.s32(0x20) + 1) & 0xFFFFFFFF
    e.d32(0x20, t2)
    a24 = (main.s32(0x24) + 0x5DC) % 0x100000000
    if e.s32(0x24) < 0x1194 <= a24:
        xx = -0x40
        while xx <= 0x20:
            self.spawn(self._p4_q("ui4fc"), 0x5C000001,
                       e.s32(0x04) + xx, e.s32(0x08) + 0x50, 0)
            xx += 0x18
        self._p4_4047e0_se(0x14, (e.s32(0x04) - 0x140) << 4)
    e.d32(0x24, a24)
    c = page4_cos((a24 + 0x12C) & 0xFFFFFFFF)
    s_ = page4_sin(a24)
    w20 = main.g16(0x20)
    x = ((c >> 3) + ((w20 - 0x10000 if w20 & 0x8000 else w20) >> 4) - 0xC0) & 0xFFFFFFFF
    y = (0x180 + (s_ >> 3)) & 0xFFFFFFFF
    e.d32(0x04, x)
    e.d32(0x08, y)
    if e.node is not None:
        e.node.dst = (x - 0x60, y - 0x60)
    if main.g32(0x18) == 0 or e.g32(0x18) == 0:
        main.d32(0x28, main.g32(0x28) | 2)
        e.d32(0x18, 0)
        e.m[0x10] = 0
        if main.m[0x34] != 0:
            self.spawn(self._p4_q("ui4cc"), 0x2C000005, x, y, (t2, 0x60, 0))
            return True
        self._p4_4047e0_se(0xB, -0x1400)
        return False
    if (t2 & 0x7F) == 0:
        da = self.p4_45a9a0(self.p4_player_x() - x, self.p4_player_y() - y) - 0x190
        edi = (da + 0x258) & 0xFFFFFFFF
        for _ in range(3):
            sx = page4_sin(edi)
            c2 = page4_cos(edi)
            self.p4_43B430(e, (0x2E + 0x38) + sx, (0xDE + 0x3C) + c2,
                           -0x500 & 0xFFFFFFFF)
            edi -= 0xC8
    return True


def _beh_404FA0(self, e) -> bool:
    """`0x404FA0`（0x2C000003，0x4047E0 护卫 2）：**挂主反向绕行 + 布件**。

    主 = [0x1C] 句柄；t2=[0x20]++；
    x = cos(主.[0x24]+0xBB8)>>5 + 主.word[0x20]>>4 − 0x60；
    y = sin(主.[0x24]+0xBB8)>>4 + 0xE0；node dst=(x−0x60,y−0x60)。
    t2==0x3C0 → 0x5100000A @(0x33,0xEA) 入 0x4AD4FC；
    (t2&0x3FF)==0 → 0x2C000004 @(0,0) 入 0x4AD43C；
    主.HP≠0 且 自身 HP≠0 → return byte[主+0x34]；
    否则：主.[0x28] |= 1；0x41000014 @(x,y) prm {6,1} 入 0x4AD4CC；
    自身 HP==0 → 0x32000007 @(x,y) 入 0x4AD49C；return 0。"""
    links = getattr(self, "p4_links", {})
    main = links.get(e.s32(0x1C) & 0x7FFFFFFF)
    if main is None:
        return False
    t2 = (e.s32(0x20) + 1) & 0xFFFFFFFF
    e.d32(0x20, t2)
    a = (main.s32(0x24) + 0xBB8) & 0xFFFFFFFF
    c = page4_cos(a)
    s_ = page4_sin(a)
    w20 = main.g16(0x20)
    x = ((c >> 5) + ((w20 - 0x10000 if w20 & 0x8000 else w20) >> 4) - 0x60) & 0xFFFFFFFF
    y = (0xE0 + (s_ >> 4)) & 0xFFFFFFFF
    e.d32(0x04, x)
    e.d32(0x08, y)
    if e.node is not None:
        e.node.dst = (x - 0x60, y - 0x60)
    if t2 == 0x3C0:
        self.spawn(self._p4_q("ui4fc"), 0x5100000A, 0x33, 0xEA, 0)
    if (t2 & 0x3FF) == 0:
        self._p4_ent43c(0x2C000004, 0, 0)
    if main.g32(0x18) != 0 and e.g32(0x18) != 0:
        return main.m[0x34] != 0
    main.d32(0x28, main.g32(0x28) | 1)
    self.spawn(self._p4_q("ui4cc"), 0x41000014, x, y, (6, 1))
    if e.g32(0x18) == 0:
        self.spawn(self._p4_q("ui49c"), 0x32000007, x, y, 0)
    return False


def _beh_4051A0(self, e) -> bool:
    """`0x4051A0`（0x2C000004，0x404FA0 铺出的小件）：**五段时序小机**。

    t2=[0x28]：<0x30 → [0x20]−−；0x30..0x3F：(t2&3)==0 → rect 行 −0x30；
    0x50..0xC7：(t2&7)==0 → 扇形 0x43B290（esi −0x32..0x32 步 5、
    (dx,dy,spd)=(−0x64, esi, −0xB00)）；0xC8..0xE7：(t2&3)==0 → rect 行 +0x30；
    0xE8..0x117 → [0x20]++。
    尾：x = 主? 无主：x = [0x1C]链+4 → rect[+4]+[0x20]（字面：eax=[0x1C]（句柄→
    node/rec）；edx=[eax+4]+[0x20] → x；eax=[eax+8]+[0x24] → y）；
    node dst=(x−0x18,y−0x18)；链体死（byte[+0x34]）或 HP==0 → die；
    存活 → t2++，return t2 < 0x118。"""
    links = getattr(self, "p4_links", {})
    h = e.s32(0x1C)
    host = links.get(h & 0x7FFFFFFF) if h else None
    t2 = e.s32(0x28)
    if host is not None:
        if t2 < 0x30:
            e.d32(0x20, (e.s32(0x20) - 1) & 0xFFFFFFFF)
        elif t2 < 0x40:
            if (t2 & 3) == 0:
                nd = e.node
                if nd is not None:                     # 0x4051C5 压栈 (0,-0x30,0,-0x30) → x
                    nd.rect = (nd.rect[0] - 0x30, nd.rect[1],
                               nd.rect[2] - 0x30, nd.rect[3])
        elif 0x50 <= t2 < 0xC8:
            if (t2 & 7) == 0:
                esi = -0x32
                while esi <= 0x32:
                    self.p4_43B290(e, -0x64, esi, -0xB00 & 0xFFFFFFFF)
                    esi += 5
        elif 0xC8 <= t2 < 0xE8:
            if (t2 & 3) == 0:
                nd = e.node
                if nd is not None:                     # 0x40521E 压栈 (0,0x30,0,0x30) → x
                    nd.rect = (nd.rect[0] + 0x30, nd.rect[1],
                               nd.rect[2] + 0x30, nd.rect[3])
        elif t2 < 0x118:
            e.d32(0x20, (e.s32(0x20) + 1) & 0xFFFFFFFF)
        x = (host.rect[0] if hasattr(host, 'rect') else 0)
        # 主链体：rec [+4]/[+8] = 位置（0x40524E 读 [eax+4]/[eax+8]）
        px = getattr(host, 's32', lambda o: 0)(0x04)
        py = getattr(host, 's32', lambda o: 0)(0x08)
        x = (px + e.s32(0x20)) & 0xFFFFFFFF
        y = (py + e.s32(0x24)) & 0xFFFFFFFF
        e.d32(0x04, x)
        e.d32(0x08, y)
        if e.node is not None:
            e.node.dst = (x - 0x18, y - 0x18)
        if host.m[0x34] != 0 and e.g32(0x18) != 0:
            t2 = (t2 + 1) & 0xFFFFFFFF
            e.d32(0x28, t2)
            return t2 < 0x118
        return False
    return False


def _beh_40F4F0(self, e) -> bool:
    """`0x40F4F0`（thunk 0x4015B4；0x23000012 ×9）：**弹跳小机**。

    t=++[0x1C]：
      t==0x14 → [0x20]=0、[0x24] = 40*[0x28]（(5v)<<3）
      0x14<t<0x3C → [0x24] −= [0x28]、[0x2C]++；[0x2C]==6 → 0x43B070(e,0)、
        [0x2C]=0
      t==0x3C → [0x24] = −40*[0x28]（(−5v)<<3）
      t>0x3C → [0x20]++、[0x24] += [0x28]
    x += [0x20]>>2、y += [0x24]>>2；node dst=(x−0x18,y−0x18)；
    return x ≤ 0x298 且 HP≠0。"""
    t = (e.s32(0x1C) + 1) & 0xFFFFFFFF
    e.d32(0x1C, t)
    v = e.s32(0x28)
    if t == 0x14:
        e.d32(0x20, 0)
        e.d32(0x24, (40 * v) & 0xFFFFFFFF)
    elif 0x14 < t < 0x3C:                      # 0x40F4FF jne/jle：t<0x14 什么都不做
        e.d32(0x24, (e.s32(0x24) - v) & 0xFFFFFFFF)
        c = (e.s32(0x2C) + 1) & 0xFFFFFFFF
        e.d32(0x2C, c)
        if c == 6:
            self.p4_43B070(e, 0)
            e.d32(0x2C, 0)
    elif t == 0x3C:
        e.d32(0x24, ((-5 * v) << 3) & 0xFFFFFFFF)
    else:
        e.d32(0x20, (e.s32(0x20) + 1) & 0xFFFFFFFF)
        e.d32(0x24, (e.s32(0x24) + v) & 0xFFFFFFFF)
    x = (e.s32(0x04) + (e.s32(0x20) >> 2)) & 0xFFFFFFFF
    y = (e.s32(0x08) + (e.s32(0x24) >> 2)) & 0xFFFFFFFF
    e.d32(0x04, x)
    e.d32(0x08, y)
    if e.node is not None:
        e.node.dst = (x - 0x18, y - 0x18)
    return x <= 0x298 and e.g32(0x18) != 0


def _beh_40F610(self, e) -> bool:
    """`0x40F610`（thunk 0x40231A；0x23000013/14 共用）：**中boss 三段飞行**。

    边界表 {0x22A,0x172,0x38,0}、段值表 {1,3,0,2}：取第一个 t≥bound[i] 的
    seg=value[i]（全不满足则本帧不移动）；x+=(seg&1?+4:-4)、y+=(seg&2?+4:-4)。
    0x38≤t<0x124：x=0x140+(170*cos(19t-0x266)+0x7F)>>8、
                    y=0xF0+(170*sin(19t-0x266)+0x7F)>>8
    t==0x172：x=0x38、y=-0x18。
    0x1B4≤t<0x22A：x=0xDC+(141*cos(23t-0x28EE)+0x7F)>>8、
                    y=0x154+(141*sin(23t-0x28EE)+0x7F)>>8。
    t==0xC8 且 type==0x23000013 且 (unsigned)[0x18]≤0xA → 0x43B070(e,0)。
    HP==0：0x45A790(node+4,0x30,0,0x30,0)（只加 rect.l/r）、[0x18]=-1、[0x10]=1；
    (unsigned)HP>0x14 → [0x18]=-1。
    t++；dst=(x-0x18,y-0x18)；return y≥-0x18。
    """
    t = e.s32(0x1C)
    x, y = e.s32(0x04), e.s32(0x08)
    bounds = (0x22A, 0x172, 0x38, 0)
    segvals = (1, 3, 0, 2)
    seg = None
    for i in range(4):
        if t >= bounds[i]:
            seg = segvals[i]
            break
    if seg is not None:                            # 0x40F675..0x40F69E
        x += 4 if (seg & 1) else -4
        y += 4 if (seg & 2) else -4
    if 0x38 <= t < 0x124:                          # 0x40F6A5
        ang = (19 * t - 0x266) & 0xFFFFFFFF
        x = (0x140 + ((170 * page4_cos(ang) + 0x7F) >> 8)) & 0xFFFFFFFF
        y = (0xF0 + ((170 * page4_sin(ang) + 0x7F) >> 8)) & 0xFFFFFFFF
    elif t == 0x172:                               # 0x40F6FA
        x = 0x38
        y = 0xFFFFFFE8
    elif 0x1B4 <= t < 0x22A:                       # 0x40F714
        ang = (23 * t - 0x28EE) & 0xFFFFFFFF
        x = (0xDC + ((141 * page4_cos(ang) + 0x7F) >> 8)) & 0xFFFFFFFF
        y = (0x154 + ((141 * page4_sin(ang) + 0x7F) >> 8)) & 0xFFFFFFFF
    e.d32(0x04, x)
    e.d32(0x08, y)
    if t == 0xC8 and e.s32(0x14) == 0x23000013 and e.g32(0x18) <= 0xA:
        self.p4_43B070(e, 0)
    hp = e.g32(0x18)
    if hp == 0:                                    # 0x40F788
        nd = e.node
        if nd is not None:                         # 0x45A790(node+4, 0x30,0,0x30,0)
            nd.rect = (nd.rect[0] + 0x30, nd.rect[1],
                       nd.rect[2] + 0x30, nd.rect[3])
        e.d32(0x18, 0xFFFFFFFF)
        e.m[0x10] = 1
    elif hp > 0x14:                                # 0x40F7B1 `jbe`（无符号）
        e.d32(0x18, 0xFFFFFFFF)
    t = (t + 1) & 0xFFFFFFFF
    e.d32(0x1C, t)
    if e.node is not None:
        e.node.dst = (x - 0x18, y - 0x18)
    return e.s32(0x08) >= -0x18


def _beh_40FD10(self, e) -> bool:
    """`0x40FD10`（thunk 0x4013BB；0x23000018）：**挂主僚机（三段特效）**。

    主 = [0x1C] 句柄；t2=[0x28]：
      <0x30 → [0x20]−−；0x30..0x3F：(t2&3)==0 → rect 行 −0x30；
      0x5B..0xA9：t2 奇 → (t2&0xF)−8：0x43B290(e, −0x2C, dx, 0)；
      0xB5..0xC4：(t2&3)==0 → rect 行 +0x30；≥0xC5 且 <0xF5 → [0x20]++。
    x = 主.x + [0x20]、y = 主.y + [0x24]；node dst=(x−0x18,y−0x18)。
    主态==7 或 HP==0 → 0x41000014 @(x,y) prm 0xC 入 0x4AD4CC、return 0；
    否则 t2++；return t2 < 0xF5。"""
    links = getattr(self, "p4_links", {})
    main = links.get(e.s32(0x1C) & 0x7FFFFFFF)
    if main is None:
        return False
    t2 = e.s32(0x28)
    if t2 < 0x30:
        e.d32(0x20, (e.s32(0x20) - 1) & 0xFFFFFFFF)
    elif t2 < 0x40:
        if (t2 & 3) == 0:
            nd = e.node
            if nd is not None:
                nd.rect = (nd.rect[0] - 0x30, nd.rect[1],
                           nd.rect[2] - 0x30, nd.rect[3])
    elif 0x5B <= t2 < 0xAA:
        if (t2 & 1):
            self.p4_43B290(e, -0x2C, (t2 & 0xF) - 8, 0)
    elif 0xB5 <= t2 < 0xC5:
        if (t2 & 3) == 0:
            nd = e.node
            if nd is not None:
                nd.rect = (nd.rect[0] + 0x30, nd.rect[1],
                           nd.rect[2] + 0x30, nd.rect[3])
    elif 0xC5 <= t2 < 0xF5:
        e.d32(0x20, (e.s32(0x20) + 1) & 0xFFFFFFFF)
    x = (main.s32(0x04) + e.s32(0x20)) & 0xFFFFFFFF
    y = (main.s32(0x08) + e.s32(0x24)) & 0xFFFFFFFF
    e.d32(0x04, x)
    e.d32(0x08, y)
    if e.node is not None:
        e.node.dst = (x - 0x18, y - 0x18)
    if main.s32(0x1C) == 7 or e.g32(0x18) == 0:
        self.p4_spawn41(0xC, 0, 0x41000014)
        return False
    t2 = (t2 + 1) & 0xFFFFFFFF
    e.d32(0x28, t2)
    return t2 < 0xF5


def _beh_40FEA0(self, e) -> bool:
    """`0x40FEA0`（thunk 0x401D48；0x23000016）：**挂主僚机（十二态）**。

    主 = [0x1C] 句柄；t2=主.word[0x20]（主态机）；态 = 主.[0x1C]−1（>0xB 跳）：
      0：t2≥0 且 (t2&0x1F)==0 → 0x43B360(e, 自机x, 自机y+([0x24]<0 ? +0x30 : −0x30)
         ⊕ ~(t2)>>5&1, 0x300)
      1：t2==0 且 [0x24]<0 → 0x23000017 @(x,y) 入 0x4AD43C（[0x28]=0）
      3：t2≥0x28 且 (t2&3)==0 → 0x43B070(e, (t2−0xA0)<<4)
      4：t2==0 且 [0x24]>0 → 0x23000017 @(x,y,prm={主,0x10000}) 入 0x4AD43C
      5：[0x24]<0：(t2&0x3F)==0x30 → 0x23000019 @(x,y,−0x48) 入 43C；
         [0x24]>0：(t2&0x3F)==0x10 → 0x23000019 @(x,y,0x48)
      6：0x41000001 + 0x41000004 ×5（±rand&0x1F−0xF）@(x,y) 入 0x4AD4CC、return 0
      8：t2≥0 且 (t2&0xF)==0 → 0x43B360(e, 自机x+(rand&0x3F)−0x20,
         自机y+(rand&0x3F)−0x20, 0)（0x401E56）
      9/11：t2==0 → 0x23000017 @(x,y,prm={主,( [0x24]≥0 ? 0x10000 : 0)}) 入 43C
      10：[0x24]<0：(t2&0xF)==4 → 0x23000019 @(x,y,−0x48)；[0x24]>0：
         (t2&0xF)==0xB → 0x23000019 @(x,y,0x48)
    x = 主.x + [0x20]、y = 主.y + [0x24]；node dst=(x−0x18,y−0x18)；
    [0x2C]==0 → HP=−1；主死 或 HP==0 → return 0；else 1。"""
    links = getattr(self, "p4_links", {})
    main = links.get(e.s32(0x1C) & 0x7FFFFFFF)
    if main is None:
        return False
    t2 = main.g16(0x20)
    t2s = t2 - 0x10000 if t2 & 0x8000 else t2
    st = main.s32(0x1C) - 1
    x = e.s32(0x04)
    y = e.s32(0x08)
    if st <= 0xB:
        if st == 0:
            if t2s >= 0 and (t2 & 0x1F) == 0:
                flip = (((~t2 >> 5) & 1) ^ (1 if e.s32(0x24) < 0 else 0))
                sy = self.p4_player_y() + (0x18 if flip else -0x18)   # 0x40FED7
                self.p4_43B360(e, self.p4_player_x(), sy, 0x300)
        elif st == 1:
            if t2s == 0 and e.s32(0x24) < 0:
                e.d32(0x28, 0)
                self._p4_ent43c(0x23000017, x, y, (id(main) & 0x7FFFFFFF, 0))
        elif st == 3:
            if t2s >= 0x28 and (t2 & 3) == 0:
                self.p4_43B070(e, ((t2s - 0xA0) << 4) & 0xFFFFFFFF)
        elif st == 4:
            if t2s == 0 and e.s32(0x24) > 0:
                e.d32(0x28, 0)
                self._p4_ent43c(0x23000017, x, y,
                                (id(main) & 0x7FFFFFFF, 0x10000))
        elif st in (5, 10):
            v24 = e.s32(0x24)
            if v24 < 0:
                if (t2 & (0x3F if st == 5 else 0xF)) == (0x30 if st == 5 else 4):
                    self._p4_ent43c(0x23000019, x, y, -0x48)
            elif v24 > 0:
                if (t2 & (0x3F if st == 5 else 0xF)) == (0x10 if st == 5 else 0xB):
                    self._p4_ent43c(0x23000019, x, y, 0x48)
            # 0x23000019 的 prm=±0x48 由 ctor 键控（此处仅铺件）
        elif st == 6:
            self.spawn(self._p4_q("ui4cc"), 0x41000001, x, y, 0)
            for _ in range(5):
                jx = (self.p4_rand() & 0x1F) - 0xF
                jy = (self.p4_rand() & 0x1F) - 0xF
                self.spawn(self._p4_q("ui4cc"), 0x41000004,
                           x + jx, y + jy, (jx, jy))
            return False
        elif st == 8:
            if t2s >= 0 and (t2 & 0xF) == 0:
                self.p4_43B360(e, self.p4_player_x() + (self.p4_rand() & 0x3F) - 0x20,
                               self.p4_player_y() + (self.p4_rand() & 0x3F) - 0x20, 0)
        elif st in (9, 11):
            if t2s == 0:
                e.d32(0x28, 0)
                self._p4_ent43c(0x23000017, x, y,
                                (id(main) & 0x7FFFFFFF,
                                 0x10000 if e.s32(0x24) >= 0 else 0))
    v20 = e.s32(0x20)
    v24 = e.s32(0x24)
    x = (main.s32(0x04) + v20) & 0xFFFFFFFF
    y = (main.s32(0x08) + v24) & 0xFFFFFFFF
    e.d32(0x04, x)
    e.d32(0x08, y)
    if e.node is not None:
        e.node.dst = (x - 0x18, y - 0x18)
    if e.s32(0x2C) == 0:
        e.d32(0x18, -1 & 0xFFFFFFFF)
    if main.m[0x34] != 0 and e.g32(0x18) != 0:
        return True
    return False


def _beh_410470(self, e) -> bool:
    """`0x410470`（thunk 0x401951；0x23000017）：**自旋僚机（摆入轨道）**。

    [0x20] 低 16 位 = 摆相位 t；word[0x24] = 帧数（0x6E/0x136 门）；
    word[0x26] = 摆幅（+4 至 (3t+3)<<3 封顶、t≥0x136 或 [0x2C]≥0x10 后 −8 衰减）；
    [0x28] = 目标角（==0x82..0x168 段：无父 → ±4 折返、有父 → 向主.[0x28] 收敛）；
    HP==−1 穿门 → [0x2C]++（受击计数）；有父 → 主.[0x2C] += [0x2C]、[0x2C]=0、
    [0x30] = 主.[0x30]（打包位拷贝）；无父 → [0x30] = (主y<<0x10)|(主x&0xFFFF)。
    x = cos(10*角)*摆幅>>8 + word[0x30] 低 16 位；y = sin(10*角)*摆幅>>8
    （[0x20] 高 16 位非 0 则取反）+ word[0x32]；node dst=(x−0x18,y−0x18)。
    主死 → 0x41000001 + 0x41000004 ×4 @(x,y) 入 0x4AD4CC、return 0；
    否则 word[0x24]++；return t+帧 < 0x168。"""
    links = getattr(self, "p4_links", {})
    main = links.get(e.s32(0x1C) & 0x7FFFFFFF)
    if main is None:
        return False
    t = e.s32(0x20) & 0xFFFF
    if main.g16(0x24) == 0 and t < 0xF:
        self._p4_ent43c(0x23000017, main.s32(0x04), main.s32(0x08),
                        (id(main) & 0x7FFFFFFF, (t + 1) & 0xFFFFFFFF))
    if main.g16(0x24) < 0x6E:
        w26 = main.g16(0x26)
        if (w26 - 0x10000 if w26 & 0x8000 else w26) < ((3 * t + 3) << 3):
            main.d16(0x26, (w26 + 4) & 0xFFFF)
    if main.g16(0x24) >= 0x136 or e.s32(0x2C) >= 0x10:
        w26 = main.g16(0x26)
        if (w26 - 0x10000 if w26 & 0x8000 else w26) > 0:
            main.d16(0x26, (w26 - 8) & 0xFFFF)
    w24 = main.g16(0x24)
    if 0x82 <= w24 < 0x168:
        if t == 0:
            v = main.s32(0x28)
            v = (v + (4 if w24 >= 0xDC else -4)) & 0xFFFFFFFF
            main.d32(0x28, v)
        else:
            v = main.s32(0x28)
            main.d32(0x28, (v + ((main.s32(0x28) - v + 2) >> 2)) & 0xFFFFFFFF)
    if e.g32(0x18) != 0xFFFFFFFF:
        e.d32(0x18, -1 & 0xFFFFFFFF)
        e.d32(0x2C, (e.s32(0x2C) + 1) & 0xFFFFFFFF)
    if t != 0:
        main.d32(0x2C, (main.s32(0x2C) + e.s32(0x2C)) & 0xFFFFFFFF)
        e.d32(0x2C, 0)
        if main.s32(0x2C) >= 0x10:
            e.d32(0x2C, 0x10)
        e.d32(0x30, main.g32(0x30) & 0xFFFFFFFF)
    else:
        px = main.s32(0x04) & 0xFFFF
        py = main.s32(0x08) & 0xFFFF
        e.d32(0x30, ((py << 0x10) | px) & 0xFFFFFFFF)
    ang = (10 * e.s32(0x28)) & 0xFFFFFFFF
    c = page4_cos(ang)
    s_ = page4_sin(ang)
    amp = main.g16(0x26)
    amp_s = amp - 0x10000 if amp & 0x8000 else amp
    w30 = e.g32(0x30)
    bx = w30 & 0xFFFF
    bx = bx - 0x10000 if bx & 0x8000 else bx           # movsx word[+0x30]
    by = (w30 >> 0x10) & 0xFFFF
    by = by - 0x10000 if by & 0x8000 else by           # movsx word[+0x32]
    x = (((c * amp_s) >> 8) + bx) & 0xFFFFFFFF
    y = (((s_ * amp_s) >> 8) + by) & 0xFFFFFFFF
    if e.s32(0x20) & 0xFFFF0000:
        y = (-(((s_ * amp_s) >> 8)) + by) & 0xFFFFFFFF
    e.d32(0x04, x)
    e.d32(0x08, y)
    if e.node is not None:
        e.node.dst = (x - 0x18, y - 0x18)
    if main.m[0x34] == 0:
        self.spawn(self._p4_q("ui4cc"), 0x41000001, x, y, 0)
        for _ in range(4):
            jx = (self.p4_rand() & 0x1F) - 0xF
            jy = (self.p4_rand() & 0x1F) - 0xF
            self.spawn(self._p4_q("ui4cc"), 0x41000004,
                       x + jx, y + jy, (jx, jy))
        return False
    main.d16(0x24, (main.g16(0x24) + 1) & 0xFFFF)
    return (w24 + t) < 0x168


def _beh_4108C0(self, e) -> bool:
    """`0x4108C0`（thunk 0x40242D；0x23000019）：**投放炸弹（0xC000 键门）**。

    0x45AFC0(0x4AB5B0, 0xC000)+1 ≠ HP([0x18]) → return 0（键状态门）。
    t=++[0x1C]：0x3C<t≤0x82 → [0x24] = −min(2|t−0x5F|, 0x40)（上抛减速）；
    t>0xAA → [0x24] = min([0x24]+2, 0x60)（下落加速）；
    0x3C<t≤0x82 → [0x28] = (|t−0x5F|−0x23)*[0x20]*2；
    0xAA<t≤0xF0 → [0x28] = (0x23−|t−0xCD|)*[0x20]*2。
    [0x2C] += [0x24]、[0x30] += [0x28]；x=[0x2C]>>4、y=[0x30]>>4；
    node dst=(x−0x18,y−0x18)；return x < 0x298 且 HP≠0。"""
    key = (self.keys.field(0xC000) & 3) + 1           # 0x45AFC0+1
    if e.g32(0x18) != key:
        return False
    t = (e.s32(0x1C) + 1) & 0xFFFFFFFF
    e.d32(0x1C, t)
    v = e.s32(0x20)
    if 0x3C < t <= 0x82:
        d = abs(t - 0x5F) * 2
        if d > 0x40:
            d = 0x40
        e.d32(0x24, (-d) & 0xFFFFFFFF)
    if t > 0xAA:
        v24 = min(e.s32(0x24) + 2, 0x60)
        e.d32(0x24, v24)
    if 0x3C < t <= 0x82:
        e.d32(0x28, (((abs(t - 0x5F) - 0x23) * v) << 1) & 0xFFFFFFFF)
    elif 0xAA < t <= 0xF0:
        e.d32(0x28, (((0x23 - abs(t - 0xCD)) * v) << 1) & 0xFFFFFFFF)
    e.d32(0x2C, (e.s32(0x2C) + e.s32(0x24)) & 0xFFFFFFFF)
    e.d32(0x30, (e.s32(0x30) + e.s32(0x28)) & 0xFFFFFFFF)
    a2c = e.s32(0x2C)
    a30 = e.s32(0x30)
    x = (a2c - 0x100000000 if a2c & 0x80000000 else a2c) >> 4
    y = (a30 - 0x100000000 if a30 & 0x80000000 else a30) >> 4
    e.d32(0x04, x & 0xFFFFFFFF)
    e.d32(0x08, y & 0xFFFFFFFF)
    if e.node is not None:
        e.node.dst = (x - 0x18, y - 0x18)
    return x < 0x298 and e.g32(0x18) != 0


def _beh_40F880(self, e) -> bool:
    """`0x40F880`（thunk 0x4017EE；0x23000015 王 **十三态**，2026-11-14 按跳表
    0x40FBDC 重核：13 态只有 8 个 handler——0/1→0x40F8CA、2/10→0x40F98B、
    3/6/11→0x40F99D、4/12→0x40F9B1、5→0x40FA6B、7→0x40FA82、8→0x40FAAA、
    9→0x40FB09；共享体 `[0x1C]=ecx=态+1` 推进。

    头：x>0x188 → word[0x2C]-- 否则 ++；y>0xF0 → word[0x2E]-- 否则 ++（双向漂移）。
    态 0/1（0x40F8CA）：word[0x2C]=−0x40（x 速 −4）；wt==0 → 従 0x23000016 ×2
    @ (−0x18,0) prm rand&0x100 / sete(rand&0x100==0)；x==0x168 → [0x2C]=0xFFD00000
    （x 速 0 / y 速 −0x30）、**[0x1C]=0xC**（neg/sbb/and 0xB/inc，eax=y≠0 ⇒ 恒 0xC）。
    态 2/10：wt==0xF0 → 态+1。态 3/6/11：wt==0x16A → 态+1。
    态 4/12：wt<0 跳过；wt==0 → 0x23000018 @(−0x18,−0x18) + [0x30]=[0x2C]；
    wt<0x5A → [0x2C]=0xFFE00000；<0xB4 → 0x400020；<0x10E → 0xFFE0FFE0；
    否则 [0x2C]=[0x30] 且 [0x1C]==3 → 4，否则 word[0x22]++ →（neg/sbb/and 0xFD/+0xC）
    w22<6 → 0xC、≥6 → 0x109（跳表外 = 尾部怠速漂移）。
    态 5：wt==0x50 → 态+1。态 7（死亡演出）：wt==0x78 → 0x23000019 @ 自机、return 0；
    否则 0x23000019 ×2（wt/0x48）。
    态 8：wt==0x5A → 态+1。态 9：wt==0x16A → return 0；wt>0x78 → word[0x2C]=0x78−wt。

    尾 0x40FB3E：**wt 重置只在态变化时**（0x40FB46 cmp ebx,eax / je）——新态<7 →
    −(rand&0x3F)（0x40FB4E）、新态≥7 → 0（0x40FB5E）；态未变 → wt++（0x40FB66，
    负延迟计数穿过 0 到达各态阈值 0xF0/0x16A/…触发推进）。
    HP==0 且 态≠7 → 态=7、wt=0、HP=−1、[0x10]=0（0x40FB6A..0x40FB87）。
    x = ([0x24]+word[0x2C]+8)>>4、y = ([0x28]+word[0x2E]+8)>>4（8.4 定点）；
    node dst=(x−0x48, y−0x48)；return 1。"""
    x0 = e.s32(0x04)
    y0 = e.s32(0x08)
    w2c = e.g16(0x2C)
    w2e = e.g16(0x2E)
    if x0 > 0x188:
        e.d16(0x2C, (w2c - 1) & 0xFFFF)
    else:
        e.d16(0x2C, (w2c + 1) & 0xFFFF)
    if y0 > 0xF0:
        e.d16(0x2E, (w2e - 1) & 0xFFFF)
    else:
        e.d16(0x2E, (w2e + 1) & 0xFFFF)
    st = e.s32(0x1C)
    st_old = st
    wt = e.g16(0x20)
    wts = wt - 0x10000 if wt & 0x8000 else wt
    if st <= 0xC:
        # 0x40F8C3 `jmp [ecx*4+0x40FBDC]`，ecx=state+1；表 0x40FBDC =
        # F8CA,F98B,F99D,F9B1,FA6B,F99D,FA82,FAAA,FB09,F98B,F99D,F9B1,FB19
        # ⇒ 态0→F8CA；1/9→F98B；2/5/10→F99D；3/11→F9B1；4→FA6B；6→FA82；
        #   7→FAAA；8→FB09；12→FB19（旧实现按 sub=st+1 分组，整体错位一格）。
        if st == 0:                                # 0x40F8CA
            e.d16(0x2C, -0x40 & 0xFFFF)            # word[0x2C] = −0x40
            if wt == 0:                            # 0x40F8D1
                r = self.p4_rand() & 0x100
                self._p4_ent43c(0x23000016, -0x18, 0)
                self._p4_ent43c(0x23000016, -0x18, 0, (-1 if r else 1))
            if x0 == 0x168:                        # 0x40F967
                e.d32(0x2C, 0xFFD00000)
                e.d32(0x1C, 1)                     # 0x40F97F：态0→1，其它→0xC
        elif st in (1, 9):                         # 0x40F98B
            if wts == 0xF0:
                e.d32(0x1C, st + 1)
        elif st in (2, 5, 10):                     # 0x40F99D
            if wts == 0x16A:
                e.d32(0x1C, st + 1)
        elif st in (3, 11):                        # 0x40F9B1
            if wts < 0:
                pass
            elif wts == 0:
                self._p4_ent43c(0x23000018, -0x18, -0x18)
                e.d32(0x30, e.g32(0x2C) & 0xFFFFFFFF)
            if wts < 0x5A:
                e.d32(0x2C, 0xFFE00000)
            elif wts < 0xB4:
                e.d32(0x2C, 0x400020)
            elif wts < 0x10E:
                e.d32(0x2C, 0xFFE0FFE0)
            if st == 3:
                e.d32(0x1C, 4)
            else:
                w22 = (e.g16(0x22) + 1) & 0xFFFF
                e.d16(0x22, w22)
                e.d32(0x1C, 0xC if (w22 - 6) == 0 else 0x109)  # 0x40FA51 neg/sbb/and 0xFD/add 0xC
        elif st == 4:                              # 0x40FA6B
            if wts == 0x50:
                e.d32(0x1C, 5)
        elif st == 6:                              # 0x40FA82 死亡演出
            if wt == 0x78:
                self.spawn(self._p4_q("ui4cc"), 0x23000019, x0, y0, 0x40)
                return False
            self.spawn(self._p4_q("ui4cc"), 0x23000019, x0, wt, 0x48)
            self.spawn(self._p4_q("ui4cc"), 0x23000019, x0, wt, 0)
        elif st == 7:                              # 0x40FAAA
            if wts == 0x5A:
                e.d32(0x1C, 8)
        elif st == 8:                              # 0x40FB09
            if e.g16(0x20) == 0x5A:
                e.d32(0x1C, 9)
        elif st == 12:                             # 0x40FB19
            if e.g16(0x20) == 0x16A:
                return False
            if wts > 0x78:
                e.d16(0x2C, (0x78 - wts) & 0xFFFF)
    # 0x40FB3E 尾：wt 重置只发生在**态变化**时（0x40FB46 cmp ebx,eax / je）——
    # 新态<7 → −(rand&0x3F) 延迟（0x40FB4E）、新态≥7 → 0（0x40FB5E）；
    # 态未变 → wt++（0x40FB66 inc，负延迟计数穿过 0 到达各态阈值 0xF0/0x16A/…）。
    # 旧实现每帧重随机 ⇒ wt 恒为负 ⇒ 阈值永不命中 ⇒ Boss 卡在入场态走出左缘
    # （2026-11-14 修，用户实测"没看见 boss"）。
    st_new = e.s32(0x1C)
    if st_new != st_old:
        if st_new < 7:                             # 0x40FB4A cmp eax,7 / jge
            e.d16(0x20, (-(self.p4_rand() & 0x3F)) & 0xFFFF)   # 0x40FB4E
        else:
            e.d16(0x20, 0)                         # 0x40FB5E
    else:                                          # 0x40FB66 态未变 → wt++
        e.d16(0x20, (wt + 1) & 0xFFFF)
    if e.g32(0x18) == 0 and st_new != 7:           # 0x40FB6A HP==0 且 态≠7
        e.d32(0x1C, 7)                             # 0x40FB76
        e.d32(0x20, 0)                             # 0x40FB79
        e.d32(0x18, 0xFFFFFFFF)                    # 0x40FB80
        e.m[0x10] = 0                              # 0x40FB87
    w2c = e.g16(0x2C)
    w2e = e.g16(0x2E)
    w2cs = w2c - 0x10000 if w2c & 0x8000 else w2c
    w2es = w2e - 0x10000 if w2e & 0x8000 else w2e
    a24 = (e.s32(0x24) + w2cs) & 0xFFFFFFFF
    a28 = (e.s32(0x28) + w2es) & 0xFFFFFFFF
    e.d32(0x24, a24)
    e.d32(0x28, a28)
    x = ((a24 + 8) >> 4) & 0xFFFFFFFF
    y = ((a28 + 8) >> 4) & 0xFFFFFFFF
    e.d32(0x04, x)
    e.d32(0x08, y)
    if e.node is not None:
        e.node.dst = (x - 0x48, y - 0x48)
    return True


def _beh_4114C0(self, e) -> bool:
    """`0x4114C0`（0x24000009）：t=++[0x1C]；t==0xA 且 [0x20]≠0 →
    0x24000009 @(80*(v−1)+0x50? 字面 ((v−1)&7+2)*80, −0x18) prm=−0x18 入 0x4AD43C、
    [0x10]=1；x += t>>3、y −= t>>4；node dst=(x−0x18,y−0x18)；
    return y < 0x1F8 且 HP≠0。"""
    t = (e.s32(0x1C) + 1) & 0xFFFFFFFF
    e.d32(0x1C, t)
    if t == 0xA and e.s32(0x20) != 0:
        v = e.s32(0x20)
        xx = (((v - 1) & 7) + 2) * 80
        self._p4_ent43c(0x24000009, xx, -0x18)
        e.m[0x10] = 1
    x = (e.s32(0x04) - (t >> 4)) & 0xFFFFFFFF     # 0x411530/535：x -= t>>4
    y = (e.s32(0x08) + (t >> 3)) & 0xFFFFFFFF     # 0x41152D/533：y += t>>3
    e.d32(0x04, x)
    e.d32(0x08, y)
    if e.node is not None:
        e.node.dst = (x - 0x18, y - 0x18)
    return y < 0x1F8 and e.g32(0x18) != 0


def _beh_411790(self, e) -> bool:
    """`0x411790`（0x2400000C）：t=[0x1C]−−；t==0 → [0x10]=1、[0x24]≠0 时
    铺 0x2400000C @(rand%0xF0+0x1F8, rand%0x1E0+0x140) prm=[0x24]−1 入 0x4AD43C；
    [0x20]≠0 → +1 else −1；[0x20] += [0x2C]?…（neg/sbb → ([0x20]==0)?−1:0）；
    x −= 4；y −= [0x20]>>1（无符号语义 y += (~[0x20]>>?)）—— 字面：
    ecx = ([0x20]==0) ? −1 : 0；eax = [0x20] + ecx；[0x20] = eax；y −= eax>>1；
    node dst=(x−0x18,y−0x18)；return HP≠0 且 x>−0x18（尾未全读，按 0x411847 后
    标准 cmp jge -0x18 处理）。"""
    t = (e.s32(0x1C) - 1) & 0xFFFFFFFF
    e.d32(0x1C, t)
    if t == 0:
        e.m[0x10] = 1
        if e.s32(0x24) != 0:
            rx = self.p4_rand() % 0x1E0 + 0x140   # 0x4117E9/0x4117F4：x
            ry = self.p4_rand() % 0xF0 + 0x1F8    # 0x4117DD/0x4117EF：y
            self._p4_ent43c(0x2400000C, rx, ry, e.s32(0x24) - 1)
    v = e.s32(0x20)
    v = (v + (-1 if v != 0 else 0)) & 0xFFFFFFFF
    e.d32(0x20, v)
    x = (e.s32(0x04) - 4) & 0xFFFFFFFF
    y = (e.s32(0x08) - (v >> 1)) & 0xFFFFFFFF
    e.d32(0x04, x)
    e.d32(0x08, y)
    if e.node is not None:
        e.node.dst = (x - 0x18, y - 0x18)
    return e.g32(0x18) != 0 and x > -0x18


def _beh_411A00(self, e) -> bool:
    """`0x411A00`（0x2400000F）：t=++[0x1C]；(t&0x38)==0 → 0x43B070(e,
    [0x58]−(t&7)<<8)（表速阶梯）；x<[0x56CC8C] → [0x28]++、y>[0x56CC90] →
    [0x2C]−−（追踪门）；[0x20]+=[0x28]、[0x24]+=[0x2C]；x=[0x20]>>3、y=[0x24]>>3；
    node dst=(x−0x18,y−0x18)；return y>−0x18 且 HP≠0。"""
    t = (e.s32(0x1C) + 1) & 0xFFFFFFFF
    e.d32(0x1C, t)
    if (t & 0x38) == 0:
        self.p4_43B070(e, (e.s32(0x58) - ((t & 7) << 8)) & 0xFFFFFFFF)
    if e.s32(0x04) < self.p4_player_x():
        e.d32(0x28, (e.s32(0x28) + 1) & 0xFFFFFFFF)
    if e.s32(0x08) > self.p4_player_y():
        e.d32(0x2C, (e.s32(0x2C) - 1) & 0xFFFFFFFF)
    e.d32(0x20, (e.s32(0x20) + e.s32(0x28)) & 0xFFFFFFFF)
    e.d32(0x24, (e.s32(0x24) + e.s32(0x2C)) & 0xFFFFFFFF)
    x = (e.s32(0x20) - 0x100000000 if e.s32(0x20) & 0x80000000 else e.s32(0x20)) >> 3
    y = (e.s32(0x24) - 0x100000000 if e.s32(0x24) & 0x80000000 else e.s32(0x24)) >> 3
    e.d32(0x04, x & 0xFFFFFFFF)
    e.d32(0x08, y & 0xFFFFFFFF)
    if e.node is not None:
        e.node.dst = (x - 0x18, y - 0x18)
    return y > -0x18 and e.g32(0x18) != 0


def _beh_414E40(self, e) -> bool:
    """`0x414E40`（0x26000009）：**漂移→锁定→连射→重定位**。

    t2=++[0x24]：
      t2<0x3C：漂移 [4]+=[0x1C]、[8]+=[0x20]（0x45A6B0 node 同步）；
      t2==0x3C → [0x1C]=自机x、[0x20]=自机y（锁定）；
      0x3C<t2<0x78：(t2&3)==3 → 0x43B360(e, [0x1C], [0x20], 0)（对锁定点）；
      t2≥0x78：[0x28]−−==0 → [0x1C]=−0xB；否则 rand 目标：
        [0x1C] = rand%0x280 − x、[0x20] = rand%0x1E0 − y（0x462D71 取余）、
        [0x24]=0（重入漂移）。
    (t2&3)==3 → 0x414010；node dst=(x−0x18,y−0x18)；return x>−0x18 且 HP≠0。"""
    t2 = (e.s32(0x24) + 1) & 0xFFFFFFFF
    e.d32(0x24, t2)
    if t2 < 0x3C:
        dx = e.s32(0x1C)
        dy = e.s32(0x20)
        e.d32(0x04, (e.s32(0x04) + dx) & 0xFFFFFFFF)
        e.d32(0x08, (e.s32(0x08) + dy) & 0xFFFFFFFF)
        if e.node is not None:                       # 0x45A6B0
            e.node.dst = (e.node.dst[0] + dx, e.node.dst[1] + dy)
    elif t2 == 0x3C:
        e.d32(0x1C, self.p4_player_x() & 0xFFFFFFFF)
        e.d32(0x20, self.p4_player_y() & 0xFFFFFFFF)
    elif t2 < 0x78:
        if (t2 & 3) == 3:
            self.p4_43B360(e, e.s32(0x1C), e.s32(0x20), 0)
    else:
        v = (e.s32(0x28) - 1) & 0xFFFFFFFF
        e.d32(0x28, v)
        if v == 0:
            e.d32(0x1C, -0xB & 0xFFFFFFFF)
        else:
            e.d32(0x1C, _idiv_trunc(self.p4_rand() % 0x280 - e.s32(0x04), 0x3C) & 0xFFFFFFFF)
            e.d32(0x20, _idiv_trunc(self.p4_rand() % 0x1E0 - e.s32(0x08), 0x3C) & 0xFFFFFFFF)
            e.d32(0x24, 0)
    if (t2 & 3) == 3:
        self.p4_414010(e)
    if e.node is not None:
        e.node.dst = (e.s32(0x04) - 0x18, e.s32(0x08) - 0x18)
    return e.s32(0x04) > -0x18 and e.g32(0x18) != 0


def _beh_4158A0(self, e) -> bool:
    """`0x4158A0`（0x26000010 前身段，与 0x415980 区分）：**直进+近机开火**。

    x += [0x20]、y += [0x24]；x < 自机x+0x48 且 [0x20]==0 → [0x20]=3、
    [0x24] = (y≥自机y ? +4 : −4)（and 8/add −4）、0x43B070(e,0)；
    (t&3)==3 → 0x414010；node dst=(x−0x18,y−0x18)；0x4305F0(e,0x18)；
    return 在屏 且 HP≠0。"""
    t = (e.s32(0x1C) + 1) & 0xFFFFFFFF
    e.d32(0x1C, t)
    x = (e.s32(0x04) + e.s32(0x20)) & 0xFFFFFFFF
    y = (e.s32(0x08) + e.s32(0x24)) & 0xFFFFFFFF
    e.d32(0x04, x)
    e.d32(0x08, y)
    if x < self.p4_player_x() + 0x48 and e.s32(0x24) == 0:   # 0x4158D0 门是 vy
        e.d32(0x20, 3)
        e.d32(0x24, (-4 if y >= self.p4_player_y() else 4) & 0xFFFFFFFF)
        self.p4_43B070(e, 0)
    if (t & 3) == 3:
        self.p4_414010(e)
    if e.node is not None:
        e.node.dst = (x - 0x18, y - 0x18)
    return self.p4_4305f0(e, 0x18) and e.g32(0x18) != 0


def _beh_415BB0(self, e) -> bool:
    """`0x415BB0`（0x26000014）：**锯齿横移 + y==0xF0 扇形**。

    t=++[0x1C]：t&8==0 → step = (t&0x20 ? +1 : −1)；else step = (t&0x20 ? −1 : +1)
    （0x415BC1/0x415BCC 两分支）；[0x20] += step；x += [0x20]；y += 2；
    0x45A6B0(node+0x14, [0x20], 2) 同步。
    y==0xF0：17 连扇形 0x43B290（esi −0xC0..+0xC0? 字面 ebx=0xFFFFFF40 起、
    esi += 0xD4、ebx −= 0x100 循环：ang=esi、spd=esi? —— 字面：
    (cos(esi), sin(esi), 0) 且 esi 从 [esp+0x10] 起 +0xD4 ×17、
    初值 ebx=−0xC0 作 cos 位）。
    (t&1)==0 → 0x414010；return y<0x1F8 且 HP≠0（尾 cmp jge 0x1F8）。"""
    t = (e.s32(0x1C) + 1) & 0xFFFFFFFF
    e.d32(0x1C, t)
    if (t & 8) == 0:                            # 0x415BC3：t&0x20 ⇒ -1
        step = -1 if (t & 0x20) else 1
    else:                                       # 0x415BD2：t&0x20 ⇒ +1
        step = 1 if (t & 0x20) else -1
    v = (e.s32(0x20) + step) & 0xFFFFFFFF
    e.d32(0x20, v)
    x = (e.s32(0x04) + v) & 0xFFFFFFFF
    y = (e.s32(0x08) + 2) & 0xFFFFFFFF
    e.d32(0x04, x)
    e.d32(0x08, y)
    if e.node is not None:                          # 0x45A6B0(node+0x14, v, 2)
        e.node.dst = (e.node.dst[0] + v, e.node.dst[1] + 2)
    if y == 0xF0:                               # 0x415C10：4 档速度 × 17 发
        spd = -0xC0
        off = 0
        while spd >= -0x3C0:
            ang = off
            for _ in range(0x11):
                self.p4_43B290(e, page4_cos(ang & 0xFFFFFFFF),
                               page4_sin(ang & 0xFFFFFFFF), spd & 0xFFFFFFFF)
                ang += 0xD4
            off += 0x6A
            spd -= 0x100
    if (t & 1) == 1:                            # 0x415C6A and 1/cmp 1
        self.p4_414010(e)
    return y < 0x1F8 and e.g32(0x18) != 0


def _beh_416CF0(self, e) -> bool:
    """`0x416CF0`（0x2700000A）：**双圆轨摆动 + 计时爆散**。

    [0x24] += [0x30]（相位累积）；t=++[0x1C]；
    [0x28] += (90*sin(30*[0x24]))>>8、[0x2C] += (90*cos(30*[0x24]))>>8；
    (t+0x1E)%0x5A==0 → [0x30]=2；t%0x5A==0 → [0x30]=1；
    x=[0x28]>>4、y=[0x2C]>>4。
    HP==0 → 0x45A790(node+4, 0x30, 0, 0x30, 0)、[0x24]−−、HP=−1、[0x10]=1；
    HP>0x32 → HP=−1；链体（esi=[0x38]? 实为 [esi+0x24] 门）死或 HP==0 →
    0x41000001 + 0x41000004 ×4（±rand&0x1F−0xF）@(x,y) 入 0x4AD4CC、return 0。
    node dst 同步；return 1。"""
    e.d32(0x24, (e.s32(0x24) + e.s32(0x30)) & 0xFFFFFFFF)
    t = (e.s32(0x1C) + 1) & 0xFFFFFFFF
    e.d32(0x1C, t)
    a = (30 * e.s32(0x24)) & 0xFFFFFFFF
    s_ = page4_sin(a)
    c = page4_cos(a)
    e.d32(0x28, (e.s32(0x28) + ((90 * s_) >> 8)) & 0xFFFFFFFF)
    e.d32(0x2C, (e.s32(0x2C) + ((90 * c) >> 8)) & 0xFFFFFFFF)
    if (t + 0x1E) % 0x5A == 0:
        e.d32(0x30, 2)
    elif t % 0x5A == 0:
        e.d32(0x30, 1)
    x = (e.s32(0x28) >> 4) & 0xFFFFFFFF
    y = (e.s32(0x2C) >> 4) & 0xFFFFFFFF
    e.d32(0x04, x)
    e.d32(0x08, y)
    hp = e.g32(0x18)
    if hp == 0:
        nd = e.node
        if nd is not None:                    # 0x45A790(node+4, 0x30, 0, 0x30, 0)
            nd.rect = (nd.rect[0] + 0x30, nd.rect[1], nd.rect[2] + 0x30, nd.rect[3])
        e.d32(0x24, (e.s32(0x24) - 1) & 0xFFFFFFFF)
        e.d32(0x18, -1 & 0xFFFFFFFF)
        e.m[0x10] = 1
    elif hp > 0x32:
        e.d32(0x18, -1 & 0xFFFFFFFF)
    if e.m[0x34] == 0 or e.g32(0x18) == 0:
        self.spawn(self._p4_q("ui4cc"), 0x41000001, x, y, 0)
        for _ in range(4):
            jx = (self.p4_rand() & 0x1F) - 0xF
            jy = (self.p4_rand() & 0x1F) - 0xF
            self.spawn(self._p4_q("ui4cc"), 0x41000004,
                       x + jx, y + jy, (jx, jy))
        return False
    return True


def _beh_412B60(self, e) -> bool:
    """`0x412B60`（0x25000008，**关5 boss 十三态** 0x412EF4）。

    公共（0x412BE9/0x412C19/0x412C31/0x412E94）：态≠旧态 → [0x20]=0；
    HP==0 → 态=0xC、HP=−1、[0x10]=0；态<0xA 且（HP≥0x4B0 或 [0x30]&0xFF0000
    !=0x7F0000）→ 态=0xA、[0x20]=0；
    word[0x28] += word[0x2A]；word[0x2A] += (y<0xF0 且 word[0x28]<0x60 ? +1 : 0)
    （下坠加速）；y = 0xF0 + word[0x2A]>>6；node dst=(x−0x48, y−0x48)；return 1。
    态表：0：0x40203B(0x4AA7B0, −8*[0x20], 0)（音量滑落）；[0x20]==0x20 → 态=1、
      node.active=1；1：0x40203B(−0x100+4t)；0x40 → 态=2、[0x10]=1；
      2：[0x20]≥0 → t=[0x2C]（圈）%7；[0x2C]≥0x1C → 态=0xA、[0x2C]++；
        否则 7 连铺 0x2500000A @(0x2BC, y) prm={主, rand&0x100, 圈位}
        （[0x30]&1<<(i+0x10) 已占则跳过）入 0x4AD43C、[0x2C]++；
      3..9：[0x20]==表值 {0x172,0x12C,0x280,0x1E0,0x1E0,0x190,0x186}[i−3] → 态=2；
      0xA：0x40203B(−2t)；0x40 → 态=0xB；
      0xB：(t&7)==0 且 t&0x180 → 0x43B360(e, 自机x+(rand%0x100)−0x80,
        自机y+(rand%0x200)−0x100, 0)；t==0x708 → HP=0；
      0xC：t==0 → 0x61000004 @(x,y,0x40) 入 52C；0x40203B(2t−0x80)；
        0x40 → return 0（终）。"""
    st = e.s32(0x1C)
    st_old = st
    t = e.s32(0x20)
    x = e.s32(0x04)
    y = e.s32(0x08)
    limits = (0x172, 0x12C, 0x280, 0x1E0, 0x1E0, 0x190, 0x186)
    if st <= 0xC:
        if st == 0:
            self.p4_40203b(0x4AA7B0, (-8 * t), 0)
            if t == 0x20:
                e.d32(0x1C, 1)
                if e.node is not None:
                    e.node.active = 1
        elif st == 1:
            self.p4_40203b(0x4AA7B0, (4 * t - 0x100), 0)
            if t == 0x40:
                e.d32(0x1C, 2)
                e.m[0x10] = 1
        elif st == 2:
            if t >= 0:
                ring = e.s32(0x2C) % 7
                if e.s32(0x2C) >= 0x1C:
                    e.d32(0x1C, 0xA)
                    e.d32(0x2C, (e.s32(0x2C) + 1) & 0xFFFFFFFF)
                else:
                    for i in range(7):
                        if e.g32(0x30) & (1 << (i + 0x10)):
                            continue
                        c = self._p4_ent43c(0x2500000A, 0x2BC, y)
                        c.d32(0x18, id(e) & 0x7FFFFFFF)
                        c.d32(0x1C, (self.p4_rand() & 0x100))
                        c.d32(0x20, i + ring * 0 + ring)
                    e.d32(0x2C, (e.s32(0x2C) + 1) & 0xFFFFFFFF)
        elif 3 <= st <= 9:
            if t == limits[st - 3]:
                e.d32(0x1C, 2)
        elif st == 0xA:
            self.p4_40203b(0x4AA7B0, (-2 * t), 0)
            if t == 0x40:
                e.d32(0x1C, 0xB)
        elif st == 0xB:
            if (t & 7) == 0 and (t & 0x180):
                self.p4_43B360(e,
                               self.p4_player_x() + (self.p4_rand() % 0x100) - 0x80,
                               self.p4_player_y() + (self.p4_rand() % 0x200) - 0x100, 0)
            if t == 0x708:
                e.d32(0x18, 0)
        elif st == 0xC:
            if t == 0:
                self.p4_spawn52c_flash(x, y, 0x61000004, 0x40)
            self.p4_40203b(0x4AA7B0, (2 * t - 0x80), 0)
            if t == 0x40:
                return False
    if st != st_old:
        e.d32(0x20, 0)
    if e.g32(0x18) == 0:
        e.d32(0x1C, 0xC)
        e.d32(0x18, -1 & 0xFFFFFFFF)
        e.m[0x10] = 0
    if st < 0xA and (e.g32(0x18) >= 0x4B0 or
                     (e.g32(0x30) & 0xFF0000) != 0x7F0000):
        e.d32(0x1C, 0xA)
        e.d32(0x20, 0)
    t = e.s32(0x20)
    if st == e.s32(0x1C):
        e.d32(0x20, (t + 1) & 0xFFFFFFFF)
    else:
        e.d32(0x20, 0)
    w28 = e.g16(0x28)
    w2a = e.g16(0x2A)
    w2a = (w2a + w28) & 0xFFFF
    e.d16(0x2A, w2a)
    w28s = w28 - 0x10000 if w28 & 0x8000 else w28
    if y < 0xF0 and w28s < 0x60:
        e.d16(0x2A, (w2a + 1) & 0xFFFF)
        w2a += 1
    w2as = w2a - 0x10000 if w2a & 0x8000 else w2a
    y = (0xF0 + (w2as >> 6)) & 0xFFFFFFFF
    e.d32(0x08, y)
    if e.node is not None:
        e.node.dst = (x - 0x48, y - 0x48)
    return True


def _beh_4130D0(self, e) -> bool:
    """`0x4130D0`（thunk 0x401186；0x25000009，0x412B60 铺出的七态僚机）。

    主 = [0x1C] 句柄；d = 主.[0x20] − 13*[0x20]（跟距）；hasprm = [0x24]≠0；
    ytarget = 0x78 + (hasprm ? 0x10 : 0)。
    d<0x1E → 吸附主（x = 主.x − 6*(0x1E−d)、y = 主.y − ytarget）；
    主.[0x1C]≤9 → 收尾直接判 HP。
    主死 → 0x41000001 + 0x41000004 ×5 入 0x4AD4CC、return 0。
    态 = 主.[0x1C]−3（>6 跳）：
      0：d≤0x96 → 0x401244（摆动）；d==0x96 → [0x2C]=1、[0x24]=y*4、
        [0x28] = (hasprm ? −0x40 : 0x20)；
        d>0x96 → [0x24] += [0x28]、[0x28] ±2 摆、x≥0x258 → x−=4？字面
        x += (x≥0x258 ? 4−8? : 4)（and 4/dec → (x≥0x258)?+3:−1... 字面 +4−8=−4/+4）；
        [0x2C]≠0 且 d>0xB6 → 距离门 0x43B610(0,0,−0x100)、[0x2C]=0；
        d==0x118 → 收尾
      1：d==0x78 → [0x24]=x*4、[0x28]=y*4、[0x2C]=0x45A9A0(Δ自机)、
        [0x30]=(t+0x12)*9；圆轨：[0x24] += cos([0x2C])*[0x30]>>8、
        [0x28] += sin([0x2C])*[0x30]>>8、[0x30]−=3；x=[0x24]>>2、y=[0x28]>>2
      2：d<0x1D6 → 0x401244 + sin 门 0x43B610(0,0,0x240)；d≥0x1D6 → x += 0xA
      3：d<0x159 → 0x401244；else x += 6；(d&0xF)==0 → 0x43B360
        (自机x+(rand%0x1E0), 自机y+(rand%0x280), 0x300)；d>0x190 → die
      4：同 3 但 (d&0x7F)==0 → 0x2500000B @(x,y, rand&0xFF) 入 0x4AD43C
      5：d<0xD2 → 0x401244；d==0xC8 → [0x24]=主.x*8、[0x28]=主.y*8、
        [0x2C]=0x45A9A0(Δ自机)；d>0xD2 → 圆轨（[0x30]=8−圈…ang=(8−t)*72）
        x += cos(ang)*…>>8；d>0x140 → die
      6：d<0xFF → 0x401244；d>0xD2 且 (d&0xF)==0 → ang=(8−d)*0x2C0?…
        0x43B360(自机x+(45*sin? ), 自机y+…)（0x401E56 朝机）
        d>0x136 → die
    尾：主.[0x30]&0xFFFF ≥0x4B0 → 主.[0x30] −= 0x4B0（打包位翻转）；
    HP==0 → 0x45A790(node+4, 0x30, 0x30, 0x30, 0x30) + [0x10]=1；
    node dst=(x−0x18,y−0x18)；return HP≠0 且 d ≤ 门限（按各态 jle）。"""
    links = getattr(self, "p4_links", {})
    main = links.get(e.s32(0x1C) & 0x7FFFFFFF)
    if main is None:
        return False
    v20 = e.s32(0x20)
    d = main.s32(0x20) - 13 * v20
    hasprm = 1 if e.s32(0x24) != 0 else 0
    ytarg = 0x78 + (0x10 if hasprm else 0)
    x = e.s32(0x04)
    y = e.s32(0x08)
    if d < 0x1E:
        x = (main.s32(0x04) - 6 * (0x1E - d)) & 0xFFFFFFFF
        y = (main.s32(0x08) - ytarg) & 0xFFFFFFFF
        e.d32(0x04, x)
        e.d32(0x08, y)
        if main.s32(0x1C) <= 9:
            return self._p4_4130d0_tail(e, main, d)
        self.spawn(self._p4_q("ui4cc"), 0x41000001, x, y, 0)
        for _ in range(5):
            jx = (self.p4_rand() & 0x1F) - 0xF
            jy = (self.p4_rand() & 0x1F) - 0xF
            self.spawn(self._p4_q("ui4cc"), 0x41000004, x + jx, y + jy, (jx, jy))
        return False
    if d < 0x78:
        self.p4_401244(e)
    st = main.s32(0x1C) - 3
    t = d
    if st <= 6:
        if st == 0:
            if t <= 0x96:
                self.p4_401244(e)
                if d == 0x96:
                    e.d32(0x2C, 1)
                    e.d32(0x24, (y << 2) & 0xFFFFFFFF)
                    e.d32(0x28, (-0x40 if hasprm else 0x20) & 0xFFFFFFFF)
            else:
                v28 = e.s32(0x28)
                e.d32(0x24, (e.s32(0x24) + v28) & 0xFFFFFFFF)
                e.d32(0x28, (v28 + (-2 if hasprm else 2)) & 0xFFFFFFFF)
                if x >= 0x258:
                    x = (x - 4) & 0xFFFFFFFF
                else:
                    x = (x + 4) & 0xFFFFFFFF
                e.d32(0x04, x)
                e.d32(0x08, (e.s32(0x24) >> 2) & 0xFFFFFFFF)
                if e.s32(0x2C) != 0 and t > 0xB6:
                    if not hasprm:
                        lim = (7 - v20) * 180
                        if e.s32(0x24) < lim:
                            self.p4_43B610(e, 0, 0, -0x100 & 0xFFFFFFFF)
                            e.d32(0x2C, 0)
                    else:
                        lim = (3 * v20 + 3) * 20
                        if e.s32(0x24) > lim:
                            self.p4_43B610(e, 0, 0, -0x100 & 0xFFFFFFFF)
                            e.d32(0x2C, 0)
        elif st == 1:
            if t == 0x78:
                e.d32(0x24, (x << 2) & 0xFFFFFFFF)
                e.d32(0x28, (y << 2) & 0xFFFFFFFF)
                e.d32(0x2C, self.p4_45a9a0(
                    self.p4_player_x() - x, self.p4_player_y() - y) & 0xFFFFFFFF)
                e.d32(0x30, ((t + 0x12) * 9) & 0xFFFFFFFF)
            a = e.s32(0x2C)
            spd = e.s32(0x30)
            e.d32(0x24, (e.s32(0x24) + ((page4_cos(a) * spd) >> 8)) & 0xFFFFFFFF)
            e.d32(0x28, (e.s32(0x28) + ((page4_sin(a) * spd) >> 8)) & 0xFFFFFFFF)
            e.d32(0x30, (spd - 3) & 0xFFFFFFFF)
            e.d32(0x04, (e.s32(0x24) >> 2) & 0xFFFFFFFF)
            e.d32(0x08, (e.s32(0x28) >> 2) & 0xFFFFFFFF)
        elif st == 2:
            if t < 0x1D6:
                self.p4_401244(e)
                if (d & 0x3F) == 0:
                    self.p4_43B610(e, 0, 0, 0x240)
            else:
                e.d32(0x04, (x + 0xA) & 0xFFFFFFFF)
        elif st in (3, 4):
            if t < 0x159:
                self.p4_401244(e)
            else:
                e.d32(0x04, (x + 6) & 0xFFFFFFFF)
            gate = 0xF if st == 3 else 0x7F
            if (d & gate) == 0:
                if st == 3:
                    self.p4_43B360(e,
                                   self.p4_player_x() + (self.p4_rand() % 0x1E0),
                                   self.p4_player_y() + (self.p4_rand() % 0x280), 0x300)
                else:
                    self._p4_ent43c(0x2500000B, x, y,
                                    (self.p4_rand() & 0xFF))
        elif st == 5:
            if t < 0xD2:
                self.p4_401244(e)
                if d == 0xC8:
                    e.d32(0x24, (main.s32(0x04) << 3) & 0xFFFFFFFF)
                    e.d32(0x28, (main.s32(0x08) << 3) & 0xFFFFFFFF)
                    e.d32(0x2C, self.p4_45a9a0(
                        self.p4_player_x() - main.s32(0x04),
                        self.p4_player_y() - main.s32(0x08)) & 0xFFFFFFFF)
            else:
                a = e.s32(0x2C)
                e.d32(0x24, (e.s32(0x24) + ((page4_cos(a) * 3) >> 4)) & 0xFFFFFFFF)
                e.d32(0x28, (e.s32(0x28) + ((page4_sin(a) * 3) >> 4)) & 0xFFFFFFFF)
                ang = ((8 - (t - 0xC8 % 0x100)) * 72) & 0xFFFFFFFF
                e.d32(0x04, (main.s32(0x04) + ((page4_cos(ang) * (8 - v20) * 72) >> 8)) & 0xFFFFFFFF)
                e.d32(0x08, (main.s32(0x08) + ((page4_sin(ang) * (8 - v20) * 72) >> 8)) & 0xFFFFFFFF)
        elif st == 6:
            if t < 0xFF:
                self.p4_401244(e)
            if t > 0xD2 and (t & 0xF) == 0:
                ang = ((8 - v20) * 0x2C0) & 0xFFFFFFFF
                sy = self.p4_player_y() + ((page4_sin(ang) * 2) >> 8)
                sx = self.p4_player_x() + (((page4_sin(ang) * 3) >> 8) * 15)
                self.p4_43B360(e, sx, sy, 0)
    return self._p4_4130d0_tail(e, main, d)


def _p4_4130d0_tail(self, e, main, d: int) -> bool:
    """`0x4130D0` 收尾：主打包位翻转、HP 门、node dst。"""
    p30 = main.g32(0x30)
    if (p30 & 0xFFFF) >= 0x4B0:
        main.d32(0x30, (p30 - 0x4B0) & 0xFFFFFFFF)
    x = e.s32(0x04)
    y = e.s32(0x08)
    if e.g32(0x18) == 0:
        nd = e.node
        if nd is not None:                   # 0x45A790(node+4, 0x30,0x30,0x30,0x30)
            nd.rect = (nd.rect[0] + 0x30, nd.rect[1] + 0x30,
                       nd.rect[2] + 0x30, nd.rect[3] + 0x30)
        e.m[0x10] = 1
    if e.node is not None:
        e.node.dst = (x - 0x18, y - 0x18)
    return e.g32(0x18) != 0


def _p4_45ac70(self, tgt: list, cur: list, lim: int) -> bool:
    """`0x45AC70`（thunk 0x40105A）：**定角步进追踪** —— ang=0x45A9A0(Δ)；
    *cur += (sin(ang)*lim + 0x80)>>8、*tgt += (cos(ang)*lim + 0x80)>>8
    （[tgt]==0 且 [cur]==0 → return 0）。"""
    if tgt[0] == 0 and cur[0] == 0:
        return False
    a = self.p4_45a9a0(tgt[0], cur[0])
    s_ = page4_sin(a)
    c = page4_cos(a)
    cur[0] = (cur[0] + ((s_ * lim + 0x80) >> 8)) & 0xFFFFFFFF
    tgt[0] = (tgt[0] + ((c * lim + 0x80) >> 8)) & 0xFFFFFFFF
    return True


def _beh_4053A0(self, e) -> bool:
    """`0x4053A0`（0x2C000005，0x4047E0 三连铺出的光珠）：**追踪光珠**。

    0x45AC70(&{dy}, &{dx}, 0x40)：x/y 8.8 累积向自机 0x40 步进；
    再 0x45AC70(&[0x20], &[0x1C], 0x600)（自身位移分量同法）；
    [0x28] += [0x20]、[0x24] += [0x1C]；x=[0x24]>>8、y=[0x28]>>8；
    node dst=(x−0x18,y−0x18)；word[0x56CCA8]&3==0 → 0x4D000001 @(x,y) 入 0x4AD4CC
    （拖尾）；0x4305F0(e,0x18)；return 在屏 且 HP≠0。"""
    px, py = self.p4_player_x(), self.p4_player_y()
    dx = px - e.s32(0x04)
    dy = py - e.s32(0x08)
    cur = [dx]
    tgt = [dy]
    if self._p4_45ac70(tgt, cur, 0x40):
        e.d32(0x1C, (e.s32(0x1C) + cur[0]) & 0xFFFFFFFF)
        e.d32(0x20, (e.s32(0x20) + tgt[0]) & 0xFFFFFFFF)
    cur2 = [e.s32(0x1C)]
    tgt2 = [e.s32(0x20)]
    self._p4_45ac70(tgt2, cur2, 0x600)
    e.d32(0x1C, cur2[0] & 0xFFFFFFFF)
    e.d32(0x20, tgt2[0] & 0xFFFFFFFF)
    e.d32(0x28, (e.s32(0x28) + e.s32(0x20)) & 0xFFFFFFFF)
    e.d32(0x24, (e.s32(0x24) + e.s32(0x1C)) & 0xFFFFFFFF)
    a28 = e.s32(0x28)
    a24 = e.s32(0x24)
    x = (a24 - 0x100000000 if a24 & 0x80000000 else a24) >> 8
    y = (a28 - 0x100000000 if a28 & 0x80000000 else a28) >> 8
    e.d32(0x04, x & 0xFFFFFFFF)
    e.d32(0x08, y & 0xFFFFFFFF)
    if e.node is not None:
        e.node.dst = (x - 0x18, y - 0x18)
    if (self.p4_frame_no() & 3) == 0:
        self.spawn(self._p4_q("ui4cc"), 0x4D000001, x, y, 0)
    return self.p4_4305f0(e, 0x18) and e.g32(0x18) != 0


def _beh_405510(self, e) -> bool:
    """`0x405510`（0x2C000006，0x4047E0 铺出的爆点）：**下坠 + 落地横扫**。

    [0x1C] += 0x20；[0x20] += [0x1C]；y = [0x20]>>8；
    y > 0x1CC → y=0x1CC、x −= 4；x < 自机x → 九连 0x43B290
    （(0, dx, −0xC00..−0x400 步 0x80)）+ 0x401C08(0x4AD4CC, x, y, 0x18, i, 1)
    ×9、return 0；否则 y≤0x1CC → x++。
    node dst=(x−0x18,y−0x18)；return HP≠0。"""
    v1c = (e.s32(0x1C) + 0x20) & 0xFFFFFFFF
    e.d32(0x1C, v1c)
    v20 = (e.s32(0x20) + v1c) & 0xFFFFFFFF
    e.d32(0x20, v20)
    y = (v20 - 0x100000000 if v20 & 0x80000000 else v20) >> 8
    x = e.s32(0x04)
    if y > 0x1CC:
        y = 0x1CC
        x = (x - 4) & 0xFFFFFFFF
        if x < self.p4_player_x():
            # 0x4055E8 只有一个九连环：(dx, −0x100, 0)，dx=−0xC00..−0x400 步 0x80
            dx = -0xC00
            while dx <= -0x400:
                self.p4_43B290(e, dx, -0x100, 0)
                dx += 0x80
            i = 0
            while i <= 8:
                self.spawn(self._p4_q("ui4cc"), 0x2C000005, x, y, (i, 0x18, 1))
                i += 1
            return False
    else:
        e.d32(0x04, (x + 1) & 0xFFFFFFFF)
        x = x + 1
    e.d32(0x08, y & 0xFFFFFFFF)
    if e.node is not None:
        e.node.dst = (x - 0x18, y - 0x18)
    return e.g32(0x18) != 0


def _beh_405600(self, e) -> bool:
    """`0x405600`（0x2C000008，**关8 关底母舰六态** 0x40612D 后公共尾）。

    态0：铺 0x1E 架 0x2C00000A @(0x780302)（镜像递减）入 0x4AD43C；
      t<0xB4 → x=0x2E4−45t、y=0x78；t==0x78 → 0x5100000A @(0x18,0x190) 入 4FC；
      0xB4≤t<0x258 → y=0x190；t≥0x258 → 态1。
    态1：t<0x3C → x=0x208+sin(45t)*(0x6E−t)>>7、y=0x140+cos(45t)*(0x64−t)>>7；
      0x3C..0x6D → x=0x208+sin(45t)*90>>7、y=0xA0+sin(40(t+0x28))*90>>7；
      0x1A4≤t<0x2BC → x−=6、y+=6；t∈{0x96,0xD2,0x10E,0x14A} → 双发 0x2C000009
      @(0x7802BC,0x834)/(0x16802BC,0x5DC) 入 0x4AD43C；t==0x2BC → 态2。
    态2：铺 0xA 架 0x2C00000A @(0x235027B)；t<0x28 → x=0x27B−t、y=0x235−t；
      0x28..0x259 → 椭圆（cos(40t−0xFA)…）+ (t&3)==0 → 0x43B610(2x−0x1E0, 2y−0xF0,
      −0x800)；0x25A..0x2ED → x+=6、y−=6；t==0x2B2 且 [0x28]==2 → 0x5100000A
      @(0x268,0x168) 入 4FC；t==0x2EE → 态3。
    态3：铺 6 架 0x2C00000B @(0x7802BC)；t<0x1E → x=0x190+(0x1E−t)²/3；
      y += (自机y−y+8)>>4；0x78..0xB3 → 同法吸 y；0xB4..0x329 →（未全读，过渡）；
      t==0x32A →（态 4 入口）。
    态4：铺 0x3C 架 0x2C00000A @(0xFF9C0280)；x=0x2B0、y=−0x30、[0x2C]=0xFD002B00；
      t%0x96==0 且 t≤0x2EE → [0x28]=0x45A9A0(Δ自机)；角步进 word[0x2C/0x2E] +=
      3*sin/cos([0x28])>>2；x=word[0x2C]>>4、y=word[0x2E]>>4；出界钳
      {[0x28]: 0xA8C/0/0x384/0x708}；t==0x546 → 态5。
    态5：铺 0x14 架 0x2C00000A @(0x2402BC)；x=0x2BC、y=0x24；t<0x14 → x−=0xC；
      0x14..0x9F → y 向 0x54/0x1F4 吸（>>2）；0xA0..0xAF → y 同；≥0xB0 且 <0x32A →
      x−=8、y+=8（0x4B0 → 态6）。
    弹幕（0x405F02）：0xF0≤t<0x32A 且 (t&7)==0 → 0x33000020 @(x,y)
      prm=(40sin(45(t+0xC8))>>0xA+0x200, 40cos(45(t+0xC8))>>0xA+0x200) 入 0x4AD49C
      + 对映 (−vx,−vy) 同型。
    态推进：各态终点 [0x1C]++。"""
    st = e.s32(0x1C)
    t = e.s32(0x20)
    if st == 0:
        if t == 0:
            for i in range(0x1E):
                self._p4_ent43c(0x2C00000A, 0x780302, 1 if i == 0 else 0)
            if e.s32(0x24) == 0:
                e.d32(0x24, 1)
        if t < 0xB4:
            e.d32(0x08, 0x78)
            e.d32(0x04, (0x2E4 - 45 * t) & 0xFFFFFFFF)
            if t == 0x78:
                self.spawn(self._p4_q("ui4fc"), 0x5100000A, 0x18, 0x190, 0)
        elif t < 0x258:
            e.d32(0x08, 0x190)
        else:
            e.d32(0x1C, 1)
    elif st == 1:
        if t < 0x3C:
            a = (45 * t) & 0xFFFFFFFF
            e.d32(0x04, (0x208 + ((page4_sin(a) * (0x6E - t)) >> 7)) & 0xFFFFFFFF)
            e.d32(0x08, (0x140 + ((page4_cos(a) * (0x64 - t)) >> 7)) & 0xFFFFFFFF)
        elif t < 0x6E:
            a = (45 * t) & 0xFFFFFFFF
            e.d32(0x04, (0x208 + ((page4_sin(a) * 90) >> 7)) & 0xFFFFFFFF)
            a2 = (40 * (t + 0x28)) & 0xFFFFFFFF
            e.d32(0x08, (0xA0 + ((page4_sin(a2) * 90) >> 7)) & 0xFFFFFFFF)
        elif 0x1A4 <= t < 0x2BC:
            e.d32(0x04, (e.s32(0x04) - 6) & 0xFFFFFFFF)
            e.d32(0x08, (e.s32(0x08) + 6) & 0xFFFFFFFF)
        if t in (0x96, 0xD2, 0x10E, 0x14A):
            self._p4_ent43c(0x2C000009, 0x7802BC, 0x834)
            self._p4_ent43c(0x2C000009, 0x16802BC, 0x5DC)
        if t == 0x2BC:
            e.d32(0x1C, 2)
    elif st == 2:
        if t == 0:
            for i in range(0xA):
                self._p4_ent43c(0x2C00000A, 0x235027B, 1 if i == 0 else 0)
        if t < 0x28:
            e.d32(0x04, (0x27B - t) & 0xFFFFFFFF)
            e.d32(0x08, (0x235 - t) & 0xFFFFFFFF)
        elif t < 0x25A:
            a = (40 * t - 0xFA) & 0xFFFFFFFF
            s_ = page4_sin(a)
            c = page4_cos(a)
            e.d32(0x04, (0x1E0 + ((s_ * 15) >> 8) * 1) & 0xFFFFFFFF) \
                if False else (0x1E0 + (((s_ * 15) >> 8))) & 0xFFFFFFFF
            e.d32(0x08, (0xF0 + ((c * 15) >> 8)) & 0xFFFFFFFF)
            if t >= 0x80 and (t & 3) == 0:
                self.p4_43B610(e, 2 * e.s32(0x04) - 0x1E0,
                               2 * e.s32(0x08) - 0xF0, -0x800 & 0xFFFFFFFF)
        elif t < 0x2EE:
            e.d32(0x04, (e.s32(0x04) + 6) & 0xFFFFFFFF)
            e.d32(0x08, (e.s32(0x08) - 6) & 0xFFFFFFFF)
        else:
            e.d32(0x1C, 3)
        if e.s32(0x28) == 2 and t == 0x2B2:
            self.spawn(self._p4_q("ui4fc"), 0x5100000A, 0x268, 0x168, 0)
    elif st == 3:
        if t == 0:
            for i in range(6):
                self._p4_ent43c(0x2C00000B, 0x7802BC, 1 if i == 0 else 0)
        if t < 0x1E:
            q = (0x1E - t)
            e.d32(0x04, (0x190 + (q * q) // 3) & 0xFFFFFFFF)
        yy = e.s32(0x08)
        e.d32(0x08, (yy + ((self.p4_player_y() - yy + 8) >> 4)) & 0xFFFFFFFF)
        if t == 0x32A:
            e.d32(0x1C, 4)
    elif st == 4:
        if t == 0:
            for i in range(0x3C):
                self._p4_ent43c(0x2C00000A, 0xFF9C0280, 1 if i == 0 else 0)
            e.d32(0x04, 0x2B0)
            e.d32(0x08, -0x30 & 0xFFFFFFFF)
            e.d32(0x2C, 0xFD002B00)
        if t % 0x96 == 0 and t <= 0x2EE:
            e.d32(0x28, self.p4_45a9a0(
                self.p4_player_x() - e.s32(0x04),
                self.p4_player_y() - e.s32(0x08)) & 0xFFFFFFFF)
        a = e.s32(0x28)
        w2c = (e.g16(0x2C) + ((page4_sin(a) * 3) >> 2)) & 0xFFFF
        w2e = (e.g16(0x2E) + ((page4_cos(a) * 3) >> 2)) & 0xFFFF
        e.d16(0x2C, w2c)
        e.d16(0x2E, w2e)
        x = (w2c - 0x8000 if w2c & 0x8000 else w2c) >> 4
        y = (w2e - 0x8000 if w2e & 0x8000 else w2e) >> 4
        e.d32(0x04, x & 0xFFFFFFFF)
        e.d32(0x08, y & 0xFFFFFFFF)
        if t % 0x96 > 0xA:
            if x <= -0x60:
                e.d32(0x28, 0xA8C)
            if y <= -0x60:
                e.d32(0x28, 0)
            if x >= 0x2E0:
                e.d32(0x28, 0x384)
            if y >= 0x240 and x > -0x60:
                e.d32(0x28, 0x708)
        if t == 0x546:
            e.d32(0x1C, 5)
    elif st == 5:
        if t == 0:
            for i in range(0x14):
                self._p4_ent43c(0x2C00000A, 0x2402BC, 1 if i == 0 else 0)
            e.d32(0x04, 0x2BC)
            e.d32(0x08, 0x24)
        if t < 0x14:
            e.d32(0x04, (e.s32(0x04) - 0xC) & 0xFFFFFFFF)
        elif t < 0xA0:
            xx = e.s32(0x04)
            if xx < 0x54:
                e.d32(0x08, (e.s32(0x08) + ((0x54 - xx) >> 2)) & 0xFFFFFFFF)
            elif xx > 0x22C:
                e.d32(0x08, (e.s32(0x08) - ((xx - 0x22C) >> 2)) & 0xFFFFFFFF)
            yy = e.s32(0x08)
            if yy < 0x54:
                e.d32(0x04, (xx - ((0x54 - yy) >> 2)) & 0xFFFFFFFF)
            elif yy > 0x18C:
                e.d32(0x04, (xx + ((yy - 0x18C) >> 2)) & 0xFFFFFFFF)
        elif t < 0xAF:
            xx = e.s32(0x04)
            if xx < 0x1F4:
                e.d32(0x08, (e.s32(0x08) + ((0x1F4 - xx) >> 2)) & 0xFFFFFFFF)
            elif xx > 0x22C:
                e.d32(0x08, (e.s32(0x08) - ((xx - 0x22C) >> 2)) & 0xFFFFFFFF)
            yy = e.s32(0x08)
            if yy < 0x74:
                e.d32(0x04, (xx - ((0x74 - yy) >> 2)) & 0xFFFFFFFF)
        elif t < 0x32A:
            e.d32(0x04, (e.s32(0x04) - 8) & 0xFFFFFFFF)
            e.d32(0x08, (e.s32(0x08) + 8) & 0xFFFFFFFF)
            if t == 0x4B0:
                e.d32(0x1C, 6)
        else:
            e.d32(0x1C, 6)
    t = e.s32(0x20)
    y = e.s32(0x08)
    x = e.s32(0x04)
    if 0xF0 <= t < 0x32A and (t & 7) == 0:
        a = (45 * (t + 0xC8)) & 0xFFFFFFFF
        vx = (((page4_sin(a) * 40) >> 0xA) + 0x200) & 0xFFFFFFFF
        vy = (((page4_cos(a) * 40) >> 0xA) + 0x200) & 0xFFFFFFFF
        self.spawn(self._p4_q("ui49c"), 0x33000020, x, y, (vx, vy))
        self.spawn(self._p4_q("ui49c"), 0x33000020, x, y,
                   ((-vx) & 0xFFFFFFFF, (-vy) & 0xFFFFFFFF))
    e.d32(0x20, (t + 1) & 0xFFFFFFFF)
    return True


def _beh_4064E0(self, e) -> bool:
    """`0x4064E0`（0x2C000009，0x405600 态1 铺出的护卫机）：**环绕追踪**。

    [0x24]==0：铺 8 架 0x2C00000A @((y<<0x10)|(x&0xFFFF), ±3)（镜像递减）入 0x4AD43C、
    [0x24]=1。
    [0x24]==1：a = 0x45A9A0(Δ自机) − [0x20]；a>0x708 → a −= 0x1E00*ceil((a−0x707)/0x1E00)
    （0x91A2B3C5 魔数除法 = ÷0x1E00）；a<−0x708 → a += 0x1E00*…；a ∈ (−0x28,0x28)
    外钳到 ±0x28；[0x20] = a mod 0xE10（双圈归一）；0x401843(e, 自机x, 自机y, 0x60)
    → 近机门 [0x24]=2。
    [0x24]≠0：x = word[0x1C] −= sin([0x20])；y = word[0x1E] −= cos([0x20])
    （8.8 定点反向）；x=word[0x1C]>>5、y=word[0x1E]>>5；node dst=(x−0x18,y−0x18)。
    HP==0 → 0x41000014 @(x,y) prm 0x10+(rand&0xF) 入 0x4AD4CC、return 0；
    [0x24]==2 且 0x4305F0(e,0x180)==0 → return 0；else return 1。"""
    st = e.s32(0x24)
    x = e.s32(0x04)
    y = e.s32(0x08)
    if st == 0:
        for i in range(8):
            self._p4_ent43c(0x2C00000A, ((y & 0xFFFF) << 0x10) | (x & 0xFFFF),
                            1 if i == 0 else 0)
        e.d32(0x24, 1)
        st = 1
    if st == 1:
        a = self.p4_45a9a0(x - self.p4_player_x(),
                           y - self.p4_player_y()) - e.s32(0x20)
        while a > 0x708:
            a -= 0x1E00
        while a < -0x708:
            a += 0x1E00
        if a > 0x28:
            a = 0x28
        elif a < -0x28:
            a = -0x28
        v20 = a % 0xE10
        if v20 < 0:
            v20 += 0xE10
        e.d32(0x20, v20 & 0xFFFFFFFF)
        if self.p4_4305f0(e, 0x60):
            e.d32(0x24, 2)
    if e.s32(0x24) != 0:
        a = e.s32(0x20)
        w1c = e.g16(0x1C)
        w1e = e.g16(0x1E)
        w1c = (w1c - (page4_sin(a) & 0xFFFF)) & 0xFFFF
        w1e = (w1e - (page4_cos(a) & 0xFFFF)) & 0xFFFF
        e.d16(0x1C, w1c)
        e.d16(0x1E, w1e)
        x = ((w1c - 0x8000 if w1c & 0x8000 else w1c) >> 5) & 0xFFFFFFFF
        y = ((w1e - 0x8000 if w1e & 0x8000 else w1e) >> 5) & 0xFFFFFFFF
        e.d32(0x04, x)
        e.d32(0x08, y)
        if e.node is not None:
            e.node.dst = (x - 0x18, y - 0x18)
    if e.g32(0x18) == 0:
        self.spawn(self._p4_q("ui4cc"), 0x41000014, x, y,
                   0x10 + (self.p4_rand() & 0xF))
        return False
    if e.s32(0x24) == 2 and not self.p4_4305f0(e, 0x180):
        return False
    return True


def _p4_4067a0(self, e, leader) -> bool:
    """`0x4067A0`（thunk 0x4015D7）：**编队体存活/受击助手** —— leader 死或
    HP==0 时：本 HP==0 → 不在屏则 0x2C00000D @(x,y) 入 0x4AD43C；node.dst.y += 0xC0、
    node.rect.r += 0xC0（飞出）；HP!=0 → 0x430640 在屏门；不在屏 →
    0x41000014 @(x,y) prm 0x10+(rand&3) 入 0x4AD4CC、return 0。"""
    x = e.s32(0x04)
    y = e.s32(0x08)
    if leader is None or leader.m[0x34] == 0 or e.g32(0x18) == 0:
        if e.g32(0x18) == 0:
            if not self.p4_430640(e):
                self._p4_ent43c(0x2C00000D, x, y)
            if e.node is not None:
                e.node.dst = (e.node.dst[0], e.node.dst[1] + 0xC0)
                e.node.rect = (e.node.rect[0], e.node.rect[1],
                               e.node.rect[2] + 0xC0, e.node.rect[3])
        return True
    if not self.p4_430640(e):
        self.spawn(self._p4_q("ui4cc"), 0x41000014, x, y,
                   0x10 + (self.p4_rand() & 3))
        return False
    return True


def _beh_4068C0(self, e) -> bool:
    """`0x4068C0`（0x2C00000A，母舰编队小体）：**跟随链 + 位置历史滑窗**。

    0x4067A0(e, [0x1C] 句柄) 不活 → return。
    [0x30]（打包位）== (主.y<<0x10)|(主.x&0xFFFF) → 已对齐，跳历史；
    否则：历史滑窗 word[0x20..0x30] 逐级后移（[0x22]←[0x20]、[0x24]←[0x22]…），
    byte[0x20]=主.[0x20]（低字节符号步进 → x += s8[0x20]、y += s8[0x21]）；
    跟随差 word[0x30] ← 主位；x/y 差钳 ±0x7F → [0x2C]/[0x2D]、[0x32] 累积；
    [0xC]==0x18 → [0x28]=word[0x2C]（步进到位）。
    node dst = (x−[0xC], y−[0xC])；return 1。"""
    links = getattr(self, "p4_links", {})
    leader = links.get(e.s32(0x1C) & 0x7FFFFFFF)
    if not self._p4_4067a0(e, leader):
        return True
    if leader is None:
        return True
    pack = ((leader.s32(0x08) & 0xFFFF) << 0x10) | (leader.s32(0x04) & 0xFFFF)
    if e.g32(0x30) != pack:
        # 历史滑窗（word[0x20..0x30] 逐级后移）
        for off in (0x2A, 0x28, 0x26, 0x24, 0x22):
            e.d16(off + 2 - 0x02, e.g16(off))          # [off+2] = [off]
        e.d16(0x22, e.g16(0x20))
        sx = leader.g16(0x20) & 0xFF
        sy = leader.g16(0x22) & 0xFF
        sx = sx - 0x100 if sx & 0x80 else sx
        sy = sy - 0x100 if sy & 0x80 else sy
        e.d32(0x04, (e.s32(0x04) + sx) & 0xFFFFFFFF)
        e.d32(0x08, (e.s32(0x08) + sy) & 0xFFFFFFFF)
        e.d16(0x20, leader.g16(0x24))
        e.d16(0x24, leader.g16(0x26))
        e.d16(0x26, leader.g16(0x28))
        e.d16(0x28, leader.g16(0x2A))
        e.d16(0x2A, leader.g16(0x2C))
        e.d16(0x30, (leader.s32(0x04) - e.s32(0x04)) & 0xFFFF)
        dx = leader.s32(0x04) - e.s32(0x04)
        dy = leader.s32(0x08) - e.s32(0x08)
        dx = max(-0x80, min(0x7F, dx))
        dy = max(-0x80, min(0x7F, dy))
        w30 = e.g16(0x30)
        w30 = (w30 + dx) & 0xFFFF
        e.d16(0x30, w30)
        w32 = (e.g16(0x32) + dy) & 0xFFFF
        e.d16(0x32, w32)
        e.m[0x2C] = dx & 0xFF
        e.m[0x2D] = dy & 0xFF
        if e.s32(0x0C) == 0x18:
            e.d16(0x28, e.g16(0x2C))
    x = e.s32(0x04)
    y = e.s32(0x08)
    base = e.s32(0x0C)
    if e.node is not None:
        e.node.dst = (x - base, y - base)
    return True


def _beh_406A20(self, e) -> bool:
    """`0x406A20`（0x2C00000B，0x405600 态3 铺的侧翼）：**摆入追踪**。

    0x4067A0(e, 主) 不活 → return。
    [0x28]==0 → edi=0；否则 edi=主.[0x20]；a = 0x45A9A0(Δ主) − edi；
    a>0x708 → −0x1E00 模归一、a<−0x708 → +；a∈(0, 0x3C) → [0x24] += 7；
    a∈(−0x3C, 0] → [0x24] −= 7；[0x24]>0 → −8、<0 → +8（阻尼）；a>0x28 或 <−0x28
    不额外钳（[0x24] 门同 0x4064E0 简化）。
    [0x20] += [0x24]；摆动角 = 2*0x40159B([0x20]) + 0x40159B([0x20])（字面：
    edi = sin([0x20]) + sin([0x20])（两次调用相加）、再 cos 同加）；
    x = 主.x + (5*(sin1+sin2))>>5、y = 主.y + (5*(cos1+cos2))>>5；
    node dst = (x−[0xC], y−[0xC])；[0x2C]++；return 1。"""
    links = getattr(self, "p4_links", {})
    main = links.get(e.s32(0x1C) & 0x7FFFFFFF)
    if not self._p4_4067a0(e, main):
        return True
    if main is None:
        return True
    edi = 0 if e.s32(0x28) == 0 else main.s32(0x20)
    a = self.p4_45a9a0(e.s32(0x04) - main.s32(0x04),
                       e.s32(0x08) - main.s32(0x08)) - edi
    while a > 0x708:
        a -= 0x1E00
    while a < -0x708:
        a += 0x1E00
    v24 = e.s32(0x24)
    if 0 < a < 0x3C:
        v24 += 7
    elif -0x3C <= a <= 0:
        pass
    if v24 > 0:
        v24 -= 8
    elif v24 <= 0 and v24 > -0x3C:
        v24 -= 7
        v24 = -v24
    e.d32(0x24, v24 & 0xFFFFFFFF)
    v20 = (e.s32(0x20) + v24) & 0xFFFFFFFF
    e.d32(0x20, v20)
    s1 = page4_sin(v20)
    s2 = page4_sin(v20)
    c1 = page4_cos(v20)
    c2 = page4_cos(v20)
    swing = s1 + s2
    swingc = c1 + c2
    x = (main.s32(0x04) + ((5 * swing) >> 5)) & 0xFFFFFFFF
    y = (main.s32(0x08) + ((5 * swingc) >> 5)) & 0xFFFFFFFF
    e.d32(0x04, x)
    e.d32(0x08, y)
    base = e.s32(0x0C)
    if e.node is not None:
        e.node.dst = (x - base, y - base)
    e.d32(0x2C, (e.s32(0x2C) + 1) & 0xFFFFFFFF)
    return True


def _beh_406BD0(self, e) -> bool:
    """`0x406BD0`（0x2C00000C）：**横列阵（主态门 + /3 步进）**。

    0x4067A0(e, 主) 不活 → return；主死（byte[+0x34]）→ return 0。
    a = 主.[0x28] − [0x28]；0x1E00 模归一；a∈(0,0x708] → [0x28] += a>>2；
    a∈(−0x708,0] → 不动（jge 分支）。
    x = 主.x + sin([0x28])/3（0x55555556 除法 = ÷3）、y = 主.y + cos([0x28])/3；
    node dst = (x−[0xC], y−[0xC])；[0x18]!=0x2710 → 主.[0x2C]++；[0x18]=0x2710；
    return 1。"""
    links = getattr(self, "p4_links", {})
    main = links.get(e.s32(0x1C) & 0x7FFFFFFF)
    if not self._p4_4067a0(e, main):
        return True
    if main is None or main.m[0x34] == 0:
        return False
    a = main.s32(0x28) - e.s32(0x28)
    while a > 0x708:
        a -= 0x1E00
    while a < -0x708:
        a += 0x1E00
    if a > 0:
        e.d32(0x28, (e.s32(0x28) + (a >> 2)) & 0xFFFFFFFF)
    v28 = e.s32(0x28)
    x = (main.s32(0x04) + self._p4_div3(page4_cos(v28))) & 0xFFFFFFFF  # 0x40159B=cos
    y = (main.s32(0x08) + self._p4_div3(page4_sin(v28))) & 0xFFFFFFFF  # 0x401A50=sin
    e.d32(0x04, x)
    e.d32(0x08, y)
    base = e.s32(0x0C)
    if e.node is not None:
        e.node.dst = (x - base, y - base)
    if e.g32(0x18) != 0x2710:
        main.d32(0x2C, (main.s32(0x2C) + 1) & 0xFFFFFFFF)
    e.d32(0x18, 0x2710)
    return True


@staticmethod
def _p4_div3(v: int) -> int:
    """0x55555556 魔数除法 = 向零取整 ÷3。"""
    q = abs(v) // 3
    return -q if v < 0 else q


def _beh_406D30(self, e) -> bool:
    """`0x406D30`（0x2C00000D）：**下坠旋转伞弹**。

    [0x28] += [0x24]、[0x2C] += [0x24]；x = [0x1C] − ([0x2C]>>8)、
    y = [0x20] + ([0x2C]>>8)（左下弧线）；node dst=(x−0x30,y−0x30)；
    [0x30]（寿命）≠0 → −−；==0 → [0x10]=1。
    HP==0：ang=0x45A9A0(Δ自机)：0x43B290(e, cos(ang±0x15E/±0xC8), sin 同, −0x280/
    −0x200) 六连扇；rand%0x3F==0 → 0x32000006|rand&1 @(x,y) 入 0x4AD49C；
    return 0。
    HP≠0：0x430640 在屏 且 HP≠0 → return 1；否则 return 0。"""
    e.d32(0x28, (e.s32(0x28) + e.s32(0x24)) & 0xFFFFFFFF)
    e.d32(0x2C, (e.s32(0x2C) + e.s32(0x24)) & 0xFFFFFFFF)
    a2c = e.s32(0x2C)
    off = (a2c - 0x100000000 if a2c & 0x80000000 else a2c) >> 8
    x = (e.s32(0x1C) - off) & 0xFFFFFFFF
    y = (e.s32(0x20) + off) & 0xFFFFFFFF
    e.d32(0x04, x)
    e.d32(0x08, y)
    if e.node is not None:
        e.node.dst = (x - 0x30, y - 0x30)
    if e.s32(0x30) != 0:
        e.d32(0x30, (e.s32(0x30) - 1) & 0xFFFFFFFF)
    else:
        e.m[0x10] = 1
    if e.g32(0x18) == 0:
        a = self.p4_45a9a0(self.p4_player_x() - x, self.p4_player_y() - y)
        self.p4_43B290(e, (self.p4_player_x() - x) & 0xFFFFFFFF,
                       (self.p4_player_y() - y) & 0xFFFFFFFF, -0x280 & 0xFFFFFFFF)
        for da, spd in ((0x15E, -0x280), (-0x15E, -0x280),
                        (0xC8, -0x200), (-0xC8, -0x200)):
            ang = (a + da) & 0xFFFFFFFF
            self.p4_43B290(e, page4_cos(ang), page4_sin(ang), spd & 0xFFFFFFFF)
        if self.p4_rand() % 0x3F == 0:
            self.spawn(self._p4_q("ui49c"), 0x32000006 | (self.p4_rand() & 1),
                       x, y, 0)
        return False
    return self.p4_430640(e) and e.g32(0x18) != 0


def _beh_406F60(self, e) -> bool:
    """`0x406F60`（0x2C000011，0x4070E0 挂主小机）：**角向追踪**。

    [0x28]（角速度）≥0x80 → −= 0x20；a = 0x45A9A0(Δ自机)；
    [0x20] += sin(a)*[0x28]>>8、[0x24] += cos(a)*[0x28]>>8；
    x = [0x20]>>8、y = [0x24]>>8；node dst=(x−0x48, y−0x48)；
    HP==0 或 主死 → 主.[0x28] &= 0xFFFFFFFE、0x41000014 @(x,y) prm 0x10 入 0x4AD4CC、
    return 0；else return 1。"""
    links = getattr(self, "p4_links", {})
    main = links.get(e.s32(0x1C) & 0x7FFFFFFF)
    v28 = e.s32(0x28)
    if v28 >= 0x80:
        e.d32(0x28, (v28 - 0x20) & 0xFFFFFFFF)
        v28 -= 0x20
    a = self.p4_45a9a0(self.p4_player_x() - e.s32(0x04),
                       self.p4_player_y() - e.s32(0x08))
    e.d32(0x20, (e.s32(0x20) + ((page4_cos(a) * v28) >> 8)) & 0xFFFFFFFF)  # cos→x
    e.d32(0x24, (e.s32(0x24) + ((page4_sin(a) * v28) >> 8)) & 0xFFFFFFFF)  # sin→y
    a20 = e.s32(0x20)
    a24 = e.s32(0x24)
    x = (a20 - 0x100000000 if a20 & 0x80000000 else a20) >> 8
    y = (a24 - 0x100000000 if a24 & 0x80000000 else a24) >> 8
    e.d32(0x04, x & 0xFFFFFFFF)
    e.d32(0x08, y & 0xFFFFFFFF)
    if e.node is not None:
        e.node.dst = (x - 0x48, y - 0x48)
    dead = main is None or main.m[0x34] == 0
    if e.g32(0x18) == 0 or dead:
        if main is not None:
            main.d32(0x28, main.g32(0x28) & 0xFFFFFFFE)
        self.spawn(self._p4_q("ui4cc"), 0x41000014, x, y, 0x10)
        return False
    return True


def _beh_407180(self, e) -> bool:
    """`0x407180`（0x2C000014，0x404FA0 铺出）：**环绕追踪（同 0x4064E0 变体）**。

    [0x24]==0：a = 0x45A9A0(Δ自机) − [0x20]；0x1E00 模归一；±0x1E 钳；
    [0x20] = a mod 0xE10；0x401843(e, 自机x, 自机y, 0x60) → [0x24]++（近机门）。
    [0x28]−−==0 → [0x24]++（寿命门）。
    [0x24]≠0：x = word[0x1C] −= sin([0x20])、y = word[0x1E] −= cos([0x20])；
    x=word[0x1C]>>5、y=word[0x1E]>>5；node dst=(x−0x18,y−0x18)；
    return HP≠0 且 ([0x24]==0 或 0x430640 在屏)。"""
    st = e.s32(0x24)
    if st == 0:
        a = self.p4_45a9a0(e.s32(0x04) - self.p4_player_x(),
                           e.s32(0x08) - self.p4_player_y()) - e.s32(0x20)
        while a > 0x708:
            a -= 0x1E00
        while a < -0x708:
            a += 0x1E00
        if a > 0x1E:
            a = 0x1E
        elif a < -0x1E:
            a = -0x1E
        v20 = a % 0xE10
        if v20 < 0:
            v20 += 0xE10
        e.d32(0x20, v20 & 0xFFFFFFFF)
        if self.p4_4305f0(e, 0x60):
            e.d32(0x24, 1)
    v28 = (e.s32(0x28) - 1) & 0xFFFFFFFF
    e.d32(0x28, v28)
    if v28 == 0:
        e.d32(0x24, (e.s32(0x24) + 1) & 0xFFFFFFFF)
    if e.s32(0x24) != 0:
        a = e.s32(0x20)
        w1c = (e.g16(0x1C) - (page4_sin(a) & 0xFFFF)) & 0xFFFF
        w1e = (e.g16(0x1E) - (page4_cos(a) & 0xFFFF)) & 0xFFFF
        e.d16(0x1C, w1c)
        e.d16(0x1E, w1e)
        x = ((w1c - 0x8000 if w1c & 0x8000 else w1c) >> 5) & 0xFFFFFFFF
        y = ((w1e - 0x8000 if w1e & 0x8000 else w1e) >> 5) & 0xFFFFFFFF
        e.d32(0x04, x)
        e.d32(0x08, y)
        if e.node is not None:
            e.node.dst = (x - 0x18, y - 0x18)
    return e.g32(0x18) != 0 and (e.s32(0x24) == 0 or self.p4_430640(e))


_P4_407350_LIM = (0x1900, 0xC80, 0x3840, 0x17, 0, 0, 0, 0, 0, 0)


def _beh_407350(self, e) -> bool:
    """`0x407350`（0x2C000010，**最终 boss 十态** 0x407E24）。

    HP==0 或 t≥0x3F48 → 0x41000014 @(x,y,prm 1/2) 入 0x4AD4CC、return 0。
    t<0：x=0x1E0、y=0xF0+((t*t)>>4)（下坠入场）；
    t≥0：x=0x1E0+cos(3t)>>3、y=0xF0+cos(4t)>>2（圆轨）。
    node dst=(x−0x48,y−0x48)；t++。
    [0x28]&1==0 且 [0x20]&1==0 → 发 0x2C000011 @(0x2C8, (~[0x28]&2|0x1E0)>>1)
    入 0x4AD43C、[0x28]^=3。
    [0x20]&1==0：t≥0x1900 且 [0x20]>7 → [0x20]=8；t≥0xC80 且 t<0x3840 → 直达
    公共；[0x20]>0x17 → [0x20]=0x18。
    [0x20]&1：态 = [0x20]>>1（>0x13 跳）；十态表 0x407E24：
      0：(t2&0x1F)==0 → 8× 0x2C000013 @(0x298±0x32*8..) 阶梯（esi 0x28 起 +0x32、
        ebx 0xC8 起 −0x32）入 0x4AD43C
      1：(t2&bl)==0 → rand 角向 0x2C000013（ang=rand%0xE10±(Δ自机≤?0x200:−0x200)）
        prm=(cos&0x1FFF|sin<<0x10)<<3
      2：(t2&0xF)==0 → 0x2C000012 @(0x2BC, 0x28+rand%0x190) prm −0xC00
      3：(t2&0x3F)==0 → 0x2C000014 @(x,y) 环形 6 连（ang 0x12C 起 +0x258 至 0xE10，
        prm=(ang&0xFFFF)|0x780000）
        t2==0x13F → [0x20]=0
      4/8：t2∈{0,0xA0} → 双列 0x2C000013（x 0x338/0xFFFFF908 起 +0x140 ×8、
        y 0x1B8/0x28 交替）；t2∈{0x50,0xF0} → 双列反向
      5/9：(t2&1)==0 → rand%0x708 角向 0x2C000013（0x180−sin 修正、[0x20]==0xB 取反、
        +0x45A9A0(Δ自机)、(ang&0xFFF|sin<<0x10)<<4）
      6：(t2&0xF)==0 → 0x2C000012 @(0x2BC, 0x168/0x28+rand%0x190)（t2==0xD 取
        0x168+0x10 门）prm 0x45A9A0(Δ自机−0x2BC?)… (cos&0x1FFF|sin<<0x10)<<3
      7：(t2&bl)==0 → 0x2C000014 @(0x1F0+(t2&4?−0x708:0x708)+…, rand&0x3F+0x1E0)；
        t2==0x12C → [0x20] = 0x10±8（[0x20]≥0xF?）
      9b：(t2&?)==0 → 双 V 阵 0x2C000013（0x8000800/0xF8000800 prm、0x258/0x218、
        x±0x18 步进）；t2==0x168 → [0x20]++
      9c：(t2&0xF)==0 → 环形 0x2C000013（esi=45*(t2>>4)²?…×90、[0x20]==0x25 取反、
        (cos&0x1FFF|sin<<0x10)<<3）+ 0x2C000012 @(edi, ebx=2*sin+0xF0) 对映；
        t2==0x186 → [0x20]++
      尾：(t2&7)==0 → 0x2C000014 @(x,y,prm 0x5A0546)/(x,y,0x5A08CA) 双件入 43C；
        t2==0x168 → [0x20] -= 0x1F
    公共：[0x20]≠[0x24旧] → [0x24]=0；return HP≠0。
    [0x24]（态内计时）==态限 → [0x24]++。"""
    x = e.s32(0x04)
    y = e.s32(0x08)
    t = e.s32(0x1C)
    hp = e.g32(0x18)
    if hp == 0 or t >= 0x3F48:
        self.spawn(self._p4_q("ui4cc"), 0x41000014, x, y, 1)
        return False
    if t < 0:
        e.d32(0x04, 0x1E0)
        e.d32(0x08, (0xF0 + ((t * t) >> 4)) & 0xFFFFFFFF)
        if t == -1:
            e.d32(0x20, 0)
    else:
        e.d32(0x04, (0x1E0 + (page4_cos(3 * t) >> 3)) & 0xFFFFFFFF)
        e.d32(0x08, (0xF0 + (page4_cos(4 * t) >> 2)) & 0xFFFFFFFF)
    x = e.s32(0x04)
    y = e.s32(0x08)
    t = (t + 1) & 0xFFFFFFFF
    e.d32(0x1C, t)
    v28 = e.g32(0x28)
    v20 = e.s32(0x20)
    if not (v28 & 1) and not (v20 & 1):
        yy = ((~v28 & 2) | 0x1E0) >> 1
        self._p4_ent43c(0x2C000011, 0x2C8, yy)
        e.d32(0x28, v28 ^ 3)
    v20 = e.s32(0x20)
    if not (v20 & 1):
        if t >= 0x1900 and v20 > 7:
            e.d32(0x20, 8)
        if t >= 0xC80 and t < 0x3840:
            pass
        if v20 > 0x17:
            e.d32(0x20, 0x18)
        return self._p4_407350_tail(e, x, y, v20)
    sub = v20 >> 1
    t2 = e.s32(0x24)
    if sub <= 0x13:
        if sub == 0:
            if (t2 & 0x1F) == 0:
                xx = 0x28
                ebx = 0xC8
                while ebx >= -0xC8:
                    self._p4_ent43c(0x2C000013, 0x298 + (abs(ebx) if False else (ebx ^ 0xF100 if False else ebx)) if False else 0x298 + (ebx ^ 0) if False else 0x298, 0)
                    self._p4_ent43c(0x2C000013, 0x298 + (ebx if ebx >= 0 else -ebx), xx)
                    ebx -= 0x32
                    xx += 0x32
        elif sub == 1:
            if (t2 & 0xFF) == 0:
                a = self.p4_rand() % 0xE10
                da = self.p4_45a9a0(self.p4_player_x() - x,
                                    self.p4_player_y() - y)
                ang = (a + (0x200 if a >= 0 else -0x200) + da) & 0xFFFFFFFF
                c = page4_cos(ang) & 0x1FFF
                s_ = page4_sin(ang)
                prm = (((c | (s_ << 0x10)) << 3)) & 0xFFFFFFFF
                self._p4_ent43c(0x2C000013, x, y)
            if t2 == 0x12C:
                pass
        elif sub == 2:
            if (t2 & 0xF) == 0:
                self._p4_ent43c(0x2C000012, 0x2BC,
                                0x28 + (self.p4_rand() % 0x190))
            if t2 == 0x12C:
                pass
        elif sub == 3:
            if (t2 & 0x3F) == 0:
                a = 0x12C
                while a < 0xE10:
                    prm = ((a & 0xFFFF) | 0x780000) & 0xFFFFFFFF
                    self._p4_ent43c(0x2C000014, x, y)
                    a += 0x258
            if t2 == 0x13F:
                e.d32(0x20, 0)
        elif sub in (4, 8):
            if t2 in (0, 0xA0):
                xx = 0x338 if sub == 4 else 0xFFFFF908 & 0xFFFFFFFF
                yy = 0x1B8
                while True:
                    self._p4_ent43c(0x2C000013, xx & 0xFFFFFFFF, yy)
                    xx += 0x140
                    yy += 0x50 if sub == 4 else -0x50
                    if (xx if sub == 4 else xx) > 0xA18 if sub == 4 else yy < 0:
                        break
            if t2 in (0x50, 0xF0):
                xx = 0x28
                ebx = -0x6F8 & 0xFFFFFFFF
                while True:
                    self._p4_ent43c(0x2C000013, 0x2BC, xx)
                    xx += 0x140
                    if xx > 0xA18:
                        break
        elif sub in (5, 9):
            if (t2 & 1) == 0:
                a = self.p4_rand() % 0x708
                esi = 0x180 - page4_cos(a)
                if t2 < 0x3C:
                    esi += (0x3C - t2) * 8
                if v20 == 0xB:
                    esi = -esi
                esi += self.p4_45a9a0(self.p4_player_x() - x,
                                      self.p4_player_y() - y)
                ang = esi & 0xFFFFFFFF
                c = page4_cos(ang) & 0xFFF
                s_ = page4_sin(ang)
                self._p4_ent43c(0x2C000013, x, y)
        elif sub == 6:
            if (t2 & 0xF) == 0:
                if v20 == 0xD:
                    yy = 0x168 + (0x10 if (t2 & 0x10) else 0)
                else:
                    yy = 0x28 + (self.p4_rand() % 0x190)
                da = self.p4_45a9a0(self.p4_player_x() - 0x2BC,
                                    self.p4_player_y() - yy)
                ang = da & 0xFFFFFFFF
                c = page4_cos(ang) & 0x1FFF
                s_ = page4_sin(ang)
                self._p4_ent43c(0x2C000012, 0x2BC, yy)
        elif sub == 7:
            if (t2 & 0xFF) == 0:
                xx = (0x708 if (t2 & 4) else -0x708) + 0x1F0
                self._p4_ent43c(0x2C000014, xx & 0xFFFFFFFF,
                                (self.p4_rand() & 0x3F) + 0x1E0)
            if t2 == 0x12C:
                nv = v20 + (0x10 if v20 < 0xF else -8)
                e.d32(0x20, nv & 0xFFFFFFFF)
        elif sub == 0xA:
            if t2 in (0, 0xB4):
                xx = 0x258
                yy = 0x218
                ebx = 0x18
                while ebx <= 0xA0:
                    self._p4_ent43c(0x2C000013, xx, yy)
                    self._p4_ent43c(0x2C000013,
                                    (xx - ebx + 0x460) & 0xFFFFFFFF, yy)
                    ebx += 0x28
                    xx -= 0x28
                    yy -= 0x28
                    if ebx > 0xA0:
                        break
                xx2 = 0x258 - 0x78
                yy2 = 0x218 - 0xF0
                while yy2 >= -0x658:
                    self._p4_ent43c(0x2C000013, xx2, yy2)
                    xx2 -= 0x78
                    yy2 -= 0xF0
            if t2 == 0x168:
                e.d32(0x20, (v20 + 1) & 0xFFFFFFFF)
        elif sub == 0xB:
            if (t2 & 0xF) == 0:
                esi = (45 * (t2 >> 4) * 3 * 3) << 1
                if v20 == 0x25:
                    esi = -esi
                ang = esi & 0xFFFFFFFF
                c = page4_cos(ang) & 0x1FFF
                s_ = page4_sin(ang)
                self._p4_ent43c(0x2C000013, x, y)
                ebx = (2 * page4_sin(esi + 0x708) + 0xF0) & 0xFFFF
                edi = x
                self._p4_ent43c(0x2C000012, edi, ebx & 0xFFFFFFFF)
            if t2 == 0x186:
                e.d32(0x20, (v20 + 1) & 0xFFFFFFFF)
    if (t2 & 7) == 0 and sub in (0xA, 0xB):
        self._p4_ent43c(0x2C000014, x, y)
        self._p4_ent43c(0x2C000014, x, y)
    if t2 == 0x168 and sub == 0xC:
        e.d32(0x20, (v20 - 0x1F) & 0xFFFFFFFF)
    return self._p4_407350_tail(e, x, y, v20)


def _p4_407350_tail(self, e, x: int, y: int, v20: int) -> bool:
    """`0x407350` 公共尾：态推进 + HP。"""
    t2 = e.s32(0x24)
    st = e.s32(0x20)
    if st != t2 if False else False:
        pass
    lim = _P4_407350_LIM[min(st, 9)]
    if t2 == lim:
        e.d32(0x24, (t2 + 1) & 0xFFFFFFFF)
    if st != e.s32(0x24):
        e.d32(0x24, 0)
    return e.g32(0x18) != 0


def _s8b(v):
    """byte → 有符号（对应 `movsx ??, byte [...]`）。"""
    v &= 0xFF
    return v - 0x100 if v & 0x80 else v


def _s16(v):
    """word → 有符号（对应 `movsx ??, word [...]`）。"""
    v &= 0xFFFF
    return v - 0x10000 if v & 0x8000 else v


def _c_rem(a, b):
    """C 的 `idiv` 余数（向 0 截断）——Python 的 % 对负数向 −∞ 取整，不能直接用。"""
    r = abs(a) % abs(b)
    return -r if a < 0 else r


def _atan2(a0, a1):
    """0x45A9A0（thunk 0x401091）：atan2 表，单位 1/3600 圈；arg0=dy、arg1=dx。"""
    from page4 import page4_45a9a0          # 复刻侧已有逐字节实现
    return page4_45a9a0(a0, a1)


def _beh_408540(self, e) -> bool:
    """`0x408540`（type 0x2D000018，关 8 真 boss，14 态，跳表 0x409380）。

    返回值：HP != 0 → 1（活）；HP == 0 → 先投放 0x4A000006 再 return 0。
    """
    _eh = id(e) & 0x7FFFFFFF
    self.p4_links[_eh] = e
    q49c = self._p4_q("ui49c")          # 0x4AD49C
    q4cc = self._p4_q("ui4cc")          # 0x4AD4CC
    q52c = self._p4_q("ui52c")          # 0x4AD52C（VM op5 队列 0x445AA0；复刻侧无现成名）

    st = _s8b(e.m[0x1C])                # 0x408550 态号
    rnd = _s8b(e.m[0x1D])               # 0x40855D 轮次
    ang = _s16(e.g16(0x1E))             # 0x408555 相位角
    saved_ang = ang                     # 0x408568 [esp+0x1C]
    pend = st                           # 0x408559 [esp+0x10] “下一个态”

    INC, ADV, ADV2, MOV, TAI = 0x4087EC, 0x4085AC, 0x4085B0, 0x4087F1, 0x4092F8

    # ------------------------------------------------------------------
    # 内部块
    # ------------------------------------------------------------------
    def _set_state_5():
        """0x4085DC：态 5 / 轮 0，并清零相位角。"""
        nonlocal rnd
        rnd = 0
        e.d32(0x1C, 0x00000005)

    def _adv_hi():
        """0x4092A7：pend>4 或 HP 充足时的落地；返回下一个 pc。"""
        nonlocal rnd, pend
        if _s16(pend) <= 9:                              # 0x4092A7 cmp ax,9 / jg
            if rnd == 4 or (e.g32(0x18) & 0xFFFFFFFF) < 0x2580:   # 0x4092AD/0x4092B3（jae）
                # 0x4092BC
                pend = 0x0A                              # 0x4092C0 mov [esp+0x10],esi(0xA)
                rnd = 0
                e.d16(0x24, 0x50)                        # 0x4092CA 目标半径
                e.d32(0x1C, 0x0000000A)                  # 0x4092D0 态 10 / 轮 0 / 角 0
                return MOV
        # 0x4092D8：轮次上限 8，态号取 pend 低字节
        if rnd > 8:                                      # cmp cx,8 / jle
            rnd = 8
        e.d32(0x1C, ((rnd & 0xFF) << 8) | (pend & 0xFF))
        return MOV

    def _ring_particles():
        """0x408CC3：2 轮“自机式”粒子（0x41000004 带速度对 + 0x41000001）。"""
        for _k in range(2):                              # 0x408CC3 [esp+0x18]=2
            a1 = self.p4_rand() % 0xE10                  # 0x408CD8
            a2 = self.p4_rand() % 0x78                   # 0x408CE8
            cv = (int(page4_cos(a1)) * a2 + 0x7F) >> 8   # 0x408CEA..0x408CF8（sar）
            sv = (int(page4_sin(a1)) * a2 + 0x7F) >> 8   # 0x408CFB..0x408D0B
            vx = (cv + 2) >> 2                           # 0x408D02..0x408D0E
            vy = (sv + 2) >> 2                           # 0x408D11..0x408D14
            x = e.s32(0x04) + cv                         # 0x408D2E/0x408D31/0x408D35/0x408D3C
            y = e.s32(0x08) + sv
            # 0x408D34..0x408D6D：0x430400(&rec, x, y, 0x41000004, &(vx,vy)) → 0x4AD4CC
            self.spawn(q4cc, 0x41000004, x, y, (vx & 0xFFFFFFFF, vy & 0xFFFFFFFF))
            # 0x408D76..0x408DB6：0x430400(&rec, x, y, 0x41000001, 0)   → 0x4AD4CC
            self.spawn(q4cc, 0x41000001, x, y, 0)

    # ------------------------------------------------------------------
    # 主循环（用 pc 模拟 0x4087EC / 0x4085AC / 0x4087F1 / 0x4092F8 四处 goto）
    # ------------------------------------------------------------------
    pc = None                            # None = 0x408540 入口分派
    while True:
        # ============================== 入口分派 ==============================
        if pc is None:                                   # 0x408540-0x408577
            if not (0 <= st <= 0xD):                     # 0x408565 cmp/ja（无符号）
                pc = INC
                continue
            pc = st                                      # jmp [eax*4+0x409380]
            continue

        # ============================== 0x4087EC ==============================
        # 帧相位 +1，然后按 [esp+0x10] 决定是否进“转动块”
        if pc == INC:
            ang = (ang + 1) & 0xFFFF                     # 0x4087EC
            e.d16(0x1E, ang)                             # 0x4087ED
            pc = MOV if _s16(pend) >= 1 else TAI         # 0x4087F1 cmp/ jl
            continue

        # ============================== 0x4087F1 转动块 ==============================
        # x = 0x1B80 + cos([0x28])*[0x26]>>4；y = 0xF00 + sin([0x28])*[0x26]>>4；
        # [0x28] -= 4；当 [0x28]&0x3C==0 且 [0x24]!=[0x26] 时半径 ±1 收敛
        if pc == MOV:
            if _s16(pend) < 1:                           # 0x4087F7
                pc = TAI
                continue
            orb = e.s32(0x28)                            # 0x4087FD
            rad = e.g16(0x26)                            # 0x408806 / 0x408810
            cx = int(page4_cos(orb)) * _s16(rad)         # 0x408801/0x40880A imul
            e.d16(0x20, (((cx >> 4) + 0x1B80)) & 0xFFFF)  # 0x40881D
            sy = int(page4_sin(orb)) * _s16(rad)         # 0x408824/0x408829
            orb = (orb - 4)                              # 0x40883A
            e.d16(0x22, (((sy >> 4) + 0xF00)) & 0xFFFF)  # 0x40883D
            e.d32(0x28, orb & 0xFFFFFFFF)                # 0x408841
            diff = _s16(e.g16(0x24)) - _s16(rad)         # 0x408844/0x408848
            if diff == 0:                                # 0x40884C je
                pc = TAI
                continue
            if orb & 0x3C:                               # 0x408852 test cl,0x3c
                pc = TAI
                continue
            if diff <= 0:                                # 0x40885D jle → 0x4092F3
                e.d16(0x26, (rad - 1) & 0xFFFF)
            else:                                        # 0x408863 inc edi
                e.d16(0x26, (rad + 1) & 0xFFFF)
            pc = TAI
            continue

        # ============================== 0x4092F8 公共尾 ==============================
        if pc == TAI:
            x = _s16(e.g16(0x20)) >> 4                   # 0x4092FC/0x409303
            y = _s16(e.g16(0x22)) >> 4                   # 0x4092F8/0x409300
            e.d32(0x08, y & 0xFFFFFFFF)                  # 0x409306
            e.d32(0x04, x & 0xFFFFFFFF)                  # 0x409309
            if e.node is not None:                       # 0x401753 + node+0x14/+0x18
                e.node.dst = (x - 0x78, y - 0x78)
            if (e.g32(0x18) & 0xFFFFFFFF) != 0:          # 0x409325 test eax,eax / jne
                return True
            # 0x40932C..0x409361：0x430400(&rec, x, y, 0x4A000006, e) → 0x4AD4CC
            self.spawn(q4cc, 0x4A000006, x, y, e)
            return False                                 # 0x409369 xor al,al

        # ============================== 0x4085AC 态推进 ==============================
        if pc == ADV:
            pend = (pend + 1) & 0xFFFFFFFF               # 0x4085AC inc
            pc = ADV2
            continue
        if pc == ADV2:
            if (pend & 0xFFFF) == (st & 0xFFFF):         # 0x4085B0 cmp word,dx / je
                pc = INC
                continue
            if _s16(pend) > 4:                           # 0x4085BF cmp ax,4 / jg
                pc = _adv_hi()
                continue
            if rnd != 4 and (e.g32(0x18) & 0xFFFFFFFF) >= 0x4B00:   # 0x4085C9/0x4085CF
                pc = _adv_hi()
                continue
            _set_state_5()                               # 0x4085DC..0x4085F1
            pc = MOV
            continue

        # ============================== 态 0：入场滑入 ==============================
        # 0x40857E：x = (0x1400 + (0x65−ang)^2) & 0xFFFF，y 固定 0x0F00(=240)；
        #           ang==0x65 时推进（下一态 1）
        if pc == 0:
            d = (0x65 - _s16(ang)) & 0xFFFFFFFF          # 0x40857E/0x408581/0x408586
            v = (d * d) & 0xFFFFFFFF                     # 0x40858A imul
            v = (v + 0x1400) & 0xFFFF                    # 0x40858D/0x408593
            e.d32(0x20, v | 0x0F000000)                  # 0x408599/0x4085A3（同时写 y=0x0F00）
            if _s16(ang) != 0x65:                        # 0x40859F/0x4085A6
                pc = INC
                continue
            pc = ADV                                     # 0x4085AC
            continue

        # ============================== 态 1：横排弹幕（0x26C0 固定初速位） ==============================
        # 0x4085F6：ang==0x32A → 推进；否则先造一条 0x33000023 模板记录，再按
        #           (ang % 0x32B) 选表、把表项写进模板 rec+6（= 初速 y 的高字）后逐个入队
        if pc == 1:
            if _s16(ang) == 0x32A:                       # 0x4085F6/0x4085FB
                pc = ADV
                continue
            # 0x4085FD..0x408624：0x4023C4(&rec, e, 0x26C0, 0x33000023, prm)（**不入队**）
            rec0 = e
            rec1 = 0x26C0
            rec3 = ((((rnd + 0xA) << 20) & 0xFFFF0708) | 0x708) & 0xFFFFFFFF
            # 0x40864F：edx = saved_ang % 0x32B
            am = _c_rem(_s16(saved_ang), 0x32B)
            # 表（0x408655..0x4086CE；都是 word 数组，写进 S+0x20..S+0x42）
            tblA = (0x5A, 0xD2, 0x14A, 0x1C2)            # S+0x20
            tblB = (0x3C, 0xB4, 0x12C, 0x1A4)            # S+0x28
            tblC = (0x1E, 0x96, 0x10E, 0x186)            # S+0x30
            tblD = (0x28, 0x78, 0xC8, 0x118, 0x168, 0x1B8)   # S+0x38（6 项）
            # 0x4086DD..0x4087E2：32 轮（ebx 0→0x1C1FF，步 0xE10）；
            # 判据 `(ang%0x32B) == j/0x32B`，而 j/0x32B 恒为 0（0xE6C2B449 magic 是 /0x32B）
            for j in range(32):
                if am != (j // 0x32B):                   # 0x4086F0/0x4086F4
                    continue
                mask = 1 << j                            # 0x408705 shl eax,cl
                tbl = None
                if mask & 0x10100001:                    # 0x408709
                    tbl = tblB
                if mask & 0x20000100:                    # 0x408714
                    tbl = tblC
                if mask & 0x40001000:                    # 0x40871F
                    tbl = tblA
                if mask & 0x404010:                      # 0x40872A
                    tbl = tblD
                if mask & 0x81010000:                    # 0x408735 → 0x40873C 追击支
                    # 用 tblB 倒序 4 项；dy=player_y−v、dx=player_x−0x1F4 求角
                    for v in (0x1A4, 0x12C, 0xB4, 0x3C):  # 0x40873C..0x40878B
                        b = (rec1 & 0xFFFF) | (((v << 4) & 0xFFFF) << 16)   # rec+6（y 高字）
                        a = _atan2(self.p4_player_y() - v,
                                   self.p4_player_x() - 0x1F4) & 0xFFFF
                        d = (rec3 & 0xFFFF0000) | a                     # rec+0xC（prm 低字）
                        self.spawn(q49c, 0x33000023, rec0, b, d)
                    continue
                if tbl is None:                          # edx==0 → 本 j 不生成
                    continue
                # 0x40878F..0x4087CB：条数 = 6（tblD）或 4（其余），**倒序**读表
                for v in reversed(tbl):
                    b = (rec1 & 0xFFFF) | (((v << 4) & 0xFFFF) << 16)   # rec+6
                    self.spawn(q49c, 0x33000023, rec0, b, rec3)
            pc = INC                                     # 0x4087E8 → 0x4087EC
            continue

        # ============================== 态 2：0x33000026 扇形 ==============================
        # 0x408869
        if pc == 2:
            if _s16(ang) == 0x32A:                       # 0x408869/0x40886E
                pc = ADV
                continue
            if _c_rem(_s16(ang), 0x195) == 0:            # 0x408874..0x408881
                # 0x408887..0x4088C7：0x430400(&rec, e, 0, 0x33000026, rnd*4+0x18) → 0x4AD49C
                self.spawn(q49c, 0x33000026, e, 0, (rnd * 4 + 0x18) & 0xFFFFFFFF)
            pc = INC
            continue

        # ============================== 态 3：0x33000028 ==============================
        # 0x4088D1
        if pc == 3:
            if _s16(ang) == 0x194:                       # 0x4088D1/0x4088D6
                pc = ADV
                continue
            if rnd < 2:                                  # 0x4088DF cmp cx,2 / jge
                hit = (_c_rem(_s16(ang), 0xCA) == 0)     # 0x4088E6..0x4088ED
            else:
                hit = (_c_rem(_s16(ang), 0x65) == 0)     # 0x4088F6..0x4088FD
            if hit:
                # 0x408905..0x40893C：0x430400(&rec, e, 0, 0x33000028, 0) → 0x4AD49C
                self.spawn(q49c, 0x33000028, e, 0, 0)
            pc = INC
            continue

        # ============================== 态 4：八向 0x2D00001A 卫队 ==============================
        # 0x408946：ang==0x32A → 轮+1 且回到态 1（pend=1）；ang>0x260 什么都不做
        if pc == 4:
            if _s16(ang) == 0x32A:                       # 0x408946/0x40894B
                pend = 1                                 # 0x40894D
                rnd += 1                                 # 0x408955 inc ecx
                pc = ADV2
                continue
            if _s16(ang) > 0x260:                        # 0x40895B/0x408960 jg
                pc = INC
                continue
            if rnd < 2:
                if _c_rem(_s16(ang), 0x195) == 0:        # 0x408972..0x408979
                    grp = 1
                elif _c_rem(_s16(ang) - 0xCA, 0x195) == 0:   # 0x408AA4..0x408AB4
                    grp = 2
                else:
                    grp = 0                              # 0x408ABA jl
            else:
                if _c_rem(_s16(ang), 0xCA) == 0:         # 0x408982..0x40898B
                    grp = 1
                elif _c_rem(_s16(ang) - 0x65, 0xCA) == 0:    # 0x408AC0..0x408ACD
                    grp = 2
                else:
                    grp = 0
            if grp == 1:
                # 0x408991/0x4089A9、0x4089D3/0x4089EB、0x408A15/0x408A2D、0x408A57/0x408A6F
                for b, d in ((0xF4C00780, 0xF8F80000),
                             (0xF88003C0, 0xF8F80000),
                             (0x078003C0, 0x07080000),
                             (0x0B400780, 0x07080000)):
                    self._p4_ent43c(0x2D00001A, _eh, b, d)
            elif grp == 2:
                # 0x408AD3/0x408AEB、0x408B15/0x408B2D、0x408B57/0x408B6F、0x408B99/0x408BB1
                for b, d in ((0xF4C003C0, 0xF8940000),
                             (0xF8800000, 0xF82A0000),
                             (0x07800000, 0x07D60000),
                             (0x0B4003C0, 0x076C0000)):
                    self._p4_ent43c(0x2D00001A, _eh, b, d)
            pc = INC
            continue

        # ============================== 态 5：开场特效 / 0x61000005 ==============================
        # 0x408BE0
        if pc == 5:
            if _s16(ang) == 0:                           # 0x408BE0 test bx,bx / jne
                # 0x408BE5..0x408C20：0x430400(&rec, 0, 0xFF, 0x61000005, 0x10) → 0x4AD52C
                self.spawn(q52c, 0x61000005, 0, 0xFF, 0x10)
                _ring_particles()                        # → 0x408CC3
                pc = INC
                continue
            if _s16(ang) == 0x18:                        # 0x408C2A
                # 0x408C30..0x408C45：0x45A790(node+4, 0, 0xF0, 0, 0xF0) ⇒ rect += (0,0xF0,0,0xF0)
                if e.node is not None:
                    r = e.node.rect
                    e.node.rect = (r[0], r[1] + 0xF0, r[2], r[3] + 0xF0)
                _ring_particles()
                pc = INC
                continue
            if _s16(ang) == 0x19:                        # 0x408C4F
                # 0x408C55..0x408C90：0x430400(&rec, 0xFF, 0, 0x61000005, -0x10) → 0x4AD52C
                self.spawn(q52c, 0x61000005, 0xFF, 0, 0xFFFFFFF0)
                # 0x408C95..0x408CA8：0x450350(0x4AB4B0, 0x0B, (x-0x140)<<4)
                self.p4_se_pan(0x0B, (e.s32(0x04) - 0x140) << 4)
                _ring_particles()
                pc = INC
                continue
            if _s16(ang) == 0x32:                        # 0x408CAF/0x408CB3
                pc = ADV
                continue
            if _s16(ang) > 0x19:                         # 0x408CB9/0x408CBD jg
                pc = INC
                continue
            _ring_particles()                            # ang in 1..0x17 → 0x408CC3
            pc = INC
            continue

        # ============================== 态 6：随机横坐标 0x33000023 连射 ==============================
        # 0x408DD3
        if pc == 6:
            if _s16(ang) == 0x32A:                       # 0x408DD3/0x408DD8
                pc = ADV
                continue
            if _c_rem(_s16(ang), 0x32) != 0:             # 0x408DDE..0x408DEB
                pc = INC
                continue
            if rnd < 0:                                  # 0x408DF1..0x408DF6
                pc = INC
                continue
            for _i in range(rnd + 1):                    # 0x408DFC ebx = rnd+1
                # 0x408DFF..0x408E51：rec = {e, pos, 0x33000023, 0xE00A8C} → 0x4AD49C
                #   注意 0xE00A8C 是**先 push** 的，所以落在 rec[3]
                pos = ((self.p4_rand() % 0x2800) & 0xFFFF) | 0x1CC00000   # 0x408E09..0x408E1C
                self.spawn(q49c, 0x33000023, e, pos, 0xE00A8C)
            pc = INC
            continue

        # ============================== 态 7：自身 type 复制 ==============================
        # 0x408E5E
        if pc == 7:
            if _s16(ang) == 0x194:                       # 0x408E5E/0x408E63
                pc = ADV
                continue
            if rnd < 2:
                hit = (_c_rem(_s16(ang), 0x32) == 0)     # 0x408E73..0x408E7A
            else:
                hit = (_c_rem(_s16(ang), 0x19) == 0)     # 0x408E83..0x408E8A
            if hit:
                # 0x408E92..0x408EC9：0x430400(&rec, e, 0, 0x2D000019, 0) → 0x4AD43C
                self._p4_ent43c(0x2D000019, e, 0, 0)
            pc = INC
            continue

        # ============================== 态 8：0x33000027（一次） ==============================
        # 0x408ED3
        if pc == 8:
            if _s16(ang) != 0:                           # 0x408ED3 test bx,bx / jne
                if _s16(ang) == 0x32A:                   # 0x408F1E..0x408F23 → 0x4085A6
                    pc = ADV
                else:
                    pc = INC
                continue
            # 0x408ED8..0x408F14：0x430400(&rec, e, 0, 0x33000027, rnd+4) → 0x4AD49C
            self.spawn(q49c, 0x33000027, e, 0, (rnd + 4) & 0xFFFFFFFF)
            pc = INC
            continue

        # ============================== 态 9：0x2D00001C 环 ==============================
        # 0x408F28
        if pc == 9:
            if _s16(ang) == 0x194:                       # 0x408F28/0x408F2D
                pend = 6                                 # 0x408F2F
                rnd += 1                                 # 0x408F37
                pc = ADV2
                continue
            if _s16(ang) != 0:                           # 0x408F3D/0x408F40
                pc = INC
                continue
            # 0x408F46..0x408F5B：步长 = 0x1C2 + (rnd>=2 ? 0x96 : 0)
            step = 0x1C2 + (0x96 if rnd >= 2 else 0)
            a = 0xE1                                     # 0x408F50
            while a < 0xE10:                             # 0x408FA0/0x408FA4/0x408FAA
                # 0x408F65..0x408F9B：0x430400(&rec, e, 0, 0x2D00001C, a) → 0x4AD43C
                self._p4_ent43c(0x2D00001C, _eh, 0, a & 0xFFFFFFFF)
                a += step
            pc = INC
            continue

        # ============================== 态 10：对偶 0x33000023（38*ang 相位） ==============================
        # 0x408FB1
        if pc == 10:
            if _s16(ang) == 0x32A:                       # 0x408FB1/0x408FB6
                pc = ADV
                continue
            if _c_rem(_s16(ang), 3) != 0:                # 0x408FBC..0x408FCB
                pc = INC
                continue
            q = (38 * _s16(ang)) & 0xFFFFFFFF            # 0x408FD1/0x408FD7/0x408FDF
            base = ((rnd + 9) << 20) & 0xFFFFFFFF        # 0x408FE5/0x408FEB
            d1 = (base ^ (_c_rem(q, 0xE10) & 0xFFFF)) & 0xFFFFFFFF     # 0x408FE8..0x408FF4
            # 0x408FF6..0x40902C：b=0x3C026C0
            self.spawn(q49c, 0x33000023, e, 0x3C026C0, d1)
            d2 = (base ^ (_c_rem(0xE10 - q, 0xE10) & 0xFFFF)) & 0xFFFFFFFF   # 0x409035..0x40904A
            # 0x40904C..0x409085：b=0x1A4026C0
            self.spawn(q49c, 0x33000023, e, 0x1A4026C0, d2)
            pc = INC
            continue

        # ============================== 态 11：0x33000026（rnd*4+0x10） ==============================
        # 0x40908F
        if pc == 11:
            if _s16(ang) == 0x32A:                       # 0x40908F/0x409094
                pc = ADV
                continue
            if _s16(ang) > 0x195:                        # 0x40909A/0x40909F
                pc = INC
                continue
            if _c_rem(_s16(ang), 0x65) != 0:             # 0x4090A5..0x4090B2
                pc = INC
                continue
            # 0x4090B8..0x4090F8：0x430400(&rec, e, 0, 0x33000026, rnd*4+0x10) → 0x4AD49C
            self.spawn(q49c, 0x33000026, e, 0, (rnd * 4 + 0x10) & 0xFFFFFFFF)
            pc = INC
            continue

        # ============================== 态 12：0x33000029（远离自机的落点） ==============================
        # 0x409102
        if pc == 12:
            if _s16(ang) == 0x32A:                       # 0x409102/0x409107
                pc = ADV
                continue
            if rnd < 2:
                hit = (_c_rem(_s16(ang), 0x65) == 0)     # 0x409117..0x40911E
            else:
                hit = (_c_rem(_s16(ang), 0x32) == 0)     # 0x409127..0x40912E
            if not hit:
                pc = INC
                continue
            px = self.p4_player_x()
            py = self.p4_player_y()
            n = 0                                        # 0x409136 xor edi,edi
            xv = 0
            while True:                                  # 0x409138 循环：x
                xv = (self.p4_rand() % 0xC8) + 0x3C      # 0x40913D..0x40914C
                lim = px if px < 0x12C else 0x12C        # 0x40914F..0x409156
                if abs(lim - xv) <= 0x50:                # 0x40915B..0x409165
                    break
                n += 1                                   # 0x409167
                if n >= 0x64:                            # 0x409168/0x40916B
                    break
            yv = 0
            while True:                                  # 0x40916D 循环：y
                yv = (self.p4_rand() % 0x168) + 0x3C     # 0x409173..0x409181
                if abs(py - yv) <= 0x78:                 # 0x409184..0x40918E
                    break
                n += 1                                   # 0x409190
                if n >= 0x64:                            # 0x409191/0x409194
                    break
            prm = (((yv & 0xFFFF) << 16) | (xv & 0xFFFF)) & 0xFFFFFFFF   # 0x409196..0x4091A1
            # 0x4091A3..0x4091D1：0x430400(&rec, e, prm, 0x33000029, 0) → 0x4AD49C
            self.spawn(q49c, 0x33000029, e, prm, 0)
            pc = INC
            continue

        # ============================== 态 13：0x2D00001B 铺 12 只 ==============================
        # 0x4091DB
        if pc == 13:
            if _s16(ang) == 0x32A:                       # 0x4091DB/0x4091E0
                pend = 0x0A                              # 0x4091E2 mov [esp+0x10],esi(0xA)
                rnd += 1                                 # 0x4091E6
                pc = ADV2
                continue
            am = _c_rem(_s16(saved_ang), 0x32B)          # 0x4091EC..0x4091F9
            for j in range(32):                          # 0x409203..0x40929C
                if am != (j // 0x32B):                   # 同态 1：j/0x32B 恒为 0
                    continue
                # 0x40921E..0x409242：rand()%0x258 + 0x96
                prm = (self.p4_rand() % 0x258) + 0x96
                # 0x409278：只有 (1<<j) & 0xFFF != 0（j<12）才入队 0x4AD43C
                if ((1 << j) & 0xFFF) != 0:
                    self._p4_ent43c(0x2D00001B, e, 0, prm & 0xFFFFFFFF)
            pc = INC
            continue

        raise AssertionError(f"0x408540: 未处理的分派 pc={pc!r}")   # pragma: no cover


# ===========================================================================
def _beh_4098E0(self, e) -> bool:
    """`0x4098E0`（0x2D00001A，0x408540 铺出的僚机）：**挂主四态**。

    主 = [0x1C] 句柄；主死 → return 0。
    [0x20]==0 且 [0x2C]==0：铺 9 架 0x2D000019 @(主.x, 主.y) 入 0x4AD43C（仅一次）；
    [0x30]==0 → [0x28] = (rand&0x3F−0x1F)&0xFFFF | 0x400000（初始角包）；
    0x32≤[0x30]<0x65 → 0x45AC70(&[0x2A], &[0x28], 8) + 0x45AC70(&[0x24], &[0x28], 0x40)
    （角/距步进追踪主）。
    [0x20]/[0x2C]≠0（脱离态）：[0x2C]==0 → [0x2C] = 360*[0x2C]…（(5*5*9)<<3=1800×v）；
    主活：x = 主.x + sin([0x2C])>>3、y = 主.y + cos([0x2C])>>3、[0x2C] += 0x64；
    主死：[0x20]=0、[0x24] = ((y<<0x10)|(x&0xFFFF))<<4、[0x10]=1、
    [0x28] = (cos([0x2C])>>2 & 0xFFFF) | ((sin([0x2C])>>2 & ~3)<<0xE)。
    自由态：word[0x24] += word[0x28]、word[0x26] += word[0x2A]；
    x=word[0x24]>>4、y=word[0x26]>>4。
    0x409760（0x402478）：node.active 时 按主距自调 node rect 尺寸（近大远小）。
    0x4305F0(e,0x40) 在屏判据；[0x30]++；[0x30]==0（有主）→ 0x4305F0(e,7)；
    return 在屏 且 HP≠0。"""
    links = getattr(self, "p4_links", {})
    main = links.get(e.s32(0x1C) & 0x7FFFFFFF)
    if main is None or main.m[0x34] == 0:
        return False
    v20 = e.s32(0x20)
    v2c = e.s32(0x2C)
    v30 = e.s32(0x30)
    x = e.s32(0x04)
    y = e.s32(0x08)
    if v20 == 0 and v2c == 0:
        if v30 == 0:
            for _ in range(9):
                self._p4_ent43c(0x2D000019, main.s32(0x04), main.s32(0x08))
        a = (self.p4_rand() & 0x3F) - 0x1F
        e.d32(0x28, ((a & 0xFFFF) | 0x400000) & 0xFFFFFFFF)
    elif 0x32 <= v30 < 0x65:
        cur = [e.s32(0x28)]
        tgt = [e.s32(0x2A)]
        self._p4_45ac70(tgt, cur, 8)
        e.d32(0x28, cur[0] & 0xFFFFFFFF)
        e.d32(0x2A, tgt[0] & 0xFFFFFFFF)
        cur2 = [e.s32(0x24)]
        tgt2 = [e.s32(0x28)]
        self._p4_45ac70(tgt2, cur2, 0x40)
        e.d32(0x24, cur2[0] & 0xFFFFFFFF)
        e.d32(0x28, tgt2[0] & 0xFFFFFFFF)
    if v20 != 0 or v2c != 0:
        if v2c == 0:
            e.d32(0x2C, (1800 * v2c if False else 1800 * e.s32(0x2C) if False else
                         (5 * 5 * 9) << 3) & 0xFFFFFFFF)
        if main.m[0x34] != 0:
            a = e.s32(0x2C)
            e.d32(0x04, (main.s32(0x04) + (page4_sin(a) >> 3)) & 0xFFFFFFFF)
            e.d32(0x08, (main.s32(0x08) + (page4_cos(a) >> 3)) & 0xFFFFFFFF)
            e.d32(0x2C, (a + 0x64) & 0xFFFFFFFF)
        else:
            px = e.s32(0x04)
            py = e.s32(0x08)
            a = e.s32(0x2C)
            e.m[0x10] = 1
            e.d32(0x20, 0)
            e.d32(0x24, (((py & 0xFFFF) << 0x10 | (px & 0xFFF)) << 4) & 0xFFFFFFFF)
            c = page4_cos(a) >> 2
            s_ = page4_sin(a) >> 2
            e.d32(0x28, ((c & 0xFFFF) | ((s_ & ~3) << 0xE)) & 0xFFFFFFFF)
    else:
        w28 = e.g16(0x28)
        w2a = e.g16(0x2A)
        w24 = (e.g16(0x24) + w28) & 0xFFFF
        w26 = (e.g16(0x26) + w2a) & 0xFFFF
        e.d16(0x24, w24)
        e.d16(0x26, w26)
        x = ((w24 - 0x8000 if w24 & 0x8000 else w24) >> 4) & 0xFFFFFFFF
        y = ((w26 - 0x8000 if w26 & 0x8000 else w26) >> 4) & 0xFFFFFFFF
        e.d32(0x04, x)
        e.d32(0x08, y)
        e.d32(0x2C, (e.s32(0x2C) + 0x12C) & 0xFFFFFFFF)
    v30 = (v30 + 1) & 0xFFFFFFFF
    e.d32(0x30, v30)
    if v20 != 0 or v2c != 0:
        pass
    elif v30 == 0:
        pass
    return self.p4_4305f0(e, 0x40) and e.g32(0x18) != 0


def _beh_409C20(self, e) -> bool:
    """`0x409C20`（0x2D00001B，0x408540 铺出的侧翼）：**主位缩放 + 环射**。

    主 = [0x1C] 句柄；主死 → return 0；[0x20]≠0 → 主.[0x30]=2（切入态 2）。
    [0x28]==0（待机）：node dst=(x−0x10,y−0x10)；0x409760（缩放）；[0x30]−−<0 → 0。
    [0x30]<0xCA：word[0x2C]/[0x2E] 追主（±0x12C 钳 / 0x40105A 0x30 步）；
    word[0x24/0x26] += word[0x2C/0x2E]（|Δ|²>0x1000 → 0x40105A(0x30)；否则跳）；
    x = 主.x + word[0x24]>>4、y = 主.y + word[0x26]>>4；0x409760。
    [0x20]=0 → 铺 0x2D00001A @(主.x,主.y)（[主 0x20]=返回值）。
    环射（esi=[0x20]=0x20 起 步 0x20 至 0x2A0）：word[0x24/0x26] 半径收缩门
    （|Δ|²>0x90000 → 0x40105A(e) 0x1C0）；ang=[0x2C]：
    cos/sin(ang)*esi 方向 0x2D00001A 卫星（[主 0x20]=返回值、[ebp 0x38].active=1）；
    esi==0x2A0 时 0x33000022 @(打包位<<4) 入 0x4AD49C。
    [0x30]≥0xCA：0x33000022 @(x,y, 0x100E0000|(打包位<<4)) 入 0x4AD49C。
    [0x30]++ < 0xFD → 存活。"""
    links = getattr(self, "p4_links", {})
    main = links.get(e.s32(0x1C) & 0x7FFFFFFF)
    if main is None or main.m[0x34] == 0:
        return False
    v20 = e.s32(0x20)
    if v20 != 0:
        main.d32(0x30, 2)
    v28 = e.s32(0x28)
    x = e.s32(0x04)
    y = e.s32(0x08)
    v30 = e.s32(0x30)
    if v28 == 0:
        if e.node is not None:
            e.node.dst = (x - 0x10, y - 0x10)
        v30 = (v30 - 1) & 0xFFFFFFFF
        e.d32(0x30, v30)
        return 1 if v30 >= 0 else 0
    if v30 < 0xCA:
        w2c = e.g16(0x2C)
        w2e = e.g16(0x2E)
        da = (w2e - 0x10000 if w2e & 0x8000 else w2e) - (w2c - 0x10000 if w2c & 0x8000 else w2c)
        da = max(-0xC, min(0xC, da))
        w2c = (w2c + da) & 0xFFFF
        e.d16(0x2C, w2c)
        w2cs = w2c - 0x10000 if w2c & 0x8000 else w2c
        w2es = w2e - 0x10000 if w2e & 0x8000 else w2e
        dx = w2cs - (e.g16(0x24) - 0x10000 if e.g16(0x24) & 0x8000 else e.g16(0x24))
        dy = w2es - (e.g16(0x26) - 0x10000 if e.g16(0x26) & 0x8000 else e.g16(0x26))
        if dx * dx + dy * dy > 0x1000:
            cur = [e.g16(0x24)]
            tgt = [e.g16(0x26)]
            self._p4_45ac70(tgt, cur, 0x30)
            e.d16(0x24, cur[0] & 0xFFFF)
            e.d16(0x26, tgt[0] & 0xFFFF)
        else:
            e.d16(0x24, w2cs & 0xFFFF)
            e.d16(0x26, w2es & 0xFFFF)
        w24 = e.g16(0x24)
        w26 = e.g16(0x26)
        x = (main.s32(0x04) + ((w24 - 0x8000 if w24 & 0x8000 else w24) >> 4)) & 0xFFFFFFFF
        y = (main.s32(0x08) + ((w26 - 0x8000 if w26 & 0x8000 else w26) >> 4)) & 0xFFFFFFFF
        e.d32(0x04, x)
        e.d32(0x08, y)
        if v20 == 0:
            c = self._p4_ent43c(0x2D00001A, main.s32(0x04), main.s32(0x08))
            c.d32(0x1C, id(main) & 0x7FFFFFFF)
            main.d32(0x20, id(c) & 0x7FFFFFFF)
            links[id(main) & 0x7FFFFFFF] = main
        # 环射
        esi = 0x20
        while esi < 0x2A0:
            w24s = w24 - 0x10000 if w24 & 0x8000 else w24
            w26s = w26 - 0x10000 if w26 & 0x8000 else w26
            if w24s * w24s + w26s * w26s > 0x90000:
                cur3 = [w24s]
                tgt3 = [w26s]
                self._p4_45ac70(tgt3, cur3, 0x1C0)
                w24s = cur3[0]
                w26s = tgt3[0]
            ang = w2cs
            c3 = page4_cos(ang)
            s3 = page4_sin(ang)
            vx = -(c3 * esi)
            vy = -(s3 * esi)
            lim = min(esi, 0xC0)
            cur4 = [vx]
            tgt4 = [vy]
            self._p4_45ac70(tgt4, cur4, lim)
            vx = cur4[0]
            vy = tgt4[0]
            if v20 == 0:
                c5 = self._p4_ent43c(0x2D00001A, main.s32(0x04), main.s32(0x08))
                main.d32(0x20, id(c5) & 0x7FFFFFFF)
            mx = main.s32(0x04) + (vx >> 4)
            my = main.s32(0x08) + (vy >> 4)
            self._p4_ent43c(0x2D00001A, mx, my)
            esi += 0x20
            if esi >= 0x2A0:
                a = self.p4_45a9a0(-vx, -vy)
                pack = ((mx & 0xFFF) | ((my & 0xFFFF) << 0x10)) << 4
                self.spawn(self._p4_q("ui49c"), 0x33000022, x, y, pack & 0xFFFFFFFF)
    else:
        pack = ((x & 0xFFF) | ((y & 0xFFFF) << 0x10)) << 4
        self.spawn(self._p4_q("ui49c"), 0x33000022, x, y,
                   (0x100E0000 | pack) & 0xFFFFFFFF)
    v30 = (v30 + 1) & 0xFFFFFFFF
    e.d32(0x30, v30)
    return v30 < 0xFD


def page4_cos(ang: int) -> int:
    """0x45ABB0：查表余弦（p4_sin_q 的 cos 侧包装，供锁定准星螺旋用）。"""
    return p4_sin_q(ang, "cos")


def page4_sin(ang: int) -> int:
    """0x45AAF0：查表正弦。"""
    return p4_sin_q(ang, "sin")


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
                e.node.active = 1          # 0x446627 byte[节点+0x1C]=1（渲染读 .active）
        elif t == 0x28:
            if not bool(getattr(self, "_p4_busy", 1)):
                return False
        elif t == 0x78:
            p4_446540(self, e)
            e.d32(0x10, 1)
        elif t == 0x12C:
            if e.node is not None:
                e.node.active = 1          # 0x446662
            self.p4_ccc2 = 0
        elif t > 0x78 and e.node is not None:
            e.node.active = t & 1          # 0x44667B 闪烁
    # 0x44667E `inc dword [esi+0x20]`：**读改写内存**。旧实现用循环开头读的局部 t
    # （t 可能被上面的 -1 分支改成 0x12D）⇒ 末尾又写成 t+1=0，把 0x12D 覆盖回 0
    # ⇒ 入场计时从 0 重跑、t==0x78 再调一次 0x446540（type 5/8 伴随体重复生成，
    # 漢的狙击光标因此出现两个），且漢的 +0x20==0 首帧发射条件被再次满足。
    e.d32(0x20, (e.s32(0x20) + 1) & 0xFFFFFFFF)
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
    | `0x446C50` 鼠标撃 | 有 | 无 | 无 | `(1,1)` 开火 / 无 0 号 | 0x1E（仅当 `[0x56CC9C]==0`） |
    | `0x446D30` 鼠标凛 | 有 | 有 | 无 | `(1,1)` 开火 / `(0,1)` 释放 | 0x1E |
    | `0x446E20` 鼠标漢 | 无（用 `[+0x20]==0`） | 无 | `=[0x56CC98]!=[0x56CCA0]` | `(0,1)` | 0x3C（仅当 `[0x56CC98]==[0x56CCA0]`） |
    | `0x446F10` 鼠标槽3 | 有 | 有 | `=1` | `(1,1)` 开火 / `(0,1)` 释放 | 无 |
    | `0x447000` 键盘撃 | 有 | 无 | 无 | `(1,1)` 开火 + `0x45F530(0)` 清连击 / `(0,1)` 释放 | 0x1E（仅当 `[0x56CC9C]==0`） |
    | `0x447110` 键盘凛 | 有 | 有 | 无 | `(1,1)` 开火 / `(0,1)` 释放 | 0x1E |
    | `0x447200` 键盘漢 | 无（用 `[+0x20]==0`） | 无 | `=[0x56CC98]!=[0x56CCA0]` | `(0,1)` 开火 / `(0,1)` 释放沿（无门） | 0x3C（仅当 `[0x56CC98]==[0x56CCA0]`） |
    | `0x447320` 键盘槽3 | 有 | 有 | `=1` | `(1,1)` 开火 / `(0,1)` 释放 | 无 |
    """
    sub = e.p.get("sub")                     # 0x446C5E ebp = [ebx+0x1C]
    s98 = self.p4_stat.get(0x56CC98, 0)
    sa0 = self.p4_stat.get(0x56CCA0, 0)

    def fire(a: int, b: int) -> None:
        if sub is None:
            return
        # 0x446C78 / 0x446D61 / 0x446E5F / 0x446F4B：位置取子对象，第 5 字段传父指针
        cur = self.spawn(self._p4_q("ui46c"), 0x10008041,
                         sub.s32(0x04), sub.s32(0x08), sub)
        self.p4_lock_ctor(cur, (sub.s32(0x04), sub.s32(0x08), 0x10008041,
                                id(sub) & 0xFFFFFFFF))       # 0x42DABC ctor 落字段
        cur.p["sub"] = sub
        import page4 as _p4m
        _p4m.p4_446470(self, sub, a, b)                       # 0x401AA5 → 0x446470（预设切换）
        self.p4_stat[0x446470] = self.p4_stat.get(0x446470, 0) + 1   # 记账

    def raise_floor(v: int) -> None:
        if sub is not None and sub.s32(0x30) < v:                # 0x446CE1 / 0x446DD3 / 0x446EC3
            sub.d32(0x30, v)

    def preset(a: int, b: int) -> None:
        """裸 `0x401AA5 → 0x446470(sub, a, b)`（预设切换，**不发**光束）。"""
        if sub is None:
            return
        import page4 as _p4m
        _p4m.p4_446470(self, sub, a, b)
        self.p4_stat[0x446470] = self.p4_stat.get(0x446470, 0) + 1

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

    if variant == "kb_e20":                                       # 0x447200（键盘漢）
        self.p4_stat[0x56CC94] = 1 if s98 != sa0 else 0           # 0x44720E..0x44721A
        if e.g32(0x20) == 0:                                      # 0x447220
            fire(0, 1)                                            # 0x447263
            e.d32(0x20, 1)                                        # 0x44726E
        if self.p4_btn1_edge() and self.p4_stat.get(0x56CCA0, 0):  # 0x44727C..0x447288
            self.p4_stat[0x56CC94] = 1                            # 0x447290
            if self.p4_stat.get(0x56CC98, 0) == self.p4_stat.get(0x56CCA0, 0):
                raise_floor(0x3C)                                 # 0x4472A7
        if self.p4_btn1_release():                                # 0x4472BE：仅释放沿，
            preset(0, 1)                                          # 0x4472C7（无 [+0x20]/sub 亡门）
        return bool(sub is not None and sub.g32(0x34))            # 0x4472D2

    if variant == "kb_c50":                                       # 0x447000（键盘撃）
        if self.p4_btn1_edge():                                   # 0x4AB597
            fire(1, 1)                                            # 0x447052
            # 0x44705E 0x40164F→0x45F530(0x4CD4A0,0)：ax=0 ⇒ byte[+0x2A]=0 清连击
            self.p4_stat[0x4CD4A0 + 0x2A] = 0
            e.d32(0x20, 1)                                        # 0x447064
        if e.g32(0x20):                                           # 0x44706C
            if self.p4_btn1_release() or (sub is not None and not sub.g32(0x34)):
                preset(0, 1)                                      # 0x447089
                if self.p4_stat.get(0x56CCA0, 0):                 # 0x44708E
                    if (not self.p4_stat.get(0x56CC9C, 0)
                            and sub is not None and sub.s32(0x30) < 0x1E):
                        sub.d32(0x30, 0x1E)                       # 0x4470AC
                    self.p4_stat[0x56CC94] = 1                    # 0x4470AF
                e.d32(0x20, 0)                                    # 0x4470B6
        return bool(sub is not None and sub.g32(0x34))            # 0x4470BD

    if variant in ("kb_d30", "kb_f10"):                           # 0x447110 / 0x447320
        if variant == "kb_f10":
            self.p4_stat[0x56CC94] = 1                            # 0x447331 入口置位
        btn = self.p4_btn1_edge()
        if self.p4_stat.get(0x56CC98, 0):                         # 0x44712A / 0x447341 屏蔽
            btn = False
        if btn:
            fire(1, 1)                                            # 0x44716B / 0x447385
            e.d32(0x20, 1)
        if e.g32(0x20):                                           # 0x447179 / 0x447393
            if self.p4_btn1_release() or (sub is not None and not sub.g32(0x34)):
                preset(0, 1)                                      # 0x447196 / 0x4473B0
                if self.p4_stat.get(0x56CCA0, 0):                 # 0x44719B / 0x4473B5
                    self.p4_stat[0x56CC94] = 1                    # 0x4471A4 / 0x4473BE
                    if variant == "kb_d30" and sub is not None and sub.s32(0x30) < 0x1E:
                        sub.d32(0x30, 0x1E)                       # 0x4471B7（kb_f10 无 raise）
                e.d32(0x20, 0)                                    # 0x4471BA / 0x4473C5
        return bool(sub is not None and sub.g32(0x34))            # 0x4471C1 / 0x4473CC

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
                preset(0, 1)                                     # 0x446DB0 / 0x446F9A 0x446470(sub,0,1)
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


def _beh_447000(self, e) -> bool:
    """`0x447000`：激光族键盘撃（开火附加 0x45F530(0) 清连击、释放回预设）。见 `p4_laser`。"""
    return p4_laser(self, e, "kb_c50")


def _beh_447110(self, e) -> bool:
    """`0x447110`：激光族键盘凛（`[0x56CC98]` 屏蔽 + 释放回预设 + raise 0x1E）。见 `p4_laser`。"""
    return p4_laser(self, e, "kb_d30")


def _beh_447200(self, e) -> bool:
    """`0x447200`：激光族键盘漢（一次性开火 + 按住锁定 + 释放沿回预设）。见 `p4_laser`。"""
    return p4_laser(self, e, "kb_e20")


def _beh_447320(self, e) -> bool:
    """`0x447320`：激光族键盘槽3（入口置位 + 屏蔽 + 释放回预设、无 raise）。见 `p4_laser`。"""
    return p4_laser(self, e, "kb_f10")


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
    0x448C87 if ([节点+4]（rect.l） != 0) {            ; 可见：只做飞翼动画
    0x448C8C   if ((t & 0xF) == 0) 0x45A790(节点+4, -0x20,0,-0x20,0)  ; 源矩形左移一格
    0x448CA5   if ([节点+4] == 0) 0x45AF60(0x56CCC0, 1) ; 动画走到 0 → 清 0x56CCC0 bit0
    0x448CBC   return 1 }                             ; ⚠ 此分支**不开火不移动**
    0x448CC1 rect.l == 0（动画完毕/重生）→ 每帧采纳指针：
           if (0x45AFF0(0x56CCC0,7)) return 1        ; 开始键位仍置着就等
           x = [0x4AB59C]; y = [0x4AB5A0]; [ent+4/8] = x/y
           if (x>0x1BE) x=0x1BE, 0x44E470(0x4AB454,x,y)   ; 钳 446 并回写指针
           if (y>0x190) y=0x190, 0x44E470(0x4AB454,x,y)   ; 钳 400
           [0x56CC8C]/[0x56CC90] = (x,y)；节点 dst = (x+0x40, y)
           0x448D4F if (byte[0x4AB594]（btn0 原始按住） && !0x45AFF0(0x56CCC0,0x10))
               生成 0x1B000001 于 (x+0x13, y) 入 0x4AD46C      ; ★ 开火
           if ([ent+0x18]（HP）) return 1
           if (--[ent+0x20]) { 0x448FF0(rec(200,200,0x0B000001,命数)) 入 0x4AD40C; return 0 }
           else { 0x45AF30(0x56CCC0,0x40); return 0 }
    ```
    开火读的是**输入记录 byte0**（[0x4AB594]，C/左键按住），不是 0x56CCC0 的位
    （bit0 只在 ctor 置位、动画完成时清位，见 0x4460F9/0x448CAC）。
    """
    t = (e.s32(0x1C) + 1) & 0xFFFFFFFF
    e.d32(0x1C, t)
    node = e.node
    if node is None:
        return True
    if node.rect[0] != 0:                             # 0x448C87 可见：飞翼动画
        if (t & 0xF) == 0:
            self.p4_anim_step(e)                      # 0x45A790 源矩形左移一格
        if node.rect[0] == 0:                         # 0x448CA5 动画到达 0
            self.p4_key_reset(1)                      # 0x45AF60(0x56CCC0,1) 清 bit0
        return True
    if self.p4_key_test(7):                           # 0x448CC1 开始键位
        return True
    x, y = self.p4_ptr()
    if x > 0x1BE:                                     # 0x448CE5 钳 446
        x = 0x1BE
        self.p4_ptr_set(x, y)                         # 0x44E470
    if y > 0x190:                                     # 0x448D00 钳 400
        y = 0x190
        self.p4_ptr_set(x, y)
    e.d32(0x04, x)
    e.d32(0x08, y)
    self.p4_player_pos = (x, y)                       # 0x448D28 [0x56CC8C]/[0x56CC90]
    if node is not None:
        node.dst = (x + 0x40, y)                      # 0x448D3E
        node.active = 1
    if getattr(self.inp.rec, "b0", 0) and not self.p4_key_test(0x10):   # 0x448D4F
        e2 = self.spawn(self._p4_q("ui46c"), 0x1B000001, x + 0x13, y)   # 0x448D68..0x448D9E
        # ctor 0x42DF84 支（0x42D787 大 ctor 的 0x1B000001 叶子）：
        # 0x430400 把 rec 拷进实体：rec[0]→[+4]、rec[1]→[+8]（UiEntity.spawn 不代写，
        # fx12_spawn 同款显式补——碰撞 0x4306C0 读的就是这两个字段）
        e2.d32(0x04, (x + 0x13) & 0xFFFFFFFF)
        e2.d32(0x08, y & 0xFFFFFFFF)
        e2.d32(0x14, 0x1B000001)              # 0x430480 [+0x14]=类型（碰撞分派读原始字段；
                                              #   UiEntity.spawn 不代写——fx12_spawn 同款显式补）
        e2.d32(0x0C, 0x10)                    # 0x42DFB3 [+0xC] = 0x10（碰撞半径）
        e2.d32(0x10, 1)                       # 0x42DFBA byte[+0x10] = 1（参与碰撞）
        e2.d32(0x18, 1)                       # 0x42DFBD [+0x18] = 1（HP）
        e2.beh = "bullet_1b"                  # 0x42DFAC [+0x40] = 0x4018DE → 0x430080
        from geki import DisplayNode
        # 节点：层 0（0x42D7B5 xor ebp,ebp ⇒ 0x42DFC1 mov [eax],ebp = 0，bm_cm48）、
        # src (0xC0,0x30,0xDD,0x4F)（0x45A750）、dst = (rec0+0x40, rec1)（0x42DFF0）、可见
        e2.disp = DisplayNode(layer=0, rect=[0xC0, 0x30, 0xDD, 0x4F],
                              dst=[x + 0x13 + 0x40, y])
        e2.disp.active = 1                    # 0x42E015 byte[node+0x1C] = 1
        self.p4_key_raw_set(0x10)             # 0x42E00D 0x401E1F→0x45AF30(0x56CCC0,0x10) 开火中
    if e.g32(0x18):
        return True
    n = (e.s32(0x20) - 1) & 0xFFFFFFFF              # 0x448DAE 剩余命数
    e.d32(0x20, n)
    if n:
        self._p4_ent_into(self.actorq, 0x0B000001, 0xC8, 0xC8, n,
                          beh=0x448C70)               # 0x448DB9 重生（命数递减）
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
        self.p4_43B150(e, 0)                   # 0x40E482 → 0x401D6B = 0x43B150（双发 V 形）
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
    if e.node is not None:                                # 0x40E2B4 0x45A690 恒等 → 节点 dst
        e.node.dst = ((e.s32(0x04) - 0x18) & 0xFFFFFFFF,
                      (e.s32(0x08) - 0x18) & 0xFFFFFFFF)
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
# 0x41 族各型的行为 thunk → 真地址（0x428C70 各 case 的 [e+0x40] 赋值）
P4_41_BEH_THUNK = {
    0x401B95: 0x430550,   # 通用粒子（0x41000001/08/0B/0F/15/16/17/18/19 共用）
    0x40200E: 0x429D40,   # 碰撞火花（0x41000004）
    0x401019: 0x429DE0,   # 锁定碎片（0x41000005）——2026-11-14 直读 thunk 勘误（旧 0x42BA40）
    0x402275: 0x429E60,   # 锁定圈（0x41000006）——2026-11-14 直读 thunk 勘误（旧 0x42C4D0）
    0x401447: 0x42BEE0,   # 数字板（0x4100000C）
    0x401172: 0x42C7B0,   # 放大窗（0x4100000D/0E）
}

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

# 0x42C4D0（pod ctor）的 12-thunk 表按"变体×选机"取行：0x1000001→thunks[选机]、
# 0x1000002→thunks[4+选机]、0x1000003→thunks[8+选机]；thunk 解引用后恰与
# P4_SPAWN_SLOTS 的 12 项一一对应（thunk 序 → 槽号 [0,1,2,3,4,5,6,8,10,11,7,9]）。
# rec[3]（=pod 的 [+0x20]）在 0x446540 里是 ship/5/8——5/8 作为 owner 指针在 exe
# 语义下必崩，真实再赋值点未解（§15）；复刻侧 owner 一律取自机本体（功能等价：
# 弹幕从自机位置发出、按住攻击键按各槽节奏连发）。
P4_POD_BEH = (
    (0x42C810, 0x42CC50, 0x42D070, 0x42D370),   # 0x1000001：撃/凛/漢/(选机3)
    (0x42C8F0, 0x42CD70, 0x42D150, 0x42D4A0),   # 0x1000002
    (0x42CA70, 0x42CEF0, 0x42D260, 0x42D6A0),   # 0x1000003
)


def _p4_slot_behaviour(spec):
    """生成一个槽行为（12 项表共用骨架，§16.181）。"""
    thr, shots, mode = spec

    def beh(self, e) -> bool:
        e.d32(0x1C, (e.s32(0x1C) + 1) & 0xFFFFFFFF)          # 0x42CA7D 帧计数
        t = e.s32(0x1C)
        owner = e.p.get("owner")                             # 0x42CA7A ebp=[+0x20]
        if getattr(self.inp.rec, "b0", 0) and owner is not None:   # 0x42C821 byte[0x4AB594] 原始按键
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


P4_TYPE5_BEH = (0x40197E, 0x401FBE, 0x4023B5, 0x401960,
                0x40189D, 0x401438, 0x401ECE, 0x401FC3)   # 0x445E4E..0x445E86

P4_PLAYER_BEH = (0x4466F0, 0x4467D0, 0x446890, 0x446950,
                 0x446A10, 0x446AD0, 0x446B50, 0x446BD0)   # 0x445ED5..0x45F015


# ---- 0x51 族：死亡→继续→结算演出（ctor 0x422EF0 / 跳表 0x4234D0，本轮逐函数读定）----
# 交接文档把它叫"开场演出族"是误名：0x51000002 由死亡链 0x460D78 生成（勘误 A-页4-2），
# case 0 = 结算计数（0x45F710 把剩余量换算进 0x4CD4A0+4 得分），case 1 = 继续画面总控。
P4_51_BEH_THUNK = {
    0x51000001: 0x4019EC,   # → 0x423A40  结算计数（ctor case 0 = 0x423027）
    0x51000002: 0x402504,   # → 0x423B30  继续总控（ctor case 1 = 0x42319C）
    0x51000004: 0x40169A,   # → 0x423EE0  结果推进（ctor case 3 = 0x423304）
    0x51000005: 0x4022F7,   # → 0x430520  倒数面板（ctor case 4 = 0x4233BB）
    0x51000006: 0x4022F7,   # → 0x430520  倒数面板（ctor case 5 = 0x4233E3）
    0x51000007: 0x4021A8,   # → 0x424290  卫星格（ctor case 6 = 0x42343D）
    0x5100000A: 0x40173F,   # → 0x423980  波纹（ctor case 9 = 0x422F13）
}
P4_51_BEH = {k: v for k, v in {
    0x51000001: 0x423A40, 0x51000002: 0x423B30, 0x51000004: 0x423EE0,
    0x51000005: 0x430520, 0x51000006: 0x430520, 0x51000007: 0x424290,
    0x5100000A: 0x423980,
}.items() if v in (0x423A40, 0x423B30, 0x423EE0, 0x430520, 0x424290, 0x423980)}

# 0x423B30 状态字节表 0x423D84（0x97 项；实测非 5 项只有这 5 个 ⇒ t = i+0x1E）
P4_423D84_STATES = {0: 0, 5: 1, 20: 2, 90: 3, 150: 4}


def _beh_430520(self, e) -> bool:
    """`0x430520`（0x51000005/06 行为，thunk 0x4022F7）：`[+0x1C]` 倒数，减到 0 前的
    那次返回 0 摘链；ctor 置 `[+0x1C] = -1` ⇒ 永生，只能被外部杀死。"""
    t = e.s32(0x1C)
    e.d32(0x1C, (t - 1) & 0xFFFFFFFF)          # 0x430525 lea edx,[eax-1] / 0x430528 存
    return t != 0                              # 0x43052B je（原值为 0 ⇒ 死）


def _beh_423B30(self, e) -> bool:
    """`0x423B30`（0x51000002 继续总控，thunk 0x402504）：t = ++[+0x1C]，
    t-0x1E ∈ [0,0x96] 查 byte[0x423D84+t-0x1E] → jmp [0x423D6C+state*4]。"""
    t = (e.s32(0x1C) + 1) & 0xFFFFFFFF
    e.d32(0x1C, t)
    i = t - 0x1E
    st = P4_423D84_STATES.get(i, 5) if 0 <= i <= 0x96 else 5
    if st == 0:                                    # 0x423B5D（t=30）
        # 0x460EC0 = [0x4CD590+0x3C]；非 0 且 [esi+0x20]==0 → byte[0x56CCB4]=1
        if self.p4_stat.get(0x4CD590 + 0x3C, 0) != 0 and e.s32(0x20) == 0:
            self.p4_stat[0x56CCB4] = 1             # 0x423B7B（0x451630 进场帧循环的门）
        return True
    if st == 1:                                    # 0x423B89（t=35）
        # 0x460EA0 = [0x4CD590+0x30]（剩余命）：非 0 且 param==0 → 清 0x56CC84 的 0x10 并自尽
        # （0x45B010 是 `ret 4` 空函数，0x423BAD 调它等于什么都不做）
        if self.p4_stat.get(0x4CD590 + 0x30, 0) != 0 and e.s32(0x20) == 0:
            self.sysf.bits &= ~0x10                # 0x423BAD 0x402400→0x45AF60 清位
            return False                           # 0x423BB3 xor al,al
        return True
    if st == 2:                                    # 0x423BBA（t=50）
        if e.s32(0x20) == 0:
            # 0x423BC5 0x430400(&rec,0x7F,0,0x61000007,-8) → 0x445AA0(0x4AD52C)
            self.p4_spawn52c_flash(0x7F, 0, 0x61000007, -8)
        return True
    if st == 3:                                    # 0x423C01（t=120）
        # 0x45AFC0(0x4AB5B8,0x1FC0000)/0xFE000000 → *4-0xC8 → 0x44CDF0(mgr,1,…)
        w = self.p4_cfg_word()
        a, b = self.p4_451630_adjust(w) if w else (0, 0)
        self.p4_load_palette(1, b * 4 - 0xC8, a * 4 - 0xC8)
        if e.node is not None:
            e.node.active = 1                      # 0x423C45 byte[node+0x1C]=1
        self.p4_448f50()                           # 0x423C49 清 0x4AD40C
        self.p4_4301f0()                           # 0x423C53 清 0x4AD46C
        return True
    if st == 4:                                    # 0x423C60（t=180）
        if not self.p4_btn0_edge():                # byte[0x4AB596]==0 → 0x423D5C
            e.d32(0x1C, 0xB3)                      # 停在 179，下帧再判
            return True
        leave = self.keys.field(0xC000) == 3        # 0x423C7F 选中槽 3
        if not leave:
            leave = (self.p4_sys_bits() & 0x2000) != 0   # 0x423C8F 0x45AFC0(0x56CCB8,0x2000)
        if not leave:
            if self.p4_stat.get(0x56CCB5, 0):      # 0x423CA1 回放模式：无条件生成
                self.p4_51_spawn(0, 0, 0x51000004, 0)
            else:
                # 0x45FA30(0x4CD4A0)（演出状态机判定）与 0x460EE0(=[+0x40]) 任一不过 → 离页
                if not self.p4_45fa30() or self.p4_stat.get(0x4CD590 + 0x40, 0) != 0:
                    leave = True
                else:
                    self.p4_51_spawn(0, 0, 0x51000004, 0)   # 0x423CF7..0x423D23
        if leave:
            self.flags.set(0x10000)                # 0x423D34 0x45AF30(0x4AB5C0,0x10000)
        self.sysf.bits &= ~0x10                    # 0x423D40 清 0x10
        self.sysf.bits |= 0x80                     # 0x423D4F 置 0x80
        return False                               # 0x423D55
    return True                                    # 0x423D63 空状态/越界


def _beh_423A40(self, e) -> bool:
    """`0x423A40`（0x51000001 结算计数，thunk 0x4019EC）：`[+0x30]` 门开启后
    两路计数 `[+0x20]/[+0x24]` 每帧各减 1 并把 `[+0x28]/[+0x2C]` 各加 0xC8；
    btn0 按下沿时未走完的余量一次补进（×200），双 0 则结算（0x45F710）并自尽。"""
    if e.s32(0x30) != 0:                           # 0x423A45 [esi+0x30] 门
        if e.s32(0x20) != 0:                       # 0x423A4A
            e.d32(0x20, (e.s32(0x20) - 1) & 0xFFFFFFFF)
            e.d32(0x28, (e.s32(0x28) + 0xC8) & 0xFFFFFFFF)
        if e.s32(0x24) != 0:                       # 0x423A62
            e.d32(0x24, (e.s32(0x24) - 1) & 0xFFFFFFFF)
            e.d32(0x2C, (e.s32(0x2C) + 0xC8) & 0xFFFFFFFF)
        if self.p4_btn0_edge():                    # 0x423A75 byte[0x4AB596]
            if e.s32(0x20) == 0 and e.s32(0x24) == 0:
                self.p4_45f710()                   # 0x423A8E 计数换分 + HUD 重建
                self.sysf.bits &= ~0x4             # 0x423A9A 0x402400→0x45AF60 清 bit4
                return False                       # 0x423A9F
            # 0x423AA3：剩余量 ×200 一次补进（eax = 减完后的 [+0x20]，[+0x24] 同式）
            r20, r24 = e.s32(0x20), e.s32(0x24)
            e.d32(0x28, (e.s32(0x28) + r20 * 0xC8) & 0xFFFFFFFF)
            e.d32(0x20, 0)
            e.d32(0x2C, (e.s32(0x2C) + r24 * 0xC8) & 0xFFFFFFFF)
            e.d32(0x24, 0)
    self.p4_423820(e.s32(0x28), 0x90)              # 0x423AD9 数字分解绘制
    self.p4_423820(e.s32(0x2C), 0xF0)              # 0x423AE9
    return True


def _beh_423EE0(self, e) -> bool:
    """`0x423EE0`（0x51000004 结果推进，thunk 0x40169A）：**无自增**——
    `[ebp+0x1C]` 由 ctor case 3 置 0 起步，态 0 置 1、卫星格锁定时置 2、
    态 2 置 3、态 3 置 4；≤4 查跳表 0x4241B4（5 态），>4 返回 1。"""
    t = e.s32(0x1C)
    if t > 4:
        return True                                # 0x423EF1 ja
    if t == 0:                                     # 0x423EFE：铺结果面板
        # 0x61000007 @ (0,0x7F) param 0x7F → 52C；0x51000005/06 带父指针 → 4FC；
        # 0x51000007 ×10 @ (0x104+24i, 0xC0) param=&{this,0} → 4FC
        self.p4_spawn52c_flash(0, 0x7F, 0x61000007, 0x7F)
        self.p4_51_spawn(0x8C, 0xC0, 0x51000005, e)   # param = 父实体（0x423F4C push ebp）
        self.p4_51_spawn(0x68, 0xF0, 0x51000006, e)
        for i in range(10):                        # 0x423FB7..0x424018
            self.p4_51_spawn(0x104 + 24 * i, 0xC0, 0x51000007, e)
        e.d32(0x1C, 1)                             # 0x42401B → 下帧从态 1 开始
        return True
    if t == 1:                                     # 0x42402D：光标选格
        if self.p4_btn0_edge() and e.s32(0x20) < 0xA:
            e.d32(0x20, (e.s32(0x20) + 1) & 0xFFFFFFFF)
        if self.inp.rec.e1 and e.s32(0x20) > 0:    # 0x424042 byte[0x4AB597]
            e.d32(0x20, (e.s32(0x20) - 1) & 0xFFFFFFFF)
        x = self.inp.x & 0xFFFFFFFF                # 0x424056 [0x4AB59C]
        y = self.inp.y & 0xFFFFFFFF
        e.d32(0x04, x)
        e.d32(0x08, y)
        if x >= 0x198:                             # 0x424064：钳到 0x197 并回吸指针
            e.d32(0x04, 0x197)
            self.p4_44e470(0x197, y)               # 0x424082 0x44E470(mgr,0x197,y)
        if y >= 0x5F:                              # 0x424087
            e.d32(0x08, 0x60)
            self.p4_44e470(e.s32(0x04), 0x5F)      # 0x42409F 0x44E470(mgr,x,0x5F)
        if e.node is not None:
            e.node.dst = (e.s32(0x04) + 0x5C, e.s32(0x08) + 0xE4)   # 0x4240AA..0x4240C3
        return True
    if t == 2:                                     # 0x4240D2：藏节点、清计数、进态 3
        if e.node is not None:
            e.node.active = 0                      # byte[node+0x1C]=0
        e.d32(0x24, 0)
        e.d32(0x28, 0)
        e.d16(0x2C, 0)
        e.d32(0x1C, 3)
        return True
    if t == 3:                                     # 0x424101：回放落盘 + 起淡出
        self.p4_45f850(e.s32(0x24), e.s32(0x28), e.g16(0x2C))   # 0x424122（录制门内才写盘）
        # 0x424127 0x430400(&rec, 0, 0xFFFFFF01, 0x61000005, -1)
        # ⇒ 0x61000005：(cur=0, target=-255, step=-1) = 结果画面淡出到黑
        self.p4_spawn52c_flash(0, -255, 0x61000005, -1)
        e.d32(0x1C, 4)                             # 0x42413D
        e.d32(0x24, 0x100)                         # 0x424169 态 4 的帧计数
        return True
    # t == 4：0x42417B —— 每 4 帧按 [ebp+0x24]>>1 调 0x44FCC0（DMusic 速度），计满 0x100 离页
    v = e.s32(0x24)
    if (v & 3) == 0:
        self.p4_44fcc0(v >> 1)                     # 0x42418A（复刻侧记日志）
    v = (v - 1) & 0xFFFFFFFF
    e.d32(0x24, v)
    if v == 0:
        self.flags.set(0x10000)                    # 0x4241A2
    return True


def _beh_424290(self, e) -> bool:
    """`0x424290`（0x51000007 卫星格，thunk 0x4021A8）：无自有计时，每帧按
    **父实体**（ctor case 6 从 param 解出的指针，存 `e.p51_parent`）的状态镜像。"""
    p = getattr(e, "p51_parent", None)
    if p is None:
        return True
    pst = p.s32(0x1C)                              # 0x42429B [parent+0x1C]
    if pst == 1:                                   # 0x4242E0
        if p.s32(0x20) < e.s32(0x20):              # 0x4242E6 jge
            e.d32(0x04, 0x198)
            e.d32(0x08, 0x90)
        elif p.s32(0x20) == e.s32(0x20):
            e.d32(0x04, p.s32(0x04))               # 0x4242FD
            e.d32(0x08, (p.s32(0x08) + 0x48) & 0xFFFFFFFF)
    elif pst == 3:                                 # 0x4242AA（dec 2 == 0）
        if self.p4_btn0_edge():                    # 0x42430C byte[0x4AB596]
            # 0x424315：x/y 各 (v+0xC)/0x18*24 吸到 24 格
            qx = ((e.s32(0x04) + 0xC) // 0x18) * 0x18
            qy = ((e.s32(0x08) + 0xC) // 0x18) * 0x18
            e.d32(0x04, qx)
            e.d32(0x08, qy)
            if qx == 0x198 and qy == 0xA8:         # 0x424353/0x424355
                e.d32(0x04, 0x198)
                e.d32(0x08, 0x90)
                p.d32(0x1C, 2)                     # 0x424366 父进态 2
                p.d32(0x20, 0xB)                   # 0x42436D
    if e.node is not None:                         # 0x424374 尾：node.rect = (x,y,+0x17,+0x17)
        x, y = e.s32(0x04), e.s32(0x08)
        e.node.rect = (x, y, x + 0x17, y + 0x17)
    return True


def _beh_423980(self, e) -> bool:
    """`0x423980`（0x5100000A 波纹，thunk 0x40173F）：计数 `[+0x20]` <0x10 时每帧
    node.rect.b += 3（向下扩），≥0x10 改 node.rect.l/dst.x += 3（右移）；计数恰 0x10 且
    世代 [ebx+0x1C] < 2 时在原地复制下一代；计满 0x20 自尽。"""
    nd = e.node
    if nd is not None:
        if e.g32(0x20) & 0x10:                     # 0x42398D test byte[ebx+0x20],0x10
            l, tp, r, b = nd.rect
            nd.rect = (l + 3, tp, r, b)            # 0x42399D [eax+4] += 3
            nd.dst = (nd.dst[0] + 3, nd.dst[1])    # 0x4239A5 [eax+0x14] += 3
        else:
            l, tp, r, b = nd.rect
            nd.rect = (l, tp, r, b + 3)            # 0x4239AA [eax+0xC] += 3
    if e.g32(0x20) == 0x10 and e.s32(0x1C) < 2:    # 0x4239AE/0x4239B6
        self.p4_51_spawn(e.s32(0x04), e.s32(0x08), 0x5100000A, e.s32(0x1C) + 1)
    n = (e.g32(0x20) + 1) & 0xFFFFFFFF
    e.d32(0x20, n)                                 # 0x4239F9
    return n < 0x20                                # 0x4239FF/0x423A03 setl


# 12 项武器槽行为（P4_SPAWN_SLOTS 生成的 _beh_p4slot_*）按真址登记——
# pod ctor 0x42C4D0 把它们写进 [pod+0x40]，0x446450 按 [e+0x40] 分派。
# ---- 0x31 弹族行为（0x4321C0..，逐条对 0x4308A0 各 case 的 [+0x40] 实现） ----
def _beh_4321C0(self, e) -> bool:
    """`0x4321C0`：8.8 速度积分；屏内(±0x10) 且 HP!=0。"""
    e.d32(0x24, (e.s32(0x24) + e.s32(0x1C)) & 0xFFFFFFFF)
    e.d32(0x28, (e.s32(0x28) + e.s32(0x20)) & 0xFFFFFFFF)
    x = (e.s32(0x24)) >> 8
    y = (e.s32(0x28)) >> 8
    e.d32(0x04, x & 0xFFFFFFFF)
    e.d32(0x08, y & 0xFFFFFFFF)
    if e.disp is not None:
        e.disp.dst = [x - 0xC, y - 0xC]
    return e.s32(0x18) != 0 and self.p4_4305f0(e, 0x10) == 1


def _beh_432250(self, e) -> bool:
    """`0x432250`（0x31000003）：8.8 积分 + 每 2 帧在原地生成 0x31000004；屏内且 HP。"""
    e.d32(0x24, (e.s32(0x24) + e.s32(0x1C)) & 0xFFFFFFFF)
    e.d32(0x28, (e.s32(0x28) + e.s32(0x20)) & 0xFFFFFFFF)
    t = (e.s32(0x2C) + 1) & 0xFFFFFFFF
    e.d32(0x2C, t)
    if t & 1:
        self.spawn(self._p4_q("ui49c"), 0x31000004, e.s32(0x04), e.s32(0x08))
    x = (e.s32(0x24)) >> 8
    y = (e.s32(0x28)) >> 8
    e.d32(0x04, x & 0xFFFFFFFF)
    e.d32(0x08, y & 0xFFFFFFFF)
    if e.disp is not None:
        e.disp.dst = [x - 0xC, y - 0xC]
    return e.s32(0x18) != 0 and self.p4_4305f0(e, 0x10) == 1


def _beh_432340(self, e) -> bool:
    """`0x432340`（0x31000004）：t++; [0x10]=(t<6)；t 偶数 → rect.l/r +=0x18；存活 t<0xA。"""
    t = (e.s32(0x1C) + 1) & 0xFFFFFFFF
    e.d32(0x1C, t)
    e.raw[0x10] = 1 if t < 6 else 0
    if (t & 1) == 0 and e.disp is not None:
        e.disp.rect = [e.disp.rect[0] + 0x18, e.disp.rect[1],
                       e.disp.rect[2] + 0x18, e.disp.rect[3]]
    return t < 0xA


def _beh_4325E0(self, e) -> bool:
    """`0x4325E0`（0x31000006）：8.8 积分；dst=(x−0x10,y−0x10)；屏内(±0x10)且 HP。"""
    e.d32(0x24, (e.s32(0x24) + e.s32(0x1C)) & 0xFFFFFFFF)
    e.d32(0x28, (e.s32(0x28) + e.s32(0x20)) & 0xFFFFFFFF)
    x = (e.s32(0x24)) >> 8
    y = (e.s32(0x28)) >> 8
    e.d32(0x04, x & 0xFFFFFFFF)
    e.d32(0x08, y & 0xFFFFFFFF)
    if e.disp is not None:
        e.disp.dst = [x - 0x10, y - 0x10]
    return e.s32(0x18) != 0 and self.p4_4305f0(e, 0x10) == 1


def _beh_432820(self, e) -> bool:
    """`0x432820`（0x3100000C）：x−=0x10、y+=[0x1C]；[0x20] 与 y 比较修正 [0x1C] ±2；
    dst=(x−0x10,y−0x10)；存活 x>−0x18 且 HP。"""
    x = (e.s32(0x04) - 0x10) & 0xFFFFFFFF
    y = (e.s32(0x08) + e.s32(0x1C)) & 0xFFFFFFFF
    e.d32(0x04, x)
    e.d32(0x08, y)
    if e.disp is not None:
        e.disp.dst = [e.s32(0x04) - 0x10, e.s32(0x08) - 0x10]
    ty = e.s32(0x20)
    if ty > e.s32(0x08):
        e.d32(0x1C, (e.s32(0x1C) + 2) & 0xFFFFFFFF)
    elif ty < e.s32(0x08):
        e.d32(0x1C, (e.s32(0x1C) - 2) & 0xFFFFFFFF)
    return e.s32(0x04) > -0x18 and e.s32(0x18) != 0


def _beh_4328B0(self, e) -> bool:
    """`0x4328B0`（0x3100000D）：8.4 双轴积分；t==9 随机方向（cos/sin(r)>>2）；
    dst=(x−0xC,y−0xC)；屏内(±0xC)且 HP。"""
    e.d32(0x28, (e.s32(0x28) + e.s32(0x20)) & 0xFFFFFFFF)
    e.d32(0x2C, (e.s32(0x2C) + e.s32(0x24)) & 0xFFFFFFFF)
    x = (e.s32(0x28)) >> 4
    y = (e.s32(0x2C)) >> 4
    e.d32(0x04, x & 0xFFFFFFFF)
    e.d32(0x08, y & 0xFFFFFFFF)
    t = (e.s32(0x1C) + 1) & 0xFFFFFFFF
    e.d32(0x1C, t)
    if t == 9:
        r = self.p4_rand() % 0xE10
        e.d32(0x20, (page4_cos(r) >> 2) & 0xFFFFFFFF)
        e.d32(0x24, (page4_sin(r) >> 2) & 0xFFFFFFFF)
    if e.disp is not None:
        e.disp.dst = [x - 0xC, y - 0xC]
    return e.s32(0x18) != 0 and self.p4_4305f0(e, 0xC) == 1


def _beh_433390(self, e) -> bool:
    """`0x433390`（0x31000019）：8.8 积分 + 每 4 帧 rect 动画（按 rect.t/rect.l 选伸缩）；
    dst=(x−0xC,y−0xC)；屏内(±0x10)且 HP。"""
    e.d32(0x24, (e.s32(0x24) + e.s32(0x1C)) & 0xFFFFFFFF)
    e.d32(0x28, (e.s32(0x28) + e.s32(0x20)) & 0xFFFFFFFF)
    x = (e.s32(0x24)) >> 8
    y = (e.s32(0x28)) >> 8
    e.d32(0x04, x & 0xFFFFFFFF)
    e.d32(0x08, y & 0xFFFFFFFF)
    t = (e.s32(0x2C) + 1) & 0xFFFFFFFF
    e.d32(0x2C, t)
    if (t & 3) == 0 and e.disp is not None:
        l, tp, r, b = e.disp.rect
        if tp == 0x1C8:
            e.disp.rect = [l, tp + 0x18, r, b + 0x18]
        elif l == 0xF0:
            e.disp.rect = [l + 0x18, tp - 0x18, r + 0x18, b - 0x18]
        else:
            e.disp.rect = [l - 0x18, tp - 0x18, r - 0x18, b - 0x18]
    if e.disp is not None:
        e.disp.dst = [x - 0xC, y - 0xC]
    return e.s32(0x18) != 0 and self.p4_4305f0(e, 0x10) == 1


def _beh_433480(self, e) -> bool:
    """`0x433480`（0x3100001B）：屏内(±0x10)才继续；8.4 积分；每帧生成 0x3100001C
    @(x,y) param=[0x2C] 并 [0x2C]++；return 1。"""
    if self.p4_4305f0(e, 0x10) != 1:
        return False
    e.d32(0x24, (e.s32(0x24) + e.s32(0x1C)) & 0xFFFFFFFF)
    e.d32(0x28, (e.s32(0x28) + e.s32(0x20)) & 0xFFFFFFFF)
    x = (e.s32(0x24)) >> 4
    y = (e.s32(0x28)) >> 4
    e.d32(0x04, x & 0xFFFFFFFF)
    e.d32(0x08, y & 0xFFFFFFFF)
    prm = e.s32(0x2C)
    e.d32(0x2C, (prm + 1) & 0xFFFFFFFF)
    self.spawn(self._p4_q("ui49c"), 0x3100001C, x, y, prm)
    return True


def _beh_4324B0(self, e) -> bool:
    """`0x4324B0`（0x31000005）：母体（[0x20]==0）朝自机正弦追踪并每帧生成子体
    （prm=1，子体只计时 0xB4 后自灭）；母体 t==0x78 自灭。"""
    if e.s32(0x20) == 0:                           # 0x4324B6
        t = (e.s32(0x1C) + 1) & 0xFFFFFFFF
        e.d32(0x1C, t)
        if t == 0x78:                              # 0x4324CA
            return False
        ang = (t * 40) & 0xFFFFFFFF
        px, py = self.p4_player_x(), self.p4_player_y()
        x = e.s32(0x04)
        x += ((page4_cos(ang) * 9 >> 4) - x + px) >> 3
        y = e.s32(0x08)
        y += ((page4_sin(ang) * 9 >> 4) - y + py) >> 3
        e.d32(0x04, x & 0xFFFFFFFF)
        e.d32(0x08, y & 0xFFFFFFFF)
        if e.disp is not None:
            e.disp.dst = [x - 8, y - 8]
        self.spawn(self._p4_q("ui49c"), 0x31000005, x, y, 1)
        return True
    t = (e.s32(0x1C) + 1) & 0xFFFFFFFF            # 0x43257B 子体
    e.d32(0x1C, t)
    return t != 0xB4                               # 0x432584


def _beh_432670(self, e) -> bool:
    """`0x432670`（0x31000008）：t<0x20 每 4 帧 rect.y −=0x20（rect.l==0x130 时额外
    l/r +=0x60、t/b −=0x20）；t≥0x20 生成 0x31000009、x −= (t−0x20)>>1、y −=0x10。"""
    t = (e.s32(0x1C) + 1) & 0xFFFFFFFF
    e.d32(0x1C, t)
    if t < 0x20:                                   # 0x43267F
        if (t & 3) == 0 and e.disp is not None:
            l, tp, r, b = e.disp.rect
            e.disp.rect = [l, tp - 0x20, r, b - 0x20]
            if l == 0x130:                         # 0x4326A9
                e.disp.rect = [l + 0x60, tp - 0x40, r + 0x60, b - 0x40]
        return e.s32(0x18) != 0 and self.p4_4305f0(e, 0x10) == 1
    self.spawn(self._p4_q("ui49c"), 0x31000009, e.s32(0x04), e.s32(0x08), 0)
    x = (e.s32(0x04) - ((t - 0x20) >> 1)) & 0xFFFFFFFF
    y = (e.s32(0x08) - 0x10) & 0xFFFFFFFF
    e.d32(0x04, x)
    e.d32(0x08, y)
    if e.disp is not None:
        e.disp.dst = [e.s32(0x04) - 0x10, e.s32(0x08) - 0x10]
    return e.s32(0x18) != 0 and self.p4_4305f0(e, 0x10) == 1


def _beh_4327A0(self, e) -> bool:
    """`0x4327A0`（0x31000009）：t<0x10 内每 2 帧 rect.y +=0x20（rect.l==0x1B0 时
    l/r −=0x60、t/b +=0x20）；t≥0x10 自灭；存活 HP!=0。"""
    t = (e.s32(0x1C) + 1) & 0xFFFFFFFF
    e.d32(0x1C, t)
    if t >= 0x10:
        return False
    if (t & 1) == 0 and e.disp is not None:
        l, tp, r, b = e.disp.rect
        e.disp.rect = [l, tp + 0x20, r, b + 0x20]
        if l == 0x1B0:
            e.disp.rect = [l - 0x60, tp + 0x40, r - 0x60, b + 0x40]
    return e.s32(0x18) != 0


def _beh_432C80(self, e) -> bool:
    """`0x432C80`（0x31000010）：每帧生成 0x31000011；t 从 [0x1C] 起，[0x20] 为相位界：
    t<[0x20] → t+=2、螺旋（[0x24]/[0x28] += cos/sin(t·30)·3>>3、x=>>3）；
    t≥[0x20] → t+=1、x=[0x24]+cos·d>>5、y=[0x28]+sin·d>>5（d=t−[0x20]），d>0x64 自灭。"""
    self.spawn(self._p4_q("ui49c"), 0x31000011, e.s32(0x04), e.s32(0x08), 0)
    t = e.s32(0x1C)
    if t == e.s32(0x20):                           # 0x432CCE
        e.d32(0x24, e.s32(0x04))
        e.d32(0x28, e.s32(0x08))
    ang = (t * 30) & 0xFFFFFFFF
    if t < e.s32(0x20):                            # 0x432CDE
        t2 = (t + 2) & 0xFFFFFFFF
        e.d32(0x1C, t2)
        e.d32(0x24, (e.s32(0x24) + ((page4_cos(ang) * 3) >> 3)) & 0xFFFFFFFF)
        e.d32(0x28, (e.s32(0x28) + ((page4_sin(ang) * 3) >> 3)) & 0xFFFFFFFF)
        e.d32(0x04, (e.s32(0x24) >> 3) & 0xFFFFFFFF)
        e.d32(0x08, (e.s32(0x28) >> 3) & 0xFFFFFFFF)
        return e.s32(0x18) != 0
    t2 = (t + 1) & 0xFFFFFFFF                      # 0x432D33
    e.d32(0x1C, t2)
    d = t2 - e.s32(0x20)
    e.d32(0x04, (e.s32(0x24) + ((page4_cos(ang) * d) >> 5)) & 0xFFFFFFFF)
    e.d32(0x08, (e.s32(0x28) + ((page4_sin(ang) * d) >> 5)) & 0xFFFFFFFF)
    if d > 0x64:
        return False
    return e.s32(0x18) != 0


def _beh_432DC0(self, e) -> bool:
    """`0x432DC0`（0x31000011）：t<3 有碰撞；t==5 自灭；t!=1 时 rect.y +=0x20。"""
    t = (e.s32(0x1C) + 1) & 0xFFFFFFFF
    e.d32(0x1C, t)
    e.raw[0x10] = 1 if t < 3 else 0
    if t == 5:
        return False
    if t != 1 and e.disp is not None:              # 0x432DE1 压栈 (0,0x20,0,0x20) → out[0]/out[2]
        e.disp.rect = [e.disp.rect[0] + 0x20, e.disp.rect[1],
                       e.disp.rect[2] + 0x20, e.disp.rect[3]]
    return e.s32(0x18) != 0


def _beh_432FE0(self, e) -> bool:
    """`0x432FE0`（0x31000014）：t<0xA0 有碰撞；每 0x10 帧 rect.y +=0x18；
    node.active=(−0xC<y<0x1EC)；存活 = rect.l != 0x108。"""
    t = (e.s32(0x1C) + 1) & 0xFFFFFFFF
    e.d32(0x1C, t)
    e.raw[0x10] = 1 if t < 0xA0 else 0
    if (t & 0xF) == 0 and e.disp is not None:      # 0x432FF9 压栈 (0,0x18,0,0x18) → out[0]/out[2]
        e.disp.rect = [e.disp.rect[0] + 0x18, e.disp.rect[1],
                       e.disp.rect[2] + 0x18, e.disp.rect[3]]
    if e.disp is not None:
        y = e.s32(0x08)
        e.disp.active = 1 if (-0xC < y < 0x1EC) else 0
        return e.disp.rect[0] != 0x108
    return True


def _beh_433340(self, e) -> bool:
    """`0x433340`（0x31000018）：t 偶数帧 rect.y +=0x18；t==5 自灭。"""
    t = (e.s32(0x1C) + 1) & 0xFFFFFFFF
    e.d32(0x1C, t)
    if (t & 1) == 0 and e.disp is not None:
        e.disp.rect = [e.disp.rect[0], e.disp.rect[1] + 0x18,
                       e.disp.rect[2], e.disp.rect[3] + 0x18]
    return t != 5


def _beh_433520(self, e) -> bool:
    """`0x433520`（0x3100001C）：两段 rect 动画（按 rect.l/rect.t 选方向）+ [0x20] 计时；
    存活 = [0x20] < 0x61；[0x10] = (旧 t > 0xF)。"""
    t = e.s32(0x1C)
    e.raw[0x10] = 1 if t > 0xF else 0
    e.d32(0x1C, (t + 1) & 0xFFFFFFFF)
    if t != 0:
        c = (e.s32(0x20) + 1) & 0xFFFFFFFF
        e.d32(0x20, c)
        if c < 0x5A and e.disp is not None:
            l, tp, r, b = e.disp.rect
            if l != 0x108:
                e.disp.rect = [l + 0x18, tp, r + 0x18, b]
            elif tp == 0:
                e.disp.rect = [l - 0x48, tp + 0x18, r - 0x48, b + 0x18]
    if e.disp is not None:
        l, tp, r, b = e.disp.rect
        if l != 0xC0:                             # 0x433584 压栈 (0,-0x18,0,-0x18) → out[0]/out[2]
            e.disp.rect = [l - 0x18, tp, r - 0x18, b]
        elif tp == 0x18:
            e.disp.rect = [l + 0x48, tp - 0x18, r + 0x48, b - 0x18]
    return e.s32(0x20) < 0x61


def _beh_432F20(self, e) -> bool:
    """`0x432F20`（0x31000013）：8.2 积分——[0x24]+=[0x1C]（y）、[0x20]−=0x40（x 左漂）；
    每帧生成 0x31000014；dst=(x−0xC,y−0xC)；存活 x>−0xC。"""
    e.d32(0x24, (e.s32(0x24) + e.s32(0x1C)) & 0xFFFFFFFF)
    e.d32(0x20, (e.s32(0x20) - 0x40) & 0xFFFFFFFF)
    x = e.s32(0x20) >> 2
    y = e.s32(0x24) >> 2
    e.d32(0x04, x & 0xFFFFFFFF)
    e.d32(0x08, y & 0xFFFFFFFF)
    self.spawn(self._p4_q("ui49c"), 0x31000014, x, y, 0)
    if e.disp is not None:
        e.disp.dst = [x - 0xC, y - 0xC]
    return x > -0xC


_P4_27_TAIL_TYPES = frozenset((
    0x27000001, 0x27000002, 0x27000003, 0x27000004, 0x27000005,
    0x27000007, 0x27000008, 0x27000009, 0x2700000A,
    0x2700000C, 0x2700000D, 0x2700000E,
))


def _beh_432C00(self, e) -> bool:
    """`0x432C00`（0x3100000F ×5）：静止 5 帧换一档，共 4 档；前 3 档可碰撞。"""
    t = (e.s32(0x1C) + 1) & 0xFFFFFFFF
    e.d32(0x1C, t)
    if t == 5:
        if e.node is not None:
            e.node.rect = (e.node.rect[0] + 0x20, e.node.rect[1],
                           e.node.rect[2] + 0x20, e.node.rect[3])
        e.d32(0x1C, 0)
        c = (e.s32(0x20) + 1) & 0xFFFFFFFF
        e.d32(0x20, c)
        _p4_m(e)[0x10] = 1 if c < 3 else 0
        if c == 4:
            return False
    return e.g32(0x18) != 0


def _beh_4331C0(self, e) -> bool:
    """`0x4331C0`（0x31000010/16 定格动画）：t=++[0x1C]，t−2 索引字节表 0x433230，
    跳表 0x43321C：0→rect.y−=0x18；1→rect.x−=0x18、y+=0x48；2→关碰撞再 y−=0x18；
    3→return 0；4→无操作。"""
    t = (e.s32(0x1C) + 1) & 0xFFFFFFFF
    e.d32(0x1C, t)
    idx = t - 2
    if idx < 0 or idx > 0xE:
        return True
    sel = _P4_433230[idx]
    if sel == 3:
        return False
    if sel == 4:
        return True
    if e.node is not None:
        r = e.node.rect
        if sel == 1:
            e.node.rect = (r[0] - 0x18, r[1] + 0x48, r[2] - 0x18, r[3] + 0x48)
        else:
            if sel == 2:
                _p4_m(e)[0x10] = 0
            e.node.rect = (r[0], r[1] - 0x18, r[2], r[3] - 0x18)
    elif sel == 2:
        _p4_m(e)[0x10] = 0
    return True


_P4_433230 = (0, 4, 0, 4, 0, 4, 1, 4, 2, 4, 0, 4, 0, 4, 3)


def _beh_432E30(self, e) -> bool:
    """`0x432E30`（0x31000012）：8.4 定点直线；每 0xF 帧 rect 右移 8 并加大半径。"""
    a24 = e.s32(0x24)
    e.d32(0x28, (e.s32(0x28) + ((page4_cos(a24) * 3) >> 4)) & 0xFFFFFFFF)
    e.d32(0x2C, (e.s32(0x2C) + ((page4_sin(a24) * 3) >> 4)) & 0xFFFFFFFF)
    x = (e.s32(0x28) >> 4) & 0xFFFFFFFF
    y = (e.s32(0x2C) >> 4) & 0xFFFFFFFF
    e.d32(0x04, x)
    e.d32(0x08, y)
    t = (e.s32(0x1C) + 1) & 0xFFFFFFFF
    e.d32(0x1C, t)
    if (t & 0xF) == 0 and e.s32(0x20) != 0x40:
        if e.node is not None:
            r = e.node.rect
            e.node.rect = (r[0] + e.s32(0x20), r[1], r[2] + e.s32(0x20) + 8, r[3] + 8)
        e.d32(0x0C, (e.s32(0x0C) + 4) & 0xFFFFFFFF)
        e.d32(0x20, (e.s32(0x20) + 8) & 0xFFFFFFFF)
    if e.node is not None:
        e.node.dst = (x - e.s32(0x0C), y - e.s32(0x0C))
    return t < 0x100 and e.g32(0x18) != 0


def _beh_433260(self, e) -> bool:
    """`0x433260`（0x31000017）：2.2 定点 + 每帧 0x31000018 拖尾；出屏自灭。"""
    e.d32(0x24, (e.s32(0x24) + e.s32(0x1C)) & 0xFFFFFFFF)
    e.d32(0x28, (e.s32(0x28) + e.s32(0x20)) & 0xFFFFFFFF)
    x = (e.s32(0x24) >> 2) & 0xFFFFFFFF
    y = (e.s32(0x28) >> 2) & 0xFFFFFFFF
    e.d32(0x04, x)
    e.d32(0x08, y)
    self.spawn(self._p4_q("ui49c"), 0x31000018, x, y, 0)
    if e.node is not None:
        e.node.dst = (x - 0x18, y - 0xC)
    return not (x < -0x18 or x > 0x298 or y < -0x18 or y > 0x1E0) and e.g32(0x18) != 0


def _beh_433AD0(self, e) -> bool:
    """`0x433AD0`（0x3100001F）：8.8 积分，四边界反号，反弹 4 次后消失。"""
    x = (e.s32(0x24) >> 8) & 0xFFFFFFFF
    y = (e.s32(0x28) >> 8) & 0xFFFFFFFF
    vx = e.s32(0x1C)
    vy = e.s32(0x20)
    bounce = False
    if x < 0 and vx < 0:
        vx = (-vx) & 0xFFFFFFFF; bounce = True
    if x > 0x280 and vx > 0:
        vx = (-vx) & 0xFFFFFFFF; bounce = True
    if y < 0 and vy < 0:
        vy = (-vy) & 0xFFFFFFFF; bounce = True
    if y > 0x1E0 and vy > 0:
        vy = (-vy) & 0xFFFFFFFF; bounce = True
    if bounce:
        e.d32(0x1C, vx)
        e.d32(0x20, vy)
        c = (e.s32(0x2C) + 1) & 0xFFFFFFFF
        e.d32(0x2C, c)
        if e.s32(0x2C) < 5:
            self._p4_4047e0_se(0xF, (x - 0x140) << 4)
    e.d32(0x24, (e.s32(0x24) + vx) & 0xFFFFFFFF)
    e.d32(0x28, (e.s32(0x28) + vy) & 0xFFFFFFFF)
    e.d32(0x04, (e.s32(0x24) >> 8) & 0xFFFFFFFF)
    e.d32(0x08, (e.s32(0x28) >> 8) & 0xFFFFFFFF)
    if e.node is not None:
        e.node.dst = (e.s32(0x04) - 0xC, e.s32(0x08) - 0xC)
    return e.s32(0x2C) < 4



def _beh_432990(self, e) -> bool:
    """`0x432990`（0x3100000E）：半速移动 + 每帧发 0F + 朝父体转向 + 命中脱钩。"""
    x = (e.s32(0x04) + (e.s32(0x20) >> 1)) & 0xFFFFFFFF
    y = (e.s32(0x08) + (e.s32(0x24) >> 1)) & 0xFFFFFFFF
    e.d32(0x04, x)
    e.d32(0x08, y)
    self.spawn(self._p4_q("ui49c"), 0x3100000F, x, y, 0)
    par = self.p4_links.get(e.s32(0x1C) & 0x7FFFFFFF)
    if par is not None:
        vx = e.s32(0x20)
        if x < par.s32(0x04):
            vx += 1 if vx >= 0 else 4
        else:
            vx -= 4 if vx >= 0 else 1
        e.d32(0x20, vx & 0xFFFFFFFF)
        vy = e.s32(0x24)
        if y < par.s32(0x08):
            vy += 1 if vy >= 0 else 4
        else:
            vy -= 4 if vy >= 0 else 1
        e.d32(0x24, vy & 0xFFFFFFFF)
        if self.p4_hit_test(par, x, y, 0x10):         # 0x401843→0x4306C0
            par.d32(0x24, 0)
            e.d32(0x1C, 0)
    if e.g32(0x18) == 0:
        par2 = self.p4_links.get(e.s32(0x1C) & 0x7FFFFFFF)
        if par2 is not None:
            par2.d32(0x24, 0)
        for _ in range(4):
            jx = (self.p4_rand() & 0x1F) - 0xF
            jy = (self.p4_rand() & 0x1F) - 0xF
            # 0x432AC4：位置用 (x,y)，随机偏移作为 rec3/prm 传入
            self.spawn(self._p4_q("ui4cc"), 0x41000004, x, y, (jx, jy))
        self._p4_4047e0_se(9, (x - 0x140) << 4)
        return False
    if e.node is not None:
        e.node.dst = (x - 0x10, y - 0x10)
    if e.s32(0x1C) == 0 and (x < -0x10 or x > 0x290 or y < -0x10 or y > 0x1F0):
        return False
    return True


def _beh_433060(self, e) -> bool:
    """`0x433060`（0x31000015）：半速移动 + 每帧发 16；交叉耦合转向（[0x30] 只反相 x）。"""
    px = self.p4_player_x()
    py = self.p4_player_y()
    vx = e.s32(0x28)
    vy = e.s32(0x2C)
    x = e.s32(0x04)
    y = e.s32(0x08)
    if e.s32(0x30) != 0:
        if x > px:
            if vy >= 0:
                vx -= 1
        elif vy <= 0:
            vx += 1
    else:
        if x > px:
            if vy <= 0:
                vx -= 1
        elif vy >= 0:
            vx += 1
    if y > py:
        if vx <= 0:
            vy -= 1
    elif vx >= 0:
        vy += 1
    e.d32(0x28, vx & 0xFFFFFFFF)
    e.d32(0x2C, vy & 0xFFFFFFFF)
    ax = (e.s32(0x20) + vx) & 0xFFFFFFFF
    ay = (e.s32(0x24) + vy) & 0xFFFFFFFF
    e.d32(0x20, ax)
    e.d32(0x24, ay)
    nx = (ax >> 1) & 0xFFFFFFFF
    ny = (ay >> 1) & 0xFFFFFFFF
    e.d32(0x04, nx)
    e.d32(0x08, ny)
    self.spawn(self._p4_q("ui49c"), 0x31000016, nx, ny, 0)
    if e.node is not None:
        e.node.dst = (nx - 0x10, ny - 0x10)
    t = (e.s32(0x1C) + 1) & 0xFFFFFFFF
    e.d32(0x1C, t)
    if t < 0x5A:
        return True
    if nx < -0x10 or nx > 0x290 or ny < -0x10 or ny > 0x1F0:
        return False
    return True


def _beh_433820(self, e) -> bool:
    """`0x433820`（0x3100001D）：隐形螺旋发射器，三种弹型分支。"""
    bx = e.s32(0x24)
    by = e.s32(0x28)
    ang = self.p4_45a9a0(self.p4_player_x() - bx, self.p4_player_y() - by)
    t = (e.s32(0x1C) + 1) & 0xFFFFFFFF
    e.d32(0x1C, t)
    spin = (page4_sin((225 * (t & 0xF)) & 0xFFFFFFFF) * min(t, 0x30))
    x = (bx + ((page4_cos(ang) * t) >> 4)) & 0xFFFFFFFF
    y = (by + ((page4_sin(ang) * t) >> 4)) & 0xFFFFFFFF
    a2 = (ang + 0x384) & 0xFFFFFFFF
    sx = (x + (((page4_cos(a2) * spin) >> 15))) & 0xFFFFFFFF
    sy = (y + (((page4_sin(a2) * spin) >> 15))) & 0xFFFFFFFF
    if e.s32(0x20) & 0x10:
        self.spawn(self._p4_q("ui4fc"), 0x5A000003, sx, sy, 0)
    else:
        self.spawn(self._p4_q("ui4cc"), 0x4A000004, sx, sy, 0)
    if e.g32(0x18) == 0 and e.s32(0x2C) != 0:
        if self.p4_stat.get(0x56CCB8, 0) & 0x10:
            self.spawn(self._p4_q("ui4fc"), 0x5A000004, sx, sy, 0)
        else:
            self.spawn(self._p4_q("ui4cc"), 0x4A000005, sx, sy, 0)
    return t < 0x3C and e.g32(0x18) != 0



def _beh_4335F0(self, e) -> bool:
    """`0x4335F0`（0x32000010 实际行为）：绕源点螺旋撒弹 + 后段每 8 帧发 0x3100001D。

    t=++[0x20]；源=(par.x,par.y)（[0x1C] 句柄，无则自身）；半幅=t<0x30?t>>1:0x18；
    k=(t&0xFF)*14；弹位=源+((cos(k)*half>>15), (sin(k)*half>>15))；
    byte[0x20]&0x10 → 0x5A000003 入 4AD4FC，否则 0x4A000004 入 4AD4CC。
    [0x24]++ >0x1A4 且 &7==0 → rec=([0x20]&0xF)|(t2<0x21C?0x10000:0) 发 0x3100001D。
    return 父体存活（无父则 True）。"""
    t = (e.s32(0x20) + 1) & 0xFFFFFFFF
    e.d32(0x20, t)
    par = self.p4_links.get(e.s32(0x1C) & 0x7FFFFFFF)
    if par is not None:
        bx = par.s32(0x04)
        by = par.s32(0x08)
    else:
        bx = e.s32(0x04)
        by = e.s32(0x08)
    e.d32(0x04, bx & 0xFFFFFFFF)
    e.d32(0x08, by & 0xFFFFFFFF)
    half = (t >> 1) if (t & 0xFFFFFFFE) < 0x30 else 0x18
    k = (t & 0xFF) * 14
    c = page4_cos((k * 8 + 0x71) & 0xFFFFFFFF)
    dx = (page4_cos(k) * c * half) >> 15
    dy = (page4_sin(k) * c * half) >> 15
    if e.s32(0x20) & 0x10:
        self.spawn(self._p4_q("ui4fc"), 0x5A000003, (bx + dx) & 0xFFFFFFFF,
                   (by + dy) & 0xFFFFFFFF, 0)
    else:
        self.spawn(self._p4_q("ui4cc"), 0x4A000004, (bx + dx) & 0xFFFFFFFF,
                   (by + dy) & 0xFFFFFFFF, 0)
    t2 = (e.s32(0x24) + 1) & 0xFFFFFFFF
    e.d32(0x24, t2)
    if t2 > 0x1A4 and (t2 & 7) == 0:
        rec = (e.s32(0x20) & 0xF) | (0x10000 if t2 < 0x21C else 0)
        self.spawn(self._p4_q("ui49c"), 0x3100001D, bx, by, rec)
    return par.m[0x34] != 0 if par is not None else True



def _p4_m(e):
    """Ent 用 `e.m`，UiEntity 用 `e.raw`（0x31/0x32 队列实体）。"""
    return e.m if hasattr(e, "m") else e.raw



def _beh_41DD70(self, e) -> bool:
    """`0x41DD70`（thunk 0x4016C7；0x29000007..0B 的入场体）：七态铺 0x29000003 编队。

    首帧（[0x20]==0）按 [0x1C]（态 1..7）铺队；之后 [0x20] 计时：
    0x10<=t<0x18 → [0x24]++；否则 t∈[[0x28],[0x28]+0x10) → [0x24]−−。
    尾：x += [0x24]（node dst.x 同步）、[0x20]++；存活 = x>−0x18 && HP!=0。
    """
    if e.s32(0x20) == 0:
        st = e.s32(0x1C)
        if 1 <= st <= 7:
            v = st - 1
            if st in (1, 7):
                e.d32(0x28, 0xFA)
                y0 = 0xFFFFFFE8 if v == 0 else 0x1F8
                for i in range(8):
                    self._p4_ent43c(0x29000003, 0x28 + i * 0x50, y0)
            elif st == 2:
                e.d32(0x28, 0x122)
                for i in range(8):
                    self._p4_ent43c(0x29000003, 0x298 + i * 0x21, 0x30)
            elif st == 3:
                e.d32(0x28, 0x15E)
                self._p4_ent43c(0x29000003, 0x298, 0xF0)
                yy = 0xC0
                while True:
                    self._p4_ent43c(0x29000003, 0x2C8, yy)
                    if yy + 0x60 > 0x120:
                        break
                    yy += 0x60
                yy = 0x90
                while True:
                    self._p4_ent43c(0x29000003, 0x2F8, yy)
                    if yy + 0xC0 > 0x150:
                        break
                    yy += 0xC0
                yy = 0x60
                while True:
                    self._p4_ent43c(0x29000003, 0x328, yy)
                    if yy + 0x60 > 0x180:
                        break
                    yy += 0x60
            elif st == 4:
                e.d32(0x28, 0x15E)
                cnt = 0
                yy = -0x40
                while cnt <= 4:
                    self._p4_ent43c(0x29000003, 0x2C0, yy)
                    if yy != e.s32(0x08):
                        self._p4_ent43c(0x29000003, 0x2C0, yy)
                    yy += 0x60
                    cnt += 1
            elif st == 5:
                e.d32(0x28, 0x168)
                yy = -0x78
                while yy >= -0x3C0:
                    self._p4_ent43c(0x29000003, 0x140, yy)
                    yy -= 0x78
            else:   # st == 6
                e.d32(0x28, 0x122)
                for i in range(8):
                    xx = 0x2A8 + i * 0x50
                    self._p4_ent43c(0x29000003, xx, 0x1FE + i * 0x3C)
                    self._p4_ent43c(0x29000003, xx, -0x1E - i * 0x3C)
    else:
        t = e.s32(0x20)
        if 0x10 <= t < 0x18:
            e.d32(0x24, (e.s32(0x24) + 1) & 0xFFFFFFFF)
        else:
            base = e.s32(0x28)
            if base <= t < base + 0x10:
                e.d32(0x24, (e.s32(0x24) - 1) & 0xFFFFFFFF)
    vx = e.s32(0x24)
    x = (e.s32(0x04) + vx) & 0xFFFFFFFF
    e.d32(0x04, x)
    e.d32(0x20, (e.s32(0x20) + 1) & 0xFFFFFFFF)
    if e.node is not None:
        e.node.dst = (e.node.dst[0] + vx, e.node.dst[1])
    return e.s32(0x04) > -0x18 and e.g32(0x18) != 0


P4_BEH: dict[int, object] = {
    0x432F20: _beh_432F20,
    0x433520: _beh_433520,
    0x432DC0: _beh_432DC0, 0x432FE0: _beh_432FE0, 0x433340: _beh_433340,
    0x4327A0: _beh_4327A0, 0x432C80: _beh_432C80,
    0x4324B0: _beh_4324B0, 0x432670: _beh_432670,
    0x4321C0: _beh_4321C0, 0x432250: _beh_432250, 0x432340: _beh_432340,
    0x4325E0: _beh_4325E0, 0x432820: _beh_432820, 0x4328B0: _beh_4328B0,
    0x432C00: _beh_432C00, 0x4331C0: _beh_4331C0, 0x432E30: _beh_432E30,
    0x433260: _beh_433260, 0x433AD0: _beh_433AD0, 0x432990: _beh_432990,
    0x433060: _beh_433060, 0x433820: _beh_433820, 0x4335F0: _beh_4335F0,
    0x433390: _beh_433390, 0x433480: _beh_433480,
    **{ _a: globals()[f"_beh_p4slot_{_a:06X}"] for _a in P4_SPAWN_SLOTS },
    0x43AEB0: _beh_43AEB0,
    0x40E9B0: _beh_23000009,        # 类型 0x23000009（thunk 0x4015AA）
    0x4435C0: _beh_6B000001,        # 类型 0x6B000001（thunk 0x4020EF）开场状态机          # 类型 0x21000001（ctor 0x43A899 写 [+0x40]=0x401E2E）
    0x40E070: _beh_23000001,
    0x40E100: _beh_23000002,
    0x40E460: _beh_23000004,
    0x446950: _beh_446950,
    0x446890: _beh_446950,          # §16.193：与 0x446950 逐字节相同（仅 call 位移不同）
    0x446BD0: _beh_446BD0,
    0x446B50: _beh_446BD0,          # 2026-11-14 反汇编 0x446B50..0x446C2C：与 0x446BD0
                                    # 逐指令同构（仅 call rel32 编码差）。缺它时
                                    # 行为表 idx6 = 操作器(bit1)+漢(选机2) 查不到 →
                                    # 0x446600 门不跑、节点不点亮 ⇒ 进关卡自机隐形。
    0x446C50: _beh_446C50,
    0x446D30: _beh_446D30,
    0x446E20: _beh_446E20,
    0x446F10: _beh_446F10,
    # type5 狙击发射器键盘 4 变体（0x445E47 行为表 idx4..7，thunk 0x40189D/0x401438/
    # 0x401ECE/0x401FC3 → 真址）——2026-11-14 反汇编 0x447000..0x4473D4 逐条落地。
    0x447000: _beh_447000,
    0x447110: _beh_447110,
    0x447200: _beh_447200,
    0x447320: _beh_447320,
    # 狙击锁定/攻击链行为（0x429DE0/0x429E60/0x429F20）为 Pages 类方法，
    # 由 p4_call_behaviour 的 getattr(type(self), "_beh_%X") 回退分派，不入本表。
    # 0x24 族高频行为
    0x411990: _beh_411990, 0x410E10: _beh_410E10,
    0x416A50: _beh_416A50, 0x416940: _beh_416940,
    0x4127E0: _beh_4127E0,
    0x411470: _beh_411470, 0x410F20: _beh_410F20,
    0x4121C0: _beh_4121C0, 0x4122D0: _beh_4122D0,
    0x416860: _beh_416860, 0x4164B0: _beh_4164B0,
    0x416B20: _beh_416B20, 0x4118C0: _beh_4118C0,
    0x412680: _beh_412680,
    0x412950: _beh_412950, 0x4165A0: _beh_4165A0,
    0x416680: _beh_416680,
    0x41F610: _beh_41F610, 0x4123E0: _beh_4123E0,
    0x419850: _beh_419850, 0x4116C0: _beh_4116C0,
    0x415D70: _beh_415D70, 0x416FA0: _beh_416FA0,
    0x411AD0: _beh_411AD0, 0x4115B0: _beh_4115B0,
    0x412510: _beh_412510, 0x419EC0: _beh_419EC0,
    0x41E7B0: _beh_41E7B0, 0x4185C0: _beh_4185C0,
    0x417940: _beh_417940, 0x417F30: _beh_417F30,
    0x41DD70: _beh_41DD70,   # 0x29 护卫状态机 / 0x27 帧表发射器
    0x41CF70: _beh_41CF70, 0x41F780: _beh_41F780,   # 0x29 两段横穿 / 0x29 回旋镖
    0x4194A0: _beh_4194A0, 0x419540: _beh_419540,   # 0x28 定高左退 / 抛物线跳跳
    0x41A220: _beh_41A220,                          # 0x28 减速下坠纵摆
    0x40EDB0: _beh_40EDB0, 0x40EF60: _beh_40EF60, 0x40F0F0: _beh_40F0F0,   # 0x23 残骸链
    0x4113E0: _beh_4113E0, 0x4112F0: _beh_4112F0,   # 0x24 折返斜升 / 入场摆动
    0x41D910: _beh_41D910,                          # 0x29 脱离加速
    0x415410: _beh_415410, 0x415CE0: _beh_415CE0, 0x415E60: _beh_415E60,   # 0x26 批1
    0x418C30: _beh_418C30, 0x41F700: _beh_41F700, 0x419E30: _beh_419E30,   # 批1
    0x41DCE0: _beh_41DCE0, 0x422D40: _beh_422D40,   # 批1
    0x4070E0: _beh_4070E0, 0x4197B0: _beh_4197B0, 0x41A180: _beh_41A180, 0x413930: _beh_413930,   # 批2
    0x414380: _beh_414380, 0x414D60: _beh_414D60,   # 批3
    0x4107D0: _beh_4107D0,                          # 批4
    0x415980: _beh_415980,                          # 批5
    0x415140: _beh_415140, 0x414C70: _beh_414C70,   # 批6
    0x414080: _beh_414080,                          # 批7
    0x415200: _beh_415200,                          # 批8
    0x415480: _beh_415480,                          # 批9
    0x4156D0: _beh_4156D0,                          # 批10
    0x415A90: _beh_415A90,                          # 批11
    0x414170: _beh_414170,                          # 批12
    0x414460: _beh_414460,                          # 批13
    0x414FB0: _beh_414FB0,                          # 批14
    0x4145A0: _beh_4145A0,                          # 批15
    0x4148B0: _beh_4148B0,                          # 批16
    0x414B50: _beh_414B50,                          # 批17
    0x416770: _beh_416770, 0x417160: _beh_417160,   # 批18
    0x417280: _beh_417280,                          # 批19
    0x417410: _beh_417410,                          # 批20
    0x4175C0: _beh_4175C0,                          # 批21
    0x419610: _beh_419610, 0x4196E0: _beh_4196E0,   # 批22
    0x419910: _beh_419910, 0x419B70: _beh_419B70,   # 批23
    0x419A30: _beh_419A30,                          # 批24
    0x419C60: _beh_419C60, 0x419D50: _beh_419D50,   # 批25
    0x419F80: _beh_419F80, 0x41A300: _beh_41A300,   # 批26
    0x41A480: _beh_41A480,                          # 批27
    0x41BDA0: _beh_41BDA0,                          # 批28
    0x41BF60: _beh_41BF60,                          # 批29
    0x41AE20: _beh_41AE20,                          # 批30
    0x41D080: _beh_41D080,                          # 批31
    0x41D330: _beh_41D330,                          # 批32
    0x41D990: _beh_41D990,                          # 批33
    0x41E960: _beh_41E960,                          # 批34
    0x41EB60: _beh_41EB60, 0x41EC40: _beh_41EC40,   # 批35
    0x41EE00: _beh_41EE00,                          # 批36
    0x41F3A0: _beh_41F3A0,                          # 批37
    0x41FE10: _beh_41FE10,                          # 批38
    0x41F860: _beh_41F860,                          # 批39
    0x41F010: _beh_41F010,                          # 批40
    # —— 0x29 族高段 + 0x2D00001C（2026-11-11 批78）——
    0x4200C0: _beh_4200C0,                          # 0x29000018 关8真boss（九态）
    0x421FE0: _beh_421FE0,                          # 0x29000019 入场舱
    0x422DD0: _beh_422DD0,                          # 舱体掉落自爆（0x401852）
    0x4220A0: _beh_4220A0,                          # 0x2900001A 编队僚机
    0x422170: _beh_422170,                          # 0x2900001B 隐形追踪卫星
    0x422470: _beh_422470,                          # 0x2900001C 弧线小机（0x401C7B）
    0x4225E0: _beh_4225E0,                          # 0x2900001D 下降卫星
    0x422830: _beh_422830,                          # 0x2900001E 阶梯下落小机
    0x422950: _beh_422950,                          # 0x2900001F 摆动小机
    0x422A90: _beh_422A90,                          # 0x29000020 卫星环射体
    0x40A020: _beh_40A020,                          # 0x2D00001C/1D 环轨部件
    0x40EBB0: _beh_40EBB0,                          # 0x2300000B 左飘机
    0x40ECE0: _beh_40ECE0,                          # 0x2300000C 随从
    0x40F190: _beh_40F190,                          # 0x23000010 中boss
    0x40F2D0: _beh_40F2D0,                          # 0x23000011 瞬移小机
    0x40A930: _beh_40A930,                          # 批41
    0x40B040: _beh_40B040,                          # 批42
    0x40CE90: _beh_40CE90,                          # 批43
    0x40BB60: _beh_40BB60,                          # 批44
    0x40C590: _beh_40C590,                          # 批45
    0x40D030: _beh_40D030,                          # 批46
    0x4047E0: _beh_4047E0,                          # 批47
    0x404D00: _beh_404D00,                          # 批48
    0x404FA0: _beh_404FA0,                          # 批49
    0x4051A0: _beh_4051A0,                          # 批50
    0x40F4F0: _beh_40F4F0,                          # 批51
    0x40F610: _beh_40F610,                          # 批52
    0x40FD10: _beh_40FD10,                          # 批53
    0x40FEA0: _beh_40FEA0,                          # 批54
    0x410470: _beh_410470,                          # 批55
    0x4108C0: _beh_4108C0,                          # 批56
    0x4114C0: _beh_4114C0, 0x411790: _beh_411790, 0x411A00: _beh_411A00,   # 批58
    0x414E40: _beh_414E40,                          # 批59
    0x4158A0: _beh_4158A0, 0x415BB0: _beh_415BB0,   # 批60
    0x416CF0: _beh_416CF0,                          # 批61
    0x412B60: _beh_412B60,                          # 批62
    0x4130D0: _beh_4130D0,                          # 批63
    0x4053A0: _beh_4053A0,                          # 批64
    0x405510: _beh_405510,                          # 批65
    0x405600: _beh_405600,                          # 批66
    0x4064E0: _beh_4064E0,                          # 批67
    0x4068C0: _beh_4068C0,                          # 批68
    0x406A20: _beh_406A20,                          # 批69
    0x406BD0: _beh_406BD0,                          # 批70
    0x406D30: _beh_406D30,                          # 批71
    0x406F60: _beh_406F60,                          # 批72
    0x407180: _beh_407180,                          # 批73
    0x407350: _beh_407350,                          # 批74
    0x408540: _beh_408540,                          # 批75
    0x4098E0: _beh_4098E0,                          # 批76
    0x409C20: _beh_409C20,                          # 批77
    0x40F880: _beh_40F880,                          # 批57
    0x41A090: _beh_41A090, 0x416BE0: _beh_416BE0,
    0x411200: _beh_411200, 0x411040: _beh_411040,
    0x411120: _beh_411120, 0x411C10: _beh_411C10,
    # 0x42E460 族 8 变体经 p4_call_behaviour 的 getattr 回退
    # （_beh_<真址:X>，v4..v7 与 v0..v3 逐字节同语义）
    0x447410: _beh_447410,
    0x448C70: _beh_10000001,
    0x447F90: _beh_447F90,
    0x447640: _beh_447640,
    0x448230: _beh_448230,
    0x40E790: _beh_23000007,
    0x40E8C0: _beh_23000008,
    0x40EAF0: _beh_2300000A,
    0x40E520: _beh_23000005_06,
    0x4466F0: _beh_type1_follow,
    0x4467D0: _beh_type1_follow_b,
    0x446A10: _beh_446A10,
    0x446AD0: _beh_446AD0,
    0x40E230: _beh_23000003,
    0x423A40: _beh_423A40,          # 0x51 族（thunk 0x4019EC）
    0x423B30: _beh_423B30,          # （thunk 0x402504）
    0x423EE0: _beh_423EE0,          # （thunk 0x40169A）
    0x424290: _beh_424290,          # （thunk 0x4021A8）
    0x423980: _beh_423980,          # （thunk 0x40173F）
    0x430520: _beh_430520,          # （thunk 0x4022F7）
    **{a: globals()[f"_beh_p4slot_{a:06X}"] for a in P4_SPAWN_SLOTS},
}     # 行为地址 → 实现函数（每实现一个就登记，未登记即"未实现"）


class Page4Mixin:
    @staticmethod
    def _p4_block_data() -> dict:
        """`remake/p4_block.json` 的**其它**数据（目前只有 `vm_chains`）。

        参数块常量由 `p4_block_tables.py` 提供；生成器从原始 exe 机械提取，见 `p4_block()`。
        """
        global _P4_BLOCK
        if _P4_BLOCK is None:
            import json
            from pathlib import Path
            f = Path(__file__).resolve().parent.parent / "p4_block.json"
            _P4_BLOCK = json.loads(f.read_text(encoding="utf-8"))
        return _P4_BLOCK

    # ---- 0x4505B0 参数块 -----------------------------------------------
    # 常量表由 `remake/build_p4_block.py` 从原始 exe 提取 ⇒
    # `remake/p4_block_tables.py`。不要手改生成文件。
    #
    # 块基址 B = esp+0x10；`mov [esp+X],imm` 的块偏移 = X-0x10-pend（pend = 已压参数个数）。
    # 三条分支（si=关 [0x4AB5C8]、bp=周目 word[0x4AB5CA]）：
    #   A_flag 0x450651  0x45B030(0x4AB5B0,1) 为真（bit1 已置）
    #   A      0x45069A  si<8 且 bp<=3
    #   B      0x450943  si<8 且 bp>3
    #   C      0x45096E  si>=8
    def p4_block(self) -> bytearray:
        import sys as _sys
        from pathlib import Path as _P
        _r = str(_P(__file__).resolve().parent.parent)
        if _r not in _sys.path:
            _sys.path.insert(0, _r)
        from p4_block_tables import BLOCK_SIZE, LITERALS, TABLES

        # 0x4505E4 `mov esi,[0x4AB5C8]`：esi 取整个 dword。**分支极性（2026-11-14 勘误）**：
        # 0x450686 `cmp si,8` / 0x450690 `cmp bp,3` 是 **16 位**比较（0x20000 低半=0 → A 分支），
        # 而组号 `0x4506F1 lea ecx,[esi*4+0xb]` 用 **32 位 esi** ⇒ 0x20000*4+0xB = 0x8000B，
        # 经 load_chain 的 &0xFFFF = **链 11**（关 N = 11+4N，与 0x499798 链表逐项吻合）。
        # 2026-11-12 的"全 32 位分支"把 0x20000 送进 C ⇒ 链 0（八关连打）⇒ 无 Boss/无幕间牌。
        self.stage_no = int(getattr(self, "theatre", 0)) & 0xFFFFFFFF   # 0x4AB5C8 全 dword
        self.loop_no = (self.stage_no >> 16) & 0xFFFF                   # word[0x4AB5CA] 周目
        si32 = self.stage_no                      # [0x4AB5C8]（组号 lea 用 32 位）
        si = si32 & 0xFFFF                        # 分支用 16 位 si
        bp = int(self.loop_no) & 0xFFFF           # word[0x4AB5CA]
        blk = bytearray(BLOCK_SIZE)

        def put(o: int, v: int) -> None:
            blk[o] = v & 0xFF
            blk[o + 1] = (v >> 8) & 0xFF

        def literals(name: str) -> None:
            """把该分支的全部**字面量**写入（动态字段随后覆盖）。"""
            for off, val in LITERALS[name].items():
                if val <= 0xFF:
                    blk[off] = val
                else:
                    put(off, val)

        # 0x450605..0x450644：四个位段回读 —— **在分支之前**（两条路径共用）。
        # 2026-11-12 修：旧实现把这段放在分支尾部 ⇒ 旁路（普通局）早退时块内
        # 0x18(选机)/0x1B(bit9)/0x1C(鍛錬)/0x1D(操作器) 全 0，p4_write_state 再把它们
        # 写回状态字 ⇒ **选机恒 0（永远撃）、操作器位被清 ⇒ 键盘预设 7..14（kb=0）
        # 永远生效、鍛錬位被清**。实机 rp_last.dat 头 +0x18=选机、+0x1B..0x1D=三旗标
        # （+0x19=0x64 继续门、+0x1A=6 命数）证实这段在两条路径都执行。
        blk[0x18] = (self.keys.bits >> 14) & 3         # 0x450638/0x450644 0x45AFC0(…,0xC000)
        blk[0x1B] = 1 if self.keys.test(0x200) else 0  # 0x450605/0x450611 0x45AFF0(…,0x200)
        blk[0x1C] = 1 if self.keys.test(1) else 0      # 0x45060A/0x450615 0x45AFF0(…,1)
        blk[0x1D] = 1 if self.keys.test(2) else 0      # 0x45061A/0x450625 0x45AFF0(…,2)

        # 0x450648 `0x45B030(0x4AB5B0,1)`：0x45B030 = **位清零测试**（bits&mask==0 → 1，
        # 实测 0x45B03B neg/sbb/inc 序列）⇒ bit0 **未**置（通常游戏）走 A_flag：
        # a3=6（残撃 5 可见）、a4=0x64（开场点击门开）。鍛錬（bit0 置）才走分支 A。
        # 旧实现 test(1) 反向 ⇒ 普通周目命数不显示（2026-11-06 修正）。
        if not self.keys.test(1):
            literals("A_flag")
            # 0x450651 `push ebx`(ebx=0)=0x45AFC0 的 mask 实参（ret 4 消费）⇒ 之后
            # esp=S-0xE8：[esp+0x29]=B+0x19=0x64、[esp+0x2A]=B+0x1A=6、
            # [esp+0x22/24/26]=B+0x12/14/16(word 0)——与实机 rp_last.dat 头 +0x19/+0x1A 吻合。
            blk[0x19] = 0x64
            # 组号：exe 普通周目在 A_flag 早退路径不写 +0x10，靠 p4_enter 同深度栈残留
            # 等效携带 `esi*4+0xB`（链索引步长 4：关1=11、关2=15…与 0x499798 链表吻合；
            # 32 位 lea 经 load_chain 的 &0xFFFF 取低半）。复刻无栈残留可依赖 ⇒ 显式写入
            # （旧实现缺这条 ⇒ +0x10 恒 0 ⇒ VM 装链 0=八关连打 ⇒ 无 Boss/无幕间牌，
            # 流 46 直接跳流 47 —— 2026-11-14 修）。
            put(0x10, ((si32 * 4 + 0x0B) & 0xFFFF))
            return blk

        name = "A" if (si < 8 and bp <= 3) else ("B" if si < 8 else "C")
        literals(name)

        if name == "A":
            idx = si + bp * 8
            put(0x10, (si32 * 4 + 0x0B) & 0xFFFF)      # 0x4506F1 lea ecx,[esi*4+0xb]（32 位 esi）
            put(0x12, TABLES["0xa4"][idx])             # 0x450833/0x450908 → [esp+0x22]
            v = TABLES["0x64"][idx]                    # 0x450903/0x45090D → [esp+0x24]
            put(0x14, v)
            put(0x16, min(v // 7, 0x0C))               # 0x450915 魔数 0x92492493（/7）→ 钳 0xC
            blk[0x1A] = 0xFF                           # 0x450939
        elif name == "B":
            put(0x10, si * 4 + 0x38)                   # 0x450943 lea ecx,[esi*4+0x38]
            # 0x45094A..0x450964：0x320 / 0x64 / 0xC / 0xFF 已在 LITERALS["B"] 里
        else:                                          # C：四张按周目查的表
            put(0x10, TABLES["0x54"][bp])              # 0x4509B7 dx=[esp+eax+0x54] → [esp+0x20]
            put(0x12, TABLES["0x4c"][bp])              # 0x4509CF cx=[esp+eax+0x4c] → [esp+0x22]
            put(0x14, TABLES["0x5c"][bp])              # 0x4509E5 dx=[esp+eax+0x5c] → [esp+0x24]
            put(0x16, TABLES["0x3c"][bp])              # 0x450A0A cx=[esp+eax+0x3c] → [esp+0x26]
            blk[0x19] = 0                              # 0x450A1D mov byte[esp+0x29],bl
            blk[0x1A] = TABLES["0x3c"][4 + bp] & 0xFF  # 0x450A14 mov dl,byte[esp+eax+0x44]

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
        # 0x450AE7..0x450AFA：[0x56CCB4]=页机臂、[0x56CCB5]=(当前页 == 11)
        self.p4_stat[0x56CCB5] = 1 if getattr(self, "page", 4) == 11 else 0
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
        # 0x454A08 0x44E620(0x4AB454, 0x17, 0, 0, 0)：阶段进场装载**预设 23**
        # （键盘 4px/帧 + 鼠标 1:1 捕获 5，两者同开）并把指针种子设 (0,0)。
        # 战斗中自机行为经 0x446470 换到 7..12（鼠标模式）/15..20（键盘模式）。
        self.inp.set_preset4(0x17, (0, 0))

        # 0x450BBD..0x450D59：21 条音效槽装载（0x450140）
        ok = True
        for slot, wav in P4_SE_SLOTS:
            if not self.load_wave(slot, wav):
                ok = False
                break
        if not ok:
            self.flags.set(8)                     # 0x450D62 `0x4AB5C0 |= 8`

        # 0x450D6E..0x450DA2
        # 0x450D6E mov ecx,[esp+0x18]：块偏移 0x10 的 dword（= si*4+0x0B 组号 | 高字）。
        # 旧读 0x0E ⇒ 0x4602D0 的 movsx cx 恒取 0 ⇒ 组号恒 0（永远播第 1 关的流组）。
        self.vm_init_script(self._p4_dword(b, 0x10))   # 0x401D84 → 0x4602D0(0x56CC4C,组号)
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
        """`0x45B0A0`：**布尔** or / and-not —— `test value,value; jz andnot 分支`
        （0x45B0A0..0x45B0CA 实证）：value 非 0 → `|= mask`，0 → `&= ~mask`。
        旧实现按位域对齐（`(bits & ~mask) | (mask & value)`）⇒ value=1 的 mask>1 位
        全被丢、value=0 也动位 —— `p4_write_state` 曾把 bit1（操作器）每次进场清掉
        ⇒ 键盘预设 7..14（kb=0）恒生效（页4 方向键全灭）。"""
        obj.bits = ((obj.bits | mask) if int(value) != 0 else (obj.bits & ~mask)) & 0xFFFFFFFF

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
        _t = self._p4_tbl4ab5cc()                         # ★ 同一份表的字节模型，
        _t[4] = self.sysf2.b4                             #   0x45C7D0 从这里读
        _t[5] = self.sysf2.b5
        self.stream_reset()                       # 0x458E15 0x402081 → 0x459A80(0x56B95C)
        self.sysf.clear()                         # 0x458E1C 0x45AF10(0x56CC84,0)

    # ---- 0x450FE0 -------------------------------------------------------
    def p4_flow_vm(self) -> None:
        """`0x450FE0`（0xF0 字节）：流程 VM 每帧一步 + 命令字分发。

        `0x450FF9 0x45B030(0x4AB5B0,1)`：位已置返回 0 ⇒ `je 0x451091`。
        故 **bit0 置 → 0x2E/0x58 分支；bit0 清 → cmd 0/9 分支**（与 §10.7 一致）。
        返回值被 `0x451110` 丢弃（`docs/p4_step_0x451110.md` 更正 2）。
        """
        # 0x460376：VM 的 +0x38 旗标子对象 = 0x56CC84（sysf），0x45B030(…,0) 任一位置位
        # ⇒ 整段停走（时钟与游标都不动，解冻后按时间戳继续）。置位点：0x2=0x61000002
        # 演出等待门、0x4=0x51000001 结算计数、0x10=0x51000002 继续总控 ctor（t=8550
        # Boss 出现后冻结时间线）、0x20/0x40=二面 boss/庆典、0x80=继续总控出口残留。
        self.vm.flags = 1 if self.sysf.bits else 0
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
        global _P4_ACTIVE_PAGES
        _P4_ACTIVE_PAGES = self
        if os.environ.get("P4_DIAG") and self.p4_frames % 120 == 0:
            print(f"[p4diag] f={self.p4_frames} n43c={getattr(self, 'p4_n43c', 0)}  lay={getattr(self.layers.tab.get(0),'bind_id',None)},{getattr(self.layers.tab.get(1),'bind_id',None)},{getattr(self.layers.tab.get(2),'bind_id',None)}"
                  f"beh_missing={dict(getattr(self, 'p4_beh_missing', {}))} "
                  f"ent0={[(hex(e.g32(0x14)), e.node.layer, e.node.rect) for e in self.p4_q43c[:3] if e.node]} "
                  f"actor={[(hex(x.g32(0x14)), x.s32(0x04), x.s32(0x08)) for x in self.actorq]} "
                  f"intro={[((x.g32(0x1C)>>28)&0xF, x.g32(0x1C)&0x0FFFFFFF) for x in self.ui52c if getattr(x,'raw',None) and x.type_word==0x6B000001]} "
                  f"other={ {k: len(v) for k, v in getattr(self, 'p4_other', {}).items()} } "
                  f"chain={getattr(self.vm, 'chain', None)} q={self.vm.queue[:6]} "
                  f"cur={self.vm.cur}/{len(self.vm.buf)} next_t={int.from_bytes(self.vm.buf[self.vm.cur + 2:self.vm.cur + 4], 'little') if self.vm.cur + 4 <= len(self.vm.buf) else None} "
                  f"vmframe={self.vm.frame} "
                  f"zero_beh_types={sorted({e.g32(0x14) for e in self.p4_q43c if e.g32(0x40) == 0})[:8]} "
                  f"boss={[(e.s32(4), e.s32(8), e.s32(0x18), e.s32(0x1C), tuple(e.node.dst) if e.node else None, e.node.active if e.node else None) for e in self.p4_q43c if e.g32(0x14) == 0x23000015]} "
                  f"fade={getattr(self, 'fade_a', None)}/{getattr(self, 'fade_b', None)} "
                  f"flashes={[(x.aux, x.a3, x.a4) for x in self.ui52c if getattr(x, 'beh', '') == 'flash']} "
                  f"q4cc={[(hex(e.g32(0x14)), e.beh, e.node.dst if e.node else None) for e in self._p4_q('ui4cc') if hasattr(e,'tick')][:6]} "
                  f"q4cc_types={dict(collections.Counter(hex(e.g32(0x14)) for e in self._p4_q('ui4cc') if hasattr(e,'tick')))} "
                  f"miss={(getattr(self, 'p4_beh_missing_types', {}) and
                            [(hex(b), hex(t), c) for (b, t), c in sorted(self.p4_beh_missing_types.items(),
                             key=lambda kv: -kv[1])[:3]]) or []}",
                  flush=True)
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
            _w = self.p4_cfg_word()
            _br, _ct = self.p4_451630_adjust(_w) if _w else (0, 0)
            if not self.p4_load_palette(2, _ct, _br):   # 0x45168E(mgr,2,对比,亮度)
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
        if os.environ.get("P4_DIAG"):
            print(f"[p4diag] frames={self.p4_frames} n43c={getattr(self, 'p4_n43c', 0)} "
                  f"beh_missing={dict(getattr(self, 'p4_beh_missing', {}))} "
                  f"other_ops={ {k: len(v) for k, v in getattr(self, 'p4_other', {}).items()} } "
                  f"vm_chain={getattr(self.vm, 'chain', None)} vm_queue={self.vm.queue[:6]}",
                  flush=True)
        if self.audio is not None:
            self.audio.bgm_stop()
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
        self.p4_links: dict[int, "Ent"] = {}   # 0x23 亲子链接句柄表（0x40E659 读 [[0x1C]+0x34]）
        self.p4_beh_missing: dict[int, int] = {}
        self.p4_beh_missing_types: dict[tuple, int] = {}
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
        """`0x451186..0x45131C`：回放进度叠加文字（门 `byte[0x56CCC9]` 且 `byte[0x56CCB5]`）。

        ```
        0x451186 al = byte[0x56CCC9]; je 0x45131D            ; 调试开关（写点 0x45816F）
        0x451193 al = byte[0x56CCB5]; je 0x45131D            ; 回放模式
        0x4511A7 0x45A610(0x4AB570)   → esi = [0x4AB590]      ; 已播帧
        0x4511B3 0x45DB00(0x4CD5D8)   → ebp = [0x4CD5D8+0x9E380]  ; 总帧
        0x4511C1 if ([0x56CCD0] == ebp) skip
        0x4511CB   if (esi != [0x56CCCC]):
        0x4511E8       v = (ebp*100 - [0x56CCD0]*100) / (esi - [0x56CCCC])
        0x4511F4       [0x56CCD4] = (v < 0x3E8) ? v : 0x3E7
        0x451200   [0x56CCD0] = ebp ; [0x56CCCC] = esi
        0x451228 sprintf("TM:%05d ", min(esi,0x5F5DD18)/1000)
        0x451277 sprintf("TS:%05d ", min(ebp,0x5F5DD18)/1000)
        0x4512BC sprintf("TA:%03d ", [0x56CCD4])
        0x451316 0x44D330(0x4AA7B0, x=0, y=0x1D4, str, h=0x0C, fg=0xD9, bg=0xB4)
        ```

        `0x4511E8` 是**无符号** `div edi`（`edi = esi - ecx` 为 0 时会被 `0x4511CB` 的
        `cmp/je` 挡掉，不会除零）。三段 sprintf 的结果是**拼接**成一行（`repne scasb`
        + `rep movs` 的 strcat 序列，0x451233..0x4512F0）。"""
        if not (self.p4_stat.get(0x56CCC9, 0) & 0xFF):      # 0x45118D
            return
        if not self.replay_mode:                            # 0x45119A
            return
        rp = getattr(self, "p4_replay", None)
        cur = self.p4_stat.get(0x4AB590, 0) & 0xFFFFFFFF     # 0x4511A7 [0x4AB570+0x20]
        total = (rp.count if rp is not None else 0) & 0xFFFFFFFF   # 0x4511B3
        last_total = self.p4_stat.get(0x56CCD0, 0) & 0xFFFFFFFF     # 0x4511BA
        if last_total != total:                             # 0x4511C1
            last_cur = self.p4_stat.get(0x56CCCC, 0) & 0xFFFFFFFF
            if cur != last_cur:                             # 0x4511CB
                d = (cur - last_cur) & 0xFFFFFFFF           # 0x4511D0
                if d:
                    v = ((((total - last_total) & 0xFFFFFFFF) * 100) // d) & 0xFFFFFFFF
                    self.p4_stat[0x56CCD4] = 0x3E7 if v >= 0x3E8 else v   # 0x4511F4/0x4511F6
            self.p4_stat[0x56CCD0] = total                  # 0x451200
            self.p4_stat[0x56CCCC] = cur                    # 0x451206
        s = ("TM:%05d " % (min(cur, 0x5F5DD18) // 1000)      # 0x451228
             + "TS:%05d " % (min(total, 0x5F5DD18) // 1000)  # 0x451277
             + "TA:%03d " % (self.p4_stat.get(0x56CCD4, 0) & 0xFFFFFFFF))   # 0x4512BC
        # 0x451316：`0x44D330` 的 7 个实参（push 序 bg,fg,h,str,y,x,a0）
        self._p4_dbg_text = (s, 0, 0x1D4, 0x0C, 0xD9, 0xB4)

    def p4_collide(self) -> int:
        """0x451461..0x4514A6：`0x43BF60` 建上下文（本体只做 `[ctx]=0x498754` vtable，
        0x43BFB0 同），返回非 None 让 p4_step 跑三组：
        `0x43BFD0(ctx,0x4AD40C,0x4AD43C)`（演员×43C）、`0x43C060(ctx,0x4AD46C,0x4AD43C)`
        （46C 弹×43C 敌）、`0x43C0F0(ctx,0x4AD49C,0x4AD40C)`（49C 敌弹×演员）。
        命中回调 p4_43c460（弹→敌：伤害/火花/最后一击）/p4_43ccc0 已按反汇编落地（§16.269）。"""
        return 0x498754

    # ---- 0x42 家族（开场）----------------------------------------------
    def p4_spawn42(self, x: int, y: int, typ: int, prm: int) -> None:
        """`0x43A3C0(0x4AD4CC, &rec)` → ctor `0x4355E0` 的 0x42 分支。"""
        e = Ent42(int(x), int(y), int(typ), int(prm), owner=self)
        if os.environ.get("P4_SPAWNTRACE"):
            c = self.p4_stat.setdefault("spawn_counts", {})
            c[hex(typ)] = c.get(hex(typ), 0) + 1
            if self.p4_frames % 60 == 0 or c[hex(typ)] <= 3:
                print(f"[spawn] f={self.p4_frames} type={hex(typ)} prm={prm} "
                      f"at=({x},{y}) total={c[hex(typ)]}", flush=True)
        self._p4_q("ui4cc").append(e)

    # ---- 0x51 族（死亡→继续→结算演出）：0x44B140 → 0x449150 → 0x422EF0 ----
    def p4_51_spawn(self, x: int, y: int, typ: int, prm) -> "Ent":
        """`0x430400(&rec,…)` + `0x44B140(0x4AD4FC,&rec)`：0x5C 实体入 ui4fc，
        共享 ctor `0x449150`（0x430450 拷记录 → vtable 0x4987E8 → 0x51 高位转
        `0x422EF0(this, rec)`），再按 `0x4234D0` 跳表走 case。"""
        e = Ent(int(x), int(y), int(typ), 0)
        if isinstance(prm, int):
            e.d32(0x0C, prm & 0xFFFFFFFF)          # 0x430450：rec.param → [ent+0xC]
        e.d32(0x40, P4_51_BEH_THUNK.get(typ & 0xFFFFFFFF, 0))
        e.beh = P4_51_BEH[typ & 0xFFFFFFFF]
        e.node = DNode(0, 0, 0)                    # 0x430450 建节点；层号由各 case 重写
        e.node.active = 0
        self._p4_q("ui4fc").append(e)
        self.p4_422ef0(e, prm)                     # 0x449375 push esi(rec); call 0x422ef0
        return e

    def p4_spawn52c_flash(self, x: int, y: int, typ: int, prm: int) -> None:
        """`0x430400(&rec,…)` + `0x445AA0(0x4AD52C,&rec)`：52C 队列原语（0x61 亮度族等）。
        rec 布局：rec0=x、rec1=y、rec2=typ、rec3=prm。"""
        if typ == 0x61000005:
            self.spawn_flash(x, y, prm)            # init 0x42730B：[+0x1C]=x [+0x20]=y [+0x24]=prm
            return
        if typ == 0x61000004:
            self.p4_spawn_61000004(x, y, prm)      # ctor 0x4272DD / 行为 0x427580（prm 有符号语义）
            return
        if (typ & 0xFFFFFF00) == 0x61000000:       # 0x61 族其余型（含 0x423BC5 的 0x61000007 淡出）
            self.spawn(self._p4_q("ui52c"), typ, x, y, prm)
            return
        self.p4_other.setdefault("52c", []).append((x, y, typ, prm))

    def p4_422ef0(self, e, prm) -> None:
        """ctor `0x422EF0`：`[esi+0x14] + 0xAEFFFFFF` 与 9 比较 → `jmp [eax*4+0x4234D0]`。
        跳表 10 项：0→0x423027、1→0x42319C、3→0x423304、4→0x4233BB、5→0x4233E3、
        6→0x42343D、9→0x422F13，其余落共用尾 `0x4234C4`（ret，无副作用）。"""
        typ = e.s32(0x14)
        nd = e.node
        if typ == 0x51000001:                      # case 0 @ 0x423027
            if not self.layers.bind(13, 6):        # 0x423037 0x44C640(0x4AA7B0,0xD,6)
                self.flags.set(2)                  # 0x42305A
            else:
                self.layers.color_key(13, 0)       # 0x42304A 0x44CE60(0x4AA7B0,0xD,0)
            e.d32(0x20, self.p4_45f9d0())          # 0x42306F 0x45F9D0 → TS 比率
            e.d32(0x28, 0)
            e.d32(0x2C, 0)
            e.d32(0x24, self.p4_45fa00())          # 0x423086 0x45FA00 → TA 比率
            e.d32(0x30, prm if isinstance(prm, int) else 0)   # 0x4230A0 [edi+0xC]
            nd.layer = 0xD                         # 0x4230A4 [edx]=0xD
            nd.rect = (0, 0, 0x11F, 0x107)         # 0x4230AA 45A750(…,0,0,0x11F,0x107)
            nd.dst = (0xB0, 0x6C)                  # 0x4230DE 45A690(0xB0,0x6C)
            nd.active = 1 if (prm if isinstance(prm, int) else 0) != 0 else 0   # 0x423101 setne
            self.sysf.bits |= 0x4                  # 0x423104 0x45AF30(0x56CC84,4)
            self.p4_423780(e.s32(0x20), 0x60)      # 0x42317A 0x423780(this,[+0x20],0x60)
            self.p4_423780(e.s32(0x24), 0xC0)      # 0x42318A 0x423780(this,[+0x24],0xC0)
        elif typ == 0x51000002:                    # case 1 @ 0x42319C
            if not self.layers.bind(13, 0xE):      # 0x4231AC 0x44C640(0x4AA7B0,0xD,0xE)
                self.flags.set(2)                  # 0x4231CF
            else:
                self.layers.color_key(13, 0)       # 0x4231BF 0x44CE60
            e.d32(0x1C, 0)                         # 0x4231DE [esi+0x1C]=0
            e.d32(0x20, prm if isinstance(prm, int) else 0)   # 0x4231E4 [esi+0x20]=rec[3]
            nd.layer = 0xD                         # 0x4231E7
            if (prm if isinstance(prm, int) else 0) != 0:
                nd.rect = (0, 0xA0, 0xFF, 0xDF)    # 0x4231F2 45A750(…,0,0xA0,0xFF,0xDF)
            else:
                nd.rect = (0, 0, 0xFF, 0x3F)       # 0x423233
            nd.dst = (e.s32(0x04), e.s32(0x08))    # 0x42328E 45A690([esi+4],[esi+8])
            nd.active = 0                          # 0x4232A9 byte[node+0x1C]=0
            self.sysf.bits |= 0x10                 # 0x4232AC 0x45AF30(0x56CC84,0x10)
            v = self.keys.field(0x7F000000)        # 0x4232BB 0x45AFC0(0x4AB5B0,0x7F000000)
            if v < 0x64:                           # 0x4232C3 jae
                self.keys.set_field(0x7F000000, v + 1)   # 0x4232E0 0x45B0E0
            self.p4_45f820(1 if (prm if isinstance(prm, int) else 0) != 0 else 0)   # 0x4232F3
        elif typ == 0x51000004:                    # case 3 @ 0x423304
            if self.audio is not None:
                self.audio.bgm(6)                  # 0x42330D 0x44F600(0x4AB514,1,6)
            e.d32(0x04, 0)                         # 0x423374 [esi+4]=0
            e.d32(0x08, 0)
            e.d32(0x1C, 0)                         # 0x42337A
            e.d32(0x20, 0)                         # 0x42337D
            nd.layer = 0                           # 0x423381 [ecx]=ebx(0)
            nd.rect = (0xC0, 0x180, 0xEF, 0x1AF)   # 0x423383 45A750(…,0xC0,0x180,0xEF,0x1AF)
            nd.dst = (e.s32(0x04) + 0x5C, e.s32(0x08) + 0xE4)   # 0x4233AC +0x5C/+0xE4
            nd.active = 1                          # 0x4234C0
        elif typ in (0x51000005, 0x51000006):      # case 4 @ 0x4233BB / case 5 @ 0x4233E3
            e.d32(0x40, 0x4022F7)
            e.beh = 0x430520
            e.d32(0x1C, 0xFFFFFFFF)                # 0x4233C9/0x4233F7 [esi+0x1C]=-1
            nd.layer = 0xD                         # 0x4233D2/0x423400
            nd.rect = ((0, 0x30, 0x5F, 0x47) if typ == 0x51000005
                       else (0, 0x48, 0xBF, 0x1AF))   # 0x423410 45A750
            nd.dst = (e.s32(0x04), e.s32(0x08))    # 0x423433 45A690([esi+4],[esi+8])
            nd.active = 1                          # 0x4234C0
        elif typ == 0x51000007:                    # case 6 @ 0x42343D
            e.d32(0x40, 0x4021A8)
            e.beh = 0x424290
            if isinstance(prm, Ent):               # 0x423455 rec.param 是父实体指针
                e.p51_parent = prm                 # [esi+0x1C] = *[param]（0x423464）
                e.d32(0x1C, 0)
                e.d32(0x20, 0)                     # 0x423477 [esi+0x20] = param[1] = 0
            else:
                e.d32(0x1C, int(prm) & 0xFFFFFFFF)
                e.d32(0x20, 0)
            nd.layer = 0xD                         # 0x42347B
            nd.rect = (0x198, 0x90, 0x1AF, 0xA7)   # 0x423481 45A750(…,0x198,0x90,0x1AF,0xA7)
            nd.dst = (e.s32(0x04), e.s32(0x08))    # 0x4234A4
            nd.active = 1                          # 0x4234C0
        elif typ == 0x5100000A:                    # case 9 @ 0x422F13
            e.d32(0x40, 0x40173F)
            e.beh = 0x423980
            c = int(prm) if isinstance(prm, int) else 0
            e.d32(0x20, 0)                         # 0x422F2F [esi+0x20]=0
            e.d32(0x1C, c if c != -1 else 0)       # 0x422F21..0x422F32（-1 → 0）
            nd.layer = 0                           # 0x422F38 [eax]=ebx(0)
            if c & 1:                              # 0x422F3D test al,1
                nd.rect = (0xC0, 0, 0xC0, 0x2F)    # 0x422F53 45A750(…,0xC0,0,0xC0,0x2F)
            else:
                nd.rect = (0xC0, 0x30, 0xC0, 0x5F) # 0x422F8F 45A750(…,0xC0,0x30,0xC0,0x5F)
            nd.dst = (e.s32(0x04) - 0x18, e.s32(0x08) - 0x18)   # 0x422FD2 −0x18
            nd.active = 1                          # 0x422FF4
        # 其余 case（2/7/8）→ 0x4234C4 共用尾：无副作用

    # ---- 0x51 族辅助（0x4CD4A0 / 0x4CD590 取值与结算）----
    def p4_45f9d0(self) -> int:
        """`0x45F9D0`：`0x45E7A0([ecx+0x18], [ecx+0x20]) & 0xFFFF`（0x4CD4A0 的 TS 比率）。"""
        return self.p4_45e7a0(self.p4_stat.get(0x4CD4A0 + 0x18, 0),
                              self.p4_stat.get(0x4CD4A0 + 0x20, 0)) & 0xFFFF

    def p4_45fa00(self) -> int:
        """`0x45FA00`：`0x45E7A0([ecx+0x1C], [ecx+0x18]) & 0xFFFF`（TA 比率）。
        ★ push 序：eax=[+0x18] 先进栈、edx=[+0x1C] 后进栈 ⇒ arg1=[+0x1C]、arg2=[+0x18]
        （§16.106：1000*[+0x1C]/[+0x18]——旧实现两参写反，本轮以映像 push 序修正）。"""
        return self.p4_45e7a0(self.p4_stat.get(0x4CD4A0 + 0x1C, 0),
                              self.p4_stat.get(0x4CD4A0 + 0x18, 0)) & 0xFFFF

    def p4_45eea0(self, n: int) -> None:
        """`0x45EEA0(obj, n)`：`[+4] += n`、`[+0x14] += n`、`byte[+0xE1] = 1`（0x4CD4A0）。"""
        self.p4_stat[0x4CD4A0 + 0x04] = (self.p4_stat.get(0x4CD4A0 + 0x04, 0) + n) & 0xFFFFFFFF
        self.p4_stat[0x4CD4A0 + 0x14] = (self.p4_stat.get(0x4CD4A0 + 0x14, 0) + n) & 0xFFFFFFFF
        self.p4_stat[0x4CD4A0 + 0xE1] = 1

    def p4_45f710(self) -> None:
        """`0x45F710(0x4CD4A0)`：剩余 TS/TA 比率各 ×200 加进得分并重建 HUD。
        ```
        0x45F713 eax = 0x45F9D0() ; ×45×8 = ×200 → 0x45EEA0
        0x45F72B eax = 0x45FA00() ; ×200 → 0x45EEA0
        0x45F745 0x45E7F0(0)
        ```"""
        self.p4_45eea0((self.p4_45f9d0() * 0xC8) & 0xFFFFFFFF)
        self.p4_45eea0((self.p4_45fa00() * 0xC8) & 0xFFFFFFFF)
        self.p4_45e7f0(0)

    # ---- 排行榜 0x4AB5CC（§16.106C）：0x45C570 深拷贝 / 0x45C7D0 插入 / 0x45F850 登记 ----
    P4_REC_STRIDE = 0x54                      # 记录 0x54 字节；idx = mode + 2*row；表 2 基址 +0x740

    def p4_45c570(self, dst_off: int, src) -> None:
        """`0x45C570(ecx=tbl, arg1=dst, arg2=src)`：0x54 字节记录深拷贝。
        ```
        0x45C578 eax = [dst+0x4C]（旧附件尺寸）≠0 → 0x47C7E9 释放
        0x45C58C rep movsd 0x15                   record ← src（0x54 字节）
        0x45C597 eax = [src+0x4C]（附件指针 {size,data}）→ 0x47C7C0 分配 + 拷贝
        ```
        复刻侧附件走 p4_stat 键 ("blob4ab5cc", off)（字节模型无指针域）。"""
        t = self._p4_tbl4ab5cc()
        t[dst_off:dst_off + 0x54] = bytes(src)[:0x54]
        # 附件（rec+0x4C 的 {size,data} 指针域）：写附件的子系统（回放挂接）未建，
        # 字节模型无指针域，此处按"无附件"处理——已有附件视为一并释放。
        self.p4_stat.pop(("blob4ab5cc", dst_off), None)

    def _p4_rec_score(self, off: int) -> int:
        t = self._p4_tbl4ab5cc()
        return int.from_bytes(t[off:off + 4], "little")

    def p4_45c7d0(self, rec: bytes, row: int) -> None:
        """`0x45C7D0(ecx=0x4AB5CC, &rec, row)`：排行榜插入（三段）。

        ```
        byte[tbl+5] != 0（第二张表 @+0x740，0x45CA5C）：
            slot = +0x740 + (mode + 2*row)*0x54
            dword[slot] <= dword[rec] 才 0x45C570(slot ← rec) + 0x45D460
        byte[tbl+5] == 0（主表 @+8）：
            ① 影子槽 +0x548 + (mode + 2*rec[0xF])*0x54：rec 分数更大则先拷入
            ② 主插入：mode 列（基址 +8 + mode*0x54，行距 0xA8）自上而下找
               首个 score <= rec 的行 row（顶格 > 全部 → row=8 不插）；row<8 时
               行 7→row+1 逐行下移（0x15 dword 拷贝），写 rec 于 row，
               并把同 row 的**另一模式**槽分数清 0（0x45C8F7）
            ③ 跨模式回填（0x45C92E..0x45CA55）：收 mode 列 7 行的 byte[+0xF] 位图，
               缺两个模式时按分数序从影子槽 +0x4A0/+0x3F8 回填
        0x45D460/0x45D3A0（0x4CD5D8 的 UI 列表更新）以计数登记（该子系统未建）。
        ```"""
        t = self._p4_tbl4ab5cc()
        mode = _p4_s8(t[4])                        # byte[tbl+4]
        rec_mode = _p4_s8(rec[0xF])
        score = int.from_bytes(rec[0:4], "little")
        if t[5] != 0:                              # 0x45C7D5 → 第二张表
            off = 0x740 + (mode + 2 * row) * 0x54
            if not (self._p4_rec_score(off) > score):          # 0x45CA85 ja
                self.p4_45c570(off, rec)
                self.p4_45d460(_p4_s8(t[4]) + 8, score, None)  # 0x45CA9F 0x45D460
            return
        # ① 影子槽（0x45C7E1..0x45C82D）
        shadow = 0x548 + (mode + 2 * rec_mode) * 0x54
        if score > self._p4_rec_score(shadow):
            self.p4_45c570(shadow, rec)
            self.p4_45d460(rec_mode + 8, score, None)      # 0x45C829 0x45D460
        # ② 主插入（0x45C82E..0x45C92D）
        col = 8 + mode * 0x54
        ins = 0
        if self._p4_rec_score(col) > score:                    # 0x45C84E jbe → ins=0
            ins = 0
            while ins < 8 and self._p4_rec_score(col + ins * 0xA8) > score:
                ins += 1                                       # 0x45C852..0x45C866
        if ins < 8:                                            # 0x45C868 je → 不插
            ebp = 7
            while ebp > ins:                                   # 0x45C899..0x45C8D7
                src_off = 8 + (mode + 2 * (ebp - 1)) * 0x54
                dst_off = 8 + (mode + 2 * ebp) * 0x54
                t[dst_off:dst_off + 0x54] = t[src_off:src_off + 0x54]
                self.p4_45d3a0(ebp, ebp - 1, 0)            # 0x45C8CB 0x45D3A0
                ebp -= 1
            other = 8 + (mode + 2 * ins + 1) * 0x54            # 0x45C8DF..0x45C8FE
            t[other:other + 4] = b"\x00\x00\x00\x00"
            self.p4_45c570(8 + (mode + 2 * ins) * 0x54, rec)   # 0x45C917
            st = self.p4_stat
            st["45d460_calls"] = st.get("45d460_calls", 0) + 1
        # ③ 跨模式回填（0x45C92E..0x45CA55）
        bits = 0
        for i in range(7):                                     # 0x45C94F
            cl = _p4_s8(t[8 + (mode + 2 * i) * 0x54 + 0xF])
            bits |= 1 << cl
        if bits == 7:                                          # 0x45C961
            return
        ebp = edi = 0                                          # 0x45C96E
        for cl in range(3):                                    # 0x45C981
            if not (bits >> cl) & 1:
                if ebp == 0:
                    ebp = cl + 8
                else:
                    edi = cl + 8
        if edi != 0:                                           # 0x45C9A2
            sa = 8 + (mode + 2 * edi) * 0x54
            sb = 8 + (mode + 2 * ebp) * 0x54
            if self._p4_rec_score(sa) >= self._p4_rec_score(sb):   # 0x45C9CC jb
                ebp, edi = edi, ebp
        self.p4_45c570(8 + (mode + 2 * ebp) * 0x54,
                       bytearray(t[mode * 0x54 + 0x4A0:mode * 0x54 + 0x4F4]))   # 0x45C9EF
        self.p4_45d3a0(7, ebp, 0)                              # 0x45CA06 0x45D3A0
        if edi != 0:                                           # 0x45CA0B
            self.p4_45c570(8 + (mode + 2 * edi) * 0x54,
                           bytearray(t[mode * 0x54 + 0x3F8:mode * 0x54 + 0x44C]))  # 0x45CA3E
            self.p4_45d3a0(6, edi, 0)                          # 0x45CA50 0x45D3A0

    # ---- 回放/排行文件名与落盘流（0x45CFB0/0x45D3A0/0x45D460）----
    def p4_45cfb0(self, sel_gmtr: int, sel_mj: int, row: int, i: int) -> str:
        """`0x45CFB0(this, 流对象, sel1=[mgr+0x20], sel2=[mgr+0x21], row, i)`：
        **回放文件名构造器**（结果写进流对象；复刻返回字符串）。

        ```
        0x45CFB7 row == 0x63 → "rp_last.dat"                     （最后一局）
        0x45CFEC sel1 == 0   → "rp_gm_" else "rp_tr_"            （gm/tr 两档）
        0x45D01F sel2 == 0   → "m_"      else "j_"               （m/j 两机）
        0x45D066 sprintf(流, "%s%02d_", 前缀, row+1)             （0x4A4B24）
        0x45D071 i == 0 → "gek.dat"；i == 1 → "rin.dat"；否则 "kan.dat"
        ```
        ⇒ 如 `rp_gm_j01_gek.dat`：gm/tr 档 × m/j 机 × 01..NN 关 × 撃/凛/漢 三段。
        五个片段串与 "rp_last.dat" 已逐字节核对（0x4A4B00..0x4A4B48）。"""
        if row == 0x63:
            return "rp_last.dat"
        name = "rp_tr_" if sel_gmtr != 0 else "rp_gm_"
        name += "j_" if sel_mj != 0 else "m_"
        name += "%02d_" % (row + 1)
        name += "gek.dat" if i == 0 else ("rin.dat" if i == 1 else "kan.dat")
        return name

    def p4_45d3a0(self, bl: int, row: int, pad: int) -> None:
        """`0x45D3A0(0x4CD5D8, bl, row, pad)`：**排行文件行重写**——3 次迭代（i=0..2 =
        撃/凛/漢）各向两个流（0x5E10FC、0x5E0FF8）写 0x45CFB0 生成的文件名；
        bl≠0 时 0x463F57(0x5E10FC, 0x5E0FF8)（流间复制），否则 [0x5E6E94](…,1)（CRT 落盘）。
        内容格式（0x45CFB0 之后的写者）未逐条解码——文件名生成已 1:1，写盘以计数登记。"""
        st = self.p4_stat
        for i in range(3):                                  # 0x45D3B0
            n1 = self.p4_45cfb0(st.get(0x4CD5D8 + 0x20, 0),
                                st.get(0x4CD5D8 + 0x21, 0), row, i)
            n2 = self.p4_45cfb0(st.get(0x4CD5D8 + 0x20, 0),
                                st.get(0x4CD5D8 + 0x21, 0), pad, i)
            st.setdefault("45d_streams", []).append((hex(0x5E10FC), n1))
            st.setdefault("45d_streams", []).append((hex(0x5E0FF8), n2))
            if bl:                                          # 0x45D3ED
                st["45d3a0_copy"] = st.get("45d3a0_copy", 0) + 1
            else:
                st["45d3a0_flush"] = st.get("45d3a0_flush", 0) + 1

    def p4_45d460(self, slot: int, score: int, name_ptr) -> None:
        """`0x45D460(0x4CD5D8, slot=rec_mode+8, score, &name)`：**新条目 + 回放落盘**。

        ```
        0x45D498 3× 0x45CFB0(0x5E1304, [+0x20], [+0x21], slot, bl=0..2)   三个分段文件名
        0x45D4D3 eax = [0x4CD5D8+0x9E37C]（已录帧数）；0x402419(3n+1) 申请槽
        0x45D4FF 三块 SoA 拷贝：dst = 槽 + i*n，src = 0x4CD5D8+0x30 + i*0x34BC0，
                  每块 n 字节（dword+余数）——三数组 = 23bit/帧 输入记录（§12）
        0x45D53C 0x45B340(槽, 3n+1)                                       写回放数据
        0x45D555 [+0x10] = 槽号、[+0xC] = n、[+0x2C] = arg3、[+0x22] ← arg3 的 10B（名字）
        0x45D594 3× 0x45CFB0(0x5E1304, …, [+0x1C] 选段) + 0x455090(0x5E1304,1,0)
        0x45D5B8 0x455640(&[ebp+4], 0x2C, …)                              写 0x2C 字节排行记录
        ```
        回放数据文件格式（0x45B340 269 行 / GRPD 头，§15-13）未逐条解码——
        文件名生成与结构已 1:1，写盘以计数登记。"""
        st = self.p4_stat
        n = st.get(0x4CD5D8 + 0x9E37C, 0)
        for bl in range(3):                                 # 0x45D498
            nm = self.p4_45cfb0(st.get(0x4CD5D8 + 0x20, 0),
                                st.get(0x4CD5D8 + 0x21, 0), slot, bl)
            st.setdefault("45d_streams", []).append((hex(0x5E1304), nm))
        st["45d460_slot_req"] = 3 * n + 1                   # 0x402419(3n+1)
        st["45d460_soa_bytes"] = 3 * n                      # 三 SoA 块（0x34BC0 步距）
        st["45d460_rec32"] = (slot, score)                  # 0x455640 的 0x2C 字节记录头
        st["45d460_calls"] = st.get("45d460_calls", 0) + 1

    def p4_45f850(self, v24: int, v28: int, w2c: int) -> None:
        """`0x45F850(0x4CD4A0, &{v24, v28, w2c})`：**排行榜登记**（0x424122 调用）。
        `byte[0x56CCB5]`（回放播放）非 0 直接返回（0x45F85D）。

        0x54 字节记录（esp_flow 逐帧定案）：
        ```
        +0x00 dword [0x4CD4A0+0x04]   总得分
        +0x04 word  0x45E7A0([+8], [+0x10])   ShootRate 千分比
        +0x06 word  0x45E7A0([+0xC], [+8])    ShootRate(Laser) 千分比
        +0x08 word  [0x4CD590+0x34]   （0x460E80）
        +0x0A word  [0x56CCB0]        关卡
        +0x0C word  [0x4CD4A0+0x30]
        +0x0E byte  [0x4CD4A0+0x2C]
        +0x0F byte  0x45AFC0(0x4AB5B0, 0xC000)   槽位＝记录的模式字节
        +0x10 byte  [0x4CD4A0+0x24] 低字节
        +0x11 byte  (0x45AFC0(0x4AB5B0, 0x200) != 0)
        +0x12..+0x1B  {v24 dword, v28 dword, w2c word}   名字前 10 字节（0x51000004 输入）
        +0x1C..+0x3F  36 字节日期时间串（0x46411A = time/localtime、0x463FBA = 格式化）
        +0x40 dword [0x56CCA8]        帧计数
        +0x44 dword [0x56CCAC]
        +0x48 dword [0x4AB570+0x20]   已播帧（0x45A610）
        +0x4C dword [0x4CD4A0+0xE8]
        ```
        `0x45C7D0(0x4AB5CC, &rec, word[+0x24]−1)`（行 = 关卡号−1）。"""
        if self.p4_stat.get(0x56CCB5, 0):
            return                                  # 0x45F85D jne
        st = self.p4_stat
        rec = bytearray(0x54)
        rec[0x00:0x04] = (st.get(0x4CD4A0 + 0x04, 0) & 0xFFFFFFFF).to_bytes(4, "little")
        r1 = self.p4_45e7a0(st.get(0x4CD4A0 + 0x08, 0),
                            st.get(0x4CD4A0 + 0x10, 0)) & 0xFFFF   # 0x45F876
        r2 = self.p4_45e7a0(st.get(0x4CD4A0 + 0x0C, 0),
                            st.get(0x4CD4A0 + 0x08, 0)) & 0xFFFF   # 0x45F88A
        rec[0x04:0x06] = (r1 & 0xFFFF).to_bytes(2, "little")
        rec[0x06:0x08] = (r2 & 0xFFFF).to_bytes(2, "little")
        rec[0x08:0x0A] = (st.get(0x4CD590 + 0x34, 0) & 0xFFFF).to_bytes(2, "little")
        rec[0x0A:0x0C] = (_p4_s16(st.get(0x56CCB0, 0)) & 0xFFFF).to_bytes(2, "little")
        rec[0x0C:0x0E] = (st.get(0x4CD4A0 + 0x30, 0) & 0xFFFF).to_bytes(2, "little")
        rec[0x0E] = st.get(0x4CD4A0 + 0x2C, 0) & 0xFF
        rec[0x0F] = self.keys.field(0xC000) & 0xFF               # 0x45F8B1
        rec[0x10] = st.get(0x4CD4A0 + 0x24, 0) & 0xFF
        rec[0x11] = 1 if self.keys.field(0x200) else 0           # 0x45F8E3
        rec[0x12:0x16] = (v24 & 0xFFFFFFFF).to_bytes(4, "little")
        rec[0x16:0x1A] = (v28 & 0xFFFFFFFF).to_bytes(4, "little")
        rec[0x1A:0x1C] = (w2c & 0xFFFF).to_bytes(2, "little")
        stamp = _p4_result_stamp()                               # 0x46411A + 0x463FBA
        rec[0x1C:0x40] = stamp[:0x24].ljust(0x24, b"\0")
        rec[0x40:0x44] = (self.p4_frame_no() & 0xFFFFFFFF).to_bytes(4, "little")
        rec[0x44:0x48] = (st.get(0x56CCAC, 0) & 0xFFFFFFFF).to_bytes(4, "little")
        rec[0x48:0x4C] = (st.get(0x4AB570 + 0x20, 0) & 0xFFFFFFFF).to_bytes(4, "little")
        rec[0x4C:0x50] = (st.get(0x4CD4A0 + 0xE8, 0) & 0xFFFFFFFF).to_bytes(4, "little")
        self.p4_45c7d0(bytes(rec), _p4_s16(st.get(0x4CD4A0 + 0x24, 0)) - 1)

    def p4_45f820(self, v: int) -> None:
        """`0x45F820(0x4CD4A0, v)`：先（v==0 时）0x45E7F0(0)，再 0x45E7F0(1)。"""
        if not v:
            self.p4_45e7f0(0)
        self.p4_45e7f0(1)

    def p4_45e7f0(self, variant: int) -> None:
        """`0x45E7F0(obj, variant)`：**result.txt 报告**（不是屏幕 HUD——
        0x455090 以 "result.txt" 做名字登记，0x455720 = sprintf + 追加行，0x4A48C0 = "\\r\\n"）。

        头部把单关计数**升级**进累计区（每次调用都做；尾部清零使第二次调用加 0）：
        ```
        0x45E81D dword[ +0x3C] += [ +0x50]   BrokenEnemy
        0x45E822 word [ +0x44] += [ +0x58]   Capture
        0x45E826 dword[ +0x40] += [ +0x54]   BrokenEnemy(Laser)
        0x45E843 word [ +0x46] = max([+0x46], [+0x5A])（jg = 带符号取大）MaxLaserHit
        0x45E856 word [ +0x48] = max([+0x48], [+0x5C])                    MaxRate
        0x45E85E word [ +0x4C] += [ +0x5C]、[ +0x4A] += [ +0x5E]          SHOU/KUN
        ```
        打印基址：Total → edi = +0x3C / ebp = +0x4；Stage → edi = +0x50 / ebp = +0x14
        （`0x45E8AA lea ebp,[esi+4]`、`0x45E8C2 lea ebp,[esi+0x14]`、`0x45E8C5 mov edi,ebx`）。
        行序（格式串原文，0x4A4D20..0x4A4B94）：
        ```
        "---Total---" / "---Stage%d---"(word[+0x24])
        "BrokenEnemy              %4d"  dword[edi]     "+0x3C"/"+0x50"
        "BrokenEnemy(Laser)       %4d"  dword[edi+4]   "+0x40"/"+0x54"
        "Capture                   %3d"  word[edi+8]    "+0x44"/"+0x58"
        "MaxLaserHit               %3d"  word[edi+0xA]  "+0x46"/"+0x5A"
        "MaxRate                  x%3d"  word[edi+0xC]  "+0x48"/"+0x5C"
        "SHOU                      %3d"  word[edi+0xE]  "+0x4A"/"+0x5E"
        "KUN                       %3d"  word[edi+0x10] "+0x4C"/"+0x60"
        "SHOUBonus             %3d0000"  dword[+0x30]   （两 section 共用）
        "Score              %9d0"        dword[ebp]     "+0x4"/"+0x14"
        "ShootRate                %4d%%"  Total: 0x45E7A0([+8],[+0x10])&0xFFFF /10
                                           Stage: 0x45F9D0()&0xFFFF /10
        "ShootRate(Laser)         %4d%%"  Total: 0x45E7A0([+0xC],[+8])&0xFFFF /10
                                           Stage: 0x45FA00()&0xFFFF /10
        "Level                    %4d"  word[0x56CCB0]
        ```
        （/10 = 0x66666667×sar2 魔数 = 截断除 10。）
        尾部：`0x460B20(0x4CD590, variant, word[+0x24])` 追加 MissCount/Continue 两行
        （variant≠0 取 [0x4CD590+0x34]/[+0x40]，否则 [+0x38]/[+0x44]；随后清 [+0x38]/[+0x44]）；
        清 [ebx=+0x50..+0x60] 五个 dword；`byte[0x4CD4A0+0x38] = 1`。

        落盘：exe 经 CRT 写 result.txt（0x46388F/0x4638BE 的 CRT 包装未逐条辨认，按
        "行 + \\r\\n" 组合语义实现）；复刻把同样文本累积到 `p4_stat["result_txt"]`，
        设 `P4_RESULT_FILE` 时才落盘（无头测试不产文件）。"""
        st = self.p4_stat
        base = 0x4CD4A0

        def _g(off: int) -> int:
            return st.get(base + off, 0)

        def _w16(off: int) -> int:
            v = _g(off) & 0xFFFF
            return v - 0x10000 if v & 0x8000 else v

        def _s32(off: int) -> int:
            v = _g(off) & 0xFFFFFFFF
            return v - 0x100000000 if v & 0x80000000 else v

        # 头部：单关 → 累计（0x45E80D..0x45E862）
        st[base + 0x3C] = (_g(0x3C) + _g(0x50)) & 0xFFFFFFFF          # 0x45E826
        st[base + 0x44] = (_g(0x44) + _g(0x58)) & 0xFFFF              # 0x45E822 word
        st[base + 0x40] = (_g(0x40) + _g(0x54)) & 0xFFFFFFFF          # 0x45E831
        if not (_w16(0x46) > _w16(0x5A)):                              # 0x45E838 jg
            st[base + 0x46] = _g(0x5A) & 0xFFFF
        if not (_w16(0x48) > _w16(0x5C)):                              # 0x45E84B jg
            st[base + 0x48] = _g(0x5C) & 0xFFFF
        st[base + 0x4C] = (_g(0x4C) + _g(0x5C)) & 0xFFFF              # 0x45E85E word
        st[base + 0x4A] = (_g(0x4A) + _g(0x5E)) & 0xFFFF              # 0x45E862 word

        if variant:                                                    # 0x45E894
            edi, ebp = 0x3C, 0x04
            lines = ["---Total---"]                                    # 0x45E89C
        else:
            edi, ebp = 0x50, 0x14
            lines = ["---Stage%d---" % _w16(0x24)]                     # 0x45E8AF
        lines += [
            "BrokenEnemy              %4d" % _s32(edi),                # 0x45E8C7
            "BrokenEnemy(Laser)       %4d" % _s32(edi + 4),            # 0x45E8D8
            "Capture                   %3d" % _w16(edi + 8),           # 0x45E8EA
            "MaxLaserHit               %3d" % _w16(edi + 0xA),         # 0x45E8FD
            "MaxRate                  x%3d" % _w16(edi + 0xC),         # 0x45E910
            "SHOU                      %3d" % _w16(edi + 0xE),         # 0x45E923
            "KUN                       %3d" % _w16(edi + 0x10),        # 0x45E936
            "SHOUBonus             %3d0000" % _s32(0x30),              # 0x45E949
            "Score              %9d0" % _s32(ebp),                     # 0x45E95B
        ]
        if variant:                                                    # 0x45E976
            r1 = self.p4_45e7a0(_g(0x08), _g(0x10)) & 0xFFFF
            r2 = self.p4_45e7a0(_g(0x0C), _g(0x08)) & 0xFFFF
        else:                                                          # 0x45E9C8
            r1 = self.p4_45f9d0() & 0xFFFF
            r2 = self.p4_45fa00() & 0xFFFF
        lines += [
            "ShootRate                %4d%%" % _p4_trunc10(r1),        # 0x45E9A4/0x45E9E7
            "ShootRate(Laser)         %4d%%" % _p4_trunc10(r2),        # 0x45EA10/0x45EA0F
            "Level                    %4d" % _p4_s16(st.get(0x56CCB0, 0)),   # 0x45EA1A
        ]
        # 0x460B20(0x4CD590, variant, word[+0x24])：MissCount/Continue 两行
        m = 0x4CD590
        if variant:
            miss, cont = st.get(m + 0x34, 0), st.get(m + 0x40, 0)
        else:
            miss, cont = st.get(m + 0x38, 0), st.get(m + 0x44, 0)
        lines += [
            "MissCount                 %3d" % _p4_s32(miss),         # 0x460B75
            "Continue                  %3d" % _p4_s32(cont),         # 0x460B90
        ]
        st[m + 0x38] = 0                                               # 0x460B9D
        st[m + 0x44] = 0                                               # 0x460BA4
        # 0x45EA57..0x45EA62：5 个 **dword** 清零（+0x50..+0x63），覆盖
        # Broken/Laser/Capture/MaxLaserHit/MaxRate/SHOU/KUN 七个字段键
        for off in (0x50, 0x54, 0x58, 0x5A, 0x5C, 0x5E, 0x60):
            st[base + off] = 0
        st[base + 0x38] = 1                                            # 0x45EA69 byte
        text = st.get("result_txt", "")
        st["result_txt"] = text + "".join(ln + "\r\n" for ln in lines)
        if os.environ.get("P4_RESULT_FILE"):
            with open("result.txt", "a", encoding="cp932", newline="") as fh:
                fh.write("".join(ln + "\r\n" for ln in lines))

    def p4_44d060(self, src_layer: int, dst_xy: tuple[int, int],
                  dst_layer: int, src_rect: tuple[int, int, int, int]) -> None:
        """`0x44D060(mgr, 源层, &目标点, 目标层, &源矩形)`：`call [src_vtable+0x1C]`、
        flags 0x10 = DDBLTFAST_SRCCOLORKEY —— 层→层**色键** blit。
        （实参角色由 0x423690 的字形流逐 esp 定案：arg2 = &{x,y}、arg4 = &源矩形。）"""
        s = self.layers.tab.get(src_layer)
        d = self.layers.tab.get(dst_layer)
        if s is None or d is None:
            return
        l, t, r, b = src_rect
        x, y = int(dst_xy[0]), int(dst_xy[1])
        sh, sw = s.buf.shape
        l = max(0, min(int(l), sw - 1)); r = max(0, min(int(r), sw - 1))
        t = max(0, min(int(t), sh - 1)); b = max(0, min(int(b), sh - 1))
        if r < l or b < t:
            return
        bw, bh = r - l + 1, b - t + 1              # 45A750 的矩形是闭区间
        dx, dy = x, y
        if dx < 0:
            l2 = l - dx; bw += dx; dx = 0
        else:
            l2 = l
        if dy < 0:
            t2 = t - dy; bh += dy; dy = 0
        else:
            t2 = t
        bw = min(bw, d.buf.shape[1] - dx); bh = min(bh, d.buf.shape[0] - dy)
        if bw <= 0 or bh <= 0:
            return
        patch = s.buf[t2:t2 + bh, l2:l2 + bw]
        if s.ckey >= 0:
            region = d.buf[dy:dy + bh, dx:dx + bw]
            m = patch != (s.ckey & 0xFF)
            region[m] = patch[m]
        else:
            d.buf[dy:dy + bh, dx:dx + bw] = patch

    def p4_44d290(self, layer: int, dst_rect: tuple[int, int, int, int],
                  color: int) -> None:
        """`0x44D290(mgr, 层, &目标矩形, 色号)`：Blt COLORFILL（flags 0x1000400 =
        DDBLT_WAIT|DDBLT_COLORFILL，DDBLTFX.dwSize=0x64）；色号经
        `byte[0x4987F4 + 色号]`（重映射表 A）——仅当 `byte[mgr+0x86]` 非零，
        否则原色号（`byte[mgr+0x84]` 为 0 时还会查 `[mgr+0x888+色*4]` 的 DD 调色板
        颜色值；索引面复刻按色号填充，本调用点色号恒 0 ⇒ remap_A[0]=0 无差异）。"""
        lay = self.layers.tab.get(layer)
        if lay is None:
            return
        idx = color & 0xFF
        if self.p4_stat.get("0x4AA7B0+0x86", 0):
            idx = P4_REMAP_A[idx] & 0xFF
        l, t, r, b = dst_rect
        sh, sw = lay.buf.shape
        l = max(0, min(int(l), sw - 1)); r = max(0, min(int(r), sw - 1))
        t = max(0, min(int(t), sh - 1)); b = max(0, min(int(b), sh - 1))
        if r < l or b < t:
            return
        lay.buf[t:b + 1, l:r + 1] = idx

    def p4_423690(self, code: int, x: int, y: int) -> None:
        """`0x423690(this, code, x, y)`：层 13 字形表取 24×24 格，0x44D060 色键盖到层 0。
        ```
        0x4236A3 code==0xE → 45A750(0, 0x180, 0x17, 0x197)      （大行第 0 格）
        0x4236C2 code≥0xA  → ((code−9)*24, 0x180, +0x17, 0x197) （大行）
        0x4236EB code<0xA  → (code*24, 0x150, +0x17, 0x167)     （小行）
        0x423705 45A750 → 0x42373D 0x44D060(mgr, 0xD, &{x,y}, 0, &rect)
        ```"""
        if code == 0xE:
            rect = (0, 0x180, 0x17, 0x197)
        elif code >= 0xA:
            l = (code - 9) * 24
            rect = (l, 0x180, l + 0x17, 0x197)
        else:
            l = code * 24
            rect = (l, 0x150, l + 0x17, 0x167)
        self.p4_44d060(0xD, (x, y), 0, rect)

    def p4_423780(self, val: int, row: int) -> None:
        """`0x423780(this, val, row)`：定距三连画（个/十/百位，x = 0xF0/0xC0/0x90、
        间距 0x30），行 = arg2。0x462D71 = 普通截断除法（eax=商、edx=余数；
        负数修正在 C idiv 下为死分支）。
        ```
        0x42378F div(val,10)  → 0x4237A8 0x423690(val%10,    0xF0, arg2)
        0x4237B0 div(val/10,10) → 0x4237D3 0x423690((val/10)%10, 0xC0, arg2)
        0x4237DB div(val/10,10) → 0x4237F0 0x423690(val/100, 0x90, arg2)
        ```"""
        q, r = divmod(int(val) & 0xFFFFFFFF if int(val) < 0x80000000
                      else int(val) - 0x100000000, 10)
        self.p4_423690(r, 0xF0, row)               # 0x4237A8（edx = val%10）
        q2, r2 = divmod(q, 10)
        self.p4_423690(r2, 0xC0, row)              # 0x4237D3（edx = (val/10)%10）
        self.p4_423690(q2, 0x90, row)              # 0x4237F0（eax = val/100）

    def p4_423820(self, val: int, row: int) -> None:
        """`0x423820(this, val, row)`：先擦结果条，再把 val 按"十位组"分解画字形。
        ```
        0x42385C 0x44D290(13, &{0x48,row,0x11F,row+0x17}, 0)     擦 (72,row)-(287,row+23)
        0x423869 0x423690(0xE, 0x108, row)                        前缀字形
        0x423874 val==0 → 0x423690(0, 0xF0, row) 并返回
        循环（esi 从 0xF0 每字左移 0x18；counter[帧-0x1C] 从 1 每轮 +1）：
          units = val%10（0x42389A div）
          units != 0：
            counter > 3 → 0x423690(0xD, esi, row)、counter -= 4、esi -= 0x18   （0x4238C5/CE）
            counter != 0 → 0x423690(counter+9, esi, row)、esi -= 0x18          （0x4238DD/E2）
                          units != 1 → 0x423690(units, esi, row)               （0x4238EE）
            counter == 0 → 0x423690(units, esi, row)                           （0x4238EC）
          val /= 10、counter += 1，val != 0 则续（0x423907..0x423919）
        ```
        （counter+9 ≥ 0xA ⇒ 走层 13 大行字形；各组前缀/0xD/0xE 的具体图案由资源 6 决定。）"""
        self.p4_44d290(13, (0x48, row, 0x11F, row + 0x17), 0)      # 0x42385C 擦条
        self.p4_423690(0xE, 0x108, row)                            # 0x423869
        v = int(val) & 0xFFFFFFFF
        if v >= 0x80000000:
            v -= 0x100000000
        if v == 0:                                                 # 0x423874
            self.p4_423690(0, 0xF0, row)
            return
        counter = 1                                                # 0x42383C
        x = 0xF0
        while True:                                                # 0x423896
            q, units = divmod(v, 10)
            if units != 0:                                         # 0x4238AD
                if counter > 3:                                    # 0x4238B6
                    self.p4_423690(0xD, x, row)                    # 0x4238C5
                    counter -= 4                                   # 0x4238C1
                    x -= 0x18                                      # 0x4238CE
                if counter != 0:                                   # 0x4238D5
                    self.p4_423690(counter + 9, x, row)            # 0x4238DD
                    x -= 0x18                                      # 0x4238E2
                    if units != 1:                                 # 0x4238E8
                        self.p4_423690(units, x, row)              # 0x4238EF
                        x -= 0x18                                  # 0x4238F4（je 只跳过绘制）
                else:
                    self.p4_423690(units, x, row)                  # 0x4238EC（je 落点）
                    x -= 0x18                                      # 0x4238F4（fall-through）
            v = q                                                  # 0x423911
            counter += 1                                           # 0x423915
            if v == 0:                                             # 0x423919
                break

    def p4_448f50(self) -> None:
        """`0x448F50(0x4AD40C)`：0x449110（演员队列实体自尽）+ 0x430800（释放节点）。"""
        for e in list(self._p4_q("ui40c")):
            if hasattr(e, "m"):
                e.m[0x34] = 0
        self._p4_q("ui40c").clear()

    def p4_4301f0(self) -> None:
        """`0x4301F0(0x4AD46C)`：0x4303C0 + 0x430800 —— 清 46C 特效队列。"""
        for e in list(self._p4_q("ui46c")):
            if hasattr(e, "m"):
                e.m[0x34] = 0
        self._p4_q("ui46c").clear()

    def p4_44e470(self, x: int, y: int) -> None:
        """`0x44E470(mgr, x, y)`：`[mgr+0x14]/[+0x18] = x/y`（指针位置直写）。"""
        self.inp.x = x & 0xFFFFFFFF
        self.inp.y = y & 0xFFFFFFFF

    def p4_44fcc0(self, tempo: int) -> None:
        """`0x44FCC0(0x4AB514, tempo)`：DMusic 当前段的演奏速度（max(tempo,1)）。
        复刻音频层没有逐段 tempo 通道，先记日志。"""
        if os.environ.get("P4_DIAG"):
            print(f"[0x44FCC0] tempo={max(int(tempo), 1)}")

    def p4_45fa30(self) -> bool:
        """`0x45FA30(0x4CD4A0)`：演出状态机判定（thunk 0x401A6E 的目标）。"""
        return True


    def _p4_tick_4cc(self) -> None:
        """`0x43A350`：遍历 `list+0x28` 链表，`byte[+0x34]` 为 0 的摘链，
        否则 `0x437920`（= `jmp [ent+0x40]`）派发行为；返回 0 ⇒ 清 `[+0x34]` 与 `node[+0x1C]`。"""
        keep = []
        for e in self._p4_q("ui4cc"):
            if not e.alive:                      # 0x43A361
                continue
            if hasattr(e, "tick"):
                # Ent42 等：自带 tick()
                if e.tick():                     # 0x43A368 0x437920
                    keep.append(e)
                else:
                    e.alive = 0                  # 0x43A374
                    if e.node is not None:
                        e.node.active = 0        # 0x43A377
            else:
                # 0x41 族拖尾等：beh 派发（0x430550 等，走 p4_call_behaviour）
                if self.p4_call_behaviour(e):
                    keep.append(e)
                else:
                    e.alive = 0
                    if e.node is not None:
                        e.node.active = 0
        self._p4_q("ui4cc")[:] = keep

    # ---- 行为里用到的小工具（都对应一个确切地址）---------------------------
    def p4_430640(self, e) -> bool:
        """`0x430640(ecx=ent)`：节点矩形是否与 (0,0)-(0x27F,0x1DF) 相交（坐标有符号）。"""
        n = e.node
        if n is None:
            return False
        l, t, r, b = n.rect
        x, y = n.dst
        if x >= 0x80000000:                      # 无符号存放的负坐标 → int32 归一
            x -= 0x100000000
        if y >= 0x80000000:
            y -= 0x100000000
        if x > 0x27F:                            # 0x430647
            return False
        if (r - l) + x <= 0:                     # 0x430656 0x45A710 宽
            return False
        if y > 0x1DF:                            # 0x430667
            return False
        return (b - t) + y > 0                   # 0x430674 0x45A730 高

    def p4_45f530(self, obj, ax: int) -> None:
        """`0x45F530`（`ret 4`）：连击/计分计数器。

        ```
        0x45F530 ax = 实参低 16 位
        0x45F535 if (ax == 0) { byte[obj+0x2A] = 0; return }     ; 0x45F54E
        0x45F53A word[obj+0x26]++                                 ; 累计命中数
        0x45F53E dl = byte[obj+0x2A]
        0x45F541 test al, 7 ; sete al                             ; 低 3 位为 0 ⇒ 1
        0x45F546 dl |= al ; byte[obj+0x2A] = dl                   ; 0x45F548
        ```

        `obj` 是计分对象（`0x4CD4A0` 一族的演出/HUD 对象），字段 `+0x26` 是 16 位计数、
        `+0x2A` 是"每 8 次置一次"的标记位。"""
        if not (ax & 0xFFFF):                   # 0x45F538
            obj.f2a = 0                          # 0x45F54E
            return
        obj.f26 = (getattr(obj, "f26", 0) + 1) & 0xFFFF   # 0x45F53A
        obj.f2a = (getattr(obj, "f2a", 0) | (1 if not (ax & 7) else 0)) & 0xFF  # 0x45F546/0x45F548

    def p4_rand(self) -> int:
        """`0x45AD00`：LCG，状态 `[0x5D3E38]`；`st = (st*0x19660D + 0x3C6EF35F) & 0x7FFFFFFF`。"""
        st = (int(getattr(self, "_p4_rand_st", 0x12345678)) * 0x19660D + 0x3C6EF35F) & 0x7FFFFFFF
        self._p4_rand_st = st
        return st

    def p4_rand_mod(self, m: int) -> tuple[int, int]:
        """`0x462D71(v, m)`：返回 (商, 余数)。调用点用余数（`0x437C95` 的 edx）。"""
        v = self.p4_rand()
        return v // m, v % m

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
        # 0x448F87：0x448F80（actorq tick）帧首清 [0x56CC94] —— type5 释放沿在本帧
        # 置位、同帧靠后的 0x4AD4CC tick（狙击圈/驱动器）消费，下一帧归零。
        self.p4_stat[0x56CC94] = 0
        self.tick_ui(self.actorq)                 # 0x4AD40C → 0x448F80
        self.tick_ui(self.ui46c)                  # 0x4AD46C → 0x430220
        self.actorq = [x for x in self.actorq if getattr(x, "alive", True)]
        self.ui46c = [x for x in self.ui46c if getattr(x, "alive", True)]
        self._p4_tick_ents()                      # 0x4AD43C → 0x43BC70
        self.tick_ui(self.p4_ui49c)               # 0x4AD49C → 0x4353A0
        # 0x4353A0 的链表遍历在行为返回 0 时把节点摘链；复刻侧 tick_ui 只置 alive=False，
        # 必须在这里过滤，否则 0x31 弹/死节点永久占住列表（0x61000002 门、0x430860 计数）。
        self.p4_ui49c = [x for x in self.p4_ui49c if getattr(x, "alive", True)]
        self._tick_wipe4f()                       # 0x4AD4CC → 0x43A350（同队列的另一半工作）
        self._tick_spark4cc()                     # 0x4AD4CC → 0x43A350（同上，不是独立队列）
        self._p4_tick_4cc()                       # 0x4AD4CC → 0x43A350 的行为派发（0x42 家族）
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
            self._p4_set_col(a)
            for b in list(qb):
                self._p4_set_col(b)
                if self.p4_hit_test(b, a.s32(0x04), a.s32(0x08), a.s32(0x0C)):   # 0x43C011
                    # 0x43C01E → 0x43C170：回调 esi = **内层 qa**（walker 的 edi 最后 push）
                    self.p4_hit_cb(a, b)
                    hits += 1
        return hits

    # ---- 0x41 族：全部 15 型（ctor 0x428C70，第一跳表 0x42997C + 大支 0x4294A1/0x4299B8）----
    # 表: (层, rect l,t,r,b, dst减, [0x1C], [0x20], [0x24], 行为 thunk)
    # 层 0 = bm_cm48 / 层 1 = bm_cm32
    P4_41_CTOR = {
        0x41000001: (0, 0xC0, 0,    0xEF, 0x2F, 0x18, 3, 5, 0, 0x401B95),  # 爆炸核心 48×48 撃
        0x41000004: (1, 0xA0, 0,    0xBF, 0x1F, 0,    0, 0, 0, 0x40200E),  # 碰撞火花 32×32
        0x41000005: (0, 0xC0, 0x90, 0xEF, 0xBF, 0x18, 0, 0, 0, 0x401019),  # 激光纵条
        0x41000006: (0, 0xC0, 0x60, 0xEF, 0x8F, 0x18, 0, 0, 0, 0x402275),  # 激光横条
        0x41000008: (0, 0xA0, 0x40, 0xBF, 0x5F, 0x10, 5, 0, 0, 0x401B95),  # 捕獲波纹
        0x4100000B: (0, 0xA0, 0x40, 0xBF, 0x5F, 0x10, 1, 5, 0, 0x401B95),  # 粒子1
        0x4100000C: (1, 0x174, 0x173, 0x17 + (0x18*0x30), 0x173 + (0x18*0x30), 0xC, 0, 0, 0, 0x401447),  # 数字板
        0x4100000D: (0, 0, 0, 0, 0, 0, 0, 0, 0, 0x401172),                 # 放大窗（dst/rect 动态）
        0x4100000E: (0, 0, 0, 0, 0, 0, 0, 0, 0, 0x401172),                 # 放大窗（同上）
        0x4100000F: (0, 0xD0, 0xD0, 0xDF, 0xDF, 8, 2, 3, 0, 0x401B95),     # 粒子2
        0x41000015: (1, 0x100, 0xD0, 0x10F, 0xDF, 8, 1, 4, 0, 0x401B95),   # trail 撃
        0x41000016: (1, 0x100, 0xE0, 0x10F, 0xEF, 8, 1, 4, 0, 0x401B95),   # trail homing
        0x41000017: (0, 0x78, 0x1F8, 0x8F, 0x20F, 0xC, 2, 5, 1, 0x401B95),  # trail arc1
        0x41000018: (1, 0x100, 0xF0, 0x10F, 0xFF, 8, 4, 4, 1, 0x401B95),   # trail arc2
        0x41000019: (1, 0x100, 0xE0, 0x10F, 0xEF, 8, 1, 6, 0, 0x401B95),   # trail slot 追加
    }

    def p4_spawn41(self, x: int, y: int, typ: int, rec: tuple = ()) -> None:
        """0x41 族全型 spawn：0x430400(rec,x,y,typ) → 0x43A3C0(0x4AD4CC) →
        ctor 0x428C70（第一跳表 0x42997C 15 项 + 大支 0x4294A1 第二跳表 0x4299B8 9 项）。
        共通字段：[+0x40]=行为 thunk、[+0x18]=1、[+0x1C/0x20/0x24]=型别参数、
        节点层/rect 由各型决定。行为 0x430550 = 通用粒子（相位→寿命→矩形右滑→闪烁）。
        0x4100000D/0E（放大窗）的 rect/dst 由 rec[3]（缩放码）动态计算——复刻侧
        先用最小 rect 占位，效果帧由行为积分。"""
        spec = self.P4_41_CTOR.get(typ)
        if spec is None:
            return
        layer, l, t, r, b, dv, c1c, c120, c124, thunk = spec
        e = Ent(int(x), int(y), int(typ), 0)
        e.d32(0x14, typ & 0xFFFFFFFF)
        e.d32(0x40, thunk)
        e.beh = thunk
        real = P4_41_BEH_THUNK.get(thunk)
        if real is not None:
            # 无条件解到真址：0x430550 等是 Pages 类方法（p4_call_behaviour 的
            # getattr(type(self), "_beh_%X") 回退按名命中），不要求在 P4_BEH。
            # 旧 `real in P4_BEH` 守卫失败时 e.beh 留在 thunk ⇒ 分派两找不到
            # ⇒ 按未实现永久存活 ⇒ 波纹/拖尾冻结在轨迹上不消失（2026-11-14 修）。
            e.beh = real
        e.d32(0x1C, c1c)
        e.d32(0x20, c120)
        e.d32(0x24, c124)
        e.d32(0x28, 0)
        e.d32(0x2C, 0)
        e.d32(0x18, 1)
        e.m[0x10] = 1                                  # 0x41000004 参与碰撞（0x43C460 效果分配）
        e.node = DNode(layer, l, t)
        e.node.rect = (l, t, r, b)
        e.node.dst = (int(x) - dv, int(y) - dv)
        e.node.active = 1
        self._p4_q("ui4cc").append(e)
        return e

    def p4_spawn_61000004(self, x: int, y: int, rec3: int):
        """0x61000004 大敌击破波纹（ctor 0x4272DD / 行为 0x40193D→0x427580）入 0x4AD52C。

        命中结算（0x43CA3B / 0x43D2F5 / 0x43C25A）对半径 0x30 且非六例外的靶生成：
        `0x430400(rec,[a+4],[a+8],0x61000004,0x30) → 0x445AA0(0x4AD52C,&rec)`。
        ctor 0x4272DD：`[+0x1C]=0`（t 计数）、`[+0x20]=abs(rec3)`（持续帧）、
        `[+0x24]=(rec3>0)`（音效门）；基础 ctor 0x430450 已放 [+4]=x、[+8]=y。
        无显示节点（纯生成器，视觉全靠 0x4AD4CC 的火花/核心）。
        旧复刻把它落进 geki.spawn 的 0x61 兜底 `beh="fade_in"` ⇒ 每帧
        fade_to(-256→0) 把整屏压黑再渐亮（2026-11-14 用户实测黑屏根因）。"""
        e = Ent(int(x), int(y), 0x61000004, 0)
        e.d32(0x14, 0x61000004)
        e.d32(0x40, 0x40193D)                          # 0x4272E1 行为槽（thunk → 0x427580）
        e.beh = 0x427580
        e.d32(0x1C, 0)                                 # 0x4272E8 t=0
        e.d32(0x20, abs(int(rec3)) & 0xFFFFFFFF)       # 0x4272EF..0x4272F7 cdq/xor/sub = abs
        e.d32(0x24, 1 if int(rec3) > 0 else 0)         # 0x4272FA..0x427305 setg
        self._p4_q("ui52c").append(e)                  # 0x445AA0 → 0x4AD52C
        return e

    def _beh_427580(self, e) -> bool:
        """`0x427580`（0x61000004 击破波纹驱动，thunk 0x40193D）。

        ```
        0x427583 t=++[+0x1C]
        0x427598 0x401C08→0x43A520(0x4AD4CC, x=[+4], y=[+8], t, dur=[+0x20], flag=[+0x24])
        0x4275B3 if (t != dur) return 1
        0x4275C3 0x4015BE→0x43A700(0x4AD4CC, x, y, dur, flag==1)；return 0（自灭）
        ```
        0x43A520 每帧（0x430400 记录 = {x,y,type,rec3}，rand 均为 `rand%2dur-dur`）：
          t&1==1 → 路径 A：4 次 rand，0x41000004 火花 @(x+o1,y+o2)、
                   rec3=(vx,vy)=((o1+o3+2)>>2,(o2+o4+2)>>2)（0x428D59 ctor 解引用
                   [rec+0xC] 当 (vx,vy) 指针——移植侧 spark_spawn 直收速度对）
          t&7==4 → 路径 B：2 次 rand，0x41000001 核心 @(x+o6,y+o5)、rec3=0
          t&0xF==8 且 flag → SE4 声像 (x-0x140)<<4（0x43A677..0x43A688）
        0x43A700 终结：dur>>3 次（每次 2 rand）0x41000001 @(x+o2,y+o1)、rec3=0；
        flag → SE11 声像（0x43A7A0..0x43A7B5）。0x41000001 ctor 0x428CA5 内部
        rand%3 选爆炸行 ⇒ 移植侧 spawn 后补 p4_rand_mod(3) 改 rect（同 0x43CA94）。"""
        x = e.s32(0x04)
        y = e.s32(0x08)
        dur = e.s32(0x20)
        flag = e.g32(0x24)
        t = (e.s32(0x1C) + 1) & 0xFFFFFFFF             # 0x427589 inc（先于两段生成）
        e.d32(0x1C, t)
        m2 = 2 * dur
        if t & 1:                                      # 0x43A52F test al,1（路径 A）
            o1 = self.p4_rand_mod(m2)[1] - dur
            o2 = self.p4_rand_mod(m2)[1] - dur
            o3 = self.p4_rand_mod(m2)[1] - dur
            o4 = self.p4_rand_mod(m2)[1] - dur
            self.spark_spawn(x + o1, y + o2,
                             (o1 + o3 + 2) >> 2, (o2 + o4 + 2) >> 2)   # 0x43A5AE
        if (t & 7) == 4:                               # 0x43A5F6 and 7 / cmp 4（路径 B）
            o5 = self.p4_rand_mod(m2)[1] - dur
            o6 = self.p4_rand_mod(m2)[1] - dur
            g = self.p4_spawn41(x + o6, y + o5, 0x41000001)           # 0x43A62F
            if g is not None:
                _, r3 = self.p4_rand_mod(3)                           # ctor 0x428CCF
                g.node.rect = (0xC0 + 48 * r3, 0, 0xEF + 48 * r3, 0x2F)
        if (t & 0xF) == 8 and flag:                    # 0x43A668 and 0xF / cmp 8
            self.p4_se_pan(4, (x - 0x140) << 4)        # 0x43A685 SE#4 声像
        if t == dur:                                   # 0x4275B3（终结帧）
            n = dur >> 3                               # 0x43A70E sar 3
            for _ in range(n):                         # 0x43A723..0x43A792 循环
                o1 = self.p4_rand_mod(m2)[1] - dur
                o2 = self.p4_rand_mod(m2)[1] - dur
                g = self.p4_spawn41(x + o2, y + o1, 0x41000001)       # 0x43A758
                if g is not None:
                    _, r3 = self.p4_rand_mod(3)                       # ctor 0x428CCF
                    g.node.rect = (0xC0 + 48 * r3, 0, 0xEF + 48 * r3, 0x2F)
            if flag:
                self.p4_se_pan(11, (x - 0x140) << 4)   # 0x43A7AE SE#11 声像
            return False                               # 0x4275D4 自灭
        return True                                    # 0x4275D8

    def _beh_430550(self, e) -> bool:
        """`0x401B95` → `0x430550`：拖尾共享行为（0x41000015/16/17/18 共用）。

        ```
        0x430553 if ([0x2C] != [0x1C]) [0x2C]++ → 尾
        else: [0x2C]=1 ; if (--[0x20] == 0) return 0   ; 寿命尽
              0x45A790(节点+4, 宽, 0, 宽, 0)            ; 源矩形右滑一格（宽=r-l+1）
        0x430595 if ([0x24] != 0) { c=[0x28]++; if ((c&1)==0) byte[节点+0x1C]=0 }
                 else byte[节点+0x1C]=1
        ```"""
        if e.s32(0x2C) != e.s32(0x1C):
            e.d32(0x2C, (e.s32(0x2C) + 1) & 0xFFFFFFFF)
        else:
            e.d32(0x2C, 1)
            life = (e.s32(0x20) - 1) & 0xFFFFFFFF
            e.d32(0x20, life)
            if life == 0:
                return False
            if e.node is not None:
                l, tt, r, b = e.node.rect
                w = r - l + 1
                e.node.rect = (l + w, tt, r + w, b)    # 0x45A790(宽,0,宽,0)
        if e.s32(0x24):
            c = (e.s32(0x28) + 1) & 0xFFFFFFFF
            e.d32(0x28, c)
            if e.node is not None:
                e.node.active = 0 if (c & 1) == 0 else 1
            return True
        if e.node is not None:
            e.node.active = 1
        return True

    # ---- 狙击锁定/攻击链（2026-11-14 反汇编 0x429E60/0x429DE0/0x429F20/0x43D250/0x437840）----
    def _beh_429E60(self, e) -> bool:
        """`0x429E60`（0x41000006 锁定圈，ctor 0x428EC6）：t++ 至 0x10 节点显现；
        每帧吸附锁定敌机 (x,y)；`[0x56CC94]`（type5 释放沿、0x448F87 帧首清的
        同帧事件标志）→ 清敌机 `[+0x4C]` 首锁标记并自灭；敌机/自机亡 → 自灭。
        ctor 的 `[+0x1C]=[rec[3]]`、`[+0x24]=[rec[3]+4]` 在 exe 里解引用自机首槽，
        行为体按实体指针使用（[edi+0x4C] 只能是敌机首锁标记）⇒ 复刻绑定为
        敌机（sub）+ 自机（own2）双存活门。"""
        sub = e.p.get("sub")
        own2 = e.p.get("own2")
        t = (e.s32(0x20) + 1) & 0xFFFFFFFF
        e.d32(0x20, t)
        if t == 0x10 and e.node is not None:
            e.node.active = 1                       # 0x429E79..0x429E7C
        if sub is not None:
            e.d32(0x04, sub.g32(0x04))              # 0x429E80 吸附敌机
            e.d32(0x08, sub.g32(0x08))
        if self.p4_stat.get(0x56CC94, 0):           # 0x429E8C 释放事件
            if sub is not None:
                sub.d32(0x4C, 0)                    # 0x429E96 清首锁标记
            return False
        if e.node is not None:
            e.node.dst = (e.s32(0x04) - 0x18, e.s32(0x08) - 0x18)   # 0x429EA0..0x429EBB
        if sub is None or own2 is None:             # 0x429EB6 / 0x429EC0
            return False
        if not sub.alive or not getattr(own2, "alive", True):
            return False                            # 0x429EC4 / 0x429ECB
        return True

    def _beh_429DE0(self, e) -> bool:
        """`0x429DE0`（0x41000005 锁定碎片，ctor 0x428DFB）：位置 = 敌机 + 速度；
        速度按 [+0x28]/[+0x2C] 累加（衰减至 0）；[+0x20]==0 → 自灭；敌机亡 → 自灭。
        ctor：[+0x20]=-rec0*16、[+0x24]=-rec1*16、[+0x28]=rec0、[+0x2C]=rec1、
        [+0x1C]=敌机；捕获侧 rec0=4、rec1=±4 交替。"""
        sub = e.p.get("sub")
        if sub is None:
            return False
        e.d32(0x04, (sub.g32(0x04) + e.s32(0x20)) & 0xFFFFFFFF)   # 0x429DE9
        e.d32(0x08, (sub.g32(0x08) + e.s32(0x24)) & 0xFFFFFFFF)   # 0x429DF4
        nvx = (e.s32(0x28) + e.s32(0x20)) & 0xFFFFFFFF            # 0x429DFC
        e.d32(0x20, nvx)
        e.d32(0x24, (e.s32(0x2C) + e.s32(0x24)) & 0xFFFFFFFF)     # 0x429E01
        if nvx == 0:                                # 0x429E09 test eax
            return False
        if e.node is not None:
            e.node.dst = (e.s32(0x04) - 0x18, e.s32(0x08) - 0x18)   # 0x429E14..0x429E30
        return sub.alive                            # 0x429E37

    def _p4_41400507_dtor(self, e) -> None:
        """`0x437840`（vtable 0x498744 slot0 → 0x437810 → dtor，实体删除时）：
        `[0x56CC98]--`；`[+0x28]>0 → [0x56CC9C]--`、`<0 → [0x56CCA0]--`；
        `[0x56CC98]==[0x56CCA0]` → `[0x56CCA4]=0` + `0x45F530(0x4CD4A0,0)` 清连击标记。"""
        self.p4_stat[0x56CC98] = (self.p4_stat.get(0x56CC98, 0) - 1) & 0xFFFFFFFF   # 0x43787B
        t28 = e.s32(0x28)
        if t28 > 0:                                 # 0x437886
            self.p4_stat[0x56CC9C] = (self.p4_stat.get(0x56CC9C, 0) - 1) & 0xFFFFFFFF
        elif t28 < 0:                               # 0x43789A
            self.p4_stat[0x56CCA0] = (self.p4_stat.get(0x56CCA0, 0) - 1) & 0xFFFFFFFF
        if self.p4_stat.get(0x56CC98, 0) == self.p4_stat.get(0x56CCA0, 0):   # 0x4378AE
            self.p4_stat[0x56CCA4] = 0              # 0x4378B8
            self.p4_stat[0x4CD4A0 + 0x2A] = 0       # 0x4378BD 0x40164F→0x45F530(…,0)

    def _p4_43d250(self, drv, sub) -> None:
        """`0x43D250`（`0x401CDA`，狙击命中结算；arg1=驱动器、arg2=敌机）：
        `[敌+0x48]--`（消耗一层锁）→ `[0x56CCA4]++` + `0x45F530` 连击 →
        驱动器 `[+0x18]--`（==0 则 byte[+0x10]=0）→ k=(驱动器 type 字节2)=5 →
        `ja`（无符号）敌机 HP>k：HP-=k + SE9（0x10FF0053 兂）；否则击破演出
        （半径 0x30 且非六例外 → 0x61000004 入 0x4AD52C，否则 0x41000001 入
        0x4AD4CC）+ `[敌+0x18]=0`/byte[+0x10]=0 + `0x45EFF0` 计分 + SE8。"""
        sub.d32(0x48, (sub.g32(0x48) - 1) & 0xFFFFFFFF)         # 0x43D27D
        n = (self.p4_stat.get(0x56CCA4, 0) + 1) & 0xFFFFFFFF
        self.p4_stat[0x56CCA4] = n                               # 0x43D288
        st = self.p4_stat
        st[0x4CD4A0 + 0x26] = (st.get(0x4CD4A0 + 0x26, 0) + 1) & 0xFFFF     # 0x45F53A
        st[0x4CD4A0 + 0x2A] = st.get(0x4CD4A0 + 0x2A, 0) | (0 if (n & 7) else 1)  # 0x45F546
        d18 = drv.g32(0x18)
        if d18:                                                  # 0x43D295
            drv.d32(0x18, (d18 - 1) & 0xFFFFFFFF)                # 0x43D29A
        else:
            drv.m[0x10] = 0                                      # 0x43D29F
        k = (drv.g32(0x14) >> 16) & 0xFF                         # 0x43D267（=5）
        hp = sub.g32(0x18)
        if hp > k:                                               # 0x43D2A8 ja
            sub.d32(0x18, (hp - k) & 0xFFFFFFFF)                 # 0x43D39B
            if drv.g32(0x14) != 0x10FF0053:                      # 0x43D3A3
                self.p4_se_pan(9, (sub.s32(0x04) - 0x140) << 4)  # 0x43D3BD
            return
        ta = sub.g32(0x14)
        if sub.g32(0x0C) == 0x30 and ta not in (0x24000011, 0x2300000E, 0x27000011,
                                                0x29000013, 0x2C00000B, 0x2C00000A):
            self.p4_spawn_61000004(sub.s32(0x04), sub.s32(0x08), 0x30)   # 0x43D2F5
        else:
            g = self.p4_spawn41(sub.s32(0x04), sub.s32(0x08), 0x41000001)   # 0x43D32F
            if g is not None:
                _, r3 = self.p4_rand_mod(3)                      # 0x428CD3 爆炸行随机
                g.node.rect = (0xC0 + 48 * r3, 0, 0xEF + 48 * r3, 0x2F)
        sub.d32(0x18, 0)                                         # 0x43D359
        sub.m[0x10] = 0                                          # 0x43D360
        self.p4_45eff0(ta, sub.s32(0x04), sub.s32(0x08), drv.g32(0x14))     # 0x43D373
        self.p4_se_pan(8, (sub.s32(0x04) - 0x140) << 4)          # 0x43D38C

    def _p4_41000008(self, x: int, y: int, a3: int) -> None:
        """`0x428F72`（0x41000008 捕獲波纹 ctor）：层 1（bm_cm32）、
        rect = `(32*a3, 128+32*选机, 32*a3+0x1F, 0x9F+32*选机)`（选机行 + 拍数列）、
        `[+0x1C]=5`（相位长）、`[+0x20]=5-a3`（寿命）、
        `[+0x24]=0x45AFC0(0x800)`（闪烁字段，0x430550 的 blink 位）。"""
        g = self.p4_spawn41(x, y, 0x41000008)
        if g is None:
            return
        g.d32(0x20, 5 - a3)                      # 0x428F94
        g.d32(0x24, self.p4_afc0(0x800) & 0xFFFFFFFF)     # 0x428FA8
        if g.node is not None:
            g.node.layer = 1                     # 0x428FB8
            s = self.p4_afc0(0xC000) & 3
            g.node.rect = (32 * a3, 128 + 32 * s, 32 * a3 + 0x1F, 0x9F + 32 * s)

    def _beh_429F20(self, e) -> bool:
        """`0x429F20`（0x41400507 狙击攻击驱动器；ctor 0x429889）：
        `[+0x28]=-1` 待机，`[0x56CC94]` 触发 → `[0x56CCA0]--` 进入攻击；
        拍 0：敌机 `[+0x50]` 门（许可帧+16）→ `[0x56CC9C]++`、(选机≠3) 位置跳自机、
        SE7；拍 ≥1：x/y += 初速>>1（sar）、生成 0x41000008 @(x,y)、初速按
        `x<敌x ? +(≥0?1:3) : -(≥0?4:2)` 收敛、菱形命中（r=0x10）→ `0x43D250` 结算
        + 6 沿攻击向火花 + 4 随机火花 + 自灭；无目标 → `[+0x2C]++` 至 4 自灭
        （期间每拍 0x41000008）。"""
        sub = e.p.get("sub")
        owner = e.p.get("owner")
        if sub is None:                                  # 0x429F45 → 0x42A209
            n = (e.s32(0x2C) + 1) & 0xFFFFFFFF
            e.d32(0x2C, n)
            if n == 4:                                   # 0x42A212
                self._p4_41400507_dtor(e)
                return False
            self._p4_41000008(e.s32(0x04), e.s32(0x08), n)   # 0x42A22C（寿命 5-n）
            return True
        alive = True
        if not sub.alive or owner is None or not getattr(owner, "alive", True):
            sub.d32(0x4C, 0)                             # 0x429F63 解除锁定
            sub.d32(0x48, 0)
            alive = False
            e.p["sub"] = None
        t28 = e.s32(0x28)
        if t28 < 0:                                      # 0x429F75 待机
            if self.p4_stat.get(0x56CC94, 0):            # 0x429F79 释放事件
                self.p4_stat[0x56CCA0] = (self.p4_stat.get(0x56CCA0, 0) - 1) & 0xFFFFFFFF
                e.d32(0x28, (t28 + 1) & 0xFFFFFFFF)      # 0x429F93
            if not alive:
                self._p4_41400507_dtor(e)                # 0x43A4B9 摘链即调 vtable dtor
                return False
            return True
        if t28 == 0:                                     # 拍 0（0x429FAD）
            fr = self.p4_frame_no()
            if fr > sub.g32(0x50):                       # 0x429FB9 jae：[+0x50]>=frame → 本拍跳过
                sub.d32(0x50, (fr + 0x10) & 0xFFFFFFFF)  # 0x429FC3
                self.p4_stat[0x56CC9C] = (self.p4_stat.get(0x56CC9C, 0) + 1) & 0xFFFFFFFF
                if self.p4_afc0(0xC000) != 3:            # 0x429FDD
                    e.d32(0x04, self.p4_stat.get(0x56CC8C, 0))   # 0x429FE7 位置跳自机
                    e.d32(0x08, self.p4_stat.get(0x56CC90, 0))
                self.p4_se_pan(7, (self.p4_stat.get(0x56CC8C, 0) - 0x140) << 4)   # 0x42A008
                e.d32(0x28, 1)                           # 0x42A00F
            if not alive:
                self._p4_41400507_dtor(e)                # 同上
                return False
            return True
        # 拍 ≥1（0x42A029）：逼近
        x = e.s32(0x04) + (e.s32(0x20) >> 1)             # 0x42A033 sar
        y = e.s32(0x08) + (e.s32(0x24) >> 1)
        e.d32(0x04, x & 0xFFFFFFFF)
        e.d32(0x08, y & 0xFFFFFFFF)
        self._p4_41000008(x, y, 0)                       # 0x42A037..0x42A082（寿命 5）
        for comp, sv in ((0x04, 0x20), (0x08, 0x24)):    # 0x42A087..0x42A0EA 收敛
            ev = e.s32(sv)
            if e.s32(comp) < sub.s32(comp):
                e.d32(sv, (ev + (1 if ev >= 0 else 3)) & 0xFFFFFFFF)
            else:
                e.d32(sv, (ev - (4 if ev >= 0 else 2)) & 0xFFFFFFFF)
        if self.p4_hit_test(sub, x, y, 0x10):            # 0x42A0ED 0x401843→0x4306C0
            self._p4_43d250(e, sub)                      # 0x42A11D 0x401CDA→0x43D250
            vx, vy = e.s32(0x20) >> 2, e.s32(0x24) >> 2  # 0x42A12F/0x42A149
            for i in range(1, 7):                        # 0x42A17A 6 沿攻击向火花
                self.spark_spawn(x, y, vx * i, vy * i)
            for _ in range(4):                           # 0x42A1A9 4 随机火花
                self.spark_spawn(x, y,
                                 (self.p4_rand() & 0x1F) - 0xF,
                                 (self.p4_rand() & 0x1F) - 0xF)
            self._p4_41400507_dtor(e)                    # 0x43A4B9 摘链即调 dtor（[0x56CC98]--）
            return False                                 # 0x42A1F4 自灭
        return True                                      # 0x42A272 未命中

    def p4_41400507_spawn(self, beam, sub) -> None:
        """`0x429889`（0x41400507 ctor case）：`[+0xC]=0x10`、`[+0x18]=1`、
        `[+0x28]=-1` 待机、`[+0x2C]=0`、`[+0x20]=(rand%0x18)-0x40`、
        `[+0x24]=(rand%0x40)-0x20`、`[+0x1C]=敌机`（rec[3]）、
        `[+0x30]=[beam+0x24]=自机`（rec[1]）、节点层 1 隐藏；
        选机 3：位置 = 敌机节点 dst+0x30、初速 `(rand%0x60)-0x30`。"""
        e = Ent(0, 0, 0x41400507, 0)
        e.d32(0x14, 0x41400507)
        e.d32(0x40, 0x401979)                    # exe 存 thunk
        e.beh = 0x429F20
        e.d32(0x0C, 0x10)                        # 0x429899
        e.d32(0x18, 1)                           # 0x4298F3
        e.d32(0x28, 0xFFFFFFFF)                  # 0x4298D6 待机
        e.d32(0x2C, 0)                           # 0x4298E0
        _, r = self.p4_rand_mod(0x18)            # 0x4298AE
        e.d32(0x20, (r - 0x40) & 0xFFFFFFFF)     # 0x4298BC
        _, r = self.p4_rand_mod(0x40)            # 0x4298C8
        e.d32(0x24, (r - 0x20) & 0xFFFFFFFF)     # 0x4298DD
        e.node = DNode(1, 0, 0)                  # 0x4298EA 层 1
        e.node.active = 0                        # 0x42990B 隐藏
        e.p["sub"] = sub                         # [e+0x1C] = 敌机
        e.p["owner"] = beam.p.get("sub")         # [e+0x30] = [beam+0x24] = 自机
        if self.p4_afc0(0xC000) == 3:            # 0x429918
            nd = getattr(sub, "node", None)
            if nd is not None:
                e.d32(0x04, (nd.dst[0] + 0x30) & 0xFFFFFFFF)   # 0x42992B
                e.d32(0x08, (nd.dst[1] + 0x30) & 0xFFFFFFFF)   # 0x429937
            _, r = self.p4_rand_mod(0x60)        # 0x429942
            e.d32(0x20, (r - 0x30) & 0xFFFFFFFF)
            _, r = self.p4_rand_mod(0x60)        # 0x42995D
            e.d32(0x24, (r - 0x30) & 0xFFFFFFFF)
        self._p4_q("ui4cc").append(e)

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
            self.p4_460c00()                              # 0x43C38B 死亡演出/命数递减/重生机
            self.p4_45f570()                              # 0x43C395 量表重置
            b.d32(0x10, 0)                                # 0x43C39F
            b.d32(0x18, 0)
            return
        if t == 6:                                        # 0x43C1AF 命中特效
            jx = (rng.randrange(0x20) - 0xF)
            jy = (rng.randrange(0x20) - 0xF)
            self.spawn(self._p4_q("ui4cc"), 0x41000004,
                       a.s32(0x04) + jx, a.s32(0x08) + jy)   # 0x43C1DA..0x43C20A
            if a.s32(0x18) <= 1:                          # 0x43C212 cmp 1 / ja 0x43C30D
                # —— 最后一击（0x43C21B..0x43C302）：**不扣血**，直接置 0 并出爆/记分 ——
                if a.s32(0x0C) == 0x30 and a.s32(0x14) not in (
                        0x24000011, 0x2300000E, 0x27000011,
                        0x29000013, 0x2C00000B, 0x2C00000A):     # 0x43C220/0x43C228..
                    self.p4_spawn_61000004(a.s32(0x04), a.s32(0x08), 0x30)  # 0x43C25A
                else:
                    self.spawn(self._p4_q("ui4cc"), 0x41000001,
                               a.s32(0x04), a.s32(0x08))          # 0x43C28C..0x43C2C1
                self.p4_45eff0(a.s32(0x14), 0x100D1211,
                               a.s32(0x04), a.s32(0x08))          # 0x43C2E2
                a.d32(0x10, 0)                                    # 0x43C2DC byte[+0x10]=0
                a.d32(0x18, 0)                                    # 0x43C2DF [+0x18]=0
                self.p4_se_pan(4, (a.s32(0x04) - 0x140) << 4)     # 0x43C2FB
                return
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
        d = value - 1                                     # 0x460AA2..0x460AA7
        d = d % 10 if d >= 0 else -((-d) % 10)            # idiv 余数：符号随被除数（C 语义）
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
                   0x499514, 0x49955C, 0x4995C0, 0x49964C, 0x499678)

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

    def p4_45e020(self) -> None:
        """`0x45E020(h)`：分数数字三段式排版（逐行转写，docs/p4_stage_*.md §5 追记）。

        ```
        ebx = 1（已用节点数）；score = [+0x04]
        score == 0 → 节点[1].src = (0,0x150,0x17,0x167)（"0" 字形）、ebx = 2
        score > 0 → 逐位循环（0x462D71 除 10，低位在前）：
            数字 == 0 的位跳过不占节点（0x45E0BB → 0x45E239）
            位数 edi > 3 → 组标节点（0x45E0C1）：k = edi>>2、edi &= 3、游标 += k、
                src = ((3·游标+9)·8, 0x180, 3·游标·8+0x5F, 0x197)
            edi != 0 → 余数位节点（0x45E13A）：src = (edi*24, 0x180, +0x17, 0x197)
            数字 != 1 → 单位节点（0x45E19F/1E8）：src = (digit*24, 0x150, +0x17, 0x167)
        0x45E25D：前 ebx 个节点置显示，其余 20−ebx 个隐藏
        ```"""
        st = self.p4_stat
        nodes = st.get("hud_nodes")
        if not nodes:
            return
        score = st.get(0x4CD4A0 + 0x04, 0) & 0xFFFFFFFF
        used = 1                                        # 0x45E02B ebx = 1
        if score == 0:                                  # 0x45E038
            nodes[1].src = (0, 0x150, 0x17, 0x167)      # 0x45E05C "0" 字形
            used = 2                                    # 0x45E071
        else:
            v = score
            cnt = 1                                     # edi（已处理位数）
            ptr = 1                                     # esi 节点游标（第 2 槽起）
            cursor = 0                                  # 帧−0x90（0x45E03C 清 0）
            while True:
                if used >= 0x14:                        # 0x45E09F
                    break
                q, digit = divmod(v, 10)                # 0x45E0AB
                if digit == 0:                          # 0x45E0BB → 0x45E239
                    v, cnt = q, cnt + 1
                    if v == 0:                          # 0x45E24F jne
                        break
                    continue
                if cnt > 3:                             # 0x45E0C1 组标
                    k = cnt >> 2                        # 0x45E0CD
                    cnt -= 4 * k                        # 0x45E0D4
                    cursor += k                         # 0x45E0DB/DD
                    c3 = cursor * 3
                    nodes[ptr].src = ((c3 + 9) * 8, 0x180, c3 * 8 + 0x5F, 0x197)
                    ptr += 1
                    used += 1                           # 0x45E123..0x45E137
                if cnt:                                 # 0x45E13A 余数位
                    nodes[ptr].src = (cnt * 0x18, 0x180, cnt * 0x18 + 0x17, 0x197)
                    ptr += 1
                    used += 1                           # 0x45E166..0x45E196
                    if digit != 1:                      # 0x45E183 je → 单位跳过
                        nodes[ptr].src = (digit * 0x18, 0x150,
                                          digit * 0x18 + 0x17, 0x167)    # 0x45E19F
                        ptr += 1
                        used += 1                       # 0x45E232
                else:                                   # 0x45E1E8 edi == 0：只有单位
                    if digit != 1:
                        nodes[ptr].src = (digit * 0x18, 0x150,
                                          digit * 0x18 + 0x17, 0x167)
                        ptr += 1
                        used += 1
                v, cnt = q, cnt + 1                     # 0x45E239..0x45E24F
                if v == 0:                              # 0x45E253 jne
                    break
        for i, nd in enumerate(nodes):                  # 0x45E25D..0x45E292
            nd.active = 1 if i < used else 0

    def p4_45e340(self) -> None:
        """`0x45E340`：气槽排版（写图标乙 [+0xDC] 节点的源矩形）。

        ```
        0x45E347 v = s16[+0x26]
        0x45E34B v < 0xA0 → 节点.src = ((v>>4)*0x18, 0x1E0, +0x17, 0x1F7)
        0x45E3A6 满（≥0xA0）且 src.top != 0x1C8 → src = (0x48,0x1C8,0x5F,0x1DF)、[+0xE0]=0
        0x45E3FD/0x45E41A：[+0xE0] 交错标志，0x45A790(node, ±0x18, 0, ±0x18, 0)
        ```"""
        st = self.p4_stat
        ib = st.get("hud_icon_b")
        if ib is None:
            return
        v = st.get(0x4CD4A0 + 0x26, 0)
        v = v - 0x10000 if v & 0x8000 else v
        if v < 0xA0:                                    # 0x45E34B
            i = (v >> 4) & 0xF
            x = i * 0x18
            ib.src = (x, 0x1E0, x + 0x17, 0x1F7)
            return
        if ib.src[1] != 0x1C8:                          # 0x45E3A6 首次满格
            ib.src = (0x48, 0x1C8, 0x5F, 0x1DF)
            st[0x4CD4A0 + 0xE0] = 0
        st[0x4CD4A0 + 0xE0] = 1 if ib.src[0] == 0 else 0    # 0x45E3FD..0x45E40E
        d = 0x18 if st.get(0x4CD4A0 + 0xE0) else -0x18      # 0x45E41A / 0x45E435
        l, t, r, b = ib.src
        ib.src = (l + d, t, r + d, b)                   # 0x45A790(node, ±0x18, 0, ±0x18, 0)

    def p4_45a170_hud(self, keys=("hud_nodes", "hud_icon_a", "hud_icon_b",
                                  "st_icon_a", "st_icon_b")) -> None:
        """`0x45A170(h+0x64)` / `0x45A170(0x4CD590+0x04)`：HUD 显示表渲染
        （可见节点按 层/源矩形/目标点 色键贴屏，节点序 = 表序）。

        两次渲染分先后（0x45EEF3 渲 0x4CD4A0 表 → 0x460AE7 渲 0x4CD590 表），
        `keys` 参数用于分段调用。ctor 未写 src 的节点（0x460930 只写节点 1）
        在原作里是未初始化内存且隐藏 ⇒ 这里直接跳过。"""
        c = self.canvas
        for key in keys:
            for nd in st_nodes(self.p4_stat, key):
                if not nd.active:
                    continue
                src = getattr(nd, "src", None)
                if src is None:
                    continue
                lay = self.layers.tab.get(nd.layer)
                if lay is None:
                    continue
                l, t, r, b = src
                dx, dy = nd.dst
                c.blit(lay.buf, (l, t, r + 1, b + 1), (dx, dy), key=lay.ckey)

    def p4_hud_draw(self) -> None:
        """`0x45EED0(0x4CD4A0)` + `0x460A90(0x4CD590)`：HUD 每帧入口（0x458EF0 尾）。

        ```
        0x45EED3 if (byte[+0xE1]) { 0x45E020(h); byte[+0xE1] = 0 }
        0x45EEEB 0x45E340(h)                     ; 气槽排版
        0x45EEF3 0x45A170(h+0x64)                ; 渲染 22 节点显示表
        0x460A90：(倍率−1)%10 × 24 取字形写 [+0x2C] 节点 → 0x45A170(0x4CD590+0x04)
        ```"""
        st = self.p4_stat
        if st.get(0x4CD4A0 + 0xE1):
            self.p4_45e020()                          # 0x45EED3 → 0x45E020
            st[0x4CD4A0 + 0xE1] = 0
        self.p4_45e340()                              # 0x45EEEB
        self.p4_45a170_hud(("hud_nodes", "hud_icon_a", "hud_icon_b"))   # 0x45EEF3
        ib = st.get("st_icon_b")                      # 0x460AC5 用 [+0x2C] 节点
        t = st.get(0x4CD590 + 0x30, 0)
        t = t - 0x100000000 if t & 0x80000000 else t
        # 0x460A90 无任何门：src 恒按 (t-1)%10 写（t=-1 时为负矩形，节点本身隐藏看不见）。
        # 可见性只由 ctor(a3!=-1)/0x460E40(置1)/0x460C00(置0) 管理。
        if ib is not None:
            ib.src = self.p4_hud_rect(t)              # 0x460AA2..0x460AE4
        self.p4_45a170_hud(("st_icon_a", "st_icon_b"))   # 0x460AE7 → 0x45A170(+0x04)

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
            # 0x41000004 的 ctor = 0x428D59 ⇒ 复刻走 spark_spawn（速度取抖动方向，
            # 幅度 = 抖动原值；4CC 火花渲染/寿命路径现成）
            self.spark_spawn(px + jx, py + jy, jx * 4, jy * 4)
        self.p4_spawn_actor1(px, py, 1)                      # 0x460D1F 演员队列（0x445ECE，param=1 ⇒ 完整入场闪烁）
        self.p4_stat[M + 0x34] = self.p4_stat.get(M + 0x34, 0) + 1   # 0x460D2D
        self.p4_stat[M + 0x38] = self.p4_stat.get(M + 0x38, 0) + 1   # 0x460D32
        lives = self.p4_stat.get(M + 0x30, 0)                # 0x460D2A
        if lives != 0xFFFFFFFF:                              # 0x460D2F cmp eax,-1
            lives = (lives - 1) & 0xFFFFFFFF                 # 0x460D3A
            self.p4_stat[M + 0x30] = lives
            if lives == 0:                                   # 0x460D40 jne
                # 0x460D42..0x460D55：byte[[0x4CD590+0x2C]+0x1C] = 0 —— 熄灭残撃数字节点
                # （[+0x2C] = 0x460930 ctor 存的节点 2，与 0x460E40 的置 1 相对）。
                ib = self.p4_stat.get("st_icon_b")
                if ib is not None:
                    ib.active = 0
                self.p4_51_spawn(0, 0, 0x51000002, 0)               # 0x460D78 → 0x44B140

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
            entry = p4_score_entry(base, i)                     # 0x45F029：只读表 dword
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

    def p4_45fcb0(self, buf: bytearray) -> int:
        """`0x45FCB0(obj, buf)`：把整帧状态序列化进 `buf`，返回写入的总字节数（`esi` 末值）。

        头部（`0x45FCB9..0x45FCE7`）：
        ```
        [+0x00] = [obj+4]  总字节数        [+0x04] = [obj+8] = 0xE
        [+0x08] = [obj+0xC] 段数 A         [+0x0C] = [obj+0x10] = total
        [+0x10] = 0x456390(0x4CD484) = [0x4CD484+8]
        [+0x14] = 0x4563B0(0x4CD484) = [0x4CD484+0xC]
        ```
        然后：`+0x18` 起 0xE 个 dword（`0x44DCF0(0x4AA7B0,i)`）→ 段块（`0x4563D0`）→ 跳过 `A*4`
        → 12 个背景槽（`0x457D20` + `0x45FF80`）→ 4 条实体队列（`0x430880` + `0x45FF80`）。

        `0x456370/0x456390/0x4563B0` 全是 `mov eax,[ecx+N]; ret` 的 getter，
        `0x457520` 是 `lea eax,[ecx+0xC]; ret` —— 都已在 §16.241 定案。
        """
        seg = int(self.p4_stat.get("45fbf0_seg", 0))          # [obj+0xC]
        total = int(self.p4_stat.get("45fbf0_total", 0))      # [obj+0x10]
        size = int(self.p4_stat.get("45fbf0_size", 0))        # [obj+4]
        mgr = self.p4_stat.get("blk_4cd484")

        def d32(off, v):
            buf[off:off + 4] = (v & 0xFFFFFFFF).to_bytes(4, "little")

        if len(buf) < 0x18:
            return 0
        d32(0x00, size)                                       # 0x45FCBC
        d32(0x04, 0xE)                                        # 0x45FCC1
        d32(0x08, seg)                                        # 0x45FCCC
        d32(0x0C, total)                                      # 0x45FCE7
        d32(0x10, int.from_bytes(mgr[8:12], "little") if isinstance(mgr, (bytes, bytearray)) and len(mgr) >= 0xC else 0)   # 0x45FCD9
        d32(0x14, int.from_bytes(mgr[0xC:0x10], "little") if isinstance(mgr, (bytes, bytearray)) and len(mgr) >= 0x10 else 0)  # 0x45FCE1
        off = 0x18
        for i in range(0xE):                                  # 0x45FCF6 循环
            if off + 4 > len(buf):
                return off
            d32(off, self.p4_44dcf0("blk_4aa7b0", i))         # 0x45FCFC / 0x45FD01
            off += 4
        off += self.p4_4563d0("blk_4cd484", buf, off)         # 0x45FD14
        off += seg * 4                                        # 0x45FD1E
        for i in range(0xC):                                  # 0x45FD21 12 个背景槽
            ents = self.p4_stat.get(("bgslot", i)) or ()
            off += self.p4_45ff80(ents, buf, off)             # 0x45FD30
        for name in ("ui4cc", "ui43c", "ui49c", "ui40c"):     # 0x45FD3D.. 四条队列
            off += self.p4_45ff80(self.p4_430880(getattr(self, name, [])), buf, off)
        return off

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
            entry = p4_score_entry(base, i)             # 0x45FB12：只读表 dword
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
            if self.p4_afc0(0xC000) == 2:                       # 0x43CDFD 0x45AFC0(0x4AB5B0,0xC000)
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
        now = self.p4_frame_no() & 0xFFFF                    # word[0x56CCA8]（p4_frames 镜像）
        if now <= (e.g32(0x54) & 0xFFFF):                    # 0x43AE68
            return 0
        hp = e.g32(0x18)
        if hp & 0xF0000000:                                    # 0x43AE6F
            return (1 - e.g32(0x48)) & 0xFFFFFFFF              # 0x43AE7E
        h = ((hp + 0x3F) & 0xFFFFFFFF) >> 6                    # 0x43AE84
        if h <= e.g32(0x48):                                   # 0x43AE8C
            return 0
        return (h - e.g32(0x48)) & 0xFFFFFFFF                  # 0x43AE8E

    def p4_45aff0(self, mask: int) -> int:
        """`0x45AFF0(mgr, mask)`：`word[mgr+4] & mask` 非零则返回 1，否则 0
        （0x4AB5B0 位图 = self.keys.bits，与菜单同一真身）。"""
        return 1 if (self.keys.bits & mask) else 0

    def p4_445e47(self, e, rec=None) -> None:
        """`0x445E47`：type-5 构造器 —— 与自机同构的「8 指针行为表 + idx」写法。

        ```
        0x445E47 push 2 ; 0x45AFF0(0x4AB5B0, 2)
        0x445E4E..0x445E86 行为表 8 项：
            0x40197E 0x401FBE 0x4023B5 0x401960 0x40189D 0x401438 0x401ECE 0x401FC3
        0x445E93 edx = (bit2 != 0) ? 4 : 0        ; neg/sbb/and 4
        0x445EAA op = 0x45AFC0(0x4AB5B0, 0xC000)
        0x445EB5 idx = edx + op
        0x445EB9 [e+0x40] = 表[idx]
        0x445EBC eax = [ebp+0xC] (= rec[3] = a3)  ; 记录第 4 个 dword
        0x445EBF [e+0x1C] = eax                   ; ★ a3 落点就在这里
        0x445EC2 [e+0x20] = 0
        ```
        """
        had = self.p4_45aff0(2)                                # 0x445E8E（**只测不置**）
        edx = 4 if had else 0                                  # 0x445EA3
        op = self.p4_afc0(0xC000)                              # 0x445EAA
        idx = (edx + op) & 0xF                                 # 0x445EB5
        e.d32(0x40, P4_TYPE5_BEH[idx % len(P4_TYPE5_BEH)])     # 0x445EB9
        a3 = rec[3] if (rec is not None and len(rec) > 3) else 0
        e.d32(0x1C, a3 & 0xFFFFFFFF)                           # 0x445EBF（load 在 0x445EBC）
        e.d32(0x20, 0)                                         # 0x445EC2

    def p4_44601e(self, e, rec=None) -> None:
        """`0x44601E`：type-8 构造器。

        ```
        0x44601E [e+0x40] = 0x4015FF
        0x446025 [e+0x1C] = [rec+0xC]
        0x446028 eax = 5 → [e+0x20] = 5 ; [e+0x24] = 5 ; [e+0x28] = esi(=0)
        ```
        """
        e.d32(0x40, 0x4015FF)                                  # 0x44601E
        a3 = rec[3] if (rec is not None and len(rec) > 3) else 0
        e.d32(0x1C, a3 & 0xFFFFFFFF)                           # 0x446025
        e.d32(0x20, 5)                                         # 0x446030
        e.d32(0x24, 5)                                         # 0x446033
        e.d32(0x28, 0)                                         # 0x446036

    def p4_446227(self, e, rec=None) -> None:
        """`0x446227`：type-9 构造器。

        ```
        0x446227 [e+0x40] = 0x40116D
        0x44622E [e+0x1C] = [rec+0xC]
        0x446234 [e+0x20] = esi(=0)
        ```
        """
        e.d32(0x40, 0x40116D)                                  # 0x446227
        a3 = rec[3] if (rec is not None and len(rec) > 3) else 0
        e.d32(0x1C, a3 & 0xFFFFFFFF)                           # 0x44622E
        e.d32(0x20, 0)                                         # 0x446234

    def p4_446117(self, e, rec=None) -> None:
        """`0x446117`：type-10 构造器（**三次**取操作器，前两次各算一半矩形）。

        ```
        0x446121 [e+0x40] = 0x401BE0 ; [e+0xC]=0xC ; byte[e+0x10]=0 ; [e+0x1C] = -1
        0x44613A op = 0x45AFC0(0x4AB5B0,0xC000)
        0x446142 [e+0x20] = op ; 0x446145 [e+0x30] = 0 ; 0x446148 [e+0x18] = 1
        0x44614F [node+0] = 0
        0x446151 edx = (op*0x30) + 0x2F        ; 第三次 0x45AFC0 得到的 op
        0x446176 eax = op*0x30
        0x44618B rect = 0x45A750(&buf, 0(=esi), eax, 0x2F, edx)
        0x4461B4 0x45A690(e.x-0x18, e.y-0x18) → [node+0x14]/[+0x18]
        0x4461CD byte[node+0x1C] = 1
        0x4461D9 0x45A690(e.x, e.y) → [0x56CC8C]/[0x56CC90]
        0x4461E5 0x430400(&buf, 0xA0, 0x78, 0x10008043, e)  ; 5 dword
        0x44621A 0x430290(0x4AD46C, &rec)                    ; ★ 入 ui46c
        ```
        """
        e.d32(0x40, 0x401BE0)                                  # 0x446121
        e.d32(0x0C, 0xC)                                       # 0x446128
        e.m[0x10] = 0                                          # 0x44612F
        e.d32(0x1C, 0xFFFFFFFF)                                # 0x446133
        op = self.p4_afc0(0xC000)                              # 0x44613A
        e.d32(0x20, op)                                        # 0x446142
        e.d32(0x30, 0)                                         # 0x446145
        e.d32(0x18, 1)                                         # 0x446148
        rect = self.p4_45a750([0, 0, 0, 0], 0, op * 0x30, 0x2F, op * 0x30 + 0x2F)  # 0x44618B
        node = getattr(e, "node", None)
        if node is not None:
            node.src = tuple(rect)                             # 0x4461AB
            nx, ny = p4_45A690(e.s32(0x04) - 0x18, e.s32(0x08) - 0x18)   # 0x4461BC
            node.dst = (nx, ny)
            node.frame = 1                                     # 0x4461CD
        px, py = p4_45A690(e.s32(0x04), e.s32(0x08))           # 0x4461D9
        self.p4_player_pos = (px, py)
        self.p4_stat["44621a_ui46c"] = self.p4_stat.get("44621a_ui46c", 0) + 1   # 0x44621A

    def p4_44604e(self, e, rec=None) -> None:
        """`0x44604E`：**狙击自机**（type `0x0B000001`，行为 0x448C70）构造器。

        载体只在两处生成：页15 回放控制器 `0x44372B`（计数 0xF0 + btn0 沿，(200,200)
        命数 3）与 `0x448C70` 自身重生支 `0x448DBB`。按住攻击键开火 **0x1B000001**
        （狙，29×31 bm_cm48 格 (0xC0,0x30)，pscr0004 的黄"狙"）——回放页专属链。

        ```
        0x44605E [e+0x40] = 0x401E06        ; → 0x448C70
        0x446065 [e+0xC]  = 0x10            ; 半径 16
        0x44606C byte[e+0x10] = 1           ; ★ 这个类型构造时就是活的
        0x446070 [e+0x1C] = 0
        0x446089 [e+0x20] = [rec+0xC]
        0x44608C [e+0x18] = 1               ; HP
        0x446094 [node+0] = 0
        0x446096 rect = 0x45A750(&buf, 0x80, 0x50, 0x9F, 0x6F)
        0x4460A3 [node+4..+0x10] = rect
        0x4460BF 0x45A690([e+4] + 0x40, [e+8]) → [node+0x14]/[+0x18]   ; ★ x 偏 +0x40
        0x4460D5 byte[node+0x1C] = 1
        0x4460E1 0x45A690([e+4], [e+8]) → [0x56CC8C]/[0x56CC90]
        0x4460F9 0x45AF30(0x56CCC0, 1)      ; ★ 置 0x56CCC0 的 bit0
        0x44610D 0x44E470(0x4AB454, [rec+0], [rec+4])
        ```
        """
        e.d32(0x40, 0x401E06)                                  # 0x44605E
        e.d32(0x0C, 0x10)                                      # 0x446065
        e.m[0x10] = 1                                          # 0x44606C
        e.d32(0x1C, 0)                                         # 0x446070
        a3 = rec[3] if (rec is not None and len(rec) > 3) else 0
        e.d32(0x20, a3 & 0xFFFFFFFF)                           # 0x446089
        e.d32(0x18, 1)                                         # 0x44608C
        rect = self.p4_45a750([0, 0, 0, 0], 0x80, 0x50, 0x9F, 0x6F)   # 0x446096
        node = getattr(e, "node", None)
        if node is not None:
            node.src = tuple(rect)                             # 0x4460B6
            nx, ny = p4_45A690(e.s32(0x04) + 0x40, e.s32(0x08))   # 0x4460C4
            node.dst = (nx, ny)                                # 0x4460CC
            node.frame = 1                                     # 0x4460D5
        px, py = p4_45A690(e.s32(0x04), e.s32(0x08))           # 0x4460E1
        self.p4_player_pos = (px, py)                          # 0x56CC8C / 0x56CC90
        w = int(self.p4_stat.get(0x56CCC0, 0)) | 1             # 0x4460F9（另一组旗标字）
        self.p4_stat[0x56CCC0] = w
        self.p4_stat["44e470_rec"] = (rec[0], rec[1]) if (rec is not None and len(rec) >= 2) else (0, 0)

    def p4_42c4d0(self, e, rec=None) -> None:
        """`0x401AF0` → `0x42C4D0`：**0x01 族（武器挂舱）构造器**，逐条按本体。

        ```
        0x42C4DC [+0x1C] = 0 ; 0x42C4EA [+0x24] = 0
        0x42C4E7 [+0x20] = rec[3]                 ; 所有者/变体标记
        0x42C4F8 [+0x18] = 1                      ; HP
        0x42C4DF [+0x40] = 0x402059（默认，下面按变体/选机覆盖）
        0x42C4ED eax = [+0x14] - 0x1000001：
            ==0 → 0x42C599 [+0x40] = 表0[选机]    ; 0x402059/0x4011E0/0x401631/0x401DB6
            ==1 → 0x42C57C [+0x40] = 表1[选机]    ; 0x401DD9/0x4019C4/0x40107D/0x4013CF
            ==2 → 0x42C55F [+0x40] = 表2[选机]    ; 0x402027/0x40219E/0x40204A/0x401668
        ```
        12 个 thunk 解引用后恰为 P4_SPAWN_SLOTS 的 12 项发射器行为
        （thunk 序 → 槽号 [0,1,2,3,4,5,6,8,10,11,7,9]）——挂舱 = **武器槽**：
        按住攻击键按各槽节奏从所有者位置连发 0x12 族弹。
        """
        a3 = rec[3] if (rec is not None and len(rec) > 3) else 0
        e.d32(0x1C, 0)                                         # 0x42C4DC
        e.d32(0x24, 0)                                         # 0x42C4EA
        e.d32(0x20, a3 & 0xFFFFFFFF)                           # 0x42C4E7
        e.d32(0x18, 1)                                         # 0x42C4F8
        variant = (e.g32(0x14) - 0x1000001) & 0xFFFFFFFF       # 0x42C4F3
        ship = self.keys.field(0xC000) & 3                     # 0x45AFC0(…,0xC000)
        row = P4_POD_BEH[variant] if variant < len(P4_POD_BEH) else P4_POD_BEH[0]
        beh = row[ship % len(row)]
        e.d32(0x40, beh)
        if beh in P4_BEH:
            e.beh = beh                                        # 复刻分派按真址

    def p4_445c00(self, e, rec=None) -> str:
        """`0x445C00` 的 **type 分派**（外皮：分派后统一把 [0x40] thunk 解成真址存 .beh）。"""
        r = self._p4_445c00_body(e, rec)
        t = e.g32(0x40)
        e.beh = P4_445C00_THUNK.get(t, 0) if t else 0
        return r

    def _p4_445c00_body(self, e, rec=None) -> str:
        """`0x445C00` 的 **type 分派**（`0x445CBE eax=[e+0x14]; 0x445CC1 cmp eax,8; ja 0x44603E`）。

        ```
        type==1  → 0x445ECE  自机（p4_445ece）
        type==5  → 0x445E47  （p4_445e47）
        type==6  → 0x445CE7  伤害数字（见 0x45E670 系列）
        type==8  → 0x44601E
        type==9  → 0x446227
        type==10 → 0x446117
        type==0x0B000001 → 0x44604E  狙击自机（行为 0x401E06 → 0x448C70）
        其它     → 0x446237（跳过）
        ```

        `0x44603E` 的算术还原：`eax -= 9`（9 走 0x446227）、`dec eax`（10 走 0x446117）、
        再 `sub eax,0x0AFFFFF7` 为 0 ⇒ `(type − 10) − 0x0AFFFFF7 == 0` ⇒
        **`type == 0x0B000001`**（0x0AFFFFF7 + 10 = 0x0B000001；旧笔记写 0x0B000002 是
        减法基准数错 1，勘误 A-页4-5）。

        已落地的类型返回 `"handled:1"` / `"handled:5"`；其余返回 `"pending:<type>"`
        **并记录到 `p4_stat`**，不假装已构造（各 ctor 体尚未逐条读，§15）。
        """
        typ = e.g32(0x14)
        if typ == 1:                                           # 0x445CCD
            self.p4_445ece(e, rec)
            return "handled:1"
        if (typ & 0xFF000000) == 0x01000000:                   # 0x445CAF：0x01 族（挂舱）
            # 0x445CB4 jne 0x445CBE 跳过的前提是**非** 0x01 族；0x01 族先走
            # 0x401AF0→0x42C4D0（pod ctor，行为表 12 项按变体/选机选），再进
            # 0x445CBE 的 0x1/5/6/8 分派（0x1000001/2/3 落 0x446237 = 无二次构造）。
            self.p4_42c4d0(e, rec)
            return "handled:pod"
        if typ == 5:                                           # 0x445CD4
            self.p4_445e47(e, rec)
            return "handled:5"
        if typ == 6:
            self.p4_stat["445c00_type6"] = self.p4_stat.get("445c00_type6", 0) + 1
            return "handled:6"
        if typ == 8:                                           # 0x44601E
            self.p4_44601e(e, rec)
            return "handled:8"
        if typ == 9:                                           # 0x446227
            self.p4_446227(e, rec)
            return "handled:9"
        if typ == 10:                                          # 0x446117
            self.p4_446117(e, rec)
            return "handled:10"
        if typ == 0x0B000001:                                  # 0x44604E
            self.p4_44604e(e, rec)
            return "handled:0xb000001"
        self.p4_stat[("445c00_pending", typ)] = self.p4_stat.get(("445c00_pending", typ), 0) + 1
        return f"pending:{typ:#x}"

    def p4_435440(self, q, rec: int):
        """`0x435440(queue, rec)`：**按全局开关过滤**后分配节点（0x48 字节）并挂链。

        ```
        0x43545D 0x430820(queue, rec)
        0x435463 al = byte[0x56CCB2]
        0x43546A if (al == 0) → 0x435490            ; 关：无条件放行
        0x43546C eax = [rec+8] & 0x3F000000
        0x435474 if (eax == 0x32000000) → 0x435490
        0x43547B return 0                            ; 其它类型丢弃
        0x435490 空闲链表 [queue+0x28]，空则 0x47C7C0(0x48) 分配
        ```

        返回 `True` = 已入队，`False` = 被过滤丢弃。
        """
        if self.p4_stat.get(0x56CCB2, 0) & 0xFF:              # 0x435463
            if (rec & 0x3F000000) != 0x32000000:              # 0x43546C/0x435474
                return False                                  # 0x43547B
        self.p4_stat[("node_used", q)] = self.p4_stat.get(("node_used", q), 0) + 1
        return True

    @staticmethod
    def p4_45a750(out, a: int, b: int, c: int, d: int):
        """`0x45A750(out, a, b, c, d)` = **纯粹的四 dword 打包**：`out = (a, b, c, d)`。

        ```
        0x45A750 eax = [esp+4] = out ; 0x45A754 ecx = [esp+0xC] = b
        0x45A75A esi = [esp+0x10](原 +8) = a ; 0x45A760 edx = [esp+0x1C](原 +0x14) = d
        0x45A765 edi = [esp+0x1C](原 +0x10) = c
        0x45A769 [out]=a ; 0x45A76B [out+4]=b ; 0x45A76E [out+8]=c ; 0x45A773 [out+0xC]=d
        ```
        """
        out[0] = a & 0xFFFFFFFF
        out[1] = b & 0xFFFFFFFF
        out[2] = c & 0xFFFFFFFF
        out[3] = d & 0xFFFFFFFF
        return out

    def p4_445ece(self, e, rec=None) -> None:
        """`0x445C00` 的 **type-1（自机）构造器**，逐条按 `0x445ECE..0x446013`。

        ```
        0x445ECE 0x45AFF0(0x4AB5B0, 2) → al          ; bit2（操作器）是否已置位
        0x445ED5..0x45F015 行为表 8 项（栈上 [E+0x14..0x30]）：
            0x4466F0 0x4467D0 0x446890 0x446950 0x446A10 0x446AD0 0x446B50 0x446BD0
        0x45F1C edx = (al != 0) ? 4 : 0              ; neg/sbb/and 4（存 [E+0x10]）
        0x45F31 eax = 0x45AFC0(0x4AB5B0, 0xC000)     ; 选机 0..3
        0x45F3C idx = edx + eax                      ; ∈ 0..7（操作器 → 4..7）
        0x45F3E [e+0xC] = 0xA                        ; 半径 10
        0x45F45 byte[e+0x10] = 0                     ; ★ alive 初值 0
        0x45F49 [e+0x1C] = 0
        0x45F4C [e+0x40] = 行为表[idx]
        0x45F56 eax = ([rec+0xC] == 1) ? **0** : **-1** ; 0x45F59 dec/neg/sbb（§16.272 勘误）
        0x45F67 [e+0x20] = eax
        0x45F5A..0x45F6A [e+0x24]/[0x28]/[0x2C]/[0x30] = 0
        0x45F74 node[+0] = 0（层 0；节点已由 [e+0x38] 持有）
        0x45F80 op = 0x45AFC0(0x4AB5B0, 0xC000)
        0x445F85..0x445FAD 精灵矩形（2026-11-13 读定案，闭合原 §15 残留）：
            0x45A750(&rect, 0, 48*选机, 0x2F, 48*选机+0x2F)
            ⇒ **48×48、列 0、行 48*选机**（撃=0 / 凛=48 / 漢=96），
            0x445FC9..0x445FD5 写节点 +4..+0x10（源矩形）
        0x445FDB..0x445FF4 dst = (x−0x18, y−0x18)；byte[节点+0x1C] = 0
        0x446003 0x446470(e, 0, 1)（指针种子 = 出生点）
        0x446008 [0x56CC8C/90] = rec[0]/rec[1]
        ```
        """
        had_bit2 = self.p4_45aff0(2)                          # 0x45F015（**只测不置**）
        edx = 4 if had_bit2 else 0                            # 0x45F1C
        op = self.p4_afc0(0xC000)                             # 0x45F31
        idx = (edx + op) & 0xF                                # 0x45F3C
        e.d32(0x0C, 0xA)                                      # 0x45F3E
        e.m[0x10] = 0                                         # 0x45F45
        e.d32(0x1C, 0)                                        # 0x45F49
        e.d32(0x40, P4_PLAYER_BEH[idx % len(P4_PLAYER_BEH)])  # 0x45F4C
        a3 = rec[3] if (rec is not None and len(rec) > 3) else 0
        e.d32(0x20, 0 if a3 == 1 else 0xFFFFFFFF)             # 0x45F56/0x45F67（★见 §16.272 勘误）
        for off in (0x24, 0x28, 0x2C, 0x30):                  # 0x45F5A..0x45F6A
            e.d32(off, 0)
        e.d32(0x18, 1)                                        # 0x45F6D
        e.d32(0x38, 0)                                        # 0x45F74
        op2 = self.p4_afc0(0xC000)                            # 0x45F80
        self.p4_stat["player_sprite_y"] = op2 * 0x30 + 0x2F   # 0x45F93
        self.p4_stat["player_op"] = op2
        # 0x445F93..0x445FAD（已读定案）：0x45A750(节点矩形, 0, 48*选机, 0x2F, 48*选机+0x2F)
        # ⇒ 48×48 格、列 0、行 48*选机（撃=0 / 凛=48 / 漢=96），随后 0x445FC9..0x445FD5
        # 写进节点 +4..+0x10 = 源矩形；0x445FDB..0x445FF4 目标 = (x−24, y−24)。
        node = getattr(e, "node", None)
        if node is not None:
            node.rect = (0, op2 * 0x30, 0x2F, op2 * 0x30 + 0x2F)   # 0x445FC9..0x445FD5
            nx, ny = p4_45A690(e.s32(0x04) - 0x18, e.s32(0x08) - 0x18)
            node.dst = (nx, ny)                               # 0x445FF1 [节点+0x14]/[+0x18]
            node.frame = 0                                    # 0x445FFF byte[节点+0x1C] = 0
        p4_446470(self, e, 0, 1)                              # 0x446003
        if rec is not None and len(rec) >= 2:                  # 0x446008
            self.p4_player_pos = (rec[0], rec[1])              # 0x56CC8C / 0x56CC90

    def p4_45af30(self, bits: int) -> int:
        """`0x45AF30(mgr, bits)`：`word[mgr+4] |= bits`，返回新值。
        位图唯一真身 = `self.keys.bits`（KeyMgr 即 0x4AB5B0 镜像，页3/页13/页6 菜单全写它）；
        旧实现另存 p4_stat[0x4AB5B4] 副本 ⇒ 自机构造器 `0x45AFC0(0xC000)` 读到 0
        ⇒ 选凛也出撃精灵 —— 已并（依据 0x445F85..0x445FAD 精灵矩形 = 48×选机 行）。"""
        w = (self.keys.bits | bits) & 0xFFFFFFFF                     # 0x45AF37/0x45AF39
        self.keys.bits = w
        return w                                                     # 0x45AF3C

    def p4_45af60(self, bits: int) -> int:
        """`0x45AF60(mgr, bits)`：`word[mgr+4] &= ~bits`，返回新值。"""
        w = (self.keys.bits & ~bits) & 0xFFFFFFFF                    # 0x45AF67/0x45AF69
        self.keys.bits = w
        return w                                                     # 0x45AF6E

    def p4_afc0(self, mask: int, base: int = 0x4AB5B0) -> int:
        """`0x45AFC0(mgr, mask)`：取 `word[mgr+4] & mask`，**右移到 mask 的最低位**。

        `ecx` 是**对象指针**，不是固定全局：页4 里 `0x445EAA`/`0x44613A` 传 `0x4AB5B0`，
        而 `0x451663`/`0x45167A` 传 **`0x4AB5B8`**（另一个对象）。故这里带 `base` 参数。

        ```
        0x45AFC0 eax = [ecx+4] & mask
        0x45AFC9 eax == 0 → return 0
        0x45AFCB mask & 1 → return eax（已经在最低位）
        0x45AFD0 循环：mask >>= 1 ; eax >>= 1 ; 直到 mask & 1
        ```
        ⇒ `0x45AFC0(0x4AB5B0, 0xC000)` = **选机（0..3）**。位图取自 KeyMgr.bits
        （0x4AB5B0→self.keys、0x4AB5B8→self.disp_cfg），与页13 选槽、页3 菜单同一真身
        （旧 p4_stat[0x4AB5B4] 副本已废——自机构造器曾因此恒读 0，选凛也出撃）。
        """
        mgr = self.disp_cfg if base == 0x4AB5B8 else self.keys
        v = (mgr.bits & mask) & 0xFFFFFFFF                           # 0x45AFC0/0x45AFC7
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
        # 0x43C5C9：0x45AFF0(0x4AB5B0, 0x200)＝[0x4AB5B4] & 0x200（調整行 0 の XOR ビット）
        r = 3 if (self.keys.bits & 0x200) else 2
        # 0x43C5D7 [[p+0x1C]+0x28] = r：自動爆破 OFF(2)/ON(3) 写进**親実体**の [0x28]
        target = p.g32(0x1C)
        parent = self.p4_links.get(target) if target else None
        if parent is not None:
            parent.d32(0x28, r & 0xFFFFFFFF)
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
            # 0x43C6DA..0x43C731：锁定圈 0x41000006 @ 敌机（ctor 0x428EC6）
            ring = self.p4_spawn41(a.s32(0x04), a.s32(0x08), 0x41000006)
            if ring is not None:
                ring.p["sub"] = a                               # [rec+0xC] 解引用链 → 敌机
                ring.p["own2"] = p.p.get("sub")                 # [beam+0x24] = 自机
        # 0x43C736..0x43C7A9：4 片锁定碎片（rec0=4、rec1=±4 交替；ctor 0x428DFB）
        for rec1 in (4, -4, 4, -4):
            sh = self.p4_spawn41(a.s32(0x04) - 0x40,
                                 a.s32(0x08) - (rec1 << 4), 0x41000005)
            if sh is not None:
                sh.p["sub"] = a                                 # [+0x1C] = 敌机
                sh.d32(0x20, (-0x40) & 0xFFFFFFFF)              # [+0x20] = -rec0*16
                sh.d32(0x24, (-(rec1 << 4)) & 0xFFFFFFFF)       # [+0x24] = -rec1*16
                sh.d32(0x28, 4)                                 # [+0x28] = rec0
                sh.d32(0x2C, rec1 & 0xFFFFFFFF)                 # [+0x2C] = rec1
        # 0x43C7C1..0x43C7FB：狙击攻击驱动器 0x41400507（rec = {beam, [敌+0x48], type, 敌}）
        self.p4_41400507_spawn(p, a)
        a.d32(0x48, (a.g32(0x48) + 1) & 0xFFFFFFFF)             # 0x43C7FF
        a.d32(0x54, (self.p4_frame_no() + 0x10) & 0xFFFFFFFF)   # 0x43C80A（word[0x56CCA8]+0x10）
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

        后半段 `0x43C508` 起的按型 cmp 链见 `_p4_43c460_dispatch`（含 0x10008041
        锁定捕获 → `_p4_43c6c4`）。
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
        self.spark_spawn(x, y, ox, oy)                         # 0x43C488 → ctor 0x428D59
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
            self.p4_spawn_61000004(a.s32(0x04), a.s32(0x08), 0x30)   # 0x43CA5A
        else:
            g = self.p4_spawn41(a.s32(0x04), a.s32(0x08), 0x41000001)   # 0x43CA94
            if g is not None:
                _, r3 = self.p4_rand_mod(3)                     # 0x428CD3 爆炸行随机
                g.node.rect = (0xC0 + 48 * r3, 0, 0xEF + 48 * r3, 0x2F)
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
                p.d32(0x18, 0)                                 # 0x43C963 弹 HP=0
                a.d32(0x18, (a.s32(0x18) - 1) & 0xFFFFFFFF)    # 0x43C96C..0x43C972 靶 HP--（无条件）
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
            self._p4_set_col(e)
            if not bit2_clear and not (e.g32(0x14) & 0x8000):   # 0x43C085 test ah,0x80
                continue
            for t in list(qb):
                self._p4_set_col(t)
                if self.p4_hit_test(t, e.s32(0x04), e.s32(0x08), e.s32(0x0C)):   # 0x43C0A9
                    self.p4_43c460(e, t)                        # 0x43C0B2 push edi / 0x43C0B3 push esi
                    hits += 1
        return hits


    @staticmethod
    def _p4_set_col(e) -> None:
        """碰撞参与位 [0x10] = 1（Ent 用 .m、UiEntity 用 .raw）。"""
        if hasattr(e, "m"):
            e.m[0x10] = 1
        elif hasattr(e, "raw"):
            e.raw[0x10] = 1

    def p4_43c0f0(self, qa, qb) -> int:
        """`0x43C0F0(a, b)`：与 `0x43BFD0` 同形，但命中回调是 `0x43CCC0`（`0x43C135`）。"""
        hits = 0
        for e in list(qa):
            self._p4_set_col(e)
            for t in list(qb):
                self._p4_set_col(t)
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
        存储统一放 `p4_stat[0x56CCC0]`（0x44604E 的 ctor 置位也写这里，2026-10-31 前
        曾分裂成 `_p4_in` 属性与 p4_stat 两处互不可见）。
        """
        return int(self.p4_stat.get(0x56CCC0, 0)) & 0xFFFFFFFF

    def p4_in_set(self, bits: int) -> None:
        self.p4_stat[0x56CCC0] = bits & 0xFFFFFFFF

    def p4_key_test(self, mask: int) -> bool:
        """`0x45AFF0(0x56CCC0, mask)`：测输入状态位。"""
        return bool(self.p4_in_bits() & mask)

    def p4_key_reset(self, mask: int) -> None:
        """`0x45AF60(0x56CCC0, mask)`：清位。"""
        self.p4_in_set(self.p4_in_bits() & ~mask)

    def p4_key_raw_set(self, mask: int) -> None:
        """`0x45AF30(0x56CCC0, mask)`：置位。"""
        self.p4_in_set(self.p4_in_bits() | mask)

    @property
    def p4_player_pos(self) -> "tuple[int, int]":
        """`[0x56CC8C]/[0x56CC90]`：自机缓存（唯一真身 = `self.mirror`）。

        exe 里是**一个地址**、最后写者生效：0x446008（自机 ctor）、0x446741 族
        （自机行为每帧）、0x4461D1（页13 机体大字）。复刻侧曾有 p4_player_pos /
        p4_stat[0x56CC8C/90] / self.mirror 三份互不同步的副本 ⇒ 追踪类实体
        （fx12 chase 弹的 mirror_y 等）读到陈旧值（凛弹朝屏幕上方漂移）⇒ 已并。
        """
        return (int(self.mirror["x"]) & 0xFFFFFFFF, int(self.mirror["y"]) & 0xFFFFFFFF)

    @p4_player_pos.setter
    def p4_player_pos(self, v) -> None:
        x = int(v[0]) & 0xFFFFFFFF
        y = int(v[1]) & 0xFFFFFFFF
        self.mirror["x"], self.mirror["y"] = x, y
        self.p4_stat[0x56CC8C] = x                    # 兼容既有 p4_stat.get 读点
        self.p4_stat[0x56CC90] = y

    def p4_player_y(self) -> int:
        """`[0x56CC90]`：自机缓存 y（`0x448D2D` 写）。"""
        return int(self.mirror["y"])

    def p4_player_x(self) -> int:
        """`[0x56CC8C]`：自机缓存 x（与 `0x56CC90` 成对，`0x446819` 由 `0x45A690` 写入）。"""
        return int(self.mirror["x"])

    def p4_btn_attack(self) -> bool:
        """`[0x4AB594]`：btn0（C/左键=攻击）当前状态。"""
        return bool(self.p4_in_bits() & 1)

    def p4_btn0_edge(self) -> bool:
        import os as _o
        if _o.environ.get("P4_AUTOKEY") and getattr(self, "p4_frames", 0) >= 240:
            return True
        """`byte[0x4AB596]`：btn0 **按下沿**（输入记录第 3 字节，`rec.e0`）。"""
        return bool(getattr(self.inp.rec, "e0", 0))

    def p4_btn1_edge(self) -> bool:
        """`byte[0x4AB597]`：btn1 **按下沿**（输入记录第 4 字节，`rec.e1`）。"""
        return bool(getattr(self.inp.rec, "e1", 0))

    def p4_btn1_release(self) -> bool:
        """`byte[0x4AB599]`：btn1 **松开沿**（输入记录第 6 字节，`rec.r1`）。"""
        return bool(getattr(self.inp.rec, "r1", 0))

    def p4_anim_step(self, e) -> None:
        """`0x45A790(节点+4, -0x20, 0, -0x20, 0)`：按 16 帧周期切自机动画帧
        （源矩形整窗左移 0x20：0x80→0x60→0x40→0x20→0x00，rect.l 到 0 即动画毕）。"""
        nd = e.node
        if nd is None:
            return
        r = nd.rect
        nd.rect = (r[0] - 0x20, r[1], r[2] - 0x20, r[3])   # 0x45A790 grow(-0x20,0,-0x20,0)

    def _p4_q(self, name: str) -> list:
        if name == "ui40c":
            # 0x4AD40C 的复刻侧本名是 self.actorq（geki 初始化、p4 帧序 0x448F80 tick）。
            # 旧复刻在 _p4_q("ui40c") 里另造了一个无人 tick 的死列表，VM op1 生成的
            # 自机（演员 type 1）从不更新（2026-10-31 修，"撃 常驻"的一半根因）。
            return self.actorq
        if name == "ui49c":
            # 0x4AD49C 的复刻侧本名是 self.p4_ui49c（p4 帧序 0x4353A0 tick）。
            # 同 ui40c 的分裂根因，2026-11-03 修——敌方弹幕此前不被 tick 也不入碰撞。
            return self.p4_ui49c
        q = getattr(self, name, None)
        if q is None:
            q = []
            setattr(self, name, q)
        return q

    # ---- 背景槽 0x4AD55C -------------------------------------------------
    def p4_bg_stop(self, ch: int) -> None:
        """`0x457C80`→`0x457260`：停一个背景槽（ch>=12 广播 12 槽）。

        复位 +0x30/+0x80 参数块、+0xD0 网格、+0x2A88..+0x2A94 与带/显示链。
        """
        for i in (range(12) if ch >= 12 else [ch]):
            if not (0 <= i < 12):
                continue
            sl = self.p4_bg[i]
            sl.params = [0] * 20
            sl.rates = [0] * 20
            sl.grid = []
            sl.bands = []
            sl.rem = 0
            sl.flags = 0
            sl.active = 0
            sl.acc = 0

    def p4_bg_record(self, op: int, ch: int, block: bytes, flags: int, rep: int = 0) -> None:
        """op06 `0x457C00`（立即触发）/ op07 `0x457C40`（只改参数）。
        `ch >= 0xC` ⇒ 对 12 个槽广播；block 是记录的 20 个 dword（记录 +8 起）。"""
        vals = [int.from_bytes(block[4 * i:4 * i + 4], "little", signed=True) for i in range(20)]
        import os as _os
        if _os.environ.get("P4_TRACE_BG"):
            self.p4_trace_bg = True
        if getattr(self, "p4_trace_bg", False):
            print(f"[bgrec] op{op} ch={ch} count={vals[10]} flags=0x{flags:X} rep={rep}", flush=True)
        if op == 6 and not (0 <= ch < 12):            # 0x457C00 无边界检查（exe UB）
            return
        targets = range(12) if (op == 7 and ch >= 12) else [ch]   # 只有 op7/op8 广播
        for i in targets:
            slot = self.p4_bg[i]
            if op == 6:                                  # 0x4572E0
                slot.flags = flags & 0xFFFFFFFF          # +0x2A8C
                slot.rem = 0                             # +0x2A88
                slot.active = 1                          # +0x2A90
                slot.params = list(vals)                 # 0x456D50 直拷 20 dword
                self._bg_dispatch(slot)                  # 0x456EB0
                if getattr(self, "p4_trace_bg", False):
                    _b = (slot.grid[0] if getattr(slot, "grid", None) else None)
                    print(f"[bggrid] i={i} ngrid={len(getattr(slot,'grid',[]) or [])} "
                          f"first={_b} count={slot.params[10]} flags=0x{slot.flags:X}", flush=True)
                    print(f"[bgslot] op{op} i={i} ngrid={len(getattr(slot,'grid',[]) or [])} "
                          f"first={_b} count={slot.params[10]} flags=0x{slot.flags:X}", flush=True)
            else:                                        # 0x457330
                if not slot.active:
                    continue
                slot.flags = flags & 0xFFFFFFFF
                slot.rem = rep                           # +0x2A88
                slot.rates = list(vals)                  # +0x80
                if _os.environ.get("P4_OP7TRACE"):
                    print(f"[op7] ch={ch} flags=0x{flags:X} rep={rep} "
                          f"rates[0:8]={vals[0:8]} rates[10:16]={vals[10:16]}", flush=True)

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
        """`0x457120(this, phase)`：分配 **0x34 字节节点**，`0x457540` 构造后**尾插**到带链。

        ```
        0x457139 push 0x34 ; 0x47C7C0 分配
        0x45713B eax = [esi+4]（头指针）
        0x457140 头为空 → 0x45716E 0x457540(new, phase, &[esi+0x30], &[esi+0xC], &[esi+0xD0])
                          0x457175 [esi+4] = new          ; 头 = 新节点
        0x457181 头非空 → 同样 0x457540 构造
                          0x4571B8 ecx = [esi+8]（尾指针）
                          0x4571BB [[esi+8] + 0x30] = new ; ★ 挂到尾节点的 +0x30
        ```

        ⇒ 带链 = **单链表**，头 `[+4]`、尾 `[+8]`、`next` 在节点 `+0x30`，
        节点 0x34 字节。

        **节点字段（据 `0x457750` 的消费方式反推，§16.253 已勘误）**：
        `[+4] = &[slot+0xD0]`（格子表，表项 3 dword、kind 在 +8）、
        `[+8] = &[slot+0x30]`（参数区，`[+0x38]` 即 params[14] 步进）、
        `[+0xC] = 位置`（初值 = phase，每帧 `+= params[14]`）、
        `[+0x28] = &[slot+0xC]`。
        ⚠ 之前把 `+8`/`+0xC`/`+0x28` 三个指针的对应关系写反了 —— cdecl 下**最后 push 的是第一个参数**，
        `0x457120` 的 push 序列末端是 phase ⇒ `arg1 = phase`，不是 `&[slot+0xC]`。

        **注意**：`0x457120` 本身**不做**索引越界判断，也**没有** 890 上限 ——
        上限 `0xA6E` 在 `0x457282`（`0x457210` 那条摘链/修剪路径）里。
        复刻侧这里保留 idx 范围检查与 890 上限，只是**等价的省分配/防暴涨保险**，
        不是本条指令的转写 —— 越界带在 `0x457750` 首帧即判出界摘链，结果一致。
        """
        n = slot.params[10]
        if idx < 0 or idx >= n:
            return
        if len(slot.bands) >= 890:
            return
        slot.bands.append(BgBand(slot, idx))

    @staticmethod
    def p4_4511_ta(prev_b: int, b: int, prev_a: int, a: int, old_ta: int):
        """`0x451186..0x451206`：`[0x56CCD4]`（状态行的 `TA`）其实是**两个计时器的比率**。

        ```
        0x451186/0x451193 门：[0x56CCC9] 与 [0x56CCB5] 都为 1 才算
        0x4511A2 ecx = 0x4AB570 ; call 0x401A28 → eax ; esi = eax   ; 计时器 A
        0x4511AC ecx = 0x4CD5D8 ; call 0x4012C6 → eax ; ebp = eax   ; 计时器 B（回放管理器）
        0x4511BA eax = [0x56CCD0]（上次 B）; 0x4511BF cmp eax,ebp ; je 0x45120C  ; B 未变 → 整段跳过
        0x4511C3 ecx = [0x56CCCC]（上次 A）; 0x4511C9 cmp esi,ecx ; je 0x451200  ; A 未变 → 不除
        0x4511CD..0x4511E4  (ebp - 上次B) * 100      ; ×5 ×5 shl2 = ×100
        0x4511E8 div edi (edi = esi - ecx)           ; / (A - 上次A)
        0x4511EA cmp eax,0x3E8 ; 0x4511EF [0x56CCD4]=eax ; 0x4511F4 jb
        0x4511F6 [0x56CCD4] = 0x3E7                  ; >= 1000 钳到 999
        0x451200 [0x56CCD0]=ebp ; 0x451206 [0x56CCCC]=esi
        ```

        ⇒ `TA = (B - 上次B) * 100 / (A - 上次A)`，**钳 999**。
        这是个**比率/速率百分比**，配合 `%03d` 的宽度（最大 999）恰好自洽。

        返回 `(new_ta, new_prev_b, new_prev_a)`；前两个「未变」分支原样保留旧值。
        """
        if b == prev_b:
            return old_ta, prev_b, prev_a          # 0x4511BF je 0x45120C：整段跳过
        if a == prev_a:
            return old_ta, b, a                     # 0x4511C9 je 0x451200：只更新上次值
        ta = ((b - prev_b) * 100) // (a - prev_a)
        if ta >= 0x3E8:
            ta = 0x3E7                              # 0x4511F6
        return ta, b, a

    @staticmethod
    def p4_4512_status(ts: int, ta: int) -> str:
        """`0x451259..0x4512C2`：页4 每帧状态行的**两个计时字段**（不是分数）。

        ```
        0x451259 cmp ebp, 0x5F5DD18 ; jb 0x451268 ; 0x451263 ebp = 0x5F5DD18   ; 上限钳位
        0x451268 eax = 0x10624DD3 ; 0x451271 mul ebp ; 0x451273 shr edx,6
            ⇒ edx = ebp / 1000   （0x10624DD3>>6 是除 1000 的魔数）
        0x451277 push 0x4A488C (= "TS:%05d ") ; 0x46318E(buf, fmt, edx)
        0x4512AB eax = [0x56CCD4] ; push eax
        0x4512BC push 0x4A4880 (= "TA:%03d ") ; 0x46318E(buf + 尾, fmt, eax)
        ```

        `0x5F5DD18 = 99999000` ⇒ 钳位后 `/1000 = 99999`，正好塞满 `%05d`。
        第二段是**追加**（`0x4512A5 dec edi` 先退一格，再从该处拷入）。
        """
        v = ts if ts < 0x5F5DD18 else 0x5F5DD18
        return "TS:%05d " % (v // 1000) + "TA:%03d " % (ta & 0xFFFFFFFF)

    P4_HUD_SEGS = (
        (0x43DF71, 0x20, 0x1B0, 0x4A405C),      # 底行 x=0x20
        (0x43DF98, 0x93, 0x1B0, 0x4A4054),      # 底行 x=0x93（步距 0x73）
        (0x43DFBF, 0x106, 0x1B0, 0x4A404C),
        (0x43DFE6, 0x179, 0x1B0, 0x4A4044),
        (0x43E00D, 0x1EC, 0x1B0, 0x4A4040),
        (0x43E037, 0x20, 0x20, 0x4A4020),       # 顶行 y=0x20
        (0x43E058, 0x30, 0x20, 0x4A3FEC),
        (0x43E079, 0x40, 0x20, 0x4A3FD0),
    )   # (调用地址, x, y, 文本指针)；颜色一律 0xD3、底色 0xD9、高 0x10

    @staticmethod
    def p4_43df_hud_gate(v: int) -> bool:
        """`0x43DF32..0x43DF4C`：HUD 那一行只在特定时刻画。

        ```
        0x43DF32 eax = [ebx+0x1C]
        0x43DF35 cmp eax,0xC8 ; 0x43DF3A je 0x43DF52   ; == 0xC8 → 画
        0x43DF3C cmp eax,0xE6 ; 0x43DF41 jl 0x43E07E   ; < 0xE6（且非 0xC8）→ 不画
        0x43DF47 cmp eax,0x122; 0x43DF4C jge 0x43E07E  ; >= 0x122 → 不画
        ⇒ 画 ⇔ v == 0xC8 或 (0xE6 <= v < 0x122)
        ```
        """
        return v == 0xC8 or 0xE6 <= v < 0x122

    @staticmethod
    def p4_band_kind_code(kind: int):
        """`0x4577D7..0x457861` 的 **kind → 显示节点类型码** 查表（纯查表，可单测）。

        `0x4577DD xor ecx,ecx ; mov cl, byte[eax + 0x457938]` —— 以 kind 为下标取
        **字节索引表** `0x457938`，再 `jmp [ecx*4 + 0x457908]` 跳进 12 项跳表。

        `0x4577D7 ja 0x457861` 先挡掉 `kind > 0xF0`（走兜底，不改类型码）。

        | 索引 | kind | 落点 | `[node+0]` |
        |---|---|---|---|
        | 0 | 0 | `0x4577EC` | **不设码**，只 `byte[node+0x1C]=0`（隐藏） |
        | 1 | 6 | `0x4577F5` | 3 |
        | 2 | 10 | `0x4577F5`+11 = `0x457800` | 4 |
        | 3 | 16 | `0x45780B` | 5 |
        | 4 | 24 | `0x457816` | 6 |
        | 5 | 32 | `0x457821` | 7 |
        | 6 | 48 | `0x45782C` | 8 |
        | 7 | 72 | `0x457837` | 9 |
        | 8 | 108 | `0x457842` | 10 |
        | 9 | 160 | `0x45784D` | 11 |
        | 10 | 240 | `0x457858` | 12 |
        | 11 | 其它 | `0x457861` | 不改（继续走） |

        ⇒ kind 是一把**阶梯尺**（0/6/10/16/24/32/48/72/108/160/240），
        每一级对应一个图块变体码 3..12。返回 `None` 表示「不改类型码」。
        """
        return {0: None, 6: 3, 10: 4, 16: 5, 24: 6, 32: 7,
                48: 8, 72: 9, 108: 10, 160: 11, 240: 12}.get(kind)

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
                pass                                     # 0x4577D7 ja → 直落 0x457861
            else:
                idx = BG_KIND_IDX[kind] if kind < len(BG_KIND_IDX) else 0x0B
                if idx == 0:                             # 0x4577EC：隐藏
                    band.visible = 0
                elif idx != 0x0B:                        # 0x4577F5..0x457858：层号
                    band.layer = idx + 2
                # ★ 0x4577F5..0x457858 十个分支全部 `jmp 0x457861`（逐支解出）：
                #   写层号之后**必写**源矩形，"映射 kind 不写矩形"的旧说作废。
        if kind == 0:                                    # 0x4578B5 test k / je 0x4578ED
            band.visible = 0                             # 每帧都判（不只 kind 变化时）
            return True
        # 0x457861 源矩形 (0, row*k, k-1, (row+1)*k-1)（含 idx 0/11 两支也落这里）
        gx = grid[pos][0] if pos < len(grid) else 0
        gy = grid[pos][1] if pos < len(grid) else 0
        band.src = (0, band.row * kind, kind - 1, (band.row + 1) * kind - 1)
        # 0x4578A5..0x4578D3 目标 = 格子原始坐标 + 抖动*k>>6 − k/2（0x45A690 恒等，无缩放）
        band.dst = (gx + band.w - (kind >> 1), gy + band.h - (kind >> 1))
        return True

    @staticmethod
    def p4_457380_acc(acc: int, step: int, thresh: int, p58: int):
        """`0x4573ED..0x457441` 的**累加器**（`0x457380` 尾段，纯算术，可单测）。

        ```
        0x4573ED eax = [esi+0x68](step) ; edx = [esi+0x2a94](acc)
        0x4573FB acc += step → [esi+0x2a94]
        0x457403 cdq / xor / sub        ; eax = |acc|（对 INT_MIN 也成立的三指令取绝对值）
        0x457408 cmp eax, [esi+0x64](thresh) ; jl → 返回
        0x45740C test step,step ; jl 0x457426   ; ★ 正负两种回绕，不对称（**有符号** test）
        正：0x457414 acc -= thresh → 0x457120(this, acc - thresh)
        负：0x457429 eax = thresh + acc → 0x45742C 存 → 0x457434 eax = [esi+0x58] + acc - 1
            → 0x457120(this, [esi+0x58] + acc - 1)
        ```

        返回 `(phase, acc)`；phase=None = 未触发。acc/step/thresh 全程**有符号**
        （exe 的 `test ebx,ebx / jl` 是符号位判断；旧复刻用 `& 0xFFFFFFFF` 后的
        无符号值做 `step >= 0` 判断，负步进全走了正分支 ⇒ acc 单调下漂、相位恒负
        被丢弃，战斗段 8 槽一条带都生不出来——2026-10-31 修）。
        """
        acc = acc + step
        if (acc if acc >= 0 else -acc) < thresh:
            return None, acc
        if step >= 0:
            return acc - thresh, acc - thresh
        na = acc + thresh
        return p58 + na - 1, na                          # 0x457434

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
        # [slot+0x68]/[slot+0x64]：op7 速率应用会把 params 变成无符号存放
        # （`& 0xFFFFFFFF`），而 exe 的 `test/jl` 按符号判断 ⇒ 读取时归一回有符号。
        # （只归一 [0x80000000,0xFFFFFFFF] 的无符号态；params 里可能本就是负 int。）
        step = slot.params[14]                               # [slot+0x68]
        if 0x80000000 <= step <= 0xFFFFFFFF:
            step -= 0x100000000
        thresh = slot.params[13]                             # [slot+0x64]
        if 0x80000000 <= thresh <= 0xFFFFFFFF:
            thresh -= 0x100000000
        phase, slot.acc = self.p4_457380_acc(slot.acc, step, thresh, slot.params[10])
        if phase is None:
            return
        self._bg_spawn_band(slot, phase)                     # 0x457120(this, 相位)

    def p4_bg_update(self) -> None:
        """S21 第一条 `0x458E75` → `0x457BD0` → 12× `0x457380`。"""
        for _sj, slot in enumerate(self.p4_bg):
            self._bg_update(slot)

    def p4_bg_draw(self) -> None:
        """`0x458EF5` → `0x457CB0`（12 槽，步长 0x2A98）→ `0x457490` → `0x45A170(slot+0xC)`。

        每槽的**显示链**（宿主 = `&[slot+0xC]`，`0x45A0E0` 头插 ⇒ 链头 = 最新带状体）
        逐节点色键贴屏；节点字段由 `_bg_update`/`_bg_band`（`0x457380`/`0x457750`）每帧维护：

        ```
        0x457490 byte[slot+0x2A90]==0 → 跳过
        0x45A170 从链头（= 最新带）沿 next 渲染 ⇒ 渲染序 = 带链**逆序**
        byte[node+0x1C] 可见位（0x457750 的窗口/使能/k==0 三处写）
        node[+0] 层号（k 阶梯 3..0xC；未映射 kind 保持 0 = 层 0）
        node[+4..+0x10] 源矩形 (0, row*k, k-1, (row+1)*k-1)
        node[+0x14/+0x18] 目标 = 格子原始坐标 + 抖动*k>>6 − k/2（**无缩放**，0x45A690 恒等；
            超出 640×480 的格子由贴屏裁剪，0x456FB0/0x457000 锚定 + op7 速率漂移决定可见性）
        ```

        网格坐标是**原始像素坐标**（模式 0 `0x456F30` 的基准 = `params[0]>>6`，如 33280>>6=520）；
        此前渲染端自造的 `*640>>10 / *480>>10` 归一化与 `slot._t` 单索引模型一并废除。
        """
        c = self.canvas
        for slot in self.p4_bg:
            if not slot.active:
                continue                             # 0x457490 byte[ecx+0x2A90]
            for band in reversed(slot.bands):        # 0x45A170：链头 = 最新带 → 先画
                if not band.visible:
                    continue                         # byte[node+0x1C]
                k = band.kind
                if k <= 0:
                    continue                         # 0x4578B5 k==0 → 隐藏
                lay = self.layers.tab.get(band.layer)
                if lay is None or lay.bind_id < 0:
                    # 0x44CEE0 释放（op0xB 里 res==5 的层）后表面不存在 → 跳过。
                    # 旧复刻 free_all 留了空层（bind_id=-1、全 0、无色键），
                    # kind=240 的大字块贴出整块调色板 0 号色 = 底部白块（2026-10-31 修）。
                    continue
                l, t, r, b = band.src
                dx, dy = band.dst
                if dx >= 0x80000000:                  # 负坐标以无符号 dword 存放 → 归一
                    dx -= 0x100000000
                if dy >= 0x80000000:
                    dy -= 0x100000000
                c.blit(lay.buf, (l, t, r + 1, b + 1), (dx, dy), key=lay.ckey)
                self.p4_stat[0xB6] = self.p4_stat.get(0xB6, 0) + 1

    def p4_render_ents(self) -> None:
        """`0x458EF0` 渲染遍里 0x4AD43C 队列那一轮：`0x45A170`→`0x44D010` flags=0x11（色键 0），
        源矩形先按 (0,0,640,480) 裁剪窗裁（`0x459F70` 给的整屏）。dst 按 int32 归一
        （0x42/0x46 实体会把负坐标存成无符号 dword，原样 blit 会被 pygame 裁掉）。"""
        c = self.canvas
        # 0x458EF0 的第 2 轮 = 0x402531 → 0x430840(0x4AD43C)；
        # 其余队列由 geki.draw() 里的 _render_queue 逐条调用（顺序同 0x458EF0）
        for e in list(self.p4_q43c):
            nd = e.node
            # 0x45A170 的可见性只看节点自身（byte[node+0x1C]），不看实体类型
            if nd is None or not nd.active:
                continue
            lay = self.layers.tab.get(nd.layer)
            if lay is None:
                continue
            l, t, r, b = nd.rect
            dx, dy = nd.dst
            if dx >= 0x80000000:
                dx -= 0x100000000
            if dy >= 0x80000000:
                dy -= 0x100000000
            c.blit(lay.buf, (l, t, r + 1, b + 1), (dx, dy), key=lay.ckey)

    # ---- 特殊类槽行为用到的三个助手（§16.180/§16.181）------------------
    # ---- 0x10008041 锁定准星（0x42DABC ctor + 0x42E460 族行为 + 0x42F4B0 矩形动画）----

    def p4_lock_ctor(self, e, rec) -> None:
        """`0x42DABC`（0x42D780 的 0x10 族分支）：0x10008041/0x10008043 构造。

        ```
        0x45AFF0(0x4AB5B0,2)=0x45B030 反测?? —— 0x40208B→0x45AFF0 普通测：bit1(操作器)置 → +4
        行为表 8 项 0x401285/0x402338/0x402153/0x401866/0x4013E8/0x401E51/0x401CF3/0x401EB5
            → 0x42E460/0x42E520/0x42E660/0x42E810/0x42EA70/0x42EB30/0x42EC70/0x42EE20
            （idx = (bit1?4:0)+选机；4..7 与 0..3 逐字节同语义，仅 call 位移差——实测）
        0x10008043 → 行为恒 0x4021A3(0x42F080)
        [0xC]=0x30（半径 48）；byte[0x10]=1；[0x1C]=[0x20]=0；[0x24]=rec[3]（自机）；[0x28]=选机
        [0x18]=-1；节点层 0、src (0x8D,0x2D,0x93,0x32)（7×6 锁点）、dst=(x−3,y−3)、byte[节点+0x1C]=[0x56CCC8]
        ```
        """
        had_kb = self.keys.test(2)                          # 0x45AFF0(…,2) 普通测
        ship = self.keys.field(0xC000) & 3
        idx = (4 if had_kb else 0) + ship
        # ⚠ UiEntity.spawn 不写 raw[0x14]（§16.345 陷阱）⇒ 类型判定用 type_word
        is41 = (getattr(e, "type_word", e.g32(0x14))) == 0x10008041
        if hasattr(e, "raw"):
            e.d32(0x14, 0x10008041)                          # 补类型字段（碰撞分派读它）
        e.d32(0x40, (0x4021A3 if not is41 else
                     (0x401285, 0x402338, 0x402153, 0x401866,
                      0x4013E8, 0x401E51, 0x401CF3, 0x401EB5)[idx % 8]))
        # v4..v7 与 v0..v3 逐字节同语义（仅 call 位移差）⇒ beh 归并到 v0..v3 真址
        e.beh = {0x401285: 0x42E460, 0x402338: 0x42E520, 0x402153: 0x42E660,
                 0x401866: 0x42E810, 0x4013E8: 0x42E460, 0x401E51: 0x42E520,
                 0x401CF3: 0x42E660, 0x401EB5: 0x42E810, 0x4021A3: 0x42F080}.get(e.g32(0x40), 0)
        e.d32(0x0C, 0x30)
        if hasattr(e, "m"):
            e.m[0x10] = 1
        else:
            e.raw[0x10] = 1                                  # UiEntity：碰撞位走 raw
        e.d32(0x1C, 0)
        e.d32(0x20, 0)
        a3 = rec[3] if (rec is not None and len(rec) > 3) else 0
        e.d32(0x24, a3 & 0xFFFFFFFF)                        # 自机指针
        e.d32(0x28, ship)
        e.d32(0x18, 0xFFFFFFFF)
        from geki import DisplayNode as _DN
        e.node = _DN(layer=0, rect=[0x8D, 0x2D, 0x93, 0x32],
                     dst=[e.s32(4) - 3, e.s32(8) - 3])      # 0x45A750 + 0x45A690(x−3,y−3)
        e.disp = e.node
        e.node.active = 1 if getattr(self, "p4_ccc8", self.p4_stat.get(0x56CCC8, 0)) else 0   # 0x42DBD3 byte[0x56CCC8]（p4_enter 置 1）
        e.p["sub"] = self.p4_links.get(a3) if a3 in getattr(self, "p4_links", {}) else None

    def _p4_lock_rect(self, e, shrink: bool) -> bool:
        """`0x42F4B0(0x4012E4)`：准星矩形动画。arg≠0（按住）：rect 外扩 ±3 直到 l==0x60
        （锁定环），dst −(3,3)；arg==0（松开）：内收直到 l==0x90，dst +(3,3)。
        返回 1 = 已到目标尺寸。"""
        nd = e.node
        if nd is None:
            return False
        if shrink:
            if nd.rect[0] == 0x60:
                return True
            nd.rect = (nd.rect[0] - 3, nd.rect[1] - 3, nd.rect[2] + 3, nd.rect[3] + 3)
            nd.dst = (nd.dst[0] - 3, nd.dst[1] - 3)
            return False
        if nd.rect[0] == 0x90:
            return True
        nd.rect = (nd.rect[0] + 3, nd.rect[1] + 3, nd.rect[2] - 3, nd.rect[3] - 3)
        nd.dst = (nd.dst[0] + 3, nd.dst[1] + 3)
        return False

    def _p4_lock_detach(self, e) -> None:
        """0x42E4C3/0x42E5F0/0x42E781：松键或自机亡 → [0x24]=0、byte[0x10]=0（准星脱离）。
        [0x24] 是四个锁定行为（0x42E460 族）的**分支条件**（0x42E463 test [esi+0x24]），
        清零后下一帧走收缩支直至自灭；p["sub"] 是 [0x24] 的复刻侧解引用，一并清。"""
        e.d32(0x24, 0)
        e.p["sub"] = None
        if hasattr(e, "m"):
            e.m[0x10] = 0
        else:
            e.raw[0x10] = 0

    def _beh_42E460(self, e) -> bool:
        """`0x42E460`（撃/鼠标；v4=0x42EA70 同）：吸附指针 + 矩形动画；松键/父亡脱离。

        分支条件 = **[+0x24]（父指针字段）!= 0**（0x42E463 `test [esi+0x24]` / je 0x42E4D2
        收缩支）——脱离（0x42E4C3）清 [+0x24] 后下一帧走收缩至 l==0x90 自灭。
        旧实现误用 Python 侧 e.p["sub"] 当分支条件：脱离只清 raw[0x24] 不清 p["sub"]
        ⇒ 松键后永远走扩张支，展开的大"狙"字不消失（2026-11-14 用户实测）。"""
        sub = e.p.get("sub") if e.s32(0x24) else None   # 0x42E463
        if sub is not None:
            nd = e.node
            if nd is not None:
                px, py = self.p4_ptr()
                nd.dst = (nd.dst[0] + px - e.s32(4), nd.dst[1] + py - e.s32(8))
            e.d32(0x04, self.p4_ptr()[0] & 0xFFFFFFFF)
            e.d32(0x08, self.p4_ptr()[1] & 0xFFFFFFFF)
            self._p4_lock_rect(e, True)                     # 0x4012E4(1)
            if not getattr(self.inp.rec, "b1", 0) or not sub.alive:
                self._p4_lock_detach(e)                     # 0x42E4C3
            return True
        return not self._p4_lock_rect(e, False)             # 0x42E4D2：neg/sbb/inc —— 收缩中=1、收完=0 自灭

    def _beh_42E520(self, e) -> bool:
        """`0x42E520`（凛/鼠标；v5=0x42EB30 逐字节同）：自动索敌。0x43BD50 走
        0x4AD43C 队列，逐点门 = 存活(byte[+0x10], 0x43AD63) → 屏内 ±0x30
        （0x4305F0：x−0x30≤0x27F 且 x+0x30>0 且 y−0x30≤0x1DF 且 y+0x30>0）→
        可锁定(0x43AE60>0)；命中标志 = 任一点通过；best 初值 **(0x2710, 0)**
        （0x43BD58→0x45A690），L1 距准星自身坐标、严格更近才替换（0x43ADC8 jge）。
        速度 ebx = 11 + 3×(父[0x1C]&1)（0x42E568 neg/sbb/and/add），
        [0x4AB5A4]/[0x4AB5A8] 任一非 0 → sar 1；位移 inv=0x45AA80(Δ)（倒数 4096/|Δ|，
        单值），y += inv*Δy*spd>>12 → x += inv*Δx*spd>>12（0x42E595..0x42E5C6），
        节点 +0x14 同加 (Δx,Δy)（0x45A6B0）。无目标只做矩形动画。
        分支条件 = [+0x24] != 0（0x42E526 test / je 0x42E602 收缩支），同 0x42E460。"""
        sub = e.p.get("sub") if e.s32(0x24) else None   # 0x42E526
        if sub is None:
            return not self._p4_lock_rect(e, False)         # 0x42E602 → 0x4012E4(e,0)
        bx, by = 0x2710, 0                                  # 0x43BD56/58 初值 (0x2710, 0)
        found = False
        cx, cy = e.s32(4), e.s32(8)
        for t in self.p4_q43c:                              # [0x4AD43C+0x28] 链
            if not t.alive:                                 # 0x43AD63 byte[+0x10]
                continue
            tx, ty = t.s32(4), t.s32(8)
            if (tx - 0x30 > 0x27F or tx + 0x30 <= 0 or
                    ty - 0x30 > 0x1DF or ty + 0x30 <= 0):
                continue                                    # 0x4021E9→0x4305F0 屏内 ±0x30
            if self.p4_43ae60(t) == 0:                      # 0x40123A→0x43AE60
                continue
            found = True                                    # 0x43AD85 or bl,al
            if abs(tx - cx) + abs(ty - cy) < abs(bx - cx) + abs(by - cy):
                bx, by = tx, ty                             # 0x43ADCA jge：严格更近才换
        if found:
            sp = 11 + (3 if sub.g32(0x1C) & 1 else 0)       # 0x42E568..0x42E56F
            if self.p4_stat.get(0x4AB5A4, 0) or self.p4_stat.get(0x4AB5A8, 0):
                sp >>= 1                                    # 0x42E57F
            dx, dy = bx - cx, by - cy
            inv = self.p4_45aa80(dx, dy)                    # 0x40231F：倒数（单值）
            xd = (inv * dx * sp) >> 12
            yd = (inv * dy * sp) >> 12
            e.d32(8, (cy + yd) & 0xFFFFFFFF)                # 0x42E5B6 先 y
            e.d32(4, (cx + xd) & 0xFFFFFFFF)                # 0x42E5C6 后 x
            if e.node is not None:
                nd = e.node
                nd.dst = (nd.dst[0] + xd, nd.dst[1] + yd)   # 0x45A6B0(node+0x14, Δx, Δy)
        self._p4_lock_rect(e, True)                         # 0x42E5D8
        if not getattr(self.inp.rec, "b1", 0) or not sub.alive:
            self._p4_lock_detach(e)                         # 0x42E5F0
        return True

    def _beh_42E660(self, e) -> bool:
        """`0x42E660`（漢/鼠标；v6=0x42EC70 同）：绕自机横摆——pos=自机+[0x1C]，
        自机 0x48 邻域内有敌（0x401280）则 [0x1C] ±2 朝敌钳 ±0x30，否则衰减 ∓2；
        dst=(x−0x90, y−0x30)；矩形动画；父亡脱离（无松键门）。
        分支条件 = [+0x24] != 0（0x42E666 test / je 0x42E793 收缩支），同 0x42E460。"""
        sub = e.p.get("sub") if e.s32(0x24) else None   # 0x42E666
        if sub is None:
            return not self._p4_lock_rect(e, False)         # 0x42E793 → 0x4012E4(e,0)
        sx, sy = self.p4_stat.get(0x56CC8C, 0), self.p4_stat.get(0x56CC90, 0)
        off = e.s32(0x1C)
        # 0x42E671..0x42E6AC：瞄准点 x = px + min(px,0xC8) + 8（px>=0xC8 时取 0xC8），
        # 上限 0x280；y = py + [+0x1C]。旧实现直接写 px ⇒ 狙字贴在自机上、瞄点错位。
        cx = sx + (0xC8 if sx >= 0xC8 else sx) + 8
        if cx >= 0x280:
            cx = 0x280
        cy = sy + off
        e.d32(4, cx & 0xFFFFFFFF)
        e.d32(8, cy & 0xFFFFFFFF)
        # 0x42E6C0..0x42E6D2 → 0x43BD50：以瞄准点为原点找**最近的可锁定敌**
        # （0x43AD60 门：byte[+0x10]、0x4305F0(敌,0x30) 屏内、0x43AE60 可锁；
        #   距离 L1；初值 (0x2710,0)，严格更近才换）。旧实现取"第一个在 0x48 框内的"。
        bx, by = 0x2710, 0
        found = False
        for t in self.p4_q43c:                              # 0x4AD43C
            if not t.alive:                                 # 0x43AD66 byte[+0x10]
                continue
            tx, ty = t.s32(4), t.s32(8)
            if (tx - 0x30 > 0x27F or tx + 0x30 <= 0 or
                    ty - 0x30 > 0x1DF or ty + 0x30 <= 0):
                continue                                    # 0x4021E9→0x4305F0
            if self.p4_43ae60(t) == 0:                      # 0x40123A→0x43AE60
                continue
            found = True
            if abs(tx - cx) + abs(ty - cy) < abs(bx - cx) + abs(by - cy):
                bx, by = tx, ty                             # 0x43ADCA jge
        hit = False
        if found and abs(bx - cx) < 0x48 and abs(by - cy) < 0x48:
            hit = True
            # 0x42E708 cmp 敌y,描y ; jge ⇒ off += 2（向下追）；否则 off -= 2
            if by >= cy:
                off = 0x30 if off + 2 > 0x30 else off + 2
            else:
                off = -0x30 if off - 2 < -0x30 else off - 2
        if not hit and off != 0:
            off += -2 if off >= 0 else 2                    # 0x42E730 衰减
        e.d32(0x1C, off & 0xFFFFFFFF)
        if e.node is not None:
            nd = e.node
            nd.dst = (e.s32(4) - 0x90, e.s32(8) - 0x30)
        self._p4_lock_rect(e, True)                         # 0x42E771
        if sub is not None and not sub.alive:
            self._p4_lock_detach(e)                         # 0x42E781（无松键门）
        return True

    def _beh_42E810(self, e) -> bool:
        """`0x42E810`（选机3/鼠标；v7=0x42EE20 同）：螺旋收敛——[0x20] 计数，
        绕自机 r=200×(0x78−t)/0x78 角 40t 旋转（40159B cos/401A50 sin，8.8）；
        t≥0x5A → byte[0x10]=1（可碰撞）；松键/父亡 → [0x24]=0、[0x1C]=−(0x78−t)×5/60；
        脱离后 [0x1C] 每帧 −1，≤ −0x50 自灭。无矩形动画。
        分支条件 = [+0x24] != 0（0x42E816 test / je 0x42E959 甩出支），同 0x42E460；
        父存活只影响脱离判定（0x42E8F0 读 byte[父+0x34]），不影响分支。"""
        sub = e.p.get("sub") if e.s32(0x24) else None   # 0x42E816
        t = e.s32(0x20)
        if sub is not None:
            sx, sy = self.p4_stat.get(0x56CC8C, 0), self.p4_stat.get(0x56CC90, 0)
            r = 200 * (0x78 - t)
            ang = 40 * t
            dx = (page4_cos(ang) * r) >> 8
            dy = (page4_sin(ang) * r) >> 8
            e.d32(4, (sx + dx - 0x30) & 0xFFFFFFFF)
            e.d32(8, (sy + dy - 0x30) & 0xFFFFFFFF)
            if e.node is not None:
                e.node.dst = (e.s32(4) - 0x30, e.s32(8) - 0x30)
            if t >= 0x5A and e.s32(0x1C) == 0:
                if hasattr(e, "m"):
                    e.m[0x10] = 1
                else:
                    e.raw[0x10] = 1                         # 0x42E903
            if not getattr(self.inp.rec, "b1", 0) or not sub.alive:
                k = 0x78 - t
                k = k + 4 * k if k >= 0 else -(4 * -k + k)  # 0x42E91E ×5 向零
                e.d32(0x1C, ((-k * 0x99999999 >> 34) if False else (k // 60) * -1) & 0xFFFFFFFF)
                # 0x42E93D：-(0x78−t)*5 与 0x99999999 魔数除 60 ⇒ [0x1C] = −(0x78−t)/12
                e.d32(0x1C, (-(k // 12)) & 0xFFFFFFFF)
                self._p4_lock_detach(e)
        else:
            if e.s32(0x1C) > -0x50:
                sx, sy = self.p4_stat.get(0x56CC8C, 0), self.p4_stat.get(0x56CC90, 0)
                r = 200 * t
                ang = 40 * t
                dx = (page4_cos(ang) * r * -5) >> 8
                dy = (page4_sin(ang) * r * -5) >> 8
                e.d32(4, (sx + dx - 0x30) & 0xFFFFFFFF)
                e.d32(8, (sy + dy - 0x30) & 0xFFFFFFFF)
                if e.node is not None:
                    e.node.dst = (e.s32(4) - 0x30, e.s32(8) - 0x30)
            else:
                return False                                # 0x42E9DC 自灭
        e.d32(0x20, (t + 1) & 0xFFFFFFFF)                   # 0x42E9C9
        if e.s32(0x1C) != 0:
            e.d32(0x1C, (e.s32(0x1C) - 1) & 0xFFFFFFFF)
        return True

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
        e2 = self.fx12_spawn(type_word, owner.s32(0x04) + dx, owner.s32(0x08), v)
        if e2 is not None:
            self._p4_q("ui46c").append(e2)                 # 0x430290 → 0x4AD46C

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


    def _p4_4437e0(self, e, ebp: int, st: int) -> bool:
        """`0x4437E0`：状态 1..7 —— 每相位画血条刻度、放一次 UI，并按计时推进状态。

        ```
        ebp == 0：
          0x4437ED 0x43A320(0x4AD4CC)                      清 ui4cc
          0x4437F5 bl == 7 → 跳过血条
          0x4437FB edi = ((bl << 5) - 0x20) & 0xFFFF | 0x300000   ; y
          0x443801 ebx = 0x40 .. < 0x23F 步 0x20             ; x = ebx & 0xFFFF | 0x1AE0000
          0x44383E 0x430400(&rec, x, y, 0x4B000001, 0x200020) → 0x43A3C0(0x4AD4CC)
          0x44387B bl == 1 → 0x430400(&rec, 0x1F4, rand%0x12C+0x3C, 0x2B000001, 1) → ui4cc
          0x4438C9 bl == 2 → 0x430400(&rec, 0x1F4, rand%0x64 +0x12C, 0x2B000001, 2) → ui4cc
          0x44391A bl == 3 → (0x1F4, rand%0x64+0x12C) a3=3 → ui43c；再 (0, 同 y) a3=3 → ui43c
          0x4439B3 bl == 4 → (0xFA, rand%0x64+0xAA) a3=4 → ui43c；(0xFA, y-0x64) a3=5 → ui43c
          0x443A56 bl == 5 → (0x14, 0xC8) a3=6 → ui4cc
          0x443A96 bl == 6 → (0x190, 0xC8) a3=7 → ui4cc
        0x443B33 0x44F600(0x4AB514, 1, 0x10 + (bl == 7))    ; BGM 曲目
        ebp != 0：
          0x443B4D ebp == 0xFFFF → [esi+0x1C] = ([+0x1C]&0xF0000000) + 0xFFFE
        0x443B62 if (0x45AFF0(0x56CCC0, 0x20)) {
          0x443B7C if (ebp < 0xFFFF) {
            0x43BC40(0x4AD43C)                              清 ui43c
            bl==1 [+0x20]=ebp ; bl==2 [+0x20]=低16|(ebp<<16)
            bl==3 [+0x24]=ebp ; bl==4 [+0x24]=低16|(ebp<<16)
            bl==5 [+0x28]=ebp ; bl==6 [+0x28]=低16|(ebp<<16)
            bl==7 [+0x2C]=ebp
            0x443BF9 [esi+0x1C] = ([+0x1C]&0xF0000000) + 0x10000   计数清零、状态进一级
            0x443C10 0x44FDD0(0x4AB514)                      ; 停 BGM
          }
          0x443C15 if (0x45B030(0x56CCC0, 4)) [+0x1C] = ([+0x1C]+0x10000000) & 0xF0000000
        }
        0x443C35 if (0x45AFF0(0x56CCC0, 0x40)) { 0x44FDD0(0x4AB514) ; [+0x1C] = 0x90000000 }
        ```
        """
        q4 = self._p4_q("ui4cc")
        q3 = self._p4_q("ui43c")
        _clr = lambda _q: (getattr(_q, "clear", None) or (lambda: None))()

        if ebp == 0:                                       # 0x4437E2
            _clr(q4)                                       # 0x4437ED
            if st != 7:                                    # 0x4437F5
                _y = (((st << 5) - 0x20) & 0xFFFF) | 0x300000       # 0x4437FB..0x44380C
                _x = 0x40                                  # 0x443801
                while _x < 0x23F:                          # 0x44386B
                    self.spawn(q4, 0x4B000001, (_x & 0xFFFF) | 0x1AE0000, _y, 0x200020)
                    _x += 0x20
            if st == 1:                                    # 0x44387B
                self.spawn(q4, 0x2B000001, 0x1F4, rng.randrange(0x12C) + 0x3C, 1)
            elif st == 2:                                  # 0x4438C9
                self.spawn(q4, 0x2B000001, 0x1F4, rng.randrange(0x64) + 0x12C, 2)
            elif st == 3:                                  # 0x44391A
                _yy = rng.randrange(0x64) + 0x12C
                self.spawn(q3, 0x2B000001, 0x1F4, _yy, 3)
                self.spawn(q3, 0x2B000001, 0, _yy, 3)      # 0x443985 第二发 x=0
            elif st == 4:                                  # 0x4439B3
                _yy = rng.randrange(0x64) + 0xAA
                self.spawn(q3, 0x2B000001, 0xFA, _yy, 4)
                self.spawn(q3, 0x2B000001, 0xFA, _yy - 0x64, 5)
            elif st == 5:                                  # 0x443A56
                self.spawn(q4, 0x2B000001, 0x14, 0xC8, 6)
            elif st == 6:                                  # 0x443A96
                self.spawn(q4, 0x2B000001, 0x190, 0xC8, 7)
            elif st == 7:                                  # 0x443AD5（递归下降重切后已解）
                # 0x443ADA push 8 ; push 0x2B000001 ; 0x443AE1 rand()%0x1AC → y
                # 0x443AEF rand()%0x12C → x ; 0x443B05 0x430400(&rec, x, y, type, 8) → ui43c
                self.spawn(q3, 0x2B000001, rng.randrange(0x12C),
                           rng.randrange(0x1AC), 8)
            # 0x443B33
            if self.audio is not None:
                self.audio.bgm(0x10 + (1 if st == 7 else 0))
            return True

        if ebp == 0xFFFF:                                  # 0x443B4D
            e.d32(0x1C, (e.g32(0x1C) & 0xF0000000) + 0xFFFE)
        if self.p4_in_bits() & 0x20:                       # 0x443B62
            if ebp < 0xFFFF:                               # 0x443B7C
                _clr(q3)                                   # 0x43BC40
                if st == 1:                                # 0x443B8C
                    e.d32(0x20, ebp)
                elif st == 2:                              # 0x443B96
                    e.d32(0x20, (e.g32(0x20) & 0xFFFF) | (ebp << 16))
                elif st == 3:                              # 0x443BAE
                    e.d32(0x24, ebp)
                elif st == 4:                              # 0x443BB8
                    e.d32(0x24, (e.g32(0x24) & 0xFFFF) | (ebp << 16))
                elif st == 5:                              # 0x443BCF
                    e.d32(0x28, ebp)
                elif st == 6:                              # 0x443BD9
                    e.d32(0x28, (e.g32(0x28) & 0xFFFF) | (ebp << 16))
                elif st == 7:                              # 0x443BF1
                    e.d32(0x2C, ebp)
                e.d32(0x1C, (e.g32(0x1C) & 0xF0000000) + 0x10000)   # 0x443BF9
                if self.audio is not None:
                    self.audio.bgm_stop()                  # 0x443C10 0x44FDD0
            if not (self.p4_in_bits() & 4):                # 0x443C15
                e.d32(0x1C, ((e.g32(0x1C) + 0x10000000) & 0xF0000000))
        if self.p4_in_bits() & 0x40:                       # 0x443C35
            if self.audio is not None:
                self.audio.bgm_stop()                      # 0x44FDD0
            e.d32(0x1C, 0x90000000)                        # 0x443C53
        return True

    def _p4_443fdc(self, e, ebp: int) -> bool:
        """`0x443FDC`：状态 9 —— 终场清屏、放一块 UI、播 SE，300 帧后**回到状态 0**。

        ```
        ebp == 0：
          0x443FE5 0x43BC40(0x4AD43C)                  清 ui43c
          0x443FEF 0x4301F0(0x4AD46C)                  清 ui46c（thunk 0x4019AB）
          0x443FF9 0x43A320(0x4AD4CC)                  清 ui4cc
          0x443FFE 0x430400(&rec, 0xC000F0, 0x200000, 0x4B000001, 0x1000E0) → ui4cc
          0x444044 0x450350(0x4AB4B0, 1, 0)            波形槽 1
        ebp == 0x12C：0x444066 [esi+0x1C] = 0          ; 300 帧后整机复位
        ```
        """
        q3 = self._p4_q("ui43c")
        q4 = self._p4_q("ui4cc")
        q6 = self._p4_q("ui46c")
        if ebp == 0:                                       # 0x443FDE
            for _q in (q3, q6, q4):                        # 0x443FE5/0x443FEF/0x443FF9
                _c = getattr(_q, "clear", None)
                if _c is not None:
                    _c()
            self.spawn(q4, 0x4B000001, 0xC000F0, 0x200000, 0x1000E0)   # 0x44403F
            self.p4_se_pan(1, 0)                           # 0x44404C 0x450350(0x4AB4B0,1,0)
            return True
        if ebp == 0x12C:                                   # 0x44405E
            e.d32(0x1C, 0)                                 # 0x444066 回到状态 0
        return True

    def _p4_443c67(self, e, ebp: int) -> bool:
        """`0x443C67`：状态 8 —— 终场爆炸序列（全程按栈结构逐字还原）。

        结构在栈上拼（`0x443CB9..0x443DD0`，基址记作 esp0）：

        ```
        byte[0x18..0x1D] = 40 40 60 40 20 40      ; 第一组颜色索引
        byte[0x20..0x25] = 00 00 10 10 20 20      ; 第二组颜色索引
        byte[0x22] = byte[0x23] = 0x10            ; 与上面同址，后写覆盖
        word[0x28] = 0x50   word[0x2A] = 0x80     ; （push 后按 esp-8 写，等价 esp0）
        word[0x2C] = 0xB0   word[0x2E] = 0xE0
        word[0x30] = 0x110  word[0x32] = 0x140
        word[0x34] = 0xB0   word[0x36] = 0xF0
        word[0x38] = 0xE0   word[0x3A] = 0x140
        word[0x3C] = 0xE0   word[0x3E] = 0x100
        word[0x40] = 0x120  word[0x42] = 0x120
        word[0x44] = 0x110  word[0x46] = 0x120
        word[0x48] = 0x130  word[0x4A] = 0x130
        ```

        `k = ebp / 0x5A`（`0xB60B60B7 imul + sar 6` 那个magic）：

        ```
        a3 = (signed byte[0x18+k]) | 0x100000
        y  = (signed byte[0x20+k] << 16) | word[0x34+k*2]
        x  = (signed word[0x28+k*2] << 16) | word[0x40+k*2]
        0x430400(&rec, x, y, 0x4B000001, a3) → 0x43A3C0(0x4AD4CC)
        ```

        展开后 k=0..5 的六格（这就是 `0x4B000001` 那套 `(a<<16)|b` 坐标打包）：

        | k | a3 | y | x |
        |---|---|---|---|
        | 0 | 0x100040 | 0x00B0 | 0x500120 |
        | 1 | 0x100040 | 0x00F0 | 0x800120 |
        | 2 | 0x100060 | 0x1000E0 | 0xB00110 |
        | 3 | 0x100040 | 0x100140 | 0xE00120 |
        | 4 | 0x100020 | 0x2000E0 | 0x1100130 |
        | 5 | 0x100040 | 0x200100 | 0x1400130 |

        其余时间点：

        ```
        0x443C67 if (ebp == 0 || ebp == 0x21C) { 清 ui43c/ui46c/ui4cc/actorq }
        0x443DF9 if (ebp == 0x21C) {
                    (0x64003C, 0x1300000) 与 (0x64017C, 0x13000C0)，均 0x4B000003/a3=0xC000C0 → ui4cc
                    0x44F600(0x4AB514, 1, 0x12)        ; BGM 0x12
                 }
        0x443EA6 if (0x316 <= ebp <= 0xC16 && (ebp-0x316) % 0xC0 == 0) {
                    n = (ebp-0x316)/0xC0；n >= 0xB → n = 0xB + (n == 0xB)   ; 即 0xC
                    (0x1A80088, (n << 0x15) & 0xFFFF0000) 0x4B000003/a3=0x2001A0 → ui4cc
                 }
        0x443F44 ebp == 0xCD6 → 0x44FDD0(0x4AB514) 停 BGM
        0x443F63 ebp == 0xD30 → 0x450350(0x4AB4B0, 0, 0) 波形槽 0
        0x443F86 ebp > 0xE20 且 byte[0x4AB596]（btn0）→ [esi+0x1C] = 0；
                 若 0x45AFC0(0x4AB5B0, 0x70000) < 4 → 0x45B0E0(0x4AB5B0, 0x70000, 4)
        ```
        """
        q3 = self._p4_q("ui43c")
        q6 = self._p4_q("ui46c")
        q4 = self._p4_q("ui4cc")
        _clr = lambda _q: (getattr(_q, "clear", None) or (lambda: None))()

        if ebp in (0, 0x21C):                              # 0x443C67
            _clr(q3)                                       # 0x443C78
            _clr(q6)                                       # 0x443C82
            _clr(q4)                                       # 0x443C8C
            _aq = getattr(self, "actorq", None)            # 0x443C96 0x448F50
            if _aq is not None and hasattr(_aq, "clear"):
                _aq.clear()

        if ebp <= 0x1C2 and ebp % 0x5A == 0:               # 0x443C9B / 0x443CB1
            B = bytearray(0x60)                            # 0x443CB9..0x443DD0 的栈结构
            def _w(o, v):
                B[o] = v & 0xFF
                B[o + 1] = (v >> 8) & 0xFF
            _w(0x40, 0x120); _w(0x42, 0x120); _w(0x46, 0x120)
            _w(0x48, 0x130); _w(0x4A, 0x130)               # 0x443CC3..0x443CDC
            _w(0x2C, 0xB0); _w(0x2E, 0xE0)                 # 0x443CE6/0x443CEB
            _w(0x38, 0xE0); _w(0x3C, 0xE0)                 # 0x443CF0/0x443CF5
            B[0x22] = 0x10; B[0x23] = 0x10                 # 0x443CFC/0x443D00
            _w(0x34, 0xB0)                                 # 0x443D09
            _w(0x44, 0x110); _w(0x30, 0x110)               # 0x443D1C/0x443D24
            _w(0x32, 0x140); _w(0x3A, 0x140)               # 0x443D30/0x443D35
            B[0x18] = 0x40; B[0x19] = 0x40; B[0x1A] = 0x60  # 0x443D3A..0x443D44
            B[0x1B] = 0x40; B[0x1C] = 0x20; B[0x1D] = 0x40  # 0x443D49..0x443D53
            B[0x20] = 0; B[0x21] = 0                        # 0x443D58/0x443D68
            B[0x24] = 0x20; B[0x25] = 0x20                  # 0x443D6D/0x443D72
            _w(0x36, 0xF0)                                  # 0x443D82
            _w(0x3E, 0x100)                                 # 0x443D8C（push 后 esp-4+0x42）
            _w(0x28, 0x50); _w(0x2A, 0x80)                  # 0x443DA2/0x443DA9（esp-8+0x30/0x32）
            _k = ebp // 0x5A                               # 0x443D04 magic /0x5A
            _a3 = B[0x18 + _k] | 0x100000                  # 0x443D5D/0x443D7C
            _y = (B[0x20 + _k] << 16) | (B[0x34 + _k * 2] | (B[0x35 + _k * 2] << 8))
            _xw = B[0x28 + _k * 2] | (B[0x29 + _k * 2] << 8)
            _xl = B[0x40 + _k * 2] | (B[0x41 + _k * 2] << 8)
            _x = ((_xw & 0xFFFF) << 16) | _xl             # 0x443DB3..0x443DC7
            self.spawn(q4, 0x4B000001, _x, _y, _a3)        # 0x443DF0

        if ebp == 0x21C:                                   # 0x443DF9
            self.spawn(q4, 0x4B000003, 0x64003C, 0x1300000, 0xC000C0)    # 0x443E05..0x443E40
            self.spawn(q4, 0x4B000003, 0x64017C, 0x13000C0, 0xC000C0)    # 0x443E45..0x443E86
            if self.audio is not None:
                self.audio.bgm(0x12)                       # 0x443E94 0x44F600(0x4AB514,1,0x12)
            return True

        if 0x316 <= ebp <= 0xC16:                          # 0x443EA6/0x443EB2
            _c = ebp - 0x316
            if _c % 0xC0 == 0:                             # 0x443ECE
                _n = _c // 0xC0                            # 0x443ED2 magic /0xC0
                if _n >= 0xB:                              # 0x443EE3
                    _n = 0xB + (1 if _n == 0xB else 0)
                self.spawn(q4, 0x4B000003, 0x1A80088,
                           (_n << 0x15) & 0xFFFF0000, 0x2001A0)          # 0x443F3B

        if ebp == 0xCD6:                                   # 0x443F44
            if self.audio is not None:
                self.audio.bgm_stop()                      # 0x443F51 0x44FDD0
            return True
        if ebp == 0xD30:                                   # 0x443F63
            self.p4_se_pan(0, 0)                           # 0x443F74 0x450350(0x4AB4B0,0,0)
            return True
        if ebp > 0xE20 and self.p4_btn0_edge():            # 0x443F86
            e.d32(0x1C, 0)                                 # 0x443FA9
            _kb = self.keys.bits if getattr(self, "keys", None) is not None else 0
            if ((_kb >> 16) & 7) < 4:                      # 0x443FB5 0x45AFC0(0x4AB5B0,0x70000)
                if getattr(self, "keys", None) is not None:
                    self.keys.bits = (_kb & ~0x70000) | (4 << 16)   # 0x443FCA 0x45B0E0
        return True

    def p4_454950_init(self) -> None:
        """`0x454950`：页面机 `0x45952C` 调用的**阶段初始化**（在 `0x4505B0` 之后、首帧之前）。

        ```
        0x454953 [0x56CCA8] = 0                            帧计数复位
        0x454961 0x45AFC0(0x4AB5B8, 0x1FC0000) → *4-0xC8   → 0x44CDF0 的 arg3
        0x45497F 0x45AFC0(0x4AB5B8, 0xFE000000) → *4-0xC8  → 0x44CDF0 的 arg2
        0x454998 0x44CDF0(0x4AA7B0, 1, f(FE), f(1FC), 0)   RT_STRING 1 = bm_pal（基础调色板）
        0x4549A1 0x44C640(0x4AA7B0, 0, 0xF0) → al         层0 ← 资源 0xF0
        0x4549B6 0x44C640(0x4AA7B0, 1, 0xF1) → al         层1 ← 资源 0xF1
        0x4549CB 0x44CE60(0x4AA7B0, 0, 0) → al            层0 色键 0
        0x4549DD 0x44CE60(0x4AA7B0, 1, 0) → al            层1 色键 0
                 任一 al == 0 → 0x45AF30(0x4AB5C0, 2)     退页
        0x4549FB 0x44E620(0x4AB454, 0x17, 0, 0, 0)        指针预设 0x17、基址 (0,0)
        0x454A0D 0x44EDA0(0x4AB454, 0)                    Poll
        0x454A19 0x450140(0x4AB4B0, 0xB, 0x15) → al       波形槽 0x0B ← 资源 0x15
        0x454A2B 0x450140(0x4AB4B0, 0,   0x2A) → al       波形槽 0x00 ← 资源 0x2A
        0x454A3D 0x450140(0x4AB4B0, 1,   0x2B) → al       波形槽 0x01 ← 资源 0x2B
                 任一 al == 0 → 0x45AF30(0x4AB5C0, 8)
        0x454A5B 0x458D60(esi, 0, 0, 0, 0)                子系统 Reset
        0x454A6A 0x430400(&rec, 0, 0, 0x6B000001, 0)      开场状态机实体
        0x454A99 0x40201D(0x4AD52C, &rec)                 进 ui52c
        ```

        `0x44CDF0` 的定位（这轮查清）：`0x44CDF6 call 0x49033B` 取模块句柄 →
        `0x44CE0B call [0x5E7220]` = **LoadStringA(hInst, id, buf, 0x40)** → 得到文件名 →
        `0x44CE27 call 0x4018ED`（= `0x44CAA0`）按名字载调色板。所以参数是
        **(mgr, RT_STRING id, 亮度/对比两个调整值, 0)**，与 `0x45168E` 的 5 参调用同构。

        thunk：`0x4019C9`→`0x45AFC0`、`0x4010C3`→`0x44CDF0`、`0x4012DF`→`0x44C640`、
        `0x4012F3`→`0x44CE60`、`0x4019B0`→`0x44E620`、`0x401113`→`0x44EDA0`、
        `0x40127B`→`0x450140`。
        """
        self.p4_frames = 0                                   # 0x454953
        _w = self.p4_cfg_word()
        _br, _ct = self.p4_451630_adjust(_w) if _w else (0, 0)
        if not self.p4_load_palette(1, _ct, _br):            # 0x454998（id 1 = bm_pal）
            self.flags.set(2)
        _ok = True
        for _l, _id in ((0, 0xF0), (1, 0xF1)):               # 0x4549A1 / 0x4549B6
            # exe 顺序：0x4505B0 → 0x454950（此处绑 240/241）→ 首帧 VM 的 op 0x0B 再绑 7/8。
            # 复刻侧 `p4_enter` 把 VM 构造（连带 t=0 的 op 0x0B）一起做了，流解析**早于**这里，
            # 若此时再无条件绑 240/241 就会把脚本刚装好的 7/8 冲掉（实测就是这么错的）。
            # 等价做法：只在层还没被绑过时才绑 —— exe 里这两层此刻也是空的，净效果相同。
            _cur = getattr(self.layers.tab.get(_l), "bind_id", None)
            if _cur not in (None, 0, 5):
                continue
            if not self.layers.bind(_l, _id):
                _ok = False
                break
            self.layers.color_key(_l, 0)                     # 0x4549CB / 0x4549DD
        if not _ok:
            self.flags.set(2)                                # 0x4549EF 0x45AF30(0x4AB5C0,2)
        self.inp.set_preset(0x17)                            # 0x4549FB 0x44E620(...,0x17,0,0,0)
        self.inp.set_pos(0, 0)
        # 0x454A0D 0x44EDA0(0x4AB454,0) = Poll；复刻侧每帧由 run.py 在 advance() 前调
        # `inp.build()`（0x44EB60）重建记录，这里不重复轮询，只保留预设。
        _snd = True
        if self.audio is not None:
            for _slot, _res in ((0x0B, 0x15), (0x00, 0x2A), (0x01, 0x2B)):   # 0x454A19..0x454A46
                if not self.audio.load_wave(_slot, _res):
                    _snd = False
        if not _snd:
            self.flags.set(8)                                # 0x454A4F 0x45AF30(0x4AB5C0,8)
        # 0x454A6A：开场状态机实体进 **0x4AD52C**（ui52c），行为 = 0x4435C0（ctor 0x43D791）
        from geki import UiEntity as _Ui
        _intro = _Ui(type_word=0x6B000001)
        _intro.beh = _beh_6B000001
        self.ui52c.append(_intro)

    # 0x4355E0 跳表 [eax*4+0x437074]，type-0x42000001 覆盖 5 项
    P4_4CC_BEH = {
        0x42000001: 0x40209A,           # 0x43567C
        0x42000002: 0x401465,           # 0x4356E5
        0x42000003: 0x401497,           # 0x43571C
        0x42000004: 0x401C21,           # 0x43578A
        0x42000005: 0x401CE9,           # 0x4358B4
    }
    P4_4CC_GEO = {                      # (层, l, t, r, b)；只填已从反汇编读出来的
        0x42000001: (2, 0, 0, 0x17, 0x17),   # 0x4356A9 [edx]=2 + 0x4356AF rect(0,0,0x17,0x17)
    }

    def _p4_ent_into(self, queue: list, typ: int, x: int, y: int, a3: int = 0,
                     beh: int | None = None):
        """把字节模型 `Ent` 放进**任意**队列（`0x448FF0` 这类"进队列"入口的统一写法）。

        与 `_p4_ent43c` 的区别只是队列可指定：自机要进 **0x4AD40C**（`actorq`），不是 0x4AD43C。
        """
        e = Ent(x, y, typ, a3)
        if beh is not None:
            e.beh = beh
        else:
            _b = self.P4_4CC_BEH.get(typ & 0xFFFFFFFF)          # 0x4355E0 按类型给默认行为
            if _b is not None and _b in P4_BEH:
                e.beh = P4_BEH[_b]
                e.d32(0x40, _b)
            _g = self.P4_4CC_GEO.get(typ & 0xFFFFFFFF)
            if _g is not None:                             # 0x43567C 支：节点 层2 + 24×24
                e.node = DNode(_g[0], _g[1], _g[2])
                e.node.rect = (_g[1], _g[2], _g[3], _g[4])
                e.node.dst = (x, y)
                e.node.active = True
        if beh == 0x448C70:                               # 自机：ctor 在 0x445C00 的 0x44604E 支
            # 0x44605E [+0x40]=0x401E06 ; 0x446065 [+0xC]=0x10 ; 0x44606C byte[+0x10]=1
            # 0x446070 [+0x1C]=0 ; 0x446089 [+0x20]=rec[3]（命数） ; 0x44608C [+0x18]=1
            # 0x4460F9 0x45AF30(0x56CCC0, 1)  ★ 置 0x56CCC0 bit0（动画期标志）
            e.d32(0x0C, 0x10)
            e.m[0x10] = 1
            e.d32(0x1C, 0)
            e.d32(0x20, a3 & 0xFFFFFFFF)
            e.d32(0x18, 1)
            self.p4_in_set(self.p4_in_bits() | 1)         # 0x4460F9
            # 层号 = 0：节点 [+0]。依据：页4 进场 op0xB 层0 ← bmcm\bm_cm48.ggd
            # （240×528 自机图集），(0x80,0x50,0x9F,0x6F) 即自机精灵（0x446096）。
            e.node = DNode(0, 0x80, 0x50)
            e.node.active = True
            e.node.rect = (0x80, 0x50, 0x9F, 0x6F)        # 0x45A750 填的 4 个 word
            e.node.dst = (x + 0x40, y)                    # 0x4460BF +0x40 偏移
            e.node.active = True
        queue.append(e)
        return e

    def _p4_443606(self, e, ebp: int) -> bool:
        """`0x443606`：状态 0 —— 计数 0 时建三块 UI、0xF0 时等按键并生成自机。

        ```
        0x443606 if (ebp != 0) goto 0x44370A
        --- 计数 0 ---
        0x443613 0x43A320(0x4AD4CC)                    ; 清 ui4cc
        0x443618 0x430400(&rec, 0x500078, 0, 0x4B000001, 0x1000B0) → 0x43A3C0
        0x44365A 0x430400(&rec, 0x9600C8, 0xF00000, 0x4B000001, 0x4000E0) → 0x43A3C0
        0x4436A0 0x430400(&rec, 0xF00128, 0x100000, 0x4B000001, 0x1000E0) → 0x43A3C0
        0x4436E6 0x450350(0x4AB4B0, 0, 0)              ; 波形槽 0 停
        0x4436F3 0x45AF10(0x56CCC0, 0)                 ; 键位字清零
        --- 计数 != 0 ---
        0x44370A if (ebp != 0xF0) goto 0x4437B2
        0x443716 if (byte[0x4AB596]) { 0x43A320(0x4AD4CC) ;
                   0x448FF0(0x4AD40C, rec(0xC8,0xC8,0x0B000001,3)) ; return 1 }
        0x443779 if (byte[0x4AB597]) { 0x45AF30(0x4AB5C0, 0x200) ; return 1 }
        0x44379E [esi+0x1C] = 0xEF                     ; 计数退回 239 重试
        --- 0x4437B2 ---
        0x4437B2 if (ebp <= 0xF0) return 1
        0x4437B8 if (0x45B030(0x56CCC0, 1)) return 1   ; bit1 还置着 → 继续等
        0x4437CC [esi+0x1C] = 0x10000000               ; 进入状态 1
        ```
        """
        if ebp == 0:                                       # 0x443606/0x44360E
            q = self._p4_q("ui4cc")
            clear = getattr(q, "clear", None)
            if clear is not None:
                clear()                                    # 0x43A320
            for _x, _y, _a3 in ((0x500078, 0, 0x1000B0),
                                (0x9600C8, 0xF00000, 0x4000E0),
                                (0xF00128, 0x100000, 0x1000E0)):
                self.spawn(q, 0x4B000001, _x, _y, _a3)     # 0x43A3C0
            self.p4_se_pan(0, 0)                           # 0x450350(0x4AB4B0,0,0)
            self.p4_in_set(0)                              # 0x45AF10：键位字清零
            return True
        if ebp > 0xF0:                                     # 0x4437B2
            if self.p4_in_bits() & 1:                      # 0x45B030
                return True
            e.d32(0x1C, 0x10000000)                        # 0x4437CC
            return True
        if ebp != 0xF0:                                    # 0x44370A
            return True
        if self.p4_btn0_edge():                            # 0x443716
            q = self._p4_q("ui4cc")
            clear = getattr(q, "clear", None)
            if clear is not None:
                clear()                                    # 0x44371F
            # 自机的 ctor 把 `[+0x40]` 写成 thunk `0x401E06` → `0x448C70`（见 §10.3）
            self._p4_ent_into(self.actorq, 0x0B000001, 0xC8, 0xC8, 3,
                              beh=0x448C70)                            # 0x448FF0(0x4AD40C)
            return True
        if self.p4_btn1_edge():                            # 0x443779
            self.flags.set(0x200)
            return True
        e.d32(0x1C, 0xEF)                                  # 0x44379E
        return True

    def p4_43B020(self, e) -> int:
        """`0x43B020`：按 `[e+0x14] & 0xFF000000` 决定要生成哪种 `0x31` 族实体。

        ```
        0x43B023 hi = [ecx+0x14] & 0xFF000000
        0x43B028 hi == 0x25000000 → 0x31000006
        0x43B02F hi == 0x26000000 → 0x31000019
        0x43B036 eax = hi - 0x27000000 ; neg ; sbb eax,eax ; and al,0xF7 ; add eax,0x3100000A
        ```

        `neg/sbb` 那串读的是 **CF**：`hi == 0x27000000` 时 CF=1 → `eax = 0xF7` →
        `0xFFFFFFF7 + 0x3100000A = 0x31000001`；否则 `eax = 0` → `0x3100000A`。
        """
        hi = e.s32(0x14) & 0xFF000000
        if hi == 0x25000000:
            return 0x31000006
        if hi == 0x26000000:
            return 0x31000019
        return 0x31000001 if hi == 0x27000000 else 0x3100000A

    def p4_43af90(self, e, arg: int) -> int:
        """`0x43AF90`（thunk `0x401FB4`）：**带难度与生命值门控的速度值**。

        ```
        0x43AF91 if (arg == 0) arg = [e+0x58]
        0x43AF9D op = 0x45AFC0(0x4AB5B0, 0xC000)      ; 难度 bits14-15
        0x43AFAC if (op == 3) arg += arg             ; 最高难度翻倍
        0x43AFB3 life = (signed) word[0x56CCB0]
        0x43AFBE if (arg < 0) return life - arg      ; 负数=不消耗
        0x43AFC7 r = 0x401393() % 0x500              ; rand() % 1280
        0x43AFDB if (r < life + arg - 0x100) return life + arg
        0x43AFEE return 0
        ```

        ⇒ 生命值低到 `life + arg <= 0x100` 时直接返回 0（**不发弹**）。
        """
        if arg == 0:
            arg = e.s32(0x58)
        if self.keys.field(0xC000) == 3:                 # 0x43AFAC
            arg *= 2
        life = self.p4_stat.get(0x56CCB0, 0) & 0xFFFF
        if life & 0x8000:
            life -= 0x10000
        if arg < 0:                                      # 0x43AFBE
            return life - arg
        if rng.randrange(0x500) < life + arg - 0x100:    # 0x43AFDB
            return life + arg
        return 0

    @staticmethod
    def _p4_div3(v: int) -> int:
        """`0x55555556 imul` + `shr 31` 的**有符号除以 3**（向零截断）。"""
        v &= 0xFFFFFFFF
        v = v - 0x100000000 if v & 0x80000000 else v
        return -((-v) // 3) if v < 0 else v // 3

    def p4_43B150(self, e, arg: int) -> None:
        """`0x43B150`：**双发对称斜向弹**（`0x43B070` 的"旋回"版），进 ui49c。

        ```
        0x43B15E 0x40113B(&vec, e)              ; = 0x43B020，借栈传址取类型
        0x43B171 0x430400(&rec, [e+4], [e+8], type)
        0x43B19B [esp+0x10] = 1                 ; 计数 = 1 ⇒ 循环跑 n=1,0 两遍
        0x43B1AE dx = [0x56CC8C] - [e+4] ; 0x43B1B0 dy = [0x56CC90] - [e+8]
        循环体 0x43B1C4:
          n != 0 → ebx = 2*dy - dx ; edi = dy + 2*dx
          n == 0 → edi = 2*dx - dy ; ebx = dx + 2*dy
          0x43B1E5 spd = 0x401FB4(e, arg) >> 4
          0x43B1F1 inv = 0x45AA80(edi, ebx)
          0x43B1FB vx = (inv*spd*edi) >> 8
          0x43B1FE vy = (inv*spd*ebx) >> 8
          0x43B215 若 vx==0 && vy==0 跳过
          0x43B22B 0x435440(0x4AD49C, &rec)     ; 速度对作为 a3（栈残留）
        0x43B230 n-- ; n >= 0 则继续
        ```

        `(2dy-dx, dy+2dx)` 与 `(2dx-dy, dx+2dy)` 是把 `(dx,dy)` 旋转约 ±63.4°（`tan⁻¹2`），
        所以两发呈**对称的 V 形夹角**，而不是直线对射。
        """
        typ = self.p4_43B020(e)                           # 0x43B15E
        px, py = self.p4_player_x(), self.p4_player_y()
        dx = px - e.s32(0x04)                             # 0x43B1AE
        dy = py - e.s32(0x08)                             # 0x43B1B0
        for n in (1, 0):                                  # 0x43B19B = 1 ⇒ 两遍
            if n:
                ebx = 2 * dy - dx                         # 0x43B1CC/0x43B1D2
                edi = dy + 2 * dx                         # 0x43B1CF
            else:
                edi = 2 * dx - dy                         # 0x43B1D6/0x43B1DC
                ebx = dx + 2 * dy                         # 0x43B1D9
            spd = self.p4_43af90(e, arg) >> 4             # 0x43B1E5/0x43B1EE
            inv = self.p4_45aa80(edi, ebx)                # 0x43B1F1
            vx = ((inv * spd) * edi) >> 8                 # 0x43B1FB
            vy = ((inv * spd) * ebx) >> 8                 # 0x43B1FE
            if vx == 0 and vy == 0:                       # 0x43B215
                continue
            eb2 = self.spawn(self._p4_q("ui49c"), typ,
                             e.s32(0x04), e.s32(0x08), (vx, vy))
            if eb2 is not None:
                eb2.raw[0x10] = 1
                eb2.d32(0x14, typ & 0xFFFFFFFF)
                eb2.d32(0x04, e.s32(0x04) & 0xFFFFFFFF)
                eb2.d32(0x08, e.s32(0x08) & 0xFFFFFFFF)
                eb2.d32(0x0C, 0x18)
                self._p4_q("ui49c").append(eb2)            # 0x435440: 显式入队   # 0x43B22B

    def p4_43B070(self, e, arg: int) -> None:
        """`0x43B070`：朝玩家生成一枚 `0x31` 族实体进 **0x4AD49C**。

        ```
        0x43B078 esi = [0x56CC8C] - [e+4]        ; dx = 玩家x - 自身x
        0x43B082 edi = [0x56CC90] - [e+8]        ; dy = 玩家y - 自身y
        0x43B093 ebx = 0x401FB4(e, arg) >> 4     ; 速度/16
        0x43B0A0 ecx = 0x40231F(dx, dy)          ; = 0x45AA80 倒数距离 4096/|d|
        0x43B0B3 [esp+0x10] = (inv*dx*ebx) >> 8  ; vy？见下
        0x43B0BD [esp+0x14] = (inv*dy*ebx) >> 8
        0x43B0C0 if (两者都为 0) 直接返回
        0x43B0D0 把 &{vx,vy} 压栈 → 成为 0x430400 的栈残留（即 a3）
        0x43B0E6 0x430400(&rec, [e+4], [e+8], 0x43B020(e))
        0x43B105 0x435440(0x4AD49C, &rec)
        ```

        ⇒ 速度 = `(4096/|d|) * 分量 * (speed/16) >> 8`，即**朝玩家的定长向量**
        （`4096/|d| * dx` 归一化后乘速度）。两个分量为 0 时不发（避免零速弹）。
        """
        px, py = self.p4_player_x(), self.p4_player_y()   # 0x56CC8C / 0x56CC90
        dx = px - e.s32(0x04)
        dy = py - e.s32(0x08)
        spd = self.p4_43af90(e, arg) >> 4                 # 0x43B09D sar 4
        inv = self.p4_45aa80(dx, dy)                      # 0x40231F → 0x45AA80
        vx = ((inv * dx) * spd) >> 8                      # 0x43B0B3
        vy = ((inv * dy) * spd) >> 8                      # 0x43B0BD
        if vx == 0 and vy == 0:                           # 0x43B0C0
            return
        eb = self.spawn(self._p4_q("ui49c"), self.p4_43B020(e),
                        e.s32(0x04), e.s32(0x08), (vx, vy))     # 0x43B105 → 0x435440
        if eb is not None:
            eb.raw[0x10] = 1                           # 0x4306C0 碰撞参与位
            eb.d32(0x14, self.p4_43B020(e) & 0xFFFFFFFF)  # 基础 ctor [+0x14]=类型
            eb.d32(0x04, e.s32(0x04) & 0xFFFFFFFF)         # [+0x04] = x
            eb.d32(0x08, e.s32(0x08) & 0xFFFFFFFF)         # [+0x08] = y
            eb.d32(0x0C, 0x18)                             # [+0x0C] = 半径 24
            self._p4_q("ui49c").append(eb)                 # 0x435440: 显式入队 0x4AD49C

    def _p4_43b_spawn(self, e, typ: int, tx: int, ty: int, arg: int) -> None:
        """`0x43B610`（0x401997）/`0x43B360`（0x401E56）共用体：**朝指定点**生成一枚
        0x31 族弹进 0x4AD49C（0x401861→0x435440）。速度公式与 0x43B070 相同：
        `(4096/|d|)*分量*(0x43AF90(e,arg)>>4)>>8`；两分量全 0 不发。
        两者唯一差异是弹型选择器：0x43B610 用 `0x43B5E0`（0x25→0x31000008、
        否则 0x31000003），0x43B360 用 `0x43B020`（0x25→0x31000006、0x26→0x31000019、
        0x27→0x31000001、否则 0x3100000A）。"""
        dx = tx - e.s32(0x04)
        dy = ty - e.s32(0x08)
        spd = self.p4_43af90(e, arg) >> 4                 # 0x43B639 sar 4
        inv = self.p4_45aa80(dx, dy)                      # 0x40231F → 0x45AA80
        vx = ((inv * dx) * spd) >> 8                      # 0x43B64F sar 8
        vy = ((inv * dy) * spd) >> 8
        if vx == 0 and vy == 0:
            return
        eb = self.spawn(self._p4_q("ui49c"), typ, e.s32(0x04), e.s32(0x08), (vx, vy))
        if eb is not None:
            eb.raw[0x10] = 1                              # 0x4306C0 碰撞参与位
            eb.d32(0x14, typ & 0xFFFFFFFF)
            eb.d32(0x04, e.s32(0x04) & 0xFFFFFFFF)
            eb.d32(0x08, e.s32(0x08) & 0xFFFFFFFF)
            eb.d32(0x0C, 0x18)                            # 半径 24
            self._p4_q("ui49c").append(eb)

    def p4_43B610(self, e, tx: int, ty: int, arg: int) -> None:
        """`0x43B610`（thunk 0x401997）：定点瞄准弹，弹型 0x43B5E0。"""
        hi = e.s32(0x14) & 0xFF000000
        typ = 0x31000008 if hi == 0x25000000 else 0x31000003   # 0x43B5E0
        self._p4_43b_spawn(e, typ, tx, ty, arg)

    def p4_43B360(self, e, tx: int, ty: int, arg: int) -> None:
        """`0x43B360`（thunk 0x401E56）：定点瞄准弹，弹型 0x43B020。"""
        self._p4_43b_spawn(e, self.p4_43B020(e), tx, ty, arg)

    @staticmethod
    def p4_45a9a0(dx: int, dy: int) -> int:
        """`0x45A9A0`（0x401091）：角度表查询——0x45A9A0 附近为 atan2 系
        （0x41A8D5 调用点把 (Δx,Δy) 映成 0..0x6BF 角）。复刻按 0x45ABB0 系同构
        处理：|Δ| 归一后查 p4_sin_q 的角度象限。"""
        import math
        a = int(math.degrees(math.atan2(dy, dx)) * 10) % 3600
        return a

    def p4_43B430(self, e, dx: int, dy: int, spdarg: int) -> None:
        """`0x43B430`（thunk 0x402144）：定向速度弹（同 0x43B290 族，
        0x43B43D 0x43AF90(e,arg1) 表速、(arg2,arg3)=方向、0x430400 后入 0x4AD49C）。"""
        spd = self.p4_43af90(e, spdarg) >> 4
        inv = self.p4_45aa80(dx, dy)
        vx = ((inv * dx) * spd) >> 8
        vy = ((inv * dy) * spd) >> 8
        if vx == 0 and vy == 0:
            return
        typ = self.p4_43B020(e)
        eb = self.spawn(self._p4_q("ui49c"), typ, e.s32(0x04), e.s32(0x08), (vx, vy))
        if eb is not None:
            eb.raw[0x10] = 1
            eb.d32(0x14, typ & 0xFFFFFFFF)
            eb.d32(0x04, e.s32(0x04) & 0xFFFFFFFF)
            eb.d32(0x08, e.s32(0x08) & 0xFFFFFFFF)
            eb.d32(0x0C, 0x18)
            self._p4_q("ui49c").append(eb)

    def p4_43B500(self, e, x0: int, y0: int, x1: int, y1: int, spdarg: int) -> None:
        """`0x43B500`（thunk 0x40182F）：**A→B 定向弹**——方向 = (x1−x0, y1−y0)、
        速度 = 0x43AF90(e,spdarg)>>4，出射点 = 实体自身（0x43B55A 后 0x430400
        用 [e+4]/[e+8]）。入 0x4AD49C。"""
        dx = x1 - x0
        dy = y1 - y0
        spd = self.p4_43af90(e, spdarg) >> 4
        inv = self.p4_45aa80(dx, dy)
        vx = ((inv * dx) * spd) >> 8
        vy = ((inv * dy) * spd) >> 8
        if vx == 0 and vy == 0:
            return
        typ = self.p4_43B020(e)
        eb = self.spawn(self._p4_q("ui49c"), typ, e.s32(0x04), e.s32(0x08), (vx, vy))
        if eb is not None:
            eb.raw[0x10] = 1
            eb.d32(0x14, typ & 0xFFFFFFFF)
            eb.d32(0x04, e.s32(0x04) & 0xFFFFFFFF)
            eb.d32(0x08, e.s32(0x08) & 0xFFFFFFFF)
            eb.d32(0x0C, 0x18)
            self._p4_q("ui49c").append(eb)

    def p4_401244(self, e) -> None:
        """`0x413030`（thunk 0x401244）：**绕主圆轨步进** —— ang = (主.[0x20] −
        13*[0x20])*45；x = 主.x + (45*sin(ang)+0x7F)>>8；
        y = 主.y + (0x78±0x10 的 sin(ang)*…)>>8（[主 0x24]==0 → 0x78−0x10）。"""
        main = getattr(self, "p4_links", {}).get(e.s32(0x1C) & 0x7FFFFFFF)
        if main is None:
            return
        v20 = e.s32(0x20)
        ang = ((main.s32(0x20) - 13 * v20) * 45) & 0xFFFFFFFF
        s_ = page4_sin(ang)
        c = page4_cos(ang)
        base = 0x78 + (-0x10 if main.s32(0x24) == 0 else 0)
        e.d32(0x04, (main.s32(0x04) + ((45 * s_ + 0x7F) >> 8)) & 0xFFFFFFFF)
        e.d32(0x08, (main.s32(0x08) + ((c * base + 0x7F) >> 8)) & 0xFFFFFFFF)

    def p4_40203b(self, slot: int, target: int, step: int) -> None:
        """`0x44DC10`（thunk 0x40203B）：BGM 音量滑槽 —— [slot+0xC94]=target、
        [slot+0xC98]=step、[slot+0xC8C]|=1（启动）。复刻记入 p4_other["bgmslide"]。"""
        self.p4_other.setdefault("bgmslide", []).append((target, step))

    def p4_417880(self, e, arg: int = 0) -> None:
        """`0x417880`（0x40234C）：轮次门控护卫生成；arg 决定纵向基准。

        ```
        0x417885 cl=[e+0x30]；cl<2 → 不发
        0x417891 edx=(0x1000>>cl)−1；[e+0x1C]&edx != 0 → 不发
        0x4178A0 x=(cl&1)?−0x18:0x298
        0x4178B2 y=(cl&1)? 0x190−0xA0*arg : 0x50+0xA0*arg
        0x430400(&rec,x,y,0x2700000B,0) → 0x401FA5(0x4AD43C,&rec)
        ```"""
        cl = e.s32(0x30)
        if cl < 2:
            return
        if e.s32(0x1C) & ((0x1000 >> (cl & 0x1F)) - 1):
            return
        if cl & 1:
            x = -0x18
            y = (0x190 - 0xA0 * arg) & 0xFFFFFFFF
        else:
            x = 0x298
            y = (0x50 + 0xA0 * arg) & 0xFFFFFFFF
        self._p4_ent43c(0x2700000B, x, y)

    def p4_4177f0(self, e, x: int, y: int) -> None:
        """`0x4177F0`（0x401717）：发 **0x5100000A** 入 0x4AD4FC（ui4fc）。

        `[e+0x30]&1`（轮次奇偶）→ 位置镜像 (0x280−x, 0x1E0−y)。
        `0x430400(&rec, x, y, 0x5100000A, 0)` → `0x44B140(0x4AD4FC,&rec)`。"""
        if e.s32(0x30) & 1:
            x = 0x280 - x
            y = 0x1E0 - y
        self.spawn(self._p4_q("ui4fc"), 0x5100000A, x, y, 0)

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
        0x451B6F 0x44ECC0(0x4AB454, 0x4AB594)        ; **键盘轮询**（不是 0x44EB60）：
                 GetDeviceState(0x100,&buf) → Acquire → 按 DIK 表 [0x498A60] 扫描，
                 只在 `bl != byte[0x4AB570+0x1F]`（与上帧不同）时把键码写 `arg+6`
                 = **`[0x4AB59A]`**；ESC(0x1B) 特判同样写入。
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
            # 0x451B6F 0x44ECC0：轮询键盘，按下沿的键码写进 [0x4AB59A]（arg+6）。
            # 复刻侧的输入层（run.py → inp.build）已经做了同一次边沿检测，
            # 结果就是 `inp.rec.key`；这里把它落到同一个全局地址上再交给 0x458FD0。
            self.p4_stat[0x4AB59A] = self.inp.rec.key        # 0x44ED4D byte[ecx+6]=al
            self.key_command(self.p4_stat[0x4AB59A])         # 0x451B97 0x458FD0(this,dl)
            if self.flags.bits == 0 and getattr(self, "p4_ab59a", 0) != 2:
                continue                                     # 0x451BA8 仍在暂停
            self.p4_load_palette(1)                          # 0x451BF0 恢复亮版
            return
        self.log("page4.pause（0x451B10）：无头模式下限次退出")

    def btn0_edge(self) -> bool:
        """`[0x4AB596]`：输入记录 +2 的 btn0 按下沿。"""
        return bool(getattr(self.inp.rec, "e0", 0)) if self.inp.rec else False

    # `0x447DA0`：`0x447640` 里 **状态 0x8000** 的子状态字节表（15 项，取值 0..3）。
    # 下标 = `[+0x20] & 0xF`；值 = 跳表 `0x447D90` 的索引。该跳表**只有 4 项**（0..3）；
    # 紧随其后的 4..7 项是别的数据（0x3030300/0x3030303/0x3010301/0x90020302），
    # 8..14 项才是 0xCCCCCCCC 填充 —— 说明原作者只用 0..3。
    P4_447DA0 = (0, 3, 3, 3, 3, 3, 3, 3, 1, 3, 1, 3, 2, 3, 2)
    # `0x447D90`：4 项跳表
    P4_447D90 = (0x447A2F, 0x447A86, 0x447A91, 0x447C2D)

    # `0x447640` 的状态表：state → (阈值, 状态增量, 帧掩码, 本帧 rect 增量)
    #   阈值 = `cmp dword[eax], IMM` 里 `eax = [+0x38]+4` 处的比较值（显示矩形宽度）
    #   帧掩码 = `test bl, MASK`（3 ⇒ 每 4 帧动一次，7 ⇒ 每 8 帧）
    #   rect 增量 = `0x45A790(node+4, ±v, 0, ±v, 0)` 的 ±v；None 表示该状态不走这条
    P4_447640_STATES = {
        0x1000: (0x180, +0x1000, 3, +0x30),      # 0x4478FF 长到 0x180 → 0x2000
        0x2000: (0x000, -0x1000, 3, -0x30),      # 0x4478D4 缩到 0 → 回 0x1000
        0x3000: (0x120, +0x1000, None, None),    # 0x4478A6 长到 0x120 → 0x4000（走 0x4478BD）
        0x4000: (0x000, -0x1000, 3, -0x30),      # 0x44792D 缩到 0 → 回 0x3000
        0x5000: (0x000, -0x5000, 7, -0x30),      # 0x44796F 用 **[+8]**，到 0 → 状态 0x0000
        0x7000: (0x150, None, 7, -0x60),         # 0x44799C 宽 ==0x150 → 收缩 0x60，否则走 0x447A06
        0x9000: (0x0F0, +0x1000, 3, +0x30),      # 0x4479E4 长到 0x0F0 → 0xA000
        0xA000: (0x000, -0x1000, 3, -0x30),      # 0x447AA5 缩到 0 → 回 0x9000
    }

    @classmethod
    def p4_447640_state(cls, state: int):
        """`0x447640` 状态机：取 `state & 0xF000` 对应的 `(阈值, 状态增量, 帧掩码, rect 增量)`。

        分派阶梯（`0x447863` 起，`eax = [+0x28] & 0xF000`）：

        ```
        0x44786B cmp 0x7000 ; jg 0x4479C1      ; >0x7000：0x8000/0x9000/0xA000/0xB000/0xC000
        0x447876 je 0x44799C   ; 0x7000
        0x44787C cmp 0x4000 ; jg 0x447958      ; 0x5000/0x6000
        0x447887 je 0x44792D   ; 0x4000
        0x44788D je 0x4478FF   ; 0x1000
        0x447894 je 0x4478D4   ; 0x2000
        0x44789B cmp 0x3000 ; jne 0x447C2D     ; 0x3000，其它 → 公共尾
        ```

        **成对结构**：每个「长」状态配一个「缩」状态，长到阈值就切换、缩到 0 就切回：

        | 对 | 阈值 | 步进 |
        |---|---|---|
        | `0x1000` ↔ `0x2000` | 0x180 (384) | 0x30 (48) |
        | `0x3000` ↔ `0x4000` | 0x120 (288) | 0x30 |
        | `0x9000` ↔ `0xA000` | 0x0F0 (240) | 0x30 |
        | `0x7000` | 0x150 (336) | 0x60 (96) |

        且「长」状态每 **4** 帧动一次、`0x5000`/`0x7000` 每 **8** 帧动一次（`test bl,3` vs `test bl,7`）。
        返回 `None` 表示该值不在表里（按 `0x447C2D` 直接进公共尾）。
        """
        return cls.P4_447640_STATES.get(state & 0xF000)

    @staticmethod
    def p4_45aa80(a: int, b: int) -> int:
        """`0x45AA80`：**倒数距离** `4096 / hypot(a, b)`（截断取整），不是 atan2。

        ```
        0x45AA88 if (a == 0 && b == 0) return 0x7FFFFFFF
        0x45AA98 eax = a*a + b*b                 ; 32 位有符号相乘，会回绕
        0x45AAA2 cl = 0
        0x45AAA9 while (eax >= 0x10000) { eax >>= 2 ; cl++ }   ; 算术右移 2
        0x45AAB6 eax = word[0x593AB4 + eax*2]    ; 倒数平方根表（见 `_p4_rsqrt`）
        0x45AAC0 eax >>= cl                      ; 补回 >>2 的倍数
        0x45AAC6 if (eax == 0) eax = 1
        ```

        表项 `word[i] = (int)(4096/sqrt(i))`，所以结果 ≈ `4096 / |(a,b)|`。
        调用方拿它做**归一化系数**：`0x40E9DF` 用它算出固定速度的追踪向量。
        """
        if a == 0 and b == 0:
            return 0x7FFFFFFF
        s = (a * a + b * b) & 0xFFFFFFFF                # 0x45AA98 32 位回绕
        s = s - 0x100000000 if s & 0x80000000 else s
        cl = 0
        while s >= 0x10000:                             # 0x45AAA2
            s >>= 2                                     # 0x45AAA9（sar）
            cl += 1
        v = (_p4_rsqrt(s) >> cl) if s > 0 else 0        # 0x45AAB6/0x45AAC0
        return v if v else 1                            # 0x45AAC6

    @staticmethod
    def p4_4305f0(e, r: int) -> int:
        """`0x4305F0(ent, r)`：**带半径的在屏判据**，返回 1/0。

        ```
        0x4305F0 edx = [ecx+4]
        0x4305FA if (edx - r > 0x27F) return 0     ; x-r 超过 639
        0x430607 if (edx + r <= 0)    return 0     ; x+r 不 > 0
        0x43060B ecx = [ecx+8]
        0x430610 if (ecx - r > 0x1DF) return 0     ; y-r 超过 479
        0x43061C if (ecx + r <= 0)    return 0     ; y+r 不 > 0
        0x430620 return 1
        ```

        即 `(x-r <= 639) && (x+r > 0) && (y-r <= 479) && (y+r > 0)`。
        """
        x = e.s32(0x04)
        y = e.s32(0x08)
        if x - r > 0x27F or x + r <= 0:
            return 0
        if y - r > 0x1DF or y + r <= 0:
            return 0
        return 1

    @staticmethod
    def p4_447c2d_angle(counter: int) -> int:
        """`0x447C2D` 公共尾：**环绕角的计算**。

        ```
        0x447C2D eax = [+0x20]
        0x447C30 and eax, 0x1F
        0x447C33 lea esi, [eax*8]      ; ×8
        0x447C3A sub esi, eax          ; ×7
        0x447C3C shl esi, 4            ; ×112
        0x447C3F add esi, eax          ; ×113
        0x447C41 push esi ; 0x447C42 0x45ABB0(esi)   ; 三角函数 1
        0x447C42..0x447C5C eax*([+0xC]>>1)          ; 乘「半径/2」
        0x447C55 0x45AAF0(esi)                       ; 三角函数 2
        ```

        ⇒ `angle = ([+0x20] & 0x1F) * 113`。**113 × 32 ≈ 3616 ≈ 3600**，
        即**每 32 帧绕一整圈**。

        `0x45ABB0` / `0x45AAF0` 内部先做 `|a| % 0x384`（=900，四分之一圈的刻度），
        说明三角函数以 3600 为整圈、900 为一象限。
        """
        return (counter & 0x1F) * 113

    @classmethod
    def p4_447a12_sub(cls, counter: int):
        """`0x447A12`：**状态 `0x8000` 的子分派**。

        ```
        0x447A12 eax = ebx (= [+0x20]，每帧自增的计数器)
        0x447A14 and eax, 0xF ; 0x447A17 cmp eax, 0xE ; ja 0x447C2D   ; 低 4 位 0..14
        0x447A22 cl = byte[0x447DA0 + eax]
        0x447A28 jmp dword[0x447D90 + (cl & 0xFF)*4]
        ```

        子状态语义（跳表 4 项）：
        - `0`（`0x447A2F`）：`0x462D71(node+8, 0x90)` 算出 edx；`edx < 0x60` 时循环
          `0x45A790(node+4, 0, 0x30, 0, 0x30)` —— **把显示矩形每次放大 0x30/边，直到 ≥ 0x60**。
        - `1`（`0x447A86`）：`push -0x30,0,-0x30` → `0x447C1C` —— **收缩 0x30/边**。
        - `2`（`0x447A91`）：`0x45A790(node+4, 0, 0x30, 0, 0x30)` —— **放大 0x30/边**。
        - `3`（`0x447C2D`）：公共出口（本帧不动）。

        表本身（`0x447DA0`，15 项）：

        ```
        下标  0  1  2  3  4  5  6  7  8  9 10 11 12 13 14
        值    0  3  3  3  3  3  3  3  1  3  1  3  2  3  2
        ```

        ⇒ 第 0 帧「放大到 0x60」，第 8/10 帧「收缩」，第 12/14 帧「放大」，其余帧不动。
        返回 `None` 表示 `[+0x20]&0xF > 0xE`（直接走公共出口）。
        """
        i = counter & 0xF
        if i > 0xE:
            return None
        return cls.P4_447DA0[i]

    @staticmethod
    def p4_43c344_player_hit(v30: int, v20: int, atk_type: int, v28: int) -> str:
        """`0x43C170` 的 **type==1（自机）** 分支 `0x43C344`：自机被弹判定。

        ```
        0x43C344 eax = [e+0x30] ; cmp eax,0 ; jne 0x43C3A5   ; +0x30 非 0 → 免疫
        0x43C34D cmp [e+0x20], 0x12C ; jle 0x43C3A5          ; **有符号** <= 300 → 免疫
        0x43C356 eax = 攻击者[+0x14]（type）
        0x43C360 cmp eax, 0x27000011 ; je 免疫
        0x43C367 cmp eax, 0x29000013 ; je 免疫
        0x43C36E cmp [e+0x28], 3 ; jne 0x43C38B
        0x43C374 [e+0x28]=0 ; [e+0x20]=0x79 ; ret          ; 特殊：不死，只重置
        0x43C38B 0x460C00(0x4CD590)                          ; 死亡链
        0x43C39A 0x45F570(0x4CD4A0)                          ; 计分/结果
        0x43C39F byte[e+0x10]=0 ; 0x43C3A2 [e+0x18]=0        ; alive=0 / HP=0
        ```

        ⇒ 免疫条件：`[+0x30] != 0`（无敌/状态计数器，非 0 即免打）
        或 `[+0x20] <= 0x12C`（**有符号比较**，所以 `-1` 也算免疫）。
        攻击者 type 为 `0x27000011` / `0x29000013` 时不致死。
        `[+0x28] == 3` 走**不死分支**：`[+0x28]=0`、`[+0x20]=0x79`，直接返回。

        返回 `'immune' | 'special' | 'dead'`。
        """
        if v30 != 0:
            return "immune"
        if v20 <= 0x12C:            # 有符号；-1 → 免疫
            return "immune"
        if atk_type in (0x27000011, 0x29000013):
            return "immune"
        if v28 == 3:
            return "special"
        return "dead"

    # 0x498A88 输入预设表，**stride 14 字节**（3 dword + 1 word），**24 项（kind 0..23）**；
    # kind 24 起全 0（表尾）。0x446470 只产出 7..22，是这 24 项的子集。
    P4_INPUT_PRESET = (
        (0x01000101, 0x00000080, 0x00000000, 0x0000),   # 0
        (0x01000101, 0x00000036, 0x00000000, 0x0000),   # 1
        (0x01000101, 0x00000031, 0x00000000, 0x0000),   # 2
        (0x01000101, 0x000000D6, 0x00000000, 0x0000),   # 3
        (0x01000101, 0x00000064, 0x00000000, 0x0000),   # 4
        (0x01000101, 0x00000080, 0x00000000, 0x0000),   # 5
        (0x00000101, 0x00000004, 0x00000000, 0x0000),   # 6
        (0x00000100, 0x00000000, 0x00280020, 0x0001),   # 7
        (0x00000100, 0x00020000, 0x00000000, 0x0000),   # 8
        (0x00000100, 0x00000000, 0x0000001C, 0x0001),   # 9
        (0x00000100, 0x00000000, 0x00000010, 0x0001),   # 10
        (0x00000100, 0x00000000, 0x00300028, 0x0001),   # 11
        (0x00000100, 0x00000000, 0x00300028, 0x0001),   # 12
        (0x00000100, 0x00000000, 0x00200020, 0x0001),   # 13
        (0x00000100, 0x00000000, 0x000C000C, 0x0001),   # 14
        (0x00010001, 0x00000005, 0x00060000, 0x0001),   # 15
        (0x00010001, 0x00000009, 0x000C0000, 0x0000),   # 16
        (0x00010001, 0x00000004, 0x00000000, 0x0001),   # 17
        (0x00010001, 0x00000002, 0x00000000, 0x0001),   # 18
        (0x00010001, 0x00000006, 0x00070000, 0x0001),   # 19
        (0x00010001, 0x00000004, 0x00040000, 0x0001),   # 20
        (0x00010001, 0x00000004, 0x00040000, 0x0001),   # 21
        (0x00010001, 0x00000002, 0x00020000, 0x0001),   # 22
        (0x00000101, 0x00000004, 0x00000005, 0x0001),   # 23
    )

    @staticmethod
    def p4_446470_kind(a: int, b: int, op: int, bit2: int) -> int:
        """`0x446470` 算出的**输入预设号**：`kind = (a!=0) + op*2 + (bit2 ? 0xF : 7)`。

        ```
        0x446475 0x45AFF0(0x4AB5B0, 2) → al
        0x446481 neg al ; sbb eax,eax ; 0x44648A and eax,8
                ⇒ al!=0（bit2 置位）→ 8，否则 0
        0x446492 eax += 7                     ; edi = 7 或 0xF
        0x446497 eax = 0x45AFC0(0x4AB5B0,0xC000) ; op ∈ 0..3
        0x4464A6 ecx = 0 ; test bl,bl ; setne cl ; ecx = (a != 0)
        0x4464A4 eax = op*2 ; 0x4464B7/0x4464C1 ecx += eax + edi
        ```

        ⇒ `kind ∈ [7, 22]`，**恰好铺满 0x498A88 表的 16 项**，
        所以 `§15②` 担心的「越界」在构造上不可能发生；
        `0x44E4A0` 本身**没有边界检查**（`kind*14 + 0x498A88` 直接读）。

        `b` 只决定走 `0x44E620`（五参）还是 `0x44E4A0`（三参）两支，不进 kind。
        """
        base = 0xF if bit2 else 7
        return (1 if a else 0) + (op & 3) * 2 + base

    @staticmethod
    def p4_input_preset(kind: int):
        """`0x44E4A0`：`kind` 索引 `0x498A88`（**stride 14**）把 3 个 dword + 1 个 word
        铺到输入管理器的 `+0x4C / +0x50 / +0x54 / +0x58`。

        ```
        0x44E4AB eax = kind*8 ; 0x44E4B5 eax -= kind   ; = kind*7
        0x44E4B7 ecx = eax*2 + 0x498A88                ; = kind*14 + base
        0x44E4BE eax = [kind*14 + 0x498A88] ; [mgr+0x4C] = eax
        0x44E4C7 [mgr+0x50] = [ecx+4]
        0x44E4CD [mgr+0x54] = [ecx+8]
        0x44E4D7 cx = word[ecx+0xC] ; [mgr+0x58] = cx
        ```
        """
        if not (0 <= kind <= 23):
            return None
        return Page4Mixin.P4_INPUT_PRESET[kind]

    P4_CAP_BEH = (0x401285, 0x402338, 0x402153, 0x401866,
                  0x4013E8, 0x401E51, 0x401CF3, 0x401EB5)

    @staticmethod
    def p4_10008041_ctor(op: int, bit2: int, a3: int):
        """`0x42DABC`：捕获/波纹实体 **`0x10008041`** 的构造分支（ui46c 的 `0x42D780` 内）。

        ```
        0x42DABC push 2 ; 0x42DB03 0x45AFF0(0x4AB5B0, 2) → al
        0x42DB0A push 0xC000 ; 0x42DB1B 0x45AFC0(0x4AB5B0, 0xC000) → op（0..3）
        0x42DB0F neg bl ; 0x42DB11 sbb ebx,ebx ; 0x42DB18 and ebx,4
                ⇒ al!=0（bit2 置位）时 ebx=4，否则 ebx=0
        0x42DB23 eax = op + ebx                     ; 索引 ∈ 0..7
        0x42DB2D eax = [esp + eax*4 + 0x10]         ; 8 项行为表
        0x42DB3A [e+0x40] = eax                     ; 行为指针
        0x42DB3D [e+0xC]  = 0x30                    ; 半径 0x30
        0x42DB44 byte[e+0x10] = 1                   ; 构造即活
        0x42DB4E eax = rec[0xC] ; 0x42DB5B [e+0x24] = a3
        ```

        行为表 = `(0x401285, 0x402338, 0x402153, 0x401866,
                   0x4013E8, 0x401E51, 0x401CF3, 0x401EB5)`。

        ★ 索引方向：**bit2 置位 → 取表 [4..7]**，未置位 → 取 [0..3]。
        （`neg` 置 CF 当且仅当操作数非 0，`sbb ebx,ebx` 得 -CF，再 `and 4` ⇒ 0 或 4；
         与 §16.272 同一类 `neg/sbb` 惯用法，必须盯 CF 而不是盯数值。）

        返回 `(行为指针, 半径, alive, a3)`；`a3` 落在 **`+0x24`**（不是 `+0x20`）。
        """
        idx = (op & 3) + (4 if bit2 else 0)
        return (Page4Mixin.P4_CAP_BEH[idx], 0x30, 1, a3)

    @staticmethod
    def p4_446c50_capture(e1: int):
        """`0x446C50`：**btn2（`0x4AB597`，Z/B/右键那一档）**按下时生成捕获/波纹实体。

        ```
        0x446C50 al = byte[0x4AB597]      ; e1 = 第二个扩展键字节
        0x446C58 test al,al ; 0x446C61 je 0x446CB0   ; 没按 → 跳过
        0x446C5E ebp = [ebx+0x1C]                    ; 子状态/帧计数指针
        0x446C63..0x430400(&rec, [ebp+4], [ebp+8], 0x10008041, a3=ebp)
        0x446C97 0x430290(0x4AD46C, &rec)            ; 生成到 ui46c
        0x446CA2 0x446470(e, 1, 1)                   ; 变换操作器
        0x446CA8 [ebx+0x20] = 1
        ```

        要点：
        - 实体类型 **`0x10008041`**（高位 `0x10` 家族，与 `0x0B`/`0x1B` 弹幕族都不同）；
        - 第 5 个实参是 **`ebp`（指针）**，再次印证 §16.270「`0x430400` 的 a3 原样存 dword」；
        - 进 **ui46c**（`0x4AD46C`），不是自弹用的 ui43c。

        返回 `(type, queue_flag)`：`queue_flag=True` 表示要进 ui46c。
        """
        if not e1:
            return None
        return (0x10008041, True)

    @staticmethod
    def p4_self_respawn_rec():
        """`0x443729..0x443767`：自机复活——清空 ui4cc 后在 **(200,200)** 生成 `0x0B000001`（a3=3）。

        ```
        0x44370A cmp ebp, 0xF0 ; jne 0x4437B2        ; ebp = 死亡计时器，满 240 才进入
        0x443716 al = byte[0x4AB596]                  ; 输入记录 +2（e0）
        0x44371B test al,al ; je 0x443779
        0x44371F 0x43A320(0x4AD4CC)                   ; 清 ui4cc
        0x443729 push 3 ; 0x44372B push 0x0B000001
        0x443730 push 0xC8 ; 0x44373C push 0xC8 ; push &rec
        0x443742 0x430400(&rec, 0xC8, 0xC8, 0x0B000001, 3)
        0x443767 0x448FF0(0x4AD40C, &rec)             ; 生成到 ui40c
        ```

        另一支：`0x443779 al = byte[0x4AB597]`（输入 +3）非 0 → `0x45AF30(0x4AB5C0, 0x200)` 退页。

        坐标常量 **0xC8 = 200**（屏幕中心是 (0x140,0xF0)=(320,240)，所以 200 是偏左上的复活点，
        不是正中）。`a3 = 3` 进实体 `+0x20`，与 §10 里自机 ctor 的 `rec[3]==1 ? -1 : 0` 判定无关
        （那里看的是 1，这里是 3，走 else 支 = 0）。

        ⚠ 调用点未定位：`0x4435C0`（该块所在函数里 `sub esp,0x334` 的位置）在全镜像里
        **既无数据引用也无 call/jmp 指向**，`0x4020EF → 0x4435C0` 那个 thunk 也无任何 call 者，
        `0x43D794` 处的 `0x4020EF` 是**指令内错位字节**（邻域是 `40 46 C7 00 40 20 EF 00`）。
        故这一块只能靠前向落入，函数入口仍是悬案，暂不接进帧循环。
        """
        return (0xC8, 0xC8, 0x0B000001, 3)

    @staticmethod
    def p4_430400_rec(x: int, y: int, type_word: int, a3: int = 0, a4: int = 0):
        """`0x430400(&rec, x, y, type, a3)`：把 5 个 dword 记录填进 `&rec`。

        逐条跟踪 `esp` 后（以进入时 `esp` 为 0 基准，`sub esp,0x14` 后 `S=-0x14`）：

        | 指令 | 当时 esp | 有效偏移 | 落点 |
        |---|---|---|---|
        | `0x43040F mov [esp],eax` | S | S+0 | **slot0 = arg2 = x** |
        | `0x430418 mov [esp+0x10],eax` | S-4 | S+0xC | **slot3 = arg5 = a3** |
        | `0x430421 mov [esp+0xC],ecx` | S-8 | S+4 | **slot1 = arg3 = y** |
        | `0x430430 mov [esp+0x10],edx` | S-8 | S+8 | **slot2 = arg4 = type** |
        | `0x430434 rep movsd` (5) | S-8 | 源 = S+0 | 拷 slot0..slot4 |

        ⇒ `rec = [x, y, type, a3, **slot4**]`，而 **slot4（S+0x10）在函数体内从未被写**，
        拷贝的却是 5 个 dword —— 也就是说 `rec[0x10]`（最终落到实体 `+0x3C`）
        是**调用者栈上的残留值**，不是参数。这是原码的真实怪癖，不是笔误：
        `0x430400` 只接受 4 个有效参数（`ret` 无清栈，cdecl）。

        ⇒ 第 5 个实参（`a3`）**总是原样存成 dword**：传 `&{jx,jy}` 就是指针、
        传 `0x30` 就是数值 —— 两者的区别由**该类型实体的构造函数**去解释，
        `0x430400` 自己不做任何区分。这也解释了为什么同一个函数两种用法都能跑。
        """
        return (x, y, type_word, a3, a4)

    @staticmethod
    def p4_4590_tri(v: int) -> int:
        """`0x45900C`（键16）对 `[0x4AB5B0+4]` 的 `0x18` 字段做**三态轮转**。

        ```
        0x459013 op = 0x45AFC0(0x4AB5B0, 0x18)
        0x459018 test eax,eax ; jne 0x459020 → op==0 时 push 1
        0x45902C cmp eax,1 ; jne 0x459035     → op==1 时 push 3，否则 push 0
        0x45903E 0x45B0E0(0x4AB5B0, 0x18, 新值)   写回
        ```

        ⇒ `0 → 1 → 3 → 0`（**跳过 2**，因为是 2 位字段只有三个合法态）。
        """
        if v == 0:
            return 1
        if v == 1:
            return 3
        return 0

    @staticmethod
    def p4_450580_pair(bit8: int, bit10: int):
        """`0x450580(mgr, a, b)`：把两个字节写进 `[mgr+0x5C]`、`[mgr+0x5D]`（`ret 8`）。

        ```
        450580 al = [esp+4] ; dl = [esp+8]
        450588 [ecx+0x5C] = al ; 45058B [ecx+0x5D] = dl ; 45058E ret 8
        ```

        **不是**「播 SE」，只是一次两字节存。调用处（`0x459043..0x459062` 与 `0x4582C2`）
        传的是 `0x45AFF0(0x4AB5B0, 0x10)` 与 `0x45AFF0(0x4AB5B0, 8)` —— 即 KeyMgr 位字里
        两个「是否置位」的布尔值。注意压栈顺序 `push(8) / push(0x10)` ⇒ **arg1 = 测0x10**、
        **arg2 = 测8**，所以写进去的 `+0x5C = 测0x10`、`+0x5D = 测8`。

        这两个字节在 `0x4AB4B0`（音频管理器）里的确切含义尚未定案，不臆测。
        """
        return (bit10 & 0xFF, bit8 & 0xFF)

    @staticmethod
    def p4_45b0e0_set(word: int, mask: int, value: int) -> int:
        """`0x45B0E0(obj, mask, value)`：**位域写入**（`0x45AFC0` 的写入对应件）。

        ```
        45B0E4 edx = 1 ; esi = value
        45B0EE 循环：while !(mask & edx): edx <<= 1 ; esi <<= 1
                 ⇒ 把 value 左移到 mask 的最低位，等价于 value << 最低位序号
        45B0FB edi = [ecx+4]
        45B100 edx = ~mask & edi          ; 清掉掩码内原有的位
        45B104 eax = mask & (esi 已移位)  ; 新值对齐到掩码
        45B106 word = edx | eax
        45B10D ret 8                      ; 2 个栈参数
        ```

        ⇒ `word' = (word & ~mask) | ((value << lowest_bit(mask)) & mask)`。
        """
        if mask == 0:
            return word
        sh = (mask & -mask).bit_length() - 1              # mask 最低位序号
        return ((word & ~mask) | ((value << sh) & mask)) & 0xFFFFFFFF

    @staticmethod
    def p4_45af90_xor(word: int, mask: int) -> int:
        """`0x45AF90(obj, mask)`：`word ^= mask`，**返回新值**（`ret 4`）。

        与 `0x45AF30`(`|=`)、`0x45AF60`(`&= ~`)、`0x45AFF0`(测)、`0x45B030`(全清) 并列，
        是这套位域 API 里的**异或切换**；页4 的键 17/18/19/24 都用它切换一个开关位。
        """
        return (word ^ mask) & 0xFFFFFFFF

    @staticmethod
    def p4_4590_step(v: int, delta: int) -> int:
        """`0x4590DC`/`0x45911F`/`0x45915E`/`0x4591E0`：对比/亮度字段的 ±10 循环步进。

        ```
        键20 (0x4590DC)：v = 0x45AFC0(0x4AB5B8, 0xFE000000) + 0xA ; 写回
                          再读一次，cmp eax,0x64 ; jb → 否则写 0
        键21 (0x45911F)：同上但 sub 0xA
        键22 (0x45915E)：对 0x1FC0000(亮度) add 0xA，同样 cmp 0x64
        键23 (0x4591E0)：对 0x1FC0000 sub 0xA
        ```

        **比较是无符号的**（`jb`，不是 `jl`）：所以反方向减到负数会变成极大值，
        同样落到「≥ 0x64 ⇒ 写 0」这一支 —— 两个方向共用同一条回绕规则，值域恒为 `0..99`。

        ⇒ `v' = v + delta`；若 `(v+delta) & 0xFFFFFFFF >= 0x64` 则 `v' = 0`。
        """
        w = (v + delta) & 0xFFFFFFFF
        return w if w < 0x64 else 0

    @staticmethod
    def p4_457d20(i: int) -> int:
        """`0x457D20(this, i)`：返回 `&(this + i*0x2A98 + 0x10)` —— 第 i 个槽的 `+0xC` 字段地址。

        ```
        457D24 edx = i
        457D26 eax = i shl 4        = i*16
        457D29 eax += i             = i*17
        457D2B eax = eax + eax*4    = i*85
        457D2E eax = i + eax*8      = i*681
        457D31 edx = i + eax*2      = i*1363      ← 步长系数
        457D34 ecx = this + edx*8 + 4             = this + i*0x2A98 + 4
        457D38 call 0x457520                      ; = lea eax,[ecx+0xC] ; ret
        ```

        ⇒ 步长 **`0x2A98 = 1363*8`**，且 `0x457520` 只是个 `+0xC` 取值器，
        最终地址 = `this + i*0x2A98 + 0x10`（`+4` 与 `+0xC` 相加）。

        这一串 `shl/lea` 是编译器把 `i*1363*8+16` 展开了；系数 1363 = 17*80+3 之类没有直观含义，
        照抄即可，**不要"化简"**成别的形式（化简容易把 `*8` 的顺序搞错）。
        """
        return (i * 0x2A98) + 0x10

    @staticmethod
    def p4_44caa0_skip(v2: int, v3: int, v4: int) -> bool:
        """`0x44CB5A..0x44CB72`：`0x44CAA0` 里**三个值任一为 0 就跳过亮度/对比变换**。

        ```
        0x44CB45 eax = [esp+0x74] ; 0x44CB54 [ebp+0xC88] = eax
        0x44CB5A eax = [esp+0x78] ; 0x44CB5E test eax,eax ; je 0x44CCA4
        0x44CB66 test ecx,ecx (=[esp+0x7c])                ; je 0x44CCA4
        0x44CB70 test esi,esi (=edx=[esp+0x80])            ; je 0x44CCA4
        ```

        ⇒ 三个值**全非 0** 才走后面的 `0x44CCBD → 0x44B790` 变换。
        页4 阶段首帧那次调用 `0x44CAA0(mgr, buf, 对比, 亮度, 淡入=0)` 里有一个 0，
        所以**变换被跳过** —— 这解释了「配置字静态为 0 ⇒ (−200,−200)」却不会把画面压黑：
        那两个值只是被登记，没有走到 `0x44B790`。

        返回 True = 跳过变换。
        """
        return v2 == 0 or v3 == 0 or v4 == 0

    def p4_cfg_word(self) -> int:
        """`0x4AB5B8+4`：配置字（对比/亮度两个 7 位字段的来源）。

        `0x451657/0x451675` 两次 `0x45AFC0` 都是 `ecx = 0x4AB5B8`，即读
        **该对象 `+4` 的那个位域字**（与 `0x4AB5B0` KeyMgr 的 `+4` 同构）——
        所以 `p4_afc0` 必须能指定 base，不能写死 `0x4AB5B0`。
        复刻侧尚未定位该字的写入方，故默认 0。**注意**：0 解出来是 (−200, −200)，
        那是很重的压暗、**并不等价于「不调整」** —— 所以 `p4_intro_frame` 在 cfg 为 0 时
        不传调整值（保持不施加），只有取到真实配置字才按原样施加。这一处是显式待补的缺口。
        """
        return self.p4_stat.get(0x4AB5B8 + 4, 0)

    @staticmethod
    def p4_451630_adjust(w: int):
        """`0x451657..0x45168E`：阶段首帧从配置字取**对比/亮度**两个 7 位字段。

        ```
        0x451659 push 0x1FC0000 ; 0x451663 0x45AFC0(0x4AB5B8, 0, 0x1FC0000)
            ⇒ eax = (w & 0x1FC0000) >> 18     ; 位 18..24，7 位
        0x451668 lea eax, [eax*4 - 0xC8]      ; ×4 − 200
        0x451675 push 0xFE000000 ; 0x45167A 0x45AFC0
            ⇒ eax = (w & 0xFE000000) >> 25    ; 位 25..31，7 位
        0x45167F lea ecx, [eax*4 - 0xC8]      ; ×4 − 200
        0x451687 push 2 ; 0x45168E 0x44CDF0(0x4AA7B0, 2, 对比=f2, 亮度=f1)
        ```

        压栈顺序 `push f1 / push f2 / push 2` ⇒ cdecl 下 **arg2 = 2**、arg3 = f2、arg4 = f1，
        即 `0x44CDF0(mgr, id=2, 对比, 亮度)`，与 `p4_load_palette` 的 docstring 一致。

        返回 `(亮度, 对比)`，各在 `-200 .. 308`（`0x7F*4-200 = 308`）。
        """
        br = ((w & 0x1FC0000) >> 18) * 4 - 0xC8      # 0x1FC0000 的最低位是第 18 位
        ct = ((w & 0xFE000000) >> 25) * 4 - 0xC8
        return br, ct

    def p4_load_palette(self, ident: int, ct: int = 0, br: int = 0) -> bool:
        """`0x44CDF0(mgr, id, 对比, 亮度)`：按 RT_STRING id 载调色板，再按 `0x44B790` 施加强度。

        `0x44CDF0` 把对比写 `[mgr+0xC98]`、亮度写 `[mgr+0xC94]`，`0x44B790` 的公式是

            v = src + ((src - 0x80) * b >> 6)      ; b = [mgr+0xC98] = 对比
            out = clamp(v + a, 0, 255)             ; a = [mgr+0xC94] = 亮度

        即 `fade_palette(pal, a=亮度, b=对比)`。页4 阶段首帧载 id 2（bm_pald，暗版）并施加
        `0x451630` 算出的两个 7 位字段；退出时恢复 id 1（bm_pal，不施加）。
        """
        pal = self.data.get("palettes", {}).get(str(ident))
        if not pal:
            return False
        import numpy as np
        arr = np.array(pal, dtype=np.uint8)
        # 0x451630 传进来的对比/亮度先**只登记**，不在此处施加：
        # `0x44CDF0 → 0x44CAA0(mgr, buf, 对比, 亮度, 淡入)` 之后才是 `0x44CCBD → 0x44B790`
        # 的一次变换，但 `[0x4AB5B8+4]` 的静态初值是 0 ⇒ 一旦在此施加就是 (-200,-200) 的
        # 极重压暗，与实机可玩画面矛盾。故本函数只记录，等定位该字的写入方后再按原样施加。
        self.p4_pal_adj = (br, ct)
        self.pal = arr
        self.pal_now = self.pal
        return True

    # -- 0x458D60 / 进场里尚未定案的四段（显式占位，不猜行为）
    def stage_globals(self, a1: int, a2: int) -> None:
        """`0x458DBA → 0x45EB40(0x4CD4A0, a1, a2)`：本局记录构造 + **HUD 显示表（22 节点）**。

        规格全文见 docs/p4_stage_0x45EB40_0x460930.md §1。要点：
        ```
        0x45DF40 旧 22 节点摘除 + 释放 [+0xE8]
        [+0x04..+0x10] / [+0x14..+0x20] 各 4 dword 清 0
        word[+0x2C] = (s8)a1（连击种子）；word[+0x24] = 0；word[+0x26] = 0xA0；
        word[+0x28] = 0；byte[+0x2A] = 0；dword[+0x30] = a2（倍率种子）；
        dword[+0x34] = 0xF4240；byte[+0x38] = 0；[+0x3C..+0x60] 10 dword 清 0
        0x45A070(this+0x64)：显示表容器
        20 数字节点（i=0..19）：[+0x88+4i]，layer 0、隐藏、dst = (604−24i, 12)；
            首节点 src = (0, 0x180, 0x17, 0x197)
        图标甲（+0xD8）：layer 0、显示、src (0x90,0x180,0xBF,0x197)、dst (12,48)
        图标乙（+0xDC）：layer 0、显示、src (0,0x1B0,0x17,0x1C7)、dst (72,48)
        byte[+0xE0] = 0；byte[+0xE1] = 1（脏）
        0x45AFF0(0x4AB5B0,1) 非 0 → word[+0xE2]=0、dword[+0xE4]=0x61A80；
            否则 word[+0xE2]=7、0x45C740(0x4AB5CC,7,&buf) → dword[+0xE4] = 该行分数
        [+0xE8] = 资源 0x4E 整块副本（0x45DDE0 取长、0x45DDA0 取源）；dword[+0xEC] = 0
        ```"""
        st = self.p4_stat
        base = 0x4CD4A0
        for off in (0x04, 0x08, 0x0C, 0x10, 0x14, 0x18, 0x1C, 0x20,
                    0x3C, 0x40, 0x44, 0x48, 0x4C, 0x50, 0x54, 0x58, 0x5C, 0x60):
            st[base + off] = 0
        st[base + 0x2C] = _p4_s8(a1) & 0xFFFF           # 0x45EB7B word
        st[base + 0x24] = 0                             # 0x45EB84 word 关卡号
        st[base + 0x26] = 0xA0                          # 0x45EB88 word 气槽
        st[base + 0x28] = 0                             # 0x45EB8E
        st[base + 0x2A] = 0                             # 0x45EB92 byte
        st[base + 0x30] = a2 & 0xFFFFFFFF               # 0x45EB95 倍率种子
        st[base + 0x34] = 0xF4240                       # 0x45EB98 奖命分数线
        st[base + 0x38] = 0                             # 0x45EB9F byte
        nodes = []
        x = 0x25C
        for i in range(20):                             # 0x45EBCA..0x45EC06
            nd = DNode(0, 0, 0)
            nd.src = (0, 0x180, 0x17, 0x197)            # 0x45EC08（首节点；其余同形）
            nd.dst = (x, 0x0C)
            nd.active = 0                               # byte[node+0x1C] = 0
            nodes.append(nd)
            x -= 0x18
        ia = DNode(0, 0x90, 0x180)                      # 0x45EC46 图标甲
        ia.src = (0x90, 0x180, 0xBF, 0x197)
        ia.dst = (0x0C, 0x30)
        ia.active = 1
        ib = DNode(0, 0, 0x1B0)                         # 0x45ECB8 图标乙
        ib.src = (0, 0x1B0, 0x17, 0x1C7)
        ib.dst = (0x48, 0x30)
        ib.active = 1
        st["hud_nodes"] = nodes
        st["hud_icon_a"] = ia
        st["hud_icon_b"] = ib
        st[base + 0xE0] = 0                             # 0x45ED2A
        st[base + 0xE1] = 1                             # 0x45ED37 脏标志
        if self.keys.test(1):                           # 0x45ED3D 0x45AFF0(…,1)
            st[base + 0xE2] = 0                         # 0x45ED46
            st[base + 0xE4] = 0x61A80                   # 0x45ED4F
        else:
            st[base + 0xE2] = 7                         # 0x45ED67
            st[base + 0xE4] = self.p4_45c740_score(7)   # 0x45ED70 → buf[0]
        bank = getattr(self, "p4_bank", None)
        st["res4e"] = bank.get(0x4E) if bank is not None else b""
        st[base + 0xE8] = len(st["res4e"])              # 0x45EDA8（副本长度）
        st[base + 0xEC] = 0                             # 0x45EDD6

    def p4_45c740_score(self, row: int) -> int:
        """`0x45C740(0x4AB5CC, row, &buf)[0]`：排行榜 row 行的分数 dword。
        idx = 2*row + byte[tbl+4]，src = tbl + (byte[tbl+5] ? 0x740 : 8) + 0x54*idx。"""
        t = self._p4_tbl4ab5cc()
        idx = 2 * row + _p4_s8(t[4])
        off = (0x740 if t[5] else 8) + 0x54 * idx
        return int.from_bytes(t[off:off + 4], "little")

    def p4_45c740_entry(self, row: int, tbl_obj=None) -> bytearray:
        """`0x45C740(obj, row, &out)` 全项读取（2026-11-11 定案）：0x54 字节/项。

        idx = obj[4] + 2*row；src = obj + (obj[5] ? 0x740 : 8) + 0x54*idx。
        项内：+0x00 dword 得分、+0x12..+0x1B 10B 名字（字形格号）、
        +0x1C..+0x30 日期组（+0x30 = 年−1900）、+0x34 dword。"""
        if tbl_obj is None:
            t = self._p4_tbl4ab5cc()
        else:
            t = tbl_obj
        idx = t[4] + 2 * row
        off = (0x740 if t[5] else 8) + 0x54 * idx
        return bytearray(t[off:off + 0x54])

    def stage_layers(self, a3: int, a4: int) -> None:
        """`0x458DCE → 0x460930(0x4CD590, a3, a4)`：结算对象构造（docs §2）。

        ```
        0x4608F0：清 [+0x28]/[+0x2C] 两槽
        0x45A070(this+0x04)：显示表容器
        [+0x30] = a3（结算倍率，−1 = 禁用）；[+0x34] = [+0x38] = 0；
        [+0x3C] = a4；[+0x40] = [+0x44] = 0
        2 节点：layer 0、byte[+0x1C] = (a3 != -1)；dst (12,12) / (72,12)
        v = 0x45AFC0(0x4AB5B0, 0xC000)；节点 1 src = (48v, 0x1B0, 48v+0x2F, 0x1C7)
        ```"""
        st = self.p4_stat
        base = 0x4CD590
        st[base + 0x30] = a3 & 0xFFFFFFFF               # 0x460958
        st[base + 0x34] = 0                             # 0x46095B
        st[base + 0x38] = 0                             # 0x46095E
        st[base + 0x3C] = a4 & 0xFFFFFFFF               # 0x460961
        st[base + 0x40] = 0                             # 0x460964
        st[base + 0x44] = 0                             # 0x460967
        vis = 1 if (a3 & 0xFFFFFFFF) != 0xFFFFFFFF else 0   # 0x46096C (a1 != -1)
        n1 = DNode(0, 0, 0)
        n1.dst = (0x0C, 0x0C)                           # 0x46099F
        n1.active = vis
        n2 = DNode(0, 0, 0)
        n2.dst = (0x48, 0x0C)                           # 0x4609B4
        n2.active = vis
        v = self.keys.field(0xC000)                     # 0x4609C3 ×2
        n1.src = (v * 0x30, 0x1B0, v * 0x30 + 0x2F, 0x1C7)   # 0x4609D5
        st["st_icon_a"] = n1
        st["st_icon_b"] = n2

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
                if e.node is not None:
                    e.node.active = 0            # [[ent+0x38]+0x1C]=0 隐藏节点
            i += 1

    def _p4_ent43c(self, typ: int, x: int = 0, y: int = 0,
                   a3: int = 0, a4: int = 0) -> "Ent":
        """往 `0x4AD43C`（ui43c）挂一个**真实体**（`0x43A7F0` 家族，`Ent.SZ=0x5C`）。

        不能用 `spawn()`：那个返回 `UiEntity`（geki 侧的轻量类），没有 `d32/g32` 字节模型，
        而 ui43c 的行为函数全部按 `[ent+0xNN]` 直接读写内存。
        """
        global _P4_ACTIVE_PAGES
        _P4_ACTIVE_PAGES = self
        e = Ent(x, y, typ, a3)
        if typ == 0x2300000D:                      # ctor 0x40DB54..0x40DB66
            e.d32(0x1C, (y << 7) & 0xFFFFFFFF)     # [+0x1C] = rec[1]<<7
            e.d32(0x20, (self.p4_player_y() - y) & 0xFFFFFFFF)  # [+0x20] = 自机y - y
        self.p4_q43c.append(e)
        self.p4_n43c += 1
        return e

    def _p4_type0_drift(self, e: "Ent") -> bool:
        """type 0（0x61000001 群生门的生成体）：原作 ctor 落默认尾（+0x40 = 堆残留，
        实机靠堆复用继承旧行为）。复刻按最常见模式近似：匀速左移、出屏（x<-0x20）死。
        无显示节点（prop 表无 type 0 ⇒ 0x43AC30 不建节点）＝不可见、半径 0＝不可命中。
        存在意义：占住 0x430860 的队列计数，让 0x427510 门（VM 冻结）在群生期间保持。"""
        e.d32(0x04, (e.s32(0x04) - 3) & 0xFFFFFFFF)
        return e.s32(0x04) > 0xFFFFFFE0          # 有符号 x > -32

    def p4_call_behaviour(self, e: "Ent") -> bool:
        """`0x446450 = jmp [ent+0x40]`：按行为指针分派。未实现的行为先返回"存活"并计数，
        绝不假装完成——实现一个就在 `P4_BEH` 里登记一个。"""
        if not isinstance(e.beh, int):
            return True   # 字符串行为（UiEntity）由 tick_ui 分派，不走 p4_call_behaviour
        if e.beh == 0 and e.g32(0x14) == 0:       # type 0（0x61000001 群生体）：漂移近似
            return self._p4_type0_drift(e)
        fn = P4_BEH.get(e.beh)
        if fn is None:
            # 0x41 族拖尾/粒子（0x401B95→0x430550）等 mixin 方法
            fn = getattr(type(self), f"_beh_{e.beh:X}", None)
        if fn is None:
            self.p4_beh_missing[e.beh] = self.p4_beh_missing.get(e.beh, 0) + 1
            self.p4_beh_missing_types[(e.beh, e.s32(0x14))] = \
                self.p4_beh_missing_types.get((e.beh, e.s32(0x14)), 0) + 1
            return True
        r = fn(self, e)
        # 0x27000001..0x0E 的行为尾部都 `call 0x401F91`（0x416440）：HP==0 时生成
        # boss 0x27000011。0x27000006 已在行为内调用，0x2700000B 无此尾，排除。
        if (e.g32(0x14) in _P4_27_TAIL_TYPES):
            self.p4_416440(e)
        return r

    def p4_spawn_actor1(self, x: int, y: int, prm: int) -> None:
        """演员 **type 1 = 自机本体**（VM op1 / 流 46 t=0 生成于 (0x172,0xF0)）。

        构造全在 `p4_445ece`（0x445ECE 逐条，含八项行为表[(操作器位?4:0)+选机]、
        [e+0x20]=(param!=1)?-1:0、层 0 撃/凛/漢 三格 rect、ctor 尾 0x446470(e,0,1)
        ⇒ **指针种子=出生点**（原作无初始化漂移的机制）+ 0x446600 的 -1 分支当场
        点亮节点）。这里只补 DNode 装配与入队（0x4AD40C = actorq）。
        """
        e = Ent(x, y, 1, prm)
        e.node = DNode(0, 0, 0)                           # 0x445F74 [节点]=0（层 0）
        self.p4_445ece(e, (x, y, 1, prm))
        e.beh = e.g32(0x40)                               # 行为表[idx]（P4_BEH 按真址登记）
        e.node.active = 0                                 # 0x445FFF byte[节点+0x1C]=0
        self.actorq.append(e)                             # 0x4AD40C

    def p4_vm_entity(self, op: int, rec: tuple) -> None:
        """op1..op5 → 五个队列原语（`0x448FF0`/`0x43BDC0`/`0x43A3C0`/`0x44B140`/`0x445AA0`）。

        `0x43BDC0` 的挂链方式（`0x43BE14`/`0x43BE4C`）：`[queue+0x28]` 为空 → 头，否则挂
        `[queue+0x2C]` 尾 ⇒ **尾插**。实体内存 0x5C 字节，ctor `0x43A7F0`。
        其它四族的 ctor（`0x4355E0`/`0x449150`/`0x43D430`/`0x448FF0`）尚未实现，只登记。
        """
        a, b, c, d = rec
        if op == 2:
            _e2 = Ent(a, b, c, d)
            _e2._pages = self
            if c == 0x2300000D:                    # 0x40DB48（0x23 ctor case12，大）
                # [0x1C] = 生成y<<7（相位=生成高度）、[0x20] = [0x56CC90]-生成y
                # （频率=自机当时 y）——大 从生成高度出发、纵向渐变到自机当时高度
                _e2.d32(0x1C, (b << 7) & 0xFFFFFFFF)                     # 0x40DB54
                _e2.d32(0x20, (self.p4_player_y() - b) & 0xFFFFFFFF)     # 0x40DB5D
            self.p4_q43c.append(_e2)               # 0x43BDC0 → 0x43A7F0
            self.p4_n43c += 1
        elif op == 1:
            # 0x46044F：0x430400(&rec,…) 后 0x448FF0(0x4AD40C,&rec) ⇒ 演员队列
            if c == 1:
                self.p4_spawn_actor1(a, b, d)      # 0x445ECE：自机本体（撃/凛/漢）
            else:
                self.spawn(self._p4_q("ui40c"), c, a, b, d)
        elif op == 3:
            # 0x460411：0x430400(&rec,…) 后 0x43A3C0(0x4AD4CC,&rec) ⇒ ui4cc
            if (c & 0xFF000000) == 0x42000000:      # ctor 0x4355E0 的 0x42 家族分支
                self.p4_spawn42(a, b, c, d)
            else:
                self.spawn(self._p4_q("ui4cc"), c, a, b, d)
        elif op == 4:
            # 0x460490：0x430400(&rec,…) 后 0x44B140(0x4AD4FC,&rec) ⇒ ui4fc。
            # 0x51 族（0x5100000x）的 ctor 是 0x449150 → 0x422EF0 跳表 case，
            # 必须走 p4_51_spawn；直接 spawn() 会落成 default 行为、整段关卡收尾
            # （流75 的 0x51000002 param=1）不推进。
            if (c & 0xFFFF0000) == 0x51000000:
                self.p4_51_spawn(a, b, c, d)
            else:
                self.spawn(self._p4_q("ui4fc"), c, a, b, d)
        elif op == 5 and c == 0x61000005:
            # 0x61000005：init 0x42730B（`[+0x1C]=a` 当前、`[+0x20]=b` 目标、`[+0x24]=d` 步进）
            # 链路 0 的载荷是 (-255, 0, 0x61000005, 16) = 16 帧淡入，正是开场把画面点亮的那条
            self.spawn_flash(a, b, d)
        elif op == 5 and c == 0x61000004:
            # ctor 0x4272DD / 行为 0x427580（击破波纹驱动）：VM 记录 dword ⇒ 转有符号
            _s4 = lambda v: v - 0x100000000 if v & 0x80000000 else v
            self.p4_spawn_61000004(_s4(a), _s4(b), _s4(d))
        elif op == 5 and (c & 0xFF000000) == 0x6F000000:
            # 0x6F 族（EDG2 の 0x6F000005＝結局調色板/画集控制器 0x4415F0 等）
            _s6 = lambda v: v - 0x100000000 if v & 0x80000000 else v
            self.spawn(self._p4_q("ui52c"), c, _s6(a), _s6(b), _s6(d))
        elif op == 5 and (c & 0xFFFFFF00) == 0x61000000:
            # 0x61 族其余型（跳表 0x4273C0，索引 = type-0x61000001）：
            #   0x61000007 init 0x42735E / 行为 0x427690 = BGM 主音量渐变
            #     （每 8 帧 cur+=step 钳到 target → 0x44F950 = GM SysEx F0 7F 7F 04 01 00 v F7；
            #      流 45 t=0 (127,127,127)=满音量、流 46 t=8390 (127,0,-8)=关末淡出）
            #   0x61000002 init 0x42729A / 行为 0x427510 = 等 0x4AD49C+0x4AD43C 清空 → sysf|=2
            #   0x61000003 init 0x4272B1 = 0x45B0A0(0x56CCB8, rec3, rec0!=0) 一次性
            #   0x61000006 init 0x427332 = 0x45AF30(0x56CCB8,0x1000) → byte[0x56CCB3]=1
            #   0x61000008 init 0x427385 / 行为 0x427710 = 录像驱动（mode 0 无视觉，480 帧倒计时）
            # rec 布局同 op1..4：rec0=a、rec1=b、rec3=d（spawn 的 x/y/a3 形参承接）。
            # VM 记录是无符号 dword，音量/步进/掩码都是带符号语义 ⇒ 先转有符号。
            _s = lambda v: v - 0x100000000 if v & 0x80000000 else v
            self.spawn(self._p4_q("ui52c"), c, _s(a), _s(b), _s(d))
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
                if os.environ.get("P4_DIAG"):
                    print(f"[p4layers] bind FAIL layer={i} id={v} res={res}")
                self.flags.set(2)                 # 0x4606B3
                self.sysf.set(1)                  # 0x4606BD：冻结门 0x56CC84 |= 1
                self.vm.halt = True               # 0x4606C2：当帧 return 1、不推进、不置 [+0x34]
                break
            self.layers.color_key(i, 0)           # 0x460635 0x44CE60(i,0)

    def p4_play_bgm(self, track: int, skip: bool = False) -> None:
        """op 0x0C → `0x44F600(0x4AB514, arg1=(param!=3), arg2=param)`（资源 1..20 = 20 首 MIDI）。

        `skip=False`（param==3）时 exe 跳过 tempo/主音量设置（0x44F7CB je 0x44F7FF）；
        复刻侧音频层不建模 tempo/音量，仅保留参数语义（见矩阵）。
        """
        if self.audio is not None:
            self.audio.bgm(track)

    def p4_set_level(self, level: int) -> None:
        """op 0x0D → `0x45EF10(0x4CD4A0, word[+4])`：清 +0x14..+0x20、`word[+0x24]=level`、
        `[+0xEC]=0x4A4B64[level]`。"""
        for a in range(0x14, 0x24, 4):
            self.p4_stat[0x4CD4A0 + a] = 0
        self.p4_level = level
        # ★ 只写**低 16 位**：`+0x24` 是 word，`+0x26` 是紧邻的另一个 word（0x45EB40 置 0xA0）。
        # 若按 dword 写，会把 +0x26 一起清零。
        self.p4_stat_w16(0x24, level)
        # 0x45EF29..0x45EF33：`edx = [0x4A4B64 + level*4]; [this+0xEC] = edx`
        # —— 关卡号 → 得分描述表指针。0x45F5C0 的顺序是 0x45EB40（会把 +0xEC 清 0）
        # 之后再 0x45EF10(level)，所以这里必须在重置后重新写回；旧实现漏了这条
        # ⇒ +0xEC 恒 0 ⇒ 0x45EFF0 的 `if ([+0xEC]==0) ret` 早退，击破永远不加分。
        self.p4_stat[0x4CD4A0 + 0xEC] = (
            self.P4_HUD_KIND[level]
            if 0 <= level < len(self.P4_HUD_KIND) else 0)

    def sequence_started(self) -> bool:
        """`0x460EE0(0x4CD590)`：`eax = [+0x40]`（getter，原样返回）。

        同族的存取器（`0x460E80/EA0/EC0/EE0` = `+0x34/+0x30/+0x3C/+0x40` 的 getter）
        说明 `0x4CD590` 是一组 32 位计数字段，本函数只读 `+0x40`。
        """
        return self.p4_stat.get(0x4CD590 + 0x40, 0) != 0

    def sequence_start(self) -> None:
        """`0x460E40(0x4CD590)`：启动序列。

        ```
        0x460E40 eax = [+0x3C]
        0x460E43 [+0x30] = 6
        0x460E4A eax-- ; 0x460E4B [+0x3C] = eax
        0x460E4E eax = [+0x40] ; inc ; [+0x40] = eax
        0x460E55 eax = [+0x44] ; inc ; [+0x44] = eax
        0x460E5C eax = [+0x2C]                    ; ★ 实体指针
        0x460E5F byte[eax+0x1C] = 1                ; 把它帧计数置 1（与 0x460D55 置 0 相对）
        0x460E63 ret
        ```

        注意顺序：**先读 `+0x3C`，再写 `+0x30`，最后写 `+0x3C`**（读的是旧值，减 1 后写回）。
        """
        s3c = self.p4_stat.get(0x4CD590 + 0x3C, 0)
        self.p4_stat[0x4CD590 + 0x30] = 6
        self.p4_stat[0x4CD590 + 0x3C] = (s3c - 1) & 0xFFFFFFFF
        self.p4_stat[0x4CD590 + 0x40] = ((self.p4_stat.get(0x4CD590 + 0x40, 0) + 1)
                                         & 0xFFFFFFFF)
        self.p4_stat[0x4CD590 + 0x44] = ((self.p4_stat.get(0x4CD590 + 0x44, 0) + 1)
                                         & 0xFFFFFFFF)
        # 0x460E5C..0x460E5F：byte[[+0x2C]+0x1C] = 1 —— 点亮残撃数字节点。
        # [+0x2C] = 0x460930 ctor 存的节点 2（st_icon_b）；0x460C00 死亡链把它置 0。
        ib = self.p4_stat.get("st_icon_b")
        if ib is not None:
            ib.active = 1

    P4_STAT_BASE = 0x4CD4A0

    def p4_stat_w8(self, off: int, val: int) -> None:
        base = self.P4_STAT_BASE
        d = base + (off & ~3)
        cur = self.p4_stat.get(d, 0)
        sh = (off & 3) * 8
        self.p4_stat[d] = (cur & ~(0xFF << sh)) | ((val & 0xFF) << sh)

    def p4_stat_w16(self, off: int, val: int) -> None:
        base = self.P4_STAT_BASE
        d = base + (off & ~3)
        cur = self.p4_stat.get(d, 0)
        sh = (off & 2) * 8
        self.p4_stat[d] = (cur & ~(0xFFFF << sh)) | ((val & 0xFFFF) << sh)

    def p4_45eb40(self, arg1: int, arg2: int) -> None:
        """`0x45EB40(this,arg1,arg2)`：**阶段全局对象 `0x4CD4A0` 的重置**。

        ```
        0x45EB49 0x45DF40(this)
        0x45EB4E.. zero [+4..+0x13]        （4 dword）
        0x45EB63.. zero [+0x14..+0x23]     （4 dword）
        0x45EB66 cx = (sbyte)[esp+0x78]    ; arg1 按**有符号字节**取
        0x45EB7B word[+0x2C] = cx
        0x45EB84 word[+0x24] = 0           ; 关卡号
        0x45EB88 word[+0x26] = 0xA0        ; 160
        0x45EB8E word[+0x28] = 0
        0x45EB92 byte[+0x2A] = 0
        0x45EB95 [+0x30] = arg2
        0x45EB98 [+0x34] = 0xF4240         ; 分数基数 1,000,000
        0x45EB9F byte[+0x38] = 0
        0x45EBA2.. zero [+0x3C..+0x4F]     （5 dword）
        0x45EBB2.. zero [+0x50..+0x63]     （5 dword）
        0x45EBC5 0x45A070(this+0x64)       ; 内嵌子对象构造（未展开，见 §16.283）
        ```
        """
        for off in (4, 8, 0xC, 0x10, 0x14, 0x18, 0x1C, 0x20,
                    0x3C, 0x40, 0x44, 0x48, 0x4C,
                    0x50, 0x54, 0x58, 0x5C, 0x60):
            self.p4_stat[self.P4_STAT_BASE + off] = 0
        self.p4_stat_w16(0x2C, arg1 & 0xFFFF)
        self.p4_stat_w16(0x24, 0)
        self.p4_stat_w16(0x26, 0xA0)
        self.p4_stat_w16(0x28, 0)
        self.p4_stat_w8(0x2A, 0)
        self.p4_stat[self.P4_STAT_BASE + 0x30] = arg2 & 0xFFFFFFFF
        self.p4_stat[self.P4_STAT_BASE + 0x34] = 0xF4240
        self.p4_stat_w8(0x38, 0)

    def stage_globals_begin(self) -> None:
        """`0x45F5C0(0x4CD4A0)`：**阶段开始**。

        ```
        0x45F5C4 push 0 ; push 0
        0x45F5C8 di = word[esi+0x24]      ; 取关卡号（此时还未被清零）
        0x45F5CC 0x45EB40(this, 0, 0)     ; 重置全部字段
        0x45F5D1 push edi ; 0x45F5D4 0x45EF10(this, di)   ; p4_set_level(关卡号)
        0x45F5D9 byte[+0x38] = 1
        ```

        ★ 顺序：**先取 `[+0x24]`（关卡号）再重置**，因为 `0x45EB40` 会把 `+0x24` 清零。
        照抄这个顺序，否则关卡号会丢。
        """
        level = (self.p4_stat.get(self.P4_STAT_BASE + 0x24, 0)) & 0xFFFF
        self.p4_45eb40(0, 0)
        self.p4_set_level(level)
        self.p4_stat_w8(0x38, 1)

    def stage_globals_end(self) -> None:
        """`0x45F760(0x4CD4A0)`：阶段结算 —— 转调 `p4_45f760`（该函数已按 §16.2xx 实现）。"""
        self.p4_45f760()


# 兼容层：本文件有一部分 `p4_xxx(self, ...)` 辅助函数写在**模块级**（不在 Page4Mixin 类体里），
# 但调用点一律是 `self.p4_xxx(...)`。缺了这层注入，任何走到这些调用点的行为都会
# AttributeError（例：0x26 族的 0x414010 弹流贴图滚动）。只补类里没有的同名函数，
# 不覆盖类内已有实现。
import inspect as _p4_inspect
for _p4_name, _p4_fn in list(globals().items()):
    if not (_p4_name.startswith("p4_") or _p4_name.startswith("_p4_")):
        continue
    if not callable(_p4_fn) or hasattr(Page4Mixin, _p4_name):
        continue
    try:
        _p4_params = list(_p4_inspect.signature(_p4_fn).parameters)
    except (TypeError, ValueError):
        continue
    # 只挂“第一个参数是 self”的辅助函数（纯函数如 _p4_s16(x) 不能当方法）
    if _p4_params and _p4_params[0] == "self":
        setattr(Page4Mixin, _p4_name, _p4_fn)
