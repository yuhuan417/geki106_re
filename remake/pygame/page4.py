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
            self.out[op].append(tuple(int.from_bytes(body[i:i + 4], "little") for i in (0, 4, 8, 0xC)))
        elif op == 0x6:                                          # 0x460554 立即触发
            self.out[6].append((int.from_bytes(body[0:4], "little"), body[4:0x54],
                                int.from_bytes(body[0x54:0x58], "little")))
        elif op == 0x7:                                          # 0x460574 只改参数
            self.out[7].append((int.from_bytes(body[0:4], "little"), body[4:0x54],
                                int.from_bytes(body[0x54:0x58], "little"),
                                int.from_bytes(body[0x58:0x5C], "little")))
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
        self.p4_fast = True                       # 0x450D98 `[App+0x2C4] = 1`
        self.p4_intro_gate = False                # [0x56CCB4]（只有 0x423B7B 置 1）
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
        self.p4_layer_params()                    # 0x450B3D..0x450B68

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
        self.p4_fast = True                       # 0x450D98
        if not self.timer.set_period(0):          # 0x450DA2 0x401CA3 → 0x45A490
            self.flags.set(0x40)                  # 0x450DAB
        self.log("page4.enter（0x4505B0）：参数块 → 0x401EB0 回放头 → 0x458D60 → 21 音效槽 → VM")

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
        if self.p4_fast and self.p4_skip_mod():   # S1-S2 0x45112B/0x451135 0x462D71
            skip = True
        n = 1 if self.p4_fast else 4              # S3 0x451156 neg/sbb/and al,0xFD/add 4
        self.p4_pump(n)                           # S4 0x45116D
        if skip:                                  # 0x451151 jmp 0x451325：整帧跳过绘制
            self.p4_flow_vm()
            self.p4_after_vm()
            return self.flags.is_empty()
        self.p4_debug_text()                      # S5-S6 0x451186（门 0x56CCC9 & 0x56CCB5）
        self.begin_frame()                        # S7 0x458CB0（含 present）
        self.p4_flow_vm()                         # S8 0x450FE0（返回值丢弃）
        self.p4_after_vm()                        # S9-S14
        self.p4_frames += 1                       # S15 0x451442
        self.band_draw()                          # S16 0x451457 0x4562A0
        self.p4_collide()                         # S17-S20 0x451461..0x4514A6
        self.p4_dispatch()                        # S21 0x4514AD 0x458E70
        self.draw()                               # S22 0x4514B2 0x458EF0(App,1)
        self.band_advance()                       # 0x456270（0x458EF0 内尾调）
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
            self.p4_fast_state = 8 if self.p4_fast_state == 1 else 1
            self.p4_fast = self.p4_fast_state == 8

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
        self.p4_fast = True
        self.p4_fast_state = 1
        self.p4_intro_gate = False
        self.p4_skip = 0
        self.sysf2 = Flags()          # 0x4AB5CC
        self.sysb8 = Flags()          # 0x56CCB8
        self.replay_mode = False      # [0x56CCB5]
        self.stage_no = 0             # [0x4AB5C8]（关，0 基）
        self.loop_no = 0              # word[0x4AB5CA]（周目）
        self.p4_cstream: list[tuple[int, int]] = []
        self.p4_collide_ctx = None
        self.p4_ui49c: list = []
        self.p4_emit = []             # 0x4AD55C 发射器 12 通道
        self.p4_seq = None            # 0x4CD484 序列引擎
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
        f = 8 if self.p4_fast_state == 8 else 1
        if f <= 1:
            return False
        return (self.p4_frames % f) != 0

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
        self._tick_posq()                         # 0x4AD43C
        self.tick_ui(self.p4_ui49c)               # 0x4AD49C
        self._tick_wipe4f()                       # 0x4AD4CC
        self._tick_spark4cc()                     # 0x4AD4CC
        self.tick_ui(self.ui4fc)                  # 0x4AD4FC
        self.tick_ui(self.ui52c)                  # 0x4AD52C
        # 0x4AD55C 发射器 / 0x4CD484 序列引擎：待 VM 规格落地后实现

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
