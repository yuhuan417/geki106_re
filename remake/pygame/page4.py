"""页4（游戏本体）—— 按 geki106.exe 反汇编逐步实现。

进入本模块的地址依据（详见 ANALYSIS.md §10.7 / §16.119）：

    页4 handler     0x4593C2   if (0x4505B0(App)) { if (0x451110(App)) while (0x451110(App)); } 0x451C50(App)
    阶段进场        0x4505B0   （每阶段一次）
    进场公共尾      0x450A3D   清统计区 / 状态字回写 / 0x458D60 引擎 / VM 初始化 / 21 槽脚本预载
    每帧            0x451110
    进场帧循环      0x451630   （仅 [0x56CCB4]≠0）
    页收尾          0x451C50
    引擎净化序列    0x458D60   （0x401262 thunk；10 个队列 tick + 0x45EB40 + 0x460930 + 0x45D110 …）

本模块是 `geki.Pages` 的 mixin：所有 `self.*` 都指向 Pages 的实例属性
（layers / canvas / inp / flags / sysf / timer / log / tick_ui / draw …）。
"""

from __future__ import annotations

_P4_BLOCK: dict | None = None

# 0x450BBD..0x450D59：`0x40127B(slot, script_id)` 共 21 条，全部返回真才继续
# （任一条失败 → 0x450D62 `0x4AB5C0 |= 8`）。槽号 0..0x14、脚本 id 见右列。
P4_SCRIPT_SLOTS = [
    (0x00, 0x27), (0x01, 0x28), (0x02, 0x1C), (0x03, 0x1C), (0x04, 0x16),
    (0x05, 0x1E), (0x06, 0x22), (0x07, 0x23), (0x08, 0x20), (0x09, 0x21),
    (0x0A, 0x1D), (0x0B, 0x15), (0x0C, 0x1B), (0x0D, 0x17), (0x0E, 0x26),
    (0x0F, 0x25), (0x10, 0x19), (0x11, 0x1A), (0x12, 0x18), (0x13, 0x1F),
    (0x14, 0x2C),
]

# 0x450AB1..0x450B37：进场清零的统计区（dword）
P4_STAT_ZERO = [0x56CC98, 0x56CC9C, 0x56CCA0, 0x56CCA4, 0x56CCA8, 0x56CCAC,
                0x56CCCC, 0x56CCD0, 0x56CCD4]


class Page4Mixin:
    """页4 的 enter / step / finish（0x4505B0 / 0x451110 / 0x451C50）。"""

    # ---- 0x4505B0 参数块 ------------------------------------------------
    @staticmethod
    def _p4_block_data() -> dict:
        """读 `remake/p4_block.json`（`remake/build_p4_block.py` 从 `0x4505B0` 机械提取）。"""
        global _P4_BLOCK
        if _P4_BLOCK is None:
            import json
            from pathlib import Path
            f = Path(__file__).resolve().parent.parent / "p4_block.json"
            _P4_BLOCK = json.loads(f.read_text(encoding="utf-8"))
        return _P4_BLOCK

    def p4_block(self) -> bytearray:
        """`0x4505B0` 的参数块（0xD2 字节，基址 `[esp+0x10]`；`0x4505F5` 先 `rep stosd` 11 次清零）。

        块尺寸 = `esp+0x10..esp+0xE3` = 0xD4 字节（最后一对 16 位在 `0x450817/0x450821`）。

        分支选择（`0x4505C8` 之后）：
          · `0x450648 0x45B030(0x4AB5B0,1)`：**bit0 清 → 返回 1 → 落到 `0x450651`（A_flag 变体）**；
            bit0 置 → `0x450686` 继续按 `si<8` / `bp<=3` 分 A / B / C。
          · A `0x45069A`（si<8 且 bp<=3）、B `0x450943`（bp>3）、C `0x45096E`（si>=8）。
        块内 +0x10/+0x12/+0x14/+0x16 四个字段是 (关,周目) 查表的结果，其余是常量表。
        """
        d = self._p4_block_data()
        si = int(self.stage_no) & 0xFFFF          # [0x4AB5C8]
        bp = int(self.loop_no) & 0xFFFF           # word[0x4AB5CA]
        tbl = d["tables"]
        if not self.sysw.test(1):                 # bit0 清 ⇒ 0x450651 变体
            blk = bytearray(d["size"])
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
        if si < 8 and bp <= 3:
            name = "A"
        elif si < 8:
            name = "B"
        else:
            name = "C"
        blk = bytearray(d["size"])
        for off, val in d["branches"][name]["imm"].items():
            o = int(off, 16) - 0x10
            blk[o] = val & 0xFF
            blk[o + 1] = (val >> 8) & 0xFF
        def put(o: int, v: int) -> None:            # 块内偏移 → 16 位
            blk[o] = v & 0xFF
            blk[o + 1] = (v >> 8) & 0xFF
        # 查表四字段在 **esp+0x20..0x27 = 块内 0x10..0x17**
        if name == "A":
            put(0x10, si * 4 + 0x0B)               # 0x4506F1/0x450700
            put(0x12, tbl["0xa4"][si + bp * 8])    # 0x450833 → 0x450908
            v = tbl["0x64"][si + bp * 8]           # 0x450903 → 0x45090D
            put(0x14, v)
            put(0x16, min(v // 7, 0x0C))           # 0x450915..0x450932（/7 后钳 0xC）
            blk[0x1A] = 0xFF                       # 0x450939 [esp+0x2A]
        elif name == "B":
            put(0x10, si * 4 + 0x38)               # 0x450943
            put(0x12, 0x320)                       # 0x45094A
            put(0x14, 0x64)                        # 0x450956
            put(0x16, 0x0C)                        # 0x45095D
            blk[0x1A] = 0xFF                       # 0x450964
        else:                                      # C：四张按 bp 查的表（0x4509B7..0x450A21）
            put(0x10, tbl["0x54"][bp])             # [esp+0x20]
            put(0x12, tbl["0x4c"][bp])             # [esp+0x22]
            put(0x14, tbl["0x5c"][bp])             # [esp+0x24]
            put(0x16, tbl["0x3c"][bp])             # [esp+0x26]
            blk[0x19] = 0                          # [esp+0x29]=bl
            blk[0x1A] = tbl["0x44"][bp] & 0xFF     # [esp+0x2A]=dl
        blk[0x1C] = self.sysw.field_get(0xC000) & 0xFF   # 0x450644 [esp+0x2C]
        blk[0x1F] = 1 if self.sysw.test(0x200) else 0    # 0x450611 [esp+0x2F]
        blk[0x20] = 1 if self.sysw.test(1) else 0        # 0x450621 [esp+0x30]
        blk[0x21] = 1 if self.sysw.test(2) else 0        # 0x450634 [esp+0x31]
        return blk

    @staticmethod
    def _p4_sword(b: bytearray, o: int) -> int:
        v = b[o] | (b[o + 1] << 8)
        return v - 0x10000 if v & 0x8000 else v

    @classmethod
    def _p4_dword(cls, b: bytearray, o: int) -> int:
        return b[o] | (b[o + 1] << 8) | (b[o + 2] << 16) | (b[o + 3] << 24)

    @classmethod
    def _p4_sbyte(cls, b: bytearray, o: int) -> int:
        v = b[o]
        return v - 0x100 if v & 0x80 else v

    # ---- 0x4505B0 -----------------------------------------------------
    def p4_enter(self) -> None:
        """阶段进场。正常分支（`0x4505C8 cmp dword[App+0x2BC],0xB` 不等时）。

        参数块（0xD2 字节，基址 `[esp+0x10]`，`0x450A25 lea eax,[esp+0x10]`）由三条分支分别填充：
        `si=[0x4AB5C8]`（关）与 `bp=word[0x4AB5CA]`（周目）决定走哪条。三条分支的字段表
        见 `p4_block()`；两处 4×8 的 16 位表（`[esp+0x64]` 与 `[esp+0xA4]`，索引 `si+bp*8`）
        是各关/各周目的关卡参数。
        """
        self.p4_frames = 0
        self.p4_fast = True                      # 0x450D98 `[esi+0x2C4] = 1`（快进标志）
        self.p4_block_bytes = self.p4_block()    # 0x4505F5..0x450A25

        # 0x450A3D..0x450A83：参数块 → 状态字 0x4AB5B0 的回写
        b = self.p4_block_bytes
        self.sysw.or_andnot(1, self._p4_dword(b, 0x14))       # 0x450A49 0x45B0A0(…,1,?)
        self.sysw.or_andnot(2, self._p4_dword(b, 0x15))       # 0x450A5A 0x45B0A0(…,2,?)
        self.sysw.field_write(0xC000, self._p4_sbyte(b, 0x10))  # 0x450A6F 0x45B0E0(…,0xC000,?)
        self.sysw.or_andnot(0x200, self._p4_dword(b, 0x13))   # 0x450A83 0x45B0A0(…,0x200,?)

        # 0x450A88..0x450AA1：0x458D60(App, a1..a4)
        a1 = self._p4_dword(b, 0x0E)
        a2 = self._p4_sword(b, 0x0C)
        a3 = self._p4_sbyte(b, 0x12)
        a4 = self._p4_sbyte(b, 0x11)
        self.p4_engine(a1, a2, a3, a4)

        # 0x450AAB..0x450B37：统计区与输入/回放标志清零
        self.g56cc94 = 0                          # 0x450AAB byte[0x56CC94] = 0
        for a in P4_STAT_ZERO:                    # 0x450AB1..0x450B37
            self.p4_stats[a] = 0
        self.input_flags.clear()                  # 0x450B05 0x45AF10(0x56CC84, 0)
        self.replay_iface.reset()                 # 0x450B17 0x40224D
        self.p4_layer_params()                    # 0x450B3D..0x450B68 层参数（0x45AFC0 → 0x4010C3）
        self.sysw2.set_or(8)                      # 0x450B78 0x45AF30(?, 8)

        # 0x450B90 0x4013DE(0x4AB454,0,0) = SetBase(0,0)；0x450BA5 首次输入记录
        self.inp.set_base(0, 0)
        self.inp.rec = self.inp.build_record(self.mirror)

        # 0x450BBD..0x450D59：21 条脚本槽预载
        ok = True
        for slot, sid in P4_SCRIPT_SLOTS:
            if not self.cstream.preload(slot, sid):
                ok = False
                break
        if not ok:
            self.flags.set_or(8)                  # 0x450D62 `0x4AB5C0 |= 8`

        # 0x450D6E..0x450DA2
        self.vm46c_init(self._p4_dword(b, 0x0E))  # 0x401D84(0x56CC4C, ?)
        self.input_flags.clear()                  # 0x450D7D 0x45AF10(0x56CC84,0)
        self.vm_reset()                           # 0x450D88 0x402149(0x56CC4C)
        self.p4_fast = True                       # 0x450D98 [esi+0x2C4] = 1
        if not self.timer.reset():                # 0x450DA2 0x401CA3(0x4AB570,0)
            self.flags.set_or(0x40)               # 0x450DAB `0x4AB5C0 |= 0x40`
        self.log("page4.enter（0x4505B0）：参数块 + 0x458D60 + 21 槽预载")

    # ---- 0x458D60 -----------------------------------------------------
    def p4_engine(self, a1: int, a2: int, a3: int, a4: int) -> None:
        """`0x458D60`（`0x401262`）：10 个队列 tick → `0x45EB40(a1,a2)` → `0x460930(a3,a4)`
        → `0x45D110` → `0x45C710(0x4AB5CC, test(0x4AB5B0,1), test(0x4AB5B0,2))`
        → `0x459A80(0x56B95C)` → `0x45AF10(0x56CC84,0)`。"""
        for q in self.p4_queues():                # 0x458D60..0x458DB5
            q.clear()
        self.stage_globals(a1, a2)                # 0x458DBA 0x40163B → 0x45EB40
        self.stage_layers(a3, a4)                 # 0x458DCE 0x402522 → 0x460930
        self.replay_advance()                     # 0x458DE2 0x40160E → 0x45D110
        self.sysf2.set_or(                        # 0x458DF3/0x458E00 `0x45C710(0x4AB5CC,…)`
            (1 if self.sysw.test(1) else 0) | (2 if self.sysw.test(2) else 0))
        self.snapshot_reset()                     # 0x458E15 0x402081 → 0x459A80
        self.input_flags.clear()                  # 0x458E1C 0x45AF10(0x56CC84,0)

    # ---- 0x451110 -----------------------------------------------------
    def p4_step(self) -> bool:
        """页4 每帧（10 步，见 §10.7）。返回 1 = 继续，0 = 结束本页。"""
        # 1-2 快进分支：App[0x2C4]≠0 时只泵一次且跳过等待
        if self.p4_fast:
            self.pump(1)
        else:
            for _ in range(4):
                self.pump(1)
        self.begin_frame()                        # 0x458CB0 → 0x44D740（含 present）

        # 3 流程 VM 每帧一步
        self.p4_flow_vm()                         # 0x450FE0

        # 4 输入记录（+ 回放录制）
        self.inp.rec = self.inp.build_record(self.mirror)
        self.replay_record()

        # 5 光标回中 + 键命令 + 暂停/快进
        self.inp.set_cursor_pos(320, 240)
        key = self.inp.rec.key
        if key:
            self.key_command(key)
        if key == 2:                              # 0x451B10 暂停循环
            self.p4_pause()
        elif key == 5:                            # App[0x2C4] 切换
            self.p4_fast = not self.p4_fast
        self.p4_hud()                             # 0x4517xx HUD / 准星层

        # 6 背景
        self.p4_sequence_tick()                   # 0x4CD484
        self.band_draw()                          # 0x4562A0

        # 7 碰撞三组
        self.p4_collide()

        # 8 行为 + 绘制（含发射器 0x457380）
        self.p4_dispatch()

        # 9 present
        if not self.p4_fast:
            self.draw()

        # 10 进场帧循环
        while self.p4_intro_gate:
            if not self.p4_intro_frame():
                break
        self.p4_frames += 1                       # [0x56CCA8]++
        self.band_advance()                       # 0x456270
        return self.flags.is_empty()              # 0x45AFF0(0x4AB5C0,0)

    # ---- 0x450FE0 -----------------------------------------------------
    def p4_flow_vm(self) -> None:
        """`0x450FE0`（长度 0xF0）：流程 VM 每帧一步 + 命令字分发。

        - `0x450FE5 0x402149(0x56CC4C)` 返回 0 ⇒ 本帧无命令，直接返回。
        - `0x450FF9 0x40145B(0x4AB5B0,1)`（= `0x45B030`，**bit0 清时返回 1**）为真走 0x451091：
          `cmd==0x2E` ⇒ `0x4AB5C0 |= 0x400000`；`cmd==0x58` ⇒ `|= 0x800000`。
        - 否则（bit0 置）取 `cmd=(short)0x40111D(0x56CC4C)`：
          · `cmd==0`：`0x4CD590` 的 `0x401FB9` 为真 ⇒ `0x4CD4A0` 的 `0x401ED3` + `0x4AB5C0 |= 0x200000`；
            否则 `0x401D84(0x56CC4C,9)`（VM 换流）+ `0x45AF10(0x56CC84,0)`。
          · `cmd==9`：`0x4CD4A0.0x401ED3()`，然后
            `0x4AB5C0 |= (0x45AFF0(0x56CCB8,0x40) ? 0x400000 : 0x200000)`
            （`0x45102A neg al/sbb/and 0x200000/add 0x200000` 的等价式）。
          · 其余命令字：什么都不做。
        """
        if not self.flowvm.step():                # 0x450FE5 0x402149
            return
        # `0x450FF9 0x45B030(0x4AB5B0,1)` 在**位已置**时返回 0 ⇒ `je 0x451091`；
        # 即 bit0 置位走 0x2E/0x58 分支，bit0 清零走命令 0/9 分支（与 §10.7 一致）。
        if self.sysw.test(1):                     # 0x450FF2..0x451005
            cmd = self.flowvm.command()           # 0x451091 0x40111D → ax
            if cmd == 0x2E:                       # 0x451096
                self.flags.set_or(0x400000)       # 0x4510A6 0x45AF30(0x4AB5C0,0x400000)
            elif cmd == 0x58:                     # 0x4510B6
                self.flags.set_or(0x800000)       # 0x4510C6
            return
        cmd = self.flowvm.command()               # 0x45100B 0x40111D → ax
        if cmd == 0:
            if self.stage_queue.method_401FB9():  # 0x451055 0x4CD590 的方法
                self.stage_globals_obj.method_401ED3()   # 0x451025
                self.flags.set_or(0x200000)       # 0x451072
                return
            self.flowvm.restart(9)                # 0x45107F 0x401D84(0x56CC4C,9)
            self.input_flags.clear()              # 0x45108B 0x45AF10(0x56CC84,0)
            return
        if cmd == 9:                              # 0x451017
            self.stage_globals_obj.method_401ED3()       # 0x451025
            # 0x45102A..0x451049：0x56CCB8 bit6 置位 ⇒ 0x400000，否则 0x200000
            self.flags.set_or(0x400000 if self.sysw_b8.test(0x40) else 0x200000)
            return

    # ---- 0x451630 -----------------------------------------------------
    def p4_intro_frame(self) -> bool:
        """进场帧循环体（`[0x56CCB4]≠0` 时每帧进）。"""
        self.p4_intro_gate = False                # 清 0x56CCB4
        self.inp.set_preset(5, 320, 240, 0)       # 0x44E620(0x4AB454, 5, 320, 240, 0)
        self.pump(1)
        key = self.inp.rec.key
        if key:
            self.key_command(key)
        self.inp.rec = self.inp.build_record(self.mirror)
        self.p4_hud()
        return self.flags.is_empty()

    # ---- 0x451C50 -----------------------------------------------------
    def p4_finish(self) -> None:
        """页收尾：停 BGM → 填色 + present → 释放层。"""
        self.audio.stop_bgm()
        self.p4_release_layers()
        self.log("page4.finish（0x451C50）")
