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
        cmd = self.flow_vm_step()                 # 0x450FE0 → 0x460350(0x56CC4C)
        self.flow_vm_command(cmd)

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
