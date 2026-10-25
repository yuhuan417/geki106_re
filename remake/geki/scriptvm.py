"""关卡脚本 VM + 弹幕发射器 (从 exe 0x460350 / 0x457C00 还原).

记录: u16 opcode | u16 frame | args
每帧: 执行所有 time<=frame 的记录, 然后 frame++.
op0 = 载入 ID 队列中的下一个 stream (关卡链).
发射器 = 12 通道, 每通道 20 个 16.16 定点 state + 20 个 per-frame delta.
"""
from __future__ import annotations

import struct
from dataclasses import dataclass, field

FIXED = 1 << 16


def fp(v: int) -> float:
    return v / FIXED


def to_fp(v: float) -> int:
    return int(v * FIXED)


SIZES = {0: 0, 1: 20, 2: 20, 3: 20, 4: 20, 5: 20, 6: 92, 7: 96, 8: 8, 0xA: 12, 0xB: 60, 0xC: 8, 0xD: 8, 0xE: 20}


@dataclass
class Cmd:
    """op1-5 的 4 参数命令 (进入对应引擎队列)."""
    a: int
    b: int
    c: int
    d: int


@dataclass
class EmitterState:
    """单通道: state[20] 运行状态, delta[20] 每帧增量 (16.16)."""
    active: bool = False
    state: list[int] = field(default_factory=lambda: [0] * 20)
    delta: list[int] = field(default_factory=lambda: [0] * 20)
    burst: int = 0          # ch+0x2A88 连发计数
    burst_arg: int = 0      # ch+0x2A8C
    accum: int = 0          # ch+0x2A94 间隔累加器
    bullets: list = field(default_factory=list)


class EmitterBank:
    """12 通道发射器. state 字段 (下标 = (偏移-ch基址-0x30)//4):
    10/11: rand 上限 (散布), 15..18: 4 外观权重, 12: 间隔阈值, 13: 速率, 10.: ...
    已知: state[12]=interval state[13]=rate state[10]/[11]=随机散布 state[15..18]=权重
    """

    INTERVAL = 12  # ch+0x64
    RATE = 13      # ch+0x68
    COUNT = 10     # ch+0x58 (间隔复位的计数)

    def __init__(self, rng):
        self.channels = [EmitterState() for _ in range(12)]
        self.rng = rng
        self.fired = []  # 本帧新生成的弹 (引擎取走)

    def one_shot(self, idx: int, params: bytes, burst: int):
        """op6: 激活通道 + 设参数 + 立即连发 (记录尾 1 个 dword)."""
        if idx >= 12:
            for ch in self.channels:
                self._define(ch, params, burst, 0, activate=True)
        else:
            self._define(self.channels[idx], params, burst, 0, activate=True)

    def define(self, idx: int, params: bytes, arg1: int, arg2: int):
        """op7: 仅对已激活通道生效 (记录尾 2 个 dword)."""
        if idx >= 12:
            for ch in self.channels:
                self._define(ch, params, arg1, arg2, activate=False)
        else:
            self._define(self.channels[idx], params, arg1, arg2, activate=False)

    def stop(self, idx: int):
        if idx >= 12:
            for ch in self.channels:
                ch.active = False
        else:
            self.channels[idx].active = False

    def _define(self, ch: EmitterState, params: bytes, arg1: int, arg2: int, activate: bool):
        if activate:
            ch.active = True
        elif not ch.active:
            return
        ch.burst = arg1
        ch.burst_arg = arg2
        ch.delta = list(struct.unpack("<20i", params[:80]))

    def update(self):
        """每帧: 状态积分 + 连发 + 间隔生成."""
        for ch in self.channels:
            if not ch.active:
                continue
            # state += delta (20 字段)
            for i in range(20):
                ch.state[i] += ch.delta[i]
            if ch.burst > 0:
                self._fire(ch)
                ch.burst -= 1
            # 间隔累加器
            ch.accum += ch.state[self.RATE]
            acc = ch.accum
            if acc < 0:
                acc = -acc
            if acc >= ch.state[self.INTERVAL]:
                if ch.state[self.RATE] >= 0:
                    ch.accum = acc - ch.state[self.INTERVAL]
                    self._fire(ch)
                else:
                    ch.accum = ch.state[self.INTERVAL] - acc
                    self._fire(ch)

    def _fire(self, ch: EmitterState):
        st = ch.state
        jx = self.rng.randrange(st[10] + 1) if st[10] > 0 else 0
        jy = self.rng.randrange(st[11] + 1) if st[11] > 0 else 0
        w = [st[15] & 0xFFFF, st[16] & 0xFFFF, st[17] & 0xFFFF, st[18] & 0xFFFF]
        total = sum(w)
        kind = 0
        if total > 0:
            r = self.rng.randrange(total)
            for i, wi in enumerate(w):
                if r < wi:
                    kind = i
                    break
                r -= wi
        self.fired.append({
            "x": st[0] + jx, "y": st[1] + jy,
            "vx": st[2], "vy": st[3], "kind": kind, "state": list(st),
        })


class StreamVM:
    """单条脚本的执行器; op0 触发 next_stream 回调."""

    def __init__(self, data: bytes):
        self.data = data
        self.pos = 0
        self.frame = 0
        self.done = False
        self.name = ""
        # 输出队列
        self.q: dict[int, list[Cmd]] = {1: [], 2: [], 3: [], 4: [], 5: []}
        self.emitters: EmitterBank | None = None
        self.layers: list[int] | None = None
        self.param: int | None = None
        self.transition: int | None = None
        self.tables: list[tuple] = []
        self.misc: list[tuple] = []
        self.next_stream_requested = False

    def bind(self, emitters: EmitterBank):
        self.emitters = emitters

    def tick(self):
        """一帧: 消化所有到期记录."""
        data = self.data
        n = len(data)
        fired_any = False
        while not self.done and self.pos + 4 <= n:
            op, time = struct.unpack("<HH", data[self.pos : self.pos + 4])
            if op > 0xE:
                self.done = True
                break
            if time > self.frame:
                break
            if op == 9:
                cnt = struct.unpack("<I", data[self.pos + 12 : self.pos + 16])[0]
                size = 16 + cnt * 4
            else:
                size = SIZES[op]
            if op == 0:
                self.next_stream_requested = True
                self.pos += 4
                self.done = True
                break
            body = data[self.pos + 4 : self.pos + size]
            self._exec(op, body)
            self.pos += size
            fired_any = True
        self.frame += 1
        return fired_any

    def _exec(self, op: int, body: bytes):
        if op == 0xE:
            self.name = body.split(b"\0")[0].decode("ascii", "replace")
        elif op in (1, 2, 3, 4, 5):
            a, b, c, d = struct.unpack("<4I", body[:16])
            self.q[op].append(Cmd(a, b, c, d))
        elif op == 6:
            idx = struct.unpack("<I", body[:4])[0]
            (burst,) = struct.unpack("<1I", body[84:88])
            self.emitters.one_shot(idx, body[4:84], burst)
        elif op == 7:
            idx = struct.unpack("<I", body[:4])[0]
            a1, a2 = struct.unpack("<2I", body[84:92])
            self.emitters.define(idx, body[4:84], a1, a2)
        elif op == 8:
            idx = struct.unpack("<I", body[:4])[0]
            self.emitters.stop(idx)
        elif op == 9:
            a0, a1, cnt = struct.unpack("<3I", body[:12])
            vals = list(struct.unpack(f"<{cnt}I", body[12 : 12 + cnt * 4]))
            self.tables.append((a0, a1, vals))
        elif op == 0xA:
            a, b = struct.unpack("<2I", body[:8])
            self.misc.append((a, b))
        elif op == 0xB:
            self.layers = list(struct.unpack("<14I", body[:56]))
        elif op == 0xC:
            self.transition = struct.unpack("<I", body[:4])[0]
        elif op == 0xD:
            self.param = struct.unpack("<I", body[:4])[0]


class StageRunner:
    """持有 ID 队列, 按 op0 链式加载 stream (exe CStream 队列行为)."""

    PRELOAD_IDS = (0x2E, 0x2F, 0x30, 0x31, 0x32, 0x33, 0x34, 0x3C)

    def __init__(self, res, emitters: EmitterBank, first_id: int, queue: list[int]):
        self.res = res
        self.emitters = emitters
        self.queue = list(queue)  # 后续 stream id 队列 ([this+8..0x28] 的 16 槽)
        self.vm = self._load(first_id)

    def _load(self, idx: int) -> StreamVM:
        vm = StreamVM(self.res.get(idx))
        vm.bind(self.emitters)
        return vm

    def tick(self):
        self.vm.tick()
        if self.vm.next_stream_requested and self.queue:
            nxt = self.queue.pop(0)
            self.vm = self._load(nxt)
