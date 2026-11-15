"""音频子系统（pygame）：`0x4AB4B0` 波形槽管理器 + `0x4AB514` BGM。

反汇编定案（本文件的常量/语义都出自这里）：

- `0x450140(mgr, slot, res)`：把 wave 资源 #res 装进槽 slot。槽指针数组在 `mgr+8+slot*4`，
  失败打印 `"Could not open wave file!"`（0x4A4860）。⇒ 这是**波形装载**。
- `0x450440(mgr, arg)`：`arg != 0` → 旋律指针 `[mgr+0x60] = 0`（复位）；
  `arg == 0` → 停旧音、`SetFrequency(f)`、`Play`：
  `f = byte[0x498FEC[idx]] * 128 + 0x2B11`（0x2B11 = 11025），`idx++`，
  `byte[0x498FEC[idx]] == 0` 时 `idx = 0`（表 40 项 + 0 终止）。
  播的是槽 **1**（`mgr+0xC` = `mgr+8+1*4`）；前置门 `[mgr+4]`/`[mgr+0xC]`/`[mgr+0x5D]` 非 0。
- `0x450580(mgr, a, b)`：`[mgr+0x5C] = a`、`[mgr+0x5D] = b`。
- `0x44F600(0x4AB514, loop, id)`：播 BGM #id（资源 rom#1..20）；`0x44FDD0(0x4AB514)` 停。

播放等价：原作 SE 是 11025Hz 单声道 s16，靠 `SetFrequency` 变调。pygame 的 mixer 固定
44100Hz，所以用重采样复现同一效果：把 n 个样本重采样成 `n*44100/f` 个后以 44100 播放，
音高 = f/11025，时长 = n/f（f = 11025 时就是 4 倍上采样、音高不变）。
"""
from __future__ import annotations

import subprocess
import tempfile
import wave
from pathlib import Path

import numpy as np

HERE = Path(__file__).resolve().parent
REPO = HERE.parent.parent

SRC_RATE = 11025          # 0x2B11
MIX_RATE = 44100          # mixer 固定采样率
# 0x498FEC：40 字节频率索引表，其后一个 0 字节（0x4504a8 用它判断回绕）
FREQ_TABLE = bytes([
    0x83, 0x2B, 0x83, 0x6B, 0x56, 0x4C, 0x56, 0x90, 0x90, 0x90,
    0x2B, 0x83, 0x33, 0x83, 0x6B, 0x56, 0x4C, 0x56, 0x6B, 0x6B,
    0x6B, 0x77, 0x83, 0x2B, 0x83, 0x6B, 0x56, 0x4C, 0x56, 0xCC,
    0xCC, 0xCC, 0xAC, 0x90, 0x83, 0x6B, 0x56, 0x3B, 0x4C, 0x56,
])                        # 表尾 0x498FEC+40 处是 0x00

SF2_CANDIDATES = (
    "/usr/share/sounds/sf2/FluidR3_GM.sf2",
    "/usr/share/sounds/sf2/default-GM.sf2",
    "/usr/share/sounds/sf2/TimGM6mb.sf2",
    "/usr/share/soundfonts/default.sf2",
)


def se_path(res_id: int) -> Path:
    return REPO / "extracted" / "wave" / f"se_{res_id:02d}.wav"


def bgm_path(track: int) -> Path:
    return HERE.parent / "godot" / "assets" / "bgm" / f"bgm_{track:02d}.ogg"


def midi_path(track: int) -> Path:
    return REPO / "extracted" / "midi" / f"bgm_{track:02d}.mid"


def _resample(x: np.ndarray, factor: float) -> np.ndarray:
    """线性重采样：n 个样本 → n*factor 个（factor>1 变长/降低音高）。"""
    n = len(x)
    m = max(1, int(round(n * factor)))
    if m == n:
        return x
    src = np.arange(n, dtype=np.float64)
    dst = np.linspace(0.0, n - 1, m)
    return np.interp(dst, src, x).astype(np.float32)


class Audio:
    """`0x4AB4B0`（波形槽）+ `0x4AB514`（BGM）的 pygame 等价物。

    `enabled=False`（`--mute` / mixer 起不来）时所有调用都退化成"仅返回结果"，
    与页机记录的旗标语义保持一致（load_wave 返回 True 表示"不看音频也当成功"）。
    """

    def __init__(self, enabled: bool = True, verbose: bool = True) -> None:
        self.enabled = False
        self.reason = "off"
        self.slots: dict[int, tuple[np.ndarray, int]] = {}
        self._snd_cache: dict[tuple[int, int], object] = {}
        self.melody_idx = 0            # [mgr+0x60]
        self.gate_5c = 1               # [mgr+0x5C]
        self.gate_5d = 1               # [mgr+0x5D]，0x450440 的前置门之一
        self.bgm_byte50 = 1            # [0x4AB514+0x50]，0x44F640 BGM 播放的音楽开关
        self.bgm_id: int | None = None
        self.verbose = verbose
        if not enabled:
            self.reason = "muted"
            return
        try:
            import pygame

            pygame.mixer.pre_init(MIX_RATE, -16, 2, 1024)
            pygame.mixer.init()
            self._pg = pygame
            self.enabled = True
            self.reason = f"mixer {pygame.mixer.get_init()} driver={self._driver(pygame)}"
        except Exception as exc:                     # 无声卡/驱动异常 → 静音降级
            self.reason = f"disabled: {exc}"

    @staticmethod
    def _driver(pygame) -> str:
        try:
            return pygame.mixer.get_driver() or "?"
        except Exception:
            return "?"

    def _say(self, msg: str) -> None:
        if self.verbose:
            print(f"[audio] {msg}", flush=True)

    # ---------------------------------------------------------------- 波形槽
    def load_wave(self, slot: int, res_id: int) -> bool:
        """`0x450140(mgr, slot, res_id)`：把 se_XX.wav 装进槽 slot。"""
        if not self.enabled:
            return True                              # 与原件"无音频子系统"路径一致：不置错误旗标
        path = se_path(res_id)
        try:
            with wave.open(str(path), "rb") as w:
                ch, sw, rate = w.getnchannels(), w.getsampwidth(), w.getframerate()
                raw = w.readframes(w.getnframes())
        except Exception as exc:
            self._say(f"wave #{res_id} 打开失败（0x4A4860）：{exc}")
            return False
        if sw != 2:
            self._say(f"wave #{res_id} 采样宽度 {sw} 不支持")
            return False
        x = np.frombuffer(raw, dtype="<i2").astype(np.float32) / 32768.0
        if ch > 1:
            x = x.reshape(-1, ch).mean(axis=1)
        self.slots[int(slot)] = (x, rate)
        self.melody_idx = 0                          # 装新波形 ⇒ 旋律回到表头
        self._say(f"slot {slot} ← wave #{res_id}（{len(x)} 帧 @ {rate}Hz）")
        return True

    # ---------------------------------------------------------------- 旋律
    def melody_reset(self) -> None:
        """`0x450440(mgr, 非0)`：旋律指针归零。"""
        self.melody_idx = 0

    def melody_step(self) -> bool:
        """`0x450440(mgr, 0)`：按 0x498FEC 播槽 1 的下一个音，指针前进并回绕。"""
        if not self.enabled:
            return False
        if not (self.gate_5c and self.gate_5d):
            return False                             # 0x450464/0x45045c 的两道门
        entry = self.slots.get(1)
        if entry is None:
            return False                             # [mgr+0xC] == 0
        i = self.melody_idx
        freq = SRC_RATE + FREQ_TABLE[i] * 128        # 0x450488: cl*128 + 0x2b11
        snd = self._snd_cache.get((1, freq))
        if snd is None:
            x, _rate = entry
            y = _resample(x, MIX_RATE / float(freq))  # n*44100/f
            pcm = (np.clip(y, -1.0, 1.0) * 32767.0).astype("<i2")
            stereo = np.repeat(pcm[:, None], 2, axis=1).reshape(-1)
            snd = self._pg.mixer.Sound(buffer=stereo.tobytes())
            snd.set_volume(0.55)
            self._snd_cache[(1, freq)] = snd
        snd.play()
        self.melody_idx = i + 1                      # 0x4504a2
        if self.melody_idx >= len(FREQ_TABLE) or FREQ_TABLE[self.melody_idx] == 0:
            self.melody_idx = 0                      # 0x4504b2
        return True

    # ---------------------------------------------------------------- BGM
    def bgm(self, track: int, loop: bool = True) -> bool:
        """`0x44F600(0x4AB514, loop, id)`：播 BGM #track（1..20）。
        0x44F640：byte[0x50]（音楽开关，調整行 2 写入）为 0 ⇒ 不播放。"""
        if not self.bgm_byte50:
            return True                             # 0x44F645 je 0x44F860：音楽 OFF
        if not self.enabled:
            self._say(f"BGM #{track}（静音模式）")
            return True
        path = self._resolve_bgm(track)
        if path is None:
            return False
        try:
            self._pg.mixer.music.load(str(path))
            self._pg.mixer.music.set_volume(0.45)
            self._pg.mixer.music.play(-1 if loop else 0)
            self.bgm_id = track
            self._say(f"BGM #{track} ← {path.name}")
            return True
        except Exception as exc:
            self._say(f"BGM #{track} 播放失败：{exc}")
            return False

    def bgm_stop(self) -> None:
        """`0x44FDD0(0x4AB514)`：停 BGM。"""
        self.bgm_id = None
        if not self.enabled:
            return
        try:
            self._pg.mixer.music.stop()
        except Exception:
            pass

    def bgm_volume(self, v: int) -> None:
        """`0x44F950(0x4AB514, v)`：GM SysEx 主音量（F0 7F 7F 04 01 00 v F7，v=0..127）。

        0x61000007（0x427690）每 8 帧发一次。复刻后端没有 MIDI 直通 ⇒ 折算成
        `mixer.music` 音量（bgm() 的基准 0.45 对应 v=127）。"""
        v = max(0, min(127, int(v)))
        self.bgm_vol = v
        if not self.enabled:
            return
        try:
            self._pg.mixer.music.set_volume(0.45 * v / 127)
        except Exception:
            pass

    def _resolve_bgm(self, track: int):
        """优先用编译好的 OGG；没有就用 fluidsynth 现渲（结果缓存在 /tmp）。"""
        ogg = bgm_path(track)
        if ogg.exists():
            return ogg
        mid = midi_path(track)
        if not mid.exists():
            self._say(f"BGM #{track}：既无 OGG 也无 MIDI")
            return None
        sf2 = next((p for p in SF2_CANDIDATES if Path(p).exists()), None)
        import shutil

        exe = shutil.which("fluidsynth")
        if not sf2 or not exe:
            self._say(f"BGM #{track}：缺 fluidsynth/音色库，无法渲染")
            return None
        out = Path(tempfile.gettempdir()) / f"geki_bgm_{track:02d}.wav"
        if not out.exists() or out.stat().st_mtime < mid.stat().st_mtime:
            try:
                subprocess.run([exe, "-ni", "-g", "0.7", "-F", str(out), sf2, str(mid)],
                               check=True, stdout=subprocess.DEVNULL,
                               stderr=subprocess.DEVNULL)
            except Exception as exc:
                self._say(f"BGM #{track} fluidsynth 渲染失败：{exc}")
                return None
        return out

    def close(self) -> None:
        self.bgm_stop()
        if self.enabled:
            try:
                self._pg.mixer.quit()
            except Exception:
                pass
            self.enabled = False
