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

import hashlib
import shutil
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

# BGM 渲染设置。原作是 DirectMusic + 系统 GM 合成器；复刻侧用 fluidsynth 离线渲染成
# 波形后交给 pygame.mixer.music 无限循环。曲目 MIDI 的 EOT 常带数秒**数字静音**尾
# （bgm_08 有 9s、bgm_20 有 8s），直接整段循环会在每圈末尾静音一段——用户实测
# "音乐放完没声音，过一会才继续"。渲染后裁掉尾部纯静音即可无缝循环。
BGM_RATE = 48000
BGM_SETTINGS_VERSION = 2
SF2_ENV = "GEKI_SF2"
SF2_CANDIDATES = (
    # 用户自备/本仓库脚本装到用户目录的高质量音色库优先（MuseScore General）。
    str(Path.home() / ".local/share/geki106/soundfonts/MuseScore_General_Full.sf3"),
    "/usr/share/sounds/sf3/MuseScore_General_Full.sf3",
    "/usr/share/sounds/sf2/MuseScore_General.sf2",
    # 系统 GM 音色库：FluidR3 比 TimGM6mb 好，放最后兜底。
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


def _find_soundfont() -> Path | None:
    """按优先级找可用音色库；`GEKI_SF2` 可强制指定。"""
    import os
    env = os.environ.get(SF2_ENV)
    if env:
        p = Path(env).expanduser()
        if p.exists():
            return p
    user_dir = Path.home() / ".local/share/geki106/soundfonts"
    for pat in ("*.sf3", "*.sf2"):
        for p in sorted(user_dir.glob(pat)):
            return p
    for name in SF2_CANDIDATES:
        p = Path(name).expanduser()
        if p.exists():
            return p
    return None


def _trim_trailing_silence(src: Path, dst: Path) -> None:
    """把 fluid 渲染出的 WAV 尾部**纯数字静音**裁掉，保留 80ms 余量。

    只裁 `sample == 0` 的尾巴（不含混响衰减），因此不会吃掉真实的弱音尾；
    裁完的波形让 `mixer.music.play(-1)` 的循环点贴住最后一个发声样本，
    消除 MIDI EOT 多余静音造成的循环空档。顺带把整体峰值归一到 0.89，
    避免不同曲目音量差过大（原件由系统合成器统一增益）。
    """
    try:
        with wave.open(str(src), "rb") as w:
            ch, sw, rate, n = (w.getnchannels(), w.getsampwidth(),
                               w.getframerate(), w.getnframes())
            raw = w.readframes(n)
    except Exception:
        shutil.copyfile(src, dst)
        return
    if sw != 2 or ch < 1 or not raw:
        shutil.copyfile(src, dst)
        return
    a = np.frombuffer(raw, dtype="<i2")
    frames = a.reshape(-1, ch)
    # 从尾部按块找最后一个**可闻**样本（整段 300s 也不会爆内存）。
    # 不能判 `!= 0`：MuseScore 音色库渲染尾部有 -90dB 级的稀疏抖动样本，
    # 会把 9s 静音误当成"还有声音"，循环空档依旧。
    last = -1
    block = 1 << 20
    for end in range(len(frames), 0, -block):
        start = max(0, end - block)
        nz = np.flatnonzero(np.any(np.abs(frames[start:end].astype(np.int32)) > 3, axis=1))
        if nz.size:
            last = start + int(nz[-1])
            break
    if last < 0:
        shutil.copyfile(src, dst)
        return
    keep = min(len(frames), last + 1 + int(0.15 * rate))
    out = frames[:keep].astype(np.float32)
    peak = float(np.abs(out).max()) / 32768.0
    if peak > 0.0:
        out *= min(1.0, 0.89 / peak)
    pcm = np.clip(out, -32768, 32767).astype("<i2")
    with wave.open(str(dst), "wb") as w:
        w.setnchannels(ch)
        w.setsampwidth(2)
        w.setframerate(rate)
        w.writeframes(pcm.tobytes())


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
        """优先用编译好的 OGG；没有就用 fluidsynth 现渲（结果缓存在 /tmp）。

        渲染链（2026-11-19 用户反馈后重做）：
        1) 音色库优先 MuseScore General（`~/.local/share/geki106/soundfonts` 或系统），
           其次 FluidR3；可用 `GEKI_SF2` 指定。FluidR3 在 -g 0.7 下实测有削波（0.09%），
           这正是"听着很廉价"的一部分来源。
        2) 48kHz / 512 复音 / 混响合唱打开，减少 GM 干硬感。
        3) **裁掉尾部纯数字静音**后再循环：MIDI 的 EOT 带数秒静音（#8 有 9s），
           不裁的话每圈都会静音一段，正是用户报的"放完没声音，过一会才续"。
        """
        ogg = bgm_path(track)
        if ogg.exists():
            return ogg
        mid = midi_path(track)
        if not mid.exists():
            self._say(f"BGM #{track}：既无 OGG 也无 MIDI")
            return None
        sf2 = _find_soundfont()
        exe = shutil.which("fluidsynth")
        if not sf2 or not exe:
            self._say(f"BGM #{track}：缺 fluidsynth/音色库，无法渲染")
            return None
        tag = hashlib.sha1(
            f"{mid.stat().st_mtime}:{sf2.stat().st_mtime}:{BGM_SETTINGS_VERSION}".encode()
        ).hexdigest()[:10]
        out = Path(tempfile.gettempdir()) / f"geki_bgm_{track:02d}_{tag}.wav"
        if out.exists() and out.stat().st_mtime >= mid.stat().st_mtime:
            return out
        tmp = out.with_suffix(".raw.wav")
        try:
            subprocess.run(
                [exe, "-ni", "-q", "-g", "0.62", "-r", str(BGM_RATE),
                 "-o", "synth.polyphony=512",
                 "-o", "synth.reverb.active=1",
                 "-o", "synth.reverb.room-size=0.65",
                 "-o", "synth.reverb.level=0.75",
                 "-o", "synth.chorus.active=1",
                 "-F", str(tmp), str(sf2), str(mid)],
                check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            _trim_trailing_silence(tmp, out)
            self._say(f"BGM #{track} ← {sf2.name} → {out.name}")
            return out
        except Exception as exc:
            self._say(f"BGM #{track} fluidsynth 渲染失败：{exc}")
            return None
        finally:
            try:
                tmp.unlink()
            except OSError:
                pass

    def close(self) -> None:
        self.bgm_stop()
        if self.enabled:
            try:
                self._pg.mixer.quit()
            except Exception:
                pass
            self.enabled = False
