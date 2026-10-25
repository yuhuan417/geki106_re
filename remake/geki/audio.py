"""音频子系统 (可选): MIDI BGM + PCM 音效.

原作: BGM = DirectMusic 播放 Huffman 解压出的 SMF; SE = DirectSound s16 PCM
      (SetFrequency 变调表 freq=11025+tbl[i]*128, tbl@exe 0x498FEC).
重制: MIDI 优先 fluidsynth/timidity 外部渲染, 不可用则静音; WAV 用 pygame.mixer.
"""
from __future__ import annotations

import os
import shutil
import subprocess
import tempfile

from . import assets

# 每资源变调表 (40 字节, 从 exe 0x498FEC 导出)
FREQ_TABLE = [131, 43, 131, 107, 86, 76, 86, 144, 144, 144, 43, 131, 51, 131,
              107, 86, 76, 86, 107, 107, 107, 119, 131, 43, 131, 107, 86, 76,
              86, 204, 204, 204, 172, 144, 131, 107, 86, 59, 76, 86]

BASE_RATE = 11025


class Audio:
    def __init__(self, res: assets.Resources):
        self.res = res
        self.enabled = False
        self._midi_proc = None
        self._tmpdir = None
        try:
            import pygame.mixer

            pygame.mixer.pre_init(BASE_RATE, -16, 1, 512)
            pygame.mixer.init()
            self.enabled = True
            self.sounds = {}
            self._load_sounds()
        except Exception as e:
            print(f"[audio] disabled: {e}")
            self.sounds = {}

    def _load_sounds(self):
        import pygame

        import pygame.mixer

        for idx in range(21, 45):
            pcm = self.res.get(idx)
            rate = BASE_RATE + FREQ_TABLE[idx - 21] * 128
            try:
                snd = pygame.mixer.Sound(buffer=bytes(pcm))
                # pygame.mixer 以 mixer 初始化速率播放; 变调通过 Sound.set_volume 近似不可行,
                # 精确重采样在重制后期用 numpy 实现.
                self.sounds[idx] = snd
            except Exception:
                pass

    # ------------------------------------------------------------- BGM
    def play_midi(self, resource_idx: int):
        """解出 SMF 到临时文件, 用 fluidsynth/timidity 播放."""
        if self._midi_proc:
            self.stop_midi()
        try:
            smf = assets.load_midi(self.res, resource_idx)
        except Exception as e:
            print(f"[audio] midi {resource_idx} decode fail: {e}")
            return
        if self._tmpdir is None:
            self._tmpdir = tempfile.mkdtemp(prefix="geki_midi_")
        path = os.path.join(self._tmpdir, f"bgm_{resource_idx}.mid")
        open(path, "wb").write(smf)
        for cmd, args in (("fluidsynth", ["-ni", "-g", "0.5", path]),
                          ("timidity", [path])):
            exe = shutil.which(cmd)
            if exe:
                self._midi_proc = subprocess.Popen(
                    [exe] + args, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                return
        print(f"[audio] no MIDI player (saved {path})")

    def stop_midi(self):
        if self._midi_proc:
            self._midi_proc.terminate()
            self._midi_proc = None

    def se(self, resource_idx: int):
        snd = self.sounds.get(resource_idx)
        if snd:
            snd.play()
