#!/usr/bin/env python3
"""一次性离线构建全部 BGM OGG：fluidsynth 渲染 → 归一化/抖动 → ffmpeg 编码 Vorbis。

运行期（remake/pygame/audio.py）优先直接播放 `remake/godot/assets/bgm/bgm_XX.ogg`；
本脚本把它们全部预生成，此后游戏启动零渲染、零 CPU 占用。仅当 OGG 缺失
（或音色库/渲染参数变更）时才需要重跑。

  python3 remake/build_bgm.py            # 全量 20 首（已有的跳过，幂等）
  python3 remake/build_bgm.py 8 15       # 只构建指定曲目

渲染与运行期兜底同参数（fluidsynth -O s32 → _normalize_and_dither 归一+TPDF 抖动
→ s16），子进程 nice 19 并钉在最后 2 个核上——构建期间机器依旧流畅。
"""
import os
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE / "pygame"))
import audio  # noqa: E402  复用渲染参数/归一化/音色库定位

GAME = os.environ.get("GEKI_DIR") or os.path.join(HERE.parent.parent, "geki106")
OUT_DIR = HERE / "godot" / "assets" / "bgm"


def _child_prio() -> None:
    try:
        os.nice(19)
    except OSError:
        pass
    if hasattr(os, "sched_setaffinity"):
        try:
            ncpu = os.cpu_count() or 1
            os.sched_setaffinity(0, {max(0, ncpu - 2), ncpu - 1})
        except (OSError, ValueError):
            pass


def build_track(track: int, sf2: Path, exe: str) -> None:
    out = OUT_DIR / f"bgm_{track:02d}.ogg"
    if out.exists():
        print(f"[build_bgm] #{track:02d} 已有 → 跳过")
        return
    mid = audio.midi_path(track)
    if not mid.exists():
        print(f"[build_bgm] #{track:02d} 缺 MIDI {mid} → 跳过")
        return
    with tempfile.TemporaryDirectory(prefix="geki_bgm_build_") as tmp:
        tmp = Path(tmp)
        wav = tmp / "n.wav"
        raw = tmp / "r.wav"
        subprocess.run(
            [exe, "-ni", "-q", "-g", "0.62", "-r", str(audio.BGM_RATE),
             "-o", "synth.polyphony=512",
             "-o", "synth.min-note-length=20",
             "-o", "synth.reverb.active=1",
             "-o", "synth.reverb.room-size=0.62",
             "-o", "synth.reverb.damp=0.3",
             "-o", "synth.reverb.level=0.75",
             "-o", "synth.chorus.active=1",
             "-o", "synth.chorus.level=1.2",
             "-o", "synth.cpu-cores=1",
             "-O", "s32",
             "-F", str(raw), str(sf2), str(mid)],
            check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            preexec_fn=_child_prio)
        audio._normalize_and_dither(raw, wav)
        subprocess.run(
            ["ffmpeg", "-y", "-hide_banner", "-loglevel", "error",
             "-i", str(wav), "-c:a", "libvorbis", "-q:a", "4", str(out)],
            check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    print(f"[build_bgm] #{track:02d} ← {mid.name} → {out.name}（{out.stat().st_size // 1024} KiB）")


def main() -> None:
    tracks = [int(a) for a in sys.argv[1:]] or list(range(1, 21))
    sf2 = audio._find_soundfont()
    if sf2 is None:
        sys.exit("[build_bgm] 缺音色库（~/.local/share/geki106/soundfonts/ 或系统 sf2/sf3）")
    exe = shutil_which_fluidsynth()
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    print(f"[build_bgm] 音色库 {sf2.name}，fluidsynth {exe}，输出 {OUT_DIR}")
    for t in tracks:
        try:
            build_track(t, sf2, exe)
        except Exception as exc:            # 单曲失败不阻断后续
            print(f"[build_bgm] #{t:02d} 失败：{exc}")
    print("[build_bgm] 完成")


def shutil_which_fluidsynth() -> str:
    exe = os.environ.get("GEKI_FLUIDSYNTH") or None
    import shutil
    exe = shutil.which("fluidsynth") if exe is None else shutil.which(exe)
    if not exe:
        sys.exit("[build_bgm] 缺 fluidsynth")
    return exe


if __name__ == "__main__":
    main()
