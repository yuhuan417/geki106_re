#!/usr/bin/env python3
"""一次性离线构建全部 BGM OGG：fluidsynth 渲染 → 归一化/抖动 → ffmpeg 编码 Vorbis。

运行期（remake/pygame/audio.py）优先直接播放 `remake/godot/assets/bgm/bgm_XX.ogg`；
本脚本把它们全部预生成，此后游戏启动零渲染、零 CPU 占用。仅当 OGG 缺失
（或音色库/渲染参数变更）时才需要重跑。每份输出长度精确匹配 MIDI End-of-Track 时长。

  python3 remake/build_bgm.py            # 全量 20 首，并行吃满全部 CPU（默认，尽快完成）
  python3 remake/build_bgm.py --nice     # 温柔模式：单进程 nice 19 钉最后 2 核（边玩游戏边构建用）
  python3 remake/build_bgm.py --force       # 全曲库按当前 MIDI 时值重新构建
  python3 remake/build_bgm.py 8 15       # 只构建指定曲目
"""
import argparse
import concurrent.futures
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE / "pygame"))
import audio  # noqa: E402  复用渲染参数/归一化/音色库定位

OUT_DIR = HERE / "godot" / "assets" / "bgm"


def _child_prio(gentle: bool):
    """gentle（--nice）：单进程 nice 19 钉最后 2 核，边玩游戏边构建；
    默认（离线全速）：不加任何限制，fluidsynth 并行吃满全部核。"""
    if not gentle:
        return None

    def _prio() -> None:
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
    return _prio


def build_track(track: int, sf2: Path, exe: str, gentle: bool, force: bool) -> str:
    out = OUT_DIR / f"bgm_{track:02d}.ogg"
    if out.exists() and not force:
        return f"#{track:02d} 已有 → 跳过"
    mid = audio.midi_path(track)
    if not mid.exists():
        return f"#{track:02d} 缺 MIDI {mid} → 跳过"
    with tempfile.TemporaryDirectory(prefix="geki_bgm_build_") as tmp:
        tmp = Path(tmp)
        wav = tmp / "n.wav"
        raw = tmp / "r.wav"
        midi_timed = tmp / "midi-timed.wav"
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
            preexec_fn=_child_prio(gentle))
        audio._normalize_and_dither(raw, wav)
        audio._trim_rendered_audio_to_midi_end(wav, midi_timed, mid)
        subprocess.run(
            ["ffmpeg", "-y", "-hide_banner", "-loglevel", "error",
             "-i", str(midi_timed), "-c:a", "libvorbis", "-q:a", "4", str(out)],
            check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return f"#{track:02d} ← {mid.name} → {out.name}（{out.stat().st_size // 1024} KiB）"


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("tracks", nargs="*", type=int, help="只构建这些曲目（默认全部 1..20）")
    ap.add_argument("--nice", action="store_true",
                    help="温柔模式：单进程 nice 19 钉最后 2 核（默认并行吃满全部 CPU）")
    ap.add_argument("--force", action="store_true", help="覆盖已存在的 OGG")
    args = ap.parse_args()
    tracks = args.tracks or list(range(1, 21))
    sf2 = audio._find_soundfont()
    if sf2 is None:
        sys.exit("[build_bgm] 缺音色库（~/.local/share/geki106/soundfonts/ 或系统 sf2/sf3）")
    exe = shutil.which("fluidsynth")
    if not exe:
        sys.exit("[build_bgm] 缺 fluidsynth")
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    jobs = 1 if args.nice else max(1, os.cpu_count() or 1)
    print(f"[build_bgm] 音色库 {sf2.name}｜fluidsynth {exe}｜并行 {jobs}｜输出 {OUT_DIR}")
    done = 0
    with concurrent.futures.ThreadPoolExecutor(max_workers=jobs) as pool:
        futs = {pool.submit(build_track, t, sf2, exe, args.nice, args.force): t
                for t in tracks}
        for fut in concurrent.futures.as_completed(futs):
            try:
                print("[build_bgm]", fut.result(), flush=True)
                done += 1
            except Exception as exc:            # 单曲失败不阻断后续
                print(f"[build_bgm] #{futs[fut]:02d} 失败：{exc}")
    print(f"[build_bgm] 完成 {done}/{len(tracks)}")


if __name__ == "__main__":
    main()
