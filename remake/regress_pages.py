#!/usr/bin/env python3
"""页1/2/3/13 冻结区回归：把这些页在固定帧上的截图做 sha256 对表，任何像素变化都报错。

背景：页1/2/3/13 已定案（§16.4/§16.9/§16.11/§16.22/§16.118），后续只在页4 上推进。
任何共享代码（`Layers.load`、`draw()` 合成顺序、色键/表面尺寸…）的改动都可能无声破坏它们，
所以这里用"金标截图哈希"当护栏。

用法:
    python3 remake/regress_pages.py            # 校验，全部一致 → exit 0，否则列出差异并 exit 1
    python3 remake/regress_pages.py --update   # 有意改动后重打金标（会同时 regenerate golden_pages.json）

金标文件: remake/golden_pages.json
"""
from __future__ import annotations

import argparse
import hashlib
import json
import struct
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
RUN = HERE / "pygame" / "run.py"
GOLDEN = HERE / "golden_pages.json"
STATE = HERE / "pygame" / "state.dat"

# 金标生成时的存档基线（0x4AB5B0/0x4AB5B8 两个位域字）。页13 的解锁/选机
# 会随 state.dat 变化 ⇒ 跑页9/10（0x453050 会写 0x80/0x70000）或页4 存分
# 之后再回归会得到完全不同的哈希。回归必须固定这份基线，跑完再还原。
BASELINE_KEYS = 0xB21189E          # 解锁档：0x70000=3、0x800000、0x80 …
BASELINE_CFG = 0x64C80210          # 明度/彩度中性（各 50 → ×4−0xC8 = 0）
TBL_4AB5CC = 0x740 + 0x40 * 0x54   # 排行表 7232 字节


def _pin_state() -> bytes | None:
    """把 state.dat 换成金标基线；返回原文件内容（跑完由调用方还原）。"""
    saved = STATE.read_bytes() if STATE.exists() else None
    tbl = bytes(TBL_4AB5CC)
    if saved is not None:
        try:
            sys.path.insert(0, str(HERE))
            from grod_encode import grod_decode, grod_encode
            body = grod_decode(saved[0x18:])
            if len(body) >= 8:
                tbl = body[8:][:TBL_4AB5CC]
        except Exception:
            pass
    sys.path.insert(0, str(HERE))
    from grod_encode import grod_encode
    body = struct.pack("<II", BASELINE_KEYS, BASELINE_CFG) + tbl
    STATE.write_bytes(b"GRCD106A" + struct.pack("<I", len(body))
                      + struct.pack("<III", 0, 0, 0) + grod_encode(body))
    return saved

# 每个页选几个有代表性的帧（覆盖：淡入中、稳定、文字出现、收尾前）
CASES: dict[int, list[int]] = {
    1: [30, 60, 120, 240, 290],
    2: [20, 60, 470, 600, 780],
    3: [60, 120, 240],
    13: [60, 120, 240],
}


def shot(page: int, frame: int, outdir: Path) -> str:
    """跑一次 run.py 到第 frame 帧并存 PNG，返回该 PNG 的 sha256。"""
    subprocess.run(
        [sys.executable, str(RUN), "--page", str(page), "--frames", str(frame),
         "--headless", "--fixed", "--shots", str(frame), "--out", str(outdir)],
        check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    png = outdir / f"page{page}_f{frame}.png"
    if not png.exists():
        raise SystemExit(f"截图缺失: {png}")
    return hashlib.sha256(png.read_bytes()).hexdigest()


def collect() -> dict[str, dict[str, str]]:
    res: dict[str, dict[str, str]] = {}
    with tempfile.TemporaryDirectory() as td:
        for page, frames in CASES.items():
            res[str(page)] = {}
            for f in frames:
                d = Path(td) / f"p{page}_{f}"
                d.mkdir(parents=True, exist_ok=True)
                res[str(page)][str(f)] = shot(page, f, d)
                print(f"  page{page} f{f}: {res[str(page)][str(f)][:16]}")
    return res


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--update", action="store_true", help="重打金标")
    args = ap.parse_args()

    saved = _pin_state()
    try:
        cur = collect()
    finally:
        if saved is None:
            STATE.unlink(missing_ok=True)
        else:
            STATE.write_bytes(saved)
    if args.update:
        GOLDEN.write_text(json.dumps(cur, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        print(f"金标已写入 {GOLDEN}")
        return 0

    if not GOLDEN.exists():
        raise SystemExit(f"缺少金标文件 {GOLDEN}（先跑 --update）")
    old = json.loads(GOLDEN.read_text(encoding="utf-8"))

    bad = []
    for page, frames in old.items():
        for f, want in frames.items():
            got = cur.get(page, {}).get(f)
            if got != want:
                bad.append((page, f, want, got))

    if bad:
        print("\n✗ 冻结区截图发生变化：" + "  ".join(f"页{p}@f{f}" for p, f, _, _ in bad))
        for page, f, want, got in bad:
            print(f"  页{page} f{f}: 期望 {want[:16]} 实得 {str(got)[:16]}")
        print("\n若这是**有意的**改动，确认页1/2/3/13 视觉无误后执行："
              "\n  python3 remake/regress_pages.py --update")
        return 1

    n = sum(len(v) for v in old.values())
    print(f"\n✓ 冻结区回归通过（页 {','.join(old)} 共 {n} 张截图哈希一致）")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
