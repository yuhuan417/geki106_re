#!/usr/bin/env python3
"""从原作 geki106.zip（或已解压的游戏目录）重建完整工作区。

原则（见根 README「使用声明」）：拿到原作 zip 后，跑本脚本即可恢复所有不入库的产物
（extracted/ 解包资源、resource_dec.bin、remake/ 提取表），其余内容（文档、复刻代码、
解包脚本文本）随仓库分发。重建完成后即可运行游戏：

    python3 remake/pygame/run.py

用法:
    python3 tools/restore_workspace.py ~/Downloads/geki106.zip   # 从 zip 解压并重建
    python3 tools/restore_workspace.py /path/to/game_dir         # 已解压的游戏目录
    python3 tools/restore_workspace.py                           # 用现有 GEKI_DIR 或 ../geki106

游戏目录约定与运行时一致（remake/pygame/geki.py 的 GAME_DIR）：
环境变量 GEKI_DIR 优先，默认为本仓库的兄弟目录 ../geki106。
"""
import os
import shutil
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
DEFAULT_GAME = REPO.parent / "geki106"

# (名称, 命令, 说明)——cwd 一律为仓库根；GEKI_DIR 由 main() 注入
STEPS = [
    ("解包 resource.rom", ["python3", "extract_everything.py"],
     "extracted/{midi,wave,script,data,replay,ggd_png} + resource_dec.bin"),
    ("根目录 resource_dec.bin 对齐", None,
     "extract_everything 写 extracted/；script_dump/layer_decode/page4 运行时读根目录副本"),
    ("脚本文本 dump", ["python3", "script_dump.py"],
     "extracted/script_txt/"),
    ("关卡背景层", ["python3", "layer_decode.py"],
     "extracted/stage_bg/"),
    ("页机静态数据", ["python3", "remake/build_pages_data.py"],
     "remake/pages_data.json"),
    ("页3 场景快照", ["python3", "remake/build_scene0.py"],
     "remake/pages_data.json 的 scene0（追加）"),
    ("页4 进场块", ["python3", "remake/build_p4_block.py"],
     "remake/p4_block*.json"),
    ("页4 VM 链表", ["python3", "remake/build_p4_vmchains.py"],
     "remake/p4_block.json 的 vm_chains（0x499798，并入）"),
    ("页4 字串/计分表", ["python3", "remake/build_p4_str.py"],
     "remake/pygame/p4_str_table.json、p4_tbl_4993c4.json"),
    ("页4 头像表", ["python3", "remake/build_p4_avatar.py"],
     "remake/p4_avatar.json"),
    ("页4 HUD 键位", ["python3", "remake/build_p4_hudkeys.py"],
     "remake/p4_hudkeys.json"),
    ("页4 kind 映射", ["python3", "remake/build_p4_kindmap.py"],
     "remake/p4_kindmap.json"),
    ("开场脚本结构化", ["python3", "remake/build_opng_script.py"],
     "remake/opng_script.json"),
]


def place_game(arg: str) -> Path:
    """zip → 解压定位含 geki106.exe 的目录；目录 → 原样使用。返回游戏目录。"""
    p = Path(arg).expanduser().resolve()
    if p.is_dir():
        if not (p / "geki106.exe").is_file():
            sys.exit(f"[restore] {p} 里没有 geki106.exe")
        return p
    if p.suffix.lower() != ".zip" or not p.is_file():
        sys.exit(f"[restore] {p} 不是 zip 也不是目录")
    game = Path(os.environ.get("GEKI_DIR") or DEFAULT_GAME)
    if game.exists():
        sys.exit(f"[restore] 目标 {game} 已存在；请先移走，或用 GEKI_DIR 指定其他位置")
    game.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="geki_restore_") as tmp:
        with zipfile.ZipFile(p) as z:
            z.extractall(tmp)
        hits = list(Path(tmp).rglob("geki106.exe"))
        if not hits:
            sys.exit(f"[restore] {p} 内未找到 geki106.exe（确认是从 Vector 下载的 geki106.zip）")
        src = hits[0].parent
        shutil.move(str(src), str(game))
    print(f"[restore] zip 已解压 → {game}")
    return game


def main() -> None:
    arg = sys.argv[1] if len(sys.argv) > 1 else None
    if arg:
        game = place_game(arg)
    else:
        game = Path(os.environ.get("GEKI_DIR") or DEFAULT_GAME)
        if not (game / "geki106.exe").is_file():
            sys.exit(f"[restore] {game} 不是有效的游戏目录（缺 geki106.exe）；"
                     f"传入 zip 路径：python3 tools/restore_workspace.py <geki106.zip>")
    rom = game / "resource.rom"
    if not rom.is_file():
        sys.exit(f"[restore] {game} 缺 resource.rom")
    os.environ["GEKI_DIR"] = str(game)
    print(f"[restore] 游戏目录 = {game}")
    for name, cmd, note in STEPS:
        print(f"[restore] {name} → {note} ...")
        if cmd is None:                        # 内置动作
            shutil.copyfile(REPO / "extracted/resource_dec.bin", REPO / "resource_dec.bin")
            continue
        r = subprocess.run(cmd, cwd=REPO, env=os.environ.copy())
        if r.returncode != 0:
            sys.exit(f"[restore] 步骤失败（rc={r.returncode}）：{' '.join(cmd)}")
    print("[restore] 完成。验证与已提交产物一致（应无差异）：\n"
          "    git status --short extracted/ remake/*.json remake/pygame/*.json\n"
          "[restore] 运行游戏：python3 remake/pygame/run.py"
          f"{'   # GEKI_DIR=' + str(game) if str(game) != str(DEFAULT_GAME) else ''}")


if __name__ == "__main__":
    main()
