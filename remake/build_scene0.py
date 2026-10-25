"""从开篇脚本 res_45_OpngStream 提取页3 场景（§16.37）。

页3 状态0 的 `0x449E10` 会重放"当前场景"：层链来自脚本 `OP0B layers=[...]`，
逐个 14 项对应 `0x45FE10` 的「层号 = 下标」装载；背景节点来自 `OP03 (x,y,类型,段号)`。
本脚本只写**已定案**的部分（层链 + OP03 记录原文），节点几何待 §16.37 的
0x437074 五个分支读全后再翻译。
"""
import json, re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SRC = ROOT / "extracted/script_txt/res_45_OpngStream.txt"


def main() -> None:
    txt = SRC.read_text(encoding="utf-8", errors="replace")
    m = re.search(r"OP0B layers=\[([0-9, ]+)\]", txt)
    layers = [int(x) for x in m.group(1).split(",")] if m else []
    ents = []
    for line in txt.splitlines():
        mm = re.search(r"OP03\s*\((-?\d+),(-?\d+),(\d+),(-?\d+)\)", line)
        if mm:
            ents.append({"x": int(mm.group(1)), "y": int(mm.group(2)),
                         "type": int(mm.group(3)), "seg": int(mm.group(4))})
    d = json.loads((ROOT / "remake/pages_data.json").read_text(encoding="utf-8"))
    d["scene0"] = {"layers": layers, "band": [], "ents": [], "op03": ents,
                   "note": "§16.37：layers 来自 OP0B；op03 为脚本原文；背景节点几何待补"}
    (ROOT / "remake/pages_data.json").write_text(
        json.dumps(d, ensure_ascii=False, indent=1), encoding="utf-8")
    print("scene0.layers =", layers)
    print("scene0.op03 条数 =", len(ents))


if __name__ == "__main__":
    main()
