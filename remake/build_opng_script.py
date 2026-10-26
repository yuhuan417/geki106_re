#!/usr/bin/env python3
"""把 flow-VM 脚本 res_65_OpngStream（开场动画）解析成 JSON，供 pygame 复刻直接消费。

来源：extracted/script_txt/res_65_OpngStream.txt（resource.rom 第 65 项，441 行，
由 script_dump.py 按 §7 的 flow-VM 格式 dump）。

产出 remake/opng_script.json：
  [{off, t, op, args:[...]}, ...]，op 为 "OP03"/"OP0B"/"OP09" …；args 已尽量转成数字/列表。
"""
import json, re
from pathlib import Path

SRC = Path(__file__).resolve().parent.parent / "extracted/script_txt/res_65_OpngStream.txt"
OUT = Path(__file__).resolve().parent / "opng_script.json"

LINE = re.compile(r"\[(?P<off>[0-9A-Fa-f]+)\]\s+t=\s*(?P<t>-?\d+)\s*(?P<rest>.*)$")


def parse_args(rest: str):
    body = rest.strip()
    m = re.match(r"(OP[0-9A-Fa-f]{2})\s*(.*)$", body)
    if not m:
        return None, None, []
    op, tail = m.group(1), m.group(2).strip()
    args = []
    # 列表（OP0B layers=[...] / OP09 v=[...]）
    lm = re.search(r"\[([^\]]*)\]", tail)
    if lm:
        vals = []
        for tok in lm.group(1).split(","):
            tok = tok.strip()
            if not tok:
                continue
            try:
                vals.append(int(tok, 0))
            except ValueError:
                try:
                    vals.append(float(tok))
                except ValueError:
                    vals.append(tok)
        args.append(vals)
        tail = tail[: lm.start()] + tail[lm.end():]
    # 括号元组（OP03 (x,y,type,ch) / OP05 (...)）
    tm = re.search(r"\(([^)]*)\)", tail)
    if tm:
        vals = []
        for tok in tm.group(1).split(","):
            tok = tok.strip()
            if not tok:
                continue
            try:
                vals.append(int(tok, 0))
            except ValueError:
                try:
                    vals.append(float(tok))
                except ValueError:
                    vals.append(tok)
        args.append(vals)
        tail = tail[: tm.start()] + tail[tm.end():]
    # 其余裸数字（OP0C transition 1 之类）
    for tok in re.findall(r"-?\d+", tail):
        args.append(int(tok))
    return op, tail.strip(), args


def main() -> int:
    recs = []
    for line in SRC.read_text(encoding="utf-8", errors="replace").splitlines():
        m = LINE.match(line)
        if not m:
            continue
        op, note, args = parse_args(m.group("rest"))
        if op is None:                      # 纯注释行（; /*OpngStream*/ 等）
            continue
        recs.append({"off": int(m.group("off"), 16), "t": int(m.group("t")),
                     "op": op, "args": args, "note": note})
    OUT.write_text(json.dumps(recs, ensure_ascii=False, indent=0), encoding="utf-8")
    from collections import Counter
    print(f"{OUT.relative_to(OUT.parent.parent)}: {len(recs)} 条指令")
    print("操作码统计:", dict(Counter(r["op"] for r in recs)))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
