#!/usr/bin/env python3
"""0x4602D0 链表 word 表 → 并入 remake/p4_block.json 的 "vm_chains"。

exe 定案（0x4602D0）：word 表 @VA 0x499798，signed 索引直读、无表长上界，0 = 链终止；
链内上限 0xF 条（0x4602F6 cmp esi,0xF）。提取规则：读 120 word 窗口（覆盖全部已知链）
后去尾零——链0=[45..52]／链9=[60]／链0x2E=[45,66..73]／链0x58=[74]，末链 [76]。
build_p4_block.py 只写 tables/branches，本脚本把 vm_chains 并回去。
"""
import json
import os
import struct

import pefile

HERE = os.path.dirname(os.path.abspath(__file__))
GAME = os.environ.get("GEKI_DIR") or os.path.join(os.path.dirname(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), "geki106")
EXE = os.environ.get("GEKI_EXE") or os.path.join(GAME, "geki106.exe")
TABLE_VA = 0x499798
N_WORDS = 120

pe = pefile.PE(EXE, fast_load=True)
words = list(struct.unpack(f"<{N_WORDS}H", pe.get_data(TABLE_VA - 0x400000, N_WORDS * 2)))
while words and words[-1] == 0:          # 0x4602D0 无表长上界，尾零不代表实体——去尾零
    words.pop()

path = os.path.join(HERE, "p4_block.json")
d = json.load(open(path, encoding="utf-8"))
d["vm_chains"] = words
json.dump(d, open(path, "w", encoding="utf-8"), indent=1)
print("vm_chains =", words)
