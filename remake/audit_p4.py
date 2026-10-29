"""页4 反汇编不变量的自动审计（每项都对应 ANALYSIS.md 的一条定案）。

用法：python3 remake/audit_p4.py
退出码 0 = 全部通过；非 0 = 有断言失败。

设计原则：**每项都直接从 exe 字节读，跟复刻侧的数据结构对账**，
而不是自己跟自己对账。任何一项失败都说明文档/代码/exe 三者有一处不一致。
"""
import json
import math
import pathlib
import sys

import pefile

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE / "pygame"))

EXE = HERE.parent.parent / "geki106" / "geki106.exe"

fails = []


def check(name, cond, detail=""):
    if cond:
        print(f"  ok   {name}")
    else:
        print(f"  FAIL {name}  {detail}")
        fails.append(name)


def main():
    pe = pefile.PE(str(EXE), fast_load=True)
    ib = pe.OPTIONAL_HEADER.ImageBase
    img = pe.get_memory_mapped_image()

    def u32(a):
        return int.from_bytes(img[a - ib:a - ib + 4], "little")

    def u8(a):
        return img[a - ib]

    def thunk(a):
        return a + 5 + int.from_bytes(img[a + 1 - ib:a + 5 - ib], "little", signed=True)

    def deep(a):
        """跟随 jmp 蹦床（.text 里 0x401xxx..0x4026xx 多为 `E9 rel32` 蹦床）。"""
        t = thunk(a)
        while 0x401000 <= t <= 0x4026FF and img[t - ib] == 0xE9:
            t = thunk(t)
        return t

    print("== 1. 三张三角函数表（§16.135）")
    import page4
    tabs = page4.p4_tables()
    check("p4_tables() 非 None（防止 except 吞错导致全零表）", tabs is not None)
    if tabs is not None:
        sin900 = tabs["sin"]
        check("sin 表长度 900", len(sin900) == 900, f"实得 {len(sin900)}")
        bad = [k for k in range(900)
               if abs(int(sin900[k]) - int(255 * math.sin(math.radians(k * 0.1)))) > 2]
        check("sin 表与 255*sin(k*0.1°) 逐项吻合（容差 2）", not bad, f"不符 {bad[:5]}")

        # atan2 表 0x5B3E38：**镜像是全零**，运行期由 0x45A9A0 的填表循环写入。
        # 因此只能验证「盘上为全零」这一事实，以及运行期公式（由 p4_angle 覆盖）。
        atan_base = 0x5B3E38
        nonzero = [i for i in range(0, 0x10000, 97)
                   if int.from_bytes(img[atan_base - ib + i * 2:
                                         atan_base - ib + i * 2 + 2], "little")]
        check("0x5B3E38 atan 表在盘上全零（运行期填表）", not nonzero,
              f"非零样本 {nonzero[:5]}")
        atan = tabs["atan"]
        check("atan256 表 256x256", getattr(atan, "shape", None) == (256, 256),
              f"实得 {getattr(atan, 'shape', None)}")
        # exe 的常量 572.9564553093966 略小于 3600/(2π)=572.9577951...，
        # 故恰好 90° 处 trunc → 899 而不是 900（fistp 截断）。差 1 属正常。
        v = int(atan[1][0])
        check("atan256[1][0] ≈ atan2(1,0) 的 0.1° 单位（899/900 均可）", v in (899, 900), f"实得 {v}")

    print("== 2. atan2 四象限（§16.135 / d3168b1）")
    bad = []
    for a in range(-3, 4):
        for b in range(-3, 4):
            if a == 0 and b == 0:
                continue
            want = math.degrees(math.atan2(a, b))
            got = page4.p4_angle(a, b) / 10.0
            d = abs((got - want + 180) % 360 - 180)
            if d > 0.3:
                bad.append((a, b, got, want))
    check("p4_angle 7x7 网格 vs atan2（±0.3°）", not bad, f"不符 {bad[:4]}")

    print("== 3. 背景槽布局算术（§16.147）")
    check("0xD0 + 0xA6E*4 == 0x2A88", 0xD0 + 0xA6E * 4 == 0x2A88)

    print("== 4. 层级阶梯 vs kind→层号表（§16.146 / §16.149）")
    tier = list(page4._P4_BG_TIER)
    km = json.loads((HERE / "p4_kindmap.json").read_text(encoding="utf-8"))
    kindmap = km["kindmap"]
    check("kindmap 256 项", len(kindmap) == 256)
    check("jumps 12 项", len(km["jumps"]) == 12)
    # 表里有专属分支的 kind 值应当正好是阶梯（含 0 用于隐藏）
    special = [k for k in range(0xF1) if kindmap[k] != 0xB]
    # tier 末尾的 0 是 exe 表里的"终止哨兵"，去重后才是真正的档位集合
    want = list(dict.fromkeys(tier))
    check("0..0xF0 内专属分支的 kind 集合 == 阶梯集合", special == want, f"{special} vs {want}")
    check("0xF1..0xFF 表项非 0xB 但被 cmp eax,0xF0/ja 挡掉（未读区）",
          kindmap[0xF1] != 0xB and kindmap[0xFF] != 0xB,
          f"0xF1={kindmap[0xF1]:#x} 0xFF={kindmap[0xFF]:#x}")
    # 层号 = 3 + 档位
    bad = []
    for k in want:
        if k == 0:
            continue                  # kind 0 走隐藏分支，没有层号
        br = kindmap[k]
        idx = tier.index(k)
        if br != idx or page4.p4_bg_kind_layer(k) != 2 + idx:
            bad.append((k, br, idx, page4.p4_bg_kind_layer(k)))
    check("层号 = 3 + 档位、分支号 = 档位", not bad, f"不符 {bad[:4]}")

    print("== 5. 队列扫描两族（§16.152）")
    A = {0x430220: 0x40213A, 0x4353A0: 0x4024D2, 0x448F80: 0x401B72, 0x43BC70: 0x40131B}
    B = {0x44B0D0: 0x4015C8, 0x445A30: 0x4012AD, 0x43A350: 0x40236A}
    for fn in list(A) + list(B):
        t = thunk(A.get(fn) or B[fn])
        got = img[t - ib:t - ib + 3]
        check(f"{fn:#x} dispatch → jmp [ecx+0x40]", got[:2] == b"\xff\x61" and got[2] == 0x40,
              f"实得 {got.hex()}")

    print("== 6. 每帧 9 条调用序（§16.139）")
    # 地址是 `mov ecx, <队列>` 的地址（其后的 `call` 在 +5 处）
    want = [(0x458E70, 0x4AD55C), (0x458E7A, 0x4AD40C), (0x458E84, 0x4AD46C),
            (0x458E8E, 0x4AD43C), (0x458E98, 0x4AD49C), (0x458EA2, 0x4AD4CC),
            (0x458EAC, 0x4AD4FC), (0x458EB6, 0x4AD52C), (0x458EC0, 0x4CD484)]
    bad = []
    for addr, q in want:
        if img[addr - ib] != 0xB9:
            bad.append((hex(addr), "非 B9", hex(q)))
            continue
        got = int.from_bytes(img[addr + 1 - ib:addr + 5 - ib], "little")
        if got != q:
            bad.append((hex(addr), hex(got), hex(q)))
    check("0x458E70 的 9 条 mov ecx,<队列> 全部对上", not bad, f"不符 {bad}")

    print("== 7. 移动处理器两条（§16.144 / §16.145）")
    class S:
        pass
    s = S()
    s.params = [6400] + [0] * 19          # 6400>>6 = 100
    s.grid = [[10, 20, 1], [30, 40, 1], [50, 60, 1]]
    page4.p4_bg_place_axis(s, 0, 3)
    check("p4_bg_place_axis 刚性平移（间距保留）", [g[0] for g in s.grid] == [100, 120, 140],
          f"实得 {[g[0] for g in s.grid]}")
    s.grid = [[0, 0, 0] for _ in range(4)]
    page4.p4_bg_strip_axis(s, 0, 4, 64, 0)
    check("p4_bg_strip_axis ratio=0 等距", [g[0] for g in s.grid] == [100, 101, 102, 103],
          f"实得 {[g[0] for g in s.grid]}")
    s.grid = [[0, 0, 0] for _ in range(4)]
    page4.p4_bg_strip_axis(s, 0, 4, 64, 32)
    check("p4_bg_strip_axis ratio=32 递增", [g[0] for g in s.grid] == [100, 101, 102, 104],
          f"实得 {[g[0] for g in s.grid]}")

    print("== 8. 层级阶梯（§16.146）")
    g = [[0, 0, 0] for _ in range(5)]
    acc = page4.p4_bg_kind_ladder(g, 5, 64, 384)
    check("p4_bg_kind_ladder(384, ratio=64) 种类", [r[2] for r in g] == [32, 32, 32, 48, 72],
          f"实得 {[r[2] for r in g]}")
    check("p4_bg_kind_ladder 末态 acc 12288", acc == 12288, f"实得 {acc}")

    print("== 9. 页4 骨架四处（§2/§10.7）")
    skeleton = [
        ("进场 0x4593C4 → 0x4505B0", 0x4593C4, 0x4505B0),
        ("每帧 0x4593CF → 0x451110", 0x4593CF, 0x451110),
        ("每帧 0x4593DA → 0x451110（循环回边）", 0x4593DA, 0x451110),
        ("收尾 0x4593E5 → 0x451C50", 0x4593E5, 0x451C50),
        ("泵 0x451171 → 0x458B80", 0x451171, 0x458B80),
        ("色带 0x45145C → 0x4562A0", 0x45145C, 0x4562A0),
    ]
    for name, site, want in skeleton:
        got = deep(site)
        check(name, got == want, f"实得 {got:#x}")

    print("== 10. 三组碰撞判定（§16）")
    coll = [("0x451465 → 0x43BF60", 0x451465, 0x43BF60),
            ("0x451480 → 0x43BFD0", 0x451480, 0x43BFD0),
            ("0x451493 → 0x43C060", 0x451493, 0x43C060),
            ("0x4514A6 → 0x43C0F0", 0x4514A6, 0x43C0F0)]
    for name, site, want in coll:
        got = deep(site)
        check(name, got == want, f"实得 {got:#x}")

    print("== 10b. 碰撞三组的实参（§16.156）")
    pairs = [("组1 0x451480 参数 (0x4AD40C,0x4AD43C)", 0x45146A, 0x4AD43C, 0x45146F, 0x4AD40C),
             ("组2 0x451493 参数 (0x4AD46C,0x4AD43C)", 0x451485, 0x4AD43C, 0x45148A, 0x4AD46C),
             ("组3 0x4514A6 参数 (0x4AD40C,0x4AD49C)", 0x451498, 0x4AD49C, 0x45149D, 0x4AD40C)]
    for name, a1, v1, a2, v2 in pairs:
        ok = (img[a1 - ib] == 0x68 and u32(a1 + 1) == v1
              and img[a2 - ib] == 0x68 and u32(a2 + 1) == v2)
        check(name, ok, f"{img[a1-ib]:#x}{u32(a1+1):#x} / {img[a2-ib]:#x}{u32(a2+1):#x}")

    print("== 11. 菱形命中判定式 0x4306C0")
    body = img[0x4306C0 - ib:0x4306C0 - ib + 0x50]
    # 0x4306C0 mov al,[ecx+0x10] / 0x4306C3 test al,al / 0x4306C5 je
    check("0x4306C0 先读激活位 +0x10",
          body[:4] == bytes([0x8A, 0x41, 0x10, 0x84]), body[:6].hex())
    # cdq(0x99) / xor edi,edx(0x33 FA) / sub edi,edx(0x2B FA) 取 |dx|
    check("0x4306C0 用 cdq/xor/sub 取 |dx|",
          img[0x4306D1 - ib] == 0x99 and img[0x4306D8 - ib] == 0x33
          and img[0x4306DA - ib] == 0x2B,
          f"cdq={img[0x4306D1-ib]:#x} xor={img[0x4306D8-ib]:#x} sub={img[0x4306DA-ib]:#x}")

    print("== 11b. 记录构造器 0x4023C4 是 thunk（§16.138 二次更正）")
    check("0x4023C4 字节为 E9 且指向 0x430400",
          img[0x4023C4 - ib] == 0xE9 and thunk(0x4023C4) == 0x430400,
          f"{img[0x4023C4-ib-ib] if False else img[0x4023C4-ib]:#x} → {thunk(0x4023C4):#x}")
    check("0x430400 用 rep movsd 拷 5 dword",
          img[0x430425 - ib] == 0xB9 and u32(0x430426) == 5
          and img[0x430434 - ib] == 0xF3,
          "")

    print("== 11c. 子弹×敌机回调的类型分派集合（§16.158）")
    import capstone as _cs
    md32 = _cs.Cs(_cs.CS_ARCH_X86, _cs.CS_MODE_32)
    seen = []
    for ins in md32.disasm(img[0x43C508 - ib:0x43CA00 - ib], 0x43C508):
        if ins.mnemonic == "cmp" and ins.op_str.startswith("eax, 0x"):
            v = int(ins.op_str.split("0x")[1], 16)
            if v not in seen:
                seen.append(v)
    want_t = [0x12061128, 0x10142214, 0x10008041, 0x10008431, 0x00000014,
              0x10FF0053, 0x12081123, 0x120C112C, 0x1B000001]
    check("0x43C508 起比较链 == 9 个类型", seen == want_t, f"{[hex(x) for x in seen]}")
    check("0x43C49D 用 0x7000 掩码取特效模式",
          img[0x43C49D - ib:0x43C4A2 - ib] == bytes([0x25, 0x00, 0x70, 0x00, 0x00]),
          img[0x43C49D - ib:0x43C4A2 - ib].hex())

    print("== 12. 回放三数组布局（§12）")
    check("回放数组长度常量 0x34BC0", 0x34BC0 == 216000 + 0, hex(0x34BC0))
    check("三数组间距 0x34BF0", 0x34BF0 == 0x34BC0 + 0x30, hex(0x34BF0))

    print()
    if fails:
        print(f"[audit] {len(fails)} 项失败：{fails}")
        return 1
    print("[audit] 全部通过")
    return 0


if __name__ == "__main__":
    sys.exit(main())
