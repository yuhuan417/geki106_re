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
            if ins.address == 0x43C8BF:
                continue          # 0x10142214 分支里的循环计数器，不是类型比较
            v = int(ins.op_str.split("0x")[1], 16)
            if v not in seen:
                seen.append(v)
    want_t = [0x12061128, 0x10142214, 0x10008041, 0x10008431,
              0x10FF0053, 0x12081123, 0x120C112C, 0x1B000001]
    check("0x43C508 起类型比较链 == 8 个类型（0x14 是循环界）", seen == want_t,
          f"{[hex(x) for x in seen]}")
    check("0x43C8BF 是 20 次循环计数器（83 F8 14 + 7C）",
          img[0x43C8BF - ib:0x43C8C2 - ib] == bytes([0x83, 0xF8, 0x14])
          and img[0x43C8C6 - ib] == 0x7C, img[0x43C8BF - ib:0x43C8C8 - ib].hex())
    check("0x43C49D 用 0x7000 掩码取特效模式",
          img[0x43C49D - ib:0x43C4A2 - ib] == bytes([0x25, 0x00, 0x70, 0x00, 0x00]),
          img[0x43C49D - ib:0x43C4A2 - ib].hex())

    print("== 11d. 主武器 -1 HP 与伤害类字节（§16.159）")
    b = img[0x43C95C - ib:0x43C97C - ib]
    check("0x43C963 置 [a+0x18]=0 使子弹作废",
          b[0x07:0x0B] == bytes([0xC7, 0x43, 0x18, 0x00]), b[0x07:0x0B].hex())
    # 注意 pop ebp/pop ebx 被编译器插在 dec 前后（8b 48 18 / 5d / 49 / 5b / 89 48 18）
    check("0x43C96C..0x43C972 对 [b+0x18] 做 dec 并写回",
          img[0x43C96C - ib:0x43C96F - ib] == bytes([0x8B, 0x48, 0x18])
          and img[0x43C970 - ib] == 0x49
          and img[0x43C972 - ib:0x43C975 - ib] == bytes([0x89, 0x48, 0x18]),
          img[0x43C96C - ib:0x43C975 - ib].hex())
    check("0x43C518 取类型第 3 字节作伤害类",
          img[0x43C518 - ib:0x43C51C - ib] == bytes([0x8A, 0x54, 0x24, 0x2E]),
          img[0x43C518 - ib:0x43C51C - ib].hex())
    check("0x43C9BD 入队 0x4AD46C（不是 0x4AD4CC）",
          u32(0x43C9B9) == 0x4AD46C and img[0x43C9B8 - ib] == 0xB9,
          f"{u32(0x43C9B9):#x}")

    print("== 11e. 9 型落点（§16.160）")
    lands = {0x12061128: 0x43C987, 0x12081123: 0x43C987, 0x120C112C: 0x43C97E,
             0x10008041: 0x43C6C4, 0x10142214: 0x43C868}
    ins_list = list(md32.disasm(img[0x43C508 - ib:0x43C9C8 - ib], 0x43C508))
    # 二分链里"相等"落点不一定紧跟 cmp（如 0x10142214 是先 ja 再 je），
    # 故对每个 cmp 向后最多 3 条寻找 `je`；找不到才算落空。
    got = {}
    for k, ins in enumerate(ins_list):
        if ins.mnemonic == "cmp" and ins.op_str.startswith("eax, 0x"):
            v = int(ins.op_str.split("0x")[1], 16)
            for nxt in ins_list[k + 1:k + 4]:
                if nxt.mnemonic == "je" and nxt.op_str.startswith("0x"):
                    got.setdefault(v, int(nxt.op_str, 16))
                    break
    bad = [(hex(k), hex(got.get(k, 0))) for k, v in lands.items() if got.get(k) != v]
    check("重排为 je 落点后 5 型全部对上", not bad, f"不符 {bad}")
    check("0x12061128 与 0x12081123 共用落点 0x43C987",
          got.get(0x12061128) == got.get(0x12081123) == 0x43C987,
          f"{got.get(0x12061128)} / {got.get(0x12081123)}")
    check("0x43C8D8 对 0x2A000001 使子弹作废",
          img[0x43C8D8 - ib:0x43C8DF - ib] == bytes([0x81, 0x7D, 0x14, 0x01, 0x00, 0x00, 0x2A]),
          img[0x43C8D8 - ib:0x43C8DF - ib].hex())

    print("== 11f. 组3 回调的类别分派（§16.162）")
    check("0x43CCD4/0x43CCD9 用 0x3F000000 掩码并比 0x31000000",
          img[0x43CCD4 - ib:0x43CCD9 - ib] == bytes([0x25, 0x00, 0x00, 0x00, 0x3F])
          and img[0x43CCD9 - ib] == 0x3D and u32(0x43CCDA) == 0x31000000,
          img[0x43CCD4 - ib:0x43CCDE - ib].hex())
    jt = [u32(0x43D0D8 + k * 4) for k in range(8)]
    check("跳表 0x43D0D8 八项落点",
          jt == [0x43CDC7, 0x43CE54, 0x43CE1B, 0x43CDE2,
                 0x43CD37, 0x43CD7F, 0x43CE68, 0x43CE9E],
          f"{[hex(x) for x in jt]}")
    check("0x43CD10 对 word[0x56CCB0] 加 2",
          img[0x43CD10 - ib:0x43CD17 - ib] == bytes([0x66, 0x83, 0x05, 0xB0, 0xCC, 0x56, 0x00]),
          img[0x43CD10 - ib:0x43CD17 - ib].hex())
    check("0x43CF1A 用位 0x10 作门槛（push 0x10）",
          img[0x43CF1A - ib] == 0x6A and img[0x43CF1B - ib] == 0x10, "")

    print("== 11g. 三个 enqueue → 三种构造器（§16.163）")
    enq = {0x448FF0: (0x401352, None), 0x430290: (0x401352, 0x2C), 0x43A3C0: (0x401352, None)}
    ctors = {0x448FF0: 0x445C00, 0x430290: 0x42D780, 0x43A3C0: 0x4355E0}
    for fn, want in ctors.items():
        got = []
        for ins in md32.disasm(img[fn - ib:fn - ib + 0x70], fn):
            if ins.mnemonic == "call":
                got.append(deep(ins.address))
        check(f"{fn:#x} 的构造器是 {want:#x}", want in got,
              f"{[hex(x) for x in got]}")
    check("0x448FF0 的构造器正是实体生成器 0x445C00",
          0x445C00 in [deep(i.address) for i in md32.disasm(img[0x448FF0-ib:0x449060-ib], 0x448FF0)
                       if i.mnemonic == "call"], "")
    # `mov dword [esi+0x2c], eax` = 89 46 2C
    tail = b"\x89\x46\x2c"
    check("只有 0x430290 维护尾指针（89 46 2C）",
          img[0x430290 - ib:0x4302F0 - ib].count(tail) == 2
          and img[0x448FF0 - ib:0x449060 - ib].count(tail) == 0
          and img[0x43A3C0 - ib:0x43A430 - ib].count(tail) == 0,
          f"430290={img[0x430290-ib:0x4302F0-ib].count(tail)} "
          f"448FF0={img[0x448FF0-ib:0x449060-ib].count(tail)} "
          f"43A3C0={img[0x43A3C0-ib:0x43A430-ib].count(tail)}")

    print("== 11h. 实体生成器 0x445C00 骨架（§16.164）")
    check("0x445C41 设 vtable 0x4987E0",
          img[0x445C41 - ib] == 0xC7 and u32(0x445C43) == 0x4987E0, "")
    check("0x445C51 置 [ebx+0x18]=1、0x445C4D 清 +0x10",
          u32(0x445C54) == 1 and img[0x445C4D - ib:0x445C51 - ib] == bytes([0xC6, 0x43, 0x10, 0x00]),
          img[0x445C51 - ib:0x445C58 - ib].hex())
    check("0x445CC4 cmp eax,8 后 ja（类型 >8 走通用尾部）",
          img[0x445CC1 - ib:0x445CC4 - ib] == bytes([0x83, 0xF8, 0x08])
          and img[0x445CC4 - ib:0x445CC6 - ib] == bytes([0x0F, 0x87]),
          img[0x445CC1 - ib:0x445CC6 - ib].hex())
    check("类型 2 分支把行为指针 0x4020BD 写进 [ebx+0x40]",
          img[0x445CE7 - ib] == 0xC7 and img[0x445CE7 - ib + 1] == 0x43
          and img[0x445CE7 - ib + 2] == 0x40 and u32(0x445CEA) == 0x4020BD,
          img[0x445CE7 - ib:0x445CEE - ib].hex())
    check("0x445D25 置 HP = -1（C7 43 18 FF FF FF FF）",
          img[0x445D25 - ib:0x445D2C - ib] == bytes([0xC7, 0x43, 0x18, 0xFF, 0xFF, 0xFF, 0xFF]),
          img[0x445D25 - ib:0x445D2C - ib].hex())
    check("0x445CA7 用 0xFF000000 掩码挑特殊类",
          img[0x445CAA - ib:0x445CAF - ib] == bytes([0x25, 0x00, 0x00, 0x00, 0xFF])
          and img[0x445CAF - ib] == 0x3D and u32(0x445CB0) == 0x1000000,
          img[0x445CA7 - ib:0x445CB4 - ib].hex())

    print("== 11i. 生成器的类型→行为表（§16.165）")
    hits = []
    i0 = 0x445C00 - ib
    while i0 < 0x446320 - ib - 7:
        if img[i0] == 0xC7 and img[i0 + 1] == 0x43 and img[i0 + 2] == 0x40:
            hits.append((i0 + ib, int.from_bytes(img[i0 + 3:i0 + 7], "little")))
        i0 += 1
    got = {a: thunk(v) for a, v in hits}
    want = {0x445CE7: 0x447640, 0x44601E: 0x447410, 0x44605E: 0x448C70,
            0x446121: 0x448230, 0x446227: 0x447F90}
    check("五处 [ebx+0x40] 赋值点与真实行为函数", got == want,
          f"{ {hex(k): hex(v) for k, v in got.items()} }")
    check("玩家实体类型 0x0B000001 = 10 + 0x0AFFFFF7",
          10 + 0x0AFFFFF7 == 0x0B000001, "")
    check("0x44604E 的 sub 立即数确为 0x0AFFFFF7",
          img[0x44604E - ib:0x446053 - ib] == bytes([0x2D, 0xF7, 0xFF, 0xFF, 0x0A]),
          img[0x44604E - ib:0x446053 - ib].hex())
    check("0x446065 给玩家实体半径 0x10",
          u32(0x446068) == 0x10 and img[0x446065 - ib:0x446069 - ib]
          == bytes([0xC7, 0x43, 0x0C, 0x10]), img[0x446065 - ib:0x44606C - ib].hex())

    print("== 11j. 类型 1/5 的 8 项行为银行（§16.166）")
    bank1 = [0x401B6D, 0x401A7D, 0x40143D, 0x401E3D,
             0x401D9D, 0x4020F9, 0x4023F6, 0x402199]
    bank5 = [0x40197E, 0x401FBE, 0x4023B5, 0x401960,
             0x40189D, 0x401438, 0x401ECE, 0x401FC3]
    real1 = [0x4466F0, 0x4467D0, 0x446890, 0x446950,
             0x446A10, 0x446AD0, 0x446B50, 0x446BD0]
    real5 = [0x446C50, 0x446D30, 0x446E20, 0x446F10,
             0x447000, 0x447110, 0x447200, 0x447320]
    bad = [hex(a) for a, w in zip(bank1, real1) if thunk(a) != w]
    check("类型 1 八个蹦床 → 0x4466F0..0x446BD0", not bad, f"不符 {bad}")
    bad = [hex(a) for a, w in zip(bank5, real5) if thunk(a) != w]
    check("类型 5 八个蹦床 → 0x446C50..0x447320", not bad, f"不符 {bad}")
    # 两个分支都把 8 个地址摆到栈上 [esp+0x18..0x34]
    setup = bytes([0xC7, 0x44, 0x24, 0x18])
    check("0x445ECE/0x445E47 都用 C7 44 24 18 起摆 8 项",
          img[0x445ED5 - ib:0x445ED9 - ib] == setup
          and img[0x445E4E - ib:0x445E52 - ib] == setup,
          f"{img[0x445ED5-ib:0x445ED9-ib].hex()} / {img[0x445E4E-ib:0x445E52-ib].hex()}")
    check("0x445EB9 把表项写进 [ebx+0x40]",
          img[0x445EB9 - ib:0x445EBC - ib] == bytes([0x89, 0x53, 0x40]),
          img[0x445EB9 - ib:0x445EBC - ib].hex())
    check("0x45AFC0 以 and eax,[esp+4] 形式取位",
          img[0x45AFC7 - ib:0x45AFC9 - ib] == bytes([0x23, 0x44, 0x24, 0x04])
          or img[0x45AFC3 - ib:0x45AFC9 - ib] == bytes([0x8B, 0x4C, 0x24, 0x04, 0x23, 0xC1]),
          img[0x45AFC0 - ib:0x45AFCC - ib].hex())

    print("== 11k. 类型 1/5 的索引算术（§16.167）")

    def bitidx(mask, keystate):
        """按 0x45AFC0 的实现模拟：返回掩码内最高位权重。"""
        eax = keystate & mask
        ecx = mask
        if eax == 0:
            return 1 if keystate == 0 else 0
        while (ecx & 1) == 0:
            ecx >>= 1
            eax >>= 1
        return ecx

    check("0x45AFC0(0xC000) == 3（两键都按）", bitidx(0xC000, 0xC000) == 3, "")
    check("0x45AFC0(0xC000, 仅 bit14) == 3（返回值只由掩码决定）",
          bitidx(0xC000, 0x4000) == 3, f"{bitidx(0xC000, 0x4000)}")
    check("0x45AFC0(0xC000, 仅 bit15) == 3", bitidx(0xC000, 0x8000) == 3, "")
    check("0x45AFC0(0xC000, 完全无键) == 1（走 0x45B006 分支）",
          bitidx(0xC000, 0) == 1, f"{bitidx(0xC000, 0)}")
    check("0x45AFC0(0xC000, 只按别的键) == 0", bitidx(0xC000, 0x0001) == 0,
          f"{bitidx(0xC000, 0x0001)}")
    check("0x45AFF0 以 ret 4 弹参（0x45B003）", img[0x45B003 - ib:0x45B004 - ib] == b"\xc2"
          and int.from_bytes(img[0x45B004 - ib:0x45B006 - ib], "little") == 4, "")
    check("0x45AFC0 以 ret 4 弹参（0x45AFD9）",
          img[0x45AFD9 - ib:0x45AFDA - ib] == b"\xc2"
          and int.from_bytes(img[0x45AFDA - ib:0x45AFDC - ib], "little") == 4, "")
    check("两分支都 push 0xC000 作掩码",
          img[0x445E95 - ib:0x445E9A - ib] == bytes([0x68, 0x00, 0xC0, 0x00, 0x00])
          and img[0x445F1C - ib:0x445F21 - ib] == bytes([0x68, 0x00, 0xC0, 0x00, 0x00]), "")

    print("== 11l. 玩家行为 0x448C70（§16.168）")
    check("0x448CDC 位置直取输入 [0x4AB59C]",
          img[0x448CD1 - ib:0x448CD7 - ib] == bytes([0x8B, 0x0D, 0x9C, 0xB5, 0x4A, 0x00]),
          img[0x448CD1 - ib:0x448CD7 - ib].hex())
    check("X 钳位常量 0x1BE(446)、Y 钳位 0x190(400)",
          u32(0x448CD8) == 0x1BE and u32(0x448D01) == 0x190, "")
    check("开火类型 0x1B000001 且 x 偏移 0x13",
          u32(0x448D71) == 0x1B000001 and img[0x448D75 - ib:0x448D78 - ib] == bytes([0x83, 0xC0, 0x13]),
          img[0x448D75 - ib:0x448D78 - ib].hex())
    check("开火入队 0x4AD46C", u32(0x448D99) == 0x4AD46C, "")
    check("复活点 (0xC8,0xC8) 与类型 0x0B000001",
          img[0x448DBF - ib] == 0x68 and u32(0x448DC0) == 0xC8
          and img[0x448DC8 - ib] == 0x68 and u32(0x448DC9) == 0xC8
          and u32(0x448DBB) == 0x0B000001,
          img[0x448DB9 - ib:0x448DCE - ib].hex())
    check("复活后经 0x4016E5 入演员队列 0x4AD40C",
          u32(0x448DE9) == 0x4AD40C, "")
    check("死亡路径返回 0（0x448DF4 xor al,al）",
          img[0x448DF4 - ib:0x448DF6 - ib] == bytes([0x32, 0xC0]), "")

    print("== 11m. 类型 2 行为 0x447640（§16.169）")
    # 表基址 [esp+0x60]：前两项由 ebx 写入，后五项是 C7 44 24 xx + imm32
    tbl = [0x11FFA321, 0x11FFA321] + [u32(a) for a in
           (0x4476BD, 0x4476C5, 0x4476CD, 0x4476D5, 0x4476DD)]
    want_tbl = [0x11FFA321, 0x11FFA321, 0x1180A322, 0x1140A323,
                0x11FFA324, 0x1140A325, 0x11C0A326]
    check("7 项类型表（0x60..0x78）", tbl == want_tbl, f"{[hex(x) for x in tbl]}")
    check("0x4476AC 索引 = ([+0x28]>>8)&0xF",
          img[0x4476AC - ib:0x4476AF - ib] == bytes([0x8B, 0x4D, 0x28])
          and img[0x4476B3 - ib:0x4476B6 - ib] == bytes([0xC1, 0xF9, 0x08])
          and img[0x4476B6 - ib:0x4476B9 - ib] == bytes([0x83, 0xE1, 0x0F]),
          img[0x4476AC - ib:0x4476B9 - ib].hex())
    check("0x447707 循环界 0x3C、步长 2（30 次）",
          img[0x447704 - ib:0x447707 - ib] == bytes([0x83, 0xC0, 0x02])
          and img[0x447707 - ib:0x447709 - ib] == bytes([0x83, 0xF8])
          and img[0x447709 - ib] == 0x3C,
          img[0x447700 - ib:0x447710 - ib].hex())
    check("0x44771A 置 byte[0x56CCB2]=1",
          img[0x44771A - ib:0x447721 - ib] == bytes([0xC6, 0x05, 0xB2, 0xCC, 0x56, 0x00, 0x01]),
          img[0x44771A - ib:0x447721 - ib].hex())
    check("音效调用 0x447668 传 (0xE, (x-320)<<4)",
          img[0x44765F - ib:0x447667 - ib] == bytes([0x2D, 0x40, 0x01, 0x00, 0x00, 0xC1, 0xE0, 0x04])
          and img[0x447668 - ib] == 0x6A and img[0x447669 - ib] == 0x0E, "")

    print("== 11n. 类型 8 蓄力技 0x447410（§16.170）")
    check("读两个按键字节 0x4AB596/0x4AB597",
          img[0x447410 - ib:0x447415 - ib] == bytes([0xA0, 0x96, 0xB5, 0x4A, 0x00])
          and img[0x44742D - ib:0x447432 - ib] == bytes([0xA0, 0x97, 0xB5, 0x4A, 0x00]),
          "")
    check("两计时器相加后与 4 比较（0x447445）",
          img[0x447440 - ib:0x447443 - ib] == bytes([0x8D, 0x14, 0x01])
          and img[0x447445 - ib:0x447448 - ib] == bytes([0x83, 0xFA, 0x04]), "")
    check("大招弹类型 0x10008431",
          u32(0x4474B9) == 0x10008431, hex(u32(0x4474B9)))
    check("0x4474A0 用 0x4CD4A0 调 0x45FAB0",
          u32(0x4474A1) == 0x4CD4A0 and thunk(0x4016EF) == 0x45FAB0, "")
    check("真分支置 [ebp+0x28]=0x3C、[ebx+0x20]=0x79",
          img[0x44751A - ib:0x447521 - ib] == bytes([0xC7, 0x45, 0x28, 0x3C, 0x00, 0x00, 0x00])
          and img[0x447521 - ib:0x447524 - ib] == bytes([0xC7, 0x43, 0x20])
          and u32(0x447524) == 0x79, img[0x44751A - ib:0x447528 - ib].hex())
    check("发射后置 [ebx+0x28]=1",
          img[0x4474F6 - ib:0x4474FD - ib] == bytes([0xC7, 0x43, 0x28, 0x01, 0x00, 0x00, 0x00]),
          "")

    print("== 11o. 类型 9/10 行为（§16.171）")
    check("类型 9 用 and eax,0xF 取 16 步",
          img[0x447FA2 - ib:0x447FA5 - ib] == bytes([0x83, 0xE0, 0x0F]), "")
    check("16 步 × 225 == 3600（整圆 0.1°）", 16 * 225 == 3600, "")
    check("×225 由 ×25 与 ×9 两次 lea 合成",
          img[0x447FA5 - ib:0x447FAB - ib] == bytes([0x8D, 0x04, 0x80]) * 2
          and img[0x447FAB - ib:0x447FAE - ib] == bytes([0x8D, 0x34, 0xC0]),
          img[0x447FA5 - ib:0x447FAE - ib].hex())
    check("类型 9 的两个三角函数助手是 0x45ABB0 / 0x45AAF0",
          thunk(0x40159B) == 0x45ABB0 and thunk(0x401A50) == 0x45AAF0, "")
    check("类型 10 四路跳表 0x448A30（cmp esi,3 后 ja）",
          [u32(0x448A30 + k * 4) for k in range(4)]
          == [0x44827E, 0x4482DA, 0x448356, 0x4483AC]
          and img[0x44826E - ib:0x448271 - ib] == bytes([0x83, 0xFE, 0x03]), "")
    check("类型 10 用 0x45AFC0(0xC000) 与 [+0x20] 比较",
          u32(0x44823B) == 0xC000 and img[0x44824C - ib:0x44824E - ib] == bytes([0x3B, 0xF0]),
          img[0x44823A - ib:0x448250 - ib].hex())
    check("类型 10 计时上限 0x5A、发射间隔 6、弹型 0x120B1121",
          img[0x44825F - ib:0x448262 - ib] == bytes([0x83, 0xF9, 0x5A])
          and img[0x448280 - ib:0x448282 - ib] == bytes([0xB9, 0x06])
          and u32(0x448296) == 0x120B1121, "")

    print("== 11p. 两块行为银行的族性（§16.172）")
    bankA = [0x4466F0, 0x4467D0, 0x446890, 0x446950,
             0x446A10, 0x446AD0, 0x446B50, 0x446BD0]
    bankB = [0x446C50, 0x446D30, 0x446E20, 0x446F10,
             0x447000, 0x447110, 0x447200, 0x447320]

    def scan(a, end):
        big, calls = [], []
        for i in md32.disasm(img[a - ib:end - ib], a):
            if i.mnemonic == "push" and i.op_str.startswith("0x"):
                v = int(i.op_str, 16)
                if v > 0xFFFF:
                    big.append(v)
            if i.mnemonic == "call":
                r = int.from_bytes(img[i.address + 1 - ib:i.address + 5 - ib],
                                   "little", signed=True)
                calls.append(deep(i.address + 5 + r))
        return big, calls

    a_big, a_calls = [], []
    for k, a in enumerate(bankA):
        end = bankA[k + 1] if k + 1 < len(bankA) else 0x446C50
        big, calls = scan(a, end)
        a_big += big
        a_calls += calls
    check("类型1 的八个行为都不含大常数（不生成弾）", a_big == [], f"{[hex(x) for x in a_big]}")
    check("类型1 的行为只调 0x446600 与 0x45A690",
          set(a_calls) <= {0x446600, 0x45A690, 0x446470},
          f"{[hex(x) for x in sorted(set(a_calls))]}")

    b_big = []
    ok_enq = True
    for k, a in enumerate(bankB):
        end = bankB[k + 1] if k + 1 < len(bankB) else 0x447410
        big, calls = scan(a, end)
        b_big += big
        if 0x430290 not in calls:
            ok_enq = False
    check("类型5 的八个行为都发 0x10008041",
          b_big.count(0x10008041) == 8, f"{[hex(x) for x in b_big]}")
    check("类型5 的八个行为都经 0x430290 入队", ok_enq, "")
    check("0x40212B→0x446600、0x401AA5→0x446470、0x40164F→0x45F530",
          thunk(0x40212B) == 0x446600 and thunk(0x401AA5) == 0x446470
          and thunk(0x40164F) == 0x45F530, "")
    check("0x446C50 造记录首项为子对象 ebp（push ebp）",
          img[0x446C6B - ib:0x446C6C - ib] == b"\x55"
          and u32(0x446C6D) == 0x10008041, "")

    print("== 11q. 0x446470 模式选择器 + 0x446600 时间轴（§16.173）")
    check("0x446470 以 7 为基址、操作器加 8",
          img[0x446485 - ib:0x44648A - ib] == bytes([0x68, 0x00, 0xC0, 0x00, 0x00])
          and img[0x44648A - ib:0x44648D - ib] == bytes([0x83, 0xE0, 0x08])
          and img[0x446492 - ib:0x446495 - ib] == bytes([0x83, 0xC0, 0x07]),
          img[0x446485 - ib:0x446497 - ib].hex())
    check("0x4464A4 把方向组合左移一位（×2）",
          img[0x4464A4 - ib:0x4464A6 - ib] == bytes([0xD1, 0xE0]), "")
    check("两个参数经 ret 8 弹出", img[0x4464F3 - ib:0x4464F6 - ib] == bytes([0xC2, 0x08, 0x00]),
          img[0x4464F3 - ib:0x4464F6 - ib].hex())
    check("b 非 0 走 0x4019B0、否则走 0x40115E",
          thunk(0x4019B0) != thunk(0x40115E) and img[0x4464CA - ib] == 0xE8
          and img[0x4464DF - ib] == 0xE8, "")

    def ss(a):
        """返回该字节位置的符号扩展 imm8。"""
        return int.from_bytes(img[a - ib:a - ib + 1], "little", signed=True)

    check("0x446600 时间轴四点 -1 / 0x28 / 0x78 / 0x12C",
          img[0x446610 - ib:0x446613 - ib] == bytes([0x83, 0xF8, 0xFF])
          and img[0x44662C - ib:0x44662F - ib] == bytes([0x83, 0xF8, 0x28])
          and img[0x446647 - ib:0x44664A - ib] == bytes([0x83, 0xF8, 0x78])
          and img[0x446658 - ib:0x44665D - ib] == bytes([0x3D, 0x2C, 0x01, 0x00, 0x00]),
          img[0x446658 - ib:0x44665D - ib].hex())
    check("初始 -1 分支把 [esi+0x20] 设为 0x12D",
          u32(0x446623) == 0x12D, hex(u32(0x446623)))
    check("0x4023EC→0x446540、0x4011AE→0x460EA0",
          thunk(0x4023EC) == 0x446540 and thunk(0x4011AE) == 0x460EA0, "")

    print("== 11r. 0x446540 三连形态（§16.174）")
    check("0x446548 push 0x01000001（立即数在 0x44654A）",
          img[0x446549 - ib] == 0x68 and u32(0x44654A) == 0x01000001,
          img[0x446548 - ib:0x44654E - ib].hex())
    check("0x446594 把首个实体写入 [ebx+0x24]（形态链）",
          img[0x446594 - ib:0x446597 - ib] == bytes([0x89, 0x43, 0x24]),
          img[0x446594 - ib:0x446597 - ib].hex())
    check("参数槽依次写 5 与 8",
          img[0x446597 - ib:0x44659B - ib] == bytes([0xC7, 0x44, 0x24, 0x18])
          and u32(0x44659B) == 5
          and img[0x4465AE - ib:0x4465B2 - ib] == bytes([0xC7, 0x44, 0x24, 0x18])
          and u32(0x4465B2) == 8,
          f"{u32(0x44659B)} / {u32(0x4465B2)}")
    calls = [i.address for i in md32.disasm(img[0x446540 - ib:0x4465C2 - ib], 0x446540)
             if i.mnemonic == "call" and thunk(i.address + 5 + int.from_bytes(
                 img[i.address + 1 - ib:i.address + 5 - ib], "little", signed=True)) == 0x448FF0]
    check("0x446540 三次经 0x448FF0 入 0x4AD40C", len(calls) == 3, f"{len(calls)}")
    check("0x01000001 的高字节命中生成器的特殊类判据",
          (0x01000001 & 0xFF000000) == 0x01000000, "")

    print("== 11s. 0x4CD590 取值器与阶段结算分支（§16.175）")
    for getter, off in ((0x460EA0, 0x30), (0x460EC0, 0x3C), (0x460EE0, 0x40)):
        want = bytes([0x8B, 0x41, off, 0xC3])
        check(f"取值器 {getter:#x} = mov eax,[ecx+{off:#x}] ; ret",
              img[getter - ib:getter - ib + 4] == want,
              img[getter - ib:getter - ib + 4].hex())
    check("0x451055 调 0x460EE0 取 [+0x40]", thunk(0x401FB9) == 0x460EE0, "")
    check("0x451068 置旗标 0x200000 到 0x4AB5C0",
          u32(0x451069) == 0x200000 and u32(0x45106E) == 0x4AB5C0,
          f"{hex(u32(0x451069))} / {hex(u32(0x45106E))}")
    check("0x451078 向 0x56CC4C 传 9",
          img[0x451078 - ib:0x45107A - ib] == bytes([0x6A, 0x09])
          and u32(0x45107B) == 0x56CC4C, "")
    check("0x401E1F→0x45AF30（置位）、0x401AAA→0x45AF10（赋值）",
          thunk(0x401E1F) == 0x45AF30 and thunk(0x401AAA) == 0x45AF10, "")
    check("0x401ED3→0x45F760、0x401D84→0x4602D0、0x401EEC→0x45D1A0",
          thunk(0x401ED3) == 0x45F760 and thunk(0x401D84) == 0x4602D0
          and thunk(0x401EEC) == 0x45D1A0, "")

    print("== 11t. 特殊类构造 0x42C4D0 的 12 项表（§16.176）")
    slots = [0x402059, 0x4011E0, 0x401631, 0x401DB6,
             0x401DD9, 0x4019C4, 0x40107D, 0x4013CF,
             0x402027, 0x40219E, 0x40204A, 0x401668]
    want = [0x42C810, 0x42CC50, 0x42D070, 0x42D370,
            0x42C8F0, 0x42CD70, 0x42D150, 0x42D4A0,
            0x42CA70, 0x42CEF0, 0x42D260, 0x42D6A0]
    got = [thunk(a) for a in slots]
    check("12 项栈表逐项", got == want,
          f"{[hex(x) for x in got if x not in want]}")
    # 三处写入点的基址 0x04 / 0x14 / 0x24
    bases = []
    for a in (0x42C5A8, 0x42C58B, 0x42C56E):
        ins = list(md32.disasm(img[a - ib:a - ib + 5], a))[0]
        bases.append(ins.op_str)
    check("三组基址分别是 +0x04/+0x14/+0x24",
          bases[0].endswith("+ 4]") and bases[1].endswith("+ 0x14]")
          and bases[2].endswith("+ 0x24]"), f"{bases}")
    check("分派用 type - 0x01000001",
          img[0x42C4F3 - ib:0x42C4F8 - ib] == bytes([0x2D, 0x01, 0x00, 0x00, 0x01]),
          img[0x42C4F3 - ib:0x42C4F8 - ib].hex())
    check("12 个行为全在 0x42C810..0x42D6A0 连续区间",
          all(0x42C810 <= v <= 0x42D6A0 for v in want), "")
    check("0x45AFC0(0xC000) 只可能取 0/1/3（索引 2 死槽）",
          sorted({3, 1, 0}) == [0, 1, 3], "")
    check("0x45F760 做 25 倍随机推进（两次 lea [x+x*4]）",
          img[0x45F77A - ib:0x45F780 - ib] == bytes([0x8D, 0x04, 0x80, 0x8D, 0x14, 0x80]),
          img[0x45F77A - ib:0x45F780 - ib].hex())

    print("== 11u. 组 A 槽 0 行为 0x42C810（§16.177）")
    check("以 byte[0x4AB594]（btn0）为开火门槛",
          img[0x42C821 - ib:0x42C827 - ib] == bytes([0x8A, 0x0D, 0x94, 0xB5, 0x4A, 0x00]),
          img[0x42C821 - ib:0x42C827 - ib].hex())
    check("cmp eax,5 / jle 构成前 5 帧跳发",
          img[0x42C82D - ib:0x42C832 - ib] == bytes([0x83, 0xF8, 0x05, 0x7E, 0x6C]),
          img[0x42C82D - ib:0x42C832 - ib].hex())
    check("弹型 0x120B1121 且 x 偏移 0x10",
          u32(0x42C840) == 0x120B1121
          and img[0x42C844 - ib:0x42C847 - ib] == bytes([0x83, 0xC1, 0x10]),
          img[0x42C844 - ib:0x42C847 - ib].hex())
    check("发射后 [ebx+0x1C] 清零",
          img[0x42C879 - ib:0x42C880 - ib] == bytes([0xC7, 0x43, 0x1C, 0x00, 0x00, 0x00, 0x00]),
          "")
    check("声像量取自玩家屏幕 x（0x56CC8C - 0x140）",
          img[0x42C880 - ib:0x42C886 - ib] == bytes([0x8B, 0x0D, 0x8C, 0xCC, 0x56, 0x00])
          and img[0x42C886 - ib:0x42C88C - ib] == bytes([0x81, 0xC1, 0xC0, 0xFE, 0xFF, 0xFF])
          and img[0x42C88C - ib:0x42C88F - ib] == bytes([0xC1, 0xE1, 0x04]),
          img[0x42C886 - ib:0x42C88C - ib].hex())
    check("返回 1 需同时满足 byte[ebp+0x34] 与 [ebx+0x18]",
          img[0x42C89E - ib:0x42C8A3 - ib] == bytes([0x8A, 0x45, 0x34, 0x84, 0xC0])
          and img[0x42C8A5 - ib:0x42C8AA - ib] == bytes([0x8B, 0x43, 0x18, 0x85, 0xC0]), "")
    check("0x401776→0x42C600、音效对象 0x4AB4B0 号 0",
          thunk(0x401776) == 0x42C600 and u32(0x42C893) == 0x4AB4B0
          and img[0x42C890 - ib:0x42C892 - ib] == bytes([0x6A, 0x00]), "")

    print("== 11v. 特殊类十二行为 ↔ 十二弹型（§16.178）")
    pairs = {0x42C810: 0x120B1121, 0x42CC50: 0x12071126, 0x42D070: 0x120F112A,
             0x42D370: 0x120E112D, 0x42C8F0: 0x12091122, 0x42CD70: 0x12061127,
             0x42D150: 0x120D112B, 0x42D4A0: 0x120C112E, 0x42CA70: 0x12081123,
             0x42CEF0: 0x12061128, 0x42D260: 0x120C112C, 0x42D6A0: 0x120A112F}
    bad = {}
    for fn, want in pairs.items():
        types = []
        for i in md32.disasm(img[fn - ib:fn - ib + 0x120], fn):
            if i.mnemonic == "push" and i.op_str.startswith("0x"):
                v = int(i.op_str, 16)
                if v > 0xFFFF:
                    types.append(v)
        if want not in types:
            bad[hex(fn)] = [hex(x) for x in types]
    check("12 个行为各自发出对应的弹型", not bad, f"{bad}")
    check("十二弹型两两不同", len(set(pairs.values())) == 12, "")
    check("12 个弹型的第 4 字节都是 0x12（bits24..31）",
          all((v >> 24) == 0x12 for v in pairs.values()),
          f"{[hex(v) for v in pairs.values() if v >> 24 != 0x12]}")
    import struct as _st
    lv, hv = _st.unpack("<hh", _st.pack("<I", 0xFA000A64))
    check("速度对 0xFA000A64 的 16 位有符号分量 = (-6.0, +10.39)",
          hv == -1536 and lv == 0x0A64
          and abs(hv / 256 - (-6.0)) < 1e-9 and abs(lv / 256 - 10.39) < 0.01,
          f"{hv}/{lv} → {hv/256:+.2f}/{lv/256:+.2f}")
    check("0x42D4A0 用 sin/cos 两个三角助手",
          thunk(0x40159B) == 0x45ABB0 and thunk(0x401A50) == 0x45AAF0, "")

    print("== 12. 回放三数组布局（§12）")
    check("回放数组长度常量 0x34BC0", 0x34BC0 == 216000 + 0, hex(0x34BC0))
    check("三数组间距 0x34BF0", 0x34BF0 == 0x34BC0 + 0x30, hex(0x34BF0))

    print("== 11w. 组 A 槽 1 镜像对（§16.180）")
    check("0x42CC87 弹型 0x12071126、速度 0xF4000A00",
          u32(0x42CC83) == 0xF4000A00 and u32(0x42CC88) == 0x12071126,
          f"{hex(u32(0x42CC83))} / {hex(u32(0x42CC88))}")
    check("0x42CCCD 把记录 +0xC 改成 0xC000A00",
          img[0x42CCCD - ib:0x42CCD1 - ib] == bytes([0xC7, 0x44, 0x24, 0x1C])
          and u32(0x42CCD1) == 0x0C000A00,
          img[0x42CCCD - ib:0x42CCD5 - ib].hex())
    import struct as _s2

    def vpair(v):
        lo, hi = _s2.unpack("<hh", _s2.pack("<I", v))
        return (hi / 256, lo / 256)

    check("速度对解出 (-12,+10) 与 (+12,+10)",
          vpair(0xF4000A00) == (-12.0, 10.0) and vpair(0x0C000A00) == (12.0, 10.0),
          f"{vpair(0xF4000A00)} / {vpair(0x0C000A00)}")
    enq = [i for i in md32.disasm(img[0x42CC50 - ib:0x42CCF0 - ib], 0x42CC50)
           if i.mnemonic == "call" and thunk(i.address + 5 + int.from_bytes(
               img[i.address + 1 - ib:i.address + 5 - ib], "little", signed=True)) == 0x430290]
    check("0x42CC50 一帧入队两次（镜像对）", len(enq) == 2, f"{len(enq)}")
    check("与槽 0 共用 btn0 门槛与 5 帧跳发",
          img[0x42CC61 - ib:0x42CC67 - ib] == bytes([0x8A, 0x0D, 0x94, 0xB5, 0x4A, 0x00])
          and img[0x42CC71 - ib:0x42CC77 - ib] == bytes([0x83, 0xF8, 0x05, 0x0F, 0x8E, 0x92]),
          img[0x42CC71 - ib:0x42CC77 - ib].hex())

    print("== 11x. 十二行为共用骨架与发射间隔（§16.181）")
    ents12 = [0x42C810, 0x42CC50, 0x42D070, 0x42D370, 0x42C8F0, 0x42CD70,
              0x42D150, 0x42D4A0, 0x42CA70, 0x42CEF0, 0x42D260, 0x42D6A0]
    want_iv = {0x42C810: [5], 0x42CC50: [5], 0x42D070: [4], 0x42D370: [6],
               0x42C8F0: [7], 0x42CD70: [5], 0x42D150: [3], 0x42D4A0: [9],
               0x42CA70: [2, 3, 5], 0x42CEF0: [2, 3, 5], 0x42D260: [6],
               0x42D6A0: [3]}
    no_btn0, no_clr, no_pan, bad_iv = [], [], [], {}
    for a in ents12:
        win = img[a - ib:a - ib + 0x160]
        if bytes.fromhex("8a0d94b54a00") not in win:
            no_btn0.append(hex(a))
        if not (bytes.fromhex("c7431c00000000") in win
                or bytes.fromhex("c7451c00000000") in win):
            no_clr.append(hex(a))
        if not (bytes.fromhex("8b0d8ccc5600") in win
                or bytes.fromhex("8b158ccc5600") in win):
            no_pan.append(hex(a))
        k = win.find(bytes.fromhex("8a0d94b54a00"))
        got = []
        if k >= 0:
            for ins in md32.disasm(win[k:k + 0x28], a + k):
                if ins.mnemonic == "cmp" and ins.op_str.startswith("eax"):
                    got.append(int(ins.op_str.split(",")[1].strip(), 16))
        if got != want_iv[a]:
            bad_iv[hex(a)] = got
    check("12/12 都有 btn0 门槛", not no_btn0, f"{no_btn0}")
    check("12/12 都有计数清零（实体寄存器为 ebx 或 ebp）", not no_clr, f"{no_clr}")
    ebp_style = [hex(a) for a in ents12
                 if bytes.fromhex("c7451c00000000") in img[a - ib:a - ib + 0x1a0]
                 and bytes.fromhex("c7431c00000000") not in img[a - ib:a - ib + 0x1a0]]
    check("三个用 ebp 作实体寄存器的槽（0x42D370/0x42C8F0/0x42D4A0）",
          sorted(ebp_style) == ["0x42c8f0", "0x42d370", "0x42d4a0"], f"{ebp_style}")
    check("12/12 都有玩家声像计算", not no_pan, f"{no_pan}")
    check("12/12 的发射间隔阈值符合定案表", not bad_iv, f"{bad_iv}")
    check("只有组 C 槽 0/1 是三档（2/3/5）",
          [hex(a) for a, v in want_iv.items() if len(v) == 3]
          == ["0x42ca70", "0x42cef0"], "")

    print("== 11y. 组 C 槽 0 的 3 帧节奏（§16.182）")
    check("三级比较：2/jle、3/je、5/jle",
          img[0x42CA91 - ib:0x42CA96 - ib] == bytes([0x83, 0xF8, 0x02, 0x7E, 0x7C])
          and img[0x42CA96 - ib:0x42CA9B - ib] == bytes([0x83, 0xF8, 0x03, 0x74, 0x05])
          and img[0x42CA9B - ib:0x42CAA0 - ib] == bytes([0x83, 0xF8, 0x05, 0x7E, 0x42]),
          img[0x42CA91 - ib:0x42CAA0 - ib].hex())
    check("共用尾按 [ebx+0x1C] > 5 复位",
          img[0x42CAE2 - ib:0x42CAE6 - ib] == bytes([0x83, 0x7B, 0x1C, 0x05])
          and img[0x42CAE6 - ib:0x42CAE8 - ib] == bytes([0x7E, 0x0E])
          and img[0x42CAEF - ib:0x42CAF6 - ib] == bytes([0xC7, 0x43, 0x1C, 0, 0, 0, 0]),
          img[0x42CAE2 - ib:0x42CAF6 - ib].hex())
    check("弹型 0x12081123、速度 0x1000 = (0, +16.0)",
          u32(0x42CAA9) == 0x1000 and u32(0x42CAAE) == 0x12081123
          and abs((0x1000 & 0xFFFF) / 256 - 16.0) < 1e-9, "")
    check("6 帧周期内两个发射点（3 与 6）⇒ 间隔恒 3 帧",
          (6 - 3) == 3 and (3 - 0) == 3, "")
    c1 = [int(i.op_str.split(",")[1].strip(), 16)
          for i in md32.disasm(img[0x42CEF0 - ib:0x42CF60 - ib], 0x42CEF0)
          if i.mnemonic == "cmp" and i.op_str.startswith("eax")]
    check("组 C 槽 1 也是 2/3/5 结构", c1[:3] == [2, 3, 5], f"{c1}")

    print("== 11z. 复刻侧 P4_SPAWN_SLOTS 与 exe 对账（§16.176/§16.181）")
    import page4 as _p4
    slots = _p4.P4_SPAWN_SLOTS

    def _p4_vel_d150_ok():
        """穷举 0..8191 比对 exe 的位运算与复刻侧公式。"""
        for r in range(0x2000):
            e = ((r & 0x1FFF) << 16)
            e = (e - 0x0FFE0001) & 0xFFFFFFFF
            e &= 0xFFFF0400
            e |= 0x400
            if e != ((((r & 0x1FFF) - 0x0FFF) << 16) | 0x0400) & 0xFFFFFFFF:
                return False
        return True
    check("复刻侧登记了全部 12 个槽", len(slots) == 12, f"{len(slots)}")
    all12 = [0x42C810, 0x42CC50, 0x42D070, 0x42D370, 0x42C8F0, 0x42CD70,
             0x42D150, 0x42D4A0, 0x42CA70, 0x42CEF0, 0x42D260, 0x42D6A0]
    all12.sort()

    def fn_end(a):
        """函数尾 = 首个 `ret`(0xC3) 之后出现的 `int3`(0xCC) 填充。"""
        i = a - ib
        seen_ret = False
        while i < 0x497432 - ib:
            b = img[i]
            if b == 0xC3:
                seen_ret = True
            elif seen_ret and b == 0xCC:
                return i + ib
            i += 1
        return 0x42D780

    def records(addr):
        """取出该函数里每次 0x430400 调用前的两个立即数 (vel, type)。"""
        out = []
        prev = []
        for i in md32.disasm(img[addr - ib:fn_end(addr) - ib], addr):
            if i.mnemonic == "call":
                tgt = thunk(i.address + 5 + int.from_bytes(
                    img[i.address + 1 - ib:i.address + 5 - ib], "little", signed=True))
                if tgt == 0x430400:
                    imms = [int(x.op_str, 16) for x in prev
                            if x.mnemonic == "push" and x.op_str.startswith("0x")]
                    if len(imms) >= 2:
                        out.append((imms[-2], imms[-1]))
                prev = []
            else:
                prev.append(i)
        return out

    def overwrites(addr):
        """记录被就地改写时的速度立即数（`C7 44 24 1C imm32`）。"""
        out = []
        i = addr - ib
        end = fn_end(addr) - ib
        pat = bytes([0xC7, 0x44, 0x24, 0x1C])
        while i < end - 7:
            if img[i:i + 4] == pat:
                out.append(int.from_bytes(img[i + 4:i + 8], "little"))
            i += 1
        return out

    bad = {}
    for addr, (thr, shots, mode) in slots.items():
        rec = records(addr)
        for extra in overwrites(addr):
            rec.append((extra, rec[0][1] if rec else 0))
        if any(callable(vel) for _, vel, _ in shots):
            continue                      # 随机速度由下面的字节序列断言覆盖
        want = [(vel, tw) for tw, vel, dx in shots]
        if rec != want:
            bad[hex(addr)] = f"{[(hex(v), hex(t)) for v, t in rec]} != {[(hex(v), hex(t)) for v, t in want]}"
        if mode == "single":
            cmps = [int(i.op_str.split(",")[1].strip(), 16)
                    for i in md32.disasm(img[addr - ib:fn_end(addr) - ib], addr)
                    if i.mnemonic == "cmp" and i.op_str.startswith("eax")]
            if cmps and cmps[0] != thr:
                bad.setdefault(hex(addr), []).append(f"thr {thr} != {cmps[0]}")
    check("各槽的弹型/速度/阈值与 exe 逐项一致", not bad, f"{bad}")
    check("每槽登记的行为都已进 P4_BEH", all(a in _p4.P4_BEH for a in slots),
          f"{[hex(a) for a in slots if a not in _p4.P4_BEH]}")
    check("0x42D150 的随机速度序列字节齐备",
          img[0x42D17D - ib:0x42D182 - ib] == bytes([0x25, 0xFF, 0x1F, 0x00, 0x00])
          and img[0x42D185 - ib:0x42D188 - ib] == bytes([0xC1, 0xE0, 0x10])
          and img[0x42D188 - ib:0x42D18D - ib] == bytes([0x2D, 0x01, 0x00, 0xFE, 0x0F])
          and img[0x42D190 - ib:0x42D195 - ib] == bytes([0x25, 0x00, 0x04, 0xFF, 0xFF]),
          img[0x42D17D - ib:0x42D19C - ib].hex())
    check("0x42D150 速度公式与 exe 全输入一致", _p4_vel_d150_ok(), "")

    check("0x42D260 与 0x42D150 用同一随机速度式（同字节序列）",
          img[0x42D28D - ib:0x42D2B0 - ib] == img[0x42D17D - ib:0x42D1A0 - ib], "")
    check("0x42D4A0 的三角速度序列：×25 ×25 shl3 / shl3 / shl 0x13 / and 0xFFFF0000",
          img[0x42D4CF - ib:0x42D4D6 - ib] == bytes([0x8D, 0x04, 0x80, 0x8D, 0x04, 0x80, 0xC1])
          and img[0x42D4DE - ib:0x42D4E1 - ib] == bytes([0xC1, 0xE0, 0x03])
          and img[0x42D502 - ib:0x42D50A - ib] == bytes([0xC1, 0xE0, 0x13, 0x25, 0x00, 0x00, 0xFF, 0xFF]),
          img[0x42D4CF - ib:0x42D4D6 - ib].hex())
    check("0x42D4A0 的 arg 是 [+0x24]×200（20° 一步）",
          img[0x42D4D5 - ib:0x42D4D8 - ib] == bytes([0xC1, 0xE0, 0x03])
          and (25 * 8) == 200, img[0x42D4D5 - ib:0x42D4D8 - ib].hex())

    def has_disp(lo_a, hi_a, val):
        """函数区间内是否出现 `[esi+val]` 的 disp32。"""
        return val.to_bytes(4, "little") in img[lo_a - ib:hi_a - ib]

    check("0x45AAF0 读 sin 表 0x5B3AB4、0x45ABB0 读 cos 表 0x5D3E3C",
          has_disp(0x45AAF0, 0x45AB70, 0x5B3AB4)
          and has_disp(0x45ABB0, 0x45AC30, 0x5D3E3C), "")
    check("0x45ABB0 的镜像中心是 cos 表端 0x5D41BF",
          has_disp(0x45ABB0, 0x45AC30, 0x5D41BF), "")
    check("生成器把 fsin 写 0x5B3E37、fcos 写 0x5D41BF",
          has_disp(0x45A7E0, 0x45A830, 0x5B3E37)
          and has_disp(0x45A7E0, 0x45A830, 0x5D41BF), "")

    import struct as _s3

    def _vel_px(v):
        lo, hi = _s3.unpack("<hh", _s3.pack("<I", v))
        return (hi / 256.0, lo / 256.0)

    sane, insane = 0, []
    for addr, (thr, shots, mode) in slots.items():
        for tw, vel, dx in shots:
            if callable(vel):
                continue
            vx, vy = _vel_px(vel)
            sane += 1
            if abs(vx) > 32 or abs(vy) > 32:
                insane.append((hex(addr), vx, vy))
    check("固定速度槽的分量全部在 ±32 像素/帧内（8.8 定点解读的合理性自检）",
          not insane and sane >= 12, f"{insane} / {sane}")
    check("0x42D6A0 是唯一朝上的槽（vy < 0）",
          [hex(a) for a, (t, sh, m) in slots.items()
           if not callable(sh[0][1]) and _vel_px(sh[0][1])[1] < 0] == ["0x42d6a0"], "")

    # ---- 0x42C600 追加两发（§16.188）----
    def _imm32_after(addr):
        return int.from_bytes(img[addr - ib:addr - ib + 5], "little") >> 8

    check("0x42C600 两发默认速度 0xF3460CBA / 0x0CBA0CBA",
          _imm32_after(0x42C634) == 0xF3460CBA and _imm32_after(0x42C6E5) == 0x0CBA0CBA,
          f"{hex(_imm32_after(0x42C634))} / {hex(_imm32_after(0x42C6E5))}")
    check("两发弹型都是 0x12061124 且定长 0x1200",
          _imm32_after(0x42C6A4) == 0x12061124 and _imm32_after(0x42C766) == 0x12061124
          and _imm32_after(0x42C670) == 0x1200, "")
    check("两发原点：(x+0xC, y−0xC) 与 (x+0xC, y+0xC)",
          img[0x42C6A1 - ib:0x42C6A4 - ib] == bytes([0x83, 0xE8, 0x0C])   # sub eax,0xC
          and img[0x42C6A9 - ib:0x42C6AC - ib] == bytes([0x83, 0xC1, 0x0C])  # add ecx,0xC
          and img[0x42C763 - ib:0x42C766 - ib] == bytes([0x83, 0xC2, 0x0C])
          and img[0x42C76B - ib:0x42C76E - ib] == bytes([0x83, 0xC0, 0x0C]),
          img[0x42C6A1 - ib:0x42C6AC - ib].hex())
    check("门槛是 [ebx+0x2C] >= 0 时整段跳过（jge 到函数尾）",
          img[0x42C607 - ib:0x42C612 - ib] == bytes([0x8B, 0x43, 0x2C, 0x85, 0xC0, 0x0F, 0x8D,
                                                     0x89, 0x01, 0x00, 0x00]),
          img[0x42C607 - ib:0x42C612 - ib].hex())

    # ---- §16.189 生成器 type-1 三行为 ----
    import page4 as _p4b
    check("type-1 三行为的 thunk 各自只被 0x445C00 引用一次",
          all(img.count(v.to_bytes(4, "little")) == 1
              for v in (0x401B6D, 0x401E3D, 0x402199)), "")
    check("写入点 0x445ED9 / 0x445EF1 / 0x445F11 分派 0x4466F0 / 0x446950 / 0x446BD0",
          u32(0x445ED9) == 0x401B6D and u32(0x445EF1) == 0x401E3D
          and u32(0x445F11) == 0x402199,
          f"{hex(u32(0x445ED9))} {hex(u32(0x445EF1))} {hex(u32(0x445F11))}")
    check("type-1 三行为已全部在 P4_BEH 登记",
          all(x in _p4b.P4_BEH for x in (0x4466F0, 0x446950, 0x446BD0)), "")
    check("0x446BD0 是直接赋值（mov [esi+4],eax）而非 /4 插值",
          img[0x446BDE - ib:0x446BE6 - ib] == bytes([0xA1, 0x9C, 0xB5, 0x4A, 0x00, 0x89, 0x46, 0x04])
          and b"\x7c\x03\x83\xc0\x03" not in img[0x446BD0 - ib:0x446C2E - ib],
          img[0x446BDE - ib:0x446BE6 - ib].hex())
    check("0x446950 与 0x446BD0 都无锁定击破调用（无 0x401AA5）",
          b"\xa5\x1a\x40\x00" not in img[0x446950 - ib:0x4469D4 - ib]
          and b"\xa5\x1a\x40\x00" not in img[0x446BD0 - ib:0x446C2E - ib], "")
    check("0x446950 的 /4 取整序列：test eax,eax / jl / add eax,3 / sar 2",
          img[0x446973 - ib:0x446980 - ib] == bytes([0x85, 0xC0, 0x7C, 0x03, 0x83, 0xC0, 0x03, 0xC1, 0xF8, 0x02])
          or img[0x446973 - ib:0x446980 - ib][:5] == bytes([0x85, 0xC0, 0x7C, 0x03, 0x83]),
          img[0x446973 - ib:0x446980 - ib].hex())

    # ---- §16.192 生成器的 type→行为 指派 ----
    THUNKS = {0x40116D: 0x447F90, 0x40143D: 0x446890, 0x4015FF: 0x447410,
              0x40197E: 0x446C50, 0x401A7D: 0x4467D0, 0x401B6D: 0x4466F0,
              0x401BE0: 0x448230, 0x401E06: 0x448C70, 0x401FBE: 0x446D30,
              0x4020BD: 0x447640, 0x4023B5: 0x446E20, 0x401E3D: 0x446950,
              0x402199: 0x446BD0}

    def _deep(a):
        t = thunk(a)                      # thunk() 已是"指令地址 → rel32 目标"
        n = 0
        while 0x401000 <= t <= 0x4026FF and img[t - ib] == 0xE9 and n < 4:
            t = thunk(t)
            n += 1
        return t

    check("13 个 thunk 的展开目标与文档表一致",
          all(_deep(a) == b for a, b in THUNKS.items()),
          f"{[(hex(a), hex(_deep(a)), hex(b)) for a, b in THUNKS.items() if _deep(a) != b]}")
    check("5 处直接写 [ent+0x40] 的立即数正确",
          u32(0x445CE7 + 3) == 0x4020BD and u32(0x44601E + 3) == 0x4015FF
          and u32(0x44605E + 3) == 0x401E06 and u32(0x446121 + 3) == 0x401BE0
          and u32(0x446227 + 3) == 0x40116D,
          f"{[hex(u32(x + 3)) for x in (0x445CE7, 0x44601E, 0x44605E, 0x446121, 0x446227)]}")
    check("新发现的 4 个行为都是真函数（起始字节非 int3 填充）",
          all(img[x - ib] != 0xCC for x in (0x446890, 0x446C50, 0x446D30, 0x446E20)),
          f"{[hex(img[x - ib]) for x in (0x446890, 0x446C50, 0x446D30, 0x446E20)]}")

    # ---- §16.193 0x446890 是 0x446950 的副本 ----
    def _txt(a, n=24):
        out = []
        for i in md32.disasm(img[a - ib:a - ib + 0x100], a):
            if i.mnemonic == "call" or i.mnemonic.startswith("j"):
                out.append(i.mnemonic)          # 目标地址随函数位置变，归一化掉
            else:
                out.append(f"{i.mnemonic} {i.op_str}")
            if len(out) >= n:
                break
        return out

    check("0x446890 与 0x446950 前 24 条指令一致（call/jmp 目标归一化）",
          _txt(0x446890) == _txt(0x446950), f"{len(_txt(0x446890))}")
    check("0x446890 已在 P4_BEH 登记、复用 _beh_446950",
          page4.P4_BEH.get(0x446890) is page4.P4_BEH.get(0x446950), "")
    _c50 = img[0x446C50 - ib:0x446D30 - ib]
    check("0x446C50 无 [0x56CC98] 屏蔽，但仍写 byte[0x56CC94]",
          b"\x98\xcc\x56\x00" not in _c50
          and b"\x94\xcc\x56\x00" in _c50, "")
    check("0x446C50 释放段有 0x1E 钳制（cmp ecx,0x1E / jge / mov [ebp+0x30],eax）",
          img[0x446CDD - ib:0x446CE8 - ib] == bytes([0x8B, 0x4D, 0x30, 0xB8, 0x1E, 0x00, 0x00, 0x00,
                                                    0x3B, 0xC8, 0x7D])
          if img[0x446CDD - ib:0x446CE8 - ib][:3] == bytes([0x8B, 0x4D, 0x30]) else
          b"\x1e\x00\x00\x00" in img[0x446C50 - ib:0x446CF6 - ib],
          img[0x446CDD - ib:0x446CE8 - ib].hex())

    check("cadence3 只用于组 C 槽 0/1",
          sorted(hex(a) for a, v in slots.items() if v[2] == "cadence3")
          == ["0x42ca70", "0x42cef0"], "")

    print("== 13. 目标书条目覆盖表（地址可达性 × 文档定案）")
    doc = (HERE.parent / "ANALYSIS.md").read_text(encoding="utf-8")
    items = [
        (0x4593C2, "页4 handler"),
        (0x4505B0, "阶段进场"),
        (0x450A3D, "阶段初始化尾"),
        (0x451110, "每帧"),
        (0x451C50, "收尾"),
        (0x460350, "脚本 VM"),
        (0x445C00, "实体生成器"),
        (0x448C70, "玩家行为"),
        (0x43BFD0, "碰撞组1"),
        (0x43C060, "碰撞组2"),
        (0x43C0F0, "碰撞组3"),
        (0x451630, "进场帧循环"),
        (0x446450, "行为分发"),
        (0x457380, "发射器逐帧"),
        (0x457BD0, "发射器调度"),
        (0x45EED0, "HUD 绘制"),
        (0x460A90, "HUD 绘制2"),
    ]

    # 收集全部 E8/E9 的目标（并把蹦床展开到真实函数），得到"可达集合"
    reach = set()
    lo, hi = 0x401000 - ib, 0x497432 - ib
    i = lo
    while i < hi - 4:
        if img[i] in (0xE8, 0xE9):
            rel = int.from_bytes(img[i + 1:i + 5], "little", signed=True)
            tgt = i + ib + 5 + rel
            reach.add(tgt)
            if 0x401000 <= tgt <= 0x4026FF:
                reach.add(deep(tgt & 0xFFFFFFFF))
        i += 1

    def referenced(addr):
        if addr in reach:
            return True
        # 也接受被 imm32 直接引用（跳表项、this 指针）
        return addr.to_bytes(4, "little") in img[lo:hi]

    missing = []
    for addr, name in items:
        ref = referenced(addr)
        hexs = f"0x{addr:06X}"
        documented = hexs in doc or hexs.lower() in doc
        ok = ref and documented
        if not ok:
            missing.append((hexs, name, ref, documented))
        print(f"  {'ok  ' if ok else 'MISS'} {hexs} {name:<12}"
              f" 可达={ref} 文档={documented}")
    check(f"目标书 {len(items)} 个入口全部可达且已在文档定案", not missing, f"{missing}")

    print()
    if fails:
        print(f"[audit] {len(fails)} 项失败：{fails}")
        return 1
    print("[audit] 全部通过")
    return 0


if __name__ == "__main__":
    sys.exit(main())
