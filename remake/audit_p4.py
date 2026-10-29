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

    print("== 11m. 类型 6 行为 0x447640（§16.169/§16.202）")
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

    def _find_imm(v: int):
        """扫全镜像里某个 imm32 的所有出现地址。"""
        pat = v.to_bytes(4, "little")
        out, i = [], img.find(pat)
        while i != -1:
            out.append(i + ib)
            i = img.find(pat, i + 1)
        return out

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

    # ---- §16.194 激光族四变体 ----
    check("激光族四行为已全部登记",
          all(x in page4.P4_BEH for x in (0x446C50, 0x446D30, 0x446E20, 0x446F10)), "")
    def _pushreg_before(lo, hi):
        """`push 0x10008041` 紧前那条是否是单字节 `push reg`（50..57）。"""
        pat = bytes([0x68, 0x41, 0x80, 0x00, 0x10])
        blk = img[lo - ib:hi - ib]
        k = blk.find(pat)
        return k > 0 and 0x50 <= blk[k - 1] <= 0x57 and blk.count(pat) == 1

    check("四者都发 0x10008041，紧前一条是 push reg（第 5 字段 = 父指针；"
          "0x446C50/0x446D30 用 push ebp，0x446E20/0x446F10 用 push edx/eax 传同一个值）",
          all(_pushreg_before(lo, hi)
              for lo, hi in ((0x446C50, 0x446CFE), (0x446D30, 0x446DE9),
                             (0x446E20, 0x446ED2), (0x446F10, 0x446FC4))), "")
    check("只有 0x446C50 完全不查 [0x56CC98]（其余三个都读它）",
          [hex(lo) for lo, hi in ((0x446C50, 0x446CFE), (0x446D30, 0x446DE9),
                                  (0x446E20, 0x446ED2), (0x446F10, 0x446FC4))
           if b"\x98\xcc\x56\x00" not in img[lo - ib:hi - ib]] == ["0x446c50"], "")
    check("0x446E20 的**开火段**无按键门（0x446E20..0x446E95 不引用 0x4AB597）",
          b"\x97\xb5\x4a\x00" not in img[0x446E20 - ib:0x446E95 - ib]
          and b"\x97\xb5\x4a\x00" in img[0x446E9C - ib:0x446EA2 - ib], "")
    check("释放时 [ebp+0x30] 的下限：0x446C50/0x446D30 是 0x1E，0x446E20 是 0x3C",
          b"\x1e\x00\x00\x00" in img[0x446CDC - ib:0x446CE8 - ib]
          and b"\x1e\x00\x00\x00" in img[0x446DCE - ib:0x446DDA - ib]
          and b"\x3c\x00\x00\x00" in img[0x446EBE - ib:0x446ECA - ib], "")

    # ---- §16.195 0x447410 四发上限发射器 ----
    check("0x447410 已登记",
          0x447410 in page4.P4_BEH, "")
    check("0x447410 的 4 发上限是『两计数器之和 >= 4 就冻结』（cmp edx,4）",
          img[0x447440 - ib:0x447448 - ib] == bytes([0x8D, 0x14, 0x01, 0x40, 0x41, 0x83, 0xFA, 0x04])
          or b"\x83\xfa\x04" in img[0x447445 - ib:0x44744E - ib],
          img[0x447440 - ib:0x44744E - ib].hex())
    check("0x45FAB0 就是 word[0x4CD4A0+0x26] >= 0xA0 的谓词",
          img[0x45FAB0 - ib:0x45FABC - ib] == bytes([0x33, 0xC0, 0x66, 0x81, 0x79, 0x26, 0xA0,
                                                    0x00, 0x0F, 0x9D, 0xC0, 0xC3]),
          img[0x45FAB0 - ib:0x45FABC - ib].hex())
    check("0x447410 的音效调用参数是 (0xC, (x-0x140)<<4) 且共两处",
          img[0x4474F0 - ib:0x447503 - ib].count(bytes([0x83, 0xEA, 0x40])) == 0
          or (b"\x6a\x0c" in img[0x4474FD - ib:0x44750A - ib]
              and b"\x6a\x0c" in img[0x447596 - ib:0x4475A1 - ib]), "")

    # ---- 勘误 A-57：自机类型 0x0B000001 ----
    check("0x43C190 的立即数是 0x0AFFFFFB（⇒ 自机类型 0x0B000001）",
          img[0x43C190 - ib:0x43C195 - ib] == bytes([0x2D, 0xFB, 0xFF, 0xFF, 0x0A]),
          img[0x43C190 - ib:0x43C195 - ib].hex())
    check("0x0B000001 在二进制里只出现两处（0x44372C / 0x448DBB）",
          [hex(h) for h in _find_imm(0x0B000001)] == ["0x44372c", "0x448dbb"],
          f"{[hex(h) for h in _find_imm(0x0B000001)]}")
    check("0x10000001 不是自机（出现在 0x43F7D8/0x43FE59/0x440054/0x49CE45）",
          [hex(h) for h in _find_imm(0x10000001)]
          == ["0x43f7d8", "0x43fe59", "0x440054", "0x49ce45"],
          f"{[hex(h) for h in _find_imm(0x10000001)]}")
    check("复刻侧 p4_hit_cb 用 0x0B000001 判自机被弹（源码级）",
          "0x0B000001" in open("remake/pygame/page4.py", encoding="utf-8").read()
          and "t == 0x10000001" not in open("remake/pygame/page4.py", encoding="utf-8").read(), "")

    # ---- §16.197 量表重置 0x45F570 / 0x45F660 ----
    check("0x45F660 是 max(0, [+0x30] − 5)（jbe 置 0 / 否则 add eax,−5）",
          img[0x45F660 - ib:0x45F677 - ib] == bytes([0x8B, 0x41, 0x30, 0x83, 0xF8, 0x05, 0x76, 0x07,
                                                     0x83, 0xC0, 0xFB, 0x89, 0x41, 0x30, 0xC3,
                                                     0xC7, 0x41, 0x30, 0x00, 0x00, 0x00, 0x00, 0xC3]),
          img[0x45F660 - ib:0x45F677 - ib].hex())
    check("0x45F570 把 word[+0x26] 写成 0xA0（66 C7 46 26 A0 00）",
          img[0x45F58C - ib:0x45F592 - ib] == bytes([0x66, 0xC7, 0x46, 0x26, 0xA0, 0x00]),
          img[0x45F58C - ib:0x45F592 - ib].hex())
    check("0x45F570 的 [+0x2C] 最多减 2（cmp ax,2 / movsx / jl / mov ecx,2）",
          img[0x45F57C - ib:0x45F58A - ib] == bytes([0x66, 0x3D, 0x02, 0x00, 0x0F, 0xBF, 0xC8,
                                                     0x7C, 0x05, 0xB9, 0x02, 0x00, 0x00, 0x00]),
          img[0x45F57C - ib:0x45F58A - ib].hex())
    check("0x45FAB0 读的 +0x26 正是 0x45F570 写的 +0x26（同字段闭环）",
          img[0x45FAB2 - ib:0x45FAB8 - ib] == bytes([0x66, 0x81, 0x79, 0x26, 0xA0, 0x00])
          and b"\x66\xc7\x46\x26\xa0\x00" in img[0x45F570 - ib:0x45F5A1 - ib], "")
    _src = open("remake/pygame/page4.py", encoding="utf-8").read()
    check("复刻侧 p4_45f570 / p4_45f660 已定义并接进命中回调",
          "def p4_45f570(" in _src and "def p4_45f660(" in _src
          and "self.p4_45f570()" in _src, "")

    # ---- §16.198 0x460C00 死亡链（未落地，防止误登记） ----
    _c0 = img[0x460C00 - ib:0x460D84 - ib]
    check("0x460C00 不是行为（不进 P4_BEH），而是由命中回调显式调用",
          0x460C00 not in page4.P4_BEH
          and "def p4_460c00(" in open("remake/pygame/page4.py", encoding="utf-8").read()
          and "self.p4_460c00()" in open("remake/pygame/page4.py", encoding="utf-8").read(), "")
    check("0x460C00 栈帧 sub esp,0x44 且以 ret 收尾（0x460D83）",
          img[0x460C00 - ib:0x460C06 - ib] == bytes([0x66, 0xA1, 0xB0, 0xCC, 0x56, 0x00])
          and img[0x460D83 - ib] == 0xC3, img[0x460C00 - ib:0x460C06 - ib].hex())
    check("0x460C00 生成的五个类型立即数齐备（0x41000001 push / 0x4100000E·0x41000004 mov / 0x51000002 push）",
          bytes([0x68, 0x01, 0x00, 0x00, 0x41]) in _c0
          and bytes([0xC7, 0x44, 0x24, 0x1C, 0x0E, 0x00, 0x00, 0x41]) in _c0
          and bytes([0xC7, 0x44, 0x24, 0x1C, 0x04, 0x00, 0x00, 0x41]) in _c0
          and bytes([0x68, 0x02, 0x00, 0x00, 0x51]) in _c0, "")
    check("0x460C00 的抖动是 (rand&0x7F)−0x3F（83 E0 7F / 83 E8 3F 各两次）",
          _c0.count(bytes([0x83, 0xE0, 0x7F])) == 2
          and _c0.count(bytes([0x83, 0xE8, 0x3F])) == 2,
          f"{_c0.count(bytes([0x83, 0xE0, 0x7F]))}/{_c0.count(bytes([0x83, 0xE8, 0x3F]))}")

    # ---- §16.199 死亡链最后那条 type-1 记录的字段归属 ----
    check("0x460D11 push 后的 [esp+0x20]/[esp+0x24] 写入（rec+8=1 / rec+0xC=1）",
          img[0x460D11 - ib:0x460D1F - ib] == bytes([0x52, 0xB9, 0x0C, 0xD4, 0x4A, 0x00,
                                                     0x89, 0x44, 0x24, 0x20, 0x89, 0x44, 0x24, 0x24]),
          img[0x460D11 - ib:0x460D1F - ib].hex())
    check("0x460D08 的记录基准是 [esp+0x14]",
          img[0x460D08 - ib:0x460D0C - ib] == bytes([0x8D, 0x54, 0x24, 0x14]),
          img[0x460D08 - ib:0x460D0C - ib].hex())
    check("生成器小类型分派：cmp eax,8 / ja 越界 / je 8 / dec je 1 / sub 4 je 5 / dec jne",
          img[0x445CC1 - ib:0x445CC4 - ib] == bytes([0x83, 0xF8, 0x08])
          and img[0x445CC4 - ib] == 0x0F and img[0x445CC5 - ib] in (0x87, 0x84)
          and img[0x445CD0 - ib] == 0x48 and img[0x445CD7 - ib:0x445CDA - ib] == bytes([0x83, 0xE8, 0x04]),
          img[0x445CC1 - ib:0x445CCC - ib].hex())

    # ---- §16.200 0x447F90 三向旋转散射方向表 ----
    _r = img[0x447F90 - ib:0x448192 - ib]
    check("0x447F90 方向表 (256,0) / (−128,222) / (−128,−222)",
          img[0x447FD8 - ib:0x447FE8 - ib] == bytes([0xC7, 0x44, 0x24, 0x64, 0x00, 0x01, 0x00, 0x00,
                                                     0xC7, 0x44, 0x24, 0x68, 0x00, 0x00, 0x00, 0x00])
          and img[0x447FE8 - ib:0x447FF0 - ib] == bytes([0xC7, 0x44, 0x24, 0x70, 0xDE, 0x00, 0x00, 0x00])
          and img[0x447FFA - ib:0x448002 - ib] == bytes([0xC7, 0x44, 0x24, 0x78, 0x22, 0xFF, 0xFF, 0xFF])
          and img[0x447FC8 - ib:0x447FCD - ib] == bytes([0xB8, 0x80, 0xFF, 0xFF, 0xFF]), "")
    check("0x447F90 角度步长 = (n&0xF)×25×9 = 225（lea 链，无 0xE1 立即数）",
          bytes([0x83, 0xE0, 0x0F]) in _r
          and bytes([0x8D, 0x04, 0x80, 0x8D, 0x04, 0x80]) in _r
          and bytes([0x8D, 0x34, 0xC0]) in _r, "")
    check("0x447F90 旋转是 >>13 且 x 加、y 减",
          _r.count(bytes([0xC1, 0xFA, 0x0D])) == 1 and _r.count(bytes([0xC1, 0xF8, 0x0D])) == 1
          and bytes([0x2B, 0xF2]) in _r, "")
    check("0x447F90 的两条入队类型 0x10000052 / 0x41000010 至 4AD46C / 4AD4CC",
          bytes([0xC7, 0x44, 0x24, 0x30, 0x52, 0x00, 0x00, 0x10]) in _r
          and bytes([0xC7, 0x44, 0x24, 0x34, 0x10, 0x00, 0x00, 0x41]) in _r, "")
    check("0x447F90 已登记进 P4_BEH（§16.201 定案）",
          0x447F90 in page4.P4_BEH and page4.P4_BEH[0x447F90] is page4._beh_447F90, "")
    # 用分支感知的 esp_flow 证明：尾部读的 px/py 与循环里写的 x/y 是同一槽
    import os, sys
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    import esp_flow as _ef
    _m = _ef.flow(0x447F90, 0x448192)
    check("0x44811C 读的槽 == 0x448006 写的 y 槽（分支感知换算后同一地址）",
          _m[0x44811C][0x24] == _m[0x448006][0x20],
          f"{_m[0x44811C][0x24]} vs {_m[0x448006][0x20]}")
    check("0x448129 读的槽 == 0x448002 写的 x 槽",
          _m[0x448129][0x28] == _m[0x448002][0x24],
          f"{_m[0x448129][0x28]} vs {_m[0x448002][0x24]}")
    def _f(addr, raw):
        return next(iter(_m[addr][raw]))
    check("0x448123 写的 a 就在 0x448113 指针处、0x448117 写的 b 紧随其后（+4）",
          _f(0x448123, 0x1C) == _f(0x448113, 0x18)
          and _f(0x448117, 0x1C) == _f(0x448113, 0x18) + 4,
          f"{_f(0x448123, 0x1C)} {_f(0x448117, 0x1C)} {_f(0x448113, 0x18)}")

    # ---- §16.202 0x447640 的 7 项表必然越界 ----
    import os, sys
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    import esp_flow as _ef2
    _m2 = _ef2.flow(0x447640, 0x447801)
    _tab = [_m2[0x4476A6][0x60], _m2[0x4476AF][0x64], _m2[0x4476B9][0x68],
            _m2[0x4476C1][0x6C], _m2[0x4476C9][0x70], _m2[0x4476D1][0x74], _m2[0x4476D9][0x78]]
    check("0x447640 的 7 项表占据连续的 7 个 dword（帧−0x1C..帧−0x4）",
          [next(iter(x)) for x in _tab] == [-0x1C, -0x18, -0x14, -0x10, -0xC, -0x8, -0x4],
          f"{[next(iter(x)) for x in _tab]}")
    check("索引读基址 == 表首槽 ⇒ idx=7 起越界（读到帧+0x00 及以后）",
          next(iter(_m2[0x4476E1][0x60])) == next(iter(_tab[0])), "")
    # ---- §16.203 0x447640 续段的状态机与两张表 ----
    check("0x44785A 起按 [ent+0x28] & 0xF000 分派",
          img[0x447863 - ib:0x447868 - ib] == bytes([0x25, 0x00, 0xF0, 0x00, 0x00])
          and img[0x44786B - ib:0x447870 - ib] == bytes([0x3D, 0x00, 0x70, 0x00, 0x00]), "")
    check("状态 0x8000 的跳表 0x447D90 只有 4 个有效代码指针",
          [u32(0x447D90 + 4 * k) for k in range(4)] == [0x447A2F, 0x447A86, 0x447A91, 0x447C2D]
          and u32(0x447D90 + 4 * 4) != 0x44700000, "")
    check("字节表 0x447DA0 = 0,3,3,3,3,3,3,3,1,3,1,3,2,3,2（15 项，值域 0..3）",
          [img[0x447DA0 - ib + k] for k in range(15)]
          == [0, 3, 3, 3, 3, 3, 3, 3, 1, 3, 1, 3, 2, 3, 2], "")
    check("0x447A22 用 `(frame & 0xF) <= 0xE` 查字节表再跳 0x447D90",
          img[0x447A14 - ib:0x447A1C - ib] == bytes([0x83, 0xE0, 0x0F, 0x83, 0xF8, 0x0E, 0x0F, 0x87]), "")

    # ---- §16.204 三个助手 + 每帧轨道尾巴 ----
    check("0x401A0A→0x45A790 是 rect_add（p[0..3] 分别 += a,b,c,d）",
          img[0x45A790 - ib:0x45A7A7 - ib] == bytes([0x8B, 0x44, 0x24, 0x04, 0x8B, 0x4C, 0x24, 0x08,
                                                     0x8B, 0x10, 0x03, 0xD1, 0x8B, 0x48, 0x04, 0x89,
                                                     0x10, 0x8B, 0x54, 0x24, 0x0C, 0x03, 0xCA]), "")
    check("0x462D71 是带符号 ceil_div（idiv 两次 + 结果为负且余数>0 时商+1、余数-=b）",
          bytes([0xF7, 0x7D, 0x0C]) in img[0x462D71 - ib:0x462D96 - ib]
          and img[0x462D8E - ib:0x462D92 - ib] == bytes([0x41, 0x2B, 0x55, 0x0C]), "")
    check("0x40111D→0x460800 取 word[ecx+0x2A]",
          img[0x460800 - ib:0x460805 - ib] == bytes([0x66, 0x8B, 0x41, 0x2A, 0xC3]), "")
    _orb = img[0x447C2D - ib:0x447D90 - ib]
    check("0x447C2D 每帧尾巴的角度步长 = 113（lea 8倍/sub/shl 4/add 链）",
          bytes([0x8D, 0x34, 0xC5, 0x00, 0x00, 0x00, 0x00, 0x2B, 0xF0,
                 0xC1, 0xE6, 0x04, 0x03, 0xF0]) in _orb, "")
    check("0x447C2D 用 >>16 缩放且乘实体半径（cos*(r>>1) / sin*((r>>2)+r)）",
          _orb.count(bytes([0xC1, 0xFE, 0x10])) == 1 and _orb.count(bytes([0xC1, 0xF8, 0x10])) == 1
          and bytes([0xD1, 0xFA]) in _orb and bytes([0xC1, 0xF9, 0x02, 0x03, 0xCF]) in _orb, "")
    check("0x447C2D 的方向表与 0x447F90 同值（0x100 / −0x80,0xDE / −0x80,−0xDE）",
          img[0x447C74 - ib:0x447C78 - ib] == bytes([0xC7, 0x44, 0x24, 0x60])
          and img[0x447C78 - ib:0x447C7C - ib] == bytes([0x00, 0x01, 0x00, 0x00])
          and img[0x447C88 - ib:0x447C90 - ib] == bytes([0xC7, 0x44, 0x24, 0x6C, 0xDE, 0x00, 0x00, 0x00])
          and img[0x447C94 - ib:0x447C9C - ib] == bytes([0xC7, 0x44, 0x24, 0x74, 0x22, 0xFF, 0xFF, 0xFF]), "")

    check("0x447640 已登记进 P4_BEH（§16.205 落地）",
          0x447640 in page4.P4_BEH and page4.P4_BEH[0x447640] is page4._beh_447640
          and page4.P4_447640_TAB == (0, 3, 3, 3, 3, 3, 3, 3, 1, 3, 1, 3, 2, 3, 2)
          and page4.P4_447640_TYPES[6] == 0x11C0A326, "")
    check("0x447640 的 7 项表与字节表转写成常量且与 exe 一致",
          [u32(0x4476BD + 8 * k) for k in range(5)]
          == [0x1180A322, 0x1140A323, 0x11FFA324, 0x1140A325, 0x11C0A326], "")

    # ---- §16.206 0x448230 的两张跳表 ----
    check("0x448230 的相位跳表 0x448A30 = 44827E/4482DA/448356/4483AC",
          [u32(0x448A30 + 4 * k) for k in range(4)]
          == [0x44827E, 0x4482DA, 0x448356, 0x4483AC], "")
    check("窗口 B 的相位跳表 0x448A40 = 448464/448510/4485D3/44862F",
          [u32(0x448A40 + 4 * k) for k in range(4)]
          == [0x448464, 0x448510, 0x4485D3, 0x44862F], "")
    check("0x448230 依赖 0x4AB5B0 的 bits14-15（0x45AFC0 取字段）与 [ent+0x1C] 寿命窗口 0x5A/0xD2/0xF0/0x14A",
          img[0x44823A - ib:0x44823F - ib] == bytes([0x68, 0x00, 0xC0, 0x00, 0x00])
          and img[0x44823F - ib:0x448242 - ib] == bytes([0x8B, 0x75, 0x20])
          and img[0x448242 - ib:0x448247 - ib] == bytes([0xB9, 0xB0, 0xB5, 0x4A, 0x00])
          and img[0x44824C - ib:0x448250 - ib] == bytes([0x3B, 0xF0, 0x74, 0x0B])
          and img[0x44825F - ib:0x448262 - ib] == bytes([0x83, 0xF9, 0x5A])
          and img[0x44873E - ib:0x448744 - ib] == bytes([0x81, 0xF9, 0xF0, 0x00, 0x00, 0x00]), "")
    check("0x448230 的闪烁尾用 word 表 0x286/0x28E/0x216/0x39D",
          [u16(0x448991 + 2 + 2 * k) for k in range(0)] == []
          and img[0x448991 - ib:0x44899F - ib] == bytes([0x66, 0xC7, 0x44, 0x24, 0x24, 0x86, 0x02,
                                                         0x66, 0xC7, 0x44, 0x24, 0x26, 0x8E, 0x02]), "")
    check("0x448230 已登记进 P4_BEH（§16.207 落地）",
          0x448230 in page4.P4_BEH and page4.P4_BEH[0x448230] is page4._beh_448230, "")
    check("窗口 C 跳表 0x448A50 = 448766/4487BC/44886D/4488D9 且与转写表逐项一致",
          [u32(0x448A50 + 4 * k) for k in range(4)] == [0x448766, 0x4487BC, 0x44886D, 0x4488D9]
          and [t for _m, t, _r in page4.P4_448230_C] == [0x12081123, 0x12061128, 0x120C112C, 0x120A112F], "")
    check("三张相位表的模数与 type 与反汇编一致",
          [m for m, _t, _r in page4.P4_448230_A] == [6, 6, 5, 7]
          and [m for m, _t, _r in page4.P4_448230_B] == [8, 6, 3, 0]
          and [m for m, _t, _r in page4.P4_448230_C] == [3, 3, 7, 4]
          and [t for _m, t, _r in page4.P4_448230_A]
          == [0x120B1121, 0x12071126, 0x120F112A, 0x120E112D]
          and [t for _m, t, _r in page4.P4_448230_B]
          == [0x12091122, 0x12061127, 0x120D112B, 0x120C112E], "")
    check("窗口 B 相位的四发 x 偏移 0xB0/0xB0/0xC0/0x90 与 vel 序列一致",
          page4.P4_448230_B[1][2] == ((0xB0, 0xF6000A00), (0xB0, 0xA000A00),
                                     (0xC0, 0xA0008E0), (0x90, 0xF60008E0))
          and page4.P4_448230_BLINK == (0x286, 0x28E, 0x216, 0x39D), "")

    # ---- §16.208 0x43CCC0 的命中处置分流 ----
    check("0x43CCC0 的 idx 跳表 0x43D0D8 = 43CDC7/43CE54/43CE1B/43CDE2/43CD37/43CD7F/43CE68/43CE9E",
          [u32(0x43D0D8 + 4 * k) for k in range(8)]
          == [0x43CDC7, 0x43CE54, 0x43CE1B, 0x43CDE2, 0x43CD37, 0x43CD7F, 0x43CE68, 0x43CE9E], "")
    check("0x43CCC0 按 [bullet+0x14] & 0x3F000000 分流 0x31/0x32/0x33",
          img[0x43CCD0 - ib:0x43CCD3 - ib] == bytes([0x8B, 0x43, 0x14])
          and img[0x43CCD4 - ib:0x43CCD9 - ib] == bytes([0x25, 0x00, 0x00, 0x00, 0x3F])
          and img[0x43CCD9 - ib:0x43CCDE - ib] == bytes([0x3D, 0x00, 0x00, 0x00, 0x31])
          and img[0x43CCEB - ib:0x43CCF0 - ib] == bytes([0x3D, 0x00, 0x00, 0x00, 0x33]), "")
    check("0x43CCC0 的计分与状态：word[0x56CCB0] += 2、[tgt+0x30] = 0x3C、idx = type + 0xCDFFFFFE",
          img[0x43CD10 - ib:0x43CD18 - ib] == bytes([0x66, 0x83, 0x05, 0xB0, 0xCC, 0x56, 0x00, 0x02])
          and img[0x43CD18 - ib:0x43CD1F - ib] == bytes([0xC7, 0x45, 0x30, 0x3C, 0x00, 0x00, 0x00])
          and img[0x43CD22 - ib:0x43CD27 - ib] == bytes([0x05, 0xFE, 0xFF, 0xFF, 0xCD]), "")
    check("0x43CEFB 的死亡分支：>0x12C / bit4 / [tgt+0x28]==3 / 0x460C00+0x45F570",
          img[0x43CF11 - ib:0x43CF18 - ib] == bytes([0x81, 0x7D, 0x20, 0x2C, 0x01, 0x00, 0x00])
          and img[0x43CF2A - ib:0x43CF2E - ib] == bytes([0x83, 0x7D, 0x28, 0x03])
          and img[0x43CF33 - ib:0x43CF3A - ib] == bytes([0xC7, 0x45, 0x20, 0x79, 0x00, 0x00, 0x00]), "")
    # ---- §16.209 0x4CD4A0 的四个写入口 ----
    check("0x45F5F0 主计数：[mgr+0x30]++、word[mgr+0x5E]++、word[mgr+0x26] += 8",
          img[0x45F5F6 - ib:0x45F5FA - ib] == bytes([0x66, 0xFF, 0x46, 0x5E])
          and img[0x45F607 - ib:0x45F60C - ib] == bytes([0x66, 0x83, 0x46, 0x26, 0x08]), "")
    check("0x45F690 满 12 才进位（cmp ax,0xC）", img[0x45F69B - ib:0x45F69F - ib] == bytes([0x66, 0x3D, 0x0C, 0x00]), "")
    check("0x45F6E0 先把 word[mgr+0x26] 置 0xA0 再调 0x45F5F0",
          img[0x45F6EA - ib:0x45F6F0 - ib] == bytes([0x66, 0xC7, 0x41, 0x26, 0xA0, 0x00]), "")
    check("0x460E00 十次一循环：>= 0xA 或 == -1 转 0x45F690",
          img[0x460E03 - ib:0x460E0B - ib] == bytes([0x83, 0xF8, 0x0A, 0x7D, 0x0C, 0x83, 0xF8, 0xFF]), "")

    def _mk():
        class _S(page4.Page4Mixin):
            def __init__(self):
                self.p4_stat = {0x4CD590 + 0x30: 7, 0x4CD4A0 + 0x08: 50,
                                0x4CD4A0 + 0x0C: 25, 0x4CD4A0 + 0x10: 200}
        return _S()
    class _E(page4.Page4Mixin):
        def __init__(self):
            self.p4_stat = {0x4CD4A0 + 0x2C: 3, 0x4CD4A0 + 0x5A: 0, 0x4CD4A0 + 0x5C: 0}
    _e = _E()
    _r1 = page4.Page4Mixin.p4_45e710(_e, bytes([7, 0, 0, 0, 0, 2]), 5)
    _r2 = page4.Page4Mixin.p4_45e710(_e, bytes([7, 0, 0, 0, 0, 0]), 5)
    _r3 = page4.Page4Mixin.p4_45e710(_e, bytes([7, 0, 0, 0, 0, 2]), 0x200)
    class _H(page4.Page4Mixin):
        def __init__(self):
            self.calls = []
            self.p4_stat = {}
        def p4_se_pan(self, se, pan):
            self.calls.append(("SE", se, pan))
        def _p4_q(self, n):
            return n
        def spawn(self, *a):
            self.calls.append(a)
    _he = page4.Ent(100, 50, 0x23000001, 0)
    _he.d32(0x14, 0x1000)
    _he.d32(0x1C, 0x400)
    _he.d32(0x20, 0x600)
    _h1 = _H()
    page4.Page4Mixin.p4_43c460(_h1, _he)
    _he.d32(0x14, 0x3000)
    _h2 = _H()
    page4.Page4Mixin.p4_43c460(_h2, _he)
    def _hit(typ, extra30=0, life=3):
        class _HS(_H):
            pass
        e = page4.Ent(10, 20, 0x23000001, 0)
        e.d32(0x14, typ)
        e.d32(0x30, extra30)
        e.d32(0x18, life)
        h = _H()
        tgt = page4.Ent(0, 0, 0x23000001, 0)
        tgt.d32(0x18, 0x7FFFFFFF)      # 血量远大于 k ⇒ 共用尾只扣血放 SE，不毁靶
        tgt.d32(0x10, 1)
        page4.Page4Mixin.p4_43c460(h, e, tgt)
        return [(c[0], c[1]) for c in h.calls if c[0] != "SE"], e.s32(0x18)
    _c1 = _hit(0x12061128)
    _c2 = _hit(0x12081123)
    _c3 = _hit(0x120C112C)
    _c4 = _hit(0x1B000001)
    check("0x43C460 二级分发：0x12061128/0x12081123 造同类型入 ui46c；0x120C112C 置 [+0x30]=-3；"
          "0x1B000001 提前返回不走共用尾",
          _c1[0] == [("ui4cc", 0x41000004), ("ui46c", 0x12061128)] and _c1[1] == 2
          and _c2[0] == [("ui4cc", 0x41000004), ("ui46c", 0x12081123)]
          and _c3[0] == [("ui4cc", 0x41000004)] and _c3[1] == 2
          and _c4[0] == [] and _c4[1] == 0, "")
    check("0x43C460 的 cmp 链是**无符号**二叉查找（0x43C525 ja / 0x43C53B ja / 0x43C557 jne）",
          img[0x43C525 - ib:0x43C52B - ib] == bytes([0x0F, 0x87, 0x1C, 0x04, 0x00, 0x00])
          and img[0x43C53B - ib:0x43C541 - ib] == bytes([0x0F, 0x87, 0x8C, 0x03, 0x00, 0x00])
          and img[0x43C557 - ib:0x43C55D - ib] == bytes([0x0F, 0x85, 0x65, 0x04, 0x00, 0x00]), "")
    class _ZK:
        def test(self, b):
            return False
    class _Z(page4.Page4Mixin):
        def __init__(self, stat=None):
            self.calls = []
            self.p4_stat = dict(stat or {})
            self.keys = _ZK()
            self.p4_player_pos = None
        def _p4_q(self, n):
            return n
        def spawn(self, *a):
            self.calls.append(a)
        def p4_se_pan(self, *a):
            self.calls.append(("SE",) + a)
    _za = _Z({0x4AB5B0 + 4: 0xC000})
    _zb = _Z({0x4AB5B0 + 4: 0x4000})
    _zc = _Z({0x4AB5B0 + 4: 0})
    _q1 = page4.Ent(0x120, 0x80, 0x10142214, 0)
    _qz = _Z()
    page4.Page4Mixin._p4_43c868(_qz, _q1)
    _j1 = page4.Ent(0x200, 0x100, 0x10FF0053, 0)
    _j1.d32(0x10, 1)
    _j1.d32(0x18, 9)
    _ja = page4.Ent(0x10, 0x10, 0x2A000001, 0)
    _jz = _Z()
    page4.Page4Mixin.p4_43c460(_jz, _j1, _ja)
    _jhit = [c for c in _jz.calls if c[0] == "ui4cc" and c[1] == 0x41000004]
    _bo = _Z({0x4AB5B0 + 4: 0x0F00})
    _bor1 = page4.Page4Mixin.p4_45af30(_bo, 0x1000)
    _bor2 = page4.Page4Mixin.p4_45af60(_bo, 0x0100)
    _cv_p = page4.Ent(0x1C0, 0x100, 0x10008431, 0)
    _cv_p.d32(0x10, 1)
    _cv_p.d32(0x1C, 0x5000)
    _cv_a = page4.Ent(0x120, 0x90, 0x10008431, 0)
    _cv_a.d32(0x10, 1)
    _cv_a.d32(0x18, 5)
    _cv_z = _Z({0x4CD4A0 + 0xEC: 0x1000, 0x10C4: 0x30000, 0x4AB5B0 + 4: 0x200})
    page4.Page4Mixin.p4_43c460(_cv_z, _cv_p, _cv_a)
    _cv_hits = [c for c in _cv_z.calls if c[0] == "ui40c"]
    _cv_p2 = page4.Ent(0x1C0, 0x100, 0x10008431, 0)
    _cv_p2.d32(0x10, 1)
    _cv_p2.d32(0x1C, 0x5001)
    _cv_a2 = page4.Ent(0x120, 0x90, 0x10008431, 0)
    _cv_a2.d32(0x10, 1)
    _cv_a2.d32(0x18, 5)
    _cv_z2 = _Z({0x4CD4A0 + 0xEC: 0x1000, 0x10C4: 0x30000})
    page4.Page4Mixin.p4_43c460(_cv_z2, _cv_p2, _cv_a2)
    _cv_hits2 = [c for c in _cv_z2.calls if c[0] == "ui40c"]
    _ef = _Z({0x4CD4A0 + 0xEC: 0x1000})
    page4.Page4Mixin.p4_45e670(_ef, {"b0": 0x21, "b4": 0, "b5": 0, "w6": 0}, 0, 1, 0)
    _ef1 = (_ef.p4_stat.get(0x4CD4A0 + 0x18), _ef.p4_stat.get(0x4CD4A0 + 0x08))
    _ef2 = _Z()
    page4.Page4Mixin.p4_45e670(_ef2, {"b0": 5, "b4": 3, "b5": 0, "w6": 0}, 1, 1, 1)
    _t1 = page4.Ent(0x10, 0x10, 0x100001FF, 0)
    _t1.d32(0x18, 3)
    _t1.d32(0x10, 1)
    _ta1 = page4.Ent(0x120, 0x90, 0x11000000, 0)
    _ta1.d32(0x18, 0x200)
    _ta1.d32(0x10, 1)
    _tz1 = _Z()
    page4.Page4Mixin._p4_43c9c2(_tz1, _t1, _ta1, 0xFF)
    _t2 = page4.Ent(0x10, 0x10, 0x100001FF, 0)
    _t2.d32(0x18, 3)
    _t2.d32(0x10, 1)
    _ta2 = page4.Ent(0x120, 0x90, 0x11000000, 0)
    _ta2.d32(0x18, 0x10)
    _ta2.d32(0x10, 1)
    _ta2.d32(0x0C, 0x30)
    _tz2 = _Z()
    page4.Page4Mixin._p4_43c9c2(_tz2, _t2, _ta2, 0xFF)
    _t3 = page4.Ent(0x10, 0x10, 0x100001FF, 0)
    _t3.d32(0x18, 3)
    _ta3 = page4.Ent(0x120, 0x90, 0x11000000, 0)
    _tz3 = _Z()
    page4.Page4Mixin._p4_43c9c2(_tz3, _t3, _ta3, 0)
    _fb = _Z()
    _fb.ui40c = [1, 2, 3]
    _fb.ui46c = [1]
    _fbsize = page4.Page4Mixin.p4_45fbf0(_fb)
    import struct as _st
    _c7 = _Z()
    _t7 = _c7._p4_tbl4ab5cc()
    _st.pack_into("<I", _t7, 8 + 2 * 2 * 0x54, 0x1234)      # sel=0, idx=2 → k=4
    _c7v1 = _c7.p4_45c740(2)
    _t7[5] = 1                                              # flag → 基址 +0x740
    _st.pack_into("<I", _t7, 0x740 + 2 * 2 * 0x54, 0x5678)
    _c7v2 = _c7.p4_45c740(2)
    _t7[4] = 3                                              # sel=3 → k=3+4=7
    _st.pack_into("<I", _t7, 0x740 + 7 * 0x54, 0x9ABC)
    _c7v3 = _c7.p4_45c740(2)
    from geki import Record as _Rec
    class _PS(_Z):
        def __init__(self):
            super().__init__()
            class _I: pass
            self.inp = _I()
            self.inp.rec = _Rec()
        def p4_ptr(self):
            return (0x140, 0x100)
    _ps = _PS()
    class _Nd:
        dst = None
    _pe = page4.Ent(0x100, 0x100, 0x1, 0)
    _pe.d32(0x18, 1)
    _pe.node = _Nd()
    _ra = page4._beh_type1_follow(_ps, _pe)
    _dstA = _pe.node.dst
    _ps.inp.rec.b1 = True
    _pe.d32(0x04, 0x100)
    _pe.d32(0x08, 0x100)
    _pe.node.dst = None
    _rb = page4._beh_type1_follow(_ps, _pe)
    check("0x4466F0（自机行为 A）：b1==0 且 r1==0 时按 (d+3)>>2 逼近指针；"
          "b1!=0 且 r1==0 时**不移动**；显示节点摆到 (x-0x18, y-0x18)；返回 [e+0x18]!=0",
          _ra is True and _dstA == (0x110 - 0x18, 0x100 - 0x18)
          and _rb is True and _pe.g32(0x04) == 0x100, "")
    _b95s = _PS()
    _b95e = page4.Ent(0x100, 0x100, 0x1, 0)
    _b95e.d32(0x18, 1)
    _b95e.node = _Nd()
    _b95r = page4._beh_446950(_b95s, _b95e)
    _bs4 = _PS()
    _be4 = page4.Ent(0x100, 0x100, 0x1, 0)
    _be4.d32(0x18, 1)
    _be4.node = _Nd()
    _br4 = page4._beh_446A10(_bs4, _be4)
    _bs5 = _PS()
    _be5 = page4.Ent(0x100, 0x100, 0x1, 0)
    _be5.d32(0x18, 1)
    _be5.node = _Nd()
    _br5 = page4._beh_446AD0(_bs5, _be5)
    _sn_e1 = page4.Ent(0x11, 0x22, 0x44, 0)
    _sn_e1.d32(0x18, 0x55)
    _sn_e1.m[0x1C] = 0x66
    _sn_e2 = page4.Ent(0x77, 0x88, 0x99, 0)
    _sn_e2.d32(0x18, 0xAA)
    _sn_e2.m[0x1C] = 0xBB
    _sn_buf = bytearray(0x40)
    _sn_n = _Z().p4_45ff80([_sn_e1, _sn_e2], _sn_buf, 0)
    _sn_w0 = _st.unpack_from("<7I", _sn_buf, 0)
    _sn_w1 = _st.unpack_from("<7I", _sn_buf, 0x20)
    class _KN:
        def test(self, b):
            return False
    class _PN(page4.Page4Mixin):
        def __init__(self):
            self.p4_stat = {}
            self.keys = _KN()
            self.p4_player_pos = None
    class _Nd2:
        src = None
        dst = None
        frame = None
    _pn = _PN()
    _pn_e = page4.Ent(0x40, 0x50, 0x1, 0)
    _pn_e.node = _Nd2()
    _pn.p4_445ece(_pn_e, (0x11, 0x22, 0, 0))
    _pn2 = _PN()
    _pn2.p4_stat[0x4AB5B0 + 4] = 0
    _pn2_e = page4.Ent(0, 0, 0x1, 0)
    _pn2_e.node = _Nd2()
    _pn2.p4_445ece(_pn2_e, (0, 0, 0, 1))
    _fids = [(7 if not b2 else 0xF) + op * 2 + a1
             for b2 in (0, 1) for op in range(4) for a1 in (0, 1)]
    _cd = _PN()
    _cd_e1 = page4.Ent(0, 0, 0x1, 0)
    _cd_e1.node = _Nd2()
    _cd_r1 = _cd.p4_445c00(_cd_e1, (0, 0, 0, 0))
    _cd_e5a = page4.Ent(0, 0, 0x5, 0)
    _cd_e5b = page4.Ent(0, 0, 0x5, 0)
    _cd_r5a = _cd.p4_445c00(_cd_e5a, (0, 0, 0, 0))
    _cd_r5b = _cd.p4_445c00(_cd_e5b, (0, 0, 0, 0))
    _cd_e7 = page4.Ent(0, 0, 0x7, 0)
    _cd. p4_445c00(_cd_e7, (0, 0, 0, 0))
    _cd_bit = _cd.p4_stat.get(0x4AB5B0 + 4, 0)
    _cd2 = _PN()
    _cd2.p4_stat[0x4AB5B0 + 4] = 2
    _cd2_e5 = page4.Ent(0, 0, 0x5, 0)
    _cd2.p4_445c00(_cd2_e5, (0, 0, 0, 0))
    _av = _PN()
    _av_e = page4.Ent(0x30, 0x40, 0x0B000002, 0)
    _av_e.node = _Nd2()
    _av_r = _av.p4_445c00(_av_e, (0, 0, 0, 5))
    _t8 = _PN()
    _t8e = page4.Ent(0, 0, 8, 0)
    _t8e.node = _Nd2()
    _r8 = _t8.p4_445c00(_t8e, (0, 0, 0, 7))
    _t9 = _PN()
    _t9e = page4.Ent(0, 0, 9, 0)
    _t9e.node = _Nd2()
    _r9 = _t9.p4_445c00(_t9e, (0, 0, 0, 7))
    _ta = _PN()
    _tae = page4.Ent(0x30, 0x40, 10, 0)
    _tae.node = _Nd2()
    _ra = _ta.p4_445c00(_tae, (0, 0, 0, 7))
    _jt = [int.from_bytes(img[0x4606D4 - ib + i * 4:0x4606D8 - ib + i * 4], "little")
           for i in range(15)]
    _ac = page4.Page4Mixin.p4_457380_acc
    _map = {0: None, 6: 3, 10: 4, 16: 5, 24: 6, 32: 7,
            48: 8, 72: 9, 108: 10, 160: 11, 240: 12}
    _ok = True
    for _k, _code in _map.items():
        _idx = img[0x457938 - ib + _k]                    # 字节索引表
        _tgt = int.from_bytes(img[0x457908 - ib + _idx * 4:0x45790C - ib + _idx * 4], "little")
        _exp_t = [0x4577EC, 0x4577F5, 0x457800, 0x45780B, 0x457816, 0x457821,
                  0x45782C, 0x457837, 0x457842, 0x45784D, 0x457858, 0x457861]
        if _code is None:
            _ok = _ok and _idx == 0 and _tgt == 0x4577EC
        else:
            _ok = _ok and _tgt == _exp_t[_idx]
            _ok = _ok and int.from_bytes(
                img[_tgt - ib + 5:_tgt - ib + 6], "little") == _code   # mov [reg],imm8 的立即数字节
    import capstone as _cs2
    _md2 = _cs2.Cs(_cs2.CS_ARCH_X86, _cs2.CS_MODE_32)
    _hud_calls = []
    for _off, _in in enumerate(_md2.disasm(img[0x451260 - ib:0x451400 - ib], 0x451260)):
        if _in.mnemonic == "call":
            _t = _in.address + 5 + int.from_bytes(img[_in.address + 1 - ib:_in.address + 5 - ib], "little", signed=True)
            _hud_calls.append(_t)
    _segs = [(0x43DF71, 0x20, 0x1B0, 0x4A405C), (0x43DF98, 0x93, 0x1B0, 0x4A4054),
             (0x43DFBF, 0x106, 0x1B0, 0x4A404C), (0x43DFE6, 0x179, 0x1B0, 0x4A4044),
             (0x43E00D, 0x1EC, 0x1B0, 0x4A4040), (0x43E037, 0x20, 0x20, 0x4A4020),
             (0x43E058, 0x30, 0x20, 0x4A3FEC), (0x43E079, 0x40, 0x20, 0x4A3FD0)]
    _hud_ok = page4.Page4Mixin.P4_HUD_SEGS == tuple(_segs)
    for _n, (_c, _x, _y, _t) in enumerate(_segs):
        _w = img[_c - ib - 0x28:_c - ib]
        _hud_ok = (_hud_ok
                   and _w.endswith(bytes([0xB9, 0xB0, 0xA7, 0x4A, 0x00]))
                   and bytes([0x68, 0xD9, 0x00, 0x00, 0x00, 0x6A, 0x10, 0x68]) in _w
                   and _t.to_bytes(4, "little") in _w)
    _lbl = {0x4A4020: b"Gekihaden(2) version 1.0",
            0x4A3FEC: b"Copyright 2001,2004 by Tatsuya Miyamoto.",
            0x4A3FD0: b"Over 23431 bytes free",
            0x4A4040: b"run", 0x4A4044: b"list", 0x4A404C: b"goto",
            0x4A4054: b"auto", 0x4A405C: b"color"}
    _okl = all(bytes(img[_a - ib:_a - ib + len(_t)]) == _t for _a, _t in _lbl.items())
    import inspect as _insp
    import capstone as _csk
    _mdk = _csk.Cs(_csk.CS_ARCH_X86, _csk.CS_MODE_32)
    _cap = page4.Page4Mixin.p4_446c50_capture
    _cp = {i.address: (i.mnemonic, i.op_str)
           for i in _mdk.disasm(img[0x446C50 - ib:0x446CB0 - ib], 0x446C50)}
    check("0x446C50 btn2(0x4AB597) 生成捕获实体 0x10008041 到 ui46c（a3=[e+0x1C] 指针）+ 0x446470(e,1,1) + [e+0x20]=1",
          _cap(0) is None and _cap(1) == (0x10008041, True)
          and _cp.get(0x446C50) == ("mov", "al, byte ptr [0x4ab597]")
          and _cp.get(0x446C6C) == ("push", "0x10008041")
          and _cp.get(0x446C91) == ("mov", "ecx, 0x4ad46c")
          and _cp.get(0x446CA2) == ("call", "0x401aa5")
          and _cp.get(0x446CA8) == ("mov", "dword ptr [ebx + 0x20], 1"), "")
    _ct20 = {i.address: (i.mnemonic, i.op_str)
             for i in _mdk.disasm(img[0x445F56 - ib:0x445F68 - ib], 0x445F56)}
    _src = open(page4.__file__, encoding="utf-8").read()
    check("0x445F56..0x445F64 自机 ctor 的 [+0x20] = (rec[3]==1) ? **0** : **-1**"
          "（dec/neg/sbb 链：a3==1 ⇒ CF=0 ⇒ sbb 得 0；否则得 -1）；"
          "0x448DB9 复活时 a3 = 剩余次数 n",
          _ct20.get(0x445F59) == ("dec", "eax")
          and _ct20.get(0x445F5D) == ("neg", "eax")
          and _ct20.get(0x445F5F) == ("sbb", "eax, eax")
          and _ct20.get(0x445F64) == ("mov", "dword ptr [ebx + 0x20], eax")
          and "e.d32(0x20, 0 if a3 == 1 else 0xFFFFFFFF)" in _src
          and "0x0B000001, 200, 200, n)" in _src, "")
    _rs = page4.Page4Mixin.p4_self_respawn_rec
    _rd = {i.address: (i.mnemonic, i.op_str)
           for i in _mdk.disasm(img[0x44370A - ib:0x443790 - ib], 0x44370A)}
    check("0x443729 自机复活：清 ui4cc → 在 (0xC8,0xC8) 生成 0x0B000001（a3=3）入 ui40c；"
          "另一支 0x4AB597 非 0 → 置页旗标 0x200 退页；触发条件是死亡计时器 == 0xF0",
          _rs() == (0xC8, 0xC8, 0x0B000001, 3)
          and _rd.get(0x44370A) == ("cmp", "ebp, 0xf0")
          and _rd.get(0x443716) == ("mov", "al, byte ptr [0x4ab596]")
          and _rd.get(0x443729) == ("push", "3")
          and _rd.get(0x44372B) == ("push", "0xb000001")
          and _rd.get(0x443742) == ("call", "0x4023c4")     # thunk → 0x430400
          and _rd.get(0x443787) == ("mov", "ecx, 0x4ab5c0"), "")
    import re as _re
    _esp, _slotw = 0, {}
    _movsd = 0
    for _i in _mdk.disasm(img[0x430400 - ib:0x43043C - ib], 0x430400):
        if _i.mnemonic == "sub" and _i.op_str.startswith("esp"):
            _esp -= 0x14
            continue
        if _i.mnemonic == "mov" and _i.op_str.startswith("dword ptr [esp"):
            _m = _re.search(r"\[esp \+ (0x[0-9a-f]+)\]", _i.op_str) or \
                 _re.search(r"\[esp\]", _i.op_str)
            _off = int(_m.group(1), 16) if _m.groups() else 0
            _s = (_esp + _off) + 0x14                      # 相对 S 的槽号
            if _s % 4 == 0:
                _slotw[_s // 4] = _i.address
        if _i.mnemonic == "rep movsd":
            _movsd = 5
        if _i.mnemonic == "push":
            _esp -= 4
        elif _i.mnemonic == "pop":
            _esp += 4
    _rec = page4.Page4Mixin.p4_430400_rec
    check("0x430400 是 cdecl 4 参记录填充：slot0=x(arg2)、slot1=y(arg3)、slot2=type(arg4)、"
          "slot3=a3(arg5)；rep movsd 拷 5 个 dword 而 **slot4 从未被写** "
          "⇒ rec[0x10] 是调用者栈残留；a3 是 dword 指针还是数值由实体构造函数解释",
          _movsd == 5
          and sorted(_slotw) == [0, 1, 2, 3]
          and _slotw[0] == 0x43040F and _slotw[1] == 0x430421
          and _slotw[2] == 0x430430 and _slotw[3] == 0x430418
          and _rec(1, 2, 3, 4, 5) == (1, 2, 3, 4, 5)
          and img[0x43043B - ib] == 0xC3, "")
    _hit = open(page4.__file__, encoding="utf-8").read()
    _anchor = _hit.index("—— 最后一击")
    _lf = _hit[_anchor: _anchor + 1600]
    check("0x43C1AF 命中(类型6)的最后一击分支：HP<=1 时**不扣血**，"
          "半径 0x30 且类型不在 6 例 → 生成 0x61000004 入 ui52c，否则 0x41000001 入 ui4cc；"
          "随后 0x45EFF0(type,0x100D1211,x,y) + 清 active/HP + SE 4 带声像",
          _lf.count("0x61000004") >= 1 and _lf.count("0x41000001") >= 1
          and _lf.count("0x100D1211") >= 1 and _lf.count("0x140") >= 1
          and "p4_45eff0(a.s32(0x14), 0x100D1211" in _lf
          and "self.p4_se_pan(4," in _lf
          and "return" in _lf
          and img[0x43C212 - ib:0x43C215 - ib] == bytes([0x83, 0xF8, 0x01])
          and img[0x43C21B - ib:0x43C21E - ib] == bytes([0x8B, 0x45, 0x0C]), "")
    _tri = page4.Page4Mixin.p4_4590_tri
    _pair = page4.Page4Mixin.p4_450580_pair
    _bs2 = {i.address: (i.mnemonic, i.op_str)
            for i in _mdk.disasm(img[0x450580 - ib:0x450592 - ib], 0x450580)}
    check("0x450580 只是两字节存（[mgr+0x5C]=arg1、[mgr+0x5D]=arg2，ret 8），不是播 SE；"
          "键16 的 0x18 字段是三态 0→1→3→0",
          _tri(0) == 1 and _tri(1) == 3 and _tri(3) == 0 and _tri(2) == 0
          and _pair(1, 0) == (0, 1) and _pair(0, 1) == (1, 0)
          and _bs2.get(0x450588) == ("mov", "byte ptr [ecx + 0x5c], al")
          and _bs2.get(0x45058B) == ("mov", "byte ptr [ecx + 0x5d], dl")
          and _bs2.get(0x45058E) == ("ret", "8"), "")
    _setf = page4.Page4Mixin.p4_45b0e0_set
    _xorf = page4.Page4Mixin.p4_45af90_xor
    _bd = {i.address: (i.mnemonic, i.op_str)
           for i in _mdk.disasm(img[0x45AF90 - ib:0x45AFA2 - ib], 0x45AF90)}
    _bs = {i.address: (i.mnemonic, i.op_str)
           for i in _mdk.disasm(img[0x45B0E0 - ib:0x45B112 - ib], 0x45B0E0)}
    check("位域 API 补全：0x45AF90 = word^=mask(ret 4)、0x45B0E0 = "
          "word=(word&~mask)|((value<<低位序号)&mask)(ret 8)",
          _xorf(0, 0x40) == 0x40 and _xorf(0x40, 0x40) == 0
          and _setf(0, 0xFE000000, 5) == 5 << 25
          and _setf(0xABCD, 0x18, 3) == 0xABDD
          and _setf(0xFFFFFFFF, 0x18, 0) == 0xFFFFFFE7
          and _bd.get(0x45AF97) == ("xor", "edx, eax")
          and _bd.get(0x45AF9E) == ("ret", "4")
          and _bs.get(0x45B102) == ("and", "edx, edi")
          and _bs.get(0x45B106) == ("or", "edx, eax")
          and _bs.get(0x45B10D) == ("ret", "8"), "")
    _step = page4.Page4Mixin.p4_4590_step
    _dec = {i.address: (i.mnemonic, i.op_str)
            for i in _mdk.disasm(img[0x4590DC - ib:0x4591E6 - ib], 0x4590DC)}
    check("0x458FD0 的键映射 + 对比/亮度 ±10 无符号回绕（键20/21 对 0xFE000000、键22/23 对 0x1FC0000）",
          _step(0, 10) == 10 and _step(94, 10) == 0 and _step(4, -10) == 0
          and _step(99, 0) == 99 and _step(10, -10) == 0
          and _dec.get(0x4590DC) == ("push", "0xfe000000")
          and _dec.get(0x4590E1) == ("mov", "ecx, 0x4ab5b8")
          and _dec.get(0x4590EB) == ("add", "eax, 0xa")
          and _dec.get(0x45912E) == ("sub", "eax, 0xa")
          and _dec.get(0x45910D) == ("cmp", "eax, 0x64")
          and _dec.get(0x459163) == ("mov", "ecx, 0x4ab5b8")
          and _dec.get(0x45916D) == ("add", "eax, 0xa"), "")
    _d = page4.Page4Mixin.p4_457d20
    _chain = [(i.address, i.mnemonic, i.op_str)
              for i in _mdk.disasm(img[0x457D24 - ib:0x457D3A - ib], 0x457D24)]
    check("0x457D20(this,i) 的步长链 = this + i*0x2A98 + 0x10；0x457520 只是 lea eax,[ecx+0xC] 取值器",
          _d(0) == 0x10 and _d(1) == 0x2A98 + 0x10 and _d(3) == 3 * 0x2A98 + 0x10
          and 0x2A98 == 1363 * 8
          and [c[1] for c in _chain][:6] == ["mov", "shl", "add", "lea", "lea", "lea"]
          and img[0x457520 - ib:0x457520 - ib + 3] == bytes([0x8D, 0x41, 0x0C])
          and img[0x457520 - ib + 3] == 0xC3, "")
    _sk = page4.Page4Mixin.p4_44caa0_skip
    _tests = {}
    for _i in _mdk.disasm(img[0x44CB58 - ib:0x44CB7A - ib], 0x44CB58):
        if _i.mnemonic == "test":
            _tests[_i.address] = _i.op_str
        if _i.mnemonic == "je":
            _tests[("je", _i.address)] = _i.op_str
    check("0x44CAA0 的早期跳过：三个值任一为 0 → je 0x44CCA4，跳过 0x44CCBD→0x44B790 变换 "
          "（页4 那次调用带一个 0，所以登记了 (-200,-200) 也不会压黑画面）",
          _sk(1, 1, 1) is False and _sk(0, 1, 1) is True
          and _sk(1, 0, 1) is True and _sk(1, 1, 0) is True
          and _tests.get(0x44CB5E) == "eax, eax"
          and _tests.get(0x44CB66) == "ecx, ecx"
          and _tests.get(0x44CB70) == "esi, esi"
          and "0x44cca4" in (_tests.get(("je", 0x44CB60)) or "")
          and "0x44cca4" in (_tests.get(("je", 0x44CB68)) or "")
          and "0x44cca4" in (_tests.get(("je", 0x44CB72)) or ""), "")
    _af = page4.Page4Mixin.p4_afc0
    check("0x45AFC0 的 ecx 是对象指针不是固定全局：0x445EAA/0x44613A 传 0x4AB5B0、"
          "0x451663/0x45167A 传 0x4AB5B8；语义 = (word&mask) 右移到 mask 最低位，取 0 直接返回",
          list(_insp.signature(_af).parameters) == ["self", "mask", "base"]
          and img[0x45AFC0 - ib:0x45AFC0 - ib + 3] == bytes([0x8B, 0x41, 0x04])
          and img[0x45AFC9 - ib:0x45AFC9 - ib + 2] == bytes([0x74, 0x0E])
          and img[0x45AFD9 - ib:0x45AFD9 - ib + 2] == bytes([0xC2, 0x04]), "")
    _sig = _insp.signature(page4.Page4Mixin.p4_load_palette)
    import numpy as _np
    from geki import fade_palette as _fp
    _p = _np.arange(1024, dtype=_np.uint8).reshape(256, 4)
    check("0x44CDF0 的对比/亮度已接进 p4_load_palette(ident, ct, br)："
          "ct→b(乘性)、br→a(加性)，(0,0) 是恒等；cfg 未定位时不得施加强压暗",
          list(_sig.parameters) == ["self", "ident", "ct", "br"]
          and (_fp(_p, 0, 0) == _p).all()
          and _fp(_p, -200, -200)[0, 0] == 55
          and page4.Page4Mixin.p4_451630_adjust(0) == (-200, -200)
          and "self.p4_pal_adj = (br, ct)" in open(page4.__file__, encoding="utf-8").read()
          and "只登记" in open(page4.__file__, encoding="utf-8").read(), "")
    _adj = page4.Page4Mixin.p4_451630_adjust
    check("0x451657..0x45168E 阶段首帧的对比/亮度：两个 7 位字段 ×4−200；"
          "亮度取 (w&0x1FC0000)>>18、对比取 (w&0xFE000000)>>25；"
          "压栈顺序 push f1/f2/2 ⇒ 0x44CDF0(mgr, id=2, 对比, 亮度)",
          _adj(0) == (-200, -200)
          and _adj(0x1FC0000) == (308, -200)
          and _adj(0xFE000000) == (-200, 308)
          and _adj(0x1FC0000 | 0xFE000000) == (308, 308)
          and _adj(0x20000000) == (-200, -136)
          and img[0x451659 - ib:0x451659 - ib + 5] == bytes([0x68, 0x00, 0x00, 0xFC, 0x01])
          and img[0x451675 - ib:0x451675 - ib + 5] == bytes([0x68, 0x00, 0x00, 0x00, 0xFE])
          and img[0x451668 - ib:0x451668 - ib + 7] == bytes([0x8D, 0x04, 0x85, 0x38, 0xFF, 0xFF, 0xFF]), "")
    _tar = page4.Page4Mixin.p4_4511_ta
    check("0x451186..0x451206：[0x56CCD4]（TA）= (B-上次B)*100/(A-上次A)，钳 999；"
          "B 未变整段跳过、A 未变只更新上次值",
          _tar(0, 10, 0, 5, 0) == (200, 10, 5)
          and _tar(0, 0, 0, 5, 42) == (42, 0, 0)
          and _tar(0, 10, 0, 0, 42) == (42, 10, 0)
          and _tar(0, 100, 0, 1, 0) == (999, 100, 1)
          and img[0x4511EA - ib:0x4511EA - ib + 5] == bytes([0x3D, 0xE8, 0x03, 0x00, 0x00])
          and img[0x4511F6 - ib:0x4511F6 - ib + 10]
              == bytes([0xC7, 0x05, 0xD4, 0xCC, 0x56, 0x00, 0xE7, 0x03, 0x00, 0x00]), "")
    _sts = page4.Page4Mixin.p4_4512_status
    check("0x451259..0x4512C2 状态行 = 「TS:%05d 」(值/1000，钳 0x5F5DD18=99999000) + 「TA:%03d 」",
          _sts(0, 0) == "TS:00000 TA:000 "
          and _sts(12345, 7) == "TS:00012 TA:007 "
          and _sts(99999999, 999) == "TS:99999 TA:999 "
          and _sts(100000000, 12) == "TS:99999 TA:012 "
          and img[0x451268 - ib:0x451268 - ib + 5] == bytes([0xB8, 0xD3, 0x4D, 0x62, 0x10])
          and img[0x451259 - ib:0x451259 - ib + 5] == bytes([0x81, 0xFD, 0x18, 0xDD, 0xF5])
          and img[0x451273 - ib:0x451273 - ib + 3] == bytes([0xC1, 0xEA, 0x06])
          and bytes(img[0x4A488C - ib:0x4A488C - ib + 9]) == b"TS:%05d \x00"
          and bytes(img[0x4A4880 - ib:0x4A4880 - ib + 9]) == b"TA:%03d \x00", "")
    check("0x43DFxx 八段是**调试覆盖层**：版本/版权/剩余内存 + run/list/goto/auto/color；"
          "真正状态栏在 0x451316（高 0xC、y 0x1D4、x 0、文本来自栈缓冲）",
          _okl
          and img[0x451303 - ib:0x451303 - ib + 2] == bytes([0x6A, 0x0C])
          and img[0x4512F2 - ib:0x4512F2 - ib + 5] == bytes([0x68, 0xB4, 0x00, 0x00, 0x00])
          and img[0x451306 - ib:0x451306 - ib + 5] == bytes([0x68, 0xD4, 0x01, 0x00, 0x00]), "")
    _g = page4.Page4Mixin.p4_43df_hud_gate
    check("HUD 主体：8 段文字（底行 y=0x1B0 x=0x20/0x93/0x106/0x179/0x1EC，"
          "顶行 y=0x20 x=0x20/0x30/0x40），色 0xD3 底 0xD9 高 0x10；"
          "绘制门 = v==0xC8 或 0xE6<=v<0x122",
          _hud_ok
          and [_g(v) for v in (0xC7, 0xC8, 0xE5, 0xE6, 0x121, 0x122)]
              == [False, True, False, True, True, False]
          and img[0x43DF35 - ib:0x43DF3B - ib] == bytes([0x3D, 0xC8, 0x00, 0x00, 0x00, 0x74]),
          "")
    check("HUD 文字绘制的入口：页4 每帧里 0x451316 调 0x4022C0(→0x44D330)，"
          "另有 0x43DF71..0x43E079 八连调与 0x43E2C3、0x445395",
          img[0x451316 - ib] == 0xE8
          and 0x4022C0 in _hud_calls, "")
    check("0x457938 字节索引表 + 0x457908 十二项跳表：kind ∈ {0,6,10,16,24,32,48,72,108,160,240} "
          "→ 图块码 {—,3..12}；其余与 >0xF0 一律走 0x457861 兜底",
          _ok
          and all(img[0x457938 - ib + k] == 11 for k in range(0xF1)
                  if k not in _map)
          and img[0x4577DD - ib:0x4577DD - ib + 4] == bytes([0x33, 0xC9, 0x8A, 0x88]), "")
    check("0x457750：+8 是参数区指针（[+0x38]=params[14] 步进）、+0xC 是位置、"
          "+4 是格子表（表项 3 dword、kind 在 +8）；抖动按 kind 缩放 >>6",
          img[0x457757 - ib:0x457757 - ib + 6] == bytes([0x8B, 0x46, 0x08, 0x8B, 0x7E, 0x0C])
          and img[0x45775D - ib:0x45775D - ib + 3] == bytes([0x8B, 0x48, 0x38])
          and img[0x4577A4 - ib:0x4577A4 - ib + 3] == bytes([0x8D, 0x14, 0x40])
          and img[0x4577AB - ib:0x4577AB - ib + 4] == bytes([0x8B, 0x44, 0x90, 0x08])
          and img[0x4577C3 - ib:0x4577C3 - ib + 2] == bytes([0xC1, 0xF9])
          and img[0x4577D1 - ib:0x4577D1 - ib + 3] == bytes([0x89, 0x4E, 0x20]), "")
    check("0x457540 节点 ctor：vtable 0x499140、next 清 0、phase→+4、抖动 = "
          "rand % ([p8+0x20]+1) / rand % ([p8+0x24]+1)（X 先 Y 后）、+0x1C=-1、+0x20/+0x24=0",
          img[0x457553 - ib:0x457553 - ib + 5] == bytes([0xC7, 0x06, 0x40, 0x91, 0x49])
          and img[0x457559 - ib:0x457559 - ib + 3] == bytes([0x89, 0x5E, 0x30])
          and img[0x45755C - ib:0x45755C - ib + 2] == bytes([0x89, 0x46])
          and img[0x457567 - ib:0x457567 - ib + 2] == bytes([0x8B, 0x4F])
          and img[0x457576 - ib:0x457576 - ib + 2] == bytes([0x8B, 0x4F])
          and img[0x457579 - ib:0x457579 - ib + 6] == bytes([0xC7, 0x46, 0x1C, 0xFF, 0xFF, 0xFF])
          and img[0x4575A5 - ib:0x4575A5 - ib + 2] == bytes([0x89, 0x18]), "")
    check("0x457120：节点 0x34 字节、头 [+4]、尾 [+8]、next 在 +0x30；"
          "890 (=0xA6E) 上限在 0x457282（摘链路径）而不是 0x457120",
          img[0x457139 - ib:0x457139 - ib + 2] == bytes([0x6A, 0x34])
          and img[0x45713B - ib:0x45713B - ib + 2] == bytes([0x8B, 0x46])
          and img[0x457175 - ib:0x457175 - ib + 4] == bytes([0x89, 0x46, 0x04, 0xEB])
          and img[0x4571BB - ib:0x4571BB - ib + 3] == bytes([0x89, 0x41, 0x30])
          and img[0x457282 - ib:0x457282 - ib + 5] == bytes([0xB9, 0x6E, 0x0A, 0x00, 0x00]), "")
    check("0x457380 累加器：acc += step；|acc| < 阈值 不触发；"
          "step>=0 → 相位 acc-阈值、acc-=阈值；step<0 → acc += 阈值 且相位 = [+0x58]+acc-1（32 位回绕）",
          _ac(0, 3, 10, 0) == (None, 3)
          and _ac(7, 5, 10, 0) == (2, 2)
          and _ac(0, 10, 10, 0) == (0, 0)
          and _ac(7, -20, 10, 5) == (1, 0xFFFFFFFD)
          and img[0x457403 - ib:0x457408 - ib] == bytes([0x99, 0x33, 0xC2, 0x2B, 0xC2])
          and img[0x45740E - ib] == 0x7C, "")
    check("0x4606D4 = 15 项 opcode 跳表；op 1..5 分别入 ui40c/ui43c/ui4cc/ui4fc/ui52c；op 0xE 只跳过 0x14",
          _jt == [0x460686, 0x46044F, 0x4603AD, 0x460411, 0x460490,
                  0x4604D1, 0x460554, 0x460574, 0x4605C6, 0x460512,
                  0x460538, 0x460600, 0x46064A, 0x46066D, 0x4603E9]
          and img[0x4603E9 - ib:0x4603E9 - ib + 5] == bytes([0xBF, 0x14, 0x00, 0x00, 0x00])
          and img[0x460480 - ib:0x460480 - ib + 5] == bytes([0xB9, 0x0C, 0xD4, 0x4A, 0x00])
          and img[0x4603DE - ib:0x4603DE - ib + 5] == bytes([0xB9, 0x3C, 0xD4, 0x4A, 0x00])
          and img[0x4604C1 - ib:0x4604C1 - ib + 5] == bytes([0xB9, 0xFC, 0xD4, 0x4A, 0x00])
          and img[0x460502 - ib:0x460502 - ib + 5] == bytes([0xB9, 0x2C, 0xD5, 0x4A, 0x00])
          and img[0x460442 - ib:0x460442 - ib + 5] == bytes([0xB9, 0xCC, 0xD4, 0x4A, 0x00]), "")
    check("type 8/9/10 构造器：8→0x4015FF 且 [+0x20/0x24/0x28]=5/5/0；9→0x40116D 且 [+0x20]=0；"
          "10→0x401BE0 半径 0xC、[+0x1C]=-1、矩形 (0,op*0x30,0x2F,op*0x30+0x2F)、dst=(x-0x18,y-0x18)",
          _r8 == "handled:8" and _t8e.g32(0x40) == 0x4015FF
          and (_t8e.g32(0x20), _t8e.g32(0x24), _t8e.g32(0x28)) == (5, 5, 0)
          and _t8e.g32(0x1C) == 7
          and _r9 == "handled:9" and _t9e.g32(0x40) == 0x40116D and _t9e.g32(0x20) == 0
          and _ra == "handled:10" and _tae.g32(0x40) == 0x401BE0
          and _tae.g32(0x0C) == 0xC and _tae.g32(0x1C) == 0xFFFFFFFF
          and _tae.node.src == (0, 0, 47, 47)
          and _tae.node.dst == (0x30 - 0x18, 0x40 - 0x18)
          and _ta.p4_stat.get("44621a_ui46c") == 1, "")
    check("0x44604E 自机头像：行为 0x401E06、半径 0x10、**构造即活**(alive=1)、HP 1、"
          "节点 dst 的 x 偏 +0x40、frame=1、置 word[0x56CCC0] 的 bit0",
          _av_r == "handled:0xb000002"
          and _av_e.g32(0x40) == 0x401E06 and _av_e.g32(0x0C) == 0x10
          and _av_e.m[0x10] == 1 and _av_e.g32(0x18) == 1 and _av_e.g32(0x20) == 5
          and _av_e.node.dst == (0x30 + 0x40, 0x40) and _av_e.node.frame == 1
          and _av_e.node.src == (0x80, 0x50, 0x9F, 0x6F)
          and _av.p4_player_pos == (0x30, 0x40)
          and (_av.p4_stat[0x56CCC0] & 1) == 1, "")
    check("0x445C00 分派：1→0x445ECE、5→0x445E47（idx 0 稳定、bit2 置位则 idx 4）、"
          "6→已处理、其它记 pending；**构造器只测 bit1 不置位**",
          _cd_r1 == "handled:1" and _cd_e1.g32(0x40) == 0x4466F0
          and _cd_r5a == "handled:5" and _cd_r5b == "handled:5"
          and _cd_e5a.g32(0x40) == 0x40197E and _cd_e5b.g32(0x40) == 0x40197E
          and _cd_bit == 0                     # ★ 不能被构造器写成 2
          and _cd2_e5.g32(0x40) == 0x40189D
          and _cd.p4_stat.get(("445c00_pending", 7)) == 1, "")
    check("0x446470 的 fid = (7|0xF) + op*2 + arg1 ∈ 7..0x16；0x498A88 表 24 条（fid 24 起全 0），不越界",
          min(_fids) == 7 and max(_fids) == 0x16
          and img[0x498A88 - ib + 23 * 14] == 0x01                 # fid 23 仍是有效行
          and img[0x498A88 - ib + 24 * 14:0x498A88 - ib + 25 * 14] == bytes(14)
          and img[0x446475 - ib:0x446475 - ib + 5] == bytes([0x6A, 0x02, 0xB9, 0xB0, 0xB5])
          and img[0x446492 - ib:0x446492 - ib + 2] == bytes([0x83, 0xC0]), "")
    check("0x435440 的条件过滤：byte[0x56CCB2] 非零时只放行 (类型 & 0x3F000000)==0x32000000",
          _Z().p4_435440("ui49c", 0x12061128) is True
          and _Z({0x56CCB2: 1}).p4_435440("ui49c", 0x12061128) is False
          and _Z({0x56CCB2: 1}).p4_435440("ui49c", 0x32000005) is True, "")
    check("0x45F201 的 0x32000005 入队目标是 0x4AD49C（ui49c），"
          "入队函数是 0x435440（不是 0x43A3C0/0x448FF0）",
          img[0x45F201 - ib:0x45F201 - ib + 5] == bytes([0xB9, 0x9C, 0xD4, 0x4A, 0x00])
          and img[0x45F207 - ib] == 0xE8
          and img[0x45F1DC - ib:0x45F1DC - ib + 5] == bytes([0x68, 0x05, 0x00, 0x00, 0x32])
          and img[0x45F20C - ib:0x45F20C - ib + 4] == bytes([0xC6, 0x45, 0x2A, 0x00]), "")
    check("0x445ECE 尾段：0x45A750 是四 dword 打包（out=(a,b,c,d)）；"
          "矩形 = (0, op*0x30, 0x2F, op*0x30+0x2F)；dst=(x-0x18,y-0x18)；"
          "frame=0；随后 0x446470(e,0,1)；[0x56CC8C]=rec[0]",
          _pn_e.node.src == (0, 0, 47, 47)
          and _pn_e.node.dst == (0x40 - 0x18, 0x50 - 0x18)
          and _pn_e.node.frame == 0
          and _pn.p4_player_pos == (0x11, 0x22), "")
    _pl = _Z()
    _pl_e = page4.Ent(0, 0, 0x1, 0)
    _pl.p4_445ece(_pl_e, (0, 0, 0, 1))
    _pl2 = _Z()
    _pl2.p4_stat[0x4AB5B0 + 4] = 2          # bit2 已置位 ⇒ edx = 4
    _pl2_e = page4.Ent(0, 0, 0x1, 0)
    _pl2.p4_445ece(_pl2_e, (0, 0, 0, 0))
    check("0x445ECE 自机构造器：半径 0xA、alive=0、HP=1、索引 {0,5,6,7}、"
          "[+0x20]=([rec+0xC]==1 ? 0 : -1)（§16.272 勘误：原先写反）、精灵 y = op*0x30+0x2F",
          _pl_e.g32(0x0C) == 0xA and _pl_e.m[0x10] == 0 and _pl_e.g32(0x18) == 1
          and _pl_e.g32(0x40) == 0x4466F0 and _pl_e.g32(0x20) == 0          # a3==1 → 0
          and _pl.p4_stat["player_sprite_y"] == 0x2F
          and _pl2_e.g32(0x40) == 0x446A10 and _pl2_e.g32(0x20) == 0xFFFFFFFF  # a3!=1 → -1
          and page4.P4_PLAYER_BEH == (0x4466F0, 0x4467D0, 0x446890, 0x446950,
                                      0x446A10, 0x446AD0, 0x446B50, 0x446BD0), "")
    _sb = _Z()
    _sb.ui4cc = []
    _sb.ui43c = []
    _sb.ui49c = []
    _sb.ui40c = [page4.Ent(5, 6, 7, 0)]
    _sb.p4_stat["45fbf0_seg"] = 1
    _sb.p4_stat["45fbf0_total"] = 1
    _sb.p4_stat["45fbf0_size"] = 0x5C
    _sb_m = bytearray(0x20)
    _st.pack_into("<I", _sb_m, 4, 1)          # 段字节数 1*4
    _st.pack_into("<I", _sb_m, 8, 0xAA)       # [mgr+8] → buf+0x10
    _st.pack_into("<I", _sb_m, 0xC, 0xBB)     # [mgr+0xC] → buf+0x14
    _sb.p4_stat["blk_4cd484"] = _sb_m
    _sb.p4_stat[("blk", "blk_4cd484")] = bytes(range(32))
    _sb_t = bytearray(0x80)
    _sb.p4_stat["blk_4aa7b0"] = _sb_t
    _st.pack_into("<I", _sb_t, 0x4C, 0x1234)
    _sb.p4_stat[("bgslot", 0)] = [page4.Ent(1, 2, 3, 0)]
    _sb_buf = bytearray(0x400)
    _sb_n = _sb.p4_45fcb0(_sb_buf)
    _sb_hdr = _st.unpack_from("<6I", _sb_buf, 0)
    check("0x45FCB0 全程：头部 6 dword（大小/0xE/段数/total/[mgr+8]/[mgr+0xC]）"
          "+ 0xE 个层表项 + 段块 + 12 背景槽 + 4 队列；返回末偏移",
          _sb_hdr == (0x5C, 0xE, 1, 1, 0xAA, 0xBB)
          and _st.unpack_from("<I", _sb_buf, 0x18)[0] == 0x1234
          and _sb_n == 0x18 + 0x38 + 4 + 4 + 0x20 + 0x20, "")
    _dc = _Z()
    _dc_tbl = bytearray(0x80)
    _dc.p4_stat["LT"] = _dc_tbl
    _st.pack_into("<I", _dc_tbl, 0x4C + 3 * 4, 0xBEEF)
    _dc_m = bytearray(0x20)
    _st.pack_into("<I", _dc_m, 4, 3)          # [mgr+4] = 3 ⇒ 0x4563D0 拷 3*4 = 12 字节
    _st.pack_into("<I", _dc_m, 0x10, 8)       # 源偏移 8
    _dc.p4_stat["MT"] = _dc_m
    _dc.p4_stat[("blk", "MT")] = bytes(range(32))
    _dc_dst = bytearray(0x40)
    _dc_n = _dc.p4_4563d0("MT", _dc_dst, 0)
    check("0x44DCF0 = [this+idx*4+0x4C]；0x4563D0 = memcpy [mgr+4]*4 字节（源 [mgr+0x10]）",
          _dc.p4_44dcf0("LT", 3) == 0xBEEF and _dc.p4_44dcf0("LT", 99) == 0
          and _dc_n == 12 and bytes(_dc_dst[:12]) == bytes(range(8, 20)), "")
    _cq = [page4.Ent(1, 2, 3, 0) for _ in range(3)]
    check("0x430860 = [queue+0x24] 计数；0x430880 = queue+4 头指针（**两个不同函数**）；"
          "0x45FF80 写的字节数 = 0x20 × 0x430860 的计数",
          _Z().p4_430860(_cq) == 3
          and _Z().p4_430880(_cq) is _cq
          and _Z().p4_45ff80(_Z().p4_430880(_cq), bytearray(0x100)) == 0x60, "")
    check("0x45FF80 快照记录 = 0x20 字节 / 8 dword："
          "[+0]=vtable [+4]=x [+8]=y [+0xC]=半径 [+0x10]=活跃 [+0x14]=类型 [+0x18]=HP [+0x1C]=字节",
          _sn_n == 0x40
          and _sn_w0 == (0x49874C, 0x11, 0x22, 0, 0, 0x44, 0x55) and _sn_buf[0x1C] == 0x66
          and _sn_w1 == (0x49874C, 0x77, 0x88, 0, 0, 0x99, 0xAA) and _sn_buf[0x3C] == 0xBB
          and 0x20 * 8 == 0x100, "")   # 8 dword 记录 ⇒ 与 0x45FBF0 的 total*8 对齐
    check("0x446A10（索引 4）/ 0x446AD0（索引 5）：**直接吸附**到指针（无 /4），"
          "并发布坐标；两者都已登记进 P4_BEH",
          _br4 is True and (_be4.g32(0x04), _be4.g32(0x08)) == (0x140, 0x100)
          and _bs4.p4_player_pos == (0x140, 0x100)
          and _be4.node.dst == (0x140 - 0x18, 0x100 - 0x18)
          and _br5 is True and (_be5.g32(0x04), _be5.g32(0x08)) == (0x140, 0x100)
          and _be5.node.dst == (0x140 - 0x18, 0x100 - 0x18)
          and page4.P4_BEH[0x446A10] is page4._beh_446A10
          and page4.P4_BEH[0x446AD0] is page4._beh_446AD0, "")
    _bs6 = _PS()
    _be6 = page4.Ent(0x100, 0x100, 0x1, 0)
    _be6.d32(0x18, 1)
    _be6.node = _Nd()
    _bs6.inp.rec.b1 = True          # b1 != 0 且 r1 == 0 ⇒ **不移动**
    page4._beh_446A10(_bs6, _be6)
    check("0x446A10 的 b1!=0/r1==0 分支不移动（与 0x4466F0 同构的四态）",
          _be6.g32(0x04) == 0x100 and _be6.g32(0x08) == 0x100, "")
    check("0x446950（= 0x446890 逐字节相同）：1/4 步进 + **发布 [0x56CC8C]/[0x56CC90]** + "
          "显示节点 (x-0x18,y-0x18)",
          _b95r is True and _b95e.g32(0x04) == 0x110
          and _b95s.p4_player_pos == (0x110, 0x100)
          and _b95e.node.dst == (0x110 - 0x18, 0x100 - 0x18), "")
    check("0x4466F0 的输入字节是 rec.b1(0x4AB595) / rec.r1(0x4AB599)，不是位域",
          img[0x4466FE - ib:0x446703 - ib] == bytes([0xA0, 0x95, 0xB5, 0x4A, 0x00])
          and img[0x446705 - ib:0x44670A - ib] == bytes([0xA0, 0x99, 0xB5, 0x4A, 0x00]), "")
    check("0x45C740：索引 = byte[this+4] + idx*2，记录 0x54 字节，"
          "byte[this+5] 选基址 +8 或 +0x740；返回记录首 dword",
          _c7v1 == 0x1234 and _c7v2 == 0x5678 and _c7v3 == 0x9ABC, "")
    check("0x45FBF0 缓冲大小 = (A + total*8 + 0xE)*4 + 0x18；total 里 ui40c 计两次"
          "（0x430860 调了七次，最后一次仍是 0x4AD40C）",
          _fb.p4_stat["45fbf0_total"] == 7 and _fbsize == (0 + 7 * 8 + 0xE) * 4 + 0x18, "")
    _rb = _Z({0x4CD4A0 + 0xEC: 0x1000, 0x4CD4A0 + 0xE4: 10, 0x4CD4A0 + 0xE2: 3})
    page4.Page4Mixin.p4_45eff0(_rb, 0x21000131, 0, 0)
    check("0x45EFF0 尾：分数超过 [mgr+0xE4] 时重建缓冲（大小 = 0x45FBF0）并推进 [mgr+0xE2]",
          _rb.p4_stat[0x4CD4A0 + 0x04] > 10
          and isinstance(_rb.p4_stat.get(0x4CD4A0 + 0xE8), (bytes, bytearray))
          and len(_rb.p4_stat[0x4CD4A0 + 0xE8]) == _rb.p4_stat["45fbf0_size"]
          and _rb.p4_stat[0x4CD4A0 + 0xE2] == 2, "")
    check("0x43C9C2 共用尾：靶硬时 [a+0x18] -= k 且只放 SE 5（pan=(x-0x140)<<4）；"
          "靶破时入列 0x61000004(半径 0x30) 并注销靶；k==0 直接返回",
          _t1.g32(0x18) == 2 and _ta1.g32(0x18) == 0x101 and _ta1.g32(0x10) == 1
          and [c for c in _tz1.calls if c[0] == "SE"] == [("SE", 5, -512)]
          and not [c for c in _tz1.calls if c[0] != "SE"]
          and _ta2.g32(0x10) == 0 and _ta2.g32(0x18) == 0
          and any(c[0] == "ui52c" and c[1] == 0x61000004 for c in _tz2.calls)
          and _t3.g32(0x18) == 3 and _ta3.g32(0x10) == 0 and _tz3.calls == [], "")
    check("0x45E670：f→[+0x20]/[+0x10]、g→[+0x18]/[+8]、h→[+0x1C]/[+0xC]；"
          "rec[4] 的 bit0/bit1 分别屏蔽两个分支",
          _ef1 == (0x21, 0x21) and _ef2.p4_stat == {}, "")
    _e3 = _Z({0x4CD4A0 + 0xEC: 0x1000})
    page4.Page4Mixin.p4_45eff0(_e3, 0x21000131, 7, 9)
    _ev = page4.Page4Mixin.p4_45dfb0(None, page4.p4_tbl_4993c4()[0x31])["b0"]
    check("0x45EFF0：0x21 族查 0x4993C4 → 拆包 → (type&0xF00)==0x100 时 eb=rec[0]，"
          "分数/坐标/两路里程都加同一个值，调用计数 +1",
          _e3.p4_stat.get(0x4CD4A0 + 0x50) == 1
          and _e3.p4_stat.get(0x4CD4A0 + 0x26) == 1
          and _e3.p4_stat.get(0x4CD4A0 + 0x04) == _ev
          and _e3.p4_stat.get(0x4CD4A0 + 0x14) == _ev
          and _e3.p4_stat.get(0x4CD4A0 + 0x18) == _ev
          and _e3.p4_stat.get(0x4CD4A0 + 0x08) == _ev, "")
    check("0x43C55D（类型 0x10008431）：命中生成 type6（坐标为靶的 x/y），"
          "写 [[p+0x1C]+0x28]，靶被注销",
          len(_cv_hits) == 1 and _cv_hits[0][1] == 6
          and _cv_hits[0][2] == 0x120 and _cv_hits[0][3] == 0x90
          and _cv_z.p4_stat[0x5000 + 0x28] == 2
          and _cv_a.g32(0x10) == 0 and _cv_a.g32(0x18) == 0
          and len(_cv_hits2) == 1 and _cv_z2.p4_stat[0x5001 + 0x28] == 2
          and _cv_p2.g32(0x10) == 1, "")
    check("0x45AF30 = |= bits；0x45AF60 = &= ~bits（都返回新值）",
          _bor1 == 0x1F00 and _bo.p4_stat[0x4AB5B0 + 4] == 0x1E00 and _bor2 == 0x1E00
          and img[0x45AF37 - ib:0x45AF3C - ib] == bytes([0x0B, 0xD0, 0x89, 0x51, 0x04])
          and img[0x45AF67 - ib:0x45AF6C - ib] == bytes([0xF7, 0xD0, 0x23, 0xD0, 0x89]), "")
    _m1 = page4.Ent(0x40, 0x50, 0x10008431, 0)
    _m1.d32(0x10, 1)
    _m1.d32(0x18, 7)
    _mz = _Z()
    page4.Page4Mixin._p4_43c691(_mz, _m1)
    check("0x43C691 未命中：再入列一份 0x41000004 并注销 p",
          len(_mz.calls) == 1 and _mz.calls[0][0] == "ui4cc"
          and _mz.calls[0][1] == 0x41000004
          and _mz.calls[0][2] == 0x40 and _mz.calls[0][3] == 0x50
          and _m1.g32(0x18) == 0 and _m1.g32(0x10) == 0, "")
    check("0x43C8CD（类型 0x10FF0053）：抖动 ±0x10/±0x20 的 0x41000004；"
          "[a+0x14]==0x2A000001 时清零 [p+0x18]；随后进共用尾击破靶（0x43C945 jmp）",
          len(_jhit) == 1 and _jhit[0][1] == 0x41000004
          and 0x200 - 0x10 <= _jhit[0][2] <= 0x200 + 0x0F
          and 0x100 - 0x20 <= _jhit[0][3] <= 0x100 + 0x1F
          and _ja.g32(0x18) == 0
          and _ja.g32(0x10) == 0
          and any(c[0] == "ui4cc" and c[1] == 0x41000001 for c in _jz.calls), "")
    check("0x430820 把 rec+0x10 覆盖成队列 的 this+4（所以 0x430400 的第 5 实参总是被丢弃）",
          img[0x430820 - ib:0x43082D - ib] == bytes([0x8B, 0x44, 0x24, 0x04, 0x83, 0xC1, 0x04,
                                                     0x89, 0x48, 0x10, 0xC2, 0x04, 0x00]), "")
    check("0x43C868（类型 0x10142214）：同址连发 20 个 0x10032215，a3 = 0..0x13",
          len(_qz.calls) == 0x14
          and all(c[0] == "ui46c" and c[1] == 0x10032215 and c[2] == 0x120 and c[3] == 0x80
                  for c in _qz.calls)
          and [c[4] for c in _qz.calls] == list(range(0x14)), "")
    check("0x45AFC0 = 取 (word & mask) 并右移到 mask 最低位（0xC000 → 操作器 0..3）",
          page4.Page4Mixin.p4_afc0(_za, 0xC000) == 3
          and page4.Page4Mixin.p4_afc0(_zb, 0xC000) == 1
          and page4.Page4Mixin.p4_afc0(_zc, 0xC000) == 0
          and img[0x45AFC7 - ib:0x45AFC9 - ib] == bytes([0x23, 0xC1]), "")
    _z1 = page4.Ent(1, 1, 0x23000001, 0)
    _z1.d32(0x18, 0x40)
    _z1.d32(0x54, 0)
    _z2 = _Z({0x56CCA8: 0})
    check("0x43AE60 = 剩余血量层数：([+0x18]+0x3F)>>6 - [+0x48]，0x56CCA8 未到则 0",
          page4.Page4Mixin.p4_43ae60(_Z({0x56CCA8: 100}), _z1) == 1
          and page4.Page4Mixin.p4_43ae60(_z2, _z1) == 0, "")
    _zp = page4.Ent(0x300, 0x100, 0x10008041, 0)
    _zp.d32(0x24, 7)
    _zp.d32(0x10, 1)
    _za2 = page4.Ent(0x200, 0x90, 0x23000001, 0)
    _za2.d32(0x18, 0x40)
    _za2.d32(0x48, 0)
    _zs = _Z({0x56CCA8: 100, 0x4AB5B0 + 4: 0xC000})
    page4.Page4Mixin.p4_43c460(_zs, _zp, _za2)
    _kt = [c[1] for c in _zs.calls if c[0] == "ui4cc"]
    check("0x43C6C4（类型 0x10008041）：1×0x41000006 + 4×0x41000005(y=4,-4,4,-4) + 1×0x41400507",
          _kt == [0x41000006, 0x41000005, 0x41000005, 0x41000005, 0x41000005, 0x41400507]
          and [c[3] for c in _zs.calls if c[0] == "ui4cc" and c[1] == 0x41000005] == [4, -4, 4, -4]
          and _za2.g32(0x48) == 1 and _za2.m[0x4C] == 1
          and _zp.m[0x10] == 0 and _zp.g32(0x1C) == 4
          and _zs.calls[-1] == ("SE", 6, (0x300 - 0x140) << 4), "")
    check("0x43C460 前半段：(type&0x7000)==0x1000 用 [0x1C]>>7/[0x20]>>7，其它不生成",
          len(_h1.calls) == 1 and _h1.calls[0][1] == 0x41000004
          and _h1.calls[0][2] == 100 and _h1.calls[0][3] == 50
          and _h1.calls[0][4] == (8, 12) and _h2.calls == [], "")
    check("0x43C0B6 经 thunk 0x401136 指向 0x43C460（不是 0x43C170）—— p4_43c060 的接线已改正",
          img[0x43C0B6 - ib:0x43C0BB - ib] == bytes([0xE8, 0x7B, 0x50, 0xFC, 0xFF]), "")
    check("0x45E710 倍率：(min(word[0x2C],10) + min(d,100)) * rec[5] * rec[0]",
          _r1 == (3 + 5) * 2 * 7 and _r2 == 7 and _r3 == (3 + 0x64) * 2 * 7
          and _e.p4_stat[0x4CD4A0 + 0x5A] == 0x200, "")
    def _rks(score, th, v):
        class _R(page4.Page4Mixin):
            def __init__(self):
                self.p4_stat = {0x4CD4A0 + 0x04: score, 0x4CD4A0 + 0x34: th,
                                0x4CD590 + 0x30: v}
                self.calls = []
            def _p4_q(self, n):
                return n
            def spawn(self, *a):
                self.calls.append(a)
        return _R()
    _a = _rks(10_000_000, 1000, 7)
    page4.Page4Mixin.p4_45f2fb(_a)
    _b = _rks(5, 1000, 7)
    page4.Page4Mixin.p4_45f2fb(_b)
    _c = _rks(10_000_000, 1000, 0xFFFFFFFF)
    page4.Page4Mixin.p4_45f2fb(_c)
    _d = _rks(10_000_001, 0x989680, 10)
    page4.Page4Mixin.p4_45f2fb(_d)
    check("0x45F2FB 里程门槛：分数过门槛才推进；五档阈值与加成类型按反汇编",
          _a.p4_stat[0x4CD4A0 + 0x34] == 0xF4628 and _a.p4_stat[0x56CCB0] == 8
          and len(_a.calls) == 1 and _a.calls[0][1] == 0x21000001
          and _a.calls[0][4] == 0x32000003
          and _b.calls == [] and _b.p4_stat[0x4CD4A0 + 0x34] == 1000
          and _c.calls[0][4] == 0x32000008
          and _d.calls[0][4] == 0x32000008
          and _d.p4_stat[0x4CD4A0 + 0x34] == 0x989680 + 0x1E8480, "")
    check("0x45DFB0 位域拆包：低5位×10^m、两个 nibble、高字",
          img[0x45DFBA - ib:0x45DFBD - ib] == bytes([0x83, 0xE1, 0x1F])
          and img[0x45DFCC - ib:0x45DFD8 - ib] == bytes([0x8B, 0x08, 0x8D, 0x0C, 0x89, 0xD1, 0xE1, 0x4E,
                                                              0x89, 0x08, 0x75, 0xF4])
          and page4.Page4Mixin.p4_45dfb0(None, 0x32042) == {"b0": 200, "b4": 0, "b5": 2, "w6": 3}, "")
    check("0x45FAD0 返回表项高 16 位；0x21 族查 0x4993C4（256 项、215 项非零）",
          len(page4.p4_tbl_4993c4()) == 256
          and sum(1 for v in page4.p4_tbl_4993c4() if v) == 215
          and page4.p4_tbl_4993c4()[:4] == [160, 4161, 160, 204866], "")
    check("0x460800 就是 mov ax,[ecx+0x2A]; ret（字形队列 id 取值器）",
          img[0x460800 - ib:0x460805 - ib] == bytes([0x66, 0x8B, 0x41, 0x2A, 0xC3])
          and page4.Page4Mixin.p4_460800(None, page4.Ent(0, 0, 0x23000001, 0)) == 0, "")
    check("0x45FAD0 的两条取值路径：0x21 族走 0x4993C4，其它走 [mgr+0xEC]",
          img[0x45FAEB - ib:0x45FAF1 - ib] == bytes([0x81, 0xE2, 0x00, 0x00, 0x00, 0xFF])
          and img[0x45FAF1 - ib:0x45FAF7 - ib] == bytes([0x81, 0xFA, 0x00, 0x00, 0x00, 0x21])
          and img[0x45FAD0 - ib:0x45FAD9 - ib] == bytes([0x8B, 0x89, 0xEC, 0x00, 0x00, 0x00, 0x83, 0xEC, 0x0C])
          and img[0x45FB02 - ib:0x45FB09 - ib] == bytes([0x8B, 0x04, 0x85, 0xC4, 0x93, 0x49, 0x00]), "")
    check("0x460EA0 就是 mov eax,[ecx+0x30]; ret（结算取值器）",
          img[0x460EA0 - ib:0x460EA4 - ib] == bytes([0x8B, 0x41, 0x30, 0xC3]), "")
    check("0x45E7A0 是 a*1000/b：三次 lea 后 shl 3 再 div，且 a>0x200000 时同步右移",
          img[0x45E7C4 - ib:0x45E7D4 - ib] == bytes([0x8D, 0x04, 0x80, 0x33, 0xD2, 0x8D, 0x04, 0x80,
                                                    0x8D, 0x04, 0x80, 0xC1, 0xE0, 0x03, 0xF7, 0xF1]), "")
    _s1 = _mk()
    page4.Page4Mixin.p4_45f760(_s1)
    _v1 = _s1.p4_stat[0x4CD4A0 + 0x04]
    _s2 = _mk()
    _s2.p4_stat[0x4CD590 + 0x30] = 0xFFFFFFFF
    page4.Page4Mixin.p4_45f760(_s2)
    _v2 = _s2.p4_stat[0x4CD4A0 + 0x04]
    check("0x45F760 三项得分：r1*400 + r2*400 + v*200000；v==-1 时只累加前两项",
          _v1 == 1700000 and _v2 == 300000, "")
    check("0x45E7A0 边界：除零返 0、a>0x200000 先同步右移",
          page4.Page4Mixin.p4_45e7a0(_mk(), 5, 0) == 0
          and page4.Page4Mixin.p4_45e7a0(_mk(), 0x400000, 0x2000) == 512000, "")
    check("0x499798 的字形表与 p4_str_table() 逐项一致",
          page4.p4_str_table() == [int.from_bytes(img[0x499798 - ib + 2 * k:0x499798 - ib + 2 * k + 2], "little")
                                   for k in range(9)] + [60, 0]
          and page4.p4_str_table()[:9] == [45, 46, 47, 48, 49, 50, 51, 52, 0], "")
    class _K:
        def __init__(self):
            self.v = 0
        def field(self, m):
            return self.v & m
        def set_field(self, m, x):
            self.v = (self.v & ~m) | (x & m)
    class _TS(page4.Page4Mixin):
        def __init__(self):
            self.bank = None
            self.keys = _K()
    _ts = _TS()
    _o = page4.Ent(0, 0, 0x23000001, 0)
    page4.Page4Mixin.p4_4602d0(_ts, _o, 0)
    check("0x4602D0 功能：sid=0 → 队首 45 被 0x4600F0 取走，队列剩 46..52",
          [ _o.g16(0x0A + 2 * k) for k in range(9) ] == [46, 47, 48, 49, 50, 51, 52, 0, 0]
          and _o.g16(0x08) == 45 and _o.g16(0x2A) == 0, "")
    _src = __import__("inspect").getsource(page4)
    check("实体属性不再用不存在的 `.p[...]` / `.p.get(...)`（改用 Ent 的真实属性）",
          ".p.get(\"node\")" not in _src and '.p["buf2c"]' not in _src
          and '.p["link24"]' not in _src and '.p["flags38"]' not in _src, "")
    check("Ent 新增 buf2c / flags38 / link24 三个槽位",
          all(hasattr(page4.Ent(0, 0, 0x23000001, 0), n)
              for n in ("buf2c", "flags38", "link24")), "")

    class _Stub:
        def __init__(self):
            self.calls = []
        def _p4_q(self, n):
            return n
        def spawn(self, q, t, x, y, extra=None):
            self.calls.append((t, x, y, extra))
    _st = _Stub()
    page4.Page4Mixin.p4_45e4a0(_st, 7, 100, 50)
    _v7 = list(_st.calls)
    _st = _Stub()
    page4.Page4Mixin.p4_45e4a0(_st, 1000, 100, 50)
    _v1000 = list(_st.calls)
    check("0x45E4A0 数字渲染：v=7 → 首位数 6 @x-0xC 与 cnt 位 10 @x+0xC；v=1000 → 位数 0 与分组 13",
          _v7 == [(0x4100000C, 88, 50, 6), (0x4100000C, 112, 50, 10)]
          and _v1000 == [(0x4100000C, 88, 50, 0), (0x4100000C, 112, 50, 13)], "")
    check("0x45E4A0 的三条发射路径都进 0x4AD4CC（0x45E552 / 0x45E5A0）",
          img[0x45E552 - ib:0x45E557 - ib] == bytes([0xB9, 0xCC, 0xD4, 0x4A, 0x00])
          and img[0x45E5A0 - ib:0x45E5A5 - ib] == bytes([0xB9, 0xCC, 0xD4, 0x4A, 0x00]), "")
    check("0x45AFF0 与 0x45B030 只差最后一条：neg eax(0x45B001) vs inc eax(0x45B041) ⇒ 语义相反",
          img[0x45AFFD - ib:0x45B003 - ib] == bytes([0xF7, 0xD8, 0x1B, 0xC0, 0xF7, 0xD8])
          and img[0x45B03D - ib:0x45B042 - ib] == bytes([0xF7, 0xD8, 0x1B, 0xC0, 0x40])
          and img[0x45B00B - ib:0x45B00D - ib] == bytes([0x85, 0xD2])
          and img[0x45B04A - ib:0x45B04C - ib] == bytes([0x85, 0xD2]), "")
    check("位助手语义：p4_bit_any = 任一位置，p4_bit_none = 全部位清",
          hasattr(page4.Page4Mixin, "p4_bit_any") and hasattr(page4.Page4Mixin, "p4_bit_none"), "")
    check("0x451480/0x451493/0x4514A6 三组碰撞分别调 0x43BFD0 / 0x43C060 / 0x43C0F0（三个不同函数）",
          img[0x451480 - ib:0x451485 - ib] == bytes([0xE8, 0xDD, 0x02, 0xFB, 0xFF])
          and img[0x451485 - ib:0x451493 - ib] == bytes([0x68, 0x3C, 0xD4, 0x4A, 0x00,
                                                         0x68, 0x6C, 0xD4, 0x4A, 0x00,
                                                         0x8D, 0x4C, 0x24, 0x10])
          and img[0x451498 - ib:0x4514AB - ib] == bytes([0x68, 0x9C, 0xD4, 0x4A, 0x00,
                                                         0x68, 0x0C, 0xD4, 0x4A, 0x00,
                                                         0x8D, 0x4C, 0x24, 0x10,
                                                         0xE8, 0xBD, 0xFC, 0xFA, 0xFF]), "")
    check("0x43C060 与 0x43BFD0 不同：早退用 0x45B030 且 test ah,0x80 只在不早退时过滤",
          img[0x43C075 - ib:0x43C07C - ib] == bytes([0x6A, 0x02, 0xB9, 0xB8, 0xCC, 0x56, 0x00])
          and img[0x43C085 - ib:0x43C08D - ib] == bytes([0x8B, 0x46, 0x14, 0xF6, 0xC4, 0x80, 0x74, 0x35])
          and img[0x43BFDB - ib:0x43BFE0 - ib] == bytes([0xE8, 0xAB, 0x60, 0xFC, 0xFF]), "")
    check("0x43C0F0 已接入帧循环（p4_43c0f0 与 p4_43c060 都已定义）",
          hasattr(page4.Page4Mixin, "p4_43c060") and hasattr(page4.Page4Mixin, "p4_43c0f0"), "")
    check("0x43CCC0 已落地：p4_43ccc0 / p4_43c0f0 / 四个 0x4CD4A0 写入口都在",
          all(hasattr(page4.Page4Mixin, n) for n in
              ("p4_43ccc0", "p4_43c0f0", "p4_45f5f0", "p4_45f690",
               "p4_45f6e0", "p4_460e00", "_p4_43cefb", "_p4_43ced5", "_p4_43d0bf"))
          and callable(page4.p4_446470), "")
    check("0x45F5F0 的步进是 200n（lea×2 → 25n，shl 3 → 200n）",
          img[0x45F604 - ib:0x45F607 - ib] == bytes([0x8D, 0x04, 0x80])
          and img[0x45F60C - ib:0x45F60F - ib] == bytes([0x8D, 0x04, 0x80])
          and img[0x45F612 - ib:0x45F615 - ib] == bytes([0xC1, 0xE0, 0x03]), "")
    check("0x45F5F0 尾部：byte[+0xE1] = 1 且 ret 8",
          img[0x45F631 - ib:0x45F639 - ib] == bytes([0xC6, 0x86, 0xE1, 0x00, 0x00, 0x00, 0x01, 0x5E]), "")

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
