#!/usr/bin/env python3
"""生成页4 的定点三角/倒数平方根表（依据 `0x45A7E7..0x45A8xB0` 的填表代码）。

填表代码用的三个 double：
    0x4993A8 = 0.0017453333333333333    = 6.2832/3600（π 取 3.1416，0.1°/步）
    0x499398 = 255.0                    （sin/cos 幅度）
    0x499388 = 4096.0                   （倒数平方根分子）
    0x499378 = 572.9564553093966        = 3600/(2*3.1416)（atan 表，单位同为 0.1°）

转换函数 `0x463F30` 是"设置 FPU 舍入为截断后 fistp"，故一律用 int() 截断。

输出 `remake/p4_tables.npz`：
    sin900/u8, cos900/u8   —— 900 项，sin/cos(i*0.1°)*255
    isqrt900/u16           —— 900 项，4096/sqrt(i)（i 从 0xFFFF 递减，见下）
    atan256x256/u16        —— 256x256 项，atan2(i,j)*572.9564553
"""
import pathlib

import numpy as np

HERE = pathlib.Path(__file__).resolve().parent
STEP = 0.0017453333333333333      # 0x4993A8
AMP = 255.0                       # 0x499398
ISQRT_NUM = 4096.0                # 0x499388
ATAN_SCALE = 572.9564553093966    # 0x499378

# 0x45A7E7 的循环：esi 从 0x383 递减，判据 (esi + 0x383) >= 0
#   ⇒ esi ∈ [-899, 899]，写 [esi + 0x5B3E37] / [esi + 0x5D41BF]
#   ⇒ 每张表 1799 字节，以 0x383(899) 为**中心**（中心 = 角度 0），字节值 = trunc(sin/cos(esi*0.1°)*255)
off = np.arange(-899, 900, dtype=np.int64)
ang = off.astype(np.float64) * STEP
sin_t = np.trunc(np.sin(ang) * AMP).astype(np.int64) & 0xFF
cos_t = np.trunc(np.cos(ang) * AMP).astype(np.int64) & 0xFF
sin1800 = sin_t.astype(np.uint8)
cos1800 = cos_t.astype(np.uint8)

# 0x45A82E: i = 0xFFFF 起递减到 1，4096/sqrt(i) 存 word；
#   esi 从 0x5B3AB2 每次 -2 直到 >= 0x593AB4 ⇒ (0x5B3AB2-0x593AB4)/2+1 = 65535 项
src = np.arange(0xFFFF, 0, -1, dtype=np.float64)
isqrt65536 = np.trunc(ISQRT_NUM / np.sqrt(src)).astype(np.uint16)

# 0x45A863: 内层 j=0xFF..0，fpatan(atan2(外层 i, 内层 j))*scale → word
aa, bb = np.meshgrid(np.arange(256, dtype=np.float64),
                     np.arange(256, dtype=np.float64), indexing="ij")
atan_raw = np.trunc(np.arctan2(aa, bb) * ATAN_SCALE).astype(np.int64)
atan = (atan_raw & 0xFFFF).astype(np.uint16)

out = HERE / "p4_tables.npz"
np.savez_compressed(out, sin1800=sin1800, cos1800=cos1800,
                    isqrt65536=isqrt65536, atan256=atan)
print(f"写出 {out}")
print("  sin1800 中心(899)=%d  +225=%d  +450=%d  +899=%d  端点0(i=-899)=%d" % (
    int(sin1800[899]), int(sin1800[899 + 225]), int(sin1800[899 + 450]),
    int(sin1800[899 + 899]), int(sin1800[0])))
print("  cos1800 中心(899)=%d  +225=%d  +450=%d" % (
    int(cos1800[899]), int(cos1800[899 + 225]), int(cos1800[899 + 450])))
print("  isqrt65536[0(i=0xFFFF),65534(i=1)] =", int(isqrt65536[0]), int(isqrt65536[65534]))
print("  atan256[0,0] atan256[0xFF,0] atan256[1,0] =",
      int(atan[0, 0]), int(atan[0xFF, 0]), int(atan[1, 0]))
