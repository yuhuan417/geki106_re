"""页3 场景（0x45FE10 的输入）= resource.rom 记录 #0x4E（§16.43）。

取记录的方法完全按原件：
  `0x45DDA0(id)` / `0x45DDE0(id)`（= 0x45DC20 处的 resource.rom 解密块访问器）
  基址 [0x5E14D8]，索引 = id-1，条目 = **3 字节小端 24bit 偏移**（读 dword 后 and 0xFFFFFF）。

记录布局（与 0x45FE10 逐字段对应，长度自洽 0xC30 = 3120）：
  +0x00 u32 自身长度 0xC30
  +0x04 u32 N = 14      层数      → 0x45FE10 从层0 起连续装载
  +0x08 u32 M = 168     色带项数  → 0x4561D0
  +0x0C u32 K = 74      背景实体数
  +0x10 u32 0           → 传给 0x4561D0 的第 5 参
  +0x14 u32 0x240       → 传给 0x4561D0 的第 4 参
  +0x18 u32[N]  层资源ID
  然后  u32[M]  色带表（每项 {u8 color, u8 pad, i16 h}）
  然后  0x20*K  实体记录 {layer, rect.left, rect.top, rect.right, rect.bottom,
                          dst.x, dst.y, flag}（flag 只取**低字节**，0x45FEAC al=[rec+0x1C]）
"""
import json, struct
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DEC = ROOT / "extracted/resource_dec.bin"
RID = 0x4E


def rec_offset(d: bytes, i: int) -> int:
    if i == 0:
        return 0
    return struct.unpack("<I", d[(i - 1) * 3:(i - 1) * 3 + 4])[0] & 0xFFFFFF


def main() -> None:
    d = DEC.read_bytes()
    a, b = rec_offset(d, RID), rec_offset(d, RID + 1)
    rec = d[a:b]
    magic, N, M, K, v10, v14 = struct.unpack("<6I", rec[:24])
    assert magic == len(rec), (hex(magic), len(rec))
    layers = list(struct.unpack("<%dI" % N, rec[24:24 + 4 * N]))
    p = 24 + 4 * N
    bands = []
    for i in range(M):
        c, pad, h = struct.unpack("<BBh", rec[p + i * 4:p + i * 4 + 4])
        bands.append([c, h])
    p += 4 * M
    ents = []
    for i in range(K):
        lay, l, t, r, bo, x, y, fl = struct.unpack("<8i", rec[p + i * 32:p + i * 32 + 32])
        ents.append([lay, l, t, r, bo, x, y, fl & 0xFF])
    assert p + K * 32 == len(rec), (p + K * 32, len(rec))

    data = json.loads((ROOT / "remake/pages_data.json").read_text(encoding="utf-8"))
    data["scene0"] = {"layers": layers, "bands": bands, "band_args": [v10, v14],   # [起始索引, 滚动量]（0x4562A0 用 +8/+0xC）
                      "ents": ents,
                      "note": "§16.43 resource.rom #0x4E：层链/色带/背景实体，全部静态"}
    (ROOT / "remake/pages_data.json").write_text(
        json.dumps(data, ensure_ascii=False, indent=1), encoding="utf-8")
    print("layers =", layers)
    print("bands  =", len(bands), "ents =", len(ents),
          "启用 =", sum(1 for e in ents if e[7]))


if __name__ == "__main__":
    main()
