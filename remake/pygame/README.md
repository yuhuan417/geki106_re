# 页1-3 复刻（pygame）

原作：撃破伝 v1.06（640×480 8bpp、自带 60Hz 帧门）。本目录**直接用一块 640×480 的 uint8
索引画布当屏幕**，不借任何引擎的渲染/循环，避免和原作语义冲突。

```bash
python3 ../build_pages_data.py      # exe → remake/pages_data.json（一次性）
python3 run.py                      # 从页1 开始（固定 640×480 窗口；ESC 退出，1/2/3 调试切页）
python3 run.py --page 2             # 直接页2
python3 run.py --frames 300 --shot 250 --out shots   # 第 250 帧存 PNG
python3 run.py --frames 300 --headless --fixed       # 无窗口尽快跑（CI/脚本）
```

| 模块 | 对应原作 |
|---|---|
| `Canvas` | 640×480 8bpp 离屏/主表面；`fill`=0x44D200，`blit`=0x45A170 显示节点 |
| `Layers` | 0x44C560 重建 / 0x44CE60 SetColorKey / 0x44C640+0x44BE10 装载 / 0x44D060·0x44D190 层拷贝 |
| `TextRenderer` | 0x44D330（高度=arg&0xFF，1-bit 掩码，色=调色板索引） |
| `Input` | 0x4AB454 / 0x44EB60（0x18 字节帧记录、预设 0x17=4px/帧、鼠标限幅 5px） |
| `Timer` | 0x4AB570 / 0x45A490 / 0x45A510 / 0x45A5A0（period=每秒 tick 数，60→16.7ms） |
| `Pages` | 0x459360 页机 + 页1 0x451E00/0x451F80/0x452010（已完成）+ 页2/3 骨架 |
| `UiEntity` | 0x43D430 的 0x6F 表、0x424410 的 0x5F 表（0x425114）、行为 0x43DE30/0x43F560/0x4254F0/0x425560 |

**页1 完成度**：进场/每帧/收尾与 0x43DE30 的生成表(30/80/100)、换色表(10/165/170/290)、
文字表(200 单帧 / 230..289)、结束判定(攻击键或 290)→0x10000→页2，全部按反汇编；
窗口 1:1 640×480，上屏只有 0xD3/0xD9 两色（无抗锯齿）。
**页2** 的时间轴（22 条层装载 + 10 个天空流点 + 8 条层拷贝）已跑通，但"哪层上屏/present"
未定位 → 目前用 dirty 层 (0,0) 合成作**占位**（ANALYSIS §16.7-0）。
**页3** 只有 enter/step 骨架（层13←bm_mn 已知，菜单脚本链 0x24 未定位）。
