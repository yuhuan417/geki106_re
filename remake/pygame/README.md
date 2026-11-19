# pygame 主实现

原作：撃破伝 v1.06（640×480 8bpp、60Hz 帧门）。本目录直接用一块 640×480 的 uint8
索引画布当屏幕，不借引擎的渲染/循环；页机、输入记录、音频与页 4 游戏逻辑都在
`geki.py` / `page4.py` / `audio.py` 中按 exe 地址实现。

## 运行

```bash
python3 ../build_pages_data.py        # exe → remake/pages_data.json（一次性）
python3 run.py                        # 从页1 开始（ESC 退出，1/2/3 调试切页）
python3 run.py --page 4               # 直接进游戏
python3 run.py --page 13              # 选机
python3 run.py --frames 300 --headless --fixed          # 无窗口
python3 run.py --frames 300 --shot 250 --out shots      # 第 250 帧存 PNG
python3 run.py --mute                 # 不初始化音频
```

## 模块

| 模块 | 对应原作 |
|---|---|
| `Canvas` | 640×480 8bpp 离屏/主表面；`fill`=0x44D200，`blit`=0x45A170 显示节点 |
| `Layers` | 0x44C560 重建 / 0x44CE60 SetColorKey / 0x44C640+0x44BE10 装载 / 0x44D060·0x44D190 层拷贝 |
| `TextRenderer` | 0x44D330（高度=arg&0xFF，1-bit 掩码，色=调色板索引） |
| `Input` | 0x4AB454 / 0x44EB60（0x18 字节帧记录、预设 0x17=4px/帧、鼠标限幅 5px） |
| `Timer` | 0x4AB570 / 0x45A490 / 0x45A510 / 0x45A5A0（period=每秒 tick 数，60→16.7ms） |
| `Pages` | 0x459360 页机；页 1/2/3/5/6/8/9/10/12/13/14/15 流程 |
| `Page4Mixin` | 页 4/11：帧序、VM、背景槽、敌机/弹体、碰撞、HUD、回放 |
| `UiEntity` | 0x43D430 的 0x6F 表、0x424410 的 0x5F 表（0x425114） |
| `audio` | 0x450140 波形槽 / 0x450440 旋律变调 / 0x44F600 BGM |

## 当前状态

- 页 1/2/3/13 视觉冻结，16 张金标为回归护栏（`remake/golden_pages.json`）。
- 页 4/11、页 5/6/8/9/10/12/14/15 流程已实现；页 4 的实体行为按族审计，
  逐型状态见 `docs/p4_enemy_matrix.md`。
- 页 5 的完整排行浏览画面、页 15 附加关行为链只到部分（`docs/page_flow_map.md` §6）。
- BGM 由 fluidsynth 离线渲染，后台线程渲染 + 空闲预渲染；见 `ANALYSIS.md` §11。
- 未闭合的机制问题只以 `ANALYSIS.md` §15 为准。

## 验证

```bash
python3 ../regress_pages.py      # 16 张冻结金标
python3 ../audit_p4.py           # exe 不变量
python3 ../audit_ctor.py         # 180 个 ctor case
python3 ../audit_beh.py          # 行为入口/覆盖
python3 ../audit_props.py        # 7 张属性表
python3 ../check_behaviors.py    # 行为登记 + 154 型冒烟
python3 ../longrun_p4.py 3000    # 随机输入长跑
```
