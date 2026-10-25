# 撃破伝 (Gekihaden) — Godot 完全重制版

原作: 撃破伝 v1.06 (橋倉正, 2001-2003, freeware) — Windows 95/98/DirectX7 时代同人横版弹幕射击。
本工程所有资源格式、关卡脚本 VM、弹幕发射器均从 `geki106.exe` 逆向 1:1 还原(见 `../../ANALYSIS.md`)。

## 运行

```bash
# 1. 资产编译 (从原版游戏目录 -> 标准格式, 需要一次)
cd .. && python3 build_assets.py
# 2. Godot 4.3+
godot --path godot           # 窗口运行
godot --headless --path godot  # 无头逻辑验证
# 环境变量: GEKI_STAGE=1..7 选关, GEKI_FRAMES=N 跑N帧后打印状态并退出
GEKI_STAGE=3 GEKI_FRAMES=1200 godot --headless --path godot
```

### 页1-3（开场/标题/菜单，§16 复刻）
```bash
python3 ../build_pages_data.py                     # 生成 assets/pages_data.json
GEKI_PAGES=1 godot --path .                        # 从页1 开始跑（1/2/3 调试切页, G 进游戏, ESC 退出）
GEKI_PAGES=1 GEKI_PAGE=2 GEKI_FRAMES=100 GEKI_SHOT=90 godot --headless --path .
                                                   # 无头：跑 100 帧并合成 layer → pages_shot_*.png
```
**页1 已 1:1 完成**：蓝色伪启动画面（调色板 0xD3/0xB5/0xB4 换色）+ 8 行文字（0x44D330，
高度16、白 0xD9）+ 两个 bm_tilg 擦除效果（0x5F000002/3，显示节点 0x45A170）+ t=290 自动切页2。
验证：`GEKI_PAGES=1 GEKI_PAGE=1 GEKI_FRAMES=300 godot --headless --path .` 看 trace；
`GEKI_SHOT=250` 出截图。页1/2/3 的 enter/step/finish、层尺寸、色键、SetPeriod、离页旗标、生成类型全部来自反汇编
（`scripts/pages/geki_pages.gd` 内注明地址）；页2 的层装载时间轴表由 `build_pages_data.py`
从 exe 提取（22 条 状态→层→GGD + 10 个天空流触发点）。

操作: 方向键/鼠标=移动, 左键或C=弹, 右键或X/V=锁定, Z/B=捕获, P=暂停,
F1=音效开关, F2=音乐开关, PrintScreen=截图(与原作一致的 pscrNNNN.bmp), ESC=退出。

## 架构

```
build_assets.py   资产编译器: GROD容器/Huffman MIDI/图层RLE/GGD → PNG/WAV/JSON
godot/
  project.godot   640x480, 60fps 物理帧, 输入映射
  scenes/main.tscn
  scripts/
    main.gd       主循环: 实体/碰撞/计分/渲染 (CanvasItem 自绘)
    script_vm.gd  关卡脚本 VM (原作 0x460350 的移植)
    emitter.gd    12通道弹幕发射器 state/delta 积分器 (原作 0x457C00 的移植)
    audio.gd      BGM/SE (BGM 为占位合成, 有 fluidsynth 可重渲)
  assets/
    bg/      7张关卡背景 (图层RLE解码, 已验证)
    atlas/   敌机精灵图集 (#79-82)
    ggd/     147张字库/UI图
    sfx/     24个音效 (原版 PCM)
    bgm/     20首 BGM (MIDI占位渲染)
    scripts/ 7关脚本 JSON (150~411条记录/关)
```

## 验证状态

| 项目 | 结果 |
|---|---|
| Stg1 全脚本 | ✅ 9000帧跑通, transition 事件与原作脚本一致 |
| Stg2/Stg3 | ✅ 1200帧, 敌机10/7, 敌弹1213/9094 |
| Python/Godot 双实现一致性 | ✅ 600帧: 双方 5敌机/228敌弹 |
| 真实渲染 | ✅ 星空背景+实体+弹幕扇形 (WSLg 验证) |
| BGM | ✅ 20首 fluidsynth+FluidR3 真音色 OGG |
| #77 背景天空 | ✅ 定性=天空本体(用户确认): 灰阶底+图案层滚动 |
| 实体字形位图 | ✅ 战机撃凛漢/敌人bm_sX/子弹bm_cm32 (293切片) |
| #79-82 命中特效 | 🔶 定性完成(用户确认), 接入待做 |
| 锁定/捕获 | ✅ 基础实现 (锁定光束伤害/捕获吸弹) |
| GRPD 回放 | ✅ 写出原作 GRPD106A 格式, Python解码器 round-trip 验证 |
| 敌机行为 | ✅ 18 行为函数全部解码(§20.1), 12 类已实现并验证开火命中 |
| 菜单流程 | ✅ 标题→游戏→gameover→重开, 残机3 |

## 距离 100% 的清单 (地址级线索在 ../../ANALYSIS.md §19)

1. 精灵渲染: 图集 16x16 图块组合链 (0x43F230 字节=块坐标已解, 组装端待追), 替换调试色块
2. 敌机开火 0x40213F 精确弹型 + 0x23表外变体精确移动
3. #77 blt src/dest 角色微调 + 机体选择画面
