# 撃破伝 (Gekihaden) v1.06 重制版

从 Windows XP 时代同人射击游戏《撃破伝》100% 重制。
所有资源格式、脚本 VM、弹幕发射器均从 `geki106.exe` 逆向还原（见 `../ANALYSIS.md`）。

## 运行

```bash
pip install pygame numpy pefile
python3 main.py            # 窗口运行 Stg1
python3 main.py 1 600      # Stg1 跑 600 帧后退出 (保存 remake_frameN.png)
GEKI106_DIR=/path/to/game python3 main.py   # 指定原游戏目录
```

操作（还原原作）：鼠标移动/方向键 = 移动，左键/C = 弹，右键/X/V = 锁定，
左右同按/Z/B = 捕获，P = 暂停，F1 音效，F2 音乐，PrintScreen 截图（pscr%04d.bmp）。

## 当前完成度

| 子系统 | 状态 |
|---|---|
| 资源管线 (GROD/Huffman/GGD/图层RLE/调色板) | ✅ 与原作 1:1 |
| 关卡脚本 VM (15 指令) | ✅ Stg1 全脚本跑通 (9000帧到 op0 终止) |
| 弹幕发射器 (12通道 state/delta 积分器) | ✅ 真实数据出弹 (600帧228发) |
| 8bpp 调色板渲染 + 关卡背景 | ✅ 星空背景验证 |
| 敌机生成 (OP02) / 自机 / 碰撞 / 计分 | ✅ 骨架 (行为为占位) |
| 音频 (MIDI/PCM) | 🔶 可选模块, 需 fluidsynth |
| 敌机行为/AI (类型→移动模式) | 🔶 待 RE (见下) |
| 精灵渲染 | 🔶 调试图块; 图集编码已定位 (#79=16x16图块坐标映射) |
| 锁定/捕获/僚机/炸弹机制 | 🔧 按 readme 规则待实现 |
| 回放 (GRPD 读写) | 🔧 格式已解, 待接入 |
| #77 背景滚动动画 | 🔶 数据级解析完成 (layeranim.py), src/dest 微调中 |

## 剩余 RE 任务清单 (带地址)

1. **精灵渲染链**: #79-82 = 图集。每 320 字节行 = [80B 图块坐标 (16x16 块, 字节= (x,y) nibble 对)][240B 8bpp 像素]。
   初始化: exe `0x43F340` (逐字节调 `0x43F230` 解码块坐标), 渲染方法待追。
2. **敌机行为**: OP02 类型号 (0x21/0x23/0x24/0x29...) → 移动/AI。入口: 命令队列 0x4AD43C 的消费循环。
3. **#77 弹道表** (621KB u16 流): 消费点 0x459D96。
4. **发射器 state 字段几何语义**: 已知 10/11=随机散布, 15-18=外观权重, 12/13=间隔/速率;
   其余 14 个字段 (0-9, 14, 19) 的位置/角度/速度语义待从子弹节点 ctor 0x457540 后续追。
5. **GRPD 回放帧格式**: 头部+LZ已解, 输入记录位定义待完。

## 结构

```
geki/
  assets.py    资源管线 (所有原作格式解码器)
  scriptvm.py  脚本 VM + 发射器库
  game.py      游戏状态 + 主循环 + 渲染
  audio.py     可选音频 (MIDI/PCM)
  layeranim.py #77 背景图层动画流 (数据级解析完成, blit 语义微调中)
main.py        入口
```

```
geki/
  assets.py    资源管线 (所有原作格式解码器)
  scriptvm.py  脚本 VM + 发射器库
  game.py      游戏状态 + 主循环 + 渲染
  audio.py     可选音频 (MIDI/PCM)
main.py        入口
```
