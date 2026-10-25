# 撃破伝 v1.06 资源速查（定稿，配合 ANALYSIS.md）

## 容器与编码
| 格式 | 编码 | 解码位置 |
|---|---|---|
| resource.rom | GROD106A + 自定义 LZ + u24 偏移表(98 项) | exe 0x45B6E0 |
| BGM #1-20 | 静态 Huffman → 标准 SMF | exe 0x44F0B0（码表 0x498C48/0x498E48） |
| 关卡底 #83-89 | 字典 RLE 位流 → 640×480×8bpp | exe 0x45BC00 |
| 存档/回放 | GRCD/GRPD106A + 同款 LZ | exe 0x45C020 |
| GGD 图形 | GGPD + w/h + 8bpp（垂直翻转存储） | exe 0x455870 |

## resource.rom 条目
| ID | 内容 |
|---|---|
| 1-20 | BGM（标准 MIDI） |
| 21-44 | 音效（s16 PCM） |
| 45-76 | 关卡脚本（VM 记录流；46-52=Stg1-7，66-72=二周目） |
| 77 | 背景天空滚动流（2068 帧） |
| 78 | 特效尺寸表（74 条，等级 4-12） |
| 79-82 | 射击命中特效动画 |
| 83-89 | 过关画面底图 |
| 90-97 | 内置演示回放 |
| 98 | 构建日期戳 |

## GGD 文件（文件名来自 PE 字符串资源表，LoadStringA→池 0x4AA0B4）
| 文件 | 内容 |
|---|---|
| bm_otc0/1/2 | 三战机背景图：撃/凛/漢 |
| bm_mn | 主菜单整图 |
| bm_tr | 选关菜单文字 |
| bm_st1/2/3 | 设置菜单文字（st1=彩虹撃测试图） |
| bm_psel/psel2 | 选机/选关界面（psel2 含天空渐变色号） |
| bm_sX | 每关敌人字形位图 |
| bm_sXl0-l9 | 敌字形 10 级缩放序列 |
| bm_cm32 / cm48 | 子弹字形 32px×80 / 48px 字形格 |
| bm_ota0-3 / otb0-1 | 天空图案源（层 7-10 换装） |
| bm_op + opl0-9 | 开场动画字形缩放序列 |
| bm_pal/pald/pals | 调色板 ×3 |

## 渲染机制
1. 关卡底 #83-89（纯色/过关图）→ 层 3
2. 天空 = 序列引擎色带逐行填充（0x4562A0）+ #77 滚动流（层 7-10 → 屏）
3. 实体/楼墙/HUD = 系统字体实时 TextOut（0x44D330，ＭＳ明朝，随机器字体可变）
4. GGD 字形位图 = setup106 安装期以系统字体预渲染（font.txt 候选）
5. 脚本 VM 驱动关卡流程；发射器 = state/delta 积分器

## 已产出工具
| 文件 | 用途 |
|---|---|
| remake/geki/assets.py | 全格式解码（GROD/Huffman/RLE/GGD/调色板） |
| remake/build_assets.py | 资产编译器 → Godot 格式 |
| remake/build_glyphs.py | 字形切割 |
| remake/godot/ | Godot 4.3 重制工程（可运行） |
| remake/replicate_page_bg.py（上级目录） | 页2 背景机制复刻 |
| kanji_compose.py | 汉字精灵拼装实验 |
| layer_decode.py / dec83.py | #83-89 解码 |
| behaviors.asm | 18 行为函数反汇编存档 |
| remap_tables.json | 调色板重映射表 |
| api_audit.json | API 调用点审计 |
| geki106/geki106_win11.exe | WIN11 补丁版（3 补丁，24 字节） |
