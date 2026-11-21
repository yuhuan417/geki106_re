# 撃破伝 逆向研究复刻

本目录是对 Windows 同人弹幕射击游戏**《撃破伝》v1.06** 的逆向工程研究记录与复刻实现
（pygame，目标 1:1 复刻原作逻辑）。

## 原作信息

- 标题：撃破伝 1.06（全面的漢字使用射撃遊戯，`geki106.zip`，2005-05-30，需 DirectX 7.0a 以上）
- 下载页（Vector）：https://www.vector.co.jp/soft/dl/win95/game/se177492.html

## 使用声明

本项目**仅供个人学习与逆向研究使用**：

- 不得用于任何商业用途；
- 《撃破伝》的著作权归其原作者所有；原作程序、美术、音频等资源不在本项目的分发范围内，
  须使用者自行从上述官方页面获取（本仓库仅包含对该副本的研究产出：分析文档、反汇编结论与复刻代码）。
  **唯一例外**是流程脚本的解包产物（`extracted/script/` 原始脚本资源与 `extracted/script_txt/`
  带地址注记的文本 dump），作为分析对象随仓库公开。

## 从零恢复工作区

拿到原作 `geki106.zip` 后，一条命令重建所有不入库的产物并运行游戏（游戏目录默认放在
仓库旁 `../geki106`，环境变量 `GEKI_DIR` 可覆盖）：

```bash
python3 tools/restore_workspace.py ~/Downloads/geki106.zip   # 解压 + 全量解包管线
python3 remake/pygame/run.py                                 # 运行游戏
```

脚本会依次重建 `extracted/`（midi/wave/脚本/层/replay/ggd_png/`resource_dec.bin`）、
`extracted/stage_bg/` 与 `remake/` 全部提取表（`pages_data.json` 含 `scene0`、
`p4_block.json` 含 `vm_chains` 等）。重建产物与仓库中已提交的同名文件逐字节一致，
可用 `git status --short extracted/ remake/` 自查；逆向审计脚本另需原作 `geki106.exe`
在 `GEKI_DIR` 所指的游戏目录中。

## 入口

- 项目约定与文档导航：[AGENTS.md](AGENTS.md)
- 机制主文档（已确认结论）：[ANALYSIS.md](ANALYSIS.md)
- 参数表与数据布局：[ANALYSIS_archive_rounds.md](ANALYSIS_archive_rounds.md)
- 专题文档索引：[docs/README.md](docs/README.md)
- 运行方式：[remake/README.md](remake/README.md)
