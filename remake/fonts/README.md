# 字体放置目录

`0x44D330` 用 `CreateFontIndirectA` 请求系统字体 **ＭＳ 明朝**（LOGFONT@0x4A40F8：
`lfCharSet=128 SHIFTJIS_CHARSET`、`lfPitchAndFamily=1 FIXED_PITCH`、`lfQuality=0`、`lfWeight=0`）。

**原作的字体是"向系统要"的，所以结果随机器而变**：开发用的这台 Windows 没装 ＭＳ明朝，
GDI 实测把它映射成 **ＭＳ ゴシック（MS Gothic）**（`remake/tools/probe_gdi_text.ps1` 可复现，
输出 `face=[MS Gothic] tmHeight=16 asc=14 desc=2 intLead=0`）。

`TextRenderer` 的查找顺序（= 复刻 GDI 的映射结果）：

1. `remake/fonts/msmincho.ttc` / `.ttf`（想强制明朝体就放这里）
2. `/mnt/c/Windows/Fonts/msmincho.ttc`、`C:/Windows/Fonts/msmincho.ttc`
3. `/mnt/c/Windows/Fonts/msgothic.ttc`、`C:/Windows/Fonts/msgothic.ttc` ← 本机实际命中的
4. Noto Serif CJK（兜底）

页1 版权页用第 3 项时曾与宿主 GDI 逐像素一致（IoU 1.0000）。
