# 字体放置目录

`0x44D330` 用 `CreateFontIndirectA` 请求系统字体 **ＭＳ 明朝**（LOGFONT@0x4A40F8，
`lfCharSet = 128 SHIFTJIS_CHARSET`、`lfPitchAndFamily = 1`、`lfQuality = 0`）。

- 把 `msmincho.ttc`（或 `msmincho.ttf`）放到本目录，`TextRenderer` 会优先使用它，
  这样版权页/行文字窗的字形与原作一致。
- 没有该文件时退回本机明朝体替代（Noto Serif CJK）。**原作本身也是向系统要字体**，
  缺 ＭＳ明朝 时 GDI 同样会替换，所以"字形随机器而异"是原作属性，字号/字距/1bit/颜色
  才是不变的逆向结论（见 ANALYSIS.md §6.3）。
