# 撃破伝 v1.06 资源索引

资源编号与解析结论以 [ANALYSIS.md §5](ANALYSIS.md#5-资源与文件格式) 为准。本表只列可确认的容器映射；
RT_STRING 文件名映射见 `remake/pages_data.json:string_table`，不得与 GROD 资源 ID 混用。

## `resource.rom`

容器为 `GROD106A`，解包后共98项，ID从1开始。

| ID | 内容 |
|---|---|
| 1–20 | MIDI 音乐 |
| 21–44 | PCM 音效 |
| 45–76 | 流程脚本 |
| 77 | 标题矩形记录流 |
| 78 | 场景快照描述 |
| 79 | 选机人像 mosaic 数据 |
| 80–82 | 标题图集字形条数据 |
| 83–89 | 阶段背景数据 |
| 90–97 | 内置回放 |
| 98 | 构建注释 |

## 相关实现

| 路径 | 用途 |
|---|---|
| `remake/geki/assets.py` | GROD、Huffman、GGD、图层 RLE 与调色板解码 |
| `grod_decode.py`、`huff_decode.py`、`layer_decode.py`、`ggd2png.py` | 独立格式解码工具 |
| `remake/pages_data.json` | 提取后的 RT_STRING、调色板与页数据 |
