# 撃破伝 重制版

当前主要实现是 [pygame](pygame/)，包括页1/2/3/13、页4/11、页5/6与共享资源/渲染逻辑。
实现目标与已确认机制见 [逆向主文档](../ANALYSIS.md)，当前专题索引见 [docs](../docs/README.md)。

## 运行与验证

```bash
python3 pygame/run.py
python3 pygame/run.py --page 4
python3 pygame/run.py --frames 300 --headless --fixed
python3 regress_pages.py
python3 audit_p4.py
```

`regress_pages.py` 比较页1/2/3/13的16张冻结金标。`audit_p4.py` 检查当前页4行为覆盖；
它不能替代完整关卡和原作实机验证。页数据生成使用 `build_pages_data.py`；资源解码实现位于 `geki/assets.py`。
