# 文档导航

本目录只保留可复用的逆向规格和实现状态。游戏机制的主文档是
[ANALYSIS.md](../ANALYSIS.md)；实现进度以当前源码与 Git 提交为准。历史推导不作为现行结论，
地址结论须回到原始 `geki106.exe` 核对。

## 当前状态（2026-11-11）

| 范围 | 当前状态 | 依据 |
|---|---|---|
| 页1/2/3/13 | 视觉冻结；16 张金标为回归护栏 | `remake/golden_pages.json`、`remake/regress_pages.py` |
| 页4/11 | 游戏与回放共用逻辑；页4行为和流程已大幅落地，完整关卡覆盖仍需持续验证 | `remake/pygame/page4.py`、`remake/audit_p4.py` |
| 页5 | 页流程和回放入口已接入；排行文字格与选中行详情尚未完整复刻 | [p5_rank_notes.md](p5_rank_notes.md) |
| 页6 | enter/step/finish、设置行表和网格动画已实现；设置保存的跨进程持久化仍未闭合 | [p5_rank_notes.md](p5_rank_notes.md)、`ANALYSIS.md` §15.4 |
| 页12/15 | 鍛錬流程已贯通验证；页15全链路测试通过 | 最新提交 `f33c8e0` |

“实现”不自动代表已与原作逐像素或全流程验证。未闭合问题以 `ANALYSIS.md` §15 为准。

## 专题规格

| 文件 | 内容 |
|---|---|
| [p4_step_0x451110.md](p4_step_0x451110.md) | 页4/11 帧驱动、碰撞、输入与合成顺序 |
| [p4_enter_0x4505B0.md](p4_enter_0x4505B0.md) | 页4/11 阶段进场与参数块 |
| [p4_vm_0x460350.md](p4_vm_0x460350.md) | 流程 VM、操作码与发射器 |
| [p4_bg_composite.md](p4_bg_composite.md) | 页4 背景槽、带状体与层合成 |
| [p4_stage_0x45EB40_0x460930.md](p4_stage_0x45EB40_0x460930.md) | 成绩、命数及场景快照对象 |
| [p4_ent23_fields.md](p4_ent23_fields.md) | 实体公共头与 0x23 族构造字段 |
| [p4_beh_23000002.md](p4_beh_23000002.md)、[p4_beh_23000003.md](p4_beh_23000003.md) | 两类 0x23 实体的构造与行为 |
| [p4_beh_29high_notes.md](p4_beh_29high_notes.md) | 0x29 高段与关联实体行为的地址级规格 |
| [p5_rank_notes.md](p5_rank_notes.md) | 页5 排行规格与实现状态 |
| [p6_settings.md](p6_settings.md) | 页6 设置页流程、交互与验证状态 |

运行当前 pygame 无头检查：

```bash
python3 remake/pygame/run.py --frames 300 --headless --fixed
python3 remake/regress_pages.py
python3 remake/audit_p4.py
```
