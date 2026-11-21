# 文档导航

本目录只保留可复用的逆向规格和实现状态。游戏机制的主文档是
[ANALYSIS.md](../ANALYSIS.md)；实现进度以当前源码与 Git 提交为准。历史推导不作为现行结论，
地址结论须回到原始 `geki106.exe` 核对。

## 当前状态

| 范围 | 当前状态 | 依据 |
|---|---|---|
| 页1/2/3/13 | 视觉冻结；16 张金标为回归护栏 | `remake/golden_pages.json`、`remake/regress_pages.py` |
| 页4/11 | 游戏与回放共用逻辑；流程、实体行为与武器链主体已实现，逐型审计状态见矩阵 | `remake/pygame/page4.py`、`remake/audit_*.py` |
| 页5 | 页流程、排行读表与回放入口已接入；完整排行浏览画面尚未逐字节（页跳转 §6 D9） | [p5_rank_notes.md](p5_rank_notes.md) |
| 页6 | enter/step/finish、18 项交互行、网格动画、GRCD 配置位/排行持久化已实现；键位 blob 仍为会话内镜像 | [p6_settings.md](p6_settings.md) |
| 页8/9/10 | Edg1/Edg2/ExtrEnding、制作名单与解锁档已实现 | 源码、页跳转 §1 |
| 页12/15 | 鍛錬流程已贯通；页15 附加关行为链部分闭合（页跳转 §6 D8） | 源码与 `ANALYSIS.md` §14 |
| 音频 | 波形/旋律按 exe 语义；BGM 由 fluidsynth 离线渲染、后台线程 + 预渲染 | `ANALYSIS.md` §11、`remake/pygame/audio.py` |

“实现”不自动代表已与原作逐像素或全流程验证。未闭合问题以 `ANALYSIS.md` §15 为准。

## 专题规格

| 文件 | 内容 |
|---|---|
| [p4_step_0x451110.md](p4_step_0x451110.md) | 页4/11 帧驱动、碰撞、输入与合成顺序 |
| [p4_enter_0x4505B0.md](p4_enter_0x4505B0.md) | 页4/11 阶段进场与参数块 |
| [p4_vm_0x460350.md](p4_vm_0x460350.md) | 流程 VM、操作码与发射器 |
| [p4_stage_flow.md](p4_stage_flow.md) | VM 冻结门（0x56CC84）、关卡跳转、继续与结局选择 |
| [p4_weapon_chain.md](p4_weapon_chain.md) | 武器与捕获整链：挂舱/锁定弹/捕获回调/伤害编码 |
| [p4_replay_save.md](p4_replay_save.md) | 回放/存档持久化：GROD LZ、GRPD/GRCD 头与往返 |
| [p4_bg_composite.md](p4_bg_composite.md) | 页4 背景槽、带状体与层合成 |
| [p4_stage_0x45EB40_0x460930.md](p4_stage_0x45EB40_0x460930.md) | 成绩、命数及场景快照对象 |
| [p4_ent23_fields.md](p4_ent23_fields.md) | 实体公共头与 0x23 族构造字段 |
| [p4_beh_23000002.md](p4_beh_23000002.md)、[p4_beh_23000003.md](p4_beh_23000003.md) | 两类 0x23 实体的构造与行为 |
| [p4_beh_29high_notes.md](p4_beh_29high_notes.md) | 0x29 高段与关联实体行为的地址级规格 |
| [p5_rank_notes.md](p5_rank_notes.md) | 页5 排行规格与实现状态 |
| [p6_settings.md](p6_settings.md) | 页6 设置页流程、交互与验证状态 |
| [p4_enemy_matrix.md](p4_enemy_matrix.md) | 敌机/弹体全量矩阵（12 族）、审计方法与状态汇总 |

运行当前 pygame 无头检查：

```bash
python3 remake/pygame/run.py --frames 300 --headless --fixed
python3 remake/regress_pages.py     # 16 张冻结金标
python3 remake/audit_p4.py          # exe 不变量
python3 remake/audit_ctor.py        # 180 个 ctor case 字段
python3 remake/audit_beh.py         # 行为覆盖 + 入口合法性
python3 remake/audit_props.py       # 7 张属性表 vs exe
python3 remake/check_behaviors.py   # 行为登记 + 154 型冒烟
python3 remake/longrun_p4.py 3000   # 随机输入长跑
python3 remake/replay_scripts.py    # 26 条脚本链回放
```
