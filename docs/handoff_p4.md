# 页4 handoff（2026-11-04，第 32 轮结束态）

权威文档始终是 `ANALYSIS.md` §16.340–16.344（勘误表附录 A 必查）。本文只记
"接着做什么"与"踩过什么坑"，不重复定案内容。

## 会话目标四项的现状

| 项 | 状态 | 说明 |
|---|---|---|
| ① 普通子弹 | **完成** | pod ctor `0x42C4D0` + 12 槽 + fx12 弹 `0x120B1121`；3 挂舱 6 帧节奏连发（§16.342①） |
| ① 狙击子弹 | **未做** | 待办见下 |
| ② 碰撞 | **完成** | 弹↔敌命中/伤害/击毁/火花全链 + 机↔机接线；`[0x10]` 统一置位 `_p4_set_col`（§16.344） |
| ③ 生命值显示 | **定位完，未实现** | 见下 |
| ④ 敌机严格按脚本 | **VM 审计通过** | 15 op 全实现、0x23 族 20 型行为落地；3000 帧无未解析地址。长程回归继续监控 |

## 下一步（按优先级）

1. **③生命值显示**：生命 = `[0x4CD590+0x30]`（`0x460D2A` 死亡递减、-1=哨兵）。
   显示 = `0x460930` 的 2 节点（层 0，dst (12,12)/(72,12)，visible = (a3 != -1)，
   节点 1 src = (48v, 0x1B0, …) = 选机 kanji）。进场 a3 = sbyte[blk+0x1A] = 0xFF
   ⇒ 图标隐藏、[+0x30] = -1。要做的：进 `p4_enter`/`p4_460c00`（死亡重生链）时
   把生命值变化接到 HUD 节点可见/src 更新。pscr 左上"残撃 伍"行是 0x43DFxx
   文本链（不是图标），门 = `[0x56CCC9]&[0x56CCB5]`，行文本来源待查
   （P4_HUD_SEGS 里那两个指针是页1 BIOS 串，别用）。
2. **①狙击弹**：`0x1B000001` 与 `0x448C70` 开火门的接线。参考已修好的
   0x0B000001（死亡重生自机）开火路径：读 byte[0x4AB594] 原始按键、rect.l==0
   分支每帧采纳指针、动画完成清 0x56CCC0 bit0。
3. **§16.341⑤ 遗留**：0x445C00 对 0x1000001 走 0x446237 跳过 ctor ⇒ `[+0x40]=0`，
   与 `0x446450 jmp [ecx+0x40]` 不崩矛盾——挂舱行为真实来源待查（查 thunk
   caller，注意只经 thunk 调用的函数）。

## 复刻侧代码地图

- `remake/pygame/page4.py`（8483 行）：页4 全部。入口 `p4_enter/p4_step/p4_finish/
  p4_intro_frame`；实体生成 `spawn(q, type, ...)`；队列名见 `_p4_q()`。
- `remake/pygame/geki.py`（4183 行）：页机/共享渲染/Layers/draw()。**冻结区**：
  动共享部分前先想页1/2/3/13，提交前跑 `python3 remake/regress_pages.py`。
- `remake/audit_p4.py`（3448 行）：行为审计器，3000 帧查 `p4_beh_missing`。
- `docs/p4_listings/`：关键函数反汇编转储（459360/4505B0/451110/43A350 等）。

## 队列 ↔ 地址速查

| 队列名 | 地址 | 内容 |
|---|---|---|
| actorq（别名 ui40c）| 0x4AD40C | 演员（自机 type1、挂舱 0x1000001、0x0B000001） |
| ui43c | 0x4AD43C | 敌方弹 0x2300001A/0x10000052 等 |
| ui46c | 0x4AD46C | 生成入队（敌弹/敌机等） |
| ui4cc | 0x4AD4CC | 0x41 族粒子/拖尾（P4_41_CTOR 全 15 型） |
| ui4fc / ui52c | 0x4AD4FC / 0x4AD52C | 各类显示实体 |

帧序：`0x451110` 每帧 = 4×泵门 → 0x450FE0 流程 VM → 输入记录 → UI → 背景 →
三组碰撞 → **0x458E70（行为+绘制，0x446450 分发在里头）** → present。

## 本轮踩过的坑（新会话最易重犯）

1. **int32 归一**：VM 记录是无符号 dword，负坐标以 0xFFFFFFxx 送达。三个渲染
   入口都要 s32 归一后再给 pygame，否则负坐标被裁掉（陽 下沉、爆光块消失）。
2. **[0x10] 碰撞位**：`0x445C00` prologue 清零、ctor 不覆写 ⇒ 复刻遍历时统一
   `_p4_set_col(e)` 置位，别指望 ctor 带。
3. **生成 ≠ 入队**：敌方弹 spawn 后必须显式 append 到队列，否则不渲染不碰撞。
4. **UiEntity.beh 可能是字符串**（"fx12"/"menu_root"），`p4_call_behaviour` 里
   hex 格式化前要 isinstance 检查。
5. **DNode 只有 `.active`**，没有 `.visible`；写错属性 = 静默失效。
6. **split-brain 队列**：`ui40c` 现在是 actorq 的别名，别再新建死列表。
7. **hit_cb 参数序**：内层 qa 实体是第一实参。
8. **0x437940 轴序**：0x45A6B0 的 arg2→x、arg3→y，按 push 序列推。
9. **累积器符号**：`p4_457380_acc` 用有符号比较，无符号会反向。
10. **页4 渲染路径都要 `page==4` 门**：否则画进页3（§16.341④）。
11. **线性反汇编失步**：0x410000-0x445000 内嵌数据区，xref 用原始字节扫描
    （`re_dis.py` 优先）。

## 验证命令

```bash
python3 remake/pygame/run.py --frames 300 --headless --fixed   # 无头页1-3+页4
python3 remake/regress_pages.py                                # 16 金标护栏（提交前必跑）
python3 remake/audit_p4.py                                     # 行为审计
python3 remake/build_pages_data.py                             # 数据表重提（改了提取器才跑）
```

截图在 `docs/p4_shots/`、`remake/pygame/shots/`。金标 `remake/golden_pages.json`。
