# b2 — 关2/关3 boss 逐指令核对（0x24000011 + 控制器 0x64000001→0x4417D0；0x2500000B）

2026-11-21。对照 `remake/pygame/page4.py`（只读，未改）。反汇编一律 `re_dis`，
栈参数用 trace_esp，push imm / dword 用原始字节扫描。行号以当前 page4.py 为准。

结论：**4 处差异**（1 处控制器重波周期、1 处挂件兄弟链断链、2 处 ctor 随机源），
其余逐指令一致。另否定两个前提：0x2500000B 存活门是 **26** 不是 −1；
生成点是 **0x4134F1** 不是 0x41340B。

前置修正：各族 prop 子表基址不同（`0x402455→0x43AC30` 的行基址由各族 ctor push）：
0x23=`0x498000`（0x40D949 push）、0x24=`0x498138`（0x410A26）、0x25=`0x498208`（0x411E28）、
0x26=`0x498290`（0x4139F7）；行内布局 10 字节不变（byte0=半径、word2=门(0→−1)、
word4=+0x58、word6/8=src）。b3 报告把 0x26000018 的行写成 0x4983A0，实际 0x498376
（=0x498290+(0x18−1)×10），值不变。

---

## 0. 生成路径与 rec（任务④）

**0x24000011**：全 .text dword 扫描 4 处：`0x43C229`/`0x43C9FE`/`0x43D2B8`＝三张击破豁免
比较表（见 §5），`0x441801`＝控制器 0x4417D0 init 循环的 `push 0x24000011`（0x441800）。
**唯一生成者＝控制器**；脚本流无 603979793。
控制器 init（0x4417DE `cmp [ebp+0x1C],ebx(0)` / jne 0x441857）：
- 0x4417E3..0x4417EB 栈上建槽 `{[esp+0x10]=0, [esp+0x14]=ebp(控制器指针), [esp+0x18]=0x1B0}`；
- 循环 0x4417F3..0x44184E：`edx=(ebx>>1)+0x2B0`、`ecx=[esp+0x18]`，
  `0x430400(&rec, edx, ecx, 0x24000011, &slot)`（0x4417FF..0x441812 push 序：
  &slot→0x24000011→y→x→&rec）→ rec={x, y, 0x24000011, &slot}，
  `0x401FA5→0x43BDC0` 入 0x4AD43C；k+=0x60、y−=0x60、`cmp ebx,0x180 / jl`；
  **每只生成后 0x441846 `[esp+0x10]=eax`（槽[0]=新件指针=兄链）**。
  4 只：k=0/0x60/0xC0/0x120 → (0x2B0,0x1B0) (0x2E0,0x150) (0x310,0xF0) (0x340,0x90)。
- 0x441850 `[ebp+0x1C]=0xFFFFFF40`（**−0xC0**）。
page4 15760-15774 结构一致（`_P4Op5Slot{0,宿主句柄}`、`0x2B0+(k>>1)`、y 步 −0x60、
槽[0]=新件句柄）✓，**唯 t 常量写 0xFFFFFFC0（−0x40）**→ **D1**。

**0x64000001**：全 .text dword 扫描 3 处，只有 `0x43D4B6` 是真的
（0x43D430 op5 分派器 `sub edx,0x64000001 / je 0x43D4FA`）；`0x442151` 是
`mov [esp+0x1B4],0x64` 的 disp32+imm 巧合、`0x45B955` 是 `mov ecx,[esp+0x110]` 的
disp32 尾+FS 前缀巧合——**.text 内无任何 push/mov imm 0x64000001**。
实际生成者＝**脚本 OP05**：`res_47_Stg2Stream.txt` t=8760 `OP05 (664,240,1677721601,0)`、
`res_65_OpngStream.txt` t=2530 同型 rec3=0、`res_67_nohdr05000000.txt` t=7460 rec3=**1**。
rec3→ctor `[esi+0x30]`（0x43D514/0x43D51E），即 page4 状态机里挑变体的 `[0x30]`。
VM op5→`0x445AA0(0x4AD52C)`、op5 ctor 分派 0x43D430 case 0x43D4FA..0x43D538：
`[esi+0x40]=0x401F14`、`[0x1C]=[0x20]=[0x24]=[0x28]=0`、`[0x2C]=1`、`[0x30]=rec3`、
`push 0x20; mov ecx,0x56CC84; call 0x401E1F`（→0x45AF30：`[ecx+4] |= arg` **置位** sysf 0x20；
对比 0x402400→0x45AF60 `[ecx+4] &= ~arg` 清位）。
page4 `p4_vm_op5_ctl`（25134-25161）+ `P4_OP5_CTOR[0x64000001]`（15700）逐条一致 ✓。

**0x2500000B**：全 .text dword 扫描仅 1 处 `0x4134F2`＝beh 0x4130D0 内
`push 0x2500000b`（0x4134F1）；脚本流无 620757003。生成点上下文（st==4 分支
0x4134C4..0x41352A）：
```
0x4134C4  cmp eax,0x159        ; d=[esp+0x10]
0x4134C9  jge 0x4134D8         ; d≥0x159 → 0x4134D8 add [ebp+4],6（x+=6）
0x4134CB  mov ecx,ebp; call 0x401244   ; 否则摆动
0x4134D2  mov eax,[esp+0x10]
0x4134DC  test al,0x7F         ; (d&0x7F)==0 才发
0x4134DE  jne 0x413525
0x4134E0  mov ecx,[esp+0x1C]   ; hasprm（0x4130E6/0x4130F9 setne 字节）
0x4134E4  mov edx,[ebp+8]      ; e.y（移动后）
0x4134E7  mov eax,[ebp+4]      ; e.x（移动后）
0x4134EA  and ecx,0xff
0x4134F0  push ecx / 0x4134F1 push 0x2500000B / 0x4134F6 push edx
0x4134F7  lea ecx,[esp+0x44] / 0x4134FB push eax / 0x4134FC push ecx
0x4134FD  call 0x4023C4        ; →0x430400 rec={x, y, 0x2500000B, hasprm}
0x413512  lea edx,[esp+0x24]; mov ecx,0x4AD43C; push edx; call 0x401FA5
0x413525  cmp eax,0x190 / jle 0x41313C   ; d>0x190 → 静默死
```
即：**宿主=0x2500000A（beh 0x4130D0）态4**、rec={e.x, e.y, type, hasprm}、
周期 (d&0x7F)==0、d≤0x190 期间。page4 10752-10762 逐条一致 ✓
（`_p4_ent43c(0x2500000B, e.s32(4), e.s32(8), hasprm)` 入 0x4AD43C ✓）。
**ANALYSIS_archive_rounds.md §5.2 的"生成点 0x41340B"有误**：0x41340B 是
`mov esi,[0x56CC90]`（0x413407，6 字节 8B 35 90 CC 56 00）的第 5 字节（值 0x56），
不是任何指令边界。

---

## 1. 属性（任务①）

**0x24000011**：行 @`0x498138+(0x11−1)×10=0x4981D8`，字节
`30 00 78 00 40 02 80 01 00 00` → 半径 **48**、门 **120**、+0x58=**576**、
src=(**384,0**) → 节点 rect=(384,0,431,47)。page4 L482 `(48, 120, 576, 384, 0)` ✓
（应用逻辑 L970-995 与 0x43AC30 逐条一致，含门 0→−1、+0x58 符号扩展）。

ctor case（0x410A20 分派器，`add eax,0xdbffffff; cmp eax,0x10; ja; jmp [eax*4+0x410CF4]`，
jt[16]=0x410CB1）：
```
0x410CB5  mov [esi+0x40],0x401221     ; beh thunk → 0x411C10
0x410CBC  mov dword [esi+0x1C],0
0x410CC3  push 0x28
0x410CC5  mov ecx,[eax+0xC]; mov edx,[ecx]      ; 槽[0]→[0x20]（兄链）
0x410CCD  mov ecx,[eax+4];  mov [esi+0x24],ecx  ; 槽[4]→[0x24]（宿主）
0x410CD6  call 0x401393               ; rand（LCG 0x45AD00）
0x410CDB  push eax; call 0x462D71     ; 0x462D71(rand,0x28)（cdecl，add esp,8 清）
0x410CE4  mov [esp+4],eax             ; 商写进草稿槽（死存，esp 基准 S+4=init 前的 [S-4]）
0x410CE8  mov [esi+0x28],edx          ; [0x28]=rand%0x28（公转相位 0..0x27）
```
esp 断言（trace_esp 0x410A20 起）：init 块占 [S+0x10..S+0x1B]，case 体 esp=S−0xC+ret4
修正后 [esp+0x10]=记录指针、[esp+0x10]（0x410CE4 处）＝已死的槽草稿内存，后续态不会再引用。
page4 ENT24_INIT `{"beh":0x401221,"imm":{0x1C:0},"deref3":True}` + deref3 分支
（1367-1373：[0x20]=槽[0]、[0x24]=槽[4]、[0x28]=相位）✓ 结构；
**唯 [0x28] 用模块级 stdlib rng.randrange(0x28) 而非 p4_rand() LCG** → **D3**
（exe 每只挂件烧 1 步 LCG，复刻不烧，且流不同——同类先例 b3-F2）。
0x411C10 无行为跳表（单态，无 [0x1C] 分派）。

**0x2500000B**：行 @`0x498208+(0x0B−1)×10=0x49826C`，字节
`18 00 1A 00 00 00 B0 01 00 00` → 半径 **24**、门 **26**（非 −1！）、+0x58=**0**、
src=(**432,0**)。page4 L493 `(24, 26, 0, 432, 0)` ✓。
**任务前提"存活门 −1＝血量由别处管理"不成立**：exe 与 page4 均为 26（HP=26，
0x413988 直接测 [0x18]）。

ctor case（0x411E20 分派器，`add eax,0xdaffffff; cmp eax,0xA`，jt 0x4120C8 11 项，
jt[10]=0x412084；jt[9]=0x411FFE→[0x40]=0x401186（0x4130D0，0x2500000A）——
page4 ENT25_INIT 的 0A/0B 映射正确，6141 行 docstring"0x413930（0x2500000A）"是
标错型）：
```
0x412084  mov edi,[esp+0x20]          ; 记录指针
0x412088  mov [esi+0x40],0x4012D0     ; beh thunk → 0x413930
0x41208F  mov eax,[edi]; shl eax,4; mov [esi+0x1C],eax   ; [0x1C]=rec0<<4
0x412097  mov ecx,[edi+4]; shl ecx,4; mov [esi+0x20],ecx ; [0x20]=rec1<<4
0x4120A0  call 0x401393; and eax,0x3F; add eax,0x10; mov [esi+0x24],eax
0x4120AE  call 0x401393; and eax,0x3F; mov [esi+0x28],eax
0x4120B9  mov edx,[edi+0xC]; mov [esi+0x2C],edx          ; [0x2C]=rec3
```
page4 ENT25_INIT `{"beh":0x4012D0,"r0sh":(0x1C,4),"r1sh":(0x20,4),"rand_pair":True,
"d_to":0x2C}` + rand_pair 分支（1414-1417）结构一致 ✓；
**唯两次 rand 用 stdlib `_r.randrange(0x7FFFFFFF)&0x3F` 而非 LCG** → **D4**
（exe 烧 2 步 LCG）。字段语义：[0x1C]/[0x20]=8.8→12.4 位xy累加器、[0x24]=横衰减速率
(0x10..0x4F)、[0x28]=纵漂移速率(0..0x3F，−1/帧至 −0x60 下限)、[0x2C]=rec3 符号字
（0→y+=、非0→y−=）——非"放大窗"。

---

## 2. 移动行为（任务②）

**0x411C10（0x24000011）逐条**（对照 page4 `_beh_411C10` 3050-3108）：
1. 0x411C18 `mov al,byte[esi+0x1C]; test al,0x7F; jne 0x411C32`＋0x411C25
   `cmp dword[ebx+0x2C],1; jne 0x411C32`（ebx=[esi+0x24]=宿主）→
   0x411C2B `push 0; call 0x40213F`（0x43B070(e,0)，速度=[0x58]=576）✓3066-3067
   （byte&0x7F 与 dword&0x7F 等价）。
2. 0x411C32 `mov edx,[esi+0x1C]; test dl,1; je` → 0x411C3A `dec [esi+4]`（t 奇 x−=1）✓3068。
3. 0x411C3D `mov eax,[esi+0x20]; test; je 0x411C7A`：
   - 兄链路径 0x411C44..0x411C5B：`eax=[edi+8]−0x60; cmp [esi+8],eax; jge 0x411C5E`；
     y < 兄.y−0x60 → `dec [esi+4]; add ecx,2`（x−=1、y+=2）✓3072-3077；
     链走 0x411C5E..0x411C78：`al=byte[edi+0x34]; test; jne 0x411C91`（存活停），
     否则 `[esi+0x20]=[edi+0x20]`、edi=新值、非 0 循环（跳过亡兄找第一个存活者）✓3079-3082。
   - 无兄链 0x411C7A..0x411C8E：`cmp [esi+8],0x1B0; jge`；y<0x1B0 → x−=1、y+=2 ✓3083-3087。
4. 存活门 0x411C91..0x411CA3：`[0x18](HP)==0 → 死`、`byte[ebx+0x34]==0（宿主亡）→ 死`、
   `cmp [esi+4],-0x30; jl → 死`（x≥−0x30 活）✓3088-3089。
5. 活路径 0x411CA5..0x411D04：`[0x1C]++`（edx=t 旧值）、`[0x28]++`；
   `eax=新[0x28]; eax×45×2=×90; push; call 0x40159B`（cos 0x45ABB0）→
   `neg edi; sar edi,5`（**先 neg 后 sar**）→ dx=−cos>>5；
   同式 `call 0x401A50`（sin 0x45AAF0）`sar eax,5` → dy=sin>>5；
   `0x401753`（0x45A690 恒等）→ node[+0x14]=x+dx−0x30、[+0x18]=y+dy−0x30（−0x30=−r48）；
   `mov al,1` 返回 1 ✓3090-3099。
6. 死路径 0x411D05：`cmp [esi+4],-0x30; jl 0x411D9A`（x<−0x30 不发特效）；
   三次 `0x4023C4→0x430400`＋`0x401686→0x43A3C0(0x4AD4CC)`（trace_esp 0x411D05 起）：
   rec1={x, y−0x18}、rec2={x−0x18, y+0x18}、rec3={x+0x18, y+0x18}，
   均 {…, 0x44000001, 0}；0x411D9A..0x411DA9 `[ebx+0x28]++`（宿主死亡计数）+
   `xor al,al` 返 0 ✓3100-3108（`x >= -0x30` 门、三个 spawn 坐标、host[0x28]+1）。

page4 侧 **D2（实质）**：exe [0x20] 是**前件指针**、页4 存句柄
`slot.d32(0, id(piece)&0x7FFFFFFF)`（15771）但**从不把挂件注册进 p4_links**
（init 循环只注册控制器与槽；`_p4_ent43c`/Ent.__init__/_apply_family_init 均无通用注册），
`_beh_411C10` 3070 `self.p4_links.get(e.s32(0x20)&0x7FFFFFFF)` 恒 None →
兄链追逐/链走（3072-3082）永不执行，全部落 `elif y<0x1B0`（3083）：
exe 中 2..4 号出生在 0x150/0xF0/0x90 且**原地保持**（y 不小于兄.y−0x60），
page4 中它们每帧 x−=1、y+=2 一路漂到 0x1B0——阵形完全不同。
修法：生成循环里补 `self.p4_links[id(piece)&0x7FFFFFFF] = piece`。

**0x413930（0x2500000B）逐条**（对照 page4 `_beh_413930` 6140-6162）：
- 0x413933..0x41393E `[0x1C]−=[0x24]` ✓6144；
- 0x413939/0x413946..0x41394C `ecx=[0x28]; [0x2C]!=0 → neg ecx`；
  0x41394F..0x413957 `[0x20]+=ecx` ✓6146-6148；
- 0x413954 `cmp edx,-0x60; jle 0x413963` → 0x41395F `dec [0x28]`（>−0x60 才减）✓6149；
- 0x413963/0x413966 `sar ecx,4 / sar eax,4` → [8]=y、[4]=x（新 [0x20]/[0x1C]）✓6151-6155；
- 0x41396F..0x413985 dst=(x−0x18, y−0x18) ✓6156-6157；
- 返回 0x413988..0x4139B3：HP==0→0；`[0x2C]!=0 → cmp [esi+8],0x1F8; jge→0`（y≥0x1F8 死）、
  `[0x2C]==0 → cmp [esi+8],-0x18; jle→0`（y≤−0x18 死）✓6158-6162。
**0 差异**（仅 6141 docstring 型号标错）。

---

## 3. 攻击行为（任务③）

五辅助 thunk 的 E8 caller 落在 0x411C10..0x411DB0 / 0x4130D0..0x413930 /
0x413930..0x4139C0 / 0x4417D0..0x441C50 的只有：
- **0x43B070**（0x40213F）：0x411C2D（本件，arg=0，门 (byte[0x1C]&0x7F)==0 且
  宿主[0x2C]==1）；0x41343E（0x4130D0 态2，arg=**0x240**，门 (d&0x3F)==0，
  trace: `test al,0x3f / push 0x240 / call`）✓3067 / ✓10733-10734。
- **0x43B360**（0x401E56）：0x4134BD（0x4130D0 态3）：先 `push 0x1E0; rand; 0x462D71`
  → esi=%0x1E0，再 `push 0x280; rand; 0x462D71` → edx=%0x280，
  `push 0x300; push esi; push edx; call` → **arg1=%0x280、arg2=%0x1E0、arg3=0x300**，
  绝对坐标无自机偏移 ✓10747-10749；0x413695（态6）：ang=(8−d)·40
  （0x413649 lea×5/shl3）、ty=py+(sin·ytarg·2)>>8（0x413661 imul edi/shl1/sar8）、
  tx=px+(120·cos)>>8（0x413681 lea×3/lea×5/shl3/sar8）、`push tx; push ty`→
  0x413694 push 前 [F−8]=ty、[F−4]=0x2C0 → **arg=(tx,ty,0x2C0)** ✓10790-10794；
  门 main_t>0xD2 且 (main_t&0xF)==0 ✓10788。
- **0x43B610**（0x401997）：0x413301（0x4130D0 态0）：`push -0x100; push 0; push 0`
  → **arg=(0,0,−0x100)**；门 `[0x2C]!=0 且 d>0xB6`（0x4132B2..0x4132C4）；
  限额 hasprm=0：edx=((7−esi)·3)·5·4=(7−i)·60（0x4132CA..0x4132D7）`cmp ecx,edx; jl→发`；
  hasprm=1：esi=3i+3、edx=60(i+1)（0x4132E8..0x4132EF）`cmp ecx,edx; jle→不发`；
  发后 `[0x2C]=0` ✓10688-10698。
- **0x43B150 / 0x43B290**：本家族 **0 处**（xrefs 无落点）✓ page4 也不调 ✓。
控制器 0x4417D0 本体无发弹（只生成敌件/爆块）✓。

---

## 4. 控制器 0x4417D0 完整逻辑（任务⑤前半）

- 序言 `sub esp,0x14C; push ebx; push ebp; mov ebp,ecx; xor ebx,ebx; push esi; push edi`。
- init（[0x1C]==0）见 §0；**exe t=−0xC0**。之后每帧：态分派
  `eax=[ebp+0x24]; cmp eax,5; ja 0x441BB8; jmp [eax*4+0x441C24]`，
  表 0x441C24 六项 `44186A,4418A4,441950,441A2D,441AF5,441AF5`（态4/5 共体）
  （后跟 0x90909090 填充确认）。
- 态0（0x44186A）：`push 0x3C; rand; 0x462D71` → edx%0x3C；0x44187A `add edx,-0xB4`；
  `[ebp+0x20]=edx`（相位=rand%0x3C−0xB4）；`push 5; rand; 0x462D71`；
  0x441897 `inc edx` → `[ebp+0x24]=rand%5+1`（态 1..5）✓15776-15778。
  （0x441880/0x441898 `mov [esp+0x10],eax` 是把商写进 init 已死的槽草稿内存，无消费者。）
- 态1（0x4418A4）：`[0x20]!=0 → 跳过`；`[0x30]==0 → 0x430400(&rec,0x2D0,-0x18,0x24000009,0xE)`
  入 0x4AD43C；否则 y=rand%0x140+0x50、`(&rec,0x298,y,0x2400000A,0)` ✓15779-15785。
- 态2（0x441950）：`[0x30]==0`：`[0x20]<0 → 跳过`、`test al,0x1F`（ph&0x1F==0）→
  0x24000002 @(0x298, rand%0x140+0x50, 0)（0x441962..0x4419BB）；
  `[0x30]!=0`（0x4419C5）：`[0x20]<0 → 跳过`、`test al,0x3F` →
  0x2400000B @(0x298, rand%0x140+0x50, 0)（0x4419D5..0x441A23）✓15786-15795。
- 态3（0x441A2D）：`[0x20]<0 → 跳过`、`test al,0x3F`；`[0x30]==0`（0x441A40）→
  0x24000004 @(rand%0x140+0xF0, 0x1F8, 0)（0x441A43..0x441A9B，push 序：
  0x140→rand→0x462D71→push 0→push type→add edx,0xF0→push 0x1F8→…）；
  否则（0x441AA5）0x2400000F @(0x298, rand%0x140+0x50, 0) ✓15796-15804。
- 态4/5（0x441AF5）：`[0x20]<0 → 0x441B51`；`cmp eax,0x78; jge 0x441B54`；
  <0x78：`test al,1`（奇帧）→ `push 0x3C0; rand; 0x462D71` →
  rec={rand%0x3C0, -0x18, 0x44000002, 0} 入 **0x4AD4CC**（0x401686→0x43A3C0）✓15807-15811；
  ==0x78（0x441B51 `cmp; jne 0x441B5F`）→ `[0x2C]=0` ✓15812-15813；
  0x441B5F `jle 0x441BAA`（<0x78 的偶帧也走这里）；0x78<t<0xF0（0x441B61 jge 0x441BAA）
  且 `test al,0xF`==0 → rec={5t, 5t−0x6E, 0x24000003, 0} 入 0x4AD43C
  （0x441B6C lea ecx,[eax+eax*4-0x6E]、0x441B77 lea edx,[eax+eax*4]）✓15815-15816；
  ==0x1A4（0x441BAA）→ `[0x2C]=1`（挂件开火门）✓15817-15818。
- 尾 0x441BB8..0x441C20：`ecx=[0x24]; edx=0; cmp ecx,3; setg dl; dec edx; and dl,0x4C;
  add edx,0x1A4` → 限時=0x1A4+(态>3 ? 0x4C : 0)；`cmp [0x20],edx; jne`；
  相等 → `[0x24]=0`（回态0 重抽）✓15819-15821；
  `ecx=[0x1C]; pop edi; inc ecx; inc eax; [0x20]=eax; [0x1C]=ecx`（相位/t 各 +1）✓15822-15823；
  `eax=[0x28]; cmp eax,0x50; jl 0x441C18`（<80 返 1）；
  ≥0x50：`push 0x20; mov ecx,0x56CC84; call 0x402400`（→0x45AF60 **清** sysf 0x20）、
  `push 0x1400; push 0xB; mov ecx,0x4AB4B0; call 0x4013A2`（→0x450350 SE 0xB pan 0x1400）、
  `xor al,al` 返 0（下一轮摘链）✓15824-15827。

**控制器不管理 HP**：挂件血量=prop 门 120（各自 [0x18]，被弹扣），控制器只做
波次生成 + 攻击态调度 + 死亡计数（[0x28]≥0x50 触发收尾）。
page4 `_beh_4417D0`（15744-15828）除 **D1**（init t 常量）外逐条一致 ✓。

---

## 5. 死亡行为与豁免（任务⑤后半）

**三张击破豁免表**（同一 6 型名单，`cmp eax,0x24000011` 领头）：
- 0x43C220（自机弹最后一击路径，函数 0x43C170，thunk 0x401028←0x43BFD0）：
  0x43C220 `cmp eax,0x30 / jne 0x43C28C`、0x43C228/0x43C22F/0x43C236/0x43C23D/
  0x43C244/0x43C24B 逐一 `cmp/je 0x43C28C`；非豁免 → rec={x,y,0x61000004,0x30} 入
  0x4AD52C（0x40201D）；豁免 → rec={x,y,0x41000001,ebx(0)} 入 0x4AD4CC
  （0x401686，0x43C2BB）；两支汇合 0x43C2C6：`byte[ebp+0x10]=bl; [ebp+0x18]=ebx(0)`、
  `0x401F96→0x45EFF0(0x4CD4A0, type, x, y, 0x100D1211)`、SE4 pan=(x−0x140)<<4。
- 0x43C9F4（共用尾 0x43C9C2，弹/碰撞击破主路径）：0x43C9F4 `cmp [ebp+0xC],0x30 /
  jne 0x43CA61`、0x43C9FD..0x43CA25 同表 → 0x43CA2D rec={x,y,0x61000004,0x30} 入
  0x4AD52C / 0x43CA67 rec={x,y,0x41000001,0} 入 0x4AD4CC → 0x45EFF0。
- 0x43D2B4（狙击命中结算 0x43D250，thunk 0x401CDA←0x42A11D）：0x43D2AE
  `cmp [ebp+0xC],0x30 / jne 0x43D31B`、0x43D2B7..0x43D2DF 同表 → 同两支。
名单＝{0x24000011, 0x2300000E, 0x27000011, 0x29000013, 0x2C00000B, 0x2C00000A}。
**0x24000011 三处全豁免**（死亡＝0x41000001 星尘，无 0x61000004 普通爆块）；
**0x2500000B 不在名单** → 被弹击破走普通爆块 0x61000004@0x30。
page4 三处对应：21697-21701（_p4_43c9c2）、19899-19905（t==6 最后一击）、
19730-19734（_p4_43d250），名单元组一致 ✓。
- beh 返 0 路径（宿主亡 / x<−0x30 / HP==0 帧）：队列遍 0x43BC70 只清
  byte[+0x34]=0、byte[+0x10]=0、byte[[+0x38]+0x1C]=0——**静默移除无爆块**
  （0x24000011 的死亡特效全部由 beh 死路径自己发：3×0x44000001）✓
  page4 `_p4_tick_ents` 语义一致 ✓；op5 控制器走 0x445A30（0x43DC90=jmp[obj+0x40]、
  返 0 → byte[+0x34]=0 + byte[[obj+0x38]+0x1C]=0，0x445A51..0x445A57）✓
  page4 `_p4_tick_52c` ✓。
- **0x64 族不在战斗族 prop/ctor 体系内**（无 0x498138 行、无节点）：op5＝0x48 字节
  控制器对象、队列 0x4AD52C、ctor 0x430450+0x43D430、无击中碰撞路径
  （`[obj+0xC]==0x30` 类判定只对 0x5C 战斗体）。page4 建模＝`p4_vm_op5_ctl` 生成
  普通 Ent（无节点）入 ui52c、`P4_OP5_BEH_THUNK`/`P4_OP5_CTOR` 两表、
  `_p4_tick_52c` 按链语义 tick、sysf 0x20 置位（ctor 0x45AF30）/清位（尾 0x45AF60）
  ——与 exe 一致 ✓（队列次序 0x4AD52C 最后，0x458EBB ✓ p4_dispatch 19233）。

---

## 6. 差异汇总

| # | exe 地址+指令 | page4.py | 现值 → 应值 | 影响 |
|---|---|---|---|---|
| D1 | 0x441850 `mov dword [ebp+0x1C],0xFFFFFF40`（−0xC0） | 15774 `e.d32(0x1C, 0xFFFFFFC0)` | `0xFFFFFFC0`(−0x40) → `0xFFFFFF40`(−0xC0)；15748 docstring 本来就写 −0xC0 | 控制器 [0x1C] 归零周期 64→192 帧，4 只挂件重波频率 3×过快 |
| D2 | 0x441846 槽[0]=新件指针（0x411C3D/0x411C44..0x411C78 按 [0x20] 追兄） | 15771 只 `slot.d32(0, id(piece)&0x7FFFFFFF)`，未 `p4_links` 注册 | 缺 `self.p4_links[id(piece)&0x7FFFFFFF] = piece` | 兄链解析恒 None：2..4 号挂件不守 0x60 阶梯，出生即向 y=0x1B0 漂移合流 |
| D3 | 0x410CD6..0x410CE8 [0x28]=LCG rand%0x28（0x401393→0x45AD00） | 1373 `rng.randrange(0x28)`（模块 stdlib） | 改 `self._pages.p4_rand() % 0x28` | 每只挂件漏烧 1 步 LCG，全屏随机序列与 exe 失步（同类 b3-F2） |
| D4 | 0x4120A0/0x4120AE [0x24]/[0x28]=LCG rand&0x3F(+0x10) ×2 | 1414-1417 `random.randrange(0x7FFFFFFF)&0x3F` ×2 | 改 2 次 `self._pages.p4_rand() & 0x3F` | 每只 0x2500000B 漏烧 2 步 LCG |

仅注释/文档错（代码正确）：page4.py:6141 docstring "0x413930（0x2500000A）" 应为
0x2500000B；ANALYSIS_archive_rounds.md §5.2"生成点 0x41340B"应为 0x4134F1
（beh 0x4130D0 态4，周期 (d&0x7F)==0、rec={x,y,hasprm}）；b3 报告 0x26000018 prop 行
地址 0x4983A0 应为 0x498376（族基址 0x498290，值不变）。

**0 差异清单**：0x24000011 prop 行与 ctor case 字段（除 D3）、beh 0x411C10 全部
六段（发弹门/奇帧位移/兄链追逐与链走/无兄漂移/存活门/公转 dst/死路径三爆点+宿主计数）、
0x2500000B prop 行与 ctor case 字段（除 D4）、beh 0x413930 全部、
0x2500000B 生成点（宿主/rec 值/周期）、控制器态机 0..5 全部分支与尾（除 D1）、
op5 ctor case 0x43D4FA、0x64000001 生成链（脚本 OP05→0x445AA0）、
三张击破豁免表与 page4 三处对应、p4_vm_op5_ctl/_p4_tick_52c 建模。
