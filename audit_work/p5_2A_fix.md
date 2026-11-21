# p5 — 关7 挂件链（0x2A000002/03/04）惰性问题修复报告

任务来源：a7_2D_2A_23.md"报告外发现"第 3 条——0x40A930 铺挂件的生成记录缺 rec3、
0x2A 挂件 beh 把 exe 的"指针+4 寻址基"当句柄查表，导致挂件在复刻侧整体惰性。
本报告由主会话验收（执行 agent 中途配额中断，改动已全部落地并经逐条抽查）。

## exe 定案（0x40A930 态0 + 三 ctor + beh 头）

1. **生成记录**（0x40A946..0x40A9AF）：`0x4023C4(out, 0, 0, 0x2A000002, boss)`
   → rec={0, 0, type, **boss 指针**, 垃圾}；0x40A990/0x40A9A7 只改 rec2 复用同一
   记录再入队 0x2A000003/0x2A000004。rec0/rec1=0 ⇒ 出生点 (0,0)，实际位置由各
   beh 首帧按主体重算。
2. **ctor**（0x40A4BB/0x40A538/0x40A5DC，跳表 0x40A7F8 case=type−0x2A000001）：
   [0x1C] = rec[3] = boss 指针；+0x0C=0x18、+0x18=0x640、byte[0x10]=1；
   rect：02=(0x110,0,0x16F,0x5F)、03=(0x1E0,0,0x27F,0x9F)（ctor 另置 [0x30]=0
   后连调 4×0x402202 → 出口 [0x30]=4）、04=(0x170,0,0x1DF,0x103)；
   dst：02=(x−0x2C,y−0x32)、03=(x−0x50,y−0x50)、04=(x−0x28,y−0xC8)。
   注：0x40A65F 是 **0x2A000005** 的 ctor（[0x14]=rec3+0x2A000005 的型号阶梯），
   不是 0x2A000002。
3. **beh 寻址**（0x40B04C/0x40BB60 同构/0x40C59C）：`ebx = [0x1C] + 4`，
   字段读 [ebx+X] = boss+(X+4)：[ebx] = boss.x、[ebx+0x1C] = boss+0x20（态内计时）、
   [ebx+0x20] = boss+0x24（态）、[ebx+0x24] = boss+0x28（编队掩码 dword）、
   [ebx+0x30] = boss+0x34（存活字节）。掩码车道：40B040 用车道0（and 0x1FF，减量 0/1）、
   40C590 用车道2（sar 0x12，减量 0/0x40000）。
4. **st4 速度表**（0x40C7E2..0x40C8C4，esp=base−8 换算后）：A=(0x64,0x5C,0x47,0x26)、
   B=(0,0x26,0x47,0x5C)；x<自机x → A 取负；双发 0x43B290(e, −A, ±B, −0x200)。
5. **sub10 对表**（0x40C94C..0x40CA27）：(A,B)=(0xC,−5)/(5,0)/(0xC,5)/(5,5)/
   (5,0xC)/(0,5)/(−5,0xC)，自.x≥自机x → A 取负、自.y≥自机y → B 取负。
6. **sub11 三连**（0x40CA8F..0x40CAD5）：(vx,vy)/(2vx−vy, vx+2vy)/(vy+2vx, 2vy−vx)，
   −0x380；速度=inv*Δ*6>>12（0x40CA53..0x40CA76）。
7. **sub12 环形**（0x40CADC..0x40CB23）：a=0x708 步 −0x64 ×4，(cos>>2, sin>>2, 0x1C0)
   与 (−cos>>2, −sin>>2, 0x1C0) 对称双发。

## 落地改动（remake/pygame/page4.py）

- `_beh_40B040`/`_beh_40BB60`/`_beh_40C590`：`main = links.get(e.s32(0x1C))`（去 +4），
  字段读取按 boss+0x20/0x24/0x28/0x2C/0x34 换算；十三态表与开火段按上面 exe 值重写。
- `_p4_40b040_tail`：字段同步换算（[ebx+0x20]→主+0x24、[ebx+0x28]→主+0x2C、
  [ebx+0x30]→主+0x34）；重生 rec3=主句柄。
- `0x40A930` 态0：三件 rec={0,0,type,boss 句柄} + p4_links 登记。
- ENT2A_INIT：02/03/04 的 d_to 0x1C、rect/dst/imm（03 的 0x30:4）逐项对齐 ctor。

## 验收

主会话逐条抽查（0x40B040 头、st4 栈表含 esp−8 换算、sub11 三连、sub12 环形、
车道2 减量 0x40000）全部与反汇编一致。护栏：check_behaviors OK、longrun 3000 OK、
audit_p4 全部通过、regress_pages 16 张金标一致。
