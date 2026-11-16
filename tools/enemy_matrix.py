#!/usr/bin/env python3
"""生成 docs/p4_enemy_matrix.md 骨架（不覆盖人工审计列）。

用法：python3 tools/enemy_matrix.py > docs/p4_enemy_matrix.md
"""
import os,sys,re,glob
os.environ.setdefault('SDL_VIDEODRIVER','dummy'); os.environ.setdefault('SDL_AUDIODRIVER','dummy')
ROOT=os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0,os.path.join(ROOT,'remake/pygame'))
import pygame; pygame.display.init(); pygame.font.init(); pygame.display.set_mode((320,240))
import page4
TABLES=('ENT23_INIT','ENT24_INIT','ENT25_INIT','ENT26_INIT','ENT27_INIT',
        'ENT28_INIT','ENT29_INIT','ENT2A_INIT','ENT2C_INIT','ENT2D_INIT')
tables={n:getattr(page4,n) for n in TABLES if getattr(page4,n,None)}
appear={}
for fn in sorted(glob.glob(os.path.join(ROOT,'extracted/script_txt/res_*.txt'))):
    m=re.search(r'res_(\d+)',fn)
    if not m or not (45<=int(m.group(1))<=74): continue
    num=int(m.group(1))
    for mm in re.finditer(r'OP02\s+\(([^)]*)\)',open(fn,encoding='utf-8',errors='ignore').read()):
        a=[x.strip() for x in mm.group(1).split(',')]
        if len(a)>=3:
            try: t=int(a[2])
            except: continue
            appear.setdefault(t,set()).add(num)
alltypes=set()
for t in tables.values(): alltypes|=set(t)
alltypes|=set(appear)
def info(typ):
    for name,tb in tables.items():
        if typ in tb: return name,tb[typ]
    return None,None
print('# 页4 敌机全量矩阵（VM/脚本对齐用）\n')
print('> 由 `tools/enemy_matrix.py` 生成；状态列人工审计后改写。审计项：')
print('> 入场 / 移动 / 攻击 / 受击 / 关联 / 死亡 / 掉落 / 分数 / 出屏 / 接触。\n')
print('| 类型 | 族 | 行为 | 半径 | 存活门 | 出现流 | 审计 |')
print('|---|---|---|---|---|---|---|')
for typ in sorted(alltypes):
    name,i=info(typ)
    if i:
        th=i.get('beh'); real=page4.ENT23_BEH_THUNK.get(th,th) if th else None
        addr=f'0x{real:X}' if real else '-'
        prop=page4.ENT_PROP.get(typ&0xFF) if (typ>>24)==0x23 else page4.ENT_PROP_FAM.get(typ)
        r=prop[0] if prop else '-'; hp=prop[1] if prop else '-'
    else:
        addr=r=hp='-'
    st=','.join(str(x) for x in sorted(appear.get(typ,[]))) or '-'
    print(f'| 0x{typ:08X} | {name or "-"} | {addr} | {r} | {hp} | {st} | 未审计 |')
