#!/usr/bin/env python3
"""geki106 关卡脚本反汇编器（从 exe 0x460350 解释器还原）
记录: u16 opcode, u16 time(frame), args...
 op0: size 0   链到队列中的下一个 stream 资源
 op1: size 20  cmd(a,b,c,d) -> 队列 0x4AD40C
 op2: size 20  cmd -> 队列 0x4AD43C（主实体/事件队列, 引用最多）
 op3: size 20  cmd -> 队列 0x4AD4CC
 op4: size 20  cmd -> 队列 0x4AD4FC
 op5: size 20  cmd -> 队列 0x4AD52C
 op6: size 92  发射器一次性触发 (emitter bank 0x4AD55C)
 op7: size 96  发射器定义到通道 arg0 (<12=通道号, >=12=全部12通道)
 op8: size 8   停止发射器通道 arg0 (>=12 = 全部)
 op9: size 16+arg2*4  变长表 -> 0x4CD484
 opA: size 12  两参数调用 0x4CD484
 opB: size 60  14 x dword 图层/屏幕初始化 (0x4AA7B0)
 opC: size 8   阶段转换事件 (0x4AB514, arg!=3 为真)
 opD: size 8   设全局参数 (0x4CD4A0)
 opE: size 20  注释 "/*Name*/"
"""
import struct, os, sys

SIZES = {0:0, 1:20, 2:20, 3:20, 4:20, 5:20, 6:92, 7:96, 8:8, 0xA:12, 0xB:60, 0xC:8, 0xD:8, 0xE:20}

def fp(v):  # 16.16 定点
    return (v - 0x10000 if v & 0x80000000 else v) / 65536.0

def parse(data):
    pos, recs, n = 0, [], len(data)
    while pos + 4 <= n:
        op, time = struct.unpack('<HH', data[pos:pos+4])
        if op > 0xE:
            return recs, pos
        if op == 9:
            if pos + 16 > n: return recs, pos
            cnt = struct.unpack('<I', data[pos+12:pos+16])[0]
            if cnt > 65536: return recs, pos
            size = 16 + cnt*4
        else:
            size = SIZES[op]
        if op == 0:
            recs.append((pos, op, time, b''))
            return recs, pos + 4   # op0 = 链到下一 stream, 本流结束
        if pos + size > n:
            return recs, pos
        recs.append((pos, op, time, data[pos+4:pos+size]))
        pos += size
    return recs, pos

def decode_emitter(args):
    """op6: idx+80B参数+1dword尾(92); op7: idx+80B参数+2dword尾(96)"""
    out = []
    body = args[4:84]
    for i in range(0, 80, 4):
        v = struct.unpack('<I', body[i:i+4])[0]
        out.append(round(fp(v), 3))
    tail = args[84:]
    return out, tail.hex()

def render(recs):
    lines = []
    for off, op, time, args in recs:
        if op == 0xE:
            name = args.split(b'\0')[0].decode('ascii','replace')
            lines.append(f"[{off:06X}] t={time:5d} ; {name}")
        elif op in (1,2,3,4,5):
            a = struct.unpack('<4I', args[:16])
            lines.append(f"[{off:06X}] t={time:5d} OP{op:02X}  ({a[0]},{a[1]},{a[2]},{a[3]})")
        elif op in (6,7):
            idx = struct.unpack('<I', args[:4])[0]
            vals, tail = decode_emitter(args)
            lines.append(f"[{off:06X}] t={time:5d} OP{op:02X} emit ch={idx} f20={vals[:20]}")
        elif op == 8:
            idx = struct.unpack('<I', args[:4])[0]
            lines.append(f"[{off:06X}] t={time:5d} OP08 emit-stop ch={idx}")
        elif op == 9:
            a0,a1,cnt = struct.unpack('<3I', args[:12])
            extra = [struct.unpack('<I', args[12+i*4:16+i*4])[0] for i in range(cnt)]
            lines.append(f"[{off:06X}] t={time:5d} OP09 table({a0},{a1}) n={cnt} v={extra}")
        elif op == 0xA:
            a = struct.unpack('<2I', args[:8])
            lines.append(f"[{off:06X}] t={time:5d} OP0A ({a[0]},{a[1]})")
        elif op == 0xB:
            vals = struct.unpack('<14I', args[:56])
            lines.append(f"[{off:06X}] t={time:5d} OP0B layers={list(vals)}")
        elif op == 0xC:
            v = struct.unpack('<I', args[:4])[0]
            lines.append(f"[{off:06X}] t={time:5d} OP0C transition {v}")
        elif op == 0xD:
            v = struct.unpack('<I', args[:4])[0]
            lines.append(f"[{off:06X}] t={time:5d} OP0D param={v}")
        elif op == 0:
            lines.append(f"[{off:06X}] t={time:5d} OP00 NEXT-STREAM")
    return lines

if __name__ == '__main__':
    d = open('resource_dec.bin','rb').read()
    def off(i): return int.from_bytes(d[(i-1)*3:(i-1)*3+3],'little')
    n = 294//3
    def getent(idx):
        o = off(idx); e = off(idx+1) if idx < n else len(d)
        return d[o:e]
    os.makedirs('extracted/script_txt', exist_ok=True)
    for idx in range(45, 77):
        ent = getent(idx)
        recs, endpos = parse(ent)
        # 尾部允许: [4零字节][opE 更新日期注释][零填充] (作者日期戳, 游戏不读)
        tail = ent[endpos:]
        lstrip = tail.lstrip(b'\x00')
        ok = endpos == len(ent) or (lstrip[:4] in (b'\x0e\x00\x00\x00', b'') and len(lstrip) <= 20)
        name = ent[4:24].split(b'\0')[0].decode('ascii','replace') if ent[0]==0x0e else f'nohdr{ent[:4].hex()}'
        safe = name.strip('/').replace('*','') or 'x'
        lines = render(recs)
        with open(f'extracted/script_txt/res_{idx:02d}_{safe}.txt','w') as f:
            f.write('\n'.join(lines))
        ops = {}
        for _,op,_,_ in recs: ops[op] = ops.get(op,0)+1
        print(f"#{idx} {name:20s} len={len(ent):6d} recs={len(recs):4d} synced={'OK' if ok else 'DESYNC@'+hex(endpos)} ops={dict(sorted(ops.items()))}")
