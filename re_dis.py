"""Recursive-descent disassembler for geki106.exe (reusable).

Usage:
    import re_dis
    R = re_dis.load()          # R.insns: dict va -> capstone insn ; R.funcs: set of entries
    R.xrefs(val)               # list of (va, insn, kind) for mem/immediate refs
"""
import pefile, capstone, struct, collections

EXE = '/home/yuhuan/geki106/geki106.exe'


class Re:
    def __init__(self, path=EXE):
        self.pe = pefile.PE(path)
        self.ib = self.pe.OPTIONAL_HEADER.ImageBase
        self.data = self.pe.get_memory_mapped_image()
        self.sec = self.pe.sections[0]
        self.text = self.sec.get_data()
        self.tva = self.ib + self.sec.VirtualAddress
        self.tend = self.tva + len(self.text)
        self.md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
        self.md.detail = True
        self.insns = {}
        self.funcs = set()
        self.extra_entries = set()
        self.bad = set()
        self._sweep()
        self._xref_index = None

    # ---- low level ----
    def raw(self, va, n=8):
        o = va - self.ib
        return self.data[o:o + n]

    def dec(self, va):
        o = va - self.tva
        if o < 0 or o >= len(self.text):
            return None
        return next(self.md.disasm(self.text[o:o + 16], va), None)

    def jmp_target(self, ins):
        if ins.mnemonic == 'jmp' and ins.operands and ins.operands[0].type == capstone.x86.X86_OP_IMM:
            return ins.operands[0].imm
        return None

    def call_target(self, ins):
        if ins.mnemonic == 'call' and ins.operands and ins.operands[0].type == capstone.x86.X86_OP_IMM:
            return ins.operands[0].imm
        return None

    def _table_of(self, ins):
        """if ins is jmp/call dword ptr [reg*4+disp32], return targets in .text"""
        if not ins.operands:
            return []
        op = ins.operands[0]
        if op.type != capstone.x86.X86_OP_MEM:
            return []
        disp = op.mem.disp
        if not (self.ib + self.sec.VirtualAddress <= disp < self.ib + 0x600000):
            return []
        out = []
        for k in range(96):
            d = self.raw(disp + 4 * k, 4)
            if len(d) < 4:
                break
            v = struct.unpack('<I', d)[0]
            if self.tva <= v < self.tend:
                out.append(v)
            elif out:
                break
        return out

    def _seed_entries(self):
        """all E8 rel32 targets, all E9 rel32 targets, plus known entries"""
        ents = {0x4641F6}
        t = self.text
        for i in range(len(t) - 5):
            b = t[i]
            if b in (0xE8, 0xE9, 0xEB):
                rel = struct.unpack('<i', t[i + 1:i + 5])[0] if b != 0xEB else None
                if rel is None:
                    continue
                tgt = self.tva + i + 5 + rel
                if self.tva <= tgt < self.tend:
                    ents.add(tgt)
        return ents

    def _walk(self, start, seen_local):
        stack = [start]
        while stack:
            pc = stack.pop()
            while True:
                if pc in self.insns or pc in seen_local or pc in self.bad:
                    break
                ins = self.dec(pc)
                if ins is None:
                    self.bad.add(pc)
                    break
                seen_local.add(pc)
                self.insns[pc] = ins
                m = ins.mnemonic
                nxt = pc + ins.size
                if m == 'ret' or m == 'retf' or m == 'iret' or m == 'int3':
                    break
                if m == 'jmp':
                    t = self.jmp_target(ins)
                    if t is not None:
                        pc = t
                        continue
                    # indirect jump through a dword table -> seed table targets
                    tab = self._table_of(ins)
                    if tab:
                        for e in tab:
                            self.funcs.add(e)
                            self.extra_entries.add(e)
                            stack.append(e)
                    break
                if m.startswith('j') and ins.operands and ins.operands[0].type == capstone.x86.X86_OP_IMM:
                    stack.append(ins.operands[0].imm)
                    pc = nxt
                    continue
                if m == 'call':
                    t = self.call_target(ins)
                    if t is not None:
                        self.funcs.add(t)
                    pc = nxt
                    continue
                if m in ('ud2',):
                    break
                pc = nxt

    def _sweep(self):
        ents = self._seed_entries()
        self.entries = sorted(ents)
        todo = sorted(ents)
        done = set()
        while todo:
            e = todo.pop()
            if e in done or not (self.tva <= e < self.tend):
                continue
            self.funcs.add(e)
            done.add(e)
            self._walk(e, set())
            while self.extra_entries:
                todo.append(self.extra_entries.pop())
        print(f"[re_dis] insns={len(self.insns)} funcs={len(self.funcs)} bad={len(self.bad)}")

    # ---- xref ----
    def build_xref_index(self):
        idx = collections.defaultdict(list)
        for va, ins in self.insns.items():
            for i, op in enumerate(ins.operands):
                if op.type == capstone.x86.X86_OP_MEM and op.mem.disp:
                    idx[op.mem.disp & 0xffffffff].append((va, ins, i))
                elif op.type == capstone.x86.X86_OP_IMM and 0x400000 <= op.imm < 0x600000:
                    idx[op.imm].append((va, ins, i))
        self._xref_index = idx
        return idx

    def xrefs(self, val):
        if self._xref_index is None:
            self.build_xref_index()
        return self._xref_index.get(val, [])

    def writes_to(self, val):
        out = []
        for va, ins, i in self.xrefs(val):
            op = ins.operands[i]
            if i != 0:
                continue
            if op.type != capstone.x86.X86_OP_MEM:
                continue
            if ins.mnemonic in ('cmp', 'test', 'push', 'call', 'jmp', 'lea'):
                continue
            out.append((va, ins))
        return out

    def reads_from(self, val):
        out = []
        for va, ins, i in self.xrefs(val):
            op = ins.operands[i]
            if op.type == capstone.x86.X86_OP_MEM:
                if i != 0:
                    out.append((va, ins))
                elif ins.mnemonic in ('cmp', 'test', 'push'):
                    out.append((va, ins))
            else:
                out.append((va, ins))
        return out

    def dis(self, a, b, label=''):
        print(f"===== {label} {a:#x}-{b:#x} =====")
        pc = a
        while pc < b:
            ins = self.insns.get(pc) or self.dec(pc)
            if ins is None:
                print(f"{pc:#x}  ?? {self.raw(pc,8).hex()}")
                pc += 1
                continue
            print(f"{pc:#x}  {ins.mnemonic:<8} {ins.op_str}")
            pc += ins.size


def load(path=EXE):
    return Re(path)
