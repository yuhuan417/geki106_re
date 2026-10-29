import sys, os, struct
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import re_dis
R = re_dis.load()
def resolve(a, depth=6):
    chain=[a]
    for _ in range(depth):
        ins = R.insns.get(a) or R.dec(a)
        if ins is None: break
        if ins.mnemonic=='jmp' and ins.operands and ins.operands[0].type==2:
            a = ins.operands[0].imm; chain.append(a)
        else: break
    return a, chain
if __name__=='__main__':
    for a in sys.argv[1:]:
        v,ch = resolve(int(a,16))
        print(hex(int(a,16)), '->', ' -> '.join(hex(x) for x in ch), ' ==> ', hex(v))
