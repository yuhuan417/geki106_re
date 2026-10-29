import sys, os, struct
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import re_dis
R = re_dis.load()

def pad_end(start, limit=0x2000):
    d = R.data
    o = start - R.ib
    i = d.find(b'\xcc\xcc\xcc\xcc', o, o+limit)
    return (R.ib+i) if i>=0 else None

def fn(a, n=None, label=''):
    e = pad_end(a)
    if n: e = a+n
    R.dis(a, e, label)
    print('end', hex(e) if e else None, 'len', (e-a) if e else None)

if __name__ == '__main__':
    args = sys.argv[1:]
    if args[0] == 'fn':
        fn(int(args[1],16), label=args[2] if len(args)>2 else '')
    elif args[0] == 'dis':
        R.dis(int(args[1],16), int(args[2],16), args[3] if len(args)>3 else '')
    elif args[0] == 'xref':
        for va, ins, i in R.xrefs(int(args[1],16)):
            print(hex(va), ins.mnemonic, ins.op_str)
    elif args[0] == 'writes':
        for va, ins in R.writes_to(int(args[1],16)):
            print(hex(va), ins.mnemonic, ins.op_str)
    elif args[0] == 'reads':
        for va, ins in R.reads_from(int(args[1],16)):
            print(hex(va), ins.mnemonic, ins.op_str)
