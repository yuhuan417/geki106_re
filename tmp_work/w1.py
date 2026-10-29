import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import re_dis
R = re_dis.load()
R.dis(0x43A7F0, 0x43AA00, 'ctor 0x43A7F0')
