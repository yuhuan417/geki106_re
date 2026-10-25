#!/usr/bin/env python3
"""撃破伝重制版入口: python3 main.py [stage] [frames]"""
import sys

from geki.game import main

if __name__ == "__main__":
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    stage = int(args[0]) if args else 1
    frames = int(args[1]) if len(args) > 1 else None
    headless = "--headless" in sys.argv
    main(stage, frames, headless)
