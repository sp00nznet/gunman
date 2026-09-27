#!/usr/bin/env python3
"""Walk down a call tree to the lifted function whose own body breaks the frame.

    py -3 tools/treewalk.py 10050DB0          (LIT_MIN=40 to count a smeared frame as lit)

find_bad_lift.py's answer is a function whose ORIGINAL code fixes the frame --
but original code calls original code, so its whole call tree ran natively,
and the bug can be anywhere under it. This keeps the function lifted, runs its
direct callees natively (one-byte --native-range, so exactly those entries),
and halves the callees until one subtree is left; then repeats one level down.
When the callees alone don't fix it, the bug is in the function's own body.
It found AngleVectors -> sin/cos (docs/ingame.md).
"""
import os
import sys
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
os.chdir(ROOT)
sys.path.insert(0, os.path.join(ROOT, 'tools')); sys.path.insert(0, ROOT)
import find_bad_lift as f
import run_lift
from capstone import Cs, CS_ARCH_X86, CS_MODE_32
md = Cs(CS_ARCH_X86, CS_MODE_32); md.detail = True
info, byaddr, code, proven = run_lift.load_module('work/rebased/sw.dll', 'sw')
entries = proven & set(byaddr)
SKIP = {0x10083060, 0x10082E70, 0x100A0880, 0x10092994, 0x1009299B, 0x100206B0,
        0x10020580, 0x100A0084}          # prints, errors, CRT/FPU stubs
def callees(a):
    insns, _ = run_lift.descend(md, code, info.code_start, info.code_end, a, entries)
    out = []
    for i in insns:
        if i.mnemonic == 'call':
            t = i.get_branch_target()
            if t in byaddr and t != a and t not in out and t not in SKIP: out.append(t)
    return out
def trial(cs):
    return f.trial([(c, c + 1) for c in cs], 90)
f.make_bisect_images()
fn = int(sys.argv[1], 16)
while True:
    cs = callees(fn)
    f.log('walk: sub_%08X callees %s' % (fn, ' '.join('%08X' % c for c in cs)))
    if not cs or not trial(cs):
        f.log('WALK FOUND: bug in the body of sub_%08X (or needs several callees)' % fn); break
    while len(cs) > 1:
        half = cs[:len(cs) // 2]
        if trial(half): cs = half
        elif trial(cs[len(cs) // 2:]): cs = cs[len(cs) // 2:]
        else: f.log('walk: neither half alone fixes it'); cs = []; break
    if not cs: break
    f.log('walk: descend into sub_%08X' % cs[0]); fn = cs[0]
