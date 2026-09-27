#!/usr/bin/env python3
"""Find the lifted function(s) behind a symptom, by running parts as ORIGINAL code.

    py -3 tools/find_bad_lift.py sw 0x10001000 0x100AF000 [--seconds 90]

Each round lifts with part of the module's functions turned into thunks that
run the original machine code (run_lift.py --native-range), builds, boots into
a new game, and asks one question: is the frame lit? A half whose nativeness
makes it lit contains the bug. If neither half alone does, both hold one; the
first is kept native (so the second can be isolated) and the search goes on.

Why it works at all: the host is 32-bit and every module sits at its real
address, so original and lifted code can call each other. docs/boot.md has
the rounds it took to find each bug it found.
"""
import argparse
import json
import os
import re
import subprocess
import sys
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LOG = os.path.join(ROOT, 'work', 'bisect.log')


# R_RenderView (sw.dll 0x100510D0) begins with Quake's stack check: it
# Sys_Errors -- "R_RenderView: called without enough stack" -- when the current
# stack is more than 10,000 bytes from the address R_Init recorded. Native code
# runs on the host stack and lifted code on the guest stack, so a split build
# trips it. Bisection builds use a copy of the rebased images with the two
# branches into the error made harmless; the lifter reads its code from that
# copy and the runtime maps it, so both sides agree.
BISECT_DIR = 'work/rebased-bisect'
STACK_CHECK_PATCH = {0x100510E2: (b'\x7c\x07', b'\x90\x90'),   # jl  error -> nop nop
                     0x100510E9: (b'\x7e\x0d', b'\xeb\x0d')}   # jle ok    -> jmp ok


def make_bisect_images():
    import shutil
    import pefile
    src, dst = os.path.join(ROOT, 'work', 'rebased'), os.path.join(ROOT, BISECT_DIR)
    shutil.copytree(src, dst, dirs_exist_ok=True)
    path = os.path.join(dst, 'sw.dll')
    pe = pefile.PE(path, fast_load=True)
    data = bytearray(open(path, 'rb').read())
    for va, (old, new) in STACK_CHECK_PATCH.items():
        o = pe.get_offset_from_rva(va - pe.OPTIONAL_HEADER.ImageBase)
        if data[o:o + len(old)] not in (old, new):
            raise SystemExit('unexpected bytes at 0x%08X' % va)
        data[o:o + len(new)] = new
    pe.close()
    open(path, 'wb').write(bytes(data))


def input_desktop_is_default():
    """True when the desktop receiving input is the user's ("Default"), not
    the lock screen. LogonUI.exe running is NOT the test: it lingers during an
    active RDP session, and a check on it refused to run on an unlocked one."""
    import ctypes
    u = ctypes.windll.user32
    h = u.OpenInputDesktop(0, False, 0x0001)
    if not h:
        return False
    buf = ctypes.create_unicode_buffer(256)
    need = ctypes.c_ulong()
    u.GetUserObjectInformationW(h, 2, buf, ctypes.sizeof(buf), ctypes.byref(need))
    u.CloseDesktop(h)
    return buf.value == 'Default'


def log(msg):
    line = '%s  %s' % (time.strftime('%H:%M:%S'), msg)
    print(line, flush=True)
    with open(LOG, 'a') as f:
        f.write(line + '\n')


ROUND = 0
LIT_MIN = int(os.environ.get('LIT_MIN', 75))


def trial(native, seconds):
    """Lift with `native` spans as original code; True if the game frame is lit."""
    # A locked or disconnected desktop hangs DirectDraw surface locks (Bink,
    # the retail game too): every round after that is garbage. Stop instead.
    if not input_desktop_is_default():
        raise SystemExit('desktop is locked or disconnected: unlock it and rerun')
    spec = ','.join('0x%08X-0x%08X' % r for r in native)
    args = [sys.executable, 'run_lift.py', '--rebased', BISECT_DIR] + \
        (['--native-range', spec] if spec else [])
    subprocess.run(args, cwd=ROOT, check=True, stdout=subprocess.DEVNULL)
    # By full path, checked, and verified by the exe's timestamp: a bare
    # `cmd /c build.cmd` is not found from a subprocess, and for two whole
    # bisections every round quietly re-ran the previous binary.
    exe = os.path.join(ROOT, 'build', 'gunman.exe')
    before = os.path.getmtime(exe) if os.path.exists(exe) else 0
    b = subprocess.run(['cmd', '/c', os.path.join(ROOT, 'build.cmd')], cwd=ROOT,
                       capture_output=True, text=True)
    # (An identical repeat build does not relink; the exit code is the test.)
    if b.returncode or not os.path.exists(exe):
        raise RuntimeError('build failed or did not relink:\n' + b.stdout[-2000:] + b.stderr[-2000:])
    for attempt in (1, 2):
        out = subprocess.run(
            ['powershell', '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', 'tools/run.ps1',
             '-Seconds', str(seconds), '-ShotEvery', str(seconds // 3),
             '-Press', '0x1B@14 0x1B@24', '-Click', '110,189@32 85,182@44',
             '-Shot', 'work/bisect.png', '-Rebased', BISECT_DIR],
            cwd=ROOT, capture_output=True, text=True).stdout
        runlog = open(os.path.join(ROOT, 'work', 'run.log'), errors='replace').read()
        global ROUND
        ROUND += 1
        os.makedirs(os.path.join(ROOT, 'work', 'rounds'), exist_ok=True)
        with open(os.path.join(ROOT, 'work', 'rounds', '%s-%03d.log' % (time.strftime('%Y%m%d-%H%M%S'), ROUND)), 'w') as keep:
            keep.write('native: %s\n%s' % (spec, runlog))
        started = '[boot] gunman.dll' in runlog
        lit = [int(m) for m in re.findall(r'lit=(\d+)%', out)]
        crashed = any(k in runlog for k in ('[crash]', '[msgbox]', '[exit]'))   # Sys_Error is a message box
        # A verdict needs the whole timeline: a run that ended early has only
        # the menu sample, which is lit, and read as "fixed" once already.
        if started and len(lit) >= 3:
            break
        log('  (run ended early: started=%s samples=%s crash=%s -- %s)'
            % (started, lit, crashed, 'retrying' if attempt == 1 else 'counting as black'))
    # A full render measures 88-93%; every partial one so far 27-44%. With
    # one bug left the frame can draw but smear (74%): LIT_MIN lowers the bar.
    ok = started and not crashed and len(lit) >= 3 and lit[-1] >= LIT_MIN
    log('  native %-60s started=%s crash=%s lit=%s -> %s'
        % (spec[:60] or '(none)', started, crashed, lit, 'LIT' if ok else 'black'))
    return ok


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('stem')
    ap.add_argument('lo', type=lambda x: int(x, 0))
    ap.add_argument('hi', type=lambda x: int(x, 0))
    ap.add_argument('--seconds', type=int, default=90)
    a = ap.parse_args()
    make_bisect_images()
    cat = json.load(open(os.path.join(ROOT, 'analysis', a.stem + '.functions.json')))
    funcs = sorted(f['address'] for f in cat['functions'] if a.lo <= f['address'] < a.hi)
    # Start from ALL native (reliably lit) and prove halves clean by LIFTING
    # them back. A half whose lifting keeps the frame lit is clean and stays
    # lifted; one that breaks it holds a bug and is split again. Unlike
    # "find the half whose nativeness fixes it", this finds every bug when
    # there are several: with two, no single half fixes anything, and the old
    # search could only guess.
    log('searching %d functions of %s in 0x%08X-0x%08X' % (len(funcs), a.stem, a.lo, a.hi))
    if not trial([(a.lo, a.hi)], a.seconds):
        raise SystemExit('all native is not lit: nothing to search from')
    native, pending, found = [(a.lo, a.hi)], [(a.lo, a.hi)], []
    while pending:
        r = pending.pop()
        inside = [f for f in funcs if r[0] <= f < r[1]]
        if len(inside) <= 1:
            found.append(r)
            log('FOUND: 0x%08X-0x%08X  (%s)' % (r[0], r[1], ', '.join('sub_%08X' % f for f in inside)))
            continue
        mid = inside[len(inside) // 2]
        A, B = (r[0], mid), (mid, r[1])
        others = [x for x in native if x != r]
        if trial(others + [A], a.seconds):          # B lifted, still lit: B is clean
            native = others + [A]
            pending.append(A)
        elif trial(others + [B], a.seconds):        # A is clean
            native = others + [B]
            pending.append(B)
        else:                                       # a bug on each side
            log('  a bug in each half of 0x%08X-0x%08X' % r)
            native = others + [A, B]
            pending += [A, B]
    log('result: %s' % ', '.join('0x%08X-0x%08X' % r for r in found))


if __name__ == '__main__':
    main()
