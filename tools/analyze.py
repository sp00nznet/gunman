#!/usr/bin/env python3
"""Rebase, seed and disassemble every lifted module: game/ -> analysis/.

    py -3 tools/analyze.py [stem ...]     # default: every module

Runs, per module: pcrecomp cpp/rtti.py and cpp/vtable_scan.py (proven method
entries), tools/seeds.py (those plus exports), then disasm/disasm32.py seeded
with the lot. About ten minutes, nearly all of it disasm32 on gunman.exe.

pcrecomp is expected beside this repo (../tools), or at $PCRECOMP.
"""
import os
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PCRECOMP = os.environ.get('PCRECOMP', os.path.join(ROOT, '..', 'tools'))
T = os.path.join(PCRECOMP, 'tools')

# (rebased image, stem) -- the same list as run_lift.py's MODULES.
MODULES = [('work/rebased/gunman.exe', 'gunman'), ('work/rebased/vgui.dll', 'vgui'),
           ('work/rebased/sw.dll', 'sw'), ('work/rebased/client.dll', 'client'),
           ('work/rebased/gunman.dll', 'server')]


def run(*args):
    print('>', ' '.join(os.path.relpath(a, ROOT) if os.path.isabs(a) else a for a in args))
    subprocess.run([sys.executable, *args], cwd=ROOT, check=True)


def main():
    if not os.path.isdir(T):
        sys.exit('pcrecomp not found at %s (clone it there or set PCRECOMP)' % PCRECOMP)
    os.makedirs(os.path.join(ROOT, 'analysis'), exist_ok=True)
    only = set(sys.argv[1:])          # e.g. `analyze.py sw client` -- default all
    run('tools/rebase.py')
    for image, stem in MODULES:
        if only and stem not in only:
            continue
        a = 'analysis/' + stem
        run(os.path.join(T, 'cpp', 'rtti.py'), image, '-o', a + '.rtti.json',
            '--seeds', a + '.rtti_seeds.json')
        run(os.path.join(T, 'cpp', 'vtable_scan.py'), image, '--seeds', a + '.vt_seeds.json',
            '-o', a + '.vtables.json')
        run('tools/seeds.py', image, stem)
        run(os.path.join(T, 'disasm', 'disasm32.py'), image,
            '--seed-functions', a + '.seeds.json', '-o', a + '.functions.json')


if __name__ == '__main__':
    main()
