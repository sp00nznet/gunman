#!/usr/bin/env python3
"""Install Gunman Chronicles from your own disc into game/, without running Setup.

    py -3 tools/install.py <disc root>        # e.g. D:\\ or an extracted ISO

The retail installer is a Wise package (REWOLF/INSTALL.EXE). E_WISE unpacks it
and writes a batch file that renames its numbered blobs into the install tree;
that tree is exactly what Setup would have put in Program Files. Two files are
NOT in the package: the Sierra and Rewolf intro movies sit beside it on the
disc and Setup copies them across, so this does too. Without sierra.avi the
launcher's first act after the RAM check is an MCI "Cannot find the specified
file" dialog.

E_WISE ships with Universal Extractor; point E_WISE at it if it is elsewhere.
"""
import os
import shutil
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
E_WISE = os.environ.get('E_WISE', r'C:\Windows\SysWOW64\UniExtract\bin\E_WISE_W.EXE')


def main(disc):
    src = os.path.join(disc, 'REWOLF')
    game = os.path.join(ROOT, 'game')
    if not os.path.exists(os.path.join(src, 'INSTALL.EXE')):
        sys.exit('no REWOLF\\INSTALL.EXE under %s' % disc)
    if not os.path.exists(E_WISE):
        sys.exit('E_WISE not found at %s (set E_WISE=...)' % E_WISE)
    with tempfile.TemporaryDirectory() as tmp:
        subprocess.run([E_WISE, os.path.join(src, 'INSTALL.EXE'), tmp], check=True,
                       stdout=subprocess.DEVNULL)
        subprocess.run(['cmd', '/c', '00000000.BAT'], cwd=tmp, check=True,
                       stdout=subprocess.DEVNULL)
        os.makedirs(game, exist_ok=True)
        shutil.copytree(os.path.join(tmp, 'MAINDIR'), game, dirs_exist_ok=True)
    media = os.path.join(game, 'rewolf', 'media')
    for disc_name, name in (('SIERRA.AVI', 'sierra.avi'), ('REWOLF.BIK', 'rewolf.bik')):
        shutil.copy2(os.path.join(src, disc_name), os.path.join(media, name))
    print('installed to %s' % game)


if __name__ == '__main__':
    if len(sys.argv) != 2:
        sys.exit(__doc__)
    main(sys.argv[1])
