#!/usr/bin/env python3
"""Install Gunman Chronicles from your own disc into game/, without running Setup.

    py -3 tools/install.py <disc root>        # e.g. D:\\ or a mounted ISO

The retail installer is a Wise package (REWOLF/INSTALL.EXE); tools/unwise.py
unpacks its %MAINDIR% tree, which is exactly what Setup puts in Program Files.
Two files are NOT in the package: the Sierra and Rewolf intro movies sit
beside it on the disc and Setup copies them across, so this does too. Without
sierra.avi the launcher's first act after the RAM check is an MCI "Cannot find
the specified file" dialog.

This used to call E_WISE (Universal Extractor), which renames files that the
package lists twice -- and so left rewolf.ico, the general's
gen_mayan4_1.wav and finaldoor_gs.wav out under their real names.
"""
import os
import shutil
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, 'tools'))
from unwise import unwise  # noqa: E402


def main(disc):
    src = os.path.join(disc, 'REWOLF')
    game = os.path.join(ROOT, 'game')
    installer = os.path.join(src, 'INSTALL.EXE')
    if not os.path.exists(installer):
        sys.exit('no REWOLF\\INSTALL.EXE under %s -- is that the Gunman Chronicles disc?' % disc)
    print('unpacking %s (about a minute)...' % installer, flush=True)
    streams, files = unwise(installer, game)
    media = os.path.join(game, 'rewolf', 'media')
    os.makedirs(media, exist_ok=True)
    for disc_name, name in (('SIERRA.AVI', 'sierra.avi'), ('REWOLF.BIK', 'rewolf.bik')):
        shutil.copy2(os.path.join(src, disc_name), os.path.join(media, name))
    print('installed %d files to %s' % (files + 2, game))


if __name__ == '__main__':
    if len(sys.argv) != 2:
        sys.exit(__doc__)
    main(sys.argv[1])
