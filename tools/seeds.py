#!/usr/bin/env python3
"""Merge every proven function entry for one module into analysis/<stem>.seeds.json.

Three sources, all of which are entries the branch scan cannot see: RTTI
virtual methods, vtable slots found without RTTI, and exports. The exports
matter most for vgui.dll -- 452 of its 1,179 exported methods are only ever
reached from *another* module, so disasm32 on its own never finds them.

    py -3 tools/seeds.py work/rebased/vgui.dll vgui
"""
import json
import os
import sys
import pefile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def main(image, stem):
    a = os.path.join(ROOT, 'analysis', stem)
    seeds = {}
    for f in (a + '.rtti_seeds.json', a + '.vt_seeds.json'):
        if os.path.exists(f):
            for e in json.load(open(f)):
                seeds[e['address']] = e
    pe = pefile.PE(image)
    base = pe.OPTIONAL_HEADER.ImageBase
    text = next(s for s in pe.sections if s.Name.startswith(b'.text'))
    lo, hi = base + text.VirtualAddress, base + text.VirtualAddress + text.Misc_VirtualSize
    for e in getattr(pe, 'DIRECTORY_ENTRY_EXPORT', None).symbols \
            if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT') else ():
        va = base + e.address
        if lo <= va < hi:
            seeds.setdefault(va, {'address': va, 'address_hex': '0x%08X' % va,
                                  'note': 'export %s' % (e.name or b'').decode()})
    json.dump(sorted(seeds.values(), key=lambda e: e['address']),
              open(a + '.seeds.json', 'w'), indent=0)
    print('%s: %d seeds' % (stem, len(seeds)))


if __name__ == '__main__':
    main(*sys.argv[1:3])
