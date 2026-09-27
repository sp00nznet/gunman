#!/usr/bin/env python3
"""Rebase every module the menu path loads to its own fixed VA.

Every GoldSrc DLL is linked at 0x10000000, and the real loader relocates all
but one of them at run time. A static recompilation cannot: the lifted code has
every absolute address baked in as a constant. So the relocation happens here,
once, before disassembly, and the runtime maps each rebased copy at exactly the
base it was lifted for (src/runtime/modules.h holds the same table).

    py -3 tools/rebase.py            # game/ -> work/rebased/
"""
import os
import sys
import pefile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)

# name in game/ -> base. Keep in step with src/runtime/modules.h.
MODULES = {
    'gunman.exe':                0x00400000,  # launcher, fixed, no .reloc
    'sw.dll':                    0x10000000,  # software engine, its own base
    'vgui.dll':                  0x0A000000,
    'rewolf/cl_dlls/client.dll': 0x0B000000,
    'rewolf/dlls/gunman.dll':    0x0C000000,  # server game DLL
}


def rebase(path, base):
    """The file's bytes with every HIGHLOW fixup applied for `base`.

    Done by hand rather than with pefile's relocate_image(), which also rewrites
    the import thunks it parsed and left vgui.dll with an unreadable import
    table (pefile 2024.8.26).
    """
    pe = pefile.PE(path)
    data = bytearray(pe.__data__)
    delta = (base - pe.OPTIONAL_HEADER.ImageBase) & 0xFFFFFFFF
    if delta:
        for block in getattr(pe, 'DIRECTORY_ENTRY_BASERELOC', ()):
            for e in block.entries:
                if e.type == 3:                      # IMAGE_REL_BASED_HIGHLOW
                    off = pe.get_offset_from_rva(e.rva)
                    v = int.from_bytes(data[off:off + 4], 'little')
                    data[off:off + 4] = ((v + delta) & 0xFFFFFFFF).to_bytes(4, 'little')
                elif e.type != 0:                    # ABSOLUTE is padding
                    raise ValueError('%s: relocation type %d' % (path, e.type))
        off = pe.OPTIONAL_HEADER.get_file_offset() + 28   # ImageBase
        data[off:off + 4] = base.to_bytes(4, 'little')
    return bytes(data)


def main():
    out = os.path.join(ROOT, 'work', 'rebased')
    os.makedirs(out, exist_ok=True)
    for name, base in MODULES.items():
        dst = os.path.join(out, os.path.basename(name))
        with open(dst, 'wb') as f:
            f.write(rebase(os.path.join(ROOT, 'game', name), base))
        print(f'{name:28} -> {base:#010x}  {dst}')


if __name__ == '__main__':
    sys.exit(main())
