#!/usr/bin/env python3
"""Gunman Chronicles lift driver: every module the boot-to-menu path runs.

The main menu is not the engine's. WON-era GoldSrc draws its "shell" -- the
gfx/shell/ bitmaps, the New Game / Configuration buttons -- in the launcher,
gunman.exe, on top of VGUI. So booting to the menu needs gunman.exe and
vgui.dll lifted, and the engine (sw.dll / hw.dll) not at all until a map loads.

Each module is lifted from its *rebased* copy (tools/rebase.py), so the VAs
baked into the C are the ones the runtime maps it at. All modules share one
address space, one `sub_XXXXXXXX` namespace and one dispatch table.

Bodies come from descend() below (recursive descent, jump tables read);
the function lifter and chunk writer are the toolbox's `lift/generate.py`.

    py -3 tools/rebase.py
    py -3 ../tools/tools/disasm/disasm32.py work/rebased/<m> --seed-functions ... -o analysis/<m>.functions.json
    py -3 run_lift.py                      # -> src/recomp/gen/

Why descend() is shaped the way it is: docs/boot.md, "Toolkit fixes".
"""
import collections
import pefile
import json
import re
import os
import sys
import time

_HERE = os.path.dirname(os.path.abspath(__file__))
_TOOLS = os.path.join(_HERE, '..', 'tools', 'tools')
sys.path.insert(0, os.path.join(_TOOLS, 'lift'))
sys.path.insert(0, os.path.join(_TOOLS, 'pe'))

from capstone import Cs, CS_ARCH_X86, CS_MODE_32          # noqa: E402
from capstone.x86 import X86_OP_IMM, X86_OP_MEM, X86_OP_REG                        # noqa: E402
from generate import (LinearInstruction,                   # noqa: E402
                      lift_function_linear, write_chunk)
from lift32 import Lifter                                  # noqa: E402
from pe_analyze import analyze_pe, build_iat_map           # noqa: E402

OUT = os.path.join(_HERE, 'src', 'recomp', 'gen')

# (rebased image, catalog stem). The first is the process image.
MODULES = [
    ('work/rebased/gunman.exe', 'gunman'),
    ('work/rebased/vgui.dll', 'vgui'),
    ('work/rebased/sw.dll', 'sw'),              # engine, software renderer
    ('work/rebased/client.dll', 'client'),
    ('work/rebased/gunman.dll', 'server'),
]


_COND = {'je','jne','jz','jnz','ja','jae','jb','jbe','jg','jge','jl','jle',
         'js','jns','jo','jno','jp','jnp','jcxz','jecxz','loop','loope','loopne'}


def descend(md, code, cs, ce, start, entries, limit=0x10000, read32=None,
            indirect=None):
    """The instructions of the body at `start`, by recursive descent.

    Returns (instructions sorted by address, leaders) in the shape
    generate.lift_function_linear takes.

    This replaces the extent-walk-then-linear-sweep Force Commander uses, for
    one reason: jump tables. MSVC puts a switch's table (and the CRT memcpy's
    four of them) in .text between the arms, so a linear sweep decodes the
    table as instructions, loses sync, and the arm after it never gets a
    label -- memcpy's tail then ITAILed into 0x00480C94 and did nothing. Here
    only reached bytes are decoded, and `jmp [table + reg*4]` reads its arms
    out of the table.

    The rules otherwise match Force Commander's true_extent: fall through and
    follow direct branches; stop at ret/int3/hlt; a jump to another catalogued
    entry is a tail call, not a branch; `limit` bounds a walk that starts in
    data. The catalog's own `end` is not used: a data-pointer seed can plant a
    false entry mid-function (vgui's sub_0A02B71B was cut at 0x0A02B742).
    """
    hard = min(start + limit, ce)
    # Below the entry too: R_GenerateSpans (sw.dll 0x10091D01) branches back
    # to Lgs_trailing, which sits just before its label. Kept out of the body,
    # that `je` became an ITAIL to an address no function starts at, and the
    # span loop quit at the first edge with no leading surface.
    low = max(start - limit, cs)
    view = memoryview(code)
    byaddr, leaders, work = {}, {start}, [start]

    def branch(t):
        if t is not None and low <= t < hard and t not in entries - {start}:
            leaders.add(t)
            work.append(t)
            return True
        return False

    # Quake's entry vectors: `mov ebx, [ecx*4 + table]` picks a label, a store
    # parks it in a variable, and `jmp [variable]` goes there (the span
    # drawer's per-8-pixel tail, sw.dll 0x1008EC48). The labels are catalog
    # entries (the table seeds them), so a tail call to each nested one C call
    # per span segment; as local labels the jump is a switch. Either half can
    # be decoded first, so each one checks for the other.
    vectors, vjump = [], [False]
    # indirect (optional dict): 'targets' gets every local target of an
    # indirect jump that could be read (table arms, vector labels); 'unknown'
    # is set when one could not (`jmp eax`, a variable with no vector table).
    # generate.lift_function_linear labels only those targets when none is
    # unknown (see its indirect_targets).
    known, unknown = set(), [False]

    def vector_table(d):
        if read32 and read32(d) == 0:
            d += 4                          # slot 0 unused (the span drawer's is)
        while read32 and len(vectors) < 64:
            t = read32(d)
            if t is None or not (low <= t < hard):
                break
            vectors.append(t)
            d += 4

    def take_vectors():
        if vjump[0]:
            for t in vectors:
                known.add(t)
                if t not in leaders:
                    leaders.add(t)
                    work.append(t)

    while work:
        va = work.pop()
        if va in byaddr:
            continue
        # 4 KB at a time: capstone copies the buffer it is handed, and a 64 KB
        # window per work item made the whole lift 30x slower.
        nxt = None
        prev = None
        for ins in md.disasm(view[va - cs:min(va + 0x1000, hard) - cs], va):
            nxt = ins.address + ins.size
            if ins.address in byaddr:
                nxt = None
                break
            li = LinearInstruction(ins)
            byaddr[ins.address] = li
            m = ins.mnemonic
            t = None
            if ins.operands and ins.operands[0].type == X86_OP_IMM:
                t = ins.operands[0].imm & 0xFFFFFFFF
            if m in ('ret', 'retn', 'retf', 'iret', 'int3', 'hlt'):
                break
            if (m == 'mov' and len(ins.operands) == 2 and ins.operands[1].type == X86_OP_MEM
                    and ins.operands[1].mem.scale == 4 and ins.operands[1].mem.index
                    and not ins.operands[1].mem.base):
                vector_table(ins.operands[1].mem.disp & 0xFFFFFFFF)
                take_vectors()
            if m == 'jmp':
                if (t is None and ins.operands[0].type == X86_OP_MEM
                        and not ins.operands[0].mem.base and not ins.operands[0].mem.index):
                    # jmp [variable]: an import (its slot holds no code
                    # address in the file) is a tail call out, not local
                    v = read32(ins.operands[0].mem.disp & 0xFFFFFFFF) if read32 else None
                    if v is not None and cs <= v < ce:
                        vjump[0] = True
                        take_vectors()
                    elif v is None:
                        unknown[0] = True
                elif t is None and not (ins.operands[0].type == X86_OP_MEM
                                        and ins.operands[0].mem.scale == 4
                                        and ins.operands[0].mem.index):
                    unknown[0] = True               # jmp reg, or a form we can't read
                if t is None and ins.operands[0].type == X86_OP_MEM:
                    mem = ins.operands[0].mem
                    d = mem.disp & 0xFFFFFFFF
                    if mem.scale == 4 and mem.index and cs <= d < ce:
                        # Slot 0 may be dead: memcpy's `jmp [eax*4+0x480BE0]`
                        # only ever indexes 1..3, and slot 0 overlaps the
                        # bytes of the jmp itself. So one bad leading slot is
                        # skipped; after that the first bad one ends the table.
                        # `neg idx; jmp [idx*4 + table]` indexes DOWNWARD from
                        # the base: the CRT memmove's backward-copy tail
                        # (sw.dll 0x1009FB52) has its arms at and below
                        # 0x1009FC20 -- index 0 included: starting one slot
                        # down lost the arm for a count of 0, and once switches
                        # listed only known arms, memmove returned without
                        # copying and the CRT's %f formatter smashed its stack.
                        step = 4
                        if (prev is not None and prev.mnemonic == 'neg'
                                and prev.operands[0].type == X86_OP_REG
                                and prev.operands[0].reg == mem.index):
                            step = -4
                        skip = 1
                        while cs <= d and d + 4 <= ce:
                            arm = int.from_bytes(code[d - cs:d - cs + 4], 'little')
                            if branch(arm) or arm in leaders:
                                known.add(arm)
                                skip = 0
                            elif skip:
                                skip = 0
                            else:
                                break
                            d += step
                else:
                    branch(t)
                    # `push label; jmp func`: func returns to label
                    if (prev is not None and prev.mnemonic == 'push'
                            and prev.operands[0].type == X86_OP_IMM):
                        branch(prev.operands[0].imm & 0xFFFFFFFF)
                break
            if m in _COND:
                branch(t)
                leaders.add(ins.address + ins.size)
            prev = ins
            if ins.address + ins.size >= hard:
                nxt = None
                break
        else:
            if nxt is not None and nxt < hard:
                work.append(nxt)             # ran off the window, not the body
    if vjump[0] and not vectors:
        unknown[0] = True                   # jmp [variable] and no table seen
    if indirect is not None:
        indirect['targets'] = None if unknown[0] else known
    return [byaddr[a] for a in sorted(byaddr)], leaders


def code_patches(md, code, cs, ce):
    """Addresses inside .text that the module's own code stores to.

    The software renderer's assembly (Quake lineage) patches its inner loops:
    `mov al, [eax+0x12345678]` ships with a placeholder that a setup routine
    overwrites with the live colormap address (sw.dll, 13 such fields). Only
    absolute stores are looked for -- that is the only form the patchers use.
    """
    from capstone import CS_AC_WRITE
    md.skipdata = True
    out = set()
    for ins in md.disasm(code, cs):
        if ins.id == 0 or not ins.operands:
            continue
        op = ins.operands[0]
        if (op.type == X86_OP_MEM and op.access & CS_AC_WRITE
                and op.mem.base == 0 and op.mem.index == 0
                and cs <= (op.mem.disp & 0xFFFFFFFF) < ce):
            out.add(op.mem.disp & 0xFFFFFFFF)
    md.skipdata = False
    return out


# Host functions that take over a lifted one. Each is handed the lifted body
# (`void (*lifted)(void)`) and either calls it -- before, after or instead of
# its own work -- or does the job itself, popping the return address as the
# lifted `ret` would.
OVERRIDES = {
    # The launcher's windowed present: one BitBlt per row. src/runtime/present.c
    # draws the frame in one scaled blit instead (resizable window, F12 scaling
    # mode, F11 borderless fullscreen); the DirectDraw path stays lifted.
    0x0042BE70: 'present_override',
    # R_ViewChanged: Hor+ widescreen -- widen fov_x for aspects wider than 4:3
    # so the vertical view stays what 4:3 shows (present.c).
    0x1004FB90: 'fov_override',
    # D_DrawSpans16: bilinear-filtered textures (src/runtime/spans.c, F8).
    0x1008E6FC: 'spans_override',
    # Original-game bugs the recompile exposes (src/runtime/fixes.c):
    # Cvar_SetValue's 32-byte %f buffer, and LoadWeaponSprites leaving the
    # knife's and grenade's crosshair uninitialised.
    0x100223B0: 'cvar_setvalue_override',
    0x0B021DD0: 'load_weapon_sprites_override',
}


def apply_overrides(bodies):
    out = []
    for body, addr, name in bodies:
        fn = OVERRIDES.get(addr)
        if fn and body.startswith('void %s(void) {' % name):
            body = body.replace('void %s(void) {' % name, 'void %s_lifted(void) {' % name, 1)
            body += '\nvoid %s(void) { %s(%s_lifted); }\n' % (name, fn, name)
        out.append((body, addr, name))
    return out


# Static tables sized for the engine's maximum resolution (Quake's MAXWIDTH
# 1280 / MAXHEIGHT 1024). Each moves to RELOC_BASE with RELOC_GROW times the
# room: every displacement and immediate pointing into it is rewritten by the
# lifter, and the runtime copies the original contents over whenever sw.dll
# is mapped. Found by running wider modes and watching what they overran
# (docs/ingame.md, "Past 1280 wide").
RELOC_BASE, RELOC_GROW = 0x20000000, 4
RELOCS = [
    (0x102618E8, 0x1000),   # warp: per-row table        [MAXHEIGHT]
    (0x102628E8, 0x1000),   # warp: per-row table        [MAXHEIGHT]
    (0x102638E8, 0x1428),   # warp: per-column table     [MAXWIDTH + margin]
]


def reloc_map():
    """[(old, size, new)] and a lifter callback."""
    out, at = [], RELOC_BASE
    for old, size in RELOCS:
        out.append((old, size, at))
        at += (size * RELOC_GROW + 0xFFF) & ~0xFFF
    def fn(va):
        for old, size, new in out:
            if old <= va < old + size:
                return new + (va - old)
        return None
    return out, fn, at - RELOC_BASE


NONLOCAL_EXIT = re.compile(r'^\s*esp = MEM32\(', re.M)


def propagate_nonlocal_exits(bodies):
    """Let a non-local exit unwind through the C frames it skips.

    Quake-lineage assembly saves esp to a global on entry and leaves with
    `mov esp, [saved]; pop ...; ret`, discarding every frame above it in one
    go: R_ClipEdge (sw.dll 0x100915AC) recurses to clip an edge against the
    frustum, and R_EmitEdge's tail returns straight to the outermost caller.
    Lifted, each level is a real C call, so that exit returned from the
    innermost C function only and the outer levels carried on clipping with
    esp already popped past them -- the world never drew (docs/ingame.md).

    Any function that CALLS one that restores esp from memory records its
    entry esp, and after each such call returns at once if esp has risen
    above it: a skipped native frame would have been gone, so this one goes
    too. In ordinary code esp never rises above the entry, so it never fires.
    """
    exiters = {name for body, _, name in bodies if NONLOCAL_EXIT.search(body)}
    if not exiters:
        return bodies
    call = re.compile(r'(RECOMP_CALL\((%s)\);[^\n]*)' % '|'.join(sorted(exiters)))
    out, patched = [], 0
    for body, addr, name in bodies:
        if call.search(body):
            body = body.replace('RECOMP_ENTER(0x%08Xu);' % addr,
                                'RECOMP_ENTER(0x%08Xu);\n    uint32_t _entry_esp = esp;' % addr, 1)
            body = call.sub(r'\1 if (esp > _entry_esp) return;  /* non-local exit */', body)
            patched += 1
        out.append((body, addr, name))
    print('[*] non-local esp restores in %d functions; %d callers unwind through them'
          % (len(exiters), patched))
    return out


def load_module(path, stem):
    info = analyze_pe(os.path.join(_HERE, path))
    cs, ce = info.code_start, info.code_end
    cat = json.load(open(os.path.join(_HERE, 'analysis', stem + '.functions.json')))
    byaddr = {f['address']: f for f in cat['functions'] if cs <= f['address'] < ce}
    # Every vtable slot is an entry, including 8-byte adjustor thunks nothing
    # calls directly (see Force Commander's run_lift.py for the failure).
    seeds = os.path.join(_HERE, 'analysis', stem + '.seeds.json')
    seeded = {e['address'] for e in json.load(open(seeds))}         if os.path.exists(seeds) else set()
    # Proven entries: something CALLs it, the PE entry point, or a seed
    # (export, RTTI method, vtable slot). A catalog entry reached only by a
    # jump is not proof -- the CRT's _input has three such false entries, and
    # treating a jump to one as a tail call split the body until its loop's
    # back-edge had nowhere to go (ITAIL 0x0048785A).
    proven = {info.image_base + info.entry_point_rva} | seeded
    for f in cat['functions']:
        proven.update(f.get('calls_to', ()))
    if seeded:
        want = {a for a in seeded if cs <= a < ce and a not in byaddr}
        known = sorted(set(byaddr) | want)
        nxt = {a: (known[i + 1] if i + 1 < len(known) else ce)
               for i, a in enumerate(known)}
        for a in want:
            byaddr[a] = {'address': a, 'end': min(nxt[a], a + 0x100),
                         'entry_kind': 'start'}
        print('[*] %s: %d vtable slots injected' % (stem, len(want)))
    pe_data = open(os.path.join(_HERE, path), 'rb').read()
    text = [s for s in info.sections if s.name == '.text'][0]
    code = pe_data[text.raw_offset:
                   text.raw_offset + min(text.virtual_size, text.raw_size)]
    img = pefile.PE(os.path.join(_HERE, path), fast_load=True)
    mapped, base = img.get_memory_mapped_image(), img.OPTIONAL_HEADER.ImageBase

    def read32(va):
        o = va - base
        return int.from_bytes(mapped[o:o + 4], 'little') if 0 <= o <= len(mapped) - 4 else None
    info.read32 = read32
    return info, byaddr, code, proven


def parse_ranges(text):
    """'0x10090000-0x100A0000,0x...' -> [(lo, hi)]"""
    out = []
    for part in filter(None, (text or '').split(',')):
        lo, hi = part.split('-')
        out.append((int(lo, 0), int(hi, 0)))
    return out


def main():
    # --rebased DIR: lift from other rebased images (find_bad_lift.py's
    # patched copy); the runtime must be given the same directory.
    if '--rebased' in sys.argv:
        d = sys.argv[sys.argv.index('--rebased') + 1].replace('\\', '/').rstrip('/')
        MODULES[:] = [(p.replace('work/rebased', d, 1), st) for p, st in MODULES]
    # --native-range LO-HI[,LO-HI]: bisection. Every function whose entry is
    # in a range becomes a thunk that runs the ORIGINAL code natively, and the
    # runtime maps that module executable. If the symptom goes away, the bug
    # is in the range; halve it and repeat.
    # --stub-ret ADDR[,ADDR]: lift these as a bare `ret` (bisection builds only;
    # see find_bad_lift.py for why the engine's stack check needs it).
    stub_ret = set()
    if '--stub-ret' in sys.argv:
        stub_ret = {int(x, 0) for x in sys.argv[sys.argv.index('--stub-ret') + 1].split(',')}
    native = []
    if '--native-range' in sys.argv:
        native = parse_ranges(sys.argv[sys.argv.index('--native-range') + 1])
    md = Cs(CS_ARCH_X86, CS_MODE_32)
    md.detail = True
    os.makedirs(OUT, exist_ok=True)
    for fn in os.listdir(OUT):
        os.remove(os.path.join(OUT, fn))

    mods = [load_module(p, s) for p, s in MODULES]
    everything = set()
    for _, byaddr, _, _ in mods:
        everything |= set(byaddr)

    entries, chunk, idx, errors = [], [], 0, 0
    t0 = time.time()
    for (path, stem), (info, byaddr, code, proven) in zip(MODULES, mods):
        cs, ce = info.code_start, info.code_end
        # `lifted` spans every module, so a direct call across a module
        # boundary (there are none today) would still bind statically.
        patches = code_patches(md, code, cs, ce)
        if patches:
            print('[*] %s: %d self-modified code fields' % (stem, len(patches)))
        # precise_carry: the span stepper's adc/sbb read the carry of the add
        # before them (textures smeared along every span without it).
        lifter = Lifter(iat_map=build_iat_map(info), lifted=everything,
                        patch_sites=patches, precise_carry=True,
                        reloc=reloc_map()[1])
        ordered = sorted(byaddr)
        entry_set = proven & set(byaddr)
        for addr in ordered:
            name = 'sub_%08X' % addr
            if addr in stub_ret:
                chunk.append(('void %s(void) { g_esp += 4; }  /* --stub-ret */\n' % name,
                              addr, name))
                entries.append((addr, name))
                continue
            if any(lo <= addr < hi for lo, hi in native):
                chunk.append(('void %s(void) { recomp_native_call(0x%08Xu); }\n'
                              % (name, addr), addr, name))
                entries.append((addr, name))
                continue
            try:
                ind = {}
                insns, leaders = descend(md, code, cs, ce, addr, entry_set,
                                         read32=info.read32, indirect=ind)
                body = (lift_function_linear(lifter, name, insns, leaders, addr,
                                             indirect_targets=ind.get('targets'))
                        if insns else 'void %s(void) { }\n' % name)
            except Exception as e:                          # noqa: BLE001
                body = '/* ERROR %s: %s */\nvoid %s(void) {}\n' % (name, e, name)
                errors += 1
            chunk.append((body, addr, name))
            entries.append((addr, name))
        print('[*] %s: %d functions lifted (%d errors so far)'
              % (stem, len(byaddr), errors), flush=True)
    chunk = propagate_nonlocal_exits(chunk)
    chunk = apply_overrides(chunk)
    for k in range(0, len(chunk), 400):
        write_chunk(OUT, idx, chunk[k:k + 400])
        idx += 1

    with open(os.path.join(OUT, 'recomp_funcs.h'), 'w', newline='\n') as f:
        f.write('/* Gunman Chronicles - AUTO-GENERATED by run_lift.py */\n'
                '#pragma once\n#include <stdint.h>\n\n'
                '/* runtime.c: run the original code at va (--native-range) */\n'
                'void recomp_native_call(uint32_t va);\n\n')
        for va, fn in OVERRIDES.items():
            f.write('void %s(void (*lifted)(void));\nvoid sub_%08X_lifted(void);\n' % (fn, va))
        for a, n in entries:
            f.write('void %s(void);\n' % n)
    with open(os.path.join(OUT, 'recomp_dispatch.c'), 'w', newline='\n') as f:
        f.write('/* Gunman Chronicles - AUTO-GENERATED by run_lift.py */\n'
                '#include "recomp_types.h"\n#include "recomp_funcs.h"\n\n'
                'const recomp_dispatch_entry_t recomp_dispatch_table[] = {\n')
        for a, n in sorted(entries):
            f.write('    { 0x%08Xu, %s },\n' % (a, n))
        f.write('};\nconst uint32_t recomp_dispatch_count = %d;\n' % len(entries))
        moves, _, span = reloc_map()
        f.write('\n/* RELOCS: {old, size, new} -- runtime.c copies old to new on map */\n'
                'const uint32_t recomp_reloc_span = 0x%Xu;\n'
                'const uint32_t recomp_relocs[] = { %s0 };\n'
                % (span, ''.join('0x%08Xu, 0x%Xu, 0x%08Xu, ' % m for m in moves)))
        f.write('\n/* --native-range: modules holding these run executable */\n'
                'const uint32_t recomp_native_ranges[] = { %s0 };\n'
                % ''.join('0x%08Xu, 0x%08Xu, ' % r for r in native))
    if native:
        print('[*] native ranges: ' + ', '.join('0x%08X-0x%08X' % r for r in native))

    lines, unimpl = 0, collections.Counter()
    for fn in os.listdir(OUT):
        for line in open(os.path.join(OUT, fn), encoding='utf-8', errors='replace'):
            lines += 1
            if 'UNIMPLEMENTED:' in line:
                unimpl[line.split('UNIMPLEMENTED:')[1].split()[0]] += 1
    stats = {'functions': len(entries), 'errors': errors, 'files': idx,
             'lines': lines, 'unimplemented': dict(unimpl)}
    json.dump(stats, open(os.path.join(_HERE, 'analysis', 'lift_stats.json'), 'w'),
              indent=1)
    print('=' * 60)
    print('  lifted %d functions, %d errors, %d files, %s lines, %.0fs'
          % (len(entries), errors, idx, format(lines, ','), time.time() - t0))
    if unimpl:
        print('  UNIMPLEMENTED instructions: ' +
              ', '.join('%s x%d' % kv for kv in unimpl.most_common()))
    print('=' * 60)
    return 1 if errors else 0


def _selftest():
    """descend() on a hand-built memcpy-style table: dead slot 0, two arms."""
    md = Cs(CS_ARCH_X86, CS_MODE_32)
    md.detail = True
    b = 0x00401000
    # 00 jmp [eax*4+0x0040100C]  07 nop x5
    # 0C table: junk (dead slot 0), 0x18, 0x19
    # 18 ret                     19 xor eax,eax / ret
    code = bytearray([0xFF, 0x24, 0x85]) + (b + 0xC).to_bytes(4, 'little') + bytes([0x90] * 5)
    code += (0x9000480C).to_bytes(4, 'little') + (b + 0x18).to_bytes(4, 'little') \
        + (b + 0x19).to_bytes(4, 'little')
    code += bytes([0x90] * (0x18 - len(code))) + bytes([0xC3, 0x33, 0xC0, 0xC3])
    insns, leaders = descend(md, bytes(code), b, b + len(code), b, {b})
    got = [i.address - b for i in insns]
    assert got == [0x00, 0x18, 0x19, 0x1B], got          # table bytes never decoded
    assert {b + 0x18, b + 0x19} <= leaders, leaders
    # R_GenerateSpans' shape: entry at 0x10 branches BACK to 0x08, which does
    # `push 0x14; jmp 0x00` (a call returning to 0x14).
    #   00 ret   08 push 0x14 / jmp 0x00   10 test eax,eax / je 0x08   14 ret
    code = bytearray([0xC3] + [0x90] * 7) + bytes([0x68]) + (b + 0x14).to_bytes(4, 'little') \
        + bytes([0xEB, 0x100 - 0x0F])                     # jmp short 0x00
    code += bytes([0x90] * (0x10 - len(code))) + bytes([0x85, 0xC0, 0x74, 0x100 - 0x0C, 0xC3])
    insns, leaders = descend(md, bytes(code), b, b + len(code), b + 0x10, {b, b + 0x10})
    got = [i.address - b for i in insns]
    assert got == [0x08, 0x0D, 0x10, 0x12, 0x14], got
    assert {b + 0x08, b + 0x14} <= leaders, leaders
    lifter = Lifter(iat_map={}, lifted={b, b + 0x10})
    c = lift_function_linear(lifter, 'sub_t', insns, leaders, b + 0x10)
    assert c.index('goto L_%08X;' % (b + 0x10)) < c.index('L_%08X:' % (b + 0x08)), c
    assert 'RECOMP_CALL(sub_%08X); RECOMP_FLAGS_IN(); goto L_%08X;' % (b, b + 0x14) in c, c
    assert 'RECOMP_ITAIL(0x%08Xu)' % (b + 0x08) not in c, c
    print('run_lift.py self-test OK')


if __name__ == '__main__':
    if '--selftest' in sys.argv:
        sys.exit(_selftest())
    sys.exit(main())
