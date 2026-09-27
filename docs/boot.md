# Boot to menu: what it took

Every wall between the PE entry point and the main menu, in the order the boot
hit them, with what the runtime printed. Most of these would cost the next
reader as much time as they cost us, so each one says **why** as well as what.

The boot sequence, as the original does it and as the recompilation now does
it:

```
vgui.dll  CRT init (DllMain)
gunman.exe CRT init -> MFC init -> WinMain
  registry: HKLM\Software\Aureal\A3D, HKCU\Software\Valve\Gunman\Settings
  LoadLibrary HL_Res.dll
  CD key check            (first run: a VGUI prompt)
  RAM check
  sierra.avi              (MCI, ~10 s)
  rewolf.bik              (Bink, 4,569 frames at 20 fps = 228 s)
  main menu               (gfx/shell, VGUI)
```

## Toolkit fixes (in pcrecomp or run_lift.py)

### A body that falls off its end skipped the shared epilogue

```
[crash] code 0xC0000005 at 0x6116C72E (read 0x00000010)
  in lifted sub_0A028BEE ...
  host pc ...\recomp_0022.c:19401
```

`ebx` was 0 straight after `call sub_0A028FA8`, a function that pushes and
pops `ebx`. MSVC shares one epilogue (`pop edi/esi/ebx; leave; ret`) between
two paths, and disasm32 catalogued it as its own function at `0x0A02909E`.
`generate.py` ended the body before it with `return; /* end of function */`,
so one path skipped the pops. Fixed upstream in
`pcrecomp/tools/lift/generate.py`: a body that runs off its end now tail-calls
the next address, the way the CPU falls through.

### Jump tables live in `.text`, between the arms

```
ITAIL: unresolved VA 0x00480C94 from 0x00480B80
```

`0x00480B80` is the CRT's `memcpy`. It dispatches through four
`jmp [reg*4 + table]` tables that MSVC placed *inside* the function. A linear
sweep decodes the table as instructions and loses sync, so the arm after it
never gets a label. `run_lift.py`'s `descend()` only decodes bytes it reached,
and reads a table's arms out of the table. Slot 0 of `memcpy`'s
`[eax*4+0x480BE0]` table is never used, and it overlaps the bytes of the `jmp`
itself (`0x9000480C`), so one bad leading slot is skipped.

### A jump to a catalogued address is not a tail call

```
ITAIL: unresolved VA 0x0048785A from 0x00488197
```

The CRT's `_input` (scanf) at `0x00487830` had three false entries inside it
(`0x487F78`, `0x488155`, `0x488197`). Treating a jump to them as a tail call
split the body until a loop's back-edge had nowhere to go. Now a jump counts
as a tail call only when its target is a **proven** entry: something `call`s
it, or it's the entry point, an export, an RTTI method or a vtable slot. A
jump to anything else is a branch. At worst that duplicates a tail-jumped
body into its caller, which is still correct code.

### The catalog's `end` is not an extent

vgui's `sub_0A02B71B` was cut at `0x0A02B742`, where a data-pointer seed had
planted an entry. Its `jne 0x0A02B749` then targeted a label that wasn't in
the body. `descend()` ignores the catalog's `end` and bounds a walk at 64 KB
only in case it starts in data.

### disasm32 does not seed exports

vgui.dll went from 68% to 93% byte coverage once its exports were seeds:
452 of its 1,179 exported methods are only ever called from another module.
`tools/seeds.py` merges exports, RTTI methods and vtable slots.

### pefile's `relocate_image` broke vgui's import table

With pefile 2024.8.26, `pe.relocate_image(base)` followed by `pe.write()`
left `vgui.dll` unparseable:
`Error parsing the import directory. Invalid Import data at RVA: 0x38c5c`.
`tools/rebase.py` applies the HIGHLOW fixups to the file bytes itself.

## Host fixes

### UAC virtualisation: the launcher's very first registry write

```
[native] RegCreateKeyExA (80000002 004CA994 ...) from sub_00421DFA -> 00000005
[native] ChangeDisplaySettingsA ...
[native] ExitProcess (00000000 ...)
```

`0x004CA994` is `Software\Aureal\A3D` under HKLM, and 5 is
`ERROR_ACCESS_DENIED`. The retail exe has no manifest, so Windows virtualises
its HKLM writes into `VirtualStore`. MSVC gives every exe an `asInvoker`
manifest, and that switches virtualisation off. The host links with
`/MANIFESTUAC:NO`, which makes it a legacy app the way the original is.

### The CD key is stored without dashes

The launcher reads `HKCU\Software\Valve\Gunman\Settings\Key`. Writing it as
printed on the case (`xxxx-xxxxx-xxxx`) gets "Your CD Key is invalid, please
reenter". The retail exe, given the same key at its prompt, stores
13 digits and no dashes. The recompiled check agreed with the retail one both
times, so this was a usage error, not a lift bug. Entering the key once at the
first-run prompt stores it correctly.

### The RAM check

```
Your system reported only -0.00K of physical memory,
Gunman Chronicle requires at least 16MB.
```

The retail exe shows exactly this on a modern machine too. At `0x00412596`
the launcher does `cmp dwTotalPhys, 0xF00000; jge`, a **signed** compare. With
more than 4 GB installed, Windows saturates `dwTotalPhys` at `0xFFFFFFFF`,
which reads as -1. The `GlobalMemoryStatus` shim clamps each field to 2 GB.
This is a compatibility fix for a 2000-era assumption, the same one the
original needs. It's not a recompilation fix.

### The intro movies are not in the Wise package

```
[native] mciSendStringA ... a0="open rewolf\media\sierra.avi type AVIVideo ..." -> 00000113
Could not open MCI file for playback: 275: Cannot find the specified file.
```

`SIERRA.AVI` and `REWOLF.BIK` sit next to `INSTALL.EXE` on the disc, and Setup
copies them into `rewolf\media`. E_WISE only sees what's inside the package.
`tools/install.py` copies them.

## Diagnostics worth keeping

- `--imports` logs every native call with its arguments, any argument that is
  a string, and the result. It found every host-side issue above.
- A crash prints the faulting generated-C `file:line` (dbghelp over the PDB),
  and every generated line carries its guest VA in a comment.
- `tools/disat.py <va>` disassembles any rebased module at a VA.
- `tools/run.ps1 -Native` runs the **retail** exe against the same install
  and registry, which is the ground truth to compare against. It showed the CD
  key and RAM behaviour were the original's, not ours.
