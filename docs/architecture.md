# Architecture

What runs, what owns what, and how a call gets from the lifted game to Windows
and back. The code is in `run_lift.py`, `tools/` and `src/runtime/`.

## The binaries, and which ones the menu needs

Gunman Chronicles is a WON-era GoldSrc game. It ships as:

| Binary | Role | Needed for the menu? |
|---|---|---|
| `gunman.exe` | Launcher. Owns the window, the intro movies, and the **main menu** (the "shell": `gfx/shell/*.bmp`, drawn with VGUI on GDI) | yes: lifted |
| `vgui.dll` | Valve's GUI toolkit, used by the launcher and the engine | yes: lifted |
| `sw.dll` / `hw.dll` | The engine: software renderer / OpenGL | no, loaded on *New game* |
| `rewolf/cl_dlls/client.dll` | Client game code (HUD, prediction) | no, loaded by the engine |
| `rewolf/dlls/gunman.dll` | Server game code (entities, AI, weapons) | no, loaded when a map starts |
| `binkw32.dll`, `WONAuth.dll`, `WONCrypt.dll`, `hl_res.dll` | Middleware: Bink video, WON auth, launcher resources | called natively, not lifted |

The key fact is that the menu belongs to the launcher, not the engine. Earlier
plans for this repo assumed the opposite: recompile only the mod DLLs and borrow
an engine. Booting to the menu takes two lifted modules and zero engine code.

All the GoldSrc DLLs are linked at `0x10000000`. A static recompilation bakes
every absolute address into the C, so `tools/rebase.py` applies each DLL's
relocations once, up front, to a fixed base of its own:

| Module | Base |
|---|---|
| `gunman.exe` | `0x00400000` (no `.reloc`) |
| `vgui.dll` | `0x0A000000` |
| `client.dll` | `0x0B000000` |
| `sw.dll` | `0x10000000` |

That table lives in three places that have to agree: `tools/rebase.py`,
`run_lift.py` (`MODULES`) and `src/runtime/modules.c`.

## Pipeline

```
game/ (your install)
  └─ tools/rebase.py ──────────► work/rebased/*.exe|dll    (fixed bases)
       └─ pcrecomp cpp/rtti.py, cpp/vtable_scan.py, tools/seeds.py
            └─ pcrecomp disasm/disasm32.py --seed-functions ──► analysis/<m>.functions.json
                 └─ run_lift.py ──► src/recomp/gen/*.c      (pcrecomp lift32 + generate.py)
                      └─ CMake (MSVC x86) ──► build/gunman.exe
```

Nothing under `work/`, `analysis/` or `src/recomp/gen/` is committed. It is
all derived from the retail binaries.

`run_lift.py` owns one piece of logic of its own: `descend()`, which decides
what instructions belong to a function body. It replaces the extent walk plus
linear sweep that Force Commander uses, for reasons that are in
[boot.md](boot.md): jump tables, false catalog entries, shared epilogues.

## The host: 32-bit, on purpose

Force Commander's host is 64-bit, which means every Win32 struct the game
builds has to be marshalled, and every import needs a hand-written body. This
host is **32-bit**, so the lifted code and Windows share one address space. A
`WNDCLASSA` the game fills in is already the struct `RegisterClassA` expects.
That changes the three boundaries:

### Guest → Windows: `native_bridge()` (runtime.c)

At load, `link_iat()` fills every IAT slot with the **real** export address
(`LoadLibraryA` + `GetProcAddress`). Imports from another lifted module get
that module's export VA, and a short list of hand shims (`shims.c`) gets a
synthetic address from a reserved page.

When lifted code does `call [iat]`, `RECOMP_ICALL` looks the address up. A VA
outside every guest module goes to `native_bridge`, which:

1. copies 24 argument slots from the guest stack to the host stack,
2. loads `ecx` (thiscall/COM `this`) and calls the real function,
3. measures how far the callee moved `esp`. **That is the purge count.** No
   argc table is needed, and stdcall, cdecl, thiscall and COM methods all come
   out right,
4. writes `eax`/`edx` back and pops the guest frame by the measured amount.

COM works for free too. `DirectDrawCreate` returns a real object, and a call
through its vtable is just another native address.

### Windows → guest: DEP as the trampoline

`map_module()` maps each image's code **non-executable**. When Windows calls
a guest function pointer (a WndProc, an MFC CBT hook, a thread start), the CPU
faults on the old bytes. The VEH checks that the faulting PC is a lifted entry
and moves `EIP` to `cb_tramp`, which:

1. copies the native caller's arguments onto the guest stack,
2. runs the lifted function,
3. returns to the native caller with a variable `ret n`, where n is whatever
   the guest callee popped.

No callback is registered anywhere, and there is no list of APIs that take
function pointers. This is why `/NXCOMPAT` in `CMakeLists.txt` is
load-bearing.

### Threads: one machine lock

The lifted code keeps its registers in globals (`recomp32`'s model). The
launcher runs a CD-audio thread and Bink runs its own threads, so a thread
must own the register file while it executes lifted code. `mach_enter()` and
`mach_leave()` save and load it per thread, and every native call releases it,
so a thread blocked in `GetMessageA` doesn't stall the others. This is Force
Commander's `shims_impl.c` pattern. A guest thread gets its own 1 MB guest
stack and fake TIB on first entry.

Lifted code reads `fs:[n]` from a **fake TIB** (`make_tib`), never the real
TEB. That way a guest SEH frame never ends up on a chain Windows will walk.

## Hand shims (shims.c)

Everything else passes straight through. These don't, because the guest is a
mapped image rather than a module Windows loaded:

| Import | Why |
|---|---|
| `GetModuleHandleA`, `GetModuleFileNameA`, `GetCommandLineA` | The guest is `game\gunman.exe` at `0x00400000`, not the host exe |
| `LoadLibraryA`, `GetProcAddress`, `FreeLibrary` | A lifted module is mapped and attached, not loaded. Loading a not-yet-lifted one (`sw.dll`) reports and fails cleanly |
| `FindResourceA`, `LoadResource`, `SizeofResource`, `LoadIconA`, `LoadCursorA`, `LoadBitmapA`, `LoadStringA` | `0x00400000` becomes the exe opened as a datafile, since that's where the resources are |
| `SetUnhandledExceptionFilter` | The runtime's VEH reports crashes. A guest filter would run mid-crash |
| `GlobalMemoryStatus` | Clamped to 2 GB. See [boot.md](boot.md#the-ram-check) |

## What is *not* recompiled

`binkw32.dll`, `WONAuth.dll`, `WONCrypt.dll` and the system DLLs run as the
real native code, called through the bridge. Bink and WON are third-party
middleware, not the game. `hl_res.dll` is resource-only.
