# Changelog

All notable changes to this project. Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/);
versions follow [SemVer](https://semver.org/).

## [Unreleased]

### Added
- Relift on the current pcrecomp toolchain: `gunman.exe` and `vgui.dll` lifted
  whole, 9,318 functions, 0 lift errors (`run_lift.py`).
- 32-bit host runtime (`src/runtime/`): a native bridge that measures the
  callee's stack purge instead of tabulating it, DEP-driven callbacks from
  Windows into lifted code, a per-thread machine lock, a fake TIB.
  See docs/architecture.md.
- **Boots to the main menu** on its own: CRT, MFC, registry, CD-key prompt,
  RAM check, Sierra AVI, Rewolf Bink intro, shell menu.
- `tools/install.py` (install from your disc via E_WISE, plus the intro movies
  Setup copies), `tools/rebase.py`, `tools/seeds.py`, `tools/analyze.py`,
  `tools/run.ps1` (bounded run + window screenshot, `-Native` for the retail
  exe), `tools/disat.py`, `build.cmd`.
- `--imports` call trace with string arguments; crash reports name the
  generated-C line.
- docs/architecture.md, docs/boot.md, screenshots.
- MIT LICENSE, with a scope section.
- **In game**: New game → Medium loads the engine, client and server DLLs
  and the first map renders. All five modules lifted (`gunman.exe`,
  `vgui.dll`, `sw.dll`, `client.dll`, `gunman.dll`): 21,990 functions, 0 lift
  errors. See docs/ingame.md.
- **Playable**: an 81-minute playthrough, from the opening on the ship into
  the third mission, with every game module recompiled and the engine as its
  original code (`--native sw.dll`). README gets its screenshots and hero GIF.
- The loader emulates `FreeLibrary`/`LoadLibrary` properly: reference counts,
  `DLL_PROCESS_DETACH`, and a fresh image on reload. The launcher changes video
  mode by unloading and reloading the engine, which used to end the game.
- Self-modifying code support: `run_lift.py` finds a module's stores into its
  own `.text` and lifts those fields as memory reads (13 in `sw.dll`).
- Bisection tooling: `--native <module>`, `run_lift.py --native-range`,
  `tools/find_bad_lift.py`; plus `--pageheap`, `--watchdog`, `--import-stats`,
  `--trace-import`, `--callbacks`, `--grab`.
- Scripted input for unattended runs: `--press VK@S`, `--click X,Y@S` with a
  virtual cursor; the real mouse, keyboard and focus are never touched.
- `tools/run.ps1 -ShotEvery N` (lit/black timeline), `-Native` (the retail
  exe as reference), `tools/iterate.ps1`.
- **The engine renders fully recompiled**: all 21,990 functions, textured, and
  a side-by-side screenshot matches `--native sw.dll`. See docs/ingame.md.
- **Eye candy**. The presenter runs on the GPU (`src/runtime/present_d3d.c`,
  Direct3D 11; GDI remains the fallback, `--gdi`): the launcher's 16-bit DIB
  goes straight into a texture and a shader scales it -- sharp-bilinear (the
  default: crisp texels without shimmer at 3x on a 4K screen), smooth, a CRT
  look (scanlines and an aperture grille, faded out below 3x where they would
  alias), nearest and integer (F12, `--scale`), plus a vivid colour look (F9,
  `--look`).
- **Filtered textures** (`src/runtime/spans.c`, F8, `--filter`): our own span
  drawer in place of the engine's D_DrawSpans16 -- Quake's C span loop over
  the same globals, blending the four nearest texels in packed 5-6-5. On by
  default; it is also faster than the recompiled assembly it replaces (a
  median 61 fps against 42 at 1280x720).
- Playtest fixes: the Hor+ FOV hid the view model (Quake's
  `r_fov_greater_than_90`, now decided from the player's own FOV); and the
  CRT memmove's downward jump table lost its index-0 arm, so once switches
  listed only known targets `memmove` could return without copying -- the
  crash at the rust5a drop, inside the `%f` formatter. `Cvar_SetValue` now
  logs and clamps absurd values instead of overflowing its 32-byte buffer.
- The knife and grenade drew a random crosshair, a different one after every
  load: the client's LoadWeaponSprites (the HL SDK's) returns early for a
  weapon whose sprite list is empty without clearing the crosshair handles,
  which held stack garbage. `src/runtime/fixes.c` clears them first; original
  game bugs the recompile exposes live there.
- README: a new hero GIF and screenshots from a fully recompiled playthrough
  in 1280x720 widescreen.
- **Widescreen**: 1024x576, 1280x720 and 1280x800 join the video modes
  (`--modes`, `--modes original`), and the view is Hor+: R_ViewChanged gets a
  widened `fov_x` so the vertical view is what 4:3 shows (`--fov-original`
  for the engine's own). The engine's span tables stop at 1280 pixels wide.
- **Our own presenter** (`src/runtime/present.c`), in place of the launcher's
  windowed copy, which BitBlt-ed the frame one row at a time (960 GDI calls a
  frame at 1280x960). The window is resizable and maximizable, the frame is
  letterboxed to its aspect; F11 or Alt+Enter toggles borderless fullscreen,
  F12 cycles smooth, sharp and integer scaling (`--scale`, `--fullscreen`,
  `--no-present` for the original). `run_lift.py` gains `OVERRIDES`: a host
  function can take over a lifted one and fall back to it.
- **Performance**, measured with the new `--fps` (the engine's own
  `r_framecount`) and `--profile N` (a 1 ms sampling profiler over the running
  lifted function): from 10-12 fps to the game's 72 fps cap at 640x480, within
  a few fps of the engine as original code.
  - Generated C builds at `/O2` (`GEN_OPT`; it was `/Od`, in a Debug tree).
  - pcrecomp `RECOMP_LOCAL_REGS`: lifted bodies keep the registers in locals
    (written back around calls and returns) so the optimiser can hold them in
    host registers; `RECOMP_FLAT_MEMORY` drops the per-access base.
  - `descend()` reports every local target of a body's indirect jumps
    (jump-table arms, and Quake's entry-vector labels `jmp [variable]` picks
    from a table), and `generate.py` labels only those instead of every
    instruction: 1,547 of 1,630 sampled bodies with a `switch` now optimise.
  - A hit cache in front of the dispatch lookup.
- Scripted runs: 640x480 by default (`tools/run.ps1 -GameArgs`), `SetCapture`
  is a no-op so the window can be moved and minimized, `-Build DIR` picks the
  build tree, `build.cmd` takes `BUILD_DIR`/`BUILD_TYPE`.
- `tools/treewalk.py`: finds the callee under a function whose original code
  fixes the frame (a native function takes its whole call tree with it).

### Changed
- The root CMake project is now the recompilation host. The old Half-Life SDK
  rebuild of the game DLLs is no longer built from here.
- README rewritten to the house layout.
- `build\gunman.exe game` runs fully recompiled; `--native sw.dll` is the
  fallback.

### Fixed
- pcrecomp `lift32`: `cmp; inc; jae` -- after `inc`/`dec` the carry is the
  preserved one (`_cf`), not derived from the `inc`. Corrupted MSVC 6's
  small-block heap in every module linking the CRT.
- pcrecomp `lift32`: `bt; jae` was inverted; memory `bt/bts/btr/btc` with a
  register offset now address the bit string; `bts/btr/btc` and `lock`-prefixed
  instructions lift; `fist/fistp` round by the x87 control word.
- pcrecomp `lift32`: patched-immediate support applies on every read and to
  displacements, not once per instruction.
- `descend()`: jump tables indexed downward (`neg idx; jmp [idx*4+t]`).
- Native bridge: float results cross the lifted/native boundary in both
  directions.
- pcrecomp `lift/generate.py`: a body that runs off its end now falls through
  to the next address instead of returning (upstream change).
- The engine's black frame, eight lifter bugs (docs/ingame.md has the table),
  each with a difftest case:
  - `sahf` was a no-op and `fprem` left C2 stale (server `fmod` hung);
    `fxam` and `xlatb` were unimplemented (server angle-wrap hung).
  - `frndint` truncated, so `floor`/`ceil` did (`D_SCAlloc: bad cache size 0`).
  - R_ClipEdge's `mov esp, [saved]` exit now unwinds the lifted callers too
    (`run_lift.py`).
  - `descend()` follows branches to code below a function's entry, and
    `push label; jmp func` lifts as a call returning to `label`. That resolves
    413 of 414 branch targets that had no lifted function behind them.
  - Flags survive `ret`: the CRT's `sin`/`cos` read a helper's ZF.
  - `fld`/`fstp xword` are real 80-bit conversions (they pushed 0.0 and
    dropped the value), and `fsin`/`fcos`/`fsincos`/`fptan` clear C2.
  - `adc`/`sbb` take the carry of the `add`/`sub` before them (the new
    `precise_carry` Lifter option, on for Gunman): textures smeared along
    every span.
- `find_bad_lift.py` keeps every round's log (they were overwritten per run),
  and `LIT_MIN` lowers the "lit" bar for a frame that draws but smears.

### Removed
- Decompiler output and per-function symbol lists (`disasm/`) from the tree.
  They are derived from the retail binaries.
- Local copies of the classifiers and Ghidra scripts, now in pcrecomp.
- docs/TECHNICAL_PLAN.md, superseded by docs/architecture.md.
