# Menu to in-game: what it took

The second leg of the boot: *New game* → *Medium* → the engine loads → the
first map renders. [boot.md](boot.md) covers entry point → menu. Everything
here was found by running the game, and each entry has the output that showed it.

```
New game                -> launcher: difficulty page
Medium                  -> launcher: LoadLibraryA("sw.dll"), Sys_EngineAPI
sw.dll (engine)         -> filesystem, gfx.wad, decals.wad, config.cfg
                        -> LoadLibrary client.dll, gunman.dll; maps/city1a.bsp
first frame             -> the opening room on the ship
```

All five modules are now lifted: `gunman.exe`, `vgui.dll`, `sw.dll`,
`client.dll`, `gunman.dll`. That's 21,990 functions with 0 lift errors.

## The tools that found the bugs

Without these, each of the bugs below would have been a day of guessing.

| Flag | What it answers |
|---|---|
| `--native M` | Is the bug in module M's lift? M runs as its **original** machine code. That works because the host is 32-bit and M sits at its real address. |
| `run_lift.py --native-range LO-HI` | Which functions? Functions in the range become thunks to the original code. `tools/find_bad_lift.py` automates the halving. |
| `tools/treewalk.py F` | Which callee of F? F stays lifted while its callees run as original code, halved, one level at a time. |
| `--pageheap` | Who corrupted the heap? Each guest heap block sits flush against a read-only guard page. |
| `--watchdog N` | What is it doing? Prints the running lifted function and indirect-call rate. |
| `--import-stats`, `--trace-import NAME@S` | What does it ask Windows for, and how often? Counting instead of printing keeps the timing intact. |
| `--press`, `--click` | Scripted input with a virtual cursor. The real keyboard and mouse are never touched. |
| `tools/run.ps1 -ShotEvery N` | A lit/black timeline. One screenshot can't tell "renders nothing" from "caught a dark moment". |

## Bugs, in the order the game hit them

### The engine claims 0x10000000 too late

```
[loader] VirtualAlloc fixed @ 0x10000000 failed (link host at a high base)
```

`sw.dll`'s base is also the preferred base of the native `WONAuth.dll`.
Whichever loads first gets it. The runtime now maps **every** lifted module at
startup and only links and attaches each one when the game `LoadLibrary`s it.

### Scripted clicks went to the wrong window, at the wrong position

VGUI takes the pointer position from `GetCursorPos`, not from the mouse
message. The launcher's menu items are owner-drawn **child** buttons. So a
click posted to the frame, with the real cursor elsewhere, did nothing.
`--click` now keeps a virtual cursor (`GetCursorPos`, `SetCursorPos`,
`GetAsyncKeyState(VK_LBUTTON)`) and posts to the deepest child under the
point, as Windows would route a real click.

### Self-modifying code in the software renderer

```
[watchdog]    50s  in sub_10091D01  +0 icalls
```

The span generator loops forever. Quake-lineage renderer assembly patches its
own instructions at run time: `mov esi, [0x12345678]` and
`cmp esi, 0x12345678` ship with placeholders that a setup routine overwrites
(13 fields in `sw.dll`). `run_lift.py` finds every absolute store into a
module's own `.text` and passes the fields to the lifter, which reads them
from memory. pcrecomp's `lift32` already had this for immediates, but only
once per instruction. A `cmp` formats its operand twice, so the compare kept
the placeholder. It now covers displacements too and applies on every read.

### `bt; jae` was inverted

```
W_LoadWadFile: couldn't load gfx.wad
```

The file exists. The engine's `_stat` rejects names containing `?*` using
`strpbrk`, and MSVC's `strpbrk` is `bts [esp],eax` to build a 256-bit set,
then `bt [esp],eax; jae`. The lifter emitted `BT_CF` for **both** `jb` and
`jae`, so every character "matched", and every path was a wildcard. Also
fixed: a memory `bt/bts` with a register bit offset addresses a bit
**string** (`[ea + 4*(off>>5)]`), not one dword. Both are in pcrecomp, with
difftest cases against real hardware.

### The CRT's `memmove` indexes its jump table backwards

```
ITAIL: unresolved VA 0x1009FC54 from 0x1009F990
```

`neg ecx; jmp [ecx*4 + 0x1009FC20]` reads its table **downward** from the
base. `descend()` now follows the table in that direction when a `neg` of the
index register comes just before the jump.

### `cmp; inc; jae`: inc/dec preserve CF

```
[crash] code 0xC0000005 ... in lifted sub_100A3FBB   (the CRT small-block heap)
```

`--native sw.dll` made it go away, and `bisect` narrowed it to one function,
`__sbh_free_block` at `0x100A3C90`:

The function compares with `cmp`, stores a byte, increments a counter with
`inc`, stores again, and only then branches with `jae`. The carry the `jae`
reads is the compare's: `inc` leaves CF alone.

The lifter evaluated `jae` from the `inc`'s operands. The runtime even
carried a comment saying no condition was *"entitled to read"* CF after
`inc`, and that's wrong. Every module that links the CRT had a corrupting
heap. Fixed in pcrecomp: after `inc`/`dec`, `b`/`ae`/`a`/`be` take CF from
`_cf` (and `recomp_cond_cf` does the same at run time).

### Floats returned across the lifted/native boundary

`native_bridge` never carried a float result back: `st(0)` stayed on the
host FPU. `Sys_FloatTime` (`0x10083060`), `CVarGetFloat` (`0x1004BDE0`) and
friends returned stale values to lifted callers. The bridge now moves a
returned `st(0)` onto the lifted x87 stack when `TOP` dropped by one **and**
`fxam` says the register holds a value. Without the `fxam` check, a native
`fninit` looked like a return. `cb_run` does the reverse for lifted functions
that return a float to a native caller.

### Posted input doesn't make the game the foreground app

```
     9279486  ShowWindow
     4640409  SetFocus
     4640666  GetCapture          (--import-stats, 50 s window)
```

A scripted run starts behind whatever window you're using. The launcher
checks `GetForegroundWindow` every frame, finds someone else, and keeps
trying to take focus. It also calls `ClipCursor`, which would confine
**your** mouse. While the script owns the cursor, `GetForegroundWindow`
reports the game thread's own active window and `ClipCursor` does nothing.

### A black screenshot is not a black frame

`PrintWindow` can't see this game's windowed DirectDraw output reliably, and
screen capture depends on window stacking. Several "renders nothing"
conclusions came from that. `tools/run.ps1 -ShotEvery` and a comparison
against `--native` of the same module are the checks to trust.

### The black frame: eight lifter bugs, one at a time

For a long stretch the fully lifted engine loaded the map and ran with a black
frame, while `--native sw.dll` rendered. It was not one bug. Each fix below
changed what the frame did, and the next search started from there.

**How they were found.** `tools/find_bad_lift.py` runs a range of functions as
original code and halves it. But its answer comes with a catch: original code
calls original code, so a function's whole call tree runs natively, and the
bug can be anywhere under the function it names. It named V_RenderView.
`tools/treewalk.py` goes on from there: keep the function lifted, run only its
direct callees natively (a one-byte `--native-range` thunks exactly one entry),
halve the callees, go down a level. R_RenderView → R_SetupFrame → AngleVectors
→ `sin`/`cos`. Bisection builds patch R_RenderView's stack check
(`R_RenderView: called without enough stack`): native code runs on the host
stack and lifted code on the guest stack, which trips it. Launch a normal
build, not a bisection build, if you see that message.

| Symptom | Instruction | Fix (pcrecomp unless noted) |
|---|---|---|
| server hangs at map start (`fmod` loop) | `sahf` was a comment, `fprem` left C2 stale | `sahf` loads SF ZF AF PF CF from `ah`; `fprem` reports C2 clear |
| server angle-wrap loop never ends | `fxam`, `xlatb` unimplemented (the CRT classifies with them) | both lifted |
| `D_SCAlloc: bad cache size 0` | `frndint` truncated, so `floor`/`ceil` did | rounds by the control word |
| world never drew | R_ClipEdge leaves with `mov esp, [saved]`, skipping frames | callers of such functions unwind with it (`run_lift.py`) |
| span loop quits at the first trailing edge | `je` to code **below** the function entry; `push label; jmp func` | `descend()` follows branches below the entry; the pair lifts as call + `goto label` |
| every `sin`/`cos` takes the NaN path | the CRT helper returns "Inf/NaN?" in **ZF**; flags were per function | `ret` publishes the flags, `call` picks them up |
| …and returns NaN from there | `fld xword` (80-bit) pushed 0.0; `fsin` left C2 stale | real 80-bit loads and stores; the trig ops clear C2 |
| textures smear along every span | `add; sbb ecx,ecx; add; adc esi,[..]` read a stale carry | `adc`/`sbb` take CF from the `add`/`sub` before them (`precise_carry`) |

The branch-below-entry fix alone resolved 413 of the 414 branch targets that
had no lifted function behind them, across all five modules. Each of those was
a path that silently returned when taken. The last one is in bytes decoded
out of alignment and is never executed. Every row has a difftest case against
real hardware (`tools/lift/difftest.py`, 175/187 match, 12 known divergences,
0 failures).

`precise_carry` is a Lifter option, off by default: Fury3's lift depends on the
old behaviour somewhere (see the `sbb` note in `lift32.py`), so other projects
opt in when they're ready.

## Compatibility fixes (the retail exe needs them too)

- The CD key is stored as 13 digits in `HKCU\Software\Valve\Gunman\Settings\Key`.
- The RAM check is a signed compare of `dwTotalPhys` (see boot.md).
- The intro movies aren't in the Wise package (see boot.md).
