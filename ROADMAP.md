# Roadmap

## Next

- **A long playthrough of the fully recompiled build**, the way the 81-minute
  one ran with the engine native, and a look at the known issues in the
  README (the general's gate and speech, the taskbar button) against retail.
- **Conformance harness** (REPO_RULES section 9): a boot-milestone check that
  runs the recompiled launcher with `--imports` and confirms, in order, vgui
  attach, entry, `sierra.avi`, `rewolf.bik`, menu. It reports a pass count,
  skips with a clear message when `game/` is absent, and fails on regression.
  Alongside it, pcrecomp `lift/difftest.py` over the lifted bodies, and a
  screenshot comparison of the in-game frame against `--native sw.dll`.
- **CI**: build, lint, and the harness where it can run. The lift needs the
  game, so CI can check the toolchain and runtime but not the generated tree.
- Skip-intro and input checks in `tools/run.ps1` (menu navigation by posted input).

## Deferred

- The Half-Life-SDK-based rebuild of the game DLLs (`src/client`, `src/server`,
  uncommitted). It can't ship under MIT, because it's derived from the SDK, and
  recompiling the retail DLLs makes it unnecessary.
- `hw.dll` (OpenGL). The software path comes first.
- Replacing Bink and WON with our own code. They run natively as third-party
  middleware.

## Out of scope

- Distributing any game file, binary, or generated source.
- A 64-bit host. The native bridge depends on sharing one 32-bit address
  space with Windows. See docs/architecture.md.
