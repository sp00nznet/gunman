# Technical Plan: Static Recompilation of Gunman Chronicles

## Target Binaries

Gunman Chronicles is a GoldSrc mod. The game-specific logic lives in two DLLs inside the
`rewolf/` mod directory:

| Binary | Path | Size | Code Size | Purpose |
|--------|------|------|-----------|---------|
| `client.dll` | `rewolf/cl_dlls/client.dll` | 552 KB | 360 KB | Client-side game logic (HUD, weapons, effects, prediction) |
| `gunman.dll` | `rewolf/dlls/gunman.dll` | 1.32 MB | 950 KB | Server-side game logic (entities, AI, weapons, maps) |

**Note:** The server DLL is `gunman.dll`, not `hl.dll` as in standard Half-Life mods.
The `liblist.gam` config specifies: `gamedll "dlls\gunman.dll"`

Both were compiled with **MSVC 6.0** (linker version 6.0) on November 10-12, 2000.
Neither is packed or obfuscated. The server DLL only imports KERNEL32.dll.

The engine itself (`gunman.exe` / `hw.dll` / `sw.dll`) is standard GoldSrc and can be
replaced by Xash3D FWGS. We only need to recompile the **mod DLLs**.

## Why This Works

GoldSrc mods use a well-defined DLL interface. The engine loads the mod DLLs and calls exported
functions. The Half-Life SDK 2.3 provides the source code for the vanilla versions of these DLLs.

Gunman Chronicles was built by **modifying the Half-Life SDK**. This means:
- A large percentage of the code is **identical or near-identical** to the public SDK
- Custom Rewolf code (weapons, vehicles, AI) sits on top of this SDK base
- We can diff the disassembly against known SDK code to isolate Rewolf's changes

## Recompilation Strategy

### Step 1: Extract and Catalog -- DONE
- [x] Extracted disc image (MDF 2448-byte sectors -> ISO -> Wise installer)
- [x] Full PE analysis of 15 binaries (see docs/BINARY_ANALYSIS.md)
- [x] Identified all game assets: 72 maps, 304 models, 2285 sounds, 260 sprites
- [x] Hashed all targets (MD5/SHA1)
- [x] Confirmed MSVC 6.0 compilation, no packing/obfuscation

### Step 2: Disassemble
- Load `client.dll` and `gunman.dll` into Ghidra/IDA
- Apply known Half-Life SDK signatures (FLIRT/Ghidra signatures)
- This should auto-identify 50-80% of functions immediately

### Step 3: Identify Custom Code
- Functions that don't match SDK signatures = Rewolf custom code
- Focus areas likely include:
  - `CBasePlayerWeapon` subclasses (the weapon customization system)
  - Vehicle entities and physics
  - Custom AI behaviors (dinosaur enemies, etc.)
  - HUD elements for weapon tuning interface
  - Any custom particle/effect systems

### Step 4: Decompile and Reconstruct
- Use Hex-Rays/Ghidra decompiler for initial C output
- Clean up decompiler output into readable C++
- Match against SDK patterns for structure and naming
- Reconstruct class hierarchies

### Step 5: Build System
- Set up CMake project mirroring the Half-Life SDK structure
- Compile against modern MSVC/Windows SDK
- Target both x86 (for compatibility) and x64 (for modern systems)
- Link against Xash3D FWGS headers for testing

### Step 6: Test
- Run recompiled DLLs under Xash3D FWGS
- Playthrough each level comparing behavior to original
- Fix discrepancies

## Key References

- **Half-Life SDK 2.3:** https://github.com/ValveSoftware/halflife
  The base code that Gunman Chronicles was built on
- **Xash3D FWGS:** https://github.com/FWGS/xash3d-fwgs
  Open-source GoldSrc-compatible engine for testing
- **Half-Life SDK Source:** Well-documented structures for entities, weapons, and game systems

## Estimated Effort

This is a substantial project. The server DLL is larger than typical GoldSrc mods at 1.32 MB
(950 KB of code), but a huge chunk is known SDK code. The Rewolf-specific code (weapons,
vehicles, dinosaur AI) is the real challenge, but it's bounded in scope.

Notable exports from `gunman.dll` reveal custom classes:
- `CAnimeRocket`, `CBackpackAnimeRocket`, `CDemomanRocket` (projectile types)
- String constants referencing `ourano` (dinosaurs), `xenome` (aliens)
- Weapon event scripts: gauss, chemical, shotgun, sniper, minigun, rocket

Rough estimate:
- **Phase 1 (Extract/Catalog):** Days
- **Phase 2 (Disassembly):** 1-2 weeks
- **Phase 3 (Identify Custom Code):** 1-2 weeks
- **Phase 4 (Decompile/Reconstruct):** 2-6 weeks (the big one)
- **Phase 5 (Build):** Days
- **Phase 6 (Test):** 1-2 weeks ongoing

Total: **1-3 months** depending on complexity of Rewolf's custom code and available help.
