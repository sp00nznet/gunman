# Technical Plan: Static Recompilation of Gunman Chronicles

## Target Binaries

Gunman Chronicles is a GoldSrc mod. The game-specific logic lives in two DLLs inside the
`rewolf/` mod directory:

| Binary | Path | Purpose |
|--------|------|---------|
| `client.dll` | `rewolf/cl_dlls/client.dll` | Client-side game logic (HUD, weapons, effects, prediction) |
| `hl.dll` | `rewolf/dlls/hl.dll` | Server-side game logic (entities, AI, weapons, maps) |

The engine itself (`hl.exe` / `hw.dll`) is standard GoldSrc and can be replaced by Xash3D FWGS.
We only need to recompile the **mod DLLs**.

## Why This Works

GoldSrc mods use a well-defined DLL interface. The engine loads the mod DLLs and calls exported
functions. The Half-Life SDK 2.3 provides the source code for the vanilla versions of these DLLs.

Gunman Chronicles was built by **modifying the Half-Life SDK**. This means:
- A large percentage of the code is **identical or near-identical** to the public SDK
- Custom Rewolf code (weapons, vehicles, AI) sits on top of this SDK base
- We can diff the disassembly against known SDK code to isolate Rewolf's changes

## Recompilation Strategy

### Step 1: Extract and Catalog
- Mount/extract the disc image
- Identify all files in the `rewolf/` directory
- Catalog DLL sizes, timestamps, and PE headers
- Check for any additional game-specific executables

### Step 2: Disassemble
- Load `client.dll` and `hl.dll` into Ghidra/IDA
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

This is a substantial project. The good news is that GoldSrc mod DLLs are relatively small
(typically 200KB-800KB) and a huge chunk is known SDK code. The Rewolf-specific code is the
real challenge, but it's bounded in scope.

Rough estimate:
- **Phase 1 (Extract/Catalog):** Days
- **Phase 2 (Disassembly):** 1-2 weeks
- **Phase 3 (Identify Custom Code):** 1-2 weeks
- **Phase 4 (Decompile/Reconstruct):** 2-6 weeks (the big one)
- **Phase 5 (Build):** Days
- **Phase 6 (Test):** 1-2 weeks ongoing

Total: **1-3 months** depending on complexity of Rewolf's custom code and available help.
