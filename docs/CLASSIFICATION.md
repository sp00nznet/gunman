# Function Classification Results

## Overview

Using a multi-signal classifier (`tools/combined_classify.py`), we analyzed all 3,990 functions
across both game DLLs to separate Half-Life SDK 2.3 boilerplate from Rewolf's custom Gunman
Chronicles code.

## Classification Methods

Four passes are used, each building on the previous:

1. **Name-based matching** - Compare function/class names against HL SDK source (535 classes,
   3,708 function names). Catches named exports like `CBasePlayer::Spawn`, `UTIL_TraceLine`, etc.

2. **String reference analysis** - Extract Ghidra string refs from decompiled output, match
   against SDK string index (4,386 strings) and Rewolf keyword set. Identifies functions by
   their string constants (model paths, sound files, entity names).

3. **Call graph propagation** - If an unknown function is predominantly called by/calls SDK
   functions, classify it as SDK (and vice versa for Rewolf). Runs iteratively up to 5 passes.

4. **Address clustering** - Functions compiled from the same .cpp file are typically adjacent
   in the binary. Uses a sliding window to infer classification from neighbors.

## Results

### gunman.dll (Server DLL)

| Category | Functions | Bytes | % Functions | % Bytes |
|----------|-----------|-------|-------------|---------|
| SDK | 2,059 | 492,082 | 81% | 83% |
| Rewolf Custom | 366 | 80,259 | 14% | 13% |
| Unknown | 116 | 17,475 | 4% | 2% |
| **Total** | **2,541** | **589,816** | | |

SDK code maps to these source files (top matches by string analysis):
- `dlls/util.cpp` (25 functions)
- `dlls/apache.cpp` (20 functions)
- `dlls/satchel.cpp` (11 functions)
- `dlls/func_break.cpp` (9 functions)
- `dlls/game.cpp` (9 functions)
- `dlls/scientist.cpp` (9 functions)
- `dlls/crossbow.cpp` (8 functions)
- `dlls/weapons.cpp` (8 functions)
- `dlls/client.cpp`, `combat.cpp`, `sound.cpp` (7 each)

### client.dll (Client DLL)

| Category | Functions | Bytes | % Functions | % Bytes |
|----------|-----------|-------|-------------|---------|
| SDK | 1,072 | 209,643 | 83% | 81% |
| Rewolf Custom | 133 | 38,761 | 10% | 14% |
| Unknown | 82 | 10,175 | 6% | 3% |
| **Total** | **1,287** | **258,579** | | |

SDK code maps to these source files (top matches by string analysis):
- `dlls/client.cpp` (4 functions, 11 KB - largest single source match)
- `cl_dll/ammo.cpp` (6 functions)
- `cl_dll/hud_servers.cpp` (5 functions)
- `dlls/player.cpp` (7 functions)
- `cl_dll/view.cpp` (4 functions)
- `cl_dll/inputw32.cpp` (4 functions)
- `cl_dll/hud.cpp` (4 functions)

## Rewolf Custom Code Breakdown

The 499 Rewolf-custom functions (~119 KB) include:

### Weapons (Server)
- Chemical gun system (`ChemicalExplode`, `ChemicalSmokeThink`, `BouncyChemicalTouch`)
- DML launcher (`DmlGrenExplodeTouch`, `DmlHandGrenDetonate`, `DmlHandGrenTumbleThink`)
- Cluster grenades (`ClusterDetonate`, `ClusterExplode`, `ClusterSmokeThink`)
- Dart traps (`DartShootThink`)
- Beam gun, minigun, gausspistol, mechagun, polaris blade, mule, fists, shotgun2

### Monsters/NPCs
- Dinosaurs: raptor, microraptor, renesaur, rheptor
- Xenomes: xenome, xmbryo, ourano
- Rustbots: various rustbot variants
- Insects: dragonfly, butterfly, cricket, maggot, scorpion, manta
- Aquatic: gator, hatchetfish
- Human: bandit, demoman, chopper, aigirl
- Bosses: endboss

### Vehicles
- Tank system with custom triggers
- Drivable vehicle code

### Misc
- Training bot system
- PR droid
- Gas/soda can physics objects
- Weapon customization system (`cust_*`)
- Custom AI behaviors

## Files

- `disasm/gunman_combined_classification.txt` - Full server DLL classification (function-by-function)
- `disasm/client_combined_classification.txt` - Full client DLL classification (function-by-function)
- `disasm/gunman_deep_classification.txt` - String-only analysis results
- `disasm/client_deep_classification.txt` - String-only analysis results
- `disasm/classification.txt` - Initial name-only classification
- `tools/combined_classify.py` - Multi-signal classifier
- `tools/deep_classify.py` - String reference classifier
- `tools/classify_functions.py` - Name-based classifier
