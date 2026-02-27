# GUNMAN CHRONICLES: RECOMPILATION PROJECT

```
   ______                                     ________                      _      __
  / ____/_  ______  ____ ___  ____ _____     / ____/ /_  _________  ____  (_)____/ /__  _____
 / / __/ / / / __ \/ __ `__ \/ __ `/ __ \   / /   / __ \/ ___/ __ \/ __ \/ / ___/ / _ \/ ___/
/ /_/ / /_/ / / / / / / / / / /_/ / / / /  / /___/ / / / /  / /_/ / / / / / /__/ /  __(__  )
\____/\__,_/_/ /_/_/ /_/ /_/\__,_/_/ /_/   \____/_/ /_/_/   \____/_/ /_/_/\___/_/\___/____/

              ____  ________________  __  _______  ______    ___  __________________  _   __
             / __ \/ ____/ ____/ __ \/  |/  / __ \/  _/ /   /   |/_  __/  _/ __ \/ | / /
            / /_/ / __/ / /   / / / / /|_/ / /_/ // // /   / /| | / /  / // / / /  |/ /
           / _, _/ /___/ /___/ /_/ / /  / / ____// // /___/ ___ |/ / _/ // /_/ / /|  /
          /_/ |_/_____/\____/\____/_/  /_/_/   /___/_____/_/  |_/_/ /___/\____/_/ |_/
```

> *"The year is 2037. You are Major Archer, commander of the Gunman militia..."*
>
> ...and the year is 2026. This game has been dead for 25 years. We're digging it up.

---

## WTF IS THIS?

This is a **static recompilation project** for **Gunman Chronicles** (2000) -- Valve's forgotten stepchild, the sci-fi western FPS that time forgot, rights disputes buried, and Windows 11 doesn't want to run.

**The goal:** Make this masterpiece of weird run on modern hardware without emulation hacks, compatibility shims, or blood sacrifices to the GoldSrc gods.

---

## THE SAD HISTORY OF GUNMAN CHRONICLES

### The Rise (1996-2000)

| Year | Event |
|------|-------|
| **1996** | Herb Flower (yes, real name) founds **Rewolf Software** in Utah. "Rewolf" is "Flower" backwards. Already peak game dev energy. |
| **~1997** | Team starts building **"Gunmanship 101"** -- a Quake deathmatch mod about space cowboys. |
| **1998** | Port to Quake II engine. Then they see Half-Life and think "yeah, that one." Port begins to GoldSrc. |
| **1999** | Gunman steals the show at the **Half-Life Mod Expo**. Sierra says "shut up and take our money." |
| **1999-2000** | Valve gives Rewolf office space, funding, and mapper Jeff Lane. Gabe was involved. It was... complicated. |
| **Nov 21, 2000** | **Gunman Chronicles ships.** First non-Half-Life standalone game on GoldSrc. Reviews are mixed. Sales are decent. Herb "didn't get rich." |

### The Features That Were Ahead of Their Time
- **Customizable weapons** -- you could tune your guns like guitar amps
- **Drivable vehicles** -- a full tank section through canyons (in 2000!)
- **Sci-fi western aesthetic** -- dinosaurs + robots + cowboys. What's not to love?
- **Planned GameCube port** -- never happened, obviously

### The Fall (2001-forever)

| Year | Event |
|------|-------|
| **2001** | Rewolf Software **dissolves**. Team scatters to the winds. Core devs move to Netherlands, found Streamline Studios. |
| **2002** | Game shown in Steam preview at GDC. Never actually released on Steam. |
| **2008** | Sierra merges into Activision Blizzard. Rights become a legal dumpster fire between Valve and Vivendi/Activision. |
| **2020s** | Game literally **cannot be purchased anywhere legally**. Not on Steam. Not on GOG. Nowhere. |
| **2025** | Herb Flower now runs **"Goatogrammetry"** -- a photogrammetry business where actual goats carry his equipment through the Utah desert. You can't make this up. |

> *"My relationship with Gabe didn't really go that great"* -- Herb Flower, PC Gamer interview

---

## EXISTING REVIVAL EFFORTS (We're Not the First Crazies)

| Project | Approach | Status |
|---------|----------|--------|
| [FreeGunman](https://github.com/eukara/freegunman) | Clean-room reimplementation in QuakeC | ~68 commits, low activity, unclear completeness |
| [HLSourceHub Archive](https://github.com/HLSourceHub/goldsrc-gunman_chronicles) | Game files preservation | 2 commits, basically a file dump |
| [Xash3D Engine](https://www.moddb.com/engines/xash3d-engine) | Custom GoldSrc replacement engine | Works-ish. Requires `-game rewolf` flag. Menu issues in fullscreen. |
| [Steam Conversion Patch](https://steamcommunity.com/sharedfiles/filedetails/?id=368600073) | Run retail as Half-Life mod on Steam | Workaround, not a real fix |
| [reGoldSrc](https://github.com/hzqst/GameEngine-reGoldSrc) | Reverse-engineered GoldSrc engine | WIP, Windows only, no Gunman testing |
| [reGS_WON](https://github.com/ScriptedSnark/reGS_WON) | RE of GoldSrc build 738 | Very WIP |
| [Collection Chamber](https://collectionchamber.blogspot.com/p/gunman-chronicles.html) | Pre-packaged installer for modern Windows | Convenience package, not a recomp |

**None of these are a proper static recompilation.** That's where we come in.

---

## OUR APPROACH: STATIC RECOMPILATION

### What is Static Recompilation?

Instead of running the original binary through compatibility layers or reimplementing from scratch, we:

1. **Disassemble** the original game DLLs (`client.dll` + `gunman.dll` from the `rewolf/` mod directory)
2. **Analyze** the x86 machine code and reconstruct equivalent C/C++ source
3. **Recompile** with a modern compiler targeting x86_64/modern Windows
4. **Link** against modern system libraries instead of ancient Win32/GoldSrc APIs where needed

This gives us a binary that is **functionally identical** to the original but runs natively on modern systems.

### The Targets (Now Identified!)

| Binary | Size | Code | Purpose |
|--------|------|------|---------|
| `rewolf/dlls/gunman.dll` | **1.32 MB** | 950 KB | Server game logic -- entities, AI, weapons, vehicles, everything |
| `rewolf/cl_dlls/client.dll` | **552 KB** | 360 KB | Client game logic -- HUD, weapon prediction, effects, VGUI menus |

Both compiled with **MSVC 6.0** on November 10-12, 2000. Neither is packed or obfuscated.
The server DLL only imports KERNEL32 (engine provides everything else via function pointers).
The engine itself (`hw.dll`, `sw.dll`, `gunman.exe`) gets replaced by Xash3D -- we only touch the mod DLLs.

**Total code to reverse: ~1.3 MB of x86.** But most of it is Half-Life SDK 2.3 boilerplate.
The Rewolf-custom code is the real prize -- and we've found it.

### Code Classification Results

Multi-signal analysis (name matching + string references + call graph + address clustering) reveals:

| DLL | Total Functions | SDK (HL 2.3) | Rewolf Custom | Unknown |
|-----|----------------|--------------|---------------|---------|
| `gunman.dll` | 2,638 | **2,059** (81%, 492 KB) | **366** (14%, 80 KB) | 116 (4%) |
| `client.dll` | 1,352 | **1,072** (83%, 210 KB) | **133** (10%, 39 KB) | 82 (6%) |
| **Combined** | **3,990** | **3,131** (82%) | **499** (13%) | **198** (5%) |

> **Translation:** ~80% of these DLLs is straight Half-Life SDK code we can pull from public source.
> The actual Rewolf custom code -- weapons, dinos, vehicles, the fun stuff -- is only **~119 KB** across both DLLs.
> That's our focused recompilation target.

### Project Structure

```
gunman/
+-- README.md              # You are here
+-- docs/                   # Research notes, reverse engineering docs
+-- disasm/                 # Disassembly output and analysis
+-- src/                    # Recompiled C/C++ source code
|   +-- client/             # Client-side game DLL
|   +-- server/             # Server-side game DLL
|   +-- common/             # Shared code
+-- tools/                  # Helper scripts and utilities
+-- assets/                 # Asset extraction/conversion tools (no copyrighted content!)
```

### Tech Stack

- **Disassembler:** Ghidra 12.0.3 (NSA's finest, headless mode)
- **Decompiler:** Ghidra built-in decompiler
- **Compiler:** MSVC 2022 / Clang
- **Reference:** [Half-Life SDK 2.3](https://github.com/ValveSoftware/halflife) (the game DLLs are based on this)
- **Engine:** [Xash3D FWGS](https://github.com/FWGS/xash3d-fwgs) (open-source GoldSrc-compatible engine for testing)

---

## PROGRESS TRACKER

### Phase 0: Research & Setup
- [x] Research game history and context
- [x] Identify existing revival efforts
- [x] Set up repository
- [x] Extract game files from disc image (MDF/MDS -> ISO -> install)
- [x] Catalog all binary components (15 DLLs/EXEs analyzed)
- [x] PE analysis: sections, imports, exports, timestamps, hashes
- [x] Identify primary targets: `gunman.dll` (server) + `client.dll` (client)
- [x] Inventory game assets: 72 maps, 304 models, 2285 sounds, 260 sprites, 46 events
- [x] Set up disassembly environment (Ghidra 12.0.3)
- [x] Download Half-Life SDK 2.3 for reference diffing

### Phase 1: Disassembly & Analysis
- [x] Disassemble `rewolf/dlls/gunman.dll` -- **2,638 functions found** (801 named, 1,837 auto)
- [x] Disassemble `rewolf/cl_dlls/client.dll` -- **1,352 functions found** (436 named, 916 auto)
- [x] Identify all 14 Gunman-specific weapons
- [x] Identify 50+ custom monster/NPC entities (dinosaurs, xenomes, rustbots, etc.)
- [x] Document tank/vehicle system (7 tank-related triggers and functions)
- [x] Document weapon customization system (`cust_*` functions)
- [x] Decompile all functions to C pseudocode -- **3,988/3,990 decompiled (99.95%)**
- [x] Multi-signal classification (name matching, string refs, call graph, address clustering)
- [x] Map functions against Half-Life SDK 2.3
- [x] Classify all server functions -- **2,059 SDK (81%) | 366 Rewolf (14%) | 116 unknown (4%)**
- [x] Classify all client functions -- **1,072 SDK (83%) | 133 Rewolf (10%) | 82 unknown (6%)**

### Phase 2: Recompilation
- [ ] Set up build system (CMake)
- [ ] Recompile matched SDK functions
- [ ] Recompile custom Rewolf code
- [ ] Build against modern Windows SDK
- [ ] Testing with Xash3D FWGS

### Phase 3: Polish & Release
- [ ] Full playthrough testing
- [ ] Widescreen support
- [ ] High-DPI support
- [ ] Modern input handling
- [ ] Package for easy installation

---

## HOW TO HELP

This is a massive undertaking. If you know your way around:
- **x86 reverse engineering** (IDA/Ghidra)
- **GoldSrc engine internals**
- **Half-Life SDK programming**
- **C/C++ and Win32 API**

...then pull up a chair. Open an issue. Send a PR. Let's bring this beautiful disaster back from the dead.

---

## LEGAL STUFF

This project contains **no copyrighted game assets**. You need your own copy of Gunman Chronicles to use any recompiled binaries. The recompilation targets functional equivalence for preservation and compatibility purposes.

The game cannot be legally purchased anywhere as of 2026. It exists in a rights limbo between Valve, the Activision Blizzard estate, and the ghost of Sierra Entertainment. If you're reading this, Valve/Microsoft -- just put it on Steam already.

---

## LINKS & RESOURCES

- [Gunman Chronicles on Wikipedia](https://en.wikipedia.org/wiki/Gunman_Chronicles)
- [PC Gamer: "What happened to the creator of Gunman Chronicles?"](https://www.pcgamer.com/games/fps/what-happened-to-the-creator-of-gunman-chronicles-valves-forgotten-fps-my-relationship-with-gabe-didnt-really-go-that-great/)
- [Gunman Chronicles on ModDB](https://www.moddb.com/games/gunman-chronicles)
- [My Abandonware Download](https://www.myabandonware.com/game/gunman-chronicles-bgo)
- [Valve Developer Community Wiki](https://developer.valvesoftware.com/wiki/Gunman_Chronicles)
- [Steam Petition Group](https://steamcommunity.com/groups/gunman-steam-petition)
- [Internet Archive: Gunman Chronicles Prototypes](https://archive.org/details/gunman-chronicles-prototypes)
- [Half-Life Sources Hub](https://hlsources.github.io/)

---

*"In space, no one can hear you yeehaw."* -- Tagline we just made up but should have been real
