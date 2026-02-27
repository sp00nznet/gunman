# Existing Efforts to Revive Gunman Chronicles

A survey of all known projects attempting to make Gunman Chronicles playable in the modern era.

## 1. FreeGunman (Clean-Room Reimplementation)

- **URL:** https://github.com/eukara/freegunman
- **Author:** Marco Hladik (eukara)
- **Approach:** Complete clean-room reimplementation in QuakeC using the Nuclide SDK
- **Engine:** FTEQW (Quake-family engine)
- **Status:** ~68 commits, low activity, unclear completion level
- **License:** ISC
- **Notes:** Part of a broader effort reimplementing many GoldSrc games (Half-Life, Opposing Force,
  Counter-Strike, TFC, They Hunger) in QuakeC. Ambitious but spread thin across many projects.

## 2. Xash3D FWGS (Engine Replacement)

- **URL:** https://github.com/FWGS/xash3d-fwgs
- **Approach:** Open-source GoldSrc-compatible engine built from scratch
- **Status:** Active, mature project
- **Gunman Compatibility:** Partial
  - Launch with `-game rewolf` parameter
  - Menu display issues in fullscreen
  - Intro videos may not play
  - Requires HD texture pack according to some sources
- **Notes:** Best current option for playing the game on modern systems, but not perfect.

## 3. HLSourceHub Archive

- **URL:** https://github.com/HLSourceHub/goldsrc-gunman_chronicles
- **Approach:** Game files preservation
- **Status:** 2 commits (Dec 2024), effectively dormant
- **Notes:** Contains `rewolf/` directory and a batch launcher. The large `pak0.pak` is in
  the releases section, not the repo itself. Preservation effort, not a technical fix.

## 4. Steam Conversion Patch

- **URL:** https://steamcommunity.com/sharedfiles/filedetails/?id=368600073
- **Approach:** Makes retail Gunman Chronicles run as a Half-Life mod on Steam's Half-Life
- **Status:** Community guide, functional
- **Notes:** Workaround rather than proper fix. Requires owning Half-Life on Steam.

## 5. Collection Chamber Package

- **URL:** https://collectionchamber.blogspot.com/p/gunman-chronicles.html
- **Approach:** Pre-configured installer with compatibility fixes for modern Windows
- **Status:** Available
- **Notes:** Convenience package. Uses Xash3D under the hood with pre-configured settings.

## 6. reGoldSrc (Reverse-Engineered Engine)

- **URL:** https://github.com/hzqst/GameEngine-reGoldSrc
- **Approach:** Full reverse engineering of the GoldSrc engine
- **Status:** WIP, 238 commits, Windows only
- **Notes:** Has not been tested with Gunman Chronicles. Could theoretically serve as
  a foundation for running the original game binaries if completed.

## 7. reGS_WON (GoldSrc Build 738 RE)

- **URL:** https://github.com/ScriptedSnark/reGS_WON
- **Approach:** Reverse engineering of GoldSrc WON build 738
- **Status:** Very early WIP
- **Notes:** Targeting the same era of GoldSrc that Gunman Chronicles was built against.

## 8. Sandbot (Multiplayer Bot)

- **URL:** Listed on hlsources.github.io
- **Approach:** Open-source multiplayer bot
- **Status:** Active
- **Notes:** Explicitly lists Gunman Chronicles as a supported game. Not a revival effort
  per se, but shows the modding community still cares.

## Gap Analysis

| Need | Covered? | By What? |
|------|----------|----------|
| Play on modern Windows at all | Partially | Xash3D, Collection Chamber |
| Native x64 binary | No | -- |
| Proper widescreen/high-DPI | No | -- |
| Modern input handling | No | -- |
| Source code availability | Partially | FreeGunman (QuakeC, incomplete) |
| Full game logic recompilation | **No** | **This is our project** |

**Conclusion:** Nobody has done a static recompilation of the game DLLs. That's the gap we fill.
