# Gunman Chronicles Monster/NPC Inventory

## Overview

~57 entity names, ~337 functions, ~103,150 bytes of custom monster/NPC code.

## Key Architecture

- **Shared entity classes:** Raptor/Rheptor use identical vtable+class size. Gunner/RustGunr/RustGnr
  are identical code with different entity names. Apache/Human Chopper produce identical registration.
- **Class hierarchy:** All monsters derive from CBaseMonster (GoldSrc SDK).
- **Entity registration pattern:** `(*DAT_1013241c)(edict, classSize)` = `CREATE_NAMED_ENTITY`.
  Vtable written as `*puVar3 = &PTR_LAB_XXXX`.
- **Constructor patterns:**
  - Simple: set vtable + edict pointer (most monsters)
  - Complex: call `FUN_10022540` (base init) then set vtable (rustbots, demoman)
  - Schedule-based: call `FUN_1000ff20` + `FUN_10001320` for schedule/task arrays (manta, chopper, scientist)

## Monster Categories

### Dinosaurs (~46 functions, ~7,712 bytes)

| Monster | Entity Names | Functions | Bytes | Class Size |
|---------|-------------|-----------|-------|------------|
| Raptor/Rheptor | `monster_raptor`, `monster_rheptor` | ~9 | ~1,466 | 732B |
| Microraptor | `monster_microraptor` | ~5 | ~1,226 | 720B |
| Ourano + Nest | `monster_ourano`, `decore_nest` | ~10 | ~1,698 | 700B |
| Renesaur | `monster_renesaur` | ~2 | ~216 | 628B |
| Beak + Birther | `monster_beak`, `beakbirther_gib`, `monster_beakbirther` | ~15 | ~2,528 | 704B |
| Critter | `monster_critter`, `critter_gib` | ~4 | ~578 | - |

### Xenomes (~51 functions, ~12,868 bytes)

| Monster | Entity Names | Functions | Bytes | Class Size |
|---------|-------------|-----------|-------|------------|
| Xenome | `monster_xenome`, `xenomeshot` | ~16 | ~3,502 | 696B |
| Xenome Embryo | `monster_xenome_embryo` | ~3 | ~284 | 624B |
| Tube Embryo | `monster_tube_embryo` | ~4 | ~496 | 628B |
| Tube | `monster_tube` | ~13 | ~2,197 | 720B |
| Tube Queen | `monster_tubequeen`, `tubequeen_mortar`, `tuberocket` | ~15 | ~6,389 | 640B |

### Rustbots (~99 functions, ~28,417 bytes) -- LARGEST SUBSYSTEM

| Monster | Entity Names | Functions | Bytes | Class Size |
|---------|-------------|-----------|-------|------------|
| Rustflier | `monster_rustflier` | ~25 | ~9,044 | 772B |
| Rustbit/Rustbot | `monster_rustbit`, `_friendly`, `monster_rustbot`, `_friendly`, `rustbitshot` | ~41 | ~9,414 | 728-748B |
| Gunner | `monster_gunner`, `monster_rustgunr`, `monster_rustgnr`, `_friendly` | ~21 | ~3,345 | 736B |
| Anime Rockets | `anime_rocket`, `animebackpack_rocket` | ~12 | ~6,614 | - |

### Insects (~57 functions, ~18,047 bytes)

| Monster | Entity Names | Functions | Bytes | Class Size |
|---------|-------------|-----------|-------|------------|
| Manta | `monster_manta`, `grenade_mantabomb` | ~10 | ~6,421 | 768B |
| Cricket | `monster_cricket` | ~4 | ~222 | 632B |
| Dragonfly | `monster_dragonfly` | ~8 | ~3,062 | 652B |
| Butterfly | `monster_butterfly`, `decore_butterflyflock` | ~17 | ~6,559 | 632B |
| Scorpion | `monster_scorpion` | ~7 | ~797 | 632B |
| Large Scorpion | `monster_largescorpion` | ~3 | ~187 | 636B |
| Maggot | `monster_maggot`, `maggot_gib` | ~11 | ~1,799 | 700B |

### Aquatic (~20 functions, ~5,507 bytes)

| Monster | Entity Names | Functions | Bytes | Class Size |
|---------|-------------|-----------|-------|------------|
| Gator | `monster_gator` | ~10 | ~879 | 628B |
| Hatchetfish | `monster_hatchetfish` | ~10 | ~4,628 | ~628B |

### Human NPCs (~54 functions, ~19,372 bytes)

| Monster | Entity Names | Functions | Bytes | Class Size |
|---------|-------------|-----------|-------|------------|
| Chopper | `monster_apache`, `monster_human_chopper` | ~13 | ~7,959 | 732B |
| Demoman | `monster_human_demoman`, `demoman_mine`, `demoman_rocket` | ~13 | ~4,720 | 772B |
| Gunman (human) | `monster_human_gunman` | ~9 | ~2,131 | 852B |
| Unarmed Human | `monster_human_unarmed` | ~5 | ~1,083 | - |
| Bandit/Grunt | `monster_human_bandit`, `monster_human_grunt` | ~9 | ~3,076 | 776B |
| AI Girl | `monster_aigirl` | ~3 | ~265 | 648B |
| Scientist | `monster_human_scientist` | ~5 | ~1,138 | 792B |

### Bosses (~19 functions, ~8,058 bytes)

| Monster | Entity Names | Functions | Bytes | Class Size |
|---------|-------------|-----------|-------|------------|
| End Boss | `monster_endboss`, `endboss_kataball`, `endboss_rocket`, `endboss_gib`, `antirocketflare` | ~19 | ~8,058 | 668B |

### Other (~37 functions, ~11,580 bytes)

| Monster | Entity Names | Functions | Bytes | Class Size |
|---------|-------------|-----------|-------|------------|
| Training Bot | `monster_trainingbot` | ~12 | ~6,907 | 684B |
| Hologram Beak | `hologram_beak`, `hologram_damage` | ~18 | ~3,808 | - |
| Ice Beak | `decore_icebeak`, `decore_ice` | ~6 | ~706 | - |
| PR Droid | `cycler_prdroid` | ~1 | ~79 | - |

## Largest Single Functions

| Function | Monster | Bytes |
|----------|---------|-------|
| MantaThink | Manta | 2,679 |
| FUN_100b4100 | Rustflier | 2,476 |
| BotSparkThink | Training Bot | 2,403 |
| HuntThink | Rustflier | 2,304 |
| FUN_1006b560 | Chopper | 2,260 |
| TrackTarget | Tube Queen | 1,881 |
| MantaBombTouch | Manta | 1,870 |
| SwimThink | Hatchetfish | 1,708 |
| DecoreTouch | Tube Queen | 1,545 |
| AccelerateThink | Demoman | 1,552 |
