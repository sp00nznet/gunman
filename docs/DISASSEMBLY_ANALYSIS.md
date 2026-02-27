# Disassembly Analysis: Gunman Chronicles

## Ghidra Analysis Summary

Performed with Ghidra 12.0.3, headless auto-analysis.

### gunman.dll (Server Game DLL)

| Metric | Count |
|--------|-------|
| **Total functions** | 2,638 |
| **Named (from symbols)** | 801 (30.4%) |
| **Auto-named (FUN_)** | 1,837 (69.6%) |
| **Thunks** | 2 |
| **Unique named** | 703 |

### client.dll (Client Game DLL)

| Metric | Count |
|--------|-------|
| **Total functions** | 1,352 |
| **Named (from symbols)** | 436 (32.2%) |
| **Auto-named (FUN_)** | 916 (67.8%) |
| **Thunks** | 48 |

### Combined: 3,990 functions total across both DLLs

---

## Gunman Chronicles Weapons (14 unique weapons)

These are ALL custom Rewolf weapons -- none exist in the base Half-Life SDK:

| Entity Name | Description | Notes |
|-------------|-------------|-------|
| `weapon_pistol` | Basic pistol | Replaces HL Glock |
| `weapon_gausspistol` | Gauss pistol | Customizable charge-up |
| `weapon_shotgun` | Combat shotgun | Adjustable spread patterns |
| `weapon_minigun` | Minigun | Spin-up mechanic |
| `weapon_chemgun` | Chemical gun | Custom projectile behavior |
| `weapon_SPchemicalgun` | SP Chemical gun | Single-player variant |
| `weapon_beamgun` | Beam weapon | Energy beam |
| `weapon_dml` | DML (rocket launcher) | Customizable missile types |
| `weapon_dmlGrenade` | DML Grenade mode | Alt-fire for DML |
| `weapon_mechagun` | Mecha gun | Heavy weapon |
| `weapon_mule` | MULE weapon | Multi-purpose launcher? |
| `weapon_fists` | Fists | Melee, replaces HL crowbar |
| `weapon_polarisblade` | Polaris blade | Melee energy weapon |
| `weapon_aicore` | AI Core | Story/utility item |

### Ammo Types (9)
`ammo_beamgunclip`, `ammo_buckshot`, `ammo_chemical`, `ammo_dmlclip`,
`ammo_dmlsingle`, `ammo_gaussclip`, `ammo_mechgunClip`, `ammo_minigunClip`

### Weapon Customization Functions
These functions handle the signature weapon tuning system:
- `cust_1GaussPistolFireType`
- `cust_1MinigunSpin`
- `cust_1SPChemicalGunPressure`

---

## Gunman Chronicles Monsters/NPCs (50+ unique entities)

### Dinosaurs (The Ourano Family)
| Entity | Description |
|--------|-------------|
| `monster_ourano` | Main dinosaur enemy |
| `monster_raptor` | Raptor enemy |
| `monster_microraptor` | Small raptor |
| `monster_renesaur` | Renesaur creature |
| `monster_beak` | Beaked creature |
| `monster_beakbirther` | Beak spawner |

### Xenome (Alien Creatures)
| Entity | Description |
|--------|-------------|
| `monster_xenome` | Main alien enemy |
| `monster_xenome_embryo` | Alien embryo |
| `monster_tube` | Tube creature |
| `monster_tube_embryo` | Tube embryo |
| `monster_tubequeen` | Tube queen (boss?) |

### Wildlife/Critters
| Entity | Description |
|--------|-------------|
| `monster_butterfly` | Ambient butterfly |
| `monster_cricket` | Ambient cricket |
| `monster_critter` | Generic critter |
| `monster_dragonfly` | Ambient dragonfly |
| `monster_gator` | Alligator/gator |
| `monster_hatchetfish` | Fish creature |
| `monster_maggot` | Maggot creature |
| `monster_manta` | Manta ray creature |
| `monster_scorpion` | Scorpion |
| `monster_largescorpion` | Large scorpion |

### Rust Bots (Mechanical Enemies)
| Entity | Description |
|--------|-------------|
| `monster_rustbit` | Rust bit robot |
| `monster_rustbit_friendly` | Friendly variant |
| `monster_rustbot` | Rust bot |
| `monster_rustbot_friendly` | Friendly variant |
| `monster_rustflier` | Flying rust bot |
| `monster_rustgnr` | Rust gunner |
| `monster_rustgunr` | Rust gunner variant |

### Human NPCs
| Entity | Description |
|--------|-------------|
| `monster_human_gunman` | Friendly gunman soldiers |
| `monster_human_grunt` | Human grunt (from HL) |
| `monster_human_bandit` | Enemy bandits |
| `monster_human_demoman` | Demolitions soldier |
| `monster_human_chopper` | Chopper pilot? |
| `monster_human_unarmed` | Unarmed human |
| `monster_human_scientist` | Scientist NPC |
| `monster_gunner` | Gunner NPC |
| `monster_gunner_friendly` | Friendly gunner |
| `monster_aigirl` | AI girl character |

### Vehicles & Turrets
| Entity | Description |
|--------|-------------|
| `monster_tank` | Drivable tank |
| `monster_tank_rocket` | Rocket tank |
| `monster_turret` | Turret |
| `monster_miniturret` | Mini turret |
| `monster_sentry` | Sentry gun |
| `monster_sentry_mini` | Mini sentry |

### Bosses
| Entity | Description |
|--------|-------------|
| `monster_endboss` | Final boss |
| `monster_apache` | Apache helicopter (from HL, likely modified) |

---

## Gunman-Specific Triggers & Entities

### Tank System (Unique to Gunman)
- `trigger_tank` - Enter tank
- `trigger_tankeject` - Eject from tank
- `trigger_tankoutofgas` - Out of fuel event
- `trigger_tankshell` - Tank shell impact

### Other Custom Triggers
- `trigger_gunmanteleport` - Custom teleport (not standard HL)
- `env_clusterExplosion` - Cluster explosion effect
- `env_debris` - Debris system
- `func_wind` - Wind effect
- `func_tanklaserrust` - Rust-themed tank laser

### Vehicle Think/Use Functions
- `BuildVehicleThink` - Vehicle construction
- `UseVehicle` - Enter/exit vehicle
- `TouchTank` (x2 variants)
- `TankBSPUse`, `TankIgniteThink`, `TankThink`, `TankTouch`

### Items
- `item_armor` - Armor pickup
- `item_gascan` - Gas can (for vehicles)
- `item_gastank` - Gas tank
- `item_sodacan` - Soda can pickup
- `player_togglehud` - HUD toggle
- `player_giveitems` - Give items
- `cycler_prdroid` - PR Droid cycler

---

## SDK vs Custom Code Estimation

Based on entity name analysis:

### Entities shared with Half-Life SDK (will match SDK code closely):
- `func_door`, `func_button`, `func_train`, `func_breakable`, etc.
- `trigger_once`, `trigger_multiple`, `trigger_relay`, etc.
- `env_beam`, `env_explosion`, `env_sprite`, etc.
- `info_player_start`, `info_node`, `info_landmark`, etc.
- Core infrastructure: `DispatchSpawn`, `DispatchThink`, `GetEntityAPI`, etc.

### Entities unique to Gunman (require full RE):
- All 14 weapons
- All dinosaur/xenome/rustbot monsters
- Tank/vehicle system
- Gunman-specific triggers
- Custom items (gascan, gastank, etc.)
- Weapon customization system

### Rough Split Estimate:
- **~40-50% SDK-matching code** (infrastructure, base entities, physics, AI framework)
- **~50-60% Rewolf custom code** (weapons, monsters, vehicles, game-specific logic)

This is a higher custom-to-SDK ratio than typical HL mods, reflecting the scope
of Gunman Chronicles as a full standalone game rather than a simple mod.
