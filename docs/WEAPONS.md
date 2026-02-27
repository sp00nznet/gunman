# Gunman Chronicles Weapon Systems

## Overview

125+ weapon-related functions spanning ~45,000+ bytes of custom code across 11 weapon systems
and a unified customization framework with 22 pickup entities.

## Key Architecture

- **Shared vtables = weapon variants:** DML/Mule, Minigun/Mechagun, BeamGun/PolarisBlade,
  GaussPistol/Pistol, ChemGun/SPChemicalGun each share a vtable (same class, different init)
- **Entity factory pattern is uniform:** Every entity: check param -> get edict -> alloc via
  `CREATE_NAMED_ENTITY` -> set vtable at [0] -> set entvars at [4]
- **Customization system:** All `cust_*` entities are 79B each, allocating 0xa0-byte structs.
  The actual logic lives in weapon fire/deploy functions that read customization slot offsets.

## Weapon Systems

### 1. Fists (weapon_fists)
- **Functions:** ~7, ~2,580 bytes
- **Model:** v_hands.mdl, w_knife.mdl
- **Weapon ID:** 1
- **Modes:** Fist mode (alternating L/R punches, 3 sound variants) and Knife mode
- **Customization:** `cust_1fistsKnife` (toggle), `customization_knife` (pickup)

### 2. AI Core (weapon_aicore)
- **Functions:** ~4, ~304 bytes
- **Model:** w_aicore.mdl
- **Weapon ID:** 7
- **Notes:** Story/utility item, not combat. Minimal code.

### 3. Beam Gun / Polaris Blade (weapon_beamgun / weapon_polarisblade)
- **Functions:** ~5+, ~600+ bytes (shared vtable PTR_FUN_100fa100)
- **Model:** w_beam.mdl, v_beam.mdl
- **Weapon ID:** 14 (0xe)
- **Projectile:** `ball_lightning` entity
- **Customization:** `cust_1BeamFrequency`, `cust_2BeamCurrent`, `cust_3BeamVoltage`

### 4. DML Launcher / Mule (weapon_dml / weapon_mule) -- LARGEST SYSTEM
- **Functions:** ~30+, ~20,000+ bytes (shared vtable PTR_FUN_100faef8)
- **Model:** w_dml.mdl, dmlrocket.mdl
- **Weapon ID:** 16 (0x10)
- **Projectile:** `dmlRocket` entity (CDmlRocket class, 0x308 bytes)
- **Flight modes:**
  - Laser-guided (FollowThink, tracks laser spot)
  - Heat-seeking (TrackTarget, dot-product steering with "drunk missile" perturbation)
  - Straight flight (RocketThink, optional spiral)
  - Bounce mode
  - Stick-to-wall mode
- **Sub-projectile:** `dml_cluster` spawns 4 cluster grenades
- **Customization:** `cust_1DMLLaunch`, `cust_2DMLFlightpath`, `cust_3DMLDetonate`, `cust_4DMLPayload`

### 5. DML Hand Grenade (weapon_dmlGrenade)
- **Functions:** ~10, ~4,300+ bytes
- **Model:** grenadecore.mdl
- **Weapon ID:** 13 (0xd)
- **Modes:** Contact explosion or bouncy with timed detonation
- **Can spawn cluster grenades**
- **Customization:** `cust_1DMLGrenDetonate`, `cust_2DMLGrenPayload`

### 6. Gauss Pistol (weapon_gausspistol / weapon_pistol)
- **Functions:** ~10, ~2,800+ bytes
- **Model:** w_gauss.mdl
- **Weapon ID:** 30 (0x1e)
- **Fire modes:**
  - Standard (600 dmg single shot)
  - Charged (10 ammo, 1000 dmg)
  - Sniper (scope zoom)
  - Zoom mode
- **Customization:** `cust_1GaussPistolFireType`, `cust_2GaussPistolSniper`

### 7. Minigun / Mechagun (weapon_minigun / weapon_mechagun)
- **Functions:** ~8+, ~1,500+ bytes (shared vtable PTR_FUN_100fd30c)
- **Model:** w_mechagun.mdl, v_mechagun.mdl
- **Weapon ID:** 28 (0x1c)
- **Fire rates:** 0.2s normal, 0.075s spun-up
- **Customization:** `cust_1MinigunSpin`, `cust_2MinigunCooled`, `customization_coolers`

### 8. Shotgun (weapon_shotgun)
- **Functions:** ~7, ~700+ bytes
- **Model:** w_shotgun.mdl, v_shotgun.mdl
- **Weapon ID:** 17 (0x11)
- **Customization:** `cust_1ShotgunSpread` (pattern), `cust_2ShotgunShells` (count)

### 9. Chemical Gun (weapon_chemgun / weapon_SPchemicalgun)
- **Functions:** ~17+, ~6,700+ bytes
- **Model:** w_chemgun.mdl, v_chemgun.mdl
- **Projectile:** CChemGrenade with 6 chemical behavior types
- **Chemical modes:**
  - Sticky (adheres to surface, timed detonation)
  - Bouncy (bounce physics with damage reduction per bounce)
  - Stream/trail (continuous damage)
- **Chemical types affect damage:** Acid (0.5x to non-living), Base (0.5x to non-mechanical),
  Neutral (0.25x universal)
- **Customization:** `cust_1SPChemicalGunPressure`, `cust_2ChemAcid`, `cust_3ChemBase`, `cust_4ChemNuet`

### 10. Dart Trap (monster_dart / monster_darttrap)
- **Functions:** ~7, ~2,500 bytes
- **Model:** dart.mdl
- **KeyValue params:** dartcount, timebetweenshots, spread
- **Damage:** 8 per dart, sticks into walls

### 11. Cluster Explosion (env_clusterExplosion)
- **Functions:** ~5+, ~2,500+ bytes
- **Entities:** `env_clusterExplosion`, `entity_clustergod`, `dml_cluster`
- **KeyValue params:** clusterDamage, numGrenades

## Engine Globals Referenced

| Address | Purpose |
|---------|---------|
| `DAT_10132554` | gpGlobals (time, forward/right/up vectors) |
| `DAT_10132320` | PrecacheModel |
| `DAT_10132324` | PrecacheSound |
| `DAT_10132328` | SetModel |
| `DAT_10132488` | RANDOM_LONG |
| `DAT_1013248c` | RANDOM_FLOAT |
| `DAT_1013241c` | CREATE_NAMED_ENTITY |
