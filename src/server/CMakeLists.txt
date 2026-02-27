# Gunman Chronicles Server DLL (gunman.dll)
# Original: rewolf/dlls/gunman.dll (1.32 MB, MSVC 6.0, Nov 2000)
# Contains: entities, AI, weapons, vehicles, game rules

set(HL_DLLS_DIR "${HL_SDK_DIR}/dlls")

# ── SDK source files (from Half-Life SDK 2.3) ────────────────────────
# These are compiled as-is from the public SDK. The original gunman.dll
# included these with minimal or no modifications.
set(SDK_SOURCES
    ${HL_DLLS_DIR}/airtank.cpp
    ${HL_DLLS_DIR}/aflock.cpp
    ${HL_DLLS_DIR}/agrunt.cpp
    ${HL_DLLS_DIR}/animating.cpp
    ${HL_DLLS_DIR}/animation.cpp
    ${HL_DLLS_DIR}/bmodels.cpp
    ${HL_DLLS_DIR}/buttons.cpp
    ${HL_DLLS_DIR}/cbase.cpp
    ${HL_DLLS_DIR}/combat.cpp
    ${HL_DLLS_DIR}/controller.cpp
    ${HL_DLLS_DIR}/defaultai.cpp
    ${HL_DLLS_DIR}/doors.cpp
    ${HL_DLLS_DIR}/effects.cpp
    ${HL_DLLS_DIR}/explode.cpp
    ${HL_DLLS_DIR}/flyingmonster.cpp
    ${HL_DLLS_DIR}/func_break.cpp
    ${HL_DLLS_DIR}/func_tank.cpp
    ${HL_DLLS_DIR}/game.cpp
    ${HL_DLLS_DIR}/gamerules.cpp
    ${HL_DLLS_DIR}/genericmonster.cpp
    ${HL_DLLS_DIR}/ggrenade.cpp
    ${HL_DLLS_DIR}/globals.cpp
    ${HL_DLLS_DIR}/h_ai.cpp
    ${HL_DLLS_DIR}/h_battery.cpp
    ${HL_DLLS_DIR}/h_cine.cpp
    ${HL_DLLS_DIR}/h_cycler.cpp
    ${HL_DLLS_DIR}/h_export.cpp
    ${HL_DLLS_DIR}/healthkit.cpp
    ${HL_DLLS_DIR}/items.cpp
    ${HL_DLLS_DIR}/lights.cpp
    ${HL_DLLS_DIR}/maprules.cpp
    ${HL_DLLS_DIR}/monstermaker.cpp
    ${HL_DLLS_DIR}/monsters.cpp
    ${HL_DLLS_DIR}/monsterstate.cpp
    ${HL_DLLS_DIR}/mortar.cpp
    ${HL_DLLS_DIR}/multiplay_gamerules.cpp
    ${HL_DLLS_DIR}/nodes.cpp
    ${HL_DLLS_DIR}/observer.cpp
    ${HL_DLLS_DIR}/pathcorner.cpp
    ${HL_DLLS_DIR}/plats.cpp
    ${HL_DLLS_DIR}/player.cpp
    ${HL_DLLS_DIR}/playermonster.cpp
    ${HL_DLLS_DIR}/schedule.cpp
    ${HL_DLLS_DIR}/scientist.cpp
    ${HL_DLLS_DIR}/scripted.cpp
    ${HL_DLLS_DIR}/singleplay_gamerules.cpp
    ${HL_DLLS_DIR}/skill.cpp
    ${HL_DLLS_DIR}/sound.cpp
    ${HL_DLLS_DIR}/soundent.cpp
    ${HL_DLLS_DIR}/spectator.cpp
    ${HL_DLLS_DIR}/squadmonster.cpp
    ${HL_DLLS_DIR}/subs.cpp
    ${HL_DLLS_DIR}/talkmonster.cpp
    ${HL_DLLS_DIR}/teamplay_gamerules.cpp
    ${HL_DLLS_DIR}/triggers.cpp
    ${HL_DLLS_DIR}/turret.cpp
    ${HL_DLLS_DIR}/util.cpp
    ${HL_DLLS_DIR}/vehicle.cpp
    ${HL_DLLS_DIR}/weapons.cpp
    ${HL_DLLS_DIR}/world.cpp
    ${HL_DLLS_DIR}/xen.cpp
    ${HL_DLLS_DIR}/zombie.cpp
    # Additional SDK files needed for linking
    ${HL_DLLS_DIR}/client.cpp
    ${HL_DLLS_DIR}/plane.cpp
    ${HL_DLLS_DIR}/satchel.cpp
    ${HL_GAME_SHARED_DIR}/voice_gamemgr.cpp
    # Shared code
    ${HL_PM_SHARED_DIR}/pm_debug.c
    ${HL_PM_SHARED_DIR}/pm_math.c
    ${HL_PM_SHARED_DIR}/pm_shared.c
)

# SDK files that Rewolf REMOVED (these HL1 monsters don't exist in Gunman):
# apache.cpp -> replaced by Rewolf's chopper
# barnacle.cpp, barney.cpp, bigmomma.cpp, bloater.cpp, bullsquid.cpp
# crossbow.cpp, crowbar.cpp, egon.cpp, gargantua.cpp, gauss.cpp
# glock.cpp, gman.cpp, handgrenade.cpp, hassassin.cpp, headcrab.cpp
# hgrunt.cpp, hornet.cpp, hornetgun.cpp, houndeye.cpp, ichthyosaur.cpp
# islave.cpp, leech.cpp, mp5.cpp, nihilanth.cpp, osprey.cpp, python.cpp
# rat.cpp, roach.cpp, rpg.cpp, satchel.cpp, shotgun.cpp
# squeakgrenade.cpp, tentacle.cpp, tripmine.cpp

# ── Rewolf custom source files ───────────────────────────────────────
# These are the ~366 functions / ~80 KB that make Gunman Chronicles unique.
# They need to be reconstructed from the decompiled output.
set(REWOLF_SOURCES
    # Weapons
    ${CMAKE_CURRENT_SOURCE_DIR}/weapons/fists.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/weapons/aicore.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/weapons/beamgun.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/weapons/dml.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/weapons/dml_grenade.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/weapons/gausspistol.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/weapons/minigun.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/weapons/shotgun_rewolf.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/weapons/chemgun.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/weapons/weapon_customization.cpp
    # Monsters - Dinosaurs
    ${CMAKE_CURRENT_SOURCE_DIR}/monsters/raptor.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/monsters/microraptor.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/monsters/ourano.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/monsters/renesaur.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/monsters/beak.cpp
    # Monsters - Xenomes
    ${CMAKE_CURRENT_SOURCE_DIR}/monsters/xenome.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/monsters/tube.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/monsters/tubequeen.cpp
    # Monsters - Rustbots
    ${CMAKE_CURRENT_SOURCE_DIR}/monsters/rustflier.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/monsters/rustbot.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/monsters/gunner.cpp
    # Monsters - Insects
    ${CMAKE_CURRENT_SOURCE_DIR}/monsters/manta.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/monsters/cricket.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/monsters/dragonfly.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/monsters/butterfly.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/monsters/scorpion.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/monsters/maggot.cpp
    # Monsters - Aquatic
    ${CMAKE_CURRENT_SOURCE_DIR}/monsters/gator.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/monsters/hatchetfish.cpp
    # Monsters - Human NPCs
    ${CMAKE_CURRENT_SOURCE_DIR}/monsters/chopper.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/monsters/demoman.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/monsters/human_gunman.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/monsters/bandit.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/monsters/aigirl.cpp
    # Monsters - Bosses
    ${CMAKE_CURRENT_SOURCE_DIR}/monsters/endboss.cpp
    # Monsters - Other
    ${CMAKE_CURRENT_SOURCE_DIR}/monsters/trainingbot.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/monsters/hologram.cpp
    # Misc Rewolf entities
    ${CMAKE_CURRENT_SOURCE_DIR}/darttrap.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/cluster.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/tank_rewolf.cpp
    # Modified SDK files (Rewolf changed these)
    ${CMAKE_CURRENT_SOURCE_DIR}/client_rewolf.cpp
)

add_library(gunman SHARED ${SDK_SOURCES})
# Rewolf sources will be added once reconstructed:
# target_sources(gunman PRIVATE ${REWOLF_SOURCES})

target_include_directories(gunman PRIVATE
    ${COMMON_INCLUDES}
    ${HL_DLLS_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}
)

target_compile_definitions(gunman PRIVATE
    VALVE_DLL
    QUIVER
    VOXEL
    CLIENT_WEAPONS
)

set_target_properties(gunman PROPERTIES
    OUTPUT_NAME "gunman"
    PREFIX ""
    SUFFIX ".dll"
)
