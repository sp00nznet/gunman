# Gunman Chronicles Client DLL (client.dll)
# Original: rewolf/cl_dlls/client.dll (552 KB, MSVC 6.0, Nov 2000)
# Contains: HUD, weapon prediction, effects, VGUI menus

set(HL_CL_DLL_DIR "${HL_SDK_DIR}/cl_dll")
set(HL_DLLS_DIR "${HL_SDK_DIR}/dlls")

# ── SDK source files (from Half-Life SDK 2.3) ────────────────────────
set(SDK_SOURCES
    ${HL_CL_DLL_DIR}/ammo.cpp
    ${HL_CL_DLL_DIR}/ammo_secondary.cpp
    ${HL_CL_DLL_DIR}/ammohistory.cpp
    ${HL_CL_DLL_DIR}/battery.cpp
    ${HL_CL_DLL_DIR}/cdll_int.cpp
    ${HL_CL_DLL_DIR}/com_weapons.cpp
    ${HL_CL_DLL_DIR}/death.cpp
    ${HL_CL_DLL_DIR}/demo.cpp
    ${HL_CL_DLL_DIR}/entity.cpp
    ${HL_CL_DLL_DIR}/ev_common.cpp
    ${HL_CL_DLL_DIR}/events.cpp
    ${HL_CL_DLL_DIR}/flashlight.cpp
    ${HL_CL_DLL_DIR}/GameStudioModelRenderer.cpp
    ${HL_CL_DLL_DIR}/geiger.cpp
    ${HL_CL_DLL_DIR}/health.cpp
    ${HL_CL_DLL_DIR}/hud.cpp
    ${HL_CL_DLL_DIR}/hud_msg.cpp
    ${HL_CL_DLL_DIR}/hud_redraw.cpp
    ${HL_CL_DLL_DIR}/hud_spectator.cpp
    ${HL_CL_DLL_DIR}/hud_update.cpp
    ${HL_CL_DLL_DIR}/in_camera.cpp
    ${HL_CL_DLL_DIR}/input.cpp
    ${HL_CL_DLL_DIR}/inputw32.cpp
    ${HL_CL_DLL_DIR}/menu.cpp
    ${HL_CL_DLL_DIR}/message.cpp
    # overview.cpp excluded -- SDK version has API incompatibilities, Gunman has custom version
    ${HL_CL_DLL_DIR}/saytext.cpp
    ${HL_CL_DLL_DIR}/status_icons.cpp
    ${HL_CL_DLL_DIR}/statusbar.cpp
    ${HL_CL_DLL_DIR}/StudioModelRenderer.cpp
    ${HL_CL_DLL_DIR}/text_message.cpp
    ${HL_CL_DLL_DIR}/train.cpp
    ${HL_CL_DLL_DIR}/tri.cpp
    ${HL_CL_DLL_DIR}/util.cpp
    ${HL_CL_DLL_DIR}/view.cpp
    # HL weapons prediction
    ${HL_CL_DLL_DIR}/hl/hl_baseentity.cpp
    ${HL_CL_DLL_DIR}/hl/hl_events.cpp
    ${HL_CL_DLL_DIR}/hl/hl_objects.cpp
    ${HL_CL_DLL_DIR}/hl/hl_weapons.cpp
    # Shared code
    ${HL_PM_SHARED_DIR}/pm_debug.c
    ${HL_PM_SHARED_DIR}/pm_math.c
    ${HL_PM_SHARED_DIR}/pm_shared.c
)

# ── Rewolf custom source files ───────────────────────────────────────
# Client-side Rewolf code: ~133 functions / ~39 KB
set(REWOLF_SOURCES
    ${CMAKE_CURRENT_SOURCE_DIR}/ev_gunman.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/hud_rewolf.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/weapon_predict_rewolf.cpp
)

add_library(client SHARED ${SDK_SOURCES})
# Rewolf sources will be added once reconstructed:
# target_sources(client PRIVATE ${REWOLF_SOURCES})

target_include_directories(client PRIVATE
    ${COMMON_INCLUDES}
    ${HL_CL_DLL_DIR}
    ${HL_DLLS_DIR}
    ${HL_SDK_DIR}/utils/vgui/include
    ${HL_SDK_DIR}/external
    ${CMAKE_CURRENT_SOURCE_DIR}
)

target_compile_definitions(client PRIVATE
    CLIENT_DLL
    CLIENT_WEAPONS
)

set_target_properties(client PROPERTIES
    OUTPUT_NAME "client"
    PREFIX ""
    SUFFIX ".dll"
)
