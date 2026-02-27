cmake_minimum_required(VERSION 3.20)
project(GunmanChronicles VERSION 1.0.0 LANGUAGES CXX C)

# Gunman Chronicles Static Recompilation
# Builds two DLLs: gunman.dll (server) and client.dll (client)
# Based on Half-Life SDK 2.3 with Rewolf Software modifications

set(CMAKE_CXX_STANDARD 14)  # MSVC 6.0 era code, C++14 is generous
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

# Platform check -- currently Windows-only (matching original target)
if(NOT WIN32)
    message(WARNING "Gunman Chronicles was Windows-only. Cross-platform support is a future goal.")
endif()

# Compiler settings to approximate MSVC 6.0 behavior
if(MSVC)
    add_compile_options(
        /W3          # Warning level 3 (original likely used default)
        /MP          # Multi-processor compilation
        /EHsc        # C++ exception handling
        /wd4996      # Disable deprecation warnings for old CRT functions
        /wd4244      # Disable narrowing conversion warnings (rampant in HL SDK)
        /wd4305      # Disable double->float truncation warnings
    )
    add_compile_definitions(
        _CRT_SECURE_NO_WARNINGS
        WIN32
        _WINDOWS
    )
elseif(CMAKE_CXX_COMPILER_ID MATCHES "Clang|GNU")
    add_compile_options(
        -Wall
        -Wno-unused-variable
        -Wno-unused-function
        -Wno-narrowing
        -Wno-write-strings
    )
endif()

# ── Half-Life SDK paths ──────────────────────────────────────────────
set(HL_SDK_DIR "${CMAKE_SOURCE_DIR}/ref/halflife-sdk")
set(HL_ENGINE_DIR "${HL_SDK_DIR}/engine")
set(HL_COMMON_DIR "${HL_SDK_DIR}/common")
set(HL_PUBLIC_DIR "${HL_SDK_DIR}/public")
set(HL_PM_SHARED_DIR "${HL_SDK_DIR}/pm_shared")
set(HL_GAME_SHARED_DIR "${HL_SDK_DIR}/game_shared")

# Common include directories shared by both DLLs
set(COMMON_INCLUDES
    ${HL_ENGINE_DIR}
    ${HL_COMMON_DIR}
    ${HL_PUBLIC_DIR}
    ${HL_PM_SHARED_DIR}
    ${HL_GAME_SHARED_DIR}
)

# ── Server DLL (gunman.dll) ──────────────────────────────────────────
add_subdirectory(src/server)

# ── Client DLL (client.dll) ──────────────────────────────────────────
add_subdirectory(src/client)
