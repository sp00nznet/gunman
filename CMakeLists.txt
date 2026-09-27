# =============================================================================
# Gunman Chronicles - static recompilation host
#
#   1. py -3 tools/rebase.py
#   2. disassemble + seed each module (see README "Building from source")
#   3. py -3 run_lift.py                       # -> src/recomp/gen/
#   4. cmake -B build -G Ninja   (from an x86 MSVC prompt: vcvarsall x86)
#      cmake --build build
#   5. build\gunman.exe game
#
# 32-bit on purpose: the lifted code and Windows share one address space, so
# imports pass straight through. See docs/architecture.md.
# =============================================================================
cmake_minimum_required(VERSION 3.20)
project(gunman C)

if(NOT CMAKE_SIZEOF_VOID_P EQUAL 4)
  message(FATAL_ERROR "the host must be 32-bit: configure from an x86 (vcvarsall x86) prompt")
endif()
if(NOT MSVC)
  message(FATAL_ERROR "the native bridge is MSVC x86 inline assembly")
endif()
if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE RelWithDebInfo)
endif()

set(PCRECOMP "${CMAKE_SOURCE_DIR}/../tools" CACHE PATH "pcrecomp checkout")

file(GLOB GEN_SOURCES CONFIGURE_DEPENDS "${CMAKE_SOURCE_DIR}/src/recomp/gen/*.c")
if(NOT GEN_SOURCES)
  message(FATAL_ERROR "src/recomp/gen is empty -- run `py -3 run_lift.py` first")
endif()

add_executable(gunman
  src/runtime/runtime.c
  src/runtime/modules.c
  src/runtime/shims.c
  src/runtime/pageheap.c
  src/runtime/framegrab.c
  src/runtime/present.c
  src/runtime/present_d3d.c
  src/runtime/spans.c
  src/runtime/fixes.c
  ${PCRECOMP}/runtime/recomp32/image_loader.c
  ${GEN_SOURCES}
)
target_include_directories(gunman PRIVATE
  src/runtime src/recomp/gen ${PCRECOMP}/runtime/recomp32)

# RECOMP_RETADDR=0u: a leaked dummy return address reads as a benign zero.
# RECOMP_FLAT_MEMORY: guest VAs are host addresses (every module sits at its
# own base). RECOMP_LOCAL_REGS: lifted bodies keep the registers in locals the
# optimiser can hold in host registers (see recomp_types.h).
# LOCAL_REGS=OFF for diagnostic builds: crash reports print the global
# registers, which are only current when lifted code works on them directly.
option(LOCAL_REGS "lifted functions keep registers in locals" ON)
target_compile_definitions(gunman PRIVATE RECOMP_RETADDR=0u _CRT_SECURE_NO_WARNINGS
                                          RECOMP_FLAT_MEMORY)
if(LOCAL_REGS)
  target_compile_definitions(gunman PRIVATE RECOMP_LOCAL_REGS)
endif()

# The guest owns 0x00400000 (gunman.exe), 0x0A000000 (vgui), 0x0B000000
# (client) and 0x10000000 (sw.dll); the host has to sit clear of all of them.
# /NXCOMPAT is load-bearing: the callback path depends on DEP faulting when
# Windows calls into the guest's original (non-executable) code.
# /MANIFESTUAC:NO is too: the retail exe has no manifest, so Windows gives it
# UAC registry virtualisation, and its first act is RegCreateKeyExA on
# HKLM\Software\Aureal\A3D. With an asInvoker manifest that is ACCESS_DENIED
# and the launcher quits before it opens a window.
target_link_options(gunman PRIVATE /BASE:0x60000000 /FIXED:NO /DYNAMICBASE:NO
                                   /NXCOMPAT /LARGEADDRESSAWARE /STACK:0x1000000
                                   /MANIFESTUAC:NO)
# Generated code: warnings are noise; the lift's own error count is the signal.
# /O2 costs about 2 s per 60K-line file and runs the game several times faster
# than /Od; GEN_OPT=/Od is for stepping through generated C in a debugger.
set(GEN_OPT "/O2" CACHE STRING "optimisation for the generated C")
set_source_files_properties(${GEN_SOURCES} PROPERTIES COMPILE_OPTIONS "/w;${GEN_OPT}")
set_source_files_properties(src/runtime/runtime.c src/runtime/modules.c src/runtime/shims.c
  src/runtime/pageheap.c src/runtime/framegrab.c src/runtime/present.c
  src/runtime/present_d3d.c src/runtime/spans.c src/runtime/fixes.c
  PROPERTIES COMPILE_OPTIONS "/W3;/wd4996")
target_link_libraries(gunman PRIVATE user32 gdi32 kernel32 dbghelp dxguid winmm d3d11 dxgi)
