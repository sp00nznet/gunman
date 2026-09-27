/* The module table. Keep in step with tools/rebase.py and run_lift.py. */
#include <windows.h>
#include "modules.h"

char g_rebased_dir[MAX_PATH];

module_t g_modules[] = {
    /* the process image first */
    { "gunman.exe", "gunman.exe", 0x00400000u, 1, 1 },
    { "vgui.dll",   "vgui.dll",   0x0A000000u, 1, 1 },
    /* Loaded on New game: the launcher loads the engine, the engine loads
     * the client and server game DLLs. Mapped and attached on LoadLibrary. */
    { "sw.dll",     "sw.dll",     0x10000000u, 1, 0 },
    { "client.dll", "client.dll", 0x0B000000u, 1, 0 },
    { "gunman.dll", "gunman.dll", 0x0C000000u, 1, 0 },
    /* The OpenGL engine: not lifted. EngineType=1 (software) never asks for it. */
    { "hw.dll",     NULL,         0,           0, 0 },
};
const int g_module_count = sizeof g_modules / sizeof g_modules[0];
