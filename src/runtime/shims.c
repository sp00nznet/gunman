/*
 * The imports that cannot pass straight through to Windows.
 *
 * Every other import reaches the real export through native_bridge() with no
 * code here. These are the ones where the answer depends on the guest being
 * a mapped image rather than a module Windows loaded: who am I, where am I,
 * what was I started with, and where are my resources.
 *
 * The table and the reason for each: docs/architecture.md, "Hand shims".
 */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <string.h>
#include "recomp_types.h"
#include "modules.h"

#define ARG(n)     MEM32(g_esp + 4 + (n) * 4)
#define ARGS(n)    ((const char*)(uintptr_t)ARG(n))
#define STDRET(k, v) do { g_eax = (uint32_t)(v); g_esp += 4 + (k) * 4; } while (0)

static uint32_t native_proc(const char* dll, const char* name) {
    return (uint32_t)(uintptr_t)GetProcAddress(GetModuleHandleA(dll), name);
}

static void call_native(uint32_t va) { g_native_target = va; native_bridge(); }

/* ---------------------------------------------------------------- identity */

static void s_GetModuleHandleA(void) {
    const char* n = ARGS(0);
    const module_t* m = n ? module_named(n) : &g_modules[0];
    if (m && m->linked) { STDRET(1, m->base); return; }   /* loaded, not just reserved */
    call_native(native_proc("kernel32.dll", "GetModuleHandleA"));
}

static void s_GetModuleFileNameA(void) {
    uint32_t h = ARG(0);
    const module_t* m = h ? module_at(h) : &g_modules[0];
    if (m && h && m->base != h) m = NULL;
    if (m) {
        char* out = (char*)(uintptr_t)ARG(1);
        int n = snprintf(out, ARG(2), "%s\\%s", g_game_dir, m->name);
        STDRET(3, n < 0 ? 0 : n);
        return;
    }
    call_native(native_proc("kernel32.dll", "GetModuleFileNameA"));
}

static void s_GetCommandLineA(void) { STDRET(0, (uintptr_t)g_guest_cmdline); }

/* --press VK@seconds: report a key as held for half a second at that time.
 * The intro polls GetAsyncKeyState(VK_ESCAPE/VK_SPACE), which reads the
 * physical keyboard; injecting here lets a scripted run skip it without
 * pressing a real key on whatever window has the desktop's focus. */
press_t g_press[16];
int g_press_count;

/* --click x,y@seconds: a scripted left click at a point in the game window's
 * client area. VGUI takes the pointer position from GetCursorPos, not from the
 * mouse message, so posting WM_LBUTTONDOWN alone clicks wherever the REAL
 * cursor happens to be. Instead the script owns a virtual cursor that
 * GetCursorPos and GetAsyncKeyState(VK_LBUTTON) report, and the real one is
 * never moved. */
click_t g_click[16];
int g_click_count;
static volatile LONG g_vcur_valid, g_vcur_down;
static POINT g_vcur;                          /* screen coordinates */

static BOOL CALLBACK find_game_window(HWND h, LPARAM out) {
    DWORD pid;
    RECT r;
    GetWindowThreadProcessId(h, &pid);
    if (pid == GetCurrentProcessId() && IsWindowVisible(h) && GetWindowRect(h, &r) &&
        r.right - r.left > 200) {
        *(HWND*)out = h;
        return FALSE;
    }
    return TRUE;
}

static DWORD WINAPI click_script(LPVOID unused) {
    (void)unused;
    for (int i = 0; i < g_click_count; i++) {
        int wait = (int)(g_click[i].at * 1000) - (int)(GetTickCount() - g_start_tick);
        if (wait > 0) Sleep(wait);
        HWND h = NULL;
        EnumWindows(find_game_window, (LPARAM)&h);
        if (!h) { fprintf(stderr, "[click] no game window at %.1fs\n", g_click[i].at); continue; }
        POINT p = { g_click[i].x, g_click[i].y };
        ClientToScreen(h, &p);
        g_vcur = p;
        /* Deliver to the deepest child under the point, as Windows routes a
         * real click: the launcher's menu items are child windows, and a
         * message posted to the frame never reaches them. */
        for (;;) {
            POINT c = p;
            ScreenToClient(h, &c);
            HWND k = ChildWindowFromPointEx(h, c, CWP_SKIPINVISIBLE);
            if (!k || k == h) break;
            h = k;
        }
        POINT c = p;
        ScreenToClient(h, &c);
        LPARAM lp = MAKELPARAM(c.x, c.y);
        InterlockedExchange(&g_vcur_valid, 1);
        PostMessageA(h, WM_MOUSEMOVE, 0, lp);
        Sleep(150);
        InterlockedExchange(&g_vcur_down, 1);
        PostMessageA(h, WM_LBUTTONDOWN, MK_LBUTTON, lp);
        Sleep(120);
        InterlockedExchange(&g_vcur_down, 0);
        PostMessageA(h, WM_LBUTTONUP, 0, lp);
        fprintf(stderr, "[click] %d,%d at %.1fs\n", g_click[i].x, g_click[i].y, g_click[i].at);
    }
    return 0;
}

void start_click_script(void) {
    if (g_click_count) CreateThread(NULL, 0, click_script, NULL, 0, NULL);
}

static void s_GetCursorPos(void) {
    if (g_vcur_valid) {
        POINT* p = (POINT*)(uintptr_t)ARG(0);
        *p = g_vcur;
        STDRET(1, 1);
        return;
    }
    call_native(native_proc("user32.dll", "GetCursorPos"));
}

/* Mouse-look reads the cursor, applies the offset from the window centre, then
 * recentres with SetCursorPos. Once the script owns the cursor, recentring
 * must move the VIRTUAL one: otherwise GetCursorPos reports the last click
 * point forever, every frame applies the same offset, and the view spins off
 * into the void (a black screen). It also keeps the game from moving the real
 * mouse under whoever is at the desktop. */
static void s_SetCursorPos(void) {
    if (g_vcur_valid) {
        g_vcur.x = (LONG)ARG(0);
        g_vcur.y = (LONG)ARG(1);
        STDRET(2, 1);
        return;
    }
    call_native(native_proc("user32.dll", "SetCursorPos"));
}

/* --noddraw: DirectDrawCreate fails, so the launcher presents the software
 * renderer's frames through its GDI fallback. DirectDraw windowed output is
 * invisible to PrintWindow on modern Windows, which made correct frames look
 * black to every screenshot taken so far. */
int g_noddraw;

static void s_DirectDrawCreate(void) {
    if (g_noddraw) { STDRET(3, 0x80004005u); return; }        /* DDERR_GENERIC */
    call_native(native_proc("ddraw.dll", "DirectDrawCreate"));
}

/* A scripted run is never the foreground app -- it starts behind whatever the
 * person at the desktop is using, and posted clicks do not activate a window
 * the way real ones do. The launcher checks GetForegroundWindow every frame
 * and, finding someone else in front, treats the game as inactive: no
 * rendering, just ShowWindow/SetFocus/ClipCursor at ~6,600 calls a second.
 * So once the script owns the cursor, the game's own window is reported as
 * foreground, and ClipCursor -- which would confine the REAL mouse of whoever
 * is at the desktop -- does nothing. */
static void s_GetForegroundWindow(void) {
    if (g_vcur_valid) {
        /* The calling thread's own active window: exactly the window that
         * WOULD be foreground if the game had been clicked into. The launcher
         * compares against its main window and walks GetParent, so the first
         * visible window of the process (the menu) is not good enough. */
        HWND h = GetActiveWindow();
        if (!h) EnumWindows(find_game_window, (LPARAM)&h);
        if (h) { STDRET(0, (uintptr_t)h); return; }
    }
    call_native(native_proc("user32.dll", "GetForegroundWindow"));
}

static void s_ClipCursor(void) {
    if (g_vcur_valid) { STDRET(1, 1); return; }
    call_native(native_proc("user32.dll", "ClipCursor"));
}

/* Same for mouse capture, for the whole of a scripted run: a window holding
 * the capture gets every click as a client click, so the person at the
 * desktop could neither drag it by its caption nor minimize it. Scripted
 * input is posted, so the game never needed the capture. */
static void s_SetCapture(void) {
    if (g_click_count || g_press_count) { STDRET(1, 0); return; }   /* no previous owner */
    call_native(native_proc("user32.dll", "SetCapture"));
}

/* Every message box goes to the log first. The engine's Sys_Error is a
 * MessageBoxA, and an unattended run that only screenshots the process's
 * first big window was scoring that white dialog as "rendered". */
static void s_MessageBoxA(void) {
    const char* text = (const char*)(uintptr_t)ARG(1);
    const char* cap = (const char*)(uintptr_t)ARG(2);
    fprintf(stderr, "[msgbox] %s: %s  (from sub_%08X)\n", cap ? cap : "", text ? text : "",
            g_cur_func);
    fflush(stderr);
    call_native(native_proc("user32.dll", "MessageBoxA"));
}

/* A quiet exit names its caller: an unattended run that simply ends is
 * otherwise indistinguishable from one that was killed. */
static void s_ExitProcess(void) {
    fprintf(stderr, "[exit] ExitProcess(%u) from sub_%08X\n", ARG(0), g_cur_func);
    fflush(stderr);
    call_native(native_proc("kernel32.dll", "ExitProcess"));
}

static void s_GetAsyncKeyState(void) {
    uint32_t vk = ARG(0);
    if (vk == VK_LBUTTON && g_vcur_down) { STDRET(1, 0x8001); return; }
    double t = (GetTickCount() - g_start_tick) / 1000.0;
    for (int i = 0; i < g_press_count; i++)
        if (g_press[i].vk == vk && t >= g_press[i].at && t < g_press[i].at + 0.5) {
            STDRET(1, 0x8001);
            return;
        }
    STDRET(1, (uint16_t)GetAsyncKeyState((int)vk));
}

/* A guest's unhandled-exception filter would be called by Windows mid-crash,
 * through the callback path, with the register file in an unknown state. The
 * runtime's VEH reports the crash instead. */
static void s_SetUnhandledExceptionFilter(void) { STDRET(1, 0); }

/* The launcher's RAM check (0x00412596) is `cmp dwTotalPhys, 0xF00000; jge`,
 * signed. With more than 4 GB installed Windows saturates the field at
 * 0xFFFFFFFF, which reads as -1, and the retail exe refuses to start with
 * "Your system reported only -0.00K of physical memory". Same on the original
 * binary -- this is the period-compatibility fix, not a recompilation one:
 * every size is clamped to 2 GB so a signed reader sees a sane positive. */
static void s_GlobalMemoryStatus(void) {
    MEMORYSTATUS* ms = (MEMORYSTATUS*)(uintptr_t)ARG(0);
    GlobalMemoryStatus(ms);
    SIZE_T* f = &ms->dwTotalPhys;
    for (int i = 0; i < 6; i++)         /* TotalPhys .. AvailVirtual */
        if (f[i] > 0x7FFFFFFFu) f[i] = 0x7FFFFFFFu;
    STDRET(1, 0);
}

/* The software renderer makes its own .text writable before patching it
 * (WinQuake's Sys_MakeCodeWriteable). Guest code is already mapped read/write
 * and must stay NON-executable -- that is what turns a Windows callback into
 * a fault the VEH can redirect -- so a request on a guest range succeeds
 * without touching the protection. */
static void s_VirtualProtect(void) {
    if (module_at(ARG(0))) {
        uint32_t* old = (uint32_t*)(uintptr_t)ARG(3);
        if (old) *old = PAGE_EXECUTE_READWRITE;
        STDRET(4, 1);
        return;
    }
    call_native(native_proc("kernel32.dll", "VirtualProtect"));
}

/* ------------------------------------------------------------ module loading */

static void s_LoadLibraryA(void) {
    const module_t* c = module_named(ARGS(0));
    if (c) {
        module_t* m = (module_t*)c;
        if (!m->lifted) {
            fprintf(stderr, "[not lifted] LoadLibraryA(\"%s\") from sub_%08X -- failing it\n",
                    ARGS(0), g_cur_func);
            STDRET(1, 0);
            return;
        }
        /* Loaded already: one more reference, as the real loader counts. */
        if (m->attached) { m->refs++; STDRET(1, m->base); return; }
        /* Map (fresh, if it was freed) and attach before popping: DllMain
         * runs on this stack. */
        if (m->stale ? !remap_module(m) : (!m->mapped && !map_module(m))) {
            STDRET(1, 0);
            return;
        }
        link_iat(m);
        m->refs = 1;
        attach_module(m);
        STDRET(1, m->base);
        return;
    }
    call_native(native_proc("kernel32.dll", "LoadLibraryA"));
}

static void s_GetProcAddress(void) {
    const module_t* m = module_at(ARG(0));
    if (m && m->base == ARG(0)) {
        uint32_t va = guest_export(m, ARGS(1));
        if (!va) fprintf(stderr, "[link] GetProcAddress(%s, %s) not exported\n", m->name,
                         ARG(1) < 0x10000 ? "#ordinal" : ARGS(1));
        STDRET(2, va);
        return;
    }
    call_native(native_proc("kernel32.dll", "GetProcAddress"));
}

static void s_FreeLibrary(void) {
    module_t* m = (module_t*)module_at(ARG(0));
    if (m && m->base == ARG(0)) {
        /* Boot modules are held by the runtime itself and never unload. */
        if (m->attached && !m->needed_by_boot && --m->refs <= 0) detach_module(m);
        STDRET(1, 1);
        return;
    }
    call_native(native_proc("kernel32.dll", "FreeLibrary"));
}

/* ---------------------------------------------------------------- resources */

/* The exe's resources, loaded as a datafile: our mapping of it is not a
 * module Windows knows, so FindResource on 0x00400000 would find nothing. */
static uint32_t res_module(void) {
    static HMODULE h;
    if (!h) {
        char p[MAX_PATH];
        snprintf(p, sizeof p, "%s\\gunman.exe", g_game_dir);
        h = LoadLibraryExA(p, NULL, LOAD_LIBRARY_AS_DATAFILE);
        if (!h) fprintf(stderr, "[res] cannot open %s for resources\n", p);
    }
    return (uint32_t)(uintptr_t)h;
}

#define RES_SHIM(dll, nm, k) \
    static void s_##nm(void) { \
        static uint32_t f; \
        if (!f) f = native_proc(dll, #nm); \
        if (ARG(k) == GUEST_EXE_BASE) ARG(k) = res_module(); \
        call_native(f); \
    }
RES_SHIM("kernel32.dll", FindResourceA, 0)
RES_SHIM("kernel32.dll", LoadResource, 0)
RES_SHIM("kernel32.dll", SizeofResource, 0)
RES_SHIM("user32.dll", LoadIconA, 0)
RES_SHIM("user32.dll", LoadCursorA, 0)
RES_SHIM("user32.dll", LoadBitmapA, 0)
RES_SHIM("user32.dll", LoadStringA, 0)

/* ------------------------------------------------------------------- table */

typedef struct { const char* name; recomp_func_t fn; uint32_t va; } shim_t;

/* pageheap.c: pass straight through unless --pageheap */
void s_ph_HeapAlloc(void), s_ph_HeapFree(void), s_ph_HeapReAlloc(void), s_ph_HeapSize(void);

#define S(nm) { #nm, s_##nm, 0 }
shim_t g_shims[] = {
    S(GetModuleHandleA), S(GetModuleFileNameA), S(GetCommandLineA),
    S(SetUnhandledExceptionFilter), S(GlobalMemoryStatus), S(GetAsyncKeyState), S(VirtualProtect), S(GetCursorPos), S(SetCursorPos), S(DirectDrawCreate), S(GetForegroundWindow), S(ClipCursor), S(SetCapture), S(MessageBoxA), S(ExitProcess),
    { "HeapAlloc", s_ph_HeapAlloc, 0 }, { "HeapFree", s_ph_HeapFree, 0 },
    { "HeapReAlloc", s_ph_HeapReAlloc, 0 }, { "HeapSize", s_ph_HeapSize, 0 },
    S(LoadLibraryA), S(GetProcAddress), S(FreeLibrary),
    S(FindResourceA), S(LoadResource), S(SizeofResource),
    S(LoadIconA), S(LoadCursorA), S(LoadBitmapA), S(LoadStringA),
};
const int g_shim_count = sizeof g_shims / sizeof g_shims[0];
