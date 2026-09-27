/*
 * Gunman Chronicles recompilation - host runtime.
 *
 * A 32-bit host. That is the one deliberate departure from Force Commander's
 * 64-bit host, and everything else in this file follows from it: with the
 * lifted code and the host sharing one 32-bit address space, a Win32 struct
 * the game builds is already the struct Windows expects, so an import needs no
 * marshalling and no hand-written body. See docs/architecture.md.
 *
 *   guest -> Windows   native_bridge(): copy the argument window to the host
 *                      stack, call the real export, and measure how far the
 *                      callee moved ESP. That measurement IS the purge count,
 *                      so no argc table is needed (stdcall, cdecl, thiscall and
 *                      COM methods all come out right).
 *   Windows -> guest   The original .text is mapped non-executable. When
 *                      Windows calls a guest WndProc / thread start / hook, the
 *                      CPU faults on it, the VEH moves EIP to cb_tramp, and the
 *                      lifted body runs on the guest stack.
 *   guest threads      One machine lock (Force Commander's shims_impl.c
 *                      pattern): a thread owns the register file while it runs
 *                      lifted code and hands it back around every native call.
 */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <dbghelp.h>
#include <mmsystem.h>   /* timeBeginPeriod, for --profile */
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include "recomp_types.h"
#include "image_loader.h"
#include "modules.h"

/* ------------------------------------------------------------ register file */

uint32_t  g_eax, g_ecx, g_edx, g_esp, g_ebx, g_esi, g_edi, g_ebp;
double    g_st[8];
int       g_fp_top;
uint16_t  g_fpu_cw = 0x027F;
uint16_t  g_seg_cs, g_seg_ds, g_seg_es, g_seg_fs, g_seg_gs, g_seg_ss;
uint64_t  g_mm[8];
uint32_t  g_fs_base, g_gs_base;
ptrdiff_t g_mem_base = 0;
uint32_t  g_cur_func;
uint32_t  g_icall_trace[ICALL_TRACE_SIZE], g_icall_from[ICALL_TRACE_SIZE];
uint32_t  g_icall_trace_idx, g_icall_count;

typedef struct {
    uint32_t eax, ecx, edx, esp, ebx, esi, edi, ebp, fs, cur;
    double   st[8];
    int      fp_top;
    uint16_t fpu_cw;
    uint64_t mm[8];
} regs_t;

static void regs_save(regs_t* r) {
    r->eax = g_eax; r->ecx = g_ecx; r->edx = g_edx; r->esp = g_esp;
    r->ebx = g_ebx; r->esi = g_esi; r->edi = g_edi; r->ebp = g_ebp;
    r->fs = g_fs_base; r->cur = g_cur_func;
    memcpy(r->st, g_st, sizeof g_st); r->fp_top = g_fp_top; r->fpu_cw = g_fpu_cw;
    memcpy(r->mm, g_mm, sizeof g_mm);
}

static void regs_load(const regs_t* r) {
    g_eax = r->eax; g_ecx = r->ecx; g_edx = r->edx; g_esp = r->esp;
    g_ebx = r->ebx; g_esi = r->esi; g_edi = r->edi; g_ebp = r->ebp;
    g_fs_base = r->fs; g_cur_func = r->cur;
    memcpy(g_st, r->st, sizeof g_st); g_fp_top = r->fp_top; g_fpu_cw = r->fpu_cw;
    memcpy(g_mm, r->mm, sizeof g_mm);
}

/* ------------------------------------------------------------- machine lock */

static CRITICAL_SECTION g_mach;
static DWORD g_mach_tls = TLS_OUT_OF_INDEXES;

#define GUEST_STACK (1u << 20)

/* A guest thread's fake TIB. Lifted code reads fs:[n] as MEM32(g_fs_base+n);
 * the real TEB stays the host's, so a guest SEH frame never lands on a chain
 * Windows will walk. */
static uint32_t make_tib(uint32_t stack_lo, uint32_t stack_hi) {
    uint32_t* t = (uint32_t*)VirtualAlloc(NULL, 0x1000, MEM_COMMIT | MEM_RESERVE,
                                          PAGE_READWRITE);
    t[0] = 0xFFFFFFFFu;                          /* ExceptionList: end of chain */
    t[1] = stack_hi;                             /* StackBase                   */
    t[2] = stack_lo;                             /* StackLimit                  */
    t[0x18 / 4] = (uint32_t)(uintptr_t)t;        /* Self                        */
    t[0x24 / 4] = GetCurrentThreadId();
    t[0x30 / 4] = __readfsdword(0x30);           /* the real PEB                */
    return (uint32_t)(uintptr_t)t;
}

typedef struct { regs_t r; int depth; } mstate;

/* Claim the register file for this thread. Nests: a callback that arrives
 * while this thread is inside a native call claims again, and only the
 * outermost claim loads the saved state. */
void mach_enter(void) {
    EnterCriticalSection(&g_mach);
    mstate* m = (mstate*)TlsGetValue(g_mach_tls);
    if (!m) {
        /* First lifted code on a thread Windows started for the guest. */
        m = (mstate*)calloc(1, sizeof *m);
        uint32_t lo = (uint32_t)(uintptr_t)VirtualAlloc(NULL, GUEST_STACK,
                          MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        m->r.esp = lo + GUEST_STACK - 64;
        m->r.fs = make_tib(lo, lo + GUEST_STACK);
        m->r.fpu_cw = 0x027F;
        TlsSetValue(g_mach_tls, m);
    }
    if (m->depth++ == 0) regs_load(&m->r);
}

void mach_leave(void) {
    mstate* m = (mstate*)TlsGetValue(g_mach_tls);
    if (--m->depth == 0) regs_save(&m->r);
    LeaveCriticalSection(&g_mach);
}

/* ---------------------------------------------------------------- dispatch */

/* A module run as its ORIGINAL code (--native): nothing in it dispatches to
 * lifted C, and a call into it is a native call. */
static int in_native_module(uint32_t va) {
    const module_t* m = module_at(va);
    return m && m->native;
}

/* Hits only: the span drawer alone makes an indirect jump every 8 pixels
 * (Quake's entry vector), and a module scan plus a binary search over 22K
 * entries each time was a measurable share of the frame. A hit is only ever
 * stored for a lifted, non-native module, and which modules are native is
 * fixed at startup. */
#define LOOKUP_CACHE 4096u
static struct { uint32_t va; recomp_func_t fn; } g_lookup_cache[LOOKUP_CACHE];

recomp_func_t recomp_lookup(uint32_t va) {
    uint32_t slot = (va ^ (va >> 12)) & (LOOKUP_CACHE - 1);
    if (g_lookup_cache[slot].va == va && g_lookup_cache[slot].fn)
        return g_lookup_cache[slot].fn;
    if (in_native_module(va)) return NULL;
    uint32_t lo = 0, hi = recomp_dispatch_count;
    while (lo < hi) {
        uint32_t mid = lo + (hi - lo) / 2;
        uint32_t m = recomp_dispatch_table[mid].address;
        if (m == va) {
            g_lookup_cache[slot].fn = NULL;          /* never a torn pair */
            g_lookup_cache[slot].va = va;
            g_lookup_cache[slot].fn = recomp_dispatch_table[mid].func;
            return recomp_dispatch_table[mid].func;
        }
        if (m < va) lo = mid + 1; else hi = mid;
    }
    return NULL;
}

recomp_func_t recomp_lookup_manual(uint32_t va) { (void)va; return NULL; }

const module_t* module_at(uint32_t va) {
    for (int i = 0; i < g_module_count; i++)
        if (g_modules[i].mapped && va >= g_modules[i].base &&
            va < g_modules[i].base + g_modules[i].span)
            return &g_modules[i];
    return NULL;
}

/* -------------------------------------------------------- guest -> Windows */

/* Arguments copied per native call. The widest Win32 call on the menu path is
 * CreateFontA at 14; reading past a callee's real arguments is harmless. */
#define BRIDGE_SLOTS 24

uint32_t g_native_target;

/* Synthetic VAs for hand-written imports: a reserved, never-committed page, so
 * no real code or data can share an address with one. */
static uint32_t g_shim_page;
#define IS_SHIM_VA(va) (g_shim_page && (va) >= g_shim_page && (va) < g_shim_page + 0x10000u)

/* --imports: every native call by name. The names come from the IAT at link
 * time; a native address the guest got from GetProcAddress or a COM vtable
 * prints as a bare address. */
static int g_trace_imports;
static uint32_t g_trace_lo, g_trace_hi = 0xFFFFFFFFu;   /* --imports-from */
typedef struct { uint32_t va; const char* name; } native_name_t;
static native_name_t g_native_names[2048];
static int g_native_name_count;

/* --import-stats: count native calls per target, cheaply, for the watchdog
 * to report. Printing every call (--imports) slows the game enough that
 * timed input misses its moment; counting does not. */
static int g_import_stats;
static const char* g_trace_name;   /* --trace-import NAME[@S] */
static double g_trace_after;
static volatile LONG g_trace_name_n;
#define STAT_SLOTS 4096
static volatile LONG g_stat_n[STAT_SLOTS];
static uint32_t g_stat_fn[STAT_SLOTS];

static void stat_count(uint32_t fn) {
    uint32_t h = (fn * 2654435761u) >> 20;
    for (int i = 0; i < 64; i++, h = (h + 1) & (STAT_SLOTS - 1)) {
        if (g_stat_fn[h] == fn) { InterlockedIncrement(&g_stat_n[h]); return; }
        if (!g_stat_fn[h]) { g_stat_fn[h] = fn; InterlockedIncrement(&g_stat_n[h]); return; }
    }
}

static const char* native_name(uint32_t va);

static void stat_report(void) {
    for (int k = 0; k < 12; k++) {             /* top 12, then reset */
        int best = -1;
        for (int i = 0; i < STAT_SLOTS; i++)
            if (g_stat_n[i] && (best < 0 || g_stat_n[i] > g_stat_n[best])) best = i;
        if (best < 0) break;
        const char* n = native_name(g_stat_fn[best]);
        fprintf(stderr, "    %8ld  %s", g_stat_n[best], n ? n : "?");
        if (!n) fprintf(stderr, " @%08X", g_stat_fn[best]);
        fprintf(stderr, "\n");
        g_stat_n[best] = 0;
    }
    memset((void*)g_stat_n, 0, sizeof g_stat_n);
}

static const char* native_name(uint32_t va) {
    for (int i = 0; i < g_native_name_count; i++)
        if (g_native_names[i].va == va) return g_native_names[i].name;
    return NULL;
}

/* The body of a --native-range thunk: run the original code at va. */
/* The body of a --native-range thunk: run the original code at va, like an
 * import (on the host stack). find_bad_lift.py keeps R_Init and R_RenderView
 * out of the native ranges, because the engine checks that they run on the
 * same stack (docs/ingame.md). */
void recomp_native_call(uint32_t va) {
    g_native_target = va;
    native_bridge();
}

void native_bridge(void) {
    uint32_t fn = g_native_target;
    uint32_t* src = (uint32_t*)(uintptr_t)(g_esp + 4);  /* past the dummy ret */
    uint32_t this_ecx = g_ecx, r_eax, r_edx, purge;
    uint16_t sw0, sw1;
    double r_st = 0;
    int traced = g_trace_imports && g_cur_func >= g_trace_lo && g_cur_func < g_trace_hi;
    if (traced) {
        const char* n = native_name(fn);
        fprintf(stderr, "[native] %-28s (%08X %08X %08X %08X) from sub_%08X",
                n ? n : "?", src[0], src[1], src[2], src[3], g_cur_func);
        if (!n) fprintf(stderr, " @%08X", fn);
        for (int k = 0; k < 4; k++) {       /* show arguments that are strings */
            MEMORY_BASIC_INFORMATION mbi;
            const char* p = (const char*)(uintptr_t)src[k];
            if (src[k] < 0x10000 || !VirtualQuery(p, &mbi, sizeof mbi) ||
                mbi.State != MEM_COMMIT || (mbi.Protect & (PAGE_NOACCESS | PAGE_GUARD)))
                continue;
            size_t room = (const char*)mbi.BaseAddress + mbi.RegionSize - p, len = 0;
            while (len < room && len < 80 && p[len] >= 0x20 && p[len] < 0x7F) len++;
            if (len >= 3 && (len == room || len == 80 || !p[len]))
                fprintf(stderr, " a%d=\"%.*s\"", k, (int)len, p);
        }
    }
    framegrab_check(fn, src);
    if (g_import_stats) stat_count(fn);
    if (g_trace_name) {
        const char* n = native_name(fn);
        if (n && !strcmp(n, g_trace_name) &&
            (GetTickCount() - g_start_tick) / 1000.0 >= g_trace_after &&
            InterlockedIncrement(&g_trace_name_n) <= 60)
            fprintf(stderr, "[trace] %s(%08X %08X %08X %08X) from sub_%08X  %.1fs"
                            "  esp=%08X ret=%08X tid=%lu\n", n,
                    src[0], src[1], src[2], src[3], g_cur_func,
                    (GetTickCount() - g_start_tick) / 1000.0, g_esp, src[-1],
                    GetCurrentThreadId());
    }
    mach_leave();
    __asm {
        mov  esi, src
        sub  esp, BRIDGE_SLOTS * 4
        mov  edi, esp
        mov  ecx, BRIDGE_SLOTS
        cld
        rep  movsd
        mov  ebx, esp            ; callee-saved: survives the call
        fnstsw ax
        mov  sw0, ax             ; x87 TOP before
        mov  ecx, this_ecx       ; thiscall / COM 'this'
        call fn
        mov  r_eax, eax
        mov  r_edx, edx
        mov  eax, esp
        sub  eax, ebx            ; bytes the callee popped
        mov  purge, eax
        lea  esp, [ebx + BRIDGE_SLOTS * 4]
        fxam                     ; C3..C0 say whether st(0) holds anything
        fnstsw ax
        mov  sw1, ax             ; x87 TOP after, and the fxam class
    }
    /* A float/double result comes back in st(0): TOP moved down by one. Move
     * it onto the lifted code's x87 stack, where its caller will fstp it. */
    /* ...and only if that st(0) is a value: fxam's "empty" is C3=1,C0=1.
     * A native fninit/_fpreset also moves TOP (to 0), and without this check
     * that read as a returned float, pushed junk onto the lifted stack, and
     * every later frame rendered NaNs -- a black screen. */
    int st_ret = (((sw0 >> 11) - (sw1 >> 11)) & 7) == 1 &&
                 (sw1 & 0x4100) != 0x4100;
    if (st_ret) __asm fstp r_st      /* pop it off the host stack right away */
    mach_enter();
    if (st_ret) fp_push_impl(g_st, &g_fp_top, r_st);
    if (st_ret && getenv("GM_STLOG")) {   /* TEMP */
        static int n;
        if (n++ < 40) fprintf(stderr, "[st0] %08X -> %g from sub_%08X (sw %04X->%04X)\n",
                              fn, r_st, g_cur_func, sw0, sw1);
    }
    g_eax = r_eax;
    g_edx = r_edx;
    g_esp += 4 + purge;
    if (traced) fprintf(stderr, " -> %08X\n", r_eax);
}

/* Hand-written imports, keyed by the IAT slot's synthetic VA (see link_iat). */
typedef struct { const char* name; recomp_func_t fn; uint32_t va; } shim_t;
extern shim_t g_shims[];
extern const int g_shim_count;

recomp_func_t recomp_lookup_import(uint32_t va) {
    for (int i = 0; i < g_shim_count; i++)
        if (g_shims[i].va == va) return g_shims[i].fn;
    if ((!module_at(va) || in_native_module(va)) && va >= 0x10000u) {
        g_native_target = va;
        return native_bridge;
    }
    return NULL;
}

/* ------------------------------------------------------- Windows -> guest */

/* Runs a lifted function for a native caller. `sp` points at the native
 * caller's [ret][args...]. Returns eax in the low half and the bytes the
 * callee popped in the high half, for cb_tramp's variable `ret n`. */
static int g_trace_callbacks;      /* --callbacks */

static uint64_t __cdecl cb_run(uint32_t va, uint32_t* sp, uint32_t ecx) {
    /* A lifted function, or a hand shim called from --native code. */
    recomp_func_t f = IS_SHIM_VA(va) ? recomp_lookup_import(va) : recomp_lookup(va);
    if (g_trace_callbacks && !(sp[2] == WM_TIMER || sp[2] == WM_NCHITTEST ||
                               sp[2] == WM_SETCURSOR))
        fprintf(stderr, "[callback] sub_%08X (%08X %08X %08X %08X)\n",
                va, sp[1], sp[2], sp[3], sp[4]);
    mach_enter();
    regs_t saved;
    regs_save(&saved);
    g_esp -= BRIDGE_SLOTS * 4;
    memcpy((void*)(uintptr_t)g_esp, sp + 1, BRIDGE_SLOTS * 4);
    PUSH32(g_esp, RECOMP_RETADDR);
    uint32_t before = g_esp;
    g_ecx = ecx;
    f();
    uint32_t eax = g_eax, purge = g_esp - before - 4;
    /* The other half of native_bridge's st(0) transfer: a lifted function
     * that returns a float leaves it on the LIFTED x87 stack, and the native
     * caller is about to fstp its own. Without this the host stack underflows
     * into garbage and drifts, and every later TOP comparison misfires. */
    int st_ret = g_fp_top == saved.fp_top + 1;
    double cb_st = g_st[0];
    regs_load(&saved);
    mach_leave();
    if (st_ret) __asm fld cb_st      /* left in host st(0) for the caller;
                                        nothing after this touches the FPU */
    return ((uint64_t)purge << 32) | eax;
}

static __declspec(naked) void cb_tramp(void) {
    __asm {
        mov  edx, esp            ; [ret][args]
        push ecx
        push edx
        push eax                 ; the guest VA, planted by the VEH
        call cb_run
        add  esp, 12
        pop  ecx                 ; native return address
        add  esp, edx            ; pop what the guest callee popped
        jmp  ecx
    }
}

static int g_crashed;

static void dump_icalls(void) {
    fprintf(stderr, "  last indirect calls (newest first):\n");
    for (int i = 1; i <= 12 && i <= (int)g_icall_trace_idx; i++) {
        uint32_t k = (g_icall_trace_idx - i) & (ICALL_TRACE_SIZE - 1);
        fprintf(stderr, "    0x%08X  from 0x%08X\n", g_icall_trace[k], g_icall_from[k]);
    }
}

/* --watch VA: who writes these 16 bytes? The page is read-only; a write
 * faults here, is logged when it lands in the window (with the lifted
 * function doing it and the value it left), and is single-stepped through
 * with the page writable. A diagnostic: every write to the page traps. */
static uint32_t g_watch, g_watch_hit;
static DWORD g_watch_old;

static int watch_event(EXCEPTION_POINTERS* ep) {
    EXCEPTION_RECORD* er = ep->ExceptionRecord;
    uint32_t page = g_watch & ~0xFFFu;
    if (er->ExceptionCode == EXCEPTION_ACCESS_VIOLATION && er->ExceptionInformation[0] == 1 &&
        (er->ExceptionInformation[1] & ~0xFFFu) == page) {
        g_watch_hit = (uint32_t)er->ExceptionInformation[1];
        VirtualProtect((void*)(uintptr_t)page, 4096, PAGE_READWRITE, &g_watch_old);
        ep->ContextRecord->EFlags |= 0x100;             /* step the store */
        return 1;
    }
    if (er->ExceptionCode == EXCEPTION_SINGLE_STEP && g_watch_hit) {
        if (g_watch_hit >= g_watch && g_watch_hit < g_watch + 16)
            fprintf(stderr, "[watch] %5.1fs  [0x%08X] = %08X  by sub_%08X\n",
                    (GetTickCount() - g_start_tick) / 1000.0, g_watch_hit,
                    *(uint32_t*)(uintptr_t)(g_watch_hit & ~3u), g_cur_func);
        g_watch_hit = 0;
        VirtualProtect((void*)(uintptr_t)page, 4096, PAGE_READONLY, &g_watch_old);
        return 1;
    }
    return 0;
}

/* --writers S (diagnostic): at S seconds, which lifted functions write into
 * the engine's surface cache (sc_base 0x10528D90, size 0x10528D94)? The range
 * goes read-only for 3 s; each write is counted against g_cur_func and
 * single-stepped. Only the surface builders should appear. */
static double g_writers_at;
static uint32_t g_wr_baseptr = 0x10528D90u, g_wr_sizeptr = 0x10528D94u;
static volatile uint32_t g_wr_lo, g_wr_hi, g_wr_page;
static uint32_t g_wr_va[256], g_wr_n[256], g_wr_min[256], g_wr_max[256];

static int writers_event(EXCEPTION_POINTERS* ep) {
    EXCEPTION_RECORD* er = ep->ExceptionRecord;
    DWORD old;
    if (er->ExceptionCode == EXCEPTION_ACCESS_VIOLATION && er->ExceptionInformation[0] == 1) {
        uint32_t a = (uint32_t)er->ExceptionInformation[1];
        if (a < g_wr_lo || a >= g_wr_hi) return 0;
        for (int i = 0; i < 256; i++)
            if (g_wr_va[i] == g_cur_func || !g_wr_va[i]) {
                if (!g_wr_va[i]) g_wr_min[i] = g_wr_max[i] = a;
                g_wr_va[i] = g_cur_func; g_wr_n[i]++;
                if (a < g_wr_min[i]) g_wr_min[i] = a;
                if (a > g_wr_max[i]) g_wr_max[i] = a;
                break;
            }
        g_wr_page = a & ~0xFFFu;
        VirtualProtect((void*)(uintptr_t)g_wr_page, 4096, PAGE_READWRITE, &old);
        ep->ContextRecord->EFlags |= 0x100;
        return 1;
    }
    if (er->ExceptionCode == EXCEPTION_SINGLE_STEP && g_wr_page) {
        if (g_wr_hi) VirtualProtect((void*)(uintptr_t)g_wr_page, 4096, PAGE_READONLY, &old);
        g_wr_page = 0;
        return 1;
    }
    return 0;
}

static DWORD WINAPI writers_thread(LPVOID unused) {
    (void)unused;
    DWORD old;
    Sleep((DWORD)(g_writers_at * 1000));
    uint32_t base = *(volatile uint32_t*)(uintptr_t)g_wr_baseptr;
    uint32_t size = *(volatile uint32_t*)(uintptr_t)g_wr_sizeptr;
    uint32_t lo = (base + 0xFFF) & ~0xFFFu, hi = (base + size) & ~0xFFFu;
    fprintf(stderr, "[writers] 0x%08X +0x%X: watching 3 s (zbuffer 0x%08X, surface cache 0x%08X +0x%X)\n",
            base, size, *(volatile uint32_t*)(uintptr_t)0x100D7F44u,
            *(volatile uint32_t*)(uintptr_t)0x10528D90u, *(volatile uint32_t*)(uintptr_t)0x10528D94u);
    if (!base || hi <= lo) return 0;
    g_wr_lo = lo; g_wr_hi = hi;
    VirtualProtect((void*)(uintptr_t)lo, hi - lo, PAGE_READONLY, &old);
    Sleep(3000);
    g_wr_hi = 0;
    VirtualProtect((void*)(uintptr_t)lo, hi - lo, PAGE_READWRITE, &old);
    for (int i = 0; i < 256 && g_wr_va[i]; i++)
        fprintf(stderr, "[writers] %8u  sub_%08X  0x%08X..0x%08X\n", g_wr_n[i], g_wr_va[i], g_wr_min[i], g_wr_max[i]);
    return 0;
}

static LONG CALLBACK veh(EXCEPTION_POINTERS* ep) {
    EXCEPTION_RECORD* er = ep->ExceptionRecord;
    uint32_t pc = (uint32_t)(uintptr_t)er->ExceptionAddress;
    if (g_watch && watch_event(ep)) return EXCEPTION_CONTINUE_EXECUTION;
    if (g_writers_at > 0 && writers_event(ep)) return EXCEPTION_CONTINUE_EXECUTION;
    if (er->ExceptionCode == EXCEPTION_ACCESS_VIOLATION &&
        er->ExceptionInformation[0] == 8 && (module_at(pc) || IS_SHIM_VA(pc))) {
        if (recomp_lookup(pc) || IS_SHIM_VA(pc)) {
            ep->ContextRecord->Eax = pc;
            ep->ContextRecord->Eip = (DWORD)(uintptr_t)cb_tramp;
            return EXCEPTION_CONTINUE_EXECUTION;
        }
        fprintf(stderr, "[callback] Windows called guest 0x%08X, which was not lifted\n", pc);
    }
    if (er->ExceptionCode == 0x406D1388u /* thread naming */ ||
        er->ExceptionCode == DBG_PRINTEXCEPTION_C ||
        er->ExceptionCode == 0x4001000Au /* wide OutputDebugString */)
        return EXCEPTION_CONTINUE_SEARCH;
    if (!g_crashed++ &&
        (er->ExceptionCode & 0xF0000000u) == 0xC0000000u) {
        fprintf(stderr, "\n[crash] code 0x%08X at 0x%08X", er->ExceptionCode, pc);
        if (er->ExceptionCode == EXCEPTION_ACCESS_VIOLATION)
            fprintf(stderr, " (%s 0x%08X)",
                    er->ExceptionInformation[0] ? "write" : "read",
                    (uint32_t)er->ExceptionInformation[1]);
        fprintf(stderr, "\n  in lifted sub_%08X  eax=%08X ecx=%08X edx=%08X esp=%08X ebp=%08X esi=%08X edi=%08X\n",
                g_cur_func, g_eax, g_ecx, g_edx, g_esp, g_ebp, g_esi, g_edi);
        /* The host PC as generated-C file:line -- which guest instruction faulted,
         * since every generated line carries its guest VA in a comment. */
        IMAGEHLP_LINE64 ln = { sizeof ln };
        DWORD disp;
        SymInitialize(GetCurrentProcess(), NULL, TRUE);
        if (SymGetLineFromAddr64(GetCurrentProcess(), (DWORD64)ep->ContextRecord->Eip, &disp, &ln))
            fprintf(stderr, "  host pc %s:%lu\n", ln.FileName, ln.LineNumber);
        dump_icalls();
        fflush(stderr);
    }
    return EXCEPTION_CONTINUE_SEARCH;
}

/* --watchdog N: every N seconds, which lifted function holds the machine and
 * how many indirect calls ran since the last report. A hang with the count
 * still climbing is a spin in lifted code; a frozen count with the same
 * function is a wait (or a loop with no calls in it). Racy reads, on purpose:
 * taking the machine lock would stop the very thing being watched. */
static int g_watchdog;

static DWORD WINAPI watchdog(LPVOID unused) {
    (void)unused;
    uint32_t last = 0;
    for (;;) {
        Sleep(g_watchdog * 1000);
        uint32_t n = g_icall_count, k = (g_icall_trace_idx - 1) & (ICALL_TRACE_SIZE - 1);
        fprintf(stderr, "[watchdog] %5.0fs  in sub_%08X  +%u icalls  last 0x%08X from 0x%08X\n",
                (GetTickCount() - g_start_tick) / 1000.0, g_cur_func, n - last,
                g_icall_trace[k], g_icall_from[k]);
        if (g_import_stats) stat_report();
        last = n;
    }
}

extern int g_present_scale, g_present_fullscreen, g_present_off, g_present_look, g_present_gdi;
int present_scale_from_name(const char* m);
extern int g_filter_textures;       /* spans.c */
extern const char* g_present_modes;
extern int g_fov_original, g_present_corner;
void present_apply_modes(void);   /* present.c */

/* --fps: frames per second, from the engine's own r_framecount (sw.dll
 * 0x100CE96C, incremented once per rendered view in R_SetupFrame). Reading
 * the game's counter measures what it drew, native or lifted alike. */
#define R_FRAMECOUNT 0x100CE96Cu
static int g_fps;

static DWORD WINAPI fps_report(LPVOID unused) {
    (void)unused;
    uint32_t last = *(volatile uint32_t*)(uintptr_t)R_FRAMECOUNT;
    for (;;) {
        Sleep(1000);
        uint32_t n = *(volatile uint32_t*)(uintptr_t)R_FRAMECOUNT;
        if (n != last)
            fprintf(stderr, "[fps] %5.0fs  %u\n", (GetTickCount() - g_start_tick) / 1000.0, n - last);
        last = n;
    }
}

/* --profile N: a sampling profiler. Every millisecond, which lifted function
 * holds the machine (g_cur_func, set on every lifted entry); every N seconds,
 * the top 25 since the last report. Time spent in a Windows call counts
 * against the lifted function that made it. */
#define PROF_SLOTS 65536u
static int g_profile;
static uint32_t prof_va[PROF_SLOTS], prof_n[PROF_SLOTS];

static void prof_report(uint32_t total) {
    uint32_t top[25] = {0};
    for (uint32_t i = 0; i < PROF_SLOTS; i++) {
        if (!prof_n[i]) continue;
        for (int k = 0; k < 25; k++) {
            if (!top[k] || prof_n[i] > prof_n[top[k] - 1]) {
                memmove(&top[k + 1], &top[k], (24 - k) * sizeof top[0]);
                top[k] = i + 1;
                break;
            }
        }
    }
    fprintf(stderr, "[profile] %5.0fs  %u samples\n", (GetTickCount() - g_start_tick) / 1000.0, total);
    for (int k = 0; k < 25 && top[k]; k++)
        fprintf(stderr, "[profile]   %5.1f%%  sub_%08X\n", 100.0 * prof_n[top[k] - 1] / total, prof_va[top[k] - 1]);
    memset(prof_n, 0, sizeof prof_n);
}

static DWORD WINAPI profiler(LPVOID unused) {
    (void)unused;
    timeBeginPeriod(1);
    DWORD next = GetTickCount() + g_profile * 1000;
    uint32_t total = 0;
    for (;;) {
        Sleep(1);
        uint32_t va = g_cur_func, h = (va * 2654435761u) >> 16;
        while (prof_n[h] && prof_va[h] != va) h = (h + 1) & (PROF_SLOTS - 1);
        prof_va[h] = va; prof_n[h]++; total++;
        if ((int)(GetTickCount() - next) >= 0) {
            prof_report(total);
            total = 0; next += g_profile * 1000;
        }
    }
}

/* --------------------------------------------------------------- loading */

char g_game_dir[MAX_PATH];

static IMAGE_NT_HEADERS32* nt_of(uint32_t base) {
    IMAGE_DOS_HEADER* d = (IMAGE_DOS_HEADER*)(uintptr_t)base;
    return (IMAGE_NT_HEADERS32*)(uintptr_t)(base + d->e_lfanew);
}

/* An export of a mapped guest module, by name or (name < 0x10000) ordinal. */
uint32_t guest_export(const module_t* m, const char* name) {
    IMAGE_DATA_DIRECTORY dd = nt_of(m->base)->OptionalHeader.DataDirectory[0];
    if (!dd.Size) return 0;
    IMAGE_EXPORT_DIRECTORY* ex = (IMAGE_EXPORT_DIRECTORY*)(uintptr_t)(m->base + dd.VirtualAddress);
    uint32_t* funcs = (uint32_t*)(uintptr_t)(m->base + ex->AddressOfFunctions);
    uint32_t* names = (uint32_t*)(uintptr_t)(m->base + ex->AddressOfNames);
    uint16_t* ords  = (uint16_t*)(uintptr_t)(m->base + ex->AddressOfNameOrdinals);
    if ((uintptr_t)name < 0x10000) {
        uint32_t i = (uint32_t)(uintptr_t)name - ex->Base;
        return i < ex->NumberOfFunctions ? m->base + funcs[i] : 0;
    }
    for (uint32_t i = 0; i < ex->NumberOfNames; i++)
        if (!strcmp((const char*)(uintptr_t)(m->base + names[i]), name))
            return m->base + funcs[ords[i]];
    return 0;
}

const module_t* module_named(const char* path) {
    const char* b = path;
    for (const char* p = path; *p; p++) if (*p == '\\' || *p == '/') b = p + 1;
    for (int i = 0; i < g_module_count; i++) {
        const char* n = g_modules[i].name;
        for (const char* p = n; *p; p++) if (*p == '/') n = p + 1;
        if (!_stricmp(b, n)) return &g_modules[i];
        /* LoadLibrary("vgui") means vgui.dll */
        size_t bl = strlen(b);
        if (!strchr(b, '.') && !_strnicmp(b, n, bl) && !_stricmp(n + bl, ".dll"))
            return &g_modules[i];
    }
    return NULL;
}

/* Synthetic VAs for hand-written imports: a reserved, never-committed page, so
 * no real code or data can share an address with one. */

void link_iat(module_t* m) {
    if (m->linked) return;
    m->linked = 1;
    IMAGE_DATA_DIRECTORY dd = nt_of(m->base)->OptionalHeader.DataDirectory[1];
    IMAGE_IMPORT_DESCRIPTOR* d = (IMAGE_IMPORT_DESCRIPTOR*)(uintptr_t)(m->base + dd.VirtualAddress);
    int native = 0, guest = 0, shim = 0;
    for (; d->Name; d++) {
        const char* dll = (const char*)(uintptr_t)(m->base + d->Name);
        const module_t* g = module_named(dll);
        HMODULE h = g ? NULL : LoadLibraryA(dll);
        uint32_t* ilt = (uint32_t*)(uintptr_t)(m->base + (d->OriginalFirstThunk ? d->OriginalFirstThunk : d->FirstThunk));
        uint32_t* iat = (uint32_t*)(uintptr_t)(m->base + d->FirstThunk);
        for (; *ilt; ilt++, iat++) {
            const char* nm = (*ilt & 0x80000000u)
                ? (const char*)(uintptr_t)(*ilt & 0xFFFF)
                : (const char*)(uintptr_t)(m->base + *ilt + 2);
            uint32_t va = 0;
            if ((uintptr_t)nm >= 0x10000)
                for (int i = 0; i < g_shim_count; i++)
                    if (!strcmp(g_shims[i].name, nm)) {
                        if (!g_shims[i].va) g_shims[i].va = g_shim_page + 16 * i;
                        va = g_shims[i].va;
                        shim++;
                    }
            if (!va && g) {
                if (!g->mapped) {
                    fprintf(stderr, "[link] %s imports %s, which is not loaded\n", m->name, dll);
                } else if (!(va = guest_export(g, nm))) {
                    fprintf(stderr, "[link] %s: %s!%s not exported\n", m->name, dll, nm);
                }
                guest++;
            } else if (!va) {
                va = h ? (uint32_t)(uintptr_t)GetProcAddress(h, nm) : 0;
                if (!va)
                    fprintf(stderr, "[link] %s: %s!%s%s unresolved\n", m->name, dll,
                            (uintptr_t)nm < 0x10000 ? "#" : "",
                            (uintptr_t)nm < 0x10000 ? "" : nm);
                native++;
            }
            if (va && !g && g_native_name_count < 2048 && (uintptr_t)nm >= 0x10000) {
                g_native_names[g_native_name_count].va = va;
                g_native_names[g_native_name_count++].name = nm;
            }
            *iat = va;
        }
    }
    fprintf(stderr, "[link] %-10s %4d native  %4d guest  %3d shimmed\n",
            m->name, native, guest, shim);
}

/* run_lift.py --native-range: {lo, hi, lo, hi, ..., 0} */
extern const uint32_t recomp_native_ranges[];

static int has_native_range(const module_t* m) {
    for (const uint32_t* r = recomp_native_ranges; r[0]; r += 2)
        if (r[0] < m->base + m->span && r[1] > m->base) return 1;
    return 0;
}

/* Map a module, then make its code non-executable: every entry into it must
 * come through the dispatch table or the VEH, never through the old bytes. */
int map_module(module_t* m) {
    if (m->mapped) return 1;
    char path[MAX_PATH];
    snprintf(path, sizeof path, "%s/%s", g_rebased_dir, m->rebased);
    m->span = recomp_load_image(path, m->base);
    if (!m->span) return 0;
    m->mapped = 1;
    IMAGE_NT_HEADERS32* nt = nt_of(m->base);
    IMAGE_SECTION_HEADER* s = IMAGE_FIRST_SECTION(nt);
    for (int i = 0; i < nt->FileHeader.NumberOfSections; i++, s++) {
        DWORD old;
        if (s->Characteristics & IMAGE_SCN_MEM_EXECUTE)
            VirtualProtect((void*)(uintptr_t)(m->base + s->VirtualAddress),
                           s->Misc.VirtualSize,
                           m->native || has_native_range(m) ? PAGE_EXECUTE_READWRITE
                                                            : PAGE_READWRITE, &old);
    }
    return 1;
}

/* Run a guest function to completion on the current guest stack. */
static void call_guest(uint32_t va, int nargs, const uint32_t* args) {
    recomp_func_t f = recomp_lookup(va);
    if (!f) { fprintf(stderr, "[boot] no lifted function at 0x%08X\n", va); exit(3); }
    for (int i = nargs - 1; i >= 0; i--) PUSH32(g_esp, args[i]);
    PUSH32(g_esp, RECOMP_RETADDR);
    f();
}

/* DLL_PROCESS_ATTACH, once, the way the loader would. */
/* DllMain(base, reason, 0), natively or lifted. Runs on the current guest
 * stack and leaves esp where it found it. */
static uint32_t dll_main(module_t* m, uint32_t reason) {
    if (!(nt_of(m->base)->FileHeader.Characteristics & IMAGE_FILE_DLL)) return 1;
    uint32_t entry = m->base + nt_of(m->base)->OptionalHeader.AddressOfEntryPoint;
    const char* why = reason == DLL_PROCESS_ATTACH ? "DllMain" : "DllMain(DETACH)";
    if (m->native) {
        typedef BOOL (WINAPI *dllmain_t)(HINSTANCE, DWORD, LPVOID);
        mach_leave();
        BOOL r = ((dllmain_t)(uintptr_t)entry)((HINSTANCE)(uintptr_t)m->base, reason, NULL);
        mach_enter();
        fprintf(stderr, "[boot] %s %s (native) -> %d\n", m->name, why, r);
        return (uint32_t)r;
    }
    uint32_t esp0 = g_esp;
    uint32_t a[3] = { m->base, reason, 0 };
    call_guest(entry, 3, a);
    g_esp = esp0;
    fprintf(stderr, "[boot] %s %s -> %u\n", m->name, why, g_eax);
    return g_eax;
}

uint32_t attach_module(module_t* m) {
    if (m->attached) return 1;
    m->attached = 1;
    return dll_main(m, DLL_PROCESS_ATTACH);
}

/* The last FreeLibrary: DLL_PROCESS_DETACH, and forget the link, so the next
 * LoadLibrary maps a FRESH image. The launcher changes video mode by freeing
 * the engine and loading it again (gunman.exe 0x0040E7A6); handing back the
 * same already-initialised image quietly ended the game on a resolution
 * change. The address range stays reserved so nothing else can take it. */
void detach_module(module_t* m) {
    if (!m->attached) return;
    dll_main(m, DLL_PROCESS_DETACH);
    m->attached = 0;
    m->linked = 0;
    m->stale = 1;
}

/* Re-map a detached module from its file: fresh .data, fresh .bss. */
static void apply_relocs(void);

int remap_module(module_t* m) {
    m->mapped = 0;
    if (!map_module(m)) return 0;
    if (g_pageheap && !m->native) pageheap_disable_sbh(m);
    m->stale = 0;
    apply_patches();
    apply_relocs();
    return 1;
}

/* run_lift.py RELOCS: resolution-sized tables moved to a bigger home at
 * RECOMP_RELOC_BASE. The region is reserved at startup; each table's original
 * contents are copied over whenever its module is (re)mapped. */
#define RECOMP_RELOC_BASE 0x20000000u
extern const uint32_t recomp_reloc_span, recomp_relocs[];

static void apply_relocs(void) {
    static int reserved;
    if (!reserved && recomp_reloc_span) {
        if (!VirtualAlloc((void*)(uintptr_t)RECOMP_RELOC_BASE, recomp_reloc_span,
                          MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE))
            fprintf(stderr, "[reloc] cannot reserve 0x%08X (+0x%X)\n", RECOMP_RELOC_BASE, recomp_reloc_span);
        reserved = 1;
    }
    for (const uint32_t* r = recomp_relocs; r[0]; r += 3) {
        const module_t* m = module_at(r[0]);
        if (m && m->mapped)
            memcpy((void*)(uintptr_t)r[2], (void*)(uintptr_t)r[0], r[1]);
    }
}

/* --patch VA=HEXBYTES: overwrite original code or data in a mapped module.
 * For bisection builds, where ORIGINAL code runs: lifted code is not affected
 * (use run_lift.py --stub-ret for that side). Re-applied on every re-map. */
static const char* g_patch[16];
static int g_patch_count;

void apply_patches(void) {
    for (int i = 0; i < g_patch_count; i++) {
        const char* eq = strchr(g_patch[i], '=');
        if (!eq) continue;
        uint32_t va = strtoul(g_patch[i], NULL, 0);
        if (!module_at(va)) { fprintf(stderr, "[patch] 0x%08X is in no mapped module\n", va); continue; }
        uint32_t n = 0;
        for (const char* h = eq + 1; h[0] && h[1]; h += 2, n++) {
            char b[3] = { h[0], h[1], 0 };
            MEM8(va + n) = (uint8_t)strtoul(b, NULL, 16);
        }
        fprintf(stderr, "[patch] %u bytes at 0x%08X\n", n, va);
    }
}

/* ------------------------------------------------------------------ main */

char g_guest_cmdline[4096];
uint32_t g_start_tick;

static void usage(void) {
    fprintf(stderr,
        "usage: gunman <game dir> [--rebased DIR] [-- guest arguments]\n"
        "  <game dir>   your installed Gunman Chronicles (holds gunman.exe, rewolf/)\n"
        "  --rebased    the rebased images tools/rebase.py wrote (default work/rebased)\n"
        "  --imports    log every call into Windows, with arguments and result\n"
        "  --press VK@S report virtual key VK held at S seconds (0x1B@14 skips a movie)\n"
        "  --click X,Y@S left-click client point X,Y at S seconds (virtual cursor)\n"
        "  --callbacks  log every call Windows makes into the game (window procs, hooks)\n"
        "  --native M   run module M (e.g. sw.dll) as its original code, for bisection\n"
        "  --pageheap   guard-page every guest heap block, to fault on the corrupting write\n"
        "  --patch VA=HEX  overwrite original bytes in a mapped module (bisection)\n"
        "  --watchdog N every N seconds, report the running lifted function\n"
        "  --fps        print frames rendered per second (the engine's r_framecount)\n"
        "  --scale sharp|smooth|crt|nearest|integer   how the frame is scaled (F12 cycles)\n"
        "  --look natural|vivid   colour (F9 toggles)\n"
        "  --gdi        present with GDI instead of Direct3D 11\n"
        "  --filter on|off   bilinear-filtered textures (F8 toggles)\n"
        "  --fullscreen start in borderless fullscreen (F11 / Alt+Enter toggles)\n"
        "  --no-present the launcher's own presenter (no scaling, no hotkeys)\n"
        "  --profile N  every N seconds, the lifted functions that took the most time\n"
        "  --noddraw    fail DirectDrawCreate: present through GDI (screenshots work)\n"
        "  --grab S     save the frame presented at S seconds to work/frame.bmp\n"
        "  --import-stats  with --watchdog: the most-called Windows functions each interval\n"
        "  --trace-import NAME  log the first 60 calls to one import, with caller\n");
    exit(2);
}

int main(int argc, char** argv) {
    char rebased[MAX_PATH] = "work/rebased";
    const char* game = NULL;
    int i;
    for (i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--")) { i++; break; }
        else if (!strcmp(argv[i], "--rebased") && i + 1 < argc) strcpy(rebased, argv[++i]);
        else if (!strcmp(argv[i], "--imports")) g_trace_imports = 1;
        else if (!strcmp(argv[i], "--press") && i + 1 < argc && g_press_count < 16) {
            char* at = strchr(argv[++i], '@');
            g_press[g_press_count].vk = strtoul(argv[i], NULL, 0);
            g_press[g_press_count++].at = at ? atof(at + 1) : 0;
        }
        else if (!strcmp(argv[i], "--imports-from") && i + 1 < argc) {
            /* only calls made from lifted code at or above this VA, up to the
             * next module: --imports-from 0x10000000 traces just the engine */
            g_trace_imports = 1;
            g_trace_lo = strtoul(argv[++i], NULL, 0);
            for (int k = 0; k < g_module_count; k++)
                if (g_modules[k].base > g_trace_lo && g_modules[k].base < g_trace_hi)
                    g_trace_hi = g_modules[k].base;
        }
        else if (!strcmp(argv[i], "--callbacks")) g_trace_callbacks = 1;
        else if (!strcmp(argv[i], "--pageheap")) g_pageheap = 1;
        else if (!strcmp(argv[i], "--patch") && i + 1 < argc && g_patch_count < 16)
            g_patch[g_patch_count++] = argv[++i];
        else if (!strcmp(argv[i], "--noddraw")) g_noddraw = 1;
        else if (!strcmp(argv[i], "--import-stats")) g_import_stats = 1;
        else if (!strcmp(argv[i], "--trace-import") && i + 1 < argc) {
            char* at = strchr(argv[++i], '@');
            if (at) { *at = 0; g_trace_after = atof(at + 1); }
            g_trace_name = argv[i];
        }
        else if (!strcmp(argv[i], "--grab") && i + 1 < argc) g_grab_at = atof(argv[++i]);
        else if (!strcmp(argv[i], "--watchdog") && i + 1 < argc) g_watchdog = atoi(argv[++i]);
        else if (!strcmp(argv[i], "--fps")) g_fps = 1;
        else if (!strcmp(argv[i], "--fullscreen")) g_present_fullscreen = 1;
        else if (!strcmp(argv[i], "--no-present")) g_present_off = 1;
        else if (!strcmp(argv[i], "--modes") && i + 1 < argc) g_present_modes = argv[++i];
        else if (!strcmp(argv[i], "--fov-original")) g_fov_original = 1;
        else if (!strcmp(argv[i], "--corner")) g_present_corner = 1;
        else if (!strcmp(argv[i], "--watch") && i + 1 < argc) g_watch = strtoul(argv[++i], NULL, 0);
        else if (!strcmp(argv[i], "--writers") && i + 1 < argc) {   /* S[@BASEPTR,SIZEPTR] */
            const char* at = strchr(argv[++i], '@');
            g_writers_at = atof(argv[i]);
            if (at) { char* e; g_wr_baseptr = strtoul(at + 1, &e, 0); if (*e == ',') g_wr_sizeptr = strtoul(e + 1, NULL, 0); }
        }
        else if (!strcmp(argv[i], "--scale") && i + 1 < argc) g_present_scale = present_scale_from_name(argv[++i]);
        else if (!strcmp(argv[i], "--look") && i + 1 < argc) g_present_look = !strcmp(argv[++i], "vivid");
        else if (!strcmp(argv[i], "--gdi")) g_present_gdi = 1;
        else if (!strcmp(argv[i], "--filter") && i + 1 < argc) g_filter_textures = strcmp(argv[++i], "off") != 0;
        else if (!strcmp(argv[i], "--profile") && i + 1 < argc) g_profile = atoi(argv[++i]);
        else if (!strcmp(argv[i], "--native") && i + 1 < argc) {
            /* Bisection: run this module's ORIGINAL code instead of the lift.
             * If the game gets further, the bug is in that module's lift. */
            module_t* m = (module_t*)module_named(argv[++i]);
            if (!m || !m->rebased) { fprintf(stderr, "--native: no module %s\n", argv[i]); return 2; }
            m->native = 1;
        }
        else if (!strcmp(argv[i], "--click") && i + 1 < argc && g_click_count < 16) {
            click_t* c = &g_click[g_click_count++];
            const char* at = strchr(argv[++i], '@');
            sscanf(argv[i], "%d,%d", &c->x, &c->y);
            c->at = at ? atof(at + 1) : 0;
        }
        else if (!strcmp(argv[i], "--press") && i + 1 < argc && g_press_count < 16) {
            char* at = strchr(argv[++i], '@');
            g_press[g_press_count].vk = strtoul(argv[i], NULL, 0);
            g_press[g_press_count++].at = at ? atof(at + 1) : 0;
        }
        else if (argv[i][0] != '-' && !game) game = argv[i];
        else usage();
    }
    if (!game) usage();
    g_start_tick = GetTickCount();
    GetFullPathNameA(game, MAX_PATH, g_game_dir, NULL);
    GetFullPathNameA(rebased, MAX_PATH, g_rebased_dir, NULL);

    /* What the guest sees as its own command line: its exe, then whatever
     * followed `--`. */
    snprintf(g_guest_cmdline, sizeof g_guest_cmdline, "\"%s\\gunman.exe\"", g_game_dir);
    for (; i < argc; i++) {
        strncat(g_guest_cmdline, " ", sizeof g_guest_cmdline - strlen(g_guest_cmdline) - 1);
        strncat(g_guest_cmdline, argv[i], sizeof g_guest_cmdline - strlen(g_guest_cmdline) - 1);
    }

    /* The guest opens everything relative to its install, and native DLLs
     * it names (WONAuth, binkw32, hl_res) live there too. */
    if (!SetCurrentDirectoryA(g_game_dir)) {
        fprintf(stderr, "cannot enter %s\n", g_game_dir);
        return 2;
    }
    SetDllDirectoryA(g_game_dir);

    g_shim_page = (uint32_t)(uintptr_t)VirtualAlloc(NULL, 0x10000, MEM_RESERVE, PAGE_NOACCESS);
    InitializeCriticalSection(&g_mach);
    g_mach_tls = TlsAlloc();
    AddVectoredExceptionHandler(1, veh);

    /* Map EVERY lifted module before anything else loads, so their fixed VAs
     * are claimed first. sw.dll's 0x10000000 is also the preferred base of the
     * native WONAuth/WONCrypt, and whichever loads first gets it: mapping the
     * engine only when New game asks for it found the range already taken.
     * Only the boot modules are linked now; the rest link on LoadLibrary. */
    for (int k = 0; k < g_module_count; k++)
        if (g_modules[k].lifted && !map_module(&g_modules[k])) {
            fprintf(stderr, "cannot map %s -- run tools/rebase.py first\n", g_modules[k].rebased);
            return 2;
        }
    for (int k = 0; k < g_module_count; k++)
        if (g_pageheap && g_modules[k].mapped && !g_modules[k].native)
            pageheap_disable_sbh(&g_modules[k]);
    apply_patches();
    apply_relocs();
    present_apply_modes();
    if (g_watch) VirtualProtect((void*)(uintptr_t)(g_watch & ~0xFFFu), 4096, PAGE_READONLY, &g_watch_old);
    for (int k = 0; k < g_module_count; k++)
        if (g_modules[k].needed_by_boot) link_iat(&g_modules[k]);

    /* The main guest thread: its stack, its TIB, the lock. */
    mach_enter();
    for (int k = g_module_count - 1; k >= 0; k--)   /* DLLs before the exe */
        if (g_modules[k].needed_by_boot) attach_module(&g_modules[k]);

    uint32_t entry = g_modules[0].base + nt_of(g_modules[0].base)->OptionalHeader.AddressOfEntryPoint;
    fprintf(stderr, "[boot] gunman.exe entry 0x%08X  cmdline %s\n", entry, g_guest_cmdline);
    start_click_script();
    framegrab_init();
    if (g_watchdog > 0) CreateThread(NULL, 0, watchdog, NULL, 0, NULL);
    if (g_fps) CreateThread(NULL, 0, fps_report, NULL, 0, NULL);
    if (g_profile > 0) CreateThread(NULL, 0, profiler, NULL, 0, NULL);
    if (g_writers_at > 0) CreateThread(NULL, 0, writers_thread, NULL, 0, NULL);
    call_guest(entry, 0, NULL);
    fprintf(stderr, "[boot] entry point returned %u\n", g_eax);
    mach_leave();
    return (int)g_eax;
}

/* work/bchk.py (diagnostic builds only): an index past a fixed-size array.
 * Logs each array's largest out-of-range index as it grows. */
uint32_t bchk(uint32_t idx, uint32_t n, uint32_t base, uint32_t site) {
    static uint32_t bases[64], worst[64];
    if (idx < n) return idx;
    for (int i = 0; i < 64; i++) {
        if (bases[i] == base || !bases[i]) {
            if (!bases[i] || (int32_t)idx > (int32_t)worst[i]) {
                bases[i] = base; worst[i] = idx;
                fprintf(stderr, "[bchk] array 0x%08X [%u]: index %d (gen line %u)\n", base, n, (int32_t)idx, site);
            }
            break;
        }
    }
    return idx;
}
