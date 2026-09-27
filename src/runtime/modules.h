/*
 * The guest modules: every image that is lifted, or that the guest might ask
 * to load. Bases must match tools/rebase.py -- the lifted C has them baked in.
 */
#ifndef GUNMAN_MODULES_H
#define GUNMAN_MODULES_H
#include <stdint.h>

typedef struct {
    const char* name;        /* as the guest names it: "vgui.dll"          */
    const char* rebased;     /* file in the rebased dir                    */
    uint32_t    base;
    int         lifted;      /* its code is in the dispatch table          */
    int         needed_by_boot;
    uint32_t    span;        /* runtime: mapped bytes, 0 until mapped      */
    int         mapped, linked, attached;
    int         native;      /* --native: original code runs, not the lift */
    int         refs, stale; /* LoadLibrary count; freed, needs a fresh map */
} module_t;

extern module_t g_modules[];
extern const int g_module_count;
extern char g_rebased_dir[];
extern char g_game_dir[];
extern char g_guest_cmdline[];

#define GUEST_EXE_BASE 0x00400000u

typedef struct { uint32_t vk; double at; } press_t;   /* --press */
extern press_t g_press[16];
extern int g_press_count;
extern uint32_t g_start_tick;

typedef struct { int x, y; double at; } click_t;       /* --click */
extern click_t g_click[16];
extern int g_click_count;
void start_click_script(void);

extern double g_grab_at;                                /* framegrab.c */
extern const char* g_grab_path;
void framegrab_init(void);
void framegrab_check(uint32_t fn, const uint32_t* args);
extern int g_noddraw;                                   /* shims.c */
extern int g_pageheap;                                  /* pageheap.c */
void pageheap_disable_sbh(const module_t* m);

const module_t* module_at(uint32_t va);
const module_t* module_named(const char* path);
uint32_t guest_export(const module_t* m, const char* name);
int      map_module(module_t* m);   /* map only; link_iat() resolves imports */
void     link_iat(module_t* m);
uint32_t attach_module(module_t* m);
void     detach_module(module_t* m);
void     apply_patches(void);
int      remap_module(module_t* m);

/* Call the native function at `va` with the guest's current argument frame. */
extern uint32_t g_native_target;
void native_bridge(void);

#endif
