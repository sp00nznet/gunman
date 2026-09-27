/*
 * --pageheap: guard-page allocation for the guest, to catch heap corruption at
 * the write that causes it rather than at the free that notices it.
 *
 * Two parts:
 *  1. Every lifted module's statically linked MSVC 6 CRT keeps a small-block
 *     heap (__sbh_*) for allocations up to __sbh_threshold (0x3F8). Those
 *     blocks live in the CRT's own VirtualAlloc'd regions, where nothing can
 *     guard them, so the threshold is found by its code pattern and set to 0:
 *     every malloc then goes to HeapAlloc. (The launcher's CRT, which sets its
 *     threshold at run time, keeps its small-block heap.)
 *  2. HeapAlloc/HeapFree/HeapReAlloc/HeapSize from lifted code are shimmed.
 *     Each block is placed flush against a read-only page, so an overrunning
 *     WRITE faults on the offending instruction, and a freed block is decommitted
 *     (quarantined) so a use-after-free faults too.
 *
 * Diagnostic only: it costs at least 8 KB of address space per allocation.
 * See docs/boot.md for what it found.
 */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <string.h>
#include "recomp_types.h"
#include "modules.h"

#define ARG(n)       MEM32(g_esp + 4 + (n) * 4)
#define STDRET(k, v) do { g_eax = (uint32_t)(v); g_esp += 4 + (k) * 4; } while (0)

int g_pageheap;

#define PH_MAGIC 0x50480001u
typedef struct { uint32_t magic, size, base, pages; } ph_hdr_t;   /* just before the block */

static uint32_t ph_alloc(uint32_t size, int zero) {
    (void)zero;                            /* VirtualAlloc memory is zeroed */
    uint32_t rsize = (size + 7) & ~7u;     /* HeapAlloc's 8-byte alignment */
    uint32_t pages = (rsize + sizeof(ph_hdr_t) + 0xFFF) / 0x1000;
    uint8_t* base = (uint8_t*)VirtualAlloc(NULL, (pages + 1) * 0x1000, MEM_RESERVE, PAGE_NOACCESS);
    if (!base) return 0;
    VirtualAlloc(base, pages * 0x1000, MEM_COMMIT, PAGE_READWRITE);
    /* The guard is READ-ONLY, not no-access: corruption is a write, and 2000-
     * era code reads one past its arrays all the time (the launcher's
     * sub_0040A770 reads float [20] of a 20-float table on every menu frame). */
    VirtualAlloc(base + pages * 0x1000, 0x1000, MEM_COMMIT, PAGE_READONLY);
    uint8_t* p = base + pages * 0x1000 - rsize;
    ph_hdr_t* h = (ph_hdr_t*)p - 1;
    h->magic = PH_MAGIC; h->size = size; h->base = (uint32_t)(uintptr_t)base; h->pages = pages;
    return (uint32_t)(uintptr_t)p;
}

static ph_hdr_t* ph_hdr(uint32_t p) {
    if (!p) return NULL;
    ph_hdr_t* h = (ph_hdr_t*)(uintptr_t)p - 1;
    MEMORY_BASIC_INFORMATION mbi;
    if (!VirtualQuery(h, &mbi, sizeof mbi) || mbi.State != MEM_COMMIT) return NULL;
    return h->magic == PH_MAGIC ? h : NULL;
}

static void ph_free(ph_hdr_t* h) {
    h->magic = 0xDEADF4EEu;
    /* Decommit and keep the reservation: touching it again faults. */
    VirtualFree((void*)(uintptr_t)h->base, h->pages * 0x1000, MEM_DECOMMIT);
}

static void call_real(const char* name) {
    g_native_target = (uint32_t)(uintptr_t)GetProcAddress(GetModuleHandleA("kernel32.dll"), name);
    native_bridge();
}

/* HeapAlloc(heap, flags, size) */
void s_ph_HeapAlloc(void) {
    if (!g_pageheap) { call_real("HeapAlloc"); return; }
    STDRET(3, ph_alloc(ARG(2), ARG(1) & HEAP_ZERO_MEMORY));
}

/* HeapFree(heap, flags, p) */
void s_ph_HeapFree(void) {
    ph_hdr_t* h = g_pageheap ? ph_hdr(ARG(2)) : NULL;
    if (!h) { call_real("HeapFree"); return; }
    ph_free(h);
    STDRET(3, 1);
}

/* HeapReAlloc(heap, flags, p, size) */
void s_ph_HeapReAlloc(void) {
    ph_hdr_t* h = g_pageheap ? ph_hdr(ARG(2)) : NULL;
    if (!h) { call_real("HeapReAlloc"); return; }
    uint32_t size = ARG(3);
    if ((ARG(1) & HEAP_REALLOC_IN_PLACE_ONLY) && size > h->size) { STDRET(4, 0); return; }
    uint32_t n = ph_alloc(size, 1);
    if (n) {
        memcpy((void*)(uintptr_t)n, (void*)(uintptr_t)ARG(2), h->size < size ? h->size : size);
        ph_free(h);
    }
    STDRET(4, n);
}

/* HeapSize(heap, flags, p) */
void s_ph_HeapSize(void) {
    ph_hdr_t* h = g_pageheap ? ph_hdr(ARG(2)) : NULL;
    if (!h) { call_real("HeapSize"); return; }
    STDRET(3, h->size);
}

/* The CRT's `cmp reg, [__sbh_threshold]; (push edi;) ja ...; push 9; call _lock`
 * in front of every __sbh_alloc_block call. Sets every threshold found to 0. */
void pageheap_disable_sbh(const module_t* m) {
    IMAGE_DOS_HEADER* d = (IMAGE_DOS_HEADER*)(uintptr_t)m->base;
    IMAGE_NT_HEADERS32* nt = (IMAGE_NT_HEADERS32*)(uintptr_t)(m->base + d->e_lfanew);
    IMAGE_SECTION_HEADER* s = IMAGE_FIRST_SECTION(nt);
    uint32_t found[8]; int hits[8] = {0}, nfound = 0;
    for (int i = 0; i < nt->FileHeader.NumberOfSections; i++, s++) {
        if (!(s->Characteristics & IMAGE_SCN_MEM_EXECUTE)) continue;
        const uint8_t* c = (const uint8_t*)(uintptr_t)(m->base + s->VirtualAddress);
        for (uint32_t k = 0; k + 16 < s->Misc.VirtualSize; k++) {
            if (c[k] != 0x3B || (c[k + 1] & 0xC7) != 0x05) continue;
            uint32_t addr;
            memcpy(&addr, c + k + 2, 4);
            for (int j = 6; j < 14; j++)
                if (c[k + j] == 0x6A && c[k + j + 1] == 0x09 && c[k + j + 2] == 0xE8) {
                    int f;
                    for (f = 0; f < nfound && found[f] != addr; f++) ;
                    if (f == nfound && nfound < 8) found[nfound++] = addr;
                    if (f < 8) hits[f]++;
                    break;
                }
        }
    }
    /* The MSVC 6 default is exactly 0x3F8; anything else is a lookalike
     * (gunman.exe's MFC has a `cmp reg,[0x004D37EC]` with 0x1E0 there). */
    for (int f = 0; f < nfound; f++)
        if (hits[f] >= 2 && module_at(found[f]) == m && MEM32(found[f]) == 0x3F8) {
            fprintf(stderr, "[pageheap] %s: __sbh_threshold at 0x%08X (was 0x%X) -> 0\n",
                    m->name, found[f], MEM32(found[f]));
            MEM32(found[f]) = 0;
        }
}
