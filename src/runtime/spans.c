/* spans.c -- filtered textures: our own span drawer, with a bilinear fetch.
 *
 * The engine draws every opaque world surface with D_DrawSpans16 (sw.dll
 * 0x1008E6FC, hand-written assembly): perspective-correct every 8 pixels,
 * affine in between, one texel per pixel from the lit surface cache -- the
 * blocky look up close. This is Quake's C span loop (d_scan.c D_DrawSpans8)
 * over the same globals, 16-bit, with each pixel blended from the four
 * nearest texels. F8 toggles it (--filter on|off); off runs the original.
 */
#include <windows.h>
#include <stdio.h>
#include <stdint.h>
#include "recomp_types.h"

#define GF(va) (*(volatile float*)(uintptr_t)(va))
#define GI(va) (*(volatile int32_t*)(uintptr_t)(va))

/* The drawer's globals (Quake names; see the D_DrawSpans16 prologue). */
#define d_sdivzstepu  GF(0x100D7F04u)
#define d_tdivzstepu  GF(0x100D7F08u)
#define d_zistepu     GF(0x100D7F0Cu)
#define d_sdivzstepv  GF(0x100D7F10u)
#define d_tdivzstepv  GF(0x100D7F14u)
#define d_zistepv     GF(0x100D7F18u)
#define d_sdivzorigin GF(0x100D7F1Cu)
#define d_tdivzorigin GF(0x100D7F20u)
#define d_ziorigin    GF(0x100D7F24u)
#define sadjust       GI(0x100D7F28u)
#define tadjust       GI(0x100D7F2Cu)
#define bbextents     GI(0x100D7F30u)
#define bbextentt     GI(0x100D7F34u)
#define cacheblock    ((const uint16_t*)(uintptr_t)GI(0x100D7F38u))
#define cachewidth    GI(0x100D7F3Cu)
#define d_viewbuffer  ((uint8_t*)(uintptr_t)GI(0x100D7F40u))
#define d_scantable   ((volatile int32_t*)(uintptr_t)0x10551B00u)

typedef struct espan_s { int32_t u, v, count; uint32_t pnext; } espan_t;

int g_filter_textures = 1;
int g_pixel_555;                    /* present_d3d.c: the frame is 5-5-5, not 5-6-5 */

/* 565 spread so each channel has room to be scaled by a 5-bit weight:
 * 00000gggggg00000rrrrr000000bbbbb  (green up top, red and blue below). */
static inline uint32_t spread565(uint32_t c) { return (c | (c << 16)) & 0x07E0F81Fu; }
static inline uint16_t pack565(uint32_t x) { x &= 0x07E0F81Fu; return (uint16_t)(x | (x >> 16)); }
static inline uint32_t spread555(uint32_t c) { return (c | (c << 16)) & 0x03E07C1Fu; }
static inline uint16_t pack555(uint32_t x) { x &= 0x03E07C1Fu; return (uint16_t)(x | (x >> 16)); }

/* The four texels around (s, t) in 16.16, blended with 5-bit weights. */
static inline uint16_t fetch(const uint16_t* base, int cw, int s, int t, int smax, int tmax, int is555) {
    int si = s >> 16, ti = t >> 16;
    int s1 = si < smax ? si + 1 : si, t1 = ti < tmax ? ti + 1 : ti;
    uint32_t fs = (s >> 11) & 31, ft = (t >> 11) & 31;
    const uint16_t* r0 = base + ti * cw;
    const uint16_t* r1 = base + t1 * cw;
    if (is555) {
        uint32_t a = spread555(r0[si]), b = spread555(r0[s1]), c = spread555(r1[si]), d = spread555(r1[s1]);
        uint32_t top = (a * (32 - fs) + b * fs) >> 5 & 0x03E07C1Fu;
        uint32_t bot = (c * (32 - fs) + d * fs) >> 5 & 0x03E07C1Fu;
        return pack555((top * (32 - ft) + bot * ft) >> 5);
    }
    uint32_t a = spread565(r0[si]), b = spread565(r0[s1]), c = spread565(r1[si]), d = spread565(r1[s1]);
    uint32_t top = (a * (32 - fs) + b * fs) >> 5 & 0x07E0F81Fu;
    uint32_t bot = (c * (32 - fs) + d * fs) >> 5 & 0x07E0F81Fu;
    return pack565((top * (32 - ft) + bot * ft) >> 5);
}

static void draw_spans(const espan_t* pspan) {
    const uint16_t* pbase = cacheblock;
    int cw = cachewidth, bs = bbextents, bt = bbextentt, sa = sadjust, ta = tadjust;
    int smax = bs >> 16, tmax = bt >> 16, is555 = g_pixel_555;
    float sdivz8stepu = d_sdivzstepu * 8, tdivz8stepu = d_tdivzstepu * 8, zi8stepu = d_zistepu * 8;
    uint8_t* view = d_viewbuffer;
    do {
        uint16_t* pdest = (uint16_t*)(view + d_scantable[pspan->v]) + pspan->u;
        int count = pspan->count;
        float du = (float)pspan->u, dv = (float)pspan->v;
        float sdivz = d_sdivzorigin + dv * d_sdivzstepv + du * d_sdivzstepu;
        float tdivz = d_tdivzorigin + dv * d_tdivzstepv + du * d_tdivzstepu;
        float zi = d_ziorigin + dv * d_zistepv + du * d_zistepu;
        float z = 65536.0f / zi;
        int s = (int)(sdivz * z) + sa, t = (int)(tdivz * z) + ta;
        s = s > bs ? bs : s < 0 ? 0 : s;
        t = t > bt ? bt : t < 0 ? 0 : t;
        do {
            int n = count >= 8 ? 8 : count, snext, tnext, sstep = 0, tstep = 0;
            count -= n;
            if (count) {
                sdivz += sdivz8stepu; tdivz += tdivz8stepu; zi += zi8stepu;
                z = 65536.0f / zi;
                snext = (int)(sdivz * z) + sa; tnext = (int)(tdivz * z) + ta;
                snext = snext > bs ? bs : snext < 8 ? 8 : snext;
                tnext = tnext > bt ? bt : tnext < 8 ? 8 : tnext;
                sstep = (snext - s) >> 3; tstep = (tnext - t) >> 3;
            } else {
                float k = (float)(n - 1);
                sdivz += d_sdivzstepu * k; tdivz += d_tdivzstepu * k; zi += d_zistepu * k;
                z = 65536.0f / zi;
                snext = (int)(sdivz * z) + sa; tnext = (int)(tdivz * z) + ta;
                snext = snext > bs ? bs : snext < 8 ? 8 : snext;
                tnext = tnext > bt ? bt : tnext < 8 ? 8 : tnext;
                if (n > 1) { sstep = (snext - s) / (n - 1); tstep = (tnext - t) / (n - 1); }
            }
            do {
                *pdest++ = fetch(pbase, cw, s, t, smax, tmax, is555);
                s += sstep; t += tstep;
            } while (--n > 0);
            s = snext; t = tnext;
        } while (count > 0);
        pspan = (const espan_t*)(uintptr_t)pspan->pnext;
    } while (pspan);
}

void spans_override(void (*lifted)(void)) {
    if (!g_filter_textures) { lifted(); return; }
    const espan_t* pspan = (const espan_t*)(uintptr_t)(*(volatile uint32_t*)(uintptr_t)(g_esp + 4));
    if (pspan) draw_spans(pspan);
    g_esp += 4;                                     /* the lifted `ret` */
}
