/*
 * --grab S: save the frame the game presents S seconds in, as work/frame.bmp.
 *
 * DirectDraw windowed output is invisible to PrintWindow on modern Windows and
 * screen capture depends on window stacking, so neither can say whether the
 * game drew anything. This captures at the source instead: every DirectDraw
 * call from lifted code goes through native_bridge, and when it is a surface
 * Blt/BltFast the source surface is read through its own GetDC -- the exact
 * pixels being presented, in whatever format the game chose.
 *
 * The method addresses are learned at startup from a throwaway surface's
 * vtables (IDirectDrawSurface v1..v7 all put Blt at slot 5, BltFast at 7).
 */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <ddraw.h>
#include <stdio.h>
#include "modules.h"

static uint32_t g_blt[5], g_bltfast[5];
static int g_nvt;
double g_grab_at = -1;              /* seconds; <0 = off */
const char* g_grab_path = "work/frame.bmp";
static volatile LONG g_grabbed;

void framegrab_init(void) {
    if (g_grab_at < 0) return;
    typedef HRESULT (WINAPI *create_t)(GUID*, LPDIRECTDRAW*, IUnknown*);
    create_t create = (create_t)GetProcAddress(LoadLibraryA("ddraw.dll"), "DirectDrawCreate");
    LPDIRECTDRAW dd = NULL;
    if (!create || create(NULL, &dd, NULL) != DD_OK) { fprintf(stderr, "[grab] no DirectDraw\n"); return; }
    IDirectDraw_SetCooperativeLevel(dd, NULL, DDSCL_NORMAL);
    DDSURFACEDESC sd = { sizeof sd };
    sd.dwFlags = DDSD_CAPS | DDSD_WIDTH | DDSD_HEIGHT;
    sd.ddsCaps.dwCaps = DDSCAPS_OFFSCREENPLAIN | DDSCAPS_SYSTEMMEMORY;
    sd.dwWidth = sd.dwHeight = 8;
    LPDIRECTDRAWSURFACE s = NULL;
    if (IDirectDraw_CreateSurface(dd, &sd, &s, NULL) == DD_OK) {
        const IID* iids[] = { &IID_IDirectDrawSurface, &IID_IDirectDrawSurface2,
                              &IID_IDirectDrawSurface3, &IID_IDirectDrawSurface4,
                              &IID_IDirectDrawSurface7 };
        for (int i = 0; i < 5; i++) {
            void* q = NULL;
            if (IDirectDrawSurface_QueryInterface(s, iids[i], &q) == S_OK && q) {
                uint32_t* vt = *(uint32_t**)q;
                g_blt[g_nvt] = vt[5];
                g_bltfast[g_nvt++] = vt[7];
                ((IUnknown*)q)->lpVtbl->Release((IUnknown*)q);
            }
        }
        IDirectDrawSurface_Release(s);
    }
    IDirectDraw_Release(dd);
    if (g_grab_at >= 0)
        fprintf(stderr, "[grab] watching %d surface vtables; frame at %.0fs -> %s\n",
                g_nvt, g_grab_at, g_grab_path);
}

static void save_bmp(HDC src, int w, int h) {
    BITMAPINFO bi = { { sizeof(BITMAPINFOHEADER), w, -h, 1, 32, BI_RGB } };
    void* bits = NULL;
    HDC mem = CreateCompatibleDC(src);
    HBITMAP dib = CreateDIBSection(mem, &bi, DIB_RGB_COLORS, &bits, NULL, 0);
    HGDIOBJ old = SelectObject(mem, dib);
    BitBlt(mem, 0, 0, w, h, src, 0, 0, SRCCOPY);
    GdiFlush();
    FILE* f = fopen(g_grab_path, "wb");
    if (f) {
        BITMAPFILEHEADER fh = { 0x4D42 };
        uint32_t n = (uint32_t)w * h * 4;
        fh.bfOffBits = sizeof fh + sizeof(BITMAPINFOHEADER);
        fh.bfSize = fh.bfOffBits + n;
        fwrite(&fh, sizeof fh, 1, f);
        fwrite(&bi.bmiHeader, sizeof(BITMAPINFOHEADER), 1, f);
        fwrite(bits, n, 1, f);
        fclose(f);
    }
    SelectObject(mem, old);
    DeleteObject(dib);
    DeleteDC(mem);
}

/* Called by native_bridge before every native call; `a` is the argument window. */
void framegrab_check(uint32_t fn, const uint32_t* a) {
    if (g_grab_at < 0 || g_grabbed) return;
    int blt = 0, fast = 0;
    for (int i = 0; i < g_nvt; i++) {
        if (fn == g_blt[i]) blt = 1;
        if (fn == g_bltfast[i]) fast = 1;
    }
    if (!blt && !fast) return;
    if ((GetTickCount() - g_start_tick) / 1000.0 < g_grab_at) return;
    /* Blt(this, dstRect, srcSurf, srcRect, flags, fx); BltFast(this, x, y, srcSurf, srcRect, flags) */
    LPDIRECTDRAWSURFACE src = (LPDIRECTDRAWSURFACE)(uintptr_t)(blt ? a[2] : a[3]);
    if (!src) return;
    DDSURFACEDESC sd = { sizeof sd };
    HDC dc;
    if (IDirectDrawSurface_GetSurfaceDesc(src, &sd) != DD_OK) return;
    if (IDirectDrawSurface_GetDC(src, &dc) != DD_OK) return;
    if (InterlockedExchange(&g_grabbed, 1) == 0) {
        save_bmp(dc, (int)sd.dwWidth, (int)sd.dwHeight);
        fprintf(stderr, "[grab] %lux%lu frame -> %s\n", sd.dwWidth, sd.dwHeight, g_grab_path);
    }
    IDirectDrawSurface_ReleaseDC(src, dc);
}
