/* present.c -- our presenter for the launcher's windowed mode.
 *
 * The launcher (gunman.exe sub_0042BE70) shows a frame by BitBlt-ing its DIB
 * one ROW at a time, bottom-up: 960 GDI calls per frame at 1280x960, each a
 * crossing from lifted code into Windows -- a third of the frame time. This
 * draws it once, scaled to whatever size the window is, on the GPU
 * (present_d3d.c) or, failing that, with one GDI StretchBlt:
 *
 *   window      resizable and maximizable; the frame is letterboxed to its
 *               aspect ratio
 *   F11, Alt+Enter   borderless fullscreen on the window's monitor, and back
 *   F12         scaling: sharp (sharp-bilinear), smooth, crt, nearest, integer
 *   F9          colour: natural, vivid
 *   F8          textures: filtered (bilinear, spans.c) or the original texels
 *
 * --scale MODE, --look vivid and --fullscreen set the starting state;
 * --gdi skips Direct3D. The DirectDraw (exclusive fullscreen) path stays the
 * launcher's own lifted code.
 */
#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <math.h>
#include "recomp_types.h"

/* The launcher's globals, read by sub_0042BE70 (see its disassembly). */
#define G_ACTIVE_A   0x004DCD28u   /* either nonzero: present */
#define G_ACTIVE_B   0x004E569Cu
#define G_WIDTH      0x004E1B4Cu
#define G_HEIGHT     0x004E1B50u
#define G_HDC_WINDOW 0x004F41A8u   /* 0 = the DirectDraw path */
#define G_HDC_FRAME  0x004F3D7Cu

/* runtime.c: release/reclaim the machine around Windows calls, as the native
 * bridge does -- SetWindowPos and friends call the game's window procedure,
 * which is lifted code, right back. */
void mach_enter(void);
void mach_leave(void);
/* present_d3d.c */
int d3d_present(HWND hw, HDC src, int w, int h, const RECT* r, int cw, int ch, int mode, int look);

#define GUEST32(va) (*(volatile uint32_t*)(uintptr_t)(va))

/* The order is the shader's `mode` for the first four. */
enum { SCALE_SHARP, SCALE_SMOOTH, SCALE_CRT, SCALE_NEAREST, SCALE_INTEGER, SCALE_COUNT };
static const char* const scale_names[] = { "sharp", "smooth", "crt", "nearest", "integer" };
static const char* const look_names[] = { "natural", "vivid" };

int g_present_scale = SCALE_SHARP;
int g_present_look;
int g_present_gdi;                  /* --gdi: no Direct3D */
int g_present_fullscreen;
int g_present_corner;               /* --corner: park the window bottom-right (test runs) */
int g_present_off;                  /* --no-present: the launcher's own row-by-row copy */
extern int g_filter_textures;       /* spans.c */

int present_scale_from_name(const char* m) {
    for (int i = 0; i < SCALE_COUNT; i++)
        if (!strcmp(m, scale_names[i])) return i;
    return SCALE_SHARP;
}

static HWND    s_hwnd;
static WNDPROC s_game_proc;
static int     s_is_full;
static LONG    s_saved_style;
static RECT    s_saved_rect;
static RECT    s_last_dst;           /* GDI: letterbox bars are cleared on change */

static void set_fullscreen(int on) {
    if (on == s_is_full || !s_hwnd) return;
    if (on) {
        s_saved_style = GetWindowLongA(s_hwnd, GWL_STYLE);
        GetWindowRect(s_hwnd, &s_saved_rect);
        MONITORINFO mi = { sizeof mi };
        GetMonitorInfoA(MonitorFromWindow(s_hwnd, MONITOR_DEFAULTTONEAREST), &mi);
        SetWindowLongA(s_hwnd, GWL_STYLE, (s_saved_style & ~WS_OVERLAPPEDWINDOW) | WS_POPUP);
        SetWindowPos(s_hwnd, HWND_TOP, mi.rcMonitor.left, mi.rcMonitor.top,
                     mi.rcMonitor.right - mi.rcMonitor.left, mi.rcMonitor.bottom - mi.rcMonitor.top,
                     SWP_FRAMECHANGED | SWP_NOOWNERZORDER);
    } else {
        SetWindowLongA(s_hwnd, GWL_STYLE, s_saved_style);
        SetWindowPos(s_hwnd, NULL, s_saved_rect.left, s_saved_rect.top,
                     s_saved_rect.right - s_saved_rect.left, s_saved_rect.bottom - s_saved_rect.top,
                     SWP_FRAMECHANGED | SWP_NOZORDER | SWP_NOOWNERZORDER);
    }
    s_is_full = on;
    SetRectEmpty(&s_last_dst);
    fprintf(stderr, "[present] %s\n", on ? "borderless fullscreen" : "windowed");
}

/* Ahead of the game's own window procedure: our keys, and sizing. */
static LRESULT CALLBACK present_proc(HWND h, UINT msg, WPARAM wp, LPARAM lp) {
    int alt_enter = wp == VK_RETURN && (lp & (1 << 29));
    int ours = wp == VK_F11 || wp == VK_F12 || wp == VK_F9 || wp == VK_F8 || alt_enter;
    switch (msg) {
    case WM_KEYDOWN:
    case WM_SYSKEYDOWN:
        if (!ours) break;
        if (!(lp & (1 << 30))) {                                        /* not auto-repeat */
            if (wp == VK_F11 || alt_enter) set_fullscreen(!s_is_full);
            if (wp == VK_F12) {
                g_present_scale = (g_present_scale + 1) % SCALE_COUNT;
                fprintf(stderr, "[present] scaling: %s\n", scale_names[g_present_scale]);
            }
            if (wp == VK_F8) {
                g_filter_textures = !g_filter_textures;
                fprintf(stderr, "[present] textures: %s\n", g_filter_textures ? "filtered" : "original");
            }
            if (wp == VK_F9) {
                g_present_look = !g_present_look;
                fprintf(stderr, "[present] colour: %s\n", look_names[g_present_look]);
            }
            SetRectEmpty(&s_last_dst);
        }
        return 0;
    case WM_KEYUP:
    case WM_SYSKEYUP:
        if (ours) return 0;
        break;
    case WM_SIZE:
        SetRectEmpty(&s_last_dst);
        break;
    }
    return CallWindowProcA(s_game_proc, h, msg, wp, lp);
}

static void adopt_window(HWND h) {
    s_hwnd = h;
    /* Resizable and maximizable; the frame scales to fit. */
    LONG st = GetWindowLongA(h, GWL_STYLE);
    if (!(st & WS_POPUP))
        SetWindowLongA(h, GWL_STYLE, st | WS_THICKFRAME | WS_MAXIMIZEBOX);
    SetWindowPos(h, NULL, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE | SWP_NOZORDER | SWP_FRAMECHANGED);
    s_game_proc = (WNDPROC)SetWindowLongA(h, GWL_WNDPROC, (LONG)(uintptr_t)present_proc);
    fprintf(stderr, "[present] taking over the window: scaling %s, colour %s "
            "(F12 scaling, F9 colour, F8 texture filtering, F11 fullscreen)\n",
            scale_names[g_present_scale], look_names[g_present_look]);
    if (g_present_corner) {                         /* out of the way of whoever is at the desktop */
        RECT wr; MONITORINFO mi = { sizeof mi };
        GetWindowRect(h, &wr);
        GetMonitorInfoA(MonitorFromWindow(h, MONITOR_DEFAULTTONEAREST), &mi);
        SetWindowPos(h, HWND_BOTTOM, mi.rcWork.right - (wr.right - wr.left),
                     mi.rcWork.bottom - (wr.bottom - wr.top), 0, 0, SWP_NOSIZE | SWP_NOACTIVATE);
    }
    if (g_present_fullscreen) set_fullscreen(1);
}

/* The frame's rectangle inside a cw x ch client area. */
static RECT fit(int w, int h, int cw, int ch) {
    int dw, dh;
    if (g_present_scale == SCALE_INTEGER && cw >= w && ch >= h) {
        int k = min(cw / w, ch / h);
        dw = w * k; dh = h * k;
    } else if ((long long)cw * h > (long long)ch * w) {       /* wider: bars left and right */
        dh = ch; dw = (int)((long long)ch * w / h);
    } else {
        dw = cw; dh = (int)((long long)cw * h / w);
    }
    RECT r = { (cw - dw) / 2, (ch - dh) / 2, (cw - dw) / 2 + dw, (ch - dh) / 2 + dh };
    return r;
}

void present_override(void (*lifted)(void)) {
    HDC dst = (HDC)(uintptr_t)GUEST32(G_HDC_WINDOW);
    HDC src = (HDC)(uintptr_t)GUEST32(G_HDC_FRAME);
    int w = (int)GUEST32(G_WIDTH), h = (int)GUEST32(G_HEIGHT);
    if (g_present_off || !dst || !src || w <= 0 || h <= 0 || (!GUEST32(G_ACTIVE_A) && !GUEST32(G_ACTIVE_B)))
        { lifted(); return; }                       /* the launcher's own code */

    g_esp += 4;                                     /* the lifted `ret` */
    mach_leave();
    HWND hw = WindowFromDC(dst);
    if (hw && hw != s_hwnd) adopt_window(hw);

    RECT cr;
    if (!hw || !GetClientRect(hw, &cr) || cr.right <= 0 || cr.bottom <= 0) {
        mach_enter();                               /* minimized: nothing to draw */
        return;
    }
    RECT d = fit(w, h, cr.right, cr.bottom);
    int shader_mode = g_present_scale == SCALE_INTEGER ? SCALE_NEAREST : g_present_scale;
    if (g_present_gdi || !d3d_present(hw, src, w, h, &d, cr.right, cr.bottom, shader_mode, g_present_look)) {
        if (!EqualRect(&d, &s_last_dst)) {          /* clear the bars once */
            FillRect(dst, &cr, (HBRUSH)GetStockObject(BLACK_BRUSH));
            s_last_dst = d;
        }
        int smooth = g_present_scale == SCALE_SHARP || g_present_scale == SCALE_SMOOTH ||
                     g_present_scale == SCALE_CRT;
        SetStretchBltMode(dst, smooth ? HALFTONE : COLORONCOLOR);
        SetBrushOrgEx(dst, 0, 0, NULL);
        /* The frame is stored bottom-up: the launcher copied source row h-1-y to
         * window row y. A negative source height mirrors it back. */
        StretchBlt(dst, d.left, d.top, d.right - d.left, d.bottom - d.top,
                   src, 0, h - 1, w, -h, SRCCOPY);
    }
    mach_enter();
}

/* Hor+ widescreen. R_ViewChanged (sw.dll 0x1004FB90) turns fov_x into the
 * projection: horizontalFieldOfView = 2 tan(fov_x/2), with the vertical
 * following from the aspect -- so a 16:9 frame showed the 4:3 width and lost
 * the top and bottom. For the length of that call fov_x is widened so the
 * VERTICAL view is what 4:3 shows: tan(fov'/2) = tan(fov/2) * aspect / (4/3).
 * An exact no-op at 4:3; zoomed fovs convert the same way. --fov-original
 * keeps the engine's own. */
#define FOV_X      0x100D01CCu      /* the float R_ViewChanged reads */
#define R_FOV_GT_90 0x1049D3A8u     /* r_fov_greater_than_90: no view model */
int g_fov_original;

void fov_override(void (*lifted)(void)) {
    uint32_t pv = GUEST32(g_esp + 4);               /* vrect_t *: x y width height */
    int w = (int)GUEST32(pv + 8), h = (int)GUEST32(pv + 12);
    volatile float* fov = (volatile float*)(uintptr_t)FOV_X;
    float orig = *fov;
    if (!g_fov_original && h > 0 && w * 3 > h * 4 && orig > 0 && orig < 180) {
        const double pi = 3.14159265358979323846;
        double t = tan(orig * pi / 360) * ((double)w / h) / (4.0 / 3.0);
        *fov = (float)(atan(t) * 360 / pi);
    }
    lifted();
    *fov = orig;
    /* R_ViewChanged also sets Quake's r_fov_greater_than_90, and with it set
     * R_DrawViewModel draws no weapon: the widened 106 degrees of 16:9 hid the
     * gun. Decide it from the fov the player chose, as 4:3 would. */
    *(volatile int32_t*)(uintptr_t)R_FOV_GT_90 = orig > 90.0f;
}

/* The launcher's windowed video modes. It builds its list from seven
 * (width, height) pairs at 0x004C9F00 -- 400x300 to 1280x960, all 4:3 -- and
 * the loop bound is compiled in, so the seven pairs are rewritten in place (a
 * shorter list repeats its last entry; the launcher keeps both, harmlessly).
 * By default: widescreen alongside 4:3. The engine's span tables stop at
 * 1280 pixels wide (1360x768 and 1600x900 crash in sub_10029150, as Quake's
 * MAXWIDTH would), so 16:9 and 16:10 top out at 1280x720 and 1280x800, and
 * the presenter scales them to the window or the monitor.
 * --modes WxH,... picks others; --modes original keeps the game's own. */
#define MODE_TABLE 0x004C9F00u
const char* g_present_modes = "640x480,800x600,1024x768,1280x960,1024x576,1280x720,1280x800";

void present_apply_modes(void) {
    if (!g_present_modes || !strcmp(g_present_modes, "original")) return;
    uint32_t w[7], h[7];
    int n = 0;
    for (const char* p = g_present_modes; *p && n < 7; ) {
        char* e;
        w[n] = strtoul(p, &e, 10);
        if (*e != 'x' && *e != 'X') break;
        h[n] = strtoul(e + 1, &e, 10);
        if (w[n] && h[n]) n++;
        p = (*e == ',') ? e + 1 : e;
        if (!*e) break;
    }
    if (!n) { fprintf(stderr, "[present] --modes: expected WxH,WxH,...\n"); return; }
    for (int i = 0; i < 7; i++) {
        int k = i < n ? i : n - 1;
        GUEST32(MODE_TABLE + 8 * i) = w[k];
        GUEST32(MODE_TABLE + 8 * i + 4) = h[k];
    }
    fprintf(stderr, "[present] %d video modes: %s\n", n, g_present_modes);
}
