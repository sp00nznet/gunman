/* pad.c -- Xbox (XInput) controller support, mapped by controller.ini.
 *
 * Nothing in the game changes: the pad is turned into the input the game
 * already reads, so every action goes through Gunman's own key bindings.
 *   - buttons, triggers and the left stick press KEYS: WM_KEYDOWN/UP with the
 *     key's scan code, which is what the engine's key mapping reads;
 *   - MOUSE1..3 are pad bits merged into the MK_* flags of every mouse
 *     message (present.c's window procedure calls pad_mouse_flags). The
 *     engine takes button state from those flags, so a posted "button down"
 *     alone would be undone by the next ordinary mouse move;
 *   - MWHEELUP/DOWN post WM_MOUSEWHEEL (repeating while held);
 *   - the right stick is mouse look: its motion is added to what the
 *     GetCursorPos shim reports, which is how the client measures the mouse.
 * The pad only acts while the game window is in front.
 *
 * controller.ini sits in the working directory (the repo folder) and is
 * written with the defaults on first run. --no-pad turns all of this off.
 */
#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <math.h>
#include <ctype.h>
#include <stdlib.h>

#define PAD_INI "controller.ini"

typedef struct { WORD wButtons; BYTE bLeftTrigger, bRightTrigger; SHORT sThumbLX, sThumbLY, sThumbRX, sThumbRY; } XPAD;
typedef struct { DWORD dwPacketNumber; XPAD Gamepad; } XSTATE;
typedef DWORD (WINAPI *xinput_get_state)(DWORD, XSTATE*);

enum { ACT_NONE, ACT_KEY, ACT_MOUSE, ACT_WHEEL };
typedef struct { int kind, code; } action_t;       /* KEY: vk; MOUSE: MK_ bit; WHEEL: +1/-1 */

/* Pad inputs, in controller.ini's names. The first 14 are XInput button bits. */
static const struct { const char* name; WORD bit; } k_buttons[] = {
    { "dpad_up", 0x0001 }, { "dpad_down", 0x0002 }, { "dpad_left", 0x0004 }, { "dpad_right", 0x0008 },
    { "start", 0x0010 }, { "back", 0x0020 }, { "left_stick", 0x0040 }, { "right_stick", 0x0080 },
    { "lb", 0x0100 }, { "rb", 0x0200 }, { "a", 0x1000 }, { "b", 0x2000 }, { "x", 0x4000 }, { "y", 0x8000 },
};
#define NBUTTONS (sizeof k_buttons / sizeof k_buttons[0])
enum { IN_LT = NBUTTONS, IN_RT, IN_MOVE_UP, IN_MOVE_DOWN, IN_MOVE_LEFT, IN_MOVE_RIGHT, IN_COUNT };
static const char* const k_extra[] = { "lt", "rt", "move_forward", "move_back", "move_left", "move_right" };

static action_t s_map[IN_COUNT];
static float s_look = 14.0f;        /* degrees-ish per second at full tilt, times the game's sensitivity */
static int   s_invert_y;
static float s_dead_move = 0.30f, s_dead_look = 0.18f;
static int   s_trigger = 60;        /* 0..255: how far a trigger counts as pressed */

int g_pad_off;                      /* --no-pad */
static HWND s_hwnd;
static volatile LONG s_mouse_bits;  /* MK_ flags held by the pad */
static volatile LONG s_look_dx, s_look_dy;

static const char k_default_ini[] =
"; Gunman Chronicles recompiled -- Xbox controller mapping.\r\n"
"; Each pad input presses a key (or mouse button), so it does whatever that key\r\n"
"; is bound to in the game (Configuration > Controls). Delete this file to get\r\n"
"; the defaults back.\r\n"
";\r\n"
"; Keys: a letter or digit, SPACE CTRL SHIFT ALT TAB ENTER ESCAPE BACKSPACE,\r\n"
"; UPARROW DOWNARROW LEFTARROW RIGHTARROW, F1-F12, INS DEL HOME END PGUP PGDN,\r\n"
"; [ ] SEMICOLON ' , . / - = `, MOUSE1 MOUSE2 MOUSE3, MWHEELUP MWHEELDOWN, or NONE.\r\n"
"\r\n"
"rt = MOUSE1          ; +attack\r\n"
"lt = MOUSE2          ; +custom (weapon customization)\r\n"
"a = SPACE            ; +jump\r\n"
"b = CTRL             ; +duck\r\n"
"x = r                ; +reload\r\n"
"y = q                ; lastinv\r\n"
"lb = MWHEELDOWN      ; invprev\r\n"
"rb = MWHEELUP        ; invnext\r\n"
"left_stick = SHIFT   ; +speed\r\n"
"right_stick = e      ; +use\r\n"
"dpad_up = f          ; flashlight\r\n"
"dpad_down = e        ; +use\r\n"
"dpad_left = [        ; invprev\r\n"
"dpad_right = ]       ; invnext\r\n"
"back = TAB           ; +showscores\r\n"
"start = ESCAPE       ; menu\r\n"
"\r\n"
"; the left stick walks with these keys\r\n"
"move_forward = w\r\n"
"move_back = s\r\n"
"move_left = a\r\n"
"move_right = d\r\n"
"\r\n"
"look_speed = 14      ; right stick: how fast you turn\r\n"
"invert_y = 0         ; 1 = pushing up looks down\r\n"
"move_deadzone = 0.30 ; 0..1 of the stick's travel that is ignored\r\n"
"look_deadzone = 0.18\r\n"
"trigger_press = 60   ; 0..255 of a trigger's travel that counts as pressed\r\n";

static int parse_key(const char* v, action_t* a) {
    static const struct { const char* n; int kind, code; } names[] = {
        { "NONE", ACT_NONE, 0 }, { "SPACE", ACT_KEY, VK_SPACE }, { "CTRL", ACT_KEY, VK_CONTROL },
        { "SHIFT", ACT_KEY, VK_SHIFT }, { "ALT", ACT_KEY, VK_MENU }, { "TAB", ACT_KEY, VK_TAB },
        { "ENTER", ACT_KEY, VK_RETURN }, { "ESCAPE", ACT_KEY, VK_ESCAPE }, { "BACKSPACE", ACT_KEY, VK_BACK },
        { "UPARROW", ACT_KEY, VK_UP }, { "DOWNARROW", ACT_KEY, VK_DOWN }, { "LEFTARROW", ACT_KEY, VK_LEFT },
        { "RIGHTARROW", ACT_KEY, VK_RIGHT }, { "INS", ACT_KEY, VK_INSERT }, { "DEL", ACT_KEY, VK_DELETE },
        { "HOME", ACT_KEY, VK_HOME }, { "END", ACT_KEY, VK_END }, { "PGUP", ACT_KEY, VK_PRIOR },
        { "PGDN", ACT_KEY, VK_NEXT }, { "[", ACT_KEY, VK_OEM_4 }, { "]", ACT_KEY, VK_OEM_6 },
        { "SEMICOLON", ACT_KEY, VK_OEM_1 }, { "'", ACT_KEY, VK_OEM_7 }, { ",", ACT_KEY, VK_OEM_COMMA },
        { ".", ACT_KEY, VK_OEM_PERIOD }, { "/", ACT_KEY, VK_OEM_2 }, { "-", ACT_KEY, VK_OEM_MINUS },
        { "=", ACT_KEY, VK_OEM_PLUS }, { "`", ACT_KEY, VK_OEM_3 },
        { "MOUSE1", ACT_MOUSE, MK_LBUTTON }, { "MOUSE2", ACT_MOUSE, MK_RBUTTON }, { "MOUSE3", ACT_MOUSE, MK_MBUTTON },
        { "MWHEELUP", ACT_WHEEL, 1 }, { "MWHEELDOWN", ACT_WHEEL, -1 },
    };
    for (size_t i = 0; i < sizeof names / sizeof names[0]; i++)
        if (!_stricmp(v, names[i].n)) { a->kind = names[i].kind; a->code = names[i].code; return 1; }
    if (v[0] && !v[1] && isalnum((unsigned char)v[0])) { a->kind = ACT_KEY; a->code = toupper((unsigned char)v[0]); return 1; }
    if ((v[0] == 'F' || v[0] == 'f') && atoi(v + 1) >= 1 && atoi(v + 1) <= 12) { a->kind = ACT_KEY; a->code = VK_F1 + atoi(v + 1) - 1; return 1; }
    return 0;
}

static void apply_line(char* line, int lineno) {
    char* c = strchr(line, ';');                    /* a comment (the ; key is SEMICOLON) */
    if (c) *c = 0;
    char* eq = strchr(line, '=');
    if (!eq) return;
    *eq = 0;
    char *k = line, *v = eq + 1;
    while (*k == ' ' || *k == '\t') k++;
    for (char* e = k + strlen(k); e > k && (e[-1] == ' ' || e[-1] == '\t'); ) *--e = 0;
    while (*v == ' ' || *v == '\t') v++;
    for (char* e = v + strlen(v); e > v && (e[-1] == ' ' || e[-1] == '\t' || e[-1] == '\r' || e[-1] == '\n'); ) *--e = 0;
    if (!*k) return;
    if (!_stricmp(k, "look_speed")) { s_look = (float)atof(v); return; }
    if (!_stricmp(k, "invert_y")) { s_invert_y = atoi(v); return; }
    if (!_stricmp(k, "move_deadzone")) { s_dead_move = (float)atof(v); return; }
    if (!_stricmp(k, "look_deadzone")) { s_dead_look = (float)atof(v); return; }
    if (!_stricmp(k, "trigger_press")) { s_trigger = atoi(v); return; }
    for (int i = 0; i < IN_COUNT; i++) {
        const char* n = i < (int)NBUTTONS ? k_buttons[i].name : k_extra[i - NBUTTONS];
        if (_stricmp(k, n)) continue;
        if (!parse_key(v, &s_map[i]))
            fprintf(stderr, "[pad] " PAD_INI " line %d: unknown key '%s'\n", lineno, v);
        return;
    }
    fprintf(stderr, "[pad] " PAD_INI " line %d: unknown setting '%s'\n", lineno, k);
}

static void load_ini(void) {
    FILE* f = fopen(PAD_INI, "rb");
    if (!f) {                                       /* first run: write the defaults */
        f = fopen(PAD_INI, "wb");
        if (f) { fwrite(k_default_ini, 1, sizeof k_default_ini - 1, f); fclose(f); }
        f = fopen(PAD_INI, "rb");
    }
    char line[256];
    int n = 0;
    if (f) {
        while (fgets(line, sizeof line, f)) apply_line(line, ++n);
        fclose(f);
    } else {                                        /* read-only folder: defaults from memory */
        char buf[sizeof k_default_ini];
        memcpy(buf, k_default_ini, sizeof buf);
        for (char* l = strtok(buf, "\n"); l; l = strtok(NULL, "\n")) apply_line(l, ++n);
    }
}

static void press(const action_t* a, int down) {
    switch (a->kind) {
    case ACT_KEY: {
        UINT sc = MapVirtualKeyA(a->code, MAPVK_VK_TO_VSC);
        LPARAM lp = 1 | (sc << 16) | (down ? 0 : (3u << 30));
        if (a->code == VK_UP || a->code == VK_DOWN || a->code == VK_LEFT || a->code == VK_RIGHT ||
            a->code == VK_INSERT || a->code == VK_DELETE || a->code == VK_HOME || a->code == VK_END ||
            a->code == VK_PRIOR || a->code == VK_NEXT)
            lp |= 1 << 24;                          /* extended keys */
        PostMessageA(s_hwnd, down ? WM_KEYDOWN : WM_KEYUP, a->code, lp);
        break;
    }
    case ACT_MOUSE: {
        if (down) InterlockedOr(&s_mouse_bits, a->code); else InterlockedAnd(&s_mouse_bits, ~a->code);
        POINT p; GetCursorPos(&p); ScreenToClient(s_hwnd, &p);
        PostMessageA(s_hwnd, WM_MOUSEMOVE, 0, MAKELPARAM(p.x, p.y));   /* flags merged in present.c */
        break;
    }
    case ACT_WHEEL:
        if (down) PostMessageA(s_hwnd, WM_MOUSEWHEEL, MAKEWPARAM(0, a->code * WHEEL_DELTA), 0);
        break;
    }
}

/* One axis past a deadzone, rescaled to 0..1 beyond it. */
static float axis(SHORT raw, float dead) {
    float v = raw / 32767.0f;
    float m = fabsf(v);
    if (m < dead) return 0;
    return (v > 0 ? 1 : -1) * fminf(1.0f, (m - dead) / (1 - dead));
}

static DWORD WINAPI pad_thread(LPVOID unused) {
    (void)unused;
    HMODULE x = LoadLibraryA("xinput1_4.dll");
    if (!x) x = LoadLibraryA("xinput9_1_0.dll");
    xinput_get_state get = x ? (xinput_get_state)GetProcAddress(x, "XInputGetState") : NULL;
    if (!get) { fprintf(stderr, "[pad] no XInput on this system: controller support off\n"); return 0; }
    int held[IN_COUNT] = {0}, connected = -1;
    DWORD wheel_next[IN_COUNT] = {0}, last = GetTickCount();
    float fx = 0, fy = 0;
    for (;;) {
        Sleep(8);
        DWORD now = GetTickCount();
        float dt = (now - last) / 1000.0f; last = now;
        XSTATE st;
        int ok = get(0, &st) == ERROR_SUCCESS;
        if (ok != connected) {
            fprintf(stderr, "[pad] controller %s\n", ok ? "connected" : "not connected");
            connected = ok;
        }
        int front = ok && GetForegroundWindow() == s_hwnd;
        int in[IN_COUNT] = {0};
        if (front) {
            const XPAD* g = &st.Gamepad;
            for (size_t i = 0; i < NBUTTONS; i++) in[i] = (g->wButtons & k_buttons[i].bit) != 0;
            in[IN_LT] = g->bLeftTrigger > s_trigger;
            in[IN_RT] = g->bRightTrigger > s_trigger;
            float mx = axis(g->sThumbLX, s_dead_move), my = axis(g->sThumbLY, s_dead_move);
            in[IN_MOVE_UP] = my > 0.35f; in[IN_MOVE_DOWN] = my < -0.35f;
            in[IN_MOVE_RIGHT] = mx > 0.35f; in[IN_MOVE_LEFT] = mx < -0.35f;
            /* Look: a squared response (fine aim near the centre), in pixels
             * the client turns into view angles with its own sensitivity. */
            float lx = axis(g->sThumbRX, s_dead_look), ly = axis(g->sThumbRY, s_dead_look);
            fx += lx * fabsf(lx) * s_look * 60 * dt;
            fy += -ly * fabsf(ly) * s_look * 60 * dt * (s_invert_y ? -1 : 1);
            int ix = (int)fx, iy = (int)fy;
            if (ix || iy) {
                InterlockedExchangeAdd(&s_look_dx, ix); InterlockedExchangeAdd(&s_look_dy, iy);
                fx -= ix; fy -= iy;
            }
        }
        for (int i = 0; i < IN_COUNT; i++) {
            if (in[i] != held[i]) { press(&s_map[i], in[i]); held[i] = in[i]; wheel_next[i] = now + 350; }
            else if (in[i] && s_map[i].kind == ACT_WHEEL && (int)(now - wheel_next[i]) >= 0) {
                press(&s_map[i], 1); wheel_next[i] = now + 180;   /* held: keep scrolling */
            }
        }
    }
}

void pad_start(HWND hwnd) {
    static int started;
    s_hwnd = hwnd;
    if (started || g_pad_off) return;
    started = 1;
    load_ini();
    CreateThread(NULL, 0, pad_thread, NULL, 0, NULL);
    fprintf(stderr, "[pad] Xbox controller support on (" PAD_INI ")\n");
}

/* present.c: the MK_ flags the pad holds, for every mouse message. */
WPARAM pad_mouse_flags(WPARAM wp) { return wp | (WPARAM)s_mouse_bits; }

/* shims.c: right-stick motion, added to the cursor position the game reads. */
void pad_look(POINT* p) {
    if (!p) return;
    p->x += InterlockedExchange(&s_look_dx, 0);
    p->y += InterlockedExchange(&s_look_dy, 0);
}

#ifdef PAD_SELFTEST
/* cl /nologo /DPAD_SELFTEST src\runtime\pad.c user32.lib && pad.exe */
int main(void) {
    char dir[MAX_PATH];
    GetTempPathA(sizeof dir, dir);
    SetCurrentDirectoryA(dir);
    DeleteFileA(PAD_INI);
    load_ini();                                     /* writes and reads the defaults */
    int ok = s_map[IN_RT].kind == ACT_MOUSE && s_map[IN_RT].code == MK_LBUTTON
          && s_map[10].kind == ACT_KEY && s_map[10].code == VK_SPACE          /* a */
          && s_map[8].kind == ACT_WHEEL && s_map[8].code == -1                 /* lb */
          && s_map[IN_MOVE_UP].code == 'W' && s_map[14 - 1].code == 'Q'        /* y */
          && fabsf(s_look - 14.0f) < 0.01f && fabsf(s_dead_move - 0.30f) < 0.001f;
    char l1[] = "x = SEMICOLON   ; comment", l2[] = "b = nonsense";
    apply_line(l1, 1); apply_line(l2, 2);           /* the second prints a warning */
    ok = ok && s_map[12].kind == ACT_KEY && s_map[12].code == VK_OEM_1;
    DeleteFileA(PAD_INI);
    puts(ok ? "pad self-test OK" : "pad self-test FAILED");
    return !ok;
}
#endif
