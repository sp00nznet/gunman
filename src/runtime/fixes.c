/* fixes.c -- bugs in the original game that the recompilation exposes.
 *
 * Each one lived on in the retail game because some leftover value happened
 * to be harmless there; a recompiled program leaves different leftovers.
 * Hooked through run_lift.py OVERRIDES: each gets the lifted body.
 */
#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <math.h>
#include "recomp_types.h"

#define GUEST32(va) (*(volatile uint32_t*)(uintptr_t)(va))

/* client.dll 0x0B021DD0, the HL SDK's WeaponsResource::LoadWeaponSprites.
 * It clears the active/inactive/ammo sprites, then returns early when the
 * weapon's sprites/<name>.txt lists nothing -- weapon_fists.txt (the knife)
 * and weapon_dmlGrenade.txt both say "0" -- without clearing the crosshair,
 * autoaim and zoomed handles. Those came from an uninitialised WEAPON on the
 * WeaponList handler's stack, so the knife and grenade drew a random sprite
 * as their crosshair, a different one after each load. Clear the four
 * handle+rect pairs (0x184..0x1D3) first; a weapon without one gets none. */
#define WEAPON_CROSSHAIR_FIELDS 0x184u
#define WEAPON_CROSSHAIR_BYTES  0x50u

void load_weapon_sprites_override(void (*lifted)(void)) {
    uint32_t w = GUEST32(g_esp + 4);                /* WEAPON * */
    if (w) memset((void*)(uintptr_t)(w + WEAPON_CROSSHAIR_FIELDS), 0, WEAPON_CROSSHAIR_BYTES);
    lifted();
}

/* sw.dll 0x100223B0, Cvar_SetValue: sprintf("%f") into a 32-byte stack
 * buffer, so a value past ~1e24 prints more than 32 characters and smashes
 * the frame -- a crash inside the CRT's %f code, well away from whoever
 * produced the number. Log such values with the cvar and the caller, and
 * clamp them so the game survives. */
void cvar_setvalue_override(void (*lifted)(void)) {
    volatile float* v = (volatile float*)(uintptr_t)(g_esp + 8);
    if (!(fabsf(*v) < 1e15f)) {
        const char* name = (const char*)(uintptr_t)GUEST32(g_esp + 4);
        fprintf(stderr, "[cvar] %s = %g from sub_%08X: clamped\n", name ? name : "?", *v, g_cur_func);
        *v = *v != *v ? 0.0f : *v > 0 ? 1e15f : -1e15f;
    }
    lifted();
}
