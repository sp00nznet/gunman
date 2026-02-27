# Binary Analysis: Gunman Chronicles

Source installation: `C:\sierra\gunman` (retail CD, Nov 2000 build)

## Target Binaries (What We Need to Recompile)

### PRIMARY TARGET: `rewolf/dlls/gunman.dll` (Server Game DLL)

| Property | Value |
|----------|-------|
| **Size** | 1,388,603 bytes (1.32 MB) |
| **MD5** | `61f6ba33d133d16c800aedeb9fd01802` |
| **SHA1** | `fa69e046b1eb69c66491a637d9b436bdf47d7e16` |
| **Architecture** | x86 (i386), PE32 |
| **Linker** | MSVC 6.0 |
| **Compiled** | 2000-11-10 22:46:15 UTC |
| **Packed** | No |
| **Code size** | 0xE8000 (950 KB) .text section |
| **Imports** | KERNEL32.dll only |
| **Notable** | Named `gunman.dll` (not `hl.dll` as in standard HL mods) |

This is the big one. 950KB of code. Contains all server-side game logic:
entities, AI, weapons (with the customization system), vehicles, triggers,
map scripting, etc. Imports only KERNEL32.dll because the engine provides
all other APIs via function pointers (standard GoldSrc mod interface).

**Key exports include Rewolf-custom classes:**
- `CAnimeRocket`, `CBackpackAnimeRocket`, `CDemomanRocket` - Custom projectiles
- Various `??_C@` string constants referencing: `ourano` (dinosaurs), `xenome` (aliens),
  weapon sounds, model paths - these are the Gunman-specific content

### SECONDARY TARGET: `rewolf/cl_dlls/client.dll` (Client Game DLL)

| Property | Value |
|----------|-------|
| **Size** | 565,248 bytes (552 KB) |
| **MD5** | `dad536e8764f6925cdffacad35923e31` |
| **SHA1** | `8e3b84f1c8c6f20dfd0e875a43c840b94cb4675f` |
| **Architecture** | x86 (i386), PE32 |
| **Linker** | MSVC 6.0 |
| **Compiled** | 2000-11-12 19:45:26 UTC |
| **Packed** | No |
| **Code size** | 0x5A000 (360 KB) .text section |
| **Imports** | WINMM.dll, vgui.dll, WSOCK32.dll, USER32.dll, KERNEL32.dll |

Client-side game logic: HUD rendering, weapon prediction, effects,
VGUI menus, the weapon customization UI, etc. Smaller than the server DLL.

## Engine Binaries (Replaceable with Xash3D)

These are standard GoldSrc engine components. We do NOT need to recompile these --
Xash3D FWGS replaces them entirely.

| Binary | Size | Purpose | Notes |
|--------|------|---------|-------|
| `gunman.exe` | 1.2 MB | Game launcher | Custom launcher, has `.cms_t`/`.cms_d` sections (ContentManagement?) |
| `hw.dll` | 1.1 MB | Hardware renderer engine | OpenGL renderer + engine core |
| `sw.dll` | 995 KB | Software renderer engine | Software fallback renderer |
| `hlds.exe` | 60 KB | Dedicated server | Standard HL dedicated server |
| `vgui.dll` | 344 KB | UI framework | Valve GUI library |

## Support Libraries (Third-Party, Not Our Concern)

| Binary | Size | Purpose | Notes |
|--------|------|---------|-------|
| `WONAuth.dll` | 640 KB | WON authentication | Dead service (WON shut down 2004) |
| `WONCrypt.dll` | 640 KB | WON encryption | Dead service |
| `a3dapi.dll` | 211 KB | Aureal 3D audio | A3D positional audio (Aureal went bankrupt 2000) |
| `binkw32.dll` | 291 KB | Bink video codec | RAD Game Tools video player |
| `gldrv/3dfxgl.dll` | 137 KB | 3dfx Glide OpenGL wrapper | Voodoo graphics card support (3dfx bankrupt 2002) |
| `hl_res.dll` | 49 KB | Resource DLL | Icons/dialogs only, no code sections |

## Compilation Details

All Rewolf binaries were compiled with **Microsoft Visual C++ 6.0** (linker version 6.0),
which is consistent with the era and with Half-Life SDK development practices.

The server DLL (`gunman.dll`) has only KERNEL32.dll as an import, confirming the standard
GoldSrc mod architecture where the engine passes function pointers to the DLL rather than
using direct imports. The client DLL additionally imports VGUI and multimedia libraries
as expected.

## Recompilation Priority

1. **`rewolf/dlls/gunman.dll`** - Server game DLL (highest priority, all game logic)
2. **`rewolf/cl_dlls/client.dll`** - Client game DLL (HUD, prediction, effects)
3. Engine replacement handled by Xash3D FWGS (no recompilation needed)
4. WON/A3D/3dfx libraries can be stubbed or removed (dead hardware/services)

## File Inventory

Additional game data in `rewolf/` directory:
- **Maps:** BSP files in `rewolf/maps/`
- **Models:** MDL files in `rewolf/models/`
- **Sounds:** WAV files in `rewolf/sound/`
- **Textures:** WAD files (`rewolf.WAD`, `cached.wad`, `decals.WAD`)
- **Sprites:** SPR files in `rewolf/sprites/`
- **Events:** SC files in `rewolf/events/` (weapon event scripts)
- **Config:** Skill.cfg, liblist.gam, delta.lst, various text schemes
