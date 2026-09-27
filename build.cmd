@echo off
rem Configure and build the 32-bit host with MSVC x86 + Ninja.
rem Needs Visual Studio 2022 (any edition) with the C++ x86 tools.
setlocal
set "VSWHERE=%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe"
for /f "usebackq delims=" %%i in (`"%VSWHERE%" -latest -property installationPath`) do set "VS=%%i"
if not defined VS (echo Visual Studio 2022 not found & exit /b 1)
call "%VS%\VC\Auxiliary\Build\vcvarsall.bat" x86 >nul || exit /b 1
rem BUILD_DIR / BUILD_TYPE pick another tree (a second build while one runs).
if not defined BUILD_DIR set "BUILD_DIR=build"
if not defined BUILD_TYPE set "BUILD_TYPE=RelWithDebInfo"
if not exist %BUILD_DIR%\build.ninja cmake -S . -B %BUILD_DIR% -G Ninja -DCMAKE_BUILD_TYPE=%BUILD_TYPE% || exit /b 1
cmake --build %BUILD_DIR% %*
