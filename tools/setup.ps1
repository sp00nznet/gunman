# One-click setup for Gunman Chronicles, recompiled. Run it by double-clicking
# Setup.cmd in the repo folder; the README's "Step by step" is the same thing
# by hand.
#
# It checks for what the build needs (Python 3 with pefile and capstone, the
# pcrecomp toolkit beside this repo, Visual Studio's C++ build tools) and asks
# before installing anything. Then: install from your disc or ISO, analyze,
# lift, build, and a "Gunman Chronicles" shortcut in this folder. Each step is
# skipped when its output already exists (-Force redoes them). Everything it
# does goes to setup.log.
param([switch]$Force, [string]$Disc = "")

$ErrorActionPreference = 'Stop'
$Root = Split-Path -Parent $PSScriptRoot
$Toolkit = Join-Path (Split-Path -Parent $Root) 'tools'
$Log = Join-Path $Root 'setup.log'
Set-Location $Root
function Log($t) { Add-Content -Path $Log -Value $t -Encoding UTF8 }
Log "==== setup $(Get-Date -Format s)"

function Say($t, $c = 'Gray') { Write-Host $t -ForegroundColor $c; Log $t }
function Step($n, $t) { Write-Host ""; Say "[$n/6] $t" 'Cyan' }
function Fail($t) {
  Say "" ; Say "Setup stopped: $t" 'Red'
  Say "The details are in $Log. Fix that and run Setup.cmd again; finished steps are skipped." 'Yellow'
  Read-Host "Press Enter to close" | Out-Null; exit 1
}
function Ask($q) { $a = Read-Host "$q [Y/n]"; return -not ($a -match '^[nN]') }   # Enter = yes
function Refresh-Path {
  $env:Path = [Environment]::GetEnvironmentVariable('Path', 'Machine') + ';' + [Environment]::GetEnvironmentVariable('Path', 'User')
}
# Run a program with its output in the log. Windows PowerShell turns a native
# program's stderr into errors, so 'Stop' is off while it runs.
function Exec([string[]]$cmd) {
  $old = $ErrorActionPreference; $ErrorActionPreference = 'Continue'
  $rest = @($cmd | Select-Object -Skip 1)   # @(): a one-element slice would splat as characters
  & $cmd[0] @rest 2>&1 | ForEach-Object { Log "$_" }
  $code = $LASTEXITCODE
  $ErrorActionPreference = $old
  return $code
}
function Run($what, [string[]]$cmd) {
  Say "  $what..."
  $code = Exec $cmd
  if ($code -ne 0) { Fail "$what failed (exit code $code)." }
}
function Winget($id, $extra) {
  if (-not (Get-Command winget -ErrorAction SilentlyContinue)) {
    Fail "winget is missing. Install 'App Installer' from the Microsoft Store, or install $id yourself."
  }
  Exec (@('winget', 'install', '-e', '--id', $id, '--accept-package-agreements', '--accept-source-agreements') + $extra) | Out-Null
  Refresh-Path
}

Clear-Host
Say "Gunman Chronicles: static recompilation setup" 'White'
Say "You need your Gunman Chronicles CD (or an ISO of it) and about 10 GB free."
Say "This takes 20-40 minutes, most of it the one-time analysis and build."

# ---------------------------------------------------------------- tools
Step 1 "Checking the tools the build needs"
# A Python that answers "Python 3.x". The Store's placeholder "python" (the
# one that opens the Store) answers nothing, so asking is the reliable test.
function Find-Python {
  foreach ($c in @(@('py', '-3'), @('python'), @('python3'))) {
    if (-not (Get-Command $c[0] -ErrorAction SilentlyContinue)) { continue }
    $old = $ErrorActionPreference; $ErrorActionPreference = 'Continue'
    $rest = @($c | Select-Object -Skip 1)
    $v = (& $c[0] @rest --version 2>&1 | Out-String).Trim()
    $ErrorActionPreference = $old
    if ($v -match '^Python 3\.(\d+)' -and [int]$Matches[1] -ge 8) { return ,$c }
  }
  return $null
}
$pyargs = Find-Python
if (-not $pyargs) {
  Say "  Python 3 is not installed."
  if (-not (Ask "  Install Python 3.12 now (winget, for your user only)?")) { Fail "Python 3 is required." }
  Winget 'Python.Python.3.12' @('--scope', 'user')
  $pyargs = Find-Python
  if (-not $pyargs) { Fail "Python installed, but Windows has not picked it up yet: close this window and run Setup.cmd again." }
}
Say "  Python: $($pyargs -join ' ')"

if ((Exec ($pyargs + @('-c', 'import pefile, capstone'))) -ne 0) {
  Say "  The Python packages pefile and capstone are missing."
  if (-not (Ask "  Install them now (pip, for your user only)?")) { Fail "pefile and capstone are required." }
  Run "Installing pefile and capstone" ($pyargs + @('-m', 'pip', 'install', '--user', 'pefile', 'capstone'))
}

if (-not (Test-Path (Join-Path $Toolkit 'tools\lift\lift32.py'))) {
  Say "  The pcrecomp toolkit is not beside this folder ($Toolkit)."
  if (-not (Ask "  Download it now?")) { Fail "pcrecomp is required at $Toolkit." }
  if (Get-Command git -ErrorAction SilentlyContinue) {
    Run "Cloning pcrecomp" @('git', 'clone', '--depth', '1', 'https://github.com/sp00nznet/pcrecomp', $Toolkit)
  } else {
    $zip = Join-Path $env:TEMP 'pcrecomp.zip'
    Say "  Downloading pcrecomp..."
    Invoke-WebRequest 'https://github.com/sp00nznet/pcrecomp/archive/refs/heads/main.zip' -OutFile $zip -UseBasicParsing
    $tmp = Join-Path $env:TEMP 'pcrecomp-unzip'
    Remove-Item $tmp -Recurse -Force -ErrorAction SilentlyContinue
    Expand-Archive $zip $tmp
    Move-Item (Join-Path $tmp 'pcrecomp-main') $Toolkit
  }
}
Say "  pcrecomp: $Toolkit"

$vswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'
function Have-VS {
  if (-not (Test-Path $vswhere)) { return $false }
  $p = & $vswhere -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 Microsoft.VisualStudio.Component.VC.CMake.Project -property installationPath
  return [bool]$p
}
if (-not (Have-VS)) {
  Say "  Visual Studio's C++ build tools (with CMake) are not installed."
  Say "  They are free, about 6 GB, and need an administrator prompt."
  if (-not (Ask "  Install Visual Studio 2022 Build Tools now (winget)?")) { Fail "The C++ build tools are required." }
  Winget 'Microsoft.VisualStudio.2022.BuildTools' @('--override', '--passive --wait --add Microsoft.VisualStudio.Workload.VCTools --add Microsoft.VisualStudio.Component.VC.CMake.Project --includeRecommended')
  if (-not (Have-VS)) { Fail "The build tools did not finish installing. Run Setup.cmd again once the Visual Studio Installer is done." }
}
Say "  C++ build tools: found"

# ---------------------------------------------------------------- disc
Step 2 "Installing the game from your disc"
$script:mounted = $null
# A drive letter, a folder, or an .iso file (mounted here) -> the disc root, or "".
function Resolve-Disc([string]$d) {
  $d = $d.Trim('"', ' ')
  if (-not $d) { return "" }
  if ($d -match '\.iso$') {
    if (-not (Test-Path $d)) { Say "  No file at $d" 'Yellow'; return "" }
    try {
      $iso = (Resolve-Path $d).Path
      $img = Mount-DiskImage -ImagePath $iso -PassThru
      $script:mounted = $iso
      $d = "$(($img | Get-Volume).DriveLetter):\"
      Say "  Mounted the ISO as $d"
    } catch {
      Say "  Windows would not mount it from here. Double-click the .iso in Explorer" 'Yellow'
      Say "  (that mounts it as a drive), then type that drive's letter." 'Yellow'
      return ""
    }
  } elseif ($d -match '^[A-Za-z]:?\\?$') { $d = "$($d.Substring(0,1)):\" }
  if (-not (Test-Path (Join-Path $d 'REWOLF\INSTALL.EXE'))) {
    Say "  No REWOLF\INSTALL.EXE under $d -- that is not the Gunman Chronicles disc." 'Yellow'
    return ""
  }
  return $d
}

if ((Test-Path 'game\gunman.exe') -and (Test-Path 'game\rewolf\media\sierra.avi') -and -not $Force) {
  Say "  Already installed in game\ (skipping)."
} else {
  $Disc = Resolve-Disc $Disc
  if (-not $Disc) {
    $found = Get-Volume -ErrorAction SilentlyContinue | Where-Object { $_.DriveType -eq 'CD-ROM' -and $_.DriveLetter } |
             Where-Object { Test-Path "$($_.DriveLetter):\REWOLF\INSTALL.EXE" } | Select-Object -First 1
    if ($found) { $Disc = "$($found.DriveLetter):\"; Say "  Found the disc in $Disc" }
  }
  while (-not $Disc) {
    $Disc = Resolve-Disc (Read-Host "  Insert the disc and type its drive letter (e.g. E), or paste the path of an .iso file")
  }
  Run "Unpacking the game (a minute or two)" ($pyargs + @('tools\install.py', $Disc))
  if ($script:mounted) { Dismount-DiskImage -ImagePath $script:mounted | Out-Null }
}

# ---------------------------------------------------------------- build
Step 3 "Analyzing the game's code (about 10 minutes, once)"
if ((Test-Path 'analysis\server.functions.json') -and -not $Force) { Say "  Already done (skipping)." }
else { Run "Analyzing" ($pyargs + @('tools\analyze.py')) }

Step 4 "Translating it to C (a few minutes)"
if ((Test-Path 'src\recomp\gen\recomp_dispatch.c') -and -not $Force) { Say "  Already done (skipping)." }
else { Run "Lifting" ($pyargs + @('run_lift.py')) }

Step 5 "Compiling (10-20 minutes the first time)"
Run "Building" @('cmd', '/c', (Join-Path $Root 'build.cmd'))
if (-not (Test-Path 'build\gunman.exe')) { Fail "the build did not produce build\gunman.exe." }

# ---------------------------------------------------------------- shortcut
Step 6 "Making a shortcut"
$lnk = Join-Path $Root 'Gunman Chronicles.lnk'
$sh = New-Object -ComObject WScript.Shell
$s = $sh.CreateShortcut($lnk)
$s.TargetPath = Join-Path $Root 'build\gunman.exe'
$s.Arguments = 'game'
$s.WorkingDirectory = $Root
$s.IconLocation = (Join-Path $Root 'game\gunman.exe') + ',0'
$s.Description = 'Gunman Chronicles, statically recompiled'
$s.Save()
Say "  $lnk"

Write-Host ""
Say "Done. Double-click 'Gunman Chronicles' in this folder to play." 'Green'
Say "First run: the game asks for your CD key, then plays the intros (Esc skips)."
Say "In game: F11 fullscreen, F12 scaling, F9 colour, F8 texture filtering."
Read-Host "Press Enter to close" | Out-Null
