<#
  Boot the recompiled launcher for N seconds, then screenshot its window (only
  its window, never the desktop) and stop it.

    powershell -File tools/run.ps1 [-Seconds 20] [-Shot work/shot.png] [-- guest args]
#>
param(
  [int]$Seconds = 20,             # run this long, then screenshot and stop
  [string]$Shot = "work/shot.png",
  [string]$Press = "",            # "0x1B@14 ..."      -> --press (virtual key held)
  [string]$Click = "",            # "110,189@32 ..."   -> --click (virtual cursor)
  [switch]$Imports,               # --imports: every call into Windows
  [string]$ImportsFrom = "",      # --imports-from VA: only calls from one module
  [switch]$Callbacks,             # --callbacks: every call Windows makes into the game
  [switch]$PageHeap,              # --pageheap: guard-page guest heap blocks
  [int]$Watchdog = 0,             # --watchdog N
  [string]$Build = "build",       # which build directory's gunman.exe
  [switch]$Fps,
  [string]$Extra = "",           # more runtime flags, e.g. "--no-present"
  [int]$Profile = 0,             # --profile N: sampling profile every N seconds                  # --fps: frames per second from r_framecount
  [string]$NativeMods = "",       # "sw.dll vgui.dll" -> --native (bisection)
  [string]$TypeFile, [int]$TypeAt = 8,   # type a line of text into the focused control
  [switch]$Native,                # run the RETAIL exe instead: the reference
  [string]$Rebased = "work/rebased",
  [string]$Patch = "",            # "VA=HEX ..." -> --patch (bisection)
  [switch]$ImportStats,
  [string]$TraceImport = "",       # --trace-import NAME           # --import-stats (report with -Watchdog)
  [int]$ShotEvery = 0,            # also capture every N seconds: a lit/black timeline
  [int]$Grab = 0,                 # --grab S: in-process capture of the presented frame
  [switch]$NoDDraw,               # --noddraw: GDI presentation, so PrintWindow sees frames
  [switch]$FromScreen,            # capture the screen pixels under the window, not PrintWindow
  [string]$GameArgs = "-width 640 -height 480",  # the game's own command line; small so a test window stays out of the way
  [Parameter(ValueFromRemainingArguments = $true)] $GuestArgs)
$root = Split-Path $PSScriptRoot -Parent
Set-Location $root
$a = @('game', '--rebased', $Rebased)
if ($Imports) { $a += '--imports' }
foreach ($k in ($Press -split '\s+' | Where-Object { $_ })) { $a += '--press'; $a += $k }
if ($Callbacks) { $a += '--callbacks' }
if ($PageHeap) { $a += '--pageheap' }
if ($Fps) { $a += '--fps' }
$a += '--corner'   # test windows sit bottom-right, not activated
foreach ($k in ($Extra -split '\s+' | Where-Object { $_ })) { $a += $k }
if ($Profile) { $a += '--profile'; $a += $Profile }
if ($NoDDraw) { $a += '--noddraw' }
if ($ImportStats) { $a += '--import-stats' }
foreach ($k in ($Patch -split '\s+' | Where-Object { $_ })) { $a += '--patch'; $a += $k }
if ($TraceImport) { $a += '--trace-import'; $a += $TraceImport }
if ($Grab) { $a += '--grab'; $a += $Grab; Remove-Item work\frame.bmp -ErrorAction SilentlyContinue }
if ($Watchdog) { $a += '--watchdog'; $a += $Watchdog }
foreach ($k in ($NativeMods -split '\s+' | Where-Object { $_ })) { $a += '--native'; $a += $k }
if ($ImportsFrom) { $a += '--imports-from'; $a += $ImportsFrom }
# -Click is done by the runtime (a virtual cursor), not by posting from here.
foreach ($k in ($Click -split '\s+' | Where-Object { $_ })) { $a += '--click'; $a += $k }
if ($GameArgs) { $GuestArgs = @($GameArgs -split '\s+' | Where-Object { $_ }) + @($GuestArgs | Where-Object { $_ }) }
if ($GuestArgs) { $a += '--'; $a += $GuestArgs }
if ($Native) {
  # The RETAIL exe on the same install and registry: the reference to compare
  # against. Guest args (after --) go to it; the runtime flags do not apply.
  $exe = Join-Path $root 'game\gunman.exe'; $wd = Join-Path $root 'game'
  if ($GuestArgs) { $p = Start-Process $exe -ArgumentList $GuestArgs -WorkingDirectory $wd -PassThru }
  else            { $p = Start-Process $exe -WorkingDirectory $wd -PassThru }
} else {
  $p = Start-Process (Join-Path $Build 'gunman.exe') -ArgumentList $a -PassThru -NoNewWindow `
         -RedirectStandardError work\run.log -RedirectStandardOutput work\run.out
}
if ($TypeFile) { Start-Sleep $TypeAt; $Seconds = [Math]::Max(1, $Seconds - $TypeAt) }
$p.Refresh()
Add-Type @"
using System; using System.Runtime.InteropServices; using System.Text;
public class W {
  public delegate bool EP(IntPtr h, IntPtr l);
  [DllImport("user32.dll")] public static extern bool EnumWindows(EP f, IntPtr l);
  [DllImport("user32.dll")] public static extern uint GetWindowThreadProcessId(IntPtr h, out uint p);
  [DllImport("user32.dll")] public static extern bool IsWindowVisible(IntPtr h);
  [DllImport("user32.dll")] public static extern bool GetWindowRect(IntPtr h, out RECT r);
  [DllImport("user32.dll")] public static extern bool PrintWindow(IntPtr h, IntPtr dc, uint f);
  [DllImport("user32.dll")] public static extern int GetWindowText(IntPtr h, StringBuilder s, int n);
  [DllImport("user32.dll")] public static extern bool IsHungAppWindow(IntPtr h);
  [DllImport("user32.dll")] public static extern IntPtr SendMessageTimeout(IntPtr h, uint m, IntPtr w, IntPtr l, uint f, uint ms, out IntPtr r);
  public static bool Responds(IntPtr h) { IntPtr r; return SendMessageTimeout(h, 0, IntPtr.Zero, IntPtr.Zero, 2, 2000, out r) != IntPtr.Zero; }
  [DllImport("user32.dll")] public static extern bool SetWindowPos(IntPtr h, IntPtr after, int x, int y, int cx, int cy, uint f);
  [DllImport("user32.dll")] public static extern bool PostMessage(IntPtr h, uint m, IntPtr w, IntPtr l);
  [StructLayout(LayoutKind.Sequential)] public struct GUI {
    public int cb, flags; public IntPtr active, focus, capture, menu, move, caret; public RECT rc; }
  [DllImport("user32.dll")] public static extern bool GetGUIThreadInfo(uint tid, ref GUI g);
  [StructLayout(LayoutKind.Sequential)] public struct RECT { public int L, T, R, B; }
}
"@
Add-Type -AssemblyName System.Drawing
function Capture($h, $path) {
  # PrintWindow waits on the window thread forever; probe it with a timeout first.
  if ([W]::IsHungAppWindow($h) -or -not [W]::Responds($h)) { return "not responding" }
  $r = New-Object W+RECT; [void][W]::GetWindowRect($h, [ref]$r)
  $bmp = New-Object Drawing.Bitmap ($r.R - $r.L), ($r.B - $r.T)
  $g = [Drawing.Graphics]::FromImage($bmp); $dc = $g.GetHdc()
  [void][W]::PrintWindow($h, $dc, 2); $g.ReleaseHdc($dc)
  $bmp.Save((Join-Path $root $path))
  $lit = 0; $n = 0
  for ($y = 40; $y -lt $bmp.Height; $y += 4) { for ($x = 8; $x -lt $bmp.Width - 8; $x += 4) {
    $c = $bmp.GetPixel($x, $y); $n++; if (($c.R + $c.G + $c.B) -gt 30) { $lit++ } } }
  "{0:P0}" -f ($lit / [Math]::Max(1, $n))
}
$found = $null
function Find-Window {
  # The game's own window by title, over any other window of the process: an
  # error message box is a visible window too, and white reads as "lit".
  $script:found = $null; $script:any = $null
  [W]::EnumWindows({ param($h, $l)
    $pid2 = 0; [void][W]::GetWindowThreadProcessId($h, [ref]$pid2)
    if ($pid2 -eq $p.Id -and [W]::IsWindowVisible($h)) {
      $sb = New-Object Text.StringBuilder 256; [void][W]::GetWindowText($h, $sb, 256)
      if ($sb.ToString() -eq 'Gunman Chronicles' -and -not $script:found) { $script:found = $h }
      if (-not $script:any) { $script:any = $h }
    }
    $true }, [IntPtr]::Zero) | Out-Null
  if ($script:found) { $script:found } else { $script:any }
}
# -TypeFile: post a line of text, then Enter, to the guest's window -- WM_CHAR
# straight to the window procedure, so nothing steals focus from the desktop.
if ($TypeFile -and -not $p.HasExited) {
  $h = Find-Window
  # The prompt is a dialog: text goes to whichever child has the focus.
  $tid = [W]::GetWindowThreadProcessId($h, [ref]([uint32]0))
  $g = New-Object W+GUI; $g.cb = [Runtime.InteropServices.Marshal]::SizeOf($g)
  if ([W]::GetGUIThreadInfo($tid, [ref]$g) -and $g.focus -ne [IntPtr]::Zero) { $h = $g.focus }
  foreach ($c in ((Get-Content $TypeFile -Raw).Trim()).ToCharArray()) {
    [void][W]::PostMessage($h, 0x0102, [IntPtr][int]$c, [IntPtr]1); Start-Sleep -Milliseconds 30
  }
  [void][W]::PostMessage($h, 0x0100, [IntPtr]0x0D, [IntPtr]1)
  [void][W]::PostMessage($h, 0x0102, [IntPtr]0x0D, [IntPtr]1)
  [void][W]::PostMessage($h, 0x0101, [IntPtr]0x0D, [IntPtr]1)
  "typed $TypeFile into the guest window"
  $found = $null
}

if ($ShotEvery -gt 0) {
  # A lit/black timeline: the game's opening alternates, so one shot says little.
  $t0 = (Get-Date) - $p.StartTime
  for ($t = [int][Math]::Ceiling($t0.TotalSeconds / $ShotEvery) * $ShotEvery; $t -le $Seconds; $t += $ShotEvery) {
    $wait = $t - ((Get-Date) - $p.StartTime).TotalSeconds
    if ($wait -gt 0) { Start-Sleep -Milliseconds ([int]($wait * 1000)) }
    $p.Refresh(); if ($p.HasExited) { "exited at ${t}s"; break }
    $h = Find-Window
    if ($h) { "t={0,4}s  lit={1}" -f $t, (Capture $h ("work/t{0:D4}.png" -f $t)) }
  }
} else { Start-Sleep $Seconds }
$p.Refresh()
if (-not $p.HasExited) {
  [W]::EnumWindows({ param($h, $l)
    $pid2 = 0; [void][W]::GetWindowThreadProcessId($h, [ref]$pid2)
    if ($pid2 -eq $p.Id -and [W]::IsWindowVisible($h)) {
      $r = New-Object W+RECT; [void][W]::GetWindowRect($h, [ref]$r)
      $sb = New-Object Text.StringBuilder 256; [void][W]::GetWindowText($h, $sb, 256)
      "window: '$($sb)' $($r.R - $r.L)x$($r.B - $r.T)"
      if (-not $script:found -and ($r.R - $r.L) -gt 100) { $script:found = $h }
    }
    $true }, [IntPtr]::Zero) | Out-Null
  if ($script:found -and ([W]::IsHungAppWindow($script:found) -or -not [W]::Responds($script:found))) {
    # PrintWindow waits on the window's thread; a hung game would hang us too.
    "window not responding -- no screenshot"
  } elseif ($script:found) {
    $r = New-Object W+RECT; [void][W]::GetWindowRect($script:found, [ref]$r)
    $bmp = New-Object Drawing.Bitmap ($r.R - $r.L), ($r.B - $r.T)
    $g = [Drawing.Graphics]::FromImage($bmp); $dc = $g.GetHdc()
    if ($FromScreen) {
      # DirectDraw output can be invisible to PrintWindow; read what is
      # actually on screen there instead (only valid while it is on top).
      $g.ReleaseHdc($dc)
      # Topmost for the capture, WITHOUT activating: nothing takes the
      # keyboard from whoever is at the desktop. (NOSIZE|NOMOVE|NOACTIVATE)
      [void][W]::SetWindowPos($script:found, [IntPtr](-1), 0, 0, 0, 0, 0x13)
      Start-Sleep -Milliseconds 600
      $g.CopyFromScreen($r.L, $r.T, 0, 0, $bmp.Size)
      [void][W]::SetWindowPos($script:found, [IntPtr](-2), 0, 0, 0, 0, 0x13)
    } else {
      [void][W]::PrintWindow($script:found, $dc, 2); $g.ReleaseHdc($dc)
    }
    $bmp.Save((Join-Path $root $Shot))
    # How much of the client area is not black: a quick "is anything drawn".
    $lit = 0; $n = 0
    for ($y = 40; $y -lt $bmp.Height; $y += 4) { for ($x = 8; $x -lt $bmp.Width - 8; $x += 4) {
      $c = $bmp.GetPixel($x, $y); $n++; if (($c.R + $c.G + $c.B) -gt 30) { $lit++ } } }
    "screenshot: $Shot  nonblack={0:P0}" -f ($lit / [Math]::Max(1, $n))
  }
  Stop-Process -Id $p.Id -Force
} else { "exited with $($p.ExitCode)" }
