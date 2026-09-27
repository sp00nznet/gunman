<#
  The bring-up loop: lift, build, then boot to a new game on Medium.
    powershell -File tools/iterate.ps1 [-NoLift] [-Seconds 90] [-Extra "..."]
#>
param([switch]$NoLift, [int]$Seconds = 90, [string]$Extra = "")
$root = Split-Path $PSScriptRoot -Parent
Set-Location $root
if (-not $NoLift) { python run_lift.py 2>&1 | Select-Object -Last 3 }
cmd /c .\build.cmd 2>&1 | Select-String -Pattern " error |FAILED" | Select-Object -First 5
# Esc through both intros, New game, Medium.
$args2 = @('-Seconds', $Seconds, '-Press', '0x1B@14 0x1B@24', '-Click', '110,189@32 85,182@40',
           '-Shot', 'work/ingame.png')
if ($Extra) { $args2 += ($Extra -split ' ') }
powershell -NoProfile -ExecutionPolicy Bypass -File tools/run.ps1 @args2 | Select-Object -Last 1
Get-Content work\run.log | Where-Object { $_ -notmatch '^\[(callback|native)\]' } | Select-Object -Last 25
