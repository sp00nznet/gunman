<#
  One bisection step: lift with the given ranges running as ORIGINAL code,
  build, boot into a new game, and report whether it crashed and what it drew.
    powershell -File tools/bisect.ps1 -Range 0x100A3C27-0x100A4870 [-Extra "-PageHeap"]
#>
param([string]$Range = "", [int]$Seconds = 150, [string]$Extra = "")
$root = Split-Path $PSScriptRoot -Parent
Set-Location $root
if ($Range) { python run_lift.py --native-range $Range 2>&1 | Select-String "native ranges|errors" }
else { python run_lift.py 2>&1 | Select-String "errors" }
cmd /c .\build.cmd 2>&1 | Select-String -Pattern " error |FAILED" | Select-Object -First 5
$a = @('-Seconds', $Seconds, '-Press', '0x1B@14 0x1B@24', '-Click', '110,189@32 85,182@40',
       '-Watchdog', '30', '-Shot', 'work/bisect.png')
if ($Extra) { $a += ($Extra -split ' ') }
powershell -NoProfile -ExecutionPolicy Bypass -File tools/run.ps1 @a | Select-Object -Last 1
Get-Content work\run.log | Select-String "crash\]|ITAIL|ICALL|in lifted" | Select-Object -First 4
