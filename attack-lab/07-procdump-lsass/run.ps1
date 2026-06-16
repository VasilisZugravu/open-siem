# Scenario 07 — LSASS Memory Dump via procdump
# Triggers RULE-007: process_creation, command_line contains "lsass"
# REQUIRES: procdump.exe in the same folder as this script, run as Administrator.
# Download procdump.exe from https://learn.microsoft.com/en-us/sysinternals/downloads/procdump
# Run on: Windows VM with Sysmon + windows_forwarder.py running, as Administrator

$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$procdump = Join-Path $here "procdump.exe"

if (-not (Test-Path $procdump)) {
    Write-Error "procdump.exe not found at $procdump. Download it from Sysinternals."
    exit 1
}

Write-Host "[07] Running procdump against lsass.exe..."
$dump = Join-Path $here "lsass.dmp"
& $procdump -accepteula -ma lsass.exe $dump | Out-Null
Write-Host "[07] Removing dump file..."
Remove-Item $dump -Force -ErrorAction SilentlyContinue
Write-Host "[07] Done."
