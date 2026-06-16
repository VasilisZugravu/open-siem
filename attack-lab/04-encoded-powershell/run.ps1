# Scenario 04 — Encoded PowerShell Command
# Triggers RULE-004: process_creation, process_name=powershell.exe, command_line contains "-enc"
# Run on: Windows VM with Sysmon + windows_forwarder.py running

$cmd = "Write-Output 'attack-lab'"
$enc = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($cmd))
Write-Host "[04] Running: powershell.exe -enc <base64>..."
powershell.exe -enc $enc
Write-Host "[04] Done."
