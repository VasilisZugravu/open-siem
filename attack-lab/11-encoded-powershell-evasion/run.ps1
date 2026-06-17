# Scenario 11 — Encoded PowerShell, Case/Long-Form Evasion
# Triggers RULE-011: process_creation, process_name matches powershell.exe and
# command_line matches -enc, both case-insensitively. Demonstrates that RULE-004
# (exact-case process_name equality + exact-case "-enc" substring) does NOT fire
# on this command line, while RULE-011 closes that gap.
# Run on: Windows VM with Sysmon + windows_forwarder.py running

$cmd = "Write-Output 'attack-lab'"
$enc = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($cmd))
Write-Host "[11] Running: PowerShell.EXE -EnCoDedCommand <base64>..."
& "$env:WINDIR\System32\WindowsPowerShell\v1.0\PowerShell.EXE" -EnCoDedCommand $enc
Write-Host "[11] Done."
