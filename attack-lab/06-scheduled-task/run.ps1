# Scenario 06 — Scheduled Task Created
# Triggers RULE-006: process_creation, process_name=schtasks.exe, command_line contains "/create"
# Run on: Windows VM with Sysmon + windows_forwarder.py running

Write-Host "[06] Creating scheduled task AttackLabTask..."
schtasks /create /tn "AttackLabTask" /tr "cmd.exe" /sc once /st 00:00 /f | Out-Null
Write-Host "[06] Deleting scheduled task..."
schtasks /delete /tn "AttackLabTask" /f | Out-Null
Write-Host "[06] Done."
