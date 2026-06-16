# Scenario 05 — Office Application Spawns Shell (simulated)
# Triggers RULE-005: process_creation, process_name=cmd.exe, parent_process=winword.exe
# Simulation: copies cmd.exe to $TEMP\winword.exe, spawns cmd.exe from it.
# Sysmon Event ID 1 captures cmd.exe with ParentImage ending in winword.exe.
# Run on: Windows VM with Sysmon + windows_forwarder.py running

$fake = "$env:TEMP\winword.exe"
Write-Host "[05] Copying cmd.exe to $fake..."
Copy-Item "$env:SystemRoot\System32\cmd.exe" $fake -Force
Write-Host "[05] Spawning cmd.exe from simulated winword.exe..."
& $fake /c "echo attack-lab"
Write-Host "[05] Cleaning up..."
Remove-Item $fake -Force
Write-Host "[05] Done."
