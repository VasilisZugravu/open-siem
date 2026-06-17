# Scenario 12 — certutil Used to Decode a File
# Triggers RULE-012: process_creation, process_name=certutil.exe, command_line
# contains -decode. Simulates the LOLBin payload-staging technique: encode a
# harmless text file to Base64 (the staging step an attacker would normally skip,
# having delivered the encoded blob already), then decode it back with certutil.
# Run on: Windows VM with Sysmon + windows_forwarder.py running

$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$plain = Join-Path $here "payload.txt"
$encoded = Join-Path $here "payload.b64"
$decoded = Join-Path $here "payload.out"

"attack-lab" | Out-File -FilePath $plain -Encoding ascii -NoNewline
certutil.exe -encode $plain $encoded | Out-Null

Write-Host "[12] Running: certutil.exe -decode payload.b64 payload.out..."
certutil.exe -decode $encoded $decoded | Out-Null

Write-Host "[12] Cleaning up..."
Remove-Item $plain, $encoded, $decoded -Force -ErrorAction SilentlyContinue
Write-Host "[12] Done."
