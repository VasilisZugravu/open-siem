# Scenario 08 — Outbound Connection to C2 Port
# Triggers RULE-008: network_connection, dest_port in [4444, 4445]
# The connection attempt is refused (nothing listening) but Sysmon Event ID 3 still fires.
# Run on: Windows VM with Sysmon + windows_forwarder.py running

Write-Host "[08] Attempting TCP connection to 127.0.0.1:4444..."
$tcp = New-Object System.Net.Sockets.TcpClient
try { $tcp.Connect("127.0.0.1", 4444) } catch {}
$tcp.Close()
Write-Host "[08] Done."
