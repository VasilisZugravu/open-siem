# RULE-008 — Outbound Connection to Known C2 Port

**Trigger:** `network_connection` to `dest_port` 4444 or 4445.
**Severity:** High · **ATT&CK:** T1071 (Command and Control)

## Triage (first 5 minutes)

1. Open the alert, note the connecting `process_name` and `dest_ip`.
2. Check whether `dest_ip` is internal/private — a developer running a
   local Metasploit lab or `localtunnel` instance is the realistic FP here.
3. If `dest_ip` is external/public, treat as a likely live C2 channel and
   move to Containment without waiting for further confirmation.

## Investigation

- Resolve `dest_ip` reputation (known C2 infrastructure, hosting provider,
  Tor exit, etc.).
- Identify what spawned the connecting process — does it trace back to a
  RULE-004/005/011 alert (encoded PowerShell or macro-spawned shell) on the
  same host shortly before?
- Check for repeated/periodic connections to the same `dest_ip` (beaconing
  interval) using the [network-beaconing hunt](../hunting/network-beaconing.md).

## Containment

- Block `dest_ip` at the firewall and isolate the host from the network.
- Kill the connecting process and preserve it (don't just kill -9 without
  capturing the binary/command line first).

## Escalation

Escalate immediately for any external `dest_ip` — this rule has low FP
exposure on production hosts and high impact if real.

## False positive check

See [RULE-008 in false-positives.md](../docs/false-positives.md#rule-008--outbound-connection-to-known-c2-port-t1071) —
developer/test traffic to internal services on 4444 is the only realistic FP.

## Closure

- **closed_fp:** Confirmed internal developer tooling on an allowlisted host.
- **closed_tp:** Document `dest_ip`, the connecting process chain, and
  containment actions taken.
