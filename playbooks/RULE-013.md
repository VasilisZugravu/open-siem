# RULE-013 — Inbound Connection from External Host

**Trigger:** `network_connection` with `direction=inbound` and `external=true`
(an internet host connected to one of this machine's listening ports).
**Severity:** Medium · **ATT&CK:** T1133 (External Remote Services)

## Triage (first 5 minutes)

1. Open the alert, note the connecting `src_ip` (the external peer), its
   geo/ASN enrichment, and the local port it connected to (`details.dest_port`).
2. Check `details.remote_host` (reverse-DNS) — a recognizable, reputable
   hostname (e.g. a known monitoring/CDN provider) lowers urgency; no PTR or
   an unrelated hosting provider raises it.
3. Identify what's actually listening on that local port and whether you
   intentionally exposed it (e.g. a dev server you forwarded, RDP/SSH you
   meant to allow) — most FPs here are exactly that.

## Investigation

- Cross-reference `src_ip` against recent outbound alerts on the same host —
  is this peer also showing up as a C2 destination (RULE-008) or part of a
  brute-force source (RULE-001)?
- Check for repeated inbound connections from the same `src_ip` across
  multiple ports (port-scan follow-up) — see the
  [network-beaconing hunt](../hunting/network-beaconing.md) for the query
  pattern, adapted to group by `src_ip` instead of `dest_ip`.
- Confirm whether the local port is meant to be internet-reachable at all
  (check firewall/router port-forwarding rules) — an unexpectedly open port
  is itself a finding independent of this specific connection.

## Containment

- If the port/service was not meant to be exposed, close it at the firewall
  immediately and remove any port-forwarding rule that exposed it.
- If the connecting process on the local side is unexpected (not the
  legitimate service you expect on that port), treat as a probable backdoor:
  isolate the host and preserve the process for analysis.

## Escalation

Escalate when the local port hosts anything privileged (RDP, SSH, database,
admin panel) and the connection wasn't expected, or when `src_ip` has no
legitimate reason to reach this host at all.

## False positive check

The dominant FP is intentional exposure: a developer port-forwarding a local
service, a monitoring/uptime-check provider, or a VPN/remote-access tool the
user set up themselves. Confirm intent before treating as malicious.

## Closure

- **closed_fp:** Confirmed intentional exposure (document the service, port,
  and who/why it's reachable from the internet).
- **closed_tp:** Document `src_ip`, local port/service, what the connection
  did, and containment actions taken.
