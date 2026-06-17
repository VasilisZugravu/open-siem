# RULE-001 — SSH Brute Force

**Trigger:** 5 or more `auth_failure` events for `sshd` from the same `src_ip`
within 60 seconds. **Severity:** Medium · **ATT&CK:** T1110 (Credential Access)

## Triage (first 5 minutes)

1. Open the alert — note `host` and the `src_ip` in `details`.
2. Pull every `auth_failure` and `auth_success` event for that `src_ip` across
   **all** hosts in the Event Explorer (`/events?search=<src_ip>`), not just
   the alerting host — brute force tools fan out across a host list.
3. Check whether any `auth_success` for the same `src_ip` exists after the
   failures. If yes, this is no longer a brute force attempt — it's a
   suspected compromise. Jump straight to Containment.

## Investigation

- Resolve `src_ip` reputation (is it a known scanner range, a Tor exit node,
  or unattributed)? Internal/jump-host IPs lower the priority significantly.
- Check the targeted `user` field — repeated attempts against `root` or a
  named service account are more concerning than a fat-fingered real user.
- Look for the same `src_ip` appearing on RULE-009 (brute force → useradd) —
  that sequence rule is the high-fidelity escalation of this one.

## Containment

- If a successful login followed the failures: treat as compromised
  credentials. Force a password reset for the affected account and review
  `auth_success` + `command_execution` events on that host for the following
  hour.
- Block `src_ip` at the firewall/security group if external and not a known
  scanner.

## Escalation

Escalate immediately if an `auth_success` follows the brute force, or if the
same `src_ip` is hitting more than one host (credential-stuffing campaign,
not a single misconfigured client).

## False positive check

See [RULE-001 in false-positives.md](../docs/false-positives.md#rule-001--ssh-brute-force-t1110) —
automated retry tools and mistyped passwords are the common benign causes.

## Closure

- **closed_fp:** Source is a known monitoring/backup tool, or a single user
  confirmed they mistyped their password.
- **closed_tp:** Confirmed brute force attempt; record whether it succeeded
  and what containment action was taken in the alert notes.
