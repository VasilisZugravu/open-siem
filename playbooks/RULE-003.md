# RULE-003 — New Local User Account Created

**Trigger:** A `command_execution` event whose `command_line` contains
`useradd`. **Severity:** Medium · **ATT&CK:** T1136.001 (Persistence)

## Triage (first 5 minutes)

1. Open the alert, note the `user` who ran the command and the new account
   name in `command_line`.
2. Check whether this matches a known onboarding ticket / change request.
3. Look for a preceding `auth_success` on the same host within the last
   10 minutes (`/events?host=<host>&event_type=auth_success`) — if present,
   this should already have fired RULE-009; if RULE-009 did **not** fire,
   check whether the login was from a different host than the useradd, since
   RULE-009 requires both steps on the same host.

## Investigation

- Resolve the new account's group membership and home directory flags
  (`-G sudo`, `-G wheel`, custom `-d` path) — privileged group membership
  on an unapproved account is the strongest signal of malicious intent.
- Check whether the account was used to log in shortly after creation.
- Cross-reference against your ticketing system / change log for a matching
  provisioning request.

## Containment

- If unapproved: disable the new account immediately (`usermod -L`) and
  preserve it for forensics rather than deleting it outright.
- Audit `/etc/passwd` and `/etc/group` for any other recently added accounts
  on the same host.

## Escalation

Escalate if the account was created outside business hours, granted
sudo/wheel membership, or was created by a non-admin user.

## False positive check

See [RULE-003 in false-positives.md](../docs/false-positives.md#rule-003--new-local-user-created-t1136001) —
this is the highest-FP rule in the set; routine provisioning fires it
constantly without an allowlist.

## Closure

- **closed_fp:** Matches an approved provisioning ticket/change request.
- **closed_tp:** Unapproved account; document whether it was disabled and
  whether it was used before disablement.
