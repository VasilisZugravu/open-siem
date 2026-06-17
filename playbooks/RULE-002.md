# RULE-002 — Sudo Used to Edit Shadow File or Run visudo

**Trigger:** A `command_execution` event whose `command_line` matches
`(shadow|visudo)`. **Severity:** High · **ATT&CK:** T1548.003 (Privilege Escalation)

## Triage (first 5 minutes)

1. Open the alert, note the `user` and exact `command_line` on the
   triggering event (Alert Detail page lists triggering events).
2. Ask: is this a known administrator performing scheduled sudoers
   maintenance, or an unexpected user/time?
3. Check the immediately preceding events for that user on that host
   (`/events?host=<host>&search=<user>`) — was there a suspicious login or
   privilege-escalation attempt just before this command?

## Investigation

- If `visudo` was used: check whether the sudoers file was actually modified
  (timestamp on `/etc/sudoers`) and whether new NOPASSWD entries or wildcard
  rules were added.
- If `/etc/shadow` was touched directly: that's a stronger signal than
  `visudo` — direct shadow edits are rarer in normal admin workflow and often
  indicate password-hash tampering or backdoor account creation.
- Correlate with RULE-003 (new user) and RULE-009 (brute → useradd) on the
  same host within the surrounding hour.

## Containment

- If unauthorized: revert the sudoers/shadow change from backup, rotate the
  affected account's password, and audit all sudo grants on the host.
- Lock the account that ran the command if it isn't a known administrator.

## Escalation

Escalate if the command ran under a service account, ran outside business
hours, or if `/etc/shadow` itself (not just `visudo`) was the target.

## False positive check

See [RULE-002 in false-positives.md](../docs/false-positives.md#rule-002--sudo-shadow-edit-t1548003) —
the regex also matches unrelated package names like `shadowsocks` or
`shadow-utils`.

## Closure

- **closed_fp:** Command line matched the substring but wasn't a real
  shadow/sudoers edit (e.g. `shadowsocks` service restart).
- **closed_tp:** Confirmed privilege-escalation attempt; document what was
  changed and whether it was reverted.
