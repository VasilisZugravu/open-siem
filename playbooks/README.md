# Incident Response Playbooks

One playbook per detection rule. Each follows the same structure so an analyst
new to this SIEM can pick up any alert and know what to do without reading code:

- **Trigger** — what fired this alert, in plain language.
- **Triage** — the first 5 minutes: what to look at in the dashboard, in order.
- **Investigation** — what to pivot on next if triage doesn't resolve it.
- **Containment** — actions to stop the activity if it looks real.
- **Escalation** — when to stop investigating alone and loop someone else in.
- **False positive check** — link to the matching section in
  [docs/false-positives.md](../docs/false-positives.md), which has the full
  FP rationale and tuning recommendations.
- **Closure** — what "closed_tp" / "closed_fp" should mean for this rule.

| Rule | Playbook | Severity |
|------|----------|----------|
| RULE-001 | [SSH Brute Force](RULE-001.md) | Medium |
| RULE-002 | [Sudo Shadow Edit](RULE-002.md) | High |
| RULE-003 | [New Local User Created](RULE-003.md) | Medium |
| RULE-004 | [Encoded PowerShell](RULE-004.md) | High |
| RULE-005 | [Office Spawns Shell](RULE-005.md) | High |
| RULE-006 | [Scheduled Task Created](RULE-006.md) | Medium |
| RULE-007 | [LSASS Memory Dump (procdump)](RULE-007.md) | High |
| RULE-008 | [C2 Port Connection](RULE-008.md) | High |
| RULE-009 | [Brute Force → Account Creation](RULE-009.md) | Critical |
| RULE-010 | [LSASS Dump via comsvcs.dll](RULE-010.md) | High |
| RULE-011 | [Encoded PowerShell Evasion](RULE-011.md) | High |
| RULE-012 | [certutil Decode](RULE-012.md) | Medium |

## Using a playbook

1. Open the alert in the dashboard (`/alerts/<id>`) — note the `host`,
   triggering event IDs, and `created_at`.
2. Follow **Triage** for that rule.
3. Use the [Event Explorer](../README.md#detection-coverage) (`/events?host=<host>`)
   to pull surrounding activity on the same host.
4. Record findings in the alert's notes field before changing status.
5. Set status via the dashboard: `new` → `in_progress` → `closed_tp` or `closed_fp`.

See [hunting/](../hunting/) for proactive queries that look for activity *not*
already covered by these 12 rules.
