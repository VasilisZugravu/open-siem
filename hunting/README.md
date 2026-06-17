# Threat Hunting

Detection rules fire on known patterns. Hunting looks for activity those
patterns don't cover — the gap between "we have a rule for it" and "we'd
actually notice it." Each hunt below is a hypothesis, a query against the
`events`/`alerts` tables, and what a legitimate result looks like (so you
don't chase every hit as an incident).

Queries are written for PostgreSQL (the `docker-compose` deployment target).
Run them with `psql $DATABASE_URL -f hunting/<file>.sql`, or paste the `SELECT`
into any Postgres client connected to the SIEM database. For the local SQLite
dev database, drop the `->>`/`::` JSON operators and use SQLite's
`json_extract()` equivalent instead — see the note in each file.

| Hunt | Hypothesis | Covers the gap in |
|------|-----------|---------------------|
| [lolbin-inventory.md](lolbin-inventory.md) | Living-off-the-land binaries are being used outside the specific flag combinations the rules check for | RULE-004, 007, 010, 011, 012 |
| [rare-parent-child.md](rare-parent-child.md) | A process spawned from a parent it has never spawned from before on that host | RULE-005 (only checks Office→shell, not arbitrary unusual lineage) |
| [off-hours-privileged-activity.md](off-hours-privileged-activity.md) | Privileged commands run outside the host's normal active hours | RULE-002, 003, 006 (none of which have a time-of-day gate) |
| [network-beaconing.md](network-beaconing.md) | A process makes outbound connections at a suspiciously regular interval, regardless of destination port | RULE-008 (only checks ports 4444/4445) |
| [cross-host-rule-fan-out.md](cross-host-rule-fan-out.md) | The same low-severity rule fires across many hosts in a short window — a single host alert looks like noise, a fleet-wide pattern looks like a campaign | All single-event rules, which only ever evaluate one host at a time |

## Workflow

1. Run the hunt's query against a recent time window (each query has a
   default window — widen or narrow it as needed).
2. Triage hits the same way you'd triage an alert: pull surrounding events
   in the [Event Explorer](../README.md#detection-coverage), check the host
   and user against known-good baselines.
3. If a hunt produces a hit pattern that should become a standing detection,
   write it up as a new rule in `rules/` and add a playbook in `playbooks/`
   rather than re-running the hunt manually every time.
4. If a hunt is noisy, tighten the query (add an allowlist clause) before the
   next run rather than discarding it — see each file's "Tuning" note.
