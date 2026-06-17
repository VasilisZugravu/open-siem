# Hunt: Off-Hours Privileged Activity

**Hypothesis:** RULE-002 (sudo/visudo), RULE-003 (useradd), and RULE-006
(scheduled task) have no time-of-day gate — they fire identically at 2pm
and 3am. An attacker operating outside business hours (to avoid a live
analyst) is a meaningfully different risk than the same command run during
the day, even though both fire the same alert today.

**Data source:** `events` where `event_type IN ('command_execution',
'process_creation')`, filtered to the same command patterns RULE-002,
RULE-003, and RULE-006 already match, but with a time-of-day filter the
rules don't have.

```sql
SELECT host, "user", process_name, command_line, timestamp,
       EXTRACT(HOUR FROM timestamp) AS hour_utc
FROM events
WHERE (
    command_line ~* '(shadow|visudo)'          -- RULE-002 pattern
    OR command_line ILIKE '%useradd%'          -- RULE-003 pattern
    OR (process_name = 'schtasks.exe' AND command_line ILIKE '%/create%')  -- RULE-006 pattern
)
AND EXTRACT(HOUR FROM timestamp) NOT BETWEEN 7 AND 19   -- adjust to your business hours, in UTC
AND timestamp >= now() - interval '7 days'
ORDER BY timestamp;
```

**SQLite equivalent:** replace `EXTRACT(HOUR FROM timestamp)` with
`CAST(strftime('%H', timestamp) AS INTEGER)`, `~*` with `LIKE` (SQLite has
no regex without an extension — use `LIKE '%shadow%' OR LIKE '%visudo%'`),
and `now() - interval '7 days'` with `datetime('now', '-7 days')`.

## What a legitimate result looks like

- Scheduled maintenance windows that are deliberately off-hours.
- An on-call admin handling a 3am page that genuinely requires sudo/useradd.
- Automated CI/CD pipelines that provision infrastructure outside business
  hours by design.

## What to escalate on sight

- Privileged activity from an account that has no history of off-hours
  access.
- Any off-hours hit that also matches RULE-009's pattern (login →
  useradd) — that combination should already be Critical; this hunt is
  mainly useful for RULE-002/006, which RULE-009 doesn't cover.

## Tuning

Maintain an allowlist of known on-call accounts and CI service accounts and
exclude them explicitly (`AND "user" NOT IN (...)`) rather than narrowing
the hour window, which would just create a blind spot at the edges of your
allowlisted hours.
