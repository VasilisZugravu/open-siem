# Hunt: Rare Parent/Child Process Pairs

**Hypothesis:** RULE-005 only flags Office apps spawning a shell. Malicious
process lineage takes many other forms (a browser spawning a shell, a PDF
reader spawning PowerShell, a service binary spawning `cmd.exe` for the
first time ever on that host). The signal isn't a specific pair — it's a
pair that has **never been seen before** on that host.

**Data source:** `events` where `event_type = 'process_creation'`.

```sql
WITH pairs AS (
    SELECT
        host,
        details->>'parent_process' AS parent_process,
        process_name AS child_process,
        timestamp
    FROM events
    WHERE event_type = 'process_creation'
      AND details->>'parent_process' IS NOT NULL
),
first_seen AS (
    SELECT host, parent_process, child_process, MIN(timestamp) AS first_ts
    FROM pairs
    GROUP BY host, parent_process, child_process
)
SELECT p.host, p.parent_process, p.child_process, p.timestamp
FROM pairs p
JOIN first_seen f
  ON p.host = f.host
  AND p.parent_process = f.parent_process
  AND p.child_process = f.child_process
  AND p.timestamp = f.first_ts
WHERE p.timestamp >= now() - interval '24 hours'
ORDER BY p.host, p.timestamp;
```

This returns the first-ever occurrence of each `(host, parent, child)`
triple that happened in the last 24 hours — i.e. brand-new lineage on a
host that's presumably been running for a while.

**SQLite equivalent:** replace `details->>'parent_process'` with
`json_extract(details, '$.parent_process')` and `now() - interval '24 hours'`
with `datetime('now', '-1 day')`.

## What a legitimate result looks like

- A new pair appearing right after a software install or update (new
  installer binary spawning a one-time setup helper).
- The first reboot after deploying new endpoint software.

## What to escalate on sight

- A browser, PDF reader, or media player spawning `cmd.exe`, `powershell.exe`,
  or `rundll32.exe` for the first time.
- Any unsigned/unknown parent process spawning a known LOLBin.

## Tuning

This hunt is naturally noisy right after any fleet-wide software deployment
— run it before and after planned deployment windows separately, and expect
a spike immediately following one. If a specific new-pair pattern repeats
across many hosts right after a known deployment, allowlist it by parent
binary path rather than suppressing the whole hunt.
