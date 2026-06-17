# Hunt: Cross-Host Rule Fan-Out

**Hypothesis:** Every detection rule in this SIEM evaluates one host at a
time — RULE-001 looks at one `src_ip` on one host, RULE-003 looks at one
`useradd` on one host. A single medium-severity alert on one host looks
like noise. The same rule firing across many **different** hosts in a
short window looks like an automated campaign, and none of the existing
rules can see that pattern because none of them look across hosts.

**Data source:** `alerts`.

```sql
SELECT
    rule_id,
    title,
    date_trunc('hour', created_at) AS hour_bucket,
    COUNT(DISTINCT host) AS distinct_hosts,
    COUNT(*) AS total_alerts,
    array_agg(DISTINCT host) AS hosts
FROM alerts
WHERE created_at >= now() - interval '24 hours'
GROUP BY rule_id, title, date_trunc('hour', created_at)
HAVING COUNT(DISTINCT host) >= 3
ORDER BY distinct_hosts DESC, hour_bucket DESC;
```

**SQLite equivalent:** replace `date_trunc('hour', created_at)` with
`strftime('%Y-%m-%d %H:00', created_at)`, `array_agg(DISTINCT host)` with
`group_concat(DISTINCT host)`, and `now() - interval '24 hours'` with
`datetime('now', '-1 day')`.

## What a legitimate result looks like

- RULE-006 (scheduled task) fanning out across many hosts right after a
  fleet-wide software deployment — expected and benign.
- RULE-001 (SSH brute force) hitting several internet-facing hosts from
  generic internet scanning traffic — still worth noting, but lower
  priority than a targeted campaign.

## What to escalate on sight

- Any **high/critical** severity rule (RULE-004, 005, 007, 009, 010, 011)
  fanning out across 3+ hosts in the same hour — this is no longer
  "investigate one alert," it's "assume a fleet-wide compromise and stand
  up an incident."
- The same rule fanning out across hosts that have no logical reason to be
  related (different business units, no shared deployment pipeline).

## Tuning

If a specific rule routinely fans out for a known benign reason (e.g.
RULE-006 after every patch Tuesday), exclude that rule from the hunt during
known deployment windows rather than raising the `distinct_hosts` threshold
for everyone — that threshold is what makes a genuine high-severity
fan-out stand out.
