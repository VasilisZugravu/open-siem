# Hunt: Network Beaconing (Any Port)

**Hypothesis:** RULE-008 only flags ports 4444/4445. C2 frameworks routinely
use 443, 8080, or any port that blends in with normal traffic — the
distinguishing signal isn't the port, it's a suspiciously **regular
interval** between connections from the same process to the same
destination (classic beaconing behavior), regardless of which port is used.

**Data source:** `events` where `event_type = 'network_connection'`.

```sql
WITH conns AS (
    SELECT
        host,
        process_name,
        dest_ip,
        timestamp,
        LAG(timestamp) OVER (
            PARTITION BY host, process_name, dest_ip ORDER BY timestamp
        ) AS prev_timestamp
    FROM events
    WHERE event_type = 'network_connection'
      AND timestamp >= now() - interval '24 hours'
),
intervals AS (
    SELECT host, process_name, dest_ip,
           EXTRACT(EPOCH FROM (timestamp - prev_timestamp)) AS interval_seconds
    FROM conns
    WHERE prev_timestamp IS NOT NULL
)
SELECT host, process_name, dest_ip,
       COUNT(*) AS connection_count,
       AVG(interval_seconds) AS avg_interval_seconds,
       STDDEV(interval_seconds) AS stddev_interval_seconds
FROM intervals
GROUP BY host, process_name, dest_ip
HAVING COUNT(*) >= 5
   AND STDDEV(interval_seconds) < AVG(interval_seconds) * 0.1   -- tight, regular interval
ORDER BY connection_count DESC;
```

A low `stddev/avg` ratio means the connections are happening at a near-fixed
interval — human-driven traffic is bursty and irregular; beaconing malware
is not.

**SQLite equivalent:** SQLite lacks `STDDEV`/window-function `LAG` in older
builds — run this hunt against the Postgres deployment (`docker-compose`)
rather than the local SQLite dev database.

## What a legitimate result looks like

- A health-check or telemetry agent polling a fixed internal endpoint every
  N seconds (these are usually well-known process names — baseline them
  once and allowlist by `process_name` + `dest_ip`).
- A package manager or update checker on a fixed schedule.

## What to escalate on sight

- A regular-interval connection to an external `dest_ip` from a process
  that isn't a known agent/updater.
- Regular intervals that match common C2 framework defaults (e.g. ~60s).

## Tuning

Once you've identified the legitimate recurring connections in your
environment, allowlist them by `(process_name, dest_ip)` pair rather than
raising the `stddev` threshold — raising the threshold globally would also
hide real beaconing that happens to jitter slightly.
