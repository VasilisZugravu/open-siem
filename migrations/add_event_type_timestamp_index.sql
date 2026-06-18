-- C3: Composite index on (event_type, timestamp) to speed up aggregation and
-- sequence rule queries, both of which filter on these two columns every 30s
-- detection cycle. Without this index each rule performs a full table scan.
CREATE INDEX IF NOT EXISTS ix_events_event_type_timestamp ON events(event_type, timestamp);
