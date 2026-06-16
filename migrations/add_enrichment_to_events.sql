-- Run against existing PostgreSQL installations to add the enrichment column.
-- IF NOT EXISTS prevents errors on re-runs. Fresh installs use db.create_all().
ALTER TABLE events ADD COLUMN IF NOT EXISTS enrichment JSON;
