-- Run against existing PostgreSQL installations to add triage notes columns.
-- IF NOT EXISTS prevents errors on re-runs. Fresh installs use db.create_all().
ALTER TABLE alerts ADD COLUMN IF NOT EXISTS notes TEXT;
ALTER TABLE alerts ADD COLUMN IF NOT EXISTS notes_updated_at TIMESTAMP;
