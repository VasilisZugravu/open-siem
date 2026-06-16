-- Run once against existing installations to add triage notes columns.
-- Fresh installs pick these up automatically via db.create_all().
ALTER TABLE alerts ADD COLUMN notes TEXT;
ALTER TABLE alerts ADD COLUMN notes_updated_at TIMESTAMP;
