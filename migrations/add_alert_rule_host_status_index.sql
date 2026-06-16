CREATE INDEX IF NOT EXISTS ix_alert_rule_host_status ON alerts (rule_id, host, status);
