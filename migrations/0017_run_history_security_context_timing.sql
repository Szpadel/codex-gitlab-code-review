ALTER TABLE run_history
    ADD COLUMN security_context_generated_at INTEGER;

ALTER TABLE run_history
    ADD COLUMN security_context_expires_at INTEGER;
