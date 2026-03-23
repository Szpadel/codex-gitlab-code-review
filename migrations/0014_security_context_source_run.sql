ALTER TABLE security_review_context_cache
    ADD COLUMN source_run_history_id INTEGER;

UPDATE security_review_context_cache
SET source_run_history_id = 0
WHERE source_run_history_id IS NULL;

ALTER TABLE run_history
    ADD COLUMN security_context_source_run_id INTEGER;
