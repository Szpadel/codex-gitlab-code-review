ALTER TABLE run_history
    ADD COLUMN events_persisted_cleanly INTEGER NOT NULL DEFAULT 1;
