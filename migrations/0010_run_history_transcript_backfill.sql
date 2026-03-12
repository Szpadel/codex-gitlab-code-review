ALTER TABLE run_history
    ADD COLUMN transcript_backfill_state TEXT NOT NULL DEFAULT 'not_requested';

ALTER TABLE run_history
    ADD COLUMN transcript_backfill_error TEXT;
