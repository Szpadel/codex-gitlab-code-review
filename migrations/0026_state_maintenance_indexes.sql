CREATE INDEX idx_review_state_stale
    ON review_state (updated_at) WHERE status = 'in_progress';

CREATE INDEX idx_mention_command_state_stale
    ON mention_command_state (updated_at) WHERE status = 'in_progress';

CREATE INDEX idx_security_context_cache_expiry
    ON security_review_context_cache (expires_at);

CREATE INDEX idx_run_history_inline_completion
    ON run_history (kind, review_lane, repo, iid, head_sha)
    WHERE status = 'done' AND result = 'comment';
