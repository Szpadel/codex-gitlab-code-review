CREATE TABLE IF NOT EXISTS security_review_debounce_state (
    repo TEXT NOT NULL,
    iid INTEGER NOT NULL,
    last_started_at INTEGER NOT NULL,
    next_eligible_at INTEGER NOT NULL,
    PRIMARY KEY (repo, iid)
);

CREATE INDEX IF NOT EXISTS idx_security_review_debounce_repo_due
    ON security_review_debounce_state (repo, next_eligible_at);
