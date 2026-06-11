CREATE TABLE IF NOT EXISTS runtime_mention_quota_pending (
    repo TEXT NOT NULL,
    iid INTEGER NOT NULL,
    discussion_id TEXT NOT NULL,
    trigger_note_id INTEGER NOT NULL,
    first_blocked_at INTEGER NOT NULL,
    last_blocked_at INTEGER NOT NULL,
    last_seen_head_sha TEXT NOT NULL,
    next_retry_at INTEGER NOT NULL,
    PRIMARY KEY (repo, iid, discussion_id, trigger_note_id)
);

CREATE INDEX IF NOT EXISTS idx_runtime_mention_quota_pending_retry
    ON runtime_mention_quota_pending (next_retry_at, repo, iid);
