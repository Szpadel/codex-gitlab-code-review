CREATE TABLE IF NOT EXISTS runtime_review_rate_limit_rule (
    id TEXT NOT NULL PRIMARY KEY,
    label TEXT NOT NULL,
    scope_repo TEXT NOT NULL,
    scope_subject_iid INTEGER NOT NULL,
    applies_to_review INTEGER NOT NULL,
    applies_to_security INTEGER NOT NULL,
    scope TEXT NOT NULL,
    capacity INTEGER NOT NULL,
    window_seconds INTEGER NOT NULL,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    CHECK (scope IN ('project', 'merge_request')),
    CHECK (applies_to_review IN (0, 1)),
    CHECK (applies_to_security IN (0, 1)),
    CHECK (applies_to_review = 1 OR applies_to_security = 1),
    CHECK (capacity > 0),
    CHECK (window_seconds > 0),
    CHECK (
        (scope = 'project' AND scope_subject_iid = 0)
        OR (scope = 'merge_request' AND scope_subject_iid > 0)
    )
);

CREATE INDEX IF NOT EXISTS idx_runtime_review_rate_limit_rule_scope
    ON runtime_review_rate_limit_rule (scope, scope_repo, scope_subject_iid, applies_to_review, applies_to_security);

CREATE TABLE IF NOT EXISTS runtime_review_rate_limit_bucket (
    rule_id TEXT NOT NULL PRIMARY KEY,
    available_slots REAL NOT NULL,
    updated_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS runtime_review_rate_limit_pending (
    lane TEXT NOT NULL,
    repo TEXT NOT NULL,
    iid INTEGER NOT NULL,
    first_blocked_at INTEGER NOT NULL,
    last_blocked_at INTEGER NOT NULL,
    last_seen_head_sha TEXT NOT NULL,
    next_retry_at INTEGER NOT NULL,
    PRIMARY KEY (lane, repo, iid),
    CHECK (lane IN ('general', 'security'))
);

CREATE INDEX IF NOT EXISTS idx_runtime_review_rate_limit_pending_retry
    ON runtime_review_rate_limit_pending (next_retry_at, first_blocked_at, lane, repo, iid);
