ALTER TABLE runtime_review_rate_limit_rule
    ADD COLUMN bucket_mode TEXT NOT NULL DEFAULT 'shared';

CREATE TABLE IF NOT EXISTS runtime_review_rate_limit_rule_target (
    rule_id TEXT NOT NULL,
    sort_order INTEGER NOT NULL,
    target_kind TEXT NOT NULL,
    target_path TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    PRIMARY KEY (rule_id, target_kind, target_path),
    CHECK (target_kind IN ('repo', 'group'))
);

INSERT OR IGNORE INTO runtime_review_rate_limit_rule_target (
    rule_id,
    sort_order,
    target_kind,
    target_path,
    created_at
)
SELECT id, 0, 'repo', scope_repo, created_at
FROM runtime_review_rate_limit_rule;

ALTER TABLE runtime_review_rate_limit_bucket
    RENAME TO runtime_review_rate_limit_bucket_legacy;

CREATE TABLE runtime_review_rate_limit_bucket (
    bucket_id TEXT NOT NULL PRIMARY KEY,
    rule_id TEXT NOT NULL,
    target_kind TEXT NOT NULL,
    target_path TEXT NOT NULL,
    available_slots REAL NOT NULL,
    updated_at INTEGER NOT NULL,
    CHECK (target_kind IN ('repo', 'group'))
);

INSERT INTO runtime_review_rate_limit_bucket (
    bucket_id,
    rule_id,
    target_kind,
    target_path,
    available_slots,
    updated_at
)
SELECT legacy.rule_id, legacy.rule_id, 'repo', rule.scope_repo, legacy.available_slots, legacy.updated_at
FROM runtime_review_rate_limit_bucket_legacy legacy
JOIN runtime_review_rate_limit_rule rule ON rule.id = legacy.rule_id;

DROP TABLE runtime_review_rate_limit_bucket_legacy;

CREATE INDEX IF NOT EXISTS idx_runtime_review_rate_limit_rule_target_rule
    ON runtime_review_rate_limit_rule_target (rule_id, target_kind, target_path);

CREATE INDEX IF NOT EXISTS idx_runtime_review_rate_limit_bucket_rule
    ON runtime_review_rate_limit_bucket (rule_id, target_kind, target_path);

ALTER TABLE runtime_review_rate_limit_bucket
    ADD COLUMN scope_repo TEXT NOT NULL DEFAULT '';

ALTER TABLE runtime_review_rate_limit_bucket
    ADD COLUMN scope_subject_iid INTEGER NOT NULL DEFAULT 0;

UPDATE runtime_review_rate_limit_bucket
SET scope_repo = target_path,
    scope_subject_iid = 0
WHERE scope_repo = '';

CREATE INDEX IF NOT EXISTS idx_runtime_review_rate_limit_bucket_scope
    ON runtime_review_rate_limit_bucket (rule_id, scope_repo, scope_subject_iid);

ALTER TABLE runtime_review_rate_limit_rule
    RENAME TO runtime_review_rate_limit_rule_legacy;

CREATE TABLE runtime_review_rate_limit_rule (
    id TEXT NOT NULL PRIMARY KEY,
    label TEXT NOT NULL,
    scope_repo TEXT NOT NULL,
    scope_subject_iid INTEGER NOT NULL,
    applies_to_review INTEGER NOT NULL,
    applies_to_security INTEGER NOT NULL,
    scope TEXT NOT NULL,
    capacity INTEGER NOT NULL,
    window_seconds INTEGER NOT NULL,
    bucket_mode TEXT NOT NULL DEFAULT 'shared',
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    CHECK (scope IN ('project', 'merge_request')),
    CHECK (bucket_mode IN ('shared', 'independent')),
    CHECK (applies_to_review IN (0, 1)),
    CHECK (applies_to_security IN (0, 1)),
    CHECK (applies_to_review = 1 OR applies_to_security = 1),
    CHECK (capacity > 0),
    CHECK (window_seconds > 0),
    CHECK (
        (scope = 'project' AND scope_subject_iid = 0)
        OR (scope = 'merge_request' AND scope_subject_iid >= 0)
    )
);

INSERT INTO runtime_review_rate_limit_rule (
    id,
    label,
    scope_repo,
    scope_subject_iid,
    applies_to_review,
    applies_to_security,
    scope,
    capacity,
    window_seconds,
    bucket_mode,
    created_at,
    updated_at
)
SELECT
    id,
    label,
    scope_repo,
    CASE
        WHEN scope = 'merge_request' THEN 0
        ELSE scope_subject_iid
    END,
    applies_to_review,
    applies_to_security,
    scope,
    capacity,
    window_seconds,
    bucket_mode,
    created_at,
    updated_at
FROM runtime_review_rate_limit_rule_legacy;

DELETE FROM runtime_review_rate_limit_bucket
WHERE rule_id IN (
    SELECT id
    FROM runtime_review_rate_limit_rule
    WHERE scope = 'merge_request'
);

DROP TABLE runtime_review_rate_limit_rule_legacy;

CREATE INDEX IF NOT EXISTS idx_runtime_review_rate_limit_rule_scope
    ON runtime_review_rate_limit_rule (scope, scope_repo, scope_subject_iid, applies_to_review, applies_to_security);
