ALTER TABLE run_history
    ADD COLUMN review_lane TEXT;

UPDATE run_history
SET review_lane = 'general'
WHERE kind = 'review' AND review_lane IS NULL;

CREATE TABLE IF NOT EXISTS review_state_v2 (
    repo TEXT NOT NULL,
    iid INTEGER NOT NULL,
    lane TEXT NOT NULL DEFAULT 'general',
    head_sha TEXT NOT NULL,
    status TEXT NOT NULL,
    started_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    result TEXT,
    PRIMARY KEY (repo, iid, lane)
);

INSERT INTO review_state_v2 (repo, iid, lane, head_sha, status, started_at, updated_at, result)
SELECT repo, iid, 'general', head_sha, status, started_at, updated_at, result
FROM review_state;

DROP TABLE review_state;

ALTER TABLE review_state_v2 RENAME TO review_state;

CREATE TABLE IF NOT EXISTS security_review_context_cache (
    repo TEXT NOT NULL,
    base_branch TEXT NOT NULL,
    base_head_sha TEXT NOT NULL,
    prompt_version TEXT NOT NULL,
    payload_json TEXT NOT NULL,
    generated_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    PRIMARY KEY (repo, base_branch, base_head_sha, prompt_version)
);
