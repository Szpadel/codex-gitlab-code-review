CREATE TABLE IF NOT EXISTS review_state (
    repo TEXT NOT NULL,
    iid INTEGER NOT NULL,
    head_sha TEXT NOT NULL,
    status TEXT NOT NULL,
    started_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    result TEXT,
    PRIMARY KEY (repo, iid)
);
