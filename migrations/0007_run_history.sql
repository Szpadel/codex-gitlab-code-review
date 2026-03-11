CREATE TABLE IF NOT EXISTS run_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    kind TEXT NOT NULL,
    repo TEXT NOT NULL,
    iid INTEGER NOT NULL,
    head_sha TEXT NOT NULL,
    status TEXT NOT NULL,
    result TEXT,
    started_at INTEGER NOT NULL,
    finished_at INTEGER,
    updated_at INTEGER NOT NULL,
    thread_id TEXT,
    turn_id TEXT,
    review_thread_id TEXT,
    preview TEXT,
    summary TEXT,
    error TEXT,
    auth_account_name TEXT,
    discussion_id TEXT,
    trigger_note_id INTEGER,
    trigger_note_author_name TEXT,
    trigger_note_body TEXT,
    command_repo TEXT,
    commit_sha TEXT
);

CREATE INDEX IF NOT EXISTS idx_run_history_repo_iid_started_at
    ON run_history (repo, iid, started_at DESC, id DESC);

CREATE INDEX IF NOT EXISTS idx_run_history_started_at
    ON run_history (started_at DESC, id DESC);
