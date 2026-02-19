CREATE TABLE IF NOT EXISTS mention_command_state (
    repo TEXT NOT NULL,
    iid INTEGER NOT NULL,
    discussion_id TEXT NOT NULL,
    trigger_note_id INTEGER NOT NULL,
    head_sha TEXT NOT NULL,
    status TEXT NOT NULL,
    started_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    result TEXT,
    PRIMARY KEY (repo, iid, discussion_id, trigger_note_id)
);
