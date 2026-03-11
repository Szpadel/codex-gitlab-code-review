CREATE TABLE IF NOT EXISTS run_history_event (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_history_id INTEGER NOT NULL,
    sequence INTEGER NOT NULL,
    turn_id TEXT,
    event_type TEXT NOT NULL,
    payload_json TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    FOREIGN KEY(run_history_id) REFERENCES run_history(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_run_history_event_run_sequence
    ON run_history_event (run_history_id, sequence, id);
