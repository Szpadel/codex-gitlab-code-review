CREATE TABLE IF NOT EXISTS project_state (
    repo TEXT NOT NULL PRIMARY KEY,
    last_activity_at TEXT NOT NULL
);
