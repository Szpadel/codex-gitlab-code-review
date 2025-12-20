CREATE TABLE IF NOT EXISTS project_catalog (
    cache_key TEXT NOT NULL PRIMARY KEY,
    fetched_at INTEGER NOT NULL,
    projects TEXT NOT NULL
);
