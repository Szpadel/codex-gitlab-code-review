CREATE TABLE IF NOT EXISTS run_history_token_usage (
    run_history_id INTEGER NOT NULL,
    response_id TEXT NOT NULL,
    thread_id TEXT NOT NULL,
    turn_id TEXT NOT NULL,
    input_tokens INTEGER NOT NULL CHECK (input_tokens >= 0),
    cached_input_tokens INTEGER NOT NULL CHECK (cached_input_tokens >= 0),
    cache_write_input_tokens INTEGER NOT NULL DEFAULT 0 CHECK (cache_write_input_tokens >= 0),
    output_tokens INTEGER NOT NULL CHECK (output_tokens >= 0),
    reasoning_output_tokens INTEGER NOT NULL CHECK (reasoning_output_tokens >= 0),
    total_tokens INTEGER NOT NULL CHECK (total_tokens >= 0),
    created_at INTEGER NOT NULL,
    PRIMARY KEY (run_history_id, response_id),
    FOREIGN KEY(run_history_id) REFERENCES run_history(id) ON DELETE CASCADE
);
