-- One row per run replaces response-level aggregation on History requests.
CREATE TABLE run_history_token_usage_rollup (
    run_history_id INTEGER PRIMARY KEY REFERENCES run_history(id) ON DELETE CASCADE,
    response_count INTEGER NOT NULL,
    input_tokens INTEGER NOT NULL,
    cached_input_tokens INTEGER NOT NULL,
    cache_write_input_tokens INTEGER NOT NULL,
    output_tokens INTEGER NOT NULL,
    reasoning_output_tokens INTEGER NOT NULL,
    total_tokens INTEGER NOT NULL
);

INSERT INTO run_history_token_usage_rollup
SELECT run_history_id, COUNT(*),
       SUM(input_tokens), SUM(cached_input_tokens), SUM(cache_write_input_tokens),
       SUM(output_tokens), SUM(reasoning_output_tokens), SUM(total_tokens)
FROM run_history_token_usage
GROUP BY run_history_id;

-- Triggers also cover transcript recovery and writes from older application versions.
CREATE TRIGGER run_history_token_usage_insert_rollup
AFTER INSERT ON run_history_token_usage
BEGIN
    INSERT INTO run_history_token_usage_rollup (
        run_history_id, response_count, input_tokens, cached_input_tokens,
        cache_write_input_tokens, output_tokens, reasoning_output_tokens, total_tokens
    ) VALUES (
        NEW.run_history_id, 1, NEW.input_tokens, NEW.cached_input_tokens,
        NEW.cache_write_input_tokens, NEW.output_tokens,
        NEW.reasoning_output_tokens, NEW.total_tokens
    )
    ON CONFLICT(run_history_id) DO UPDATE SET
        response_count = response_count + 1,
        input_tokens = input_tokens + excluded.input_tokens,
        cached_input_tokens = cached_input_tokens + excluded.cached_input_tokens,
        cache_write_input_tokens = cache_write_input_tokens + excluded.cache_write_input_tokens,
        output_tokens = output_tokens + excluded.output_tokens,
        reasoning_output_tokens = reasoning_output_tokens + excluded.reasoning_output_tokens,
        total_tokens = total_tokens + excluded.total_tokens;
END;

CREATE TRIGGER run_history_token_usage_update_rollup
AFTER UPDATE ON run_history_token_usage
BEGIN
    UPDATE run_history_token_usage_rollup SET
        response_count = response_count - 1,
        input_tokens = input_tokens - OLD.input_tokens,
        cached_input_tokens = cached_input_tokens - OLD.cached_input_tokens,
        cache_write_input_tokens = cache_write_input_tokens - OLD.cache_write_input_tokens,
        output_tokens = output_tokens - OLD.output_tokens,
        reasoning_output_tokens = reasoning_output_tokens - OLD.reasoning_output_tokens,
        total_tokens = total_tokens - OLD.total_tokens
    WHERE run_history_id = OLD.run_history_id;
    INSERT INTO run_history_token_usage_rollup (
        run_history_id, response_count, input_tokens, cached_input_tokens,
        cache_write_input_tokens, output_tokens, reasoning_output_tokens, total_tokens
    ) VALUES (
        NEW.run_history_id, 1, NEW.input_tokens, NEW.cached_input_tokens,
        NEW.cache_write_input_tokens, NEW.output_tokens,
        NEW.reasoning_output_tokens, NEW.total_tokens
    )
    ON CONFLICT(run_history_id) DO UPDATE SET
        response_count = response_count + 1,
        input_tokens = input_tokens + excluded.input_tokens,
        cached_input_tokens = cached_input_tokens + excluded.cached_input_tokens,
        cache_write_input_tokens = cache_write_input_tokens + excluded.cache_write_input_tokens,
        output_tokens = output_tokens + excluded.output_tokens,
        reasoning_output_tokens = reasoning_output_tokens + excluded.reasoning_output_tokens,
        total_tokens = total_tokens + excluded.total_tokens;
    DELETE FROM run_history_token_usage_rollup
    WHERE run_history_id = OLD.run_history_id AND response_count = 0;
END;

CREATE TRIGGER run_history_token_usage_delete_rollup
AFTER DELETE ON run_history_token_usage
BEGIN
    UPDATE run_history_token_usage_rollup SET
        response_count = response_count - 1,
        input_tokens = input_tokens - OLD.input_tokens,
        cached_input_tokens = cached_input_tokens - OLD.cached_input_tokens,
        cache_write_input_tokens = cache_write_input_tokens - OLD.cache_write_input_tokens,
        output_tokens = output_tokens - OLD.output_tokens,
        reasoning_output_tokens = reasoning_output_tokens - OLD.reasoning_output_tokens,
        total_tokens = total_tokens - OLD.total_tokens
    WHERE run_history_id = OLD.run_history_id;
    DELETE FROM run_history_token_usage_rollup
    WHERE run_history_id = OLD.run_history_id AND response_count = 0;
END;
