ALTER TABLE run_history
    ADD COLUMN feature_flags_json TEXT NOT NULL DEFAULT '{"gitlab_discovery_mcp":false}';
