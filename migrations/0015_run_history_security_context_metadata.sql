ALTER TABLE run_history
    ADD COLUMN security_context_base_branch TEXT;

ALTER TABLE run_history
    ADD COLUMN security_context_base_head_sha TEXT;

ALTER TABLE run_history
    ADD COLUMN security_context_prompt_version TEXT;
