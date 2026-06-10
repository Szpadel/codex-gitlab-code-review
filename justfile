dev-mode:
    cargo run -- --dev-mode

sync-prompts ref:
    @if [ '{{ref}}' = '--help' ]; then python3 scripts/sync_codex_review_prompts.py --help; else python3 scripts/sync_codex_review_prompts.py --ref '{{ref}}' && echo "Commit src/generated_review_prompt_templates.rs with the Codex image/version bump."; fi
