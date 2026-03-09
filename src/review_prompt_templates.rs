use crate::generated_review_prompt_templates::{
    BASE_BRANCH_PROMPT, COMMIT_PROMPT, COMMIT_PROMPT_WITH_TITLE, SOURCE_COMMIT, SOURCE_PATH,
};

const LOCAL_BASE_BRANCH_PROMPT_BACKUP: &str = "Review the code changes against the base branch '{branch}'. Start by finding the merge diff between the current branch and {branch} e.g. (`git merge-base HEAD \"{branch}\"`), then run `git diff` against that SHA to see what changes we would merge into the {branch} branch. Provide prioritized, actionable findings.";

// Drift note:
// This module mirrors only Codex upstream review target prompt construction from
// `codex-rs/core/src/review_prompts.rs`. The synced string templates live in the
// generated module and should be refreshed with `scripts/sync_codex_review_prompts.py`.
//
// We intentionally do not copy Codex's baked review rubric from
// `codex-rs/core/src/tasks/review.rs`; review mode should keep using the runtime
// Codex image's own rubric.
//
// Local alterations:
// - append `Additional review instructions` when this service is configured to
//   do so
// - use a local-branch merge-base backup prompt because this service creates a
//   plain branch ref in `build_command_script` instead of configuring
//   `<branch>@{upstream}` tracking
pub fn build_base_branch_review_prompt(branch: &str, merge_base_sha: Option<&str>) -> String {
    let branch = branch.trim();
    if let Some(merge_base_sha) = merge_base_sha
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        BASE_BRANCH_PROMPT
            .replace("{baseBranch}", branch)
            .replace("{mergeBaseSha}", merge_base_sha)
    } else {
        LOCAL_BASE_BRANCH_PROMPT_BACKUP.replace("{branch}", branch)
    }
}

pub fn build_commit_review_prompt(sha: &str, title: Option<&str>) -> String {
    let sha = sha.trim();
    if let Some(title) = title.map(str::trim).filter(|value| !value.is_empty()) {
        COMMIT_PROMPT_WITH_TITLE
            .replace("{sha}", sha)
            .replace("{title}", title)
    } else {
        COMMIT_PROMPT.replace("{sha}", sha)
    }
}

pub fn append_additional_review_instructions(
    prompt: &str,
    additional_instructions: &str,
) -> String {
    format!(
        "{prompt}\n\nAdditional review instructions:\n{}",
        additional_instructions.trim()
    )
}

pub fn upstream_review_prompt_source_path() -> &'static str {
    SOURCE_PATH
}

pub fn upstream_review_prompt_source_commit() -> &'static str {
    SOURCE_COMMIT
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_base_branch_prompt_with_merge_base() {
        let prompt = build_base_branch_review_prompt("main", Some("abc123"));
        assert_eq!(
            prompt,
            "Review the code changes against the base branch 'main'. The merge base commit for this comparison is abc123. Run `git diff abc123` to inspect the changes relative to main. Provide prioritized, actionable findings."
        );
    }

    #[test]
    fn builds_base_branch_prompt_without_merge_base() {
        let prompt = build_base_branch_review_prompt("main", None);
        assert_eq!(
            prompt,
            "Review the code changes against the base branch 'main'. Start by finding the merge diff between the current branch and main e.g. (`git merge-base HEAD \"main\"`), then run `git diff` against that SHA to see what changes we would merge into the main branch. Provide prioritized, actionable findings."
        );
    }

    #[test]
    fn builds_commit_prompt_with_title() {
        let prompt = build_commit_review_prompt("abc123", Some("Polish tui colors"));
        assert_eq!(
            prompt,
            "Review the code changes introduced by commit abc123 (\"Polish tui colors\"). Provide prioritized, actionable findings."
        );
    }

    #[test]
    fn appends_additional_review_instructions() {
        let prompt = append_additional_review_instructions(
            "Review the changes.",
            "  Check browser regressions.  ",
        );
        assert_eq!(
            prompt,
            "Review the changes.\n\nAdditional review instructions:\nCheck browser regressions."
        );
    }
}
