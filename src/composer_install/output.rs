use super::auth::{collect_string_leaves, composer_auth_notice};
use super::command::composer_skip_line;
use super::{COMPOSER_SKIP_EXIT_CODE, ComposerInstallMode, ComposerInstallResult};
use serde_json::Value;

const COMPOSER_DEBUG_PREAMBLE_MAX_CHARS: usize = 1_200;

#[must_use]
pub fn composer_install_result_from_exec_output(
    input: ComposerInstallExecOutput<'_>,
) -> ComposerInstallResult {
    let auth_source_for_excerpt = input.auth_source.clone();
    let redacted_stdout =
        redact_composer_related_output(input.stdout, input.gitlab_token, input.composer_auth);
    let redacted_stderr =
        redact_composer_related_output(input.stderr, input.gitlab_token, input.composer_auth);
    let redacted_debug_lines = input
        .debug_lines
        .iter()
        .map(|line| redact_composer_related_output(line, input.gitlab_token, input.composer_auth))
        .collect::<Vec<_>>();
    if input.exit_code == COMPOSER_SKIP_EXIT_CODE && is_preflight_skip_output(&redacted_stdout) {
        return ComposerInstallResult::skipped(input.mode, input.auth_source);
    }
    if input.exit_code == 0 {
        return ComposerInstallResult::succeeded(
            input.mode,
            input.auth_source.clone(),
            composer_success_log_excerpt(
                auth_source_for_excerpt.as_deref(),
                &redacted_debug_lines,
                &redacted_stdout,
                &redacted_stderr,
            ),
        );
    }
    ComposerInstallResult::failed(
        input.mode,
        input.auth_source,
        composer_failure_log_excerpt(
            auth_source_for_excerpt.as_deref(),
            &redacted_debug_lines,
            &redacted_stdout,
            &redacted_stderr,
        ),
    )
}

pub struct ComposerInstallExecOutput<'a> {
    pub mode: ComposerInstallMode,
    pub auth_source: Option<String>,
    pub exit_code: i64,
    pub stdout: &'a str,
    pub stderr: &'a str,
    pub gitlab_token: Option<&'a str>,
    pub composer_auth: Option<&'a str>,
    pub debug_lines: &'a [String],
}

fn is_preflight_skip_output(stdout: &str) -> bool {
    let skip_line = composer_skip_line();
    stdout.lines().any(|line| line.trim() == skip_line)
}

#[must_use]
pub fn redact_composer_related_output(
    input: &str,
    gitlab_token: Option<&str>,
    composer_auth: Option<&str>,
) -> String {
    let mut redacted = input.to_string();
    if let Some(token) = gitlab_token
        && !token.is_empty()
    {
        redacted = redacted.replace(token, "[REDACTED_GITLAB_TOKEN]");
    }

    for secret in composer_secret_strings(composer_auth) {
        if secret.is_empty() {
            continue;
        }
        redacted = redacted.replace(&secret, "[REDACTED_COMPOSER_SECRET]");
    }

    redact_oauth2_credentials(&redacted)
}

fn composer_secret_strings(composer_auth: Option<&str>) -> Vec<String> {
    let Some(composer_auth) = composer_auth else {
        return Vec::new();
    };
    let mut secrets = vec![composer_auth.to_string()];
    let Ok(parsed) = serde_json::from_str::<Value>(composer_auth) else {
        return secrets;
    };
    collect_string_leaves(&parsed, &mut secrets);
    secrets.sort_by(|left, right| right.len().cmp(&left.len()).then_with(|| left.cmp(right)));
    secrets.dedup();
    secrets
}

fn redact_oauth2_credentials(input: &str) -> String {
    let mut remainder = input;
    let mut sanitized = String::with_capacity(input.len());
    while let Some(index) = remainder.find("oauth2:") {
        sanitized.push_str(&remainder[..index]);
        let suffix = &remainder[index + "oauth2:".len()..];
        if let Some(at_index) = suffix.find('@') {
            sanitized.push_str("oauth2:[REDACTED]@");
            remainder = &suffix[at_index + 1..];
        } else {
            sanitized.push_str(&remainder[index..]);
            remainder = "";
            break;
        }
    }
    sanitized.push_str(remainder);
    sanitized
}

fn composer_failure_log_excerpt(
    auth_source: Option<&str>,
    debug_lines: &[String],
    stdout: &str,
    stderr: &str,
) -> String {
    let mut sections = Vec::new();
    if !stdout.trim().is_empty() {
        sections.push(stdout.trim());
    }
    if !stderr.trim().is_empty() {
        sections.push(stderr.trim());
    }
    let combined = if sections.is_empty() {
        "composer install failed".to_string()
    } else {
        sections.join("\n")
    };
    let excerpt = compose_excerpt_with_debug_notice(auth_source, debug_lines, Some(combined))
        .expect("failure excerpts always include fallback output");
    truncate_excerpt(&excerpt, 8_000)
}

fn composer_success_log_excerpt(
    auth_source: Option<&str>,
    debug_lines: &[String],
    stdout: &str,
    stderr: &str,
) -> Option<String> {
    let mut sections = Vec::new();
    if !stdout.trim().is_empty() {
        sections.push(stdout.trim());
    }
    if !stderr.trim().is_empty() {
        sections.push(stderr.trim());
    }
    compose_excerpt_with_debug_notice(
        auth_source,
        debug_lines,
        (!sections.is_empty()).then(|| sections.join("\n")),
    )
    .map(|excerpt| truncate_excerpt(&excerpt, 8_000))
}

fn compose_excerpt_with_debug_notice(
    auth_source: Option<&str>,
    debug_lines: &[String],
    body: Option<String>,
) -> Option<String> {
    let mut notices = debug_lines.to_vec();
    if let Some(notice) = composer_auth_notice(auth_source)
        && !notices.iter().any(|line| line == &notice)
    {
        notices.push(notice);
    }
    let notices = (!notices.is_empty())
        .then(|| truncate_excerpt(&notices.join("\n"), COMPOSER_DEBUG_PREAMBLE_MAX_CHARS));
    match (notices, body) {
        (Some(notice), Some(body)) => Some(format!("{notice}\n{body}")),
        (Some(notice), None) => Some(notice),
        (None, Some(body)) => Some(body),
        (None, None) => None,
    }
}

fn truncate_excerpt(input: &str, max_chars: usize) -> String {
    if input.chars().count() <= max_chars {
        return input.to_string();
    }
    let truncated = input.chars().take(max_chars).collect::<String>();
    format!("{truncated}\n[truncated]")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::composer_install::ComposerInstallResult;

    #[test]
    fn redact_composer_related_output_scrubs_gitlab_token_and_auth_leaves() {
        let output = redact_composer_related_output(
            "token abc\nhttps://oauth2:token@example.com/repo.git\npassword s3cr3t",
            Some("token"),
            Some(r#"{"http-basic":{"example.com":{"username":"bot","password":"s3cr3t"}}}"#),
        );

        assert!(!output.contains("s3cr3t"));
        assert!(!output.contains("token@example.com"));
        assert!(output.contains("[REDACTED_COMPOSER_SECRET]"));
        assert!(output.contains("oauth2:[REDACTED]@example.com/repo.git"));
    }

    #[test]
    fn redact_composer_related_output_handles_multiple_oauth2_urls() {
        let output = redact_composer_related_output(
            "first https://oauth2:token1@example.com/a.git second https://oauth2:token2@example.com/b.git",
            None,
            None,
        );

        assert!(output.contains("https://oauth2:[REDACTED]@example.com/a.git"));
        assert!(output.contains("https://oauth2:[REDACTED]@example.com/b.git"));
    }

    #[test]
    fn redact_composer_related_output_redacts_longer_overlapping_secrets_first() {
        let output =
            redact_composer_related_output("abc123", None, Some(r#"{"one":"abc","two":"abc123"}"#));

        assert_eq!(output, "[REDACTED_COMPOSER_SECRET]");
    }

    #[test]
    fn composer_install_result_marks_missing_composer_json_as_skipped() {
        let result = composer_install_result_from_exec_output(ComposerInstallExecOutput {
            mode: ComposerInstallMode::Full,
            auth_source: None,
            exit_code: 86,
            stdout: "CODEX_COMPOSER_SKIP:missing-composer-json\n",
            stderr: "",
            gitlab_token: None,
            composer_auth: None,
            debug_lines: &[],
        });

        assert_eq!(
            result,
            ComposerInstallResult::skipped(ComposerInstallMode::Full, None)
        );
    }

    #[test]
    fn composer_install_result_does_not_treat_success_log_as_skip_marker() {
        let result = composer_install_result_from_exec_output(ComposerInstallExecOutput {
            mode: ComposerInstallMode::Full,
            auth_source: None,
            exit_code: 0,
            stdout: "Installing\nCODEX_COMPOSER_SKIP not actually a preflight skip\nDone",
            stderr: "",
            gitlab_token: None,
            composer_auth: None,
            debug_lines: &[],
        });

        assert!(result.attempted);
        assert!(result.success);
    }

    #[test]
    fn composer_install_result_does_not_treat_success_exit_with_marker_line_as_skipped() {
        let result = composer_install_result_from_exec_output(ComposerInstallExecOutput {
            mode: ComposerInstallMode::Full,
            auth_source: None,
            exit_code: 0,
            stdout: "CODEX_COMPOSER_SKIP:missing-composer-json",
            stderr: "",
            gitlab_token: None,
            composer_auth: None,
            debug_lines: &[],
        });

        assert!(result.attempted);
        assert!(result.success);
    }

    #[test]
    fn composer_install_result_treats_skip_marker_line_with_noise_as_skipped() {
        let result = composer_install_result_from_exec_output(ComposerInstallExecOutput {
            mode: ComposerInstallMode::Full,
            auth_source: None,
            exit_code: 86,
            stdout: "wrapper noise\nCODEX_COMPOSER_SKIP:missing-composer-json\nmore wrapper noise",
            stderr: "",
            gitlab_token: None,
            composer_auth: None,
            debug_lines: &[],
        });

        assert_eq!(
            result,
            ComposerInstallResult::skipped(ComposerInstallMode::Full, None)
        );
    }

    #[test]
    fn composer_install_result_redacts_failure_excerpt() {
        let result = composer_install_result_from_exec_output(ComposerInstallExecOutput {
            mode: ComposerInstallMode::Safe,
            auth_source: Some("group:team/platform".to_string()),
            exit_code: 1,
            stdout: "install failed for s3cr3t",
            stderr: "https://oauth2:token@example.com/repo.git",
            gitlab_token: Some("token"),
            composer_auth: Some(r#"{"http-basic":{"example.com":{"password":"s3cr3t"}}}"#),
            debug_lines: &[
                "checked group:team/platform -> found".to_string(),
                "derived Composer repository hosts: example.com".to_string(),
            ],
        });

        assert!(result.attempted);
        assert!(!result.success);
        let excerpt = result.log_excerpt.expect("failure excerpt");
        assert!(excerpt.contains("checked group:team/platform -> found"));
        assert!(excerpt.contains("COMPOSER_AUTH detected from group team/platform"));
        assert!(excerpt.contains("derived Composer repository hosts: example.com"));
        assert!(!excerpt.contains("s3cr3t"));
        assert!(!excerpt.contains("token@example.com"));
    }

    #[test]
    fn composer_install_result_redacts_debug_lines_before_logging() {
        let result = composer_install_result_from_exec_output(ComposerInstallExecOutput {
            mode: ComposerInstallMode::Safe,
            auth_source: Some("group:team/platform".to_string()),
            exit_code: 1,
            stdout: "install failed",
            stderr: "",
            gitlab_token: Some("token"),
            composer_auth: Some(r#"{"http-basic":{"example.com":{"password":"s3cr3t"}}}"#),
            debug_lines: &[
                "ignored COMPOSER_AUTH repository entries: 1".to_string(),
                "derived Composer repository hosts: example.com".to_string(),
            ],
        });

        let excerpt = result.log_excerpt.expect("failure excerpt");
        assert!(excerpt.contains("ignored COMPOSER_AUTH repository entries: 1"));
    }

    #[test]
    fn composer_install_result_keeps_redacted_success_excerpt() {
        let result = composer_install_result_from_exec_output(ComposerInstallExecOutput {
            mode: ComposerInstallMode::Full,
            auth_source: Some("project:group/repo".to_string()),
            exit_code: 0,
            stdout: "Installing package with s3cr3t",
            stderr: "https://oauth2:token@example.com/repo.git",
            gitlab_token: Some("token"),
            composer_auth: Some(r#"{"http-basic":{"example.com":{"password":"s3cr3t"}}}"#),
            debug_lines: &[
                "checked project:group/repo -> found".to_string(),
                "temporary COMPOSER_HOME config: written".to_string(),
            ],
        });

        assert!(result.attempted);
        assert!(result.success);
        let excerpt = result.log_excerpt.expect("success excerpt");
        assert!(excerpt.contains("checked project:group/repo -> found"));
        assert!(excerpt.contains("COMPOSER_AUTH detected from repository group/repo"));
        assert!(excerpt.contains("temporary COMPOSER_HOME config: written"));
        assert!(!excerpt.contains("s3cr3t"));
        assert!(!excerpt.contains("token@example.com"));
    }

    #[test]
    fn composer_install_result_without_auth_source_keeps_debug_preamble() {
        let result = composer_install_result_from_exec_output(ComposerInstallExecOutput {
            mode: ComposerInstallMode::Full,
            auth_source: None,
            exit_code: 0,
            stdout: "Installing dependencies from lock file",
            stderr: "",
            gitlab_token: None,
            composer_auth: None,
            debug_lines: &[
                "checked project:group/repo -> not found".to_string(),
                "COMPOSER_AUTH detected: none".to_string(),
                "COMPOSER_AUTH exported to composer: no".to_string(),
            ],
        });

        assert!(result.attempted);
        assert!(result.success);
        let excerpt = result.log_excerpt.expect("success excerpt");
        assert!(excerpt.contains("checked project:group/repo -> not found"));
        assert!(excerpt.contains("COMPOSER_AUTH detected: none"));
        assert!(excerpt.contains("COMPOSER_AUTH exported to composer: no"));
        assert!(excerpt.contains("Installing dependencies from lock file"));
    }

    #[test]
    fn composer_install_result_truncates_notice_and_output_together() {
        let long_output = "x".repeat(8_100);
        let result = composer_install_result_from_exec_output(ComposerInstallExecOutput {
            mode: ComposerInstallMode::Full,
            auth_source: Some("group:team/platform".to_string()),
            exit_code: 0,
            stdout: &long_output,
            stderr: "",
            gitlab_token: None,
            composer_auth: None,
            debug_lines: &["checked group:team/platform -> found".to_string()],
        });

        let excerpt = result.log_excerpt.expect("truncated excerpt");
        assert!(excerpt.starts_with("checked group:team/platform -> found\n"));
        assert!(excerpt.contains(&"x".repeat(128)));
        assert!(excerpt.ends_with("[truncated]"));
    }
}
