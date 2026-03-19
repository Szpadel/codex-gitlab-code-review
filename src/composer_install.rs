use crate::feature_flags::FeatureFlagSnapshot;
use crate::gitlab::{GitLabApi, GitLabCiVariable};
use rmcp::schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::BTreeSet;
use std::time::Duration;
use url::{Host, Url};

pub const COMPOSER_AUTH_VARIABLE_KEY: &str = "COMPOSER_AUTH";
pub const COMPOSER_SKIP_MARKER: &str = "CODEX_COMPOSER_SKIP";
pub const COMPOSER_INSTALL_TURN_ID: &str = "composer-install";
pub const DEFAULT_COMPOSER_INSTALL_TIMEOUT_SECONDS: u64 = 300;
const COMPOSER_SKIP_EXIT_CODE: i64 = 86;
const COMPOSER_SKIP_REASON_MISSING_JSON: &str = "missing-composer-json";
const COMPOSER_DEBUG_PREAMBLE_MAX_CHARS: usize = 1_200;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ComposerInstallMode {
    Full,
    Safe,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ComposerInstallResult {
    pub attempted: bool,
    pub success: bool,
    pub mode: ComposerInstallMode,
    #[serde(default)]
    pub auth_source: Option<String>,
    #[serde(default)]
    pub log_excerpt: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ComposerAuthLookup {
    pub value: Option<String>,
    pub source: Option<String>,
    pub attempts: Vec<ComposerAuthLookupAttempt>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ComposerAuthLookupAttempt {
    pub scope: String,
    pub found: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreparedComposerAuth {
    pub env_value: Option<String>,
    pub repository_config_json: Option<String>,
    pub supported_sections: Vec<String>,
    pub repository_urls: Vec<String>,
    pub ignored_repository_entries: Vec<String>,
    pub parse_failed: bool,
}

impl ComposerInstallMode {
    pub fn for_flags(flags: &FeatureFlagSnapshot) -> Option<Self> {
        if !flags.composer_install {
            return None;
        }

        Some(if flags.composer_safe_install {
            Self::Safe
        } else {
            Self::Full
        })
    }

    pub fn command_label(self) -> &'static str {
        match self {
            Self::Full => "composer install --no-interaction --no-progress --ignore-platform-reqs",
            Self::Safe => {
                "composer install --no-dev --no-scripts --no-plugins --prefer-dist --no-interaction --no-progress --ignore-platform-reqs"
            }
        }
    }
}

impl ComposerInstallResult {
    pub fn skipped(mode: ComposerInstallMode, auth_source: Option<String>) -> Self {
        Self {
            attempted: false,
            success: true,
            mode,
            auth_source,
            log_excerpt: None,
        }
    }

    pub fn succeeded(
        mode: ComposerInstallMode,
        auth_source: Option<String>,
        log_excerpt: Option<String>,
    ) -> Self {
        Self {
            attempted: true,
            success: true,
            mode,
            auth_source,
            log_excerpt,
        }
    }

    pub fn failed(
        mode: ComposerInstallMode,
        auth_source: Option<String>,
        log_excerpt: String,
    ) -> Self {
        Self {
            attempted: true,
            success: false,
            mode,
            auth_source,
            log_excerpt: Some(log_excerpt),
        }
    }
}

pub fn composer_install_exec_command(
    mode: ComposerInstallMode,
    timeout_seconds: u64,
    repository_config_json: Option<&str>,
) -> Vec<String> {
    let composer_command = mode.command_label();
    let skip_line = composer_skip_line();
    let composer_home_setup = repository_config_json
        .map(|config| {
            let config_q = shell_quote(config);
            format!(
                "composer_home=\"$(mktemp -d /tmp/codex-composer-home.XXXXXX)\" || {{\n\
  echo \"failed to create temporary COMPOSER_HOME\" >&2\n\
  exit 1\n\
}}\n\
printf '%s' {config_q} >\"$composer_home/config.json\" || {{\n\
  echo \"failed to write temporary Composer config\" >&2\n\
  exit 1\n\
}}\n\
export COMPOSER_HOME=\"$composer_home\"\n"
            )
        })
        .unwrap_or_default();
    let script = format!(
        r#"set +e
composer_home=""
if [ ! -f composer.json ]; then
  printf '{skip_line}\n'
  exit {skip_exit_code}
fi
if ! command -v composer >/dev/null 2>&1; then
  echo "composer not found in PATH" >&2
  exit 127
fi
log_file="$(mktemp /tmp/codex-composer-install.XXXXXX)"
timeout_marker="$(mktemp /tmp/codex-composer-timeout.XXXXXX)"
cleanup() {{
  rm -f "$log_file"
  rm -f "$timeout_marker"
  if [ -n "$composer_home" ]; then
    rm -rf "$composer_home"
  fi
}}
trap cleanup EXIT
{composer_home_setup}\
COMPOSER_ALLOW_SUPERUSER=1 {composer_command} >"$log_file" 2>&1 &
run_pid="$!"
(
  sleep "{timeout_seconds}"
  if kill -0 "$run_pid" 2>/dev/null; then
    printf 'composer install timed out after {timeout_seconds}s\n' >"$timeout_marker"
    kill "$run_pid" 2>/dev/null || true
    sleep 1
    kill -9 "$run_pid" 2>/dev/null || true
  fi
) &
watchdog_pid="$!"
wait "$run_pid"
status="$?"
kill "$watchdog_pid" 2>/dev/null || true
wait "$watchdog_pid" 2>/dev/null || true
if [ "$status" -eq 0 ]; then
  tail -n 100 "$log_file"
  exit 0
fi
if [ -s "$timeout_marker" ]; then
  cat "$timeout_marker"
  tail -n 100 "$log_file"
  exit 124
fi
tail -n 100 "$log_file"
    exit "$status"
"#,
        skip_line = skip_line,
        skip_exit_code = COMPOSER_SKIP_EXIT_CODE,
        composer_home_setup = composer_home_setup,
        composer_command = composer_command,
        timeout_seconds = timeout_seconds,
    );
    vec!["bash".to_string(), "-lc".to_string(), script]
}

pub fn composer_install_timeout_seconds(remaining: Duration) -> Option<u64> {
    if remaining.is_zero() {
        return None;
    }

    let rounded_up = remaining
        .as_secs()
        .saturating_add(u64::from(remaining.subsec_nanos() > 0));
    Some(rounded_up.min(DEFAULT_COMPOSER_INSTALL_TIMEOUT_SECONDS))
}

pub async fn resolve_composer_auth(gitlab: &dyn GitLabApi, repo_path: &str) -> ComposerAuthLookup {
    if repo_path.trim().is_empty() {
        return ComposerAuthLookup {
            value: None,
            source: None,
            attempts: Vec::new(),
        };
    }

    let mut attempts = Vec::new();
    if let Some(variable) = resolve_project_variable(gitlab, repo_path).await {
        attempts.push(ComposerAuthLookupAttempt {
            scope: format!("project:{repo_path}"),
            found: true,
        });
        return ComposerAuthLookup {
            value: Some(variable.value),
            source: Some(format!("project:{repo_path}")),
            attempts,
        };
    }
    attempts.push(ComposerAuthLookupAttempt {
        scope: format!("project:{repo_path}"),
        found: false,
    });

    for group in repo_parent_groups(repo_path) {
        if let Some(variable) = resolve_group_variable(gitlab, &group).await {
            attempts.push(ComposerAuthLookupAttempt {
                scope: format!("group:{group}"),
                found: true,
            });
            return ComposerAuthLookup {
                value: Some(variable.value),
                source: Some(format!("group:{group}")),
                attempts,
            };
        }
        attempts.push(ComposerAuthLookupAttempt {
            scope: format!("group:{group}"),
            found: false,
        });
    }

    ComposerAuthLookup {
        value: None,
        source: None,
        attempts,
    }
}

pub fn prepare_composer_auth(
    composer_auth: Option<&str>,
    auto_repositories_enabled: bool,
) -> PreparedComposerAuth {
    let env_value = composer_auth.map(ToOwned::to_owned);
    let analysis = analyze_composer_auth(composer_auth);
    let repository_config_json =
        (auto_repositories_enabled && !analysis.repository_urls.is_empty()).then(|| {
            json!({
                "repositories": analysis
                    .repository_urls
                    .iter()
                    .map(|url| json!({
                        "type": "composer",
                        "url": url,
                    }))
                    .collect::<Vec<_>>()
            })
            .to_string()
        });
    PreparedComposerAuth {
        env_value,
        repository_config_json,
        supported_sections: analysis.supported_sections,
        repository_urls: analysis.repository_urls,
        ignored_repository_entries: analysis.ignored_repository_entries,
        parse_failed: analysis.parse_failed,
    }
}

pub fn composer_install_result_from_exec_output(
    mode: ComposerInstallMode,
    auth_source: Option<String>,
    exit_code: i64,
    stdout: &str,
    stderr: &str,
    gitlab_token: Option<&str>,
    composer_auth: Option<&str>,
    debug_lines: &[String],
) -> ComposerInstallResult {
    let auth_source_for_excerpt = auth_source.clone();
    let redacted_stdout = redact_composer_related_output(stdout, gitlab_token, composer_auth);
    let redacted_stderr = redact_composer_related_output(stderr, gitlab_token, composer_auth);
    let redacted_debug_lines = debug_lines
        .iter()
        .map(|line| redact_composer_related_output(line, gitlab_token, composer_auth))
        .collect::<Vec<_>>();
    if exit_code == COMPOSER_SKIP_EXIT_CODE && is_preflight_skip_output(&redacted_stdout) {
        return ComposerInstallResult::skipped(mode, auth_source);
    }
    if exit_code == 0 {
        return ComposerInstallResult::succeeded(
            mode,
            auth_source.clone(),
            composer_success_log_excerpt(
                auth_source_for_excerpt.as_deref(),
                &redacted_debug_lines,
                &redacted_stdout,
                &redacted_stderr,
            ),
        );
    }
    ComposerInstallResult::failed(
        mode,
        auth_source,
        composer_failure_log_excerpt(
            auth_source_for_excerpt.as_deref(),
            &redacted_debug_lines,
            &redacted_stdout,
            &redacted_stderr,
        ),
    )
}

fn is_preflight_skip_output(stdout: &str) -> bool {
    let skip_line = composer_skip_line();
    stdout.lines().any(|line| line.trim() == skip_line)
}

fn composer_skip_line() -> String {
    format!("{COMPOSER_SKIP_MARKER}:{COMPOSER_SKIP_REASON_MISSING_JSON}")
}

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

#[derive(Default)]
struct ComposerAuthAnalysis {
    supported_sections: Vec<String>,
    repository_urls: Vec<String>,
    ignored_repository_entries: Vec<String>,
    parse_failed: bool,
}

fn analyze_composer_auth(composer_auth: Option<&str>) -> ComposerAuthAnalysis {
    let Some(composer_auth) = composer_auth else {
        return ComposerAuthAnalysis::default();
    };
    let Ok(parsed) = serde_json::from_str::<Value>(composer_auth) else {
        return ComposerAuthAnalysis {
            parse_failed: true,
            ..ComposerAuthAnalysis::default()
        };
    };
    supported_repository_urls(&parsed)
}

fn supported_repository_urls(value: &Value) -> ComposerAuthAnalysis {
    let mut supported_sections = BTreeSet::new();
    let mut repository_urls = BTreeSet::new();
    let mut ignored_entries = BTreeSet::new();
    let Some(map) = value.as_object() else {
        return ComposerAuthAnalysis::default();
    };
    for section in ["http-basic", "bearer", "custom-headers"] {
        let Some(section_value) = map.get(section) else {
            continue;
        };
        let Some(section_map) = section_value.as_object() else {
            continue;
        };
        supported_sections.insert(section.to_string());
        for raw_host in section_map.keys() {
            if let Some(url) = normalized_composer_repository_url(raw_host) {
                repository_urls.insert(url);
            } else {
                ignored_entries.insert(raw_host.to_string());
            }
        }
    }
    ComposerAuthAnalysis {
        supported_sections: supported_sections.into_iter().collect(),
        repository_urls: repository_urls.into_iter().collect(),
        ignored_repository_entries: ignored_entries.into_iter().collect(),
        parse_failed: false,
    }
}

fn normalized_composer_repository_url(raw: &str) -> Option<String> {
    let raw = raw.trim();
    if raw.is_empty() {
        return None;
    }
    if raw.contains("://") {
        let parsed = Url::parse(raw).ok()?;
        return normalized_repository_url_from_parsed(&parsed, Some(parsed.scheme()), true);
    }
    let parsed = Url::parse(&format!("https://{raw}")).ok()?;
    normalized_repository_url_from_parsed(&parsed, Some("https"), false)
}

fn normalized_repository_url_from_parsed(
    parsed: &Url,
    forced_scheme: Option<&str>,
    allow_path: bool,
) -> Option<String> {
    if !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.query().is_some()
        || parsed.fragment().is_some()
    {
        return None;
    }
    if !allow_path && parsed.path() != "/" {
        return None;
    }
    let scheme = forced_scheme.unwrap_or(parsed.scheme());
    if scheme != "http" && scheme != "https" {
        return None;
    }
    let host = match parsed.host()? {
        Host::Domain(domain) => domain.to_string(),
        Host::Ipv4(ip) => ip.to_string(),
        Host::Ipv6(ip) => format!("[{ip}]"),
    };
    let host_port = match parsed.port() {
        Some(port) => format!("{host}:{port}"),
        None => host,
    };
    let path = match parsed.path() {
        "/" => "",
        other => other,
    };
    Some(format!("{scheme}://{host_port}{path}"))
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

fn composer_auth_notice(auth_source: Option<&str>) -> Option<String> {
    let auth_source = auth_source?;
    if let Some(repo_path) = auth_source.strip_prefix("project:") {
        return Some(format!(
            "COMPOSER_AUTH detected from repository {repo_path}"
        ));
    }
    if let Some(group_path) = auth_source.strip_prefix("group:") {
        return Some(format!("COMPOSER_AUTH detected from group {group_path}"));
    }
    Some(format!("COMPOSER_AUTH detected from {auth_source}"))
}

pub fn composer_debug_lines(
    auth_lookup: &ComposerAuthLookup,
    prepared_auth: &PreparedComposerAuth,
    auto_repositories_enabled: bool,
) -> Vec<String> {
    let mut lines = auth_lookup
        .attempts
        .iter()
        .map(|attempt| {
            format!(
                "checked {} -> {}",
                attempt.scope,
                if attempt.found { "found" } else { "not found" }
            )
        })
        .collect::<Vec<_>>();

    if let Some(notice) = composer_auth_notice(auth_lookup.source.as_deref()) {
        lines.push(notice);
    } else {
        lines.push("COMPOSER_AUTH detected: none".to_string());
    }

    lines.push(format!(
        "composer_auto_repositories: {}",
        if auto_repositories_enabled {
            "enabled"
        } else {
            "disabled"
        }
    ));

    if prepared_auth.parse_failed {
        lines.push("COMPOSER_AUTH JSON parse: failed".to_string());
    } else {
        lines.push(format!(
            "supported COMPOSER_AUTH sections: {}",
            if prepared_auth.supported_sections.is_empty() {
                "none".to_string()
            } else {
                prepared_auth.supported_sections.join(", ")
            }
        ));
    }

    lines.push(format!(
        "derived Composer repository hosts: {}",
        if prepared_auth.repository_urls.is_empty() {
            "none".to_string()
        } else {
            repository_debug_labels(&prepared_auth.repository_urls).join(", ")
        }
    ));

    if !prepared_auth.ignored_repository_entries.is_empty() {
        lines.push(format!(
            "ignored COMPOSER_AUTH repository entries: {}",
            prepared_auth.ignored_repository_entries.len()
        ));
    }

    lines.push(format!(
        "temporary COMPOSER_HOME config: {}",
        if prepared_auth.repository_config_json.is_some() {
            "written"
        } else {
            "skipped"
        }
    ));
    lines.push(format!(
        "COMPOSER_AUTH exported to composer: {}",
        if prepared_auth.env_value.is_some() {
            "yes"
        } else {
            "no"
        }
    ));

    lines
}

fn truncate_excerpt(input: &str, max_chars: usize) -> String {
    if input.chars().count() <= max_chars {
        return input.to_string();
    }
    let truncated = input.chars().take(max_chars).collect::<String>();
    format!("{truncated}\n[truncated]")
}

fn repository_debug_labels(urls: &[String]) -> Vec<String> {
    urls.iter()
        .filter_map(|url| {
            let parsed = Url::parse(url).ok()?;
            let host = parsed.host_str()?;
            Some(match parsed.port() {
                Some(port) => format!("{host}:{port}"),
                None => host.to_string(),
            })
        })
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

fn collect_string_leaves(value: &Value, output: &mut Vec<String>) {
    match value {
        Value::String(string) => output.push(string.clone()),
        Value::Array(items) => {
            for item in items {
                collect_string_leaves(item, output);
            }
        }
        Value::Object(map) => {
            for value in map.values() {
                collect_string_leaves(value, output);
            }
        }
        Value::Null | Value::Bool(_) | Value::Number(_) => {}
    }
}

fn shell_quote(input: &str) -> String {
    format!("'{}'", input.replace('\'', "'\"'\"'"))
}

async fn resolve_project_variable(
    gitlab: &dyn GitLabApi,
    repo_path: &str,
) -> Option<GitLabCiVariable> {
    match gitlab
        .get_project_variable(repo_path, COMPOSER_AUTH_VARIABLE_KEY)
        .await
    {
        Ok(variable) => Some(variable),
        Err(_) => select_global_scope_variable(
            gitlab
                .list_project_variables(repo_path)
                .await
                .unwrap_or_default()
                .into_iter(),
        ),
    }
}

async fn resolve_group_variable(gitlab: &dyn GitLabApi, group: &str) -> Option<GitLabCiVariable> {
    match gitlab
        .get_group_variable(group, COMPOSER_AUTH_VARIABLE_KEY)
        .await
    {
        Ok(variable) => Some(variable),
        Err(_) => select_global_scope_variable(
            gitlab
                .list_group_variables(group)
                .await
                .unwrap_or_default()
                .into_iter(),
        ),
    }
}

fn select_global_scope_variable(
    variables: impl IntoIterator<Item = GitLabCiVariable>,
) -> Option<GitLabCiVariable> {
    variables.into_iter().find(|variable| {
        variable.key == COMPOSER_AUTH_VARIABLE_KEY && variable.environment_scope == "*"
    })
}

fn repo_parent_groups(repo_path: &str) -> Vec<String> {
    let mut parts = repo_path
        .split('/')
        .map(str::trim)
        .filter(|part| !part.is_empty())
        .collect::<Vec<_>>();
    if parts.len() < 2 {
        return Vec::new();
    }
    parts.pop();
    let mut groups = Vec::new();
    for depth in (1..=parts.len()).rev() {
        groups.push(parts[..depth].join("/"));
    }
    groups
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::feature_flags::FeatureFlagSnapshot;
    use anyhow::Result;
    use async_trait::async_trait;
    use std::collections::BTreeMap;

    #[derive(Default)]
    struct FakeVariableGitLab {
        project_variables: BTreeMap<String, GitLabCiVariable>,
        group_variables: BTreeMap<String, GitLabCiVariable>,
    }

    #[async_trait]
    impl GitLabApi for FakeVariableGitLab {
        async fn current_user(&self) -> Result<crate::gitlab::GitLabUser> {
            unimplemented!()
        }

        async fn list_projects(&self) -> Result<Vec<crate::gitlab::GitLabProjectSummary>> {
            unimplemented!()
        }

        async fn list_group_projects(
            &self,
            _group: &str,
        ) -> Result<Vec<crate::gitlab::GitLabProjectSummary>> {
            unimplemented!()
        }

        async fn list_open_mrs(&self, _project: &str) -> Result<Vec<crate::gitlab::MergeRequest>> {
            unimplemented!()
        }

        async fn get_latest_open_mr_activity(
            &self,
            _project: &str,
        ) -> Result<Option<crate::gitlab::MergeRequest>> {
            unimplemented!()
        }

        async fn get_mr(&self, _project: &str, _iid: u64) -> Result<crate::gitlab::MergeRequest> {
            unimplemented!()
        }

        async fn get_project(&self, _project: &str) -> Result<crate::gitlab::GitLabProject> {
            unimplemented!()
        }

        async fn get_group(&self, _group: &str) -> Result<crate::gitlab::GitLabGroup> {
            unimplemented!()
        }

        async fn list_awards(
            &self,
            _project: &str,
            _iid: u64,
        ) -> Result<Vec<crate::gitlab::AwardEmoji>> {
            unimplemented!()
        }

        async fn add_award(&self, _project: &str, _iid: u64, _name: &str) -> Result<()> {
            unimplemented!()
        }

        async fn delete_award(&self, _project: &str, _iid: u64, _award_id: u64) -> Result<()> {
            unimplemented!()
        }

        async fn list_notes(&self, _project: &str, _iid: u64) -> Result<Vec<crate::gitlab::Note>> {
            unimplemented!()
        }

        async fn list_discussions(
            &self,
            _project: &str,
            _iid: u64,
        ) -> Result<Vec<crate::gitlab::MergeRequestDiscussion>> {
            unimplemented!()
        }

        async fn create_note(&self, _project: &str, _iid: u64, _body: &str) -> Result<()> {
            unimplemented!()
        }

        async fn get_project_variable(&self, project: &str, key: &str) -> Result<GitLabCiVariable> {
            self.project_variables
                .get(&format!("{project}:{key}"))
                .cloned()
                .ok_or_else(|| anyhow::anyhow!("not found"))
        }

        async fn list_project_variables(&self, project: &str) -> Result<Vec<GitLabCiVariable>> {
            Ok(self
                .project_variables
                .iter()
                .filter_map(|(composite_key, variable)| {
                    composite_key
                        .strip_suffix(&format!(":{COMPOSER_AUTH_VARIABLE_KEY}"))
                        .filter(|candidate| *candidate == project)
                        .map(|_| variable.clone())
                })
                .collect())
        }

        async fn get_group_variable(&self, group: &str, key: &str) -> Result<GitLabCiVariable> {
            self.group_variables
                .get(&format!("{group}:{key}"))
                .cloned()
                .ok_or_else(|| anyhow::anyhow!("not found"))
        }

        async fn list_group_variables(&self, group: &str) -> Result<Vec<GitLabCiVariable>> {
            Ok(self
                .group_variables
                .iter()
                .filter_map(|(composite_key, variable)| {
                    composite_key
                        .strip_suffix(&format!(":{COMPOSER_AUTH_VARIABLE_KEY}"))
                        .filter(|candidate| *candidate == group)
                        .map(|_| variable.clone())
                })
                .collect())
        }
    }

    #[test]
    fn mode_defaults_to_full_when_safe_flag_is_disabled() {
        assert_eq!(
            ComposerInstallMode::for_flags(&FeatureFlagSnapshot {
                composer_install: true,
                composer_safe_install: false,
                ..FeatureFlagSnapshot::default()
            }),
            Some(ComposerInstallMode::Full)
        );
    }

    #[test]
    fn mode_uses_safe_install_when_safe_flag_is_enabled() {
        assert_eq!(
            ComposerInstallMode::for_flags(&FeatureFlagSnapshot {
                composer_install: true,
                composer_safe_install: true,
                ..FeatureFlagSnapshot::default()
            }),
            Some(ComposerInstallMode::Safe)
        );
    }

    #[tokio::test]
    async fn resolve_composer_auth_prefers_project_variable_and_records_attempts() {
        let mut gitlab = FakeVariableGitLab::default();
        gitlab.project_variables.insert(
            "group/sub/repo:COMPOSER_AUTH".to_string(),
            GitLabCiVariable {
                key: COMPOSER_AUTH_VARIABLE_KEY.to_string(),
                value: r#"{"http-basic":{"repo.example.com":{"password":"s3cr3t"}}}"#.to_string(),
                environment_scope: "*".to_string(),
            },
        );

        let lookup = resolve_composer_auth(&gitlab, "group/sub/repo").await;

        assert_eq!(lookup.source.as_deref(), Some("project:group/sub/repo"));
        assert_eq!(
            lookup.attempts,
            vec![ComposerAuthLookupAttempt {
                scope: "project:group/sub/repo".to_string(),
                found: true,
            }]
        );
    }

    #[tokio::test]
    async fn resolve_composer_auth_falls_back_to_nearest_parent_group_and_records_attempts() {
        let mut gitlab = FakeVariableGitLab::default();
        gitlab.group_variables.insert(
            "group/sub:COMPOSER_AUTH".to_string(),
            GitLabCiVariable {
                key: COMPOSER_AUTH_VARIABLE_KEY.to_string(),
                value: r#"{"bearer":{"cache.example.com":"token"}}"#.to_string(),
                environment_scope: "*".to_string(),
            },
        );
        gitlab.group_variables.insert(
            "group:COMPOSER_AUTH".to_string(),
            GitLabCiVariable {
                key: COMPOSER_AUTH_VARIABLE_KEY.to_string(),
                value: r#"{"http-basic":{"repo.example.com":{"password":"s3cr3t"}}}"#.to_string(),
                environment_scope: "*".to_string(),
            },
        );

        let lookup = resolve_composer_auth(&gitlab, "group/sub/repo").await;

        assert_eq!(lookup.source.as_deref(), Some("group:group/sub"));
        assert_eq!(
            lookup.attempts,
            vec![
                ComposerAuthLookupAttempt {
                    scope: "project:group/sub/repo".to_string(),
                    found: false,
                },
                ComposerAuthLookupAttempt {
                    scope: "group:group/sub".to_string(),
                    found: true,
                },
            ]
        );
    }

    #[test]
    fn composer_install_exec_command_cleans_up_temporary_log_file() {
        let command = composer_install_exec_command(ComposerInstallMode::Full, 42, None);
        let script = command.last().expect("bash script");

        assert!(script.contains("mktemp /tmp/codex-composer-install."));
        assert!(script.contains("mktemp /tmp/codex-composer-timeout."));
        assert!(script.contains("trap cleanup EXIT"));
        assert!(script.contains("rm -f \"$log_file\""));
        assert!(script.contains("rm -f \"$timeout_marker\""));
        assert!(!script.contains("mktemp -d /tmp/codex-composer-home."));
        assert!(script.contains("composer install timed out after 42s"));
        let run_pid_pos = script.find("run_pid=\"$!\"").expect("run pid assignment");
        let watchdog_pos = script
            .find("watchdog_pid=\"$!\"")
            .expect("watchdog assignment");
        assert!(run_pid_pos < watchdog_pos);
    }

    #[test]
    fn composer_install_exec_command_configures_temporary_composer_home_when_requested() {
        let command = composer_install_exec_command(
            ComposerInstallMode::Full,
            42,
            Some(r#"{"repositories":[{"type":"composer","url":"https://example.com"}]}"#),
        );
        let script = command.last().expect("bash script");

        assert!(script.contains("composer_home=\"$(mktemp -d /tmp/codex-composer-home."));
        assert!(script.contains("failed to create temporary COMPOSER_HOME"));
        assert!(script.contains("failed to write temporary Composer config"));
        assert!(script.contains("export COMPOSER_HOME=\"$composer_home\""));
        assert!(script.contains("config.json"));
        assert!(script.contains("rm -rf \"$composer_home\""));
    }

    #[test]
    fn repo_parent_groups_prefers_closest_group_first() {
        assert_eq!(
            repo_parent_groups("group/subgroup/project"),
            vec!["group/subgroup".to_string(), "group".to_string()]
        );
    }

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
    fn prepare_composer_auth_leaves_env_unchanged_when_auto_repositories_disabled() {
        let raw = r#"{"http-basic":{"example.com":{"username":"bot","password":"s3cr3t"}}}"#;

        let prepared = prepare_composer_auth(Some(raw), false);

        assert_eq!(prepared.env_value.as_deref(), Some(raw));
        assert_eq!(prepared.repository_config_json, None);
        assert_eq!(prepared.supported_sections, vec!["http-basic".to_string()]);
        assert_eq!(
            prepared.repository_urls,
            vec!["https://example.com".to_string()]
        );
        assert!(prepared.ignored_repository_entries.is_empty());
        assert!(!prepared.parse_failed);
    }

    #[test]
    fn prepare_composer_auth_derives_supported_http_auth_hosts() {
        let raw = r#"{
          "http-basic":{"repo.example.com":{"username":"bot","password":"s3cr3t"}},
          "bearer":{"cache.example.com":"token"},
          "custom-headers":{"https://mirror.example.com/packages.json":["Authorization: token value"]},
          "gitlab-token":{"gitlab.example.com":"token"},
          "github-oauth":{"github.com":"token"}
        }"#;

        let prepared = prepare_composer_auth(Some(raw), true);
        let config = serde_json::from_str::<Value>(
            prepared
                .repository_config_json
                .as_deref()
                .expect("repository config"),
        )
        .expect("valid repository config");

        assert_eq!(prepared.env_value.as_deref(), Some(raw));
        assert_eq!(
            prepared.supported_sections,
            vec![
                "bearer".to_string(),
                "custom-headers".to_string(),
                "http-basic".to_string()
            ]
        );
        assert_eq!(
            prepared.repository_urls,
            vec![
                "https://cache.example.com".to_string(),
                "https://mirror.example.com/packages.json".to_string(),
                "https://repo.example.com".to_string()
            ]
        );
        assert_eq!(
            config,
            json!({
                "repositories": [
                    { "type": "composer", "url": "https://cache.example.com" },
                    { "type": "composer", "url": "https://mirror.example.com/packages.json" },
                    { "type": "composer", "url": "https://repo.example.com" }
                ]
            })
        );
    }

    #[test]
    fn prepare_composer_auth_preserves_ipv6_host_format() {
        let raw = r#"{
          "http-basic":{
            "[2001:db8::1]":{"username":"bot","password":"s3cr3t"},
            "[2001:db8::2]:8443":{"username":"bot","password":"s3cr3t"}
          }
        }"#;

        let prepared = prepare_composer_auth(Some(raw), true);
        let config = serde_json::from_str::<Value>(
            prepared
                .repository_config_json
                .as_deref()
                .expect("repository config"),
        )
        .expect("valid repository config");

        assert_eq!(
            config,
            json!({
                "repositories": [
                    { "type": "composer", "url": "https://[2001:db8::1]" },
                    { "type": "composer", "url": "https://[2001:db8::2]:8443" }
                ]
            })
        );
    }

    #[test]
    fn prepare_composer_auth_ignores_invalid_or_unsupported_hosts() {
        let raw = r#"{
          "http-basic":{"":"bad","https://scheme.example.com":"bad","path/example.com":"bad","oauth2:token@example.com":"bad"},
          "gitlab-token":{"gitlab.example.com":"token"}
        }"#;

        let prepared = prepare_composer_auth(Some(raw), true);

        assert_eq!(prepared.env_value.as_deref(), Some(raw));
        assert_eq!(
            prepared.repository_urls,
            vec!["https://scheme.example.com".to_string()]
        );
        assert_eq!(
            prepared.ignored_repository_entries,
            vec![
                "".to_string(),
                "oauth2:token@example.com".to_string(),
                "path/example.com".to_string()
            ]
        );
    }

    #[test]
    fn prepare_composer_auth_ignores_invalid_json() {
        let raw = "{not-json";

        let prepared = prepare_composer_auth(Some(raw), true);

        assert_eq!(prepared.env_value.as_deref(), Some(raw));
        assert_eq!(prepared.repository_config_json, None);
        assert!(prepared.parse_failed);
    }

    #[test]
    fn composer_debug_lines_report_lookup_and_repository_derivation_steps() {
        let lookup = ComposerAuthLookup {
            value: Some("secret".to_string()),
            source: Some("group:team/platform".to_string()),
            attempts: vec![
                ComposerAuthLookupAttempt {
                    scope: "project:team/platform/app".to_string(),
                    found: false,
                },
                ComposerAuthLookupAttempt {
                    scope: "group:team/platform".to_string(),
                    found: true,
                },
            ],
        };
        let prepared = PreparedComposerAuth {
            env_value: Some("secret".to_string()),
            repository_config_json: Some(
                r#"{"repositories":[{"type":"composer","url":"https://repo.example.com"}]}"#
                    .to_string(),
            ),
            supported_sections: vec!["http-basic".to_string()],
            repository_urls: vec!["https://repo.example.com".to_string()],
            ignored_repository_entries: vec!["path/example.com".to_string()],
            parse_failed: false,
        };

        let lines = composer_debug_lines(&lookup, &prepared, true);

        assert_eq!(
            lines,
            vec![
                "checked project:team/platform/app -> not found".to_string(),
                "checked group:team/platform -> found".to_string(),
                "COMPOSER_AUTH detected from group team/platform".to_string(),
                "composer_auto_repositories: enabled".to_string(),
                "supported COMPOSER_AUTH sections: http-basic".to_string(),
                "derived Composer repository hosts: repo.example.com".to_string(),
                "ignored COMPOSER_AUTH repository entries: 1".to_string(),
                "temporary COMPOSER_HOME config: written".to_string(),
                "COMPOSER_AUTH exported to composer: yes".to_string(),
            ]
        );
    }

    #[test]
    fn composer_install_result_marks_missing_composer_json_as_skipped() {
        let result = composer_install_result_from_exec_output(
            ComposerInstallMode::Full,
            None,
            86,
            "CODEX_COMPOSER_SKIP:missing-composer-json\n",
            "",
            None,
            None,
            &[],
        );

        assert_eq!(
            result,
            ComposerInstallResult::skipped(ComposerInstallMode::Full, None)
        );
    }

    #[test]
    fn composer_install_result_does_not_treat_success_log_as_skip_marker() {
        let result = composer_install_result_from_exec_output(
            ComposerInstallMode::Full,
            None,
            0,
            "Installing\nCODEX_COMPOSER_SKIP not actually a preflight skip\nDone",
            "",
            None,
            None,
            &[],
        );

        assert!(result.attempted);
        assert!(result.success);
    }

    #[test]
    fn composer_install_result_does_not_treat_success_exit_with_marker_line_as_skipped() {
        let result = composer_install_result_from_exec_output(
            ComposerInstallMode::Full,
            None,
            0,
            "CODEX_COMPOSER_SKIP:missing-composer-json",
            "",
            None,
            None,
            &[],
        );

        assert!(result.attempted);
        assert!(result.success);
    }

    #[test]
    fn composer_install_result_treats_skip_marker_line_with_noise_as_skipped() {
        let result = composer_install_result_from_exec_output(
            ComposerInstallMode::Full,
            None,
            86,
            "wrapper noise\nCODEX_COMPOSER_SKIP:missing-composer-json\nmore wrapper noise",
            "",
            None,
            None,
            &[],
        );

        assert_eq!(
            result,
            ComposerInstallResult::skipped(ComposerInstallMode::Full, None)
        );
    }

    #[test]
    fn composer_install_result_redacts_failure_excerpt() {
        let result = composer_install_result_from_exec_output(
            ComposerInstallMode::Safe,
            Some("group:team/platform".to_string()),
            1,
            "install failed for s3cr3t",
            "https://oauth2:token@example.com/repo.git",
            Some("token"),
            Some(r#"{"http-basic":{"example.com":{"password":"s3cr3t"}}}"#),
            &[
                "checked group:team/platform -> found".to_string(),
                "derived Composer repository hosts: example.com".to_string(),
            ],
        );

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
        let result = composer_install_result_from_exec_output(
            ComposerInstallMode::Safe,
            Some("group:team/platform".to_string()),
            1,
            "install failed",
            "",
            Some("token"),
            Some(r#"{"http-basic":{"example.com":{"password":"s3cr3t"}}}"#),
            &[
                "ignored COMPOSER_AUTH repository entries: 1".to_string(),
                "derived Composer repository hosts: example.com".to_string(),
            ],
        );

        let excerpt = result.log_excerpt.expect("failure excerpt");
        assert!(excerpt.contains("ignored COMPOSER_AUTH repository entries: 1"));
    }

    #[test]
    fn composer_install_result_keeps_redacted_success_excerpt() {
        let result = composer_install_result_from_exec_output(
            ComposerInstallMode::Full,
            Some("project:group/repo".to_string()),
            0,
            "Installing package with s3cr3t",
            "https://oauth2:token@example.com/repo.git",
            Some("token"),
            Some(r#"{"http-basic":{"example.com":{"password":"s3cr3t"}}}"#),
            &[
                "checked project:group/repo -> found".to_string(),
                "temporary COMPOSER_HOME config: written".to_string(),
            ],
        );

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
        let result = composer_install_result_from_exec_output(
            ComposerInstallMode::Full,
            None,
            0,
            "Installing dependencies from lock file",
            "",
            None,
            None,
            &[
                "checked project:group/repo -> not found".to_string(),
                "COMPOSER_AUTH detected: none".to_string(),
                "COMPOSER_AUTH exported to composer: no".to_string(),
            ],
        );

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
        let result = composer_install_result_from_exec_output(
            ComposerInstallMode::Full,
            Some("group:team/platform".to_string()),
            0,
            &long_output,
            "",
            None,
            None,
            &["checked group:team/platform -> found".to_string()],
        );

        let excerpt = result.log_excerpt.expect("truncated excerpt");
        assert!(excerpt.starts_with("checked group:team/platform -> found\n"));
        assert!(excerpt.contains(&"x".repeat(128)));
        assert!(excerpt.ends_with("[truncated]"));
    }

    #[test]
    fn composer_install_timeout_seconds_rounds_up_subsecond_budget() {
        assert_eq!(
            composer_install_timeout_seconds(Duration::from_millis(1)),
            Some(1)
        );
        assert_eq!(
            composer_install_timeout_seconds(Duration::from_millis(1500)),
            Some(2)
        );
        assert_eq!(composer_install_timeout_seconds(Duration::ZERO), None);
    }
}
