use super::{
    ContainerInspectResponse, Context, DockerCodexRunner, LogOutput, LogsOptionsBuilder, Result,
    RunnerRuntime, StreamExt, anyhow, warn,
};
use crate::codex_runner::browser_mcp::tail_log_lines;
use crate::composer_install::redact_composer_related_output;
#[cfg(test)]
use anyhow::bail;
use bollard::errors::Error as BollardError;
use bollard::query_parameters::DownloadFromContainerOptionsBuilder;
use std::fmt;
use std::io::Read;
use std::time::Duration;

const APP_SERVER_DIAGNOSTICS_FLUSH_GRACE: Duration = Duration::from_millis(100);
const APP_SERVER_DIAGNOSTICS_TIMEOUT: Duration = Duration::from_secs(5);
const APP_SERVER_LOG_MAX_BYTES: usize = 512 * 1024;
pub(crate) const CODEX_INSTALL_LOG_PATH: &str = "/tmp/codex-install.log";
const CODEX_INSTALL_ARCHIVE_MAX_BYTES: usize = 1024 * 1024;
pub(crate) const CODEX_INSTALL_LOG_CHUNK_BYTES: usize = 64 * 1024;
pub(crate) const CODEX_INSTALL_LOG_MAX_BYTES: usize = 512 * 1024;
const CODEX_INSTALL_LOG_WORKING_MAX_BYTES: usize =
    CODEX_INSTALL_LOG_MAX_BYTES + CODEX_INSTALL_LOG_CHUNK_BYTES;

#[derive(Debug)]
pub(crate) struct AppServerContainerDiagnosticsContext(String);

impl AppServerContainerDiagnosticsContext {
    pub(crate) fn new(value: String) -> Self {
        Self(value)
    }
}

impl fmt::Display for AppServerContainerDiagnosticsContext {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl std::error::Error for AppServerContainerDiagnosticsContext {}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct AppServerLogTail {
    pub(crate) stdout: Vec<String>,
    pub(crate) stderr: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AppServerContainerStateSnapshot {
    pub(crate) image: Option<String>,
    pub(crate) image_id: Option<String>,
    pub(crate) status: Option<String>,
    pub(crate) running: Option<bool>,
    pub(crate) exit_code: Option<i64>,
    pub(crate) oom_killed: Option<bool>,
    pub(crate) error: Option<String>,
    pub(crate) started_at: Option<String>,
    pub(crate) finished_at: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AppServerContainerDiagnostics {
    pub(crate) container_id: String,
    pub(crate) state: Option<AppServerContainerStateSnapshot>,
    pub(crate) state_collection_error: Option<String>,
    pub(crate) log_tail: AppServerLogTail,
    pub(crate) log_collection_error: Option<String>,
    pub(crate) codex_install_log_tail: Option<Vec<String>>,
    pub(crate) codex_install_log_collection_error: Option<String>,
}

impl AppServerContainerDiagnostics {
    pub(crate) fn format_context(&self) -> String {
        let mut lines = vec![
            "app-server container diagnostics:".to_string(),
            format!("  id={}", self.container_id),
        ];

        match (&self.state, &self.state_collection_error) {
            (Some(state), _) => {
                lines.push(format!(
                    "  image={} image_id={}",
                    state.image.as_deref().unwrap_or("<unknown>"),
                    state.image_id.as_deref().unwrap_or("<unknown>")
                ));
                lines.push(format!(
                "  state status={} running={} exit_code={} oom_killed={} started_at={} finished_at={} error={}",
                state.status.as_deref().unwrap_or("<unknown>"),
                state
                    .running
                    .map_or_else(|| "<unknown>".to_string(), |value| value.to_string()),
                state
                    .exit_code
                    .map_or_else(|| "<unknown>".to_string(), |value| value.to_string()),
                state
                    .oom_killed
                    .map_or_else(|| "<unknown>".to_string(), |value| value.to_string()),
                state.started_at.as_deref().unwrap_or("<unknown>"),
                state.finished_at.as_deref().unwrap_or("<unknown>"),
                state.error.as_deref().unwrap_or("<none>")
                ));
            }
            (None, Some(err)) => lines.push(format!("  state unavailable: {err}")),
            (None, None) => lines.push("  state unavailable: <unknown>".to_string()),
        }

        if let Some(err) = &self.log_collection_error {
            lines.push(format!("  log tail unavailable: {err}"));
        } else {
            if self.log_tail.stdout.is_empty() {
                lines.push("  stdout tail: <empty>".to_string());
            } else {
                lines.push("  stdout tail:".to_string());
                for line in &self.log_tail.stdout {
                    lines.push(format!("    {line}"));
                }
            }
            if self.log_tail.stderr.is_empty() {
                lines.push("  stderr tail: <empty>".to_string());
            } else {
                lines.push("  stderr tail:".to_string());
                for line in &self.log_tail.stderr {
                    lines.push(format!("    {line}"));
                }
            }
        }

        match (
            &self.codex_install_log_tail,
            &self.codex_install_log_collection_error,
        ) {
            (Some(log_tail), _) if log_tail.is_empty() => {
                lines.push("  codex install log tail: <empty>".to_string());
            }
            (Some(log_tail), _) => {
                lines.push("  codex install log tail:".to_string());
                for line in log_tail {
                    lines.push(format!("    {line}"));
                }
            }
            (None, Some(err)) => lines.push(format!("  codex install log unavailable: {err}")),
            (None, None) => {
                lines.push("  codex install log tail: <not present>".to_string());
            }
        }

        lines.join("\n")
    }
}

impl DockerCodexRunner {
    pub(crate) async fn collect_app_server_container_diagnostics(
        &self,
        app_server_container_id: &str,
    ) -> AppServerContainerDiagnostics {
        #[cfg(test)]
        if let RunnerRuntime::Fake(harness) = &self.runtime {
            return harness
                .collect_app_server_container_diagnostics(app_server_container_id)
                .await;
        }

        #[cfg(test)]
        let docker = match &self.runtime {
            RunnerRuntime::Docker { docker, .. } => docker,
            RunnerRuntime::Fake(_) => unreachable!("fake runtime handled above"),
        };
        #[cfg(not(test))]
        let RunnerRuntime::Docker { docker, .. } = &self.runtime;
        tokio::time::sleep(APP_SERVER_DIAGNOSTICS_FLUSH_GRACE).await;
        let inspect = async {
            docker
                .inspect_container(
                    app_server_container_id,
                    None::<bollard::query_parameters::InspectContainerOptions>,
                )
                .await
                .map(app_server_container_state_snapshot)
                .map_err(|err| {
                    anyhow!(err).context(format!(
                        "inspect docker app-server container {app_server_container_id}"
                    ))
                })
        };
        let (state_result, log_result, codex_install_log_result) = tokio::join!(
            tokio::time::timeout(APP_SERVER_DIAGNOSTICS_TIMEOUT, inspect),
            tokio::time::timeout(
                APP_SERVER_DIAGNOSTICS_TIMEOUT,
                self.collect_app_server_container_log_tail(app_server_container_id)
            ),
            tokio::time::timeout(
                APP_SERVER_DIAGNOSTICS_TIMEOUT,
                self.collect_codex_install_log_tail(app_server_container_id)
            ),
        );
        let (state, state_collection_error) = match state_result {
            Ok(Ok(state)) => (Some(state), None),
            Ok(Err(err)) => (None, Some(format!("{err:#}"))),
            Err(_) => (
                None,
                Some("timed out collecting app-server container state".to_string()),
            ),
        };
        let (log_tail, log_collection_error) = match log_result {
            Ok(Ok(log_tail)) => (log_tail, None),
            Ok(Err(err)) => (AppServerLogTail::default(), Some(format!("{err:#}"))),
            Err(_) => (
                AppServerLogTail::default(),
                Some("timed out collecting app-server container logs".to_string()),
            ),
        };
        let (codex_install_log_tail, codex_install_log_collection_error) =
            match codex_install_log_result {
                Ok(Ok(log_tail)) => (log_tail, None),
                Ok(Err(err)) => (None, Some(format!("{err:#}"))),
                Err(_) => (
                    None,
                    Some("timed out collecting Codex install log".to_string()),
                ),
            };

        AppServerContainerDiagnostics {
            container_id: app_server_container_id.to_string(),
            state,
            state_collection_error,
            log_tail,
            log_collection_error,
            codex_install_log_tail,
            codex_install_log_collection_error,
        }
    }

    pub(crate) async fn collect_app_server_container_log_tail(
        &self,
        app_server_container_id: &str,
    ) -> Result<AppServerLogTail> {
        #[cfg(test)]
        let docker = match &self.runtime {
            RunnerRuntime::Docker { docker, .. } => docker,
            RunnerRuntime::Fake(_) => {
                bail!("fake runtime should not collect live app-server logs directly");
            }
        };
        #[cfg(not(test))]
        let RunnerRuntime::Docker { docker, .. } = &self.runtime;
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let mut stream = docker.logs(
            app_server_container_id,
            Some(
                LogsOptionsBuilder::default()
                    .follow(false)
                    .stdout(true)
                    .stderr(true)
                    .tail("50")
                    .build(),
            ),
        );

        while let Some(message) = stream.next().await {
            match message.with_context(|| {
                format!("read docker app-server container logs for {app_server_container_id}")
            })? {
                LogOutput::StdOut { message } | LogOutput::Console { message } => {
                    append_bounded_log_bytes(&mut stdout, &message);
                }
                LogOutput::StdErr { message } => {
                    append_bounded_log_bytes(&mut stderr, &message);
                }
                LogOutput::StdIn { .. } => {}
            }
        }

        Ok(app_server_log_tail_from_raw(
            &String::from_utf8_lossy(&stdout),
            &String::from_utf8_lossy(&stderr),
            Some(&self.gitlab_token),
        ))
    }

    async fn collect_codex_install_log_tail(
        &self,
        app_server_container_id: &str,
    ) -> Result<Option<Vec<String>>> {
        #[cfg(test)]
        let docker = match &self.runtime {
            RunnerRuntime::Docker { docker, .. } => docker,
            RunnerRuntime::Fake(_) => {
                bail!("fake runtime should not collect live Codex install logs directly");
            }
        };
        #[cfg(not(test))]
        let RunnerRuntime::Docker { docker, .. } = &self.runtime;
        let mut archive_bytes = Vec::new();
        let mut stream = docker.download_from_container(
            app_server_container_id,
            Some(
                DownloadFromContainerOptionsBuilder::default()
                    .path(CODEX_INSTALL_LOG_PATH)
                    .build(),
            ),
        );

        while let Some(chunk) = stream.next().await {
            match chunk {
                Ok(chunk) => {
                    if archive_bytes.len().saturating_add(chunk.len())
                        > CODEX_INSTALL_ARCHIVE_MAX_BYTES
                    {
                        anyhow::bail!(
                            "docker archive for {CODEX_INSTALL_LOG_PATH} exceeded {CODEX_INSTALL_ARCHIVE_MAX_BYTES} bytes"
                        );
                    }
                    archive_bytes.extend_from_slice(&chunk);
                }
                Err(err) if archive_bytes.is_empty() && docker_error_is_not_found(&err) => {
                    return Ok(None);
                }
                Err(err) => {
                    return Err(anyhow!(err).context(format!(
                        "download {CODEX_INSTALL_LOG_PATH} from docker app-server container {app_server_container_id}"
                    )));
                }
            }
        }

        if archive_bytes.is_empty() {
            return Ok(None);
        }
        app_server_install_log_tail_from_archive(&archive_bytes, Some(self.gitlab_token.as_str()))
            .map(Some)
    }

    pub(crate) async fn enrich_error_with_app_server_diagnostics(
        &self,
        err: anyhow::Error,
        app_server_container_id: &str,
    ) -> anyhow::Error {
        let diagnostics = self
            .collect_app_server_container_diagnostics(app_server_container_id)
            .await;
        let formatted = diagnostics.format_context();
        warn!(
            container_id = app_server_container_id,
            diagnostics = %formatted,
            "app-server container diagnostics captured"
        );
        err.context(AppServerContainerDiagnosticsContext::new(formatted))
    }
}

pub(crate) fn app_server_container_state_snapshot(
    inspect: ContainerInspectResponse,
) -> AppServerContainerStateSnapshot {
    let image = inspect
        .config
        .as_ref()
        .and_then(|config| config.image.clone());
    let image_id = inspect.image.clone();
    let state = inspect.state;
    AppServerContainerStateSnapshot {
        image,
        image_id,
        status: state
            .as_ref()
            .and_then(|state| state.status)
            .map(|value| format!("{value:?}").to_ascii_lowercase()),
        running: state.as_ref().and_then(|state| state.running),
        exit_code: state.as_ref().and_then(|state| state.exit_code),
        oom_killed: state.as_ref().and_then(|state| state.oom_killed),
        error: state
            .as_ref()
            .and_then(|state| state.error.as_deref())
            .filter(|value| !value.trim().is_empty())
            .map(ToOwned::to_owned),
        started_at: state
            .as_ref()
            .and_then(|state| state.started_at.as_deref())
            .filter(|value| !value.trim().is_empty())
            .map(ToOwned::to_owned),
        finished_at: state
            .as_ref()
            .and_then(|state| state.finished_at.as_deref())
            .filter(|value| !value.trim().is_empty())
            .map(ToOwned::to_owned),
    }
}

fn docker_error_is_not_found(err: &BollardError) -> bool {
    matches!(
        err,
        BollardError::DockerResponseServerError {
            status_code: 404,
            ..
        }
    )
}

pub(crate) fn app_server_install_log_tail_from_archive(
    archive_bytes: &[u8],
    gitlab_token: Option<&str>,
) -> Result<Vec<String>> {
    let mut archive = tar::Archive::new(archive_bytes);
    let entries = archive
        .entries()
        .context("read Codex install log docker archive")?;
    for entry in entries {
        let mut entry = entry.context("read entry from Codex install log docker archive")?;
        let path = entry
            .path()
            .context("read path from Codex install log docker archive")?;
        if path.file_name().and_then(|name| name.to_str()) != Some("codex-install.log") {
            continue;
        }
        let mut contents = Vec::new();
        entry
            .by_ref()
            .take((CODEX_INSTALL_LOG_WORKING_MAX_BYTES + 1) as u64)
            .read_to_end(&mut contents)
            .context("read Codex install log from docker archive")?;
        if contents.len() > CODEX_INSTALL_LOG_WORKING_MAX_BYTES {
            anyhow::bail!(
                "{CODEX_INSTALL_LOG_PATH} exceeded {CODEX_INSTALL_LOG_WORKING_MAX_BYTES} bytes"
            );
        }
        let contents = &contents[contents.len().saturating_sub(CODEX_INSTALL_LOG_MAX_BYTES)..];
        let contents = String::from_utf8_lossy(contents);
        let redacted = redact_app_server_diagnostic_output(&contents, gitlab_token);
        return Ok(tail_log_lines(&redacted));
    }
    anyhow::bail!("{CODEX_INSTALL_LOG_PATH} was missing from docker archive")
}

fn redact_app_server_diagnostic_output(input: &str, gitlab_token: Option<&str>) -> String {
    let mut redacted = redact_composer_related_output(input, gitlab_token, None);
    for key in [
        "_authToken=",
        "_authtoken=",
        "_auth=",
        "_password=",
        "NPM_TOKEN=",
        "npm_token=",
        "NODE_AUTH_TOKEN=",
        "node_auth_token=",
    ] {
        redacted = redact_secret_assignments(redacted, key);
    }
    redact_url_userinfo(redacted)
}

fn redact_secret_assignments(mut input: String, key: &str) -> String {
    const REDACTED: &str = "[REDACTED_NPM_SECRET]";
    let mut search_from = 0;
    while let Some(relative_key_start) = input[search_from..].find(key) {
        let raw_value_start = search_from + relative_key_start + key.len();
        let value_start = raw_value_start + input[raw_value_start..].len()
            - input[raw_value_start..].trim_start().len();
        let quote = input[value_start..]
            .chars()
            .next()
            .filter(|character| matches!(character, '\'' | '"' | '`'));
        let secret_start = value_start + quote.map_or(0, char::len_utf8);
        let secret_end = quote.map_or_else(
            || {
                input[secret_start..]
                    .find(|character: char| {
                        character.is_whitespace() || matches!(character, ',' | '}' | ']')
                    })
                    .map_or(input.len(), |relative_end| secret_start + relative_end)
            },
            |quote| {
                input[secret_start..]
                    .find(quote)
                    .map_or(input.len(), |relative_end| secret_start + relative_end)
            },
        );
        if secret_end == secret_start {
            search_from = secret_start.saturating_add(1).min(input.len());
            continue;
        }
        input.replace_range(secret_start..secret_end, REDACTED);
        search_from = secret_start + REDACTED.len();
    }
    input
}

fn redact_url_userinfo(mut input: String) -> String {
    const REDACTED: &str = "[REDACTED]";
    let mut search_from = 0;
    while let Some(relative_scheme_end) = input[search_from..].find("://") {
        let authority_start = search_from + relative_scheme_end + 3;
        let authority_end = input[authority_start..]
            .find(|character: char| {
                character.is_whitespace() || matches!(character, '/' | '?' | '#')
            })
            .map_or(input.len(), |relative_end| authority_start + relative_end);
        let Some(relative_at) = input[authority_start..authority_end].rfind('@') else {
            search_from = authority_end;
            continue;
        };
        let userinfo_end = authority_start + relative_at;
        input.replace_range(authority_start..userinfo_end, REDACTED);
        search_from = authority_start + REDACTED.len() + 1;
    }
    input
}

pub(crate) fn append_bounded_log_bytes(buffer: &mut Vec<u8>, chunk: &[u8]) {
    if chunk.len() >= APP_SERVER_LOG_MAX_BYTES {
        buffer.clear();
        buffer.extend_from_slice(&chunk[chunk.len() - APP_SERVER_LOG_MAX_BYTES..]);
        return;
    }
    let overflow = buffer
        .len()
        .saturating_add(chunk.len())
        .saturating_sub(APP_SERVER_LOG_MAX_BYTES);
    if overflow > 0 {
        buffer.drain(..overflow.min(buffer.len()));
    }
    buffer.extend_from_slice(chunk);
}

pub(crate) fn app_server_log_tail_from_raw(
    stdout: &str,
    stderr: &str,
    gitlab_token: Option<&str>,
) -> AppServerLogTail {
    let redacted_stdout = redact_app_server_diagnostic_output(stdout, gitlab_token);
    let redacted_stderr = redact_app_server_diagnostic_output(stderr, gitlab_token);

    AppServerLogTail {
        stdout: tail_log_lines(&redacted_stdout),
        stderr: tail_log_lines(&redacted_stderr),
    }
}
