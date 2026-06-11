use super::{
    ContainerInspectResponse, Context, DockerCodexRunner, LogOutput, LogsOptionsBuilder, Result,
    RunnerRuntime, StreamExt, anyhow, warn,
};
use crate::codex_runner::browser_mcp::tail_log_lines;
use crate::composer_install::redact_composer_related_output;
#[cfg(test)]
use anyhow::bail;

const SAFE_APP_SERVER_STDOUT_PREFIXES: &[&str] = &[
    "codex-runner:",
    "codex-runner-warn:",
    "codex-runner-error:",
    "codex-install:",
    "codex-install-error:",
];

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct AppServerLogTail {
    pub(crate) stdout: Vec<String>,
    pub(crate) stdout_redacted_line_count: usize,
    pub(crate) stderr: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AppServerContainerStateSnapshot {
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
}

impl AppServerContainerDiagnostics {
    pub(crate) fn format_context(&self) -> String {
        let mut lines = vec![
            "app-server container diagnostics:".to_string(),
            format!("  id={}", self.container_id),
        ];

        match (&self.state, &self.state_collection_error) {
            (Some(state), _) => lines.push(format!(
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
            )),
            (None, Some(err)) => lines.push(format!("  state unavailable: {err}")),
            (None, None) => lines.push("  state unavailable: <unknown>".to_string()),
        }

        if let Some(err) = &self.log_collection_error {
            lines.push(format!("  log tail unavailable: {err}"));
        } else {
            if self.log_tail.stdout.is_empty() && self.log_tail.stdout_redacted_line_count == 0 {
                lines.push("  stdout tail: <empty>".to_string());
            } else if self.log_tail.stdout.is_empty() {
                lines.push(format!(
                    "  stdout tail: {}",
                    redacted_stdout_marker(self.log_tail.stdout_redacted_line_count)
                ));
            } else {
                lines.push("  stdout tail:".to_string());
                for line in &self.log_tail.stdout {
                    lines.push(format!("    {line}"));
                }
                if self.log_tail.stdout_redacted_line_count > 0 {
                    lines.push(format!(
                        "    {}",
                        redacted_stdout_marker(self.log_tail.stdout_redacted_line_count)
                    ));
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
        let (state, state_collection_error) = match docker
            .inspect_container(
                app_server_container_id,
                None::<bollard::query_parameters::InspectContainerOptions>,
            )
            .await
        {
            Ok(inspect) => (app_server_container_state_snapshot(inspect), None),
            Err(err) => (
                None,
                Some(format!(
                    "{:#}",
                    anyhow!(err).context(format!(
                        "inspect docker app-server container {app_server_container_id}"
                    ))
                )),
            ),
        };

        let (log_tail, log_collection_error) = match self
            .collect_app_server_container_log_tail(app_server_container_id)
            .await
        {
            Ok(log_tail) => (log_tail, None),
            Err(err) => (AppServerLogTail::default(), Some(format!("{err:#}"))),
        };

        AppServerContainerDiagnostics {
            container_id: app_server_container_id.to_string(),
            state,
            state_collection_error,
            log_tail,
            log_collection_error,
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
        let mut stdout = String::new();
        let mut stderr = String::new();
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
                    stdout.push_str(String::from_utf8_lossy(&message).as_ref());
                }
                LogOutput::StdErr { message } => {
                    stderr.push_str(String::from_utf8_lossy(&message).as_ref());
                }
                LogOutput::StdIn { .. } => {}
            }
        }

        Ok(app_server_log_tail_from_raw(
            &stdout,
            &stderr,
            Some(&self.gitlab_token),
        ))
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
        err.context(formatted)
    }
}

pub(crate) fn app_server_container_state_snapshot(
    inspect: ContainerInspectResponse,
) -> Option<AppServerContainerStateSnapshot> {
    let state = inspect.state?;
    Some(AppServerContainerStateSnapshot {
        status: state
            .status
            .map(|value| format!("{value:?}").to_ascii_lowercase()),
        running: state.running,
        exit_code: state.exit_code,
        oom_killed: state.oom_killed,
        error: state.error.filter(|value| !value.trim().is_empty()),
        started_at: state.started_at.filter(|value| !value.trim().is_empty()),
        finished_at: state.finished_at.filter(|value| !value.trim().is_empty()),
    })
}

pub(crate) fn app_server_log_tail_from_raw(
    stdout: &str,
    stderr: &str,
    gitlab_token: Option<&str>,
) -> AppServerLogTail {
    let redacted_stdout = redact_composer_related_output(stdout, gitlab_token, None);
    let mut safe_stdout = Vec::new();
    let mut redacted_stdout_count = 0;
    for line in tail_log_lines(&redacted_stdout) {
        if is_safe_app_server_stdout_line(&line) {
            safe_stdout.push(line);
        } else {
            redacted_stdout_count += 1;
        }
    }

    let redacted_stderr = redact_composer_related_output(stderr, gitlab_token, None);

    AppServerLogTail {
        stdout: safe_stdout,
        stdout_redacted_line_count: redacted_stdout_count,
        stderr: tail_log_lines(&redacted_stderr),
    }
}

fn is_safe_app_server_stdout_line(line: &str) -> bool {
    SAFE_APP_SERVER_STDOUT_PREFIXES
        .iter()
        .any(|prefix| line.starts_with(prefix))
}

fn redacted_stdout_marker(line_count: usize) -> String {
    format!("<redacted; {line_count} protocol/unclassified line(s)>")
}
