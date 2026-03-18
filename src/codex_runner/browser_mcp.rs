use super::*;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct BrowserLaunchConfig {
    pub(crate) image: String,
    pub(crate) entrypoint: Vec<String>,
    pub(crate) cmd: Vec<String>,
}

impl BrowserLaunchConfig {
    pub(crate) fn from_browser_mcp(browser_mcp: &BrowserMcpConfig) -> Self {
        let image = DockerCodexRunner::normalize_image_reference(&browser_mcp.browser_image);
        Self {
            image: image.clone(),
            entrypoint: browser_mcp.browser_entrypoint.clone(),
            cmd: browser_container_cmd(&image, &browser_mcp.browser_entrypoint, browser_mcp),
        }
    }

    pub(crate) fn entrypoint_display(&self) -> String {
        if self.entrypoint.is_empty() {
            "<image-default>".to_string()
        } else {
            format_command_for_log(&self.entrypoint)
        }
    }

    pub(crate) fn cmd_display(&self) -> String {
        if self.cmd.is_empty() {
            "<none>".to_string()
        } else {
            format_command_for_log(&self.cmd)
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct BrowserLogTail {
    pub(crate) stdout: Vec<String>,
    pub(crate) stderr: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct BrowserContainerStateSnapshot {
    pub(crate) status: Option<String>,
    pub(crate) running: Option<bool>,
    pub(crate) exit_code: Option<i64>,
    pub(crate) oom_killed: Option<bool>,
    pub(crate) error: Option<String>,
    pub(crate) started_at: Option<String>,
    pub(crate) finished_at: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct BrowserContainerDiagnostics {
    pub(crate) container_id: String,
    pub(crate) launch: BrowserLaunchConfig,
    pub(crate) state: Option<BrowserContainerStateSnapshot>,
    pub(crate) state_collection_error: Option<String>,
    pub(crate) log_tail: BrowserLogTail,
    pub(crate) log_collection_error: Option<String>,
}

impl BrowserContainerDiagnostics {
    pub(crate) fn format_context(&self) -> String {
        let mut lines = vec![
            "browser container diagnostics:".to_string(),
            format!("  id={}", self.container_id),
            format!(
                "  launch image={} entrypoint={} cmd={}",
                self.launch.image,
                self.launch.entrypoint_display(),
                self.launch.cmd_display()
            ),
        ];

        match (&self.state, &self.state_collection_error) {
            (Some(state), _) => lines.push(format!(
                "  state status={} running={} exit_code={} oom_killed={} started_at={} finished_at={} error={}",
                state.status.as_deref().unwrap_or("<unknown>"),
                state
                    .running
                    .map(|value| value.to_string())
                    .unwrap_or_else(|| "<unknown>".to_string()),
                state
                    .exit_code
                    .map(|value| value.to_string())
                    .unwrap_or_else(|| "<unknown>".to_string()),
                state
                    .oom_killed
                    .map(|value| value.to_string())
                    .unwrap_or_else(|| "<unknown>".to_string()),
                state.started_at.as_deref().unwrap_or("<unknown>"),
                state.finished_at.as_deref().unwrap_or("<unknown>"),
                state.error.as_deref().unwrap_or("<none>")
            )),
            (None, Some(err)) => lines.push(format!("  state unavailable: {err}")),
            (None, None) => lines.push("  state unavailable: <unknown>".to_string()),
        }

        match &self.log_collection_error {
            Some(err) => lines.push(format!("  log tail unavailable: {err}")),
            None => {
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
        }

        lines.join("\n")
    }
}

impl DockerCodexRunner {
    pub(crate) async fn collect_browser_container_diagnostics(
        &self,
        browser_container_id: &str,
        launch: &BrowserLaunchConfig,
    ) -> BrowserContainerDiagnostics {
        #[cfg(test)]
        if let RunnerRuntime::Fake(harness) = &self.runtime {
            return harness
                .collect_browser_container_diagnostics(browser_container_id, launch)
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
                browser_container_id,
                None::<bollard::query_parameters::InspectContainerOptions>,
            )
            .await
        {
            Ok(inspect) => (browser_container_state_snapshot(inspect), None),
            Err(err) => (
                None,
                Some(format!(
                    "{:#}",
                    anyhow!(err).context(format!(
                        "inspect docker browser container {}",
                        browser_container_id
                    ))
                )),
            ),
        };

        let (log_tail, log_collection_error) = match self
            .collect_browser_container_log_tail(browser_container_id)
            .await
        {
            Ok(log_tail) => (log_tail, None),
            Err(err) => (BrowserLogTail::default(), Some(format!("{err:#}"))),
        };

        BrowserContainerDiagnostics {
            container_id: browser_container_id.to_string(),
            launch: launch.clone(),
            state,
            state_collection_error,
            log_tail,
            log_collection_error,
        }
    }

    pub(crate) async fn collect_browser_container_log_tail(
        &self,
        browser_container_id: &str,
    ) -> Result<BrowserLogTail> {
        #[cfg(test)]
        let docker = match &self.runtime {
            RunnerRuntime::Docker { docker, .. } => docker,
            RunnerRuntime::Fake(_) => {
                bail!("fake runtime should not collect live browser logs directly");
            }
        };
        #[cfg(not(test))]
        let RunnerRuntime::Docker { docker, .. } = &self.runtime;
        let mut stdout = String::new();
        let mut stderr = String::new();
        let mut stream = docker.logs(
            browser_container_id,
            Some(
                LogsOptionsBuilder::default()
                    .follow(false)
                    .stdout(true)
                    .stderr(true)
                    .tail(BROWSER_CONTAINER_LOG_FETCH_TAIL)
                    .build(),
            ),
        );

        while let Some(message) = stream.next().await {
            match message.with_context(|| {
                format!(
                    "read docker browser container logs for {}",
                    browser_container_id
                )
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

        Ok(BrowserLogTail {
            stdout: tail_log_lines(&stdout),
            stderr: tail_log_lines(&stderr),
        })
    }

    pub(crate) async fn enrich_error_with_browser_diagnostics(
        &self,
        err: anyhow::Error,
        browser_container_id: Option<&str>,
        browser_mcp: Option<&BrowserMcpConfig>,
    ) -> anyhow::Error {
        let (Some(browser_container_id), Some(browser_mcp)) = (browser_container_id, browser_mcp)
        else {
            return err;
        };
        let launch = BrowserLaunchConfig::from_browser_mcp(browser_mcp);
        let diagnostics = self
            .collect_browser_container_diagnostics(browser_container_id, &launch)
            .await;
        let formatted = diagnostics.format_context();
        warn!(
            container_id = browser_container_id,
            diagnostics = %formatted,
            "browser container diagnostics captured"
        );
        err.context(formatted)
    }

    pub(crate) async fn wait_for_browser_container_ready(
        &self,
        browser_container_id: &str,
        launch: &BrowserLaunchConfig,
    ) -> Result<()> {
        info!(
            container_id = browser_container_id,
            expected_port = BROWSER_MCP_REMOTE_DEBUGGING_PORT,
            timeout_secs = BROWSER_CONTAINER_READY_TIMEOUT.as_secs(),
            "waiting for browser container readiness"
        );
        let deadline = Instant::now() + BROWSER_CONTAINER_READY_TIMEOUT;
        let mut running_since = None;
        loop {
            let diagnostics = self
                .collect_browser_container_diagnostics(browser_container_id, launch)
                .await;
            if browser_logs_report_ready(&diagnostics.log_tail, BROWSER_MCP_REMOTE_DEBUGGING_PORT) {
                info!(
                    container_id = browser_container_id,
                    expected_port = BROWSER_MCP_REMOTE_DEBUGGING_PORT,
                    "browser container reported DevTools readiness"
                );
                return Ok(());
            }
            if diagnostics.state.as_ref().and_then(|state| state.running) == Some(true) {
                let running_since_ref = running_since.get_or_insert_with(Instant::now);
                if running_since_ref.elapsed() >= BROWSER_CONTAINER_RUNNING_GRACE_PERIOD {
                    info!(
                        container_id = browser_container_id,
                        expected_port = BROWSER_MCP_REMOTE_DEBUGGING_PORT,
                        grace_period_secs = BROWSER_CONTAINER_RUNNING_GRACE_PERIOD.as_secs(),
                        "browser container stayed running without a DevTools log marker; continuing"
                    );
                    return Ok(());
                }
            } else {
                running_since = None;
            }
            if browser_container_has_exited(diagnostics.state.as_ref()) {
                let formatted = diagnostics.format_context();
                warn!(
                    container_id = browser_container_id,
                    diagnostics = %formatted,
                    "browser container exited before readiness"
                );
                return Err(anyhow!(
                    "browser container exited before reporting readiness on port {}",
                    BROWSER_MCP_REMOTE_DEBUGGING_PORT
                )
                .context(formatted));
            }
            if Instant::now() >= deadline {
                let formatted = diagnostics.format_context();
                warn!(
                    container_id = browser_container_id,
                    diagnostics = %formatted,
                    "browser container readiness timed out"
                );
                return Err(anyhow!(
                    "browser container did not report readiness on port {} within {} seconds",
                    BROWSER_MCP_REMOTE_DEBUGGING_PORT,
                    BROWSER_CONTAINER_READY_TIMEOUT.as_secs()
                )
                .context(formatted));
            }
            sleep(Duration::from_secs(1)).await;
        }
    }

    pub(crate) async fn start_browser_container(
        &self,
        browser_mcp: &BrowserMcpConfig,
        extra_hosts: Vec<String>,
    ) -> Result<String> {
        #[cfg(test)]
        let docker = match &self.runtime {
            RunnerRuntime::Docker { docker, .. } => docker,
            RunnerRuntime::Fake(_) => {
                bail!("fake runtime should start browser sidecars via start_app_server_container");
            }
        };
        #[cfg(not(test))]
        let RunnerRuntime::Docker { docker, .. } = &self.runtime;
        let launch = BrowserLaunchConfig::from_browser_mcp(browser_mcp);
        let image_ref = launch.image.clone();
        self.ensure_image_available(&image_ref).await?;
        let name = format!("{}{}", BROWSER_CONTAINER_NAME_PREFIX, Uuid::new_v4());
        let entrypoint_display = launch.entrypoint_display();
        let cmd_display = launch.cmd_display();
        info!(
            name = name.as_str(),
            image = image_ref.as_str(),
            entrypoint = entrypoint_display.as_str(),
            cmd = cmd_display.as_str(),
            expected_port = BROWSER_MCP_REMOTE_DEBUGGING_PORT,
            "starting browser container"
        );
        let config = ContainerCreateBody {
            image: Some(image_ref.clone()),
            entrypoint: (!launch.entrypoint.is_empty()).then(|| launch.entrypoint.clone()),
            cmd: (!launch.cmd.is_empty()).then(|| launch.cmd.clone()),
            labels: Some(Self::review_container_labels(&self.owner_id)),
            host_config: Some(HostConfig {
                auto_remove: Some(false),
                extra_hosts: (!extra_hosts.is_empty()).then_some(extra_hosts),
                ..Default::default()
            }),
            ..Default::default()
        };

        let create = docker
            .create_container(
                Some(CreateContainerOptionsBuilder::new().name(&name).build()),
                config,
            )
            .await
            .with_context(|| {
                format!(
                    "create docker browser container {} with image {}",
                    name, image_ref
                )
            })?;
        let id = create.id;
        let start_result = docker
            .start_container(&id, Some(StartContainerOptionsBuilder::new().build()))
            .await
            .with_context(|| format!("start docker browser container {}", id));
        if let Err(err) = start_result {
            let err = self
                .enrich_error_with_browser_diagnostics(err, Some(&id), Some(browser_mcp))
                .await;
            self.remove_container_best_effort(&id).await;
            return Err(err);
        }
        info!(
            container_id = id.as_str(),
            image = image_ref.as_str(),
            entrypoint = entrypoint_display.as_str(),
            cmd = cmd_display.as_str(),
            expected_port = BROWSER_MCP_REMOTE_DEBUGGING_PORT,
            "started browser container"
        );
        if let Err(err) = self.wait_for_browser_container_ready(&id, &launch).await {
            self.remove_container_best_effort(&id).await;
            return Err(err);
        }
        Ok(id)
    }
}

pub(crate) fn browser_container_cmd(
    image: &str,
    configured_entrypoint: &[String],
    browser_mcp: &BrowserMcpConfig,
) -> Vec<String> {
    if uses_headless_shell_wrapper(image, configured_entrypoint) {
        // chromedp/headless-shell's image-default /headless-shell/run.sh appends its argv to a
        // wrapper that keeps the browser on 9223 and exposes 9222 externally via socat. Passing
        // only browser_args here preserves that contract; injecting our own debug flags conflicts
        // with the wrapper and breaks the externally reachable 9222 endpoint.
        return browser_mcp.browser_args.clone();
    }

    let mut cmd = vec![
        "--no-sandbox".to_string(),
        "--remote-debugging-address=0.0.0.0".to_string(),
        format!(
            "--remote-debugging-port={}",
            BROWSER_MCP_REMOTE_DEBUGGING_PORT
        ),
        "--disable-gpu".to_string(),
        "--enable-unsafe-swiftshader".to_string(),
    ];
    cmd.extend(browser_mcp.browser_args.clone());
    cmd
}

pub(crate) fn uses_headless_shell_wrapper(image: &str, configured_entrypoint: &[String]) -> bool {
    configured_entrypoint.is_empty() && is_headless_shell_image(image)
}

pub(crate) fn is_headless_shell_image(image: &str) -> bool {
    let repository = image_repository(image);
    repository == "chromedp/headless-shell" || repository.ends_with("/chromedp/headless-shell")
}

pub(crate) fn image_repository(image: &str) -> &str {
    let image = image.split('@').next().unwrap_or(image);
    match image.rsplit_once(':') {
        Some((repository, suffix)) if !suffix.contains('/') => repository,
        _ => image,
    }
}

pub(crate) fn tail_log_lines(text: &str) -> Vec<String> {
    let mut lines = text
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(|line| truncate_log_line(line, BROWSER_CONTAINER_LOG_LINE_MAX_CHARS))
        .collect::<Vec<_>>();
    if lines.len() > BROWSER_CONTAINER_LOG_LINE_LIMIT {
        lines = lines[lines.len() - BROWSER_CONTAINER_LOG_LINE_LIMIT..].to_vec();
    }
    lines
}

pub(crate) fn truncate_log_line(line: &str, max_chars: usize) -> String {
    let mut truncated = line.chars().take(max_chars).collect::<String>();
    if line.chars().count() > max_chars {
        truncated.push_str("...");
    }
    truncated
}

pub(crate) fn browser_logs_report_ready(log_tail: &BrowserLogTail, expected_port: u16) -> bool {
    log_tail
        .stdout
        .iter()
        .chain(log_tail.stderr.iter())
        .filter_map(|line| extract_devtools_port(line))
        .any(|port| port == expected_port)
}

pub(crate) fn extract_devtools_port(line: &str) -> Option<u16> {
    let marker = "DevTools listening on ";
    let url = line.split_once(marker)?.1.split_whitespace().next()?;
    Url::parse(url).ok()?.port_or_known_default()
}

pub(crate) fn browser_container_has_exited(state: Option<&BrowserContainerStateSnapshot>) -> bool {
    let Some(state) = state else {
        return false;
    };
    matches!(state.status.as_deref(), Some("exited" | "dead"))
}

pub(crate) fn browser_container_state_snapshot(
    inspect: ContainerInspectResponse,
) -> Option<BrowserContainerStateSnapshot> {
    let state = inspect.state?;
    Some(BrowserContainerStateSnapshot {
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
