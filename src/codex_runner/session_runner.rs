use super::{
    AppServerClient, AuthAccount, BrowserMcpConfig, DockerCodexRunner, Duration,
    PreparedGitLabDiscoveryMcp, RegisteredGitLabDiscoverySession, Result, StartedAppServer, Value,
    anyhow, timeout, warn,
};
use crate::feature_flags::FeatureFlagSnapshot;
use std::collections::BTreeMap;
use std::future::Future;

#[derive(Debug, Clone)]
pub(crate) struct PreparedRunnerSessionComponents {
    pub(crate) browser_mcp: Option<BrowserMcpConfig>,
    pub(crate) gitlab_discovery_mcp: Option<PreparedGitLabDiscoveryMcp>,
    pub(crate) effective_mcp_server_overrides: BTreeMap<String, bool>,
    pub(crate) gitlab_discovery_extra_hosts: Vec<String>,
}

impl PreparedRunnerSessionComponents {
    pub(crate) fn extra_writable_roots(&self) -> Vec<String> {
        self.gitlab_discovery_mcp
            .as_ref()
            .map(|prepared| vec![prepared.runtime_config.clone_root.clone()])
            .unwrap_or_default()
    }
}

#[derive(Debug, Clone)]
pub(crate) struct RunnerSessionConfig {
    pub(crate) script: String,
    pub(crate) auth_account: AuthAccount,
    pub(crate) run_history_id: Option<i64>,
    pub(crate) browser_mcp: Option<BrowserMcpConfig>,
    pub(crate) gitlab_discovery_mcp: Option<PreparedGitLabDiscoveryMcp>,
    pub(crate) gitlab_discovery_extra_hosts: Vec<String>,
}

pub(crate) struct RunnerSession {
    pub(crate) container_id: String,
    pub(crate) browser_container_id: Option<String>,
    pub(crate) client: AppServerClient,
    pub(crate) auth_account_name: String,
    pub(crate) run_history_id: Option<i64>,
    gitlab_discovery_mcp: Option<PreparedGitLabDiscoveryMcp>,
    gitlab_discovery_session: Option<RegisteredGitLabDiscoverySession>,
}

#[derive(Debug, Clone)]
pub(crate) struct StartedReviewTurn {
    pub(crate) turn_id: String,
    pub(crate) review_thread_id: String,
}

impl RunnerSession {
    fn gitlab_discovery_server_name(&self) -> Option<&str> {
        self.gitlab_discovery_mcp
            .as_ref()
            .map(|prepared| prepared.runtime_config.server_name.as_str())
    }
}

impl DockerCodexRunner {
    pub(crate) async fn prepare_runner_session_components(
        &self,
        run_history_id: Option<i64>,
        feature_flags: &FeatureFlagSnapshot,
        project_path: &str,
        mcp_server_overrides: &BTreeMap<String, bool>,
        allow_gitlab_discovery: bool,
    ) -> PreparedRunnerSessionComponents {
        let browser_mcp = self.effective_browser_mcp(mcp_server_overrides).cloned();
        let gitlab_discovery_mcp = if allow_gitlab_discovery {
            self.prepare_gitlab_discovery_mcp(project_path, feature_flags, mcp_server_overrides)
        } else {
            None
        };
        self.sync_effective_feature_flags(
            run_history_id,
            feature_flags,
            gitlab_discovery_mcp.is_some(),
        )
        .await;
        let effective_mcp_server_overrides = self.effective_mcp_server_overrides_for_run(
            mcp_server_overrides,
            gitlab_discovery_mcp.is_some(),
        );
        let gitlab_discovery_extra_hosts = gitlab_discovery_mcp
            .as_ref()
            .map(|prepared| self.gitlab_discovery_extra_hosts(&prepared.runtime_config))
            .unwrap_or_default();
        PreparedRunnerSessionComponents {
            browser_mcp,
            gitlab_discovery_mcp,
            effective_mcp_server_overrides,
            gitlab_discovery_extra_hosts,
        }
    }

    pub(crate) async fn start_runner_session(
        &self,
        config: RunnerSessionConfig,
    ) -> Result<RunnerSession> {
        let StartedAppServer {
            container_id,
            browser_container_id,
            client,
        } = self
            .start_app_server_container(
                config.script,
                &config.auth_account.auth_host_path,
                Vec::new(),
                Vec::new(),
                config.browser_mcp.as_ref(),
                config.gitlab_discovery_extra_hosts,
            )
            .await?;

        let mut session = RunnerSession {
            container_id,
            browser_container_id,
            client,
            auth_account_name: config.auth_account.name,
            run_history_id: config.run_history_id,
            // Browser diagnostics use browser container id + launch config at call sites.
            gitlab_discovery_mcp: config.gitlab_discovery_mcp,
            gitlab_discovery_session: None,
        };

        session.gitlab_discovery_session = match self
            .register_gitlab_discovery_session(
                session.gitlab_discovery_mcp.as_ref(),
                &session.container_id,
                session
                    .browser_container_id
                    .as_deref()
                    .unwrap_or(&session.container_id),
                session.run_history_id,
            )
            .await
        {
            Ok(binding) => binding,
            Err(err) => {
                warn!(
                    container_id = session.container_id.as_str(),
                    error = %err,
                    "failed to register gitlab discovery MCP session"
                );
                self.append_gitlab_discovery_mcp_startup_failure(
                    session.run_history_id,
                    session
                        .gitlab_discovery_mcp
                        .as_ref()
                        .map_or("<unknown>", |prepared| {
                            prepared.runtime_config.advertise_url.as_str()
                        }),
                    "failed to register MCP session binding",
                )
                .await;
                None
            }
        };

        self.probe_gitlab_discovery_mcp_endpoint(
            session.gitlab_discovery_mcp.as_ref(),
            &session.container_id,
            session.gitlab_discovery_session.as_ref(),
            session.run_history_id,
        )
        .await;

        Ok(session)
    }

    pub(crate) async fn close_runner_session(&self, session: RunnerSession) {
        self.unregister_gitlab_discovery_session(session.gitlab_discovery_session.as_ref())
            .await;
        self.cleanup_app_server_containers(
            &session.container_id,
            session.browser_container_id.as_deref(),
        )
        .await;
    }

    pub(crate) async fn run_session_with_timeout<T, Fut>(
        &self,
        browser_container_id: Option<&str>,
        browser_mcp: Option<&BrowserMcpConfig>,
        timeout_duration: Duration,
        timeout_error: &'static str,
        future: Fut,
    ) -> Result<T>
    where
        Fut: Future<Output = Result<T>>,
    {
        match timeout(timeout_duration, future).await {
            Ok(Ok(value)) => Ok(value),
            Ok(Err(err)) => Err(self
                .enrich_error_with_browser_diagnostics(err, browser_container_id, browser_mcp)
                .await),
            Err(_) => Err(self
                .enrich_error_with_browser_diagnostics(
                    anyhow!(timeout_error),
                    browser_container_id,
                    browser_mcp,
                )
                .await),
        }
    }

    pub(crate) async fn session_start_thread(
        &self,
        session: &mut RunnerSession,
        params: Value,
        missing_thread_id_error: &'static str,
    ) -> Result<String> {
        let response = session.client.request("thread/start", params).await?;
        response
            .get("thread")
            .and_then(|thread| thread.get("id"))
            .and_then(|id| id.as_str())
            .map(ToOwned::to_owned)
            .ok_or_else(|| anyhow!(missing_thread_id_error))
    }

    pub(crate) async fn session_start_turn(
        &self,
        session: &mut RunnerSession,
        params: Value,
        missing_turn_id_error: &'static str,
    ) -> Result<String> {
        let response = session.client.request("turn/start", params).await?;
        response
            .get("turn")
            .and_then(|turn| turn.get("id"))
            .and_then(|id| id.as_str())
            .map(ToOwned::to_owned)
            .ok_or_else(|| anyhow!(missing_turn_id_error))
    }

    pub(crate) async fn session_start_review(
        &self,
        session: &mut RunnerSession,
        thread_id: &str,
        target: Value,
    ) -> Result<StartedReviewTurn> {
        let response = session
            .client
            .request(
                "review/start",
                serde_json::json!({
                    "threadId": thread_id,
                    "delivery": "inline",
                    "target": target,
                }),
            )
            .await?;
        let turn_id = response
            .get("turn")
            .and_then(|turn| turn.get("id"))
            .and_then(|id| id.as_str())
            .map(ToOwned::to_owned)
            .ok_or_else(|| anyhow!("review/start missing turn id"))?;
        let review_thread_id = response
            .get("reviewThreadId")
            .and_then(|id| id.as_str())
            .unwrap_or(thread_id)
            .to_string();
        Ok(StartedReviewTurn {
            turn_id,
            review_thread_id,
        })
    }

    pub(crate) async fn session_stream_turn_message(
        &self,
        session: &mut RunnerSession,
        thread_id: &str,
        turn_id: &str,
    ) -> Result<String> {
        let run_history_id = session.run_history_id;
        let gitlab_discovery_server_name = session
            .gitlab_discovery_server_name()
            .map(ToOwned::to_owned);
        session
            .client
            .stream_turn_message(
                thread_id,
                turn_id,
                gitlab_discovery_server_name.as_deref(),
                |events| async move {
                    self.append_run_history_events(run_history_id, &events)
                        .await;
                },
                || async move {
                    self.clear_gitlab_discovery_mcp_startup_failure(run_history_id)
                        .await;
                },
            )
            .await
    }

    pub(crate) async fn session_stream_review(
        &self,
        session: &mut RunnerSession,
        review_thread_id: &str,
        turn_id: &str,
    ) -> Result<String> {
        let run_history_id = session.run_history_id;
        let gitlab_discovery_server_name = session
            .gitlab_discovery_server_name()
            .map(ToOwned::to_owned);
        session
            .client
            .stream_review(
                review_thread_id,
                turn_id,
                gitlab_discovery_server_name.as_deref(),
                |events| async move {
                    self.append_run_history_events(run_history_id, &events)
                        .await;
                },
                || async move {
                    self.clear_gitlab_discovery_mcp_startup_failure(run_history_id)
                        .await;
                },
            )
            .await
    }
}
