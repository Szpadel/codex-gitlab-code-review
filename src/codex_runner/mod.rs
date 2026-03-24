use crate::config::{
    BROWSER_MCP_REMOTE_DEBUGGING_PORT, BrowserMcpConfig, CodexConfig, DockerConfig,
};
use crate::docker_utils::{connect_docker, ensure_image, normalize_image_reference};
use crate::feature_flags::FeatureFlagSnapshot;
use crate::gitlab::MergeRequest;
use crate::gitlab_discovery_mcp::{GitLabDiscoveryMcpService, ResolvedGitLabDiscoveryAllowList};
use crate::gitlab_links::GitLabMarkdownImageUpload;
use crate::review_lane::ReviewLane;
use crate::review_prompt_templates::{
    append_additional_review_instructions, build_base_branch_review_prompt,
    build_commit_review_prompt, upstream_review_prompt_source_commit,
    upstream_review_prompt_source_path,
};
use crate::state::{NewRunHistoryEvent, ReviewStateStore, RunHistorySessionUpdate};
use anyhow::{Context, Result, anyhow, bail};
use async_trait::async_trait;
use bollard::Docker;
use bollard::container::LogOutput;
use bollard::exec::{StartExecOptions, StartExecResults};
use bollard::models::{ContainerCreateBody, ContainerInspectResponse, ExecConfig, HostConfig};
use bollard::query_parameters::{
    AttachContainerOptionsBuilder, CreateContainerOptionsBuilder, ListContainersOptionsBuilder,
    LogsOptionsBuilder, RemoveContainerOptionsBuilder, StartContainerOptionsBuilder,
};
use chrono::{DateTime, Duration as ChronoDuration, SecondsFormat, Utc};
use futures::{FutureExt, StreamExt, future::BoxFuture, future::Shared};
use serde::Deserialize;
use serde_json::{Value, json};
use std::cell::RefCell;
use std::collections::{BTreeMap, HashMap, VecDeque};
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tokio::sync::Notify;
use tokio::time::{Instant, sleep, timeout};
use tracing::{debug, info, warn};
use url::Url;
use uuid::Uuid;

mod app_server;
mod auth;
mod browser_mcp;
mod composer;
mod container;
mod gitlab_discovery;
mod mention_flow;
mod mention_inputs;
mod review_flow;
mod scripts;
#[cfg(test)]
pub(crate) mod test_support;

use self::app_server::*;
use self::auth::*;
use self::container::*;
use self::gitlab_discovery::*;
use self::review_flow::*;
use self::scripts::*;

#[derive(Debug, Clone)]
pub struct ReviewContext {
    pub lane: ReviewLane,
    pub repo: String,
    pub project_path: String,
    pub mr: MergeRequest,
    pub head_sha: String,
    pub feature_flags: FeatureFlagSnapshot,
    pub additional_developer_instructions: Option<String>,
    pub min_confidence_score: Option<f32>,
    pub security_context_ttl_seconds: Option<u64>,
    pub run_history_id: Option<i64>,
}

#[derive(Debug, Clone)]
pub struct MentionCommandContext {
    pub repo: String,
    pub project_path: String,
    pub(crate) discussion_project_path: String,
    pub mr: MergeRequest,
    pub head_sha: String,
    pub discussion_id: String,
    pub trigger_note_id: u64,
    pub requester_name: String,
    pub requester_email: String,
    pub additional_developer_instructions: Option<String>,
    pub prompt: String,
    pub(crate) image_uploads: Vec<GitLabMarkdownImageUpload>,
    pub feature_flags: FeatureFlagSnapshot,
    pub run_history_id: Option<i64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReviewLineRange {
    pub start: usize,
    pub end: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReviewCodeLocation {
    pub absolute_file_path: String,
    pub line_range: ReviewLineRange,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ReviewFinding {
    pub title: String,
    pub body: String,
    pub confidence_score: Option<f32>,
    pub priority: Option<u8>,
    pub code_location: ReviewCodeLocation,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ReviewComment {
    pub summary: String,
    pub overall_explanation: Option<String>,
    pub overall_confidence_score: Option<f32>,
    pub findings: Vec<ReviewFinding>,
    pub body: String,
}

#[derive(Debug, Clone)]
pub enum CodexResult {
    Pass { summary: String },
    Comment(ReviewComment),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MentionCommandStatus {
    Committed,
    NoChanges,
}

#[derive(Debug, Clone)]
pub struct MentionCommandResult {
    pub status: MentionCommandStatus,
    pub commit_sha: Option<String>,
    pub reply_message: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) struct SecurityContextBuildKey {
    pub(crate) repo: String,
    pub(crate) base_branch: String,
    pub(crate) base_head_sha: String,
    pub(crate) prompt_version: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SecurityContextBuildStatus {
    Running,
    Finished,
}

#[derive(Debug)]
pub(crate) struct SecurityContextBuildSlot {
    status: Mutex<SecurityContextBuildStatus>,
    notify: Notify,
}

impl SecurityContextBuildSlot {
    fn new_running() -> Self {
        Self {
            status: Mutex::new(SecurityContextBuildStatus::Running),
            notify: Notify::new(),
        }
    }

    fn finish(&self) {
        let mut status = self
            .status
            .lock()
            .expect("security context build slot lock poisoned");
        *status = SecurityContextBuildStatus::Finished;
        drop(status);
        self.notify.notify_waiters();
    }

    async fn wait(&self) {
        loop {
            let notified = self.notify.notified();
            {
                let status = self
                    .status
                    .lock()
                    .expect("security context build slot lock poisoned");
                if *status == SecurityContextBuildStatus::Finished {
                    return;
                }
            }
            notified.await;
        }
    }
}

enum SecurityContextBuildRegistration {
    Leader(SecurityContextBuildCompletionGuard),
    Follower(Arc<SecurityContextBuildSlot>),
}

pub(crate) struct SecurityContextBuildCompletionGuard {
    builds: Arc<Mutex<HashMap<SecurityContextBuildKey, Arc<SecurityContextBuildSlot>>>>,
    key: SecurityContextBuildKey,
    slot: Arc<SecurityContextBuildSlot>,
    completed: bool,
}

impl SecurityContextBuildCompletionGuard {
    fn finish_build(&self) {
        self.slot.finish();
        let mut builds = self
            .builds
            .lock()
            .expect("security context build map lock poisoned");
        if builds
            .get(&self.key)
            .is_some_and(|current| Arc::ptr_eq(current, &self.slot))
        {
            builds.remove(&self.key);
        }
    }

    fn complete(mut self) {
        self.finish_build();
        self.completed = true;
    }
}

impl Drop for SecurityContextBuildCompletionGuard {
    fn drop(&mut self) {
        if !self.completed {
            self.finish_build();
            self.completed = true;
        }
    }
}

const REVIEW_CONTAINER_NAME_PREFIX: &str = "codex-review-";
const BROWSER_CONTAINER_NAME_PREFIX: &str = "codex-browser-";
const REVIEW_OWNER_LABEL_KEY: &str = "codex.gitlab.review.owner";
const PRIMARY_AUTH_ACCOUNT_NAME: &str = "primary";
const BROWSER_CONTAINER_READY_TIMEOUT: Duration = Duration::from_secs(30);
const BROWSER_CONTAINER_RUNNING_GRACE_PERIOD: Duration = Duration::from_secs(10);
const BROWSER_CONTAINER_LOG_FETCH_TAIL: &str = "50";
const BROWSER_CONTAINER_LOG_LINE_LIMIT: usize = 12;
const BROWSER_CONTAINER_LOG_LINE_MAX_CHARS: usize = 240;
pub(crate) const PRIMARY_REPO_ROOT: &str = "/work/repo";

pub(crate) fn repo_checkout_root(project_path: &str) -> String {
    let trimmed = project_path.trim().trim_matches('/');
    if trimmed.is_empty() {
        PRIMARY_REPO_ROOT.to_string()
    } else {
        format!("{PRIMARY_REPO_ROOT}/{trimmed}")
    }
}

pub(crate) struct StartedAppServer {
    container_id: String,
    browser_container_id: Option<String>,
    client: AppServerClient,
}

enum RunnerRuntime {
    Docker {
        docker: Docker,
        image_pulls: Mutex<HashMap<String, InFlightImagePull>>,
        next_image_pull_id: AtomicU64,
    },
    #[cfg(test)]
    Fake(Arc<dyn test_support::RunnerHarness>),
}

#[async_trait]
pub trait CodexRunner: Send + Sync {
    async fn warm_up_images(&self) -> Result<()> {
        Ok(())
    }

    async fn run_review(&self, ctx: ReviewContext) -> Result<CodexResult>;

    async fn run_mention_command(
        &self,
        _ctx: MentionCommandContext,
    ) -> Result<MentionCommandResult> {
        bail!("mention command execution is not implemented by this runner")
    }

    async fn stop_active_reviews(&self) -> Result<()> {
        Ok(())
    }

    async fn read_thread(&self, _account_name: &str, _thread_id: &str) -> Result<Value> {
        bail!("thread history is not implemented by this runner")
    }
}

pub struct DockerCodexRunner {
    runtime: RunnerRuntime,
    security_context_builds:
        Arc<Mutex<HashMap<SecurityContextBuildKey, Arc<SecurityContextBuildSlot>>>>,
    codex: CodexConfig,
    gitlab_discovery_mcp: Option<Arc<dyn GitLabDiscoveryHandle>>,
    mention_commands_active: bool,
    review_additional_developer_instructions: Option<String>,
    git_base: Url,
    gitlab_token: String,
    log_all_json: bool,
    owner_id: String,
    state: Arc<ReviewStateStore>,
    auth_accounts: Vec<AuthAccount>,
}

#[derive(Debug, Clone)]
pub struct RunnerRuntimeOptions {
    pub gitlab_token: String,
    pub log_all_json: bool,
    pub owner_id: String,
    pub mention_commands_active: bool,
    pub review_additional_developer_instructions: Option<String>,
}

impl DockerCodexRunner {
    fn register_security_context_build(
        &self,
        key: SecurityContextBuildKey,
    ) -> SecurityContextBuildRegistration {
        let mut builds = self
            .security_context_builds
            .lock()
            .expect("security context build map lock poisoned");
        if let Some(slot) = builds.get(&key) {
            return SecurityContextBuildRegistration::Follower(Arc::clone(slot));
        }
        let slot = Arc::new(SecurityContextBuildSlot::new_running());
        builds.insert(key.clone(), Arc::clone(&slot));
        SecurityContextBuildRegistration::Leader(SecurityContextBuildCompletionGuard {
            builds: Arc::clone(&self.security_context_builds),
            key,
            slot,
            completed: false,
        })
    }

    async fn update_run_history_session(
        &self,
        run_history_id: Option<i64>,
        update: RunHistorySessionUpdate,
    ) {
        let Some(run_history_id) = run_history_id else {
            return;
        };
        if let Err(err) = self
            .state
            .update_run_history_session(run_history_id, update)
            .await
        {
            warn!(
                run_history_id,
                error = %err,
                "failed to update run history session metadata"
            );
        }
    }

    async fn append_run_history_events(
        &self,
        run_history_id: Option<i64>,
        events: &[NewRunHistoryEvent],
    ) {
        let Some(run_history_id) = run_history_id else {
            return;
        };
        if events.is_empty() {
            return;
        }
        if let Err(err) = self
            .state
            .append_run_history_events(run_history_id, events)
            .await
        {
            warn!(
                run_history_id,
                error = %format!("{err:#}"),
                "failed to append run history events"
            );
            // Sticky on purpose: a failed batch means this run's persisted transcript may have
            // permanent gaps because we do not replay already-consumed notifications.
            if let Err(mark_err) = self
                .state
                .mark_run_history_events_incomplete(run_history_id)
                .await
            {
                warn!(
                    run_history_id,
                    error = %format!("{mark_err:#}"),
                    "failed to mark run history events incomplete"
                );
            }
        }
    }

    async fn replace_run_history_events_for_turn(
        &self,
        run_history_id: Option<i64>,
        turn_id: &str,
        events: &[NewRunHistoryEvent],
    ) {
        let Some(run_history_id) = run_history_id else {
            return;
        };
        if let Err(err) = self
            .state
            .replace_run_history_events_for_turn(run_history_id, turn_id, events)
            .await
        {
            warn!(
                run_history_id,
                turn_id,
                error = %format!("{err:#}"),
                "failed to rewrite run history events for turn"
            );
            if let Err(mark_err) = self
                .state
                .mark_run_history_events_incomplete(run_history_id)
                .await
            {
                warn!(
                    run_history_id,
                    error = %format!("{mark_err:#}"),
                    "failed to mark run history events incomplete after turn rewrite error"
                );
            }
        }
    }

    pub fn new(
        docker_cfg: DockerConfig,
        codex: CodexConfig,
        git_base: Url,
        state: Arc<ReviewStateStore>,
        gitlab_discovery_mcp: Option<Arc<GitLabDiscoveryMcpService>>,
        runtime: RunnerRuntimeOptions,
    ) -> Result<Self> {
        let docker = connect_docker(&docker_cfg)?;
        let auth_accounts = Self::build_auth_accounts(&codex);
        Ok(Self {
            runtime: RunnerRuntime::Docker {
                docker,
                image_pulls: Mutex::new(HashMap::new()),
                next_image_pull_id: AtomicU64::new(1),
            },
            security_context_builds: Arc::new(Mutex::new(HashMap::new())),
            codex,
            gitlab_discovery_mcp: gitlab_discovery_mcp.map(|service| {
                let handle: Arc<dyn GitLabDiscoveryHandle> = service;
                handle
            }),
            mention_commands_active: runtime.mention_commands_active,
            review_additional_developer_instructions: runtime
                .review_additional_developer_instructions,
            git_base,
            gitlab_token: runtime.gitlab_token,
            log_all_json: runtime.log_all_json,
            owner_id: runtime.owner_id,
            state,
            auth_accounts,
        })
    }

    #[cfg(test)]
    pub(crate) fn new_with_test_runtime(
        codex: CodexConfig,
        git_base: Url,
        state: Arc<ReviewStateStore>,
        gitlab_discovery_mcp: Option<Arc<dyn GitLabDiscoveryHandle>>,
        runtime: RunnerRuntimeOptions,
        harness: Arc<dyn test_support::RunnerHarness>,
    ) -> Self {
        let auth_accounts = Self::build_auth_accounts(&codex);
        Self {
            runtime: RunnerRuntime::Fake(harness),
            security_context_builds: Arc::new(Mutex::new(HashMap::new())),
            codex,
            gitlab_discovery_mcp,
            mention_commands_active: runtime.mention_commands_active,
            review_additional_developer_instructions: runtime
                .review_additional_developer_instructions,
            git_base,
            gitlab_token: runtime.gitlab_token,
            log_all_json: runtime.log_all_json,
            owner_id: runtime.owner_id,
            state,
            auth_accounts,
        }
    }
}

impl DockerCodexRunner {
    fn sandbox_mode_value(&self) -> &'static str {
        match self.codex.exec_sandbox.as_str() {
            "read-only" => "read-only",
            "workspace-write" => "workspace-write",
            _ => "danger-full-access",
        }
    }

    fn thread_start_params(
        &self,
        cwd: &str,
        developer_instructions: Option<String>,
        extra_writable_roots: &[String],
    ) -> Value {
        let mut params = json!({
            "cwd": cwd,
            "approvalPolicy": "never",
            "sandbox": self.sandbox_mode_value(),
            "persistExtendedHistory": true,
        });
        if let Some(developer_instructions) = developer_instructions {
            params["developerInstructions"] = Value::String(developer_instructions);
        }
        if self.sandbox_mode_value() == "workspace-write" && !extra_writable_roots.is_empty() {
            let mut writable_roots = vec![cwd.to_string()];
            writable_roots.extend(extra_writable_roots.iter().cloned());
            writable_roots.sort();
            writable_roots.dedup();
            // Codex strips *TOKEN*, *SECRET*, and *KEY* variables out of
            // agent-spawned tool environments, so keeping workspace-write
            // network access enabled does not expose the runner's GitLab token.
            params["config"] = json!({
                "sandbox_workspace_write": {
                    "writable_roots": writable_roots,
                    "network_access": true,
                    "exclude_tmpdir_env_var": false,
                    "exclude_slash_tmp": false,
                }
            });
        }
        params
    }

    fn auth_account_by_name(&self, account_name: &str) -> Option<&AuthAccount> {
        self.auth_accounts
            .iter()
            .find(|account| account.name == account_name)
    }

    async fn read_thread_with_account(
        &self,
        account: &AuthAccount,
        thread_id: &str,
    ) -> Result<Value> {
        let script = Self::build_history_reader_script(&self.codex.auth_mount_path);
        let StartedAppServer {
            container_id,
            browser_container_id,
            mut client,
        } = self
            .start_app_server_container(
                script,
                &account.auth_host_path,
                Vec::new(),
                Vec::new(),
                None,
                Vec::new(),
            )
            .await?;

        let result = timeout(Duration::from_secs(self.codex.timeout_seconds), async {
            client.initialize().await?;
            client.initialized().await?;
            client
                .request(
                    "thread/read",
                    json!({
                        "threadId": thread_id,
                        "includeTurns": true,
                    }),
                )
                .await
        })
        .await;

        self.cleanup_app_server_containers(&container_id, browser_container_id.as_deref())
            .await;

        match result {
            Ok(Ok(response)) => Ok(response),
            Ok(Err(err)) => Err(err),
            Err(_) => Err(anyhow!("codex thread/read timed out")),
        }
    }
}

#[async_trait]
impl CodexRunner for DockerCodexRunner {
    async fn warm_up_images(&self) -> Result<()> {
        let images = self.warm_up_image_refs();
        info!(images = ?images, "warming up docker images");
        for image in &images {
            self.ensure_image_available(image).await?;
            info!(image = image.as_str(), "docker image warm-up complete");
        }
        Ok(())
    }

    async fn run_review(&self, ctx: ReviewContext) -> Result<CodexResult> {
        info!(
            repo = ctx.repo.as_str(),
            iid = ctx.mr.iid,
            lane = ctx.lane.as_str(),
            "starting codex review"
        );
        let output = self.run_app_server_review(&ctx).await?;
        parse_review_output_for_lane(&output, ctx.lane, ctx.min_confidence_score).with_context(
            || {
                format!(
                    "parse codex review output for repo {} merge request {}",
                    ctx.repo, ctx.mr.iid
                )
            },
        )
    }

    async fn run_mention_command(
        &self,
        ctx: MentionCommandContext,
    ) -> Result<MentionCommandResult> {
        info!(
            repo = ctx.repo.as_str(),
            iid = ctx.mr.iid,
            discussion_id = ctx.discussion_id.as_str(),
            trigger_note_id = ctx.trigger_note_id,
            "starting codex mention command"
        );
        self.run_mention_container(&ctx).await.with_context(|| {
            format!(
                "run mention command for repo {} merge request {} discussion {} note {}",
                ctx.repo, ctx.mr.iid, ctx.discussion_id, ctx.trigger_note_id
            )
        })
    }

    async fn stop_active_reviews(&self) -> Result<()> {
        self.stop_active_review_containers_best_effort().await;
        Ok(())
    }

    async fn read_thread(&self, account_name: &str, thread_id: &str) -> Result<Value> {
        let account = self
            .auth_account_by_name(account_name)
            .ok_or_else(|| anyhow!("unknown codex auth account: {account_name}"))?;
        self.read_thread_with_account(account, thread_id).await
    }
}

#[cfg(test)]
mod tests;
