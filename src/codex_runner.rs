use crate::config::{
    BROWSER_MCP_REMOTE_DEBUGGING_PORT, BrowserMcpConfig, CodexConfig, DockerConfig,
};
use crate::docker_utils::{connect_docker, ensure_image, normalize_image_reference};
use crate::gitlab::MergeRequest;
use crate::state::ReviewStateStore;
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
use chrono::{DateTime, Duration as ChronoDuration, Utc};
use futures::StreamExt;
use serde::Deserialize;
use serde_json::{Value, json};
use std::cell::RefCell;
use std::collections::{BTreeMap, HashMap, VecDeque};
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tokio::time::{Instant, sleep, timeout};
use tracing::{debug, info, warn};
use url::Url;
use uuid::Uuid;

#[derive(Debug, Clone)]
pub struct ReviewContext {
    pub repo: String,
    pub project_path: String,
    pub mr: MergeRequest,
    pub head_sha: String,
}

#[derive(Debug, Clone)]
pub struct MentionCommandContext {
    pub repo: String,
    pub project_path: String,
    pub mr: MergeRequest,
    pub head_sha: String,
    pub discussion_id: String,
    pub trigger_note_id: u64,
    pub requester_name: String,
    pub requester_email: String,
    pub additional_developer_instructions: Option<String>,
    pub prompt: String,
}

#[derive(Debug, Clone)]
pub enum CodexResult {
    Pass { summary: String },
    Comment { summary: String, body: String },
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

const REVIEW_CONTAINER_NAME_PREFIX: &str = "codex-review-";
const BROWSER_CONTAINER_NAME_PREFIX: &str = "codex-browser-";
const REVIEW_OWNER_LABEL_KEY: &str = "codex.gitlab.review.owner";
const PRIMARY_AUTH_ACCOUNT_NAME: &str = "primary";
const BROWSER_CONTAINER_READY_TIMEOUT: Duration = Duration::from_secs(30);
const BROWSER_CONTAINER_RUNNING_GRACE_PERIOD: Duration = Duration::from_secs(10);
const BROWSER_CONTAINER_LOG_FETCH_TAIL: &str = "50";
const BROWSER_CONTAINER_LOG_LINE_LIMIT: usize = 12;
const BROWSER_CONTAINER_LOG_LINE_MAX_CHARS: usize = 240;
#[derive(Debug, Clone)]
struct AuthAccount {
    name: String,
    auth_host_path: String,
    state_key: String,
    is_primary: bool,
}

struct StartedAppServer {
    container_id: String,
    browser_container_id: Option<String>,
    client: AppServerClient,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct BrowserLaunchConfig {
    image: String,
    entrypoint: Vec<String>,
    cmd: Vec<String>,
}

impl BrowserLaunchConfig {
    fn from_browser_mcp(browser_mcp: &BrowserMcpConfig) -> Self {
        let image = DockerCodexRunner::normalize_image_reference(&browser_mcp.browser_image);
        Self {
            image: image.clone(),
            entrypoint: browser_mcp.browser_entrypoint.clone(),
            cmd: browser_container_cmd(&image, &browser_mcp.browser_entrypoint, browser_mcp),
        }
    }

    fn entrypoint_display(&self) -> String {
        if self.entrypoint.is_empty() {
            "<image-default>".to_string()
        } else {
            format_command_for_log(&self.entrypoint)
        }
    }

    fn cmd_display(&self) -> String {
        if self.cmd.is_empty() {
            "<none>".to_string()
        } else {
            format_command_for_log(&self.cmd)
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct BrowserLogTail {
    stdout: Vec<String>,
    stderr: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct BrowserContainerStateSnapshot {
    status: Option<String>,
    running: Option<bool>,
    exit_code: Option<i64>,
    oom_killed: Option<bool>,
    error: Option<String>,
    started_at: Option<String>,
    finished_at: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct BrowserContainerDiagnostics {
    container_id: String,
    launch: BrowserLaunchConfig,
    state: Option<BrowserContainerStateSnapshot>,
    state_collection_error: Option<String>,
    log_tail: BrowserLogTail,
    log_collection_error: Option<String>,
}

#[derive(Clone, Copy)]
struct AppServerCommandOptions<'a> {
    browser_mcp: Option<&'a BrowserMcpConfig>,
    mcp_server_overrides: &'a BTreeMap<String, bool>,
    reasoning_effort: Option<&'a str>,
}

impl BrowserContainerDiagnostics {
    fn format_context(&self) -> String {
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

#[derive(Debug, Clone, PartialEq, Eq)]
enum AuthFailureKind {
    UsageLimited { reset_at: DateTime<Utc> },
    AuthUnavailable,
    Other,
}

#[async_trait]
pub trait CodexRunner: Send + Sync {
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
}

pub struct DockerCodexRunner {
    docker: Docker,
    codex: CodexConfig,
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
}

impl DockerCodexRunner {
    pub fn new(
        docker_cfg: DockerConfig,
        codex: CodexConfig,
        git_base: Url,
        state: Arc<ReviewStateStore>,
        runtime: RunnerRuntimeOptions,
    ) -> Result<Self> {
        let docker = connect_docker(&docker_cfg)?;
        let auth_accounts = Self::build_auth_accounts(&codex);
        Ok(Self {
            docker,
            codex,
            git_base,
            gitlab_token: runtime.gitlab_token,
            log_all_json: runtime.log_all_json,
            owner_id: runtime.owner_id,
            state,
            auth_accounts,
        })
    }

    fn build_auth_accounts(codex: &CodexConfig) -> Vec<AuthAccount> {
        let mut accounts = vec![AuthAccount {
            name: PRIMARY_AUTH_ACCOUNT_NAME.to_string(),
            auth_host_path: codex.auth_host_path.clone(),
            state_key: auth_account_state_key(PRIMARY_AUTH_ACCOUNT_NAME, &codex.auth_host_path),
            is_primary: true,
        }];
        accounts.extend(
            codex
                .fallback_auth_accounts
                .iter()
                .map(|account| AuthAccount {
                    name: account.name.clone(),
                    auth_host_path: account.auth_host_path.clone(),
                    state_key: auth_account_state_key(&account.name, &account.auth_host_path),
                    is_primary: false,
                }),
        );
        accounts
    }

    fn clone_url(&self, repo: &str) -> Result<String> {
        let scheme = self.git_base.scheme();
        let host = self
            .git_base
            .host_str()
            .ok_or_else(|| anyhow!("missing git base host"))?;
        let port = self.git_base.port();
        let mut host_port = host.to_string();
        if let Some(port) = port {
            host_port = format!("{}:{}", host, port);
        }
        let base_path = self.git_base.path().trim_end_matches('/');
        let repo_path = if base_path.is_empty() {
            format!("/{}.git", repo)
        } else {
            format!("{}/{}.git", base_path, repo)
        };
        if self.gitlab_token.is_empty() {
            Ok(format!("{}://{}{}", scheme, host_port, repo_path))
        } else {
            Ok(format!(
                "{}://oauth2:${{GITLAB_TOKEN}}@{}{}",
                scheme, host_port, repo_path
            ))
        }
    }

    fn review_instructions(&self, ctx: &ReviewContext) -> String {
        let title = ctx
            .mr
            .title
            .clone()
            .unwrap_or_else(|| "(no title)".to_string());
        let url = ctx
            .mr
            .web_url
            .clone()
            .unwrap_or_else(|| "(no url)".to_string());
        let target_branch = ctx
            .mr
            .target_branch
            .clone()
            .unwrap_or_else(|| "(unknown)".to_string());
        format!(
            "You are a senior code reviewer. Review only the changes introduced by this merge request (diff against the target branch) and return JSON only.\n\nRepo: {}\nMR: {}\nURL: {}\nHead SHA: {}\nTarget branch: {}\n\nReturn JSON with fields verdict (pass or comment), summary, and comment_markdown. If verdict is pass, comment_markdown can be an empty string.",
            ctx.repo, title, url, ctx.head_sha, target_branch
        )
    }

    fn env_vars(&self) -> Vec<String> {
        let mut env = vec![
            format!("GITLAB_TOKEN={}", self.gitlab_token),
            "HOME=/root".to_string(),
        ];
        if self.log_all_json {
            env.push("CODEX_RUNNER_DEBUG=1".to_string());
        }
        env
    }

    fn command(
        &self,
        ctx: &ReviewContext,
        browser_mcp: Option<&BrowserMcpConfig>,
    ) -> Result<String> {
        let clone_url = self.clone_url(&ctx.repo)?;
        let reasoning_effort =
            configured_reasoning_effort(self.codex.reasoning_effort.review.as_deref());
        Ok(Self::build_command_script(
            &clone_url,
            ctx.head_sha.as_str(),
            &self.codex.auth_mount_path,
            ctx.mr
                .target_branch
                .as_deref()
                .filter(|value| !value.is_empty()),
            self.codex.deps.enabled,
            AppServerCommandOptions {
                browser_mcp,
                mcp_server_overrides: &self.codex.mcp_server_overrides.review,
                reasoning_effort,
            },
        ))
    }

    fn browser_mcp(&self) -> Option<&BrowserMcpConfig> {
        self.codex
            .browser_mcp
            .enabled
            .then_some(&self.codex.browser_mcp)
    }

    fn effective_browser_mcp(
        &self,
        mcp_server_overrides: &BTreeMap<String, bool>,
    ) -> Option<&BrowserMcpConfig> {
        effective_browser_mcp(self.browser_mcp(), mcp_server_overrides)
    }

    fn mention_developer_instructions(ctx: &MentionCommandContext) -> String {
        let mut instructions = format!(
            "You are handling a GitLab mention command request.\n\
             \n\
             Git identity for commits is configured as:\n\
             - Name: {name}\n\
             - Email: {email}\n\
             \n\
             Requirements:\n\
             - If code changes are required, create at least one commit before you finish.\n\
             - In your final response, include the commit SHA(s) you created.\n\
             - If no code changes are required, explicitly say that no commit was created.\n\
             - Do not push to remote.\n\
             - Keep the response focused on what you changed or answered.",
            name = ctx.requester_name,
            email = ctx.requester_email
        );
        if let Some(extra) = ctx
            .additional_developer_instructions
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
        {
            instructions.push_str("\n\nAdditional instructions:\n");
            instructions.push_str(extra);
        }
        instructions
    }

    fn build_mention_command_script(
        ctx: &MentionCommandContext,
        clone_url: &str,
        auth_mount_path: &str,
        app_server: AppServerCommandOptions<'_>,
    ) -> String {
        let clone_url_dq = clone_url.replace('\\', "\\\\").replace('"', "\\\"");
        let head_sha_q = shell_quote(&ctx.head_sha);
        let auth_mount_path_q = shell_quote(auth_mount_path);
        let browser_prereq_script = browser_mcp_prereq_script(app_server.browser_mcp);
        let browser_wait_script = browser_wait_script(app_server.browser_mcp);
        let app_server_exec_cmd = codex_app_server_exec_command(
            app_server.browser_mcp,
            app_server.mcp_server_overrides,
            app_server.reasoning_effort,
        );
        format!(
            r#"set -eu
repo_dir='/work/repo'
log_file="/tmp/codex-mention-git.log"
mkdir -p /work
cd /work
run_git() {{
  action="$1"
  shift
  if [ "${{CODEX_RUNNER_DEBUG:-}}" = "1" ]; then
    "$@" || {{ echo "codex-runner-error: git ${{action}} failed"; exit 1; }}
  else
    if ! "$@" >"$log_file" 2>&1; then
      echo "codex-runner-error: git ${{action}} failed"
      tail -n 50 "$log_file" | sed 's/^/codex-runner-error: /'
      exit 1
    fi
  fi
}}
run_git clone git clone --depth 1 --recurse-submodules "{clone_url_dq}" "$repo_dir"
cd "$repo_dir"
run_git fetch git fetch --depth 1 origin {head_sha_q}
run_git checkout git checkout {head_sha_q}
run_git submodule_update git submodule update --init --recursive
origin_url="$(git remote get-url origin || true)"
if [ -n "$origin_url" ]; then
  sanitized_origin="$(printf '%s' "$origin_url" | sed -E 's#(https?://)oauth2:[^@]*@#\1#')"
  run_git set_url git remote set-url origin "$sanitized_origin"
fi
run_git set_pushurl git remote set-url --push origin "no_push://disabled"
mkdir -p {auth_mount_path_q}
export CODEX_HOME={auth_mount_path_q}
if ! command -v codex >/dev/null 2>&1; then
  echo "codex-runner: codex not found, installing"
  if command -v npm >/dev/null 2>&1; then
    if [ "${{CODEX_RUNNER_DEBUG:-}}" = "1" ]; then
      npm install -g @openai/codex
    else
      if ! npm install -g @openai/codex >/tmp/codex-install.log 2>&1; then
        echo "codex-runner-error: codex install failed"
        tail -n 50 /tmp/codex-install.log | sed 's/^/codex-runner-error: /'
        exit 1
      fi
    fi
  else
    echo "codex-runner-error: npm not found; provide a base image with node/npm or preinstall codex"
    exit 1
  fi
fi
{browser_prereq_script}
{browser_wait_script}
{app_server_exec_cmd}
"#,
            clone_url_dq = clone_url_dq,
            head_sha_q = head_sha_q,
            auth_mount_path_q = auth_mount_path_q,
            browser_prereq_script = browser_prereq_script,
            browser_wait_script = browser_wait_script,
            app_server_exec_cmd = app_server_exec_cmd,
        )
    }

    fn build_command_script(
        clone_url: &str,
        head_sha: &str,
        auth_mount_path: &str,
        target_branch: Option<&str>,
        deps_enabled: bool,
        app_server: AppServerCommandOptions<'_>,
    ) -> String {
        let target_branch_script = target_branch
            .map(|branch| {
                format!(
                    "run_git fetch git fetch --depth 1 origin \"{branch}\"\n\
git branch --force \"{branch}\" FETCH_HEAD\n\
# Ensure merge-base works for PR review by unshallowing history.\n\
run_git fetch git fetch --unshallow\n"
                )
            })
            .unwrap_or_default();
        let deps_prefetch_script = if deps_enabled {
            r#"
prefetch_deps() (
  set +e
  deps_dir="/work/repo/.codex_deps"
  log_file="/tmp/codex-deps.log"
  mkdir -p "$deps_dir"
  failures=0
  run_prefetch() {
    action="$1"
    shift
    if [ "${CODEX_RUNNER_DEBUG:-}" = "1" ]; then
      "$@" || { echo "codex-runner-warn: $action failed"; failures=$((failures+1)); }
    else
      if ! "$@" >"$log_file" 2>&1; then
        echo "codex-runner-warn: $action failed"
        tail -n 50 "$log_file" | sed 's/^/codex-runner-warn: /'
        failures=$((failures+1))
      fi
    fi
  }

  if [ -f "package.json" ]; then
    if [ -f "pnpm-lock.yaml" ] && command -v pnpm >/dev/null 2>&1; then
      run_prefetch "pnpm install" pnpm install --ignore-scripts
    elif [ -f "yarn.lock" ] && command -v yarn >/dev/null 2>&1; then
      run_prefetch "yarn install" yarn install --ignore-scripts
    elif [ -f "package-lock.json" ] || [ -f "npm-shrinkwrap.json" ]; then
      run_prefetch "npm ci" npm ci --ignore-scripts --no-audit --no-fund
    else
      run_prefetch "npm install" npm install --ignore-scripts --no-audit --no-fund
    fi
  fi

  if [ -f "Cargo.toml" ] && command -v cargo >/dev/null 2>&1; then
    mkdir -p "$deps_dir/cargo"
    if [ -f "Cargo.lock" ]; then
      CARGO_HOME="$deps_dir/cargo" run_prefetch "cargo fetch" cargo fetch --locked
    else
      echo "codex-runner-warn: Cargo.lock missing; skipping cargo fetch"
    fi
  fi

  if [ -f "go.mod" ] && command -v go >/dev/null 2>&1; then
    mkdir -p "$deps_dir/go/mod" "$deps_dir/go/cache"
    GOMODCACHE="$deps_dir/go/mod" GOCACHE="$deps_dir/go/cache" GOFLAGS="-mod=readonly" run_prefetch "go mod download" go mod download
  fi

  if [ -f "requirements.txt" ] && command -v pip >/dev/null 2>&1; then
    mkdir -p "$deps_dir/pip"
    run_prefetch "pip download requirements.txt" pip download -r requirements.txt -d "$deps_dir/pip"
  fi

  if [ -f "pyproject.toml" ] && [ -f "poetry.lock" ] && command -v poetry >/dev/null 2>&1 && command -v pip >/dev/null 2>&1; then
    if [ "${CODEX_RUNNER_DEBUG:-}" = "1" ]; then
      poetry export -f requirements.txt --without-hashes -o /tmp/poetry-reqs.txt || failures=$((failures+1))
    else
      if ! poetry export -f requirements.txt --without-hashes -o /tmp/poetry-reqs.txt >"$log_file" 2>&1; then
        echo "codex-runner-warn: poetry export failed"
        tail -n 50 "$log_file" | sed 's/^/codex-runner-warn: /'
        failures=$((failures+1))
      fi
    fi
    if [ -f /tmp/poetry-reqs.txt ]; then
      mkdir -p "$deps_dir/pip"
      run_prefetch "pip download poetry export" pip download -r /tmp/poetry-reqs.txt -d "$deps_dir/pip"
    fi
  fi

  if [ -f "pom.xml" ] && command -v mvn >/dev/null 2>&1; then
    mkdir -p "$deps_dir/m2"
    MAVEN_USER_HOME="$deps_dir/m2" run_prefetch "maven go-offline" mvn -q -DskipTests dependency:go-offline
  fi

  if [ -f "composer.json" ] && command -v composer >/dev/null 2>&1; then
    mkdir -p "$deps_dir/composer-cache"
    COMPOSER_CACHE_DIR="$deps_dir/composer-cache" COMPOSER_ALLOW_SUPERUSER=1 run_prefetch "composer install" \
      composer install --no-dev --no-scripts --no-plugins --prefer-dist --no-interaction --no-progress
  fi

  if [ "$failures" -ne 0 ]; then
    return 1
  fi
  return 0
)
prefetch_home="/tmp/codex-prefetch"
mkdir -p "$prefetch_home/.config" "$prefetch_home/.cache" "$prefetch_home/.state"
if ! HOME="$prefetch_home" XDG_CONFIG_HOME="$prefetch_home/.config" XDG_CACHE_HOME="$prefetch_home/.cache" \
  XDG_STATE_HOME="$prefetch_home/.state" GITLAB_TOKEN="" CODEX_HOME="" prefetch_deps; then
  echo "codex-runner-warn: dependency prefetch had failures; continuing"
fi
export CARGO_HOME="/work/repo/.codex_deps/cargo"
export GOMODCACHE="/work/repo/.codex_deps/go/mod"
export GOCACHE="/work/repo/.codex_deps/go/cache"
export MAVEN_USER_HOME="/work/repo/.codex_deps/m2"
export COMPOSER_CACHE_DIR="/work/repo/.codex_deps/composer-cache"
"#
        } else {
            ""
        };
        let browser_prereq_script = browser_mcp_prereq_script(app_server.browser_mcp);
        let browser_wait_script = browser_wait_script(app_server.browser_mcp);
        let app_server_exec_cmd = codex_app_server_exec_command(
            app_server.browser_mcp,
            app_server.mcp_server_overrides,
            app_server.reasoning_effort,
        );
        format!(
            r#"set -eu
mkdir -p /work
cd /work
log_file="/tmp/codex-git.log"
run_git() {{
  action="$1"
  shift
  if [ "${{CODEX_RUNNER_DEBUG:-}}" = "1" ]; then
    "$@" || {{ echo "codex-runner-error: git ${{action}} failed"; exit 1; }}
  else
    if ! "$@" >"$log_file" 2>&1; then
      echo "codex-runner-error: git ${{action}} failed"
      tail -n 50 "$log_file" | sed 's/^/codex-runner-error: /'
      exit 1
    fi
  fi
}}
run_git clone git clone --depth 1 --recurse-submodules "{clone_url}" repo
cd repo
run_git fetch git fetch --depth 1 origin "{head_sha}"
run_git checkout git checkout "{head_sha}"
run_git submodule_update git submodule update --init --recursive
{target_branch_script}{deps_prefetch_script}# Use the mounted auth directory directly so token refresh persists.
mkdir -p "{auth_mount_path}"
export CODEX_HOME="{auth_mount_path}"
# Ensure Codex CLI is available for app-server mode
if ! command -v codex >/dev/null 2>&1; then
  echo "codex-runner: codex not found, installing"
  if command -v npm >/dev/null 2>&1; then
    if [ "${{CODEX_RUNNER_DEBUG:-}}" = "1" ]; then
      npm install -g @openai/codex
    else
      if ! npm install -g @openai/codex >/tmp/codex-install.log 2>&1; then
        echo "codex-runner-error: codex install failed"
        tail -n 50 /tmp/codex-install.log | sed 's/^/codex-runner-error: /'
        exit 1
      fi
    fi
  else
    echo "codex-runner-error: npm not found; provide a base image with node/npm or preinstall codex"
    exit 1
  fi
fi
{browser_prereq_script}
{browser_wait_script}
{app_server_exec_cmd}
"#,
            clone_url = clone_url,
            head_sha = head_sha,
            auth_mount_path = auth_mount_path,
            target_branch_script = target_branch_script,
            deps_prefetch_script = deps_prefetch_script,
            browser_prereq_script = browser_prereq_script,
            browser_wait_script = browser_wait_script,
            app_server_exec_cmd = app_server_exec_cmd
        )
    }

    fn app_server_cmd(script: String) -> Vec<String> {
        // The codex-universal entrypoint runs `bash --login "$@"`, so pass only bash flags + script.
        vec!["-lc".to_string(), script]
    }

    fn normalize_image_reference(image: &str) -> String {
        normalize_image_reference(image)
    }

    async fn collect_browser_container_diagnostics(
        &self,
        browser_container_id: &str,
        launch: &BrowserLaunchConfig,
    ) -> BrowserContainerDiagnostics {
        let (state, state_collection_error) = match self
            .docker
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

    async fn collect_browser_container_log_tail(
        &self,
        browser_container_id: &str,
    ) -> Result<BrowserLogTail> {
        let mut stdout = String::new();
        let mut stderr = String::new();
        let mut stream = self.docker.logs(
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

    async fn enrich_error_with_browser_diagnostics(
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

    async fn wait_for_browser_container_ready(
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

    fn sandbox_mode_value(&self) -> &'static str {
        match self.codex.exec_sandbox.as_str() {
            "read-only" => "read-only",
            "workspace-write" => "workspace-write",
            _ => "danger-full-access",
        }
    }

    async fn remove_container_best_effort(&self, id: &str) {
        let _ = self
            .docker
            .remove_container(
                id,
                Some(RemoveContainerOptionsBuilder::new().force(true).build()),
            )
            .await;
    }

    async fn cleanup_app_server_containers(
        &self,
        container_id: &str,
        browser_container_id: Option<&str>,
    ) {
        self.remove_container_best_effort(container_id).await;
        if let Some(browser_container_id) = browser_container_id {
            self.remove_container_best_effort(browser_container_id)
                .await;
        }
    }

    async fn exec_container_command(
        &self,
        container_id: &str,
        command: Vec<String>,
        cwd: Option<&str>,
    ) -> Result<ContainerExecOutput> {
        let command_display = format_command_for_log(&command);
        let cwd_display = cwd.unwrap_or("<default>");
        info!(
            container_id,
            command = command_display.as_str(),
            cwd = cwd_display,
            "running docker exec command"
        );

        // Deliberately bypass app-server command RPC and its sandbox semantics for
        // mention auxiliary git operations.
        let exec = self
            .docker
            .create_exec(
                container_id,
                ExecConfig {
                    attach_stdout: Some(true),
                    attach_stderr: Some(true),
                    cmd: Some(command.clone()),
                    working_dir: cwd.map(|value| value.to_string()),
                    ..Default::default()
                },
            )
            .await
            .with_context(|| {
                format!(
                    "create docker exec command '{}' in container {}",
                    command_display, container_id
                )
            })?;

        let start_result = self
            .docker
            .start_exec(&exec.id, None::<StartExecOptions>)
            .await
            .with_context(|| {
                format!(
                    "start docker exec command '{}' in container {}",
                    command_display, container_id
                )
            })?;

        let mut stdout = String::new();
        let mut stderr = String::new();
        match start_result {
            StartExecResults::Attached { mut output, .. } => {
                while let Some(message) = output.next().await {
                    match message.with_context(|| {
                        format!(
                            "read docker exec output for command '{}' in container {}",
                            command_display, container_id
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
            }
            StartExecResults::Detached => {
                bail!(
                    "docker exec command '{}' unexpectedly detached in container {}",
                    command_display,
                    container_id
                );
            }
        }

        let inspect = self.docker.inspect_exec(&exec.id).await.with_context(|| {
            format!(
                "inspect docker exec command '{}' in container {}",
                command_display, container_id
            )
        })?;
        let output = validate_container_exec_result(
            &command,
            cwd,
            ContainerExecOutput {
                exit_code: inspect.exit_code.unwrap_or(-1),
                stdout,
                stderr,
            },
        )?;

        info!(
            container_id,
            command = command_display.as_str(),
            cwd = cwd_display,
            exit_code = output.exit_code,
            "docker exec command completed"
        );

        Ok(output)
    }

    fn is_managed_container_name(name: &str) -> bool {
        let name = name.trim_start_matches('/');
        name.starts_with(REVIEW_CONTAINER_NAME_PREFIX)
            || name.starts_with(BROWSER_CONTAINER_NAME_PREFIX)
    }

    fn review_container_labels(owner_id: &str) -> HashMap<String, String> {
        HashMap::from([(REVIEW_OWNER_LABEL_KEY.to_string(), owner_id.to_string())])
    }

    fn review_container_filters(owner_id: &str) -> HashMap<String, Vec<String>> {
        HashMap::from([
            (
                "name".to_string(),
                vec![
                    REVIEW_CONTAINER_NAME_PREFIX.to_string(),
                    BROWSER_CONTAINER_NAME_PREFIX.to_string(),
                ],
            ),
            (
                "label".to_string(),
                vec![format!("{REVIEW_OWNER_LABEL_KEY}={owner_id}")],
            ),
        ])
    }

    fn has_review_owner_label(labels: Option<&HashMap<String, String>>, owner_id: &str) -> bool {
        labels
            .and_then(|labels| labels.get(REVIEW_OWNER_LABEL_KEY))
            .map(|value| value == owner_id)
            .unwrap_or(false)
    }

    async fn stop_active_review_containers_best_effort(&self) {
        let filters = Self::review_container_filters(&self.owner_id);
        let options = ListContainersOptionsBuilder::new()
            .all(true)
            .filters(&filters)
            .build();

        let containers = match self.docker.list_containers(Some(options)).await {
            Ok(containers) => containers,
            Err(err) => {
                warn!(
                    error = %err,
                    "failed to list docker containers while stopping active codex reviews"
                );
                return;
            }
        };

        for container in containers {
            let names = container.names.unwrap_or_default();
            if !names
                .iter()
                .any(|name| Self::is_managed_container_name(name))
            {
                continue;
            }
            if !Self::has_review_owner_label(container.labels.as_ref(), &self.owner_id) {
                continue;
            }

            let Some(id) = container.id.as_deref() else {
                let names_value = if names.is_empty() {
                    "<unknown>".to_string()
                } else {
                    names.join(",")
                };
                warn!(
                    container_names = names_value.as_str(),
                    "skipping managed codex container without id"
                );
                continue;
            };

            if let Err(err) = self
                .docker
                .remove_container(
                    id,
                    Some(RemoveContainerOptionsBuilder::new().force(true).build()),
                )
                .await
            {
                let container_name = names
                    .iter()
                    .find(|name| Self::is_managed_container_name(name))
                    .map(|name| name.trim_start_matches('/'))
                    .unwrap_or("<unknown>");
                warn!(
                    container_id = id,
                    container_name,
                    error = %err,
                    "failed to remove managed codex container"
                );
            }
        }
    }

    async fn account_is_temporarily_blocked(
        &self,
        account: &AuthAccount,
        now: DateTime<Utc>,
    ) -> Result<bool> {
        let Some(raw_reset_at) = self
            .state
            .get_auth_limit_reset_at(&account.state_key)
            .await?
        else {
            return Ok(false);
        };
        match DateTime::parse_from_rfc3339(&raw_reset_at) {
            Ok(parsed) => Ok(parsed.with_timezone(&Utc) > now),
            Err(err) => {
                warn!(
                    account = account.name.as_str(),
                    raw_reset_at = raw_reset_at.as_str(),
                    error = %err,
                    "invalid account reset timestamp in state; clearing stale entry"
                );
                self.state
                    .clear_auth_limit_reset_at(&account.state_key)
                    .await?;
                Ok(false)
            }
        }
    }

    async fn available_auth_accounts(&self, now: DateTime<Utc>) -> Result<Vec<AuthAccount>> {
        let mut available = Vec::new();
        for account in &self.auth_accounts {
            if self.account_is_temporarily_blocked(account, now).await? {
                continue;
            }
            available.push(account.clone());
        }
        Ok(available)
    }

    async fn clear_limit_reset_if_stale(
        &self,
        account: &AuthAccount,
        attempt_started_at: DateTime<Utc>,
    ) -> Result<()> {
        let Some(raw_reset_at) = self
            .state
            .get_auth_limit_reset_at(&account.state_key)
            .await?
        else {
            return Ok(());
        };
        match DateTime::parse_from_rfc3339(&raw_reset_at) {
            Ok(parsed) => {
                let reset_at = parsed.with_timezone(&Utc);
                if should_clear_limit_reset(reset_at, attempt_started_at) {
                    self.state
                        .clear_auth_limit_reset_at(&account.state_key)
                        .await?;
                }
            }
            Err(_) => {
                self.state
                    .clear_auth_limit_reset_at(&account.state_key)
                    .await?;
            }
        }
        Ok(())
    }

    async fn mark_limit_reset_at(
        &self,
        account: &AuthAccount,
        reset_at: DateTime<Utc>,
    ) -> Result<()> {
        self.state
            .set_auth_limit_reset_at(&account.state_key, &reset_at.to_rfc3339())
            .await
    }

    async fn start_app_server_container(
        &self,
        script: String,
        auth_host_path: &str,
        extra_binds: Vec<String>,
        browser_mcp: Option<&BrowserMcpConfig>,
    ) -> Result<StartedAppServer> {
        let image_ref = Self::normalize_image_reference(&self.codex.image);
        ensure_image(&self.docker, &image_ref).await?;
        let browser_container_id = if let Some(browser_mcp) = browser_mcp {
            Some(self.start_browser_container(browser_mcp).await?)
        } else {
            None
        };
        let name = format!("{}{}", REVIEW_CONTAINER_NAME_PREFIX, Uuid::new_v4());
        let mut binds = vec![format!(
            "{}:{}:rw",
            auth_host_path, self.codex.auth_mount_path
        )];
        binds.extend(extra_binds);
        let config = ContainerCreateBody {
            image: Some(image_ref.clone()),
            cmd: Some(Self::app_server_cmd(script)),
            env: Some(self.env_vars()),
            labels: Some(Self::review_container_labels(&self.owner_id)),
            attach_stdout: Some(true),
            attach_stderr: Some(true),
            attach_stdin: Some(true),
            open_stdin: Some(true),
            tty: Some(false),
            host_config: Some(HostConfig {
                binds: Some(binds),
                network_mode: browser_container_id
                    .as_ref()
                    .map(|id| format!("container:{id}")),
                auto_remove: Some(false),
                ..Default::default()
            }),
            ..Default::default()
        };

        let create = match self
            .docker
            .create_container(
                Some(CreateContainerOptionsBuilder::new().name(&name).build()),
                config,
            )
            .await
            .with_context(|| format!("create docker container {} with image {}", name, image_ref))
        {
            Ok(create) => create,
            Err(err) => {
                if let Some(browser_id) = browser_container_id.as_deref() {
                    self.remove_container_best_effort(browser_id).await;
                }
                return Err(err);
            }
        };
        let id = create.id;
        let start_result = self
            .docker
            .start_container(&id, Some(StartContainerOptionsBuilder::new().build()))
            .await
            .with_context(|| format!("start docker container {}", id));
        if let Err(err) = start_result {
            self.remove_container_best_effort(&id).await;
            if let Some(browser_id) = browser_container_id.as_deref() {
                self.remove_container_best_effort(browser_id).await;
            }
            return Err(err);
        }

        let attach = match self
            .docker
            .attach_container(
                &id,
                Some(
                    AttachContainerOptionsBuilder::new()
                        .stdout(true)
                        .stderr(true)
                        .stdin(true)
                        .stream(true)
                        .logs(true)
                        .build(),
                ),
            )
            .await
            .with_context(|| format!("attach docker container {}", id))
        {
            Ok(attach) => attach,
            Err(err) => {
                self.remove_container_best_effort(&id).await;
                if let Some(browser_id) = browser_container_id.as_deref() {
                    self.remove_container_best_effort(browser_id).await;
                }
                return Err(err);
            }
        };

        Ok(StartedAppServer {
            container_id: id,
            browser_container_id,
            client: AppServerClient::new(attach, self.log_all_json),
        })
    }

    async fn start_browser_container(&self, browser_mcp: &BrowserMcpConfig) -> Result<String> {
        let launch = BrowserLaunchConfig::from_browser_mcp(browser_mcp);
        let image_ref = launch.image.clone();
        ensure_image(&self.docker, &image_ref).await?;
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
                ..Default::default()
            }),
            ..Default::default()
        };

        let create = self
            .docker
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
        let start_result = self
            .docker
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

    async fn run_app_server_review_with_account(
        &self,
        ctx: &ReviewContext,
        account: &AuthAccount,
    ) -> Result<String> {
        let browser_mcp = self.effective_browser_mcp(&self.codex.mcp_server_overrides.review);
        let script = self.command(ctx, browser_mcp)?;
        let StartedAppServer {
            container_id,
            browser_container_id,
            mut client,
        } = self
            .start_app_server_container(script, &account.auth_host_path, Vec::new(), browser_mcp)
            .await?;
        let repo_path = "/work/repo";
        let instructions = self.review_instructions(ctx);
        let base_branch = ctx
            .mr
            .target_branch
            .as_deref()
            .filter(|value| !value.is_empty());
        let review_target = if let Some(branch) = base_branch {
            json!({ "type": "baseBranch", "branch": branch })
        } else {
            json!({ "type": "custom", "instructions": instructions.clone() })
        };

        let review_result = timeout(Duration::from_secs(self.codex.timeout_seconds), async {
            client.initialize().await?;
            client.initialized().await?;
            let thread_response = client
                .request(
                    "thread/start",
                    json!({
                        "cwd": repo_path,
                        "approvalPolicy": "never",
                        "sandbox": self.sandbox_mode_value(),
                        "baseInstructions": instructions,
                    }),
                )
                .await?;
            let thread_id = thread_response
                .get("thread")
                .and_then(|thread| thread.get("id"))
                .and_then(|id| id.as_str())
                .ok_or_else(|| anyhow!("thread/start missing thread id"))?
                .to_string();
            let review_response = client
                .request(
                    "review/start",
                    json!({
                        "threadId": thread_id,
                        "delivery": "inline",
                        "target": review_target,
                    }),
                )
                .await?;
            let turn_id = review_response
                .get("turn")
                .and_then(|turn| turn.get("id"))
                .and_then(|id| id.as_str())
                .ok_or_else(|| anyhow!("review/start missing turn id"))?
                .to_string();
            let review_thread_id = review_response
                .get("reviewThreadId")
                .and_then(|id| id.as_str())
                .unwrap_or(thread_id.as_str())
                .to_string();
            client.stream_review(&review_thread_id, &turn_id).await
        })
        .await;

        let review_result = match review_result {
            Ok(Ok(review)) => Ok(review),
            Ok(Err(err)) => Err(self
                .enrich_error_with_browser_diagnostics(
                    err,
                    browser_container_id.as_deref(),
                    browser_mcp,
                )
                .await),
            Err(_) => Err(self
                .enrich_error_with_browser_diagnostics(
                    anyhow!("codex review timed out"),
                    browser_container_id.as_deref(),
                    browser_mcp,
                )
                .await),
        };

        self.cleanup_app_server_containers(&container_id, browser_container_id.as_deref())
            .await;

        review_result
    }

    async fn run_app_server_review(&self, ctx: &ReviewContext) -> Result<String> {
        let now = Utc::now();
        let available_accounts = self.available_auth_accounts(now).await?;
        if available_accounts.is_empty() {
            bail!(
                "no available codex auth accounts (all accounts are waiting for usage-limit reset)"
            );
        }

        let mut auth_fallback_errors = Vec::new();
        for account in &available_accounts {
            let attempt_started_at = Utc::now();
            info!(
                account = account.name.as_str(),
                is_primary = account.is_primary,
                repo = ctx.repo.as_str(),
                iid = ctx.mr.iid,
                "running codex review with auth account"
            );
            match self.run_app_server_review_with_account(ctx, account).await {
                Ok(output) => {
                    self.clear_limit_reset_if_stale(account, attempt_started_at)
                        .await?;
                    return Ok(output);
                }
                Err(err) => {
                    let kind = classify_auth_failure(
                        &err,
                        Utc::now(),
                        self.codex.usage_limit_fallback_cooldown_seconds,
                    );
                    let kind = classify_auth_failure_for_account(kind, &err, account);
                    match kind {
                        AuthFailureKind::UsageLimited { reset_at } => {
                            self.mark_limit_reset_at(account, reset_at).await?;
                            warn!(
                                account = account.name.as_str(),
                                is_primary = account.is_primary,
                                reset_at = %reset_at,
                                error = %err,
                                "codex auth account usage-limited; trying next account"
                            );
                            auth_fallback_errors.push(format!(
                                "account '{}' usage-limited until {}: {}",
                                account.name, reset_at, err
                            ));
                        }
                        AuthFailureKind::AuthUnavailable => {
                            warn!(
                                account = account.name.as_str(),
                                is_primary = account.is_primary,
                                error = %err,
                                "codex auth account unavailable; trying next account"
                            );
                            auth_fallback_errors
                                .push(format!("account '{}' unavailable: {}", account.name, err));
                        }
                        AuthFailureKind::Other => {
                            return Err(err).with_context(|| {
                                format!(
                                    "codex review failed for account '{}' without fallback classification",
                                    account.name
                                )
                            });
                        }
                    }
                }
            }
        }

        bail!(
            "all codex auth accounts failed with usage-limit/auth errors: {}",
            auth_fallback_errors.join(" | ")
        );
    }

    async fn run_mention_container_with_sandbox(
        &self,
        ctx: &MentionCommandContext,
        sandbox_mode: &str,
        account: &AuthAccount,
    ) -> Result<MentionCommandResult> {
        let clone_url = self.clone_url(&ctx.repo)?;
        let repo_dir = "/work/repo";
        let browser_mcp = self.effective_browser_mcp(&self.codex.mcp_server_overrides.mention);
        let reasoning_effort =
            configured_reasoning_effort(self.codex.reasoning_effort.mention.as_deref());
        let script = Self::build_mention_command_script(
            ctx,
            &clone_url,
            &self.codex.auth_mount_path,
            AppServerCommandOptions {
                browser_mcp,
                mcp_server_overrides: &self.codex.mcp_server_overrides.mention,
                reasoning_effort,
            },
        );
        let StartedAppServer {
            container_id,
            browser_container_id,
            mut client,
        } = self
            .start_app_server_container(script, &account.auth_host_path, Vec::new(), browser_mcp)
            .await?;

        let mention_result = timeout(Duration::from_secs(self.codex.timeout_seconds), async {
            client.initialize().await?;
            client.initialized().await?;
            let thread_response = client
                .request(
                    "thread/start",
                    json!({
                        "cwd": repo_dir,
                        "approvalPolicy": "never",
                        "sandbox": sandbox_mode,
                        "developerInstructions": Self::mention_developer_instructions(ctx),
                    }),
                )
                .await?;
            let thread_id = thread_response
                .get("thread")
                .and_then(|thread| thread.get("id"))
                .and_then(|id| id.as_str())
                .ok_or_else(|| anyhow!("thread/start missing thread id"))?
                .to_string();

            self.exec_container_command(
                &container_id,
                vec![
                    "git".to_string(),
                    "config".to_string(),
                    "user.name".to_string(),
                    ctx.requester_name.clone(),
                ],
                Some(repo_dir),
            )
            .await?;
            self.exec_container_command(
                &container_id,
                vec![
                    "git".to_string(),
                    "config".to_string(),
                    "user.email".to_string(),
                    ctx.requester_email.clone(),
                ],
                Some(repo_dir),
            )
            .await?;
            self.exec_container_command(
                &container_id,
                vec![
                    "git".to_string(),
                    "remote".to_string(),
                    "set-url".to_string(),
                    "--push".to_string(),
                    "origin".to_string(),
                    "no_push://disabled".to_string(),
                ],
                Some(repo_dir),
            )
            .await?;
            let before_sha = self
                .exec_container_command(
                    &container_id,
                    vec![
                        "git".to_string(),
                        "rev-parse".to_string(),
                        "HEAD".to_string(),
                    ],
                    Some(repo_dir),
                )
                .await?
                .stdout
                .trim()
                .to_string();

            let turn_response = client
                .request(
                    "turn/start",
                    json!({
                        "threadId": thread_id.as_str(),
                        "cwd": repo_dir,
                        "input": [{ "type": "text", "text": ctx.prompt.as_str() }],
                    }),
                )
                .await?;
            let turn_id = turn_response
                .get("turn")
                .and_then(|turn| turn.get("id"))
                .and_then(|id| id.as_str())
                .ok_or_else(|| anyhow!("turn/start missing turn id"))?
                .to_string();
            let mut reply_message = client.stream_turn_message(&thread_id, &turn_id).await?;
            if reply_message.trim().is_empty() {
                reply_message = "Mention command completed.".to_string();
            }

            let after_sha = self
                .exec_container_command(
                    &container_id,
                    vec![
                        "git".to_string(),
                        "rev-parse".to_string(),
                        "HEAD".to_string(),
                    ],
                    Some(repo_dir),
                )
                .await?
                .stdout
                .trim()
                .to_string();
            let (status, commit_sha) = if after_sha != before_sha {
                let source_branch = ctx
                    .mr
                    .source_branch
                    .as_deref()
                    .filter(|value| !value.is_empty())
                    .ok_or_else(|| anyhow!("merge request source branch is missing"))?;
                if let Err(err) = self
                    .exec_container_command(
                        &container_id,
                        vec![
                            "git".to_string(),
                            "merge-base".to_string(),
                            "--is-ancestor".to_string(),
                            before_sha.clone(),
                            after_sha.clone(),
                        ],
                        Some(repo_dir),
                    )
                    .await
                {
                    bail!("mention command moved HEAD outside MR ancestry: {err}");
                }
                let commit_count_output = self
                    .exec_container_command(
                        &container_id,
                        vec![
                            "git".to_string(),
                            "rev-list".to_string(),
                            "--count".to_string(),
                            format!("{before_sha}..{after_sha}"),
                        ],
                        Some(repo_dir),
                    )
                    .await?;
                let commit_count = commit_count_output
                    .stdout
                    .trim()
                    .parse::<u64>()
                    .with_context(|| {
                        format!(
                            "parse commit count for mention command range {}..{}",
                            before_sha, after_sha
                        )
                    })?;
                if commit_count == 0 {
                    bail!("mention command moved HEAD without producing new commits");
                }
                let push_url_dq = clone_url.replace('\\', "\\\\").replace('"', "\\\"");
                self.exec_container_command(
                    &container_id,
                    vec![
                        "bash".to_string(),
                        "-lc".to_string(),
                        format!("git remote set-url --push origin \"{push_url_dq}\""),
                    ],
                    Some(repo_dir),
                )
                .await?;
                self.exec_container_command(
                    &container_id,
                    vec![
                        "git".to_string(),
                        "push".to_string(),
                        "origin".to_string(),
                        format!("HEAD:{source_branch}"),
                    ],
                    Some(repo_dir),
                )
                .await?;
                (MentionCommandStatus::Committed, Some(after_sha))
            } else {
                let worktree_state = self
                    .exec_container_command(
                        &container_id,
                        vec![
                            "git".to_string(),
                            "status".to_string(),
                            "--porcelain".to_string(),
                        ],
                        Some(repo_dir),
                    )
                    .await?;
                if !worktree_state.stdout.trim().is_empty() {
                    bail!("mention command left uncommitted changes without creating a commit");
                }
                (MentionCommandStatus::NoChanges, None)
            };

            Ok::<MentionCommandResult, anyhow::Error>(MentionCommandResult {
                status,
                commit_sha,
                reply_message,
            })
        })
        .await;

        let mention_result = match mention_result {
            Ok(Ok(result)) => Ok(result),
            Ok(Err(err)) => Err(self
                .enrich_error_with_browser_diagnostics(
                    err,
                    browser_container_id.as_deref(),
                    browser_mcp,
                )
                .await),
            Err(_) => Err(self
                .enrich_error_with_browser_diagnostics(
                    anyhow!("codex mention command timed out"),
                    browser_container_id.as_deref(),
                    browser_mcp,
                )
                .await),
        };

        self.cleanup_app_server_containers(&container_id, browser_container_id.as_deref())
            .await;

        mention_result
    }

    async fn run_mention_container(
        &self,
        ctx: &MentionCommandContext,
    ) -> Result<MentionCommandResult> {
        let now = Utc::now();
        let available_accounts = self.available_auth_accounts(now).await?;
        if available_accounts.is_empty() {
            bail!(
                "no available codex auth accounts (all accounts are waiting for usage-limit reset)"
            );
        }

        let mut auth_fallback_errors = Vec::new();
        for account in &available_accounts {
            let attempt_started_at = Utc::now();
            info!(
                account = account.name.as_str(),
                is_primary = account.is_primary,
                repo = ctx.repo.as_str(),
                iid = ctx.mr.iid,
                discussion_id = ctx.discussion_id.as_str(),
                trigger_note_id = ctx.trigger_note_id,
                "running codex mention command with auth account"
            );
            match self
                .run_mention_container_with_sandbox(ctx, self.sandbox_mode_value(), account)
                .await
            {
                Ok(result) => {
                    self.clear_limit_reset_if_stale(account, attempt_started_at)
                        .await?;
                    return Ok(result);
                }
                Err(err) => {
                    let kind = classify_auth_failure(
                        &err,
                        Utc::now(),
                        self.codex.usage_limit_fallback_cooldown_seconds,
                    );
                    let kind = classify_auth_failure_for_account(kind, &err, account);
                    match kind {
                        AuthFailureKind::UsageLimited { reset_at } => {
                            self.mark_limit_reset_at(account, reset_at).await?;
                            warn!(
                                account = account.name.as_str(),
                                is_primary = account.is_primary,
                                reset_at = %reset_at,
                                error = %err,
                                "codex auth account usage-limited for mention command; trying next account"
                            );
                            auth_fallback_errors.push(format!(
                                "account '{}' usage-limited until {}: {}",
                                account.name, reset_at, err
                            ));
                        }
                        AuthFailureKind::AuthUnavailable => {
                            warn!(
                                account = account.name.as_str(),
                                is_primary = account.is_primary,
                                error = %err,
                                "codex auth account unavailable for mention command; trying next account"
                            );
                            auth_fallback_errors
                                .push(format!("account '{}' unavailable: {}", account.name, err));
                        }
                        AuthFailureKind::Other => {
                            return Err(err).with_context(|| {
                                format!(
                                    "mention command failed for account '{}' without fallback classification",
                                    account.name
                                )
                            });
                        }
                    }
                }
            }
        }

        bail!(
            "all codex auth accounts failed with usage-limit/auth errors for mention command: {}",
            auth_fallback_errors.join(" | ")
        );
    }
}

#[async_trait]
impl CodexRunner for DockerCodexRunner {
    async fn run_review(&self, ctx: ReviewContext) -> Result<CodexResult> {
        info!(
            repo = ctx.repo.as_str(),
            iid = ctx.mr.iid,
            "starting codex review"
        );
        let output = self.run_app_server_review(&ctx).await?;
        parse_review_output(&output).with_context(|| {
            format!(
                "parse codex review output for repo {} merge request {}",
                ctx.repo, ctx.mr.iid
            )
        })
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
}

struct AppServerClient {
    input: Pin<Box<dyn tokio::io::AsyncWrite + Send>>,
    output: Pin<Box<dyn futures::Stream<Item = Result<LogOutput, bollard::errors::Error>> + Send>>,
    buffer: Vec<u8>,
    pending_notifications: VecDeque<Value>,
    reasoning_buffers: HashMap<String, ReasoningBuffer>,
    recent_runner_errors: VecDeque<String>,
    log_all_json: bool,
}

#[derive(Default)]
struct ReasoningBuffer {
    summary: String,
    text: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum TurnStreamNotificationOutcome {
    Continue,
    TurnCompleted,
}

impl AppServerClient {
    fn new(attach: bollard::container::AttachContainerResults, log_all_json: bool) -> Self {
        Self {
            input: attach.input,
            output: attach.output,
            buffer: Vec::new(),
            pending_notifications: VecDeque::new(),
            reasoning_buffers: HashMap::new(),
            recent_runner_errors: VecDeque::new(),
            log_all_json,
        }
    }

    async fn initialize(&mut self) -> Result<()> {
        let response = self
            .request(
                "initialize",
                json!({
                    "clientInfo": {
                        "name": "codex-gitlab-review",
                        "title": "Codex GitLab Review Service",
                        "version": env!("CARGO_PKG_VERSION"),
                    }
                }),
            )
            .await?;
        debug!(response = ?response, "codex app-server initialized");
        Ok(())
    }

    async fn initialized(&mut self) -> Result<()> {
        self.send_json(&json!({ "method": "initialized" })).await
    }

    async fn stream_review(&mut self, thread_id: &str, turn_id: &str) -> Result<String> {
        let mut review_text = None;
        loop {
            let message = self.next_notification().await?;
            let method = message
                .get("method")
                .and_then(|value| value.as_str())
                .unwrap_or("<unknown>");
            let params = message.get("params");
            if !matches_thread_turn(params, thread_id, turn_id) {
                continue;
            }

            let outcome = self.handle_turn_notification(
                method,
                params,
                thread_id,
                turn_id,
                |_, _| {},
                |item| {
                    if let Some(review) = item.get("review").and_then(|value| value.as_str())
                        && item.get("type").and_then(|value| value.as_str())
                            == Some("exitedReviewMode")
                    {
                        review_text = Some(review.to_string());
                    }
                },
            )?;
            if outcome == TurnStreamNotificationOutcome::TurnCompleted {
                break;
            }
        }

        review_text.ok_or_else(|| anyhow!("codex review missing review text"))
    }

    async fn stream_turn_message(&mut self, thread_id: &str, turn_id: &str) -> Result<String> {
        let final_message = RefCell::new(None);
        let message_deltas: RefCell<HashMap<String, String>> = RefCell::new(HashMap::new());
        loop {
            let message = self.next_notification().await?;
            let method = message
                .get("method")
                .and_then(|value| value.as_str())
                .unwrap_or("<unknown>");
            let params = message.get("params");
            if !matches_thread_turn(params, thread_id, turn_id) {
                continue;
            }

            let outcome = self.handle_turn_notification(
                method,
                params,
                thread_id,
                turn_id,
                |item_id, delta| {
                    if item_id != "<unknown>" {
                        message_deltas
                            .borrow_mut()
                            .entry(item_id.to_string())
                            .or_default()
                            .push_str(delta);
                    }
                },
                |item| {
                    if matches!(
                        item.get("type").and_then(|value| value.as_str()),
                        Some("agentMessage") | Some("AgentMessage")
                    ) {
                        let item_id = item
                            .get("id")
                            .and_then(|value| value.as_str())
                            .unwrap_or("<unknown>");
                        let extracted = extract_agent_message_text(item)
                            .or_else(|| message_deltas.borrow_mut().remove(item_id))
                            .unwrap_or_default();
                        if !extracted.trim().is_empty() {
                            info!(
                                item_id,
                                kind = "agent",
                                message = extracted.as_str(),
                                "codex item message"
                            );
                            *final_message.borrow_mut() = Some(extracted);
                        }
                    }
                },
            )?;
            if outcome == TurnStreamNotificationOutcome::TurnCompleted {
                break;
            }
        }

        if let Some(message) = final_message.into_inner() {
            return Ok(message);
        }
        let fallback = message_deltas
            .into_inner()
            .into_values()
            .find(|value| !value.trim().is_empty())
            .unwrap_or_default();
        Ok(fallback)
    }

    fn handle_turn_notification<FDelta, FCompleted>(
        &mut self,
        method: &str,
        params: Option<&Value>,
        thread_id: &str,
        turn_id: &str,
        mut on_agent_message_delta: FDelta,
        mut on_item_completed: FCompleted,
    ) -> Result<TurnStreamNotificationOutcome>
    where
        FDelta: FnMut(&str, &str),
        FCompleted: FnMut(&Value),
    {
        match method {
            "turn/started" => {
                info!(thread_id, turn_id, "codex turn started");
            }
            "item/agentMessage/delta" => {
                if let Some(delta) = params
                    .and_then(|value| value.get("delta"))
                    .and_then(|value| value.as_str())
                {
                    let item_id = params
                        .and_then(|value| value.get("itemId"))
                        .and_then(|value| value.as_str())
                        .unwrap_or("<unknown>");
                    on_agent_message_delta(item_id, delta);
                }
            }
            "item/commandExecution/outputDelta" => {
                if let Some(delta) = params
                    .and_then(|value| value.get("delta"))
                    .and_then(|value| value.as_str())
                {
                    let item_id = params
                        .and_then(|value| value.get("itemId"))
                        .and_then(|value| value.as_str())
                        .unwrap_or("<unknown>");
                    info!(item_id, kind = "command", output = %delta, "codex command output");
                }
            }
            "item/reasoning/summaryTextDelta" => {
                if let Some(delta) = params
                    .and_then(|value| value.get("delta"))
                    .and_then(|value| value.as_str())
                {
                    let item_id = params
                        .and_then(|value| value.get("itemId"))
                        .and_then(|value| value.as_str())
                        .unwrap_or("<unknown>");
                    if item_id != "<unknown>" {
                        self.reasoning_buffers
                            .entry(item_id.to_string())
                            .or_default()
                            .summary
                            .push_str(delta);
                    }
                }
            }
            "item/reasoning/textDelta" => {
                if let Some(delta) = params
                    .and_then(|value| value.get("delta"))
                    .and_then(|value| value.as_str())
                {
                    let item_id = params
                        .and_then(|value| value.get("itemId"))
                        .and_then(|value| value.as_str())
                        .unwrap_or("<unknown>");
                    if item_id != "<unknown>" {
                        self.reasoning_buffers
                            .entry(item_id.to_string())
                            .or_default()
                            .text
                            .push_str(delta);
                    }
                }
            }
            "item/reasoning/summaryPartAdded" => {
                let item_id = params
                    .and_then(|value| value.get("itemId"))
                    .and_then(|value| value.as_str())
                    .unwrap_or("<unknown>");
                if item_id != "<unknown>" {
                    let entry = self
                        .reasoning_buffers
                        .entry(item_id.to_string())
                        .or_default();
                    if !entry.summary.is_empty() {
                        entry.summary.push('\n');
                    }
                }
            }
            "item/started" => {
                if let Some(item) = params.and_then(|value| value.get("item"))
                    && let Some(item_type) = item.get("type").and_then(|value| value.as_str())
                {
                    match item_type {
                        "commandExecution" => {
                            let item_id = item
                                .get("id")
                                .and_then(|value| value.as_str())
                                .unwrap_or("<unknown>");
                            let command = item
                                .get("command")
                                .and_then(|value| value.as_str())
                                .unwrap_or("<unknown>");
                            let cwd = item
                                .get("cwd")
                                .and_then(|value| value.as_str())
                                .unwrap_or("<unknown>");
                            let status = item
                                .get("status")
                                .and_then(|value| value.as_str())
                                .unwrap_or("<unknown>");
                            info!(item_id, command, cwd, status, "codex command started");
                        }
                        "reasoning" => {
                            if self.log_all_json {
                                debug!(item_type, "codex item started");
                            }
                        }
                        _ => {
                            info!(item_type, "codex item started");
                        }
                    }
                }
            }
            "item/completed" => {
                if let Some(item) = params.and_then(|value| value.get("item"))
                    && let Some(item_type) = item.get("type").and_then(|value| value.as_str())
                {
                    if item_type == "reasoning" {
                        if let Some(item_id) = item.get("id").and_then(|value| value.as_str())
                            && let Some(buffer) = self.reasoning_buffers.remove(item_id)
                        {
                            let reasoning = if !buffer.summary.trim().is_empty() {
                                buffer.summary
                            } else {
                                buffer.text
                            };
                            if !reasoning.trim().is_empty() {
                                info!(
                                    item_id,
                                    reasoning = reasoning.as_str(),
                                    "codex reasoning completed"
                                );
                            }
                        }
                    } else if item_type == "commandExecution" {
                        let item_id = item
                            .get("id")
                            .and_then(|value| value.as_str())
                            .unwrap_or("<unknown>");
                        let command = item
                            .get("command")
                            .and_then(|value| value.as_str())
                            .unwrap_or("<unknown>");
                        let cwd = item
                            .get("cwd")
                            .and_then(|value| value.as_str())
                            .unwrap_or("<unknown>");
                        let status = item
                            .get("status")
                            .and_then(|value| value.as_str())
                            .unwrap_or("<unknown>");
                        let exit_code = item.get("exitCode").and_then(|value| value.as_i64());
                        let duration_ms = item.get("durationMs").and_then(|value| value.as_i64());
                        info!(
                            item_id,
                            command, cwd, status, exit_code, duration_ms, "codex command completed"
                        );
                    } else {
                        info!(item_type, "codex item completed");
                    }
                    on_item_completed(item);
                }
            }
            "turn/completed" => {
                let status = params
                    .and_then(|value| value.get("turn"))
                    .and_then(|value| value.get("status"))
                    .and_then(|value| value.as_str())
                    .unwrap_or("unknown");
                info!(status, "codex turn completed");
                if status == "failed" {
                    let error_message = params
                        .and_then(|value| value.get("turn"))
                        .and_then(|value| value.get("error"))
                        .and_then(|value| value.get("message"))
                        .and_then(|value| value.as_str())
                        .unwrap_or("unknown error");
                    return Err(anyhow!("codex turn failed: {}", error_message));
                }
                return Ok(TurnStreamNotificationOutcome::TurnCompleted);
            }
            "error" => {
                if let Some(error_message) = params
                    .and_then(|value| value.get("error"))
                    .and_then(|value| value.get("message"))
                    .and_then(|value| value.as_str())
                {
                    warn!(error_message, "codex error");
                }
            }
            _ => {
                if self.log_all_json {
                    debug!(method, "codex notification");
                }
            }
        }
        Ok(TurnStreamNotificationOutcome::Continue)
    }

    async fn request(&mut self, method: &str, params: Value) -> Result<Value> {
        let id = Value::String(Uuid::new_v4().to_string());
        let request = json!({
            "id": id,
            "method": method,
            "params": params,
        });
        self.send_json(&request).await?;

        loop {
            let message = self.next_message().await?;
            let method_name = message.get("method").and_then(|value| value.as_str());
            let message_id = message.get("id");
            if let (Some(method_name), Some(message_id)) = (method_name, message_id) {
                self.handle_server_request(method_name, message_id, message.get("params"))
                    .await?;
                continue;
            }
            if message_id == Some(&id) {
                if let Some(error) = message.get("error") {
                    return Err(anyhow!("codex app-server error: {}", error));
                }
                if let Some(result) = message.get("result") {
                    return Ok(result.clone());
                }
                return Err(anyhow!("codex app-server response missing result"));
            }
            if method_name.is_some() {
                self.pending_notifications.push_back(message);
            }
        }
    }

    async fn next_notification(&mut self) -> Result<Value> {
        if let Some(notification) = self.pending_notifications.pop_front() {
            return Ok(notification);
        }

        loop {
            let message = self.next_message().await?;
            let method = message.get("method").and_then(|value| value.as_str());
            let id = message.get("id");
            if let (Some(method), Some(id)) = (method, id) {
                self.handle_server_request(method, id, message.get("params"))
                    .await?;
                continue;
            }
            if method.is_some() {
                return Ok(message);
            }
        }
    }

    async fn handle_server_request(
        &mut self,
        method: &str,
        id: &Value,
        params: Option<&Value>,
    ) -> Result<()> {
        debug!(method, params = ?params, "codex app-server request");
        match method {
            "item/commandExecution/requestApproval" => {
                self.send_json(&json!({
                    "id": id,
                    "result": { "decision": "accept" }
                }))
                .await
            }
            "item/fileChange/requestApproval" => {
                self.send_json(&json!({
                    "id": id,
                    "result": { "decision": "accept" }
                }))
                .await
            }
            other => {
                warn!(method = other, "unsupported codex app-server request");
                self.send_json(&json!({
                    "id": id,
                    "error": { "message": "unsupported request" }
                }))
                .await
            }
        }
    }

    async fn send_json(&mut self, value: &Value) -> Result<()> {
        let line = serde_json::to_string(value)?;
        if self.log_all_json {
            debug!(json = %line, "codex app-server message");
        }
        self.input.write_all(line.as_bytes()).await?;
        self.input.write_all(b"\n").await?;
        self.input.flush().await?;
        Ok(())
    }

    async fn next_message(&mut self) -> Result<Value> {
        loop {
            if let Some(pos) = self.buffer.iter().position(|byte| *byte == b'\n') {
                let line = self.buffer.drain(..=pos).collect::<Vec<u8>>();
                let line = String::from_utf8_lossy(&line);
                let trimmed = line.trim();
                if trimmed.is_empty() {
                    continue;
                }
                if trimmed.starts_with("codex-runner:") {
                    info!("{}", trimmed);
                    continue;
                }
                if trimmed.starts_with("codex-runner-warn:") {
                    warn!("{}", trimmed);
                    continue;
                }
                if trimmed.starts_with("codex-runner-error:") {
                    warn!("{}", trimmed);
                    self.push_runner_error(trimmed);
                    continue;
                }
                if trimmed.starts_with("codex-install:") {
                    info!("{}", trimmed);
                    continue;
                }
                if trimmed.starts_with("codex-install-error:") {
                    warn!("{}", trimmed);
                    self.push_runner_error(trimmed);
                    continue;
                }
                match serde_json::from_str::<Value>(trimmed) {
                    Ok(value) => {
                        if self.log_all_json {
                            debug!(json = %trimmed, "codex app-server message");
                        }
                        return Ok(value);
                    }
                    Err(_) => {
                        if self.log_all_json {
                            debug!(line = %trimmed, "codex app-server non-json output");
                        }
                        continue;
                    }
                }
            }

            match self.output.next().await {
                Some(Ok(output)) => match output {
                    LogOutput::StdOut { message }
                    | LogOutput::StdErr { message }
                    | LogOutput::Console { message } => {
                        self.buffer.extend_from_slice(&message);
                    }
                    LogOutput::StdIn { .. } => {}
                },
                Some(Err(err)) => {
                    return Err(with_recent_runner_errors(
                        anyhow!(err).context("read codex app-server output"),
                        &self.recent_runner_errors,
                    ));
                }
                None => {
                    return Err(with_recent_runner_errors(
                        anyhow!("codex app-server closed stdout"),
                        &self.recent_runner_errors,
                    ));
                }
            }
        }
    }

    fn push_runner_error(&mut self, line: &str) {
        const MAX_RECENT_RUNNER_ERRORS: usize = 8;
        self.recent_runner_errors.push_back(line.to_string());
        while self.recent_runner_errors.len() > MAX_RECENT_RUNNER_ERRORS {
            self.recent_runner_errors.pop_front();
        }
    }
}

fn matches_thread_turn(params: Option<&Value>, thread_id: &str, turn_id: &str) -> bool {
    let Some(params) = params else {
        return true;
    };
    let thread_matches = params
        .get("threadId")
        .and_then(|value| value.as_str())
        .map(|value| value == thread_id)
        .unwrap_or(true);
    let turn_matches = params
        .get("turnId")
        .and_then(|value| value.as_str())
        .map(|value| value == turn_id)
        .unwrap_or(true);
    thread_matches && turn_matches
}

fn extract_agent_message_text(item: &Value) -> Option<String> {
    let content = item.get("content")?.as_array()?;
    let mut parts = Vec::new();
    for entry in content {
        if entry.get("type").and_then(|value| value.as_str()) == Some("Text")
            && let Some(text) = entry.get("text").and_then(|value| value.as_str())
            && !text.trim().is_empty()
        {
            parts.push(text.to_string());
        }
    }
    if parts.is_empty() {
        None
    } else {
        Some(parts.join("\n\n"))
    }
}

fn parse_review_output(text: &str) -> Result<CodexResult> {
    let trimmed = text.trim();
    if trimmed.is_empty() {
        return Ok(CodexResult::Pass {
            summary: "no issues found".to_string(),
        });
    }

    if let Some(json_text) = extract_json_block(trimmed)
        && let Ok(parsed) = serde_json::from_str::<CodexOutput>(&json_text)
    {
        return match parsed.verdict.as_str() {
            "pass" => Ok(CodexResult::Pass {
                summary: parsed.summary,
            }),
            "comment" => Ok(CodexResult::Comment {
                summary: parsed.summary,
                body: parsed.comment_markdown,
            }),
            other => Err(anyhow!("unknown verdict: {}", other)),
        };
    }

    let summary = trimmed
        .lines()
        .find(|line| !line.trim().is_empty())
        .unwrap_or("Codex review")
        .trim()
        .to_string();
    Ok(CodexResult::Comment {
        summary,
        body: trimmed.to_string(),
    })
}

fn extract_json_block(text: &str) -> Option<String> {
    let start = text.find('{')?;
    let end = text.rfind('}')?;
    if end < start {
        return None;
    }
    Some(text[start..=end].to_string())
}

fn with_recent_runner_errors(
    err: anyhow::Error,
    recent_runner_errors: &VecDeque<String>,
) -> anyhow::Error {
    if recent_runner_errors.is_empty() {
        err
    } else {
        err.context(format!(
            "recent runner errors: {}",
            recent_runner_errors
                .iter()
                .map(String::as_str)
                .collect::<Vec<_>>()
                .join(" | ")
        ))
    }
}

fn classify_auth_failure(
    err: &anyhow::Error,
    now: DateTime<Utc>,
    fallback_cooldown_seconds: u64,
) -> AuthFailureKind {
    let chain = format!("{err:#}");
    let chain_lower = chain.to_ascii_lowercase();
    if is_usage_limit_error(&chain_lower) {
        let reset_at = parse_usage_limit_reset_at(&chain, now)
            .unwrap_or_else(|| safe_reset_at_from_cooldown(now, fallback_cooldown_seconds));
        return AuthFailureKind::UsageLimited { reset_at };
    }
    if is_auth_unavailable_error(&chain_lower) {
        return AuthFailureKind::AuthUnavailable;
    }
    AuthFailureKind::Other
}

fn classify_auth_failure_for_account(
    base: AuthFailureKind,
    err: &anyhow::Error,
    account: &AuthAccount,
) -> AuthFailureKind {
    if base != AuthFailureKind::Other {
        return base;
    }
    let chain_lower = format!("{err:#}").to_ascii_lowercase();
    if is_account_startup_failure(&chain_lower, &account.auth_host_path) {
        AuthFailureKind::AuthUnavailable
    } else {
        AuthFailureKind::Other
    }
}

fn is_usage_limit_error(error_text_lower: &str) -> bool {
    let explicit = [
        "rate_limit_exceeded",
        "insufficient_quota",
        "x-ratelimit",
        "usage limit exceeded",
    ]
    .iter()
    .any(|needle| error_text_lower.contains(needle));
    let reached_with_retry_hint = error_text_lower.contains("rate limit reached")
        && error_text_lower.contains("try again in");
    explicit || reached_with_retry_hint
}

fn is_auth_unavailable_error(error_text_lower: &str) -> bool {
    [
        "not authenticated",
        "authentication required",
        "invalid credentials",
        "invalid api key",
        "auth.json",
        "please run codex auth login",
    ]
    .iter()
    .any(|needle| error_text_lower.contains(needle))
}

fn is_account_startup_failure(error_text_lower: &str, auth_host_path: &str) -> bool {
    let path_lower = auth_host_path.to_ascii_lowercase();
    if path_lower.is_empty() || !error_text_lower.contains(path_lower.as_str()) {
        return false;
    }
    [
        "invalid mount config",
        "bind source path does not exist",
        "no such file or directory",
        "mount",
    ]
    .iter()
    .any(|needle| error_text_lower.contains(needle))
}

fn parse_usage_limit_reset_at(text: &str, now: DateTime<Utc>) -> Option<DateTime<Utc>> {
    let absolute = parse_rfc3339_reset_timestamp(text, now);
    let relative = parse_relative_reset_timestamp(text, now);
    match (absolute, relative) {
        (Some(abs), Some(rel)) => Some(abs.min(rel)),
        (Some(abs), None) => Some(abs),
        (None, Some(rel)) => Some(rel),
        (None, None) => None,
    }
}

fn parse_rfc3339_reset_timestamp(text: &str, now: DateTime<Utc>) -> Option<DateTime<Utc>> {
    let mut candidates = Vec::new();
    for token in text.split_whitespace() {
        let cleaned = token.trim_matches(|ch: char| {
            matches!(
                ch,
                ',' | ';' | '.' | '"' | '\'' | '(' | ')' | '[' | ']' | '{' | '}' | '<' | '>'
            )
        });
        if cleaned.is_empty() {
            continue;
        }
        if let Ok(parsed) = DateTime::parse_from_rfc3339(cleaned) {
            let utc = parsed.with_timezone(&Utc);
            if utc > now {
                candidates.push(utc);
            }
        }
    }
    candidates.into_iter().min()
}

fn parse_relative_reset_timestamp(text: &str, now: DateTime<Utc>) -> Option<DateTime<Utc>> {
    let lower = text.to_ascii_lowercase();
    for anchor in ["try again in", "resets in", "retry in"] {
        if let Some(idx) = lower.find(anchor) {
            let slice = &lower[idx + anchor.len()..];
            if let Some(seconds) = parse_duration_seconds_from_text(slice) {
                let duration = safe_duration_from_seconds(seconds);
                return now.checked_add_signed(duration);
            }
        }
    }
    None
}

fn parse_duration_seconds_from_text(text: &str) -> Option<i64> {
    let tokens = text
        .split_whitespace()
        .map(|raw_token| {
            raw_token.trim_matches(|ch: char| {
                matches!(
                    ch,
                    ',' | ';' | '.' | '"' | '\'' | '(' | ')' | '[' | ']' | '{' | '}' | '<' | '>'
                )
            })
        })
        .filter(|token| !token.is_empty())
        .collect::<Vec<_>>();

    let mut total = 0i64;
    let mut consumed = false;
    let mut idx = 0usize;
    while idx < tokens.len() {
        if let Some(seconds) = parse_duration_token_seconds(tokens[idx]) {
            total = total.saturating_add(seconds);
            consumed = true;
            idx += 1;
            continue;
        }

        if let Ok(value) = tokens[idx].parse::<f64>()
            && let Some(unit_token) = tokens.get(idx + 1)
            && let Some(unit_seconds) = duration_unit_seconds(unit_token)
        {
            total = total.saturating_add(seconds_from_numeric_value(value, unit_seconds));
            consumed = true;
            idx += 2;
            continue;
        }

        if consumed && matches!(tokens[idx], "and" | "then") {
            idx += 1;
            continue;
        }

        if consumed {
            break;
        }
        idx += 1;
    }

    if consumed && total > 0i64 {
        Some(total)
    } else {
        None
    }
}

fn parse_duration_token_seconds(token: &str) -> Option<i64> {
    let mut numeric_end = 0usize;
    let mut seen_digit = false;
    let mut seen_dot = false;
    for (idx, ch) in token.char_indices() {
        if ch.is_ascii_digit() {
            seen_digit = true;
            numeric_end = idx + ch.len_utf8();
            continue;
        }
        if ch == '.' && seen_digit && !seen_dot {
            seen_dot = true;
            numeric_end = idx + ch.len_utf8();
            continue;
        }
        break;
    }
    if !seen_digit || numeric_end == 0 || numeric_end >= token.len() {
        return None;
    }
    let value = token[..numeric_end].parse::<f64>().ok()?;
    let unit = &token[numeric_end..];
    duration_unit_seconds(unit).map(|seconds| seconds_from_numeric_value(value, seconds))
}

fn duration_unit_seconds(unit: &str) -> Option<i64> {
    match unit {
        "d" | "day" | "days" => Some(86_400),
        "h" | "hr" | "hrs" | "hour" | "hours" => Some(3_600),
        "m" | "min" | "mins" | "minute" | "minutes" => Some(60),
        "s" | "sec" | "secs" | "second" | "seconds" => Some(1),
        _ => None,
    }
}

fn seconds_from_numeric_value(value: f64, unit_seconds: i64) -> i64 {
    if !value.is_finite() || value <= 0.0 {
        return 0;
    }
    let total = value * unit_seconds as f64;
    if total >= i64::MAX as f64 {
        i64::MAX
    } else {
        total.ceil() as i64
    }
}

fn safe_cooldown_duration(cooldown_seconds: u64) -> ChronoDuration {
    let seconds = i64::try_from(cooldown_seconds).ok().unwrap_or(i64::MAX);
    safe_duration_from_seconds(seconds)
}

fn safe_duration_from_seconds(seconds: i64) -> ChronoDuration {
    const MAX_CHRONO_SECONDS: i64 = i64::MAX / 1000;
    let clamped = seconds.clamp(0, MAX_CHRONO_SECONDS);
    ChronoDuration::seconds(clamped)
}

fn safe_reset_at_from_cooldown(now: DateTime<Utc>, cooldown_seconds: u64) -> DateTime<Utc> {
    let cooldown = safe_cooldown_duration(cooldown_seconds);
    if let Some(reset_at) = now.checked_add_signed(cooldown) {
        return reset_at;
    }
    now.checked_add_signed(ChronoDuration::days(3650))
        .unwrap_or(now)
}

fn should_clear_limit_reset(
    existing_reset_at: DateTime<Utc>,
    attempt_started_at: DateTime<Utc>,
) -> bool {
    existing_reset_at <= attempt_started_at
}

fn auth_account_state_key(name: &str, auth_host_path: &str) -> String {
    format!("{name}::{auth_host_path}")
}

#[derive(Debug, Deserialize)]
struct CodexOutput {
    verdict: String,
    summary: String,
    comment_markdown: String,
}

#[derive(Debug)]
struct ContainerExecOutput {
    exit_code: i64,
    stdout: String,
    stderr: String,
}

fn validate_container_exec_result(
    command: &[String],
    cwd: Option<&str>,
    output: ContainerExecOutput,
) -> Result<ContainerExecOutput> {
    if output.exit_code == 0 {
        return Ok(output);
    }

    let command_display = format_command_for_log(command);
    let cwd_display = cwd.unwrap_or("<default>");
    let stderr = output.stderr.trim();
    if stderr.is_empty() {
        bail!(
            "docker exec command failed with exit code {} (command: {}, cwd: {})",
            output.exit_code,
            command_display,
            cwd_display
        );
    }

    bail!(
        "docker exec command failed with exit code {} (command: {}, cwd: {}): {}",
        output.exit_code,
        command_display,
        cwd_display,
        stderr
    );
}

fn format_command_for_log(command: &[String]) -> String {
    command
        .iter()
        .map(|value| shell_quote(value))
        .collect::<Vec<_>>()
        .join(" ")
}

fn browser_container_cmd(
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

fn uses_headless_shell_wrapper(image: &str, configured_entrypoint: &[String]) -> bool {
    configured_entrypoint.is_empty() && is_headless_shell_image(image)
}

fn is_headless_shell_image(image: &str) -> bool {
    let repository = image_repository(image);
    repository == "chromedp/headless-shell" || repository.ends_with("/chromedp/headless-shell")
}

fn image_repository(image: &str) -> &str {
    let image = image.split('@').next().unwrap_or(image);
    match image.rsplit_once(':') {
        Some((repository, suffix)) if !suffix.contains('/') => repository,
        _ => image,
    }
}

fn tail_log_lines(text: &str) -> Vec<String> {
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

fn truncate_log_line(line: &str, max_chars: usize) -> String {
    let mut truncated = line.chars().take(max_chars).collect::<String>();
    if line.chars().count() > max_chars {
        truncated.push_str("...");
    }
    truncated
}

fn browser_logs_report_ready(log_tail: &BrowserLogTail, expected_port: u16) -> bool {
    log_tail
        .stdout
        .iter()
        .chain(log_tail.stderr.iter())
        .filter_map(|line| extract_devtools_port(line))
        .any(|port| port == expected_port)
}

fn extract_devtools_port(line: &str) -> Option<u16> {
    let marker = "DevTools listening on ";
    let url = line.split_once(marker)?.1.split_whitespace().next()?;
    Url::parse(url).ok()?.port_or_known_default()
}

fn browser_container_has_exited(state: Option<&BrowserContainerStateSnapshot>) -> bool {
    let Some(state) = state else {
        return false;
    };
    matches!(state.status.as_deref(), Some("exited" | "dead"))
}

fn browser_container_state_snapshot(
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

fn shell_quote(input: &str) -> String {
    format!("'{}'", input.replace('\'', "'\"'\"'"))
}

fn escape_toml_basic_string(value: &str) -> String {
    value.replace('\\', "\\\\").replace('"', "\\\"")
}

fn toml_basic_string(value: &str) -> String {
    format!("\"{}\"", escape_toml_basic_string(value))
}

fn browser_mcp_prereq_script(browser_mcp: Option<&BrowserMcpConfig>) -> String {
    let Some(browser_mcp) = browser_mcp else {
        return String::new();
    };
    let command_q = shell_quote(&browser_mcp.mcp_command);
    format!(
        r#"browser_mcp_command={command_q}
if ! command -v "$browser_mcp_command" >/dev/null 2>&1; then
  echo "codex-runner-error: browser MCP requires $browser_mcp_command in the Codex image"
  exit 1
fi
"#,
    )
}

fn effective_browser_mcp<'a>(
    browser_mcp: Option<&'a BrowserMcpConfig>,
    mcp_server_overrides: &BTreeMap<String, bool>,
) -> Option<&'a BrowserMcpConfig> {
    let browser_mcp = browser_mcp?;
    if matches!(
        mcp_server_overrides.get(browser_mcp.server_name.as_str()),
        Some(false)
    ) {
        return None;
    }
    Some(browser_mcp)
}

fn browser_wait_script(browser_mcp: Option<&BrowserMcpConfig>) -> String {
    if browser_mcp.is_none() {
        return String::new();
    }
    format!(
        r#"wait_for_browser_mcp() {{
  deadline=$((SECONDS + 30))
  while [ "$SECONDS" -lt "$deadline" ]; do
    if exec 3<>/dev/tcp/127.0.0.1/{port} 2>/dev/null; then
      printf 'GET /json/version HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n' >&3
      if IFS= read -r status_line <&3 && printf '%s' "$status_line" | grep -q ' 200 '; then
        exec 3<&-
        exec 3>&-
        return 0
      fi
      exec 3<&-
      exec 3>&-
    fi
    sleep 1
  done
  echo "codex-runner-error: browser MCP endpoint did not become ready at http://127.0.0.1:{port}/json/version"
  exit 1
}}
wait_for_browser_mcp
"#,
        port = BROWSER_MCP_REMOTE_DEBUGGING_PORT,
    )
}

fn configured_reasoning_effort(value: Option<&str>) -> Option<&str> {
    value.map(str::trim).filter(|value| !value.is_empty())
}

fn codex_app_server_exec_command(
    browser_mcp: Option<&BrowserMcpConfig>,
    mcp_server_overrides: &BTreeMap<String, bool>,
    reasoning_effort: Option<&str>,
) -> String {
    if browser_mcp.is_none() && mcp_server_overrides.is_empty() && reasoning_effort.is_none() {
        return "exec codex app-server".to_string();
    }

    let mut cmd_parts = vec!["exec codex".to_string()];
    if let Some(reasoning_effort) = reasoning_effort {
        let override_value = format!(
            "model_reasoning_effort={}",
            toml_basic_string(reasoning_effort)
        );
        cmd_parts.push(format!("-c {}", shell_quote(&override_value)));
    }
    if let Some(browser_mcp) = browser_mcp {
        // Codex CLI `-c key=value` overrides split nested paths on `.` before
        // TOML parsing. Quoted TOML dotted-key segments therefore do not work
        // here: `mcp_servers."foo.bar".enabled=true` is treated as a literal
        // server name containing quotes, not as server `foo.bar`.
        let args_override = format!(
            "mcp_servers.{}.args=[{args}]",
            browser_mcp.server_name,
            args = browser_mcp
                .mcp_args
                .iter()
                .map(|arg| toml_basic_string(arg))
                .chain(std::iter::once(toml_basic_string(&format!(
                    "--browserUrl=http://127.0.0.1:{}",
                    BROWSER_MCP_REMOTE_DEBUGGING_PORT
                ))))
                .collect::<Vec<_>>()
                .join(",")
        );
        for override_value in [
            format!(
                "mcp_servers.{}.command={}",
                browser_mcp.server_name,
                toml_basic_string(&browser_mcp.mcp_command)
            ),
            args_override,
            format!("mcp_servers.{}.enabled=true", browser_mcp.server_name),
        ] {
            cmd_parts.push(format!("-c {}", shell_quote(&override_value)));
        }
    }
    for (server_name, enabled) in mcp_server_overrides {
        let override_value = format!("mcp_servers.{server_name}.enabled={enabled}");
        cmd_parts.push(format!("-c {}", shell_quote(&override_value)));
    }
    cmd_parts.push("app-server".to_string());
    cmd_parts.join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{DepsConfig, FallbackAuthAccountConfig, McpServerOverridesConfig};
    use chrono::TimeZone;
    use std::collections::BTreeMap;

    #[test]
    fn parse_review_output_json_pass() -> Result<()> {
        let text = r#"{"verdict":"pass","summary":"ok","comment_markdown":""}"#;
        let result = parse_review_output(text)?;
        match result {
            CodexResult::Pass { summary } => {
                assert_eq!(summary, "ok");
                Ok(())
            }
            _ => bail!("expected pass"),
        }
    }

    #[test]
    fn parse_review_output_json_comment() -> Result<()> {
        let text = r#"{"verdict":"comment","summary":"needs changes","comment_markdown":"- fix"}"#;
        let result = parse_review_output(text)?;
        match result {
            CodexResult::Comment { summary, body } => {
                assert_eq!(summary, "needs changes");
                assert_eq!(body, "- fix");
                Ok(())
            }
            _ => bail!("expected comment"),
        }
    }

    #[test]
    fn parse_review_output_fallback_comment() -> Result<()> {
        let text = "Looks good overall\n\n- minor nit";
        let result = parse_review_output(text)?;
        match result {
            CodexResult::Comment { summary, body } => {
                assert_eq!(summary, "Looks good overall");
                assert_eq!(body, text);
                Ok(())
            }
            _ => bail!("expected comment"),
        }
    }

    #[test]
    fn parse_usage_limit_reset_at_supports_rfc3339() {
        let now = Utc
            .with_ymd_and_hms(2026, 3, 2, 10, 0, 0)
            .single()
            .expect("valid");
        let text = "rate limit reached; resets at 2026-03-02T12:30:00Z";
        let reset = parse_usage_limit_reset_at(text, now).expect("parsed reset");
        assert_eq!(
            reset,
            Utc.with_ymd_and_hms(2026, 3, 2, 12, 30, 0)
                .single()
                .expect("valid")
        );
    }

    #[test]
    fn parse_usage_limit_reset_at_supports_compact_relative_duration() {
        let now = Utc
            .with_ymd_and_hms(2026, 3, 2, 10, 0, 0)
            .single()
            .expect("valid");
        let text = "usage limit exceeded, try again in 1h 20m";
        let reset = parse_usage_limit_reset_at(text, now).expect("parsed reset");
        assert_eq!(
            reset,
            Utc.with_ymd_and_hms(2026, 3, 2, 11, 20, 0)
                .single()
                .expect("valid")
        );
    }

    #[test]
    fn parse_usage_limit_reset_at_supports_spaced_relative_duration() {
        let now = Utc
            .with_ymd_and_hms(2026, 3, 2, 10, 0, 0)
            .single()
            .expect("valid");
        let text = "quota reached; try again in 1 hour 30 minutes";
        let reset = parse_usage_limit_reset_at(text, now).expect("parsed reset");
        assert_eq!(
            reset,
            Utc.with_ymd_and_hms(2026, 3, 2, 11, 30, 0)
                .single()
                .expect("valid")
        );
    }

    #[test]
    fn parse_usage_limit_reset_at_supports_conjunction_in_duration() {
        let now = Utc
            .with_ymd_and_hms(2026, 3, 2, 10, 0, 0)
            .single()
            .expect("valid");
        let text = "usage limit exceeded; try again in 1 hour and 30 minutes";
        let reset = parse_usage_limit_reset_at(text, now).expect("parsed reset");
        assert_eq!(
            reset,
            Utc.with_ymd_and_hms(2026, 3, 2, 11, 30, 0)
                .single()
                .expect("valid")
        );
    }

    #[test]
    fn parse_usage_limit_reset_at_supports_fractional_seconds() {
        let now = Utc
            .with_ymd_and_hms(2026, 3, 2, 10, 0, 0)
            .single()
            .expect("valid");
        let text = "usage limit exceeded; try again in 2.3s";
        let reset = parse_usage_limit_reset_at(text, now).expect("parsed reset");
        assert_eq!(
            reset,
            Utc.with_ymd_and_hms(2026, 3, 2, 10, 0, 3)
                .single()
                .expect("valid")
        );
    }

    #[test]
    fn classify_auth_failure_usage_limit_falls_back_to_default_cooldown_when_unparseable() {
        let now = Utc
            .with_ymd_and_hms(2026, 3, 2, 10, 0, 0)
            .single()
            .expect("valid");
        let err = anyhow!("codex turn failed: usage limit exceeded");
        let kind = classify_auth_failure(&err, now, 3600);
        assert_eq!(
            kind,
            AuthFailureKind::UsageLimited {
                reset_at: Utc
                    .with_ymd_and_hms(2026, 3, 2, 11, 0, 0)
                    .single()
                    .expect("valid"),
            }
        );
    }

    #[test]
    fn classify_auth_failure_handles_huge_cooldown_without_panicking() {
        let now = Utc
            .with_ymd_and_hms(2026, 3, 2, 10, 0, 0)
            .single()
            .expect("valid");
        let err = anyhow!("codex turn failed: usage limit exceeded");
        let kind = classify_auth_failure(&err, now, u64::MAX);
        match kind {
            AuthFailureKind::UsageLimited { reset_at } => {
                assert!(reset_at > now);
            }
            _ => panic!("expected usage-limited classification"),
        }
    }

    #[test]
    fn classify_auth_failure_detects_rate_limit_reached_phrase() {
        let now = Utc
            .with_ymd_and_hms(2026, 3, 2, 10, 0, 0)
            .single()
            .expect("valid");
        let err = anyhow!("codex turn failed: Rate limit reached, try again in 45m");
        let kind = classify_auth_failure(&err, now, 3600);
        assert!(matches!(kind, AuthFailureKind::UsageLimited { .. }));
    }

    #[test]
    fn classify_auth_failure_handles_huge_relative_retry_hint_without_panicking() {
        let now = Utc
            .with_ymd_and_hms(2026, 3, 2, 10, 0, 0)
            .single()
            .expect("valid");
        let err =
            anyhow!("codex turn failed: usage limit exceeded, try again in 9223372036854775807s");
        let kind = classify_auth_failure(&err, now, 3600);
        match kind {
            AuthFailureKind::UsageLimited { reset_at } => {
                assert!(reset_at > now);
            }
            _ => panic!("expected usage-limited classification"),
        }
    }

    #[test]
    fn classify_auth_failure_detects_auth_unavailable() {
        let now = Utc
            .with_ymd_and_hms(2026, 3, 2, 10, 0, 0)
            .single()
            .expect("valid");
        let err = anyhow!("codex app-server error: not authenticated, run codex auth login");
        let kind = classify_auth_failure(&err, now, 3600);
        assert_eq!(kind, AuthFailureKind::AuthUnavailable);
    }

    #[test]
    fn classify_auth_failure_preserves_non_auth_errors() {
        let now = Utc
            .with_ymd_and_hms(2026, 3, 2, 10, 0, 0)
            .single()
            .expect("valid");
        let err = anyhow!("codex app-server closed stdout");
        let kind = classify_auth_failure(&err, now, 3600);
        assert_eq!(kind, AuthFailureKind::Other);
    }

    #[test]
    fn classify_auth_failure_ignores_non_codex_rate_limit_errors() {
        let now = Utc
            .with_ymd_and_hms(2026, 3, 2, 10, 0, 0)
            .single()
            .expect("valid");
        let err = anyhow!("git clone failed: received HTTP 429 from gitlab");
        let kind = classify_auth_failure(&err, now, 3600);
        assert_eq!(kind, AuthFailureKind::Other);
    }

    #[test]
    fn classify_auth_failure_ignores_generic_app_server_429_without_codex_limit_context() {
        let now = Utc
            .with_ymd_and_hms(2026, 3, 2, 10, 0, 0)
            .single()
            .expect("valid");
        let err = anyhow!(
            "codex app-server closed stdout: recent runner errors: git clone failed with 429"
        );
        let kind = classify_auth_failure(&err, now, 3600);
        assert_eq!(kind, AuthFailureKind::Other);
    }

    #[test]
    fn classify_auth_failure_ignores_openai_package_install_429() {
        let now = Utc
            .with_ymd_and_hms(2026, 3, 2, 10, 0, 0)
            .single()
            .expect("valid");
        let err = anyhow!("codex-runner-error: npm install -g @openai/codex failed with 429");
        let kind = classify_auth_failure(&err, now, 3600);
        assert_eq!(kind, AuthFailureKind::Other);
    }

    #[test]
    fn classify_auth_failure_ignores_disk_quota_exceeded_errors() {
        let now = Utc
            .with_ymd_and_hms(2026, 3, 2, 10, 0, 0)
            .single()
            .expect("valid");
        let err = anyhow!("write failed: disk quota exceeded");
        let kind = classify_auth_failure(&err, now, 3600);
        assert_eq!(kind, AuthFailureKind::Other);
    }

    #[test]
    fn classify_auth_failure_for_account_marks_mount_path_errors_as_unavailable() {
        let now = Utc
            .with_ymd_and_hms(2026, 3, 2, 10, 0, 0)
            .single()
            .expect("valid");
        let account = AuthAccount {
            name: "backup".to_string(),
            auth_host_path: "/missing/codex-auth".to_string(),
            state_key: auth_account_state_key("backup", "/missing/codex-auth"),
            is_primary: false,
        };
        let err = anyhow!(
            "create docker container failed: invalid mount config for type \"bind\": bind source path does not exist: /missing/codex-auth"
        );
        let base = classify_auth_failure(&err, now, 3600);
        let kind = classify_auth_failure_for_account(base, &err, &account);
        assert_eq!(kind, AuthFailureKind::AuthUnavailable);
    }

    #[test]
    fn should_clear_limit_reset_only_when_marker_is_not_newer_than_attempt() {
        let attempt_started_at = Utc
            .with_ymd_and_hms(2026, 3, 2, 10, 0, 0)
            .single()
            .expect("valid");
        let older_reset = Utc
            .with_ymd_and_hms(2026, 3, 2, 9, 0, 0)
            .single()
            .expect("valid");
        let newer_reset = Utc
            .with_ymd_and_hms(2026, 3, 2, 11, 0, 0)
            .single()
            .expect("valid");

        assert!(should_clear_limit_reset(older_reset, attempt_started_at));
        assert!(should_clear_limit_reset(
            attempt_started_at,
            attempt_started_at
        ));
        assert!(!should_clear_limit_reset(newer_reset, attempt_started_at));
    }

    #[test]
    fn build_auth_accounts_keeps_primary_first_then_fallback_order() {
        let codex = CodexConfig {
            image: "ghcr.io/openai/codex-universal:latest".to_string(),
            timeout_seconds: 300,
            auth_host_path: "/root/.codex-primary".to_string(),
            auth_mount_path: "/root/.codex".to_string(),
            exec_sandbox: "danger-full-access".to_string(),
            fallback_auth_accounts: vec![
                FallbackAuthAccountConfig {
                    name: "backup-high".to_string(),
                    auth_host_path: "/root/.codex-backup-high".to_string(),
                },
                FallbackAuthAccountConfig {
                    name: "backup-low".to_string(),
                    auth_host_path: "/root/.codex-backup-low".to_string(),
                },
            ],
            usage_limit_fallback_cooldown_seconds: 3600,
            deps: DepsConfig { enabled: false },
            browser_mcp: BrowserMcpConfig::default(),
            mcp_server_overrides: McpServerOverridesConfig::default(),
            reasoning_effort: crate::config::ReasoningEffortOverridesConfig::default(),
        };

        let accounts = DockerCodexRunner::build_auth_accounts(&codex);
        assert_eq!(accounts.len(), 3);
        assert_eq!(accounts[0].name, PRIMARY_AUTH_ACCOUNT_NAME);
        assert_eq!(accounts[0].auth_host_path, "/root/.codex-primary");
        assert_eq!(
            accounts[0].state_key,
            auth_account_state_key(PRIMARY_AUTH_ACCOUNT_NAME, "/root/.codex-primary")
        );
        assert!(accounts[0].is_primary);
        assert_eq!(accounts[1].name, "backup-high");
        assert_eq!(accounts[2].name, "backup-low");
        assert_eq!(
            accounts[1].state_key,
            auth_account_state_key("backup-high", "/root/.codex-backup-high")
        );
        assert_eq!(
            accounts[2].state_key,
            auth_account_state_key("backup-low", "/root/.codex-backup-low")
        );
        assert!(!accounts[1].is_primary);
        assert!(!accounts[2].is_primary);
    }

    #[test]
    fn runner_env_vars_do_not_include_proxy_settings() {
        let runtime = tokio::runtime::Runtime::new().expect("runtime");
        let runner = DockerCodexRunner {
            docker: connect_docker(&DockerConfig {
                host: "tcp://127.0.0.1:2375".to_string(),
            })
            .expect("docker client"),
            codex: CodexConfig {
                image: "ghcr.io/openai/codex-universal:latest".to_string(),
                timeout_seconds: 300,
                auth_host_path: "/root/.codex".to_string(),
                auth_mount_path: "/root/.codex".to_string(),
                exec_sandbox: "danger-full-access".to_string(),
                fallback_auth_accounts: Vec::new(),
                usage_limit_fallback_cooldown_seconds: 3600,
                deps: DepsConfig { enabled: false },
                browser_mcp: BrowserMcpConfig::default(),
                mcp_server_overrides: McpServerOverridesConfig::default(),
                reasoning_effort: crate::config::ReasoningEffortOverridesConfig::default(),
            },
            git_base: Url::parse("https://gitlab.example.com").expect("url"),
            gitlab_token: "token".to_string(),
            log_all_json: false,
            owner_id: "owner-id".to_string(),
            state: Arc::new(
                runtime
                    .block_on(ReviewStateStore::new(":memory:"))
                    .expect("state"),
            ),
            auth_accounts: Vec::new(),
        };

        let env = runner.env_vars();

        assert_eq!(
            env,
            vec!["GITLAB_TOKEN=token".to_string(), "HOME=/root".to_string(),]
        );
    }

    #[test]
    fn with_recent_runner_errors_adds_context() {
        let err = anyhow!("codex app-server closed stdout");
        let recent = VecDeque::from(vec![
            "codex-runner-error: codex install failed".to_string(),
            "codex-runner-error: npm ERR! network".to_string(),
        ]);
        let wrapped = with_recent_runner_errors(err, &recent);
        let chain = format!("{wrapped:#}");
        assert!(chain.contains("codex app-server closed stdout"));
        assert!(chain.contains("recent runner errors:"));
        assert!(chain.contains("codex-runner-error: codex install failed"));
        assert!(chain.contains("codex-runner-error: npm ERR! network"));
    }

    #[test]
    fn with_recent_runner_errors_is_noop_when_empty() {
        let err = anyhow!("codex app-server closed stdout");
        let recent = VecDeque::new();
        let wrapped = with_recent_runner_errors(err, &recent);
        assert_eq!(
            wrapped.to_string(),
            "codex app-server closed stdout".to_string()
        );
    }

    #[test]
    fn validate_container_exec_result_accepts_zero_exit_code() -> Result<()> {
        let command = vec!["git".to_string(), "status".to_string()];
        let output = ContainerExecOutput {
            exit_code: 0,
            stdout: "clean\n".to_string(),
            stderr: String::new(),
        };
        let validated = validate_container_exec_result(&command, Some("/work/repo"), output)?;
        assert_eq!(validated.stdout, "clean\n");
        Ok(())
    }

    #[test]
    fn validate_container_exec_result_rejects_nonzero_exit_with_stderr() {
        let command = vec!["git".to_string(), "status".to_string()];
        let output = ContainerExecOutput {
            exit_code: 128,
            stdout: String::new(),
            stderr: "fatal: not a git repository\n".to_string(),
        };
        let err = validate_container_exec_result(&command, Some("/work/repo"), output)
            .expect_err("expected command failure");
        let text = err.to_string();
        assert!(text.contains("docker exec command failed with exit code 128"));
        assert!(text.contains("'git' 'status'"));
        assert!(text.contains("/work/repo"));
        assert!(text.contains("fatal: not a git repository"));
    }

    #[test]
    fn validate_container_exec_result_rejects_nonzero_exit_without_stderr() {
        let command = vec!["git".to_string(), "status".to_string()];
        let output = ContainerExecOutput {
            exit_code: 1,
            stdout: String::new(),
            stderr: " \n ".to_string(),
        };
        let err = validate_container_exec_result(&command, Some("/work/repo"), output)
            .expect_err("expected command failure");
        let text = err.to_string();
        assert!(text.contains("docker exec command failed with exit code 1"));
        assert!(text.contains("'git' 'status'"));
        assert!(text.contains("/work/repo"));
    }

    #[test]
    fn app_server_cmd_uses_bash_login_args() {
        let cmd = DockerCodexRunner::app_server_cmd("echo hi".to_string());
        assert_eq!(cmd, vec!["-lc".to_string(), "echo hi".to_string()]);
    }

    #[test]
    fn codex_app_server_exec_command_without_mcp_overrides_is_plain() {
        let overrides = BTreeMap::new();
        let cmd = codex_app_server_exec_command(None, &overrides, None);
        assert_eq!(cmd, "exec codex app-server");
    }

    #[test]
    fn codex_app_server_exec_command_renders_sorted_mcp_overrides() {
        let overrides =
            BTreeMap::from([("serena".to_string(), false), ("github".to_string(), true)]);
        let cmd = codex_app_server_exec_command(None, &overrides, None);
        assert_eq!(
            cmd,
            "exec codex -c 'mcp_servers.github.enabled=true' -c 'mcp_servers.serena.enabled=false' app-server"
        );
    }

    #[test]
    fn codex_app_server_exec_command_includes_reasoning_effort_override() {
        let cmd = codex_app_server_exec_command(None, &BTreeMap::new(), Some("high"));
        assert_eq!(
            cmd,
            "exec codex -c 'model_reasoning_effort=\"high\"' app-server"
        );
    }

    #[test]
    fn codex_app_server_exec_command_includes_browser_mcp_config() {
        let cmd = codex_app_server_exec_command(
            Some(&BrowserMcpConfig {
                enabled: true,
                server_name: "chrome-devtools".to_string(),
                browser_image: "chromedp/headless-shell:latest".to_string(),
                browser_args: vec![],
                remote_debugging_port: 9222,
                ..BrowserMcpConfig::default()
            }),
            &BTreeMap::new(),
            None,
        );
        assert!(cmd.contains("mcp_servers.chrome-devtools.command=\"npx\""));
        assert!(cmd.contains("chrome-devtools-mcp@latest"));
        assert!(cmd.contains("--browserUrl=http://127.0.0.1:9222"));
        assert!(cmd.contains("mcp_servers.chrome-devtools.enabled=true"));
    }

    #[test]
    fn codex_app_server_exec_command_allows_mode_overrides_to_disable_browser_mcp() {
        let cmd = codex_app_server_exec_command(
            Some(&BrowserMcpConfig {
                enabled: true,
                server_name: "chrome-devtools".to_string(),
                browser_image: "chromedp/headless-shell:latest".to_string(),
                browser_entrypoint: Vec::new(),
                remote_debugging_port: 9222,
                browser_args: vec![],
                mcp_command: "npx".to_string(),
                mcp_args: vec!["-y".to_string(), "chrome-devtools-mcp@latest".to_string()],
            }),
            &BTreeMap::from([("chrome-devtools".to_string(), false)]),
            None,
        );
        let expected_enable = "-c 'mcp_servers.chrome-devtools.enabled=true'";
        let expected_disable = "-c 'mcp_servers.chrome-devtools.enabled=false'";
        assert!(cmd.contains(expected_enable));
        assert!(cmd.contains(expected_disable));
        assert!(cmd.find(expected_enable) < cmd.find(expected_disable));
    }

    #[test]
    fn codex_app_server_exec_command_places_reasoning_effort_before_mcp_overrides() {
        let overrides = BTreeMap::from([("github".to_string(), false)]);
        let cmd = codex_app_server_exec_command(None, &overrides, Some("medium"));
        let reasoning = "-c 'model_reasoning_effort=\"medium\"'";
        let mcp = "-c 'mcp_servers.github.enabled=false'";
        assert!(cmd.contains(reasoning));
        assert!(cmd.contains(mcp));
        assert!(cmd.find(reasoning) < cmd.find(mcp));
    }

    #[test]
    fn effective_browser_mcp_disables_sidecar_when_mode_override_is_false() {
        let browser_mcp = BrowserMcpConfig {
            enabled: true,
            server_name: "chrome-devtools".to_string(),
            browser_image: "chromedp/headless-shell:latest".to_string(),
            ..BrowserMcpConfig::default()
        };
        let effective = effective_browser_mcp(
            Some(&browser_mcp),
            &BTreeMap::from([("chrome-devtools".to_string(), false)]),
        );
        assert!(effective.is_none());
    }

    #[test]
    fn effective_browser_mcp_keeps_sidecar_when_mode_override_is_true() {
        let browser_mcp = BrowserMcpConfig {
            enabled: true,
            server_name: "chrome-devtools".to_string(),
            browser_image: "chromedp/headless-shell:latest".to_string(),
            ..BrowserMcpConfig::default()
        };
        let effective = effective_browser_mcp(
            Some(&browser_mcp),
            &BTreeMap::from([("chrome-devtools".to_string(), true)]),
        );
        assert_eq!(effective, Some(&browser_mcp));
    }

    #[test]
    fn browser_container_cmd_includes_no_sandbox_by_default() {
        let cmd = browser_container_cmd(
            "ghcr.io/acme/browser:latest",
            &[],
            &BrowserMcpConfig {
                enabled: true,
                server_name: "chrome-devtools".to_string(),
                browser_image: "ghcr.io/acme/browser:latest".to_string(),
                ..BrowserMcpConfig::default()
            },
        );
        assert!(cmd.iter().any(|arg| arg == "--no-sandbox"));
    }

    #[test]
    fn browser_container_cmd_skips_injected_debug_flags_for_headless_shell_wrapper() {
        let cmd = browser_container_cmd(
            "chromedp/headless-shell:latest",
            &[],
            &BrowserMcpConfig {
                enabled: true,
                server_name: "chrome-devtools".to_string(),
                browser_image: "chromedp/headless-shell:latest".to_string(),
                browser_args: vec!["--window-size=1280,720".to_string()],
                ..BrowserMcpConfig::default()
            },
        );
        assert_eq!(cmd, vec!["--window-size=1280,720".to_string()]);
    }

    #[test]
    fn browser_launch_config_keeps_image_default_entrypoint_for_default_headless_shell_image() {
        let launch = BrowserLaunchConfig::from_browser_mcp(&BrowserMcpConfig {
            enabled: true,
            server_name: "chrome-devtools".to_string(),
            browser_image: "chromedp/headless-shell:latest".to_string(),
            browser_entrypoint: Vec::new(),
            ..BrowserMcpConfig::default()
        });
        assert!(launch.entrypoint.is_empty());
        assert!(launch.cmd.is_empty());
    }

    #[test]
    fn browser_launch_config_preserves_explicit_entrypoint_override() {
        let launch = BrowserLaunchConfig::from_browser_mcp(&BrowserMcpConfig {
            enabled: true,
            server_name: "chrome-devtools".to_string(),
            browser_image: "chromedp/headless-shell:latest".to_string(),
            browser_entrypoint: vec!["/custom/entrypoint".to_string()],
            ..BrowserMcpConfig::default()
        });
        assert_eq!(launch.entrypoint, vec!["/custom/entrypoint".to_string()]);
        assert!(
            launch
                .cmd
                .iter()
                .any(|arg| arg == "--remote-debugging-address=0.0.0.0")
        );
    }

    #[test]
    fn browser_launch_config_keeps_other_images_on_image_default_entrypoint() {
        let launch = BrowserLaunchConfig::from_browser_mcp(&BrowserMcpConfig {
            enabled: true,
            server_name: "chrome-devtools".to_string(),
            browser_image: "ghcr.io/acme/browser:latest".to_string(),
            browser_entrypoint: Vec::new(),
            ..BrowserMcpConfig::default()
        });
        assert!(launch.entrypoint.is_empty());
    }

    #[test]
    fn browser_logs_report_ready_requires_expected_port() {
        let ready = browser_logs_report_ready(
            &BrowserLogTail {
                stdout: vec![],
                stderr: vec![
                    "DevTools listening on ws://127.0.0.1:9222/devtools/browser/abc".to_string(),
                ],
            },
            9222,
        );
        let wrong_port = browser_logs_report_ready(
            &BrowserLogTail {
                stdout: vec![],
                stderr: vec![
                    "DevTools listening on ws://127.0.0.1:9223/devtools/browser/abc".to_string(),
                ],
            },
            9222,
        );
        let prefix_port = browser_logs_report_ready(
            &BrowserLogTail {
                stdout: vec![],
                stderr: vec![
                    "DevTools listening on ws://127.0.0.1:9222/devtools/browser/abc".to_string(),
                ],
            },
            922,
        );
        assert!(ready);
        assert!(!wrong_port);
        assert!(!prefix_port);
    }

    #[test]
    fn browser_container_has_exited_only_for_terminal_states() {
        assert!(!browser_container_has_exited(Some(
            &BrowserContainerStateSnapshot {
                status: Some("created".to_string()),
                running: Some(false),
                exit_code: None,
                oom_killed: None,
                error: None,
                started_at: None,
                finished_at: None,
            },
        )));
        assert!(browser_container_has_exited(Some(
            &BrowserContainerStateSnapshot {
                status: Some("exited".to_string()),
                running: Some(false),
                exit_code: Some(1),
                oom_killed: Some(false),
                error: Some("boom".to_string()),
                started_at: None,
                finished_at: Some("2026-03-06T07:22:00Z".to_string()),
            },
        )));
    }

    #[test]
    fn browser_container_running_grace_period_is_ten_seconds() {
        assert_eq!(BROWSER_CONTAINER_RUNNING_GRACE_PERIOD.as_secs(), 10);
    }

    #[test]
    fn browser_container_diagnostics_context_includes_state_and_logs() {
        let diagnostics = BrowserContainerDiagnostics {
            container_id: "browser-123".to_string(),
            launch: BrowserLaunchConfig {
                image: "chromedp/headless-shell:latest".to_string(),
                entrypoint: vec!["/headless-shell/headless-shell".to_string()],
                cmd: vec!["--remote-debugging-port=9222".to_string()],
            },
            state: Some(BrowserContainerStateSnapshot {
                status: Some("running".to_string()),
                running: Some(true),
                exit_code: Some(0),
                oom_killed: Some(false),
                error: None,
                started_at: Some("2026-03-06T07:20:00Z".to_string()),
                finished_at: None,
            }),
            state_collection_error: None,
            log_tail: BrowserLogTail {
                stdout: vec!["browser stdout line".to_string()],
                stderr: vec![
                    "DevTools listening on ws://127.0.0.1:9222/devtools/browser/abc".to_string(),
                ],
            },
            log_collection_error: None,
        };

        let formatted = diagnostics.format_context();

        assert!(formatted.contains("browser container diagnostics"));
        assert!(formatted.contains("browser-123"));
        assert!(formatted.contains("chromedp/headless-shell:latest"));
        assert!(formatted.contains("/headless-shell/headless-shell"));
        assert!(formatted.contains("status=running"));
        assert!(formatted.contains("browser stdout line"));
        assert!(formatted.contains("DevTools listening on ws://127.0.0.1:9222"));
    }

    #[test]
    fn browser_container_diagnostics_context_includes_collection_errors() {
        let diagnostics = BrowserContainerDiagnostics {
            container_id: "browser-123".to_string(),
            launch: BrowserLaunchConfig {
                image: "chromedp/headless-shell:latest".to_string(),
                entrypoint: vec![],
                cmd: vec!["--remote-debugging-port=9222".to_string()],
            },
            state: None,
            state_collection_error: Some("inspect failed".to_string()),
            log_tail: BrowserLogTail::default(),
            log_collection_error: Some("log fetch failed".to_string()),
        };

        let formatted = diagnostics.format_context();

        assert!(formatted.contains("state unavailable: inspect failed"));
        assert!(formatted.contains("log tail unavailable: log fetch failed"));
        assert!(formatted.contains("entrypoint=<image-default>"));
    }

    #[test]
    fn build_command_script_sets_writable_codex_home() {
        let script = DockerCodexRunner::build_command_script(
            "https://example.com/repo.git",
            "abc",
            "/root/.codex",
            None,
            false,
            AppServerCommandOptions {
                browser_mcp: None,
                mcp_server_overrides: &BTreeMap::new(),
                reasoning_effort: None,
            },
        );
        assert!(script.contains("export CODEX_HOME=\"/root/.codex\""));
        assert!(script.contains("mkdir -p \"/root/.codex\""));
    }

    #[test]
    fn build_command_script_fetches_target_branch() {
        let script = DockerCodexRunner::build_command_script(
            "https://example.com/repo.git",
            "abc",
            "/root/.codex",
            Some("main"),
            false,
            AppServerCommandOptions {
                browser_mcp: None,
                mcp_server_overrides: &BTreeMap::new(),
                reasoning_effort: None,
            },
        );
        assert!(script.contains("git fetch --depth 1 origin \"main\""));
        assert!(script.contains("git branch --force \"main\" FETCH_HEAD"));
        assert!(script.contains("git fetch --unshallow"));
    }

    #[test]
    fn build_command_script_updates_submodules() {
        let script = DockerCodexRunner::build_command_script(
            "https://example.com/repo.git",
            "abc",
            "/root/.codex",
            None,
            false,
            AppServerCommandOptions {
                browser_mcp: None,
                mcp_server_overrides: &BTreeMap::new(),
                reasoning_effort: None,
            },
        );
        assert!(script.contains("git clone --depth 1 --recurse-submodules"));
        assert!(script.contains("git submodule update --init --recursive"));
    }

    #[test]
    fn build_command_script_includes_prefetch_when_enabled() {
        let script = DockerCodexRunner::build_command_script(
            "https://example.com/repo.git",
            "abc",
            "/root/.codex",
            None,
            true,
            AppServerCommandOptions {
                browser_mcp: None,
                mcp_server_overrides: &BTreeMap::new(),
                reasoning_effort: None,
            },
        );
        assert!(script.contains("prefetch_deps()"));
        assert!(script.contains("composer install"));
    }

    #[test]
    fn build_command_script_includes_mcp_server_overrides() {
        let overrides = BTreeMap::from([("github".to_string(), false)]);
        let script = DockerCodexRunner::build_command_script(
            "https://example.com/repo.git",
            "abc",
            "/root/.codex",
            None,
            false,
            AppServerCommandOptions {
                browser_mcp: None,
                mcp_server_overrides: &overrides,
                reasoning_effort: None,
            },
        );
        assert!(script.contains("exec codex -c 'mcp_servers.github.enabled=false' app-server"));
    }

    #[test]
    fn build_command_script_includes_reasoning_effort_override() {
        let script = DockerCodexRunner::build_command_script(
            "https://example.com/repo.git",
            "abc",
            "/root/.codex",
            None,
            false,
            AppServerCommandOptions {
                browser_mcp: None,
                mcp_server_overrides: &BTreeMap::new(),
                reasoning_effort: Some("high"),
            },
        );
        assert!(script.contains("exec codex -c 'model_reasoning_effort=\"high\"' app-server"));
    }

    #[test]
    fn build_command_script_waits_for_browser_when_enabled() {
        let script = DockerCodexRunner::build_command_script(
            "https://example.com/repo.git",
            "abc",
            "/root/.codex",
            None,
            false,
            AppServerCommandOptions {
                browser_mcp: Some(&BrowserMcpConfig {
                    enabled: true,
                    server_name: "chrome-devtools".to_string(),
                    browser_image: "chromedp/headless-shell:latest".to_string(),
                    remote_debugging_port: 9222,
                    browser_args: vec!["--no-sandbox".to_string()],
                    ..BrowserMcpConfig::default()
                }),
                mcp_server_overrides: &BTreeMap::new(),
                reasoning_effort: None,
            },
        );
        assert!(script.contains("browser_mcp_command='npx'"));
        assert!(script.contains("browser MCP requires $browser_mcp_command"));
        assert!(script.contains("127.0.0.1:9222/json/version"));
        assert!(script.contains("browser MCP endpoint did not become ready"));
    }

    #[test]
    fn browser_mcp_prereq_script_requires_npx_when_enabled() {
        let script = browser_mcp_prereq_script(Some(&BrowserMcpConfig {
            enabled: true,
            server_name: "chrome-devtools".to_string(),
            browser_image: "chromedp/headless-shell:latest".to_string(),
            remote_debugging_port: 9222,
            browser_args: vec![],
            ..BrowserMcpConfig::default()
        }));
        assert!(script.contains("browser_mcp_command='npx'"));
        assert!(script.contains("browser MCP requires $browser_mcp_command"));
    }

    #[test]
    fn browser_mcp_prereq_script_is_empty_when_disabled() {
        let script = browser_mcp_prereq_script(None);
        assert!(script.is_empty());
    }

    #[test]
    fn mention_command_script_clones_repo_and_starts_app_server() {
        let ctx = MentionCommandContext {
            repo: "group/repo".to_string(),
            project_path: "group/repo".to_string(),
            mr: MergeRequest {
                iid: 11,
                title: Some("Title".to_string()),
                web_url: Some(
                    "https://gitlab.example.com/group/repo/-/merge_requests/11".to_string(),
                ),
                created_at: None,
                updated_at: None,
                sha: Some("abc123".to_string()),
                source_branch: None,
                target_branch: Some("main".to_string()),
                author: None,
                source_project_id: None,
                target_project_id: None,
                diff_refs: None,
            },
            head_sha: "abc123".to_string(),
            discussion_id: "discussion-1".to_string(),
            trigger_note_id: 77,
            requester_name: "Alice Example".to_string(),
            requester_email: "alice@example.com".to_string(),
            additional_developer_instructions: None,
            prompt: "Do the change".to_string(),
        };
        let script = DockerCodexRunner::build_mention_command_script(
            &ctx,
            "https://oauth2:${GITLAB_TOKEN}@example.com/repo.git",
            "/root/.codex",
            AppServerCommandOptions {
                browser_mcp: None,
                mcp_server_overrides: &BTreeMap::new(),
                reasoning_effort: None,
            },
        );
        assert!(
            script.contains("git clone --depth 1 --recurse-submodules \"https://oauth2:${GITLAB_TOKEN}@example.com/repo.git\"")
        );
        assert!(!script.contains("rm -rf"));
        assert!(script.contains("git remote set-url --push origin \"no_push://disabled\""));
        assert!(script.contains("exec codex app-server"));
        assert!(!script.contains("codex exec --sandbox workspace-write"));
        assert!(!script.contains("GIT_AUTHOR_NAME="));
    }

    #[test]
    fn mention_command_script_includes_mcp_server_overrides() {
        let ctx = MentionCommandContext {
            repo: "group/repo".to_string(),
            project_path: "group/repo".to_string(),
            mr: MergeRequest {
                iid: 11,
                title: Some("Title".to_string()),
                web_url: Some(
                    "https://gitlab.example.com/group/repo/-/merge_requests/11".to_string(),
                ),
                created_at: None,
                updated_at: None,
                sha: Some("abc123".to_string()),
                source_branch: None,
                target_branch: Some("main".to_string()),
                author: None,
                source_project_id: None,
                target_project_id: None,
                diff_refs: None,
            },
            head_sha: "abc123".to_string(),
            discussion_id: "discussion-1".to_string(),
            trigger_note_id: 77,
            requester_name: "Alice Example".to_string(),
            requester_email: "alice@example.com".to_string(),
            additional_developer_instructions: None,
            prompt: "Do the change".to_string(),
        };
        let overrides = BTreeMap::from([("playwright".to_string(), true)]);
        let script = DockerCodexRunner::build_mention_command_script(
            &ctx,
            "https://oauth2:${GITLAB_TOKEN}@example.com/repo.git",
            "/root/.codex",
            AppServerCommandOptions {
                browser_mcp: None,
                mcp_server_overrides: &overrides,
                reasoning_effort: None,
            },
        );
        assert!(script.contains("exec codex -c 'mcp_servers.playwright.enabled=true' app-server"));
    }

    #[test]
    fn mention_command_script_includes_reasoning_effort_override() {
        let ctx = MentionCommandContext {
            repo: "group/repo".to_string(),
            project_path: "group/repo".to_string(),
            mr: MergeRequest {
                iid: 11,
                title: Some("Title".to_string()),
                web_url: Some(
                    "https://gitlab.example.com/group/repo/-/merge_requests/11".to_string(),
                ),
                created_at: None,
                updated_at: None,
                sha: Some("abc123".to_string()),
                source_branch: None,
                target_branch: Some("main".to_string()),
                author: None,
                source_project_id: None,
                target_project_id: None,
                diff_refs: None,
            },
            head_sha: "abc123".to_string(),
            discussion_id: "discussion-1".to_string(),
            trigger_note_id: 77,
            requester_name: "Alice Example".to_string(),
            requester_email: "alice@example.com".to_string(),
            additional_developer_instructions: None,
            prompt: "Do the change".to_string(),
        };
        let script = DockerCodexRunner::build_mention_command_script(
            &ctx,
            "https://oauth2:${GITLAB_TOKEN}@example.com/repo.git",
            "/root/.codex",
            AppServerCommandOptions {
                browser_mcp: None,
                mcp_server_overrides: &BTreeMap::new(),
                reasoning_effort: Some("low"),
            },
        );
        assert!(script.contains("exec codex -c 'model_reasoning_effort=\"low\"' app-server"));
    }

    #[test]
    fn mention_command_script_waits_for_browser_when_enabled() {
        let ctx = MentionCommandContext {
            repo: "group/repo".to_string(),
            project_path: "group/repo".to_string(),
            mr: MergeRequest {
                iid: 11,
                title: Some("Title".to_string()),
                web_url: Some(
                    "https://gitlab.example.com/group/repo/-/merge_requests/11".to_string(),
                ),
                created_at: None,
                updated_at: None,
                sha: Some("abc123".to_string()),
                source_branch: None,
                target_branch: Some("main".to_string()),
                author: None,
                source_project_id: None,
                target_project_id: None,
                diff_refs: None,
            },
            head_sha: "abc123".to_string(),
            discussion_id: "discussion-1".to_string(),
            trigger_note_id: 77,
            requester_name: "Alice Example".to_string(),
            requester_email: "alice@example.com".to_string(),
            additional_developer_instructions: None,
            prompt: "Do the change".to_string(),
        };
        let script = DockerCodexRunner::build_mention_command_script(
            &ctx,
            "https://oauth2:${GITLAB_TOKEN}@example.com/repo.git",
            "/root/.codex",
            AppServerCommandOptions {
                browser_mcp: Some(&BrowserMcpConfig {
                    enabled: true,
                    server_name: "chrome-devtools".to_string(),
                    browser_image: "chromedp/headless-shell:latest".to_string(),
                    remote_debugging_port: 9222,
                    browser_args: vec![],
                    ..BrowserMcpConfig::default()
                }),
                mcp_server_overrides: &BTreeMap::new(),
                reasoning_effort: None,
            },
        );
        assert!(script.contains("browser_mcp_command='npx'"));
        assert!(script.contains("browser MCP requires $browser_mcp_command"));
        assert!(script.contains("127.0.0.1:9222/json/version"));
        assert!(script.contains("browser MCP endpoint did not become ready"));
    }

    #[test]
    fn mention_developer_instructions_require_commit_and_sha_reporting() {
        let ctx = MentionCommandContext {
            repo: "group/repo".to_string(),
            project_path: "group/repo".to_string(),
            mr: MergeRequest {
                iid: 11,
                title: Some("Title".to_string()),
                web_url: Some(
                    "https://gitlab.example.com/group/repo/-/merge_requests/11".to_string(),
                ),
                created_at: None,
                updated_at: None,
                sha: Some("abc123".to_string()),
                source_branch: None,
                target_branch: Some("main".to_string()),
                author: None,
                source_project_id: None,
                target_project_id: None,
                diff_refs: None,
            },
            head_sha: "abc123".to_string(),
            discussion_id: "discussion-1".to_string(),
            trigger_note_id: 77,
            requester_name: "Alice Example".to_string(),
            requester_email: "alice@example.com".to_string(),
            additional_developer_instructions: None,
            prompt: "Do the change".to_string(),
        };
        let instructions = DockerCodexRunner::mention_developer_instructions(&ctx);
        assert!(instructions.contains("create at least one commit before you finish"));
        assert!(instructions.contains("include the commit SHA"));
        assert!(instructions.contains("no commit was created"));
        assert!(instructions.contains("Name: Alice Example"));
        assert!(instructions.contains("Email: alice@example.com"));
        assert!(!instructions.contains("Additional instructions:"));
    }

    #[test]
    fn mention_developer_instructions_include_additional_section_when_configured() {
        let ctx = MentionCommandContext {
            repo: "group/repo".to_string(),
            project_path: "group/repo".to_string(),
            mr: MergeRequest {
                iid: 11,
                title: Some("Title".to_string()),
                web_url: Some(
                    "https://gitlab.example.com/group/repo/-/merge_requests/11".to_string(),
                ),
                created_at: None,
                updated_at: None,
                sha: Some("abc123".to_string()),
                source_branch: None,
                target_branch: Some("main".to_string()),
                author: None,
                source_project_id: None,
                target_project_id: None,
                diff_refs: None,
            },
            head_sha: "abc123".to_string(),
            discussion_id: "discussion-1".to_string(),
            trigger_note_id: 77,
            requester_name: "Alice Example".to_string(),
            requester_email: "alice@example.com".to_string(),
            additional_developer_instructions: Some(
                "  Prefer minimal diffs and include tests.  ".to_string(),
            ),
            prompt: "Do the change".to_string(),
        };
        let instructions = DockerCodexRunner::mention_developer_instructions(&ctx);
        assert!(instructions.contains("Additional instructions:"));
        assert!(instructions.contains("Prefer minimal diffs and include tests."));
    }

    #[test]
    fn normalize_image_reference_appends_latest_when_missing_tag() {
        let image = "ghcr.io/openai/codex-universal";
        assert_eq!(
            DockerCodexRunner::normalize_image_reference(image),
            "ghcr.io/openai/codex-universal:latest"
        );
    }

    #[test]
    fn normalize_image_reference_preserves_tag() {
        let image = "ghcr.io/openai/codex-universal:v1.2.3";
        assert_eq!(
            DockerCodexRunner::normalize_image_reference(image),
            "ghcr.io/openai/codex-universal:v1.2.3"
        );
    }

    #[test]
    fn normalize_image_reference_preserves_digest() {
        let image = "ghcr.io/openai/codex-universal@sha256:deadbeef";
        assert_eq!(
            DockerCodexRunner::normalize_image_reference(image),
            "ghcr.io/openai/codex-universal@sha256:deadbeef"
        );
    }

    #[test]
    fn normalize_image_reference_handles_registry_port() {
        let image = "localhost:5000/codex-universal";
        assert_eq!(
            DockerCodexRunner::normalize_image_reference(image),
            "localhost:5000/codex-universal:latest"
        );
    }

    #[test]
    fn normalize_image_reference_keeps_tag_with_registry_port() {
        let image = "localhost:5000/codex-universal:canary";
        assert_eq!(
            DockerCodexRunner::normalize_image_reference(image),
            "localhost:5000/codex-universal:canary"
        );
    }

    #[test]
    fn review_container_prefix_matcher_handles_docker_name_format() {
        assert!(DockerCodexRunner::is_managed_container_name(
            "codex-review-abc"
        ));
        assert!(DockerCodexRunner::is_managed_container_name(
            "/codex-review-def"
        ));
        assert!(DockerCodexRunner::is_managed_container_name(
            "/codex-browser-jkl"
        ));
        assert!(!DockerCodexRunner::is_managed_container_name(
            "/codex-auth-ghi"
        ));
    }

    #[test]
    fn review_container_labels_include_owner_label() {
        let labels = DockerCodexRunner::review_container_labels("worker-a");
        assert_eq!(
            labels.get(REVIEW_OWNER_LABEL_KEY),
            Some(&"worker-a".to_string())
        );
        assert_eq!(labels.len(), 1);
    }

    #[test]
    fn review_container_filters_include_name_prefix_and_owner_label() {
        let filters = DockerCodexRunner::review_container_filters("worker-a");
        assert_eq!(
            filters.get("name"),
            Some(&vec![
                REVIEW_CONTAINER_NAME_PREFIX.to_string(),
                BROWSER_CONTAINER_NAME_PREFIX.to_string()
            ])
        );
        assert_eq!(
            filters.get("label"),
            Some(&vec![format!("{REVIEW_OWNER_LABEL_KEY}=worker-a")])
        );
    }

    #[test]
    fn has_review_owner_label_requires_exact_owner_match() {
        let labels = HashMap::from([(REVIEW_OWNER_LABEL_KEY.to_string(), "worker-a".to_string())]);
        assert!(DockerCodexRunner::has_review_owner_label(
            Some(&labels),
            "worker-a"
        ));
        assert!(!DockerCodexRunner::has_review_owner_label(
            Some(&labels),
            "worker-b"
        ));
        assert!(!DockerCodexRunner::has_review_owner_label(None, "worker-a"));
    }
}
