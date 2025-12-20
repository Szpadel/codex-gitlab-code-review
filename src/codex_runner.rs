use crate::config::{CodexConfig, DockerConfig, ProxyConfig};
use crate::gitlab::MergeRequest;
use anyhow::{anyhow, bail, Context, Result};
use async_trait::async_trait;
use bollard::container::{
    AttachContainerOptions, Config as ContainerConfig, CreateContainerOptions, LogOutput,
    RemoveContainerOptions, StartContainerOptions,
};
use bollard::models::HostConfig;
use bollard::{Docker, API_DEFAULT_VERSION};
use futures::StreamExt;
use serde::Deserialize;
use serde_json::{json, Value};
use std::collections::{HashMap, VecDeque};
use std::pin::Pin;
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tokio::time::timeout;
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
pub enum CodexResult {
    Pass { summary: String },
    Comment { summary: String, body: String },
}

#[async_trait]
pub trait CodexRunner: Send + Sync {
    async fn run_review(&self, ctx: ReviewContext) -> Result<CodexResult>;
}

pub struct DockerCodexRunner {
    docker: Docker,
    codex: CodexConfig,
    proxy: ProxyConfig,
    git_base: Url,
    gitlab_token: String,
    log_all_json: bool,
}

impl DockerCodexRunner {
    pub fn new(
        docker_cfg: DockerConfig,
        codex: CodexConfig,
        proxy: ProxyConfig,
        git_base: Url,
        gitlab_token: String,
        log_all_json: bool,
    ) -> Result<Self> {
        let docker = if docker_cfg.host.starts_with("unix://") {
            Docker::connect_with_unix(&docker_cfg.host, 120, API_DEFAULT_VERSION)
                .with_context(|| format!("connect to docker unix socket {}", docker_cfg.host))?
        } else if docker_cfg.host.ends_with(".sock") {
            Docker::connect_with_unix(&docker_cfg.host, 120, API_DEFAULT_VERSION)
                .with_context(|| format!("connect to docker unix socket {}", docker_cfg.host))?
        } else {
            Docker::connect_with_http(&docker_cfg.host, 120, API_DEFAULT_VERSION)
                .with_context(|| format!("connect to docker host {}", docker_cfg.host))?
        };
        Ok(Self {
            docker,
            codex,
            proxy,
            git_base,
            gitlab_token,
            log_all_json,
        })
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
        let title = ctx.mr.title.clone().unwrap_or_else(|| "(no title)".to_string());
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
            ctx.repo,
            title,
            url,
            ctx.head_sha,
            target_branch
        )
    }

    fn env_vars(&self) -> Vec<String> {
        let mut env = vec![
            format!("GITLAB_TOKEN={}", self.gitlab_token),
            "HOME=/root".to_string(),
        ];
        if let Some(value) = &self.proxy.http_proxy {
            env.push(format!("HTTP_PROXY={value}"));
        }
        if let Some(value) = &self.proxy.https_proxy {
            env.push(format!("HTTPS_PROXY={value}"));
        }
        if let Some(value) = &self.proxy.no_proxy {
            env.push(format!("NO_PROXY={value}"));
        }
        if self.log_all_json {
            env.push("CODEX_RUNNER_DEBUG=1".to_string());
        }
        env
    }

    fn command(&self, ctx: &ReviewContext) -> Result<String> {
        let clone_url = self.clone_url(&ctx.repo)?;
        Ok(Self::build_command_script(
            &clone_url,
            ctx.head_sha.as_str(),
            &self.codex.auth_mount_path,
            ctx.mr
                .target_branch
                .as_deref()
                .filter(|value| !value.is_empty()),
        ))
    }

    fn build_command_script(
        clone_url: &str,
        head_sha: &str,
        auth_mount_path: &str,
        target_branch: Option<&str>,
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
run_git clone git clone --depth 1 "{clone_url}" repo
cd repo
run_git fetch git fetch --depth 1 origin "{head_sha}"
run_git checkout git checkout "{head_sha}"
{target_branch_script}# Create a writable CODEX_HOME and copy auth/config from the read-only mount.
codex_home="/tmp/codex"
mkdir -p "${{codex_home}}"
if [ -f "{auth_mount_path}/auth.json" ]; then
  cp "{auth_mount_path}/auth.json" "${{codex_home}}/auth.json"
fi
if [ -f "{auth_mount_path}/config.toml" ]; then
  cp "{auth_mount_path}/config.toml" "${{codex_home}}/config.toml"
fi
export CODEX_HOME="${{codex_home}}"
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
exec codex app-server
"#,
            clone_url = clone_url,
            head_sha = head_sha,
            auth_mount_path = auth_mount_path,
            target_branch_script = target_branch_script
        )
    }

    fn app_server_cmd(script: String) -> Vec<String> {
        // The codex-universal entrypoint runs `bash --login "$@"`, so pass only bash flags + script.
        vec!["-lc".to_string(), script]
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
                Some(RemoveContainerOptions {
                    force: true,
                    ..Default::default()
                }),
            )
            .await;
    }

    async fn run_app_server_review(&self, ctx: &ReviewContext) -> Result<String> {
        let script = self.command(ctx)?;
        let name = format!("codex-review-{}", Uuid::new_v4());
        let config = ContainerConfig {
            image: Some(self.codex.image.clone()),
            cmd: Some(Self::app_server_cmd(script)),
            env: Some(self.env_vars()),
            attach_stdout: Some(true),
            attach_stderr: Some(true),
            attach_stdin: Some(true),
            open_stdin: Some(true),
            tty: Some(false),
            host_config: Some(HostConfig {
                binds: Some(vec![format!(
                    "{}:{}:ro",
                    self.codex.auth_host_path, self.codex.auth_mount_path
                )]),
                auto_remove: Some(false),
                ..Default::default()
            }),
            ..Default::default()
        };

        let create = self
            .docker
            .create_container(
                Some(CreateContainerOptions {
                    name: &name,
                    platform: None,
                }),
                config,
            )
            .await
            .with_context(|| {
                format!(
                    "create docker container {} with image {}",
                    name, self.codex.image
                )
            })?;
        let id = create.id;
        let start_result = self
            .docker
            .start_container(&id, None::<StartContainerOptions<String>>)
            .await
            .with_context(|| format!("start docker container {}", id));
        if let Err(err) = start_result {
            self.remove_container_best_effort(&id).await;
            return Err(err);
        }

        let attach = match self
            .docker
            .attach_container(
                &id,
                Some(AttachContainerOptions::<String> {
                    stdout: Some(true),
                    stderr: Some(true),
                    stdin: Some(true),
                    stream: Some(true),
                    logs: Some(true),
                    ..Default::default()
                }),
            )
            .await
            .with_context(|| format!("attach docker container {}", id))
        {
            Ok(attach) => attach,
            Err(err) => {
                self.remove_container_best_effort(&id).await;
                return Err(err);
            }
        };

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
        let mut client = AppServerClient::new(attach, self.log_all_json);

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
            client
                .stream_review(&review_thread_id, &turn_id)
                .await
        })
        .await;

        self.remove_container_best_effort(&id).await;

        let review_result = review_result.map_err(|_| anyhow!("codex review timed out"))?;
        review_result
    }
}

#[async_trait]
impl CodexRunner for DockerCodexRunner {
    async fn run_review(&self, ctx: ReviewContext) -> Result<CodexResult> {
        info!(repo = ctx.repo.as_str(), iid = ctx.mr.iid, "starting codex review");
        let output = self.run_app_server_review(&ctx).await?;
        parse_review_output(&output).with_context(|| {
            format!(
                "parse codex review output for repo {} merge request {}",
                ctx.repo, ctx.mr.iid
            )
        })
    }
}

struct AppServerClient {
    input: Pin<Box<dyn tokio::io::AsyncWrite + Send>>,
    output: Pin<Box<dyn futures::Stream<Item = Result<LogOutput, bollard::errors::Error>> + Send>>,
    buffer: Vec<u8>,
    pending_notifications: VecDeque<Value>,
    reasoning_buffers: HashMap<String, ReasoningBuffer>,
    log_all_json: bool,
}

#[derive(Default)]
struct ReasoningBuffer {
    summary: String,
    text: String,
}

impl AppServerClient {
    fn new(
        attach: bollard::container::AttachContainerResults,
        log_all_json: bool,
    ) -> Self {
        Self {
            input: attach.input,
            output: attach.output,
            buffer: Vec::new(),
            pending_notifications: VecDeque::new(),
            reasoning_buffers: HashMap::new(),
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
        self.send_json(&json!({ "method": "initialized" }))
            .await
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
                        info!(item_id, kind = "agent", message = %delta, "codex item message");
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
                    if let Some(item) = params.and_then(|value| value.get("item")) {
                        if let Some(item_type) = item.get("type").and_then(|value| value.as_str()) {
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
                                    info!(
                                        item_id,
                                        command,
                                        cwd,
                                        status,
                                        "codex command started"
                                    );
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
                }
                "item/completed" => {
                    if let Some(item) = params.and_then(|value| value.get("item")) {
                        if let Some(item_type) = item.get("type").and_then(|value| value.as_str()) {
                            if item_type == "reasoning" {
                                if let Some(item_id) =
                                    item.get("id").and_then(|value| value.as_str())
                                {
                                    if let Some(buffer) =
                                        self.reasoning_buffers.remove(item_id)
                                    {
                                        let reasoning = if !buffer.summary.trim().is_empty() {
                                            buffer.summary
                                        } else {
                                            buffer.text
                                        };
                                        if !reasoning.trim().is_empty() {
                                            info!(item_id, reasoning = reasoning.as_str(), "codex reasoning completed");
                                        }
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
                                let duration_ms =
                                    item.get("durationMs").and_then(|value| value.as_i64());
                                info!(
                                    item_id,
                                    command,
                                    cwd,
                                    status,
                                    exit_code,
                                    duration_ms,
                                    "codex command completed"
                                );
                            } else {
                                info!(item_type, "codex item completed");
                            }
                        }
                        if let Some(review) = item
                            .get("review")
                            .and_then(|value| value.as_str())
                        {
                            if item
                                .get("type")
                                .and_then(|value| value.as_str())
                                == Some("exitedReviewMode")
                            {
                                review_text = Some(review.to_string());
                            }
                        }
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
                    break;
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
        }

        review_text.ok_or_else(|| anyhow!("codex review missing review text"))
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
                if trimmed.starts_with("codex-runner-error:") {
                    warn!("{}", trimmed);
                    continue;
                }
                if trimmed.starts_with("codex-install:") {
                    info!("{}", trimmed);
                    continue;
                }
                if trimmed.starts_with("codex-install-error:") {
                    warn!("{}", trimmed);
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
                Some(Err(err)) => return Err(anyhow!(err).context("read codex app-server output")),
                None => bail!("codex app-server closed stdout"),
            }
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

fn parse_review_output(text: &str) -> Result<CodexResult> {
    let trimmed = text.trim();
    if trimmed.is_empty() {
        return Ok(CodexResult::Pass {
            summary: "no issues found".to_string(),
        });
    }

    if let Some(json_text) = extract_json_block(trimmed) {
        if let Ok(parsed) = serde_json::from_str::<CodexOutput>(&json_text) {
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

#[derive(Debug, Deserialize)]
struct CodexOutput {
    verdict: String,
    summary: String,
    comment_markdown: String,
}

#[cfg(test)]
mod tests {
    use super::*;

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
    fn app_server_cmd_uses_bash_login_args() {
        let cmd = DockerCodexRunner::app_server_cmd("echo hi".to_string());
        assert_eq!(cmd, vec!["-lc".to_string(), "echo hi".to_string()]);
    }

    #[test]
    fn build_command_script_sets_writable_codex_home() {
        let script = DockerCodexRunner::build_command_script(
            "https://example.com/repo.git",
            "abc",
            "/root/.codex",
            None,
        );
        assert!(script.contains("codex_home=\"/tmp/codex\""));
        assert!(script.contains("export CODEX_HOME=\"${codex_home}\""));
        assert!(script.contains("cp \"/root/.codex/auth.json\""));
    }

    #[test]
    fn build_command_script_fetches_target_branch() {
        let script = DockerCodexRunner::build_command_script(
            "https://example.com/repo.git",
            "abc",
            "/root/.codex",
            Some("main"),
        );
        assert!(script.contains("git fetch --depth 1 origin \"main\""));
        assert!(script.contains("git branch --force \"main\" FETCH_HEAD"));
        assert!(script.contains("git fetch --unshallow"));
    }
}
