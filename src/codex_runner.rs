use crate::config::{CodexConfig, DockerConfig, ProxyConfig};
use crate::docker_utils::{connect_docker, ensure_image, normalize_image_reference};
use crate::gitlab::MergeRequest;
use anyhow::{Context, Result, anyhow, bail};
use async_trait::async_trait;
use bollard::Docker;
use bollard::container::LogOutput;
use bollard::models::{ContainerCreateBody, HostConfig};
use bollard::query_parameters::{
    AttachContainerOptionsBuilder, CreateContainerOptionsBuilder, ListContainersOptionsBuilder,
    RemoveContainerOptionsBuilder, StartContainerOptionsBuilder,
};
use futures::StreamExt;
use serde::Deserialize;
use serde_json::{Value, json};
use std::cell::RefCell;
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
const REVIEW_OWNER_LABEL_KEY: &str = "codex.gitlab.review.owner";

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
    proxy: ProxyConfig,
    git_base: Url,
    gitlab_token: String,
    log_all_json: bool,
    owner_id: String,
}

impl DockerCodexRunner {
    pub fn new(
        docker_cfg: DockerConfig,
        codex: CodexConfig,
        proxy: ProxyConfig,
        git_base: Url,
        gitlab_token: String,
        log_all_json: bool,
        owner_id: String,
    ) -> Result<Self> {
        let docker = connect_docker(&docker_cfg)?;
        Ok(Self {
            docker,
            codex,
            proxy,
            git_base,
            gitlab_token,
            log_all_json,
            owner_id,
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
            self.codex.deps.enabled,
        ))
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
    ) -> String {
        let clone_url_dq = clone_url.replace('\\', "\\\\").replace('"', "\\\"");
        let head_sha_q = shell_quote(&ctx.head_sha);
        let auth_mount_path_q = shell_quote(auth_mount_path);
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
exec codex app-server
"#,
            clone_url_dq = clone_url_dq,
            head_sha_q = head_sha_q,
            auth_mount_path_q = auth_mount_path_q,
        )
    }

    fn build_command_script(
        clone_url: &str,
        head_sha: &str,
        auth_mount_path: &str,
        target_branch: Option<&str>,
        deps_enabled: bool,
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
exec codex app-server
"#,
            clone_url = clone_url,
            head_sha = head_sha,
            auth_mount_path = auth_mount_path,
            target_branch_script = target_branch_script,
            deps_prefetch_script = deps_prefetch_script
        )
    }

    fn app_server_cmd(script: String) -> Vec<String> {
        // The codex-universal entrypoint runs `bash --login "$@"`, so pass only bash flags + script.
        vec!["-lc".to_string(), script]
    }

    fn normalize_image_reference(image: &str) -> String {
        normalize_image_reference(image)
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

    fn is_review_container_name(name: &str) -> bool {
        name.trim_start_matches('/')
            .starts_with(REVIEW_CONTAINER_NAME_PREFIX)
    }

    fn review_container_labels(owner_id: &str) -> HashMap<String, String> {
        HashMap::from([(REVIEW_OWNER_LABEL_KEY.to_string(), owner_id.to_string())])
    }

    fn review_container_filters(owner_id: &str) -> HashMap<String, Vec<String>> {
        HashMap::from([
            (
                "name".to_string(),
                vec![REVIEW_CONTAINER_NAME_PREFIX.to_string()],
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
                .any(|name| Self::is_review_container_name(name))
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
                    "skipping codex review container without id"
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
                    .find(|name| Self::is_review_container_name(name))
                    .map(|name| name.trim_start_matches('/'))
                    .unwrap_or("<unknown>");
                warn!(
                    container_id = id,
                    container_name,
                    error = %err,
                    "failed to remove codex review container"
                );
            }
        }
    }

    async fn start_app_server_container(
        &self,
        script: String,
        extra_binds: Vec<String>,
    ) -> Result<(String, AppServerClient)> {
        let image_ref = Self::normalize_image_reference(&self.codex.image);
        ensure_image(&self.docker, &image_ref).await?;
        let name = format!("{}{}", REVIEW_CONTAINER_NAME_PREFIX, Uuid::new_v4());
        let mut binds = vec![format!(
            "{}:{}:rw",
            self.codex.auth_host_path, self.codex.auth_mount_path
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
                format!("create docker container {} with image {}", name, image_ref)
            })?;
        let id = create.id;
        let start_result = self
            .docker
            .start_container(&id, Some(StartContainerOptionsBuilder::new().build()))
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
                return Err(err);
            }
        };

        Ok((id, AppServerClient::new(attach, self.log_all_json)))
    }

    async fn run_app_server_review(&self, ctx: &ReviewContext) -> Result<String> {
        let script = self.command(ctx)?;
        let (id, mut client) = self.start_app_server_container(script, Vec::new()).await?;
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

        self.remove_container_best_effort(&id).await;

        review_result.map_err(|_| anyhow!("codex review timed out"))?
    }

    async fn run_mention_container_with_sandbox(
        &self,
        ctx: &MentionCommandContext,
        sandbox_mode: &str,
    ) -> Result<MentionCommandResult> {
        let clone_url = self.clone_url(&ctx.repo)?;
        let repo_dir = "/work/repo";
        let script =
            Self::build_mention_command_script(ctx, &clone_url, &self.codex.auth_mount_path);
        let (id, mut client) = self.start_app_server_container(script, Vec::new()).await?;

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

            client
                .exec_one_off_command(
                    vec![
                        "git".to_string(),
                        "config".to_string(),
                        "user.name".to_string(),
                        ctx.requester_name.clone(),
                    ],
                    Some(repo_dir),
                    None,
                    sandbox_mode,
                )
                .await?;
            client
                .exec_one_off_command(
                    vec![
                        "git".to_string(),
                        "config".to_string(),
                        "user.email".to_string(),
                        ctx.requester_email.clone(),
                    ],
                    Some(repo_dir),
                    None,
                    sandbox_mode,
                )
                .await?;
            client
                .exec_one_off_command(
                    vec![
                        "git".to_string(),
                        "remote".to_string(),
                        "set-url".to_string(),
                        "--push".to_string(),
                        "origin".to_string(),
                        "no_push://disabled".to_string(),
                    ],
                    Some(repo_dir),
                    None,
                    sandbox_mode,
                )
                .await?;
            let before_sha = client
                .exec_one_off_command(
                    vec![
                        "git".to_string(),
                        "rev-parse".to_string(),
                        "HEAD".to_string(),
                    ],
                    Some(repo_dir),
                    None,
                    sandbox_mode,
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

            let after_sha = client
                .exec_one_off_command(
                    vec![
                        "git".to_string(),
                        "rev-parse".to_string(),
                        "HEAD".to_string(),
                    ],
                    Some(repo_dir),
                    None,
                    sandbox_mode,
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
                if let Err(err) = client
                    .exec_one_off_command(
                        vec![
                            "git".to_string(),
                            "merge-base".to_string(),
                            "--is-ancestor".to_string(),
                            before_sha.clone(),
                            after_sha.clone(),
                        ],
                        Some(repo_dir),
                        None,
                        sandbox_mode,
                    )
                    .await
                {
                    bail!("mention command moved HEAD outside MR ancestry: {err}");
                }
                let commit_count_output = client
                    .exec_one_off_command(
                        vec![
                            "git".to_string(),
                            "rev-list".to_string(),
                            "--count".to_string(),
                            format!("{before_sha}..{after_sha}"),
                        ],
                        Some(repo_dir),
                        None,
                        sandbox_mode,
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
                client
                    .exec_one_off_command(
                        vec![
                            "bash".to_string(),
                            "-lc".to_string(),
                            format!("git remote set-url --push origin \"{push_url_dq}\""),
                        ],
                        Some(repo_dir),
                        None,
                        sandbox_mode,
                    )
                    .await?;
                client
                    .exec_one_off_command(
                        vec![
                            "git".to_string(),
                            "push".to_string(),
                            "origin".to_string(),
                            format!("HEAD:{source_branch}"),
                        ],
                        Some(repo_dir),
                        None,
                        sandbox_mode,
                    )
                    .await?;
                (MentionCommandStatus::Committed, Some(after_sha))
            } else {
                let worktree_state = client
                    .exec_one_off_command(
                        vec![
                            "git".to_string(),
                            "status".to_string(),
                            "--porcelain".to_string(),
                        ],
                        Some(repo_dir),
                        None,
                        sandbox_mode,
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

        self.remove_container_best_effort(&id).await;

        mention_result.map_err(|_| anyhow!("codex mention command timed out"))?
    }

    async fn run_mention_container(
        &self,
        ctx: &MentionCommandContext,
    ) -> Result<MentionCommandResult> {
        self.run_mention_container_with_sandbox(ctx, self.sandbox_mode_value())
            .await
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

    async fn exec_one_off_command(
        &mut self,
        command: Vec<String>,
        cwd: Option<&str>,
        timeout_ms: Option<u64>,
        sandbox_mode: &str,
    ) -> Result<ExecOneOffCommandOutput> {
        let response = self
            .request(
                "execOneOffCommand",
                json!({
                    "command": command,
                    "cwd": cwd,
                    "timeoutMs": timeout_ms,
                    "sandboxPolicy": exec_one_off_sandbox_policy(sandbox_mode),
                }),
            )
            .await?;
        let parsed: ExecOneOffCommandOutput =
            serde_json::from_value(response).context("parse execOneOffCommand response")?;
        if parsed.exit_code != 0 {
            let stderr = parsed.stderr.trim();
            if stderr.is_empty() {
                bail!(
                    "execOneOffCommand failed with exit code {}",
                    parsed.exit_code
                );
            }
            bail!(
                "execOneOffCommand failed with exit code {}: {}",
                parsed.exit_code,
                stderr
            );
        }
        Ok(parsed)
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

fn exec_one_off_sandbox_policy(sandbox_mode: &str) -> Value {
    match sandbox_mode {
        "read-only" => json!({ "type": "read-only" }),
        "workspace-write" => json!({ "type": "workspace-write" }),
        _ => json!({ "type": "danger-full-access" }),
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

#[derive(Debug, Deserialize)]
struct CodexOutput {
    verdict: String,
    summary: String,
    comment_markdown: String,
}

#[derive(Debug, Deserialize)]
struct ExecOneOffCommandOutput {
    #[serde(rename = "exitCode")]
    exit_code: i32,
    stdout: String,
    stderr: String,
}

fn shell_quote(input: &str) -> String {
    format!("'{}'", input.replace('\'', "'\"'\"'"))
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
            false,
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
        );
        assert!(script.contains("prefetch_deps()"));
        assert!(script.contains("composer install"));
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
        assert!(DockerCodexRunner::is_review_container_name(
            "codex-review-abc"
        ));
        assert!(DockerCodexRunner::is_review_container_name(
            "/codex-review-def"
        ));
        assert!(!DockerCodexRunner::is_review_container_name(
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
            Some(&vec![REVIEW_CONTAINER_NAME_PREFIX.to_string()])
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
