use super::server::build_router;
use super::{
    GitLabCheckoutKind, GitLabDiscoverySessionBinding, GitLabDiscoverySessionRegistry,
    ResolvedGitLabDiscoveryAllowList, resolve_allow_list,
};
use crate::config::{DockerConfig, GitLabConfig, GitLabDiscoveryMcpConfig};
use crate::docker_utils::connect_docker;
use crate::gitlab::GitLabClient;
use anyhow::{Context, Result, anyhow, bail};
use bollard::Docker;
use bollard::container::LogOutput;
use bollard::exec::{StartExecOptions, StartExecResults};
use bollard::models::ExecConfig;
use futures::StreamExt;
use rmcp::ErrorData as McpError;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio_util::sync::CancellationToken;
use tracing::error;
use url::Url;

#[derive(Clone)]
pub struct GitLabDiscoveryMcpService {
    config: GitLabDiscoveryMcpConfig,
    docker: Docker,
    pub(crate) gitlab: GitLabClient,
    git_base: Url,
    gitlab_token: String,
    registry: Arc<GitLabDiscoverySessionRegistry>,
    shutdown: CancellationToken,
}

#[derive(Debug, Clone)]
struct ContainerExecOutput {
    exit_code: i64,
    stdout: String,
    stderr: String,
}

impl GitLabDiscoveryMcpService {
    pub fn new(
        docker_cfg: DockerConfig,
        gitlab_cfg: &GitLabConfig,
        config: GitLabDiscoveryMcpConfig,
    ) -> Result<Self> {
        let docker = connect_docker(&docker_cfg)?;
        let gitlab = GitLabClient::new(&gitlab_cfg.base_url, &gitlab_cfg.token)?;
        let git_base = gitlab.git_base_url()?;
        Ok(Self {
            config,
            docker,
            gitlab,
            git_base,
            gitlab_token: gitlab_cfg.token.clone(),
            registry: Arc::new(GitLabDiscoverySessionRegistry::default()),
            shutdown: CancellationToken::new(),
        })
    }

    pub fn registry(&self) -> Arc<GitLabDiscoverySessionRegistry> {
        Arc::clone(&self.registry)
    }

    pub fn advertise_url(&self) -> &str {
        &self.config.advertise_url
    }

    pub fn server_name(&self) -> &str {
        &self.config.server_name
    }

    pub fn clone_root(&self) -> &str {
        &self.config.clone_root
    }

    pub fn resolve_allow_list(&self, source_repo: &str) -> ResolvedGitLabDiscoveryAllowList {
        resolve_allow_list(source_repo, &self.config.allow)
    }

    pub async fn bind_listener(&self) -> Result<TcpListener> {
        TcpListener::bind(&self.config.bind_addr)
            .await
            .with_context(|| {
                format!(
                    "bind gitlab discovery MCP server on {}",
                    self.config.bind_addr
                )
            })
    }

    pub async fn run(self: Arc<Self>, listener: TcpListener) {
        let app = build_router(Arc::clone(&self));
        if let Err(err) = axum::serve(
            listener,
            app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
        )
        .with_graceful_shutdown(async move { self.shutdown.cancelled().await })
        .await
        {
            error!(error = %err, "gitlab discovery MCP server failed");
        }
    }

    pub fn shutdown(&self) {
        self.shutdown.cancel();
    }

    pub(crate) async fn clone_repository(
        &self,
        binding: &GitLabDiscoverySessionBinding,
        repo_path: &str,
    ) -> Result<String> {
        let clone_url = self
            .clone_url_template(repo_path)?
            .replace('\\', "\\\\")
            .replace('"', "\\\"");
        let script = format!(
            r#"set -eu
clone_root={clone_root}
repo_path={repo_path}
clone_url="{clone_url}"
mkdir -p "$clone_root"
safe_repo="$(printf '%s' "$repo_path" | tr '/:@' '____')"
dest="$(mktemp -d "$clone_root/${{safe_repo}}-XXXXXX")"
git clone "$clone_url" "$dest" >/tmp/gitlab-discovery-clone.log 2>&1 || {{
  tail -n 100 /tmp/gitlab-discovery-clone.log >&2
  exit 1
}}
cd "$dest"
git fetch --prune origin '+refs/heads/*:refs/remotes/origin/*' >/tmp/gitlab-discovery-fetch.log 2>&1 || {{
  tail -n 100 /tmp/gitlab-discovery-fetch.log >&2
  exit 1
}}
git fetch --tags origin >/tmp/gitlab-discovery-tags.log 2>&1 || {{
  tail -n 100 /tmp/gitlab-discovery-tags.log >&2
  exit 1
}}
origin_url="$(git remote get-url origin || true)"
if [ -n "$origin_url" ]; then
  sanitized_origin="$(printf '%s' "$origin_url" | sed -E 's#(https?://)oauth2:[^@]*@#\1#')"
  git remote set-url origin "$sanitized_origin"
fi
git remote set-url --push origin "no_push://disabled"
printf '%s\n' "$dest"
"#,
            clone_root = shell_quote(&binding.clone_root),
            repo_path = shell_quote(repo_path),
            clone_url = clone_url,
        );
        let output = self
            .exec_container_command(
                &binding.container_id,
                vec!["/bin/bash".to_string(), "-lc".to_string(), script],
                None,
                Some(vec![format!("GITLAB_TOKEN={}", self.gitlab_token)]),
            )
            .await?;
        Ok(output.stdout.trim().to_string())
    }

    pub(crate) async fn list_remote_branches(
        &self,
        container_id: &str,
        repo_path: &str,
    ) -> Result<Vec<String>> {
        let output = self
            .exec_container_command(
                container_id,
                vec![
                    "git".to_string(),
                    "for-each-ref".to_string(),
                    "--format=%(refname:lstrip=3)".to_string(),
                    "refs/remotes/origin".to_string(),
                ],
                Some(repo_path),
                None,
            )
            .await?;
        let mut branches = output
            .stdout
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty() && *line != "HEAD")
            .map(ToOwned::to_owned)
            .collect::<Vec<_>>();
        branches.sort();
        branches.dedup();
        Ok(branches)
    }

    pub(crate) async fn list_tags(
        &self,
        container_id: &str,
        repo_path: &str,
    ) -> Result<Vec<String>> {
        let output = self
            .exec_container_command(
                container_id,
                vec!["git".to_string(), "tag".to_string(), "--list".to_string()],
                Some(repo_path),
                None,
            )
            .await?;
        let mut tags = output
            .stdout
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty())
            .map(ToOwned::to_owned)
            .collect::<Vec<_>>();
        tags.sort();
        tags.dedup();
        Ok(tags)
    }

    pub(crate) async fn default_branch(
        &self,
        container_id: &str,
        repo_path: &str,
    ) -> Result<String> {
        let output = self
            .exec_container_command(
                container_id,
                vec![
                    "git".to_string(),
                    "symbolic-ref".to_string(),
                    "refs/remotes/origin/HEAD".to_string(),
                ],
                Some(repo_path),
                None,
            )
            .await?;
        output
            .stdout
            .trim()
            .strip_prefix("refs/remotes/origin/")
            .map(ToOwned::to_owned)
            .context("parse default branch from refs/remotes/origin/HEAD")
    }

    pub(crate) async fn checkout_ref(
        &self,
        container_id: &str,
        repo_path: &str,
        checkout_ref: &str,
        branches: &[String],
        tags: &[String],
    ) -> Result<(String, GitLabCheckoutKind)> {
        let (resolved_ref, kind, command) =
            if let Some(branch_name) = checkout_ref.strip_prefix("refs/heads/") {
                ensure_contains(branches, branch_name, "branch")?;
                (
                    checkout_ref.to_string(),
                    GitLabCheckoutKind::Branch,
                    vec![
                        "git".to_string(),
                        "checkout".to_string(),
                        "-B".to_string(),
                        branch_name.to_string(),
                        format!("refs/remotes/origin/{branch_name}"),
                    ],
                )
            } else if let Some(tag_name) = checkout_ref.strip_prefix("refs/tags/") {
                ensure_contains(tags, tag_name, "tag")?;
                (
                    checkout_ref.to_string(),
                    GitLabCheckoutKind::Tag,
                    vec![
                        "git".to_string(),
                        "checkout".to_string(),
                        "--detach".to_string(),
                        format!("refs/tags/{tag_name}"),
                    ],
                )
            } else {
                let branch_exists = branches.iter().any(|branch| branch == checkout_ref);
                let tag_exists = tags.iter().any(|tag| tag == checkout_ref);
                match (branch_exists, tag_exists) {
                    (true, true) => bail!(
                        "checkout_ref '{}' is ambiguous; use refs/heads/{} or refs/tags/{}",
                        checkout_ref,
                        checkout_ref,
                        checkout_ref
                    ),
                    (true, false) => (
                        checkout_ref.to_string(),
                        GitLabCheckoutKind::Branch,
                        vec![
                            "git".to_string(),
                            "checkout".to_string(),
                            "-B".to_string(),
                            checkout_ref.to_string(),
                            format!("refs/remotes/origin/{checkout_ref}"),
                        ],
                    ),
                    (false, true) => (
                        checkout_ref.to_string(),
                        GitLabCheckoutKind::Tag,
                        vec![
                            "git".to_string(),
                            "checkout".to_string(),
                            "--detach".to_string(),
                            format!("refs/tags/{checkout_ref}"),
                        ],
                    ),
                    (false, false) => bail!(
                        "checkout_ref '{}' does not match any fetched branch or tag",
                        checkout_ref
                    ),
                }
            };

        self.exec_container_command(container_id, command, Some(repo_path), None)
            .await?;
        Ok((resolved_ref, kind))
    }

    pub(crate) async fn head_sha(&self, container_id: &str, repo_path: &str) -> Result<String> {
        let output = self
            .exec_container_command(
                container_id,
                vec![
                    "git".to_string(),
                    "rev-parse".to_string(),
                    "HEAD".to_string(),
                ],
                Some(repo_path),
                None,
            )
            .await?;
        Ok(output.stdout.trim().to_string())
    }

    async fn exec_container_command(
        &self,
        container_id: &str,
        command: Vec<String>,
        cwd: Option<&str>,
        env: Option<Vec<String>>,
    ) -> Result<ContainerExecOutput> {
        let exec = self
            .docker
            .create_exec(
                container_id,
                ExecConfig {
                    attach_stdout: Some(true),
                    attach_stderr: Some(true),
                    cmd: Some(command.clone()),
                    working_dir: cwd.map(ToOwned::to_owned),
                    env,
                    ..Default::default()
                },
            )
            .await
            .with_context(|| format!("create docker exec for container {}", container_id))?;

        let start = self
            .docker
            .start_exec(&exec.id, None::<StartExecOptions>)
            .await
            .with_context(|| format!("start docker exec for container {}", container_id))?;

        let mut stdout = String::new();
        let mut stderr = String::new();
        match start {
            StartExecResults::Attached { mut output, .. } => {
                while let Some(message) = output.next().await {
                    match message.context("read docker exec output")? {
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
            StartExecResults::Detached => bail!("docker exec unexpectedly detached"),
        }

        let inspect = self
            .docker
            .inspect_exec(&exec.id)
            .await
            .context("inspect docker exec result")?;
        let output = ContainerExecOutput {
            exit_code: inspect.exit_code.unwrap_or(-1),
            stdout: self.redact_sensitive_output(&stdout),
            stderr: self.redact_sensitive_output(&stderr),
        };
        if output.exit_code != 0 {
            bail!(
                "docker exec failed (exit={}): stdout='{}' stderr='{}'",
                output.exit_code,
                output.stdout.trim(),
                output.stderr.trim()
            );
        }
        Ok(output)
    }

    fn clone_url_template(&self, repo: &str) -> Result<String> {
        let encoded_path = repo
            .split('/')
            .map(urlencoding::encode)
            .collect::<Vec<_>>()
            .join("/");
        let scheme = self.git_base.scheme();
        let host = self
            .git_base
            .host_str()
            .ok_or_else(|| anyhow!("missing git base host"))?;
        let mut host_port = host.to_string();
        if let Some(port) = self.git_base.port() {
            host_port = format!("{host}:{port}");
        }
        let base_path = self.git_base.path().trim_end_matches('/');
        let repo_path = if base_path.is_empty() {
            format!("/{encoded_path}.git")
        } else {
            format!("{base_path}/{encoded_path}.git")
        };
        if self.gitlab_token.is_empty() {
            Ok(format!("{scheme}://{host_port}{repo_path}"))
        } else {
            Ok(format!(
                "{scheme}://oauth2:${{GITLAB_TOKEN}}@{host_port}{repo_path}"
            ))
        }
    }

    fn redact_sensitive_output(&self, input: &str) -> String {
        let mut redacted = if self.gitlab_token.is_empty() {
            input.to_string()
        } else {
            input.replace(&self.gitlab_token, "[REDACTED_GITLAB_TOKEN]")
        };

        let mut sanitized = String::with_capacity(redacted.len());
        while let Some(index) = redacted.find("oauth2:") {
            sanitized.push_str(&redacted[..index]);
            let suffix = &redacted[index + "oauth2:".len()..];
            if let Some(at_index) = suffix.find('@') {
                sanitized.push_str("oauth2:[REDACTED]@");
                redacted = suffix[at_index + 1..].to_string();
            } else {
                sanitized.push_str(&redacted[index..]);
                redacted.clear();
                break;
            }
        }
        sanitized.push_str(&redacted);
        sanitized
    }
}

fn ensure_contains(values: &[String], wanted: &str, label: &str) -> Result<()> {
    if values.iter().any(|value| value == wanted) {
        Ok(())
    } else {
        bail!(
            "{label} '{}' was not fetched for the cloned repository",
            wanted
        )
    }
}

pub(crate) fn shell_quote(input: &str) -> String {
    format!("'{}'", input.replace('\'', "'\"'\"'"))
}

pub(crate) fn mcp_internal_error(err: anyhow::Error) -> McpError {
    McpError::internal_error(err.to_string(), None)
}

#[cfg(test)]
mod tests {
    use super::GitLabDiscoveryMcpService;

    #[test]
    fn redact_sensitive_output_removes_gitlab_tokens_from_urls_and_plain_text() {
        let service = GitLabDiscoveryMcpService {
            config: crate::config::GitLabDiscoveryMcpConfig::default(),
            docker: crate::docker_utils::connect_docker(&crate::config::DockerConfig::default())
                .expect("docker client"),
            gitlab: crate::gitlab::GitLabClient::new("https://gitlab.example.com", "secret-token")
                .expect("gitlab client"),
            git_base: url::Url::parse("https://gitlab.example.com").expect("git base"),
            gitlab_token: "secret-token".to_string(),
            registry: std::sync::Arc::new(super::GitLabDiscoverySessionRegistry::default()),
            shutdown: tokio_util::sync::CancellationToken::new(),
        };

        let input = "fatal: could not read from https://oauth2:secret-token@gitlab.example.com/group/repo.git\nplain secret-token token";
        let output = service.redact_sensitive_output(input);

        assert!(!output.contains("secret-token"));
        assert!(output.contains("oauth2:[REDACTED]@gitlab.example.com/group/repo.git"));
        assert!(output.contains("[REDACTED_GITLAB_TOKEN]"));
    }
}
