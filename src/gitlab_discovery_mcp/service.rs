use super::server::build_router;
use super::{
    GitLabCheckoutKind, GitLabDiscoverySessionBinding, GitLabDiscoverySessionRegistry,
    ResolvedGitLabDiscoveryAllowList, resolve_allow_list,
};
use crate::codex_runner::docker::connect_docker;
use crate::codex_runner::placeholders::render_placeholders;
use crate::composer_install::{
    ComposerInstallExecOutput, ComposerInstallMode, ComposerInstallResult,
    DEFAULT_COMPOSER_INSTALL_TIMEOUT_SECONDS, composer_debug_lines, composer_install_exec_command,
    composer_install_result_from_exec_output, prepare_composer_auth,
    redact_composer_related_output, resolve_composer_auth,
};
use crate::config::{DockerConfig, GitLabConfig, GitLabDiscoveryMcpConfig};
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

const CLONE_REPOSITORY_SCRIPT_TEMPLATE: &str = include_str!("assets/clone_repository.sh");
// Git runs this helper from the environment without writing the token to config.
const GITLAB_CREDENTIAL_HELPER: &str = "!f() { if [ \"$1\" = get ]; then printf 'username=oauth2\\npassword=%s\\n' \"$GITLAB_TOKEN\"; fi; }; f";

#[derive(Clone)]
pub struct GitLabDiscoveryMcpService {
    config: GitLabDiscoveryMcpConfig,
    /// Host of `config.advertise_url`. Codex containers send it in the `Host` header.
    advertised_host: String,
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

#[derive(Clone, Copy)]
pub(crate) struct CheckoutTargetRequest<'a> {
    pub(crate) repo_path: &'a str,
    pub(crate) gitlab_repo_path: &'a str,
    pub(crate) checkout_ref: Option<&'a str>,
    pub(crate) commit_sha: Option<&'a str>,
    pub(crate) branches: &'a [String],
    pub(crate) tags: &'a [String],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ResolvedCheckoutTarget {
    Branch {
        requested_ref: String,
        branch_name: String,
    },
    Tag {
        requested_ref: String,
        tag_name: String,
    },
    Commit {
        commit_sha: String,
    },
}

impl ResolvedCheckoutTarget {
    fn checked_out_ref(&self) -> &str {
        match self {
            Self::Branch { requested_ref, .. } | Self::Tag { requested_ref, .. } => requested_ref,
            Self::Commit { commit_sha } => commit_sha,
        }
    }

    fn checked_out_kind(&self) -> GitLabCheckoutKind {
        match self {
            Self::Branch { .. } => GitLabCheckoutKind::Branch,
            Self::Tag { .. } => GitLabCheckoutKind::Tag,
            Self::Commit { .. } => GitLabCheckoutKind::Commit,
        }
    }

    fn checkout_command(&self) -> Vec<String> {
        match self {
            Self::Branch { branch_name, .. } => vec![
                "git".to_string(),
                "checkout".to_string(),
                "-B".to_string(),
                branch_name.clone(),
                format!("refs/remotes/origin/{branch_name}"),
            ],
            Self::Tag { tag_name, .. } => vec![
                "git".to_string(),
                "checkout".to_string(),
                "--detach".to_string(),
                format!("refs/tags/{tag_name}"),
            ],
            Self::Commit { commit_sha } => vec![
                "git".to_string(),
                "checkout".to_string(),
                "--detach".to_string(),
                commit_sha.clone(),
            ],
        }
    }
}

impl GitLabDiscoveryMcpService {
    /// # Errors
    ///
    /// Returns an error if the Docker or GitLab client cannot be created, or if
    /// `config.advertise_url` has no host.
    pub fn new(
        docker_cfg: DockerConfig,
        gitlab_cfg: &GitLabConfig,
        config: GitLabDiscoveryMcpConfig,
    ) -> Result<Self> {
        let docker = connect_docker(&docker_cfg)?;
        let gitlab = GitLabClient::new(&gitlab_cfg.base_url, &gitlab_cfg.token)?;
        let git_base = gitlab.git_base_url()?;
        let advertised_host = Url::parse(&config.advertise_url)
            .ok()
            .and_then(|url| url.host_str().map(ToOwned::to_owned))
            .with_context(|| {
                format!(
                    "parse codex.gitlab_discovery_mcp.advertise_url host from {}",
                    config.advertise_url
                )
            })?;
        Ok(Self {
            config,
            advertised_host,
            docker,
            gitlab,
            git_base,
            gitlab_token: gitlab_cfg.token.clone(),
            registry: Arc::new(GitLabDiscoverySessionRegistry::default()),
            shutdown: CancellationToken::new(),
        })
    }

    #[must_use]
    pub fn registry(&self) -> Arc<GitLabDiscoverySessionRegistry> {
        Arc::clone(&self.registry)
    }

    #[must_use]
    pub fn advertise_url(&self) -> &str {
        &self.config.advertise_url
    }

    pub(crate) fn advertised_host(&self) -> &str {
        &self.advertised_host
    }

    #[must_use]
    pub fn server_name(&self) -> &str {
        &self.config.server_name
    }

    #[must_use]
    pub fn clone_root(&self) -> &str {
        &self.config.clone_root
    }

    #[must_use]
    pub fn resolve_allow_list(&self, source_repo: &str) -> ResolvedGitLabDiscoveryAllowList {
        resolve_allow_list(source_repo, &self.config.allow)
    }

    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
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
        let app = build_router(&self);
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
        let script = clone_repository_script(
            &binding.clone_root,
            repo_path,
            &self.clone_url_template(repo_path)?,
        );
        let output = self
            .exec_container_command(
                &binding.container_id,
                vec!["/bin/bash".to_string(), "-lc".to_string(), script],
                None,
                Some(self.git_auth_env()),
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

    pub(crate) async fn checkout_target(
        &self,
        container_id: &str,
        request: CheckoutTargetRequest<'_>,
    ) -> Result<(String, GitLabCheckoutKind)> {
        let target = resolve_checkout_target(
            request.checkout_ref,
            request.commit_sha,
            request.branches,
            request.tags,
        )?;
        if let ResolvedCheckoutTarget::Commit { commit_sha } = &target {
            self.fetch_commit_if_missing(
                container_id,
                request.repo_path,
                request.gitlab_repo_path,
                commit_sha,
            )
            .await?;
        }

        self.exec_container_command(
            container_id,
            target.checkout_command(),
            Some(request.repo_path),
            None,
        )
        .await?;
        Ok((
            target.checked_out_ref().to_string(),
            target.checked_out_kind(),
        ))
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

    pub(crate) async fn run_composer_install(
        &self,
        binding: &GitLabDiscoverySessionBinding,
        repo_path: &str,
        gitlab_repo_path: &str,
    ) -> Option<ComposerInstallResult> {
        let mode = ComposerInstallMode::for_flags(&binding.feature_flags)?;
        let auth_lookup = resolve_composer_auth(&self.gitlab, gitlab_repo_path).await;
        let composer_auth = auth_lookup.value.clone();
        let prepared_auth = prepare_composer_auth(
            composer_auth.as_deref(),
            binding.feature_flags.composer_auto_repositories,
        );
        let debug_lines = composer_debug_lines(
            &auth_lookup,
            &prepared_auth,
            binding.feature_flags.composer_auto_repositories,
        );
        let env = prepared_auth
            .env_value
            .as_ref()
            .map(|value| vec![format!("COMPOSER_AUTH={value}")]);
        let command = composer_install_exec_command(
            mode,
            DEFAULT_COMPOSER_INSTALL_TIMEOUT_SECONDS,
            prepared_auth.repository_config_json.as_deref(),
        );
        match self
            .exec_container_command_allow_failure(
                &binding.container_id,
                command,
                Some(repo_path),
                env,
            )
            .await
        {
            Ok(output) => Some(composer_install_result_from_exec_output(
                ComposerInstallExecOutput {
                    mode,
                    auth_source: auth_lookup.source,
                    exit_code: output.exit_code,
                    stdout: &output.stdout,
                    stderr: &output.stderr,
                    gitlab_token: Some(&self.gitlab_token),
                    composer_auth: composer_auth.as_deref(),
                    debug_lines: &debug_lines,
                },
            )),
            Err(err) => Some(composer_install_result_from_exec_output(
                ComposerInstallExecOutput {
                    mode,
                    auth_source: auth_lookup.source,
                    exit_code: 1,
                    stdout: "",
                    stderr: &err.to_string(),
                    gitlab_token: Some(&self.gitlab_token),
                    composer_auth: composer_auth.as_deref(),
                    debug_lines: &debug_lines,
                },
            )),
        }
    }

    async fn exec_container_command(
        &self,
        container_id: &str,
        command: Vec<String>,
        cwd: Option<&str>,
        env: Option<Vec<String>>,
    ) -> Result<ContainerExecOutput> {
        let output = self
            .exec_container_command_allow_failure(container_id, command, cwd, env)
            .await?;
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

    async fn exec_container_command_allow_failure(
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
            .with_context(|| format!("create docker exec for container {container_id}"))?;

        let start = self
            .docker
            .start_exec(&exec.id, None::<StartExecOptions>)
            .await
            .with_context(|| format!("start docker exec for container {container_id}"))?;

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
            stdout: self.redact_sensitive_output(&stdout, None),
            stderr: self.redact_sensitive_output(&stderr, None),
        };
        Ok(output)
    }

    async fn fetch_commit_if_missing(
        &self,
        container_id: &str,
        repo_path: &str,
        gitlab_repo_path: &str,
        commit_sha: &str,
    ) -> Result<()> {
        if self
            .commit_exists(container_id, repo_path, commit_sha)
            .await?
        {
            return Ok(());
        }

        let fetch_url = self.clone_url_template(gitlab_repo_path)?;

        self.exec_container_command(
            container_id,
            vec![
                "git".to_string(),
                "fetch".to_string(),
                fetch_url,
                commit_sha.to_string(),
            ],
            Some(repo_path),
            Some(self.git_auth_env()),
        )
        .await
        .with_context(|| format!("fetch commit '{commit_sha}' from origin"))?;

        if self
            .commit_exists(container_id, repo_path, commit_sha)
            .await?
        {
            Ok(())
        } else {
            bail!("commit '{commit_sha}' was not fetched for the cloned repository");
        }
    }

    async fn commit_exists(
        &self,
        container_id: &str,
        repo_path: &str,
        commit_sha: &str,
    ) -> Result<bool> {
        let output = self
            .exec_container_command_allow_failure(
                container_id,
                vec![
                    "git".to_string(),
                    "cat-file".to_string(),
                    "-e".to_string(),
                    format!("{commit_sha}^{{commit}}"),
                ],
                Some(repo_path),
                None,
            )
            .await?;
        Ok(output.exit_code == 0)
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
        Ok(format!("{scheme}://{host_port}{repo_path}"))
    }

    /// Supplies credentials to Git subprocesses without a disk credential helper.
    fn git_auth_env(&self) -> Vec<String> {
        if self.gitlab_token.is_empty() {
            return Vec::new();
        }
        vec![
            format!("GITLAB_TOKEN={}", self.gitlab_token),
            "GIT_CONFIG_COUNT=2".to_string(),
            "GIT_CONFIG_KEY_0=credential.helper".to_string(),
            "GIT_CONFIG_VALUE_0=".to_string(),
            "GIT_CONFIG_KEY_1=credential.helper".to_string(),
            format!("GIT_CONFIG_VALUE_1={GITLAB_CREDENTIAL_HELPER}"),
            "GIT_TERMINAL_PROMPT=0".to_string(),
        ]
    }

    fn redact_sensitive_output(&self, input: &str, composer_auth: Option<&str>) -> String {
        redact_composer_related_output(input, Some(&self.gitlab_token), composer_auth)
    }
}

fn ensure_contains(values: &[String], wanted: &str, label: &str) -> Result<()> {
    if values.iter().any(|value| value == wanted) {
        Ok(())
    } else {
        bail!("{label} '{wanted}' was not fetched for the cloned repository")
    }
}

fn ensure_valid_commit_sha(commit_sha: &str) -> Result<()> {
    anyhow::ensure!(
        (7..=40).contains(&commit_sha.len()) && commit_sha.chars().all(|ch| ch.is_ascii_hexdigit()),
        "commit_sha must be a 7-40 character hexadecimal Git commit SHA"
    );
    Ok(())
}

pub(crate) fn resolve_checkout_target(
    checkout_ref: Option<&str>,
    commit_sha: Option<&str>,
    branches: &[String],
    tags: &[String],
) -> Result<ResolvedCheckoutTarget> {
    let checkout_ref = checkout_ref
        .map(str::trim)
        .filter(|value| !value.is_empty());
    let commit_sha = commit_sha.map(str::trim).filter(|value| !value.is_empty());

    if checkout_ref.is_some() && commit_sha.is_some() {
        bail!("checkout_ref and commit_sha are mutually exclusive");
    }

    if let Some(commit_sha) = commit_sha {
        ensure_valid_commit_sha(commit_sha)?;
        return Ok(ResolvedCheckoutTarget::Commit {
            commit_sha: commit_sha.to_string(),
        });
    }

    let checkout_ref = checkout_ref.context("checkout_ref or commit_sha is required")?;
    if let Some(branch_name) = checkout_ref.strip_prefix("refs/heads/") {
        ensure_contains(branches, branch_name, "branch")?;
        Ok(ResolvedCheckoutTarget::Branch {
            requested_ref: checkout_ref.to_string(),
            branch_name: branch_name.to_string(),
        })
    } else if let Some(tag_name) = checkout_ref.strip_prefix("refs/tags/") {
        ensure_contains(tags, tag_name, "tag")?;
        Ok(ResolvedCheckoutTarget::Tag {
            requested_ref: checkout_ref.to_string(),
            tag_name: tag_name.to_string(),
        })
    } else {
        let branch_exists = branches.iter().any(|branch| branch == checkout_ref);
        let tag_exists = tags.iter().any(|tag| tag == checkout_ref);
        match (branch_exists, tag_exists) {
            (true, true) => bail!(
                "checkout_ref '{checkout_ref}' is ambiguous; use refs/heads/{checkout_ref} or refs/tags/{checkout_ref}"
            ),
            (true, false) => Ok(ResolvedCheckoutTarget::Branch {
                requested_ref: checkout_ref.to_string(),
                branch_name: checkout_ref.to_string(),
            }),
            (false, true) => Ok(ResolvedCheckoutTarget::Tag {
                requested_ref: checkout_ref.to_string(),
                tag_name: checkout_ref.to_string(),
            }),
            (false, false) => {
                bail!("checkout_ref '{checkout_ref}' does not match any fetched branch or tag")
            }
        }
    }
}

fn clone_repository_script(clone_root: &str, repo_path: &str, clone_url: &str) -> String {
    let clone_url = clone_url.replace('\\', "\\\\").replace('"', "\\\"");
    render_placeholders(
        CLONE_REPOSITORY_SCRIPT_TEMPLATE,
        &[
            ("CLONE_ROOT", &shell_quote(clone_root)),
            ("REPO_PATH", &shell_quote(repo_path)),
            ("CLONE_URL", &clone_url),
        ],
    )
    .expect("clone repository script template placeholders are valid")
}

pub(crate) fn shell_quote(input: &str) -> String {
    format!("'{}'", input.replace('\'', "'\"'\"'"))
}

pub(crate) fn mcp_internal_error(err: anyhow::Error) -> McpError {
    McpError::internal_error(err.to_string(), None)
}

#[cfg(test)]
mod tests {
    use super::{
        GitLabDiscoveryMcpService, ResolvedCheckoutTarget, clone_repository_script,
        resolve_checkout_target,
    };
    use crate::gitlab_discovery_mcp::GitLabCheckoutKind;
    use std::fs;
    use std::io::Write;
    use std::os::unix::fs::PermissionsExt;
    use std::process::{Command, Stdio};

    #[test]
    fn clone_script_removes_failed_clones_and_keeps_tokens_off_disk() -> anyhow::Result<()> {
        let service = GitLabDiscoveryMcpService::new(
            crate::config::DockerConfig::default(),
            &crate::config::GitLabConfig {
                base_url: "https://gitlab.example.com".to_string(),
                token: "secret-clone-token".to_string(),
                bot_user_id: None,
                created_after: None,
                targets: crate::config::GitLabTargets::default(),
            },
            crate::config::GitLabDiscoveryMcpConfig {
                advertise_url: "http://host.docker.internal:8091/mcp".to_string(),
                ..Default::default()
            },
        )?;
        let temp = tempfile::tempdir()?;
        let bin = temp.path().join("bin");
        fs::create_dir(&bin)?;
        let stub = bin.join("git");
        fs::write(
            &stub,
            r#"#!/bin/bash
set -eu
case "$1" in
  clone)
    mkdir -p "$3/.git"
    printf '%s\n' "$3" > "$DEST_RECORD"
    printf '%s\n' "$2" > "$3/.git/config"
    printf '%s\n' "$2" > "$URL_RECORD"
    if [ "$FAIL_STAGE" = clone ]; then exit 23; fi
    ;;
  fetch)
    if [ "$FAIL_STAGE" = fetch ] || { [ "$FAIL_STAGE" = tags ] && [ "$2" = --tags ]; }; then
      printf '%s\n' 'fetch failed' >&2
      exit 23
    fi
    ;;
  remote)
    if [ "$2" = get-url ]; then cat .git/config; fi
    ;;
esac
"#,
        )?;
        fs::set_permissions(&stub, fs::Permissions::from_mode(0o755))?;
        let dest_record = temp.path().join("destination");
        let url_record = temp.path().join("clone-url");
        let git_env = service.git_auth_env();
        let git_env = git_env
            .iter()
            .map(|entry| entry.split_once('=').unwrap())
            .collect::<Vec<_>>();

        // Exercise Git's credential protocol with the production environment.
        let mut credential = Command::new("git")
            .args(["credential", "fill"])
            .envs(git_env.iter().copied())
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .current_dir(temp.path())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()?;
        credential
            .stdin
            .take()
            .unwrap()
            .write_all(b"protocol=https\nhost=gitlab.example.com\n\n")?;
        let credentials = credential.wait_with_output()?;
        assert!(credentials.status.success());
        let credentials = String::from_utf8(credentials.stdout)?;
        assert!(credentials.contains("username=oauth2\n"));
        assert!(credentials.contains(&format!("password={}\n", service.gitlab_token)));

        for fail_stage in ["fetch", "clone", "tags", "none"] {
            let root = temp.path().join(fail_stage);
            let script = clone_repository_script(
                root.to_str().unwrap(),
                "group/repo",
                &service.clone_url_template("group/repo")?,
            );
            let output = Command::new("bash")
                .args(["-c", &script])
                .env("PATH", format!("{}:/usr/bin:/bin", bin.display()))
                .envs(git_env.iter().copied())
                .env("DEST_RECORD", &dest_record)
                .env("URL_RECORD", &url_record)
                .env("FAIL_STAGE", fail_stage)
                .output()?;
            let destination = fs::read_to_string(&dest_record)?;
            if fail_stage == "none" {
                assert!(output.status.success(), "{output:?}");
                assert_eq!(String::from_utf8(output.stdout)?, destination);
                let config = fs::read_to_string(
                    std::path::Path::new(destination.trim()).join(".git/config"),
                )?;
                assert!(!config.contains(&service.gitlab_token));
            } else {
                assert!(!output.status.success());
                assert!(
                    !std::path::Path::new(destination.trim()).exists(),
                    "failed {fail_stage} clone remains on disk"
                );
                assert_eq!(fs::read_dir(&root)?.count(), 0);
            }
            assert!(
                !fs::read_to_string(&url_record)?.contains(&service.gitlab_token),
                "clone URL contains the token"
            );
        }
        Ok(())
    }

    #[test]
    fn redact_sensitive_output_removes_gitlab_tokens_from_urls_and_plain_text() {
        let service = GitLabDiscoveryMcpService {
            config: crate::config::GitLabDiscoveryMcpConfig::default(),
            advertised_host: "host.docker.internal".to_string(),
            docker: crate::codex_runner::docker::connect_docker(
                &crate::config::DockerConfig::default(),
            )
            .expect("docker client"),
            gitlab: crate::gitlab::GitLabClient::new("https://gitlab.example.com", "secret-token")
                .expect("gitlab client"),
            git_base: url::Url::parse("https://gitlab.example.com").expect("git base"),
            gitlab_token: "secret-token".to_string(),
            registry: std::sync::Arc::new(super::GitLabDiscoverySessionRegistry::default()),
            shutdown: tokio_util::sync::CancellationToken::new(),
        };

        let input = "fatal: could not read from https://oauth2:secret-token@gitlab.example.com/group/repo.git\nplain secret-token token";
        let output = service.redact_sensitive_output(input, None);

        assert!(!output.contains("secret-token"));
        assert!(output.contains("oauth2:[REDACTED]@gitlab.example.com/group/repo.git"));
        assert!(output.contains("[REDACTED_GITLAB_TOKEN]"));
    }

    #[test]
    fn clone_repository_script_renders_snapshot_without_placeholders() {
        let script = clone_repository_script(
            "/tmp/gitlab-discovery",
            "group/repo",
            "https://gitlab.example.com/group/repo.git",
        );

        assert!(!script.contains("@@"), "{script}");
        insta::assert_snapshot!("clone_repository_script", script);
    }

    #[test]
    fn resolve_checkout_target_rejects_checkout_ref_and_commit_sha() {
        let err =
            resolve_checkout_target(Some("main"), Some("deadbeef"), &["main".to_string()], &[])
                .expect_err("mutually exclusive inputs must fail");

        assert!(
            err.to_string()
                .contains("checkout_ref and commit_sha are mutually exclusive")
        );
    }

    #[test]
    fn resolve_checkout_target_resolves_commit_sha_to_detached_checkout() {
        let resolved =
            resolve_checkout_target(None, Some("deadbeef"), &[], &[]).expect("commit target");

        assert_eq!(
            resolved,
            ResolvedCheckoutTarget::Commit {
                commit_sha: "deadbeef".to_string(),
            }
        );
        assert_eq!(resolved.checked_out_ref(), "deadbeef");
        assert_eq!(resolved.checked_out_kind(), GitLabCheckoutKind::Commit);
    }

    #[test]
    fn resolve_checkout_target_rejects_non_sha_commit_values() {
        let err = resolve_checkout_target(None, Some("main"), &[], &[])
            .expect_err("non-SHA commit target must fail");

        assert!(
            err.to_string()
                .contains("commit_sha must be a 7-40 character hexadecimal Git commit SHA")
        );
    }

    #[test]
    fn resolve_checkout_target_preserves_branch_and_tag_behavior() {
        let branch = resolve_checkout_target(
            Some("main"),
            None,
            &["main".to_string()],
            &["v1.0.0".to_string()],
        )
        .expect("branch target");
        assert_eq!(
            branch,
            ResolvedCheckoutTarget::Branch {
                requested_ref: "main".to_string(),
                branch_name: "main".to_string(),
            }
        );

        let tag = resolve_checkout_target(
            Some("refs/tags/v1.0.0"),
            None,
            &["main".to_string()],
            &["v1.0.0".to_string()],
        )
        .expect("tag target");
        assert_eq!(
            tag,
            ResolvedCheckoutTarget::Tag {
                requested_ref: "refs/tags/v1.0.0".to_string(),
                tag_name: "v1.0.0".to_string(),
            }
        );
    }
}
