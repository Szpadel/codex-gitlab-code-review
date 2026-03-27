use super::{
    BROWSER_MCP_REMOTE_DEBUGGING_PORT, BTreeMap, BrowserMcpConfig, DockerCodexRunner,
    GitLabDiscoveryMcpRuntimeConfig, MentionCommandContext, Result, ReviewContext, Url, anyhow,
    repo_checkout_root,
};
use std::fmt::Write as _;

const MENTION_COMMAND_TEMPLATE: &str = include_str!("assets/mention_command.sh");
const REVIEW_COMMAND_TEMPLATE: &str = include_str!("assets/review_command.sh");
const DEPS_PREFETCH_TEMPLATE: &str = include_str!("assets/deps_prefetch.sh");
const HISTORY_READER_TEMPLATE: &str = include_str!("assets/history_reader.sh");
const GIT_BOOTSTRAP_AUTH_CLEANUP_TEMPLATE: &str =
    include_str!("assets/git_bootstrap_auth_cleanup.sh");
const BROWSER_MCP_PREREQ_TEMPLATE: &str = include_str!("assets/browser_mcp_prereq.sh");
const BROWSER_WAIT_TEMPLATE: &str = include_str!("assets/browser_wait.sh");

#[derive(Clone, Copy)]
pub(crate) struct AppServerCommandOptions<'a> {
    pub(crate) browser_mcp: Option<&'a BrowserMcpConfig>,
    pub(crate) gitlab_discovery_mcp: Option<&'a GitLabDiscoveryMcpRuntimeConfig>,
    pub(crate) mcp_server_overrides: &'a BTreeMap<String, bool>,
    pub(crate) session_override: ConfiguredSessionOverride<'a>,
}

#[derive(Clone, Copy, Default)]
pub(crate) struct ConfiguredSessionOverride<'a> {
    pub(crate) model: Option<&'a str>,
    pub(crate) reasoning_summary: Option<&'a str>,
    pub(crate) reasoning_effort: Option<&'a str>,
}

#[derive(Clone, Copy)]
pub(crate) struct BuildCommandScriptInput<'a> {
    pub(crate) clone_url: &'a str,
    pub(crate) gitlab_token: &'a str,
    pub(crate) repo: &'a str,
    pub(crate) project_path: &'a str,
    pub(crate) head_sha: &'a str,
    pub(crate) auth_mount_path: &'a str,
    pub(crate) target_branch: Option<&'a str>,
    pub(crate) deps_enabled: bool,
}

fn render_template(template: &str, replacements: &[(&str, &str)]) -> String {
    let mut rendered = template.to_string();
    for (needle, replacement) in replacements {
        rendered = rendered.replace(needle, replacement);
    }
    rendered
}

impl DockerCodexRunner {
    pub(crate) fn clone_url(&self, repo: &str) -> Result<String> {
        let scheme = self.git_base.scheme();
        let host = self
            .git_base
            .host_str()
            .ok_or_else(|| anyhow!("missing git base host"))?;
        let port = self.git_base.port();
        let mut host_port = host.to_string();
        if let Some(port) = port {
            host_port = format!("{host}:{port}");
        }
        let base_path = self.git_base.path().trim_end_matches('/');
        let repo_path = if base_path.is_empty() {
            format!("/{repo}.git")
        } else {
            format!("{base_path}/{repo}.git")
        };
        if self.gitlab_token.is_empty() {
            Ok(format!("{scheme}://{host_port}{repo_path}"))
        } else {
            Ok(format!(
                "{scheme}://oauth2:${{GITLAB_TOKEN}}@{host_port}{repo_path}"
            ))
        }
    }

    pub(crate) fn env_vars(&self, extra_env: &[String]) -> Vec<String> {
        let mut env = vec!["HOME=/root".to_string()];
        env.extend(extra_env.iter().cloned());
        if self.log_all_json {
            env.push("CODEX_RUNNER_DEBUG=1".to_string());
        }
        env
    }

    pub(crate) fn effective_mcp_server_overrides_for_run(
        &self,
        overrides: &BTreeMap<String, bool>,
        gitlab_discovery_injected: bool,
    ) -> BTreeMap<String, bool> {
        let mut effective = overrides.clone();
        if !gitlab_discovery_injected
            && effective
                .get(&self.codex.gitlab_discovery_mcp.server_name)
                .copied()
                == Some(true)
        {
            effective.remove(&self.codex.gitlab_discovery_mcp.server_name);
        }
        effective
    }

    pub(crate) fn command(
        &self,
        ctx: &ReviewContext,
        app_server: AppServerCommandOptions<'_>,
    ) -> Result<String> {
        let clone_url = self.clone_url(&ctx.repo)?;
        let mcp_server_overrides = self.effective_mcp_server_overrides_for_run(
            app_server.mcp_server_overrides,
            app_server.gitlab_discovery_mcp.is_some(),
        );
        Ok(Self::build_command_script(
            BuildCommandScriptInput {
                clone_url: &clone_url,
                gitlab_token: &self.gitlab_token,
                repo: &ctx.repo,
                project_path: &ctx.project_path,
                head_sha: ctx.head_sha.as_str(),
                auth_mount_path: &self.codex.auth_mount_path,
                target_branch: ctx
                    .mr
                    .target_branch
                    .as_deref()
                    .filter(|value| !value.is_empty()),
                deps_enabled: self.codex.deps.enabled,
            },
            AppServerCommandOptions {
                browser_mcp: app_server.browser_mcp,
                gitlab_discovery_mcp: app_server.gitlab_discovery_mcp,
                mcp_server_overrides: &mcp_server_overrides,
                session_override: app_server.session_override,
            },
        ))
    }

    pub(crate) fn review_reasoning_summary(&self) -> Option<&str> {
        configured_reasoning_summary(self.codex.reasoning_summary.review.as_deref())
    }

    pub(crate) fn review_session_override(&self) -> ConfiguredSessionOverride<'_> {
        ConfiguredSessionOverride {
            model: configured_model(self.codex.session_overrides.review.model.as_deref()),
            reasoning_summary: self.review_reasoning_summary(),
            reasoning_effort: configured_reasoning_effort(
                self.codex
                    .session_overrides
                    .review
                    .reasoning_effort
                    .as_deref(),
            ),
        }
    }

    pub(crate) fn security_context_session_override(&self) -> ConfiguredSessionOverride<'_> {
        ConfiguredSessionOverride {
            model: configured_model(
                self.codex
                    .session_overrides
                    .security_context
                    .model
                    .as_deref(),
            ),
            reasoning_summary: self.review_reasoning_summary(),
            reasoning_effort: configured_reasoning_effort(
                self.codex
                    .session_overrides
                    .security_context
                    .reasoning_effort
                    .as_deref(),
            ),
        }
    }

    pub(crate) fn security_review_session_override(&self) -> ConfiguredSessionOverride<'_> {
        ConfiguredSessionOverride {
            model: configured_model(
                self.codex
                    .session_overrides
                    .security_review
                    .model
                    .as_deref(),
            ),
            reasoning_summary: self.review_reasoning_summary(),
            reasoning_effort: configured_reasoning_effort(
                self.codex
                    .session_overrides
                    .security_review
                    .reasoning_effort
                    .as_deref(),
            ),
        }
    }

    pub(crate) fn mention_session_override(&self) -> ConfiguredSessionOverride<'_> {
        ConfiguredSessionOverride {
            model: configured_model(self.codex.session_overrides.mention.model.as_deref()),
            reasoning_summary: configured_reasoning_summary(
                self.codex.reasoning_summary.mention.as_deref(),
            ),
            reasoning_effort: configured_reasoning_effort(
                self.codex
                    .session_overrides
                    .mention
                    .reasoning_effort
                    .as_deref(),
            ),
        }
    }

    pub(crate) fn browser_mcp(&self) -> Option<&BrowserMcpConfig> {
        self.codex
            .browser_mcp
            .enabled
            .then_some(&self.codex.browser_mcp)
    }

    pub(crate) fn effective_browser_mcp(
        &self,
        mcp_server_overrides: &BTreeMap<String, bool>,
    ) -> Option<&BrowserMcpConfig> {
        effective_browser_mcp(self.browser_mcp(), mcp_server_overrides)
    }

    pub(crate) fn build_mention_command_script(
        ctx: &MentionCommandContext,
        clone_url: &str,
        gitlab_token: &str,
        auth_mount_path: &str,
        app_server: AppServerCommandOptions<'_>,
    ) -> String {
        let clone_url_dq = clone_url.replace('\\', "\\\\").replace('"', "\\\"");
        let head_sha_q = shell_quote(&ctx.head_sha);
        let gitlab_token_q = shell_quote(gitlab_token);
        let auth_mount_path_q = shell_quote(auth_mount_path);
        let repo_dir_q = shell_quote(&repo_checkout_root(&ctx.project_path));
        let git_auth_setup_script =
            git_bootstrap_auth_setup_script(clone_url, &ctx.repo, gitlab_token);
        let git_auth_cleanup_script = git_bootstrap_auth_cleanup_script();
        let browser_prereq_script = browser_mcp_prereq_script(app_server.browser_mcp);
        let browser_wait_script = browser_wait_script(app_server.browser_mcp);
        let app_server_exec_cmd = codex_app_server_exec_command(
            app_server.browser_mcp,
            app_server.gitlab_discovery_mcp,
            app_server.mcp_server_overrides,
            app_server.session_override,
        );
        render_template(
            MENTION_COMMAND_TEMPLATE,
            &[
                ("@@CLONE_URL_DQ@@", &clone_url_dq),
                ("@@GITLAB_TOKEN_Q@@", &gitlab_token_q),
                ("@@HEAD_SHA_Q@@", &head_sha_q),
                ("@@AUTH_MOUNT_PATH_Q@@", &auth_mount_path_q),
                ("@@REPO_DIR_Q@@", &repo_dir_q),
                ("@@GIT_AUTH_SETUP_SCRIPT@@", &git_auth_setup_script),
                ("@@GIT_AUTH_CLEANUP_SCRIPT@@", git_auth_cleanup_script),
                ("@@BROWSER_PREREQ_SCRIPT@@", &browser_prereq_script),
                ("@@BROWSER_WAIT_SCRIPT@@", &browser_wait_script),
                ("@@APP_SERVER_EXEC_CMD@@", &app_server_exec_cmd),
            ],
        )
    }

    pub(crate) fn build_command_script(
        input: BuildCommandScriptInput<'_>,
        app_server: AppServerCommandOptions<'_>,
    ) -> String {
        let target_branch_script = input
            .target_branch
            .map(|branch| {
                format!(
                    "run_git fetch git fetch --depth 1 origin \"{branch}\"\n\
git branch --force \"{branch}\" FETCH_HEAD\n\
# Ensure merge-base works for PR review by unshallowing history.\n\
run_git fetch git fetch --unshallow\n"
                )
            })
            .unwrap_or_default();
        let deps_prefetch_script = if input.deps_enabled {
            DEPS_PREFETCH_TEMPLATE
        } else {
            ""
        };
        let git_auth_setup_script =
            git_bootstrap_auth_setup_script(input.clone_url, input.repo, input.gitlab_token);
        let git_auth_cleanup_script = git_bootstrap_auth_cleanup_script();
        let gitlab_token_q = shell_quote(input.gitlab_token);
        let repo_dir_q = shell_quote(&repo_checkout_root(input.project_path));
        let browser_prereq_script = browser_mcp_prereq_script(app_server.browser_mcp);
        let browser_wait_script = browser_wait_script(app_server.browser_mcp);
        let app_server_exec_cmd = codex_app_server_exec_command(
            app_server.browser_mcp,
            app_server.gitlab_discovery_mcp,
            app_server.mcp_server_overrides,
            app_server.session_override,
        );
        render_template(
            REVIEW_COMMAND_TEMPLATE,
            &[
                ("@@CLONE_URL@@", input.clone_url),
                ("@@GITLAB_TOKEN_Q@@", &gitlab_token_q),
                ("@@REPO_DIR_Q@@", &repo_dir_q),
                ("@@HEAD_SHA@@", input.head_sha),
                ("@@AUTH_MOUNT_PATH@@", input.auth_mount_path),
                ("@@TARGET_BRANCH_SCRIPT@@", &target_branch_script),
                ("@@DEPS_PREFETCH_SCRIPT@@", deps_prefetch_script),
                ("@@GIT_AUTH_SETUP_SCRIPT@@", &git_auth_setup_script),
                ("@@GIT_AUTH_CLEANUP_SCRIPT@@", git_auth_cleanup_script),
                ("@@BROWSER_PREREQ_SCRIPT@@", &browser_prereq_script),
                ("@@BROWSER_WAIT_SCRIPT@@", &browser_wait_script),
                ("@@APP_SERVER_EXEC_CMD@@", &app_server_exec_cmd),
            ],
        )
    }

    pub(crate) fn app_server_cmd(script: String) -> Vec<String> {
        // The codex-universal entrypoint runs `bash --login "$@"`, so pass only bash flags + script.
        vec!["-lc".to_string(), script]
    }

    pub(crate) fn build_history_reader_script(auth_mount_path: &str) -> String {
        render_template(
            HISTORY_READER_TEMPLATE,
            &[("@@AUTH_MOUNT_PATH@@", auth_mount_path)],
        )
    }
}

pub(crate) fn restore_push_remote_url_exec_command(push_url: &str) -> Vec<String> {
    let push_url_dq = push_url.replace('\\', "\\\\").replace('"', "\\\"");
    vec![
        "bash".to_string(),
        "-lc".to_string(),
        format!("git remote set-url --push origin \"{push_url_dq}\""),
    ]
}

pub(crate) fn shell_quote(input: &str) -> String {
    format!("'{}'", input.replace('\'', "'\"'\"'"))
}

fn git_url_rewrites(clone_url: &str, repo: &str) -> Vec<(String, String)> {
    let Some((scheme, rest)) = clone_url.split_once("://") else {
        return Vec::new();
    };
    let Some((authority, path_with_slash)) = rest.split_once('/') else {
        return Vec::new();
    };

    let Ok(parsed_clone_url) = Url::parse(clone_url) else {
        return Vec::new();
    };
    let Some(host) = parsed_clone_url.host_str() else {
        return Vec::new();
    };
    let host_endpoint = authority
        .rsplit_once('@')
        .map_or(authority, |(_, value)| value);

    let path = format!("/{path_with_slash}");
    let repo_suffix = format!("/{repo}.git");
    let base_path = path
        .strip_suffix(&repo_suffix)
        .unwrap_or("")
        .trim_end_matches('/');
    let base_url = if base_path.is_empty() {
        format!("{scheme}://{authority}/")
    } else {
        format!("{scheme}://{authority}{base_path}/")
    };

    let mut rewrites = vec![
        (format!("url.{base_url}.insteadOf"), format!("git@{host}:")),
        (
            format!("url.{base_url}.insteadOf"),
            format!("ssh://git@{host_endpoint}/"),
        ),
    ];

    if base_path.is_empty() {
        rewrites.push((
            format!("url.{base_url}.insteadOf"),
            format!("{scheme}://{host_endpoint}/"),
        ));
    } else {
        let base_path = base_path.trim_start_matches('/');
        rewrites.push((
            format!("url.{base_url}.insteadOf"),
            format!("git@{host}:{base_path}/"),
        ));
        rewrites.push((
            format!("url.{base_url}.insteadOf"),
            format!("ssh://git@{host_endpoint}/{base_path}/"),
        ));
        rewrites.push((
            format!("url.{base_url}.insteadOf"),
            format!("{scheme}://{host_endpoint}/{base_path}/"),
        ));
    }

    rewrites
}

pub(crate) fn git_bootstrap_auth_setup_script(
    clone_url: &str,
    repo: &str,
    gitlab_token: &str,
) -> String {
    let materialized_clone_url = clone_url.replace("${GITLAB_TOKEN}", gitlab_token);
    let rewrites = git_url_rewrites(&materialized_clone_url, repo);
    if rewrites.is_empty() {
        return String::new();
    }

    let mut script = format!(
        "export GIT_CONFIG_COUNT={}\n",
        shell_quote(&rewrites.len().to_string())
    );
    for (index, (key, value)) in rewrites.into_iter().enumerate() {
        let _ = write!(
            script,
            "export GIT_CONFIG_KEY_{index}={}\nexport GIT_CONFIG_VALUE_{index}={}\n",
            shell_quote(&key),
            shell_quote(&value)
        );
    }
    script
}

pub(crate) fn git_bootstrap_auth_cleanup_script() -> &'static str {
    GIT_BOOTSTRAP_AUTH_CLEANUP_TEMPLATE
}

pub(crate) fn escape_toml_basic_string(value: &str) -> String {
    value.replace('\\', "\\\\").replace('"', "\\\"")
}

pub(crate) fn toml_basic_string(value: &str) -> String {
    format!("\"{}\"", escape_toml_basic_string(value))
}

pub(crate) fn browser_mcp_prereq_script(browser_mcp: Option<&BrowserMcpConfig>) -> String {
    let Some(browser_mcp) = browser_mcp else {
        return String::new();
    };
    let command_q = shell_quote(&browser_mcp.mcp_command);
    render_template(
        BROWSER_MCP_PREREQ_TEMPLATE,
        &[("@@COMMAND_Q@@", &command_q)],
    )
}

pub(crate) fn effective_browser_mcp<'a>(
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

pub(crate) fn browser_wait_script(browser_mcp: Option<&BrowserMcpConfig>) -> String {
    if browser_mcp.is_none() {
        return String::new();
    }
    let port = BROWSER_MCP_REMOTE_DEBUGGING_PORT.to_string();
    render_template(BROWSER_WAIT_TEMPLATE, &[("@@PORT@@", &port)])
}

pub(crate) fn configured_model(value: Option<&str>) -> Option<&str> {
    value.map(str::trim).filter(|value| !value.is_empty())
}

pub(crate) fn configured_reasoning_effort(value: Option<&str>) -> Option<&str> {
    value.map(str::trim).filter(|value| !value.is_empty())
}

pub(crate) fn configured_reasoning_summary(value: Option<&str>) -> Option<&str> {
    value.map(str::trim).filter(|value| !value.is_empty())
}

pub(crate) fn codex_app_server_exec_command(
    browser_mcp: Option<&BrowserMcpConfig>,
    gitlab_discovery_mcp: Option<&GitLabDiscoveryMcpRuntimeConfig>,
    mcp_server_overrides: &BTreeMap<String, bool>,
    session_override: ConfiguredSessionOverride<'_>,
) -> String {
    if browser_mcp.is_none()
        && gitlab_discovery_mcp.is_none()
        && mcp_server_overrides.is_empty()
        && session_override.model.is_none()
        && session_override.reasoning_summary.is_none()
        && session_override.reasoning_effort.is_none()
    {
        return "exec codex app-server".to_string();
    }

    let mut cmd_parts = vec!["exec codex".to_string()];
    if let Some(model) = session_override.model {
        let override_value = format!("model={}", toml_basic_string(model));
        cmd_parts.push(format!("-c {}", shell_quote(&override_value)));
    }
    if let Some(reasoning_summary) = session_override.reasoning_summary {
        let override_value = format!(
            "model_reasoning_summary={}",
            toml_basic_string(reasoning_summary)
        );
        cmd_parts.push(format!("-c {}", shell_quote(&override_value)));
    }
    if let Some(reasoning_effort) = session_override.reasoning_effort {
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
                    "--browserUrl=http://127.0.0.1:{BROWSER_MCP_REMOTE_DEBUGGING_PORT}"
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
    if let Some(gitlab_discovery_mcp) = gitlab_discovery_mcp {
        for override_value in [
            format!(
                "mcp_servers.{}.url={}",
                gitlab_discovery_mcp.server_name,
                toml_basic_string(&gitlab_discovery_mcp.advertise_url)
            ),
            format!(
                "mcp_servers.{}.enabled=true",
                gitlab_discovery_mcp.server_name
            ),
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
