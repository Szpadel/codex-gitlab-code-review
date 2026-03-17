use super::*;

#[derive(Clone, Copy)]
pub(crate) struct AppServerCommandOptions<'a> {
    pub(crate) browser_mcp: Option<&'a BrowserMcpConfig>,
    pub(crate) gitlab_discovery_mcp: Option<&'a GitLabDiscoveryMcpRuntimeConfig>,
    pub(crate) mcp_server_overrides: &'a BTreeMap<String, bool>,
    pub(crate) reasoning_summary: Option<&'a str>,
    pub(crate) reasoning_effort: Option<&'a str>,
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

    pub(crate) fn env_vars(&self, extra_env: &[String]) -> Vec<String> {
        let mut env = vec![
            format!("GITLAB_TOKEN={}", self.gitlab_token),
            "HOME=/root".to_string(),
        ];
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
        let reasoning_summary =
            configured_reasoning_summary(self.codex.reasoning_summary.review.as_deref());
        let reasoning_effort =
            configured_reasoning_effort(self.codex.reasoning_effort.review.as_deref());
        let mcp_server_overrides = self.effective_mcp_server_overrides_for_run(
            app_server.mcp_server_overrides,
            app_server.gitlab_discovery_mcp.is_some(),
        );
        Ok(Self::build_command_script(
            &clone_url,
            &ctx.repo,
            ctx.head_sha.as_str(),
            &self.codex.auth_mount_path,
            ctx.mr
                .target_branch
                .as_deref()
                .filter(|value| !value.is_empty()),
            self.codex.deps.enabled,
            AppServerCommandOptions {
                browser_mcp: app_server.browser_mcp,
                gitlab_discovery_mcp: app_server.gitlab_discovery_mcp,
                mcp_server_overrides: &mcp_server_overrides,
                reasoning_summary: reasoning_summary.or(app_server.reasoning_summary),
                reasoning_effort: reasoning_effort.or(app_server.reasoning_effort),
            },
        ))
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
        auth_mount_path: &str,
        app_server: AppServerCommandOptions<'_>,
    ) -> String {
        let clone_url_dq = clone_url.replace('\\', "\\\\").replace('"', "\\\"");
        let head_sha_q = shell_quote(&ctx.head_sha);
        let auth_mount_path_q = shell_quote(auth_mount_path);
        let git_url_rewrite_script = git_url_rewrite_script(clone_url, &ctx.repo);
        let browser_prereq_script = browser_mcp_prereq_script(app_server.browser_mcp);
        let browser_wait_script = browser_wait_script(app_server.browser_mcp);
        let app_server_exec_cmd = codex_app_server_exec_command(
            app_server.browser_mcp,
            app_server.gitlab_discovery_mcp,
            app_server.mcp_server_overrides,
            app_server.reasoning_summary,
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
{git_url_rewrite_script}
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
            git_url_rewrite_script = git_url_rewrite_script,
            browser_prereq_script = browser_prereq_script,
            browser_wait_script = browser_wait_script,
            app_server_exec_cmd = app_server_exec_cmd,
        )
    }

    pub(crate) fn build_command_script(
        clone_url: &str,
        repo: &str,
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
        let git_url_rewrite_script = git_url_rewrite_script(clone_url, repo);
        let browser_prereq_script = browser_mcp_prereq_script(app_server.browser_mcp);
        let browser_wait_script = browser_wait_script(app_server.browser_mcp);
        let app_server_exec_cmd = codex_app_server_exec_command(
            app_server.browser_mcp,
            app_server.gitlab_discovery_mcp,
            app_server.mcp_server_overrides,
            app_server.reasoning_summary,
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
{git_url_rewrite_script}
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
            git_url_rewrite_script = git_url_rewrite_script,
            browser_prereq_script = browser_prereq_script,
            browser_wait_script = browser_wait_script,
            app_server_exec_cmd = app_server_exec_cmd
        )
    }

    pub(crate) fn app_server_cmd(script: String) -> Vec<String> {
        // The codex-universal entrypoint runs `bash --login "$@"`, so pass only bash flags + script.
        vec!["-lc".to_string(), script]
    }

    pub(crate) fn build_history_reader_script(auth_mount_path: &str) -> String {
        format!(
            r#"set -eu
mkdir -p "{auth_mount_path}"
export CODEX_HOME="{auth_mount_path}"
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
exec codex app-server --listen stdio://
"#,
            auth_mount_path = auth_mount_path
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

pub(crate) fn git_url_rewrite_script(clone_url: &str, repo: &str) -> String {
    let Some((scheme, rest)) = clone_url.split_once("://") else {
        return String::new();
    };
    let Some((authority, path_with_slash)) = rest.split_once('/') else {
        return String::new();
    };

    let sanitized_clone_url = clone_url.replace("${GITLAB_TOKEN}", "token");
    let Ok(parsed_clone_url) = Url::parse(&sanitized_clone_url) else {
        return String::new();
    };
    let Some(host) = parsed_clone_url.host_str() else {
        return String::new();
    };
    let host_endpoint = authority
        .rsplit_once('@')
        .map(|(_, value)| value)
        .unwrap_or(authority);

    let path = format!("/{}", path_with_slash);
    let repo_suffix = format!("/{}.git", repo);
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

    if !base_path.is_empty() {
        let base_path = base_path.trim_start_matches('/');
        rewrites.push((
            format!("url.{base_url}.insteadOf"),
            format!("git@{host}:{base_path}/"),
        ));
        rewrites.push((
            format!("url.{base_url}.insteadOf"),
            format!("ssh://git@{host_endpoint}/{base_path}/"),
        ));
    }

    let mut script = format!("export GIT_CONFIG_COUNT=\"{}\"\n", rewrites.len());
    for (index, (key, value)) in rewrites.into_iter().enumerate() {
        let key = key.replace('\\', "\\\\").replace('"', "\\\"");
        let value = value.replace('\\', "\\\\").replace('"', "\\\"");
        script.push_str(&format!("export GIT_CONFIG_KEY_{index}=\"{key}\"\n"));
        script.push_str(&format!("export GIT_CONFIG_VALUE_{index}=\"{value}\"\n"));
    }
    script
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
    format!(
        r#"browser_mcp_command={command_q}
if ! command -v "$browser_mcp_command" >/dev/null 2>&1; then
  echo "codex-runner-error: browser MCP requires $browser_mcp_command in the Codex image"
  exit 1
fi
"#,
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
    reasoning_summary: Option<&str>,
    reasoning_effort: Option<&str>,
) -> String {
    if browser_mcp.is_none()
        && gitlab_discovery_mcp.is_none()
        && mcp_server_overrides.is_empty()
        && reasoning_summary.is_none()
        && reasoning_effort.is_none()
    {
        return "exec codex app-server".to_string();
    }

    let mut cmd_parts = vec!["exec codex".to_string()];
    if let Some(reasoning_summary) = reasoning_summary {
        let override_value = format!(
            "model_reasoning_summary={}",
            toml_basic_string(reasoning_summary)
        );
        cmd_parts.push(format!("-c {}", shell_quote(&override_value)));
    }
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
    if let Some(gitlab_discovery_mcp) = gitlab_discovery_mcp {
        for override_value in [
            format!(
                "mcp_servers.{}.url={}",
                gitlab_discovery_mcp.server_name,
                toml_basic_string(&gitlab_discovery_mcp.advertise_url)
            ),
            format!(
                "mcp_servers.{}.bearer_token_env_var={}",
                gitlab_discovery_mcp.server_name,
                toml_basic_string(&gitlab_discovery_mcp.bearer_token_env_var)
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
