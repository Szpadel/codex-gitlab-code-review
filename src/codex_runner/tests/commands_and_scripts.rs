use super::*;
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
fn auxiliary_git_exec_command_wraps_git_in_login_shell() {
    let command = auxiliary_git_exec_command(&["status".to_string()]);
    assert_eq!(
        command,
        vec![
            "bash".to_string(),
            "-lc".to_string(),
            "'git' 'status'".to_string()
        ]
    );
}

#[test]
fn auxiliary_git_exec_command_quotes_arguments() {
    let command = auxiliary_git_exec_command(&[
        "config".to_string(),
        "user.name".to_string(),
        "O'Brian Example".to_string(),
    ]);
    assert_eq!(
        command,
        vec![
            "bash".to_string(),
            "-lc".to_string(),
            "'git' 'config' 'user.name' 'O'\"'\"'Brian Example'".to_string()
        ]
    );
}

#[test]
fn auxiliary_git_exec_command_wraps_merge_base_flags_and_shas() {
    let command = auxiliary_git_exec_command(&[
        "merge-base".to_string(),
        "--is-ancestor".to_string(),
        "before123".to_string(),
        "after456".to_string(),
    ]);
    assert_eq!(
        command,
        vec![
            "bash".to_string(),
            "-lc".to_string(),
            "'git' 'merge-base' '--is-ancestor' 'before123' 'after456'".to_string()
        ]
    );
}

#[test]
fn restore_push_remote_url_exec_command_preserves_gitlab_token_expansion() {
    let command = restore_push_remote_url_exec_command(
        "https://oauth2:${GITLAB_TOKEN}@gitlab.example.com/group/repo.git",
    );
    assert_eq!(
        command,
        vec![
            "bash".to_string(),
            "-lc".to_string(),
            "git remote set-url --push origin \"https://oauth2:${GITLAB_TOKEN}@gitlab.example.com/group/repo.git\"".to_string(),
        ]
    );
}

#[test]
fn app_server_cmd_uses_bash_login_args() {
    let cmd = DockerCodexRunner::app_server_cmd("echo hi".to_string());
    assert_eq!(cmd, vec!["-lc".to_string(), "echo hi".to_string()]);
}

#[test]
fn codex_app_server_exec_command_without_mcp_overrides_is_plain() {
    let overrides = BTreeMap::new();
    let cmd =
        codex_app_server_exec_command(None, None, &overrides, ConfiguredSessionOverride::default());
    assert_eq!(cmd, "exec codex app-server");
}

#[test]
fn codex_app_server_exec_command_renders_sorted_mcp_overrides() {
    let overrides = BTreeMap::from([("serena".to_string(), false), ("github".to_string(), true)]);
    let cmd =
        codex_app_server_exec_command(None, None, &overrides, ConfiguredSessionOverride::default());
    assert_eq!(
        cmd,
        "exec codex -c 'mcp_servers.github.enabled=true' -c 'mcp_servers.serena.enabled=false' app-server"
    );
}

#[test]
fn codex_app_server_exec_command_includes_reasoning_effort_override() {
    let cmd = codex_app_server_exec_command(
        None,
        None,
        &BTreeMap::new(),
        ConfiguredSessionOverride {
            reasoning_effort: Some("high"),
            ..ConfiguredSessionOverride::default()
        },
    );
    assert_eq!(
        cmd,
        "exec codex -c 'model_reasoning_effort=\"high\"' app-server"
    );
}

#[test]
fn codex_app_server_exec_command_includes_reasoning_summary_override() {
    let cmd = codex_app_server_exec_command(
        None,
        None,
        &BTreeMap::new(),
        ConfiguredSessionOverride {
            reasoning_summary: Some("detailed"),
            ..ConfiguredSessionOverride::default()
        },
    );
    assert_eq!(
        cmd,
        "exec codex -c 'model_reasoning_summary=\"detailed\"' app-server"
    );
}

#[test]
fn codex_app_server_exec_command_includes_model_override() {
    let cmd = codex_app_server_exec_command(
        None,
        None,
        &BTreeMap::new(),
        ConfiguredSessionOverride {
            model: Some("gpt-5.4"),
            ..ConfiguredSessionOverride::default()
        },
    );
    assert_eq!(cmd, "exec codex -c 'model=\"gpt-5.4\"' app-server");
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
        None,
        &BTreeMap::new(),
        ConfiguredSessionOverride::default(),
    );
    assert!(cmd.contains("mcp_servers.chrome-devtools.command=\"npx\""));
    assert!(cmd.contains("chrome-devtools-mcp@latest"));
    assert!(cmd.contains("--browserUrl=http://127.0.0.1:9222"));
    assert!(cmd.contains("mcp_servers.chrome-devtools.enabled=true"));
}

#[test]
fn codex_app_server_exec_command_includes_gitlab_discovery_mcp_config() {
    let cmd = codex_app_server_exec_command(
        None,
        Some(&GitLabDiscoveryMcpRuntimeConfig {
            server_name: "gitlab-discovery".to_string(),
            advertise_url: "http://gitlab-discovery.internal/mcp".to_string(),
            clone_root: "/work/mcp".to_string(),
        }),
        &BTreeMap::new(),
        ConfiguredSessionOverride::default(),
    );
    assert!(
        cmd.contains("mcp_servers.gitlab-discovery.url=\"http://gitlab-discovery.internal/mcp\"")
    );
    assert!(cmd.contains("mcp_servers.gitlab-discovery.enabled=true"));
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
        None,
        &BTreeMap::from([("chrome-devtools".to_string(), false)]),
        ConfiguredSessionOverride::default(),
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
    let cmd = codex_app_server_exec_command(
        None,
        None,
        &overrides,
        ConfiguredSessionOverride {
            reasoning_effort: Some("medium"),
            ..ConfiguredSessionOverride::default()
        },
    );
    let reasoning = "-c 'model_reasoning_effort=\"medium\"'";
    let mcp = "-c 'mcp_servers.github.enabled=false'";
    assert!(cmd.contains(reasoning));
    assert!(cmd.contains(mcp));
    assert!(cmd.find(reasoning) < cmd.find(mcp));
}

#[test]
fn codex_app_server_exec_command_places_model_before_summary_and_effort() {
    let cmd = codex_app_server_exec_command(
        None,
        None,
        &BTreeMap::new(),
        ConfiguredSessionOverride {
            model: Some("gpt-5.4"),
            reasoning_summary: Some("detailed"),
            reasoning_effort: Some("medium"),
        },
    );
    let model = "-c 'model=\"gpt-5.4\"'";
    let summary = "-c 'model_reasoning_summary=\"detailed\"'";
    let effort = "-c 'model_reasoning_effort=\"medium\"'";
    assert!(cmd.contains(model));
    assert!(cmd.contains(summary));
    assert!(cmd.contains(effort));
    assert!(cmd.find(model) < cmd.find(summary));
    assert!(cmd.find(summary) < cmd.find(effort));
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
        BuildCommandScriptInput {
            clone_url: "https://example.com/repo.git",
            gitlab_token: "token",
            repo: "repo",
            project_path: "repo",
            head_sha: "abc",
            auth_mount_path: "/root/.codex",
            target_branch: None,
            deps_enabled: false,
        },
        AppServerCommandOptions {
            browser_mcp: None,
            gitlab_discovery_mcp: None,
            mcp_server_overrides: &BTreeMap::new(),
            session_override: ConfiguredSessionOverride::default(),
        },
    );
    assert!(script.contains("export CODEX_HOME=\"/root/.codex\""));
    assert!(script.contains("mkdir -p \"/root/.codex\""));
    assert!(script.contains("repo_dir='/work/repo/repo'"));
}

#[test]
fn build_command_script_fetches_target_branch() {
    let script = DockerCodexRunner::build_command_script(
        BuildCommandScriptInput {
            clone_url: "https://example.com/repo.git",
            gitlab_token: "token",
            repo: "repo",
            project_path: "repo",
            head_sha: "abc",
            auth_mount_path: "/root/.codex",
            target_branch: Some("main"),
            deps_enabled: false,
        },
        AppServerCommandOptions {
            browser_mcp: None,
            gitlab_discovery_mcp: None,
            mcp_server_overrides: &BTreeMap::new(),
            session_override: ConfiguredSessionOverride::default(),
        },
    );
    assert!(script.contains("git fetch --depth 1 origin \"main\""));
    assert!(script.contains("git branch --force \"main\" FETCH_HEAD"));
    assert!(script.contains("git fetch --unshallow"));
}

#[test]
fn build_command_script_updates_submodules() {
    let script = DockerCodexRunner::build_command_script(
        BuildCommandScriptInput {
            clone_url: "https://example.com/repo.git",
            gitlab_token: "token",
            repo: "repo",
            project_path: "repo",
            head_sha: "abc",
            auth_mount_path: "/root/.codex",
            target_branch: None,
            deps_enabled: false,
        },
        AppServerCommandOptions {
            browser_mcp: None,
            gitlab_discovery_mcp: None,
            mcp_server_overrides: &BTreeMap::new(),
            session_override: ConfiguredSessionOverride::default(),
        },
    );
    assert!(script.contains("run_git clone git clone --depth 1 --recurse-submodules"));
    assert!(script.contains("run_git submodule_update git submodule update --init --recursive"));
    assert!(script.contains("export GIT_CONFIG_COUNT="));
    assert!(script.contains("export GIT_CONFIG_KEY_0="));
    assert!(script.contains("export GIT_CONFIG_VALUE_0="));
}

#[test]
fn git_bootstrap_auth_setup_script_prefers_relative_url_root_when_present() {
    let script = git_bootstrap_auth_setup_script(
        "https://oauth2:${GITLAB_TOKEN}@example.com/gitlab/group/repo.git",
        "group/repo",
        "token",
    );

    assert!(script.contains("export GIT_CONFIG_COUNT='5'"));
    assert!(script.contains(
        "export GIT_CONFIG_KEY_0='url.https://oauth2:token@example.com/gitlab/.insteadOf'"
    ));
    assert!(script.contains("export GIT_CONFIG_VALUE_0='git@example.com:'"));
    assert!(script.contains("export GIT_CONFIG_VALUE_2='git@example.com:gitlab/'"));
    assert!(script.contains("export GIT_CONFIG_VALUE_3='ssh://git@example.com/gitlab/'"));
    assert!(script.contains("export GIT_CONFIG_VALUE_4='https://example.com/gitlab/'"));
}

#[test]
fn git_bootstrap_auth_setup_script_preserves_explicit_host_port_for_ssh_urls() {
    let script = git_bootstrap_auth_setup_script(
        "https://oauth2:${GITLAB_TOKEN}@example.com:8443/group/repo.git",
        "group/repo",
        "token",
    );

    assert!(script.contains("export GIT_CONFIG_VALUE_1='ssh://git@example.com:8443/'"));
}

#[test]
fn git_bootstrap_auth_setup_script_rewrites_same_host_https_submodule_urls() {
    let script = git_bootstrap_auth_setup_script(
        "https://oauth2:${GITLAB_TOKEN}@example.com/group/repo.git",
        "group/repo",
        "token",
    );

    assert!(script.contains("export GIT_CONFIG_COUNT='3'"));
    assert!(script.contains("export GIT_CONFIG_VALUE_2='https://example.com/'"));
}

#[test]
fn git_bootstrap_auth_setup_script_rewrites_https_submodule_urls_under_relative_root() {
    let script = git_bootstrap_auth_setup_script(
        "https://oauth2:${GITLAB_TOKEN}@example.com:8443/gitlab/group/repo.git",
        "group/repo",
        "token",
    );

    assert!(script.contains("export GIT_CONFIG_COUNT='5'"));
    assert!(script.contains("export GIT_CONFIG_VALUE_4='https://example.com:8443/gitlab/'"));
}

#[test]
fn build_command_script_clears_bootstrap_git_auth_before_app_server() {
    let script = DockerCodexRunner::build_command_script(
        BuildCommandScriptInput {
            clone_url: "https://oauth2:${GITLAB_TOKEN}@example.com/repo.git",
            gitlab_token: "token",
            repo: "repo",
            project_path: "repo",
            head_sha: "abc",
            auth_mount_path: "/root/.codex",
            target_branch: Some("main"),
            deps_enabled: false,
        },
        AppServerCommandOptions {
            browser_mcp: None,
            gitlab_discovery_mcp: None,
            mcp_server_overrides: &BTreeMap::new(),
            session_override: ConfiguredSessionOverride::default(),
        },
    );

    let unset_pos = script
        .find("unset GIT_CONFIG_COUNT")
        .expect("bootstrap git auth cleanup");
    let unset_token_pos = script
        .find("unset GITLAB_TOKEN")
        .expect("gitlab token cleanup");
    let sanitize_remote_pos = script
        .find("git remote set-url origin \"$sanitized_origin\"")
        .expect("origin sanitization");
    let target_fetch_pos = script
        .find("git fetch --depth 1 origin \"main\"")
        .expect("target branch fetch");
    let exec_pos = script
        .find("exec codex app-server")
        .expect("app server exec");
    assert!(target_fetch_pos < unset_pos);
    assert!(unset_pos < exec_pos);
    assert!(unset_token_pos < exec_pos);
    assert!(sanitize_remote_pos < exec_pos);
}

#[test]
fn build_command_script_includes_prefetch_when_enabled_without_composer_install() {
    let script = DockerCodexRunner::build_command_script(
        BuildCommandScriptInput {
            clone_url: "https://example.com/repo.git",
            gitlab_token: "token",
            repo: "repo",
            project_path: "repo",
            head_sha: "abc",
            auth_mount_path: "/root/.codex",
            target_branch: None,
            deps_enabled: true,
        },
        AppServerCommandOptions {
            browser_mcp: None,
            gitlab_discovery_mcp: None,
            mcp_server_overrides: &BTreeMap::new(),
            session_override: ConfiguredSessionOverride::default(),
        },
    );
    assert!(script.contains("prefetch_deps()"));
    assert!(!script.contains("composer install"));
    assert!(script.contains("npm install"));
}

#[test]
fn build_command_script_includes_mcp_server_overrides() {
    let overrides = BTreeMap::from([("github".to_string(), false)]);
    let script = DockerCodexRunner::build_command_script(
        BuildCommandScriptInput {
            clone_url: "https://example.com/repo.git",
            gitlab_token: "token",
            repo: "repo",
            project_path: "repo",
            head_sha: "abc",
            auth_mount_path: "/root/.codex",
            target_branch: None,
            deps_enabled: false,
        },
        AppServerCommandOptions {
            browser_mcp: None,
            gitlab_discovery_mcp: None,
            mcp_server_overrides: &overrides,
            session_override: ConfiguredSessionOverride::default(),
        },
    );
    assert!(script.contains("exec codex -c 'mcp_servers.github.enabled=false' app-server"));
}

#[test]
fn gitlab_discovery_mcp_probe_exec_command_uses_runtime_url_and_health_check() {
    let command = gitlab_discovery_mcp_probe_exec_command(&GitLabDiscoveryMcpRuntimeConfig {
        server_name: "gitlab-discovery".to_string(),
        advertise_url: "http://10.42.0.15:8081/mcp".to_string(),
        clone_root: "/work/mcp".to_string(),
    })
    .expect("probe command");

    assert_eq!(command[0], "/bin/bash");
    assert_eq!(command[1], "-lc");
    assert!(command[2].contains("http://10.42.0.15:8081/mcp"));
    assert!(command[2].contains("http://10.42.0.15:8081/healthz"));
    assert!(command[2].contains("command -v curl"));
    assert!(command[2].contains("python3 - <<'PY'"));
    assert!(command[2].contains("healthz unavailable"));
    assert!(!command[2].contains("ERROR healthz failed"));
    assert!(command[2].contains("\"method\":\"initialize\""));
    assert!(command[2].contains("\"method\":\"tools/list\""));
    assert!(command[2].contains("gitlab discovery MCP tools reachable"));
    assert!(command[2].contains("inspect_gitlab_repo"));
}

#[test]
fn gitlab_discovery_mcp_probe_exec_command_rejects_invalid_url() {
    assert!(
        gitlab_discovery_mcp_probe_exec_command(&GitLabDiscoveryMcpRuntimeConfig {
            server_name: "gitlab-discovery".to_string(),
            advertise_url: "not-a-url".to_string(),
            clone_root: "/work/mcp".to_string(),
        })
        .is_none()
    );
}

#[test]
fn gitlab_discovery_mcp_startup_failure_events_create_completed_system_turn() {
    let events = gitlab_discovery_mcp_startup_failure_events(
        "GitLab discovery MCP startup warning: endpoint http://10.0.0.5:8081/mcp was unreachable.",
    );

    assert_eq!(events.len(), 3);
    assert_eq!(
        events[0].turn_id.as_deref(),
        Some(GITLAB_DISCOVERY_MCP_STARTUP_TURN_ID)
    );
    assert_eq!(events[0].event_type, "turn_started");
    assert_eq!(
        events[1].turn_id.as_deref(),
        Some(GITLAB_DISCOVERY_MCP_STARTUP_TURN_ID)
    );
    assert_eq!(events[1].event_type, "item_completed");
    assert_eq!(events[1].payload["type"], json!("agentMessage"));
    assert_eq!(events[1].payload["phase"], json!("system"));
    assert!(
        events[1].payload["text"]
            .as_str()
            .expect("message text")
            .contains("GitLab discovery MCP startup warning")
    );
    assert_eq!(
        events[2].turn_id.as_deref(),
        Some(GITLAB_DISCOVERY_MCP_STARTUP_TURN_ID)
    );
    assert_eq!(events[2].event_type, "turn_completed");
    assert_eq!(events[2].payload["status"], json!("completed"));
}

#[test]
fn successful_gitlab_discovery_mcp_tool_call_is_detected() {
    let item = json!({
        "type": "mcpToolCall",
        "server": "gitlab-discovery",
        "tool": "list_gitlab_paths",
        "status": "completed",
        "result": {"paths": []}
    });

    assert!(item_is_successful_gitlab_discovery_call(
        &item,
        Some("gitlab-discovery")
    ));
}

#[test]
fn failed_or_unrelated_mcp_tool_calls_do_not_clear_startup_warning() {
    let failed = json!({
        "type": "mcpToolCall",
        "server": "gitlab-discovery",
        "tool": "list_gitlab_paths",
        "status": "failed",
        "error": {"message": "boom"}
    });
    let other_server = json!({
        "type": "mcpToolCall",
        "server": "chrome-devtools",
        "tool": "list_pages",
        "status": "completed"
    });

    assert!(!item_is_successful_gitlab_discovery_call(
        &failed,
        Some("gitlab-discovery")
    ));
    assert!(!item_is_successful_gitlab_discovery_call(
        &other_server,
        Some("gitlab-discovery")
    ));
}

#[test]
fn build_command_script_includes_reasoning_effort_override() {
    let script = DockerCodexRunner::build_command_script(
        BuildCommandScriptInput {
            clone_url: "https://example.com/repo.git",
            gitlab_token: "token",
            repo: "repo",
            project_path: "repo",
            head_sha: "abc",
            auth_mount_path: "/root/.codex",
            target_branch: None,
            deps_enabled: false,
        },
        AppServerCommandOptions {
            browser_mcp: None,
            gitlab_discovery_mcp: None,
            mcp_server_overrides: &BTreeMap::new(),
            session_override: ConfiguredSessionOverride {
                reasoning_effort: Some("high"),
                ..ConfiguredSessionOverride::default()
            },
        },
    );
    assert!(script.contains("exec codex -c 'model_reasoning_effort=\"high\"' app-server"));
}

#[test]
fn build_command_script_includes_model_override() {
    let script = DockerCodexRunner::build_command_script(
        BuildCommandScriptInput {
            clone_url: "https://example.com/repo.git",
            gitlab_token: "token",
            repo: "repo",
            project_path: "repo",
            head_sha: "abc",
            auth_mount_path: "/root/.codex",
            target_branch: None,
            deps_enabled: false,
        },
        AppServerCommandOptions {
            browser_mcp: None,
            gitlab_discovery_mcp: None,
            mcp_server_overrides: &BTreeMap::new(),
            session_override: ConfiguredSessionOverride {
                model: Some("gpt-5.4"),
                ..ConfiguredSessionOverride::default()
            },
        },
    );
    assert!(script.contains("exec codex -c 'model=\"gpt-5.4\"' app-server"));
}

#[test]
fn build_command_script_includes_reasoning_summary_override() {
    let script = DockerCodexRunner::build_command_script(
        BuildCommandScriptInput {
            clone_url: "https://example.com/repo.git",
            gitlab_token: "token",
            repo: "repo",
            project_path: "repo",
            head_sha: "abc",
            auth_mount_path: "/root/.codex",
            target_branch: None,
            deps_enabled: false,
        },
        AppServerCommandOptions {
            browser_mcp: None,
            gitlab_discovery_mcp: None,
            mcp_server_overrides: &BTreeMap::new(),
            session_override: ConfiguredSessionOverride {
                reasoning_summary: Some("detailed"),
                ..ConfiguredSessionOverride::default()
            },
        },
    );
    assert!(script.contains("exec codex -c 'model_reasoning_summary=\"detailed\"' app-server"));
}

#[test]
fn security_context_session_override_uses_security_context_model_and_review_summary() {
    let mut codex = test_codex_config();
    codex.session_overrides.security_context.model = Some("gpt-5.4-mini".to_string());
    let runner = test_runner_with_codex(codex);

    let session_override = runner.security_context_session_override();

    assert_eq!(session_override.model, Some("gpt-5.4-mini"));
    assert_eq!(session_override.reasoning_summary, Some("detailed"));
    assert_eq!(session_override.reasoning_effort, Some("xhigh"));
}

#[test]
fn security_review_session_override_uses_security_review_model_and_review_summary() {
    let mut codex = test_codex_config();
    codex.session_overrides.security_review.model = Some("gpt-5.4".to_string());
    let runner = test_runner_with_codex(codex);

    let session_override = runner.security_review_session_override();

    assert_eq!(session_override.model, Some("gpt-5.4"));
    assert_eq!(session_override.reasoning_summary, Some("detailed"));
    assert_eq!(session_override.reasoning_effort, Some("high"));
}

#[test]
fn thread_start_params_include_extra_workspace_write_roots() {
    let mut codex = test_codex_config();
    codex.exec_sandbox = "workspace-write".to_string();
    let runner = test_runner_with_codex(codex);

    let params =
        runner.thread_start_params("/work/repo/group/repo", None, &["/work/mcp".to_string()]);

    assert_eq!(params["sandbox"], "workspace-write");
    assert_eq!(
        params["config"]["sandbox_workspace_write"]["writable_roots"],
        serde_json::json!(["/work/mcp", "/work/repo/group/repo"])
    );
    assert_eq!(
        params["config"]["sandbox_workspace_write"]["network_access"],
        serde_json::json!(true)
    );
}

#[test]
fn thread_start_params_preserve_workspace_write_defaults_without_extra_roots() {
    let mut codex = test_codex_config();
    codex.exec_sandbox = "workspace-write".to_string();
    let runner = test_runner_with_codex(codex);

    let params = runner.thread_start_params("/work/repo/group/repo", None, &[]);

    assert_eq!(params["sandbox"], "workspace-write");
    assert!(params.get("config").is_none());
}

#[test]
fn effective_feature_flags_require_injected_gitlab_discovery_mcp() {
    let requested = FeatureFlagSnapshot {
        gitlab_discovery_mcp: true,
        gitlab_inline_review_comments: false,
        composer_install: false,
        composer_auto_repositories: false,
        composer_safe_install: false,
        security_review: false,
        security_context_ignore_base_head: false,
    };

    assert!(DockerCodexRunner::effective_feature_flags(&requested, true).gitlab_discovery_mcp);
    assert!(!DockerCodexRunner::effective_feature_flags(&requested, false).gitlab_discovery_mcp);
}

#[test]
fn command_skips_static_gitlab_discovery_enable_override_without_injection() {
    let mut codex = test_codex_config();
    codex.mcp_server_overrides.review =
        BTreeMap::from([(codex.gitlab_discovery_mcp.server_name.clone(), true)]);
    let runner = test_runner_with_codex(codex);
    let ctx = review_context_with_target_branch(Some("main"));

    let script = runner
        .command(
            &ctx,
            AppServerCommandOptions {
                browser_mcp: None,
                gitlab_discovery_mcp: None,
                mcp_server_overrides: &runner.codex.mcp_server_overrides.review,
                session_override: runner.review_session_override(),
            },
        )
        .expect("command script");

    assert!(!script.contains("mcp_servers.gitlab-discovery.enabled=true"));
}

#[test]
fn prepare_gitlab_discovery_mcp_rejects_empty_source_repo() {
    let mut codex = test_codex_config();
    codex.gitlab_discovery_mcp = crate::config::GitLabDiscoveryMcpConfig {
        enabled: true,
        bind_addr: "127.0.0.1:8091".to_string(),
        advertise_url: "http://mcp.internal:8091/mcp".to_string(),
        allow: vec![crate::config::GitLabDiscoveryAllowRule {
            source_repos: vec!["group/repo".to_string()],
            source_group_prefixes: Vec::new(),
            target_repos: vec!["group/shared".to_string()],
            target_groups: Vec::new(),
        }],
        ..crate::config::GitLabDiscoveryMcpConfig::default()
    };
    let service = Arc::new(
        crate::gitlab_discovery_mcp::GitLabDiscoveryMcpService::new(
            DockerConfig {
                host: "tcp://127.0.0.1:2375".to_string(),
            },
            &crate::config::GitLabConfig {
                base_url: "https://gitlab.example.com".to_string(),
                token: "token".to_string(),
                bot_user_id: Some(1),
                created_after: None,
                targets: GitLabTargets::default(),
            },
            codex.gitlab_discovery_mcp.clone(),
        )
        .expect("gitlab discovery service"),
    );
    let mut runner = test_runner_with_codex(codex);
    runner.gitlab_discovery_mcp = Some(service as Arc<dyn GitLabDiscoveryHandle>);

    let prepared = runner.prepare_gitlab_discovery_mcp(
        "",
        &FeatureFlagSnapshot {
            gitlab_discovery_mcp: true,
            gitlab_inline_review_comments: false,
            composer_install: false,
            composer_auto_repositories: false,
            composer_safe_install: false,
            security_review: false,
            security_context_ignore_base_head: false,
        },
        &BTreeMap::new(),
    );

    assert!(prepared.is_none());
}

#[test]
fn browser_mcp_prereq_script_fails_when_command_is_missing() -> Result<()> {
    let script = browser_mcp_prereq_script(Some(&test_browser_mcp_config(
        "definitely-not-installed-browser-mcp",
    )));
    let output = run_bash_script(&script)?;
    assert!(!output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("browser MCP requires"));
    Ok(())
}

#[test]
fn browser_mcp_prereq_script_succeeds_when_command_exists() -> Result<()> {
    let script = browser_mcp_prereq_script(Some(&test_browser_mcp_config("sh")));
    let output = run_bash_script(&script)?;
    assert!(output.status.success());
    Ok(())
}

#[test]
fn browser_mcp_prereq_script_is_empty_when_disabled() {
    let script = browser_mcp_prereq_script(None);
    assert!(script.is_empty());
}

#[test]
fn browser_wait_script_probes_endpoint_until_ready() -> Result<()> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let port = listener.local_addr()?.port();
    let server = thread::spawn(move || -> Result<Vec<u8>> {
        let (mut stream, _) = listener.accept()?;
        stream.set_read_timeout(Some(Duration::from_secs(5)))?;

        let mut request = Vec::new();
        let mut buf = [0_u8; 256];
        loop {
            match stream.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    request.extend_from_slice(&buf[..n]);
                    if request.ends_with(b"\r\n\r\n") {
                        break;
                    }
                }
                Err(err)
                    if matches!(
                        err.kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                    ) =>
                {
                    break;
                }
                Err(err) => return Err(err.into()),
            }
        }

        if request == b"GET /json/version HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n"
        {
            stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")?;
        }

        Ok(request)
    });

    let output = run_bash_script(&render_browser_wait_script_for_port(port))?;
    let request = server.join().expect("server thread panicked")?;

    assert!(
        output.status.success(),
        "stdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        request,
        b"GET /json/version HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n"
    );
    Ok(())
}
