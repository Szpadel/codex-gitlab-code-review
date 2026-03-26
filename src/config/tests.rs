use super::*;
use std::fs;
use std::path::PathBuf;
use std::sync::Mutex;
use uuid::Uuid;

static ENV_LOCK: Mutex<()> = Mutex::new(());

fn write_temp_config(contents: &str) -> PathBuf {
    let mut path = env::temp_dir();
    path.push(format!("codex-review-config-{}.yaml", Uuid::new_v4()));
    fs::write(&path, contents).expect("write temp config");
    path
}

fn try_load_from_yaml(contents: &str) -> Result<Config> {
    let _lock = ENV_LOCK.lock().expect("lock env");
    let path = write_temp_config(contents);
    let previous = env::var("CONFIG_PATH").ok();
    unsafe {
        env::set_var("CONFIG_PATH", &path);
    }
    let loaded = Config::load();
    match previous {
        Some(value) => unsafe {
            env::set_var("CONFIG_PATH", value);
        },
        None => unsafe {
            env::remove_var("CONFIG_PATH");
        },
    }
    let _ = fs::remove_file(&path);
    loaded
}

fn load_from_yaml(contents: &str) -> Config {
    try_load_from_yaml(contents).expect("load config")
}

fn with_env_var<T>(name: &str, value: Option<&str>, action: impl FnOnce() -> T) -> T {
    let _lock = ENV_LOCK.lock().expect("lock env");
    let previous = env::var(name).ok();
    match value {
        Some(value) => unsafe {
            env::set_var(name, value);
        },
        None => unsafe {
            env::remove_var(name);
        },
    }
    let result = action();
    match previous {
        Some(value) => unsafe {
            env::set_var(name, value);
        },
        None => unsafe {
            env::remove_var(name);
        },
    }
    result
}

fn base_config_yaml(extra: &str) -> String {
    format!(
        r#"
gitlab:
  base_url: "https://gitlab.example.com"
  token: "token"
  bot_user_id: 1
  targets:
    repos:
      - "group/repo"
schedule:
  cron: "* * * * *"
  timezone: null
review:
  max_concurrent: 1
  eyes_emoji: "eyes"
  thumbs_emoji: "thumbsup"
  comment_marker_prefix: "<!-- codex-review:sha="
  stale_in_progress_minutes: 60
  dry_run: false
codex:
  image: "ghcr.io/openai/codex-universal:latest"
  timeout_seconds: 300
  auth_host_path: "/root/.codex"
  auth_mount_path: "/root/.codex"
  exec_sandbox: "danger-full-access"
database:
  path: "/tmp/state.sqlite"
server:
  bind_addr: "127.0.0.1:0"
{}
"#,
        extra
    )
}

#[test]
fn defaults_docker_host_when_missing() {
    let yaml = base_config_yaml("");
    let config = load_from_yaml(&yaml);
    assert_eq!(config.docker.host, default_docker_host());
}

#[test]
fn defaults_docker_host_when_empty() {
    let yaml = base_config_yaml(
        r#"
docker:
  host: ""
"#,
    );
    let config = load_from_yaml(&yaml);
    assert_eq!(config.docker.host, default_docker_host());
}

#[test]
fn defaults_mention_commands_when_missing() {
    let yaml = base_config_yaml("");
    let config = load_from_yaml(&yaml);
    assert_eq!(config.review.additional_developer_instructions, None);
    assert!(!config.review.mention_commands.enabled);
    assert_eq!(config.review.mention_commands.bot_username, None);
    assert_eq!(config.review.mention_commands.eyes_emoji, None);
    assert_eq!(
        config
            .review
            .mention_commands
            .additional_developer_instructions,
        None
    );
    assert!(config.codex.fallback_auth_accounts.is_empty());
    assert_eq!(config.codex.usage_limit_fallback_cooldown_seconds, 3600);
    assert!(config.codex.mcp_server_overrides.review.is_empty());
    assert!(config.codex.mcp_server_overrides.mention.is_empty());
    assert_eq!(config.codex.reasoning_effort.review, None);
    assert_eq!(config.codex.reasoning_effort.mention, None);
    assert_eq!(
        config.codex.reasoning_effort.security_context.as_deref(),
        Some("xhigh")
    );
    assert_eq!(
        config.codex.reasoning_effort.security_review.as_deref(),
        Some("high")
    );
    assert_eq!(
        config.codex.reasoning_summary.review.as_deref(),
        Some("detailed")
    );
    assert_eq!(
        config.codex.reasoning_summary.mention.as_deref(),
        Some("detailed")
    );
    assert_eq!(config.codex.browser_mcp, BrowserMcpConfig::default());
}

#[test]
fn parses_security_config_without_debounce() {
    let yaml = r#"
gitlab:
  base_url: "https://gitlab.example.com"
  token: "token"
  bot_user_id: 1
  targets:
    repos:
      - "group/repo"
schedule:
  cron: "* * * * *"
  timezone: null
review:
  max_concurrent: 1
  eyes_emoji: "eyes"
  thumbs_emoji: "thumbsup"
  comment_marker_prefix: "<!-- codex-review:sha="
  stale_in_progress_minutes: 60
  dry_run: false
  security:
    context_ttl_seconds: 900
    min_confidence_score: 0.9
    comment_marker_prefix: "<!-- custom-security-review:sha="
    finding_marker_prefix: "<!-- custom-security-review-finding:sha="
    additional_developer_instructions: "Tighten the rubric."
codex:
  image: "ghcr.io/openai/codex-universal:latest"
  timeout_seconds: 300
  auth_host_path: "/root/.codex"
  auth_mount_path: "/root/.codex"
  exec_sandbox: "danger-full-access"
database:
  path: "/tmp/state.sqlite"
server:
  bind_addr: "127.0.0.1:0"
"#;
    let config = load_from_yaml(yaml);
    assert_eq!(config.review.security.context_ttl_seconds, 900);
    assert_eq!(config.review.security.min_confidence_score, 0.9);
    assert_eq!(
        config.review.security.comment_marker_prefix,
        "<!-- custom-security-review:sha="
    );
    assert_eq!(
        config.review.security.finding_marker_prefix,
        "<!-- custom-security-review-finding:sha="
    );
    assert_eq!(
        config
            .review
            .security
            .additional_developer_instructions
            .as_deref(),
        Some("Tighten the rubric.")
    );
}

#[test]
fn ignores_legacy_proxy_block() {
    let yaml = base_config_yaml(
        r#"
proxy:
  http_proxy: "http://proxy.internal:3128"
  https_proxy: "http://proxy.internal:3128"
  no_proxy: "localhost"
"#,
    );
    let config = load_from_yaml(&yaml);
    assert_eq!(config.docker.host, default_docker_host());
    assert_eq!(config.server.bind_addr, "127.0.0.1:0");
}

#[test]
fn detects_legacy_proxy_block() {
    let yaml = base_config_yaml(
        r#"
proxy:
  http_proxy: "http://proxy.internal:3128"
"#,
    );
    let path = write_temp_config(&yaml);
    let cfg = config::Config::builder()
        .add_source(config::File::from(path.as_path()))
        .build()
        .expect("load raw config");
    let _ = fs::remove_file(&path);

    assert!(legacy_proxy_config_present(&cfg));
}

#[test]
fn loads_mention_commands_overrides() {
    let yaml = r#"
gitlab:
  base_url: "https://gitlab.example.com"
  token: "token"
  bot_user_id: 1
  targets:
    repos:
      - "group/repo"
schedule:
  cron: "* * * * *"
  timezone: null
review:
  max_concurrent: 1
  eyes_emoji: "eyes"
  thumbs_emoji: "thumbsup"
  comment_marker_prefix: "<!-- codex-review:sha="
  stale_in_progress_minutes: 60
  dry_run: false
  additional_developer_instructions: "Check performance-sensitive paths."
  mention_commands:
    enabled: true
    bot_username: "botuser"
    eyes_emoji: "inspect"
    additional_developer_instructions: "Prefer small commits."
codex:
  image: "ghcr.io/openai/codex-universal:latest"
  timeout_seconds: 300
  auth_host_path: "/root/.codex"
  auth_mount_path: "/root/.codex"
  exec_sandbox: "danger-full-access"
database:
  path: "/tmp/state.sqlite"
server:
  bind_addr: "127.0.0.1:0"
"#;
    let config = load_from_yaml(yaml);
    assert_eq!(
        config.review.additional_developer_instructions.as_deref(),
        Some("Check performance-sensitive paths.")
    );
    assert!(config.review.mention_commands.enabled);
    assert_eq!(
        config.review.mention_commands.bot_username.as_deref(),
        Some("botuser")
    );
    assert_eq!(
        config.review.mention_commands.eyes_emoji.as_deref(),
        Some("inspect")
    );
    assert_eq!(
        config
            .review
            .mention_commands
            .additional_developer_instructions
            .as_deref(),
        Some("Prefer small commits.")
    );
}

#[test]
fn loads_mcp_server_overrides() {
    let yaml = r#"
gitlab:
  base_url: "https://gitlab.example.com"
  token: "token"
  bot_user_id: 1
  targets:
    repos:
      - "group/repo"
schedule:
  cron: "* * * * *"
  timezone: null
review:
  max_concurrent: 1
  eyes_emoji: "eyes"
  thumbs_emoji: "thumbsup"
  comment_marker_prefix: "<!-- codex-review:sha="
  stale_in_progress_minutes: 60
  dry_run: false
codex:
  image: "ghcr.io/openai/codex-universal:latest"
  timeout_seconds: 300
  auth_host_path: "/root/.codex"
  auth_mount_path: "/root/.codex"
  exec_sandbox: "danger-full-access"
  mcp_server_overrides:
    review:
      github: false
      memory: true
    mention:
      github: true
      playwright: false
database:
  path: "/tmp/state.sqlite"
server:
  bind_addr: "127.0.0.1:0"
"#;
    let config = load_from_yaml(yaml);
    assert_eq!(
        config.codex.mcp_server_overrides.review.get("github"),
        Some(&false)
    );
    assert_eq!(
        config.codex.mcp_server_overrides.review.get("memory"),
        Some(&true)
    );
    assert_eq!(
        config.codex.mcp_server_overrides.mention.get("github"),
        Some(&true)
    );
    assert_eq!(
        config.codex.mcp_server_overrides.mention.get("playwright"),
        Some(&false)
    );
}

#[test]
fn loads_reasoning_effort_overrides() {
    let yaml = r#"
gitlab:
  base_url: "https://gitlab.example.com"
  token: "token"
  bot_user_id: 1
  targets:
    repos:
      - "group/repo"
schedule:
  cron: "* * * * *"
  timezone: null
review:
  max_concurrent: 1
  eyes_emoji: "eyes"
  thumbs_emoji: "thumbsup"
  comment_marker_prefix: "<!-- codex-review:sha="
  stale_in_progress_minutes: 60
  dry_run: false
codex:
  image: "ghcr.io/openai/codex-universal:latest"
  timeout_seconds: 300
  auth_host_path: "/root/.codex"
  auth_mount_path: "/root/.codex"
  exec_sandbox: "danger-full-access"
  reasoning_effort:
    review: "high"
    mention: "low"
    security_context: "medium"
    security_review: "xhigh"
database:
  path: "/tmp/state.sqlite"
server:
  bind_addr: "127.0.0.1:0"
"#;
    let config = load_from_yaml(yaml);
    assert_eq!(
        config.codex.reasoning_effort.review.as_deref(),
        Some("high")
    );
    assert_eq!(
        config.codex.reasoning_effort.mention.as_deref(),
        Some("low")
    );
    assert_eq!(
        config.codex.reasoning_effort.security_context.as_deref(),
        Some("medium")
    );
    assert_eq!(
        config.codex.reasoning_effort.security_review.as_deref(),
        Some("xhigh")
    );
}

#[test]
fn explicit_null_security_reasoning_effort_overrides_disable_defaults() {
    let yaml = r#"
gitlab:
  base_url: "https://gitlab.example.com"
  token: "token"
  bot_user_id: 1
  targets:
    repos:
      - "group/repo"
schedule:
  cron: "* * * * *"
  timezone: null
review:
  max_concurrent: 1
  eyes_emoji: "eyes"
  thumbs_emoji: "thumbsup"
  comment_marker_prefix: "<!-- codex-review:sha="
  stale_in_progress_minutes: 60
  dry_run: false
codex:
  image: "ghcr.io/openai/codex-universal:latest"
  timeout_seconds: 300
  auth_host_path: "/root/.codex"
  auth_mount_path: "/root/.codex"
  exec_sandbox: "danger-full-access"
  reasoning_effort:
    security_context: null
    security_review: null
database:
  path: "/tmp/state.sqlite"
server:
  bind_addr: "127.0.0.1:0"
"#;
    let config = load_from_yaml(yaml);
    assert_eq!(config.codex.reasoning_effort.security_context, None);
    assert_eq!(config.codex.reasoning_effort.security_review, None);
}

#[test]
fn loads_reasoning_summary_overrides() {
    let yaml = r#"
gitlab:
  base_url: "https://gitlab.example.com"
  token: "token"
  bot_user_id: 1
  targets:
    repos:
      - "group/repo"
schedule:
  cron: "* * * * *"
  timezone: null
review:
  max_concurrent: 1
  eyes_emoji: "eyes"
  thumbs_emoji: "thumbsup"
  comment_marker_prefix: "<!-- codex-review:sha="
  stale_in_progress_minutes: 60
  dry_run: false
codex:
  image: "ghcr.io/openai/codex-universal:latest"
  timeout_seconds: 300
  auth_host_path: "/root/.codex"
  auth_mount_path: "/root/.codex"
  exec_sandbox: "danger-full-access"
  reasoning_summary:
    review: "detailed"
    mention: "none"
database:
  path: "/tmp/state.sqlite"
server:
  bind_addr: "127.0.0.1:0"
"#;
    let config = load_from_yaml(yaml);
    assert_eq!(
        config.codex.reasoning_summary.review.as_deref(),
        Some("detailed")
    );
    assert_eq!(
        config.codex.reasoning_summary.mention.as_deref(),
        Some("none")
    );
}

#[test]
fn loads_browser_mcp_config() {
    let yaml = r#"
gitlab:
  base_url: "https://gitlab.example.com"
  token: "token"
  bot_user_id: 1
  targets:
    repos:
      - "group/repo"
schedule:
  cron: "* * * * *"
  timezone: null
review:
  max_concurrent: 1
  eyes_emoji: "eyes"
  thumbs_emoji: "thumbsup"
  comment_marker_prefix: "<!-- codex-review:sha="
  stale_in_progress_minutes: 60
  dry_run: false
codex:
  image: "ghcr.io/openai/codex-universal:latest"
  timeout_seconds: 300
  auth_host_path: "/root/.codex"
  auth_mount_path: "/root/.codex"
  exec_sandbox: "danger-full-access"
  browser_mcp:
    enabled: true
    server_name: "chrome-devtools"
    browser_image: "chromedp/headless-shell:latest"
    remote_debugging_port: 9222
    browser_args:
      - "--disable-gpu"
      - "--no-sandbox"
database:
  path: "/tmp/state.sqlite"
server:
  bind_addr: "127.0.0.1:0"
"#;
    let config = load_from_yaml(yaml);
    assert!(config.codex.browser_mcp.enabled);
    assert_eq!(config.codex.browser_mcp.server_name, "chrome-devtools");
    assert_eq!(
        config.codex.browser_mcp.browser_image,
        "chromedp/headless-shell:latest"
    );
    assert_eq!(config.codex.browser_mcp.remote_debugging_port, 9222);
    assert_eq!(
        config.codex.browser_mcp.browser_args,
        vec!["--disable-gpu".to_string(), "--no-sandbox".to_string()]
    );
    assert!(config.codex.browser_mcp.browser_entrypoint.is_empty());
    assert_eq!(config.codex.browser_mcp.mcp_command, "npx");
    assert_eq!(
        config.codex.browser_mcp.mcp_args,
        vec!["-y".to_string(), "chrome-devtools-mcp@latest".to_string()]
    );
}

#[test]
fn errors_on_browser_mcp_non_default_port() {
    let yaml = r#"
gitlab:
  base_url: "https://gitlab.example.com"
  token: "token"
  bot_user_id: 1
  targets:
    repos:
      - "group/repo"
schedule:
  cron: "* * * * *"
  timezone: null
review:
  max_concurrent: 1
  eyes_emoji: "eyes"
  thumbs_emoji: "thumbsup"
  comment_marker_prefix: "<!-- codex-review:sha="
  stale_in_progress_minutes: 60
  dry_run: false
codex:
  image: "ghcr.io/openai/codex-universal:latest"
  timeout_seconds: 300
  auth_host_path: "/root/.codex"
  auth_mount_path: "/root/.codex"
  exec_sandbox: "danger-full-access"
  browser_mcp:
    enabled: true
    server_name: "chrome-devtools"
    browser_image: "chromedp/headless-shell:latest"
    remote_debugging_port: 9333
database:
  path: "/tmp/state.sqlite"
server:
  bind_addr: "127.0.0.1:0"
"#;
    let result = try_load_from_yaml(yaml);
    assert!(result.is_err());
    let msg = format!("{:#}", result.expect_err("error"));
    assert!(msg.contains("codex.browser_mcp.remote_debugging_port must be 9222"));
}

#[test]
fn errors_on_browser_mcp_browser_args_overriding_debug_endpoint() {
    let yaml = r#"
gitlab:
  base_url: "https://gitlab.example.com"
  token: "token"
  bot_user_id: 1
  targets:
    repos:
      - "group/repo"
schedule:
  cron: "* * * * *"
  timezone: null
review:
  max_concurrent: 1
  eyes_emoji: "eyes"
  thumbs_emoji: "thumbsup"
  comment_marker_prefix: "<!-- codex-review:sha="
  stale_in_progress_minutes: 60
  dry_run: false
codex:
  image: "ghcr.io/openai/codex-universal:latest"
  timeout_seconds: 300
  auth_host_path: "/root/.codex"
  auth_mount_path: "/root/.codex"
  exec_sandbox: "danger-full-access"
  browser_mcp:
    enabled: true
    server_name: "chrome-devtools"
    browser_image: "chromedp/headless-shell:latest"
    remote_debugging_port: 9222
    browser_args:
      - "--remote-debugging-port=9333"
database:
  path: "/tmp/state.sqlite"
server:
  bind_addr: "127.0.0.1:0"
"#;
    let result = try_load_from_yaml(yaml);
    assert!(result.is_err());
    let msg = format!("{:#}", result.expect_err("error"));
    assert!(msg.contains("must not override --remote-debugging-port"));
}

#[test]
fn errors_on_browser_mcp_browser_args_overriding_debug_endpoint_split_form() {
    let yaml = r#"
gitlab:
  base_url: "https://gitlab.example.com"
  token: "token"
  bot_user_id: 1
  targets:
    repos:
      - "group/repo"
schedule:
  cron: "* * * * *"
  timezone: null
review:
  max_concurrent: 1
  eyes_emoji: "eyes"
  thumbs_emoji: "thumbsup"
  comment_marker_prefix: "<!-- codex-review:sha="
  stale_in_progress_minutes: 60
  dry_run: false
codex:
  image: "ghcr.io/openai/codex-universal:latest"
  timeout_seconds: 300
  auth_host_path: "/root/.codex"
  auth_mount_path: "/root/.codex"
  exec_sandbox: "danger-full-access"
  browser_mcp:
    enabled: true
    server_name: "chrome-devtools"
    browser_image: "chromedp/headless-shell:latest"
    remote_debugging_port: 9222
    browser_args:
      - "--remote-debugging-address"
      - "127.0.0.2"
database:
  path: "/tmp/state.sqlite"
server:
  bind_addr: "127.0.0.1:0"
"#;
    let result = try_load_from_yaml(yaml);
    assert!(result.is_err());
    let msg = format!("{:#}", result.expect_err("error"));
    assert!(msg.contains("must not override --remote-debugging-address"));
}

#[test]
fn errors_on_browser_mcp_server_name_with_control_characters() {
    let yaml = r#"
gitlab:
  base_url: "https://gitlab.example.com"
  token: "token"
  bot_user_id: 1
  targets:
    repos:
      - "group/repo"
schedule:
  cron: "* * * * *"
  timezone: null
review:
  max_concurrent: 1
  eyes_emoji: "eyes"
  thumbs_emoji: "thumbsup"
  comment_marker_prefix: "<!-- codex-review:sha="
  stale_in_progress_minutes: 60
  dry_run: false
codex:
  image: "ghcr.io/openai/codex-universal:latest"
  timeout_seconds: 300
  auth_host_path: "/root/.codex"
  auth_mount_path: "/root/.codex"
  exec_sandbox: "danger-full-access"
  browser_mcp:
    enabled: true
    server_name: "chrome\ndevtools"
    browser_image: "chromedp/headless-shell:latest"
    remote_debugging_port: 9222
database:
  path: "/tmp/state.sqlite"
server:
  bind_addr: "127.0.0.1:0"
"#;
    let result = try_load_from_yaml(yaml);
    assert!(result.is_err());
    let msg = format!("{:#}", result.expect_err("error"));
    assert!(msg.contains("must not contain control characters"));
}

#[test]
fn errors_on_browser_mcp_server_name_with_invalid_characters() {
    let yaml = r#"
gitlab:
  base_url: "https://gitlab.example.com"
  token: "token"
  bot_user_id: 1
  targets:
    repos:
      - "group/repo"
schedule:
  cron: "* * * * *"
  timezone: null
review:
  max_concurrent: 1
  eyes_emoji: "eyes"
  thumbs_emoji: "thumbsup"
  comment_marker_prefix: "<!-- codex-review:sha="
  stale_in_progress_minutes: 60
  dry_run: false
codex:
  image: "ghcr.io/openai/codex-universal:latest"
  timeout_seconds: 300
  auth_host_path: "/root/.codex"
  auth_mount_path: "/root/.codex"
  exec_sandbox: "danger-full-access"
  browser_mcp:
    enabled: true
    server_name: "chrome.devtools"
    browser_image: "chromedp/headless-shell:latest"
    remote_debugging_port: 9222
database:
  path: "/tmp/state.sqlite"
server:
  bind_addr: "127.0.0.1:0"
"#;
    let result = try_load_from_yaml(yaml);
    assert!(result.is_err());
    let msg = format!("{:#}", result.expect_err("error"));
    assert!(msg.contains("must match ^[a-zA-Z0-9_-]+$"));
}

#[test]
fn loads_enabled_gitlab_discovery_mcp_without_allow_rules() {
    let yaml = r#"
gitlab:
  base_url: "https://gitlab.example.com"
  token: "token"
  bot_user_id: 1
  targets:
    repos:
      - "group/repo"
schedule:
  cron: "* * * * *"
  timezone: null
review:
  max_concurrent: 1
  eyes_emoji: "eyes"
  thumbs_emoji: "thumbsup"
  comment_marker_prefix: "<!-- codex-review:sha="
  stale_in_progress_minutes: 60
  dry_run: false
codex:
  image: "ghcr.io/openai/codex-universal:latest"
  timeout_seconds: 300
  auth_host_path: "/root/.codex"
  auth_mount_path: "/root/.codex"
  exec_sandbox: "danger-full-access"
  gitlab_discovery_mcp:
    enabled: true
    server_name: "gitlab-discovery"
    bind_addr: "0.0.0.0:8081"
    advertise_url: "http://host.docker.internal:8081/mcp"
    clone_root: "/work/mcp"
    allow: []
database:
  path: "/tmp/state.sqlite"
server:
  bind_addr: "127.0.0.1:0"
"#;
    let config = load_from_yaml(yaml);
    assert!(config.codex.gitlab_discovery_mcp.enabled);
    assert!(config.codex.gitlab_discovery_mcp.allow.is_empty());
}

#[test]
fn errors_on_gitlab_discovery_mcp_bind_addr_with_port_zero() {
    let yaml = r#"
gitlab:
  base_url: "https://gitlab.example.com"
  token: "token"
  bot_user_id: 1
  targets:
    repos:
      - "group/repo"
schedule:
  cron: "* * * * *"
  timezone: null
review:
  max_concurrent: 1
  eyes_emoji: "eyes"
  thumbs_emoji: "thumbsup"
  comment_marker_prefix: "<!-- codex-review:sha="
  stale_in_progress_minutes: 60
  dry_run: false
codex:
  image: "ghcr.io/openai/codex-universal:latest"
  timeout_seconds: 300
  auth_host_path: "/root/.codex"
  auth_mount_path: "/root/.codex"
  exec_sandbox: "danger-full-access"
  gitlab_discovery_mcp:
    enabled: true
    server_name: "gitlab-discovery"
    bind_addr: "127.0.0.1:0"
    advertise_url: "http://host.docker.internal:8081/mcp"
    clone_root: "/work/mcp"
database:
  path: "/tmp/state.sqlite"
server:
  bind_addr: "127.0.0.1:0"
"#;
    let result = try_load_from_yaml(yaml);
    assert!(result.is_err());
    let msg = format!("{:#}", result.expect_err("error"));
    assert!(msg.contains("codex.gitlab_discovery_mcp.bind_addr must include a non-zero port"));
}

#[test]
fn defaults_gitlab_discovery_advertise_url_to_host_gateway_when_unspecified() {
    let yaml = r#"
gitlab:
  base_url: "https://gitlab.example.com"
  token: "token"
  bot_user_id: 1
  targets:
    repos:
      - "group/repo"
schedule:
  cron: "* * * * *"
  timezone: null
review:
  max_concurrent: 1
  eyes_emoji: "eyes"
  thumbs_emoji: "thumbsup"
  comment_marker_prefix: "<!-- codex-review:sha="
  stale_in_progress_minutes: 60
  dry_run: false
codex:
  image: "ghcr.io/openai/codex-universal:latest"
  timeout_seconds: 300
  auth_host_path: "/root/.codex"
  auth_mount_path: "/root/.codex"
  exec_sandbox: "danger-full-access"
  gitlab_discovery_mcp:
    enabled: true
    server_name: "gitlab-discovery"
    bind_addr: "0.0.0.0:8081"
    advertise_url: ""
    clone_root: "/work/mcp"
database:
  path: "/tmp/state.sqlite"
server:
  bind_addr: "127.0.0.1:0"
"#;
    let config = load_from_yaml(yaml);
    assert_eq!(
        config.codex.gitlab_discovery_mcp.advertise_url,
        "http://host.docker.internal:8081/mcp"
    );
}

#[test]
fn errors_on_duplicate_enabled_injected_mcp_server_names() {
    let yaml = r#"
gitlab:
  base_url: "https://gitlab.example.com"
  token: "token"
  bot_user_id: 1
  targets:
    repos:
      - "group/repo"
schedule:
  cron: "* * * * *"
  timezone: null
review:
  max_concurrent: 1
  eyes_emoji: "eyes"
  thumbs_emoji: "thumbsup"
  comment_marker_prefix: "<!-- codex-review:sha="
  stale_in_progress_minutes: 60
  dry_run: false
codex:
  image: "ghcr.io/openai/codex-universal:latest"
  timeout_seconds: 300
  auth_host_path: "/root/.codex"
  auth_mount_path: "/root/.codex"
  exec_sandbox: "danger-full-access"
  browser_mcp:
    enabled: true
    server_name: "shared-mcp"
    browser_image: "chromedp/headless-shell:latest"
    remote_debugging_port: 9222
  gitlab_discovery_mcp:
    enabled: true
    server_name: "shared-mcp"
    bind_addr: "0.0.0.0:8081"
    advertise_url: "http://host.docker.internal:8081/mcp"
    clone_root: "/work/mcp"
database:
  path: "/tmp/state.sqlite"
server:
  bind_addr: "127.0.0.1:0"
"#;
    let result = try_load_from_yaml(yaml);
    assert!(result.is_err());
    let msg = format!("{:#}", result.expect_err("error"));
    assert!(msg.contains(
        "codex.browser_mcp.server_name and codex.gitlab_discovery_mcp.server_name must be distinct"
    ));
}

#[test]
fn errors_on_http_and_gitlab_discovery_bind_addr_collision() {
    let yaml = r#"
gitlab:
  base_url: "https://gitlab.example.com"
  token: "token"
  bot_user_id: 1
  targets:
    repos:
      - "group/repo"
schedule:
  cron: "* * * * *"
  timezone: null
review:
  max_concurrent: 1
  eyes_emoji: "eyes"
  thumbs_emoji: "thumbsup"
  comment_marker_prefix: "<!-- codex-review:sha="
  stale_in_progress_minutes: 60
  dry_run: false
codex:
  image: "ghcr.io/openai/codex-universal:latest"
  timeout_seconds: 300
  auth_host_path: "/root/.codex"
  auth_mount_path: "/root/.codex"
  exec_sandbox: "danger-full-access"
  gitlab_discovery_mcp:
    enabled: true
    server_name: "gitlab-discovery"
    bind_addr: "0.0.0.0:8080"
    advertise_url: "http://host.docker.internal:8081/mcp"
    clone_root: "/work/mcp"
database:
  path: "/tmp/state.sqlite"
server:
  bind_addr: "0.0.0.0:8080"
"#;
    let result = try_load_from_yaml(yaml);
    assert!(result.is_err());
    let msg = format!("{:#}", result.expect_err("error"));
    assert!(msg.contains(
"server.bind_addr and codex.gitlab_discovery_mcp.bind_addr must not target the same listener socket"
));
}

#[test]
fn errors_on_http_and_gitlab_discovery_bind_addr_collision_with_expanded_ipv6_wildcard() {
    let yaml = r#"
gitlab:
  base_url: "https://gitlab.example.com"
  token: "token"
  bot_user_id: 1
  targets:
    repos:
      - "group/repo"
schedule:
  cron: "* * * * * *"
review:
  max_concurrent: 1
  eyes_emoji: "eyes"
  thumbs_emoji: "thumbsup"
  comment_marker_prefix: "<!-- codex-review:sha="
  stale_in_progress_minutes: 60
  dry_run: false
codex:
  image: "ghcr.io/openai/codex-universal:latest"
  timeout_seconds: 300
  auth_host_path: "/root/.codex"
  auth_mount_path: "/root/.codex"
  exec_sandbox: "danger-full-access"
  gitlab_discovery_mcp:
    enabled: true
    server_name: "gitlab-discovery"
    bind_addr: "[0:0:0:0:0:0:0:0]:8080"
    advertise_url: "http://host.docker.internal:8081/mcp"
    clone_root: "/work/mcp"
database:
  path: "/tmp/state.sqlite"
server:
  bind_addr: "[::]:8080"
"#;
    let result = try_load_from_yaml(yaml);
    assert!(result.is_err());
    let msg = format!("{:#}", result.expect_err("error"));
    assert!(msg.contains(
"server.bind_addr and codex.gitlab_discovery_mcp.bind_addr must not target the same listener socket"
));
}

#[test]
fn errors_on_mcp_server_override_key_with_invalid_characters() {
    let yaml = r#"
gitlab:
  base_url: "https://gitlab.example.com"
  token: "token"
  bot_user_id: 1
  targets:
    repos:
      - "group/repo"
schedule:
  cron: "* * * * *"
  timezone: null
review:
  max_concurrent: 1
  eyes_emoji: "eyes"
  thumbs_emoji: "thumbsup"
  comment_marker_prefix: "<!-- codex-review:sha="
  stale_in_progress_minutes: 60
  dry_run: false
codex:
  image: "ghcr.io/openai/codex-universal:latest"
  timeout_seconds: 300
  auth_host_path: "/root/.codex"
  auth_mount_path: "/root/.codex"
  exec_sandbox: "danger-full-access"
  mcp_server_overrides:
    review:
      chrome.devtools: false
database:
  path: "/tmp/state.sqlite"
server:
  bind_addr: "127.0.0.1:0"
"#;
    let result = try_load_from_yaml(yaml);
    assert!(result.is_err());
    let msg = format!("{:#}", result.expect_err("error"));
    assert!(msg.contains("keys must match ^[a-zA-Z0-9_-]+$"));
}

#[test]
fn errors_on_empty_reasoning_effort_override() {
    let yaml = r#"
gitlab:
  base_url: "https://gitlab.example.com"
  token: "token"
  bot_user_id: 1
  targets:
    repos:
      - "group/repo"
schedule:
  cron: "* * * * *"
  timezone: null
review:
  max_concurrent: 1
  eyes_emoji: "eyes"
  thumbs_emoji: "thumbsup"
  comment_marker_prefix: "<!-- codex-review:sha="
  stale_in_progress_minutes: 60
  dry_run: false
codex:
  image: "ghcr.io/openai/codex-universal:latest"
  timeout_seconds: 300
  auth_host_path: "/root/.codex"
  auth_mount_path: "/root/.codex"
  exec_sandbox: "danger-full-access"
  reasoning_effort:
    review: "   "
database:
  path: "/tmp/state.sqlite"
server:
  bind_addr: "127.0.0.1:0"
"#;
    let result = try_load_from_yaml(yaml);
    assert!(result.is_err());
    let msg = format!("{:#}", result.expect_err("error"));
    assert!(msg.contains("codex.reasoning_effort.review must not be empty"));
}

#[test]
fn errors_on_unsupported_reasoning_effort_override() {
    let yaml = r#"
gitlab:
  base_url: "https://gitlab.example.com"
  token: "token"
  bot_user_id: 1
  targets:
    repos:
      - "group/repo"
schedule:
  cron: "* * * * *"
  timezone: null
review:
  max_concurrent: 1
  eyes_emoji: "eyes"
  thumbs_emoji: "thumbsup"
  comment_marker_prefix: "<!-- codex-review:sha="
  stale_in_progress_minutes: 60
  dry_run: false
codex:
  image: "ghcr.io/openai/codex-universal:latest"
  timeout_seconds: 300
  auth_host_path: "/root/.codex"
  auth_mount_path: "/root/.codex"
  exec_sandbox: "danger-full-access"
  reasoning_effort:
    mention: "fast"
database:
  path: "/tmp/state.sqlite"
server:
  bind_addr: "127.0.0.1:0"
"#;
    let result = try_load_from_yaml(yaml);
    assert!(result.is_err());
    let msg = format!("{:#}", result.expect_err("error"));
    assert!(
        msg.contains("codex.reasoning_effort.mention must be one of: low, medium, high, xhigh")
    );
}

#[test]
fn errors_on_empty_reasoning_summary_override() {
    let yaml = r#"
gitlab:
  base_url: "https://gitlab.example.com"
  token: "token"
  bot_user_id: 1
  targets:
    repos:
      - "group/repo"
schedule:
  cron: "* * * * *"
  timezone: null
review:
  max_concurrent: 1
  eyes_emoji: "eyes"
  thumbs_emoji: "thumbsup"
  comment_marker_prefix: "<!-- codex-review:sha="
  stale_in_progress_minutes: 60
  dry_run: false
codex:
  image: "ghcr.io/openai/codex-universal:latest"
  timeout_seconds: 300
  auth_host_path: "/root/.codex"
  auth_mount_path: "/root/.codex"
  exec_sandbox: "danger-full-access"
  reasoning_summary:
    review: "   "
database:
  path: "/tmp/state.sqlite"
server:
  bind_addr: "127.0.0.1:0"
"#;
    let result = try_load_from_yaml(yaml);
    assert!(result.is_err());
    let msg = format!("{:#}", result.expect_err("error"));
    assert!(msg.contains("codex.reasoning_summary.review must not be empty"));
}

#[test]
fn errors_on_unsupported_reasoning_summary_override() {
    let yaml = r#"
gitlab:
  base_url: "https://gitlab.example.com"
  token: "token"
  bot_user_id: 1
  targets:
    repos:
      - "group/repo"
schedule:
  cron: "* * * * *"
  timezone: null
review:
  max_concurrent: 1
  eyes_emoji: "eyes"
  thumbs_emoji: "thumbsup"
  comment_marker_prefix: "<!-- codex-review:sha="
  stale_in_progress_minutes: 60
  dry_run: false
codex:
  image: "ghcr.io/openai/codex-universal:latest"
  timeout_seconds: 300
  auth_host_path: "/root/.codex"
  auth_mount_path: "/root/.codex"
  exec_sandbox: "danger-full-access"
  reasoning_summary:
    mention: "verbose"
database:
  path: "/tmp/state.sqlite"
server:
  bind_addr: "127.0.0.1:0"
"#;
    let result = try_load_from_yaml(yaml);
    assert!(result.is_err());
    let msg = format!("{:#}", result.expect_err("error"));
    assert!(msg.contains("codex.reasoning_summary.mention must be one of: none, auto, detailed"));
}

#[test]
fn loads_all_target_selector() {
    let yaml = r#"
gitlab:
  base_url: "https://gitlab.example.com"
  token: "token"
  bot_user_id: 1
  targets:
    repos: all
schedule:
  cron: "* * * * *"
  timezone: null
review:
  max_concurrent: 1
  eyes_emoji: "eyes"
  thumbs_emoji: "thumbsup"
  comment_marker_prefix: "<!-- codex-review:sha="
  stale_in_progress_minutes: 60
  dry_run: false
codex:
  image: "ghcr.io/openai/codex-universal:latest"
  timeout_seconds: 300
  auth_host_path: "/root/.codex"
  auth_mount_path: "/root/.codex"
  exec_sandbox: "danger-full-access"
database:
  path: "/tmp/state.sqlite"
server:
  bind_addr: "127.0.0.1:0"
"#;
    let config = load_from_yaml(yaml);
    assert!(config.gitlab.targets.repos.is_all());
}

#[test]
fn errors_on_invalid_target_selector() {
    let yaml = r#"
gitlab:
  base_url: "https://gitlab.example.com"
  token: "token"
  bot_user_id: 1
  targets:
    repos: everything
schedule:
  cron: "* * * * *"
  timezone: null
review:
  max_concurrent: 1
  eyes_emoji: "eyes"
  thumbs_emoji: "thumbsup"
  comment_marker_prefix: "<!-- codex-review:sha="
  stale_in_progress_minutes: 60
  dry_run: false
codex:
  image: "ghcr.io/openai/codex-universal:latest"
  timeout_seconds: 300
  auth_host_path: "/root/.codex"
  auth_mount_path: "/root/.codex"
  exec_sandbox: "danger-full-access"
database:
  path: "/tmp/state.sqlite"
server:
  bind_addr: "127.0.0.1:0"
"#;
    let result = try_load_from_yaml(yaml);
    assert!(result.is_err());
}

#[test]
fn loads_fallback_auth_accounts_in_declared_order() {
    let yaml = r#"
gitlab:
  base_url: "https://gitlab.example.com"
  token: "token"
  bot_user_id: 1
  targets:
    repos:
      - "group/repo"
schedule:
  cron: "* * * * *"
  timezone: null
review:
  max_concurrent: 1
  eyes_emoji: "eyes"
  thumbs_emoji: "thumbsup"
  comment_marker_prefix: "<!-- codex-review:sha="
  stale_in_progress_minutes: 60
  dry_run: false
codex:
  image: "ghcr.io/openai/codex-universal:latest"
  timeout_seconds: 300
  auth_host_path: "/root/.codex"
  auth_mount_path: "/root/.codex"
  exec_sandbox: "danger-full-access"
  usage_limit_fallback_cooldown_seconds: 120
  fallback_auth_accounts:
    - name: "backup-high"
      auth_host_path: "/root/.codex-backup-high"
    - name: "backup-low"
      auth_host_path: "/root/.codex-backup-low"
database:
  path: "/tmp/state.sqlite"
server:
  bind_addr: "127.0.0.1:0"
"#;
    let config = load_from_yaml(yaml);
    assert_eq!(config.codex.usage_limit_fallback_cooldown_seconds, 120);
    assert_eq!(config.codex.fallback_auth_accounts.len(), 2);
    assert_eq!(config.codex.fallback_auth_accounts[0].name, "backup-high");
    assert_eq!(
        config.codex.fallback_auth_accounts[0].auth_host_path,
        "/root/.codex-backup-high"
    );
    assert_eq!(config.codex.fallback_auth_accounts[1].name, "backup-low");
    assert_eq!(
        config.codex.fallback_auth_accounts[1].auth_host_path,
        "/root/.codex-backup-low"
    );
}

#[test]
fn errors_on_duplicate_fallback_account_name() {
    let yaml = r#"
gitlab:
  base_url: "https://gitlab.example.com"
  token: "token"
  bot_user_id: 1
  targets:
    repos:
      - "group/repo"
schedule:
  cron: "* * * * *"
  timezone: null
review:
  max_concurrent: 1
  eyes_emoji: "eyes"
  thumbs_emoji: "thumbsup"
  comment_marker_prefix: "<!-- codex-review:sha="
  stale_in_progress_minutes: 60
  dry_run: false
codex:
  image: "ghcr.io/openai/codex-universal:latest"
  timeout_seconds: 300
  auth_host_path: "/root/.codex"
  auth_mount_path: "/root/.codex"
  exec_sandbox: "danger-full-access"
  fallback_auth_accounts:
    - name: "backup"
      auth_host_path: "/root/.codex-backup-a"
    - name: "backup"
      auth_host_path: "/root/.codex-backup-b"
database:
  path: "/tmp/state.sqlite"
server:
  bind_addr: "127.0.0.1:0"
"#;
    let result = try_load_from_yaml(yaml);
    assert!(result.is_err());
    let msg = format!("{:#}", result.expect_err("error"));
    assert!(msg.contains("duplicate codex fallback account name"));
}

#[test]
fn errors_on_duplicate_auth_host_path_between_primary_and_fallback() {
    let yaml = r#"
gitlab:
  base_url: "https://gitlab.example.com"
  token: "token"
  bot_user_id: 1
  targets:
    repos:
      - "group/repo"
schedule:
  cron: "* * * * *"
  timezone: null
review:
  max_concurrent: 1
  eyes_emoji: "eyes"
  thumbs_emoji: "thumbsup"
  comment_marker_prefix: "<!-- codex-review:sha="
  stale_in_progress_minutes: 60
  dry_run: false
codex:
  image: "ghcr.io/openai/codex-universal:latest"
  timeout_seconds: 300
  auth_host_path: "/root/.codex"
  auth_mount_path: "/root/.codex"
  exec_sandbox: "danger-full-access"
  fallback_auth_accounts:
    - name: "backup"
      auth_host_path: "/root/.codex"
database:
  path: "/tmp/state.sqlite"
server:
  bind_addr: "127.0.0.1:0"
"#;
    let result = try_load_from_yaml(yaml);
    assert!(result.is_err());
    let msg = format!("{:#}", result.expect_err("error"));
    assert!(msg.contains("duplicate codex auth_host_path"));
}

#[test]
fn errors_on_reserved_primary_fallback_name() {
    let yaml = r#"
gitlab:
  base_url: "https://gitlab.example.com"
  token: "token"
  bot_user_id: 1
  targets:
    repos:
      - "group/repo"
schedule:
  cron: "* * * * *"
  timezone: null
review:
  max_concurrent: 1
  eyes_emoji: "eyes"
  thumbs_emoji: "thumbsup"
  comment_marker_prefix: "<!-- codex-review:sha="
  stale_in_progress_minutes: 60
  dry_run: false
codex:
  image: "ghcr.io/openai/codex-universal:latest"
  timeout_seconds: 300
  auth_host_path: "/root/.codex"
  auth_mount_path: "/root/.codex"
  exec_sandbox: "danger-full-access"
  fallback_auth_accounts:
    - name: "primary"
      auth_host_path: "/root/.codex-backup"
database:
  path: "/tmp/state.sqlite"
server:
  bind_addr: "127.0.0.1:0"
"#;
    let result = try_load_from_yaml(yaml);
    assert!(result.is_err());
    let msg = format!("{:#}", result.expect_err("error"));
    assert!(msg.contains("name 'primary' is reserved"));
}

#[test]
fn detects_cluster_service_advertise_urls() {
    let mut config = load_from_yaml(
        r#"
gitlab:
  base_url: "https://gitlab.example.com"
  token: "token"
  bot_user_id: 1
  targets:
    repos:
      - "group/repo"
schedule:
  cron: "* * * * *"
  timezone: null
review:
  max_concurrent: 1
  eyes_emoji: "eyes"
  thumbs_emoji: "thumbsup"
  comment_marker_prefix: "<!-- codex-review:sha="
  stale_in_progress_minutes: 60
  dry_run: false
codex:
  image: "ghcr.io/openai/codex-universal:latest"
  timeout_seconds: 300
  auth_host_path: "/root/.codex"
  auth_mount_path: "/root/.codex"
  exec_sandbox: "danger-full-access"
  gitlab_discovery_mcp:
    enabled: true
    server_name: "gitlab-discovery"
    bind_addr: "0.0.0.0:8081"
    advertise_url: "http://host.docker.internal:8081/mcp"
    clone_root: "/work/mcp"
database:
  path: "/tmp/state.sqlite"
server:
  bind_addr: "127.0.0.1:0"
"#,
    );

    config.codex.gitlab_discovery_mcp.advertise_url =
        "http://codex-gitlab-review.default.svc.cluster.local:8081/mcp".to_string();

    assert!(gitlab_discovery_mcp_uses_cluster_service_advertise_url(
        &config.codex
    ));
}

#[test]
fn ignores_non_cluster_service_advertise_urls() {
    let config = load_from_yaml(
        r#"
gitlab:
  base_url: "https://gitlab.example.com"
  token: "token"
  bot_user_id: 1
  targets:
    repos:
      - "group/repo"
schedule:
  cron: "* * * * *"
  timezone: null
review:
  max_concurrent: 1
  eyes_emoji: "eyes"
  thumbs_emoji: "thumbsup"
  comment_marker_prefix: "<!-- codex-review:sha="
  stale_in_progress_minutes: 60
  dry_run: false
codex:
  image: "ghcr.io/openai/codex-universal:latest"
  timeout_seconds: 300
  auth_host_path: "/root/.codex"
  auth_mount_path: "/root/.codex"
  exec_sandbox: "danger-full-access"
  gitlab_discovery_mcp:
    enabled: true
    server_name: "gitlab-discovery"
    bind_addr: "0.0.0.0:8081"
    advertise_url: "http://10.42.0.15:8081/mcp"
    clone_root: "/work/mcp"
database:
  path: "/tmp/state.sqlite"
server:
  bind_addr: "127.0.0.1:0"
"#,
    );

    assert!(!gitlab_discovery_mcp_uses_cluster_service_advertise_url(
        &config.codex
    ));
}

#[test]
fn fills_gitlab_discovery_advertise_url_from_pod_ip() {
    let mut config = load_from_yaml(
        r#"
gitlab:
  base_url: "https://gitlab.example.com"
  token: "token"
  bot_user_id: 1
  targets:
    repos:
      - "group/repo"
schedule:
  cron: "* * * * *"
  timezone: null
review:
  max_concurrent: 1
  eyes_emoji: "eyes"
  thumbs_emoji: "thumbsup"
  comment_marker_prefix: "<!-- codex-review:sha="
  stale_in_progress_minutes: 60
  dry_run: false
codex:
  image: "ghcr.io/openai/codex-universal:latest"
  timeout_seconds: 300
  auth_host_path: "/root/.codex"
  auth_mount_path: "/root/.codex"
  exec_sandbox: "danger-full-access"
  gitlab_discovery_mcp:
    enabled: true
    server_name: "gitlab-discovery"
    bind_addr: "0.0.0.0:19091"
    advertise_url: "http://10.42.0.15:19091/mcp"
    clone_root: "/work/mcp"
database:
  path: "/tmp/state.sqlite"
server:
  bind_addr: "127.0.0.1:0"
"#,
    );
    config.codex.gitlab_discovery_mcp.advertise_url.clear();

    with_env_var("POD_IP", Some("10.42.0.15"), || {
        apply_gitlab_discovery_mcp_runtime_defaults(&mut config)
            .expect("pod IP default should be applied");
    });

    assert_eq!(
        config.codex.gitlab_discovery_mcp.advertise_url,
        "http://10.42.0.15:19091/mcp"
    );
}

#[test]
fn fills_gitlab_discovery_advertise_url_from_ipv6_pod_ip() {
    let mut config = load_from_yaml(
        r#"
gitlab:
  base_url: "https://gitlab.example.com"
  token: "token"
  bot_user_id: 1
  targets:
    repos:
      - "group/repo"
schedule:
  cron: "* * * * *"
  timezone: null
review:
  max_concurrent: 1
  eyes_emoji: "eyes"
  thumbs_emoji: "thumbsup"
  comment_marker_prefix: "<!-- codex-review:sha="
  stale_in_progress_minutes: 60
  dry_run: false
codex:
  image: "ghcr.io/openai/codex-universal:latest"
  timeout_seconds: 300
  auth_host_path: "/root/.codex"
  auth_mount_path: "/root/.codex"
  exec_sandbox: "danger-full-access"
  gitlab_discovery_mcp:
    enabled: true
    server_name: "gitlab-discovery"
    bind_addr: "[::]:8081"
    advertise_url: "http://[fd00::123]:8081/mcp"
    clone_root: "/work/mcp"
database:
  path: "/tmp/state.sqlite"
server:
  bind_addr: "127.0.0.1:0"
"#,
    );
    config.codex.gitlab_discovery_mcp.advertise_url.clear();

    with_env_var("POD_IP", Some("fd00::123"), || {
        apply_gitlab_discovery_mcp_runtime_defaults(&mut config)
            .expect("IPv6 pod IP default should be applied");
    });

    assert_eq!(
        config.codex.gitlab_discovery_mcp.advertise_url,
        "http://[fd00::123]:8081/mcp"
    );
}

#[test]
fn falls_back_to_host_gateway_when_pod_ip_is_absent() {
    let mut config = load_from_yaml(
        r#"
gitlab:
  base_url: "https://gitlab.example.com"
  token: "token"
  bot_user_id: 1
  targets:
    repos:
      - "group/repo"
schedule:
  cron: "* * * * *"
  timezone: null
review:
  max_concurrent: 1
  eyes_emoji: "eyes"
  thumbs_emoji: "thumbsup"
  comment_marker_prefix: "<!-- codex-review:sha="
  stale_in_progress_minutes: 60
  dry_run: false
codex:
  image: "ghcr.io/openai/codex-universal:latest"
  timeout_seconds: 300
  auth_host_path: "/root/.codex"
  auth_mount_path: "/root/.codex"
  exec_sandbox: "danger-full-access"
  gitlab_discovery_mcp:
    enabled: true
    server_name: "gitlab-discovery"
    bind_addr: "0.0.0.0:19091"
    advertise_url: "http://10.42.0.15:19091/mcp"
    clone_root: "/work/mcp"
database:
  path: "/tmp/state.sqlite"
server:
  bind_addr: "127.0.0.1:0"
"#,
    );
    config.codex.gitlab_discovery_mcp.advertise_url.clear();

    with_env_var("POD_IP", None, || {
        apply_gitlab_discovery_mcp_runtime_defaults(&mut config)
            .expect("host-gateway fallback should be applied");
    });

    assert_eq!(
        config.codex.gitlab_discovery_mcp.advertise_url,
        "http://host.docker.internal:19091/mcp"
    );
}

#[test]
fn falls_back_to_host_gateway_when_pod_ip_family_does_not_match_bind_host() {
    let mut config = load_from_yaml(
        r#"
gitlab:
  base_url: "https://gitlab.example.com"
  token: "token"
  bot_user_id: 1
  targets:
    repos:
      - "group/repo"
schedule:
  cron: "* * * * *"
  timezone: null
review:
  max_concurrent: 1
  eyes_emoji: "eyes"
  thumbs_emoji: "thumbsup"
  comment_marker_prefix: "<!-- codex-review:sha="
  stale_in_progress_minutes: 60
  dry_run: false
codex:
  image: "ghcr.io/openai/codex-universal:latest"
  timeout_seconds: 300
  auth_host_path: "/root/.codex"
  auth_mount_path: "/root/.codex"
  exec_sandbox: "danger-full-access"
  gitlab_discovery_mcp:
    enabled: true
    server_name: "gitlab-discovery"
    bind_addr: "0.0.0.0:19091"
    advertise_url: "http://10.42.0.15:19091/mcp"
    clone_root: "/work/mcp"
database:
  path: "/tmp/state.sqlite"
server:
  bind_addr: "127.0.0.1:0"
"#,
    );
    config.codex.gitlab_discovery_mcp.advertise_url.clear();

    with_env_var("POD_IP", Some("fd00::123"), || {
        apply_gitlab_discovery_mcp_runtime_defaults(&mut config)
            .expect("host-gateway fallback should be applied for address-family mismatch");
    });

    assert_eq!(
        config.codex.gitlab_discovery_mcp.advertise_url,
        "http://host.docker.internal:19091/mcp"
    );
}

#[test]
fn rejects_pod_ip_default_for_non_wildcard_bind_host() {
    let mut config = load_from_yaml(
        r#"
gitlab:
  base_url: "https://gitlab.example.com"
  token: "token"
  bot_user_id: 1
  targets:
    repos:
      - "group/repo"
schedule:
  cron: "* * * * *"
  timezone: null
review:
  max_concurrent: 1
  eyes_emoji: "eyes"
  thumbs_emoji: "thumbsup"
  comment_marker_prefix: "<!-- codex-review:sha="
  stale_in_progress_minutes: 60
  dry_run: false
codex:
  image: "ghcr.io/openai/codex-universal:latest"
  timeout_seconds: 300
  auth_host_path: "/root/.codex"
  auth_mount_path: "/root/.codex"
  exec_sandbox: "danger-full-access"
  gitlab_discovery_mcp:
    enabled: true
    server_name: "gitlab-discovery"
    bind_addr: "127.0.0.1:19091"
    advertise_url: "http://127.0.0.1:19091/mcp"
    clone_root: "/work/mcp"
database:
  path: "/tmp/state.sqlite"
server:
  bind_addr: "127.0.0.1:0"
"#,
    );
    config.codex.gitlab_discovery_mcp.advertise_url.clear();

    let err = with_env_var("POD_IP", Some("10.42.0.15"), || {
        apply_gitlab_discovery_mcp_runtime_defaults(&mut config)
            .expect_err("non-wildcard bind host should require an explicit advertise_url")
    });

    assert!(format!("{err:#}").contains("cannot default from POD_IP"));
}
