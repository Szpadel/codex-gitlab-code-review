use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use serde::Deserialize;
use serde::de::{self, Deserializer};
use std::collections::{BTreeMap, HashSet};
use std::env;

pub const BROWSER_MCP_REMOTE_DEBUGGING_PORT: u16 = 9222;

#[derive(Clone, Debug, Deserialize)]
pub struct Config {
    pub gitlab: GitLabConfig,
    pub schedule: ScheduleConfig,
    pub review: ReviewConfig,
    pub codex: CodexConfig,
    #[serde(default)]
    pub docker: DockerConfig,
    pub database: DatabaseConfig,
    pub server: ServerConfig,
    #[serde(default)]
    pub proxy: ProxyConfig,
}

#[derive(Clone, Debug, Deserialize)]
pub struct GitLabConfig {
    pub base_url: String,
    pub token: String,
    pub bot_user_id: Option<u64>,
    #[serde(default)]
    pub created_after: Option<DateTime<Utc>>,
    #[serde(default)]
    pub targets: GitLabTargets,
}

#[derive(Clone, Debug, Deserialize)]
pub struct GitLabTargets {
    #[serde(default)]
    pub repos: TargetSelector,
    #[serde(default)]
    pub groups: TargetSelector,
    #[serde(default)]
    pub exclude_repos: Vec<String>,
    #[serde(default)]
    pub exclude_groups: Vec<String>,
    #[serde(default = "default_refresh_seconds")]
    pub refresh_seconds: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TargetSelector {
    All,
    List(Vec<String>),
}

impl Default for GitLabTargets {
    fn default() -> Self {
        Self {
            repos: TargetSelector::default(),
            groups: TargetSelector::default(),
            exclude_repos: Vec::new(),
            exclude_groups: Vec::new(),
            refresh_seconds: default_refresh_seconds(),
        }
    }
}

impl Default for TargetSelector {
    fn default() -> Self {
        TargetSelector::List(Vec::new())
    }
}

impl TargetSelector {
    pub fn is_all(&self) -> bool {
        matches!(self, Self::All)
    }

    pub fn list(&self) -> &[String] {
        match self {
            Self::All => &[],
            Self::List(items) => items,
        }
    }
}

impl<'de> Deserialize<'de> for TargetSelector {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum RawSelector {
            String(String),
            List(Vec<String>),
            None(()),
        }

        match RawSelector::deserialize(deserializer)? {
            RawSelector::String(value) => {
                if value == "all" {
                    Ok(TargetSelector::All)
                } else {
                    Err(de::Error::custom(format!(
                        "expected \"all\" or list, got \"{}\"",
                        value
                    )))
                }
            }
            RawSelector::List(items) => Ok(TargetSelector::List(items)),
            RawSelector::None(()) => Ok(TargetSelector::default()),
        }
    }
}

impl GitLabTargets {
    pub fn cache_key_for_all(&self) -> String {
        "all".to_string()
    }

    pub fn cache_key_for_groups(&self) -> String {
        let mut groups = self.groups.list().to_vec();
        groups.sort();
        format!("groups={}", groups.join(","))
    }
}

#[derive(Clone, Debug, Deserialize)]
pub struct ScheduleConfig {
    pub cron: String,
    pub timezone: Option<String>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct ReviewConfig {
    pub max_concurrent: usize,
    pub eyes_emoji: String,
    pub thumbs_emoji: String,
    pub comment_marker_prefix: String,
    pub stale_in_progress_minutes: u64,
    #[serde(default)]
    pub dry_run: bool,
    #[serde(default)]
    pub mention_commands: ReviewMentionCommandsConfig,
}

#[derive(Clone, Debug, Default, Deserialize)]
pub struct ReviewMentionCommandsConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub bot_username: Option<String>,
    #[serde(default)]
    pub eyes_emoji: Option<String>,
    #[serde(default)]
    pub additional_developer_instructions: Option<String>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct CodexConfig {
    pub image: String,
    pub timeout_seconds: u64,
    #[serde(default)]
    pub auth_host_path: String,
    pub auth_mount_path: String,
    pub exec_sandbox: String,
    #[serde(default)]
    pub fallback_auth_accounts: Vec<FallbackAuthAccountConfig>,
    #[serde(default = "default_usage_limit_fallback_cooldown_seconds")]
    pub usage_limit_fallback_cooldown_seconds: u64,
    #[serde(default)]
    pub deps: DepsConfig,
    #[serde(default)]
    pub browser_mcp: BrowserMcpConfig,
    #[serde(default)]
    pub mcp_server_overrides: McpServerOverridesConfig,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
pub struct BrowserMcpConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_browser_mcp_server_name")]
    pub server_name: String,
    #[serde(default = "default_browser_mcp_image")]
    pub browser_image: String,
    #[serde(default)]
    pub browser_entrypoint: Vec<String>,
    #[serde(default = "default_browser_mcp_remote_debugging_port")]
    pub remote_debugging_port: u16,
    #[serde(default)]
    pub browser_args: Vec<String>,
    #[serde(default = "default_browser_mcp_command")]
    pub mcp_command: String,
    #[serde(default = "default_browser_mcp_args")]
    pub mcp_args: Vec<String>,
}

#[derive(Clone, Debug, Default, Deserialize)]
pub struct McpServerOverridesConfig {
    #[serde(default)]
    pub review: BTreeMap<String, bool>,
    #[serde(default)]
    pub mention: BTreeMap<String, bool>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct FallbackAuthAccountConfig {
    pub name: String,
    pub auth_host_path: String,
}

#[derive(Clone, Debug, Deserialize)]
pub struct DockerConfig {
    #[serde(default = "default_docker_host")]
    pub host: String,
}

fn default_refresh_seconds() -> u64 {
    3600
}

fn default_docker_host() -> String {
    "unix:///var/run/docker.sock".to_string()
}

fn default_usage_limit_fallback_cooldown_seconds() -> u64 {
    3600
}

fn default_browser_mcp_server_name() -> String {
    "chrome-devtools".to_string()
}

fn default_browser_mcp_image() -> String {
    "chromedp/headless-shell:latest".to_string()
}

fn default_browser_mcp_remote_debugging_port() -> u16 {
    BROWSER_MCP_REMOTE_DEBUGGING_PORT
}

fn default_browser_mcp_command() -> String {
    "npx".to_string()
}

fn default_browser_mcp_args() -> Vec<String> {
    vec!["-y".to_string(), "chrome-devtools-mcp@latest".to_string()]
}

impl Default for DockerConfig {
    fn default() -> Self {
        Self {
            host: default_docker_host(),
        }
    }
}

impl Default for BrowserMcpConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            server_name: default_browser_mcp_server_name(),
            browser_image: default_browser_mcp_image(),
            browser_entrypoint: Vec::new(),
            remote_debugging_port: default_browser_mcp_remote_debugging_port(),
            browser_args: Vec::new(),
            mcp_command: default_browser_mcp_command(),
            mcp_args: default_browser_mcp_args(),
        }
    }
}

#[derive(Clone, Debug, Deserialize)]
pub struct DatabaseConfig {
    pub path: String,
}

#[derive(Clone, Debug, Deserialize)]
pub struct ServerConfig {
    pub bind_addr: String,
}

#[derive(Clone, Debug, Default, Deserialize)]
pub struct ProxyConfig {
    pub http_proxy: Option<String>,
    pub https_proxy: Option<String>,
    pub no_proxy: Option<String>,
}

#[derive(Clone, Debug, Default, Deserialize)]
pub struct DepsConfig {
    #[serde(default)]
    pub enabled: bool,
}

impl Config {
    pub fn load() -> Result<Self> {
        let path = env::var("CONFIG_PATH").unwrap_or_else(|_| "config.yaml".to_string());
        let builder = config::Config::builder()
            .add_source(config::File::with_name(&path))
            .add_source(config::Environment::with_prefix("CODEX_REVIEW").separator("__"));
        let cfg = builder
            .build()
            .with_context(|| format!("load config from {}", path))?;
        let mut config: Config = cfg.try_deserialize().context("deserialize config")?;
        if config.codex.auth_host_path.is_empty() {
            config.codex.auth_host_path = config.codex.auth_mount_path.clone();
        }
        if config.docker.host.trim().is_empty() {
            config.docker.host = default_docker_host();
        }
        validate_codex_auth_accounts(&config.codex)?;
        validate_browser_mcp(&config.codex)?;
        validate_mcp_server_overrides(&config.codex)?;
        Ok(config)
    }
}

fn validate_codex_auth_accounts(codex: &CodexConfig) -> Result<()> {
    anyhow::ensure!(
        !codex.auth_host_path.trim().is_empty(),
        "codex.auth_host_path must not be empty"
    );

    let mut names = HashSet::new();
    let mut host_paths = HashSet::new();
    host_paths.insert(codex.auth_host_path.as_str());

    for account in &codex.fallback_auth_accounts {
        anyhow::ensure!(
            !account.name.trim().is_empty(),
            "codex.fallback_auth_accounts[].name must not be empty"
        );
        anyhow::ensure!(
            account.name != "primary",
            "codex.fallback_auth_accounts[].name 'primary' is reserved"
        );
        anyhow::ensure!(
            !account.auth_host_path.trim().is_empty(),
            "codex.fallback_auth_accounts[].auth_host_path must not be empty"
        );
        anyhow::ensure!(
            names.insert(account.name.as_str()),
            "duplicate codex fallback account name: {}",
            account.name
        );
        anyhow::ensure!(
            host_paths.insert(account.auth_host_path.as_str()),
            "duplicate codex auth_host_path across primary/fallback accounts: {}",
            account.auth_host_path
        );
    }

    Ok(())
}

fn validate_mcp_server_overrides(codex: &CodexConfig) -> Result<()> {
    for server in codex
        .mcp_server_overrides
        .review
        .keys()
        .chain(codex.mcp_server_overrides.mention.keys())
    {
        anyhow::ensure!(
            !server.trim().is_empty(),
            "codex.mcp_server_overrides keys must not be empty"
        );
        anyhow::ensure!(
            is_valid_mcp_server_name(server),
            "codex.mcp_server_overrides keys must match ^[a-zA-Z0-9_-]+$"
        );
    }
    Ok(())
}

fn validate_browser_mcp(codex: &CodexConfig) -> Result<()> {
    if !codex.browser_mcp.enabled {
        return Ok(());
    }

    anyhow::ensure!(
        !codex.browser_mcp.server_name.trim().is_empty(),
        "codex.browser_mcp.server_name must not be empty"
    );
    anyhow::ensure!(
        codex
            .browser_mcp
            .server_name
            .chars()
            .all(|ch| !ch.is_control()),
        "codex.browser_mcp.server_name must not contain control characters"
    );
    anyhow::ensure!(
        is_valid_mcp_server_name(&codex.browser_mcp.server_name),
        "codex.browser_mcp.server_name must match ^[a-zA-Z0-9_-]+$"
    );
    anyhow::ensure!(
        !codex.browser_mcp.browser_image.trim().is_empty(),
        "codex.browser_mcp.browser_image must not be empty"
    );
    anyhow::ensure!(
        !codex.browser_mcp.mcp_command.trim().is_empty(),
        "codex.browser_mcp.mcp_command must not be empty"
    );
    anyhow::ensure!(
        codex.browser_mcp.remote_debugging_port == BROWSER_MCP_REMOTE_DEBUGGING_PORT,
        "codex.browser_mcp.remote_debugging_port must be {}",
        BROWSER_MCP_REMOTE_DEBUGGING_PORT
    );
    for arg in &codex.browser_mcp.browser_args {
        let trimmed = arg.trim();
        anyhow::ensure!(
            trimmed != "--remote-debugging-port"
                && !trimmed.starts_with("--remote-debugging-port="),
            "codex.browser_mcp.browser_args must not override --remote-debugging-port"
        );
        anyhow::ensure!(
            trimmed != "--remote-debugging-address"
                && !trimmed.starts_with("--remote-debugging-address="),
            "codex.browser_mcp.browser_args must not override --remote-debugging-address"
        );
    }

    Ok(())
}

fn is_valid_mcp_server_name(name: &str) -> bool {
    // Codex CLI `-c key=value` overrides split nested config paths on `.`, so
    // names that require quoted TOML dotted-key segments cannot be targeted by
    // our runtime override path. Codex itself also rejects MCP server names
    // outside this upstream pattern during MCP startup.
    !name.is_empty()
        && name
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '_' | '-'))
}

#[cfg(test)]
mod tests {
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
    fn defaults_proxy_when_missing() {
        let yaml = base_config_yaml("");
        let config = load_from_yaml(&yaml);
        assert_eq!(config.proxy.http_proxy, None);
        assert_eq!(config.proxy.https_proxy, None);
        assert_eq!(config.proxy.no_proxy, None);
    }

    #[test]
    fn defaults_mention_commands_when_missing() {
        let yaml = base_config_yaml("");
        let config = load_from_yaml(&yaml);
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
        assert_eq!(config.codex.browser_mcp, BrowserMcpConfig::default());
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
}
