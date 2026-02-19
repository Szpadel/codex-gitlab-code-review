use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use serde::Deserialize;
use serde::de::{self, Deserializer};
use std::env;

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
    pub deps: DepsConfig,
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

impl Default for DockerConfig {
    fn default() -> Self {
        Self {
            host: default_docker_host(),
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
        Ok(config)
    }
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
}
