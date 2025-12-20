use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use serde::Deserialize;
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
    pub mode: GitLabTargetMode,
    #[serde(default)]
    pub repos: Vec<String>,
    #[serde(default)]
    pub groups: Vec<String>,
    #[serde(default = "default_refresh_seconds")]
    pub refresh_seconds: u64,
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum GitLabTargetMode {
    Repos,
    Groups,
    All,
}

impl Default for GitLabTargets {
    fn default() -> Self {
        Self {
            mode: GitLabTargetMode::Repos,
            repos: Vec::new(),
            groups: Vec::new(),
            refresh_seconds: default_refresh_seconds(),
        }
    }
}

impl Default for GitLabTargetMode {
    fn default() -> Self {
        GitLabTargetMode::Repos
    }
}

impl GitLabTargetMode {
    pub fn as_str(self) -> &'static str {
        match self {
            GitLabTargetMode::Repos => "repos",
            GitLabTargetMode::Groups => "groups",
            GitLabTargetMode::All => "all",
        }
    }
}

impl GitLabTargets {
    pub fn cache_key(&self) -> String {
        let mut repos = self.repos.clone();
        repos.sort();
        let mut groups = self.groups.clone();
        groups.sort();
        format!(
            "mode={};repos={};groups={}",
            self.mode.as_str(),
            repos.join(","),
            groups.join(",")
        )
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
}

#[derive(Clone, Debug, Deserialize)]
pub struct CodexConfig {
    pub image: String,
    pub timeout_seconds: u64,
    #[serde(default)]
    pub auth_host_path: String,
    pub auth_mount_path: String,
    pub exec_sandbox: String,
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

impl Config {
    pub fn load() -> Result<Self> {
        let path = env::var("CONFIG_PATH").unwrap_or_else(|_| "config.yaml".to_string());
        let builder = config::Config::builder()
            .add_source(config::File::with_name(&path))
            .add_source(config::Environment::with_prefix("CODEX_REVIEW").separator("__"));
        let cfg = builder
            .build()
            .with_context(|| format!("load config from {}", path))?;
        let mut config: Config = cfg
            .try_deserialize()
            .context("deserialize config")?;
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

    fn load_from_yaml(contents: &str) -> Config {
        let _lock = ENV_LOCK.lock().expect("lock env");
        let path = write_temp_config(contents);
        let previous = env::var("CONFIG_PATH").ok();
        unsafe {
            env::set_var("CONFIG_PATH", &path);
        }
        let loaded = Config::load().expect("load config");
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

    fn base_config_yaml(extra: &str) -> String {
        format!(
            r#"
gitlab:
  base_url: "https://gitlab.example.com"
  token: "token"
  bot_user_id: 1
  targets:
    mode: repos
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
}
