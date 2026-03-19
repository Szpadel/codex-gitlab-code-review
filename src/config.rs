use crate::feature_flags::{
    FeatureFlagAvailability, FeatureFlagDefaults, FeatureFlagSnapshot, RuntimeFeatureFlagOverrides,
};
use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use serde::Deserialize;
use serde::de::{self, Deserializer};
use std::collections::{BTreeMap, HashSet};
use std::env;
use url::Url;

pub const BROWSER_MCP_REMOTE_DEBUGGING_PORT: u16 = 9222;
const SUPPORTED_REASONING_EFFORTS: &[&str] = &["low", "medium", "high", "xhigh"];
const SUPPORTED_REASONING_SUMMARIES: &[&str] = &["none", "auto", "detailed"];

#[derive(Clone, Debug, Deserialize)]
pub struct Config {
    #[serde(default)]
    pub feature_flags: FeatureFlagDefaults,
    pub gitlab: GitLabConfig,
    pub schedule: ScheduleConfig,
    pub review: ReviewConfig,
    pub codex: CodexConfig,
    #[serde(default)]
    pub docker: DockerConfig,
    pub database: DatabaseConfig,
    pub server: ServerConfig,
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
    pub additional_developer_instructions: Option<String>,
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
    #[serde(default, deserialize_with = "empty_string_as_none")]
    pub session_history_path: Option<String>,
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
    pub gitlab_discovery_mcp: GitLabDiscoveryMcpConfig,
    #[serde(default)]
    pub mcp_server_overrides: McpServerOverridesConfig,
    #[serde(default)]
    pub reasoning_effort: ReasoningEffortOverridesConfig,
    #[serde(default)]
    pub reasoning_summary: ReasoningSummaryOverridesConfig,
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

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
pub struct GitLabDiscoveryMcpConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_gitlab_discovery_mcp_server_name")]
    pub server_name: String,
    #[serde(default = "default_gitlab_discovery_mcp_bind_addr")]
    pub bind_addr: String,
    #[serde(default)]
    pub advertise_url: String,
    #[serde(default = "default_gitlab_discovery_mcp_clone_root")]
    pub clone_root: String,
    #[serde(default)]
    pub allow: Vec<GitLabDiscoveryAllowRule>,
}

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq)]
pub struct GitLabDiscoveryAllowRule {
    #[serde(default)]
    pub source_repos: Vec<String>,
    #[serde(default)]
    pub source_group_prefixes: Vec<String>,
    #[serde(default)]
    pub target_repos: Vec<String>,
    #[serde(default)]
    pub target_groups: Vec<String>,
}

#[derive(Clone, Debug, Default, Deserialize)]
pub struct McpServerOverridesConfig {
    #[serde(default)]
    pub review: BTreeMap<String, bool>,
    #[serde(default)]
    pub mention: BTreeMap<String, bool>,
}

#[derive(Clone, Debug, Default, Deserialize)]
pub struct ReasoningEffortOverridesConfig {
    #[serde(default)]
    pub review: Option<String>,
    #[serde(default)]
    pub mention: Option<String>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
pub struct ReasoningSummaryOverridesConfig {
    #[serde(default = "default_reasoning_summary_override")]
    pub review: Option<String>,
    #[serde(default = "default_reasoning_summary_override")]
    pub mention: Option<String>,
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

fn default_reasoning_summary_override() -> Option<String> {
    Some("detailed".to_string())
}

fn default_gitlab_discovery_mcp_server_name() -> String {
    "gitlab-discovery".to_string()
}

fn default_gitlab_discovery_mcp_bind_addr() -> String {
    "0.0.0.0:8091".to_string()
}

fn default_gitlab_discovery_mcp_clone_root() -> String {
    "/work/mcp".to_string()
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

impl Default for GitLabDiscoveryMcpConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            server_name: default_gitlab_discovery_mcp_server_name(),
            bind_addr: default_gitlab_discovery_mcp_bind_addr(),
            advertise_url: String::new(),
            clone_root: default_gitlab_discovery_mcp_clone_root(),
            allow: Vec::new(),
        }
    }
}

impl Default for ReasoningSummaryOverridesConfig {
    fn default() -> Self {
        Self {
            review: default_reasoning_summary_override(),
            mention: default_reasoning_summary_override(),
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
    #[serde(default)]
    pub status_ui_enabled: bool,
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
        if legacy_proxy_config_present(&cfg) {
            tracing::warn!(
                "legacy proxy config detected but ignored; built-in proxy support has been removed"
            );
        }
        let mut config: Config = cfg.try_deserialize().context("deserialize config")?;
        if config.codex.auth_host_path.is_empty() {
            config.codex.auth_host_path = config.codex.auth_mount_path.clone();
        }
        if config.docker.host.trim().is_empty() {
            config.docker.host = default_docker_host();
        }
        apply_gitlab_discovery_mcp_runtime_defaults(&mut config)?;
        validate_codex_auth_accounts(&config.codex)?;
        validate_browser_mcp(&config.codex)?;
        validate_gitlab_discovery_mcp(&config.codex)?;
        validate_unique_injected_mcp_server_names(&config.codex)?;
        validate_distinct_http_and_gitlab_discovery_bind_addrs(&config)?;
        validate_mcp_server_overrides(&config.codex)?;
        validate_reasoning_effort_overrides(&config.codex)?;
        validate_reasoning_summary_overrides(&config.codex)?;
        Ok(config)
    }

    pub fn feature_flag_availability(&self) -> FeatureFlagAvailability {
        FeatureFlagAvailability {
            gitlab_discovery_mcp: self.codex.gitlab_discovery_mcp.enabled
                && !self.codex.gitlab_discovery_mcp.allow.is_empty(),
            gitlab_inline_review_comments: true,
            composer_install: true,
            composer_auto_repositories: true,
            composer_safe_install: true,
        }
    }

    pub fn resolve_feature_flags(
        &self,
        overrides: &RuntimeFeatureFlagOverrides,
    ) -> FeatureFlagSnapshot {
        FeatureFlagSnapshot::resolve(
            &self.feature_flags,
            &self.feature_flag_availability(),
            overrides,
        )
    }
}

fn apply_gitlab_discovery_mcp_runtime_defaults(config: &mut Config) -> Result<()> {
    if !config.codex.gitlab_discovery_mcp.enabled
        || !config
            .codex
            .gitlab_discovery_mcp
            .advertise_url
            .trim()
            .is_empty()
    {
        return Ok(());
    }

    let (bind_host, port) = parse_bind_addr(
        "codex.gitlab_discovery_mcp.bind_addr",
        &config.codex.gitlab_discovery_mcp.bind_addr,
    )?;
    let pod_ip = env::var("POD_IP")
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty());
    match pod_ip {
        Some(pod_ip) => {
            anyhow::ensure!(
                is_wildcard_host(&bind_host),
                "codex.gitlab_discovery_mcp.advertise_url cannot default from POD_IP when codex.gitlab_discovery_mcp.bind_addr listens on {bind_host}; use a wildcard bind_addr or set advertise_url explicitly"
            );
            let pod_ip = pod_ip
                .parse::<std::net::IpAddr>()
                .context("parse POD_IP for gitlab discovery MCP advertise_url default")?;
            if bind_host_supports_ip(&bind_host, pod_ip) {
                let host = match pod_ip {
                    std::net::IpAddr::V4(ip) => ip.to_string(),
                    std::net::IpAddr::V6(ip) => format!("[{ip}]"),
                };
                config.codex.gitlab_discovery_mcp.advertise_url =
                    format!("http://{host}:{port}/mcp");
            } else {
                config.codex.gitlab_discovery_mcp.advertise_url =
                    format!("http://host.docker.internal:{port}/mcp");
            }
        }
        None => {
            anyhow::ensure!(
                is_wildcard_host(&bind_host),
                "codex.gitlab_discovery_mcp.advertise_url cannot default to host.docker.internal when codex.gitlab_discovery_mcp.bind_addr listens on {bind_host}; use a wildcard bind_addr or set advertise_url explicitly"
            );
            config.codex.gitlab_discovery_mcp.advertise_url =
                format!("http://host.docker.internal:{port}/mcp");
        }
    }
    Ok(())
}

pub fn gitlab_discovery_mcp_uses_cluster_service_advertise_url(codex: &CodexConfig) -> bool {
    if !codex.gitlab_discovery_mcp.enabled {
        return false;
    }

    let Ok(advertise_url) = Url::parse(&codex.gitlab_discovery_mcp.advertise_url) else {
        return false;
    };
    let Some(host) = advertise_url.host_str() else {
        return false;
    };

    host.ends_with(".svc.cluster.local") || host.ends_with(".cluster.local")
}

fn empty_string_as_none<'de, D>(deserializer: D) -> Result<Option<String>, D::Error>
where
    D: Deserializer<'de>,
{
    let value = Option::<String>::deserialize(deserializer)?;
    Ok(value.and_then(|value| {
        let trimmed = value.trim();
        (!trimmed.is_empty()).then(|| trimmed.to_string())
    }))
}

fn legacy_proxy_config_present(cfg: &config::Config) -> bool {
    cfg.get_table("proxy")
        .map(|table| !table.is_empty())
        .unwrap_or(false)
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

fn validate_gitlab_discovery_mcp(codex: &CodexConfig) -> Result<()> {
    if !codex.gitlab_discovery_mcp.enabled {
        return Ok(());
    }

    let mcp = &codex.gitlab_discovery_mcp;
    anyhow::ensure!(
        !mcp.server_name.trim().is_empty(),
        "codex.gitlab_discovery_mcp.server_name must not be empty"
    );
    anyhow::ensure!(
        mcp.server_name.chars().all(|ch| !ch.is_control()),
        "codex.gitlab_discovery_mcp.server_name must not contain control characters"
    );
    anyhow::ensure!(
        is_valid_mcp_server_name(&mcp.server_name),
        "codex.gitlab_discovery_mcp.server_name must match ^[a-zA-Z0-9_-]+$"
    );
    anyhow::ensure!(
        !mcp.bind_addr.trim().is_empty(),
        "codex.gitlab_discovery_mcp.bind_addr must not be empty"
    );
    let bind_addr = Url::parse(&format!("tcp://{}", mcp.bind_addr))
        .context("parse codex.gitlab_discovery_mcp.bind_addr")?;
    anyhow::ensure!(
        bind_addr.port().is_some_and(|port| port != 0),
        "codex.gitlab_discovery_mcp.bind_addr must include a non-zero port"
    );
    anyhow::ensure!(
        !mcp.advertise_url.trim().is_empty(),
        "codex.gitlab_discovery_mcp.advertise_url must not be empty"
    );
    let advertise_url =
        Url::parse(&mcp.advertise_url).context("parse codex.gitlab_discovery_mcp.advertise_url")?;
    anyhow::ensure!(
        matches!(advertise_url.scheme(), "http" | "https"),
        "codex.gitlab_discovery_mcp.advertise_url must use http or https"
    );
    advertise_url
        .host_str()
        .context("parse codex.gitlab_discovery_mcp.advertise_url host")?;
    anyhow::ensure!(
        !mcp.clone_root.trim().is_empty(),
        "codex.gitlab_discovery_mcp.clone_root must not be empty"
    );
    anyhow::ensure!(
        mcp.clone_root.starts_with('/'),
        "codex.gitlab_discovery_mcp.clone_root must be an absolute path"
    );
    for (index, rule) in mcp.allow.iter().enumerate() {
        let rule_name = format!("codex.gitlab_discovery_mcp.allow[{index}]");
        anyhow::ensure!(
            !(rule.source_repos.is_empty() && rule.source_group_prefixes.is_empty()),
            "{rule_name} must include at least one source_repos or source_group_prefixes entry"
        );
        anyhow::ensure!(
            !(rule.target_repos.is_empty() && rule.target_groups.is_empty()),
            "{rule_name} must include at least one target_repos or target_groups entry"
        );

        for (field, values) in [
            ("source_repos", &rule.source_repos),
            ("source_group_prefixes", &rule.source_group_prefixes),
            ("target_repos", &rule.target_repos),
            ("target_groups", &rule.target_groups),
        ] {
            for value in values {
                anyhow::ensure!(
                    !value.trim().is_empty(),
                    "{rule_name}.{field} values must not be empty"
                );
                anyhow::ensure!(
                    value.chars().all(|ch| !ch.is_control()),
                    "{rule_name}.{field} values must not contain control characters"
                );
            }
        }
    }

    Ok(())
}

fn validate_unique_injected_mcp_server_names(codex: &CodexConfig) -> Result<()> {
    if codex.browser_mcp.enabled
        && codex.gitlab_discovery_mcp.enabled
        && codex.browser_mcp.server_name == codex.gitlab_discovery_mcp.server_name
    {
        anyhow::bail!(
            "codex.browser_mcp.server_name and codex.gitlab_discovery_mcp.server_name must be distinct when both MCP injectors are enabled"
        );
    }

    Ok(())
}

fn validate_distinct_http_and_gitlab_discovery_bind_addrs(config: &Config) -> Result<()> {
    if !config.codex.gitlab_discovery_mcp.enabled {
        return Ok(());
    }

    let (http_host, http_port) = parse_bind_addr("server.bind_addr", &config.server.bind_addr)?;
    let (mcp_host, mcp_port) = parse_bind_addr(
        "codex.gitlab_discovery_mcp.bind_addr",
        &config.codex.gitlab_discovery_mcp.bind_addr,
    )?;
    if http_port == mcp_port
        && (http_host == mcp_host || is_wildcard_host(&http_host) || is_wildcard_host(&mcp_host))
    {
        anyhow::bail!(
            "server.bind_addr and codex.gitlab_discovery_mcp.bind_addr must not target the same listener socket"
        );
    }

    Ok(())
}

fn parse_bind_addr(field: &str, value: &str) -> Result<(String, u16)> {
    let url = Url::parse(&format!("tcp://{value}")).with_context(|| format!("parse {field}"))?;
    let host = url
        .host_str()
        .map(ToOwned::to_owned)
        .with_context(|| format!("{field} must include a host"))?;
    let port = url
        .port()
        .with_context(|| format!("{field} must include a port"))?;
    Ok((host, port))
}

fn is_wildcard_host(host: &str) -> bool {
    matches!(host, "0.0.0.0" | "::" | "[::]" | "0:0:0:0:0:0:0:0")
}

fn bind_host_supports_ip(bind_host: &str, ip: std::net::IpAddr) -> bool {
    match ip {
        std::net::IpAddr::V4(_) => bind_host == "0.0.0.0",
        std::net::IpAddr::V6(_) => matches!(bind_host, "::" | "[::]" | "0:0:0:0:0:0:0:0"),
    }
}

fn validate_reasoning_effort_overrides(codex: &CodexConfig) -> Result<()> {
    for (field, value) in [
        ("review", codex.reasoning_effort.review.as_deref()),
        ("mention", codex.reasoning_effort.mention.as_deref()),
    ] {
        let Some(value) = value else {
            continue;
        };
        anyhow::ensure!(
            !value.trim().is_empty(),
            "codex.reasoning_effort.{field} must not be empty"
        );
        anyhow::ensure!(
            value.chars().all(|ch| !ch.is_control()),
            "codex.reasoning_effort.{field} must not contain control characters"
        );
        anyhow::ensure!(
            SUPPORTED_REASONING_EFFORTS.contains(&value),
            "codex.reasoning_effort.{field} must be one of: {}",
            SUPPORTED_REASONING_EFFORTS.join(", ")
        );
    }
    Ok(())
}

fn validate_reasoning_summary_overrides(codex: &CodexConfig) -> Result<()> {
    for (field, value) in [
        ("review", codex.reasoning_summary.review.as_deref()),
        ("mention", codex.reasoning_summary.mention.as_deref()),
    ] {
        let Some(value) = value else {
            continue;
        };
        anyhow::ensure!(
            !value.trim().is_empty(),
            "codex.reasoning_summary.{field} must not be empty"
        );
        anyhow::ensure!(
            value.chars().all(|ch| !ch.is_control()),
            "codex.reasoning_summary.{field} must not contain control characters"
        );
        anyhow::ensure!(
            SUPPORTED_REASONING_SUMMARIES.contains(&value),
            "codex.reasoning_summary.{field} must be one of: {}",
            SUPPORTED_REASONING_SUMMARIES.join(", ")
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
        assert!(
            msg.contains("codex.reasoning_summary.mention must be one of: none, auto, detailed")
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
}
