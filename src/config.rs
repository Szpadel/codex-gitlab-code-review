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
    #[serde(default = "default_review_rate_limit_emoji")]
    pub rate_limit_emoji: String,
    pub comment_marker_prefix: String,
    pub stale_in_progress_minutes: u64,
    #[serde(default)]
    pub dry_run: bool,
    #[serde(default)]
    pub additional_developer_instructions: Option<String>,
    #[serde(default)]
    pub security: ReviewSecurityConfig,
    #[serde(default)]
    pub mention_commands: ReviewMentionCommandsConfig,
}

#[derive(Clone, Debug, Deserialize, PartialEq)]
pub struct ReviewSecurityConfig {
    #[serde(default = "default_security_review_context_ttl_seconds")]
    pub context_ttl_seconds: u64,
    #[serde(default = "default_security_review_min_confidence_score")]
    pub min_confidence_score: f32,
    #[serde(default = "default_security_review_comment_marker_prefix")]
    pub comment_marker_prefix: String,
    #[serde(default = "default_security_review_finding_marker_prefix")]
    pub finding_marker_prefix: String,
    #[serde(default)]
    pub additional_developer_instructions: Option<String>,
}

impl Default for ReviewSecurityConfig {
    fn default() -> Self {
        Self {
            context_ttl_seconds: default_security_review_context_ttl_seconds(),
            min_confidence_score: default_security_review_min_confidence_score(),
            comment_marker_prefix: default_security_review_comment_marker_prefix(),
            finding_marker_prefix: default_security_review_finding_marker_prefix(),
            additional_developer_instructions: None,
        }
    }
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

#[derive(Clone, Debug, Deserialize)]
pub struct ReasoningEffortOverridesConfig {
    #[serde(default)]
    pub review: Option<String>,
    #[serde(default)]
    pub mention: Option<String>,
    #[serde(default = "default_security_context_reasoning_effort_override")]
    pub security_context: Option<String>,
    #[serde(default = "default_security_review_reasoning_effort_override")]
    pub security_review: Option<String>,
}

impl Default for ReasoningEffortOverridesConfig {
    fn default() -> Self {
        Self {
            review: None,
            mention: None,
            security_context: default_security_context_reasoning_effort_override(),
            security_review: default_security_review_reasoning_effort_override(),
        }
    }
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

fn default_review_rate_limit_emoji() -> String {
    "hourglass_flowing_sand".to_string()
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

fn default_security_context_reasoning_effort_override() -> Option<String> {
    Some("xhigh".to_string())
}

fn default_security_review_reasoning_effort_override() -> Option<String> {
    Some("high".to_string())
}

fn default_gitlab_discovery_mcp_server_name() -> String {
    "gitlab-discovery".to_string()
}

fn default_security_review_context_ttl_seconds() -> u64 {
    1_209_600
}

fn default_security_review_min_confidence_score() -> f32 {
    0.85
}

fn default_security_review_comment_marker_prefix() -> String {
    "<!-- codex-security-review:sha=".to_string()
}

fn default_security_review_finding_marker_prefix() -> String {
    "<!-- codex-security-review-finding:sha=".to_string()
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
            security_review: true,
            security_context_ignore_base_head: true,
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
        (
            "security_context",
            codex.reasoning_effort.security_context.as_deref(),
        ),
        (
            "security_review",
            codex.reasoning_effort.security_review.as_deref(),
        ),
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
mod tests;
