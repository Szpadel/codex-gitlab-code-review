use crate::feature_flags::{
    FeatureFlagAvailability, FeatureFlagDefaults, FeatureFlagSnapshot, RuntimeFeatureFlagOverrides,
};
use chrono::{DateTime, Utc};
use serde::Deserialize;
use serde::de::{self, Deserializer};
use std::collections::BTreeMap;

pub const BROWSER_MCP_REMOTE_DEBUGGING_PORT: u16 = 9222;

pub(crate) mod defaults;
mod load;
mod validate;

use self::defaults::{
    default_browser_mcp_args, default_browser_mcp_command, default_browser_mcp_image,
    default_browser_mcp_remote_debugging_port, default_browser_mcp_server_name,
    default_docker_host, default_gitlab_discovery_mcp_bind_addr,
    default_gitlab_discovery_mcp_clone_root, default_gitlab_discovery_mcp_server_name,
    default_reasoning_summary_override, default_refresh_seconds, default_review_rate_limit_emoji,
    default_security_context_session_override, default_security_review_comment_marker_prefix,
    default_security_review_context_ttl_seconds, default_security_review_finding_marker_prefix,
    default_security_review_min_confidence_score, default_security_review_session_override,
    default_usage_limit_fallback_cooldown_seconds,
};
use self::load::{
    deserialize_security_context_session_override, deserialize_security_review_session_override,
    empty_string_as_none,
};

#[cfg(test)]
pub(crate) use self::load::legacy_proxy_config_present;
pub use self::load::load_raw_config;
#[cfg(test)]
pub(crate) use self::validate::apply_gitlab_discovery_mcp_runtime_defaults;
pub use self::validate::{
    ValidatedConfig, gitlab_discovery_mcp_uses_cluster_service_advertise_url, validate_config,
};

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

impl TargetSelector {
    #[must_use]
    pub fn is_all(&self) -> bool {
        matches!(self, Self::All)
    }

    #[must_use]
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
                        "expected \"all\" or list, got \"{value}\""
                    )))
                }
            }
            RawSelector::List(items) => Ok(TargetSelector::List(items)),
            RawSelector::None(()) => Ok(TargetSelector::default()),
        }
    }
}

impl GitLabTargets {
    #[must_use]
    pub fn cache_key_for_all(&self) -> String {
        "all".to_string()
    }

    #[must_use]
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
    pub work_tmpfs: WorkTmpfsConfig,
    #[serde(default)]
    pub gitlab_discovery_mcp: GitLabDiscoveryMcpConfig,
    #[serde(default)]
    pub mcp_server_overrides: McpServerOverridesConfig,
    #[serde(default)]
    pub session_overrides: SessionOverridesConfig,
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

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq)]
pub struct WorkTmpfsConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub size_mib: Option<u64>,
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
pub struct SessionModeOverrideConfig {
    #[serde(default)]
    pub model: Option<String>,
    #[serde(default)]
    pub reasoning_effort: Option<String>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct SessionOverridesConfig {
    #[serde(default)]
    pub review: SessionModeOverrideConfig,
    #[serde(default)]
    pub mention: SessionModeOverrideConfig,
    #[serde(
        default = "default_security_context_session_override",
        deserialize_with = "deserialize_security_context_session_override"
    )]
    pub security_context: SessionModeOverrideConfig,
    #[serde(
        default = "default_security_review_session_override",
        deserialize_with = "deserialize_security_review_session_override"
    )]
    pub security_review: SessionModeOverrideConfig,
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
    #[must_use]
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

    #[must_use]
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

#[cfg(test)]
mod tests;
