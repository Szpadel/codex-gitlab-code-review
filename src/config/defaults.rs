use super::{
    BROWSER_MCP_REMOTE_DEBUGGING_PORT, BrowserMcpConfig, DockerConfig, GitLabDiscoveryMcpConfig,
    GitLabTargets, ReasoningSummaryOverridesConfig, ReviewSecurityConfig,
    SessionModeOverrideConfig, SessionOverridesConfig, TargetSelector,
};

pub(super) fn default_refresh_seconds() -> u64 {
    3600
}

pub(crate) fn default_docker_host() -> String {
    "unix:///var/run/docker.sock".to_string()
}

pub(super) fn default_usage_limit_fallback_cooldown_seconds() -> u64 {
    3600
}

pub(super) fn default_review_rate_limit_emoji() -> String {
    "hourglass_flowing_sand".to_string()
}

pub(super) fn default_browser_mcp_server_name() -> String {
    "chrome-devtools".to_string()
}

pub(super) fn default_browser_mcp_image() -> String {
    "chromedp/headless-shell:latest".to_string()
}

pub(super) fn default_browser_mcp_remote_debugging_port() -> u16 {
    BROWSER_MCP_REMOTE_DEBUGGING_PORT
}

pub(super) fn default_browser_mcp_command() -> String {
    "npx".to_string()
}

pub(super) fn default_browser_mcp_args() -> Vec<String> {
    vec!["-y".to_string(), "chrome-devtools-mcp@latest".to_string()]
}

pub(super) fn default_reasoning_summary_override() -> Option<String> {
    default_optional_text("detailed")
}

pub(super) fn default_security_context_session_override() -> SessionModeOverrideConfig {
    SessionModeOverrideConfig {
        model: None,
        reasoning_effort: default_security_context_reasoning_effort_override(),
    }
}

pub(super) fn default_security_review_session_override() -> SessionModeOverrideConfig {
    SessionModeOverrideConfig {
        model: None,
        reasoning_effort: default_security_review_reasoning_effort_override(),
    }
}

fn default_security_context_reasoning_effort_override() -> Option<String> {
    default_optional_text("xhigh")
}

fn default_security_review_reasoning_effort_override() -> Option<String> {
    default_optional_text("high")
}

fn default_optional_text(value: &'static str) -> Option<String> {
    (!value.is_empty()).then(|| value.to_string())
}

pub(super) fn default_gitlab_discovery_mcp_server_name() -> String {
    "gitlab-discovery".to_string()
}

pub(super) fn default_security_review_context_ttl_seconds() -> u64 {
    1_209_600
}

pub(super) fn default_security_review_min_confidence_score() -> f32 {
    0.85
}

pub(super) fn default_security_review_comment_marker_prefix() -> String {
    "<!-- codex-security-review:sha=".to_string()
}

pub(super) fn default_security_review_finding_marker_prefix() -> String {
    "<!-- codex-security-review-finding:sha=".to_string()
}

pub(super) fn default_gitlab_discovery_mcp_bind_addr() -> String {
    "0.0.0.0:8091".to_string()
}

pub(super) fn default_gitlab_discovery_mcp_clone_root() -> String {
    "/work/mcp".to_string()
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
        Self::List(Vec::new())
    }
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

impl Default for SessionOverridesConfig {
    fn default() -> Self {
        Self {
            review: SessionModeOverrideConfig::default(),
            mention: SessionModeOverrideConfig::default(),
            security_context: default_security_context_session_override(),
            security_review: default_security_review_session_override(),
        }
    }
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
