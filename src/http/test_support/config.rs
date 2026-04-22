use crate::config::{
    BrowserMcpConfig, CodexConfig, Config, DatabaseConfig, DockerConfig, GitLabConfig,
    GitLabTargets, McpServerOverridesConfig, ReasoningSummaryOverridesConfig, ReviewConfig,
    ReviewMentionCommandsConfig, ScheduleConfig, ServerConfig, SessionOverridesConfig,
    TargetSelector,
};

pub(crate) fn test_config() -> Config {
    Config {
        feature_flags: crate::feature_flags::FeatureFlagDefaults::default(),
        gitlab: GitLabConfig {
            base_url: "https://gitlab.example.com".to_string(),
            token: String::new(),
            bot_user_id: Some(123),
            created_after: None,
            targets: GitLabTargets {
                repos: TargetSelector::List(vec!["group/repo".to_string()]),
                groups: TargetSelector::List(vec![]),
                exclude_repos: vec![],
                exclude_groups: vec![],
                refresh_seconds: 3600,
            },
        },
        schedule: ScheduleConfig {
            cron: "0 */10 * * * *".to_string(),
            timezone: Some("UTC".to_string()),
        },
        review: ReviewConfig {
            max_concurrent: 2,
            eyes_emoji: "eyes".to_string(),
            thumbs_emoji: "thumbsup".to_string(),
            rate_limit_emoji: "hourglass_flowing_sand".to_string(),
            comment_marker_prefix: "<!-- codex-review:sha=".to_string(),
            stale_in_progress_minutes: 120,
            dry_run: true,
            additional_developer_instructions: None,
            security: crate::config::ReviewSecurityConfig::default(),
            mention_commands: ReviewMentionCommandsConfig {
                enabled: true,
                bot_username: Some("codex".to_string()),
                eyes_emoji: None,
                additional_developer_instructions: None,
            },
        },
        codex: CodexConfig {
            image: "ghcr.io/openai/codex-universal:latest".to_string(),
            timeout_seconds: 1800,
            auth_host_path: "/tmp/codex".to_string(),
            auth_mount_path: "/root/.codex".to_string(),
            session_history_path: None,
            exec_sandbox: "danger-full-access".to_string(),
            fallback_auth_accounts: vec![],
            usage_limit_fallback_cooldown_seconds: 3600,
            deps: Default::default(),
            browser_mcp: BrowserMcpConfig::default(),
            work_tmpfs: crate::config::WorkTmpfsConfig::default(),
            gitlab_discovery_mcp: crate::config::GitLabDiscoveryMcpConfig::default(),
            mcp_server_overrides: McpServerOverridesConfig::default(),
            session_overrides: SessionOverridesConfig::default(),
            reasoning_summary: ReasoningSummaryOverridesConfig::default(),
        },
        docker: DockerConfig {
            host: "unix:///var/run/docker.sock".to_string(),
        },
        database: DatabaseConfig {
            path: ":memory:".to_string(),
        },
        server: ServerConfig {
            bind_addr: "127.0.0.1:0".to_string(),
            status_ui_enabled: true,
        },
    }
}
