use super::{
    BrowserMcpConfig, CodexConfig, Config, DatabaseConfig, DepsConfig, DockerConfig,
    FeatureFlagDefaults, GitLabConfig, GitLabDiscoveryMcpConfig, GitLabTargets,
    McpServerOverridesConfig, ReasoningSummaryOverridesConfig, ReviewConfig,
    ReviewMentionCommandsConfig, ReviewSecurityConfig, ScheduleConfig, ServerConfig,
    SessionOverridesConfig, TargetSelector, WorkTmpfsConfig,
};

pub(crate) struct ConfigBuilder {
    config: Config,
}

impl ConfigBuilder {
    pub(crate) fn for_http_tests() -> Self {
        Self::base()
            .gitlab_bot_user_id(Some(123))
            .review_mention_commands(ReviewMentionCommandsConfig {
                enabled: true,
                bot_username: Some("codex".to_string()),
                eyes_emoji: None,
                additional_developer_instructions: None,
            })
            .server_status_ui_enabled(true)
    }

    pub(crate) fn for_review_tests() -> Self {
        Self::review_base().docker_host("tcp://localhost:2375")
    }

    pub(crate) fn for_review_service_tests() -> Self {
        Self::review_base()
    }

    pub(crate) fn for_service_factory_tests() -> Self {
        Self::base()
    }

    pub(crate) fn for_scheduler_tests() -> Self {
        Self::base()
    }

    pub(crate) fn for_status_tests() -> Self {
        Self::base().server_status_ui_enabled(true)
    }

    pub(crate) fn build(self) -> Config {
        self.config
    }

    fn base() -> Self {
        Self {
            config: Config {
                feature_flags: FeatureFlagDefaults::default(),
                gitlab: GitLabConfig {
                    base_url: "https://gitlab.example.com".to_string(),
                    token: String::new(),
                    bot_user_id: Some(1),
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
                    quota_emoji: "fuelpump".to_string(),
                    comment_marker_prefix: "<!-- codex-review:sha=".to_string(),
                    stale_in_progress_minutes: 120,
                    dry_run: true,
                    additional_developer_instructions: None,
                    security: ReviewSecurityConfig::default(),
                    mention_commands: ReviewMentionCommandsConfig {
                        enabled: false,
                        bot_username: None,
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
                    usage_limit_recheck_seconds: 900,
                    deps: DepsConfig::default(),
                    browser_mcp: BrowserMcpConfig::default(),
                    work_tmpfs: WorkTmpfsConfig::default(),
                    gitlab_discovery_mcp: GitLabDiscoveryMcpConfig::default(),
                    mcp_server_overrides: McpServerOverridesConfig::default(),
                    session_overrides: SessionOverridesConfig::default(),
                    reasoning_summary: ReasoningSummaryOverridesConfig::default(),
                },
                docker: DockerConfig::default(),
                database: DatabaseConfig {
                    path: ":memory:".to_string(),
                },
                server: ServerConfig {
                    bind_addr: "127.0.0.1:0".to_string(),
                    status_ui_enabled: false,
                },
            },
        }
    }

    fn review_base() -> Self {
        Self::base()
            .gitlab_token("token")
            .schedule_cron("* * * * *")
            .schedule_timezone(None)
            .review_max_concurrent(1)
            .review_stale_in_progress_minutes(60)
            .review_dry_run(false)
            .codex_timeout_seconds(300)
            .codex_auth_paths("/root/.codex", "/root/.codex")
    }

    fn gitlab_token(mut self, token: impl Into<String>) -> Self {
        self.config.gitlab.token = token.into();
        self
    }

    fn gitlab_bot_user_id(mut self, bot_user_id: Option<u64>) -> Self {
        self.config.gitlab.bot_user_id = bot_user_id;
        self
    }

    fn schedule_cron(mut self, cron: impl Into<String>) -> Self {
        self.config.schedule.cron = cron.into();
        self
    }

    fn schedule_timezone(mut self, timezone: Option<&str>) -> Self {
        self.config.schedule.timezone = timezone.map(ToString::to_string);
        self
    }

    fn review_max_concurrent(mut self, max_concurrent: usize) -> Self {
        self.config.review.max_concurrent = max_concurrent;
        self
    }

    fn review_stale_in_progress_minutes(mut self, stale_in_progress_minutes: u64) -> Self {
        self.config.review.stale_in_progress_minutes = stale_in_progress_minutes;
        self
    }

    fn review_dry_run(mut self, dry_run: bool) -> Self {
        self.config.review.dry_run = dry_run;
        self
    }

    fn review_mention_commands(mut self, mention_commands: ReviewMentionCommandsConfig) -> Self {
        self.config.review.mention_commands = mention_commands;
        self
    }

    fn codex_timeout_seconds(mut self, timeout_seconds: u64) -> Self {
        self.config.codex.timeout_seconds = timeout_seconds;
        self
    }

    fn codex_auth_paths(
        mut self,
        auth_host_path: impl Into<String>,
        auth_mount_path: impl Into<String>,
    ) -> Self {
        self.config.codex.auth_host_path = auth_host_path.into();
        self.config.codex.auth_mount_path = auth_mount_path.into();
        self
    }

    fn docker_host(mut self, host: impl Into<String>) -> Self {
        self.config.docker.host = host.into();
        self
    }

    fn server_status_ui_enabled(mut self, status_ui_enabled: bool) -> Self {
        self.config.server.status_ui_enabled = status_ui_enabled;
        self
    }
}
