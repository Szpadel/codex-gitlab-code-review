use anyhow::Result;
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use std::sync::Arc;
use std::time::Duration;
use tokio::task::JoinHandle;
use tracing::{info, warn};
use uuid::Uuid;

use crate::codex_runner::{CodexRunner, DockerCodexRunner, RunnerRuntimeOptions};
use crate::config::{
    Config, DockerConfig, TargetSelector, ValidatedConfig,
    gitlab_discovery_mcp_uses_cluster_service_advertise_url, load_raw_config, validate_config,
};
use crate::dev_mode::{DEV_MODE_BASE_URL, DevToolsService, MockCodexRunner};
use crate::docker_utils::wait_for_docker_ready;
use crate::gitlab::{GitLabApi, GitLabClient, GitLabUser, GitLabUserDetail};
use crate::gitlab_discovery_mcp::GitLabDiscoveryMcpService;
use crate::http::HttpServices;
use crate::review::ReviewService;
use crate::state::ReviewStateStore;

const STARTUP_DOCKER_READY_TIMEOUT: Duration = Duration::from_secs(30);
const STARTUP_DOCKER_READY_POLL_INTERVAL: Duration = Duration::from_secs(1);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuntimeMode {
    Normal,
    Development,
}

#[derive(Debug, Clone, Copy)]
pub struct ServiceFactoryOptions {
    pub run_once: bool,
    pub force_dry_run: bool,
    pub log_all_json: bool,
    pub runtime_mode: RuntimeMode,
}

struct RuntimeServices {
    state: Arc<ReviewStateStore>,
    runner: Arc<dyn CodexRunner>,
    gitlab_client: Option<Arc<GitLabClient>>,
    service: Arc<ReviewService>,
    http_services: Arc<HttpServices>,
    gitlab_discovery_mcp: Option<Arc<GitLabDiscoveryMcpService>>,
    dev_tools: Option<Arc<DevToolsService>>,
}

pub struct ServiceBundle {
    pub config: ValidatedConfig,
    pub run_once: bool,
    pub state: Arc<ReviewStateStore>,
    pub runner: Arc<dyn CodexRunner>,
    pub gitlab_client: Option<Arc<GitLabClient>>,
    pub service: Arc<ReviewService>,
    pub http_services: Arc<HttpServices>,
    pub gitlab_discovery_mcp: Option<Arc<GitLabDiscoveryMcpService>>,
    pub dev_tools: Option<Arc<DevToolsService>>,
}

#[async_trait]
trait DockerReadinessProbe: Send + Sync {
    async fn wait_for_startup_docker(&self, docker_cfg: &DockerConfig) -> Result<()>;
}

struct RealDockerReadinessProbe;

#[async_trait]
impl DockerReadinessProbe for RealDockerReadinessProbe {
    async fn wait_for_startup_docker(&self, docker_cfg: &DockerConfig) -> Result<()> {
        info!(
            docker_host = docker_cfg.host.as_str(),
            timeout_secs = STARTUP_DOCKER_READY_TIMEOUT.as_secs(),
            "waiting for docker daemon readiness"
        );
        wait_for_docker_ready(
            docker_cfg,
            STARTUP_DOCKER_READY_TIMEOUT,
            STARTUP_DOCKER_READY_POLL_INTERVAL,
        )
        .await?;
        info!(
            docker_host = docker_cfg.host.as_str(),
            "docker daemon is ready"
        );
        Ok(())
    }
}

#[async_trait]
trait BotUserResolver: Send + Sync {
    async fn current_user(&self) -> Result<GitLabUser>;
    async fn get_user(&self, user_id: u64) -> Result<GitLabUserDetail>;
}

#[async_trait]
impl BotUserResolver for GitLabClient {
    async fn current_user(&self) -> Result<GitLabUser> {
        GitLabApi::current_user(self).await
    }

    async fn get_user(&self, user_id: u64) -> Result<GitLabUserDetail> {
        GitLabApi::get_user(self, user_id).await
    }
}

pub fn load_config(dev_mode: bool) -> Result<ValidatedConfig> {
    let mut config = load_raw_config()?;
    if dev_mode {
        apply_dev_mode_profile(&mut config);
    }
    if gitlab_discovery_mcp_uses_cluster_service_advertise_url(&config.codex) {
        warn!(
            advertise_url = config.codex.gitlab_discovery_mcp.advertise_url.as_str(),
            "gitlab discovery MCP advertise_url uses cluster service DNS; Docker review containers may fail to reach it, so prefer host.docker.internal with host-gateway mapping or another explicit routable address"
        );
    }
    validate_config(config)
}

pub async fn build_service_bundle(
    config: ValidatedConfig,
    options: ServiceFactoryOptions,
) -> Result<ServiceBundle> {
    let readiness_probe = RealDockerReadinessProbe;
    build_service_bundle_with_probe(config, options, &readiness_probe).await
}

async fn build_service_bundle_with_probe(
    config: ValidatedConfig,
    options: ServiceFactoryOptions,
    readiness_probe: &dyn DockerReadinessProbe,
) -> Result<ServiceBundle> {
    let mut runtime_config = config.into_inner();
    if options.force_dry_run {
        runtime_config.review.dry_run = true;
        info!("dry run enabled");
    }
    info!(
        gitlab_base = runtime_config.gitlab.base_url.as_str(),
        dev_mode = matches!(options.runtime_mode, RuntimeMode::Development),
        repos_all = runtime_config.gitlab.targets.repos.is_all(),
        repos = runtime_config.gitlab.targets.repos.list().len(),
        groups_all = runtime_config.gitlab.targets.groups.is_all(),
        groups = runtime_config.gitlab.targets.groups.list().len(),
        exclude_repos = runtime_config.gitlab.targets.exclude_repos.len(),
        exclude_groups = runtime_config.gitlab.targets.exclude_groups.len(),
        run_once = options.run_once,
        dry_run = runtime_config.review.dry_run,
        "starting codex gitlab review"
    );

    let state = build_review_state_store(&runtime_config).await?;
    let created_after = resolve_created_after(&runtime_config, state.as_ref()).await?;
    info!(
        created_after = %created_after,
        "using merge request created_after cutoff"
    );

    let runtime = if matches!(options.runtime_mode, RuntimeMode::Development) {
        build_dev_runtime(
            &runtime_config,
            Arc::clone(&state),
            options.run_once,
            created_after,
        )?
    } else {
        build_normal_runtime(
            &mut runtime_config,
            Arc::clone(&state),
            options.run_once,
            created_after,
            options.log_all_json,
            readiness_probe,
        )
        .await?
    };
    let config = validate_config(runtime_config)?;

    Ok(ServiceBundle {
        config,
        run_once: options.run_once,
        state: runtime.state,
        runner: runtime.runner,
        gitlab_client: runtime.gitlab_client,
        service: runtime.service,
        http_services: runtime.http_services,
        gitlab_discovery_mcp: runtime.gitlab_discovery_mcp,
        dev_tools: runtime.dev_tools,
    })
}

pub(crate) async fn build_review_state_store(config: &Config) -> Result<Arc<ReviewStateStore>> {
    Ok(Arc::new(
        ReviewStateStore::new(&config.database.path).await?,
    ))
}

pub fn apply_dev_mode_profile(config: &mut Config) {
    config.gitlab.base_url = DEV_MODE_BASE_URL.to_string();
    config.gitlab.token.clear();
    config.gitlab.bot_user_id = Some(1);
    config.gitlab.targets.repos = TargetSelector::All;
    config.gitlab.targets.groups = TargetSelector::List(Vec::new());
    config.gitlab.targets.exclude_repos.clear();
    config.gitlab.targets.exclude_groups.clear();
    config.review.mention_commands.enabled = false;
    config.review.mention_commands.bot_username = None;
    config.codex.browser_mcp.enabled = false;
    config.codex.gitlab_discovery_mcp.enabled = false;
    config.server.status_ui_enabled = true;
    config.database.path = format!(
        "/tmp/codex-gitlab-code-review-dev-{}.sqlite",
        Uuid::new_v4()
    );
}

fn build_dev_runtime(
    config: &Config,
    state: Arc<ReviewStateStore>,
    run_once: bool,
    created_after: DateTime<Utc>,
) -> Result<RuntimeServices> {
    let dev_tools = Arc::new(DevToolsService::new(&config.database.path));
    let runner = Arc::new(MockCodexRunner::new(Arc::clone(&state))) as Arc<dyn CodexRunner>;
    let service = Arc::new(
        ReviewService::new(
            config.clone(),
            dev_tools.gitlab_api(),
            Arc::clone(&state),
            Arc::clone(&runner),
            1,
            created_after,
        )
        .with_dynamic_repo_source(dev_tools.clone()),
    );
    let http_services = Arc::new(
        HttpServices::new(
            config.clone(),
            Arc::clone(&state),
            run_once,
            Some(Arc::clone(&runner)),
        )
        .with_runtime_mode("development"),
    );
    Ok(RuntimeServices {
        state,
        runner,
        gitlab_client: None,
        service,
        http_services,
        gitlab_discovery_mcp: None,
        dev_tools: Some(dev_tools),
    })
}

async fn build_normal_runtime(
    config: &mut Config,
    state: Arc<ReviewStateStore>,
    run_once: bool,
    created_after: DateTime<Utc>,
    log_all_json: bool,
    readiness_probe: &dyn DockerReadinessProbe,
) -> Result<RuntimeServices> {
    readiness_probe
        .wait_for_startup_docker(&config.docker)
        .await?;
    let gitlab_client = Arc::new(GitLabClient::new(
        &config.gitlab.base_url,
        &config.gitlab.token,
    )?);
    let bot_user_id = resolve_bot_user_id(config, gitlab_client.as_ref()).await?;

    let git_base = gitlab_client.git_base_url()?;
    let review_owner_id = state.service_state.get_or_create_review_owner_id().await?;
    let mention_commands_active = mention_commands_active(config);
    let gitlab_discovery_mcp = if config.codex.gitlab_discovery_mcp.enabled {
        Some(Arc::new(GitLabDiscoveryMcpService::new(
            config.docker.clone(),
            &config.gitlab,
            config.codex.gitlab_discovery_mcp.clone(),
        )?))
    } else {
        None
    };
    if let Some(service) = gitlab_discovery_mcp.as_ref() {
        let listener = service.bind_listener().await?;
        tokio::spawn(Arc::clone(service).run(listener));
    }

    let runner = Arc::new(DockerCodexRunner::new(
        &config.docker,
        config.codex.clone(),
        git_base,
        Arc::clone(&state),
        gitlab_discovery_mcp.clone(),
        RunnerRuntimeOptions {
            gitlab_token: config.gitlab.token.clone(),
            log_all_json,
            owner_id: review_owner_id,
            mention_commands_active,
            review_additional_developer_instructions: config
                .review
                .additional_developer_instructions
                .clone(),
        },
    )?) as Arc<dyn CodexRunner>;
    spawn_startup_warmup(Arc::clone(&runner));

    let service = Arc::new(ReviewService::new(
        config.clone(),
        Arc::clone(&gitlab_client) as Arc<dyn GitLabApi>,
        Arc::clone(&state),
        Arc::clone(&runner),
        bot_user_id,
        created_after,
    ));
    let http_services = Arc::new(
        HttpServices::new(
            config.clone(),
            Arc::clone(&state),
            run_once,
            Some(Arc::clone(&runner)),
        )
        .with_runtime_mode("normal"),
    );

    Ok(RuntimeServices {
        state,
        runner,
        gitlab_client: Some(gitlab_client),
        service,
        http_services,
        gitlab_discovery_mcp,
        dev_tools: None,
    })
}

async fn resolve_bot_user_id(
    config: &mut Config,
    user_resolver: &dyn BotUserResolver,
) -> Result<u64> {
    let needs_current_user_for_bot_user_id = config.gitlab.bot_user_id.is_none();
    let needs_current_user_for_mention = config.review.mention_commands.enabled
        && config.review.mention_commands.bot_username.is_none();

    let current_user = if config.gitlab.token.is_empty() {
        None
    } else if needs_current_user_for_bot_user_id {
        Some(user_resolver.current_user().await?)
    } else if needs_current_user_for_mention {
        match user_resolver.current_user().await {
            Ok(user) => Some(user),
            Err(err) => {
                warn!(
                    error = %err,
                    "failed to resolve bot username for mention commands; mention triggers will be skipped"
                );
                None
            }
        }
    } else {
        None
    };

    let bot_user_id = match config.gitlab.bot_user_id {
        Some(id) => id,
        None if config.gitlab.token.is_empty() => {
            warn!("missing gitlab token; cannot determine bot user id");
            0
        }
        None => current_user
            .as_ref()
            .map(|user| user.id)
            .ok_or_else(|| anyhow::anyhow!("failed to resolve bot user id"))?,
    };

    if config.review.mention_commands.enabled
        && config.review.mention_commands.bot_username.is_none()
    {
        if let Some(configured_bot_user_id) = config.gitlab.bot_user_id {
            if config.gitlab.token.is_empty() {
                warn!(
                    "mention commands enabled with configured bot_user_id but gitlab token is missing; mention triggers will be skipped"
                );
            } else {
                match user_resolver.get_user(configured_bot_user_id).await {
                    Ok(user) => {
                        config.review.mention_commands.bot_username = user.username;
                    }
                    Err(err) => {
                        warn!(
                            error = %err,
                            bot_user_id = configured_bot_user_id,
                            "failed to resolve mention bot username from configured bot_user_id"
                        );
                        if let Some(username) = current_user
                            .as_ref()
                            .filter(|user| user.id == configured_bot_user_id)
                            .and_then(|user| user.username.clone())
                        {
                            warn!(
                                bot_user_id = configured_bot_user_id,
                                "falling back to current_user username for mention commands"
                            );
                            config.review.mention_commands.bot_username = Some(username);
                        }
                    }
                }
            }
        } else {
            config.review.mention_commands.bot_username =
                current_user.as_ref().and_then(|user| user.username.clone());
        }

        if config.review.mention_commands.bot_username.is_none() {
            warn!(
                "mention commands enabled but bot username could not be resolved; mention triggers will be skipped"
            );
        }
    }

    if config.review.mention_commands.enabled {
        if let Some(bot_username) = config.review.mention_commands.bot_username.as_deref() {
            info!(
                bot_username = bot_username,
                "mention commands enabled (scanning MR discussions for standalone comments and replies)"
            );
        } else {
            warn!("mention commands enabled but inactive: bot username unavailable");
        }
    } else {
        info!("mention commands disabled");
    }

    Ok(bot_user_id)
}

pub async fn resolve_created_after(
    config: &Config,
    state: &ReviewStateStore,
) -> Result<DateTime<Utc>> {
    if let Some(value) = config.gitlab.created_after.as_ref() {
        let normalized = value.to_rfc3339();
        state.service_state.set_created_after(&normalized).await?;
        return Ok(value.to_owned());
    }

    if let Some(raw) = state.service_state.get_created_after().await? {
        match DateTime::parse_from_rfc3339(&raw) {
            Ok(parsed) => Ok(parsed.with_timezone(&Utc)),
            Err(err) => {
                warn!(
                    stored_value = raw.as_str(),
                    error = %err,
                    "invalid created_after in state; resetting to now"
                );
                let now = Utc::now();
                state
                    .service_state
                    .set_created_after(&now.to_rfc3339())
                    .await?;
                Ok(now)
            }
        }
    } else {
        let now = Utc::now();
        state
            .service_state
            .set_created_after(&now.to_rfc3339())
            .await?;
        Ok(now)
    }
}

fn mention_commands_active(config: &Config) -> bool {
    config.review.mention_commands.enabled
        && !config.review.dry_run
        && config
            .review
            .mention_commands
            .bot_username
            .as_deref()
            .map(str::trim)
            .is_some_and(|value| !value.is_empty())
}

fn spawn_startup_warmup(runner: Arc<dyn CodexRunner>) -> JoinHandle<()> {
    tokio::spawn(async move {
        if let Err(err) = runner.warm_up_images().await {
            warn!(error = %err, "startup docker image warm-up failed");
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codex_runner::{
        CodexResult, MentionCommandContext, MentionCommandResult, ReviewContext,
    };
    use crate::config::{
        BrowserMcpConfig, CodexConfig, DatabaseConfig, DockerConfig, GitLabConfig,
        GitLabDiscoveryMcpConfig, GitLabTargets, McpServerOverridesConfig,
        ReasoningSummaryOverridesConfig, ReviewConfig, ReviewMentionCommandsConfig, ScheduleConfig,
        ServerConfig, SessionOverridesConfig,
    };
    use crate::feature_flags::FeatureFlagDefaults;
    use anyhow::anyhow;
    use async_trait::async_trait;
    use chrono::TimeZone;
    use std::sync::Mutex;

    struct WarmupRunner {
        calls: Mutex<u32>,
        fail: bool,
    }

    #[async_trait]
    impl CodexRunner for WarmupRunner {
        async fn warm_up_images(&self) -> Result<()> {
            *self.calls.lock().expect("warmup calls lock") += 1;
            if self.fail {
                Err(anyhow!("warmup failed"))
            } else {
                Ok(())
            }
        }

        async fn run_review(&self, _ctx: ReviewContext) -> Result<CodexResult> {
            unreachable!("run_review should not be called")
        }

        async fn run_mention_command(
            &self,
            _ctx: MentionCommandContext,
        ) -> Result<MentionCommandResult> {
            unreachable!("run_mention_command should not be called")
        }
    }

    struct StubBotUserResolver {
        current_user: Option<GitLabUser>,
        lookup_user: Option<GitLabUserDetail>,
    }

    #[async_trait]
    impl BotUserResolver for StubBotUserResolver {
        async fn current_user(&self) -> Result<GitLabUser> {
            self.current_user
                .clone()
                .ok_or_else(|| anyhow!("current_user failed"))
        }

        async fn get_user(&self, _user_id: u64) -> Result<GitLabUserDetail> {
            self.lookup_user
                .clone()
                .ok_or_else(|| anyhow!("get_user failed"))
        }
    }

    #[tokio::test]
    async fn startup_warmup_runs_runner_once() {
        let runner = Arc::new(WarmupRunner {
            calls: Mutex::new(0),
            fail: false,
        });

        spawn_startup_warmup(runner.clone())
            .await
            .expect("warmup task finished");

        assert_eq!(*runner.calls.lock().expect("warmup calls lock"), 1);
    }

    #[tokio::test]
    async fn startup_warmup_is_best_effort_on_failure() {
        let runner = Arc::new(WarmupRunner {
            calls: Mutex::new(0),
            fail: true,
        });

        spawn_startup_warmup(runner.clone())
            .await
            .expect("warmup task finished");

        assert_eq!(*runner.calls.lock().expect("warmup calls lock"), 1);
    }

    #[tokio::test]
    async fn resolve_bot_user_id_uses_configured_lookup_for_mentions() -> Result<()> {
        let mut config = test_config();
        config.gitlab.token = "secret".to_string();
        config.gitlab.bot_user_id = Some(123);
        config.review.mention_commands.enabled = true;
        config.review.mention_commands.bot_username = None;

        let resolver = StubBotUserResolver {
            current_user: Some(GitLabUser {
                id: 999,
                username: Some("runner".to_string()),
                name: None,
            }),
            lookup_user: Some(GitLabUserDetail {
                id: 123,
                username: Some("configured-bot".to_string()),
                name: None,
                public_email: None,
            }),
        };

        let bot_user_id = resolve_bot_user_id(&mut config, &resolver).await?;

        assert_eq!(bot_user_id, 123);
        assert_eq!(
            config.review.mention_commands.bot_username.as_deref(),
            Some("configured-bot")
        );
        Ok(())
    }

    #[tokio::test]
    async fn resolve_bot_user_id_without_token_falls_back_to_zero() -> Result<()> {
        let mut config = test_config();
        config.gitlab.token.clear();
        config.gitlab.bot_user_id = None;
        config.review.mention_commands.enabled = false;

        let resolver = StubBotUserResolver {
            current_user: Some(GitLabUser {
                id: 321,
                username: Some("runner".to_string()),
                name: None,
            }),
            lookup_user: None,
        };

        let bot_user_id = resolve_bot_user_id(&mut config, &resolver).await?;

        assert_eq!(bot_user_id, 0);
        Ok(())
    }

    #[test]
    fn mention_commands_active_requires_runtime_usable_state() {
        let mut config = test_config();
        config.review.dry_run = false;
        config.review.mention_commands.enabled = true;
        config.review.mention_commands.bot_username = Some("bot".to_string());
        assert!(mention_commands_active(&config));

        config.review.dry_run = true;
        assert!(!mention_commands_active(&config));

        config.review.dry_run = false;
        config.review.mention_commands.bot_username = None;
        assert!(!mention_commands_active(&config));

        config.review.mention_commands.bot_username = Some("   ".to_string());
        assert!(!mention_commands_active(&config));
    }

    #[test]
    fn apply_dev_mode_profile_switches_to_safe_mocked_runtime() {
        let mut config = test_config();
        config.server.status_ui_enabled = false;
        config.codex.browser_mcp.enabled = true;
        config.codex.gitlab_discovery_mcp.enabled = true;
        config.review.mention_commands.enabled = true;

        apply_dev_mode_profile(&mut config);

        assert_eq!(config.gitlab.base_url, "https://dev-mode.invalid");
        assert!(config.server.status_ui_enabled);
        assert!(!config.codex.browser_mcp.enabled);
        assert!(!config.codex.gitlab_discovery_mcp.enabled);
        assert!(!config.review.mention_commands.enabled);
        assert!(config.database.path.starts_with("/tmp/"));
        assert!(
            config
                .database
                .path
                .contains("codex-gitlab-code-review-dev-")
        );
    }

    fn test_config() -> Config {
        Config {
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
                comment_marker_prefix: "<!-- codex-review:sha=".to_string(),
                stale_in_progress_minutes: 120,
                dry_run: true,
                additional_developer_instructions: None,
                security: crate::config::ReviewSecurityConfig::default(),
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
                deps: Default::default(),
                browser_mcp: BrowserMcpConfig::default(),
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
        }
    }

    #[test]
    fn resolve_created_after_prefers_explicit_config_value() -> Result<()> {
        let mut config = test_config();
        config.gitlab.created_after = Some(Utc.with_ymd_and_hms(2026, 3, 25, 12, 0, 0).unwrap());

        let runtime = tokio::runtime::Runtime::new()?;
        runtime.block_on(async {
            let state = build_review_state_store(&config).await?;
            let created_after = resolve_created_after(&config, state.as_ref()).await?;
            assert_eq!(
                created_after,
                Utc.with_ymd_and_hms(2026, 3, 25, 12, 0, 0).unwrap()
            );
            Ok::<(), anyhow::Error>(())
        })?;

        Ok(())
    }
}
