use anyhow::Result;
use chrono::{DateTime, Utc};
use std::sync::Arc;
use tokio::task::JoinHandle;
use tracing::{info, warn};

use crate::codex_runner::{CodexRunner, DockerCodexRunner, RunnerRuntimeOptions};
use crate::config::{Config, ValidatedConfig, validate_config};
use crate::dev_mode::{DevToolsService, MockCodexRunner};
use crate::gitlab::bot_user::resolve_and_update_bot_user_config;
use crate::gitlab::{GitLabApi, GitLabClient};
use crate::gitlab_discovery_mcp::GitLabDiscoveryMcpService;
use crate::http::HttpServices;
use crate::review::ReviewService;
use crate::state::ReviewStateStore;

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

impl RuntimeServices {
    fn into_bundle(self, config: ValidatedConfig, run_once: bool) -> ServiceBundle {
        ServiceBundle {
            config,
            run_once,
            state: self.state,
            runner: self.runner,
            gitlab_client: self.gitlab_client,
            service: self.service,
            http_services: self.http_services,
            gitlab_discovery_mcp: self.gitlab_discovery_mcp,
            dev_tools: self.dev_tools,
        }
    }
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

pub async fn build_service_bundle(
    config: ValidatedConfig,
    options: ServiceFactoryOptions,
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
        )
        .await?
    };
    let config = validate_config(runtime_config)?;

    Ok(runtime.into_bundle(config, options.run_once))
}

pub(crate) async fn build_review_state_store(config: &Config) -> Result<Arc<ReviewStateStore>> {
    Ok(Arc::new(
        ReviewStateStore::new(&config.database.path).await?,
    ))
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
) -> Result<RuntimeServices> {
    let gitlab_client = Arc::new(GitLabClient::new(
        &config.gitlab.base_url,
        &config.gitlab.token,
    )?);
    let bot_user_id = resolve_and_update_bot_user_config(config, gitlab_client.as_ref()).await?;

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
    use crate::config::test_builder::ConfigBuilder;
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

    fn test_config() -> Config {
        ConfigBuilder::for_service_factory_tests().build()
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
