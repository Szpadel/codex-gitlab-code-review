use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use clap::{Parser, Subcommand};
use cron::Schedule;
use std::future::Future;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::watch;
use tokio::task::JoinHandle;
use tracing::{info, warn};
use uuid::Uuid;

use codex_gitlab_code_review::auth_cli::{AuthAction as RunnerAuthAction, AuthRunner};
use codex_gitlab_code_review::codex_runner::{DockerCodexRunner, RunnerRuntimeOptions};
use codex_gitlab_code_review::config::{
    Config, DockerConfig, TargetSelector, gitlab_discovery_mcp_uses_cluster_service_advertise_url,
};
use codex_gitlab_code_review::demo_history::seed_example_history;
use codex_gitlab_code_review::dev_mode::{DEV_MODE_BASE_URL, DevToolsService, MockCodexRunner};
use codex_gitlab_code_review::docker_utils::wait_for_docker_ready;
use codex_gitlab_code_review::gitlab::{GitLabApi, GitLabClient};
use codex_gitlab_code_review::gitlab_discovery_mcp::GitLabDiscoveryMcpService;
use codex_gitlab_code_review::http::{StatusService, run_http_server_with_dev_tools};
use codex_gitlab_code_review::review::{ReviewService, ScanRunStatus};
use codex_gitlab_code_review::state::{ReviewStateStore, ScanMode, ScanOutcome};

const STARTUP_DOCKER_READY_TIMEOUT: Duration = Duration::from_secs(30);
const STARTUP_DOCKER_READY_POLL_INTERVAL: Duration = Duration::from_secs(1);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ScheduledWakeReason {
    Cron,
    PendingRateLimit,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ScheduledWake {
    at: DateTime<Utc>,
    reason: ScheduledWakeReason,
}

#[derive(Parser, Debug)]
#[command(author, version, about = "Codex GitLab review service")]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,
    /// Run a single scan and exit.
    #[arg(long)]
    once: bool,
    /// Force dry-run mode (skip GitLab writes).
    #[arg(long)]
    dry_run: bool,
    /// Enable verbose logging and full Codex app-server event logs.
    #[arg(long)]
    debug: bool,
    /// Start with mocked GitLab and Codex integrations plus development tools UI.
    #[arg(long)]
    dev_mode: bool,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Manage Codex authentication.
    Auth(AuthCommand),
    /// Developer-only utilities.
    Dev(DevCommand),
}

#[derive(Parser, Debug)]
struct AuthCommand {
    #[command(subcommand)]
    action: AuthSubcommand,
}

#[derive(Subcommand, Debug)]
enum AuthSubcommand {
    /// Run device-code login flow and persist auth.json.
    Login,
    /// Show current authentication status.
    Status,
}

#[derive(Parser, Debug)]
struct DevCommand {
    #[command(subcommand)]
    action: DevSubcommand,
}

#[derive(Subcommand, Debug)]
enum DevSubcommand {
    /// Append synthetic review and mention history for validating the web UI.
    SeedExampleHistory {
        /// Required acknowledgement that this mutates the configured database.path.
        #[arg(long)]
        yes_append_to_configured_state: bool,
    },
}

struct RuntimeServices {
    service: Arc<ReviewService>,
    status_service: Arc<StatusService>,
    gitlab_discovery_mcp: Option<Arc<GitLabDiscoveryMcpService>>,
    dev_tools: Option<Arc<DevToolsService>>,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let filter = tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| {
        if cli.debug {
            tracing_subscriber::EnvFilter::new("debug")
        } else {
            tracing_subscriber::EnvFilter::new("info")
        }
    });
    tracing_subscriber::fmt().with_env_filter(filter).init();

    let mut config = Config::load()?;
    if cli.dev_mode {
        apply_dev_mode_profile(&mut config);
    }
    if gitlab_discovery_mcp_uses_cluster_service_advertise_url(&config.codex) {
        warn!(
            advertise_url = config.codex.gitlab_discovery_mcp.advertise_url.as_str(),
            "gitlab discovery MCP advertise_url uses cluster service DNS; Docker review containers may fail to reach it, so prefer host.docker.internal with host-gateway mapping or another explicit routable address"
        );
    }
    if let Some(command) = cli.command {
        match command {
            Command::Auth(auth_cmd) => {
                let runner = AuthRunner::new(&config.docker, config.codex.clone())?;
                let action = match auth_cmd.action {
                    AuthSubcommand::Login => RunnerAuthAction::Login,
                    AuthSubcommand::Status => RunnerAuthAction::Status,
                };
                runner.run(action, cli.debug).await?;
                return Ok(());
            }
            Command::Dev(dev_cmd) => match dev_cmd.action {
                DevSubcommand::SeedExampleHistory {
                    yes_append_to_configured_state,
                } => {
                    if !yes_append_to_configured_state {
                        anyhow::bail!(
                            "refusing to append demo data into configured runtime state; rerun with --yes-append-to-configured-state"
                        );
                    }
                    let report = seed_example_history(&config).await?;
                    println!(
                        "Seeded {} demo run(s) into {}.",
                        report.runs.len(),
                        report.database_path
                    );
                    for run in report.runs {
                        println!(
                            "- run {}: {:?} {} !{} [{}] -> {} | {}",
                            run.run_id,
                            run.kind,
                            run.repo,
                            run.iid,
                            run.result,
                            run.history_path,
                            run.mr_history_path
                        );
                    }
                    return Ok(());
                }
            },
        }
    }
    let run_once = cli.once || env_flag("RUN_ONCE");
    let dry_run_override = cli.dry_run || env_flag("DRY_RUN");
    if dry_run_override {
        config.review.dry_run = true;
        info!("dry run enabled");
    }
    info!(
        gitlab_base = config.gitlab.base_url.as_str(),
        dev_mode = cli.dev_mode,
        repos_all = config.gitlab.targets.repos.is_all(),
        repos = config.gitlab.targets.repos.list().len(),
        groups_all = config.gitlab.targets.groups.is_all(),
        groups = config.gitlab.targets.groups.list().len(),
        exclude_repos = config.gitlab.targets.exclude_repos.len(),
        exclude_groups = config.gitlab.targets.exclude_groups.len(),
        run_once,
        dry_run = config.review.dry_run,
        "starting codex gitlab review"
    );

    let state = Arc::new(ReviewStateStore::new(&config.database.path).await?);
    let created_after = resolve_created_after(&config, state.as_ref()).await?;
    info!(
        created_after = %created_after,
        "using merge request created_after cutoff"
    );
    let runtime = if cli.dev_mode {
        build_dev_runtime(&config, Arc::clone(&state), run_once, created_after)?
    } else {
        build_normal_runtime(
            &mut config,
            Arc::clone(&state),
            run_once,
            created_after,
            cli.debug,
        )
        .await?
    };
    let service = runtime.service;
    let status_service = runtime.status_service;
    let gitlab_discovery_mcp = runtime.gitlab_discovery_mcp;
    let dev_tools = runtime.dev_tools;

    if let Err(err) = service.recover_in_progress_reviews().await {
        warn!(error = %err, "startup recovery of interrupted reviews failed");
    }
    if let Err(err) = status_service.recover_startup_status().await {
        warn!(error = %err, "failed to reconcile startup scan status");
    }
    tokio::spawn(run_http_server_with_dev_tools(
        config.server.bind_addr.clone(),
        Arc::clone(&status_service),
        dev_tools.clone(),
    ));

    if run_once {
        info!("running single scan");
        if let Err(err) = status_service.clear_next_scan_at().await {
            warn!(error = %err, "failed to clear next scheduled scan status");
        }
        run_tracked_scan(status_service.as_ref(), ScanMode::Full, service.scan_once()).await?;
        info!("single scan complete");
        return Ok(());
    }

    info!("starting scan loop");
    if let Err(err) =
        run_tracked_scan(status_service.as_ref(), ScanMode::Full, service.scan_once()).await
    {
        warn!(error = %format!("{err:#}"), "initial scan failed");
    }

    let tz = parse_timezone(config.schedule.timezone.as_deref())?;
    let schedule = Schedule::from_str(&config.schedule.cron).with_context(|| {
        format!(
            "invalid cron expression '{}'. Expected 6 fields (sec min hour day month dow) like '0 */10 * * * *' or a shorthand like '@hourly'",
            config.schedule.cron
        )
    })?;

    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let scheduled_service = Arc::clone(&service);
    let scheduled_status_service = Arc::clone(&status_service);
    let mut scheduled_loop = tokio::spawn(async move {
        run_schedule_loop(
            scheduled_service.as_ref(),
            scheduled_status_service.as_ref(),
            schedule,
            tz,
            shutdown_rx,
        )
        .await
    });

    let shutdown_signal = wait_for_shutdown_signal();
    tokio::pin!(shutdown_signal);
    tokio::select! {
        signal_result = &mut shutdown_signal => {
            signal_result?;
            info!("shutdown signal received");
        }
        scheduled_result = &mut scheduled_loop => {
            return match scheduled_result {
                Ok(Ok(())) => Err(anyhow::anyhow!(
                    "scheduler task exited before receiving a shutdown signal"
                )),
                Ok(Err(err)) => Err(err),
                Err(err) => Err(err.into()),
            };
        }
    }

    service.request_shutdown();
    if let Some(service) = gitlab_discovery_mcp.as_ref() {
        service.shutdown();
    }
    let _ = shutdown_tx.send(true);
    if let Err(err) = service.recover_in_progress_reviews().await {
        warn!(error = %err, "shutdown recovery of interrupted reviews failed");
    }
    if let Err(err) = status_service.reconcile_interrupted_run_history().await {
        warn!(error = %err, "shutdown reconciliation of run history failed");
    }

    match scheduled_loop.await {
        Ok(result) => result,
        Err(err) => Err(err.into()),
    }
}

fn apply_dev_mode_profile(config: &mut Config) {
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
    let runner = Arc::new(MockCodexRunner::new(Arc::clone(&state)));
    let service = Arc::new(
        ReviewService::new(
            config.clone(),
            dev_tools.gitlab_api(),
            Arc::clone(&state),
            runner.clone(),
            1,
            created_after,
        )
        .with_dynamic_repo_source(dev_tools.clone()),
    );
    let status_service = Arc::new(
        StatusService::new(config.clone(), state, run_once, Some(runner))
            .with_runtime_mode("development"),
    );
    Ok(RuntimeServices {
        service,
        status_service,
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
    wait_for_startup_docker(&config.docker).await?;
    let gitlab_client = GitLabClient::new(&config.gitlab.base_url, &config.gitlab.token)?;
    let needs_current_user_for_bot_user_id = config.gitlab.bot_user_id.is_none();
    let needs_current_user_for_mention = config.review.mention_commands.enabled
        && config.review.mention_commands.bot_username.is_none();
    let current_user = if config.gitlab.token.is_empty() {
        None
    } else if needs_current_user_for_bot_user_id {
        Some(gitlab_client.current_user().await?)
    } else if needs_current_user_for_mention {
        match gitlab_client.current_user().await {
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
                match gitlab_client.get_user(configured_bot_user_id).await {
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
    let git_base = gitlab_client.git_base_url()?;
    let review_owner_id = state.get_or_create_review_owner_id().await?;
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
    )?);
    spawn_startup_warmup(runner.clone());
    let service = Arc::new(ReviewService::new(
        config.clone(),
        Arc::new(gitlab_client),
        Arc::clone(&state),
        runner.clone(),
        bot_user_id,
        created_after,
    ));
    let status_service = Arc::new(
        StatusService::new(config.clone(), state, run_once, Some(runner))
            .with_runtime_mode("normal"),
    );
    Ok(RuntimeServices {
        service,
        status_service,
        gitlab_discovery_mcp,
        dev_tools: None,
    })
}

fn parse_timezone(value: Option<&str>) -> Result<chrono_tz::Tz> {
    match value {
        Some(tz) => Ok(chrono_tz::Tz::from_str(tz)?),
        None => Ok(chrono_tz::UTC),
    }
}

async fn resolve_created_after(config: &Config, state: &ReviewStateStore) -> Result<DateTime<Utc>> {
    if let Some(value) = config.gitlab.created_after.as_ref() {
        let normalized = value.to_rfc3339();
        state.set_created_after(&normalized).await?;
        return Ok(value.to_owned());
    }
    if let Some(raw) = state.get_created_after().await? {
        match DateTime::parse_from_rfc3339(&raw) {
            Ok(parsed) => Ok(parsed.with_timezone(&Utc)),
            Err(err) => {
                warn!(
                    stored_value = raw.as_str(),
                    error = %err,
                    "invalid created_after in state; resetting to now"
                );
                let now = Utc::now();
                state.set_created_after(&now.to_rfc3339()).await?;
                Ok(now)
            }
        }
    } else {
        let now = Utc::now();
        state.set_created_after(&now.to_rfc3339()).await?;
        Ok(now)
    }
}

fn env_flag(name: &str) -> bool {
    std::env::var(name)
        .is_ok_and(|value| matches!(value.to_lowercase().as_str(), "1" | "true" | "yes"))
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

async fn wait_for_startup_docker(docker_cfg: &DockerConfig) -> Result<()> {
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

fn spawn_startup_warmup(
    runner: Arc<dyn codex_gitlab_code_review::codex_runner::CodexRunner>,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        if let Err(err) = runner.warm_up_images().await {
            warn!(error = %err, "startup docker image warm-up failed");
        }
    })
}

async fn run_schedule_loop(
    service: &ReviewService,
    status_service: &StatusService,
    schedule: Schedule,
    tz: chrono_tz::Tz,
    mut shutdown_rx: watch::Receiver<bool>,
) -> Result<()> {
    let mut next_cron_at = schedule
        .upcoming(tz)
        .next()
        .ok_or_else(|| anyhow::anyhow!("cron has no future times"))?
        .with_timezone(&Utc);
    loop {
        if *shutdown_rx.borrow() {
            if let Err(err) = status_service.clear_next_scan_at().await {
                warn!(error = %err, "failed to clear next scheduled scan status");
            }
            info!("stopping schedule loop: shutdown requested");
            return Ok(());
        }
        let now = Utc::now().with_timezone(&tz);
        let next_pending_retry_at = match service.next_pending_rate_limit_retry_at().await {
            Ok(value) => value,
            Err(err) => {
                warn!(error = %err, "failed to load next pending review wake time");
                None
            }
        };
        let scheduled_wake =
            select_next_wake(now.with_timezone(&Utc), next_cron_at, next_pending_retry_at);
        if let Err(err) = status_service
            .set_next_scan_at(Some(scheduled_wake.at))
            .await
        {
            warn!(error = %err, "failed to persist next scheduled scan status");
        }
        let delay = (scheduled_wake.at.with_timezone(&tz) - now)
            .to_std()
            .unwrap_or_else(|_| Duration::from_secs(0));
        let sleep = tokio::time::sleep(delay);
        tokio::pin!(sleep);
        tokio::select! {
            () = &mut sleep => {}
            changed = shutdown_rx.changed() => match changed {
                Ok(()) if *shutdown_rx.borrow() => {
                    if let Err(err) = status_service.clear_next_scan_at().await {
                        warn!(error = %err, "failed to clear next scheduled scan status");
                    }
                    info!("stopping schedule loop: shutdown requested");
                    return Ok(());
                }
                Ok(()) => continue,
                Err(_) => return Ok(()),
            },
        }
        if *shutdown_rx.borrow() {
            if let Err(err) = status_service.clear_next_scan_at().await {
                warn!(error = %err, "failed to clear next scheduled scan status");
            }
            info!("stopping schedule loop: shutdown requested");
            return Ok(());
        }
        let scan_result = match scheduled_wake.reason {
            ScheduledWakeReason::Cron => {
                run_tracked_scan(
                    status_service,
                    ScanMode::Incremental,
                    service.scan_once_incremental(),
                )
                .await
            }
            ScheduledWakeReason::PendingRateLimit => {
                run_tracked_scan(
                    status_service,
                    ScanMode::Incremental,
                    service.process_due_pending_rate_limit_reviews(),
                )
                .await
            }
        };
        if let Err(err) = scan_result {
            warn!(error = %format!("{err:#}"), "scheduled wake failed");
        }
        if matches!(scheduled_wake.reason, ScheduledWakeReason::Cron) {
            next_cron_at = schedule
                .upcoming(tz)
                .next()
                .ok_or_else(|| anyhow::anyhow!("cron has no future times"))?
                .with_timezone(&Utc);
        }
    }
}

fn select_next_wake(
    now: DateTime<Utc>,
    next_cron_at: DateTime<Utc>,
    next_pending_retry_at: Option<DateTime<Utc>>,
) -> ScheduledWake {
    if next_cron_at <= now {
        return ScheduledWake {
            at: next_cron_at,
            reason: ScheduledWakeReason::Cron,
        };
    }
    match next_pending_retry_at {
        Some(next_pending_retry_at) if next_pending_retry_at < next_cron_at => ScheduledWake {
            at: next_pending_retry_at,
            reason: ScheduledWakeReason::PendingRateLimit,
        },
        _ => ScheduledWake {
            at: next_cron_at,
            reason: ScheduledWakeReason::Cron,
        },
    }
}

async fn run_tracked_scan<F>(status_service: &StatusService, mode: ScanMode, scan: F) -> Result<()>
where
    F: Future<Output = Result<ScanRunStatus>>,
{
    if let Err(err) = status_service.mark_scan_started(mode).await {
        warn!(error = %err, ?mode, "failed to persist scan start status");
    }
    let result = scan.await;
    match &result {
        Ok(ScanRunStatus::Interrupted) => {
            if let Err(status_err) = status_service
                .mark_scan_finished(
                    mode,
                    ScanOutcome::Failure,
                    Some("scan interrupted by shutdown".to_string()),
                )
                .await
            {
                warn!(
                    error = %status_err,
                    ?mode,
                    "failed to persist interrupted scan status"
                );
            }
        }
        Ok(ScanRunStatus::Completed) => {
            if let Err(err) = status_service
                .mark_scan_finished(mode, ScanOutcome::Success, None)
                .await
            {
                warn!(error = %err, ?mode, "failed to persist successful scan status");
            }
        }
        Err(err) => {
            if let Err(status_err) = status_service
                .mark_scan_finished(mode, ScanOutcome::Failure, Some(err.to_string()))
                .await
            {
                warn!(
                    error = %status_err,
                    ?mode,
                    "failed to persist failed scan status"
                );
            }
        }
    }
    result.map(|_| ())
}

async fn wait_for_shutdown_signal() -> Result<()> {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};

        let mut terminate = signal(SignalKind::terminate()).context("listen for SIGTERM")?;
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {}
            _ = terminate.recv() => {}
        }
        Ok(())
    }
    #[cfg(not(unix))]
    {
        tokio::signal::ctrl_c().await.context("listen for Ctrl+C")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::anyhow;
    use async_trait::async_trait;
    use chrono::TimeZone;
    use codex_gitlab_code_review::codex_runner::{
        CodexResult, MentionCommandContext, MentionCommandResult, ReviewContext,
    };
    use codex_gitlab_code_review::config::{
        BrowserMcpConfig, CodexConfig, DatabaseConfig, DockerConfig, GitLabConfig,
        GitLabDiscoveryMcpConfig, GitLabTargets, McpServerOverridesConfig,
        ReasoningSummaryOverridesConfig, ReviewConfig, ReviewMentionCommandsConfig, ScheduleConfig,
        ServerConfig, SessionOverridesConfig, TargetSelector,
    };
    use codex_gitlab_code_review::feature_flags::FeatureFlagDefaults;
    use sqlx::Executor;
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicBool, Ordering};

    #[tokio::test]
    async fn tracked_scan_runs_even_when_status_state_is_malformed() -> Result<()> {
        let state = Arc::new(ReviewStateStore::new(":memory:").await?);
        state
            .pool()
            .execute(sqlx::query(
                "INSERT INTO service_state (key, value) VALUES ('scan_status', 'not-json')",
            ))
            .await?;
        let status_service = StatusService::new(test_config(), state, false, None);
        let executed = Arc::new(AtomicBool::new(false));
        let executed_flag = Arc::clone(&executed);

        run_tracked_scan(&status_service, ScanMode::Full, async move {
            executed_flag.store(true, Ordering::SeqCst);
            Ok(ScanRunStatus::Completed)
        })
        .await?;

        assert!(executed.load(Ordering::SeqCst));
        Ok(())
    }

    #[test]
    fn select_next_wake_prefers_pending_retry_before_cron() {
        let now = Utc.with_ymd_and_hms(2026, 3, 25, 12, 0, 0).unwrap();
        let cron_at = Utc.with_ymd_and_hms(2026, 3, 25, 12, 30, 0).unwrap();
        let pending_at = Utc.with_ymd_and_hms(2026, 3, 25, 12, 20, 0).unwrap();

        let wake = select_next_wake(now, cron_at, Some(pending_at));

        assert_eq!(wake.at, pending_at);
        assert_eq!(wake.reason, ScheduledWakeReason::PendingRateLimit);
    }

    #[test]
    fn select_next_wake_keeps_cron_when_pending_retry_is_later() {
        let now = Utc.with_ymd_and_hms(2026, 3, 25, 12, 0, 0).unwrap();
        let cron_at = Utc.with_ymd_and_hms(2026, 3, 25, 12, 30, 0).unwrap();
        let pending_at = Utc.with_ymd_and_hms(2026, 3, 25, 12, 40, 0).unwrap();

        let wake = select_next_wake(now, cron_at, Some(pending_at));

        assert_eq!(wake.at, cron_at);
        assert_eq!(wake.reason, ScheduledWakeReason::Cron);
    }

    #[test]
    fn select_next_wake_prefers_due_cron_over_pending_retry() {
        let now = Utc.with_ymd_and_hms(2026, 3, 25, 12, 31, 0).unwrap();
        let cron_at = Utc.with_ymd_and_hms(2026, 3, 25, 12, 30, 0).unwrap();
        let pending_at = Utc.with_ymd_and_hms(2026, 3, 25, 12, 20, 0).unwrap();

        let wake = select_next_wake(now, cron_at, Some(pending_at));

        assert_eq!(wake.at, cron_at);
        assert_eq!(wake.reason, ScheduledWakeReason::Cron);
    }

    struct WarmupRunner {
        calls: Mutex<u32>,
        fail: bool,
    }

    #[async_trait]
    impl codex_gitlab_code_review::codex_runner::CodexRunner for WarmupRunner {
        async fn warm_up_images(&self) -> Result<()> {
            *self.calls.lock().unwrap() += 1;
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
            .expect("task finished");

        assert_eq!(*runner.calls.lock().unwrap(), 1);
    }

    #[tokio::test]
    async fn startup_warmup_is_best_effort_on_failure() {
        let runner = Arc::new(WarmupRunner {
            calls: Mutex::new(0),
            fail: true,
        });

        spawn_startup_warmup(runner.clone())
            .await
            .expect("task finished");

        assert_eq!(*runner.calls.lock().unwrap(), 1);
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
                security: codex_gitlab_code_review::config::ReviewSecurityConfig::default(),
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
}
