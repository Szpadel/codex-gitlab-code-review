use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use clap::{Parser, Subcommand};
use cron::Schedule;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::watch;
use tracing::{error, info, warn};

use codex_gitlab_code_review::auth_cli::{AuthAction as RunnerAuthAction, AuthRunner};
use codex_gitlab_code_review::codex_runner::DockerCodexRunner;
use codex_gitlab_code_review::config::Config;
use codex_gitlab_code_review::gitlab::{GitLabApi, GitLabClient};
use codex_gitlab_code_review::review::ReviewService;
use codex_gitlab_code_review::state::ReviewStateStore;

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
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Manage Codex authentication.
    Auth(AuthCommand),
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
    if let Some(Command::Auth(auth_cmd)) = cli.command {
        let runner = AuthRunner::new(
            config.docker.clone(),
            config.codex.clone(),
            config.proxy.clone(),
        )?;
        let action = match auth_cmd.action {
            AuthSubcommand::Login => RunnerAuthAction::Login,
            AuthSubcommand::Status => RunnerAuthAction::Status,
        };
        runner.run(action, cli.debug).await?;
        return Ok(());
    }
    let run_once = cli.once || env_flag("RUN_ONCE");
    let dry_run_override = cli.dry_run || env_flag("DRY_RUN");
    if dry_run_override {
        config.review.dry_run = true;
        info!("dry run enabled");
    }
    info!(
        gitlab_base = config.gitlab.base_url.as_str(),
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
    let git_base = gitlab_client.git_base_url()?;

    let state = Arc::new(ReviewStateStore::new(&config.database.path).await?);
    let created_after = resolve_created_after(&config, state.as_ref()).await?;
    info!(
        created_after = %created_after,
        "using merge request created_after cutoff"
    );
    let review_owner_id = state.get_or_create_review_owner_id().await?;
    let runner = DockerCodexRunner::new(
        config.docker.clone(),
        config.codex.clone(),
        config.proxy.clone(),
        git_base,
        config.gitlab.token.clone(),
        cli.debug,
        review_owner_id,
    )?;

    let service = Arc::new(ReviewService::new(
        config.clone(),
        Arc::new(gitlab_client),
        state,
        Arc::new(runner),
        bot_user_id,
        created_after,
    ));

    tokio::spawn(run_health_server(config.server.bind_addr.clone()));

    if let Err(err) = service.recover_in_progress_reviews().await {
        warn!(error = %err, "startup recovery of interrupted reviews failed");
    }

    if run_once {
        info!("running single scan");
        service.scan_once().await?;
        info!("single scan complete");
        return Ok(());
    }

    info!("starting scan loop");
    if let Err(err) = service.scan_once().await {
        warn!(error = %err, "initial scan failed");
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
    let mut scheduled_loop = tokio::spawn(async move {
        run_schedule_loop(scheduled_service.as_ref(), schedule, tz, shutdown_rx).await
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
    let _ = shutdown_tx.send(true);
    if let Err(err) = service.recover_in_progress_reviews().await {
        warn!(error = %err, "shutdown recovery of interrupted reviews failed");
    }

    match scheduled_loop.await {
        Ok(result) => result,
        Err(err) => Err(err.into()),
    }
}

async fn run_health_server(bind_addr: String) {
    use axum::{Router, routing::get};
    use tokio::net::TcpListener;

    let app = Router::new().route("/healthz", get(|| async { "OK" }));
    match TcpListener::bind(&bind_addr).await {
        Ok(listener) => {
            if let Err(err) = axum::serve(listener, app).await {
                error!(error = %err, "health server failed");
            }
        }
        Err(err) => {
            error!(error = %err, "failed to bind health server");
        }
    }
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
    match state.get_created_after().await? {
        Some(raw) => match DateTime::parse_from_rfc3339(&raw) {
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
        },
        None => {
            let now = Utc::now();
            state.set_created_after(&now.to_rfc3339()).await?;
            Ok(now)
        }
    }
}

fn env_flag(name: &str) -> bool {
    std::env::var(name)
        .map(|value| matches!(value.to_lowercase().as_str(), "1" | "true" | "yes"))
        .unwrap_or(false)
}

async fn run_schedule_loop(
    service: &ReviewService,
    schedule: Schedule,
    tz: chrono_tz::Tz,
    mut shutdown_rx: watch::Receiver<bool>,
) -> Result<()> {
    loop {
        if *shutdown_rx.borrow() {
            info!("stopping schedule loop: shutdown requested");
            return Ok(());
        }
        let now = Utc::now().with_timezone(&tz);
        let mut upcoming = schedule.upcoming(tz);
        let next = upcoming
            .next()
            .ok_or_else(|| anyhow::anyhow!("cron has no future times"))?;
        let delay = (next - now)
            .to_std()
            .unwrap_or_else(|_| Duration::from_secs(0));
        let sleep = tokio::time::sleep(delay);
        tokio::pin!(sleep);
        tokio::select! {
            _ = &mut sleep => {}
            changed = shutdown_rx.changed() => match changed {
                Ok(()) if *shutdown_rx.borrow() => {
                    info!("stopping schedule loop: shutdown requested");
                    return Ok(());
                }
                Ok(()) => continue,
                Err(_) => return Ok(()),
            },
        }
        if *shutdown_rx.borrow() {
            info!("stopping schedule loop: shutdown requested");
            return Ok(());
        }
        if let Err(err) = service.scan_once_incremental().await {
            warn!(error = %err, "scheduled scan failed");
        }
    }
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
