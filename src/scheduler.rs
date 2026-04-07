use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use cron::Schedule;
use std::future::Future;
use std::pin::Pin;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::watch;
use tokio::task::JoinHandle;
use tracing::{info, warn};

use crate::bootstrap::BootstrappedRuntime;
use crate::dev_mode::DevToolsService;
use crate::gitlab_discovery_mcp::GitLabDiscoveryMcpService;
use crate::http::{StatusService, run_http_server_with_dev_tools};
use crate::lifecycle::ServiceLifecycleSignal;
use crate::review::{ReviewService, ScanRunStatus};
use crate::state::{ScanMode, ScanOutcome};

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

pub(crate) trait ShutdownSignalSource: Send + Sync {
    fn wait_for_shutdown_signal(
        &self,
    ) -> Pin<Box<dyn Future<Output = Result<ServiceLifecycleSignal>> + Send + '_>>;
}

struct OsShutdownSignalSource;

impl ShutdownSignalSource for OsShutdownSignalSource {
    fn wait_for_shutdown_signal(
        &self,
    ) -> Pin<Box<dyn Future<Output = Result<ServiceLifecycleSignal>> + Send + '_>> {
        Box::pin(wait_for_shutdown_signal())
    }
}

pub(crate) trait HttpServerLauncher: Send + Sync {
    fn launch(
        &self,
        bind_addr: String,
        status_service: Arc<StatusService>,
        dev_tools: Option<Arc<DevToolsService>>,
    ) -> JoinHandle<()>;
}

struct DefaultHttpServerLauncher;

impl HttpServerLauncher for DefaultHttpServerLauncher {
    fn launch(
        &self,
        bind_addr: String,
        status_service: Arc<StatusService>,
        dev_tools: Option<Arc<DevToolsService>>,
    ) -> JoinHandle<()> {
        tokio::spawn(run_http_server_with_dev_tools(
            bind_addr,
            status_service,
            dev_tools,
        ))
    }
}

pub(crate) async fn run(runtime: BootstrappedRuntime) -> Result<()> {
    let signal_source = OsShutdownSignalSource;
    let http_launcher = DefaultHttpServerLauncher;
    run_with_hooks(runtime, &signal_source, &http_launcher).await
}

pub(crate) async fn run_with_hooks(
    runtime: BootstrappedRuntime,
    signal_source: &dyn ShutdownSignalSource,
    http_launcher: &dyn HttpServerLauncher,
) -> Result<()> {
    let BootstrappedRuntime {
        config,
        run_once,
        service,
        status_service,
        gitlab_discovery_mcp,
        dev_tools,
    } = runtime;

    if let Err(err) = service.recover_in_progress_reviews().await {
        warn!(error = %err, "startup recovery of interrupted reviews failed");
    }
    if let Err(err) = status_service.recover_startup_status().await {
        warn!(error = %err, "failed to reconcile startup scan status");
    }

    let _http_server = http_launcher.launch(
        config.server.bind_addr.clone(),
        Arc::clone(&status_service),
        dev_tools.clone(),
    );

    if run_once {
        info!("running single scan");
        if let Err(err) = status_service.clear_next_scan_at().await {
            warn!(error = %err, "failed to clear next scheduled scan status");
        }
        run_tracked_scan(status_service.as_ref(), ScanMode::Full, service.scan_once()).await?;
        info!("single scan complete");
        return Ok(());
    }

    let shutdown_signal = signal_source.wait_for_shutdown_signal();
    tokio::pin!(shutdown_signal);

    info!("starting scan loop");
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let initial_scan_service = Arc::clone(&service);
    let initial_scan_status_service = Arc::clone(&status_service);
    let mut initial_scan = tokio::spawn(async move {
        run_tracked_scan(
            initial_scan_status_service.as_ref(),
            ScanMode::Full,
            initial_scan_service.scan_once(),
        )
        .await
    });
    tokio::select! {
        signal_result = &mut shutdown_signal => {
            let signal = signal_result?;
            handle_service_signal(
                signal,
                service.as_ref(),
                status_service.as_ref(),
                gitlab_discovery_mcp.as_ref(),
                &shutdown_tx,
            )
            .await;
            log_task_result("initial scan", initial_scan.await);
            if matches!(signal, ServiceLifecycleSignal::GracefulDrain) {
                finalize_graceful_drain(service.as_ref(), gitlab_discovery_mcp.as_ref()).await;
            }
            return Ok(());
        }
        initial_result = &mut initial_scan => {
            if let Ok(Err(err)) = &initial_result {
                warn!(error = %format!("{err:#}"), "initial scan failed");
            } else if let Err(err) = &initial_result {
                warn!(error = %err, "initial scan task failed");
            }
        }
    }

    let tz = parse_timezone(config.schedule.timezone.as_deref())?;
    let schedule = Schedule::from_str(&config.schedule.cron).with_context(|| {
        format!(
            "invalid cron expression '{}'. Expected 6 fields (sec min hour day month dow) like '0 */10 * * * *' or a shorthand like '@hourly'",
            config.schedule.cron
        )
    })?;

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

    tokio::select! {
        signal_result = &mut shutdown_signal => {
            let signal = signal_result?;
            handle_service_signal(
                signal,
                service.as_ref(),
                status_service.as_ref(),
                gitlab_discovery_mcp.as_ref(),
                &shutdown_tx,
            )
            .await;
            log_task_result("schedule loop", scheduled_loop.await);
            if matches!(signal, ServiceLifecycleSignal::GracefulDrain) {
                finalize_graceful_drain(service.as_ref(), gitlab_discovery_mcp.as_ref()).await;
            }
            Ok(())
        }
        scheduled_result = &mut scheduled_loop => {
            match scheduled_result {
                Ok(Ok(())) => Err(anyhow::anyhow!(
                    "scheduler task exited before receiving a shutdown signal"
                )),
                Ok(Err(err)) => Err(err),
                Err(err) => Err(err.into()),
            }
        }
    }
}

fn parse_timezone(value: Option<&str>) -> Result<chrono_tz::Tz> {
    match value {
        Some(tz) => Ok(chrono_tz::Tz::from_str(tz)?),
        None => Ok(chrono_tz::UTC),
    }
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

pub(crate) async fn run_tracked_scan<F>(
    status_service: &StatusService,
    mode: ScanMode,
    scan: F,
) -> Result<()>
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

async fn handle_service_signal(
    signal: ServiceLifecycleSignal,
    service: &ReviewService,
    status_service: &StatusService,
    gitlab_discovery_mcp: Option<&Arc<GitLabDiscoveryMcpService>>,
    shutdown_tx: &watch::Sender<bool>,
) {
    match signal {
        ServiceLifecycleSignal::GracefulDrain => {
            info!("graceful drain signal received");
            service.request_graceful_drain();
            let _ = shutdown_tx.send(true);
        }
        ServiceLifecycleSignal::FastStop => {
            info!("shutdown signal received");
            service.request_shutdown();
            if let Some(service) = gitlab_discovery_mcp {
                service.shutdown();
            }
            let _ = shutdown_tx.send(true);
            if let Err(err) = service.recover_in_progress_reviews().await {
                warn!(error = %err, "shutdown recovery of interrupted reviews failed");
            }
            if let Err(err) = status_service.reconcile_interrupted_run_history().await {
                warn!(error = %err, "shutdown reconciliation of run history failed");
            }
        }
    }
}

async fn finalize_graceful_drain(
    service: &ReviewService,
    gitlab_discovery_mcp: Option<&Arc<GitLabDiscoveryMcpService>>,
) {
    service.wait_for_started_runs().await;
    service.wait_for_active_tasks().await;
    if let Some(service) = gitlab_discovery_mcp {
        service.shutdown();
    }
}

fn log_task_result(label: &str, result: std::result::Result<Result<()>, tokio::task::JoinError>) {
    match result {
        Ok(Ok(())) => {}
        Ok(Err(err)) => warn!(task = label, error = %format!("{err:#}"), "background task failed"),
        Err(err) => warn!(task = label, error = %err, "background task join failed"),
    }
}

async fn wait_for_shutdown_signal() -> Result<ServiceLifecycleSignal> {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};

        let mut terminate = signal(SignalKind::terminate()).context("listen for SIGTERM")?;
        let mut graceful_drain =
            signal(SignalKind::user_defined1()).context("listen for SIGUSR1")?;
        tokio::select! {
            _ = tokio::signal::ctrl_c() => Ok(ServiceLifecycleSignal::FastStop),
            _ = terminate.recv() => Ok(ServiceLifecycleSignal::FastStop),
            _ = graceful_drain.recv() => Ok(ServiceLifecycleSignal::GracefulDrain),
        }
    }
    #[cfg(not(unix))]
    {
        tokio::signal::ctrl_c().await.context("listen for Ctrl+C")?;
        Ok(ServiceLifecycleSignal::FastStop)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bootstrap::{BootstrapOptions, apply_dev_mode_profile, bootstrap_runtime};
    use crate::config::{
        BrowserMcpConfig, CodexConfig, Config, DatabaseConfig, DockerConfig, GitLabConfig,
        GitLabDiscoveryMcpConfig, GitLabTargets, McpServerOverridesConfig,
        ReasoningSummaryOverridesConfig, ReviewConfig, ReviewMentionCommandsConfig, ScheduleConfig,
        ServerConfig, SessionOverridesConfig, TargetSelector,
    };
    use crate::feature_flags::FeatureFlagDefaults;
    use sqlx::Executor;
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct PanicSignalSource;

    impl ShutdownSignalSource for PanicSignalSource {
        fn wait_for_shutdown_signal(
            &self,
        ) -> Pin<Box<dyn Future<Output = Result<ServiceLifecycleSignal>> + Send + '_>> {
            panic!("run_once path should not subscribe to shutdown signals")
        }
    }

    struct RecordingHttpServerLauncher {
        launches: Arc<AtomicUsize>,
    }

    impl HttpServerLauncher for RecordingHttpServerLauncher {
        fn launch(
            &self,
            _bind_addr: String,
            _status_service: Arc<StatusService>,
            _dev_tools: Option<Arc<DevToolsService>>,
        ) -> JoinHandle<()> {
            self.launches.fetch_add(1, Ordering::SeqCst);
            tokio::spawn(async {})
        }
    }

    #[tokio::test]
    async fn tracked_scan_runs_even_when_status_state_is_malformed() -> Result<()> {
        let state = Arc::new(crate::state::ReviewStateStore::new(":memory:").await?);
        state
            .pool()
            .execute(sqlx::query(
                "INSERT INTO service_state (key, value) VALUES ('scan_status', 'not-json')",
            ))
            .await?;
        let status_service = StatusService::new(test_config(), state, false, None);

        let executed = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let executed_flag = Arc::clone(&executed);

        run_tracked_scan(&status_service, ScanMode::Full, async move {
            executed_flag.store(true, std::sync::atomic::Ordering::SeqCst);
            Ok(ScanRunStatus::Completed)
        })
        .await?;

        assert!(executed.load(std::sync::atomic::Ordering::SeqCst));
        Ok(())
    }

    #[tokio::test]
    async fn run_once_path_can_be_tested_without_waiting_for_os_signals() -> Result<()> {
        let mut config = test_config();
        apply_dev_mode_profile(&mut config);
        let runtime = bootstrap_runtime(
            config,
            BootstrapOptions {
                run_once: true,
                force_dry_run: false,
                log_all_json: false,
                dev_mode: true,
            },
        )
        .await?;

        let launch_count = Arc::new(AtomicUsize::new(0));
        let launcher = RecordingHttpServerLauncher {
            launches: Arc::clone(&launch_count),
        };

        run_with_hooks(runtime, &PanicSignalSource, &launcher).await?;

        assert_eq!(launch_count.load(Ordering::SeqCst), 1);
        Ok(())
    }

    #[test]
    fn select_next_wake_prefers_pending_retry_before_cron() {
        use chrono::TimeZone;

        let now = Utc.with_ymd_and_hms(2026, 3, 25, 12, 0, 0).unwrap();
        let cron_at = Utc.with_ymd_and_hms(2026, 3, 25, 12, 30, 0).unwrap();
        let pending_at = Utc.with_ymd_and_hms(2026, 3, 25, 12, 20, 0).unwrap();

        let wake = select_next_wake(now, cron_at, Some(pending_at));

        assert_eq!(wake.at, pending_at);
        assert_eq!(wake.reason, ScheduledWakeReason::PendingRateLimit);
    }

    #[test]
    fn select_next_wake_keeps_cron_when_pending_retry_is_later() {
        use chrono::TimeZone;

        let now = Utc.with_ymd_and_hms(2026, 3, 25, 12, 0, 0).unwrap();
        let cron_at = Utc.with_ymd_and_hms(2026, 3, 25, 12, 30, 0).unwrap();
        let pending_at = Utc.with_ymd_and_hms(2026, 3, 25, 12, 40, 0).unwrap();

        let wake = select_next_wake(now, cron_at, Some(pending_at));

        assert_eq!(wake.at, cron_at);
        assert_eq!(wake.reason, ScheduledWakeReason::Cron);
    }

    #[test]
    fn select_next_wake_prefers_due_cron_over_pending_retry() {
        use chrono::TimeZone;

        let now = Utc.with_ymd_and_hms(2026, 3, 25, 12, 31, 0).unwrap();
        let cron_at = Utc.with_ymd_and_hms(2026, 3, 25, 12, 30, 0).unwrap();
        let pending_at = Utc.with_ymd_and_hms(2026, 3, 25, 12, 20, 0).unwrap();

        let wake = select_next_wake(now, cron_at, Some(pending_at));

        assert_eq!(wake.at, cron_at);
        assert_eq!(wake.reason, ScheduledWakeReason::Cron);
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
}
