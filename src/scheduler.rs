use anyhow::{Context, Result};
use async_trait::async_trait;
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

use crate::background_tasks::BackgroundTasks;
use crate::bootstrap::BootstrappedRuntime;
use crate::codex_runner::CodexRunner;
use crate::dev_mode::DevToolsService;
use crate::gitlab_discovery_mcp::GitLabDiscoveryMcpService;
use crate::http::{AdminService, HttpServices, run_http_server_with_dev_tools};
use crate::lifecycle::ServiceLifecycleSignal;
use crate::review::{ReviewService, ScanRunStatus};
use crate::state::{ReviewStateStore, ScanMode, ScanOutcome};

mod transcript_retention;

// Give accepted writes 30 seconds to persist without an unbounded exit delay.
const SQLITE_SHUTDOWN_DRAIN_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ScheduledWakeReason {
    Cron,
    PendingRateLimit,
    ReviewBackoff,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ScheduledWake {
    at: DateTime<Utc>,
    reason: ScheduledWakeReason,
}

enum ScheduledWait {
    Ready,
    Recalculate,
    ShutdownRequested,
    ChannelClosed,
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

#[async_trait]
pub(crate) trait HttpServerLauncher: Send + Sync {
    async fn launch(
        &self,
        bind_addr: String,
        http_services: Arc<HttpServices>,
        dev_tools: Option<Arc<DevToolsService>>,
        background_tasks: &BackgroundTasks,
    ) -> Result<()>;
}

struct DefaultHttpServerLauncher;

#[async_trait]
impl HttpServerLauncher for DefaultHttpServerLauncher {
    async fn launch(
        &self,
        bind_addr: String,
        http_services: Arc<HttpServices>,
        dev_tools: Option<Arc<DevToolsService>>,
        background_tasks: &BackgroundTasks,
    ) -> Result<()> {
        let listener = tokio::net::TcpListener::bind(&bind_addr)
            .await
            .with_context(|| format!("bind HTTP server on {bind_addr}"))?;
        background_tasks.spawn_listener(
            "HTTP server",
            run_http_server_with_dev_tools(
                listener,
                http_services,
                dev_tools,
                background_tasks.cancellation(),
            ),
        );
        Ok(())
    }
}

pub(crate) async fn run(runtime: BootstrappedRuntime) -> Result<()> {
    let signal_source = OsShutdownSignalSource;
    let http_launcher = DefaultHttpServerLauncher;
    run_with_hooks(runtime, &signal_source, &http_launcher).await
}

/// Stops runs, usage sessions, writes, and background tasks after the scheduler exits.
/// Scheduler errors take precedence over usage cleanup and SQLite drain errors.
pub(crate) async fn run_with_hooks(
    runtime: BootstrappedRuntime,
    signal_source: &dyn ShutdownSignalSource,
    http_launcher: &dyn HttpServerLauncher,
) -> Result<()> {
    let runner = Arc::clone(&runtime.runner);
    let service = Arc::clone(&runtime.service);
    let state = Arc::clone(&runtime.state);
    let background_tasks = runtime.state.background_tasks();
    let result = run_until_stopped(runtime, signal_source, http_launcher).await;
    // Scans do not wait for their runs, so runs can still be active on every exit path.
    // Stop them and wait for their cleanup before the runner and the state store close.
    service.request_shutdown();
    recover_interrupted_reviews(
        service.as_ref(),
        "shutdown recovery of interrupted reviews failed",
    )
    .await;
    service.wait_for_active_tasks().await;
    let cleanup = shutdown_usage_sessions(runner.as_ref()).await;
    let drain = drain_background_writes(state.as_ref()).await;
    background_tasks.shutdown().await;
    result.and(cleanup).and(drain)
}

/// Reports usage cleanup failures and returns them for the final exit result.
async fn shutdown_usage_sessions(runner: &dyn CodexRunner) -> Result<()> {
    let cleanup = runner.shutdown_usage_sessions().await;
    if let Err(error) = &cleanup {
        warn!(error = %error, "Failed to shut down Usage sessions");
    }
    cleanup
}

/// Bounds the SQLite drain and reports failures without preventing task shutdown.
async fn drain_background_writes(state: &ReviewStateStore) -> Result<()> {
    let drain = tokio::time::timeout(
        SQLITE_SHUTDOWN_DRAIN_TIMEOUT,
        state.shutdown_background_writes(),
    )
    .await
    .context("sqlite background drain timed out")
    .and_then(|result| result);
    if let Err(error) = &drain {
        warn!(error = %error, "sqlite background drain failed");
    }
    drain
}

async fn run_until_stopped(
    runtime: BootstrappedRuntime,
    signal_source: &dyn ShutdownSignalSource,
    http_launcher: &dyn HttpServerLauncher,
) -> Result<()> {
    let BootstrappedRuntime {
        config,
        run_once,
        service,
        state,
        http_services,
        gitlab_discovery_mcp,
        dev_tools,
        runner,
        ..
    } = runtime;

    recover_interrupted_reviews(
        service.as_ref(),
        "startup recovery of interrupted reviews failed",
    )
    .await;
    recover_startup_scan_status(http_services.admin.as_ref()).await;

    // Bind HTTP before scans can admit runs.
    let background_tasks = state.background_tasks();
    http_launcher
        .launch(
            config.server.bind_addr.clone(),
            Arc::clone(&http_services),
            dev_tools.clone(),
            &background_tasks,
        )
        .await?;

    let _startup_warmup = spawn_startup_warmup(runner, &state.background_tasks());
    let _transcript_retention = transcript_retention::spawn(
        Arc::clone(&state),
        config.database.transcript_retention_days,
        &background_tasks,
    );

    if run_once {
        return run_single_scan(
            service.as_ref(),
            http_services.admin.as_ref(),
            gitlab_discovery_mcp.as_ref(),
            &background_tasks,
        )
        .await;
    }

    let shutdown_signal = async {
        tokio::select! {
            signal = signal_source.wait_for_shutdown_signal() => signal,
            error = background_tasks.wait_for_listener_failure() => Err(error),
        }
    };
    tokio::pin!(shutdown_signal);

    // The startup scan queues runs and returns. Parse the schedule first, so a bad
    // schedule stops startup before any run starts.
    let tz = parse_timezone(config.schedule.timezone.as_deref())?;
    let schedule = Schedule::from_str(&config.schedule.cron).with_context(|| {
        format!(
            "invalid cron expression '{}'. Expected 6 fields (sec min hour day month dow) like '0 */10 * * * *' or a shorthand like '@hourly'",
            config.schedule.cron
        )
    })?;

    info!("starting scan loop");
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let initial_scan_service = Arc::clone(&service);
    let initial_scan_admin_service = Arc::clone(&http_services.admin);
    let mut initial_scan = state.background_tasks().spawn(async move {
        run_tracked_scan(
            initial_scan_admin_service.as_ref(),
            ScanMode::Full,
            initial_scan_service.queue_full_scan(),
        )
        .await
    });
    tokio::select! {
        signal_result = &mut shutdown_signal => {
            return stop_scheduler_task(
                signal_result,
                "initial scan",
                initial_scan,
                service.as_ref(),
                http_services.admin.as_ref(),
                gitlab_discovery_mcp.as_ref(),
                &shutdown_tx,
            )
            .await;
        }
        initial_result = &mut initial_scan => {
            log_initial_scan_result(initial_result);
        }
    }

    let scheduled_service = Arc::clone(&service);
    let scheduled_admin_service = Arc::clone(&http_services.admin);
    let mut scheduled_loop = state.background_tasks().spawn(async move {
        run_schedule_loop(
            scheduled_service.as_ref(),
            scheduled_admin_service.as_ref(),
            schedule,
            tz,
            shutdown_rx,
        )
        .await
    });

    tokio::select! {
        signal_result = &mut shutdown_signal => {
            stop_scheduler_task(
                signal_result,
                "schedule loop",
                scheduled_loop,
                service.as_ref(),
                http_services.admin.as_ref(),
                gitlab_discovery_mcp.as_ref(),
                &shutdown_tx,
            )
            .await
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

/// Runs once without subscribing to OS signals. Listener failure still stops the scan.
async fn run_single_scan(
    service: &ReviewService,
    admin_service: &AdminService,
    gitlab_discovery_mcp: Option<&Arc<GitLabDiscoveryMcpService>>,
    background_tasks: &BackgroundTasks,
) -> Result<()> {
    prepare_single_scan(admin_service).await;
    supervise_single_scan(
        service,
        admin_service,
        gitlab_discovery_mcp,
        background_tasks,
    )
    .await?;
    info!("single scan complete");
    Ok(())
}

/// Single-scan mode clears any persisted scheduled wake before scan admission.
async fn prepare_single_scan(admin_service: &AdminService) {
    info!("running single scan");
    clear_next_scan_status(admin_service).await;
}

/// Listener failure cancels the scan and waits for it before returning the listener error.
async fn supervise_single_scan(
    service: &ReviewService,
    admin_service: &AdminService,
    gitlab_discovery_mcp: Option<&Arc<GitLabDiscoveryMcpService>>,
    background_tasks: &BackgroundTasks,
) -> Result<()> {
    let scan = run_tracked_scan(admin_service, ScanMode::Full, service.scan_once());
    tokio::pin!(scan);
    tokio::select! {
        result = &mut scan => result?,
        error = background_tasks.wait_for_listener_failure() => {
            stop_single_scan(service, admin_service, gitlab_discovery_mcp, scan).await;
            return Err(error);
        }
    }
    Ok(())
}

/// Requests a fast stop and waits for the interrupted scan before reporting listener failure.
async fn stop_single_scan<F>(
    service: &ReviewService,
    admin_service: &AdminService,
    gitlab_discovery_mcp: Option<&Arc<GitLabDiscoveryMcpService>>,
    scan: F,
) where
    F: Future<Output = Result<()>>,
{
    let (shutdown_tx, _) = watch::channel(false);
    handle_service_signal(
        ServiceLifecycleSignal::FastStop,
        service,
        admin_service,
        gitlab_discovery_mcp,
        &shutdown_tx,
    )
    .await;
    report_single_scan_shutdown(scan.await);
}

/// A scan failure during shutdown must not replace the listener failure.
fn report_single_scan_shutdown(result: Result<()>) {
    if let Err(scan_error) = result {
        warn!(error = %scan_error, "single scan failed during shutdown");
    }
}

/// A signal-source failure uses a fast stop. The original signal result remains the exit result.
async fn stop_scheduler_task(
    signal_result: Result<ServiceLifecycleSignal>,
    label: &str,
    task: JoinHandle<Result<()>>,
    service: &ReviewService,
    admin_service: &AdminService,
    gitlab_discovery_mcp: Option<&Arc<GitLabDiscoveryMcpService>>,
    shutdown_tx: &watch::Sender<bool>,
) -> Result<()> {
    let signal = *signal_result
        .as_ref()
        .unwrap_or(&ServiceLifecycleSignal::FastStop);
    handle_service_signal(
        signal,
        service,
        admin_service,
        gitlab_discovery_mcp,
        shutdown_tx,
    )
    .await;
    log_task_result(label, task.await);
    if matches!(signal, ServiceLifecycleSignal::GracefulDrain) {
        finalize_graceful_drain(service, gitlab_discovery_mcp).await;
    }
    signal_result.map(|_| ())
}

/// Initial scan failures are reported, but they do not prevent scheduled scans.
fn log_initial_scan_result(result: std::result::Result<Result<()>, tokio::task::JoinError>) {
    let (error, message) = match result {
        Ok(Ok(())) => return,
        Ok(Err(error)) => (format!("{error:#}"), "initial scan failed"),
        Err(error) => (error.to_string(), "initial scan task failed"),
    };
    warn!(error = %error, "{message}");
}

fn spawn_startup_warmup(
    runner: Arc<dyn CodexRunner>,
    background_tasks: &BackgroundTasks,
) -> JoinHandle<()> {
    let cancellation = background_tasks.cancellation();
    background_tasks.spawn(async move {
        tokio::select! {
            () = cancellation.cancelled() => {}
            result = runner.warm_up_images() => {
                if let Err(err) = result {
                    warn!(error = %err, "startup docker image warm-up failed");
                }
            }
        }
    })
}

fn parse_timezone(value: Option<&str>) -> Result<chrono_tz::Tz> {
    match value {
        Some(tz) => Ok(chrono_tz::Tz::from_str(tz)?),
        None => Ok(chrono_tz::UTC),
    }
}

/// Reports scan failures and continues scheduling. Missing future cron times stop the loop.
async fn run_schedule_loop(
    service: &ReviewService,
    admin_service: &AdminService,
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
            record_schedule_shutdown(admin_service).await;
            return Ok(());
        }

        let now = Utc::now().with_timezone(&tz);
        let next_pending_retry_at = load_pending_retry_at(service).await;
        let next_review_backoff_at = service.next_review_backoff_retry_at();
        let scheduled_wake = select_next_wake(
            now.with_timezone(&Utc),
            next_cron_at,
            next_pending_retry_at,
            next_review_backoff_at,
        );
        persist_next_scan_status(admin_service, scheduled_wake.at).await;

        let delay = (scheduled_wake.at.with_timezone(&tz) - now)
            .to_std()
            .unwrap_or_else(|_| Duration::from_secs(0));
        match wait_for_scheduled_wake(service, delay, &mut shutdown_rx).await {
            ScheduledWait::Ready => {}
            ScheduledWait::Recalculate => continue,
            ScheduledWait::ShutdownRequested => {
                record_schedule_shutdown(admin_service).await;
                return Ok(());
            }
            ScheduledWait::ChannelClosed => return Ok(()),
        }

        if *shutdown_rx.borrow() {
            record_schedule_shutdown(admin_service).await;
            return Ok(());
        }

        let scan_result = run_scheduled_scan(service, admin_service, scheduled_wake.reason).await;
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

/// A retry lookup failure leaves cron and in-memory backoff wakes available.
async fn load_pending_retry_at(service: &ReviewService) -> Option<DateTime<Utc>> {
    match service.next_pending_rate_limit_retry_at().await {
        Ok(value) => value,
        Err(err) => {
            warn!(error = %err, "failed to load next pending review wake time");
            None
        }
    }
}

/// Status persistence failures do not prevent the scheduled wake.
async fn persist_next_scan_status(admin_service: &AdminService, at: DateTime<Utc>) {
    if let Err(err) = admin_service.set_next_scan_at(Some(at)).await {
        warn!(error = %err, "failed to persist next scheduled scan status");
    }
}

/// Clearing status is best effort so shutdown can continue after a storage failure.
async fn clear_next_scan_status(admin_service: &AdminService) {
    if let Err(err) = admin_service.clear_next_scan_at().await {
        warn!(error = %err, "failed to clear next scheduled scan status");
    }
}

/// Clears the next wake and reports shutdown. Storage failure does not delay loop exit.
async fn record_schedule_shutdown(admin_service: &AdminService) {
    clear_next_scan_status(admin_service).await;
    info!("stopping schedule loop: shutdown requested");
}

/// A finished run can add an earlier retry. Channel closure exits without clearing scan status.
async fn wait_for_scheduled_wake(
    service: &ReviewService,
    delay: Duration,
    shutdown_rx: &mut watch::Receiver<bool>,
) -> ScheduledWait {
    let sleep = tokio::time::sleep(delay);
    tokio::pin!(sleep);
    tokio::select! {
        () = &mut sleep => ScheduledWait::Ready,
        () = service.wait_for_run_finished() => ScheduledWait::Recalculate,
        changed = shutdown_rx.changed() => match changed {
            Ok(()) if *shutdown_rx.borrow() => ScheduledWait::ShutdownRequested,
            Ok(()) => ScheduledWait::Recalculate,
            Err(_) => ScheduledWait::ChannelClosed,
        },
    }
}

/// All wake reasons record an incremental scan. Failures return to the loop for reporting.
async fn run_scheduled_scan(
    service: &ReviewService,
    admin_service: &AdminService,
    reason: ScheduledWakeReason,
) -> Result<()> {
    match reason {
        ScheduledWakeReason::Cron => {
            run_tracked_scan(
                admin_service,
                ScanMode::Incremental,
                service.scan_once_incremental(),
            )
            .await
        }
        ScheduledWakeReason::PendingRateLimit => {
            run_tracked_scan(
                admin_service,
                ScanMode::Incremental,
                service.queue_due_pending_retries(),
            )
            .await
        }
        ScheduledWakeReason::ReviewBackoff => {
            run_tracked_scan(
                admin_service,
                ScanMode::Incremental,
                service.queue_due_review_backoff_retries(),
            )
            .await
        }
    }
}

fn select_next_wake(
    now: DateTime<Utc>,
    next_cron_at: DateTime<Utc>,
    next_pending_retry_at: Option<DateTime<Utc>>,
    next_review_backoff_at: Option<DateTime<Utc>>,
) -> ScheduledWake {
    if next_cron_at <= now {
        return ScheduledWake {
            at: next_cron_at,
            reason: ScheduledWakeReason::Cron,
        };
    }

    let mut wake = ScheduledWake {
        at: next_cron_at,
        reason: ScheduledWakeReason::Cron,
    };
    if let Some(next_pending_retry_at) = next_pending_retry_at
        && next_pending_retry_at < wake.at
    {
        wake = ScheduledWake {
            at: next_pending_retry_at,
            reason: ScheduledWakeReason::PendingRateLimit,
        };
    }
    if let Some(next_review_backoff_at) = next_review_backoff_at
        && next_review_backoff_at < wake.at
    {
        wake = ScheduledWake {
            at: next_review_backoff_at,
            reason: ScheduledWakeReason::ReviewBackoff,
        };
    }
    wake
}

/// Records scan status without letting persistence failures prevent or replace the scan result.
pub(crate) async fn run_tracked_scan<F>(
    admin_service: &AdminService,
    mode: ScanMode,
    scan: F,
) -> Result<()>
where
    F: Future<Output = Result<ScanRunStatus>>,
{
    if let Err(err) = admin_service.mark_scan_started(mode).await {
        warn!(error = %err, ?mode, "failed to persist scan start status");
    }

    let result = scan.await;
    let (outcome, error, failure_message) = match &result {
        Ok(ScanRunStatus::Interrupted) => (
            ScanOutcome::Failure,
            Some("scan interrupted by shutdown".to_string()),
            "failed to persist interrupted scan status",
        ),
        Ok(ScanRunStatus::Completed) => (
            ScanOutcome::Success,
            None,
            "failed to persist successful scan status",
        ),
        Err(err) => (
            ScanOutcome::Failure,
            Some(err.to_string()),
            "failed to persist failed scan status",
        ),
    };

    if let Err(status_err) = admin_service.mark_scan_finished(mode, outcome, error).await {
        warn!(error = %status_err, ?mode, "{failure_message}");
    }
    result.map(|_| ())
}

/// Fast stop cancels runs and reconciles state. Graceful drain lets started runs finish.
async fn handle_service_signal(
    signal: ServiceLifecycleSignal,
    service: &ReviewService,
    admin_service: &AdminService,
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
            recover_interrupted_reviews(service, "shutdown recovery of interrupted reviews failed")
                .await;
            reconcile_shutdown_history(admin_service).await;
        }
    }
}

/// Recovery failures are reported so startup or shutdown can continue.
async fn recover_interrupted_reviews(service: &ReviewService, failure_message: &str) {
    if let Err(err) = service.recover_in_progress_reviews().await {
        warn!(error = %err, "{failure_message}");
    }
}

/// Startup status failures are reported without preventing HTTP startup or scan admission.
async fn recover_startup_scan_status(admin_service: &AdminService) {
    if let Err(err) = admin_service.recover_startup_status().await {
        warn!(error = %err, "failed to reconcile startup scan status");
    }
}

/// History failures are reported without preventing task cleanup.
async fn reconcile_shutdown_history(admin_service: &AdminService) {
    if let Err(err) = admin_service.reconcile_interrupted_run_history().await {
        warn!(error = %err, "shutdown reconciliation of run history failed");
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
    use crate::bootstrap::{BootstrapOptions, bootstrap_runtime_from_config};
    use crate::codex_runner::{
        CodexResult, CodexRunner, MentionCommandContext, MentionCommandResult, ReviewContext,
    };
    use crate::config::apply_dev_mode_profile;
    use crate::config::{Config, test_builder::ConfigBuilder, validate_config};
    use crate::review::DynamicRepoSource;
    use crate::state::build_review_state_store;
    use anyhow::anyhow;
    use async_trait::async_trait;
    use sqlx::Executor;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio::sync::Notify;

    type EventLog = Arc<std::sync::Mutex<Vec<&'static str>>>;

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

    struct ImmediateSignalSource(Option<ServiceLifecycleSignal>);

    struct PendingSignalSource;

    impl ShutdownSignalSource for PendingSignalSource {
        fn wait_for_shutdown_signal(
            &self,
        ) -> Pin<Box<dyn Future<Output = Result<ServiceLifecycleSignal>> + Send + '_>> {
            Box::pin(std::future::pending())
        }
    }

    struct EndingHttpServerLauncher;

    #[async_trait]
    impl HttpServerLauncher for EndingHttpServerLauncher {
        async fn launch(
            &self,
            bind_addr: String,
            http_services: Arc<HttpServices>,
            dev_tools: Option<Arc<DevToolsService>>,
            background_tasks: &BackgroundTasks,
        ) -> Result<()> {
            let listener = tokio::net::TcpListener::bind(bind_addr).await?;
            let cancellation = tokio_util::sync::CancellationToken::new();
            cancellation.cancel();
            background_tasks.spawn_listener(
                "HTTP server",
                run_http_server_with_dev_tools(listener, http_services, dev_tools, cancellation),
            );
            Ok(())
        }
    }

    impl ShutdownSignalSource for ImmediateSignalSource {
        fn wait_for_shutdown_signal(
            &self,
        ) -> Pin<Box<dyn Future<Output = Result<ServiceLifecycleSignal>> + Send + '_>> {
            Box::pin(async { self.0.ok_or_else(|| anyhow!("signal source failed")) })
        }
    }

    #[async_trait]
    impl HttpServerLauncher for RecordingHttpServerLauncher {
        async fn launch(
            &self,
            _bind_addr: String,
            _http_services: Arc<HttpServices>,
            _dev_tools: Option<Arc<DevToolsService>>,
            background_tasks: &BackgroundTasks,
        ) -> Result<()> {
            self.launches.fetch_add(1, Ordering::SeqCst);
            background_tasks.spawn(async {});
            Ok(())
        }
    }

    #[tokio::test]
    async fn tracked_scan_runs_even_when_status_state_is_malformed() -> Result<()> {
        let config = test_config();
        let state = build_review_state_store(&config).await?;
        state
            .pool()
            .execute(sqlx::query(
                "INSERT INTO service_state (key, value) VALUES ('scan_status', 'not-json')",
            ))
            .await?;
        let http_services = HttpServices::new(config, state, false, None);

        let executed = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let executed_flag = Arc::clone(&executed);

        run_tracked_scan(http_services.admin.as_ref(), ScanMode::Full, async move {
            executed_flag.store(true, std::sync::atomic::Ordering::SeqCst);
            Ok(ScanRunStatus::Completed)
        })
        .await?;

        assert!(executed.load(std::sync::atomic::Ordering::SeqCst));
        Ok(())
    }

    #[tokio::test]
    async fn tracked_scan_persists_completion_and_returns_scan_errors() -> Result<()> {
        use crate::state::ScanState;

        let config = test_config();
        let state = build_review_state_store(&config).await?;
        let http_services = HttpServices::new(config, Arc::clone(&state), false, None);
        let cases = [
            (Ok(ScanRunStatus::Completed), ScanOutcome::Success, None),
            (
                Ok(ScanRunStatus::Interrupted),
                ScanOutcome::Failure,
                Some("scan interrupted by shutdown"),
            ),
            (
                Err(anyhow!("repository discovery failed")),
                ScanOutcome::Failure,
                Some("repository discovery failed"),
            ),
        ];

        for (scan_result, outcome, error) in cases {
            let scan_error = scan_result.as_ref().err().map(ToString::to_string);
            let result = run_tracked_scan(http_services.admin.as_ref(), ScanMode::Full, async {
                let status = state.service_state.get_scan_status().await?;
                assert_eq!(status.state, ScanState::Scanning);
                assert_eq!(status.mode, Some(ScanMode::Full));
                scan_result
            })
            .await;

            assert_eq!(result.err().map(|err| err.to_string()), scan_error);
            let status = state.service_state.get_scan_status().await?;
            assert_eq!(status.state, ScanState::Idle);
            assert_eq!(status.mode, Some(ScanMode::Full));
            assert_eq!(status.outcome, Some(outcome));
            assert_eq!(status.error.as_deref(), error);
            assert!(status.started_at.is_some());
            assert!(status.finished_at.is_some());
        }
        Ok(())
    }

    #[tokio::test]
    async fn schedule_shutdown_clears_status_but_channel_closure_keeps_it() -> Result<()> {
        let events = Arc::new(std::sync::Mutex::new(Vec::new()));
        let warmup_started = Arc::new(Notify::new());
        let runner = Arc::new(BlockingWarmupRunner {
            events: Arc::clone(&events),
            warmup_started: Arc::clone(&warmup_started),
            release_warmup: Arc::new(Notify::new()),
            release_scan_on_stop: None,
        });
        let runtime =
            runtime_with_recording_sources(Arc::clone(&events), warmup_started, runner).await?;
        let admin_service = runtime.http_services.admin.as_ref();
        let schedule = Schedule::from_str("@yearly")?;
        admin_service.set_next_scan_at(Some(Utc::now())).await?;

        let (_shutdown_tx, shutdown_rx) = watch::channel(true);
        run_schedule_loop(
            runtime.service.as_ref(),
            admin_service,
            schedule.clone(),
            chrono_tz::UTC,
            shutdown_rx,
        )
        .await?;
        let status = runtime.state.service_state.get_scan_status().await?;
        assert!(status.next_scan_at.is_none());

        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        drop(shutdown_tx);
        tokio::time::timeout(
            Duration::from_secs(5),
            run_schedule_loop(
                runtime.service.as_ref(),
                admin_service,
                schedule,
                chrono_tz::UTC,
                shutdown_rx,
            ),
        )
        .await??;
        let status = runtime.state.service_state.get_scan_status().await?;
        assert!(status.next_scan_at.is_some());
        assert!(events.lock().unwrap().is_empty());
        Ok(())
    }

    #[tokio::test]
    async fn run_once_path_can_be_tested_without_waiting_for_os_signals() -> Result<()> {
        let mut config = test_config();
        apply_dev_mode_profile(&mut config);
        let runtime = bootstrap_runtime_from_config(
            validate_config(config)?,
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

    #[tokio::test]
    async fn run_once_starts_image_warmup_before_scanning_without_waiting_for_it() -> Result<()> {
        let events = Arc::new(std::sync::Mutex::new(Vec::new()));
        let warmup_started = Arc::new(Notify::new());
        let release_warmup = Arc::new(Notify::new());
        let runner = Arc::new(BlockingWarmupRunner {
            events: Arc::clone(&events),
            warmup_started: Arc::clone(&warmup_started),
            release_warmup: Arc::clone(&release_warmup),
            release_scan_on_stop: None,
        });
        let runner_reference = Arc::downgrade(&runner);
        let runtime =
            runtime_with_recording_sources(Arc::clone(&events), warmup_started, runner).await?;
        let launch_count = Arc::new(AtomicUsize::new(0));
        let launcher = RecordingHttpServerLauncher {
            launches: Arc::clone(&launch_count),
        };

        let result = tokio::time::timeout(
            Duration::from_millis(250),
            run_with_hooks(runtime, &PanicSignalSource, &launcher),
        )
        .await;
        release_warmup.notify_waiters();
        result.context("run_once scan should not wait for warmup to finish")??;

        assert_eq!(
            *events.lock().expect("event log lock"),
            vec!["warmup", "resolve_repos", "usage_shutdown"]
        );
        assert_eq!(launch_count.load(Ordering::SeqCst), 1);
        assert!(
            runner_reference.upgrade().is_none(),
            "single scan must cancel and join its background warmup"
        );
        Ok(())
    }

    #[tokio::test]
    async fn listener_failure_during_single_scan_keeps_listener_error_and_cleans_up() -> Result<()>
    {
        let events = Arc::new(std::sync::Mutex::new(Vec::new()));
        let warmup_started = Arc::new(Notify::new());
        let scan_started = Arc::new(Notify::new());
        let release_scan = Arc::new(Notify::new());
        let runner = Arc::new(BlockingWarmupRunner {
            events: Arc::clone(&events),
            warmup_started: Arc::clone(&warmup_started),
            release_warmup: Arc::new(Notify::new()),
            release_scan_on_stop: Some(Arc::clone(&release_scan)),
        });
        let runner_reference = Arc::downgrade(&runner);
        let mut runtime = runtime_with_recording_sources(
            Arc::clone(&events),
            Arc::clone(&warmup_started),
            runner,
        )
        .await?;
        let service = Arc::try_unwrap(runtime.service)
            .ok()
            .expect("test owns the review service");
        runtime.service = Arc::new(service.with_dynamic_repo_source(Arc::new(
            RecordingRepoSource {
                events: Arc::clone(&events),
                warmup_started,
                blocked_scan: Some(BlockedScan {
                    started: Arc::clone(&scan_started),
                    release: release_scan,
                }),
            },
        )));
        let state = Arc::clone(&runtime.state);
        let background_tasks = state.background_tasks();
        background_tasks.spawn_listener("HTTP server", async move {
            scan_started.notified().await;
            Err(anyhow!("listener stopped during single scan"))
        });
        let launcher = RecordingHttpServerLauncher {
            launches: Arc::new(AtomicUsize::new(0)),
        };

        let error = tokio::time::timeout(
            Duration::from_secs(5),
            run_with_hooks(runtime, &PanicSignalSource, &launcher),
        )
        .await?
        .expect_err("listener failure must fail run-once mode");

        assert_eq!(
            error.to_string(),
            "HTTP server failed: listener stopped during single scan"
        );
        let status = state.service_state.get_scan_status().await?;
        assert_eq!(status.outcome, Some(ScanOutcome::Failure));
        assert_eq!(
            status.error.as_deref(),
            Some("repository discovery failed during stop")
        );
        assert_eq!(
            *events.lock().unwrap(),
            vec!["warmup", "resolve_repos", "usage_shutdown"]
        );
        assert!(background_tasks.cancellation().is_cancelled());
        assert!(runner_reference.upgrade().is_none());
        Ok(())
    }

    #[tokio::test]
    async fn scheduler_shuts_down_usage_after_signals_and_errors() -> Result<()> {
        for signal in [
            Some(ServiceLifecycleSignal::GracefulDrain),
            Some(ServiceLifecycleSignal::FastStop),
            None,
        ] {
            let events = Arc::new(std::sync::Mutex::new(Vec::new()));
            let warmup_started = Arc::new(Notify::new());
            let release_warmup = Arc::new(Notify::new());
            let runner = Arc::new(BlockingWarmupRunner {
                events: events.clone(),
                warmup_started: warmup_started.clone(),
                release_warmup: release_warmup.clone(),
                release_scan_on_stop: None,
            });
            let mut runtime =
                runtime_with_recording_sources(events.clone(), warmup_started, runner).await?;
            runtime.run_once = false;
            let launcher = RecordingHttpServerLauncher {
                launches: Arc::new(AtomicUsize::new(0)),
            };
            let result = tokio::time::timeout(
                Duration::from_secs(5),
                run_with_hooks(runtime, &ImmediateSignalSource(signal), &launcher),
            )
            .await?;
            release_warmup.notify_waiters();
            assert_eq!(result.is_ok(), signal.is_some());
            assert_eq!(
                events
                    .lock()
                    .unwrap()
                    .iter()
                    .filter(|event| **event == "usage_shutdown")
                    .count(),
                1
            );
        }
        Ok(())
    }

    #[tokio::test]
    async fn fast_stop_persists_accepted_background_events_and_closes_admission() -> Result<()> {
        use crate::run_history_kind::RunHistoryKind;
        use crate::state::{NewRunHistory, NewRunHistoryEvent};

        let mut config = test_config();
        apply_dev_mode_profile(&mut config);
        let runtime = bootstrap_runtime_from_config(
            validate_config(config)?,
            BootstrapOptions {
                run_once: false,
                force_dry_run: false,
                log_all_json: false,
                dev_mode: true,
            },
        )
        .await?;
        let state = Arc::clone(&runtime.state);
        let run_id = state
            .run_history
            .start_run_history(NewRunHistory {
                kind: RunHistoryKind::Review,
                repo: "group/repo".to_string(),
                iid: 1,
                head_sha: "sha".to_string(),
                discussion_id: None,
                trigger_note_id: None,
                trigger_note_author_name: None,
                trigger_note_body: None,
                command_repo: None,
            })
            .await?;
        let pause = state.pause_background_writes_for_test().await;
        for sequence in 1..=5 {
            state
                .run_history
                .append_run_history_events_bg(
                    run_id,
                    vec![NewRunHistoryEvent {
                        sequence,
                        turn_id: None,
                        event_type: "turn_started".to_string(),
                        payload: serde_json::json!({}),
                    }],
                )
                .await?;
        }
        let release = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(100)).await;
            drop(pause);
        });
        let launcher = RecordingHttpServerLauncher {
            launches: Arc::new(AtomicUsize::new(0)),
        };
        run_with_hooks(
            runtime,
            &ImmediateSignalSource(Some(ServiceLifecycleSignal::FastStop)),
            &launcher,
        )
        .await?;
        release.await?;
        assert_eq!(
            state
                .run_history
                .list_run_history_events(run_id)
                .await?
                .len(),
            5,
            "FastStop must persist all accepted events"
        );
        assert!(
            state
                .run_history
                .append_run_history_events_bg(
                    run_id,
                    vec![NewRunHistoryEvent {
                        sequence: 6,
                        turn_id: None,
                        event_type: "turn_started".to_string(),
                        payload: serde_json::json!({}),
                    }]
                )
                .await
                .is_err(),
            "shutdown must reject new background writes"
        );
        Ok(())
    }

    #[tokio::test]
    async fn occupied_http_port_fails_before_scan_admission() -> Result<()> {
        let occupied = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let events = Arc::new(std::sync::Mutex::new(Vec::new()));
        let warmup_started = Arc::new(Notify::new());
        let runner = Arc::new(BlockingWarmupRunner {
            events: events.clone(),
            warmup_started: warmup_started.clone(),
            release_warmup: Arc::new(Notify::new()),
            release_scan_on_stop: None,
        });
        let mut runtime =
            runtime_with_recording_sources(events.clone(), warmup_started, runner).await?;
        let mut config = runtime.config.clone().into_inner();
        config.server.bind_addr = occupied.local_addr()?.to_string();
        runtime.config = validate_config(config)?;

        let error = run_with_hooks(runtime, &PanicSignalSource, &DefaultHttpServerLauncher)
            .await
            .expect_err("an occupied HTTP port must fail startup");
        assert!(format!("{error:#}").contains("bind HTTP server"));
        assert!(!events.lock().unwrap().contains(&"resolve_repos"));
        Ok(())
    }

    #[tokio::test]
    async fn unexpected_listener_exit_stops_scheduler_with_error() -> Result<()> {
        for discovery_listener in [false, true] {
            let mut config = test_config();
            apply_dev_mode_profile(&mut config);
            let mut runtime = bootstrap_runtime_from_config(
                validate_config(config)?,
                BootstrapOptions {
                    run_once: false,
                    force_dry_run: false,
                    log_all_json: false,
                    dev_mode: true,
                },
            )
            .await?;
            let state = Arc::clone(&runtime.state);
            let launcher: &dyn HttpServerLauncher = if discovery_listener {
                &DefaultHttpServerLauncher
            } else {
                &EndingHttpServerLauncher
            };
            let release = if discovery_listener {
                let service = Arc::new(GitLabDiscoveryMcpService::new(
                    runtime.config.docker.clone(),
                    &runtime.config.gitlab,
                    crate::config::GitLabDiscoveryMcpConfig {
                        bind_addr: "127.0.0.1:0".to_string(),
                        advertise_url: "http://host.docker.internal:8091/mcp".to_string(),
                        ..Default::default()
                    },
                )?);
                let listener = service.bind_listener().await?;
                state.background_tasks().spawn_listener(
                    "GitLab discovery MCP server",
                    Arc::clone(&service).run(listener),
                );
                runtime.gitlab_discovery_mcp = Some(service.clone());
                Some(tokio::spawn(async move {
                    tokio::time::sleep(Duration::from_millis(50)).await;
                    service.shutdown();
                }))
            } else {
                None
            };

            let error = tokio::time::timeout(
                Duration::from_secs(5),
                run_with_hooks(runtime, &PendingSignalSource, launcher),
            )
            .await?
            .expect_err("unexpected listener exit must stop the scheduler");
            let name = if discovery_listener {
                "GitLab discovery MCP server"
            } else {
                "HTTP server"
            };
            assert!(
                error
                    .to_string()
                    .contains(&format!("{name} exited before shutdown")),
                "{error:#}"
            );
            if let Some(release) = release {
                release.await?;
            }
        }
        Ok(())
    }

    #[test]
    fn select_next_wake_prefers_pending_retry_before_cron() {
        use chrono::TimeZone;

        let now = Utc.with_ymd_and_hms(2026, 3, 25, 12, 0, 0).unwrap();
        let cron_at = Utc.with_ymd_and_hms(2026, 3, 25, 12, 30, 0).unwrap();
        let pending_at = Utc.with_ymd_and_hms(2026, 3, 25, 12, 20, 0).unwrap();

        let wake = select_next_wake(now, cron_at, Some(pending_at), None);

        assert_eq!(wake.at, pending_at);
        assert_eq!(wake.reason, ScheduledWakeReason::PendingRateLimit);
    }

    #[test]
    fn select_next_wake_keeps_cron_when_pending_retry_is_later() {
        use chrono::TimeZone;

        let now = Utc.with_ymd_and_hms(2026, 3, 25, 12, 0, 0).unwrap();
        let cron_at = Utc.with_ymd_and_hms(2026, 3, 25, 12, 30, 0).unwrap();
        let pending_at = Utc.with_ymd_and_hms(2026, 3, 25, 12, 40, 0).unwrap();

        let wake = select_next_wake(now, cron_at, Some(pending_at), None);

        assert_eq!(wake.at, cron_at);
        assert_eq!(wake.reason, ScheduledWakeReason::Cron);
    }

    #[test]
    fn select_next_wake_prefers_due_cron_over_pending_retry() {
        use chrono::TimeZone;

        let now = Utc.with_ymd_and_hms(2026, 3, 25, 12, 31, 0).unwrap();
        let cron_at = Utc.with_ymd_and_hms(2026, 3, 25, 12, 30, 0).unwrap();
        let pending_at = Utc.with_ymd_and_hms(2026, 3, 25, 12, 20, 0).unwrap();

        let wake = select_next_wake(now, cron_at, Some(pending_at), None);

        assert_eq!(wake.at, cron_at);
        assert_eq!(wake.reason, ScheduledWakeReason::Cron);
    }

    #[test]
    fn select_next_wake_prefers_review_backoff_before_cron() {
        use chrono::TimeZone;

        let now = Utc.with_ymd_and_hms(2026, 3, 25, 12, 0, 0).unwrap();
        let cron_at = Utc.with_ymd_and_hms(2026, 3, 25, 12, 30, 0).unwrap();
        let review_backoff_at = Utc.with_ymd_and_hms(2026, 3, 25, 12, 15, 0).unwrap();

        let wake = select_next_wake(now, cron_at, None, Some(review_backoff_at));

        assert_eq!(wake.at, review_backoff_at);
        assert_eq!(wake.reason, ScheduledWakeReason::ReviewBackoff);
    }

    fn test_config() -> Config {
        ConfigBuilder::for_scheduler_tests().build()
    }

    async fn runtime_with_recording_sources(
        events: EventLog,
        warmup_started: Arc<Notify>,
        runner: Arc<BlockingWarmupRunner>,
    ) -> Result<BootstrappedRuntime> {
        let config = test_config();
        let validated_config = validate_config(config.clone())?;
        let state = build_review_state_store(&config).await?;
        let dev_tools = DevToolsService::new(&config.database.path);
        let runner = runner as Arc<dyn CodexRunner>;
        let dynamic_repo_source: Arc<dyn DynamicRepoSource> = Arc::new(RecordingRepoSource {
            events,
            warmup_started,
            blocked_scan: None,
        });
        let service = Arc::new(
            ReviewService::new(
                config.clone(),
                dev_tools.gitlab_api(),
                Arc::clone(&state),
                Arc::clone(&runner),
                1,
                Utc::now(),
            )
            .with_dynamic_repo_source(dynamic_repo_source),
        );
        let http_services = Arc::new(HttpServices::new(
            config,
            Arc::clone(&state),
            true,
            Some(Arc::clone(&runner)),
        ));

        Ok(BootstrappedRuntime {
            config: validated_config,
            run_once: true,
            state,
            runner,
            gitlab_client: None,
            service,
            http_services,
            gitlab_discovery_mcp: None,
            dev_tools: None,
        })
    }

    struct BlockingWarmupRunner {
        events: EventLog,
        warmup_started: Arc<Notify>,
        release_warmup: Arc<Notify>,
        release_scan_on_stop: Option<Arc<Notify>>,
    }

    #[async_trait]
    impl CodexRunner for BlockingWarmupRunner {
        async fn stop_active_reviews(&self) -> Result<()> {
            // Startup recovery must not release a scan that has not started.
            if self.events.lock().unwrap().contains(&"resolve_repos")
                && let Some(release) = &self.release_scan_on_stop
            {
                release.notify_one();
            }
            Ok(())
        }

        async fn shutdown_usage_sessions(&self) -> Result<()> {
            self.events
                .lock()
                .expect("event log lock")
                .push("usage_shutdown");
            Ok(())
        }

        async fn warm_up_images(&self) -> Result<()> {
            self.events.lock().expect("event log lock").push("warmup");
            self.warmup_started.notify_one();
            self.release_warmup.notified().await;
            Err(anyhow!("warmup failed after scan started"))
        }

        async fn run_review(&self, _ctx: ReviewContext) -> Result<CodexResult> {
            Err(anyhow!(
                "run_review should not be called in warmup ordering test"
            ))
        }

        async fn run_mention_command(
            &self,
            _ctx: MentionCommandContext,
        ) -> Result<MentionCommandResult> {
            Err(anyhow!(
                "run_mention_command should not be called in warmup ordering test"
            ))
        }
    }

    struct RecordingRepoSource {
        events: EventLog,
        warmup_started: Arc<Notify>,
        blocked_scan: Option<BlockedScan>,
    }

    struct BlockedScan {
        started: Arc<Notify>,
        release: Arc<Notify>,
    }

    #[async_trait]
    impl DynamicRepoSource for RecordingRepoSource {
        async fn list_repos(&self) -> Result<Vec<String>> {
            tokio::time::timeout(Duration::from_millis(100), self.warmup_started.notified())
                .await
                .context("warmup should be started before repository discovery completes")?;
            self.events
                .lock()
                .expect("event log lock")
                .push("resolve_repos");
            if let Some(scan) = &self.blocked_scan {
                scan.started.notify_one();
                scan.release.notified().await;
                return Err(anyhow!("repository discovery failed during stop"));
            }
            Ok(vec!["demo/group/service-a".to_string()])
        }
    }
}
