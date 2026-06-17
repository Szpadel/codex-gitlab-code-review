use anyhow::{Context, Result, anyhow, bail};
use futures::future::BoxFuture;
use sqlx::{
    SqlitePool,
    sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions, SqliteSynchronous},
};
use std::future::Future;
use std::path::Path;
use std::str::FromStr;
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};
use std::time::Duration;
use tokio::sync::{Mutex, Notify, OwnedSemaphorePermit, Semaphore, mpsc};
use tracing::warn;

const BACKGROUND_QUEUE_CAPACITY: usize = 256;
const SQLITE_BUSY_RETRY_DELAYS: [Duration; 4] = [
    Duration::from_millis(25),
    Duration::from_millis(75),
    Duration::from_millis(200),
    Duration::from_millis(500),
];

type BackgroundOperation =
    Box<dyn FnMut(SqlitePool) -> BoxFuture<'static, Result<()>> + Send + 'static>;
type BackgroundFailureOperation =
    Box<dyn FnMut(SqlitePool, String) -> BoxFuture<'static, Result<()>> + Send + 'static>;

struct BackgroundJob {
    label: &'static str,
    operation: BackgroundOperation,
    on_failure: Option<BackgroundFailureOperation>,
}

#[derive(Clone)]
pub(crate) struct SqliteCoordinator {
    inner: Arc<SqliteCoordinatorInner>,
    background_tx: mpsc::Sender<BackgroundJob>,
}

struct SqliteCoordinatorInner {
    pool: SqlitePool,
    write_gate: Arc<Semaphore>,
    foreground_waiters: AtomicUsize,
    foreground_waiters_drained: Notify,
    pending_background: AtomicUsize,
    pending_background_notify: Notify,
    background_errors: Mutex<Vec<String>>,
    #[cfg(test)]
    background_pause: Arc<Mutex<()>>,
}

struct ForegroundWaiter<'a> {
    waiters: &'a AtomicUsize,
    drained: &'a Notify,
}

impl Drop for ForegroundWaiter<'_> {
    fn drop(&mut self) {
        if self.waiters.fetch_sub(1, Ordering::SeqCst) == 1 {
            self.drained.notify_waiters();
        }
    }
}

impl SqliteCoordinator {
    /// # Errors
    ///
    /// Returns an error if the `SQLite` database cannot be connected.
    pub(crate) async fn connect(path: &str) -> Result<Self> {
        let url = sqlite_url(path);
        let max_connections = if path == ":memory:" { 1 } else { 5 };
        let connect_options = sqlite_connect_options(path, &url)?;
        let pool = SqlitePoolOptions::new()
            .max_connections(max_connections)
            .connect_with(connect_options)
            .await
            .with_context(|| format!("connect sqlite database at {path}"))?;
        Ok(Self::new(pool))
    }

    pub(crate) fn new(pool: SqlitePool) -> Self {
        let (background_tx, background_rx) = mpsc::channel(BACKGROUND_QUEUE_CAPACITY);
        let inner = Arc::new(SqliteCoordinatorInner {
            pool,
            write_gate: Arc::new(Semaphore::new(1)),
            foreground_waiters: AtomicUsize::new(0),
            foreground_waiters_drained: Notify::new(),
            pending_background: AtomicUsize::new(0),
            pending_background_notify: Notify::new(),
            background_errors: Mutex::new(Vec::new()),
            #[cfg(test)]
            background_pause: Arc::new(Mutex::new(())),
        });
        spawn_background_writer(Arc::clone(&inner), background_rx);
        Self {
            inner,
            background_tx,
        }
    }

    pub(crate) fn read_pool(&self) -> &SqlitePool {
        &self.inner.pool
    }

    pub(crate) async fn write_foreground<T, F, Fut>(
        &self,
        label: &'static str,
        operation: F,
    ) -> Result<T>
    where
        F: FnMut(SqlitePool) -> Fut,
        Fut: Future<Output = Result<T>>,
    {
        self.inner.foreground_waiters.fetch_add(1, Ordering::SeqCst);
        let waiter = ForegroundWaiter {
            waiters: &self.inner.foreground_waiters,
            drained: &self.inner.foreground_waiters_drained,
        };
        let write_gate = Arc::clone(&self.inner.write_gate);
        let result =
            run_sqlite_write_with_retry(label, operation, self.inner.pool.clone(), move || {
                let write_gate = Arc::clone(&write_gate);
                async move {
                    write_gate
                        .acquire_owned()
                        .await
                        .context("acquire sqlite foreground write permit")
                }
            })
            .await;
        drop(waiter);
        result
    }

    pub(crate) async fn enqueue_background<F>(
        &self,
        label: &'static str,
        operation: F,
    ) -> Result<()>
    where
        F: FnMut(SqlitePool) -> BoxFuture<'static, Result<()>> + Send + 'static,
    {
        self.enqueue_background_job(label, operation, None).await
    }

    pub(crate) async fn enqueue_background_with_failure<F, H>(
        &self,
        label: &'static str,
        operation: F,
        on_failure: H,
    ) -> Result<()>
    where
        F: FnMut(SqlitePool) -> BoxFuture<'static, Result<()>> + Send + 'static,
        H: FnMut(SqlitePool, String) -> BoxFuture<'static, Result<()>> + Send + 'static,
    {
        self.enqueue_background_job(label, operation, Some(Box::new(on_failure)))
            .await
    }

    pub(crate) fn try_enqueue_background<F>(
        &self,
        label: &'static str,
        operation: F,
    ) -> Result<bool>
    where
        F: FnMut(SqlitePool) -> BoxFuture<'static, Result<()>> + Send + 'static,
    {
        let job = BackgroundJob {
            label,
            operation: Box::new(operation),
            on_failure: None,
        };
        match self.background_tx.try_reserve() {
            Ok(permit) => {
                self.inner.pending_background.fetch_add(1, Ordering::SeqCst);
                permit.send(job);
                Ok(true)
            }
            Err(tokio::sync::mpsc::error::TrySendError::Full(())) => Ok(false),
            Err(tokio::sync::mpsc::error::TrySendError::Closed(())) => {
                bail!("enqueue sqlite background write {label}: background writer closed")
            }
        }
    }

    async fn enqueue_background_job<F>(
        &self,
        label: &'static str,
        operation: F,
        on_failure: Option<BackgroundFailureOperation>,
    ) -> Result<()>
    where
        F: FnMut(SqlitePool) -> BoxFuture<'static, Result<()>> + Send + 'static,
    {
        let job = BackgroundJob {
            label,
            operation: Box::new(operation),
            on_failure,
        };
        let permit = self
            .background_tx
            .reserve()
            .await
            .map_err(|err| anyhow!("enqueue sqlite background write {label}: {err}"))?;
        self.inner.pending_background.fetch_add(1, Ordering::SeqCst);
        permit.send(job);
        Ok(())
    }

    /// # Errors
    ///
    /// Returns an error if any accepted background write failed since the
    /// previous flush.
    pub(crate) async fn flush_background_writes(&self) -> Result<()> {
        loop {
            if self.inner.pending_background.load(Ordering::SeqCst) == 0 {
                let mut errors = self.inner.background_errors.lock().await;
                if errors.is_empty() {
                    return Ok(());
                }
                let joined = errors.join("; ");
                errors.clear();
                bail!("sqlite background write failures: {joined}");
            }
            let notified = self.inner.pending_background_notify.notified();
            if self.inner.pending_background.load(Ordering::SeqCst) == 0 {
                continue;
            }
            notified.await;
        }
    }

    #[cfg(test)]
    pub(crate) async fn pause_background_writes_for_test(
        &self,
    ) -> tokio::sync::OwnedMutexGuard<()> {
        self.inner.background_pause.clone().lock_owned().await
    }
}

fn spawn_background_writer(
    inner: Arc<SqliteCoordinatorInner>,
    mut background_rx: mpsc::Receiver<BackgroundJob>,
) {
    tokio::spawn(async move {
        loop {
            #[cfg(test)]
            {
                let pause_guard = inner.background_pause.lock().await;
                drop(pause_guard);
            }
            let Some(job) = background_rx.recv().await else {
                break;
            };
            #[cfg(test)]
            {
                let pause_guard = inner.background_pause.lock().await;
                drop(pause_guard);
            }
            run_background_job(&inner, job).await;
            if inner.pending_background.fetch_sub(1, Ordering::SeqCst) == 1 {
                inner.pending_background_notify.notify_waiters();
            }
        }
    });
}

async fn run_background_job(inner: &Arc<SqliteCoordinatorInner>, job: BackgroundJob) {
    let BackgroundJob {
        label,
        operation,
        on_failure,
    } = job;
    let coordinator = Arc::clone(inner);
    let result = run_sqlite_write_with_retry(label, operation, inner.pool.clone(), move || {
        let coordinator = Arc::clone(&coordinator);
        async move { acquire_background_write_permit(&coordinator).await }
    })
    .await;
    if let Err(err) = result {
        if let Some(on_failure) = on_failure {
            run_background_failure_handler(inner, label, on_failure, format!("{err:#}")).await;
        }
        record_background_error(inner, label, err).await;
    }
}

async fn run_background_failure_handler(
    inner: &Arc<SqliteCoordinatorInner>,
    label: &'static str,
    on_failure: BackgroundFailureOperation,
    error_message: String,
) {
    let coordinator = Arc::clone(inner);
    let mut on_failure = on_failure;
    if let Err(err) = run_sqlite_write_with_retry(
        label,
        move |pool| on_failure(pool, error_message.clone()),
        inner.pool.clone(),
        move || {
            let coordinator = Arc::clone(&coordinator);
            async move { acquire_background_write_permit(&coordinator).await }
        },
    )
    .await
    {
        warn!(
            operation = label,
            error = %format!("{err:#}"),
            "sqlite background failure handler failed"
        );
    }
}

async fn acquire_background_write_permit(
    inner: &Arc<SqliteCoordinatorInner>,
) -> Result<OwnedSemaphorePermit> {
    loop {
        while inner.foreground_waiters.load(Ordering::SeqCst) > 0 {
            let drained = inner.foreground_waiters_drained.notified();
            if inner.foreground_waiters.load(Ordering::SeqCst) == 0 {
                break;
            }
            drained.await;
        }
        let permit = inner
            .write_gate
            .clone()
            .acquire_owned()
            .await
            .context("acquire sqlite background write permit")?;
        if inner.foreground_waiters.load(Ordering::SeqCst) == 0 {
            return Ok(permit);
        }
        drop(permit);
    }
}

async fn record_background_error(
    inner: &Arc<SqliteCoordinatorInner>,
    label: &'static str,
    err: anyhow::Error,
) {
    warn!(
        operation = label,
        error = %format!("{err:#}"),
        "sqlite background write failed"
    );
    inner
        .background_errors
        .lock()
        .await
        .push(format!("{label}: {err:#}"));
}

async fn run_sqlite_write_with_retry<T, F, Fut, FutAcquire>(
    label: &'static str,
    mut operation: F,
    pool: SqlitePool,
    mut acquire_permit: impl FnMut() -> FutAcquire,
) -> Result<T>
where
    F: FnMut(SqlitePool) -> Fut,
    Fut: Future<Output = Result<T>>,
    FutAcquire: Future<Output = Result<OwnedSemaphorePermit>>,
{
    let mut attempt = 0usize;
    loop {
        let permit = acquire_permit().await?;
        let result = operation(pool.clone()).await;
        drop(permit);
        match result {
            Ok(value) => return Ok(value),
            Err(err) if sqlite_error_is_busy(&err) && attempt < SQLITE_BUSY_RETRY_DELAYS.len() => {
                let delay = SQLITE_BUSY_RETRY_DELAYS[attempt];
                attempt += 1;
                warn!(
                    operation = label,
                    attempt,
                    delay_ms = delay.as_millis(),
                    error = %format!("{err:#}"),
                    "sqlite write busy; retrying"
                );
                tokio::time::sleep(delay).await;
            }
            Err(err) => return Err(err),
        }
    }
}

fn sqlite_error_is_busy(err: &anyhow::Error) -> bool {
    err.chain().any(|cause| {
        let message = cause.to_string();
        if message.contains("database is locked") || message.contains("SQLITE_BUSY") {
            return true;
        }
        let Some(sqlx::Error::Database(database)) = cause.downcast_ref::<sqlx::Error>() else {
            return false;
        };
        database.code().is_some_and(|code| code == "5")
    })
}

pub(crate) fn sqlite_url(path: &str) -> String {
    if path == ":memory:" {
        "sqlite::memory:".to_string()
    } else if path.starts_with('/') {
        format!("sqlite:///{}", path.trim_start_matches('/'))
    } else {
        format!("sqlite://{path}")
    }
}

pub(crate) fn sqlite_connect_options(path: &str, url: &str) -> Result<SqliteConnectOptions> {
    let mut options =
        SqliteConnectOptions::from_str(url).with_context(|| format!("parse sqlite url {url}"))?;
    if path != ":memory:" {
        options = options
            .journal_mode(SqliteJournalMode::Wal)
            .synchronous(SqliteSynchronous::Normal);
    }
    Ok(options)
}

pub(crate) fn ensure_sqlite_file(path: &str) -> Result<()> {
    if path == ":memory:" {
        return Ok(());
    }
    let path_obj = Path::new(path);
    if path_obj.is_dir() {
        bail!("database path is a directory: {}", path_obj.display());
    }
    if let Some(parent) = path_obj.parent()
        && !parent.as_os_str().is_empty()
    {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("create database directory {}", parent.display()))?;
    }
    if !path_obj.exists() {
        std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(false)
            .open(path_obj)
            .with_context(|| format!("create database file {}", path_obj.display()))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::bail;
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };
    use tokio::time::timeout;

    async fn coordinator_with_items_table() -> Result<SqliteCoordinator> {
        let sqlite = SqliteCoordinator::connect(":memory:").await?;
        sqlite
            .write_foreground("create items table", |pool| async move {
                sqlx::query(
                    "CREATE TABLE items (id INTEGER PRIMARY KEY AUTOINCREMENT, label TEXT NOT NULL)",
                )
                .execute(&pool)
                .await
                .context("create items table")?;
                Ok(())
            })
            .await?;
        Ok(sqlite)
    }

    #[tokio::test]
    async fn foreground_writes_run_before_queued_background_jobs() -> Result<()> {
        let sqlite = coordinator_with_items_table().await?;
        let pause = sqlite.pause_background_writes_for_test().await;
        sqlite
            .enqueue_background("background insert", |pool| {
                Box::pin(async move {
                    sqlx::query("INSERT INTO items (label) VALUES ('background')")
                        .execute(&pool)
                        .await
                        .context("insert background item")?;
                    Ok(())
                })
            })
            .await?;

        timeout(
            Duration::from_millis(100),
            sqlite.write_foreground("foreground insert", |pool| async move {
                sqlx::query("INSERT INTO items (label) VALUES ('foreground')")
                    .execute(&pool)
                    .await
                    .context("insert foreground item")?;
                Ok(())
            }),
        )
        .await
        .context("foreground write should not wait for queued background job")??;

        drop(pause);
        sqlite.flush_background_writes().await?;
        let labels = sqlx::query_scalar::<_, String>("SELECT label FROM items ORDER BY id ASC")
            .fetch_all(sqlite.read_pool())
            .await
            .context("list item labels")?;
        assert_eq!(labels, vec!["foreground", "background"]);
        Ok(())
    }

    #[tokio::test]
    async fn reads_complete_while_background_jobs_are_queued() -> Result<()> {
        let sqlite = coordinator_with_items_table().await?;
        let pause = sqlite.pause_background_writes_for_test().await;
        sqlite
            .enqueue_background("queued insert", |pool| {
                Box::pin(async move {
                    sqlx::query("INSERT INTO items (label) VALUES ('queued')")
                        .execute(&pool)
                        .await
                        .context("insert queued item")?;
                    Ok(())
                })
            })
            .await?;

        let count = timeout(
            Duration::from_millis(100),
            sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM items")
                .fetch_one(sqlite.read_pool()),
        )
        .await
        .context("read should not wait for queued background job")?
        .context("count items")?;
        assert_eq!(count, 0);

        drop(pause);
        sqlite.flush_background_writes().await?;
        Ok(())
    }

    #[tokio::test]
    async fn try_enqueued_background_job_is_counted_by_flush() -> Result<()> {
        let sqlite = coordinator_with_items_table().await?;
        let pause = sqlite.pause_background_writes_for_test().await;
        assert!(sqlite.try_enqueue_background("try queued insert", |pool| {
            Box::pin(async move {
                sqlx::query("INSERT INTO items (label) VALUES ('try-queued')")
                    .execute(&pool)
                    .await
                    .context("insert try queued item")?;
                Ok(())
            })
        })?);

        let flush = tokio::spawn({
            let sqlite = sqlite.clone();
            async move { sqlite.flush_background_writes().await }
        });
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(
            !flush.is_finished(),
            "flush should wait for accepted try-enqueued background writes"
        );

        drop(pause);
        flush.await.context("join background flush")??;
        let count = sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM items")
            .fetch_one(sqlite.read_pool())
            .await
            .context("count try queued items")?;
        assert_eq!(count, 1);
        Ok(())
    }

    #[tokio::test]
    async fn dropping_last_coordinator_handle_stops_background_writer() -> Result<()> {
        let sqlite = SqliteCoordinator::connect(":memory:").await?;
        let inner = Arc::downgrade(&sqlite.inner);
        drop(sqlite);

        for _ in 0..20 {
            if inner.upgrade().is_none() {
                return Ok(());
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }

        assert!(
            inner.upgrade().is_none(),
            "background writer should release coordinator state after the final sender is dropped"
        );
        Ok(())
    }

    #[tokio::test]
    async fn background_enqueue_waits_when_queue_is_at_capacity() -> Result<()> {
        let sqlite = SqliteCoordinator::connect(":memory:").await?;
        let pause = sqlite.pause_background_writes_for_test().await;
        for _ in 0..BACKGROUND_QUEUE_CAPACITY {
            sqlite
                .enqueue_background("queued no-op", |_pool| Box::pin(async move { Ok(()) }))
                .await?;
        }

        let blocked_enqueue = tokio::spawn({
            let sqlite = sqlite.clone();
            async move {
                sqlite
                    .enqueue_background("blocked no-op", |_pool| Box::pin(async move { Ok(()) }))
                    .await
            }
        });
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(
            !blocked_enqueue.is_finished(),
            "enqueue should wait while the bounded background queue is full"
        );

        drop(pause);
        blocked_enqueue.await.context("join blocked enqueue")??;
        sqlite.flush_background_writes().await?;
        Ok(())
    }

    #[tokio::test]
    async fn busy_foreground_and_background_writes_retry() -> Result<()> {
        let sqlite = coordinator_with_items_table().await?;
        let foreground_attempts = Arc::new(AtomicUsize::new(0));
        sqlite
            .write_foreground("retry foreground insert", {
                let foreground_attempts = Arc::clone(&foreground_attempts);
                move |pool| {
                    let foreground_attempts = Arc::clone(&foreground_attempts);
                    async move {
                        if foreground_attempts.fetch_add(1, Ordering::SeqCst) == 0 {
                            bail!("database is locked");
                        }
                        sqlx::query("INSERT INTO items (label) VALUES ('foreground-retry')")
                            .execute(&pool)
                            .await
                            .context("insert retried foreground item")?;
                        Ok(())
                    }
                }
            })
            .await?;
        assert_eq!(foreground_attempts.load(Ordering::SeqCst), 2);

        let background_attempts = Arc::new(AtomicUsize::new(0));
        sqlite
            .enqueue_background("retry background insert", {
                let background_attempts = Arc::clone(&background_attempts);
                move |pool| {
                    let background_attempts = Arc::clone(&background_attempts);
                    Box::pin(async move {
                        if background_attempts.fetch_add(1, Ordering::SeqCst) == 0 {
                            bail!("database is locked");
                        }
                        sqlx::query("INSERT INTO items (label) VALUES ('background-retry')")
                            .execute(&pool)
                            .await
                            .context("insert retried background item")?;
                        Ok(())
                    })
                }
            })
            .await?;
        sqlite.flush_background_writes().await?;
        assert_eq!(background_attempts.load(Ordering::SeqCst), 2);

        let labels = sqlx::query_scalar::<_, String>("SELECT label FROM items ORDER BY id ASC")
            .fetch_all(sqlite.read_pool())
            .await
            .context("list retried item labels")?;
        assert_eq!(labels, vec!["foreground-retry", "background-retry"]);
        Ok(())
    }
}
