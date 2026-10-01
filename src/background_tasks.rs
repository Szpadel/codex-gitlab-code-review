//! Owns runtime tasks from startup through cancellation and bounded shutdown.

use anyhow::{Result, anyhow};
use futures::FutureExt;
use std::future::Future;
use std::panic::AssertUnwindSafe;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::watch;
use tokio::task::{AbortHandle, JoinHandle};
use tokio_util::{sync::CancellationToken, task::TaskTracker};
use tracing::warn;

// Allow network connections to close without delaying process exit indefinitely.
const BACKGROUND_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(30);

/// Clones share one cancellation token and one set of runtime tasks.
#[derive(Clone, Default)]
pub(crate) struct BackgroundTasks {
    inner: Arc<BackgroundTasksInner>,
}

struct BackgroundTasksInner {
    tracker: TaskTracker,
    cancellation: CancellationToken,
    abort_handles: Mutex<Vec<AbortHandle>>,
    listener_failure: watch::Sender<Option<String>>,
}

impl Default for BackgroundTasksInner {
    fn default() -> Self {
        Self {
            tracker: TaskTracker::new(),
            cancellation: CancellationToken::new(),
            abort_handles: Mutex::new(Vec::new()),
            listener_failure: watch::channel(None).0,
        }
    }
}

impl BackgroundTasks {
    pub(crate) fn cancellation(&self) -> CancellationToken {
        self.inner.cancellation.clone()
    }

    /// Tracks the task until its future is dropped, including after an abort.
    pub(crate) fn spawn<F>(&self, future: F) -> JoinHandle<F::Output>
    where
        F: Future + Send + 'static,
        F::Output: Send + 'static,
    {
        let task = self.inner.tracker.spawn(future);
        self.inner
            .abort_handles
            .lock()
            .expect("background task handles lock")
            .push(task.abort_handle());
        task
    }

    /// Reports listener errors, panics, and exits before runtime cancellation.
    pub(crate) fn spawn_listener<F>(&self, name: &'static str, future: F)
    where
        F: Future<Output = Result<()>> + Send + 'static,
    {
        let cancellation = self.cancellation();
        let failure = self.inner.listener_failure.clone();
        self.spawn(async move {
            let result = AssertUnwindSafe(future).catch_unwind().await;
            if cancellation.is_cancelled() {
                return;
            }
            let error = match result {
                Ok(Ok(())) => format!("{name} exited before shutdown"),
                Ok(Err(error)) => format!("{name} failed: {error:#}"),
                Err(_) => format!("{name} panicked"),
            };
            failure.send_if_modified(|current| {
                if current.is_some() {
                    return false;
                }
                *current = Some(error);
                true
            });
        });
    }

    /// Waits for the first unexpected listener exit, including a prior failure.
    pub(crate) async fn wait_for_listener_failure(&self) -> anyhow::Error {
        let mut receiver = self.inner.listener_failure.subscribe();
        loop {
            if let Some(error) = receiver.borrow().clone() {
                return anyhow!(error);
            }
            receiver
                .changed()
                .await
                .expect("runtime owner retains failure sender");
        }
    }

    /// Waits at most 30 seconds for cancellation, then 30 seconds for abortion.
    pub(crate) async fn shutdown(&self) {
        self.inner.cancellation.cancel();
        self.inner.tracker.close();
        if tokio::time::timeout(BACKGROUND_SHUTDOWN_TIMEOUT, self.inner.tracker.wait())
            .await
            .is_err()
        {
            warn!("background task shutdown timed out");
            self.inner.abort_all();
            if tokio::time::timeout(BACKGROUND_SHUTDOWN_TIMEOUT, self.inner.tracker.wait())
                .await
                .is_err()
            {
                warn!("background tasks did not stop after abort");
            }
        }
    }
}

impl BackgroundTasksInner {
    fn abort_all(&self) {
        for handle in self
            .abort_handles
            .lock()
            .expect("background task handles lock")
            .iter()
        {
            handle.abort();
        }
    }
}

impl Drop for BackgroundTasksInner {
    fn drop(&mut self) {
        self.cancellation.cancel();
        self.abort_all();
    }
}
