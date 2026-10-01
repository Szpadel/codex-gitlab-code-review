//! Owns runtime tasks from startup through cancellation and bounded shutdown.

use std::future::Future;
use std::sync::{Arc, Mutex};
use std::time::Duration;
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

#[derive(Default)]
struct BackgroundTasksInner {
    tracker: TaskTracker,
    cancellation: CancellationToken,
    abort_handles: Mutex<Vec<AbortHandle>>,
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
