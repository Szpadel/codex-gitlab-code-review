use std::sync::Arc;
use std::sync::atomic::{AtomicU8, AtomicUsize, Ordering};
use tokio::sync::Notify;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ServiceLifecycleSignal {
    GracefulDrain,
    FastStop,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ServiceLifecycleState {
    Running = 0,
    Draining = 1,
    Stopping = 2,
}

impl ServiceLifecycleState {
    fn from_u8(value: u8) -> Self {
        match value {
            0 => Self::Running,
            1 => Self::Draining,
            2 => Self::Stopping,
            _ => Self::Stopping,
        }
    }
}

pub(crate) struct ServiceLifecycle {
    state: AtomicU8,
    started_runs: AtomicUsize,
    started_runs_notify: Notify,
}

impl Default for ServiceLifecycle {
    fn default() -> Self {
        Self {
            state: AtomicU8::new(ServiceLifecycleState::Running as u8),
            started_runs: AtomicUsize::new(0),
            started_runs_notify: Notify::new(),
        }
    }
}

impl ServiceLifecycle {
    #[must_use]
    pub(crate) fn state(&self) -> ServiceLifecycleState {
        ServiceLifecycleState::from_u8(self.state.load(Ordering::SeqCst))
    }

    pub(crate) fn request_graceful_drain(&self) {
        let _ = self.state.compare_exchange(
            ServiceLifecycleState::Running as u8,
            ServiceLifecycleState::Draining as u8,
            Ordering::SeqCst,
            Ordering::SeqCst,
        );
    }

    pub(crate) fn request_fast_stop(&self) {
        self.state
            .store(ServiceLifecycleState::Stopping as u8, Ordering::SeqCst);
    }

    #[must_use]
    pub(crate) fn accepts_new_work(&self) -> bool {
        matches!(self.state(), ServiceLifecycleState::Running)
    }

    #[must_use]
    pub(crate) fn should_cancel_active_work(&self) -> bool {
        matches!(self.state(), ServiceLifecycleState::Stopping)
    }

    #[must_use]
    pub(crate) fn track_started_run(self: &Arc<Self>) -> StartedRunGuard {
        self.started_runs.fetch_add(1, Ordering::SeqCst);
        StartedRunGuard {
            lifecycle: Arc::clone(self),
        }
    }

    pub(crate) async fn wait_for_started_runs(&self) {
        let notified = self.started_runs_notify.notified();
        tokio::pin!(notified);
        loop {
            notified.as_mut().enable();
            if self.started_runs.load(Ordering::SeqCst) == 0 {
                return;
            }
            notified.as_mut().await;
            notified.set(self.started_runs_notify.notified());
        }
    }

    fn finish_started_run(&self) {
        let previous = self.started_runs.fetch_sub(1, Ordering::SeqCst);
        debug_assert!(previous > 0, "started run counter underflow");
        if previous == 1 {
            self.started_runs_notify.notify_waiters();
        }
    }
}

pub(crate) struct StartedRunGuard {
    lifecycle: Arc<ServiceLifecycle>,
}

impl Drop for StartedRunGuard {
    fn drop(&mut self) {
        self.lifecycle.finish_started_run();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn graceful_drain_rejects_new_work_without_cancelling_active_work() {
        let lifecycle = ServiceLifecycle::default();

        lifecycle.request_graceful_drain();

        assert!(!lifecycle.accepts_new_work());
        assert!(!lifecycle.should_cancel_active_work());
        assert_eq!(lifecycle.state(), ServiceLifecycleState::Draining);
    }

    #[test]
    fn fast_stop_overrides_graceful_drain() {
        let lifecycle = ServiceLifecycle::default();

        lifecycle.request_graceful_drain();
        lifecycle.request_fast_stop();

        assert!(!lifecycle.accepts_new_work());
        assert!(lifecycle.should_cancel_active_work());
        assert_eq!(lifecycle.state(), ServiceLifecycleState::Stopping);
    }
}
