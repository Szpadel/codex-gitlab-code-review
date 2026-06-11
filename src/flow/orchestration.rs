use super::{
    ActiveMentionGuard, ActiveMentionKey, ActiveReviewGuard, ActiveReviewKey, ActiveTaskRegistry,
    FlowShared,
};
use std::future::Future;
use std::sync::Arc;
use tokio::task::JoinHandle;

pub(crate) enum ActiveTaskKey {
    Review(ActiveReviewKey),
    Mention(ActiveMentionKey),
}

enum ActiveTaskGuard {
    Review(ActiveReviewGuard),
    Mention(ActiveMentionGuard),
}

impl Drop for ActiveTaskGuard {
    fn drop(&mut self) {
        match self {
            ActiveTaskGuard::Review(_guard) => {}
            ActiveTaskGuard::Mention(_guard) => {}
        }
    }
}

fn track_active_task(registry: &Arc<ActiveTaskRegistry>, key: ActiveTaskKey) -> ActiveTaskGuard {
    match key {
        ActiveTaskKey::Review(key) => ActiveTaskGuard::Review(registry.track_review(key)),
        ActiveTaskKey::Mention(key) => ActiveTaskGuard::Mention(registry.track_mention(key)),
    }
}

pub(crate) fn spawn_orchestrated_task<
    BeforeAcquire,
    BeforeState,
    OnSemaphoreClosed,
    OnSemaphoreClosedFuture,
    OnStartRejected,
    OnStartRejectedFuture,
    Work,
    WorkFuture,
>(
    shared: &FlowShared,
    key: ActiveTaskKey,
    tasks: &mut Vec<JoinHandle<()>>,
    before_acquire: BeforeAcquire,
    on_semaphore_closed: OnSemaphoreClosed,
    on_start_rejected: OnStartRejected,
    work: Work,
) where
    BeforeAcquire: Future<Output = BeforeState> + Send + 'static,
    BeforeState: Send + 'static,
    OnSemaphoreClosed: FnOnce(BeforeState) -> OnSemaphoreClosedFuture + Send + 'static,
    OnSemaphoreClosedFuture: Future<Output = ()> + Send + 'static,
    OnStartRejected: FnOnce(BeforeState) -> OnStartRejectedFuture + Send + 'static,
    OnStartRejectedFuture: Future<Output = ()> + Send + 'static,
    Work: FnOnce(BeforeState) -> WorkFuture + Send + 'static,
    WorkFuture: Future<Output = ()> + Send + 'static,
{
    let semaphore = Arc::clone(&shared.semaphore);
    let lifecycle = Arc::clone(&shared.lifecycle);
    let active_task = track_active_task(&shared.active_tasks, key);
    tasks.push(tokio::spawn(async move {
        let _active_task = active_task;
        let before_state = before_acquire.await;
        let Ok(_permit) = semaphore.acquire_owned().await else {
            on_semaphore_closed(before_state).await;
            return;
        };
        if !lifecycle.accepts_new_work() {
            on_start_rejected(before_state).await;
            return;
        }
        work(before_state).await;
    }));
}
