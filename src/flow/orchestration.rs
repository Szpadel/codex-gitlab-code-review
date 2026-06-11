use super::{
    ActiveMentionGuard, ActiveMentionKey, ActiveReviewGuard, ActiveReviewKey, ActiveTaskRegistry,
    FlowShared,
};
use crate::state::{ReviewStateStore, RunHistoryFinish};
use anyhow::Result;
use chrono::Utc;
use std::future::Future;
use std::sync::Arc;
use tokio::task::JoinHandle;

#[derive(Clone, Debug)]
pub(crate) struct ScheduledTaskContext {
    pub(crate) repo: String,
    pub(crate) iid: u64,
    pub(crate) head_sha: String,
    pub(crate) run_history_id: i64,
}

impl ScheduledTaskContext {
    pub(crate) fn new(repo: &str, iid: u64, head_sha: &str, run_history_id: i64) -> Self {
        Self {
            repo: repo.to_string(),
            iid,
            head_sha: head_sha.to_string(),
            run_history_id,
        }
    }
}

pub(crate) fn task_cancelled_finish(result: &str, preview: String) -> RunHistoryFinish {
    RunHistoryFinish {
        result: result.to_string(),
        preview: Some(preview),
        ..RunHistoryFinish::default()
    }
}

pub(crate) fn task_error_finish(
    result: &str,
    preview: String,
    err: &anyhow::Error,
) -> RunHistoryFinish {
    RunHistoryFinish {
        result: result.to_string(),
        preview: Some(preview),
        error: Some(format!("{err:#}")),
        ..RunHistoryFinish::default()
    }
}

pub(crate) async fn finish_task_run_history(
    state: &ReviewStateStore,
    task: &ScheduledTaskContext,
    finish: RunHistoryFinish,
) -> Result<()> {
    state
        .run_history
        .finish_run_history(task.run_history_id, finish)
        .await
}

pub(crate) async fn refund_review_rate_limits(
    state: &ReviewStateStore,
    acquired_rule_ids: &[String],
) -> Result<()> {
    if acquired_rule_ids.is_empty() {
        return Ok(());
    }
    state
        .review_rate_limit
        .refund_review_rate_limit_buckets(acquired_rule_ids, Utc::now().timestamp())
        .await
}

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
